"""Assemble the corpus, and report what it is actually made of.

    python -m training.corpus.build --out data/corpus/clean
    python -m training.corpus.build --report          # read an existing build

Discovers every ``SPEC`` under ``training/corpus/sources/``, fetches, cleans,
deduplicates, and writes JSONL with provenance intact. Then — the part that
earns this file's existence — prints the **balance report**.

The first Whetstone corpus was ~10 MB of this author's own repositories. It
looked fine. The tokenizer fitted to it beat gpt2 by 7% instead of the 25-30%
the argument predicted, and only a per-sample breakdown revealed why: the corpus
was Python, C and Markdown, so ATT&CK ids scored -45% and CVE ids -26% while
netstat output scored +47%. The corpus had been starved of entire registers and
nothing said so until four steps downstream.

So this build refuses to be quiet about composition. Every document carries a
:class:`~training.corpus.source.Register`, every build prints observed share
against :data:`~training.corpus.source.REGISTER_TARGETS`, and a corpus that has
drifted is visible in the terminal before a single token is trained.

**On balancing.** ``--balance`` subsamples over-represented registers toward
their target. It never *repeats* an under-represented one: duplicated text in a
small corpus is worse than missing text, because the model memorises it and the
validation loss lies to you about it. Under-representation is therefore reported
as a gap to go and collect more source for, never papered over — and everything
dropped is logged, because a silent cap reads as "we covered it" when we did not.

**On the per-source watchdog.** Every source runs under a wall-clock budget
(``--source-timeout``) in a child process that is killed when it blows it. That
exists because of an outage: one adapter hit catastrophic regex backtracking and
spun at 99.7% CPU for seven and a half hours without completing, taking an entire
overnight training run with it. The build already survived a source that
*raises*; it had no answer at all for a source that simply never returns, and an
unattended pipeline has to survive both. See :func:`_source_documents` for why
the timeout has to be a separate process rather than a signal.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib
import json
import multiprocessing
import os
import pkgutil
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Iterator

from .source import (
    REGISTER_TARGETS,
    Document,
    Register,
    Side,
    SourceError,
    SourceSpec,
)

__all__ = [
    "discover_sources", "build", "read_documents", "balance_report",
    "CorpusGateFailed", "DEFAULT_SOURCE_TIMEOUT", "GATE_MARKER",
]


class CorpusGateFailed(RuntimeError):
    """The written corpus did not pass :func:`~training.corpus.verify.verify_corpus`.

    Raised at the very end of :func:`build`, after the balance report, so the
    operator gets the full diagnosis and then the refusal rather than a refusal
    with no context. Nothing is deleted: the leaking JSONL is the evidence that
    says which adapter is leaking, and destroying it to feel safer would destroy
    the only thing that names the bug. What stops the corpus being trained on is
    :data:`GATE_MARKER`, which :func:`read_documents` refuses to read past.
    """


class _RedactionRefused(Exception):
    """Redaction did not complete for a document, so nothing about it is trusted.

    Separate from every other failure on purpose. ``redact_identity`` refuses
    rather than degrades, and before this type existed its refusal landed in the
    same ``except Exception`` as a malformed upstream file and was reported as
    ``parse failed`` — which sends the reader to the adapter's parser when the
    thing that needs fixing is that the adapter is carrying identity. The two
    also need different blast radii: a parse failure is one bad file in a walk,
    a redaction refusal is a source that has been handling identifying text all
    along and whose earlier documents came out of the same walk.

    Any exception out of the redactor becomes this, not just the documented
    ``RuntimeError``. If the substitution raised a ``KeyError`` on a case-fold
    the table does not hold, we equally do not know the document is clean, and
    "we do not know" is the same answer as "it is dirty".
    """


def discover_sources() -> list[SourceSpec]:
    """Import every adapter under ``sources/`` and collect its SPEC.

    Import-time discovery rather than a hand-maintained list: a source that
    exists but was forgotten in a registry is exactly the kind of silent
    omission this module is written to prevent.
    """
    from . import sources as sources_pkg

    _IMPORT_FAILURES.clear()
    specs: list[SourceSpec] = []
    for info in pkgutil.iter_modules(sources_pkg.__path__):
        if info.name.startswith("_"):
            continue
        try:
            module = importlib.import_module(f"{sources_pkg.__name__}.{info.name}")
        except Exception as exc:
            # A source that will not import is a real bug and says so loudly,
            # but it must not take the other twenty-three down with it. An
            # unattended build that dies at 2am because one adapter has a typo
            # costs a night; one that reports the casualty and carries on costs
            # that source's share. The failures are re-listed after the build
            # so they cannot scroll past unnoticed.
            _IMPORT_FAILURES.append((info.name, f"{type(exc).__name__}: {exc}"))
            print(f"  ! {info.name} failed to import — skipped: "
                  f"{type(exc).__name__}: {exc}", file=sys.stderr)
            continue
        spec = getattr(module, "SPEC", None)
        if spec is None:
            print(f"  ! {info.name} defines no SPEC — skipped", file=sys.stderr)
            continue
        if not isinstance(spec, SourceSpec):
            raise SourceError(f"{info.name}.SPEC is not a SourceSpec")
        specs.append(spec)
    return sorted(specs, key=lambda s: s.name)


#: Sources that could not be imported this run, reported again after the build.
_IMPORT_FAILURES: list[tuple[str, str]] = []


@dataclass
class BuildStats:
    """What one source contributed, after dedup."""

    name: str
    register: Register
    side: Side
    license: str
    docs: int = 0
    chars: int = 0
    duplicates: int = 0
    dropped_for_balance: int = 0
    error: str = ""


# ---------------------------------------------------------------------------
# The per-source watchdog.
#
# A source that raises has been survivable for a while: build() catches it, sets
# BuildStats.error and moves on. A source that *never returns* was not. One
# adapter hit catastrophic regex backtracking and held one core at 99.7% for
# seven and a half hours without finishing, with no output, and the overnight
# training run behind it was simply gone.
#
# The cheap-looking fix is signal.SIGALRM, and it does not hold up. Three
# measurements on this interpreter (CPython 3.13, macOS), each under a 2-second
# alarm:
#
#   * ``re.match(r'(a+)+$', 'a'*30+'b')`` on the main thread IS interrupted at
#     2.00s. CPython's SRE engine has polled PyErr_CheckSignals() from inside
#     its backtracking loop for years, so the folklore that a long re.sub() is
#     simply uninterruptible is out of date, and it is worth saying so rather
#     than repeating it.
#
#   * The same call on a worker thread ran for 25.14s and the alarm was never
#     delivered at all. Python runs signal handlers on the main thread only, and
#     SRE holds the GIL throughout, so the main thread never got to execute the
#     handler it had already been sent.
#
#   * Worst of all, on the main thread, inside a loop shaped like a real
#     adapter::
#
#         for path in files:
#             try:
#                 ... re.match(...) ...
#             except (OSError, UnicodeDecodeError):
#                 continue
#
#     ran 52.54s under the 2-second alarm — twenty-six times over budget, and
#     silently. TimeoutError is a subclass of OSError, so the exception the
#     alarm raises lands in the adapter's own perfectly correct "skip this file"
#     handler and is discarded. That is not a hypothetical shape: sigma.py does
#     exactly this, and a sweep of sources/ finds dozens of ``except OSError``
#     and several bare ``except Exception`` clauses, every one of which would
#     eat the watchdog's only means of enforcement.
#
# So an in-process timeout is defeated by ordinary, correct adapter code, and
# by any C extension that does not happen to poll for signals. The enforcement
# has to live somewhere the adapter cannot reach, which means another process
# and a kill.
# ---------------------------------------------------------------------------

#: Wall-clock budget per source, in seconds. Thirty minutes.
#:
#: The number has to clear legitimate slowness by a wide margin, because a
#: watchdog that fires on a healthy source is worse than none: it silently
#: removes a register from the corpus and the balance report cannot tell you
#: whether the source was slow or broken. The slowest healthy step measured here
#: is the ``rfc`` fetch, a ten-thousand-file download that runs past eight
#: minutes on a warm link and longer on a cold one. 1800s is roughly 3.75x that,
#: which leaves room for a bad network without leaving room for a hang.
#:
#: At the other end it has to be small enough to matter. With ~25 sources the
#: absolute worst case — every single one wedged — is bounded at about twelve
#: hours instead of unbounded, and the realistic case, one runaway source, costs
#: thirty minutes instead of the seven and a half hours it actually cost.
DEFAULT_SOURCE_TIMEOUT = 1800.0

#: Sources killed for exceeding their budget this run, re-listed after the
#: balance report for the same reason _IMPORT_FAILURES is: a source that
#: contributed nothing and a source that was never allowed to finish look
#: identical in the report above and have completely different fixes.
_TIMEOUTS: list[tuple[str, float]] = []

#: Previous builds' JSONL deleted this run because the source that owns it
#: produced nothing, re-listed after the balance report. Deleting is the honest
#: answer — the alternative is a directory holding two builds at once — but it
#: can remove hundreds of megabytes of a source that was fine yesterday, and
#: that is not something to learn about from a directory listing a week later.
_STALE_REMOVED: list[tuple[str, int]] = []

#: Sources discarded whole because redaction refused a document, re-listed after
#: the balance report for a reason the other two lists do not share: a timeout
#: or a failed fetch is somebody else's outage and the answer is to re-run. A
#: redaction refusal is a defect in an adapter in this tree, and re-running it
#: produces the same refusal — the fix is to stop that adapter carrying
#: identifying text, not to try again.
_REDACTION_REFUSED: list[tuple[str, str]] = []

#: Per-source email counts, ``name -> (rewritten, kept_by_policy)``, printed
#: after the balance report. The whole lesson of this audit is that a redactor
#: which was added but never run is indistinguishable, from the code, from one
#: that ran and found nothing — so the chokepoint reports what it did on every
#: build, and a ``keep`` decision that nobody intended is visible as a number
#: instead of waiting to be discovered in a checkpoint.
_EMAIL_COUNTS: dict[str, list[int]] = {}

#: Written into the corpus directory on every build with the verification
#: gate's verdict. Its ``FAIL`` form is what :func:`read_documents` refuses to
#: read past, which is how one gate run protects the tokenizer, the shard writer
#: and the data loader without any of them having to remember to ask.
GATE_MARKER = "CORPUS-GATE.txt"

#: How long to wait for a SIGTERM to land before escalating to SIGKILL. A child
#: wedged in a C call has no Python-level cleanup to run, so this is short; the
#: only thing it buys is a chance for a well-behaved child to close its files.
_KILL_GRACE = 5.0


@dataclass
class _SourceRun:
    """The outcome of running one source, however it was run."""

    #: Documents to consume, streamed. Empty when the run failed before
    #: producing any.
    documents: Iterator[Document]
    #: Set when the source produced nothing usable and must be skipped whole —
    #: a failed fetch, a blown budget, a child that died. Already worded for
    #: BuildStats.error.
    fatal: str = ""
    #: Set when the source yielded for a while and then raised. build() formats
    #: it with its own post-dedup document count so the message reads exactly as
    #: it did when documents() ran in the parent.
    partial: str = ""
    #: True only for a blown budget, so it can be re-listed after the report.
    timed_out: bool = False
    #: ``(rewritten, kept)`` address counts from the child's redaction pass, or
    #: ``None`` when no child ran. Carried back explicitly because the child
    #: redacts before it writes its transport file, so the work happens in a
    #: process whose module globals the parent never sees — and a build report
    #: that silently counted zero because the counting ran somewhere else would
    #: be the same class of lie as the redactor that was never called.
    #:
    #: ``None`` rather than ``(0, 0)`` because the two are different facts: no
    #: child ran, versus a child ran and found no addresses. The parent's own
    #: pass is a second, idempotent sweep over text the child already cleaned,
    #: so adding the two together would report every address twice.
    emails: tuple[int, int] | None = None


def _child_main(
    spec: SourceSpec, cache_dir: Path, docs_path: Path, status_path: Path
) -> None:
    """Run one source's fetch and documents, in a process we are willing to kill.

    Entry point for the spawned child. It writes two files and returns nothing:
    the documents as JSONL, and a small status record describing how it ended.
    Nothing is sent back over a pipe — see :func:`_source_documents` for why.

    The status file is written **last**, in a ``finally``, so its absence is
    itself information: it means the process did not reach the end of this
    function, which is exactly what happens when the parent kills it.
    """
    # Become a process-group leader so the parent can kill this child *and*
    # anything it started. Six adapters shell out (git, curl, man, msfconsole),
    # and killing only the Python child would leave those grandchildren holding
    # the CPU we were trying to reclaim. The parent verifies the setsid took
    # effect before it ever calls killpg, so losing this race is safe.
    if hasattr(os, "setsid"):
        with contextlib.suppress(OSError):
            os.setsid()

    status = {"phase": "fetch", "error": "", "emitted": 0}
    try:
        try:
            path = spec.fetch(cache_dir / spec.name)
        except BaseException as exc:                # noqa: BLE001 - reported, not handled
            status["error"] = f"{type(exc).__name__}: {exc}"
            return

        status["phase"] = "documents"
        emitted = 0
        policy = _email_policy(spec.name)
        emails = [0, 0]
        with docs_path.open("w", encoding="utf-8") as fh:
            try:
                for doc in spec.documents(path):
                    # Redact HERE, before the transport file is written, and
                    # again at the chokepoint in the parent. Not belt and
                    # braces — the two calls guard different things.
                    #
                    # This hop is a real file on a real disk holding every
                    # document of every source in the final schema, and under
                    # scripts/overnight.sh TMPDIR is the external volume, so the
                    # spill lands beside the corpus it is supposed to be a
                    # redacted version of. Redacting only in the parent meant
                    # the unredacted set existed on disk for the length of the
                    # source and survived anything that stopped the parent
                    # before its ``finally``. Redacting first means the worst a
                    # SIGKILL can leave behind is an artifact of the same class
                    # as the corpus, which is the only version of this guarantee
                    # that does not depend on cleanup running.
                    #
                    # The parent's call stays because ``--source-timeout 0`` has
                    # no child at all, and because redaction must be the last
                    # thing to touch the text. Both passes are idempotent: every
                    # replacement this produces is drawn from a vocabulary that
                    # the matchers deliberately do not match, so a second pass
                    # is a no-op rather than a second substitution.
                    doc = _redacted(doc, policy, emails)
                    # Exactly the schema build() writes to the final corpus
                    # JSONL, so the two encodings cannot drift apart.
                    #
                    # ensure_ascii=True on purpose, and only here. The corpus
                    # itself is written with ensure_ascii=False, but this hop is
                    # a transport, and ASCII-escaping means a lone surrogate in
                    # some upstream document cannot turn into an encoding error
                    # that kills a whole source. Such a document still fails at
                    # the final write, which is where it failed before this
                    # watchdog existed. The cost is nil: this text is
                    # overwhelmingly ASCII already.
                    fh.write(json.dumps({
                        "text": doc.text,
                        "source": doc.source,
                        "register": doc.register.value,
                        "side": doc.side.value,
                        "ident": doc.ident,
                    }, ensure_ascii=True) + "\n")
                    emitted += 1
            except BaseException as exc:            # noqa: BLE001 - reported, not handled
                # Whatever it managed to yield before this is already on disk
                # and stays valid, which is what the in-process build did too.
                status["error"] = f"{type(exc).__name__}: {exc}"
        status["emitted"] = emitted
        # A FILE OF ITS OWN, not a field on the status record. That record is
        # written last, in a finally, precisely so that its absence means the
        # child was killed — `_child_fatal` reads it that way and a test pins
        # its exact shape. A tally has nothing to do with how the process
        # ended, and hanging one on it would blunt the only signal there is.
        # This file's absence means zero, which is the right default for a
        # count.
        with contextlib.suppress(OSError):
            (docs_path.parent / _EMAIL_COUNTS_FILE).write_text(
                json.dumps(emails), encoding="utf-8")
        if not status["error"]:
            status["phase"] = "ok"
    finally:
        with contextlib.suppress(OSError):
            status_path.write_text(json.dumps(status), encoding="utf-8")
        # The child shares the parent's stdout; adapters print progress to it.
        # Flush explicitly, because when the build is redirected to a log file
        # that stream is block-buffered and an unflushed child loses its output.
        for stream in (sys.stdout, sys.stderr):
            with contextlib.suppress(Exception):
                stream.flush()


def _kill_child(proc: multiprocessing.process.BaseProcess) -> None:
    """Stop ``proc`` and everything it spawned. Safe to call more than once.

    SIGTERM first — a child that is merely slow gets to close its files — then
    SIGKILL, which no handler can refuse. SIGTERM is enough for the case this
    was written for, because Python installs no SIGTERM handler, so the kernel
    terminates the process immediately even in the middle of a C call that would
    never have looked at a Python-level signal.
    """
    if proc.pid is None or not proc.is_alive():
        return
    hard = getattr(signal, "SIGKILL", signal.SIGTERM)
    for sig, grace in ((signal.SIGTERM, _KILL_GRACE), (hard, _KILL_GRACE * 2)):
        # Signal the whole group when — and only when — the child really did
        # become its own group leader. os.killpg(pid) addresses *the group whose
        # id is pid*; if the child lost the setsid race that group does not
        # exist, and blindly calling killpg on a pid that is not a group leader
        # is how a watchdog kills the build that owns it.
        targeted_group = False
        try:
            if hasattr(os, "getpgid") and os.getpgid(proc.pid) == proc.pid:
                os.killpg(proc.pid, sig)
                targeted_group = True
        except (OSError, AttributeError):
            pass
        if not targeted_group:
            with contextlib.suppress(Exception):
                proc.terminate() if sig == signal.SIGTERM else proc.kill()
        proc.join(grace)
        if not proc.is_alive():
            return


def _read_status(path: Path) -> dict | None:
    """Parse the child's status record, or None if it never wrote a whole one.

    None is the killed-or-crashed signal. A half-written file parses as None
    too, which is the conservative answer: if we cannot read how the child
    ended, we do not trust what it produced.
    """
    try:
        status = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return status if isinstance(status, dict) and "phase" in status else None


def _count_lines(path: Path) -> int:
    """Newlines in ``path``, or 0 if it does not exist.

    Read in fixed blocks rather than iterated line by line: this runs over a
    57 MB temporary JSONL and the only thing wanted from it is a count, so
    materialising a Python string per line would be pure waste. The child writes
    exactly one newline-terminated line per document, so this count and the
    child's own ``emitted`` are the same number when nothing was lost.
    """
    if not path.is_file():
        return 0
    total = 0
    with path.open("rb") as fh:
        while chunk := fh.read(1 << 20):
            total += chunk.count(b"\n")
    return total


def _child_fatal(status: dict, docs_path: Path, elapsed: float) -> str:
    """Decide whether a finished child's output can be trusted. ``""`` means yes.

    Split out of :func:`_source_documents` because the bug this encodes was in
    the *interpretation* of the status record rather than in the plumbing around
    it, and a test that has to spawn an interpreter to reach the decision is a
    test nobody writes.

    Only two endings are trustworthy: ``"ok"``, the clean run, and
    ``"documents"`` with an error recorded, which is documents() raising part way
    and is the legitimate partial yield the in-process path allows too.

    Everything else is a child that died without saying so. ``_child_main``'s
    inner ``except BaseException`` sits INSIDE the ``with docs_path.open(...)``
    block, so it covers neither opening the file nor the implicit flush-and-close
    when the block exits — and that close is exactly where an ENOSPC or EIO on
    the external volume this corpus is built on will land. The status then reads
    ``{"phase": "documents", "error": "", "emitted": 0}`` over a JSONL that is a
    truncated prefix of the source. Falling through to read it, which is what
    this used to do, is indistinguishable from a clean run that yielded nothing:
    the build records ``docs=0, chars=0, error=""`` and nobody ever learns the
    child died.
    """
    phase = status.get("phase")
    error = status.get("error", "")
    if phase == "fetch":
        return f"fetch failed: {error or 'unknown'}"
    if phase != "ok" and not error:
        return (f"child process stopped in phase {phase!r} after {elapsed:,.0f}s "
                f"without reporting an error — its output cannot be trusted, "
                f"source skipped")

    # Second line of defence, and it costs one sequential read. The check above
    # catches a failure that raised inside the child; it cannot see a JSONL
    # truncated by anything that did not raise there. A truncation landing on a
    # line boundary parses perfectly, and a short source counted as whole is the
    # exact "truncated and counted" outcome the timeout path refuses. The child's
    # own count is the thing to check it against.
    emitted = status.get("emitted", 0)
    written = _count_lines(docs_path)
    if written != emitted:
        return (f"child reported {emitted:,} documents but wrote {written:,} "
                f"lines — its JSONL is truncated, so the source would be a "
                f"prefix of itself; skipped entirely")
    return ""


#: Where the child leaves its address tally. Separate from the status record on
#: purpose: see _child_main.
_EMAIL_COUNTS_FILE = "emails.json"


def _read_child_emails(workdir: Path) -> tuple[int, int]:
    """The child's ``(rewritten, kept)`` address counts, or zeros.

    Zeros for an unreadable or absent file, which is the honest default: a
    count that could not be read is not evidence that redaction did nothing,
    and the build report shows the number beside the source name so a zero on a
    source known to carry addresses is visible rather than reassuring.
    """
    try:
        value = json.loads((workdir / _EMAIL_COUNTS_FILE).read_text(encoding="utf-8"))
        return (int(value[0]), int(value[1]))
    except (OSError, ValueError, TypeError, IndexError, KeyError):
        return (0, 0)


def _read_child_documents(path: Path) -> Iterator[Document]:
    """Stream the child's JSONL back as Documents.

    A generator rather than a list so the parent never holds the raw JSONL and
    the decoded documents at the same time. The dedup loop in build() keeps
    exactly what it kept before; nothing else is resident.
    """
    if not path.is_file():
        return
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            row = json.loads(line)
            yield Document(
                text=row["text"],
                source=row["source"],
                register=Register(row["register"]),
                side=Side(row["side"]),
                ident=row.get("ident", ""),
            )


@contextlib.contextmanager
def _source_documents(
    spec: SourceSpec, cache_dir: Path, timeout: float
) -> Iterator[_SourceRun]:
    """Run one source under a wall-clock budget. Yields a :class:`_SourceRun`.

    **Why a process.** The long comment above this section has the measurements;
    the summary is that an in-process timeout is enforced by raising an
    exception, and an adapter's own ``except OSError`` — which every adapter
    here has, correctly — discards it. A kill is not something the adapter can
    catch. That is the whole argument.

    **Why spawn.** ``fork`` on macOS is unsafe in any process that has touched
    the ObjC runtime or threads, and it would also hand the child a
    copy-on-write view of the parent's ``seen`` fingerprint set — hundreds of
    thousands of strings the child has no use for. ``spawn`` costs an
    interpreter start per source, which against a thirty-minute budget is not a
    number worth thinking about. Note that ``spawn`` re-executes this module in
    the child under the name ``__mp_main__``, which is why the ``__main__``
    guard at the bottom of this file matters: without it every child would start
    its own build.

    **Why a file and not a Queue.** One source in this corpus produces 57 MB of
    documents. ``multiprocessing.Queue`` is a pipe with a feeder thread, and an
    OS pipe buffer is 64 KB: the child fills it, blocks in the feeder, and never
    reaches ``join()`` — while the parent sits in ``join()`` waiting for a child
    that is waiting for the parent to drain. That is a textbook deadlock and at
    these sizes it is not an edge case, it is the normal path. Draining
    concurrently would fix the deadlock and replace it with holding the entire
    source in memory twice. A temporary JSONL has no backpressure to deadlock
    on, needs no pickling of Document objects across the boundary, and reuses
    the exact serialisation the build already writes.

    **Why a timed-out source is dropped whole.** The child's partial JSONL is a
    real prefix of a real source, and admitting it would be the worst outcome
    available: the corpus quietly changes composition by however far the source
    got before the clock ran out, and the balance report describes that as
    though it were the source. Skipped and named is honest; truncated and
    counted is not.

    **Why this cannot poison the cache.** Every adapter writes its completion
    marker last, precisely so that an interrupted fetch re-fetches instead of
    being mistaken for a finished one. Killing a child mid-download therefore
    leaves the cache in the "not finished" state it was already designed to
    express, and the next build re-fetches. This code relies on that convention
    and does not clean up after the child itself — deleting a half-written cache
    would be guessing at an adapter's internals.

    ``timeout <= 0`` disables the isolation and runs the source in the parent,
    which is the pre-watchdog code path kept for debugging (a pdb breakpoint or
    a profiler inside an adapter needs the parent's process). The document
    consumption loop in build() is shared by both paths, so they cannot drift.
    """
    if timeout <= 0:
        try:
            path = spec.fetch(cache_dir / spec.name)
        except Exception as exc:                    # a source is allowed to fail
            yield _SourceRun(iter(()), fatal=f"fetch failed: {type(exc).__name__}: {exc}")
            return
        yield _SourceRun(spec.documents(path))
        return

    ctx = multiprocessing.get_context("spawn")
    # mkdtemp is already 0700, which is stated rather than relied on: this
    # directory holds every document of one source, and on a shared or
    # multi-user machine a transport file is as readable as the corpus. The
    # child redacts before it writes here, so what is inside carries the same
    # guarantee as the output — but the mode is the thing that stops anybody
    # else reading it in the window before the rmtree below, and a comment is
    # cheaper than discovering the default changed.
    workdir = Path(tempfile.mkdtemp(prefix=f"whetstone-corpus-{spec.name}-"))
    os.chmod(workdir, 0o700)
    docs_path = workdir / "documents.jsonl"
    status_path = workdir / "status.json"
    proc = ctx.Process(
        target=_child_main,
        args=(spec, cache_dir, docs_path, status_path),
        name=f"corpus-{spec.name}",
        # Not daemonic: a daemonic process may not create children of its own,
        # and six adapters shell out. The kill path below is what guarantees the
        # child does not outlive its budget; daemon= would add nothing.
        daemon=False,
    )
    started = time.monotonic()
    try:
        proc.start()
        proc.join(timeout)
        elapsed = time.monotonic() - started

        if proc.is_alive():
            _kill_child(proc)
            yield _SourceRun(
                iter(()),
                timed_out=True,
                fatal=(f"TIMED OUT after {elapsed:,.0f}s (budget {timeout:,.0f}s) — "
                       f"child process killed, source skipped entirely"),
            )
            return

        status = _read_status(status_path)
        if status is None:
            # No status record means the child never reached the end of
            # _child_main: a segfault, an OOM kill, a C-level abort. Whatever it
            # wrote is untrustworthy, so none of it is read.
            yield _SourceRun(iter(()), fatal=(
                f"child process died after {elapsed:,.0f}s with exit code "
                f"{proc.exitcode} without reporting — source skipped"))
            return

        fatal = _child_fatal(status, docs_path, elapsed)
        if fatal:
            yield _SourceRun(iter(()), fatal=fatal)
            return

        yield _SourceRun(_read_child_documents(docs_path),
                         partial=status.get("error", ""),
                         emails=_read_child_emails(workdir))
    finally:
        # Unconditional: a KeyboardInterrupt in the parent must not leave a
        # child holding a core, and setsid means the child no longer shares the
        # terminal's Ctrl-C.
        #
        # A `finally` covers every exception and a Ctrl-C. It does not cover a
        # SIGKILL of the parent or a power loss, and no amount of cleanup code
        # can, which is precisely why the child redacts before it writes: this
        # guarantee is "the spill is no worse than the corpus", not "the spill
        # is always removed". Claiming the second would be the fail-open shape
        # this whole file exists to avoid.
        _kill_child(proc)
        shutil.rmtree(workdir, ignore_errors=True)


def build(
    out_dir: Path,
    cache_dir: Path,
    *,
    only: list[str] | None = None,
    balance: bool = False,
    max_source_share: float = 0.30,
    max_register_multiple: float = 0.0,
    min_chars: int = 40,
    source_timeout: float = DEFAULT_SOURCE_TIMEOUT,
    require_identity_table: bool = True,
) -> list[BuildStats]:
    """Fetch, clean, dedupe and write the corpus. Returns per-source stats.

    ``source_timeout`` is the per-source wall-clock budget in seconds. A source
    that exceeds it is killed, skipped, recorded in its BuildStats.error and
    re-listed after the balance report — the same treatment a failed fetch gets,
    because from the corpus's point of view they are the same event. 0 disables
    the watchdog and runs every source in this process, which is the behaviour
    that let one runaway regex burn seven and a half hours.

    ``require_identity_table`` refuses to start when this machine has nothing
    identifying for :func:`~training.trajectories.redact_identity` to remove.
    That sounds like a non-event and it is the fail-open: the redactor's first
    two lines are ``pattern = _identity_pattern(); if pattern is None: return
    text``, so on a host whose account name, host name and temp dir are all
    generic — a container running as root, a CI runner, a uid missing from the
    passwd database — every document is returned byte-for-byte and *nothing says
    so*. A build with an empty table is identical in its output and in its log
    to a build where redaction ran and found nothing. Pass ``False`` only when
    there is genuinely no identity to protect, and know that it is the one flag
    in this file that can make the corpus worse in a way the report cannot show.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)

    _TIMEOUTS.clear()
    _STALE_REMOVED.clear()
    _REDACTION_REFUSED.clear()
    _EMAIL_COUNTS.clear()
    _preflight_redaction(require_identity_table=require_identity_table)
    all_specs = discover_sources()
    _check_email_policy_names(all_specs)
    specs = [s for s in all_specs if s.name in only] if only else list(all_specs)
    if not specs:
        raise SystemExit(
            "no corpus sources found under training/corpus/sources/. "
            "Each adapter exports a module-level SPEC = SourceSpec(...)."
        )

    # Refuse an unsatisfiable cap HERE, before a single byte is fetched, rather
    # than at trim time after an hour of downloads. n sources cannot all be
    # under a 1/n share of one corpus, so `--only sigma` against the default 30%
    # is arithmetic with no answer — and the cap used to answer it anyway, by
    # quietly deleting 70% of the one source it had been asked to build. The
    # condition is knowable from the flags alone, so this costs nothing.
    if max_source_share and len(specs) * max_source_share <= 1.0:
        raise SystemExit(
            f"--max-source-share {max_source_share:g} cannot be met by "
            f"{len(specs)} source(s): one of them must be at least "
            f"{1 / len(specs):.0%} of the corpus. Pass --max-source-share 0 to "
            f"build this selection uncapped, or select more sources."
        )

    print(f"{len(specs)} source(s): {', '.join(s.name for s in specs)}\n")

    seen: set[str] = set()
    stats: list[BuildStats] = []
    collected: dict[str, list[Document]] = {}

    for spec in specs:
        st = BuildStats(name=spec.name, register=spec.register, side=spec.side,
                        license=spec.license)
        stats.append(st)
        print(f"── {spec.name}  [{spec.register.value}/{spec.side.value}]  {spec.license}")

        # A source may declare its own budget; otherwise it gets the build's.
        budget = spec.timeout if spec.timeout is not None else source_timeout
        policy = _email_policy(spec.name)
        kept: list[Document] = []
        # Fingerprints this source added to the shared `seen` set, so that
        # discarding the source can also undo its claim on them. Without this a
        # discarded source still suppresses an identical document in a later
        # one, and the later source is then the one that looks short.
        claimed: list[str] = []
        refused = ""
        # (rewritten, kept) address counts for this source. The parent's own
        # pass and the child's are summed, because with the watchdog armed the
        # child does the work and with --source-timeout 0 the parent does.
        emails = [0, 0]
        run_emails: tuple[int, int] | None = None
        with _source_documents(spec, cache_dir, budget) as run:
            run_emails = run.emails
            if run.fatal:
                # A failed fetch, a blown budget or a dead child all land here
                # and are all handled the same way they always were: named,
                # skipped, and left out of `collected` entirely.
                st.error = run.fatal
                print(f"   ! {st.error}")
                if run.timed_out:
                    _TIMEOUTS.append((spec.name, budget))
                continue

            try:
                for doc in run.documents:
                    if doc.n_chars < min_chars:
                        continue
                    # Identity redaction is a CHOKEPOINT, not a courtesy each
                    # source performs. The trajectory generator redacted its own
                    # output and every other adapter did not, which was fine
                    # until `ownrepos` walked the maintainer's own repositories
                    # and carried their account name and the per-user temp path
                    # that fingerprints one particular Mac into the corpus — and
                    # from there into weights, where it is not removable. A
                    # measured audit of the shipped corpus found identity in two
                    # sources, only one of which had ever thought about it.
                    #
                    # So it happens here, once, on the way in, where no future
                    # adapter can forget it. redact_identity refuses rather than
                    # degrades: a survivor raises instead of being written.
                    #
                    # **The blast radius of that refusal is the whole source**,
                    # and the comment that used to sit here claimed the opposite
                    # — "one bad source is skipped and named". It was not. The
                    # `except` wraps this entire loop while `kept` is appended
                    # to inside it, and `collected[spec.name] = kept` ran
                    # unconditionally afterwards, so a refusal TRUNCATED the
                    # source and wrote every document before the offending one
                    # to disk. Those are precisely the documents that cannot be
                    # trusted: they came out of the same adapter and the same
                    # walk as the one caught carrying identity, and the only
                    # thing distinguishing them is that the redactor had not
                    # reached them yet. The run was then labelled `parse failed`
                    # and the source appeared in the balance report as a healthy
                    # contributor *and* in the failure list.
                    #
                    # This file's own standard, from _source_documents: "Skipped
                    # and named is honest; truncated and counted is not." The
                    # timeout path obeys it. Now so does this one.
                    doc = _redacted(doc, policy, emails)
                    fp = doc.fingerprint
                    if fp in seen:
                        st.duplicates += 1
                        continue
                    seen.add(fp)
                    claimed.append(fp)
                    kept.append(doc)
                    st.docs += 1
                    st.chars += doc.n_chars
            except _RedactionRefused as exc:
                # Not an error on the source's stats yet: the whole source is
                # about to be discarded, so the counts those stats hold describe
                # documents that will never be written and must not survive into
                # the report.
                refused = f"REDACTION REFUSED after {st.docs} docs: {exc}"
            except Exception as exc:
                # Reached when documents() runs in this process (timeout
                # disabled), and when the child's JSONL itself is unreadable.
                st.error = f"parse failed after {st.docs} docs: {type(exc).__name__}: {exc}"
                print(f"   ! {st.error}")

            if run.partial:
                # The isolated path's equivalent: documents() raised in the
                # child, so the exception never crosses into this process. Worded
                # identically, and with this process's post-dedup count, so the
                # two paths are indistinguishable in a build log.
                #
                # Except for one case, which has to cross the process boundary
                # as well: the child redacts before it writes its transport
                # file, so a refusal can happen over there. The marker travels
                # inside the message because that is the only channel the status
                # record has, and treating it as a parse failure here would
                # reinstate exactly the truncation this function just fixed.
                if _REFUSAL_MARKER in run.partial:
                    refused = f"REDACTION REFUSED after {st.docs} docs: {run.partial}"
                else:
                    st.error = f"parse failed after {st.docs} docs: {run.partial}"
                    print(f"   ! {st.error}")

        if refused:
            # Discard the source whole. `collected` is never assigned, so the
            # write loop below treats it exactly as it treats a timeout: no file
            # is written, and any file a previous build left behind is removed
            # and named, because a directory must not hold two builds at once.
            seen.difference_update(claimed)
            st.docs = st.chars = st.duplicates = 0
            st.error = refused
            _REDACTION_REFUSED.append((spec.name, refused))
            print(f"   ! {refused}")
            print(f"   ! {spec.name} discarded ENTIRELY — the documents before "
                  f"the refusal came from the same walk and are not trusted")
            continue

        # The child's pass IS the redaction when the watchdog is armed; the
        # parent's loop is an idempotent second sweep over text already clean.
        # Summing them would double every address.
        _EMAIL_COUNTS[spec.name] = (list(run_emails) if run_emails is not None
                                    else emails)
        collected[spec.name] = kept
        _note_source(st)
        if not kept and not st.error:
            # A source that gave nothing, with nothing to blame. balance_report
            # builds its register table from `[s for s in stats if s.docs]` and
            # its failure list from `[s for s in stats if s.error]`, so this
            # source would appear in NEITHER — it vanishes from the report and
            # reads, to anyone looking, like a source that simply had nothing to
            # give. _note_if_emptied already makes this argument for a source a
            # cap reduced to zero, and is wired only into the caps; this is the
            # same hole one door along. Recording it as an error is not a
            # mischaracterisation: a whole upstream is missing from the corpus,
            # and the failure list is the only channel the report already
            # watches.
            st.error = ("produced 0 documents and reported no failure — the "
                        "whole source is absent from the corpus, and the "
                        f"register table cannot show that (expected at least "
                        f"{spec.expect_min_docs:,})")
            print(f"   ! {st.error}")
        elif st.docs < spec.expect_min_docs:
            print(f"   ! expected at least {spec.expect_min_docs:,} docs but got "
                  f"{st.docs:,} — upstream layout may have changed")

    _strip_boilerplate(collected, stats)

    # Redaction has to be the LAST thing that touches the text, and until this
    # call it was not. _redacted runs in the document loop above;
    # _strip_boilerplate runs here and *mutates* text, so the guarantee the
    # chokepoint comment implied — "every written byte passed redaction" — was
    # really "every byte passed redaction and was then edited again". Boilerplate
    # removal only deletes, so it cannot introduce a literal that was not
    # already latent; it can delete the characters separating two halves of one.
    #
    # Re-redacting the documents it changed is cheaper than reasoning about
    # whether line-granular deletion can ever join two fragments, and an
    # invariant that rests on nobody adding a third transform later is not an
    # invariant. Everything after this point only selects and drops.
    _reredact_mutated(collected, stats)

    if max_source_share:
        _cap_source_share(collected, stats, max_source_share)

    if max_register_multiple:
        _cap_register_share(collected, stats, max_register_multiple)

    if balance:
        _apply_balance(collected, stats)

    # Write after boilerplate removal and balancing so what lands on disk is
    # exactly what the report describes — and, for a source that produced
    # nothing, DELETE the file the last build left behind.
    #
    # Nothing here used to delete anything, and read_documents() globs *.jsonl
    # unconditionally. So a source that timed out, failed its fetch or was
    # emptied by a cap kept its previous build's documents in the corpus while
    # the balance report, built from this run's stats, recorded it as
    # contributing zero. The directory and the report then described two
    # different corpora, and the shards, the tokenizer and every measurement
    # downstream followed the directory. That is the watchdog's own guarantee —
    # "skipped and named is honest; truncated and counted is not" — arriving by
    # another door: it held in memory and not on disk. tokenize_corpus already
    # clears its stale shard-*.bin for exactly this reason.
    #
    # Only sources in THIS run's selection are touched. `--only sigma` must not
    # delete the fourteen files it was never asked to rebuild; the provenance
    # record below is what keeps those honest.
    for spec in specs:
        path = out_dir / f"{spec.name}.jsonl"
        docs = collected.get(spec.name, [])
        if not docs:
            if path.is_file():
                _STALE_REMOVED.append((spec.name, path.stat().st_size))
                path.unlink()
            continue
        with path.open("w", encoding="utf-8") as fh:
            for doc in docs:
                fh.write(json.dumps({
                    "text": doc.text,
                    "source": doc.source,
                    "register": doc.register.value,
                    "side": doc.side.value,
                    "ident": doc.ident,
                }, ensure_ascii=False) + "\n")

    # Verify the ARTIFACT, not the intention. Every finding in the audit this
    # function was rewritten for comes back to one sentence: a redactor that was
    # added but never run is indistinguishable, from the code, from one that ran
    # and found nothing. The corpus on disk shipped an email address the adapter
    # had learned to remove twenty days earlier, and nothing noticed, because
    # nothing ever read the output back. One pass over the written JSONL would
    # have caught it on day one — so here is the pass, over the bytes, after
    # every transform, where no in-memory reasoning about ordering can be wrong.
    gate = _verify_written(out_dir, stats)

    orphans = _write_provenance(out_dir, all_specs, stats)
    print("\n" + balance_report(stats))
    if _EMAIL_COUNTS:
        print("\n" + _email_report())
    if _TIMEOUTS:
        # Re-listed for the same reason import failures are, and it is the more
        # expensive mistake of the two: in the report above, a source that was
        # killed at the deadline is indistinguishable from a source that
        # contributed nothing, and "the upstream is empty" and "the adapter
        # wedged" have nothing in common as fixes.
        print(f"\n{len(_TIMEOUTS)} source(s) EXCEEDED THE TIME BUDGET, were "
              f"killed, and contributed nothing to the report above:")
        for name, budget in _TIMEOUTS:
            print(f"  ! {name}: exceeded {budget:,.0f}s and was terminated. "
                  f"Its cache is untouched, so a re-run re-fetches; raise "
                  f"--source-timeout only once you know the source is merely "
                  f"slow and not wedged.")
    if _STALE_REMOVED:
        # Same precedent again. Deleting a previous build's file is the only way
        # to keep the directory and the report describing one corpus, but it can
        # silently drop half a gigabyte of a source that was healthy yesterday,
        # and the report above cannot show what is no longer in it.
        print(f"\n{len(_STALE_REMOVED)} previous build file(s) REMOVED because "
              f"the source produced nothing this run:")
        for name, size in _STALE_REMOVED:
            print(f"  ! {name}.jsonl ({size/1e6:.1f}M) deleted. A corpus must "
                  f"not mix two builds, so the old documents cannot stay while "
                  f"the report says this source contributed nothing. Re-run once "
                  f"the failure named above is fixed.")
    if orphans:
        # Not deleted: a file with no adapter may be a renamed source or data put
        # here by hand, and guessing is not worth destroying it. It is still read
        # by read_documents() and still trained on, and its licence cannot be
        # reconstructed — which source.py names as the thing this corpus must
        # never become — so it is stated instead.
        print(f"\n{len(orphans)} file(s) in {out_dir} belong to NO source in "
              f"this tree and have no provenance:")
        for name in orphans:
            print(f"  ! {name} is still read by every consumer of this corpus "
                  f"and cannot be attributed to a licence. Delete it, or restore "
                  f"the adapter that owns it.")
    if _IMPORT_FAILURES:
        # Last thing printed, because it is the thing most worth acting on: a
        # source missing from the balance report above looks like a source that
        # contributed nothing, and those two have very different fixes.
        print(f"\n{len(_IMPORT_FAILURES)} source(s) FAILED TO IMPORT and are "
              f"absent from the report above:")
        for name, err in _IMPORT_FAILURES:
            print(f"  ! {name}: {err}")
    if _REDACTION_REFUSED:
        # Its own list rather than a line in the timeout one, because the action
        # is different. A timeout says re-run; a redaction refusal says an
        # adapter in this tree is carrying identifying text and will refuse
        # again, identically, forever, until it is fixed.
        print(f"\n{len(_REDACTION_REFUSED)} source(s) were DISCARDED WHOLE "
              f"because redaction refused a document:")
        for name, why in _REDACTION_REFUSED:
            print(f"  ! {name}: {why}")
            print(f"    Nothing from {name} was written. Re-running will refuse "
                  f"again — the fix is in the adapter, which is handing the "
                  f"chokepoint text carrying this machine's identity.")
    print("\n" + gate.report)
    if not gate.ok:
        raise CorpusGateFailed(gate.report)
    return stats



# ---------------------------------------------------------------------------
# The chokepoint.
#
# Two kinds of identifier reach this corpus and they need different answers.
#
# THIS MACHINE'S IDENTITY — account name, home path, host name, per-user temp
# directory — is removed by training.trajectories.redact_identity, which derives
# its table from the operating system at runtime rather than from a configured
# list. That distinction is the whole design: a configured list is a list of the
# leaks somebody already noticed.
#
# EMAIL ADDRESSES are a different problem, and before this they were handled in
# exactly one adapter as a courtesy. ownrepos.py grew a redactor because it swept
# up a university project README listing four people by name with their
# addresses — the author's own, and three .edu addresses belonging to other
# students who never agreed to be in a training corpus. The redactor worked. It
# had also never been run: its module's mtime was twenty days later than the
# corpus file's, and the shipped document still carried all eight addresses with
# not one placeholder anywhere in 208,346 documents.
#
# So email redaction moves here, where no adapter can forget it, and the policy
# is written down instead of being whatever one adapter happened to do.
# ---------------------------------------------------------------------------

#: Address shape. Deliberately the same expression ownrepos.py used, so that
#: moving the pass here cannot change which strings count as an address.
#:
#: The trailing ``\.[A-Za-z]{2,}`` is what keeps this off the corpus's enormous
#: population of at-signs that are not addresses: ``pkg@1.2.3``, ``HEAD@{1}``,
#: ``user@host`` in an ssh line and ``@staticmethod`` all fail it, because a
#: dotted alphabetic suffix of two or more characters is the one part of an
#: address that none of those have.
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

#: Local parts that name a *mailbox* rather than a person, from RFC 2142 plus
#: the automated senders every log corpus is full of. ``security@vendor.example``
#: in an advisory is a published reporting channel; rewriting it identifies
#: nobody better and destroys signal a security model should have — that
#: vulnerabilities go to ``security@`` and bounces come from ``mailer-daemon``.
_EMAIL_ROLE_LOCALS = frozenset({
    # RFC 2142 §3-5
    "postmaster", "abuse", "noc", "security", "hostmaster", "webmaster",
    "usenet", "news", "uucp", "ftp", "info", "marketing", "sales", "support",
    # Automated senders and system accounts.
    "noreply", "no-reply", "donotreply", "do-not-reply", "mailer-daemon",
    "root", "admin", "administrator", "nobody", "daemon", "bounces",
})

#: Reserved for documentation and testing, and therefore *deliberate content*.
#: RFC 2606 names the four TLDs and the three second-level domains; RFC 6761
#: reserves ``localhost``. This corpus is full of them on purpose — a payload,
#: a man page, an RFC example — and rewriting one corrupts the example while
#: protecting nobody. Same discipline as not counting ``192.0.2.0/24`` as a leak.
_EMAIL_RESERVED_TLDS = frozenset({"test", "example", "invalid", "localhost"})
_EMAIL_RESERVED_DOMAINS = frozenset({"example.com", "example.net", "example.org"})

#: The replacement for an address that belongs to the operator of this machine.
#: One fixed literal, because there is no generalisation argument to make about
#: a handful of occurrences and a single obvious marker is easier to grep for.
_HOST_EMAIL_REPLACEMENT = "operator@example.invalid"

#: The pseudonym vocabulary. 8 local parts x 8 buckets = 64 distinct
#: placeholders, all under RFC 2606's ``.invalid``.
#:
#: **Why not one placeholder.** The obvious implementation substitutes a single
#: string, and it passes the privacy gate while making the model worse. There
#: are roughly 7,700 address occurrences in the sources this policy rewrites;
#: collapsing them onto one 26-character literal creates a new high-frequency
#: sequence in a corpus whose measured problem is already literals repeated
#: hundreds of times each. Privacy is satisfied by *any* substitution.
#: Generalisation is satisfied only by a varied one, and the two are the same
#: pass but not the same problem.
#:
#: **Why not more than 64.** The bucket is derived from the address, so it is
#: information about it. 64 buckets over ~3,900 distinct addresses puts about 60
#: real addresses in each — the bucket is a lossy class label, not a
#: fingerprint, and no amount of corpus reading recovers an address from it.
#: Push the count up for more variety and each bucket narrows toward identifying
#: its members; this is where that trade stops being worth taking.
#:
#: ``operator`` is deliberately absent: it is redact_identity's own replacement
#: for the account name, and two redactors sharing a placeholder makes every
#: later question about which one produced a string unanswerable.
_EMAIL_LOCAL_VOCAB = (
    "contributor", "maintainer", "author", "reporter",
    "reviewer", "analyst", "engineer", "researcher",
)
_EMAIL_BUCKETS = 8

#: Sources exempt from third-party email redaction, and *why*, per source. The
#: default is to redact; this table is the whole of the exception, which is the
#: point — "the public standards policy" was previously an accident (no source
#: redacted anything except ownrepos) and is now four lines somebody can argue
#: with.
#:
#: The line drawn here: an address is kept only where the address is part of the
#: licensed artifact rather than incidental to it. Those two sources carry ~72%
#: of all address occurrences in the corpus, so this is not a rounding decision.
#:
#: Everything else redacts, including upstream material that is already public.
#: Three reasons. (1) Nothing requires it: the CC-BY and CC-BY-SA sources here
#: satisfy attribution with the provenance line each adapter already writes,
#: naming the repository and its licence — not with an address in a document
#: body. (2) A published checkpoint memorises what it is shown and cannot be
#: grepped afterwards, so "already public" is not the same as "safe to bake in".
#: (3) For the detection sources, where an address is sometimes an indicator of
#: compromise, the signal a from-scratch model needs is that a YARA rule matches
#: on address-shaped strings — not the exact address of a mail drop from 2019,
#: which is both stale and the only part that is somebody's identity.
#:
#: A new adapter therefore defaults to the safe side, and the per-source counts
#: printed after every balance report are how an over-redaction gets noticed in
#: one build instead of in a checkpoint.
_EMAIL_KEEP: dict[str, str] = {
    "rfc": ("IETF Trust Legal Provisions permit reproduction and distribution "
            "of an RFC *in full*. The author block is part of the document, so "
            "a copy with the addresses rewritten is no longer the copy the "
            "licence permits."),
    "kerneldocs": ("Author, maintainer and Signed-off-by lines are the kernel's "
                   "Developer Certificate of Origin record. Rewriting them does "
                   "not anonymise a contributor who signed publicly — it "
                   "misrepresents who certified the contribution."),
}

#: Sources whose text comes from THIS machine's filesystem rather than from a
#: declared upstream. They redact by default like everything else; they are
#: named so the decision is affirmative rather than inherited, because these are
#: the ones where an address is in the corpus purely as a consequence of where
#: the build ran, with nobody's consent and no licence covering it.
_EMAIL_HOST_DERIVED = ("ownrepos", "trajectories", "manpages")

#: Marker that carries a redaction refusal across the parent/child boundary.
#: The child records ``f"{type(exc).__name__}: {exc}"``, so the class name *is*
#: the wire format; deriving it rather than retyping it means a rename cannot
#: silently turn a refusal back into a "parse failed".
_REFUSAL_MARKER = _RedactionRefused.__name__


@dataclass(frozen=True)
class _EmailPolicy:
    """What to do about third-party addresses in one source, and why."""

    source: str
    keep_third_party: bool
    reason: str


def _email_policy(name: str) -> _EmailPolicy:
    """Resolve one source's email policy. Unknown sources redact."""
    if name in _EMAIL_KEEP:
        return _EmailPolicy(name, True, _EMAIL_KEEP[name])
    if name in _EMAIL_HOST_DERIVED:
        return _EmailPolicy(name, False, "built from this machine's filesystem")
    return _EmailPolicy(name, False, "third-party upstream, default policy")


def _check_email_policy_names(specs: list[SourceSpec]) -> None:
    """Name a policy entry that applies to no source. Costs nothing, catches a rename.

    A keep entry for a source that no longer exists is a policy nobody is
    getting — the same silent-omission shape :func:`discover_sources` refuses a
    hand-maintained registry for. Checked against every *discovered* source, not
    the selection, so ``--only sigma`` does not accuse the other forty-six.
    """
    from . import sources as sources_pkg

    # Read the package rather than ``specs``: the question is whether an
    # adapter *file* was renamed, and answering it from a list the caller
    # supplied would make every build with a narrowed selection — and every
    # test that substitutes its own sources — accuse the other forty-six.
    known = {info.name for info in pkgutil.iter_modules(sources_pkg.__path__)}
    known |= {s.name for s in specs}
    named = set(_EMAIL_KEEP) | set(_EMAIL_HOST_DERIVED)
    stale = sorted(named - known)
    if stale:
        print(f"  ! email policy names {len(stale)} source(s) that do not "
              f"exist: {', '.join(stale)} — a renamed adapter has silently "
              f"fallen back to the default", file=sys.stderr)


@lru_cache(maxsize=1)
def _host_email_needles() -> frozenset[str]:
    """This machine's own addresses, derived at runtime and never persisted.

    Derived, not configured, for the reason the identity table is: a list of
    identifiers written into a file is a list of the leaks somebody already
    noticed, and the file itself becomes the next leak. The audit that found
    these problems proved that the hard way — six of its own working files wrote
    live addresses to disk as cleartext while its report said it had not.

    So these come from ``git config`` and the environment, they live only in
    this process, and nothing in this module ever prints one, writes one or puts
    one in an exception message. The build reports a *count*.

    An empty result is not a silent fail-open: every source that is built from
    this machine's own filesystem redacts all addresses anyway, so this set only
    does work in the two sources exempted by policy. The preflight prints its
    size so that "nothing was found" and "nothing was looked for" are different
    lines in the log.
    """
    found: set[str] = set()
    for var in ("EMAIL", "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL"):
        value = os.environ.get(var, "").strip().lower()
        if value:
            found.add(value)
    for args in (["config", "--get-all", "user.email"],
                 ["config", "--global", "--get-all", "user.email"]):
        try:
            out = subprocess.run(["git", *args], capture_output=True, text=True,
                                 timeout=10, check=False)
        except (OSError, subprocess.SubprocessError):
            continue
        for line in out.stdout.splitlines():
            value = line.strip().lower()
            if value:
                found.add(value)
    # Only well-formed addresses: a misconfigured user.email of "me" would
    # otherwise become a needle that matches a substring of ordinary prose.
    return frozenset(v for v in found if _EMAIL.fullmatch(v))


def _is_reserved_email_domain(domain: str) -> bool:
    """True for the documentation and testing domains RFC 2606/6761 reserve."""
    if domain in _EMAIL_RESERVED_DOMAINS:
        return True
    if any(domain.endswith("." + d) for d in _EMAIL_RESERVED_DOMAINS):
        return True
    return domain.rpartition(".")[2] in _EMAIL_RESERVED_TLDS


def _email_pseudonym(address: str) -> str:
    """A stable, varied, shape-preserving placeholder for one address.

    ``blake2b`` rather than :func:`hash`, which is salted per process: the same
    address must map to the same placeholder in every build and on every
    machine, or the corpus is not reproducible and the dedup fingerprints move
    under it. Same argument :func:`_cap_source_share` makes for its selection.
    """
    digest = hashlib.blake2b(address.encode("utf-8"), digest_size=8).digest()
    h = int.from_bytes(digest, "big")
    local = _EMAIL_LOCAL_VOCAB[h % len(_EMAIL_LOCAL_VOCAB)]
    bucket = (h // len(_EMAIL_LOCAL_VOCAB)) % _EMAIL_BUCKETS
    return f"{local}-{bucket}@example.invalid"


def _email_replacement(address: str, policy: _EmailPolicy) -> str | None:
    """What one address becomes, or ``None`` to leave it alone.

    The order of these four tests is the policy, and the first one is the only
    rule with no exception anywhere: an address of the operator's is removed from
    every source including the exempt ones. He can publish his own address on
    his own website whenever he likes; a checkpoint is not a place he can
    un-publish it from.
    """
    low = address.lower()
    if low in _host_email_needles():
        return _HOST_EMAIL_REPLACEMENT
    local, _, domain = low.rpartition("@")
    if _is_reserved_email_domain(domain):
        return None                       # documentation, on purpose
    if local in _EMAIL_ROLE_LOCALS:
        return None                       # a mailbox, not a person
    if policy.keep_third_party:
        return None                       # named in _EMAIL_KEEP, with a reason
    return _email_pseudonym(low)


def _redact_emails(text: str, policy: _EmailPolicy) -> tuple[str, int, int]:
    """Apply the policy to ``text``. Returns (text, rewritten, kept).

    Both counts are returned because only reporting the rewrites would make an
    all-keep policy look identical to a redactor that never ran, which is the
    failure this whole pass exists to end.
    """
    if "@" not in text:
        return text, 0, 0
    tally = [0, 0]

    def _one(match: re.Match[str]) -> str:
        address = match.group(0)
        replacement = _email_replacement(address, policy)
        if replacement is None:
            tally[1] += 1
            return address
        tally[0] += 1
        return replacement

    return _EMAIL.sub(_one, text), tally[0], tally[1]


def _scrubbed(text: str, policy: _EmailPolicy) -> tuple[str, int, int]:
    """Addresses then identity, in that order, with every failure a refusal.

    **Emails first, and the order is load-bearing.** The identity table holds
    the account name, and on this machine the account name is a substring of the
    operator's own address. Redacting identity first turns that address into
    ``operator@<provider>`` — which no longer matches the host needle set, so
    the one rule with no exception would silently stop firing. Addresses are
    matched whole, before anything mangles them.

    Any exception out of the identity redactor becomes :class:`_RedactionRefused`.
    It documents a ``RuntimeError`` for a survivor, and it is also capable of a
    ``KeyError`` when a Unicode case-fold matches its case-insensitive pattern
    but is not a key of its own table. The two mean the same thing here: the
    redactor did not complete, so nothing about this document is known.
    """
    from training.trajectories import redact_identity

    out, rewritten, kept = _redact_emails(text, policy)
    try:
        out = redact_identity(out)
    except _RedactionRefused:
        raise
    except Exception as exc:
        # The message carries the exception type and the redactor's own words,
        # which name the surviving FORM (a table key such as "the home path"),
        # never a value — redact_identity reports forms, and this must not be
        # the place that starts reporting values.
        raise _RedactionRefused(f"{type(exc).__name__}: {exc}") from exc
    return out, rewritten, kept


def _redacted(doc, policy: _EmailPolicy | None = None,
              tally: list[int] | None = None):
    """Remove this machine's identity and policy-covered addresses from a document.

    Imported lazily because :mod:`training.trajectories` pulls in the kernel and
    the adapters, and the corpus builder has no other reason to depend on them.
    If that import ever fails the build must FAIL rather than quietly write
    unredacted text — a corpus that is clean only when an optional import
    succeeds is a corpus nobody can make a claim about. :func:`build` therefore
    does the import once in its preflight, before a single byte is fetched.

    **``ident`` as well as ``text``.** This used to touch ``text`` only, and
    ``ident`` is written into the shipped JSONL beside it. Several adapters build
    ``ident`` from a filesystem path — ``logsamples`` from the repository path,
    ``metasploit`` from the module path, ``cloudsec``/``sigma``/``nuclei``/
    ``elastic`` from relative paths — so an absolute path off this machine in any
    adapter's ``ident`` landed in the corpus with no redaction and no check. It
    does not reach the tokenizer, which reads ``row["text"]`` only; it reaches
    everybody who reads or is sent the corpus file, which is the population this
    is about.

    ``getattr`` rather than attribute access because the field is optional on
    the Document and because this function is called directly by tests with
    minimal stand-ins, and a redactor that requires a particular shape of input
    is a redactor somebody will route around.
    """
    from dataclasses import replace

    if policy is None:
        policy = _email_policy(getattr(doc, "source", ""))

    updates = {}
    text, rewritten, kept = _scrubbed(doc.text, policy)
    if text != doc.text:
        updates["text"] = text

    ident = getattr(doc, "ident", "") or ""
    if ident:
        clean, r_ident, k_ident = _scrubbed(ident, policy)
        rewritten += r_ident
        kept += k_ident
        if clean != ident:
            updates["ident"] = clean

    if tally is not None:
        tally[0] += rewritten
        tally[1] += kept
    return replace(doc, **updates) if updates else doc


def _reredact_mutated(
    collected: dict[str, list[Document]], stats: list[BuildStats]
) -> None:
    """Re-run the chokepoint after the last transform that edits text.

    Expected to be a no-op on every document, and that is exactly why it is
    here: the alternative is an argument that line-granular deletion can never
    join two halves of a literal, and an invariant that rests on an argument
    about a transform somebody else will add later is not an invariant. When it
    is *not* a no-op, that is a finding and it says so.

    A refusal at this point discards the source the same way the document loop
    does. Nothing has been written yet, so the blast radius is identical.
    """
    st_by_name = {s.name: s for s in stats}
    changed = 0
    for name in list(collected):
        policy = _email_policy(name)
        try:
            rebuilt = [_redacted(d, policy) for d in collected[name]]
        except _RedactionRefused as exc:
            why = (f"REDACTION REFUSED after boilerplate removal: {exc}. "
                   f"Stripping a recurring line re-exposed a literal, which "
                   f"means the in-loop redaction was not the last word")
            del collected[name]
            st = st_by_name.get(name)
            if st is not None:
                st.docs = st.chars = st.duplicates = 0
                st.error = why
            _REDACTION_REFUSED.append((name, why))
            print(f"   ! {name}: {why}")
            continue
        changed += sum(1 for old, new in zip(collected[name], rebuilt)
                       if new.text != old.text or new.ident != old.ident)
        collected[name] = rebuilt
        st = st_by_name.get(name)
        if st is not None:
            st.chars = sum(d.n_chars for d in rebuilt)
            st.docs = len(rebuilt)
    if changed:
        print(f"\n  ! REDACTION FIRED AFTER BOILERPLATE REMOVAL on {changed:,} "
              f"document(s). Deleting a recurring line joined two fragments "
              f"into a literal the in-loop pass could not see. The documents are "
              f"clean — this pass is why — but the boilerplate keys are worth "
              f"looking at.")


def _preflight_redaction(*, require_identity_table: bool) -> None:
    """Prove the redactor can work before anything is fetched.

    Two refusals, both before the first byte of download, for the same reason
    :func:`build` refuses an unsatisfiable share cap up front: the condition is
    knowable from the start and discovering it after an hour of fetching costs
    the hour.

    The import is first because :func:`_redacted`'s contract is that a failed
    import fails the build. Left to happen lazily inside the document loop it
    was caught as a per-source ``parse failed`` and the build carried on writing
    unredacted text for forty-seven sources.

    The empty-table check is the fail-open. ``redact_identity`` opens with
    ``pattern = _identity_pattern(); if pattern is None: return text`` — so on a
    host with nothing identifying to find, every document is returned
    byte-for-byte and nothing is logged. A build with an empty table produces
    the same output and the same log as a build where redaction ran and found
    nothing, which is the one shape this codebase has already been bitten by.
    ``_identity_table`` is private and is imported anyway: it is the only way to
    ask the redactor whether it has anything to do, and the alternative is to
    assume.
    """
    try:
        from training.trajectories import _identity_table, redact_identity
        # Called, not merely imported. A name that imports and then raises on
        # its first use is precisely the failure this preflight exists to move
        # to the front of the build, and the empty string is enough to force
        # the table build and the pattern compile.
        redact_identity("")
    except Exception as exc:
        raise SystemExit(
            f"the identity redactor will not import ({type(exc).__name__}: "
            f"{exc}), so no corpus built now could be claimed to be redacted. "
            f"Fix the import rather than building — a corpus that is clean only "
            f"when an optional import succeeds is a corpus nobody can make a "
            f"claim about."
        ) from exc

    forms = len(_identity_table())
    needles = len(_host_email_needles())
    print(f"redaction: {forms} identity form(s) for this host, {needles} host "
          f"email identity/ies, {len(_EMAIL_KEEP)} source(s) exempt from "
          f"third-party email redaction by policy")
    if forms or not require_identity_table:
        if not forms:
            print("  ! identity redaction is INACTIVE and the build was asked "
                  "to proceed anyway. Nothing this run writes carries an "
                  "identity guarantee.", file=sys.stderr)
        return
    raise SystemExit(
        "identity redaction would be a no-op on this host: the table is empty, "
        "so redact_identity returns every document unchanged and says nothing "
        "about it. That is indistinguishable, in the output and in this log, "
        "from a build where redaction ran and found nothing — which is the "
        "exact failure this chokepoint exists to prevent. Pass "
        "require_identity_table=False (--allow-unidentified-host) if this host "
        "genuinely has no identity to protect."
    )


def _email_report() -> str:
    """Per-source address counts and the policy that produced them.

    Printed on every build. A redactor that cannot show what it did on this run
    is a redactor nobody can distinguish from one that was never called, and
    that distinction is what twenty days of a shipped corpus cost.
    """
    lines = ["email policy", "-" * 58,
             f"{'source':<18}{'rewritten':>11}{'kept':>8}   policy"]
    for name in sorted(_EMAIL_COUNTS):
        rewritten, kept = _EMAIL_COUNTS[name]
        if not (rewritten or kept):
            continue
        keep = name in _EMAIL_KEEP
        label = "KEEP (exempt)" if keep else "redact"
        lines.append(f"{name:<18}{rewritten:>11,}{kept:>8,}   {label}")
    lines += [
        "",
        "kept = reserved documentation domains (RFC 2606), role mailboxes "
        "(RFC 2142),",
        "       and the sources exempted by policy:",
    ]
    for name, reason in sorted(_EMAIL_KEEP.items()):
        lines.append(f"  {name}: {reason}")
    return "\n".join(lines)


@dataclass(frozen=True)
class _GateResult:
    """Whether the written corpus passed verification, and what to print."""

    ok: bool
    report: str


def _verify_written(out_dir: Path, stats: list[BuildStats]) -> _GateResult:
    """Scan the JSONL that was just written and decide whether it may be used.

    This is the piece whose absence produced every finding in the audit. The
    redactor was correct, the adapter's fix was correct, and the corpus on disk
    carried four people's email addresses for twenty days — because *nothing
    ever read the output back*. From the code alone, a redactor that was added
    but never run is indistinguishable from one that ran and found nothing. The
    only thing that tells those apart is a pass over the bytes.

    Over the bytes, deliberately, and not over the in-memory documents: that
    makes the ordering of every transform above irrelevant, which is the right
    way to hold this invariant rather than by inspecting call sites.

    Nothing is deleted on a failure. The leaking file is the evidence that names
    the adapter, and :data:`GATE_MARKER` is what stops the corpus being read —
    :func:`read_documents` refuses to stream from a directory whose marker says
    FAIL, so one gate run protects the tokenizer, the shard writer and the data
    loader without any of them having to remember to ask.

    When ``verify.py`` is not importable the build does NOT fail, and that is a
    deliberate, uncomfortable exception: refusing would make this module
    unusable until the scanner lands. It is written into the marker as
    UNVERIFIED and printed in capitals, because the one thing it must not be
    is quiet.
    """
    written = sorted(p.name for p in out_dir.glob("*.jsonl"))
    marker = out_dir / GATE_MARKER
    try:
        from .verify import host_needles, render, verify_corpus
    except Exception as exc:
        body = (f"CORPUS GATE: UNVERIFIED — training.corpus.verify is not "
                f"importable ({type(exc).__name__}: {exc}).\n"
                f"  {len(written)} file(s) were written and NOTHING read them "
                f"back. Do not publish a checkpoint trained on this directory: "
                f"a redactor that was added but never run looks exactly like "
                f"one that ran and found nothing, and this build cannot tell "
                f"you which it was.")
        _write_marker(marker, "UNVERIFIED", body)
        return _GateResult(True, body)

    try:
        needles = host_needles()
        leaks = verify_corpus(out_dir, needles=needles)
    except Exception as exc:
        # Fail CLOSED. A scanner that crashed did not certify anything, and
        # "we could not check" has to resolve the same way as "it is dirty".
        body = (f"CORPUS GATE: FAILED — the verifier itself raised "
                f"{type(exc).__name__}: {exc}. Nothing was certified, so "
                f"nothing may be trained on. This is not a verifier bug to work "
                f"around; until it answers, the corpus is unverified.")
        _write_marker(marker, "FAIL", body)
        return _GateResult(False, body)

    # Split on what becomes weights. A leak in a *.jsonl is a training document
    # and the gate's whole purpose; a leak in anything else in the directory
    # ships with the corpus but is read by nothing that trains. The distinction
    # matters because PROVENANCE.md deliberately names each source's author and
    # URL — for `ownrepos` that is this operator's own GitHub handle, and it is
    # there as the attribution the MIT licence is satisfied by. A gate that
    # refused its own licence record would have exactly one stable state, which
    # is switched off. So those are reported in full and not enforced, and the
    # reader decides.
    docs_leaks = [leak for leak in leaks if leak.path.endswith(".jsonl")]
    other_leaks = [leak for leak in leaks if not leak.path.endswith(".jsonl")]

    notes: list[str] = []
    gaps = needles.gaps()
    if gaps:
        notes += [
            "",
            f"INSTRUMENT INCOMPLETE — no needles were derived for: "
            f"{', '.join(gaps)}. '0 leaks' from a thin table means nothing was "
            f"looked for, which is the same fail-open as a redactor with an "
            f"empty table. This is a statement about the scanner, not about the "
            f"corpus, so it does not fail the build — it withholds the PASS.",
        ]
    if other_leaks:
        notes += [
            "",
            f"Also found, OUTSIDE the training documents ({len(other_leaks)} "
            f"occurrence(s)). Nothing trains on these files, so they do not "
            f"fail the build; they do ship beside the corpus:",
            render(other_leaks),
        ]

    # Provenance, before the verdict. One kind of finding is ambiguous by
    # construction — an RFC1918 address bound here is the same bytes as one used
    # as an example in an Nmap script — so it is resolved by asking whether the
    # value is in that source's own raw upstream download, which was fetched
    # from the upstream and has never seen this machine's network config. The
    # rule lives in training.corpus.provenance so that this gate,
    # training.data.require_clean_corpus and scripts/gate_corpus.py cannot
    # disagree about it; three copies of a security policy is three chances for
    # the quiet one to be wrong. identity/email/mac/ipv6-global/volume are never
    # exonerable there, whatever any cache says.
    exonerated: list = []
    if docs_leaks:
        try:
            from .provenance import partition
            # partition() returns (leak, why) PAIRS on both sides. Unpack the
            # real side back to bare leaks — assigning the pairs straight to
            # docs_leaks made the failure path do `leak.path` on a tuple, which
            # this module's own gate tests caught immediately.
            real_pairs, exonerated = partition(docs_leaks)
            docs_leaks = [leak for leak, _ in real_pairs]
        except Exception as exc:  # fail CLOSED: an unavailable rule excuses nothing
            notes += ["", f"Provenance check unavailable ({type(exc).__name__}: "
                          f"{exc}); every finding is treated as real."]
    if exonerated:
        notes += [
            "",
            f"Exonerated by provenance ({len(exonerated)} occurrence(s)) — present "
            f"in the source's own raw upstream download, so the upstream shipped "
            f"them and they are not this host's data. Printed because 'passed' and "
            f"'found nothing' are different sentences:",
            *(f"  {leak.kind:<13} {leak.path}  {leak.fingerprint}  — {why}"
              for leak, why in exonerated),
        ]

    if docs_leaks:
        files = sorted({leak.path for leak in docs_leaks})
        body = "\n".join([
            f"CORPUS GATE: FAILED — {len(docs_leaks):,} leak(s) in "
            f"{len(files)} training file(s) this build just wrote.",
            "",
            render(docs_leaks),
            "",
            "Values are reported as kind, length and a sha256 prefix and never "
            "printed: the audit that found these problems created a new leak by "
            "writing its own needle table to a JSON file, and this gate will "
            "not repeat it. Paths are scrubbed by the same needle set, because "
            "this corpus lives under a volume whose name is itself a needle.",
            "",
            "Nothing was deleted. The files below are the evidence that names "
            "the leaking adapter:",
            *(f"  {name}" for name in files),
            "",
            f"{GATE_MARKER} now says FAIL, and read_documents() refuses to "
            f"stream from this directory until it does not. Fix the adapter and "
            f"rebuild; do not delete the marker.",
            *notes,
        ])
        _write_marker(marker, "FAIL", body)
        return _GateResult(False, body)

    docs = sum(s.docs for s in stats if s.docs)
    verdict = "UNVERIFIED" if gaps else "PASS"
    body = "\n".join([
        f"CORPUS GATE: {verdict} — {len(written)} training file(s), "
        f"{docs:,} document(s) read back from disk and scanned for this host's "
        f"identifiers, addresses, networks and paths. 0 leaks in the training "
        f"documents.",
        *notes,
    ])
    _write_marker(marker, verdict, body)
    return _GateResult(True, body)


def _write_marker(path: Path, verdict: str, body: str) -> None:
    """Record the gate's verdict beside the corpus it describes.

    Beside the data for the same reason PROVENANCE.md is: a verdict that lives
    somewhere else drifts out of date, and the directory is what every consumer
    actually opens. The body is the printed report, which carries fingerprints
    and never values.
    """
    stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    with contextlib.suppress(OSError):
        path.write_text(f"{verdict}\n{stamp}\n\n{body}\n", encoding="utf-8")


def _refuse_failed_gate(clean_dir: Path) -> None:
    """Raise if this directory's last build failed verification.

    The honest place for this check. ``read_documents`` is the one door the
    tokenizer and the shard writer are documented to come through, so a verdict
    enforced here reaches all of them; a verdict enforced in each of them
    reaches whichever ones remembered.
    """
    marker = clean_dir / GATE_MARKER
    try:
        first = marker.read_text(encoding="utf-8").split("\n", 1)[0].strip()
    except OSError:
        return
    if first == "FAIL":
        raise CorpusGateFailed(
            f"{marker} says the last build of this corpus FAILED verification, "
            f"so it will not be streamed. Read the marker for the fingerprints, "
            f"fix the adapter it names and rebuild. Deleting the marker makes "
            f"the refusal go away and the leak stay."
        )


def _note_source(st: BuildStats) -> None:
    note = f"   {st.docs:,} docs  {st.chars/1e6:.2f}M chars"
    if st.duplicates:
        note += f"  ({st.duplicates:,} duplicates dropped)"
    print(note)


def _note_if_emptied(st: BuildStats, before: int, kept: list[Document], why: str) -> None:
    """Make a source that a cap reduced to nothing impossible to miss.

    :func:`balance_report` builds its register table from ``[s for s in stats if
    s.docs]`` and its failure list from ``[s for s in stats if s.error]``, so a
    source trimmed to zero documents with no error set appears in neither — it
    vanishes from the output entirely and reads, to anyone looking, like a source
    that simply had nothing to give. Recording it as an error is not a
    mischaracterisation: a whole upstream is missing from the corpus, and this is
    the only channel the report already watches.
    """
    if kept or not before:
        return
    note = f"reduced to 0 documents by {why} — the whole source is out of the corpus"
    st.error = f"{st.error}; {note}" if st.error else note


def _cap_source_share(
    collected: dict[str, list[Document]], stats: list[BuildStats], max_share: float
) -> None:
    """No single source may exceed ``max_share`` of the corpus by characters.

    RFC is the reason this exists. At 505M chars it was 64% of the whole corpus
    on its own — protocol text is genuinely valuable, but a model trained on a
    corpus that is two-thirds one source learns that source's voice and little
    else. This is the same argument the man-page family cap makes one level down,
    applied across sources: breadth is what a from-scratch model has instead of
    scale, and one source drowning the rest throws that away.

    A cap, not an exclusion — RFC keeps its full share of the ceiling. What is
    trimmed is the excess beyond it. Everything dropped is logged; a silent cap
    reads as coverage that is not there.

    **What survives is a representative sample, not the front of the list**, and
    that is this function's second scar. It used to walk ``docs`` in the order
    the adapter yielded them and keep documents until the ceiling ran out. For a
    source that yields in any meaningful order this is not a cap, it is a filter
    on that order — and every large adapter here yields in a meaningful order,
    because a stable order is what makes a build reproducible.

    It cost the corpus the modern internet. ``rfc`` yields numerically, RFC 1
    upward, and at 14.2% of the corpus it is the source this cap actually binds.
    The built v6 corpus held RFC 1 through RFC 3166 and **not one of the 6,500
    after it**: no TLS 1.3 (8446), no HTTP/2 (9113), no HTTP/3 or QUIC (9114,
    9000), no OAuth 2.0 (6749), no JWT (7519). All 9,832 were fetched and cached;
    the cap threw away everything published after 2001. A model whose single
    largest source is thirty-year-old protocol text learns the internet of 1998.

    :mod:`~training.corpus.sources.nvd` hit the same wall from the other side and
    worked around it locally, by emitting in a deterministic shuffled order so
    that any prefix of its stream is representative. That fix was right and it is
    still there; this one generalises it, so the next adapter to grow past the
    ceiling does not have to rediscover it. Selection is by ``blake2b`` of the
    document identity — deterministic across runs and machines, unlike
    :func:`hash`, which is salted per process — and the survivors are then
    emitted in their original order, so the cap changes *which* documents land
    and never the order they land in.

    **The ceiling is solved against the total the trim leaves behind**, not the
    one it starts from, and that distinction is the whole of this function's
    history. Trimming shrinks the corpus, so every surviving source's *share*
    rises afterwards. Computing ``ceiling = total * max_share`` once from the
    pre-trim total and trimming to it left rfc — 64% of 789k chars under a 30%
    cap — sitting at **50%** of a corpus 40% smaller, while printing that it had
    been "trimmed to the 30% ceiling". :func:`_cap_register_share` hit this first
    and answered it with a fixed point; this function, the one that is on by
    default, was left with the single pass.
    """
    sizes = {name: sum(d.n_chars for d in docs)
             for name, docs in collected.items() if docs}
    total = sum(sizes.values())
    if not total:
        return

    # T = Σ min(available_s, max_share · T) is monotone and bounded above by the
    # pre-trim total, so iterating down from it converges onto the largest fixed
    # point — the one that keeps the most text. Same shape, same reasoning, as
    # the register cap below; two solvers of one problem would drift apart.
    #
    # It converges only where the cap is reachable, and reachability is pure
    # arithmetic: n sources cannot all be under a 1/n share. Below that line
    # every source is over the ceiling at every T, the map is T -> n·max_share·T
    # with n·max_share < 1, and it walks the ceiling to zero. build() refuses
    # that configuration before fetching; this branch is what is left when
    # sources die at runtime and the survivors are too few, and there a raise
    # would discard a whole build over a condition the operator did not choose.
    if len(sizes) * max_share <= 1.0:
        largest = max(sizes, key=lambda n: sizes[n])
        print(f"\n  SOURCE CAP NOT APPLIED: only {len(sizes)} source(s) produced "
              f"anything, and {len(sizes)} sources cannot all sit under "
              f"{max_share:.0%} of one corpus — an equal split is already "
              f"{1 / len(sizes):.0%} each. Trimming toward a ceiling that cannot "
              f"be reached walks it to zero and deletes the corpus, so nothing "
              f"was trimmed: {largest} stands at {sizes[largest] / total:.0%}. "
              f"Fix the failed sources above before training on this.")
        return

    # 200 passes rather than the register cap's 10, and the difference is not
    # drift: the contraction rate here is (number of sources over the cap) ×
    # max_share, which the reachability line above allows to reach 0.9. At that
    # rate ten passes leave a third of the initial gap and the ceiling would be
    # visibly wrong. The loop exits on convergence, so the extra passes cost
    # nothing in the ordinary case of one source over the cap.
    resolved = float(total)
    for _ in range(200):
        nxt = sum(min(float(c), max_share * resolved) for c in sizes.values())
        if abs(nxt - resolved) < 1.0:
            break
        resolved = nxt
    ceiling = int(max_share * resolved)

    st_by_name = {s.name: s for s in stats}
    dropped: dict[str, int] = {}
    for name, docs in collected.items():
        if sizes.get(name, 0) <= ceiling:
            continue
        kept: list[Document] = []
        running = 0
        # Spread the keep across the whole source instead of the front of it.
        # Keyed on ident where the adapter set one and on the text otherwise, so
        # a source that leaves ident blank still gets a stable, well-distributed
        # order rather than falling back to yield order.
        order = sorted(
            range(len(docs)),
            key=lambda i: hashlib.blake2b(
                (docs[i].ident or docs[i].text[:512]).encode("utf-8"),
                digest_size=8,
            ).digest(),
        )
        chosen: set[int] = set()
        for i in order:
            doc = docs[i]
            if running + doc.n_chars > ceiling:
                st_by_name[name].dropped_for_balance += 1
                continue
            running += doc.n_chars
            chosen.add(i)
        # Back into the adapter's own order: the cap decides membership, never
        # sequence. A corpus whose document order changed with its size would
        # make every build diff unreadable.
        kept = [docs[i] for i in range(len(docs)) if i in chosen]
        collected[name] = kept
        st_by_name[name].chars = running
        st_by_name[name].docs = len(kept)
        dropped[name] = len(docs) - len(kept)
        _note_if_emptied(st_by_name[name], len(docs), kept,
                         f"--max-source-share {max_share:g}")

    if not dropped:
        return

    # Report the share that was ACHIEVED, never the one that was requested. The
    # old line said "trimmed to the 30% ceiling", which was true of the number
    # asked for and false of the corpus on disk — and a cap nobody can tell did
    # not hold is worse than no cap at all.
    after = sum(s.chars for s in stats if s.docs) or 1
    print(f"\n  source cap at {max_share:.0%} of the corpus "
          f"({total / 1e6:.1f}M -> {after / 1e6:.1f}M chars):")
    for name in sorted(dropped):
        st = st_by_name[name]
        print(f"    {name:<14} {sizes[name] / 1e6:>7.1f}M ({sizes[name] / total:>4.0%}) -> "
              f"{st.chars / 1e6:>7.1f}M ({st.chars / after:>4.0%}), "
              f"-{dropped[name]:,} docs")

    # The fixed point holds every trimmed source at or below `ceiling`, but
    # documents are granular: a source stops one document short of its ceiling
    # and that lifts every other source's share by a hair. Drift wider than the
    # largest single document can explain means the solve is wrong rather than
    # the packing, and the one outcome this rewrite exists to prevent is a cap
    # that prints success without capping. So it raises rather than prints.
    biggest = max((d.n_chars for docs in collected.values() for d in docs), default=0)
    slack = len(dropped) * biggest / after
    for name in dropped:
        share = st_by_name[name].chars / after
        if share > max_share + slack:
            raise SourceError(
                f"the source cap did not hold: {name} is {share:.1%} of the "
                f"corpus after trimming to a {max_share:.0%} ceiling, which the "
                f"post-trim solve above should have made impossible. Refusing to "
                f"report a cap that did not happen.")


def _fair_shares(amounts: Counter[str], ceiling: int) -> dict[str, float]:
    """Divide ``ceiling`` among contributors so none is starved by a bigger one.

    Max-min fair, which is the water-filling allocation: everyone is offered an
    equal share, whoever wants less than the offer keeps all of it, and what they
    left is re-offered to the rest. A source smaller than its equal share is
    therefore untouched, and the sources actually responsible for a register
    being over target are the ones that pay for it.

    Strictly proportional allocation was the other candidate and is the wrong one
    here, for the reason the register cap exists in the first place: it shrinks
    *every* contributor, so a 600 KB source would lose a fifth of itself to make
    room for a 35 MB one. Breadth is what this corpus has instead of scale.

    One ascending pass is the whole algorithm — the offer can only grow as the
    small contributors take less than it, so a source passed over once never
    needs revisiting. Ties break by name so two equal sources cannot swap places
    between two builds of the same corpus.
    """
    shares: dict[str, float] = {}
    remaining = float(ceiling)
    queue = sorted(amounts, key=lambda n: (amounts[n], n))
    for i, name in enumerate(queue):
        offer = remaining / (len(queue) - i)
        take = min(float(amounts[name]), offer)
        shares[name] = take
        remaining -= take
    return shares


def _cap_register_share(
    collected: dict[str, list[Document]], stats: list[BuildStats], multiple: float
) -> None:
    """Cap each register at ``multiple`` times its target share.

    The middle ground between the two bad options. ``--balance`` scales every
    register down to whichever is scarcest relative to target, which discarded
    78% of the corpus when ADVERSARY was the constraint. Doing nothing leaves
    ADVISORY at 37% and SYSTEM at 51% against targets of 9% and 24%, because NVD
    is 167M characters and the RFC series is half a gigabyte.

    Per-*source* capping cannot fix that: SYSTEM is over target because three
    separate sources (rfc, kerneldocs, manpages) are each legitimately large,
    and no per-source ceiling that keeps them individually reasonable keeps
    their sum reasonable. The register is the level the imbalance exists at, so
    it is the level to control it at.

    Trimming only — a register under target is left alone and reported as a gap,
    because the alternative is repeating text, and repeated text in a corpus
    this size is memorised rather than learned.
    """
    by_register: Counter[Register] = Counter()
    for docs in collected.values():
        for d in docs:
            by_register[d.register] += d.n_chars
    total = sum(by_register.values())
    if not total:
        return

    # Solve for the ceiling as a FIXED POINT, not in one shot.
    #
    # A single pass computes ceilings from the pre-trim total, then trims — and
    # the total shrinks, so every surviving register's *share* rises. The first
    # version of this did exactly that and pushed SYSTEM from 50.9% to 59.4%,
    # making the imbalance worse while reporting that it had capped it.
    #
    # T = Σ min(available_r, k · target_r · T) is monotone decreasing from
    # T = Σ available_r, so iterating converges from above. Ten passes is far
    # more than enough at this precision and costs nothing.
    keys = [r for r in by_register if REGISTER_TARGETS.get(r, 0.0) > 0]

    # The same reachability trap the source cap has, one level up, and it has to
    # be checked before iterating rather than after. A positive fixed point
    # exists only if f(T) rises above T somewhere: near zero every targeted
    # register is over its ceiling, so f has slope Σ(target_r · multiple) there,
    # plus whatever the untargeted registers contribute as a constant. With
    # neither — a build whose registers do not span the targets, which is what
    # `--only sigma --max-register-multiple 1.6` is, DETECTION alone at 0.13 x
    # 1.6 = 0.21 — the map is a contraction onto zero and ten passes of it turn
    # the ceiling into a rounding error that deletes the corpus.
    spanned = sum(REGISTER_TARGETS[r] for r in keys) * multiple
    untargeted = sum(by_register[r] for r in by_register if r not in keys)
    if spanned < 1.0 and not untargeted:
        print(f"\n  REGISTER CAP NOT APPLIED: the registers in this build cover "
              f"only {spanned / multiple:.0%} of the target mix, so at "
              f"{multiple:.1f}x every one of them is over its ceiling at every "
              f"size and the ceiling solves to zero. Capping here would delete "
              f"the corpus rather than balance it. Build the missing registers, "
              f"or raise --max-register-multiple above "
              f"{1 / sum(REGISTER_TARGETS[r] for r in keys):.1f}.")
        return

    resolved = float(total)
    for _ in range(10):
        nxt = sum(min(by_register[r], REGISTER_TARGETS[r] * multiple * resolved)
                  for r in keys)
        nxt += sum(by_register[r] for r in by_register if r not in keys)
        if abs(nxt - resolved) < 1.0:
            break
        resolved = nxt

    ceilings: dict[Register, int] = {}
    for reg in keys:
        ceiling = int(REGISTER_TARGETS[reg] * multiple * resolved)
        if by_register[reg] > ceiling:
            ceilings[reg] = ceiling
    if not ceilings:
        return

    # Split each ceiling across the sources that feed the register BEFORE
    # trimming anything, so every source has a budget of its own.
    #
    # The trim used to run off one shared per-register counter in whatever order
    # `collected` happened to be in — which is discover_sources()' name sort. The
    # first source alphabetically therefore ate the register's entire ceiling and
    # the ones after it were dropped document by document until nothing was left.
    # Measured on the real corpus at `--max-register-multiple 1.0`, that removed
    # manpages and capec from the build ENTIRELY: kerneldocs (34.8M, sorts
    # before manpages) took all of SYSTEM, attackactors took all of ADVERSARY,
    # and the printed register table read perfectly on target while two whole
    # upstreams had left the corpus without one line of output saying so.
    per_register: dict[Register, Counter] = {}
    for name, docs in collected.items():
        for d in docs:
            if d.register in ceilings:
                per_register.setdefault(d.register, Counter())[name] += d.n_chars
    budgets: dict[tuple[str, Register], float] = {}
    for reg, amounts in per_register.items():
        for name, allowance in _fair_shares(amounts, ceilings[reg]).items():
            budgets[(name, reg)] = allowance

    spent: Counter[Register] = Counter()
    dropped: Counter[str] = Counter()
    st_by_name = {s.name: s for s in stats}
    for name, docs in collected.items():
        kept: list[Document] = []
        used: Counter[Register] = Counter()
        for doc in docs:
            cap = budgets.get((name, doc.register))
            if cap is not None and used[doc.register] + doc.n_chars > cap:
                st_by_name[name].dropped_for_balance += 1
                dropped[name] += 1
                continue
            used[doc.register] += doc.n_chars
            kept.append(doc)
        spent.update(used)
        collected[name] = kept
        st_by_name[name].chars = sum(d.n_chars for d in kept)
        st_by_name[name].docs = len(kept)
        _note_if_emptied(st_by_name[name], len(docs), kept,
                         f"--max-register-multiple {multiple:g}")

    print(f"\n  register cap at {multiple:.1f}x target:")
    for reg, ceiling in sorted(ceilings.items(), key=lambda kv: kv[0].value):
        print(f"    {reg.value:<11} {by_register[reg]/1e6:>7.1f}M -> "
              f"{spent[reg]/1e6:>6.1f}M  (ceiling {ceiling/1e6:.0f}M)")
    # Per source as well as per register, the way _apply_balance already reports
    # its drops. The register totals alone cannot tell you WHO paid for them, and
    # who paid is the thing that goes wrong here.
    for name in sorted(dropped):
        st = st_by_name[name]
        print(f"    -{dropped[name]:,} docs from {name} ({st.register.value}), "
              f"{st.docs:,} left")


def _strip_boilerplate(
    collected: dict[str, list[Document]], stats: list[BuildStats]
) -> None:
    """Remove corpus-wide line furniture after every source is collected.

    Runs here, once, rather than in each adapter, because a line is only
    boilerplate relative to the *whole* corpus: the IETF copyright block is
    furniture because it spans thousands of RFCs, and no single adapter can see
    that. Two passes are unavoidable — you cannot know a line recurs until you
    have read everything — but both are cheap line scans over text already in
    memory.
    """
    from dataclasses import replace as _replace

    from .boilerplate import find_boilerplate

    all_docs = [d for docs in collected.values() for d in docs]
    if not all_docs:
        return
    bp = find_boilerplate(all_docs)
    if not bp.keys:
        return

    print("\n" + bp.report())
    st_by_name = {s.name: s for s in stats}
    for name, docs in collected.items():
        rebuilt: list[Document] = []
        for doc in docs:
            stripped = bp.strip(doc.text)
            # A document that was *entirely* boilerplate (a bare notice page)
            # drops out rather than becoming an empty string.
            if len(stripped) < 40:
                continue
            rebuilt.append(doc if stripped == doc.text else _replace(doc, text=stripped))
        collected[name] = rebuilt
        st_by_name[name].chars = sum(d.n_chars for d in rebuilt)
        st_by_name[name].docs = len(rebuilt)


def _apply_balance(collected: dict[str, list[Document]], stats: list[BuildStats]) -> None:
    """Subsample over-represented registers toward target. Never repeats.

    Repetition is the tempting fix for an under-represented register and it is
    the wrong one: in a corpus this size the model memorises repeated passages,
    and held-out loss then reports a number that has nothing to do with
    generalisation. Under-representation stays visible in the report as a gap to
    collect more source for.
    """
    by_register: dict[Register, int] = Counter()
    for docs in collected.values():
        for d in docs:
            by_register[d.register] += d.n_chars
    total = sum(by_register.values())
    if not total:
        return

    # The binding constraint: the register furthest BELOW its target sets the
    # scale everything else can be trimmed to. Trimming to an absolute target
    # would throw away most of the corpus for no reason.
    scale = min(
        (by_register[r] / (REGISTER_TARGETS[r] * total)
         for r in by_register
         if REGISTER_TARGETS.get(r, 0) > 0 and by_register[r] > 0),
        default=1.0,
    )
    if scale <= 0:
        return

    budget = {r: REGISTER_TARGETS.get(r, 0) * total * scale for r in by_register}
    spent: dict[Register, float] = Counter()
    st_by_name = {s.name: s for s in stats}

    for name, docs in collected.items():
        keep: list[Document] = []
        for doc in docs:
            allowance = budget.get(doc.register, 0)
            if allowance and spent[doc.register] + doc.n_chars > allowance:
                st_by_name[name].dropped_for_balance += 1
                continue
            spent[doc.register] += doc.n_chars
            keep.append(doc)
        collected[name] = keep
        st_by_name[name].docs = len(keep)
        st_by_name[name].chars = sum(d.n_chars for d in keep)

    dropped = sum(s.dropped_for_balance for s in stats)
    if dropped:
        # No silent caps: say exactly what went, and from where.
        print(f"\nbalance: dropped {dropped:,} documents to approach register targets")
        for s in stats:
            if s.dropped_for_balance:
                print(f"  -{s.dropped_for_balance:,} from {s.name} ({s.register.value})")

        kept = sum(s.chars for s in stats)
        lost = 1 - (kept / total) if total else 0
        if lost > 0.5:
            scarcest = min(
                (r for r in by_register if REGISTER_TARGETS.get(r, 0) > 0),
                key=lambda r: by_register[r] / REGISTER_TARGETS[r],
            )
            print(
                f"\n  WARNING: balancing discarded {lost:.0%} of the corpus.\n"
                f"  The binding constraint is {scarcest.value!r} — every other register\n"
                f"  is scaled down to match the one that is scarcest relative to target.\n"
                f"  For PRETRAINING this is usually the wrong trade: unique text is the\n"
                f"  scarce resource at this model size, and a perfectly balanced corpus\n"
                f"  a fifth the size trains a worse model than a skewed larger one.\n"
                f"  Prefer: build unbalanced for the language model, use --balance only\n"
                f"  for fitting the tokenizer (where the register mix decides the merges\n"
                f"  and the cost of dropping text is near zero), and treat the register\n"
                f"  report as a shopping list for what to collect next."
            )


def _count_documents(path: Path) -> tuple[int, int]:
    """``(documents, characters)`` of a built JSONL, counted back off disk.

    Only ever reached for a source the current run did not rebuild — a ``--only``
    build's untouched neighbours — so a full build pays nothing for it.
    """
    docs = chars = 0
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            docs += 1
            chars += len(json.loads(line)["text"])
    return docs, chars


def _write_provenance(
    out_dir: Path, specs: list[SourceSpec], stats: list[BuildStats]
) -> list[str]:
    """Record where every byte came from and under what licence.

    Written on every build, next to the data, because a provenance file that
    lives somewhere else drifts out of date and a corpus whose licensing cannot
    be reconstructed is a corpus that cannot be published.

    **It describes the directory, not the run**, and ``specs`` is therefore every
    discovered source rather than the ones selected this time. Handed the
    filtered list, ``--only sigma`` rewrote this file to a one-row table and
    deleted the licence record for fourteen files that were still on disk and
    still being trained on. A source this run did not rebuild keeps its row,
    counted back out of its own JSONL and named below the table as carried over:
    a directory holding two builds is a fact the record has to state, not one it
    can quietly drop.

    Returns the ``*.jsonl`` files that belong to no source at all, for the
    caller to report. They are not deleted and not given a row — there is no
    licence to give them, which is the whole problem with them.
    """
    by_name = {s.name: s for s in stats}
    lines = [
        "# Corpus provenance",
        "",
        "Generated by `training/corpus/build.py`. Every source states its upstream",
        "licence; the build refuses a source that declares none.",
        "",
        "| Source | Register | Side | Documents | Chars | Licence | Upstream |",
        "|---|---|---|---:|---:|---|---|",
    ]
    carried: list[str] = []
    shown: list[SourceSpec] = []
    for spec in specs:
        st = by_name.get(spec.name)
        path = out_dir / f"{spec.name}.jsonl"
        if st is not None:
            docs, chars = st.docs, st.chars
        elif path.is_file():
            docs, chars = _count_documents(path)
            carried.append(spec.name)
        else:
            continue
        shown.append(spec)
        lines.append(
            f"| `{spec.name}` | {spec.register.value} | {spec.side.value} | "
            f"{docs:,} | {chars:,} | {spec.license} | {spec.url} |"
        )

    if carried:
        lines += [
            "",
            "## Carried over from an earlier build",
            "",
            "This run did not rebuild these sources; their rows were counted back out",
            "of the files already in this directory, which were written by a previous",
            "build and may not share this run's cleaning, caps or balance.",
            "",
        ] + [f"- `{name}`" for name in carried]

    known = {s.name for s in specs}
    orphans = sorted(p.name for p in out_dir.glob("*.jsonl") if p.stem not in known)
    if orphans:
        lines += [
            "",
            "## Files with no source in this tree",
            "",
            "No adapter under `training/corpus/sources/` claims these, so their licence",
            "cannot be stated. Every consumer of this corpus still reads them.",
            "",
        ] + [f"- `{name}`" for name in orphans]

    notes = [f"- **{s.name}** — {s.notes}" for s in shown if s.notes]
    if notes:
        lines += ["", "## Notes", ""] + notes
    (out_dir / "PROVENANCE.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return orphans


def balance_report(stats: list[BuildStats]) -> str:
    """Observed composition against target. The output that matters.

    Read this before every training run. A register far under target is the
    tokenizer result from the first attempt, visible in advance instead of
    four steps downstream.
    """
    ok = [s for s in stats if s.docs]
    total_chars = sum(s.chars for s in ok) or 1

    by_reg: Counter[Register] = Counter()
    by_side: Counter[Side] = Counter()
    for s in ok:
        by_reg[s.register] += s.chars
        by_side[s.side] += s.chars

    lines = ["register coverage", "-" * 58,
             f"{'register':<12}{'chars':>12}{'share':>9}{'target':>9}{'drift':>10}"]
    for reg in Register:
        target = REGISTER_TARGETS.get(reg, 0.0)
        if not target and not by_reg[reg]:
            continue
        share = by_reg[reg] / total_chars
        drift = share - target
        flag = "" if abs(drift) < 0.05 else ("  LOW" if drift < 0 else "  high")
        lines.append(f"{reg.value:<12}{by_reg[reg]:>12,}{share:>8.1%}"
                     f"{target:>9.0%}{drift:>+9.1%}{flag}")

    red = by_side[Side.RED] / total_chars
    blue = by_side[Side.BLUE] / total_chars
    neutral = by_side[Side.NEUTRAL] / total_chars
    offensive = red / (red + blue) if (red + blue) else 0.0

    lines += [
        "", "offence / defence balance", "-" * 58,
        f"red {red:.1%}   blue {blue:.1%}   neutral {neutral:.1%}",
        f"red share of the non-neutral corpus: {offensive:.0%}  (target ~60%)",
        "", f"total: {total_chars/1e6:.1f}M chars across {sum(s.docs for s in ok):,} documents",
    ]

    failed = [s for s in stats if s.error]
    if failed:
        lines += ["", "sources that failed", "-" * 58]
        lines += [f"  {s.name}: {s.error}" for s in failed]

    return "\n".join(lines)


def read_documents(clean_dir: Path, *, registers: Iterable[Register] | None = None) -> Iterator[dict]:
    """Stream built documents back, optionally filtered by register.

    The tokenizer and the shard writer both read through here rather than
    globbing raw text, so metadata survives all the way to the point where it
    can be used — which is what lets a tokenizer be fitted to a deliberately
    chosen register mix instead of whatever happened to be on disk.

    It is also where the verification gate is enforced, for that same reason:
    this is the one door every consumer is documented to come through, so a
    verdict checked here reaches all of them, while a verdict checked in each of
    them reaches whichever ones remembered. A directory whose last build failed
    verification is not streamed at all. The check fires on the first
    ``next()`` rather than at call time, because this is a generator — which is
    soon enough, since nothing can consume a document without reaching it.
    """
    _refuse_failed_gate(clean_dir)
    wanted = {r.value for r in registers} if registers else None
    for path in sorted(clean_dir.glob("*.jsonl")):
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                row = json.loads(line)
                if wanted and row.get("register") not in wanted:
                    continue
                yield row


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Build the Whetstone corpus.")
    # Relative, through the repository's own `data` symlink, which is what this
    # module's usage line has always documented. The absolute default these
    # replaced named one machine's mount point — wrong for anybody else, and a
    # host identifier in a published source file, which is what makes the
    # self-scan in tests/test_build_chokepoint.py possible at all. Every caller
    # in scripts/ passes --out explicitly, so nothing depended on the old value.
    p.add_argument("--out", type=Path, default=Path("data/corpus/clean"))
    p.add_argument("--cache", type=Path, default=Path("data/corpus/raw"))
    p.add_argument("--only", nargs="*", help="build only these sources")
    p.add_argument("--balance", action="store_true",
                   help="subsample over-represented registers toward target")
    p.add_argument("--max-register-multiple", type=float, default=0.0,
                   help="cap each register at N times its target share "
                        "(e.g. 1.6). Trims the over-represented without "
                        "scaling everything to the scarcest, which --balance "
                        "does and which cost 78%% of the corpus.")
    p.add_argument("--max-source-share", type=float, default=0.30,
                   help="cap any single source at this fraction of the corpus "
                        "(0 disables). RFC alone was 64%% without it.")
    p.add_argument("--source-timeout", type=float, metavar="SECONDS",
                   default=DEFAULT_SOURCE_TIMEOUT,
                   help="wall-clock budget per source (default "
                        f"{DEFAULT_SOURCE_TIMEOUT:.0f}s). A source that exceeds "
                        "it is killed, skipped and re-listed after the report. "
                        "0 runs every source in-process with no budget, which "
                        "is how one runaway regex once burned 7.5 hours.")
    p.add_argument("--allow-unidentified-host", action="store_true",
                   help="build even though identity redaction would be a no-op "
                        "on this host (an empty identity table). Nothing the "
                        "build writes then carries an identity guarantee, and "
                        "the log says so.")
    p.add_argument("--report", action="store_true",
                   help="report on an existing build without fetching")
    args = p.parse_args(argv)

    if args.report:
        counts: dict[tuple[str, str, str], list[int]] = {}
        for row in read_documents(args.out):
            key = (row["source"], row["register"], row["side"])
            slot = counts.setdefault(key, [0, 0])
            slot[0] += 1
            slot[1] += len(row["text"])
        stats = [
            BuildStats(name=n, register=Register(r), side=Side(s), license="",
                       docs=c[0], chars=c[1])
            for (n, r, s), c in sorted(counts.items())
        ]
        print(balance_report(stats))
        return 0

    build(args.out, args.cache, only=args.only, balance=args.balance,
          max_source_share=args.max_source_share,
          max_register_multiple=args.max_register_multiple,
          source_timeout=args.source_timeout,
          require_identity_table=not args.allow_unidentified_host)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
