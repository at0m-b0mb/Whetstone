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
import importlib
import json
import multiprocessing
import os
import pkgutil
import shutil
import signal
import sys
import tempfile
import time
from collections import Counter
from dataclasses import dataclass
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
    "DEFAULT_SOURCE_TIMEOUT",
]


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
        with docs_path.open("w", encoding="utf-8") as fh:
            try:
                for doc in spec.documents(path):
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
    workdir = Path(tempfile.mkdtemp(prefix=f"whetstone-corpus-{spec.name}-"))
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
                         partial=status.get("error", ""))
    finally:
        # Unconditional: a KeyboardInterrupt in the parent must not leave a
        # child holding a core, and setsid means the child no longer shares the
        # terminal's Ctrl-C.
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
) -> list[BuildStats]:
    """Fetch, clean, dedupe and write the corpus. Returns per-source stats.

    ``source_timeout`` is the per-source wall-clock budget in seconds. A source
    that exceeds it is killed, skipped, recorded in its BuildStats.error and
    re-listed after the balance report — the same treatment a failed fetch gets,
    because from the corpus's point of view they are the same event. 0 disables
    the watchdog and runs every source in this process, which is the behaviour
    that let one runaway regex burn seven and a half hours.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)

    _TIMEOUTS.clear()
    _STALE_REMOVED.clear()
    all_specs = discover_sources()
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
        kept: list[Document] = []
        with _source_documents(spec, cache_dir, budget) as run:
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
                    # degrades: a survivor raises instead of being written, and
                    # the raise is caught below as a source-level failure, which
                    # is the correct blast radius — one bad source is skipped
                    # and named, the corpus is not silently contaminated.
                    doc = _redacted(doc)
                    fp = doc.fingerprint
                    if fp in seen:
                        st.duplicates += 1
                        continue
                    seen.add(fp)
                    kept.append(doc)
                    st.docs += 1
                    st.chars += doc.n_chars
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
                st.error = f"parse failed after {st.docs} docs: {run.partial}"
                print(f"   ! {st.error}")

        collected[spec.name] = kept
        _note_source(st)
        if st.docs < spec.expect_min_docs:
            print(f"   ! expected at least {spec.expect_min_docs:,} docs but got "
                  f"{st.docs:,} — upstream layout may have changed")

    _strip_boilerplate(collected, stats)

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

    orphans = _write_provenance(out_dir, all_specs, stats)
    print("\n" + balance_report(stats))
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
    return stats



def _redacted(doc):
    """Substitute this machine's identity out of a document before it is kept.

    Imported lazily because :mod:`training.trajectories` pulls in the kernel and
    the adapters, and the corpus builder has no other reason to depend on them.
    If that import ever fails the build must FAIL rather than quietly write
    unredacted text — a corpus that is clean only when an optional import
    succeeds is a corpus nobody can make a claim about.
    """
    from dataclasses import replace

    from training.trajectories import redact_identity

    clean = redact_identity(doc.text)
    return doc if clean == doc.text else replace(doc, text=clean)


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
    trimmed is the excess beyond it, oldest-document-first so the trim is
    deterministic. Everything dropped is logged; a silent cap reads as coverage
    that is not there.

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
        for doc in docs:
            if running + doc.n_chars > ceiling:
                st_by_name[name].dropped_for_balance += 1
                continue
            running += doc.n_chars
            kept.append(doc)
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
    """
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
    p.add_argument("--out", type=Path,
                   default=Path("/Volumes/at0m_b0mb/whetstone/corpus/clean"))
    p.add_argument("--cache", type=Path,
                   default=Path("/Volumes/at0m_b0mb/whetstone/corpus/raw"))
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
          source_timeout=args.source_timeout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
