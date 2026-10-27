"""Corpus → token shards → batches.

Three jobs, kept in one file because they share a format and drifting apart
would be silent: tokenise text into flat binary shards, memory-map those shards
at training time, and hand out batches.

**uint16, not uint32.** The vocabulary is 16,384, which fits in 16 bits with
room to spare, so every token costs two bytes instead of four. On a 3B-token
corpus that is 6 GB rather than 12 — the difference between the training set
living in the page cache and being read off the disk every epoch. The
:func:`write_shard` guard makes the assumption explicit, because the day someone
raises the vocabulary past 65,535 this file must fail loudly rather than wrap
tokens around to zero and produce a model that has learned nonsense.

**Sampling is with replacement, from a global index.** A loader that walks
shards in order and restarts is the classic silent bug: the model sees shard 0
far more often than shard 9, and the loss curve looks perfectly healthy while
the data distribution is quietly wrong. Here every batch draws uniformly across
the whole concatenated corpus, so shard boundaries have no effect on what the
model sees. :meth:`Dataset.coverage_report` exists so that claim is checkable
rather than trusted.

**The validation split is held out by position, from a stream that was already
shuffled at the document level.** Both halves of that sentence are load-bearing
and the first version of this file only had one of them.

Positional holdout is right: the last ``val_fraction`` of tokens is reserved and
never sampled for training, so near-duplicate passages cannot straddle the split
the way they would if windows were shuffled.

But the *stream* must be interleaved first. ``build.py`` writes one JSONL per
source and they are read in sorted order, so an unshuffled corpus ends with
whichever source sorts last — here ``sigma`` — and the validation split was
therefore **100% Sigma detection rules**. Validation loss measured how well the
model predicted YAML rather than how well it modelled the corpus, and it sat 1.3
nats above training loss for that reason alone while looking exactly like
overfitting. :func:`_interleaved` fixes it and
:meth:`Dataset.split_composition` makes the claim checkable rather than trusted.

**Nothing here reads a corpus directory that has not been verified.** The
redaction chokepoint is in ``build.py`` and everything in this file reads the
*finished* JSONL, so an unredacted corpus on disk — and there is one — flowed
straight into a shard and from there into the weights.
:func:`require_clean_corpus` closes that, :class:`CorpusProvenance` records what
was *actually* read rather than what was asked for, and :class:`ShardIndex`
carries that record so the shards cannot launder it.
"""

from __future__ import annotations

import dataclasses
import hashlib
import importlib
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

import numpy as np

__all__ = ["write_shard", "tokenize_corpus", "Dataset", "ShardIndex",
           "require_clean_corpus", "CorpusProvenance", "CorpusLeakError",
           "CorpusUnverifiable", "STAMP_NAME", "leak_token"]

#: Tokens are stored as uint16. See the module docstring.
TOKEN_DTYPE = np.uint16
MAX_VOCAB = np.iinfo(TOKEN_DTYPE).max + 1


# ─────────────────────────────────────────────────────────────────────────────
# The chokepoint bypass gate
# ─────────────────────────────────────────────────────────────────────────────
#
# ``build.py`` redacts on the way out. Everything in this file and in
# ``train_tokenizer.py`` reads the *finished* JSONL, so until now nothing
# between a corpus directory and the weights looked at the text again — and
# there is an unredacted corpus on disk to prove that matters: ``corpus/clean/``
# carries 5,356 raw identity occurrences in ``trajectories.jsonl``. Pointing a
# tokenizer at it puts the account name in the BPE merges, and a tokenizer.json
# is a shipped artifact. A published checkpoint is not greppable and not
# removable.
#
# So every entry point that reads a corpus directory verifies it first, with
# :mod:`training.corpus.verify`, and refuses on a leak.
#
# **Why a stamp.** Measured on this machine against ``corpus/clean-v7`` (47
# files, 625 MB): a full verify pass costs 23.6 s, and hashing every byte of
# the same files costs 0.50 s — 47× cheaper. A gate that charges 24 s to every
# tokenizer start, every shard build and every smoke test is a gate that gets
# patched out, and a gate that is patched out protects nothing. So a clean scan
# writes :data:`STAMP_NAME` into the corpus directory recording *what it
# checked*, and a later run re-confirms it for the price of the hash.
#
# **Why the stamp hashes content and not stat.** ``corpus_identity`` in
# ``train_tokenizer.py`` deliberately costs one ``stat`` per file, because its
# job is to *label* a measurement. This stamp's job is to decide whether a scan
# can be skipped, and the most likely edit to a corpus file here is a
# redaction — which can replace a value with a placeholder of the same length
# and leave the size untouched. Name-and-size would call that corpus
# unchanged, skip the scan, and be wrong in the one direction that matters.
# Two different questions, two different instruments.
#
# A stamp never records a needle: file *basenames*, byte counts and digests,
# the verifier's contract, the kind names it checked, and one digest naming the
# needle table it used. It never records a path, because
# the data volume's own name is one of the kinds the verifier looks for, and
# the audit that found these leaks created a new one by writing its own needle
# table to a JSON file.
#
# A stamp that does not match the files it claims to describe counts as
# **absent**, never as valid — so does one written by a different build of the
# verifier, one written against a different needle table, one covering fewer
# kinds than the verifier covers today, and one whose JSON does not parse.
#
# **And a clean answer from an instrument that cannot see is not a clean
# answer.** ``verify_corpus`` returns ``[]`` for an empty needle table, so the
# gate asks the table what it is blind to and refuses to call anything clean
# while it is — with no override, because that refusal can name nothing
# actionable and a stamp written there would make it permanent.

#: Written into a corpus directory by a clean scan. Leading dot so
#: ``read_documents``' ``*.jsonl`` glob cannot see it; named in
#: ``iter_corpus``' skip set so the raw-text path cannot eat it either.
STAMP_NAME = ".corpus-verified.json"

#: Bumped when the stamp's meaning changes. An older format counts as absent.
STAMP_FORMAT = 1

#: The leak kinds of the pinned verifier interface, used only when the verifier
#: does not publish its own set. Kind *names* are categories, never values.
_PINNED_KINDS: tuple[str, ...] = (
    "email", "ident-path", "identity", "ipv4-private", "ipv6-global",
    "mac", "volume",
)

#: Suffixes the raw-text path skips. Binary, and the stamp.
_RAW_SKIP_SUFFIXES = {".bin", ".npy", ".png", ".jpg", ".zip", ".gz"}


class CorpusUnverifiable(RuntimeError):
    """The verifier could not be used, so no corpus may be read.

    This is the fail-**closed** direction, and it is the whole point. The
    identity redactor's own ``if pattern is None: return text`` returns
    Mac-captured text unchanged when the identity table comes back empty, which
    is what happens in a container or a CI build — silently, with no leak and
    no log line. A gate that answers "I could not check" with "carry on" is
    that bug again one layer up.
    """


class CorpusLeakError(RuntimeError):
    """A corpus carries values that must not reach a tokenizer or a shard."""

    def __init__(self, message: str, *, token: str, leaks: list) -> None:
        super().__init__(message)
        #: The acceptance token for exactly these leaks. See
        #: :func:`require_clean_corpus`.
        self.token = token
        #: The verifier's own :class:`Leak` records. Fingerprints, not values.
        self.leaks = list(leaks)


@dataclass(frozen=True)
class CorpusProvenance:
    """What was actually read, and whether anything vouched for it.

    ``given`` and ``resolved`` differ whenever the path is a symlink, and one
    is: ``corpus/clean-v8`` is a symlink to ``corpus/clean-v7``, so every
    record saying a tokenizer or a shard set was built from v8 is a statement
    about v7's bytes. :meth:`as_record` therefore reports both — by *basename*,
    never by path.
    """

    given: Path
    resolved: Path
    files: int
    nbytes: int
    #: Digest of the content manifest: names, sizes and per-file content hashes.
    digest: str
    #: Kind names the verifier checked. Categories, not values.
    kinds: tuple[str, ...]
    #: Identifies the build of the verifier that checked this.
    contract: str
    #: True when the scan found nothing at all.
    verified: bool
    #: Non-zero only when the override below was used.
    accepted_leaks: int = 0
    #: The acceptance token, empty when the corpus is clean.
    token: str = ""
    #: True when a valid stamp answered instead of a fresh scan.
    from_stamp: bool = False

    def as_record(self) -> dict:
        """The form that may be written to disk.

        Basenames only. The absolute path is printed to whoever asked — they
        typed it — but never serialised, because the volume name is one of the
        kinds the verifier hunts for and this record lands in ``index.json``.
        ``location`` is a digest of the parent directory, so two corpora with
        the same basename in different trees stay distinguishable without
        naming either tree.
        """
        return {
            "given": self.given.name,
            "resolved": self.resolved.name,
            "location": _digest_text(str(self.resolved.parent)),
            "files": self.files,
            "bytes": self.nbytes,
            "digest": self.digest,
            "kinds": list(self.kinds),
            "verifier": self.contract,
            "verified": self.verified,
            "accepted_leaks": self.accepted_leaks,
            "token": self.token,
        }

    @property
    def redirected(self) -> bool:
        """True when the path read is not the path asked for."""
        return self.resolved != self.given.absolute()

    def __repr__(self) -> str:                      # names and digests only
        return (f"CorpusProvenance({self.given.name!r}"
                f"{'→' + repr(self.resolved.name) if self.redirected else ''}, "
                f"{self.files} files, digest={self.digest}, "
                f"verified={self.verified}, accepted={self.accepted_leaks})")


def _digest_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:12]


def _verifier():
    """Import the artifact verifier, or refuse to let anything read a corpus.

    Resolved through :mod:`importlib` rather than ``from .corpus import
    verify`` so a test can substitute a module in ``sys.modules``: the real
    verifier's needles are derived from this machine and a test may not write
    one to disk, so the only honest way to exercise a *refusal* is a scanner
    looking for a value a test is allowed to fabricate.
    """
    try:
        verify = importlib.import_module(".corpus.verify", package=__package__)
    except Exception as exc:                        # ImportError, SyntaxError…
        raise CorpusUnverifiable(
            f"training/corpus/verify.py could not be imported ({exc!r}), so no "
            f"corpus can be verified — and nothing here will read one "
            f"unverified. This fails closed on purpose: the identity "
            f"redactor's own 'if pattern is None: return text' is the same "
            f"shape of hole one layer down, and it returns Mac-captured text "
            f"unchanged whenever the identity table comes back empty."
        ) from exc
    missing = [name for name in ("verify_corpus", "scan_text", "host_needles",
                                 "render")
               if not callable(getattr(verify, name, None))]
    if missing:
        raise CorpusUnverifiable(
            f"training/corpus/verify.py is missing {', '.join(missing)}, so it "
            f"cannot be used as the artifact verifier. Refusing rather than "
            f"reading a corpus nothing has checked.")
    return verify


def _contract(verify) -> str:
    """Identify this build of the verifier.

    The digest of its source, so *any* change to the scanner invalidates every
    stamp written by the old one without anybody having to remember to bump a
    version. A verifier whose source cannot be read gets no stamp at all: a
    stamp that cannot be bound to the scanner that wrote it is a stamp that
    outlives the scan it stands for.
    """
    path = getattr(verify, "__file__", None)
    if not path or not os.path.isfile(path):
        return ""
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()[:16]
    except OSError:
        return ""


def _coverage(verify, needles) -> tuple[tuple[str, ...], tuple[str, ...], str]:
    """What this needle table actually covers, what it is blind to, and its id.

    Three things, all from the table rather than from the scanner's vocabulary,
    because the difference is the fail-open. ``verify_corpus`` returns ``[]``
    for an empty table, and ``[]`` from an empty table means *nothing was
    looked for* — the same failure as ``redact_identity``'s ``if pattern is
    None: return text``, which returns Mac-captured text unchanged whenever the
    identity table comes back empty. So the gate asks the table what it knows
    before it believes a clean answer.

    The third value identifies the table itself, as **one** digest over the
    verifier's own per-root fingerprints. No value, and not even a per-value
    hash: the table has to be held already to reproduce it. It is in the stamp
    so that a *changed* table — a volume mounted, an address renewed, a second
    account appearing — invalidates every stamp written under the old one. A
    stamp is a claim about what was checked, and the needle set is half of what
    was checked.
    """
    kinds = getattr(needles, "kinds", None)
    if callable(kinds):
        covered = tuple(sorted(str(k) for k in kinds()))
    else:
        published = getattr(verify, "KINDS", None) or _PINNED_KINDS
        covered = tuple(sorted(str(k) for k in published))

    gaps = getattr(needles, "gaps", None)
    blind = tuple(str(g) for g in gaps()) if callable(gaps) else ()

    prints = getattr(needles, "fingerprints", None)
    identity = (_digest_text("\n".join(sorted(str(f) for f in prints())))
                if callable(prints) else "")
    return covered, blind, identity


def _corpus_files(directory: Path) -> tuple[list[Path], bool]:
    """The files a reader would ingest, and whether this is a built corpus.

    ``os.walk(followlinks=False)`` for the raw side, never ``rglob``. The
    ``ownrepos`` adapter once followed this repo's ``data`` symlink into the SSD
    and pulled the corpus cache back in as prose — the corpus ate itself, and
    only the balance report caught it. ``Path.rglob`` follows symlinks, so the
    raw-text path in ``iter_corpus`` had that same hole until this walk
    replaced it.
    """
    if directory.is_file():
        return [directory], False
    if not directory.is_dir():
        return [], False
    built = sorted(directory.glob("*.jsonl"))
    if built:
        return built, True

    raw: list[Path] = []
    for root, dirs, names in os.walk(directory, followlinks=False):
        dirs[:] = sorted(d for d in dirs if not d.startswith("."))
        for name in sorted(names):
            if name == STAMP_NAME or name.startswith("."):
                continue
            path = Path(root) / name
            if path.suffix.lower() in _RAW_SKIP_SUFFIXES:
                continue
            if path.is_symlink() or not path.is_file():
                continue
            raw.append(path)
    return raw, False


def _manifest(files: Iterable[Path], *, base: Path) -> tuple[list[dict], str, int]:
    """Per-file content digests, their digest, and the total byte count."""
    entries: list[dict] = []
    total = 0
    roll = hashlib.sha256()
    for path in files:
        h = hashlib.sha256()
        size = 0
        with path.open("rb") as fh:
            while True:
                chunk = fh.read(1 << 22)
                if not chunk:
                    break
                size += len(chunk)
                h.update(chunk)
        name = _relative(path, base)
        entries.append({"name": name, "bytes": size,
                        "sha256": h.hexdigest()[:16]})
        roll.update(f"{name}\0{size}\0{h.hexdigest()}\n".encode("utf-8"))
        total += size
    return entries, roll.hexdigest()[:16], total


def _relative(path: Path, base: Path) -> str:
    """A name for ``path`` that reveals nothing above ``base``."""
    try:
        return str(path.resolve().relative_to(base))
    except ValueError:
        return path.name


def _stat_key(files: Iterable[Path]) -> tuple:
    out = []
    for path in files:
        try:
            st = path.stat()
        except OSError:
            out.append((path.name, -1, -1))
        else:
            out.append((path.name, st.st_size, st.st_mtime_ns))
    return tuple(out)


def leak_token(leaks: Iterable, *, base: Path | None = None) -> str:
    """A short token naming **exactly** this set of leaks.

    This is the whole override affordance. It cannot be guessed, it cannot be
    typed from memory, and it stops matching the moment the corpus changes —
    so it cannot be parked in a shell script, a config file or an environment
    variable and quietly keep permitting something else. Derived from kind,
    relative path, line, field and the verifier's fingerprint: there is no
    value in it, and none in the token.
    """
    rows = []
    for leak in leaks:
        path = str(getattr(leak, "path", ""))
        if base is not None and path:
            path = _relative(Path(path), base)
        rows.append(f"{getattr(leak, 'kind', '?')}|{path}|"
                    f"{getattr(leak, 'line', 0)}|{getattr(leak, 'field', '?')}|"
                    f"{getattr(leak, 'fingerprint', '?')}")
    joined = "\n".join(sorted(rows))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:12]


def _read_stamp(directory: Path, *, entries: list[dict], digest: str,
                contract: str, kinds: tuple[str, ...], needles: str) -> bool:
    """True only if a stamp vouches for *these* files, from *this* verifier.

    Every other answer — missing, unparseable, older format, different
    verifier, a different needle table, fewer kinds, one byte different
    anywhere — is "absent".

    The kind check is a **superset** test, not equality, and the asymmetry is
    deliberate: a stamp written where the verifier could see more than it can
    see here still vouches for these bytes, while a stamp written somewhere
    blinder does not. That is also why a blind run never writes one — otherwise
    a CI image with no ``ifconfig`` would quietly downgrade the Mac's stamp.
    """
    path = directory / STAMP_NAME
    try:
        stamp = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if not isinstance(stamp, dict):
        return False
    if stamp.get("stamp") != STAMP_FORMAT:
        return False
    if stamp.get("leaks") != 0:
        return False
    verifier = stamp.get("verifier")
    if not isinstance(verifier, dict):
        return False
    if not contract or verifier.get("contract") != contract:
        return False
    if not set(str(k) for k in verifier.get("kinds") or ()) >= set(kinds):
        return False
    if needles and verifier.get("needles") != needles:
        return False
    if stamp.get("digest") != digest:
        return False
    # The manifest is checked as well as the digest it rolls up, so a stamp
    # cannot claim a digest it did not compute from these names and sizes.
    return stamp.get("files") == entries


def _write_stamp(directory: Path, *, entries: list[dict], digest: str,
                 contract: str, kinds: tuple[str, ...], needles: str) -> bool:
    """Record a clean scan. Best effort: a read-only corpus just costs a scan.

    No needle, no path, no host name. Basenames, byte counts, digests, the
    verifier's contract, the kind names it checked and one digest naming the
    needle table it checked them with.
    """
    if not contract:
        return False
    stamp = {
        "stamp": STAMP_FORMAT,
        "verifier": {"contract": contract, "kinds": list(kinds),
                     "needles": needles},
        "digest": digest,
        "files": entries,
        "leaks": 0,
        "note": ("written by training/data.py after a clean verify pass. "
                 "Delete it to force a re-scan; edit any corpus file and it "
                 "stops matching, which counts as absent."),
    }
    tmp = directory / f"{STAMP_NAME}.tmp"
    try:
        tmp.write_text(json.dumps(stamp, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, directory / STAMP_NAME)
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass
        return False
    return True


def _scan_raw(files: list[Path], *, verify, needles, base: Path) -> list:
    """Scan unbuilt text with the verifier's own ``scan_text``.

    The raw path exists so a new source can be smoke-tested before it has an
    adapter, which means it is *by definition* material that has never been
    through the chokepoint. It cannot be handed to ``verify_corpus``, which
    reads the built JSONL schema, so the scan is assembled here from the one
    pinned primitive that takes a string. Whole file first; line numbers are
    only paid for on a file that already failed.
    """
    leaks: list = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not verify.scan_text(text, needles=needles, field="text"):
            continue
        name = _relative(path, base)
        for number, line in enumerate(text.splitlines(), start=1):
            for leak in verify.scan_text(line, needles=needles, field="text"):
                leaks.append(_locate(leak, name, number))
    return leaks


def _locate(leak, path: str, line: int):
    """Attach a path and line number to a ``scan_text`` result."""
    if dataclasses.is_dataclass(leak):
        try:
            return dataclasses.replace(leak, path=path, line=line)
        except (TypeError, ValueError):
            pass
    return leak


def _summarise(leaks: list, *, base: Path) -> str:
    by_kind: dict[str, int] = {}
    by_file: dict[str, int] = {}
    for leak in leaks:
        kind = str(getattr(leak, "kind", "?"))
        by_kind[kind] = by_kind.get(kind, 0) + 1
        path = str(getattr(leak, "path", "")) or "?"
        name = _relative(Path(path), base) if path != "?" else "?"
        by_file[name] = by_file.get(name, 0) + 1
    lines = ["  by kind:"]
    lines += [f"    {k:<14}{n:>8,}" for k, n in sorted(by_kind.items())]
    lines.append("  by file:")
    lines += [f"    {f:<24}{n:>8,}"
              for f, n in sorted(by_file.items(), key=lambda kv: -kv[1])[:12]]
    if len(by_file) > 12:
        lines.append(f"    … and {len(by_file) - 12} more file(s)")
    return "\n".join(lines)


#: Per-process memo, so the gate can sit on every entry point without charging
#: the hash more than once per corpus per run. Keyed on the cheap stat
#: signature — which is a *cache key*, never the authority: the authority is
#: the content digest recomputed on the first call.
_GATE_MEMO: dict[tuple, CorpusProvenance] = {}

#: Roots already warned about, so a legacy shard set says so once per process.
_WARNED: set[str] = set()


def require_clean_corpus(
    roots: Iterable[Path],
    *,
    accept_leaking_corpus: str | None = None,
    stream=None,
) -> list[CorpusProvenance]:
    """Verify every corpus root, and refuse to let a leaking one be read.

    Returns one :class:`CorpusProvenance` per root. Raises
    :class:`CorpusLeakError` when the verifier finds anything, and
    :class:`CorpusUnverifiable` when it cannot be used at all.

    **The escape hatch.** He has to be able to work on a corpus he knows is
    dirty while fixing it — an absolute refusal would make that impossible and
    get patched out, and a gate that is patched out protects nothing. So
    ``accept_leaking_corpus`` takes the :func:`leak_token` of the leaks found
    right now. That is deliberately the most awkward affordance that is still
    usable:

    * it is not a boolean, so it cannot be flipped on by a default;
    * it is not read from the environment or from any config file — nothing in
      this module reads ``os.environ``, and a test asserts that;
    * it names *these* leaks, so it stops working the moment the corpus
      changes, and cannot be parked in ``overnight.sh``;
    * you can only obtain it by running the scan and reading the refusal,
      which prints what you would be permitting.

    It is not called ``--force``. ``--force`` is a word people type.

    There is deliberately **no** ``needles`` parameter. It would be the obvious
    convenience and it is a silent bypass: hand it an empty table and every
    corpus verifies, gets stamped clean, and the stamp outlives the call. That
    is the same fail-open shape as ``redact_identity``'s ``if pattern is None:
    return text``, which returns Mac-captured text unchanged whenever the
    identity table comes back empty. The needles come from the verifier, from
    the running system, every time. A test drives this by substituting the
    verifier's own scan functions, because a test may not write a real needle
    to disk.
    """
    out = stream if stream is not None else sys.stderr
    verify = _verifier()
    contract = _contract(verify)
    needles = verify.host_needles()
    kinds, blind, table = _coverage(verify, needles)
    provenance: list[CorpusProvenance] = []

    for root in roots:
        given = Path(root)
        resolved = Path(os.path.realpath(given))
        files, built = _corpus_files(resolved)
        memo_key = (str(resolved), contract, kinds, table, _stat_key(files),
                    accept_leaking_corpus or "")
        cached = _GATE_MEMO.get(memo_key)
        if cached is not None:
            provenance.append(cached)
            continue

        entries, digest, nbytes = _manifest(files, base=resolved)
        stamped = bool(files) and built and _read_stamp(
            resolved, entries=entries, digest=digest, contract=contract,
            kinds=kinds, needles=table)

        if stamped:
            record = CorpusProvenance(
                given=given, resolved=resolved, files=len(files),
                nbytes=nbytes, digest=digest, kinds=kinds, contract=contract,
                verified=True, from_stamp=True)
            _GATE_MEMO[memo_key] = record
            provenance.append(record)
            continue

        if not files:
            leaks: list = []
        elif built:
            leaks = list(verify.verify_corpus(resolved, needles=needles))
        else:
            leaks = _scan_raw(files, verify=verify, needles=needles,
                              base=resolved)

        # Provenance, before any verdict. One kind of finding is ambiguous by
        # construction — an RFC1918 address bound on this host is the same bytes
        # as one used as an example in an Nmap script — so it is settled by
        # asking whether the value is present in that source's own raw upstream
        # download, which was fetched from the upstream and has never seen this
        # machine's network configuration. The rule lives in
        # training.corpus.provenance precisely so this gate, build.py's stamp and
        # scripts/gate_corpus.py cannot disagree about it. Nothing else is
        # exonerable there: identity, email, mac, ipv6-global, volume and
        # ident-path fail whatever any cache says, because a hardware MAC in an
        # upstream would mean the upstream had acquired this host's identifiers,
        # which is worse news than a leak and must not be quietly excused.
        exonerated: list = []
        if leaks:
            try:
                from training.corpus.provenance import partition
                real_pairs, excused_pairs = partition(leaks)
                leaks = [leak for leak, _ in real_pairs]
                exonerated = excused_pairs
            except Exception as exc:
                # Fail CLOSED. A rule that could not be consulted excuses nothing.
                print(f"provenance check unavailable ({type(exc).__name__}: "
                      f"{exc}); treating every finding as real.", file=out)
        if exonerated:
            print(f"\n{len(exonerated)} finding(s) exonerated by provenance — "
                  f"present in the source's own raw upstream download, so the "
                  f"upstream shipped them:", file=out)
            for leak, why in exonerated:
                print(f"  {leak.kind:<13} {leak.fingerprint}  — {why}", file=out)
            print("That is not the same sentence as 'found nothing'.\n", file=out)

        if not leaks and blind:
            # Clean, from an instrument that cannot see. This is the fail-open
            # the audit found one layer down, and it has no override on
            # purpose: a corpus the verifier could not fully check is not a
            # corpus somebody should be able to wave through, because the
            # refusal above at least names what it found and this would name
            # nothing. Fix the environment — the probes run off `ifconfig`,
            # the account name and the mounted volumes — and ask again.
            raise CorpusUnverifiable(
                f"\nREFUSING TO CALL {given} CLEAN. The scan found nothing, "
                f"and it was blind to:\n    {', '.join(blind)}\n\n"
                f"An empty needle table returns no leaks, so \"no leaks\" from "
                f"a thin table says\nonly that nothing was looked for. The "
                f"probes behind those kinds are the ones\nthat do not survive "
                f"a container or a CI image. Nothing is stamped, because a "
                f"stamp\nwritten here would make this answer permanent.")

        if not leaks:
            wrote = bool(files) and built and _write_stamp(
                resolved, entries=entries, digest=digest, contract=contract,
                kinds=kinds, needles=table)
            if wrote:
                print(f"verified {given} ({len(files)} files, {nbytes:,} bytes, "
                      f"{len(kinds)} leak kinds) — stamped {STAMP_NAME}",
                      file=out)
            record = CorpusProvenance(
                given=given, resolved=resolved, files=len(files),
                nbytes=nbytes, digest=digest, kinds=kinds, contract=contract,
                verified=True)
            _GATE_MEMO[memo_key] = record
            provenance.append(record)
            continue

        token = leak_token(leaks, base=resolved)
        detail = _summarise(leaks, base=resolved)
        where = (f"  corpus          {given}\n"
                 f"  actually read   {resolved}"
                 f"{'   (SYMLINK)' if resolved != given.absolute() else ''}\n"
                 f"  files           {len(files)} ({nbytes:,} bytes)\n"
                 f"  digest          {digest}\n"
                 f"  leaks           {len(leaks):,}\n")

        if accept_leaking_corpus and accept_leaking_corpus == token:
            print("\n" + "=" * 78, file=out)
            print("PERMITTING A LEAKING CORPUS. This was asked for explicitly:\n"
                  "there is no default, no config key and no environment "
                  "variable that\ncan reach this line.\n", file=out)
            print(where + detail, file=out)
            print(f"\n  token           {token}  (names exactly these leaks)\n"
                  "\nAnything fitted to this corpus memorises those values. A "
                  "tokenizer.json\nkeeps them as merges and a checkpoint keeps "
                  "them in the weights, where\nthey are neither greppable nor "
                  "removable.", file=out)
            print("=" * 78 + "\n", file=out)
            record = CorpusProvenance(
                given=given, resolved=resolved, files=len(files),
                nbytes=nbytes, digest=digest, kinds=kinds, contract=contract,
                verified=False, accepted_leaks=len(leaks), token=token)
            _GATE_MEMO[memo_key] = record
            provenance.append(record)
            continue

        rendered = verify.render(leaks)
        message = (
            f"\nREFUSING TO READ THIS CORPUS — the verifier found "
            f"{len(leaks):,} leak(s).\n\n{where}{detail}\n\n{rendered}\n\n"
            f"Fix the corpus, or say explicitly that you are working on a dirty "
            f"one:\n\n"
            f"    --accept-leaking-corpus {token}\n"
            f"    require_clean_corpus(..., accept_leaking_corpus="
            f"{token!r})\n\n"
            f"That token names exactly the {len(leaks):,} leak(s) above. Change "
            f"the corpus and it\nchanges, so it cannot be parked in a script, "
            f"a config file or an environment\nvariable — there is deliberately "
            f"no env var and no default. Values are never\nprinted: every "
            f"finding above is kind, length and a sha256 prefix.\n")
        if accept_leaking_corpus:
            message += (
                f"\nThe token given ({accept_leaking_corpus}) does not match. "
                f"It was minted for a\ndifferent set of leaks, which means the "
                f"corpus has changed since it was\nread — look again rather "
                f"than editing the token.\n")
        raise CorpusLeakError(message, token=token, leaks=leaks)

    return provenance


def write_shard(path: Path, tokens: Sequence[int] | np.ndarray) -> int:
    """Write one shard of token ids, returning how many were written."""
    arr = np.asarray(tokens, dtype=np.int64)
    if arr.size and int(arr.max()) >= MAX_VOCAB:
        raise ValueError(
            f"token id {int(arr.max())} does not fit in {TOKEN_DTYPE.__name__} "
            f"(max {MAX_VOCAB - 1}). Either shrink the vocabulary or widen "
            "TOKEN_DTYPE — do not let this wrap, it would silently corrupt "
            "every shard written afterwards."
        )
    if arr.size and int(arr.min()) < 0:
        raise ValueError("negative token id")
    path.parent.mkdir(parents=True, exist_ok=True)
    arr.astype(TOKEN_DTYPE).tofile(path)
    return int(arr.size)


def _interleaved(corpus_dirs: list[Path], *, seed: int,
                 accept_leaking_corpus: str | None = None,
                 ) -> Iterator[tuple[str, str]]:
    """Yield ``(source, text)`` in a deterministic shuffled order.

    Verified first, every time. This function is the only thing that opens a
    corpus file in this module, so the gate belongs here as well as in
    :func:`tokenize_corpus`: a caller that reaches past the public function
    still cannot read an unverified corpus. The check is memoised per process,
    so paying for it twice costs nothing.

    **Why this is not optional.** ``build.py`` writes one JSONL per source and
    the loader reads them in sorted order, so a corpus laid down verbatim is
    ``atomic … attack … manpages … nvd … ownrepos … psdocs … sigma``. The
    :class:`Dataset` validation split is the last slice of the token stream by
    position — which made it **100% Sigma detection rules**. Validation loss was
    measuring how well the model predicted YAML, not how well it modelled the
    corpus, and it read 1.3 nats worse than training loss for that reason alone
    while looking exactly like overfitting.

    Shuffling is done over *document pointers*, not document text: each JSONL is
    scanned once for line offsets, the offsets are permuted, and lines are read
    back by ``seek``. Memory is a few million integers regardless of corpus size,
    which matters because this corpus is meant to grow by a hundredfold.

    Whole documents stay intact, so this does not reintroduce the near-duplicate
    leakage that positional splitting exists to avoid — and ``build.py`` has
    already deduplicated by fingerprint across every source.
    """
    require_clean_corpus(corpus_dirs,
                         accept_leaking_corpus=accept_leaking_corpus)

    pointers: list[tuple[Path, int]] = []
    for root in corpus_dirs:
        files = sorted(root.glob("*.jsonl")) if root.is_dir() else []
        if not files:
            # Not a built corpus — fall back to the raw-text path, which has no
            # source structure to interleave in the first place. It is gated
            # above like any other root; `iter_corpus` gates again on its own,
            # and the memo makes the second check free.
            from .tokenizer.train_tokenizer import iter_corpus
            for text in iter_corpus([root],
                                    accept_leaking_corpus=accept_leaking_corpus):
                yield ("raw", text)
            continue
        for path in files:
            with path.open("rb") as fh:
                offset = 0
                for line in fh:
                    if line.strip():
                        pointers.append((path, offset))
                    offset += len(line)

    if not pointers:
        return

    rng = np.random.default_rng(seed)
    order = rng.permutation(len(pointers))

    handles: dict[Path, Any] = {}
    try:
        for index in order:
            path, offset = pointers[int(index)]
            fh = handles.get(path)
            if fh is None:
                fh = handles[path] = path.open("rb")
            fh.seek(offset)
            row = json.loads(fh.readline().decode("utf-8"))
            yield (row.get("source", path.stem), row["text"])
    finally:
        for fh in handles.values():
            fh.close()


def tokenize_corpus(
    corpus_dirs: list[Path],
    tokenizer_path: Path,
    out_dir: Path,
    *,
    shard_tokens: int = 50_000_000,
    eos_between_documents: bool = True,
    shuffle_seed: int = 1337,
    accept_leaking_corpus: str | None = None,
) -> ShardIndex:
    """Tokenise every file under ``corpus_dirs`` into shards under ``out_dir``.

    Documents are separated by the EOS token so the model learns that documents
    end. Without it, training windows straddle unrelated documents and the model
    spends capacity learning to predict the start of an arbitrary next file from
    the end of the previous one — a mapping that does not exist.

    Documents are interleaved across sources before writing — see
    :func:`_interleaved` for why that is load-bearing rather than tidy.

    Every root is verified before a byte is tokenised, and what the verifier
    said goes into the :class:`ShardIndex` — including the resolved path, so a
    shard set built from ``clean-v8`` records that it read ``clean-v7``'s bytes.
    See :func:`require_clean_corpus` for ``accept_leaking_corpus``.
    """
    from tokenizers import Tokenizer

    from .tokenizer.protocol import EOS

    provenance = require_clean_corpus(
        corpus_dirs, accept_leaking_corpus=accept_leaking_corpus)

    tok = Tokenizer.from_file(str(tokenizer_path))
    eos_id = tok.token_to_id(EOS)
    if eos_between_documents and eos_id is None:
        raise ValueError(f"tokenizer has no {EOS} token")

    out_dir.mkdir(parents=True, exist_ok=True)
    for stale in out_dir.glob("shard-*.bin"):
        stale.unlink()

    shards: list[dict] = []
    buffer: list[int] = []
    total = 0
    docs = 0
    by_source: dict[str, int] = {}

    def flush(index: int) -> None:
        nonlocal buffer
        if not buffer:
            return
        path = out_dir / f"shard-{index:04d}.bin"
        n = write_shard(path, buffer)
        shards.append({"file": path.name, "tokens": n})
        print(f"  {path.name}  {n:,} tokens")
        buffer = []

    for source, text in _interleaved(
            corpus_dirs, seed=shuffle_seed,
            accept_leaking_corpus=accept_leaking_corpus):
        ids = tok.encode(text).ids
        if not ids:
            continue
        buffer.extend(ids)
        if eos_between_documents:
            buffer.append(eos_id)
        docs += 1
        by_source[source] = by_source.get(source, 0) + len(ids)
        total += len(ids) + (1 if eos_between_documents else 0)
        if len(buffer) >= shard_tokens:
            flush(len(shards))

    flush(len(shards))

    index = ShardIndex(root=out_dir, shards=shards, total_tokens=total,
                       documents=docs, vocab_size=tok.get_vocab_size(),
                       by_source=dict(sorted(by_source.items())),
                       corpus=[p.as_record() for p in provenance])
    index.save()
    print(f"\n{total:,} tokens from {docs:,} documents "
          f"across {len(shards)} shard(s) → {out_dir}")
    for record in provenance:
        if record.redirected:
            print(f"  provenance: asked for {record.given.name}, read "
                  f"{record.resolved.name} (symlink) — index.json records the "
                  f"name that was read")
    return index


@dataclass
class ShardIndex:
    """What was written, so training does not have to rediscover it."""

    root: Path
    shards: list[dict]
    total_tokens: int
    documents: int
    vocab_size: int
    #: source -> tokens contributed, so a split's composition is auditable.
    by_source: dict = field(default_factory=dict)
    #: One :meth:`CorpusProvenance.as_record` per corpus root these shards were
    #: tokenised from: what was asked for, what was *read*, the content digest,
    #: and whether anything vouched for it. Empty on a shard set written before
    #: this existed, which is a different statement from "verified" and
    #: :class:`Dataset` says so out loud.
    corpus: list = field(default_factory=list)

    def save(self) -> None:
        (self.root / "index.json").write_text(json.dumps({
            "shards": self.shards,
            "total_tokens": self.total_tokens,
            "documents": self.documents,
            "vocab_size": self.vocab_size,
            "by_source": self.by_source,
            "corpus": self.corpus,
        }, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, root: Path) -> ShardIndex:
        meta = json.loads((root / "index.json").read_text(encoding="utf-8"))
        return cls(root=root, shards=meta["shards"],
                   total_tokens=meta["total_tokens"],
                   documents=meta["documents"],
                   vocab_size=meta["vocab_size"],
                   by_source=meta.get("by_source", {}),
                   corpus=meta.get("corpus", []))

    def provenance_report(self) -> str:
        """What these shards were built from, by name and digest.

        Reads as a record of what was *read*, not of what was typed: the two
        differ whenever the corpus path is a symlink, and ``clean-v8`` is one.
        """
        if not self.corpus:
            return ("this shard set records no corpus provenance: it was "
                    "written before the provenance record existed, so nothing "
                    "here can say which corpus it read or whether anything "
                    "verified it.")
        lines = [f"{'asked for':<16}{'read':<16}{'digest':<18}"
                 f"{'files':>7}{'verified':>10}"]
        for rec in self.corpus:
            verified = ("yes" if rec.get("verified")
                        else f"NO ({rec.get('accepted_leaks', 0):,} leaks)")
            lines.append(f"{str(rec.get('given', '?')):<16}"
                         f"{str(rec.get('resolved', '?')):<16}"
                         f"{str(rec.get('digest', '?')):<18}"
                         f"{rec.get('files', 0):>7}{verified:>10}")
            if rec.get("given") != rec.get("resolved"):
                lines.append(f"  SYMLINK: {rec.get('given')} is not the "
                             f"directory whose bytes were tokenised.")
        return "\n".join(lines)


def _check_shard_provenance(root: Path, index: ShardIndex, *,
                            accept_leaking_shards: str | None) -> None:
    """Refuse shards whose own index says the corpus behind them leaked.

    The gate on the corpus directory is the one that matters, but without this
    the shards launder it: tokenise once with ``accept_leaking_corpus``, and
    every later run reads ``*.bin`` and asks nothing. The acceptance has to be
    re-stated at the point where the leak would reach a model, and the token is
    the one recorded in ``index.json`` — it cannot be re-derived from shards,
    because tokens are not greppable, which is the whole reason this gate
    exists.

    A shard set with no provenance record at all is a *different* statement
    from a verified one, and gets a warning rather than a refusal: it predates
    the record, so refusing it would make every existing shard set unusable
    and the gate the first thing patched out.
    """
    if not index.corpus:
        key = str(root)
        if key not in _WARNED:
            _WARNED.add(key)
            print(f"NOTE: {root.name}/index.json records no corpus "
                  f"provenance, so nothing here can say which corpus these "
                  f"shards read or whether it was verified. Re-run "
                  f"tokenize_corpus to get that record.", file=sys.stderr)
        return

    leaking = [rec for rec in index.corpus if not rec.get("verified", False)]
    if not leaking:
        return
    tokens = sorted({str(rec.get("token", "")) for rec in leaking})
    total = sum(int(rec.get("accepted_leaks", 0)) for rec in leaking)
    if accept_leaking_shards and accept_leaking_shards in tokens:
        print(f"\nTRAINING ON SHARDS BUILT FROM A LEAKING CORPUS: "
              f"{total:,} leak(s) were permitted when these shards were "
              f"written, and that permission is being re-stated now. Whatever "
              f"those values are, this run puts them in the weights.\n",
              file=sys.stderr)
        return
    raise CorpusLeakError(
        f"\nREFUSING THESE SHARDS. {root.name}/index.json records that the "
        f"corpus behind\nthem was permitted to leak: {total:,} leak(s) across "
        f"{len(leaking)} root(s).\n\n"
        f"{index.provenance_report()}\n\n"
        f"Re-tokenise from a clean corpus, or re-state the permission here:\n\n"
        f"    Dataset(..., accept_leaking_shards={tokens[0]!r})\n\n"
        f"The token is the one the corpus gate minted; it is recorded above "
        f"rather than\nre-derived, because a shard is not greppable — which is "
        f"the whole reason this\ngate exists.\n",
        token=tokens[0] if tokens else "", leaks=[])


class Dataset:
    """Memory-mapped token stream with uniform random-window sampling."""

    def __init__(
        self,
        root: Path,
        seq_len: int,
        *,
        val_fraction: float = 0.005,
        split: str = "train",
        seed: int = 1337,
        accept_leaking_shards: str | None = None,
    ) -> None:
        self.index = ShardIndex.load(root)
        _check_shard_provenance(root, self.index,
                                accept_leaking_shards=accept_leaking_shards)
        self.seq_len = seq_len
        self.split = split
        # Sampling is a pure function of (seed, draw index) rather than of a
        # long-lived RNG's accumulated state. A stateful generator cannot be
        # restored on resume without replaying every draw, so a run resumed at
        # step 1,000 silently re-served the batches steps 0-1,000 had already
        # seen and never reached the tail of the stream — the loss curve looks
        # healthy the whole time, because re-learning old data does lower loss.
        # Deriving the generator per draw makes `seek` exact from any step.
        self._seed = seed
        self._draw = 0

        self._maps: list[np.memmap] = []
        self._starts: list[int] = []
        offset = 0
        for shard in self.index.shards:
            path = root / shard["file"]
            mm = np.memmap(path, dtype=TOKEN_DTYPE, mode="r")
            if mm.size != shard["tokens"]:
                raise ValueError(
                    f"{path.name} holds {mm.size:,} tokens but the index claims "
                    f"{shard['tokens']:,}. The shard was rewritten without "
                    "updating the index; re-run tokenize_corpus."
                )
            self._maps.append(mm)
            self._starts.append(offset)
            offset += mm.size
        self.total = offset

        if self.total <= seq_len + 1:
            raise ValueError(
                f"corpus holds {self.total:,} tokens, which is not enough for "
                f"even one window of {seq_len + 1}"
            )

        # Held out by position, not by shuffling. See the module docstring.
        boundary = int(self.total * (1 - val_fraction))
        if split == "train":
            self.lo, self.hi = 0, boundary
        elif split == "val":
            self.lo, self.hi = boundary, self.total
        else:
            raise ValueError(f"unknown split {split!r}")

        if self.hi - self.lo <= seq_len + 1:
            raise ValueError(
                f"{split} split holds {self.hi - self.lo:,} tokens, too few for "
                f"a window of {seq_len + 1}. Lower val_fraction or add corpus."
            )

    def _read(self, start: int, length: int) -> np.ndarray:
        """Read ``length`` tokens from the global position ``start``.

        Windows may straddle a shard boundary, so this stitches. Returning a
        short window instead would bias the sampler toward the interiors of
        shards, which is the subtle version of the bug the module docstring
        warns about.
        """
        out = np.empty(length, dtype=np.int64)
        written = 0
        shard = int(np.searchsorted(self._starts, start, side="right") - 1)
        pos = start - self._starts[shard]
        while written < length:
            mm = self._maps[shard]
            take = min(length - written, mm.size - pos)
            out[written:written + take] = mm[pos:pos + take]
            written += take
            shard += 1
            pos = 0
            if shard >= len(self._maps):
                break
        if written < length:                       # ran off the end; wrap
            out[written:] = self._maps[0][:length - written]
        return out

    def seek(self, draw: int) -> None:
        """Position the sampler at draw ``draw``, so a resumed run continues.

        Call with the number of batches already consumed. Because sampling is a
        pure function of the draw index, this is exact: the stream from here on
        is byte-identical to what an uninterrupted run would have served.
        """
        if draw < 0:
            raise ValueError(f"draw must be non-negative, got {draw}")
        self._draw = draw

    @property
    def draw(self) -> int:
        """Batches served so far — the position to persist for resume."""
        return self._draw

    def batch(self, batch_size: int) -> tuple[np.ndarray, np.ndarray]:
        """One batch of ``(inputs, targets)``, each ``(batch_size, seq_len)``."""
        span = self.hi - self.lo - self.seq_len - 1
        rng = np.random.default_rng((self._seed, self._draw))
        self._draw += 1
        starts = rng.integers(self.lo, self.lo + span, size=batch_size)
        window = np.stack([self._read(int(s), self.seq_len + 1) for s in starts])
        return window[:, :-1], window[:, 1:]

    def iter_batches(self, batch_size: int, n: int) -> Iterator[tuple[np.ndarray, np.ndarray]]:
        for _ in range(n):
            yield self.batch(batch_size)

    def coverage_report(self, batch_size: int = 32, batches: int = 200) -> str:
        """Sample the sampler and report how evenly shards are visited.

        The loader bug this guards against does not announce itself: the loss
        curve looks fine while the model sees the first shard ten times as often
        as the last. Run this once after building shards, not never.
        """
        counts = np.zeros(len(self._maps), dtype=np.int64)
        span = self.hi - self.lo - self.seq_len - 1
        rng = np.random.default_rng(0)
        for _ in range(batches):
            for s in rng.integers(self.lo, self.lo + span, size=batch_size):
                counts[int(np.searchsorted(self._starts, int(s), side="right") - 1)] += 1
        sizes = np.array([m.size for m in self._maps], dtype=np.float64)
        expected = sizes / sizes.sum()
        actual = counts / max(counts.sum(), 1)
        lines = [f"{'shard':<14}{'tokens':>14}{'expected':>10}{'actual':>9}{'drift':>8}"]
        for i, shard in enumerate(self.index.shards):
            lines.append(
                f"{shard['file']:<14}{shard['tokens']:>14,}"
                f"{expected[i]:>9.1%}{actual[i]:>9.1%}"
                f"{actual[i]-expected[i]:>+8.1%}"
            )
        worst = float(np.max(np.abs(actual - expected))) if len(counts) else 0.0
        lines.append(f"\nworst drift {worst:.2%} "
                     f"({'uniform' if worst < 0.02 else 'CHECK THE SAMPLER'})")
        return "\n".join(lines)

    def split_composition(self, tokenizer_path: Path, samples: int = 200) -> str:
        """Decode a sample of this split and report which sources appear.

        Exists because the failure it detects is invisible in every other
        signal. A validation split drawn entirely from one source produces a
        perfectly smooth loss curve and a number that means nothing, and the
        only way to notice is to look at the text. Run it once per corpus build.
        """
        from tokenizers import Tokenizer

        tok = Tokenizer.from_file(str(tokenizer_path))
        # Cheap source fingerprints: strings that are near-exclusive to one
        # source's surface form. Crude, and enough to catch a monoculture.
        markers = {
            "sigma": ("logsource:", "falsepositives:", "condition: selection"),
            "atomic": ("atomic test:", "executor:", "elevation required"),
            "attack": ("ATT&CK ID:", "## Description", "Sub-technique of:"),
            "nvd": ("cvss:", "vector: CVSS", "weakness: CWE-"),
            "manpages": ("SYNOPSIS", "DESCRIPTION", "NAME\n"),
            "psdocs": ("## SYNTAX", "-ParameterName", "```powershell"),
            "ownrepos": ("def ", "import ", "## "),
        }
        hits: dict[str, int] = {}
        span = self.hi - self.lo - self.seq_len - 1
        rng = np.random.default_rng(0)
        for start in rng.integers(self.lo, self.lo + span, size=samples):
            text = tok.decode(list(self._read(int(start), 256)))
            for name, needles in markers.items():
                if any(n in text for n in needles):
                    hits[name] = hits.get(name, 0) + 1

        total = sum(hits.values()) or 1
        lines = [f"{self.split} split composition ({samples} windows sampled)"]
        for name, count in sorted(hits.items(), key=lambda kv: -kv[1]):
            lines.append(f"  {name:<10}{count:>5}  {count/total:>6.1%}")
        distinct = len(hits)
        if distinct <= 1:
            lines.append(
                "\n  MONOCULTURE: this split is drawn from one source. Loss "
                "measured here describes that source, not the corpus. Re-shard "
                "with interleaving."
            )
        else:
            lines.append(f"\n  {distinct} sources present — representative.")
        return "\n".join(lines)

    def __repr__(self) -> str:
        return (f"Dataset({self.split}, {self.hi - self.lo:,} tokens, "
                f"seq_len={self.seq_len}, {len(self._maps)} shard(s))")
