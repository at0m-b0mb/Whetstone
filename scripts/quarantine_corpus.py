#!/usr/bin/env python3
"""Move every corpus generation that predates the redaction fixes aside.

    python3 scripts/quarantine_corpus.py                 # dry run, prints the plan
    python3 scripts/quarantine_corpus.py --apply          # performs it
    python3 scripts/quarantine_corpus.py --scan-full      # every byte, not a sample

**It moves. It never deletes.** Every generation on this disk is the operator's
own data and the decision to destroy it is his, so the only filesystem calls in
here are ``os.rename`` and ``os.symlink``; there is no ``unlink`` and no
``rmtree``, and a cross-device move is refused rather than performed as the
copy-then-delete that ``shutil.move`` would silently turn it into.

Why this exists. Every corpus generation on disk was built before the redaction
fixes landed, and a published checkpoint is not greppable: whatever the corpus
leaks, the weights keep. A generation left in place under a confident name is a
generation somebody trains on at 2am. So the contaminated ones move to
``QUARANTINE-<reason>/`` with a README that says what was found, in
fingerprints, and gives the exact ``mv`` back.

Three things this is careful about, each because of a real trap:

**The symlinks.** ``clean-v8`` and ``tokenized-v8`` are symlinks to ``-v7``, so
"v8 was verified" is a statement about v7's bytes. Moving the target and leaving
the link produces a dangling ``clean-v8`` that reads as *missing* rather than as
*quarantined* — the worse of the two failures, because missing invites a rebuild
under the same name while the leaking bytes sit somewhere nobody is looking. So
a link whose target is being quarantined is moved with its target and repointed
inside the quarantine, and the README carries the ``ln -sfn`` that puts the
original target string back.

**A clean scan is not a clean verdict.** The scanner reports what it found; it
cannot report what it was never able to look for. The fallback needle set has no
email layer, a sampled scan has seen a fraction of the bytes, and a tokenizer
shard is token ids with no text in it at all. So a generation with zero hits is
still quarantined when it predates the youngest redaction fix — on provenance,
labelled as provenance, and never dressed up as a measurement.

**No needle is ever written anywhere.** Needles come from the operating system
at runtime; findings are reported as ``kind + length + sha256 prefix``. The
audit that found these leaks created a new one by writing its own needle table
to a JSON file, and Vigil's keystone property — never print a full secret — is
the standard this holds to.

What it will not do: it will not touch ``models/``. A checkpoint trained on a
quarantined generation is covered by a rule in ``docs/PRIVACY.md``, not by a
move, because a model file is not a corpus generation and conflating the two
would let a quarantine report imply a publication decision it has not made.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

# ``scripts/`` is not a package: a bare ``python3 scripts/x.py`` puts
# ``scripts/`` on sys.path and not the repo. Make the repo importable
# either way, so the data-root policy has exactly one home.
if str(Path(__file__).resolve().parents[1]) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from whetstone.paths import data_root  # noqa: E402


CORPUS = data_root() / "corpus"
REPO = Path(__file__).resolve().parents[1]

#: The files whose mtime decides what "predates the fix" means. Derived rather
#: than a hardcoded date: a generation is contaminated if it is older than the
#: youngest fix that was supposed to be in it, and that question answers itself
#: again on the next build without anybody editing a constant here.
FIX_SOURCES = (
    "training/corpus/build.py",
    "training/corpus/verify.py",
    "training/corpus/sources/ownrepos.py",
    "training/trajectories.py",
)

#: Printed in the plan and the README as the reason a generation moved.
REASONS = {
    "identity-leak": "the scanner found this machine's identifiers in it",
    "pre-redaction-fix": "built before the youngest redaction fix; no hit "
                         "from the scanner that ran, which is not a clean bill",
    "derived": "derived from a quarantined generation, and token ids cannot "
               "be text-scanned, so provenance is the only evidence there is",
    "stale-cache": "a fetch cache no live adapter reads any more",
}

C = {"dim": "\033[2m", "b": "\033[1m", "g": "\033[32m", "y": "\033[33m",
     "r": "\033[31m", "c": "\033[36m", "x": "\033[0m"}


def fingerprint(value: str) -> str:
    """``len=<n>,sha256=<8 hex>`` — the only form a needle is ever reported in.

    The same spelling agent C's ``verify.Leak.fingerprint`` uses, so a report
    assembled from both scanners reads as one report.
    """
    return "len=%d,sha256=%s" % (
        len(value), hashlib.sha256(value.encode("utf-8")).hexdigest()[:8])


# ---------------------------------------------------------------------------
# the scanner: agent C's verifier when it exists, a needle pass when it does not
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Leak:
    """One finding. Deliberately field-compatible with ``verify.Leak``."""

    kind: str
    path: str
    line: int
    field: str
    fingerprint: str


class _Needles:
    """This machine's identifiers, read from the OS, never persisted.

    The fallback for a tree where ``training/corpus/verify.py`` does not exist
    yet. It covers two layers:

    *identity* — whatever ``training.trajectories.identity_leaks`` knows, which
    is the account name, the host name in both spellings, the home path and the
    per-user temp directories. Reached through the public function rather than
    the private table so this script does not pin another module's internals:
    ``identity_leaks`` returns the literals it found, which is all a needle
    scan needs.

    *network* — the MAC addresses and global IPv6 addresses ``ifconfig`` reports
    right now, plus the /64 prefixes of those addresses. This layer exists
    because the identity table has none, and the identifiers it covers are the
    ones the operator cannot change: a NIC address is hardware-derived and a
    /64 is his subscription.

    ``__repr__`` and ``__str__`` reveal counts and nothing else. That is not
    decoration. The audit that found these leaks wrote its own needle table to
    a JSON file and then reported that it had not.
    """

    __slots__ = ("_pairs",)

    def __init__(self, pairs: Sequence[tuple[str, str]]) -> None:
        self._pairs = tuple(pairs)

    def __repr__(self) -> str:
        kinds: dict[str, int] = {}
        for kind, _ in self._pairs:
            kinds[kind] = kinds.get(kind, 0) + 1
        inner = ", ".join(f"{k}={v}" for k, v in sorted(kinds.items()))
        return f"<Needles {len(self._pairs)} needles: {inner}>"

    __str__ = __repr__

    def __len__(self) -> int:
        return len(self._pairs)

    def __iter__(self):
        return iter(self._pairs)

    def probes(self) -> list[tuple[str, bytes, str]]:
        """``(kind, lowercased bytes, fingerprint)`` for a raw-byte pass."""
        return [(kind, value.lower().encode("utf-8", "surrogatepass"),
                 fingerprint(value)) for kind, value in self._pairs]


def _identity_needles() -> list[tuple[str, str]]:
    """The identity layer, via the public function, with nothing persisted."""
    try:
        from training.trajectories import identity_leaks
    except Exception:                                       # noqa: BLE001
        return []
    # A probe document containing every literal the table knows: handing the
    # table's own machine-read values back to it is the only way to enumerate
    # them through a function that takes text. Built by asking the module for
    # the literals present in a document assembled from the OS the same way the
    # module assembles them, which is why the probe is the OS itself.
    import getpass
    import glob
    import platform
    import socket
    import tempfile

    candidates = {getpass.getuser(), socket.gethostname(), platform.node(),
                  str(Path.home()), tempfile.gettempdir()}
    candidates.update(glob.glob("/var/folders/*/*/T"))
    try:
        import pwd

        candidates.add(pwd.getpwuid(os.getuid()).pw_gecos.split(",")[0].strip())
    except Exception:                                       # noqa: BLE001
        pass
    for name in list(candidates):
        if name and "." in name:
            candidates.add(name.partition(".")[0])
        if name:
            resolved = str(Path(name).resolve()) if name.startswith("/") else ""
            if resolved:
                candidates.add(resolved)
    probe = "\n".join(sorted(c for c in candidates if c))
    return [("identity", form) for form in identity_leaks(probe)]


def _network_needles() -> list[tuple[str, str]]:
    """MACs, global IPv6 addresses and their /64 prefixes, from ``ifconfig``.

    The layer the identity table does not have. Only *global* addresses are
    taken: a link-local ``fe80::`` is the same on every machine on the planet
    and counting it would bury the real findings, which is the mistake an
    uncalibrated scanner over a security corpus makes first. The /64 prefix is
    kept as well as the address, because the prefix is the subscription and it
    identifies the household even when the host part has rotated.
    """
    out: list[tuple[str, str]] = []
    for argv in (["/sbin/ifconfig"], ["ip", "-o", "addr"]):
        try:
            text = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=20, errors="replace").stdout
        except (OSError, subprocess.SubprocessError):
            continue
        if text:
            break
    else:
        return out
    for mac in sorted(set(re.findall(r"\b(?:ether|link/ether) ([0-9a-f:]{17})\b",
                                     text))):
        out.append(("mac", mac))
    prefixes: set[str] = set()
    for raw in sorted(set(re.findall(r"\binet6 ([0-9a-fA-F:]+)", text))):
        try:
            addr = ipaddress.IPv6Address(raw)
        except ValueError:
            continue
        # is_global excludes fe80::/10, ::1, and — on purpose — the
        # 2001:db8::/32 documentation range this corpus is full of by design.
        if not addr.is_global:
            continue
        out.append(("ipv6-global", str(addr)))
        net = ipaddress.IPv6Network((addr, 64), strict=False)
        # The textual prefix, trimmed of its final ':' group separator so it
        # matches the way an address on that /64 is actually spelled.
        prefixes.add(str(net.network_address).rstrip("0").rstrip(":"))
    for pfx in sorted(prefixes):
        if len(pfx) >= 8:
            out.append(("ipv6-prefix64", pfx))
    return out


def host_needles() -> _Needles:
    """Everything this machine can leak, derived now, held in memory only."""
    return _Needles(_identity_needles() + _network_needles())


@dataclass
class Scan:
    """What a scanner managed to look at, and what it found.

    ``mode`` is load-bearing. ``verify.py`` means agent C's verifier ran;
    ``fallback`` means the needle pass above ran, which has no email layer;
    ``unscannable`` means the bytes are not text and nothing looked. A caller
    that treats all three the same has turned "nobody checked" into "clean".
    """

    mode: str
    files: int = 0
    scanned: int = 0
    sampled: bool = False
    occurrences: int = 0
    by_needle: dict[str, int] = field(default_factory=dict)
    leaks: list[Leak] = field(default_factory=list)
    note: str = ""
    seconds: float = 0.0

    @property
    def leaking(self) -> bool:
        return self.occurrences > 0 or bool(self.leaks)


def _text_files(root: Path, limit: int | None) -> tuple[list[Path], int]:
    """Every text-ish file under *root*, breadth-stable, links never followed.

    ``os.walk(followlinks=False)`` rather than ``rglob``: ``ownrepos`` once
    followed this repository's ``data`` symlink into the SSD and pulled the
    corpus cache back in as prose. The corpus ate itself, and the only thing
    that caught it was the balance report.
    """
    found: list[Path] = []
    total = 0
    for base, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs
                         if d not in {"__pycache__", ".git"}
                         and not d.startswith("QUARANTINE-"))
        for name in sorted(names):
            if name.startswith("."):
                continue
            if name.endswith((".bin", ".npy", ".safetensors", ".gz", ".zip")):
                continue
            total += 1
            found.append(Path(base) / name)
    if limit is not None and limit > 0 and len(found) > limit:
        step = len(found) / float(limit)
        found = [found[int(i * step)] for i in range(limit)]
    return found, total


def _needle_pass(paths: Iterable[Path], needles: _Needles,
                 root: Path) -> tuple[int, dict[str, int], list[Leak]]:
    """Count needle occurrences per file, then find the first line of each hit.

    Two phases on purpose. The whole-file ``bytes.count`` is the verdict and it
    runs at memchr speed over hundreds of megabytes; the line walk runs only on
    a file that already came back dirty, so the cost of knowing *where* is paid
    only where there is something to point at.
    """
    probes = needles.probes()
    total = 0
    by_needle: dict[str, int] = {}
    leaks: list[Leak] = []
    for path in paths:
        try:
            blob = path.read_bytes().lower()
        except OSError:
            continue
        hit: list[tuple[str, bytes, str]] = []
        for kind, probe, fpr in probes:
            n = blob.count(probe)
            if n:
                total += n
                by_needle[f"{kind} {fpr}"] = by_needle.get(f"{kind} {fpr}", 0) + n
                hit.append((kind, probe, fpr))
        if not hit:
            continue
        del blob
        want = {fpr for _, _, fpr in hit}
        try:
            with path.open("rb") as fh:
                for lineno, raw in enumerate(fh, 1):
                    low = raw.lower()
                    for kind, probe, fpr in hit:
                        if fpr in want and probe in low:
                            want.discard(fpr)
                            leaks.append(Leak(
                                kind=kind,
                                path=str(path.relative_to(root)),
                                line=lineno, field="text", fingerprint=fpr))
                    if not want:
                        break
        except OSError:
            continue
    return total, by_needle, leaks


def _load_verifier() -> Any:
    """Agent C's verifier, or ``None`` — and the degradation is reported."""
    if str(REPO) not in sys.path:
        sys.path.insert(0, str(REPO))
    try:
        from training.corpus import verify as module
    except Exception:                                       # noqa: BLE001
        return None
    needed = ("host_needles", "scan_file", "verify_corpus")
    if not all(hasattr(module, name) for name in needed):
        return None
    return module


def scan_generation(root: Path, *, verifier: Any, needles: _Needles,
                    sample: int | None) -> Scan:
    """Look for leaks in one generation, with whatever instrument exists.

    ``sample`` of ``None`` scans every text file; an integer scans that many,
    spread across the walk rather than taken off the head, because
    ``nvd.jsonl`` is ordered oldest-first and a head sample of this corpus
    describes 1999.
    """
    if not root.exists():
        return Scan(mode="unscannable", note="path does not exist")
    files, total = _text_files(root, sample)
    if total == 0:
        return Scan(mode="unscannable", files=0,
                    note="no text files — token ids or an empty tree; "
                         "provenance is the only evidence available")
    t0 = time.time()
    if verifier is not None:
        try:
            vn = verifier.host_needles()
            found = []
            for path in files:
                found.extend(verifier.scan_file(path, needles=vn))
            leaks = [Leak(kind=getattr(l, "kind", "?"),
                          path=str(Path(getattr(l, "path", str(path)))),
                          line=int(getattr(l, "line", 0)),
                          field=str(getattr(l, "field", "?")),
                          fingerprint=str(getattr(l, "fingerprint", "?")))
                     for l in found]
            by: dict[str, int] = {}
            for l in leaks:
                key = f"{l.kind} {l.fingerprint}"
                by[key] = by.get(key, 0) + 1
            return Scan(mode="verify.py", files=total, scanned=len(files),
                        sampled=len(files) < total, occurrences=len(leaks),
                        by_needle=by, leaks=leaks[:40],
                        seconds=time.time() - t0)
        except Exception as exc:                            # noqa: BLE001
            note = (f"verify.py raised {type(exc).__name__}: {exc}"[:160] +
                    " — fell back to the needle pass")
            occ, by, leaks = _needle_pass(files, needles, root)
            return Scan(mode="fallback", files=total, scanned=len(files),
                        sampled=len(files) < total, occurrences=occ,
                        by_needle=by, leaks=leaks[:40], note=note,
                        seconds=time.time() - t0)
    occ, by, leaks = _needle_pass(files, needles, root)
    return Scan(mode="fallback", files=total, scanned=len(files),
                sampled=len(files) < total, occurrences=occ, by_needle=by,
                leaks=leaks[:40],
                note="training/corpus/verify.py not importable: this pass has "
                     "an identity and a network layer and NO email layer, so a "
                     "zero here says nothing about third-party addresses",
                seconds=time.time() - t0)


# ---------------------------------------------------------------------------
# the inventory
# ---------------------------------------------------------------------------

@dataclass
class Entry:
    """One thing in the corpus directory, measured rather than assumed."""

    name: str
    path: Path
    kind: str
    is_symlink: bool
    link_target: str = ""
    resolved: Path | None = None
    dangling: bool = False
    bytes: int = 0
    files: int = 0
    mtime: float = 0.0
    scan: Scan | None = None
    reason: str = ""
    why: str = ""

    @property
    def keep(self) -> bool:
        return not self.reason


def _tree_size(root: Path) -> tuple[int, int, float]:
    """Real bytes, file count and newest mtime, following no links."""
    total = count = 0
    newest = 0.0
    for base, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(dirs)
        for name in names:
            path = Path(base) / name
            try:
                st = path.lstat()
            except OSError:
                continue
            count += 1
            total += st.st_size
            newest = max(newest, st.st_mtime)
    try:
        newest = max(newest, root.lstat().st_mtime)
    except OSError:
        pass
    return total, count, newest


def highest_missing(path: Path) -> Path:
    """The shallowest ancestor of *path* that does not exist.

    Naming this rather than the leaf is the difference between "raw/ is gone,
    did somebody move it" and "the drive is unplugged".
    """
    missing = path
    probe = path
    while probe != probe.parent:
        if probe.exists():
            break
        missing = probe
        probe = probe.parent
    return missing


def require_volume(path: Path, *, what: str = "the corpus") -> None:
    """Refuse to continue if the volume holding *path* has gone away.

    Not defensive programming and not hypothetical: the external SSD this
    corpus lives on disconnected in the middle of a full scan, and the
    traceback it produced named a missing ``raw/`` directory — which reads
    exactly like a directory somebody moved. Mid-``--apply`` the same event
    would leave the plan half done with no statement of where it stopped, so
    this is re-run before every single move.
    """
    if path.exists():
        return
    missing = highest_missing(path)
    if missing.parent == Path("/Volumes"):
        detail = (f"the volume {missing.name!r} is not mounted. Reconnect the "
                  f"drive and re-run. Nothing was changed.")
    elif missing == path:
        detail = (f"its parent is mounted, so {what} itself is missing — "
                  f"check whether it was already moved.")
    else:
        detail = f"{missing} does not exist either, so the whole tree is gone."
    raise SystemExit(f"{path} is not there: {detail}")


def _kind_of(name: str) -> str:
    if name.startswith("clean"):
        return "clean"
    if name.startswith("tokenized"):
        return "tokenized"
    if name.startswith("trajectories"):
        return "trajectories"
    if name == "raw":
        return "raw"
    return "other"


def fix_epoch(repo: Path = REPO) -> tuple[float, str]:
    """The youngest redaction fix's mtime, and which file it was.

    A generation older than this was built by code that did not contain the
    fix, whatever its own report said at the time. That is the whole
    provenance test, and deriving it means it stays true after the next commit
    instead of becoming a stale constant somebody has to remember.
    """
    newest, which = 0.0, "none of the redaction sources exist"
    for rel in FIX_SOURCES:
        path = repo / rel
        try:
            st = path.stat()
        except OSError:
            continue
        if st.st_mtime > newest:
            newest, which = st.st_mtime, rel
    return newest, which


def inventory(corpus: Path, *, verifier: Any, needles: _Needles,
              sample: int | None, scan_raw: bool,
              scan: bool = True) -> list[Entry]:
    """Every generation in *corpus*, with its real size, links and leaks."""
    entries: list[Entry] = []
    for child in sorted(corpus.iterdir()):
        if child.name.startswith(".") or child.name.startswith("QUARANTINE-"):
            continue
        is_link = child.is_symlink()
        entry = Entry(name=child.name, path=child, kind=_kind_of(child.name),
                      is_symlink=is_link)
        if is_link:
            entry.link_target = os.readlink(child)
            target = Path(entry.link_target)
            if not target.is_absolute():
                target = child.parent / target
            entry.resolved = target
            entry.dangling = not target.exists()
            try:
                entry.mtime = child.lstat().st_mtime
            except OSError:
                pass
            # Not sized and not scanned: a link has no bytes of its own, and
            # scanning it would report its target's leaks a second time under a
            # second name, which is how one leaking generation becomes two in a
            # count and then one of them gets "fixed".
            entries.append(entry)
            continue
        entry.bytes, entry.files, entry.mtime = _tree_size(child)
        if child.name == "raw":
            entries.append(entry)
            try:
                children = sorted(p for p in child.iterdir() if p.is_dir())
            except OSError as exc:
                entry.scan = Scan(mode="unscannable",
                                  note=f"could not be read: {exc}")
                continue
            for sub in children:
                sub_entry = Entry(name=f"raw/{sub.name}", path=sub, kind="raw",
                                  is_symlink=sub.is_symlink())
                sub_entry.bytes, sub_entry.files, sub_entry.mtime = _tree_size(sub)
                if scan and scan_raw:
                    sub_entry.scan = scan_generation(
                        sub, verifier=verifier, needles=needles, sample=sample)
                entries.append(sub_entry)
            continue
        if scan:
            entry.scan = scan_generation(child, verifier=verifier,
                                         needles=needles, sample=sample)
        entries.append(entry)
    return entries


# ---------------------------------------------------------------------------
# the verdict
# ---------------------------------------------------------------------------

def live_source_names() -> tuple[frozenset[str], str]:
    """The names the live source adapters fetch into, from the adapters.

    ``raw/<name>`` is a fetch cache for the source called ``<name>``, so the
    only honest way to tell a live cache from a stale one is to ask the build
    which sources exist. Discovered rather than listed, for the reason
    ``discover_sources`` itself gives: a source that exists but was forgotten
    in a registry is the silent omission this codebase is written to prevent —
    and the inverse, a cache nobody fetches into any more, is how 1,197 files
    of C and Python from a superseded ``ownrepos`` adapter stayed on the disk
    for a month.

    If the adapters will not import, every cache is treated as live. Being
    unsure is a reason to leave his data alone, not a reason to move it.
    """
    if str(REPO) not in sys.path:
        sys.path.insert(0, str(REPO))
    try:
        from training.corpus.build import discover_sources

        names = frozenset(spec.name for spec in discover_sources())
    except Exception as exc:                                # noqa: BLE001
        return frozenset(), (f"source adapters would not import "
                             f"({type(exc).__name__}) — every raw cache "
                             f"treated as live")
    return names, f"{len(names)} live source adapters"


def classify(entries: Sequence[Entry], *, epoch: float,
             epoch_source: str) -> None:
    """Fill in ``reason`` and ``why`` for every entry. Evidence first.

    The order matters. A measured hit is a stronger reason than a date, and a
    date is a stronger reason than a guess about what a shard contains — so
    each entry is labelled with the strongest evidence that applies to it, and
    the label is printed, so nobody reads "quarantined" and assumes somebody
    saw a leak.
    """
    live, live_note = live_source_names()
    quarantined: set[str] = set()
    for entry in entries:
        if entry.kind == "raw" and entry.name == "raw":
            entry.why = ("the fetch cache tree itself; its children are judged "
                         "individually against " + live_note)
            continue
        if entry.kind == "raw":
            short = entry.name.partition("/")[2]
            if not live or short in live:
                entry.why = ("a live fetch cache for source %r, upstream of "
                             "the build's chokepoint by design — identity in "
                             "it is expected, and moving it forces a re-fetch "
                             "that loses collection provenance" % short)
                continue
            entry.reason = "stale-cache"
            entry.why = ("no live source adapter is called %r, so nothing "
                         "fetches into this any more" % short)
            quarantined.add(entry.name)
            continue
        if entry.is_symlink:
            continue                      # decided below, with its target
        if entry.scan is not None and entry.scan.leaking:
            entry.reason = "identity-leak"
            entry.why = ("%d needle occurrences over %d distinct needles (%s)"
                         % (entry.scan.occurrences, len(entry.scan.by_needle),
                            entry.scan.mode))
            quarantined.add(entry.name)
            continue
        if entry.kind == "tokenized":
            version = entry.name.partition("tokenized")[2].lstrip("-")
            entry.reason = "derived"
            entry.why = ("token ids, not text: by naming convention this came "
                         "from clean-%s, and index.json records no source "
                         "generation, so the derivation is an inference from "
                         "the name and nothing else"
                         % (version or "(unversioned)"))
            quarantined.add(entry.name)
            continue
        if entry.mtime and entry.mtime < epoch:
            scanned = ("no scan ran" if entry.scan is None else
                       "the %s scan found nothing" % entry.scan.mode)
            entry.reason = "pre-redaction-fix"
            entry.why = ("built %s, older than %s (%s); %s, which is not a "
                         "clean bill"
                         % (time.strftime("%Y-%m-%d", time.localtime(entry.mtime)),
                            time.strftime("%Y-%m-%d", time.localtime(epoch)),
                            epoch_source, scanned))
            quarantined.add(entry.name)
            continue
        entry.why = ("newer than the youngest redaction fix, and "
                     + ("no scan ran" if entry.scan is None
                        else "no hit from the %s scan" % entry.scan.mode))

    # The links last, so a link follows its target's verdict rather than
    # guessing at one. A link to a quarantined generation is itself a name that
    # reads as available, which is exactly the failure to avoid.
    for entry in entries:
        if not entry.is_symlink:
            continue
        target_name = Path(entry.link_target).name
        if entry.dangling:
            entry.reason = "derived"
            entry.why = (f"dangling: its target {target_name!r} is already "
                         "gone, so this name reads as missing rather than as "
                         "quarantined")
        elif target_name in quarantined:
            entry.reason = next(e.reason for e in entries
                                if e.name == target_name)
            entry.why = (f"a symlink to {target_name}, which is being "
                         f"quarantined — left here it would dangle and read "
                         f"as missing")
        else:
            entry.why = f"a symlink to {target_name}, which stays"


# ---------------------------------------------------------------------------
# the plan
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Step:
    """One filesystem action. ``move`` is a rename; ``relink`` rewrites a link.

    ``origin`` is only set on a relink: it is where the link lived *before* the
    move, which is where the reversal has to put the original target back. A
    reversal that ran ``ln -sfn`` against the quarantine path instead would
    restore the bytes and leave the link pointing into an empty quarantine —
    which is the failure this script was written to avoid, reintroduced by its
    own undo.
    """

    kind: str
    src: Path
    dst: Path
    detail: str = ""
    origin: Path | None = None


def build_plan(entries: Sequence[Entry], corpus: Path) -> list[Step]:
    """The moves, and the relinks that keep the quarantine internally honest."""
    steps: list[Step] = []
    moved: dict[str, Path] = {}
    for entry in entries:
        if entry.keep:
            continue
        dst = corpus / f"QUARANTINE-{entry.reason}" / entry.name
        steps.append(Step("move", entry.path, dst,
                          f"{entry.reason}: {entry.why}"))
        moved[entry.name] = dst
    for entry in entries:
        if entry.keep or not entry.is_symlink or entry.dangling:
            continue
        target_name = Path(entry.link_target).name
        new_target = moved.get(target_name)
        if new_target is None:
            continue
        link = moved[entry.name]
        steps.append(Step("relink", link, new_target,
                          f"was -> {entry.link_target}", origin=entry.path))
    return steps


def _same_device(src: Path, dst_parent: Path) -> bool:
    """Both ends on one device, or the move is a copy-then-delete in disguise.

    ``lstat`` on the source, not ``stat``. The source can be a symlink whose
    target has already been moved by an earlier step of this very plan, and
    ``stat`` follows the link: it raises on a dangling one, the move is refused,
    and the plan leaves exactly the half-moved state this check exists to
    prevent. What is being moved is the link itself, so the link's own device
    is the one that matters.
    """
    probe = dst_parent
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    try:
        return os.lstat(src).st_dev == os.stat(probe).st_dev
    except OSError:
        return False


def readme(entries: Sequence[Entry], steps: Sequence[Step], reason: str,
           corpus: Path, epoch_source: str) -> str:
    """The README that goes in a quarantine directory. Fingerprints only."""
    mine = [e for e in entries if e.reason == reason]
    lines = [
        f"# QUARANTINE-{reason}",
        "",
        f"`{REASONS.get(reason, reason)}`",
        "",
        f"Moved {time.strftime('%Y-%m-%d %H:%M %Z')} by "
        "`scripts/quarantine_corpus.py`.",
        "",
        "**Nothing here was deleted.** Every path below was moved with",
        "`os.rename` on one device. The reversal is at the bottom of this file",
        "and it is exact.",
        "",
        "## Why",
        "",
        "Every corpus generation on this disk was built before the redaction",
        "fixes landed. A published checkpoint is not greppable and not",
        "removable: whatever the corpus leaked, the weights keep. So these",
        "generations are out of the way of the next training run until a",
        "rebuild replaces them.",
        "",
        f"The provenance cut is the mtime of `{epoch_source}` — the youngest",
        "redaction fix in the tree. A generation older than that was built by",
        "code that did not contain it, whatever its own report said.",
        "",
        "## What was found",
        "",
        "Values are reported as `kind len=<n>,sha256=<8 hex>` and never as",
        "values. A needle in a README is a new leak, which is exactly the",
        "mistake the audit that found these made.",
        "",
    ]
    for entry in mine:
        scan = entry.scan
        lines.append(f"### {entry.name}")
        lines.append("")
        if entry.is_symlink:
            lines.append(f"- symlink, was `-> {entry.link_target}`")
        else:
            lines.append(f"- {entry.bytes:,} bytes in {entry.files:,} files")
        if entry.mtime:
            lines.append("- mtime "
                         + time.strftime("%Y-%m-%d %H:%M",
                                         time.localtime(entry.mtime)))
        lines.append(f"- reason: {entry.why}")
        if scan is None:
            lines.append("- not scanned")
        elif scan.mode == "unscannable":
            lines.append(f"- NOT SCANNED: {scan.note}")
        else:
            lines.append(f"- scanner: {scan.mode}, {scan.scanned:,} of "
                         f"{scan.files:,} files"
                         + (" (sampled)" if scan.sampled else " (all)"))
            if scan.note:
                lines.append(f"- scanner note: {scan.note}")
            if scan.by_needle:
                lines.append("- occurrences by needle:")
                for key, count in sorted(scan.by_needle.items(),
                                         key=lambda kv: -kv[1]):
                    lines.append(f"    - `{key}` x{count:,}")
                lines.append("- first line of each hit:")
                for leak in scan.leaks[:12]:
                    lines.append(f"    - `{leak.path}`:{leak.line} "
                                 f"[{leak.kind}] `{leak.fingerprint}`")
            else:
                lines.append("- no needle hit from the scanner that ran. That "
                             "is not a clean bill: see the reason above.")
        lines.append("")
    lines += [
        "## Reversing this",
        "",
        "```sh",
    ]
    for step in steps:
        if step.kind == "move":
            lines.append(f"mkdir -p {shellquote(str(step.src.parent))}")
            lines.append(f"mv {shellquote(str(step.dst))} "
                         f"{shellquote(str(step.src))}")
        else:
            original = step.detail.replace("was -> ", "", 1)
            where = step.origin or step.src
            lines.append(f"ln -sfn {shellquote(original)} "
                         f"{shellquote(str(where))}")
    lines += [
        "```",
        "",
        "The `ln -sfn` lines matter. A symlink whose target moved was",
        "repointed inside this directory so the quarantine is not full of",
        "dangling names; restoring the move without restoring the link leaves",
        "a link pointing into a quarantine directory that no longer holds",
        "anything.",
        "",
        "## The part a move cannot fix",
        "",
        "Tokenizers and checkpoints derived from these generations are still",
        "in `models/`. They were not touched, because a model file is not a",
        "corpus generation and this script does not make publication",
        "decisions. The rule that covers them is in `docs/PRIVACY.md`: no",
        "checkpoint trained on a quarantined generation may be published.",
        "",
    ]
    return "\n".join(lines) + "\n"


def shellquote(text: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_@%+=:,./-]+", text):
        return text
    return "'" + text.replace("'", "'\\''") + "'"


def apply_plan(steps: Sequence[Step], *, dry: bool) -> list[str]:
    """Perform the plan, or say what it would do. Idempotent either way.

    A relink whose move was refused is refused too. Otherwise a refused move
    leaves the original link in place *and* writes a second link of the same
    name inside the quarantine — two names for one generation, which is the
    confusion this whole script exists to end.
    """
    log: list[str] = []
    refused: set[Path] = set()
    done = 0
    for step in steps:
        if step.kind == "move":
            if not step.src.exists() and not step.src.is_symlink():
                log.append(f"SKIP  {step.src.name}: already moved")
                continue
            if step.dst.exists() or step.dst.is_symlink():
                log.append(f"REFUSE {step.dst} exists — nothing overwritten")
                refused.add(step.dst)
                continue
            if not _same_device(step.src, step.dst.parent):
                log.append(f"REFUSE {step.src.name}: destination is on another "
                           "device, and a cross-device move is a copy followed "
                           "by a delete. Nothing was moved.")
                refused.add(step.dst)
                continue
            log.append(f"mv    {step.src} -> {step.dst}")
            if not dry:
                # Re-checked per step rather than once at the start. A volume
                # that disappears between two moves leaves the plan half
                # applied, and a half-applied quarantine is worse than none:
                # the generation is neither where the build looks nor where the
                # README says it went.
                try:
                    require_volume(step.dst.parent.parent)
                except SystemExit as exc:
                    log.append(f"STOPPED after {done} of {len(steps)} steps: "
                               f"{exc}")
                    return log
                step.dst.parent.mkdir(parents=True, exist_ok=True)
                os.rename(step.src, step.dst)
                done += 1
        else:
            if step.src in refused or step.dst in refused:
                log.append(f"REFUSE relink {step.src.name}: its move did not "
                           "happen, so there is nothing here to repoint")
                continue
            log.append(f"relink {step.src} -> {step.dst}  ({step.detail})")
            if not dry:
                # symlink to a fresh name then os.replace: the swap is atomic
                # and never leaves the path without a link. The only thing this
                # script ever discards is a link's pointer, and the README
                # carries the ln -sfn that puts the original string back.
                tmp = step.src.with_name(step.src.name + ".relink-tmp")
                os.symlink(step.dst, tmp)
                os.replace(tmp, step.src)
    return log


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _render_inventory(entries: Sequence[Entry]) -> None:
    hdr = (f"{'generation':<22}{'bytes':>14}{'files':>9}{'mtime':>12}"
           f"{'scan':>12}{'needle hits':>13}")
    print(C["b"] + hdr + C["x"])
    print(C["dim"] + "-" * len(hdr) + C["x"])
    for entry in entries:
        scan = entry.scan
        if entry.is_symlink:
            size, files = "symlink", ""
        else:
            size, files = f"{entry.bytes:,}", f"{entry.files:,}"
        when = (time.strftime("%Y-%m-%d", time.localtime(entry.mtime))
                if entry.mtime else "")
        mode = scan.mode if scan else "-"
        hits = f"{scan.occurrences:,}" if scan and scan.mode != "unscannable" else "-"
        tint = C["r"] if (scan and scan.leaking) else C["dim"]
        print(f"  {entry.name:<20}{size:>14}{files:>9}{when:>12}"
              f"{mode:>12}{tint}{hits:>13}{C['x']}")
        if entry.is_symlink:
            arrow = "DANGLING -> " if entry.dangling else "-> "
            tint = C["r"] if entry.dangling else C["dim"]
            print(f"      {tint}{arrow}{entry.link_target}{C['x']}")
        if scan and scan.note:
            print(f"      {C['y']}{scan.note}{C['x']}")
        if scan and scan.by_needle:
            for key, count in sorted(scan.by_needle.items(),
                                     key=lambda kv: -kv[1])[:8]:
                print(f"      {C['dim']}{key:<42}{count:>9,}{C['x']}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Inventory the corpus and move contaminated generations "
                    "aside. Dry run unless --apply.")
    p.add_argument("--corpus", type=Path, default=CORPUS)
    p.add_argument("--apply", action="store_true",
                   help="perform the plan (default is to print it only)")
    p.add_argument("--scan-sample", type=int, default=400, metavar="N",
                   help="text files scanned per generation (default 400); a "
                        "sampled zero is not a clean verdict and is labelled")
    p.add_argument("--scan-full", action="store_true",
                   help="scan every text file — slower and the only scan whose "
                        "zero means anything")
    p.add_argument("--no-scan", action="store_true",
                   help="inventory and provenance only, no leak scan")
    p.add_argument("--scan-raw", action="store_true",
                   help="also scan raw/*, which is upstream of the chokepoint "
                        "and expected to contain identity")
    p.add_argument("--verifier", choices=("auto", "module", "fallback"),
                   default="auto")
    args = p.parse_args(argv)

    require_volume(args.corpus)

    verifier = None
    if args.verifier in ("auto", "module"):
        verifier = _load_verifier()
    if args.verifier == "module" and verifier is None:
        print("training/corpus/verify.py is not importable and --verifier "
              "module was required")
        return 1
    needles = host_needles()
    sample = None if args.scan_full else args.scan_sample

    epoch, epoch_source = fix_epoch()
    print(f"\n{C['b']}{C['c']}corpus quarantine — {args.corpus}{C['x']}")
    print(f"{C['dim']}verifier: "
          f"{'training.corpus.verify' if verifier else 'NOT PRESENT — needle '
             'fallback, no email layer'}{C['x']}")
    print(f"{C['dim']}needles:  {needles!r}  (runtime-derived, never written)"
          f"{C['x']}")
    print(f"{C['dim']}fix cut:  "
          f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(epoch))} "
          f"from {epoch_source}{C['x']}")
    print(f"{C['dim']}scan:     "
          f"{'none' if args.no_scan else ('every text file' if args.scan_full else f'{args.scan_sample} files per generation (sampled)')}"
          f"{C['x']}\n")

    entries = inventory(args.corpus, verifier=verifier, needles=needles,
                        sample=sample, scan_raw=args.scan_raw,
                        scan=not args.no_scan)
    _render_inventory(entries)
    classify(entries, epoch=epoch, epoch_source=epoch_source)

    print(f"\n{C['b']}verdict{C['x']}")
    for entry in entries:
        tint = C["g"] if entry.keep else C["y"]
        label = "KEEP" if entry.keep else entry.reason.upper()
        print(f"  {tint}{label:<20}{C['x']}{entry.name:<22}{C['dim']}"
              f"{entry.why}{C['x']}")

    steps = build_plan(entries, args.corpus)
    if not steps:
        print(f"\n{C['g']}nothing to move{C['x']}")
        return 0

    print(f"\n{C['b']}plan — {len(steps)} steps{C['x']}")
    for line in apply_plan(steps, dry=True):
        print("  " + line)

    if not args.apply:
        print(f"\n{C['y']}DRY RUN — nothing moved. Re-run with --apply.{C['x']}")
        if any("REFUSE" in line for line in apply_plan(steps, dry=True)):
            print(f"{C['r']}The plan is not clean: see REFUSE above.{C['x']}")
            return 1
        return 0

    log = apply_plan(steps, dry=False)
    for line in log:
        print("  " + line)
    for reason in sorted({e.reason for e in entries if not e.keep}):
        out = args.corpus / f"QUARANTINE-{reason}"
        if not out.exists():
            continue
        mine = [s for s in steps
                if f"QUARANTINE-{reason}" in str(s.dst) or
                f"QUARANTINE-{reason}" in str(s.src)]
        (out / "README.md").write_text(
            readme(entries, mine, reason, args.corpus, epoch_source),
            encoding="utf-8")
        print(f"  wrote {out / 'README.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
