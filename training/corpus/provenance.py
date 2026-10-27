"""Provenance exoneration: telling a collision apart from a leak.

One kind of verifier finding is **ambiguous by construction**, and
:mod:`training.corpus.verify` says so in its own output: an RFC1918 address
bound on this machine is *the same bytes* as an RFC1918 address used as an
example in RFC text, an Nmap script, a nuclei template or a Sigma rule. They
cannot be told apart by looking at the value, because there is nothing to tell
apart — they are identical strings.

This module tells them apart by **provenance** instead. If the exact value is
present in the *raw upstream download* of the source that carried it, that
source shipped it: the cache was fetched from the upstream and has never been
near this machine's network configuration. That is proof of origin, not an
excuse for one.

**Why this is a module and not a flag in three programs.** The same question is
asked by three gates built in the same week — ``build.py``'s own post-build
stamp, ``training.data.require_clean_corpus`` guarding ``read_documents``, and
``scripts/gate_corpus.py`` at the orchestration layer. Three copies of a
security policy is three chances for them to disagree, and the one that
disagrees quietly is the one that matters. So the rule lives here and they all
ask it.

**What is deliberately NOT exonerable.** ``identity``, ``email``, ``mac``,
``ipv6-global``, ``volume`` and ``ident-path`` are never exonerated whatever the
cache says. A global IPv6 address or a hardware MAC turning up in an upstream
would mean the upstream had somehow acquired this machine's identifiers — a far
more alarming finding than a leak, and one that must not be silenced by a
provenance check. A rule that can exonerate those is a bypass wearing a
justification.

**No value is ever written anywhere.** :class:`~training.corpus.verify.Needles`
is deliberately unserialisable and exposes no way to read a value back, which is
correct: the audit that found these leaks created a new exposure by writing its
own needle table to a JSON file. So this module re-derives candidates from the
operating system in memory, matches them by fingerprint, uses them, and lets
them fall out of scope. It returns reasons, never values.

Measured instance, 2026-10-15: ``clean-v9`` verified with **4 occurrences of 1
distinct value**, kind ``ipv4-private``, all in ``nselua.jsonl`` ::
``scripts/mrinfo.nse``. The same address sits in Nmap's own ``mrinfo.nse`` and
``mtrace.nse`` inside ``corpus/raw/nselua``. For contrast ``clean-v7`` carried
**23,531** findings that are not exonerable by this rule under any
circumstances — two live global IPv6 addresses, three hardware MACs, the volume
name, the operator's own name and address, and three non-consenting third
parties' names and addresses.
"""

from __future__ import annotations

import functools
import hashlib
import ipaddress
import re
import subprocess
from pathlib import Path
from typing import Any, Iterable
from whetstone.paths import data_root

__all__ = [
    "AMBIGUOUS_KINDS",
    "default_raw",
    "exonerate",
    "partition",
    "fingerprint",
]

#: Kinds whose value cannot be distinguished from legitimate upstream content by
#: inspection, and which are therefore eligible for provenance exoneration.
AMBIGUOUS_KINDS = frozenset({"ipv4-private"})

def default_raw() -> Path:
    """Where each source's untouched download lives by default.

    Whether a cache exists is checked rather than assumed: "not in the
    cache" and "there is no cache" are different facts and only the first is
    evidence of anything.

    A function and not a constant so ``WHETSTONE_DATA`` can be set by a
    caller that imports this module before configuring itself.
    """
    return data_root() / "corpus" / "raw"


def fingerprint(value: str) -> str:
    """The shape ``Leak.fingerprint`` carries: length plus a sha256 prefix.

    Confirmed against a real finding rather than read off the type — the leak in
    ``nselua.jsonl`` reported ``len=10,sha256=3fd8e0d2`` and the sha256 of the
    matching bound address begins with exactly those eight hex digits.
    """
    return f"len={len(value)},sha256={hashlib.sha256(value.encode()).hexdigest()[:8]}"


@functools.lru_cache(maxsize=1)
def _bound_private() -> tuple[str, ...]:
    """RFC1918 IPv4 addresses currently bound on an interface of this machine.

    Cached because the caller asks once per *occurrence*, not once per value: on
    the old generation that was 23,531 questions, and without this it spawned
    ``ifconfig`` for each one. A dirty corpus is precisely when a gate must stay
    responsive, because that is when somebody is waiting on its answer.
    """
    try:
        out = subprocess.run(
            ["ifconfig"], capture_output=True, text=True, timeout=20
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return ()
    found: list[str] = []
    for raw in re.findall(r"inet (\d+\.\d+\.\d+\.\d+)", out):
        try:
            parsed = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if parsed.is_private and not parsed.is_loopback:
            found.append(raw)
    return tuple(found)


@functools.lru_cache(maxsize=512)
def _in_raw(raw_root: Path, source: str, value: str) -> tuple[bool, str]:
    """Whether ``value`` appears in ``source``'s untouched download.

    Memoised on (root, source, value): the cache on disk does not change during
    a run and the same question recurs once per occurrence.
    """
    cache = raw_root / source
    if not cache.is_dir():
        return False, f"no raw cache for {source!r}, so provenance is unknown"
    needle = value.encode()
    for path in sorted(cache.rglob("*")):
        if not path.is_file():
            continue
        try:
            if needle in path.read_bytes():
                return True, (
                    f"present in the raw {source} download ({path.name})"
                    f" — upstream content"
                )
        except OSError:
            continue
    return False, f"not present in the raw {source} download"


def _source_of(leak_path: str) -> str:
    """The source name a finding's file belongs to."""
    name = Path(leak_path).name
    for suffix in (".jsonl", ".md", ".txt"):
        name = name.removesuffix(suffix)
    return name


def exonerate(leak: Any, *, raw_root: Path | None = None) -> tuple[bool, str]:
    """Is this finding provably upstream content? Returns ``(exonerated, why)``.

    ``leak`` is a :class:`~training.corpus.verify.Leak`; it is typed loosely so
    this module does not import the verifier and create a cycle.
    """
    root = default_raw() if raw_root is None else raw_root
    kind = getattr(leak, "kind", "")
    if kind not in AMBIGUOUS_KINDS:
        return False, f"{kind} is never exonerable by provenance"

    want = getattr(leak, "fingerprint", "")
    value = next((a for a in _bound_private() if fingerprint(a) == want), None)
    if value is None:
        return False, "no bound address matches this fingerprint"

    return _in_raw(root, _source_of(getattr(leak, "path", "")), value)


def partition(
    leaks: Iterable[Any], *, raw_root: Path | None = None
) -> tuple[list[tuple[Any, str]], list[tuple[Any, str]]]:
    """Split findings into ``(real, exonerated)``, each paired with its reason.

    The caller decides what to do; this only answers the question. Both lists
    are meant to be **printed** — "the gate passed" and "the gate found nothing"
    are different sentences, and whoever reads the log is entitled to know which
    one happened.
    """
    real: list[tuple[Any, str]] = []
    excused: list[tuple[Any, str]] = []
    for leak in leaks:
        ok, why = exonerate(leak, raw_root=raw_root)
        (excused if ok else real).append((leak, why))
    return real, excused
