#!/usr/bin/env python3
"""The corpus gate: run the verifier, then decide what its findings mean.

    python3 scripts/gate_corpus.py <corpus-dir>
    exit 0  clean, or every finding exonerated by proven upstream provenance
    exit 1  a real leak — do not tokenize
    exit 2  the instrument could not produce a usable verdict

**Why this is a separate program from the verifier.**
``training.corpus.verify.verify_corpus`` is documented to *return* leaks and
never to raise, precisely so one scanner can serve a build gate, a CLI and a
test instead of three that disagree. Policy belongs to the caller. This is the
caller, and this file is where the policy is written down.

**The policy has exactly one rule.**
One kind of finding is *ambiguous by construction*, and the verifier says so in
its own output: an RFC1918 address bound on this machine is **the same bytes** as
an RFC1918 address used as an example in RFC text, an Nmap script, a nuclei
template or a Sigma rule. They cannot be told apart by looking at the value,
because there is nothing to tell apart — they are identical strings.

So this gate tells them apart by **provenance**. If the exact value appears in
the *raw upstream download* of the source that carried it, that source shipped
it, and the cache was fetched from the upstream and has never been near this
machine's network configuration. That is proof of origin, not an excuse.

Measured instance, 2026-10-15: ``clean-v9`` verified with **4 occurrences of 1
distinct value**, kind ``ipv4-private``, in ``nselua.jsonl`` ::
``scripts/mrinfo.nse``. The same address sits in Nmap's own ``mrinfo.nse`` and
``mtrace.nse`` inside ``corpus/raw/nselua``. Nmap's source cannot contain this
operator's address. For contrast the previous generation carried **23,535
occurrences of 11 distinct values** — two live global IPv6 addresses, three
hardware MACs, the volume name, the operator's own name and address, and three
non-consenting third parties' names and addresses. **None of those could ever be
exonerated this way**, which is the whole point of restricting the rule.

**What is deliberately NOT exonerable.**
``identity``, ``email``, ``mac``, ``ipv6-global``, ``volume`` and ``ident-path``
are never exonerated whatever the cache says. A global IPv6 address or a hardware
MAC turning up in an upstream would mean the upstream had somehow acquired this
machine's identifiers — a far more alarming finding than a leak, and one that
must not be silenced by a provenance check. A rule that can exonerate those is a
bypass wearing a justification.

**No value is ever written anywhere.** ``Needles`` is deliberately unserialisable
and exposes no way to read a value back, which is correct: the audit that found
these leaks created a new exposure by writing its own needle table to a JSON
file. So this gate re-derives candidates from the OS in memory, matches them by
fingerprint, uses them, and lets them fall out of scope. It prints fingerprints.

The gate is loud either way. An exonerated finding is still printed with the file
it came from and the upstream that carried it, because "the gate passed" and "the
gate found nothing" are different sentences and whoever reads the log is entitled
to know which one happened.
"""

from __future__ import annotations

import functools
import hashlib
import ipaddress
import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from training.corpus import verify as V  # noqa: E402
from whetstone.paths import data_root  # noqa: E402

#: Kinds whose value cannot be distinguished from legitimate upstream content by
#: inspection, and which are therefore eligible for provenance exoneration.
AMBIGUOUS_KINDS = frozenset({"ipv4-private"})

#: Where each source's untouched download lives. Whether a cache exists is
#: checked rather than assumed: "not in the cache" and "there is no cache" are
#: different facts and only the first is evidence of anything.
RAW = data_root() / "corpus" / "raw"


def fingerprint(value: str) -> str:
    """The same shape ``Leak.fingerprint`` carries: length plus a sha256 prefix.

    Confirmed against a real finding rather than read off the type: the leak in
    ``nselua.jsonl`` reported ``len=10,sha256=3fd8e0d2`` and the sha256 of the
    matching bound address starts with exactly those eight hex digits.
    """
    digest = hashlib.sha256(value.encode()).hexdigest()[:8]
    return f"len={len(value)},sha256={digest}"


@functools.lru_cache(maxsize=1)
def bound_private_addresses() -> tuple[str, ...]:
    """RFC1918 IPv4 addresses currently bound on an interface of this machine.

    Re-derived here rather than extracted from ``Needles``, which has no method
    to read a value back — and should not have one.

    **Cached, because the gate is called once per occurrence and not once per
    value.** Without this, running the gate on the old leaking generation spawned
    ``ifconfig`` for every finding; a dirty corpus is exactly when the gate must
    stay responsive, because that is when somebody is waiting on its answer.
    """
    try:
        out = subprocess.run(["ifconfig"], capture_output=True, text=True,
                             timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    found = []
    for raw in re.findall(r"inet (\d+\.\d+\.\d+\.\d+)", out):
        try:
            parsed = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if parsed.is_private and not parsed.is_loopback:
            found.append(raw)
    return tuple(found)


def exonerate(leak: V.Leak) -> tuple[bool, str]:
    """Is this finding provably upstream content? Returns ``(exonerated, why)``."""
    if leak.kind not in AMBIGUOUS_KINDS:
        return False, f"{leak.kind} is never exonerable by provenance"

    value = next((a for a in bound_private_addresses()
                  if fingerprint(a) == leak.fingerprint), None)
    if value is None:
        return False, "no bound address matches this fingerprint"

    source = pathlib.Path(leak.path).name
    for suffix in (".jsonl", ".md", ".txt"):
        source = source.removesuffix(suffix)
    cache = RAW / source
    if not cache.is_dir():
        return False, f"no raw cache for {source!r}, so provenance is unknown"

    return _in_raw_cache(source, value)


@functools.lru_cache(maxsize=256)
def _in_raw_cache(source: str, value: str) -> tuple[bool, str]:
    """Whether ``value`` appears in ``source``'s untouched download.

    Memoised on (source, value). The cache on disk does not change during a run,
    and the gate is called once per *occurrence* — 23,535 times on the old
    generation — so without this it re-read an upstream tree per finding.
    """
    cache = RAW / source
    needle = value.encode()
    for path in sorted(cache.rglob("*")):
        if not path.is_file():
            continue
        try:
            if needle in path.read_bytes():
                return True, (f"present in the raw {source} download "
                              f"({path.name}) — upstream content")
        except OSError:
            continue
    return False, f"not present in the raw {source} download"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: gate_corpus.py <corpus-dir>")
        return 2
    directory = pathlib.Path(argv[1])

    needles = V.host_needles()
    gaps = needles.gaps()
    if gaps:
        print(f"GATE: the needle table is incomplete {tuple(gaps)}.")
        print("  An incomplete table means part of what should be looked for was")
        print("  not looked for, which is not a clean verdict. Refusing to pass.")
        return 2

    leaks = V.verify_corpus(directory, needles=needles)
    read = getattr(V.verify_corpus, "last_bytes_read", 0)
    if read <= 0:
        print("GATE: the pass read 0 bytes.")
        print("  That is the instrument failing, not a clean corpus — exactly the")
        print("  '0 leaks, exit 0 having read nothing' bug this gate outlives.")
        return 2

    mb = read / 1e6
    if not leaks:
        print(f"GATE: CLEAN — {mb:,.1f} MB read, 0 findings.")
        return 0

    real: list[tuple[V.Leak, str]] = []
    excused: list[tuple[V.Leak, str]] = []
    for leak in leaks:
        ok, why = exonerate(leak)
        (excused if ok else real).append((leak, why))

    for leak, why in excused:
        print(f"GATE: exonerated  {leak.kind:<13} {leak.path:<22} "
              f"{leak.fingerprint}  — {why}")
    for leak, why in real:
        print(f"GATE: LEAK        {leak.kind:<13} {leak.path:<22} "
              f"{leak.fingerprint}  — {why}")

    print()
    if real:
        files = len({leak.path for leak, _ in real})
        print(f"GATE: FAILED — {len(real)} real finding(s) in {files} file(s), "
              f"{mb:,.1f} MB read. Not tokenizing.")
        print("  A corpus becomes weights, and weights are neither greppable nor")
        print("  removable. Fix the chokepoint and rebuild.")
        return 1

    print(f"GATE: PASSED — {mb:,.1f} MB read, {len(excused)} finding(s) "
          f"exonerated by proven upstream provenance.")
    print("  That is not the same sentence as 'found nothing'; each one is above.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
