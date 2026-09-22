#!/usr/bin/env python3
"""Audit corpus quality — the checks that catch data a loss curve will not.

    python3 scripts/audit_corpus.py
    python3 scripts/audit_corpus.py --corpus <dir> --sample 4000

Every check here exists because something in this class actually happened to
this project, and none of them would have shown up as a training failure. A
model trained on damaged text converges perfectly well; it just converges on
the damage.

Samples at RANDOM offsets, never from the head. nvd.jsonl is ordered
oldest-first and a head sample of it describes 1999, which is how a real bug was
nearly mis-diagnosed here as the adapter dropping data.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import sys
from collections import Counter
from pathlib import Path

D = Path("/Volumes/at0m_b0mb/whetstone")
C = {"dim": "\033[2m", "b": "\033[1m", "g": "\033[32m", "y": "\033[33m",
     "r": "\033[31m", "c": "\033[36m", "x": "\033[0m"}

#: Text that is almost all one alphabet of characters is a blob wearing a
#: document's clothes — a base64 payload, a hex dump, a decimal-encoded DLL. One
#: adapter here found a page that was 79.9% five lines of a DLL written as
#: decimal integers, which is ~40 training windows of pure digits.
BLOBBY = re.compile(r"[0-9a-fA-F+/=,\s]{2000,}")
MOJIBAKE = re.compile(r"â€|Ã¢|�|Ã©|Â ")
#: A run this long is the artefact normalise() is documented to bound.
WIDE_RUN = re.compile(r" {200,}")


def offsets(path: Path) -> list[int]:
    out, pos = [], 0
    with path.open("rb") as fh:
        for line in fh:
            out.append(pos)
            pos += len(line)
    return out


def audit(path: Path, n: int, rng: random.Random, leaks) -> dict:
    offs = offsets(path)
    picked = rng.sample(offs, min(n, len(offs)))
    stat = Counter()
    lens: list[int] = []
    seen: set[bytes] = set()
    registers, sides = Counter(), Counter()
    examples: dict[str, str] = {}

    with path.open("rb") as fh:
        for off in picked:
            fh.seek(off)
            raw = fh.readline()
            try:
                row = json.loads(raw)
            except json.JSONDecodeError:
                stat["unparseable"] += 1
                continue
            text = row.get("text", "")
            stat["docs"] += 1
            lens.append(len(text))
            registers[row.get("register", "?")] += 1
            sides[row.get("side", "?")] += 1

            if not text.strip():
                stat["empty"] += 1
            if len(text) < 200:
                stat["tiny"] += 1
            fp = hashlib.blake2b(text.encode(), digest_size=16).digest()
            if fp in seen:
                stat["duplicate"] += 1
            seen.add(fp)
            if MOJIBAKE.search(text):
                stat["mojibake"] += 1
                examples.setdefault("mojibake", text[:160])
            if WIDE_RUN.search(text):
                stat["wide_space_run"] += 1
            if BLOBBY.search(text):
                stat["blob"] += 1
                examples.setdefault("blob", text[:160])
            if text.rstrip().endswith(("...", "…")) and len(text) > 1000:
                stat["maybe_truncated"] += 1
            found = leaks(text)
            if found:
                stat["identity_leak"] += 1
                examples.setdefault("identity_leak", ", ".join(found[:3]))

    return {"stat": stat, "lens": lens, "registers": registers,
            "sides": sides, "examples": examples, "total": len(offs)}


def main() -> int:
    p = argparse.ArgumentParser(description="Audit corpus quality.")
    p.add_argument("--corpus", type=Path, default=D / "corpus/clean-v5")
    p.add_argument("--sample", type=int, default=2500, help="docs per source")
    p.add_argument("--seed", type=int, default=0)
    args = p.parse_args()

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    try:
        from training.trajectories import identity_leaks as leaks
    except Exception:
        def leaks(_t):  # noqa: ANN001
            return []

    rng = random.Random(args.seed)
    files = sorted(args.corpus.glob("*.jsonl"))
    if not files:
        print(f"no *.jsonl under {args.corpus}")
        return 1

    print(f"\n{C['b']}{C['c']}corpus audit — {args.corpus}{C['x']}")
    print(f"{C['dim']}{len(files)} sources, up to {args.sample:,} random "
          f"documents each{C['x']}\n")

    hdr = (f"{'source':<18}{'docs':>9}{'median':>8}{'empty':>7}{'dup':>6}"
           f"{'moji':>6}{'blob':>6}{'IDENTITY':>10}")
    print(C["b"] + hdr + C["x"])
    print(C["dim"] + "-" * len(hdr) + C["x"])

    totals = Counter()
    problems: list[str] = []
    for f in files:
        r = audit(f, args.sample, rng, leaks)
        s, lens = r["stat"], sorted(r["lens"])
        med = lens[len(lens) // 2] if lens else 0
        idn = s["identity_leak"]
        tint = C["r"] if idn else C["dim"]
        print(f"  {f.stem:<16}{r['total']:>9,}{med:>8,}{s['empty']:>7}"
              f"{s['duplicate']:>6}{s['mojibake']:>6}{s['blob']:>6}"
              f"{tint}{idn:>10}{C['x']}")
        for k in ("empty", "duplicate", "mojibake", "blob", "identity_leak",
                  "unparseable", "wide_space_run", "maybe_truncated", "tiny"):
            totals[k] += s[k]
        totals["docs"] += s["docs"]
        if idn:
            problems.append(f"{f.stem}: {idn} identity leaks — "
                            f"{r['examples'].get('identity_leak', '')}")
        if s["mojibake"]:
            problems.append(f"{f.stem}: {s['mojibake']} mojibake")
        if s["blob"] > s["docs"] * 0.05 and s["docs"]:
            problems.append(f"{f.stem}: {s['blob']}/{s['docs']} look like blobs")

    print()
    print(f"{C['b']}sampled {totals['docs']:,} documents{C['x']}")
    for k, label in (("identity_leak", "IDENTITY LEAKS"),
                     ("empty", "empty documents"),
                     ("duplicate", "exact duplicates"),
                     ("mojibake", "encoding damage"),
                     ("blob", "blob-like documents"),
                     ("wide_space_run", "200+ space runs"),
                     ("unparseable", "unparseable rows"),
                     ("maybe_truncated", "possibly truncated")):
        v = totals[k]
        tint = C["r"] if (v and k == "identity_leak") else (C["y"] if v else C["g"])
        print(f"  {tint}{v:>7,}{C['x']}  {label}")

    if problems:
        print(f"\n{C['b']}{C['r']}problems{C['x']}")
        for line in problems[:20]:
            print(f"  {line}")
    return 1 if totals["identity_leak"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
