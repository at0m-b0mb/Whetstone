#!/usr/bin/env python3
"""Read the training data — the actual documents, not a summary of them.

    python3 scripts/show_data.py                    # one sample per source
    python3 scripts/show_data.py --source nuclei    # several from one source
    python3 scripts/show_data.py --register shell   # everything in a register
    python3 scripts/show_data.py --chars 2000       # longer excerpts

Samples are drawn at RANDOM POSITIONS, never from the head of a file. That is
not a stylistic choice: nvd.jsonl is ordered oldest-first, and a head sample of
it returns CVEs published in 1999 that use CVSS v2 and predate CWE assignment.
Reading the first three documents of that file and concluding anything about the
corpus is how this project nearly mis-diagnosed a real bug — so the sampler
refuses to make that easy.
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

D = Path("/Volumes/at0m_b0mb/whetstone")
C = {"dim": "\033[2m", "b": "\033[1m", "c": "\033[36m", "y": "\033[33m",
     "g": "\033[32m", "m": "\033[35m", "x": "\033[0m"}


def offsets(path: Path) -> list[int]:
    """Byte offset of every line, so we can seek to a random document."""
    out, pos = [], 0
    with path.open("rb") as fh:
        for line in fh:
            out.append(pos)
            pos += len(line)
    return out


def sample(path: Path, n: int, rng: random.Random) -> list[dict]:
    offs = offsets(path)
    if not offs:
        return []
    picked = rng.sample(offs, min(n, len(offs)))
    rows = []
    with path.open("rb") as fh:
        for off in picked:
            fh.seek(off)
            try:
                rows.append(json.loads(fh.readline()))
            except json.JSONDecodeError:
                continue
    return rows


def show(row: dict, chars: int) -> None:
    text = row.get("text", "")
    reg, side = row.get("register", "?"), row.get("side", "?")
    tint = {"red": "\033[31m", "blue": C["c"]}.get(side, C["dim"])
    print(f"  {C['dim']}register{C['x']} {reg}   {C['dim']}side{C['x']} "
          f"{tint}{side}{C['x']}   {C['dim']}{len(text):,} chars{C['x']}")
    body = text[:chars]
    for line in body.splitlines():
        print(f"  {C['dim']}│{C['x']} {line[:110]}")
    if len(text) > chars:
        print(f"  {C['dim']}│ … {len(text) - chars:,} more chars{C['x']}")
    print()


def main() -> int:
    p = argparse.ArgumentParser(description="Read the training corpus.")
    p.add_argument("--corpus", type=Path, default=D / "corpus/clean-v5")
    p.add_argument("--source", help="one source, several samples")
    p.add_argument("--register", help="only this register")
    p.add_argument("--n", type=int, default=1, help="samples per source")
    p.add_argument("--chars", type=int, default=900)
    p.add_argument("--seed", type=int, default=0)
    args = p.parse_args()

    rng = random.Random(args.seed)
    files = sorted(args.corpus.glob("*.jsonl"))
    if args.source:
        files = [f for f in files if f.stem == args.source]
        if not files:
            print(f"no source {args.source!r}. available:")
            print("  " + " ".join(sorted(f.stem for f in args.corpus.glob("*.jsonl"))))
            return 1
        args.n = max(args.n, 3)

    for f in files:
        rows = sample(f, args.n * 3, rng)
        if args.register:
            rows = [r for r in rows if r.get("register") == args.register]
        rows = rows[:args.n]
        if not rows:
            continue
        print(f"\n{C['b']}{C['c']}── {f.stem} {'─' * max(0, 60 - len(f.stem))}{C['x']}")
        for r in rows:
            show(r, args.chars)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
