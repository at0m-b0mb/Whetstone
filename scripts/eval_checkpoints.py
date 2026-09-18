#!/usr/bin/env python3
"""Re-score saved checkpoints against the FIXED validation set, after the fact.

    PYTHONPATH=. python3 scripts/eval_checkpoints.py \
        --data /Volumes/at0m_b0mb/whetstone/corpus/tokenized-v5 \
        /Volumes/at0m_b0mb/whetstone/models/checkpoints-v5/small \
        /Volumes/at0m_b0mb/whetstone/models/checkpoints-v5/small/best

**Why this exists.** Until ``training.pretrain`` was fixed, every evaluation
drew a *fresh random subsample* of the validation split — 80 windows out of
486, with replacement, redrawn each time. ``out/best`` was therefore selected
by comparing numbers measured on different data, which picks the checkpoint
that drew the easiest windows rather than the best model, and reports a best
loss biased optimistically low. The ``val_loss`` recorded inside each
checkpoint's state.json carries that jitter and so does ``val_history``.

A run already in flight cannot pick the fix up: the process loaded its code at
launch and will keep drawing fresh samples until it exits. This scores whatever
checkpoints are on disk against one identical window set, so that run can still
have its true best identified once it finishes. It only ever reads; deciding
what to do with the answer is left to a person.

The comparison is only valid between checkpoints of the same context length
against the same corpus, because the window set is derived from the split's
bounds and the sequence length — so both are checked rather than assumed.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
from pathlib import Path

from training.config import ModelConfig, TrainConfig
from training.data import Dataset
from training.model import Whetstone
from training.pretrain import evaluate, load_weights_only, val_window_starts


def score(ckpt: Path, data_root: Path, *, val_fraction: float,
          windows: int, batch_size: int) -> dict:
    """Load one checkpoint and return its fixed-val-set loss and metadata."""
    state = json.loads((ckpt / "state.json").read_text(encoding="utf-8"))
    cfg = ModelConfig(**state["model"])
    model = Whetstone(cfg)
    # Weights only: validation loss is a function of them alone, so refusing a
    # checkpoint whose optimizer file is torn or absent would be refusing to
    # answer a question that does not involve it.
    load_weights_only(ckpt, model)
    data = Dataset(data_root, cfg.max_seq_len, split="val",
                   val_fraction=val_fraction)
    return {
        "path": ckpt,
        "step": state.get("step"),
        "recorded": state.get("val_loss"),
        "seq_len": cfg.max_seq_len,
        "n_windows": len(val_window_starts(data, windows)),
        "loss": evaluate(model, data, batch_size, limit=windows),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Re-score checkpoints on the fixed validation set.")
    p.add_argument("checkpoints", type=Path, nargs="+",
                   help="checkpoint directories (each holding state.json and "
                        "weights.safetensors)")
    p.add_argument("--data", type=Path, required=True,
                   help="the tokenized shard directory the run trained on")
    p.add_argument("--val-fraction", type=float, default=0.005,
                   help="must match the run's; the split boundary is derived "
                        "from it, so a different value scores different tokens")
    p.add_argument("--windows", type=int, default=TrainConfig().val_windows,
                   help="cap on validation windows; the default is the one the "
                        "trainer uses, and is exhaustive for the v5 split")
    p.add_argument("--batch-size", type=int, default=4,
                   help="windows per forward pass — memory only, it cannot "
                        "change the answer")
    args = p.parse_args(argv)

    for ckpt in args.checkpoints:
        if not (ckpt / "state.json").is_file():
            raise SystemExit(f"{ckpt} holds no state.json — not a checkpoint")

    results = [score(c, args.data, val_fraction=args.val_fraction,
                     windows=args.windows, batch_size=args.batch_size)
               for c in args.checkpoints]

    lengths = {r["seq_len"] for r in results}
    if len(lengths) > 1:
        raise SystemExit(
            f"these checkpoints have different context lengths ({sorted(lengths)}), "
            "so they cannot be scored on one window set: the windows are "
            "seq_len + 1 tokens wide. Score them in separate runs and do not "
            "compare the numbers."
        )

    n = results[0]["n_windows"]
    print(f"\nfixed val set: {n:,} windows x {results[0]['seq_len']:,} tokens "
          f"from {args.data}")
    # Checkpoint paths are long and differ only in their tail, so the shared
    # prefix is printed once and the rows carry what actually distinguishes
    # them. A table whose first column wraps is a table nobody reads.
    root = Path(os.path.commonpath([str(r["path"]) for r in results]))
    if root.name:
        print(f"under: {root}")
    labels = {id(r): (str(r["path"].relative_to(root)) if r["path"] != root
                      else r["path"].name) for r in results}
    width = max(len("checkpoint"), max(len(v) for v in labels.values())) + 2
    print(f"{'checkpoint':<{width}}{'step':>9}{'recorded':>11}{'fixed val':>11}"
          f"{'ppl':>8}{'drift':>9}")
    best = min(results, key=lambda r: r["loss"])
    for r in sorted(results, key=lambda r: r["loss"]):
        rec = r["recorded"]
        # The gap between the number the run recorded and the number the fixed
        # set produces IS the sampling noise the old evaluate() was selecting
        # on. It is the reason this script exists, so it is printed rather than
        # left for someone to subtract in their head.
        drift = f"{r['loss'] - rec:+.4f}" if rec is not None else "—"
        print(f"{labels[id(r)]:<{width}}{r['step']:>9,}"
              f"{(f'{rec:.4f}' if rec is not None else '—'):>11}"
              f"{r['loss']:>11.4f}{math.exp(min(r['loss'], 20)):>8.1f}"
              f"{drift:>9}"
              f"{'  <- best' if r is best else ''}")

    print(f"\nlowest loss on identical data: {best['path']}")
    if len(results) > 1:
        print("that is the checkpoint to use. The `recorded` column is what "
              "each\ncheckpoint believed about itself, measured on a different "
              "sample each\ntime, and is not comparable across rows.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
