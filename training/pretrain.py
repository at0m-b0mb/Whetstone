"""Pretraining: the loop that turns a corpus into a checkpoint.

    python -m training.pretrain --model tiny --data data/corpus/tokenized
    python -m training.pretrain --model base --resume

Run ``tiny`` first. It finishes in about five hours — or in two minutes with
``--max-steps 200`` — and every bug worth finding shows itself there: a loader
that favours one shard, a schedule that never warms up, a checkpoint that does
not round-trip. Finding those at ``base`` costs a week.

**On resume.** A run that cannot resume is a run that loses a week to a
reboot. Resuming restores model weights, optimizer state *and* the step
counter, because the learning-rate schedule is a function of the step: restore
the weights alone and the run silently continues at the peak learning rate it
should long since have decayed past. ``--verify-resume`` proves the round trip
by saving, reloading and asserting the next loss matches — worth running once
after any change to the checkpoint format.

**On the loss spike you will eventually see.** A from-scratch run meets a bad
batch sooner or later — a shard of base64, a minified blob, a binary that
survived the corpus cleaner. Gradient clipping at 1.0 keeps that from ending
the run. If loss spikes and does *not* recover within a few hundred steps, the
problem is the data, not the optimiser, and the fix is upstream in
``training/corpus/``.
"""

from __future__ import annotations

import argparse
import json
import math
import time
from dataclasses import asdict
from pathlib import Path

import mlx.core as mx
import mlx.nn as nn
import mlx.optimizers as optim
import numpy as np

from .config import STAIRCASE, ModelConfig, TrainConfig, get_config
from .data import Dataset
from .model import Whetstone

__all__ = ["train", "cosine_lr", "save_checkpoint", "load_checkpoint"]


def cosine_lr(step: int, total: int, cfg: TrainConfig) -> float:
    """Linear warmup, then cosine decay to ``min_lr_ratio`` of peak.

    Warmup is a *fraction* of the run rather than a fixed step count so the
    staircase scales: 2% of 4,451 steps at ``tiny`` and 2% of 46,090 at
    ``base`` are both the right shape, where a hardcoded 2,000 would be half
    the tiny run and a rounding error in the base one.
    """
    warmup = max(1, int(total * cfg.warmup_ratio))
    if step < warmup:
        return cfg.learning_rate * (step + 1) / warmup
    progress = (step - warmup) / max(1, total - warmup)
    progress = min(1.0, max(0.0, progress))
    cosine = 0.5 * (1 + math.cos(math.pi * progress))
    return cfg.learning_rate * (cfg.min_lr_ratio + (1 - cfg.min_lr_ratio) * cosine)


def save_checkpoint(
    out: Path, model: Whetstone, opt: optim.Optimizer, step: int,
    model_cfg: ModelConfig, train_cfg: TrainConfig,
    *, val_loss: float | None = None, history: list[dict] | None = None,
) -> None:
    """Weights, optimizer state and step — all three, atomically.

    Written to a temporary name and renamed, so a crash mid-write leaves the
    previous checkpoint intact rather than a truncated file that fails to load
    at exactly the moment you need it.
    """
    out.mkdir(parents=True, exist_ok=True)
    from mlx.utils import tree_flatten

    tmp = out / ".weights.tmp.safetensors"
    mx.save_safetensors(str(tmp), dict(tree_flatten(model.parameters())))
    tmp.replace(out / "weights.safetensors")

    tmp = out / ".opt.tmp.safetensors"
    mx.save_safetensors(str(tmp), dict(tree_flatten(opt.state)))
    tmp.replace(out / "optimizer.safetensors")

    state: dict = {
        "step": step,
        "model": asdict(model_cfg),
        "train": asdict(train_cfg),
    }
    if val_loss is not None:
        state["val_loss"] = val_loss
        state["val_ppl"] = round(math.exp(min(val_loss, 20)), 2)
    if history is not None:
        # The whole curve, so the run can be judged after the fact without
        # having to still have the log.
        state["val_history"] = history
    (out / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")


def load_checkpoint(out: Path, model: Whetstone, opt: optim.Optimizer) -> int:
    """Restore weights, optimizer state and step. Returns the step."""
    from mlx.utils import tree_unflatten

    state = json.loads((out / "state.json").read_text(encoding="utf-8"))
    model.update(tree_unflatten(list(mx.load(str(out / "weights.safetensors")).items())))
    opt_path = out / "optimizer.safetensors"
    if opt_path.is_file():
        opt.state = tree_unflatten(list(mx.load(str(opt_path)).items()))
    mx.eval(model.parameters(), opt.state)
    return int(state["step"])


def evaluate(model: Whetstone, data: Dataset, batch_size: int, batches: int = 20) -> float:
    """Mean validation loss. No gradient, no optimizer, no dropout to disable."""
    total = 0.0
    for x, y in data.iter_batches(batch_size, batches):
        loss = model.loss(mx.array(x), mx.array(y))
        mx.eval(loss)
        total += loss.item()
    return total / batches


def train(
    model_name: str,
    data_root: Path,
    out_root: Path,
    *,
    max_steps: int | None = None,
    resume: bool = False,
    train_cfg: TrainConfig | None = None,
) -> Path:
    cfg = get_config(model_name)
    tcfg = train_cfg or TrainConfig()
    out = out_root / model_name
    mx.random.seed(tcfg.seed)

    train_data = Dataset(data_root, cfg.max_seq_len, split="train", seed=tcfg.seed)
    val_data = Dataset(data_root, cfg.max_seq_len, split="val", seed=tcfg.seed + 1)

    if train_data.index.vocab_size != cfg.vocab_size:
        raise SystemExit(
            f"tokenizer vocabulary is {train_data.index.vocab_size} but the "
            f"model expects {cfg.vocab_size}. Training on this mismatch would "
            "produce a model whose output ids mean nothing."
        )

    model = Whetstone(cfg)
    opt = optim.AdamW(
        learning_rate=tcfg.learning_rate,
        betas=[tcfg.beta1, tcfg.beta2],
        weight_decay=tcfg.weight_decay,
    )

    total_steps = min(tcfg.total_steps(cfg), max_steps or 10**9)
    accum = tcfg.grad_accum_steps(cfg)
    micro = tcfg.micro_batch

    start = 0
    best_val = float("inf")
    history: list[dict] = []
    if resume and (out / "state.json").is_file():
        prior = json.loads((out / "state.json").read_text(encoding="utf-8"))
        history = list(prior.get("val_history", []))
        # Carry the best across the interruption, or a resumed run would call
        # its first eval "best" and overwrite a genuinely better checkpoint.
        if (best := out / "best" / "state.json").is_file():
            best_val = json.loads(best.read_text(encoding="utf-8")).get(
                "val_loss", float("inf"))
        start = load_checkpoint(out, model, opt)
        # Restore the data position too. Weights and optimizer alone are not a
        # resumable run: without this the sampler restarts and re-serves the
        # batches the first `start` steps already consumed.
        train_data.seek(start * accum)
        print(f"resumed from step {start:,} "
              f"(data position {start * accum:,} batches)")

    print(f"\n{cfg.summary()}")
    print(f"  {train_data}\n  {val_data}")
    print(f"  {total_steps:,} steps × {micro}×{cfg.max_seq_len} × {accum} accum "
          f"= {tcfg.batch_tokens:,} tokens/step")
    print(f"  ~{cfg.measured_days(total_steps * tcfg.batch_tokens):.1f} days at the "
          f"measured {cfg.measured_tokens_per_sec:,.0f} tok/s\n")

    def loss_fn(m: Whetstone, x: mx.array, y: mx.array) -> mx.array:
        return m.loss(x, y)

    grad_fn = nn.value_and_grad(model, loss_fn)
    t0 = time.perf_counter()
    seen = 0

    for step in range(start, total_steps):
        opt.learning_rate = cosine_lr(step, total_steps, tcfg)

        # Gradient accumulation: several micro-batches summed into one update,
        # so the effective batch is large enough to be stable without needing
        # memory for all of it at once.
        total_loss = 0.0
        grads = None
        for _ in range(accum):
            x, y = train_data.batch(micro)
            loss, g = grad_fn(model, mx.array(x), mx.array(y))
            grads = g if grads is None else _tree_add(grads, g)
            # Materialise each micro-batch before building the next one. MLX is
            # lazy: without this, the graphs for all `accum` micro-batches are
            # held simultaneously and peak memory scales with accumulation
            # depth rather than with micro-batch size. `small` at 4x1024 with
            # 16 accumulation steps drove this machine to 13 GB of swap and
            # never reached step 1, while `tiny` survived the same bug only
            # because eight shallow graphs happened to fit. Gradient
            # accumulation exists precisely to keep peak memory flat, and
            # without this line it does the opposite of its job.
            mx.eval(grads)
            total_loss += loss.item()
            seen += micro * cfg.max_seq_len

        grads = _tree_scale(grads, 1.0 / accum)
        grads, gnorm = optim.clip_grad_norm(grads, tcfg.grad_clip)
        opt.update(model, grads)
        mx.eval(model.parameters(), opt.state)

        if step % tcfg.log_every == 0:
            dt = time.perf_counter() - t0
            tps = seen / dt if dt else 0
            print(f"step {step:>7,}/{total_steps:,}  loss {total_loss/accum:6.3f}  "
                  f"lr {opt.learning_rate.item():.2e}  |g| {float(gnorm):5.2f}  "
                  f"{tps:>8,.0f} tok/s", flush=True)

        if step and step % tcfg.eval_every == 0:
            vl = evaluate(model, val_data, micro)
            history.append({"step": step, "val_loss": vl})
            flag = ""
            if vl < best_val:
                # Keep the best model, not merely the most recent one. Val loss
                # on a small corpus is noisy and eventually rises: `tiny`
                # reached ppl 11.0 and was saved at 13.9, because the run kept
                # whatever happened to be in memory when the step counter ran
                # out. An overnight run that discards its best checkpoint has
                # wasted the night.
                best_val = vl
                save_checkpoint(out / "best", model, opt, step, cfg, tcfg,
                                val_loss=vl, history=history)
                flag = "  ← best"
            print(f"  ── val loss {vl:.4f}  (ppl {math.exp(min(vl, 20)):.1f})"
                  f"{flag}", flush=True)

        if step and step % tcfg.checkpoint_every == 0:
            save_checkpoint(out, model, opt, step, cfg, tcfg, history=history)

    final = evaluate(model, val_data, micro)
    history.append({"step": total_steps, "val_loss": final})
    if final < best_val:
        best_val = final
        save_checkpoint(out / "best", model, opt, total_steps, cfg, tcfg,
                        val_loss=final, history=history)
    save_checkpoint(out, model, opt, total_steps, cfg, tcfg,
                    val_loss=final, history=history)

    print(f"\ndone. final val loss {final:.4f} "
          f"(ppl {math.exp(min(final, 20)):.1f}) → {out}")
    if best_val < final:
        print(f"      best val loss {best_val:.4f} "
              f"(ppl {math.exp(min(best_val, 20)):.1f}) → {out / 'best'}"
              f"\n      the final model is worse than the best one. Use "
              f"{out.name}/best unless you have a reason not to.")
    return out


def _tree_add(a, b):
    from mlx.utils import tree_map
    return tree_map(lambda x, y: x + y, a, b)


def _tree_scale(t, s: float):
    from mlx.utils import tree_map
    return tree_map(lambda x: x * s, t)


def verify_resume(model_name: str, data_root: Path, out_root: Path) -> bool:
    """Prove a checkpoint round-trips: same weights, same optimizer, same step.

    Cheap, and the alternative to running it is discovering on day six that the
    thing you have been checkpointing all week cannot be loaded.
    """
    cfg = get_config(model_name)
    tcfg = TrainConfig()
    tmp = out_root / f".verify-{model_name}"
    data = Dataset(data_root, cfg.max_seq_len, split="val", seed=7)

    model = Whetstone(cfg)
    opt = optim.AdamW(learning_rate=1e-4)
    x, y = data.batch(2)
    loss, g = nn.value_and_grad(model, lambda m: m.loss(mx.array(x), mx.array(y)))(model)
    opt.update(model, g)
    mx.eval(model.parameters(), opt.state)
    before = model.loss(mx.array(x), mx.array(y)).item()
    save_checkpoint(tmp, model, opt, 42, cfg, tcfg)

    restored = Whetstone(cfg)
    ropt = optim.AdamW(learning_rate=1e-4)
    step = load_checkpoint(tmp, restored, ropt)
    after = restored.loss(mx.array(x), mx.array(y)).item()

    ok = step == 42 and abs(before - after) < 1e-4
    print(f"resume round-trip: step {step} (want 42), "
          f"loss {before:.6f} → {after:.6f}  {'OK' if ok else 'MISMATCH'}")
    return ok


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Pretrain a Whetstone model.")
    p.add_argument("--model", default="tiny", choices=list(STAIRCASE))
    p.add_argument("--data", type=Path, default=Path("data/corpus/tokenized"))
    p.add_argument("--out", type=Path, default=Path("data/models/checkpoints"))
    p.add_argument("--max-steps", type=int, default=None)
    p.add_argument("--micro-batch", type=int, default=None,
                   help="sequences per forward pass. Lower it if the run swaps: "
                        "gradient accumulation is raised to keep the effective "
                        "batch identical, so this trades speed for memory and "
                        "nothing else. small at 8 x 1024 swapped this machine to "
                        "24.9 GB and never reached step 1.")
    p.add_argument("--resume", action="store_true")
    p.add_argument("--verify-resume", action="store_true",
                   help="prove checkpoints round-trip, then exit")
    p.add_argument("--coverage", action="store_true",
                   help="report how evenly the sampler visits shards, then exit")
    args = p.parse_args(argv)

    if args.coverage:
        cfg = get_config(args.model)
        print(Dataset(args.data, cfg.max_seq_len).coverage_report())
        return 0
    if args.verify_resume:
        return 0 if verify_resume(args.model, args.data, args.out) else 1

    train(args.model, args.data, args.out,
          max_steps=args.max_steps, resume=args.resume,
          train_cfg=(TrainConfig(micro_batch=args.micro_batch)
                     if args.micro_batch else None))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
