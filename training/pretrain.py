"""Pretraining: the loop that turns a corpus into a checkpoint.

    python -m training.pretrain --model tiny --data data/corpus/tokenized
    python -m training.pretrain --model base --resume

Run ``tiny`` first. It finishes in about five hours — or in two minutes with
``--max-steps 200`` — and every bug worth finding shows itself there: a loader
that favours one shard, a schedule that never warms up, a checkpoint that does
not round-trip. Finding those at ``base`` costs a week.

**On resume.** A run that cannot resume is a run that loses a week to a
reboot. Resuming restores four things, and three of them are not the weights:
optimizer state, the step counter (the learning-rate schedule is a function of
it, so restoring weights alone silently continues at a peak learning rate the
run should long since have decayed past) and the sampler's position in the
token stream. All four are written down, because every one of them that is
re-derived instead is a number that was right until the day somebody changed a
flag. ``--verify-resume`` proves the round trip — weights, optimizer tensors,
step and position — and is worth running once after any change to the
checkpoint format.

**On the validation number.** The val set is a fixed set of windows, spread
evenly across the whole held-out split and identical at every evaluation. It
has to be: "best checkpoint" is a comparison between evaluations, and a
comparison between two different random samples measures the sampler. See
``val_window_starts``. Checkpoints written before that was true can be
re-scored against the fixed set afterwards with ``scripts/eval_checkpoints.py``.

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
import os
import time
from dataclasses import asdict, replace
from pathlib import Path

import mlx.core as mx
import mlx.nn as nn
import mlx.optimizers as optim
import numpy as np

from .config import STAIRCASE, ModelConfig, TrainConfig, get_config
from .data import Dataset
from .model import Whetstone

__all__ = ["train", "cosine_lr", "save_checkpoint", "load_checkpoint",
           "load_weights_only", "evaluate", "val_window_starts"]


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


#: Stamped into the safetensors metadata of both tensor files and into
#: state.json, so the three files of one checkpoint can be recognised as
#: belonging together. See ``save_checkpoint``.
_SAVE_ID = "whetstone_save_id"


def _fsync(path: Path) -> None:
    """Force ``path`` — a file or a directory — durable before moving on.

    A rename is atomic with respect to the *directory entry*, not with respect
    to the data behind it: after a crash the name can point at a file whose
    contents never left the page cache. The failure this project has actually
    seen is an external SSD dropping mid-run, which is exactly that case, so
    every temporary file is fsynced before it is renamed and the directory is
    fsynced after. Without this the tmp-and-rename dance is decorative.
    """
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def save_checkpoint(
    out: Path, model: Whetstone, opt: optim.Optimizer, step: int,
    model_cfg: ModelConfig, train_cfg: TrainConfig,
    *, val_loss: float | None = None, history: list[dict] | None = None,
    draw: int | None = None,
) -> None:
    """Weights, optimizer state, step and data position — one checkpoint.

    ``step`` is the index of the step whose update these weights contain, so a
    resume starts at ``step + 1``; ``draw`` is the sampler position at the same
    instant. Both are needed: a run that restores two of the four is not
    resumable, it is a run that quietly repeats work.

    **On committing three files.** Three files cannot be replaced in one
    syscall, so this makes a torn checkpoint *detectable* rather than merely
    unlikely. Every save mints one ``save_id``, stamps it into the safetensors
    metadata of both tensor files and into state.json, writes all three to
    temporary names, fsyncs them, and only then renames — state.json last,
    because it is the file that names the save. The commit point is that last
    rename, and ``load_checkpoint`` refuses a checkpoint whose ids disagree.
    The previous shape renamed each file the moment it finished writing, so a
    death between two renames left weights from one step beside an optimizer
    from the step before, and nothing recorded which was which; the retry loop
    in scripts/overnight.sh then resumed it silently and trained against
    another weight vector's Adam moments. state.json was worse still — a plain
    ``write_text``, so a death mid-write left truncated JSON that killed all
    twenty retries with valid weights sitting next to it.

    Staging the three files in a directory and replacing the directory in one
    call would be a genuine single commit point, but ``os.replace`` refuses a
    non-empty destination: it would have to delete the live checkpoint first,
    leaving a window with *no* checkpoint, which is strictly worse than a
    window with a detectably torn one. Repointing a ``latest`` symlink would
    work, but bench, ``training.sft`` and scripts/overnight.sh all open
    ``weights.safetensors`` inside the checkpoint directory by name, so that is
    a layout change rather than a save change.
    """
    out.mkdir(parents=True, exist_ok=True)
    from mlx.utils import tree_flatten

    # The step alone does not identify a save: `out/` and `out/best` are both
    # written at the same step, and a resumed run rewrites steps it has already
    # saved once. The clock distinguishes a save from its predecessor, which is
    # the only comparison the torn-checkpoint check has to make.
    save_id = f"{step}-{time.time_ns():x}"
    meta = {_SAVE_ID: save_id}

    w_tmp = out / ".weights.tmp.safetensors"
    mx.save_safetensors(str(w_tmp), dict(tree_flatten(model.parameters())), meta)
    _fsync(w_tmp)

    o_tmp = out / ".opt.tmp.safetensors"
    mx.save_safetensors(str(o_tmp), dict(tree_flatten(opt.state)), meta)
    _fsync(o_tmp)

    state: dict = {
        "save_id": save_id,
        "step": step,
        "model": asdict(model_cfg),
        "train": asdict(train_cfg),
    }
    if draw is not None:
        # Persisted rather than re-derived. `Dataset.draw` exists precisely to
        # be written down here; reconstructing it downstream as step × accum
        # was wrong by one step always, and wrong by a factor of two the first
        # time a death at MICRO=4 was resumed at MICRO=8.
        state["draw"] = draw
    if val_loss is not None:
        state["val_loss"] = val_loss
        state["val_ppl"] = round(math.exp(min(val_loss, 20)), 2)
    if history is not None:
        # The whole curve, so the run can be judged after the fact without
        # having to still have the log.
        state["val_history"] = history
    s_tmp = out / ".state.tmp.json"
    s_tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    _fsync(s_tmp)

    # Renames only from here: the bytes are already durable, so the three
    # commit points are microseconds apart rather than the seconds it takes to
    # write 370 MB of tensors.
    w_tmp.replace(out / "weights.safetensors")
    o_tmp.replace(out / "optimizer.safetensors")
    s_tmp.replace(out / "state.json")          # last — this is the commit
    _fsync(out)


def load_checkpoint(
    out: Path, model: Whetstone, opt: optim.Optimizer,
    *, require_optimizer: bool = True,
) -> int:
    """Restore weights, optimizer state and step. Returns the step.

    Refuses rather than repairs, in both directions it can fail. A checkpoint
    whose three files came from different saves, and a checkpoint with no
    optimizer file at all, are not slightly-degraded resumes: the first trains
    weights against another weight vector's Adam moments, and the second warm-
    restarts with zeroed first and second moments at whatever mid-schedule
    learning rate the cosine says — MLX's ``Optimizer.state`` setter clears
    ``_initialized``, so the missing moments are silently re-created as zeros
    on the first update. Both produce a loss spike that recovers within a few
    hundred steps, which is indistinguishable from the bad-batch spike this
    module's docstring describes, and sends the investigation upstream into
    ``training/corpus/`` for a bug that is in this function.
    """
    from mlx.utils import tree_unflatten

    state = json.loads((out / "state.json").read_text(encoding="utf-8"))
    weights, w_meta = mx.load(str(out / "weights.safetensors"), return_metadata=True)
    model.update(tree_unflatten(list(weights.items())))

    opt_path = out / "optimizer.safetensors"
    o_meta: dict = {}
    if opt_path.is_file():
        opt_arrays, o_meta = mx.load(str(opt_path), return_metadata=True)
        opt.state = tree_unflatten(list(opt_arrays.items()))
    elif require_optimizer:
        raise SystemExit(
            f"{opt_path} is missing, so this checkpoint cannot be resumed as "
            "written. Restoring the weights alone restarts Adam from zeroed "
            "moments at the learning rate step "
            f"{state.get('step', '?')} sits at on the cosine — a warm restart "
            "that spikes the loss and looks exactly like a bad batch. Pass "
            "--reset-optimizer to ask for that deliberately, or resume from a "
            "checkpoint that has all three files."
        )
    else:
        print("  WARNING: --reset-optimizer — Adam restarts from zeroed "
              "moments. Expect a loss spike over the next few hundred steps; "
              "it is this flag and not the corpus.", flush=True)

    want = state.get("save_id")
    if want is None:
        print("  WARNING: this checkpoint predates the save-id stamp, so its "
              "three files cannot be cross-checked. If the run that wrote it "
              "died between two renames, the weights and the optimizer are "
              "from different steps and nothing here can tell.", flush=True)
    else:
        files = [("weights.safetensors", w_meta)]
        if opt_path.is_file():
            files.append(("optimizer.safetensors", o_meta))
        for name, file_meta in files:
            got = (file_meta or {}).get(_SAVE_ID)
            if got != want:
                raise SystemExit(
                    f"torn checkpoint in {out}: state.json is from save "
                    f"{want!r} but {name} is from {got!r}. The run that wrote "
                    "it died between two of the three renames, so these files "
                    "hold different steps. Resuming would train these weights "
                    "against another step's Adam moments at another step's "
                    "learning rate, spike, recover, and leave nothing in the "
                    "log to say why. Resume from another checkpoint — out/best "
                    "if it is intact — rather than deleting state.json to make "
                    "this message go away."
                )

    mx.eval(model.parameters(), opt.state)
    return int(state["step"])


def load_weights_only(out: Path, model: Whetstone) -> dict:
    """Restore weights for scoring and return the checkpoint's state dict.

    Separate from ``load_checkpoint`` because evaluation has no optimizer to
    restore and therefore no business refusing a checkpoint whose optimizer
    file is torn or absent: validation loss is a function of the weights alone.
    Resuming is the operation that needs all three files to agree.
    """
    from mlx.utils import tree_unflatten

    state = json.loads((out / "state.json").read_text(encoding="utf-8"))
    model.update(tree_unflatten(
        list(mx.load(str(out / "weights.safetensors")).items())))
    mx.eval(model.parameters())
    return state


def val_window_starts(data: Dataset, limit: int) -> list[int]:
    """The fixed validation window set, as global token offsets.

    Deterministic arithmetic over the split's bounds: no RNG, no draw counter,
    no seed. That is the whole point. ``Dataset.batch`` seeds from
    ``(seed, draw)`` and advances the draw on every call, so the previous
    ``evaluate`` scored a *different* random subsample of val every time it
    ran — 80 windows out of 486 for the v5 corpus, redrawn with replacement
    across sources whose per-window entropy differs wildly. The val curve then
    moved when the sample moved, and ``if vl < best_val`` over eighteen such
    estimates is selection on noise: it keeps the checkpoint that drew the
    easiest windows and reports a best loss biased low by about the size of the
    jitter. Two evaluations are comparable only if they score the same tokens.

    Because the window set does not depend on the seed, two runs that differ
    only in ``seed`` now produce val curves that can be read against each other
    as well.

    Windows are spread evenly across the whole split rather than taken from its
    head. The split is a contiguous slice of the token stream and shards are
    grouped by source, so a prefix would score the model on whichever two or
    three sources happen to sit at the start of the held-out tail.

    When the split holds no more than ``limit`` non-overlapping windows — 486
    against a limit of 512, for v5 — this returns the entire split and the val
    number stops being an estimate of anything at all.
    """
    stride = data.seq_len + 1
    available = max(1, (data.hi - data.lo) // stride)
    n = min(limit, available)
    # `i * available // n` and not `i * (available // n)`: the second truncates
    # the spacing, which bunches every window into the leading `n/available` of
    # the split — the head-of-the-split bias again, in a subtler shape.
    return [data.lo + (i * available // n) * stride for i in range(n)]


def evaluate(model: Whetstone, data: Dataset, batch_size: int,
             *, limit: int = 512) -> float:
    """Mean validation loss over a FIXED window set. No gradient, no dropout.

    Reads through ``Dataset._read`` rather than ``Dataset.batch`` because
    ``batch`` is *defined* as a random draw — there is no argument to it that
    asks for a chosen window — and because it advances the sampler position as
    a side effect. Reaching for the private reader is the honest version of
    that, and it means an evaluation can no longer perturb a resume.
    """
    starts = val_window_starts(data, limit)
    span = data.seq_len + 1
    total = 0.0
    counted = 0
    for i in range(0, len(starts), batch_size):
        chunk = starts[i:i + batch_size]
        window = np.stack([data._read(s, span) for s in chunk])
        loss = model.loss(mx.array(window[:, :-1]), mx.array(window[:, 1:]))
        mx.eval(loss)
        # Weighted by window count rather than averaged over batches: the last
        # batch is usually short (486 windows do not divide by 4), and a plain
        # mean of batch means would give its two windows the weight of four.
        total += loss.item() * len(chunk)
        counted += len(chunk)
    return total / counted


def train(
    model_name: str,
    data_root: Path,
    out_root: Path,
    *,
    max_steps: int | None = None,
    resume: bool = False,
    train_cfg: TrainConfig | None = None,
    reset_optimizer: bool = False,
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
    # The batch the run takes, which is the configured one only when
    # micro × ctx divides it. Every number printed or estimated below is
    # against this, never against tcfg.batch_tokens — see TrainConfig
    # .effective_batch_tokens for what reading the configured value cost.
    batch_tokens = tcfg.effective_batch_tokens(cfg)

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
        # +1, because the checkpoint is written at the *end* of step `step` and
        # already contains that step's update. Starting the loop at `step` ran
        # it a second time: one duplicated optimizer update at the same
        # learning rate, and one step's worth of data served twice, on every
        # resume the retry loop ever performed.
        start = load_checkpoint(out, model, opt,
                                require_optimizer=not reset_optimizer) + 1

        # The config the checkpoint was WRITTEN with, which is not necessarily
        # this process's: --micro-batch is the flag operators are told to
        # change when a run swaps, and overnight.sh exposes it as $MICRO across
        # a death and its retry.
        prior_train = prior.get("train", {})
        prior_tcfg = replace(
            tcfg,
            micro_batch=int(prior_train.get("micro_batch", micro)),
            batch_tokens=int(prior_train.get("batch_tokens", tcfg.batch_tokens)),
        )
        if "draw" in prior:
            resume_draw = int(prior["draw"])
        else:
            # A checkpoint from before the position was persisted. Re-derive
            # it, but from the checkpoint's own micro_batch rather than this
            # process's: a run that died at MICRO=4 and resumed at MICRO=8
            # derived half the position and replayed 16,000 batches it had
            # already trained on, which lowers the loss and says nothing.
            resume_draw = start * prior_tcfg.grad_accum_steps(cfg)
            print(f"  WARNING: this checkpoint stores no data position; "
                  f"re-deriving it as {start:,} steps × "
                  f"{prior_tcfg.grad_accum_steps(cfg)} accum. Exact only if the "
                  "run that wrote it never changed --micro-batch.", flush=True)
        # Weights and optimizer alone are not a resumable run: without this the
        # sampler restarts and re-serves the batches the first `start` steps
        # already consumed.
        train_data.seek(resume_draw)
        print(f"resumed from step {start:,} "
              f"(data position {resume_draw:,} batches)")

        prior_batch = prior_tcfg.effective_batch_tokens(cfg)
        if prior_batch != batch_tokens:
            print(f"  WARNING: this checkpoint was written with an effective "
                  f"batch of {prior_batch:,} tokens/step and this process takes "
                  f"{batch_tokens:,}. The step budget and the cosine schedule "
                  "were both built for the first number, so the second half of "
                  "this run is on a different curve from the first.", flush=True)

    print(f"\n{cfg.summary()}")
    print(f"  {train_data}\n  {val_data}")
    print(f"  {total_steps:,} steps × {micro}×{cfg.max_seq_len} × {accum} accum "
          f"= {batch_tokens:,} tokens/step")
    if batch_tokens != tcfg.batch_tokens:
        print(f"  NOTE: that is not the configured {tcfg.batch_tokens:,}. "
              f"{micro}×{cfg.max_seq_len} does not divide it, so accumulation "
              f"truncates to {accum}. Every number here is against the batch "
              f"the run actually takes, but the learning rate "
              f"{tcfg.learning_rate:.1e} was chosen for "
              f"{tcfg.batch_tokens:,}: pick a micro-batch that divides "
              f"{tcfg.batch_tokens // cfg.max_seq_len} sequences to avoid this.")
    n_val = len(val_window_starts(val_data, tcfg.val_windows))
    print(f"  val: a fixed {n_val:,} windows ({n_val * cfg.max_seq_len:,} tokens), "
          f"the same ones at every eval")
    print(f"  ~{cfg.measured_days(total_steps * batch_tokens):.1f} days at the "
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
            vl = evaluate(model, val_data, micro, limit=tcfg.val_windows)
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
                                val_loss=vl, history=history,
                                draw=train_data.draw)
                flag = "  ← best"
            print(f"  ── val loss {vl:.4f}  (ppl {math.exp(min(vl, 20)):.1f})"
                  f"{flag}", flush=True)

        if step and step % tcfg.checkpoint_every == 0:
            save_checkpoint(out, model, opt, step, cfg, tcfg, history=history,
                            draw=train_data.draw)

    final = evaluate(model, val_data, micro, limit=tcfg.val_windows)
    history.append({"step": total_steps, "val_loss": final})
    if final < best_val:
        best_val = final
        save_checkpoint(out / "best", model, opt, total_steps, cfg, tcfg,
                        val_loss=final, history=history, draw=train_data.draw)
    # `total_steps` here is a count and not an index — the last step run was
    # total_steps - 1 — so a --resume against a finished run starts at
    # total_steps + 1 and falls straight through the empty range, which is the
    # behaviour wanted: a finished run has nothing left to do.
    save_checkpoint(out, model, opt, total_steps, cfg, tcfg,
                    val_loss=final, history=history, draw=train_data.draw)

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
    save_checkpoint(tmp, model, opt, 42, cfg, tcfg, draw=9)

    restored = Whetstone(cfg)
    ropt = optim.AdamW(learning_rate=1e-4)
    step = load_checkpoint(tmp, restored, ropt)
    after = restored.loss(mx.array(x), mx.array(y)).item()

    # A forward loss can only ever prove the WEIGHTS round-tripped, because it
    # is a pure function of them — and the optimizer is the half that fails
    # silently. This check printed OK for a loader that skipped the optimizer
    # restore entirely. Compare the tensors, or the docstring above is a claim
    # nothing tests.
    from mlx.utils import tree_flatten
    saved = dict(tree_flatten(opt.state))
    loaded = dict(tree_flatten(ropt.state))
    opt_ok = saved.keys() == loaded.keys() and all(
        saved[k].dtype == loaded[k].dtype
        and bool(mx.array_equal(saved[k], loaded[k]))
        for k in saved
    )
    # The sampler position is the fourth thing a resume restores and the one
    # with no in-memory consequence, so it is the one that rots unnoticed.
    draw_ok = json.loads((tmp / "state.json").read_text(encoding="utf-8")
                         ).get("draw") == 9

    ok = step == 42 and abs(before - after) < 1e-4 and opt_ok and draw_ok
    print(f"resume round-trip: step {step} (want 42), "
          f"loss {before:.6f} → {after:.6f}, "
          f"optimizer {len(saved)} tensors {'match' if opt_ok else 'DIFFER'}, "
          f"data position {'kept' if draw_ok else 'LOST'}  "
          f"{'OK' if ok else 'MISMATCH'}")
    return ok


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Pretrain a Whetstone model.")
    p.add_argument("--model", default="tiny", choices=list(STAIRCASE))
    p.add_argument("--data", type=Path, default=Path("data/corpus/tokenized"))
    p.add_argument("--out", type=Path, default=Path("data/models/checkpoints"))
    p.add_argument("--max-steps", type=int, default=None)
    p.add_argument("--micro-batch", type=int, default=None,
                   help="sequences per forward pass. Lower it if the run swaps: "
                        "small at 8 x 1024 swapped this machine to 24.9 GB and "
                        "never reached step 1. Accumulation is raised to keep "
                        "the effective batch identical ONLY when this divides "
                        "batch_tokens/ctx — 64 sequences by default, so 1/2/4/8/"
                        "16/32/64. Anything else truncates the accumulation "
                        "count and shrinks the real batch; the run says so on "
                        "startup rather than reporting the configured number.")
    p.add_argument("--resume", action="store_true")
    p.add_argument("--reset-optimizer", action="store_true",
                   help="resume from weights alone, with Adam's moments zeroed. "
                        "A warm restart at mid-schedule learning rate: it "
                        "spikes the loss. Only for branching a run from copied "
                        "weights — without it a missing optimizer file is an "
                        "error, because it used to be a silent one.")
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
          reset_optimizer=args.reset_optimizer,
          train_cfg=(TrainConfig(micro_batch=args.micro_batch)
                     if args.micro_batch else None))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
