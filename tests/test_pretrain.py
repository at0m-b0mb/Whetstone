"""Tests for the pretraining loop's checkpoints and its validation set.

Everything asserted here is a bug that still produces a falling loss curve, so
none of it can be caught by looking at training. A validation sample that moves
between evaluations, a checkpoint whose three files came from different steps,
an optimizer restore that silently did not happen, a resume that replays the
step it just saved, a batch 6% smaller than the one the learning rate was
chosen for — every one of them looks like a healthy run and several of them
look like the *same* healthy run, a loss spike that recovers, which is why they
were previously blamed on the corpus.

The validation-set property is the expensive one: `out/best` was being selected
by comparing numbers measured on different data, so the saved "best" checkpoint
was whichever step drew the easiest windows.
"""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

np = pytest.importorskip("numpy")
mx = pytest.importorskip("mlx.core")
optim = pytest.importorskip("mlx.optimizers")

from training.config import ModelConfig, TrainConfig  # noqa: E402
from training.data import TOKEN_DTYPE, Dataset, ShardIndex  # noqa: E402
from training.model import Whetstone  # noqa: E402
from training.pretrain import (  # noqa: E402
    evaluate,
    load_checkpoint,
    save_checkpoint,
    train,
    val_window_starts,
)

#: Deliberately far below `tiny`. These tests assert properties of the loop and
#: the checkpoint format, not of the architecture, and a real rung would make
#: them slow enough that nobody runs them — which is how a checkpoint format
#: goes a week without being round-tripped.
TINY = ModelConfig(name="test", vocab_size=64, d_model=32, n_layers=1,
                   n_heads=2, n_kv_heads=1, d_ff=64, max_seq_len=16)


def _corpus(root, *, shards: int = 3, tokens_per_shard: int = 4096,
            vocab: int = 64) -> None:
    """Write a real shard set, with ids inside the model's vocabulary.

    `test_data`'s fixture counts upward across the whole corpus, which is what
    it wants — identifiable batches. Here the ids are also fed to an embedding
    table, and an id past `vocab_size` indexes off the end of it.
    """
    root.mkdir(parents=True, exist_ok=True)
    meta = []
    value = 0
    for i in range(shards):
        data = np.array([(value + j) % vocab for j in range(tokens_per_shard)],
                        dtype=TOKEN_DTYPE)
        name = f"shard-{i:04d}.bin"
        data.tofile(root / name)
        meta.append({"file": name, "tokens": int(tokens_per_shard)})
        value += tokens_per_shard
    ShardIndex(root=root, shards=meta, total_tokens=shards * tokens_per_shard,
               documents=shards, vocab_size=vocab).save()


@pytest.fixture()
def corpus(tmp_path):
    root = tmp_path / "tokenized"
    _corpus(root)
    return root


def _trained_pair(seed: int = 3):
    """A model and an optimizer with one real update behind them.

    A freshly constructed AdamW has no state at all, so saving one proves
    nothing about the optimizer round trip: the moments have to exist first.
    """
    mx.random.seed(seed)
    model = Whetstone(TINY)
    opt = optim.AdamW(learning_rate=1e-3)
    x = mx.array(np.zeros((2, TINY.max_seq_len), dtype=np.int64))
    import mlx.nn as nn
    _, grads = nn.value_and_grad(model, lambda m: m.loss(x, x))(model)
    opt.update(model, grads)
    mx.eval(model.parameters(), opt.state)
    return model, opt


class TestFixedValidationSet:
    """Two evaluations are comparable only if they score the same tokens."""

    def test_evaluate_is_identical_across_calls(self, corpus):
        # The bug itself, pinned. `Dataset.batch` seeds from (seed, draw) and
        # advances the draw, so the old evaluate() measured a different random
        # subsample every time and `if vl < best_val` was selecting on noise.
        model, _ = _trained_pair()
        data = Dataset(corpus, TINY.max_seq_len, split="val", seed=5)
        first = evaluate(model, data, 2, limit=8)
        second = evaluate(model, data, 2, limit=8)
        assert first == second, (
            "the val set must be the same windows every time, or the val "
            "curve moves when the sample moves and 'best' means 'luckiest'")

    def test_evaluate_does_not_move_the_sampler(self, corpus):
        """Evaluation must not perturb the position a resume is built on."""
        model, _ = _trained_pair()
        data = Dataset(corpus, TINY.max_seq_len, split="val", seed=5)
        evaluate(model, data, 2, limit=8)
        assert data.draw == 0

    def test_the_window_set_does_not_depend_on_the_seed(self, corpus):
        a = Dataset(corpus, TINY.max_seq_len, split="val", seed=1)
        b = Dataset(corpus, TINY.max_seq_len, split="val", seed=999)
        assert val_window_starts(a, 8) == val_window_starts(b, 8), (
            "two runs differing only in seed must produce comparable val "
            "curves")

    def test_windows_span_the_whole_split_and_stay_inside_it(self, corpus):
        data = Dataset(corpus, TINY.max_seq_len, split="val", seed=1,
                       val_fraction=0.5)
        span = data.seq_len + 1
        available = (data.hi - data.lo) // span

        whole = val_window_starts(data, available * 10)
        assert len(whole) == available, "an uncapped set must be exhaustive"
        assert whole[0] == data.lo
        assert whole[-1] + span <= data.hi, "a window must not run past the split"
        assert len(set(whole)) == len(whole), "windows must not repeat"

        # The capped set must still reach the far end. Truncating the spacing
        # instead of the count bunches every window into the head of the
        # split, which for a positional split means scoring the model on
        # whichever sources happen to sit there.
        capped = val_window_starts(data, 4)
        assert len(capped) == 4
        assert capped[-1] > data.lo + (data.hi - data.lo) // 2


class TestCheckpointIsOneThing:
    """Three files, one commit point, and a loud refusal when they disagree."""

    def test_round_trips_weights_optimizer_and_step(self, tmp_path):
        model, opt = _trained_pair()
        save_checkpoint(tmp_path, model, opt, 42, TINY, TrainConfig(), draw=7)

        restored = Whetstone(TINY)
        ropt = optim.AdamW(learning_rate=1e-3)
        assert load_checkpoint(tmp_path, restored, ropt) == 42

        from mlx.utils import tree_flatten
        saved = dict(tree_flatten(opt.state))
        loaded = dict(tree_flatten(ropt.state))
        assert saved.keys() == loaded.keys()
        assert all(bool(mx.array_equal(saved[k], loaded[k])) for k in saved)

    def test_the_data_position_is_persisted(self, tmp_path):
        """Re-deriving it from step x accum was wrong the moment MICRO changed."""
        model, opt = _trained_pair()
        save_checkpoint(tmp_path, model, opt, 42, TINY, TrainConfig(), draw=1234)
        state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
        assert state["draw"] == 1234

    def test_no_temporary_files_are_left_behind(self, tmp_path):
        model, opt = _trained_pair()
        save_checkpoint(tmp_path, model, opt, 1, TINY, TrainConfig(), draw=0)
        assert not [p for p in tmp_path.iterdir() if p.name.startswith(".")]

    def test_a_torn_checkpoint_is_refused(self, tmp_path):
        """Weights from one save beside an optimizer from another.

        Exactly what a crash between two of the three renames leaves, and what
        the retry loop in scripts/overnight.sh then resumed without a word:
        weights that have taken 500 more steps than the moments that are about
        to be applied to them.
        """
        model, opt = _trained_pair()
        save_checkpoint(tmp_path, model, opt, 1000, TINY, TrainConfig(), draw=0)
        stale = (tmp_path / "optimizer.safetensors").read_bytes()

        model, opt = _trained_pair(seed=4)
        save_checkpoint(tmp_path, model, opt, 1500, TINY, TrainConfig(), draw=0)
        (tmp_path / "optimizer.safetensors").write_bytes(stale)

        with pytest.raises(SystemExit, match="torn checkpoint"):
            load_checkpoint(tmp_path, Whetstone(TINY),
                            optim.AdamW(learning_rate=1e-3))

    def test_a_missing_optimizer_is_refused_unless_asked_for(self, tmp_path):
        model, opt = _trained_pair()
        save_checkpoint(tmp_path, model, opt, 10, TINY, TrainConfig(), draw=0)
        (tmp_path / "optimizer.safetensors").unlink()

        with pytest.raises(SystemExit, match="missing"):
            load_checkpoint(tmp_path, Whetstone(TINY),
                            optim.AdamW(learning_rate=1e-3))

        # Deliberately, and only deliberately: a warm restart with zeroed
        # moments is a legitimate thing to want when branching a run, and an
        # illegitimate thing to be handed silently.
        assert load_checkpoint(tmp_path, Whetstone(TINY),
                               optim.AdamW(learning_rate=1e-3),
                               require_optimizer=False) == 10


class TestResumeDoesNotReplay:
    def test_resume_starts_after_the_checkpointed_step(self, corpus, tmp_path,
                                                       monkeypatch, capsys):
        """The checkpoint is written at the END of a step, so resume is step+1.

        Starting at `step` re-ran it: one duplicated optimizer update at the
        same learning rate and one step's data served twice, on every resume.
        """
        import training.pretrain as pretrain
        monkeypatch.setattr(pretrain, "get_config", lambda name: TINY)

        tcfg = TrainConfig(batch_tokens=64, micro_batch=2, eval_every=10**9,
                           checkpoint_every=10**9, log_every=10**9,
                           val_windows=4)
        out = tmp_path / "ckpt" / "test"
        model, opt = _trained_pair()
        save_checkpoint(out, model, opt, 1000, TINY, tcfg, draw=1234)

        train("test", corpus, tmp_path / "ckpt", max_steps=1001, resume=True,
              train_cfg=tcfg)
        printed = capsys.readouterr().out
        assert "resumed from step 1,001" in printed
        assert "data position 1,234 batches" in printed

    def test_resume_uses_the_persisted_position_not_the_current_accum(
            self, corpus, tmp_path, monkeypatch, capsys):
        """A checkpoint written at MICRO=4 and resumed at MICRO=8 must not move.

        The position was derived as step x accum from the *current* config, so
        halving micro_batch halved the derived position and replayed thousands
        of batches the run had already trained on — which lowers the loss and
        looks like nothing at all.
        """
        import training.pretrain as pretrain
        monkeypatch.setattr(pretrain, "get_config", lambda name: TINY)

        out = tmp_path / "ckpt" / "test"
        written_with = TrainConfig(batch_tokens=64, micro_batch=2,
                                   eval_every=10**9, checkpoint_every=10**9,
                                   log_every=10**9, val_windows=4)
        model, opt = _trained_pair()
        save_checkpoint(out, model, opt, 100, TINY, written_with, draw=555)

        resumed_with = replace(written_with, micro_batch=4)
        train("test", corpus, tmp_path / "ckpt", max_steps=101, resume=True,
              train_cfg=resumed_with)
        assert "data position 555 batches" in capsys.readouterr().out


class TestEffectiveBatch:
    """The batch the run takes, versus the batch every printout claimed."""

    def test_a_non_dividing_micro_batch_shrinks_the_batch(self):
        cfg = ModelConfig(name="ctx", max_seq_len=1024)
        six = TrainConfig(micro_batch=6)
        assert six.grad_accum_steps(cfg) == 10
        assert six.effective_batch_tokens(cfg) == 61_440
        assert six.effective_batch_tokens(cfg) != six.batch_tokens, (
            "65,536 // 6,144 truncates; the run is 6% short of the batch the "
            "learning rate was chosen for, and used to say 65,536 anyway")

    def test_a_dividing_micro_batch_is_exact(self):
        cfg = ModelConfig(name="ctx", max_seq_len=1024)
        for micro in (1, 2, 4, 8, 16, 32, 64):
            t = TrainConfig(micro_batch=micro)
            assert t.effective_batch_tokens(cfg) == t.batch_tokens

    def test_an_oversized_micro_batch_enlarges_the_batch(self):
        """The reverse case, which is silent in the other direction."""
        cfg = ModelConfig(name="ctx", max_seq_len=1024)
        big = TrainConfig(micro_batch=128)
        assert big.grad_accum_steps(cfg) == 1
        assert big.effective_batch_tokens(cfg) == 131_072

    def test_the_step_budget_is_built_on_the_real_batch(self):
        """Or the run hits its step count having trained on less than asked."""
        cfg = ModelConfig(name="ctx", max_seq_len=1024)
        six = TrainConfig(micro_batch=6)
        assert six.total_steps(cfg) == max(
            1, six.total_tokens(cfg) // six.effective_batch_tokens(cfg))
        assert six.total_steps(cfg) > six.total_tokens(cfg) // six.batch_tokens
