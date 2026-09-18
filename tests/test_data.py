"""Tests for the training data loader.

The loader is the component whose bugs are hardest to see, because every one of
them still produces a falling loss curve. A sampler that re-serves old batches,
a split that holds out one source, a shard visited ten times more often than its
neighbour — none of these raise, and all of them look like training working.
So the properties are asserted here rather than inferred from the loss.

The resume property is the one that cost real compute: weights and optimizer
were being restored while the sampler silently restarted from draw zero.
"""

from __future__ import annotations

import json

import pytest

np = pytest.importorskip("numpy")

from training.data import TOKEN_DTYPE, Dataset, ShardIndex  # noqa: E402


def _corpus(root, *, shards: int = 3, tokens_per_shard: int = 4096) -> None:
    """Write a real shard set — distinct values, so batches are identifiable."""
    root.mkdir(parents=True, exist_ok=True)
    meta = []
    value = 1
    for i in range(shards):
        data = np.arange(value, value + tokens_per_shard, dtype=TOKEN_DTYPE)
        name = f"shard-{i:04d}.bin"
        data.tofile(root / name)
        meta.append({"file": name, "tokens": int(tokens_per_shard)})
        value += tokens_per_shard
    ShardIndex(root=root, shards=meta, total_tokens=shards * tokens_per_shard,
               documents=shards, vocab_size=16384).save()


@pytest.fixture()
def corpus(tmp_path):
    root = tmp_path / "tokenized"
    _corpus(root)
    return root


class TestResume:
    """A resumed run must continue the stream, not replay it."""

    def test_seek_continues_the_stream(self, corpus):
        uninterrupted = Dataset(corpus, 64, split="train", seed=7)
        served = [uninterrupted.batch(2)[0] for _ in range(6)]

        # A fresh loader that seeks to draw 3 must serve batches 4, 5, 6 —
        # exactly what the uninterrupted run served next.
        resumed = Dataset(corpus, 64, split="train", seed=7)
        resumed.seek(3)
        for expected in served[3:]:
            assert np.array_equal(resumed.batch(2)[0], expected)

    def test_without_seek_a_resumed_loader_replays(self, corpus):
        """The bug itself, pinned: construction alone restarts the stream."""
        a = Dataset(corpus, 64, split="train", seed=7)
        first = a.batch(2)[0]
        for _ in range(4):
            a.batch(2)

        fresh = Dataset(corpus, 64, split="train", seed=7)
        assert np.array_equal(fresh.batch(2)[0], first), (
            "a fresh loader restarts the stream — which is why resume must "
            "seek, and why this test exists")

    def test_draw_tracks_position(self, corpus):
        d = Dataset(corpus, 64, split="train", seed=7)
        assert d.draw == 0
        for i in range(1, 4):
            d.batch(2)
            assert d.draw == i

    def test_seek_rejects_negative(self, corpus):
        d = Dataset(corpus, 64, split="train", seed=7)
        with pytest.raises(ValueError, match="non-negative"):
            d.seek(-1)

    def test_successive_draws_differ(self, corpus):
        """Per-draw seeding must not collapse into the same batch every time."""
        d = Dataset(corpus, 64, split="train", seed=7)
        batches = [d.batch(2)[0].tobytes() for _ in range(5)]
        assert len(set(batches)) == 5, "each draw must sample independently"

    def test_seed_still_determines_the_stream(self, corpus):
        same = [Dataset(corpus, 64, split="train", seed=11).batch(2)[0]
                for _ in range(2)]
        assert np.array_equal(*same), "same seed must reproduce"
        other = Dataset(corpus, 64, split="train", seed=12).batch(2)[0]
        assert not np.array_equal(same[0], other), "different seed must differ"


class TestSplits:
    def test_train_and_val_do_not_overlap(self, corpus):
        # An explicit fraction: the production default of 0.5% would hold out
        # fewer tokens than one window from a fixture this size.
        train = Dataset(corpus, 64, split="train", seed=1, val_fraction=0.2)
        val = Dataset(corpus, 64, split="val", seed=1, val_fraction=0.2)
        assert train.hi <= val.lo, "a val window must not be trainable"

    def test_shapes_line_up_for_next_token_prediction(self, corpus):
        x, y = Dataset(corpus, 64, split="train", seed=1).batch(3)
        assert x.shape == y.shape == (3, 64)
        # y is x shifted by one: the target at t is the input at t+1.
        assert np.array_equal(x[:, 1:], y[:, :-1])

    def test_index_mismatch_is_refused(self, tmp_path):
        root = tmp_path / "bad"
        _corpus(root, shards=1)
        meta = json.loads((root / "index.json").read_text())
        meta["shards"][0]["tokens"] = 999          # lie about the shard
        (root / "index.json").write_text(json.dumps(meta))
        with pytest.raises(ValueError, match="index claims"):
            Dataset(root, 64, split="train", seed=1)
