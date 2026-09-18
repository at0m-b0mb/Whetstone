"""Tests for supervised fine-tuning's two accounting rules.

Both bugs pinned here had the same shape: a decision about *units*, made once,
that nothing downstream could see. The loss fell either way. The run printed a
healthy-looking number either way. The only visible consequence was a benchmark
score, and the natural reading of a bad benchmark score is that the model is too
small — which is a conclusion about the model drawn from a slicing rule and a
counter.

**Where the budget comes out of an over-long trajectory.** Findings are rendered
last, so head truncation deletes the rarest model turn first. The test is that a
trajectory whose ``<|find|>`` falls past ``seq_len`` still supervises that
finding afterwards.

**What ``replay_fraction`` is a fraction of.** The loss is masked, so an
example's pull is its supervised-token count, and a 1,023-target pretraining
window is not one vote like a 69-target trajectory is. Two wrong answers are
tested alongside the right one, because "share of examples" and "share of all
supervised tokens" both look correct and miss in opposite directions.

The tokenizer is built here rather than loaded: with no merges, every character
is its own id, so a document's token count is its character count and a
``<|find|>`` can be placed a known distance past the budget instead of wherever
BPE happened to put it.
"""

from __future__ import annotations

import pytest

np = pytest.importorskip("numpy")
pytest.importorskip("mlx.core")          # training.sft imports MLX at module scope
pytest.importorskip("tokenizers")

from training.sft import (  # noqa: E402
    build_examples,
    replay_share,
    size_replay,
    supervised_targets,
)
from training.tokenizer.protocol import SPECIAL_TOKENS  # noqa: E402

FINDING = "no process-creation logging"


def _write_tokenizer(path, *, specials=SPECIAL_TOKENS):
    """A byte-level tokenizer with no merges: one token per character."""
    from tokenizers import Tokenizer, decoders, models, pre_tokenizers

    alphabet = sorted(pre_tokenizers.ByteLevel.alphabet())
    tok = Tokenizer(models.BPE(vocab={c: i for i, c in enumerate(alphabet)},
                               merges=[]))
    tok.pre_tokenizer = pre_tokenizers.ByteLevel(add_prefix_space=False,
                                                 use_regex=False)
    tok.decoder = decoders.ByteLevel()
    if specials:
        tok.add_special_tokens(list(specials))
    tok.save(str(path))
    return path


@pytest.fixture()
def tokenizer(tmp_path):
    return _write_tokenizer(tmp_path / "tokenizer.json")


def _trajectory(turns: int = 3, obs_chars: int = 200, finding: str = FINDING) -> str:
    """One rendered episode, in render_episode's order.

    The order is the point: every ``<|find|>`` goes after the last observation,
    which is what makes a head cut take the findings and leave the boilerplate.
    """
    parts = ["<|bos|>", "<|task|>find what runs without a human",
             "<|host|>linux", "<|scope|>observe",
             "<|verbs|>enum.persistence(); detect.telemetry()"]
    for _ in range(turns):
        parts.append('<|act|>{"verb":"enum.persistence","target":"127.0.0.1"}')
        parts.append('<|obs|>{"ok":true,"data":{"autoruns":"'
                     + "x" * obs_chars + '"}}')
    if finding:
        parts.append('<|find|>{"title":"' + finding + '","severity":"high"}')
    parts.append("<|eos|>")
    return "".join(parts)


def _corpus(root, documents):
    root.mkdir(parents=True, exist_ok=True)
    for i, text in enumerate(documents):
        (root / f"trajectory-{i:05d}.txt").write_text(text, encoding="utf-8")
    return root


def _supervised_text(tokenizer_path, ids, mask) -> str:
    """Exactly what the loss will train the model to produce, as text."""
    from tokenizers import Tokenizer

    tok = Tokenizer.from_file(str(tokenizer_path))
    return tok.decode([int(t) for t, m in zip(ids, mask) if m])


class TestTruncation:
    """An over-long trajectory gives up observations, never its own turns."""

    def test_the_finding_survives_a_trajectory_that_does_not_fit(
            self, tmp_path, tokenizer):
        text = _trajectory(turns=4, obs_chars=200)
        seq_len = len(text) // 2                      # comfortably over budget
        root = _corpus(tmp_path / "traj", [text])

        ids, mask, stats = build_examples(root, tokenizer, seq_len)

        assert stats.finding_turns == 1, "the finding must still be in the data"
        assert FINDING in _supervised_text(tokenizer, ids[0], mask[0]), (
            "the <|find|> span is what the model is being trained to produce; "
            "without it the episode teaches how to act and never why")

    def test_head_truncation_is_what_this_replaces(self, tokenizer):
        """The bug itself, pinned: the old rule cut exactly the finding."""
        from tokenizers import Tokenizer

        tok = Tokenizer.from_file(str(tokenizer))
        text = _trajectory(turns=4, obs_chars=200)
        raw = tok.encode(text).ids
        seq_len = len(text) // 2

        assert tok.token_to_id("<|find|>") in raw
        assert tok.token_to_id("<|find|>") not in raw[:seq_len], (
            "findings are rendered last, so ids[:seq_len] takes them first — "
            "while leaving enough <|act|> supervision behind that nothing "
            "refuses the example")
        assert tok.token_to_id("<|act|>") in raw[:seq_len], (
            "and this is why the mask.sum() == 0 guard never caught it")

    def test_the_budget_comes_out_of_the_observations(self, tmp_path, tokenizer):
        text = _trajectory(turns=4, obs_chars=200)
        root = _corpus(tmp_path / "traj", [text])

        ids, _mask, stats = build_examples(root, tokenizer, len(text) // 2)

        assert stats.elided_trajectories == 1
        assert stats.elided_observations >= 1
        from tokenizers import Tokenizer
        kept = Tokenizer.from_file(str(tokenizer)).decode(
            [int(t) for t in ids[0]], skip_special_tokens=False)
        assert '{"elided":true}' in kept, (
            "an elided observation says so: valid JSON, because the model "
            "parses observations, and marked, because a silent cut teaches it "
            "that hosts really do have four services")
        assert kept.count('"verb":"enum.persistence"') == 4, (
            "every action the model has to produce is still there")

    def test_a_trajectory_that_fits_is_left_alone(self, tmp_path, tokenizer):
        text = _trajectory(turns=2, obs_chars=40)
        root = _corpus(tmp_path / "traj", [text])

        ids, _mask, stats = build_examples(root, tokenizer, len(text) + 64)

        assert (stats.elided_trajectories, stats.elided_observations) == (0, 0)
        from tokenizers import Tokenizer
        tok = Tokenizer.from_file(str(tokenizer))
        assert tok.decode([int(t) for t in ids[0][:len(tok.encode(text).ids)]],
                          skip_special_tokens=False) == text

    def test_an_episode_whose_own_turns_overflow_is_dropped_and_counted(
            self, tmp_path, tokenizer):
        """Not truncated into something plausible. Dropped, and said out loud."""
        fits = _trajectory(turns=1, obs_chars=20)
        overflows = _trajectory(turns=1, obs_chars=20, finding="g" * 4000)
        root = _corpus(tmp_path / "traj", [fits, overflows])

        _ids, _mask, stats = build_examples(root, tokenizer, 512)

        assert stats.trajectories == 1
        assert stats.dropped_over_length == 1
        assert "DROPPED" in stats.report()

    def test_a_corpus_that_all_drops_out_raises(self, tmp_path, tokenizer):
        root = _corpus(tmp_path / "traj",
                       [_trajectory(turns=1, finding="g" * 4000)])
        with pytest.raises(SystemExit, match="every trajectory"):
            build_examples(root, tokenizer, 512)

    def test_observations_are_never_supervised(self, tmp_path, tokenizer):
        """The property the whole file exists for, restated after the rewrite."""
        text = _trajectory(turns=4, obs_chars=200)
        root = _corpus(tmp_path / "traj", [text])

        ids, mask, _stats = build_examples(root, tokenizer, len(text) // 2)

        supervised = _supervised_text(tokenizer, ids[0], mask[0])
        assert '"ok":true' not in supervised, (
            "a model trained to predict an observation hallucinates tool output")
        assert "elided" not in supervised


class TestTokenizerContract:
    def test_a_tokenizer_without_the_markers_is_refused(self, tmp_path):
        """Loudly, because the silent failure is a run that trains on nothing."""
        path = _write_tokenizer(tmp_path / "bare.json", specials=())
        root = _corpus(tmp_path / "traj", [_trajectory(turns=1)])
        with pytest.raises(SystemExit, match="atomic ids"):
            build_examples(root, path, 512)


class TestSupervisedTargets:
    def test_position_zero_is_not_a_target(self):
        """It has no predecessor, so a 1 there is supervision that never happens.

        The count and masked_loss have to agree exactly: the replay mixture is
        budgeted in these units, and a counter that is generous by one per
        example would size the rehearsal against a number the optimiser never
        sees.
        """
        mask = np.zeros((2, 5), dtype=np.int8)
        mask[:, 0] = 1
        assert supervised_targets(mask) == 0
        mask[:, 3] = 1
        assert supervised_targets(mask) == 2


class TestReplayMixture:
    """What ``replay_fraction`` is a fraction of.

    The numbers are the production ones: 1,250 trajectories averaging 69
    supervised targets, 1,023-target pretraining windows, batches of 4.
    """

    TRAJ = np.full(1250, 69)
    WINDOW = 1023
    KW = {"batch_size": 4, "epochs": 3, "seed": 1337}

    def test_sizing_by_examples_drowns_the_task(self):
        """The bug itself, pinned: 25% of the examples is 51% of the objective.

        79% of the supervised tokens, and 51% of the objective once per-batch
        normalisation has had its say. Either number makes the same point.
        """
        by_examples = int(len(self.TRAJ) * 0.25)           # the old rule
        share = replay_share(self.TRAJ, by_examples, self.WINDOW, **self.KW)
        assert share > 0.45, (
            "a replay window supervises 1,023 targets where a trajectory "
            "supervises 69, so counting examples gets the mixture wrong by an "
            "order of magnitude — and the log printed '(25%)'")

    def test_sizing_by_supervised_tokens_starves_it_instead(self):
        """The obvious correction, pinned too: it misses the other way.

        Per-batch normalisation caps what any one batch contributes, so windows
        that are 25% of the corpus's supervised tokens land in a handful of
        batches and carry far less than 25% of the objective.
        """
        by_tokens = round(0.25 / 0.75 * self.TRAJ.sum() / self.WINDOW)
        share = replay_share(self.TRAJ, by_tokens, self.WINDOW, **self.KW)
        assert share < 0.12

    def test_size_replay_hits_what_was_asked_for(self):
        for fraction in (0.1, 0.25, 0.5):
            n = size_replay(self.TRAJ, fraction, self.WINDOW, **self.KW)
            realised = replay_share(self.TRAJ, n, self.WINDOW, **self.KW)
            assert abs(realised - fraction) < 0.02, (
                f"asked {fraction:.0%}, sized {n} windows, realised "
                f"{realised:.1%}")

    def test_the_realised_share_is_the_run_that_will_happen(self):
        """Same seed, same batches: the printed number is not an estimate."""
        a = replay_share(self.TRAJ, 40, self.WINDOW, **self.KW)
        b = replay_share(self.TRAJ, 40, self.WINDOW, **self.KW)
        assert a == b
        other = replay_share(self.TRAJ, 40, self.WINDOW, batch_size=4,
                             epochs=3, seed=7)
        assert other != a, "a different seed deals different batches"

    def test_no_replay_asked_for_is_no_windows(self):
        assert size_replay(self.TRAJ, 0.0, self.WINDOW, **self.KW) == 0
        assert replay_share(self.TRAJ, 0, self.WINDOW, **self.KW) == 0.0

    @pytest.mark.parametrize("fraction", [1.0, 1.5, -0.1])
    def test_a_fraction_outside_the_unit_interval_is_refused(self, fraction):
        with pytest.raises(ValueError, match=r"\[0, 1\)"):
            size_replay(self.TRAJ, fraction, self.WINDOW, **self.KW)
