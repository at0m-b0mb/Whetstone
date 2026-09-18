"""Tests for the scoring pass behind constrained decoding.

What is asserted here is that the ranking numbers are the log-probabilities they
claim to be, and that producing them costs what the candidates cost rather than
what the transcript costs. The second half is a memory property, which is an
odd thing to put in a test suite until you notice that the decoder runs on the
same laptop as the training run: a scoring pass that allocates in proportion to
the episode-so-far gets slower every turn and then fails on the turn that
matters, and nothing about the output says why.

The model is a stub whose next-token distribution is a fixed table indexed by
the input id. A real checkpoint would test the checkpoint; a table means the
expected score can be worked out position by position, independently of the
batching the module under test does.
"""

from __future__ import annotations

import pytest

pytest.importorskip("mlx.core")
pytest.importorskip("tokenizers")

import mlx.core as mx  # noqa: E402

from training.constrained import score_continuations  # noqa: E402

VOCAB = 512


class _StubModel:
    """Logits for position p are row ``ids[p]`` of a fixed table."""

    def __init__(self, seed: int = 0) -> None:
        mx.random.seed(seed)
        self.table = mx.random.normal((VOCAB, VOCAB))

    def __call__(self, ids, cache=None):
        return self.table[ids], None


@pytest.fixture()
def tok():
    """Byte-level, no merges: one token per character, so rows are countable."""
    from tokenizers import Tokenizer, models, pre_tokenizers

    alphabet = sorted(pre_tokenizers.ByteLevel.alphabet())
    t = Tokenizer(models.BPE(vocab={c: i for i, c in enumerate(alphabet)},
                             merges=[]))
    t.pre_tokenizer = pre_tokenizers.ByteLevel(add_prefix_space=False,
                                               use_regex=False)
    t.add_special_tokens(["<|pad|>"])
    return t


@pytest.fixture()
def model():
    return _StubModel()


def _by_hand(model, tok, prompt: str, candidate: str) -> float:
    """The same quantity, computed one position at a time.

    Deliberately not the batched form: a candidate token at ``start + j`` is
    predicted from the position before it, and this walks that definition
    rather than reproducing the module's own slicing.
    """
    row = tok.encode(prompt).ids + tok.encode(candidate).ids
    start = len(tok.encode(prompt).ids)
    total = 0.0
    for j in range(len(row) - start):
        logits = model.table[row[start + j - 1]]
        logprobs = logits - mx.logsumexp(logits)
        total += float(logprobs[row[start + j]].item())
    return total


def _normalise_the_whole_pass(model, tok, prompt, candidates):
    """The shape this module replaced, kept so the test can show the cost.

    Two full-vocabulary float32 arrays the size of the entire padded batch, so
    that a few dozen numbers can be read out of the candidate positions.
    """
    prompt_ids = tok.encode(prompt).ids
    rows, spans = [], []
    for cand in candidates:
        cand_ids = tok.encode(cand).ids
        rows.append(prompt_ids + cand_ids)
        spans.append(len(cand_ids))
    width = max(len(r) for r in rows)
    pad_id = tok.token_to_id("<|pad|>") or 0
    batch = mx.array([r + [pad_id] * (width - len(r)) for r in rows])
    logits, _ = model(batch[:, :-1])
    logprobs = logits.astype(mx.float32) - mx.logsumexp(
        logits.astype(mx.float32), axis=-1, keepdims=True)
    mx.eval(logprobs)
    out = []
    start = len(prompt_ids)
    for i, span in enumerate(spans):
        total = 0.0
        for j in range(span):
            token = int(batch[i, start + j].item())
            total += float(logprobs[i, start + j - 1, token].item())
        out.append(total)
    return out


class TestScores:
    def test_a_candidate_scores_its_own_log_probability(self, model, tok):
        prompt = "<|pad|>the host answers "
        candidates = ['{"verb":"enum.persistence"', '{"verb":"detect.telemetry"']
        got = score_continuations(model, tok, prompt, candidates)
        for score, cand in zip(got, candidates):
            assert score == pytest.approx(_by_hand(model, tok, prompt, cand),
                                          abs=1e-4)

    def test_candidates_of_different_lengths_stop_at_their_own_ends(
            self, model, tok):
        """The batch is scored to the longest candidate; the overhang is padding.

        Summing it would charge the short candidates for tokens they do not
        have, which is a length bias invented by the batching rather than
        believed by the model.
        """
        prompt = "<|pad|>the host answers "
        candidates = ["a", "ab", "abcdefghijklmnop"]
        got = score_continuations(model, tok, prompt, candidates)
        for score, cand in zip(got, candidates):
            assert score == pytest.approx(_by_hand(model, tok, prompt, cand),
                                          abs=1e-4)

    def test_length_normalise_divides_by_the_span(self, model, tok):
        prompt = "<|pad|>the host answers "
        candidates = ["a", "abcd"]
        plain = score_continuations(model, tok, prompt, candidates)
        divided = score_continuations(model, tok, prompt, candidates,
                                      length_normalise=True)
        assert divided[0] == pytest.approx(plain[0], abs=1e-4)
        assert divided[1] == pytest.approx(plain[1] / 4, abs=1e-4)

    def test_no_candidates_is_no_scores(self, model, tok):
        assert score_continuations(model, tok, "a prompt", []) == []

    def test_a_candidate_that_tokenises_to_nothing_is_refused(self, model, tok):
        """Because the empty sum is 0.0, and every real score is negative.

        Scored rather than refused, a candidate nobody can score sorts above
        every candidate that can be — it wins the ranking by having no evidence
        for it at all.
        """
        with pytest.raises(ValueError, match="no tokens"):
            score_continuations(model, tok, "<|pad|>a prompt", ["", "abc"])

    def test_an_empty_prompt_is_refused(self, model, tok):
        """Rather than scored from position -1, which is the last row position.

        MLX wraps a negative index, so the old form returned a number — a
        confident one, computed from the wrong end of the sequence — for a call
        that has no defined answer.
        """
        with pytest.raises(ValueError, match="non-empty prompt"):
            score_continuations(model, tok, "", ['{"verb":"enum.persistence"'])


class TestCost:
    """The allocation must follow the candidates, not the transcript."""

    PROMPT = "the quick brown fox jumps over the lazy dog " * 28   # ~1.2k tokens
    CANDIDATES = [f'{{"verb":"enum.{i:02d}"' for i in range(12)]

    def _peak(self, fn, model, tok) -> int:
        mx.eval(model.table)
        mx.reset_peak_memory()
        fn(model, tok, self.PROMPT, self.CANDIDATES)
        return mx.get_peak_memory()

    def test_only_the_candidate_positions_are_normalised(self, model, tok):
        whole = self._peak(_normalise_the_whole_pass, model, tok)
        sliced = self._peak(score_continuations, model, tok)
        assert sliced * 1.5 < whole, (
            f"normalising every prompt position cost {whole/1e6:.0f} MB and "
            f"slicing first cost {sliced/1e6:.0f} MB, on a 1.2k-token prompt "
            "with a 512 vocabulary. The production numbers are a 1,700-token "
            "prompt and a 16,384 vocabulary, where the arrays being avoided "
            "are 3 GB each")

    def test_the_two_shapes_agree_on_every_score(self, model, tok):
        whole = _normalise_the_whole_pass(model, tok, self.PROMPT, self.CANDIDATES)
        sliced = score_continuations(model, tok, self.PROMPT, self.CANDIDATES)
        assert sliced == pytest.approx(whole, abs=1e-3), (
            "slicing before the softmax is exact, not an approximation: a "
            "softmax is per position over the vocabulary axis, so dropping "
            "positions cannot change the ones that are kept")
