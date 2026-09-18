"""Tests for the tokenizer's train/holdout split.

The split is the only thing standing between "+29% against gpt2 on held-out
text" and "+29% against gpt2 on its own training text", and the difference is
invisible in the output: both print a table. So the properties pinned here are
that a document's side does not move when the corpus around it changes, and
that a measurement which cannot prove it was held out refuses to print a number
at all.

``tokenizers`` lives in the ``[train]`` extra rather than ``[dev]``, because the
runtime has to stay installable on a machine that will never train anything — so
CI has no wheel for it and these skip there instead of failing. The split logic
itself is plain Python and would run anywhere; it is behind the skip only
because ``train_tokenizer`` imports ``tokenizers`` at module level.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("tokenizers")

from training.tokenizer import train_tokenizer as tt


def _corpus(directory: Path, texts: list[str], *, name: str = "a") -> Path:
    """Write ``texts`` as a built corpus directory, in build.py's own schema."""
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{name}.jsonl").write_text(
        "\n".join(json.dumps({"text": t, "source": name, "register": "prose",
                              "side": "neutral", "ident": str(i)})
                  for i, t in enumerate(texts)) + "\n",
        encoding="utf-8")
    return directory


class TestHoldoutSurvivesARebuild:
    """A document's side of the split must not move when its neighbours do.

    The rule was ``i % HOLDOUT_EVERY == 0`` over ``read_documents``, and ``i``
    counts every document preceding this one across the sorted ``*.jsonl``. So
    inserting, dropping or reordering one document anywhere shifted every index
    after it and rotated the partition: a tenth of the corpus swapped sides for
    a single insertion, and every one of those swaps moves a document the
    tokenizer was trained on into the "held-out" set.

    That is not hypothetical here. tokenizer-v5's meta.json records 115,849
    training documents against a clean/ directory that now holds 46,835 — the
    corpus was rebuilt underneath it, so ``--compare --clean`` against that
    tokenizer had no holdout in it at all, and the number it produced is the one
    the whole from-scratch case rests on.
    """

    def _sides(self, clean: Path) -> dict[str, bool]:
        held = {t for _r, t in tt.iter_split(clean, holdout=True)}
        trained = {t for _r, t in tt.iter_split(clean, holdout=False)}
        assert held, "nothing was held out at all"
        assert trained, "nothing was left to train on"
        assert not held & trained, "a document is on both sides of the split"
        return {**{t: True for t in held}, **{t: False for t in trained}}

    def test_inserting_one_document_does_not_move_the_others(self, tmp_path):
        texts = [f"document number {i}, long enough to be a real corpus row"
                 for i in range(200)]
        before = self._sides(_corpus(tmp_path / "v1", texts))
        after = self._sides(_corpus(tmp_path / "v2", ["a brand new first row"] + texts))

        moved = [t for t in texts if before[t] != after[t]]
        assert not moved, f"{len(moved)} of {len(texts)} documents changed sides"

    def test_reordering_the_corpus_does_not_move_anything(self, tmp_path):
        """Two sources' files sort by name, so adding one reorders the rest."""
        texts = [f"row {i} of a corpus that is about to be rebuilt" for i in range(200)]
        before = self._sides(_corpus(tmp_path / "v1", texts, name="zzz"))
        after = self._sides(_corpus(tmp_path / "v2", list(reversed(texts)), name="aaa"))
        assert all(before[t] == after[t] for t in texts)

    def test_it_still_holds_out_about_the_advertised_fraction(self, tmp_path):
        """A stable split is no use if it stops partitioning at the stated rate."""
        texts = [f"row {i}: " + "x" * (i % 7) + " some corpus text here"
                 for i in range(2000)]
        clean = _corpus(tmp_path / "c", texts)
        held = list(tt.iter_split(clean, holdout=True))
        assert 0.03 < len(held) / len(texts) < 0.08, len(held)


class TestCompareRefusesAnUnprovableHoldout:
    """No record of how the split was drawn means no measurement.

    The number ``compare_on_corpus`` prints feeds the decision gate at the
    bottom of it — below ~15% a general-purpose tokenizer is the better answer
    and the from-scratch case weakens. A figure that has quietly stopped being
    held out does not read as broken, it reads as a win, so this refuses rather
    than reports. Both refusals happen before gpt2 is even fetched, which is
    also why these tests need no network and no tokenizer object.
    """

    def test_a_tokenizer_with_no_holdout_record_is_refused(self, tmp_path):
        """Every tokenizer fitted before the split was keyed on content.

        Their meta.json records `holdout_every` and nothing about the rule, and
        the rule they were fitted under moves with every rebuild — so there is
        no way to say which documents they trained on.
        """
        clean = _corpus(tmp_path / "c", ["some corpus text " * 5])
        with pytest.raises(SystemExit, match="no holdout rule"):
            tt.compare_on_corpus(None, clean, meta={"vocab_size": 16384})

    def test_a_tokenizer_fitted_under_a_different_rule_is_refused(self, tmp_path):
        clean = _corpus(tmp_path / "c", ["some corpus text " * 5])
        with pytest.raises(SystemExit, match="do not agree"):
            tt.compare_on_corpus(
                None, clean, meta={"holdout": {"scheme": "position", "every": 20}})

    def test_a_different_holdout_rate_is_refused_too(self, tmp_path):
        """Same rule, different N, is still a different partition."""
        clean = _corpus(tmp_path / "c", ["some corpus text " * 5])
        with pytest.raises(SystemExit, match="do not agree"):
            tt.compare_on_corpus(
                None, clean,
                meta={"holdout": {"scheme": tt.HOLDOUT_SCHEME, "every": 5}})


class TestCorpusIdentity:
    """Naming the corpus a tokenizer was fitted to, for the price of a stat().

    A drifted corpus is not a leak once the split is keyed on content — a
    document that was trained on stays trained on — but the register mix being
    measured is no longer the mix the tokenizer was fitted to, and the
    per-register rows have to be read that way. Recording it is what makes that
    statable at all.
    """

    def test_it_changes_when_a_source_file_changes(self, tmp_path):
        a = _corpus(tmp_path / "a", ["one row of corpus text"])
        first = tt.corpus_identity(a)
        assert tt.corpus_identity(a) == first, "not stable across two reads"
        _corpus(tmp_path / "a", ["one row of corpus text", "and a second one"])
        assert tt.corpus_identity(a) != first

    def test_it_ignores_everything_that_is_not_a_source_file(self, tmp_path):
        a = _corpus(tmp_path / "a", ["one row of corpus text"])
        first = tt.corpus_identity(a)
        (a / "PROVENANCE.md").write_text("# rewritten every build\n", encoding="utf-8")
        assert tt.corpus_identity(a) == first
