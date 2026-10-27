"""Tests for the coverage scanner — the ruler, not the thing it measures.

:mod:`training.corpus.coverage` is the instrument that turns 580 MB of corpus
into a sentence like "41 strong, 76 thin, 23 absent". Every bug it can have
produces a plausible number, which is the whole problem: this project has three
recorded measurement bugs that each accused the model and were all in the
ruler, and one of them was a verifier reporting a 625 MB corpus clean at
128,124 MB/s having read zero bytes.

So the properties pinned here are the ones whose failure would be invisible in
a report:

**The prefilter cannot lose a match.** The scanner does not run 1,071 patterns
over every document — the obvious implementation measured 0.46 MB/s and 21
minutes for one generation. It takes the set of a document's lowercase word
runs, looks up candidate terms by their rarest word, and only then runs the
real pattern. That is sound only if "every word of the term appears in the
document" is a *necessary* condition for the term to match, and only if the
optional plural in :func:`curriculum.term_pattern` is probed for too.
:class:`TestPrefilterIsLossless` runs the slow reference implementation — every
term, ``IGNORECASE``, against the original text — over documents built to
attack exactly those two assumptions, and requires identical answers.

**The scanner bites.** :class:`TestSelfTest` runs the planted-document check:
documents written from the field's own vocabulary, each about a known topic,
must be attributed to that topic, and two decoys about tape archives and mail
headers must be attributed to nothing. A scanner that found neither and a
scanner that found everything both report a number.

**The controls are real controls.** :data:`coverage.CONTROL_ABSENT` must be
unmatchable and :data:`coverage.CONTROL_PRESENT` must be matchable;
:class:`TestControls` proves each by construction, because a control that
cannot fail is decoration.

**Verdicts come from declared thresholds.** :class:`TestClassify` pins the
boundaries and the orthogonal flags, so that a later edit that moves
``FAIR_SHARE_DOCS`` to make a report look better has to move the test and the
``COVERAGE_VERSION`` with it.

**The gold label is independent.** Recall is scored against ATT&CK technique
documents matched by their own ``ATT&CK ID:`` line. That is only an independent
label if no curriculum term is itself an ATT&CK id, so
:class:`TestGoldIsIndependent` checks that rather than trusting it.

Nothing here reads the SSD, the network or any corpus generation. Every test
builds its own documents in a temporary directory.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from training.corpus import curriculum as C
from training.corpus.coverage import (
    CONTROL_ABSENT,
    CONTROL_PRESENT,
    COVERAGE_VERSION,
    FAIR_SHARE_DOCS,
    MAX_PLAUSIBLE_MBPS,
    SINGLE_SOURCE_AT,
    VERDICTS,
    Matcher,
    _probe_forms,
    attack_inventory,
    classify,
    register_rulers,
    sample_word_df,
    scan_generation,
    self_test,
)


@pytest.fixture(scope="module")
def matcher() -> Matcher:
    return Matcher(word_df={})


def _write(root: Path, source: str, docs: list[dict]) -> None:
    (root / f"{source}.jsonl").write_text(
        "\n".join(json.dumps(d) for d in docs) + "\n", encoding="utf-8"
    )


def _doc(text: str, source: str, register: str = "prose") -> dict:
    return {
        "text": text,
        "source": source,
        "register": register,
        "side": "red",
        "ident": "test",
    }


class TestPrefilterIsLossless:
    """The fast path must agree with the slow one on every term, always."""

    @staticmethod
    def _reference(text: str) -> set[str]:
        """Every term, compiled as the curriculum compiles it, over the text."""
        return {
            t for t in C.all_terms() if C.term_pattern(t).search(text) is not None
        }

    def test_agrees_on_adversarial_documents(self, matcher: Matcher) -> None:
        # Each of these is written to break one assumption the prefilter makes:
        # case, a line-wrapped phrase, an optional plural, punctuation-only
        # terms, and a term appearing only as part of a longer word.
        docs = [
            "KERBEROAST and RUBEUS in shouting caps, plus GetUserSPNs.",
            "resource-based constrained\n delegation wrapped across a newline",
            "The yara rules fired. Sigma rules did not. Atomic tests ran.",
            "A payload with ../../ and $where and <script>alert(1)</script>.",
            "unquoted service path, SeImpersonatePrivilege, and dcsync",
            "nothing here but bread, a garden and a stylesheet changelog",
            "logsource: product: windows\ncondition: selection\nfalsepositives:",
            "T1003.001 LSASS Memory and CWE-89 and CVE-2024-21412",
            "kerberoasting is not kerberoast and roastingkerberos is neither",
        ]
        for text in docs:
            fast = set(matcher.hits(text))
            slow = self._reference(text)
            assert fast == slow, (
                f"prefilter disagrees on {text[:40]!r}: "
                f"missed {sorted(slow - fast)}, invented {sorted(fast - slow)}"
            )

    def test_every_term_survives_its_own_sentence(self, matcher: Matcher) -> None:
        """Plant each term and require the prefilter to admit it.

        This is the loss the prefilter could silently take: a probe word chosen
        wrongly makes the term unfindable and the topic reads as a data gap
        forever. 1,071 terms, one sentence each.
        """
        missed = []
        for term in C.all_terms():
            text = f"Context before. {term} and then context after."
            if term not in matcher.hits(text):
                missed.append(term)
        assert not missed, f"prefilter cannot find its own terms: {missed[:10]}"

    def test_plural_probe_is_present_where_the_pattern_allows_one(self) -> None:
        # A single-word term ending in a non-s letter: the pattern accepts the
        # plural, the probe word IS the last word, so both forms must be
        # probed or every plural mention is lost silently.
        assert _probe_forms("rootkit", {"rootkit": 5}) == ("rootkit", "rootkits")
        # A phrase whose rare word is not the last needs no plural probe.
        assert _probe_forms("sigma rule", {"sigma": 1, "rule": 10_000}) == (
            "sigma",
        )
        # ... and when the last word is the rare one, it gets both forms.
        assert _probe_forms("sigma rule", {"sigma": 10_000, "rule": 1}) == (
            "rule",
            "rules",
        )
        # A term already ending in "s" gets no plural form, because
        # term_pattern does not add one.
        assert _probe_forms("credentials", {"credentials": 5}) == ("credentials",)

    def test_matcher_finds_plurals_end_to_end(self, matcher: Matcher) -> None:
        assert "sigma rule" in matcher.hits("The sigma rules are in the repo.")
        assert "rules of engagement" in matcher.hits(
            "Check the rules of engagement first."
        )


class TestTermsAreLowercaseAscii:
    """The equivalence the fast path rests on, stated as a property.

    Dropping ``IGNORECASE`` and matching a lowercased copy of the document is
    only equivalent if every term is already lowercase ASCII. If a term with an
    uppercase letter is ever added, this fails here rather than silently
    scoring that term at zero in every report.
    """

    def test_all_terms_lowercase_ascii(self) -> None:
        bad = [t for t in C.all_terms() if t != t.lower() or not t.isascii()]
        assert not bad, bad


class TestGoldIsIndependent:
    """Recall is scored on a label the matcher cannot see."""

    def test_no_term_is_an_attack_or_atlas_id(self) -> None:
        ids = [
            t
            for t in C.all_terms()
            if C.ATTACK_ID_RE.match(t.upper()) or C.ATLAS_ID_RE.match(t.upper())
        ]
        assert not ids, (
            "a term that is an ATT&CK id makes the gold recall circular: "
            f"{ids}"
        )

    def test_no_term_contains_a_technique_id(self) -> None:
        ids = [t for t in C.all_terms() if re.search(r"t\d{4}", t)]
        assert not ids, ids


class TestControls:
    """A control that cannot fail is decoration."""

    def test_absent_controls_are_unmatchable_in_plausible_text(
        self, matcher: Matcher
    ) -> None:
        text = (
            "The operator escalated privilege, dumped credentials and left a "
            "beacon. Standard tradecraft, nothing exotic."
        )
        hits = matcher.controls(text)
        assert not [t for t in CONTROL_ABSENT if t in hits]

    def test_absent_controls_do_fire_when_planted(self, matcher: Matcher) -> None:
        for term in CONTROL_ABSENT:
            assert term in matcher.controls(f"a {term} was observed")

    def test_present_controls_fire(self, matcher: Matcher) -> None:
        for term, floor in CONTROL_PRESENT:
            assert floor > 0
            assert term in matcher.controls(f"... {term} ...")

    def test_absent_controls_are_not_curriculum_terms(self) -> None:
        overlap = set(CONTROL_ABSENT) & set(C.all_terms())
        assert not overlap, overlap


class TestClassify:
    """Thresholds are declared, not fitted. Changing one changes this test."""

    def test_boundaries(self) -> None:
        src = {"a": 10, "b": 10, "c": 10}
        terms = {"x": 10, "y": 10}
        assert classify(0, {}, {}, 0)[0] == "absent"
        assert classify(1, src, terms, 1)[0] == "trace"
        assert classify(49, src, terms, 40)[0] == "trace"
        assert classify(50, src, terms, 40)[0] == "thin"
        assert classify(FAIR_SHARE_DOCS - 1, src, terms, 900)[0] == "thin"
        # Three sources and two terms clears the count but not the quality
        # condition, so it is "covered" and not "strong".
        assert classify(FAIR_SHARE_DOCS, src, terms, 900)[0] == "covered"

    def test_strong_is_a_quality_condition_not_a_bigger_number(self) -> None:
        """Ten times fair share is unreachable by construction, so it is not
        the top band: the curriculum rejects terms above ~4.2% document
        frequency, which caps any topic near 8,800 of 208,346 documents.
        """
        wide = {f"s{i}": 300 for i in range(6)}
        many = {"x": 100, "y": 90, "z": 80}
        assert classify(1800, wide, many, 1500)[0] == "strong"
        # One source short.
        narrow = {f"s{i}": 450 for i in range(4)}
        assert classify(1800, narrow, many, 1500)[0] == "covered"
        # One term short.
        assert classify(1800, wide, {"x": 100, "y": 90}, 1500)[0] == "covered"
        # Mostly name-drops.
        assert classify(1800, wide, many, 100)[0] == "covered"

    def test_fragile_flag_is_orthogonal_to_the_count(self) -> None:
        verdict, flags = classify(
            10_000, {"sigma": 9_900, "other": 100}, {"x": 10, "y": 3}, 9_000
        )
        # Big, and a statement about one adapter: the count says covered, the
        # flag says why it is not strong.
        assert verdict == "covered"
        assert "fragile" in flags

    def test_single_source_threshold(self) -> None:
        n = 1000
        at = int(n * SINGLE_SOURCE_AT)
        assert "fragile" in classify(n, {"a": at, "b": n - at}, {"x": 1}, 900)[1]
        assert "fragile" not in classify(
            n, {"a": at - 1, "b": n - at + 1}, {"x": 1}, 900
        )[1]

    def test_name_drop_flag(self) -> None:
        _v, flags = classify(1000, {"a": 500, "b": 500}, {"x": 1, "y": 1}, 10)
        assert "name-drop" in flags
        _v, flags = classify(1000, {"a": 500, "b": 500}, {"x": 1, "y": 1}, 900)
        assert "name-drop" not in flags

    def test_verdicts_are_the_declared_set(self) -> None:
        src, terms = {"a": 1}, {"x": 1}
        for n in (0, 1, 60, 2000, 50_000):
            assert classify(n, src, terms, n // 2)[0] in VERDICTS


class TestSelfTest:
    """The planted-needle check, which is the whole licence to report numbers."""

    def test_self_test_passes(self) -> None:
        out = self_test()
        assert out["pass"], out
        assert out["planted_found"] == out["planted_topics"]
        assert out["decoys_silent"], out["decoy_matches"]
        assert out["controls_absent_hits"] == 0

    def test_self_test_notices_a_blind_scanner(self, monkeypatch) -> None:
        """A scanner that matches nothing must fail the self test.

        The failure mode this guards is the one that actually happened in
        ``verify``: an instrument that reports a clean, plausible, *empty*
        result. Patching the matcher to find nothing has to turn the self test
        red, or the self test is not checking anything.
        """
        monkeypatch.setattr(Matcher, "hits", lambda self, text: {})
        out = self_test()
        assert not out["pass"]
        assert out["planted_found"] == 0


class TestScan:
    """End to end over a synthetic generation, single process."""

    @pytest.fixture
    def generation(self, tmp_path: Path) -> Path:
        root = tmp_path / "clean-test"
        root.mkdir()
        _write(
            root,
            "sigma",
            [
                _doc(
                    "logsource: product: windows\ncondition: selection\n"
                    "falsepositives: admin",
                    "sigma",
                    "detection",
                )
                for _ in range(12)
            ],
        )
        _write(
            root,
            "attack",
            [
                _doc(
                    "T1558.003 Kerberoasting\n\nATT&CK ID: T1558.003\n"
                    "Matrix: Enterprise ATT&CK\nType: Technique\n\n"
                    "Adversaries request a service ticket and crack it. "
                    "A kerberoast needs a service principal name.",
                    "attack",
                    "adversary",
                ),
                _doc(
                    "T1055 Process Injection\n\nATT&CK ID: T1055\n"
                    "Matrix: Enterprise ATT&CK\nType: Technique\n\n"
                    "Adversaries inject code into a live process.",
                    "attack",
                    "adversary",
                ),
                _doc(
                    "M1026 Privileged Account Management\n\n"
                    "ATT&CK ID: M1026\nMatrix: Enterprise ATT&CK\n"
                    "Type: Mitigation\n\nManage privileged accounts.",
                    "attack",
                    "adversary",
                ),
            ],
        )
        _write(
            root,
            "manpages",
            [
                _doc("tar - manipulate tape archives", "manpages", "system")
                for _ in range(5)
            ],
        )
        return root

    def test_scan_counts_and_attributes(self, generation: Path) -> None:
        report = scan_generation(generation, workers=1, df_sample=50)
        assert report.docs == 20
        assert report.chars > 0
        assert report.files == 3
        sigma = next(t for t in report.topics if t.topic_id == "detect.sigma-rules")
        assert sigma.docs == 12
        assert sigma.sources == {"sigma": 12}
        assert sigma.registers == {"detection": 12}
        assert "fragile" in sigma.flags
        assert report.by_register["detection"]["docs"] == 12
        assert report.source_registers["manpages"] == {
            "system": report.by_source["manpages"]["chars"]
        }

    def test_ruler_is_named_and_is_characters(self, generation: Path) -> None:
        report = scan_generation(generation, workers=1, df_sample=50)
        assert report.ruler == "characters"
        payload = report.to_json()
        assert payload["ruler"] == "characters"
        assert payload["registers"]["ruler"] == "characters"

    def test_gold_recall_scores_the_claiming_topic(self, generation: Path) -> None:
        report = scan_generation(generation, workers=1, df_sample=50)
        gold = report.gold_recall()
        # T1558.003 is claimed by a topic whose vocabulary is in that document;
        # T1055 is claimed by topics whose vocabulary is deliberately not.
        assert gold["documents"] >= 2
        assert 0 < gold["found"] <= gold["documents"]
        kerb = next(t for t in report.topics if t.topic_id == "winad.kerberoasting")
        assert kerb.gold_total == 1 and kerb.gold_hit == 1

    def test_mitigation_documents_are_not_scored_as_gold(
        self, generation: Path
    ) -> None:
        """Only Technique documents carry a technique id of their own.

        Scoring a mitigation page as a gold technique document would credit or
        blame a topic for a document that is not about one technique, and the
        ATT&CK corpus has 108 of them.
        """
        report = scan_generation(generation, workers=1, df_sample=50)
        assert report.attack is not None
        assert report.attack.by_type.get("Mitigation") == 1
        assert sum(t.gold_total for t in report.topics) <= 2 * len(
            [t for t in report.topics if t.gold_total]
        )

    def test_partial_scan_says_so(self, generation: Path) -> None:
        report = scan_generation(generation, workers=1, limit=2, df_sample=50)
        assert any("PARTIAL SCAN" in n for n in report.notes)
        assert report.docs == 6

    def test_blind_spot_is_counted(self, generation: Path) -> None:
        report = scan_generation(generation, workers=1, df_sample=50)
        # The five tar man pages match no topic in the taxonomy.
        assert report.unseen_docs >= 5
        assert report.topics_per_doc["0"] >= 5

    def test_blind_spot_is_attributed_to_a_source(self, generation: Path) -> None:
        """Half a corpus matching no topic is a mood; naming the sources is a
        decision. The man pages are the whole blind spot in this fixture.
        """
        report = scan_generation(generation, workers=1, df_sample=50)
        assert report.unseen_by_source["manpages"]["docs"] == 5
        assert report.unseen_by_source["manpages"]["share_of_source"] == 1.0
        assert "sigma" not in report.unseen_by_source
        payload = report.to_json()
        assert payload["taxonomy_blind_spot"]["by_source"]["manpages"]["docs"] == 5

    def test_throughput_ceiling_is_an_instrument_check(
        self, generation: Path
    ) -> None:
        report = scan_generation(generation, workers=1, df_sample=50)
        assert MAX_PLAUSIBLE_MBPS > 0
        # A real scan of a tiny generation is slow in MB/s, not fast; what is
        # pinned here is that the check exists and is reported.
        assert "mb_per_s" in report.instrument
        assert report.instrument["max_plausible_mbps"] == MAX_PLAUSIBLE_MBPS

    def test_samples_carry_no_text(self, generation: Path) -> None:
        report = scan_generation(generation, workers=1, sample_size=10, df_sample=50)
        assert report.samples
        allowed = {
            "topic", "source", "file", "line", "terms", "id", "occurrences",
            "corroborated",
        }
        for item in report.samples:
            assert set(item) <= allowed
            assert "text" not in item

    def test_sample_ids_are_content_addressed(self, generation: Path) -> None:
        """A verdict is a judgement about a document, not about a draw order.

        Two scans of the same generation returned the same counts and a
        different order, so positional ids moved 31 of 80 hand verdicts onto
        other documents. Hashing the coordinates is what stops that.
        """
        from training.corpus.coverage import sample_id

        a = scan_generation(generation, workers=1, sample_size=10, df_sample=50)
        b = scan_generation(generation, workers=1, sample_size=10, df_sample=50)
        ids_a = {s["id"]: (s["topic"], s["file"], s["line"]) for s in a.samples}
        ids_b = {s["id"]: (s["topic"], s["file"], s["line"]) for s in b.samples}
        assert ids_a == ids_b
        for sid, (topic, fname, line) in ids_a.items():
            assert sid == sample_id(topic, fname, line)

    def test_report_json_round_trips(self, generation: Path) -> None:
        report = scan_generation(generation, workers=1, df_sample=50)
        payload = report.to_json()
        assert json.loads(json.dumps(payload))["coverage_version"] == (
            COVERAGE_VERSION
        )
        assert payload["curriculum_version"] == C.CURRICULUM_VERSION
        assert sum(payload["distribution"].values()) == len(C.TOPICS)

    def test_empty_directory_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            scan_generation(tmp_path, workers=1)


class TestAttackInventory:
    """The ATT&CK object graph, counted by type and by matrix."""

    def test_counts_types_matrices_and_distinct_ids(self, tmp_path: Path) -> None:
        root = tmp_path / "gen"
        root.mkdir()
        _write(
            root,
            "attack",
            [
                _doc(
                    f"ATT&CK ID: T{1000+i}\nMatrix: Enterprise ATT&CK\n"
                    f"Type: Technique\n\nbody",
                    "attack",
                    "adversary",
                )
                for i in range(3)
            ]
            + [
                _doc(
                    "ATT&CK ID: T0800\nMatrix: ICS ATT&CK\nType: Technique\n\nb",
                    "attack",
                    "adversary",
                ),
                _doc(
                    "ATT&CK ID: M1026\nMatrix: Enterprise ATT&CK\n"
                    "Type: Mitigation\n\nb",
                    "attack",
                    "adversary",
                ),
            ],
        )
        _write(
            root,
            "attackactors",
            [
                _doc(
                    "ATT&CK ID: G0007\nMatrix: Enterprise ATT&CK\n"
                    "Type: Threat group\n\nUses T1055 and T1003.001.",
                    "attackactors",
                    "adversary",
                )
            ],
        )
        inv = attack_inventory(root)
        assert inv.by_type == {"Technique": 4, "Mitigation": 1, "Threat group": 1}
        assert inv.by_matrix["ICS ATT&CK"] == 1
        assert inv.distinct_ids["Technique"] == 4
        assert inv.distinct_ids["Threat group"] == 1
        # T1000..T1002, T0800, and the two ids quoted inside the group page.
        assert inv.technique_ids_total == 6
        assert inv.technique_docs_by_source["attackactors"] == 1

    def test_missing_source_is_not_an_error(self, tmp_path: Path) -> None:
        inv = attack_inventory(tmp_path)
        assert inv.docs == 0 and inv.by_type == {}


class TestRegisterRulers:
    """Two rulers, reported side by side, never averaged."""

    def test_character_shares_sum_to_one(self) -> None:
        by_register = {
            "shell": {"docs": 10, "chars": 800},
            "system": {"docs": 10, "chars": 3600},
            "trajectory": {"docs": 10, "chars": 780},
        }
        out = register_rulers(by_register)
        assert out["ruler"] == "characters"
        total = sum(v["char_share"] for v in out["registers"].values())
        assert abs(total - 1.0) < 1e-6
        assert out["registers"]["shell"]["target"] == 0.26

    def test_token_ruler_can_disagree_with_the_character_ruler(self) -> None:
        """The disagreement is the point, so it has to be representable.

        Two sources with equal characters and very different tokens-per-
        character — which is what a BPE does to repetitive generated text
        against dense shell text — must come out with different shares under
        the two rulers. A function that could not show that would be hiding
        the thing the report exists to settle.
        """
        by_register = {
            "shell": {"docs": 10, "chars": 1000},
            "trajectory": {"docs": 10, "chars": 1000},
        }
        source_registers = {
            "shellscripts": {"shell": 1000},
            "trajectories": {"trajectory": 1000},
        }
        index = {
            "by_source": {"shellscripts": 400, "trajectories": 100},
            "total_tokens": 500,
            "documents": 20,
        }
        out = register_rulers(by_register, index, source_registers)
        assert out["registers"]["shell"]["char_share"] == 0.5
        assert out["registers"]["trajectory"]["char_share"] == 0.5
        assert out["registers"]["shell"]["token_share"] == 0.8
        assert out["registers"]["trajectory"]["token_share"] == 0.2

    def test_sources_missing_from_the_token_index_are_named(self) -> None:
        out = register_rulers(
            {"shell": {"docs": 1, "chars": 10}},
            {"by_source": {}, "total_tokens": 0},
            {"shellscripts": {"shell": 10}},
        )
        assert out["token_ruler"]["sources_missing_from_index"] == ["shellscripts"]

    def test_multi_register_source_splits_by_characters(self) -> None:
        out = register_rulers(
            {"shell": {"docs": 1, "chars": 75}, "prose": {"docs": 1, "chars": 25}},
            {"by_source": {"mixed": 1000}, "total_tokens": 1000},
            {"mixed": {"shell": 75, "prose": 25}},
        )
        assert out["registers"]["shell"]["tokens"] == 750
        assert out["registers"]["prose"]["tokens"] == 250


class TestWordDf:
    def test_sample_is_deterministic_and_bounded(self, tmp_path: Path) -> None:
        root = tmp_path / "gen"
        root.mkdir()
        _write(
            root,
            "a",
            [_doc(f"document number {i} about kerberoast", "a") for i in range(10)],
        )
        paths = sorted(root.glob("*.jsonl"))
        first = sample_word_df(paths, per_file=3)
        second = sample_word_df(paths, per_file=3)
        assert first == second
        assert first["kerberoast"] == 3
        assert first["document"] == 3

    def test_bad_json_is_skipped_not_fatal(self, tmp_path: Path) -> None:
        root = tmp_path / "gen"
        root.mkdir()
        (root / "a.jsonl").write_text(
            "not json\n" + json.dumps(_doc("a kerberoast here", "a")) + "\n",
            encoding="utf-8",
        )
        paths = sorted(root.glob("*.jsonl"))
        assert sample_word_df(paths)["kerberoast"] == 1
        report = scan_generation(root, workers=1, df_sample=10)
        assert report.instrument["bad_json_lines"] == 1
        assert report.docs == 1
