"""Tests for the curriculum taxonomy — the scale on the coverage ruler.

:mod:`training.corpus.curriculum` is pure data and three functions, which makes
it look like the kind of module that does not need tests. It is the opposite.
Nothing in it executes, so nothing in it fails loudly; a term that can never
match, a topic with no discriminating vocabulary, or an ATT&CK id with a typo
all behave identically to correct data right up until a coverage report quotes
them as a number. **Check the instrument first** — this project has three
recorded cases of the ruler being wrong and the model being accused, and a
taxonomy is a ruler with no moving parts to notice.

Four properties here are load-bearing:

**Every term can match something.** A term whose compiled pattern cannot match
its own text is the silent failure mode: the topic reports 0% coverage forever
and reads as a data gap. :class:`TestTermsRoundTrip` plants each term in a
synthetic sentence and requires it to be found, including the terms with
punctuation and the ones with internal whitespace spanning a newline.

**No term is so broad it measures nothing.** :class:`TestNotTooBroad` holds a
fixed sample of writing with nothing to do with security — bread, a garden, a
football match, a stylesheet changelog — and requires that not one of the
hundreds of matcher terms fires on any of it. A term that matches a knitting
pattern will match a third of the corpus, and the coverage report will say the
corpus is complete.

**The ATT&CK facts are the current ones.** Model priors on ATT&CK are stale by
a whole generation: ``TA0005`` was renamed from "Defense Evasion" to
**"Stealth"** and ``TA0112 Defense Impairment`` was added, which makes fifteen
enterprise tactics. Both were read out of the STIX bundle cached on this
machine, and :class:`TestAttackFacts` pins them so that a future edit "fixing"
them back to the remembered names fails instead of silently reintroducing the
stale map that :mod:`training.corpus.sources.threathunt` still carries.

**Ids are stable.** Coverage numbers are compared across runs, so a renamed
topic id silently breaks a comparison. :class:`TestIdentity` pins a digest of
the id set; changing the taxonomy means changing that digest and
``CURRICULUM_VERSION`` in the same commit, deliberately.

Nothing here reads the corpus, the network or the SSD. The document
frequencies that calibrated the terms were measured by a separate scan and
recorded in :data:`~training.corpus.curriculum.REJECTED_TERMS`; this file
tests the taxonomy, not the measurement.
"""

from __future__ import annotations

import hashlib
import re

import pytest

from training.corpus.curriculum import (
    ATLAS_ID_RE,
    CALIBRATION_DOCS,
    CALIBRATION_GENERATION,
    MEASURED_GAPS,
    REJECTION_CLASSES,
    SOURCE_CONCENTRATION,
    TERM_DOC_FREQ,
    ATTACK_ID_RE,
    ATTACK_TACTICS,
    COLLAPSED,
    CURRICULUM_VERSION,
    DOMAINS,
    REJECTED_TERMS,
    TOPICS,
    all_terms,
    atlas_index,
    attack_index,
    by_domain,
    by_id,
    by_register,
    domain,
    domain_ids,
    iter_topics,
    term_pattern,
    topic_ids,
    topic_pattern,
)
from training.corpus.source import Register


# ---------------------------------------------------------------------------
# Fixed unrelated text
# ---------------------------------------------------------------------------

#: Writing with nothing to do with security, written for this file. These are
#: the negative control: a matcher term that fires here is broad enough to fire
#: across the corpus, and a coverage report built on it would be noise.
#:
#: The last two are deliberately *technical but not security* — a stylesheet
#: changelog and a statistics note — because the terms most likely to be too
#: broad are the ones that are ordinary vocabulary in a neighbouring field.
UNRELATED: tuple[str, ...] = (
    """Keep the starter at room temperature and feed it twice a day with equal
    weights of flour and water. On the third day it should double in volume
    within six hours of feeding, which is the point at which it can raise a
    loaf. Mix the dough to a shaggy mass, rest it for thirty minutes, then
    fold it four times at half-hour intervals before shaping.""",
    """The raised beds get full sun until about three in the afternoon. Beans
    and squash went in after the last frost; the garlic was planted in autumn
    and will be lifted when the lower leaves have browned. Mulch heavily with
    straw to keep the soil from drying out, and water at the roots rather than
    over the leaves to avoid mildew.""",
    """Practise the left-hand arpeggios slowly with a metronome at sixty beats
    per minute, counting aloud. The thumb crossing in bar nine is the hard
    part; isolate it, play it ten times evenly, then rejoin it to the phrase
    before and after. Only raise the tempo once the crossing stops being
    audible as a seam.""",
    """United pressed high for the first twenty minutes and should have been
    two goals up at the interval. The equaliser came from a corner that nobody
    attacked properly, and after that the midfield stopped moving the ball
    forward. The substitution on the hour changed the shape and the second half
    finished with both sides exchanging long passes and little else.""",
    """Cast on ninety stitches on a four-millimetre circular needle and work
    eight rounds of twisted rib. Increase evenly on the next round to ninety-six
    and begin the cable chart, repeating rows one to sixteen six times in all.
    Block the finished piece gently with pins and leave it flat to dry.""",
    """The lake is deepest at the northern end, where the old quarry workings
    drop away sharply a few metres from the bank. Herons stand in the shallows
    at dawn. In August the water is warm enough to swim before breakfast, and
    the path around the far shore takes a little under an hour at a walk.""",
    """Lay out all the panels face down on a soft surface and check the parts
    against the list before you start. The dowels go into the pre-drilled holes
    in the side panel; tap them flush with a mallet rather than forcing them by
    hand. Tighten the cam locks only after all four sides are standing, or the
    frame will rack and the drawer will bind.""",
    """Release 4.2 drops the deprecated grid fallback and adds logical property
    shorthands for margin and padding. Nested selectors now resolve at parse
    time, which removes a whole class of specificity surprises in themed
    builds. The minifier no longer rewrites custom property names, so a
    stylesheet can be concatenated with another without collisions.""",
    """We fitted the model on the first eleven years and held the last three
    back. The residuals are close to normal with a slight left skew, and the
    seasonal term absorbs most of the winter variance. Cross-validated error
    rose by about four percent when the interaction was dropped, which is
    within the spread of the folds and not on its own a reason to keep it.""",
    """Breakfast is served from seven until half past nine in the room at the
    back, which looks out over the courtyard. There is no lift, so the top
    floor is a climb with luggage. Checkout is at eleven but they will hold
    bags behind the desk until the evening train.""",
)

#: Single words that are ordinary English or ordinary across the whole corpus.
#: A term that is one of these, alone, measures the corpus and not a topic.
BROAD_SINGLE_WORDS = frozenset(
    """
    attack access account admin advisory alert analysis api application
    archive argument asset attacker audit auth authentication authorization
    binary bypass certificate client cloud code command config container
    control credential credentials data database debug default detection
    device directory domain dump encryption endpoint engine entry error event
    exploit export file filter firewall flag function group hash header host
    identity image impact index info injection input instance interface issue
    kernel key library linux log login logs machine malware memory message
    method module network node object option output packet parameter password
    patch path payload permission persistence policy port privilege process
    protocol proxy query registry remote report request resource response
    risk rule scan script secret security server service session shell signal
    socket source stack string system table target task technique template
    test text threat token tool traffic user value vector version
    vulnerability windows
    """.split()
)


def _discriminating(term: str) -> bool:
    """The property every topic needs at least one term to have.

    Not "is it a good term" — that was decided by measurement, recorded in
    :data:`REJECTED_TERMS`. This is the structural floor a term must clear
    before measuring it is even meaningful: it must be a phrase, or a single
    token specific enough that it is not ordinary vocabulary.
    """
    words = term.split()
    if len(words) >= 2:
        return True
    lowered = term.lower().strip("-_/.$")
    if lowered in BROAD_SINGLE_WORDS:
        return False
    # A single token earns its place three ways, and the first draft of this
    # predicate only allowed one of them -- an eight-character floor, which
    # threw out "axfr", "setspn", "dcsync", "drsuapi", "setfacl" and "safeseh".
    # Those are among the most discriminating strings in the whole taxonomy:
    # nothing but the topic says them. Length is a proxy for rarity and a bad
    # one for identifiers.
    if bool(re.search(r"[0-9_/.$\\-]", term)):
        return True                       # carries structure prose does not
    if len(lowered) >= 4 and len(re.findall(r"[aeiou]", lowered)) <= 1:
        return True                       # acronym-shaped: axfr, nbtns, tgs
    return len(lowered) >= 6


# ---------------------------------------------------------------------------
# Shape and identity
# ---------------------------------------------------------------------------

class TestLoads:
    """It imports, and it is not empty in either direction."""

    def test_topics_present(self) -> None:
        assert len(TOPICS) > 100, "a taxonomy this small cannot measure 208k documents"
        assert len(TOPICS) < 600, "more leaves than the corpus can support per topic"

    def test_domains_present(self) -> None:
        assert 10 <= len(DOMAINS) <= 40

    def test_version_declared(self) -> None:
        assert re.fullmatch(r"\d+\.\d+", CURRICULUM_VERSION)

    def test_collapse_decisions_recorded(self) -> None:
        # Granularity without a record of what was collapsed is taste, not a
        # decision. Each entry must actually say something.
        assert len(COLLAPSED) >= 4
        for name, why in COLLAPSED:
            assert name.strip()
            assert len(why.strip()) > 40, name


class TestIdentity:
    """Ids are unique, structured, and pinned."""

    def test_unique(self) -> None:
        ids = topic_ids()
        assert len(ids) == len(set(ids))

    def test_domain_ids_unique(self) -> None:
        dids = domain_ids()
        assert len(dids) == len(set(dids))

    def test_structured(self) -> None:
        dids = set(domain_ids())
        for t in TOPICS:
            assert re.fullmatch(r"[a-z][a-z0-9]*\.[a-z0-9]+(?:-[a-z0-9]+)*", t.id), t.id
            assert t.id.split(".", 1)[0] == t.domain, t.id
            assert t.domain in dids, t.id

    def test_every_domain_has_topics(self) -> None:
        for d in DOMAINS:
            assert by_domain(d.id), d.id

    def test_id_set_is_pinned(self) -> None:
        """A renamed id silently breaks a cross-run coverage comparison.

        If this fails because the taxonomy was changed on purpose, update the
        digest **and** ``CURRICULUM_VERSION`` in the same change, so a report
        carrying the old version number is never compared against new ids.
        """
        digest = hashlib.sha256("\n".join(sorted(topic_ids())).encode()).hexdigest()
        assert digest == (
            "94fbfdd06ccaddeb88d6f3ed11430f2b0bbeaa9ca8524076ad35e7ec03cdc127"
        ), f"topic id set changed; new digest {digest}"


class TestFields:
    """Every field a coverage report reads must be populated and well-formed."""

    def test_description_present(self) -> None:
        for t in TOPICS:
            assert t.description.strip(), t.id
            assert len(t.description.strip()) >= 40, t.id

    def test_description_is_not_the_id(self) -> None:
        # A description generated from the id teaches the reader nothing.
        for t in TOPICS:
            slug = t.id.split(".", 1)[1].replace("-", " ")
            assert t.description.strip().lower() != slug, t.id

    def test_register_is_a_register(self) -> None:
        for t in TOPICS:
            assert isinstance(t.register, Register), t.id

    def test_registers_are_all_used(self) -> None:
        # A taxonomy that never mentions a register cannot report a gap in it,
        # and TRAJECTORY in particular was added to the corpus because nothing
        # measured it.
        for reg in Register:
            assert by_register(reg), reg

    def test_spine_or_attack(self) -> None:
        # Every topic must say what placed it: an ATT&CK id, or a named open
        # framework. "It seemed important" is not a spine.
        for t in TOPICS:
            assert t.attack_ids or t.atlas_ids or t.spine.strip(), t.id

    def test_domains_declare_a_spine(self) -> None:
        for d in DOMAINS:
            assert d.spine.strip(), d.id


class TestAttackIds:
    """Identifier well-formedness, which is the one thing a regex can prove."""

    def test_attack_ids_well_formed(self) -> None:
        for t in TOPICS:
            for aid in t.attack_ids:
                assert ATTACK_ID_RE.fullmatch(aid), f"{t.id}: {aid}"

    def test_atlas_ids_well_formed(self) -> None:
        for t in TOPICS:
            for aid in t.atlas_ids:
                assert ATLAS_ID_RE.fullmatch(aid), f"{t.id}: {aid}"

    def test_no_duplicate_ids_within_a_topic(self) -> None:
        for t in TOPICS:
            assert len(t.attack_ids) == len(set(t.attack_ids)), t.id
            assert len(t.atlas_ids) == len(set(t.atlas_ids)), t.id

    def test_index_round_trips(self) -> None:
        index = attack_index()
        for t in TOPICS:
            for aid in t.attack_ids:
                assert t.id in index[aid]
        assert atlas_index(), "the AI/ML domain must carry ATLAS ids"

    def test_coverage_is_partial_by_design(self) -> None:
        """Some domains must have no ATT&CK ids at all.

        ATT&CK describes adversary behaviour, not a tester's workflow, so
        binary exploitation and report writing have no technique ids. If every
        topic acquired one, somebody has been mapping by vibes, and an
        ATT&CK-only coverage model would then score a real blind spot as
        complete.
        """
        unmapped = [t.id for t in TOPICS if not t.attack_ids]
        assert len(unmapped) >= 20, "suspiciously complete ATT&CK mapping"
        assert all(not t.attack_ids for t in by_domain("binexp"))
        assert not by_id("method.report-writing").attack_ids


class TestAttackFacts:
    """The tactic map, pinned against stale recall."""

    def test_fifteen_enterprise_tactics(self) -> None:
        assert len(ATTACK_TACTICS) == 15

    def test_ta0005_is_stealth(self) -> None:
        # Renamed from "Defense Evasion". Read out of the cached STIX bundle
        # (x-mitre-collection "Enterprise ATT&CK 19.2"), not recalled.
        assert ATTACK_TACTICS["TA0005"] == "Stealth"
        assert "Defense Evasion" not in ATTACK_TACTICS.values()

    def test_ta0112_defense_impairment_exists(self) -> None:
        assert ATTACK_TACTICS["TA0112"] == "Defense Impairment"

    def test_tactic_ids_well_formed(self) -> None:
        for tid in ATTACK_TACTICS:
            assert re.fullmatch(r"TA\d{4}", tid), tid

    def test_tactics_referenced_as_ids_resolve(self) -> None:
        for t in TOPICS:
            for aid in t.attack_ids:
                if aid.startswith("TA"):
                    assert aid in ATTACK_TACTICS, f"{t.id}: {aid}"


# ---------------------------------------------------------------------------
# Terms
# ---------------------------------------------------------------------------

class TestTerms:
    """The matcher vocabulary: present, specific, and tidy."""

    def test_every_topic_has_terms(self) -> None:
        for t in TOPICS:
            assert len(t.terms) >= 3, t.id

    def test_every_topic_has_a_discriminating_term(self) -> None:
        for t in TOPICS:
            assert any(_discriminating(term) for term in t.terms), t.id

    def test_every_term_is_discriminating(self) -> None:
        # Stronger than the requirement, and it should hold: a topic carrying
        # one good term and four useless ones still reports inflated coverage,
        # because a match on any term counts the document.
        offenders = [
            (t.id, term)
            for t in TOPICS
            for term in t.terms
            if not _discriminating(term)
        ]
        assert not offenders, offenders

    def test_terms_are_normalised(self) -> None:
        for t in TOPICS:
            for term in t.terms:
                assert term == term.strip(), (t.id, term)
                assert term == term.lower(), (t.id, term)
                assert "  " not in term, (t.id, term)
                assert "\n" not in term and "\t" not in term, (t.id, term)
                assert len(term) >= 3, (t.id, term)

    def test_no_duplicate_terms_within_a_topic(self) -> None:
        for t in TOPICS:
            assert len(t.terms) == len(set(t.terms)), t.id

    def test_terms_are_not_mostly_shared(self) -> None:
        """A term on ten topics distinguishes none of them."""
        owners: dict[str, list[str]] = {}
        for t in TOPICS:
            for term in t.terms:
                owners.setdefault(term, []).append(t.id)
        over = {term: ids for term, ids in owners.items() if len(ids) > 3}
        assert not over, over

    def test_rejected_terms_are_not_live(self) -> None:
        """Calibration has to be consistent with the data it calibrated.

        A term recorded as too broad that is still in a topic's term list is
        the worst of both worlds: the module claims it calibrated and the
        matcher behaves as if it had not.
        """
        live = set(all_terms())
        for rejected in REJECTED_TERMS:
            assert rejected.term not in live, rejected.term

    def test_rejections_are_evidenced(self) -> None:
        assert len(REJECTED_TERMS) >= 10
        for r in REJECTED_TERMS:
            assert r.term == r.term.lower().strip()
            assert len(r.reason.strip()) > 20, r.term
            # -1 means "rejected on reading, never measured" and must say so.
            assert r.doc_freq >= 0 or "not measured" in r.reason, r.term

    def test_measured_rejections_are_actually_frequent(self) -> None:
        """Most rejections must be high-frequency, or the record is decorative."""
        measured = [r for r in REJECTED_TERMS if r.doc_freq >= 0]
        assert len(measured) >= 8
        # 5% of the 208,346 documents in clean-v7.
        threshold = int(0.05 * 208_346)
        assert sum(1 for r in measured if r.doc_freq >= threshold) >= 5


class TestTermsRoundTrip:
    """Every term must be able to match its own text.

    A pattern that cannot match anything is indistinguishable from a topic the
    corpus does not cover, and that is exactly the confusion this taxonomy
    exists to remove.
    """

    def test_term_matches_itself(self) -> None:
        for term in all_terms():
            assert term_pattern(term).search(term), term

    def test_term_matches_inside_a_sentence(self) -> None:
        for term in all_terms():
            sentence = f"The report noted that {term} was observed on the host."
            assert term_pattern(term).search(sentence), term

    def test_term_matches_case_folded(self) -> None:
        for term in all_terms():
            assert term_pattern(term).search(term.upper()), term

    def test_multiword_term_matches_across_a_newline(self) -> None:
        wrapped = [t for t in all_terms() if " " in t]
        assert wrapped, "a taxonomy of single words would not need this"
        for term in wrapped:
            head, _, tail = term.partition(" ")
            assert term_pattern(term).search(f"{head}\n    {tail}"), term

    def test_topic_pattern_matches_each_of_its_terms(self) -> None:
        for t in TOPICS:
            pattern = topic_pattern(t.id)
            for term in t.terms:
                assert pattern.search(term), (t.id, term)

    def test_word_boundaries_are_enforced(self) -> None:
        # The boundary rule is what stops "axfr" matching "axfrs" and
        # "shellcode" matching "shellcoded".
        assert term_pattern("axfr").search("axfr request")
        assert not term_pattern("axfr").search("axfrx")
        assert not term_pattern("axfr").search("xaxfr")
        assert term_pattern("shellcode").search("the shellcode, padded")

    def test_plurals_match_and_other_suffixes_do_not(self) -> None:
        # A deliberate relaxation, made after the first calibration scan found
        # the matcher refusing "yara rules" for the term "yara rule".
        assert term_pattern("yara rule").search("three yara rules fired")
        assert term_pattern("shellcode").search("two shellcodes")
        assert not term_pattern("shellcode").search("shellcoded")
        assert not term_pattern("yara rule").search("yara ruleset")
        # Terms ending in a digit or punctuation get no plural tolerance.
        assert not term_pattern("imdsv2").search("imdsv2s")

    def test_hits_counts_occurrences(self) -> None:
        t = by_id("webapp.sql-injection")
        text = "SQL injection here, and sql injection again, with a UNION SELECT."
        hits = t.hits(text)
        assert hits["sql injection"] == 2
        assert hits["union select"] == 1
        assert "time-based blind" not in hits
        assert t.matches(text)

    def test_matches_is_false_on_unrelated_text(self) -> None:
        t = by_id("winad.kerberoasting")
        assert not t.matches(UNRELATED[0])


class TestNotTooBroad:
    """The negative control, and the headline property of this file."""

    def test_no_term_matches_unrelated_text(self) -> None:
        offenders: list[tuple[str, str, str]] = []
        for t in TOPICS:
            for term in t.terms:
                pattern = term_pattern(term)
                for i, sample in enumerate(UNRELATED):
                    if pattern.search(sample):
                        offenders.append((t.id, term, f"sample {i}"))
        assert not offenders, offenders

    def test_the_control_is_a_real_control(self) -> None:
        """A sample set that matched nothing by construction would prove nothing.

        So assert the samples are substantial, and that an obviously broad term
        *does* fire on them — otherwise a future edit could quietly empty the
        samples and the test above would still pass.
        """
        assert len(UNRELATED) >= 8
        for sample in UNRELATED:
            assert len(sample.split()) >= 40
        joined = " ".join(UNRELATED)
        assert term_pattern("water").search(joined)
        assert term_pattern("model").search(joined)
        assert term_pattern("release").search(joined)

    def test_broad_single_words_would_be_rejected(self) -> None:
        for word in ("exploit", "payload", "injection", "token", "technique"):
            assert not _discriminating(word), word


# ---------------------------------------------------------------------------
# Lookups
# ---------------------------------------------------------------------------

class TestLookups:

    def test_by_id(self) -> None:
        for t in TOPICS:
            assert by_id(t.id) is t
        with pytest.raises(KeyError):
            by_id("nope.not-a-topic")

    def test_by_domain(self) -> None:
        total = sum(len(by_domain(d.id)) for d in DOMAINS)
        assert total == len(TOPICS)
        with pytest.raises(KeyError):
            by_domain("nope")

    def test_domain_lookup(self) -> None:
        for d in DOMAINS:
            assert domain(d.id) is d

    def test_iter_topics(self) -> None:
        assert list(iter_topics()) == list(TOPICS)

    def test_all_terms_is_deduplicated_and_sorted(self) -> None:
        terms = all_terms()
        assert list(terms) == sorted(set(terms))
        assert len(terms) > 400

    def test_topics_are_immutable(self) -> None:
        # Frozen dataclasses: a coverage run must not be able to edit the scale
        # it is measuring against halfway through.
        with pytest.raises(Exception):
            TOPICS[0].terms = ()  # type: ignore[misc]


class TestCalibration:
    """The measured appendices, and the instrument checks on them.

    These assertions are about the *ruler*, not the corpus. Two of them would
    have caught the first draft of this taxonomy, which measured 399 of its own
    952 terms at zero -- partly because the terms were invented compounds the
    field does not write ("sudoers misconfiguration" where the corpus says
    ``sudoers``), and partly because the matcher refused a plural, so the term
    "yara rule" could not match "yara rules". Both failures look exactly like a
    corpus with nothing in it.
    """

    def test_every_live_term_has_a_measured_frequency(self) -> None:
        assert set(TERM_DOC_FREQ) == set(all_terms())

    def test_no_live_term_is_over_the_ceiling(self) -> None:
        ceiling = int(0.05 * CALIBRATION_DOCS)
        over = {t: n for t, n in TERM_DOC_FREQ.items() if n >= ceiling}
        assert not over, over

    def test_frequencies_are_plausible(self) -> None:
        assert CALIBRATION_DOCS == 208_346
        assert CALIBRATION_GENERATION == "clean-v7"
        for term, n in TERM_DOC_FREQ.items():
            assert 0 <= n < CALIBRATION_DOCS, (term, n)

    def test_the_matcher_is_not_dead(self) -> None:
        """All-zero is a broken matcher, not an empty corpus.

        This is the direction the first draft failed in, and the dangerous one:
        a coverage report full of zeros reads as "the corpus lacks everything"
        and gets believed.
        """
        occurring = [t for t, n in TERM_DOC_FREQ.items() if n > 0]
        assert len(occurring) > 0.6 * len(TERM_DOC_FREQ), (
            f"only {len(occurring)} of {len(TERM_DOC_FREQ)} terms occur at all; "
            "suspect the matcher before the corpus"
        )

    def test_the_matcher_is_not_saturated(self) -> None:
        """And a high median is the mirror failure: 100% coverage everywhere."""
        median = sorted(TERM_DOC_FREQ.values())[len(TERM_DOC_FREQ) // 2]
        assert median < 0.02 * CALIBRATION_DOCS, median

    def test_every_topic_has_at_least_one_occurring_term(self) -> None:
        """Otherwise the topic is unmeasurable rather than uncovered.

        It is a real distinction: a topic with one term at 40 documents says
        "the corpus barely covers this". A topic whose every term is zero says
        nothing at all, because the terms might simply be the wrong strings.
        """
        silent = [t.id for t in TOPICS
                  if all(TERM_DOC_FREQ[x] == 0 for x in t.terms)]
        assert not silent, silent

    def test_measured_gaps_are_consistent(self) -> None:
        gaps = set(MEASURED_GAPS)
        assert gaps <= set(topic_ids())
        for t in TOPICS:
            all_zero = all(TERM_DOC_FREQ[term] == 0 for term in t.terms)
            assert all_zero == (t.id in gaps), t.id

    def test_rejection_classes_are_recorded(self) -> None:
        assert len(REJECTION_CLASSES) >= 4
        for name, count, why in REJECTION_CLASSES:
            assert name.strip() and why.strip()
            assert count >= 0

    def test_source_concentration_is_well_formed(self) -> None:
        for term, (source, hits, total) in SOURCE_CONCENTRATION.items():
            assert term in TERM_DOC_FREQ, term
            assert source and source.islower(), term
            assert 0 < hits <= total, term
            assert hits / total >= 0.6, term

    def test_concentration_covers_the_big_terms(self) -> None:
        """The check only means something if it actually looked at them."""
        big = {t for t, n in TERM_DOC_FREQ.items() if n >= 1000}
        assert big, "no term is large enough for concentration to matter?"
        looked_at = big & set(SOURCE_CONCENTRATION)
        assert looked_at, "concentration data is missing for every large term"
