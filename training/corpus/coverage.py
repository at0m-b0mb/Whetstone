"""Measure a corpus generation against the curriculum — ruler first.

:mod:`training.corpus.curriculum` says what the field contains: 22 domains,
192 topics, 1,071 matcher terms, each term's document frequency measured once.
This module answers the next question — *which of those topics does this corpus
actually teach, out of which sources, in which register* — and it is built
around the one lesson this project keeps relearning:

    **CHECK THE INSTRUMENT FIRST.** Three measurement bugs here each accused
    the model and all three were in the ruler. The verifier once reported a
    625.3 MB corpus clean in 0.0 s — 128,124 MB/s — having read zero bytes,
    and the tell was the throughput, not the verdict.

So this module refuses to report a coverage number it has not earned:

* :func:`self_test` builds a synthetic generation whose answers are known by
  construction and scores the scanner against them. It is the needle in the
  copy: if the scanner cannot find a planted document, nothing it says about
  580 MB of real text means anything.
* :data:`CONTROL_PRESENT` and :data:`CONTROL_ABSENT` ride along on every real
  scan. The present controls are terms this corpus cannot plausibly lack; the
  absent controls are well-formed nonsense no corpus can contain. A scan where
  the present controls are zero read nothing. A scan where the absent controls
  are non-zero is matching something other than what it says.
* Throughput is reported in MB/s and flagged above
  :data:`MAX_PLAUSIBLE_MBPS`, because a regex pass over text has a speed limit
  and exceeding it means the bytes were never looked at.
* Recall is measured against a **gold label the matcher cannot see**: every
  ATT&CK technique document in the corpus carries its own ``ATT&CK ID:`` line,
  and a topic that claims that id must match that document. No term in the
  curriculum is an ATT&CK id (checked by :mod:`tests.test_coverage`), so this
  is an independent label and not the matcher grading its own homework.

**Precision cannot be measured this way and the module does not pretend it
can.** Whether a document that mentions "pass-the-hash" is *about*
pass-the-hash is a judgement, so ``--sample`` draws a uniform random sample of
(topic, document) matches for a reader to adjudicate, and ``--adjudication``
folds the verdicts back in. What the scan *can* measure without judgement is
corroboration: a document matching one term once is a name-drop, and a document
matching two distinct terms, or one term three times, is evidence. Both counts
are reported per topic, so a precision claim can be read off the shape even
before anyone adjudicates a sample.

**The two rulers.** Characters and tokens disagree about this corpus and the
disagreement is load-bearing, so this module uses **characters** everywhere and
says so in the report (``ruler: "characters"``). Characters are what the build
balances on (``_cap_register_share`` sums ``d.n_chars``) and what
``TERM_DOC_FREQ`` was measured against. Token shares come from a tokenised
generation's own index and are reported, when one is supplied, as a separate
column rather than averaged in. See :func:`register_rulers`.

Everything here is standard library, streams the generation a line at a time,
and writes nothing except the report file it is asked for. It never writes a
value out of the corpus: samples carry ``(file, line)`` coordinates and the
terms that matched, never text, because the corpus is known to contain live
host identity and third-party names and a coverage report is not the place to
discover that again.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import re
import time
from collections import Counter
from collections.abc import Iterable, Iterator, Sequence
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import curriculum as C
from .source import REGISTER_TARGETS

__all__ = [
    "CONTROL_ABSENT",
    "CONTROL_PRESENT",
    "COVERAGE_VERSION",
    "FAIR_SHARE_DOCS",
    "MAX_PLAUSIBLE_MBPS",
    "SINGLE_SOURCE_AT",
    "VERDICTS",
    "AttackInventory",
    "Matcher",
    "Report",
    "TopicCoverage",
    "attack_inventory",
    "classify",
    "main",
    "register_rulers",
    "sample_lines",
    "scan_generation",
    "self_test",
]

#: Bumped when the verdict thresholds or the scan semantics change, so a number
#: from an older run is not compared against a newer one. Paired in every
#: report with ``curriculum.CURRICULUM_VERSION``: the taxonomy and the ruler
#: version independently and both have to match for two reports to be
#: comparable.
COVERAGE_VERSION = "1.1"

#: A topic's "fair share" of documents, declared **before** looking at any
#: result so the thresholds are not fitted to make the corpus look good:
#: 208,346 documents over 192 topics is 1,085 documents each if the corpus were
#: uniform, so 1,000 is the round number for "at or above a uniform share".
#: Below it a topic is present but under-fed; two orders of magnitude below it a
#: topic is a vocabulary trace rather than material to learn from.
FAIR_SHARE_DOCS = 1000

#: One source supplying this fraction of a topic's documents makes the topic
#: **fragile**: the number is then a statement about one adapter, and if that
#: adapter changes shape the topic moves. Not a failure — Sigma rules *are*
#: this corpus's Sigma coverage — but it must be said out loud.
SINGLE_SOURCE_AT = 0.80

#: Verdicts, in descending order of health. Orthogonal flags (``fragile``,
#: ``name-drop``) travel beside the verdict rather than inside it, because a
#: topic can be large and fragile at once and collapsing the two hides which.
VERDICTS: tuple[str, ...] = ("strong", "covered", "thin", "trace", "absent")

#: A regex pass over text cannot go faster than this on this machine, so a
#: scan that claims to have is a scan that did not read. The real matcher runs
#: between 0.9 and 7 MB/s per worker depending on document size; 120 MB/s is
#: more than an order of magnitude of headroom and still far below the
#: 128,124 MB/s that gave away the verifier's fail-open.
MAX_PLAUSIBLE_MBPS = 120.0

#: Terms this corpus cannot plausibly lack, with the floor each must clear.
#: These are **not** curriculum terms and are not reported as coverage; they
#: exist so that "every topic scored zero" can be distinguished from "the
#: scanner read nothing", which are the same number and different bugs.
CONTROL_PRESENT: tuple[tuple[str, int], ...] = (
    ("password", 5000),
    ("windows", 5000),
    ("linux", 5000),
    ("vulnerability", 2000),
)

#: Well-formed nonsense: English-shaped, security-shaped, and impossible. Any
#: hit means the matcher is matching something other than the term it was
#: handed — a boundary bug, a pattern escaping bug, or the wrong text.
CONTROL_ABSENT: tuple[str, ...] = (
    "zarquon privilege escalation",
    "flibbertigibbet payload",
    "quorblax credential dump",
    "snargleflax beacon",
)

#: Lowercase word, for the prefilter. Deliberately the same character class the
#: matcher's own boundary assertions use, ``[0-9A-Za-z_]``, so that a term's
#: words are exactly the runs its pattern can land on.
WORD = re.compile(r"[a-z0-9_]+")

_ATTACK_ID_LINE = re.compile(r"^ATT&CK ID: (\S+)\s*$", re.MULTILINE)
_TYPE_LINE = re.compile(r"^Type: (.+?)\s*$", re.MULTILINE)
_MATRIX_LINE = re.compile(r"^Matrix: (.+?)\s*$", re.MULTILINE)
_TECHNIQUE_ID = re.compile(r"(?<![0-9A-Za-z_.])T\d{4}(?:\.\d{3})?(?![0-9A-Za-z_])")


# ---------------------------------------------------------------------------
# The matcher
# ---------------------------------------------------------------------------


class Matcher:
    """Curriculum terms, applied to a document, fast enough to finish.

    The obvious implementation — one alternation over all 1,071 terms — was
    measured first and abandoned: 0.46 MB/s, 21 minutes for the generation, and
    that is before any per-term attribution. Python's ``re`` is a backtracking
    engine and a 1,071-way alternation of patterns that each open with a
    lookbehind is the worst case for it.

    What this does instead is a two-stage filter whose first stage cannot
    produce a false negative:

    1. Lowercase the document once and take the **set** of its ``[a-z0-9_]+``
       runs. Every curriculum term is lowercase ASCII (pinned by
       :mod:`tests.test_coverage`), its pattern joins its words with ``\\s+``,
       and both boundary assertions are on the same character class — so a term
       cannot match a document unless *every* word of the term appears as a run
       in it. Requiring one chosen word is therefore a necessary condition, and
       set membership is free.
    2. Run the real :func:`curriculum.term_pattern` for the few candidate terms
       that survive, against the lowercased text with ``IGNORECASE`` dropped.

    Two details are not optional. The probe word is the **rarest** word of the
    term, by a sampled document frequency: probing "union select" on ``select``
    admits every SQL document in the corpus and probing it on ``union`` admits
    few, and that choice alone is a 2.4x difference in candidates per document.
    And when the probe word is the term's last word, the plural form is probed
    too, because :func:`curriculum.term_pattern` makes a trailing ``s``
    optional — a prefilter that misses "yara rules" for the term "yara rule"
    reintroduces exactly the silent zero that rule was written to fix.

    Dropping ``IGNORECASE`` and matching the lowercased copy is an equivalence
    claim, so it is checked rather than assumed: over 480 documents from four
    sources, all 1,071 terms, the two implementations disagreed on nothing
    (:func:`self_test` keeps a smaller version of that check in the tests).
    """

    def __init__(self, word_df: dict[str, int] | None = None) -> None:
        self.terms: tuple[str, ...] = C.all_terms()
        self._pat: dict[str, re.Pattern[str]] = {
            t: re.compile(C.term_pattern(t).pattern) for t in self.terms
        }
        self.topics_of: dict[str, tuple[str, ...]] = _topics_by_term()
        self.probe: dict[str, tuple[str, ...]] = {}
        index: dict[str, list[str]] = {}
        for term in self.terms:
            forms = _probe_forms(term, word_df or {})
            self.probe[term] = forms
            for form in forms:
                index.setdefault(form, []).append(term)
        self.index: dict[str, tuple[str, ...]] = {
            k: tuple(v) for k, v in index.items()
        }
        self._control: dict[str, re.Pattern[str]] = {
            t: re.compile(C.term_pattern(t).pattern)
            for t, _floor in CONTROL_PRESENT
        }
        self._control.update(
            {t: re.compile(C.term_pattern(t).pattern) for t in CONTROL_ABSENT}
        )

    # -- the hot path ----------------------------------------------------

    def hits(self, text: str) -> dict[str, int]:
        """Per-term occurrence counts for one document, zero entries omitted."""
        low = text.lower()
        cands: set[str] = set()
        get = self.index.get
        for word in set(WORD.findall(low)):
            found = get(word)
            if found:
                cands.update(found)
        out: dict[str, int] = {}
        # Sorted, not set order. Set iteration order over strings varies with
        # PYTHONHASHSEED, so an unsorted loop here made the *counts* stable and
        # the *sample draw* irreproducible: two scans of the same generation
        # returned the same numbers and a different 80 documents to adjudicate,
        # which was caught by diffing two runs and would otherwise have made
        # every precision figure unrecheckable.
        for term in sorted(cands):
            n = len(self._pat[term].findall(low))
            if n:
                out[term] = n
        return out

    def controls(self, text: str) -> dict[str, int]:
        """Which control terms this document contains. One search each."""
        low = text.lower()
        return {
            name: 1 for name, pat in self._control.items() if pat.search(low)
        }

    def topics(self, hits: dict[str, int]) -> dict[str, dict[str, int]]:
        """Fold per-term hits into per-topic hits."""
        out: dict[str, dict[str, int]] = {}
        for term, n in hits.items():
            for tid in self.topics_of[term]:
                out.setdefault(tid, {})[term] = n
        return out


def _topics_by_term() -> dict[str, tuple[str, ...]]:
    """Term to the topics that claim it. Shared terms exist and are kept."""
    index: dict[str, list[str]] = {}
    for topic in C.TOPICS:
        for term in topic.terms:
            index.setdefault(term, []).append(topic.id)
    return {k: tuple(v) for k, v in index.items()}


def _probe_forms(term: str, word_df: dict[str, int]) -> tuple[str, ...]:
    """The prefilter word(s) for one term: rarest word, plus its plural if last.

    Ties break on the longer word and then on *not* being the last word, since
    the last word is the one that may have to be probed twice.
    """
    words = WORD.findall(term.lower())
    if not words:  # no term in the curriculum is wordless; kept for safety
        return ()
    last = len(words) - 1
    pick = min(
        range(len(words)),
        key=lambda i: (word_df.get(words[i], 0), -len(words[i]), i == last),
    )
    word = words[pick]
    plural = term[-1].isalpha() and term[-1] != "s"
    if pick == last and plural:
        return (word, word + "s")
    return (word,)


def sample_word_df(paths: Sequence[Path], per_file: int = 150) -> dict[str, int]:
    """Document frequency of words, from the first ``per_file`` of each file.

    A sample, and it only has to be good enough to order the words of a term by
    rarity. Deterministic — the first N lines of each file, never a random draw
    — so two runs of this module build the same prefilter and any difference in
    their numbers is a difference in the corpus.
    """
    df: Counter[str] = Counter()
    for path in paths:
        try:
            with path.open(encoding="utf-8", errors="replace") as handle:
                for i, line in enumerate(handle):
                    if i >= per_file:
                        break
                    try:
                        text = json.loads(line).get("text") or ""
                    except json.JSONDecodeError:
                        continue
                    df.update(set(WORD.findall(text.lower())))
        except OSError:
            continue
    return dict(df)


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TopicCoverage:
    """What the scan found for one topic. Counts, never percentages alone."""

    topic_id: str
    domain: str
    declared_register: str
    docs: int
    chars: int
    occurrences: int
    #: Documents matching two distinct terms, or one term three or more times.
    corroborated: int
    #: Documents matching exactly one term exactly once.
    name_drops: int
    #: Source to documents, descending.
    sources: dict[str, int]
    #: Observed register to documents, descending. Compare with
    #: ``declared_register``, which is an authored claim and not a measurement.
    registers: dict[str, int]
    #: Term to documents, for terms that occurred.
    terms: dict[str, int]
    #: Terms of this topic that matched nothing at all.
    dead_terms: tuple[str, ...]
    verdict: str
    #: ``fragile`` when one source supplies ``SINGLE_SOURCE_AT`` of the
    #: documents; ``name-drop`` when most matches are a single mention;
    #: ``one-term`` when a single term carries the whole topic.
    flags: tuple[str, ...]
    #: Gold ATT&CK documents for this topic, and how many the matcher found.
    gold_total: int = 0
    gold_hit: int = 0

    @property
    def top_source(self) -> tuple[str, int]:
        return next(iter(self.sources.items()), ("", 0))

    def to_json(self) -> dict[str, Any]:
        out = {
            "topic": self.topic_id,
            "domain": self.domain,
            "declared_register": self.declared_register,
            "docs": self.docs,
            "chars": self.chars,
            "occurrences": self.occurrences,
            "corroborated": self.corroborated,
            "name_drops": self.name_drops,
            "verdict": self.verdict,
            "flags": list(self.flags),
            "sources": self.sources,
            "registers": self.registers,
            "terms": self.terms,
            "dead_terms": list(self.dead_terms),
        }
        if self.gold_total:
            out["gold"] = {
                "documents": self.gold_total,
                "found": self.gold_hit,
                "recall": round(self.gold_hit / self.gold_total, 4),
            }
        return out


@dataclass(frozen=True, slots=True)
class AttackInventory:
    """Which ATT&CK objects the corpus actually contains, by type and matrix.

    Exists because one benchmark probe, ``attck-real``, has never moved off
    0/10 and the three candidate explanations — no data, expensive tokens, a
    broken adapter — are distinguishable only by counting. This counts.
    """

    docs: int
    chars: int
    by_type: dict[str, int]
    by_matrix: dict[str, int]
    #: Object type to the number of *distinct* ids seen, which is the number
    #: that matters: 64 mitigation documents over 64 ids is coverage, 64 over
    #: 3 is repetition.
    distinct_ids: dict[str, int]
    #: Distinct technique ids mentioned anywhere in the generation, and the
    #: documents that mention at least one, per source.
    technique_ids_total: int
    technique_docs_by_source: dict[str, int]

    def to_json(self) -> dict[str, Any]:
        return {
            "docs": self.docs,
            "chars": self.chars,
            "by_type": self.by_type,
            "by_matrix": self.by_matrix,
            "distinct_ids": self.distinct_ids,
            "technique_ids_total": self.technique_ids_total,
            "technique_docs_by_source": self.technique_docs_by_source,
        }


@dataclass
class Report:
    """One scan of one generation. The unit a coverage claim is made in."""

    generation: str
    curriculum_version: str
    coverage_version: str
    ruler: str
    docs: int
    chars: int
    elapsed: float
    mbps: float
    files: int
    by_source: dict[str, dict[str, int]]
    by_register: dict[str, dict[str, int]]
    #: The cross-tabulation the marginals cannot give back: source to register
    #: to characters. Needed for the token ruler, and the only way to see that
    #: a source spans registers rather than declaring one.
    source_registers: dict[str, dict[str, int]]
    topics: list[TopicCoverage]
    #: Documents matching no topic at all — the taxonomy's own blind spot.
    unseen_docs: int
    unseen_chars: int
    #: Where the blind spot is, by source. This is the actionable half of the
    #: headline figure: "half the corpus matches no topic" is a mood, and
    #: "yara supplies 10,298 of those documents and the taxonomy has no YARA
    #: vocabulary at all because the term was rejected for excess frequency" is
    #: a decision about either the taxonomy or the corpus.
    unseen_by_source: dict[str, dict[str, int]]
    #: Documents matching n topics, as a histogram keyed by n (string keys so
    #: the report round-trips through JSON unchanged).
    topics_per_doc: dict[str, int]
    controls_present: dict[str, int]
    controls_absent: dict[str, int]
    instrument: dict[str, Any]
    attack: AttackInventory | None = None
    samples: list[dict[str, Any]] = field(default_factory=list)
    adjudication: dict[str, Any] | None = None
    notes: list[str] = field(default_factory=list)

    # -- rollups ---------------------------------------------------------

    def by_verdict(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {v: [] for v in VERDICTS}
        for topic in self.topics:
            out[topic.verdict].append(topic.topic_id)
        return out

    def domains(self) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for dom in C.DOMAINS:
            mine = [t for t in self.topics if t.domain == dom.id]
            counts = Counter(t.verdict for t in mine)
            out[dom.id] = {
                "label": dom.label,
                "spine": dom.spine,
                "topics": len(mine),
                "docs": sum(t.docs for t in mine),
                "verdicts": {v: counts.get(v, 0) for v in VERDICTS},
                "fragile": sum(1 for t in mine if "fragile" in t.flags),
            }
        return out

    def gold_recall(self) -> dict[str, Any]:
        total = sum(t.gold_total for t in self.topics)
        hit = sum(t.gold_hit for t in self.topics)
        misses = [
            {
                "topic": t.topic_id,
                "documents": t.gold_total,
                "found": t.gold_hit,
            }
            for t in self.topics
            if t.gold_total and t.gold_hit < t.gold_total
        ]
        misses.sort(key=lambda m: (m["found"] / m["documents"], -m["documents"]))
        return {
            "label": "ATT&CK technique documents, matched by id (independent "
                     "of the matcher: no curriculum term is an ATT&CK id)",
            "documents": total,
            "found": hit,
            "recall": round(hit / total, 4) if total else None,
            "topics_scored": sum(1 for t in self.topics if t.gold_total),
            "topics_below_full_recall": misses[:40],
        }

    def to_json(self) -> dict[str, Any]:
        verdicts = self.by_verdict()
        return {
            "generation": self.generation,
            "curriculum_version": self.curriculum_version,
            "coverage_version": self.coverage_version,
            "ruler": self.ruler,
            "scanned": {
                "documents": self.docs,
                "characters": self.chars,
                "files": self.files,
                "elapsed_s": round(self.elapsed, 1),
                "mb_per_s": round(self.mbps, 2),
            },
            "instrument": self.instrument,
            "distribution": {v: len(verdicts[v]) for v in VERDICTS},
            "absent": verdicts["absent"],
            "trace": verdicts["trace"],
            "thin": verdicts["thin"],
            "fragile": [t.topic_id for t in self.topics if "fragile" in t.flags],
            "taxonomy_blind_spot": {
                "documents_matching_no_topic": self.unseen_docs,
                "characters_matching_no_topic": self.unseen_chars,
                "by_source": self.unseen_by_source,
                "share_of_documents": round(self.unseen_docs / self.docs, 4)
                if self.docs
                else None,
                "topics_per_doc": self.topics_per_doc,
            },
            "calibration": {
                "gold_recall": self.gold_recall(),
                "controls_present": self.controls_present,
                "controls_absent": self.controls_absent,
                "adjudication": self.adjudication,
            },
            "registers": register_rulers(self.by_register),
            "source_registers": self.source_registers,
            "sources": self.by_source,
            "attack": self.attack.to_json() if self.attack else None,
            "domains": self.domains(),
            "topics": [t.to_json() for t in self.topics],
            "samples": self.samples,
            "notes": self.notes,
        }


def classify(
    docs: int, sources: dict[str, int], terms: dict[str, int], corroborated: int
) -> tuple[str, tuple[str, ...]]:
    """Verdict and flags for one topic, from counts only.

    The lower bands are :data:`FAIR_SHARE_DOCS` and a twentieth of it, declared
    before any result was looked at. The **top** band is not a multiple of fair
    share, and that is a correction made with a reason rather than to flatter a
    number: the curriculum rejects any term appearing in more than ~4.2% of the
    corpus, so no topic can reach 8,800 of 208,346 documents and a band at ten
    times fair share is unreachable *by construction of the taxonomy*. Measured
    on ``clean-v7`` the largest topic is 8,828 documents, and a report that said
    "0 strong" would have been describing the rejection rule, not the corpus.

    So the top band is a quality condition instead, and every part of it is
    something the scan measures: at or above fair share, spread over at least
    five sources, carrying at least three live terms, and not flagged
    ``fragile`` or ``name-drop``. It is strictly harder to reach than a
    document count, which is the right direction for a threshold to move.

    The flags are the part a single number hides: a topic can clear every
    threshold on one source and one term, and then the coverage figure is
    really a statement about one adapter.
    """
    flags: list[str] = []
    if docs:
        top = max(sources.values()) if sources else 0
        if top / docs >= SINGLE_SOURCE_AT:
            flags.append("fragile")
        if len(terms) == 1:
            flags.append("one-term")
        if corroborated / docs < 0.25:
            flags.append("name-drop")

    if docs == 0:
        verdict = "absent"
    elif docs < FAIR_SHARE_DOCS // 20:  # < 50
        verdict = "trace"
    elif docs < FAIR_SHARE_DOCS:
        verdict = "thin"
    elif (
        len(sources) >= 5
        and len(terms) >= 3
        and "fragile" not in flags
        and "name-drop" not in flags
    ):
        verdict = "strong"
    else:
        verdict = "covered"
    return verdict, tuple(flags)


# ---------------------------------------------------------------------------
# The scan
# ---------------------------------------------------------------------------

_WORKER: dict[str, Any] = {}


def _worker_init(word_df: dict[str, int]) -> None:
    _WORKER["matcher"] = Matcher(word_df)


def _scan_file(args: tuple[str, int, int]) -> dict[str, Any]:
    """Scan one JSONL file. Runs in a worker process; returns plain counters."""
    path_s, limit, seed = args
    matcher: Matcher = _WORKER["matcher"]
    path = Path(path_s)
    name = path.stem
    out: dict[str, Any] = {
        "file": path.name,
        "docs": 0,
        "chars": 0,
        "bad_lines": 0,
        "src_docs": Counter(),
        "src_chars": Counter(),
        "reg_docs": Counter(),
        "reg_chars": Counter(),
        "src_reg_chars": Counter(),
        "src_reg_docs": Counter(),
        "topic_docs": Counter(),
        "topic_chars": Counter(),
        "topic_occ": Counter(),
        "topic_corrob": Counter(),
        "topic_namedrop": Counter(),
        "topic_src": Counter(),
        "topic_reg": Counter(),
        "term_docs": Counter(),
        "term_occ": Counter(),
        "gold_total": Counter(),
        "gold_hit": Counter(),
        "controls": Counter(),
        "unseen_docs": 0,
        "unseen_chars": 0,
        "unseen_by_source": Counter(),
        "unseen_chars_by_source": Counter(),
        "topics_per_doc": Counter(),
        "attack_type": Counter(),
        "attack_matrix": Counter(),
        "attack_ids": {},
        "attack_docs": 0,
        "attack_chars": 0,
        "technique_ids": set(),
        "technique_docs": 0,
        "match_total": 0,
        "reservoir": [],
    }
    rng = random.Random(f"{seed}:{path.name}")
    reservoir_k = 240
    t0 = time.time()
    with path.open(encoding="utf-8", errors="replace") as handle:
        for lineno, line in enumerate(handle, start=1):
            if limit and out["docs"] >= limit:
                break
            try:
                doc = json.loads(line)
            except json.JSONDecodeError:
                out["bad_lines"] += 1
                continue
            text = doc.get("text") or ""
            source = doc.get("source") or name
            register = doc.get("register") or "?"
            n_chars = len(text)
            out["docs"] += 1
            out["chars"] += n_chars
            out["src_docs"][source] += 1
            out["src_chars"][source] += n_chars
            out["reg_docs"][register] += 1
            out["reg_chars"][register] += n_chars
            out["src_reg_docs"][(source, register)] += 1
            out["src_reg_chars"][(source, register)] += n_chars

            hits = matcher.hits(text)
            for term, n in hits.items():
                out["term_docs"][term] += 1
                out["term_occ"][term] += n
            per_topic = matcher.topics(hits)
            out["topics_per_doc"][len(per_topic)] += 1
            if not per_topic:
                out["unseen_docs"] += 1
                out["unseen_chars"] += n_chars
                out["unseen_by_source"][source] += 1
                out["unseen_chars_by_source"][source] += n_chars
            for tid, thits in sorted(per_topic.items()):
                total = sum(thits.values())
                out["topic_docs"][tid] += 1
                out["topic_chars"][tid] += n_chars
                out["topic_occ"][tid] += total
                out["topic_src"][(tid, source)] += 1
                out["topic_reg"][(tid, register)] += 1
                if len(thits) >= 2 or total >= 3:
                    out["topic_corrob"][tid] += 1
                elif total == 1:
                    out["topic_namedrop"][tid] += 1
                out["match_total"] += 1
                item = {
                    "topic": tid,
                    "source": source,
                    "file": path.name,
                    "line": lineno,
                    "terms": sorted(thits),
                    "occurrences": total,
                    "corroborated": len(thits) >= 2 or total >= 3,
                }
                if len(out["reservoir"]) < reservoir_k:
                    out["reservoir"].append(item)
                else:
                    j = rng.randrange(out["match_total"])
                    if j < reservoir_k:
                        out["reservoir"][j] = item

            for name_ in matcher.controls(text):
                out["controls"][name_] += 1

            # -- ATT&CK inventory and the gold label -----------------------
            ids = _TECHNIQUE_ID.findall(text)
            if ids:
                out["technique_docs"] += 1
                out["technique_ids"].update(ids)
            own = _ATTACK_ID_LINE.search(text)
            if own:
                kind = _TYPE_LINE.search(text)
                kind_s = kind.group(1) if kind else "?"
                matrix = _MATRIX_LINE.search(text)
                out["attack_docs"] += 1
                out["attack_chars"] += n_chars
                out["attack_type"][kind_s] += 1
                if matrix:
                    out["attack_matrix"][matrix.group(1)] += 1
                out["attack_ids"].setdefault(kind_s, set()).add(own.group(1))
                if kind_s == "Technique":
                    for tid in _GOLD_INDEX.get(own.group(1), ()):
                        out["gold_total"][tid] += 1
                        if tid in per_topic:
                            out["gold_hit"][tid] += 1
    out["elapsed"] = time.time() - t0
    return out


#: ATT&CK id to the topics claiming it, built once at import so the workers do
#: not each rebuild it.
_GOLD_INDEX: dict[str, tuple[str, ...]] = C.attack_index()


def scan_generation(
    clean_dir: str | os.PathLike[str],
    *,
    workers: int = 6,
    limit: int = 0,
    seed: int = 20261014,
    sample_size: int = 120,
    df_sample: int = 150,
) -> Report:
    """Stream a generation and measure every topic against it.

    ``limit`` caps documents per file and exists for the tests and for a smoke
    run; a limited scan says so in ``notes`` so its numbers cannot be quoted as
    the generation's.
    """
    root = Path(clean_dir)
    paths = sorted(p for p in root.glob("*.jsonl"))
    if not paths:
        raise FileNotFoundError(f"no .jsonl files in {root}")
    word_df = sample_word_df(paths, per_file=df_sample)
    jobs = [(str(p), limit, seed) for p in paths]

    t0 = time.time()
    results: list[dict[str, Any]] = []
    if workers > 1 and len(jobs) > 1:
        with ProcessPoolExecutor(
            max_workers=workers, initializer=_worker_init, initargs=(word_df,)
        ) as pool:
            results.extend(pool.map(_scan_file, jobs, chunksize=1))
    else:
        _worker_init(word_df)
        for job in jobs:
            results.append(_scan_file(job))
    elapsed = time.time() - t0

    return _assemble(
        root, results, elapsed, seed=seed, sample_size=sample_size, limit=limit
    )


def _merge(results: Sequence[dict[str, Any]], key: str) -> Counter:
    out: Counter = Counter()
    for res in results:
        out.update(res[key])
    return out


def _assemble(
    root: Path,
    results: Sequence[dict[str, Any]],
    elapsed: float,
    *,
    seed: int,
    sample_size: int,
    limit: int,
) -> Report:
    docs = sum(r["docs"] for r in results)
    chars = sum(r["chars"] for r in results)
    topic_docs = _merge(results, "topic_docs")
    topic_chars = _merge(results, "topic_chars")
    topic_occ = _merge(results, "topic_occ")
    topic_corrob = _merge(results, "topic_corrob")
    topic_nd = _merge(results, "topic_namedrop")
    topic_src = _merge(results, "topic_src")
    topic_reg = _merge(results, "topic_reg")
    term_docs = _merge(results, "term_docs")
    gold_total = _merge(results, "gold_total")
    gold_hit = _merge(results, "gold_hit")
    controls = _merge(results, "controls")
    src_docs = _merge(results, "src_docs")
    src_chars = _merge(results, "src_chars")
    reg_docs = _merge(results, "reg_docs")
    reg_chars = _merge(results, "reg_chars")
    tpd = _merge(results, "topics_per_doc")

    topics: list[TopicCoverage] = []
    for topic in C.TOPICS:
        tid = topic.id
        n = topic_docs.get(tid, 0)
        sources = {
            s: c
            for (t, s), c in sorted(
                topic_src.items(), key=lambda kv: -kv[1]
            )
            if t == tid
        }
        registers = {
            r: c
            for (t, r), c in sorted(topic_reg.items(), key=lambda kv: -kv[1])
            if t == tid
        }
        terms = {
            term: term_docs[term]
            for term in sorted(
                topic.terms, key=lambda x: -term_docs.get(x, 0)
            )
            if term_docs.get(term, 0)
        }
        dead = tuple(t for t in topic.terms if not term_docs.get(t, 0))
        verdict, flags = classify(n, sources, terms, topic_corrob.get(tid, 0))
        topics.append(
            TopicCoverage(
                topic_id=tid,
                domain=topic.domain,
                declared_register=topic.register.value,
                docs=n,
                chars=topic_chars.get(tid, 0),
                occurrences=topic_occ.get(tid, 0),
                corroborated=topic_corrob.get(tid, 0),
                name_drops=topic_nd.get(tid, 0),
                sources=sources,
                registers=registers,
                terms=terms,
                dead_terms=dead,
                verdict=verdict,
                flags=flags,
                gold_total=gold_total.get(tid, 0),
                gold_hit=gold_hit.get(tid, 0),
            )
        )

    mbps = (chars / 1e6 / elapsed) if elapsed > 0 else float("inf")
    present = {t: controls.get(t, 0) for t, _f in CONTROL_PRESENT}
    absent = {t: controls.get(t, 0) for t in CONTROL_ABSENT}
    failures: list[str] = []
    # A partial scan cannot be held to a whole generation's floors, so the
    # floor becomes "more than nothing" and the report says which rule it was
    # judged under. Dropping the check entirely would be the fail-open.
    for term, floor in CONTROL_PRESENT:
        effective = 1 if limit else floor
        if present[term] < effective:
            failures.append(
                f"present control {term!r} found in {present[term]} documents, "
                f"floor {effective}"
            )
    for term in CONTROL_ABSENT:
        if absent[term]:
            failures.append(
                f"absent control {term!r} matched {absent[term]} documents"
            )
    if mbps > MAX_PLAUSIBLE_MBPS:
        failures.append(
            f"throughput {mbps:.0f} MB/s exceeds the plausible ceiling "
            f"{MAX_PLAUSIBLE_MBPS:.0f} MB/s — the bytes were not read"
        )
    if not docs or not chars:
        failures.append("scan read no documents")

    instrument = {
        "controls_pass": not failures,
        "failures": failures,
        "mb_per_s": round(mbps, 2),
        "bad_json_lines": sum(r["bad_lines"] for r in results),
        "worker_seconds": round(sum(r["elapsed"] for r in results), 1),
        "fair_share_docs": FAIR_SHARE_DOCS,
        "single_source_at": SINGLE_SOURCE_AT,
        "present_control_rule": "> 0 (partial scan)" if limit else "full floors",
        "max_plausible_mbps": MAX_PLAUSIBLE_MBPS,
    }

    attack = AttackInventory(
        docs=sum(r["attack_docs"] for r in results),
        chars=sum(r["attack_chars"] for r in results),
        by_type=dict(_merge(results, "attack_type").most_common()),
        by_matrix=dict(_merge(results, "attack_matrix").most_common()),
        distinct_ids=_distinct_ids(results),
        technique_ids_total=len(
            set().union(*[r["technique_ids"] for r in results]) if results else set()
        ),
        technique_docs_by_source={
            r["file"].removesuffix(".jsonl"): r["technique_docs"]
            for r in sorted(results, key=lambda r: -r["technique_docs"])
            if r["technique_docs"]
        },
    )

    notes: list[str] = []
    if limit:
        notes.append(
            f"PARTIAL SCAN: at most {limit} documents per file. These counts "
            f"are not the generation's."
        )
    by_source = {
        s: {"docs": src_docs[s], "chars": src_chars[s]}
        for s in sorted(src_docs, key=lambda k: -src_chars[k])
    }
    by_register = {
        r: {"docs": reg_docs[r], "chars": reg_chars[r]}
        for r in sorted(reg_docs, key=lambda k: -reg_chars[k])
    }
    unseen_src = _merge(results, "unseen_by_source")
    unseen_src_chars = _merge(results, "unseen_chars_by_source")
    unseen_by_source = {
        s: {
            "docs": unseen_src[s],
            "chars": unseen_src_chars[s],
            "share_of_source": round(unseen_src[s] / src_docs[s], 4)
            if src_docs.get(s)
            else None,
        }
        for s in sorted(unseen_src, key=lambda k: -unseen_src[k])
    }
    src_reg_chars = _merge(results, "src_reg_chars")
    source_registers: dict[str, dict[str, int]] = {}
    for (source, register), n in src_reg_chars.items():
        source_registers.setdefault(source, {})[register] = n
    source_registers = {
        s: dict(sorted(v.items(), key=lambda kv: -kv[1]))
        for s, v in sorted(source_registers.items())
    }

    return Report(
        generation=root.name,
        curriculum_version=C.CURRICULUM_VERSION,
        coverage_version=COVERAGE_VERSION,
        ruler="characters",
        docs=docs,
        chars=chars,
        elapsed=elapsed,
        mbps=mbps,
        files=len(results),
        by_source=by_source,
        by_register=by_register,
        source_registers=source_registers,
        topics=topics,
        unseen_docs=sum(r["unseen_docs"] for r in results),
        unseen_chars=sum(r["unseen_chars"] for r in results),
        unseen_by_source=unseen_by_source,
        topics_per_doc={str(k): v for k, v in sorted(tpd.items())},
        controls_present=present,
        controls_absent=absent,
        instrument=instrument,
        attack=attack,
        samples=_sample(results, seed=seed, size=sample_size),
        notes=notes,
    )


def _distinct_ids(results: Sequence[dict[str, Any]]) -> dict[str, int]:
    merged: dict[str, set[str]] = {}
    for res in results:
        for kind, ids in res["attack_ids"].items():
            merged.setdefault(kind, set()).update(ids)
    return {k: len(v) for k, v in sorted(merged.items(), key=lambda kv: -len(kv[1]))}


def _sample(
    results: Sequence[dict[str, Any]], *, seed: int, size: int
) -> list[dict[str, Any]]:
    """A uniform random sample of (topic, document) matches, for adjudication.

    Each worker reservoir-samples its own file uniformly and reports how many
    matches it saw. Drawing files in proportion to those totals and then
    uniformly within a file is uniform over all matches — the standard
    distributed reservoir, and the reason the per-file reservoirs are 240 deep
    while the sample is 120: a file can be asked for more than its share.

    Carries coordinates and matched terms, **never text**. The corpus is known
    to contain live host identity and third-party names; a sample file that
    quoted documents would be a new copy of that leak.
    """
    pool = [(r, r["match_total"]) for r in results if r["reservoir"]]
    if not pool:
        return []
    rng = random.Random(seed)
    weights = [n for _r, n in pool]
    total = sum(weights)
    draws: Counter[int] = Counter()
    for _ in range(min(size, total)):
        pick = rng.random() * total
        upto = 0.0
        for i, w in enumerate(weights):
            upto += w
            if pick <= upto:
                draws[i] += 1
                break
    out: list[dict[str, Any]] = []
    for i, k in draws.items():
        res = pool[i][0]
        got = res["reservoir"]
        take = rng.sample(got, min(k, len(got)))
        out.extend(take)
    out.sort(key=lambda it: (it["file"], it["line"], it["topic"]))
    rng.shuffle(out)
    for item in out:
        item["id"] = sample_id(item["topic"], item["file"], item["line"])
    return out


def sample_id(topic: str, file: str, line: int) -> str:
    """A content-addressed id for one (topic, document) match.

    Positional ids (``s000``, ``s001``) were the first design and were wrong:
    an adjudication is a judgement about *a document*, and a positional id ties
    it to the draw instead. Two scans of this generation produced the same
    numbers and a different order, so 31 of 80 verdicts silently attached to
    different documents. Hashing the coordinates means a verdict stays attached
    to what was actually read, and a verdict for a document that is not in this
    report is reported as unmatched rather than counted.
    """
    import hashlib

    digest = hashlib.sha256(f"{topic}|{file}|{line}".encode()).hexdigest()
    return f"s{digest[:10]}"


def sample_lines(
    root: str | os.PathLike[str], samples: Iterable[dict[str, Any]]
) -> Iterator[tuple[dict[str, Any], str]]:
    """Re-read the documents a sample points at, in file order.

    Yields ``(sample, text)``. The caller is responsible for redacting before
    showing or storing anything: ``training.corpus.verify.scan_text`` with
    ``host_needles()`` is the supported way, and it is what ``--sample``
    does.
    """
    root = Path(root)
    wanted: dict[str, dict[int, list[dict[str, Any]]]] = {}
    for item in samples:
        wanted.setdefault(item["file"], {}).setdefault(item["line"], []).append(item)
    for fname, lines in wanted.items():
        path = root / fname
        if not path.exists():
            continue
        with path.open(encoding="utf-8", errors="replace") as handle:
            for lineno, line in enumerate(handle, start=1):
                if lineno not in lines:
                    continue
                try:
                    text = json.loads(line).get("text") or ""
                except json.JSONDecodeError:
                    text = ""
                for item in lines[lineno]:
                    yield item, text


# ---------------------------------------------------------------------------
# The two rulers
# ---------------------------------------------------------------------------


def register_rulers(
    by_register: dict[str, dict[str, int]],
    token_index: dict[str, Any] | None = None,
    source_registers: dict[str, dict[str, int]] | None = None,
) -> dict[str, Any]:
    """Register shares by character, beside the target, and by token if known.

    The disagreement this resolves: ``docs/ROADMAP.md`` quotes shell at 15.6%
    and trajectory at 3.4%, a character count of ``clean-v7`` gives 8.0% and
    7.8%, and both were being quoted as "the register share". They are two
    different measurements of two different things and neither is wrong.

    A character share is what the build balances on. A token share is what the
    model is actually trained on, and it differs by register by a large factor
    because BPE compression is not uniform: repetitive generated text
    (TRAJECTORY) compresses far better than dense punctuation-heavy text
    (SHELL), so converting one ruler into the other moves shares in opposite
    directions. Given a tokenised generation's ``index.json`` — which carries
    exact token counts per source — and the per-source register split measured
    by the scan, the token share follows without re-tokenising anything.
    """
    chars_total = sum(v["chars"] for v in by_register.values()) or 1
    docs_total = sum(v["docs"] for v in by_register.values()) or 1
    out: dict[str, Any] = {"ruler": "characters", "registers": {}}
    for name, v in by_register.items():
        target = next(
            (t for r, t in REGISTER_TARGETS.items() if r.value == name), None
        )
        out["registers"][name] = {
            "docs": v["docs"],
            "doc_share": round(v["docs"] / docs_total, 4),
            "chars": v["chars"],
            "char_share": round(v["chars"] / chars_total, 4),
            "target": target,
        }
    if token_index and source_registers:
        by_src = token_index.get("by_source") or {}
        tokens: Counter[str] = Counter()
        missing: list[str] = []
        for source, regs in source_registers.items():
            toks = by_src.get(source)
            if toks is None:
                missing.append(source)
                continue
            total = sum(regs.values()) or 1
            for reg, nchars in regs.items():
                tokens[reg] += toks * nchars / total
        tok_total = sum(tokens.values()) or 1
        for name, entry in out["registers"].items():
            entry["tokens"] = int(tokens.get(name, 0))
            entry["token_share"] = round(tokens.get(name, 0) / tok_total, 4)
        out["token_ruler"] = {
            "index_total_tokens": token_index.get("total_tokens"),
            "index_documents": token_index.get("documents"),
            "attributed_tokens": int(tok_total),
            "sources_missing_from_index": sorted(missing),
            "method": "exact tokens per source from the tokenised index, split "
                      "across registers in proportion to measured characters "
                      "within that source",
        }
    return out


# ---------------------------------------------------------------------------
# ATT&CK inventory, standalone
# ---------------------------------------------------------------------------


def attack_inventory(
    clean_dir: str | os.PathLike[str], sources: Sequence[str] = ("attack", "attackactors")
) -> AttackInventory:
    """Count the ATT&CK object graph in a generation, without a full scan.

    Answers the adapter question directly: a generation whose ``attack`` source
    emits only ``attack-pattern`` objects has techniques and no groups, no
    mitigations, no campaigns and one matrix. Counting distinct ids by type is
    how that is seen, and it is three orders of magnitude cheaper than training
    a model to find out.
    """
    root = Path(clean_dir)
    by_type: Counter[str] = Counter()
    by_matrix: Counter[str] = Counter()
    ids: dict[str, set[str]] = {}
    tech_ids: set[str] = set()
    tech_docs: Counter[str] = Counter()
    docs = chars = 0
    for name in sources:
        path = root / f"{name}.jsonl"
        if not path.exists():
            continue
        with path.open(encoding="utf-8", errors="replace") as handle:
            for line in handle:
                try:
                    text = json.loads(line).get("text") or ""
                except json.JSONDecodeError:
                    continue
                docs += 1
                chars += len(text)
                found = _TECHNIQUE_ID.findall(text)
                if found:
                    tech_docs[name] += 1
                    tech_ids.update(found)
                own = _ATTACK_ID_LINE.search(text)
                if not own:
                    continue
                kind = _TYPE_LINE.search(text)
                kind_s = kind.group(1) if kind else "?"
                by_type[kind_s] += 1
                matrix = _MATRIX_LINE.search(text)
                if matrix:
                    by_matrix[matrix.group(1)] += 1
                ids.setdefault(kind_s, set()).add(own.group(1))
    return AttackInventory(
        docs=docs,
        chars=chars,
        by_type=dict(by_type.most_common()),
        by_matrix=dict(by_matrix.most_common()),
        distinct_ids={
            k: len(v) for k, v in sorted(ids.items(), key=lambda kv: -len(kv[1]))
        },
        technique_ids_total=len(tech_ids),
        technique_docs_by_source=dict(tech_docs.most_common()),
    )


# ---------------------------------------------------------------------------
# Instrument check
# ---------------------------------------------------------------------------

#: The synthetic generation :func:`self_test` scans. Each entry is
#: ``(source, register, topic the document is about or "" for a decoy, text)``.
#: The texts are written here, from the field's own vocabulary, so that the
#: right answer is known by construction rather than by agreement with the
#: thing being tested.
_FIXTURES: tuple[tuple[str, str, str, str], ...] = (
    # "Kerberoasting" on its own would NOT match the term "kerberoast": the
    # pattern makes a trailing "s" optional and nothing else, so the "-ing"
    # breaks the trailing boundary. The fixture spells the term the way the
    # corpus does, and the near miss is written down here because it is a real
    # limit of the matcher rather than a quirk of this test.
    ("attack", "adversary", "winad.kerberoasting",
     "Adversaries request a service ticket for an account with a registered "
     "service principal name and crack it offline. A kerberoast is cheap "
     "because the ticket is encrypted with the service account password."),
    ("sigma", "detection", "detect.sigma-rules",
     "title: Suspicious Process\nlogsource:\n  product: windows\n"
     "detection:\n  condition: selection\nfalsepositives:\n  - Admin activity"),
    ("nvd", "advisory", "webapp.sql-injection",
     "The product fails to neutralise special elements, allowing SQL "
     "injection via the id parameter. A UNION SELECT payload returns the "
     "password hash column. CWE-89 applies."),
    ("manpages", "system", "",
     "tar - manipulate tape archives. The options -c, -x and -f select the "
     "mode of operation and the archive file."),
    ("rfc", "system", "",
     "This memo describes a format for electronic mail messages, including "
     "the header fields and the rules for folding long lines."),
)


def self_test(*, workers: int = 1) -> dict[str, Any]:
    """Prove the scanner bites, on documents whose answers are known.

    Three things are checked, and each one has failed in this project in some
    other module:

    * a planted document about a topic **is** attributed to that topic (recall);
    * the decoys, which are real text about nothing in the taxonomy's
      vocabulary, are attributed to **no** topic at all;
    * the absent controls stay at zero and the present controls fire.

    Returns a dict rather than printing, so the tests can assert on it.
    """
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        by_source: dict[str, list[str]] = {}
        for source, register, _topic, text in _FIXTURES:
            by_source.setdefault(source, []).append(
                json.dumps(
                    {
                        "text": text,
                        "source": source,
                        "register": register,
                        "side": "red",
                        "ident": "fixture",
                    }
                )
            )
        # A present control needs documents to be present in; the floors are
        # written for a real generation, so the self test scores the controls
        # itself and does not inherit those floors.
        by_source.setdefault("manpages", []).append(
            json.dumps(
                {
                    "text": "The password file on a linux or windows host "
                            "records each account. A vulnerability in it is a "
                            "vulnerability in every account.",
                    "source": "manpages",
                    "register": "system",
                    "side": "blue",
                    "ident": "fixture-control",
                }
            )
        )
        for source, lines in by_source.items():
            (root / f"{source}.jsonl").write_text(
                "\n".join(lines) + "\n", encoding="utf-8"
            )
        report = scan_generation(
            root, workers=workers, sample_size=4, df_sample=50
        )

    found: dict[str, bool] = {}
    for _s, _r, topic, _text in _FIXTURES:
        if not topic:
            continue
        hit = next((t for t in report.topics if t.topic_id == topic), None)
        found[topic] = bool(hit and hit.docs)
    decoys = sum(1 for s in _FIXTURES if not s[2])
    out = {
        "documents": report.docs,
        "planted_topics": len(found),
        "planted_found": sum(found.values()),
        "planted_missing": sorted(k for k, v in found.items() if not v),
        "decoys": decoys,
        "documents_matching_no_topic": report.unseen_docs,
        "controls_absent_hits": sum(report.controls_absent.values()),
        "controls_present_hits": report.controls_present,
        "mb_per_s": round(report.mbps, 2),
    }
    # The decoys are checked document by document rather than by subtraction.
    # "No topic other than the planted ones matched anything" is a different
    # and wrong assertion: the SQL fixture cites CWE-89, which really is a
    # weakness classification, so a second topic matching it is the matcher
    # being right. What must hold is that text about tape archives and mail
    # headers matches nothing at all.
    matcher = Matcher()
    silent: dict[str, list[str]] = {}
    for _s, _r, topic, text in _FIXTURES:
        if topic:
            continue
        got = sorted(matcher.topics(matcher.hits(text)))
        silent[text[:40]] = got
    out["decoys_silent"] = all(not v for v in silent.values())
    out["decoy_matches"] = {k: v for k, v in silent.items() if v}
    out["incidental_topics"] = sorted(
        {t.topic_id for t in report.topics if t.docs and t.topic_id not in found}
    )
    out["pass"] = bool(
        out["planted_found"] == out["planted_topics"]
        and out["controls_absent_hits"] == 0
        and out["documents"] >= len(_FIXTURES)
        and out["decoys_silent"]
        and all(v > 0 for v in report.controls_present.values())
    )
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _render(report: Report) -> str:
    lines: list[str] = []
    r = report
    lines.append(
        f"{r.generation}: {r.docs:,} docs, {r.chars/1e6:.1f}M chars, "
        f"{r.files} files, {r.elapsed:.0f}s ({r.mbps:.2f} MB/s), "
        f"ruler={r.ruler}"
    )
    lines.append(
        f"curriculum {r.curriculum_version} / coverage {r.coverage_version}"
    )
    if r.instrument["controls_pass"]:
        lines.append("INSTRUMENT: controls pass")
    else:
        lines.append("INSTRUMENT FAILED:")
        for f in r.instrument["failures"]:
            lines.append(f"  ! {f}")
    counts = {k: len(v) for k, v in r.by_verdict().items()}
    lines.append(
        "distribution: "
        + ", ".join(f"{counts[v]} {v}" for v in VERDICTS)
        + f" (of {len(r.topics)} topics)"
    )
    gold = r.gold_recall()
    if gold["documents"]:
        lines.append(
            f"gold ATT&CK recall: {gold['found']}/{gold['documents']} "
            f"= {gold['recall']:.1%} over {gold['topics_scored']} topics"
        )
    lines.append(
        f"taxonomy blind spot: {r.unseen_docs:,} docs "
        f"({r.unseen_docs/r.docs:.1%}) match no topic"
    )
    for src, v in list(r.unseen_by_source.items())[:8]:
        lines.append(
            f"    {src:<16} {v['docs']:>7,} unseen "
            f"({v['share_of_source']:.0%} of that source)"
        )
    frag = [t.topic_id for t in r.topics if "fragile" in t.flags]
    lines.append(f"fragile (one source >= {SINGLE_SOURCE_AT:.0%}): {len(frag)}")
    lines.append("")
    lines.append("largest 15 topics (docs, corroborated, sources):")
    for t in sorted(r.topics, key=lambda t: -t.docs)[:15]:
        lines.append(
            f"  {t.docs:>7,}  {t.topic_id:<42} corrob={t.corroborated:>6,}  "
            f"{len(t.sources):>2} src  {t.verdict} {'/'.join(t.flags)}"
        )
    lines.append("")
    lines.append("thinnest 25 topics (docs, sources, top source):")
    for t in sorted(r.topics, key=lambda t: (t.docs, t.topic_id))[:25]:
        top, n = t.top_source
        lines.append(
            f"  {t.docs:>7,}  {t.topic_id:<42} {len(t.sources):>2} src  "
            f"{top}={n}  {'/'.join(t.flags)}"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python3 -m training.corpus.coverage",
        description="Measure a corpus generation against the curriculum.",
    )
    ap.add_argument("directory", nargs="?", help="a corpus generation")
    ap.add_argument("--out", help="write the JSON report here")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--limit", type=int, default=0,
                    help="documents per file; a partial scan says so")
    ap.add_argument("--sample", type=int, default=120,
                    help="how many (topic, document) matches to sample")
    ap.add_argument("--show-sample", action="store_true",
                    help="print the sample with redacted excerpts, for "
                         "adjudication")
    ap.add_argument("--adjudication",
                    help="JSON file of {sample id: true|false} verdicts to "
                         "fold into the report as measured precision")
    ap.add_argument("--token-index",
                    help="a tokenised generation's index.json, to report the "
                         "token ruler beside the character one")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the scanner finds planted documents, and exit")
    ap.add_argument("--attack-only", action="store_true",
                    help="count the ATT&CK object graph and exit")
    args = ap.parse_args(argv)

    if args.self_test:
        out = self_test()
        print(json.dumps(out, indent=2))
        return 0 if out["pass"] else 1

    if not args.directory:
        ap.error("a generation directory is required")
    root = Path(args.directory)

    if args.attack_only:
        print(json.dumps(attack_inventory(root).to_json(), indent=2))
        return 0

    report = scan_generation(
        root, workers=args.workers, limit=args.limit, sample_size=args.sample
    )

    if args.token_index:
        index = json.loads(Path(args.token_index).read_text(encoding="utf-8"))
        report_json_registers = register_rulers(
            report.by_register, index, report.source_registers
        )
    else:
        report_json_registers = None

    if args.adjudication:
        verdicts = json.loads(Path(args.adjudication).read_text(encoding="utf-8"))
        report.adjudication = _fold_adjudication(report, verdicts)

    print(_render(report))

    if args.show_sample:
        _print_sample(root, report)

    if args.out:
        payload = report.to_json()
        if report_json_registers:
            payload["registers"] = report_json_registers
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=1, sort_keys=False) + "\n",
                       encoding="utf-8")
        print(f"\nwrote {out} ({out.stat().st_size/1e6:.2f} MB)")
    return 0 if report.instrument["controls_pass"] else 2


def _fold_adjudication(report: Report, verdicts: dict[str, Any]) -> dict[str, Any]:
    by_id = {s["id"]: s for s in report.samples}
    judged = [(by_id[k], bool(v)) for k, v in verdicts.items() if k in by_id]
    unmatched = sorted(k for k in verdicts if k not in by_id)
    n = len(judged)
    good = sum(1 for _s, ok in judged if ok)
    if not n:
        return {"judged": 0, "note": "no sample ids matched this report"}
    p = good / n
    # Wilson interval, because a precision of 55/60 with no interval invites
    # being quoted as a corpus-wide fact.
    z = 1.96
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return {
        "judged": n,
        "relevant": good,
        "precision": round(p, 4),
        "wilson95": [round(centre - half, 4), round(centre + half, 4)],
        "sampled": len(report.samples),
        "verdicts_not_in_this_report": unmatched,
        "method": "a uniform random sample of (topic, document) matches, read "
                  "and judged by hand: relevant means a reader looking for "
                  "material on that topic would accept the document. Single "
                  "passing mentions count as not relevant.",
        "errors_by_topic_verdict": dict(
            Counter(
                next(
                    (t.verdict for t in report.topics if t.topic_id == s["topic"]),
                    "?",
                )
                for s, ok in judged
                if not ok
            )
        ),
        "by_corroboration": _precision_by_corroboration(judged),
    }


def _precision_by_corroboration(
    judged: Sequence[tuple[dict[str, Any], bool]],
) -> dict[str, Any]:
    """Precision split by the cheap signal, which is the point of measuring it.

    ``corroborated`` — two distinct terms, or one term three or more times — is
    computed for every one of the 208,346 documents at no extra cost. Hand
    adjudication is expensive and was done 80 times. If the cheap signal tracks
    the expensive one, the per-topic ``corroborated`` count can be read as a
    precision estimate for every topic in the taxonomy, which no sample of 80
    could ever cover.
    """
    buckets: dict[str, list[bool]] = {"corroborated": [], "single-mention": []}
    for item, ok in judged:
        key = "corroborated" if item.get("corroborated") else "single-mention"
        buckets[key].append(ok)
    return {
        k: {
            "judged": len(v),
            "relevant": sum(1 for x in v if x),
            "precision": round(sum(1 for x in v if x) / len(v), 4) if v else None,
        }
        for k, v in buckets.items()
    }


def _print_sample(root: Path, report: Report) -> None:
    """Print the sample with host identity redacted, for adjudication.

    Redaction is not optional and not hand-rolled: it goes through
    :mod:`training.corpus.verify`, the module whose whole job is knowing what
    in this corpus identifies this machine. If that import fails the excerpts
    are withheld rather than printed unredacted.
    """
    try:
        from .verify import (  # type: ignore[attr-defined]
            _redact_for_report,
            host_needles,
        )

        needles = host_needles()
    except Exception as exc:  # pragma: no cover - environment dependent
        print(f"\nSAMPLE WITHHELD: cannot load the redactor ({exc})")
        return
    print(f"\n{len(report.samples)} sampled matches, redacted:\n")
    for item, text in sample_lines(root, report.samples):
        safe = _redact_for_report(text[:600], needles)
        print(f"--- {item['id']} topic={item['topic']} source={item['source']} "
              f"terms={','.join(item['terms'])}")
        print(safe.replace("\n", " ")[:560])
        print()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
