"""whetbench — does the model actually know any security, or does it just sound like it?

Loss curves say a model is learning something. Generation samples say what, but
cherry-picked ones say whatever you want them to. This measures capabilities that
are **mechanically checkable**, so the answer is evidence rather than an opinion
about how plausible some text looked.

Every probe here has a ground truth that exists independently of the model:

*Schema fidelity.* A CVSS v3 vector is a grammar. Either the eight metrics are
present, in order, with legal values, or they are not. No judgement required.

*Identifier reality.* ``T1547.001`` either is in the real ATT&CK catalogue or it
is invented. The catalogue is on disk. A model that emits well-formed but
non-existent technique ids has learned the *shape* of an identifier without the
referent, and that distinction is invisible to loss and obvious here.

*Action validity.* The one task the model exists to do: emit an action the verb
registry accepts. ``REGISTRY.parse`` raises on a hallucinated verb, a missing
parameter or an invented parameter name, so the pass rate is exact.

*Register routing.* Prompted with PowerShell, does it continue in PowerShell —
or does it slide into whatever register dominates the corpus? This is the probe
that caught the corpus skew: the first ``tiny`` run answered CVE records to a
``Get-Process`` prompt, because advisory text outweighed shell text twelve to
one. Loss never mentioned it.

**On checking the instrument.** Every probe here scores the model's
*continuation* and nothing else, and ``run_bench`` refuses to start until two
properties hold. First, no probe's own prompt satisfies its own checker: both
routing probes once reported 5/5 against any checkpoint whatsoever, because the
scorer was handed ``prompt + continuation`` and the ``Get-Process`` prompt
contains the marker ``get-``. Second, no probe prompt carries its own ``<|bos|>``,
because the generator prepends one and two of them are a prefix that appears in
no trajectory. Both bugs produced numbers that were reported as capability. A
probe that can pass before the model has emitted a token measures nothing, and
measuring nothing quietly is the worst thing an instrument can do here.

**On honesty.** Scores are reported per probe and never averaged into one number.
A single headline invites the reading "83% good", which is meaningless when the
probes measure unrelated things and a 14.6M model is expected to fail most of
them. The point of a benchmark on a small model is to show *which* capability
appeared first, not to award a grade.

**On the bench being too small to steer by, which is what this wave fixed.**
A whole night was spent reading moves off this instrument, and most of the moves
were not there. The table said::

    verb-choice      3/8  ->  2/8
    shell-routing   10/10 ->  1/5
    detection-routing 10/10 -> 0/5
    attck-real       0/10 ->  2/5

Three of those four rows compare *different instruments*: the sample count moved
from ten to five between the runs, so ``10/10 -> 1/5`` is not a regression, it is
an unanswerable question. The one row measured on a fixed scale, ``verb-choice``,
moved by a single sample out of eight — which is noise at that n, and was read as
a decline. Four things follow, and all four are mechanical here rather than
advisory:

*Enough samples.* The judgement probes run at n >= 100 (``verb-choice`` at 114
tasks) and the generative probes at n = 100, up from five. :func:`wilson` prints
a 95% interval beside every rate, because ``2/8`` with no interval is exactly
what let a one-sample move read as a capability change.

*A floor beside every score, or no report at all.* A rate means nothing without
the thing it is being compared against, so :class:`ProbeScore` **cannot be
constructed** without its controls: a chance floor (a uniform-random pick from
the legal verb set, or an untrained random-init model of the same shape) and a
degenerate floor (the score of the best constant a cheater could emit). The
report renders :class:`ProbeScore` objects and nothing else, so a table with no
floor in it is not something this module can produce.

*An instrument digest.* :func:`instrument_digest` hashes probe names, prompts,
predicate source, sample counts and the verb-choice task bank into every result.
:func:`assert_comparable` **refuses** to put two runs side by side when the
digests differ. The ``10/10 -> 1/5`` confusion existed because nothing recorded
that the probe had changed; now something does, and it declines to guess.

*Perplexity is not a cross-generation number.* :func:`format_perplexity_table`
refuses to print two ``val_ppl`` figures together unless they share a tokenizer
digest and a corpus identity. ``small-v8`` at 4.96 looks far better than
``tiny-v9`` at 9.52 and the comparison is meaningless: different tokenizers,
different vocabularies fitted to different corpora, and perplexity is a function
of the tokenization. The bench probes score *behaviour* and are comparable across
checkpoints, which is the whole reason this file is worth widening.

**What the widening found, and it is not flattering to this file.** Every one of
the eight generative probes is won outright by a one-line constant:
``CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`` scores 100% on ``cvss-vector``,
``CVE-2024-0001`` scores 100% on ``cve-shape``, ``Get-Item`` scores 100% on
``shell-routing``, and a single hardcoded action object scores 100% on the probe
labelled THE TASK. Measured, not assumed — see ``degenerate`` on each probe. So
those eight probes are **necessary-condition probes**: a low score is evidence of
absence, a high score is not evidence of capability, because a lookup table would
beat the model. They are kept, because evidence of absence is what caught the
corpus skew, and they are now printed with the constant's score next to them so
nobody can read a high rate as knowledge. ``verb-choice`` is the only probe here
whose degenerate score is low (8.8%, against a 6.7% uniform-random floor), and
that is because constrained decoding makes validity free and leaves only the
judgement — which is the design the rest of the file should grow toward.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import inspect
import json
import math
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence
from whetstone.paths import data_root

# NOTE: `assert_instrument`, `measure` and `verb_choice_measure` were named here
# by the widening pass and never written — the agent doing it hit a usage limit
# mid-file. They are removed from __all__ rather than left in it, because an
# __all__ that names a missing function makes `import *` raise and advertises an
# API that is not there. What IS shipped and complete: the n=100 probes, Wilson
# intervals, the Floor type with FloorMissingError so a report cannot omit its
# control, instrument_digest + InstrumentMismatch, the perplexity comparability
# guard (assert_comparable / TokenizerIdentity / PerplexityRow), and
# assert_probes_can_pass. The missing three were the convenience wrappers for
# running the whole thing in one call; `run_bench` does the work today.
__all__ = ["Probe", "PROBES", "ProbeDesignError", "assert_probes_can_fail",
           "assert_prompts_carry_no_bos", "assert_probes_can_pass",
           "assert_verb_choice_tasks_are_answerable",
           "assert_comparable", "run_bench",
           "wilson", "Floor", "ProbeScore", "BenchReport",
           "FloorMissingError", "InstrumentMismatch", "ComparabilityError",
           "instrument_digest", "tokenizer_identity", "TokenizerIdentity",
           "PerplexityRow", "format_perplexity_table",
           "VERB_CHOICE_TASKS", "verb_choice_score",
           "uniform_random_verb_floor", "best_constant_verb",
           "random_init_model", "CHANCE_KINDS"]


def _catalogue() -> None:
    """Import the verb catalogue for its registration side effect.

    ``import whetstone.verbs`` with a ``# noqa`` was the idiom here, and pyflakes
    does not read ``noqa`` — it reported the import unused in four places in this
    file, which is four lines of noise in a lint run that is supposed to be
    readable. Calling it says the same thing out loud: the module is imported to
    populate ``REGISTRY``, and nothing in this file touches its namespace.
    """
    importlib.import_module("whetstone.verbs")


# --------------------------------------------------------------------------
# intervals — a rate with no interval is what let a one-sample move read as a
# capability change
# --------------------------------------------------------------------------


def wilson(passed: int, of: int, *, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for ``passed`` successes out of ``of`` trials.

    Wilson rather than the textbook normal approximation, because the normal one
    is wrong exactly where this benchmark lives. At ``0/5`` it gives the interval
    ``[0, 0]`` — zero width, total certainty, from five samples — and at ``5/5``
    it gives ``[1, 1]``. Half the rows in every table this file has ever printed
    were 0/5 or 5/5, so the approximation that collapses on those rows is the one
    that would have concealed the problem it was added to expose. Wilson keeps
    width at the boundaries: ``0/5`` is ``[0.000, 0.434]`` and ``5/5`` is
    ``[0.566, 1.000]``, which says what five samples actually support.

    The arithmetic is the closed form, so there is nothing to converge and no
    dependency to add::

        centre = (k + z²/2) / (n + z²)
        half   = z/(n + z²) · √(k(n−k)/n + z²/4)

    ``of == 0`` returns the whole unit interval rather than raising. A probe with
    no samples is a probe that measured nothing, and the honest rendering of
    "measured nothing" is "anywhere between 0 and 1" — not a crash, and
    emphatically not a point estimate.
    """
    if of <= 0:
        return 0.0, 1.0
    if passed < 0 or passed > of:
        raise ValueError(
            f"{passed} successes out of {of} trials is not a rate; a count "
            "outside its own denominator is an arithmetic bug upstream, and "
            "this function would otherwise return a confident-looking interval "
            "computed from it")
    n = float(of)
    k = float(passed)
    z2 = z * z
    denom = n + z2
    centre = (k + z2 / 2.0) / denom
    half = (z / denom) * math.sqrt(k * (n - k) / n + z2 / 4.0)
    return max(0.0, centre - half), min(1.0, centre + half)


def _pct(x: float) -> str:
    return f"{100.0 * x:5.1f}%"


def _interval_text(passed: int, of: int) -> str:
    lo, hi = wilson(passed, of)
    return f"[{_pct(lo).strip()} – {_pct(hi).strip()}]"


# --------------------------------------------------------------------------
# checkers — each returns (passed, detail)
# --------------------------------------------------------------------------

_CVSS3 = re.compile(
    r"CVSS:3\.[01]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]"
)
_TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")
_CWE = re.compile(r"\bCWE-\d{1,4}\b")


def _real_techniques() -> set[str]:
    """Technique ids that genuinely exist, read from the cached ATT&CK bundle.

    Falls back to an empty set if the bundle is absent, and the probe then
    reports itself as skipped rather than silently passing everything — a skip
    that looks like a pass is the one outcome a benchmark must never produce.
    """
    import gzip

    for candidate in (
        data_root() / "corpus/raw/attack/enterprise-attack.json.gz",
        Path("data/corpus/raw/attack/enterprise-attack.json.gz"),
    ):
        if not candidate.is_file():
            continue
        try:
            with gzip.open(candidate, "rt", encoding="utf-8") as fh:
                bundle = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        out: set[str] = set()
        for obj in bundle.get("objects", ()):
            for ref in obj.get("external_references", ()) or ():
                ident = ref.get("external_id", "")
                if ref.get("source_name") == "mitre-attack" and _TECHNIQUE.fullmatch(ident):
                    out.add(ident)
        return out
    return set()


REAL_TECHNIQUES: set[str] = _real_techniques()


#: CVSS v2, which is a different grammar and not a broken v3: no ``CVSS:3.x``
#: prefix, an ``Au`` (Authentication) metric v3 replaced with ``PR``/``UI``, and
#: no ``S`` (Scope). Matched deliberately so a v2 vector can be REPORTED as one.
_CVSS2 = re.compile(r"AV:[NAL]/AC:[HML]/Au:[MSN]/C:[NPC]/I:[NPC]/A:[NPC]")


def check_cvss(text: str) -> tuple[bool, str]:
    """A syntactically complete CVSS v3 vector anywhere in the continuation.

    Still fails on anything that is not v3 — that is what the probe is for — but
    it now says WHICH failure, because the three were indistinguishable and the
    difference is the whole diagnosis.

    The model scored 0/5 here and the detail line read "no vector emitted" five
    times, which says the model cannot produce a CVSS vector. It can. It was
    emitting ``AV:N/AC:L/Au:N/C:P/I:P/A:P`` — a perfectly well-formed CVSS *v2*
    vector — and 44.7% of the CVSS vectors in the corpus it learned from are v2,
    so it had no reason to prefer otherwise. "Emitted the wrong version" and
    "emitted nothing" are different facts with different fixes: the first is a
    corpus composition problem, the second would be a capability problem. A
    probe that collapses them reports the wrong one, and this project has been
    misled by an instrument six times already.
    """
    m = _CVSS3.search(text)
    if m:
        return True, m.group(0)
    if (loose := re.search(r"CVSS:3\.[01]/\S+", text)):
        return False, f"malformed v3: {loose.group(0)[:48]}"
    if (v2 := _CVSS2.search(text)):
        return False, f"well-formed CVSS v2, not v3: {v2.group(0)}"
    return False, "no vector emitted"


def check_technique_real(text: str) -> tuple[bool, str]:
    """Emitted technique ids must exist in the real ATT&CK catalogue."""
    found = _TECHNIQUE.findall(text)
    if not found:
        return False, "no technique id emitted"
    if not REAL_TECHNIQUES:
        return False, "SKIP: ATT&CK bundle not available to check against"
    real = [t for t in found if t in REAL_TECHNIQUES]
    return bool(real), (f"{len(real)}/{len(found)} real — "
                        f"{', '.join(found[:4])}")


def check_cve_shape(text: str) -> tuple[bool, str]:
    m = _CVE.search(text)
    return (True, m.group(0)) if m else (False, "no well-formed CVE id")


def check_cwe_shape(text: str) -> tuple[bool, str]:
    m = _CWE.search(text)
    return (True, m.group(0)) if m else (False, "no CWE id")


def extract_json_object(text: str) -> str | None:
    """First balanced ``{...}`` in ``text``, or None.

    A non-greedy ``\\{.*?\\}`` cannot do this and the difference is not
    academic: an action is ``{"verb":"enum.host","params":{},"target":"..."}``
    and the lazy match stops at the ``}`` closing the empty ``params``, handing
    the parser ``{"verb":"enum.host","params":{}`` — invalid JSON. The benchmark
    scored a correct model 0/5 and reported "Expecting ',' delimiter" as though
    the model had produced malformed output. Brace depth, tracked properly, with
    string literals and escapes respected so a brace inside a value does not
    close the object.
    """
    start = text.find("{")
    if start < 0:
        return None
    depth = 0
    in_string = False
    escaped = False
    for i in range(start, len(text)):
        ch = text[i]
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None


def check_action_json(text: str) -> tuple[bool, str]:
    """The task the model exists for: emit an action the registry accepts."""
    from whetstone.actions import REGISTRY, SchemaError
    _catalogue()

    blob = extract_json_object(text)
    if blob is None:
        return False, "no JSON object emitted"
    try:
        payload = json.loads(blob)
    except json.JSONDecodeError as exc:
        return False, f"unparseable: {exc.msg} — {blob[:44]}"
    try:
        action = REGISTRY.parse(payload)
    except SchemaError as exc:
        return False, f"rejected: {str(exc)[:66]}"
    return True, action.render()[:70]


def _register_checker(markers: tuple[str, ...], label: str) -> Callable[[str], tuple[bool, str]]:
    """A substring vote on which register a continuation is written in.

    Substring matching is the weakest check in this file and it survives only
    because of where the text comes from: the *continuation alone*, from a
    prompt that contains none of these markers. Both of those conditions are
    load-bearing and both were once violated at the same time. ``run_bench``
    scored ``prompt + continuation``, and the ``PS C:\\> Get-Process | `` prompt
    contains ``get-`` while the ``logsource:`` prompt contains ``logsource``, so
    the two routing probes returned True before the model produced a single
    token and reported 5/5 on every checkpoint they were ever run against.

    Hence the prompts below carry no marker of their own, which is a stronger
    property than "do not concatenate": a model that has collapsed into echoing
    its prompt — the failure mode a small model reaches first — also scores
    zero, because repeating a prompt with no markers in it produces no hits.
    ``assert_probes_can_fail`` enforces the property on every run.
    """
    def check(text: str) -> tuple[bool, str]:
        hits = [m for m in markers if m.lower() in text.lower()]
        return bool(hits), (f"{label}: {', '.join(hits[:3])}" if hits
                            else f"drifted out of {label}")

    # The predicate IS the marker list, and ``inspect.getsource`` cannot see it:
    # both register checkers are closures over the same four lines above, so
    # hashing their source would give the two probes the same fingerprint and
    # would not change when a marker was added or dropped. Dropping ``set-``
    # from the shell list changed what the probe measures; a digest that did not
    # move for it would be a digest that lets an incomparable pair be compared.
    check.whetbench_fingerprint = ("register-vote", label, tuple(markers))
    return check


# The PowerShell half of this list grew when the prompt stopped being a pipeline
# fragment. `PS C:\> Get-Process | ` invited a continuation like
# `Where-Object { $_.CPU -gt 10 }`, so `$_` and `| select` covered most correct
# answers; a prompt that asks for a whole command invites `Restart-Service` or
# `Sort-Object`, and the old list scored both as drift. `-object` is one marker
# for the whole Select/Sort/Where/ForEach/Measure/Group-Object family.
#
# Every marker has to be a string that does not occur in ordinary advisory
# prose, because advisory prose is the *wrong* answer this probe exists to catch
# and a marker it matches would turn the probe back into one that cannot fail.
# That rules out several obvious candidates — `-force` lives inside
# "brute-force", `-service` inside "denial-of-service", `start-` inside
# "start-up" — and it is why `set-` was dropped rather than kept: matching is
# case-insensitive, so it fired on "Set-up guidance", scoring a paragraph of CVE
# prose as PowerShell. Narrowing it instead would mean enumerating `Set-Service`,
# `Set-ItemProperty` and the rest, which is the kind of list that goes stale.
#
# The cost is that `Set-Service`, `Start-Service` and `Test-Path` are correct
# PowerShell this list scores as drift. That bias is deliberate and it is the
# safe direction: a missed hit understates the model, a spurious hit overstates
# it, and this file exists because of the second.
check_shell = _register_checker(
    ("get-", "new-", "invoke-", "restart-", "-object", "-recurse",
     "-erroraction", "| select", "-command", "$_", "$env:", "sudo", "systemctl",
     "/etc/", "chmod", "grep", "ps -", "netstat", "launchctl"), "shell")
check_detection = _register_checker(
    ("detection:", "selection:", "condition:", "logsource", "eventid",
     "falsepositives", "level:", "index=", "| stats"), "detection")


# --------------------------------------------------------------------------
# probes
# --------------------------------------------------------------------------


@dataclass
class Probe:
    """One capability, its prompt, and a mechanical check."""

    name: str
    prompt: str
    #: Given the model's CONTINUATION, never the prompt and never the two of
    #: them joined. A checker that needed prompt context would be a checker
    #: whose prompt can answer it, which is the one thing a probe may not be.
    check: Callable[[str], tuple[bool, str]]
    #: What a pass actually demonstrates. Printed with the result so a number is
    #: never separated from its meaning.
    measures: str
    #: A continuation a competent model would plausibly produce, which this
    #: probe's checker MUST accept. The other direction of
    #: ``assert_probes_can_fail``: a probe no good answer can pass is as broken
    #: as one no bad answer can fail, and it fails in the more flattering
    #: direction for whoever is reporting a low score as "the model cannot do
    #: this". Enforced by :func:`assert_probes_can_pass` over the shipped set,
    #: and left defaulted so an ad-hoc fixture probe in a test can still be
    #: built to exercise one guard without satisfying all of them.
    exemplar: str = ""
    #: The cheapest constant a cheater could emit — a lookup table's answer,
    #: with no model behind it. Scored and PRINTED beside the real rate rather
    #: than assumed to fail, because for eight of the nine probes here it does
    #: not fail: it wins outright. A probe whose constant wins is a probe whose
    #: high scores mean nothing, and that is a fact about this instrument that
    #: belongs in its own output.
    degenerate: str | None = None
    samples: int = 100
    max_tokens: int = 90
    results: list[tuple[bool, str]] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for ok, _ in self.results if ok)

    @property
    def rate(self) -> float:
        return self.passed / len(self.results) if self.results else 0.0

    @property
    def skipped(self) -> bool:
        return bool(self.results) and all(
            d.startswith("SKIP") for _ok, d in self.results)


def _action_prompt() -> str:
    """A realistic trajectory prefix, ending at the point the model must act.

    Deliberately **without** a leading ``<|bos|>``. ``training.generate.generate``
    prepends the bos id itself and does so unconditionally, so writing one here
    too handed the model ``<|bos|><|bos|><|task|>…`` — verified against the real
    tokenizer as ids ``[1, 1, 4, …]``. Nothing in the corpus looks like that:
    ``render_trajectory`` opens with exactly one ``<|bos|>`` and ``training/sft``
    encodes that text as-is. A 14.6M model has no spare capacity to absorb a
    prefix shape it has never seen, so the probe labelled THE TASK was scoring a
    model that had been asked the question in a dialect it was never taught.

    ``verb_choice_score`` below keeps its explicit ``BOS`` and that is not an
    inconsistency: it goes through ``decode_action`` -> ``score_continuations``,
    which encodes the prompt bare and prepends nothing. The two generation paths
    genuinely differ, so the prompts must differ to arrive at the same token
    sequence. ``assert_prompts_carry_no_bos`` pins the ``generate`` half of that.
    """
    from whetstone.actions import REGISTRY, Intent, TargetKind
    _catalogue()

    from training.tokenizer.protocol import ACT, HOST, SCOPE, TASK, VERBS

    catalogue = "; ".join(
        f"{v.id}({', '.join(p.name for p in v.params)})"
        for v in REGISTRY.select(intent=Intent.OBSERVE)
        if v.target is TargetKind.HOST)[:400]
    return (f"{TASK}Find anything on this host that runs without a human "
            f"starting it.{HOST}macos{SCOPE}observe; loopback only; no red "
            f"verbs{VERBS}{catalogue}{ACT}")


_ACTION_PROMPT = _action_prompt()


PROBES: list[Probe] = [
    # The prompt is NVD-shaped on purpose. A bare "CVE-2024-" used to elicit an
    # NVD record because NVD dominated the advisory register; it now elicits a
    # GHSA one — id, then references and dates — because ghsa is 14,509
    # documents against nvd's share, and GHSA records carry no `vector:` line at
    # all. The probe scored 0/5 and the model had not forgotten anything: given
    # `cvss: 8.8 HIGH` it still emits a vector. A probe whose result depends on
    # which source happens to dominate is measuring corpus composition and
    # reporting it as capability, so it now asks for the thing it is named
    # after. That makes it incomparable with scores recorded before this change,
    # which is the honest trade: the earlier numbers measured something else.
    Probe("cvss-vector", "CVE-2024-21412\ncvss: 9.8 CRITICAL\n",
          check_cvss,
          "can produce a grammatically valid CVSS v3 vector — 8 metrics, in "
          "order, legal values",
          exemplar="vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n"
                   "cwe: CWE-693 Protection Mechanism Failure\n",
          degenerate="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    Probe("cve-shape", "A new vulnerability was published as ",
          check_cve_shape,
          "has learned the CVE identifier format",
          exemplar="CVE-2024-21412, a SmartScreen bypass reported in February.",
          degenerate="CVE-2024-0001"),
    Probe("cwe-shape", "CVE-2023-4863\ncvss: 8.8 HIGH\n",
          check_cwe_shape,
          "associates a weakness class with a vulnerability record",
          exemplar="cwe: CWE-787 Out-of-bounds Write\nproduct: libwebp\n",
          degenerate="CWE-79"),
    Probe("attck-real", "The adversary used technique ",
          check_technique_real,
          "emits ATT&CK ids that EXIST from an UNCUED prompt. Reads as a "
          "knowledge probe and is really a robustness one — see attck-cued",
          exemplar="T1547.001 to survive reboot, then T1078.004 for access.",
          degenerate="T1547.001"),
    # Two probes because one number was answering two questions and getting
    # both wrong. attck-real went 2/5 on v5 and 0/5 on v6, which reads as the
    # model forgetting ATT&CK. It has not. Asked with this prompt it emits no
    # technique id at all and completes into reference URLs and CVE links,
    # because "The adversary used technique " resembles nothing in the corpus
    # and the model falls into the register that dominates it — advisory at
    # 16.2% of tokens against adversary's 4.2%.
    #
    # Handed a shape it has actually seen, it produces real ids immediately:
    # nine of nine verified against the attack source's 1,116 distinct
    # technique ids, including the whole T1078.001-.004 sub-technique family in
    # order. So the knowledge is there and the first probe cannot see it.
    #
    # This prompt is an ATT&CK mitigation page, which is a real document shape
    # in the corpus and carries no technique id of its own — assert_probes_can_fail
    # rules out the obvious cue, a list of ids with one missing, because that
    # prompt would satisfy this checker on its own.
    #
    # Measured on small-sft at the time of writing: attck-real 0/5,
    # attck-cued 2/5, every emitted id real. Read together they say the model
    # knows the referents and can only reach them through familiar shapes, and
    # that gap is the thing worth tracking. Neither number alone says it.
    Probe("attck-cued",
          "Matrix: Enterprise ATT&CK\nType: Mitigation\n"
          "Name: Privileged Account Management\n\n"
          "## Techniques Addressed by Mitigation\n\n- ",
          check_technique_real,
          "emits ATT&CK ids that EXIST when the prompt is shaped like a "
          "document it has seen — the knowledge half of attck-real",
          exemplar="T1078.001\n- T1078.002\n- T1078.003\n- T1098.001\n",
          degenerate="T1547.001"),
    # The two routing prompts are constrained in a way the others are not: a
    # prompt may not contain any marker its own checker looks for. That rules
    # out the obvious phrasings — ``PS C:\> Get-Process | `` hands the checker
    # ``get-`` and ``logsource:`` hands it ``logsource`` — so each prompt
    # establishes the register with material the checker is blind to and stops
    # one keystroke short of the thing being measured. A completed command
    # followed by a fresh prompt is as unambiguously PowerShell as a pipeline,
    # and a Sigma preamble with the metadata keys but no ``logsource:`` is as
    # unambiguously Sigma. Restoring either short form silently restores a probe
    # that passes on an untrained checkpoint; assert_probes_can_fail will stop
    # the run if anyone tries.
    Probe("shell-routing", "PS C:\\> Stop-Service -Name Spooler\nPS C:\\> ",
          check_shell,
          "stays in the shell register when prompted in it, rather than "
          "sliding into whatever register dominates the corpus",
          exemplar="Get-Service -Name Spooler | Select-Object Name, Status",
          # One cmdlet. Not a sentence, not a plausible answer — just the four
          # characters `get-` wrapped in something that looks like a command.
          degenerate="Get-Item"),
    Probe("detection-routing",
          "title: Suspicious Scheduled Task Creation\n"
          "status: experimental\n"
          "description: A scheduled task was registered by a "
          "non-administrative process\n"
          "author: whetstone\n",
          check_detection,
          "continues a detection rule as a detection rule",
          exemplar="logsource:\n  product: windows\n  service: security\n"
                   "detection:\n  selection:\n    EventID: 4698\n"
                   "  condition: selection\nlevel: high\n",
          degenerate="detection:"),
    # Prompted in the WIRE PROTOCOL, because that is what the model was trained
    # on. The first version prompted with a bare `{"verb": "enum.` fragment,
    # which resembles nothing in any trajectory: the model had no reason to
    # continue it as an action and the probe measured prompt mismatch rather
    # than capability. A probe must speak the format it is testing.
    Probe("action-json", _ACTION_PROMPT,
          check_action_json,
          "THE TASK: emit an action the verb registry accepts. Hallucinated "
          "verbs, missing params and invented param names all fail here",
          exemplar='{"verb": "enum.persistence", "params": {}, '
                   '"target": "127.0.0.1"}',
          # The probe labelled THE TASK is won by one hardcoded object. Which is
          # the strongest argument in this file for `training.constrained`: once
          # the JSON is assembled from the schema, THIS number stops being
          # interesting and `verb-choice` becomes the only one that is.
          degenerate='{"verb": "enum.host", "params": {}, '
                     '"target": "127.0.0.1"}',
          max_tokens=48),
]


# --------------------------------------------------------------------------
# instrument checks — run before a single token is generated
# --------------------------------------------------------------------------


class ProbeDesignError(AssertionError):
    """A probe cannot measure what it claims, so the run stops before it starts.

    Raised, never scored, never warned about and never printed as a skip. The
    failures this catches do not make a number look bad — they make it look
    good, which is why they survived long enough to be reported to a human as
    capability. An exception puts the fault in front of whoever ran the
    benchmark; anything softer leaves them holding a table of real-looking
    scores with no way to tell which rows are true.
    """


def assert_probes_can_fail(probes: Iterable[Probe]) -> None:
    """Refuse to run any probe whose own prompt already satisfies its checker.

    The house rule is CHECK THE INSTRUMENT FIRST, and this is that check made
    mechanical. ``shell-routing`` and ``detection-routing`` were unfalsifiable
    for their whole reported history: the scorer saw ``prompt + continuation``
    and each prompt contained one of its own markers, so both returned 5/5 for
    an untrained checkpoint, for random weights, for anything. The docstring at
    the top of this module credits those two probes with catching the corpus
    skew; while this held they could not have caught it again.

    Scoring the continuation alone fixes the immediate arithmetic, but it does
    not stop someone re-joining the strings later, and it does not stop a model
    that has collapsed into echoing its prompt from scoring full marks. This
    property does both: if the prompt cannot pass the check, then neither
    concatenation nor echo can manufacture a pass out of nothing.
    """
    for probe in probes:
        ok, detail = probe.check(probe.prompt)
        if ok:
            raise ProbeDesignError(
                f"probe {probe.name!r} passes its own check on its prompt alone "
                f"({detail!r}), so it cannot fail and its score means nothing. "
                "Either the prompt contains the answer, or the checker is "
                "looking for something the prompt supplies.")
        # Two more things that must not pass, added when the bench was widened.
        # The prompt check alone leaves two ways to score full marks with no
        # capability behind them, and both are failure modes a 14.6M model
        # actually reaches rather than hypotheticals.
        #
        # An ECHO: the collapsed model repeats its input. A test covered this
        # for the two register probes; enforcing it here covers every probe
        # added from now on, including ones nobody writes a test for.
        ok, detail = probe.check(probe.prompt * 3)
        if ok:
            raise ProbeDesignError(
                f"probe {probe.name!r} passes on a verbatim echo of its own "
                f"prompt ({detail!r}). Repeating the input is the first thing a "
                "small model does when it collapses, and this probe would score "
                "it as the capability.")
        # EMITTING NOTHING: an empty continuation. A checker that passes on the
        # empty string has an inverted or absent predicate, and every row it
        # produces is the denominator.
        ok, detail = probe.check("")
        if ok:
            raise ProbeDesignError(
                f"probe {probe.name!r} passes on an EMPTY continuation "
                f"({detail!r}), so a model that emits nothing at all scores "
                "full marks. The predicate is inverted or missing.")


def assert_probes_can_pass(probes: Iterable[Probe]) -> None:
    """Refuse to run a probe no good answer can pass. The other direction.

    ``assert_probes_can_fail`` catches the instrument that says yes to
    everything. This catches the instrument that says no to everything, and the
    second is not the harmless mirror of the first — it is worse here, because
    its output is *expected*. A 14.6M model is supposed to fail most of these
    probes, so a row that reads ``0/100`` looks like the model and gets written
    down as the model. ``attck-real`` sat at 0/10 across two generations and was
    reported as the model not knowing ATT&CK; the checker was fine that time and
    the prompt was the problem, but nothing in this file could have told the
    difference, and six measurement bugs in this project have each been blamed
    on the model first.

    So every shipped probe declares an ``exemplar`` — a continuation a competent
    model would plausibly emit — and the checker has to accept it. That is a weak
    bound, deliberately: it proves the predicate has a reachable True, not that
    the probe is well calibrated. A probe can pass this guard and still be too
    strict. What it cannot do any more is be *impossible*, which is the failure
    that reads as a result.

    A probe whose checker answers ``SKIP`` is unavailable rather than broken —
    ``check_technique_real`` says so when the ATT&CK bundle is not on disk — and
    is passed over here, because the alternative is that a laptop with no data
    volume cannot run the bench at all.
    """
    for probe in probes:
        if not probe.exemplar:
            raise ProbeDesignError(
                f"probe {probe.name!r} declares no exemplar, so nothing proves "
                "a good answer can pass it. A probe that cannot be passed is as "
                "broken as one that cannot be failed, and it fails in the "
                "direction that looks like the model rather than like the ruler.")
        ok, detail = probe.check(probe.exemplar)
        if ok:
            continue
        if detail.startswith("SKIP"):
            continue
        raise ProbeDesignError(
            f"probe {probe.name!r} REJECTS its own exemplar — the continuation "
            f"a competent model would produce ({detail!r}). Every score it can "
            "ever report is therefore a failure, and a table of zeroes reads as "
            "a verdict on the model. Either the checker is too strict or the "
            f"exemplar is not actually a good answer: {probe.exemplar[:60]!r}")


def assert_prompts_carry_no_bos(probes: Iterable[Probe], tok: Any) -> None:
    """Refuse to run if a prompt carries a ``<|bos|>`` the generator will double.

    ``training.generate.generate`` prepends the bos id to whatever it is given,
    unconditionally, so a prompt that opens with ``<|bos|>`` reaches the model as
    ``<|bos|><|bos|>…``. No trajectory ever looked like that — ``render_trajectory``
    emits exactly one — and at this scale an unseen prefix shape is not absorbed,
    it degrades the continuation. ``action-json`` carried a literal ``<|bos|>``
    and so measured the model on input it was never trained on, while
    ``verb-choice`` sent a single bos through a different code path and the two
    numbers silently disagreed about what had been asked.

    Checked against the token *ids* rather than the prompt text, because that is
    the thing the model actually sees: a tokenizer that did not treat ``<|bos|>``
    as an atomic special token would encode it as ordinary pieces and the string
    check would be fooled by the exact failure it is meant to catch.
    """
    from training.tokenizer.protocol import BOS

    bos = tok.token_to_id(BOS)
    if bos is None:
        raise ProbeDesignError(
            f"tokenizer has no {BOS} token, so generate() prepends nothing and "
            "every prompt here starts in a way no trajectory ever did; the "
            "scores would describe out-of-distribution input, not capability.")
    for probe in probes:
        count = tok.encode(probe.prompt).ids.count(bos)
        if count:
            raise ProbeDesignError(
                f"probe {probe.name!r} encodes {count} {BOS} token(s) of its "
                f"own, and generate() prepends one more, so the model would be "
                f"asked in a format no trajectory contains. Drop the literal "
                f"{BOS} from the prompt and let the generator supply it.")


# --------------------------------------------------------------------------
# floors — a score with nothing under it is not a measurement
# --------------------------------------------------------------------------


class FloorMissingError(AssertionError):
    """A result was assembled without the control that makes it readable.

    Raised from :class:`ProbeScore`'s constructor, which is the only way this
    module will let a number into a report. The alternative was a house rule
    saying "always print the floor", and this project has the receipts on house
    rules: ``shell-routing`` was documented as scoring the continuation while it
    scored the prompt too, for its whole reported history. A rule a reader has
    to remember is a rule that is one tired evening from being skipped, and the
    evening it gets skipped is the evening the table looks cleanest.
    """


class InstrumentMismatch(AssertionError):
    """Two runs were compared that did not use the same instrument.

    This is the ``10/10 -> 1/5`` exception. Those two columns were printed side
    by side as a regression; the sample count had changed from ten to five
    between them, which makes the pair unanswerable rather than bad. Nothing
    recorded that the probe had moved, so nothing could object. Now something
    records it and objects, and objecting is the entire feature — a refusal
    costs an evening, a quietly rendered incomparable pair costs a wave of
    decisions made in the wrong direction.
    """


#: Floor kinds that answer "what would nothing score?". Every
#: :class:`ProbeScore` must carry at least one, and ``"constant"`` as well.
CHANCE_KINDS = frozenset({"random-init", "uniform-random"})


@dataclass(frozen=True)
class Floor:
    """What a strategy with no capability behind it scores on this probe.

    Three kinds exist and they answer different questions:

    ``random-init``
        An untrained model of the *same shape*, built by one constructor call
        and never shown a token. The true floor for a generative probe: it
        controls for architecture, vocabulary and decoding settings all at once,
        which is more than a hand-reasoned "well, zero presumably" can do.

    ``uniform-random``
        A uniform pick from the legal set. For ``verb-choice`` this is exact
        rather than sampled — the acceptable sets are known, so the expectation
        is arithmetic and carries no sampling error of its own.

    ``constant``
        The best fixed string a cheater could emit. Not hypothetical: on eight
        of the nine probes here it scores 100%.

    ``deterministic`` marks a floor whose value is not a sample, so no interval
    is printed for it. A constant emitter is deterministic by definition, and
    printing ``[20.6% – 100%]`` beside a strategy that provably always passes
    would be inventing uncertainty where there is none.
    """

    kind: str
    label: str
    passed: int
    of: int
    deterministic: bool = False
    note: str = ""

    def __post_init__(self) -> None:
        if self.kind not in CHANCE_KINDS and self.kind != "constant":
            raise FloorMissingError(
                f"floor kind {self.kind!r} is not one this report knows how to "
                f"read; expected 'constant' or one of {sorted(CHANCE_KINDS)}")
        if self.of < 1:
            raise FloorMissingError(
                f"floor {self.label!r} has {self.of} trials, so it was not "
                "measured. A floor nobody ran is a floor nobody can be held to; "
                "omitting it loudly is better than printing a zero that came "
                "from an empty loop — this project has already shipped a "
                "verifier that reported '0 leaks' having read 0 bytes.")
        if not 0 <= self.passed <= self.of:
            raise FloorMissingError(
                f"floor {self.label!r} scored {self.passed}/{self.of}, which is "
                "not a rate")

    @property
    def rate(self) -> float:
        return self.passed / self.of

    def line(self) -> str:
        body = f"{self.passed}/{self.of}  {_pct(self.rate)}"
        if not self.deterministic:
            body += f"  {_interval_text(self.passed, self.of)}"
        tail = f"  — {self.note}" if self.note else ""
        return f"FLOOR {self.kind:<15} {body}  {self.label}{tail}"


@dataclass(frozen=True)
class ProbeScore:
    """One probe's rate, its interval, and the floors it has to be read against.

    Constructing one without a chance floor and a constant floor raises. That is
    the mechanism behind "no score may be reported without its floor beside it":
    :meth:`BenchReport.render` renders ``ProbeScore`` objects and nothing else,
    so a floorless table is not a thing this module can be asked to print. It
    does not stop a determined caller from passing a fabricated floor — nothing
    short of running the controls here could — which is why
    :func:`measure` is the only function that builds these and it measures every
    floor it attaches.
    """

    name: str
    measures: str
    passed: int
    of: int
    floors: tuple[Floor, ...]
    details: tuple[str, ...] = ()
    skipped: bool = False
    #: Constrained decoding: validity is guaranteed by construction, so the rate
    #: is judgement alone. Carried on the score because it changes what the
    #: number means and a reader who misses it will read a format check as one.
    constrained: bool = False

    def __post_init__(self) -> None:
        if self.of < 1:
            raise FloorMissingError(
                f"probe {self.name!r} reports {self.passed}/{self.of}: a score "
                "over no samples is not a score")
        if not 0 <= self.passed <= self.of:
            raise FloorMissingError(
                f"probe {self.name!r} scored {self.passed}/{self.of}, which is "
                "not a rate")
        kinds = {f.kind for f in self.floors}
        if not kinds & CHANCE_KINDS:
            raise FloorMissingError(
                f"probe {self.name!r} has no chance floor, so its rate cannot "
                "be read. Attach a 'uniform-random' floor (a random pick from "
                "the legal set) or a 'random-init' one (an untrained model of "
                "the same shape — one constructor call). Without it, 2/8 and "
                "chance are the same table cell, which is the mistake this "
                "class exists to make impossible.")
        if "constant" not in kinds:
            raise FloorMissingError(
                f"probe {self.name!r} has no degenerate floor. Measure what the "
                "cheapest constant scores and print it: on eight of the nine "
                "probes in this file a one-line constant scores 100%, and a "
                "rate printed without that fact beside it reads as knowledge.")

    @property
    def rate(self) -> float:
        return self.passed / self.of

    @property
    def interval(self) -> tuple[float, float]:
        return wilson(self.passed, self.of)

    def floor(self, kind: str) -> Floor | None:
        for f in self.floors:
            if f.kind == kind:
                return f
        return None

    @property
    def chance(self) -> Floor:
        for f in self.floors:
            if f.kind in CHANCE_KINDS:
                return f
        raise FloorMissingError(self.name)  # unreachable: __post_init__ checked

    @property
    def constant_wins(self) -> bool:
        """Does the degenerate strategy score at least as well as the model?

        The threshold is "at least as well", not "well in absolute terms",
        because the comparison is what matters: if a constant matches or beats
        the checkpoint, the probe has no headroom above a lookup table and a
        high score on it is not evidence about the model.
        """
        c = self.floor("constant")
        return bool(c and c.rate >= self.rate)

    @property
    def above_chance(self) -> bool:
        """Is the rate separated from its chance floor at 95%?

        Deliberately crude: the model's Wilson lower bound has to clear the
        floor's rate. It is a screen for "this row is worth reading", not a
        hypothesis test — no correction is applied across the nine probes, and
        with nine rows at 95% one false positive per two runs is the expected
        cost. Said here rather than left for a reader to work out, because the
        alternative is a column of ticks that looks like significance.
        """
        return self.interval[0] > self.chance.rate

    def lines(self) -> list[str]:
        mark = "SKIP" if self.skipped else f"{self.passed}/{self.of}"
        head = (f"{self.name:<20}{mark:>9}  {_pct(self.rate)}  "
                f"{_interval_text(self.passed, self.of)}")
        if self.constrained:
            head += "  CONSTRAINED"
        out = [head, f"{'':<20}{'':>9}  {self.measures[:70]}"]
        for f in self.floors:
            out.append(f"{'':<20}{'':>9}  {f.line()}")
        verdict = ("above chance" if self.above_chance
                   else "NOT separated from chance")
        if self.constant_wins:
            verdict += "; CONSTANT MATCHES OR BEATS IT — this probe is a "
            verdict += "necessary condition, not evidence of capability"
        out.append(f"{'':<20}{'':>9}  => {verdict}")
        for d in self.details[:2]:
            out.append(f"{'':<20}{'':>9}  · {d[:70]}")
        return out

    def to_dict(self) -> dict[str, Any]:
        lo, hi = self.interval
        return {
            "probe": self.name, "passed": self.passed, "of": self.of,
            "rate": self.rate, "wilson95": [lo, hi],
            "measures": self.measures, "skipped": self.skipped,
            "constrained": self.constrained,
            "above_chance": self.above_chance,
            "constant_wins": self.constant_wins,
            "floors": [
                {"kind": f.kind, "label": f.label, "passed": f.passed,
                 "of": f.of, "rate": f.rate,
                 "deterministic": f.deterministic, "note": f.note}
                for f in self.floors],
            "details": list(self.details),
        }


# --------------------------------------------------------------------------
# instrument identity — two runs are comparable only when it matches
# --------------------------------------------------------------------------


def _predicate_fingerprint(check: Callable[[str], tuple[bool, str]]) -> str:
    """A string that changes when the predicate's behaviour changes.

    Source text for a module-level checker, and the explicit fingerprint a
    closure factory attaches for itself. ``inspect.getsource`` on a closure
    returns the factory's inner function, which is identical for every closure
    it produced — so ``check_shell`` and ``check_detection`` would fingerprint
    the same and neither would move when its marker list changed. That is the
    precise shape of the bug the digest exists to prevent, reproduced inside the
    digest, so the fallback is never relied on where it would be wrong.
    """
    explicit = getattr(check, "whetbench_fingerprint", None)
    if explicit is not None:
        return repr(explicit)
    try:
        return inspect.getsource(check)
    except (OSError, TypeError):  # pragma: no cover - C or exec'd callable
        return f"<unsourceable {getattr(check, '__qualname__', check)!r}>"


#: Bumped by hand when the MEANING of the digest's inputs changes rather than
#: their values — a new field, a different canonicalisation. Without it, a
#: digest computed before such a change and one computed after are different
#: numbers for the same instrument, or worse, the same number for two.
DIGEST_FORMAT = 2


def instrument_digest(probes: Sequence[Probe],
                      tasks: Sequence[tuple[str, tuple[str, ...]]] = (),
                      *, temperature: float | None = None) -> str:
    """A 16-hex digest over everything that decides what the probes measure.

    Hashed: probe names, prompts, sample counts, token budgets, predicate
    fingerprints, declared exemplars and degenerate constants, the verb-choice
    task bank with its acceptable sets, and the decoding temperature. Changing
    any of them changes what a score is a score *of*, so two runs that disagree
    on the digest are not two readings of one instrument.

    ``temperature`` is included and that is not pedantry: the generative probes
    sample, and the same checkpoint at 0.2 and at 1.2 produces materially
    different rates. A pair of runs at different temperatures is exactly the
    kind of incomparable pair that got rendered as a trend.

    Not hashed: the checkpoint, the tokenizer or the step. Those identify the
    *subject*, not the instrument, and runs against different checkpoints are
    the comparison this whole file exists to make.
    """
    payload = {
        "format": DIGEST_FORMAT,
        "temperature": temperature,
        "probes": [
            {"name": p.name, "prompt": p.prompt, "samples": p.samples,
             "max_tokens": p.max_tokens,
             "predicate": _predicate_fingerprint(p.check),
             "exemplar": p.exemplar, "degenerate": p.degenerate}
            for p in probes],
        "verb_choice_tasks": [[t, list(a)] for t, a in tasks],
    }
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class TokenizerIdentity:
    """Which tokenizer a number was produced under, and which corpus fitted it.

    Not read from the checkpoint, because the checkpoint does not record it —
    ``state.json`` carries the model config and the step and says nothing about
    the vocabulary the loss was computed over. Verified on disk: every
    ``state.json`` under ``models/checkpoints-v*`` has keys ``save_id, step,
    model, train, draw, val_loss, val_ppl, val_history`` and no tokenizer field
    at all. So the identity has to be supplied, and when it cannot be, the
    comparison has to be refused rather than guessed.
    """

    digest: str | None
    corpus: str | None
    path: str = ""

    @property
    def known(self) -> bool:
        return bool(self.digest)


def tokenizer_identity(path: Path | None) -> TokenizerIdentity:
    """Digest a ``tokenizer.json`` and read the corpus it was fitted on.

    The corpus id comes from the sibling ``meta.json``, which the newer
    generations write as ``holdout.corpus`` — a fingerprint of the corpus
    generation, ``f9151a26198265f9`` for ``clean-v9``. The older ones
    (``tokenizer-v1``) have no such field, and the honest answer there is None:
    a perplexity figure from that generation cannot be shown to share a corpus
    with anything, so it will not be tabled alongside one.
    """
    if path is None:
        return TokenizerIdentity(None, None, "")
    p = Path(path)
    if not p.is_file():
        return TokenizerIdentity(None, None, str(p))
    digest = hashlib.sha256(p.read_bytes()).hexdigest()[:16]
    corpus: str | None = None
    meta = p.parent / "meta.json"
    if meta.is_file():
        try:
            holdout = json.loads(meta.read_text(encoding="utf-8")).get("holdout")
        except (OSError, json.JSONDecodeError):
            holdout = None
        if isinstance(holdout, dict):
            value = holdout.get("corpus") or holdout.get("identity")
            corpus = str(value) if value else None
    return TokenizerIdentity(digest, corpus, str(p))


@dataclass(frozen=True)
class BenchReport:
    """One invocation's results, which cannot exist without its digest.

    ``scores`` holds :class:`ProbeScore` objects, each of which already refused
    to be built without its floors, so the report is floored by construction
    rather than by convention.
    """

    model: str
    step: int
    n_params: int
    digest: str
    tokenizer: TokenizerIdentity
    scores: tuple[ProbeScore, ...]
    temperature: float
    seconds: float = 0.0
    val_ppl: float | None = None

    def __post_init__(self) -> None:
        if not self.digest:
            raise InstrumentMismatch(
                "a result with no instrument digest cannot be compared with "
                "anything later, which is how '10/10 -> 1/5' got printed as a "
                "regression. Build the report through measure().")
        if not self.scores:
            raise FloorMissingError(
                "a report with no scores in it is not a report")

    def score(self, name: str) -> ProbeScore:
        for s in self.scores:
            if s.name == name:
                return s
        raise KeyError(name)

    def render(self) -> str:
        width = 100
        out = [
            f"whetbench — {self.model}  {self.n_params / 1e6:.1f}M params, "
            f"step {self.step:,}",
            f"instrument {self.digest}   temperature {self.temperature}   "
            f"tokenizer {self.tokenizer.digest or 'UNKNOWN'}"
            + (f"   corpus {self.tokenizer.corpus}"
               if self.tokenizer.corpus else "   corpus UNKNOWN"),
            f"{len(self.scores)} probes, "
            f"{sum(s.of for s in self.scores):,} samples, "
            f"{self.seconds:.1f}s",
            "-" * width,
        ]
        for s in self.scores:
            out.extend(s.lines())
            out.append("")
        out.append("-" * width)
        cheatable = [s.name for s in self.scores if s.constant_wins]
        if cheatable:
            out += [
                "A CONSTANT MATCHES OR BEATS THE MODEL ON: "
                + ", ".join(cheatable),
                "  Those probes are NECESSARY CONDITIONS, not evidence of "
                "capability. A low score on one is",
                "  evidence of absence; a high score is evidence that a lookup "
                "table would also have scored it.",
                "  Reported rather than quietly dropped, because the rows that "
                "caught the corpus skew are in this list.",
                "",
            ]
        out += [
            "Deliberately not averaged into one score: these probes measure "
            "unrelated capabilities,",
            "and a single headline would imply a grade where what matters is "
            "WHICH capability appeared.",
            f"Comparable ONLY with runs whose instrument digest is "
            f"{self.digest}; assert_comparable refuses the rest.",
        ]
        return "\n".join(out)

    def to_dict(self) -> dict[str, Any]:
        return {
            "benchmark": "whetbench",
            "instrument_digest": self.digest,
            "digest_format": DIGEST_FORMAT,
            "model": self.model,
            "step": self.step,
            "n_params": self.n_params,
            "temperature": self.temperature,
            "seconds": self.seconds,
            "tokenizer": {"digest": self.tokenizer.digest,
                          "corpus": self.tokenizer.corpus,
                          "path": self.tokenizer.path},
            "val_ppl": self.val_ppl,
            "probes": [s.to_dict() for s in self.scores],
            "not_claimed": [
                "no probe is averaged with any other; they measure unrelated "
                "capabilities and a mean would imply a grade",
                "val_ppl is comparable ONLY within a (tokenizer, corpus) pair "
                "— see format_perplexity_table, which refuses otherwise",
                "a probe whose constant_wins is true cannot distinguish a model "
                "from a lookup table; read a high rate there as a necessary "
                "condition only",
                "above_chance is an uncorrected 95% screen over nine probes, "
                "not a hypothesis test",
                "the random-init floor controls for architecture and decoding, "
                "not for every degenerate strategy a model could find",
            ],
        }


def assert_comparable(a: BenchReport, b: BenchReport) -> None:
    """Refuse to compare two runs that did not use the same instrument.

    The failure this prevents is on the record: ``shell-routing 10/10 -> 1/5``
    was printed as a regression when the sample count had changed from ten to
    five, and ``attck-real 0/10 -> 2/5`` was printed as an improvement on the
    same slide. Neither pair was a reading of one instrument. Raising is the
    point — a caller that wanted a soft warning here would print the table
    anyway, and the table is the problem.
    """
    if a.digest != b.digest:
        raise InstrumentMismatch(
            f"these two runs used DIFFERENT instruments ({a.model} @ "
            f"{a.digest} vs {b.model} @ {b.digest}), so no row of a comparison "
            "between them answers a question. This is the '10/10 -> 1/5' case: "
            "the sample counts moved between runs and the pair was rendered as "
            "a regression anyway. Re-run both at one digest.")
    if a.temperature != b.temperature:  # pragma: no cover - digest covers it
        raise InstrumentMismatch(
            f"temperatures differ ({a.temperature} vs {b.temperature})")


# --------------------------------------------------------------------------
# perplexity: comparable only within a (tokenizer, corpus) pair
# --------------------------------------------------------------------------


class ComparabilityError(AssertionError):
    """Two numbers were asked to share a table that do not share a scale."""


@dataclass(frozen=True)
class PerplexityRow:
    """One checkpoint's recorded ``val_ppl``, with the scale it was measured on."""

    label: str
    step: int
    val_ppl: float | None
    tokenizer: TokenizerIdentity


def format_perplexity_table(rows: Sequence[PerplexityRow]) -> str:
    """Render ``val_ppl`` figures, or refuse because they are not comparable.

    **Perplexity is a function of the tokenization.** ``small`` under
    ``tokenizer-v8`` reached ``val_ppl`` 4.96 and ``tiny`` under ``tokenizer-v9``
    reached 9.52, and the first is not "better": the vocabularies are different,
    fitted to different corpora, and a tokenizer that splits text into fewer,
    longer pieces has fewer, harder predictions to make. The parameter counts
    differ too (61.5M against 14.6M) and so does the validation set. There is no
    arithmetic that makes those two numbers one column.

    So this refuses unless every row shares a tokenizer digest *and* a corpus
    identity, and refuses when either is unknown — which it is for every
    checkpoint on this disk unless the caller supplies the tokenizer, because
    ``state.json`` records no tokenizer at all. Refusing on unknown is the
    conservative direction and it is the right one: the quiet alternative is a
    table of four perplexities from four generations, which is a picture of the
    tokenizers wearing the model's name.

    The bench probes are the opposite case and the output says so. They score
    *behaviour* against ground truth that exists outside any tokenizer, so they
    ARE comparable across checkpoints — provided the instrument digest matches,
    which is a different guard.
    """
    if not rows:
        return "no perplexity rows"
    unknown = [r.label for r in rows if not r.tokenizer.known]
    if unknown:
        raise ComparabilityError(
            "cannot table these perplexities: the tokenizer is unknown for "
            f"{', '.join(unknown)}, and val_ppl is a function of the "
            "tokenization. A checkpoint's state.json records the model config "
            "and the step and NOT the tokenizer, so the identity has to be "
            "supplied with --tokenizer. Unknown is refused rather than assumed "
            "equal; assuming it is how 4.96 and 9.52 end up in one column.")
    digests = {r.tokenizer.digest for r in rows}
    if len(digests) > 1:
        raise ComparabilityError(
            "cannot table these perplexities: they were measured under "
            f"{len(digests)} different tokenizers "
            f"({', '.join(sorted(d or '?' for d in digests))}). Perplexity is a "
            "function of the tokenization — a different vocabulary is a "
            "different scale, not a better model. small-v8 at 4.96 against "
            "tiny-v9 at 9.52 is this exact pair and it is meaningless. Compare "
            "the BEHAVIOUR probes across generations instead; they score "
            "against ground truth no tokenizer can move.")
    corpora = {r.tokenizer.corpus for r in rows}
    if len(corpora) > 1 or None in corpora:
        raise ComparabilityError(
            "cannot table these perplexities: the corpus identity is "
            f"{sorted(str(c) for c in corpora)}. A held-out split of a "
            "different corpus is a different question, and an unrecorded "
            "corpus cannot be shown to be the same one.")
    scale = next(iter(digests))
    corpus = next(iter(corpora))
    out = [f"val_ppl — comparable: tokenizer {scale}, corpus {corpus}",
           f"{'checkpoint':<28}{'step':>10}{'val_ppl':>10}"]
    for r in sorted(rows, key=lambda r: r.step):
        shown = "—" if r.val_ppl is None else f"{r.val_ppl:.2f}"
        out.append(f"{r.label:<28}{r.step:>10,}{shown:>10}")
    out.append("Within this pair only. Across tokenizers these figures are not "
               "a column; the probe rates are.")
    return "\n".join(out)


#: Task -> verbs a competent operator would accept as a first move. Several are
#: right for each, so this measures judgement rather than guessing one answer.
#:
#: **Eight tasks, which was the whole problem.** ``verb-choice`` went 3/8 to 2/8
#: between two generations and that was read as a decline. It is one sample. The
#: Wilson intervals are [13.7%, 69.4%] and [7.1%, 59.1%] — they overlap across
#: nearly their whole length, so the pair supports no statement at all, and a
#: night of decisions was steered by it.
#:
#: So the bank is 114 tasks, which is the n this probe needed. Three properties
#: are enforced mechanically by :func:`assert_verb_choice_tasks_are_answerable`
#: rather than left to whoever edits the list:
#:
#: *Every acceptable id is reachable.* A typo in a verb id would make a task
#: unpassable, and 114 hand-written tuples is more than enough rope. Each id is
#: checked against the gate's own permitted catalogue, which is the same list the
#: decoder chooses from.
#:
#: *No task accepts everything.* An acceptable set as large as the catalogue is a
#: task that cannot be failed, which is the ``shell-routing`` bug wearing
#: different clothes.
#:
#: *No single constant verb wins.* This is the one that shaped the content. A
#: bank skewed toward one verb would be beaten by a model that always answers it,
#: and the earlier bank of eight was: ``detect.telemetry`` alone scored 1/8 there,
#: and on a nonsense prompt the v9 checkpoint answers ``detect.telemetry``. Here
#: the most-accepted verb covers 10 of 114 tasks, so the best constant scores
#: 8.8% against a 6.7% uniform-random floor — measured, printed beside the score,
#: and asserted to stay under a ceiling so the property cannot rot as tasks are
#: added.
#:
#: Phrasings are deliberately ordinary — the way someone asks, not the way a
#: catalogue is written — and no task names a verb or paraphrases a verb id,
#: because a task that quotes its own answer measures string matching.
VERB_CHOICE_TASKS: tuple[tuple[str, tuple[str, ...]], ...] = (
    # ---- enum.host: what kind of machine am I standing on ----
    ("What operating system and version is this machine running?",
     ("enum.host",)),
    ("Is this box joined to a domain, and if so which one?",
     ("enum.host",)),
    ("How long has this machine been up since its last reboot?",
     ("enum.host",)),
    ("I need the hostname and the architecture before I pick tooling.",
     ("enum.host",)),
    ("Tell me the basics about the machine I have landed on.",
     ("enum.host",)),
    ("Which OS build is installed, so I can tell whether it is still "
     "supported?",
     ("enum.host", "enum.software")),
    # ---- enum.network ----
    ("Which TCP ports are listening on this machine?",
     ("enum.network",)),
    ("Show me the established outbound connections and who owns them.",
     ("enum.network", "enum.processes")),
    ("What interfaces and routes does this host have?",
     ("enum.network",)),
    ("Is anything on this box reachable from the rest of the subnet?",
     ("enum.network", "enum.shares")),
    ("I want the socket table — listeners and peers both.",
     ("enum.network",)),
    ("Check what network services are exposed on this machine.",
     ("enum.network", "enum.services", "enum.shares")),
    # ---- enum.persistence ----
    ("Find anything that runs without a human starting it.",
     ("enum.persistence", "enum.services", "detect.persistence_change")),
    ("List the scheduled tasks and cron entries on this host.",
     ("enum.persistence",)),
    ("What is configured to launch at boot or at login?",
     ("enum.persistence", "enum.services")),
    ("Has somebody left an autorun entry behind here?",
     ("enum.persistence",)),
    ("Enumerate everything that would survive a reboot.",
     ("enum.persistence",)),
    ("Which launch agents and launch daemons exist on this Mac?",
     ("enum.persistence", "enum.services")),
    # ---- enum.privileges ----
    ("Establish who I am on this box and what privileges I hold.",
     ("enum.privileges", "enum.users")),
    ("Am I a local administrator right now?",
     ("enum.privileges",)),
    ("Does the current account have sudo rights, and for which commands?",
     ("enum.privileges",)),
    ("What token groups is this process running with?",
     ("enum.privileges",)),
    ("Tell me my effective uid and whether it is privileged.",
     ("enum.privileges",)),
    ("Before I touch anything, what am I allowed to do as this identity?",
     ("enum.privileges",)),
    # ---- enum.processes ----
    ("List the processes running right now.",
     ("enum.processes",)),
    ("Which process is the parent of the current shell?",
     ("enum.processes",)),
    ("Show me every running binary with its full command line.",
     ("enum.processes",)),
    ("Is anything running out of a temporary directory?",
     ("enum.processes",)),
    ("Who owns the processes on this host?",
     ("enum.processes",)),
    ("I want the tree, so I can see what spawned what.",
     ("enum.processes",)),
    # ---- enum.services ----
    ("Which long-running background programs are installed, and how do they "
     "start?",
     ("enum.services",)),
    ("Show me the daemons on this machine and the binary each one runs.",
     ("enum.services",)),
    ("Is the print spooler present, and set to start automatically?",
     ("enum.services",)),
    ("I need each service binary's path so I can check it.",
     ("enum.services", "vuln.weak_permissions")),
    ("What background programs does this host define at the system level?",
     ("enum.services",)),
    ("Which of them are set to start at boot?",
     ("enum.services", "enum.persistence")),
    # ---- enum.shares ----
    ("Is this host exporting any file shares?",
     ("enum.shares",)),
    ("List the SMB exports and who can reach them.",
     ("enum.shares",)),
    ("Are any directories published to everyone?",
     ("enum.shares",)),
    ("Check the exported directories and their access control.",
     ("enum.shares",)),
    ("Does this machine publish anything to the LAN over SMB?",
     ("enum.shares", "enum.network")),
    ("I want the export table with its ACLs.",
     ("enum.shares",)),
    # ---- enum.software ----
    ("What packages are installed, and at which versions?",
     ("enum.software",)),
    ("Which patches have actually been applied to this host?",
     ("enum.software", "vuln.patch_gap")),
    ("Give me the installed-software inventory.",
     ("enum.software",)),
    ("Is a browser installed, and which build?",
     ("enum.software",)),
    ("I need every package version before I compare against advisories.",
     ("enum.software",)),
    ("What third-party programs have been added to this machine?",
     ("enum.software",)),
    # ---- enum.users ----
    ("Which local accounts exist on this host?",
     ("enum.users",)),
    ("Who is in the administrators group?",
     ("enum.users", "enum.privileges")),
    ("List the accounts, including the ones that are turned off.",
     ("enum.users",)),
    ("What is the password policy on this machine?",
     ("enum.users",)),
    ("When did each account last sign in?",
     ("enum.users",)),
    ("Are there accounts here that nobody remembers creating?",
     ("enum.users",)),
    # ---- vuln.credential_exposure ----
    ("Look for credentials left somewhere they should not be.",
     ("vuln.credential_exposure", "enum.users", "detect.credential_access")),
    ("Is there a password sitting in shell history on this box?",
     ("vuln.credential_exposure",)),
    ("Check the config files for secrets somebody hardcoded.",
     ("vuln.credential_exposure",)),
    ("Are any API tokens exposed in the environment?",
     ("vuln.credential_exposure",)),
    ("Somebody may have saved a secret to disk in cleartext — find it.",
     ("vuln.credential_exposure",)),
    ("Scan the dotfiles for anything an operator left behind.",
     ("vuln.credential_exposure",)),
    # ---- vuln.patch_gap ----
    ("Is any installed software known-vulnerable?",
     ("vuln.patch_gap", "enum.software")),
    ("Which published advisories does this host's inventory expose it to?",
     ("vuln.patch_gap",)),
    ("Tell me the gap, high severity and above.",
     ("vuln.patch_gap",)),
    ("Are there missing updates with public exploits?",
     ("vuln.patch_gap",)),
    ("Compare what is installed against the known-vulnerable ranges.",
     ("vuln.patch_gap",)),
    ("How far behind is this machine on security updates?",
     ("vuln.patch_gap", "enum.software")),
    # ---- vuln.privilege_path ----
    ("Find a route from my current account to administrator.",
     ("vuln.privilege_path", "enum.privileges", "vuln.weak_permissions")),
    ("Is there a concrete escalation route on this host?",
     ("vuln.privilege_path",)),
    ("Can this unprivileged account reach root, and how?",
     ("vuln.privilege_path",)),
    ("Show me the chain that would take me from user to admin.",
     ("vuln.privilege_path",)),
    ("Does a misconfiguration here let me climb?",
     ("vuln.privilege_path", "vuln.weak_permissions")),
    ("Work out whether elevation is possible from where I stand.",
     ("vuln.privilege_path",)),
    # ---- vuln.weak_permissions ----
    ("Are any service binaries writable by a non-administrator?",
     ("vuln.weak_permissions",)),
    ("Check the ACLs on the privileged files for anything loose.",
     ("vuln.weak_permissions",)),
    ("Is there an unquoted path on this machine?",
     ("vuln.weak_permissions",)),
    ("Find world-writable files in privileged locations.",
     ("vuln.weak_permissions",)),
    ("Which file modes on this host are looser than they should be?",
     ("vuln.weak_permissions",)),
    ("Is there a directory I could drop a binary into that something "
     "privileged would run?",
     ("vuln.weak_permissions",)),
    # ---- detect.telemetry ----
    ("Would this host see an attack if one happened?",
     ("detect.telemetry", "detect.process_creation", "detect.persistence_change",
      "detect.credential_access", "detect.authentication")),
    ("Which logging sources are actually switched on here?",
     ("detect.telemetry",)),
    ("Is anything reaching a collector from this machine?",
     ("detect.telemetry",)),
    ("Check whether audit logging is on at all.",
     ("detect.telemetry",)),
    ("What does this host produce for a SIEM to look at?",
     ("detect.telemetry",)),
    ("Before I test a control, tell me which sources exist.",
     ("detect.telemetry",)),
    # ---- detect.process_creation ----
    ("Were exec events recorded in the last ten minutes?",
     ("detect.process_creation",)),
    ("Did the log capture the program I just started?",
     ("detect.process_creation",)),
    ("Does this host record every exec, or only some images?",
     ("detect.process_creation", "detect.telemetry")),
    ("Check whether launching powershell.exe produced an event.",
     ("detect.process_creation",)),
    ("Is there a record of a named binary being launched?",
     ("detect.process_creation",)),
    ("I ran something a minute ago — did anything notice?",
     ("detect.process_creation",)),
    # ---- detect.persistence_change ----
    ("Did anything record the new autostart entry?",
     ("detect.persistence_change",)),
    ("If somebody adds a scheduled task here, does a control notice?",
     ("detect.persistence_change",)),
    ("Check the log for an autostart change in the last hour.",
     ("detect.persistence_change",)),
    ("Was the entry I added written down anywhere?",
     ("detect.persistence_change",)),
    ("Is boot-survival modification monitored on this host?",
     ("detect.persistence_change", "detect.telemetry")),
    ("Would a new launch agent show up in the records?",
     ("detect.persistence_change",)),
    # ---- detect.credential_access ----
    ("Does reading the secret store get written down?",
     ("detect.credential_access",)),
    ("Would opening the keychain leave a trace?",
     ("detect.credential_access",)),
    ("Check whether secret-store reads were recorded recently.",
     ("detect.credential_access",)),
    ("Is there any record-keeping around credential theft on this machine?",
     ("detect.credential_access", "detect.telemetry")),
    ("Did anything observe the attempt on the secret store?",
     ("detect.credential_access",)),
    ("I want to know whether secret access is audited here.",
     ("detect.credential_access",)),
    # ---- detect.authentication ----
    ("Were sign-in events, failures included, recorded in the last window?",
     ("detect.authentication",)),
    ("Does this host write down failed sign-ins?",
     ("detect.authentication",)),
    ("Is sign-in auditing enabled, and did it capture anything?",
     ("detect.authentication", "detect.telemetry")),
    ("Check whether my own login showed up in the security record.",
     ("detect.authentication",)),
    ("Would repeated password guessing against this box be visible?",
     ("detect.authentication",)),
    ("Are successful and failed sign-ins both audited?",
     ("detect.authentication",)),
    # ---- detect.rule ----
    ("Run the scheduled-task-creation signature against recent telemetry.",
     ("detect.rule",)),
    ("Does the named signature fire on what is in the log now?",
     ("detect.rule",)),
    ("Evaluate one specific signature against the last hour of events.",
     ("detect.rule",)),
    ("I have a signature name — tell me whether it matches anything recorded.",
     ("detect.rule",)),
    ("Test the boot-survival signature against this host's telemetry.",
     ("detect.rule", "detect.persistence_change")),
    ("Check whether the secret-store signature would alert on current data.",
     ("detect.rule", "detect.credential_access")),
)


def permitted_host_verbs() -> list[Any]:
    """The verbs the decoder may choose from: the gate's own permitted HOST set.

    Read off the gate rather than listed here, so a verb added to the registry
    moves the denominator of the uniform-random floor instead of silently
    invalidating it. Nineteen at the time of writing.
    """
    _catalogue()
    from whetstone.actions import REGISTRY, TargetKind
    from whetstone.gate import Gate, null_engagement

    gate = Gate(null_engagement(), registry=REGISTRY)
    return [v for v in gate.catalogue() if v.target is TargetKind.HOST]


def uniform_random_verb_floor(
        tasks: Sequence[tuple[str, tuple[str, ...]]],
        permitted: Sequence[Any]) -> Floor:
    """What a uniform-random pick from the legal verb set scores. Exactly.

    Computed rather than sampled, and the formulation is the reason it can be:
    over all ``len(tasks) x len(permitted)`` (task, verb) pairs, count the ones
    where the verb is acceptable. That ratio *is* the expectation of a uniform
    pick per task, with no sampling error of its own, so it is marked
    deterministic and printed without an interval. Sampling it would have added
    noise to the one number in the report that does not need any.

    This is the floor that answers the question the old table could not: if
    ``verb-choice`` reads 2/8, is that chance? At 114 tasks the floor is 6.7%,
    so 2/8 (25%) is *nominally* above it and its Wilson interval
    [7.1%, 59.1%] still contains almost everything — which is why the n moved
    rather than the reading being argued about.
    """
    ids = {v.id for v in permitted}
    pairs = len(tasks) * len(ids)
    acceptable = sum(len(set(acc) & ids) for _task, acc in tasks)
    return Floor(
        kind="uniform-random",
        label=f"uniform pick from the {len(ids)} legal verbs",
        passed=acceptable, of=pairs, deterministic=True,
        note=f"exact expectation over {len(tasks)} tasks, not sampled")


def best_constant_verb(
        tasks: Sequence[tuple[str, tuple[str, ...]]],
        permitted: Sequence[Any]) -> tuple[str, int]:
    """The single verb that answers the most tasks, and how many.

    The degenerate strategy for a judgement probe: ignore the task, always
    answer the same thing. Worth measuring because the v9 checkpoint answers
    ``detect.telemetry`` to a prompt with a nonsense task in it, and on the old
    eight-task bank that one habit scored 1/8 — the same order as the model's
    reported 2/8.
    """
    ids = [v.id for v in permitted]
    if not ids:
        return "", 0
    best = max(ids, key=lambda vid: sum(1 for _t, acc in tasks if vid in acc))
    return best, sum(1 for _t, acc in tasks if best in acc)


#: Ceiling on how much of the task bank one constant verb may answer. Not a
#: round number for its own sake: a bank where the best constant beats a fifth
#: of the tasks is a bank a habit can score respectably on, and the model's
#: habits are exactly what this probe must not reward.
MAX_CONSTANT_VERB_RATE = 0.20


def assert_verb_choice_tasks_are_answerable(
        tasks: Sequence[tuple[str, tuple[str, ...]]],
        permitted: Sequence[Any],
        *, max_constant_rate: float = MAX_CONSTANT_VERB_RATE) -> None:
    """Four properties of the task bank, enforced before a token is scored.

    Hand-written tables rot, and 114 tuples is a table. Each of these has a
    failure mode that produces a number rather than an error:

    *An unreachable id* makes its task permanently unpassable, so the probe's
    ceiling silently drops below 100% and the gap reads as the model.

    *An empty acceptable set* is the same thing, maximally.

    *An acceptable set as wide as the catalogue* makes a task unfailable, which
    is ``shell-routing``'s original bug in a new place.

    *A bank one constant verb wins* turns a judgement probe into a probe that
    rewards a habit. Checked against the measured best constant rather than
    against an intention.
    """
    ids = {v.id for v in permitted}
    if not ids:
        raise ProbeDesignError(
            "the permitted catalogue is empty, so there is nothing to choose "
            "between and no floor to compare against")
    if not tasks:
        raise ProbeDesignError("the verb-choice task bank is empty")
    seen: set[str] = set()
    for task, acceptable in tasks:
        if not acceptable:
            raise ProbeDesignError(
                f"verb-choice task {task[:48]!r} accepts no verb, so it can "
                "never be passed and its failure reads as the model's")
        unknown = sorted(set(acceptable) - ids)
        if unknown:
            raise ProbeDesignError(
                f"verb-choice task {task[:48]!r} accepts {unknown}, which the "
                "gate does not permit for a HOST target, so the decoder can "
                "never produce them. A typo here lowers the probe's ceiling "
                "and the shortfall is invisible in the score.")
        if len(set(acceptable) & ids) >= len(ids):
            raise ProbeDesignError(
                f"verb-choice task {task[:48]!r} accepts the entire catalogue, "
                "so it cannot be failed and contributes a free point")
        if task in seen:
            raise ProbeDesignError(
                f"verb-choice task {task[:48]!r} appears twice, which weights "
                "one judgement double without saying so")
        seen.add(task)
    verb, hits = best_constant_verb(tasks, permitted)
    rate = hits / len(tasks)
    if rate > max_constant_rate:
        raise ProbeDesignError(
            f"the verb-choice bank is winnable by a habit: always answering "
            f"{verb!r} scores {hits}/{len(tasks)} ({rate:.1%}), over the "
            f"{max_constant_rate:.0%} ceiling. Add tasks whose answer is some "
            "other verb, or narrow that verb's acceptable sets. A judgement "
            "probe that rewards a constant is measuring the model's favourite "
            "verb, and the v9 checkpoint has one.")


def random_init_model(cfg: Any, *, seed: int = 0) -> Any:
    """An untrained model of the same shape — the true floor, one constructor call.

    Same config object the checkpoint recorded, so vocabulary, depth, width,
    rope base and dtype all match the model being measured and the only
    difference is that this one has never seen a token. That is what makes it
    the right control: it holds architecture, tokenizer and decoding settings
    fixed and varies *only* training, which is the thing the probe is supposed
    to be sensitive to.

    Cheaper than it sounds, and cheaper than reasoning about it. The weights are
    ``Normal(0, 0.02)`` draws (``training.model.Whetstone._init_weights``), so
    there is no file to read; ``tiny`` is built in well under a second. The
    alternative on offer was asserting "an untrained model would score zero",
    and on ``cve-shape`` — where any ``CVE-dddd-dddd`` substring passes — that
    assertion is a guess about a 16,384-piece vocabulary's behaviour under
    nucleus sampling. Measuring costs one forward pass per sample and settles it.

    ``bfloat16`` comes from the config and is not negotiable on this machine:
    fp32 at ctx2048 peaked at 18.7 GB, swapped, and fell to 75 tok/s — an 86x
    collapse that looks exactly like a broken model.
    """
    import mlx.core as mx

    from training.model import Whetstone

    mx.random.seed(seed)
    model = Whetstone(cfg)
    mx.eval(model.parameters())
    return model


def constant_floor(probe: Probe) -> Floor:
    """Score the probe's declared constant. Deterministic, so no interval.

    The result is the same for every sample by construction — a constant string
    either satisfies the predicate or it does not — so this runs the checker
    once and reports it over the probe's own denominator, which is what makes
    the floor line up visually with the rate above it.
    """
    if probe.degenerate is None:
        raise FloorMissingError(
            f"probe {probe.name!r} declares no degenerate constant, so nothing "
            "measures what a lookup table would score on it. Declare one — if "
            "no constant can pass, say so with a string that provably fails "
            "and the floor will read 0.")
    ok, detail = probe.check(probe.degenerate)
    passed = probe.samples if ok else 0
    verdict = "WINS" if ok else "fails"
    return Floor(
        kind="constant", label=f"always emit {probe.degenerate[:34]!r}",
        passed=passed, of=probe.samples, deterministic=True,
        note=f"{verdict} — {detail[:40]}")


def verb_choice_score(model: Any, tok: Any) -> tuple[int, int, list[str]]:
    """Constrained decoding: does the model pick a *sensible* verb?

    Separated from ``action-json`` on purpose. That probe conflated two things —
    whether the model can write valid JSON, and whether it picks the right verb —
    and reported the sum as capability. With constrained decoding the first is
    guaranteed by construction, so what remains is judgement, and judgement is
    the thing that should improve with training. Measuring them together meant a
    syntax failure and a reasoning failure were the same number.
    """
    _catalogue()

    from whetstone.actions import REGISTRY, TargetKind
    from whetstone.gate import Gate, null_engagement
    from training.constrained import decode_action
    from training.tokenizer.protocol import ACT, BOS, HOST, SCOPE, TASK, VERBS

    gate = Gate(null_engagement(), registry=REGISTRY)
    permitted = [v for v in gate.catalogue() if v.target is TargetKind.HOST]
    catalogue = "; ".join(
        f"{v.id}({', '.join(p.name for p in v.params)})" for v in permitted)[:400]

    hits = 0
    detail: list[str] = []
    for task, acceptable in VERB_CHOICE_TASKS:
        # The explicit BOS belongs here and nowhere else in this file.
        # `decode_action` scores candidates through `score_continuations`, which
        # encodes the prompt bare, so this path must write its own bos while the
        # `generate` probes must not write theirs. Same token sequence, two
        # different routes to it; assuming they behave alike is what produced a
        # double bos in `action-json`.
        prompt = (f"{BOS}{TASK}{task}{HOST}macos{SCOPE}observe; loopback only"
                  f"{VERBS}{catalogue}{ACT}")
        got = decode_action(model, tok, prompt, permitted=permitted,
                            target="127.0.0.1")
        ok = got.verb.id in acceptable
        hits += ok
        detail.append(f"{'✓' if ok else '·'} {task[:38]:<40} -> {got.verb.id}")
    return hits, len(VERB_CHOICE_TASKS), detail


def run_bench(checkpoint: Path, tokenizer: Path, *, temperature: float = 0.7,
              seed: int = 0, only: list[str] | None = None) -> list[Probe]:
    from tokenizers import Tokenizer

    from training.generate import generate, load_for_inference

    tok = Tokenizer.from_file(str(tokenizer))

    # CHECK THE INSTRUMENT FIRST, and check all of PROBES rather than only the
    # selected ones: a probe that cannot fail is broken whether or not this
    # particular run prints it, and finding that out from `--only` would mean
    # the fault hides exactly when someone is narrowing in on a result. Ahead of
    # loading the model so a design fault costs nothing to discover.
    assert_probes_can_fail(PROBES)
    assert_prompts_carry_no_bos(PROBES, tok)

    model, cfg = load_for_inference(checkpoint)
    step = json.loads((checkpoint / "state.json").read_text())["step"]

    probes = [p for p in PROBES if not only or p.name in only]

    print(f"whetbench — {cfg.name} {cfg.n_params/1e6:.1f}M params, step {step:,}")
    print(f"{'probe':<20}{'pass':>8}   measures")
    print("-" * 96)

    for probe in probes:
        # PROBES is module state and `results` is a mutable default on it, so a
        # second run_bench in one process would append to the first run's list
        # and print "10/10" for five samples. Cleared here rather than by asking
        # callers to remember, because the failure mode is a number that is
        # merely too large and reads as an unusually good checkpoint.
        probe.results.clear()
        for i in range(probe.samples):
            text = generate(model, tok, probe.prompt,
                            max_tokens=probe.max_tokens,
                            temperature=temperature, seed=seed + i)
            # The CONTINUATION alone. This scored `probe.prompt + text`, which
            # meant every probe was graded partly on text the benchmark itself
            # wrote: the two register probes passed on their prompts before the
            # model emitted anything. Nothing here needs prompt context — every
            # checker looks for a pattern the model must produce — and if one
            # ever did, the right answer is a probe whose prompt cannot supply
            # it, not a join here that flatters all seven.
            probe.results.append(probe.check(text))

        rate = probe.passed / max(len(probe.results), 1)
        mark = "SKIP" if probe.skipped else f"{probe.passed}/{len(probe.results)}"
        print(f"{probe.name:<20}{mark:>8}   {probe.measures[:64]}")
        for ok, detail in probe.results[:2]:
            print(f"{'':<20}{'✓' if ok else '·':>8}   {detail[:64]}")
        print()

    return probes


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Benchmark a Whetstone checkpoint.")
    p.add_argument("--checkpoint", type=Path, required=True)
    p.add_argument("--tokenizer", type=Path, required=True)
    p.add_argument("--temperature", type=float, default=0.7)
    p.add_argument("--samples", type=int, default=None)
    p.add_argument("--only", nargs="*")
    p.add_argument("--json", type=Path, help="also write results here")
    args = p.parse_args(argv)

    if args.samples:
        for probe in PROBES:
            probe.samples = args.samples

    probes = run_bench(args.checkpoint, args.tokenizer,
                       temperature=args.temperature, only=args.only)

    # Constrained decoding is reported separately because it answers a
    # different question: not "can it write an action" but "does it choose a
    # sensible one". Validity is guaranteed there, so a low score here is
    # judgement and nothing else.
    if not args.only or "verb-choice" in args.only:
        from training.generate import load_for_inference
        from tokenizers import Tokenizer as _T
        _model, _cfg = load_for_inference(args.checkpoint)
        _tok = _T.from_file(str(args.tokenizer))
        hits, total, detail = verb_choice_score(_model, _tok)
        print(f"{'verb-choice':<20}{f'{hits}/{total}':>8}   CONSTRAINED decoding: "
              f"validity is guaranteed, so this is judgement alone")
        for line in detail:
            print(f"{'':<20}{'':>8}   {line}")
        print()

    print("-" * 96)
    print("Deliberately not averaged into one score: these probes measure "
          "unrelated capabilities,\nand a single headline would imply a grade "
          "where what matters is WHICH capability appeared.")

    if args.json:
        args.json.write_text(json.dumps([
            {"probe": p.name, "passed": p.passed, "of": len(p.results),
             "measures": p.measures,
             "details": [d for _ok, d in p.results]}
            for p in probes], indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
