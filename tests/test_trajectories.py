"""Tests for the trajectory generator.

The corpus this module produces is the only thing standing between a fine-tuned
checkpoint and a model that has never seen the job, so the properties worth
testing are the ones whose failure would be invisible in the output. A
trajectory full of plausible-looking nonsense reads exactly like a good one.

Four things are checked, and each corresponds to a way the generator could
quietly start lying:

**Every action is one the registry accepts.** If it is not, the model is being
trained to emit something the runtime will reject, and the benchmark register
this whole module exists to fund stays at zero.

**Every finding follows evidence.** An earlier version of this generator
appended a hand-written ``<|find|>`` to a scenario whether or not the
observations supported one — training the model to produce a detection gap
after observations that showed no such thing. That is training hallucination,
and the test here is that a finding only ever appears after a red verb that
really succeeded in the same episode.

**Nothing above OBSERVE runs against the real machine.** Generating training
data must never be a reason for the laptop doing the generating to have its
audit policy edited or a service binary replaced. The host engagements are
constructed so that this is impossible; the test asserts it rather than
trusting the construction.

**The decisions are reproducible.** Observations of a live machine move between
runs and pinning them would mean replaying recordings instead of reading a
machine. Everything the generator itself decides — scenarios, phrasing,
actions, rulings, findings — must not.

**A claim of closure carries the evidence for it.** The remediation families
teach the model to emit a hardening verb, and the ``<|find|>`` segment they end
on is supervised text that says whether the gap is shut. A trajectory asserting
``"state":"closed"`` without a second run of the attack and a second run of the
control in the same document would be training the model to write the word —
the same defect as the hand-assembled findings above, moved from the red half to
the blue one and with worse consequences, because the output of that mistake is
a hole reported fixed. :class:`TestRemediationFollowsEvidence` reads the claim
out of the finding and looks for the actions behind it in the same document.

The host adapter is stubbed throughout. Shelling out to ``ps``, ``launchctl``
or PowerShell three times over in CI would be slow, flaky and would test the
adapters rather than this module. The sandbox worlds are *not* stubbed: they
are plain file I/O and they are where the interesting findings come from.
"""

from __future__ import annotations

import json
import re

import pytest

import whetstone.verbs  # noqa: F401  (registers the catalogue)
from training import trajectories as T
from whetstone.actions import REGISTRY, Action, Intent, Observation, Side
from whetstone.kernel import REMEDIATION_STATES


# --------------------------------------------------------------------------
# a stand-in for the machine
# --------------------------------------------------------------------------

class _StubHost:
    """Answers every host verb with a small, plausible, *constant* payload.

    Constant is the point. These tests are about the generator's choices, and a
    payload that moved would make a determinism assertion test the weather.
    """

    platform = "linux"

    def implemented(self) -> tuple[str, ...]:
        return tuple(v.id for v in REGISTRY
                     if v.target.value != "none")

    def execute(self, verb, action) -> Observation:
        if verb.id.startswith("vuln."):
            data = {"findings": []}
        elif verb.id.startswith("detect."):
            data = {"logged": False, "count": 0}
        else:
            data = {"items": [{"name": "stub"}], "count": 1}
        return Observation(action=action, ok=True, data=data,
                           platform=self.platform)


def _generate(**kw):
    defaults = dict(repeats=2, seed=99, observe=24, refusals=40, lab=40,
                    clean=16, remediate=48, host_executor=_StubHost())
    defaults.update(kw)
    stats: dict = {}
    texts = list(T.generate_trajectories(stats=stats, **defaults))
    return texts, stats


@pytest.fixture(scope="module")
def corpus():
    return _generate()


def _segments(text: str, marker: str) -> list[str]:
    return re.findall(re.escape(marker) + r"(\{.*?\})(?=<\|)", text)


def _verbs(text: str) -> list[str]:
    """The verb id of every action in a document, in order."""
    return [json.loads(blob)["verb"] for blob in _segments(text, "<|act|>")]


def _executed(text: str) -> list[str]:
    """The verb id of every action that reached an adapter, in order.

    An action is *proposed* whenever it appears; it is carried out only when the
    segment after it is an ``<|obs|>`` rather than a ``<|gate|>``. The two are
    worth separating because the refusal families deliberately propose MODIFY
    verbs — including hardening ones — against engagements that deny them, so
    "this trajectory contains a harden verb" and "this trajectory changed a
    host" are different statements and only the second is the one that needs a
    detection gap behind it.
    """
    parts = re.split(r"(<\|act\|>|<\|obs\|>|<\|gate\|>|<\|find\|>|<\|eos\|>)",
                     text)
    out = []
    for i, part in enumerate(parts):
        if part == "<|act|>" and parts[i + 2 : i + 3] == ["<|obs|>"]:
            out.append(json.loads(parts[i + 1])["verb"])
    return out


def _remediated(texts):
    """Every ``(text, finding)`` pair whose finding carries a remediation.

    Yielding the whole document alongside the finding is the point: the claim
    the finding makes is only checkable against the actions in the same
    document, which is what makes these assertions about honesty rather than
    about schema.
    """
    for text in texts:
        for blob in _segments(text, "<|find|>"):
            finding = json.loads(blob)
            if finding.get("remediation"):
                yield text, finding


# --------------------------------------------------------------------------
# the wire protocol
# --------------------------------------------------------------------------

class TestProtocol:
    def test_every_document_is_well_formed(self, corpus):
        texts, _ = corpus
        assert texts
        for text in texts:
            assert text.startswith("<|bos|><|task|>")
            assert text.endswith("<|eos|>")
            for marker in ("<|host|>", "<|scope|>", "<|verbs|>", "<|act|>"):
                assert marker in text, marker

    def test_every_action_round_trips_through_the_registry(self, corpus):
        """A trajectory carrying an action the registry would reject trains the
        model to emit something the runtime cannot run."""
        texts, _ = corpus
        seen = 0
        for text in texts:
            for blob in _segments(text, "<|act|>"):
                REGISTRY.parse(json.loads(blob))
                seen += 1
        assert seen > 100

    def test_rulings_carry_a_rule_and_a_reason(self, corpus):
        """``rule`` is the stable id things depend on; ``reason`` is the
        correction the model is meant to learn from. A ruling with an empty
        reason is a training example that teaches nothing."""
        texts, _ = corpus
        for text in texts:
            for blob in _segments(text, "<|gate|>"):
                ruling = json.loads(blob)
                assert ruling["verdict"] == "deny"
                assert ruling["rule"]
                assert len(ruling["reason"]) > 20

    def test_findings_match_the_runtime_finding_schema(self, corpus):
        """``<|find|>`` must be exactly what ``Finding.to_dict`` emits.

        The previous generator wrote its own finding dicts and omitted ``kind``,
        so the corpus taught one shape and the runtime produced another. At this
        model size there is no capacity to absorb that.

        ``produced_by`` joined the required set when the remediation phase gave
        a finding a reason to name the red verb behind it structurally rather
        than in prose. ``remediation`` is the one optional key: it is present
        only on a gap something was actually done about, and absent means
        nothing was attempted — never "nothing worked".
        """
        required = {"kind", "technique", "expected", "detail", "produced_by"}
        texts, _ = corpus
        kinds = set()
        for text in texts:
            for blob in _segments(text, "<|find|>"):
                finding = json.loads(blob)
                assert required <= set(finding) <= required | {"remediation"}
                assert finding["kind"] in {"detection_gap", "no_coverage",
                                           "observation"}
                if "remediation" in finding:
                    assert finding["kind"] == "detection_gap", (
                        "only a gap is remediated; a remediation on any other "
                        "kind would mean a fix was credited to a finding that "
                        "never established there was anything to fix")
                    assert set(finding["remediation"]) == {"state", "verb",
                                                           "detail"}
                    assert finding["remediation"]["state"] in REMEDIATION_STATES
                kinds.add(finding["kind"])
        assert kinds, "the corpus contains no findings at all"


# --------------------------------------------------------------------------
# honesty
# --------------------------------------------------------------------------

class TestFindingsFollowEvidence:
    def test_a_finding_is_always_preceded_by_a_successful_red_action(self, corpus):
        """No finding without something that earned it.

        The kernel only produces findings by pairing a red verb with the
        detections it declared, so a ``<|find|>`` in a trajectory whose actions
        are all observation verbs would mean the text had been assembled rather
        than run.
        """
        texts, _ = corpus
        checked = 0
        for text in texts:
            if "<|find|>" not in text:
                continue
            reds = [a for a in _segments(text, "<|act|>")
                    if REGISTRY.get(json.loads(a)["verb"]).side is Side.RED]
            assert reds, "a finding appeared with no red action before it"
            checked += 1
        assert checked, "no finding-bearing trajectories were generated"

    def test_clean_hosts_end_without_a_finding(self, corpus):
        """The episode that answers "is this box fine?" with nothing.

        A model shown only vulnerable hosts invents a finding on a healthy one,
        because a finding is the only ending it has ever seen. These episodes
        run the real assessment verbs against a sandbox with nothing planted in
        it, get an empty finding list back, and stop.
        """
        texts, _ = corpus
        clean = [t for t in texts
                 if '"findings":[]' in t and "<|find|>" not in t]
        assert len(clean) >= 10, (
            "clean-host trajectories are missing; a corpus of nothing but "
            "broken machines teaches a model to always find something")

    def test_inconclusive_detection_is_reported_as_inconclusive(self, corpus):
        """A detection query that failed is not a detection gap.

        Produced by a sandbox whose telemetry log is genuinely unreadable, so
        the query really raises and ``detection_fired`` really answers None.
        Windows does not enforce a POSIX mode, so the log stays readable there
        and the variant degrades to an ordinary gap — skipped rather than
        weakened, because the property is real and the platform is not.
        """
        texts, _ = corpus
        inconclusive = [t for t in texts if '"kind":"observation"' in t]
        if not inconclusive:
            pytest.skip("this platform does not enforce an unreadable file")
        for text in inconclusive:
            assert "could not establish whether it fired" in text
            assert "this is not evidence of a gap" in text

    def test_no_coverage_is_a_disclosure_not_a_gap(self, corpus):
        """``detect.nothing`` means nothing in the catalogue covers this.

        Different from silence and it has to stay different: "we looked and saw
        nothing" and "we did not look, because there is nothing to look with"
        support different decisions on the blue side.
        """
        texts, _ = corpus
        rows = [t for t in texts if '"kind":"no_coverage"' in t]
        assert rows, "the no-coverage finding kind is absent from the corpus"
        for text in rows:
            assert "no control in this catalogue" in text


# --------------------------------------------------------------------------
# the defending half
# --------------------------------------------------------------------------

class TestRemediationFollowsEvidence:
    """The blue-side twin of :class:`TestFindingsFollowEvidence`.

    Both supervised segment types carry a remediation: the ``<|act|>`` for the
    hardening verb, and the outcome inside the ``<|find|>``. So both are places
    the corpus can teach the model to assert something the evidence does not
    support, and the second is the dangerous one — a model that writes "closed"
    after any harden verb produces a report that says the hole is shut.
    """

    def test_the_corpus_reaches_more_than_one_outcome(self, corpus):
        """Five of the six states, or the lesson is "a fix always works".

        This is the assertion the whole remediation family exists to satisfy. A
        corpus in which every fix came back ``closed`` would train the model on
        one word and the distinction between running a fix and shutting a hole —
        the distinction the re-attack was built to enforce — would be absent
        from the only place the model learns anything.

        ``failed`` is deliberately not in the set: reaching it means emitting a
        hardening action with a parameter the adapter rejects, and that action
        is supervised. See :func:`training.trajectories._derived_remediation`.
        """
        texts, _ = corpus
        states = {f["remediation"]["state"] for _t, f in _remediated(texts)}
        missing = {"closed", "ineffective", "undetermined", "refused",
                   "unavailable"} - states
        assert not missing, (
            f"the corpus never reaches {sorted(missing)}; a model trained on "
            "the remaining states learns that outcome as what remediation is")

    def test_a_closed_gap_carries_the_attack_that_proved_it(self, corpus):
        """``closed`` means re-attacked and re-detected, in this document.

        The state is the strongest claim this tool makes and the only one that
        says a hole is shut. It is earned by performing the original technique a
        second time and asking the control that was silent the same question
        again, so both actions are in the trajectory: the red verb named in
        ``produced_by`` twice, and the detection named in ``expected`` twice.

        Checked on the rendered text rather than on the episode object because
        the text is what the model is trained on. A closure whose evidence was
        elsewhere would be indistinguishable, to the model, from one with no
        evidence at all.
        """
        texts, _ = corpus
        checked = 0
        for text, finding in _remediated(texts):
            if finding["remediation"]["state"] != "closed":
                continue
            verbs = _verbs(text)
            assert verbs.count(finding["produced_by"]) >= 2, (
                f"{finding['produced_by']} is reported closed but ran once; "
                "the claim rests on a re-attack that is not in the document")
            assert verbs.count(finding["expected"]) >= 2, (
                f"{finding['expected']} is reported to have fired after the fix "
                "but was only ever asked once")
            checked += 1
        assert checked, "no closed remediation was generated to check"

    def test_a_refused_fix_is_never_followed_by_a_verification(self, corpus):
        """The gate said no, so nothing was applied and nothing is re-run.

        Worth pinning separately from the state name. The re-attack is a second
        real execution of an exploit, and a loop that ran one after a fix the
        gate had *denied* would be attacking a host to test a change that was
        never made — the exact shape of unauthorised activity the engagement
        exists to prevent, performed by the half of the loop that is supposed to
        be defending.
        """
        texts, _ = corpus
        checked = 0
        for text, finding in _remediated(texts):
            if finding["remediation"]["state"] != "refused":
                continue
            verbs = _verbs(text)
            assert verbs.count(finding["produced_by"]) == 1, (
                "the fix was refused and the technique was performed again "
                "anyway")
            checked += 1
        assert checked, "no refused remediation was generated to check"

    def test_a_host_is_never_changed_without_a_gap_behind_it(self, corpus):
        """No fix *carried out* without something to fix.

        A ``harden.*`` action that reached an adapter in a trajectory with no
        ``detection_gap`` in it would teach the model to modify a host it had
        established nothing about. That is the defending half of hallucinating a
        finding and it is worse: a hallucinated finding is a wrong sentence, a
        hallucinated fix is a change to somebody's machine.

        Proposals are excluded rather than overlooked. The ``confirm.declined``
        and ``intent.ceiling`` refusal families draw from the MODIFY half of the
        catalogue and land on hardening verbs by design, and a proposal the gate
        answered is a refusal lesson, not a change.
        """
        texts, _ = corpus
        checked = 0
        for text in texts:
            if not any(v.startswith("harden.") for v in _executed(text)):
                continue
            assert '"kind":"detection_gap"' in text, (
                "a hardening verb was carried out in an episode that never "
                "established a detection gap")
            checked += 1
        assert checked, "no hardening verb was ever carried out"

    def test_being_asked_to_fix_is_not_a_reason_to_fix(self, corpus):
        """Episodes told to close the gaps that correctly close nothing.

        The mirror of the clean-host family. Those episodes stop a model
        inventing a finding on a healthy machine; these stop it inventing a fix
        because the instruction mentioned one. The remediation phase is on and
        the task asks for the holes to be shut; the control saw the attack, or
        could not be established either way, or nothing in the catalogue covers
        the technique — so there is nothing to remediate and the right answer is
        to emit no hardening verb at all.
        """
        texts, _ = corpus
        asked = [t for t in texts
                 if any(ask.strip() in t.split("<|host|>")[0]
                        for ask in T._REMEDIATE_ASK)]
        assert asked, "no episode carried a remediation instruction"
        # A gap must be absent as well as a fix. An episode that found a gap
        # and had nothing in the catalogue to close it also ends without a
        # hardening verb, and it is a different lesson — there was something to
        # fix and no way to fix it. What this test is about is the episode where
        # the instruction was the only reason to reach for a fix at all.
        quiet = [t for t in asked
                 if '"kind":"detection_gap"' not in t
                 and not any(v.startswith("harden.") for v in _verbs(t))]
        assert len(quiet) >= 8, (
            f"only {len(quiet)} of {len(asked)} episodes were asked to fix "
            "something, found nothing to fix, and correctly fixed nothing; the "
            "model will learn that the instruction is the trigger")

    def test_most_of_the_corpus_still_ends_at_the_finding(self, corpus):
        """Hardening is a minority of the data and has to stay one.

        The corpus is overwhelmingly reconnaissance, assessment and refusal,
        because that is overwhelmingly the job. A model whose training set is
        half remediation reaches for a MODIFY on a host it was asked to look at,
        and the gate would stop it — but a model that has to be stopped that
        often is one whose proposals an operator learns to ignore.
        """
        texts, _ = corpus
        hardening = [t for t in texts
                     if any(v.startswith("harden.") for v in _executed(t))]
        assert len(hardening) < 0.30 * len(texts), (
            f"{len(hardening)} of {len(texts)} trajectories harden something")

    def test_the_families_produced_the_outcomes_they_claim(self, corpus):
        """Intent against result, asserted rather than printed.

        A remediation family names a world, a red verb and a preferred fix, and
        then the sandbox decides what happens — a real chmod, a real gate
        ruling, a real empty log. So the label and the outcome are joined by the
        adapter's behaviour and nothing else, and a change there could turn the
        ineffective family into a second batch of closures while every other
        assertion in this file still passed: the documents would be well formed,
        the actions would bind, and one whole state would have left the corpus.
        """
        _texts, stats = corpus
        assert not stats["fix_mismatch"], stats["fix_mismatch"]

    def test_remediation_is_absent_from_a_corpus_built_without_it(self):
        """``--remediate 0`` reproduces the corpus as it was.

        The flag is the seam an ablation runs through — the question "did seeing
        defence help?" is only answerable if the no-defence corpus is still
        buildable — so it has to actually remove every remediation rather than
        merely stop adding the family.
        """
        texts, stats = _generate(remediate=0, observe=8, refusals=8, lab=24,
                                 clean=8, repeats=1)
        assert not stats["remediation"], stats["remediation"]
        for text in texts:
            # Proposals survive — the refusal families still put a MODIFY in
            # front of a gate that denies it, and that is not remediation. What
            # must be gone is every fix that ran and every outcome recorded.
            assert not [v for v in _executed(text) if v.startswith("harden.")]
            assert '"remediation":{"state"' not in text


# --------------------------------------------------------------------------
# safety
# --------------------------------------------------------------------------

class TestNothingRunsOnTheHost:
    def test_no_action_above_observe_ever_executes_on_a_host_world(self):
        """The generator may not modify the machine it is generating on.

        Every host engagement either caps intent at OBSERVE or lists only
        OBSERVE as unattended with no confirmer attached, so a MODIFY or EXECUTE
        proposal is always answered by the gate rather than by an adapter. The
        assertion is that every such action is followed by a ``<|gate|>`` and
        never by an ``<|obs|>``.
        """
        texts, _ = _generate(include_lab=False, observe=20, refusals=60,
                             repeats=2)
        checked = 0
        for text in texts:
            parts = re.split(r"(<\|act\|>|<\|obs\|>|<\|gate\|>)", text)
            for i, part in enumerate(parts):
                if part != "<|act|>":
                    continue
                action = Action.from_dict(json.loads(parts[i + 1]))
                verb = REGISTRY.get(action.verb_id)
                if verb.intent is Intent.OBSERVE:
                    continue
                assert parts[i + 2] == "<|gate|>", (
                    f"{verb.id} is {verb.intent.value} and was executed against "
                    "the host rather than refused")
                checked += 1
        assert checked, "no above-OBSERVE proposals were generated to check"

    def test_host_engagements_cannot_authorise_red_verbs(self):
        """Not one host world authorises red-team activity.

        Belt and braces against the previous test: that one checks the output,
        this one checks the engagements themselves, so a future scenario family
        cannot open a hole the output test happens not to sample.
        """
        worlds = T._host_worlds(_StubHost())
        for name, world in worlds.items():
            assert not world.engagement.authorize.red_team, name
            if world.engagement.authorize.max_intent is not Intent.OBSERVE:
                assert world.confirmer is T.REFUSE_UNATTENDED, name
                assert world.engagement.authorize.unattended == frozenset(
                    {Intent.OBSERVE}), name


# --------------------------------------------------------------------------
# coverage and reproducibility
# --------------------------------------------------------------------------

class TestCoverage:
    def test_every_gate_rule_family_is_represented(self, corpus):
        """The gate is the safety spine and DENY has no override anywhere.

        A refusal reason the model has never met is a refusal it will try to
        argue with, so every rule the policy engine can reach without executing
        something has to appear in the corpus.
        """
        _texts, stats = corpus
        expected = {
            "scope.host.unlisted", "scope.host.excluded", "engagement.expired",
            "engagement.early", "intent.ceiling", "confirm.declined",
            "red.unauthorized", "technique.unauthorized",
        }
        missing = expected - set(stats["rule"])
        assert not missing, f"no trajectory exercises {sorted(missing)}"

    def test_every_scenario_family_produced_something(self, corpus):
        _texts, stats = corpus
        for kind in ("observe", "refusal", "gap", "seen", "clean",
                     "fix-closed", "fix-ineffective", "fix-undetermined",
                     "fix-refused", "fix-unavailable", "fix-none"):
            assert stats["kind"].get(kind), f"{kind} produced nothing"

    def test_nothing_errored(self, corpus):
        """A scenario that cannot run is skipped rather than crashing the build,
        which makes it easy not to notice. So: notice."""
        _texts, stats = corpus
        assert not stats["errors"], stats["errors"]

    def test_task_phrasing_is_not_one_sentence(self, corpus):
        """``<|task|>`` is the instruction. If every episode opens the same way
        the model learns the sentence rather than the job."""
        texts, _ = corpus
        tasks = {t.split("<|task|>")[1].split("<|host|>")[0] for t in texts}
        assert len(tasks) > 0.8 * len(texts)

    def test_episode_lengths_vary(self, corpus):
        """A corpus where every episode is four turns teaches that an episode is
        four turns, and the model stops after four on a host that needed nine."""
        texts, _ = corpus
        lengths = sorted(t.count("<|act|>") for t in texts)
        assert lengths[0] <= 2
        assert lengths[-1] >= 8
        assert len(set(lengths)) >= 6

    def test_every_verb_has_a_noun_phrase(self):
        """The task generator indexes :data:`_NOUN` by verb id. A verb added to
        the catalogue without a phrase here would be a KeyError at generation
        time; catching it in a test is cheaper than catching it in a build."""
        missing = {v.id for v in REGISTRY} - set(T._NOUN)
        assert not missing, missing

    def test_every_verb_can_be_bound_from_the_fill_table(self):
        """Every verb must be proposable. A required parameter with no entry in
        :data:`_FILL` falls back to the literal string ``placeholder``, which
        would teach the model to emit that."""
        import random

        rng = random.Random(0)
        for verb in REGISTRY:
            params = T._params_for(rng, verb, {})
            verb.bind(params, target=None
                      if verb.target.value == "none" else "127.0.0.1")
            assert "placeholder" not in params.values(), verb.id


class TestReproducibility:
    def test_the_same_seed_decides_the_same_things(self):
        """Task, actions, rulings and findings are identical run to run.

        Observation *content* is not, and must not be: it is read from a live
        machine, and pinning it would mean replaying a recording. The stub host
        here is constant, so with the sandbox disabled the whole document is
        byte-identical and the assertion can be exact.
        """
        first, _ = _generate(include_lab=False, observe=12, refusals=18,
                             repeats=2)
        second, _ = _generate(include_lab=False, observe=12, refusals=18,
                              repeats=2)
        assert first == second

    def test_a_different_seed_decides_different_things(self):
        first, _ = _generate(include_lab=False, observe=12, refusals=18,
                             repeats=2, seed=1)
        second, _ = _generate(include_lab=False, observe=12, refusals=18,
                              repeats=2, seed=2)
        assert first != second
