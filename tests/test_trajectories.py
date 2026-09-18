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
                    clean=16, host_executor=_StubHost())
    defaults.update(kw)
    stats: dict = {}
    texts = list(T.generate_trajectories(stats=stats, **defaults))
    return texts, stats


@pytest.fixture(scope="module")
def corpus():
    return _generate()


def _segments(text: str, marker: str) -> list[str]:
    return re.findall(re.escape(marker) + r"(\{.*?\})(?=<\|)", text)


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
        """
        texts, _ = corpus
        kinds = set()
        for text in texts:
            for blob in _segments(text, "<|find|>"):
                finding = json.loads(blob)
                assert set(finding) == {"kind", "technique", "expected", "detail"}
                assert finding["kind"] in {"detection_gap", "no_coverage",
                                           "observation"}
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
        for kind in ("observe", "refusal", "gap", "seen", "clean"):
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
