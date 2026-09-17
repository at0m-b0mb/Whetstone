"""Tests for the agent loop.

The detection pairing is the project's central claim, and it is tested here with
a stub executor rather than by running real exploits. That is not squeamishness:
the logic under test is "given that the technique ran, and given what the
detection said, what should be recorded" — and that logic is independent of
whether a scheduled task was genuinely created on someone's laptop. Exercising
the real red path belongs in the lab, against a machine that exists to be broken.

The distinction the tests care most about is between *silence* and *cannot tell*.
A detection that says nothing fired is a finding. A detection that failed to run
tells you nothing about the control, and reporting it as a gap manufactures a
finding out of a broken query. A report full of those is a report nobody acts on.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from whetstone.actions import (
    NO_DETECTION,
    Action,
    Intent,
    Observation,
    Param,
    Side,
    TargetKind,
    Verb,
    VerbRegistry,
)
from whetstone.gate import Gate, always_confirm
from whetstone.gate.engagement import Authorization, Engagement, Scope
from whetstone.kernel import (
    Episode,
    Finding,
    HeuristicChooser,
    Kernel,
    Turn,
    detection_fired,
)

#: Relative to the real clock, not a fixed instant. The Kernel calls
#: Gate.submit without a `now` override — it is a live loop, not a pure
#: function — so a hardcoded window silently expires as wall-clock passes it and
#: every test starts failing on engagement.expired. The gate's own tests can
#: freeze time because decide() takes `now`; these cannot.
def _now() -> datetime:
    return datetime.now(timezone.utc)


def _registry() -> VerbRegistry:
    r = VerbRegistry()
    r.register(Verb(id="enum.host", summary="Look.", intent=Intent.OBSERVE,
                    side=Side.NEUTRAL, target=TargetKind.HOST))
    r.register(Verb(id="detect.saw_it", summary="A detection.",
                    intent=Intent.OBSERVE, side=Side.BLUE, target=TargetKind.HOST,
                    params=(Param("since_seconds", "integer", "window",
                                  required=False, default=300),)))
    r.register(Verb(id="exploit.thing", summary="Prove it.",
                    intent=Intent.EXECUTE, side=Side.RED, target=TargetKind.HOST,
                    attck=("T1547.001",), caution="Runs code.",
                    detected_by=("detect.saw_it",)))
    r.register(Verb(id="exploit.uncovered", summary="Nothing sees this.",
                    intent=Intent.EXECUTE, side=Side.RED, target=TargetKind.HOST,
                    attck=("T1041",), caution="Runs code.",
                    detected_by=(NO_DETECTION,)))
    r.register(Verb(id="enum.absent", summary="Not on this platform.",
                    intent=Intent.OBSERVE, side=Side.NEUTRAL,
                    target=TargetKind.HOST))
    return r.freeze()


REG = _registry()


def _engagement(**kw) -> Engagement:
    base = dict(
        name="kernel test",
        authorization="TICKET-1, test only",
        starts=_now() - timedelta(hours=1),
        expires=_now() + timedelta(hours=12),
        scope=Scope(hosts=("10.0.0.0/24",)),
        authorize=Authorization(
            red_team=True, max_intent=Intent.EXECUTE,
            techniques=("T1547", "T1041"),
            unattended=frozenset({Intent.OBSERVE, Intent.EXECUTE})),
    )
    base.update(kw)
    return Engagement(**base)


class StubExecutor:
    """Returns scripted observations. Records what it was asked to run."""

    platform = "stub"

    def __init__(self, responses: dict[str, Observation | str] | None = None):
        self.responses = responses or {}
        self.calls: list[str] = []

    def execute(self, verb: Verb, action: Action) -> Observation:
        self.calls.append(verb.id)
        canned = self.responses.get(verb.id)
        if isinstance(canned, Observation):
            return Observation(action=action, ok=canned.ok, data=canned.data,
                               error=canned.error, unsupported=canned.unsupported,
                               platform=self.platform)
        if canned == "unsupported":
            return Observation(action=action, ok=False, unsupported=True,
                               platform=self.platform, error="no such concept here")
        if canned == "error":
            return Observation(action=action, ok=False, platform=self.platform,
                               error="command failed")
        return Observation(action=action, ok=True, data={"ran": True},
                           platform=self.platform)


def _kernel(responses=None, chooser=None, **kw) -> tuple[Kernel, StubExecutor]:
    ex = StubExecutor(responses)
    gate = Gate(_engagement(), registry=REG, confirmer=always_confirm)
    return Kernel(gate, ex, chooser, **kw), ex


class OneShot:
    """A chooser that plays a fixed list of verbs, once each."""

    def __init__(self, *verb_ids: str):
        self.queue = list(verb_ids)

    def choose(self, episode, permitted, *, exclude, target):
        while self.queue:
            verb_id = self.queue.pop(0)
            if verb_id in exclude:
                continue
            verb = REG.get(verb_id)
            params = {p.name: p.default for p in verb.params
                      if p.default is not None}
            return verb.bind(params, target=target)
        return None


# --------------------------------------------------------------------------
# detection_fired — the silence / cannot-tell distinction
# --------------------------------------------------------------------------


class TestDetectionFired:
    def _obs(self, **kw) -> Observation:
        action = REG.bind("detect.saw_it", {}, target="10.0.0.5")
        base = dict(action=action, ok=True)
        base.update(kw)
        return Observation(**base)

    def test_explicit_logged_true(self):
        assert detection_fired(self._obs(data={"logged": True})) is True

    def test_explicit_logged_false(self):
        assert detection_fired(self._obs(data={"logged": False})) is False

    def test_hit_count_is_read(self):
        assert detection_fired(self._obs(data={"count": 3})) is True
        assert detection_fired(self._obs(data={"count": 0})) is False

    def test_failed_probe_is_cannot_tell_not_silence(self):
        """The distinction the whole finding logic rests on."""
        assert detection_fired(self._obs(ok=False, error="query failed")) is None

    def test_unsupported_probe_is_cannot_tell(self):
        assert detection_fired(self._obs(ok=False, unsupported=True)) is None

    def test_unrecognised_payload_is_cannot_tell(self):
        """Better to say "do not know" than to guess a gap into existence."""
        assert detection_fired(self._obs(data={"something": "else"})) is None

    def test_telemetry_source_list(self):
        assert detection_fired(self._obs(
            data={"sources": [{"source": "a", "enabled": False}]})) is False
        assert detection_fired(self._obs(
            data={"sources": [{"source": "a", "enabled": True}]})) is True


# --------------------------------------------------------------------------
# the pairing
# --------------------------------------------------------------------------


class TestDetectionPairing:
    def test_silent_detection_becomes_a_gap(self):
        """The artefact this project exists to produce."""
        kernel, ex = _kernel(
            responses={"detect.saw_it": Observation(
                action=REG.bind("detect.saw_it", {}, target="10.0.0.5"),
                ok=True, data={"logged": False})},
            chooser=OneShot("exploit.thing"))
        ep = kernel.run("prove it", target="10.0.0.5")

        assert "detect.saw_it" in ex.calls, "the detection must be run after the exploit"
        gaps = [f for f in ep.findings if f.kind == "detection_gap"]
        assert len(gaps) == 1
        assert gaps[0].technique == "T1547.001"
        assert gaps[0].expected == "detect.saw_it"

    def test_firing_detection_produces_no_gap(self):
        kernel, _ex = _kernel(
            responses={"detect.saw_it": Observation(
                action=REG.bind("detect.saw_it", {}, target="10.0.0.5"),
                ok=True, data={"logged": True})},
            chooser=OneShot("exploit.thing"))
        ep = kernel.run("prove it", target="10.0.0.5")
        assert not [f for f in ep.findings if f.kind == "detection_gap"]

    def test_broken_probe_is_not_reported_as_a_gap(self):
        """A failed query is not evidence about the control."""
        kernel, _ex = _kernel(
            responses={"detect.saw_it": "error"},
            chooser=OneShot("exploit.thing"))
        ep = kernel.run("prove it", target="10.0.0.5")
        assert not [f for f in ep.findings if f.kind == "detection_gap"]
        assert [f for f in ep.findings if f.kind == "observation"]

    def test_declared_no_coverage_is_its_own_finding(self):
        """"We did not look" and "we looked and saw nothing" are different claims."""
        kernel, ex = _kernel(chooser=OneShot("exploit.uncovered"))
        ep = kernel.run("prove it", target="10.0.0.5")
        kinds = {f.kind for f in ep.findings}
        assert kinds == {"no_coverage"}
        assert "detect.saw_it" not in ex.calls

    def test_neutral_verbs_trigger_no_pairing(self):
        kernel, ex = _kernel(chooser=OneShot("enum.host"))
        ep = kernel.run("look", target="10.0.0.5")
        assert ex.calls == ["enum.host"]
        assert ep.findings == []

    def test_pairing_can_be_disabled(self):
        kernel, ex = _kernel(chooser=OneShot("exploit.thing"),
                             pair_detections=False)
        kernel.run("prove it", target="10.0.0.5")
        assert "detect.saw_it" not in ex.calls


# --------------------------------------------------------------------------
# critique: refusals and impossibilities
# --------------------------------------------------------------------------


class TestCritique:
    def test_refusal_is_recorded_not_raised(self):
        kernel, ex = _kernel(chooser=OneShot("enum.host"))
        ep = kernel.run("look", target="192.168.99.1")     # out of scope
        assert len(ep.turns) == 1
        assert ep.turns[0].refused
        assert ep.turns[0].decision.rule == "scope.host.unlisted"
        assert ex.calls == [], "a refused action must never reach the executor"

    def test_refused_verb_is_excluded_from_retry(self):
        """Otherwise the loop proposes the same denied action until it runs out."""
        kernel, _ex = _kernel(chooser=OneShot("enum.host", "enum.host", "enum.host"))
        ep = kernel.run("look", target="192.168.99.1")
        assert len(ep.turns) == 1

    def test_unsupported_is_not_retried(self):
        """A platform fact, not a transient failure."""
        kernel, ex = _kernel(responses={"enum.absent": "unsupported"},
                             chooser=OneShot("enum.absent", "enum.absent"))
        ep = kernel.run("look", target="10.0.0.5")
        assert ex.calls == ["enum.absent"]
        assert ep.turns[0].observation.unsupported

    def test_max_turns_is_respected(self):
        kernel, _ex = _kernel(chooser=HeuristicChooser(), max_turns=2)
        ep = kernel.run("look", target="10.0.0.5")
        assert len(ep.turns) <= 2

    def test_chooser_returning_none_stops_cleanly(self):
        kernel, _ex = _kernel(chooser=OneShot())
        ep = kernel.run("look", target="10.0.0.5")
        assert ep.turns == []


# --------------------------------------------------------------------------
# an episode is a trajectory
# --------------------------------------------------------------------------


class TestEpisodeRendering:
    def test_renders_the_wire_protocol(self):
        kernel, _ex = _kernel(
            responses={"detect.saw_it": Observation(
                action=REG.bind("detect.saw_it", {}, target="10.0.0.5"),
                ok=True, data={"logged": False})},
            chooser=OneShot("exploit.thing"))
        text = kernel.run("prove it", target="10.0.0.5").render()

        for marker in ("<|bos|>", "<|task|>", "<|host|>", "<|scope|>",
                       "<|verbs|>", "<|act|>", "<|obs|>", "<|find|>", "<|eos|>"):
            assert marker in text, marker

    def test_refusal_appears_as_a_gate_segment(self):
        """The recovery signal. Dropping denied actions teaches a model that
        never needs to correct."""
        kernel, _ex = _kernel(chooser=OneShot("enum.host"))
        text = kernel.run("look", target="192.168.99.1").render()
        assert "<|gate|>" in text
        assert "scope.host.unlisted" in text

    def test_emitted_actions_round_trip_through_the_registry(self):
        """Whatever the loop rendered must be something the registry accepts."""
        import json
        import re

        kernel, _ex = _kernel(chooser=OneShot("enum.host", "exploit.thing"))
        text = kernel.run("go", target="10.0.0.5").render()
        blobs = re.findall(r"<\|act\|>(\{.*?\})(?=<\|)", text)
        assert blobs
        for blob in blobs:
            REG.parse(json.loads(blob))

    def test_observations_are_capped_with_the_cut_stated(self):
        from whetstone.kernel.render import shrink_payload
        out = shrink_payload({"items": list(range(50))})
        assert out["items"][-1] == "+46 more"

    def test_protocol_markers_match_the_training_definitions(self):
        """The runtime duplicates these rather than importing from training/.

        The dependency runs one way on purpose, so the duplication is
        deliberate — and a mismatch would silently produce trajectories the
        tokenizer has no special tokens for.
        """
        pytest.importorskip("tokenizers")
        from training.tokenizer import protocol as p
        from whetstone.kernel import render as r

        for name in ("BOS", "EOS", "TASK", "HOST", "SCOPE", "VERBS",
                     "ACT", "OBS", "GATE", "FIND"):
            assert getattr(r, name) == getattr(p, name), name
