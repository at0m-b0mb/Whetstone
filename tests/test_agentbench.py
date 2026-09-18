"""Tests for the agent benchmark — because an unverified instrument is a liar.

This project has been bitten more than once by a measurement bug that pointed at
the model when the fault was in the thing doing the measuring: a non-greedy brace
match that scored a correct model 0/5, a probe written in a format no trajectory
ever used, a validation split that was 100% one source. Every one of those looked
like a capability result. So the benchmark gets tested the way the runtime does.

The load-bearing test is the pair at the bottom of :class:`TestKnownGoodChooser`:
the scripted sweep — a chooser whose behaviour is known exactly, because a human
wrote the plan — must score three gaps with telemetry off and zero with it on. If
the benchmark cannot get that right on a chooser with no ambiguity in it, nothing
it says about a model means anything.

The rest exist to check that the metrics are *independent* rather than one number
wearing several hats. A chooser that never exploits must score no gaps; a chooser
that exploits without looking must score the gaps and fail the ordering; a broken
detection probe must land in the undetermined column and in neither of the other
two. Each of those is a way the benchmark could flatter an agent, and each is
closed by a chooser built to trigger exactly that failure.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import whetstone.verbs  # noqa: F401  (registers the catalogue)
from bench.agentbench import (
    WEAKNESS_EVIDENCE,
    WEAKNESS_PROOF,
    ActionValidityError,
    provable_weaknesses,
    run_bench,
    run_episode,
)
from lab.run import ScriptedSweep
from whetstone.actions import REGISTRY, Action, Observation
from whetstone.kernel import HeuristicChooser


# --------------------------------------------------------------------------
# choosers built to break specific metrics
# --------------------------------------------------------------------------

def _bind(verb, extra=None):
    """Fill a verb's parameters the way any rule-based chooser does."""
    params = {p.name: (p.choices[0] if p.choices else p.default)
              for p in verb.params if p.required or p.default is not None}
    params = {k: v for k, v in params.items() if v is not None}
    params.update(extra or {})
    return params


class TriggerHappy:
    """Exploits immediately, having observed nothing. Gaps without judgement.

    The point of this chooser is that it scores a *perfect* gap recall. It runs
    all three exploits, the kernel pairs each with its detection, and with
    telemetry off all three come back silent. If gap recall were the only metric
    the benchmark reported, this chooser would look like a competent agent. It
    is the reason ordering is a separate axis.
    """

    ORDER = ("exploit.service_permissions", "postex.credential_dump",
             "postex.persistence_install")

    def choose(self, episode, permitted, *, exclude, target):
        done = {t.action.verb_id for t in episode.turns} | set(exclude)
        by_id = {v.id: v for v in permitted}
        for verb_id in self.ORDER:
            if verb_id in done or verb_id not in by_id:
                continue
            verb = by_id[verb_id]
            extra = ({"service": "acme-agent"}
                     if verb_id == "exploit.service_permissions" else {})
            return verb.bind(_bind(verb, extra), target=target)
        return None


class Dawdler:
    """Every observation verb first, red verbs last. Full coverage, far too late.

    The mirror image of :class:`TriggerHappy`, and the reason the coverage rows
    are re-read under a tight budget. This chooser has no judgement at all — it
    sorts by side and nothing else — yet it reaches every weakness and every gap,
    because like ``ModelChooser`` it stops only when the verb pool is empty. An
    untruncated coverage count cannot tell it apart from an agent that chose
    well. The turn it got there on can.
    """

    def choose(self, episode, permitted, *, exclude, target):
        from whetstone.actions import Side

        done = {t.action.verb_id for t in episode.turns} | set(exclude)
        pool = [v for v in permitted if v.id not in done]
        if not pool:
            return None
        observe = [v for v in pool if v.side is not Side.RED]
        verb = (observe or pool)[0]
        extra = ({"service": "acme-agent"}
                 if verb.id == "exploit.service_permissions" else {})
        return verb.bind(_bind(verb, extra), target=target)


class EarlyProbes:
    """Hunts for evidence of an attack it has not carried out yet.

    Two detection probes before any exploit. Neither can return anything but
    silence, because nothing has happened, so both are turns spent learning
    nothing — the judgement error that no coverage count will ever show.
    """

    ORDER = ("detect.process_creation", "detect.persistence_change",
             "exploit.service_permissions", "postex.credential_dump",
             "postex.persistence_install")

    def choose(self, episode, permitted, *, exclude, target):
        done = {t.action.verb_id for t in episode.turns} | set(exclude)
        by_id = {v.id: v for v in permitted}
        for verb_id in self.ORDER:
            if verb_id in done or verb_id not in by_id:
                continue
            verb = by_id[verb_id]
            extra = ({"service": "acme-agent"}
                     if verb_id == "exploit.service_permissions" else {})
            return verb.bind(_bind(verb, extra), target=target)
        return None


class OneBadAction:
    """Emits an action carrying a parameter the verb does not have.

    Hand-built rather than bound, because ``Verb.bind`` would refuse it — which
    is the whole reason an invalid action is unreachable in normal operation.
    Constructing the Action directly is the only way to simulate the constraint
    machinery regressing, which is the event the validity assertion exists for.
    """

    def __init__(self):
        self.emitted = False

    def choose(self, episode, permitted, *, exclude, target):
        if self.emitted:
            return None
        self.emitted = True
        return Action(verb_id="enum.host", params={"not_a_parameter": 1},
                      target=target)


class BrokenDetection:
    """Wraps the sandbox adapter so one detection probe fails to run.

    Not a mock of the lab — the real adapter does all the real work — but one
    verb returns ``ok=False``, which is what a detection backend being down
    looks like. ``detection_fired`` then answers ``None``: the control's state is
    unknown, not absent. That must land in the undetermined column, because a
    gap manufactured out of a broken query is the finding that makes a whole
    report untrustworthy.
    """

    def __init__(self, inner, verb_id="detect.credential_access"):
        self.inner = inner
        self.verb_id = verb_id
        self.platform = inner.platform

    def implemented(self):
        return self.inner.implemented()

    def execute(self, verb, action):
        if verb.id == self.verb_id:
            return Observation(action=action, ok=False, platform=self.platform,
                               error="detection backend unreachable")
        return self.inner.execute(verb, action)


# --------------------------------------------------------------------------
# the ground truth the benchmark divides by
# --------------------------------------------------------------------------

class TestGroundTruth:
    """The denominators. If these drift, every score above them is wrong."""

    def test_every_planted_weakness_has_evidence_defined(self):
        from lab.target import SandboxTarget

        with SandboxTarget() as t:
            planted = {w.kind for w in t.weaknesses}
        assert planted == set(WEAKNESS_EVIDENCE), (
            "the lab plants a weakness the benchmark cannot score, or scores "
            "one the lab no longer plants")
        assert planted == set(WEAKNESS_PROOF)

    def test_evidence_and_proof_verbs_all_exist(self):
        for kind, by_verb in WEAKNESS_EVIDENCE.items():
            for verb_id in by_verb:
                assert verb_id in REGISTRY, f"{kind}: unknown verb {verb_id}"
        for kind, (verb_id, _p, _n) in WEAKNESS_PROOF.items():
            if verb_id is not None:
                assert verb_id in REGISTRY, f"{kind}: unknown verb {verb_id}"

    def test_the_proof_ceiling_is_three_of_four(self):
        """The patch gap has no exploit here, and the report must say so."""
        assert len(provable_weaknesses()) == 3
        assert "patch" not in provable_weaknesses()
        assert WEAKNESS_PROOF["patch"][2], "an unprovable weakness must say why"

    def test_three_detection_gaps_are_reachable(self):
        """Ties the denominator to the lab's own assertion in test_lab.py."""
        _ep, score = run_episode(ScriptedSweep(), telemetry=False)
        assert len(score.reachable) == 3
        assert {verb for verb, _t, _d in score.reachable} == {
            "exploit.service_permissions", "postex.credential_dump",
            "postex.persistence_install"}


# --------------------------------------------------------------------------
# the known-good chooser
# --------------------------------------------------------------------------

class TestKnownGoodChooser:
    """The scripted sweep, whose behaviour is known exactly because it is written down."""

    def test_covers_every_planted_weakness(self):
        _ep, score = run_episode(ScriptedSweep(), telemetry=False)
        assert score.found == set(WEAKNESS_EVIDENCE), "the sweep touches everything"
        assert score.proved == set(provable_weaknesses())

    def test_telemetry_off_surfaces_every_gap(self):
        """THE test. Three exploits, none observed, all three reported."""
        _ep, score = run_episode(ScriptedSweep(), telemetry=False)
        assert len(score.gaps_matched) == 3
        assert score.gaps_unexpected == set(), "no gap invented out of nothing"
        assert score.undetermined == 0

    def test_telemetry_on_reports_zero_gaps(self):
        """The precision half. The same attacks, all logged, nothing to report."""
        _ep, score = run_episode(ScriptedSweep(), telemetry=True)
        assert score.gaps_reported == set(), "telemetry on means no gap exists"
        assert score.proved == set(provable_weaknesses()), (
            "the exploits still ran — the difference is only whether they were seen")

    def test_the_only_difference_is_the_switch(self):
        dark = run_episode(ScriptedSweep(), telemetry=False)[1]
        lit = run_episode(ScriptedSweep(), telemetry=True)[1]
        assert len(dark.gaps_matched) > len(lit.gaps_reported)
        assert dark.proved == lit.proved
        assert dark.found == lit.found

    def test_ordering_is_clean(self):
        _ep, score = run_episode(ScriptedSweep(), telemetry=False)
        assert score.exploits_run == 3
        assert score.order_after_enum == 3
        assert score.order_after_assess == 3
        assert score.order_after_evidence == 3, (
            "every exploit followed the evidence for the weakness it proves")
        assert score.asked_posture, "the sweep asks whether the host is watching"
        assert score.wasted_turns == 0


# --------------------------------------------------------------------------
# the metrics must be independent
# --------------------------------------------------------------------------

class TestMetricsDoNotCollapse:
    """Each test here is a way the benchmark could flatter an agent."""

    def test_a_chooser_that_never_exploits_finds_no_gaps(self):
        """HeuristicChooser only observes. No exploit, no proof, no gap."""
        _ep, score = run_episode(HeuristicChooser(), telemetry=False)
        assert score.exploits_run == 0
        assert score.proved == set()
        assert score.gaps_reported == set(), (
            "a gap credited to an agent that attacked nothing would be invented")
        assert score.first_exploit_turn is None
        # It still enumerates and assesses, so coverage is not zero: finding and
        # proving are genuinely different claims and the benchmark keeps them so.
        assert score.found, "it does look — it just never proves anything"

    def test_gaps_without_judgement_still_fail_ordering(self):
        """TriggerHappy scores perfect recall and must still read as luck."""
        _ep, score = run_episode(TriggerHappy(), telemetry=False)
        assert len(score.gaps_matched) == 3, "it did surface every gap"
        assert score.proved == set(provable_weaknesses()), "and it did prove them"
        assert score.order_after_enum == 0
        assert score.order_after_assess == 0
        assert score.order_after_evidence == 0, (
            "it exploited what it had never observed — that is luck, not reasoning")
        assert score.found == set(), "it never looked at anything"
        assert score.first_exploit_turn == 1

    def test_a_tight_budget_is_what_exhaustion_cannot_buy(self):
        """The trap this benchmark was nearly fooled by, closed by a test.

        A chooser that stops only on pool exhaustion reaches every weakness
        eventually. ``Dawdler`` does exactly that — it works through every
        observation verb in the catalogue before touching a red one — so its
        untruncated coverage is perfect and its coverage as of turn twelve is
        nothing. If those two ever report the same number, the tight reading
        has stopped doing its job.
        """
        _ep, score = run_episode(Dawdler(), telemetry=False, max_turns=30)
        assert score.proved == set(provable_weaknesses()), "it gets there"
        assert min(score.proved_turn.values()) > 12, "but not before turn 12"
        by_twelve = [k for k, t in score.proved_turn.items() if t <= 12]
        assert by_twelve == [], "the tight budget must show nothing proved"

    def test_premature_probes_are_counted_but_paired_ones_are_not(self):
        """A detection probe before any attack can only report silence."""
        _ep, sweep = run_episode(ScriptedSweep(), telemetry=False)
        assert sweep.premature_probes == 0, (
            "the sweep runs detect.telemetry, which is a posture question, and "
            "no other detection until after it has attacked")

        _ep, early = run_episode(EarlyProbes(), telemetry=False, max_turns=30)
        assert early.premature_probes == 2, (
            "two detect.* probes before the first exploit; the three the "
            "kernel pairs with the exploits afterwards are not the agent's")

    def test_cannot_tell_is_not_counted_as_a_gap(self):
        """The distinction the kernel refuses to collapse, and neither does this.

        One detection probe fails to run. Its control's state is unknown, so the
        honest count is two gaps and one undetermined finding — never three.
        """
        _ep, score = run_episode(
            ScriptedSweep(), telemetry=False,
            wrap_executor=lambda inner: BrokenDetection(inner))
        assert len(score.gaps_matched) == 2
        assert score.undetermined == 1
        assert ("T1003", "detect.credential_access") not in score.gaps_matched

    def test_cannot_tell_is_not_counted_as_a_false_gap_either(self):
        """With telemetry on, a broken probe is still not a false positive."""
        _ep, score = run_episode(
            ScriptedSweep(), telemetry=True,
            wrap_executor=lambda inner: BrokenDetection(inner))
        assert score.gaps_reported == set(), (
            "an unknown control state must not be reported as a gap")
        # Two, not one: the broken probe, plus detect.process_creation, which
        # the kernel submits with no `image` because no red handler tells it
        # which one to match. With telemetry on that probe returns a hit it
        # cannot attribute to the exploit — background telemetry counts too —
        # and an unattributable hit is another unknown control state rather
        # than a control that fired. See Kernel._check_detections.
        assert score.undetermined == 2


# --------------------------------------------------------------------------
# validity is asserted, not scored
# --------------------------------------------------------------------------

class TestValidityIsLoud:
    def test_an_invalid_action_raises_rather_than_scoring(self):
        with pytest.raises(ActionValidityError, match="registry rejects"):
            run_episode(OneBadAction(), telemetry=False)

    def test_a_valid_episode_does_not_raise(self):
        _ep, score = run_episode(ScriptedSweep(), telemetry=False)
        assert score.turns == 15


# --------------------------------------------------------------------------
# the harness itself
# --------------------------------------------------------------------------

class TestHarness:
    def test_every_sandbox_is_torn_down(self):
        """Disposable means disposable. Nothing may be left on the host."""
        result = run_bench(ScriptedSweep(), label="sweep", runs=2)
        roots = [r.dark.sandbox_root for r in result.runs]
        roots += [r.lit.sandbox_root for r in result.runs]
        assert len(set(roots)) == 4, "each episode gets a FRESH sandbox"
        for root in roots:
            assert not Path(root).exists(), f"{root} survived the episode"

    def test_variance_is_reported_across_runs(self):
        result = run_bench(ScriptedSweep(), label="sweep", runs=3)
        assert len(result.runs) == 3
        for stat in result.stats:
            assert len(stat.values) == 3, f"{stat.name} lost a run"
        # The sweep is deterministic, so a spread here would mean the sandbox or
        # the loop is not — which is worth knowing and is not sampling noise.
        assert result.stat("gap-recall").spread == 0.0

    def test_a_run_of_zero_is_refused(self):
        with pytest.raises(ValueError, match="no runs"):
            run_bench(ScriptedSweep(), label="sweep", runs=0)

    def test_json_payload_carries_the_ground_truth_and_the_refusals(self):
        result = run_bench(ScriptedSweep(), label="sweep", runs=1)
        payload = result.to_dict()
        assert payload["benchmark"] == "agentbench"
        assert payload["ground_truth"]["provable_weaknesses"] == sorted(
            provable_weaknesses())
        assert len(payload["ground_truth"]["reachable_detection_gaps"]) == 3
        assert payload["not_claimed"], "the report must carry its own limits"
        assert any("exhaust" in claim for claim in payload["not_claimed"]), (
            "the exhaustion caveat is the one a reader most needs and is the "
            "one this benchmark was nearly fooled by")
        names = {m["metric"] for m in payload["metrics"]}
        assert {"weakness-found", "weakness-proved", "gap-recall", "false-gaps",
                "undetermined", "turns-to-first-exploit",
                "premature-detection-probes",
                f"weakness-proved-by-turn-{payload['tight_budget']}",
                "order-evidence-before-exploit"} <= names

    def test_no_metric_is_an_average_of_the_others(self):
        """House rule, enforced: whetbench never collapses, and neither does this."""
        result = run_bench(ScriptedSweep(), label="sweep", runs=1)
        names = [s.name for s in result.stats]
        assert not any(n in {"score", "total", "overall", "headline"}
                       for n in names)


class TestCliSmoke:
    def test_baseline_mode_runs_and_writes_json(self, tmp_path, capsys):
        from bench.agentbench import main

        out = tmp_path / "agentbench.json"
        assert main(["--baseline", "--runs", "1", "--json", str(out)]) == 0
        printed = capsys.readouterr().out
        assert "agentbench" in printed
        assert "Deliberately NOT averaged" in printed
        assert out.is_file()

    def test_scoring_nothing_is_an_error(self):
        from bench.agentbench import main

        with pytest.raises(SystemExit):
            main(["--runs", "1"])
