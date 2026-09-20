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

The defending half is tested the same way, and its load-bearing test is
:meth:`TestClosureIsCheckedAgainstTheLab.test_a_fix_that_lies_is_caught`. The
kernel already refuses to call a gap closed on a harden verb's exit status — it
re-attacks and re-probes — so the only way to know whether this benchmark is
*independently* checking closure is to hand it a loop whose every claim is
false and watch it disagree. An adapter that reports the fix succeeded, changes
nothing, and then has the control announce a hit produces three ``closed``
findings against an empty telemetry log. If the benchmark echoes the kernel it
prints three closures; if it checks the lab it prints three false closures.
There is no third possibility and no way to pass that test by accident.
"""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

import pytest

import whetstone.verbs  # noqa: F401  (registers the catalogue)
from bench.agentbench import (
    DETECTION_TELEMETRY,
    FIX_REPAIRS,
    WEAKNESS_EVIDENCE,
    WEAKNESS_PROOF,
    WEAKNESS_REPAIR,
    ActionValidityError,
    DefenceGroundTruthError,
    _PLANTED_CRON,
    _STATE_ORDER,
    provable_weaknesses,
    repairable_weaknesses,
    report,
    run_bench,
    run_episode,
    score_episode,
)
from lab.run import ScriptedSweep
from whetstone.actions import REGISTRY, Action, Observation, Side
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


def _extra(verb_id):
    """The parameters these baselines know how to supply from nowhere."""
    return {"service": "acme-agent"} if verb_id == "exploit.service_permissions" else {}


@contextmanager
def _live_episode(chooser, *, telemetry=False, remediate=True, max_turns=24,
                  wrap_executor=None):
    """Run one episode and keep its sandbox alive, so a test can re-score it.

    :func:`run_episode` builds and destroys the sandbox inside one call, which
    is right for a benchmark — an exploit from a previous episode must never sit
    in the next one's telemetry log — and wrong for a test that needs to ask the
    lab a question afterwards, or score the same episode twice against different
    evidence. Same construction, same engagement, torn down the same way; the
    only difference is where the ``with`` block ends.
    """
    from bench.agentbench import TASK, reachable_gaps
    from lab.adapter import SandboxAdapter
    from lab.run import _engagement
    from lab.target import SandboxTarget
    from whetstone.gate import Gate, always_confirm
    from whetstone.kernel import Kernel

    with SandboxTarget(telemetry=telemetry) as target:
        executor = SandboxAdapter(target)
        if wrap_executor is not None:
            executor = wrap_executor(executor)
        gate = Gate(_engagement(str(target.root)), registry=REGISTRY,
                    confirmer=always_confirm)
        reachable = reachable_gaps(gate, executor)
        episode = Kernel(gate, executor, chooser, max_turns=max_turns,
                         remediate=remediate).run(TASK, target="127.0.0.1")
        yield episode, target, reachable


def _fillable(verb, extra=None):
    """Whether a rule-based chooser can supply every required parameter.

    A chooser that sweeps whatever the catalogue offers has to stop somewhere,
    and the honest place is here: a required parameter with no choices, no
    default and nothing supplied cannot be invented. The ``harden.*`` verbs are
    the reason this exists — ``path``, ``source`` and ``entry`` name things only
    an observation can name, so a baseline that sorts verbs and takes the first
    one has no business proposing them. It is the same rule the kernel's own
    deterministic remediation proposer follows, and it keeps these choosers
    measuring attacking and gap-finding, which is what this benchmark scores.
    """
    have = set(extra or ())
    return all(p.name in have or bool(p.choices)
               for p in verb.params if p.required)


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
        pool = [v for v in permitted
                if v.id not in done and _fillable(v, _extra(v.id))]
        if not pool:
            return None
        observe = [v for v in pool if v.side is not Side.RED]
        verb = (observe or pool)[0]
        return verb.bind(_bind(verb, _extra(verb.id)), target=target)


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


class FixThatLies:
    """Every fix reports success, changes nothing, and the controls then agree.

    The adapter a purple report should be most afraid of, and the one that makes
    the closure check testable. The attacking half runs for real, so three
    genuine gaps are produced against a genuinely silent host. Then the fix is
    intercepted: ``ok=True``, telemetry never actually switched on, nothing
    written anywhere. Afterwards every ``detect.*`` call claims a hit and echoes
    back whatever discriminator it was handed, so the kernel's probe is aimed,
    attributable and positive.

    Nothing in the loop can tell. The kernel's evidence for closure — the
    re-attack ran, the control fired, the hit matched the image — is all present
    and all false, which is precisely why the benchmark has to ask the sandbox
    instead of asking the kernel. The sandbox's log is empty, because the switch
    was never flipped and ``SandboxTarget.event`` writes nothing when it is off.

    The lie is **timed**, and that is what keeps this adapter frightening. The
    kernel takes a silent reading of the control between the fix and the
    re-attack, so a liar that claims a hit from the moment the fix lands is
    caught by the loop itself and never reaches the benchmark. This one stays
    silent until the technique has run again, which is exactly the timeline a
    control that genuinely started working would produce. Every signal the
    kernel has is consistent; only the host disagrees.
    """

    def __init__(self, inner):
        self.inner = inner
        self.platform = inner.platform
        self.hardened = False
        #: Whether a red verb has run since the fix. Until one has, the lie
        #: would be visible to the kernel's pre-re-attack reading.
        self.attacked_since_fix = False

    def implemented(self):
        return self.inner.implemented()

    def execute(self, verb, action):
        if verb.id.startswith("harden."):
            self.hardened = True
            self.attacked_since_fix = False
            return Observation(action=action, ok=True, platform=self.platform,
                               data={"enabled": True, "changed": True})
        if self.hardened and verb.id.startswith("detect."):
            if not self.attacked_since_fix:
                # The silent reading the kernel takes before the re-attack. A
                # control that had just been switched on would have nothing yet.
                return Observation(action=action, ok=True, platform=self.platform,
                                   data={"logged": False, "count": 0,
                                         "events": []})
            image = action.params.get("image")
            return Observation(action=action, ok=True, platform=self.platform,
                               data={"logged": True, "count": 1,
                                     "matched_image": image or "",
                                     "events": ["a hit that never happened"]})
        if self.hardened and REGISTRY.get(verb.id).side is Side.RED:
            self.attacked_since_fix = True
        return self.inner.execute(verb, action)


class SilentUntilHardened:
    """One control that is genuinely blind until a fix runs — on a host that logs.

    Not a lie, unlike :class:`FixThatLies`: the detection really does report a
    genuine negative, the fix really runs, and afterwards the query passes
    through to the real adapter and finds the real record. Every step is
    honest, and on a LIT sandbox the result is a combination the benchmark
    cannot rule on. The telemetry log was full before the episode began, so
    "there is a row of this kind" says nothing about whether the fix changed
    anything.

    That is what ``closure_unverifiable`` is for. A check that could not be
    applied is not a check that failed.

    "Blind" lasts until the technique runs again, not until the fix returns. A
    control that has just been switched on holds no records of what happened
    while it was off, so it answers the kernel's pre-re-attack reading with a
    genuine negative and only then starts passing through to the real log. That
    is both the honest model of enabling a source and the only one under which
    this scenario is reachable: a control reporting the original attack the
    moment the fix lands has not been shown to see the re-attack, and the kernel
    now says so.
    """

    def __init__(self, inner, verb_id="detect.credential_access"):
        self.inner = inner
        self.verb_id = verb_id
        self.platform = inner.platform
        self.hardened = False
        self.attacked_since_fix = False

    def implemented(self):
        return self.inner.implemented()

    def execute(self, verb, action):
        if verb.id.startswith("harden."):
            self.hardened = True
            self.attacked_since_fix = False
        elif self.hardened and REGISTRY.get(verb.id).side is Side.RED:
            self.attacked_since_fix = True
        if verb.id == self.verb_id and not (self.hardened
                                            and self.attacked_since_fix):
            # A real negative, not a failure to query: `logged: False` with
            # nothing marking the source unreadable is what the kernel is
            # entitled to read as a gap, and does.
            #
            # The remediation hint is here because a silent control in this lab
            # publishes one — it is how `harden.enable_telemetry` gets a source
            # to aim at, and without it the gap would be reported unfixable and
            # this test would exercise nothing. `_SOURCE` is imported rather
            # than spelled out so the name cannot drift away from the adapter's.
            from lab.adapter import _SOURCE

            return Observation(
                action=action, ok=True, platform=self.platform,
                data={"logged": False, "count": 0, "events": [],
                      "remediation": {"harden.enable_telemetry":
                                      {"source": _SOURCE}}})
        return self.inner.execute(verb, action)


class NoRemediationHints:
    """Strips the remediation hints out of every payload, changing nothing else.

    The gaps still form, the catalogue still contains a fix that declares each
    of them, and not one of those fixes can be aimed: ``source``, ``path`` and
    ``entry`` name things only an observation can name, and the observations
    have stopped naming them. Every gap therefore ends ``unavailable`` with a
    perfectly well-targeted verb in it.

    It exists to hold the other end of the targeting metric down. "Nothing could
    be aimed" and "the chooser pointed a fix at the wrong gap" both land on
    ``unavailable``, and a benchmark that counted them together would report a
    catalogue-coverage problem as an agent's mistake.
    """

    def __init__(self, inner):
        self.inner = inner
        self.platform = inner.platform

    def implemented(self):
        return self.inner.implemented()

    def execute(self, verb, action):
        observation = self.inner.execute(verb, action)
        data = observation.data
        if isinstance(data, dict) and "remediation" in data:
            stripped = {k: v for k, v in data.items() if k != "remediation"}
            return Observation(action=observation.action, ok=observation.ok,
                               data=stripped, error=observation.error,
                               platform=observation.platform,
                               unsupported=observation.unsupported)
        return observation


class RemoveTheWeakness:
    """Sweeps as usual, then answers every gap with the fix that removes the weakness.

    A defending chooser, which the baselines are not: it implements
    ``remediate``, so the kernel asks it before falling back. It always prefers
    the fix that takes the weakness away over the one that makes the technique
    visible — the opposite of the deterministic proposer's ordering, and a
    defensible thing for an operator to want.

    It is here because that choice produces an outcome the benchmark has to get
    right and could easily get wrong. Removing the write bit means the re-attack
    *fails*, so the control is never given anything to see, so the gap is not
    closed — and the host is genuinely better off. A benchmark that scored that
    as a failed remediation would be punishing the better answer, and one that
    scored it as a closure would be reporting a control that still cannot see
    the technique as fixed.

    Parameters come from what the episode observed, the way a model's would:
    the path out of ``vuln.weak_permissions``, the autostart line out of
    ``enum.persistence``. Nothing is invented, which is the same rule the
    kernel's own proposer follows.
    """

    def __init__(self):
        self.sweep = ScriptedSweep()

    def choose(self, episode, permitted, *, exclude, target):
        return self.sweep.choose(episode, permitted, exclude=exclude,
                                 target=target)

    @staticmethod
    def _payloads(episode, verb_id):
        for turn in episode.turns:
            if turn.action.verb_id == verb_id and turn.succeeded:
                data = turn.observation.data
                if isinstance(data, dict):
                    yield data

    def remediate(self, episode, finding, *, candidates, target):
        for verb in candidates:
            if FIX_REPAIRS.get(verb.id) != "weakness":
                continue
            params = self._aim(episode, verb.id)
            if params is None:
                continue
            return verb.bind(params, target=target)
        return None                      # fall back to the deterministic proposer

    def _aim(self, episode, verb_id):
        if verb_id == "harden.fix_permissions":
            for data in self._payloads(episode, "vuln.weak_permissions"):
                for hit in data.get("findings") or ():
                    if isinstance(hit, dict) and hit.get("path"):
                        return {"path": hit["path"]}
        if verb_id == "harden.remove_persistence":
            for data in self._payloads(episode, "enum.persistence"):
                for entry in data.get("autostart") or ():
                    if isinstance(entry, dict) and entry.get("entry"):
                        return {"entry": entry["entry"]}
        return None


class FixTheWrongGap:
    """Answers every gap with a hardening verb that does not claim it.

    The targeting error, in its only unambiguous form. ``remediates`` is a
    declaration on the verb, and the kernel matches a fix to a gap on that and
    nothing else — so proposing ``harden.remove_persistence`` for a credential
    dump is not a debatable preference, it is an association the catalogue
    explicitly does not make. The kernel records the proposal and drops it
    rather than substituting the right verb, and the benchmark has to count that
    rather than let it read as "no fix was available".
    """

    WRONG = "harden.remove_persistence"

    def __init__(self):
        self.sweep = ScriptedSweep()

    def choose(self, episode, permitted, *, exclude, target):
        return self.sweep.choose(episode, permitted, exclude=exclude,
                                 target=target)

    def remediate(self, episode, finding, *, candidates, target):
        if any(v.id == self.WRONG for v in candidates):
            return None                  # it would be legitimate here
        verb = REGISTRY.get(self.WRONG)
        return verb.bind({"entry": "@reboot root /opt/acme/acme-agent"},
                         target=target)


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
        # One: the broken probe, and nothing else.
        #
        # It used to be two. `detect.process_creation` was submitted with no
        # `image`, because no red handler said which one to match, so with
        # telemetry on it returned a hit it could not attribute to the exploit —
        # background telemetry counts too — and an unattributable hit is another
        # unknown control state rather than a control that fired.
        #
        # `exploit.service_permissions` now publishes the image it touched, so
        # the kernel aims the probe and the hit is attributable. The change is
        # in the lab, not in the rule: `Kernel._check_detections` still refuses
        # to read an unaimed hit as a verdict, and the test above this one still
        # proves it. What moved is that the lab stopped asking a question it
        # could have answered precisely — which it had to, because a control
        # whose hit can never be attributed can never be shown to have started
        # firing, and a gap that cannot be shown to close cannot be remediated.
        assert score.undetermined == 1


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


class TestRemediationDoesNotInflateTheAgentsScore:
    """The kernel's remediation turns are not the agent's behaviour.

    One of them is the agent's own exploit, run a second time as the evidence
    that a fix worked. Counting it would report three re-attacks as three more
    exploits the agent chose to run, and would pull turns-to-first-exploit down
    for an agent that did nothing differently — a wrong number produced by a
    feature nobody turned on in this file.
    """

    def _both(self):
        return (run_episode(ScriptedSweep(), telemetry=False)[1],
                run_episode(ScriptedSweep(), telemetry=False,
                            remediate=True)[1])

    def test_the_agent_metrics_are_identical_with_and_without_the_phase(self):
        plain, remediated = self._both()
        assert remediated.exploits_run == plain.exploits_run == 3
        assert remediated.first_exploit_turn == plain.first_exploit_turn
        assert remediated.turns == plain.turns
        assert remediated.verbs == plain.verbs
        assert remediated.order_after_evidence == plain.order_after_evidence == 3
        assert remediated.wasted_turns == plain.wasted_turns == 0

    def test_the_gaps_are_still_counted_and_still_matched(self):
        """The finding side is untouched: three gaps, reported and reachable,
        whether or not anything was done about them afterwards."""
        plain, remediated = self._both()
        assert len(remediated.gaps_matched) == len(plain.gaps_matched) == 3
        assert remediated.gaps_unexpected == plain.gaps_unexpected == set()
        assert remediated.undetermined == plain.undetermined == 0

    def test_the_remediation_actually_ran(self):
        """Otherwise the two tests above pass by the phase doing nothing."""
        episode, _score = run_episode(ScriptedSweep(), telemetry=False,
                                      remediate=True)
        applied = [t for t in episode.turns if t.phase == "remediate"]
        assert len(applied) == 3
        assert all(f.remediation is not None and f.remediation.proven_closed
                   for f in episode.findings if f.kind == "detection_gap")


# --------------------------------------------------------------------------
# the ground truth the DEFENDING metrics divide by
# --------------------------------------------------------------------------

class TestDefenceGroundTruth:
    """The tables. A closure checked against a stale table is not checked."""

    def test_every_hardening_verb_is_classified(self):
        """A new fix nobody classified must break a test, not a total."""
        from whetstone.actions import Intent, Side

        fixes = {v.id for v in REGISTRY
                 if v.side is Side.BLUE and v.intent is not Intent.OBSERVE}
        assert fixes == set(FIX_REPAIRS), (
            "the catalogue grew or lost a hardening verb and FIX_REPAIRS did "
            "not follow; an unclassified fix would be counted as neither repair")
        assert set(FIX_REPAIRS.values()) == {"visibility", "weakness"}

    def test_the_repair_table_covers_every_planted_weakness(self):
        assert set(WEAKNESS_REPAIR) == set(WEAKNESS_EVIDENCE)
        assert set(repairable_weaknesses()) == {"writable_service", "persistence"}
        for kind, (predicate, note) in WEAKNESS_REPAIR.items():
            if predicate is None:
                assert note, f"{kind}: an unrepairable weakness must say why"

    def test_the_planted_autostart_line_is_really_planted(self):
        """The repair predicate is unsatisfiable if this ever stops matching."""
        from lab.target import SandboxTarget

        with SandboxTarget() as target:
            lines = [ln.strip() for ln in
                     target.resolve("etc/crontab").read_text().splitlines()]
        assert _PLANTED_CRON in lines

    def test_the_telemetry_kinds_are_the_ones_the_lab_actually_writes(self):
        """Ties DETECTION_TELEMETRY to the lab instead of to a memory of it.

        Run the three red verbs against a lit sandbox and require a row of
        every kind the table names. A renamed kind would otherwise make the
        closure check silently unsatisfiable — every real closure would start
        reading as a false one, which is the most damaging direction a
        measurement bug in this half could take.
        """
        from lab.adapter import SandboxAdapter
        from lab.target import SandboxTarget

        plan = (("exploit.service_permissions", {"service": "acme-agent"}),
                ("postex.credential_dump", {}),
                ("postex.persistence_install", {}))
        with SandboxTarget(telemetry=True) as target:
            adapter = SandboxAdapter(target)
            for verb_id, extra in plan:
                verb = REGISTRY.get(verb_id)
                adapter.execute(verb, verb.bind(_bind(verb, extra),
                                                target="127.0.0.1"))
            for detection, kind in DETECTION_TELEMETRY.items():
                assert target.events(kind=kind), (
                    f"{detection} is recorded as reading {kind!r} and the lab "
                    "never writes a row of that kind")

    def test_every_reachable_gap_can_be_checked(self):
        _ep, score = run_episode(ScriptedSweep(), telemetry=False)
        assert {d for _v, _t, d in score.reachable} <= set(DETECTION_TELEMETRY)

    def test_the_state_order_matches_the_kernels_states(self):
        """The report prints every state the kernel can produce, or fails."""
        from whetstone.kernel import REMEDIATION_STATES

        assert set(_STATE_ORDER) == set(REMEDIATION_STATES)

    def test_an_uncheckable_closure_raises_rather_than_guessing(self, monkeypatch):
        """A table that drifted must stop the run, not pick an answer."""
        monkeypatch.delitem(DETECTION_TELEMETRY, "detect.credential_access")
        with pytest.raises(DefenceGroundTruthError, match="cannot be checked"):
            run_episode(ScriptedSweep(), telemetry=False, remediate=True)

    def test_an_unclassified_fix_raises_rather_than_being_uncounted(self, monkeypatch):
        monkeypatch.delitem(FIX_REPAIRS, "harden.enable_telemetry")
        with pytest.raises(DefenceGroundTruthError, match="FIX_REPAIRS"):
            run_episode(ScriptedSweep(), telemetry=False, remediate=True)


# --------------------------------------------------------------------------
# closure is the lab's verdict, not the loop's
# --------------------------------------------------------------------------

class TestClosureIsCheckedAgainstTheLab:
    """Whether a gap is shut is a question about the host, so ask the host."""

    def test_a_real_closure_verifies(self):
        """The sweep really does close all three, and the lab agrees."""
        _ep, score = run_episode(ScriptedSweep(), telemetry=False,
                                 remediate=True)
        assert len(score.closure_claimed) == 3
        assert score.closure_verified == score.closure_claimed
        assert score.closure_false == set()
        assert score.closure_unverifiable == 0
        assert set(score.fix_states.values()) == {"closed"}

    def test_a_fix_that_lies_is_caught(self):
        """THE test for this half. Every kernel-side signal says closed.

        The fix returns ok, the re-attack really runs, the control announces a
        hit and the hit carries the image it was aimed with. The kernel has
        nothing left to check and writes ``closed`` three times — correctly,
        given what it was told. The sandbox's log is empty, because the switch
        was never flipped, and that is the only place the truth lives.

        If this ever reports closures, the benchmark has stopped checking and
        has started repeating.
        """
        _ep, score = run_episode(
            ScriptedSweep(), telemetry=False, remediate=True,
            wrap_executor=FixThatLies)
        assert len(score.closure_claimed) == 3, (
            "the loop should have been fooled; if it was not, this test is no "
            "longer testing what it says it is")
        assert score.closure_verified == set()
        assert len(score.closure_false) == 3
        assert score.first_fix_verified is False

    def test_a_closure_needs_the_re_attack_to_have_happened(self):
        """Both halves of the check are required, and neither alone will do.

        The lying adapter leaves the log empty. This leaves the log full and
        takes the re-attack away: the same episode is scored twice, the second
        time with the ``verify`` turns for one red verb removed. The finding
        still says ``closed`` and the log still carries a row of the right
        kind, so the log check alone would confirm it — and it must not,
        because the row could have been written by anything. Only the evidence
        that the technique was performed again makes it a closure.

        The kernel cannot produce that combination today, which is the reason
        to check it here rather than to assume it: the day it can, this is
        where it shows up.
        """
        gap = ("T1003", "detect.credential_access")
        with _live_episode(ScriptedSweep()) as (episode, target, reachable):
            kwargs = {"reachable": reachable, "telemetry": False,
                      "remediation_phase": True}
            full = score_episode(episode, target, **kwargs)
            assert gap in full.closure_verified

            episode.turns = [
                turn for turn in episode.turns
                if not (turn.phase == "verify"
                        and turn.action.verb_id == "postex.credential_dump")]
            stripped = score_episode(episode, target, **kwargs)
            assert target.events(kind="credential_access"), (
                "the log must still carry the row, or this proves nothing")

        assert gap in stripped.closure_false
        assert gap not in stripped.closure_verified
        assert len(stripped.closure_verified) == 2, "the other two are untouched"

    def test_a_closure_that_cannot_be_checked_is_in_neither_column(self):
        """The invariant the whole project rests on, applied to this half.

        A lit sandbox has been logging since it was built, so a row of the
        right kind proves nothing about a fix — the benchmark's evidence cannot
        separate the re-attack's record from the ones before it.
        :class:`SilentUntilHardened` manufactures exactly that case: a real gap
        on a host that logs, a real fix, a real re-attack, and a control that
        really does fire afterwards.

        The claim is neither confirmed nor refuted, and it must land in neither
        column. Counting it as verified would award a closure the benchmark did
        not check; counting it as false would accuse the loop of lying on the
        strength of a check that never ran. ``detection_fired`` returns None for
        the same reason and it is the same rule.
        """
        _ep, score = run_episode(ScriptedSweep(), telemetry=True,
                                 remediate=True,
                                 wrap_executor=SilentUntilHardened)
        assert len(score.closure_claimed) == 1, (
            "the setup should have produced one gap and closed it; if it did "
            "not, this test is no longer testing what it says it is")
        assert score.closure_unverifiable == 1
        assert score.closure_verified == set()
        assert score.closure_false == set()

    def test_a_lit_episode_normally_has_nothing_to_close(self):
        """The ordinary case behind the one above: no gap, so no fix."""
        _ep, score = run_episode(ScriptedSweep(), telemetry=True,
                                 remediate=True)
        assert score.gaps_reported == set(), "nothing to close with telemetry on"
        assert score.closure_false == set()
        assert score.fixes_applied == 0, (
            "no gap was proven, so nothing should have been changed")


# --------------------------------------------------------------------------
# the defending metrics must not collapse either
# --------------------------------------------------------------------------

class TestDefendingMetricsDoNotCollapse:
    """Each of these is a way the defending half could flatter the loop."""

    def test_removing_the_weakness_is_not_closing_the_gap(self):
        """The better fix, and the one that must not read as a closure.

        ``harden.fix_permissions`` strips the write bit, so the re-attack
        cannot run, so ``detect.process_creation`` is never given anything to
        see. The gap is not shut — the control is exactly as blind as it was —
        and the host is nevertheless better off. Three separate facts, and the
        benchmark has to keep all three.
        """
        _ep, score = run_episode(RemoveTheWeakness(), telemetry=False,
                                 remediate=True)
        service_gap = ("T1574.010", "detect.process_creation")
        assert score.fix_states[service_gap] == "undetermined"
        assert service_gap not in score.closure_claimed
        assert service_gap not in score.closure_false, (
            "a gap nobody claimed to have closed cannot be a false closure")
        assert "writable_service" in score.weaknesses_removed
        assert score.fixes_by_repair.get("weakness", 0) >= 1

    def test_a_weakness_removal_is_never_added_to_the_closures(self):
        _ep, score = run_episode(RemoveTheWeakness(), telemetry=False,
                                 remediate=True)
        assert score.weaknesses_removed == {"writable_service", "persistence"}
        assert len(score.closure_verified) < 3, (
            "two of the three gaps were answered by removing the weakness "
            "rather than by making the control see it")
        assert not (score.weaknesses_removed & {p[0] for p
                                                in score.closure_verified})

    def test_the_first_fix_reading_is_not_bought_by_a_later_one(self):
        """The defending twin of the by-turn-12 trap, closed by a test.

        ``RemoveTheWeakness`` answers the first gap by taking the write bit
        away, which does not make anything visible: that gap ends
        ``undetermined``. The second gap falls through to the deterministic
        proposer, which switches telemetry on — and from that moment every
        later gap closes whatever is done about it, because the log is on. So
        the untruncated closure count is nonzero and the first-fix reading is
        zero, and if those two ever agree the confounded reading has stopped
        being isolated.
        """
        _ep, score = run_episode(RemoveTheWeakness(), telemetry=False,
                                 remediate=True)
        assert score.first_fix_gap == ("T1574.010", "detect.process_creation")
        assert score.first_fix_verified is False
        assert len(score.closure_verified) >= 1, (
            "a later fix did close something — which is the point: the "
            "untruncated count alone would have read as a partial success")

    def test_a_fix_aimed_at_the_wrong_gap_is_counted_as_misaimed(self):
        """Not as 'no fix was available', which is a statement about the catalogue."""
        _ep, score = run_episode(FixTheWrongGap(), telemetry=False,
                                 remediate=True)
        credential_gap = ("T1003", "detect.credential_access")
        assert score.fix_states[credential_gap] == "unavailable"
        assert score.misaimed_fixes == 2, (
            "the service and credential gaps were both answered with a verb "
            "that does not claim them; the persistence gap was not, because "
            "there the wrong verb happens to be a declared candidate")
        assert credential_gap not in score.closure_claimed

    def test_a_fix_that_could_not_be_aimed_is_not_a_targeting_error(self):
        """The other half of the same metric, and the reason it is a metric.

        Both of these end ``unavailable``: a fix pointed at a gap that does not
        declare it, and a fix that declares the gap but has nothing to aim at.
        The first is the agent's mistake, the second is the catalogue's — and a
        count that included the second would blame an agent for evidence that
        never named a path. Every gap here is unavailable and none of them is
        misaimed.
        """
        _ep, score = run_episode(ScriptedSweep(), telemetry=False,
                                 remediate=True,
                                 wrap_executor=NoRemediationHints)
        assert len(score.fix_states) == 3
        assert set(score.fix_states.values()) == {"unavailable"}, (
            "no fix could be aimed, so none should have been applied")
        assert score.misaimed_fixes == 0, (
            "nothing was aimed at the wrong gap — nothing was aimed at all")
        assert score.fixes_applied == 0
        assert score.closure_claimed == set()

    def test_nothing_to_defend_reads_never_rather_than_zero(self):
        """An agent that attacks nothing has not earned a clean defending record.

        ``HeuristicChooser`` never exploits, so no gap exists, so no fix is
        offered and none fails. Reported as zero, that would be a perfect false
        closure count and an apparently honest tool. Reported as "never", it is
        what it is: there was nothing to defend.
        """
        result = run_bench(HeuristicChooser(), label="heuristic", runs=1)
        closed = result.stat("gaps-closed")
        assert closed.values == [None]
        assert closed.mean is None
        assert closed.headline() == "never"
        assert result.stat("false-closure").values == [None]

    def test_the_phase_being_off_reads_never_too(self):
        result = run_bench(ScriptedSweep(), label="sweep", runs=1,
                           remediate=False)
        assert result.stat("gaps-closed").values == [None]
        assert result.stat("fixes-without-a-gap").values == [None]
        assert result.stat("gap-recall").mean == 3.0, (
            "turning the defending half off moves no attacking number")

    def test_a_remediated_dark_episode_is_still_recorded_as_telemetry_off(self):
        """The posture the episode RAN under, not the one the fix left behind.

        ``harden.enable_telemetry`` really flips the target's switch, so reading
        it back after the episode reports the opposite of the exercise that was
        run — and, worse, tells the closure check that the log was never empty
        and so cannot be used as evidence. Both failures are silent.
        """
        _ep, score = run_episode(ScriptedSweep(), telemetry=False,
                                 remediate=True)
        assert score.telemetry is False
        assert score.to_dict()["telemetry"] is False
        assert score.closure_unverifiable == 0, (
            "the closure check must still have been applicable")

    def test_a_no_op_fix_is_counted_only_when_it_says_so(self):
        """Three gaps, one switch: two of the three fixes changed nothing.

        Both halves of the rule are exercised, because the first half alone
        cannot fail. ``harden.enable_telemetry`` reports ``changed`` every time,
        so counting "not explicitly true" and counting "explicitly false" give
        the same answer for the sweep and the distinction is untested.
        ``harden.remove_persistence`` returns no ``changed`` field at all, and
        under the looser rule a fix that really did delete a line would be
        counted as having done nothing — inferring a no-op from silence, which
        is the collapse this file refuses everywhere else.
        """
        _ep, sweep = run_episode(ScriptedSweep(), telemetry=False,
                                 remediate=True)
        assert sweep.fixes_applied == 3
        assert sweep.fixes_unchanged == 2, (
            "the same source enabled once per gap; only the first did anything")

        _ep, remover = run_episode(RemoveTheWeakness(), telemetry=False,
                                   remediate=True)
        assert remover.fixes_applied == 3
        assert remover.fixes_unchanged == 0, (
            "one of these fixes does not report whether it changed anything, "
            "and not saying is not the same as saying no")


class TestDefendingReport:
    """What the reader is told before they are shown a number."""

    def test_the_report_says_whose_fixes_it_scored(self, capsys):
        result = run_bench(ScriptedSweep(), label="sweep", runs=1)
        assert result.chooser_defends is False
        report(result)
        printed = capsys.readouterr().out
        assert "NO remediate method" in printed
        assert "not the agent" in printed

    def test_a_defending_chooser_is_reported_as_one(self, capsys):
        result = run_bench(RemoveTheWeakness(), label="remover", runs=1)
        assert result.chooser_defends is True
        report(result)
        assert "CHOOSER picked the fixes" in capsys.readouterr().out

    def test_every_remediation_state_is_printed_even_at_zero(self, capsys):
        """A state with no row is a state whose drift to zero nobody sees."""
        result = run_bench(ScriptedSweep(), label="sweep", runs=1)
        report(result)
        printed = capsys.readouterr().out
        for state in _STATE_ORDER:
            assert f"{state} " in printed, f"{state} vanished from the report"
        assert "not attempted" in printed

    def test_the_json_carries_the_defending_ground_truth_and_its_limits(self):
        result = run_bench(ScriptedSweep(), label="sweep", runs=1)
        payload = result.to_dict()
        assert payload["ground_truth"]["repairable_weaknesses"] == sorted(
            repairable_weaknesses())
        assert payload["defending"]["phase"] is True
        assert payload["defending"]["chooser_defends"] is False
        assert payload["defending"]["states"]["closed"] == 3
        names = {m["metric"] for m in payload["metrics"]}
        assert {"gaps-closed", "false-closure",
                "gaps-closed-before-any-other-fix", "remediation-undetermined",
                "misaimed-fixes", "weaknesses-removed",
                "fixes-without-a-gap"} <= names
        assert any("deterministic proposer" in claim
                   for claim in payload["not_claimed"]), (
            "a report whose fixes were chosen by the fallback must say so")
        assert any("refute" in claim for claim in payload["not_claimed"])
