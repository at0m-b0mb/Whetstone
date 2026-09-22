"""Run the lab loop against the sandbox — the thing you can test now.

    python -m lab.run                 # telemetry off: watch the gap appear,
                                      # then watch the agent close it
    python -m lab.run --cycle         # the same run, narrated in order:
                                      # attack, silence, gap, fix, re-attack,
                                      # the control speaking, closure
    python -m lab.run --telemetry     # telemetry on: nothing to find
    python -m lab.run --both          # both, side by side
    python -m lab.run --no-remediate  # stop where the loop used to stop

Three modes, which are three different **engagements** rather than three
settings on one:

    python -m lab.run --red-only      # attack and observe. The gate refuses
                                      # every hardening measure, visibly.
    python -m lab.run --blue-only     # defend only. No attack is possible.
    python -m lab.run --purple        # the full cycle. The default.

The mode is spelled with the profile's own word — ``red-only``, not ``red`` —
because that word is the same one in the engagement document and in the gate's
refusal, and a runner that invents a shorter spelling of it is the first step
towards three vocabularies for one thing. ``--red`` and ``--blue`` work anyway,
as argparse abbreviations of the real flags, which costs nothing and adds no
second name to keep in step. See :mod:`lab.profiles` for what each mode
authorises and :class:`whetstone.gate.Profile` for why a per-side ceiling is a
different axis from ``max_intent``.

This is the end-to-end demonstration. It builds a real sandbox with planted
weaknesses, points the agent at it under an engagement that authorises the red
verbs, and lets the kernel run: enumerate, find the weakness, prove it by
exploiting it, then check whether anything saw. With telemetry off the exploit
succeeds unobserved and a detection gap is produced; with telemetry on the same
exploit is caught and no gap appears. Same attack, different blue posture — which
is the whole thesis, made runnable.

Then the other half, which for a long time existed only on paper. For each gap
the agent is offered a hardening measure, the kernel applies it, **runs the same
attack again**, and asks the same control the same question a second time. A fix
that returns success is a claim; the re-attack is the evidence. The gaps open
with telemetry off and close because the agent changed the host's posture —
which is the difference between a tool that reports and a tool that defends.

The other two modes are the same machinery under a narrower document. Red-only
runs the identical attack plan and is refused the moment it reaches for a
``harden.*`` verb — the refusal is printed rather than swallowed, because
watching the gate stop an attacker from editing the defence is the whole
demonstration. Blue-only cannot attack at all: it reads the posture, hardens
what is weak, and reads the control a second time, which is the defending half's
version of the re-attack. Neither is a subset of purple; they are three
documents, and the gate is what makes them different rather than which verbs
this file happens to propose.

``--cycle`` exists because the loop got harder to read at exactly the moment it
got interesting. A run is now twenty-four gated actions, nine of which the
kernel injected on its own initiative, and the flat turn list the summary prints
shows ``exploit.service_permissions`` twice with nothing saying that the second
one is evidence rather than a second attack. The narrated mode groups the turns
back into the story they came from, so the claim this project makes can be read
top to bottom by somebody who has not read the kernel.

Nothing here touches the host. Every file the exploits write is under the
sandbox root and reverted on teardown; the agent is scope-locked to the sandbox
by the engagement.
"""

from __future__ import annotations

import argparse
import textwrap
from pathlib import Path
from typing import Any, Callable

import whetstone.verbs  # noqa: F401  (registers the catalogue)
from whetstone.actions import REGISTRY, Intent, Side
from whetstone.gate import Gate, Profile, always_confirm
from whetstone.gate.engagement import Engagement
from whetstone.kernel import (Episode, HeuristicChooser, Kernel, Turn,
                              detection_fired)

from .adapter import SandboxAdapter
from .capture import (attack_beats, findings_for, fix_blocks,
                      pair_fix_blocks)
from .profiles import PROFILE_NAMES, engagement_for, purple
from .target import SandboxTarget

# A chooser that runs a full purple sweep: look, assess, exploit, and the
# kernel pairs each exploit with its detection automatically.
# (verb, extra params). Required parameters a real model would fill from an
# observation are supplied explicitly here so the demo is deterministic — the
# scripted sweep is a stand-in for a chooser, not a model.
_PLAN = (
    ("enum.host", {}), ("enum.privileges", {}), ("enum.services", {}),
    ("enum.persistence", {}), ("enum.software", {}),
    ("vuln.weak_permissions", {}), ("vuln.credential_exposure", {}),
    ("vuln.patch_gap", {}), ("detect.telemetry", {}),
    ("exploit.service_permissions", {"service": "acme-agent"}),
    ("postex.credential_dump", {"redact": True}),
    ("postex.persistence_install", {"mechanism": "cron"}),
)


#: The sandbox's one telemetry source, by the name ``harden.enable_telemetry``
#: accepts. Red-only names it in order to be refused and blue-only names it in
#: order to switch it on, so it is written once here rather than typed into two
#: plans that would then be free to drift apart.
_SOURCE = "sandbox-eventlog"

#: The one step in the red plan that is *meant* to be refused, and the reason
#: red-only is worth running rather than describing.
#:
#: Every other entry in ``_RED_PLAN`` is an entry in ``_PLAN``: the attack this
#: lab has always run, unchanged. This one reaches past the catalogue on purpose.
#: ``Gate.catalogue()`` already drops ``harden.*`` under red-only, so a chooser
#: that picks only from what it is offered can never demonstrate the rule — it
#: would simply never think of the verb, and a reader would be left with a run
#: that looks identical to purple-minus-remediation and a claim that the gate did
#: something. Binding it straight off the registry is what a model chooser
#: effectively does the first time its ranking comes out that way, and it is the
#: case the whole profile axis exists for: the catalogue is the convenience, the
#: policy rule is the control, and reaching past the first meets the second.
#:
#: The refusal is ``profile.intent``, not ``intent.ceiling``: this engagement's
#: ceiling really is EXECUTE, which is *above* the MODIFY this verb needs, and
#: that is precisely why the mode had to become its own axis.
_RED_OVERREACH = ("harden.enable_telemetry", {"source": _SOURCE})

#: Red-only: the purple attack plan, plus the reach for the defence at the end.
#: Last rather than first so it lands after the gap has been found, which is the
#: moment an attacker — or a purple loop, or a model that has learned the purple
#: loop — would reach for the fix. What the operator sees is the gate declining
#: to let the side that just broke in touch the control that failed to see it.
_RED_PLAN = _PLAN + (_RED_OVERREACH,)


def _weak_path(episode: Episode) -> dict[str, Any] | None:
    """Aim ``harden.fix_permissions`` at whatever ``vuln.weak_permissions`` found.

    The blue plan cannot hard-code the path: the sandbox root is a fresh temp
    directory every run, so the only way to know which file is weak is to have
    looked. That is the blue loop working the way round it should — the fix is
    aimed by the assessment, and if the assessment found nothing there is nothing
    to aim and the step is skipped rather than pointed at a guess.
    """
    for turn in episode.turns:
        if turn.action.verb_id != "vuln.weak_permissions" or not turn.succeeded:
            continue
        data = turn.observation.data
        findings = data.get("findings") if isinstance(data, dict) else None
        for finding in findings or ():
            path = finding.get("path") if isinstance(finding, dict) else None
            if isinstance(path, str) and path:
                return {"path": path}
    return None


#: Blue-only's one reach past the catalogue, for the same reason red-only has
#: one: a mode that holds because nothing proposed the forbidden verb is a
#: convention. Refused by ``profile.side`` rather than ``profile.intent`` — this
#: engagement does not run the red playbook *at all*, which is a different
#: sentence from "not that hard" and comes back as a different rule id.
_BLUE_OVERREACH = ("exploit.service_permissions", {"service": "acme-agent"})

#: Blue-only: look, assess, harden what the assessment found, then look again.
#:
#: The last two steps are the point of the plan and the reason this is not just
#: ``_PLAN`` with the red verbs filtered out. A ``harden.*`` verb returning
#: ``ok=True`` has said that a command exited zero, which is the claim this
#: project refuses to accept as evidence anywhere else; the defending half's
#: version of the re-attack is to ask the same read-only question a second time
#: and compare the two answers. ``detect.telemetry`` and
#: ``vuln.weak_permissions`` therefore appear twice each, which is why the blue
#: chooser walks a cursor instead of a done-set.
#:
#: The overreach sits exactly where the purple loop would exploit: the
#: assessment has just reported a writable root binary, and proving it means
#: performing the technique. That is the step this mode does not have, so the
#: refusal lands there and the run then hardens the file on the strength of the
#: assessment alone — which is what defending without an attack to point at
#: actually looks like.
_BLUE_PLAN = (
    ("enum.host", {}), ("enum.privileges", {}), ("enum.services", {}),
    ("enum.persistence", {}), ("enum.software", {}),
    ("vuln.weak_permissions", {}), ("vuln.credential_exposure", {}),
    ("vuln.patch_gap", {}), ("detect.telemetry", {}),
    _BLUE_OVERREACH,
    ("harden.enable_telemetry", {"source": _SOURCE}),
    ("harden.fix_permissions", _weak_path),
    ("detect.telemetry", {}),
    ("vuln.weak_permissions", {}),
)

#: What the agent is told to do, per mode. This is the model's instruction, not
#: a caption: it is rendered into the prompt verbatim and a trained chooser
#: ranks against it.
#:
#: Purple's line is the one this lab has always used and is left byte-for-byte
#: alone, so that adding modes changed nothing about the demonstration that
#: already existed.
#:
#: Blue's took the most care and is the one worth reading twice. "Assess this
#: host and prove what you find" is an attacker's brief — on the red side a
#: finding is proven by performing the technique, which is exactly what this
#: mode must not do, and handing a model that sentence under a blue engagement
#: teaches it that the gate is an obstacle between it and the obvious next move.
#: So the blue brief names the defending side's own standard of proof: read the
#: control again after the change, and let the difference be the evidence.
TASKS: dict[Profile, str] = {
    Profile.PURPLE:
        "Assess this host, prove what you find, and tell me what nobody saw.",
    Profile.RED:
        "Assess this host, prove what you find by performing it, and tell me "
        "what nobody saw. Report the gaps; changing this host's defences is "
        "not part of this engagement.",
    Profile.BLUE:
        "Inspect this host's defences, harden what is weak, and prove the "
        "change by reading the control again afterwards. Do not emulate an "
        "adversary: on this side a finding is proven by re-reading, never by "
        "performing the technique.",
}


class ScriptedSweep:
    """Plays a fixed purple sequence, skipping anything refused or already run.

    This is the lab's stand-in for a trained model: a fixed, legible plan so the
    demonstration is deterministic. Swap in ``ModelChooser`` (constrained
    decoding over a checkpoint) to watch a trained model drive the same loop.

    ``reach_past`` names the verbs this sweep will bind straight off the registry
    when the gate's catalogue does not offer them — the deliberate overreach the
    mode demonstrations are built on. It is empty by default, so the sweep every
    other caller constructs picks only from ``permitted`` exactly as it always
    did.
    """

    def __init__(self, plan=_PLAN, *, reach_past: tuple[str, ...] = ()):
        self.plan = list(plan)
        self.reach_past = frozenset(reach_past)

    def choose(self, episode, permitted, *, exclude, target):
        from whetstone.actions import TargetKind
        done = {t.action.verb_id for t in episode.turns} | set(exclude)
        by_id = {v.id: v for v in permitted}
        for verb_id, extra in self.plan:
            if verb_id in done:
                continue
            verb = by_id.get(verb_id)
            if verb is None:
                if verb_id not in self.reach_past:
                    continue
                # Past the catalogue on purpose. The gate rules on it like
                # anything else, which is the entire claim being demonstrated.
                verb = REGISTRY.get(verb_id)
            elif verb_id in self.reach_past:
                # The catalogue is offering it, so this engagement permits it —
                # and an overreach step exists only to be refused. Submitting it
                # here would run a MODIFY that nothing in the plan asked for,
                # under a mode that never intended to change the host. Skipping
                # is the safe reading of a demonstration that cannot happen.
                continue
            params = {p.name: (p.choices[0] if p.choices else p.default)
                      for p in verb.params if p.default is not None}
            params = {k: v for k, v in params.items() if v is not None}
            params.update(extra)                       # explicit required params
            return verb.bind(params,
                             target=None if verb.target is TargetKind.NONE else target)
        return None


class PostureSweep:
    """Plays the blue plan in order, letting a verb be read twice.

    A cursor, not a done-set, and that is the whole difference from
    :class:`ScriptedSweep`. The defending loop's evidence is the *second* reading
    of a control that was read before the fix, so a chooser that skips anything
    it has already run cannot produce it — it would harden the host and then have
    nothing to compare against but the fix's own return value, which is the claim
    rather than the evidence.

    A step whose parameters come from a callable is aimed from the episode so
    far (see :func:`_weak_path`). When the callable finds nothing to aim at, the
    step is skipped: an unaimed MODIFY is a change pointed at a guess, and no
    assessment saying a file is weak is a good reason not to chmod one.
    """

    def __init__(self, plan=_BLUE_PLAN, *, reach_past: tuple[str, ...] = ()):
        self.plan = list(plan)
        self.reach_past = frozenset(reach_past)
        self.cursor = 0

    def choose(self, episode, permitted, *, exclude, target):
        from whetstone.actions import TargetKind
        by_id = {v.id: v for v in permitted}
        refused = set(exclude)
        while self.cursor < len(self.plan):
            verb_id, aim = self.plan[self.cursor]
            self.cursor += 1
            if verb_id in refused:
                # Denied or unsupported once already. The kernel put it in
                # `exclude` and asking again would spend a turn learning the
                # same thing twice.
                continue
            verb = by_id.get(verb_id)
            if verb is None:
                if verb_id not in self.reach_past:
                    continue
                verb = REGISTRY.get(verb_id)
            elif verb_id in self.reach_past:
                continue                              # see ScriptedSweep.choose
            extra: dict[str, Any] | None = (
                aim(episode) if callable(aim) else dict(aim))
            if extra is None:
                continue
            params = {p.name: (p.choices[0] if p.choices else p.default)
                      for p in verb.params if p.default is not None}
            params = {k: v for k, v in params.items() if v is not None}
            params.update(extra)
            return verb.bind(params,
                             target=None if verb.target is TargetKind.NONE else target)
        return None


#: Which chooser drives which mode, and with which deliberate overreach. Red and
#: purple share ``ScriptedSweep`` and the same attack; the plan is not what makes
#: them different.
_DRIVERS: dict[Profile, Callable[[], Any]] = {
    Profile.PURPLE: lambda: ScriptedSweep(),
    Profile.RED: lambda: ScriptedSweep(
        _RED_PLAN, reach_past=(_RED_OVERREACH[0],)),
    Profile.BLUE: lambda: PostureSweep(
        _BLUE_PLAN, reach_past=(_BLUE_OVERREACH[0],)),
}


def chooser_for(profile: Profile):
    """The scripted driver for one mode."""
    return _DRIVERS[profile]()


def _engagement(root: str) -> Engagement:
    """The purple engagement, by the name the benchmark and the capture use.

    Kept as a function of its own because ``bench.agentbench``,
    ``lab.record_run`` and two test modules import this name, and it is now what
    it always described: :func:`lab.profiles.purple`. The document moved into
    :mod:`lab.profiles` when the three modes arrived, so that the word in an
    engagement, the word a flag takes and the word in a refusal are one word.

    One thing did change, and it is the reason the delegation is worth stating.
    The purple profile pins the neutral side at OBSERVE and authorises a wider
    technique list than the inline document did. Neither is visible from here:
    every neutral verb in the catalogue is already OBSERVE, and the extra
    techniques belong to red verbs the sandbox adapter does not implement, which
    the kernel intersects away before the model is ever offered them.
    """
    return purple(root)


# --------------------------------------------------------------------------
# narrating the cycle
# --------------------------------------------------------------------------

#: Width every rule and every wrapped paragraph in the narration is cut to,
#: matching the ``=`` rules the summary blocks already print.
_WIDTH = 74

#: How a detection probe's answer is spoken. Keyed by what
#: :func:`~whetstone.kernel.detection_fired` returned, and the ``None`` row is
#: the reason this is a table rather than a conditional. ``None`` means the
#: probe could not establish anything, which is a third answer and not a soft
#: spelling of the second; a narration that prints it as "silent" describes a
#: detection gap that the kernel did not find and will not have recorded, and
#: the operator reading the screen has then been told the one thing this whole
#: project exists not to say. The wording is deliberately not a single word,
#: because a column of one-word verdicts invites the eye to sort it into two.
_PROBE_ANSWER = {
    True: "fired — the control saw the technique",
    False: "silent — the control saw nothing",
    None: "could not tell — the probe established nothing either way",
}

#: The verdict word for each remediation state, and the states are spoken with
#: the same care the kernel spells them with. Only ``closed`` is allowed to read
#: as closure; ``undetermined`` says unproven rather than borrowing either of
#: the words beside it. Every line here has ``Remediation.detail`` printed
#: underneath it, because the state is coarse on purpose and the route taken to
#: it is in the prose.
_FIX_VERDICT = {
    "closed": "GAP CLOSED",
    "ineffective": "STILL OPEN — the fix ran and did not work",
    "undetermined": "UNPROVEN — the fix ran, closure was not established",
    "failed": "NOT APPLIED — the hardening measure itself did not run",
    "refused": "NOT APPLIED — the gate refused the fix",
    "unavailable": "NOTHING PROPOSED — the catalogue had no fix to aim",
}


#: Wrapping options shared by every paragraph and every field below.
#:
#: Both defaults are turned off and both matter. ``break_on_hyphens`` splits
#: ``acme-agent`` across a line break, and the service name is the one parameter
#: a reader checks against the trajectory to confirm that the re-attack really
#: was the same action — a narration that renders it ``acme-\nagent`` has made
#: the evidence unverifiable to make the margin straight. ``break_long_words``
#: does the same to a long verb id or a sandbox path. An over-long line is a
#: cosmetic defect; a mangled identifier is a wrong one.
_WRAP = {"break_on_hyphens": False, "break_long_words": False}


def _para(text: str, indent: str = "") -> list[str]:
    """One wrapped paragraph, or an empty list for empty text."""
    if not text.strip():
        return []
    return textwrap.wrap(text.strip(), width=_WIDTH, initial_indent=indent,
                         subsequent_indent=indent, **_WRAP)


#: What the narrated run is not evidence of, printed under it rather than left
#: to the docs. A demonstration that ends on "3 of 3 proven closed" and says
#: nothing else is read as a claim about machines, and the person reading this
#: screen is exactly the person who will not go and check which parts of the
#: sandbox are modelled. Every sentence here is one of the documented limits of
#: the remediation phase, not a disclaimer written to sound careful.
_SANDBOX_CAVEAT = "\n".join([
    "-- what a sandbox proves, and what it does not " + "-" * (_WIDTH - 47),
    *_para(
        "the loop above is real: real files were overwritten, a real log was "
        "read, and the telemetry switch a fix flipped is the same boolean the "
        "probes read back. closure here means the technique really was "
        "performed a second time and the control really did answer."),
    "",
    *_para(
        "three things do not carry over. harden.fix_permissions really changes "
        "the mode, but the sandbox process owns the file, so a real chmod "
        "cannot lock it out — the foothold that makes the re-attack fail is "
        "asserted by the adapter, and this run is not proof that a chmod stops "
        "an attacker. on a real linux host the commonest blue failure by far "
        "is auditd running with no rule loaded, which the adapter reports "
        "honestly as unqueryable: that becomes an inconclusive observation, "
        "not a gap, and only gaps are remediated — so the case where switching "
        "the source on feels most obviously right produces no remediation at "
        "all. and on macos and windows the harden verbs are implemented but "
        "nothing publishes the parameters to aim them, so remediation there "
        "reports unavailable rather than closed."),
    "-" * _WIDTH,
])


#: The red-only sibling of :data:`_SANDBOX_CAVEAT`. A red-only run reaches no
#: closure, so the paragraphs about what "proven closed" is worth would be
#: describing a phase that did not run — accurate sentences about the wrong
#: screen, which is how a careful-sounding footer stops being read at all. What
#: this mode needs said instead is the thing its own output makes easy to
#: forget: the gaps are still open. Finding three of them and being refused the
#: fix is the designed outcome, not a partial run.
_RED_CAVEAT = "\n".join([
    "-- what an attacking run proves, and what it does not " + "-" * (_WIDTH - 54),
    *_para(
        "the attacks above are real: real files were overwritten and a real "
        "log was read to ask whether anything noticed. a gap here means this "
        "sandbox's one telemetry source held no record of the technique, which "
        "is a statement about a control that was really queried and not about "
        "any machine."),
    "",
    *_para(
        "every gap listed above is still open. this mode attacks and reports; "
        "the gate refused the one action that would have changed the defence, "
        "and nothing in this run has made the host better. the fix, and the "
        "second attack that would prove it held, are the purple cycle."),
    "-" * _WIDTH,
])


def _field(label: str, value: str, *, indent: int = 4, width: int = 10) -> list[str]:
    """A labelled line whose value wraps under itself rather than off the edge.

    Actions render long — ``exploit.service_permissions(restore=True,
    service=acme-agent) on 127.0.0.1`` is sixty-six characters before the
    label — and an action truncated to fit is an action the reader cannot
    check against the trajectory beside it. So the value wraps and the label
    column stays put.
    """
    pad = " " * indent
    hang = pad + " " * (width + 1)
    return textwrap.wrap(value, width=_WIDTH,
                         initial_indent=f"{pad}{label:<{width}} ",
                         subsequent_indent=hang,
                         **_WRAP) or [f"{pad}{label:<{width}} "]


def _mark(turn: Turn) -> str:
    """The one-word column for a turn whose outcome needs no sentence.

    Used for the reconnaissance block, where nine lines of "succeeded" is nine
    lines of the reader's attention spent on the least surprising thing on the
    screen. A turn that did *not* succeed still gets its own word here, because
    that is the line worth stopping on.
    """
    if turn.refused:
        return "DENY"
    if turn.observation is None:
        return "no obs"
    if turn.observation.unsupported:
        return "n/a"
    return "ok" if turn.observation.ok else "failed"


def _outcome(turn: Turn) -> str:
    """What became of one submitted action, in the loop's own vocabulary."""
    if turn.refused:
        return f"REFUSED by the gate ({turn.decision.rule})"
    if turn.observation is None:
        return "no observation came back"
    if turn.observation.unsupported:
        return f"unsupported on this platform: {turn.observation.error}"
    if turn.observation.ok:
        return "succeeded"
    return f"failed: {turn.observation.error or 'no reason given'}"


def _refusal_block(episode: Episode, profile: Profile | None) -> list[str]:
    """Every action the gate refused, with the rule that refused it.

    Printed as its own block rather than left to be spotted in the flat turn
    list, because under red-only and blue-only the refusal *is* the result. A
    run that attacks and finds gaps looks the same in either mode until you see
    the line where the gate declined to let the attacking side touch the
    control, and a demonstration that leaves the reader to infer that from an
    absence has demonstrated nothing.

    Generic over the modes on purpose: a refusal is worth printing whatever
    produced it. A scope denial or an expired window shows up here too, which is
    the correct behaviour for a screen whose heading is "what the gate stopped".
    """
    refused = [t for t in episode.turns if t.refused]
    if not refused:
        return []
    lines = ["-- what the gate refused " + "-" * (_WIDTH - 25)]
    lines += _para(
        f"{len(refused)} submitted action(s) were denied. the mode is "
        + (f"{profile.value} ({profile.describe()})." if profile is not None
           else "unrestricted by side; these are the older rules speaking.")
        + " a DENY has no override: the way to change one of these lines is to "
        "write a different engagement, not to pass a different flag.")
    lines.append("")
    for turn in refused:
        lines += _field("proposed", turn.action.render())
        lines += _field("DENY", f"[{turn.decision.rule}] {turn.decision.reason}")
        lines.append("")
    return lines


def render_cycle(episode: Episode, *, profile: Profile | None = None) -> str:
    """The whole purple cycle as one document, read top to bottom.

    Written as a pure function over a finished :class:`Episode` so the narration
    can be tested without building a sandbox, and so the demonstration and the
    captured transcript can never tell two different stories about one run.

    ``profile`` is the mode the episode ran under, and it changes only what the
    narration is allowed to *say*, never what it reports. It is optional because
    the captured transcripts and the tests call this with an episode and nothing
    else; without it the narration says what it always said.
    """
    gaps = [f for f in episode.findings if f.kind == "detection_gap"]
    beats = attack_beats(episode)
    pairs = pair_fix_blocks(gaps, fix_blocks(episode))

    # Refused turns are not reconnaissance and are not counted as observations.
    # A red-only run reaches for a harden verb and is denied, and listing that
    # denial among the reads — under a heading that says how many observations
    # were taken before anything was touched — both inflates the count and
    # buries the one line the mode exists to show. The refusals get their own
    # block below.
    recon = [t for t in episode.turns
             if t.phase == "plan" and not t.refused
             and REGISTRY.get(t.action.verb_id).side is not Side.RED]

    lines: list[str] = []
    lines += _para(
        "the full cycle, in the order it happened. every line below is a real "
        "gated action against the sandbox above — the exploits really wrote to "
        "those files and the probes really read that log.")
    lines.append("")

    # -- 1. reconnaissance --------------------------------------------------
    lines.append("-- 1. look " + "-" * (_WIDTH - 11))
    lines += _para(
        f"{len(recon)} observation(s) before anything was touched. none of "
        "these changes the host; the agent is reading.")
    lines.append("")
    for turn in recon:
        lines += _field(_mark(turn), turn.action.render())
    lines.append("")

    # -- 2. attack and detection -------------------------------------------
    lines.append("-- 2. attack, and ask who saw " + "-" * (_WIDTH - 30))
    lines += _para(
        "each red action is followed immediately by the control that claims to "
        "cover its technique, aimed from what the attack itself reported. a "
        "control with nothing to say is the finding.")
    lines.append("")

    pending = list(episode.findings)
    for n, (red, probes) in enumerate(beats, start=1):
        verb = REGISTRY.get(red.action.verb_id)
        technique = ", ".join(verb.attck) or verb.id
        lines.append(f"  attack {n} of {len(beats)} — {technique}")
        lines += _field("ran", f"{red.action.render()} — {_outcome(red)}")
        for probe in probes:
            answer = _PROBE_ANSWER[
                detection_fired(probe.observation) if probe.observation else None]
            lines += _field("control", probe.action.render())
            lines += _field("", answer)
        for finding in findings_for(pending, red.action.verb_id):
            head = {"detection_gap": "GAP", "no_coverage": "NO COVERAGE",
                    "observation": "INCONCLUSIVE"}.get(finding.kind, finding.kind)
            lines += _field("finding", f"{head} — {finding.detail}")
        lines.append("")

    if pending:
        # Never dropped. See findings_for.
        lines.append("  findings not attributable to an attack above")
        for finding in pending:
            lines += _field(finding.kind[:10], finding.detail)
        lines.append("")

    # -- 3. remediation -----------------------------------------------------
    if not gaps:
        lines.append("-- 3. nothing to fix " + "-" * (_WIDTH - 21))
        lines += _para(
            "no detection gap was produced, so there is nothing for the "
            "remediation phase to act on. that is the result, not a failure to "
            "run: a control that already sees the technique needs no fix.")
        lines.append("")
        lines += _refusal_block(episode, profile)
        return "\n".join(lines)

    # A gap with no ``Remediation`` at all was never offered one. When that is
    # true of every gap the phase did not run, and printing the "a fix is a
    # claim, the re-attack is the evidence" paragraph over three lines that say
    # nothing happened describes a run that did not take place.
    attempted = [g for g in gaps if g.remediation is not None]
    if not attempted:
        # Two different reasons to be here and they must not be spoken as one.
        # Under purple the phase was switched off and the other half is a flag
        # away; under red-only there is no flag, because this engagement does
        # not run the blue playbook above OBSERVE and the fix is not the
        # operator's to turn on. Telling a red-only operator to drop
        # --no-remediate would send them to a command that produces the same
        # screen, and they would read the gate's rule as a broken runner.
        red_only = profile is Profile.RED
        lines.append("-- 3. no fix was attempted " + "-" * (_WIDTH - 27))
        lines += _para(
            "the remediation phase did not run, so the gaps above are the "
            "whole result: found, proven by the exploit, and left open. "
            + ("that is the entire output of a red-only exercise. this mode "
               "attacks and reports; it does not hold the authorisation to "
               "change what it found, and the refusal below is the gate saying "
               "so. run the same exercise under --purple to see the other half."
               if red_only else
               "that is where this loop stopped for most of its life — the "
               "report without the fix. run the same command without "
               "--no-remediate to see the other half."))
        lines.append("")
        for n, gap in enumerate(gaps, start=1):
            lines += _field(f"gap {n}", f"{gap.technique} — {gap.detail}")
        lines.append("")
        lines += _refusal_block(episode, profile)
        return "\n".join(lines)

    lines.append("-- 3. fix it, then attack again " + "-" * (_WIDTH - 32))
    lines += _para(
        "a hardening verb returning ok has said only that a command exited "
        "zero. every report this project keeps finding fault with says "
        "\"fixed\" on that sentence. so the fix is followed by a silent "
        "reading of the control, then the original action repeated verbatim — "
        "same verb, same parameters — then the same control asked the same "
        "question again. the verdict is the DIFFERENCE between the two "
        "readings, never the second one on its own: a log that already held a "
        "row of that kind would otherwise close this gap on somebody else's "
        "evidence.")
    lines.append("")

    by_gap = {id(g): block for g, block in pairs}
    for n, gap in enumerate(gaps, start=1):
        lines.append(f"  gap {n} of {len(gaps)} — {gap.technique}, "
                     f"opened by {gap.produced_by}")
        fix = gap.remediation
        if fix is None:
            # Other gaps in this episode were attempted, so the phase was on
            # and this one fell past max_remediations. Never "nothing worked".
            lines += _field("no fix", "never offered one — the episode's "
                            "remediation budget was spent on the gaps above. "
                            "this gap is open and untouched, not unfixable")
            lines.append("")
            continue

        # The two probe readings are the same control asked the same question
        # before and after the re-attack, and the whole verdict is the
        # difference between them. Labelled by which side of the re-attack they
        # fall on, because two lines both called "control" would print the
        # comparison as a repetition and the reader would have to reconstruct
        # which one the verdict rests on.
        reattacked = False
        for turn in by_gap.get(id(gap), []):
            if turn.phase == "remediate":
                lines += _field("fix", f"{turn.action.render()} — {_outcome(turn)}")
            elif REGISTRY.get(turn.action.verb_id).side is Side.RED:
                reattacked = True
                lines += _field("re-attack",
                                f"{turn.action.render()} — {_outcome(turn)}")
            else:
                answer = _PROBE_ANSWER[
                    detection_fired(turn.observation) if turn.observation else None]
                lines += _field("control" if reattacked else "baseline",
                                turn.action.render())
                lines += _field("", answer)

        lines += _field("verdict", _FIX_VERDICT.get(fix.state, fix.state))
        lines += _field("", fix.detail)
        lines.append("")

    # -- the ledger ---------------------------------------------------------
    closed = [g for g in gaps
              if g.remediation is not None and g.remediation.proven_closed]
    lines.append("-- what this run showed " + "-" * (_WIDTH - 24))
    lines += _para(
        f"{len(beats)} technique(s) performed against the sandbox. "
        f"{len(gaps)} of them succeeded with nothing logging it. "
        f"{len(closed)} of those {len(gaps)} proven closed — meaning the "
        "technique was performed a second time after the fix and the control "
        "that had been silent answered.")
    if len(closed) != len(gaps):
        lines.append("")
        lines += _para(
            f"the other {len(gaps) - len(closed)} are listed above with the "
            "verdict the kernel reached and the route it took to get there. "
            "not one of them is closed, and a fix having run is not a reason "
            "to read any of them as closed — that is the sentence this whole "
            "phase exists to stop being written.")
    lines.append("")
    lines += _refusal_block(episode, profile)
    return "\n".join(lines)


# --------------------------------------------------------------------------
# narrating the defending half
# --------------------------------------------------------------------------

#: What a blue-only run is not evidence of. The mirror of ``_SANDBOX_CAVEAT``
#: and, for this mode, the more important of the two: a screen that ends on "2
#: of 2 changes verified" is read as "the host is now safe from what it was
#: weak to", and nothing on that screen has earned the second sentence. No
#: attack ran. A second reading is evidence that the host's own report of itself
#: changed; only a re-attack is evidence about an attack, and this mode is
#: deliberately not authorised to perform one.
_POSTURE_CAVEAT = "\n".join([
    "-- what a defending run proves, and what it does not " + "-" * (_WIDTH - 53),
    *_para(
        "nothing above was attacked, so nothing above is proof that an attack "
        "would now fail. the fixes really ran — the switch really flipped, the "
        "mode bits really changed — and the second reading is a genuine "
        "re-query of the same control rather than the fix's own return value. "
        "that is the strongest claim available to a mode that cannot attack: "
        "the host reports itself differently, and the report was taken twice."),
    "",
    *_para(
        "for evidence about the attack, the technique has to be performed after "
        "the fix and the control asked again. that is the purple cycle, and it "
        "is a different engagement rather than a different flag — run the same "
        "exercise under --purple."),
    "-" * _WIDTH,
])


def _reading(turn: Turn) -> str:
    """What one read-only observation actually said, in a line.

    Deliberately shallow. It reports the fields the adapters agree on — a
    ``summary`` sentence, a ``findings`` list — and says nothing at all when it
    recognises neither, because the alternative is a renderer inventing a
    summary of a payload shape it does not understand. A blank line here costs
    the reader one lookup; a confident wrong one costs them the run.
    """
    if turn.refused or turn.observation is None or not turn.observation.ok:
        return _outcome(turn)
    data = turn.observation.data
    if not isinstance(data, dict):
        return ""
    summary = data.get("summary")
    if isinstance(summary, str) and summary.strip():
        return summary.strip()
    findings = data.get("findings")
    if isinstance(findings, list):
        if not findings:
            return "0 finding(s)"
        first = findings[0] if isinstance(findings[0], dict) else {}
        where = first.get("path") or first.get("package") or ""
        mode = first.get("mode")
        return (f"{len(findings)} finding(s), first: {where}"
                + (f" mode {mode}" if mode else ""))
    return ""


def posture_pairs(episode: Episode) -> list[tuple[str, Turn, Turn]]:
    """Reads of the same control taken before and after the hardening.

    The defending half's evidence, and the reason the blue plan reads twice.
    Paired on the verb id and split on the first ``MODIFY`` turn, so a "before"
    is genuinely before every change and an "after" genuinely after one — a pair
    built out of two reads that both preceded the fix would compare a control to
    itself and print the result as verification.

    Returns nothing rather than guessing when a verb was read only once: one
    reading is a statement about the host and there is no difference in it.
    """
    change_at = next(
        (n for n, t in enumerate(episode.turns)
         if not t.refused
         and REGISTRY.get(t.action.verb_id).intent is not Intent.OBSERVE),
        None)
    if change_at is None:
        return []
    pairs: list[tuple[str, Turn, Turn]] = []
    for verb_id in dict.fromkeys(t.action.verb_id for t in episode.turns):
        before = [t for n, t in enumerate(episode.turns)
                  if t.action.verb_id == verb_id and n < change_at and t.succeeded]
        after = [t for n, t in enumerate(episode.turns)
                 if t.action.verb_id == verb_id and n > change_at and t.succeeded]
        if before and after:
            pairs.append((verb_id, before[0], after[-1]))
    return pairs


def render_posture(episode: Episode, *, profile: Profile | None = None) -> str:
    """The defending half as one document: look, harden, look again.

    A separate renderer rather than :func:`render_cycle` with the red parts
    switched off. That function's spine is "each red action is followed by the
    control that claims to cover its technique", and a blue-only episode has no
    red action — printing that heading over an empty list would describe a run
    that did not happen, which is the same defect as narrating a gap nobody
    found. The two modes produce different evidence and get different screens.
    """
    # Split on the verb's own intent rather than on the group its id starts
    # with. `harden.*` is the only MODIFY in the catalogue today, and a blue
    # verb added tomorrow at MODIFY under some other name would otherwise be
    # narrated as a read — a change to the host reported in the block headed
    # "none of this changes the host".
    changes = [t for t in episode.turns
               if not t.refused
               and REGISTRY.get(t.action.verb_id).intent is not Intent.OBSERVE]
    reads = [t for t in episode.turns
             if t.phase == "plan" and not t.refused
             and REGISTRY.get(t.action.verb_id).intent is Intent.OBSERVE]
    pairs = posture_pairs(episode)

    lines: list[str] = []
    lines += _para(
        "the defending half, in the order it happened. no attack was performed "
        "and none could be: every line below is either a read of this host or a "
        "change to it, and every change is followed by a second read of the "
        "control it claims to have changed.")
    lines.append("")

    # -- 1. posture ---------------------------------------------------------
    lines.append("-- 1. look " + "-" * (_WIDTH - 11))
    lines += _para(
        f"{len(reads)} observation(s) of this host's own posture — what runs, "
        "what is weak, and whether anything is recording.")
    lines.append("")
    for turn in reads:
        lines += _field(_mark(turn), turn.action.render())
        said = _reading(turn)
        if said:
            lines += _field("", said)
    lines.append("")

    # -- 2. the boundary ----------------------------------------------------
    lines += _refusal_block(episode, profile)

    # -- 3. harden ----------------------------------------------------------
    if not changes:
        lines.append("-- nothing was changed " + "-" * (_WIDTH - 23))
        lines += _para(
            "no hardening measure ran. either nothing the assessment found has "
            "a fix in this catalogue, or the adapter driving this exercise "
            "implements none — the VM adapter, for instance, implements no "
            "harden verb at all, so a blue exercise against it reports posture "
            "and stops there. that is a limit of the target, not a clean bill "
            "of health.")
        lines.append("")
        return "\n".join(lines)

    lines.append("-- 2. harden what the assessment found " + "-" * (_WIDTH - 39))
    lines += _para(
        "each of these really changed the sandbox. what none of them has done "
        "yet is prove anything: a harden verb returning ok has said that a "
        "command exited zero, which is the one sentence this project refuses to "
        "accept anywhere else.")
    lines.append("")
    for turn in changes:
        lines += _field("applied", f"{turn.action.render()} — {_outcome(turn)}")
        said = _reading(turn)
        if said:
            lines += _field("", said)
    lines.append("")

    # -- 4. read it again ---------------------------------------------------
    lines.append("-- 3. read the same control again " + "-" * (_WIDTH - 34))
    lines += _para(
        "the defending half's version of the re-attack. the same read-only "
        "question, put a second time after the change, and the verdict is the "
        "difference between the two answers rather than the second one alone.")
    lines.append("")
    if not pairs:
        lines += _field("no pair", "nothing was read both before and after a "
                        "change, so no difference was established. the fixes "
                        "above are claims and this run did not test them")
        lines.append("")
        return "\n".join(lines)

    moved = 0
    for verb_id, before, after in pairs:
        said_before, said_after = _reading(before), _reading(after)
        lines.append(f"  {verb_id}")
        lines += _field("before", said_before or "(payload said nothing this "
                        "renderer recognises)")
        lines += _field("after", said_after or "(payload said nothing this "
                        "renderer recognises)")
        if said_before and said_after and said_before != said_after:
            moved += 1
            lines += _field("verdict", "CHANGED — the control answers "
                            "differently than it did before the fix")
        else:
            lines += _field("verdict", "UNCHANGED — the second reading is the "
                            "first one again, so nothing this control can see "
                            "moved")
        lines.append("")

    lines.append("-- what this run showed " + "-" * (_WIDTH - 24))
    lines += _para(
        f"{len(changes)} change(s) applied to this host. {len(pairs)} control(s) "
        f"read before and after them, of which {moved} answer differently now. "
        "no technique was performed at any point in this run.")
    lines.append("")
    return "\n".join(lines)


def run_once(telemetry: bool, chooser=None, *, remediate: bool = True,
             narrate: bool = False, profile: Profile = Profile.PURPLE) -> None:
    if remediate and profile is not Profile.PURPLE:
        # Loudly, here, rather than as a screen full of "unavailable". The
        # remediation phase draws its candidates from `gate.catalogue()`, which
        # under red-only and blue-only holds no harden verb the phase could aim
        # — red-only because the mode forbids them, blue-only because it
        # produces no detection gap to aim one at. Running anyway would print a
        # remediation section reporting that nothing could be proposed, and an
        # operator would read the mode's design as a broken catalogue.
        raise ValueError(
            f"remediate=True is not meaningful under {profile.value}: the "
            "attack -> gap -> fix -> re-attack loop needs both playbooks, and "
            "this mode runs one. Use purple, or pass remediate=False.")

    with SandboxTarget(telemetry=telemetry) as target:
        print("=" * 74)
        print(target.summary())
        print("=" * 74)

        engagement = engagement_for(profile.value, str(target.root))
        gate = Gate(engagement, registry=REGISTRY, confirmer=always_confirm)
        print(f"mode          {profile.value} — {profile.describe()}")
        print(f"engagement    {engagement.name}: {engagement.authorization}")
        print("=" * 74)

        # The sandbox adapter is scope-locked by target confinement, and the
        # engagement authorises the techniques the plan uses.
        # remediate=True is the lab's choice, not the kernel's default. The
        # phase changes the target and re-runs the exploits to check, which is
        # exactly what a disposable sandbox is for and exactly what a machine
        # somebody depends on is not.
        kernel = Kernel(gate, SandboxAdapter(target),
                        chooser or chooser_for(profile),
                        max_turns=20, remediate=remediate)
        episode = kernel.run(TASKS[profile], target="127.0.0.1")

        if narrate:
            # The narration replaces the summary rather than joining it. It
            # says everything the summary says and says which of the twenty-odd
            # turns were the agent's and which were the kernel's evidence,
            # which the flat list cannot; printing both would ask the reader to
            # reconcile two orderings of one run.
            print()
            if profile is Profile.BLUE:
                print(render_posture(episode, profile=profile))
                print(_POSTURE_CAVEAT)
            else:
                print(render_cycle(episode, profile=profile))
                # Each mode gets the footer that describes the run it just
                # printed. The purple caveat is about what closure is worth,
                # and a red-only run reaches none.
                print(_RED_CAVEAT if profile is Profile.RED
                      else _SANDBOX_CAVEAT)
            return

        print("\n" + episode.summary())

        if profile is Profile.BLUE:
            _print_posture_ledger(episode, telemetry)
            return

        gaps = [f for f in episode.findings if f.kind == "detection_gap"]
        print("\n" + "-" * 74)
        if telemetry:
            print(f"telemetry ON  -> {len(gaps)} detection gap(s): the blue side "
                  "saw the attacks.")
        else:
            print(f"telemetry OFF -> {len(gaps)} detection gap(s): the attacks "
                  "succeeded unobserved.")
            for g in gaps:
                print(f"    GAP  {g.technique}: {g.detail}")

        if remediate and gaps:
            # Counted by state rather than summarised as "remediated", because
            # "we ran a fix" and "the hole is shut" are the two claims this
            # whole phase exists to keep apart.
            closed = [g for g in gaps
                      if g.remediation is not None and g.remediation.proven_closed]
            print("\n" + "-" * 74)
            print(f"remediation   -> {len(closed)} of {len(gaps)} gap(s) PROVEN "
                  "closed, by re-running the attack and re-asking the control.")
            for g in gaps:
                fix = g.remediation
                if fix is None:
                    print(f"    [NOT ATTEMPTED] {g.technique}")
                    continue
                print(f"    [{fix.state.upper()}] {g.technique} "
                      f"via {fix.verb or '(nothing proposed)'}")
                print(f"        {fix.detail}")
        _print_refusals(episode)
        print("-" * 74)


def _print_refusals(episode: Episode) -> None:
    """The gate's denials, under the ledger rather than buried in the turn list.

    ``Episode.summary`` already prints every refusal with sixty characters of
    its reason, which is enough to spot one and not enough to understand it. The
    line that matters under red-only is the whole sentence, because it names the
    mode and says that widening the ceiling would not help — and that is exactly
    the part sixty characters cuts off.
    """
    refused = [t for t in episode.turns if t.refused]
    if not refused:
        return
    print("\n" + "-" * 74)
    print(f"the gate     -> {len(refused)} action(s) refused. a DENY has no "
          "override; the engagement is the only way to change one.")
    for turn in refused:
        print(f"    [{turn.decision.rule}] {turn.action.render()}")
        print(f"        {turn.decision.reason}")


def _print_posture_ledger(episode: Episode, telemetry: bool) -> None:
    """The blue tail: what changed, and what a second reading said about it."""
    changes = [t for t in episode.turns
               if not t.refused
               and REGISTRY.get(t.action.verb_id).intent is not Intent.OBSERVE]
    pairs = posture_pairs(episode)
    moved = [p for p in pairs if _reading(p[1]) != _reading(p[2])
             and _reading(p[1]) and _reading(p[2])]

    print("\n" + "-" * 74)
    state = "ON" if telemetry else "OFF"
    print(f"telemetry {state:<3} -> {len(changes)} hardening measure(s) applied, "
          f"{len(moved)} of {len(pairs)} control(s) answering differently now.")
    for verb_id, before, after in pairs:
        print(f"    {verb_id}")
        print(f"        before  {_reading(before)}")
        print(f"        after   {_reading(after)}")
    print("\n    no technique was performed in this run, so none of the above "
          "is evidence\n    that an attack would now fail. that needs the "
          "purple cycle.")
    _print_refusals(episode)
    print("-" * 74)


def add_profile_flags(p: argparse.ArgumentParser) -> None:
    """Give a runner the three modes, spelled the way the engagement spells them.

    One ``--mode`` taking a profile name, plus a flag per mode that sets it, all
    writing the same ``mode`` attribute and refusing to be combined. The long
    flags are the profile's own value string — ``--red-only``, not ``--red`` —
    so there is exactly one word per mode across the flag, the engagement
    document and the gate's refusal. ``--red`` and ``--blue`` still work, as
    argparse abbreviations of those flags rather than as aliases anybody has to
    keep in step with them.

    Shared by ``lab.run`` and ``scripts/trace_run.py`` so the two runners cannot
    drift into offering different words for the same three documents.
    """
    modes = p.add_mutually_exclusive_group()
    modes.add_argument("--mode", dest="mode", choices=PROFILE_NAMES,
                       default=Profile.PURPLE.value,
                       help="which engagement to run under (default: purple)")
    for name, blurb in (
        ("red-only", "attack and observe; the gate refuses every hardening "
                     "measure, visibly"),
        ("blue-only", "defend only; no attack is possible under this "
                      "engagement"),
        ("purple", "the full cycle: attack, gap, fix, re-attack, prove closure"),
    ):
        modes.add_argument(f"--{name}", dest="mode", action="store_const",
                           const=name, help=blurb)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Run the lab loop against the sandbox.")
    add_profile_flags(p)
    p.add_argument("--telemetry", action="store_true",
                   help="enable the sandbox event log (gaps close)")
    p.add_argument("--both", action="store_true",
                   help="run with telemetry off, then on, to compare")
    p.add_argument("--cycle", action="store_true",
                   help="narrate the run in order — attack, the control's "
                        "answer, the gap, the fix, the re-attack, the control "
                        "again — instead of printing the flat turn list")
    p.add_argument("--no-remediate", dest="remediate", action="store_false",
                   help="stop at the gap, the way the loop did before the "
                        "remediation phase existed")
    p.add_argument("--model", type=Path,
                   help="drive the loop with a trained checkpoint instead of "
                        "the scripted sweep (constrained decoding)")
    p.add_argument("--tokenizer", type=Path,
                   default=Path("/Volumes/at0m_b0mb/whetstone/models/tokenizer-v1/tokenizer.json"))
    args = p.parse_args(argv)
    profile = Profile(args.mode)

    chooser = None
    if args.model:
        from training.agent import load_chooser
        print(f"driving with the trained model at {args.model}\n")
        chooser = load_chooser(args.model, args.tokenizer, verbose=True)

    # Remediation is the purple cycle and only the purple cycle. Under the other
    # two modes it is off because the mode has one playbook, not because the
    # operator asked — so --no-remediate is honoured where it means something
    # and is a no-op where the phase was never going to run. Nothing here
    # widens: this line can only turn the phase off.
    remediate = args.remediate and profile is Profile.PURPLE

    # --cycle is presentation and nothing else: the same episode, read in the
    # order it happened rather than as a list of turns. It deliberately does
    # not imply --no-remediate's opposite or force telemetry off, because a
    # flag that quietly changes what was run in order to make the output look
    # better is how a demonstration stops being a run.
    if args.both:
        print("\n### TELEMETRY OFF — the attack nobody logged\n")
        run_once(False, chooser, remediate=remediate, narrate=args.cycle,
                 profile=profile)
        print("\n\n### TELEMETRY ON — the same attack, this time seen\n")
        run_once(True, chooser, remediate=remediate, narrate=args.cycle,
                 profile=profile)
    else:
        run_once(args.telemetry, chooser, remediate=remediate,
                 narrate=args.cycle, profile=profile)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
