"""Run the full purple loop against the sandbox — the thing you can test now.

    python -m lab.run                 # telemetry off: watch the gap appear,
                                      # then watch the agent close it
    python -m lab.run --cycle         # the same run, narrated in order:
                                      # attack, silence, gap, fix, re-attack,
                                      # the control speaking, closure
    python -m lab.run --telemetry     # telemetry on: nothing to find
    python -m lab.run --both          # both, side by side
    python -m lab.run --no-remediate  # stop where the loop used to stop

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
from datetime import datetime, timedelta, timezone
from pathlib import Path

import whetstone.verbs  # noqa: F401  (registers the catalogue)
from whetstone.actions import REGISTRY, Side
from whetstone.gate import Gate, always_confirm
from whetstone.gate.engagement import Authorization, Engagement, Scope
from whetstone.kernel import (Episode, HeuristicChooser, Kernel, Turn,
                              detection_fired)

from .adapter import SandboxAdapter
from .capture import (attack_beats, findings_for, fix_blocks,
                      pair_fix_blocks)
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


class ScriptedSweep:
    """Plays a fixed purple sequence, skipping anything refused or already run.

    This is the lab's stand-in for a trained model: a fixed, legible plan so the
    demonstration is deterministic. Swap in ``ModelChooser`` (constrained
    decoding over a checkpoint) to watch a trained model drive the same loop.
    """

    def __init__(self, plan=_PLAN):
        self.plan = list(plan)

    def choose(self, episode, permitted, *, exclude, target):
        from whetstone.actions import TargetKind
        done = {t.action.verb_id for t in episode.turns} | set(exclude)
        by_id = {v.id: v for v in permitted}
        for verb_id, extra in self.plan:
            if verb_id in done or verb_id not in by_id:
                continue
            verb = by_id[verb_id]
            params = {p.name: (p.choices[0] if p.choices else p.default)
                      for p in verb.params if p.default is not None}
            params = {k: v for k, v in params.items() if v is not None}
            params.update(extra)                       # explicit required params
            return verb.bind(params,
                             target=None if verb.target is TargetKind.NONE else target)
        return None


def _engagement(root: str) -> Engagement:
    now = datetime.now(timezone.utc)
    return Engagement(
        name="sandbox purple exercise",
        authorization="LAB — self-contained sandbox, no real host in scope",
        starts=now - timedelta(minutes=1),
        expires=now + timedelta(hours=1),
        scope=Scope(paths=(root,), allow_loopback=True),
        authorize=Authorization(
            red_team=True, max_intent=__import__(
                "whetstone.actions", fromlist=["Intent"]).Intent.EXECUTE,
            techniques=("T1574", "T1003", "T1547", "T1543", "T1053", "T1041"),
            unattended=frozenset(__import__(
                "whetstone.actions", fromlist=["Intent"]).Intent)),
    )


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


def render_cycle(episode: Episode) -> str:
    """The whole purple cycle as one document, read top to bottom.

    Written as a pure function over a finished :class:`Episode` so the narration
    can be tested without building a sandbox, and so the demonstration and the
    captured transcript can never tell two different stories about one run.
    """
    gaps = [f for f in episode.findings if f.kind == "detection_gap"]
    beats = attack_beats(episode)
    pairs = pair_fix_blocks(gaps, fix_blocks(episode))

    recon = [t for t in episode.turns
             if t.phase == "plan"
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
        return "\n".join(lines)

    # A gap with no ``Remediation`` at all was never offered one. When that is
    # true of every gap the phase did not run, and printing the "a fix is a
    # claim, the re-attack is the evidence" paragraph over three lines that say
    # nothing happened describes a run that did not take place.
    attempted = [g for g in gaps if g.remediation is not None]
    if not attempted:
        lines.append("-- 3. no fix was attempted " + "-" * (_WIDTH - 27))
        lines += _para(
            "the remediation phase did not run, so the gaps above are the "
            "whole result: found, proven by the exploit, and left open. that "
            "is where this loop stopped for most of its life — the report "
            "without the fix. run the same command without --no-remediate to "
            "see the other half.")
        lines.append("")
        for n, gap in enumerate(gaps, start=1):
            lines += _field(f"gap {n}", f"{gap.technique} — {gap.detail}")
        lines.append("")
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
    return "\n".join(lines)


def run_once(telemetry: bool, chooser=None, *, remediate: bool = True,
             narrate: bool = False) -> None:
    with SandboxTarget(telemetry=telemetry) as target:
        print("=" * 74)
        print(target.summary())
        print("=" * 74)

        gate = Gate(_engagement(str(target.root)), registry=REGISTRY,
                    confirmer=always_confirm)
        # The sandbox adapter is scope-locked by target confinement, and the
        # engagement authorises the techniques the plan uses.
        # remediate=True is the lab's choice, not the kernel's default. The
        # phase changes the target and re-runs the exploits to check, which is
        # exactly what a disposable sandbox is for and exactly what a machine
        # somebody depends on is not.
        kernel = Kernel(gate, SandboxAdapter(target), chooser or ScriptedSweep(),
                        max_turns=20, remediate=remediate)
        episode = kernel.run(
            "Assess this host, prove what you find, and tell me what nobody saw.",
            target="127.0.0.1")

        if narrate:
            # The narration replaces the summary rather than joining it. It
            # says everything the summary says and says which of the twenty-odd
            # turns were the agent's and which were the kernel's evidence,
            # which the flat list cannot; printing both would ask the reader to
            # reconcile two orderings of one run.
            print()
            print(render_cycle(episode))
            print(_SANDBOX_CAVEAT)
            return

        print("\n" + episode.summary())

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
        print("-" * 74)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Run the purple loop against the sandbox.")
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

    chooser = None
    if args.model:
        from training.agent import load_chooser
        print(f"driving with the trained model at {args.model}\n")
        chooser = load_chooser(args.model, args.tokenizer, verbose=True)

    # --cycle is presentation and nothing else: the same episode, read in the
    # order it happened rather than as a list of turns. It deliberately does
    # not imply --no-remediate's opposite or force telemetry off, because a
    # flag that quietly changes what was run in order to make the output look
    # better is how a demonstration stops being a run.
    if args.both:
        print("\n### TELEMETRY OFF — the attack nobody logged\n")
        run_once(False, chooser, remediate=args.remediate, narrate=args.cycle)
        print("\n\n### TELEMETRY ON — the same attack, this time seen\n")
        run_once(True, chooser, remediate=args.remediate, narrate=args.cycle)
    else:
        run_once(args.telemetry, chooser, remediate=args.remediate,
                 narrate=args.cycle)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
