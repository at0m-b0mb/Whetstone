"""Capture a real run to committable artifacts — the model, on the record.

Runs the agent against a lab target for real and writes three files that
together are an honest record of what happened:

* ``<name>.trajectory.txt`` — the wire protocol, byte for byte. This is the
  training-data format, so the file doubles as a worked example of what a
  trajectory looks like and as proof that a real run produces valid training
  data with no conversion step.
* ``<name>.transcript.md`` — the same run for a human: each action, the real
  observation it returned, and the findings, with the model's own runner-up
  choices shown so its judgement is legible rather than a black box.
* ``<name>.findings.json`` — the machine-readable result: the detection gaps,
  what produced them, and what was done about them.

Nothing here is illustrative or edited. The observations are what the adapter
actually returned from the actual target on this machine, captured at the
timestamp in the header. Regenerate on a different host and the observations
change, because they are observations.

**One thing is edited and it is not optional.** Every byte of all three files
goes through :func:`~training.trajectories.redact_identity` before it is
written, and :func:`~training.trajectories.identity_leaks` is asked afterwards
whether the substitution took. ``examples/runs/`` is force-included by
``.gitignore`` and pushed to a public repository, and an artifact that proves
this tool works while also publishing the maintainer's account name and the
per-user temp path that identifies their Mac has proved two things. It used to
be a step somebody had to remember between capturing and committing; a step
somebody has to remember is a step that gets skipped on the day the run finally
works. It is now the write path, and there is no other one.

**The remediation phase is part of the record.** A capture that stopped at the
findings would describe half a run: the transcript names every turn's phase, so
a reader can see which actions the agent chose and which the kernel injected as
evidence, and the findings JSON carries the remediation outcome exactly as the
kernel spelled it. ``closed`` means the attack was performed a second time and
the control answered. Nothing weaker is written as closure, here or anywhere.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from whetstone.actions import REGISTRY, Side
from whetstone.kernel import Episode, Finding, Turn, detection_fired
from whetstone.kernel.render import render_episode, shrink_payload

__all__ = ["capture", "CaptureMeta", "attack_beats", "fix_blocks",
           "pair_fix_blocks", "findings_for", "turns_by_phase"]


# --------------------------------------------------------------------------
# reading an episode's shape back out
# --------------------------------------------------------------------------
#
# An :class:`Episode` is a flat list of turns with a ``phase`` on each. That is
# the right shape to record and the wrong shape to read: the same exploit
# appears twice, once because the agent chose it and once because the kernel
# replayed it as evidence, and a reader given the flat list has no way to tell
# those apart. These four functions put the structure back, and both the
# narrated demonstration in ``lab/run.py`` and the transcript below are built on
# them — so the screen and the committed file can never tell different stories
# about one run.

#: The one remediation state the kernel reaches without submitting anything.
#: Every other return in :meth:`Kernel._close_gap` happens *after* the harden
#: action has gone through the gate, so a gap in any other state owns exactly
#: one block of remediation turns. :func:`pair_fix_blocks` relies on that and
#: checks it rather than assuming it.
NO_TURNS_STATE = "unavailable"


def turns_by_phase(episode: Episode) -> dict[str, int]:
    """How many turns each phase contributed, in a fixed order.

    Reported in the artifacts because "24 turns" stopped meaning what it used to
    mean. Nine of those twenty-four are the kernel's own evidence-gathering, and
    an artifact that prints one number invites the reader — or a later
    benchmark — to treat the kernel's re-attacks as things the agent decided to
    do. The breakdown costs one line and removes the ambiguity.
    """
    counts = {"plan": 0, "detect": 0, "remediate": 0, "verify": 0}
    for turn in episode.turns:
        counts[turn.phase] = counts.get(turn.phase, 0) + 1
    return counts


def attack_beats(episode: Episode) -> list[tuple[Turn, list[Turn]]]:
    """Each red action the agent chose, with the probes the kernel ran for it.

    The grouping is structural rather than inferred.
    :meth:`Kernel._check_detections` appends every probe immediately after the
    red turn that provoked it and nothing else is appended in between, so a
    ``plan`` turn followed by a contiguous run of ``detect`` turns *is* one
    attack and its detections. That is a fact about the loop rather than a guess
    about verb names, which is what makes it safe to reconstruct out here: if
    the kernel ever stops emitting them contiguously, the grouping breaks
    visibly on the first run instead of quietly crediting a probe to the wrong
    attack.
    """
    beats: list[tuple[Turn, list[Turn]]] = []
    turns = episode.turns
    i = 0
    while i < len(turns):
        turn = turns[i]
        i += 1
        if turn.phase != "plan":
            continue
        probes: list[Turn] = []
        while i < len(turns) and turns[i].phase == "detect":
            probes.append(turns[i])
            i += 1
        if REGISTRY.get(turn.action.verb_id).side is Side.RED:
            beats.append((turn, probes))
    return beats


def findings_for(pending: list[Finding], verb_id: str) -> list[Finding]:
    """Take the findings this red verb produced off the front of ``pending``.

    Consumed in order rather than filtered by id, and the difference shows when
    the same verb runs twice: a filter would hand both runs' findings to the
    first beat and none to the second. The kernel appends a red turn's findings
    before it moves on, so the queue order and the beat order are one order.

    Mutates ``pending``, which is the point — whatever is left when the caller
    has walked every beat is a finding no beat claimed, and the callers print
    that under its own heading. A narration that silently dropped it would be a
    report that is missing a finding and does not say so.
    """
    out: list[Finding] = []
    while pending and pending[0].produced_by == verb_id:
        out.append(pending.pop(0))
    return out


def fix_blocks(episode: Episode) -> list[list[Turn]]:
    """The remediation turns, split into one block per gap the kernel acted on.

    A block opens at a ``remediate`` turn and absorbs the ``verify`` turns after
    it. A ``verify`` turn with no block open cannot happen — the kernel only
    submits a re-attack after the fix it is verifying — so it raises rather than
    being tolerated, because the alternative is attaching one gap's re-attack to
    the previous gap's fix and printing it as that fix's evidence.
    """
    blocks: list[list[Turn]] = []
    for turn in episode.turns:
        if turn.phase == "remediate":
            blocks.append([turn])
        elif turn.phase == "verify":
            if not blocks:
                raise ValueError(
                    "a verify turn appeared before any remediate turn; the "
                    "kernel only submits a re-attack after the fix it is "
                    "verifying, so there is no way to say which gap this "
                    "belongs to and this will not guess")
            blocks[-1].append(turn)
    return blocks


def pair_fix_blocks(
    gaps: Sequence[Finding], blocks: Sequence[list[Turn]]
) -> list[tuple[Finding, list[Turn]]]:
    """Match each acted-on gap to the turns that were submitted for it.

    The pairing is positional and it is checked. :meth:`Kernel.remediate_gaps`
    walks the gaps in the order they were found and submits for each in turn, so
    the *n*-th block belongs to the *n*-th gap that got as far as a submission —
    which is every gap whose state is not :data:`NO_TURNS_STATE`.

    A count mismatch raises. Zipping the two and printing whatever lined up
    would produce a file showing one gap's fix under another gap's heading with
    nothing marking it wrong, which is the same class of error as crediting a
    fix to the wrong gap inside the kernel and ends the same way: a hole
    reported shut. Loud is cheaper than plausible.
    """
    acted = [g for g in gaps
             if g.remediation is not None
             and g.remediation.state != NO_TURNS_STATE]
    if len(acted) != len(blocks):
        raise ValueError(
            f"{len(blocks)} block(s) of remediation turns for {len(acted)} "
            "gap(s) that reached the gate. These are matched by position and "
            "the kernel's states say how many to expect, so one of the two has "
            "changed: states seen were "
            f"{[g.remediation.state for g in gaps if g.remediation]!r}")
    return list(zip(acted, blocks))


# --------------------------------------------------------------------------
# writing, with the redaction in the write path
# --------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class CaptureMeta:
    """Provenance for a captured run, so the artifact is reproducible."""

    checkpoint: str
    target: str
    telemetry: str
    timestamp: str
    driver: str          # "trained model (constrained decoding)" | "scripted" | ...
    #: Whether the kernel was allowed to propose fixes and verify them by
    #: re-attacking. Recorded because a capture with no remediation section
    #: could mean the phase was off or could mean every gap was unfixable, and
    #: an artifact that cannot distinguish those is an artifact that will be
    #: read as whichever one the reader expected.
    remediation: str = "off"


def _write_redacted(path: Path, text: str, *, as_json: bool = False) -> None:
    """Substitute this machine's identity out of ``text``, then write it.

    ``redact_identity`` refuses loudly when a literal survives its own
    substitution, so the failure mode here is an exception and an unwritten
    file rather than a published account name. ``identity_leaks`` is asked
    again afterwards: it is the same table read the same way, so it cannot
    catch anything ``redact_identity`` missed, and that is not why it is here.
    It is here so that this write path keeps answering the question even if
    somebody later swaps the substitution for something cleverer.

    ``as_json`` re-parses the redacted text, and the trap it guards is specific.
    Redaction runs on the finished document, which for this file is already
    serialised JSON, and the replacement for the per-user temp directory is
    ``C:\\Temp`` on Windows — a backslash, inserted into a JSON string, where
    ``\\T`` is not a valid escape. On this Mac the replacement is ``/tmp`` and
    nothing can go wrong; on the first Windows capture the file would be written
    and would not parse, and the thing that noticed would be whatever read it
    next. Checking costs one ``json.loads``.
    """
    from training.trajectories import identity_leaks, redact_identity

    clean = redact_identity(text)

    survivors = identity_leaks(clean)
    if survivors:
        raise RuntimeError(
            f"{path.name} still carries {survivors!r} after redaction and will "
            "not be written. examples/runs/ is public; fix _identity_table in "
            "training/trajectories.py rather than this check.")

    if as_json:
        try:
            json.loads(clean)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"redaction left {path.name} as invalid JSON ({exc}). A "
                "replacement string containing a backslash was substituted "
                "into already-serialised JSON — build the document from "
                "redacted values instead of redacting the finished text."
            ) from exc

    path.write_text(clean, encoding="utf-8")


# --------------------------------------------------------------------------
# the transcript
# --------------------------------------------------------------------------

#: How a probe's answer is written in the transcript, keyed by what
#: :func:`~whetstone.kernel.detection_fired` returned. The ``None`` row is why
#: this is a table: ``None`` means the probe established nothing, which is a
#: third answer and not a gentler spelling of the second. Writing it as "silent"
#: would put a detection gap in a published file that the kernel never found.
_PROBE_ANSWER = {
    True: "**fired** — the control saw the technique",
    False: "**silent** — the control saw nothing",
    None: "**could not tell** — the probe established nothing either way",
}

#: The phase marker shown beside each turn heading. ``plan`` is the agent's own
#: choice and is left unmarked so the injected turns stand out rather than the
#: other way round.
_PHASE_MARK = {"plan": "", "detect": " · _kernel probe_",
               "remediate": " · _kernel fix_", "verify": " · _kernel evidence_"}


def _probe_answer(turn: Turn) -> str:
    return _PROBE_ANSWER[
        detection_fired(turn.observation) if turn.observation else None]


def _turn_outcome(turn: Turn) -> str:
    if turn.refused:
        return "REFUSED"
    if turn.observation is not None and turn.observation.unsupported:
        return "unsupported"
    return "ok" if turn.succeeded else "failed"


def _remediation_section(episode: Episode) -> list[str]:
    """What was fixed and what the re-attack proved, or nothing at all.

    Returns an empty list when no gap was ever offered a fix, rather than a
    heading over an empty table. A section that says "remediation: none" reads
    as a result; the absence of the section, next to the ``remediation`` row in
    the header table, says what actually happened.
    """
    gaps = [f for f in episode.findings if f.kind == "detection_gap"]
    attempted = [g for g in gaps if g.remediation is not None]
    if not attempted:
        return []

    blocks = dict(
        (id(g), b) for g, b in pair_fix_blocks(gaps, fix_blocks(episode)))
    closed = [g for g in attempted if g.remediation.proven_closed]

    lines = [
        "---",
        "",
        "## Remediation — what was fixed, and what proved it",
        "",
        "A hardening verb returning `ok` has said only that a command exited",
        "zero. Under each fix below is the **original attack repeated",
        "verbatim** — same verb, same parameters — and the **same control asked",
        "the same question a second time**. That answer is the evidence, and",
        "`closed` is the only state that means the gap is shut.",
        "",
        f"**{len(closed)} of {len(gaps)} gap(s) proven closed.**",
        "",
        "| gap | technique | fix | state |",
        "|---|---|---|---|",
    ]
    for n, gap in enumerate(gaps, start=1):
        fix = gap.remediation
        state = "_never offered one_" if fix is None else f"`{fix.state}`"
        verb = "—" if fix is None or not fix.verb else f"`{fix.verb}`"
        lines.append(f"| {n} | `{gap.technique}` | {verb} | {state} |")
    lines.append("")

    for n, gap in enumerate(gaps, start=1):
        fix = gap.remediation
        lines += [f"### Gap {n} — `{gap.technique}`, opened by "
                  f"`{gap.produced_by}`", ""]
        if fix is None:
            lines += ["_Never offered a fix: the episode's remediation budget "
                      "was spent on the gaps above. Open and untouched, which "
                      "is not the same as unfixable._", ""]
            continue
        # Numbered by the order the kernel submits them, and the two probe
        # readings are named for which side of the re-attack they fall on. The
        # verdict is the difference between them; two steps both called
        # "control" would read as the same step done twice and hide what the
        # claim actually rests on.
        reattacked = False
        for turn in blocks.get(id(gap), []):
            rendered = f"`{turn.action.render()}`"
            if turn.phase == "remediate":
                lines.append(f"1. **fix** — {rendered} — {_turn_outcome(turn)}")
            elif REGISTRY.get(turn.action.verb_id).side is Side.RED:
                reattacked = True
                lines.append(f"3. **re-attack** — {rendered} — "
                             f"{_turn_outcome(turn)}")
            elif reattacked:
                lines.append(f"4. **control** — {rendered} — "
                             f"{_probe_answer(turn)}")
            else:
                lines.append(f"2. **baseline** — {rendered} — "
                             f"{_probe_answer(turn)}")
        lines += ["", f"**{fix.state}** — {fix.detail}", ""]
    return lines


def _transcript(episode: Episode, meta: CaptureMeta, decisions: list[dict]) -> str:
    phases = turns_by_phase(episode)
    agent_turns = phases["plan"]
    lines = [
        f"# Whetstone run — {meta.target}",
        "",
        "> A real run, captured verbatim. The observations are what the adapter",
        "> returned from the actual target; nothing here is illustrative.",
        "",
        "| | |",
        "|---|---|",
        f"| driver | {meta.driver} |",
        f"| checkpoint | `{meta.checkpoint}` |",
        f"| target | {meta.target} |",
        f"| telemetry | {meta.telemetry} |",
        f"| remediation | {meta.remediation} |",
        f"| captured | {meta.timestamp} |",
        "",
        f"**Task** — {episode.task}",
        "",
        # Split rather than totalled. The agent chose `plan` turns; the kernel
        # injected the other three as evidence, and one of them is the agent's
        # own exploit replayed. A single "24 turns" reads as twenty-four
        # decisions and there were nine.
        f"**Result** — {agent_turns} action(s) the agent chose, plus "
        f"{phases['detect']} detection probe(s), {phases['remediate']} fix(es) "
        f"and {phases['verify']} verification turn(s) injected by the kernel. "
        f"{episode.observations} observations, {episode.refusals} refusals, "
        f"**{len(episode.findings)} findings**.",
        "",
        "---",
        "",
        "## The run, turn by turn",
        "",
    ]

    decision_by_i = {d["turn"]: d for d in decisions}
    for i, turn in enumerate(episode.turns):
        verdict = ("REFUSED" if turn.refused else
                   "ok" if turn.succeeded else "failed")
        mark = _PHASE_MARK.get(turn.phase, f" · _{turn.phase}_")
        lines.append(f"### {i + 1}. `{turn.action.render()}` — {verdict}{mark}")

        d = decision_by_i.get(i)
        if d and d.get("alternatives"):
            alts = ", ".join(f"`{a}`" for a in d["alternatives"][:3])
            lines.append(f"*model chose this over: {alts}*")

        if turn.refused:
            lines += ["", "```", f"{turn.decision.rule}: {turn.decision.reason}",
                      "```", ""]
            continue

        if turn.observation is not None and turn.observation.data is not None:
            payload = shrink_payload(turn.observation.data)
            lines += ["", "```json",
                      json.dumps(payload, indent=2, ensure_ascii=False)[:900],
                      "```", ""]
        elif turn.observation is not None and turn.observation.unsupported:
            lines += ["", f"_unsupported: {turn.observation.error}_", ""]

    if episode.findings:
        lines += ["---", "", "## Findings", ""]
        for f in episode.findings:
            head = {"detection_gap": "🔴 DETECTION GAP",
                    "no_coverage": "⚪ NO COVERAGE",
                    "observation": "🟡 INCONCLUSIVE"}.get(f.kind, f.kind)
            lines.append(f"- **{head}** — `{f.technique}` — {f.detail}")
        lines.append("")

    lines += _remediation_section(episode)

    lines += ["---", "",
              "*Generated by `lab/capture.py`. "
              "Reproduce with the command in the run's header comment.*"]
    return "\n".join(lines) + "\n"


def capture(
    episode: Episode, meta: CaptureMeta, out_dir: Path, name: str,
    *, decisions: list[dict] | None = None,
) -> dict[str, Path]:
    """Write the three artifacts and return their paths.

    Every one goes out through :func:`_write_redacted`. Nothing in this module
    writes a file any other way, so there is no path by which a capture reaches
    ``examples/runs/`` carrying this machine's identity.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    decisions = decisions or []

    gaps = [f for f in episode.findings if f.kind == "detection_gap"]

    traj = out_dir / f"{name}.trajectory.txt"
    _write_redacted(traj, render_episode(episode))

    md = out_dir / f"{name}.transcript.md"
    _write_redacted(md, _transcript(episode, meta, decisions))

    findings = out_dir / f"{name}.findings.json"
    payload: dict[str, Any] = {
        "meta": {"checkpoint": meta.checkpoint, "target": meta.target,
                 "telemetry": meta.telemetry, "remediation": meta.remediation,
                 "captured": meta.timestamp, "driver": meta.driver,
                 "task": episode.task},
        "turns": len(episode.turns),
        # The agent's own turns, kept beside the total rather than replacing it.
        # `turns` is how long the episode is; `agent_turns` is how much of it
        # the agent decided, and any measurement of the agent wants the second.
        "agent_turns": turns_by_phase(episode)["plan"],
        "turns_by_phase": turns_by_phase(episode),
        "observations": episode.observations,
        "refusals": episode.refusals,
        # Counted by state, never summarised as "remediated". `Finding.to_dict`
        # emits the remediation on each gap that has one; this is the tally, and
        # `closed` is deliberately the only key a reader can add up to get
        # closure.
        "remediation_states": _state_counts(gaps),
        "findings": [f.to_dict() for f in episode.findings],
    }
    _write_redacted(
        findings,
        json.dumps(payload, indent=2, ensure_ascii=False),
        as_json=True)

    return {"trajectory": traj, "transcript": md, "findings": findings}


def _state_counts(gaps: Sequence[Finding]) -> dict[str, int]:
    """Gaps per remediation state, with the never-attempted ones named.

    ``not_attempted`` is spelled out rather than left as the difference between
    two totals, because the difference between two totals is a number somebody
    computes wrongly. It means the phase was off or the budget ran out — never
    "every fix failed", which is what ``failed`` and ``ineffective`` are for.
    """
    counts: dict[str, int] = {}
    for gap in gaps:
        key = "not_attempted" if gap.remediation is None else gap.remediation.state
        counts[key] = counts.get(key, 0) + 1
    return counts
