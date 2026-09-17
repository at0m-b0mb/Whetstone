"""The agent loop: decide, submit, observe, critique, retry — and check who saw.

This is the piece that turns a catalogue of verbs into an agent, and it is where
the project's central claim finally becomes executable rather than declared.

``detected_by`` has been enforced on every red verb since the first commit: a
red verb that names no detection raises at import. But nothing *ran* the
detection after the exploit, so the most valuable artefact Whetstone claims to
produce — "the technique worked and nothing noticed" — was never actually
produced by anything. :meth:`Kernel.run` produces it. After a red action
succeeds, its declared detections are run immediately and silence becomes a
:class:`Finding`.

Four properties are deliberate.

**The loop is model-agnostic.** It takes a :class:`Chooser` — anything that can
pick an action given the context so far. That may be the constrained decoder
over a trained checkpoint, a rule-based baseline, or a frontier model behind an
API. The runtime has claimed model-independence from the start and this keeps it
true; the kernel never imports a model.

**A refusal is an input, not an exception.** When the gate denies an action the
loop records the ruling, adds the verb to the exclusion set, and decides again
with the reason in context. That is the correction pattern, and it is the half of
agent behaviour that a success-only trajectory corpus can never teach.

**An episode *is* a trajectory.** :meth:`Episode.render` emits the wire protocol
directly, so a completed run is training data without a conversion step. That
closes the loop the project is built around: the agent works, the work is
recorded, the recording teaches the next model. Before this existed, trajectories
were scripted verb sequences — the model was learning to imitate a list someone
else wrote, which teaches format and cannot teach choosing.

**Unsupported is never retried.** An adapter returning ``unsupported=True`` is
stating a fact about the platform, not failing transiently. macOS has no
registry. Retrying is the cheapest way to burn a turn budget, and the
distinction only exists because :class:`~whetstone.actions.Observation` carries
it separately from ``ok``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Protocol, Sequence

from ..actions import NO_DETECTION, Action, Intent, Observation, Side, Verb
from ..gate import Decision, Gate, GateRefusal, Verdict

__all__ = [
    "Kernel", "Chooser", "HeuristicChooser", "Turn", "Episode", "Finding",
    "detection_fired",
]


# --------------------------------------------------------------------------
# did the blue side see it?
# --------------------------------------------------------------------------

def detection_fired(observation: Observation) -> bool | None:
    """Whether a ``detect.*`` observation indicates the control fired.

    Returns ``None`` for "cannot tell", which is not the same as "did not fire"
    and must never collapse into it. A detection verb that failed to run tells
    you nothing about the control; reporting that as a gap would manufacture a
    finding out of a broken query, and a report full of those is a report nobody
    trusts.

    The payload conventions are read tolerantly because the adapters were written
    independently and settled on slightly different shapes — ``logged`` on Linux,
    ``process_creation_auditing`` on macOS, hit counts elsewhere. Standardising
    them is worth doing; guessing in the meantime is not, hence the explicit
    ``None``.
    """
    if not observation.ok or observation.unsupported:
        return None
    data = observation.data
    if not isinstance(data, dict):
        return None

    for key in ("logged", "fired", "detected", "present"):
        if isinstance(data.get(key), bool):
            return data[key]
    for key in ("count", "hits", "matches", "events"):
        value = data.get(key)
        if isinstance(value, int):
            return value > 0
        if isinstance(value, list):
            return len(value) > 0
    # Telemetry-shaped payloads: a source list where nothing is enabled is a
    # legitimate "no".
    sources = data.get("sources")
    if isinstance(sources, list) and sources:
        enabled = [s for s in sources
                   if isinstance(s, dict) and s.get("enabled") is True]
        return bool(enabled)
    return None


@dataclass(frozen=True, slots=True)
class Finding:
    """Something worth telling the operator."""

    kind: str                     # "detection_gap" | "no_coverage" | "observation"
    technique: str
    expected: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "technique": self.technique,
                "expected": self.expected, "detail": self.detail}


@dataclass(frozen=True, slots=True)
class Turn:
    """One cycle of the loop."""

    action: Action
    decision: Decision
    observation: Observation | None = None

    @property
    def refused(self) -> bool:
        return self.decision.verdict is Verdict.DENY

    @property
    def succeeded(self) -> bool:
        return self.observation is not None and self.observation.ok


# --------------------------------------------------------------------------
# choosing
# --------------------------------------------------------------------------

class Chooser(Protocol):
    """Picks the next action. The only thing the kernel needs from a model."""

    def choose(
        self, task: str, history: Sequence[Turn], permitted: Sequence[Verb],
        *, exclude: Sequence[str], target: str | None,
    ) -> Action | None:
        """Return the next action, or None to stop."""
        ...


class HeuristicChooser:
    """A rule-based baseline: look before you touch, then check who saw.

    Exists for two reasons beyond convenience. It makes the kernel testable with
    no model and no MLX, so the loop's logic is covered in ordinary CI. And it is
    the number a trained model has to beat — if a checkpoint cannot outperform
    an ordering written in twenty lines, the training is not earning its cost.

    It must never become the thing the corpus is tuned toward. A model that
    learns to imitate this baseline has learned this baseline's blind spots, and
    the whole point of training is to find orderings a human did not think of.
    """

    #: Look first, assess second, act third, and always ask who noticed.
    PREFERENCE = ("enum.host", "enum.privileges", "enum.persistence",
                  "enum.services", "enum.network", "enum.processes",
                  "enum.users", "enum.software", "enum.shares",
                  "vuln.weak_permissions", "vuln.credential_exposure",
                  "vuln.patch_gap", "vuln.privilege_path",
                  "detect.telemetry")

    def choose(
        self, task: str, history: Sequence[Turn], permitted: Sequence[Verb],
        *, exclude: Sequence[str], target: str | None,
    ) -> Action | None:
        done = {t.action.verb_id for t in history} | set(exclude)
        by_id = {v.id: v for v in permitted}
        for verb_id in self.PREFERENCE:
            if verb_id in done or verb_id not in by_id:
                continue
            verb = by_id[verb_id]
            params = {p.name: (p.choices[0] if p.choices else p.default)
                      for p in verb.params
                      if p.required or p.default is not None}
            params = {k: v for k, v in params.items() if v is not None}
            from ..actions import TargetKind
            return verb.bind(params,
                             target=None if verb.target is TargetKind.NONE else target)
        return None


# --------------------------------------------------------------------------
# the episode
# --------------------------------------------------------------------------

@dataclass
class Episode:
    """A complete run, renderable as a trajectory."""

    task: str
    host: str
    scope: str
    catalogue: str
    turns: list[Turn] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def refusals(self) -> int:
        return sum(1 for t in self.turns if t.refused)

    @property
    def observations(self) -> int:
        return sum(1 for t in self.turns if t.succeeded)

    def render(self) -> str:
        """The wire protocol, so an episode is training data as it stands.

        Observations are capped here for the same reason the generator caps
        them: an untruncated ``enum.processes`` payload does not fit a 1024-token
        window, and a trajectory that is 90% one observation teaches that
        observations are noise.
        """
        from ..kernel.render import render_episode
        return render_episode(self)

    def summary(self) -> str:
        lines = [f"task: {self.task}",
                 f"{len(self.turns)} turn(s), {self.observations} observation(s), "
                 f"{self.refusals} refusal(s), {len(self.findings)} finding(s)"]
        for turn in self.turns:
            mark = ("DENY " if turn.refused else
                    "ok   " if turn.succeeded else "fail ")
            lines.append(f"  {mark} {turn.action.render()[:66]}")
            if turn.refused:
                lines.append(f"         {turn.decision.rule}: "
                             f"{turn.decision.reason[:60]}")
        for finding in self.findings:
            lines.append(f"  FINDING [{finding.kind}] {finding.technique} — "
                         f"{finding.detail[:60]}")
        return "\n".join(lines)


# --------------------------------------------------------------------------
# the loop
# --------------------------------------------------------------------------

class Kernel:
    """Runs an episode: decide, submit, observe, critique, retry."""

    def __init__(
        self,
        gate: Gate,
        executor: Any,
        chooser: Chooser | None = None,
        *,
        max_turns: int = 12,
        pair_detections: bool = True,
    ) -> None:
        self.gate = gate
        self.executor = executor
        self.chooser = chooser or HeuristicChooser()
        self.max_turns = max_turns
        self.pair_detections = pair_detections

    # ------------------------------------------------------------------ run

    def run(self, task: str, *, target: str | None = "127.0.0.1",
            host: str = "") -> Episode:
        permitted = list(self.gate.catalogue())
        catalogue = "; ".join(
            f"{v.id}({', '.join(p.name for p in v.params)})" for v in permitted
        )[:400]
        episode = Episode(
            task=task,
            host=host or getattr(self.executor, "platform", "unknown"),
            scope=self._scope_line(),
            catalogue=catalogue,
        )

        exclude: list[str] = []
        while len(episode.turns) < self.max_turns:
            action = self.chooser.choose(
                task, episode.turns, permitted, exclude=exclude, target=target)
            if action is None:
                break

            turn = self._submit(action)
            episode.turns.append(turn)

            # Critique. A refusal or an impossibility both mean "do not try this
            # again", but for different reasons and with different lessons.
            if turn.refused or (turn.observation and turn.observation.unsupported):
                exclude.append(action.verb_id)
                continue

            if turn.succeeded and self.pair_detections:
                self._check_detections(episode, action, target)

        return episode

    # ------------------------------------------------------------- internals

    def _scope_line(self) -> str:
        auth = self.gate.engagement.authorize
        bits = [auth.max_intent.value]
        if auth.red_team:
            bits.append("red:" + " ".join(auth.techniques))
        else:
            bits.append("no red verbs")
        if self.gate.engagement.scope.allow_loopback:
            bits.append("loopback only")
        return "; ".join(bits)

    def _submit(self, action: Action) -> Turn:
        """One gated submission, with a refusal captured rather than raised."""
        try:
            result = self.gate.submit(action, self.executor.execute)
        except GateRefusal as refusal:
            return Turn(action=action, decision=refusal.decision)
        return Turn(action=action, decision=result.decision,
                    observation=result.observation)

    def _check_detections(
        self, episode: Episode, action: Action, target: str | None
    ) -> None:
        """Run the detections a red verb declared, and record silence as a gap.

        The whole reason the red half of this catalogue exists. An exploit proves
        a hole; this proves nobody would have known, and defenders act on the
        second far faster than the first.
        """
        verb = self.gate.registry.get(action.verb_id)
        if verb.side is not Side.RED:
            return

        technique = ", ".join(verb.attck) or verb.id

        for expected in verb.detected_by:
            if expected == NO_DETECTION:
                # Declared honestly at the verb: nothing in this catalogue covers
                # the technique. Recorded as its own kind, because "we did not
                # look" and "we looked and saw nothing" are different claims and
                # conflating them is how a report overstates coverage.
                episode.findings.append(Finding(
                    kind="no_coverage", technique=technique, expected=NO_DETECTION,
                    detail=(f"{verb.id} ran and no control in this catalogue "
                            "covers the technique, so silence proves nothing"),
                ))
                continue

            probe = self.gate.registry.get(expected)
            params = {p.name: p.default for p in probe.params
                      if p.default is not None}
            from ..actions import TargetKind
            probe_action = probe.bind(
                params,
                target=None if probe.target is TargetKind.NONE else target)
            turn = self._submit(probe_action)
            episode.turns.append(turn)

            fired = detection_fired(turn.observation) if turn.observation else None
            if fired is True:
                continue
            if fired is None:
                episode.findings.append(Finding(
                    kind="observation", technique=technique, expected=expected,
                    detail=(f"{expected} could not establish whether it fired; "
                            "this is not evidence of a gap"),
                ))
                continue
            episode.findings.append(Finding(
                kind="detection_gap", technique=technique, expected=expected,
                detail=(f"{verb.id} ran and {expected} did not fire — the "
                        "technique succeeded unobserved"),
            ))
