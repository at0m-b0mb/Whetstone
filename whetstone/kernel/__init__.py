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

A fifth property is the one the findings are only as good as. **Both ends of a
detection verdict have to be earned.** "Nothing fired" is the artefact, so a
probe that could not run must not produce it, and a probe that was never aimed
at the technique must not retract it either — "was anything logged in the last
five minutes" is a different question from "was this logged", and answering the
first suppresses exactly the gaps the tool exists to find. The three finding
kinds stay distinct for the same reason: ``detection_gap`` is a claim about the
control, ``no_coverage`` a claim about the catalogue, and ``observation`` the
honest "cannot tell" that neither of the others is allowed to absorb.
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

#: The one ``detect.*`` parameter that narrows *when* rather than *what*. Every
#: other parameter a detection verb declares exists to aim it at a particular
#: technique, which is what makes the distinction below computable from the
#: schema instead of from a hand-maintained list.
_WINDOW_PARAM = "since_seconds"

#: Parameter types whose values can be lifted out of a red observation without
#: any conversion. Restricted to these so that a value taken from an adapter
#: payload can never make :meth:`Verb.bind` raise mid-episode: ``Param.validate``
#: accepts any non-blank string for all three, so the aim either lands or is
#: skipped, and never crashes the loop.
_TEXT_PARAM_TYPES = frozenset({"string", "path", "host"})


def _source_unqueryable(data: dict[str, Any]) -> bool:
    """Whether the payload states that the log behind it could not be read.

    These fields are *provenance*, not a verdict. An adapter that could not open
    the audit log, or that found the source switched off, still has to return
    something, and all three production adapters return a falsey verdict beside
    a marker saying why — ``source: "none"`` plus a ``gap`` note on Linux when
    ``ausearch`` is absent, ``enabled: false`` on Windows when process-creation
    auditing is off, ``telemetry_available: false`` on macOS where keychain
    reads are not audited at all. Read as a verdict, every one of those is
    "the control stayed silent", which is a detection gap invented out of a
    query that never ran.

    ``reason`` is deliberately absent from this set even though Linux happens to
    attach it to the same payloads. It is a generic explanation field, and an
    adapter is just as likely to use it for "no matching events" — a genuine
    negative. Treating that as provenance would suppress a real gap, which is
    the same failure pointing the other way, and the two markers that matter on
    Linux already carry ``source: "none"``.
    """
    if data.get("source") == "none":
        return True
    if data.get("gap"):
        return True
    for key in ("enabled", "telemetry_available"):
        if data.get(key) is False:
            return True
    return False


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

    ``ok`` and ``unsupported`` are not enough of a guard on their own, because
    the adapters report "I could not query the log" as a *successful* call with
    a falsey verdict rather than as a failure. So a falsey verdict is checked
    against :func:`_source_unqueryable` before it is believed.

    That check is asymmetric on purpose, and the asymmetry is the whole point: a
    disabled or unreadable source makes *absence* meaningless, not presence. On
    Windows, Sysmon can record a process creation while Security/4688 auditing
    is off, so the payload carries ``enabled: false`` alongside a real hit;
    discarding that hit would hide a control that genuinely fired.
    """
    if not observation.ok or observation.unsupported:
        return None
    data = observation.data
    if not isinstance(data, dict):
        return None

    verdict = _read_verdict(data)
    if verdict is False and _source_unqueryable(data):
        return None
    return verdict


def _read_verdict(data: dict[str, Any]) -> bool | None:
    """The bare reading of a detection payload, before provenance is weighed."""
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


def _inconclusive(technique: str, expected: str, why: str = "") -> Finding:
    """The "cannot tell" finding, phrased the one way it is ever phrased.

    There is more than one route to it — the probe failed to run, the log it
    reads was not queryable, the hit it found could not be attributed — and each
    route contributes its own ``why``. The opening and closing clauses are
    written once here because they are the claim itself, and a claim readers
    (and the corpus tests that grep for it) have to recognise in two phrasings is
    a claim that will eventually drift into meaning two different things.
    """
    return Finding(
        kind="observation", technique=technique, expected=expected,
        detail=(f"{expected} could not establish whether it fired{why}; "
                "this is not evidence of a gap"),
    )


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
    """Picks the next action. The only thing the kernel needs from a model.

    Receives the whole :class:`Episode` so far, not just the history list,
    because a model chooser needs the task, the host, the scope and the
    catalogue to reconstruct the exact prompt prefix it was trained on — and
    those live on the episode. A rule-based chooser is free to ignore all but
    ``episode.turns``.
    """

    def choose(
        self, episode: "Episode", permitted: Sequence[Verb],
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
        self, episode: "Episode", permitted: Sequence[Verb],
        *, exclude: Sequence[str], target: str | None,
    ) -> Action | None:
        done = {t.action.verb_id for t in episode.turns} | set(exclude)
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
        # What the engagement allows, intersected with what this executor can
        # actually carry out. Offering a verb the adapter does not implement
        # wastes a turn on a guaranteed "unsupported", and — worse for a model
        # chooser — puts a choice in front of the model that can only fail. An
        # executor that does not report its coverage (a bare stub in a test) is
        # trusted to run anything, which keeps the old behaviour for callers
        # that never had adapter-aware filtering.
        permitted = list(self.gate.catalogue())
        implemented = getattr(self.executor, "implemented", None)
        if callable(implemented):
            runnable = set(implemented())
            permitted = [v for v in permitted if v.id in runnable]
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
                episode, permitted, exclude=exclude, target=target)
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
                self._check_detections(episode, turn, target)

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

    @staticmethod
    def _aim(probe: Verb, evidence: Observation | None) -> dict[str, Any]:
        """Discriminator values for ``probe``, lifted from the red observation.

        A red handler is the only thing in the system that knows what it just
        touched — the ExecStart binary it overwrote, the task name it created —
        and a probe aimed at that is asking about the technique instead of about
        the host's background noise. The convention is an exact name match: a
        handler that wants ``detect.process_creation`` aimed returns the process
        under the key ``image``, which is what that verb calls its own parameter.

        An exact match is used rather than anything cleverer because a *wrong*
        discriminator is worse than none at all. A probe aimed at an image the
        log never recorded comes back empty, and an empty correlated probe reads
        as a detection gap — so a guess at the right key name would manufacture
        exactly the finding this method exists to make trustworthy. Nothing is
        inferred from the verb id, the parameters or the payload's shape.
        """
        if evidence is None or not isinstance(evidence.data, dict):
            return {}
        aimed: dict[str, Any] = {}
        for p in probe.params:
            if p.name == _WINDOW_PARAM or p.type not in _TEXT_PARAM_TYPES:
                continue
            value = evidence.data.get(p.name)
            if isinstance(value, str) and value.strip():
                aimed[p.name] = value
        return aimed

    def _check_detections(
        self, episode: Episode, red: Turn, target: str | None
    ) -> None:
        """Run the detections a red verb declared, and record silence as a gap.

        The whole reason the red half of this catalogue exists. An exploit proves
        a hole; this proves nobody would have known, and defenders act on the
        second far faster than the first.

        Takes the whole red :class:`Turn` rather than just its action because the
        observation is what aims the probe — see :meth:`_aim`.
        """
        action = red.action
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
            params.update(self._aim(probe, red.observation))
            # Which of the probe's discriminators went unfilled. Bound before
            # the probe runs, because it decides what its answer is worth: a
            # probe with nothing to match on asks a broader question than the
            # one that was put to it, and the two possible answers are worth
            # very different amounts (see below).
            unaimed = [p.name for p in probe.params
                       if p.name != _WINDOW_PARAM and p.name not in params]

            from ..actions import TargetKind
            probe_action = probe.bind(
                params,
                target=None if probe.target is TargetKind.NONE else target)
            turn = self._submit(probe_action)
            episode.turns.append(turn)

            fired = detection_fired(turn.observation) if turn.observation else None
            if fired is True and unaimed:
                # An unaimed probe counts everything of its kind in the window,
                # including the agent's own earlier turns and whatever else the
                # host was doing. `detect.process_creation` with no `image` asks
                # "was anything logged", not "was THIS logged", and reading that
                # as the verdict on the red action silently suppresses a real
                # gap — a purple tool that reports no gaps on exactly the hosts
                # that have telemetry.
                #
                # Silence from the same probe still counts, and the asymmetry is
                # not a fudge: nothing of this kind was logged in a window that
                # contained the technique, so the technique was not logged. Only
                # the positive is ambiguous.
                episode.findings.append(_inconclusive(
                    technique, expected,
                    why=(": it found activity in the window but had no "
                         f"{', '.join(unaimed)} to match against, so the hit "
                         "may be unrelated to the technique"),
                ))
                continue
            if fired is True:
                continue
            if fired is None:
                episode.findings.append(_inconclusive(technique, expected))
                continue
            episode.findings.append(Finding(
                kind="detection_gap", technique=technique, expected=expected,
                detail=(f"{verb.id} ran and {expected} did not fire — the "
                        "technique succeeded unobserved"),
            ))
