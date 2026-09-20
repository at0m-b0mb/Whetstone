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

A sixth property closes the loop rather than describing it. **A fix is a claim;
a re-attack is evidence.** :meth:`Kernel.remediate_gaps` gives the agent a
chance to propose a hardening measure for each detection gap, and then — this is
the part that makes it worth anything — runs the original red action again and
runs its detection again. A ``harden.*`` verb that returns ``ok=True`` has said
only that a command succeeded. Every report this project keeps finding fault
with says "fixed" on that basis. Closure here means the technique was performed
a second time and the control that was silent spoke, and nothing weaker is
allowed to spell it "closed": see :class:`Remediation`.

That phase is **off by default**. Every other action the kernel injects on its
own initiative is an ``OBSERVE``; remediation is a ``MODIFY`` and the re-attack
is a second real execution of an exploit. A loop that hardens a machine nobody
asked it to harden — and attacks it again to check — is the mirror image of the
thing the gate exists to prevent, and "the engagement would have refused it" is
a weaker guarantee than not proposing it. The caller says ``remediate=True``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from typing import Any, Mapping, Protocol, Sequence

from ..actions import (
    NO_DETECTION, Action, Intent, Observation, SchemaError, Side, Verb,
)
from ..gate import Decision, Gate, GateRefusal, Verdict

__all__ = [
    "Kernel", "Chooser", "HeuristicChooser", "Turn", "Episode", "Finding",
    "Remediation", "REMEDIATION_STATES", "detection_fired",
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


#: Every state :class:`Remediation` may carry. Frozen into a set so a typo in a
#: consumer is a lookup that fails rather than a branch that silently never
#: matches — the same reason the finding kinds are compared against literals
#: everywhere and never derived.
REMEDIATION_STATES = frozenset({
    "closed", "ineffective", "undetermined", "failed", "refused", "unavailable",
})


@dataclass(frozen=True, slots=True)
class Remediation:
    """What was done about a detection gap, and — separately — what that proved.

    Six states, and they are six rather than two for the reason the finding
    kinds are three rather than two. "We ran a fix" and "the hole is shut" are
    different claims, and every report that has ever overstated its remediation
    did it by letting the first one print as the second.

    ``closed``
        A hardening measure ran, the original red action was performed **again**,
        its declared detection was run again, and that detection fired and could
        be attributed to the re-attack. This is the only state that means the
        gap is shut, and it is the only one backed by evidence rather than by a
        command's exit status.

    ``ineffective``
        The fix ran, the technique still succeeded, and the control was still
        established to be silent. The remediation did not work. Worth as much as
        ``closed`` and much more embarrassing, which is exactly why it gets its
        own word instead of being rolled into "attempted".

    ``undetermined``
        The fix ran but closure could not be established: the control was
        already reporting activity of this kind *before* the re-attack (so a hit
        after it proves nothing), the re-attack no longer succeeds (so the
        control was never given anything to see), the re-attack was refused, or
        the second detection could not tell. **Never closure.** A technique that
        stops working is a real and good outcome — it is simply not evidence
        about the control, and the gap was a statement about the control. The
        detail says which route was taken.

    ``failed``
        The hardening verb itself did not run: it returned ``ok=False``, or the
        adapter does not implement it. No fix was applied, so there is nothing
        to verify. Kept apart from ``undetermined`` because one is a broken fix
        and the other is a fix whose effect is unknown.

    ``refused``
        The gate denied the hardening action. Remediation is ``MODIFY`` and is
        ruled on like anything else; being defensive earns it nothing. This is
        an authorisation fact an operator can act on by amending the engagement,
        not a measurement, so it does not hide inside ``undetermined``.

    ``unavailable``
        Nothing was proposed. Either no verb in the permitted catalogue declares
        that it remediates the red verb that produced this gap, or the one that
        does could not be aimed from the evidence. The blue-side twin of
        ``no_coverage``: the catalogue has no answer, and saying so is more
        useful than a fix pointed at a guess.

    A gap with no ``Remediation`` at all (the field is ``None``) was never
    offered one — the phase was off, or the episode ran out of its budget.
    """

    state: str
    #: The hardening verb that was proposed, if one was. Empty for
    #: ``unavailable`` when nothing claimed the gap.
    verb: str = ""
    #: Prose for the operator, naming the route taken to this state. Read it;
    #: the state alone deliberately does not distinguish "the technique now
    #: fails" from "the second probe broke", and both land on ``undetermined``.
    detail: str = ""

    def __post_init__(self) -> None:
        if self.state not in REMEDIATION_STATES:
            raise ValueError(
                f"unknown remediation state {self.state!r}; expected one of "
                f"{sorted(REMEDIATION_STATES)}")

    @property
    def proven_closed(self) -> bool:
        """The one question a report is allowed to ask without reading ``detail``."""
        return self.state == "closed"

    def to_dict(self) -> dict[str, Any]:
        return {"state": self.state, "verb": self.verb, "detail": self.detail}


@dataclass(frozen=True, slots=True)
class Finding:
    """Something worth telling the operator."""

    kind: str                     # "detection_gap" | "no_coverage" | "observation"
    technique: str
    expected: str
    detail: str
    #: The red verb whose run produced this finding. Carried as a field rather
    #: than left inside ``detail`` because the remediation phase matches a fix
    #: to a gap on this id: a harden verb declares the red verbs it closes, and
    #: the two meet on a string, never on being adjacent in a list.
    produced_by: str = ""
    #: What was done about it, for a ``detection_gap``. ``None`` means nothing
    #: was attempted — never "nothing worked".
    #:
    #: Recorded *on the gap* rather than as a fourth finding kind on purpose.
    #: The gap is a historical fact: the technique ran and nothing saw it, and
    #: that stays true and stays in the report whatever happened afterwards. A
    #: separate finding would either duplicate the event, so that anything
    #: counting gaps counts it twice, or replace it, erasing what the exercise
    #: actually produced. One record per event, with what is now known about it
    #: attached, keeps both the count and the history honest.
    remediation: Remediation | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"kind": self.kind, "technique": self.technique,
                             "expected": self.expected, "detail": self.detail,
                             "produced_by": self.produced_by}
        # Present only when something was attempted. A key that is sometimes
        # absent is cheaper for a 14.6M model than one that is usually null, and
        # "the field is missing" already means "not attempted" everywhere else.
        if self.remediation is not None:
            d["remediation"] = self.remediation.to_dict()
        return d


def _inconclusive(technique: str, expected: str, produced_by: str = "",
                  why: str = "") -> Finding:
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
        produced_by=produced_by,
        detail=(f"{expected} could not establish whether it fired{why}; "
                "this is not evidence of a gap"),
    )


#: What put a turn in the episode. Only ``"plan"`` is the agent's own choosing;
#: the rest are injected by the kernel as evidence, and anything measuring agent
#: behaviour — how many exploits it ran, how early, in what order — has to
#: exclude them or it is measuring the kernel. That is not hypothetical: before
#: the phase existed, three re-attacks would have read as three more exploits
#: the agent chose to run.
TURN_PHASES = frozenset({"plan", "detect", "remediate", "verify"})


@dataclass(frozen=True, slots=True)
class Turn:
    """One cycle of the loop."""

    action: Action
    decision: Decision
    observation: Observation | None = None
    #: ``"plan"`` — the chooser picked it. ``"detect"`` — a probe the kernel
    #: paired with a red action. ``"remediate"`` — a hardening measure.
    #: ``"verify"`` — the re-attack, or the second probe that judges it.
    phase: str = "plan"

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

    # A chooser MAY also implement::
    #
    #     def remediate(self, episode, finding, *, candidates, target) -> Action | None
    #
    # to pick the hardening measure for a detection gap. It is looked up with
    # ``getattr`` rather than declared here because the protocol is duck-typed
    # and every chooser written before the remediation phase existed — the
    # heuristic baseline, the lab sweep, the constrained decoder — satisfies
    # ``Chooser`` without it. Making it mandatory would break all three to buy
    # a type check the runtime does not perform.
    #
    # Defending is a thing the model should learn to do, so the chooser is asked
    # first. When it declines, or has no such method, the kernel falls back to a
    # deterministic proposer, which is what keeps the whole loop demonstrable
    # with no model and no MLX. ``candidates`` is pre-filtered to verbs that
    # declare they remediate the red verb behind this gap, so a chooser cannot
    # widen the association by choosing badly; one that returns a verb outside
    # the set has its proposal recorded and dropped.


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
            fix = finding.remediation
            if fix is not None:
                lines.append(f"     FIX [{fix.state}] "
                             f"{fix.verb or 'nothing proposed'} — "
                             f"{fix.detail[:56]}")
        return "\n".join(lines)


# --------------------------------------------------------------------------
# the loop
# --------------------------------------------------------------------------

#: The observation payload key through which a handler says what would fix what
#: it just reported. ``{"remediation": {"harden.fix_permissions": {"path": ...}}}``
#: — keyed by the exact verb id, then by that verb's own parameter names.
#:
#: Namespaced rather than lifted from the payload's top level, which is how the
#: detection probes are aimed. The two cases differ in one way that decides it:
#: a probe's parameters (``image``, ``rule``) are named after the thing being
#: matched and a collision is unlikely, whereas ``source`` means a config file
#: to one adapter payload and a log stream to ``harden.enable_telemetry``. An
#: exact-name lift would point a MODIFY at the wrong object with the gate's
#: blessing, because the wrong object is in scope too.
#:
#: The content is written by the target, which in an engagement is adversarial
#: by definition. It is a suggestion and nothing more: the verb it can name is
#: restricted to the ones that declare they remediate this gap, unknown
#: parameter names are dropped, and whatever survives is ruled on by the gate
#: like any other action.
_REMEDIATION_KEY = "remediation"


def _remediation_hints(observation: Observation | None) -> dict[str, dict[str, Any]]:
    """Read the remediation hints out of an observation, tolerating anything.

    Every shape that is not the documented one yields ``{}``. A handler that
    publishes nothing, a payload that is a list, a hint whose value is a string
    — none of them is an error worth raising, because the fallback is a fix that
    cannot be aimed and is honestly reported as such, and a malformed hint must
    not be the thing that takes down an episode after the attacking is done.
    """
    if observation is None or not isinstance(observation.data, dict):
        return {}
    raw = observation.data.get(_REMEDIATION_KEY)
    if not isinstance(raw, Mapping):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for verb_id, params in raw.items():
        if isinstance(verb_id, str) and isinstance(params, Mapping):
            out[verb_id] = {k: v for k, v in params.items() if isinstance(k, str)}
    return out


@dataclass(frozen=True, slots=True)
class _OpenGap:
    """A gap the loop produced, with everything needed to try to close it.

    Internal to one :meth:`Kernel.run`. It holds both sides of the evidence
    because both are needed later and neither is recoverable from the finding:
    the red :class:`Turn` supplies the exact action to repeat and what it
    touched, and the probe :class:`Turn` supplies what the blind control said
    about its own blindness. ``index`` is where the finding sits in
    ``episode.findings``, so the outcome can be attached to the record that
    already exists instead of appending a second one about the same event.
    """

    index: int
    red: Turn
    probe: Turn
    expected: str


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
        remediate: bool = False,
        max_remediations: int = 8,
    ) -> None:
        self.gate = gate
        self.executor = executor
        self.chooser = chooser or HeuristicChooser()
        self.max_turns = max_turns
        self.pair_detections = pair_detections
        #: Offer a fix for each detection gap and verify it by re-attacking.
        #: Off by default: it is the only phase that changes the target on the
        #: kernel's own initiative, and verifying it means running the exploit
        #: a second time. See the module docstring.
        self.remediate = remediate
        #: How many gaps one episode will try to close. Each costs four gated
        #: actions — the fix, a silent reading of the control, the re-attack
        #: and the control again — so an episode
        #: that produced twenty gaps would otherwise triple its own length
        #: after the chooser had already stopped. Gaps past the budget keep
        #: ``remediation=None``, which reads as "never offered one".
        self.max_remediations = max_remediations

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
        #: Gaps this episode produced, paired with the evidence that produced
        #: them, in the order they happened. Built here rather than recovered
        #: from ``episode.findings`` afterwards because a finding does not carry
        #: the red *action* — only the verb id — and the re-attack has to repeat
        #: the exact parameters, not a fresh guess at them.
        gaps: list[_OpenGap] = []

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
                self._check_detections(episode, turn, target, gaps)

        if self.remediate and gaps:
            self.remediate_gaps(episode, gaps, permitted, target)

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

    def _submit(self, action: Action, *, phase: str = "plan") -> Turn:
        """One gated submission, with a refusal captured rather than raised.

        ``phase`` is recorded on the turn rather than inferred from the verb's
        group afterwards, because the same verb appears in two phases: the
        re-attack repeats the agent's own exploit, and only this call knows
        which of the two it is.
        """
        try:
            result = self.gate.submit(action, self.executor.execute)
        except GateRefusal as refusal:
            return Turn(action=action, decision=refusal.decision, phase=phase)
        return Turn(action=action, decision=result.decision,
                    observation=result.observation, phase=phase)

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

    def _probe(
        self, episode: Episode, expected: str, red: Turn, target: str | None,
        *, phase: str,
    ) -> tuple[Turn, bool | None, list[str]]:
        """Run one detection verb against one red turn and read its answer.

        Shared by the pairing and by the re-check after a fix, because the two
        have to ask the identical question — same parameters, same aim, same
        reading of the payload — or "the control was silent" and "the control
        fired" would be answers to different questions and the comparison
        between them would mean nothing. Written once for the same reason the
        prompt renderer is written once.

        Returns the turn, what :func:`detection_fired` made of it, and which of
        the probe's discriminators went unfilled — the last one bound *before*
        the probe runs, because it decides what the answer is worth.
        """
        probe = self.gate.registry.get(expected)
        params = {p.name: p.default for p in probe.params
                  if p.default is not None}
        params.update(self._aim(probe, red.observation))
        unaimed = [p.name for p in probe.params
                   if p.name != _WINDOW_PARAM and p.name not in params]

        from ..actions import TargetKind
        probe_action = probe.bind(
            params, target=None if probe.target is TargetKind.NONE else target)
        turn = self._submit(probe_action, phase=phase)
        episode.turns.append(turn)

        fired = detection_fired(turn.observation) if turn.observation else None
        return turn, fired, unaimed

    def _check_detections(
        self, episode: Episode, red: Turn, target: str | None,
        gaps: list[_OpenGap] | None = None,
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
                    produced_by=verb.id,
                    detail=(f"{verb.id} ran and no control in this catalogue "
                            "covers the technique, so silence proves nothing"),
                ))
                continue

            turn, fired, unaimed = self._probe(
                episode, expected, red, target, phase="detect")
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
                    technique, expected, verb.id,
                    why=(": it found activity in the window but had no "
                         f"{', '.join(unaimed)} to match against, so the hit "
                         "may be unrelated to the technique"),
                ))
                continue
            if fired is True:
                continue
            if fired is None:
                episode.findings.append(_inconclusive(
                    technique, expected, verb.id))
                continue
            episode.findings.append(Finding(
                kind="detection_gap", technique=technique, expected=expected,
                produced_by=verb.id,
                detail=(f"{verb.id} ran and {expected} did not fire — the "
                        "technique succeeded unobserved"),
            ))
            if gaps is not None:
                gaps.append(_OpenGap(index=len(episode.findings) - 1, red=red,
                                     probe=turn, expected=expected))

    # ---------------------------------------------------------- remediation

    def remediate_gaps(
        self, episode: Episode, gaps: Sequence[_OpenGap],
        permitted: Sequence[Verb], target: str | None,
    ) -> None:
        """Offer a fix for each detection gap, then prove or disprove it.

        The half of purple teaming that this project declared and never ran.
        Three ``harden.*`` verbs have been in the catalogue since the first
        commit, implemented on Linux, macOS and Windows, and nothing had ever
        called one: the loop found a gap and stopped, which is the report and
        not the fix.

        Each gap gets at most four gated actions — the hardening measure, the
        same detection read once to establish silence, the original red action
        performed again, and that detection asked the same question a second
        time. Closure is the difference between the two readings. The outcome is attached to the finding that
        already exists rather than appended as a new one, so a report counting
        gaps counts the same number before and after.

        Two things are deliberately *not* done here. Nothing is retried: a fix
        that failed gets one attempt, because a second identical MODIFY against
        a machine is a change nobody asked for twice. And a gap whose fix was
        refused does not fall back to another candidate — the gate said no to
        remediation under this engagement, and hunting for a verb it will say
        yes to is how an authorisation model becomes advisory.
        """
        # How many fixes this episode has already applied, which is carried
        # into the next gap because it changes what its verification can claim.
        # See `_close_gap`: gaps are closed one at a time against a host that
        # earlier fixes have already altered, and a second `closed` is a weaker
        # statement than the first.
        applied = 0
        for gap in list(gaps)[: self.max_remediations]:
            finding = episode.findings[gap.index]
            outcome = self._close_gap(episode, finding, gap, permitted, target,
                                      applied_before=applied)
            if outcome.state not in ("unavailable", "refused"):
                applied += 1
            episode.findings[gap.index] = replace(finding, remediation=outcome)

    @staticmethod
    def _fix_candidates(
        red_verb_id: str, permitted: Sequence[Verb]
    ) -> tuple[Verb, ...]:
        """The hardening measures that *declare* they close this red verb.

        The association is a declared id on both sides and nothing else. Not the
        verb's group, not its parameter names, not which fix happens to be next
        in the catalogue — the detection side already shipped a correlation bug
        built out of exactly that kind of proximity, where a probe with nothing
        to match on answered a broader question than the one that was put to it
        and its answer was read as the verdict. A fix credited to the wrong gap
        would be the same defect with worse consequences, because it would end
        with a hole reported shut.

        ``permitted`` is the engagement's catalogue already intersected with
        what this executor implements, so a verb the adapter cannot carry out is
        never proposed and a verb the engagement will not allow above OBSERVE is
        never even considered.
        """
        return tuple(sorted(
            (v for v in permitted
             if v.side is Side.BLUE and v.intent is not Intent.OBSERVE
             and red_verb_id in v.remediates),
            key=lambda v: v.id))

    def _close_gap(
        self, episode: Episode, finding: Finding, gap: _OpenGap,
        permitted: Sequence[Verb], target: str | None,
        *, applied_before: int = 0,
    ) -> Remediation:
        """One gap: propose, apply, re-attack, re-detect. See :class:`Remediation`.

        ``applied_before`` is how many fixes this episode already applied, and it
        exists because of a confound the lab made visible the first time this ran
        against three gaps at once. Gap one is fixed by switching a log source
        on; gap three is fixed by deleting a persistence entry — and gap three's
        re-attack is then seen, because the *log* is on. "The gap is shut" is
        still true and still proven by the second attack. "This fix shut it" is
        not, and the kernel cannot tell the two apart without reverting the host
        between gaps, which is possible in a sandbox and not on a machine.

        So the claim is narrowed in words rather than guessed at. The state stays
        ``closed`` — the question a gap asks is whether the control sees the
        technique, and it demonstrably now does — and the detail says the host
        carries earlier changes, so closure is not attributable to this fix
        alone. An operator reading it knows to keep both fixes.
        """
        candidates = self._fix_candidates(finding.produced_by, permitted)
        if not candidates:
            return Remediation(
                "unavailable",
                detail=(f"nothing in the permitted catalogue declares that it "
                        f"remediates {finding.produced_by or 'this technique'}, "
                        "so no fix was attempted"))

        action = None
        propose = getattr(self.chooser, "remediate", None)
        if callable(propose):
            action = propose(episode, finding, candidates=candidates,
                             target=target)
        if action is not None and action.verb_id not in {v.id for v in candidates}:
            # Recorded, not silently swapped for the default. A chooser that
            # answers a gap with an unrelated fix has made precisely the
            # association error this phase is built to avoid, and substituting
            # the right verb behind its back would keep that mistake out of the
            # trajectory that is supposed to teach it not to make it.
            return Remediation(
                "unavailable", verb=action.verb_id,
                detail=(f"the chooser proposed {action.verb_id}, which does not "
                        f"declare that it remediates {finding.produced_by}; a "
                        "fix is matched to a gap by declaration, never by "
                        "plausibility"))
        if action is None:
            action = self._default_fix(gap, candidates, target)
        if action is None:
            return Remediation(
                "unavailable",
                verb=", ".join(v.id for v in candidates),
                detail=("a fix for this technique exists in the catalogue but "
                        "the evidence did not say where to point it: no "
                        "observation published a remediation hint naming its "
                        "required parameters, and guessing one would aim a "
                        "MODIFY at something nobody identified"))

        # Re-bind through the registry so a malformed proposal fails here,
        # loudly and in one place, rather than as a KeyError inside an adapter
        # three frames down. This is what `VerbRegistry.parse` does to model
        # output, for the same reason.
        try:
            action = self.gate.registry.get(action.verb_id).bind(
                dict(action.params), target=action.target)
        except SchemaError as exc:
            return Remediation(
                "unavailable", verb=action.verb_id,
                detail=f"the proposed fix does not satisfy its own schema: {exc}")

        turn = self._submit(action, phase="remediate")
        episode.turns.append(turn)

        if turn.refused:
            # Remediation is MODIFY and is ruled on like any other MODIFY. Being
            # defensive buys it nothing, which is the point: a hole in the
            # authorisation model shaped like good intentions is still a hole.
            return Remediation(
                "refused", verb=action.verb_id,
                detail=(f"the gate refused the fix ({turn.decision.rule}): "
                        f"{turn.decision.reason[:160]}"))
        if not turn.succeeded:
            why = (turn.observation.error[:160] if turn.observation
                   else "no observation came back")
            return Remediation(
                "failed", verb=action.verb_id,
                detail=f"the fix did not run, so there is nothing to verify: {why}")

        # Everything above this line is a CLAIM. `ok=True` from a harden verb
        # means a command exited zero; it is the sentence every report that
        # overstated its remediation was built on. What follows is the evidence.

        # First, establish the control is silent *now* — after the fix and
        # before the re-attack. The gap's original probe is not good enough for
        # that, because two things have happened since: the fix ran, and, if
        # this is not the first gap, other gaps' re-attacks ran. Both land
        # inside the probe's own lookback window.
        #
        # Without this, closure is an absolute reading ("the log has a row of
        # this kind") rather than a differential one ("the re-attack put a row
        # there"), and an absolute reading closes a gap on somebody else's
        # evidence. That is not hypothetical and `unaimed` does not catch it:
        # `detect.persistence_change` declares no discriminator parameter at
        # all, so `unaimed` is empty for it by construction, and it is the
        # declared detection for BOTH `exploit.scheduled_task` and
        # `postex.persistence_install`. Fix the first gap, re-attack, and the
        # second gap's probe finds the first gap's row and reports a technique
        # that was never logged as one the control now sees — a hole reported
        # shut, which this project ranks as the worst output it can produce.
        #
        # It also catches the fix manufacturing its own proof. A hardening verb
        # that emits an event of the kind the control reads would otherwise be
        # indistinguishable from the technique being caught; the lab's harden
        # handlers are written not to, and a real adapter has no such promise.
        #
        # The cost is one extra OBSERVE per gap against a host the loop is
        # already re-attacking, which is the cheapest action in the catalogue
        # and the only one that makes the expensive one mean anything.
        baseline, baseline_fired, _bl_unaimed = self._probe(
            episode, gap.expected, gap.red, target, phase="verify")

        if baseline_fired is not False:
            # `True` is a confound and `None` is a probe that stopped
            # answering; neither establishes the silence a later hit would have
            # to break to prove anything. Collapsed into one branch because the
            # remedy is identical and the detail says which happened — the same
            # reason `undetermined` is one state with several routes.
            why = ("was already reporting activity of this kind before the "
                   "re-attack, so a hit afterwards cannot be attributed to it"
                   if baseline_fired else
                   "could not establish whether it was silent immediately "
                   "before the re-attack, and unknown is not silence")
            return Remediation(
                "undetermined", verb=action.verb_id,
                detail=(f"{action.verb_id} reported success, but "
                        f"{gap.expected} {why}. Closure has to be the "
                        "difference the re-attack made, not the state of the "
                        "log afterwards"))

        again = self._submit(gap.red.action, phase="verify")
        episode.turns.append(again)

        if again.refused:
            return Remediation(
                "undetermined", verb=action.verb_id,
                detail=(f"{action.verb_id} reported success, but the gate "
                        f"refused the re-attack ({again.decision.rule}), so the "
                        "control was never given anything to see"))
        if not again.succeeded:
            why = (again.observation.error[:120] if again.observation
                   else "no observation came back")
            return Remediation(
                "undetermined", verb=action.verb_id,
                detail=(f"{action.verb_id} reported success and "
                        f"{gap.red.action.verb_id} no longer succeeds ({why}). "
                        "That is a real outcome and it is not this finding: the "
                        "gap was a statement about the control, and a technique "
                        "that cannot run tells you nothing about what would have "
                        "been logged if it had"))

        evidence, fired, unaimed = self._probe(
            episode, gap.expected, again, target, phase="verify")

        if fired is True and unaimed:
            return Remediation(
                "undetermined", verb=action.verb_id,
                detail=(f"{gap.expected} found activity after the re-attack but "
                        f"had no {', '.join(unaimed)} to match against, so the "
                        "hit may be unrelated to the technique. An unattributable "
                        "hit closed nothing"))
        if fired is True and evidence.action.params != baseline.action.params:
            # The baseline is aimed from the original red observation and this
            # one from the re-attack's, because each is aimed at the evidence it
            # has. They are the same verb run with the same parameters, so the
            # two aims are the same in every case anyone has seen — but "the
            # control was silent" and "the control fired" are only comparable
            # when they answer the same question, and if the aims ever diverge
            # the baseline did not establish silence for the question the
            # evidence probe asked. Said out loud rather than assumed.
            return Remediation(
                "undetermined", verb=action.verb_id,
                detail=(f"{gap.expected} fired after the re-attack, but it was "
                        f"aimed differently from the silent reading taken "
                        f"before it ({baseline.action.params} then "
                        f"{evidence.action.params}), so the two are not the "
                        "same question and the difference between them proves "
                        "nothing"))
        if fired is True:
            confound = ""
            if applied_before:
                confound = (f". Note that {applied_before} earlier fix(es) in "
                            "this episode had already changed this host, so the "
                            "gap is proven shut but not proven shut by this fix "
                            "alone — keep them all")
            return Remediation(
                "closed", verb=action.verb_id,
                detail=(f"{action.verb_id} ran, {gap.red.action.verb_id} was "
                        f"performed again, and {gap.expected} fired. The gap is "
                        "shut and the proof is the second attack, not the fix's "
                        f"exit status{confound}"))
        if fired is None:
            return Remediation(
                "undetermined", verb=action.verb_id,
                detail=(f"{action.verb_id} ran and the re-attack succeeded, but "
                        f"{gap.expected} could not establish whether it fired. "
                        "Unknown is not closed and it is not still open"))
        return Remediation(
            "ineffective", verb=action.verb_id,
            detail=(f"{action.verb_id} reported success, but "
                    f"{gap.red.action.verb_id} ran again and {gap.expected} was "
                    "still silent. The fix did not close the gap"))

    @staticmethod
    def _default_fix(
        gap: _OpenGap, candidates: Sequence[Verb], target: str | None,
    ) -> Action | None:
        """The deterministic proposer, used when no chooser offers one.

        Its existence is the reason the whole phase can be demonstrated, tested
        and benchmarked with no model and no MLX, exactly as
        :class:`HeuristicChooser` is for the loop — and it is the number a
        trained model's defending has to beat.

        Two rules, and both are about not guessing.

        *Parameters come from the evidence or not at all.* A handler publishes
        what would fix what it just reported, under the ``remediation`` key,
        keyed by the exact harden verb id and the exact parameter names that
        verb declares. Nothing is inferred from the payload's shape. That
        matters more here than it does for aiming a probe: the sandbox's
        ``postex.credential_dump`` returns a ``source`` field naming the config
        file it read, and ``harden.enable_telemetry`` takes a parameter called
        ``source`` meaning a log stream. Lifting by name alone would enable
        telemetry on ``/etc/acme.conf``, and the gate would have allowed it —
        the path is in scope. A namespaced channel cannot make that mistake.

        *A fix the blind control named beats one the attacker named.* Both the
        red observation and the detection probe may publish hints, and a
        detection gap is a statement about the control, so the control's own
        account of why it saw nothing is the more specific answer. The fix that
        removes the weakness is still there as a fallback; it closes the hole
        without making the next instance of it visible, which is a different
        and lesser thing to have done.

        A candidate whose required parameters cannot be filled is skipped rather
        than bound with a placeholder. A MODIFY aimed at a guess is worse than a
        gap left open and honestly reported.
        """
        from ..actions import TargetKind

        red_hints = _remediation_hints(gap.red.observation)
        probe_hints = _remediation_hints(gap.probe.observation)

        ordered = sorted(candidates, key=lambda v: (
            0 if v.id in probe_hints else 1 if v.id in red_hints else 2, v.id))

        for verb in ordered:
            known = {p.name for p in verb.params}
            params: dict[str, Any] = {p.name: p.default for p in verb.params
                                      if p.default is not None}
            # Red first, probe second, so the probe wins a collision. Unknown
            # keys are dropped rather than passed through: a payload that
            # carries a junk field should not be able to knock out a fix that
            # would otherwise have bound.
            for hints in (red_hints, probe_hints):
                params.update({k: v for k, v in hints.get(verb.id, {}).items()
                               if k in known})
            try:
                return verb.bind(
                    params,
                    target=None if verb.target is TargetKind.NONE else target)
            except SchemaError:
                continue
        return None
