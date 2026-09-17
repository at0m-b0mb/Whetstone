"""The action schema — the contract between the model and the machine.

This module is the keystone of the whole project, so it is worth being explicit
about why it exists before reading the code.

Whetstone trains a *small* model from scratch. A 150M-parameter network has no
hope of holding the world's security knowledge in its weights, and no hope of
free-form reasoning about a novel intrusion. What it can do — genuinely, at this
scale — is learn a narrow, well-shaped distribution. So we shape one.

The model never emits a shell command. It emits an :class:`Action`: a verb id
and a parameter dict, chosen from a closed registry. Three consequences follow,
and each one buys back capacity we would otherwise not have:

*The output space is small and closed.* Predicting one of ~200 verb ids is a
classification problem. Predicting an arbitrary PowerShell one-liner is not. The
first is learnable from scratch on a laptop; the second is not.

*The syntax lives in the adapters, not the weights.* ``enum.persistence`` means
the same thing on all three operating systems. The Windows adapter knows it is a
registry-plus-scheduled-task-plus-service sweep; the Linux adapter knows it is
cron, systemd units and shell profiles. The model learns the *concept* once
rather than memorising three dialects, which is the single largest saving
available to us.

*The facts live in retrieval, not the weights.* A verb can carry ATT&CK
technique ids, and those are looked up. The model is never asked to recall what
T1547.001 is, only that persistence enumeration is the right move here.

A fourth consequence matters for safety rather than capacity: because every
operation is a structured Action with a declared :class:`Intent` and
:class:`Side`, the gate can reason about what is being asked *before* anything
runs. A free-text command string cannot be reasoned about. This is why there is
no escape hatch verb that takes arbitrary shell — see ``docs/DESIGN.md``.

The registry is therefore three things at once: the runtime's dispatch table,
the gate's policy surface, and the model's vocabulary. Changing it changes all
three, which is why it is defined in one place.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Iterator, Mapping, Sequence

__all__ = [
    "Intent",
    "Side",
    "TargetKind",
    "Param",
    "Verb",
    "Action",
    "Observation",
    "VerbRegistry",
    "SchemaError",
    "NO_DETECTION",
    "REGISTRY",
]


class SchemaError(ValueError):
    """A verb definition or an action is malformed."""


class Intent(Enum):
    """What an operation does to the target, ordered by how hard it is to undo.

    The gate escalates on this axis, so the order is load-bearing rather than
    cosmetic. ``OBSERVE`` leaves no trace an admin would have to clean up;
    ``MODIFY`` changes durable state; ``EXECUTE`` runs code of our choosing on
    the target, which is the point past which "I can put it back" stops being a
    promise anyone should believe.
    """

    OBSERVE = "observe"
    MODIFY = "modify"
    EXECUTE = "execute"

    @property
    def rank(self) -> int:
        return _INTENT_RANK[self]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Intent):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Intent):
            return NotImplemented
        return self.rank <= other.rank


_INTENT_RANK = {Intent.OBSERVE: 0, Intent.MODIFY: 1, Intent.EXECUTE: 2}


class Side(Enum):
    """Whose playbook a verb belongs to.

    This is the purple in purple teaming, and it is a property of the *verb*,
    not of the operator. ``RED`` marks a verb that emulates adversary behaviour.
    ``BLUE`` marks one that detects, hardens or recovers. ``NEUTRAL`` marks the
    shared substrate — reading a file, listing processes — that both sides use
    and neither side owns.

    Keeping this on the verb lets an engagement authorise the blue half of the
    tool without the red half, which is the common case for a defender who wants
    the agent on a production box.
    """

    BLUE = "blue"
    RED = "red"
    NEUTRAL = "neutral"


class TargetKind(Enum):
    """What kind of thing a verb acts on, which decides how scope is checked.

    A verb that touches a host is checked against the engagement's host scope; a
    verb that touches a path is checked against the path scope. ``NONE`` is for
    pure computation — parsing a log the agent already holds, say — which needs
    no scope check because it reaches nothing.
    """

    HOST = "host"
    PATH = "path"
    NONE = "none"


# Verb ids are ``group.name`` or ``group.sub.name``: lowercase, dot-separated,
# no surprises. The model will emit these token-by-token, so they are kept short
# and consistently shaped — a predictable id is a cheaper id.
_VERB_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9_]*){1,3}$")

_PARAM_TYPES = frozenset({"string", "integer", "boolean", "path", "host", "enum"})

#: Sentinel for ``Verb.detected_by`` meaning "no control in this catalogue
#: covers this technique". Spelling it out is the point: an attack with no
#: detection should be a deliberate, visible statement rather than an empty
#: field somebody forgot to fill in. Every occurrence is a to-do for the blue
#: side, and ``whet coverage`` lists them.
NO_DETECTION = "detect.nothing"


@dataclass(frozen=True, slots=True)
class Param:
    """One parameter of a verb.

    The type vocabulary is deliberately tiny. Rich types would let verbs express
    more, but every distinct shape is something the model has to learn to fill
    correctly, and a parameter it fills wrongly is worse than one that does not
    exist. When a verb wants something complicated, that is a sign it should be
    two verbs.
    """

    name: str
    type: str
    description: str
    required: bool = True
    default: Any = None
    choices: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.name.isidentifier():
            raise SchemaError(f"parameter name {self.name!r} is not an identifier")
        if self.type not in _PARAM_TYPES:
            raise SchemaError(
                f"parameter {self.name!r} has unknown type {self.type!r}; "
                f"expected one of {sorted(_PARAM_TYPES)}"
            )
        if self.type == "enum" and not self.choices:
            raise SchemaError(f"enum parameter {self.name!r} declares no choices")
        if self.choices and self.type != "enum":
            raise SchemaError(
                f"parameter {self.name!r} has choices but type {self.type!r}"
            )
        if self.required and self.default is not None:
            raise SchemaError(
                f"parameter {self.name!r} is required and also has a default; "
                "pick one"
            )

    def validate(self, value: Any) -> Any:
        """Check and normalise one supplied value, or raise :class:`SchemaError`.

        Normalising here rather than in each adapter means a verb behaves the
        same way whichever platform runs it, and — more importantly — means the
        training data and the runtime agree on what a well-formed parameter
        looks like. A model trained on ``"true"`` and served against a runtime
        that demands ``True`` will fail in a way nobody enjoys debugging.
        """
        if self.type == "boolean":
            if isinstance(value, bool):
                return value
            if isinstance(value, str) and value.lower() in {"true", "false"}:
                return value.lower() == "true"
            raise SchemaError(f"{self.name}: expected boolean, got {value!r}")

        if self.type == "integer":
            # bool is a subclass of int; accepting it here would silently turn
            # True into 1 and hide a model mistake we would rather see.
            if isinstance(value, bool):
                raise SchemaError(f"{self.name}: expected integer, got boolean")
            if isinstance(value, int):
                return value
            if isinstance(value, str):
                try:
                    return int(value, 10)
                except ValueError:
                    pass
            raise SchemaError(f"{self.name}: expected integer, got {value!r}")

        if self.type == "enum":
            if value in self.choices:
                return value
            raise SchemaError(
                f"{self.name}: {value!r} is not one of {list(self.choices)}"
            )

        if not isinstance(value, str):
            raise SchemaError(f"{self.name}: expected string, got {value!r}")
        if self.type in {"path", "host"} and not value.strip():
            raise SchemaError(f"{self.name}: must not be blank")
        return value


@dataclass(frozen=True, slots=True)
class Verb:
    """A semantic operation, defined once and implemented per platform.

    A verb is not a command. ``enum.persistence`` is a question — "what runs
    without a human starting it?" — and each adapter answers it in its own
    idiom. Verbs are the unit the model reasons in and the unit the gate
    authorises, so the registry's shape is the system's shape.
    """

    id: str
    summary: str
    intent: Intent
    side: Side
    target: TargetKind
    params: tuple[Param, ...] = ()
    attck: tuple[str, ...] = ()
    #: Free-text note shown to a human at a confirmation prompt. Worth writing
    #: for anything above OBSERVE: it is the last thing an operator reads before
    #: saying yes, and it should say what will actually change.
    caution: str = ""
    #: The blue verbs that *should* notice this one. This is the hinge the whole
    #: project turns on, so it is a schema field rather than documentation.
    #:
    #: A red verb names the detections that ought to fire when it runs. After
    #: the attack lands, the agent runs each of these and compares. Caught is a
    #: control working; silence is a **detection gap** — a finding that names the
    #: technique, the host, and the telemetry that was missing. That pairing is
    #: what makes this purple rather than merely offensive: the exploit is not
    #: the deliverable, the gap it reveals is.
    #:
    #: It is also the cleanest training signal in the system. "Did rule X fire
    #: within N seconds of technique Y?" is a mechanically checkable fact, not a
    #: judge model's opinion, which means trajectories can be labelled correct or
    #: incorrect without a human in the loop. Most domains would kill for a
    #: verifier this good.
    detected_by: tuple[str, ...] = ()
    #: The red verbs this blue verb is meant to catch. The inverse of
    #: ``detected_by``, kept explicit so coverage can be computed in both
    #: directions: which attacks have no detection, and which detections guard
    #: nothing.
    detects: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not _VERB_ID_RE.match(self.id):
            raise SchemaError(
                f"verb id {self.id!r} must be lowercase dotted, e.g. 'enum.persistence'"
            )
        if not self.summary:
            raise SchemaError(f"verb {self.id!r} has no summary")
        seen: set[str] = set()
        for p in self.params:
            if p.name in seen:
                raise SchemaError(f"verb {self.id!r} repeats parameter {p.name!r}")
            seen.add(p.name)
        for t in self.attck:
            if not re.match(r"^T\d{4}(\.\d{3})?$", t):
                raise SchemaError(
                    f"verb {self.id!r} has malformed ATT&CK id {t!r}"
                )
        # A red verb that only observes is usually a mislabelled blue verb, but
        # it is legitimate for reconnaissance, so this is not an error. A red
        # verb with no caution text is a real gap though: someone will be asked
        # to approve it with nothing to read.
        if self.intent is not Intent.OBSERVE and not self.caution:
            raise SchemaError(
                f"verb {self.id!r} is {self.intent.value} and must declare a caution"
            )
        # The purple discipline, enforced by the type system rather than by
        # review: you do not get to add an attack without saying what ought to
        # catch it. If the honest answer is "nothing currently does", that is a
        # finding worth writing down, and `detect.nothing` exists to say so
        # explicitly rather than by omission.
        if self.side is Side.RED and not self.detected_by:
            raise SchemaError(
                f"red verb {self.id!r} declares no detected_by. Name the blue "
                "verb(s) that should catch it — or 'detect.nothing' if the "
                "honest answer is that no control covers this technique yet."
            )
        if self.side is not Side.RED and self.detected_by:
            raise SchemaError(
                f"verb {self.id!r} is {self.side.value} and cannot declare "
                "detected_by; use 'detects' on a blue verb instead"
            )
        if self.detects and self.side is not Side.BLUE:
            raise SchemaError(
                f"verb {self.id!r} declares 'detects' but is not a blue verb"
            )

    @property
    def group(self) -> str:
        """The leading segment of the id — ``enum``, ``detect``, ``harden``…"""
        return self.id.split(".", 1)[0]

    def bind(self, params: Mapping[str, Any] | None = None, *, target: str | None = None) -> Action:
        """Validate parameters and produce a concrete :class:`Action`.

        This is the only supported way to build an Action from a Verb, so that
        an Action in flight is always one that passed schema validation. The
        gate can then concern itself with authorisation rather than re-checking
        shapes.
        """
        supplied = dict(params or {})
        bound: dict[str, Any] = {}
        known = {p.name: p for p in self.params}

        for name in supplied:
            if name not in known:
                raise SchemaError(
                    f"verb {self.id!r} has no parameter {name!r}; "
                    f"known: {sorted(known) or 'none'}"
                )

        for p in self.params:
            if p.name in supplied:
                bound[p.name] = p.validate(supplied[p.name])
            elif p.required:
                raise SchemaError(f"verb {self.id!r} requires parameter {p.name!r}")
            elif p.default is not None:
                bound[p.name] = p.default

        if self.target is TargetKind.NONE:
            if target is not None:
                raise SchemaError(f"verb {self.id!r} takes no target")
        elif not target:
            raise SchemaError(
                f"verb {self.id!r} acts on a {self.target.value} and needs a target"
            )

        return Action(verb_id=self.id, params=bound, target=target)


@dataclass(frozen=True, slots=True)
class Action:
    """One concrete thing to do: a verb id, its parameters, and a target.

    This is what the model emits and what the gate rules on. It is deliberately
    inert — constructing one does nothing at all. Something has to hand it to an
    adapter, and the gate sits on that path.
    """

    verb_id: str
    params: Mapping[str, Any] = field(default_factory=dict)
    target: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"verb": self.verb_id, "params": dict(self.params)}
        if self.target is not None:
            d["target"] = self.target
        return d

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> Action:
        """Rebuild an Action from its serialised form.

        Used for replaying audit logs and for reading model output, both of
        which arrive as untrusted dicts — hence the explicit checks rather than
        a bare ``cls(**d)``.
        """
        if "verb" not in d:
            raise SchemaError("action has no 'verb' key")
        verb = d["verb"]
        if not isinstance(verb, str):
            raise SchemaError(f"action verb must be a string, got {verb!r}")
        params = d.get("params", {})
        if not isinstance(params, Mapping):
            raise SchemaError(f"action params must be a mapping, got {params!r}")
        target = d.get("target")
        if target is not None and not isinstance(target, str):
            raise SchemaError(f"action target must be a string, got {target!r}")
        return cls(verb_id=verb, params=dict(params), target=target)

    def render(self) -> str:
        """A compact one-line form, for logs and for the model's context.

        ``enum.persistence(scope=user) on host:dc01`` reads well to a human and
        tokenises predictably for the model, which sees this shape far more
        often than any other during training.
        """
        inner = ", ".join(f"{k}={v}" for k, v in sorted(self.params.items()))
        head = f"{self.verb_id}({inner})"
        return f"{head} on {self.target}" if self.target else head


@dataclass(frozen=True, slots=True)
class Observation:
    """What came back. The other half of every training example.

    The agent loop is plan-act-observe-critique, and this is the observe. It
    carries ``ok`` separately from ``data`` because "the command ran and found
    nothing" and "the command did not run" are different facts that a model will
    happily conflate if the schema lets it.
    """

    action: Action
    ok: bool
    data: Any = None
    error: str = ""
    duration_ms: int = 0
    platform: str = ""
    #: Set when an adapter declined to implement a verb on this platform, as
    #: opposed to trying and failing. Kept distinct because "macOS has no
    #: registry" is a fact about the world, not a bug to retry.
    unsupported: bool = False

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "action": self.action.to_dict(),
            "ok": self.ok,
            "duration_ms": self.duration_ms,
        }
        if self.data is not None:
            d["data"] = self.data
        if self.error:
            d["error"] = self.error
        if self.platform:
            d["platform"] = self.platform
        if self.unsupported:
            d["unsupported"] = True
        return d


class VerbRegistry:
    """The closed set of things Whetstone can do.

    Closed is the operative word. A registry you can add to at runtime is a
    registry the gate cannot make promises about, and an action space the model
    cannot be trained against. Verbs are registered at import time by the
    modules under :mod:`whetstone.verbs`, and then the registry is frozen.
    """

    def __init__(self) -> None:
        self._verbs: dict[str, Verb] = {}
        self._frozen = False

    def register(self, verb: Verb) -> Verb:
        if self._frozen:
            raise SchemaError(
                f"cannot register {verb.id!r}: the registry is frozen. "
                "Verbs must be declared at import time so that the gate and the "
                "tokenizer see the same action space the runtime does."
            )
        if verb.id in self._verbs:
            raise SchemaError(f"duplicate verb id {verb.id!r}")
        self._verbs[verb.id] = verb
        return verb

    def freeze(self) -> VerbRegistry:
        """Close the registry, after checking every cross-reference resolves.

        Pairing is validated here rather than at verb-definition time because a
        red verb is often written before the detection that should catch it
        exists. Deferring to freeze lets the two be added in either order while
        still guaranteeing that, once the process is up, every ``detected_by``
        points at something real.
        """
        for verb in self._verbs.values():
            for ref in verb.detected_by:
                if ref == NO_DETECTION:
                    continue
                if ref not in self._verbs:
                    raise SchemaError(
                        f"red verb {verb.id!r} says it is detected by {ref!r}, "
                        "which is not a registered verb"
                    )
                if self._verbs[ref].side is not Side.BLUE:
                    raise SchemaError(
                        f"red verb {verb.id!r} names {ref!r} as its detection, "
                        f"but {ref!r} is a {self._verbs[ref].side.value} verb"
                    )
            for ref in verb.detects:
                if ref not in self._verbs:
                    raise SchemaError(
                        f"blue verb {verb.id!r} claims to detect {ref!r}, which "
                        "is not a registered verb"
                    )
                if self._verbs[ref].side is not Side.RED:
                    raise SchemaError(
                        f"blue verb {verb.id!r} claims to detect {ref!r}, which "
                        "is not a red verb"
                    )
        self._frozen = True
        return self

    def coverage(self) -> dict[str, tuple[str, ...]]:
        """Red verbs mapped to the detections that claim them, for gap analysis.

        A red verb whose value is empty is one this tool can perform and nothing
        in the catalogue would notice — which is a finding about *Whetstone*,
        not about the target, and worth surfacing before an exercise rather
        than during one.
        """
        out: dict[str, tuple[str, ...]] = {}
        for verb in self:
            if verb.side is not Side.RED:
                continue
            claimed = [
                blue.id for blue in self if verb.id in blue.detects
            ]
            declared = [d for d in verb.detected_by if d != NO_DETECTION]
            out[verb.id] = tuple(sorted(set(claimed) | set(declared)))
        return out

    @property
    def frozen(self) -> bool:
        return self._frozen

    def get(self, verb_id: str) -> Verb:
        try:
            return self._verbs[verb_id]
        except KeyError:
            raise SchemaError(f"unknown verb {verb_id!r}") from None

    def __contains__(self, verb_id: object) -> bool:
        return verb_id in self._verbs

    def __len__(self) -> int:
        return len(self._verbs)

    def __iter__(self) -> Iterator[Verb]:
        return iter(sorted(self._verbs.values(), key=lambda v: v.id))

    def ids(self) -> tuple[str, ...]:
        """Every verb id, sorted. This is the model's output vocabulary."""
        return tuple(sorted(self._verbs))

    def groups(self) -> dict[str, tuple[Verb, ...]]:
        out: dict[str, list[Verb]] = {}
        for v in self:
            out.setdefault(v.group, []).append(v)
        return {k: tuple(v) for k, v in sorted(out.items())}

    def select(
        self,
        *,
        side: Side | None = None,
        intent: Intent | None = None,
        max_intent: Intent | None = None,
        group: str | None = None,
    ) -> tuple[Verb, ...]:
        """Filter the registry. Used to show a model only what it may do.

        Handing a model the full catalogue and relying on it to avoid the red
        half is a strictly worse design than not showing it the red half. The
        gate still refuses either way, but a refusal the model never had to
        earn is a refusal we do not have to train.
        """
        out: Iterable[Verb] = self
        if side is not None:
            out = (v for v in out if v.side is side)
        if intent is not None:
            out = (v for v in out if v.intent is intent)
        if max_intent is not None:
            out = (v for v in out if v.intent <= max_intent)
        if group is not None:
            out = (v for v in out if v.group == group)
        return tuple(out)

    def bind(
        self,
        verb_id: str,
        params: Mapping[str, Any] | None = None,
        *,
        target: str | None = None,
    ) -> Action:
        return self.get(verb_id).bind(params, target=target)

    def parse(self, d: Mapping[str, Any]) -> Action:
        """Turn model output into a validated Action.

        Round-tripping through the verb's own ``bind`` is the point: it means a
        hallucinated verb id, a missing parameter or an invented parameter name
        all fail here, loudly, with a message the agent loop can feed back to
        the model as a correction rather than discovering downstream.
        """
        raw = Action.from_dict(d)
        return self.get(raw.verb_id).bind(raw.params, target=raw.target)

    def describe(self, verb_ids: Sequence[str] | None = None) -> str:
        """Render verbs as the compact catalogue shown to the model.

        Format is one verb per line, because line-oriented text is what the
        tokenizer will be trained on and what the model will be prompted with.
        Keeping the training-time and serving-time rendering in one function is
        how they stay identical.
        """
        verbs = [self.get(v) for v in verb_ids] if verb_ids is not None else list(self)
        lines = []
        for v in verbs:
            sig = ", ".join(
                f"{p.name}:{p.type}" + ("" if p.required else "?") for p in v.params
            )
            tag = f"[{v.side.value[0]}{v.intent.value[0]}]"
            lines.append(f"{tag} {v.id}({sig}) — {v.summary}")
        return "\n".join(lines)


#: The process-wide registry. Imported by adapters, the gate, the CLI and the
#: corpus builder alike, so that all four are provably talking about the same
#: set of operations.
REGISTRY = VerbRegistry()
