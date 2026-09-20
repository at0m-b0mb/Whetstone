"""The decision engine: may this action run, and does a human have to say so?

This is a pure function of (engagement, verb, action, clock). It touches no
files, opens no sockets and runs no commands, which means the entire safety
surface of Whetstone can be tested exhaustively on a laptop with no lab, no VM
and no target. That property is worth more than it sounds: the rules below are
the part of the system that must never regress, and they are the part that is
cheapest to test.

Three design commitments, each of which rules out a class of mistake.

**Deny is terminal.** :func:`decide` has no ``force`` parameter, no ``override``
argument and no environment variable that softens it, and neither does anything
that calls it. When the answer is DENY the only way to change it is to edit the
engagement document — which is a file, in git, with an author and a timestamp.
A flag leaves no evidence; a diff does. This is also why the rules are ordered
with the denials first: once one fires, nothing later can promote the verdict.

**The default is CONFIRM, not ALLOW.** Read the rule table from the bottom: an
action that matches no rule at all lands on CONFIRM. A verb someone adds next
year without thinking about policy is therefore gated by a human rather than
waved through, which is the right way round for a system whose failure mode is
running something it shouldn't on a machine it shouldn't.

**A decision carries its reason.** Every verdict names the rule that produced it
and explains itself in a sentence written for the operator. That text goes three
places: the refusal the human sees, the audit log, and — when the model proposed
the action — back into the agent's context as a correction. The last one is why
the wording is plain and specific rather than "policy violation": it is training
signal, and a model cannot learn from an error message that says nothing.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Callable

from ..actions import Action, Intent, Side, TargetKind, Verb
from .engagement import Engagement, host_form_error

__all__ = ["Verdict", "Decision", "decide", "RULES"]


class Verdict(Enum):
    """The three possible answers. There is no fourth."""

    ALLOW = "allow"
    CONFIRM = "confirm"
    DENY = "deny"

    @property
    def blocked(self) -> bool:
        return self is Verdict.DENY


@dataclass(frozen=True, slots=True)
class Decision:
    """A verdict, the rule that produced it, and why — in that order of trust.

    ``rule`` is a stable machine-readable id. Tests assert on it, the audit log
    records it, and the eval harness counts by it. ``reason`` is prose for a
    human and may be reworded freely; ``rule`` may not, because things depend
    on it.
    """

    verdict: Verdict
    rule: str
    reason: str

    @property
    def allowed(self) -> bool:
        """True only for ALLOW. CONFIRM is not permission; it is a question."""
        return self.verdict is Verdict.ALLOW

    def __str__(self) -> str:
        return f"{self.verdict.value.upper()} [{self.rule}] {self.reason}"


# A rule takes the decision context and returns a Decision to stop on, or None
# to fall through to the next rule.
@dataclass(frozen=True, slots=True)
class _Ctx:
    engagement: Engagement
    verb: Verb
    action: Action
    now: datetime


_Rule = Callable[[_Ctx], "Decision | None"]


def _r_window(c: _Ctx) -> Decision | None:
    state = c.engagement.window_state(c.now)
    if state == "expired":
        return Decision(
            Verdict.DENY,
            "engagement.expired",
            f"the engagement {c.engagement.name!r} expired at "
            f"{c.engagement.expires.isoformat() if c.engagement.expires else 'an unset time'}. "
            "Authorisation does not extend itself; get a new window in writing.",
        )
    if state == "early":
        return Decision(
            Verdict.DENY,
            "engagement.early",
            f"the engagement {c.engagement.name!r} does not begin until "
            f"{c.engagement.starts.isoformat() if c.engagement.starts else 'an unset time'}.",
        )
    return None


def _scoped_hosts(c: _Ctx) -> list[tuple[str, str]]:
    """Every host this action would touch, as ``(label, value)``.

    The target is the obvious one. The parameters are the one that was
    missed: ``postex.exfil_probe`` declares ``sink`` as a host and its own
    caution promised the sink "is scope-checked like any other host", but the
    rule only ever read ``action.target``. An exfiltration probe aimed at an
    in-scope target could therefore name any collector on the internet and be
    allowed, which is the precise shape of mistake the gate exists to make
    impossible. A parameter that names a host is a host.
    """
    seen: list[tuple[str, str]] = []
    if c.verb.target is TargetKind.HOST:
        seen.append(("target", c.action.target or ""))
    for param in c.verb.params:
        if param.type != "host":
            continue
        value = c.action.params.get(param.name)
        if isinstance(value, str) and value:
            seen.append((param.name, value))
    return seen


def _r_scope_host(c: _Ctx) -> Decision | None:
    for label, host in _scoped_hosts(c):
        if (d := _host_in_scope(c, label, host)) is not None:
            return d
    return None


def _host_in_scope(c: _Ctx, label: str, host: str) -> Decision | None:
    where = "" if label == "target" else f"parameter {label!r}: "
    # Form before scope, because a string that is not a host makes both the
    # inclusion and the exclusion comparison meaningless: every adapter strips a
    # `host:` prefix and cuts a port off at a colon before it dials, so the gate
    # was matching one string and the socket was opening another. `*.lab.internal`
    # matched `evil.example.com:443.lab.internal` and the probe went to
    # evil.example.com; `host:dc01.lab.internal` slipped past the exclusion on
    # dc01 and the adapter stripped the prefix back off. Denying the shape is
    # what keeps the authorised string and the dialled string the same string.
    if (problem := host_form_error(host)) is not None:
        return Decision(
            Verdict.DENY,
            "scope.host.malformed",
            f"{where}{host!r} {problem}. A host is written one way — a bare "
            "hostname, an IPv4 literal or an IPv6 literal — because the gate "
            "rules on the exact string an adapter will connect to.",
        )
    excluded = c.engagement.scope.host_excluded(host)
    if excluded:
        return Decision(
            Verdict.DENY,
            "scope.host.excluded",
            f"{where}{host} is explicitly excluded by the rule {excluded!r}. An "
            "exclusion beats any range that would otherwise cover it.",
        )
    if not c.engagement.scope.host_included(host):
        return Decision(
            Verdict.DENY,
            "scope.host.unlisted",
            f"{where}{host} is not in the engagement's host scope. "
            + (
                "Only the loopback interface is in scope while no engagement is "
                "loaded."
                if c.engagement.source == "builtin:null"
                else f"In scope: {', '.join(c.engagement.scope.hosts) or 'nothing'}."
            ),
        )
    return None


def _scoped_paths(c: _Ctx) -> list[tuple[str, str]]:
    """Every path this action would touch — target and path-typed params.

    ``harden.permissions`` takes a ``path`` parameter and its target is not a
    path, so before this the verb could be pointed at any file on the machine
    and the scope rule would never look. Blue verbs write too.
    """
    seen: list[tuple[str, str]] = []
    if c.verb.target is TargetKind.PATH:
        seen.append(("target", c.action.target or ""))
    for param in c.verb.params:
        if param.type != "path":
            continue
        value = c.action.params.get(param.name)
        if isinstance(value, str) and value:
            seen.append((param.name, value))
    return seen


def _r_scope_path(c: _Ctx) -> Decision | None:
    for label, path in _scoped_paths(c):
        if (d := _path_in_scope(c, label, path)) is not None:
            return d
    return None


def _path_in_scope(c: _Ctx, label: str, path: str) -> Decision | None:
    where = "" if label == "target" else f"parameter {label!r}: "
    excluded = c.engagement.scope.path_excluded(path)
    if excluded:
        return Decision(
            Verdict.DENY,
            "scope.path.excluded",
            f"{where}{path} is under the excluded prefix {excluded!r}.",
        )
    if not c.engagement.scope.path_included(path):
        return Decision(
            Verdict.DENY,
            "scope.path.unlisted",
            f"{where}{path} is outside the engagement's path scope"
            + (
                "."
                if not c.engagement.scope.paths
                else f" ({', '.join(c.engagement.scope.paths)})."
            )
            + " Paths are compared after resolution, so a symlink out of the "
            "tree does not bring the target back in.",
        )
    return None


def _r_profile(c: _Ctx) -> Decision | None:
    """Refuse what this engagement's *mode* does not run, by side.

    This is the control that makes red-only, blue-only and purple three
    different things rather than three ways of configuring one runner. The
    distinction is not academic: a mode that holds because the runner never
    proposes the forbidden verb is a convention, and a convention survives
    exactly until somebody drives the same gate with a model chooser, which
    ranks over whatever catalogue it is handed and will propose
    ``exploit.service_permissions`` under a blue engagement the first time the
    ranking comes out that way. So the refusal lives here, where nothing that
    chooses an action can route around it.

    Two ways to fail, kept as two rule ids because they are two different
    sentences to an operator. ``profile.side`` means this mode does not run that
    playbook at all — a red verb under blue-only. ``profile.intent`` means it
    runs the playbook but not this hard — ``harden.*`` under red-only, which is
    the one the intent ceiling cannot catch, because red needs an ``EXECUTE``
    ceiling and ``MODIFY`` is underneath it.

    Both reasons name the mode. That wording is not decoration: the operator who
    meets this refusal has an engagement in front of them that says ``red_team:
    true`` and ``max_intent: execute``, and every other denial the gate can
    produce would leave them reading those two lines and concluding the tool is
    broken. The one fact that explains the refusal is which mode they are in, so
    the refusal says it.
    """
    profile = c.engagement.authorize.profile
    if profile is None:
        return None
    side = c.verb.side
    ceiling = profile.ceiling(side)
    if ceiling is None:
        return Decision(
            Verdict.DENY,
            "profile.side",
            f"{c.verb.id} is a {side.value} verb and this engagement runs in "
            f"{profile.value} mode, which does not run the {side.value} "
            f"playbook at all ({profile.describe()}). This is a property of the "
            "mode, not of the ceiling or the technique list: widening those "
            "changes nothing here. Run the exercise under a mode that includes "
            f"the {side.value} side.",
        )
    if c.verb.intent.rank > ceiling.rank:
        return Decision(
            Verdict.DENY,
            "profile.intent",
            f"{c.verb.id} is a {c.verb.intent.value} operation on the "
            f"{side.value} side and this engagement runs in {profile.value} "
            f"mode, which permits {side.value} verbs no further than "
            f"{ceiling.value} ({profile.describe()}). Intent and side are two "
            "axes: authorising exploitation raises the ceiling for the red "
            "playbook and is not thereby an authorisation to modify defensive "
            "configuration.",
        )
    return None


def _r_intent_ceiling(c: _Ctx) -> Decision | None:
    ceiling = c.engagement.authorize.max_intent
    if c.verb.intent.rank > ceiling.rank:
        return Decision(
            Verdict.DENY,
            "intent.ceiling",
            f"{c.verb.id} is an {c.verb.intent.value} operation but this "
            f"engagement permits at most {ceiling.value}.",
        )
    return None


def _r_red_team(c: _Ctx) -> Decision | None:
    if c.verb.side is Side.RED and not c.engagement.authorize.red_team:
        return Decision(
            Verdict.DENY,
            "red.unauthorized",
            f"{c.verb.id} emulates adversary behaviour and this engagement does "
            "not authorise red-team activity. Set authorize.red_team and list "
            "the techniques you are cleared to emulate.",
        )
    return None


def _r_technique(c: _Ctx) -> Decision | None:
    if c.verb.side is not Side.RED:
        return None
    if not c.engagement.authorize.technique_allowed(c.verb.attck):
        permitted = ", ".join(c.engagement.authorize.techniques) or "none"
        return Decision(
            Verdict.DENY,
            "technique.unauthorized",
            f"{c.verb.id} covers {', '.join(c.verb.attck)}, which is outside the "
            f"authorised technique list ({permitted}). Every technique a verb "
            "touches must be authorised, not just one of them.",
        )
    return None


def _r_unattended(c: _Ctx) -> Decision | None:
    if c.verb.intent in c.engagement.authorize.unattended:
        return Decision(
            Verdict.ALLOW,
            "intent.unattended",
            f"{c.verb.intent.value} operations run unattended under this "
            "engagement.",
        )
    return None


#: The rules, in the order they run. First one to return a Decision wins, so the
#: denials come first and the permissive rule comes last. Anything that reaches
#: the end without matching falls through to CONFIRM.
#:
#: The order is part of the contract and the tests assert on it. In particular
#: scope is checked before intent: being out of scope is a harder no than being
#: too aggressive, and the operator should be told the more fundamental problem.
#:
#: ``profile`` sits between them for the same reason and one more. Scope still
#: wins, because "not that machine" is more fundamental than "not in this mode".
#: But the mode has to be decided before the ceiling and before ``red.authorized``,
#: or a blue engagement's refusal of an exploit comes back as ``intent.ceiling``
#: — true, unhelpful, and silent about the only fact that explains it. A denial
#: that does not say which mode produced it reads, to the operator, like a bug.
RULES: tuple[tuple[str, _Rule], ...] = (
    ("window", _r_window),
    ("scope.host", _r_scope_host),
    ("scope.path", _r_scope_path),
    ("profile", _r_profile),
    ("intent.ceiling", _r_intent_ceiling),
    ("red.authorized", _r_red_team),
    ("technique", _r_technique),
    ("unattended", _r_unattended),
)


def decide(
    engagement: Engagement,
    verb: Verb,
    action: Action,
    *,
    now: datetime | None = None,
) -> Decision:
    """Rule on one action. Pure, total, and the only path to execution.

    ``verb`` and ``action`` are passed separately rather than looked up here so
    that this function has no dependency on the global registry, which in turn
    means a test can construct an adversarial verb that no real adapter would
    ever register and check that the rules still hold.
    """
    if action.verb_id != verb.id:
        # Defensive: an action carrying one id ruled on with another verb's
        # policy would be a confused-deputy bug of exactly the kind this module
        # exists to prevent, so it is an error rather than a denial.
        raise ValueError(
            f"action names verb {action.verb_id!r} but was ruled against "
            f"{verb.id!r}"
        )

    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        raise ValueError("now must be timezone-aware")

    ctx = _Ctx(engagement=engagement, verb=verb, action=action, now=moment)

    for _name, rule in RULES:
        decision = rule(ctx)
        if decision is not None:
            return decision

    return Decision(
        Verdict.CONFIRM,
        "default.confirm",
        f"{verb.id} is a {verb.intent.value} operation and is not in this "
        f"engagement's unattended list, so a human approves it."
        + (f" {verb.caution}" if verb.caution else ""),
    )
