"""The gate: the single chokepoint between deciding to act and acting.

:mod:`.policy` decides, :mod:`.audit` records, :mod:`.engagement` says what was
authorised — and this module is what forces all three to happen together. The
:class:`Gate` owns the executor, so there is no arrangement of imports that lets
a caller reach an adapter without passing through a ruling and leaving a log
entry. That is the difference between a safety property and a coding standard:
the second one survives only as long as everybody remembers it.

Two defaults here are worth stating out loud because they invert what a
convenience-minded library would do.

*No confirmer means no confirmation.* If nothing has been wired up to ask a
human, :data:`REFUSE_UNATTENDED` answers no to every CONFIRM. An agent running
in a cron job, a test, or a corpus-generation batch therefore gets the
restrictive reading automatically. The failure mode of the opposite default —
auto-approving because nobody was listening — is the one that ends up in an
incident report.

*A confirmation is per-action.* There is no "yes to all", no session-wide
approval and no remembered answer. If that is tedious during an exercise, the
correct fix is to widen ``authorize.unattended`` in the engagement document,
where the widening is written down and dated, rather than to click through
prompts, where it is not.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Protocol

from ..actions import Action, Observation, Side, Verb, VerbRegistry
from .audit import AuditLog, AuditRecord, AuditError, verify
from .engagement import (
    Authorization,
    Engagement,
    EngagementError,
    Scope,
    load_engagement,
    null_engagement,
    parse_engagement,
)
from .policy import Decision, RULES, Verdict, decide

__all__ = [
    "Gate",
    "GateRefusal",
    "Confirmer",
    "REFUSE_UNATTENDED",
    "always_confirm",
    # re-exported so callers need only import from whetstone.gate
    "Engagement",
    "EngagementError",
    "Scope",
    "Authorization",
    "null_engagement",
    "load_engagement",
    "parse_engagement",
    "Decision",
    "Verdict",
    "decide",
    "RULES",
    "AuditLog",
    "AuditRecord",
    "AuditError",
    "verify",
]


class GateRefusal(PermissionError):
    """The gate said no. Carries the decision so callers can explain why.

    Deliberately a subclass of :class:`PermissionError` rather than a bespoke
    base: code that wraps Whetstone in something larger tends to already have a
    handler for permission failures, and this should land in it.
    """

    def __init__(self, decision: Decision, action: Action) -> None:
        super().__init__(f"{action.render()}: {decision.reason}")
        self.decision = decision
        self.action = action


class Confirmer(Protocol):
    """Asks a human to approve one action. Returns True only for a clear yes."""

    def __call__(self, verb: Verb, action: Action, decision: Decision) -> bool: ...


def REFUSE_UNATTENDED(verb: Verb, action: Action, decision: Decision) -> bool:
    """The default confirmer: there is no human here, so the answer is no."""
    return False


def always_confirm(verb: Verb, action: Action, decision: Decision) -> bool:
    """A confirmer that approves everything. **Tests and lab automation only.**

    Named so that it is obvious in a diff. If this appears in anything that runs
    against a machine you do not own, that is the bug.
    """
    return True


class Executor(Protocol):
    """Whatever actually carries out an action on this platform."""

    def __call__(self, verb: Verb, action: Action) -> Observation: ...


@dataclass(frozen=True, slots=True)
class GateResult:
    """What came of submitting an action: the ruling, and the outcome if it ran."""

    decision: Decision
    observation: Observation | None = None
    confirmed: bool = False

    @property
    def ran(self) -> bool:
        return self.observation is not None


class Gate:
    """Holds the engagement, the log and the confirmer, and guards the executor.

    Construct one per session. Everything that wants to act goes through
    :meth:`submit`.
    """

    def __init__(
        self,
        engagement: Engagement | None = None,
        *,
        registry: VerbRegistry,
        audit: AuditLog | str | Path | None = None,
        confirmer: Confirmer = REFUSE_UNATTENDED,
        operator: str = "",
    ) -> None:
        self.engagement = engagement or null_engagement()
        self.registry = registry
        self.confirmer = confirmer
        self.operator = operator or self.engagement.operator

        if isinstance(audit, AuditLog):
            self.audit: AuditLog | None = audit
        elif audit is None:
            self.audit = None
        else:
            self.audit = AuditLog(audit)

        if self.audit is not None:
            self.audit.note(
                "session opened",
                engagement=self.engagement.name,
                authorization=self.engagement.authorization,
                source=self.engagement.source,
                operator=self.operator,
            )

    # ------------------------------------------------------------------ rule

    def rule(self, action: Action, *, now: datetime | None = None) -> Decision:
        """Rule on an action without running it or logging it.

        This is the dry-run path, used by ``whet plan`` and by the trainer when
        it wants to label a proposed action without side effects. Because it
        does not log, it is *not* the path anything that executes may take —
        :meth:`submit` re-rules rather than trusting a Decision handed to it.
        """
        verb = self.registry.get(action.verb_id)
        return decide(self.engagement, verb, action, now=now)

    # ---------------------------------------------------------------- submit

    def submit(
        self,
        action: Action,
        executor: Executor,
        *,
        now: datetime | None = None,
    ) -> GateResult:
        """Rule, log, maybe ask a human, and only then execute.

        Raises :class:`GateRefusal` on DENY, and on a CONFIRM the human declined.
        Returning a result object for "denied" would make it too easy to ignore
        the denial by not looking at the field; an exception is harder to not
        notice, which is the point.
        """
        verb = self.registry.get(action.verb_id)
        decision = decide(self.engagement, verb, action, now=now)

        confirmed = False
        if decision.verdict is Verdict.CONFIRM:
            confirmed = bool(self.confirmer(verb, action, decision))
            if not confirmed:
                decision = Decision(
                    Verdict.DENY,
                    "confirm.declined",
                    f"a human declined {action.render()}."
                    if self.confirmer is not REFUSE_UNATTENDED
                    else (
                        f"{action.render()} needs a human to approve it and no "
                        "confirmer is attached, so it is refused. Widen "
                        "authorize.unattended in the engagement if this should "
                        "run on its own."
                    ),
                )

        self._log_decision(action, decision, confirmed)

        if decision.verdict is Verdict.DENY:
            raise GateRefusal(decision, action)

        observation = executor(verb, action)

        if self.audit is not None:
            self.audit.observation(
                action=action.to_dict(), result=observation.to_dict()
            )

        return GateResult(decision=decision, observation=observation, confirmed=confirmed)

    def _log_decision(self, action: Action, decision: Decision, confirmed: bool) -> None:
        if self.audit is None:
            return
        self.audit.decision(
            engagement=self.engagement.name,
            authorization=self.engagement.authorization,
            action=action.to_dict(),
            verdict=decision.verdict.value,
            rule=decision.rule,
            reason=decision.reason,
            confirmed_by=(self.operator or "operator") if confirmed else None,
        )

    # ----------------------------------------------------------------- misc

    def catalogue(self) -> tuple[Verb, ...]:
        """The verbs this engagement could plausibly permit.

        Used to build the prompt handed to the model. Filtering here rather than
        relying on the model to avoid the red half is intentional: a temptation
        removed is cheaper than a refusal trained.
        """
        auth = self.engagement.authorize
        verbs = self.registry.select(max_intent=auth.max_intent)
        if not auth.red_team:
            return tuple(v for v in verbs if v.side is not Side.RED)
        return tuple(
            v
            for v in verbs
            if v.side is not Side.RED or auth.technique_allowed(v.attck)
        )

    def close(self) -> None:
        if self.audit is not None:
            ok, message = self.audit.verify()
            self.audit.note("session closed", chain_ok=ok, chain=message)
