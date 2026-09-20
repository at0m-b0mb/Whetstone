"""The three engagements a lab exercise can run under: red, blue, purple.

An exercise is not a runner with flags on it. It is an authorisation document,
and these are three different documents:

    red-only     Attacks and observes. Runs the ``exploit.*`` and ``postex.*``
                 verbs, and runs ``detect.*`` to ask whether anything saw —
                 because an attacker that cannot ask that cannot find a
                 detection gap, and the gap is the product. It **cannot
                 harden**. An engagement that authorises exploitation is not
                 thereby an authorisation to rewrite the host's defensive
                 configuration.
    blue-only    Inspects posture, hardens, verifies. **Cannot attack at all.**
                 No red verb reaches an adapter under this engagement.
    purple       Both, in one loop: attack, find the gap, fix it, re-attack to
                 prove the fix held. This is what the two shipped lab runners
                 have always done, now with the neutral half pinned.

The separation is enforced by :class:`~whetstone.gate.Profile` inside the gate,
not by which verbs a runner chooses to offer. That distinction is the point of
this module existing at all. A runner that simply declines to propose
``exploit.service_permissions`` under a blue exercise has a convention, and the
convention holds right up until the same gate is driven by a model chooser,
which ranks over whatever it is handed and will eventually rank an exploit
first. Under these engagements the gate answers DENY with a reason naming the
mode, and no amount of proposing changes that.

Each profile also sets the older authorisation fields as tightly as it can, so
the modes are not standing on the new rule alone. Blue-only carries
``red_team=False`` and a ``MODIFY`` ceiling, either of which would deny an
exploit on its own; the profile rule simply gets there first, and gets there
with a message that names the mode. Red-only is the one that genuinely needed
the new axis — see :class:`~whetstone.gate.Profile` for why the intent ceiling
cannot express it.

**These are lab engagements.** Every one of them runs unattended at every
intent and points at a disposable target. Nothing here is a template for an
engagement against a machine somebody depends on.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from whetstone.actions import Intent
from whetstone.gate.engagement import (Authorization, Engagement, Profile,
                                       Scope)

__all__ = [
    "red_only",
    "blue_only",
    "purple",
    "PROFILES",
    "PROFILE_NAMES",
    "engagement_for",
]


#: Every ATT&CK family the shipped red catalogue declares, written out rather
#: than read off the registry. Deriving it would authorise whatever the registry
#: happens to contain, which turns "the techniques you are cleared to emulate"
#: into a sentence with no content — and the one field in the authorisation
#: model whose entire purpose is to require typing would stop requiring any.
#:
#: The cost is that adding a red verb under a new family denies it until
#: somebody adds the family here. That is the intended failure: ``tests/
#: test_profiles.py`` walks the registry under the purple profile and goes red,
#: naming the technique, so the omission is found at test time by a person who
#: then decides on purpose.
_RED_TECHNIQUES: tuple[str, ...] = (
    "T1003",   # credential dumping
    "T1021",   # remote services / lateral movement
    "T1041",   # exfiltration over C2
    "T1053",   # scheduled task/job
    "T1068",   # exploitation for privilege escalation
    "T1543",   # create or modify system process
    "T1547",   # boot or logon autostart execution
    "T1548",   # abuse elevation control mechanism
    "T1574",   # hijack execution flow
)

#: The longest window a lab engagement may be written for. An expiry is the one
#: limit that keeps working after everybody has gone home, so it is not a knob
#: that opens all the way: an exercise nobody is watching stops being authorised
#: by itself. Twelve hours is longer than any exercise here and shorter than
#: leaving one running overnight by accident.
_MAX_HOURS = 12.0


def _window(hours: float) -> tuple[datetime, datetime]:
    """The authorisation window, starting a minute ago so clock skew cannot bite.

    The backdate is not cosmetic. ``starts`` in the future is ``engagement.early``
    and denies everything, and a target whose clock is a few seconds ahead of
    this process is enough to produce it — a whole exercise refused with a
    message about a window that looks, to the operator reading it, already open.
    """
    if not (0 < hours <= _MAX_HOURS):
        # Loudly, and before the Engagement is built: an out-of-range window
        # clamped to something reasonable would hand back an authorisation
        # nobody asked for and say nothing about having done so.
        raise ValueError(
            f"hours={hours!r} is not a lab window; write something in "
            f"(0, {_MAX_HOURS}]. An exercise that outlives the people watching "
            "it is the thing the expiry exists to stop."
        )
    now = datetime.now(timezone.utc)
    return now - timedelta(minutes=1), now + timedelta(hours=hours)


def _scope(root: str | None) -> Scope:
    """The sandbox's scope when ``root`` is given, the VM's when it is not.

    One function because the two targets differ in exactly one way — the
    sandbox confines by path, the VM by host — and the three profiles differ in
    none of it. Keeping the scope in one place is what lets the profile
    functions below be about authorisation and nothing else.

    ``allow_loopback`` is on in both. The kernel runs with ``target=
    "127.0.0.1"`` and every ``TargetKind.HOST`` verb is scope-checked against
    it, so without this the sandbox exercise would be denied at its first
    ``enum.host``.
    """
    if root is None:
        return Scope(hosts=("127.0.0.1",), allow_loopback=True)
    return Scope(paths=(root,), allow_loopback=True)


def _where(root: str | None) -> str:
    return ("disposable Lima VM, exists to be broken" if root is None
            else "self-contained sandbox, no real host in scope")


def red_only(root: str | None = None, *, hours: float = 1.0) -> Engagement:
    """Attack and observe. Cannot harden.

    ``root`` is the sandbox directory for ``lab.run``, or ``None`` for the VM.

    The ceiling is ``EXECUTE`` because every red verb is ``EXECUTE``, which is
    precisely why this profile cannot be expressed by the ceiling alone:
    ``EXECUTE`` is the top of the ladder and ``harden.*`` at ``MODIFY`` sits
    underneath it. ``Profile.RED`` is what keeps the blue side of this
    engagement at ``OBSERVE`` while the red side runs at the top — two axes, not
    two points on one line. Read the ceiling here as a statement about the red
    playbook only; the blue playbook's limit is in the mode.
    """
    starts, expires = _window(hours)
    return Engagement(
        name="lab red-only exercise",
        authorization=f"LAB — {_where(root)}. Red only: exploitation "
                      "authorised, hardening is not.",
        starts=starts,
        expires=expires,
        scope=_scope(root),
        authorize=Authorization(
            red_team=True,
            max_intent=Intent.EXECUTE,
            techniques=_RED_TECHNIQUES,
            unattended=frozenset(Intent),
            profile=Profile.RED,
        ),
    )


def blue_only(root: str | None = None, *, hours: float = 1.0) -> Engagement:
    """Inspect, harden, verify. Cannot attack at all.

    ``root`` is the sandbox directory for ``lab.run``, or ``None`` for the VM.

    Three independent locks sit on the red half here and all three are meant.
    ``Profile.BLUE`` has no row for ``Side.RED`` and refuses it outright;
    ``red_team=False`` refuses it again; the ``MODIFY`` ceiling refuses it a
    third time because every red verb is ``EXECUTE``. The profile is the one
    that fires, because it runs first and because it is the only one whose
    message names the mode — but deleting any single one of the three must not
    make an exploit run, and none of them is load-bearing alone.
    """
    starts, expires = _window(hours)
    return Engagement(
        name="lab blue-only exercise",
        authorization=f"LAB — {_where(root)}. Blue only: posture and "
                      "hardening authorised, no adversary emulation.",
        starts=starts,
        expires=expires,
        scope=_scope(root),
        authorize=Authorization(
            red_team=False,
            # MODIFY, because hardening is what this mode is for. Note that this
            # is *higher* than red-only's limit on the same side and lower than
            # red-only's ceiling overall, which is the clearest single statement
            # that the two modes are not ordered.
            max_intent=Intent.MODIFY,
            techniques=(),
            unattended=frozenset(Intent),
            profile=Profile.BLUE,
        ),
    )


def purple(root: str | None = None, *, hours: float = 1.0) -> Engagement:
    """Both halves in one loop: attack, find the gap, fix it, re-attack.

    ``root`` is the sandbox directory for ``lab.run``, or ``None`` for the VM.

    This is what the two lab runners built inline before this module existed,
    with one difference: ``Profile.PURPLE`` pins the neutral side at ``OBSERVE``.
    Every neutral verb shipped today is already ``OBSERVE``, so nothing changes
    now — and a neutral ``EXECUTE`` verb added later is denied until somebody
    edits the profile table, instead of inheriting an ``EXECUTE`` ceiling that
    was raised for the red playbook and meant nothing else by it.
    """
    starts, expires = _window(hours)
    return Engagement(
        name="lab purple exercise",
        authorization=f"LAB — {_where(root)}. Purple: attack, prove the gap, "
                      "fix it, and re-attack to show the fix held.",
        starts=starts,
        expires=expires,
        scope=_scope(root),
        authorize=Authorization(
            red_team=True,
            max_intent=Intent.EXECUTE,
            techniques=_RED_TECHNIQUES,
            unattended=frozenset(Intent),
            profile=Profile.PURPLE,
        ),
    )


#: The three, by the name a runner's ``--profile`` flag takes. Keyed by the
#: :class:`~whetstone.gate.Profile` value so the word an operator types, the
#: word in an engagement document, and the word in a gate refusal are one word.
PROFILES = {
    Profile.RED.value: red_only,
    Profile.BLUE.value: blue_only,
    Profile.PURPLE.value: purple,
}

#: Ready for ``argparse(choices=...)``. Ordered red, blue, purple — the order
#: the modes are explained in, not alphabetical.
PROFILE_NAMES: tuple[str, ...] = tuple(PROFILES)


def engagement_for(name: str, root: str | None = None, *,
                   hours: float = 1.0) -> Engagement:
    """Build one profile by name. Raises :class:`ValueError` on an unknown name.

    A ``KeyError`` off :data:`PROFILES` would be a correct refusal with a
    useless message. A runner that takes the mode from the command line is the
    place a typo happens, and the cheapest moment to say what the three words
    are is the moment somebody gets one of them wrong.
    """
    try:
        build = PROFILES[name.strip().lower()]
    except KeyError:
        raise ValueError(
            f"{name!r} is not a lab profile; expected one of "
            f"{', '.join(PROFILE_NAMES)}"
        ) from None
    return build(root, hours=hours)
