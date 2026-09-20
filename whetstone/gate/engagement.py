"""The engagement — what you are authorised to touch, and until when.

An agent that can run commands on other people's machines needs its authority
written down somewhere it cannot edit. That is this file. An engagement is a
document a human writes and signs off before any work starts; Whetstone reads
it, and refuses everything outside it.

The shape of the refusal matters as much as the refusal. Three properties are
deliberate and load-bearing:

*Exclusions beat inclusions, always.* If a host is in ``exclude_hosts`` it is
out of scope even if a wider CIDR in ``hosts`` covers it. The gateway inside the
lab subnet is the classic case, and the safe default is that the narrower, more
explicit statement of "not this one" wins.

That promise has a sharp edge, because one machine can be named two ways and
scope never resolves a name — DNS is not ours, and authority must not depend on
something we do not control. An exclusion written ``10.20.4.1`` therefore cannot
recognise the same gateway reached as ``gw.lab.internal``. The two directions
fail in opposite ways: a pattern that can never match is fail-closed in ``hosts``
(everything is denied and the operator notices within a minute) and fail-OPEN in
``exclude_hosts``, where nothing ever reports that the carve-out did not fire. So
a document whose ``hosts`` admits a naming form that none of its ``exclude_hosts``
uses is refused at load (:func:`_validate_scope`), and the operator writes each
carve-out in every form the scope admits.

*A host value has exactly one legal form.* The gate must rule on the same string
the adapter will ultimately dial, or the check is theatre. The adapters strip a
leading ``host:`` and split a ``:port`` off a host before they open a socket, so
``dc01.lab.internal:22`` and ``host:dc01.lab.internal`` are each two strings
wearing one coat: the gate matched the whole thing and the socket went somewhere
else. :func:`host_form_error` refuses those shapes rather than growing a fourth
parser here that would have to agree with the other three forever.

*An absent engagement is not an unrestricted one.* With no engagement file
loaded, :func:`null_engagement` gives you loopback-only, observe-only, blue-and-
neutral-only. You can read your own machine and nothing else. This is the mode
the tutorial and the training-data generator run in.

*There is no override.* Nowhere in this package does a function take ``force=``
or ``--yes-really``. A denial is the end of the conversation. If the scope is
wrong, the fix is to change the engagement document, which leaves a diff and a
timestamp, rather than to pass a flag, which leaves nothing.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..actions import Intent, Side

__all__ = [
    "Engagement",
    "Scope",
    "Authorization",
    "Profile",
    "EngagementError",
    "null_engagement",
    "load_engagement",
    "parse_engagement",
    "host_form_error",
]


class EngagementError(ValueError):
    """The engagement document is malformed or self-contradictory."""


_LOOPBACK_NAMES = frozenset({"localhost", "127.0.0.1", "::1", "loopback", ""})


def _as_address(text: str) -> ipaddress._BaseAddress | None:
    """Parse ``text`` as a bare IP literal, or return None if it is not one."""
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _is_loopback(host: str) -> bool:
    h = host.strip().lower()
    if h in _LOOPBACK_NAMES:
        return True
    addr = _as_address(h)
    return addr is not None and addr.is_loopback


def _as_network(text: str) -> ipaddress._BaseNetwork | None:
    """Parse ``text`` as an IP or CIDR, or return None if it is a hostname.

    ``strict=True`` is load-bearing. Under ``strict=False`` — which is what this
    used to pass — ``ip_network("192.168.1.50/24")`` does not fail; it discards
    the host bits and hands back ``192.168.1.0/24``, so an operator who copied
    one workstation's address out of ``ip addr show`` silently authorised 256
    machines. Nothing said so: the document still read ``192.168.1.50/24`` and
    :meth:`Engagement.summary` echoed the operator's own text back at them.
    Strict parsing turns that into a pattern that does not parse, which
    :func:`_pattern_form` then refuses at load with a message naming the entry
    and both readings. Nothing legitimate depended on the loose mode — a bare
    ``10.0.0.5`` still parses, as a /32.
    """
    try:
        return ipaddress.ip_network(text, strict=True)
    except ValueError:
        return None


#: Substrings that mean a host value is carrying something other than a host:
#: a scheme, a path or CIDR suffix, userinfo, a bracketed literal, or a glob
#: that belongs in a scope pattern rather than in an action.
_HOST_VALUE_BANS: tuple[tuple[str, str], ...] = (
    ("://", "looks like a URL; a host names a machine, not a service"),
    ("/", "contains '/', so it is a CIDR or a path rather than one host"),
    ("@", "contains '@'; credentials do not travel in a host value"),
    ("[", "is bracketed; write an IPv6 literal bare, because no adapter unbrackets it"),
    ("]", "is bracketed; write an IPv6 literal bare, because no adapter unbrackets it"),
    ("*", "contains a glob; a glob is a scope *pattern*, and an action runs against one host"),
    ("?", "contains a glob; a glob is a scope *pattern*, and an action runs against one host"),
)


def host_form_error(value: str) -> str | None:
    """Why ``value`` is not a host the gate may rule on, or None if it is one.

    The gate has to judge the exact string an adapter will hand to
    ``socket.create_connection``, or the check is theatre. Every adapter
    re-parses a host before it dials: all three strip a leading ``host:`` and
    then cut a port off at a colon — ``adapters/macos.py`` and
    ``adapters/windows.py`` at the first colon, ``adapters/linux.py`` at the
    last. So the gate matched ``evil.example.com:443.lab.internal`` against
    ``*.lab.internal``, said ALLOW, and the socket went to evil.example.com:443.
    The same trick walks past an exclusion from the other side:
    ``host:dc01.lab.internal`` is not the excluded ``dc01.lab.internal`` to a
    literal comparison, but the ``*`` in an inclusion glob eats the prefix that
    the adapter then strips back off.

    The repair is not a fourth parser here. A parser differential is what caused
    this, and a copy of the splitting logic in the gate would have to stay in
    agreement with three adapters that already disagree with each other about
    which colon wins. Instead a host value has one legal form — a bare hostname,
    an IPv4 literal or an IPv6 literal — on which the adapters' stripping and
    splitting are the identity, so what was authorised is provably what gets
    dialled. Anything else is refused, and the refusal names the part of the
    string that did it.

    The one surviving gap is an IPv6 literal, which is a real host but does
    contain colons, so the ``sink`` splitters still cut it in half. That mangles
    the probe rather than aiming it somewhere an attacker chose, and closing it
    properly means giving ``postex.exfil_probe`` its own integer ``port``
    parameter and deleting the splits — a change in ``whetstone/verbs.py`` and
    the three adapters, not here. Until then this function admits IPv6 because
    the corpus and the target path treat it as an ordinary host, and refuses
    every colon that is not part of one.
    """
    if not value.strip():
        return "is blank"
    if value != value.strip():
        return (
            "carries surrounding whitespace, so the gate would match the "
            "trimmed string while an adapter dials the raw one"
        )
    if any(ch.isspace() for ch in value):
        return "contains whitespace, so it is not a single host"
    for needle, why in _HOST_VALUE_BANS:
        if needle in value:
            return why
    if value.lower().startswith("host:"):
        # Named separately from the host:port case below because it is the one
        # that defeats an *exclusion*: the prefix is invisible to a literal
        # comparison, an inclusion glob swallows it, and the adapter takes it
        # straight back off before dialling the host underneath.
        return (
            "starts with 'host:', a prefix every adapter strips before it "
            "dials, so the gate would be ruling on characters the socket never "
            "sees"
        )
    if ":" in value and _as_address(value) is None:
        return (
            "looks like host:port. The port has to travel in its own parameter: "
            "the gate would scope-check the whole string while an adapter splits "
            "it at a colon and dials only one side, and a 'host:' prefix that an "
            "adapter strips is enough to walk past an exclusion"
        )
    return None


def _parse_ts(value: Any, field_name: str) -> datetime | None:
    """Parse an ISO-8601 timestamp, requiring a timezone.

    A naive timestamp in an authorisation document is an ambiguity nobody needs
    at 2am during an exercise, so we reject it rather than guessing UTC.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        text = value.strip()
        # datetime.fromisoformat only learned to accept a trailing Z in 3.11,
        # and this package supports 3.10.
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            raise EngagementError(
                f"{field_name}: {value!r} is not an ISO-8601 timestamp "
                "(try 2026-09-20T18:00:00Z)"
            ) from None
    else:
        raise EngagementError(f"{field_name}: expected a timestamp, got {value!r}")

    if dt.tzinfo is None:
        raise EngagementError(
            f"{field_name}: {value!r} has no timezone. Write it explicitly — "
            "an authorisation window without a timezone is not an authorisation."
        )
    return dt.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class Scope:
    """Where the agent may reach.

    Host patterns may be a literal IP, a CIDR block, a hostname, or a hostname
    glob such as ``*.lab.internal``. Path patterns are directory prefixes and
    are compared after resolution, so a symlink out of the tree does not escape
    the scope — it resolves to somewhere outside and is refused.

    Two rules about host strings live either side of this class, and both exist
    because a machine can be named more than one way. A carve-out has to appear
    in every naming form the scope admits, which :func:`_validate_scope` checks
    when an :class:`Engagement` is built rather than here, where a mismatch
    would be undecidable without DNS. And the host *values* compared against
    these patterns have exactly one legal form — see :func:`host_form_error` —
    because the gate must judge the string an adapter will dial, not a longer
    one that contains it.
    """

    hosts: tuple[str, ...] = ()
    exclude_hosts: tuple[str, ...] = ()
    paths: tuple[str, ...] = ()
    exclude_paths: tuple[str, ...] = ()
    #: When true, the loopback interface is in scope without being listed. This
    #: is how the null engagement lets you inspect your own machine.
    allow_loopback: bool = False

    def host_excluded(self, host: str) -> str | None:
        """Return the exclusion pattern that covers ``host``, if any.

        Deliberately does *not* refuse a malformed host the way
        :meth:`host_included` does. A string nobody should be acting on is still
        excluded if an exclusion catches it; dropping out early here would be
        the one direction where being strict grants authority.
        """
        return _match_host(host, self.exclude_hosts, exclusion=True)

    def host_included(self, host: str) -> str | None:
        if host_form_error(host) is not None:
            # Not a host this gate can honestly compare: the adapter would act
            # on a different string than the one matched here, so treating the
            # match as authorisation is exactly the bypass host_form_error
            # exists to describe. Inclusion is the direction where being wrong
            # hands out authority, so it fails closed.
            return None
        if self.allow_loopback and _is_loopback(host):
            return "loopback"
        return _match_host(host, self.hosts)

    def path_excluded(self, path: str) -> str | None:
        return _match_path(path, self.exclude_paths)

    def path_included(self, path: str) -> str | None:
        return _match_path(path, self.paths)


def _match_host(host: str, patterns: Sequence[str], *, exclusion: bool = False) -> str | None:
    """Return the first pattern in ``patterns`` matching ``host``, else None.

    ``exclusion`` is not cosmetic. The same comparison serves both directions,
    but the two directions fail opposite ways — a pattern that cannot match
    denies everything in ``hosts`` and permits everything in ``exclude_hosts``,
    silently — so an exclusion is allowed to match *more*, and every asymmetry
    below leans that way. Two exclusion shapes used to be inert:

    ``exclude_hosts: ["10.0.0.*"]``
        A glob was only ever compared against a host that was not an IP, so a
        glob written over a range of addresses excluded nothing at all while
        reading, in the document, exactly as if it did. Under ``exclusion`` the
        glob is applied to the address text too.

    ``exclude_hosts: ["127.0.0.1"]`` with ``allow_loopback``
        ``localhost`` is the same machine and a different string. Loopback is
        the one cross-form case that is decidable without asking DNS, because
        the standard fixes both forms, so an exclusion naming loopback in any
        form covers loopback named in any other.

    The remaining cross-form case — an address exclusion against a target named
    by hostname — cannot be decided here at all without resolving the name,
    which this function refuses to do on purpose. :func:`_validate_scope`
    refuses the *document* instead, at load, where a human can fix it.
    """
    h = host.strip().lower()
    if not h:
        return None
    addr = _as_address(h)

    for pat in patterns:
        p = pat.strip().lower()
        if not p:
            continue
        net = _as_network(p)
        if exclusion and _is_loopback(h) and (
            _is_loopback(p) or (net is not None and net.is_loopback)
        ):
            return pat
        if net is not None:
            # Pattern is an IP or CIDR. It can only match an IP target; a
            # hostname is not silently resolved, because resolution depends on
            # DNS we do not control and scope must not depend on that.
            if addr is not None and addr in net:
                return pat
            continue
        if (addr is None or exclusion) and fnmatch.fnmatch(h, p):
            return pat
    return None


def _match_path(path: str, patterns: Sequence[str]) -> str | None:
    """Return the first prefix in ``patterns`` containing ``path``, else None."""
    try:
        target = Path(path).expanduser().resolve()
    except (OSError, RuntimeError):
        return None
    for pat in patterns:
        if not pat.strip():
            continue
        try:
            root = Path(pat).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if target == root or root in target.parents:
            return pat
    return None


#: The two ways a scope pattern can name a machine. They are not interchangeable
#: and nothing here translates between them, because translating means asking
#: DNS and scope must not depend on DNS.
_FORM_ADDRESS = "address"
_FORM_NAME = "name"

#: Written for the operator, not for the parser: each form paired with the
#: reason the *other* form cannot stand in for it.
_FORM_PROSE: dict[str, tuple[str, str]] = {
    _FORM_NAME: (
        "by name",
        "An address exclusion can never match a host reached by name, because "
        "the gate does not resolve names — so the machine you carved out is "
        "still in scope under its hostname.",
    ),
    _FORM_ADDRESS: (
        "by address",
        "A name exclusion can never match a host reached by address, because "
        "the gate does not resolve names — so the machine you carved out is "
        "still in scope under its IP.",
    ),
}


def _pattern_form(pat: str, where: str) -> str:
    """Classify one scope pattern, or raise :class:`EngagementError`.

    Every pattern is either an address form (a literal or a CIDR) or a name form
    (a hostname or a glob), and a pattern that is neither is rejected here
    rather than being quietly filed under "name", where it would become a glob
    that matches nothing: inert in ``hosts`` is merely annoying, inert in
    ``exclude_hosts`` is an authorisation bypass that reads correctly in the
    document.
    """
    p = pat.strip().lower()
    if not p:
        raise EngagementError(f"{where}: an empty pattern matches nothing; remove it")
    if "/" in p:
        if _as_network(p) is not None:
            return _FORM_ADDRESS
        try:
            loose = ipaddress.ip_network(p, strict=False)
        except ValueError:
            raise EngagementError(
                f"{where}: {pat!r} contains '/' but is not a CIDR block"
            ) from None
        # Reached only via strict parsing having refused it: the operator wrote
        # an address with a prefix length that does not cover it, which is what
        # `ip addr show` prints. The two readings differ by the whole subnet, so
        # they have to say which one they signed for.
        host_part = p.split("/", 1)[0]
        raise EngagementError(
            f"{where}: {pat!r} has host bits set. Write "
            f"{loose.network_address}/{loose.prefixlen} for the whole subnet or "
            f"{host_part}/{loose.max_prefixlen} for that one host — the two "
            f"differ by {loose.num_addresses} machines, so say which you mean."
        )
    if _as_address(p) is not None:
        return _FORM_ADDRESS
    # Whatever is left has to be a hostname or a hostname glob. A glob is legal
    # in a pattern and nowhere else — that is the only way patterns are laxer
    # than values — and anything else is refused rather than filed under "name",
    # where it would become a glob that matches nothing while reading, in the
    # document, exactly like a carve-out.
    for needle, why in (
        ("@", "contains '@'; a scope pattern names machines, not accounts"),
        ("[", "is bracketed; write an IPv6 pattern bare"),
        ("]", "is bracketed; write an IPv6 pattern bare"),
        (":", "contains a colon but is not an IPv6 address or network, and a "
              "port is not part of a host pattern"),
    ):
        if needle in p:
            raise EngagementError(f"{where}: {pat!r} {why}")
    if any(ch.isspace() for ch in p):
        raise EngagementError(
            f"{where}: {pat!r} contains whitespace, so it is not one host pattern"
        )
    return _FORM_NAME


def _validate_scope(scope: Scope) -> None:
    """Refuse a scope whose exclusions cannot reach what its inclusions admit.

    This is the only place the cross-form hole can be caught. At match time the
    two naming forms are genuinely incomparable without DNS, and an exclusion
    that cannot fire is invisible: ``host_excluded`` returns None, the policy
    rule reads that as "not excluded", and nothing anywhere says the carve-out
    never applied. Whetstone's own shipped example was this shape — a /24 and
    ``*.lab.internal`` in ``hosts``, two bare addresses in ``exclude_hosts`` —
    and a credential dump against the excluded gateway was ALLOW the moment it
    was named ``gw.lab.internal`` instead of ``10.20.4.1``.

    So: if the document admits hosts in a form that no exclusion uses, it does
    not load. The operator writes each carve-out in every form the scope admits,
    which is a sentence of typing and the only statement that means what the
    document appears to say. Note this fires on the *scope*, not on the match,
    so it costs nothing at decision time and cannot be argued with at 2am.
    """
    included: dict[str, list[str]] = {}
    for pat in scope.hosts:
        included.setdefault(_pattern_form(pat, "scope.hosts"), []).append(pat)
    excluded: dict[str, list[str]] = {}
    for pat in scope.exclude_hosts:
        excluded.setdefault(_pattern_form(pat, "scope.exclude_hosts"), []).append(pat)

    if not excluded:
        # Nothing to be inert. A scope with no carve-outs promises nothing about
        # them, and loopback is handled by _is_loopback, which knows both forms.
        return

    for form in (_FORM_NAME, _FORM_ADDRESS):
        if form not in included or form in excluded:
            continue
        admits, why = _FORM_PROSE[form]
        raise EngagementError(
            f"scope.hosts admits hosts {admits} "
            f"({', '.join(repr(p) for p in included[form])}) but no entry in "
            f"scope.exclude_hosts is written that way "
            f"({', '.join(repr(p) for p in sum(excluded.values(), []))}). "
            f"{why} List every excluded host in each form this scope admits."
        )


class Profile(Enum):
    """Which half of the tool is live — the engagement's *mode*.

    ``max_intent`` and ``red_team`` were nearly enough to say this, and the gap
    between "nearly" and "enough" is the reason this type exists.

    Blue-only is expressible with what was already here: ``red_team=False``
    denies every red verb by :func:`~.policy._r_red_team`, and a ``MODIFY``
    ceiling denies them a second time because every red verb in the catalogue is
    ``EXECUTE``. Purple is the shipped labs' engagement: red authorised, ceiling
    at ``EXECUTE``.

    Red-only is not expressible, and the reason is worth stating precisely
    because it is the bug this type exists to make impossible. Red verbs are
    ``EXECUTE``, so a red engagement's ceiling has to be ``EXECUTE`` — and
    ``EXECUTE`` is the top of the ladder, so ``harden.*`` at ``MODIFY`` passes
    under it for free. Authorising exploitation would silently carry an
    authorisation to rewrite the host's defensive configuration, which is a
    different and larger permission: an attacker does not get to fix what it
    broke, and "you may run code here" was never "you may edit the controls
    that watch you". **Intent and side are two axes, not two points on one
    line.** The ceiling ranks how hard an operation pushes; the profile says
    whose playbook may push at all, and how far *on that side*.

    So a profile is a per-side ceiling, and it is a whitelist: a side absent
    from the table below is refused outright, not defaulted to the global
    ceiling. That direction is deliberate in both places it bites. A side
    nobody thought about is denied rather than admitted, and — the case that
    will actually happen — a verb added next year on a side at an intent above
    that side's row is denied until somebody edits this table on purpose. That
    is why ``NEUTRAL`` is pinned at ``OBSERVE`` in all three profiles even
    though every neutral verb shipped today is already ``OBSERVE``: the pin
    costs nothing now and is the thing standing between a future neutral
    ``EXECUTE`` verb and every profile waving it through.

    A profile only ever narrows. It can turn an ALLOW into a DENY and can never
    do the reverse, so no engagement becomes more permissive by naming one, and
    an engagement that names none behaves exactly as it did before this existed.
    """

    RED = "red-only"
    BLUE = "blue-only"
    PURPLE = "purple"

    def ceiling(self, side: Side) -> Intent | None:
        """The hardest intent this profile permits on ``side``, or None for "never".

        None and ``Intent.OBSERVE`` are different answers and the caller must
        keep them apart: the first means the side's playbook does not run here
        at all, the second means it runs but only to look. Collapsing them would
        let red-only's "blue may observe" read as blue-only's "red never runs",
        and the operator would be told the wrong thing about their own mode.
        """
        return _PROFILE_CEILINGS[self].get(side)

    def describe(self) -> str:
        """One line naming what each side may do, for a refusal or a summary.

        Written from the table rather than hand-typed per profile so a change to
        the table cannot leave the prose describing the old rules — the summary
        an operator checks before starting work is only worth reading if it is
        generated by the thing it describes.
        """
        table = _PROFILE_CEILINGS[self]
        parts = []
        for side in (Side.RED, Side.BLUE, Side.NEUTRAL):
            limit = table.get(side)
            parts.append(
                f"{side.value} not run at all" if limit is None
                else f"{side.value} up to {limit.value}"
            )
        return ", ".join(parts)


#: What each profile permits, per side. The whole separation is these nine
#: entries, and the absences are as load-bearing as the presences: ``Side.RED``
#: has no row under ``BLUE``, which is what makes a blue engagement refuse an
#: exploit *by rule* rather than by the runner having declined to offer one.
#:
#: Red-only's ``Side.BLUE: OBSERVE`` is the line that took the most thought. Red
#: has to keep the ``detect.*`` verbs — an attacker that cannot ask whether
#: anything saw it cannot find a detection gap, and finding detection gaps is
#: the entire product. What it loses is ``harden.*``, the only MODIFY verbs in
#: the catalogue and the only ones that rewrite the defence.
_PROFILE_CEILINGS: dict[Profile, dict[Side, Intent]] = {
    Profile.RED: {
        Side.RED: Intent.EXECUTE,
        Side.BLUE: Intent.OBSERVE,
        Side.NEUTRAL: Intent.OBSERVE,
    },
    Profile.BLUE: {
        Side.BLUE: Intent.MODIFY,
        Side.NEUTRAL: Intent.OBSERVE,
    },
    Profile.PURPLE: {
        Side.RED: Intent.EXECUTE,
        Side.BLUE: Intent.MODIFY,
        Side.NEUTRAL: Intent.OBSERVE,
    },
}

_PROFILES = {p.value: p for p in Profile}


@dataclass(frozen=True, slots=True)
class Authorization:
    """What classes of operation the engagement permits.

    Note that ``techniques`` is opt-in and empty by default: a red-team-enabled
    engagement that lists no techniques authorises no red verbs. Making the
    permissive case require typing is the whole idea.
    """

    red_team: bool = False
    max_intent: Intent = Intent.OBSERVE
    #: ATT&CK ids or prefixes, e.g. ``T1547`` covers ``T1547.001``.
    techniques: tuple[str, ...] = ()
    #: Intents that may run without a human confirming each one. Anything not
    #: listed still runs — it just has to be approved first.
    unattended: frozenset[Intent] = frozenset({Intent.OBSERVE})
    #: Which half of the tool is live. See :class:`Profile`. ``None`` means no
    #: per-side restriction, which is what every engagement written before this
    #: field existed means and is why the default is not ``PURPLE``: a profile
    #: pins ``NEUTRAL`` at ``OBSERVE``, so defaulting to one would quietly
    #: tighten documents nobody edited.
    profile: Profile | None = None

    def technique_allowed(self, attck: Sequence[str]) -> bool:
        """True when every technique the verb touches is authorised.

        Every, not any. A verb that emulates two techniques where only one is
        in scope is not half-authorised; it is unauthorised.
        """
        if not attck:
            return True
        for t in attck:
            if not any(t == a or t.startswith(a + ".") for a in self.techniques):
                return False
        return True


@dataclass(frozen=True, slots=True)
class Engagement:
    """A signed-off authorisation to operate, with an expiry.

    The metadata fields are not decoration. ``authorization`` is the string that
    gets quoted back in the audit log and in any report, and it is required to
    be non-empty for anything beyond the null engagement, because "who said you
    could do this" is the first question asked after an incident.
    """

    name: str
    authorization: str = ""
    operator: str = ""
    starts: datetime | None = None
    expires: datetime | None = None
    scope: Scope = field(default_factory=Scope)
    authorize: Authorization = field(default_factory=Authorization)
    #: Where this came from, for the audit log. Set by :func:`load_engagement`.
    source: str = ""

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise EngagementError("engagement has no name")
        # Validated on the object rather than in parse_engagement so that an
        # engagement assembled in code — the corpus builder and the lab both do
        # this — cannot hold an inert exclusion either. There is one shape of
        # authority in this system, and it is checked in one place.
        _validate_scope(self.scope)
        if self.starts and self.expires and self.expires <= self.starts:
            raise EngagementError(
                f"engagement {self.name!r} expires at or before it starts"
            )
        needs_auth = (
            self.authorize.red_team
            or self.authorize.max_intent is not Intent.OBSERVE
            or self.scope.hosts
            or self.scope.paths
        )
        if needs_auth and not self.authorization.strip():
            raise EngagementError(
                f"engagement {self.name!r} claims scope or elevated intent but "
                "records no authorization. Name the ticket, the approver and the "
                "date — this string is what gets quoted back when someone asks "
                "who said you could do this."
            )

    def window_state(self, now: datetime | None = None) -> str:
        """``"open"``, ``"early"`` or ``"expired"``."""
        moment = now or datetime.now(timezone.utc)
        if moment.tzinfo is None:
            raise EngagementError("now must be timezone-aware")
        if self.starts and moment < self.starts:
            return "early"
        if self.expires and moment >= self.expires:
            return "expired"
        return "open"

    def side_allowed(self, side: Side) -> bool:
        return side is not Side.RED or self.authorize.red_team

    def with_source(self, source: str) -> Engagement:
        return replace(self, source=source)

    def summary(self) -> str:
        """A few lines a human can check at a glance before starting work."""
        auth = self.authorize
        window = "no expiry set"
        if self.expires:
            window = f"until {self.expires.isoformat()}"
            if self.starts:
                window = f"{self.starts.isoformat()} → {self.expires.isoformat()}"
        hosts = ", ".join(self.scope.hosts) or ("loopback only" if self.scope.allow_loopback else "none")
        lines = [
            f"engagement   {self.name}",
            f"authority    {self.authorization or '(none — restricted mode)'}",
            f"window       {window}  [{self.window_state()}]",
            f"hosts        {hosts}",
        ]
        if self.scope.exclude_hosts:
            lines.append(f"  excluding  {', '.join(self.scope.exclude_hosts)}")
        if self.scope.paths:
            lines.append(f"paths        {', '.join(self.scope.paths)}")
        if self.scope.exclude_paths:
            lines.append(f"  excluding  {', '.join(self.scope.exclude_paths)}")
        if auth.profile is not None:
            # Printed above the two lines it overrules, because an operator who
            # has already read "red team authorised / max intent execute" and
            # then meets a refusal concludes the tool is broken. The mode is the
            # first thing that decides, so it is the first thing said.
            lines.append(
                f"mode         {auth.profile.value} "
                f"({auth.profile.describe()})"
            )
        lines.append(
            f"red team     {'authorised' if auth.red_team else 'NOT authorised'}"
            + (f"  techniques: {', '.join(auth.techniques)}" if auth.techniques else "")
        )
        lines.append(f"max intent   {auth.max_intent.value}")
        lines.append(
            "unattended   "
            + (", ".join(sorted(i.value for i in auth.unattended)) or "nothing")
        )
        return "\n".join(lines)


def null_engagement() -> Engagement:
    """The engagement you get when none is loaded: your own machine, read-only.

    This is not a crippled mode to be escaped from. It is the correct default
    and the mode most of Whetstone's own development happens in — the corpus
    builder, the tutorial and the test suite all run here. Loopback, observe,
    no red verbs.
    """
    return Engagement(
        name="restricted (no engagement loaded)",
        scope=Scope(allow_loopback=True),
        authorize=Authorization(
            red_team=False,
            max_intent=Intent.OBSERVE,
            techniques=(),
            unattended=frozenset({Intent.OBSERVE}),
        ),
        source="builtin:null",
    )


_INTENTS = {i.value: i for i in Intent}


def _intent(value: Any, where: str) -> Intent:
    if isinstance(value, Intent):
        return value
    if isinstance(value, str) and value.lower() in _INTENTS:
        return _INTENTS[value.lower()]
    raise EngagementError(
        f"{where}: {value!r} is not an intent; expected one of "
        f"{sorted(_INTENTS)}"
    )


def _strtuple(value: Any, where: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        raise EngagementError(
            f"{where}: expected a list, got a bare string {value!r}. "
            "A single entry still needs to be a list item."
        )
    if not isinstance(value, Sequence):
        raise EngagementError(f"{where}: expected a list, got {value!r}")
    out = []
    for item in value:
        if not isinstance(item, str):
            raise EngagementError(f"{where}: {item!r} is not a string")
        if item.strip():
            out.append(item.strip())
    return tuple(out)


_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def parse_engagement(doc: Mapping[str, Any], *, source: str = "") -> Engagement:
    """Build an :class:`Engagement` from a parsed YAML/JSON document.

    Unknown top-level keys are an error rather than a warning. A typo in an
    authorisation document should stop the run, not silently widen or narrow
    what the operator thought they had written.
    """
    if not isinstance(doc, Mapping):
        raise EngagementError("engagement document must be a mapping")

    known = {"engagement", "scope", "authorize"}
    unknown = set(doc) - known
    if unknown:
        raise EngagementError(
            f"unknown top-level key(s): {', '.join(sorted(unknown))}. "
            f"Expected: {', '.join(sorted(known))}"
        )

    meta = doc.get("engagement") or {}
    if not isinstance(meta, Mapping):
        raise EngagementError("'engagement' must be a mapping")
    meta_unknown = set(meta) - {"name", "authorization", "operator", "starts", "expires"}
    if meta_unknown:
        raise EngagementError(
            f"unknown key(s) under 'engagement': {', '.join(sorted(meta_unknown))}"
        )

    scope_doc = doc.get("scope") or {}
    if not isinstance(scope_doc, Mapping):
        raise EngagementError("'scope' must be a mapping")
    scope_unknown = set(scope_doc) - {
        "hosts", "exclude_hosts", "paths", "exclude_paths", "allow_loopback",
    }
    if scope_unknown:
        raise EngagementError(
            f"unknown key(s) under 'scope': {', '.join(sorted(scope_unknown))}"
        )

    auth_doc = doc.get("authorize") or {}
    if not isinstance(auth_doc, Mapping):
        raise EngagementError("'authorize' must be a mapping")
    auth_unknown = set(auth_doc) - {
        "red_team", "max_intent", "techniques", "unattended", "profile",
    }
    if auth_unknown:
        raise EngagementError(
            f"unknown key(s) under 'authorize': {', '.join(sorted(auth_unknown))}"
        )

    techniques = _strtuple(auth_doc.get("techniques"), "authorize.techniques")
    for t in techniques:
        if not _TECHNIQUE_RE.match(t):
            raise EngagementError(
                f"authorize.techniques: {t!r} is not an ATT&CK id "
                "(expected e.g. T1547 or T1547.001)"
            )

    unattended_raw = auth_doc.get("unattended")
    if unattended_raw is None:
        unattended = frozenset({Intent.OBSERVE})
    else:
        unattended = frozenset(
            _intent(v, "authorize.unattended")
            for v in _strtuple(unattended_raw, "authorize.unattended")
        )

    profile_raw = auth_doc.get("profile")
    if profile_raw is None:
        profile = None
    elif isinstance(profile_raw, Profile):
        profile = profile_raw
    elif isinstance(profile_raw, str) and profile_raw.strip().lower() in _PROFILES:
        profile = _PROFILES[profile_raw.strip().lower()]
    else:
        # Not defaulted to anything. A misspelled mode is the one typo that must
        # not be survivable: falling back to None would run a document that says
        # "red-onyl" as an engagement with no side separation at all, and the
        # operator would read their own word back off the page and believe it.
        raise EngagementError(
            f"authorize.profile: {profile_raw!r} is not a mode; expected one of "
            f"{sorted(_PROFILES)}"
        )

    red_team = bool(auth_doc.get("red_team", False))
    if red_team and not techniques:
        raise EngagementError(
            "authorize.red_team is true but no techniques are listed, so no red "
            "verb could run anyway. List the ATT&CK ids you are authorised to "
            "emulate, or set red_team: false."
        )

    scope = Scope(
        hosts=_strtuple(scope_doc.get("hosts"), "scope.hosts"),
        exclude_hosts=_strtuple(scope_doc.get("exclude_hosts"), "scope.exclude_hosts"),
        paths=_strtuple(scope_doc.get("paths"), "scope.paths"),
        exclude_paths=_strtuple(scope_doc.get("exclude_paths"), "scope.exclude_paths"),
        allow_loopback=bool(scope_doc.get("allow_loopback", False)),
    )

    return Engagement(
        name=str(meta.get("name", "")).strip(),
        authorization=str(meta.get("authorization", "")).strip(),
        operator=str(meta.get("operator", "")).strip(),
        starts=_parse_ts(meta.get("starts"), "engagement.starts"),
        expires=_parse_ts(meta.get("expires"), "engagement.expires"),
        scope=scope,
        authorize=Authorization(
            red_team=red_team,
            max_intent=_intent(auth_doc.get("max_intent", "observe"), "authorize.max_intent"),
            techniques=techniques,
            unattended=unattended,
            profile=profile,
        ),
        source=source,
    )


def load_engagement(path: str | Path) -> Engagement:
    """Read an engagement from a ``.yaml``/``.yml``/``.json`` file.

    YAML support is optional at import time so that the core package keeps its
    "standard library only" property; PyYAML is pulled in only when someone
    actually hands us a YAML file.
    """
    p = Path(path).expanduser()
    if not p.is_file():
        raise EngagementError(f"no engagement file at {p}")
    text = p.read_text(encoding="utf-8")

    if p.suffix.lower() in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore[import-untyped]
        except ImportError:
            raise EngagementError(
                "reading a YAML engagement needs PyYAML (pip install pyyaml), "
                "or write the engagement as .json instead"
            ) from None
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise EngagementError(f"{p}: {exc}") from None
    else:
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as exc:
            raise EngagementError(f"{p}: {exc}") from None

    if doc is None:
        raise EngagementError(f"{p} is empty")
    return parse_engagement(doc, source=str(p))
