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
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..actions import Intent, Side

__all__ = [
    "Engagement",
    "Scope",
    "Authorization",
    "EngagementError",
    "null_engagement",
    "load_engagement",
    "parse_engagement",
]


class EngagementError(ValueError):
    """The engagement document is malformed or self-contradictory."""


_LOOPBACK_NAMES = frozenset({"localhost", "127.0.0.1", "::1", "loopback", ""})


def _is_loopback(host: str) -> bool:
    h = host.strip().lower()
    if h in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def _as_network(text: str) -> ipaddress._BaseNetwork | None:
    """Parse ``text`` as an IP or CIDR, or return None if it is a hostname."""
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
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
    """

    hosts: tuple[str, ...] = ()
    exclude_hosts: tuple[str, ...] = ()
    paths: tuple[str, ...] = ()
    exclude_paths: tuple[str, ...] = ()
    #: When true, the loopback interface is in scope without being listed. This
    #: is how the null engagement lets you inspect your own machine.
    allow_loopback: bool = False

    def host_excluded(self, host: str) -> str | None:
        """Return the exclusion pattern that covers ``host``, if any."""
        return _match_host(host, self.exclude_hosts)

    def host_included(self, host: str) -> str | None:
        if self.allow_loopback and _is_loopback(host):
            return "loopback"
        return _match_host(host, self.hosts)

    def path_excluded(self, path: str) -> str | None:
        return _match_path(path, self.exclude_paths)

    def path_included(self, path: str) -> str | None:
        return _match_path(path, self.paths)


def _match_host(host: str, patterns: Sequence[str]) -> str | None:
    """Return the first pattern in ``patterns`` matching ``host``, else None."""
    h = host.strip().lower()
    if not h:
        return None
    addr: ipaddress._BaseAddress | None
    try:
        addr = ipaddress.ip_address(h)
    except ValueError:
        addr = None

    for pat in patterns:
        p = pat.strip().lower()
        if not p:
            continue
        net = _as_network(p)
        if net is not None:
            # Pattern is an IP or CIDR. It can only match an IP target; a
            # hostname is not silently resolved, because resolution depends on
            # DNS we do not control and scope must not depend on that.
            if addr is not None and addr in net:
                return pat
            continue
        if addr is None and fnmatch.fnmatch(h, p):
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
        "red_team", "max_intent", "techniques", "unattended",
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
