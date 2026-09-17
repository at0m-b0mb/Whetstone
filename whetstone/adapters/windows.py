"""The Windows adapter: the verb catalogue answered in Windows idiom.

Everything here is built around two decisions that are worth stating up front,
because the rest of the file is their consequence.

**Structured in, structured out.** Almost every handler drives PowerShell as an
argv list (never a shell string — see :func:`whetstone.adapters.base.run`) and
asks it to emit JSON with ``ConvertTo-Json`` rather than a formatted table. A
table is laid out for a human at a particular terminal width; JSON is laid out
for a parser. Scraping ``Format-Table`` output is how you get a parser that
works until someone's console is 80 columns instead of 120. So the commands end
in ``| ConvertTo-Json`` and the parsers are :func:`json.loads` plus a little
normalisation.

There is one surprising wrinkle that every JSON parser here has to handle, and
it is the single most common way a naive Windows-JSON parser breaks:
``ConvertTo-Json`` collapses a *single* object to a JSON object and a *sequence*
to a JSON array. ``Get-LocalUser`` on a box with one account returns an object;
on a box with five it returns an array. :func:`_as_list` exists precisely to
paper over that, so a handler never has to care how many rows came back. The
second wrinkle: Windows PowerShell 5.1's ``ConvertTo-Json`` defaults to a depth
of 2 and silently truncates deeper structure, so every command passes ``-Depth``
explicitly.

**Parsing is separated from execution, on purpose.** Every ``parse_*`` function
in this module is pure, module-level and importable: it takes the *string* a
command produced and returns structured data, touching nothing. That is not a
style preference — it is the only way this adapter can be tested on a Mac. CI
feeds these parsers captured fixture output (``tests/fixtures/windows/``) and
checks the structured result. A handler is then the thin part: run the command,
hand its stdout to the parser. If a parser needed a live Windows box to run, it
could not be tested in this project's CI, which runs on whatever the developer
has.

The red verbs (``exploit.*``, ``postex.*``) are implemented, because a
purple-team tool that can only defend is half a tool, but with the discipline
rule 6 of the adapter contract demands: they record exactly what they changed so
a human can undo it by hand, they honour and truthfully report cleanup, and the
file/registry primitives they are built on are exercised only against a
temporary sandbox (see the ``stage_*`` / ``restore_*`` helpers and the tests),
never against a real service or account.
"""

from __future__ import annotations

import json
import os
import re
import socket
import tempfile
import uuid
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from ..actions import Action, Observation, Verb
from .base import Adapter, AdapterError, CommandResult, register_adapter, run, which

__all__ = ["WindowsAdapter"]


# ---------------------------------------------------------------------------
# PowerShell invocation
#
# One place that knows how to spawn PowerShell, so the flags are consistent and
# auditable. -NoProfile keeps a user's profile.ps1 from changing what a command
# does (a real supply-chain surface); -NonInteractive makes a cmdlet that would
# otherwise prompt fail fast instead of hanging until run()'s timeout; -Command
# takes the whole script as ONE argv element, so nothing the model supplied is
# ever parsed as PowerShell syntax it did not intend.
# ---------------------------------------------------------------------------

_PS_FLAGS = ("-NoProfile", "-NonInteractive", "-NoLogo", "-OutputFormat", "Text")


def _powershell() -> str | None:
    """The PowerShell executable to use, preferring cross-platform ``pwsh``.

    ``pwsh`` (PowerShell 7+) is preferred when present because its
    ``ConvertTo-Json`` is saner (no depth-2 default surprise, ``-AsArray``
    exists), then Windows PowerShell 5.1 (``powershell``) which is on every
    Windows box. Returns ``None`` when neither is on ``PATH`` — the signal a
    handler uses to degrade instead of raising.
    """
    return which("pwsh") or which("powershell")


def _run_ps(script: str, *, timeout: int = 45) -> CommandResult:
    """Run a PowerShell script as an argv list, or a synthetic failure result.

    The script is passed as a single ``-Command`` argument. It is never
    interpolated into a shell, so a parameter that reached this script (for
    example a service name) cannot break out of it into command syntax.
    """
    exe = _powershell()
    if exe is None:
        return CommandResult(
            argv=("powershell", "-Command", "<not found>"),
            returncode=-1,
            stderr="PowerShell (pwsh/powershell) is not on PATH",
        )
    return run([exe, *_PS_FLAGS, "-Command", script], timeout=timeout)


def _no_powershell(action: Action) -> Observation:
    """A uniform 'PowerShell is unavailable' failure — not 'unsupported'.

    The verb *is* supported on Windows; we simply cannot reach the interpreter
    from here. That is a retryable environment fault, not a fact about the
    platform, so ``unsupported`` stays False and the agent loop may try again
    on a host where PowerShell is present.
    """
    return Observation(
        action=action,
        ok=False,
        platform="windows",
        error="PowerShell not found (looked for pwsh, powershell). "
        "This handler needs it and cannot run without it.",
    )


# ---------------------------------------------------------------------------
# JSON normalisation shared by every ConvertTo-Json parser
# ---------------------------------------------------------------------------


def _load_json(text: str) -> Any:
    """Parse ``ConvertTo-Json`` output, tolerating an empty pipeline.

    A pipeline that produced nothing yields empty stdout (not ``null``), so an
    empty or whitespace string is normalised to ``None`` rather than raising —
    "the command found nothing" is a legitimate answer, not a parse error.
    """
    text = (text or "").strip()
    # A UTF-8 BOM sometimes leads Windows PowerShell output; json.loads chokes
    # on it, so strip it before parsing.
    if text.startswith("\ufeff"):
        text = text[1:]
    if not text:
        return None
    return json.loads(text)


def _as_list(obj: Any) -> list[Any]:
    """Normalise ``ConvertTo-Json`` output to a list.

    This is the fix for the single-object-vs-array collapse described in the
    module docstring: a lone row comes back as a dict, many rows as a list, and
    an empty pipeline as ``None``. Callers want a list either way.
    """
    if obj is None:
        return []
    if isinstance(obj, list):
        return obj
    return [obj]


def _b(value: Any) -> bool | None:
    """Coerce a JSON-ish truthy registry/CIM value to bool, or None if absent.

    Registry DWORDs come back as ``1``/``0``; ``ConvertTo-Json`` may render a
    boolean as ``true``/``false`` or as the string ``"True"``. A missing value
    is ``None`` (absent), which is a different fact from ``False`` (present and
    off) and is kept distinct because a detection gap depends on the difference.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        s = value.strip().lower()
        if s in {"1", "true", "yes", "enabled", "on"}:
            return True
        if s in {"0", "false", "no", "disabled", "off", ""}:
            return False
    return None


# ===========================================================================
# enum parsers
# ===========================================================================


def parse_host_info(text: str) -> dict[str, Any]:
    """``Get-CimInstance Win32_OperatingSystem`` + ``Win32_ComputerSystem`` JSON.

    Uptime is derived here from ``LastBootUpTime`` rather than trusted from the
    command, so it is correct at parse time even if the capture is replayed
    later. ``ConvertTo-Json`` renders CIM datetimes as ISO 8601 under pwsh and
    as ``/Date(ms)/`` under Windows PowerShell 5.1, so both shapes are accepted.
    """
    raw = _load_json(text)
    if not isinstance(raw, dict):
        return {}
    out: dict[str, Any] = {
        "hostname": raw.get("hostname") or raw.get("CSName") or raw.get("Name"),
        "os": raw.get("os_caption") or raw.get("Caption"),
        "version": raw.get("version") or raw.get("Version"),
        "build": str(raw.get("build") or raw.get("BuildNumber") or "") or None,
        "architecture": raw.get("architecture") or raw.get("OSArchitecture"),
        "domain": raw.get("domain") or raw.get("Domain"),
        "part_of_domain": _b(raw.get("part_of_domain")),
        "manufacturer": raw.get("manufacturer"),
        "model": raw.get("model"),
        "logged_on_user": raw.get("logged_on_user") or raw.get("UserName"),
    }
    boot = raw.get("last_boot") or raw.get("LastBootUpTime")
    out["last_boot"] = _normalise_cim_date(boot)
    return {k: v for k, v in out.items() if v is not None}


def _normalise_cim_date(value: Any) -> str | None:
    """Return an ISO-ish date string from either JSON date shape, or None."""
    if not value:
        return None
    if isinstance(value, str):
        m = re.search(r"/Date\((\d+)", value)
        if m:
            # Milliseconds since the Unix epoch; keep it as an int-seconds hint
            # rather than importing tz machinery for a display string.
            return f"epoch_ms:{m.group(1)}"
        return value
    return str(value)


def parse_local_users(text: str, *, include_disabled: bool = True) -> list[dict[str, Any]]:
    """``Get-LocalUser | Select ... | ConvertTo-Json`` into account rows.

    ``Enabled`` is the field that decides whether a filtered result hides an
    account. It is kept as a real bool, and disabled accounts are dropped only
    when the caller asked to (``include_disabled=False``), so the default answer
    is complete.
    """
    rows: list[dict[str, Any]] = []
    for u in _as_list(_load_json(text)):
        if not isinstance(u, dict):
            continue
        enabled = _b(u.get("Enabled"))
        if not include_disabled and enabled is False:
            continue
        rows.append(
            {
                "name": u.get("Name"),
                "enabled": enabled,
                "sid": u.get("SID"),
                "description": u.get("Description") or None,
                "last_logon": _normalise_cim_date(u.get("LastLogon")),
                "password_required": _b(u.get("PasswordRequired")),
                "password_expires": _normalise_cim_date(u.get("PasswordExpires")),
                "password_last_set": _normalise_cim_date(u.get("PasswordLastSet")),
                "source": u.get("PrincipalSource"),
            }
        )
    return [{k: v for k, v in r.items() if v is not None} for r in rows]


def parse_group_members(text: str) -> list[dict[str, Any]]:
    """``Get-LocalGroupMember`` JSON into ``{name, sid, class}`` rows.

    Used for the Administrators group, so ``enum.users`` can say which local
    accounts are privileged without the caller cross-referencing SIDs.
    """
    rows: list[dict[str, Any]] = []
    for m in _as_list(_load_json(text)):
        if not isinstance(m, dict):
            continue
        rows.append(
            {
                "name": m.get("Name"),
                "sid": m.get("SID"),
                "class": m.get("ObjectClass"),
                "source": m.get("PrincipalSource"),
            }
        )
    return [{k: v for k, v in r.items() if v is not None} for r in rows]


# --- whoami /all : fixed-width table parsing --------------------------------
#
# whoami /all is one of the few Windows tools with no structured output mode
# worth using (its /fo csv drops the privileges section's descriptions), so it
# is parsed as the fixed-width tables it prints. The reliable way to parse a
# fixed-width table is not to split on whitespace — a value like
# "BUILTIN\Administrators" or "Group used for deny only" contains spaces — but
# to read the column boundaries from the ==== ruler line and slice by them.


def _ruler_columns(ruler: str) -> list[tuple[int, int]]:
    """Column (start, end) slices from a ``==== ====`` ruler line.

    Each run of ``=`` is one column. The final column is returned open-ended
    (end past the ruler) because the rightmost field — Attributes — routinely
    prints wider than its own header.
    """
    cols: list[tuple[int, int]] = []
    for m in re.finditer(r"=+", ruler):
        cols.append((m.start(), m.end()))
    if cols:
        cols[-1] = (cols[-1][0], 10**6)
    return cols


def _slice_row(line: str, cols: Sequence[tuple[int, int]]) -> list[str]:
    return [line[a:b].strip() for a, b in cols]


def parse_whoami_all(text: str) -> dict[str, Any]:
    """Parse ``whoami /all`` into user, groups, privileges and derived flags.

    Returns ``is_admin`` and ``integrity`` as first-class fields because those
    are the two questions ``enum.privileges`` actually exists to answer, and
    both take reading two different sections to get right. UAC matters here: on
    a filtered (non-elevated) admin token, ``BUILTIN\\Administrators`` is
    present but marked "Group used for deny only", so membership alone would
    over-report admin. The deny-only attribute is checked, not just membership.
    """
    lines = (text or "").splitlines()
    sections = _split_whoami_sections(lines)

    user = _parse_whoami_user(sections.get("USER INFORMATION", []))
    groups = _parse_whoami_table(
        sections.get("GROUP INFORMATION", []),
        ("group", "type", "sid", "attributes"),
    )
    privileges = _parse_whoami_table(
        sections.get("PRIVILEGES INFORMATION", []),
        ("privilege", "description", "state"),
    )

    integrity = None
    admin_member = False
    admin_deny_only = False
    for g in groups:
        name = (g.get("group") or "")
        attrs = (g.get("attributes") or "")
        if "Mandatory Level" in name:
            integrity = name.split("\\")[-1].replace(" Mandatory Level", "").strip()
        if name.lower() in {"builtin\\administrators", "administrators"}:
            admin_member = True
            if "deny only" in attrs.lower():
                admin_deny_only = True

    enabled_privs = sorted(
        p["privilege"] for p in privileges
        if p.get("privilege") and (p.get("state") or "").lower() == "enabled"
    )
    notable = sorted(set(enabled_privs) & _NOTABLE_PRIVILEGES)

    return {
        "user": user.get("user"),
        "sid": user.get("sid"),
        "is_admin": admin_member and not admin_deny_only,
        "admin_member": admin_member,
        "admin_deny_only": admin_deny_only,
        "integrity": integrity,
        "groups": groups,
        "privileges": privileges,
        "enabled_privileges": enabled_privs,
        "notable_privileges": notable,
    }


#: Privileges that hand a low-priv account a realistic path to SYSTEM. Named so
#: that vuln.privilege_path can reason about them without re-deriving the list.
_NOTABLE_PRIVILEGES = frozenset(
    {
        "SeImpersonatePrivilege",
        "SeAssignPrimaryTokenPrivilege",
        "SeDebugPrivilege",
        "SeBackupPrivilege",
        "SeRestorePrivilege",
        "SeTakeOwnershipPrivilege",
        "SeLoadDriverPrivilege",
        "SeTcbPrivilege",
        "SeCreateTokenPrivilege",
        "SeManageVolumePrivilege",
    }
)


def _split_whoami_sections(lines: Sequence[str]) -> dict[str, list[str]]:
    """Group whoami output into its ALL-CAPS sections (title on a line, then ---)."""
    sections: dict[str, list[str]] = {}
    current: str | None = None
    titles = {"USER INFORMATION", "GROUP INFORMATION", "PRIVILEGES INFORMATION"}
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped in titles:
            current = stripped
            sections[current] = []
            continue
        if current is not None:
            sections[current].append(line)
    return sections


def _parse_whoami_user(block: Sequence[str]) -> dict[str, Any]:
    cols, data = _find_table(block)
    if not data:
        return {}
    row = _slice_row(data[0], cols) if cols else data[0].split()
    if len(row) >= 2:
        return {"user": row[0], "sid": row[1]}
    if row:
        return {"user": row[0]}
    return {}


def _parse_whoami_table(block: Sequence[str], keys: Sequence[str]) -> list[dict[str, Any]]:
    cols, data = _find_table(block)
    out: list[dict[str, Any]] = []
    for line in data:
        fields = _slice_row(line, cols) if cols else re.split(r"\s{2,}", line.strip())
        row = {}
        for k, v in zip(keys, fields):
            if v:
                row[k] = v
        if row:
            out.append(row)
    return out


def _find_table(block: Sequence[str]) -> tuple[list[tuple[int, int]], list[str]]:
    """Locate the ``====`` ruler in a section and return its columns + data rows."""
    ruler_idx = None
    for i, line in enumerate(block):
        if line.strip() and set(line.strip()) <= {"=", " "}:
            ruler_idx = i
            break
    if ruler_idx is None:
        return [], []
    cols = _ruler_columns(block[ruler_idx])
    data = [ln for ln in block[ruler_idx + 1:] if ln.strip()]
    return cols, data


def parse_processes(text: str) -> list[dict[str, Any]]:
    """``Win32_Process`` JSON into ``{pid, ppid, name, cmdline, path, user}``.

    Command line and parent pid are the whole point of using ``Win32_Process``
    over ``Get-Process``: the parent-child edge is what turns a process list into
    a tree an analyst can reason about, and the command line is where the
    interesting arguments live. Owner is best-effort — resolving it needs an
    extra CIM call per process that may be denied — so ``user`` may be absent.
    """
    rows: list[dict[str, Any]] = []
    for p in _as_list(_load_json(text)):
        if not isinstance(p, dict):
            continue
        rows.append(
            {
                "pid": p.get("ProcessId") or p.get("pid"),
                "ppid": p.get("ParentProcessId") or p.get("ppid"),
                "name": p.get("Name") or p.get("name"),
                "cmdline": p.get("CommandLine") or p.get("cmdline") or None,
                "path": p.get("ExecutablePath") or p.get("path") or None,
                "user": p.get("Owner") or p.get("user") or None,
            }
        )
    return [{k: v for k, v in r.items() if v is not None} for r in rows]


def parse_services(text: str) -> list[dict[str, Any]]:
    """``Win32_Service`` JSON into service rows, keeping ``path`` (PathName).

    ``path`` is load-bearing downstream: ``vuln.weak_permissions`` keys its
    unquoted-path and writable-binary checks off it, and the exploit verbs act
    on it. ``run_as`` (StartName) matters too — a writable binary is only a
    privilege escalation if the service runs as something more privileged than
    the attacker.
    """
    rows: list[dict[str, Any]] = []
    for s in _as_list(_load_json(text)):
        if not isinstance(s, dict):
            continue
        rows.append(
            {
                "name": s.get("Name"),
                "display_name": s.get("DisplayName") or None,
                "state": s.get("State"),
                "start_mode": s.get("StartMode"),
                "path": s.get("PathName") or None,
                "run_as": s.get("StartName") or None,
                "pid": s.get("ProcessId") or None,
            }
        )
    return [{k: v for k, v in r.items() if v is not None} for r in rows]


def parse_persistence(text: str) -> dict[str, Any]:
    """Normalise the composite persistence sweep JSON into named buckets.

    ``enum.persistence`` is one verb with many sources on Windows — Run/RunOnce
    keys in both hives, scheduled tasks, auto-start services, WMI event
    subscriptions and startup folders — so the handler gathers them into one
    object and this normalises whatever subset came back. Missing buckets are
    returned empty rather than absent so a consumer can iterate all five without
    guarding each.
    """
    raw = _load_json(text)
    raw = raw if isinstance(raw, dict) else {}

    run_keys = []
    for r in _as_list(raw.get("run_keys")):
        if isinstance(r, dict) and r.get("name"):
            run_keys.append(
                {
                    "kind": "run_key",
                    "hive": r.get("hive"),
                    "name": r.get("name"),
                    "command": r.get("command"),
                    "id": f"run_key:{r.get('hive')}\\{r.get('name')}",
                }
            )

    tasks = []
    for t in _as_list(raw.get("scheduled_tasks")):
        if isinstance(t, dict) and t.get("name"):
            path = t.get("path") or "\\"
            tasks.append(
                {
                    "kind": "scheduled_task",
                    "name": t.get("name"),
                    "path": path,
                    "action": t.get("action"),
                    "author": t.get("author"),
                    "state": t.get("state"),
                    "id": f"scheduled_task:{path}{t.get('name')}",
                }
            )

    startup = []
    for f in _as_list(raw.get("startup_folder")):
        if isinstance(f, dict) and f.get("path"):
            startup.append(
                {
                    "kind": "startup_folder",
                    "path": f.get("path"),
                    "name": f.get("name"),
                    "id": f"startup_folder:{f.get('path')}",
                }
            )

    wmi = []
    for w in _as_list(raw.get("wmi_subscriptions")):
        if isinstance(w, dict) and w.get("name"):
            wmi.append(
                {
                    "kind": "wmi_subscription",
                    "name": w.get("name"),
                    "consumer_type": w.get("consumer_type"),
                    "command": w.get("command"),
                    "id": f"wmi_subscription:{w.get('name')}",
                }
            )

    services = []
    for s in _as_list(raw.get("auto_services")):
        if isinstance(s, dict) and s.get("name"):
            services.append(
                {
                    "kind": "service",
                    "name": s.get("name"),
                    "path": s.get("path"),
                    "start_mode": s.get("start_mode"),
                    "id": f"service:{s.get('name')}",
                }
            )

    entries = run_keys + tasks + startup + wmi + services
    return {
        "run_keys": run_keys,
        "scheduled_tasks": tasks,
        "startup_folder": startup,
        "wmi_subscriptions": wmi,
        "services": services,
        "count": len(entries),
        "entries": entries,
    }


def parse_network(text: str) -> dict[str, Any]:
    """Composite network JSON: interfaces, routes, TCP and UDP endpoints.

    TCP rows carry the owning process (pid resolved to a name in PowerShell via
    the ``OwningProcess`` field of ``Get-NetTCPConnection``), which is the field
    that turns "something is listening on 4444" into "``rat.exe`` is listening on
    4444". Listening sockets are separated from established connections because
    an analyst triages them differently.
    """
    raw = _load_json(text)
    raw = raw if isinstance(raw, dict) else {}

    interfaces = []
    for i in _as_list(raw.get("interfaces")):
        if isinstance(i, dict):
            interfaces.append(
                {
                    "interface": i.get("InterfaceAlias") or i.get("interface"),
                    "address": i.get("IPAddress") or i.get("address"),
                    "family": i.get("AddressFamily") or i.get("family"),
                    "prefix": i.get("PrefixLength"),
                }
            )

    routes = []
    for r in _as_list(raw.get("routes")):
        if isinstance(r, dict):
            routes.append(
                {
                    "destination": r.get("DestinationPrefix") or r.get("destination"),
                    "next_hop": r.get("NextHop") or r.get("next_hop"),
                    "interface": r.get("InterfaceAlias") or r.get("interface"),
                }
            )

    tcp = []
    for c in _as_list(raw.get("tcp")):
        if isinstance(c, dict):
            tcp.append(
                {
                    "local": f"{c.get('LocalAddress')}:{c.get('LocalPort')}",
                    "remote": f"{c.get('RemoteAddress')}:{c.get('RemotePort')}",
                    "state": c.get("State"),
                    "pid": c.get("OwningProcess"),
                    "process": c.get("Process") or c.get("process"),
                }
            )

    udp = []
    for c in _as_list(raw.get("udp")):
        if isinstance(c, dict):
            udp.append(
                {
                    "local": f"{c.get('LocalAddress')}:{c.get('LocalPort')}",
                    "pid": c.get("OwningProcess"),
                    "process": c.get("Process") or c.get("process"),
                }
            )

    listening = [t for t in tcp if (t.get("state") or "").lower() == "listen"]
    return {
        "interfaces": interfaces,
        "routes": routes,
        "tcp": tcp,
        "udp": udp,
        "listening": listening,
        "established": [t for t in tcp if (t.get("state") or "").lower() == "established"],
    }


def parse_netstat_ano(text: str) -> list[dict[str, Any]]:
    """Fallback socket parser for ``netstat -ano`` when the Net cmdlets are absent.

    Older or minimal hosts may not have the NetTCPIP module, so this scrapes the
    classic netstat table. The columns are fixed by netstat, not the terminal,
    so a whitespace split is safe here (unlike whoami). Kept as a fallback, not
    the primary path, because it loses the process *name* — netstat only prints
    the pid.
    """
    rows: list[dict[str, Any]] = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0] not in {"TCP", "UDP"}:
            continue
        proto = parts[0]
        local = parts[1]
        if proto == "TCP" and len(parts) >= 5:
            remote, state, pid = parts[2], parts[3], parts[4]
        else:
            remote, state, pid = (parts[2] if len(parts) > 2 else ""), "", parts[-1]
        rows.append(
            {
                "proto": proto,
                "local": local,
                "remote": remote or None,
                "state": state or None,
                "pid": int(pid) if pid.isdigit() else None,
            }
        )
    return [{k: v for k, v in r.items() if v is not None} for r in rows]


def parse_software(text: str) -> dict[str, Any]:
    """Composite ``{software: [...], hotfixes: [...]}`` from Uninstall keys + Get-HotFix.

    Installed software comes from the Uninstall registry keys rather than
    ``Get-Package`` because the registry view is the one that sees MSI *and*
    per-user installs; hotfixes come from ``Get-HotFix`` (the Win32_QuickFixEngineering
    view), which is what ``vuln.patch_gap`` correlates against a build number.
    """
    raw = _load_json(text)
    raw = raw if isinstance(raw, dict) else {}

    software = []
    for s in _as_list(raw.get("software")):
        if isinstance(s, dict) and s.get("DisplayName"):
            software.append(
                {
                    "name": s.get("DisplayName"),
                    "version": s.get("DisplayVersion") or None,
                    "publisher": s.get("Publisher") or None,
                    "install_date": s.get("InstallDate") or None,
                }
            )

    hotfixes = []
    for h in _as_list(raw.get("hotfixes")):
        if isinstance(h, dict) and h.get("HotFixID"):
            hotfixes.append(
                {
                    "id": h.get("HotFixID"),
                    "description": h.get("Description") or None,
                    "installed_on": _normalise_cim_date(h.get("InstalledOn")),
                }
            )

    return {
        "software": [{k: v for k, v in s.items() if v is not None} for s in software],
        "hotfixes": [{k: v for k, v in h.items() if v is not None} for h in hotfixes],
    }


def parse_shares(text: str) -> list[dict[str, Any]]:
    """``Get-SmbShare`` (+ ``Get-SmbShareAccess``) JSON into share rows with ACL.

    The access-control list is folded onto each share so a reader sees "who can
    reach C$" in one row rather than having to join two tables. Administrative
    shares (names ending in ``$``) are flagged, not hidden — they are exactly the
    ones an exercise cares about.
    """
    rows: list[dict[str, Any]] = []
    for s in _as_list(_load_json(text)):
        if not isinstance(s, dict) or not s.get("Name"):
            continue
        access = []
        for a in _as_list(s.get("Access")):
            if isinstance(a, dict):
                access.append(
                    {
                        "account": a.get("AccountName"),
                        "rights": a.get("AccessRight"),
                        "type": a.get("AccessControlType"),
                    }
                )
        name = s.get("Name")
        rows.append(
            {
                "name": name,
                "path": s.get("Path") or None,
                "description": s.get("Description") or None,
                "administrative": bool(name.endswith("$")),
                "access": access,
            }
        )
    return rows


# ===========================================================================
# detect parsers
# ===========================================================================


def parse_auditpol_csv(text: str) -> dict[str, str]:
    """``auditpol /get /category:* /r`` CSV into ``subcategory -> setting``.

    ``/r`` is the machine-readable CSV form; its columns are Machine Name, Policy
    Target, Subcategory, Subcategory GUID, Inclusion Setting, Exclusion Setting.
    The inclusion setting ("Success", "Success and Failure", "No Auditing") is the
    one that answers "is this being logged", so that is what is mapped. Parsed by
    hand rather than with :mod:`csv` because the values never contain commas and
    keeping it dependency-light keeps the parser importable anywhere.
    """
    out: dict[str, str] = {}
    header_seen = False
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split(",")]
        if not header_seen and "Subcategory" in parts:
            header_seen = True
            continue
        # Rows have 6 columns; subcategory is index 2, inclusion setting index 4.
        if len(parts) >= 5 and parts[2]:
            out[parts[2]] = parts[4]
    return out


def parse_winevent_log(text: str) -> list[dict[str, Any]]:
    """``Get-WinEvent -ListLog`` JSON into per-log status rows.

    ``IsEnabled`` plus ``RecordCount`` answers the blunt question at the bottom
    of every Windows detection story: is the Security log even being written? A
    disabled Security log or one whose ``RecordCount`` is suspiciously low is not
    a subtle detection-engineering gap, it is the finding.
    """
    rows: list[dict[str, Any]] = []
    for lg in _as_list(_load_json(text)):
        if not isinstance(lg, dict):
            continue
        rows.append(
            {
                "log": lg.get("LogName"),
                "enabled": _b(lg.get("IsEnabled")),
                "records": lg.get("RecordCount"),
                "max_bytes": lg.get("MaximumSizeInBytes"),
                "mode": lg.get("LogMode"),
                "last_write": _normalise_cim_date(lg.get("LastWriteTime")),
            }
        )
    return [{k: v for k, v in r.items() if v is not None} for r in rows]


def parse_winevent_events(text: str) -> list[dict[str, Any]]:
    """Projected event JSON (``{id, time, provider, log, data}``) into rows.

    The handler asks PowerShell to flatten each event's ``EventData`` (via
    ``$_.ToXml()``) into a ``data`` dict before serialising, because pulling
    fields out of the localised ``Message`` string is exactly the terminal-width
    fragility this whole adapter avoids. So the parser just normalises the
    already-structured projection: id to int, data to a plain dict.
    """
    rows: list[dict[str, Any]] = []
    for e in _as_list(_load_json(text)):
        if not isinstance(e, dict):
            continue
        data = e.get("data")
        if not isinstance(data, dict):
            data = {}
        rows.append(
            {
                "id": int(e["id"]) if str(e.get("id", "")).isdigit() else e.get("id"),
                "time": e.get("time"),
                "provider": e.get("provider"),
                "log": e.get("log"),
                "data": {k: v for k, v in data.items() if k},
            }
        )
    return rows


def parse_sysmon_status(text: str) -> dict[str, Any]:
    """Sysmon presence JSON into ``{installed, driver, service, config_hash}``.

    Sysmon is the richest single source of Windows endpoint telemetry, so
    ``detect.telemetry`` leads with "is it here and what is it configured with".
    ``installed`` is true only if the service *and* the driver are present — a
    half-removed Sysmon logs nothing but leaves a service entry that would fool a
    membership-only check.
    """
    raw = _load_json(text)
    raw = raw if isinstance(raw, dict) else {}
    services = [s for s in _as_list(raw.get("services")) if isinstance(s, dict)]
    running = [s.get("Name") for s in services if (s.get("Status") or "").lower() == "running"]
    driver = _b(raw.get("driver_registered"))
    return {
        "installed": bool(services) and bool(driver),
        "driver_registered": driver,
        "services": [
            {"name": s.get("Name"), "status": s.get("Status")} for s in services
        ],
        "running": [r for r in running if r],
        "config_hash": raw.get("config_hash") or None,
    }


def parse_reg_values(text: str) -> dict[str, Any]:
    """Generic ``[pscustomobject]{...} | ConvertTo-Json`` of registry values.

    Used for the audit-policy and PowerShell-logging registry flags, where a
    value is either a DWORD or absent. Values are coerced to bool-or-None so a
    consumer can tell "off" from "never configured", which is the distinction a
    detection gap turns on.
    """
    raw = _load_json(text)
    raw = raw if isinstance(raw, dict) else {}
    return {k: _b(v) for k, v in raw.items() if not k.startswith("PS")}


def assess_telemetry(
    *,
    sysmon: Mapping[str, Any] | None,
    logs: Sequence[Mapping[str, Any]] | None,
    audit: Mapping[str, str] | None,
    ps_logging: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Fold the four telemetry probes into one verdict, with an explicit gap list.

    This is deliberately pure so it can be tested without a Windows box: the four
    inputs are exactly what the four parsers above return. The ``gaps`` list is
    the product — every gap here is a foundation for a later ``detect.*`` finding,
    and reporting them once, up front, is what stops a red run from generating
    forty "nothing fired" findings that all trace back to one switched-off audit
    subcategory.
    """
    audit = dict(audit or {})
    logs = list(logs or [])
    ps_logging = dict(ps_logging or {})
    sysmon = dict(sysmon or {})

    by_log = { (lg.get("log") or ""): lg for lg in logs }
    security = by_log.get("Security", {})

    proc_audit = audit.get("Process Creation", "")
    cmdline = bool(ps_logging.get("cmdline_audit"))
    scriptblock = bool(ps_logging.get("scriptblock"))

    gaps: list[str] = []
    if security and security.get("enabled") is False:
        gaps.append("Security event log is disabled — nothing is being written to it")
    if "No Auditing" in proc_audit or proc_audit == "":
        gaps.append(
            "Process creation auditing (4688) is off — process-creation "
            "detections cannot fire"
        )
    if proc_audit and "No Auditing" not in proc_audit and not cmdline:
        gaps.append(
            "4688 is on but command-line logging is off — process events lack "
            "the argument line, so most process-based rules are blind"
        )
    if not scriptblock:
        gaps.append(
            "PowerShell script-block logging (4104) is off — PowerShell "
            "tradecraft is invisible"
        )
    if not sysmon.get("installed"):
        gaps.append(
            "Sysmon is not installed — no image-load, network-connection or "
            "process-access telemetry"
        )

    return {
        "sysmon": sysmon,
        "process_creation_audit": proc_audit or "No Auditing",
        "command_line_logging": cmdline,
        "scriptblock_logging": scriptblock,
        "module_logging": bool(ps_logging.get("module_logging")),
        "transcription": bool(ps_logging.get("transcription")),
        "logs": logs,
        "security_log_enabled": security.get("enabled") if security else None,
        "gaps": gaps,
        "gap_count": len(gaps),
    }


# ===========================================================================
# vuln parsers / analysers (all pure)
# ===========================================================================


def parse_pathname(pathname: str) -> dict[str, Any]:
    """Split a service ``PathName`` into executable + arguments, noting quoting.

    A service PathName is a command line, not just a path: ``"C:\\Program
    Files\\App\\svc.exe" -k netsvcs``. Whether the executable is quoted is the
    entire question behind the unquoted-service-path vulnerability, so it is
    surfaced as ``quoted``.
    """
    s = (pathname or "").strip()
    if not s:
        return {"executable": "", "arguments": "", "quoted": False}
    if s.startswith('"'):
        end = s.find('"', 1)
        if end != -1:
            return {
                "executable": s[1:end],
                "arguments": s[end + 1:].strip(),
                "quoted": True,
            }
        return {"executable": s.strip('"'), "arguments": "", "quoted": True}
    # Unquoted: the executable is everything up to the first .exe token, but the
    # *vulnerability* is about the spaces before it, so keep the whole head as
    # the executable and let the interception analysis look at the spaces.
    m = re.search(r"\.exe(\s|$)", s, re.IGNORECASE)
    if m:
        return {
            "executable": s[: m.end() - len(m.group(1))].strip(),
            "arguments": s[m.end():].strip(),
            "quoted": False,
        }
    parts = s.split(" ", 1)
    return {
        "executable": parts[0],
        "arguments": parts[1] if len(parts) > 1 else "",
        "quoted": False,
    }


def interception_paths(pathname: str) -> list[str]:
    """The paths Windows would try, in order, for an unquoted service path.

    For ``C:\\Program Files\\Sub Dir\\svc.exe`` the service control manager tries
    ``C:\\Program.exe``, then ``C:\\Program Files\\Sub.exe``, then the real
    binary. Each earlier path a low-priv user can write is a place to plant a
    binary that runs as the service account. Only paths that are genuinely
    ambiguous (a space in a directory component) produce interception points, so
    a quoted path or a spaceless path returns an empty list.
    """
    info = parse_pathname(pathname)
    if info["quoted"]:
        return []
    exe = info["executable"]
    if not exe or " " not in exe:
        return []
    # Windows resolves an unquoted path by trying, at every space, the text up to
    # that space with ".exe" appended. So "C:\Program Files\Sub Dir\svc.exe"
    # yields "C:\Program.exe" (at the first space) and
    # "C:\Program Files\Sub.exe" (at the second) before the real binary — each an
    # interception point. The earlier bug split at only the first space and so
    # produced "C:\Program.exe" twice; iterating over every space is what makes
    # the second point appear.
    candidates: list[str] = []
    for m in re.finditer(r" ", exe):
        candidate = exe[: m.start()] + ".exe"
        if candidate.lower() != exe.lower() and candidate not in candidates:
            candidates.append(candidate)
    return candidates


def find_unquoted_service_paths(services: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Services whose unquoted PathName has a real interception point.

    Only services that both (a) have an unquoted path with a space and (b) run
    as something more privileged than a normal user are worth reporting, but the
    privilege judgement is left to ``vuln.privilege_path``; here we report every
    structurally-vulnerable path and note the run-as account so the caller can
    prioritise.
    """
    out: list[dict[str, Any]] = []
    for s in services:
        path = s.get("path") or ""
        info = parse_pathname(path)
        if info["quoted"]:
            continue
        points = interception_paths(path)
        if not points:
            continue
        out.append(
            {
                "service": s.get("name"),
                "path": path,
                "run_as": s.get("run_as"),
                "interception_points": points,
                "attck": "T1574.009",
            }
        )
    return out


def scan_for_credentials(text: str, source: str, *, redact: bool = True) -> list[dict[str, Any]]:
    """Scan one blob of text for credential-shaped strings.

    Pure and source-agnostic, so it can be run over a shell history, a
    ``web.config``, an unattend file or a registry export with the same code and
    tested against a fixture. With ``redact=True`` (the default that
    ``vuln.credential_exposure`` uses) the finding names *what* leaked and where,
    and replaces the secret with a fingerprint — enough to prove exposure and
    de-duplicate, never the secret itself.
    """
    findings: list[dict[str, Any]] = []
    for lineno, line in enumerate((text or "").splitlines(), start=1):
        for label, pattern in _CREDENTIAL_PATTERNS:
            for m in pattern.finditer(line):
                secret = m.group("secret") if "secret" in m.groupdict() else m.group(0)
                if not secret or len(secret) < 3:
                    continue
                findings.append(
                    {
                        "source": source,
                        "line": lineno,
                        "kind": label,
                        "match": _redact_secret(secret) if redact else secret,
                        "redacted": redact,
                    }
                )
    return findings


#: Deliberately conservative patterns. Each is anchored on a key/label so a bare
#: high-entropy string does not trip it — the goal is "a credential is sitting in
#: cleartext here", which is a specific, defensible finding, not "this looks
#: random". Extending this list is how the blue side improves the check.
_CREDENTIAL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("password_assignment", re.compile(
        r"(?i)(?:password|passwd|pwd)\s*[:=]\s*(?P<secret>[^\s'\";]{3,})")),
    ("connection_string", re.compile(
        r"(?i)(?:pwd|password)\s*=\s*(?P<secret>[^;]{3,})")),
    ("autologon", re.compile(
        r"(?i)DefaultPassword\s*[:=]\s*(?P<secret>\S{3,})")),
    ("api_key", re.compile(
        r"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?key)\s*[:=]\s*(?P<secret>[A-Za-z0-9/+_\-]{8,})")),
    ("aws_key", re.compile(r"(?P<secret>AKIA[0-9A-Z]{16})")),
    ("private_key", re.compile(r"(?P<secret>-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)")),
    ("unattend_password", re.compile(
        r"(?i)<Password>\s*<Value>(?P<secret>[^<]{3,})</Value>")),
)


def _redact_secret(secret: str) -> str:
    """A stable, non-reversible fingerprint of a secret, for de-duplication.

    Shows the length and a short hash so two findings of the same leaked
    password can be seen to be the same without the password ever being written
    down. Uses the standard library only (no hashlib import cost beyond what is
    already loaded elsewhere is required — a short FNV-style digest is enough for
    de-dup and is intentionally not cryptographic, because it must never be
    treated as reversible).
    """
    h = 0x811C9DC5
    for ch in secret.encode("utf-8", "replace"):
        h = ((h ^ ch) * 0x01000193) & 0xFFFFFFFF
    return f"<redacted len={len(secret)} fp={h:08x}>"


def build_privilege_paths(
    *,
    privileges: Mapping[str, Any],
    services: Sequence[Mapping[str, Any]],
    weak_permissions: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Compose enum + vuln observations into concrete escalation chains.

    Returns chains, not a score — a chain is a sequence of steps an operator (or
    ``postex.privilege_escalate``) can actually execute, whereas a score is a
    number in a report nobody acts on. Three chain families are recognised, each
    keyed off data the other verbs already produced:

    * a writable service binary on a service that runs as SYSTEM/LocalSystem;
    * an unquoted service path with a writable interception point;
    * a notable token privilege (SeImpersonate → a potato-family chain).
    """
    chains: list[dict[str, Any]] = []
    priv_admin = bool(privileges.get("is_admin"))
    notable = set(privileges.get("notable_privileges") or ())

    writable = {w.get("service"): w for w in weak_permissions.get("writable_binaries", [])}
    unquoted = {u.get("service"): u for u in weak_permissions.get("unquoted_paths", [])}

    for s in services:
        name = s.get("name")
        run_as = (s.get("run_as") or "").lower()
        privileged = run_as in {"localsystem", "", "nt authority\\system"} or "system" in run_as
        if name in writable and privileged:
            chains.append(
                {
                    "id": f"chain:service_binary:{name}",
                    "kind": "writable_service_binary",
                    "steps": [
                        f"service {name} runs as {s.get('run_as') or 'LocalSystem'}",
                        f"its binary {writable[name].get('path')} is writable by the current user",
                        "replace the binary and restart the service (exploit.service_permissions)",
                    ],
                    "exploit": "exploit.service_permissions",
                    "service": name,
                }
            )
        if name in unquoted and privileged:
            chains.append(
                {
                    "id": f"chain:unquoted_path:{name}",
                    "kind": "unquoted_service_path",
                    "steps": [
                        f"service {name} has unquoted path {unquoted[name].get('path')}",
                        f"interception point {unquoted[name].get('interception_points', ['?'])[0]}",
                        "plant a binary at the interception point (exploit.unquoted_path)",
                    ],
                    "exploit": "exploit.unquoted_path",
                    "service": name,
                }
            )

    if not priv_admin and "SeImpersonatePrivilege" in notable:
        chains.append(
            {
                "id": "chain:seimpersonate",
                "kind": "token_impersonation",
                "steps": [
                    "current token holds SeImpersonatePrivilege",
                    "coerce a SYSTEM service to authenticate and impersonate it",
                    "(potato-family; postex.privilege_escalate)",
                ],
                "exploit": "postex.privilege_escalate",
                "privilege": "SeImpersonatePrivilege",
            }
        )

    return chains


def parse_cmdkey_list(text: str) -> list[dict[str, Any]]:
    """``cmdkey /list`` text into stored-credential targets — names only.

    ``cmdkey`` never prints the secret, only the target and the user it is stored
    for, which is exactly the redacted view ``postex.credential_dump`` wants: it
    proves "there are saved credentials for these targets" without touching
    secret material.
    """
    rows: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    for line in (text or "").splitlines():
        s = line.strip()
        if s.lower().startswith("target:"):
            if current:
                rows.append(current)
            current = {"target": s.split(":", 1)[1].strip()}
        elif s.lower().startswith("type:"):
            current["type"] = s.split(":", 1)[1].strip()
        elif s.lower().startswith("user:"):
            current["user"] = s.split(":", 1)[1].strip()
    if current:
        rows.append(current)
    return rows


# ===========================================================================
# Red-verb file/registry primitives — sandbox-testable, honest about cleanup
# ===========================================================================


def stage_file_replacement(target: str, payload: bytes, workdir: str) -> dict[str, Any]:
    """Back up ``target`` into ``workdir`` and overwrite it with ``payload``.

    Returns a manifest recording the original path, the backup path and the
    bytes written — everything a human needs to undo the change by hand if the
    automatic restore later fails. This is the write primitive behind
    ``exploit.service_permissions``; it is exercised only against a temp sandbox
    in the tests, never a live service binary, per adapter-contract rule 6.
    """
    target_p = Path(target)
    backup = Path(workdir) / (target_p.name + ".whetstone.bak")
    original = target_p.read_bytes() if target_p.exists() else None
    if original is not None:
        backup.write_bytes(original)
    target_p.write_bytes(payload)
    return {
        "target": str(target_p),
        "backup": str(backup) if original is not None else None,
        "original_existed": original is not None,
        "bytes_written": len(payload),
    }


def restore_file_replacement(manifest: Mapping[str, Any]) -> bool:
    """Undo a :func:`stage_file_replacement`, returning whether it fully succeeded.

    Truthful by construction: it returns ``False`` if the backup is missing or a
    write fails, so a caller can report a *failed* cleanup rather than assuming
    one that never happened — a silently-failed restore is worse than one that
    never ran (rule 6).
    """
    target = manifest.get("target")
    backup = manifest.get("backup")
    if not target:
        return False
    try:
        if backup and Path(backup).exists():
            Path(target).write_bytes(Path(backup).read_bytes())
            Path(backup).unlink(missing_ok=True)
            return True
        if not manifest.get("original_existed"):
            # We created the file; removing it is the correct restore.
            Path(target).unlink(missing_ok=True)
            return True
        return False
    except OSError:
        return False


def stage_planted_file(path: str, payload: bytes) -> dict[str, Any]:
    """Create a file at ``path`` (an unquoted-path interception point), no clobber.

    Refuses to overwrite an existing file, because the interception attack is
    about a path that is *empty* — if something is already there, planting would
    be destroying an unrelated file, which the verb must never do.
    """
    p = Path(path)
    if p.exists():
        return {"path": str(p), "planted": False, "reason": "path already exists"}
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(payload)
    return {"path": str(p), "planted": True, "bytes_written": len(payload)}


def remove_planted_file(manifest: Mapping[str, Any]) -> bool:
    """Delete a file :func:`stage_planted_file` created; True only if it is gone."""
    if not manifest.get("planted"):
        return False
    try:
        Path(manifest["path"]).unlink(missing_ok=True)
        return not Path(manifest["path"]).exists()
    except OSError:
        return False


def _marker_payload(tag: str) -> bytes:
    """A benign, obviously-inert proof-of-control payload.

    Never an executable. It is a text marker naming Whetstone and the run, so
    that if cleanup ever fails a responder who finds it on disk immediately knows
    what wrote it and that it is not live adversary tooling.
    """
    return (
        f"WHETSTONE PURPLE-TEAM MARKER — inert proof of write access.\n"
        f"tag={tag}\n"
        f"This file is not executable and does nothing. Safe to delete.\n"
    ).encode("utf-8")


# ===========================================================================
# The adapter
# ===========================================================================


@register_adapter
class WindowsAdapter(Adapter):
    """Windows implementation of the verb catalogue.

    Handlers are registered below the class with ``@WindowsAdapter.implements``.
    Each is the thin half of the split the module docstring describes: build an
    argv, run it, hand the stdout to a pure parser. When PowerShell is missing
    the handler returns a failed (not unsupported) observation, because the verb
    remains a Windows concept even on a host where the interpreter is absent.
    """

    platform = "windows"

    # -- small internal helpers used across handlers ------------------------

    def _is_elevated(self) -> bool | None:
        """Best-effort 'are we an elevated admin', or None if we cannot tell.

        Used by the MODIFY/red handlers to say honestly "this needs privileges I
        do not have" instead of attempting a change that will half-succeed.
        """
        res = _run_ps(
            "([Security.Principal.WindowsPrincipal]"
            "[Security.Principal.WindowsIdentity]::GetCurrent())"
            ".IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)"
        )
        if not res.ok:
            return None
        return res.stdout.strip().lower().startswith("true")


# ---------------------------------------------------------------------------
# enum handlers
# ---------------------------------------------------------------------------


@WindowsAdapter.implements("enum.host")
def _enum_host(self: WindowsAdapter, verb: Verb, action: Action) -> Any:
    if _powershell() is None:
        return _no_powershell(action)
    script = (
        "$os=Get-CimInstance Win32_OperatingSystem;"
        "$cs=Get-CimInstance Win32_ComputerSystem;"
        "[pscustomobject]@{"
        "hostname=$env:COMPUTERNAME;"
        "os_caption=$os.Caption; version=$os.Version; build=$os.BuildNumber;"
        "architecture=$os.OSArchitecture; last_boot=$os.LastBootUpTime;"
        "domain=$cs.Domain; part_of_domain=$cs.PartOfDomain;"
        "manufacturer=$cs.Manufacturer; model=$cs.Model;"
        "logged_on_user=$cs.UserName"
        "} | ConvertTo-Json -Depth 3 -Compress"
    )
    res = _run_ps(script)
    if not res.ok:
        return _failed(action, res, "could not read host information")
    return parse_host_info(res.stdout)


@WindowsAdapter.implements("enum.users")
def _enum_users(self: WindowsAdapter, verb: Verb, action: Action) -> Any:
    if _powershell() is None:
        return _no_powershell(action)
    include_disabled = bool(action.params.get("include_disabled", False))
    users_res = _run_ps(
        "Get-LocalUser | Select-Object Name,Enabled,SID,Description,LastLogon,"
        "PasswordRequired,PasswordExpires,PasswordLastSet,PrincipalSource | "
        "ConvertTo-Json -Depth 3"
    )
    if not users_res.ok:
        return _failed(action, users_res, "could not enumerate local users")
    users = parse_local_users(users_res.stdout, include_disabled=include_disabled)

    admins_res = _run_ps(
        "Get-LocalGroupMember -Group Administrators -ErrorAction SilentlyContinue | "
        "Select-Object Name,SID,ObjectClass,PrincipalSource | ConvertTo-Json -Depth 3"
    )
    admins = parse_group_members(admins_res.stdout) if admins_res.ok else []
    admin_names = {a.get("name") for a in admins}
    for u in users:
        # A local account that is a direct member of Administrators is flagged so
        # the reader does not have to join SIDs by hand.
        u["is_administrator"] = u.get("name") in admin_names

    return {"users": users, "administrators": admins, "count": len(users)}


@WindowsAdapter.implements("enum.privileges")
def _enum_privileges(self: WindowsAdapter, verb: Verb, action: Action) -> Any:
    whoami = which("whoami")
    if whoami is None:
        return _no_powershell(action) if _powershell() is None else Observation(
            action=action, ok=False, platform="windows",
            error="whoami.exe not found; cannot read token privileges",
        )
    res = run([whoami, "/all"])
    if not res.ok:
        return _failed(action, res, "whoami /all failed")
    return parse_whoami_all(res.stdout)


@WindowsAdapter.implements("enum.processes")
def _enum_processes(self: WindowsAdapter, verb: Verb, action: Action) -> Any:
    if _powershell() is None:
        return _no_powershell(action)
    # GetOwner is called per-process; SilentlyContinue keeps a denied owner
    # lookup from aborting the whole enumeration.
    # GetOwner is computed into a plain variable first: an `if` is a statement,
    # not a value, so it cannot appear on the right of a hashtable key.
    script = (
        "Get-CimInstance Win32_Process | ForEach-Object {"
        "$o=$null; try { $o=Invoke-CimMethod -InputObject $_ -MethodName GetOwner"
        " -ErrorAction Stop } catch {};"
        "$own=$null; if($o -and $o.User){ $own=((@($o.Domain,$o.User) |"
        " Where-Object {$_}) -join '\\') };"
        "[pscustomobject]@{ProcessId=$_.ProcessId; ParentProcessId=$_.ParentProcessId;"
        " Name=$_.Name; CommandLine=$_.CommandLine; ExecutablePath=$_.ExecutablePath;"
        " Owner=$own}"
        "} | ConvertTo-Json -Depth 3"
    )
    res = _run_ps(script, timeout=60)
    if not res.ok:
        return _failed(action, res, "could not enumerate processes")
    procs = parse_processes(res.stdout)
    return {"processes": procs, "count": len(procs)}


@WindowsAdapter.implements("enum.services")
def _enum_services(self: WindowsAdapter, verb: Verb, action: Action) -> Any:
    if _powershell() is None:
        return _no_powershell(action)
    res = _run_ps(
        "Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,"
        "StartMode,PathName,StartName,ProcessId | ConvertTo-Json -Depth 3"
    )
    if not res.ok:
        return _failed(action, res, "could not enumerate services")
    services = parse_services(res.stdout)
    return {"services": services, "count": len(services)}


@WindowsAdapter.implements("enum.persistence")
def _enum_persistence(self: WindowsAdapter, verb: Verb, action: Action) -> Any:
    if _powershell() is None:
        return _no_powershell(action)
    res = _run_ps(_PERSISTENCE_SCRIPT, timeout=90)
    if not res.ok:
        return _failed(action, res, "could not enumerate persistence")
    return parse_persistence(res.stdout)


@WindowsAdapter.implements("enum.network")
def _enum_network(self: WindowsAdapter, verb: Verb, action: Action) -> Any:
    if _powershell() is None:
        return _no_powershell(action)
    res = _run_ps(_NETWORK_SCRIPT, timeout=60)
    if res.ok and res.stdout.strip():
        return parse_network(res.stdout)
    # Fall back to netstat if the Net cmdlets are unavailable (Server Core, old
    # boxes). A partial answer beats an exception.
    netstat = which("netstat")
    if netstat is not None:
        ns = run([netstat, "-ano"], timeout=30)
        if ns.ok:
            sockets = parse_netstat_ano(ns.stdout)
            return {
                "interfaces": [], "routes": [], "tcp": sockets, "udp": [],
                "listening": [s for s in sockets if (s.get("state") or "") == "LISTENING"],
                "established": [s for s in sockets if (s.get("state") or "") == "ESTABLISHED"],
                "source": "netstat",
            }
    return _failed(action, res, "could not enumerate network state")


@WindowsAdapter.implements("enum.software")
def _enum_software(self: WindowsAdapter, verb: Verb, action: Action) -> Any:
    if _powershell() is None:
        return _no_powershell(action)
    res = _run_ps(_SOFTWARE_SCRIPT, timeout=60)
    if not res.ok:
        return _failed(action, res, "could not enumerate installed software")
    return parse_software(res.stdout)


@WindowsAdapter.implements("enum.shares")
def _enum_shares(self: WindowsAdapter, verb: Verb, action: Action) -> Any:
    if _powershell() is None:
        return _no_powershell(action)
    res = _run_ps(
        "Get-SmbShare | ForEach-Object { $s=$_; "
        "$acc = Get-SmbShareAccess -Name $s.Name -ErrorAction SilentlyContinue | "
        "Select-Object AccountName,AccessRight,AccessControlType;"
        "[pscustomobject]@{Name=$s.Name; Path=$s.Path; Description=$s.Description;"
        " Access=$acc} } | ConvertTo-Json -Depth 4"
    )
    if not res.ok:
        return _failed(action, res, "could not enumerate SMB shares")
    shares = parse_shares(res.stdout)
    return {"shares": shares, "count": len(shares)}


# ---------------------------------------------------------------------------
# detect handlers
# ---------------------------------------------------------------------------


@WindowsAdapter.implements("detect.telemetry")
def _detect_telemetry(self: WindowsAdapter, verb: Verb, action: Action) -> Any:
    if _powershell() is None:
        return _no_powershell(action)
    sysmon = parse_sysmon_status(_run_ps(_SYSMON_SCRIPT).stdout)
    logs = parse_winevent_log(_run_ps(_LOGLIST_SCRIPT).stdout)
    ps_logging = parse_reg_values(_run_ps(_PSLOGGING_SCRIPT).stdout)

    audit: dict[str, str] = {}
    auditpol = which("auditpol")
    if auditpol is not None:
        ap = run([auditpol, "/get", "/category:*", "/r"], timeout=30)
        if ap.ok:
            audit = parse_auditpol_csv(ap.stdout)

    return assess_telemetry(sysmon=sysmon, logs=logs, audit=audit, ps_logging=ps_logging)


@WindowsAdapter.implements("detect.process_creation")
def _detect_process_creation(self: WindowsAdapter, verb: Verb, action: Action) -> Any:
    if _powershell() is None:
        return _no_powershell(action)
    since = int(action.params.get("since_seconds", 300))
    image = action.params.get("image")
    events = _query_events("Security", [4688], since) + _query_events(
        "Microsoft-Windows-Sysmon/Operational", [1], since
    )
    matched = _filter_events_by_image(events, image) if image else events
    enabled = _process_auditing_enabled()
    return {
        "window_seconds": since,
        "image": image,
        "enabled": enabled,
        "sources": ["Security/4688", "Sysmon/1"],
        "count": len(matched),
        "matched": matched[:50],
        "note": (
            "process-creation auditing is off; absence of events here is a "
            "configuration gap, not proof the process did not run"
            if enabled is False
            else None
        ),
    }


@WindowsAdapter.implements("detect.persistence_change")
def _detect_persistence_change(self: WindowsAdapter, verb: Verb, action: Action) -> Any:
    if _powershell() is None:
        return _no_powershell(action)
    since = int(action.params.get("since_seconds", 300))
    events = (
        _query_events("Security", [4698, 4699, 4700, 4701, 4702], since)  # scheduled task
        + _query_events("Security", [4657], since)  # registry value modified (if audited)
        + _query_events("Microsoft-Windows-Sysmon/Operational", [12, 13, 11], since)
    )
    return {
        "window_seconds": since,
        "sources": ["Security/4698-4702", "Security/4657", "Sysmon/11-13"],
        "count": len(events),
        "matched": events[:50],
    }


@WindowsAdapter.implements("detect.credential_access")
def _detect_credential_access(self: WindowsAdapter, verb: Verb, action: Action) -> Any:
    if _powershell() is None:
        return _no_powershell(action)
    since = int(action.params.get("since_seconds", 300))
    events = (
        _query_events("Security", [4656, 4663], since)  # handle to object (LSASS if audited)
        + _query_events("Microsoft-Windows-Sysmon/Operational", [10], since)  # ProcessAccess
    )
    # A ProcessAccess (Sysmon 10) targeting lsass.exe is the signal that matters.
    lsass = [e for e in events if "lsass" in json.dumps(e.get("data", {})).lower()]
    return {
        "window_seconds": since,
        "sources": ["Security/4656", "Security/4663", "Sysmon/10"],
        "count": len(events),
        "lsass_access": len(lsass),
        "matched": events[:50],
    }


@WindowsAdapter.implements("detect.authentication")
def _detect_authentication(self: WindowsAdapter, verb: Verb, action: Action) -> Any:
    if _powershell() is None:
        return _no_powershell(action)
    since = int(action.params.get("since_seconds", 300))
    events = _query_events("Security", [4624, 4625, 4648, 4672], since)
    failures = [e for e in events if e.get("id") == 4625]
    return {
        "window_seconds": since,
        "sources": ["Security/4624", "Security/4625", "Security/4648", "Security/4672"],
        "count": len(events),
        "failures": len(failures),
        "matched": events[:50],
    }


@WindowsAdapter.implements("detect.rule")
def _detect_rule(self: WindowsAdapter, verb: Verb, action: Action) -> Any:
    if _powershell() is None:
        return _no_powershell(action)
    rule = str(action.params["rule"]).strip()
    since = int(action.params.get("since_seconds", 300))

    spec = _resolve_rule(rule)
    if spec is None:
        # Honest: this minimal engine is not a Sigma backend. It knows a handful
        # of named rules and can run a raw "LogName/EventId" query, and says so
        # rather than pretending an unknown rule id "did not fire".
        return Observation(
            action=action, ok=False, platform="windows",
            error=(
                f"rule {rule!r} is not known to this minimal detection engine. "
                "Supported: a raw query like 'Security/4688' or 'Sysmon/1', or one "
                f"of the built-in names {sorted(_NAMED_RULES)}."
            ),
        )
    log, ids, label = spec
    events = _query_events(log, ids, since)
    return {
        "rule": rule,
        "resolved": {"log": log, "event_ids": ids, "name": label},
        "window_seconds": since,
        "fired": len(events) > 0,
        "count": len(events),
        "matched": events[:50],
    }


# ---------------------------------------------------------------------------
# vuln handlers
# ---------------------------------------------------------------------------


@WindowsAdapter.implements("vuln.weak_permissions")
def _vuln_weak_permissions(self: WindowsAdapter, verb: Verb, action: Action) -> Any:
    if _powershell() is None:
        return _no_powershell(action)
    svc_res = _run_ps(
        "Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,"
        "StartMode,PathName,StartName,ProcessId | ConvertTo-Json -Depth 3"
    )
    if not svc_res.ok:
        return _failed(action, svc_res, "could not read services for permission analysis")
    services = parse_services(svc_res.stdout)

    unquoted = find_unquoted_service_paths(services)

    # Writable-binary check: ask icacls about each service executable and see
    # whether a non-admin principal has a write-shaped right. This is a real
    # filesystem question, so it runs icacls per candidate binary; it degrades to
    # "unknown" (no writable finding) if icacls is unavailable.
    writable: list[dict[str, Any]] = []
    icacls = which("icacls")
    seen: set[str] = set()
    for s in services:
        info = parse_pathname(s.get("path") or "")
        exe = info["executable"]
        if not exe or exe.lower() in seen:
            continue
        seen.add(exe.lower())
        if icacls is None:
            continue
        acl = run([icacls, exe], timeout=15)
        if not acl.ok:
            continue
        weak = _icacls_weak_principals(acl.stdout)
        if weak:
            writable.append(
                {
                    "service": s.get("name"),
                    "path": exe,
                    "run_as": s.get("run_as"),
                    "writable_by": weak,
                    "attck": "T1574.010",
                }
            )

    return {
        "unquoted_paths": unquoted,
        "writable_binaries": writable,
        "count": len(unquoted) + len(writable),
    }


@WindowsAdapter.implements("vuln.credential_exposure")
def _vuln_credential_exposure(self: WindowsAdapter, verb: Verb, action: Action) -> Any:
    if _powershell() is None:
        return _no_powershell(action)
    # Gather candidate blobs in one PowerShell pass: known credential-bearing
    # files that exist, plus the Winlogon autologon registry values. The scan
    # itself is the pure scan_for_credentials over each blob.
    res = _run_ps(_CRED_HUNT_SCRIPT, timeout=45)
    findings: list[dict[str, Any]] = []
    blobs = _load_json(res.stdout) if res.ok else None
    for b in _as_list(blobs):
        if not isinstance(b, dict):
            continue
        source = b.get("source") or "?"
        content = b.get("content") or ""
        findings.extend(scan_for_credentials(content, source, redact=True))
    return {
        "findings": findings,
        "count": len(findings),
        "note": "secrets are fingerprinted, not recorded; set the engagement to "
        "collect evidence if raw values are required",
    }


@WindowsAdapter.implements("vuln.privilege_path")
def _vuln_privilege_path(self: WindowsAdapter, verb: Verb, action: Action) -> Any:
    if _powershell() is None:
        return _no_powershell(action)
    priv = {}
    whoami = which("whoami")
    if whoami is not None:
        wres = run([whoami, "/all"])
        if wres.ok:
            priv = parse_whoami_all(wres.stdout)

    svc_res = _run_ps(
        "Get-CimInstance Win32_Service | Select-Object Name,StartName,PathName,"
        "State,StartMode | ConvertTo-Json -Depth 3"
    )
    services = parse_services(svc_res.stdout) if svc_res.ok else []
    weak = _vuln_weak_permissions(self, verb, action)
    if isinstance(weak, Observation):
        weak = {"unquoted_paths": [], "writable_binaries": []}

    chains = build_privilege_paths(
        privileges=priv,
        services=services,
        weak_permissions={
            "unquoted_paths": weak.get("unquoted_paths", []),
            "writable_binaries": weak.get("writable_binaries", []),
        },
    )
    return {
        "chains": chains,
        "count": len(chains),
        "current_is_admin": bool(priv.get("is_admin")),
    }


@WindowsAdapter.implements("vuln.patch_gap")
def _vuln_patch_gap(self: WindowsAdapter, verb: Verb, action: Action) -> Any:
    if _powershell() is None:
        return _no_powershell(action)
    min_sev = action.params.get("min_severity", "medium")
    sw = _run_ps(_SOFTWARE_SCRIPT, timeout=60)
    host = _run_ps(
        "$os=Get-CimInstance Win32_OperatingSystem;"
        "[pscustomobject]@{version=$os.Version; build=$os.BuildNumber} | "
        "ConvertTo-Json -Compress"
    )
    software = parse_software(sw.stdout) if sw.ok else {"software": [], "hotfixes": []}
    hostinfo = _load_json(host.stdout) if host.ok else {}
    # Honest scope: a real patch-gap analysis needs an external CVE/KB feed this
    # runtime deliberately does not carry (standard-library only). What is
    # returned is the ground truth a feed would be correlated against — the build
    # number and the applied hotfix ids — plus a clear statement of the limit.
    return {
        "os_build": (hostinfo or {}).get("build"),
        "os_version": (hostinfo or {}).get("version"),
        "hotfixes": software.get("hotfixes", []),
        "hotfix_count": len(software.get("hotfixes", [])),
        "min_severity": min_sev,
        "correlated": False,
        "note": (
            "patch-gap correlation against known-vulnerable ranges requires an "
            "external CVE/KB feed, which the standard-library-only runtime does "
            "not bundle. Build number and applied hotfixes are reported so an "
            "offline feed can be correlated against them."
        ),
    }


# ---------------------------------------------------------------------------
# harden handlers
# ---------------------------------------------------------------------------


@WindowsAdapter.implements("harden.enable_telemetry")
def _harden_enable_telemetry(self: WindowsAdapter, verb: Verb, action: Action) -> Any:
    source = str(action.params["source"]).strip().lower()
    plan = _TELEMETRY_ENABLERS.get(source)
    if plan is None:
        return Observation(
            action=action, ok=False, platform="windows",
            error=(
                f"unknown telemetry source {source!r}. Known: "
                f"{sorted(_TELEMETRY_ENABLERS)}."
            ),
        )
    elevated = self._is_elevated()
    if elevated is False:
        return Observation(
            action=action, ok=False, platform="windows",
            error=f"enabling {source!r} changes machine audit policy and needs an "
            "elevated (administrator) token; the current token is not elevated.",
        )
    argv, change = plan
    res = run(list(argv), timeout=30)
    return Observation(
        action=action, ok=res.ok, platform="windows",
        data={
            "source": source,
            "changed": change,
            "command": list(argv),
            "result": res.to_dict(),
        },
        error="" if res.ok else f"enable command failed: {res.stderr.strip()[:200]}",
    )


@WindowsAdapter.implements("harden.fix_permissions")
def _harden_fix_permissions(self: WindowsAdapter, verb: Verb, action: Action) -> Any:
    path = action.target or action.params.get("path")
    if not path:
        return Observation(action=action, ok=False, platform="windows",
                           error="no path given to correct")
    icacls = which("icacls")
    if icacls is None:
        return Observation(action=action, ok=False, platform="windows",
                           error="icacls.exe not found; cannot change ACLs")
    # Record the previous ACL (as SDDL) so the change is reversible, then remove
    # the two over-broad grants a weak-permissions finding is usually about.
    before = _run_ps(
        f"(Get-Acl -LiteralPath {_ps_quote(path)}).Sddl"
    )
    prev_sddl = before.stdout.strip() if before.ok else None
    removed = []
    for principal in ("*S-1-1-0", "*S-1-5-32-545", "*S-1-5-11"):  # Everyone, Users, Auth Users
        r = run([icacls, path, "/remove:g", principal], timeout=20)
        removed.append({"principal": principal, "ok": r.ok})
    return Observation(
        action=action, ok=any(x["ok"] for x in removed), platform="windows",
        data={
            "path": path,
            "previous_sddl": prev_sddl,
            "removed_grants": removed,
            "restore_hint": "icacls <path> /setowner ... or re-apply previous_sddl "
            "with Set-Acl to revert",
        },
    )


@WindowsAdapter.implements("harden.remove_persistence")
def _harden_remove_persistence(self: WindowsAdapter, verb: Verb, action: Action) -> Any:
    entry = str(action.params["entry"]).strip()
    kind, _, rest = entry.partition(":")
    if kind == "run_key":
        # rest is HIVE\NAME as enum.persistence emitted it.
        hive, _, name = rest.rpartition("\\")
        reg = which("reg")
        if reg is None:
            return Observation(action=action, ok=False, platform="windows",
                               error="reg.exe not found")
        r = run([reg, "delete", _reg_hive_path(hive), "/v", name, "/f"], timeout=20)
        return Observation(action=action, ok=r.ok, platform="windows",
                           data={"removed": entry, "command": list(r.argv),
                                 "result": r.to_dict()},
                           error="" if r.ok else r.stderr.strip()[:200])
    if kind == "scheduled_task":
        schtasks = which("schtasks")
        if schtasks is None:
            return Observation(action=action, ok=False, platform="windows",
                               error="schtasks.exe not found")
        r = run([schtasks, "/delete", "/tn", rest, "/f"], timeout=20)
        return Observation(action=action, ok=r.ok, platform="windows",
                           data={"removed": entry, "command": list(r.argv),
                                 "result": r.to_dict()},
                           error="" if r.ok else r.stderr.strip()[:200])
    if kind == "startup_folder":
        try:
            existed = Path(rest).exists()
            Path(rest).unlink(missing_ok=True)
            return Observation(action=action, ok=True, platform="windows",
                               data={"removed": entry, "existed": existed})
        except OSError as exc:
            return Observation(action=action, ok=False, platform="windows",
                               error=str(exc))
    return Observation(
        action=action, ok=False, platform="windows",
        error=f"do not know how to remove a {kind!r} entry; supported kinds are "
        "run_key, scheduled_task, startup_folder",
    )


# ---------------------------------------------------------------------------
# exploit handlers (red)
# ---------------------------------------------------------------------------


@WindowsAdapter.implements("exploit.service_permissions")
def _exploit_service_permissions(self: WindowsAdapter, verb: Verb, action: Action) -> Any:
    if _powershell() is None:
        return _no_powershell(action)
    service = str(action.params["service"]).strip()
    restore = bool(action.params.get("restore", True))

    svc_res = _run_ps(
        f"Get-CimInstance Win32_Service -Filter \"Name='{service}'\" | "
        "Select-Object Name,PathName,StartName,State | ConvertTo-Json -Depth 3"
    )
    rows = parse_services(svc_res.stdout) if svc_res.ok else []
    if not rows:
        return Observation(action=action, ok=False, platform="windows",
                           error=f"service {service!r} not found")
    exe = parse_pathname(rows[0].get("path") or "")["executable"]
    if not exe:
        return Observation(action=action, ok=False, platform="windows",
                           error=f"service {service!r} has no resolvable binary path")

    # Verify write access before touching anything. If the binary is not writable
    # by us, the finding it is built on is wrong; say so rather than failing mid-swap.
    icacls = which("icacls")
    if icacls is not None:
        acl = run([icacls, exe], timeout=15)
        if acl.ok and not _icacls_weak_principals(acl.stdout):
            return Observation(
                action=action, ok=False, platform="windows",
                error=f"the binary {exe} is not writable by a non-admin principal; "
                "this service is not vulnerable to a binary swap by the current user.",
            )

    # Prove write access with a mandatory backup and immediate restore, rather
    # than dropping a live payload and restarting — that would break the service
    # if the payload is not a valid PE, and this handler must not gamble a
    # production service on that. The audit trail records the exact file and the
    # backup path, and cleanup is reported truthfully.
    workdir = tempfile.mkdtemp(prefix="whetstone-svcperm-")
    tag = uuid.uuid4().hex[:12]
    manifest = None
    try:
        manifest = stage_file_replacement(exe, _marker_payload(f"service_permissions:{service}:{tag}"), workdir)
        cleaned = restore_file_replacement(manifest) if restore else False
        return Observation(
            action=action, ok=True, platform="windows",
            data={
                "service": service,
                "binary": exe,
                "run_as": rows[0].get("run_as"),
                "wrote": manifest,
                "restore_requested": restore,
                "restore_succeeded": cleaned,
                "technique": "T1574.010",
                "note": "demonstrated write access to the service binary with an "
                "inert marker and a mandatory backup; a real payload would be a "
                "PE. The service was not restarted, to avoid disrupting it.",
                "manual_cleanup": None if cleaned else
                f"restore the original from {manifest.get('backup')} to {exe} by hand",
            },
        )
    except OSError as exc:
        cleaned = restore_file_replacement(manifest) if (restore and manifest) else False
        return Observation(
            action=action, ok=False, platform="windows",
            error=f"binary swap failed: {exc}",
            data={"restore_succeeded": cleaned, "wrote": manifest},
        )
    finally:
        try:
            os.rmdir(workdir)
        except OSError:
            pass  # backup may still be present if restore failed; leave it for the human


@WindowsAdapter.implements("exploit.unquoted_path")
def _exploit_unquoted_path(self: WindowsAdapter, verb: Verb, action: Action) -> Any:
    if _powershell() is None:
        return _no_powershell(action)
    service = str(action.params["service"]).strip()
    restore = bool(action.params.get("restore", True))

    svc_res = _run_ps(
        f"Get-CimInstance Win32_Service -Filter \"Name='{service}'\" | "
        "Select-Object Name,PathName,StartName | ConvertTo-Json -Depth 3"
    )
    rows = parse_services(svc_res.stdout) if svc_res.ok else []
    if not rows:
        return Observation(action=action, ok=False, platform="windows",
                           error=f"service {service!r} not found")
    path = rows[0].get("path") or ""
    points = interception_paths(path)
    if not points:
        return Observation(
            action=action, ok=False, platform="windows",
            error=f"service {service!r} path {path!r} has no unquoted interception "
            "point; it is not vulnerable to this technique.",
        )

    # Plant at the first interception point that is empty. stage_planted_file
    # refuses to clobber, so we never destroy an unrelated file.
    tag = uuid.uuid4().hex[:12]
    planted = None
    for candidate in points:
        m = stage_planted_file(candidate, _marker_payload(f"unquoted_path:{service}:{tag}"))
        if m.get("planted"):
            planted = m
            break
    if planted is None:
        return Observation(
            action=action, ok=False, platform="windows",
            error=f"could not plant at any interception point {points} (all exist "
            "or are not writable); no change was made.",
        )
    cleaned = remove_planted_file(planted) if restore else False
    return Observation(
        action=action, ok=True, platform="windows",
        data={
            "service": service,
            "service_path": path,
            "interception_points": points,
            "planted": planted,
            "restore_requested": restore,
            "restore_succeeded": cleaned,
            "technique": "T1574.009",
            "note": "planted an inert marker at the interception point to prove the "
            "path is writable and would be executed ahead of the real binary. Not a "
            "working payload.",
            "manual_cleanup": None if cleaned else f"delete {planted.get('path')} by hand",
        },
    )


@WindowsAdapter.implements("exploit.scheduled_task")
def _exploit_scheduled_task(self: WindowsAdapter, verb: Verb, action: Action) -> Any:
    schtasks = which("schtasks")
    if schtasks is None:
        return _no_powershell(action) if _powershell() is None else Observation(
            action=action, ok=False, platform="windows",
            error="schtasks.exe not found; cannot create a scheduled task",
        )
    as_user = str(action.params.get("as_user", "SYSTEM")).strip()
    cleanup = bool(action.params.get("cleanup", True))

    task_name = f"Whetstone-{uuid.uuid4().hex[:12]}"
    # A benign, self-evidencing command: write a marker file. Never a payload.
    marker = str(Path(tempfile.gettempdir()) / f"{task_name}.txt")
    tr = f'cmd /c echo whetstone {task_name} > "{marker}"'

    create = run(
        [schtasks, "/create", "/tn", task_name, "/tr", tr, "/sc", "ONCE",
         "/st", "23:59", "/ru", as_user, "/f"],
        timeout=30,
    )
    if not create.ok:
        return Observation(
            action=action, ok=False, platform="windows",
            error=f"could not create task as {as_user!r}: {create.stderr.strip()[:200]}",
            data={"as_user": as_user, "attempted_task": task_name,
                  "command": list(create.argv)},
        )

    deleted = False
    if cleanup:
        d = run([schtasks, "/delete", "/tn", task_name, "/f"], timeout=20)
        deleted = d.ok
        try:
            Path(marker).unlink(missing_ok=True)
        except OSError:
            pass

    return Observation(
        action=action, ok=True, platform="windows",
        data={
            "task_name": task_name,
            "runs_as": as_user,
            "command": tr,
            "marker": marker,
            "cleanup_requested": cleanup,
            "cleanup_succeeded": deleted,
            "technique": "T1053.005",
            "manual_cleanup": None if (not cleanup or deleted)
            else f"schtasks /delete /tn {task_name} /f",
        },
    )


# ---------------------------------------------------------------------------
# postex handlers (red)
# ---------------------------------------------------------------------------


@WindowsAdapter.implements("postex.credential_dump")
def _postex_credential_dump(self: WindowsAdapter, verb: Verb, action: Action) -> Any:
    redact = bool(action.params.get("redact", True))
    cmdkey = which("cmdkey")
    stored: list[dict[str, Any]] = []
    if cmdkey is not None:
        r = run([cmdkey, "/list"], timeout=20)
        if r.ok:
            stored = parse_cmdkey_list(r.stdout)

    # Autologon credential presence (a real, common exposure) — reported as a
    # surface, never read. With redact on (default) we never fetch DefaultPassword.
    autologon_present = None
    winlogon = None
    if _powershell() is not None:
        wl = _run_ps(
            "$k='HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon';"
            "$p=Get-ItemProperty $k -ErrorAction SilentlyContinue;"
            "[pscustomobject]@{"
            "AutoAdminLogon=$p.AutoAdminLogon; DefaultUserName=$p.DefaultUserName;"
            "HasDefaultPassword=[bool]$p.DefaultPassword} | ConvertTo-Json -Compress"
        )
        winlogon = _load_json(wl.stdout) if wl.ok else None
        if isinstance(winlogon, dict):
            autologon_present = _b(winlogon.get("HasDefaultPassword"))

    exposed_accounts = sorted({s.get("user") for s in stored if s.get("user")})
    if isinstance(winlogon, dict) and winlogon.get("DefaultUserName"):
        exposed_accounts = sorted(set(exposed_accounts) | {winlogon.get("DefaultUserName")})

    return {
        "redacted": redact,
        "stored_credentials": len(stored),
        "stored_targets": [s.get("target") for s in stored],
        "exposed_accounts": exposed_accounts,
        "autologon_password_present": autologon_present,
        "secret_count": len(stored) + (1 if autologon_present else 0),
        "note": (
            "reports which accounts/targets have credentials exposed and how many, "
            "never the secret material. LSASS memory (the classic credential dump "
            "surface) is deliberately not read: doing so needs SeDebug and a memory "
            "read this verb will not perform. Set redact=false in a lab engagement "
            "to collect raw values."
        ),
        "lsass_note": "LSASS not accessed; would require elevated debug rights",
    }


@WindowsAdapter.implements("postex.persistence_install")
def _postex_persistence_install(self: WindowsAdapter, verb: Verb, action: Action) -> Any:
    mechanism = str(action.params["mechanism"]).strip()
    cleanup = bool(action.params.get("cleanup", True))

    if mechanism in {"cron", "launch_agent"}:
        return Observation(
            action=action, ok=False, platform="windows", unsupported=True,
            error=f"{mechanism!r} is not a Windows concept; on Windows use "
            "'autorun' (Run key), 'service', or 'profile' (PowerShell profile).",
        )

    if mechanism == "autorun":
        reg = which("reg")
        if reg is None:
            return Observation(action=action, ok=False, platform="windows",
                               error="reg.exe not found")
        value_name = f"Whetstone-{uuid.uuid4().hex[:8]}"
        marker = str(Path(tempfile.gettempdir()) / f"{value_name}.txt")
        command = f'cmd /c echo whetstone {value_name} > "{marker}"'
        key = "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        add = run([reg, "add", key, "/v", value_name, "/t", "REG_SZ",
                   "/d", command, "/f"], timeout=20)
        if not add.ok:
            return Observation(action=action, ok=False, platform="windows",
                               error=f"could not write Run value: {add.stderr.strip()[:200]}",
                               data={"key": key, "value": value_name})
        removed = False
        if cleanup:
            d = run([reg, "delete", key, "/v", value_name, "/f"], timeout=20)
            removed = d.ok
        return Observation(
            action=action, ok=True, platform="windows",
            data={
                "mechanism": "autorun",
                "hive": "HKCU",
                "key": key,
                "value_name": value_name,
                "command": command,
                "id": f"run_key:HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\{value_name}",
                "cleanup_requested": cleanup,
                "cleanup_succeeded": removed,
                "technique": "T1547.001",
                "manual_cleanup": None if (not cleanup or removed)
                else f"reg delete {key} /v {value_name} /f",
            },
        )

    if mechanism == "service":
        elevated = self._is_elevated()
        if elevated is False:
            return Observation(action=action, ok=False, platform="windows",
                               error="creating a service needs an elevated token; "
                               "the current token is not elevated.")
        sc = which("sc") or which("sc.exe")
        if sc is None:
            return Observation(action=action, ok=False, platform="windows",
                               error="sc.exe not found")
        svc_name = f"Whetstone{uuid.uuid4().hex[:8]}"
        binpath = 'cmd /c echo whetstone-service-marker'
        create = run([sc, "create", svc_name, "binPath=", binpath, "start=", "demand"],
                     timeout=25)
        if not create.ok:
            return Observation(action=action, ok=False, platform="windows",
                               error=f"could not create service: {create.stderr.strip()[:200]}",
                               data={"service": svc_name, "command": list(create.argv)})
        removed = False
        if cleanup:
            d = run([sc, "delete", svc_name], timeout=20)
            removed = d.ok
        return Observation(
            action=action, ok=True, platform="windows",
            data={
                "mechanism": "service",
                "service": svc_name,
                "bin_path": binpath,
                "id": f"service:{svc_name}",
                "cleanup_requested": cleanup,
                "cleanup_succeeded": removed,
                "technique": "T1543.003",
                "manual_cleanup": None if (not cleanup or removed) else f"sc delete {svc_name}",
            },
        )

    if mechanism == "profile":
        if _powershell() is None:
            return _no_powershell(action)
        # Append a benign marker to the current user's PowerShell profile, and
        # record exactly what was appended so it can be removed by hand.
        tag = uuid.uuid4().hex[:8]
        marker_line = f"# whetstone-persistence {tag} (inert marker)"
        script = (
            "$p=$PROFILE.CurrentUserCurrentHost;"
            "New-Item -ItemType File -Path $p -Force | Out-Null;"
            f"Add-Content -Path $p -Value '{marker_line}';"
            "[pscustomobject]@{profile=$p} | ConvertTo-Json -Compress"
        )
        res = _run_ps(script)
        prof = _load_json(res.stdout) if res.ok else None
        profile_path = prof.get("profile") if isinstance(prof, dict) else None
        removed = False
        if cleanup and profile_path:
            rm = _run_ps(
                f"(Get-Content -LiteralPath {_ps_quote(profile_path)}) "
                f"| Where-Object {{ $_ -ne '{marker_line}' }} "
                f"| Set-Content -LiteralPath {_ps_quote(profile_path)}"
            )
            removed = rm.ok
        return Observation(
            action=action, ok=res.ok, platform="windows",
            data={
                "mechanism": "profile",
                "profile": profile_path,
                "appended": marker_line,
                "id": f"profile:{profile_path}",
                "cleanup_requested": cleanup,
                "cleanup_succeeded": removed,
                "technique": "T1546.013",
                "manual_cleanup": None if (not cleanup or removed)
                else f"remove the line {marker_line!r} from {profile_path}",
            },
            error="" if res.ok else res.stderr.strip()[:200],
        )

    return Observation(action=action, ok=False, platform="windows",
                       error=f"unknown mechanism {mechanism!r}")


@WindowsAdapter.implements("postex.privilege_escalate")
def _postex_privilege_escalate(self: WindowsAdapter, verb: Verb, action: Action) -> Any:
    chain = str(action.params["chain"]).strip()
    # Chains come from vuln.privilege_path and encode which primitive to run. We
    # only ever execute a primitive the analysis named; an unknown chain is
    # refused rather than guessed.
    if chain.startswith("chain:service_binary:"):
        service = chain.split(":", 2)[2]
        sub = action.__class__(verb_id="exploit.service_permissions",
                               params={"service": service, "restore": True},
                               target=action.target)
        inner = _exploit_service_permissions(self, verb, sub)
        return _wrap_escalation(action, chain, "exploit.service_permissions", inner)
    if chain.startswith("chain:unquoted_path:"):
        service = chain.split(":", 2)[2]
        sub = action.__class__(verb_id="exploit.unquoted_path",
                               params={"service": service, "restore": True},
                               target=action.target)
        inner = _exploit_unquoted_path(self, verb, sub)
        return _wrap_escalation(action, chain, "exploit.unquoted_path", inner)
    if chain == "chain:seimpersonate":
        return Observation(
            action=action, ok=False, platform="windows",
            error="the SeImpersonate (potato-family) chain requires a token-"
            "coercion primitive this runtime does not carry; it is identified but "
            "not executed. Report it as a validated privilege-escalation path.",
            data={"chain": chain, "privilege": "SeImpersonatePrivilege"},
        )
    return Observation(
        action=action, ok=False, platform="windows",
        error=f"chain {chain!r} was not produced by vuln.privilege_path; refusing to "
        "attempt an escalation route that was not identified first.",
    )


@WindowsAdapter.implements("postex.lateral_move")
def _postex_lateral_move(self: WindowsAdapter, verb: Verb, action: Action) -> Any:
    method = str(action.params["method"]).strip()
    as_user = str(action.params["as_user"]).strip()
    dest = action.target or ""
    host = dest.split(":", 1)[1] if dest.startswith("host:") else dest
    if not host:
        return Observation(action=action, ok=False, platform="windows",
                           error="no destination host in the action target")

    port = {"smb": 445, "winrm": 5985, "ssh": 22, "rdp": 3389}.get(method)
    reachable = _tcp_reachable(host, port) if port else None

    # A reachability + service probe, not an automated credential replay. Whether
    # the port answers and (for WinRM) whether WS-Man responds is a truthful
    # measure of whether lateral movement is *possible*; actually authenticating
    # with obtained credentials is left to a human step so this verb never
    # silently sprays a credential across the network.
    wsman = None
    if method == "winrm" and reachable and _powershell() is not None:
        t = _run_ps(f"try {{ Test-WSMan -ComputerName {_ps_quote(host)} -ErrorAction "
                    "Stop | Out-Null; 'ok' }} catch {{ 'fail' }}", timeout=20)
        wsman = t.stdout.strip() == "ok" if t.ok else None

    return {
        "target_host": host,
        "method": method,
        "as_user": as_user,
        "port": port,
        "reachable": reachable,
        "wsman_responds": wsman,
        "authenticated": False,
        "note": "measured reachability of the remote access service; did not "
        "transmit credentials. Confirm the credential and complete the "
        "authentication as a deliberate step.",
    }


@WindowsAdapter.implements("postex.exfil_probe")
def _postex_exfil_probe(self: WindowsAdapter, verb: Verb, action: Action) -> Any:
    n = int(action.params.get("bytes", 1048576))
    sink = str(action.params["sink"]).strip()
    host, _, port_s = sink.partition(":")
    port = int(port_s) if port_s.isdigit() else 443

    # Synthetic bytes only — a fixed filler pattern, never file contents. The
    # measurement is "did N bytes leave to the sink", which is what an egress
    # control would (or would not) notice.
    sent = 0
    completed = False
    error = None
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            chunk = b"W" * 65536
            remaining = n
            sock.settimeout(10)
            while remaining > 0:
                block = chunk if remaining >= len(chunk) else chunk[:remaining]
                sock.sendall(block)
                sent += len(block)
                remaining -= len(block)
            completed = True
    except OSError as exc:
        error = str(exc)

    return Observation(
        action=action, ok=completed, platform="windows",
        data={
            "sink": f"{host}:{port}",
            "requested_bytes": n,
            "sent_bytes": sent,
            "completed": completed,
            "synthetic": True,
            "technique": "T1041",
            "note": "sent generated filler bytes, never file contents, to measure "
            "whether egress controls flag the volume.",
        },
        error=error or "",
    )


# ---------------------------------------------------------------------------
# handler-support helpers (module-level so they stay unit-testable)
# ---------------------------------------------------------------------------


def _failed(action: Action, res: CommandResult, what: str) -> Observation:
    """Turn a failed CommandResult into a uniform failed Observation."""
    detail = res.stderr.strip()[:200] or (f"exit {res.returncode}")
    return Observation(
        action=action, ok=False, platform="windows",
        error=f"{what}: {detail}",
        data={"command": list(res.argv), "rc": res.returncode},
        duration_ms=res.duration_ms,
    )


def _ps_quote(value: str) -> str:
    """Single-quote a value for embedding in a PowerShell string literal.

    PowerShell single-quoted strings escape an embedded quote by doubling it.
    This is only ever used for values *we* generate (paths we already hold), not
    model-supplied command syntax — the argv boundary is still what stops
    injection; this just keeps a legitimate path with a space intact.
    """
    return "'" + value.replace("'", "''") + "'"


def _icacls_weak_principals(text: str) -> list[str]:
    """Principals in icacls output that hold a write-shaped right, minus admins.

    A write ((W)), modify ((M)) or full ((F)) grant to a broad principal —
    Everyone, Authenticated Users, BUILTIN\\Users — on a service binary is the
    weak-permission finding. Admin/SYSTEM/TrustedInstaller grants are expected
    and ignored, so the result is only the *unexpected* writers.
    """
    weak: list[str] = []
    broad = ("everyone", "authenticated users", "builtin\\users", "users",
             "nt authority\\authenticated users", "domain users")
    for line in (text or "").splitlines():
        s = line.strip()
        m = re.search(r"\(([^)]*)\)\s*$", s)
        if not m:
            continue
        rights = m.group(1).upper().replace(" ", "")
        if not any(tok in rights for tok in ("W", "M", "F", "WD", "AD")):
            continue
        principal = s[: m.start()].strip()
        # icacls may print multiple (..)(..) groups; take the text before the first.
        principal = re.split(r"\s*\(", principal)[0].strip()
        if principal.lower() in broad:
            weak.append(principal)
    return sorted(set(weak))


def _reg_hive_path(hive: str) -> str:
    """Map a PowerShell-style hive path to the reg.exe form.

    enum.persistence emits hives as ``HKLM:\\SOFTWARE\\...``; reg.exe wants
    ``HKLM\\SOFTWARE\\...`` (no colon) with the long hive names accepted too.
    """
    h = hive.replace(":", "")
    return h


# --- detect helpers ---------------------------------------------------------

_NAMED_RULES: dict[str, tuple[str, list[int]]] = {
    "process_creation": ("Security", [4688]),
    "sysmon_process_creation": ("Microsoft-Windows-Sysmon/Operational", [1]),
    "scheduled_task_created": ("Security", [4698]),
    "logon": ("Security", [4624]),
    "logon_failure": ("Security", [4625]),
    "service_installed": ("Security", [4697, 7045]),
    "lsass_access": ("Microsoft-Windows-Sysmon/Operational", [10]),
    "powershell_scriptblock": ("Microsoft-Windows-PowerShell/Operational", [4104]),
}


def _resolve_rule(rule: str) -> tuple[str, list[int], str] | None:
    """Resolve a rule id to (logname, event ids, label), or None if unknown.

    Accepts a built-in name, or a raw ``Log/Id`` (or ``Log/Id,Id``) query so an
    operator can point the engine at any event without a rule definition — which
    is the honest scope of a minimal detection runner.
    """
    key = rule.strip().lower()
    if key in _NAMED_RULES:
        log, ids = _NAMED_RULES[key]
        return log, ids, key
    if "/" in rule:
        log, _, ids_s = rule.partition("/")
        log = _RULE_LOG_ALIASES.get(log.strip().lower(), log.strip())
        ids = [int(x) for x in re.findall(r"\d+", ids_s)]
        if log and ids:
            return log, ids, rule
    return None


_RULE_LOG_ALIASES = {
    "security": "Security",
    "system": "System",
    "application": "Application",
    "sysmon": "Microsoft-Windows-Sysmon/Operational",
    "powershell": "Microsoft-Windows-PowerShell/Operational",
}


def _query_events(logname: str, ids: Sequence[int], since_seconds: int) -> list[dict[str, Any]]:
    """Query a log for event ids in a window and return parsed event rows.

    Not pure (it runs Get-WinEvent), but everything downstream of it is: the
    projection is parsed by :func:`parse_winevent_events`, which the tests cover.
    """
    if _powershell() is None:
        return []
    id_list = ",".join(str(i) for i in ids)
    script = (
        f"$since=(Get-Date).AddSeconds(-{int(since_seconds)});"
        f"$f=@{{LogName='{logname}'; Id={id_list}; StartTime=$since}};"
        "Get-WinEvent -FilterHashtable $f -ErrorAction SilentlyContinue | "
        "ForEach-Object { $x=[xml]$_.ToXml(); $d=@{};"
        "foreach($n in $x.Event.EventData.Data){ if($n.Name){ $d[$n.Name]=$n.'#text' } }"
        "[pscustomobject]@{ id=$_.Id; time=$_.TimeCreated.ToString('o');"
        " provider=$_.ProviderName; log=$_.LogName; data=$d } } | ConvertTo-Json -Depth 4"
    )
    res = _run_ps(script, timeout=45)
    return parse_winevent_events(res.stdout) if res.ok else []


def _filter_events_by_image(events: Sequence[Mapping[str, Any]], image: str) -> list[dict[str, Any]]:
    needle = image.lower()
    out = []
    for e in events:
        blob = json.dumps(e.get("data", {})).lower()
        if needle in blob:
            out.append(dict(e))
    return out


def _process_auditing_enabled() -> bool | None:
    """Whether 'Audit Process Creation' is on, or None if auditpol is unreadable."""
    auditpol = which("auditpol")
    if auditpol is None:
        return None
    ap = run([auditpol, "/get", "/subcategory:Process Creation", "/r"], timeout=20)
    if not ap.ok:
        return None
    settings = parse_auditpol_csv(ap.stdout)
    val = settings.get("Process Creation", "")
    return bool(val) and "No Auditing" not in val


def _tcp_reachable(host: str, port: int, timeout: float = 5.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _wrap_escalation(action: Action, chain: str, exploit: str, inner: Any) -> Observation:
    """Wrap an exploit primitive's result as a privilege-escalation observation."""
    if isinstance(inner, Observation):
        ok = inner.ok
        data = inner.data if isinstance(inner.data, dict) else {"result": inner.data}
        err = inner.error
    else:
        ok = True
        data = inner if isinstance(inner, dict) else {"result": inner}
        err = ""
    return Observation(
        action=action, ok=ok, platform="windows",
        data={"chain": chain, "executed": exploit, **({"detail": data} if data else {})},
        error=err,
    )


# --- telemetry-enable plans (harden.enable_telemetry) -----------------------
#
# Each source maps to the exact argv that turns it on plus a human-readable
# statement of what changes, which is quoted straight into the audit log.

def _auditpol_path() -> str:
    return which("auditpol") or "auditpol"


def _reg_path() -> str:
    return which("reg") or "reg"


_TELEMETRY_ENABLERS: dict[str, tuple[tuple[str, ...], str]] = {
    "process_creation": (
        (_auditpol_path(), "/set", "/subcategory:Process Creation", "/success:enable"),
        "enables Success auditing of the Process Creation subcategory (event 4688)",
    ),
    "command_line": (
        (_reg_path(), "add",
         r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
         "/v", "ProcessCreationIncludeCmdLine_Enabled", "/t", "REG_DWORD", "/d", "1", "/f"),
        "adds the command line to 4688 process-creation events",
    ),
    "scriptblock": (
        (_reg_path(), "add",
         r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
         "/v", "EnableScriptBlockLogging", "/t", "REG_DWORD", "/d", "1", "/f"),
        "enables PowerShell script-block logging (event 4104)",
    ),
    "module_logging": (
        (_reg_path(), "add",
         r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging",
         "/v", "EnableModuleLogging", "/t", "REG_DWORD", "/d", "1", "/f"),
        "enables PowerShell module logging (event 4103)",
    ),
    "logon": (
        (_auditpol_path(), "/set", "/subcategory:Logon", "/success:enable", "/failure:enable"),
        "enables Success and Failure auditing of interactive/remote logon (4624/4625)",
    ),
}


# ---------------------------------------------------------------------------
# Longer PowerShell scripts, kept out of the handlers for readability. Each is a
# single -Command argument; the newlines are inside the one string.
# ---------------------------------------------------------------------------

_PERSISTENCE_SCRIPT = r"""
$run=@()
foreach($h in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
              'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
              'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
              'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'){
  if(Test-Path $h){
    $props=Get-ItemProperty -Path $h
    foreach($p in $props.PSObject.Properties){
      if($p.Name -notlike 'PS*'){
        $run += [pscustomobject]@{hive=$h; name=$p.Name; command=[string]$p.Value}
      }
    }
  }
}
$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {$_.State -ne 'Disabled'} |
  ForEach-Object {
    [pscustomobject]@{
      name=$_.TaskName; path=$_.TaskPath;
      action=(($_.Actions | ForEach-Object { ("{0} {1}" -f $_.Execute,$_.Arguments).Trim() }) -join '; ');
      author=$_.Author; state=[string]$_.State
    }
  }
$startup=@()
foreach($d in "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
              "$env:AppData\Microsoft\Windows\Start Menu\Programs\Startup"){
  if(Test-Path $d){
    Get-ChildItem -Path $d -File -ErrorAction SilentlyContinue | ForEach-Object {
      $startup += [pscustomobject]@{path=$_.FullName; name=$_.Name}
    }
  }
}
$wmi=@()
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | ForEach-Object {
  $wmi += [pscustomobject]@{name=[string]$_.Consumer; consumer_type='binding'; command=[string]$_.Filter}
}
$autosvc = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {$_.StartMode -eq 'Auto'} |
  ForEach-Object { [pscustomobject]@{name=$_.Name; path=$_.PathName; start_mode=$_.StartMode} }
[pscustomobject]@{run_keys=$run; scheduled_tasks=$tasks; startup_folder=$startup; wmi_subscriptions=$wmi; auto_services=$autosvc} | ConvertTo-Json -Depth 5
"""

_NETWORK_SCRIPT = r"""
$if = Get-NetIPAddress -ErrorAction SilentlyContinue | Select-Object InterfaceAlias,IPAddress,
      @{n='AddressFamily';e={[string]$_.AddressFamily}},PrefixLength
$rt = Get-NetRoute -ErrorAction SilentlyContinue | Where-Object {$_.DestinationPrefix -eq '0.0.0.0/0' -or $_.DestinationPrefix -eq '::/0'} |
      Select-Object DestinationPrefix,NextHop,InterfaceAlias
$tcp = Get-NetTCPConnection -ErrorAction SilentlyContinue | ForEach-Object {
  $pname=$null; try { $pname=(Get-Process -Id $_.OwningProcess -ErrorAction Stop).ProcessName } catch {}
  [pscustomobject]@{LocalAddress=$_.LocalAddress; LocalPort=$_.LocalPort;
    RemoteAddress=$_.RemoteAddress; RemotePort=$_.RemotePort; State=[string]$_.State;
    OwningProcess=$_.OwningProcess; Process=$pname}
}
$udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object {
  $pname=$null; try { $pname=(Get-Process -Id $_.OwningProcess -ErrorAction Stop).ProcessName } catch {}
  [pscustomobject]@{LocalAddress=$_.LocalAddress; LocalPort=$_.LocalPort;
    OwningProcess=$_.OwningProcess; Process=$pname}
}
[pscustomobject]@{interfaces=$if; routes=$rt; tcp=$tcp; udp=$udp} | ConvertTo-Json -Depth 4
"""

_SOFTWARE_SCRIPT = r"""
$keys='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
      'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
$sw = foreach($k in $keys){
  Get-ItemProperty $k -ErrorAction SilentlyContinue |
    Where-Object {$_.DisplayName} |
    Select-Object DisplayName,DisplayVersion,Publisher,InstallDate
}
$hf = Get-HotFix -ErrorAction SilentlyContinue | Select-Object HotFixID,Description,
      @{n='InstalledOn';e={[string]$_.InstalledOn}}
[pscustomobject]@{software=$sw; hotfixes=$hf} | ConvertTo-Json -Depth 4
"""

_SYSMON_SCRIPT = r"""
$svc = Get-Service -Name Sysmon,Sysmon64,SysmonDrv -ErrorAction SilentlyContinue |
       Select-Object Name,@{n='Status';e={[string]$_.Status}}
$driver = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv'
$hash = $null
foreach($p in 'HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon\Parameters',
              'HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon64\Parameters'){
  if(Test-Path $p){ $hash=(Get-ItemProperty $p -ErrorAction SilentlyContinue).'ConfigHash' }
}
[pscustomobject]@{services=$svc; driver_registered=$driver; config_hash=$hash} | ConvertTo-Json -Depth 3
"""

_LOGLIST_SCRIPT = r"""
Get-WinEvent -ListLog 'Security','Microsoft-Windows-Sysmon/Operational',
  'Windows PowerShell','Microsoft-Windows-PowerShell/Operational','System' -ErrorAction SilentlyContinue |
  Select-Object LogName,IsEnabled,RecordCount,MaximumSizeInBytes,
    @{n='LogMode';e={[string]$_.LogMode}},@{n='LastWriteTime';e={[string]$_.LastWriteTime}} |
  ConvertTo-Json -Depth 3
"""

_PSLOGGING_SCRIPT = r"""
[pscustomobject]@{
  cmdline_audit=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
  scriptblock=(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
  module_logging=(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name EnableModuleLogging -ErrorAction SilentlyContinue).EnableModuleLogging
  transcription=(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name EnableTranscripting -ErrorAction SilentlyContinue).EnableTranscripting
} | ConvertTo-Json -Compress
"""

_CRED_HUNT_SCRIPT = r"""
$blobs=@()
$files = @(
  "$env:SystemDrive\unattend.xml",
  "$env:SystemDrive\Windows\Panther\unattend.xml",
  "$env:SystemDrive\Windows\Panther\Unattend\unattend.xml",
  "$env:SystemDrive\Windows\System32\Sysprep\unattend.xml",
  "$env:AppData\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
)
foreach($f in $files){
  if(Test-Path $f){
    try { $blobs += [pscustomobject]@{source=$f; content=(Get-Content -Raw -LiteralPath $f -ErrorAction Stop)} } catch {}
  }
}
$wl='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$p=Get-ItemProperty $wl -ErrorAction SilentlyContinue
if($p -and $p.DefaultPassword){
  $blobs += [pscustomobject]@{source='registry:Winlogon'; content=("DefaultPassword={0}" -f $p.DefaultPassword)}
}
$blobs | ConvertTo-Json -Depth 3
"""
