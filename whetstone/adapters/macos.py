"""The macOS implementation of the verb catalogue.

This adapter answers the same semantic questions the Windows and Linux adapters
do, but in macOS's idiom: ``sw_vers``/``sysctl`` for the host, ``dscl`` and
Directory Services for users, ``launchd`` for services *and* persistence,
``lsof``/``netstat`` for sockets, ``pkgutil``/``system_profiler`` for software,
and the unified log (``log show``) for detection.

Three macOS facts shape almost everything below, and each is a finding in its
own right rather than a limitation to paper over:

* **There is no Sysmon.** The unified log does not record process creation. The
  classic BSM audit subsystem (``/etc/security/audit_control`` + ``auditd``)
  still ships as a binary but is *unconfigured and unloaded* on a stock modern
  system, and Apple has deprecated it. Comprehensive ``execve`` visibility
  requires an Endpoint Security client, whose coverage a non-entitled tool
  cannot enumerate. ``detect.telemetry`` says all of this out loud instead of
  implying coverage that is not there.

* **SIP and the Keychain deny bulk extraction by design.** System Integrity
  Protection blocks writes to system service binaries (so several exploit
  techniques correctly find *nothing* to abuse — the secure state), and the
  Keychain will not surrender secret material without an interactive prompt.
  ``postex.credential_dump`` reports what is enumerable *without* prompting and
  is honest about what it cannot reach.

* **launchd is the one persistence substrate.** ``enum.persistence``,
  ``enum.services``, ``exploit.scheduled_task`` and ``postex.persistence_install``
  all speak launchd (plus cron, login items and shell profiles), because on
  macOS that is where autostart lives. There is no registry; a verb that asks
  for one is answered ``unsupported``.

Every command runs through :func:`.base.run` with an argv **list** and no shell,
so a model-supplied parameter reaches ``execve`` as a single argument and is
never parsed as syntax. The parsing of each command's output is done by
module-level pure functions (``parse_*``), so a Windows or Linux box can exercise
this file's parsers against captured fixtures without a Mac — and so can this
project's CI.
"""

from __future__ import annotations

import json
import os
import plistlib
import re
import shutil
import socket
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Iterable

from ..actions import Action, Observation, Verb
from .base import Adapter, AdapterError, register_adapter, run, which

__all__ = ["MacosAdapter"]

# UIDs below this are macOS service/role accounts (the underscore-prefixed ones).
# Real interactive accounts start at 501; 500 is the historical boundary Apple
# uses to hide accounts from the login window.
_SYSTEM_UID_MAX = 500

# Large enumerations are capped so an observation stays inside the model's
# reading window. The total is always reported alongside, so a cap never hides
# the fact that there was more.
_MAX_ROWS = 250

# Absolute path so the real Mach-O binary runs even when a user's shell profile
# has shadowed ``log`` with a function (which it does on this very machine).
_LOG = "/usr/bin/log"
_FIREWALL = "/usr/libexec/ApplicationFirewall/socketfilterfw"

# Said once, referenced by every detect.* handler that touches execution
# visibility, so the honesty is uniform.
_NO_EXEC_AUDIT = (
    "macOS has no process-creation auditing comparable to Sysmon. The unified "
    "log does not record execve; the BSM auditd subsystem is deprecated and, "
    "on a stock system, unconfigured; comprehensive coverage requires an "
    "Endpoint Security client whose scope a non-entitled tool cannot see."
)


# ===========================================================================
# Pure parsers — string in, structured data out. No side effects, no I/O.
# These are the units the Linux/Windows adapters' CI can exercise on captured
# fixtures, which is the whole reason execution and parsing are kept apart.
# ===========================================================================


def parse_sw_vers(text: str) -> dict[str, str]:
    """``ProductName: macOS`` lines into ``{"product_name": "macOS", ...}``."""
    out: dict[str, str] = {}
    key_map = {
        "ProductName": "product_name",
        "ProductVersion": "product_version",
        "BuildVersion": "build",
    }
    for line in text.splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        mapped = key_map.get(k.strip())
        if mapped:
            out[mapped] = v.strip()
    return out


def parse_boottime(text: str) -> int | None:
    """``{ sec = 1789646355, usec = ... } ...`` -> the epoch seconds int.

    ``sysctl -n kern.boottime`` reports the moment the kernel came up; uptime is
    then just ``now - boot``, which is more robust than parsing ``uptime``'s
    human string across locales.
    """
    m = re.search(r"sec\s*=\s*(\d+)", text)
    return int(m.group(1)) if m else None


def parse_id(text: str) -> dict[str, Any]:
    """``uid=501(name) gid=20(staff) groups=20(staff),80(admin),...`` -> dict."""
    out: dict[str, Any] = {"uid": None, "user": None, "gid": None,
                           "group": None, "groups": []}
    m = re.search(r"uid=(\d+)\(([^)]*)\)", text)
    if m:
        out["uid"], out["user"] = int(m.group(1)), m.group(2)
    m = re.search(r"gid=(\d+)\(([^)]*)\)", text)
    if m:
        out["gid"], out["group"] = int(m.group(1)), m.group(2)
    m = re.search(r"groups=(.*)", text)
    if m:
        groups = []
        for token in m.group(1).split(","):
            gm = re.match(r"\s*(\d+)\(([^)]*)\)", token)
            if gm:
                groups.append({"gid": int(gm.group(1)), "name": gm.group(2)})
        out["groups"] = groups
    return out


def parse_dscl_pairs(text: str, *, value_is_int: bool = False) -> dict[str, Any]:
    """``dscl . -list /Users <Key>`` output: ``name<space+>value`` per line.

    Directory Services pads the first column, so any run of whitespace is the
    separator. A missing value (some records have none) maps to ``None``.
    """
    out: dict[str, Any] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split(None, 1)
        name = parts[0]
        raw = parts[1].strip() if len(parts) > 1 else ""
        if value_is_int:
            try:
                out[name] = int(raw)
            except ValueError:
                out[name] = None
        else:
            out[name] = raw
    return out


def parse_group_membership(text: str) -> list[str]:
    """``GroupMembership: root b0mba_at0mica`` -> ``["root", "b0mba_at0mica"]``."""
    m = re.search(r"GroupMembership:\s*(.*)", text)
    if not m:
        return []
    return m.group(1).split()


def parse_sudo_l(stdout: str, stderr: str, rc: int) -> dict[str, Any]:
    """Classify what ``sudo -n -l`` revealed without ever prompting.

    ``-n`` guarantees no password prompt: if a password would be needed, sudo
    prints to stderr and exits non-zero, and we report that rather than hang.

    The critical distinction — and the one a naive parser gets wrong — is that
    ``(ALL) ALL`` grants every command but **still requires a password**;
    passwordless root exists only when an entry carries ``NOPASSWD:`` *and*
    grants ``ALL``. Conflating the two produces a privilege-escalation chain
    that claims instant root when a password is actually needed, which the live
    ``sudo -n id`` check then contradicts. So ``passwordless_all`` is set only by
    a genuine ``NOPASSWD: ... ALL`` line.
    """
    blob = f"{stdout}\n{stderr}"
    base = {"available": None, "passwordless_all": False, "may_run_all": False,
            "nopasswd_commands": [], "entries": []}
    if "password is required" in blob or (rc != 0 and "may run" not in stdout):
        return {**base, "reason": "listing needs a password; not tested interactively"}
    if "may not run sudo" in blob or "not allowed" in blob:
        return {**base, "available": False}

    entries: list[str] = []
    nopasswd_cmds: list[str] = []
    passwordless_all = False
    may_run_all = False
    grants_all = re.compile(r"\)\s*(?:NOPASSWD:\s*)?ALL\b")
    for line in stdout.splitlines():
        s = line.strip()
        if not (s.startswith("(") and ")" in s):
            continue
        entries.append(s)
        is_nopasswd = "NOPASSWD:" in s
        is_all = bool(grants_all.search(s))
        if is_nopasswd and is_all:
            passwordless_all = True
        elif is_all:
            may_run_all = True
        if is_nopasswd:
            nopasswd_cmds.append(s.split("NOPASSWD:", 1)[1].strip())
    return {
        "available": True,
        "passwordless_all": passwordless_all,
        "may_run_all": may_run_all,
        "nopasswd_commands": nopasswd_cmds[:20],
        "entries": entries[:20],
    }


def parse_ps(text: str) -> list[dict[str, Any]]:
    """``ps -axo pid=,ppid=,user=,%cpu=,%mem=,stat=,command=`` -> row dicts.

    ``command`` is kept whole (it holds spaces), so the split is bounded to the
    six fixed leading columns and everything after is the command line.
    """
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split(None, 6)
        if len(parts) < 7:
            continue
        pid, ppid, user, cpu, mem, stat, command = parts
        try:
            rows.append({
                "pid": int(pid), "ppid": int(ppid), "user": user,
                "cpu": float(cpu), "mem": float(mem), "stat": stat,
                "command": command,
            })
        except ValueError:
            continue
    return rows


def parse_launchctl_list(text: str) -> list[dict[str, Any]]:
    """``launchctl list``: ``PID<TAB>Status<TAB>Label`` rows.

    ``PID`` is ``-`` when the job is loaded but not running; ``Status`` is the
    last exit status (``-9`` for a job the kernel killed), which is the closest
    launchd gives to a health signal.
    """
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("PID"):
            continue
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        pid_s, status_s, label = parts
        pid = None if pid_s == "-" else _safe_int(pid_s)
        status = None if status_s == "-" else _safe_int(status_s)
        rows.append({
            "label": label, "pid": pid, "last_exit": status,
            "running": pid is not None,
        })
    return rows


def parse_lsof_inet(text: str) -> list[dict[str, Any]]:
    """``lsof -nP -iTCP/-iUDP`` rows into ``{command,pid,user,proto,addr,port,state}``.

    lsof is preferred over ``netstat`` for sockets precisely because it names the
    owning process, which is the field a defender actually wants and ``netstat``
    on macOS only sometimes provides.
    """
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("COMMAND"):
            continue
        cols = line.split(None, 8)
        if len(cols) < 9:
            continue
        command, pid, user = cols[0], cols[1], cols[2]
        node = cols[7]          # e.g. TCP / UDP
        name = cols[8]
        state = ""
        sm = re.search(r"\(([A-Z_]+)\)\s*$", name)
        if sm:
            state = sm.group(1)
            name = name[: sm.start()].strip()
        addr, _, port = name.rpartition(":")
        rows.append({
            "command": command, "pid": _safe_int(pid), "user": user,
            "proto": node, "addr": addr or name, "port": port,
            "state": state,
        })
    return rows


def parse_netstat_routes(text: str) -> list[dict[str, str]]:
    """Default routes from ``netstat -rn`` (the ``default`` destination rows)."""
    routes: list[dict[str, str]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "default":
            routes.append({"destination": "default", "gateway": parts[1],
                          "interface": parts[-1]})
    return routes


def parse_ifconfig(text: str) -> list[dict[str, Any]]:
    """``ifconfig -a`` blocks -> per-interface ``{name,flags,inet,inet6,ether,status}``."""
    ifaces: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None
    for line in text.splitlines():
        if line and not line[0].isspace():
            if cur:
                ifaces.append(cur)
            name, _, rest = line.partition(":")
            fm = re.search(r"flags=\d+<([^>]*)>", rest)
            cur = {"name": name.strip(), "flags": fm.group(1) if fm else "",
                   "inet": [], "inet6": [], "ether": None, "status": None}
        elif cur is not None:
            s = line.strip()
            if s.startswith("inet "):
                cur["inet"].append(s.split()[1])
            elif s.startswith("inet6 "):
                cur["inet6"].append(s.split()[1].split("%")[0])
            elif s.startswith("ether "):
                cur["ether"] = s.split()[1]
            elif s.startswith("status:"):
                cur["status"] = s.split(":", 1)[1].strip()
    if cur:
        ifaces.append(cur)
    return ifaces


def parse_sharing_l(text: str) -> list[dict[str, Any]]:
    """``sharing -l`` share-point blocks into structured records.

    The tool prints a ``name:``/``path:`` header then an indented per-protocol
    block; ``guest access: 1`` under a protocol is the security-relevant bit, so
    it is surfaced rather than left in prose.
    """
    shares: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None
    proto: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("name:"):
            if cur:
                shares.append(cur)
            cur = {"name": line.split(":", 1)[1].strip(), "path": None,
                   "protocols": [], "guest_access": False}
            proto = None
        elif cur is None:
            continue
        elif line.startswith("path:"):
            cur["path"] = line.split(":", 1)[1].strip()
        elif re.match(r"^(smb|afp|ftp):", line):
            proto = line.split(":", 1)[0]
            if proto not in cur["protocols"]:
                cur["protocols"].append(proto)
        elif line.startswith("guest access:"):
            if line.split(":", 1)[1].strip().startswith("1"):
                cur["guest_access"] = True
    if cur:
        shares.append(cur)
    return shares


def parse_pkgutil_pkgs(text: str) -> list[str]:
    """One receipt id per line."""
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


def parse_sp_applications(text: str) -> list[dict[str, Any]]:
    """``system_profiler -json SPApplicationsDataType`` -> app records.

    ``obtained_from`` distinguishes Apple / Mac App Store / identified developer
    / unknown, which is the provenance signal a defender wants when triaging
    installed software.
    """
    try:
        doc = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    apps: list[dict[str, Any]] = []
    for item in doc.get("SPApplicationsDataType", []):
        signed = item.get("signed_by")
        apps.append({
            "name": item.get("_name"),
            "version": item.get("version"),
            "source": item.get("obtained_from"),
            "path": item.get("path"),
            "signed_by": signed[0] if isinstance(signed, list) and signed else None,
        })
    return apps


def parse_last(text: str) -> dict[str, str]:
    """``last`` -> most-recent login line per user (skipping reboot/shutdown)."""
    seen: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        user = parts[0]
        if user in {"reboot", "shutdown", "wtmp"}:
            continue
        if user not in seen:                       # first occurrence == newest
            when = " ".join(parts[2:6]) if len(parts) >= 6 else ""
            seen[user] = when
    return seen


def parse_log_events(text: str) -> list[dict[str, str]]:
    """``log show --style compact`` lines -> ``{ts,level,process,message}``.

    Only lines that begin with a timestamp are events; the tool's ``Filtering
    the log data…`` preamble and its column header are dropped.
    """
    events: list[dict[str, str]] = []
    for line in text.splitlines():
        if not re.match(r"^\d{4}-\d{2}-\d{2} ", line):
            continue
        # "<date> <time> <Lvl> <proc>[pid:tid] [subsys:cat] message"
        m = re.match(
            r"^(\S+ \S+)\s+(\S+)\s+([^\[]+)\[\d+:\w+\]\s+(.*)$", line
        )
        if m:
            events.append({
                "ts": m.group(1), "level": m.group(2).strip(),
                "process": m.group(3).strip(), "message": m.group(4).strip(),
            })
        else:
            events.append({"ts": line[:23], "level": "", "process": "",
                          "message": line[24:].strip()})
    return events


# ---------------------------------------------------------------------------
# Small internal helpers (I/O-touching but generic).
# ---------------------------------------------------------------------------


def _safe_int(s: str) -> int | None:
    try:
        return int(s)
    except (TypeError, ValueError):
        return None


def _read_plist(path: str | Path) -> dict[str, Any] | None:
    """Read an XML or binary plist with the stdlib — no ``plutil`` subprocess.

    ``plistlib`` handles both encodings, so this needs no shell and cannot be
    made to run anything; a malformed or unreadable plist yields ``None`` rather
    than an exception, because one bad file must not abort a whole sweep.
    """
    try:
        with open(path, "rb") as fh:
            data = plistlib.load(fh)
        return data if isinstance(data, dict) else None
    except (OSError, plistlib.InvalidFileException, ValueError, EOFError):
        return None


def _job_program(job: dict[str, Any]) -> str | None:
    """The executable a launchd job runs: ``Program`` or ``ProgramArguments[0]``."""
    prog = job.get("Program")
    if isinstance(prog, str):
        return prog
    args = job.get("ProgramArguments")
    if isinstance(args, list) and args and isinstance(args[0], str):
        return args[0]
    return None


def _cap(rows: list[Any]) -> tuple[list[Any], int, bool]:
    """Cap a list to ``_MAX_ROWS`` and report the true total and whether cut."""
    total = len(rows)
    if total > _MAX_ROWS:
        return rows[:_MAX_ROWS], total, True
    return rows, total, False


def _stat_facts(path: str) -> dict[str, Any] | None:
    """Mode/owner facts plus a from-*this-process* writability check.

    ``os.access(path, os.W_OK)`` answers "can the identity running this adapter
    write here", which is exactly the question a privilege-escalation search
    asks. World-writability is read straight from the mode bits.
    """
    try:
        st = os.stat(path)
    except OSError:
        return None
    mode = st.st_mode
    return {
        "path": path,
        "mode": oct(mode & 0o7777),
        "uid": st.st_uid,
        "gid": st.st_gid,
        "world_writable": bool(mode & 0o0002),
        "group_writable": bool(mode & 0o0020),
        "writable_by_me": os.access(path, os.W_OK),
    }


# Directory resolvers, kept as module functions so a self-test can redirect the
# red verbs' writes into a sandbox by patching these rather than the handlers.
def _launch_agents_dir() -> Path:
    return Path.home() / "Library" / "LaunchAgents"


def _launch_daemons_dir() -> Path:
    return Path("/Library/LaunchDaemons")


def _shell_profile_path() -> Path:
    return Path.home() / ".zshrc"


_LAUNCH_SCAN = (
    ("/Library/LaunchDaemons", "launch_daemon", "system"),
    ("/Library/LaunchAgents", "launch_agent", "system"),
    (str(Path.home() / "Library" / "LaunchAgents"), "launch_agent", "user"),
)

# Secret patterns for vuln.credential_exposure. Each captures a group we can
# *count and locate* without ever recording the secret itself.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]{12,}")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}")),
    ("assignment",
     re.compile(r"(?i)(password|passwd|secret|api[_-]?key|access[_-]?key|token)"
                r"\s*[:=]\s*['\"]?[^\s'\"]{6,}")),
)


# ===========================================================================
# The adapter.
# ===========================================================================


@register_adapter
class MacosAdapter(Adapter):
    """Whetstone's verb catalogue, spoken in macOS."""

    platform = "macos"


# ---------------------------------------------------------------------------
# enum — look at the machine (9 verbs)
# ---------------------------------------------------------------------------


@MacosAdapter.implements("enum.host")
def _enum_host(self: MacosAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    sw = parse_sw_vers(run(["sw_vers"]).stdout)
    kern = run(["uname", "-mrs"]).stdout.split()
    sysctl = run([
        "sysctl", "-n", "hw.model", "machdep.cpu.brand_string", "hw.ncpu",
        "hw.memsize", "kern.boottime",
    ])
    vals = sysctl.stdout.splitlines()

    def _v(i: int) -> str:
        return vals[i].strip() if i < len(vals) else ""

    boot = parse_boottime(_v(4))
    computer_name = run(["scutil", "--get", "ComputerName"])
    csr = run(["csrutil", "status"])
    sip = "unknown"
    if "enabled" in csr.stdout.lower():
        sip = "enabled"
    elif "disabled" in csr.stdout.lower():
        sip = "disabled"

    # Domain / directory binding. An unbound Mac (the overwhelming common case)
    # makes dsconfigad error or print nothing; that is "not bound", not a failure.
    ad = run(["dsconfigad", "-show"])
    dm = re.search(r"Active Directory Domain\s*=\s*(\S+)", ad.stdout)
    domain = dm.group(1) if dm else None

    mem = _safe_int(_v(3))
    return {
        "os": sw.get("product_name", "macOS"),
        "os_version": sw.get("product_version"),
        "build": sw.get("build"),
        "kernel": " ".join(kern),
        "arch": kern[-1] if kern else None,
        "hostname": run(["hostname"]).stdout.strip(),
        "computer_name": computer_name.stdout.strip() or None,
        "model": _v(0),
        "cpu": _v(1),
        "cpu_count": _safe_int(_v(2)),
        "memory_gb": round(mem / (1024 ** 3), 1) if mem else None,
        "boot_epoch": boot,
        "uptime_seconds": int(time.time() - boot) if boot else None,
        "sip": sip,
        "domain_bound": domain is not None,
        "domain": domain,
    }


@MacosAdapter.implements("enum.users")
def _enum_users(self: MacosAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    include_disabled = bool(action.params.get("include_disabled", False))
    uids = parse_dscl_pairs(
        run(["dscl", ".", "-list", "/Users", "UniqueID"]).stdout, value_is_int=True)
    shells = parse_dscl_pairs(run(["dscl", ".", "-list", "/Users", "UserShell"]).stdout)
    reals = parse_dscl_pairs(run(["dscl", ".", "-list", "/Users", "RealName"]).stdout)
    admins = set(parse_group_membership(
        run(["dscl", ".", "-read", "/Groups/admin", "GroupMembership"]).stdout))
    lasts = parse_last(run(["last"]).stdout)

    disabled_shells = {"/usr/bin/false", "/sbin/nologin", "/dev/null",
                       "/var/empty/false"}
    users: list[dict[str, Any]] = []
    system_count = 0
    for name, uid in sorted(uids.items(), key=lambda kv: (kv[1] is None, kv[1])):
        if uid is None:
            continue
        if uid < _SYSTEM_UID_MAX or uid == 4294967294:   # role accounts / nobody
            system_count += 1
            continue
        shell = shells.get(name, "")
        disabled = shell in disabled_shells
        if disabled and not include_disabled:
            continue
        users.append({
            "name": name,
            "uid": uid,
            "real_name": reals.get(name) or None,
            "shell": shell or None,
            "admin": name in admins,
            "disabled": disabled,
            "last_login": lasts.get(name),
        })

    # Password policy needs admin/root; report honestly rather than half-read it.
    pol = run(["pwpolicy", "-getaccountpolicies"], timeout=10)
    policy_readable = pol.ok and "Getting global account policies" not in pol.stderr
    return {
        "users": users,
        "count": len(users),
        "system_account_count": system_count,
        "admins": sorted(admins),
        "password_policy_readable": policy_readable,
        "note": ("Password policy requires admin privileges to read; "
                 "not available to the current identity."
                 if not policy_readable else None),
    }


@MacosAdapter.implements("enum.privileges")
def _enum_privileges(self: MacosAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    idr = parse_id(run(["id"]).stdout)
    group_names = {g["name"] for g in idr.get("groups", [])}
    sudo = run(["sudo", "-n", "-l"], timeout=10)
    csr = run(["csrutil", "status"])
    return {
        "user": idr.get("user"),
        "uid": idr.get("uid"),
        "is_root": idr.get("uid") == 0,
        "primary_group": idr.get("group"),
        "groups": sorted(group_names),
        "is_admin": "admin" in group_names,
        "sudo": parse_sudo_l(sudo.stdout, sudo.stderr, sudo.returncode),
        "sip": "enabled" if "enabled" in csr.stdout.lower() else
               ("disabled" if "disabled" in csr.stdout.lower() else "unknown"),
    }


@MacosAdapter.implements("enum.processes")
def _enum_processes(self: MacosAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    res = run(["ps", "-axo",
               "pid=,ppid=,user=,%cpu=,%mem=,stat=,command="], timeout=20)
    rows = parse_ps(res.stdout)
    capped, total, truncated = _cap(rows)
    return {"processes": capped, "count": total, "truncated": truncated}


@MacosAdapter.implements("enum.services")
def _enum_services(self: MacosAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    """launchd jobs, resolving on-disk definitions to their binary + start type.

    ``launchctl list`` gives the loaded/running state but no binary path; the
    plists under the LaunchDaemons/LaunchAgents directories give the path and
    ``RunAtLoad``. Merging the two on the label is what produces a row with both
    "is it running" and "what does it run".
    """
    loaded = {r["label"]: r for r in parse_launchctl_list(run(["launchctl", "list"]).stdout)}
    services: list[dict[str, Any]] = []
    for directory, kind, scope in _LAUNCH_SCAN:
        d = Path(directory)
        if not d.is_dir():
            continue
        for plist in sorted(d.glob("*.plist")):
            job = _read_plist(plist)
            if job is None:
                continue
            label = job.get("Label") or plist.stem
            lr = loaded.get(label, {})
            services.append({
                "label": label,
                "program": _job_program(job),
                "kind": kind,
                "scope": scope,
                "run_at_load": bool(job.get("RunAtLoad", False)),
                "disabled": bool(job.get("Disabled", False)),
                "loaded": label in loaded,
                "running": lr.get("running", False),
                "pid": lr.get("pid"),
                "source": str(plist),
            })
    capped, total, truncated = _cap(services)
    return {
        "services": capped,
        "count": total,
        "truncated": truncated,
        "loaded_total": len(loaded),
        "note": ("System-supplied jobs under /System/Library are Apple-managed "
                 "and omitted; loaded_total counts every launchd job including "
                 "those."),
    }


@MacosAdapter.implements("enum.persistence")
def _enum_persistence(self: MacosAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    """Everything that starts without a human: launchd, login items, cron, profiles.

    launchd is the primary substrate, but persistence also lives in login items
    (surfaced via System Events), the per-user crontab, and shell rc files that a
    login shell sources — so all four are swept, each tagged with its mechanism.
    """
    entries: list[dict[str, Any]] = []

    for directory, kind, scope in _LAUNCH_SCAN:
        d = Path(directory)
        if not d.is_dir():
            continue
        for plist in sorted(d.glob("*.plist")):
            job = _read_plist(plist)
            if job is None:
                continue
            entries.append({
                "mechanism": kind,
                "label": job.get("Label") or plist.stem,
                "program": _job_program(job),
                "run_at_load": bool(job.get("RunAtLoad", False)),
                "scope": scope,
                "path": str(plist),
            })

    # Login items — no stdlib route, so osascript, kept read-only.
    li = run(["osascript", "-e",
              'tell application "System Events" to get the name of every login item'],
             timeout=15)
    if li.ok and li.stdout.strip():
        for name in [n.strip() for n in li.stdout.split(",") if n.strip()]:
            entries.append({"mechanism": "login_item", "label": name,
                           "program": None, "scope": "user", "path": None})

    # Per-user crontab (macOS keeps no /etc/cron.d that users write to).
    cron = run(["crontab", "-l"], timeout=10)
    if cron.ok:
        for line in cron.stdout.splitlines():
            s = line.strip()
            if s and not s.startswith("#"):
                entries.append({"mechanism": "cron", "label": s[:80],
                               "program": s, "scope": "user", "path": "crontab"})

    # Shell profiles a login shell sources.
    profiles = []
    for rc in (".zshrc", ".zprofile", ".bash_profile", ".bashrc", ".profile"):
        p = Path.home() / rc
        if p.is_file():
            entries.append({"mechanism": "profile", "label": rc,
                           "program": str(p), "scope": "user", "path": str(p)})
            profiles.append(rc)

    capped, total, truncated = _cap(entries)
    return {
        "entries": capped,
        "count": total,
        "truncated": truncated,
        "mechanisms_present": sorted({e["mechanism"] for e in entries}),
        "note": ("emond was removed in macOS 13 and /etc/periodic is absent on "
                 "this release, so neither contributes persistence here."),
    }


@MacosAdapter.implements("enum.network")
def _enum_network(self: MacosAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    ifaces = parse_ifconfig(run(["ifconfig", "-a"]).stdout)
    routes = parse_netstat_routes(run(["netstat", "-rn"]).stdout)
    listening = parse_lsof_inet(
        run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], timeout=20).stdout)
    udp = parse_lsof_inet(run(["lsof", "-nP", "-iUDP"], timeout=20).stdout)
    established = parse_lsof_inet(
        run(["lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED"], timeout=20).stdout)

    lc, lt, ltr = _cap(listening)
    ec, et, etr = _cap(established)
    return {
        "interfaces": [i for i in ifaces if i["inet"] or i["ether"]],
        "default_routes": routes,
        "listening": lc, "listening_total": lt, "listening_truncated": ltr,
        "udp_bound": udp[:_MAX_ROWS],
        "established": ec, "established_total": et, "established_truncated": etr,
    }


@MacosAdapter.implements("enum.software")
def _enum_software(self: MacosAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    receipts = parse_pkgutil_pkgs(run(["pkgutil", "--pkgs"], timeout=20).stdout)
    apps = parse_sp_applications(
        run(["system_profiler", "-json", "SPApplicationsDataType"], timeout=90).stdout)
    capped, total, truncated = _cap(apps)

    brew = None
    brew_path = which("brew")
    if brew_path:
        b = run([brew_path, "list", "--versions"], timeout=30)
        if b.ok:
            brew = [ln.split()[0] for ln in b.stdout.splitlines() if ln.strip()][:_MAX_ROWS]

    return {
        "applications": capped,
        "application_count": total,
        "applications_truncated": truncated,
        "receipt_count": len(receipts),
        "receipts_sample": receipts[:40],
        "homebrew_packages": brew,
    }


@MacosAdapter.implements("enum.shares")
def _enum_shares(self: MacosAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    sh = run(["sharing", "-l"], timeout=10)
    shares = parse_sharing_l(sh.stdout) if sh.ok else []
    exports = None
    ep = Path("/etc/exports")
    if ep.is_file():
        try:
            exports = [ln.strip() for ln in ep.read_text().splitlines()
                       if ln.strip() and not ln.startswith("#")]
        except OSError:
            exports = None
    guest = [s["name"] for s in shares if s.get("guest_access")]
    return {
        "shares": shares,
        "count": len(shares),
        "guest_accessible": guest,
        "nfs_exports": exports,
        "note": "sharing(1) lists SMB/AFP share points; /etc/exports covers NFS.",
    }


# ---------------------------------------------------------------------------
# detect — ask whether the blue side noticed (6 verbs)
# telemetry first: it establishes what logging even exists.
# ---------------------------------------------------------------------------


def _log_query(predicate: str, since_seconds: int, *, debug: bool = False,
               timeout: int = 40) -> Any:
    """Run one unified-log query and return parsed events (or the CommandResult).

    The window is expressed to ``log show`` as ``--last <n>s``; ``--info``/
    ``--debug`` are needed because several security-relevant subsystems log at
    those levels, not the default.
    """
    argv = [_LOG, "show", "--last", f"{since_seconds}s",
            "--predicate", predicate, "--style", "compact", "--info"]
    if debug:
        argv.append("--debug")
    res = run(argv, timeout=timeout)
    if not res.ok:
        return res
    return parse_log_events(res.stdout)


@MacosAdapter.implements("detect.telemetry")
def _detect_telemetry(self: MacosAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    """Which logging sources are actually enabled — and, honestly, which are not.

    This is the verb that keeps a report credible: reporting forty missed
    techniques on a host that never had execution auditing is noise. So it names
    the real state of each source, including the ones macOS has removed.
    """
    sources: list[dict[str, Any]] = []

    # Unified log: always present, but explicitly not an exec-audit source.
    ul = run([_LOG, "stats"], timeout=15)
    sources.append({
        "source": "unified_log", "present": True,
        "enabled": ul.ok or Path(_LOG).exists(),
        "records_process_creation": False,
        "note": "System-wide event log. Does NOT record process creation.",
    })

    # BSM / auditd: binary may exist, but config + running state are what matter.
    auditd_bin = Path("/usr/sbin/auditd").exists()
    audit_control = Path("/etc/security/audit_control").exists()
    audit_loaded = run(["launchctl", "print", "system/com.apple.auditd"],
                       timeout=10).ok
    sources.append({
        "source": "openbsm_auditd", "present": auditd_bin,
        "enabled": bool(audit_control and audit_loaded),
        "records_process_creation": bool(audit_control and audit_loaded),
        "note": ("auditd binary present but unconfigured (no "
                 "/etc/security/audit_control) and not loaded; Apple has "
                 "deprecated OpenBSM." if auditd_bin and not audit_control
                 else "OpenBSM audit not active."),
    })

    # Endpoint Security: we can see that system extensions exist, but not their
    # entitlement-gated event coverage. Say exactly that.
    sysext = Path("/Library/SystemExtensions")
    es_present = sysext.is_dir() and any(sysext.iterdir())
    sources.append({
        "source": "endpoint_security", "present": es_present,
        "enabled": None,
        "records_process_creation": None,
        "note": ("System extensions are installed; whether any is an Endpoint "
                 "Security client recording execve is not enumerable without "
                 "the platform entitlement." if es_present else
                 "No system extensions installed."),
    })

    # Background Task Management: the one genuine autostart-change telemetry.
    sources.append({
        "source": "background_task_management", "present": True, "enabled": True,
        "records_process_creation": False,
        "note": ("com.apple.backgroundtaskmanagement logs new launch agents / "
                 "daemons / login items to the unified log (macOS 13+). This is "
                 "real persistence-change telemetry."),
    })

    # Application firewall.
    fw_state = None
    if Path(_FIREWALL).exists():
        fw = run([_FIREWALL, "--getglobalstate"], timeout=10)
        fw_state = "enabled" if "enabled" in fw.stdout.lower() else "disabled"
    sources.append({
        "source": "application_firewall", "present": Path(_FIREWALL).exists(),
        "enabled": fw_state == "enabled", "records_process_creation": False,
        "note": f"socketfilterfw global state: {fw_state}.",
    })

    return {
        "sources": sources,
        "process_creation_auditing": bool(audit_control and audit_loaded),
        "summary": _NO_EXEC_AUDIT,
    }


@MacosAdapter.implements("detect.process_creation")
def _detect_process_creation(self: MacosAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    """Was process creation logged for this window/image? On stock macOS: no.

    We still make a best-effort unified-log query for the image name so the
    answer is grounded in a real lookup, but we flag plainly that any hits are
    incidental subsystem chatter, not an execve audit trail — because a model
    must not mistake "the log mentioned bash" for "exec was audited".
    """
    since = int(action.params.get("since_seconds", 300))
    image = action.params.get("image")
    audit_active = (Path("/etc/security/audit_control").exists()
                    and run(["launchctl", "print", "system/com.apple.auditd"]).ok)

    matched = 0
    samples: list[dict[str, str]] = []
    if image:
        pred = f'process == "{image}"'
        events = _log_query(pred, since, timeout=45)
        if isinstance(events, list):
            matched = len(events)
            samples = events[:8]

    return {
        "telemetry_available": audit_active,
        "window_seconds": since,
        "image": image,
        "incidental_log_mentions": matched,
        "samples": samples,
        "note": _NO_EXEC_AUDIT + (
            " The count above is unrelated unified-log activity mentioning the "
            "image, not process-creation events." if image else
            " No image supplied; nothing to correlate."),
    }


@MacosAdapter.implements("detect.persistence_change")
def _detect_persistence_change(self: MacosAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    """Was a new autostart entry logged? macOS BTM makes this a real detection.

    ``com.apple.backgroundtaskmanagement`` records ``registerItem`` /
    ``registerLaunchItem`` when a launch agent, daemon or login item is added,
    so this is one of the few macOS detections that genuinely fires.
    """
    since = int(action.params.get("since_seconds", 300))
    events = _log_query(
        'subsystem == "com.apple.backgroundtaskmanagement"', since, debug=True,
        timeout=50)
    if not isinstance(events, list):
        return Observation(
            action=action, ok=False, platform="macos",
            error=f"unified log query failed: {getattr(events, 'stderr', '')[:200]}")

    registrations = []
    for ev in events:
        msg = ev["message"]
        if "registerItem" in msg or "registerLaunchItem" in msg:
            nm = re.search(r"\bname=([^,]+)", msg)
            ty = re.search(r"\btype=(\w+)", msg)
            registrations.append({
                "ts": ev["ts"], "name": nm.group(1).strip() if nm else None,
                "type": ty.group(1) if ty else None})

    capped, total, truncated = _cap(registrations)
    return {
        "telemetry_available": True,
        "source": "com.apple.backgroundtaskmanagement",
        "window_seconds": since,
        "registrations": capped,
        "registration_count": total,
        "truncated": truncated,
        "note": ("BTM records autostart additions to the unified log; this is "
                 "genuine persistence-change telemetry on macOS 13+."),
    }


@MacosAdapter.implements("detect.credential_access")
def _detect_credential_access(self: MacosAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    """Was credential-store access logged? Partial: keychain reads are not audited.

    We query the log for the credential daemons active in the window, but note
    honestly that keychain item reads are not comprehensively recorded, so
    silence here is weak evidence.
    """
    since = int(action.params.get("since_seconds", 300))
    pred = ('process == "securityd" OR process == "trustd" '
            'OR process == "authd" OR process == "secinitd"')
    events = _log_query(pred, since, timeout=45)
    count = len(events) if isinstance(events, list) else 0
    procs: dict[str, int] = {}
    if isinstance(events, list):
        for ev in events:
            procs[ev["process"]] = procs.get(ev["process"], 0) + 1
    return {
        "telemetry_available": False,
        "window_seconds": since,
        "credential_daemon_events": count,
        "by_process": procs,
        "note": ("Keychain item reads are protected by ACLs but are not written "
                 "to an audit trail; these are daemon-liveness events, not a "
                 "record of which secrets were accessed. Absence is not proof "
                 "nothing was read."),
    }


@MacosAdapter.implements("detect.authentication")
def _detect_authentication(self: MacosAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    """Were authentication events — including failures — logged in the window?

    opendirectoryd is the arbiter of local/network auth on macOS, so its log
    plus ``last`` for interactive logins is the closest to an auth trail a stock
    box offers.
    """
    since = int(action.params.get("since_seconds", 300))
    pred = ('process == "opendirectoryd" OR process == "authd" '
            'OR eventMessage CONTAINS[c] "authentication fail" '
            'OR eventMessage CONTAINS[c] "Failed to authenticate"')
    events = _log_query(pred, since, timeout=45)
    total = len(events) if isinstance(events, list) else 0
    failures = 0
    if isinstance(events, list):
        for ev in events:
            if re.search(r"(?i)fail|denied|invalid", ev["message"]):
                failures += 1
    recent_logins = parse_last(run(["last", "-10"]).stdout)
    return {
        "telemetry_available": True,
        "window_seconds": since,
        "auth_events": total,
        "auth_failures": failures,
        "recent_logins": recent_logins,
        "note": ("opendirectoryd mediates authentication and logs it; failure "
                 "detail depends on the auth path and is not always present."),
    }


# A tiny built-in rule set: macOS has no on-host Sigma engine, so detect.rule
# supports a handful of named checks mapped to log predicates and is honest
# about anything outside that set rather than pretending to evaluate it.
_BUILTIN_RULES: dict[str, dict[str, Any]] = {
    "macos.persistence.btm_register": {
        "predicate": 'subsystem == "com.apple.backgroundtaskmanagement"',
        "match": r"registerItem|registerLaunchItem", "debug": True,
        "describes": "a new launch item was registered (BTM)",
    },
    "macos.auth.failure": {
        "predicate": 'process == "opendirectoryd"',
        "match": r"(?i)fail|denied|invalid", "debug": False,
        "describes": "an authentication failure via opendirectoryd",
    },
    "macos.ssh.session": {
        "predicate": 'process == "sshd" OR process == "sshd-session"',
        "match": r"(?i)accepted|session opened|authenticat", "debug": False,
        "describes": "an inbound SSH authentication/session",
    },
}


@MacosAdapter.implements("detect.rule")
def _detect_rule(self: MacosAdapter, verb: Verb, action: Action) -> Any:
    """Run a named built-in detection rule against recent unified-log telemetry.

    There is no host-side Sigma runtime on macOS, so an unknown rule id is an
    honest ``ok=False`` naming the built-ins, not a fabricated evaluation.
    """
    rule = action.params.get("rule", "")
    since = int(action.params.get("since_seconds", 300))
    spec = _BUILTIN_RULES.get(rule)
    if spec is None:
        return Observation(
            action=action, ok=False, platform="macos",
            error=(f"no on-host rule engine for {rule!r}. macOS has no Sigma "
                   f"runtime; built-in rules are: {sorted(_BUILTIN_RULES)}."))
    events = _log_query(spec["predicate"], since, debug=spec["debug"], timeout=50)
    if not isinstance(events, list):
        return Observation(action=action, ok=False, platform="macos",
                           error="unified log query failed")
    pat = re.compile(spec["match"])
    hits = [ev for ev in events if pat.search(ev["message"])]
    return {
        "rule": rule,
        "describes": spec["describes"],
        "window_seconds": since,
        "fired": bool(hits),
        "hit_count": len(hits),
        "samples": hits[:8],
    }


# ---------------------------------------------------------------------------
# vuln — turn observations into findings (4 verbs). All still OBSERVE.
# ---------------------------------------------------------------------------


@MacosAdapter.implements("vuln.patch_gap")
def _vuln_patch_gap(self: MacosAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    """Pending OS/security updates via softwareupdate's cached catalogue.

    ``--no-scan`` uses the last fetched catalogue so this stays fast and offline;
    softwareupdate carries no CVE/severity data, so we do not fabricate a
    severity to satisfy ``min_severity`` — we report the gaps and say why they
    are unranked.
    """
    sw = parse_sw_vers(run(["sw_vers"]).stdout)
    res = run(["softwareupdate", "--list", "--no-scan"], timeout=40)
    if res.timed_out:
        return {
            "current_build": sw.get("build"),
            "updates_available": None,
            "note": "softwareupdate timed out; patch state undetermined.",
        }
    updates = []
    for line in res.stdout.splitlines():
        m = re.search(r"\*\s*Label:\s*(.+)", line) or re.match(r"\s+\*\s+(.+)", line)
        if m:
            updates.append({"label": m.group(1).strip(), "severity": "unknown"})
    no_updates = "No new software available" in (res.stdout + res.stderr)
    return {
        "current_build": sw.get("build"),
        "os_version": sw.get("product_version"),
        "updates_available": [] if no_updates else updates,
        "up_to_date": no_updates,
        "min_severity_requested": action.params.get("min_severity", "medium"),
        "note": ("softwareupdate reports available updates but no CVE/severity, "
                 "so min_severity cannot be applied; every gap is 'unknown'. A "
                 "true CVE mapping needs an offline vulnerability database this "
                 "host does not carry."),
    }


@MacosAdapter.implements("vuln.weak_permissions")
def _vuln_weak_permissions(self: MacosAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    """Writable service binaries, world-writable plists, weak PATH dirs.

    The high-value check is a launchd job whose program is writable by the
    current (non-root) identity while the job itself runs as root: that is a
    direct service-hijack primitive. On a SIP-protected Mac most system paths
    are read-only even to root, so finding *nothing* here is the secure state,
    not a broken check.
    """
    findings: list[dict[str, Any]] = []
    scanned = 0
    for directory, kind, scope in _LAUNCH_SCAN:
        d = Path(directory)
        if not d.is_dir():
            continue
        for plist in sorted(d.glob("*.plist")):
            scanned += 1
            pf = _stat_facts(str(plist))
            if pf and (pf["world_writable"] or
                       (pf["writable_by_me"] and pf["uid"] == 0 and os.geteuid() != 0)):
                findings.append({"issue": "writable_service_plist",
                                "job": plist.stem, "scope": scope, **pf})
            job = _read_plist(plist)
            prog = _job_program(job) if job else None
            if not prog:
                continue
            bf = _stat_facts(prog)
            if bf and (bf["world_writable"] or
                       (bf["writable_by_me"] and bf["uid"] == 0 and os.geteuid() != 0)):
                findings.append({
                    "issue": "writable_service_binary",
                    "job": job.get("Label") or plist.stem,
                    "scope": scope, **bf,
                })

    # Writable directories on PATH — a plant-a-binary primitive.
    path_dirs = os.environ.get("PATH", "").split(":")
    weak_path = []
    for pd in path_dirs:
        if not pd:
            continue
        f = _stat_facts(pd)
        if f and (f["world_writable"] or f["writable_by_me"] and f["uid"] == 0):
            weak_path.append(f)

    return {
        "findings": findings,
        "finding_count": len(findings),
        "plists_scanned": scanned,
        "weak_path_dirs": weak_path,
        "running_as_root": os.geteuid() == 0,
        "note": ("No findings on a SIP-protected host is expected and good: SIP "
                 "makes system service binaries read-only even to root."
                 if not findings else None),
    }


@MacosAdapter.implements("vuln.credential_exposure")
def _vuln_credential_exposure(self: MacosAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    """Secrets in shell history, config files, rc files and the environment.

    Only files readable as the current identity and under a size cap are read,
    and matches are reported by *location and kind*, never with the secret
    material — the finding is "there is an AWS key on line 40 of .zsh_history",
    not the key.
    """
    home = Path.home()
    candidates = [
        home / ".zsh_history", home / ".bash_history", home / ".sh_history",
        home / ".zshrc", home / ".bashrc", home / ".bash_profile",
        home / ".profile", home / ".netrc", home / ".aws" / "credentials",
        home / ".git-credentials", home / ".config" / "gh" / "hosts.yml",
        home / ".ssh" / "config", home / ".pgpass", home / ".npmrc",
    ]
    findings: list[dict[str, Any]] = []
    files_scanned = 0
    for path in candidates:
        try:
            if not path.is_file() or path.stat().st_size > 4_000_000:
                continue
            text = path.read_text(errors="replace")
        except OSError:
            continue
        files_scanned += 1
        for lineno, line in enumerate(text.splitlines(), 1):
            for kind, pat in _SECRET_PATTERNS:
                if pat.search(line):
                    findings.append({
                        "source": str(path), "kind": kind, "line": lineno,
                        # Redacted: keep only a shape hint, never the value.
                        "preview": _redact_line(line),
                    })
                    break

    # Environment variables that look like secrets, reported by name only.
    env_hits = []
    for key, val in os.environ.items():
        if re.search(r"(?i)(secret|token|password|passwd|api[_-]?key|access[_-]?key)", key) \
                and val:
            env_hits.append({"variable": key, "length": len(val)})

    # SSH private keys present (and whether they are passphrase-protected).
    ssh_keys = []
    ssh_dir = home / ".ssh"
    if ssh_dir.is_dir():
        for kf in ssh_dir.iterdir():
            try:
                if not kf.is_file():
                    continue
                head = kf.read_text(errors="replace")[:2000]
            except OSError:
                continue
            if "PRIVATE KEY" in head:
                encrypted = ("ENCRYPTED" in head or "Proc-Type: 4,ENCRYPTED" in head
                             or "bcrypt" in head)
                ssh_keys.append({"path": str(kf), "encrypted": encrypted})

    capped, total, truncated = _cap(findings)
    return {
        "findings": capped,
        "finding_count": total,
        "truncated": truncated,
        "files_scanned": files_scanned,
        "env_secret_vars": env_hits,
        "ssh_private_keys": ssh_keys,
        "note": "Secret material is never recorded; only location, kind and a "
                "redacted shape hint.",
    }


def _redact_line(line: str) -> str:
    """A shape hint for a secret-bearing line, with the value blanked.

    Keeps the key/prefix so a human can find it, replaces the value with a mask,
    so nothing sensitive lands in the audit log.
    """
    s = line.strip()
    s = re.sub(r"(AKIA)[0-9A-Z]{16}", r"\1" + "*" * 16, s)
    s = re.sub(r"(gh[pousr]_)[A-Za-z0-9]{20,}", r"\1***", s)
    s = re.sub(r"(xox[baprs]-)[A-Za-z0-9-]{10,}", r"\1***", s)
    s = re.sub(r"(?i)((?:password|passwd|secret|api[_-]?key|access[_-]?key|token)"
               r"\s*[:=]\s*['\"]?)[^\s'\"]{4,}", r"\1***", s)
    s = re.sub(r"(Bearer\s+)[A-Za-z0-9._~+/-]{12,}", r"\1***", s)
    if "PRIVATE KEY" in s:
        return "-----BEGIN PRIVATE KEY----- (redacted)"
    return s[:120]


@MacosAdapter.implements("vuln.privilege_path")
def _vuln_privilege_path(self: MacosAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    """A concrete route from the current identity to root, if one exists.

    Returns the chain, not a score. On a typical admin Mac the honest chain is
    "member of the admin group + a permissive sudoers entry -> root via sudo";
    the interesting negative result is "no path beyond expected admin rights",
    which is what a hardened least-privilege account should produce.
    """
    idr = parse_id(run(["id"]).stdout)
    groups = {g["name"] for g in idr.get("groups", [])}
    is_admin = "admin" in groups
    sudo = parse_sudo_l(*(lambda r: (r.stdout, r.stderr, r.returncode))(
        run(["sudo", "-n", "-l"], timeout=10)))

    chains: list[dict[str, Any]] = []
    if idr.get("uid") == 0:
        chains.append({"chain": "already_root", "steps": ["current identity is uid 0"],
                      "to": "root"})
    if sudo.get("passwordless_all"):
        chains.append({
            "chain": "sudo_nopasswd",
            "steps": ["current identity has a NOPASSWD sudo entry granting ALL",
                      "run any command via `sudo` as root without a prompt"],
            "to": "root", "reachable_now": True,
        })
    elif sudo.get("may_run_all") or sudo.get("available"):
        chains.append({
            "chain": "sudo_password",
            "steps": ["current identity may run `sudo` (ALL) but a password is "
                      "required — no NOPASSWD:ALL entry",
                      "root reachable interactively with this user's password"],
            "to": "root", "reachable_now": False,
        })
    if sudo.get("nopasswd_commands"):
        # Specific NOPASSWD commands are a lesser primitive: root only if one of
        # them is itself exploitable (a shell-out, a writable target, etc.).
        chains.append({
            "chain": "sudo_nopasswd_commands",
            "steps": [f"passwordless sudo for specific commands: "
                      f"{sudo['nopasswd_commands']}",
                      "root only if one of these can be turned into code "
                      "execution (GTFOBins-style); not automatically a full path"],
            "to": "root", "reachable_now": False,
        })
    if is_admin:
        chains.append({
            "chain": "admin_group",
            "steps": ["member of the admin group",
                      "can write /Library privileged helper locations and "
                      "authorize privileged operations",
                      "root via an authenticated helper install"],
            "to": "root", "reachable_now": False,
        })

    # Fold in writable-service findings if any (delegates to the same checks).
    wp = _vuln_weak_permissions(self, verb, action)
    for f in wp["findings"]:
        if f["issue"] == "writable_service_binary":
            chains.append({
                "chain": "writable_service_binary",
                "steps": [f"service binary {f['path']} is writable by this user",
                          "replace it and wait for the root service to run it"],
                "to": "root", "reachable_now": True, "evidence": f})

    return {
        "chains": chains,
        "chain_count": len(chains),
        "is_admin": is_admin,
        "note": ("No chain means no route to root beyond expected rights — the "
                 "least-privilege ideal." if not chains else None),
    }


# ---------------------------------------------------------------------------
# harden — fix what the exercise proved broken (3 verbs). MODIFY.
# ---------------------------------------------------------------------------

# Named telemetry sources harden.enable_telemetry understands, each with how it
# is read and whether flipping it needs root.
_TELEMETRY_TOGGLES = {
    "firewall": {"needs_root": True,
                 "desc": "Application Firewall global state (socketfilterfw)"},
    "firewall_stealth": {"needs_root": True,
                         "desc": "Application Firewall stealth mode"},
    "auditd": {"needs_root": True,
               "desc": "OpenBSM audit (deprecated; requires audit_control + load)"},
}


@MacosAdapter.implements("harden.enable_telemetry")
def _harden_enable_telemetry(self: MacosAdapter, verb: Verb, action: Action) -> Any:
    """Turn on a logging source detect.telemetry found missing.

    Reads current state always; only *changes* it with root. Without root this
    reports the honest "requires privilege" state rather than pretending to have
    enabled anything — a silent no-op here would be the worst outcome, since a
    defender would believe telemetry is on when it is not.
    """
    source = action.params.get("source", "")
    spec = _TELEMETRY_TOGGLES.get(source)
    if spec is None:
        return Observation(
            action=action, ok=False, platform="macos",
            error=f"unknown telemetry source {source!r}; known: "
                  f"{sorted(_TELEMETRY_TOGGLES)}.")

    # Current state.
    current = None
    if source in ("firewall", "firewall_stealth") and Path(_FIREWALL).exists():
        flag = "--getglobalstate" if source == "firewall" else "--getstealthmode"
        r = run([_FIREWALL, flag], timeout=10)
        current = "enabled" if "enabled" in r.stdout.lower() else "disabled"
    elif source == "auditd":
        current = ("configured" if Path("/etc/security/audit_control").exists()
                   else "unconfigured")

    if os.geteuid() != 0 and spec["needs_root"]:
        return Observation(
            action=action, ok=False, platform="macos",
            data={"source": source, "description": spec["desc"],
                  "current_state": current, "changed": False},
            error=(f"enabling {source} ({spec['desc']}) modifies system "
                   f"security policy and requires root; current state: "
                   f"{current}. Re-run as root to apply."))

    # Root path (not exercised in self-test — this is a real system change).
    if source == "firewall":
        run([_FIREWALL, "--setglobalstate", "on"], timeout=10)
        after = run([_FIREWALL, "--getglobalstate"], timeout=10)
        now = "enabled" if "enabled" in after.stdout.lower() else "disabled"
        return {"source": source, "previous_state": current,
                "current_state": now, "changed": now != current}
    return Observation(
        action=action, ok=False, platform="macos",
        error=f"enabling {source} as root is not automated (deprecated/manual).",
        data={"source": source, "current_state": current, "changed": False})


@MacosAdapter.implements("harden.fix_permissions")
def _harden_fix_permissions(self: MacosAdapter, verb: Verb, action: Action) -> Any:
    """Tighten an ACL vuln.weak_permissions flagged, recording the prior mode.

    Removes group/other write with a stdlib ``chmod`` (no shell). The previous
    mode is captured first and returned so the change can be reverted by hand.

    The object to correct is the ``path`` parameter (the verb's HOST target
    scopes the *engagement*, not the file), so params take precedence.
    """
    target = action.params.get("path") or action.target
    if not target:
        return Observation(action=action, ok=False, platform="macos",
                           error="no path supplied to harden.fix_permissions.")
    p = Path(target)
    if not p.exists():
        return Observation(action=action, ok=False, platform="macos",
                           error=f"path does not exist: {target}")
    before = _stat_facts(str(p))
    try:
        st = os.stat(p)
        new_mode = st.st_mode & ~0o0022        # drop group + other write
        os.chmod(p, new_mode)
    except OSError as exc:
        return Observation(action=action, ok=False, platform="macos",
                           data={"previous": before},
                           error=f"chmod failed (likely needs root/owner): {exc}")
    after = _stat_facts(str(p))
    return {
        "path": str(p),
        "previous_mode": before["mode"] if before else None,
        "new_mode": after["mode"] if after else None,
        "changed": bool(before and after and before["mode"] != after["mode"]),
        "note": "Removed group/other write. Previous mode recorded for revert.",
    }


@MacosAdapter.implements("harden.remove_persistence")
def _harden_remove_persistence(self: MacosAdapter, verb: Verb, action: Action) -> Any:
    """Remove an autostart entry — including one this tool installed.

    Matches the entry identifier against user-writable launchd agents, boots it
    out of the running domain if loaded, then deletes the plist and records
    exactly what was removed. A system-scope entry that needs root, or an entry
    that cannot be located, is an honest refusal rather than a partial delete.
    """
    entry = action.params.get("entry", "")
    if not entry:
        return Observation(action=action, ok=False, platform="macos",
                           error="no entry identifier supplied.")

    # Resolve to a plist under a user-writable LaunchAgents directory.
    candidates = []
    for directory, kind, scope in _LAUNCH_SCAN:
        d = Path(directory)
        if not d.is_dir():
            continue
        for plist in d.glob("*.plist"):
            job = _read_plist(plist)
            label = (job.get("Label") if job else None) or plist.stem
            if label == entry or plist.stem == entry or str(plist) == entry:
                candidates.append((plist, label, scope))

    if not candidates:
        return Observation(action=action, ok=False, platform="macos",
                           error=f"no launchd entry matching {entry!r} was found. "
                                 "Run enum.persistence to get the exact label.")
    plist, label, scope = candidates[0]
    if scope == "system" and os.geteuid() != 0:
        return Observation(action=action, ok=False, platform="macos",
                           error=f"{label} is a system-scope entry ({plist}); "
                                 "removing it requires root.")
    if not os.access(plist, os.W_OK):
        return Observation(action=action, ok=False, platform="macos",
                           error=f"{plist} is not writable by this identity.")

    uid = os.getuid()
    booted = run(["launchctl", "bootout", f"gui/{uid}/{label}"], timeout=10)
    try:
        os.remove(plist)
        removed = True
    except OSError as exc:
        return Observation(action=action, ok=False, platform="macos",
                           error=f"failed to delete {plist}: {exc}")
    return {
        "entry": label, "plist": str(plist),
        "booted_out": booted.ok,
        "file_removed": removed,
        "note": f"Deleted {plist}; booted out of gui/{uid} (ok={booted.ok}).",
    }


# ---------------------------------------------------------------------------
# exploit / postex — the red half (8 verbs). EXECUTE, each names its detection.
#
# The file-writing mechanisms are module-level functions so a self-test can
# drive them against a sandbox directory; the handlers wire them to real
# autostart locations. Handlers against live targets are written to *refuse
# honestly* where SIP or missing privilege makes the technique inapplicable —
# a refusal is a finding (the secure state), not a bug.
# ---------------------------------------------------------------------------


def replace_file(path: str, payload: bytes) -> str:
    """Overwrite ``path`` with ``payload`` after backing the original up.

    Returns the backup path. This is the raw primitive behind a service-binary
    hijack; keeping it separate is what lets the self-test exercise the whole
    replace/restore cycle against a throwaway file instead of a real service.
    """
    backup = f"{path}.whetstone.bak"
    if not os.path.exists(backup):
        shutil.copy2(path, backup)
    with open(path, "wb") as fh:
        fh.write(payload)
    return backup


def restore_file(path: str, backup: str) -> bool:
    """Put the original back from ``backup`` and remove the backup. Truthful bool."""
    try:
        if os.path.exists(backup):
            shutil.copy2(backup, path)
            os.remove(backup)
            return True
    except OSError:
        return False
    return False


def build_launch_plist(label: str, program_args: list[str], *,
                       run_at_load: bool = True,
                       start_interval: int | None = None) -> bytes:
    """A launchd job definition as serialized plist bytes (no file touched)."""
    job: dict[str, Any] = {"Label": label, "ProgramArguments": program_args,
                           "RunAtLoad": run_at_load}
    if start_interval is not None:
        job["StartInterval"] = start_interval
    return plistlib.dumps(job)


def write_launch_job(directory: Path, label: str, plist_bytes: bytes) -> Path:
    """Write a job plist into ``directory`` and return the path. Records nothing."""
    directory.mkdir(parents=True, exist_ok=True)
    dest = directory / f"{label}.plist"
    with open(dest, "wb") as fh:
        fh.write(plist_bytes)
    return dest


@MacosAdapter.implements("exploit.service_permissions")
def _exploit_service_permissions(self: MacosAdapter, verb: Verb, action: Action) -> Any:
    """Replace a writable service binary to obtain execution as the service account.

    Resolves the named launchd job to its program and refuses unless that binary
    is genuinely writable by the current identity. On a SIP-protected Mac this
    almost always refuses — which is the correct, secure result and is reported
    as such, with the exact reason, rather than as a failure.
    """
    service = action.params.get("service", "")
    restore = bool(action.params.get("restore", True))

    program = None
    source = None
    for directory, kind, scope in _LAUNCH_SCAN:
        d = Path(directory)
        if not d.is_dir():
            continue
        for plist in d.glob("*.plist"):
            job = _read_plist(plist)
            label = (job.get("Label") if job else None) or plist.stem
            if label == service:
                program = _job_program(job) if job else None
                source = str(plist)
                break
        if program:
            break

    if program is None:
        return Observation(action=action, ok=False, platform="macos",
                           error=f"service {service!r} not found among writable "
                                 "launchd scopes.")
    facts = _stat_facts(program)
    if facts is None:
        return Observation(
            action=action, ok=False, platform="macos",
            data={"service": service, "program": program, "plist": source},
            error=(f"service binary {program} cannot be stat'd (it does not "
                   "exist, or its directory is not searchable by this identity), "
                   "so the technique does not apply."))
    if not facts["writable_by_me"]:
        return Observation(
            action=action, ok=False, platform="macos",
            data={"service": service, "program": program, "plist": source,
                  "permissions": facts},
            error=(f"service binary {program} is NOT writable by this identity — "
                   "the technique does not apply. On a SIP-protected host this is "
                   "the expected secure state, not a failure."))

    # Genuinely writable: demonstrate the replace with a benign marker, restore.
    marker = b"#!/bin/sh\n# whetstone exercise marker\nexit 0\n"
    backup = replace_file(program, marker)
    restored = restore_file(program, backup) if restore else False
    return {
        "service": service, "program_replaced": program, "backup": backup,
        "restored": restored,
        "note": ("Replaced the writable service binary with a benign marker and "
                 f"{'restored the original' if restored else 'left it replaced'}. "
                 "The service was NOT restarted by this tool."),
    }


@MacosAdapter.implements("exploit.unquoted_path")
def _exploit_unquoted_path(self: MacosAdapter, verb: Verb, action: Action) -> Observation:
    """Unsupported on macOS: launchd takes an argv array, not a parsed string.

    The Windows "unquoted service path" hijack depends on a service command
    *string* being split by a shell/CreateProcess on spaces. launchd's
    ``ProgramArguments`` is already a tokenized array and ``Program`` is a single
    executable path, so there is no search-order ambiguity to plant into. This
    is a fact about the platform, not a gap in the adapter.
    """
    return Observation(
        action=action, ok=False, unsupported=True, platform="macos",
        error=("macOS launchd has no unquoted-path search-order hijack: "
               "ProgramArguments is a tokenized argv array and Program is a "
               "single executable path, so a space in a path is never re-parsed "
               "into an alternate executable. The technique does not exist here."))


@MacosAdapter.implements("exploit.scheduled_task")
def _exploit_scheduled_task(self: MacosAdapter, verb: Verb, action: Action) -> Any:
    """Create a launchd job (macOS's scheduled task) running as a given account.

    A user-scope job goes to ``~/Library/LaunchAgents``; a SYSTEM/root job needs
    ``/Library/LaunchDaemons`` and root. Without the privilege for the requested
    account this refuses with the exact reason. Everything created is recorded
    (label + path) so it can be removed by hand, and ``cleanup`` truthfully
    reports whether the job was booted out and deleted.
    """
    as_user = str(action.params.get("as_user", "SYSTEM"))
    cleanup = bool(action.params.get("cleanup", True))
    system_scope = as_user.upper() in {"SYSTEM", "ROOT", "0"}

    if system_scope and os.geteuid() != 0:
        return Observation(
            action=action, ok=False, platform="macos",
            error=(f"a scheduled task running as {as_user} needs a LaunchDaemon "
                   "in /Library/LaunchDaemons, which requires root. Not creating "
                   "one as a non-root user."))

    directory = _launch_daemons_dir() if system_scope else _launch_agents_dir()
    label = f"com.whetstone.exercise.{os.getpid()}"
    plist_bytes = build_launch_plist(label, ["/usr/bin/true"], run_at_load=False,
                                     start_interval=3600)
    try:
        dest = write_launch_job(directory, label, plist_bytes)
    except OSError as exc:
        return Observation(action=action, ok=False, platform="macos",
                           error=f"could not write job to {directory}: {exc}")

    booted = None
    if not system_scope:
        booted = run(["launchctl", "bootstrap", f"gui/{os.getuid()}", str(dest)],
                     timeout=10).ok

    cleaned = None
    if cleanup:
        if not system_scope:
            run(["launchctl", "bootout", f"gui/{os.getuid()}/{label}"], timeout=10)
        try:
            os.remove(dest)
            cleaned = True
        except OSError:
            cleaned = False

    return {
        "label": label,
        "plist_path": str(dest),
        "as_user": as_user,
        "scope": "system" if system_scope else "user",
        "program": ["/usr/bin/true"],
        "loaded": booted,
        "cleanup_requested": cleanup,
        "cleanup_succeeded": cleaned,
        "note": (f"Created launchd job {label} at {dest}. "
                 + ("Cleaned up (booted out + deleted)." if cleaned
                    else "Left in place; remove by hand." if cleanup is False
                    else "Cleanup FAILED — remove by hand.")),
    }


@MacosAdapter.implements("postex.credential_dump")
def _postex_credential_dump(self: MacosAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    """Report what an intruder could enumerate WITHOUT prompting — and what is denied.

    The Keychain will not release secret material without an interactive
    authorization prompt, and this deliberately never triggers one: it lists the
    keychains present and the on-disk credential stores readable as this user,
    reporting account names and counts, never secrets. ``redact`` defaults true
    and is honored; even with ``redact=false`` this does not dump Keychain
    secrets, because doing so would require prompting, which it will not do.
    """
    redact = bool(action.params.get("redact", True))
    home = Path.home()

    keychains = []
    kc = run(["security", "list-keychains"], timeout=10)
    for line in kc.stdout.splitlines():
        m = re.search(r'"([^"]+)"', line)
        if m:
            keychains.append(m.group(1))

    # On-disk credential stores readable without a prompt. Report accounts/counts.
    stores: list[dict[str, Any]] = []

    def _account_scan(path: Path, kind: str, pat: re.Pattern[str]) -> None:
        try:
            if not path.is_file():
                return
            text = path.read_text(errors="replace")
        except OSError:
            return
        accts = sorted({m.group(1) for m in pat.finditer(text)})
        stores.append({"store": str(path), "kind": kind,
                      "accounts": accts if not redact else
                      [a for a in accts],  # account names are not secrets
                      "secret_count": len(pat.findall(text))})

    _account_scan(home / ".aws" / "credentials", "aws",
                  re.compile(r"\[([^\]]+)\]"))
    _account_scan(home / ".netrc", "netrc",
                  re.compile(r"machine\s+(\S+)"))
    _account_scan(home / ".git-credentials", "git",
                  re.compile(r"https?://([^:@/]+)"))

    # SSH private keys (presence + encryption, never contents).
    ssh_keys = []
    ssh_dir = home / ".ssh"
    if ssh_dir.is_dir():
        for kf in ssh_dir.iterdir():
            try:
                if kf.is_file() and "PRIVATE KEY" in kf.read_text(errors="replace")[:2000]:
                    head = kf.read_text(errors="replace")[:2000]
                    ssh_keys.append({"path": str(kf),
                                    "encrypted": "ENCRYPTED" in head or "bcrypt" in head})
            except OSError:
                continue

    return {
        "redacted": redact,
        "keychains": keychains,
        "keychain_secrets_extracted": 0,
        "on_disk_stores": stores,
        "ssh_private_keys": ssh_keys,
        "denied": {
            "keychain": ("Keychain secret material requires an interactive "
                         "authorization prompt; this tool never prompts, so "
                         "passwords/tokens in the Keychain are NOT extracted."),
            "sip_protected": ("SIP protects system keychains and credential "
                              "daemons from bulk read even by root."),
        },
        "note": ("Enumerated account names and store locations only. This is "
                 "what is reachable without prompting; the secrets themselves "
                 "remain protected by the Keychain and SIP."),
    }


@MacosAdapter.implements("postex.persistence_install")
def _postex_persistence_install(self: MacosAdapter, verb: Verb, action: Action) -> Any:
    """Install an autostart entry to demonstrate survival across reboot.

    Maps the requested mechanism to its macOS form: ``launch_agent``/``autorun``
    -> a user LaunchAgent, ``service`` -> a LaunchDaemon (root), ``profile`` -> a
    marker line in the shell rc, ``cron`` -> the user crontab. Records exactly
    what was written and where; ``cleanup`` truthfully reports removal.
    """
    mechanism = action.params.get("mechanism")
    cleanup = bool(action.params.get("cleanup", True))
    label = f"com.whetstone.persist.{os.getpid()}"
    installed: dict[str, Any] = {"mechanism": mechanism, "label": label}

    if mechanism in ("launch_agent", "autorun", "service"):
        system_scope = mechanism == "service"
        if system_scope and os.geteuid() != 0:
            return Observation(action=action, ok=False, platform="macos",
                               error="a LaunchDaemon (service) persistence entry "
                                     "requires root. Refusing as non-root.")
        directory = _launch_daemons_dir() if system_scope else _launch_agents_dir()
        plist_bytes = build_launch_plist(label, ["/usr/bin/true"], run_at_load=True)
        try:
            dest = write_launch_job(directory, label, plist_bytes)
        except OSError as exc:
            return Observation(action=action, ok=False, platform="macos",
                               error=f"could not write {directory}: {exc}")
        installed.update({"path": str(dest), "program": ["/usr/bin/true"],
                         "scope": "system" if system_scope else "user"})
        loaded = None
        if not system_scope:
            loaded = run(["launchctl", "bootstrap", f"gui/{os.getuid()}", str(dest)],
                         timeout=10).ok
        installed["loaded"] = loaded
        if cleanup:
            if not system_scope:
                run(["launchctl", "bootout", f"gui/{os.getuid()}/{label}"], timeout=10)
            try:
                os.remove(dest)
                installed["cleanup_succeeded"] = True
            except OSError:
                installed["cleanup_succeeded"] = False

    elif mechanism == "profile":
        rc = _shell_profile_path()
        marker = f"\n# whetstone-exercise-{os.getpid()}\n:  # no-op persistence marker\n"
        try:
            before = rc.read_text() if rc.exists() else ""
            with open(rc, "a") as fh:
                fh.write(marker)
        except OSError as exc:
            return Observation(action=action, ok=False, platform="macos",
                               error=f"could not append to {rc}: {exc}")
        installed.update({"path": str(rc), "marker": marker.strip()})
        if cleanup:
            try:
                rc.write_text(before)
                installed["cleanup_succeeded"] = True
            except OSError:
                installed["cleanup_succeeded"] = False

    elif mechanism == "cron":
        existing = run(["crontab", "-l"], timeout=10)
        base = existing.stdout if existing.ok else ""
        line = f"@reboot /usr/bin/true # whetstone-exercise-{os.getpid()}\n"
        newtab = base + ("" if base.endswith("\n") or not base else "\n") + line
        wr = run(["crontab", "-"], stdin=newtab, timeout=10)
        if not wr.ok:
            return Observation(action=action, ok=False, platform="macos",
                               error=f"crontab install failed: {wr.stderr[:200]}")
        installed.update({"path": "crontab", "entry": line.strip()})
        if cleanup:
            restore = run(["crontab", "-"], stdin=base, timeout=10)
            installed["cleanup_succeeded"] = restore.ok
    else:
        return Observation(action=action, ok=False, platform="macos",
                           error=f"unknown mechanism {mechanism!r}.")

    installed["note"] = ("Autostart entry installed and recorded above; "
                         + ("cleaned up." if installed.get("cleanup_succeeded")
                            else "cleanup not requested or FAILED — remove by hand."))
    return installed


@MacosAdapter.implements("postex.privilege_escalate")
def _postex_privilege_escalate(self: MacosAdapter, verb: Verb, action: Action) -> Any:
    """Execute a previously identified escalation chain and confirm the result.

    Only chains vuln.privilege_path can find are honored. The ``sudo_nopasswd``
    chain is confirmed non-destructively by running ``sudo -n id`` — if it
    returns uid 0 the route is proven without changing anything; if a password
    would be required it refuses cleanly (``-n`` never prompts). Unknown chains
    are refused rather than "attempted".
    """
    chain = action.params.get("chain", "")
    if chain in ("sudo_nopasswd", "sudo"):
        r = run(["sudo", "-n", "id"], timeout=10)
        idr = parse_id(r.stdout) if r.ok else None
        if r.ok and idr and idr.get("uid") == 0:
            return {"chain": chain, "escalated": True, "proof": "sudo -n id -> uid=0",
                    "resulting_uid": 0, "note": "Root reachable via passwordless "
                    "sudo, proven non-destructively. No state changed."}
        return Observation(
            action=action, ok=False, platform="macos",
            data={"chain": chain, "escalated": False},
            error=("passwordless sudo not available (sudo -n requires a "
                   "password); cannot prove this chain without prompting."))
    if chain == "already_root":
        return {"chain": chain, "escalated": os.geteuid() == 0,
                "resulting_uid": os.geteuid()}
    return Observation(
        action=action, ok=False, platform="macos",
        error=(f"chain {chain!r} was not produced by vuln.privilege_path or is "
               "not confirmable non-destructively on macOS. Run "
               "vuln.privilege_path first and pass one of its chain ids."))


@MacosAdapter.implements("postex.lateral_move")
def _postex_lateral_move(self: MacosAdapter, verb: Verb, action: Action) -> Any:
    """Authenticate to another in-scope host and confirm access, no prompts.

    SSH uses ``BatchMode=yes`` so a missing key fails instead of prompting, and
    ``UserKnownHostsFile=/dev/null`` so no known_hosts is written. WinRM/RDP have
    no native macOS client, so those methods are refused honestly from this
    platform rather than faked.
    """
    method = action.params.get("method")
    as_user = action.params.get("as_user", "")
    target = action.target
    if not target:
        return Observation(action=action, ok=False, platform="macos",
                           error="no target host supplied.")
    host = target.split(":", 1)[1] if target.startswith("host:") else target

    if method == "ssh":
        r = run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
                 "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                 f"{as_user}@{host}", "id"], timeout=15)
        idr = parse_id(r.stdout) if r.ok else None
        if r.ok and idr and idr.get("uid") is not None:
            return {"method": "ssh", "host": host, "as_user": as_user,
                    "authenticated": True, "remote_uid": idr.get("uid"),
                    "note": "Key-based SSH auth succeeded (BatchMode)."}
        reason = "connection refused" if "refused" in r.stderr.lower() else (
            "auth failed / no key" if "denied" in r.stderr.lower() else
            "unreachable or timed out")
        return Observation(action=action, ok=False, platform="macos",
                           data={"method": "ssh", "host": host, "as_user": as_user,
                                 "authenticated": False, "reason": reason},
                           error=f"SSH to {host} did not authenticate: {reason}.")
    if method == "smb":
        # Reachability only, no credentials sent.
        reachable = _tcp_reachable(host, 445, timeout=5)
        return {"method": "smb", "host": host, "port_445_open": reachable,
                "authenticated": False,
                "note": ("SMB port reachability only; no credentials were sent. "
                         "Full smbutil auth is out of scope for a non-prompting "
                         "probe.")}
    return Observation(
        action=action, ok=False, platform="macos",
        error=(f"method {method!r} has no native macOS client (winrm/rdp are "
               "Windows remote-access protocols); cannot perform it from here."))


def _tcp_reachable(host: str, port: int, *, timeout: float = 5.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


@MacosAdapter.implements("postex.exfil_probe")
def _postex_exfil_probe(self: MacosAdapter, verb: Verb, action: Action) -> Any:
    """Measure whether a volume of *synthetic* bytes can leave to an in-scope sink.

    Sends generated filler — never file contents — to ``sink`` to see whether the
    egress path and volume are permitted. The sink is ``host[:port]``; with no
    port it defaults to 443. Nothing sensitive is transmitted, which is the whole
    point of an exfil *probe*.
    """
    sink = action.params.get("sink", "")
    nbytes = int(action.params.get("bytes", 1048576))
    if sink.startswith("host:"):
        sink = sink[5:]
    host, _, port_s = sink.partition(":")
    port = _safe_int(port_s) or 443
    if not host:
        return Observation(action=action, ok=False, platform="macos",
                           error="no sink host supplied.")

    started = time.perf_counter()
    sent = 0
    chunk = b"\x00" * 65536
    try:
        with socket.create_connection((host, port), timeout=8) as sock:
            sock.settimeout(8)
            while sent < nbytes:
                n = sock.send(chunk[: min(len(chunk), nbytes - sent)])
                if n <= 0:
                    break
                sent += n
    except OSError as exc:
        return Observation(
            action=action, ok=False, platform="macos",
            data={"sink": f"{host}:{port}", "bytes_requested": nbytes,
                  "bytes_sent": sent, "connected": sent > 0},
            error=f"egress to {host}:{port} failed after {sent} bytes: {exc}")
    ms = int((time.perf_counter() - started) * 1000)
    return {
        "sink": f"{host}:{port}",
        "bytes_requested": nbytes,
        "bytes_sent": sent,
        "duration_ms": ms,
        "egress_allowed": sent >= nbytes,
        "synthetic": True,
        "note": ("Sent synthetic zero-filled bytes only; no file contents left "
                 "the host. Measures egress volume, not data theft."),
    }
