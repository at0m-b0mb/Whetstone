"""Drive the agent against the real Lima VM over SSH.

The sandbox proves the loop's logic on a contained directory tree. This proves
it on an actual operating system — a real kernel, real systemd, real auditd,
real file permissions — which is the difference between "the pairing logic is
correct" and "the tool works against a machine". It is the roadmap's item 2 and
half of item 4, delivered against a VM that boots in under a minute.

The design reuses the Linux adapter's parsers rather than reimplementing them.
Those parsers were written as pure functions precisely so they could be tested
off-platform against captured fixtures; here they finally meet the real command
output they were modelled on. An ``ssh`` transport runs the command on the VM
and hands the raw text to the same ``parse_*`` function the host adapter uses,
so a bug in a parser is caught in one place and a fix lands for both.

Everything runs through ``limactl shell`` with an argv list, so the no-shell
guarantee holds across the SSH boundary: a model-supplied parameter is a single
argv entry to ``limactl``, never a fragment of a command line the VM's shell
parses. The one place a remote shell is unavoidable — running a compound command
on the VM — passes a fixed script with the parameter supplied through argv to
that script, not interpolated into it.
"""

from __future__ import annotations

import os
import subprocess
from typing import Any

from whetstone.actions import Action, Observation, Verb
from whetstone.adapters import linux as linux_adapter
from whetstone.adapters.base import Adapter, AdapterError

__all__ = ["VMAdapter", "vm_available"]

_LIMA_HOME = os.environ.get(
    "LIMA_HOME", "/Volumes/at0m_b0mb/whetstone/lab/lima")
_VM = os.environ.get("WHETSTONE_LAB_VM", "whetstone-lab")


def _run_on_vm(argv: list[str], *, timeout: int = 30) -> tuple[int, str, str]:
    """Run one argv list on the VM. No shell on either side of the boundary."""
    full = ["limactl", "shell", "--workdir", "/", _VM, "--", *argv]
    env = {**os.environ, "LIMA_HOME": _LIMA_HOME}
    try:
        proc = subprocess.run(full, capture_output=True, text=True,
                              timeout=timeout, env=env, errors="replace")
    except FileNotFoundError:
        raise AdapterError("limactl not found; is Lima installed?") from None
    except subprocess.TimeoutExpired:
        return -1, "", f"timed out after {timeout}s"
    return proc.returncode, proc.stdout, proc.stderr


def vm_available() -> bool:
    """Whether the lab VM is running and reachable."""
    rc, out, _ = _run_on_vm(["true"], timeout=10)
    return rc == 0


class VMAdapter(Adapter):
    """The catalogue against the real Lima VM. Not a registered platform."""

    platform = "linux-vm"

    def __init__(self) -> None:
        if not vm_available():
            raise AdapterError(
                f"lab VM {_VM!r} is not reachable. Start it with:\n"
                f"  LIMA_HOME={_LIMA_HOME} limactl start "
                "lab/vm/whetstone-lab.yaml")


V = VMAdapter


def _observe(parser, argv: list[str], key: str = "") -> Any:
    """Run a command on the VM and parse it with the Linux adapter's parser."""
    rc, out, err = _run_on_vm(argv)
    if rc != 0 and not out:
        raise AdapterError(f"{' '.join(argv)} failed on the VM: {err.strip()[:160]}")
    return parser(out)


# --------------------------------------------------------------- enumerate
# Each handler runs a real command on the VM and reuses the host Linux parser,
# so the parser meets the exact output it was written against.

@V.implements("enum.host")
def _host(self: VMAdapter, verb: Verb, action: Action) -> Any:
    rc, out, _ = _run_on_vm(["sh", "-c",
        "cat /etc/os-release; echo '---'; uname -a; echo '---'; hostname"])
    os_release, _, rest = out.partition("---")
    uname, _, host = rest.partition("---")
    pretty = next((ln.split("=", 1)[1].strip().strip('"')
                   for ln in os_release.splitlines()
                   if ln.startswith("PRETTY_NAME=")), "Linux")
    return {"os": pretty, "kernel": uname.strip(), "hostname": host.strip()}


@V.implements("enum.privileges")
def _priv(self: VMAdapter, verb: Verb, action: Action) -> Any:
    return _observe(linux_adapter.parse_id, ["id"])


@V.implements("enum.services")
def _services(self: VMAdapter, verb: Verb, action: Action) -> Any:
    return {"services": _observe(
        linux_adapter.parse_systemctl_units,
        ["systemctl", "list-units", "--type=service", "--all",
         "--no-pager", "--plain", "--no-legend"])}


@V.implements("enum.processes")
def _processes(self: VMAdapter, verb: Verb, action: Action) -> Any:
    rc, out, _ = _run_on_vm(
        ["ps", "-eo", "pid,ppid,user,comm", "--no-headers"], timeout=15)
    procs = []
    for ln in out.splitlines():
        parts = ln.split(None, 3)
        if len(parts) == 4:
            pid, ppid, user, comm = parts
            procs.append({"pid": pid, "ppid": ppid, "user": user, "comm": comm})
    return {"processes": procs}


# ------------------------------------------------------------------- assess

@V.implements("vuln.weak_permissions")
def _weak(self: VMAdapter, verb: Verb, action: Action) -> Any:
    """Find world-writable files owned by root under a couple of real paths."""
    rc, out, _ = _run_on_vm(
        ["find", "/opt", "/usr/local", "-maxdepth", "3", "-type", "f",
         "-perm", "-0002", "-user", "root"], timeout=25)
    hits = [{"path": ln.strip(), "technique": "T1574.010",
             "why": "world-writable file owned by root"}
            for ln in out.splitlines() if ln.strip()]
    return {"findings": hits}


@V.implements("vuln.credential_exposure")
def _creds(self: VMAdapter, verb: Verb, action: Action) -> Any:
    rc, out, _ = _run_on_vm(
        ["grep", "-rIl", "-e", "password", "-e", "secret", "/etc/acme.conf"],
        timeout=15)
    files = [ln.strip() for ln in out.splitlines() if ln.strip()]
    return {"findings": [{"path": f, "technique": "T1552.001"} for f in files]}


# ------------------------------------------------------------------ exploit

@V.implements("exploit.service_permissions")
def _exploit_service(self: VMAdapter, verb: Verb, action: Action) -> Any:
    """Really overwrite the writable binary on the VM, then restore it.

    This is a real write to a real file on a real operating system. It is safe
    only because the VM is a disposable target that exists to be broken, the
    binary is one the lab planted, and the engagement scopes the agent to it.
    """
    path = "/opt/acme/acme-agent"
    restore = bool(action.params.get("restore", True))

    rc, original, _ = _run_on_vm(["cat", path])
    if rc != 0:
        raise AdapterError(f"{path} not present on the VM")

    marker = "#!/bin/sh\n# whetstone marker\n"
    # tee reads the payload from stdin, so the payload is never on a command
    # line the VM shell parses.
    write = subprocess.run(
        ["limactl", "shell", "--workdir", "/", _VM, "--",
         "sudo", "tee", path],
        input=marker, capture_output=True, text=True,
        env={**os.environ, "LIMA_HOME": _LIMA_HOME})
    changed = write.returncode == 0

    cleaned = None
    if restore and changed:
        restore_proc = subprocess.run(
            ["limactl", "shell", "--workdir", "/", _VM, "--", "sudo", "tee", path],
            input=original, capture_output=True, text=True,
            env={**os.environ, "LIMA_HOME": _LIMA_HOME})
        rc2, now, _ = _run_on_vm(["cat", path])
        cleaned = now == original

    return {"changed": path, "ran_as": "root", "wrote": changed,
            "cleanup": "succeeded" if cleaned else
            ("failed" if restore else "not requested")}


# ------------------------------------------------------------------- detect

@V.implements("detect.telemetry")
def _telemetry(self: VMAdapter, verb: Verb, action: Action) -> Any:
    """Is auditd actually running and are rules loaded? The real blue posture."""
    rc, active, _ = _run_on_vm(["systemctl", "is-active", "auditd"])
    rc2, rules, _ = _run_on_vm(["sudo", "auditctl", "-l"], timeout=15)
    running = active.strip() == "active"
    rule_lines = [ln for ln in rules.splitlines()
                  if ln.strip() and "No rules" not in ln]
    return {"sources": [{"source": "auditd", "enabled": running,
                         "rules_loaded": len(rule_lines)}],
            "process_creation_auditing": running and bool(rule_lines),
            "summary": (f"auditd is {active.strip()} with {len(rule_lines)} "
                        "rule(s) loaded" if running else
                        "auditd is not running; this host would see nothing")}


#: The key the lab's auditd watch rule tags its records with.
AUDIT_KEY = "whetstone_svc"

_AUDIT_EPOCH = __import__("re").compile(r"audit\((\d+)\.")


@V.implements("detect.process_creation")
def _detect_proc(self: VMAdapter, verb: Verb, action: Action) -> Any:
    """Did auditd record a change to the watched binary in the window?

    Reads the raw audit log rather than ``ausearch``, deliberately. ``ausearch
    -ts recent`` silently found nothing on this VM while the log plainly held the
    records — a clock-skew between the guest RTC and ausearch's window, common on
    cloud images under a lightweight hypervisor. Parsing the log's own
    ``audit(EPOCH:seq)`` timestamps and comparing them to the guest's own clock
    keeps both sides on the same clock, so the window is honoured without
    trusting ausearch's interpretation of "recent".

    The pairing here is the file-modification watch, which is the correct
    detection for T1574.010: the exploit overwrites a root-owned binary, and a
    ``-w <path> -p wa`` rule is exactly what catches that. An execve rule would
    fire only when the replaced binary later ran, which this lab does not do.
    """
    since = int(action.params.get("since_seconds", 300))
    rc_now, now_s, _ = _run_on_vm(["date", "+%s"])
    try:
        cutoff = int(now_s.strip()) - since
    except ValueError:
        cutoff = 0

    rc, log, _ = _run_on_vm(["sudo", "tail", "-n", "2000",
                             "/var/log/audit/audit.log"], timeout=20)
    hits = 0
    for line in log.splitlines():
        if f"key=\"{AUDIT_KEY}\"" not in line and AUDIT_KEY not in line:
            continue
        m = _AUDIT_EPOCH.search(line)
        if m and int(m.group(1)) >= cutoff:
            hits += 1

    return {"logged": hits > 0, "count": hits,
            "note": (f"auditd recorded {hits} write(s) to the watched binary"
                     if hits else
                     "auditd has no record of the change — either no watch rule "
                     "is loaded, or it is not watching this path")}
