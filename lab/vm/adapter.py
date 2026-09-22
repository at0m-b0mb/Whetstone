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
import posixpath
import re
import subprocess
import time
from typing import Any

from whetstone.actions import Action, Observation, Verb
from whetstone.adapters import linux as linux_adapter
from whetstone.adapters.base import Adapter, AdapterError

__all__ = ["VMAdapter", "vm_available", "AUDIT_KEY", "SERVICE_PATH",
           "SERVICE_IMAGE", "TELEMETRY_SOURCE", "LAB_PATHS", "AUDIT_RULE_ARGV"]

_LIMA_HOME = os.environ.get(
    "LIMA_HOME", "/Volumes/at0m_b0mb/whetstone/lab/lima")
_VM = os.environ.get("WHETSTONE_LAB_VM", "whetstone-lab")

#: The binary the lab planted world-writable, and the name a detection probe
#: aims by. Both are constants rather than parameters: the ``service`` parameter
#: arriving from a model chooses *which finding is being proven*, not which file
#: on the guest gets overwritten, and a red verb that took its target from model
#: output would be one typo away from rewriting something the VM needs.
SERVICE_PATH = "/opt/acme/acme-agent"

#: What the red handler publishes under ``image`` and what ``detect.
#: process_creation`` matches an audit ``PATH`` record against. The bare
#: basename rather than the full path, matching the sandbox's ``_SERVICE_IMAGE``
#: so the two labs speak one vocabulary; the matcher below accepts either form.
SERVICE_IMAGE = "acme-agent"

#: The one telemetry source this guest has. ``harden.enable_telemetry`` takes a
#: ``source`` parameter and this is the only value it can honour — see the
#: handler for why anything else is declined rather than quietly treated as this.
TELEMETRY_SOURCE = "auditd"

#: The key the lab's auditd watch rule tags its records with.
AUDIT_KEY = "whetstone_svc"

#: The file-modification watch, as the argv that loads it. One definition shared
#: by ``harden.enable_telemetry`` and by the runner's ``--arm``, because the
#: experiment compares "armed by hand" against "armed by the agent" and those
#: two are only comparable if they load the identical rule. Two copies of this
#: that drifted would make the run's central before/after meaningless while
#: still printing a number.
AUDIT_RULE_ARGV: tuple[str, ...] = (
    "-w", SERVICE_PATH, "-p", "wa", "-k", AUDIT_KEY)

#: Where on the guest a ``path`` parameter may point. The gate's path scope is
#: the first line here and this is the second, deliberately: the gate resolves a
#: path against *this* machine's filesystem while the adapter acts on the
#: *guest's*, so a symlink or a case-folded name on the macOS host would have the
#: two disagree about which file is meant. The check that matters for what
#: actually gets chmod-ed is the one performed on the string that crosses to the
#: VM, which is this one.
LAB_PATHS: tuple[str, ...] = ("/opt/acme",)


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


def _run_on_vm_stdin(argv: list[str], payload: str, *,
                     timeout: int = 30) -> tuple[int, str, str]:
    """Run one argv list on the VM feeding *payload* on stdin, bounded.

    The sibling of ``_run_on_vm`` for the two commands that must hand the VM a
    payload without it ever appearing on a command line the VM shell parses
    (``tee`` reads it from stdin). It is a separate function purely so the
    timeout cannot be forgotten: base.run() states the rule for the whole runtime
    — "A timeout is mandatory and finite" — because a blocked ``subprocess.run``
    never *raises*, so ``Adapter.execute``'s except-to-Observation net cannot
    catch it and the kernel's turn loop wedges forever with no observation and no
    diagnostic. A half-open Lima SSH control connection on macOS wake is the
    ordinary way that happens mid-run. On expiry we return the same
    ``(-1, "", msg)`` tuple ``_run_on_vm`` uses, so a stall is just another failed
    command to the caller rather than a hang.
    """
    full = ["limactl", "shell", "--workdir", "/", _VM, "--", *argv]
    env = {**os.environ, "LIMA_HOME": _LIMA_HOME}
    try:
        proc = subprocess.run(full, input=payload, capture_output=True,
                              text=True, timeout=timeout, env=env,
                              errors="replace")
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


def _lab_path(raw: str) -> str:
    """A guest path a MODIFY verb may act on, or a loud refusal.

    ``harden.fix_permissions`` takes its ``path`` from a model or from a
    remediation hint published by the target, and it ends in ``sudo chmod`` on a
    real operating system. The gate checks it first — the VM engagement carries
    ``/opt/acme`` in its path scope precisely so ``scope.path.unlisted`` denies
    ``/etc/shadow`` before this function ever runs — and this is the second lock
    rather than a duplicate of the first, because the two do not check the same
    thing. **The gate resolves the path against the machine running the gate;
    this adapter acts on the guest.** A ``/opt/acme`` that is a symlink on the
    macOS host, or a name the host's case-insensitive filesystem folds, would
    have the gate approve one file and the VM modify another. The string that
    crosses to the VM is the only one whose confinement decides what actually
    gets chmod-ed, so it is checked here too, on the guest's own terms.

    Which is why this normalises with :mod:`posixpath` and never with
    :class:`pathlib.Path`. ``Path.resolve()`` would consult the *host's*
    filesystem — following host symlinks, inventing a working directory for a
    relative path — to answer a question about the guest's. ``posixpath.normpath``
    is pure text: it collapses ``..`` without asking any filesystem anything,
    which is the only honest way to reason about a path on a machine this
    process cannot stat.
    """
    if not raw.startswith("/"):
        # Refused rather than resolved. A relative path has no meaning without a
        # working directory, and the working directory here belongs to a shell
        # on the other side of an SSH boundary — so "resolving" it would mean
        # guessing, and the guess would aim a chmod.
        raise AdapterError(
            f"{raw!r} is not an absolute path on the guest; this adapter will "
            "not guess a working directory for a file it is about to chmod")
    path = posixpath.normpath(raw)
    for root in LAB_PATHS:
        if path == root or path.startswith(root.rstrip("/") + "/"):
            return path
    raise AdapterError(
        f"{path} is outside the lab's own directory ({', '.join(LAB_PATHS)}); "
        "this VM is disposable but it is not a scratchpad, and a hardening verb "
        "gets no exemption for meaning well. Nothing was changed.")


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
    """Really overwrite the writable binary on the VM, as the unprivileged user.

    This is a real write to a real file on a real operating system. It is safe
    only because the VM is a disposable target that exists to be broken, the
    binary is one the lab planted, and the engagement scopes the agent to it.

    **The write is deliberately NOT run under sudo**, and that is the single
    change that makes ``harden.fix_permissions`` mean anything here. The
    weakness the lab planted is a root-owned binary at mode 0777: a user who is
    not root can replace the file a root service executes. ``limactl shell``
    lands on the guest as an ordinary uid, so that user is a real one and the
    kernel enforces the weakness for real — which is exactly what the sandbox
    cannot do and has to model instead, because the sandbox process *owns* its
    file and cannot be locked out of it by any mode change.

    Writing this through ``sudo`` would exercise nothing. root ignores the mode
    bits, so the attack would keep succeeding after a chmod that genuinely
    worked, ``harden.fix_permissions`` could never be shown to be effective, and
    the fix would be unfalsifiable — a verb that always reports success and can
    never be caught not working, which is the failure this whole project is
    built to make impossible.

    The *restore* does keep its sudo, and the asymmetry is meant rather than
    overlooked. The attack is the model's action and has to meet the machine's
    real answer; the cleanup is the operator putting their own lab back, using
    their own privilege. It matters because a restore that can be refused is a
    restore that leaves the binary holding the marker, and the next exercise
    then reads a tampered file as its baseline.

    A write that did not take raises rather than returning a cheerful
    ``wrote: False``. The kernel reads a failed re-attack as "the technique no
    longer runs, and that tells you nothing about the control" — the honest
    verdict after a permissions fix — whereas a successful observation saying
    nothing happened would be scored as a silent control and reported as the fix
    having been *ineffective*, which is a false accusation against a fix that
    worked perfectly.
    """
    path = SERVICE_PATH
    restore = bool(action.params.get("restore", True))

    rc, original, _ = _run_on_vm(["cat", path])
    if rc != 0:
        raise AdapterError(f"{path} not present on the VM")

    # The payload carries a nonce, and it has to. A FIXED marker makes the
    # read-back below say nothing: a guest whose binary already held the marker
    # — from a previous exercise whose restore did not complete, or from an
    # operator testing by hand — compares equal whether or not this invocation
    # wrote a single byte. That is not hypothetical; it is how this was found.
    # After `harden.fix_permissions` really blocked the write, the handler still
    # reported `wrote: true` against a file that happened to already contain the
    # marker, which would have told the remediation phase that a fix that worked
    # perfectly had failed. A nonce makes "the file holds this" mean "this
    # invocation put it there".
    marker = (f"#!/bin/sh\n# whetstone marker {time.time_ns()}\n")
    wrote = False
    cleaned = None
    write_err = ""
    try:
        # tee reads the payload from stdin, so the payload is never on a command
        # line the VM shell parses. A bounded run means a stalled write (a dead
        # SSH transport on host wake) reports rc=-1 and falls through to the
        # restore instead of hanging the whole episode.
        _, _, write_err = _run_on_vm_stdin(["tee", path], marker)
        # Read the file back rather than believing tee's exit status. The
        # returncode is a claim about a pipeline that ran over SSH; the contents
        # are the evidence, and this project's whole argument is that the two are
        # not the same thing. It also settles the case tee cannot report on its
        # own: a partial write that exited zero.
        rc_v, after, _ = _run_on_vm(["cat", path])
        wrote = rc_v == 0 and after == marker
    finally:
        # Restore lives in a finally, not behind ``if wrote``, because the
        # danger is precisely the path where the write did NOT cleanly succeed:
        # a timed-out or half-applied write can leave the binary holding the
        # marker, and the next run reads that corrupted file at ``cat path`` as
        # its "original" baseline — so the following exercise would compare a
        # tampered baseline against itself and call the cleanup a success. The
        # revert therefore has to be attempted on every exit path, and its own
        # write is bounded too so a dead VM cannot hang teardown either.
        if restore:
            _run_on_vm_stdin(["sudo", "tee", path], original)
            rc_c, now, _ = _run_on_vm(["cat", path])
            cleaned = rc_c == 0 and now == original

    if not wrote:
        # Raised after the finally has already put the binary back, so the
        # failure path still leaves the guest tidy. The mode is quoted because
        # it is the answer to the only question worth asking here — a fix landed
        # on this file, or it never was writable in the first place.
        rc_m, mode, _ = _run_on_vm(["stat", "-c", "%a owned by %U", path])
        raise AdapterError(
            f"could not overwrite {path} as the unprivileged lab user: it is "
            f"now mode {mode.strip() or '(unreadable)'} and tee said "
            f"{write_err.strip()[:80] or 'nothing'}. The technique depended on "
            "the group/other write bit and that bit is gone.")

    return {"changed": path, "ran_as": "the unprivileged lab user",
            "wrote": wrote,
            "cleanup": "succeeded" if cleaned else
            ("failed" if restore else "not requested"),
            # Named `image` because that is what `detect.process_creation` calls
            # its own parameter, which is the exact-match convention the kernel
            # aims a probe by. Without it the probe asks "was anything logged in
            # the window" and the kernel — correctly — refuses to read that as a
            # verdict on this technique, so a gap here could never be proven
            # closed however good the fix was.
            "image": SERVICE_IMAGE,
            # What would fix this, under the key the kernel reads and under the
            # harden verb's own parameter name. The red handler is the only
            # thing that knows which file it just overwrote. The kernel ranks
            # this *below* a hint published by the blind control itself, which
            # is why enabling the watch wins over tightening the mode: a
            # detection gap is a statement about the control.
            "remediation": {"harden.fix_permissions": {"path": path}}}


# ------------------------------------------------------------------- detect

@V.implements("detect.telemetry")
def _telemetry(self: VMAdapter, verb: Verb, action: Action) -> Any:
    """Is auditd actually running and are rules loaded? The real blue posture."""
    rc, active, err = _run_on_vm(["systemctl", "is-active", "auditd"])
    # ``is-active`` legitimately exits non-zero when auditd is simply not active
    # and still prints the state ("inactive"/"failed") to stdout, so a non-zero
    # rc here is an *answer*, not a failure — checking rc would misread a dead
    # service as a broken query. The broken-query case is the command not running
    # at all (systemctl missing, sudo denied, timeout), which ``_run_on_vm``
    # surfaces as empty output. Reporting that as "auditd is not running" would
    # assert the blue posture of a host we never managed to ask; fail loudly so
    # it becomes a failed Observation instead of a fabricated all-clear.
    if not active.strip():
        raise AdapterError(
            f"could not query auditd state on the VM: {err.strip()[:120]}")
    rc2, rules, err2 = _run_on_vm(["sudo", "auditctl", "-l"], timeout=15)
    # ``auditctl -l`` prints "No rules" (rc 0) when none are loaded, so empty
    # output is never a legitimate "zero rules" — it means the listing itself
    # failed (no auditctl, no sudo, timeout). Counting that as 0 rules would
    # report a watched host as unwatched, the same inversion in miniature.
    if rc2 != 0 and not rules.strip():
        raise AdapterError(
            f"could not list auditd rules on the VM: {err2.strip()[:120]}")
    running = active.strip() == "active"
    rule_lines = [ln for ln in rules.splitlines()
                  if ln.strip() and "No rules" not in ln]
    return {"sources": [{"source": "auditd", "enabled": running,
                         "rules_loaded": len(rule_lines)}],
            "process_creation_auditing": running and bool(rule_lines),
            "summary": (f"auditd is {active.strip()} with {len(rule_lines)} "
                        "rule(s) loaded" if running else
                        "auditd is not running; this host would see nothing")}


#: ``audit(EPOCH.ms:SERIAL)`` — both halves, because both are load-bearing. The
#: epoch honours the detection window; the serial is what ties a ``SYSCALL``
#: record to the ``PATH`` records that say which file it touched, since auditd
#: writes one event as several consecutive lines sharing that number.
_AUDIT_EVENT = re.compile(r"audit\((\d+)\.\d+:(\d+)\)")

#: The filename inside a ``type=PATH`` record. Quoted form only, which is not an
#: oversight: auditd hex-encodes a name containing characters it will not put in
#: a quoted string, and this pattern deliberately does not match that. The cost
#: is under-counting a write to a path with an exotic name, and under-counting
#: on this side surfaces as a fix reported *ineffective* — a loud, wrong,
#: investigable result. Matching a hex blob by guesswork could instead attribute
#: a record to the wrong file and report a hole shut.
_AUDIT_PATH_NAME = re.compile(r'\bname="([^"]*)"')


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

    ``image``, when the kernel supplies it, is **honoured** rather than accepted
    and ignored, and the remediation phase is the reason it had to be. A probe
    whose discriminator the adapter throws away answers "was anything of this
    kind logged in the window", and the kernel — which tracks its unfilled
    discriminators in ``unaimed`` — refuses to read that as a verdict on this
    technique. So an unaimed probe can record a gap (silence in a window
    containing the technique is still silence) but can never *close* one: a hit
    after the re-attack would be unattributable and the fix would come back
    ``undetermined`` forever, no matter how well it worked. Honouring ``image``
    is what makes closure on a real operating system provable at all.
    """
    since = int(action.params.get("since_seconds", 300))
    image = action.params.get("image")
    image = image.strip() if isinstance(image, str) else ""
    rc_now, now_s, err_now = _run_on_vm(["date", "+%s"])
    try:
        cutoff = int(now_s.strip()) - since
    except ValueError:
        # A wrong window is worse than a crash: with no readable guest clock we
        # cannot honour ``since_seconds`` at all, and the old ``cutoff = 0`` did
        # not disable the check — it widened the window to all of history, so
        # every stale keyed record in the 2000-line tail would count and a real
        # gap could read as a hit. We cannot answer the question, so we refuse
        # it; the raise becomes a failed Observation and ``detection_fired``
        # returns None ("cannot tell"), never False.
        raise AdapterError(
            f"could not read the guest clock to size the detection window: "
            f"date returned {now_s.strip()!r} ({err_now.strip()[:80]})")

    rc, log, err = _run_on_vm(["sudo", "tail", "-n", "2000",
                              "/var/log/audit/audit.log"], timeout=20)
    # A tail that could not run tells us nothing about the control. The old code
    # ignored ``rc`` and let a failed read fall through as an empty log, so a
    # permission error or a 20s timeout on a loaded VM returned ``logged: False``
    # — indistinguishable from a real "auditd saw nothing", and the kernel would
    # then write a detection_gap manufactured entirely out of a broken query.
    # Mirror ``_observe``: an error with no output is raised, so the turn is a
    # failed Observation and the gap is never fabricated.
    if rc != 0 and not log:
        raise AdapterError(
            f"could not read the audit log on the VM: {err.strip()[:160]}")

    # One pass, two collections, because the evidence for one write is spread
    # across several lines. auditd emits an event as consecutive records sharing
    # an ``audit(EPOCH:SERIAL)`` id: the ``SYSCALL`` record says who did what and
    # whether it worked, and the ``PATH`` records say which files were touched.
    # Neither alone answers "did the watched binary get written"; the serial is
    # what joins them.
    #
    # ``candidates`` maps serial -> epoch for every record that is a real,
    # recorded, successful write under our key. The ``-w -p wa`` watch tags its
    # SYSCALL record with key="whetstone_svc" — but auditd tags its OWN
    # rule-administration records with that same key, emitting a
    # ``type=CONFIG_CHANGE op=add_rule key="whetstone_svc"`` line every time the
    # rule is armed and ``op=remove_rule`` every time it is disarmed. A bare
    # ``AUDIT_KEY in line`` test reduces the whole question to "does this line
    # mention the string anywhere", so arming the watch — or a stale disarm from
    # an earlier run — counts as a detected write. That inverts the project's
    # central measurement: ARMING the control would manufacture the proof it
    # fired. So we require the access record itself:
    #   * key="whetstone_svc" in its exact keyed form (no bare-substring
    #     fallback, which is what let CONFIG_CHANGE through);
    #   * type=SYSCALL — the record of the syscall that touched the file, which
    #     a CONFIG_CHANGE line never is;
    #   * success=yes — the write actually completed; a denied/failed syscall is
    #     not evidence the binary changed, and after harden.fix_permissions the
    #     log really does fill up with success=no openat records from the
    #     re-attack being refused by the kernel.
    # The explicit CONFIG_CHANGE exclusion is redundant given the SYSCALL
    # requirement, but it is kept so the intent survives a later refactor that
    # loosens the type check.
    candidates: dict[str, int] = {}
    touched: dict[str, set[str]] = {}
    for line in log.splitlines():
        event = _AUDIT_EVENT.search(line)
        if event is None:
            continue
        epoch, serial = int(event.group(1)), event.group(2)
        if "type=PATH" in line:
            name = _AUDIT_PATH_NAME.search(line)
            if name is not None:
                touched.setdefault(serial, set()).add(name.group(1))
            continue
        if f'key="{AUDIT_KEY}"' not in line:
            continue
        if "type=SYSCALL" not in line or "type=CONFIG_CHANGE" in line:
            continue
        if "success=yes" not in line:
            continue
        candidates[serial] = epoch

    # PATH records follow their SYSCALL record in the file, so the one way the
    # join can be incomplete is a ``tail`` boundary landing inside an event —
    # which loses the SYSCALL line and drops the event entirely rather than
    # leaving it half-attributed. 2000 lines against a log the runner truncates
    # per exercise makes that unreachable in practice; it is written down because
    # the failure would be a silent under-count, and an under-count here reads as
    # a gap.
    hits = 0
    unattributed = 0
    for serial, epoch in candidates.items():
        if epoch < cutoff:
            continue
        if image and not _names_the_image(image, touched.get(serial, frozenset())):
            # A keyed successful write we cannot tie to the file we were asked
            # about. Not counted, and counted separately so the note can say so:
            # "we found writes but none to your file" and "we found nothing at
            # all" are different states of the world, and only the first one
            # suggests the watch is aimed at something else.
            unattributed += 1
            continue
        hits += 1

    aim = f" to {image}" if image else ""
    if hits:
        note = f"auditd recorded {hits} write(s){aim}"
    elif unattributed:
        note = (f"auditd recorded {unattributed} keyed write(s) in the window "
                f"but none of them touched {image}")
    else:
        note = ("auditd has no record of the change — either no watch rule is "
                "loaded, or it is not watching this path")

    payload: dict[str, Any] = {"logged": hits > 0, "count": hits,
                               "aimed_at": image, "note": note}
    if hits == 0 and not unattributed:
        # The control naming its own remedy, published only when it saw nothing
        # — a control that fired has nothing to remediate, and a hint attached to
        # a hit would offer a fix for a gap that does not exist. The kernel
        # prefers this over the red side's hint, which is what makes loading the
        # watch beat tightening the mode: a detection gap is a statement about
        # the control, and the fix that answers it is the one that makes the next
        # instance of the technique visible.
        #
        # Withheld when writes were found but not attributed, because then the
        # watch is demonstrably loaded and enabling it again would change
        # nothing while reporting success.
        #
        # Note what this payload deliberately does NOT carry. An ``enabled:
        # false`` or a ``source: "none"`` here would be read by
        # ``detection_fired`` as provenance — "the source could not be queried" —
        # and the honest reading is the opposite: the log is present, readable,
        # and really was read. It is empty because nothing wrote to it while the
        # technique ran. That is a queryable control that saw nothing, which is
        # the one finding this lab exists to produce, and dressing it up as
        # unknowable would suppress it.
        payload["remediation"] = {
            "harden.enable_telemetry": {"source": TELEMETRY_SOURCE}}
    return payload


def _names_the_image(image: str, names: "frozenset[str] | set[str]") -> bool:
    """Whether any ``PATH`` record in an event names the file we asked about.

    Exact on both forms and nothing looser. ``image`` is the sandbox's
    vocabulary — a bare ``acme-agent`` — while an audit ``PATH`` record carries
    the resolved ``/opt/acme/acme-agent``, so both are accepted; a substring test
    would additionally accept ``agent`` and any path that merely contained the
    word, which is how a probe starts answering a broader question than the one
    put to it. The project has already shipped that bug once on the detection
    side, and on this side its consequence is a hole reported shut.

    The ``PARENT`` record for the same event names ``/opt/acme/`` — whose
    basename is the empty string — so it cannot match, which is the intended
    outcome: writing *into* the directory is not writing the binary.
    """
    return any(n == image or posixpath.basename(n) == image for n in names)


# -------------------------------------------------------------------- harden
#
# The half this adapter did not have. Until now the VM could attack and could
# ask whether anything saw, but could not fix anything — so the defending half
# of the project was demonstrable only in the sandbox, against a contained
# directory tree, and every claim about real hosts rested on the red side alone.
#
# Each of these really changes the guest: the mode bits really move, the watch
# rule really loads into the running kernel, the autostart file really goes.
# That is not a nicety, because the kernel proves closure by RE-ATTACKING. A
# fix that returned ok=True without doing anything would be caught within two
# turns — the exploit would succeed again and the control would stay silent —
# and reported as the gap still being open. A half-hearted implementation here
# shows up immediately as a failure rather than as a false success, which is the
# property that makes the remediation phase worth having.
#
# Every one of them therefore ends by READING THE GUEST BACK. A command's exit
# status is a claim about a pipeline that ran over SSH; the mode, the loaded
# rule list and the file listing are the evidence. Where the two can disagree
# the evidence wins, and where the evidence says the change did not take, the
# handler raises instead of returning a cheerful payload.
#
# None of them writes anything a detection verb reads. ``detect.process_creation``
# counts keyed SYSCALL records against the watched binary; arming the watch emits
# a CONFIG_CHANGE record carrying the same key, which the detector refuses by
# type, and the kernel independently takes a silent baseline reading after the
# fix and before the re-attack. Both guards exist because a fix that can
# manufacture its own proof is the exact failure the re-attack was built to
# catch, and it would be embarrassing to reintroduce it in the fix itself.


def _watch_loaded(rules: str) -> bool:
    """Whether ``auditctl -l`` output already contains the lab's write watch.

    Parsed into flags rather than compared as a string. ``auditctl`` prints a
    rule in its own normal form, not the argv it was given, so an exact-text
    comparison against :data:`AUDIT_RULE_ARGV` would answer "not loaded" the
    first time a future auditd reorders or respells anything — and this function
    deciding "not loaded" means the fix reports having changed something it did
    not, which is the claim the whole phase exists to stop.

    The permission field is checked for ``w`` specifically. A watch on the same
    path with the same key but ``-p r`` is a real rule that would list here and
    would never fire for a write, so treating "the path and key appear" as
    loaded would read a read-watch as write coverage.
    """
    for line in rules.splitlines():
        tokens = line.split()
        flags = dict(zip(tokens, tokens[1:]))
        if flags.get("-w") != SERVICE_PATH or flags.get("-k") != AUDIT_KEY:
            continue
        if "w" in flags.get("-p", ""):
            return True
    return False


@V.implements("harden.enable_telemetry")
def _harden_telemetry(self: VMAdapter, verb: Verb, action: Action) -> Any:
    """Really load the file-modification watch into the running kernel.

    This is the fix that closes the gap a VM run actually finds. Out of the box
    the provisioned guest runs auditd with no rules loaded — the commonest real
    blue posture there is, the tool present and watching nothing — so the
    exploit succeeds unobserved and the control is honestly silent. Loading this
    one rule is the whole difference, and the kernel proves it by attacking
    again.

    Deliberately the *same* rule the runner's ``--arm`` loads, from one shared
    constant. The run's central comparison is "armed by hand, no gap" against
    "armed by the agent, gap closed", and two rules that drifted apart would
    make that comparison meaningless while still printing a number.

    Live only, not persisted to ``/etc/audit/rules.d``. The shipped Linux
    adapter does both, and the difference is the target: that one hardens a
    machine somebody depends on, where a control that disappears at the next
    reboot is not a fix. This is a disposable lab whose runner re-plants its
    weakness at the top of every exercise, and a rule surviving a reboot would
    quietly carry one exercise's posture into the next — which is the confound
    the truncation and the re-planting exist to remove.
    """
    source = action.params["source"]
    if source != TELEMETRY_SOURCE:
        # `unsupported` rather than an error, because this is a fact about the
        # guest rather than a failure: it has one telemetry source and that is
        # not it. Enabling a source that does not exist would report success and
        # change nothing, which is the one outcome worse than declining.
        return Observation(
            action=action, ok=False, unsupported=True, platform=V.platform,
            error=(f"this VM has one telemetry source, {TELEMETRY_SOURCE!r}; "
                   f"{source!r} is not something it can turn on."))

    rc_a, active, err_a = _run_on_vm(["systemctl", "is-active", "auditd"])
    # See _telemetry: a non-zero rc with state on stdout is an answer, empty
    # output is a query that never ran. Both are refused here, for the same
    # reason but not the same one as there. auditctl loads a rule into the
    # KERNEL, and it succeeds whether or not a daemon is alive to drain the
    # records — so on a host with auditd stopped this verb would return rc=0,
    # report the watch armed, and produce a control that still sees nothing.
    # That is precisely a fix that reports success and changes nothing, so we
    # refuse to attempt it rather than leave the re-attack to discover it.
    if not active.strip():
        raise AdapterError(
            f"could not query auditd state on the VM: {err_a.strip()[:120]}")
    if active.strip() != "active":
        raise AdapterError(
            f"auditd is {active.strip()} on this guest. auditctl would load the "
            "watch into the kernel and report success, but with no daemon "
            "draining the records nothing would be written and the control "
            "would still see nothing — a fix that changes nothing while "
            "claiming to. Start it first: sudo systemctl start auditd")

    rc_b, before, err_b = _run_on_vm(["sudo", "auditctl", "-l"], timeout=15)
    # `auditctl -l` prints "No rules" (rc 0) when none are loaded, so empty
    # output is never a legitimate "zero rules" — it means the listing failed.
    # Proceeding on an unreadable listing would make `was_already_on` a guess,
    # and the verification below would have nothing to compare against.
    if rc_b != 0 and not before.strip():
        raise AdapterError(
            f"could not list auditd rules before arming: {err_b.strip()[:120]}")
    already = _watch_loaded(before)

    if not already:
        _run_on_vm(["sudo", "auditctl", *AUDIT_RULE_ARGV], timeout=15)

    # The evidence. auditctl's returncode is not consulted at all: what decides
    # whether this verb did its job is whether the kernel is now holding the
    # rule, and that is a question with an answer. `-e 2` locks the config and
    # makes auditctl exit non-zero; a re-provisioned guest can lose passwordless
    # sudo; either way the honest report is the rule list, not the exit code.
    rc_c, after, err_c = _run_on_vm(["sudo", "auditctl", "-l"], timeout=15)
    if rc_c != 0 and not after.strip():
        raise AdapterError(
            f"could not list auditd rules after arming, so there is no evidence "
            f"the watch loaded: {err_c.strip()[:120]}")
    if not _watch_loaded(after):
        raise AdapterError(
            f"auditctl did not load the watch on {SERVICE_PATH}; the rule list "
            f"still reads {after.strip()[:160]!r}. Reporting this as enabled "
            "would hand the re-attack a control that was never armed.")

    return {"source": TELEMETRY_SOURCE, "enabled": True,
            "rule": " ".join(AUDIT_RULE_ARGV),
            "changed": not already, "was_already_on": already,
            "restore_hint": f"sudo auditctl -W {SERVICE_PATH} -p wa -k {AUDIT_KEY}"}


@V.implements("harden.fix_permissions")
def _harden_permissions(self: VMAdapter, verb: Verb, action: Action) -> Any:
    """Really strip group/other write from the binary on the guest.

    Strips ``go-w`` and touches nothing else, which is what the shipped Linux
    adapter does and for the reason it gives: loosening is never the fix, and
    removing the group/other write bit addresses exactly what
    ``vuln.weak_permissions`` flagged without guessing at intent.

    On this guest the fix is genuinely effective and genuinely falsifiable,
    which the sandbox cannot manage. The sandbox process owns its file, so no
    mode change can lock it out and the foothold has to be modelled; here the
    binary is owned by root, ``limactl shell`` lands as an ordinary uid, and the
    kernel enforces the mode for real. After this runs, the exploit's write is
    refused by the operating system — verified by hand, and the refused attempt
    even shows up in the audit log as a ``success=no`` record, which the
    detector declines to count as a write.

    That means the re-attack the kernel performs to check this fix will *fail*,
    and the honest verdict it produces is ``undetermined``: the technique can no
    longer run, which is a real outcome and tells you nothing about whether the
    control would have seen it. That is the correct answer and not a defect in
    this handler. The fix that answers a *detection* gap is enabling the watch,
    and the kernel prefers it because the blind control publishes it.

    The path goes through :func:`_lab_path`, so a parameter pointing at
    ``/etc/shadow`` is refused on the guest's own terms in addition to being
    denied by the gate's path scope. A blue verb gets no exemption for meaning
    well.
    """
    path = _lab_path(action.params["path"])

    rc_b, before, err_b = _run_on_vm(["stat", "-c", "%a", path])
    if rc_b != 0 or not before.strip():
        raise AdapterError(
            f"cannot stat {path} on the VM, so there is no ACL to fix: "
            f"{err_b.strip()[:120]}")

    # `go-w` in symbolic form rather than an octal mode computed here. An octal
    # chmod would have to be built from the mode read a moment ago, and the two
    # commands are separate round trips over SSH — so anything that changed the
    # file in between would be silently overwritten with a stale mode. The
    # symbolic form asks the guest's own chmod to clear two bits of whatever it
    # finds, which cannot clobber a concurrent change.
    _run_on_vm(["sudo", "chmod", "go-w", path])

    rc_a, after, err_a = _run_on_vm(["stat", "-c", "%a", path])
    if rc_a != 0 or not after.strip():
        raise AdapterError(
            f"could not re-read the mode of {path} after chmod, so there is no "
            f"evidence the fix took: {err_a.strip()[:120]}")
    # chmod's exit status is not consulted: the mode is. A fix whose proof is
    # the exit code of the command that claimed to apply it is not proof.
    if int(after.strip(), 8) & 0o022:
        raise AdapterError(
            f"chmod did not clear the group/other write bits on {path}: it is "
            f"still mode {after.strip()}. Reporting this as fixed would leave "
            "the weakness in place under a green line.")

    return {"path": path, "previous_mode": f"0o{before.strip()}",
            "new_mode": f"0o{after.strip()}",
            "changed": before.strip() != after.strip(),
            "restore_hint": f"sudo chmod {before.strip()} {path}"}


#: The substring an autostart entry must carry before this adapter will remove
#: it. This is a borrowed machine with a real init system on it, and a verb that
#: removed whatever it was pointed at would be one bad parameter away from
#: disabling something the guest needs to boot. The lab plants everything it
#: plants under its own name, so requiring the name is a cheap way of saying
#: "remove only what this project put here".
_PLANTED_MARKER = "whetstone"


@V.implements("harden.remove_persistence")
def _harden_remove_persistence(self: VMAdapter, verb: Verb, action: Action) -> Any:
    """Really remove a planted autostart entry — or decline, honestly.

    **Nothing in this lab plants persistence.** The guest's provisioning creates
    a world-writable binary and a credential file and nothing else, and this
    adapter implements neither ``enum.persistence`` nor
    ``postex.persistence_install``, so no observation here can name an entry.
    The ordinary answer this verb gives on this VM is therefore ``unsupported``,
    and that is the point of writing it: an adapter that reported fixing
    something that was never there is worse than one that declines, because the
    first produces a report saying a hole was closed and the second produces a
    report saying nothing happened.

    It still looks, and it still removes for real when there is something to
    remove — a unit or a drop-in planted by hand, which is how this was verified.
    Two forms, matching the shipped Linux adapter's:

    * a systemd unit name — checked to exist, then ``disable --now``;
    * an absolute file path — moved aside rather than deleted, so an operator
      can put it back with one ``mv``.

    A bare cron *line* is not accepted, for the reason the Linux adapter gives:
    it is too easy to delete the wrong one. The sandbox can accept a line
    because it hands the line out verbatim from its own ``enum.persistence``, so
    an exact match is always satisfiable by a caller that looked first. Nothing
    on this guest hands anything out, so an entry arriving here was composed
    rather than observed, and a composed cron line is a guess at another line's
    text.

    Both accepted forms must also carry :data:`_PLANTED_MARKER`. That refusal is
    an error rather than an ``unsupported``, because it is this adapter
    declining to act, not the guest lacking the concept.
    """
    entry = action.params["entry"].strip()
    if not entry:
        raise AdapterError("no entry was named, so there is nothing to remove")
    if _PLANTED_MARKER not in entry:
        raise AdapterError(
            f"{entry!r} does not carry the lab's own {_PLANTED_MARKER!r} marker. "
            "This adapter removes persistence this project planted and nothing "
            "else: the guest is disposable but it is a real machine with a real "
            "init system, and a hardening verb that disabled whatever it was "
            "handed would be one bad parameter from breaking the boot. Nothing "
            "was changed.")

    if entry.endswith((".service", ".timer", ".path", ".socket")):
        # `systemctl cat` fails on a unit that does not exist, which is the
        # cheapest existence check that does not also start anything.
        rc, _, _ = _run_on_vm(["systemctl", "cat", entry], timeout=15)
        if rc != 0:
            return Observation(
                action=action, ok=False, unsupported=True, platform=V.platform,
                error=(f"no unit named {entry!r} exists on this guest, so there "
                       "is nothing to remove. This lab plants no persistence; "
                       "reporting a removal here would be inventing one."))
        _run_on_vm(["sudo", "systemctl", "disable", "--now", entry], timeout=30)
        rc_v, state, _ = _run_on_vm(["systemctl", "is-enabled", entry], timeout=15)
        # `is-enabled` prints the state on stdout and exits non-zero for most of
        # the states that mean "not enabled", so the text is the answer and the
        # returncode is not. An empty read means the query itself failed, and a
        # removal we cannot confirm is a removal we do not claim.
        if not state.strip():
            raise AdapterError(
                f"disabled {entry} but could not read its state back, so there "
                "is no evidence the change took")
        if state.strip() == "enabled":
            raise AdapterError(
                f"{entry} is still enabled after systemctl disable --now; the "
                "autostart entry is still there.")
        return {"entry": entry, "action": "systemctl disable --now",
                "now": state.strip(), "removed": 1,
                "restore_hint": f"sudo systemctl enable --now {entry}"}

    if entry.startswith("/"):
        path = posixpath.normpath(entry)
        rc, _, _ = _run_on_vm(["test", "-f", path], timeout=15)
        if rc != 0:
            return Observation(
                action=action, ok=False, unsupported=True, platform=V.platform,
                error=(f"{path} is not a file on this guest, so there is "
                       "nothing to remove. This lab plants no persistence; "
                       "reporting a removal here would be inventing one."))
        aside = path + ".whetstone-disabled"
        # Moved aside, not deleted. Reversible by hand with one command, which
        # matters on a machine where the entry might have been something the
        # operator planted for a different reason than this run assumed.
        _run_on_vm(["sudo", "mv", path, aside], timeout=15)
        rc_gone, _, _ = _run_on_vm(["test", "-e", path], timeout=15)
        rc_there, _, _ = _run_on_vm(["test", "-f", aside], timeout=15)
        if rc_gone == 0 or rc_there != 0:
            raise AdapterError(
                f"could not move {path} aside; it is still in place, so the "
                "autostart entry has not been removed.")
        return {"entry": path, "action": "moved aside", "moved_to": aside,
                "removed": 1, "restore_hint": f"sudo mv {aside} {path}"}

    return Observation(
        action=action, ok=False, unsupported=True, platform=V.platform,
        error=(f"cannot act on persistence entry {entry!r} on this guest: name "
               "a systemd unit or an absolute file path. A raw cron line is "
               "refused rather than matched, because nothing on this VM reports "
               "one verbatim — so an entry in that form was composed rather "
               "than observed, and removing a near-enough line deletes a "
               "different entry than the one that was meant."))
