"""Tests for the real-VM adapter and runner.

These never touch a Lima VM. Every command that would cross the SSH boundary is
stubbed, because the properties under test are about *how the handler reads what
the VM said*, not about the VM: does arming the watch get miscounted as a write,
does a broken query get misreported as a gap, does a stalled write still get
reverted. Those are pure interpretation bugs, and interpretation is exactly what
can be exercised off-platform against canned output — the same argument the
adapter's own docstring makes for reusing the Linux parsers.

The distinction the detection tests defend is the one the whole project turns on
and the one ``detection_fired`` encodes: a control that *fired*, a control that
*did not fire* (a real gap), and a query that *could not be answered* (which must
never collapse into "did not fire", or the report manufactures gaps out of its
own failures). Arming auditd, and a failed log read, each corrupt that
measurement in opposite directions, so both are pinned here.
"""

from __future__ import annotations

import subprocess
import time

import pytest

import whetstone.verbs  # noqa: F401  (registers the catalogue)
from whetstone.actions import REGISTRY
from whetstone.kernel import detection_fired

from lab.vm import adapter as vm_adapter
from lab.vm import run as vm_run
from lab.vm.adapter import AUDIT_KEY, VMAdapter


def _adapter() -> VMAdapter:
    # Bypass __init__: it probes a live VM, and these tests supply the VM's
    # answers themselves. execute() only needs the class-level handler table.
    return VMAdapter.__new__(VMAdapter)


def _detect(since_seconds: int = 300):
    verb = REGISTRY.get("detect.process_creation")
    action = REGISTRY.bind("detect.process_creation",
                           {"since_seconds": since_seconds}, target="127.0.0.1")
    return _adapter().execute(verb, action)


def _syscall_line(epoch: int, *, success: str = "yes") -> str:
    return (f"type=SYSCALL msg=audit({epoch}.124:457): arch=c000003e "
            f"syscall=257 success={success} exit=3 a0=ffffff9c "
            f'comm="tee" exe="/usr/bin/tee" key="{AUDIT_KEY}"')


def _config_change_line(epoch: int, *, op: str = "add_rule") -> str:
    return (f"type=CONFIG_CHANGE msg=audit({epoch}.123:456): auid=1000 ses=1 "
            f'op={op} key="{AUDIT_KEY}" list=4 res=1')


class TestDetectProcessCreation:
    """The parse that decides whether auditd saw the exploit."""

    def test_arming_the_watch_is_not_counted_as_a_write(self, monkeypatch):
        """A CONFIG_CHANGE add_rule record carries the key but is not a write.

        This is the inversion the project most has to avoid: the sequence that
        arms the watch writes a keyed rule-administration record into the log,
        and the old bare-substring filter counted it — so turning the control ON
        manufactured the proof that it fired.
        """
        now = int(time.time())

        def fake(argv, *, timeout=30):
            if argv[:2] == ["date", "+%s"]:
                return 0, f"{now}\n", ""
            if argv[0] == "sudo" and "tail" in argv:
                return 0, _config_change_line(now) + "\n", ""
            return 0, "", ""

        monkeypatch.setattr(vm_adapter, "_run_on_vm", fake)
        obs = _detect()
        assert obs.ok
        assert obs.data["logged"] is False
        assert obs.data["count"] == 0

    def test_disarm_remove_rule_record_is_not_counted(self, monkeypatch):
        """The stale ``op=remove_rule`` a previous run leaves is not a write.

        This is the cross-run leak: a disarm from an earlier exercise sits in the
        log, and a later standalone detect (training trajectories drive the VM
        adapter with no truncation) would otherwise read it as a fresh write.
        """
        now = int(time.time())

        def fake(argv, *, timeout=30):
            if argv[:2] == ["date", "+%s"]:
                return 0, f"{now}\n", ""
            if argv[0] == "sudo" and "tail" in argv:
                return 0, _config_change_line(now, op="remove_rule") + "\n", ""
            return 0, "", ""

        monkeypatch.setattr(vm_adapter, "_run_on_vm", fake)
        obs = _detect()
        assert obs.data["logged"] is False
        assert obs.data["count"] == 0

    def test_a_real_recorded_write_is_counted(self, monkeypatch):
        """The positive control: a genuine SYSCALL write must still register.

        Without this the CONFIG_CHANGE fix could pass by making the filter reject
        everything, which would be the same lie the other way round.
        """
        now = int(time.time())

        def fake(argv, *, timeout=30):
            if argv[:2] == ["date", "+%s"]:
                return 0, f"{now}\n", ""
            if argv[0] == "sudo" and "tail" in argv:
                return 0, (_config_change_line(now) + "\n"
                           + _syscall_line(now) + "\n"), ""
            return 0, "", ""

        monkeypatch.setattr(vm_adapter, "_run_on_vm", fake)
        obs = _detect()
        assert obs.data["logged"] is True
        assert obs.data["count"] == 1  # the SYSCALL record, not the CONFIG_CHANGE

    def test_a_failed_write_syscall_is_not_counted(self, monkeypatch):
        """success=no is a denied/failed syscall, not evidence the file changed."""
        now = int(time.time())

        def fake(argv, *, timeout=30):
            if argv[:2] == ["date", "+%s"]:
                return 0, f"{now}\n", ""
            if argv[0] == "sudo" and "tail" in argv:
                return 0, _syscall_line(now, success="no") + "\n", ""
            return 0, "", ""

        monkeypatch.setattr(vm_adapter, "_run_on_vm", fake)
        obs = _detect()
        assert obs.data["logged"] is False

    def test_a_failed_log_read_is_not_a_gap(self, monkeypatch):
        """A tail that could not run answers nothing — it must not read as False.

        ``detection_fired`` returning False makes the kernel write a
        detection_gap. A permission error or a timeout on the read yields an
        empty log, and the old code returned ``logged: False`` for it,
        indistinguishable from "auditd saw nothing". The query has to fail
        loudly so ``detection_fired`` returns None ("cannot tell") instead.
        """
        now = int(time.time())

        def fake(argv, *, timeout=30):
            if argv[:2] == ["date", "+%s"]:
                return 0, f"{now}\n", ""
            if argv[0] == "sudo" and "tail" in argv:
                return 1, "", "tail: cannot open audit.log: Permission denied"
            return 0, "", ""

        monkeypatch.setattr(vm_adapter, "_run_on_vm", fake)
        obs = _detect()
        assert obs.ok is False
        assert detection_fired(obs) is None

    def test_an_unreadable_clock_does_not_widen_the_window(self, monkeypatch):
        """A bad ``date`` must fail, not silently set the window to all history.

        The old ``except ValueError: cutoff = 0`` did not disable the check — it
        made every stale keyed record in the tail eligible, so a real gap could
        read as a hit. With no clock we cannot honour ``since_seconds``, so we
        refuse the query rather than answer it wrongly.
        """
        def fake(argv, *, timeout=30):
            if argv[:2] == ["date", "+%s"]:
                return 0, "not-a-number\n", ""
            if argv[0] == "sudo" and "tail" in argv:
                return 0, "", ""  # a clean, successful, empty read
            return 0, "", ""

        monkeypatch.setattr(vm_adapter, "_run_on_vm", fake)
        obs = _detect()
        assert obs.ok is False
        assert detection_fired(obs) is None


class TestDetectTelemetry:
    """The blue-posture read must not assert about a host it never reached."""

    def test_unreachable_systemctl_is_not_reported_as_not_running(self, monkeypatch):
        """Empty is-active output means we could not ask, not "inactive"."""
        def fake(argv, *, timeout=30):
            if argv[:2] == ["systemctl", "is-active"]:
                return -1, "", "timed out after 30s"  # command never ran
            if argv[:2] == ["sudo", "auditctl"]:
                return 0, "No rules\n", ""
            return 0, "", ""

        monkeypatch.setattr(vm_adapter, "_run_on_vm", fake)
        verb = REGISTRY.get("detect.telemetry")
        obs = _adapter().execute(verb, REGISTRY.bind("detect.telemetry",
                                                     target="127.0.0.1"))
        assert obs.ok is False

    def test_an_inactive_service_is_a_valid_answer(self, monkeypatch):
        """is-active exits non-zero with "inactive" on stdout — that is an answer."""
        def fake(argv, *, timeout=30):
            if argv[:2] == ["systemctl", "is-active"]:
                return 3, "inactive\n", ""  # non-zero rc, but a real state
            if argv[:2] == ["sudo", "auditctl"]:
                return 0, "No rules\n", ""
            return 0, "", ""

        monkeypatch.setattr(vm_adapter, "_run_on_vm", fake)
        verb = REGISTRY.get("detect.telemetry")
        obs = _adapter().execute(verb, REGISTRY.bind("detect.telemetry",
                                                     target="127.0.0.1"))
        assert obs.ok is True
        assert obs.data["sources"][0]["enabled"] is False


class TestExploitRevert:
    """A stalled or failed write must still be reverted, and never hang."""

    def _run_exploit(self, monkeypatch, *, write_rc):
        """Drive _exploit_service with subprocess.run stubbed at the boundary.

        Patching at subprocess.run (not the _run_on_vm helpers) is deliberate:
        it intercepts the old inline writes and the new helper alike, so the same
        test measures behaviour across the fix rather than around it.
        """
        original = "#!/bin/sh\n# legitimate\n"
        tee_payloads: list[str] = []

        def fake_run(cmd, **kw):
            inner = cmd[6:]  # after: limactl shell --workdir / <VM> --
            if inner[:1] == ["cat"]:
                return subprocess.CompletedProcess(cmd, 0, stdout=original,
                                                   stderr="")
            if inner[:2] == ["sudo", "tee"]:
                tee_payloads.append(kw.get("input", ""))
                rc = write_rc if len(tee_payloads) == 1 else 0
                return subprocess.CompletedProcess(cmd, rc, stdout="", stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        monkeypatch.setattr(vm_adapter.subprocess, "run", fake_run)
        verb = REGISTRY.get("exploit.service_permissions")
        action = REGISTRY.bind("exploit.service_permissions",
                               {"service": "acme-agent", "restore": True},
                               target="127.0.0.1")
        obs = _adapter().execute(verb, action)
        return obs, tee_payloads

    def test_revert_runs_even_when_the_write_fails(self, monkeypatch):
        """The restore is in a finally, so a non-succeeding write still reverts.

        The old ``if restore and changed`` skipped the revert whenever the write
        did not cleanly succeed — the exact case that leaves the binary holding
        the marker, which the next run then reads as its "original" baseline.
        """
        obs, tee_payloads = self._run_exploit(monkeypatch, write_rc=1)
        assert obs.ok is True
        assert obs.data["wrote"] is False
        assert len(tee_payloads) == 2, "restore must be attempted after a failed write"
        assert obs.data["cleanup"] == "succeeded"


class TestBoundedVMCalls:
    """No subprocess that crosses to the VM may run without a deadline."""

    def test_stdin_helper_converts_a_timeout_to_a_failed_result(self, monkeypatch):
        """_run_on_vm_stdin must bound the write, or the episode can hang forever."""
        def raise_timeout(cmd, **kw):
            assert kw.get("timeout"), "the stdin write must carry a finite timeout"
            raise subprocess.TimeoutExpired(cmd, kw["timeout"])

        monkeypatch.setattr(vm_adapter.subprocess, "run", raise_timeout)
        rc, out, err = vm_adapter._run_on_vm_stdin(["sudo", "tee", "/x"], "payload")
        assert rc == -1
        assert "timed out" in err

    def test_runner_vm_helper_bounds_and_degrades(self, monkeypatch):
        """lab.vm.run._vm must not propagate a hang before/after the episode."""
        def raise_timeout(cmd, **kw):
            assert kw.get("timeout"), "the runner's VM calls must carry a timeout"
            raise subprocess.TimeoutExpired(cmd, kw["timeout"])

        monkeypatch.setattr(vm_run.subprocess, "run", raise_timeout)
        result = vm_run._vm(["sudo", "auditctl", "-D"])
        assert result.returncode == -1


class TestArmAuditdVerified:
    """Arming is the experiment's independent variable — it must be checked."""

    def test_a_failed_auditctl_is_fatal(self, monkeypatch):
        """arm_auditd must not print "armed" when auditctl failed."""
        monkeypatch.setattr(vm_run, "_vm", lambda *a, **k:
                            subprocess.CompletedProcess(
                                a[0], 1, stdout="", stderr="auditctl: not found"))
        with pytest.raises(SystemExit):
            vm_run.arm_auditd()

    def test_a_successful_auditctl_arms_quietly(self, monkeypatch):
        monkeypatch.setattr(vm_run, "_vm", lambda *a, **k:
                            subprocess.CompletedProcess(a[0], 0, stdout="",
                                                        stderr=""))
        vm_run.arm_auditd()  # must not raise
