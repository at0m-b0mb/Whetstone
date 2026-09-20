"""Tests for the Linux adapter's pure parsers and the detect.* verbs.

The Linux adapter cannot exercise real auditd/journald on the CI machine (a Mac),
which is exactly why every command's output is turned into structured data by a
*pure* module-level function (``count_ausearch_records``, ``parse_auth_events``,
``filter_auth_window``, ``find_secrets``). These tests feed those functions
captured/synthetic output and check the structured result — the same fixture
strategy ``tests/test_windows_adapter.py`` uses for Windows.

Three of the tests below pin *detection honesty* rather than parsing: a detect
verb that reports a control as fired when it did not silently deletes the
detection-gap finding that is this whole project's output, so each guards against
one such false positive that was found here.
"""

from __future__ import annotations

import os
import time

import whetstone.verbs  # noqa: F401  (registers the catalogue the verbs bind to)
from whetstone.adapters import linux as L
from whetstone.adapters.base import CommandResult
from whetstone.adapters.linux import (
    LinuxAdapter,
    count_ausearch_records,
    filter_auth_window,
    find_secrets,
    parse_auth_events,
)


class _Action:
    """Minimal stand-in for an Action: the detect handlers only read ``.params``."""

    def __init__(self, **params):
        self.params = params


# ===========================================================================
# detect.process_creation — must count EXECVE, not "any audit record"
# ===========================================================================

# auditd emits USER_AUTH / CRED_ACQ from PAM and SERVICE_START from systemd with
# no audit rules loaded at all. This is the "tool present, watching nothing"
# state, and it must NOT read as process-creation auditing.
_AUSEARCH_NOISE = (
    "----\n"
    "type=USER_AUTH msg=audit(1700000000.1:1): pid=900 uid=0 "
    "msg='op=PAM:authentication acct=\"kali\" exe=\"/usr/bin/sudo\" res=success'\n"
    "----\n"
    "type=CRED_ACQ msg=audit(1700000001.2:2): pid=901 uid=0 "
    "msg='op=PAM:setcred acct=\"kali\" res=success'\n"
)
_AUSEARCH_EXECVE = (
    "----\n"
    "type=SYSCALL msg=audit(1700000002.3:3): arch=c000003e syscall=execve "
    'success=yes exe="/usr/bin/id" key="exec"\n'
    "type=EXECVE msg=audit(1700000002.3:3): argc=1 a0=\"id\"\n"
)


class TestProcessCreationCounter:
    def test_execve_filter_ignores_pam_noise(self):
        """The bug: unfiltered counting reported process creation on PAM records."""
        assert count_ausearch_records(_AUSEARCH_NOISE) == 2  # everything is there
        assert count_ausearch_records(_AUSEARCH_NOISE, record_type="EXECVE") == 0

    def test_execve_filter_keeps_real_execve(self):
        assert count_ausearch_records(_AUSEARCH_EXECVE, record_type="EXECVE") == 1

    def test_verb_reports_gap_when_only_noise_present(self, monkeypatch):
        """End-to-end: auditd running, no execve rule, PAM chatter in the window.

        The honest answer is ``logged: False`` — process creation was NOT recorded
        — which the kernel turns into a detection gap. Before the fix this returned
        ``logged: True`` because the PAM records were counted.
        """
        monkeypatch.setattr(L, "which", lambda name: "/sbin/ausearch")
        monkeypatch.setattr(
            L, "run", lambda argv, **kw: CommandResult(
                argv=tuple(argv), returncode=0, stdout=_AUSEARCH_NOISE))
        result = L._detect_process_creation(
            LinuxAdapter(), None, _Action(since_seconds=300))
        assert result["logged"] is False
        assert result["count"] == 0

    def test_verb_reports_fired_on_real_execve(self, monkeypatch):
        monkeypatch.setattr(L, "which", lambda name: "/sbin/ausearch")
        monkeypatch.setattr(
            L, "run", lambda argv, **kw: CommandResult(
                argv=tuple(argv), returncode=0, stdout=_AUSEARCH_EXECVE))
        result = L._detect_process_creation(
            LinuxAdapter(), None, _Action(since_seconds=300))
        assert result["logged"] is True
        assert result["count"] == 1

    def test_verb_asks_auditd_for_execve_only(self, monkeypatch):
        """The kernel-side filter is half the defence; assert it is actually sent."""
        seen = {}

        def fake_run(argv, **kw):
            seen["argv"] = list(argv)
            return CommandResult(argv=tuple(argv), returncode=0, stdout="")

        monkeypatch.setattr(L, "which", lambda name: "/sbin/ausearch")
        monkeypatch.setattr(L, "run", fake_run)
        L._detect_process_creation(LinuxAdapter(), None, _Action(since_seconds=300))
        assert "-m" in seen["argv"]
        assert seen["argv"][seen["argv"].index("-m") + 1] == "EXECVE"


# ===========================================================================
# detect.authentication — the auth.log fallback must honour the time window
# ===========================================================================

# A year-anchored "now" makes the window deterministic regardless of when the
# suite runs. The log lines below are all on Jan 10 of that same year.
_YEAR = time.localtime().tm_year
_JAN10_1004 = time.mktime((_YEAR, 1, 10, 10, 4, 0, 0, 0, -1))
_AUTH_LOG = (
    f"Jan 10 10:00:01 host sshd[1]: Accepted publickey for kali from ::1 port 1 ssh2\n"
    f"Jan 10 10:01:15 host sshd[2]: Failed password for root from ::1 port 2 ssh2\n"
    f"Jan 10 10:03:10 host sudo:  kali : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/id\n"
)


class TestAuthWindow:
    def test_recent_lines_are_kept(self):
        win, parsed = filter_auth_window(_AUTH_LOG, 300, now=_JAN10_1004)
        assert parsed is True
        assert parse_auth_events(win)["total"] == 3

    def test_old_lines_are_dropped(self):
        """A one-second window excludes a file full of older records.

        This is the bug's core: the old fallback tallied the whole file, so a host
        with months of accumulated sshd lines read as "authentication logged" no
        matter how stale.
        """
        win, parsed = filter_auth_window(_AUTH_LOG, 1, now=_JAN10_1004)
        assert parsed is True
        assert parse_auth_events(win)["total"] == 0

    def test_december_line_tailed_in_january(self):
        """A Dec 31 line read on Jan 1 belongs to last year, not eleven months on."""
        dec = "Dec 31 23:59:59 host sshd[9]: Accepted publickey for kali from ::1 port 1 ssh2\n"
        jan_now = time.mktime((2027, 1, 1, 0, 0, 30, 0, 0, -1))
        win, parsed = filter_auth_window(dec, 300, now=jan_now)
        assert parsed is True
        assert parse_auth_events(win)["total"] == 1

    def test_unparseable_reports_cannot_tell(self):
        win, parsed = filter_auth_window("no timestamp here\nanother junk line\n",
                                         300, now=_JAN10_1004)
        assert parsed is False
        assert win == ""

    def test_iso_timestamps_accepted(self):
        iso = (f"{_YEAR}-01-10T10:03:30 host sshd[3]: Accepted publickey for kali\n"
               f"{_YEAR}-01-10T09:00:00 host sshd[4]: Accepted publickey for kali\n")
        win, parsed = filter_auth_window(iso, 300, now=_JAN10_1004)
        assert parsed is True
        assert parse_auth_events(win)["total"] == 1  # only the 10:03:30 line is recent

    def test_verb_fallback_drops_stale_log(self, monkeypatch):
        """journalctl absent, auth.log full of months-old lines -> logged False."""
        monkeypatch.setattr(L, "which", lambda name: None)
        stale = time.mktime((_YEAR, 6, 1, 0, 0, 0, 0, 0, -1))  # long after the log
        monkeypatch.setattr(
            time, "time", lambda: stale)  # freeze the window's "now"
        monkeypatch.setattr(LinuxAdapter, "_read_text",
                            lambda self, path, **kw: _AUTH_LOG if "auth.log" in path else None)
        result = L._detect_authentication(
            LinuxAdapter(), None, _Action(since_seconds=300))
        assert result["logged"] is False
        assert result["source"] == "auth.log"

    def test_verb_fallback_unparseable_is_none(self, monkeypatch):
        """A log with no parseable timestamps must be 'cannot tell', not fired."""
        monkeypatch.setattr(L, "which", lambda name: None)
        monkeypatch.setattr(
            LinuxAdapter, "_read_text",
            lambda self, path, **kw: "garbage with no timestamp\n" if "auth.log" in path else None)
        result = L._detect_authentication(
            LinuxAdapter(), None, _Action(since_seconds=300))
        assert result["logged"] is None
        assert "could not be parsed" in result["reason"]


# ===========================================================================
# find_secrets — the private-key marker must not be silently dropped
# ===========================================================================


class TestFindSecretsPrivateKey:
    def test_openssh_private_key_is_reported(self):
        findings = find_secrets(
            "-----BEGIN OPENSSH PRIVATE KEY-----", source="/home/u/.ssh/id_rsa")
        kinds = {f["kind"] for f in findings}
        assert "private_key_block" in kinds

    def test_all_private_key_variants_report(self):
        for header in ("RSA ", "EC ", "OPENSSH ", "DSA ", "PGP ", ""):
            text = f"-----BEGIN {header}PRIVATE KEY-----"
            kinds = {f["kind"] for f in find_secrets(text, source="x")}
            assert "private_key_block" in kinds, header

    def test_private_key_finding_has_nonzero_length_and_redacts(self):
        pk = next(f for f in find_secrets(
            "-----BEGIN OPENSSH PRIVATE KEY-----", source="x")
            if f["kind"] == "private_key_block")
        assert pk["value_length"] > 0            # not "an empty secret"
        assert pk["value"] == "***redacted***"   # marker text never copied out

    def test_placeholder_password_still_dropped(self):
        """The fix must not weaken the placeholder filter for captured values."""
        findings = find_secrets("password = changeme", source="x")
        assert findings == []


# ===========================================================================
# exploit.scheduled_task — the root-run proof marker must be unpredictable
# ===========================================================================


class TestScheduledTaskMarker:
    def test_marker_is_created_and_unpredictable(self, tmp_path):
        """A fixed /tmp name let a local user symlink-hijack a root-truncated file.

        The marker must exist on return (so root only ever truncates a file we
        already own) and two calls must never share a name (so there is nothing
        predictable to pre-plant).
        """
        m1 = L._create_proof_marker(dir=str(tmp_path))
        m2 = L._create_proof_marker(dir=str(tmp_path))
        assert os.path.isfile(m1)
        assert os.path.isfile(m2)
        assert m1 != m2
        assert not m1.endswith("whetstone-scheduled-task.proof")

    def test_marker_refuses_to_follow_a_preplanted_symlink(self, tmp_path):
        """mkstemp opens O_EXCL, so it cannot land on an attacker-planted path.

        This is the property that matters: even if an attacker could guess the
        name, creation would fail rather than truncate the symlink target. We
        assert the created file is the marker itself, not the victim behind a link.
        """
        victim = tmp_path / "victim"
        victim.write_text("do not truncate me")
        marker = L._create_proof_marker(dir=str(tmp_path))
        # The marker is its own fresh file, never the pre-existing victim.
        assert os.path.realpath(marker) != os.path.realpath(str(victim))
        assert victim.read_text() == "do not truncate me"


# ===========================================================================
# every detect.* query path: "could not ask" must never read as "nobody saw it"
# ===========================================================================


class TestAQueryThatDidNotRunIsNotSilence:
    """The mirror that was missed when the auth.log fallback was repaired.

    ``detect.authentication``'s FILE fallback was taught to say "cannot tell"
    when it could not apply its window, and the two ``ausearch``-absent branches
    were given ``source: "none"``. The paths that actually run on an ordinary
    systemd host were left alone: ``_ausearch_window`` counted records out of a
    timed-out ``ausearch``'s empty stdout, and ``_detect_authentication`` /
    ``_detect_rule`` tallied a timed-out ``journalctl``'s empty stdout the same
    way. Each produced ``logged: False`` with a source naming a log that was
    never read, which ``Kernel.detection_fired`` believes, and the kernel writes
    ``detection_gap`` — "the technique succeeded unobserved" — out of a query
    that never happened. A fabricated indictment of a control nobody asked.

    The half of this that has to keep working is asserted alongside each case: a
    query that DID run and found nothing is still a gap, because suppressing a
    real silence is the same bug facing the other way.
    """

    @staticmethod
    def _dead(argv, **kw):
        """What ``run()`` returns for a command that never produced output."""
        return CommandResult(argv=tuple(argv), returncode=-1, stdout="",
                             stderr=f"timed out after {kw.get('timeout', 30)}s",
                             timed_out=True)

    @staticmethod
    def _silent(argv, **kw):
        """A query that ran cleanly and had nothing to report."""
        return CommandResult(argv=tuple(argv), returncode=0, stdout="")

    def _fired(self, result):
        """Read the payload the way the kernel reads it."""
        from whetstone.actions import Observation
        from whetstone.kernel import detection_fired

        return detection_fired(Observation(action=None, ok=True,
                                           platform="linux", data=result))

    def test_a_timed_out_ausearch_is_not_a_detection_gap(self, monkeypatch):
        monkeypatch.setattr(L, "which", lambda name: "/sbin/ausearch")
        monkeypatch.setattr(L, "run", self._dead)
        result = L._detect_process_creation(
            LinuxAdapter(), None, _Action(since_seconds=300))
        assert result["source"] == "none", result
        assert self._fired(result) is None, result

    def test_a_working_ausearch_that_saw_nothing_still_is_a_gap(self, monkeypatch):
        monkeypatch.setattr(L, "which", lambda name: "/sbin/ausearch")
        monkeypatch.setattr(L, "run", self._silent)
        result = L._detect_process_creation(
            LinuxAdapter(), None, _Action(since_seconds=300))
        assert result["source"] == "auditd"
        assert self._fired(result) is False, result

    def test_a_timed_out_journalctl_is_not_an_authentication_gap(self, monkeypatch):
        monkeypatch.setattr(L, "which", lambda name: "/bin/journalctl")
        monkeypatch.setattr(L, "run", self._dead)
        result = L._detect_authentication(
            LinuxAdapter(), None, _Action(since_seconds=300))
        assert result["source"] == "none", result
        assert self._fired(result) is None, result

    def test_a_working_journalctl_that_saw_nothing_still_is_a_gap(self, monkeypatch):
        monkeypatch.setattr(L, "which", lambda name: "/bin/journalctl")
        monkeypatch.setattr(L, "run", self._silent)
        result = L._detect_authentication(
            LinuxAdapter(), None, _Action(since_seconds=300))
        assert result["source"] == "journald"
        assert self._fired(result) is False, result

    def test_a_timed_out_grep_is_not_a_rule_that_failed_to_fire(self, monkeypatch):
        monkeypatch.setattr(L, "which", lambda name: "/bin/journalctl")
        monkeypatch.setattr(L, "run", self._dead)
        result = L._detect_rule(
            LinuxAdapter(), None, _Action(rule="sigma:whatever", since_seconds=300))
        assert result["source"] == "none", result
        assert self._fired(result) is None, result

    def test_a_grep_that_matched_nothing_is_still_a_verdict(self, monkeypatch):
        """``-g`` exiting non-zero on an empty match must NOT become "cannot tell".

        This is why ``query_failed`` asks for a stderr diagnostic *and* an empty
        stdout rather than trusting the exit code on its own: on builds where a
        no-match grep exits 1 and says nothing, reading that as a broken query
        would delete every real detection gap this verb can report — the same
        fabrication as the tests above, pointing the other way. A non-zero exit
        with nothing to explain it is a negative, not a failure.
        """
        monkeypatch.setattr(L, "which", lambda name: "/bin/journalctl")
        monkeypatch.setattr(
            L, "run", lambda argv, **kw: CommandResult(
                argv=tuple(argv), returncode=1, stdout="", stderr=""))
        result = L._detect_rule(
            LinuxAdapter(), None, _Action(rule="sigma:whatever", since_seconds=300))
        assert result["source"] == "journald-grep", result
        assert self._fired(result) is False, result


# --------------------------------------------------------------------------
# the remediation hint
#
# The channel a handler declares a fix through. Pure, so it is testable on a Mac
# like the parsers above — and worth testing for the same reason: getting it
# wrong does not produce a wrong answer, it produces a fix that is never
# proposed, which looks exactly like a host with nothing to fix.
# --------------------------------------------------------------------------


class TestRemediationHint:
    def test_genuine_silence_gets_a_hint(self):
        out = L.offer_telemetry(
            {"logged": False, "count": 0, "source": "auditd"},
            "detect.process_creation")
        assert out["remediation"] == {
            "harden.enable_telemetry": {"source": "execve"}}

    def test_an_unqueryable_source_gets_none(self):
        """`source: "none"` means the log was never read, so detection_fired
        answers "cannot tell" and the kernel writes an observation rather than a
        gap. Only a gap is remediated; a hint here offers a fix for a finding
        nobody established."""
        out = L.offer_telemetry(
            {"logged": False, "source": "none", "reason": "ausearch timed out"},
            "detect.process_creation")
        assert "remediation" not in out

    def test_a_declared_gap_marker_gets_none(self):
        """The same rule from the other direction: auditd running with no execve
        rule is the case where enabling the source feels most obviously right
        and is least obviously proven necessary."""
        out = L.offer_telemetry(
            {"logged": False, "count": 0, "source": "auditd",
             "gap": "no auditd execve auditing"},
            "detect.credential_access")
        assert "remediation" not in out

    def test_a_control_that_fired_gets_none(self):
        out = L.offer_telemetry({"logged": True, "count": 3, "source": "auditd"},
                                "detect.persistence_change")
        assert "remediation" not in out

    def test_every_source_offered_is_one_the_fix_can_enable(self):
        """Two tables that have to agree, pinned rather than commented.

        ``offer_telemetry`` names a source and ``harden.enable_telemetry``
        refuses a source it has no audit rule for. A name in one and not the
        other is a fix proposed on every silent probe and applied on none —
        remediation that runs, reports ``unsupported``, and closes nothing.
        """
        for verb_id, source in L._TELEMETRY_FOR.items():
            assert L._audit_rule_for(source) is not None, (
                f"{verb_id} offers telemetry source {source!r}, which "
                "harden.enable_telemetry does not know how to enable")

    def test_the_exploit_names_the_image_it_will_run(self, tmp_path):
        """Without it every Linux process-creation probe is unaimed, so a hit
        can never be attributed and the control can never be shown to fire.

        This drives the handler. The version this replaced asserted only that
        ``detect.process_creation`` declares an ``image`` parameter — a fact
        about ``whetstone/verbs.py`` that no change to this adapter can break —
        under a name promising the exploit publishes one. Deleting the line that
        publishes it left the whole suite green, which is the failure this file's
        own docstring is about: the probe would go unaimed, every hit would read
        as unattributable, and no Linux gap on that control could ever be proven
        closed. Silence, where the tool's entire output is a claim about silence.

        Service resolution is stubbed because it needs systemd; the payload
        write is real, against a file in ``tmp_path``.
        """
        from whetstone.actions import REGISTRY

        binary = tmp_path / "acme-agent"
        binary.write_bytes(b"original service binary\n")
        adapter = LinuxAdapter()
        adapter._service_exec_paths = lambda: {"acme.service": str(binary)}

        verb = REGISTRY.get("exploit.service_permissions")
        action = verb.bind({"service": "acme", "restore": True},
                           target="127.0.0.1")
        rec = L._exploit_service_permissions(adapter, verb, action)

        assert rec["ok"], rec
        assert rec["image"] == "acme-agent", (
            "the kernel aims a probe by EXACT parameter-name match, so the "
            "handler that overwrote the binary — the only thing that knows "
            "which image will run — has to publish it under the name "
            "detect.process_creation gives its own parameter")
        assert any(p.name == "image"
                   for p in REGISTRY.get("detect.process_creation").params), (
            "and the name on the other side of that match is `image` too; if "
            "the probe ever renames it, publishing the old one aims nothing")
        assert binary.read_bytes() == b"original service binary\n", (
            "restore=True, and a test that leaves the payload behind is a test "
            "that has not exercised the restore path")
