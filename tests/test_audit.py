"""Tests for the audit log's tamper-evidence, kept apart from the gate's logic.

test_gate.py is about the gate being a pure function of (engagement, verb,
action, clock). This file is about the other half of the safety story: whether
the file that records what happened can be quietly edited afterwards, and
whether the tool that answers that question survives being pointed at a damaged
log. Those fail for different reasons and read better apart.

Every test here is named after an attack or an accident rather than after the
method it calls, because the thing being asserted is a property of the scheme,
not of an API.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from whetstone.gate import AuditError, AuditLog, verify

# Private on purpose — the sidecar's name is an implementation detail of the
# module, and a test that hardcoded ".anchor" would keep passing while pointing
# at a file the code no longer writes.
from whetstone.gate.audit import _anchor_path

posix_only = pytest.mark.skipif(
    os.name != "posix",
    reason="POSIX modes; on Windows the log is protected by the directory ACL",
)


def _log_with(tmp_path: Path, n: int) -> AuditLog:
    log = AuditLog(tmp_path / "run.jsonl")
    for i in range(n):
        log.note(f"entry {i}")
    return log


def _drop_last_line(path: Path) -> None:
    lines = path.read_text().splitlines()
    path.write_text("\n".join(lines[:-1]) + "\n")


class TestTruncation:
    """The records deleted from the end are the ones worth deleting."""

    def test_dropping_the_last_record_is_detected(self, tmp_path):
        """The chain alone cannot see this: a prefix of a valid chain is valid.

        This is the whole reason the anchor exists. Before it, `head -n -1` over
        a log whose last record was the credential dump returned a clean verdict.
        """
        log = _log_with(tmp_path, 3)
        _drop_last_line(log.path)

        ok, msg = verify(log.path)
        assert not ok, msg
        assert "removed from the end" in msg
        assert "record 3" in msg

    def test_deleting_the_log_is_not_mistaken_for_one_never_written(self, tmp_path):
        log = _log_with(tmp_path, 2)
        log.path.unlink()

        ok, msg = verify(log.path)
        assert not ok
        assert "deleted, not never written" in msg

    def test_appending_to_a_truncated_log_is_refused(self, tmp_path):
        """Appending is the one response that destroys the evidence.

        The next append rewrites the anchor with the short history's tip, after
        which nothing on disk remembers that anything was ever removed.
        """
        log = _log_with(tmp_path, 3)
        _drop_last_line(log.path)

        with pytest.raises(AuditError, match="removed from the end"):
            AuditLog(log.path)

    def test_a_log_ahead_of_its_anchor_is_not_an_alarm(self, tmp_path):
        """A crash between the record write and the anchor write looks like this.

        Verification has to stay quiet about it or it cries wolf on every killed
        process, and a verifier nobody reads protects nothing.
        """
        log = _log_with(tmp_path, 3)
        records = [json.loads(ln) for ln in log.path.read_text().splitlines()]
        _anchor_path(log.path).write_text(
            json.dumps({"seq": 2, "hash": records[1]["hash"], "ts": records[1]["ts"]})
        )

        ok, msg = verify(log.path)
        assert ok, msg

        AuditLog(log.path).note("still appendable")
        assert verify(log.path)[0]

    def test_rebuilding_the_log_under_its_own_anchor_is_detected(self, tmp_path):
        """A forged chain verifies against itself and against nothing else."""
        real = _log_with(tmp_path, 3)
        kept_anchor = _anchor_path(real.path).read_text()

        forged = AuditLog(tmp_path / "forged.jsonl")
        for i in range(3):
            forged.note(f"harmless {i}")
        real.path.write_text(forged.path.read_text())
        _anchor_path(real.path).write_text(kept_anchor)

        ok, msg = verify(real.path)
        assert not ok, msg
        assert "rebuilt from the start" in msg


class TestOffBoxAnchor:
    """The sidecar cannot survive an attacker who knows about the sidecar."""

    def test_a_consistent_rewrite_of_both_files_needs_a_pinned_tip(self, tmp_path):
        log = _log_with(tmp_path, 3)
        pinned_seq, pinned_tip = len(log), log.tip

        log.path.unlink()
        _anchor_path(log.path).unlink()
        AuditLog(log.path).note("nothing happened here")

        assert verify(log.path)[0], "a rewritten pair verifies; that is the point"

        ok, msg = verify(log.path, expect_seq=pinned_seq, expect_tip=pinned_tip)
        assert not ok
        assert "records were removed" in msg

    def test_a_pinned_tip_catches_a_same_length_rewrite(self, tmp_path):
        """Counting records is not enough when the forger keeps the count."""
        log = _log_with(tmp_path, 3)
        pinned_tip = log.tip

        log.path.unlink()
        _anchor_path(log.path).unlink()
        replacement = AuditLog(log.path)
        for i in range(3):
            replacement.note(f"harmless {i}")

        assert verify(log.path, expect_seq=3)[0]
        ok, msg = verify(log.path, expect_tip=pinned_tip)
        assert not ok
        assert "not the log that was recorded off the box" in msg

    def test_a_log_without_an_anchor_says_so_rather_than_implying_safety(self, tmp_path):
        """Logs predating the anchor, and logs copied without their sidecar."""
        log = _log_with(tmp_path, 2)
        _anchor_path(log.path).unlink()

        ok, msg = verify(log.path)
        assert ok, msg
        assert "no anchor" in msg


class TestVerifyAlwaysReturnsAVerdict:
    """verify() is run because the log is already suspect. It must not crash."""

    def test_a_half_written_final_line_is_a_verdict_not_a_traceback(self, tmp_path):
        """The killed-process and full-disk case, mid-write."""
        log = _log_with(tmp_path, 3)
        log.path.write_bytes(log.path.read_bytes()[:-40])

        ok, msg = verify(log.path)
        assert not ok
        assert str(log.path) in msg

    def test_a_garbled_line_in_the_middle_is_a_verdict_not_a_traceback(self, tmp_path):
        log = _log_with(tmp_path, 3)
        lines = log.path.read_text().splitlines()
        lines[1] = "{not json"
        log.path.write_text("\n".join(lines) + "\n")

        ok, msg = verify(log.path)
        assert not ok
        assert ":2:" in msg

    def test_an_unreadable_anchor_is_a_verdict_not_a_traceback(self, tmp_path):
        log = _log_with(tmp_path, 2)
        _anchor_path(log.path).write_text("{ truncated")

        ok, msg = verify(log.path)
        assert not ok
        assert "cannot be read" in msg


class TestPermissions:
    """`redact=false` puts /etc/shadow hashes in this file. It is a secret."""

    @posix_only
    def test_log_and_anchor_are_not_readable_by_other_users(self, tmp_path):
        log = _log_with(tmp_path, 1)
        assert log.path.stat().st_mode & 0o077 == 0
        assert _anchor_path(log.path).stat().st_mode & 0o077 == 0

    @posix_only
    def test_the_directory_holding_the_log_is_owner_only(self, tmp_path):
        """The containing directory is the one that has to deny traversal.

        With parents=True, CPython applies mode= to the final component only, so
        `runs/` keeps the umask default while `runs/today/` is 0700. Reaching the
        log means traversing `runs/today/`, so that is what is asserted here.
        """
        d = tmp_path / "runs" / "today"
        AuditLog(d / "run.jsonl").note("hello")

        assert d.stat().st_mode & 0o077 == 0

    @posix_only
    def test_an_existing_wide_log_is_narrowed_before_it_is_written_to(self, tmp_path):
        """An older Whetstone under umask 022 — or a file pre-created wide."""
        path = tmp_path / "run.jsonl"
        path.touch()
        path.chmod(0o644)

        AuditLog(path).note("first")
        assert path.stat().st_mode & 0o077 == 0

    @posix_only
    def test_an_existing_directory_is_left_alone(self, tmp_path):
        """path.parent is usually the operator's cwd or home. Not ours to narrow."""
        tmp_path.chmod(0o755)
        AuditLog(tmp_path / "run.jsonl").note("hello")

        assert tmp_path.stat().st_mode & 0o777 == 0o755

    @posix_only
    def test_a_readonly_open_changes_nothing_on_disk(self, tmp_path):
        """verify() must not chmod a log it does not own.

        _restrict() raises when the chmod fails, so a verifier that tried would
        report a perfectly intact chain as broken purely because it was someone
        else's file.
        """
        log = _log_with(tmp_path, 1)
        log.path.chmod(0o644)

        AuditLog(log.path, readonly=True)
        assert log.path.stat().st_mode & 0o777 == 0o644
        assert verify(log.path)[0]

    def test_a_readonly_open_creates_no_directory(self, tmp_path):
        missing = tmp_path / "nowhere" / "run.jsonl"
        AuditLog(missing, readonly=True)
        assert not missing.parent.exists()
