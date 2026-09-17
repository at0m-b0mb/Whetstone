"""Tests for the Windows adapter's pure parsers and red-verb primitives.

The Windows adapter cannot run on the CI machine (a Mac), which is the whole
reason its every command output is turned into structured data by a *pure*
module-level ``parse_*`` function. These tests feed those functions captured
fixture output from ``tests/fixtures/windows/`` and check the structured result —
so the parsing logic, which is where the real complexity lives, is covered
without a Windows box in sight.

They also exercise the red-verb file/registry primitives (``stage_*`` /
``restore_*`` / ``*_planted_file``) against a temporary sandbox directory, which
is the only place adapter-contract rule 6 permits them to be self-tested.
"""

from __future__ import annotations

from pathlib import Path

from whetstone.actions import REGISTRY
from whetstone.adapters import windows as w
from whetstone.adapters.windows import WindowsAdapter

# Loading the catalogue is what registers the verbs the execute()-path tests bind.
import whetstone.verbs  # noqa: F401,E402

FIXTURES = Path(__file__).parent / "fixtures" / "windows"


def fx(name: str) -> str:
    return (FIXTURES / name).read_text()


# ===========================================================================
# enum parsers
# ===========================================================================


class TestHostInfo:
    def test_windows11_workstation(self):
        h = w.parse_host_info(fx("host_info.json"))
        assert h["hostname"] == "DESKTOP-7A1"
        assert "Windows 11" in h["os"]
        assert h["build"] == "22631"
        assert h["part_of_domain"] is False
        assert h["last_boot"].startswith("2026-09-16")

    def test_ps51_domain_controller_date_shape(self):
        """Windows PowerShell 5.1 renders CIM dates as /Date(ms)/; both are accepted."""
        h = w.parse_host_info(fx("host_info_ps51.json"))
        assert h["part_of_domain"] is True
        assert h["domain"] == "corp.example.com"
        assert h["last_boot"].startswith("epoch_ms:")

    def test_empty_is_empty_dict(self):
        assert w.parse_host_info("") == {}


class TestLocalUsers:
    def test_all_accounts_by_default(self):
        users = w.parse_local_users(fx("local_users.json"))
        assert len(users) == 4
        alice = next(u for u in users if u["name"] == "alice")
        assert alice["enabled"] is True
        assert alice["sid"].endswith("-1001")

    def test_disabled_filtered_when_asked(self):
        users = w.parse_local_users(fx("local_users.json"), include_disabled=False)
        names = {u["name"] for u in users}
        assert names == {"alice", "svcweb"}  # Administrator + Guest are disabled

    def test_single_object_collapse(self):
        """ConvertTo-Json emits a lone account as an object, not an array."""
        users = w.parse_local_users(fx("local_users_single.json"))
        assert len(users) == 1 and users[0]["name"] == "alice"

    def test_service_account_password_not_required(self):
        users = w.parse_local_users(fx("local_users.json"))
        svc = next(u for u in users if u["name"] == "svcweb")
        assert svc["password_required"] is False


class TestGroupMembers:
    def test_admins(self):
        admins = w.parse_group_members(fx("group_members_admins.json"))
        assert {a["name"] for a in admins} == {
            "DESKTOP-7A1\\Administrator",
            "DESKTOP-7A1\\alice",
        }


class TestWhoamiAll:
    def test_low_priv_service_account(self):
        d = w.parse_whoami_all(fx("whoami_all.txt"))
        assert d["user"] == "desktop-7a1\\svcweb"
        assert d["sid"].endswith("-1105")
        assert d["is_admin"] is False
        assert d["integrity"] == "High"
        # Only enabled privileges are "enabled", and only notable ones surface.
        assert "SeImpersonatePrivilege" in d["notable_privileges"]
        assert "SeAssignPrimaryTokenPrivilege" not in d["notable_privileges"]  # Disabled
        assert set(d["enabled_privileges"]) == {
            "SeChangeNotifyPrivilege",
            "SeImpersonatePrivilege",
            "SeCreateGlobalPrivilege",
        }

    def test_uac_filtered_token_is_not_admin(self):
        """The UAC trap: Administrators present but 'deny only' → not elevated."""
        d = w.parse_whoami_all(fx("whoami_all_filtered.txt"))
        assert d["admin_member"] is True
        assert d["admin_deny_only"] is True
        assert d["is_admin"] is False
        assert d["integrity"] == "Medium"

    def test_elevated_admin(self):
        d = w.parse_whoami_all(fx("whoami_all_elevated.txt"))
        assert d["is_admin"] is True
        assert d["admin_deny_only"] is False
        assert d["integrity"] == "High"
        assert "SeDebugPrivilege" in d["notable_privileges"]

    def test_group_with_spaces_in_name_parses(self):
        """A value like 'NT AUTHORITY\\Authenticated Users' must not split on space."""
        d = w.parse_whoami_all(fx("whoami_all.txt"))
        names = {g["group"] for g in d["groups"]}
        assert "NT AUTHORITY\\Authenticated Users" in names


class TestProcesses:
    def test_tree_and_cmdline(self):
        procs = w.parse_processes(fx("processes.json"))
        assert len(procs) == 4
        ps = next(p for p in procs if p["name"] == "powershell.exe")
        assert ps["ppid"] == 720
        assert "-enc" in ps["cmdline"]
        assert ps["user"] == "DESKTOP-7A1\\svcweb"

    def test_missing_cmdline_is_absent_not_empty(self):
        procs = w.parse_processes(fx("processes.json"))
        system = next(p for p in procs if p["name"] == "System")
        assert "cmdline" not in system


class TestServices:
    def test_pathname_preserved(self):
        svcs = w.parse_services(fx("services.json"))
        vuln = next(s for s in svcs if s["name"] == "VulnSvc")
        assert vuln["path"].startswith("C:\\Program Files\\Acme Updater")
        assert vuln["run_as"] == "LocalSystem"


class TestPersistence:
    def test_all_buckets(self):
        p = w.parse_persistence(fx("persistence.json"))
        assert len(p["run_keys"]) == 3
        assert len(p["scheduled_tasks"]) == 2
        assert len(p["startup_folder"]) == 1
        assert len(p["wmi_subscriptions"]) == 1
        assert len(p["services"]) == 1
        assert p["count"] == 8
        # Every entry carries a stable id harden.remove_persistence can key off.
        assert all("id" in e for e in p["entries"])
        task = next(e for e in p["entries"] if e["kind"] == "scheduled_task"
                    and e["name"] == "SysHealth")
        assert task["id"] == "scheduled_task:\\Microsoft\\Windows\\Maintenance\\SysHealth"

    def test_single_object_buckets_collapse(self):
        p = w.parse_persistence(fx("persistence_single_task.json"))
        assert len(p["run_keys"]) == 1
        assert len(p["scheduled_tasks"]) == 1
        assert p["count"] == 2


class TestNetwork:
    def test_sockets_with_owning_process(self):
        n = w.parse_network(fx("network.json"))
        assert len(n["tcp"]) == 4
        assert len(n["listening"]) == 2
        assert len(n["established"]) == 2
        beacon = next(t for t in n["tcp"] if t["remote"] == "10.0.0.5:4444")
        assert beacon["process"] == "powershell"

    def test_netstat_fallback(self):
        rows = w.parse_netstat_ano(fx("netstat_ano.txt"))
        assert len(rows) == 5
        listening = [r for r in rows if r.get("state") == "LISTENING"]
        assert len(listening) == 2
        udp = [r for r in rows if r["proto"] == "UDP"]
        assert udp and udp[0]["pid"] == 2400


class TestSoftware:
    def test_software_and_hotfixes(self):
        s = w.parse_software(fx("software.json"))
        assert len(s["software"]) == 4
        assert len(s["hotfixes"]) == 3
        assert {h["id"] for h in s["hotfixes"]} == {"KB5041585", "KB5043145", "KB5012170"}


class TestShares:
    def test_admin_shares_flagged(self):
        shares = w.parse_shares(fx("shares.json"))
        by = {s["name"]: s for s in shares}
        assert by["ADMIN$"]["administrative"] is True
        assert by["C$"]["administrative"] is True
        assert by["Public"]["administrative"] is False
        everyone = [a for a in by["Public"]["access"] if a["account"] == "Everyone"]
        assert everyone and everyone[0]["rights"] == "Full"


# ===========================================================================
# detect parsers
# ===========================================================================


class TestAuditpol:
    def test_process_creation_off(self):
        a = w.parse_auditpol_csv(fx("auditpol.csv"))
        assert a["Process Creation"] == "No Auditing"
        assert a["Logon"] == "Success and Failure"

    def test_hardened(self):
        a = w.parse_auditpol_csv(fx("auditpol_hardened.csv"))
        assert a["Process Creation"] == "Success and Failure"


class TestWinEventLog:
    def test_security_enabled(self):
        logs = w.parse_winevent_log(fx("winevent_loglist.json"))
        sec = next(lg for lg in logs if lg["log"] == "Security")
        assert sec["enabled"] is True
        assert sec["records"] == 148203

    def test_security_disabled_is_the_finding(self):
        logs = w.parse_winevent_log(fx("winevent_loglist_disabled.json"))
        assert logs[0]["enabled"] is False


class TestWinEventEvents:
    def test_projected_4688(self):
        ev = w.parse_winevent_events(fx("winevent_4688.json"))
        assert len(ev) == 2
        assert all(isinstance(e["id"], int) for e in ev)
        assert ev[0]["data"]["NewProcessName"].endswith("powershell.exe")

    def test_single_event_collapse(self):
        ev = w.parse_winevent_events(fx("winevent_single_event.json"))
        assert len(ev) == 1 and ev[0]["id"] == 1

    def test_empty_window(self):
        assert w.parse_winevent_events(fx("winevent_empty.json")) == []


class TestSysmon:
    def test_installed(self):
        s = w.parse_sysmon_status(fx("sysmon_status.json"))
        assert s["installed"] is True
        assert s["running"] == ["Sysmon64"]

    def test_absent(self):
        s = w.parse_sysmon_status(fx("sysmon_absent.json"))
        assert s["installed"] is False


class TestRegValues:
    def test_on(self):
        r = w.parse_reg_values(fx("pslogging_on.json"))
        assert r["cmdline_audit"] is True
        assert r["scriptblock"] is True
        assert r["transcription"] is None  # never configured, distinct from False

    def test_off(self):
        r = w.parse_reg_values(fx("pslogging_off.json"))
        assert all(v is None for v in r.values())


class TestAssessTelemetry:
    """The pure fold that turns the four probes into a gap list."""

    def test_well_instrumented_host_has_no_gaps(self):
        out = w.assess_telemetry(
            sysmon=w.parse_sysmon_status(fx("sysmon_status.json")),
            logs=w.parse_winevent_log(fx("winevent_loglist.json")),
            audit=w.parse_auditpol_csv(fx("auditpol_hardened.csv")),
            ps_logging=w.parse_reg_values(fx("pslogging_on.json")),
        )
        assert out["gap_count"] == 0
        assert out["command_line_logging"] is True
        assert out["sysmon"]["installed"] is True

    def test_blind_host_names_every_gap(self):
        out = w.assess_telemetry(
            sysmon=w.parse_sysmon_status(fx("sysmon_absent.json")),
            logs=w.parse_winevent_log(fx("winevent_loglist_disabled.json")),
            audit=w.parse_auditpol_csv(fx("auditpol.csv")),
            ps_logging=w.parse_reg_values(fx("pslogging_off.json")),
        )
        joined = " | ".join(out["gaps"]).lower()
        assert "security event log is disabled" in joined
        assert "process creation auditing" in joined
        assert "script-block" in joined
        assert "sysmon is not installed" in joined
        assert out["gap_count"] >= 4


# ===========================================================================
# vuln analysers (pure)
# ===========================================================================


class TestUnquotedPaths:
    def test_classic_two_interception_points(self):
        pts = w.interception_paths(r"C:\Program Files\Sub Dir\svc.exe")
        assert pts == [r"C:\Program.exe", r"C:\Program Files\Sub.exe"]

    def test_quoted_path_is_safe(self):
        assert w.interception_paths(r'"C:\Program Files\App\svc.exe"') == []

    def test_no_space_is_safe(self):
        assert w.interception_paths(r"C:\Windows\system32\svchost.exe") == []

    def test_finds_only_the_vulnerable_service(self):
        svcs = w.parse_services(fx("services.json"))
        found = w.find_unquoted_service_paths(svcs)
        assert [f["service"] for f in found] == ["VulnSvc"]
        assert found[0]["interception_points"][0] == r"C:\Program.exe"
        assert found[0]["run_as"] == "LocalSystem"


class TestIcacls:
    def test_weak_grant_to_users(self):
        weak = w._icacls_weak_principals(fx("icacls_weak.txt"))
        assert weak == ["BUILTIN\\Users"]

    def test_strong_acl_has_no_weak_principal(self):
        assert w._icacls_weak_principals(fx("icacls_strong.txt")) == []


class TestCredentialScan:
    def test_finds_and_redacts(self):
        blobs = w._as_list(w._load_json(fx("cred_hunt_blobs.json")))
        findings = []
        for b in blobs:
            findings += w.scan_for_credentials(b["content"], b["source"], redact=True)
        kinds = {f["kind"] for f in findings}
        assert "unattend_password" in kinds
        assert "aws_key" in kinds
        assert any("Winlogon" in f["source"] for f in findings)
        # Nothing leaks the actual secret when redacted.
        assert all(f["match"].startswith("<redacted") for f in findings)
        assert not any("P@ssw0rd-Unattend" in f["match"] for f in findings)

    def test_raw_mode_returns_secret(self):
        f = w.scan_for_credentials("Password=SuperSecret123", "x", redact=False)
        assert f and f[0]["match"] == "SuperSecret123"


class TestPrivilegePaths:
    def test_chains_from_composed_findings(self):
        priv = w.parse_whoami_all(fx("whoami_all.txt"))  # low-priv, SeImpersonate
        services = w.parse_services(fx("services.json"))
        weak = {
            "unquoted_paths": w.find_unquoted_service_paths(services),
            "writable_binaries": [
                {"service": "WritableSvc", "path": r"C:\ProgramData\Contoso\agent.exe",
                 "run_as": "LocalSystem"}
            ],
        }
        chains = w.build_privilege_paths(
            privileges=priv, services=services, weak_permissions=weak
        )
        kinds = {c["kind"] for c in chains}
        assert "unquoted_service_path" in kinds       # VulnSvc runs as LocalSystem
        assert "writable_service_binary" in kinds     # WritableSvc runs as LocalSystem
        assert "token_impersonation" in kinds         # SeImpersonate, not admin
        # Each chain points at a real exploit verb.
        assert all(c["exploit"] in REGISTRY for c in chains)


class TestCmdkey:
    def test_targets_and_users(self):
        rows = w.parse_cmdkey_list(fx("cmdkey_list.txt"))
        assert len(rows) == 3
        assert any(r.get("user") == "CORP\\backup_svc" for r in rows)


# ===========================================================================
# red-verb primitives — sandbox only (adapter-contract rule 6)
# ===========================================================================


class TestSandboxPrimitives:
    def test_stage_and_restore_round_trip(self, tmp_path):
        target = tmp_path / "svc.exe"
        target.write_bytes(b"ORIGINAL-BINARY")
        work = tmp_path / "work"
        work.mkdir()

        manifest = w.stage_file_replacement(
            str(target), w._marker_payload("test"), str(work)
        )
        assert target.read_bytes().startswith(b"WHETSTONE")
        assert manifest["original_existed"] is True

        assert w.restore_file_replacement(manifest) is True
        assert target.read_bytes() == b"ORIGINAL-BINARY"

    def test_restore_reports_failure_when_backup_gone(self, tmp_path):
        target = tmp_path / "svc.exe"
        target.write_bytes(b"X")
        work = tmp_path / "work"
        work.mkdir()
        manifest = w.stage_file_replacement(str(target), b"NEW", str(work))
        # Simulate a lost backup: cleanup must return False, never a silent True.
        Path(manifest["backup"]).unlink()
        assert w.restore_file_replacement(manifest) is False

    def test_plant_refuses_to_clobber(self, tmp_path):
        existing = tmp_path / "Program.exe"
        existing.write_bytes(b"REAL")
        m = w.stage_planted_file(str(existing), b"PAYLOAD")
        assert m["planted"] is False
        assert existing.read_bytes() == b"REAL"  # untouched

    def test_plant_and_remove(self, tmp_path):
        spot = tmp_path / "Program.exe"
        m = w.stage_planted_file(str(spot), w._marker_payload("t"))
        assert m["planted"] is True and spot.exists()
        assert w.remove_planted_file(m) is True
        assert not spot.exists()


# ===========================================================================
# adapter dispatch: unsupported, and degradation without PowerShell
# ===========================================================================


class TestAdapterDispatch:
    def test_cron_mechanism_is_unsupported_on_windows(self):
        adapter = WindowsAdapter()
        verb = REGISTRY.get("postex.persistence_install")
        action = verb.bind({"mechanism": "cron", "cleanup": True}, target="host:local")
        obs = adapter.execute(verb, action)
        assert obs.ok is False
        assert obs.unsupported is True
        assert "not a Windows concept" in obs.error

    def test_launch_agent_mechanism_is_unsupported(self):
        adapter = WindowsAdapter()
        verb = REGISTRY.get("postex.persistence_install")
        action = verb.bind({"mechanism": "launch_agent"}, target="host:local")
        obs = adapter.execute(verb, action)
        assert obs.unsupported is True

    def test_enum_host_degrades_without_powershell(self, monkeypatch):
        """No PowerShell is a retryable failure, not 'unsupported'."""
        monkeypatch.setattr(w, "_powershell", lambda: None)
        adapter = WindowsAdapter()
        verb = REGISTRY.get("enum.host")
        action = verb.bind(target="host:local")
        obs = adapter.execute(verb, action)
        assert obs.ok is False
        assert obs.unsupported is False       # the verb is a Windows concept
        assert "PowerShell" in obs.error

    def test_detect_rule_rejects_unknown_rule(self, monkeypatch):
        # Pretend PowerShell exists so the handler reaches the rule resolver.
        monkeypatch.setattr(w, "_powershell", lambda: "/usr/bin/pwsh")
        adapter = WindowsAdapter()
        verb = REGISTRY.get("detect.rule")
        action = verb.bind({"rule": "totally-made-up-rule"}, target="host:local")
        obs = adapter.execute(verb, action)
        assert obs.ok is False
        assert "not known to this minimal detection engine" in obs.error


class TestHardenAndExfil:
    def test_fix_permissions_reads_path_param_not_host_target(self, monkeypatch):
        """The object to correct is the 'path' param; the target is the host."""
        monkeypatch.setattr(w, "which", lambda name: None)  # no icacls on this box
        adapter = WindowsAdapter()
        verb = REGISTRY.get("harden.fix_permissions")
        action = verb.bind({"path": r"C:\ProgramData\Contoso\agent.exe"},
                           target="host:local")
        obs = adapter.execute(verb, action)
        # It got past the path check (would say "no path" otherwise) to the tool
        # check, proving it read the parameter rather than the host target.
        assert obs.ok is False
        assert "icacls" in obs.error

    def test_exfil_probe_sends_synthetic_bytes_to_a_local_sink(self):
        """A red verb that actually runs here: measure egress to a local socket."""
        import socket
        import threading

        received = {"n": 0}
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        def drain():
            conn, _ = srv.accept()
            with conn:
                while True:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    received["n"] += len(chunk)

        t = threading.Thread(target=drain)
        t.start()

        adapter = WindowsAdapter()
        verb = REGISTRY.get("postex.exfil_probe")
        action = verb.bind({"bytes": 100000, "sink": f"127.0.0.1:{port}"},
                           target="host:local")
        obs = adapter.execute(verb, action)
        t.join(timeout=5)
        srv.close()

        assert obs.ok is True
        assert obs.data["sent_bytes"] == 100000
        assert obs.data["synthetic"] is True
        assert received["n"] == 100000


class TestRuleResolver:
    def test_named_rule(self):
        assert w._resolve_rule("process_creation") == ("Security", [4688], "process_creation")

    def test_raw_query(self):
        log, ids, _ = w._resolve_rule("Sysmon/1")
        assert log == "Microsoft-Windows-Sysmon/Operational" and ids == [1]

    def test_unknown(self):
        assert w._resolve_rule("no-such-rule") is None
