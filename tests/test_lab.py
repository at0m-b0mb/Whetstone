"""Tests for the sandbox lab.

The lab's whole reason for existing is to make the detection verifier runnable
without a VM, so the property that matters most is that the *same attack*
produces a gap with telemetry off and no gap with telemetry on. If that ever
stops holding, the lab is lying about the one thing it is for.

The second property is confinement. Every file operation must stay under the
sandbox root, because the red verbs here really write to disk — the safety of
running the genuine article depends on the writes going nowhere else.
"""

from __future__ import annotations

import pytest

import whetstone.verbs  # noqa: F401  (registers the catalogue)
from lab.adapter import SandboxAdapter
from lab.target import SandboxTarget
from whetstone.actions import REGISTRY


class TestSandboxTarget:
    def test_plants_its_weaknesses(self):
        with SandboxTarget() as t:
            kinds = {w.kind for w in t.weaknesses}
            assert kinds == {"writable_service", "credential", "persistence", "patch"}

    def test_telemetry_switch_gates_the_log(self):
        with SandboxTarget(telemetry=False) as t:
            assert t.event("x", "T1", "detail") is False
            assert t.events() == []
        with SandboxTarget(telemetry=True) as t:
            before = len(t.events())          # the build logs a baseline event
            assert t.event("x", "T1", "detail") is True
            assert len(t.events()) == before + 1

    def test_confinement_refuses_escape(self):
        with SandboxTarget() as t:
            for bad in ("../escape", "/etc/passwd", "../../root/.ssh/id_rsa"):
                with pytest.raises(ValueError, match="escapes the sandbox"):
                    t.resolve(bad)

    def test_teardown_removes_the_tree(self):
        t = SandboxTarget()
        root = t.root
        assert root.exists()
        t.close()
        assert not root.exists()

    def test_revert_restores_mutated_files(self):
        with SandboxTarget() as t:
            svc = t.resolve("opt/acme/acme-agent")
            before = svc.read_bytes()
            svc.write_bytes(b"tampered")
            t.revert()
            assert svc.read_bytes() == before


class TestSandboxAdapter:
    def _adapter(self, **kw):
        t = SandboxTarget(**kw)
        return SandboxAdapter(t), t

    def test_enumerate_finds_planted_state(self):
        ad, t = self._adapter()
        try:
            svc = ad.execute(REGISTRY.get("enum.services"),
                             REGISTRY.bind("enum.services", target="127.0.0.1"))
            names = [s["name"] for s in svc.data["services"]]
            assert "acme-agent" in names
        finally:
            t.close()

    def test_vuln_finds_the_writable_binary(self):
        ad, t = self._adapter()
        try:
            obs = ad.execute(REGISTRY.get("vuln.weak_permissions"),
                             REGISTRY.bind("vuln.weak_permissions", target="127.0.0.1"))
            assert obs.data["findings"], "the world-writable service must be found"
            assert obs.data["findings"][0]["technique"] == "T1574.010"
        finally:
            t.close()

    def test_exploit_really_writes_then_reverts(self):
        ad, t = self._adapter()
        try:
            svc = t.resolve("opt/acme/acme-agent")
            original = svc.read_bytes()
            obs = ad.execute(
                REGISTRY.get("exploit.service_permissions"),
                REGISTRY.bind("exploit.service_permissions",
                              {"service": "acme-agent", "restore": True},
                              target="127.0.0.1"))
            assert obs.data["cleanup"] == "succeeded"
            assert svc.read_bytes() == original, "restore must put the file back"
        finally:
            t.close()

    def test_credential_exposure_never_returns_the_secret(self):
        # The assess verb reports that a credential is exposed; it must not carry
        # the value. The old shape returned the raw line ("password = hunter2..."),
        # which every real adapter redacts and which is the one shape that becomes
        # pretraining data — so it taught the model that this verb's output
        # includes the secret.
        ad, t = self._adapter()
        try:
            obs = ad.execute(
                REGISTRY.get("vuln.credential_exposure"),
                REGISTRY.bind("vuln.credential_exposure", target="127.0.0.1"))
            assert obs.data["findings"], "the planted credential must be found"
            assert "hunter2" not in str(obs.data), \
                "the secret value must never appear in the observation"
            f = obs.data["findings"][0]
            assert f["value"] == "***redacted***"
            assert f["technique"] == "T1552.001"
        finally:
            t.close()

    def test_credential_dump_redacts_by_default(self):
        ad, t = self._adapter()
        try:
            obs = ad.execute(
                REGISTRY.get("postex.credential_dump"),
                REGISTRY.bind("postex.credential_dump", {"redact": True},
                              target="127.0.0.1"))
            assert obs.data["secrets_found"] >= 1
            assert all(v == "<redacted>" for v in obs.data["values"])
            assert "hunter2" not in str(obs.data)
        finally:
            t.close()


class TestTheThesis:
    """The one property the lab exists to demonstrate."""

    def _run(self, telemetry: bool):
        from lab.run import ScriptedSweep, _engagement
        from whetstone.gate import Gate, always_confirm
        from whetstone.kernel import Kernel

        t = SandboxTarget(telemetry=telemetry)
        try:
            gate = Gate(_engagement(str(t.root)), registry=REGISTRY,
                        confirmer=always_confirm)
            ep = Kernel(gate, SandboxAdapter(t), ScriptedSweep(), max_turns=20).run(
                "assess and report gaps", target="127.0.0.1")
            return [f for f in ep.findings if f.kind == "detection_gap"]
        finally:
            t.close()

    def test_telemetry_off_produces_gaps(self):
        gaps = self._run(telemetry=False)
        assert len(gaps) == 3, "three exploits, none observed"

    def test_telemetry_on_closes_them(self):
        gaps = self._run(telemetry=True)
        assert gaps == [], "the same three exploits, all seen"

    def test_the_only_difference_is_the_switch(self):
        """Same plan, same exploits — the gap count is a function of telemetry."""
        assert len(self._run(False)) > len(self._run(True))


# --------------------------------------------------------------------------
# the defending half
#
# Three harden verbs had implementations on Linux, macOS and Windows and had
# never been called by anything. Here they run for real against the sandbox:
# the switch really flips, the mode bits really change, the crontab line really
# goes. The tests that matter are the ones that check the *effect* rather than
# the return value, because a harden verb's return value is the exact thing this
# project refuses to take as proof.
# --------------------------------------------------------------------------


def _do(adapter, verb_id, params=None, target="127.0.0.1"):
    return adapter.execute(REGISTRY.get(verb_id),
                           REGISTRY.bind(verb_id, params or {}, target=target))


class TestHardenIsReal:
    def test_enable_telemetry_really_flips_the_switch(self):
        with SandboxTarget(telemetry=False) as t:
            ad = SandboxAdapter(t)
            assert t.event("x", "T1", "before") is False

            obs = _do(ad, "harden.enable_telemetry", {"source": "sandbox-eventlog"})
            assert obs.ok and obs.data["changed"] is True
            assert t.telemetry is True
            assert t.event("x", "T1", "after") is True, (
                "the log must really start recording; a fix that only reports "
                "success is the thing the re-attack exists to catch")

    def test_enable_telemetry_refuses_a_source_that_does_not_exist(self):
        """Turning on a source the host does not have would report success and
        change nothing — a fix that is indistinguishable from a lie."""
        with SandboxTarget(telemetry=False) as t:
            obs = _do(SandboxAdapter(t), "harden.enable_telemetry",
                      {"source": "splunk"})
            assert not obs.ok and obs.unsupported
            assert t.telemetry is False

    def test_fix_permissions_really_defeats_the_exploit(self):
        """Effectiveness measured against the attack, not against the chmod.

        `vuln.weak_permissions` stops flagging the binary and
        `exploit.service_permissions` stops working — which is what "genuinely
        effective" has to mean, because the mode bits changing is only evidence
        that a command ran.
        """
        with SandboxTarget() as t:
            ad = SandboxAdapter(t)
            svc = t.resolve("opt/acme/acme-agent")
            assert _do(ad, "vuln.weak_permissions").data["findings"]
            assert _do(ad, "exploit.service_permissions",
                       {"service": "acme-agent"}).ok

            obs = _do(ad, "harden.fix_permissions", {"path": str(svc)})
            assert obs.ok and obs.data["changed"] is True
            assert svc.stat().st_mode & 0o022 == 0, "group/other write is gone"
            assert svc.stat().st_mode & 0o500, "read and execute are untouched"

            assert _do(ad, "vuln.weak_permissions").data["findings"] == []
            again = _do(ad, "exploit.service_permissions", {"service": "acme-agent"})
            assert not again.ok, "the technique must actually stop working"
            assert "write" in again.error

    def test_fix_permissions_stays_inside_the_sandbox(self):
        """A blue verb gets no exemption from confinement for meaning well."""
        with SandboxTarget() as t:
            obs = _do(SandboxAdapter(t), "harden.fix_permissions",
                      {"path": "/etc/passwd"})
            assert not obs.ok
            assert "escapes the sandbox" in obs.error

    def test_remove_persistence_really_removes_the_line(self):
        with SandboxTarget() as t:
            ad = SandboxAdapter(t)
            entry = _do(ad, "enum.persistence").data["autostart"][0]["entry"]

            obs = _do(ad, "harden.remove_persistence", {"entry": entry})
            assert obs.ok and obs.data["removed"] == 1
            assert entry not in t.resolve("etc/crontab").read_text()
            assert _do(ad, "enum.persistence").data["autostart"] == [], (
                "enumeration must agree with the fix; if it still reports the "
                "entry then one of the two is lying")

    def test_remove_persistence_refuses_a_near_miss(self):
        """Loud, because the alternative is deleting somebody else's autostart
        entry and reporting ok. The Linux adapter refuses raw cron lines
        outright for the same reason."""
        with SandboxTarget() as t:
            before = t.resolve("etc/crontab").read_text()
            obs = _do(SandboxAdapter(t), "harden.remove_persistence",
                      {"entry": "@reboot root"})
            assert not obs.ok
            assert "nothing was removed" in obs.error
            assert t.resolve("etc/crontab").read_text() == before

    def test_revert_undoes_a_fix_as_well_as_an_exploit(self):
        """The sandbox's contract is that the next episode gets what the last
        one got. A revert that restored the bytes and left the mode — or left
        the telemetry switch on — hands it a box with a weakness missing."""
        with SandboxTarget(telemetry=False) as t:
            ad = SandboxAdapter(t)
            svc = t.resolve("opt/acme/acme-agent")
            mode = svc.stat().st_mode & 0o777
            entry = _do(ad, "enum.persistence").data["autostart"][0]["entry"]

            _do(ad, "harden.fix_permissions", {"path": str(svc)})
            _do(ad, "harden.enable_telemetry", {"source": "sandbox-eventlog"})
            _do(ad, "harden.remove_persistence", {"entry": entry})

            t.revert()
            assert svc.stat().st_mode & 0o777 == mode
            assert t.telemetry is False
            assert entry in t.resolve("etc/crontab").read_text()


class TestHardenIsNotAHoleInTheGate:
    def test_a_harden_verb_is_denied_when_modify_is_not_authorised(self):
        """The defensive half must not become an authorisation bypass because
        its intentions are good. MODIFY above the ceiling is DENY, full stop."""
        from datetime import datetime, timedelta, timezone

        from whetstone.actions import Intent
        from whetstone.gate import Gate, GateRefusal, always_confirm
        from whetstone.gate.engagement import Authorization, Engagement, Scope

        with SandboxTarget() as t:
            now = datetime.now(timezone.utc)
            observe_only = Engagement(
                name="read-only review",
                authorization="LAB — observation only",
                starts=now - timedelta(minutes=1), expires=now + timedelta(hours=1),
                scope=Scope(paths=(str(t.root),), allow_loopback=True),
                authorize=Authorization(
                    red_team=False, max_intent=Intent.OBSERVE,
                    unattended=frozenset({Intent.OBSERVE})))
            adapter = SandboxAdapter(t)
            gate = Gate(observe_only, registry=REGISTRY, confirmer=always_confirm)

            action = REGISTRY.bind("harden.enable_telemetry",
                                   {"source": "sandbox-eventlog"},
                                   target="127.0.0.1")
            with pytest.raises(GateRefusal) as refusal:
                gate.submit(action, adapter.execute)

            assert refusal.value.decision.rule == "intent.ceiling"
            assert t.telemetry is False, "the switch must not have moved"

    def test_an_observe_only_engagement_never_offers_a_fix(self):
        """`Gate.catalogue` filters on the ceiling, so the verb is not even put
        in front of the agent — a temptation removed is cheaper than a refusal
        trained."""
        from datetime import datetime, timedelta, timezone

        from whetstone.actions import Intent, Side
        from whetstone.gate import Gate, always_confirm
        from whetstone.gate.engagement import Authorization, Engagement, Scope

        with SandboxTarget() as t:
            now = datetime.now(timezone.utc)
            gate = Gate(Engagement(
                name="read-only review",
                authorization="LAB — observation only",
                starts=now - timedelta(minutes=1), expires=now + timedelta(hours=1),
                scope=Scope(paths=(str(t.root),), allow_loopback=True),
                authorize=Authorization(
                    red_team=False, max_intent=Intent.OBSERVE,
                    unattended=frozenset({Intent.OBSERVE}))),
                registry=REGISTRY, confirmer=always_confirm)
            offered = [v.id for v in gate.catalogue()
                       if v.side is Side.BLUE and v.intent is not Intent.OBSERVE]
            assert offered == []


class TestTheLoopCloses:
    """attack -> detect -> gap -> harden -> re-attack -> re-detect -> closed."""

    def _run(self, telemetry: bool, remediate: bool):
        from lab.run import ScriptedSweep, _engagement
        from whetstone.gate import Gate, always_confirm
        from whetstone.kernel import Kernel

        t = SandboxTarget(telemetry=telemetry)
        try:
            gate = Gate(_engagement(str(t.root)), registry=REGISTRY,
                        confirmer=always_confirm)
            return Kernel(gate, SandboxAdapter(t), ScriptedSweep(), max_turns=20,
                          remediate=remediate).run("assess and report gaps",
                                                   target="127.0.0.1"), t
        finally:
            pass

    def test_every_gap_the_lab_opens_is_proven_closed(self):
        ep, t = self._run(telemetry=False, remediate=True)
        try:
            gaps = [f for f in ep.findings if f.kind == "detection_gap"]
            assert len(gaps) == 3, "the three gaps are still found"
            assert all(g.remediation is not None for g in gaps)
            assert [g.remediation.state for g in gaps] == ["closed"] * 3
            assert all(g.remediation.verb == "harden.enable_telemetry"
                       for g in gaps), (
                "the control named its own remedy and the kernel preferred it "
                "over the fix that merely removes one instance of the weakness")
        finally:
            t.close()

    def test_closure_is_proven_by_a_second_attack_not_by_the_fix(self):
        """Each closed gap must be backed by the exploit running again and the
        same probe being asked again, both after the fix."""
        ep, t = self._run(telemetry=False, remediate=True)
        try:
            phases = [(turn.action.verb_id, turn.phase) for turn in ep.turns]
            assert ("harden.enable_telemetry", "remediate") in phases
            for red, probe in (("exploit.service_permissions", "detect.process_creation"),
                               ("postex.credential_dump", "detect.credential_access"),
                               ("postex.persistence_install", "detect.persistence_change")):
                assert (red, "plan") in phases and (red, "verify") in phases, (
                    f"{red} must have run twice: once as the attack, once as "
                    "the evidence that the fix worked")
                assert (probe, "detect") in phases and (probe, "verify") in phases
        finally:
            t.close()

    def test_the_gap_count_is_unchanged_by_remediating(self):
        """Remediation attaches an outcome to a finding. It must not delete the
        gap, and it must not invent a second finding about the same event."""
        closed, t1 = self._run(telemetry=False, remediate=True)
        left_open, t2 = self._run(telemetry=False, remediate=False)
        try:
            assert ([f.kind for f in closed.findings]
                    == [f.kind for f in left_open.findings]
                    == ["detection_gap"] * 3)
            assert ([f.detail for f in closed.findings]
                    == [f.detail for f in left_open.findings])
        finally:
            t1.close()
            t2.close()

    def test_telemetry_on_still_has_nothing_to_remediate(self):
        ep, t = self._run(telemetry=True, remediate=True)
        try:
            assert [f for f in ep.findings if f.kind == "detection_gap"] == []
            assert not [turn for turn in ep.turns if turn.phase != "plan"
                        and turn.action.verb_id.startswith("harden.")]
        finally:
            t.close()
