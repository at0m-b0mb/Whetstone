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
