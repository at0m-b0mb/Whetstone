"""A self-contained lab target: real files, real weaknesses, a real telemetry log.

The roadmap's top blocker was that the red path could not be exercised without a
VM, so the detection verifier — the mechanically checkable ground truth this
whole project is built around — had nowhere to run. A full Windows-plus-Linux
lab is the right long-term answer. This is the one that works today, on the
machine in front of you, with nothing to download.

It is a **real** environment, not a mock. The sandbox is a temporary directory
tree containing an actually-writable "service binary", a config file with an
actual credential in it, an actual persistence entry. The exploit verbs really
overwrite that binary and really append to the persistence file — the writes hit
the disk, they are just confined to the sandbox and reverted on teardown. The
detection verbs really read a real telemetry log. Nothing here pretends.

The point that makes it a *test* rather than a toy is the telemetry switch. When
telemetry is enabled, an exploit writes an event to the log and the paired
detection finds it — no gap. When telemetry is disabled, the exploit runs
exactly the same way, writes nothing to the log, and the detection finds
silence — a detection gap. Flip the switch and the whole purple thesis is
visible end to end: the same attack, seen or unseen depending only on whether
the blue side was watching.

Everything is confined to :attr:`SandboxTarget.root`. There is no code path that
writes outside it, because every path is built by joining onto ``root`` and the
join is checked. A red verb pointed at this target cannot touch the real host,
which is the property that makes it safe to run the genuine article.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = ["SandboxTarget", "Weakness"]


@dataclass(frozen=True, slots=True)
class Weakness:
    """One planted flaw, so a scenario's ground truth is explicit.

    The lab knows exactly what it planted, which is what lets the benchmark ask
    "did the agent find the weakness that is actually here" rather than "did the
    agent find something that looks like a weakness". A finding that matches a
    planted ``Weakness`` is a true positive by construction.
    """

    kind: str          # "writable_service" | "credential" | "persistence" | "patch"
    technique: str     # the ATT&CK id it enables
    detail: str


class SandboxTarget:
    """A disposable host the agent can enumerate, exploit and inspect for real.

    Use as a context manager so the tree is always cleaned up::

        with SandboxTarget(telemetry=False) as tgt:
            adapter = SandboxAdapter(tgt)
            ...

    ``telemetry`` is the switch the whole lab exists to demonstrate. It defaults
    to ``False`` because the interesting, report-worthy case — the one a
    defender needs to see — is the attack that nobody logged.
    """

    def __init__(self, *, telemetry: bool = False,
                 root: Path | None = None) -> None:
        self.telemetry = telemetry
        self._owns_root = root is None
        self.root = (root or Path(tempfile.mkdtemp(prefix="whetstone-lab-"))).resolve()
        self.log_path = self.root / "var" / "telemetry.log"
        self.weaknesses: list[Weakness] = []
        self._original: dict[str, bytes] = {}
        self._build()

    # ------------------------------------------------------------------ setup

    def _build(self) -> None:
        """Plant the environment. Each weakness is recorded as ground truth."""
        (self.root / "var").mkdir(parents=True, exist_ok=True)
        (self.root / "etc").mkdir(exist_ok=True)
        (self.root / "opt" / "acme").mkdir(parents=True, exist_ok=True)
        self.log_path.write_text("", encoding="utf-8")

        # A world-writable service binary running as a privileged account: the
        # classic file-permissions escalation.
        svc = self.root / "opt" / "acme" / "acme-agent"
        svc.write_text("#!/bin/sh\n# legitimate service\nexec /usr/bin/true\n",
                       encoding="utf-8")
        svc.chmod(0o777)
        self._remember(svc)
        self.weaknesses.append(Weakness(
            "writable_service", "T1574.010",
            f"{svc} is world-writable and runs as root"))

        # A credential sitting in a config file.
        cfg = self.root / "etc" / "acme.conf"
        cfg.write_text("[db]\nhost = 10.20.4.9\n"
                       "password = hunter2-do-not-ship\n", encoding="utf-8")
        self._remember(cfg)
        self.weaknesses.append(Weakness(
            "credential", "T1552.001",
            f"{cfg} contains a plaintext database password"))

        # An autostart entry, so persistence enumeration finds something.
        cron = self.root / "etc" / "crontab"
        cron.write_text("# m h dom mon dow user command\n"
                        "@reboot root /opt/acme/acme-agent\n", encoding="utf-8")
        self._remember(cron)
        self.weaknesses.append(Weakness(
            "persistence", "T1053.003",
            f"{cron} runs /opt/acme/acme-agent at boot as root"))

        # Outdated software, for the patch-gap check.
        (self.root / "etc" / "installed.json").write_text(json.dumps({
            "openssl": "1.0.1", "sudo": "1.8.2", "acme-agent": "2.1.0",
        }), encoding="utf-8")
        self.weaknesses.append(Weakness(
            "patch", "T1203",
            "openssl 1.0.1 and sudo 1.8.2 are both known-vulnerable"))

        self.event("baseline", "lab", "sandbox built")

    def _remember(self, path: Path) -> None:
        """Snapshot a file so an exploit that mutates it can be reverted."""
        self._original[str(path)] = path.read_bytes()

    # --------------------------------------------------------------- confinement

    def resolve(self, name: str) -> Path:
        """A path inside the sandbox, or raise. The confinement boundary.

        Every file operation goes through here. A ``name`` that escapes the root
        — via ``..`` or an absolute path or a symlink — resolves to somewhere
        outside and is refused, so there is no reachable way for a verb to touch
        the real host even when handed a hostile parameter.
        """
        candidate = (self.root / name).resolve()
        if candidate != self.root and self.root not in candidate.parents:
            raise ValueError(f"{name!r} escapes the sandbox root")
        return candidate

    # ------------------------------------------------------------------ telemetry

    def event(self, kind: str, technique: str, detail: str) -> bool:
        """Record a telemetry event — but only if telemetry is enabled.

        Returns whether it was actually written. This is the single switch the
        lab turns on: an exploit calls it after acting, and whether the paired
        detection later finds anything depends entirely on the boolean set at
        construction. Nothing else differs between the seen and unseen cases.
        """
        if not self.telemetry:
            return False
        line = json.dumps({
            "ts": round(time.time(), 3), "kind": kind,
            "technique": technique, "detail": detail,
        })
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        return True

    def events(self, *, kind: str | None = None, since: float | None = None) -> list[dict[str, Any]]:
        """Read telemetry back, the way a detection verb does."""
        out: list[dict[str, Any]] = []
        if not self.log_path.exists():
            return out
        for line in self.log_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if kind and row.get("kind") != kind:
                continue
            if since and row.get("ts", 0) < since:
                continue
            out.append(row)
        return out

    # ------------------------------------------------------------------ teardown

    def revert(self) -> None:
        """Restore every file an exploit changed. Proves cleanup really works."""
        for path_str, content in self._original.items():
            try:
                Path(path_str).write_bytes(content)
            except OSError:
                pass

    def close(self) -> None:
        if self._owns_root and self.root.exists():
            shutil.rmtree(self.root, ignore_errors=True)

    def __enter__(self) -> SandboxTarget:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def summary(self) -> str:
        lines = [f"sandbox at {self.root}",
                 f"telemetry: {'ENABLED' if self.telemetry else 'DISABLED'}",
                 f"{len(self.weaknesses)} planted weakness(es):"]
        for w in self.weaknesses:
            lines.append(f"  [{w.technique}] {w.kind}: {w.detail}")
        return "\n".join(lines)
