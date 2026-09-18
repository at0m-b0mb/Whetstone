"""An adapter that drives a :class:`SandboxTarget` — the red path, for real.

The platform adapters run against the host. This one runs against the sandbox,
which is the difference between *exercising* an exploit and merely *planning* it.
Every red verb here really acts: ``exploit.service_permissions`` really
overwrites the planted binary, ``postex.persistence_install`` really appends to
the crontab, ``postex.credential_dump`` really reads the config. The writes are
real; they are confined to the sandbox and reverted on teardown.

That confinement is what makes running the genuine article safe. A platform
adapter's ``exploit.*`` on a laptop is a real change to a real machine; the same
verb here changes only files under the sandbox root, so the full attack →
detect → gap loop can be run, tested, and put in a benchmark without a VM and
without touching anything that matters.

Crucially, this adapter does **not** decide whether a detection fires. It calls
:meth:`SandboxTarget.event` after each red action, and whether that event is
recorded depends only on the target's telemetry switch. The detection verbs then
read whatever is actually in the log. So a detection gap emerges from the same
mechanism it would on a real host — an action that logged nothing, and a query
that therefore found nothing — rather than from anything this adapter asserts.
"""

from __future__ import annotations

import json
from typing import Any

from whetstone.actions import Action, Observation, Verb
from whetstone.adapters.base import Adapter

from .target import SandboxTarget

__all__ = ["SandboxAdapter"]

#: Versions below these are treated as vulnerable by the patch-gap check. Kept
#: tiny and explicit rather than pulling a CVE feed: the lab's job is to exercise
#: the loop, and a hand-checkable table makes the ground truth obvious.
_MIN_SAFE = {"openssl": (3, 0, 0), "sudo": (1, 9, 5)}


def _ver(text: str) -> tuple[int, ...]:
    return tuple(int(p) for p in text.split(".") if p.isdigit())


class SandboxAdapter(Adapter):
    """Implements the catalogue against a sandbox rather than the host.

    Not registered by platform — the sandbox is not an operating system, and
    :func:`whetstone.adapters.base.get_adapter` should never return it by
    accident. It is constructed directly with a target and handed to the kernel.
    """

    platform = "sandbox"

    def __init__(self, target: SandboxTarget) -> None:
        self.target = target


T = SandboxAdapter


# ---------------------------------------------------------------- enumerate

@T.implements("enum.host")
def _enum_host(self: SandboxAdapter, verb: Verb, action: Action) -> Any:
    return {"os": "sandbox-linux", "hostname": "acme-lab",
            "root": str(self.target.root), "kernel": "6.1.0-lab"}


@T.implements("enum.privileges")
def _enum_priv(self: SandboxAdapter, verb: Verb, action: Action) -> Any:
    return {"user": "operator", "uid": 1000, "is_admin": False,
            "sudo": ["/opt/acme/acme-agent"], "note": "non-root foothold"}


@T.implements("enum.services")
def _enum_services(self: SandboxAdapter, verb: Verb, action: Action) -> Any:
    svc = self.target.resolve("opt/acme/acme-agent")
    mode = oct(svc.stat().st_mode & 0o777)
    return {"services": [{"name": "acme-agent", "path": str(svc),
                          "runs_as": "root", "mode": mode}]}


@T.implements("enum.persistence")
def _enum_persistence(self: SandboxAdapter, verb: Verb, action: Action) -> Any:
    cron = self.target.resolve("etc/crontab")
    entries = [ln for ln in cron.read_text().splitlines()
               if ln.strip() and not ln.startswith("#")]
    return {"autostart": [{"source": "crontab", "entry": e} for e in entries]}


@T.implements("enum.software")
def _enum_software(self: SandboxAdapter, verb: Verb, action: Action) -> Any:
    data = json.loads(self.target.resolve("etc/installed.json").read_text())
    return {"packages": [{"name": k, "version": v} for k, v in data.items()]}


# ------------------------------------------------------------------- assess

@T.implements("vuln.weak_permissions")
def _vuln_perms(self: SandboxAdapter, verb: Verb, action: Action) -> Any:
    svc = self.target.resolve("opt/acme/acme-agent")
    mode = svc.stat().st_mode & 0o777
    findings = []
    if mode & 0o022:      # world- or group-writable
        findings.append({"path": str(svc), "mode": oct(mode), "runs_as": "root",
                         "technique": "T1574.010",
                         "why": "writable binary executed by a root service"})
    return {"findings": findings}


@T.implements("vuln.credential_exposure")
def _vuln_creds(self: SandboxAdapter, verb: Verb, action: Action) -> Any:
    # An *assessment* verb reports that a credential is exposed; it must not
    # become a second copy of the credential. The old shape returned the raw
    # matching line — ``"line": "password = hunter2-do-not-ship"`` — which is the
    # exact leak every real adapter is built to avoid: linux emits
    # ``value: "***redacted***"`` (find_secrets), macOS a redacted preview,
    # windows ``redact=True``, and the VM sibling here returns only path+
    # technique. This adapter is the one whose observations become pretraining
    # data, so leaving the secret in ``line`` would teach the model that this
    # verb's output *includes* the value — the opposite of the contract. We now
    # report the line NUMBER (matching linux's ``line`` field, which is an int)
    # and a redacted value, keeping ``path`` and ``technique`` so the ground-truth
    # Weakness still matches by technique.
    cfg = self.target.resolve("etc/acme.conf")
    hits = [{"path": str(cfg), "line": n, "kind": "password_assignment",
             "value": "***redacted***", "technique": "T1552.001"}
            for n, ln in enumerate(cfg.read_text().splitlines(), start=1)
            if "password" in ln.lower() or "secret" in ln.lower()]
    return {"findings": hits}


@T.implements("vuln.patch_gap")
def _vuln_patch(self: SandboxAdapter, verb: Verb, action: Action) -> Any:
    data = json.loads(self.target.resolve("etc/installed.json").read_text())
    gaps = []
    for name, floor in _MIN_SAFE.items():
        have = _ver(data.get(name, "0"))
        if have and have < floor:
            gaps.append({"package": name, "installed": data[name],
                         "min_safe": ".".join(map(str, floor)),
                         "technique": "T1203"})
    return {"findings": gaps}


# ------------------------------------------------------------------ exploit

@T.implements("exploit.service_permissions")
def _exploit_service(self: SandboxAdapter, verb: Verb, action: Action) -> Any:
    """Really overwrite the writable service binary, then log (or not)."""
    svc = self.target.resolve("opt/acme/acme-agent")
    restore = bool(action.params.get("restore", True))
    original = svc.read_bytes()

    payload = b"#!/bin/sh\n# whetstone marker: execution as service account\n"
    svc.write_bytes(payload)
    logged = self.target.event("process_creation", "T1574.010",
                               "acme-agent binary replaced and would run as root")

    cleaned = None
    if restore:
        svc.write_bytes(original)
        cleaned = svc.read_bytes() == original

    return {"changed": str(svc), "bytes_written": len(payload),
            "ran_as": "root", "cleanup": "succeeded" if cleaned else
            ("failed" if restore else "not requested"),
            "telemetry_written": logged}


@T.implements("postex.credential_dump")
def _postex_creds(self: SandboxAdapter, verb: Verb, action: Action) -> Any:
    """Really read the credential store; redact by default."""
    redact = bool(action.params.get("redact", True))
    cfg = self.target.resolve("etc/acme.conf")
    secrets = [ln.split("=", 1)[1].strip()
               for ln in cfg.read_text().splitlines()
               if ln.lower().strip().startswith("password")]
    self.target.event("credential_access", "T1552.001",
                      "acme.conf read for stored credentials")
    return {"source": str(cfg), "secrets_found": len(secrets),
            "accounts": ["db"],
            "values": ["<redacted>"] * len(secrets) if redact else secrets,
            "redacted": redact}


@T.implements("postex.persistence_install")
def _postex_persist(self: SandboxAdapter, verb: Verb, action: Action) -> Any:
    """Really append an autostart entry, then log (or not)."""
    cron = self.target.resolve("etc/crontab")
    cleanup = bool(action.params.get("cleanup", True))
    original = cron.read_text()
    marker = "@reboot root /tmp/.whetstone-marker  # whetstone persistence test"
    cron.write_text(original + marker + "\n", encoding="utf-8")
    logged = self.target.event("persistence_change", "T1053.003",
                               "new @reboot crontab entry installed")
    removed = None
    if cleanup:
        cron.write_text(original, encoding="utf-8")
        removed = marker not in cron.read_text()
    return {"installed_in": str(cron), "entry": marker,
            "cleanup": "succeeded" if removed else
            ("failed" if cleanup else "not requested"),
            "telemetry_written": logged}


# ------------------------------------------------------------------- detect

def _window(action: Action) -> float:
    import time
    return time.time() - float(action.params.get("since_seconds", 300))


@T.implements("detect.telemetry")
def _detect_telemetry(self: SandboxAdapter, verb: Verb, action: Action) -> Any:
    on = self.target.telemetry
    return {"sources": [{"source": "sandbox-eventlog", "enabled": on,
                         "records_process_creation": on}],
            "process_creation_auditing": on,
            "summary": ("telemetry is enabled; actions are being logged" if on
                        else "telemetry is DISABLED on this host; nothing is "
                             "recorded, so no attack would be seen")}


@T.implements("detect.process_creation")
def _detect_proc(self: SandboxAdapter, verb: Verb, action: Action) -> Any:
    events = self.target.events(kind="process_creation", since=_window(action))
    return {"logged": bool(events), "count": len(events),
            "events": [e["detail"] for e in events[:4]]}


@T.implements("detect.persistence_change")
def _detect_persist(self: SandboxAdapter, verb: Verb, action: Action) -> Any:
    events = self.target.events(kind="persistence_change", since=_window(action))
    return {"logged": bool(events), "count": len(events),
            "events": [e["detail"] for e in events[:4]]}


@T.implements("detect.credential_access")
def _detect_cred(self: SandboxAdapter, verb: Verb, action: Action) -> Any:
    events = self.target.events(kind="credential_access", since=_window(action))
    return {"logged": bool(events), "count": len(events),
            "events": [e["detail"] for e in events[:4]]}
