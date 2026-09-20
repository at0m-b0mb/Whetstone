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
from whetstone.adapters.base import Adapter, AdapterError

from .target import SandboxTarget

__all__ = ["SandboxAdapter"]

#: The sandbox's one telemetry source. Named in three places that have to agree
#: — what ``detect.telemetry`` reports, what a silent probe suggests enabling,
#: and what ``harden.enable_telemetry`` accepts — so it is a constant rather
#: than a string typed out three times. A fix aimed at a source name that does
#: not exist would be refused by the adapter, which is the right answer to the
#: wrong question: the interesting failure is the one where the names drift and
#: the fix quietly stops being proposable.
_SOURCE = "sandbox-eventlog"

#: The service binary, relative to the sandbox root. The planted weakness, the
#: exploit, the permission fix and the process image in the telemetry record all
#: refer to this one file.
_SERVICE = "opt/acme/acme-agent"
_SERVICE_IMAGE = "acme-agent"

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
    """Really overwrite the writable service binary, then log (or not).

    The permission check at the top is what makes ``harden.fix_permissions``
    mean something, and it is a *model* rather than a real ``EACCES`` — worth
    being explicit about, because a model that pretends to be an enforcement
    boundary is how a lab starts lying.

    The weakness planted here is "a non-root user can write a binary a root
    service executes". ``enum.privileges`` says so: uid 1000, not admin. But the
    process running this adapter *owns* the file, so ``chmod go-w`` cannot stop
    it from writing — the operating system would deny the foothold user and
    cannot deny the owner. Asking the filesystem would therefore report the
    exploit still working after a fix that genuinely worked, which is the
    opposite of the error this project usually worries about and just as bad.

    So the foothold's identity is modelled and the file's permissions are not:
    the mode is read from the real file, which a real ``chmod`` really changed,
    and the only invented part is "uid 1000 is not the owner". Everything a
    verdict rests on — the mode, the write, the log — is genuine.
    """
    svc = self.target.resolve(_SERVICE)
    mode = svc.stat().st_mode & 0o777
    if not mode & 0o022:
        raise AdapterError(
            f"cannot write {svc}: mode is {oct(mode)}, and the foothold this "
            "lab models is uid 1000, which neither owns the file nor is in its "
            "group. The technique depended on the group/other write bit and "
            "that bit is gone.")

    restore = bool(action.params.get("restore", True))
    original = svc.read_bytes()

    payload = b"#!/bin/sh\n# whetstone marker: execution as service account\n"
    svc.write_bytes(payload)
    logged = self.target.event(
        "process_creation", "T1574.010",
        "acme-agent binary replaced and would run as root",
        image=_SERVICE_IMAGE)

    cleaned = None
    if restore:
        svc.write_bytes(original)
        cleaned = svc.read_bytes() == original

    return {"changed": str(svc), "bytes_written": len(payload),
            "ran_as": "root", "cleanup": "succeeded" if cleaned else
            ("failed" if restore else "not requested"),
            "telemetry_written": logged,
            # Named `image` because that is what `detect.process_creation`
            # calls its own parameter, which is the exact-match convention the
            # kernel aims a probe by. Without it the probe asks "was anything
            # logged in the window" and the kernel — correctly — refuses to read
            # the answer as a verdict on this technique, so a gap here could
            # never be proven closed however good the fix was.
            "image": _SERVICE_IMAGE,
            # What would fix this, named under the key the kernel reads and
            # under the harden verb's own parameter name. The red handler is the
            # only thing that knows which file it just overwrote.
            "remediation": {"harden.fix_permissions": {"path": str(svc)}}}


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
    payload = {"installed_in": str(cron), "entry": marker,
               "cleanup": "succeeded" if removed else
               ("failed" if cleanup else "not requested"),
               "telemetry_written": logged}
    # Only offer the removal when the entry is actually still on disk. Cleanup
    # usually took it away already, and a hint pointing at a line that is gone
    # would send a MODIFY at nothing and come back "failed" — a true statement
    # about a fix nobody should have attempted. A hint is a claim about the
    # current state, so it is made only when the state supports it.
    if not removed:
        payload["remediation"] = {"harden.remove_persistence": {"entry": marker}}
    return payload


# ------------------------------------------------------------------- detect

def _window(action: Action) -> float:
    import time
    return time.time() - float(action.params.get("since_seconds", 300))


def _silent(events: list[Any]) -> dict[str, Any]:
    """The remediation hint a control publishes when it saw nothing.

    Only when it saw nothing: a control that fired has nothing to remediate, and
    a hint attached to a hit would be a fix offered for a gap that does not
    exist.

    This is the *control* naming its own remedy, which is why the kernel prefers
    it over a hint from the red side. A detection gap is a statement about the
    control: the fix that makes it see the next instance of the technique
    answers the finding, and the fix that removes this one instance of the
    weakness answers a different and narrower question. Both are offered; the
    ordering says which one the finding asked for.

    Note what this payload deliberately does **not** carry. Adding
    ``enabled: false`` would be read by ``detection_fired`` as provenance —
    "the source could not be queried" — and the honest reading here is the
    opposite. The log is present, readable and really was read; it is empty
    because nothing wrote to it while the technique ran. That is a queryable
    control that saw nothing, which is a genuine gap, and dressing it up as
    unknowable would suppress the one finding this lab exists to produce.
    """
    if events:
        return {}
    return {"remediation": {"harden.enable_telemetry": {"source": _SOURCE}}}


@T.implements("detect.telemetry")
def _detect_telemetry(self: SandboxAdapter, verb: Verb, action: Action) -> Any:
    on = self.target.telemetry
    return {"sources": [{"source": _SOURCE, "enabled": on,
                         "records_process_creation": on}],
            "process_creation_auditing": on,
            "summary": ("telemetry is enabled; actions are being logged" if on
                        else "telemetry is DISABLED on this host; nothing is "
                             "recorded, so no attack would be seen")}


@T.implements("detect.process_creation")
def _detect_proc(self: SandboxAdapter, verb: Verb, action: Action) -> Any:
    # `image` is honoured rather than accepted and ignored. A probe whose
    # discriminator the adapter throws away answers "was anything logged"
    # while claiming to answer "was this logged", and the kernel has no way to
    # tell the difference — it would read an unrelated record as proof that the
    # control caught the technique.
    image = action.params.get("image")
    events = self.target.events(kind="process_creation", since=_window(action),
                                image=image if isinstance(image, str) else None)
    return {"logged": bool(events), "count": len(events),
            "matched_image": image or "",
            "events": [e["detail"] for e in events[:4]],
            **_silent(events)}


@T.implements("detect.persistence_change")
def _detect_persist(self: SandboxAdapter, verb: Verb, action: Action) -> Any:
    events = self.target.events(kind="persistence_change", since=_window(action))
    return {"logged": bool(events), "count": len(events),
            "events": [e["detail"] for e in events[:4]],
            **_silent(events)}


@T.implements("detect.credential_access")
def _detect_cred(self: SandboxAdapter, verb: Verb, action: Action) -> Any:
    events = self.target.events(kind="credential_access", since=_window(action))
    return {"logged": bool(events), "count": len(events),
            "events": [e["detail"] for e in events[:4]],
            **_silent(events)}


# -------------------------------------------------------------------- harden
#
# The half of the catalogue that had never run. Three verbs, implemented for
# real against the sandbox: the switch really flips, the mode bits really
# change, the crontab line really goes. Each is faithful to what the Linux
# adapter does on a machine — strip group/other write and leave read/execute
# alone; act only on an entry named exactly, never on a pattern — so that the
# thing demonstrated here is the thing that would happen on a host.
#
# None of them writes a telemetry record under the kind of the technique it
# remediates. A removal is not an installation, and a `persistence_change`
# event emitted by the fix would sit in the same window as the re-attack and
# could be counted as the control noticing the attack. The fix must not be able
# to manufacture its own proof; that is the entire failure mode the re-attack
# exists to catch, and it would be embarrassing to reintroduce it here. They
# log under `harden`, which no detection verb reads.


@T.implements("harden.enable_telemetry")
def _harden_telemetry(self: SandboxAdapter, verb: Verb, action: Action) -> Any:
    """Really switch the sandbox's logging on."""
    source = action.params["source"]
    if source != _SOURCE:
        return Observation(
            action=action, ok=False, unsupported=True, platform="sandbox",
            error=(f"this sandbox has one telemetry source, {_SOURCE!r}; "
                   f"{source!r} is not something it can turn on. Enabling a "
                   "source that does not exist would report success and change "
                   "nothing."))
    changed = self.target.set_telemetry(True)
    self.target.event("harden", "lab", f"telemetry source {source} enabled")
    return {"source": source, "enabled": True, "changed": changed,
            "was_already_on": not changed,
            "restore_hint": "SandboxTarget.set_telemetry(False), or revert()"}


@T.implements("harden.fix_permissions")
def _harden_permissions(self: SandboxAdapter, verb: Verb, action: Action) -> Any:
    """Really tighten the mode bits, confined to the sandbox like everything else.

    Strips group and other write and touches nothing else, which is what the
    Linux adapter does and for the reason it gives: loosening is never the fix,
    and removing ``g+w``/``o+w`` addresses exactly what ``vuln.weak_permissions``
    flags without guessing at intent.

    The path arrives from the model or from a remediation hint and goes through
    ``target.resolve``, so a parameter pointing at ``/etc/passwd`` raises rather
    than chmod-ing the real host. That is the same boundary every other verb
    here crosses; a blue verb gets no exemption for meaning well.
    """
    path = self.target.resolve(action.params["path"])
    if not path.exists():
        raise AdapterError(f"{path} does not exist, so there is no ACL to fix")
    before = path.stat().st_mode & 0o777
    after = before & ~0o022
    path.chmod(after)
    return {"path": str(path), "previous_mode": oct(before),
            "new_mode": oct(after), "changed": before != after,
            "restore_hint": f"chmod {oct(before)[2:]} {path}"}


@T.implements("harden.remove_persistence")
def _harden_remove_persistence(self: SandboxAdapter, verb: Verb, action: Action) -> Any:
    """Really delete an autostart line from the sandbox crontab.

    The match is on the whole line, exactly. ``enum.persistence`` hands out the
    crontab line verbatim as the entry identifier, so an exact match is always
    satisfiable by a caller that looked first — and a substring match would let
    ``root`` remove every root entry on the box. The Linux adapter refuses raw
    cron lines altogether for this reason; here the identifier is unambiguous,
    so the removal is possible, but not looser than that.

    A miss raises instead of reporting a no-op success. A fix that removed
    nothing and said ``ok`` is precisely the claim this whole phase exists to
    stop being believed.
    """
    entry = action.params["entry"].strip()
    cron = self.target.resolve("etc/crontab")
    lines = cron.read_text(encoding="utf-8").splitlines()
    kept = [ln for ln in lines if ln.strip() != entry]
    removed = len(lines) - len(kept)
    if removed == 0:
        raise AdapterError(
            f"no line in {cron} is exactly {entry!r}; nothing was removed. Run "
            "enum.persistence and pass an entry it reported verbatim — a "
            "near-miss must not silently delete a different autostart entry.")
    cron.write_text("\n".join(kept) + "\n", encoding="utf-8")
    self.target.event("harden", "T1053.003",
                      f"autostart entry removed: {entry}")
    return {"entry": entry, "removed": removed, "file": str(cron),
            "remaining": len([ln for ln in kept
                              if ln.strip() and not ln.startswith("#")]),
            "restore_hint": f"re-add {entry!r} to {cron}"}
