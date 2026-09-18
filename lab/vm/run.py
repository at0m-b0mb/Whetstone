"""Run the purple loop against the real Lima VM — the genuine article.

    python -m lab.vm.run              # auditd has no rules: the gap is real
    python -m lab.vm.run --arm        # load an execve audit rule first, then run

The VM version of ``lab.run``. The sandbox demonstrates the loop on a contained
directory; this demonstrates it on Ubuntu, against auditd, over SSH. The exploit
really overwrites a root-owned binary on the VM and restores it; the detection
really asks auditd whether it saw.

``--arm`` is the real-host equivalent of the sandbox's telemetry switch. Out of
the box the provisioned VM runs auditd with no rules loaded — the common
real-world state where the tool is present and watching nothing. Arming it loads
an ``execve`` rule, so the same exploit that went unseen is now caught. The gap
opens and closes based on a genuine change to a genuine control.
"""

from __future__ import annotations

import argparse
import os
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import whetstone.verbs  # noqa: F401  (registers the catalogue)
from whetstone.actions import REGISTRY, Intent
from whetstone.gate import Gate, always_confirm
from whetstone.gate.engagement import Authorization, Engagement, Scope
from whetstone.kernel import Kernel

from .adapter import VMAdapter, _LIMA_HOME, _VM

_PLAN = (
    ("enum.host", {}), ("enum.privileges", {}), ("enum.services", {}),
    ("vuln.weak_permissions", {}), ("vuln.credential_exposure", {}),
    ("detect.telemetry", {}),
    ("exploit.service_permissions", {"service": "acme-agent"}),
)


class Sweep:
    def __init__(self, plan=_PLAN):
        self.plan = list(plan)

    def choose(self, episode, permitted, *, exclude, target):
        from whetstone.actions import TargetKind
        done = {t.action.verb_id for t in episode.turns} | set(exclude)
        by_id = {v.id: v for v in permitted}
        for verb_id, extra in self.plan:
            if verb_id in done or verb_id not in by_id:
                continue
            verb = by_id[verb_id]
            params = {p.name: (p.choices[0] if p.choices else p.default)
                      for p in verb.params if p.default is not None}
            params = {k: v for k, v in params.items() if v is not None}
            params.update(extra)
            return verb.bind(params,
                             target=None if verb.target is TargetKind.NONE else target)
        return None


def _vm(argv, *, timeout: int = 30, **kw):
    """Run one argv on the VM, bounded. A stalled guest must degrade, not wedge.

    These auditctl/truncate calls run outside the adapter, so ``Adapter.execute``
    's exception-to-Observation safety net does not cover them, and a bare
    ``subprocess.run`` with no deadline blocks the runner forever on a half-open
    Lima SSH session (routine on macOS wake). Before the episode that hangs the
    process with no diagnostic; after it, ``disarm_auditd`` never returns, so the
    run looks finished but never exits and the audit rule is left armed on the
    VM. A finite timeout turns the stall into a failed CompletedProcess the
    caller can see and act on, matching ``_run_on_vm`` in the adapter.
    """
    try:
        return subprocess.run(
            ["limactl", "shell", "--workdir", "/", _VM, "--", *argv],
            env={**os.environ, "LIMA_HOME": _LIMA_HOME},
            capture_output=True, text=True, timeout=timeout, **kw)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(
            argv, returncode=-1, stdout="",
            stderr=f"timed out after {timeout}s")


def arm_auditd() -> None:
    """Load the file-modification watch, so the blue side actually watches.

    Whether auditd was armed is the experiment's independent variable — the whole
    run's conclusion is read against it — so asserting "armed" without checking
    the result would be asserting the very thing under test. A failed auditctl
    (missing binary, ``-e 2`` locked config, no passwordless sudo on a
    re-provisioned VM) would otherwise print "armed" while nothing watches, and
    the unrecorded exploit would then be reported as a real control that missed a
    root-binary overwrite: a fabricated indictment, the wrong-number-nobody-
    notices this project refuses to emit. So we check the returncode and fail
    loudly instead.
    """
    from .adapter import AUDIT_KEY
    r = _vm(["sudo", "auditctl", "-w", "/opt/acme/acme-agent", "-p", "wa",
             "-k", AUDIT_KEY])
    if r.returncode != 0:
        raise SystemExit(
            f"could not arm auditd (auditctl rc={r.returncode}): "
            f"{r.stderr.strip()[:200] or 'no error output'}")
    print(f"armed auditd: file-modification watch on /opt/acme/acme-agent "
          f"(key={AUDIT_KEY})\n")


def disarm_auditd() -> None:
    # Result intentionally not fatal: disarm is teardown, and a failure here must
    # not mask the episode's own report. It is still bounded by _vm's timeout so
    # it cannot hang the process on the way out. A non-zero rc is surfaced as a
    # warning rather than swallowed, so a rule left loaded on the VM is at least
    # visible to the operator.
    r = _vm(["sudo", "auditctl", "-D"])
    if r.returncode != 0:
        print(f"warning: could not disarm auditd (rc={r.returncode}); "
              f"the watch rule may still be loaded on the VM")


def _engagement() -> Engagement:
    now = datetime.now(timezone.utc)
    return Engagement(
        name="lab VM purple exercise",
        authorization="LAB — disposable Lima VM, exists to be broken",
        starts=now - timedelta(minutes=1), expires=now + timedelta(hours=1),
        scope=Scope(hosts=("127.0.0.1",), allow_loopback=True),
        authorize=Authorization(red_team=True, max_intent=Intent.EXECUTE,
            techniques=("T1574", "T1552", "T1053"),
            unattended=frozenset(Intent)))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Purple loop against the real VM.")
    p.add_argument("--arm", action="store_true",
                   help="load an auditd file-watch rule before running")
    p.add_argument("--model", type=Path,
                   help="drive with a trained checkpoint (constrained decoding)")
    p.add_argument("--tokenizer", type=Path,
                   default=Path("/Volumes/at0m_b0mb/whetstone/models/tokenizer-v1/tokenizer.json"))
    args = p.parse_args(argv)

    chooser = Sweep()
    if args.model:
        from training.agent import load_chooser
        print(f"driving the real VM with the trained model at {args.model}\n")
        chooser = load_chooser(args.model, args.tokenizer, verbose=True)

    adapter = VMAdapter()          # raises with instructions if the VM is down
    disarm_auditd()
    if args.arm:
        arm_auditd()
    # Truncate the audit log AFTER arming, not before. auditctl writes a
    # ``CONFIG_CHANGE op=add_rule key=...`` record the moment the watch loads;
    # truncating first would leave that keyed rule-administration record as the
    # first line of the fresh log, sitting inside the detection window for the
    # whole run. The detector now refuses to count CONFIG_CHANGE as a write, so
    # this ordering is belt-and-suspenders — but a clean log keeps anything that
    # reads it raw honest too, and truncating last still gives each exercise the
    # fresh telemetry the disposable lab wants. The log persists across runs, so
    # a stale keyed record from a previous exercise would otherwise be counted as
    # this run's exploit being seen. A failed truncate breaks exactly that
    # freshness assumption, so it is fatal rather than silent.
    r = _vm(["sudo", "truncate", "-s", "0", "/var/log/audit/audit.log"])
    if r.returncode != 0:
        raise SystemExit(
            f"could not truncate the audit log (rc={r.returncode}): "
            f"{r.stderr.strip()[:200] or 'no error output'}")

    gate = Gate(_engagement(), registry=REGISTRY, confirmer=always_confirm)
    episode = Kernel(gate, adapter, chooser, max_turns=16).run(
        "Assess this Ubuntu host, prove the writable-service finding, and tell "
        "me whether auditd saw it.", target="127.0.0.1")

    print(episode.summary())
    gaps = [f for f in episode.findings if f.kind == "detection_gap"]
    print("\n" + "-" * 74)
    state = "ARMED" if args.arm else "no rules loaded"
    print(f"auditd {state} -> {len(gaps)} detection gap(s) on the real VM")
    for g in gaps:
        print(f"    GAP  {g.technique}: {g.detail}")
    print("-" * 74)
    disarm_auditd()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
