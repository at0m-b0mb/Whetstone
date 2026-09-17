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


def _vm(argv, **kw):
    return subprocess.run(["limactl", "shell", "--workdir", "/", _VM, "--", *argv],
                          env={**os.environ, "LIMA_HOME": _LIMA_HOME},
                          capture_output=True, text=True, **kw)


def arm_auditd() -> None:
    """Load an execve audit rule, so the blue side actually watches."""
    from .adapter import AUDIT_KEY
    _vm(["sudo", "auditctl", "-w", "/opt/acme/acme-agent", "-p", "wa",
         "-k", AUDIT_KEY])
    print(f"armed auditd: file-modification watch on /opt/acme/acme-agent "
          f"(key={AUDIT_KEY})\n")


def disarm_auditd() -> None:
    _vm(["sudo", "auditctl", "-D"])


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
    # Start each exercise with a clean audit log. The log persists across runs,
    # so a stale record from a previous exercise would otherwise be counted as
    # this run's exploit being seen — a false negative on the gap. Truncating is
    # correct for a disposable lab: each exercise gets fresh telemetry.
    _vm(["sudo", "truncate", "-s", "0", "/var/log/audit/audit.log"])
    if args.arm:
        arm_auditd()

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
