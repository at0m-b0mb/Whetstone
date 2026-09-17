"""Run the full purple loop against the sandbox — the thing you can test now.

    python -m lab.run                 # telemetry off: watch the gap appear
    python -m lab.run --telemetry     # telemetry on: watch it close
    python -m lab.run --both          # both, side by side

This is the end-to-end demonstration. It builds a real sandbox with planted
weaknesses, points the agent at it under an engagement that authorises the red
verbs, and lets the kernel run: enumerate, find the weakness, prove it by
exploiting it, then check whether anything saw. With telemetry off the exploit
succeeds unobserved and a detection gap is produced; with telemetry on the same
exploit is caught and no gap appears. Same attack, different blue posture — which
is the whole thesis, made runnable.

Nothing here touches the host. Every file the exploits write is under the
sandbox root and reverted on teardown; the agent is scope-locked to the sandbox
by the engagement.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone

import whetstone.verbs  # noqa: F401  (registers the catalogue)
from whetstone.actions import REGISTRY
from whetstone.gate import Gate, always_confirm
from whetstone.gate.engagement import Authorization, Engagement, Scope
from whetstone.kernel import HeuristicChooser, Kernel

from .adapter import SandboxAdapter
from .target import SandboxTarget

# A chooser that runs a full purple sweep: look, assess, exploit, and the
# kernel pairs each exploit with its detection automatically.
# (verb, extra params). Required parameters a real model would fill from an
# observation are supplied explicitly here so the demo is deterministic — the
# scripted sweep is a stand-in for a chooser, not a model.
_PLAN = (
    ("enum.host", {}), ("enum.privileges", {}), ("enum.services", {}),
    ("enum.persistence", {}), ("enum.software", {}),
    ("vuln.weak_permissions", {}), ("vuln.credential_exposure", {}),
    ("vuln.patch_gap", {}), ("detect.telemetry", {}),
    ("exploit.service_permissions", {"service": "acme-agent"}),
    ("postex.credential_dump", {"redact": True}),
    ("postex.persistence_install", {"mechanism": "cron"}),
)


class ScriptedSweep:
    """Plays a fixed purple sequence, skipping anything refused or already run.

    This is the lab's stand-in for a trained model: a fixed, legible plan so the
    demonstration is deterministic. Swap in ``ModelChooser`` (constrained
    decoding over a checkpoint) to watch a trained model drive the same loop.
    """

    def __init__(self, plan=_PLAN):
        self.plan = list(plan)

    def choose(self, task, history, permitted, *, exclude, target):
        from whetstone.actions import TargetKind
        done = {t.action.verb_id for t in history} | set(exclude)
        by_id = {v.id: v for v in permitted}
        for verb_id, extra in self.plan:
            if verb_id in done or verb_id not in by_id:
                continue
            verb = by_id[verb_id]
            params = {p.name: (p.choices[0] if p.choices else p.default)
                      for p in verb.params if p.default is not None}
            params = {k: v for k, v in params.items() if v is not None}
            params.update(extra)                       # explicit required params
            return verb.bind(params,
                             target=None if verb.target is TargetKind.NONE else target)
        return None


def _engagement(root: str) -> Engagement:
    now = datetime.now(timezone.utc)
    return Engagement(
        name="sandbox purple exercise",
        authorization="LAB — self-contained sandbox, no real host in scope",
        starts=now - timedelta(minutes=1),
        expires=now + timedelta(hours=1),
        scope=Scope(paths=(root,), allow_loopback=True),
        authorize=Authorization(
            red_team=True, max_intent=__import__(
                "whetstone.actions", fromlist=["Intent"]).Intent.EXECUTE,
            techniques=("T1574", "T1003", "T1547", "T1543", "T1053", "T1041"),
            unattended=frozenset(__import__(
                "whetstone.actions", fromlist=["Intent"]).Intent)),
    )


def run_once(telemetry: bool) -> None:
    with SandboxTarget(telemetry=telemetry) as target:
        print("=" * 74)
        print(target.summary())
        print("=" * 74)

        gate = Gate(_engagement(str(target.root)), registry=REGISTRY,
                    confirmer=always_confirm)
        # The sandbox adapter is scope-locked by target confinement, and the
        # engagement authorises the techniques the plan uses.
        kernel = Kernel(gate, SandboxAdapter(target), ScriptedSweep(),
                        max_turns=20)
        episode = kernel.run(
            "Assess this host, prove what you find, and tell me what nobody saw.",
            target="127.0.0.1")

        print("\n" + episode.summary())

        gaps = [f for f in episode.findings if f.kind == "detection_gap"]
        print("\n" + "-" * 74)
        if telemetry:
            print(f"telemetry ON  -> {len(gaps)} detection gap(s): the blue side "
                  "saw the attacks.")
        else:
            print(f"telemetry OFF -> {len(gaps)} detection gap(s): the attacks "
                  "succeeded unobserved.")
            for g in gaps:
                print(f"    GAP  {g.technique}: {g.detail}")
        print("-" * 74)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Run the purple loop against the sandbox.")
    p.add_argument("--telemetry", action="store_true",
                   help="enable the sandbox event log (gaps close)")
    p.add_argument("--both", action="store_true",
                   help="run with telemetry off, then on, to compare")
    args = p.parse_args(argv)

    if args.both:
        print("\n### TELEMETRY OFF — the attack nobody logged\n")
        run_once(False)
        print("\n\n### TELEMETRY ON — the same attack, this time seen\n")
        run_once(True)
    else:
        run_once(args.telemetry)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
