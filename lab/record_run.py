"""Produce the committed example artifacts from a real run.

    python -m lab.record_run --scripted --name sandbox-purple-cycle
    python -m lab.record_run --checkpoint <ckpt> --tokenizer <tok> --out examples/runs

Runs the agent against the sandbox with telemetry off, so the gaps show, and
lets the remediation phase close them — then captures the three artifacts. The
transcript records, for each turn, the verbs the model ranked below the one it
chose, so the record shows the model's judgement rather than only its output.

Two drivers, and both produce the same artifacts.

``--checkpoint`` is the one this file was written for: a trained model driving
the loop under constrained decoding, which is the capture worth publishing
because it is a record of what the model does rather than of what the lab can
do. It needs MLX and the weights.

``--scripted`` drives the identical loop with :class:`~lab.run.ScriptedSweep`
and needs neither. That matters more than convenience. The remediation phase's
deterministic proposer has no model behind it either, so a scripted capture is a
complete, honest record of the full purple cycle — attack, silence, gap, fix,
re-attack, closure — that anyone can reproduce on a laptop with no weights, no
GPU and no download. What it is *not* is evidence about the model's judgement:
the plan is a list a human wrote, and a capture made this way says so in its
header rather than leaving the reader to infer it from the driver line.

Everything written goes through the redaction in :mod:`lab.capture`, which
refuses rather than degrades. ``examples/runs/`` is public.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

import whetstone.verbs  # noqa: F401  (registers the catalogue)
from whetstone.actions import REGISTRY
from whetstone.gate import Gate, always_confirm
from whetstone.kernel import Kernel

from .adapter import SandboxAdapter
from .capture import CaptureMeta, capture
from .run import ScriptedSweep, _engagement
from .target import SandboxTarget


class RecordingChooser:
    """Wraps a chooser and records each decision's runner-up choices.

    A thin decorator, so the recording is honest: it captures exactly what the
    wrapped chooser decided, adding nothing and changing nothing about the run.

    It sees only ``plan`` turns. The kernel injects its probes, fixes and
    re-attacks without consulting a chooser, so no decision is recorded for
    them — which is correct, because there was none to record. The turn index it
    stores is ``len(episode.turns)`` at the moment of choosing, and that stays
    the index of the turn about to be appended however many the kernel has
    injected in between.
    """

    def __init__(self, inner) -> None:
        self.inner = inner
        self.decisions: list[dict] = []
        self._turn = 0

    def choose(self, episode, permitted, *, exclude, target):
        # Reconstruct the ranking the model saw, to record the runners-up.
        alternatives: list[str] = []
        if hasattr(self.inner, "model"):
            from training.constrained import rank_verbs
            from whetstone.kernel.render import render_prompt
            done = {t.action.verb_id for t in episode.turns} | set(exclude)
            pool = [v for v in permitted if v.id not in done]
            if pool:
                ranked = rank_verbs(self.inner.model, self.inner.tok,
                                    render_prompt(episode), pool)
                alternatives = [v.id for v, _s in ranked]

        action = self.inner.choose(episode, permitted, exclude=exclude, target=target)
        if action is not None:
            chosen = action.verb_id
            self.decisions.append({
                "turn": len(episode.turns),
                "chosen": chosen,
                "alternatives": [a for a in alternatives if a != chosen],
            })
        return action


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Capture a real run to artifacts.")
    p.add_argument("--checkpoint", type=Path,
                   help="drive the loop with a trained model (needs MLX)")
    p.add_argument("--tokenizer", type=Path,
                   help="tokenizer for --checkpoint")
    p.add_argument("--scripted", action="store_true",
                   help="drive the loop with the scripted sweep instead — no "
                        "model, no MLX, reproducible anywhere")
    p.add_argument("--out", type=Path, default=Path("examples/runs"))
    p.add_argument("--name", default="sandbox-model-run")
    p.add_argument("--max-turns", type=int, default=18)
    p.add_argument("--no-remediate", dest="remediate", action="store_false",
                   help="capture only the attacking half, the way this file "
                        "did before the remediation phase existed")
    args = p.parse_args(argv)

    if bool(args.checkpoint) == bool(args.scripted):
        # Refused rather than defaulted. A capture's header names its driver and
        # the artifact is published as evidence; picking one silently would put
        # "scripted" on a file somebody meant to be a model run, or the reverse.
        p.error("pass exactly one of --checkpoint or --scripted")
    if args.checkpoint and not args.tokenizer:
        p.error("--checkpoint needs --tokenizer")

    if args.scripted:
        inner = ScriptedSweep()
        checkpoint = "none — scripted sweep, no model in this run"
        driver = "scripted sweep (a fixed plan, not a model's judgement)"
    else:
        from training.agent import load_chooser

        inner = load_chooser(args.checkpoint, args.tokenizer, verbose=True)
        # The step, so the artifact names its exact model rather than a
        # directory that will be overwritten by the next run.
        import json as _json
        step = _json.loads((args.checkpoint / "state.json").read_text())["step"]
        checkpoint = f"{args.checkpoint.name} (step {step})"
        driver = "trained model (constrained decoding)"

    chooser = RecordingChooser(inner)

    with SandboxTarget(telemetry=False) as target:
        print(target.summary())
        print("\n== capturing a real run ==\n")
        gate = Gate(_engagement(str(target.root)), registry=REGISTRY,
                    confirmer=always_confirm)
        episode = Kernel(gate, SandboxAdapter(target), chooser,
                         max_turns=args.max_turns,
                         remediate=args.remediate).run(
            "Assess this host, prove what you find, and tell me what nobody saw.",
            target="127.0.0.1")

        meta = CaptureMeta(
            checkpoint=checkpoint,
            target="sandbox (self-contained, telemetry off)",
            telemetry="disabled",
            timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            driver=driver,
            remediation=("on — each gap gets a fix, the control read silent, "
                         "the original attack again, and the same control "
                         "re-asked; closure is the difference between the two "
                         "readings"
                         if args.remediate else "off"))
        paths = capture(episode, meta, args.out, args.name,
                        decisions=chooser.decisions)

    print("\n" + episode.summary())
    print("\nwrote:")
    for kind, path in paths.items():
        print(f"  {kind:<12} {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
