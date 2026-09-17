"""Produce the committed example artifacts from a real model-driven run.

    python -m lab.record_run --checkpoint <ckpt> --tokenizer <tok> --out examples/runs

Runs the trained model against the sandbox (telemetry off, so the gaps show)
and captures the three artifacts. The transcript records, for each turn, the
verbs the model ranked below the one it chose, so the record shows the model's
judgement rather than only its output.
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
from .run import _engagement
from .target import SandboxTarget


class RecordingChooser:
    """Wraps a chooser and records each decision's runner-up choices.

    A thin decorator, so the recording is honest: it captures exactly what the
    wrapped chooser decided, adding nothing and changing nothing about the run.
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
    p = argparse.ArgumentParser(description="Capture a real model run to artifacts.")
    p.add_argument("--checkpoint", type=Path, required=True)
    p.add_argument("--tokenizer", type=Path, required=True)
    p.add_argument("--out", type=Path, default=Path("examples/runs"))
    p.add_argument("--name", default="sandbox-model-run")
    p.add_argument("--max-turns", type=int, default=18)
    args = p.parse_args(argv)

    from training.agent import load_chooser

    inner = load_chooser(args.checkpoint, args.tokenizer, verbose=True)
    chooser = RecordingChooser(inner)

    with SandboxTarget(telemetry=False) as target:
        print(target.summary())
        print("\n== capturing a real run ==\n")
        gate = Gate(_engagement(str(target.root)), registry=REGISTRY,
                    confirmer=always_confirm)
        episode = Kernel(gate, SandboxAdapter(target), chooser,
                         max_turns=args.max_turns).run(
            "Assess this host, prove what you find, and tell me what nobody saw.",
            target="127.0.0.1")

        # Checkpoint step for the header, so the artifact names its exact model.
        import json as _json
        step = _json.loads((args.checkpoint / "state.json").read_text())["step"]
        meta = CaptureMeta(
            checkpoint=f"{args.checkpoint.name} (step {step})",
            target="sandbox (self-contained, telemetry off)",
            telemetry="disabled",
            timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            driver="trained model (constrained decoding)")
        paths = capture(episode, meta, args.out, args.name,
                        decisions=chooser.decisions)

    print("\n" + episode.summary())
    print("\nwrote:")
    for kind, path in paths.items():
        print(f"  {kind:<12} {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
