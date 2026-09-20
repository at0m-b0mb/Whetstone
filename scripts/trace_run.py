#!/usr/bin/env python3
"""Watch the agent think, decide and act — a glass box over the real loop.

    python3 scripts/trace_run.py                       # trained model drives
    python3 scripts/trace_run.py --scripted            # no model needed
    python3 scripts/trace_run.py --telemetry           # the blue side is watching

The ordinary runners print what the agent DID. This prints why. For each turn:

  * the exact prompt text handed to the model, in the wire protocol it was
    trained on — not a paraphrase of it, the bytes;
  * every permitted verb with the model's score, so the choice is visible as a
    ranking rather than an announcement, and the runner-up gap shows whether it
    was confident or nearly tossed a coin;
  * the gate's ruling, by rule id, including the refusals;
  * what the adapter actually did — the argv where a command is run, the file
    operation where one is not;
  * the observation that came back, which becomes the next prompt's context.

It wraps the real Kernel, real Gate and real adapter rather than reimplementing
the loop. A trace of a simplified copy would be a trace of something nobody
runs, and the details worth seeing — a refusal changing the next choice, an
observation shrinking to fit the context — only exist in the real thing.

Nothing here touches the host: the sandbox is a temp directory that is reverted
and deleted, and the engagement is scope-locked to it.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import whetstone.verbs  # noqa: F401  (registers the catalogue)
from whetstone.actions import REGISTRY
from whetstone.gate import Gate, always_confirm
from whetstone.kernel import Kernel

from lab.adapter import SandboxAdapter
from lab.run import _engagement
from lab.target import SandboxTarget

C = {"dim": "\033[2m", "b": "\033[1m", "g": "\033[32m", "y": "\033[33m",
     "c": "\033[36m", "r": "\033[31m", "m": "\033[35m", "blue": "\033[34m",
     "x": "\033[0m"}
W = 78


def rule(title: str = "", colour: str = "dim") -> None:
    if title:
        pad = "─" * max(0, W - len(title) - 4)
        print(f"{C[colour]}── {C['b']}{title}{C['x']}{C[colour]} {pad}{C['x']}")
    else:
        print(f"{C['dim']}{'─' * W}{C['x']}")


def block(text: str, colour: str = "dim", indent: str = "   ") -> None:
    for line in text.splitlines():
        print(f"{indent}{C[colour]}{line}{C['x']}")


class TracingChooser:
    """Prints the prompt and the full ranking, then delegates unchanged.

    A decorator rather than a fork of the chooser: what is printed is exactly
    what the wrapped chooser saw and returned, so the trace cannot drift from
    the behaviour it claims to explain.
    """

    def __init__(self, inner, *, prompt_chars: int) -> None:
        self.inner = inner
        self.prompt_chars = prompt_chars
        self.turn = 0

    def choose(self, episode, permitted, *, exclude, target):
        self.turn += 1
        print()
        rule(f"TURN {self.turn}", "c")

        done = {t.action.verb_id for t in episode.turns} | set(exclude)
        pool = [v for v in permitted if v.id not in done]

        # 1. what the model is actually given
        if hasattr(self.inner, "model"):
            from whetstone.kernel.render import render_prompt

            prompt = render_prompt(episode)
            shown = prompt[-self.prompt_chars:]
            elided = len(prompt) - len(shown)
            print(f"\n {C['b']}PROMPT → MODEL{C['x']}  "
                  f"{C['dim']}({len(prompt):,} chars"
                  + (f", showing last {self.prompt_chars}" if elided else "")
                  + f"){C['x']}")
            if elided:
                print(f"   {C['dim']}… {elided:,} earlier chars elided …{C['x']}")
            block(shown, "blue")

        # 2. how it ranked the options
        action = None
        if hasattr(self.inner, "model") and pool:
            from training.constrained import rank_verbs
            from whetstone.kernel.render import render_prompt

            ranked = rank_verbs(self.inner.model, self.inner.tok,
                                render_prompt(episode), pool)
            print(f"\n {C['b']}MODEL RANKING{C['x']}  "
                  f"{C['dim']}{len(pool)} verbs permitted and not yet run, "
                  f"scored by sequence log-probability{C['x']}")
            top = ranked[:6]
            for i, (verb, score) in enumerate(top):
                mark = f"  {C['g']}← chooses{C['x']}" if i == 0 else ""
                side = {"red": C["r"], "blue": C["c"]}.get(verb.side.value, C["dim"])
                print(f"   {score:9.3f}  {side}{verb.id:<30}{C['x']}"
                      f"{C['dim']}{verb.side.value:<8}{C['x']}{mark}")
            if len(ranked) > len(top):
                print(f"   {C['dim']}… {len(ranked) - len(top)} lower-ranked "
                      f"verbs not shown{C['x']}")
            if len(ranked) >= 2:
                margin = ranked[0][1] - ranked[1][1]
                confidence = ("decisive" if margin > 2 else
                              "clear" if margin > 0.5 else "narrow — near a coin toss")
                print(f"   {C['dim']}margin over runner-up: "
                      f"{margin:.3f} nats — {confidence}{C['x']}")

        action = self.inner.choose(episode, permitted, exclude=exclude, target=target)

        if action is None:
            print(f"\n {C['y']}chooser returned None — nothing left to do{C['x']}")
            return None

        verb = REGISTRY.get(action.verb_id)
        side = {"red": C["r"], "blue": C["c"]}.get(verb.side.value, C["dim"])
        print(f"\n {C['b']}ACTION{C['x']}   {side}{C['b']}{action.render()}{C['x']}")
        print(f"   {C['dim']}{verb.side.value} · {verb.intent.name} · "
              f"ATT&CK {', '.join(verb.attck) or '—'}{C['x']}")
        if verb.detected_by:
            print(f"   {C['dim']}declares it should be caught by: "
                  f"{', '.join(verb.detected_by)}{C['x']}")
        return action


class TracingGate(Gate):
    """The real gate, printing its ruling and what the adapter then did."""

    def __init__(self, *a, payload_chars: int = 420, **kw) -> None:
        super().__init__(*a, **kw)
        self.payload_chars = payload_chars

    def submit(self, action, executor, *, now=None):
        traced = _TracingExecutor(executor, self.payload_chars)
        try:
            result = super().submit(action, traced, now=now)
        except Exception as exc:
            # A refusal is an ordinary outcome here, not an error: the loop
            # feeds it back to the model as a correction. Printing it in place
            # is the whole reason to watch — a refusal visibly changes the next
            # ranking, and that is the gate teaching the agent.
            print(f"\n {C['b']}GATE{C['x']}     {C['r']}REFUSED{C['x']}  "
                  f"{C['dim']}{type(exc).__name__}{C['x']}")
            block(str(exc), "r")
            raise
        decision = getattr(result, "decision", None)
        if decision is not None:
            verdict = decision.verdict.name
            colour = {"ALLOW": "g", "CONFIRM": "y"}.get(verdict, "r")
            print(f"\n {C['b']}GATE{C['x']}     {C[colour]}{verdict}{C['x']}  "
                  f"{C['dim']}[{decision.rule}]{C['x']}")
        return result


class _TracingExecutor:
    """Prints what the adapter really did, then the observation it returned.

    Callable rather than an object with ``.execute``: the kernel hands the gate
    ``self.executor.execute``, a bound method, so what arrives here is a plain
    callable and the wrapper has to be one too.
    """

    def __init__(self, inner, payload_chars: int) -> None:
        self.inner = inner
        self.payload_chars = payload_chars

    def __call__(self, verb, action):
        obs = self.inner(verb, action)

        commands = []
        for key in ("commands", "argv", "ran"):
            got = (obs.data or {}).get(key) if isinstance(obs.data, dict) else None
            if got:
                commands = got if isinstance(got, list) else [got]
                break
        if commands:
            print(f"\n {C['b']}RAN{C['x']}")
            for c in commands[:6]:
                block(" ".join(c) if isinstance(c, list) else str(c), "y")
        else:
            print(f"\n {C['b']}RAN{C['x']}      {C['dim']}in-process against the "
                  f"sandbox tree — no external command for this verb{C['x']}")

        status = (f"{C['g']}ok{C['x']}" if obs.ok else
                  f"{C['y']}unsupported{C['x']}" if obs.unsupported else
                  f"{C['r']}failed{C['x']}")
        print(f"\n {C['b']}OBSERVATION{C['x']}  {status}"
              f"{C['dim']}  ({obs.duration_ms} ms){C['x']}")
        if obs.error:
            block(obs.error, "r")
        if obs.data is not None:
            from whetstone.kernel.render import shrink_payload

            text = json.dumps(shrink_payload(obs.data), indent=2)
            if len(text) > self.payload_chars:
                text = text[:self.payload_chars] + "\n…"
            block(text, "dim")
        return obs


def main(argv: list[str] | None = None) -> int:
    D = Path("/Volumes/at0m_b0mb/whetstone")
    p = argparse.ArgumentParser(description="Watch the agent think and act.")
    p.add_argument("--model", type=Path,
                   default=D / "models/checkpoints-v5/small/best")
    p.add_argument("--tokenizer", type=Path,
                   default=D / "models/tokenizer-v5/tokenizer.json")
    p.add_argument("--scripted", action="store_true",
                   help="drive with the fixed sweep instead of a model")
    p.add_argument("--telemetry", action="store_true",
                   help="the sandbox logs events, so the detections fire")
    p.add_argument("--vm", action="store_true",
                   help="drive the REAL Lima Ubuntu VM instead of the sandbox — "
                        "the exploit really overwrites a root-owned binary and "
                        "auditd is really asked whether it saw")
    p.add_argument("--arm", action="store_true",
                   help="with --vm: load the auditd watch first, so the blue "
                        "side is actually watching")
    p.add_argument("--max-turns", type=int, default=20)
    p.add_argument("--prompt-chars", type=int, default=900)
    args = p.parse_args(argv)

    if args.scripted:
        from lab.run import ScriptedSweep
        inner, driver = ScriptedSweep(), "scripted sweep (no model)"
    else:
        from training.agent import load_chooser
        inner = load_chooser(args.model, args.tokenizer, verbose=False)
        driver = f"model at {args.model.name}"

    print()
    rule("WHETSTONE — the loop, traced", "c")
    print(f"   driver     {C['b']}{driver}{C['x']}")

    if args.vm:
        # The real thing: an Ubuntu guest over SSH, where the exploit overwrites
        # a genuinely root-owned binary and the detection genuinely reads
        # auditd. Nothing here is the sandbox's in-process imitation.
        from lab.vm.adapter import VMAdapter
        from lab.vm.run import _engagement as _vm_engagement
        from lab.vm.run import arm_auditd, disarm_auditd, _vm as _vm_shell

        print(f"   target     {C['b']}real Lima Ubuntu VM (whetstone-lab){C['x']}")
        print(f"   auditd     {C['b']}"
              f"{'ARMED — a file watch is loaded' if args.arm else 'no rules loaded — the common real-world state'}{C['x']}")
        adapter = VMAdapter()
        disarm_auditd()
        # The audit log persists across runs, so a stale record from an earlier
        # exercise would be counted as this run's exploit being seen — a false
        # negative on the gap, which is the one error this must not make.
        _vm_shell(["sudo", "truncate", "-s", "0", "/var/log/audit/audit.log"])
        if args.arm:
            arm_auditd()

        gate = TracingGate(_vm_engagement(), registry=REGISTRY,
                           confirmer=always_confirm)
        chooser = TracingChooser(inner, prompt_chars=args.prompt_chars)
        episode = Kernel(gate, adapter, chooser, max_turns=args.max_turns).run(
            "Assess this Ubuntu host, prove the writable-service finding, and "
            "tell me whether auditd saw it.", target="127.0.0.1")
        disarm_auditd()

        print()
        rule("EPISODE", "c")
        print()
        block(episode.summary(), "dim", indent="   ")
        for f in episode.findings:
            head = {"detection_gap": f"{C['r']}DETECTION GAP{C['x']}",
                    "no_coverage": f"{C['y']}NO COVERAGE{C['x']}",
                    "observation": f"{C['y']}INCONCLUSIVE{C['x']}"}.get(f.kind, f.kind)
            print(f"\n   {head}  {C['b']}{f.technique}{C['x']}")
            print(f"      {C['dim']}{f.detail}{C['x']}")
        print()
        return 0

    print(f"   telemetry  {C['b']}{'ON — blue is watching' if args.telemetry else 'OFF — nothing is logging'}{C['x']}")

    with SandboxTarget(telemetry=args.telemetry) as target:
        print(f"   target     {C['dim']}{target.root}{C['x']}")
        print()
        block(target.summary(), "dim", indent="   ")

        gate = TracingGate(_engagement(str(target.root)), registry=REGISTRY,
                           confirmer=always_confirm)
        chooser = TracingChooser(inner, prompt_chars=args.prompt_chars)
        episode = Kernel(gate, SandboxAdapter(target), chooser,
                         max_turns=args.max_turns).run(
            "Assess this host, prove what you find, and tell me what nobody saw.",
            target="127.0.0.1")

        print()
        rule("EPISODE", "c")
        print()
        block(episode.summary(), "dim", indent="   ")
        if episode.findings:
            print()
            for f in episode.findings:
                head = {"detection_gap": f"{C['r']}DETECTION GAP{C['x']}",
                        "no_coverage": f"{C['y']}NO COVERAGE{C['x']}",
                        "observation": f"{C['y']}INCONCLUSIVE{C['x']}"}.get(
                            f.kind, f.kind)
                print(f"   {head}  {C['b']}{f.technique}{C['x']}")
                print(f"      {C['dim']}{f.detail}{C['x']}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
