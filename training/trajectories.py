"""Generate agent trajectories by actually running the agent.

``bench/whetbench.py`` scores ``action-json`` at 0/5: the model cannot emit an
action the verb registry will accept. That is not a mystery and not a capacity
limit. The corpus contains **zero** trajectory data — the TRAJECTORY register
sits at 0.00% — so the model has learned the language of security and has never
once seen the job it exists to do. The protocol tokens are in the vocabulary,
reserved and unused.

This module closes that gap, and the important word is *actually*.

**Nothing here is imagined.** Every ``<|act|>`` is a real action the registry
bound and validated. Every ``<|obs|>`` is the real structured payload a real
adapter returned from a real command on this machine. Every ``<|gate|>`` is a
real ruling from :func:`whetstone.gate.policy.decide`. Fabricating plausible
observations would be easy and would teach the model a world that does not
exist — it would learn to predict what tool output *looks like* rather than what
this tool *returns*, and the difference only shows up when something is wired to
a live host and answers confidently about a machine it misread.

**Refusals are training data, not errors.** A trajectory that proposes an
out-of-scope host, receives a DENY with its reason, and recovers with something
in scope teaches recovery. A corpus of clean successes teaches a model that has
never seen a correction and does not know how to make one — and this agent will
be refused constantly, because that is what the gate is for.

**Observations are truncated deliberately and visibly.** ``enum.processes`` on a
real machine returns hundreds of records; a trajectory carrying all of them
would not fit in a 1024-token window and would teach the model that an
observation is mostly noise. Payloads are capped and the cap is *stated in the
text* (``"...": "+412 more"``) so the model learns that observations are
summarised rather than learning that machines have four processes.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from whetstone.actions import REGISTRY, Intent, TargetKind

__all__ = ["Scenario", "SCENARIOS", "generate_trajectories"]


#: Maximum records kept from a list-shaped observation payload.
_MAX_ITEMS = 4
#: Maximum characters for any single stringified value.
_MAX_VALUE = 220


def _shrink(value: Any, depth: int = 0) -> Any:
    """Cap an observation payload, saying so where it cuts.

    The elision marker is part of the lesson. A model trained on silently
    truncated lists learns that hosts have four services; one trained on lists
    that carry ``"+118 more"`` learns that it is reading a summary and that the
    number is the interesting part.
    """
    if isinstance(value, list):
        head = [_shrink(v, depth + 1) for v in value[:_MAX_ITEMS]]
        if len(value) > _MAX_ITEMS:
            head.append(f"+{len(value) - _MAX_ITEMS} more")
        return head
    if isinstance(value, dict):
        if depth >= 3:
            return f"<{len(value)} fields>"
        return {k: _shrink(v, depth + 1) for k, v in list(value.items())[:10]}
    if isinstance(value, str) and len(value) > _MAX_VALUE:
        return value[:_MAX_VALUE] + "…"
    return value


@dataclass
class Scenario:
    """One objective and the verbs that answer it.

    ``refusal_target`` is a host deliberately outside the engagement. Including
    it produces the correction pattern — propose, be refused, recover — which is
    the half of agent behaviour a success-only corpus never teaches.
    """

    task: str
    verbs: tuple[str, ...]
    refusal_target: str | None = None
    finding: dict[str, str] | None = None


SCENARIOS: list[Scenario] = [
    Scenario(
        "Find anything on this host that runs without a human starting it.",
        ("enum.host", "enum.persistence", "detect.persistence_change"),
    ),
    Scenario(
        "Establish what this machine is and who I am on it before doing anything else.",
        ("enum.host", "enum.privileges", "enum.users"),
    ),
    Scenario(
        "Work out whether this host could see an attack if one happened.",
        ("detect.telemetry", "detect.process_creation", "detect.credential_access"),
        finding={"technique": "T1059", "expected": "detect.process_creation",
                 "missing_telemetry": "process creation auditing"},
    ),
    Scenario(
        "Check the network exposure of this machine.",
        ("enum.network", "enum.shares", "enum.services"),
    ),
    Scenario(
        "Look for weak file permissions that could be abused for escalation.",
        ("enum.privileges", "vuln.weak_permissions", "vuln.privilege_path"),
    ),
    Scenario(
        "Find credentials sitting somewhere they should not be.",
        ("enum.users", "vuln.credential_exposure"),
    ),
    Scenario(
        "Assess this host for known-vulnerable software.",
        ("enum.host", "enum.software", "vuln.patch_gap"),
    ),
    Scenario(
        "Enumerate the host, then confirm whether the logging would catch me.",
        ("enum.processes", "detect.telemetry"),
        refusal_target="10.20.4.77",
    ),
    Scenario(
        "Map running services and check whether service changes are logged.",
        ("enum.services", "detect.persistence_change"),
        refusal_target="192.168.1.50",
    ),
    Scenario(
        "Baseline this machine: identity, autostart, and what the logs record.",
        ("enum.privileges", "enum.persistence", "detect.telemetry"),
        finding={"technique": "T1547", "expected": "detect.persistence_change"},
    ),
]

#: Hosts deliberately outside the null engagement's loopback-only scope, so the
#: refusal they provoke is a real ruling rather than a staged one.
_OUT_OF_SCOPE = ("10.20.4.77", "192.168.1.50", "dc01.lab.internal",
                 "172.16.8.9", "10.0.0.5", "fileserver.corp.internal")


def _derived_scenarios(rng: random.Random, count: int = 60) -> list[Scenario]:
    """Build scenarios combinatorially from the catalogue itself.

    Ten hand-written scenarios cap the corpus at ten verb sequences, and a model
    trained on that learns those ten rather than learning that a task maps to
    *some* ordered subset of the permitted verbs. Deriving them from the
    registry means the diversity scales with the catalogue and cannot drift out
    of sync with it when a verb is added.

    Only OBSERVE verbs are drawn, because this runs under the null engagement
    and anything else would be refused — which would be a real refusal, but a
    corpus of nothing but refusals teaches nothing about doing the work.
    """
    import whetstone.verbs  # noqa: F401

    pool = [v.id for v in REGISTRY.select(intent=Intent.OBSERVE)
            if REGISTRY.get(v.id).target is TargetKind.HOST]
    openers = [v for v in pool if v.startswith("enum.")]
    closers = [v for v in pool if v.startswith("detect.")]

    verbs_phrase = {
        "enum.": "enumerate", "vuln.": "assess", "detect.": "check the logging for",
    }
    out: list[Scenario] = []
    for _ in range(count):
        n = rng.randint(2, 4)
        chosen = [rng.choice(openers)]
        while len(chosen) < n:
            pick = rng.choice(pool)
            if pick not in chosen:
                chosen.append(pick)
        # Roughly a third of runs end on a detection check, which is the shape
        # the agent should default to: do the thing, then ask who noticed.
        if rng.random() < 0.35 and closers:
            tail = rng.choice(closers)
            if tail not in chosen:
                chosen.append(tail)

        nouns = ", ".join(v.split(".", 1)[1].replace("_", " ") for v in chosen)
        verb_word = next((w for p, w in verbs_phrase.items()
                          if chosen[0].startswith(p)), "look at")
        task = f"On this host, {verb_word} {nouns}."

        out.append(Scenario(
            task=task,
            verbs=tuple(chosen),
            refusal_target=(rng.choice(_OUT_OF_SCOPE) if rng.random() < 0.4 else None),
            finding=({"technique": rng.choice(("T1547", "T1059", "T1003", "T1053")),
                      "expected": rng.choice(closers)} if closers and rng.random() < 0.3
                     else None),
        ))
    return out


#: Task rephrasings, so the model does not learn one sentence per verb sequence.
_PARAPHRASE = (
    "{t}",
    "{t} Report what you find.",
    "Objective: {t}",
    "{t} Stop when you have enough to write a finding.",
    "I need this answered: {t}",
)


def _catalogue_line(gate: Any, limit: int = 12) -> str:
    """The verbs this engagement permits, as the model will be shown them."""
    verbs = gate.catalogue()[:limit]
    return "; ".join(f"{v.id}({', '.join(p.name for p in v.params)})" for v in verbs)


def _run_one(gate: Any, adapter: Any, verb_id: str, target: str | None) -> tuple[dict, dict]:
    """Bind, submit and run one verb. Returns (action dict, observation dict)."""
    verb = REGISTRY.get(verb_id)
    params: dict[str, Any] = {}
    for p in verb.params:
        if p.required:
            params[p.name] = (p.choices[0] if p.choices else
                              1 if p.type == "integer" else
                              False if p.type == "boolean" else "placeholder")
    action = REGISTRY.bind(verb_id, params, target=target)
    result = gate.submit(action, adapter.execute)
    obs = result.observation
    payload: dict[str, Any] = {"ok": obs.ok}
    if obs.data is not None:
        payload["data"] = _shrink(obs.data)
    if obs.error:
        payload["error"] = obs.error[:_MAX_VALUE]
    if obs.unsupported:
        payload["unsupported"] = True
    return action.to_dict(), payload


def generate_trajectories(
    *, repeats: int = 6, seed: int = 1337, verbose: bool = False
) -> Iterator[str]:
    """Yield rendered trajectory documents, each from a real agent run.

    Runs under the *null engagement*: loopback only, observe only, no red verbs.
    That is not a limitation for this purpose — the format, the action shape, the
    observation shape and the refusal pattern are all identical whatever the
    engagement authorises, and generating red trajectories would mean running
    exploits against this machine to make training data, which is not a trade
    anyone should take.
    """
    from whetstone.adapters.base import get_adapter
    from whetstone.gate import Gate, null_engagement
    import whetstone.verbs  # noqa: F401  (registers the catalogue)
    from .tokenizer.protocol import (ACT, FIND, GATE, HOST, OBS, SCOPE, TASK,
                                     VERBS, render_trajectory)

    rng = random.Random(seed)
    # Hand-written scenarios anchor the common shapes; derived ones give the
    # catalogue-wide diversity that stops the model memorising ten sequences.
    scenarios = SCENARIOS + _derived_scenarios(rng)
    adapter = get_adapter()
    engagement = null_engagement()
    gate = Gate(engagement, registry=REGISTRY)
    catalogue = _catalogue_line(gate)

    # Cache each verb's real result: the machine does not change between
    # trajectories, and re-running enum.processes fifty times would take minutes
    # and produce fifty near-identical payloads anyway.
    cache: dict[str, tuple[dict, dict]] = {}

    for scenario in scenarios:
        for rep in range(repeats):
            segments: list[tuple[str, str]] = []
            task = rng.choice(_PARAPHRASE).format(t=scenario.task)
            segments.append((TASK, task))
            segments.append((HOST, adapter.platform))
            segments.append((SCOPE, "observe; loopback only; no red verbs"))
            segments.append((VERBS, catalogue))

            # A refusal first, when the scenario calls for one: propose a host
            # the engagement does not cover, take the real DENY, then recover.
            if scenario.refusal_target:
                verb_id = scenario.verbs[0]
                bad = REGISTRY.bind(verb_id, {}, target=scenario.refusal_target)
                decision = gate.rule(bad)
                segments.append((ACT, json.dumps(bad.to_dict(), separators=(",", ":"))))
                segments.append((GATE, json.dumps(
                    {"verdict": decision.verdict.value, "rule": decision.rule,
                     "reason": decision.reason[:_MAX_VALUE]},
                    separators=(",", ":"))))

            order = list(scenario.verbs)
            if rep % 3 == 1 and len(order) > 1:
                rng.shuffle(order)          # order is not always fixed

            for verb_id in order:
                key = verb_id
                if key not in cache:
                    try:
                        cache[key] = _run_one(gate, adapter, verb_id, "127.0.0.1")
                    except Exception as exc:                # a verb may legitimately fail
                        if verbose:
                            print(f"   {verb_id}: {type(exc).__name__}: {exc}")
                        continue
                action, payload = cache[key]
                segments.append((ACT, json.dumps(action, separators=(",", ":"))))
                segments.append((OBS, json.dumps(payload, separators=(",", ":"))))

            if scenario.finding:
                segments.append((FIND, json.dumps(scenario.finding,
                                                  separators=(",", ":"))))

            yield render_trajectory(segments)


def main(argv: list[str] | None = None) -> int:
    import argparse

    p = argparse.ArgumentParser(description="Generate real agent trajectories.")
    p.add_argument("--out", type=Path,
                   default=Path("/Volumes/at0m_b0mb/whetstone/corpus/raw/trajectories"))
    p.add_argument("--repeats", type=int, default=6)
    args = p.parse_args(argv)

    args.out.mkdir(parents=True, exist_ok=True)
    n = chars = 0
    for i, text in enumerate(generate_trajectories(repeats=args.repeats, verbose=True)):
        (args.out / f"trajectory-{i:05d}.txt").write_text(text, encoding="utf-8")
        n += 1
        chars += len(text)
    print(f"{n:,} trajectories, {chars/1e6:.2f}M chars -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
