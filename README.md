# Whetstone

**A purple-team agent runtime, and a small cybersecurity model trained from scratch to drive it.**

A whetstone does not cut anything. It exists so the blade does its job better, and
it is useless on its own. That is the argument for the red half of this project:
the attack side is here to sharpen the defence, and nothing in it is built to be
pointed at someone who has not asked for it.

---

## What this is

Two things that depend on each other in one direction only.

**The runtime** (`whetstone/`) is a cross-platform agent that enumerates a machine,
finds weaknesses, proves them by exploitation, and then asks whether anything
noticed. It is model-agnostic — it works today with any backend, and it would still
work if the model half of this repo were deleted.

**The model** (`training/`) is a small language model pretrained from scratch — not
fine-tuned from someone else's weights — on a security corpus, to drive that
runtime. It depends on the runtime, because the runtime defines the action space it
learns to produce and generates the trajectories it learns from.

The dependency runs one way on purpose. You cannot know what to train until you can
measure, and you cannot measure until the harness exists.

---

## The one idea

Every offensive verb declares the detection that should catch it.

```python
_v(
    id="postex.credential_dump",
    intent=Intent.EXECUTE,
    side=Side.RED,
    attck=("T1003",),
    detected_by=("detect.credential_access",),   # ← this
)
```

The agent runs the attack, then runs the detection, then compares. **Caught** is a
control working. **Silence** is a detection gap — a finding that names the
technique, the host, and the telemetry that was missing.

This is not documentation, it is a schema field the constructor enforces: a red verb
that declares no `detected_by` raises at import time. If the honest answer is that
nothing covers the technique, you write `detect.nothing` and it shows up in
`whet coverage` as a gap on the blue backlog. Silence by omission is not available.

The exploit is not the deliverable. The gap it reveals is. `report.detection_gap`
is the highest-value artefact this tool produces, because "there is a hole" gets
triaged into next quarter and "there is a hole, and nobody would have known" gets
fixed on Monday.

It is also the cleanest training signal in the system. *Did rule X fire within N
seconds of technique Y?* is a mechanically checkable fact, not a judge model's
opinion — so trajectories get labelled correct or incorrect with no human in the
loop. Most domains would kill for a verifier this good.

---

## Autonomy and authorisation are different axes

The common objection to a gate is that it makes the agent stop and ask permission.
It does not. It defines the walls inside which it never has to.

```yaml
authorize:
  red_team: true
  max_intent: execute
  techniques: [T1547, T1053, T1003, T1574.010]
  unattended: [observe, modify, execute]   # ← the autonomy dial
```

With `execute` in `unattended`, the agent enumerates, finds the weakness, exploits
it, escalates, pivots and reports **without pausing once**. That is the autonomy
axis, fully open.

What it still cannot do is touch a host nobody authorised. That is the other axis,
and it is what makes the tool deployable at all.

```
$ whet -e engagement.yaml plan exploit.scheduled_task 10.20.4.77
ALLOW   exploit.scheduled_task(as_user=SYSTEM, cleanup=True) on 10.20.4.77
        rule: intent.unattended
        after this runs, the agent checks: detect.persistence_change, detect.process_creation

$ whet -e engagement.yaml plan exploit.scheduled_task 10.20.4.50
DENY    exploit.scheduled_task(as_user=SYSTEM, cleanup=True) on 10.20.4.50
        rule: scope.host.excluded
        10.20.4.50 is explicitly excluded by the rule '10.20.4.50'.
        An exclusion beats any range that would otherwise cover it.
```

**A denial has no override.** Nowhere in this package does a function take `force=`
or `--yes-really`, and a test asserts that mechanically across the public API. If
the scope is wrong, the fix is to edit the engagement document — which is a file, in
git, with an author and a timestamp. A flag leaves no evidence; a diff does.

---

## Why a closed verb catalogue

The obvious shortcut is one verb taking an arbitrary command string. It would
collapse `whetstone/verbs.py` into four lines and destroy every property that makes
the project work.

- **The gate could no longer reason about what it is approving**, because the meaning
  would be inside an opaque string.
- **The model would have to generate correct PowerShell, bash and zsh** instead of
  choosing a concept. `enum.persistence` means the same thing on all three operating
  systems; the Windows adapter knows it is a registry-plus-scheduled-task-plus-service
  sweep, Linux knows it is cron and systemd units, macOS knows it is launchd plists.
  The model learns the question once, not three dialects — the single largest capacity
  saving available at this model size.
- **The detection pairing would be impossible**, since it depends on knowing which
  technique is being performed.

The catalogue is more work and it is the entire design. A test asserts no such verb
ever gets added.

---

## About "from scratch"

This is a genuine from-random-init pretrain, not a fine-tune. That decision was made
with the numbers in front of us, and the numbers are worth stating plainly.

Training FLOPs ≈ `6 · N · D`. A 100M-parameter model on 2B tokens is ~1.2×10¹⁸ FLOPs
— **four to five days** of sustained GPU on an M4 Pro. Feasible. It checkpoints and
resumes. We climb a staircase — **15M → 60M → 150M** — because nobody should debug a
pipeline on a four-day run.

**What a 150M model can do**, given the design above: route a task, choose a verb,
fill its parameters, read the result, decide the next step. That is a narrow, closed
distribution, and narrow closed distributions are learnable at this scale.

**What it cannot do**: discover novel vulnerability classes. Fuzzing, memory-safety
reasoning and logic-flaw hunting are hard for frontier models and impossible here.
Whetstone finds *known* weaknesses and misconfigurations and chains them — which is
what most of a real engagement consists of — and it does not pretend otherwise.

Four things buy back the capacity a from-scratch model gives up:

| Lever | Why it matters |
|---|---|
| Domain tokenizer | Generic BPE spends 6 tokens on `Get-WmiObject`; a security BPE spends 2 |
| Closed action space | Picking one of ~200 verb ids is classification, not free generation |
| Retrieval for facts | The model never memorises a CVE or an ATT&CK description |
| Adapters for syntax | Concepts live in weights, dialects live in code |

The corpus is weighted toward offence, roughly 60/40. This is not a preference, it is
an allocation argument: blue knowledge — Sigma rules, log schemas, control catalogues
— is highly retrievable, while red judgement ("what do I try next from this foothold")
is sequential decision-making that retrieval cannot supply. Spend the weights on what
retrieval cannot do. An attacker-strong model also produces *better* blue output here
by construction, because you cannot write a detection for a technique you cannot
perform.

---

## Status

Phase 0. The spine is built and tested; the rest is scaffolded and empty.

| | |
|---|---|
| ✅ Action schema, verb catalogue, detection pairing | `whetstone/actions.py`, `verbs.py` |
| ✅ The gate — engagement, policy, hash-chained audit | `whetstone/gate/` |
| ✅ CLI — `verbs`, `coverage`, `check`, `plan`, `audit` | `whetstone/cli.py` |
| ✅ 66 tests, whole safety surface, no lab required | `tests/` |
| ⬜ Platform adapters (Windows / Linux / macOS) | `whetstone/adapters/` |
| ⬜ Agent loop with self-correction | `whetstone/kernel/` |
| ⬜ MCP + HTTP surfaces | `whetstone/surfaces/` |
| ⬜ Lab, verifiers, `whetstone-bench` | `lab/`, `bench/` |
| ⬜ Tokenizer → corpus → pretrain → SFT | `training/` |

The gate is a pure function of `(engagement, verb, action, clock)` — it touches no
files, opens no sockets and runs no commands. The entire safety surface is therefore
tested on a laptop with no lab, no VM and no target, in 50 milliseconds. That was the
point of the design and `tests/test_gate.py` is the payoff.

---

## Try it

```bash
python3 -m whetstone.cli verbs --side red
python3 -m whetstone.cli coverage
python3 -m whetstone.cli -e examples/engagement.yaml check
python3 -m whetstone.cli -e examples/engagement.yaml plan postex.credential_dump 10.20.4.77
```

---

## Scope of use

Whetstone runs against systems you are authorised to test, and the engagement
document is where that authorisation is written down. It is not covert, it does not
hide itself, and every decision it makes — including every refusal — lands in a
hash-chained log that an operator can hand to whoever asks.

MIT licensed.
