# Roadmap

Written from measurements, not ambition. Every item below exists because
something was measured and found wanting, and each names the number it is meant
to move.

---

## Where it actually stands

**Working and verified.** 30 of 32 verbs on Windows, Linux and macOS; the gate
is a pure function with no override and 175 tests over it; a 13-source corpus
with every licence checked at source; a tokenizer that beats gpt2 by 29% on
held-out text with every register winning; a from-scratch model that learned the
CVE schema in 500 steps.

**The honest scoreboard** at 14.6M parameters, after pretraining and SFT:

| probe | score | reading |
|---|:--:|---|
| `shell-routing` | 10/10 | stays in register when prompted |
| `detection-routing` | 10/10 | continues a Sigma rule as a Sigma rule |
| `cwe-shape` | 10/10 | real weakness ids, contextually apt |
| `action-json` | **valid by construction** | constrained decoding; was 5/10 free |
| `verb-choice` | **3/8** | **judgement — the real number now** |
| `cvss-vector` | 3/5 → 0/10 under SFT | capacity conflict |
| `attck-real` | 0/10 | never moved |

`verb-choice` is the number that matters from here. Constrained decoding made
syntax a solved problem, which finally separates *can it write an action* from
*does it pick a sensible one*. Only the second is a training problem, and only
the second is worth optimising.

---

## What is genuinely blocking, in order

### 1. The agent loop does not exist

`whetstone/kernel/` is empty. Without it there is no plan-act-observe-critique
cycle, so trajectories are **scripted verb sequences rather than decisions**. The
model is trained to imitate a list someone else wrote, which teaches format and
cannot teach choosing.

It is also what makes the detection pairing operational. `detected_by` is
declared on every red verb and enforced at import, but nothing yet *runs the
detection after the exploit and writes the gap*. The single most valuable
artefact this project claims to produce is not yet produced by anything.

**Moves:** `verb-choice`, and it creates the loop that feeds everything else.

### 2. Trajectories come from one machine

Every observation in the trajectory corpus is from this Mac. The model is
learning *this host's* service list, not how to read a service list. Regenerate
on another machine and the text changes completely — which is the correct
behaviour for real observations and a generalisation problem for training data.

**Moves:** `verb-choice` on unseen hosts, which is the only number that matters
for a tool pointed at someone else's network. Needs the lab (item 4).

### 3. The starved registers

| register | share | target | gap |
|---|--:|--:|--|
| shell | 15.6% | 26% | needs ~2× |
| trajectory | 3.4% | 8% | needs ~2.5×, blocked on items 1 and 4 |
| adversary | 9.0% | 11% | close |
| prose | 6.0% | 9% | close |

`attck-real` has never moved off 0/10, and ADVERSARY being under target is the
likely reason. Collection targets, best value first: Elastic detection-rules and
Wazuh/Suricata/Zeek for DETECTION; `ss64`, busybox and coreutils usage text for
SHELL; permissively-licensed threat-intel writeups for ADVERSARY.

### 4. No lab

The SSD has ~900 GB free and there is nothing on it. A Windows VM and a Linux VM
with Sysmon, auditd and a Sigma pipeline would make three things real at once:
multi-platform trajectories, red verbs that can actually be exercised end to end,
and **the detection verifier** — *did rule X fire within N seconds of technique
Y*. That last one is the mechanically checkable ground truth this whole project
is built around, and it currently has nowhere to run.

### 5. The corpus caps model size

30.6M tokens after balancing. `small` is training at ~4 tokens/parameter against
Chinchilla's 20 — undertrained on purpose, because the alternative was eight
epochs of repetition. `base` at 151M would need 3B tokens and would see the
corpus a hundred times.

**`base` should not be attempted until the corpus is roughly 10× larger.** A
bigger model on a corpus this size memorises it; that is not a capability gain,
it is an expensive way to build a lookup table.

---

## The plan

### Now — the agent loop
Build `whetstone/kernel/`: plan → decode (constrained) → gate → adapter →
observe → critique → retry, bounded. Wire the detection pairing so every red
action is followed by its `detected_by` checks and silence becomes a
`report.detection_gap`. Regenerate trajectories from *real loop decisions*
rather than scripts.

**Done when** trajectories contain decisions the loop made and recovered from,
and `verb-choice` is measured on loop-generated data.

### Next — the lab
Two VMs on the SSD with real telemetry. Then the verifier works, red verbs can
be exercised for real, and trajectories stop being single-host.

**Done when** `bench` can report *technique ran, rule fired* as an observed fact
on a machine that is not this laptop.

### Then — corpus to ~300M tokens
Collection focused on SHELL, DETECTION and ADVERSARY. The register report is
already the shopping list and updates itself on every build.

**Done when** no register sits below 60% of its target.

### Then — `small` properly, and `base` if warranted
`small` re-run at a real token budget on the larger corpus. `base` only if
`small`'s `verb-choice` improvement over `tiny` justifies the week.

### Throughout — keep the instruments honest
Three measurement bugs have pointed at the model so far and all three were mine:
a validation split that was 100% Sigma rules; a non-greedy regex that truncated
valid JSON and reported it as malformed; length normalisation that compressed a
3.9-nat ranking signal into 0.16 nats of noise. In every case the code was
working and the ruler was bent.

**Check the instrument before believing the result** is the most expensive lesson
this project has taught, and it is worth paying attention to rather than
learning a fourth time.

---

## What this will not become

It will not discover novel vulnerabilities. No fuzzing, no memory-safety
reasoning, no logic-flaw hunting — those are hard for frontier models and out of
reach at 151M parameters. Whetstone finds *known* weaknesses and misconfigurations
and chains them, which is what most of a real engagement consists of.

It will not act outside an engagement, and no amount of capability changes that.
The gate is a pure function with no override, and a denial is the end of the
conversation.
