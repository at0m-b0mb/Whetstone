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
CVE schema in 500 steps; an agent loop that finds a detection gap by exploiting
a real weakness and then **closes it by fixing the host and attacking it again**.

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

### 1. ~~The agent loop does not exist~~ — built, and it now closes

`whetstone/kernel/` runs the plan-act-observe-critique cycle, pairs every red
action with the detections it declares, and records silence as a
`detection_gap`. The single most valuable artefact this project claims to
produce is now produced by something.

It also runs the other half. For each gap the agent is offered a hardening
measure, the kernel applies it, **performs the original attack a second time**
and asks the same control the same question again — so `closed` means the
re-attack happened and the silent control spoke, not that a fix exited zero.
See [PURPLE-LOOP.md](PURPLE-LOOP.md); watch it with `python3 -m lab.run --cycle`.

**What is left of this item:** nothing has taught a *model* to defend. The
trajectory format carries remediation turns and their outcomes, so the training
data exists as a format, but no corpus has been rebuilt on it and no checkpoint
has seen one. Defending today is a deterministic proposer following declared
`remediates` edges — the number a trained model has to beat.

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

### 4. ~~No lab~~ — two of them, and the second is a real machine

The self-contained sandbox (`lab/`) builds a real tree with real planted
weaknesses and a real telemetry switch, so the detection verifier has somewhere
to run on any laptop with nothing to download. The Lima Ubuntu VM
(`python3 -m lab.vm.run --arm`) is the honest version: real auditd, real
`ausearch`, a real root-owned binary really overwritten.

**What is left of this item.** The VM exercises the *attacking* half only —
`lab/vm/adapter.py` implements no `harden.*` verbs, so remediation against it is
always `unavailable`, and every closed gap this project can currently show
happened in a temporary directory. There is still no Windows VM, so Sysmon and
the Windows adapter's detections have never been exercised end to end. And
trajectories are still overwhelmingly single-host: `--vm` is the route to real
Linux data, and the corpus has not been regenerated through it at volume.

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

### Now — teach the model to defend
The loop closes; nothing has trained on it closing. Rebuild the corpus from
loop-generated episodes that include the remediation phase, so a checkpoint sees
a fix proposed, applied, re-attacked and judged — and give `bench` a score for
the defending half, built on `Turn.phase` and `Finding.remediation`.

**Done when** a trained chooser's `remediate` beats the deterministic proposer,
measured, and the benchmark reports closures it verified against the lab's own
ground truth rather than against the loop's word for it.

### Next — remediation on a machine that is not a temp directory
`lab/vm/adapter.py` implements no `harden.*` verbs, so every proven closure so
far is a sandbox closure. Implement the three on the VM adapter and publish the
remediation hints from the macOS and Windows adapters, which is mechanical.

**Done when** `bench` can report *technique ran, nothing logged, fix applied,
technique ran again, rule fired* as an observed fact on a machine that is not
this laptop.

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
