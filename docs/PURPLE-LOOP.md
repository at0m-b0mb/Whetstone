# The closed loop — attacking, then defending

For most of this project's life the loop stopped at the finding. It enumerated a
host, proved a weakness by exploiting it, asked the control that claimed to
cover the technique whether it had seen anything, and wrote down the silence.
That is a report. This document describes the other half, which now runs: the
agent proposes a fix, the kernel applies it, **performs the original attack a
second time**, and asks the same control the same question again.

The distinction that makes it worth anything is one sentence long.

> A fix that returns success is a claim. The re-attack is the evidence.

Three `harden.*` verbs had been in the catalogue since the first commit,
implemented on Linux, macOS and Windows, and nothing had ever called one. It
would have been easy to call one, print "remediated", and be wrong in exactly
the way every security report that overstates its remediation is wrong — by
letting a command's exit status print as a statement about the world.

---

## See it run

```bash
python3 -m lab.run --cycle
```

No weights, no MLX, no download, nothing outside a temporary directory. It
builds a sandbox with four planted weaknesses, points the agent at it under an
engagement that authorises the red verbs, and narrates the whole cycle in the
order it happened:

```
-- 2. attack, and ask who saw --------------------------------------------
  attack 1 of 3 — T1574.010
    ran        exploit.service_permissions(restore=True,
               service=acme-agent) on 127.0.0.1 — succeeded
    control    detect.process_creation(image=acme-agent,
               since_seconds=300) on 127.0.0.1
               silent — the control saw nothing
    finding    GAP — exploit.service_permissions ran and
               detect.process_creation did not fire — the technique
               succeeded unobserved

-- 3. fix it, then attack again ------------------------------------------
  gap 1 of 3 — T1574.010, opened by exploit.service_permissions
    fix        harden.enable_telemetry(source=sandbox-eventlog) on
               127.0.0.1 — succeeded
    baseline   detect.process_creation(image=acme-agent,
               since_seconds=300) on 127.0.0.1
               silent — the control saw nothing
    re-attack  exploit.service_permissions(restore=True,
               service=acme-agent) on 127.0.0.1 — succeeded
    control    detect.process_creation(image=acme-agent,
               since_seconds=300) on 127.0.0.1
               fired — the control saw the technique
    verdict    GAP CLOSED
```

Related commands:

| command | what it does |
|---|---|
| `python3 -m lab.run --cycle` | the narration above, telemetry off, gaps opened and closed |
| `python3 -m lab.run --cycle --telemetry` | the same attacks against a host that was already watching — no gaps, nothing to fix |
| `python3 -m lab.run --cycle --no-remediate` | stops at the finding, the way the loop did for most of its life |
| `python3 -m lab.run` | the flat turn list, unchanged |
| `python3 -m lab.record_run --scripted --out examples/runs --name sandbox-purple-cycle` | the same run, written to the three committable artifacts |
| `whet coverage` | which red verbs a control claims to see, and which have a hardening measure at all |

`--cycle` is presentation and nothing else. It does not change what runs, does
not imply telemetry off, and does not turn remediation on — a flag that quietly
changes the run in order to make the output look better is how a demonstration
stops being a run.

---

## What the cycle actually does

Per detection gap, at most four more gated actions. All four go through
`Gate.submit`, so all four are ruled on and land in the hash-chained audit log
like anything else.

1. **The fix.** The chooser is asked first — defending is a thing a model should
   learn to do — from a candidate set pre-filtered to verbs that *declare* they
   remediate the red verb behind this gap. When it declines or has no opinion, a
   deterministic proposer takes over, which is why the whole phase is
   demonstrable with no model at all. Phase `remediate`.
2. **The control, read once, before anything else happens.** The gap's own
   original probe is not good enough for this, because the fix has run since —
   and if this is not the first gap, so have other gaps' re-attacks, all of them
   inside this probe's lookback window. If the control is *already* reporting
   activity of this kind, the reading is spoiled and the phase stops here:
   `undetermined`, and the re-attack is not run at all. Phase `verify`.
3. **The original attack, verbatim.** Same verb, same parameters. Not a fresh
   guess at what the attack was — the recorded action, replayed. Phase `verify`.
4. **The same control, asked the same question.** Same probe, aimed the same way
   from the *new* red observation, read by the same function that read it the
   first time. Phase `verify`.

Closure is the **difference between steps 2 and 4**, never step 4 on its own.
That distinction is not theoretical. `detect.persistence_change` declares no
discriminator parameter at all, so the "an unaimed hit proves nothing" guard is
empty for it by construction — and it is the declared detection for *both*
`exploit.scheduled_task` and `postex.persistence_install`, which every
production adapter implements. Without step 2, fixing the first of those two
gaps and re-attacking puts a row in the log that closes the second gap on
evidence belonging to the first, and reports a technique that was never logged
as one the control now sees. Step 2 also catches a fix that emits an event of
the kind the control reads and so manufactures its own proof.

The outcome is attached to the finding that already exists, rather than appended
as a new one. The gap is a historical fact — the technique ran and nothing saw
it — and that stays true and stays in the report whatever happened afterwards.
A second finding would either double-count the event or erase it.

### The six states, and why there are six

`closed` is the only one that means the gap is shut.

| state | what happened |
|---|---|
| `closed` | fix ran, the control read silent, attack repeated, that control then fired, and the hit was attributable |
| `ineffective` | fix ran, attack still worked, control still silent — the fix did not work |
| `undetermined` | fix ran, closure unprovable. Five routes, named in `detail` |
| `failed` | the hardening verb itself did not run. Nothing applied |
| `refused` | the gate denied the fix. Remediation is `MODIFY` and being defensive earns it nothing |
| `unavailable` | nothing was proposed: no verb claims this gap, or none could be aimed from the evidence |

A `remediation` of `None` means the gap was never *offered* a fix — the phase was
off, or the episode's budget ran out. It never means "nothing worked".

`undetermined` is the one that deserves suspicion, because it is where a
tempting lie would live. One of its five routes is *the control was already
reporting activity of this kind before the re-attack* — the spoiled baseline
above, which is the difference between proving a fix worked and noticing the log
is not empty. Another is *the re-attack no longer succeeds*: the fix removed the weakness and the technique cannot run any more.
That is a real and good outcome, and it is **not** closure. The gap was a
statement about the control, and a technique that cannot run tells you nothing
about what would have been logged if it had. Writing that as `closed` would be
the single easiest way to make this tool report holes shut that are not.

### Reading the outcome in code

```python
for f in episode.findings:
    if f.kind != "detection_gap":
        continue
    if f.remediation is None:            # never offered a fix
        ...
    elif f.remediation.proven_closed:    # gap found AND closed
        ...
    else:                                # fix attempted, gap remains
        ...                              # f.remediation.state says which
```

Never treat any state but `closed` as closure, and never derive closure from an
observation's `ok` flag. `proven_closed` exists so that the one question a report
is allowed to ask without reading prose has exactly one spelling.

---

## What is proven in the sandbox

The sandbox is a real environment, not a mock. The exploits really overwrite a
real file and really append to a real crontab; the detections really read a real
log; `harden.enable_telemetry` really flips the boolean that decides whether the
log is written, and the probes really read it back afterwards. When `--cycle`
prints `GAP CLOSED`, these things happened in this order:

- the technique ran and the log stayed empty;
- a fix changed the host's posture;
- the same query against the same log was run and still found nothing, so
  whatever comes next is the re-attack's doing and not the fix's or an earlier
  gap's;
- **the same technique ran again**;
- the same query against the same log returned a row matching that technique.

That is a real demonstration of a real closed loop, and it is reproducible on any
laptop in about a second.

## What is *not* proven in the sandbox

Five things, and they are listed here rather than in a footnote because a demo
that ends on "3 of 3 proven closed" gets read as a claim about machines.

**1. The permissions fix rests on a modelled foothold.** `harden.fix_permissions`
really chmods the file and really strips group/other write. But the sandbox
process *owns* that file, and a real chmod cannot lock out the owner — so "the
exploit now fails" is asserted by the adapter modelling a non-root attacker, not
demonstrated. The mode change is real; the consequence is modelled. Do not read
the lab's result as proof that a chmod stops a real attacker.

**2. On a real Linux host, remediation fires less often than you would expect,
and that is correct.** The commonest real blue-team failure by a distance is
auditd running with no rules loaded — a tool present and watching nothing. The
Linux adapter reports that honestly as unqueryable, `detection_fired` returns
`None`, and the kernel writes an `observation`, not a `detection_gap`. Only gaps
are remediated. So the case where switching the source on feels most obviously
right produces no remediation at all, because nothing was ever established. That
is the invariant doing its job, not the loop failing to run.

**3. macOS and Windows report `unavailable`.** Their three harden verbs are
implemented, but nothing on those platforms publishes the remediation hints that
say where to point them, so no required parameter can be filled from evidence and
nothing is proposed. Aiming a `MODIFY` at a guess is worse than a gap left open
and honestly reported. Only Linux and the lab publish hints today; adding them is
mechanical.

**4. Closure is not attributable to a single fix when several ran.** Gaps are
remediated one at a time against a host that earlier fixes already changed, and
the kernel cannot revert a real machine between gaps. The state stays `closed` —
the control demonstrably now sees the technique — and the detail says the claim
is narrower, so an operator knows to keep all of them. Per-fix attribution needs
a revert between gaps, which only the sandbox can do.

**5. It has not run against the Lima VM.** `lab/vm/adapter.py` implements no
harden verbs, so remediation on the real Ubuntu VM is always `unavailable`.
Everything above happened in a temporary directory. The attacking half has been
run against the VM and that record is in `examples/runs/vm-ubuntu-tiny-sft2.*`;
the defending half has not.

---

## The record

`python3 -m lab.record_run` writes three files, and a run that is not written
down is a demonstration rather than evidence.

- **`*.trajectory.txt`** — the wire protocol, byte for byte. Remediation turns
  are ordinary `<|act|>`/`<|obs|>` pairs and each `<|find|>` carries the
  remediation outcome, so a captured purple cycle is training data for defending
  with no conversion step. The corpus has not been rebuilt on it yet.
- **`*.transcript.md`** — the run for a human. Every turn is marked with its
  phase, so the agent's own decisions are distinguishable from the kernel's
  injected evidence; the remediation section shows each fix, its re-attack and
  the control's two answers as four steps you can check.
- **`*.findings.json`** — the machine-readable result, with `produced_by`,
  `remediation` per gap, a tally by state, and the turn counts split by phase.

Every byte of all three goes through `redact_identity()` on the way to disk and
is checked with `identity_leaks()` afterwards; a survivor raises and nothing is
written. `examples/runs/` is public, and an artifact that proves this tool works
while also publishing the maintainer's account name has proved two things. This
used to be a step somebody had to remember between capturing and committing. It
is now the write path, and there is no other one.

A worked example of the full cycle is committed at
`examples/runs/sandbox-purple-cycle.*`.

---

## What this does not do yet

**Nothing has taught a model to defend.** The chooser is asked for a fix before
the deterministic proposer is, and the trajectory format carries the remediation
turns and their outcomes — so the training data exists as a format. No corpus has
been rebuilt on it and no checkpoint has seen one. The defending in every run
described here is a deterministic proposer following declared `remediates`
edges, which is the number a trained model has to beat, exactly as
`HeuristicChooser` is for the attacking half.

**The benchmark scores only the attacking half.** `bench/agentbench.py` measures
recall, precision, ordering and cost over the verbs the agent chose. It now
correctly excludes `remediate` and `verify` turns so the kernel's re-attacks are
not counted as the agent's initiative, but it does not score defending.
`Turn.phase` and `Finding.remediation` are what that should be built on.

**No retries, and no second candidate after a refusal.** A failed fix gets one
attempt — a second identical `MODIFY` against a machine is a change nobody asked
for twice. A refused fix does not go hunting for a verb the gate will permit,
because that is how an authorisation model becomes advisory.

**`no_coverage` and `observation` findings are never remediated.** There is
nothing to re-attack into for the first and nothing established for the second.
And `postex.exfil_probe` has no fix and is meant not to: nothing in this
catalogue watches egress volume, so no hardening measure could make a declared
control fire for it. `whet coverage` lists it under NO FIX on both axes, which
is a disclosure rather than a gap.
