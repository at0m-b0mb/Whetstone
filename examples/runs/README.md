# Example runs — the model, on the record

These are **real, captured runs**. Nothing here is illustrative or
hand-written. The observations are what the adapters actually returned from the
actual targets, at the timestamp in each file's header. Regenerate them on a
different machine and the observations change, because they are observations.

**One thing is edited, and naming it is the whole point of this paragraph.**
Before these files were committed, the machine's identity was substituted out of
them: the operator's account name became `operator`, and the macOS per-user temp
directory the sandbox was built under — `/var/folders/<two>/<28 characters>/T`,
which is a stable identifier for one particular Mac and incidentally gives away
that a host labelled `sandbox-linux` is not Linux — became `/tmp`. Nothing else
was touched. The services, the permissions, the package versions, the auditd
state, the model's rankings and every finding are exactly what the run produced.
This repository is public, and a proof of work that also publishes the
maintainer's local account name is proof of something else as well.

The substitution is `redact_identity()` in
[`training/trajectories.py`](../../training/trajectories.py) — the same function
that strips identity out of the training corpus, so there is one definition of
what counts as identity rather than one per artifact. A re-capture has to run
its three files through it before they are committed, and `identity_leaks()` in
the same module is the check that says whether it did. The uid is left alone on
purpose: `501` on a Linux VM says the VM is Lima on a Mac, which the target line
at the top of the transcript already says in words, and it names nobody.

Each run produces three files:

| file | what it is |
|---|---|
| `*.transcript.md` | the run for a human — every action, the real observation it returned, and the findings, with the verbs the model ranked *below* the one it chose |
| `*.findings.json` | the machine-readable result — the detection gaps and what produced them |
| `*.trajectory.txt` | the wire protocol, byte for byte — the exact format the model trains on, so this doubles as a worked training example |

---

## What's here

### `sandbox-tiny-sft2.*` — the trained model vs the self-contained sandbox

The 14.6M `tiny-sft2` checkpoint drives the full purple loop against a
disposable sandbox with planted weaknesses: it enumerates, assesses, exploits
all three, and the kernel pairs each exploit with the detection that should have
caught it. With the sandbox's telemetry switch **off**, the result is **three
detection gaps** — the attacks succeeded and nothing logged them.

### `vm-ubuntu-tiny-sft2.*` — the trained model vs a real Ubuntu VM

The same model, driving the loop against an actual Ubuntu 24.04 VM over SSH. The
`enum.host` observation is the real kernel string; the exploit really overwrote a
root-owned binary on the VM; the detection really queried auditd. auditd was
running with **no rules loaded** — the single most common real-world blue-team
failure, a tool present and watching nothing — so the overwrite went unseen and
became a **detection gap** on a real operating system.

---

## How to read a transcript

Every action line names what the model chose *over*:

```
### 6. `enum.services() on 127.0.0.1` — ok
*model chose this over: `vuln.weak_permissions`, `vuln.credential_exposure`, `exploit.service_permissions`*
```

That line is the model's judgement, made legible. The action itself is **valid by
construction** — constrained decoding means the model picks from the permitted
verb set, so a run never contains a hallucinated verb or malformed JSON. What
the ranking shows is *which* valid verb the model preferred, given everything it
had seen so far.

The findings distinguish three states, and the distinction matters:

- 🔴 **detection gap** — the technique ran and the control saw nothing. Actionable.
- ⚪ **no coverage** — the technique ran and nothing in the catalogue covers it. A disclosure, not a gap.
- 🟡 **inconclusive** — the detection query itself failed, so nothing can be said about the control. Never counted as a gap.

---

## Honest limitations, visible in the files

The exploit lines read `service=unset`. That is not a bug hidden — it is
[documented in `training/constrained.py`](../../training/constrained.py):
constrained decoding solves verb choice and enum/boolean parameters exactly, but
a required *free-string* parameter (a service name, a path) has to be read from
an observation the model already saw, which is open generation and a harder
problem. It is filled with a visible placeholder rather than a plausible-but-wrong
guess. The lab adapters key off the target, so the loop runs; a real arbitrary
target would need the model to fill it.

And the model's *judgement* is that of a 14.6M network trained on scripted
trajectories: it explores more than an expert would before it exploits. Making
that judgement genuinely good is what the larger `small` and `base` models, and
training on real loop-generated trajectories, are for. These runs are the honest
current state, captured so the progress is measurable.

---

## Reproduce

`data/` is the symlink at the repository root that points at wherever this
project's weights, corpus and VM images live — an NVMe volume here, whatever you
set up there. Written that way rather than as the absolute path this run used,
because the absolute path is one more machine identifier and it is not yours.

```bash
export LIMA_HOME="$PWD/data/lab/lima"
CK=data/models/checkpoints-v3/tiny-sft2
TOK=data/models/tokenizer-v1/tokenizer.json

python3 -m lab.record_run --checkpoint "$CK" --tokenizer "$TOK" \
    --out examples/runs --name sandbox-tiny-sft2
```
