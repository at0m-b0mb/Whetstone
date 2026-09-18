# Overnight run v5 — the corpus was the ceiling

Written before the run, so the predictions can be marked honestly afterwards.

## Why this run exists

`tiny` (14.6M) trained fine and then stopped improving. The diagnosis was not
the model: it was that the corpus held **30.6M tokens**, and a 61.5M-parameter
model wants roughly 1.2B. Every run was therefore either undertrained or was
repeating the same text — `small`'s first attempt was scheduled for **8 epochs**
over the same 30M tokens, which is a memorisation exercise wearing a training
run's clothes.

So this run grows the data first and trains second.

## Baseline to beat — `tiny-sft2`, corpus v4

| probe | score | reading |
|---|---|---|
| `cwe-shape` | 5/5 | solid |
| `shell-routing` | 5/5 | register routing works |
| `detection-routing` | 5/5 | register routing works |
| `action-json` | 4/5 | the task itself, nearly there |
| `verb-choice` | 3/8 | judgement — the honest weak point |
| `cve-shape` | 1/5 | |
| `cvss-vector` | 0/5 | lost to SFT; a measured capacity trade at 14.6M |
| `attck-real` | 0/5 | **never had the data** |

`attck-real` at 0/5 was the clue worth chasing. The model could not emit a real
ATT&CK technique id because ATT&CK was **1.8% of the corpus** — and that turned
out to be a bug, not a budget: two of the three matrices were never downloaded,
only `attack-pattern` objects were emitted, and the adapter never took a
relationship hop, so threat groups and mitigations were absent **entirely**.

## What changed

**Sources added or expanded** (each verified independently before the build):

| source | register | what it brings |
|---|---|---|
| `attack` (expanded) | adversary | 846 → 1,606 docs, 2.7M → 7.6M chars; groups 0 → 171, mitigations 0 → 108 |
| `ghsa` | advisory | 14,509 advisories, 32.4M chars — real CVSS vectors and CVE aliases |
| `elastic` | detection | 2,247 production SIEM rules, EQL/KQL, 14.3M chars |
| `cwe` | advisory | 1,413 docs; 13,342 CWE and 6,302 CVE references |
| `nuclei` | detection | active vulnerability checks, raw HTTP transcripts |
| `lolbas` / `gtfobins` | shell | Windows and Unix living-off-the-land tradecraft |
| `metasploit` / `payloads` | adversary | how exploitation actually proceeds, in order |
| `yara` / `netrules` | detection | file and network detection — surfaces nothing else covers |
| `cisa` | advisory | incident narratives: attack, telemetry, mitigation in one document |
| `powershell` / `shellscripts` / `pythoncode` | shell / system | **real code**, not documentation about code |
| `windocs` | system | the Windows security model, to balance 34% Linux kernel docs |
| `rfc` | system | 9,825 documents that were silently absent from v4 |

`rfc` is worth a note: it was never broken. It yields 9,825 documents and
contributed zero to v4 only because its fetch takes over eight minutes and the
build never completed it. Nothing reported this, which is why import and fetch
failures are now re-listed *after* the balance report — a source missing from
that report looks identical to a source that contributed nothing.

## Two pretraining bugs found while preparing this run

Both would have wasted the night, and both hide behind a falling loss curve.

1. **The sampler restarted on resume.** Weights and optimizer were restored;
   the data position was not. A run resumed at step 1,000 re-served the batches
   steps 0–1,000 had already consumed. Loss keeps falling, because re-learning
   old data does lower loss.
2. **The run discarded its best model.** `tiny` reached val ppl **11.0** and was
   saved at **13.9** — 26% worse — because only the last checkpoint was kept.

That is now four measurement or plumbing bugs on this project, every one of
which initially looked like a fact about the model. The instrument gets checked
first.

## Predictions

Recorded in advance so they can be wrong in public:

- `attck-real` moves off 0/5. This is the most confident prediction — the data
  simply was not there before and now it is.
- `cve-shape` and `cvss-vector` improve, from GHSA's real advisories.
- `verb-choice` is the one to watch. It is judgement, not recall, and it is the
  honest test of whether more capacity and more data produce a better *agent*
  rather than a better autocomplete. It may not move, and if it does not, that
  is the finding.
- The run is **budget-bound, not Chinchilla-bound**: `small` at 20 tokens per
  parameter is 18,765 steps ≈ 36.7 hours. One night buys a fraction of that, so
  the model will be undertrained by design and should be read that way.
