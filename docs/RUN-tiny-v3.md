# tiny / corpus v3 — first full run

14.6M params, 138.1M-token corpus, 4,451 steps (2.1 epochs), bf16, M4 Pro.

## What it learned, at step 500

```
CVE-2024-0637
published: 2017-11-11T11:29:08.717
cvss: 9.3 HIGH
vector: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
weakness: CWE-787
```

The CVSS vector is syntactically valid — all eight metrics, correct order,
legal values. Field order matches the NVD adapter's emit format. CWE-787 is a
real identifier. From random initialisation, in 500 steps, a 14.6M model has
learned the *schema* of a vulnerability record.

## What it did not learn, and why that is the useful part

Prompted with `Get-Process` or `detection:`, it still emits CVE and CPE text.
That is not a model defect; it is the corpus composition showing up as
behaviour:

| register | share | target |
|---|---:|---:|
| advisory | 34.5% | 10% |
| system | 52.4% | 26% |
| shell | 2.7% | 28% |
| detection | 3.0% | 14% |
| adversary | 1.0% | 12% |

The model is an accurate mirror of what it was fed. `build.py`'s balance report
predicted this before training started; generation confirmed it. Also visible:
`CVE-2024-…` paired with `published: 2017-…` (no year correlation), and verbatim
`cpe:2.3:a:adobe:flash_player` strings (memorisation of a high-frequency form).

## Consequence for the staircase

Do not run `small` or `base` on this mix. A larger model trained on it becomes a
better CVE-record generator, which is not the product. The corpus needs
shell/detection/adversary volume first — those three are 6.7% of the corpus
between them and 54% of the target.

Collection shopping list, in order of value per byte:
- SHELL: more Atomic executors, ss64/SS command references, busybox/coreutils
  usage text, PowerShell gallery module docs
- DETECTION: Elastic detection-rules, Chronicle/YARA-L, Wazuh rules, Suricata
  and Zeek signature sets
- ADVERSARY: threat-intel writeups with permissive licences, MITRE Engage,
  ATT&CK groups/software/campaigns (already downloaded in the STIX bundle —
  `attack.py` currently emits only attack-pattern objects)

The last one is nearly free: the ATT&CK bundle already on disk contains
intrusion-set, malware, tool and campaign objects that the adapter does not yet
emit. That is ADVERSARY volume sitting in a file we have already fetched.
