# Whetstone run — sandbox (self-contained, telemetry off)

> A real run, captured verbatim. The observations are what the adapter
> returned from the actual target; nothing here is illustrative.

| | |
|---|---|
| driver | trained model (constrained decoding) |
| checkpoint | `small-sft (step 13134)` |
| target | sandbox (self-contained, telemetry off) |
| telemetry | disabled |
| remediation | on — each gap gets a fix, the original attack again, and the same control re-asked |
| captured | 2026-09-19T22:45:46+00:00 |

**Task** — Assess this host, prove what you find, and tell me what nobody saw.

**Result** — 15 action(s) the agent chose, plus 3 detection probe(s), 3 fix(es) and 6 verification turn(s) injected by the kernel. 24 observations, 1 refusals, **3 findings**.

---

## The run, turn by turn

### 1. `enum.host() on 127.0.0.1` — ok
*model chose this over: `enum.services`, `enum.software`, `enum.privileges`*

```json
{
  "os": "sandbox-linux",
  "hostname": "acme-lab",
  "root": "/tmp/whetstone-lab-ceqtugb5",
  "kernel": "6.1.0-lab"
}
```

### 2. `vuln.weak_permissions() on 127.0.0.1` — ok
*model chose this over: `vuln.patch_gap`, `vuln.credential_exposure`, `postex.credential_dump`*

```json
{
  "findings": [
    {
      "path": "/tmp/whetstone-lab-ceqtugb5/opt/acme/acme-agent",
      "mode": "0o777",
      "runs_as": "root",
      "technique": "T1574.010",
      "why": "writable binary executed by a root service"
    }
  ]
}
```

### 3. `exploit.service_permissions(restore=True, service=unset) on 127.0.0.1` — ok
*model chose this over: `postex.credential_dump`, `vuln.credential_exposure`, `enum.services`*

```json
{
  "changed": "/tmp/whetstone-lab-ceqtugb5/opt/acme/acme-agent",
  "bytes_written": 59,
  "ran_as": "root",
  "cleanup": "succeeded",
  "telemetry_written": false,
  "image": "acme-agent",
  "remediation": {
    "harden.fix_permissions": {
      "path": "/tmp/whetstone-lab-ceqtugb5/opt/acme/acme-agent"
    }
  }
}
```

### 4. `detect.process_creation(image=acme-agent, since_seconds=300) on 127.0.0.1` — ok · _kernel probe_

```json
{
  "logged": false,
  "count": 0,
  "matched_image": "acme-agent",
  "events": [],
  "remediation": {
    "harden.enable_telemetry": {
      "source": "sandbox-eventlog"
    }
  }
}
```

### 5. `detect.telemetry() on 127.0.0.1` — ok
*model chose this over: `enum.services`, `vuln.patch_gap`, `vuln.credential_exposure`*

```json
{
  "sources": [
    {
      "source": "sandbox-eventlog",
      "enabled": false,
      "records_process_creation": false
    }
  ],
  "process_creation_auditing": false,
  "summary": "telemetry is DISABLED on this host; nothing is recorded, so no attack would be seen"
}
```

### 6. `postex.credential_dump(redact=True) on 127.0.0.1` — ok
*model chose this over: `postex.persistence_install`, `vuln.patch_gap`, `vuln.credential_exposure`*

```json
{
  "source": "/tmp/whetstone-lab-ceqtugb5/etc/acme.conf",
  "secrets_found": 1,
  "accounts": [
    "db"
  ],
  "values": [
    "<redacted>"
  ],
  "redacted": true
}
```

### 7. `detect.credential_access(since_seconds=300) on 127.0.0.1` — ok · _kernel probe_

```json
{
  "logged": false,
  "count": 0,
  "events": [],
  "remediation": {
    "harden.enable_telemetry": {
      "source": "sandbox-eventlog"
    }
  }
}
```

### 8. `vuln.patch_gap(min_severity=medium) on 127.0.0.1` — ok
*model chose this over: `enum.services`, `vuln.credential_exposure`, `enum.software`*

```json
{
  "findings": [
    {
      "package": "openssl",
      "installed": "1.0.1",
      "min_safe": "3.0.0",
      "technique": "T1203"
    },
    {
      "package": "sudo",
      "installed": "1.8.2",
      "min_safe": "1.9.5",
      "technique": "T1203"
    }
  ]
}
```

### 9. `enum.services() on 127.0.0.1` — ok
*model chose this over: `enum.privileges`, `vuln.credential_exposure`, `enum.persistence`*

```json
{
  "services": [
    {
      "name": "acme-agent",
      "path": "/tmp/whetstone-lab-ceqtugb5/opt/acme/acme-agent",
      "runs_as": "root",
      "mode": "0o777"
    }
  ]
}
```

### 10. `vuln.credential_exposure() on 127.0.0.1` — ok
*model chose this over: `enum.privileges`, `enum.software`, `enum.persistence`*

```json
{
  "findings": [
    {
      "path": "/tmp/whetstone-lab-ceqtugb5/etc/acme.conf",
      "line": 3,
      "kind": "password_assignment",
      "value": "***redacted***",
      "technique": "T1552.001"
    }
  ]
}
```

### 11. `enum.software() on 127.0.0.1` — ok
*model chose this over: `enum.privileges`, `enum.persistence`, `postex.persistence_install`*

```json
{
  "packages": [
    {
      "name": "openssl",
      "version": "1.0.1"
    },
    {
      "name": "sudo",
      "version": "1.8.2"
    },
    {
      "name": "acme-agent",
      "version": "2.1.0"
    }
  ]
}
```

### 12. `enum.privileges() on 127.0.0.1` — ok
*model chose this over: `enum.persistence`, `postex.persistence_install`, `harden.enable_telemetry`*

```json
{
  "user": "operator",
  "uid": 1000,
  "is_admin": false,
  "sudo": [
    "/opt/acme/acme-agent"
  ],
  "note": "non-root foothold"
}
```

### 13. `enum.persistence() on 127.0.0.1` — ok
*model chose this over: `postex.persistence_install`, `harden.remove_persistence`, `harden.enable_telemetry`*

```json
{
  "autostart": [
    {
      "source": "crontab",
      "entry": "@reboot root /opt/acme/acme-agent"
    }
  ]
}
```

### 14. `postex.persistence_install(cleanup=True, mechanism=cron) on 127.0.0.1` — ok
*model chose this over: `harden.enable_telemetry`, `harden.remove_persistence`, `harden.fix_permissions`*

```json
{
  "installed_in": "/tmp/whetstone-lab-ceqtugb5/etc/crontab",
  "entry": "@reboot root /tmp/.whetstone-marker  # whetstone persistence test",
  "cleanup": "succeeded",
  "telemetry_written": false
}
```

### 15. `detect.persistence_change(since_seconds=300) on 127.0.0.1` — ok · _kernel probe_

```json
{
  "logged": false,
  "count": 0,
  "events": [],
  "remediation": {
    "harden.enable_telemetry": {
      "source": "sandbox-eventlog"
    }
  }
}
```

### 16. `harden.remove_persistence(entry=unset) on 127.0.0.1` — failed
*model chose this over: `harden.enable_telemetry`, `harden.fix_permissions`*
### 17. `harden.enable_telemetry(source=unset) on 127.0.0.1` — failed
*model chose this over: `harden.fix_permissions`*

_unsupported: this sandbox has one telemetry source, 'sandbox-eventlog'; 'unset' is not something it can turn on. Enabling a source that does not exist would report success and change nothing._

### 18. `harden.fix_permissions(path=unset) on 127.0.0.1` — REFUSED

```
scope.path.unlisted: parameter 'path': unset is outside the engagement's path scope (/tmp/whetstone-lab-ceqtugb5). Paths are compared after resolution, so a symlink out of the tree does not bring the target back in.
```

### 19. `harden.enable_telemetry(source=sandbox-eventlog) on 127.0.0.1` — ok · _kernel fix_

```json
{
  "source": "sandbox-eventlog",
  "enabled": true,
  "changed": true,
  "was_already_on": false,
  "restore_hint": "SandboxTarget.set_telemetry(False), or revert()"
}
```

### 20. `exploit.service_permissions(restore=True, service=unset) on 127.0.0.1` — ok · _kernel evidence_

```json
{
  "changed": "/tmp/whetstone-lab-ceqtugb5/opt/acme/acme-agent",
  "bytes_written": 59,
  "ran_as": "root",
  "cleanup": "succeeded",
  "telemetry_written": true,
  "image": "acme-agent",
  "remediation": {
    "harden.fix_permissions": {
      "path": "/tmp/whetstone-lab-ceqtugb5/opt/acme/acme-agent"
    }
  }
}
```

### 21. `detect.process_creation(image=acme-agent, since_seconds=300) on 127.0.0.1` — ok · _kernel evidence_

```json
{
  "logged": true,
  "count": 1,
  "matched_image": "acme-agent",
  "events": [
    "acme-agent binary replaced and would run as root"
  ]
}
```

### 22. `harden.enable_telemetry(source=sandbox-eventlog) on 127.0.0.1` — ok · _kernel fix_

```json
{
  "source": "sandbox-eventlog",
  "enabled": true,
  "changed": false,
  "was_already_on": true,
  "restore_hint": "SandboxTarget.set_telemetry(False), or revert()"
}
```

### 23. `postex.credential_dump(redact=True) on 127.0.0.1` — ok · _kernel evidence_

```json
{
  "source": "/tmp/whetstone-lab-ceqtugb5/etc/acme.conf",
  "secrets_found": 1,
  "accounts": [
    "db"
  ],
  "values": [
    "<redacted>"
  ],
  "redacted": true
}
```

### 24. `detect.credential_access(since_seconds=300) on 127.0.0.1` — ok · _kernel evidence_

```json
{
  "logged": true,
  "count": 1,
  "events": [
    "acme.conf read for stored credentials"
  ]
}
```

### 25. `harden.enable_telemetry(source=sandbox-eventlog) on 127.0.0.1` — ok · _kernel fix_

```json
{
  "source": "sandbox-eventlog",
  "enabled": true,
  "changed": false,
  "was_already_on": true,
  "restore_hint": "SandboxTarget.set_telemetry(False), or revert()"
}
```

### 26. `postex.persistence_install(cleanup=True, mechanism=cron) on 127.0.0.1` — ok · _kernel evidence_

```json
{
  "installed_in": "/tmp/whetstone-lab-ceqtugb5/etc/crontab",
  "entry": "@reboot root /tmp/.whetstone-marker  # whetstone persistence test",
  "cleanup": "succeeded",
  "telemetry_written": true
}
```

### 27. `detect.persistence_change(since_seconds=300) on 127.0.0.1` — ok · _kernel evidence_

```json
{
  "logged": true,
  "count": 1,
  "events": [
    "new @reboot crontab entry installed"
  ]
}
```

---

## Findings

- **🔴 DETECTION GAP** — `T1574.010` — exploit.service_permissions ran and detect.process_creation did not fire — the technique succeeded unobserved
- **🔴 DETECTION GAP** — `T1003` — postex.credential_dump ran and detect.credential_access did not fire — the technique succeeded unobserved
- **🔴 DETECTION GAP** — `T1547.001, T1543` — postex.persistence_install ran and detect.persistence_change did not fire — the technique succeeded unobserved

---

## Remediation — what was fixed, and what proved it

A hardening verb returning `ok` has said only that a command exited
zero. Under each fix below is the **original attack repeated
verbatim** — same verb, same parameters — and the **same control asked
the same question a second time**. That answer is the evidence, and
`closed` is the only state that means the gap is shut.

**3 of 3 gap(s) proven closed.**

| gap | technique | fix | state |
|---|---|---|---|
| 1 | `T1574.010` | `harden.enable_telemetry` | `closed` |
| 2 | `T1003` | `harden.enable_telemetry` | `closed` |
| 3 | `T1547.001, T1543` | `harden.enable_telemetry` | `closed` |

### Gap 1 — `T1574.010`, opened by `exploit.service_permissions`

1. **fix** — `harden.enable_telemetry(source=sandbox-eventlog) on 127.0.0.1` — ok
2. **re-attack** — `exploit.service_permissions(restore=True, service=unset) on 127.0.0.1` — ok
3. **control** — `detect.process_creation(image=acme-agent, since_seconds=300) on 127.0.0.1` — **fired** — the control saw the technique

**closed** — harden.enable_telemetry ran, exploit.service_permissions was performed again, and detect.process_creation fired. The gap is shut and the proof is the second attack, not the fix's exit status

### Gap 2 — `T1003`, opened by `postex.credential_dump`

1. **fix** — `harden.enable_telemetry(source=sandbox-eventlog) on 127.0.0.1` — ok
2. **re-attack** — `postex.credential_dump(redact=True) on 127.0.0.1` — ok
3. **control** — `detect.credential_access(since_seconds=300) on 127.0.0.1` — **fired** — the control saw the technique

**closed** — harden.enable_telemetry ran, postex.credential_dump was performed again, and detect.credential_access fired. The gap is shut and the proof is the second attack, not the fix's exit status. Note that 1 earlier fix(es) in this episode had already changed this host, so the gap is proven shut but not proven shut by this fix alone — keep them all

### Gap 3 — `T1547.001, T1543`, opened by `postex.persistence_install`

1. **fix** — `harden.enable_telemetry(source=sandbox-eventlog) on 127.0.0.1` — ok
2. **re-attack** — `postex.persistence_install(cleanup=True, mechanism=cron) on 127.0.0.1` — ok
3. **control** — `detect.persistence_change(since_seconds=300) on 127.0.0.1` — **fired** — the control saw the technique

**closed** — harden.enable_telemetry ran, postex.persistence_install was performed again, and detect.persistence_change fired. The gap is shut and the proof is the second attack, not the fix's exit status. Note that 2 earlier fix(es) in this episode had already changed this host, so the gap is proven shut but not proven shut by this fix alone — keep them all

---

*Generated by `lab/capture.py`. Reproduce with the command in the run's header comment.*
