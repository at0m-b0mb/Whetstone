# Whetstone run — sandbox (self-contained, telemetry off)

> A real run, captured verbatim. The observations are what the adapter
> returned from the actual target; nothing here is illustrative.
>
> **Host identity is substituted.** The account name reads `operator` and the
> per-user temp directory reads `/tmp`, because this repository is public.
> Nothing else is edited — see [`README.md`](README.md).

| | |
|---|---|
| driver | trained model (constrained decoding) |
| checkpoint | `tiny-sft2 (step 5699)` |
| target | sandbox (self-contained, telemetry off) |
| telemetry | disabled |
| captured | 2026-09-17T20:52:53+00:00 |

**Task** — Assess this host, prove what you find, and tell me what nobody saw.

**Result** — 18 turns, 18 observations, 0 refusals, **3 findings**.

---

## The run, turn by turn

### 1. `enum.privileges() on 127.0.0.1` — ok
*model chose this over: `enum.host`, `detect.persistence_change`, `enum.services`*

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

### 2. `detect.persistence_change(since_seconds=300) on 127.0.0.1` — ok
*model chose this over: `enum.host`, `enum.services`, `detect.credential_access`*

```json
{
  "logged": false,
  "count": 0,
  "events": []
}
```

### 3. `detect.credential_access(since_seconds=300) on 127.0.0.1` — ok
*model chose this over: `vuln.patch_gap`, `enum.services`, `enum.host`*

```json
{
  "logged": false,
  "count": 0,
  "events": []
}
```

### 4. `enum.services() on 127.0.0.1` — ok
*model chose this over: `vuln.patch_gap`, `detect.process_creation`, `detect.telemetry`*

```json
{
  "services": [
    {
      "name": "acme-agent",
      "path": "/tmp/whetstone-lab-8c2owhk1/opt/acme/acme-agent",
      "runs_as": "root",
      "mode": "0o777"
    }
  ]
}
```

### 5. `vuln.patch_gap(min_severity=medium) on 127.0.0.1` — ok
*model chose this over: `detect.process_creation`, `vuln.credential_exposure`, `detect.telemetry`*

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

### 6. `detect.process_creation(since_seconds=300) on 127.0.0.1` — ok
*model chose this over: `vuln.credential_exposure`, `enum.host`, `detect.telemetry`*

```json
{
  "logged": false,
  "count": 0,
  "events": []
}
```

### 7. `detect.telemetry() on 127.0.0.1` — ok
*model chose this over: `vuln.credential_exposure`, `enum.host`, `enum.persistence`*

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

### 8. `vuln.credential_exposure() on 127.0.0.1` — ok
*model chose this over: `enum.host`, `enum.software`, `enum.persistence`*

```json
{
  "findings": [
    {
      "path": "/tmp/whetstone-lab-8c2owhk1/etc/acme.conf",
      "line": "password = hunter2-do-not-ship",
      "technique": "T1552.001"
    }
  ]
}
```

### 9. `enum.host() on 127.0.0.1` — ok
*model chose this over: `enum.persistence`, `enum.software`, `vuln.weak_permissions`*

```json
{
  "os": "sandbox-linux",
  "hostname": "acme-lab",
  "root": "/tmp/whetstone-lab-8c2owhk1",
  "kernel": "6.1.0-lab"
}
```

### 10. `enum.persistence() on 127.0.0.1` — ok
*model chose this over: `enum.software`, `vuln.weak_permissions`, `exploit.service_permissions`*

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

### 11. `enum.software() on 127.0.0.1` — ok
*model chose this over: `vuln.weak_permissions`, `exploit.service_permissions`, `postex.persistence_install`*

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

### 12. `vuln.weak_permissions() on 127.0.0.1` — ok
*model chose this over: `exploit.service_permissions`, `postex.credential_dump`, `postex.persistence_install`*

```json
{
  "findings": [
    {
      "path": "/tmp/whetstone-lab-8c2owhk1/opt/acme/acme-agent",
      "mode": "0o777",
      "runs_as": "root",
      "technique": "T1574.010",
      "why": "writable binary executed by a root service"
    }
  ]
}
```

### 13. `exploit.service_permissions(restore=True, service=unset) on 127.0.0.1` — ok
*model chose this over: `postex.credential_dump`, `postex.persistence_install`*

```json
{
  "changed": "/tmp/whetstone-lab-8c2owhk1/opt/acme/acme-agent",
  "bytes_written": 59,
  "ran_as": "root",
  "cleanup": "succeeded",
  "telemetry_written": false
}
```

### 14. `detect.process_creation(since_seconds=300) on 127.0.0.1` — ok

```json
{
  "logged": false,
  "count": 0,
  "events": []
}
```

### 15. `postex.credential_dump(redact=True) on 127.0.0.1` — ok
*model chose this over: `postex.persistence_install`*

```json
{
  "source": "/tmp/whetstone-lab-8c2owhk1/etc/acme.conf",
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

### 16. `detect.credential_access(since_seconds=300) on 127.0.0.1` — ok

```json
{
  "logged": false,
  "count": 0,
  "events": []
}
```

### 17. `postex.persistence_install(cleanup=True, mechanism=service) on 127.0.0.1` — ok

```json
{
  "installed_in": "/tmp/whetstone-lab-8c2owhk1/etc/crontab",
  "entry": "@reboot root /tmp/.whetstone-marker  # whetstone persistence test",
  "cleanup": "succeeded",
  "telemetry_written": false
}
```

### 18. `detect.persistence_change(since_seconds=300) on 127.0.0.1` — ok

```json
{
  "logged": false,
  "count": 0,
  "events": []
}
```

---

## Findings

- **🔴 DETECTION GAP** — `T1574.010` — exploit.service_permissions ran and detect.process_creation did not fire — the technique succeeded unobserved
- **🔴 DETECTION GAP** — `T1003` — postex.credential_dump ran and detect.credential_access did not fire — the technique succeeded unobserved
- **🔴 DETECTION GAP** — `T1547.001, T1543` — postex.persistence_install ran and detect.persistence_change did not fire — the technique succeeded unobserved

---

*Generated by `lab/capture.py`. Reproduce with the command in the run's header comment.*
