"""NVD vulnerability records — the ADVISORY register.

Written to close a gap the balance report would otherwise have shouted about:
every other source lands in SHELL, SYSTEM, DETECTION, ADVERSARY or PROSE, so
ADVISORY was sitting at 0% against a 10% target.

It also targets a specific measured failure. In the first tokenizer comparison
``CVE-2024-21412 CVSS 8.1 SmartScreen Prompt Security Feature Bypass`` scored
**-26% against gpt2** — our tokenizer was *worse*, because gpt2 has met CVE
identifiers all over the web and ours had never seen one. The fix is not a
tokenizer change, it is this file.

The highest-value text here is the part that looks least like prose. A CVSS
vector string::

    CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H

is a dense, rigidly-structured token sequence that appears constantly in
security work and essentially never in general web text. Same for CPE match
strings and CWE identifiers. Those are precisely the sequences a domain
vocabulary should win on, so each record is emitted with its identifier, vector,
weakness and affected-configuration strings kept together.

**Licensing.** NVD data is produced by NIST, a US Government agency, and is not
subject to domestic copyright — it is free to use with attribution. See
https://nvd.nist.gov/general/FAQ-Sections/General-FAQs.

**Rate limits.** Without an API key the public endpoint allows roughly 5
requests per rolling 30 seconds. ``_fetch`` sleeps 6.5s between pages and caches
every page to disk, so a re-run costs nothing. Set ``NVD_API_KEY`` in the
environment to go faster; the code uses it if present and works fine without it.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Iterator

from ..net import NetworkError, fetch
from ..source import Document, Register, Side, SourceError, SourceSpec, normalise

_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_PAGE = 2000
#: Pages to pull by default. 20 x 2000 = 40k records, which is ample for a
#: register targeted at ~10% of the corpus and keeps a cold fetch near two
#: minutes rather than several hours.
_PAGES = int(os.environ.get("WHETSTONE_NVD_PAGES", "20"))
_SLEEP_NO_KEY = 6.5
_SLEEP_KEY = 0.8


def _fetch(cache_dir: Path) -> Path:
    """Download CVE pages into the cache. Idempotent: skips pages already there."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    delay = _SLEEP_KEY if api_key else _SLEEP_NO_KEY

    for page in range(_PAGES):
        target = cache_dir / f"page-{page:03d}.json"
        if target.exists() and target.stat().st_size > 1000:
            continue

        url = f"{_API}?resultsPerPage={_PAGE}&startIndex={page * _PAGE}"
        try:
            payload = fetch(url, timeout=90,
                            headers={"apiKey": api_key} if api_key else None)
        except NetworkError as exc:
            # A partial corpus is fine and a failed build is not: NVD rate-limits
            # aggressively and an exercise should not die because page 14 of 20
            # timed out. Stop here and use what we have.
            if page == 0:
                raise SourceError(f"NVD unreachable on the first page: {exc}") from None
            print(f"   nvd: stopping at page {page} ({exc})")
            break

        target.write_bytes(payload)
        time.sleep(delay)

    return cache_dir


def _cvss(metrics: dict) -> tuple[str, str]:
    """Best available CVSS vector and score, newest version first."""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        data = entries[0].get("cvssData", {})
        vector = data.get("vectorString", "")
        score = data.get("baseScore", "")
        severity = data.get("baseSeverity", "") or entries[0].get("baseSeverity", "")
        if vector:
            return vector, f"{score} {severity}".strip()
    return "", ""


def _configurations(cve: dict, limit: int = 12) -> list[str]:
    """CPE match strings — rigid, structured, and absent from general web text."""
    out: list[str] = []
    for config in cve.get("configurations", []) or []:
        for node in config.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                criteria = match.get("criteria")
                if not criteria:
                    continue
                bounds = " ".join(
                    f"{k}={match[k]}" for k in (
                        "versionStartIncluding", "versionStartExcluding",
                        "versionEndIncluding", "versionEndExcluding")
                    if match.get(k)
                )
                out.append(f"{criteria} {bounds}".strip())
                if len(out) >= limit:
                    return out
    return out


def _documents(path: Path) -> Iterator[Document]:
    for page in sorted(path.glob("page-*.json")):
        try:
            payload = json.loads(page.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue

        for item in payload.get("vulnerabilities", []) or []:
            cve = item.get("cve") or {}
            cve_id = cve.get("id")
            if not cve_id:
                continue

            descriptions = [
                d.get("value", "") for d in cve.get("descriptions", []) or []
                if d.get("lang") == "en"
            ]
            description = " ".join(x for x in descriptions if x).strip()
            # "** REJECT **" records carry no technical content worth training on.
            if not description or description.startswith("** REJECT"):
                continue

            vector, score = _cvss(cve.get("metrics") or {})
            weaknesses = sorted({
                d.get("value", "")
                for w in cve.get("weaknesses", []) or []
                for d in w.get("description", []) or []
                if d.get("value", "").startswith("CWE-")
            })

            lines = [f"{cve_id}"]
            if cve.get("published"):
                lines.append(f"published: {cve['published']}")
            if score:
                lines.append(f"cvss: {score}")
            if vector:
                lines.append(f"vector: {vector}")
            if weaknesses:
                lines.append(f"weakness: {', '.join(weaknesses)}")
            lines.append("")
            lines.append(description)

            configs = _configurations(cve)
            if configs:
                lines.append("")
                lines.append("affected:")
                lines.extend(f"  {c}" for c in configs)

            refs = [
                r.get("url", "") for r in (cve.get("references") or [])[:6]
                if r.get("url")
            ]
            if refs:
                lines.append("")
                lines.append("references:")
                lines.extend(f"  {u}" for u in refs)

            text = normalise("\n".join(lines))
            if len(text) < 120:
                continue
            yield Document(text=text, source="nvd", register=Register.ADVISORY,
                           side=Side.NEUTRAL, ident=cve_id)


SPEC = SourceSpec(
    name="nvd",
    license=("Public domain — NVD data is produced by NIST, a US Government "
             "agency, and is not subject to domestic copyright. Free to use "
             "with attribution: https://nvd.nist.gov/general/FAQ-Sections/General-FAQs"),
    url="https://services.nvd.nist.gov/rest/json/cves/2.0",
    register=Register.ADVISORY,
    side=Side.NEUTRAL,
    fetch=_fetch,
    documents=_documents,
    expect_min_docs=5000,
    notes=("CVE records with CVSS vector strings, CWE ids and CPE match strings. "
           "Written specifically to close the -26% CVE-identifier result from the "
           "first tokenizer comparison. Set NVD_API_KEY to fetch faster."),
)
