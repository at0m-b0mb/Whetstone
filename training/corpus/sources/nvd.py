"""NVD vulnerability records — the ADVISORY register.

Written to close a gap the balance report would otherwise have shouted about:
every other source lands in SHELL, SYSTEM, DETECTION, ADVERSARY or PROSE, so
ADVISORY was sitting at 0% against a 9% target.

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

**This adapter used to teach the wrong century, and that is what most of the
code below is about.** It paged the API from ``startIndex=0`` and stopped after
twenty pages. The API returns records in ascending chronological order, so
"the first 40,000 records" means "every CVE published between 1988 and 2009 and
nothing whatsoever after it" — the oldest 10% of a 396,163-record catalogue.
Measured on a random sample of 3,000 of the documents that produced:

===========================  =======
CVSS v2 vector                 97.5%
CVSS v3 vector                  1.6%
CVSS v4 vector                  0.0%
carries a ``weakness:`` line   38.3%
===========================  =======

Those records predate CWE assignment and predate CVSS v3 entirely, so the
model's learnt prototype of "a CVE record" had a v2 vector and no weakness
line. The consequence is visible in the benchmark: the ``cwe-shape`` probe,
which hands the model ``CVE-2023-4863\\ncvss: 8.8 HIGH\\n`` and asks for the
next line, scored 0/5. The model had genuinely not learnt the CVE-to-CWE
association, because the dominant shape it saw does not contain one.

The adapter was never dropping the ``weaknesses`` field — it read it correctly
then and reads it correctly now. The bug was **selection**, and it had two
halves. Fixing only the obvious half would have left the benchmark where it was.

**Half one: which records are fetched.** Selection is now a systematic
stratified sample over the whole index space — one probe request for
``totalResults``, then :data:`_STRATA` equally-spaced offsets across it, each
contributing one page. See :func:`_offsets` for why that particular design and
what was rejected.

**Half two: what order they are yielded in, which is the half that hides.**
``build.py`` trims over-represented registers in both ``_apply_balance`` and
``_cap_register_share``, and both trim by walking a source's document list and
keeping documents until the allowance runs out. That is a **prefix cut**. A
perfectly stratified fetch, yielded stratum by stratum in file order, gets
re-sorted into exactly the old bias the instant the balancer decides ADVISORY
is over target and keeps only the front of the list — which is stratum 0, which
is 1988. This is why the built corpus showed 9.7% CWE coverage while the raw
cache showed 38.3%: the balancer had kept the oldest 12,254 of 40,000. So
:func:`_documents` emits in a deterministic shuffled order, and any prefix of
that stream is a representative sample of the whole.

The permutation is keyed on ``blake2b`` of the CVE id rather than
:func:`random.shuffle` or :func:`hash`. ``hash()`` on a ``str`` is salted per
process by ``PYTHONHASHSEED``, so it would have produced a different corpus on
every run and made two training runs impossible to compare — and it would have
done so silently, since any single run looks perfectly well shuffled.

**Rate limits.** Without an API key the public endpoint allows roughly 5
requests per rolling 30 seconds. :func:`_fetch` sleeps 6.5s between strata and
caches every stratum to disk, so a re-run costs nothing. Set ``NVD_API_KEY`` in
the environment to go faster; the code uses it if present and works fine
without it. A cold fetch is about four and a half minutes without a key.

**The trap in the failure path.** The old code did ``break`` on the first
``NetworkError``, on the reasoning that a partial corpus beats a failed build.
That reasoning is sound and the ``break`` was still wrong here: under
contiguous paging, stopping early costs you the tail; under stratified offsets,
stopping early costs you every *later* stratum, and later means more recent.
A single timed-out request would have quietly reconstructed the exact bug this
file exists to fix, and the balance report would have shown nothing amiss
because the document count barely moves. A failed stratum is now skipped rather
than fatal, and only a run of :data:`_MAX_CONSECUTIVE_FAILURES` gives up.

**Licensing, and the part the previous version of this docstring got wrong.**
It claimed the whole record was public domain because NVD is a NIST product.
Half of that is right. The two halves of a record have two different owners:

* The **enrichment** — CVSS base scores and vector strings, CWE mappings, CPE
  applicability statements — is produced by NIST analysts. Works of NIST
  employees are not subject to domestic copyright under 17 USC 105, per NIST's
  own statement at https://www.nist.gov/open/copyright-fair-use-and-licensing-statements-srd-data-software-and-technical-series-publications
  ("Data/works created by NIST employees ... are subject to 17 U.S.C. §105 and
  generally are not subject to copyright protection within the United States").
* The **CVE record itself** — the identifier, the description text, the
  references — comes from the CVE Program and is MITRE's, under the CVE Program
  Terms of Use. That grant is broad but it is *conditional*:

      MITRE hereby grants you a perpetual, worldwide, non-exclusive, no-charge,
      royalty-free, irrevocable copyright license to reproduce, prepare
      derivative works of, publicly display, publicly perform, sublicense, and
      distribute Common Vulnerabilities and Exposures (CVE). Any copy you make
      for such purposes is authorized provided that you reproduce MITRE's
      copyright designation and this license in any such copy.

  The description is the bulk of every document here, so the condition attaches
  to this corpus and is satisfied the way :mod:`~training.corpus.sources.capec`
  satisfies MITRE's: the designation and the licence are reproduced verbatim in
  :data:`_LICENCE_TEXT`, written into the cache beside the data, and summarised
  in :data:`SPEC`.

Reading those two terms was more work than it should have been and is worth
recording, because the next person will hit it: both ``nvd.nist.gov`` and
``www.cve.org`` are JavaScript single-page applications that serve a 2 KB shell
with no licence text in it, and ``cve.mitre.org/about/termsofuse.html`` now
serves a generic "you are viewing an ARCHIVE" page instead of the terms it
still appears to link to. A badge or a remembered summary would have been the
easy route and is exactly how a project names the wrong licence. The NIST text
came from its server-rendered copyright page; the MITRE text was read out of
the CVE.org application bundle, which is the site's own content and the only
machine-readable copy of it that exists.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Iterator

from ..net import NetworkError, fetch
from ..source import Document, Register, Side, SourceError, SourceSpec, normalise

_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

#: ``noRejected`` is a **valueless** flag in this API — ``&noRejected``, not
#: ``&noRejected=true``, which is quietly ignored. It matters beyond saving
#: bandwidth on records :func:`_documents` would discard anyway: it changes
#: ``totalResults`` (396,163 -> 377,792 at the time of writing), so the index
#: space the offsets are computed against and the index space they are fetched
#: from must be the *same* query or every offset points somewhere else.
_FILTER = "&noRejected"

#: Records taken from each stratum, and how many strata. 40 x 1000 = 40,000
#: records, which is deliberately the same volume the contiguous version
#: produced: this change is about the *composition* of the source, not its
#: size, and holding the character count still keeps the register balance
#: report comparable across the fix.
#:
#: Splitting the same budget into more, smaller pages is what buys the spread.
#: A stratum is a contiguous block of the catalogue, so it is a cluster — 1,000
#: consecutive modern CVEs span about three days and share whatever vendors
#: happened to publish that week. Forty clusters of 1,000 sample forty separate
#: weeks across thirty-eight years; twenty clusters of 2,000 sample twenty
#: fortnights. The cost is one request each, and requests are the slow part.
_PER_STRATUM = int(os.environ.get("WHETSTONE_NVD_PER_STRATUM", "1000"))
_STRATA = int(os.environ.get("WHETSTONE_NVD_STRATA", "40"))

_SLEEP_NO_KEY = 6.5
_SLEEP_KEY = 0.8

#: Transient failures are survived, a sustained outage is not. Four in a row
#: without a single success is NVD being down or throttling us hard, and
#: sleeping 6.5s through another thirty-six of them helps nobody.
_MAX_CONSECUTIVE_FAILURES = 4

_STRATUM = "stratum-{:03d}.json"
_MARKER = ".nvd-complete.json"
_LICENCE_FILE = "LICENCE-nvd-cve.txt"

#: Short of this a stratum file is an error page or a truncated transfer.
_MIN_STRATUM_BYTES = 1000

#: Reproduced verbatim into the cache beside the data it covers, because the
#: MITRE half of the grant is conditioned on exactly that. Both texts were read
#: from the rights-holders' own pages; see the module docstring for where, and
#: for why that was not a one-line lookup.
_LICENCE_TEXT = """\
NVD CVE records as used by the Whetstone corpus have two rights-holders.

1. NVD ENRICHMENT (CVSS base scores and vector strings, CWE mappings, CPE
   applicability statements) is produced by analysts at the National Institute
   of Standards and Technology, an agency of the US Federal Government.

   Per NIST's own copyright statement:

       "Data/works created by NIST employees that are not covered by the
       Standard Reference Data Act are subject to 17 U.S.C. sec. 105 and
       generally are not subject to copyright protection within the United
       States. NIST data or other works may be subject to copyright protection
       in foreign countries."

   Source: https://www.nist.gov/open/copyright-fair-use-and-licensing-statements-srd-data-software-and-technical-series-publications

   NIST asks to be acknowledged as the source of the data. This corpus does so
   here and in the source adapter.

2. THE CVE RECORD ITSELF (identifier, description text, references) is the
   property of The MITRE Corporation and is used under the CVE Program Terms
   of Use, reproduced verbatim:

       "CVE Usage: MITRE hereby grants you a perpetual, worldwide,
       non-exclusive, no-charge, royalty-free, irrevocable copyright license to
       reproduce, prepare derivative works of, publicly display, publicly
       perform, sublicense, and distribute Common Vulnerabilities and Exposures
       (CVE(TM)). Any copy you make for such purposes is authorized provided
       that you reproduce MITRE's copyright designation and this license in any
       such copy."

   Source: https://www.cve.org/Legal/TermsOfUse

   MITRE's copyright designation, reproduced as that grant requires:

       Copyright (c) 1999-2026, The MITRE Corporation. CVE and the CVE logo are
       registered trademarks of The MITRE Corporation.

   The CVE Program is sponsored by the US Cybersecurity and Infrastructure
   Security Agency (CISA).

DISCLAIMER (MITRE, CVE Program Terms of Use): all documents and the information
contained therein are provided on an "AS IS" basis and MITRE disclaims all
warranties, express or implied.
"""


def _headers(api_key: str) -> dict[str, str] | None:
    return {"apiKey": api_key} if api_key else None


def _get(url: str, api_key: str) -> tuple[bytes, dict]:
    """One API call, returning the raw body **and** its decoded form.

    Both, from a single request. The obvious shape here is a validating helper
    that returns the decoded object and a separate ``fetch`` to get the bytes
    to write — which issues two requests per stratum and silently halves an
    already tight rate-limit budget. The bytes are what lands in the cache, the
    dict is what proves they are worth landing, and they must come from one
    call or they are not even describing the same response.
    """
    payload = fetch(url, timeout=90, headers=_headers(api_key))
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        # A 200 carrying an HTML maintenance page is the realistic version of
        # this, and it must not be mistaken for an empty result set.
        raise NetworkError(f"NVD returned undecodable JSON: {exc}") from None
    if not isinstance(data, dict):
        raise NetworkError("NVD returned JSON that is not an object")
    return payload, data


def _offsets(total: int) -> list[int]:
    """Equally-spaced start indices across the whole catalogue.

    The API returns records in ascending chronological order — verified rather
    than assumed, by reading the first record at nine offsets across the index
    space: 0 is CVE-1999-0095 published 1988, 25% is a 2017 record, 62% a 2024
    one, 99% a 2026 one. So index position is a monotone proxy for publication
    date, and equal-width blocks of the index are equal-width blocks of
    *history by volume*.

    That is the whole argument for this design. Sampling one page from each of
    N equal index blocks is proportional stratified sampling over publication
    volume, and it has three properties worth having:

    * It is **proportional**, not arbitrary. The resulting corpus mirrors the
      real distribution of CVE records, and since annual CVE volume has
      exploded — roughly 15% of all records ever published predate 2013 — it
      lands modern-dominant on its own. Nobody has to pick a date and defend
      it; the catalogue's own shape picks it.
    * It is **systematic**, not random. Every block contributes exactly one
      page, so no era can come up empty by luck. History is preserved by
      construction rather than by hoping the RNG was kind, and a reader can
      check it by listing the cache.
    * It **keeps CVSS v2 at roughly its true weight** (~15%) instead of 97%.
      Enough to learn that the form exists — v2 vectors are still all over
      historical advisories and scanner output the model will be asked to
      read — without it being the prototype.

    Three alternatives were considered and rejected:

    **A cutoff, "only CVE-2016 and later".** Simplest to write, and it throws
    away the records a security model is most likely to be asked about:
    CVE-2014-0160 is Heartbleed, CVE-2014-6271 is Shellshock. Losing real
    history to fix a distribution is paying too much.

    **Filtering on "has a CWE and a v3 vector".** Tempting because it drives
    the target metric straight to 100%, and it teaches the model two false
    things. First, that every CVE record carries a weakness line: NVD marks a
    large minority ``NVD-CWE-noinfo`` or ``NVD-CWE-Other``, and a model trained
    to always produce a CWE will invent one when the real answer is that nobody
    assigned it. Optimising the ``cwe-shape`` probe by making its subject
    unfalsifiable is not learning. Second, that v2 vectors do not exist. A
    filter that guarantees the benchmark number is a filter that has stopped
    measuring anything.

    **Date-window queries** (``pubStartDate``/``pubEndDate``). Precise, and the
    API caps a window at 120 days, so covering 1988-2026 needs well over a
    hundred requests before paging — against 41 here, at 6.5s each without an
    API key. Since the ordering is already chronological, the index achieves
    the same stratification for a quarter of the wall time.
    """
    if total <= 0:
        raise SourceError(f"NVD reported {total} total records")

    # Equal-width blocks. The last offset is clamped so the final page is a
    # full one rather than running off the end of the catalogue — without this
    # the most recent stratum is the only short one, which is the stratum this
    # whole exercise is trying to stop under-sampling.
    span = total / _STRATA
    ceiling = max(0, total - _PER_STRATUM)
    seen: set[int] = set()
    out: list[int] = []
    for i in range(_STRATA):
        offset = min(int(i * span), ceiling)
        if offset in seen:
            # Only reachable on a catalogue smaller than _STRATA * _PER_STRATUM,
            # where the blocks collapse together. Taking it once is right.
            continue
        seen.add(offset)
        out.append(offset)
    return out


def _fetch(cache_dir: Path) -> Path:
    """Download a stratified sample of CVE records. Idempotent.

    The completion marker is written **last**, and only when every stratum
    landed. An interrupted or partially-failed fetch therefore leaves no
    marker, so the next run tops up the gaps — cached strata are skipped, so
    that costs one request per missing stratum and nothing else. The failure
    mode this guards against is the expensive one: a half-fetched cache that a
    later run mistakes for a finished one and trains on.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    marker = cache_dir / _MARKER
    if marker.is_file():
        return cache_dir

    api_key = os.environ.get("NVD_API_KEY", "").strip()
    delay = _SLEEP_KEY if api_key else _SLEEP_NO_KEY

    # The probe doubles as the reachability check. If this fails there is no
    # index space to stratify over and nothing sensible to do but say so.
    try:
        probe = _get(f"{_API}?resultsPerPage=1&startIndex=0{_FILTER}", api_key)
    except NetworkError as exc:
        raise SourceError(f"NVD unreachable on the count probe: {exc}") from None
    total = int(probe.get("totalResults") or 0)
    offsets = _offsets(total)
    time.sleep(delay)

    fetched: list[dict] = []
    missing = 0
    consecutive = 0
    for index, offset in enumerate(offsets):
        target = cache_dir / _STRATUM.format(index)
        if target.is_file() and target.stat().st_size > _MIN_STRATUM_BYTES:
            fetched.append({"stratum": index, "offset": offset, "cached": True})
            continue

        url = (f"{_API}?resultsPerPage={_PER_STRATUM}&startIndex={offset}"
               f"{_FILTER}")
        try:
            _get(url, api_key)  # validated before anything touches the cache
            payload = fetch(url, timeout=90, headers=_headers(api_key))
        except NetworkError as exc:
            # Skip, do not break. See the module docstring: breaking here drops
            # every later stratum, and later means more recent, which rebuilds
            # the exact bias this file was rewritten to remove.
            missing += 1
            consecutive += 1
            print(f"   nvd: stratum {index} at offset {offset:,} failed ({exc})")
            if consecutive >= _MAX_CONSECUTIVE_FAILURES:
                print(f"   nvd: {consecutive} consecutive failures, giving up "
                      f"with {index + 1 - missing}/{len(offsets)} strata")
                break
            time.sleep(delay)
            continue

        consecutive = 0
        target.write_bytes(payload)
        fetched.append({"stratum": index, "offset": offset, "cached": False})
        time.sleep(delay)

    (cache_dir / _LICENCE_FILE).write_text(_LICENCE_TEXT, encoding="utf-8")

    if missing:
        print(f"   nvd: {missing} of {len(offsets)} strata missing; leaving the "
              f"completion marker off so the next run tops them up")
        return cache_dir

    marker.write_text(json.dumps({
        "total_results": total,
        "strata": len(offsets),
        "per_stratum": _PER_STRATUM,
        "filter": _FILTER,
        "offsets": [f["offset"] for f in fetched],
        "fetched_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }, indent=2), encoding="utf-8")
    return cache_dir


def _cvss(metrics: dict) -> tuple[str, str]:
    """Best available CVSS vector and score, newest version first.

    Within a version, NVD may carry several entries: a ``Primary`` one scored
    by NIST and ``Secondary`` ones supplied by the assigning CNA, which
    routinely disagree. The Primary entry is the authoritative NVD assessment
    and it is also the half of the record that is unambiguously public domain,
    so it is preferred where present rather than taking whichever entry
    happened to be serialised first.
    """
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        chosen = next(
            (e for e in entries if e.get("type") == "Primary"), entries[0])
        data = chosen.get("cvssData", {})
        vector = data.get("vectorString", "")
        score = data.get("baseScore", "")
        # v2 puts baseSeverity on the entry, v3 and v4 put it on cvssData.
        severity = data.get("baseSeverity", "") or chosen.get("baseSeverity", "")
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


def _render(cve: dict) -> str | None:
    """One CVE record as training text, or ``None`` if there is nothing to learn."""
    cve_id = cve.get("id")
    if not cve_id:
        return None

    descriptions = [
        d.get("value", "") for d in cve.get("descriptions", []) or []
        if d.get("lang") == "en"
    ]
    description = " ".join(x for x in descriptions if x).strip()
    # "** REJECT **" records carry no technical content worth training on.
    # &noRejected should have excluded these upstream; the check stays because
    # a filter that silently stops working is not something to find out about
    # by reading the corpus.
    if not description or description.startswith("** REJECT"):
        return None

    vector, score = _cvss(cve.get("metrics") or {})
    # NVD-CWE-noinfo and NVD-CWE-Other are placeholders meaning "nobody
    # assigned one", not weakness classes. Dropping them is what keeps the
    # absence of a weakness line honest: a record with no CWE should train the
    # model that CVEs sometimes have no CWE, not that the answer is "noinfo".
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
    return text if len(text) >= 120 else None


def _shuffle_key(cve_id: str) -> bytes:
    """A stable, process-independent permutation key.

    :func:`hash` is salted per interpreter by ``PYTHONHASHSEED`` and
    :func:`random.shuffle` depends on seeding discipline nobody will maintain.
    Either would reorder the corpus between runs, and because the balancer
    keeps a prefix, reordering the corpus *changes which documents survive*.
    Two training runs would then differ for a reason invisible in every report
    the build prints. A hash of the identifier is reproducible on any machine
    and any Python, forever.
    """
    return hashlib.blake2b(cve_id.encode("utf-8"), digest_size=8).digest()


def _documents(path: Path) -> Iterator[Document]:
    """Yield every cached record, in an order whose every prefix is fair.

    Deliberately materialised rather than streamed. ``build.py``'s balancer
    keeps a prefix of this list, so the shuffle is not cosmetic — it is half
    the fix, and a shuffle cannot be done lazily. The cost is bounded and
    small: 40,000 rendered records is about 34 MB of strings, and the page
    JSON, which is the actually large thing at 157 MB, is dropped one stratum
    at a time as we go.
    """
    rendered: list[tuple[bytes, str, str]] = []

    # A flat, non-recursive glob over one directory this adapter owns. Not
    # rglob and not a walk: there is no tree here to descend and so no symlink
    # for a traversal to follow back into the corpus cache.
    for stratum in sorted(path.glob("stratum-*.json")):
        try:
            payload = json.loads(stratum.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue

        for item in payload.get("vulnerabilities", []) or []:
            cve = item.get("cve") or {}
            text = _render(cve)
            if text is None:
                continue
            cve_id = cve["id"]
            rendered.append((_shuffle_key(cve_id), cve_id, text))

    # Sorting by the hash IS the shuffle. Second element breaks the (vanishing)
    # tie deterministically so the order never depends on read order.
    rendered.sort(key=lambda r: (r[0], r[1]))

    for _, cve_id, text in rendered:
        yield Document(text=text, source="nvd", register=Register.ADVISORY,
                       side=Side.NEUTRAL, ident=cve_id)


SPEC = SourceSpec(
    name="nvd",
    license=(
        "Mixed, both permissive, and not a single licence — the record and its "
        "enrichment have different owners. NVD enrichment (CVSS vectors and "
        "scores, CWE mappings, CPE applicability) is the work of NIST, a US "
        "Government agency, and is not subject to domestic copyright under 17 "
        "USC 105 per NIST's own statement at "
        "https://www.nist.gov/open/copyright-fair-use-and-licensing-statements-srd-data-software-and-technical-series-publications "
        "— free to use, NIST asks to be cited. The CVE record itself "
        "(identifier, description, references) is MITRE's, under the CVE "
        "Program Terms of Use (https://www.cve.org/Legal/TermsOfUse): a "
        "perpetual, worldwide, non-exclusive, no-charge, royalty-free, "
        "irrevocable copyright licence to reproduce, prepare derivative works "
        "of and distribute CVE, CONDITIONED on reproducing MITRE's copyright "
        "designation and the licence in any copy. Both texts are reproduced "
        "verbatim into LICENCE-nvd-cve.txt in the cache, which is what "
        "satisfies that condition. Copyright (c) 1999-2026, The MITRE "
        "Corporation."
    ),
    url="https://services.nvd.nist.gov/rest/json/cves/2.0",
    register=Register.ADVISORY,
    side=Side.NEUTRAL,
    fetch=_fetch,
    documents=_documents,
    #: 40 strata x 1,000 records, less the handful too short to be worth
    #: training on, lands just under 40,000. A floor at 25,000 absorbs a few
    #: failed strata without complaining and still goes loud if NVD changes its
    #: response shape and this source starts yielding hundreds.
    expect_min_docs=25_000,
    notes=("CVE records with CVSS vector strings, CWE ids and CPE match "
           "strings, sampled as 40 equally-spaced strata across the whole "
           "396k-record catalogue rather than the oldest 40k — the contiguous "
           "version was 97.5% CVSS v2 and 38% CWE because it stopped at 2009. "
           "Yielded in a hash-shuffled order because build.py's balancer keeps "
           "a prefix. Set NVD_API_KEY to fetch faster."),
)
