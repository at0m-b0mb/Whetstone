"""CISA operational guidance — the incident report, written by defenders. ADVISORY/BLUE.

Everything else in this corpus is a taxonomy entry, a rule, or code. ATT&CK
names a behaviour. CAPEC orders one. Sigma matches one. NVD records a flaw.
None of them is a *report*. CISA's joint advisories are, and they are the only
source here that reads the way the thing this project's agent has to produce at
the end of an engagement reads: here is what the adversary did, in order, with
the ATT&CK technique id beside each step; here is what it looked like in
telemetry — file names, SHA-256 hashes, ports, registry keys, command lines;
here is what to do about it, prioritised, with the control named. Attack
sequence, observed indicators and recommended mitigations in one document, in
prose, under headings a reader can navigate. That whole shape is the deliverable,
and nothing else in the corpus teaches its form.

The KEV catalogue is here for a narrower and blunter reason. It carries the
single most operationally important fact in vulnerability management, and it is a
fact no CVSS score contains: **which vulnerabilities are actually being exploited
in the wild**, as opposed to merely scoring high. A model trained only on NVD
learns that severity is a number between 0 and 10. A model that has also read KEV
learns that 1,713 of the several hundred thousand published CVEs are the ones
with a federal remediation deadline attached, which is a different and much more
useful ordering of the same universe.

The SCuBA secure configuration baselines are the third leg: CISA's own hardening
guidance, as machine-readable Markdown rather than the PDFs most of CISA's
hardening guides ship as. Each policy carries an identifier (``MS.AAD.3.2v2``), a
criticality (``SHALL``/``SHOULD``), a rationale sentence, a NIST SP 800-53 control
mapping (``CM-7``) and an ATT&CK TTP mapping — four identifier systems joined to
one English justification, which is exactly the join a report has to make when it
says why a control is being recommended.

**Register.** ADVISORY throughout, and deliberately so even for the narrative
advisories, which are *about* adversaries and would be tempting to file as
ADVERSARY. Register is a claim about surface form, not about topic: what these
documents look like on the page is CVE identifiers, vendor and product names,
dated headers, alert codes, indicator tables and numbered mitigation lists. That
is the advisory register. Side is BLUE: every one of these documents is written
by defenders, for defenders, and ends in a list of things to go and fix.

**Feeds, and why these.** Three, all machine-readable or close to it:

* ``known_exploited_vulnerabilities.json`` — the KEV catalogue, one JSON file,
  no pagination, no key.
* The advisory index at ``/news-events/cybersecurity-advisories``, faceted by
  advisory type, walked page by page to recover the slugs, then one HTML fetch
  per advisory. CISA publishes an RSS feed at ``/cybersecurity-advisories/all.xml``
  and its ``<description>`` elements *do* carry the full advisory body — but the
  feed is fixed at the most recent 30 items and honours neither ``page`` nor the
  facet query string (all four variants return byte-identical XML). Thirty
  documents is not an archive, so the index walk is the only route to the ~180
  ``aa##-###`` joint advisories and the ~90 ``ar##-###`` analysis and malware
  reports, and the HTML is parsed with :mod:`html.parser` from the stdlib.
* The SCuBA baselines from ``cisagov/ScubaGear`` on GitHub, as raw Markdown.

**Deliberately not taken: the CSAF advisories.** ``cisagov/CSAF`` publishes every
ICS advisory back to 2010 as structured CSAF JSON, thousands of files, trivially
fetchable. It is left out on purpose. Those are vendor vulnerability advisories —
product tree, CVE, CVSS vector, remediation — which is precisely the shape
:mod:`~training.corpus.sources.nvd` already contributes 40,000 of. Adding several
thousand more would swamp the 260 narrative documents this source exists for
inside the same source's own share cap, which is the opposite of the point.

---

**Trap 1: the WAF refuses Python's TLS handshake.** ``www.cisa.gov`` answers 403
to every request from ``urllib`` and 200 to the identical request from ``curl``.
It is not the User-Agent, not the ``Accept`` headers, not HTTP/1.1 versus
HTTP/2 — curl replaying urllib's exact header set still gets 200. It is the
ClientHello: the edge fingerprints the handshake, and OpenSSL 3's default cipher
list is on the wrong side of the rule, while macOS curl's LibreSSL list is not.
The static asset path that serves the KEV JSON is exempt, which is why KEV works
and nothing else does.

So :func:`_context` derives a context from :func:`..net.ssl_context` and sets an
explicit browser-shaped cipher list, which changes the fingerprint. Three things
matter about how that is done:

1. ``net.ssl_context()`` remains the only code in this project that decides
   *what to trust*. Its CA store is copied out with
   ``get_ca_certs(binary_form=True)`` and loaded into the derived context, so
   this module never goes looking for a CA bundle itself — the exact duplication
   :mod:`..net` was written to stop.
2. The shared context is **not mutated**. It is cached and every other adapter
   holds the same object; reordering its ciphers as a side effect of importing
   this module would be an invisible action at a distance.
3. Verification is not weakened. ``check_hostname`` stays on, ``verify_mode``
   stays ``CERT_REQUIRED``, the minimum version stays TLS 1.2. The cipher list
   is all ECDHE-forward-secret AEAD suites plus the CBC suites a browser still
   offers. This changes the shape of the handshake, not its security.

If the edge ever refuses this too, :data:`_FORBIDDEN` says all of the above in
the exception rather than leaving the next reader to rediscover it.

**Trap 2: horizontal whitespace.** :func:`~training.corpus.source.normalise`
does not collapse runs of spaces, and that is the contract — the alignment of an
indicator table is meaning, and flattening it destroys the single best-scoring
register this corpus has. This adapter therefore *constructs* alignment: an HTML
``<table>`` of file names and hashes is rendered as padded columns, because that
is what makes it a table rather than a list of words. What it does collapse is
whitespace *inside an HTML text node*, which is a different thing entirely —
HTML collapses that itself when rendering, it is the CMS's own source
indentation, and preserving it would produce ragged garbage rather than
structure. Same argument :mod:`.capec` makes about XML pretty-printing: decoding
the format is not cleaning the text. Inside ``<pre>`` the original spacing is
kept verbatim, because there it is the author's and not the serialiser's.

Wide tables are not padded. A mitigation table whose cells hold paragraphs
cannot be aligned into anything readable, so past
:data:`_TABLE_MAX_WIDTH` the renderer switches to one ``Header: value`` line per
cell. Column padding is also capped well below the 200-space run that
``normalise`` treats as a rendering artefact and crushes.

**Trap 3: silent zero.** This corpus has already had one source contribute
nothing without saying so, and a scraper of a government CMS is the likeliest
candidate to do it again — a facet id changes, a path moves, and a parser that
shrugs yields an empty iterator and a build report nobody reads twice. Every
structural assumption here is therefore an assertion that raises
:class:`~training.corpus.source.SourceError` with the URL and the expectation in
the message: the KEV catalogue must parse and hold at least
:data:`_KEV_MIN_ENTRIES` entries, the first index page of the joint-advisory
facet must yield links, the advisory fetch must not fail more often than
:data:`_MAX_FAILURE_RATE`, and :func:`_documents` refuses to run at all against a
cache that is missing its KEV file or has no advisory pages in it.

**Politeness.** One request per :data:`_DELAY` seconds to ``www.cisa.gov``,
serialised through a module-level clock, with the corpus's descriptive
User-Agent from :mod:`..net`. Everything is cached to disk and nothing already
cached is re-fetched: a cold run costs ~280 requests and about six minutes, and
every run after that costs the index pages only, and those only once their cache
is :data:`_INDEX_TTL_DAYS` days old — enough to pick up new advisories without
re-walking the archive. ``WHETSTONE_CISA_REFRESH=1`` forces the lot.

**Licence.** Recorded from what CISA actually states, which is: nothing. There is
no terms-of-use page on cisa.gov — the site links list offers a linking policy
and a privacy policy and no copyright page at all. The operative rule is
therefore 17 U.S.C. § 105: a work prepared by an officer or employee of the US
Government as part of that person's official duties is not subject to copyright
protection in the United States. The advisories' own Disclaimer section
disclaims *endorsement* of the vendors named in them and says nothing that
restricts redistribution. The SCuBA baselines are separate and explicit: CC0 1.0
Universal, per the LICENSE file in ``cisagov/ScubaGear``.
"""

from __future__ import annotations

import json
import os
import re
import ssl
import time
import urllib.error
import urllib.request
from html.parser import HTMLParser
from pathlib import Path
from typing import Iterator

from ..net import USER_AGENT, NetworkError, ssl_context
from ..source import Document, Register, Side, SourceError, SourceSpec, normalise

# ---------------------------------------------------------------------------
# endpoints
# ---------------------------------------------------------------------------

#: The KEV catalogue, whole, in one file. Served from the static asset path,
#: which is the one part of www.cisa.gov the edge does not fingerprint — a plain
#: ``net.fetch`` reaches it where nothing else on the host is reachable.
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

#: The advisory index, faceted by advisory type. The facet ids are Drupal term
#: ids read off the type filter on the live page; they are the least stable
#: thing in this module, which is why an empty first page is fatal rather than
#: merely quiet.
_INDEX_URL = ("https://www.cisa.gov/news-events/cybersecurity-advisories"
              "?f%5B0%5D=advisory_type%3A{facet}&page={page}")

#: facet id -> (human name, required). Type 94 is the ``aa##-###`` joint
#: advisories, which are the whole reason this source exists, so its absence is
#: an error. Type 65 is the Analysis Report / Malware Analysis Report series,
#: same narrative shape aimed at one malware family rather than one intrusion
#: set; welcome, but not worth failing a build over. Type 93 ("Alert") is
#: deliberately absent: those are two-paragraph "CISA has added N CVEs to the
#: KEV catalogue" notices whose content this source already carries in full.
_FACETS: dict[str, tuple[str, bool]] = {
    "94": ("Cybersecurity Advisory", True),
    "65": ("Analysis Report", False),
}

#: Detail pages hang off two different path prefixes depending on type, so the
#: slug harvester accepts both and nothing else. Anchors and query strings are
#: excluded from the capture so the same advisory cannot arrive twice under two
#: spellings.
_SLUG_LINK = re.compile(
    r'href="(/news-events/(?:cybersecurity-advisories|analysis-reports)/'
    r'[a-z0-9][a-z0-9-]{4,})"'
)

#: CISA's Secure Cloud Business Applications baselines, as published Markdown.
#: GitHub raw, so none of the WAF problem applies and a plain fetch is enough.
_SCUBA_RAW = ("https://raw.githubusercontent.com/cisagov/ScubaGear/main/"
              "PowerShell/ScubaGear/baselines/{name}.md")
_SCUBA_FILES: tuple[str, ...] = (
    "aad", "defender", "exo", "powerbi", "powerplatform", "securitysuite",
    "sharepoint", "teams",
)

# ---------------------------------------------------------------------------
# cache layout and limits
# ---------------------------------------------------------------------------

_KEV_FILE = "kev.json"
_INDEX_FILE = "index.json"
_ADVISORY_DIR = "advisories"
_BASELINE_DIR = "baselines"
_MANIFEST = "cisa.meta.json"

#: Seconds between requests to www.cisa.gov. One federal web server, a few
#: hundred pages, no hurry; a cold fetch takes about six minutes and every later
#: fetch takes none.
_DELAY = float(os.environ.get("WHETSTONE_CISA_DELAY", "1.2"))
#: Multiplied by the attempt number after a transient failure.
_BACKOFF = 4.0
_ATTEMPTS = 3

#: The index is the only thing worth re-fetching, and only occasionally: new
#: advisories appear roughly weekly, and the archive behind them does not move.
_INDEX_TTL_DAYS = float(os.environ.get("WHETSTONE_CISA_INDEX_TTL", "7"))

#: Stop walking a facet after this many pages. Type 94 is 18 pages today; this
#: is a runaway guard for the case where the pager stops honouring ``page`` and
#: returns page 0 forever, which would otherwise loop until the disk filled.
_MAX_PAGES = 60

#: Refuse a KEV file smaller than this. The catalogue passed 1,700 entries in
#: 2026 and only grows; a floor this far below it rejects a truncated transfer
#: or an HTML error page served with a 200 without being brittle.
_KEV_MIN_ENTRIES = 500

#: If more than this fraction of advisory pages fail to fetch, the run is not
#: having a bad day — something systemic has changed — and it stops.
_MAX_FAILURE_RATE = 0.25

#: A rendered advisory shorter than this is a stub or a parse that found the
#: wrong div. Real joint advisories average 29,000 characters and run to sixty
#: thousand; measured across the whole archive the smallest genuine one renders
#: to 597, an advisory that is a single ATT&CK technique table and nothing else,
#: and the only page below that is a revision-history stub whose actual content
#: was a downloadable file. 500 sits in that gap.
_MIN_ADVISORY_CHARS = 500
#: KEV entries average 1,067 characters and the shortest carry a one-sentence
#: description with no references; well below this means missing fields.
_MIN_KEV_CHARS = 200
#: A baseline section below this is a heading with a link under it.
_MIN_BASELINE_CHARS = 400

#: Past this rendered width a table cannot be aligned into anything a reader or
#: a tokenizer benefits from, and the renderer switches to labelled rows.
#:
#: 160 is not arbitrary. Measured across the sample advisories, it is the
#: threshold that puts the indicator grids on the aligned side — a file name, a
#: 64-character SHA-256 and a short description come to 138 — and the ATT&CK
#: technique tables on the labelled side, because their "Use" column holds a
#: paragraph and runs to 400 characters on its own. That is the right split:
#: one is a grid, the other is prose in a box.
#:
#: It doubles as the bound on padding. No column can be padded wider than the
#: whole table, so no run of spaces this renderer produces comes near the
#: 200-space run ``normalise`` treats as a rendering artefact and crushes.
_TABLE_MAX_WIDTH = 160

_REFRESH = os.environ.get("WHETSTONE_CISA_REFRESH", "").strip() not in ("", "0")

# ---------------------------------------------------------------------------
# transport
# ---------------------------------------------------------------------------

#: A browser-shaped cipher list. Every suite here is either an ECDHE AEAD suite
#: or a CBC suite mainstream browsers still offer; nothing anonymous, nothing
#: export, nothing NULL. Its purpose is the *order and membership* of the list
#: as it appears in the ClientHello, which is what the edge fingerprints — not
#: any change in the strength of what is negotiated.
_CLIENT_HELLO_CIPHERS = (
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:"
    "ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:"
    "AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA"
)

_FORBIDDEN = (
    "{url}: HTTP 403.\n"
    "www.cisa.gov fingerprints the TLS ClientHello at its edge and refuses the "
    "one OpenSSL produces by default. This module already works around that by "
    "deriving a context from net.ssl_context() with a browser-shaped cipher "
    "list (see _CLIENT_HELLO_CIPHERS); a 403 here means the workaround has "
    "stopped being enough.\n"
    "Diagnose it the way it was diagnosed the first time: 'curl -sS -o /dev/null "
    "-w \"%{{http_code}}\\n\" {url}' will very likely return 200 from the same "
    "machine. If it does, the problem is the handshake and not the network, the "
    "path or the User-Agent.\n"
    "Do not answer this by disabling certificate verification. It is not a "
    "trust failure and turning verification off would not fix it."
)

#: Used for 404 and for 403 on the static asset path, because that path has no
#: handshake quirk to confuse the reading: a missing file under
#: ``/sites/default/files/`` is answered 403 by CISA's edge, not 404, so
#: treating only 404 as "this moved" would report a URL that no longer exists as
#: a mysterious permission problem.
_MOVED = (
    "{url}: HTTP {code}.\n"
    "That endpoint is gone or is no longer served. This source refuses to fall "
    "back to yielding zero documents quietly — a corpus that silently loses a "
    "source is worse than a build that stops, because nobody notices until a "
    "tokenizer comparison months later says a register is empty.\n"
    "Re-derive the URL from https://www.cisa.gov/cybersecurity-advisories (or, "
    "for the baselines, from github.com/cisagov/ScubaGear) and update the "
    "constant at the top of this module."
)

_derived: ssl.SSLContext | None = None
_last_request = 0.0


def _context() -> ssl.SSLContext:
    """A verifying context with a ClientHello the CISA edge will accept.

    Derived from :func:`..net.ssl_context` rather than built beside it: that
    function is the project's single decision about what certificate
    authorities to trust and it stays that way, its store simply being copied
    into a second context that differs only in its offered cipher suites. The
    shared context is never mutated — other adapters hold the same object.
    """
    global _derived
    if _derived is not None:
        return _derived

    base = ssl_context()
    anchors = base.get_ca_certs(binary_form=True)
    if not anchors:
        # Some platforms load their trust store in a form the context will not
        # hand back (a Windows system store, notably). Nothing to copy means
        # nothing safe to derive, so use net's context unchanged and let the
        # request fail with _FORBIDDEN, which explains precisely this.
        _derived = base
        return base

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cadata=b"".join(anchors))
    try:
        context.set_ciphers(_CLIENT_HELLO_CIPHERS)
    except ssl.SSLError:
        # A LibreSSL-linked Python will not know some of those OpenSSL names.
        # It also produces a different ClientHello already, so it is quite
        # likely not to need the workaround at all.
        pass
    _derived = context
    return context


def _get(url: str, *, timeout: int = 60, fatal_404: bool = True) -> bytes:
    """One rate-limited, retried GET against www.cisa.gov.

    The delay is enforced against a module-level clock rather than by sleeping
    after each call, so consecutive fetches are spaced by wall time regardless
    of how long the previous response took to arrive — which is the behaviour
    "one request every 1.2 seconds" actually means.

    ``fatal_404`` separates the two meanings a 404 can carry. On the KEV file or
    the advisory index it means the endpoint moved and everything downstream is
    about to be silently empty, which is the failure this module is built to
    refuse. On one advisory page it means that advisory was withdrawn or
    re-slugged since the index was walked, which is ordinary; the caller counts
    it and :data:`_MAX_FAILURE_RATE` decides whether it has stopped being
    ordinary.
    """
    global _last_request
    last = ""
    for attempt in range(1, _ATTEMPTS + 1):
        gap = _DELAY - (time.monotonic() - _last_request)
        if gap > 0:
            time.sleep(gap)
        _last_request = time.monotonic()

        request = urllib.request.Request(url, headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        })
        try:
            with urllib.request.urlopen(request, timeout=timeout,
                                        context=_context()) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 403:
                raise SourceError(_FORBIDDEN.format(url=url)) from None
            if exc.code == 404:
                if fatal_404:
                    raise SourceError(
                        _MOVED.format(url=url, code=404)) from None
                raise NetworkError(f"{url}: HTTP 404 Not Found") from None
            last = f"HTTP {exc.code} {exc.reason}"
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = str(exc)
        if attempt < _ATTEMPTS:
            time.sleep(_BACKOFF * attempt)
    raise NetworkError(f"{url}: {last} (after {_ATTEMPTS} attempts)")


def _plain_get(url: str, *, timeout: int = 90) -> bytes:
    """A fetch for hosts with no WAF quirk — the static KEV path and GitHub raw.

    Kept separate from :func:`_get` so the rate limiter only throttles the one
    server that needs throttling, and so the cipher workaround is scoped to the
    one host that needs it.
    """
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout,
                                    context=ssl_context()) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        if exc.code in (403, 404):
            raise SourceError(
                _MOVED.format(url=url, code=exc.code)) from None
        raise NetworkError(f"{url}: HTTP {exc.code} {exc.reason}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise NetworkError(f"{url}: {exc}") from None


# ---------------------------------------------------------------------------
# fetch
# ---------------------------------------------------------------------------

def _fetch_kev(root: Path) -> str:
    """The KEV catalogue, validated before it is allowed into the cache.

    Validated rather than merely downloaded because the failure this guards is
    not a network error — it is a 200 carrying CISA's HTML "page not found",
    which writes cleanly to disk and parses to zero vulnerabilities. Returns the
    catalogue version, for the manifest.
    """
    target = root / _KEV_FILE
    if target.exists() and not _REFRESH:
        try:
            return str(json.loads(
                target.read_text(encoding="utf-8")).get("catalogVersion", ""))
        except (OSError, ValueError):
            pass  # unreadable cache: fall through and fetch it again

    payload = _plain_get(_KEV_URL, timeout=120)
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise SourceError(
            f"{_KEV_URL} did not return JSON ({exc}). The catalogue has moved "
            f"or the response was intercepted; it began {payload[:120]!r}."
        ) from None

    entries = data.get("vulnerabilities")
    if not isinstance(entries, list) or len(entries) < _KEV_MIN_ENTRIES:
        raise SourceError(
            f"{_KEV_URL} parsed but holds {len(entries or [])} entries, and the "
            f"KEV catalogue has held more than {_KEV_MIN_ENTRIES:,} since 2022. "
            "Either the schema changed or this is not the catalogue."
        )

    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(".json.part")
    tmp.write_bytes(payload)
    tmp.replace(target)
    return str(data.get("catalogVersion", ""))


def _harvest(page_html: str) -> list[str]:
    """Advisory slugs from one index page, in page order, deduplicated."""
    seen: dict[str, None] = {}
    for path in _SLUG_LINK.findall(page_html):
        seen.setdefault(path, None)
    return list(seen)


def _fetch_index(root: Path) -> list[str]:
    """Walk the faceted index and return every advisory path, newest first.

    Walking stops when a page contributes no path the walk has not already
    seen. That is a stronger stopping rule than "the page is empty": a pager
    that has stopped honouring ``page`` re-serves page 0, which is not empty
    and would otherwise loop to :data:`_MAX_PAGES`.
    """
    index_file = root / _INDEX_FILE
    if index_file.exists() and not _REFRESH:
        try:
            cached = json.loads(index_file.read_text(encoding="utf-8"))
            age = (time.time() - float(cached.get("fetched", 0))) / 86400.0
            if age < _INDEX_TTL_DAYS and cached.get("paths"):
                return list(cached["paths"])
        except (OSError, ValueError, TypeError):
            pass  # a corrupt index is re-walked, not repaired

    paths: dict[str, None] = {}
    for facet, (label, required) in _FACETS.items():
        found = 0
        for page in range(_MAX_PAGES):
            url = _INDEX_URL.format(facet=facet, page=page)
            body = _get(url, timeout=60).decode("utf-8", "replace")
            fresh = [p for p in _harvest(body) if p not in paths]
            if not fresh:
                break
            for path in fresh:
                paths[path] = None
            found += len(fresh)

        if found == 0 and required:
            raise SourceError(
                f"the {label} facet at "
                f"{_INDEX_URL.format(facet=facet, page=0)} yielded no advisory "
                "links. The Drupal term id for the advisory type, the listing "
                "path or the detail-page URL shape has changed. This source "
                "will not quietly contribute zero narrative advisories: fix "
                "_FACETS or _SLUG_LINK at the top of this module."
            )

    index_file.parent.mkdir(parents=True, exist_ok=True)
    index_file.write_text(
        json.dumps({"fetched": time.time(), "paths": list(paths)}, indent=1),
        encoding="utf-8",
    )
    return list(paths)


def _fetch_advisories(root: Path, paths: list[str]) -> int:
    """Download every advisory page not already cached. Returns how many exist.

    An individual page may legitimately vanish — advisories are occasionally
    withdrawn or re-slugged — so one failure is recorded and skipped. A quarter
    of them failing is not bad luck, and stops the run.
    """
    directory = root / _ADVISORY_DIR
    directory.mkdir(parents=True, exist_ok=True)

    wanted = len(paths)
    failures: list[str] = []
    for path in paths:
        slug = path.rsplit("/", 1)[-1]
        target = directory / f"{slug}.html"
        if target.exists() and target.stat().st_size > 4096 and not _REFRESH:
            continue
        try:
            body = _get(f"https://www.cisa.gov{path}", timeout=90,
                        fatal_404=False)
        except SourceError:
            # Only a 403 reaches here, and a 403 is never about one page: the
            # edge has started refusing the handshake. Let it out with its own
            # message rather than counting it as a missing advisory.
            raise
        except NetworkError as exc:
            failures.append(f"{slug}: {exc}")
            continue
        tmp = target.with_suffix(".html.part")
        tmp.write_bytes(body)
        tmp.replace(target)

    if wanted and len(failures) > wanted * _MAX_FAILURE_RATE:
        raise SourceError(
            f"{len(failures)} of {wanted} advisory pages failed to download, "
            f"which is past the {_MAX_FAILURE_RATE:.0%} tolerance for a bad "
            "day. First few:\n  " + "\n  ".join(failures[:5])
        )
    if failures:
        print(f"   cisa: {len(failures)} advisory page(s) skipped "
              f"(e.g. {failures[0]})")

    return len(list(directory.glob("*.html")))


def _fetch_baselines(root: Path) -> int:
    """CISA's SCuBA secure configuration baselines, as raw Markdown from GitHub.

    Individually optional: the baseline set is renamed from time to time as
    products are added and retired, and losing one file is not worth failing a
    build. Losing all of them is, because it means the repository layout moved.
    """
    directory = root / _BASELINE_DIR
    directory.mkdir(parents=True, exist_ok=True)

    got = 0
    for name in _SCUBA_FILES:
        target = directory / f"{name}.md"
        if target.exists() and target.stat().st_size > 2048 and not _REFRESH:
            got += 1
            continue
        try:
            body = _plain_get(_SCUBA_RAW.format(name=name), timeout=60)
        except (SourceError, NetworkError) as exc:
            print(f"   cisa: baseline {name}.md unavailable ({exc})")
            continue
        target.write_bytes(body)
        got += 1

    if got == 0:
        raise SourceError(
            "none of the SCuBA baselines could be fetched from "
            f"{_SCUBA_RAW.format(name='<name>')}. cisagov/ScubaGear has moved "
            "its baselines directory or renamed its default branch."
        )
    return got


def _fetch(cache_dir: Path) -> Path:
    """Populate the cache and return its root. Idempotent and cheap on re-runs.

    ``build.py`` hands each source ``<cache>/<name>``, while a hand-run fetch
    from a shell one-liner almost always passes the cache root itself. Anchoring
    on a ``cisa/`` directory either way means both land in the same place, so a
    build after a manual verification run does not re-download 280 pages.
    """
    root = cache_dir if cache_dir.name == "cisa" else cache_dir / "cisa"
    root.mkdir(parents=True, exist_ok=True)

    version = _fetch_kev(root)
    paths = _fetch_index(root)
    advisories = _fetch_advisories(root, paths)
    baselines = _fetch_baselines(root)

    (root / _MANIFEST).write_text(json.dumps({
        "fetched": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "kev_url": _KEV_URL,
        "kev_catalog_version": version,
        "advisory_index": _INDEX_URL.format(facet="94", page=0),
        "advisory_paths_known": len(paths),
        "advisory_pages_cached": advisories,
        "baselines_cached": baselines,
        "license": _LICENSE,
    }, indent=1), encoding="utf-8")
    return root


# ---------------------------------------------------------------------------
# HTML to text
# ---------------------------------------------------------------------------

#: Class markers that start a body capture, outermost first.
#:
#: ``l-full__main`` is the layout region holding the article and nothing else:
#: the key-takeaways panel, then the rich-text sections from Summary through
#: Disclaimer, Version History and Notes. The related-advisory teasers, the tag
#: list and the product-survey widget all sit in the sibling ``l-full__footer``
#: and are therefore excluded by construction rather than by a deny-list of
#: things to strip, which is the difference between a rule that holds and a rule
#: that rots.
#:
#: The obvious choice — Drupal's ``c-field--name-body`` rich-text wrapper — is
#: kept only as a fallback, because on an advisory page it is *not* the
#: advisory. It appears seven times: the header promo bar, several footer
#: blocks, and the one-sentence "This product is provided subject to this
#: Notification" line. The article body itself is assembled from
#: ``l-page-section`` blocks that do not use it at all. Capturing every match
#: and keeping the longest makes the fallback safe on page types that do.
_BODY_MARKERS: tuple[str, ...] = ("l-full__main", "c-field--name-body")

#: Simple label/content field pairs in the page header. Narrow enough to read
#: with a regex because the markup is one non-nested div per field.
_FIELD = (r'c-field--name-field-{name}[^"]*">\s*'
          r'<div[^>]*c-field__label[^>]*>[^<]*</div>\s*'
          r'<div[^>]*c-field__content[^>]*>(.*?)</div>')
_H1 = re.compile(r"<h1[^>]*>(.*?)</h1>", re.S)
_TAGS = re.compile(r"<[^>]+>")

_HEADINGS = {"h1": "#", "h2": "##", "h3": "###",
             "h4": "####", "h5": "#####", "h6": "######"}
#: Tags that end the current line when they open or close. ``td`` and ``th`` are
#: absent on purpose — their content goes to a cell buffer, not to the page.
_BREAKS = {"p", "div", "section", "article", "header", "footer", "aside",
           "ul", "ol", "dl", "dt", "dd", "blockquote", "figure", "figcaption",
           "hr", "table", "tr", "h1", "h2", "h3", "h4", "h5", "h6"}
_DROP = {"script", "style", "noscript", "svg", "form", "button", "select",
         "iframe", "template"}

#: A bare superscript number is a footnote marker, and rendered as text it
#: glues a digit to the end of a word: "threat actors2 mostly using". Dropped
#: only when the superscript holds nothing but digits, so "1st" and "n²" survive.
_FOOTNOTE = re.compile(r"^\s*[\d,\s]*\s*$")


def _render_table(rows: list[list[str]], labelled: bool) -> str:
    """One HTML table as text, aligned when alignment can carry meaning.

    An indicator table — file name, hash, description — is a grid, and the grid
    is the information: reading down a column is how a responder uses it. Those
    are padded into real columns, which is also the surface form that scored
    best of anything in this project's tokenizer comparison.

    A mitigation table whose cells hold whole paragraphs is a grid only by
    accident of markup. Padding it produces lines hundreds of characters wide
    with the text of one cell scattered across them, so past
    :data:`_TABLE_MAX_WIDTH` each row is written out as labelled fields instead
    — which loses nothing, because there was no column structure to lose.

    ``labelled`` says whether the table declared a header row with ``<th>``, and
    it has to be asked rather than assumed. The obvious shortcut — treat row
    zero as the header — produces nonsense on CISA's "Advisory at a Glance"
    panel, which is a two-column key/value table with no header at all: its
    first row is ``Executive Summary | CISA began incident response efforts…``,
    and using that as a header labels the *next* row's bullet list with a whole
    paragraph of summary text. A two-column table with no header is exactly a
    key/value list and is rendered as one.
    """
    # Two views of the same cells. ``kept`` preserves the line structure inside
    # a cell — CISA builds its "Advisory at a Glance" panels out of table cells
    # containing whole bulleted lists, and flattening those turns three
    # recommendations into one run-on sentence. ``flat`` is the one-line form,
    # which is the only form a padded column can use.
    kept = [[re.sub(r"[ \t]*\n[ \t]*", "\n", cell).strip() for cell in row]
            for row in rows]
    kept = [row for row in kept if any(row)]
    if not kept:
        return ""
    flat = [[" ".join(cell.split()) for cell in row] for row in kept]

    columns = max(len(row) for row in flat)
    if columns == 1:
        return "\n".join(row[0] for row in kept)

    widths = [
        max((len(row[i]) if i < len(row) else 0) for row in flat)
        for i in range(columns)
    ]

    if sum(widths) + 2 * (columns - 1) <= _TABLE_MAX_WIDTH:
        lines = []
        for row in flat:
            cells = [(row[i] if i < len(row) else "") for i in range(columns)]
            lines.append("  ".join(
                cell.ljust(width) for cell, width in zip(cells, widths)
            ).rstrip())
        return "\n".join(lines)

    def _field_lines(label: str, cell: str) -> list[str]:
        """``label: first line``, with any further lines of the cell under it."""
        first, _, rest = cell.partition("\n")
        if label and first.startswith("- "):
            # The cell is a list. Its first item does not belong on the label's
            # line, where it would read as "Key Actions: - Prevent compromise".
            return [f"{label}:"] + [f"  {line}" for line in cell.split("\n") if line]
        out = [f"{label}: {first}" if label else first]
        out.extend(f"  {line}" for line in rest.split("\n") if line)
        return out

    lines: list[str] = []
    if labelled:
        header = flat[0]
        for row in kept[1:]:
            for i, cell in enumerate(row):
                if not cell:
                    continue
                label = (header[i] if i < len(header) and header[i]
                         else f"Column {i + 1}")
                lines += _field_lines(label, cell)
            lines.append("")
    elif columns == 2:
        for row in kept:
            key = " ".join(row[0].split()) if row else ""
            value = row[1] if len(row) > 1 else ""
            if not (key or value):
                continue
            lines += _field_lines(key, value)
            lines.append("")
    else:
        # No header and not a key/value pair: nothing names these columns, so
        # each row becomes its own small block rather than inventing labels.
        for row in kept:
            lines += [cell for cell in row if cell]
            lines.append("")

    return "\n".join(lines).strip() or "\n".join("  ".join(r) for r in flat)


class _Article(HTMLParser):
    """Render the advisory body field as text with its structure intact.

    Text nodes have their whitespace collapsed, which looks like exactly the
    thing :func:`~training.corpus.source.normalise` forbids and is not: the
    whitespace in an HTML text node is the CMS's source indentation, invisible
    in every renderer, and keeping it would produce a ragged mess rather than
    preserved alignment. The alignment that *is* meaning in an advisory lives in
    its tables, and this parser builds that alignment rather than inheriting it.
    Inside ``<pre>`` the source spacing is the author's and is kept byte for
    byte.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        #: Every finished body-field rendering. The advisory is the longest.
        self.blocks: list[str] = []
        self._out: list[str] = []
        self._capturing = False
        #: One entry per open ``<div>`` while capturing; True marks the div that
        #: started the capture, so the matching close is unambiguous however
        #: deeply Drupal nests its wrappers.
        self._divs: list[bool] = []
        self._drop = 0
        self._pre = 0
        self._sup: list[str] | None = None
        #: A stack, because an advisory occasionally nests a table inside a
        #: cell. Each entry is the table's rows and whether it ever used a
        #: ``<th>``, which is what tells :func:`_render_table` that row zero is
        #: a header and not data.
        self._tables: list[tuple[list[list[str]], list[bool]]] = []
        self._cell: list[str] | None = None

    # -- sinks ------------------------------------------------------------

    def _emit(self, text: str) -> None:
        if self._sup is not None:
            self._sup.append(text)
        elif self._cell is not None:
            self._cell.append(text)
        else:
            self._out.append(text)

    def _newline(self) -> None:
        """A line break into whichever sink is current.

        Table cells get them too. :func:`_render_table` decides per table
        whether to keep them — a padded column cannot, a labelled row can — and
        it can only make that choice if the breaks are still there to discard.
        A superscript is always one inline run and never takes a break.
        """
        if self._sup is not None:
            return
        sink = self._out if self._cell is None else self._cell
        if sink and sink[-1] == "- ":
            # CISA writes list items as <li><p>text</p></li>. The <p> would
            # otherwise put a line break between the bullet and its own text,
            # leaving every list in every advisory as alternating "-" and
            # orphaned sentences.
            return
        sink.append("\n")

    # -- parsing ----------------------------------------------------------

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _DROP:
            self._drop += 1
            return
        if self._drop:
            return

        if tag == "div":
            classes = dict(attrs).get("class") or ""
            starting = (not self._capturing
                        and any(marker in classes for marker in _BODY_MARKERS))
            if starting:
                self._capturing = True
                self._out = []
            self._divs.append(starting)

        if not self._capturing:
            return

        if tag == "pre":
            self._pre += 1
            self._newline()
        elif tag == "sup":
            self._sup = []
        elif tag == "table":
            self._tables.append(([], []))
            self._newline()
        elif tag == "tr" and self._tables:
            rows, headers = self._tables[-1]
            rows.append([])
            headers.append(False)
        elif tag in ("td", "th") and self._tables and self._tables[-1][0]:
            if tag == "th":
                self._tables[-1][1][-1] = True
            self._cell = []
        elif tag == "br":
            self._newline()
        elif tag == "li":
            self._newline()
            self._emit("- ")
        elif tag in _HEADINGS:
            self._newline()
            self._newline()
            self._emit(_HEADINGS[tag] + " ")
        elif tag in _BREAKS:
            self._newline()

    def handle_endtag(self, tag: str) -> None:
        if tag in _DROP:
            self._drop = max(0, self._drop - 1)
            return
        if self._drop:
            return

        if tag == "div":
            started = self._divs.pop() if self._divs else False
            if started:
                self.blocks.append("".join(self._out))
                self._out = []
                self._capturing = False
                # A body field never legitimately contains an unclosed table,
                # so anything still open belonged to markup we mis-tracked and
                # is dropped rather than leaked into the next block.
                self._tables.clear()
                self._cell = None
                return

        if not self._capturing:
            return

        if tag == "pre":
            self._pre = max(0, self._pre - 1)
            self._newline()
        elif tag == "sup":
            content = "".join(self._sup or ())
            self._sup = None
            if content and not _FOOTNOTE.match(content):
                self._emit(content)
        elif tag in ("td", "th"):
            if self._cell is not None and self._tables and self._tables[-1][0]:
                self._tables[-1][0][-1].append("".join(self._cell))
            self._cell = None
        elif tag == "table":
            if self._tables:
                rows, headers = self._tables.pop()
                rendered = _render_table(rows, bool(headers) and headers[0])
                if rendered:
                    # Into whatever sink is now current: a nested table belongs
                    # inside its enclosing cell, not at the top of the page.
                    self._emit("\n" + rendered + "\n")
            self._newline()
        elif tag in _HEADINGS or tag in _BREAKS:
            self._newline()

    def handle_data(self, data: str) -> None:
        if self._drop or not self._capturing:
            return
        if self._pre:
            self._emit(data)
            return
        if not data.strip():
            # Pure inter-tag indentation, but it may still be the single space
            # separating two inline elements, so it is not discarded outright.
            sink = self._out if self._cell is None else self._cell
            if self._sup is None and sink and not sink[-1].endswith((" ", "\n")):
                self._emit(" ")
            return
        self._emit(re.sub(r"\s+", " ", data))

    # -- result -----------------------------------------------------------

    def body(self) -> str:
        """The largest captured block, tidied.

        Largest rather than first: the promotional banners at the top of every
        CISA page use the same field wrapper as the advisory, and no banner has
        ever been longer than a joint advisory.
        """
        if not self.blocks:
            return ""
        best = max(self.blocks, key=len)
        best = re.sub(r"[ \t]*\n[ \t]*", "\n", best)
        return re.sub(r"\n{3,}", "\n\n", best).strip()


def _field(page: str, name: str) -> str:
    """One header field's rendered content, tags stripped. Empty if absent."""
    match = re.search(_FIELD.format(name=re.escape(name)), page, re.S)
    if not match:
        return ""
    return " ".join(_TAGS.sub(" ", match.group(1)).split())


def _title(page: str) -> str:
    match = _H1.search(page)
    if not match:
        return ""
    return " ".join(_TAGS.sub(" ", match.group(1)).split())


# ---------------------------------------------------------------------------
# documents
# ---------------------------------------------------------------------------

def _kev_documents(root: Path) -> Iterator[Document]:
    """One document per catalogued vulnerability.

    The lead sentence exists for a measured reason. Putting ``CVE-2024-21412``
    immediately beside the vendor, the product and the human name of the flaw,
    inside a sentence rather than in a field table, is the identifier-next-to-
    name form that took ATT&CK ids from -45% against gpt2 to +13% in this
    project's tokenizer comparison; the same argument applies to CVE ids, which
    scored -26% in that first measurement and are the reason
    :mod:`.nvd` exists.

    ``requiredAction`` is rendered on its own line and not folded into the
    prose. Most entries now share one long identical BOD-compliance paragraph,
    and :mod:`..boilerplate` removes text that recurs across many documents
    *line by line* — so giving it its own line lets the filter take exactly that
    paragraph out of the several hundred documents that repeat it, without
    taking a sentence of real description with it.
    """
    path = root / _KEV_FILE
    if not path.is_file():
        raise SourceError(
            f"{path} is missing. Run fetch() before documents(): this source "
            "will not pretend an empty cache is an empty catalogue."
        )
    data = json.loads(path.read_text(encoding="utf-8"))
    entries = data.get("vulnerabilities") or []
    if len(entries) < _KEV_MIN_ENTRIES:
        raise SourceError(
            f"{path} holds {len(entries)} entries, below the {_KEV_MIN_ENTRIES:,} "
            "floor. The cached catalogue is truncated; delete it and re-fetch."
        )

    # The catalogue version is deliberately not written into the documents. It
    # is identical across all 1,713 of them, which makes it 1,713 copies of one
    # date — too short for ..boilerplate's 40-character floor to remove, and
    # provenance the cache manifest already records properly.
    for entry in entries:
        cve = str(entry.get("cveID", "")).strip()
        if not cve:
            continue
        vendor = str(entry.get("vendorProject", "")).strip()
        product = str(entry.get("product", "")).strip()
        name = str(entry.get("vulnerabilityName", "")).strip()
        description = str(entry.get("shortDescription", "")).strip()
        added = str(entry.get("dateAdded", "")).strip()
        due = str(entry.get("dueDate", "")).strip()
        action = str(entry.get("requiredAction", "")).strip()
        ransomware = str(entry.get("knownRansomwareCampaignUse", "")).strip()
        cwes = [c for c in (entry.get("cwes") or []) if str(c).startswith("CWE-")]

        subject = f"{vendor} {product}".strip() or vendor or product or "the product"
        lead = f"{cve} is a known exploited vulnerability in {subject}"
        if name:
            lead += f", catalogued by CISA as {name}"
        lead += "."
        if added:
            lead += (f" CISA added {cve} to the Known Exploited Vulnerabilities "
                     f"catalogue on {added}")
            lead += f", with a remediation due date of {due}." if due else "."
        if ransomware and ransomware.lower() not in ("unknown", ""):
            lead += (f" It is known to have been used in ransomware campaigns "
                     f"({ransomware}).")

        lines = [f"{cve} {name}".strip(), ""]
        lines.append(f"CVE ID: {cve}")
        if vendor:
            lines.append(f"Vendor: {vendor}")
        if product:
            lines.append(f"Product: {product}")
        if cwes:
            lines.append(f"Weakness: {', '.join(cwes)}")
        if added:
            lines.append(f"Added to KEV: {added}")
        if due:
            lines.append(f"Remediation due: {due}")
        if ransomware:
            lines.append(f"Known ransomware campaign use: {ransomware}")

        lines += ["", lead]
        if description:
            lines += ["", description]
        if action:
            lines += ["", f"Required action: {action}"]

        notes = [n.strip() for n in
                 str(entry.get("notes", "")).split(";") if n.strip()]
        if notes:
            lines += ["", "References:"] + [f"  {n}" for n in notes[:6]]

        text = normalise("\n".join(lines))
        if len(text) < _MIN_KEV_CHARS:
            continue
        yield Document(text=text, source="cisa", register=Register.ADVISORY,
                       side=Side.BLUE, ident=f"kev/{cve}")


def _advisory_documents(root: Path) -> Iterator[Document]:
    """One document per cached advisory page: the narrative, whole.

    Nothing is summarised and no section is dropped. The value of these
    documents is that Summary, Technical Details, Indicators of Compromise,
    Mitigations and Validate Security Controls sit in one document in that
    order — an agent learning to write a report needs the shape of the whole
    thing, and a truncated advisory is a report with its recommendations cut off.
    """
    directory = root / _ADVISORY_DIR
    pages = sorted(directory.glob("*.html")) if directory.is_dir() else []
    if not pages:
        raise SourceError(
            f"no advisory pages under {directory}. The narrative advisories are "
            "the reason this source exists, so yielding only the KEV catalogue "
            "would be a silent half-failure. Run fetch(), and read the error it "
            "raises if it raises one."
        )

    for page_path in pages:
        try:
            page = page_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        parser = _Article()
        try:
            parser.feed(page)
            parser.close()
        except Exception:
            # html.parser is forgiving, but a half-written cache file is not
            # worth killing a build for: skip it and let the count guard below
            # notice if this stops being rare.
            continue
        body = parser.body()
        if len(body) < _MIN_ADVISORY_CHARS:
            continue

        slug = page_path.stem
        code = _field(page, "alert-code") or slug.upper()
        title = _title(page)
        released = _field(page, "release-date")
        revised = _field(page, "last-updated")

        header = [f"{code} {title}".strip(), "", f"Alert Code: {code}"]
        if title:
            header.append(f"Title: {title}")
        if released:
            header.append(f"Release Date: {released}")
        if revised:
            header.append(f"Last Revised: {revised}")
        header.append("Source: CISA Cybersecurity Advisory, "
                      f"https://www.cisa.gov/news-events/cybersecurity-advisories/{slug}")
        header.append("")

        text = normalise("\n".join(header) + "\n" + body)
        yield Document(text=text, source="cisa", register=Register.ADVISORY,
                       side=Side.BLUE, ident=f"advisory/{slug}")


#: Markdown image badges — ``[![Automated Check](https://img.shields.io/...)](...)``
#: — carry no text a reader would read aloud and two URLs each. Removed inline
#: so the sentence around them survives.
_BADGE = re.compile(r"\[!\[[^\]]*\]\([^)]*\)\](?:\([^)]*\))?")
#: The baselines annotate each policy with an HTML comment holding the policy id
#: and its criticality. The delimiters go; the identifiers stay, because
#: ``Policy: MS.AAD.3.2v2; Criticality: SHALL`` is exactly the id-next-to-meaning
#: join this corpus is short of.
_MD_COMMENT = re.compile(r"<!--\s*(.*?)\s*-->", re.S)
#: Sections that are legal furniture rather than guidance. Skipped by name
#: because there are only eight baseline files, which is far below the
#: cross-document threshold :mod:`..boilerplate` needs to spot them.
_BASELINE_SKIP = {"license compliance and copyright", "table of contents"}


def _baseline_documents(root: Path) -> Iterator[Document]:
    """CISA's SCuBA baselines, split into one document per policy group.

    Split at level-2 headings rather than emitted whole: ``aad.md`` alone is
    86 KB, and a single document that large is both an awkward training example
    and a large fraction of one source's share. A level-2 section is one policy
    group — "Strong Authentication and a Secure Registration Process" — with its
    policies, their rationales, their control mappings and the implementation
    steps that satisfy them, which is a coherent unit on its own.
    """
    directory = root / _BASELINE_DIR
    if not directory.is_dir():
        return

    for md_path in sorted(directory.glob("*.md")):
        raw = md_path.read_text(encoding="utf-8", errors="replace")
        raw = _BADGE.sub("", raw)
        raw = _MD_COMMENT.sub(r"\1", raw)

        document_title = ""
        for line in raw.splitlines():
            if line.startswith("# "):
                document_title = line[2:].strip()
                break

        sections: list[tuple[str, list[str]]] = []
        heading = ""
        buffer: list[str] = []
        for line in raw.splitlines():
            if line.startswith("## "):
                if buffer:
                    sections.append((heading, buffer))
                heading = line[3:].strip()
                buffer = []
            else:
                buffer.append(line)
        if buffer:
            sections.append((heading, buffer))

        for number, (title, body_lines) in enumerate(sections):
            if title.strip().lower() in _BASELINE_SKIP:
                continue
            head = f"{document_title} — {title}".strip(" —") if title else document_title
            block = "\n".join([
                head, "",
                f"Source: CISA SCuBA Secure Configuration Baseline, {md_path.name}",
                "",
                *body_lines,
            ])
            text = normalise(block)
            if len(text) < _MIN_BASELINE_CHARS:
                continue
            yield Document(text=text, source="cisa", register=Register.ADVISORY,
                           side=Side.BLUE,
                           ident=f"scuba/{md_path.stem}/{number:02d}")


def _documents(path: Path) -> Iterator[Document]:
    """Everything in the cache, KEV first, then the advisories, then baselines.

    The order is the order of confidence: KEV is a validated JSON file and
    cannot be half-parsed, the advisories are HTML from a CMS, and the baselines
    are Markdown from a repository that can rename its files. Failures in the
    first two raise; a missing baseline directory is a shrug.
    """
    root = path if path.name == "cisa" else path / "cisa"
    if not root.is_dir():
        raise SourceError(
            f"{root} does not exist. documents() was called against a cache "
            "fetch() never populated."
        )
    yield from _kev_documents(root)
    yield from _advisory_documents(root)
    yield from _baseline_documents(root)


_LICENSE = (
    "Public domain in the United States. CISA states no terms of use on "
    "cisa.gov — the site links list offers a linking policy and a privacy "
    "policy and no copyright page — so the operative rule is 17 U.S.C. § 105: "
    "a work prepared by an officer or employee of the US Government as part of "
    "that person's official duties is not subject to copyright protection. The "
    "advisories' own Disclaimer section disclaims endorsement of the vendors "
    "named in them and places no restriction on redistribution. The SCuBA "
    "secure configuration baselines are separately and explicitly released by "
    "CISA under CC0 1.0 Universal: "
    "https://github.com/cisagov/ScubaGear/blob/main/LICENSE"
)


SPEC = SourceSpec(
    name="cisa",
    license=_LICENSE,
    url="https://www.cisa.gov/cybersecurity-advisories",
    register=Register.ADVISORY,
    side=Side.BLUE,
    fetch=_fetch,
    documents=_documents,
    #: KEV alone is over 1,700 entries and has only grown since 2022; the
    #: advisories add ~260 and the baselines ~100. A floor of 1,500 refuses a
    #: run that lost the catalogue or lost the narrative half without noticing,
    #: while leaving room for CISA to retire advisories.
    expect_min_docs=1500,
    notes=("The KEV catalogue one document per CVE, every aa##-### joint "
           "advisory and ar##-### analysis report as full narrative with ATT&CK "
           "technique ids in prose and indicator tables kept aligned, and the "
           "SCuBA hardening baselines. The only source in the corpus shaped "
           "like the incident report the agent has to write. www.cisa.gov "
           "fingerprints the TLS ClientHello and refuses OpenSSL's default; see "
           "_context() for the workaround, which does not weaken verification."),
)
