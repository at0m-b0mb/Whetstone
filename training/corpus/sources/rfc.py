"""The IETF RFC series — the largest SYSTEM-register source there is.

9,825 protocol specifications in plain text, 506 MB of it, which is roughly four
times everything else in this corpus put together. It is the exact register
:mod:`training.corpus.source` says the first corpus was starved of, and the one
this model has to read fluently. An RFC is not prose *about* a protocol,
it is the protocol's surface form — header field names (``Content-Length``,
``Sec-WebSocket-Key``), ABNF grammars (``token = 1*tchar``), state-machine
tables (``SYN-SENT -> SYN-RECEIVED``), option/flag/opcode tables, port numbers,
status codes, packet diagrams drawn in ASCII, and the ``MUST``/``SHOULD``/``MAY``
vocabulary of RFC 2119. None of that appears anywhere else in written English,
and every one of those tokens is a token the model meets again the first time it
is asked to read a capture or reason about a service.

**There is no bulk tarball any more.** The brief for this adapter named
``https://www.rfc-editor.org/in-notes/tar/RFCs-all-txt.tar.gz`` and preferring it
was the right instinct; it is simply gone. That URL, ``…/tar/RFC-all.tar.gz``,
``…/rfc/tar/…``, the whole ``/in-notes/`` tree and ``ftp.rfc-editor.org`` all
answer 404 or do not connect as of this writing — the RFC Editor site is now a
Nuxt application that serves ``/rfc/rfcNNNN.txt`` and little else, and its own
"Download RFCs" page offers exactly one bulk method: ``rsync``. rsync is not an
option here, because :mod:`training.corpus.net` is the only door to the network
and shelling out to an unauthenticated rsync daemon for text the model will be
trained on is precisely the supply-chain shortcut that module exists to refuse.

So this fetches per-RFC over verified HTTPS, and being a good citizen is
engineered rather than hoped for: one 2 MB index request decides exactly which
files exist (no probing, no 404 storms), at most :data:`_WORKERS` requests are in
flight, every worker pauses :data:`_REQUEST_PAUSE` between requests, failures back
off exponentially, and every file lands in the cache atomically so the *second*
run costs zero requests. An interrupted fetch resumes; it does not restart.

Four things about RFC text are traps:

**Page furniture is the noise floor.** 8,412 of these documents were typeset for
a line printer: a form feed every 58 lines, a running footer (``Fielding, et al.
Standards Track  [Page 42]``) before it and a running header (``RFC 2616
HTTP/1.1   June 1999``) after it. That is two lines of pure boilerplate per page,
half a million pages over — 6.0% of the raw characters, 32 MB — and ``normalise``
cannot remove it: it strips the form feed as a control byte and leaves the header
and footer behind as text. They are stripped here, before ``normalise`` sees the
document. What is emphatically *not* touched is indentation: ABNF, packet
diagrams and state tables are load-bearing whitespace, and
:func:`~training.corpus.source.normalise` preserves it by contract.

**Modern RFCs have no pages at all.** The other 1,413 are unpaginated — RFC 9000
contains zero form feeds and zero ``[Page]`` markers — because from roughly RFC
8700 onward the canonical text output stopped being paginated. A stripper that
assumed pagination would be fine; one that *required* it would quietly mangle the
newest and most valuable seventh of the series. So the stripper is
frequency-driven per document and no-ops on a file with no form feed.

**The HTML in here is not residue.** A markup scan of the fetched series finds
angle-bracket tags in a hundred-odd documents, which in any scraped source would
be a rendering artefact to strip — the ATT&CK adapter left 1,014 ``<code>`` tags
in its text and they taught the model nothing. Here the worst offenders are RFC
1866 (180 tags), 1942 (165) and 2070 (57): the HTML specifications themselves,
quoting the language they define. The tags have a referent, they *are* the
document, and stripping them would delete the content. Nothing in this source is
de-marked-up, and the only reason that is safe is that it was checked rather than
assumed.

**The index promises text that is not there.** 55 entries are PostScript-era
documents whose ``Format:`` field still claims TXT; for 7 of them the text file
really is only a note — ``rfc1119.txt`` in its entirety is 143 bytes reading "is
available only in PostScript form". Those 7 are detected by content and dropped,
and the count is printed rather than silently absorbed.

**Licence.** RFCs are not public domain and not MIT. They are published under
BCP 78 / RFC 5378 and the IETF Trust Legal Provisions: the series may be
reproduced and distributed *in full*, and translated, by anyone; derivative works
outside the IETF standards process are restricted. Pre-2008 documents carry
their own equivalent Internet Society notice. Reproduction is permitted, which is
what this source needs; see the ``license`` field for the terms URL.
"""

from __future__ import annotations

import json
import re
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Iterator, NamedTuple

from ..net import NetworkError, download
from ..source import Document, Register, Side, SourceError, SourceSpec, normalise

#: The whole series in one 2 MB file: number, title, authors, date, available
#: formats, status and the obsoletes/updates graph. Fetching this first is what
#: makes the rest polite — it tells us exactly which numbers exist, so nothing
#: probes for RFCs that were never issued (188 of them) and nothing asks for a
#: format that is not published.
_INDEX_URL = "https://www.rfc-editor.org/rfc-index.txt"

#: The only bulk-ish endpoint the site still serves. ``{num}`` is unpadded.
_TEXT_URL = "https://www.rfc-editor.org/rfc/rfc{num}.txt"

#: Written last, and only after every file is on disk, so its presence means
#: "this cache is complete". Delete it to pick up newly published RFCs.
_MANIFEST = "manifest.json"
_INDEX_FILE = "rfc-index.txt"
_TEXT_DIR = "txt"

#: Bumped when the cache layout changes in a way that makes an old cache wrong.
_CACHE_VERSION = 1

#: Politeness, not throughput. Four connections with a 100 ms pause each measured
#: at 4.5 requests a second against a static, CDN-fronted text file — slower than
#: a person clicking through a directory listing — which put the whole series on
#: disk in 37 minutes. That happens once per machine, because the cache is
#: resumable and complete caches never touch the network again.
_WORKERS = 4
_REQUEST_PAUSE = 0.1
_ATTEMPTS = 4
_BACKOFF = 2.0
_TIMEOUT = 60

#: All 9,832 indexed text RFCs answered on the first run, so the tolerance here
#: is headroom rather than an observed rate. A *lot* of failures means something
#: else is wrong — rate limiting, a layout change, a captive portal — and a
#: corpus quietly missing a tenth of the RFC series is worse than a build that
#: stops and says so.
_MAX_MISSING_FRACTION = 0.02

#: A backstop, not the filter. The PostScript placeholders are ~140 characters
#: and :func:`_is_format_stub` already catches them by content; this only exists
#: so a truncated or empty file cannot reach the Document constructor.
#:
#: Deliberately far below the shortest real document rather than just below it.
#: The 1969 memos are tiny — RFC 18 is 512 characters of cleaned text, RFC 16 is
#: 565 — and they are genuine RFCs, so a floor set by eye at "about 500" would
#: sit one edit away from deleting the first year of the series. Measured over
#: the fetched cache, this drops nothing at all.
_MIN_CHARS = 300

#: A page break is a form feed. Everything else about pagination is inferred
#: per document, because the layout changed several times across 57 years.
_FORM_FEED = "\f"

#: The page marker, in every paginated RFC ever published. Deliberately not
#: anchored to the end of the line: the pre-1985 documents alternate sides, so
#: ``Postel  [Page 1]`` closes an odd page and ``[Page 2]  Postel`` *opens* the
#: even one. An end-anchored rule strips the first and leaves the second, which
#: is how RFC 821 kept 34 stray page numbers in the middle of its text. Applied
#: only to lines at a page boundary, so a body line that happens to contain the
#: phrase is never at risk.
_PAGE_MARK = re.compile(r"\[Page\s+\S+\]")

#: A whole line carrying that marker. Used to recover page boundaries in the
#: earliest RFCs, which paginate without ever emitting a form feed.
_FOOTER_LINE = re.compile(r"(?m)^[^\n]*\[Page\s+\S+\][^\n]*$")

_MONTHS = (
    "January|February|March|April|May|June|July|August|September|October"
    "|November|December"
)

#: A running header, recognised without needing frequency evidence. Both forms
#: must start at column 0, which is the discriminator that makes this safe:
#: RFC body text is indented three spaces, so a line flush against the left
#: margin is either a section heading (which matches neither alternative) or
#: page furniture.
#:
#: Form one is the modern header ``RFC 2616   HTTP/1.1   June 1999``; form two
#: is the 1980s header, which put a bare month and year on its own line above an
#: indented title (RFC 793 does this on all 91 of its pages).
_HEADER = re.compile(
    rf"^(?:RFC\s*-?\s*\d+\b.*\b(?:19|20)\d{{2}}\s*$"
    rf"|(?:{_MONTHS})\s+(?:19|20)\d{{2}}\s*$)"
)

#: A PostScript/PDF-only document's text placeholder.
_FORMAT_STUB = re.compile(
    r"(?i)(?:is\s+)?(?:only\s+)?available\s+(?:only\s+)?in\s+"
    r"(?:PostScript|PDF|\.?ps|\.?pdf)\b"
)

#: Digits are masked before a line is used as a repetition key, because the one
#: thing that varies in a running footer is the page number:
#: ``Klensin  Standards Track  [Page 7]`` and ``[Page 8]`` are the same furniture
#: and must count as the same line.
_DIGITS = re.compile(r"\d+")

#: Recognises a paragraph that ran over a page break, so the break can be closed
#: up instead of being turned into a paragraph boundary the document never had.
#:
#: Deliberately narrow, because the cost of a false positive here is two
#: paragraphs welded together. The previous page must end on a line that does not
#: end a sentence, and the next page must *resume* — an indented line beginning
#: with a lower-case letter or an opening parenthesis. That excludes section
#: headings and anything else flush with the left margin, excludes capitalised
#: sentence starts, and excludes the ``+``, ``|`` and digit rules that begin a
#: packet diagram or a table continued across a page.
#: ``}`` closes a MIB object definition, so it ends a unit of text even though it
#: ends no sentence. Relaxing ``_RESUMES`` to allow column 0 was tried and
#: measured: it would have closed up 1,716 more breaks, and the sample was
#: ``::= { dlswCircuitEntry 27 }`` welded onto the *next* OBJECT-TYPE definition,
#: plus routing-table rows in RFC 845/846 welded into each other. The indentation
#: requirement is what keeps those apart, and this character is the belt to its
#: braces.
_UNFINISHED = re.compile(r"[^.!?:;\"')\]}]$")
_RESUMES = re.compile(r"^ {2,}[a-z(]")


class _Entry(NamedTuple):
    """One row of the RFC index, reduced to what this adapter needs."""

    num: int
    title: str
    status: str
    #: True when a later RFC obsoletes this one. Carried purely so the build can
    #: *report* how much of the series is superseded revisions; nothing is
    #: dropped for it. See :func:`_documents`.
    superseded: bool


def _key(line: str) -> str:
    """Repetition key for a line: whitespace collapsed, digits masked.

    Collapsing whitespace here is safe and is *not* a corpus transformation —
    the key is thrown away and the original line is what survives or is dropped.
    ``normalise`` still sees the untouched text.
    """
    return _DIGITS.sub("#", " ".join(line.split()))


def _parse_index(raw: str) -> list[_Entry]:
    """Pull ``(number, title, status)`` out of ``rfc-index.txt``.

    The file is blank-line-separated blocks, each beginning with an unpadded RFC
    number at column 0 and wrapped at 72 columns, e.g.::

        2616 Hypertext Transfer Protocol -- HTTP/1.1. R. Fielding, et al.
             June 1999. (Format: TXT, PDF, HTML) (Obsoletes RFC2068)
             (Obsoleted by RFC7230) (Status: DRAFT STANDARD) (DOI: ...)

    Entries without ``TXT`` in their format list are dropped here rather than
    downloaded and discarded later: seven RFCs are PDF-only, and the point of
    reading the index at all is to not ask the server for things it does not
    have. ``Not Issued`` numbers (188 of them) go the same way.

    The title is taken as everything up to the first sentence-ending period,
    which is crude — a title containing an abbreviation loses its tail — and
    that is acceptable because the title is used only to group documents for the
    concentration cap, never as corpus text.
    """
    entries: list[_Entry] = []
    for block in re.split(r"\n\s*\n", raw):
        if not block or not block[0].isdigit():
            continue
        flat = " ".join(block.split())
        head, _, rest = flat.partition(" ")
        try:
            num = int(head)
        except ValueError:
            continue
        if rest.startswith("Not Issued"):
            continue
        formats = re.search(r"\(Format:\s*([^)]*)\)", flat)
        if not formats or "TXT" not in formats.group(1).upper():
            continue
        status = re.search(r"\(Status:\s*([^)]*)\)", flat)
        title = rest.split(". ", 1)[0].strip()
        entries.append(
            _Entry(num=num, title=title,
                   status=(status.group(1).strip() if status else "UNKNOWN"),
                   superseded="(Obsoleted by " in flat)
        )
    return entries


def _download_one(entry: _Entry, text_dir: Path) -> bool:
    """Fetch one RFC into the cache. True if it is now on disk.

    Retries with exponential backoff, because a single transient failure in a
    9,800-request run must not cost the whole fetch — but a 404 is answered
    immediately rather than retried three times, since the index promising a
    text file the server does not have is a fact about the document, not a
    transient. :class:`~training.corpus.net.NetworkError` flattens the HTTP
    status into its message, so that is where the check has to look.
    """
    target = text_dir / f"rfc{entry.num}.txt"
    if target.is_file():
        return True
    delay = _BACKOFF
    for attempt in range(_ATTEMPTS):
        try:
            # download() writes a .part sibling and renames, so an interrupt
            # cannot leave a truncated file that the resume logic would mistake
            # for a complete one.
            download(_TEXT_URL.format(num=entry.num), target, timeout=_TIMEOUT)
            time.sleep(_REQUEST_PAUSE)
            return True
        except NetworkError as exc:
            if "HTTP 404" in str(exc):
                return False
            if attempt == _ATTEMPTS - 1:
                return False
            time.sleep(delay)
            delay *= 2
    return False


def _cache_is_complete(cache_dir: Path) -> bool:
    """True when a previous fetch finished and its files are still there.

    The manifest alone is not evidence. A cache copied between volumes, or
    half-cleaned, leaves ``manifest.json`` intact while ``txt/`` is gone, and
    every downstream guard is perfectly happy with that: the JSON parses, it
    lists 9,800 documents, and the source then yields nothing while the build
    reports success. One stat per entry is cheap; a silent hole in the largest
    register in the corpus is not.
    """
    manifest_path = cache_dir / _MANIFEST
    if not manifest_path.is_file():
        return False
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if manifest.get("version") != _CACHE_VERSION:
        return False
    rfcs = manifest.get("rfcs", ())
    if not rfcs:
        return False
    return all((cache_dir / row["file"]).is_file() for row in rfcs)


def _fetch(cache_dir: Path) -> Path:
    """Populate ``cache_dir`` with the RFC series as plain text.

    Idempotent: a complete cache returns before a single byte crosses the
    network. Resumable: files already present are skipped, so an interrupted run
    continues where it stopped instead of re-downloading 536 MB. Everything is
    written under ``cache_dir`` and nowhere else.

    To pick up RFCs published since the last run, delete ``manifest.json`` — the
    individual text files are kept, only the new numbers are fetched, and the
    whole thing takes under a second plus the index request (measured).
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    if _cache_is_complete(cache_dir):
        return cache_dir

    text_dir = cache_dir / _TEXT_DIR
    text_dir.mkdir(parents=True, exist_ok=True)

    index_path = cache_dir / _INDEX_FILE
    try:
        download(_INDEX_URL, index_path, timeout=_TIMEOUT)
    except NetworkError as exc:
        raise SourceError(f"rfc: could not fetch the index: {exc}") from None

    entries = _parse_index(index_path.read_text(encoding="utf-8", errors="replace"))
    if len(entries) < 5000:
        raise SourceError(
            f"rfc: {_INDEX_URL} parsed to only {len(entries)} text RFCs "
            "(expected ~9,800). The index format has changed; fix the parser "
            "rather than training on a fragment of the series."
        )

    pending = [e for e in entries if not (text_dir / f"rfc{e.num}.txt").is_file()]
    if pending:
        print(f"   rfc: fetching {len(pending)} of {len(entries)} RFCs "
              f"({len(entries) - len(pending)} already cached)")

    missing: list[int] = []
    done = 0
    with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
        for entry, ok in zip(pending, pool.map(
                lambda e: _download_one(e, text_dir), pending)):
            done += 1
            if not ok:
                missing.append(entry.num)
            if done % 500 == 0:
                print(f"   rfc: {done}/{len(pending)} fetched, "
                      f"{len(missing)} unavailable")

    # download() leaves a .part sibling behind when it is interrupted mid-write.
    # Nothing downstream reads them — documents() walks the manifest, not the
    # directory — but a cache that accumulates partial files across interrupted
    # runs is a cache nobody trusts.
    for leftover in text_dir.glob("*.txt.part"):
        leftover.unlink(missing_ok=True)

    present = [e for e in entries if (text_dir / f"rfc{e.num}.txt").is_file()]
    absent = len(entries) - len(present)
    if absent > max(60, int(len(entries) * _MAX_MISSING_FRACTION)):
        raise SourceError(
            f"rfc: {absent} of {len(entries)} indexed RFCs could not be "
            "fetched. That is more than the handful of PostScript-era documents "
            "expected to be missing — suspect rate limiting or a site change. "
            "The cache is resumable, so re-running is cheap once the cause is "
            "fixed; it is deliberately not written as complete."
        )

    (cache_dir / _MANIFEST).write_text(
        json.dumps(
            {
                "version": _CACHE_VERSION,
                "index_url": _INDEX_URL,
                "text_url": _TEXT_URL,
                "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "indexed": len(entries),
                "unavailable": sorted(missing),
                "rfcs": [
                    {
                        "num": e.num,
                        "ident": f"rfc{e.num}",
                        "file": f"{_TEXT_DIR}/rfc{e.num}.txt",
                        "title": e.title,
                        "status": e.status,
                        "superseded": e.superseded,
                    }
                    for e in present
                ],
            },
            indent=1,
        ),
        encoding="utf-8",
    )
    return cache_dir


def _strip_pagination(text: str) -> str:
    """Remove running headers, running footers and page breaks.

    The layout of an RFC page has been stable for decades but not uniform, so
    this infers the furniture from the document itself instead of hard-coding a
    shape. Split on form feeds; look at the first two non-blank lines of each
    page and the last non-blank line; a line that recurs in that *position*
    across the majority of pages is furniture by construction, whatever it says.
    That handles the modern one-line header (``RFC 2616  HTTP/1.1  June 1999``)
    and the 1980s two-line header (a bare ``September 1981`` above an indented
    title) with the same rule, and it handles footers once page numbers are
    masked out of the key.

    Two unconditional rules back the frequency test up for short documents,
    where nothing can repeat often enough to be evidence: a boundary line
    carrying ``[Page N]`` is always furniture, and :data:`_HEADER` is always a
    header.

    Documents with no form feed *and* no page marker — everything published
    since roughly RFC 8700 — return unchanged. Their canonical text is
    unpaginated and there is nothing here to remove.
    """
    if _FORM_FEED in text:
        pages = text.split(_FORM_FEED)
    elif _FOOTER_LINE.search(text):
        # The first few hundred RFCs were typed, not typeset: they paginate
        # with a ``[Page 3]`` line and a running header and never emit a form
        # feed. Splitting on the marker line itself recovers the same page
        # structure, and drops that line in the same move.
        pages = _FOOTER_LINE.split(text)
    else:
        return text
    if len(pages) < 2:
        return text

    def first_lines(page: str, count: int) -> list[str]:
        lines = page.split("\n")
        while lines and not lines[0].strip():
            lines.pop(0)
        return lines[:count]

    def last_line(page: str) -> str:
        lines = page.split("\n")
        while lines and not lines[-1].strip():
            lines.pop()
        return lines[-1] if lines else ""

    # Positional counters. Headers are counted over pages[1:] because page one
    # carries the document's title block, not a running head.
    head0: Counter[str] = Counter()
    head1: Counter[str] = Counter()
    foot: Counter[str] = Counter()
    for page in pages[1:]:
        lines = first_lines(page, 2)
        if lines:
            head0[_key(lines[0])] += 1
        if len(lines) > 1:
            head1[_key(lines[1])] += 1
    for page in pages:
        tail = last_line(page)
        if tail:
            foot[_key(tail)] += 1

    # A majority of pages, and at least two of them. One repetition is a
    # coincidence; half the document is a template.
    threshold = max(2, len(pages) // 2)
    header_keys = {k for k, n in head0.items() if n >= threshold}
    subhead_keys = {k for k, n in head1.items() if n >= threshold}
    footer_keys = {k for k, n in foot.items() if n >= threshold}

    cleaned: list[str] = []
    for position, page in enumerate(pages):
        lines = page.split("\n")

        if position:  # page one has no running header above its title block
            for depth in range(2):
                while lines and not lines[0].strip():
                    lines.pop(0)
                if not lines:
                    break
                key = _key(lines[0])
                is_furniture = (
                    key in header_keys
                    if depth == 0
                    else key in subhead_keys
                ) or bool(_PAGE_MARK.search(lines[0])) or (
                    depth == 0 and bool(_HEADER.match(lines[0]))
                )
                if not is_furniture:
                    break
                lines.pop(0)

        while lines and not lines[-1].strip():
            lines.pop()
        if lines and (_key(lines[-1]) in footer_keys
                      or _PAGE_MARK.search(lines[-1])):
            lines.pop()

        body = "\n".join(lines).strip("\n")
        if body.strip():
            cleaned.append(body)

    # A page break is not a paragraph break, and joining every page with a blank
    # line asserts that it is. Measured over the fetched series, that put a
    # paragraph boundary into the middle of 35,727 sentences across 6,331
    # documents — RFC 8083 reads "...suboptimal for the media quality unless
    # the" / blank / "transport protocol is designed to..." — teaching the model
    # that a paragraph can end mid-clause, which is precisely the kind of
    # invented structure this corpus is supposed to avoid. Joining everything
    # with a single newline instead is the opposite error: it welds the last
    # paragraph of a page onto the first paragraph of the next, and the page
    # bodies are multi-line strings, so nothing is ever welded *onto the line
    # above* whichever separator is used.
    #
    # So the separator is decided per break, and only an unambiguous
    # continuation is closed up. Everything else keeps the blank line.
    if not cleaned:
        return ""
    joined = [cleaned[0]]
    for body in cleaned[1:]:
        tail = joined[-1].rsplit("\n", 1)[-1]
        head = body.split("\n", 1)[0]
        joined.append(
            "\n" + body
            if _UNFINISHED.search(tail) and _RESUMES.match(head)
            else "\n\n" + body
        )
    return "".join(joined)


def _decode(raw: bytes) -> str:
    """Decode an RFC, tolerating the pre-Unicode half of the series.

    Modern RFCs are UTF-8 with a BOM (``utf-8-sig`` eats it; leaving it in would
    put a zero-width no-break space at the head of a thousand documents). Older
    ones are ASCII, and a handful carry stray Latin-1 bytes in an author's name.
    ``latin-1`` cannot fail, so it is the floor — better one mojibake character
    in a name than ``errors="replace"`` scattering U+FFFD through a document.
    """
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _is_format_stub(text: str) -> bool:
    """True for the placeholder left where an RFC exists only as PostScript.

    ``rfc1119.txt`` in full: *RFC-1119 "Network Time Protocol (Version 2)
    Specification and Implementation" is available only in PostScript form in
    the file RFC1119.PS*. The index still lists TXT for these, so the only way
    to find them is to read them. The length bound keeps the rule from catching
    a genuine RFC that happens to discuss PostScript availability.
    """
    return len(text) < 2000 and bool(_FORMAT_STUB.search(text))


#: No single topic family may exceed this share of the source's characters.
#:
#: Measured over the whole fetched series, on cleaned characters: routing
#: (BGP/MPLS/OSPF/IS-IS/SRv6/PCE) 11.5%, crypto 7.0%, data models (MIB, YANG,
#: SNMP) 6.6%, addressing 6.1%, real-time media 6.1%, transport 4.6%, email 3.5%,
#: web 3.0%, DNS 2.6%, and 49.1% with no recognisable keyword at all. The largest
#: single *document* is RFC 8881 (NFSv4.1) at 0.31%.
#:
#: So nothing here is close to the runaway concentration this rule exists for —
#: manpages gave 54% of its characters to Perl and Tcl API reference — and this
#: cap holds back nothing today. It is kept anyway, because the series grows by
#: ~300 RFCs a year and that growth is not uniform: YANG modules and SRv6 are
#: the families visibly accelerating, and a cap discovered by hand two years
#: from now is a cap that did not work. The observed share is printed on every
#: build (see :func:`_documents`) so the day it starts to bind is visible.
_FAMILY_CAP = 0.15

#: Ordered, first match wins: a "BGP YANG module" is routing before it is a data
#: model, because the routing family is the larger concentration risk. Matched
#: against the index title only, which is the one piece of metadata that exists
#: for all 9,800 documents without parsing them.
_FAMILIES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("routing", ("BGP", "MPLS", "OSPF", "IS-IS", "ISIS", "RSVP", "LDP", "PCE",
                 "PCEP", "SRv6", "Segment Routing", "RIP", "EIGRP", "BFD",
                 "VPN", "EVPN", "Routing", "Router", "Traffic Engineering")),
    ("datamodel", ("MIB", "Management Information Base", "YANG", "SMI",
                   "NETCONF", "RESTCONF", "SNMP")),
    ("email", ("Mail", "SMTP", "IMAP", "POP3", "MIME", "Message Format",
               "DKIM", "SPF", "Messaging")),
    ("web", ("HTTP", "URI", "URL", "WebSocket", "HTML", "CoAP", "REST",
             "Hypertext", "Web")),
    ("crypto", ("TLS", "Cryptographic", "Cipher", "Encryption", "Key Exchange",
                "Certificate", "X.509", "PKIX", "S/MIME", "Signature", "Hash",
                "OAuth", "JOSE", "JSON Web", "Kerberos", "IPsec", "IKE",
                "SSH", "OpenPGP", "Post-Quantum")),
    ("dns", ("DNS", "Domain Name", "DNSSEC", "Resource Record", "RDAP",
             "WHOIS", "Registry")),
    ("realtime", ("SIP", "RTP", "RTCP", "SDP", "Codec", "Telephony", "Voice",
                  "Media Type Registration", "WebRTC", "Audio", "Video")),
    ("addressing", ("IPv6", "IPv4", "DHCP", "ICMP", "NAT", "Address",
                    "Neighbor Discovery")),
    ("transport", ("TCP", "UDP", "QUIC", "SCTP", "Congestion", "Transport")),
)


#: Each family's keywords as one alternation, bounded so a keyword only matches
#: a whole word.
#:
#: The boundaries are not tidiness, they are the difference between a
#: classifier and a random number generator. Written first as a plain substring
#: test, this put "The Transmission Control Protocol" in *datamodel* — because
#: ``TRAN-SMI-SSION`` contains ``SMI`` — and every RFC with "Security" in its
#: title in *web*, because ``SEC-URI-TY`` contains ``URI``. ``RIP`` inside
#: "Description", ``NAT`` inside "Alternate" and ``REST`` inside "Restrictions"
#: did the same. A cap computed from those groups would have held back exactly
#: the wrong documents, and nothing downstream would have contradicted it.
#: ``\b`` is avoided in favour of explicit lookaround because several keywords
#: end in punctuation (``X.509``, ``S/MIME``), where ``\b`` asserts the opposite
#: of what is wanted.
_FAMILY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (
        family,
        re.compile(
            r"(?<![A-Za-z0-9])(?:"
            + "|".join(re.escape(k) for k in keywords)
            + r")(?![A-Za-z0-9])",
            re.IGNORECASE,
        ),
    )
    for family, keywords in _FAMILIES
)


def _family(title: str) -> str:
    """Group a document by topic for the concentration cap.

    Whole-word keyword matching on the title, deliberately crude. A classifier
    good enough to argue about would be a second thing to keep correct, and the
    cap only needs to catch families large enough to distort a register — which,
    by construction, are families with an obvious name in their titles.
    """
    for family, pattern in _FAMILY_PATTERNS:
        if pattern.search(title):
            return family
    return "other"


def _over_cap(path: Path, rows: list[dict]) -> dict[str, str]:
    """Decide which documents a family cap holds back: ``{ident: family}``.

    Sizes come from ``stat`` rather than from reading and cleaning everything
    twice. File size over-counts a paginated RFC by the 6% of page furniture this
    source strips, uniformly enough across families that it does not change which
    family is over the line.

    **Newest first.** Within a capped family the budget is spent on the highest
    RFC numbers, so what survives is the current specification and what is held
    back is the superseded edition. Deciding this here, before iteration, is the
    reason: yielding in ascending order and stopping at the budget would have
    filled the quota with 1988 routing memos and dropped modern BGP — a cap that
    fires in exactly the wrong direction is worse than no cap, because it looks
    like curation.

    ``other`` is exempt. It is not a topic — it is the 49% of the series with no
    recognisable keyword in its title, and capping it would hold back the most
    diverse documents in the source in order to protect the corpus from variety.
    That is the same mistake, in the same place, that once capped ``section:man1``
    in the man page adapter and held back 512 pages of core command documentation.
    """
    sized: list[tuple[int, str, str, int]] = []   # num, ident, family, bytes
    sizes: dict[str, int] = {}
    total = 0
    for row in rows:
        try:
            size = (path / row["file"]).stat().st_size
        except OSError:
            continue
        family = _family(row["title"])
        sized.append((row["num"], row["ident"], family, size))
        sizes[family] = sizes.get(family, 0) + size
        total += size
    if not total:
        return {}

    cap = int(total * _FAMILY_CAP)
    capped = {f for f, size in sizes.items() if size > cap and f != "other"}
    if not capped:
        return {}

    spent: dict[str, int] = {}
    held: dict[str, str] = {}
    for num, ident, family, size in sorted(sized, reverse=True):
        if family not in capped:
            continue
        # A capped family is thinned, never erased: its newest document is
        # admitted even if it alone exceeds the budget. Without this, a family
        # whose single largest document is bigger than the cap disappears from
        # the corpus entirely — a rule meant to limit a topic silently deleting
        # it is the worst outcome available.
        if family in spent and spent[family] + size > cap:
            held[ident] = family
        else:
            spent[family] = spent.get(family, 0) + size
    return held


def _documents(path: Path) -> Iterator[Document]:
    """Yield one Document per RFC, in ascending RFC number.

    Reads only the cache and its manifest, never the network and never the
    filesystem at large: no directory walk, therefore no symlink to follow, and
    the set of documents is exactly the set :func:`_fetch` recorded.
    """
    manifest_path = path / _MANIFEST
    if not manifest_path.is_file():
        raise SourceError(f"rfc: no manifest at {manifest_path}; run fetch first")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    rows = sorted(manifest.get("rfcs", ()), key=lambda r: r["num"])
    held_back = _over_cap(path, rows)
    dropped: dict[str, int] = {}
    family_chars: dict[str, int] = {}
    stubs = 0
    tiny = 0
    superseded = 0
    superseded_chars = 0
    kept_chars = 0

    for row in rows:
        file = path / row["file"]
        try:
            raw = file.read_bytes()
        except OSError as exc:
            # Not skippable: the manifest is this source's own record of what it
            # fetched, so an unreadable entry means a damaged cache, and quietly
            # dropping it would shrink the SYSTEM register by an unknown amount
            # while the build reported success.
            raise SourceError(
                f"rfc: manifest lists {row['ident']} at {file}, which could not "
                f"be read. The cache is damaged; delete {path} and re-fetch."
            ) from exc

        text = _decode(raw)
        if _is_format_stub(text):
            stubs += 1
            continue
        text = normalise(_strip_pagination(text))
        if len(text) < _MIN_CHARS:
            tiny += 1
            continue

        family = held_back.get(row["ident"])
        if family is not None:
            dropped[family] = dropped.get(family, 0) + 1
            continue

        kept_chars += len(text)
        topic = _family(row["title"])
        family_chars[topic] = family_chars.get(topic, 0) + len(text)
        if row.get("superseded"):
            superseded += 1
            superseded_chars += len(text)

        yield Document(
            text=text,
            source="rfc",
            register=Register.SYSTEM,
            side=Side.NEUTRAL,
            ident=row["ident"],
        )

    # Nothing held back in silence: a cap that is not reported reads as coverage
    # the corpus does not have.
    if stubs:
        print(f"   rfc: skipped {stubs} PostScript/PDF-only placeholder(s)")
    if tiny:
        print(f"   rfc: skipped {tiny} file(s) under {_MIN_CHARS} chars")
    for family, count in sorted(dropped.items(), key=lambda kv: -kv[1]):
        print(f"   rfc: held back {count} '{family}' RFC(s) at the "
              f"{_FAMILY_CAP:.0%} per-family cap (oldest first; the current "
              "specifications are the ones kept)")
    topics = {f: n for f, n in family_chars.items() if f != "other"}
    if topics and kept_chars:
        # Printed whether or not the cap fired. A concentration rule that only
        # speaks when it triggers gives no warning as a family climbs toward the
        # line, which is the whole period in which acting is cheap.
        top, size = max(topics.items(), key=lambda kv: kv[1])
        print(f"   rfc: largest topic family '{top}' at "
              f"{size / kept_chars:.0%} of characters (cap {_FAMILY_CAP:.0%})")
    if superseded and kept_chars:
        # Disclosed rather than dropped, and this is the one number that would
        # justify revisiting that. A revision does not copy its predecessor but
        # it does quote it: measured on 8-word shingles, RFC 1725 -> 1939 (POP3)
        # repeats 64% of the newer document and RFC 2068 -> 2616 (HTTP/1.1) 61%,
        # while a generational rewrite twenty years apart, RFC 821 -> 2821
        # (SMTP), repeats only 21%. Fingerprint dedup in build.py cannot see any
        # of it, because a rewritten document hashes to something new. They are
        # kept because a superseded protocol is still protocol text the model
        # will meet in the wild — old equipment outlives its RFC — and because
        # deleting a sixth of the series to avoid partial overlap trades
        # certain volume for speculative purity.
        print(f"   rfc: {superseded} of the yielded RFCs are superseded "
              f"revisions ({superseded_chars / kept_chars:.0%} of characters), "
              "kept deliberately — they partially repeat their successors")


SPEC = SourceSpec(
    name="rfc",
    license=(
        "IETF Trust Legal Provisions (BCP 78 / RFC 5378) — "
        "https://trustee.ietf.org/license-info . RFCs may be reproduced and "
        "distributed in full by anyone, and translated; derivative works "
        "outside the IETF standards process are restricted. Pre-2008 documents "
        "carry the equivalent Internet Society notice. Not public domain, not "
        "an SPDX open-source licence."
    ),
    url="https://www.rfc-editor.org/rfc/",
    register=Register.SYSTEM,
    side=Side.NEUTRAL,
    fetch=_fetch,
    documents=_documents,
    #: 9,832 RFCs were indexed with a text format when this was written and
    #: 9,825 yielded documents (7 are PostScript-era placeholders). The floor
    #: sits well below that, so a partial cache or a site change is loud rather
    #: than merely thinner.
    expect_min_docs=9000,
    notes=(
        "9,825 documents, 506 MB, measured. Per-RFC HTTPS fetch: the bulk "
        "tarball named in the brief (in-notes/tar/RFCs-all-txt.tar.gz) is 404, "
        "as is the whole /in-notes/ tree, and the RFC Editor now offers only "
        "rsync for bulk, which would bypass training.corpus.net. One index "
        "request decides what to ask for, 4 workers with a 100 ms pause each do "
        "the asking (4.5 req/s, 37 minutes once), and the cache is resumable. "
        "Page furniture (form feeds, '[Page N]' footers, 'RFC 2616  HTTP/1.1  "
        "June 1999' headers) is stripped by a per-document frequency rule before "
        "normalise() — 6% of the raw characters — while indentation is untouched, "
        "because ABNF, packet diagrams and state tables are the reason this "
        "source exists. The 1,413 RFCs published since ~8700 are unpaginated and "
        "pass through unchanged. HTML tags appear only where an RFC specifies "
        "HTML (1866, 1942, 2070), so nothing is de-marked-up. 1,382 of the "
        "documents are superseded revisions that partially repeat their "
        "successors (17% of characters); kept deliberately and reported."
    ),
)
