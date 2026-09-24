"""English Wikipedia, computer science and security only. PROSE/NEUTRAL.

This adapter answers a hole the corpus can be measured to have. Scanning the
built v6 corpus for foundational concepts found them present, but only ever
*applied*::

    crypto primitives    3,056 docs (1.6%)   top: govguidance, ghsa, cisa
    TLS/PKI              4,569 docs (2.3%)   top: netrules, govguidance, nvd
    OS/memory concepts   4,449 docs (2.3%)   top: nvd, kerneldocs, attack
    networking basics    2,130 docs (1.1%)   top: rfc, cloudsec, govguidance

Every one of those top sources is a STIG, an advisory feed or a detection rule.
The model meets ``AES`` inside a CVE about a broken implementation of it, and
inside a STIG requiring it, and never once meets an explanation of what AES *is*.
The corpus is deep in application and empty in foundation, and a model that has
only ever seen a thing named cannot reason about it when the name changes.

**Why a curated slice rather than Wikipedia.** The whole of English Wikipedia is
roughly three billion tokens, and the corpus is data-limited — 146M tokens for a
61.5M-parameter model, where Chinchilla would want 1.2B. It is tempting to close
that gap here. It would be a mistake. Capacity is finite and currently spent
entirely on security; adding billions of tokens about football clubs and
medieval popes buys a model that is mediocre at general knowledge *and* worse at
security, because the security weights were diluted to make room. The answer to
data-limited for a specialist model is more domain data, never more general text.

So this takes ~2,900 articles from hand-picked categories, around 7% of the
corpus, and stops. The categories are listed in :data:`_SEEDS` and were sized
against the live API before being chosen, not guessed.

**Depth, and why it is not uniform.** Security and protocol categories descend
one level into their subcategories; the computer-science foundations do not.
This is not fussiness. Wikipedia's category graph is not a tree and it is not
curated for descent: ``Algorithms`` reaches pure mathematics in two hops and
philosophy in four, while ``Cryptographic protocols`` stays on topic because its
subcategories are things like ``Key-agreement protocols``. Depth is therefore a
property of the seed, set per seed, and :data:`_MAX_DEPTH` is a backstop rather
than the policy.

**Licence: CC BY-SA 4.0**, read from the API's own ``siteinfo`` rather than
assumed::

    action=query&meta=siteinfo&siprop=rightsinfo
    -> "Creative Commons Attribution-Share Alike 4.0"

Share-alike and attribution, the same terms as
:mod:`~training.corpus.sources.owasp`, and the attribution obligation is
honoured the same way: every document carries its article title and canonical
URL in the header, which is what CC BY-SA 4.0 section 3(a) asks for.

**Politeness is a design constraint here, not an afterthought.** Wikipedia rate
limits, and it does so quickly: eight rapid requests from one client were enough
to start returning HTTP errors during development. So this adapter sends a
descriptive User-Agent as the API policy requires, paces itself at
:data:`_DELAY` between calls, backs off on failure, and asks for extracts in
one article per request, because the API refuses to batch whole articles at all
(see :data:`_BATCH`). The result is a fetch measured in tens of minutes rather
than seconds, which is why :data:`SPEC` overrides the build-wide source timeout
— a budget written for a source that downloads one tarball is not a budget for
one that makes a few thousand paced requests.
"""

from __future__ import annotations

import json
import re
import time
import urllib.parse
from pathlib import Path
from typing import Iterator

from ..net import NetworkError, fetch
from ..source import Document, Register, Side, SourceError, SourceSpec

_API = "https://en.wikipedia.org/w/api.php"

#: The API policy asks for a descriptive agent naming the tool and a contact.
#: A generic urllib agent is refused outright.
_UA = ("whetstone-corpus/1.0 (security research corpus builder; "
       "https://github.com/at0m-b0mb)")

#: Seconds between API calls. Measured, not chosen: eight unpaced requests
#: during development were enough to start drawing HTTP errors.
_DELAY = 1.1

#: Titles per extracts request, and it is 1 by MediaWiki's rule rather than by
#: choice. ``prop=extracts`` allows ``exlimit`` above 1 **only** when
#: ``exintro`` is set — that is, only when you are asking for lead paragraphs.
#: Ask for whole articles and the API silently answers with the first one and
#: drops the rest: a batch of six titles came back holding exactly one article
#: during development, with no error and no warning. Batching here would have
#: quietly built a corpus of one article in six.
#:
#: So this pays one request per article. At :data:`_DELAY` that is about fifty
#: minutes for the whole seed list, once, cached forever after — which is what
#: :data:`SPEC`'s timeout override is sized for.
_BATCH = 1

#: A backstop on category descent, not the policy — see the module docstring.
_MAX_DEPTH = 1

#: An article shorter than this is a stub or a disambiguation page. Wikipedia
#: has a great many of both and neither teaches anything.
_MIN_CHARS = 1_200

#: Above this a single article is split at its own section headings, for the
#: same reason every other adapter here splits: the training window is 1024
#: tokens and an unsplit 80 KB article is a document the model only ever sees
#: the first eighth of.
_SPLIT_ABOVE = 8_000

#: ``(category, depth)``. Depth 1 descends one level into subcategories; depth 0
#: takes the category's own pages only. Counts beside each are the direct page
#: counts measured against the live API when this list was chosen.
_SEEDS: tuple[tuple[str, int], ...] = (
    # ---- Security core -------------------------------------------------
    # Depth chosen per seed after reading each one's actual subcategory list,
    # not by a rule. The counts beside each are direct pages, measured.
    ("Cryptography", 1),              # 31 subcats: algorithms, attacks, ciphers,
                                      # disk/E2E encryption. Biography and
                                      # contest subcats are blocked below.
    ("Computer network security", 1), # 8 subcats, nearly all on topic:
                                      # analyzers, firewalls, VPNs, email auth.
    ("Computer security", 1),         # 23 subcats. Good core, but a third are
                                      # organisations, conferences and country
                                      # articles — blocked below.
    ("Computer security exploits", 1),# 10 subcats and the best of the set:
                                      # injection, DoS, privesc, web shells,
                                      # transient-execution CPU vulnerabilities.
    ("Cryptographic protocols", 1),   # 9 subcats, every one on topic: TLS, SSH,
                                      # key agreement, zero-knowledge, mix nets.
    ("Public-key cryptography", 1),   # 11 subcats: signatures, ECC, PQC, PKI,
                                      # OpenPGP, attacks on public-key systems.
    ("Malware", 1),                   # 5 subcats. By type and by platform are
                                      # exactly right; 'Fiction about malware'
                                      # is blocked below, which is not a joke.
    ("Authentication methods", 1),    # 15 subcats, but over half are physical
                                      # and legal identity — seals, shibboleths,
                                      # ID documents. Heavily blocked below.
    # ---- Protocols and networking ---------------------------------------
    ("Network protocols", 1),         # 22 subcats: OSI layers, routing,
                                      # discovery. Vendor trees are blocked.
    ("Internet protocols", 1),        # 22 subcats: ARP, IPsec, link, MAC,
                                      # network layer. Strong throughout.
    ("Application layer protocols", 1),  # 36 subcats and the noisiest good
                                      # category: DNS, file transfer and clear
                                      # text protocols sit beside Bitcoin,
                                      # groupware and file-sharing software.
    ("Computer networking", 1),       # 17 subcats. Algorithms, booting,
                                      # standards kept; people, conferences,
                                      # organisations and download sites out.
    ("Wireless networking", 1),       # 16 subcats. Wi-Fi, Bluetooth, mesh,
                                      # packet radio, amateur radio — directly
                                      # the ground this project's RF hardware
                                      # works on. Vendor brands blocked.
    ("Computer network analysis", 1), # 2 subcats, both on topic.
    ("Transport layer protocols", 1), # 4 subcats: TCP, sockets, flow control,
                                      # error detection. All of them useful.
    # ---- Systems foundations ---------------------------------------------
    ("Operating system technology", 1),  # 31 subcats, and this one was
                                      # PROMOTED from depth 0 after reading it:
                                      # booting, device drivers, executable file
                                      # formats, interrupts, file systems,
                                      # command shells. That is where privilege
                                      # escalation and driver exploitation live,
                                      # and the corpus has almost none of it.
    ("Computer architecture", 1),     # 29 subcats. Kept for the CPU tree —
                                      # Spectre and Meltdown are architecture
                                      # bugs — with people and conferences out.
    # ---- Foundations, depth 0 --------------------------------------------
    # These three stay flat, and the subcategory listings are why.
    ("Algorithms", 0),                # 59 subcats including algorithmic art,
                                      # algorithmic trading, calendar algorithms
                                      # and bioinformatics. Descending here buys
                                      # a few checksum articles and a great deal
                                      # of mathematics.
    ("Data structures", 0),           # 19 subcats, nearly all academic:
                                      # amortized, kinetic, functional.
    ("Database management systems", 0),  # 27 subcats, mostly product listings
                                      # and 'by licence' groupings.
)

#: Subcategories refused by name, whatever seed reaches them. Depth decides how
#: far to walk; this decides where not to step. Every entry was read off the
#: live listing of the seed above it, so this is a record of what is actually
#: there rather than a guess at what might be.
#:
#: The rule behind the list: Wikipedia organises by *subject*, and a subject
#: category holds the people who work on it, the conferences they attend and the
#: companies that sell it, all beside the thing itself. Those are encyclopedia
#: articles about a field, not explanations of how the field works, and a model
#: learning post-exploitation gains nothing from a conference's attendance
#: history.
_SKIP_SUBCATS = frozenset({
    # People, events, organisations, geography — the biggest single class.
    "Cryptographers", "Cryptography contests", "Cryptologic education",
    "History of cryptography", "Computer security conferences",
    "Computer security organizations", "Computer security by country",
    "InfoSec Twitter", "Internet leaks", "Computer networking people",
    "Computer networking conferences", "Computer network organizations",
    "Computer architects", "Computer architecture conferences",
    # Lists and comparisons: tables of links, no prose.
    "Cryptography lists and comparisons", "Lists of database management software",
    # Vendor and product trees.
    "D-Link", "Netgear", "Cisco protocols", "Nortel protocols",
    "Download websites", "Online services", "File sharing software",
    "Bulletin board system software", "Clients (computing)", "Groupware",
    # Off-domain despite the parent.
    "Fiction about malware", "Swatting", "Controversial top-level domains",
    "Bitcoin", "Cryptocurrencies", "Algorithmic trading", "Algorithmic art",
    "Seals (insignia)", "Shibboleths", "Identity documents", "Age verification",
    "Identification friend or foe", "Authentication methods in Iran",
    "Caller ID", "Turing tests", "Signatures", "Personal identification",
    "Digital contact tracing protocols", "Audio network protocols",
    "Printing protocols", "Smart devices", "Mobile web",
    "Wireless display technologies", "Indoor positioning system",
    "Supercomputers by architecture",
    # Redirect and stub containers: no article text at all.
    "Redirects from Common Vulnerabilities and Exposures", "Malware stubs",
})

#: Namespaces and title shapes that are never article prose.
_SKIP_PREFIXES = ("List of ", "Index of ", "Outline of ", "Comparison of ",
                  "Timeline of ", "Glossary of ")

#: An article whose opening sentence says it is a company, a product brand or a
#: trade body, refused at document time rather than at title time. The category
#: blocklist above removes whole subcategories of these; this catches the ones
#: that sit directly inside a good category — ``NetCentrics`` under computer
#: security, ``Blockscale`` under cryptography, ``NANOG`` under networking.
#:
#: Matched against the lead sentence only, and deliberately narrow. A sample of
#: 30 articles from the resolved list read as roughly three quarters clearly
#: useful and a quarter corporate or vintage-hardware trivia, and the cost of
#: the two errors is not symmetric: dropping ``LibreSSL`` because its lead
#: mentions a company would lose real material, while keeping one article about
#: a Virginia contractor costs a few thousand characters of a 40M-character
#: source. So this only fires on phrasings observed in that sample, and when in
#: doubt it keeps the article.
_CORPORATE_LEAD = re.compile(
    r"\bis (?:a|an|the) [^.]{0,40}\b(?:company|corporation|subsidiary|vendor|"
    r"start-?up|trade association|trade group|industry (?:body|group|"
    r"association)|forum for|professional association)\b"
    r"|\bwas (?:a|an|the) [^.]{0,40}\b(?:company|corporation|brand of|"
    r"service from|home computer|personal computer)\b"
    r"|\bis a brand (?:of|name)\b"
    r"|\b(?:Inc|Corp|Ltd|LLC|GmbH)\.,? (?:based|headquartered)\b"
    # "NetCentrics Corporation, based in Herndon, Virginia, is a contractor to"
    # — the corporate marker and the verb sit on opposite sides of a clause, so
    # neither half above reaches it.
    r"|\b(?:Corporation|Incorporated|Holdings|Technologies|Systems|Labs),? "
    r"(?:based|headquartered)\b"
    r"|\bis (?:a|an|the) [^.]{0,40}\bcontractor\b",
    re.IGNORECASE)

_TITLES_FILE = "titles.json"
_PAGES_DIR = "pages"
_MARKER = ".fetched.json"


def _call(params: dict[str, str], attempts: int = 4) -> dict:
    """One paced, backed-off API call returning decoded JSON.

    Backs off rather than failing on the first error because the realistic
    failure here is a rate limit, and a rate limit answered by giving up throws
    away the hundreds of requests already spent.
    """
    params = {**params, "format": "json", "formatversion": "2"}
    url = f"{_API}?{urllib.parse.urlencode(params)}"
    last = ""
    for attempt in range(attempts):
        time.sleep(_DELAY if attempt == 0 else _DELAY * 4 * attempt)
        try:
            body = fetch(url, timeout=60, headers={"User-Agent": _UA})
        except NetworkError as exc:
            last = str(exc)
            continue
        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            last = f"undecodable JSON: {exc}"
    raise SourceError(f"wikipedia: {params.get('list') or params.get('prop')} "
                      f"failed after {attempts} attempts: {last}")


def _members(category: str, kind: str) -> list[str]:
    """Page or subcategory titles directly in ``category``."""
    out: list[str] = []
    cont: dict[str, str] = {}
    while True:
        data = _call({"action": "query", "list": "categorymembers",
                      "cmtitle": f"Category:{category}", "cmlimit": "500",
                      "cmtype": kind, **cont})
        out += [m["title"] for m in data.get("query", {}).get("categorymembers", [])]
        if "continue" not in data:
            return out
        cont = {k: v for k, v in data["continue"].items() if k != "continue"}


def _titles() -> list[str]:
    """Every article title the seeds resolve to, deduplicated and ordered.

    Deduplicated because the category graph is not a tree: ``Transport Layer
    Security`` sits under Cryptography, Cryptographic protocols and Internet
    protocols at once, and fetching it three times would spend three times the
    rate-limit budget to put one article into the corpus once.
    """
    seen: dict[str, None] = {}
    for category, depth in _SEEDS:
        categories = [category]
        if depth >= 1:
            for sub in _members(category, "subcat"):
                name = sub.removeprefix("Category:")
                if name in _SKIP_SUBCATS:
                    continue
                categories.append(name)
        for name in categories:
            for title in _members(name, "page"):
                if title.startswith(_SKIP_PREFIXES) or ":" in title.split(" ")[0]:
                    continue
                seen.setdefault(title, None)
    return list(seen)


def _extracts(titles: list[str]) -> Iterator[tuple[str, str]]:
    """Yield ``(title, plaintext)`` for a batch of titles.

    ``explaintext`` rather than parsing wikitext: the API renders the article
    and hands back plain prose, which removes an entire class of bug — template
    expansion, infobox markup, reference syntax — and a dependency with it.
    """
    data = _call({"action": "query", "prop": "extracts", "explaintext": "1",
                  "exlimit": str(len(titles)), "redirects": "1",
                  "titles": "|".join(titles)})
    for page in data.get("query", {}).get("pages", []):
        text = page.get("extract") or ""
        if text:
            yield page.get("title", ""), text


def _fetch(cache_dir: Path) -> Path:
    """Resolve the seed categories to titles, then fetch every extract.

    Two phases with two markers, because they fail differently: resolving
    categories is a few dozen requests and cheap to redo, while fetching a few
    thousand extracts is the expensive half and must never be repeated for
    pages already on disk. A build re-run costs nothing once ``_MARKER`` exists.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    if (cache_dir / _MARKER).is_file():
        return cache_dir

    titles_path = cache_dir / _TITLES_FILE
    if titles_path.is_file():
        titles = json.loads(titles_path.read_text())
    else:
        titles = _titles()
        if len(titles) < 1_000:
            # The seeds measured ~2,900 direct pages. Far under that means a
            # category was renamed or the API changed shape, and continuing
            # would quietly build a corpus of a few hundred articles that looks
            # like a deliberate choice.
            raise SourceError(
                f"wikipedia: seeds resolved to only {len(titles)} titles; "
                f"expected thousands — a seed category has probably been "
                f"renamed upstream")
        titles_path.write_text(json.dumps(titles, indent=1))

    pages = cache_dir / _PAGES_DIR
    pages.mkdir(exist_ok=True)
    pending = [t for t in titles
               if not (pages / f"{_slug(t)}.json").is_file()]
    for i in range(0, len(pending), _BATCH):
        batch = pending[i:i + _BATCH]
        for title, text in _extracts(batch):
            (pages / f"{_slug(title)}.json").write_text(
                json.dumps({"title": title, "text": text}, ensure_ascii=False))

    (cache_dir / _MARKER).write_text(json.dumps({
        "titles": len(titles),
        "pages": sum(1 for _ in pages.glob("*.json")),
        "license": "CC-BY-SA-4.0",
        "seeds": [c for c, _ in _SEEDS],
    }, indent=1))
    return cache_dir


def _slug(title: str) -> str:
    """A filesystem-safe name for a title, stable across runs."""
    return urllib.parse.quote(title.replace(" ", "_"), safe="")[:180]


def _url(title: str) -> str:
    return f"https://en.wikipedia.org/wiki/{urllib.parse.quote(title.replace(' ', '_'))}"


def _sections(text: str) -> list[tuple[str, str]]:
    """Split an extract at its own ``== Heading ==`` lines."""
    out: list[tuple[str, str]] = []
    head, body = "", []
    for line in text.split("\n"):
        stripped = line.strip()
        if stripped.startswith("==") and stripped.endswith("==") and len(stripped) > 4:
            if body:
                out.append((head, "\n".join(body).strip()))
            head, body = stripped.strip("= ").strip(), []
        else:
            body.append(line)
    if body:
        out.append((head, "\n".join(body).strip()))
    return [(h, b) for h, b in out if b]


#: Sections that are navigation rather than content. Dropped by name because
#: their names are stable across the whole encyclopedia, unlike their contents.
_DROP_SECTIONS = frozenset({
    "see also", "references", "external links", "further reading",
    "notes", "bibliography", "sources", "footnotes",
})


def _documents(path: Path) -> Iterator[Document]:
    pages = sorted((path / _PAGES_DIR).glob("*.json"))
    short = corporate = 0
    for page_file in pages:
        page = json.loads(page_file.read_text())
        title, text = page["title"], page["text"]
        if len(text) < _MIN_CHARS:
            short += 1
            continue
        if _CORPORATE_LEAD.search(text.split(". ")[0][:300]):
            corporate += 1
            continue

        header = [
            f"Wikipedia: {title}",
            f"Reference: {_url(title)}",
            # CC BY-SA 4.0 section 3(a): attribution travels with the text.
            "License: CC BY-SA 4.0, English Wikipedia contributors",
        ]
        sections = [(h, b) for h, b in _sections(text)
                    if h.lower() not in _DROP_SECTIONS]
        if not sections:
            short += 1
            continue

        if len(text) <= _SPLIT_ABOVE:
            body = "\n\n".join(f"{h}\n{b}" if h else b for h, b in sections)
            yield Document(text="\n".join(header) + "\n\n" + body,
                           source="wikipedia", register=Register.PROSE,
                           side=Side.NEUTRAL, ident=title)
            continue

        # Long article: one document per section group, each reopening with the
        # header so a window landing in part 4 still knows what it is reading.
        part, size, index = [], 0, 1
        for heading, body in sections:
            chunk = f"{heading}\n{body}" if heading else body
            if part and size + len(chunk) > _SPLIT_ABOVE:
                yield Document(
                    text="\n".join(header + [f"Part {index}"]) + "\n\n"
                         + "\n\n".join(part),
                    source="wikipedia", register=Register.PROSE,
                    side=Side.NEUTRAL, ident=f"{title}#{index}")
                part, size, index = [], 0, index + 1
            part.append(chunk)
            size += len(chunk)
        if part:
            yield Document(
                text="\n".join(header + [f"Part {index}"]) + "\n\n"
                     + "\n\n".join(part),
                source="wikipedia", register=Register.PROSE,
                side=Side.NEUTRAL, ident=f"{title}#{index}")

    if short or corporate:
        print(f"   wikipedia: {len(pages)} articles cached; held back {short} "
              f"under {_MIN_CHARS} chars or with no content section, "
              f"{corporate} company/product/trade-body article(s)")


SPEC = SourceSpec(
    name="wikipedia",
    license=(
        "CC-BY-SA-4.0 — English Wikipedia, read from the API's own "
        "action=query&meta=siteinfo&siprop=rightsinfo, which returns "
        "'Creative Commons Attribution-Share Alike 4.0'. Share-alike and "
        "attribution: every document carries its article title, canonical URL "
        "and the licence line, which is what section 3(a) requires. Only the "
        "computer-science and security categories listed in the module are "
        "taken; this is not a general Wikipedia dump."
    ),
    url="https://en.wikipedia.org/",
    register=Register.PROSE,
    side=Side.NEUTRAL,
    fetch=_fetch,
    documents=_documents,
    #: ~2,900 direct pages across the seeds, before depth-1 descent and before
    #: long articles split. The floor is deliberately far below the expectation:
    #: category membership on Wikipedia moves daily, and the regression worth
    #: catching is a seed renamed to nothing, which _fetch already refuses.
    expect_min_docs=1_500,
    #: MEASURED, after the first estimate was wrong by a factor of three and
    #: cost a build. The seeds resolve to 9,074 titles, not the ~2,900 the
    #: direct page counts suggested — depth-1 descent triples it — and the API
    #: refuses to batch whole articles, so it is 9,074 paced requests at
    #: _DELAY plus latency: about 3.2 hours cold. The v7 build allowed 5,400s,
    #: reached 3,827 pages, was killed, and the source was skipped entirely.
    #:
    #: Four hours, and the fetch is resumable by construction: every page is
    #: written as it arrives and `pending` skips what is already cached, so a
    #: build that dies here resumes where it stopped rather than restarting.
    #: That is what makes a budget this large safe rather than reckless.
    timeout=14_400,
    notes=(
        "Hand-picked computer-science and security categories only, never a "
        "general dump: the corpus is data-limited but a 61.5M-parameter model "
        "has finite capacity, and general text buys token count by diluting "
        "the domain. Security and protocol seeds descend one subcategory "
        "level; foundations do not, because Algorithms reaches pure "
        "mathematics in two hops. Articles over 8 KB split at their own "
        "section headings, each part reopening with title, URL and licence."
    ),
)
