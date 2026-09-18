"""MITRE CWE — the weakness taxonomy that joins CVE records to CAPEC patterns.
ADVISORY/NEUTRAL.

The corpus had both ends of a triangle and not the node in the middle. NVD
supplies CVE records — *instances*: this product, this version, this bug — and
CAPEC supplies attack patterns: the sequence an adversary runs. What sits
between them is the weakness *class*. A CVE record points at a CWE, a CAPEC
pattern exploits a CWE, and analysts reach for the CWE first when asked what
kind of bug something is. Without this file the model met both endpoints of
that relation and never the node they both name.

The benchmark already says so out loud. ``cwe-shape`` prompts with the exact
header :mod:`~training.corpus.sources.nvd` renders — ``CVE-2023-4863`` then a
CVSS line — and asks for a weakness id to follow. Nothing in the corpus taught
that pairing; CWE's ``Observed_Examples`` are that pairing written out 3,126
times, each a real CVE id beside a sentence saying what went wrong. This source
is the natural teacher for that probe.

**Identifiers are the point, and CWE stores them as bare integers.** The
measurement this corpus was rebuilt around said that an identifier written
beside the name of the thing it denotes moved a sample from -45% to +13%
against gpt2. CWE's XML holds ``ID="89"``, ``CWE_ID="732"``, ``CAPEC_ID="66"``,
``View_ID="1000"`` — rendered as written, this adapter would emit tens of
thousands of naked integers and not one usable identifier. So every
cross-reference is written back into the form the world writes it, next to the
name it denotes. Counted in CWE 4.20:

* 3,134 observed examples, 3,126 of them a real ``CVE-YYYY-NNNNN`` with a
  description of the bug and a ``cve.org`` link that carries the same id a
  second time in a query string;
* 1,602 weakness-to-weakness edges (``ChildOf``, ``CanPrecede``, ``PeerOf``,
  ``Requires``, ``StartsWith``) rendered as ``ChildOf: CWE-732 Incorrect
  Permission Assignment for Critical Resource``;
* 1,212 ``CAPEC-###`` links — the other side of the join CAPEC already makes
  from its end;
* 4,260 category memberships and 764 view memberships, each a dense run of
  ``CWE-### Name`` pairs, which is grouping knowledge no single entry states;
* every entry's own id in three syntactic positions: leading the document, on
  its own ``CWE ID:`` line, and inside a ``/data/definitions/89.html`` URL.

CWE carries no ATT&CK taxonomy mapping, so unlike
:mod:`~training.corpus.sources.capec` there is no bare ``1574.010`` here
needing its ``T`` restored. Its 17 taxonomies are PLOVER, CERT C, CLASP, OWASP
and friends, and those entry ids (``STR31-C``) are already in wild form.

**The XML.** ``xml.etree`` from the stdlib, which ignores the DTD entirely and
is right for that reason. The catalogue is namespaced
(``http://cwe.mitre.org/cwe-7``) and its prose fields carry a second namespace,
XHTML, as mixed content: ``<xhtml:p>``, ``<xhtml:br/>``, and nested
``<xhtml:div style="margin-left:1em;">`` blocks that *are* the indentation of
the code examples. The namespace is read off the root element rather than
hardcoded, so a future ``cwe-8`` schema fails at the root-name check instead of
quietly matching nothing and yielding zero documents — the failure mode that
looks like success in a build log.

**The ZIP.** MITRE ships the catalogue zipped, and the member name carries the
version (``cwec_v4.20.xml``), so it cannot be hardcoded either: the archive is
opened, its single XML member located, and that member *read* and written to a
path of our choosing. Never ``extractall`` — a member name is data, and data
that names its own destination is how a zip walks out of the directory you put
it in.

**Whitespace, and the trap this source has that CAPEC did not.** The contract
in :func:`~training.corpus.source.normalise` forbids collapsing horizontal
whitespace, and nothing here collapses any: the ``margin-left`` nesting that
gives a vulnerable C function its shape survives as real indentation. But CWE's
XML, unlike CAPEC's, hard-wraps its own text nodes. 3,887 of them carry content
*and* a newline — CAPEC had exactly zero — so a sentence is stored as
``"...strictly typed but support\\n\\t       casting/conversion..."`` and a code
line as ``"\\n\\t\\t  123.123.123.123 admin [17/Jul/2017..."``. Emitted
verbatim, prose would arrive broken across lines with tab runs in the middle of
sentences, and every code line would be shifted by whatever the serializer
happened to indent it. So one rule, as narrow as it can be made: a whitespace
run *containing a newline* is the file's own wrapping and becomes a single
space, dropped entirely where it lands at the start of a line. A run *without*
a newline is untouched. That is safe by measurement — in this catalogue real
line breaks are ``<br/>`` elements and real indentation is nested divs, and the
only content nodes with meaningful leading spaces (five of them, inside one
code example) contain no newline and so are never reached.

**Boilerplate is held back, loudly.** ``Content_History`` is 24.6% of all
weakness text and is the same four lines repeated across 16,575 modification
records; ``Mapping_Notes`` adds 6.1%, of which the ``Comments`` field takes 47
distinct values across 969 entries with one of them repeated 739 times, and the
``Rationale`` beside it 45 values with one repeated 456 times. At a corpus of
this size that is not volume, it is memorisation practice. Both are compacted
— history to two dates, mapping notes to the ``Usage`` verdict that actually
varies — and the characters dropped are counted and printed rather than
silently discarded.

**Register.** ADVISORY, not SYSTEM, and that was measured rather than guessed:
``Example_Code`` is 7.3% of the weakness text. This is advisory prose — what
the weakness is, what it costs, which CVEs were it — with code quoted inside
it, and it belongs beside NVD where a CVE record's ``weakness: CWE-89`` line
finally has a referent. NEUTRAL side: a weakness description is the same fact
to whoever reads it, which is precisely what makes it the join.

**Licence.** CWE's Terms of Use grant a non-exclusive, royalty-free licence for
research, development and commercial purposes, conditioned on reproducing
MITRE's copyright designation and the licence in any copy. Both are reproduced
verbatim in :data:`SPEC` and written into the cache sidecar, read from
https://cwe.mitre.org/about/termsofuse.html rather than assumed.
"""

from __future__ import annotations

import json
import os
import re
import time
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Iterator

from ..net import NetworkError, download
from ..source import Document, Register, Side, SourceError, SourceSpec, normalise

#: The whole catalogue in one archive. MITRE also publishes per-view CSV and
#: HTML, but those are *slices* filtered by view and several entries belong to
#: no view at all, so the complete XML is both simpler and strictly more
#: complete — the same call capec.py makes.
_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

_BLOB = "cwec_latest.xml"
_ARCHIVE = ".cwec_latest.zip.staging"
_STAGING = ".cwec_latest.xml.staging"
_META = "cwe.meta.json"

#: CWE 4.20 is a 2.0 MB archive holding 18.2 MB of XML. Both floors sit far
#: under that: enough to refuse an error page or a truncated transfer, loose
#: enough that a future release which shrinks slightly still passes.
_MIN_ZIP_BYTES = 700_000
_MIN_XML_BYTES = 6_000_000

#: A decompression ceiling. ``file_size`` in the zip header is a claim, not a
#: fact, so the copy loop below enforces this against bytes actually written.
#: 18 MB today; 256 MB leaves a decade of growth and still refuses a bomb.
_MAX_MEMBER_BYTES = 256 * 1024 * 1024

#: Local name of the root element. Checked before anything else, because the
#: cheapest way to discover MITRE moved the URL is a 200 response carrying a
#: redirect page.
_ROOT = "Weakness_Catalog"

#: CWE 4.20 has 969 weaknesses. Well under it, so a release cannot trip this
#: while a namespace change that breaks every lookup will.
_MIN_WEAKNESSES = 500

#: Below this a rendering is a header with nothing under it — a malformed entry
#: rather than a weakness. Real entries start around 600 characters.
_MIN_CHARS = 200

#: XHTML elements that flow inside a line. Everything else — div, p, li, table,
#: br, and CWE's own field elements — begins one, which is the single fact the
#: unwrapping rule in :func:`_text_node` needs to know.
_INLINE = frozenset({
    "b", "i", "em", "strong", "span", "a", "sup", "sub", "u",
    "code", "tt", "font", "small", "big", "img",
})

#: ``class`` values MITRE puts on indented blocks inside prose. They say what
#: the block *is*, which an indented line alone no longer shows once flattened.
_DIV_CLASSES = {"attack", "result", "bad", "good", "mitigation", "informative"}

#: The file's own line wrapping: a whitespace run with a newline in it. See the
#: module docstring — collapsing this, and only this, is what keeps CWE's prose
#: in sentences without touching a single run of real indentation.
_WRAP = re.compile(r"[ \t]*\n[ \t]*")

#: Double-escaped in the source (``&amp;#x435;``), so the parser hands them back
#: as literal text. Nine occurrences catalogue-wide, and they matter: they are
#: the Cyrillic homoglyphs in CWE-1007's homograph example, which without them
#: is an example of nothing — two identical-looking log lines that are in fact
#: identical. Resolved by this narrow pattern rather than ``html.unescape``,
#: which would also rewrite entity-shaped fragments of real payloads
#: (``&ZERO;``, ``&globalVar``) and corrupt them.
_NUMERIC_REF = re.compile(r"&#(?:[0-9]{1,7}|[xX][0-9A-Fa-f]{1,6});")

#: A deprecated entry earns its place by saying what replaced it. This is the
#: test for that: a forwarding pointer to another catalogued identifier.
_POINTER = re.compile(r"\b(?:CWE|CAPEC)[\s-]*[:-]?\s*\d+", re.IGNORECASE)

#: Only for the build report — the headline join this source exists to add.
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b")


# ---------------------------------------------------------------------------
# fetch
# ---------------------------------------------------------------------------

def _fetch(cache_dir: Path) -> Path:
    """Download and unzip the catalogue into ``cache_dir``; return the XML file.

    Idempotent and network-free on re-run: an extracted blob of plausible size
    short-circuits immediately, because the build runs often.

    Both the archive and the extracted XML land on staging names and are
    validated there — size, then zip structure, then an actual parse — and only
    a file that survives all three is renamed to the name :func:`_documents`
    looks for. An interrupted download or an HTML error page therefore cannot
    leave behind something a later run mistakes for a complete cache, which is
    the failure mode that turns "idempotent" into a lie and trains on half a
    register without saying so.

    The archive is deleted once the XML is extracted. Keeping both would mean
    two artefacts that can disagree about which version the cache holds.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    blob = cache_dir / _BLOB
    if blob.is_file() and blob.stat().st_size >= _MIN_XML_BYTES:
        return blob

    archive = cache_dir / _ARCHIVE
    staging = cache_dir / _STAGING
    try:
        download(_URL, archive, timeout=300)
    except NetworkError as exc:
        archive.unlink(missing_ok=True)
        raise SourceError(f"cwe: could not fetch {_URL}: {exc}") from exc

    try:
        zipped = archive.stat().st_size
        if zipped < _MIN_ZIP_BYTES:
            raise SourceError(
                f"cwe: {_URL} returned only {zipped} bytes — that is an error "
                f"page or a truncated transfer, not the CWE archive"
            )
        member = _extract(archive, staging)
        size = staging.stat().st_size
        if size < _MIN_XML_BYTES:
            raise SourceError(
                f"cwe: {member} unzipped to only {size} bytes; CWE 4.20 is "
                "18.2 MB. The archive is truncated or is not the catalogue."
            )
        # Parse before promoting: a body of the right size that is not the
        # catalogue must never reach the cache under the catalogue's name.
        version, date, counts = _probe(staging)
    except Exception:
        staging.unlink(missing_ok=True)
        archive.unlink(missing_ok=True)
        raise

    os.replace(staging, blob)
    archive.unlink(missing_ok=True)
    _write_meta(cache_dir, member, version, date, counts, size)
    return blob


def _extract(archive: Path, target: Path) -> str:
    """Write the archive's single XML member to ``target``; return its name.

    The member is *read* and written to a path this function chose, never
    extracted to a path the archive named. ``extractall`` and
    ``ZipFile.extract`` both honour the stored filename, and a stored filename
    is untrusted data — ``../../.ssh/authorized_keys`` is a valid one. Reading
    the bytes makes path traversal structurally impossible rather than
    defended against.

    The member name is found by search, not hardcoded, because MITRE puts the
    version in it: ``cwec_v4.20.xml`` today, something else next release. The
    copy is bounded so a small archive that claims to hold a terabyte fills a
    buffer and an error message instead of the disk.
    """
    try:
        with zipfile.ZipFile(archive) as bundle:
            members = [
                info for info in bundle.infolist()
                if not info.is_dir() and info.filename.lower().endswith(".xml")
            ]
            if len(members) != 1:
                names = ", ".join(i.filename for i in bundle.infolist()) or "nothing"
                raise SourceError(
                    f"cwe: expected exactly one .xml in {archive.name}, found "
                    f"{len(members)} ({names}). MITRE has changed the bundle "
                    "layout — fix the adapter rather than guessing which file "
                    "is the catalogue."
                )
            info = members[0]
            if info.file_size > _MAX_MEMBER_BYTES:
                raise SourceError(
                    f"cwe: {info.filename} declares {info.file_size} bytes, "
                    f"over the {_MAX_MEMBER_BYTES} byte ceiling"
                )
            written = 0
            with bundle.open(info) as source, open(target, "wb") as sink:
                while chunk := source.read(1 << 20):
                    written += len(chunk)
                    if written > _MAX_MEMBER_BYTES:
                        raise SourceError(
                            f"cwe: {info.filename} exceeded the "
                            f"{_MAX_MEMBER_BYTES} byte ceiling while unzipping"
                        )
                    sink.write(chunk)
    except zipfile.BadZipFile as exc:
        raise SourceError(f"cwe: {archive} is not a zip archive: {exc}") from exc
    return info.filename


def _probe(path: Path) -> tuple[str, str, dict[str, int]]:
    """Confirm the file really is a CWE catalogue; return version/date/counts."""
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as exc:
        raise SourceError(f"cwe: {path} is not parseable XML: {exc}") from exc
    if _local(root.tag) != _ROOT:
        raise SourceError(
            f"cwe: {path} has root <{_local(root.tag)}>, expected <{_ROOT}>. "
            f"{_URL} is probably serving something other than the catalogue."
        )
    ns = _namespace(root)
    counts = {
        "weaknesses": len(root.findall(f"{ns}Weaknesses/{ns}Weakness")),
        "categories": len(root.findall(f"{ns}Categories/{ns}Category")),
        "views": len(root.findall(f"{ns}Views/{ns}View")),
    }
    if counts["weaknesses"] < _MIN_WEAKNESSES:
        raise SourceError(
            f"cwe: only {counts['weaknesses']} weaknesses in {path}; CWE 4.20 "
            "has 969. The upstream layout or the namespace has changed — fix "
            "the adapter rather than training on a fragment of the taxonomy."
        )
    return str(root.get("Version", "")), str(root.get("Date", "")), counts


def _write_meta(cache_dir: Path, member: str, version: str, date: str,
                counts: dict[str, int], size: int) -> None:
    """Record the fetched version and MITRE's licence beside the cache.

    Best-effort: a corpus build must not fail because a sidecar note could not
    be written.
    """
    try:
        (cache_dir / _META).write_text(
            json.dumps(
                {
                    "url": _URL,
                    "member": member,
                    "cwe_version": version,
                    "cwe_date": date,
                    **counts,
                    "bytes": size,
                    "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "license": _LICENSE,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    except OSError:
        return


# ---------------------------------------------------------------------------
# XML helpers
# ---------------------------------------------------------------------------

def _local(tag: str) -> str:
    """The local name of a possibly namespaced tag."""
    return tag.rpartition("}")[2]


def _namespace(root: ET.Element) -> str:
    """The catalogue's namespace in ``{uri}`` form, read off the root element.

    Hardcoding ``cwe-7`` would mean a future schema quietly yielding zero
    documents: every ``find`` would miss and the source would report success
    with nothing in it. Reading it here makes that event either work outright
    or fail at the root-name check, both of which beat silence.
    """
    tag = root.tag
    return tag[: tag.index("}") + 1] if tag.startswith("{") else ""


def _text_node(text: str | None, *, at_line_start: bool) -> str:
    """Decode one text node: drop the serializer's layout, keep the content.

    Three cases, and the order matters.

    A whitespace-only node containing a newline is the XML file's own
    pretty-printing indent and is dropped. One *without* a newline is a real
    space between inline elements and is kept.

    A node with content has its line wrapping undone: every whitespace run
    containing a newline becomes a single space, because in this catalogue such
    a run can only be the serializer breaking a long line — real line breaks
    are ``<br/>`` elements and real indentation is nested ``margin-left``
    divs. A run with no newline is left exactly as written, which is what
    preserves the handful of code fragments MITRE indented with literal spaces.

    ``at_line_start`` says the node sits where a line begins — the text of a
    block element, or the tail of a ``<br/>`` or a block. There the leading
    space this rule would otherwise introduce is deleted, so a code line starts
    in the column its indentation puts it in rather than one to the right of
    it. Inline positions keep the space, because dropping it there would weld
    two words together: ``<b>Note</b>\\n\\tthe value`` must not become
    ``Notethe value``.
    """
    if not text:
        return ""
    if not text.strip():
        return "" if "\n" in text else text
    unwrapped = _WRAP.sub(" ", text)
    if at_line_start and _WRAP.match(text):
        unwrapped = unwrapped.lstrip(" ")
    return unwrapped


def _starts_line(tag: str) -> bool:
    """Does this element begin a line rather than flow inside one?"""
    return tag not in _INLINE


def _flatten(element: ET.Element) -> str:
    """Render CWE's embedded XHTML as plain text, keeping block structure.

    Paragraphs become lines, ``<br/>`` becomes a newline, list items become
    ``- `` lines, and a ``<div style="margin-left:1em;">`` becomes a block
    indented by four spaces — nested divs nest, which is exactly how CWE
    encodes the indentation of its demonstrative code. A free ``malloc`` three
    levels inside a function is only visibly three levels in if this survives,
    and it is the reason the corpus contract forbids collapsing horizontal
    whitespace.

    Divs *without* a ``margin-left`` style are plain block wrappers — MITRE
    uses them around ``<i>`` comments inside code — and indenting those too
    would push every comment one level deeper than the statement it annotates.
    """
    parts: list[str] = [
        _text_node(element.text, at_line_start=_starts_line(_local(element.tag)))
    ]
    for child in element:
        tag = _local(child.tag)
        inner = _flatten(child)
        if tag == "br":
            parts.append("\n")
        elif tag in ("p", "ul", "ol", "table", "tbody", "tr"):
            parts.append("\n" + inner.strip("\n") + "\n")
        elif tag == "li":
            parts.append("\n" + _bullet(inner.strip()) + "\n")
        elif tag == "div":
            body = inner.strip("\n")
            if "margin-left" in (child.get("style") or ""):
                body = "\n".join(("    " + line if line else "")
                                 for line in body.split("\n"))
            css = (child.get("class") or "").strip()
            if css in _DIV_CLASSES:
                body = f"    [{css}]\n{body}"
            parts.append("\n" + body + "\n")
        else:
            # b, i, em, strong, span, a, sup, td — inline, tag dropped, text
            # kept. td flows into its row rather than starting a line of its
            # own; CWE's few tables are two-column label/value pairs.
            parts.append(inner)
        parts.append(_text_node(child.tail, at_line_start=_starts_line(tag)))
    return "".join(parts)


def _text(element: ET.Element | None) -> str:
    """Flattened, entity-resolved text of an element, or the empty string."""
    if element is None:
        return ""
    return _NUMERIC_REF.sub(_unescape_numeric, _flatten(element)).strip()


def _unescape_numeric(match: re.Match[str]) -> str:
    body = match.group(0)[2:-1]
    code = int(body[1:], 16) if body[:1] in ("x", "X") else int(body)
    return chr(code) if 0 <= code <= 0x10FFFF else match.group(0)


def _bullet(text: str, marker: str = "- ", indent: str = "  ") -> str:
    """One list item, with continuation lines indented under the marker.

    Mitigations, detection methods and consequence notes routinely run to
    several sentences. Flush-left continuations would leave no way — for a
    reader or a model — to tell where one item ends and the next begins.
    """
    first, _, rest = text.partition("\n")
    if not rest:
        return marker + first
    tail = "\n".join((indent + line if line else "") for line in rest.split("\n"))
    return f"{marker}{first}\n{tail}"


def _attr(element: ET.Element, name: str) -> str:
    return str(element.get(name, "")).strip()


def _child_text(catalog: "_Catalog", element: ET.Element | None, name: str) -> str:
    """``findtext`` that tolerates a missing parent and strips the result."""
    if element is None:
        return ""
    return (element.findtext(catalog.q(name)) or "").strip()


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

class _Catalog:
    """Parsed catalogue plus the two indexes rendering needs.

    ``names`` resolves a bare id attribute to its human name, and it is the
    whole argument of this adapter in one dictionary: it turns ``ChildOf:
    732`` — a naked integer that teaches nothing — into ``ChildOf: CWE-732
    Incorrect Permission Assignment for Critical Resource``. Weaknesses,
    categories and views share one id space, so one index answers for all
    three, including the ``View_ID`` on a relationship (CWE-1000 is a view, and
    the wild writes it that way).

    ``references`` resolves the ``REF-###`` pointers MITRE stores once at the
    end of the file and cites by id from inside every entry.
    """

    def __init__(self, path: Path) -> None:
        try:
            self.root = ET.parse(path).getroot()
        except (ET.ParseError, OSError) as exc:
            raise SourceError(f"cwe: cannot read catalogue at {path}: {exc}") from exc
        if _local(self.root.tag) != _ROOT:
            raise SourceError(f"cwe: {path} is not a {_ROOT}")
        self.ns = _namespace(self.root)
        self.version = str(self.root.get("Version", ""))
        self.date = str(self.root.get("Date", ""))

        self.weaknesses = self.root.findall(f"{self.ns}Weaknesses/{self.ns}Weakness")
        self.categories = self.root.findall(f"{self.ns}Categories/{self.ns}Category")
        self.views = self.root.findall(f"{self.ns}Views/{self.ns}View")
        if not self.weaknesses:
            raise SourceError(
                f"cwe: no <Weakness> elements under namespace {self.ns!r} in "
                f"{path} — the schema namespace has moved and every lookup in "
                "this adapter is missing"
            )

        self.names: dict[str, str] = {}
        for entry in (*self.weaknesses, *self.categories, *self.views):
            self.names[_attr(entry, "ID")] = _attr(entry, "Name")

        self.references: dict[str, str] = {}
        for ref in self.root.findall(
            f"{self.ns}External_References/{self.ns}External_Reference"
        ):
            self.references[_attr(ref, "Reference_ID")] = self._render_reference(ref)

    def q(self, name: str) -> str:
        return f"{self.ns}{name}"

    def find(self, element: ET.Element, name: str) -> ET.Element | None:
        return element.find(self.q(name))

    def children(self, element: ET.Element, container: str,
                 item: str) -> list[ET.Element]:
        holder = self.find(element, container)
        return [] if holder is None else holder.findall(self.q(item))

    def contents(self, element: ET.Element, container: str) -> list[ET.Element]:
        """Every child of a container, whatever its tag.

        ``Applicable_Platforms`` holds four different element names and the
        distinction between them is the content, so this is iterated rather
        than queried. Note the explicit ``is None``: an ElementTree element
        with no children is *falsy*, so ``if holder:`` would silently skip a
        container that exists but is empty, and — worse — read as if it were
        checking for absence.
        """
        holder = self.find(element, container)
        return [] if holder is None else list(holder)

    def _render_reference(self, ref: ET.Element) -> str:
        """A bibliography entry as one line: authors, title, publisher, URL."""
        bits: list[str] = []
        authors = [a.text.strip() for a in ref.findall(self.q("Author")) if a.text]
        if authors:
            bits.append(", ".join(authors) + ".")
        for field, template in (
            ("Title", '"{}".'),
            ("Publication", "{}."),
            ("Edition", "{}."),
            ("Publisher", "{}."),
            ("Publication_Year", "{}."),
        ):
            value = ref.findtext(self.q(field))
            if value and value.strip():
                bits.append(template.format(value.strip()))
        url = ref.findtext(self.q("URL"))
        if url and url.strip():
            bits.append(url.strip())
        return " ".join(bits)

    def named(self, cwe_id: str) -> str:
        """``CWE-89 Improper Neutralization...`` — the id next to its referent.

        An id this catalogue does not define still gets its prefix: a stale
        cross-reference is rarer than a missing name, and ``CWE-1425`` alone is
        worth more to the tokenizer than ``1425`` ever is.
        """
        name = self.names.get(cwe_id, "")
        return f"CWE-{cwe_id} {name}".strip()


def _header(catalog: _Catalog, entry: ET.Element, kind: str) -> list[str]:
    """The labelled preamble every entry shares.

    The id leads the document, is repeated on its own labelled line, and
    appears a third time inside a URL path. Three syntactic positions for one
    identifier, which is the shape of exposure the tokenizer measurement
    rewarded and the shape a naive rendering of this XML would have produced
    none of.
    """
    entry_id = _attr(entry, "ID")
    name = _attr(entry, "Name")
    lines = [
        f"CWE-{entry_id} {name}".strip(),
        "",
        f"CWE ID: CWE-{entry_id}",
        f"Name: {name}",
        f"Entry type: {kind}",
    ]
    for attribute, label in (("Abstraction", "Abstraction"),
                             ("Structure", "Structure"),
                             ("Type", "View type"),
                             ("Status", "Status")):
        if value := _attr(entry, attribute):
            lines.append(f"{label}: {value}")
    if likelihood := _child_text(catalog, entry, "Likelihood_Of_Exploit"):
        lines.append(f"Likelihood of exploit: {likelihood}")
    if usage := _mapping_usage(catalog, entry):
        lines.append(f"Mapping usage: {usage}")
    lines.append(f"URL: https://cwe.mitre.org/data/definitions/{entry_id}.html")
    return lines


def _mapping_usage(catalog: _Catalog, entry: ET.Element) -> str:
    """Whether this entry may be used when mapping a CVE to a weakness.

    One line out of a 6%-of-the-catalogue block, and the only part of it that
    varies usefully: ``Allowed``, ``Allowed-with-Review``, ``Discouraged`` or
    ``Prohibited``, with the reason codes that qualify it. This is real
    operational knowledge — "do not map a CVE to this Class, go find its Base"
    — and it is precisely the judgement the ``cwe-shape`` probe is asking for.
    The ``Rationale`` and ``Comments`` prose beside it is templated to the
    point of 739 identical copies and is held back; see :data:`_MAPPING_NOTE`.
    """
    notes = catalog.find(entry, "Mapping_Notes")
    if notes is None:
        return ""
    usage = _child_text(catalog, notes, "Usage")
    reasons = [
        _attr(reason, "Type")
        for reason in catalog.children(notes, "Reasons", "Reason")
        if _attr(reason, "Type")
    ]
    if usage and reasons:
        return f"{usage} (reason: {', '.join(reasons)})"
    return usage


def _section(title: str, body: list[str]) -> list[str]:
    """A titled section, or nothing at all if there is nothing to put in it.

    The blank filter is not belt-and-braces. Most call sites build ``body``
    with a comprehension that already drops empties, but the single-value
    sections pass ``[_text(...)]`` straight through, and a list holding one
    empty string is still a truthy list — which emits a bare ``## Description``
    header with the next header directly under it, teaching that a heading can
    be followed by nothing.

    Each element of ``body`` may itself be several lines: the filter looks at
    whole entries, never at the lines inside one, so the blank line between a
    demonstrative example's prose and its code block survives.
    """
    kept = [line for line in body if line.strip()]
    return ["", f"## {title}", "", *kept] if kept else []


def _render_weakness(catalog: _Catalog, entry: ET.Element) -> str:
    """One weakness, laid out as labelled sections of plain lines.

    Section order follows the question a reader actually asks: what is it, what
    does it look like, where does it appear, what does it cost, how is it found
    and fixed, what does it look like in code, which CVEs were it, and what is
    it related to. That last group is where the identifiers live.
    """
    lines = _header(catalog, entry, "Weakness")

    lines += _section("Description", [_text(catalog.find(entry, "Description"))])
    lines += _section("Extended Description",
                      [_text(catalog.find(entry, "Extended_Description"))])

    lines += _section("Alternate Terms", [
        _bullet(" ".join(filter(None, [
            _child_text(catalog, term, "Term") + ":",
            _text(catalog.find(term, "Description")),
        ])).rstrip(":"))
        for term in catalog.children(entry, "Alternate_Terms", "Alternate_Term")
    ])

    lines += _section("Background Details", [
        _bullet(_text(detail))
        for detail in catalog.children(entry, "Background_Details", "Background_Detail")
        if _text(detail)
    ])

    lines += _section("Applicable Platforms", _render_platforms(catalog, entry))
    lines += _section("Modes of Introduction", _render_introductions(catalog, entry))
    lines += _section("Common Consequences", _render_consequences(catalog, entry))
    lines += _section("Detection Methods", _render_detection(catalog, entry))
    lines += _section("Potential Mitigations", _render_mitigations(catalog, entry))
    lines += _section("Demonstrative Examples", _render_examples(catalog, entry))
    lines += _section("Observed Examples", _render_observed(catalog, entry))
    lines += _section("Relationships", _render_relationships(catalog, entry))

    # CWE carries no CAPEC names, so the URL form is what puts the identifier
    # in a second syntactic position here — the mirror of what capec.py does
    # with its CWE links, from the other side of the same join.
    lines += _section("Related Attack Patterns", [
        _bullet(f"CAPEC-{capec} (https://capec.mitre.org/data/definitions/{capec}.html)")
        for related in catalog.children(entry, "Related_Attack_Patterns",
                                        "Related_Attack_Pattern")
        if (capec := _attr(related, "CAPEC_ID"))
    ])

    lines += _section("Weakness Ordinalities", _render_ordinalities(catalog, entry))

    lines += _section("Affected Resources", [
        _bullet(resource.text.strip())
        for resource in catalog.children(entry, "Affected_Resources", "Affected_Resource")
        if resource.text and resource.text.strip()
    ])

    lines += _section("Functional Areas", [
        _bullet(area.text.strip())
        for area in catalog.children(entry, "Functional_Areas", "Functional_Area")
        if area.text and area.text.strip()
    ])

    lines += _section("Taxonomy Mappings", _render_taxonomy(catalog, entry))
    lines += _section("Notes", _render_notes(catalog, entry))
    lines += _section("References", _render_references(catalog, entry))
    lines += _history(catalog, entry)
    return "\n".join(lines)


def _render_platforms(catalog: _Catalog, entry: ET.Element) -> list[str]:
    """Languages, technologies, operating systems and architectures.

    A platform is named either concretely (``Name="PHP"``) or as a class
    (``Class="Interpreted"``), and the two are different claims: "this bug
    happens in PHP" and "this bug happens in any interpreted language" are not
    interchangeable, so the rendering keeps them apart rather than flattening
    both to one label.
    """
    lines: list[str] = []
    for platform in catalog.contents(entry, "Applicable_Platforms"):
        kind = _local(platform.tag).replace("_", " ")
        name = _attr(platform, "Name")
        label = f"{kind}: {name}" if name else f"{kind} class: {_attr(platform, 'Class')}"
        if prevalence := _attr(platform, "Prevalence"):
            label += f" (prevalence {prevalence})"
        if label.strip().rstrip(":"):
            lines.append(_bullet(label))
    return lines


def _render_introductions(catalog: _Catalog, entry: ET.Element) -> list[str]:
    """Which phase of development lets the weakness in, and how."""
    lines: list[str] = []
    for introduction in catalog.children(entry, "Modes_Of_Introduction", "Introduction"):
        phase = _child_text(catalog, introduction, "Phase")
        note = _text(catalog.find(introduction, "Note"))
        line = f"{phase}: {note}" if note else phase
        if line:
            lines.append(_bullet(line))
    return lines


def _render_consequences(catalog: _Catalog, entry: ET.Element) -> list[str]:
    """What it costs, in CWE's own scope/impact vocabulary.

    ``Confidentiality: Read Application Data`` is a fixed pair of terms that
    appears in this form across CWE, CVSS commentary and vendor advisories, so
    the pairing is kept intact rather than dissolved into a sentence.
    """
    lines: list[str] = []
    for consequence in catalog.children(entry, "Common_Consequences", "Consequence"):
        scopes = ", ".join(s.text.strip()
                           for s in consequence.findall(catalog.q("Scope")) if s.text)
        impacts = "; ".join(i.text.strip()
                            for i in consequence.findall(catalog.q("Impact")) if i.text)
        notes = "; ".join(filter(None, (_text(n)
                                        for n in consequence.findall(catalog.q("Note")))))
        likelihood = _child_text(catalog, consequence, "Likelihood")
        line = f"{scopes}: {impacts}" if impacts else scopes
        if notes:
            line += f" ({notes})"
        if likelihood:
            line += f" [likelihood {likelihood}]"
        if line:
            lines.append(_bullet(line))
    return lines


def _render_detection(catalog: _Catalog, entry: ET.Element) -> list[str]:
    """How the weakness is actually found — the blue half of this source.

    Effectiveness is kept on its own continuation line rather than parenthesised
    into the description, because "Automated Static Analysis / effectiveness
    Moderate" is a judgement about a tool class, and that judgement is the part
    worth learning.
    """
    lines: list[str] = []
    for method in catalog.children(entry, "Detection_Methods", "Detection_Method"):
        name = _child_text(catalog, method, "Method")
        description = _text(catalog.find(method, "Description"))
        body = f"[{name}] {description}".strip() if name else description
        effectiveness = _child_text(catalog, method, "Effectiveness")
        notes = _text(catalog.find(method, "Effectiveness_Notes"))
        if effectiveness or notes:
            tail = f"Effectiveness: {effectiveness}".strip().rstrip(":")
            if notes:
                tail = f"{tail}. {notes}" if effectiveness else notes
            body = f"{body}\n{tail}" if body else tail
        if body.strip():
            lines.append(_bullet(body))
    return lines


def _render_mitigations(catalog: _Catalog, entry: ET.Element) -> list[str]:
    """The fix, tagged with the phase it belongs to and the strategy it is.

    A mitigation without its phase is advice with nowhere to go: "use a
    parameterised query" is an Implementation instruction, "choose a library
    that does it for you" is Architecture and Design, and the difference is
    who acts on it.
    """
    lines: list[str] = []
    for mitigation in catalog.children(entry, "Potential_Mitigations", "Mitigation"):
        phases = "; ".join(p.text.strip()
                           for p in mitigation.findall(catalog.q("Phase")) if p.text)
        strategy = _child_text(catalog, mitigation, "Strategy")
        tags = [tag for tag in (f"Phase: {phases}" if phases else "",
                                f"Strategy: {strategy}" if strategy else "") if tag]
        description = _text(catalog.find(mitigation, "Description"))
        body = f"[{' | '.join(tags)}] {description}".strip() if tags else description
        effectiveness = _child_text(catalog, mitigation, "Effectiveness")
        notes = _text(catalog.find(mitigation, "Effectiveness_Notes"))
        if effectiveness or notes:
            tail = f"Effectiveness: {effectiveness}".strip().rstrip(":")
            if notes:
                tail = f"{tail}. {notes}" if effectiveness else notes
            body = f"{body}\n{tail}" if body else tail
        if body.strip():
            lines.append(_bullet(body))
    return lines


def _render_examples(catalog: _Catalog, entry: ET.Element) -> list[str]:
    """Demonstrative examples: real vulnerable code beside the prose explaining it.

    Two decisions here, both about not damaging the code.

    The parts are walked **in document order** rather than gathered by tag.
    MITRE writes these as a lesson — intro, the bad code, an explanation of why
    it is bad, then the fixed version — and collecting all the ``Intro_Text``
    then all the ``Example_Code`` would shuffle a taught sequence into two
    piles and lose which explanation belongs to which listing.

    The code is **not** indented under a bullet. Every other list in this
    adapter uses ``- `` with two-space continuations; doing that here would add
    two spaces to every line of a C function whose real indentation is the
    thing the section exists to show. So an example is one block, its code
    starting in the column CWE's nested divs put it in, under a ``[Bad code,
    language C]`` label that says what the listing is — which matters, because
    roughly a fifth of these listings are the *correct* version and a model
    that cannot tell them apart learns the vulnerability as the fix.
    """
    blocks: list[str] = []
    for index, example in enumerate(
        catalog.children(entry, "Demonstrative_Examples", "Demonstrative_Example"), 1
    ):
        parts: list[str] = []
        for part in example:
            tag = _local(part.tag)
            if tag in ("Intro_Text", "Body_Text"):
                if text := _text(part):
                    parts.append(text)
            elif tag == "Example_Code":
                code = _text(part)
                if not code:
                    continue
                nature = _attr(part, "Nature") or "Example"
                language = _attr(part, "Language")
                label = (f"[{nature} code, language {language}]" if language
                         else f"[{nature} code]")
                parts.append(f"{label}\n{code}")
            elif tag == "References":
                if refs := _render_references(catalog, example):
                    parts.append("\n".join(refs))
        if not parts:
            continue
        # The label rides on the first prose paragraph when there is one, so a
        # lesson opens "Example 2: The following code illustrates..." rather
        # than on a line by itself; a code listing always starts its own line,
        # because its first column is load-bearing.
        head = f"Example {index}:"
        if not parts[0].startswith("["):
            head = f"{head} {parts.pop(0)}"
        body = "\n\n".join([head, *parts])
        # A blank line between examples. _section filters empty *entries*, so a
        # separator cannot be one; it has to travel with the block it precedes.
        blocks.append(f"\n{body}" if blocks else body)
    return blocks


def _render_observed(catalog: _Catalog, entry: ET.Element) -> list[str]:
    """Real CVEs, each beside a sentence saying what the bug actually was.

    This is the section this whole source was added for. 3,126 lines of the
    form ``CVE-2021-44228: <what went wrong> (<link carrying the id again>)``
    is the CVE-to-CWE join written out as running text, in both of the
    syntactic positions the tokenizer measurement rewarded — bare in prose and
    embedded in a URL query string.
    """
    lines: list[str] = []
    for example in catalog.children(entry, "Observed_Examples", "Observed_Example"):
        reference = _child_text(catalog, example, "Reference")
        description = _text(catalog.find(example, "Description"))
        link = _child_text(catalog, example, "Link")
        line = f"{reference}: {description}" if description else reference
        if link:
            line += f" ({link})"
        if line.strip():
            lines.append(_bullet(line))
    return lines


def _render_relationships(catalog: _Catalog, entry: ET.Element) -> list[str]:
    """The taxonomy edges, with every bare integer resolved to an id and a name.

    ``<Related_Weakness Nature="ChildOf" CWE_ID="732" View_ID="1000"
    Ordinal="Primary"/>`` is four facts and, as stored, zero identifiers. It
    renders as ``ChildOf: CWE-732 Incorrect Permission Assignment for Critical
    Resource (Primary) [in view CWE-1000 Research Concepts]`` — the edge, the
    id, the name, whether this is the primary parent, and which of CWE's views
    the edge exists in, since the hierarchy genuinely differs between them.
    """
    lines: list[str] = []
    for relation in catalog.children(entry, "Related_Weaknesses", "Related_Weakness"):
        cwe_id = _attr(relation, "CWE_ID")
        if not cwe_id:
            continue
        line = f"{_attr(relation, 'Nature') or 'RelatedTo'}: {catalog.named(cwe_id)}"
        if ordinal := _attr(relation, "Ordinal"):
            line += f" ({ordinal})"
        if view := _attr(relation, "View_ID"):
            line += f" [in view {catalog.named(view)}]"
        lines.append(_bullet(line))
    return lines


def _render_ordinalities(catalog: _Catalog, entry: ET.Element) -> list[str]:
    """Primary, Resultant or Indirect — whether this weakness is cause or effect."""
    lines: list[str] = []
    for item in catalog.children(entry, "Weakness_Ordinalities", "Weakness_Ordinality"):
        ordinality = _child_text(catalog, item, "Ordinality")
        description = _text(catalog.find(item, "Description"))
        line = f"{ordinality}: {description}" if description else ordinality
        if line:
            lines.append(_bullet(line))
    return lines


def _render_taxonomy(catalog: _Catalog, entry: ET.Element) -> list[str]:
    """Where this weakness appears in the seventeen other catalogues.

    Unlike CAPEC there is no ATT&CK mapping here and so no bare ``1574.010`` to
    put a ``T`` back on: CWE's taxonomies are PLOVER, CLASP, the CERT coding
    standards, OWASP, WASC and the OMG metrics, and their entry ids
    (``STR31-C``, ``A6``, ``ASCSM-CWE-89``) are already written the way their
    own communities write them. The ``Mapping_Fit`` qualifier is kept because
    "CWE More Specific" is the difference between a synonym and an
    approximation.
    """
    lines: list[str] = []
    for mapping in catalog.children(entry, "Taxonomy_Mappings", "Taxonomy_Mapping"):
        taxonomy = _attr(mapping, "Taxonomy_Name")
        entry_id = _child_text(catalog, mapping, "Entry_ID")
        entry_name = _child_text(catalog, mapping, "Entry_Name")
        fit = _child_text(catalog, mapping, "Mapping_Fit")
        label = f"{entry_id} {entry_name}".strip()
        line = f"{taxonomy}: {label}" if label else taxonomy
        if fit:
            line += f" (fit: {fit})"
        if line:
            lines.append(_bullet(line))
    return lines


def _render_notes(catalog: _Catalog, entry: ET.Element) -> list[str]:
    """Maintenance, Relationship, Research Gap and Terminology notes.

    Research Gap notes in particular are worth their characters: "this
    weakness is under-studied and rarely reported" is an honest statement of
    where the taxonomy's own coverage runs out, and that is exactly the kind of
    hedge a security model should have met before it is asked to make one.
    """
    return [
        _bullet(f"[{_attr(note, 'Type') or 'Other'}] {_text(note)}")
        for note in catalog.children(entry, "Notes", "Note")
        if _text(note)
    ]


def _render_references(catalog: _Catalog, entry: ET.Element) -> list[str]:
    lines: list[str] = []
    for citation in catalog.children(entry, "References", "Reference"):
        ref_id = _attr(citation, "External_Reference_ID")
        body = catalog.references.get(ref_id, "")
        section = _attr(citation, "Section")
        line = f"[{ref_id}] {body}".strip()
        if section:
            line += f" Section: {section}"
        if line:
            lines.append(_bullet(line))
    return lines


def _history(catalog: _Catalog, entry: ET.Element) -> list[str]:
    """Submission and last-modification dates, and nothing else.

    See :data:`_HISTORY_NOTE`: the full ``Content_History`` block is a quarter
    of this catalogue's text and almost all of it is four lines repeated some
    fifteen thousand times.
    """
    history = catalog.find(entry, "Content_History")
    if history is None:
        return []
    bits: list[str] = []
    submission = catalog.find(history, "Submission")
    if submission is not None:
        if date := _child_text(catalog, submission, "Submission_Date"):
            bits.append(f"submitted {date}")
    modifications = history.findall(catalog.q("Modification"))
    if modifications:
        if date := _child_text(catalog, modifications[-1], "Modification_Date"):
            bits.append(f"last modified {date}")
    return ["", f"Content history: {', '.join(bits)}"] if bits else []


def _render_category(catalog: _Catalog, entry: ET.Element) -> str:
    """A CWE category: the organising idea and the weaknesses it collects.

    Worth a document of its own because the member list is a dense run of
    ``CWE-### Name`` pairs in one place — 4,260 of them catalogue-wide — and
    because the grouping itself ("these eleven are all pointer-handling
    failures") is knowledge no individual weakness states about itself.
    """
    lines = _header(catalog, entry, "Category")
    lines += _section("Summary", [_text(catalog.find(entry, "Summary"))])
    lines += _section("Members", [
        _bullet(catalog.named(_attr(member, "CWE_ID")))
        for member in catalog.children(entry, "Relationships", "Has_Member")
        if _attr(member, "CWE_ID")
    ])
    lines += _section("Taxonomy Mappings", _render_taxonomy(catalog, entry))
    lines += _section("Notes", _render_notes(catalog, entry))
    lines += _section("References", _render_references(catalog, entry))
    lines += _history(catalog, entry)
    return "\n".join(lines)


def _render_view(catalog: _Catalog, entry: ET.Element) -> str:
    """A CWE view: the principle behind a slice of the catalogue.

    Views are where CWE says what it is for — the Top 25, the Research
    Concepts hierarchy, the mapping-friendly subset — and the ``Filter`` on an
    implicit view is a literal XPath expression over this schema, which is
    dense structured text of a kind the corpus is otherwise short of.
    """
    lines = _header(catalog, entry, "View")
    lines += _section("Objective", [_text(catalog.find(entry, "Objective"))])
    lines += _section("Audience", [
        _bullet(" ".join(filter(None, [
            _child_text(catalog, stakeholder, "Type") + ":",
            _text(catalog.find(stakeholder, "Description")),
        ])).rstrip(":"))
        for stakeholder in catalog.children(entry, "Audience", "Stakeholder")
    ])
    if selector := _text(catalog.find(entry, "Filter")):
        lines += _section("Filter", [selector])
    lines += _section("Members", [
        _bullet(catalog.named(_attr(member, "CWE_ID")))
        for member in catalog.children(entry, "Members", "Has_Member")
        if _attr(member, "CWE_ID")
    ])
    lines += _section("Notes", _render_notes(catalog, entry))
    lines += _section("References", _render_references(catalog, entry))
    lines += _history(catalog, entry)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# documents
# ---------------------------------------------------------------------------

#: What the compacted ``Content_History`` block costs, stated once so the number
#: in the build log and the reasoning for it live together.
#:
#: Measured on CWE 4.20: ``Content_History`` is 1,318,944 characters, **24.6%**
#: of all weakness text in the catalogue and its single largest field — larger
#: than every demonstrative example put together. Essentially all of it is the
#: same four lines — ``CWE Content Team`` / ``MITRE`` / a date / ``updated
#: References, Taxonomy_Mappings`` — repeated once per modification, 16,575
#: times across the catalogue. That is a memorisation hazard dressed as volume: the
#: corpus is tens of millions of tokens against a billion-token appetite, and
#: text repeated fifteen thousand times is precisely what a model trained for
#: many epochs learns by heart. The dates survive as one line per entry; the
#: boilerplate does not.
_HISTORY_NOTE = "Content_History boilerplate"

#: The same argument, one field along. ``Mapping_Notes`` is 328,311 characters,
#: 6.1% of the weakness text, and its prose barely varies: ``Comments`` takes
#: 47 distinct values across 969 entries with one repeated 739 times, and
#: ``Rationale`` 45 values with one repeated 456 times. The ``Usage`` verdict
#: beside them genuinely varies and is kept on the header line by
#: :func:`_mapping_usage`; the templated prose is held back.
_MAPPING_NOTE = "Mapping_Notes rationale boilerplate"


def _documents(path: Path) -> Iterator[Document]:
    """Yield weaknesses, then categories, then views — numerically ordered.

    Numeric order rather than string order, so CWE-20 precedes CWE-119 and a
    build report reads the way the catalogue does.

    Two holdbacks, both counted and printed rather than applied silently:

    *Deprecated categories* are dropped outright. All 35 are one templated
    sentence — "This category has been deprecated" — and not one of them has a
    single member left, so as documents they are 35 near-identical texts whose
    only distinguishing content is the header. The build's fingerprint dedup
    cannot catch them, because the differing id is inside the text.

    *Deprecated weaknesses* are kept only when the notice forwards somewhere.
    "Deprecated because it was a duplicate of CWE-908, all content transferred"
    is a true fact about an identifier that still appears in a decade of old
    scan reports, and dropping it would also throw away a valid ``CWE-###``
    string from a corpus assembled because it had too few of them. A notice
    naming no replacement forwards nowhere and is held back.
    """
    catalog = _Catalog(_resolve(path))

    held_history = 0
    emitted_history = 0
    held_mapping = 0
    held_deprecated_categories = 0
    held_tombstones = 0
    cve_refs = 0
    docs = 0

    for entry in sorted(catalog.weaknesses, key=_sort_key):
        description = _text(catalog.find(entry, "Description"))
        if _attr(entry, "Status") == "Deprecated" and not _POINTER.search(description):
            held_tombstones += 1
            continue
        text = normalise(_render_weakness(catalog, entry))
        if len(text) < _MIN_CHARS:
            continue
        held, emitted = _history_cost(catalog, entry)
        held_history += held
        emitted_history += emitted
        held_mapping += _mapping_cost(catalog, entry)
        cve_refs += len(_CVE.findall(text))
        docs += 1
        yield Document(
            text=text,
            source="cwe",
            register=Register.ADVISORY,
            side=Side.NEUTRAL,
            ident=f"CWE-{_attr(entry, 'ID')}",
        )

    for entry in sorted(catalog.categories, key=_sort_key):
        if _attr(entry, "Status") == "Deprecated":
            held_deprecated_categories += 1
            continue
        text = normalise(_render_category(catalog, entry))
        if len(text) < _MIN_CHARS:
            continue
        held, emitted = _history_cost(catalog, entry)
        held_history += held
        emitted_history += emitted
        held_mapping += _mapping_cost(catalog, entry)
        docs += 1
        yield Document(
            text=text,
            source="cwe",
            register=Register.ADVISORY,
            side=Side.NEUTRAL,
            ident=f"CWE-{_attr(entry, 'ID')} (category)",
        )

    for entry in sorted(catalog.views, key=_sort_key):
        text = normalise(_render_view(catalog, entry))
        if len(text) < _MIN_CHARS:
            continue
        held, emitted = _history_cost(catalog, entry)
        held_history += held
        emitted_history += emitted
        held_mapping += _mapping_cost(catalog, entry)
        docs += 1
        yield Document(
            text=text,
            source="cwe",
            register=Register.ADVISORY,
            side=Side.NEUTRAL,
            ident=f"CWE-{_attr(entry, 'ID')} (view)",
        )

    # No silent caps: say what was held back, and what the join actually cost.
    print(f"   cwe: CWE {catalog.version} ({catalog.date}); {docs:,} entries "
          f"carrying {cve_refs:,} CVE references")
    print(f"   cwe: held back {held_history:,} chars of {_HISTORY_NOTE} "
          f"(kept {emitted_history:,} chars of dates) and {held_mapping:,} "
          f"chars of {_MAPPING_NOTE}")
    if held_deprecated_categories:
        print(f"   cwe: held back {held_deprecated_categories} deprecated "
              "categor(ies) — one templated sentence each, no members")
    if held_tombstones:
        print(f"   cwe: held back {held_tombstones} deprecated weakness(es) "
              "whose notice names no replacement CWE or CAPEC")


def _resolve(path: Path) -> Path:
    """Accept either the XML file or the cache directory holding it."""
    if path.is_dir():
        candidate = path / _BLOB
        if not candidate.is_file():
            raise SourceError(
                f"cwe: no {_BLOB} in {path} — run the source's fetch() first"
            )
        return candidate
    if not path.is_file():
        raise SourceError(f"cwe: {path} does not exist")
    return path


def _sort_key(entry: ET.Element) -> tuple[int, str]:
    """Numeric order on the CWE id, with a stable fallback for oddities."""
    raw = _attr(entry, "ID")
    try:
        return int(raw), raw
    except ValueError:
        return 1 << 30, raw


def _history_cost(catalog: _Catalog, entry: ET.Element) -> tuple[int, int]:
    """(characters discarded, characters kept) for one entry's Content_History."""
    history = catalog.find(entry, "Content_History")
    if history is None:
        return 0, 0
    full = sum(len(chunk) for chunk in history.itertext() if chunk.strip())
    kept = sum(len(line) for line in _history(catalog, entry))
    return max(full - kept, 0), kept


def _mapping_cost(catalog: _Catalog, entry: ET.Element) -> int:
    """Characters of Mapping_Notes prose discarded for one entry."""
    notes = catalog.find(entry, "Mapping_Notes")
    if notes is None:
        return 0
    full = sum(len(chunk) for chunk in notes.itertext() if chunk.strip())
    return max(full - len(_mapping_usage(catalog, entry)), 0)


_LICENSE = (
    "MITRE CWE Terms of Use. \"CWE is free to use by any organization or "
    "individual for any research, development, and/or commercial purposes, per "
    "these CWE Terms of Use. Accordingly, The MITRE Corporation hereby grants "
    "you a non-exclusive, royalty-free license to use CWE for research, "
    "development, and commercial purposes. Any copy you make for such purposes "
    "is authorized on the condition that you reproduce MITRE's copyright "
    "designation and this license in any such copy.\" Copyright (c) 2006-2026, "
    "The MITRE Corporation. CWE, CWSS, CWRAF, and the CWE logo are trademarks "
    "of The MITRE Corporation. Terms: https://cwe.mitre.org/about/termsofuse.html"
)


SPEC = SourceSpec(
    name="cwe",
    license=_LICENSE,
    url="https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
    register=Register.ADVISORY,
    side=Side.NEUTRAL,
    fetch=_fetch,
    documents=_documents,
    #: CWE 4.20 yields 967 weaknesses (969 less 2 tombstones), 387 live
    #: categories (422 less 35 deprecated) and 59 views = 1,413. The floor
    #: sits well under that, so a normal release cannot trip it while a
    #: namespace or layout change that breaks the element lookups will — and a
    #: floor above 900 means "the weakness list is mostly here" is checked
    #: rather than assumed.
    expect_min_docs=900,
    notes=(
        "The whole cwec_latest.xml catalogue — weaknesses, live categories and "
        "views — unzipped from MITRE's archive. Closes the CVE/CWE/CAPEC "
        "triangle the corpus was missing the middle of, and is the natural "
        "teacher for the benchmark's cwe-shape probe. Every cross-reference is "
        "written in the form the world writes it (CWE-###, CAPEC-###, "
        "CVE-YYYY-NNNNN) beside the name of what it denotes, where the XML "
        "stores bare integers: 3,126 observed CVEs, 1,602 weakness edges, "
        "1,212 CAPEC links, 5,024 category and view memberships. Demonstrative "
        "examples keep their real code indentation (nested margin-left divs "
        "become real columns) and are walked in document order so the bad "
        "listing stays attached to the prose explaining it. Content_History "
        "(24.6% of the catalogue) is compacted to two dates and Mapping_Notes "
        "prose is held back, both counted out loud."
    ),
)
