"""MITRE CAPEC — attack patterns as the attacker sequences them. ADVERSARY/RED.

ADVERSARY is the scarcest register in this corpus, and scarcity there is not a
cosmetic imbalance: it is the binding constraint that forces the register
balancer to throw away most of everything else to hit
:data:`~training.corpus.source.REGISTER_TARGETS`. Every character added here
buys back characters everywhere. CAPEC is the largest body of freely licensed
adversary text that is not already in the corpus, and it is a different *shape*
of adversary text from ATT&CK: ATT&CK names a behaviour and describes it, while
CAPEC walks an attack in order — Explore, Experiment, Exploit — with the
prerequisites that gate it, the skill level it demands, the resources it costs,
and the observable consequences. That ordering is the sequential decision-making
this project exists to teach and that retrieval cannot supply.

**Identifiers are the point, and CAPEC does not store them in the form the world
writes them.** The measurement this corpus was rebuilt around said that
``T1547.001`` beside its human name in running prose moved that sample from -45%
to +13% against gpt2. CAPEC's XML stores bare numbers in attributes:
``CAPEC_ID="248"``, ``CWE_ID="89"``, and — the one that would be silently lost —
an ATT&CK taxonomy mapping whose ``Entry_ID`` is ``1574.010`` with no ``T``.
Rendered naively, this source would emit thousands of naked integers and not one
usable identifier. So every cross-reference is written back into its wild form
(``CAPEC-248``, ``CWE-89``, ``T1574.010``), beside the *name* of the thing it
denotes, and the entry's own id also appears in a URL path
(``/data/definitions/66.html``) — the same three syntactic positions that
argument justified in :mod:`~training.corpus.sources.attack`. CAPEC is unusually
rich in these joins: 1,214 CWE links, 727 CAPEC-to-CAPEC edges and 272 ATT&CK
mappings, all of them id-next-to-name.

**The XML.** ``xml.etree`` from the stdlib, which ignores the DTD entirely and
is exactly right for that reason. The catalogue is namespaced
(``http://capec.mitre.org/capec-3``) and prose fields carry a *second*
namespace, XHTML, as mixed content — ``<html:p>``, ``<html:br/>``, nested
``<html:div style="margin-left:1em;">`` blocks holding code and HTTP
transcripts. The namespace is read off the root element rather than hardcoded,
so a CAPEC 4 catalogue fails loudly at parse time instead of yielding zero
documents.

**Whitespace.** This adapter never collapses horizontal whitespace — that is the
contract, and it is what keeps nested ``margin-left`` divs rendering as real
code indentation instead of a flattened line. It does drop whitespace-only text
nodes that contain a newline, which are the XML file's own pretty-printing
indent. That is decoding, not cleaning, and it is safe by measurement: across
the whole catalogue there is **not one** text node that carries content *and* a
newline, so no sentence and no code line can be touched by that rule.

**Markup does not survive.** Tags become structure and entities are decoded by
the parser; the two surviving double-escaped numeric references (``&#92;``,
``&#46;``) are resolved narrowly by pattern rather than by running the whole
text through an unescaper, which would maul query strings like
``?x=1&globalVar=evil``. Angle brackets that *do* remain — ``<embed src=...>``
inside an XSS example — are payload, not markup, and stay.

**Licence.** CAPEC's Terms of Use grant a non-exclusive, royalty-free licence
for research, development and commercial use, conditioned on reproducing
MITRE's copyright designation and the licence itself. Both are reproduced
verbatim in :data:`SPEC` and written into the cache sidecar, read from
https://capec.mitre.org/about/termsofuse.html rather than assumed.
"""

from __future__ import annotations

import json
import os
import re
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterator

from ..net import NetworkError, download
from ..source import Document, Register, Side, SourceError, SourceSpec, normalise

#: The catalogue in one file. MITRE also publishes per-view CSV and ZIP bundles,
#: but those are *subsets* filtered by view, and several patterns belong to no
#: view at all — taking the whole XML is both simpler and strictly more complete.
_URL = "https://capec.mitre.org/data/xml/capec_latest.xml"

_BLOB = "capec_latest.xml"
_STAGING = ".capec_latest.xml.staging"
_META = "capec.meta.json"

#: CAPEC 3.9 is 3.85 MB and the catalogue has only ever grown. A floor this far
#: below it refuses an error page or a truncated transfer while leaving room for
#: a future release to shrink slightly.
_MIN_BYTES = 1_500_000

#: Local name of the root element. Checked before anything else, because the
#: cheapest way to discover that MITRE moved the URL is a 200 response carrying
#: an HTML redirect page.
_ROOT = "Attack_Pattern_Catalog"

_XHTML_NS = "http://www.w3.org/1999/xhtml"

#: Below this a rendering is a header with nothing under it — a malformed entry,
#: not an attack pattern. Real entries start around 350 characters.
_MIN_CHARS = 200

#: ``class`` values MITRE puts on the indented blocks inside examples. They say
#: what the block *is* — the payload, the server's answer, the wrong way to do
#: it — which is worth a label, because after flattening an unlabelled block is
#: just an indented line and the distinction is gone.
_DIV_CLASSES = {"attack", "result", "bad", "good", "mitigation", "informative"}

#: Double-escaped in the source (``&amp;#92;``), so the parser hands them back
#: as literal text. Two occurrences catalogue-wide. Resolved by this narrow
#: pattern rather than ``html.unescape``, which also rewrites entity-shaped
#: fragments of real payloads (``&notin``, ``&globalVar``) and would corrupt them.
_NUMERIC_REF = re.compile(r"&#(?:[0-9]{1,7}|[xX][0-9A-Fa-f]{1,6});")

#: A deprecated entry earns its place by saying what replaced it. This is the
#: test for that: a forwarding pointer to another catalogued identifier.
_POINTER = re.compile(r"\b(?:CAPEC|CWE)[\s-]*[:-]?\s*\d+", re.IGNORECASE)


# ---------------------------------------------------------------------------
# fetch
# ---------------------------------------------------------------------------

def _fetch(cache_dir: Path) -> Path:
    """Download the catalogue into ``cache_dir`` once; return the XML file.

    Idempotent and network-free on re-run: a blob of plausible size short-
    circuits immediately, because the build runs often.

    The download lands on a staging name (:func:`~training.corpus.net.download`
    itself writes ``.part`` and renames), is validated there, and only then is
    renamed to the name :func:`_documents` looks for. An interrupted or
    error-page fetch therefore cannot leave a file that a later run mistakes for
    a complete cache — the failure mode that turns "idempotent" into a lie and
    silently trains on half a register.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    blob = cache_dir / _BLOB
    if blob.is_file() and blob.stat().st_size >= _MIN_BYTES:
        return blob

    staging = cache_dir / _STAGING
    try:
        download(_URL, staging, timeout=300)
    except NetworkError as exc:
        staging.unlink(missing_ok=True)
        raise SourceError(f"capec: could not fetch {_URL}: {exc}") from exc

    try:
        size = staging.stat().st_size
        if size < _MIN_BYTES:
            raise SourceError(
                f"capec: {_URL} returned only {size} bytes — that is an error "
                f"page or a truncated transfer, not the CAPEC catalogue"
            )
        # Parse before promoting: a body that is the right size but not the
        # catalogue (a login wall, an HTML redirect) must never be cached.
        version, date, patterns = _probe(staging)
    except Exception:
        staging.unlink(missing_ok=True)
        raise

    os.replace(staging, blob)
    _write_meta(cache_dir, version, date, patterns, size)
    return blob


def _probe(path: Path) -> tuple[str, str, int]:
    """Confirm the file really is a CAPEC catalogue; return version/date/count."""
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as exc:
        raise SourceError(f"capec: {path} is not parseable XML: {exc}") from exc
    if _local(root.tag) != _ROOT:
        raise SourceError(
            f"capec: {path} has root <{_local(root.tag)}>, expected <{_ROOT}>. "
            f"{_URL} is probably serving something other than the catalogue."
        )
    ns = _namespace(root)
    patterns = len(root.findall(f"{ns}Attack_Patterns/{ns}Attack_Pattern"))
    if patterns < 100:
        raise SourceError(
            f"capec: only {patterns} attack patterns in {path}; CAPEC 3.9 has "
            "615. The upstream layout has changed — fix the adapter rather than "
            "training on a fragment of the scarcest register in the corpus."
        )
    return str(root.get("Version", "")), str(root.get("Date", "")), patterns


def _write_meta(cache_dir: Path, version: str, date: str,
                patterns: int, size: int) -> None:
    """Record the fetched version and MITRE's licence beside the cache.

    Best-effort: a corpus build must not fail because a sidecar note could not
    be written.
    """
    try:
        (cache_dir / _META).write_text(
            json.dumps(
                {
                    "url": _URL,
                    "capec_version": version,
                    "capec_date": date,
                    "attack_patterns": patterns,
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

    Hardcoding ``capec-3`` would mean a CAPEC 4 release quietly yielding zero
    documents — every ``find`` would miss and the source would report success
    with nothing in it. Reading it here makes the same event either work or
    fail at the root-name check, both of which are better than silence.
    """
    tag = root.tag
    return tag[: tag.index("}") + 1] if tag.startswith("{") else ""


def _keep(text: str | None) -> str:
    """Keep a text node, minus the XML file's own pretty-printing indent.

    A whitespace-only node containing a newline is the serializer's layout, not
    content. A whitespace-only node *without* one is a real space between inline
    elements and is kept. Nodes with content are returned untouched — never
    stripped, never collapsed — which is safe here by measurement: no text node
    in the catalogue carries both content and a newline, so this rule can never
    reach inside a sentence or a line of example code.
    """
    if not text:
        return ""
    if text.strip():
        return text
    return "" if "\n" in text else text


def _flatten(element: ET.Element) -> str:
    """Render CAPEC's embedded XHTML as plain text, keeping block structure.

    Paragraphs become lines, ``<br/>`` becomes a newline, list items become
    ``- `` lines, and a ``<div style="margin-left:1em;">`` becomes a block
    indented by four spaces — nested divs nest, which is how CAPEC encodes
    indentation in its code and HTTP-transcript examples. Preserving that is the
    whole reason the contract forbids collapsing horizontal whitespace.

    Divs *without* a ``margin-left`` style are plain block wrappers (MITRE uses
    them around ``<i>`` comments inside code); indenting those too would push
    every comment one level deeper than the statement it annotates.
    """
    parts: list[str] = [_keep(element.text)]
    for child in element:
        tag = _local(child.tag)
        inner = _flatten(child)
        if tag == "br":
            parts.append("\n")
        elif tag in ("p", "ul", "ol", "table", "tr"):
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
            # b, i, em, strong, span, a — inline, tag dropped, text kept.
            parts.append(inner)
        parts.append(_keep(child.tail))
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

    Prerequisites, mitigations and example instances routinely run to several
    paragraphs plus a code block. Flush-left continuations would leave no way —
    for a reader or a model — to tell where one item ends and the next begins.
    """
    first, _, rest = text.partition("\n")
    if not rest:
        return marker + first
    tail = "\n".join((indent + line if line else "") for line in rest.split("\n"))
    return f"{marker}{first}\n{tail}"


def _attr(element: ET.Element, name: str) -> str:
    return str(element.get(name, "")).strip()


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

class _Catalog:
    """Parsed catalogue plus the two indexes rendering needs.

    ``names`` resolves a bare ``CAPEC_ID`` attribute to its human name, which is
    what turns ``ChildOf: 248`` — a naked integer that teaches nothing — into
    ``ChildOf: CAPEC-248 Command Injection``. ``references`` resolves the
    ``REF-###`` pointers that MITRE stores once at the end of the file and cites
    by id from inside every entry.
    """

    def __init__(self, path: Path) -> None:
        try:
            self.root = ET.parse(path).getroot()
        except (ET.ParseError, OSError) as exc:
            raise SourceError(f"capec: cannot read catalogue at {path}: {exc}") from exc
        if _local(self.root.tag) != _ROOT:
            raise SourceError(f"capec: {path} is not a {_ROOT}")
        self.ns = _namespace(self.root)
        self.version = str(self.root.get("Version", ""))
        self.date = str(self.root.get("Date", ""))

        self.patterns = self.root.findall(f"{self.ns}Attack_Patterns/{self.ns}Attack_Pattern")
        self.categories = self.root.findall(f"{self.ns}Categories/{self.ns}Category")
        self.views = self.root.findall(f"{self.ns}Views/{self.ns}View")

        self.names: dict[str, str] = {}
        for entry in (*self.patterns, *self.categories, *self.views):
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

    def named(self, capec_id: str) -> str:
        """``CAPEC-248 Command Injection`` — the id next to what it denotes."""
        name = self.names.get(capec_id, "")
        return f"CAPEC-{capec_id} {name}".strip()


def _header(entry: ET.Element, kind: str) -> list[str]:
    """The labelled preamble every entry shares.

    The id leads the document, is repeated on its own labelled line, and appears
    a third time inside a URL path. Three syntactic positions for one
    identifier, which is the shape of exposure the tokenizer measurement
    rewarded.
    """
    entry_id = _attr(entry, "ID")
    name = _attr(entry, "Name")
    lines = [
        f"CAPEC-{entry_id} {name}".strip(),
        "",
        f"CAPEC ID: CAPEC-{entry_id}",
        f"Name: {name}",
        f"Entry type: {kind}",
    ]
    for attribute, label in (("Abstraction", "Abstraction"), ("Type", "View type"),
                             ("Status", "Status")):
        if value := _attr(entry, attribute):
            lines.append(f"{label}: {value}")
    lines.append(f"URL: https://capec.mitre.org/data/definitions/{entry_id}.html")
    return lines


def _section(title: str, body: list[str]) -> list[str]:
    return ["", f"## {title}", "", *body] if body else []


def _render_pattern(catalog: _Catalog, entry: ET.Element) -> str:
    """One attack pattern, laid out as labelled sections of plain lines."""
    lines = _header(entry, "Attack Pattern")
    for tag, label in (("Likelihood_Of_Attack", "Likelihood of attack"),
                       ("Typical_Severity", "Typical severity")):
        value = entry.findtext(catalog.q(tag))
        if value and value.strip():
            lines.append(f"{label}: {value.strip()}")

    lines += _section("Description", [_text(catalog.find(entry, "Description"))])
    if extended := _text(catalog.find(entry, "Extended_Description")):
        lines += _section("Extended Description", [extended])

    alternates = [
        _bullet(" ".join(filter(None, [
            (term.findtext(catalog.q("Term")) or "").strip() + ":",
            _text(catalog.find(term, "Description")),
        ])).rstrip(":"))
        for term in catalog.children(entry, "Alternate_Terms", "Alternate_Term")
    ]
    lines += _section("Alternate Terms", alternates)

    lines += _section("Prerequisites", [
        _bullet(_text(item))
        for item in catalog.children(entry, "Prerequisites", "Prerequisite")
        if _text(item)
    ])

    lines += _section("Skills Required", [
        _bullet(f"[{_attr(skill, 'Level') or 'Unspecified'}] {_text(skill)}")
        for skill in catalog.children(entry, "Skills_Required", "Skill")
        if _text(skill)
    ])

    lines += _section("Resources Required", [
        _bullet(_text(item))
        for item in catalog.children(entry, "Resources_Required", "Resource")
        if _text(item)
    ])

    lines += _section("Execution Flow", _render_flow(catalog, entry))
    lines += _section("Consequences", _render_consequences(catalog, entry))

    lines += _section("Mitigations", [
        _bullet(_text(item))
        for item in catalog.children(entry, "Mitigations", "Mitigation")
        if _text(item)
    ])

    lines += _section("Indicators", [
        _bullet(_text(item))
        for item in catalog.children(entry, "Indicators", "Indicator")
        if _text(item)
    ])

    lines += _section("Example Instances", [
        _bullet(_text(item))
        for item in catalog.children(entry, "Example_Instances", "Example")
        if _text(item)
    ])

    lines += _section("Related Attack Patterns", [
        _bullet(f"{_attr(rel, 'Nature')}: {catalog.named(_attr(rel, 'CAPEC_ID'))}")
        for rel in catalog.children(entry, "Related_Attack_Patterns",
                                    "Related_Attack_Pattern")
        if _attr(rel, "CAPEC_ID")
    ])

    # CAPEC carries no CWE names, so the URL form is what puts the identifier in
    # a second syntactic position here.
    lines += _section("Related Weaknesses", [
        _bullet(f"CWE-{cwe} (https://cwe.mitre.org/data/definitions/{cwe}.html)")
        for weakness in catalog.children(entry, "Related_Weaknesses", "Related_Weakness")
        if (cwe := _attr(weakness, "CWE_ID"))
    ])

    lines += _section("Taxonomy Mappings", _render_taxonomy(catalog, entry))
    lines += _section("Notes", [
        _bullet(f"[{_attr(note, 'Type') or 'Other'}] {_text(note)}")
        for note in catalog.children(entry, "Notes", "Note")
        if _text(note)
    ])
    lines += _section("References", _render_references(catalog, entry))
    lines += _history(catalog, entry)
    return "\n".join(lines)


def _render_flow(catalog: _Catalog, entry: ET.Element) -> list[str]:
    """The Explore / Experiment / Exploit walk, step by step.

    The step's techniques are indented under it rather than listed flat: a
    technique belongs to a step, and that containment is the ordering knowledge
    this source contributes over ATT&CK's flat behaviour descriptions.
    """
    lines: list[str] = []
    for step in catalog.children(entry, "Execution_Flow", "Attack_Step"):
        number = (step.findtext(catalog.q("Step")) or "").strip()
        phase = (step.findtext(catalog.q("Phase")) or "").strip()
        body = _text(catalog.find(step, "Description"))
        head = f"Step {number} ({phase}): {body}" if phase else f"Step {number}: {body}"
        lines.append(_bullet(head, marker="", indent="  "))
        for technique in step.findall(catalog.q("Technique")):
            if text := _text(technique):
                lines.append(_bullet(text, marker="    Technique: ", indent="      "))
    return lines


def _render_consequences(catalog: _Catalog, entry: ET.Element) -> list[str]:
    lines: list[str] = []
    for consequence in catalog.children(entry, "Consequences", "Consequence"):
        scopes = ", ".join(s.text.strip()
                           for s in consequence.findall(catalog.q("Scope")) if s.text)
        impacts = "; ".join(i.text.strip()
                            for i in consequence.findall(catalog.q("Impact")) if i.text)
        notes = "; ".join(n.text.strip()
                          for n in consequence.findall(catalog.q("Note")) if n.text)
        likelihood = (consequence.findtext(catalog.q("Likelihood")) or "").strip()
        line = f"{scopes}: {impacts}" if impacts else scopes
        if notes:
            line += f" ({notes})"
        if likelihood:
            line += f" [likelihood {likelihood}]"
        if line:
            lines.append(_bullet(line))
    return lines


def _render_taxonomy(catalog: _Catalog, entry: ET.Element) -> list[str]:
    """Cross-taxonomy mappings, with ATT&CK ids restored to their wild form.

    CAPEC stores ``<Entry_ID>1574.010</Entry_ID>`` — a bare decimal. Emitted as
    written it is indistinguishable from a version number and is worth nothing
    to a tokenizer that has to recognise ``T1574.010`` in a threat report. The
    ``T`` is put back, and the technique URL gives the same id a second form
    with the sub-technique split across a path separator, exactly as the attack
    adapter renders it.
    """
    lines: list[str] = []
    for mapping in catalog.children(entry, "Taxonomy_Mappings", "Taxonomy_Mapping"):
        taxonomy = _attr(mapping, "Taxonomy_Name")
        entry_id = (mapping.findtext(catalog.q("Entry_ID")) or "").strip()
        entry_name = (mapping.findtext(catalog.q("Entry_Name")) or "").strip()
        if taxonomy == "ATTACK" and entry_id:
            path = "T" + entry_id.replace(".", "/")
            url = f"https://attack.mitre.org/techniques/{path}"
            lines.append(_bullet(f"ATT&CK: T{entry_id} {entry_name} ({url})"))
        elif taxonomy:
            label = f"{entry_id} {entry_name}".strip()
            lines.append(_bullet(f"{taxonomy}: {label}" if label else taxonomy))
    return lines


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

    See :data:`_HISTORY_NOTE`: the full ``Content_History`` block is 15% of the
    catalogue's text and almost all of it is the same four lines repeated some
    five thousand times.
    """
    history = catalog.find(entry, "Content_History")
    if history is None:
        return []
    bits: list[str] = []
    submission = catalog.find(history, "Submission")
    if submission is not None:
        date = (submission.findtext(catalog.q("Submission_Date")) or "").strip()
        if date:
            bits.append(f"submitted {date}")
    modifications = history.findall(catalog.q("Modification"))
    if modifications:
        date = (modifications[-1].findtext(catalog.q("Modification_Date")) or "").strip()
        if date:
            bits.append(f"last modified {date}")
    return ["", f"Content history: {', '.join(bits)}"] if bits else []


def _render_category(catalog: _Catalog, entry: ET.Element) -> str:
    """A CAPEC category: the taxonomy node and the patterns it collects.

    Worth a document of its own because the member list is a dense run of
    ``CAPEC-### Name`` pairs in one place — the grouping knowledge ("excavation
    and footprinting are both information collection") that no individual
    pattern states.
    """
    lines = _header(entry, "Category")
    lines += _section("Summary", [_text(catalog.find(entry, "Summary"))])
    lines += _section("Members", [
        _bullet(catalog.named(_attr(member, "CAPEC_ID")))
        for member in catalog.children(entry, "Relationships", "Has_Member")
        if _attr(member, "CAPEC_ID")
    ])
    lines += _section("Taxonomy Mappings", _render_taxonomy(catalog, entry))
    lines += _section("Notes", [
        _bullet(f"[{_attr(note, 'Type') or 'Other'}] {_text(note)}")
        for note in catalog.children(entry, "Notes", "Note")
        if _text(note)
    ])
    lines += _section("References", _render_references(catalog, entry))
    lines += _history(catalog, entry)
    return "\n".join(lines)


def _render_view(catalog: _Catalog, entry: ET.Element) -> str:
    """A CAPEC view: the organising principle behind a slice of the catalogue."""
    lines = _header(entry, "View")
    lines += _section("Objective", [_text(catalog.find(entry, "Objective"))])
    if selector := _text(catalog.find(entry, "Filter")):
        lines += _section("Filter", [selector])
    lines += _section("Members", [
        _bullet(catalog.named(_attr(member, "CAPEC_ID")))
        for member in catalog.children(entry, "Members", "Has_Member")
        if _attr(member, "CAPEC_ID")
    ])
    lines += _section("Notes", [
        _bullet(f"[{_attr(note, 'Type') or 'Other'}] {_text(note)}")
        for note in catalog.children(entry, "Notes", "Note")
        if _text(note)
    ])
    lines += _section("References", _render_references(catalog, entry))
    lines += _history(catalog, entry)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# documents
# ---------------------------------------------------------------------------

#: What the compacted ``Content_History`` block costs, stated once so the number
#: in the build log and the reasoning for it live together.
#:
#: Measured on CAPEC 3.9: ``Content_History`` is 246,431 characters, 15.1% of
#: all element text in the catalogue and the third largest field after execution
#: flows and descriptions. Essentially all of it is the same four lines —
#: ``CAPEC Content Team`` / ``The MITRE Corporation`` / a date / ``Updated
#: References, Taxonomy_Mappings`` — repeated once per modification, some five
#: thousand times. That is a memorisation hazard dressed as volume: the corpus
#: is 31M tokens against a 3B-token appetite, and text repeated five thousand
#: times is precisely the text a model at 97 epochs will learn by heart. The
#: dates survive as one line per entry; the boilerplate does not.
_HISTORY_NOTE = "Content_History boilerplate"


def _documents(path: Path) -> Iterator[Document]:
    """Yield attack patterns, then categories, then views — numerically ordered.

    Numeric order rather than string order so CAPEC-2 precedes CAPEC-10 and a
    build report reads like the catalogue does.

    Two holdbacks, both counted and printed rather than applied silently:

    *Deprecated categories* are dropped outright. All 57 are a single templated
    sentence with no members — 49 of them differ only in the name of the WASC
    item they used to mirror — so as documents they are 57 near-identical texts
    whose unique content is their header. The build's fingerprint dedup cannot
    catch them, because the differing id is inside the text.

    *Deprecated attack patterns* are kept only when the deprecation notice
    forwards to something: "deprecated as it is a duplicate of CAPEC-65" is a
    real fact about a real identifier that still appears in old reports, and
    dropping it would also throw away a valid ``CAPEC-###`` string from a corpus
    assembled because it had too few of them. A bare "This attack pattern has
    been deprecated." forwards nowhere and is held back.
    """
    catalog = _Catalog(_resolve(path))

    held_history = 0
    held_deprecated_categories = 0
    held_tombstones = 0
    emitted_history = 0

    for entry in sorted(catalog.patterns, key=_sort_key):
        status = _attr(entry, "Status")
        description = _text(catalog.find(entry, "Description"))
        if status == "Deprecated" and not _POINTER.search(description):
            held_tombstones += 1
            continue
        text = normalise(_render_pattern(catalog, entry))
        if len(text) < _MIN_CHARS:
            continue
        held, emitted = _history_cost(catalog, entry)
        held_history += held
        emitted_history += emitted
        yield Document(
            text=text,
            source="capec",
            register=Register.ADVERSARY,
            side=Side.RED,
            ident=f"CAPEC-{_attr(entry, 'ID')}",
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
        yield Document(
            text=text,
            source="capec",
            register=Register.ADVERSARY,
            side=Side.RED,
            ident=f"CAPEC-{_attr(entry, 'ID')} (category)",
        )

    for entry in sorted(catalog.views, key=_sort_key):
        text = normalise(_render_view(catalog, entry))
        if len(text) < _MIN_CHARS:
            continue
        held, emitted = _history_cost(catalog, entry)
        held_history += held
        emitted_history += emitted
        yield Document(
            text=text,
            source="capec",
            register=Register.ADVERSARY,
            side=Side.RED,
            ident=f"CAPEC-{_attr(entry, 'ID')} (view)",
        )

    # No silent caps: say what was held back and why.
    print(f"   capec: CAPEC {catalog.version} ({catalog.date}); held back "
          f"{held_history:,} chars of {_HISTORY_NOTE} "
          f"(kept {emitted_history:,} chars of dates)")
    if held_deprecated_categories:
        print(f"   capec: held back {held_deprecated_categories} deprecated "
              "categor(ies) — one templated sentence each, no members")
    if held_tombstones:
        print(f"   capec: held back {held_tombstones} deprecated attack "
              "pattern(s) whose notice names no replacement CAPEC or CWE")


def _resolve(path: Path) -> Path:
    """Accept either the XML file or the cache directory holding it."""
    if path.is_dir():
        candidate = path / _BLOB
        if not candidate.is_file():
            raise SourceError(
                f"capec: no {_BLOB} in {path} — run the source's fetch() first"
            )
        return candidate
    if not path.is_file():
        raise SourceError(f"capec: {path} does not exist")
    return path


def _sort_key(entry: ET.Element) -> tuple[int, str]:
    """Numeric order on the CAPEC id, with a stable fallback for oddities."""
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


_LICENSE = (
    "MITRE CAPEC Terms of Use. \"The MITRE Corporation (MITRE) hereby grants you "
    "a non-exclusive, royalty-free license to use Common Attack Pattern "
    "Enumeration and Classification (CAPEC) for research, development, and "
    "commercial purposes. Any copy you make for such purposes is authorized "
    "provided that you reproduce MITRE's copyright designation and this license "
    "in any such copy.\" Copyright (c) 2007-2026, The MITRE Corporation. CAPEC "
    "and the CAPEC logo are trademarks of The MITRE Corporation. Terms: "
    "https://capec.mitre.org/about/termsofuse.html"
)


SPEC = SourceSpec(
    name="capec",
    license=_LICENSE,
    url="https://capec.mitre.org/data/xml/capec_latest.xml",
    register=Register.ADVERSARY,
    side=Side.RED,
    fetch=_fetch,
    documents=_documents,
    #: CAPEC 3.9 yields 600 patterns (615 less 15 tombstones), 21 live
    #: categories and 13 views = 634. The floor sits well under that so a normal
    #: release cannot trip it, while a namespace or layout change that breaks
    #: the element lookups will.
    expect_min_docs=550,
    notes=(
        "The whole capec_latest.xml catalogue: attack patterns, live categories "
        "and views. Each entry carries its CAPEC-### id in three syntactic "
        "positions and keeps every cross-reference in the form the world writes "
        "it — CAPEC-###, CWE-### and ATT&CK T#### (CAPEC stores that one as a "
        "bare '1574.010', so the T is restored). Execution flows keep their "
        "Explore/Experiment/Exploit ordering with techniques indented under "
        "their step. Content_History boilerplate is compacted to two dates, "
        "deprecated categories are dropped, and deprecated patterns are kept "
        "only when they forward to a replacement."
    ),
)
