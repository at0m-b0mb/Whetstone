"""Nuclei templates — executable vulnerability checks. DETECTION/RED.

This is the largest freely licensed body of *executable* vulnerability-detection
logic that exists, and it sits exactly on the seam this project is built around.
A Nuclei template is one artefact read two ways depending on who holds it: to
the attacker it is "is this target vulnerable?", to the defender it is "is my
fleet exposed?". Nothing else in the corpus is literally the same bytes on both
sides of the purple line, and a model meant to reason across that line should
have met the artefact that straddles it a few thousand times.

**Why it earns its place, in three specific ways.**

*Identifiers beside the thing they name.* The measurement this corpus was
rebuilt around — recorded in :mod:`~training.corpus.source` — is that
``T1547.001 Registry Run Keys`` in running prose moved that sample from -45% to
+13% against gpt2, while the same identifier stripped of its name taught
nothing. Nuclei carries that pattern natively and densely: 4,315 templates state
a ``cve-id``, 7,127 a ``cwe-id``, 6,815 a full CVSS v3 vector string and 4,862 a
CPE, and every one of them sits in a file whose ``info.name`` is the human name
of the same vulnerability. The renderer's job is mostly to refuse to separate
them, and to put each id in more than one syntactic position — the template id,
the classification line, the NVD or CWE URL path, and the repository file path
are four positions for one CVE in a single document.

*Raw HTTP transcripts.* 6,436 raw request strings, 3,303 of which carry a body.
That is a surface form no other source here supplies: Sigma teaches what a
defender's rule looks like, CAPEC teaches how an attack is sequenced, and
neither shows a model a request line, a header block, a multipart boundary or a
URL-encoded body as bytes on a wire. A model asked to reason about web attack
traffic needs to have read some.

*Volume.* The corpus is ~30.6M tokens. This source is 13,536 renderable
templates, and it is dense rather than padded — each document is a paragraph of
prose welded to the check that the paragraph describes.

**Register: DETECTION. Side: RED.** DETECTION is unarguable — matchers,
extractors, DSL expressions and response-part names are detection logic in the
plainest sense, and until now that register was entirely blue, being Sigma
alone. The side is the judgement call, and it goes to RED. The brief allowed
BLUE if the remediation framing dominated, and it does not: ``remediation`` is
present on 5,434 of 13,743 templates while *every* template without exception is
an active, unsolicited request fired at a machine that did not ask for it.
Verification is what the tool is used *for* some of the time; probing is what it
*is* all of the time, and the register/side pair should describe the artefact,
not the intent of one operator. Calling it blue would also quietly flatter the
corpus balance, which is the sort of thing the build report exists to make
impossible.

**Licence: MIT.** Read from the repository's own ``LICENSE.md``, which opens
``MIT License`` / ``Copyright (c) 2025 ProjectDiscovery, Inc.`` — not assumed
from the badge in the README. ``fetch`` copies that file into the cache so the
claim sits beside the text it covers.

**The trap: block scalars are protocol, not formatting.** Nuclei stores raw
requests in YAML block scalars, and inside one the blank line between the header
block and the body is the thing that makes an HTTP request an HTTP request.
Mangle it and the document teaches a model a malformed protocol. The obvious
implementation — parse the YAML, re-emit the protocol section with
``yaml.safe_dump`` — is exactly the one that breaks: PyYAML will not choose
block style for a multi-line string on its own, so a request comes back out as a
double-quoted scalar with ``\\r\\n`` escapes in it, and even with a forced block
representer the key order, quoting style and flow decisions are the dumper's
rather than the author's.

So the protocol section is never round-tripped. It is **sliced out of the file
verbatim**, by line, and only the ``info`` block is parsed for prose. The slice
rule is that a YAML top-level key is the only thing that can appear at column
zero — content inside a block scalar is by definition indented deeper than the
key that introduced it — so the spans between column-zero keys are exact block
boundaries. That is an argument, so it was checked: across all 13,743 templates
the keys recovered by :func:`_logic_blocks` match ``yaml.load(...).keys()``
exactly, 13,743 times out of 13,743, zero mismatches. The YAML parser decides
*what* a template is and supplies the prose; the file itself supplies the logic,
byte for byte.

**What the shared cleaner does to those blocks, stated rather than avoided.**
:func:`~training.corpus.source.normalise` caps runs of blank lines at one. Of
the 6,436 raw requests, 3,303 carry a body, and in 3,300 of those the
header-to-body separator is a single blank line that survives untouched; in
three templates upstream left a stray second blank line there and the cap
collapses it to the canonical single separator, which is a repair rather than
damage. The claim was checked after rendering rather than reasoned about: in
every one of the 13,518 uncapped documents, each separator with content on both
sides is still present with exactly one blank line between the same two lines —
3,180 of them, zero broken. Two or more consecutive blank lines occur
anywhere in the logic of 105 of 13,743 templates (0.8%), and there they are an
empty multipart field value or cosmetic spacing inside embedded JavaScript —
never a separator with content on both sides. Nothing is worked around privately
here: a source that quietly runs its own cleaner is how a corpus stops being
comparable across sources, and if that guarantee in ``normalise`` ever changes,
this is one of the two registers where it will show up as damage first.

**One cap, on the verbatim block, because a handful of templates are
machine-generated catalogues.** Rendered uncapped, this source is 38.3 MB — and
10.1 MB of that is *one file*,
``http/technologies/wordpress/plugins/wordpress-plugin-detect.yaml``, which is a
generated list of roughly a hundred thousand near-identical ``- type: word`` /
``words: - "/wp-content/plugins/<name>/"`` stanzas. The top ten documents are
32.6% of the source. A model learns the shape of that stanza from the first
dozen and memorises slug names from the rest, which is the failure
:mod:`~training.corpus.build` names explicitly: duplicated text in a small
corpus is worse than absent text. The distribution says where to cut — the
median document is 1,604 characters and the 99th percentile is 6,047 — so the
verbatim section is capped at 24,000 characters, which touches 18 documents of
13,536 (0.13%) and takes the source from 38.3 MB to 25.9 MB, with the largest
five documents falling from 32.6% of it to 0.49%. The cut lands on a line
boundary and leaves a comment saying how many lines were elided and where the
whole template is, because a silent truncation reads as "this is the template"
when it is not. The prose header is never capped, and nothing smaller than the
cap is altered in any way.

**Fetch: a codeload tarball, not ``git clone --depth 1``.** Same result — one
snapshot, no history — but it needs no ``git`` binary, is one request of 9.8 MB,
goes through :mod:`~training.corpus.net` so the TLS trust decision lives in the
one place this project makes it, and leaves nothing behind that a later ``git
pull`` could mutate underneath a build that is supposed to be reproducible. That
is the pattern every other repository-shaped source here already uses.

**What is skipped.** ``workflows/`` (207 files) chain other templates by name
and contain no detection logic of their own — rendering them would emit a
document whose body is a list of filenames. ``profiles/`` are scan profiles and
``helpers/`` are wordlists and payload files, neither of which is a template.
Anything that parses but has no top-level key other than ``id`` and ``info`` is
skipped for the same reason: an empty document is worse than a missing one,
because it still counts in the build report.
"""

from __future__ import annotations

import json
import re
import shutil
import tarfile
import time
from collections import Counter
from pathlib import Path
from typing import Any, Iterator

import yaml

from ..net import NetworkError, download
from ..source import Document, Register, Side, SourceError, SourceSpec, normalise

try:  # libyaml when the wheel has it: ~5x faster over fourteen thousand files
    from yaml import CSafeLoader as _Loader  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - depends on the local PyYAML build
    from yaml import SafeLoader as _Loader  # type: ignore[assignment]

__all__ = ["SPEC"]

# ---------------------------------------------------------------------------
# upstream
# ---------------------------------------------------------------------------

_REPO = "projectdiscovery/nuclei-templates"
_REF = "main"
_TARBALL = f"https://codeload.github.com/{_REPO}/tar.gz/refs/heads/{_REF}"
_HOME = f"https://github.com/{_REPO}"
_BLOB = f"{_HOME}/blob/{_REF}/"

#: The template trees worth collecting. ``http`` is 11,365 files on its own;
#: the rest are small but each carries a protocol surface the http tree does not
#: — ``tcp`` banner exchanges under ``network/``, DNS answers, TLS certificate
#: assertions, and cloud-posture checks that shell out to ``aws`` / ``az`` /
#: ``gcloud``. Deliberately absent: ``workflows/`` (template chaining, no logic),
#: ``profiles/`` (scan configuration) and ``helpers/`` (wordlists and payloads).
_TEMPLATE_DIRS: frozenset[str] = frozenset({
    "http", "network", "dns", "file", "ssl",
    "code", "javascript", "headless", "cloud", "dast",
})

#: The directory the cache is normalised into, so ``documents`` has one layout
#: to expect regardless of what the archive's root directory was called.
_TREE = "templates"
_LICENSE_FILE = "LICENSE.md"

#: Written last, so its presence means "extraction finished". A half-unpacked
#: cache therefore re-fetches instead of silently yielding a partial corpus.
_MARKER = ".fetched.json"

#: 13,743 template files were present upstream when this adapter was written.
#: A floor well below that catches a renamed or moved tree loudly at fetch time
#: rather than as a mysteriously thin build report four steps downstream.
_MIN_EXTRACTED = 8_000

#: Below this a rendering is a header with nothing under it. Real templates
#: start around 400 characters once the prose and the logic are both present.
_MIN_CHARS = 200

#: Ceiling on the verbatim logic block. The argument and the measurement are in
#: the module docstring; the short version is that a handful of generated
#: fingerprint catalogues would otherwise be a third of the source. Sits far
#: above the 99th percentile (6,047 characters), so it touches 18 documents.
_MAX_LOGIC_CHARS = 24_000

#: A 9.8 MB tarball; anything an order of magnitude smaller is an error page.
_MIN_BYTES = 2_000_000

# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------

#: A YAML top-level key. Content inside a block scalar is always indented
#: deeper than the key that introduced it, so column zero can only be a key (or
#: a comment, which this deliberately does not match — a stray comment stays
#: attached to the block above it rather than starting a phantom one).
_TOP_KEY = re.compile(r"^([A-Za-z_][A-Za-z0-9_.-]*):(?:\s|$)")

#: Keys rendered as prose in the header, and therefore not repeated verbatim.
_PROSE_KEYS = frozenset({"id", "info"})

#: ProjectDiscovery signs every template with a trailing comment holding two
#: 128-character hex blobs. Across the tree that is ~2 MB of hex that teaches a
#: tokenizer nothing except that hex exists, which it already knows from
#: everywhere else. Dropped.
_DIGEST_LINE = re.compile(r"^# digest: .*$\n?", re.MULTILINE)

#: A comma that is not backslash-escaped, which is the only kind that separates
#: two identifiers packed into one field.
_UNESCAPED_COMMA = re.compile(r"(?<!\\),")

#: Only a numeric CWE gets a URL. The catalogue also carries ``NVD-CWE-Other``
#: and ``NVD-CWE-noinfo`` placeholders on old entries, and inventing a
#: definitions URL for those would fabricate a page that does not exist.
_CWE_NUM = re.compile(r"^CWE-(\d+)$", re.IGNORECASE)

#: Protocol blocks, mapped to how the check is described in the summary
#: sentence. The key is the template's own top-level key, so this stays honest
#: about Nuclei's naming (``network/`` templates use ``tcp:``).
_PROTOCOL_VERBS: dict[str, tuple[str, str]] = {
    "http": ("sends", "HTTP request"),
    "headless": ("drives", "headless browser flow"),
    "tcp": ("opens", "raw TCP exchange"),
    "network": ("opens", "raw network exchange"),
    "dns": ("makes", "DNS query"),
    "ssl": ("inspects", "TLS certificate"),
    "file": ("scans", "file rule"),
    "code": ("runs", "code block on the host"),
    "javascript": ("runs", "javascript check"),
    "websocket": ("opens", "websocket exchange"),
    "whois": ("makes", "whois query"),
}

#: Metadata keys whose values are real query-language strings — Shodan filter
#: syntax, FOFA expressions, Google dorks, PublicWWW source searches. They are
#: kept because they are a register of their own
#: (``http.favicon.hash:1375401192``, ``app="Apache-Tomcat"``,
#: ``intitle:"index of" ".sqlite_history"``) that appears nowhere else in this
#: corpus, and because they name the exposed population the template hunts.
#: Two neighbouring keys are deliberately *not* here: ``wpscan`` holds an
#: advisory URL, which is a reference and is already in ``info.reference``, and
#: ``plugin_namespace`` holds a bare slug. Neither is a query, and filing them
#: under one would be a small lie in a section heading.
_QUERY_SUFFIXES = ("-query", "-dork")
_QUERY_KEYS = frozenset({"public-www", "publicwww"})


def _strings(value: Any) -> list[str]:
    """Flatten a scalar-or-list field into a list of non-empty strings.

    Nuclei is inconsistent about this by hand-authoring: ``reference`` is a list
    10,600 times and a bare string 4 times, ``cwe-id`` is a string 7,126 times
    and a list once, and 384 templates pack several CWEs into one
    comma-separated string. Every one of those is a real identifier that the
    renderer would otherwise drop or mangle, so they are all normalised to the
    same shape here rather than guarded at each call site.
    """
    if value is None:
        return []
    items = value if isinstance(value, (list, tuple)) else [value]
    out: list[str] = []
    for item in items:
        if item is None or isinstance(item, (dict, list, tuple)):
            continue
        text = str(item).strip()
        if not text:
            continue
        # Commas separate identifiers in classification fields, but they also
        # appear *inside* reference URLs, CVSS vectors and prose. So the split
        # is guarded rather than unconditional: it fires only when every piece
        # is still a bare token with no space and no slash in it, which a URL
        # and a sentence both fail.
        #
        # A backslash-escaped comma is never a separator — CPE 2.3 formatted
        # strings escape punctuation that way, and 12 templates carry a product
        # name like ``free_booking_plugin_for_hotels\,_restaurant_and_car_rental``
        # that an unguarded split would tear in half.
        pieces = [p.strip() for p in _UNESCAPED_COMMA.split(text)]
        if len(pieces) > 1 and all(p and " " not in p and "/" not in p for p in pieces):
            out.extend(pieces)
        else:
            out.append(text)
    return out


def _logic_blocks(raw: str) -> list[tuple[str, str]]:
    """Slice the file into ``(top-level key, verbatim text)`` spans.

    This is the whole reason the source does not round-trip through the YAML
    dumper. A span runs from one column-zero key to the line before the next,
    so whatever the author wrote between them — block scalars, blank lines,
    quoting style, key order, inline comments — comes out unchanged. The
    correctness argument is in the module docstring and was verified against the
    parser for all 13,743 templates.
    """
    lines = raw.split("\n")
    starts = [
        (index, match.group(1))
        for index, line in enumerate(lines)
        if (match := _TOP_KEY.match(line))
    ]
    blocks: list[tuple[str, str]] = []
    for position, (index, key) in enumerate(starts):
        end = starts[position + 1][0] if position + 1 < len(starts) else len(lines)
        blocks.append((key, "\n".join(lines[index:end]).rstrip()))
    return blocks


def _walk(node: Any) -> Iterator[dict[str, Any]]:
    """Every mapping anywhere under ``node``, for collecting matchers.

    Matchers and extractors are not at a fixed depth: they hang off a request
    entry, but a ``flow``-driven template nests them under per-protocol lists and
    a fuzzing template puts them beside ``payloads`` and ``fuzzing`` rules. A
    recursive walk is simpler than modelling every shape Nuclei allows, and it
    cannot miss one the day upstream adds another.
    """
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk(value)


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

def _commas(items: list[str]) -> str:
    """``a``, ``a and b``, ``a, b and c`` — an English list, not a CSV.

    The summary sentence is the one place in this source that is prose rather
    than transcript, and it is there to bind the words to the block underneath.
    A sentence that reads ``1 status, 1 word matchers hold`` does that job worse
    than one that reads like a person wrote it.
    """
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def _section(title: str, body: list[str]) -> list[str]:
    """A titled section, or nothing at all if there is nothing to put in it.

    The blank filter matters: several single-value sections pass a one-element
    list straight through, and a list holding one empty string is still truthy.
    A bare heading followed by the next heading teaches that a heading can be
    followed by nothing, which is structural noise.
    """
    kept = [line for line in body if line.strip()]
    return ["", f"## {title}", "", *kept] if kept else []


def _classification(info: dict[str, Any], name: str) -> list[str]:
    """CVE, CWE, CVSS, EPSS and CPE — each id beside what it denotes.

    The CVE line is the one that carries this source's argument: the identifier,
    the human name of the vulnerability it labels, and the identifier again
    inside an NVD URL path. That is the shape the tokenizer measurement
    rewarded, and it is free here because Nuclei already stores both halves.
    """
    cls = info.get("classification")
    if not isinstance(cls, dict):
        return []

    lines: list[str] = []
    for cve in _strings(cls.get("cve-id")):
        lines.append(f"- {cve} {name} (https://nvd.nist.gov/vuln/detail/{cve})")
    for cwe in _strings(cls.get("cwe-id")):
        if match := _CWE_NUM.match(cwe):
            number = match.group(1)
            lines.append(
                f"- {cwe} (https://cwe.mitre.org/data/definitions/{number}.html)"
            )
        else:
            lines.append(f"- {cwe}")

    vector = str(cls.get("cvss-metrics") or "").strip()
    score = cls.get("cvss-score")
    severity = str(info.get("severity") or "").strip()
    if vector:
        tail = f" — CVSS base score {score}" if score is not None else ""
        tail += f" ({severity})" if severity and tail else ""
        lines.append(f"- {vector}{tail}")
    elif score is not None:
        lines.append(f"- CVSS base score {score}"
                     + (f" ({severity})" if severity else ""))

    epss = cls.get("epss-score")
    percentile = cls.get("epss-percentile")
    if epss is not None:
        suffix = f" (percentile {percentile})" if percentile is not None else ""
        lines.append(f"- EPSS score {epss}{suffix}")

    for cpe in _strings(cls.get("cpe")):
        lines.append(f"- {cpe}")
    return lines


def _affected(info: dict[str, Any]) -> list[str]:
    """Vendor, product and framework, as labelled lines.

    Kept separate from the classification bullets because these are the words a
    model needs in order to connect ``cpe:2.3:a:getlasso:simple_urls`` to the
    prose above it — the CPE's own segments are the same two tokens, and seeing
    them labelled once makes the packed form readable rather than opaque.
    """
    meta = info.get("metadata")
    if not isinstance(meta, dict):
        return []
    lines = []
    for key, label in (("vendor", "Vendor"), ("product", "Product"),
                       ("framework", "Framework")):
        if value := str(meta.get(key) or "").strip():
            lines.append(f"{label}: {value}")
    return lines


def _queries(info: dict[str, Any]) -> list[str]:
    """Shodan / FOFA / Google / PublicWWW strings that find the exposed hosts.

    These are copied whole, never through :func:`_strings`: a query is one
    expression, and its commas belong to its own syntax
    (``body="a",title="b"``) rather than separating two of them. The key name
    is kept as the label because ``shodan-query`` and ``fofa-query`` are
    different languages and the label is what says which.
    """
    meta = info.get("metadata")
    if not isinstance(meta, dict):
        return []
    lines = []
    for key, value in meta.items():
        name = str(key)
        if not (name.endswith(_QUERY_SUFFIXES) or name in _QUERY_KEYS):
            continue
        items = value if isinstance(value, list) else [value]
        for item in items:
            if item is None or isinstance(item, (dict, list)):
                continue
            if text := str(item).strip():
                lines.append(f"- {name}: {text}")
    return lines


def _summary(doc: dict[str, Any]) -> list[str]:
    """One or two sentences saying what the logic below actually does.

    The point is the binding, not the summary. A model that reads a matcher
    block cold learns the syntax; a model that reads "flags the target when its
    dsl matcher holds" immediately above the same block learns what the syntax
    is *for*. Everything in these sentences is derived from the parsed template,
    so it cannot drift away from the verbatim text underneath it.
    """
    protocols = [key for key in doc if key in _PROTOCOL_VERBS]
    if not protocols:
        return []

    clauses: list[str] = []
    for protocol in protocols:
        block = doc[protocol]
        entries = block if isinstance(block, list) else [block]
        verb, noun = _PROTOCOL_VERBS[protocol]
        count = 0
        raw_form = False
        for entry in entries:
            if not isinstance(entry, dict):
                count += 1
                continue
            if isinstance(entry.get("raw"), list):
                count += len(entry["raw"])
                raw_form = True
            elif isinstance(entry.get("path"), list):
                count += len(entry["path"])
            else:
                count += 1
        shape = "raw " if raw_form else ""
        plural = "" if count == 1 else "s"
        # The protocol is named in parentheses only when there is more than one
        # of them; with a single block it is already on the header line above
        # and repeating it reads as filler.
        suffix = f" ({protocol})" if len(protocols) > 1 else ""
        clauses.append(f"{verb} {count} {shape}{noun}{plural}{suffix}")

    matchers: Counter[str] = Counter()
    extractors: Counter[str] = Counter()
    parts: list[str] = []
    conditions: set[str] = set()
    for mapping in _walk({k: v for k, v in doc.items() if k not in _PROSE_KEYS}):
        if isinstance(mapping.get("matchers"), list):
            for item in mapping["matchers"]:
                if not isinstance(item, dict):
                    continue
                matchers[str(item.get("type") or "unspecified")] += 1
                if part := str(item.get("part") or "").strip():
                    if part not in parts:
                        parts.append(part)
        if isinstance(mapping.get("extractors"), list):
            for item in mapping["extractors"]:
                if isinstance(item, dict):
                    extractors[str(item.get("type") or "unspecified")] += 1
        for key in ("matchers-condition", "condition"):
            if value := str(mapping.get(key) or "").strip():
                conditions.add(value)

    sentence = "The check " + ", then ".join(clauses)
    if matchers:
        listed = _commas([f"{n} {t}" for t, n in sorted(matchers.items())])
        sentence += f", and reports the target when {listed} matcher"
        sentence += "s hold" if sum(matchers.values()) != 1 else " holds"
        if conditions == {"and"}:
            sentence += " with every clause required"
        elif conditions == {"or"}:
            sentence += " with any one clause enough"
    sentence += "."

    lines = [sentence]
    if parts:
        lines.append(f"Response parts read: {', '.join(parts)}.")
    if extractors:
        listed = _commas([f"{n} {t}" for t, n in sorted(extractors.items())])
        lines.append(f"Extractors: {listed}.")
    return lines


def _render(doc: dict[str, Any], raw: str, relative: str) -> str:
    """One template as a document: prose above, its own logic verbatim below."""
    info = doc.get("info")
    if not isinstance(info, dict):
        return ""
    name = str(info.get("name") or "").strip()
    template_id = str(doc.get("id") or "").strip()
    if not name or not template_id:
        return ""

    blocks = [(key, text) for key, text in _logic_blocks(raw)
              if key not in _PROSE_KEYS and text.strip()]
    if not blocks:
        return ""

    protocols = [key for key, _ in blocks if key in _PROTOCOL_VERBS]

    # The identifier leads the document, is repeated on its own labelled line,
    # and appears in the repository path and again in the blob URL. For the
    # 4,315 templates whose id *is* a CVE, the classification section below adds
    # a fifth position, inside an NVD URL path.
    lines = [
        f"Nuclei template {template_id}: {name}",
        "",
        f"Template ID: {template_id}",
        f"Name: {name}",
    ]
    if severity := str(info.get("severity") or "").strip():
        lines.append(f"Severity: {severity}")
    if protocols:
        lines.append(f"Protocol: {', '.join(dict.fromkeys(protocols))}")
    if author := ", ".join(_strings(info.get("author"))):
        lines.append(f"Author: {author}")
    lines.append(f"Path: {relative}")
    lines.append(f"URL: {_BLOB}{relative}")

    lines += _section("Description", [str(info.get("description") or "").strip()])
    lines += _section("Impact", [str(info.get("impact") or "").strip()])
    lines += _section("Remediation", [str(info.get("remediation") or "").strip()])
    lines += _section("Classification", _classification(info, name))
    lines += _section("Affected", _affected(info))
    lines += _section("Discovery Queries", _queries(info))
    # Tags stay exactly as upstream writes them — comma-joined, no spaces
    # (``wpscan,packetstorm,cve,cve2023,xss``). Re-joining them with ", "
    # would be tidier and would also be a different token sequence from the one
    # a model will meet in a real template, which is the whole point of keeping
    # surface forms wild.
    if tags := str(info.get("tags") or "").strip():
        lines += _section("Tags", [tags])
    lines += _section("References",
                      [f"- {ref}" for ref in _strings(info.get("reference"))])

    # Everything below this heading is the file's own bytes. The summary is
    # generated, the logic is not, and the two are separated so it is obvious
    # which is which — to a reader and to a model.
    verbatim = "\n\n".join(text for _, text in blocks)
    if len(verbatim) > _MAX_LOGIC_CHARS:
        # Cut on a line boundary so the tail is a whole line, then say so. A
        # truncation that does not announce itself teaches that this *is* the
        # template, and the elided part of a generated catalogue is exactly the
        # part a model would memorise rather than learn from.
        head = verbatim[:_MAX_LOGIC_CHARS].rsplit("\n", 1)[0]
        elided = verbatim[len(head):].count("\n")
        verbatim = (f"{head}\n# ... {elided:,} further lines elided; the whole "
                    f"template is at {_BLOB}{relative}")

    # The leading newline is carried inside the string rather than passed as an
    # empty list element, because _section drops blank entries.
    lines += _section("Detection Logic", [*_summary(doc), "\n" + verbatim])
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# fetch
# ---------------------------------------------------------------------------

def _extract(archive: Path, staging: Path) -> int:
    """Unpack the template trees (plus ``LICENSE.md``) into ``staging``.

    Members are copied out by hand rather than via ``TarFile.extractall``. The
    tarball is trusted in practice, but an archive member is attacker-controlled
    data in principle: absolute paths, ``..`` segments and symlinks are all
    expressible in tar. Only regular files are written, and every destination is
    proved to resolve inside ``staging`` before it is opened.
    """
    tree = staging / _TREE
    tree.mkdir(parents=True, exist_ok=True)
    resolved = tree.resolve()
    written = 0

    try:
        with tarfile.open(archive, mode="r:gz") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                parts = Path(member.name).parts
                if len(parts) < 2:
                    continue
                # Drop the archive's single root ("nuclei-templates-main/").
                relative = Path(*parts[1:])
                if relative.is_absolute() or ".." in relative.parts:
                    continue

                if relative.as_posix() == _LICENSE_FILE:
                    target = staging / _LICENSE_FILE
                    fence = staging.resolve()
                elif (relative.parts[0] in _TEMPLATE_DIRS
                      and relative.suffix == ".yaml"):
                    target = tree / relative
                    fence = resolved
                else:
                    continue
                if not target.resolve().is_relative_to(fence):
                    continue

                source = tar.extractfile(member)
                if source is None:
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with source, target.open("wb") as handle:
                    shutil.copyfileobj(source, handle)
                if relative.suffix == ".yaml":
                    written += 1
    except (tarfile.TarError, OSError) as exc:
        raise SourceError(f"nuclei: could not unpack {archive}: {exc}") from exc

    if written < _MIN_EXTRACTED:
        raise SourceError(
            f"nuclei: only {written} template files found under "
            f"{sorted(_TEMPLATE_DIRS)} in {_TARBALL} (expected >= "
            f"{_MIN_EXTRACTED}). The upstream layout has probably changed; fix "
            "the adapter rather than training on a fraction of the source."
        )
    return written


def _fetch(cache_dir: Path) -> Path:
    """Populate ``cache_dir`` with the template trees; return the cache root.

    Idempotent and network-free on re-run: the completion marker is written only
    after a full extraction, so a populated cache short-circuits immediately.
    The build runs often and this source is 9.8 MB over the wire.

    The archive lands on a staging name and is validated there; only a complete
    tree is swapped into place. An interrupted fetch therefore cannot leave a
    half-populated directory that a later run mistakes for a finished one —
    which is the failure mode that turns "idempotent" into a lie and silently
    trains on a fraction of a register.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    tree = cache_dir / _TREE
    marker = cache_dir / _MARKER
    if marker.is_file() and tree.is_dir():
        return cache_dir

    archive = cache_dir / ".nuclei-templates.tar.gz.staging"
    staging = cache_dir / ".staging"
    shutil.rmtree(staging, ignore_errors=True)
    try:
        try:
            download(_TARBALL, archive, timeout=300)
        except NetworkError as exc:
            raise SourceError(f"nuclei: could not fetch {_TARBALL}: {exc}") from exc

        size = archive.stat().st_size
        if size < _MIN_BYTES:
            raise SourceError(
                f"nuclei: {_TARBALL} returned only {size} bytes — that is an "
                "error page or a truncated transfer, not the template archive"
            )
        written = _extract(archive, staging)

        shutil.rmtree(tree, ignore_errors=True)
        (staging / _TREE).replace(tree)
        license_file = staging / _LICENSE_FILE
        if license_file.is_file():
            license_file.replace(cache_dir / _LICENSE_FILE)
        marker.write_text(
            json.dumps(
                {
                    "url": _TARBALL,
                    "repo": _REPO,
                    "ref": _REF,
                    "template_files": written,
                    "bytes": size,
                    "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "license": "MIT — LICENSE.md, Copyright (c) ProjectDiscovery, Inc.",
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    finally:
        archive.unlink(missing_ok=True)
        shutil.rmtree(staging, ignore_errors=True)
    return cache_dir


# ---------------------------------------------------------------------------
# documents
# ---------------------------------------------------------------------------

def _documents(path: Path) -> Iterator[Document]:
    """Yield one Document per renderable template, in a stable sorted order.

    Accepts either the cache root :func:`_fetch` returns or the ``templates/``
    directory inside it, so a caller that passes one instead of the other still
    works.
    """
    root = path / _TREE if (path / _TREE).is_dir() else path

    for file in sorted(root.rglob("*.yaml")):
        if not file.is_file():
            continue
        try:
            raw = file.read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        # The signature comment is dropped before slicing, not after, so it can
        # never end up glued to the tail of the last verbatim block.
        raw = _DIGEST_LINE.sub("", raw)
        try:
            doc = yaml.load(raw, Loader=_Loader)
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict):
            continue

        rendered = _render(doc, raw, file.relative_to(root).as_posix())
        if not rendered:
            continue
        text = normalise(rendered)
        if len(text) < _MIN_CHARS:
            continue
        yield Document(
            text=text,
            source="nuclei",
            register=Register.DETECTION,
            side=Side.RED,
            # Repo-relative path: unique, stable across fetches, and readable in
            # a build report ("http/cves/2023/CVE-2023-0099.yaml").
            ident=file.relative_to(root).as_posix(),
        )


SPEC = SourceSpec(
    name="nuclei",
    license="MIT — https://github.com/projectdiscovery/nuclei-templates/blob/main/"
            "LICENSE.md (Copyright (c) ProjectDiscovery, Inc.)",
    url=_HOME,
    register=Register.DETECTION,
    side=Side.RED,
    fetch=_fetch,
    documents=_documents,
    #: 13,743 template files upstream at the time of writing, of which 13,536
    #: render (workflows carry no logic of their own). The floor sits well below
    #: that so a pruned tree is tolerated and a moved one is not.
    expect_min_docs=9_000,
    notes=("The http/, network/, dns/, file/, ssl/, code/, javascript/, "
           "headless/, cloud/ and dast/ trees; workflows/, profiles/ and "
           "helpers/ are excluded as they hold no detection logic. Each "
           "document is the info block rendered as prose — name, description, "
           "impact, remediation, CVE/CWE/CVSS/CPE beside what they denote — "
           "above the template's own protocol blocks sliced out of the file "
           "verbatim. The logic is never round-tripped through the YAML "
           "dumper: block scalars hold raw HTTP requests whose header/body "
           "blank line is protocol, not formatting."),
)
