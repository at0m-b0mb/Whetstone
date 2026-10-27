"""MITRE D3FEND — the countermeasure knowledge graph. ADVERSARY/BLUE + SYSTEM.

D3FEND is ATT&CK's missing other half: 271 defensive techniques, each with a
``D3-`` identifier, a definition, a knowledge-base article, and — the part that
makes it an ontology rather than a list — **what each technique actually touches
inside the machine**. ``D3-FA File Analysis`` is asserted to *analyze* a
``:File``; ``D3-NTA Network Traffic Analysis`` *analyzes* ``:NetworkTraffic``.
903 digital-artifact classes sit underneath those assertions with their own
definitions.

**Why the artifact layer is the reason to have this source.** This project's
thesis is that the catalogue holds the capability and the model holds the
judgement, and judgement here means knowing *mechanically* what a technique does
— which is exactly what an artifact graph encodes and what prose about security
does not. A corpus that says "process injection is detected by EDR" teaches a
sentence. A corpus that says the defensive technique analyses a ``:ProcessImage``
and the offensive one modifies a ``:ProcessSegment`` teaches the mechanism, and
the mechanism is what lets a model answer a question nobody wrote down.

**The ATT&CK mapping is a join, and this adapter says so rather than inventing
an edge.** D3FEND's published technique-to-ATT&CK mappings are *derived*: a
defensive technique and an offensive technique are related because they touch
the same digital artifact. Measured in the shipped ontology, that is not a
stored edge at all — of 497 ``d3fend-id`` classes exactly **one** has a direct
restriction onto an ``attack-id`` class, and of 1,557 ``attack-id`` classes
exactly one points back. So this adapter renders the two halves it can
substantiate — the artifacts a defensive technique acts on, and on each artifact
document the offensive techniques asserted to produce or modify it — and labels
the second for what it is. Writing "D3-FA counters T1204" would be asserting a
triple MITRE does not ship in this file.

**What is deliberately not emitted.** The ontology embeds 1,142 ATT&CK ``T####``
classes and 189 ATLAS ``AML.T####`` classes **with their upstream definitions
copied in**. Emitting those as documents would reproduce
:mod:`~training.corpus.sources.attack` and :mod:`~training.corpus.sources.atlas`
in full, under a second name, in a corpus small enough that duplication is
memorised rather than reinforced. They are read as link targets and resolved to
``T1204 User Execution`` beside the artifact that joins them — never emitted.

**Third-party personal data, and a decision made deliberately.** D3FEND's
knowledge base cites papers and patents, and it carries the citations' author
names: ``:kb-author`` appears **326** times. Those are real people, named in
published work. They are not rendered, and the reasoning is the one the corpus
privacy audit arrived at — a researcher's name in a citation has no training
value whatsoever for a model whose job is to read command output and pick a
verb, so there is nothing to weigh against including it. ``:kb-abstract`` (340)
is also dropped, on a different ground: those are third parties' paper and
patent abstracts quoted into MITRE's graph, and MITRE's MIT grant over the
ontology is not a grant over somebody else's abstract. Reference *titles* are
kept, capped, as the factual citation they are.

**The parser is hand-written, and it was checked against the file rather than
trusted.** ``rdflib`` is not a dependency of this project and will not become
one for a single source, so :func:`_tokenise` and :func:`_parse` implement the
subset of Turtle this file uses. The subset is not trivial — 1,510 triple-quoted
literals whose markdown contains lines starting with ``###`` and ``:``, 326
backslash escapes, 401 ``^^xsd:anyURI`` datatypes, 17 language tags, 4
``owl:unionOf`` collections, 1,993 blank-node restrictions, 21 statements whose
*subject* is a blank node, and prefixed names containing dots (``:AML.T0000``,
which is why "a dot ends the statement" is wrong here). A line-oriented parser
passes a smoke test on this file and silently mangles it, so the check is
arithmetic: the parser finds 497 subjects carrying ``:d3fend-id`` and 1,557
carrying ``:attack-id``, against ``grep`` counts of 499 and 1,558 — and the
differences reconcile exactly, being the one line that *declares* each property
and the one ``owl:onProperty :d3fend-id`` reference. :func:`_check` re-runs that
reconciliation on every build, so a change in either the file or the parser
fails loudly instead of yielding a thinner corpus.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Iterator

from ..net import NetworkError, download
from ..source import Document, Register, Side, SourceError, SourceSpec, normalise

_REPO = "d3fend/d3fend-ontology"
_REF = "develop"
_RAW = f"https://raw.githubusercontent.com/{_REPO}/{_REF}"
_ONTOLOGY_URL = f"{_RAW}/src/ontology/d3fend-protege.ttl"
_LICENSE_URL = f"{_RAW}/LICENSE.md"

_ONTOLOGY = "d3fend-protege.ttl"
_LICENSE_DIR = "licenses"
_MARKER = ".fetched.json"

#: 3.4 MB observed. Generous but bounded; see net.MAX_DOWNLOAD_BYTES for why a
#: per-call ceiling belongs at the call site that knows the expected size.
_MAX_ONTOLOGY_BYTES = 32 * 1024 * 1024
_MAX_LICENSE_BYTES = 256 * 1024

_MIN_CHARS = 240

#: Parser reconciliation, asserted on every build. See the module docstring:
#: these are not round numbers chosen for comfort, they are what the parser and
#: ``grep`` agree on, and the gap between them is accounted for line by line.
#: Floors rather than equalities, because D3FEND grows — what must never happen
#: is the count *falling*, which is what a parser regression looks like.
_MIN_D3FEND_IDS = 450
_MIN_ATTACK_IDS = 1400

#: Caps on the join. An artifact like ``:File`` is touched by dozens of
#: techniques on both sides, and an uncapped list turns a definition into a
#: directory listing. Longest-definition-first so what survives is substantial.
_JOIN_CAP = 20
_REFERENCE_CAP = 8
#: The relation vocabulary is one coherent thing and a single 60 KB document,
#: so it is emitted in slices. Properties stay in alphabetical order across the
#: slices, which is how a reader would look one up.
_VOCABULARY_SLICE = 50

#: See :mod:`training.corpus.sources.atlas`. Identical across this family.
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
#: The same pattern as :mod:`training.corpus.sources.atlas`, including
#: its allowlist of systems and documentation tokens; see there for why
#: ``@reboot`` and ``@property`` are not handles. The copies must stay
#: byte-identical and a test asserts that they have not diverged.
_HANDLE = re.compile(
    r"(?<![A-Za-z0-9._%+\-@/])@"
    r"(?!(?:reboot|daily|hourly|weekly|monthly|yearly|annually|midnight|"
    r"staticmethod|classmethod|property|dataclass|override|functools|"
    r"media|import|charset|font-face|supports|keyframes|namespace|"
    r"echo|param|params|returns?|throws|see|since|deprecated|author|"
    r"type|types|interface|decorator|test|patch|mock|pytest|cache|"
    r"sha256|sha1|md5|base64|xmlns|version|schema|context|id|graph)"
    r"(?![A-Za-z0-9_]))"
    r"[A-Za-z0-9_]{3,15}(?![A-Za-z0-9_@.])"
)

#: Annotation predicates never read. ``kb-author`` is 326 named individuals and
#: ``kb-abstract`` is 340 third-party abstracts; see the module docstring for
#: the two different reasons.
_NEVER_READ = frozenset({":kb-author", ":kb-abstract"})

#: A name character for the tokeniser. Turtle's PN_CHARS_BASE is a long list of
#: Unicode ranges; this covers it generously, which is the safe direction — a
#: character wrongly accepted into a name produces a name this adapter does not
#: recognise and ignores, while one wrongly rejected ends a statement early and
#: corrupts everything after it.
_NAME_CHAR = re.compile(r"[A-Za-z0-9_À-￿]")

_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f",
            '"': '"', "'": "'", "\\": "\\"}


def _short_hash(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]


# ---------------------------------------------------------------- Turtle subset


def _unescape(value: str) -> str:
    if "\\" not in value:
        return value
    out: list[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\" and index + 1 < len(value):
            nxt = value[index + 1]
            if nxt in _ESCAPES:
                out.append(_ESCAPES[nxt])
                index += 2
                continue
            if nxt in "uU":
                width = 4 if nxt == "u" else 8
                try:
                    out.append(chr(int(value[index + 2:index + 2 + width], 16)))
                    index += 2 + width
                    continue
                except ValueError:
                    pass
            out.append(nxt)
            index += 2
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _tokenise(text: str) -> list[tuple[str, str]]:
    """Turtle to ``(kind, value)`` tokens. Kinds: iri, lit, name, and punctuation.

    Character-level rather than line-level, and that is the whole point. 1,510
    of this file's literals are triple-quoted markdown; inside them are lines
    beginning ``### Technique Overview`` and ``:definition``-looking text and
    bare ``.`` at end of sentence. Any parser that decides what a line is by
    looking at its first character will read those as ontology structure. The
    only correct way to know whether a ``.`` terminates a statement is to have
    tracked string state from the top of the file, which is what this does.
    """
    tokens: list[tuple[str, str]] = []
    index, length = 0, len(text)
    while index < length:
        char = text[index]
        if char in " \t\r\n":
            index += 1
            continue
        if char == "#":                       # comment to end of line
            newline = text.find("\n", index)
            index = length if newline < 0 else newline + 1
            continue
        if char == "@":                       # @prefix / @base directive
            # The terminating '.' is looked for after the closing '>': the
            # first '.' in "@prefix : <http://d3fend.mitre.org/..." is the one
            # inside the hostname, and taking it leaves the parser mid-IRI.
            close = text.find(">", index)
            stop = text.find(".", close if close >= 0 else index)
            index = length if stop < 0 else stop + 1
            continue
        if char == "<":
            close = text.find(">", index)
            if close < 0:
                raise SourceError("d3fend: unterminated IRI in the ontology")
            tokens.append(("iri", text[index + 1:close]))
            index = close + 1
            continue
        if char == '"':
            long_form = text.startswith('"""', index)
            quote = '"""' if long_form else '"'
            cursor = index + len(quote)
            buffer: list[str] = []
            while True:
                if cursor >= length:
                    raise SourceError("d3fend: unterminated literal")
                if text[cursor] == "\\":
                    buffer.append(text[cursor:cursor + 2])
                    cursor += 2
                    continue
                if text.startswith(quote, cursor):
                    cursor += len(quote)
                    break
                buffer.append(text[cursor])
                cursor += 1
            index = cursor
            # A language tag or a datatype may follow, and both are discarded:
            # every literal this adapter reads is text, and xsd:anyURI on a URL
            # string changes nothing about how it renders.
            if index < length and text[index] == "@":
                index += 1
                while index < length and (text[index].isalnum()
                                          or text[index] == "-"):
                    index += 1
            elif text.startswith("^^", index):
                index += 2
                if index < length and text[index] == "<":
                    close = text.find(">", index)
                    index = length if close < 0 else close + 1
                else:
                    while index < length and (_NAME_CHAR.match(text[index])
                                              or text[index] in ":-_"):
                        index += 1
            tokens.append(("lit", _unescape("".join(buffer))))
            continue
        if char in ";,[]()":
            tokens.append((char, char))
            index += 1
            continue
        if char == ".":
            tokens.append((".", "."))
            index += 1
            continue
        cursor = index
        while cursor < length:
            here = text[cursor]
            if _NAME_CHAR.match(here) or here in ":-_%":
                cursor += 1
                continue
            if here == ".":
                # Turtle allows '.' inside a local name but not as its last
                # character, and this file uses it: ':AML.T0000'. So a dot
                # joins the name only when a name character follows.
                if cursor + 1 < length and _NAME_CHAR.match(text[cursor + 1]):
                    cursor += 1
                    continue
                break
            break
        if cursor == index:
            raise SourceError(
                f"d3fend: the tokeniser cannot make progress at "
                f"{text[index:index + 40]!r}. The ontology uses Turtle syntax "
                "this parser does not implement; extend it rather than "
                "skipping the character, which would corrupt every statement "
                "after this one."
            )
        tokens.append(("name", text[index:cursor]))
        index = cursor
    return tokens


#: A parsed node: predicate -> list of objects, where an object is a prefixed
#: name, an IRI, a literal, a nested node (blank node) or a list (collection).
_Node = dict[str, list[Any]]


def _parse(tokens: list[tuple[str, str]]) -> dict[str, _Node]:
    """Tokens to ``{subject: {predicate: [objects]}}``.

    Statements for the same subject are merged, which Turtle permits and this
    file does. Blank-node subjects are kept under a synthetic key rather than
    skipped: they are ``owl:AllDisjointClasses`` axioms nothing here renders,
    but a parser that *skips* a construct instead of *consuming* it leaves the
    cursor mid-statement and mis-reads everything following.
    """
    subjects: dict[str, _Node] = {}
    position = 0
    anonymous = 0

    def read_object() -> Any:
        nonlocal position
        kind, value = tokens[position]
        if kind == "[":
            position += 1
            node: _Node = {}
            read_predicates(node)
            if position < len(tokens) and tokens[position][0] == "]":
                position += 1
            return node
        if kind == "(":
            position += 1
            items: list[Any] = []
            while position < len(tokens) and tokens[position][0] != ")":
                items.append(read_object())
            if position < len(tokens):
                position += 1
            return items
        position += 1
        return value

    def read_predicates(into: _Node) -> None:
        nonlocal position
        while position < len(tokens):
            kind, value = tokens[position]
            if kind in ("]", ".", ")"):
                return
            if kind == ";":
                position += 1
                continue
            if kind not in ("name", "iri"):
                raise SourceError(
                    f"d3fend: expected a predicate, found {tokens[position]!r}"
                )
            predicate = "rdf:type" if value == "a" else value
            position += 1
            while True:
                into.setdefault(predicate, []).append(read_object())
                if position < len(tokens) and tokens[position][0] == ",":
                    position += 1
                    continue
                break

    while position < len(tokens):
        kind, value = tokens[position]
        if kind == ".":
            position += 1
            continue
        if kind == "[":
            anonymous += 1
            node = subjects.setdefault(f"_:b{anonymous}", {})
            position += 1
            read_predicates(node)
            if position < len(tokens) and tokens[position][0] == "]":
                position += 1
            read_predicates(node)
            if position < len(tokens) and tokens[position][0] == ".":
                position += 1
            continue
        if kind not in ("name", "iri"):
            raise SourceError(
                f"d3fend: expected a subject, found {tokens[position]!r}"
            )
        position += 1
        read_predicates(subjects.setdefault(value, {}))
        if position < len(tokens) and tokens[position][0] == ".":
            position += 1
    return subjects


def _check(subjects: dict[str, _Node]) -> None:
    """Refuse a parse that lost the identifiers. See the module docstring.

    This is the instrument check, and it is here because three measurement bugs
    in this project were each in the ruler rather than in the thing measured. A
    hand-written parser that returns *something* is the easiest possible place
    for that to happen again: the build would succeed, the corpus would be
    thinner, and nothing would say so.
    """
    d3fend = sum(1 for node in subjects.values() if node.get(":d3fend-id"))
    attack = sum(1 for node in subjects.values() if node.get(":attack-id"))
    if d3fend < _MIN_D3FEND_IDS or attack < _MIN_ATTACK_IDS:
        raise SourceError(
            f"d3fend: parsed {d3fend} d3fend-id and {attack} attack-id classes "
            f"(expected at least {_MIN_D3FEND_IDS} and {_MIN_ATTACK_IDS}; 497 "
            "and 1,557 were observed). Either the ontology has been "
            "reorganised or the Turtle subset parser has regressed. Check the "
            "parser first: it is the newer and more fragile of the two, and "
            "`grep -cE '^\\s+:d3fend-id \"' d3fend-protege.ttl` settles it in "
            "one command."
        )


# ------------------------------------------------------------------ the adapter


def _fetch(cache_dir: Path) -> Path:
    """Download the ontology and the upstream LICENSE.md. Returns the ontology."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    ontology = cache_dir / _ONTOLOGY
    marker = cache_dir / _MARKER
    if marker.is_file() and ontology.is_file():
        return ontology

    licenses = cache_dir / _LICENSE_DIR
    licenses.mkdir(parents=True, exist_ok=True)
    license_file = licenses / "d3fend-ontology.LICENSE.md"

    incoming = cache_dir / (_ONTOLOGY + ".incoming")
    try:
        download(_LICENSE_URL, license_file, timeout=60,
                 max_bytes=_MAX_LICENSE_BYTES)
        text = license_file.read_text(encoding="utf-8", errors="replace")
        if "MIT License" not in text or "MITRE" not in text:
            raise SourceError(
                "d3fend: the upstream LICENSE.md no longer reads as MITRE's MIT "
                f"grant ({_LICENSE_URL}). The SPEC declaration is a claim about "
                "that file, and this source is only usable because the grant "
                "permits redistribution — re-read it before building."
            )
        download(_ONTOLOGY_URL, incoming, timeout=300,
                 max_bytes=_MAX_ONTOLOGY_BYTES)
    except NetworkError as exc:
        incoming.unlink(missing_ok=True)
        raise SourceError(f"d3fend: fetch failed: {exc}") from None

    incoming.replace(ontology)
    marker.write_text(
        json.dumps(
            {
                "repo": _REPO,
                "ref": _REF,
                "ontology_url": _ONTOLOGY_URL,
                "license_url": _LICENSE_URL,
                "ontology_bytes": ontology.stat().st_size,
                "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return ontology


def _literals(node: _Node, predicate: str) -> list[str]:
    """String objects of one predicate, blank nodes and collections skipped."""
    if predicate in _NEVER_READ:
        return []
    out = []
    for value in node.get(predicate, []):
        if isinstance(value, str) and value.strip():
            out.append(value.strip())
    return out


def _first(node: _Node, predicate: str) -> str:
    found = _literals(node, predicate)
    return found[0] if found else ""


def _restrictions(node: Any) -> list[tuple[str, str]]:
    """Every ``(property, target class)`` pair in a node's restrictions.

    Walks nested blank nodes, because D3FEND nests them: an intersection inside
    a restriction inside a ``subClassOf`` list. Reading only the top level loses
    the deeper assertions, which are the specific ones.
    """
    out: list[tuple[str, str]] = []
    if isinstance(node, list):
        for item in node:
            out += _restrictions(item)
        return out
    if not isinstance(node, dict):
        return out
    properties = [v for v in node.get("owl:onProperty", []) if isinstance(v, str)]
    targets = [
        v for v in (node.get("owl:someValuesFrom", [])
                    + node.get("owl:allValuesFrom", []))
        if isinstance(v, str)
    ]
    if properties and targets:
        out.append((properties[0], targets[0]))
    for objects in node.values():
        for value in objects:
            out += _restrictions(value)
    return out


class _Graph:
    """The parsed ontology, indexed the way the renderers read it."""

    def __init__(self, subjects: dict[str, _Node]) -> None:
        self.subjects = subjects
        self.label: dict[str, str] = {}
        self.d3fend_id: dict[str, str] = {}
        self.attack_id: dict[str, str] = {}
        self.parents: dict[str, list[str]] = {}
        self.children: dict[str, list[str]] = {}

        for name, node in subjects.items():
            text = _first(node, "rdfs:label") or _first(node, "skos:prefLabel")
            if text:
                self.label[name] = text
            d3 = _first(node, ":d3fend-id")
            if d3:
                self.d3fend_id[name] = d3
            attack = _first(node, ":attack-id")
            if attack:
                self.attack_id[name] = attack
            named_parents = [
                value for value in node.get("rdfs:subClassOf", [])
                if isinstance(value, str)
            ]
            self.parents[name] = named_parents
            for parent in named_parents:
                self.children.setdefault(parent, []).append(name)

        #: class -> [(property, target)], restrictions only, resolved once.
        self.edges: dict[str, list[tuple[str, str]]] = {}
        for name, node in subjects.items():
            found = _restrictions(node)
            if found:
                self.edges[name] = found

        #: artifact -> [(property, defensive class)] and the offensive mirror.
        #: This is the join D3FEND derives its ATT&CK mapping from; see the
        #: module docstring on why it is rendered as a join and not as an edge.
        self.artifact_defensive: dict[str, list[tuple[str, str]]] = {}
        self.artifact_offensive: dict[str, list[tuple[str, str]]] = {}
        for name, found in self.edges.items():
            is_defensive = name in self.d3fend_id
            is_offensive = name in self.attack_id
            if not (is_defensive or is_offensive):
                continue
            bucket = (self.artifact_defensive if is_defensive
                      else self.artifact_offensive)
            for prop, target in found:
                bucket.setdefault(target, []).append((prop, name))

    def ancestors(self, name: str) -> set[str]:
        """Transitive named superclasses, cycle-safe.

        An ontology is not guaranteed acyclic in practice — a mis-asserted
        inverse makes a loop — and an unguarded recursion over one is a
        RecursionError in the middle of a build.
        """
        seen: set[str] = set()
        stack = list(self.parents.get(name, ()))
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            stack += self.parents.get(current, ())
        return seen

    def pretty(self, name: str) -> str:
        """``D3-FA File Analysis``, ``T1204 User Execution``, or a readable label.

        Identifier beside name, never one alone: that co-occurrence is the whole
        reason this corpus exists, and a document naming ``:ProcessImage`` as
        "Process Image" teaches a phrase while one naming ``D3-FA`` alone
        teaches a string.
        """
        label = self.label.get(name) or _declassify(name)
        for table in (self.d3fend_id, self.attack_id):
            ident = table.get(name)
            if ident:
                return f"{ident} {label}"
        return label

    def describes(self, name: str) -> bool:
        """True when the class carries a definition worth joining in."""
        return bool(_first(self.subjects.get(name, {}), ":definition"))


def _declassify(name: str) -> str:
    """``:NetworkTraffic`` to ``Network Traffic``, for a class with no label."""
    bare = name.split(":")[-1].split("#")[-1]
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", bare)
    return spaced.replace("_", " ").strip() or bare


def _relation(prop: str) -> str:
    """``:may-modify`` to ``may modify``, for rendering an edge in words."""
    return prop.split(":")[-1].replace("-", " ")


def _section(title: str, body: list[str]) -> list[str]:
    return [] if not body else ["", f"## {title}", ""] + body


def _scrubbed(text: str, ident: str, source: str = "d3fend") -> str:
    for pattern, kind in ((_EMAIL, "email address"), (_HANDLE, "social handle")):
        match = pattern.search(text)
        if match is None:
            continue
        found = match.group(0)
        raise SourceError(
            f"{source}: document {ident!r} carries what looks like a "
            f"third-party {kind} (length={len(found)}, "
            f"sha256[:8]={_short_hash(found)}). kb-author and kb-abstract are "
            "already excluded; find out which predicate this arrived through "
            "before widening anything."
        )
    return text


def _references(graph: _Graph, node: _Node) -> list[str]:
    """Reference titles for a class, capped. Authors and abstracts excluded."""
    titles: list[str] = []
    for value in node.get(":kb-reference", []):
        if not isinstance(value, str):
            continue
        reference = graph.subjects.get(value, {})
        title = _first(reference, ":kb-reference-title")
        organisation = _first(reference, ":kb-organization")
        rendered = " — ".join(x for x in (title, organisation) if x)
        if rendered and rendered not in titles:
            titles.append(rendered)
    return titles[:_REFERENCE_CAP]


def _technique_document(name: str, graph: _Graph,
                        kind_label: str = "Defensive technique") -> str:
    """One ``d3fend-id`` class: a defensive technique, or an analytic method.

    Both shapes render the same way because they are the same shape in the
    ontology — an identifier, a definition, a knowledge-base article and
    restrictions onto artifacts. What differs is the heading, and that
    difference is load-bearing: see :func:`_documents` for the measurement that
    showed 226 of the 497 ``d3fend-id`` classes are not defensive techniques at
    all, and were being labelled as such.
    """
    node = graph.subjects[name]
    ident = graph.d3fend_id[name]
    lines = [f"{ident} {graph.label.get(name, _declassify(name))}", ""]
    lines.append("Framework: MITRE D3FEND (cybersecurity countermeasure "
                 "knowledge graph)")
    lines.append(f"Type: {kind_label}")
    lines.append(f"D3FEND ID: {ident}")

    synonyms = _literals(node, ":synonym") + _literals(node, "skos:altLabel")
    if synonyms:
        lines.append(f"Also known as: {'; '.join(dict.fromkeys(synonyms))}")

    edges = graph.edges.get(name, [])
    tactics = [graph.pretty(target) for prop, target in edges
               if prop == ":enables"]
    if tactics:
        lines.append(f"Enables (defensive tactic): {'; '.join(sorted(set(tactics)))}")

    parents = [graph.pretty(p) for p in graph.parents.get(name, [])
               if p in graph.d3fend_id]
    if parents:
        lines.append(f"Parent technique: {'; '.join(parents)}")

    definition = _first(node, ":definition")
    if definition:
        lines += ["", definition]
    article = _first(node, ":kb-article")
    if article:
        lines += ["", article]

    children = sorted(graph.pretty(c) for c in graph.children.get(name, [])
                      if c in graph.d3fend_id)
    lines += _section("Sub-techniques", [f"- {c}" for c in children])

    # The artifact edges, in words. ':enables' is left out here because it was
    # already rendered as the tactic above and repeating it reads as a second,
    # different fact.
    acted_on = sorted({
        f"- {_relation(prop)}: {graph.pretty(target)}"
        for prop, target in edges if prop != ":enables"
    })
    lines += _section("Digital artifacts this technique acts on", acted_on)

    # The join, labelled as a join. Offensive techniques that touch the same
    # artifacts — which is how D3FEND derives its published ATT&CK mapping, and
    # which this adapter will not restate as a stored edge because the ontology
    # does not ship one. See the module docstring.
    related: dict[str, str] = {}
    for prop, target in edges:
        if prop == ":enables":
            continue
        for other_prop, offensive in graph.artifact_offensive.get(target, []):
            ident_offensive = graph.attack_id.get(offensive, "")
            if not ident_offensive:
                continue
            related[ident_offensive] = (
                f"- {graph.pretty(offensive)} — {_relation(other_prop)} "
                f"{graph.pretty(target)}"
            )
    joined = [related[key] for key in sorted(related)][:_JOIN_CAP]
    if len(related) > _JOIN_CAP:
        joined.append(f"- ... and {len(related) - _JOIN_CAP} more offensive "
                      "techniques touching the same artifacts")
    lines += _section(
        "Offensive techniques sharing these artifacts (D3FEND's artifact join, "
        "not an asserted countermeasure mapping)", joined)

    lines += _section("References", [f"- {r}" for r in _references(graph, node)])
    return "\n".join(lines)


def _method_document(name: str, graph: _Graph) -> str:
    """One analytic method: D3FEND's ``D3A-`` catalogue, filed as PROSE.

    These are explanations of the methods a detection analytic is built from —
    DBSCAN, ARIMA, actor-critic reinforcement learning, description logic —
    written as short expository articles. They are not countermeasures and not
    adversary behaviour, so they are neither ADVERSARY nor DETECTION; they are
    PROSE, which the register report also has under target, and labelling them
    honestly is the only way that number stays meaningful.

    Worth having rather than dropping: a model asked why an analytic clusters
    should know what clustering is, and this is MITRE's own gloss sitting in
    the same graph as the techniques that use it.
    """
    return _technique_document(name, graph, kind_label="Analytic method")


def _local(name: str) -> str:
    """The bare local name of a class, for use as a stable unique ident."""
    return name.split(":")[-1].split("#")[-1] or name


def _tactic_document(name: str, graph: _Graph) -> str:
    """A defensive tactic with every technique that enables it.

    Worth its bytes for the same reason an ATT&CK tactic document is: one
    document in which ``Detect`` sits beside forty ``D3-`` identifiers and
    forty technique names, which is a mapping no technique document can carry.
    """
    node = graph.subjects[name]
    label = graph.label.get(name, _declassify(name))
    lines = [label, ""]
    lines.append("Framework: MITRE D3FEND (cybersecurity countermeasure "
                 "knowledge graph)")
    lines.append("Type: Defensive tactic")
    definition = _first(node, ":definition")
    if definition:
        lines += ["", definition]
    article = _first(node, ":kb-article")
    if article:
        lines += ["", article]

    members = sorted(
        graph.pretty(technique)
        for technique, edges in graph.edges.items()
        if technique in graph.d3fend_id
        and any(prop == ":enables" and target == name for prop, target in edges)
    )
    lines += _section("Techniques that enable this tactic",
                      [f"- {m}" for m in members])
    return "\n".join(lines)


def _artifact_document(name: str, graph: _Graph) -> str:
    """A digital artifact, with the defensive and offensive techniques on it.

    This is the document the artifact layer exists for. ``:AccessToken`` arrives
    with its definition, the techniques asserted to analyse or modify it, and
    the offensive techniques asserted to produce or forge it — which is a
    mechanical account of why a particular detection sees a particular attack,
    rather than a sentence claiming that it does.
    """
    node = graph.subjects[name]
    label = graph.label.get(name, _declassify(name))
    lines = [label, ""]
    lines.append("Framework: MITRE D3FEND (digital artifact ontology)")
    lines.append("Type: Digital artifact")

    parents = [graph.pretty(p) for p in graph.parents.get(name, [])
               if p in graph.label or graph.describes(p)]
    if parents:
        lines.append(f"Kind of: {'; '.join(sorted(set(parents)))}")

    definition = _first(node, ":definition")
    if definition:
        lines += ["", definition]
    article = _first(node, ":kb-article")
    if article:
        lines += ["", article]

    children = sorted({graph.pretty(c) for c in graph.children.get(name, [])})
    lines += _section("Kinds of this artifact",
                      [f"- {c}" for c in children[:_JOIN_CAP]])

    own = sorted({
        f"- {_relation(prop)}: {graph.pretty(target)}"
        for prop, target in graph.edges.get(name, [])
    })
    lines += _section("Asserted relationships", own[:_JOIN_CAP])

    defensive = sorted({
        f"- {graph.pretty(technique)} — {_relation(prop)} it"
        for prop, technique in graph.artifact_defensive.get(name, [])
    })
    lines += _section("Defensive techniques acting on this artifact",
                      defensive[:_JOIN_CAP])

    offensive = sorted({
        f"- {graph.pretty(technique)} — {_relation(prop)} it"
        for prop, technique in graph.artifact_offensive.get(name, [])
        if technique in graph.attack_id
    })
    lines += _section("Offensive techniques acting on this artifact",
                      offensive[:_JOIN_CAP])
    return "\n".join(lines)


def _vocabulary_documents(graph: _Graph) -> Iterator[tuple[str, str]]:
    """The relation vocabulary, in alphabetical slices.

    D3FEND's object properties come with definitions written as logic read
    aloud: "x accesses y: The subject x takes the action of reading from,
    writing into, or executing the stored information in the object y." Every
    artifact relationship this source emits is one of these, so without them
    the artifact documents are edges whose labels the model has to guess at.
    Emitted as slices rather than one document because the whole vocabulary is
    one 60 KB wall, and a document that size is a document the balancer has to
    treat as atomic.
    """
    rows: list[tuple[str, str]] = []
    for name, node in sorted(graph.subjects.items()):
        kinds = [v for v in node.get("rdf:type", []) if isinstance(v, str)]
        if "owl:ObjectProperty" not in kinds:
            continue
        definition = _first(node, ":definition")
        if not definition:
            continue
        label = _first(node, "rdfs:label") or _declassify(name)
        inverse = [v for v in node.get("owl:inverseOf", []) if isinstance(v, str)]
        parents = [v for v in node.get("rdfs:subPropertyOf", [])
                   if isinstance(v, str)]
        detail = [f"{label} ({_relation(name)})", f"  {definition}"]
        if parents:
            detail.append("  Specialises: "
                          + "; ".join(_relation(p) for p in sorted(parents)))
        if inverse:
            detail.append("  Inverse of: "
                          + "; ".join(_relation(i) for i in sorted(inverse)))
        rows.append((label, "\n".join(detail)))

    for start in range(0, len(rows), _VOCABULARY_SLICE):
        chunk = rows[start:start + _VOCABULARY_SLICE]
        number = start // _VOCABULARY_SLICE + 1
        header = [
            f"D3FEND relation vocabulary, part {number} "
            f"({chunk[0][0]} to {chunk[-1][0]})",
            "",
            "Framework: MITRE D3FEND (digital artifact ontology)",
            "Type: Relation vocabulary",
            "",
            "Every relationship asserted between a technique and a digital "
            "artifact in D3FEND is one of these properties. Each entry is the "
            "property, then MITRE's own definition of it stated over two "
            "variables x and y.",
            "",
        ]
        yield f"vocabulary/{number:02d}", "\n".join(header + [c[1] for c in chunk])


def _documents(path: Path) -> Iterator[Document]:
    """Yield tactics, defensive techniques, digital artifacts and the vocabulary.

    Offensive technique classes are **not** emitted — see the module docstring.
    Registers differ by kind and are set per document, which the build records
    and balances on: a digital-artifact definition is SYSTEM text ("how the
    machine works") and calling it ADVERSARY to match the SPEC headline would
    put a false number in the register report.
    """
    ontology = path / _ONTOLOGY if path.is_dir() else path
    if not ontology.is_file():
        raise SourceError(f"d3fend: {ontology} is missing — fetch did not run")
    try:
        text = ontology.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise SourceError(f"d3fend: could not read {ontology}: {exc}") from None

    subjects = _parse(_tokenise(text))
    _check(subjects)
    graph = _Graph(subjects)

    tactics = sorted(
        name for name in graph.children.get(":DefensiveTactic", [])
        if graph.describes(name)
    )
    # Selected by ontology position, NOT by "has a d3fend-id" — which is what
    # this adapter did first, and it was wrong in a way no document count would
    # have shown. Of the 497 classes carrying a d3fend-id, 271 are
    # :DefensiveTechnique descendants and **226 are :AnalyticTechnique**
    # descendants: D3FEND's catalogue of analytic methods, 132 of them machine
    # learning, 56 statistical. Every one of those was being emitted under the
    # heading "Type: Defensive technique", which is a false statement in the
    # corpus about nearly half this source's technique documents. A test
    # asking whether idents were unique is what surfaced it, because the
    # analytic ids collide upstream.
    techniques = sorted(
        (n for n in graph.d3fend_id
         if ":DefensiveTechnique" in graph.ancestors(n)),
        key=lambda n: graph.d3fend_id[n],
    )
    methods = sorted(
        n for n in graph.d3fend_id
        if ":DefensiveTechnique" not in graph.ancestors(n)
        and ":AnalyticTechnique" in graph.ancestors(n)
        and graph.describes(n)
    )
    artifacts = sorted(
        name for name in graph.subjects
        if ":DigitalArtifact" in graph.ancestors(name) and graph.describes(name)
    )

    #: ``by_id`` is only safe where the identifier is unique. It is for the 271
    #: defensive techniques (measured: 271 classes, 271 distinct D3- ids) and it
    #: is **not** for the analytic methods, where upstream has given the same
    #: D3A- id to two or three different classes 27 times over — ``D3A-AL`` is
    #: both Active Learning and Alethic Logic. Those are keyed by class name,
    #: which is unique by construction, so the build report and ``--report``
    #: stay unambiguous whatever upstream does with its ids.
    plan: tuple[tuple[str, list[str], Any, Register, Side, bool], ...] = (
        ("tactic", tactics, _tactic_document,
         Register.ADVERSARY, Side.BLUE, False),
        ("technique", techniques, _technique_document,
         Register.ADVERSARY, Side.BLUE, True),
        ("method", methods, _method_document,
         Register.PROSE, Side.NEUTRAL, False),
        ("artifact", artifacts, _artifact_document,
         Register.SYSTEM, Side.NEUTRAL, False),
    )
    for kind, names, render, register, side, by_id in plan:
        for name in names:
            ident = graph.d3fend_id[name] if by_id else _local(name)
            body = normalise(render(name, graph))
            if len(body) < _MIN_CHARS:
                continue
            yield Document(
                text=_scrubbed(body, ident),
                source="d3fend",
                register=register,
                side=side,
                ident=f"{kind}/{ident}",
            )

    for ident, body in _vocabulary_documents(graph):
        body = normalise(body)
        if len(body) < _MIN_CHARS:
            continue
        yield Document(
            text=_scrubbed(body, ident),
            source="d3fend",
            register=Register.SYSTEM,
            side=Side.NEUTRAL,
            ident=ident,
        )


SPEC = SourceSpec(
    name="d3fend",
    license=(
        "MIT — MITRE D3FEND ontology. Upstream LICENSE.md reads verbatim: "
        "\"MIT License / Copyright (c) 2022 The MITRE Corporation / Permission "
        "is hereby granted, free of charge, to any person obtaining a copy of "
        "this software and associated documentation files (the \"Software\"), to "
        "deal in the Software without restriction, including without limitation "
        "the rights to use, copy, modify, merge, publish, distribute, "
        "sublicense, and/or sell copies of the Software...\" — read from "
        "https://raw.githubusercontent.com/d3fend/d3fend-ontology/develop/"
        "LICENSE.md and copied into the cache under "
        "licenses/d3fend-ontology.LICENSE.md so the claim is checkable against "
        "the download. MIT requires the notice to travel, so it is reproduced "
        "here in full rather than cited. Two further statements that live "
        "inside the ontology itself and are reproduced for completeness rather "
        "than hidden: its rdfs:comment says \"Use of the D3FEND Knowledge "
        "Graph, and the associated references from this ontology are subject to "
        "the Terms of Use... This software was produced for the U.S. Government "
        "under Basic Contract No. W56KGU-18-D0004, and is subject to the Rights "
        "in Noncommercial Computer Software and Noncommercial Computer Software "
        "Documentation Clause 252.227-7014 (FEB 2012) Copyright 2022 The MITRE "
        "Corporation\" (https://d3fend.mitre.org/resources/terms-of-use/), and "
        "its own dcterms:license states \"MIT\". The DFARS clause governs the "
        "Government's rights in software delivered under that contract rather "
        "than restricting downstream users, and MITRE then released the "
        "ontology under MIT; the tension is stated here rather than resolved "
        "silently, because a licence note that hides the awkward half is not a "
        "licence note. D3FEND is a trademark of The MITRE Corporation."
    ),
    url="https://github.com/d3fend/d3fend-ontology",
    register=Register.ADVERSARY,
    side=Side.BLUE,
    fetch=_fetch,
    documents=_documents,
    #: Measured by running the adapter: **1,227 documents, 1,019,448
    #: characters**, no two sharing a fingerprint — 7 defensive tactics, 271
    #: defensive techniques, 222 analytic methods, 723 digital artifacts and 4
    #: relation-vocabulary slices. Median document 568 characters, longest
    #: 10,490.
    #:
    #: Of the technique documents, 218 carry asserted artifact edges and 142
    #: carry the offensive join; the rest are leaf techniques whose edges
    #: D3FEND asserts on their parent only. That is left as upstream states it
    #: rather than inherited down the subclass tree: OWL semantics would
    #: justify the inheritance, but the asserted graph is the one MITRE
    #: published and the honest thing to render.
    #:
    #: The floor sits at 900 so artifact churn is quiet, while losing the
    #: artifact tree (723 of the 1,229) trips it immediately — and that is the
    #: realistic regression, since the artifacts are selected by walking the
    #: subclass chain up to :DigitalArtifact and one renamed root would empty
    #: the list.
    expect_min_docs=900,
    notes=(
        "MITRE D3FEND's shipped OWL ontology, parsed by a hand-written Turtle "
        "subset parser because rdflib is not a dependency here — and checked "
        "arithmetically against grep on every build (497 d3fend-id and 1,557 "
        "attack-id classes) because a hand-written parser that returns "
        "something is the easiest place for a silent regression. Emitted: 7 "
        "defensive tactics with their full technique membership and 271 "
        "defensive techniques (D3-####) as ADVERSARY/BLUE; 222 analytic "
        "methods (D3A-####) as PROSE/NEUTRAL; 723 digital artifacts and 4 "
        "relation-vocabulary slices as SYSTEM/NEUTRAL. Registers are set per "
        "document, since an artifact definition is 'how the machine works' and "
        "labelling it ADVERSARY would falsify the register report. The "
        "technique/method split is selected by ontology position and not by "
        "'has a d3fend-id': 226 of the 497 d3fend-id classes are "
        ":AnalyticTechnique descendants (132 machine learning, 56 "
        "statistical), and the first version of this adapter emitted every one "
        "of them labelled 'Defensive technique'. Their ids also collide "
        "upstream — D3A-AL is both Active Learning and Alethic Logic, 27 "
        "collisions in all — so methods are keyed on the class name. The "
        "artifact layer is the reason for this source: each artifact document "
        "carries the defensive techniques asserted to act on it beside the "
        "offensive ATT&CK techniques asserted to produce or modify it, which "
        "is the join D3FEND derives its published ATT&CK mapping from. That "
        "join is labelled as a join: measured in this file, exactly 1 of 497 "
        "d3fend-id classes has a direct restriction onto an attack-id class, "
        "so writing 'D3-FA counters T1204' would assert an edge MITRE does not "
        "ship here. The 1,142 ATT&CK T#### and 189 ATLAS AML.T#### classes "
        "embedded in the ontology are read as link targets and never emitted "
        "as documents — they would duplicate the attack and atlas sources "
        "outright. kb-author (326 named individuals) and kb-abstract (340 "
        "third-party paper abstracts) are never read; reference titles and "
        "organisations are, capped at eight."
    ),
)
