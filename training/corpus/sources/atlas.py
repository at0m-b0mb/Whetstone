"""MITRE ATLAS — adversary behaviour against AI systems. The ADVERSARY register.

ATLAS is ATT&CK's shape applied to machine-learning systems: tactics
(``AML.TA0002``), techniques (``AML.T0051``), mitigations (``AML.M0005``) and —
the part nothing else in this corpus has — **57 case studies whose ``procedure``
is an ordered list of (tactic, technique, what was actually done)**. That last
structure is the reason this source is worth its 452 KB. Everywhere else in the
corpus an adversary technique is described standing still; here it is described
in sequence, which is the form a planning agent has to produce.

**Why an AI-attack matrix belongs in a corpus for a security agent.** Two
reasons, and neither is novelty.

The first is register, not topic. The identifier family ``AML.T####`` is
dotted-prefixed where ATT&CK's ``T####`` is bare, so a tokenizer that has only
met the ATT&CK form has met one of the two conventions the world writes. The
original measurement that started this corpus was exactly that failure for
``T1547.001`` — an identifier the vocabulary had never seen tokenised as
punctuation accidents. ``AML.T0051.000`` is a second convention at a cost of
under half a megabyte.

The second is that 34 ATLAS techniques carry an ``ATT&CK-reference`` and 5
mitigations do, so this bundle is also a small bridge between the two
identifier spaces: a document that says ``AML.T0043`` and ``T1587`` in the same
paragraph teaches a mapping no single-framework source can.

**What is deliberately not here.** No model weights, no datasets, no attack
code. ATLAS publishes behaviour descriptions and the countermeasures for them,
which is the half of this subject that belongs in a corpus whose thesis is that
the catalogue holds the capability and the model holds the judgement.

**Relationship hops are taken, because the lesson was already paid for.** The
``attack`` adapter spent a long period emitting ``attack-pattern`` objects and
nothing else, so its technique documents named no group and no mitigation and
taught every identifier in isolation — 0 of 171 groups and 0 of 108 mitigations
reached the corpus. The repair is written into this adapter from the start:
every technique document carries the mitigations that address it **with
MITRE's own per-technique ``use`` note**, the case studies that used it with the
step text, its parent technique, its tactics, and its ATT&CK cross-reference.
Each identifier therefore arrives beside the name it denotes and beside prose
about something else that is also named.

**Third-party personal data.** Measured, not assumed: across the whole bundle
there are zero email addresses and zero ``@handle`` forms, and the ``actor`` and
``reporter`` fields name organisations ("McAfee Advanced Threat Research",
"Researchers at Brown University") rather than individuals. The scrubber in
:func:`_scrubbed` is still applied to every rendered document and still refuses,
because "upstream has none today" is a fact about today's snapshot and this
source re-fetches. See :data:`_EMAIL` for what it covers and why a refusal is
better than a silent strip.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Iterator

import yaml

from ..net import NetworkError, download
from ..source import Document, Register, Side, SourceError, SourceSpec, normalise

try:  # libyaml when the wheel has it; a 452 KB document either way
    from yaml import CSafeLoader as _Loader  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - depends on the local PyYAML build
    from yaml import SafeLoader as _Loader  # type: ignore[assignment]

_REPO = "mitre-atlas/atlas-data"
_REF = "main"
_RAW = f"https://raw.githubusercontent.com/{_REPO}/{_REF}"

#: ``dist/ATLAS.yaml`` is the distribution artifact: the per-object YAML under
#: ``atlas/`` is templated and carries ``{{...}}`` substitution markers that are
#: resolved only in this file. Taking the resolved one means no template engine
#: here and no half-rendered prose in the corpus.
_DATA_URL = f"{_RAW}/dist/ATLAS.yaml"
_LICENSE_URL = f"{_RAW}/LICENSE"

_DATA = "ATLAS.yaml"
_LICENSE_DIR = "licenses"
#: Written last: its presence means both files arrived whole.
_MARKER = ".fetched.json"

#: 452 KB observed. The ceiling is an order of magnitude over that — enough that
#: ATLAS can double, small enough that a redirect to something else is refused
#: rather than written into the cache.
_MAX_DATA_BYTES = 8 * 1024 * 1024
_MAX_LICENSE_BYTES = 256 * 1024

#: Below this a document is a title and two labelled lines with no prose behind
#: them: the identifier is present but nothing co-occurs with it, which is the
#: one thing an identifier document is for.
_MIN_CHARS = 200

#: Per-technique caps. Case studies are the long tail — ``AML.T0043`` appears in
#: a dozen of them — and an uncapped reverse index would put the same step text
#: under every technique it mentions. Longest first, so what survives the cap is
#: the substantial end of the distribution rather than whichever object happened
#: to sort first. The same reasoning capped ``attack``'s procedure examples at
#: 25 for the same reason; this corpus is a hundredth the size, so is this cap.
_CASE_CAP = 8
_MITIGATION_CAP = 12

#: An email address, deliberately loose on the local part. This is the one
#: pattern the corpus privacy audit was about: third-party personal addresses
#: reached the shipped corpus from an adapter that had never looked for them.
#:
#: A **refusal**, not a strip. A strip would mean this adapter silently changes
#: upstream prose and nobody ever learns that upstream started carrying
#: addresses; the next person to read the licence note here would be reading a
#: claim that is no longer checkable. A refusal fails the build loudly on the
#: first document that has one, which is cheap to fix and impossible to miss.
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
#: ``@handle`` as a social-media reference. Bounded at both ends so that an
#: email already caught above, a decorator and ``user@host`` paths do not
#: double-report, and so a bare ``@`` in prose is not a hit.
#: ``@handle`` as a social-media reference, with the systems and documentation
#: tokens that share its shape excluded by name.
#:
#: The allowlist is there because a test asked the pattern what it did to
#: ``the @decorator form`` and the answer was "flags it". In this family that
#: matters: the filters here DROP or REFUSE on a hit, so a false positive
#: deletes corpus content or fails a build, and ``@reboot`` in a crontab line
#: or ``@property`` in a definition is exactly the kind of text these
#: upstreams legitimately contain. A bare ``@word`` that is not on the list is
#: still flagged, which is the right default for threat-intelligence prose —
#: crediting a researcher by handle is the normal way that prose names a
#: person.
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

_OBJECT_LABEL = {
    "tactic": "Tactic",
    "technique": "Technique",
    "mitigation": "Mitigation",
    "case-study": "Case study",
}


def _fetch(cache_dir: Path) -> Path:
    """Populate the cache with ``ATLAS.yaml`` and the upstream LICENSE.

    Returns the data file. Idempotent and network-free when warm: the marker is
    written only after both downloads land, so an interrupted fetch re-fetches
    instead of yielding a corpus from half a bundle.

    The licence is copied into ``licenses/`` rather than merely cited, so the
    claim in :data:`SPEC` is checkable against the bytes that were actually
    downloaded. A licence that can only be verified by visiting a URL later is
    a licence claim about a repository, not about this cache.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    data = cache_dir / _DATA
    marker = cache_dir / _MARKER
    if marker.is_file() and data.is_file():
        return data

    licenses = cache_dir / _LICENSE_DIR
    licenses.mkdir(parents=True, exist_ok=True)
    license_file = licenses / "atlas-data.LICENSE"

    tmp = cache_dir / (_DATA + ".incoming")
    try:
        download(_DATA_URL, tmp, timeout=120, max_bytes=_MAX_DATA_BYTES)
        download(_LICENSE_URL, license_file, timeout=60,
                 max_bytes=_MAX_LICENSE_BYTES)
    except NetworkError as exc:
        tmp.unlink(missing_ok=True)
        raise SourceError(f"atlas: fetch failed: {exc}") from None

    # The licence is checked before the data is accepted, not after. A bundle in
    # the cache that this project has no licence for is the state the whole
    # convention exists to prevent, and the cheap moment to prevent it is before
    # the file is in place.
    text = license_file.read_text(encoding="utf-8", errors="replace")
    if "Apache License" not in text or "MITRE" not in text:
        tmp.unlink(missing_ok=True)
        raise SourceError(
            "atlas: the upstream LICENSE no longer reads as MITRE's Apache-2.0 "
            f"grant ({_LICENSE_URL}). The declaration in SPEC is a claim about "
            "that file; re-read it and update the declaration rather than "
            "training on a bundle whose terms have changed."
        )

    tmp.replace(data)
    marker.write_text(
        json.dumps(
            {
                "data_url": _DATA_URL,
                "license_url": _LICENSE_URL,
                "repo": _REPO,
                "ref": _REF,
                "data_bytes": data.stat().st_size,
                "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return data


def _load(path: Path) -> dict[str, Any]:
    """Parse ``ATLAS.yaml``, accepting either the file or the directory above it."""
    data = path / _DATA if path.is_dir() else path
    if not data.is_file():
        raise SourceError(f"atlas: {data} is missing — fetch did not populate it")
    try:
        parsed = yaml.load(data.read_text(encoding="utf-8"), Loader=_Loader)
    except (OSError, yaml.YAMLError) as exc:
        raise SourceError(f"atlas: could not parse {data}: {exc}") from None
    if not isinstance(parsed, dict) or "matrices" not in parsed:
        raise SourceError(
            f"atlas: {data} is not an ATLAS distribution file (no 'matrices')"
        )
    return parsed


def _scrubbed(text: str, ident: str) -> str:
    """Return ``text`` unchanged, or refuse if it carries third-party contact data.

    See :data:`_EMAIL` for why this refuses rather than strips. The check runs on
    the *rendered* document, after every field has been joined in, because the
    thing that must be true is a property of what ships — not of the fields this
    adapter happened to think of.
    """
    for pattern, kind in ((_EMAIL, "email address"), (_HANDLE, "social handle")):
        match = pattern.search(text)
        if match is None:
            continue
        found = match.group(0)
        raise SourceError(
            f"atlas: document {ident!r} carries what looks like a third-party "
            f"{kind} (kind={kind}, length={len(found)}, "
            f"sha256[:8]={_short_hash(found)}). Upstream had none when this "
            "adapter was written. Decide deliberately whether it belongs in the "
            "corpus and encode that decision here; do not widen the pattern to "
            "make the build pass."
        )
    return text


def _short_hash(value: str) -> str:
    """``sha256[:8]`` of a value that must not be printed.

    The audit that produced this convention found a verifier reporting leaks by
    quoting them, which puts the leak in the log, the terminal scrollback and
    whatever is pasted from it. Kind, length and a hash prefix are enough to
    tell two findings apart and to confirm a fix.
    """
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]


def _text(value: Any) -> str:
    """A field as prose, with YAML's trailing newlines trimmed and nothing else."""
    if value is None:
        return ""
    return str(value).strip()


def _attack_refs(obj: dict[str, Any]) -> list[str]:
    """ATT&CK cross-references, rendered as ``T#### Name``.

    ATLAS writes the reference as a mapping with ``id`` and ``name``, or as a
    list of them, and 34 techniques plus 5 mitigations carry one. Both shapes
    are handled because a single-object field that later becomes a list is the
    ordinary way an upstream grows, and an adapter that reads only one of them
    loses the cross-reference silently.
    """
    raw = obj.get("ATT&CK-reference")
    items = raw if isinstance(raw, list) else [raw] if isinstance(raw, dict) else []
    out = []
    for item in items:
        if not isinstance(item, dict):
            continue
        ident, name = _text(item.get("id")), _text(item.get("name"))
        if ident and name:
            out.append(f"{ident} {name}")
        elif ident:
            out.append(ident)
    return out


class _Index:
    """Everything one rendering pass needs, resolved once.

    Built as a class rather than threaded through as six dictionaries because
    the reverse edges are the point of this adapter and a reader should be able
    to see all of them in one place.
    """

    def __init__(self, bundle: dict[str, Any]) -> None:
        matrices = bundle.get("matrices") or []
        if not isinstance(matrices, list) or not matrices:
            raise SourceError("atlas: distribution file carries no matrices")

        self.version = _text(bundle.get("version"))
        self.tactics: list[dict[str, Any]] = []
        self.techniques: list[dict[str, Any]] = []
        self.mitigations: list[dict[str, Any]] = []
        for matrix in matrices:
            if not isinstance(matrix, dict):
                continue
            self.tactics += [o for o in matrix.get("tactics") or []
                             if isinstance(o, dict)]
            self.techniques += [o for o in matrix.get("techniques") or []
                                if isinstance(o, dict)]
            self.mitigations += [o for o in matrix.get("mitigations") or []
                                 if isinstance(o, dict)]
        self.case_studies: list[dict[str, Any]] = [
            o for o in bundle.get("case-studies") or [] if isinstance(o, dict)
        ]

        self.name: dict[str, str] = {}
        for obj in (self.tactics + self.techniques + self.mitigations
                    + self.case_studies):
            ident = _text(obj.get("id"))
            if ident:
                self.name[ident] = _text(obj.get("name"))

        #: technique id -> [(mitigation id, use note)]
        self.mitigated: dict[str, list[tuple[str, str]]] = {}
        for mitigation in self.mitigations:
            mid = _text(mitigation.get("id"))
            for entry in mitigation.get("techniques") or []:
                if not isinstance(entry, dict):
                    continue
                tid = _text(entry.get("id"))
                if tid and mid:
                    self.mitigated.setdefault(tid, []).append(
                        (mid, _text(entry.get("use")))
                    )

        #: technique id -> [(case study id, step description)]
        self.seen_in: dict[str, list[tuple[str, str]]] = {}
        #: tactic id -> [technique ids], in the order the matrix lists them
        self.tactic_members: dict[str, list[str]] = {}
        for technique in self.techniques:
            tid = _text(technique.get("id"))
            for tactic in technique.get("tactics") or []:
                key = _text(tactic)
                if key and tid:
                    self.tactic_members.setdefault(key, []).append(tid)
        for study in self.case_studies:
            cid = _text(study.get("id"))
            for step in study.get("procedure") or []:
                if not isinstance(step, dict):
                    continue
                tid = _text(step.get("technique"))
                if tid and cid:
                    self.seen_in.setdefault(tid, []).append(
                        (cid, _text(step.get("description")))
                    )

        #: technique id -> [child technique ids] over ATLAS's ``specializes``
        self.children: dict[str, list[str]] = {}
        for technique in self.techniques:
            parent = _text(technique.get("specializes"))
            tid = _text(technique.get("id"))
            if parent and tid:
                self.children.setdefault(parent, []).append(tid)

    def label(self, ident: str) -> str:
        """``AML.T0051 LLM Prompt Injection`` when the name is known, else the id.

        Never the bare name on its own: an identifier that appears without its
        referent teaches the tokenizer a string and not a mapping, and that was
        the measured failure this whole corpus was assembled to repair.
        """
        name = self.name.get(ident, "")
        return f"{ident} {name}".strip()


def _atlas_path(ident: str) -> str:
    """The ATLAS path form for an id, as a third surface form of the identifier.

    A **path, not an absolute URL**, and the distinction was checked rather than
    assumed. ``attack.py`` can emit ``https://attack.mitre.org/techniques/T1547/001``
    because that resolves; atlas.mitre.org is a client-routed single-page
    application, so every deep path — with or without a trailing slash, with or
    without a browser User-Agent — answers 404 from the server. Writing an
    absolute URL here would be inventing a fact, and an invented fact in a
    corpus is a fact the model learns.

    What *is* upstream's own convention is the relative path: 168 technique and
    19 tactic cross-references inside ATLAS's own description text are written
    ``(/techniques/AML.T0005)`` and ``(/tactics/AML.TA0002)``. That is the form
    emitted, for exactly the two kinds upstream writes it for. Mitigations and
    case studies get no path line, because nothing upstream says what theirs
    would be.
    """
    kind = ident.split(".")[1][:2] if "." in ident else ""
    segment = {"TA": "tactics", "T0": "techniques"}.get(kind)
    if segment is None:
        return ""
    return f"/{segment}/{ident}"


def _header(obj: dict[str, Any], idx: _Index) -> list[str]:
    """Title, id and URL — the three syntactic positions an identifier takes."""
    ident = _text(obj.get("id"))
    kind = _OBJECT_LABEL.get(_text(obj.get("object-type")), "Object")
    lines = [f"{ident} {_text(obj.get('name'))}".strip(), ""]
    lines.append("Matrix: MITRE ATLAS (adversarial threat landscape for AI systems)")
    lines.append(f"Type: {kind}")
    lines.append(f"ATLAS ID: {ident}")
    path = _atlas_path(ident)
    if path:
        lines.append(f"ATLAS path: {path}")
    return lines


def _section(title: str, body: list[str]) -> list[str]:
    return [] if not body else ["", f"## {title}", ""] + body


def _technique_document(obj: dict[str, Any], idx: _Index) -> str:
    lines = _header(obj, idx)

    tactics = [idx.label(_text(t)) for t in obj.get("tactics") or [] if _text(t)]
    if tactics:
        lines.append(f"Tactics: {'; '.join(tactics)}")
    parent = _text(obj.get("specializes"))
    if parent:
        lines.append(f"Specialises: {idx.label(parent)}")
    refs = _attack_refs(obj)
    if refs:
        lines.append(f"ATT&CK reference: {'; '.join(refs)}")
    maturity = _text(obj.get("maturity"))
    if maturity:
        lines.append(f"Maturity: {maturity}")

    description = _text(obj.get("description"))
    if description:
        lines += ["", description]

    ident = _text(obj.get("id"))
    children = [idx.label(c) for c in idx.children.get(ident, [])]
    lines += _section("Sub-techniques", [f"- {c}" for c in children])

    # Longest note first: the cap below keeps the substantial end of the
    # distribution rather than whichever mitigation sorts first by id.
    mitigations = sorted(idx.mitigated.get(ident, []),
                         key=lambda pair: (-len(pair[1]), pair[0]))
    body = []
    for mid, use in mitigations[:_MITIGATION_CAP]:
        body.append(f"- {idx.label(mid)}")
        if use:
            body.append(f"  {use}")
    if len(mitigations) > _MITIGATION_CAP:
        body.append(f"- ... and {len(mitigations) - _MITIGATION_CAP} more")
    lines += _section("Mitigations", body)

    studies = sorted(idx.seen_in.get(ident, []),
                     key=lambda pair: (-len(pair[1]), pair[0]))
    body = []
    for cid, step in studies[:_CASE_CAP]:
        body.append(f"- {idx.label(cid)}")
        if step:
            body.append(f"  {step}")
    if len(studies) > _CASE_CAP:
        body.append(f"- ... and {len(studies) - _CASE_CAP} more case studies")
    lines += _section("Observed in case studies", body)

    return "\n".join(lines)


def _tactic_document(obj: dict[str, Any], idx: _Index) -> str:
    """A tactic with its full technique membership.

    Unusually valuable per byte, and the reason is the same one that made
    ``attack``'s tactic documents worth emitting: ``AML.TA0002 Reconnaissance``
    arrives with every technique id underneath it beside every technique name,
    in one place, which is a mapping no technique document can express.
    """
    lines = _header(obj, idx)
    refs = _attack_refs(obj)
    if refs:
        lines.append(f"ATT&CK reference: {'; '.join(refs)}")
    description = _text(obj.get("description"))
    if description:
        lines += ["", description]
    members = idx.tactic_members.get(_text(obj.get("id")), [])
    lines += _section("Techniques in this tactic",
                      [f"- {idx.label(t)}" for t in members])
    return "\n".join(lines)


def _mitigation_document(obj: dict[str, Any], idx: _Index) -> str:
    lines = _header(obj, idx)
    for field, label in (("category", "Category"),
                         ("ml-lifecycle", "AI lifecycle stage")):
        value = obj.get(field)
        if isinstance(value, list):
            rendered = "; ".join(_text(v) for v in value if _text(v))
        else:
            rendered = _text(value)
        if rendered:
            lines.append(f"{label}: {rendered}")
    refs = _attack_refs(obj)
    if refs:
        lines.append(f"ATT&CK reference: {'; '.join(refs)}")
    description = _text(obj.get("description"))
    if description:
        lines += ["", description]

    body = []
    for entry in obj.get("techniques") or []:
        if not isinstance(entry, dict):
            continue
        tid = _text(entry.get("id"))
        if not tid:
            continue
        body.append(f"- {idx.label(tid)}")
        use = _text(entry.get("use"))
        if use:
            body.append(f"  {use}")
    lines += _section("Techniques addressed", body)
    return "\n".join(lines)


def _case_study_document(obj: dict[str, Any], idx: _Index) -> str:
    """A real incident as an ordered technique chain.

    The numbered steps are the whole point and the ordering is load-bearing: a
    procedure is a sequence, and the thing a planning agent has to learn is
    which technique follows which. Rendering the steps as an unordered list — or
    worse, grouping them by tactic, which reads tidier — would destroy exactly
    the signal this document carries.

    ``actor``, ``target`` and ``reporter`` are organisations upstream and are
    kept as written. :func:`_scrubbed` is what enforces that they stay that way.
    """
    lines = _header(obj, idx)
    for field, label in (("incident-date", "Incident date"),
                         ("case-study-type", "Case study type"),
                         ("actor", "Actor"),
                         ("target", "Target"),
                         ("reporter", "Reporter")):
        value = _text(obj.get(field))
        if value:
            lines.append(f"{label}: {value}")

    summary = _text(obj.get("summary"))
    if summary:
        lines += ["", summary]

    body = []
    for number, step in enumerate(obj.get("procedure") or [], start=1):
        if not isinstance(step, dict):
            continue
        tactic = _text(step.get("tactic"))
        technique = _text(step.get("technique"))
        heading = " / ".join(x for x in (idx.label(tactic) if tactic else "",
                                        idx.label(technique) if technique else "")
                             if x)
        body.append(f"{number}. {heading}")
        description = _text(step.get("description"))
        if description:
            for paragraph in description.split("\n"):
                body.append(f"   {paragraph}" if paragraph.strip() else "")
        body.append("")
    lines += _section("Procedure", body)

    references = [
        _text(r.get("title") or r.get("url"))
        for r in obj.get("references") or []
        if isinstance(r, dict)
    ]
    lines += _section("References", [f"- {r}" for r in references if r])
    return "\n".join(lines)


def _documents(path: Path) -> Iterator[Document]:
    """Yield tactics, techniques, mitigations and case studies, in a stable order.

    Order is id-sorted within kind and kinds are emitted in a fixed sequence, so
    two runs over the same cache produce byte-identical output. The build dedups
    on a whitespace-insensitive fingerprint, and a source whose ordering drifts
    between runs makes "did my change alter the corpus" unanswerable.
    """
    idx = _Index(_load(path))

    renderers = (
        ("tactic", idx.tactics, _tactic_document, Side.RED),
        ("technique", idx.techniques, _technique_document, Side.RED),
        # The one BLUE kind in the bundle, and marked as such because the
        # shipped JSONL records per-document side: a corpus that calls a
        # countermeasure catalogue "red" cannot report its own offence/defence
        # balance honestly.
        ("mitigation", idx.mitigations, _mitigation_document, Side.BLUE),
        ("case-study", idx.case_studies, _case_study_document, Side.RED),
    )

    for kind, objects, render, side in renderers:
        for obj in sorted(objects, key=lambda o: _text(o.get("id"))):
            ident = _text(obj.get("id"))
            if not ident:
                continue
            text = normalise(render(obj, idx))
            if len(text) < _MIN_CHARS:
                continue
            yield Document(
                text=_scrubbed(text, ident),
                source="atlas",
                register=Register.ADVERSARY,
                side=side,
                ident=f"{kind}/{ident}",
            )


SPEC = SourceSpec(
    name="atlas",
    license=(
        "Apache-2.0 — MITRE ATLAS (atlas-data). Upstream LICENSE reads verbatim: "
        "\"Copyright 2021-2026 MITRE / Licensed under the Apache License, "
        "Version 2.0 (the \"License\"); you may not use this file except in "
        "compliance with the License. You may obtain a copy of the License at "
        "http://www.apache.org/licenses/LICENSE-2.0\". Read from "
        "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/LICENSE "
        "and copied into the cache under licenses/atlas-data.LICENSE so the "
        "claim is checkable against the download. ATLAS is a trademark of The "
        "MITRE Corporation."
    ),
    url="https://github.com/mitre-atlas/atlas-data",
    register=Register.ADVERSARY,
    side=Side.RED,
    fetch=_fetch,
    documents=_documents,
    #: Observed on the v6 distribution: 16 tactics, 170 techniques, 35
    #: mitigations and 57 case studies = 278, of which a handful of
    #: cross-referenced tactics fall under the character floor. The floor sits
    #: well below that so ordinary growth and retirement are quiet, and high
    #: enough that losing a whole object kind — the realistic regression, since
    #: case studies live at the top level of the file and the rest live inside
    #: ``matrices`` — trips it immediately.
    expect_min_docs=220,
    notes=(
        "MITRE ATLAS as ADVERSARY/RED, with mitigations marked BLUE per "
        "document. One document per tactic (AML.TA####, carrying its full "
        "technique membership), technique (AML.T####, carrying its tactics, "
        "parent, sub-techniques, ATT&CK cross-reference, the mitigations that "
        "address it with MITRE's per-technique 'use' note, and the case studies "
        "it appears in), mitigation (AML.M####) and case study (AML.CS####). "
        "The case studies are the reason to have this source: their 'procedure' "
        "is an ordered (tactic, technique, what was done) chain, which is the "
        "only place in the corpus an intrusion is described as a sequence "
        "rather than as a standing description. Steps keep their numbering. "
        "Caps of 12 mitigations and 8 case studies per technique, longest note "
        "first, keep the reverse index a supplement rather than a second copy. "
        "dist/ATLAS.yaml is taken rather than the per-object YAML under atlas/, "
        "which carries unresolved {{...}} template markers. Every rendered "
        "document is checked for email addresses and @handles and the build "
        "refuses on a hit rather than stripping it silently."
    ),
)
