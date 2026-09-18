"""MITRE ATT&CK — Enterprise, Mobile and ICS, as STIX 2.1. The ADVERSARY register.

This source exists to answer one specific measurement. The first domain
tokenizer lost to gpt2 by 45% on ``T1547.001 Registry Run Keys``, the single
worst sample in the ablation, because the corpus was Python, C and Markdown and
had never once contained an ATT&CK identifier. gpt2 has met them on the web; we
had not. This adapter is the direct repair, and the repair worked: that sample
moved from -45% to +13% once technique ids appeared beside their human names in
running prose.

**Why the rendering puts the technique id in three places.** A BPE learns merges
from adjacency, so an identifier that appears once per document in one syntactic
position teaches the tokenizer one context and no more. Each document here
therefore carries ``T1547.001`` beside its human name in the title, alone on a
labelled ``ATT&CK ID:`` line, and split across a URL path as
``/techniques/T1547/001``. Those are the three surface forms the identifier
actually takes in the wild — a report headline, a table cell, a hyperlink — and
the co-occurrence of id with *name* and with *description prose* is precisely
what the corpus lacked. Every other identifier family in the bundle gets the
same treatment: ``TA0003``, ``M1040``, ``DS0017``, ``DC0084``, ``DET0103``,
``AN0110``, ``A0011``, and — reached through relationships — ``G0016`` and
``S0154``.

**What this source used to miss, and why that mattered.** For a long time it
fetched one bundle and emitted one object type: Enterprise ``attack-pattern``.
That is 846 documents and 2.75M characters, and measured against the whole
corpus it came to 1.8% while the benchmark probe ``attck-real`` scored 0/10.
Counting what the bundle held against what the adapter emitted said why. The
technique coverage was never the problem — 850 distinct ``T####`` ids were
already there. The problem was everything the techniques were *connected* to:

* **Two entire matrices were never downloaded.** Mobile ATT&CK (190 techniques,
  2,635 objects) and ICS ATT&CK (118 techniques, 2,173 objects) are separate
  bundles at sibling paths. Nothing in this project read them at all, so every
  ``T1398``, every ``A0011`` asset and every ``M0800``-series ICS mitigation was
  absent from the corpus outright.
* **The technique documents contained no G####, M#### or DS#### at all.** Those
  identifiers live one relationship hop away, and an adapter that only reads
  ``attack-pattern`` objects never takes the hop. A technique document that
  never names a group that used it, or a mitigation that stops it, teaches the
  id in isolation — which is the exact failure the original measurement
  diagnosed, one level up.
* **Tactics, data sources and data components were joined in as labels but never
  emitted as documents.** A tactic document is unusually valuable per byte: it
  lists every technique underneath it, so ``TA0003 Persistence`` arrives with a
  hundred ``T####`` ids beside a hundred technique names in one place.

**The relationship graph is where the volume is.** 21,262 relationship objects
carry 3.95M characters of description, and those descriptions are real procedure
sentences — "APT29 has used Cobalt Strike to ...". They are cited, concrete, and
by a wide margin the densest adversary narrative MITRE publishes.

**They are also already in the corpus, and that governs how much is taken here.**
:mod:`~training.corpus.sources.attackactors` reads the same Enterprise bundle and
emits those sentences grouped by the actor that performed them, 18,162 of the
19,925 described relationships. Re-emitting all of them grouped by technique
would put 3.5M characters into the corpus twice, and duplicated text in a small
corpus is worse than absent text because the model memorises it. So this source
takes the *reverse* index deliberately bounded: at most
:data:`_PROCEDURE_CAP` procedures per technique, longest first. The adjacency it
buys is genuinely different from the one attackactors buys — there, the sentence
sits under a group heading and names the technique; here it sits under the
technique and names the **group and its G#### id**, which is the direction that
was missing. The cap is what keeps that a supplement rather than a second copy.

**ATT&CK v19 moved detection out of the technique, in all three matrices.**
Older bundles carried a free-text ``x_mitre_detection`` field and an
``x_mitre_data_sources`` list on each ``attack-pattern``. Both are gone —
measured, not assumed: across Enterprise, Mobile and ICS, zero of 1,166
``attack-pattern`` objects still carry either. Detection now lives in
``x-mitre-detection-strategy`` objects joined to techniques by a ``detects``
relationship, each fanning out to ``x-mitre-analytic`` objects that carry the
prose, the tuning knobs, and concrete log-source strings like
``WinEventLog:Security`` channel ``EventCode=4768`` pointing at
``x-mitre-data-component`` records. Walking that graph is more work than reading
a field, but it is where the detection text and the data sources went, and the
log-source strings it recovers are a better prize than the old flat list: they
are the exact SYSTEM-register surface form the corpus is starved of, now sitting
in the same document as the technique id. Detection text is load-bearing for
this project's purple thesis — a technique described beside how it is caught is
the red/blue pairing the model is being taught — so both the modern walk and the
legacy fields are read, and whichever exists is emitted.

**Deprecated data sources are kept, labelled.** All 38 ``x-mitre-data-source``
objects are flagged deprecated: v17 replaced the DS#### concept with DC####
data components. They are emitted anyway, marked as superseded, for the same
reason revoked techniques are kept — ``DS0017 Command`` appears in a great deal
of existing detection-engineering writing that the model will meet, and
"deprecated, superseded by data components" is correct knowledge rather than
noise. Deprecated *techniques* remain dropped: their prose is a deprecation
banner, and at least one has the banner spliced into the middle of a sentence by
an upstream templating bug.

**Citations stay.** MITRE's ``(Citation: Mandiant APT29)`` markers and
``[Mimikatz](https://attack.mitre.org/software/S0002)`` links are noise by one
reading, and they are kept anyway, for two reasons. They are the only provenance
the prose carries — stripping them leaves an unattributed claim about a named
threat actor, which is precisely the kind of text a security model should not be
trained to produce. And the links put S#### and G#### identifiers next to the
software and group names they denote, inside running prose, which is the same
co-occurrence win this source exists for. They are stripped only when *judging*
whether a description has substance, because 1,096 relationship descriptions are
nothing but a citation marker and would otherwise consume the per-technique cap
ahead of real narrative.

**Everything here is ADVERSARY/RED, including the detection text.** That is a
deliberate call rather than an oversight. The unit of every document in this
source is an adversary behaviour: even a data-component document answers "what
telemetry sees this technique". The detection prose earns its place *inside*
those documents, as the pairing, not as a separate blue register — and ADVERSARY
is the corpus's scarcest register and the binding constraint on the balancer, so
a document that honestly belongs there is worth more here than anywhere else.

**Whitespace is never collapsed**, per the contract in
:func:`~training.corpus.source.normalise`. Structure is carried by flat labelled
lines rather than indentation, so nothing in this source depends on horizontal
spacing surviving — but nothing in this source damages it either.

An adapter that silently yielded techniques with an empty Detection section
after an upstream schema change is the exact failure ``expect_min_docs`` exists
to catch, so the walk is written to be loud rather than tolerant: if the
``detects`` relationship disappears, the detection sections vanish, the
character count halves, and the build report shows it.
"""

from __future__ import annotations

import gzip
import hashlib
import http.client
import html
import json
import os
import re
import ssl
import urllib.error
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from ..net import ssl_context as _shared_ssl_context
from ..source import Document, Register, Side, SourceError, SourceSpec, normalise


@dataclass(frozen=True, slots=True)
class _Domain:
    """One ATT&CK matrix, published as its own STIX bundle.

    MITRE ships three and they are not interchangeable: ICS carries assets and
    no meaningful platform list, Mobile carries a tactic *type* Enterprise does
    not have. Treating them as one bundle with a flag would lose those; treating
    them as three domains with a shared renderer keeps the differences visible
    at the point they are rendered.
    """

    key: str
    label: str
    #: Floor on the *uncompressed* stream. Per-domain because Enterprise is
    #: 54 MB and ICS is 4 MB — one shared floor would either wave a truncated
    #: Enterprise transfer through or reject a complete ICS one.
    min_raw_bytes: int
    #: The same floor applied to the cached gzip, which catches an error page.
    min_bytes: int
    #: Enterprise is the bundle this project is built on and the one
    #: :mod:`~training.corpus.sources.attackactors` reads; losing it is a build
    #: failure. The other two degrade to a smaller corpus instead.
    required: bool

    @property
    def url(self) -> str:
        return (
            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
            f"master/{self.key}-attack/{self.key}-attack.json"
        )

    @property
    def kill_chain(self) -> str:
        """The ``kill_chain_name`` this matrix stamps on its technique phases.

        Enterprise writes ``mitre-attack``; Mobile writes ``mitre-mobile-attack``
        and ICS writes ``mitre-ics-attack``. This was hardcoded to the Enterprise
        string while this source only read one bundle, and the first run across
        all three showed exactly what that costs: every Mobile and ICS technique
        came out with no ``Tactics:`` line at all, and 24 of the 39 tactic
        documents listed no techniques, because the phase filter matched nothing
        and a filter that matches nothing fails silently. The identifiers were
        in the bundle and the renderer simply never asked for them — which is
        the same class of omission that left this whole source at 1.8% of the
        corpus, reappearing one layer down.
        """
        return "mitre-attack" if self.key == "enterprise" else f"mitre-{self.key}-attack"

    @property
    def blob(self) -> str:
        return f"{self.key}-attack.json.gz"

    @property
    def meta(self) -> str:
        return f"{self.key}-attack.meta.json"


#: The "latest version" pointers in MITRE's official STIX distribution repo.
#: Deliberately unpinned: ATT&CK ships a couple of releases a year and a stale
#: pin would quietly train on a superseded technique set. The fetched version is
#: recorded in the sidecar metadata so a build is still reconstructible.
_DOMAINS: tuple[_Domain, ...] = (
    _Domain("enterprise", "Enterprise", 20_000_000, 1_000_000, True),
    _Domain("mobile", "Mobile", 3_000_000, 150_000, False),
    _Domain("ics", "ICS", 2_000_000, 100_000, False),
)

_ENTERPRISE = _DOMAINS[0]

#: Module-level aliases kept because :mod:`~training.corpus.sources.attackactors`
#: imports ``_BLOB``, ``_fetch``, ``_load`` and ``_strip_html`` from here, so that
#: there is exactly one downloader and one cache for the Enterprise bundle. That
#: contract is why :func:`_fetch` still returns the *Enterprise* blob path even
#: though it now populates three: the other adapter passes that path straight to
#: ``_load`` and must keep getting the bundle it expects.
_URL = _ENTERPRISE.url
_BLOB = _ENTERPRISE.blob
_META = _ENTERPRISE.meta
_MIN_BYTES = _ENTERPRISE.min_bytes
_MIN_RAW_BYTES = _ENTERPRISE.min_raw_bytes

_UA = "whetstone-corpus/1.0 (+https://github.com/at0m-b0mb)"

#: At most this many procedure sentences per technique, longest first. See the
#: module docstring: attackactors already emits the full set grouped by actor,
#: so the technique-side reverse index is a bounded supplement that buys the
#: id-next-to-technique adjacency without copying 3.5M characters into the
#: corpus a second time. Longest-first because a prolific technique's allowance
#: should go to its richest narratives, not to whichever relationship happened
#: to sort earlier in the bundle.
_PROCEDURE_CAP = 25


def _ssl_context() -> ssl.SSLContext:
    """Delegates to :mod:`training.corpus.net`, the one source of TLS contexts.

    This function used to carry its own CA-discovery logic. Two other adapters
    grew near-identical copies of the same code on the same afternoon, which is
    how one of them eventually drifts into disabling verification during a late
    debugging session. The shared version keeps the good parts of this one — the
    SSL_CERT_FILE override and the cert_store_stats check, which is stricter
    than testing whether a cafile path is merely configured.
    """
    return _shared_ssl_context()


def _fetch(cache_dir: Path) -> Path:
    """Download every ATT&CK matrix into ``cache_dir``. Returns the Enterprise blob.

    Idempotent and cheap on re-run: a domain whose blob is already cached is
    skipped without touching the network, because the build runs often and
    re-pulling 60 MB per build is how a fast edit loop dies.

    Only the Enterprise failure is fatal. A 404 on Mobile or ICS — MITRE moving
    a path, a release in flight — should cost the corpus those two matrices, not
    all 846 Enterprise techniques and not the actor source that reads the same
    blob. The loss is not silent: the failure prints, and the missing ~350
    documents push the count under ``expect_min_docs``, which the build reports.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    for domain in _DOMAINS:
        try:
            _fetch_domain(cache_dir, domain)
        except SourceError as exc:
            if domain.required:
                raise
            print(f"   ! attack: {domain.label} matrix unavailable, "
                  f"continuing without it: {exc}")
    return cache_dir / _ENTERPRISE.blob


def _fetch_domain(cache_dir: Path, domain: _Domain) -> Path:
    """Download one matrix bundle, once.

    The download streams straight into gzip and lands on a ``.part`` file that
    is only renamed into place once the whole body has arrived. An interrupted
    fetch therefore leaves no half-written blob that the next run would mistake
    for a valid cache — the failure mode that makes "idempotent" a lie.

    Uncompressed the Enterprise bundle is ~54 MB of JSON, ~90% of which is
    relationship objects. It is cached gzipped (~6 MB) because the cache is a
    long-lived directory shared with every other source, and gzip costs one
    stdlib call on either side. ``gzcat file | jq`` still inspects it.
    """
    blob = cache_dir / domain.blob
    if blob.is_file() and blob.stat().st_size >= domain.min_bytes:
        return blob

    part = cache_dir / (domain.blob + ".part")
    digest = hashlib.sha256()
    raw_bytes = 0
    request = urllib.request.Request(domain.url, headers={"User-Agent": _UA})
    try:
        with urllib.request.urlopen(request, timeout=180, context=_ssl_context()) as response:
            with gzip.open(part, "wb", compresslevel=6) as out:
                while chunk := response.read(1 << 20):
                    digest.update(chunk)
                    raw_bytes += len(chunk)
                    out.write(chunk)
    # http.client.HTTPException covers IncompleteRead, which a truncated body
    # raises and which is NOT an OSError — uncaught, it would leak the .part
    # file and escape as a non-SourceError.
    except (urllib.error.URLError, http.client.HTTPException, OSError, TimeoutError) as exc:
        part.unlink(missing_ok=True)
        raise SourceError(f"attack: could not fetch {domain.url}: {exc}") from exc

    # The compressed floor alone cannot catch a transfer that died partway: a
    # few megabytes of real JSON still gzips past it, so a truncated body would
    # be renamed into place and then cached forever, failing in ``_load`` on
    # every later run. Both floors are checked.
    if raw_bytes < domain.min_raw_bytes or part.stat().st_size < domain.min_bytes:
        part.unlink(missing_ok=True)
        raise SourceError(
            f"attack: {domain.url} returned only {raw_bytes} bytes — that is an "
            "error page or a truncated transfer, not the ATT&CK bundle"
        )

    os.replace(part, blob)
    _write_meta(cache_dir, blob, domain, raw_bytes, digest.hexdigest())
    return blob


def _write_meta(cache_dir: Path, blob: Path, domain: _Domain,
                raw_bytes: int, sha256: str) -> None:
    """Record what was fetched, so the licence and version claims stay checkable.

    Best-effort by design: a corpus build must not fail because a sidecar note
    could not be written.
    """
    version = ""
    try:
        bundle = _load(blob)
        for obj in bundle.get("objects", ()):
            if obj.get("type") == "x-mitre-collection":
                version = str(obj.get("x_mitre_version", ""))
                break
        (cache_dir / domain.meta).write_text(
            json.dumps(
                {
                    "url": domain.url,
                    "matrix": domain.label,
                    "attack_version": version,
                    "raw_bytes": raw_bytes,
                    "sha256_uncompressed": sha256,
                    "copyright": (
                        "(c) 2026 The MITRE Corporation. This work is reproduced "
                        "and distributed with the permission of The MITRE "
                        "Corporation."
                    ),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    except (OSError, SourceError, ValueError):
        return


def _load(blob: Path) -> dict[str, Any]:
    """Read one cached bundle.

    One ``json.load`` of the whole file rather than an incremental parse: the
    document graph is joined by reference in every direction (a technique needs
    its detection strategies, which need their analytics, which need their data
    components, and separately its groups, its mitigations and its assets), so a
    streaming parser would only have to rebuild the same index in memory anyway.
    Each bundle is opened once per build and released when its documents are
    exhausted.
    """
    opener = gzip.open if blob.suffix == ".gz" else open
    try:
        with opener(blob, "rt", encoding="utf-8") as handle:  # type: ignore[operator]
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        raise SourceError(f"attack: cached bundle at {blob} is unreadable: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("objects"), list):
        raise SourceError(f"attack: {blob} is not a STIX bundle")
    return data


#: Inline HTML that shows up in MITRE descriptions. Only tags and entities are
#: targeted — markdown links stay, because they carry S####/G#### identifiers
#: next to the names they denote and that co-occurrence is the point of this
#: source.
_HTML_TAG = re.compile(r"</?(?:code|br|b|i|em|strong|p|span|ul|li|ol)\s*/?>",
                       re.IGNORECASE)

#: MITRE's inline source markers. Used only to *judge* whether a description has
#: substance — see the module docstring; the markers stay in the emitted text.
_CITATION = re.compile(r"\(Citation:[^)]*\)")

#: An ATT&CK external id: an alphabetic family prefix, a number, and optionally
#: a sub-number. Covers T1547.001, TA0003, M1040, DS0017, DC0084, DET0103,
#: AN0110, G0016, S0154, C0015 and A0011 with one pattern.
_IDENT = re.compile(r"^([A-Za-z]+)(\d+)(?:\.(\d+))?$")


def _strip_html(text: str) -> str:
    """Remove inline HTML tags and unescape entities from MITRE prose.

    About a thousand ``<code>`` spans survived into the first build of this
    source. They are markup that never occurs in the command output or log text
    the model will actually read, so they teach it a pattern with no referent
    while consuming vocabulary slots the domain tokenizer exists to conserve.
    """
    text = _HTML_TAG.sub("", text)
    if "&" in text:
        text = html.unescape(text)
    return text.strip()


def _attack_ref(obj: dict[str, Any] | None) -> dict[str, Any]:
    """The one external reference that carries the ATT&CK identifier.

    Every ATT&CK object's ``external_references`` list mixes its own id with the
    citations quoted in its description, and only the ``mitre-attack`` entry is
    the identifier. Picking the first entry blindly is a plausible bug that would
    stamp a vendor blog's name onto the document, so it is filtered by source.
    """
    if not obj:
        return {}
    for ref in obj.get("external_references", ()) or ():
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref
    return {}


def _ident_sort_key(external_id: str) -> tuple[int, int]:
    """Order T1547 before T1547.001, and T2 before T10.

    A plain string sort puts T1010 before T1547 before T199, which makes the
    build report unreadable and shuffles document order between releases for no
    reason. Numeric-aware ordering keeps a parent adjacent to its children.

    Written against the family prefix rather than stripping a literal ``T``,
    because this now orders TA####, DS####, DC####, M####, G#### and A#### as
    well, and ``"TA0003".lstrip("T")`` silently yields ``"A0003"`` — a parse
    failure that sorts every tactic into the same bucket.
    """
    match = _IDENT.match(external_id.strip())
    if not match:
        return 1 << 30, -1
    return int(match.group(2)), int(match.group(3)) if match.group(3) else -1


def _join(values: Any, sep: str = ", ") -> str:
    """Render a STIX list field, tolerating the absent and the malformed.

    ICS techniques store their (empty) platform list as the literal string
    ``"None"`` rather than an empty list, so a naive join writes
    ``Platforms: None`` into a few dozen documents. That is a fact about the
    bundle's encoding, not about the technique, and it is dropped here.
    """
    if not isinstance(values, list):
        return ""
    return sep.join(str(v).strip() for v in values
                    if str(v).strip() and str(v).strip() != "None")


def _label(obj: dict[str, Any] | None) -> str:
    """``"G0016 APT29"`` — an id welded to the name it denotes, or "" if unnamed.

    This is the atom the whole source is built out of. Nothing anywhere emits a
    bare identifier and nothing emits a bare name; a STIX UUID never reaches the
    text at all.
    """
    if not obj:
        return ""
    ref = _attack_ref(obj)
    name = str(obj.get("name", "")).strip()
    ident = ref.get("external_id", "")
    return f"{ident} {name}".strip()


#: STIX types that describe an actor, a capability or a countermeasure, mapped
#: to the heading a rendered document uses and to the suffix a procedure line
#: gets. Techniques are absent deliberately: they are rendered by their own
#: renderer, which is far richer.
_KIND_LABEL: dict[str, str] = {
    "intrusion-set": "Threat group",
    "malware": "Malware",
    "tool": "Tool",
    "campaign": "Campaign",
    "course-of-action": "Mitigation",
    "x-mitre-asset": "Asset",
}


@dataclass(slots=True)
class _Index:
    """Every join the renderers need, resolved once per bundle.

    Built in a single pass over the objects rather than by searching the list
    per technique, which is the difference between a build step and a coffee
    break: 26,000 objects times 858 techniques is a scan nobody notices writing
    and everybody notices running.
    """

    domain: _Domain
    objects: list[dict[str, Any]]
    by_id: dict[str, dict[str, Any]]
    version: str = ""
    #: kill-chain shortname -> "TA0003 Persistence"
    tactic_label: dict[str, str] = field(default_factory=dict)
    #: kill-chain shortname -> sortable technique labels underneath it
    tactic_members: dict[str, list[tuple[tuple[int, int], str]]] = \
        field(default_factory=lambda: defaultdict(list))
    #: technique uuid -> detection strategy objects
    detects: dict[str, list[dict[str, Any]]] = \
        field(default_factory=lambda: defaultdict(list))
    parent_of: dict[str, str] = field(default_factory=dict)
    children_of: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    revoked_by: dict[str, str] = field(default_factory=dict)
    #: technique uuid -> (length, rendered procedure line)
    procedures: dict[str, list[tuple[int, str]]] = \
        field(default_factory=lambda: defaultdict(list))
    #: technique uuid -> rendered mitigation lines
    mitigations: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    #: technique uuid -> "A0011 VPN Server" labels (ICS only)
    assets: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    #: data component uuid -> technique labels its telemetry feeds
    component_detects: dict[str, set[str]] = \
        field(default_factory=lambda: defaultdict(set))


def _index(objects: list[dict[str, Any]], domain: _Domain) -> _Index:
    """Resolve the bundle's cross-references into lookup tables.

    The relationship pass is where the identifiers this source was rebuilt for
    actually come from. ``uses`` and ``mitigates`` both point *at* a technique,
    and both carry the description that makes them worth reading; resolving the
    other end back to a real object is what turns an opaque
    ``intrusion-set--899ce53f-...`` into ``G0016 APT29``.
    """
    idx = _Index(
        domain=domain,
        objects=objects,
        by_id={obj["id"]: obj for obj in objects if "id" in obj},
    )
    idx.version = next(
        (str(o.get("x_mitre_version", "")) for o in objects
         if o.get("type") == "x-mitre-collection"),
        "",
    )

    # Tactic shortname -> "TA0003 Persistence". kill_chain_phases only carries
    # the shortname, and the TA#### id is exactly the kind of identifier this
    # source exists to put next to prose, so it is joined back in.
    for obj in objects:
        if obj.get("type") != "x-mitre-tactic":
            continue
        short = obj.get("x_mitre_shortname")
        if short and _attack_ref(obj):
            idx.tactic_label[short] = _label(obj)

    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        kind = obj.get("relationship_type")
        src_id, dst_id = str(obj.get("source_ref", "")), str(obj.get("target_ref", ""))

        if kind == "detects" and src_id.startswith("x-mitre-detection-strategy"):
            strategy = idx.by_id.get(src_id)
            if strategy is not None:
                idx.detects[dst_id].append(strategy)
            continue
        if kind == "subtechnique-of":
            idx.parent_of[src_id] = dst_id
            idx.children_of[dst_id].append(src_id)
            continue
        if kind == "revoked-by" and src_id.startswith("attack-pattern"):
            idx.revoked_by[src_id] = dst_id
            continue
        if kind == "targets" and dst_id.startswith("x-mitre-asset"):
            if label := _label(idx.by_id.get(dst_id)):
                idx.assets[src_id].append(label)
            continue
        if kind not in ("uses", "mitigates"):
            continue

        # Only the technique-side reverse index is built here; the actor-side
        # grouping belongs to attackactors and duplicating it would put the
        # same 3.5M characters in the corpus twice.
        if not dst_id.startswith("attack-pattern"):
            continue
        description = str(obj.get("description", "")).strip()
        if not description:
            continue
        # Strip citation markers before judging substance. 1,096 of the 19,925
        # described relationships are nothing but "(Citation: Foo)" — a source
        # attribution with no procedure in it. Those sort first for prolific
        # techniques and would consume the cap before any real narrative got in.
        if len(_CITATION.sub("", description).strip()) < 25:
            continue

        source = idx.by_id.get(src_id)
        label = _label(source)
        if not label:
            continue
        prose = _strip_html(description)
        if kind == "mitigates":
            idx.mitigations[dst_id].append(f"- {label}: {prose}")
        else:
            kind_label = _KIND_LABEL.get(str(source.get("type", "")), "")
            suffix = f" ({kind_label})" if kind_label else ""
            idx.procedures[dst_id].append((len(prose), f"- {label}{suffix}: {prose}"))

    # Techniques per tactic, and the component -> technique telemetry map. Both
    # need the technique's own label, so they run after the id tables are up.
    for obj in objects:
        if obj.get("type") != "attack-pattern" or obj.get("x_mitre_deprecated"):
            continue
        ref = _attack_ref(obj)
        if not ref:
            continue
        label = _label(obj)
        key = _ident_sort_key(ref["external_id"])
        for phase in obj.get("kill_chain_phases", ()) or ():
            if phase.get("kill_chain_name") == domain.kill_chain:
                idx.tactic_members[str(phase.get("phase_name", ""))].append((key, label))
        for strategy in idx.detects.get(obj["id"], ()):
            for analytic_ref in strategy.get("x_mitre_analytic_refs", ()) or ():
                analytic = idx.by_id.get(analytic_ref)
                if analytic is None:
                    continue
                for log in analytic.get("x_mitre_log_source_references", ()) or ():
                    component = str(log.get("x_mitre_data_component_ref", ""))
                    if component:
                        idx.component_detects[component].add(label)
    return idx


def _documents(path: Path) -> Iterator[Document]:
    """Yield every matrix's techniques, tactics, telemetry and matrix-local actors.

    ``path`` is the Enterprise blob :func:`_fetch` returns; its parent is the
    cache directory holding all three. A missing Enterprise bundle is fatal, a
    missing Mobile or ICS bundle costs those documents and trips
    ``expect_min_docs``.

    Enterprise threat groups, software, campaigns and mitigations are **not**
    emitted here: :mod:`~training.corpus.sources.attackactors` owns those and
    reads the same cached blob. Mobile and ICS entities are emitted, but only
    when their identifier does not already appear in the Enterprise bundle —
    APT28 carries G0007 in all three matrices with the same description, and
    that description belongs in the corpus once. What is left after that filter
    is genuinely matrix-local: the ICS asset catalogue, the ICS M0800-series
    mitigations, and ~120 mobile malware families no other adapter sees.
    """
    cache_dir = path.parent
    enterprise_ids: set[str] = set()

    for domain in _DOMAINS:
        blob = cache_dir / domain.blob
        if not blob.is_file():
            if domain.required:
                raise SourceError(
                    f"attack: {blob} is missing — fetch did not populate the "
                    f"{domain.label} bundle"
                )
            continue

        idx = _index(_load(blob)["objects"], domain)
        if domain is _ENTERPRISE:
            enterprise_ids = {
                _attack_ref(o).get("external_id", "")
                for o in idx.objects if o.get("type") in _KIND_LABEL
            }
            enterprise_ids.discard("")

        yield from _emit(idx, enterprise_ids)


def _emit(idx: _Index, enterprise_ids: set[str]) -> Iterator[Document]:
    """Render one indexed bundle into documents, in a stable order."""
    domain = idx.domain
    suffix = "" if domain is _ENTERPRISE else f"@{domain.key}"

    def _doc(external_id: str, text: str) -> Document | None:
        text = normalise(text)
        # Below this a "document" is a title and a couple of labelled lines with
        # no prose behind them — the id is present but nothing co-occurs with
        # it, which is the one thing this source is for.
        if len(text) < 200:
            return None
        return Document(text=text, source="attack", register=Register.ADVERSARY,
                        side=Side.RED, ident=f"{external_id}{suffix}")

    def _ordered(stix_type: str) -> list[tuple[str, dict[str, Any]]]:
        rows = []
        for obj in idx.objects:
            if obj.get("type") != stix_type:
                continue
            ref = _attack_ref(obj)
            if ref:
                rows.append((ref["external_id"], obj))
        return sorted(rows, key=lambda r: (_ident_sort_key(r[0]), r[0]))

    # Techniques. Deprecated ones are dropped; revoked ones are kept and
    # labelled with what superseded them. T1066 is a real identifier that a real
    # threat report from 2019 still contains, the model will meet it, and
    # "revoked, see T1027.005" is correct knowledge rather than noise. Dropping
    # them would also throw away 149 valid T#### strings from a corpus assembled
    # specifically because it had none.
    for external_id, obj in _ordered("attack-pattern"):
        if obj.get("x_mitre_deprecated"):
            continue
        if doc := _doc(external_id, _render_technique(obj, external_id, idx)):
            yield doc

    for external_id, obj in _ordered("x-mitre-tactic"):
        if obj.get("x_mitre_deprecated"):
            continue
        if doc := _doc(external_id, _render_tactic(obj, external_id, idx)):
            yield doc

    for external_id, obj in _ordered("x-mitre-data-component"):
        if doc := _doc(external_id, _render_data_component(obj, external_id, idx)):
            yield doc

    for external_id, obj in _ordered("x-mitre-data-source"):
        if doc := _doc(external_id, _render_data_source(obj, external_id, idx)):
            yield doc

    if domain is _ENTERPRISE:
        return
    for stix_type in _KIND_LABEL:
        for external_id, obj in _ordered(stix_type):
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            if external_id in enterprise_ids:
                continue
            if doc := _doc(external_id, _render_entity(obj, external_id, idx)):
                yield doc


def _header(external_id: str, name: str, kind: str, idx: _Index,
            obj: dict[str, Any]) -> list[str]:
    """The first block every document shares: id, matrix, name, URL.

    Two of the three surface forms the module docstring argues for live here —
    the id welded to the name in the title line, and the id alone on a labelled
    line. The third is the URL, whose path splits ``T1547.001`` into
    ``/techniques/T1547/001`` and teaches the tokenizer the dotted id in a
    position where the dot is a separator rather than a suffix.
    """
    lines = [f"{external_id} {name}", "",
             f"ATT&CK ID: {external_id}",
             f"Matrix: {idx.domain.label} ATT&CK",
             f"Type: {kind}",
             f"Name: {name}"]
    if url := _attack_ref(obj).get("url"):
        lines.append(f"URL: {url}")
    return lines


def _render_technique(obj: dict[str, Any], external_id: str, idx: _Index) -> str:
    """Lay one technique out as plain labelled lines.

    No indentation is used for structure — every line names its own field, which
    reads the same to a human and to the tokenizer. (An earlier version of this
    docstring justified that by saying ``normalise`` collapses runs of spaces;
    it no longer does, precisely because collapsing them destroyed netstat
    column alignment and Sigma YAML nesting elsewhere in the corpus. Flat
    labelled lines remain the right shape here regardless.)

    The document is assembled so that a single technique carries as many
    *distinct* identifier families as the bundle can justify: its own T####, its
    parent's and children's, the TA#### of every tactic it serves, the M#### of
    every mitigation that stops it, the G####/S####/C#### of everyone observed
    using it, and — through the detection walk — DET####, AN#### and DC####.
    That density is the whole argument: an id learned beside one other id is a
    string, an id learned beside six kinds of related id is a referent.
    """
    name = str(obj.get("name", "")).strip()
    lines = _header(external_id, name, "Technique", idx, obj)

    parent = idx.by_id.get(idx.parent_of.get(obj["id"], ""))
    if parent_label := _label(parent):
        lines.append(f"Sub-technique of: {parent_label}")

    children = sorted(
        (label for cid in idx.children_of.get(obj["id"], ())
         if (label := _label(idx.by_id.get(cid)))),
        key=lambda s: _ident_sort_key(s.split(" ", 1)[0]),
    )
    if children:
        lines.append(f"Sub-techniques: {'; '.join(children)}")

    phases = [idx.tactic_label.get(p.get("phase_name", ""), p.get("phase_name", ""))
              for p in obj.get("kill_chain_phases", ()) or ()
              if p.get("kill_chain_name") == idx.domain.kill_chain]
    if phases:
        lines.append(f"Tactics: {'; '.join(phases)}")

    if platforms := _join(obj.get("x_mitre_platforms")):
        lines.append(f"Platforms: {platforms}")
    if tactic_type := _join(obj.get("x_mitre_tactic_type")):
        lines.append(f"Tactic type: {tactic_type}")
    if impact := _join(obj.get("x_mitre_impact_type")):
        lines.append(f"Impact type: {impact}")
    if permissions := _join(obj.get("x_mitre_permissions_required")):
        lines.append(f"Permissions required: {permissions}")
    if defences := _join(obj.get("x_mitre_defense_bypassed")):
        lines.append(f"Defences bypassed: {defences}")
    if obj.get("x_mitre_remote_support"):
        lines.append("Remote support: yes")
    if assets := idx.assets.get(obj["id"]):
        lines.append(f"Targeted assets: {'; '.join(sorted(set(assets)))}")

    if obj.get("revoked"):
        successor = _label(idx.by_id.get(idx.revoked_by.get(obj["id"], "")))
        lines.append(f"Status: REVOKED - superseded by {successor}" if successor
                     else "Status: REVOKED")

    version = str(obj.get("x_mitre_version", "")).strip()
    if version:
        tail = f" (ATT&CK {idx.domain.label} v{idx.version})" if idx.version else ""
        lines.append(f"Technique version: {version}{tail}")

    if description := _strip_html(str(obj.get("description", ""))):
        lines += ["", "## Description", "", description]

    if detection := _render_detection(obj, idx):
        lines += ["", "## Detection", ""] + detection

    if mitigations := sorted(idx.mitigations.get(obj["id"], ())):
        lines += ["", "## Mitigations", ""] + mitigations

    procedures = idx.procedures.get(obj["id"], ())
    if procedures:
        best = [line for _n, line in sorted(procedures, key=lambda t: -t[0])][:_PROCEDURE_CAP]
        lines += ["", "## Procedure examples", ""] + best

    return "\n".join(lines)


def _render_detection(obj: dict[str, Any], idx: _Index) -> list[str]:
    """Walk strategy -> analytic -> log source, and flatten it to labelled lines.

    Also aggregates every data component reached into one ``Data components:``
    line. That line is the nearest honest equivalent of the old
    ``x_mitre_data_sources`` field, and it is worth stating separately from the
    per-analytic detail because "what telemetry does this technique need" is a
    question asked of a technique, not of an individual analytic.

    The legacy flat fields are read first and emitted if present. They are empty
    in every v19 bundle — measured, all three matrices, zero of 1,166 techniques
    — so this costs two dictionary lookups today. It is kept because detection
    prose is the load-bearing half of this project's purple thesis, and an
    adapter that reads only the current schema would silently drop it if MITRE
    restored the field or if this source were ever pointed at an archived
    bundle. Dropping detection text is the one failure this renderer must not
    have.
    """
    lines: list[str] = []
    if legacy := _strip_html(str(obj.get("x_mitre_detection", ""))):
        lines.append(legacy)
    if legacy_sources := _join(obj.get("x_mitre_data_sources"), "; "):
        lines.append(f"Data sources: {legacy_sources}")

    strategies = idx.detects.get(obj["id"], ())
    if not strategies and not lines:
        return []

    components: dict[str, str] = {}
    for strategy in sorted(strategies,
                           key=lambda s: _attack_ref(s).get("external_id", "")):
        s_id = _attack_ref(strategy).get("external_id", "DET????")
        lines.append(f"Detection strategy {s_id}: {strategy.get('name', '')}")

        for analytic_ref in strategy.get("x_mitre_analytic_refs", ()) or ():
            analytic = idx.by_id.get(analytic_ref)
            if analytic is None or analytic.get("x_mitre_deprecated"):
                continue
            a_id = _attack_ref(analytic).get("external_id", "AN????")
            platforms = _join(analytic.get("x_mitre_platforms"))
            scope = f" ({platforms})" if platforms else ""
            if body := str(analytic.get("description", "")).strip():
                lines.append(f"Analytic {a_id}{scope}: {body}")

            sources: list[str] = []
            for log in analytic.get("x_mitre_log_source_references", ()) or ():
                label = str(log.get("name", "")).strip()
                if not label:
                    continue
                channel = str(log.get("channel", "")).strip()
                component = idx.by_id.get(str(log.get("x_mitre_data_component_ref", "")))
                c_ref = _attack_ref(component)
                if c_ref:
                    components[c_ref["external_id"]] = str(component.get("name", ""))
                sources.append(f"{label} channel {channel}" if channel else label)
            if sources:
                lines.append(f"Log sources: {'; '.join(sources)}")

            tuning = [f"{m.get('field', '')}: {m.get('description', '')}".strip(": ")
                      for m in analytic.get("x_mitre_mutable_elements", ()) or ()
                      if m.get("field")]
            if tuning:
                lines.append(f"Tuning: {' | '.join(tuning)}")

    if components:
        joined = "; ".join(f"{cid} {components[cid]}" for cid in sorted(components))
        lines.insert(0, f"Data components: {joined}")
    return lines


def _render_tactic(obj: dict[str, Any], external_id: str, idx: _Index) -> str:
    """A tactic, followed by every technique that serves it.

    The best characters-to-identifiers ratio in the bundle. ``TA0005 Defense
    Evasion`` alone lists over 180 techniques and sub-techniques, each as
    ``T1027.005 Indicator Removal from Tools`` — id welded to name, one per
    line, in one document. Nothing else in ATT&CK puts that many distinct
    identifiers of one family in that little space, and the list is exactly the
    membership relation a model needs to answer "which techniques are
    persistence".
    """
    name = str(obj.get("name", "")).strip()
    lines = _header(external_id, name, "Tactic", idx, obj)
    short = str(obj.get("x_mitre_shortname", "")).strip()
    if short:
        lines.append(f"Shortname: {short}")

    if description := _strip_html(str(obj.get("description", ""))):
        lines += ["", "## Description", "", description]

    members = sorted(set(idx.tactic_members.get(short, ())))
    if members:
        lines += ["", f"## Techniques in {external_id} {name}", ""]
        lines += [f"- {label}" for _key, label in members]
    return "\n".join(lines)


def _render_data_component(obj: dict[str, Any], external_id: str, idx: _Index) -> str:
    """One DC#### component: what it observes, in which log, for which technique.

    This is the SYSTEM-register surface the corpus is most starved of. A single
    component document carries the component id, its prose, concrete channel
    strings like ``WinEventLog:Security`` / ``EventCode=4768`` and
    ``auditd:SYSCALL`` / ``socket/connect``, and the list of techniques whose
    detection depends on it — so a raw event id ends up adjacent to a technique
    id, which is a join no single object in the bundle states outright.
    """
    name = str(obj.get("name", "")).strip()
    lines = _header(external_id, name, "Data component", idx, obj)
    if obj.get("x_mitre_deprecated"):
        lines.append("Status: DEPRECATED")

    if description := _strip_html(str(obj.get("description", ""))):
        lines += ["", "## Description", "", description]

    logs = [f"- {n} channel {c}" if (c := str(log.get('channel', '')).strip())
            else f"- {n}"
            for log in obj.get("x_mitre_log_sources", ()) or ()
            if (n := str(log.get("name", "")).strip())]
    if logs:
        lines += ["", "## Log sources", ""] + sorted(set(logs))

    detected = sorted(idx.component_detects.get(obj["id"], ()),
                      key=lambda s: _ident_sort_key(s.split(" ", 1)[0]))
    if detected:
        lines += ["", "## Techniques detected with this data component", ""]
        lines += [f"- {label}" for label in detected]
    return "\n".join(lines)


def _render_data_source(obj: dict[str, Any], external_id: str, idx: _Index) -> str:
    """A DS#### data source, kept although upstream deprecated every one of them.

    ATT&CK v17 retired the data-source layer in favour of DC#### components, so
    all 38 of these carry ``x_mitre_deprecated``. They are emitted anyway, with
    the status stated, on the same argument that keeps revoked techniques:
    ``DS0017 Command`` is written into a great deal of existing detection
    engineering that the model will meet, and an id the model can place and
    correctly call superseded is worth more than an id it has never seen.
    Silently dropping them would trade real knowledge for tidiness.
    """
    name = str(obj.get("name", "")).strip()
    lines = _header(external_id, name, "Data source", idx, obj)
    if obj.get("x_mitre_deprecated"):
        lines.append("Status: DEPRECATED - ATT&CK v17 replaced data sources "
                     "with data components (DC####)")
    if layers := _join(obj.get("x_mitre_collection_layers"), "; "):
        lines.append(f"Collection layers: {layers}")
    if platforms := _join(obj.get("x_mitre_platforms")):
        lines.append(f"Platforms: {platforms}")

    if description := _strip_html(str(obj.get("description", ""))):
        lines += ["", "## Description", "", description]
    return "\n".join(lines)


def _render_entity(obj: dict[str, Any], external_id: str, idx: _Index) -> str:
    """A matrix-local group, malware, tool, campaign, mitigation or asset.

    Only ever called for Mobile and ICS, and only for identifiers absent from
    the Enterprise bundle — see :func:`_documents`. Procedure examples are not
    attached here: they hang off the *technique* documents in this source and
    off the *actor* documents in attackactors, and a third copy would be the
    duplication the cap exists to prevent.
    """
    name = str(obj.get("name", "")).strip()
    kind = _KIND_LABEL.get(str(obj.get("type", "")), "Entity")
    lines = _header(external_id, name, kind, idx, obj)

    aliases = [a for a in (obj.get("aliases") or obj.get("x_mitre_aliases") or ())
               if str(a).strip() and str(a).strip() != name]
    if aliases:
        lines.append(f"Also known as: {', '.join(aliases)}")
    if platforms := _join(obj.get("x_mitre_platforms")):
        lines.append(f"Platforms: {platforms}")
    if sectors := _join(obj.get("x_mitre_sectors"), "; "):
        lines.append(f"Sectors: {sectors}")
    if first := str(obj.get("first_seen", "")).strip():
        lines.append(f"First seen: {first}")

    if description := _strip_html(str(obj.get("description", ""))):
        lines += ["", "## Description", "", description]

    related = [f"- {rname}: {_strip_html(str(rel.get('description', '')))}"
               for rel in obj.get("x_mitre_related_assets", ()) or ()
               if (rname := str(rel.get("name", "")).strip())]
    if related:
        lines += ["", "## Related assets", ""] + related
    return "\n".join(lines)


SPEC = SourceSpec(
    name="attack",
    license=(
        "MITRE ATT&CK Terms of Use. MITRE grants a non-exclusive, royalty-free "
        "licence to use ATT&CK for research, development and commercial purposes, "
        "provided MITRE's copyright designation and licence are reproduced: "
        "\"(c) 2026 The MITRE Corporation. This work is reproduced and distributed "
        "with the permission of The MITRE Corporation.\" ATT&CK and MITRE ATT&CK "
        "are registered trademarks of The MITRE Corporation. Terms: "
        "https://attack.mitre.org/resources/legal-and-branding/terms-of-use/ ; "
        "bundle licence: https://github.com/mitre-attack/attack-stix-data/blob/"
        "master/LICENSE.txt"
    ),
    url="https://github.com/mitre-attack/attack-stix-data",
    register=Register.ADVERSARY,
    side=Side.RED,
    fetch=_fetch,
    documents=_documents,
    #: Enterprise v19.2 yields 846 techniques (697 current plus 149 revoked),
    #: 15 tactics, 109 data components and 38 data sources; Mobile adds 190
    #: techniques and ICS 118, plus their tactics, telemetry and matrix-local
    #: entities — 1,600-odd in total. The floor is set well under that so a
    #: normal release cannot trip it, but losing a whole matrix or breaking the
    #: attack-pattern filter will.
    expect_min_docs=1200,
    notes=(
        "All three ATT&CK matrices — Enterprise, Mobile and ICS — rendered so "
        "that every identifier family appears beside the name it denotes: "
        "techniques (T####), tactics (TA####) with their full membership lists, "
        "data components (DC####) with concrete log-source strings, deprecated "
        "data sources (DS####) labelled as superseded, and matrix-local groups, "
        "software, campaigns, mitigations (M####) and ICS assets (A####). Each "
        "technique carries its detection walk (DET####/AN####), the mitigations "
        "that stop it (M####), and up to 25 procedure examples resolved back to "
        "the group or software that performed them (G####/S####/C####) — the "
        "technique-side reverse index, capped because attackactors already "
        "emits the actor-side grouping from the same bundle. ATT&CK v19 moved "
        "detection into x-mitre-detection-strategy and x-mitre-analytic "
        "objects, so detection text and data sources are joined back in over "
        "the 'detects' relationship; that drags in log-source strings "
        "(WinEventLog:Security EventCode=4768, auditd:SYSCALL socket/connect) "
        "which the old flat x_mitre_data_sources list never carried."
    ),
)
