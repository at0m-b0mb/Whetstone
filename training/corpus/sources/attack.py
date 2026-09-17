"""MITRE ATT&CK Enterprise, as STIX 2.1 — the ADVERSARY register.

This source exists to answer one specific measurement. The first domain
tokenizer lost to gpt2 by 45% on ``T1547.001 Registry Run Keys``, the single
worst sample in the ablation, because the corpus was Python, C and Markdown and
had never once contained an ATT&CK identifier. gpt2 has met them on the web; we
had not. This adapter is the direct repair.

**Why the rendering puts the technique id in three places.** A BPE learns merges
from adjacency, so an identifier that appears once per document in one syntactic
position teaches the tokenizer one context and no more. Each document here
therefore carries ``T1547.001`` beside its human name in the title, alone on a
labelled ``ATT&CK ID:`` line, and split across a URL path as
``/techniques/T1547/001``. Those are the three surface forms the identifier
actually takes in the wild — a report headline, a table cell, a hyperlink — and
the co-occurrence of id with *name* and with *description prose* is precisely
what the corpus lacked.

**ATT&CK v19 moved detection out of the technique.** Older bundles carried a
free-text ``x_mitre_detection`` field and an ``x_mitre_data_sources`` list on
each ``attack-pattern``. Both are gone. Detection now lives in
``x-mitre-detection-strategy`` objects joined to techniques by a ``detects``
relationship, each fanning out to ``x-mitre-analytic`` objects that carry the
prose, the tuning knobs, and concrete log-source strings like
``WinEventLog:Security`` channel ``EventCode=4768`` pointing at
``x-mitre-data-component`` records. Walking that graph is more work than reading
a field, but it is where the detection text and the data sources went, and the
log-source strings it recovers are a better prize than the old flat list: they
are the exact SYSTEM-register surface form the corpus is starved of, now sitting
in the same document as the technique id.

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
from pathlib import Path
from typing import Any, Iterator

from ..net import ssl_context as _shared_ssl_context
from ..source import Document, Register, Side, SourceError, SourceSpec, normalise

#: The "latest version" pointer in MITRE's official STIX distribution repo.
#: Deliberately unpinned: ATT&CK ships a couple of releases a year and a stale
#: pin would quietly train on a superseded technique set. The fetched version is
#: recorded in the sidecar metadata so a build is still reconstructible.
_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)

#: Uncompressed the bundle is ~54 MB of JSON, ~90% of which is relationship
#: objects we touch once and discard. It is cached gzipped (~7 MB) because the
#: cache is a long-lived directory shared with every other source, and gzip
#: costs one stdlib call on either side. ``gzcat file | jq`` still inspects it.
_BLOB = "enterprise-attack.json.gz"
_META = "enterprise-attack.meta.json"

#: Below this the download was truncated or we were served an error page. The
#: real artifact is tens of megabytes; 1 MB compressed is a generous floor that
#: still refuses a GitHub 404 body.
_MIN_BYTES = 1_000_000

#: The same floor applied to the *uncompressed* stream. The compressed floor
#: above cannot catch a transfer that died partway: ~11 MB of real JSON still
#: gzips to more than 1 MB, so a truncated body would be renamed into place and
#: then cached forever, failing in ``_load`` on every later run. The bundle has
#: only ever grown (v19.2 is 53.8 MB), so 20 MB is a floor no real release
#: approaches, and ``raw_bytes`` is the quantity the error message already
#: reported before this check existed to back it up.
_MIN_RAW_BYTES = 20_000_000

_UA = "whetstone-corpus/1.0 (+https://github.com/at0m-b0mb)"

#: CA bundles to fall back on, most-curated-first. macOS ships the first; the
#: second is Homebrew's.
_CA_BUNDLES = ("/etc/ssl/cert.pem", "/opt/homebrew/etc/ca-certificates/cert.pem")


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
    """Download the Enterprise bundle into ``cache_dir``, once.

    Idempotent and cheap on re-run: if a plausible blob is already cached this
    returns immediately without touching the network, because the build runs
    often and re-pulling 54 MB per build is how a fast edit loop dies.

    The download streams straight into gzip and lands on a ``.part`` file that
    is only renamed into place once the whole body has arrived. An interrupted
    fetch therefore leaves no half-written blob that the next run would mistake
    for a valid cache — the failure mode that makes "idempotent" a lie.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    blob = cache_dir / _BLOB
    if blob.is_file() and blob.stat().st_size >= _MIN_BYTES:
        return blob

    part = cache_dir / (_BLOB + ".part")
    digest = hashlib.sha256()
    raw_bytes = 0
    request = urllib.request.Request(_URL, headers={"User-Agent": _UA})
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
        raise SourceError(f"attack: could not fetch {_URL}: {exc}") from exc

    if raw_bytes < _MIN_RAW_BYTES or part.stat().st_size < _MIN_BYTES:
        part.unlink(missing_ok=True)
        raise SourceError(
            f"attack: {_URL} returned only {raw_bytes} bytes — that is an error "
            "page or a truncated transfer, not the ATT&CK bundle"
        )

    os.replace(part, blob)
    _write_meta(cache_dir, blob, raw_bytes, digest.hexdigest())
    return blob


def _write_meta(cache_dir: Path, blob: Path, raw_bytes: int, sha256: str) -> None:
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
        (cache_dir / _META).write_text(
            json.dumps(
                {
                    "url": _URL,
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
    """Read the cached bundle once.

    One ``json.load`` of the whole 54 MB rather than an incremental parse: the
    document graph is joined by reference in every direction (a technique needs
    its detection strategies, which need their analytics, which need their data
    components), so a streaming parser would only have to rebuild the same index
    in memory anyway. The bundle is opened once per build and released when
    ``_documents`` returns.
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


def _attack_ref(obj: dict[str, Any]) -> dict[str, Any]:
    """The one external reference that carries the ATT&CK identifier.

    Every ATT&CK object's ``external_references`` list mixes its own id with the
    citations quoted in its description, and only the ``mitre-attack`` entry is
    the identifier. Picking the first entry blindly is a plausible bug that would
    stamp a vendor blog's name onto the document, so it is filtered by source.
    """
    for ref in obj.get("external_references", ()):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref
    return {}


def _ident_sort_key(external_id: str) -> tuple[int, int]:
    """Order T1547 before T1547.001, and T2 before T10.

    A plain string sort puts T1010 before T1547 before T199, which makes the
    build report unreadable and shuffles document order between releases for no
    reason. Numeric-aware ordering keeps a parent adjacent to its children.
    """
    base, _, sub = external_id.lstrip("T").partition(".")
    try:
        return int(base), int(sub) if sub else -1
    except ValueError:
        return 1 << 30, -1


def _join(values: Any, sep: str = ", ") -> str:
    """Render a STIX list field, tolerating the absent and the malformed."""
    if not isinstance(values, list):
        return ""
    return sep.join(str(v).strip() for v in values if str(v).strip())


def _documents(path: Path) -> Iterator[Document]:
    """Yield one document per Enterprise technique and sub-technique.

    Deprecated techniques are dropped (there are about a dozen, their prose is a
    deprecation banner, and at least one has the banner spliced into the middle
    of a sentence by an upstream templating bug). Revoked techniques are *kept*,
    labelled with what superseded them: T1066 is a real identifier that a real
    threat report from 2019 still contains, the model will meet it, and "revoked,
    see T1027.005" is correct knowledge rather than noise. Dropping them would
    also throw away 149 valid ``T####`` strings from a corpus assembled
    specifically because it had none.
    """
    bundle = _load(path)
    objects: list[dict[str, Any]] = bundle["objects"]
    by_id = {obj["id"]: obj for obj in objects if "id" in obj}

    collection_version = next(
        (str(o.get("x_mitre_version", "")) for o in objects
         if o.get("type") == "x-mitre-collection"),
        "",
    )

    # Tactic shortname -> "TA0003 Persistence". kill_chain_phases only carries
    # the shortname, and the TA#### id is exactly the kind of identifier this
    # source exists to put next to prose, so it is joined back in.
    tactics: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") != "x-mitre-tactic":
            continue
        short = obj.get("x_mitre_shortname")
        ref = _attack_ref(obj)
        if short and ref:
            tactics[short] = f"{ref['external_id']} {obj.get('name', '')}".strip()

    detects: dict[str, list[dict[str, Any]]] = {}
    parent_of: dict[str, str] = {}
    revoked_by: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        kind = obj.get("relationship_type")
        src, dst = obj.get("source_ref", ""), obj.get("target_ref", "")
        if kind == "detects" and src.startswith("x-mitre-detection-strategy"):
            strategy = by_id.get(src)
            if strategy is not None:
                detects.setdefault(dst, []).append(strategy)
        elif kind == "subtechnique-of":
            parent_of[src] = dst
        elif kind == "revoked-by" and src.startswith("attack-pattern"):
            revoked_by[src] = dst

    techniques = []
    for obj in objects:
        if obj.get("type") != "attack-pattern" or obj.get("x_mitre_deprecated"):
            continue
        ref = _attack_ref(obj)
        if not ref:
            continue
        techniques.append((_ident_sort_key(ref["external_id"]), ref["external_id"], obj))

    for _, external_id, obj in sorted(techniques, key=lambda t: (t[0], t[1])):
        text = normalise(_render(obj, external_id, by_id, tactics, detects,
                                parent_of, revoked_by, collection_version))
        if len(text) < 200:
            continue
        yield Document(
            text=text,
            source="attack",
            register=Register.ADVERSARY,
            side=Side.RED,
            ident=external_id,
        )


def _render(
    obj: dict[str, Any],
    external_id: str,
    by_id: dict[str, Any],
    tactics: dict[str, str],
    detects: dict[str, list[dict[str, Any]]],
    parent_of: dict[str, str],
    revoked_by: dict[str, str],
    collection_version: str,
) -> str:
    """Lay one technique out as plain labelled lines.

    No indentation is used for structure — every line names its own field, which
    reads the same to a human and to the tokenizer. (An earlier version of this
    docstring justified that by saying ``normalise`` collapses runs of spaces;
    it no longer does, precisely because collapsing them destroyed netstat
    column alignment and Sigma YAML nesting elsewhere in the corpus. Flat
    labelled lines remain the right shape here regardless.)

    MITRE's ``(Citation: Foo)`` markers and
    ``[Mimikatz](https://attack.mitre.org/software/S0002)`` links are kept
    deliberately: they put S#### and G#### identifiers next to the software and
    group names they denote, inside running prose, which is the same
    co-occurrence win this source exists for.

    HTML is *not* kept. MITRE descriptions carry ``<code>`` spans and the odd
    ``<br>`` and entity, and roughly a thousand of those tags survived into the
    first build. Markup that never appears in real tool output teaches the model
    nothing and costs vocabulary slots that the domain fit exists to protect.
    """
    name = str(obj.get("name", "")).strip()
    lines: list[str] = [f"{external_id} {name}", ""]
    lines.append(f"ATT&CK ID: {external_id}")
    lines.append(f"Name: {name}")

    parent = by_id.get(parent_of.get(obj["id"], ""))
    if parent is not None:
        parent_ref = _attack_ref(parent)
        if parent_ref:
            lines.append(
                f"Sub-technique of: {parent_ref['external_id']} {parent.get('name', '')}"
            )

    phases = [tactics.get(p.get("phase_name", ""), p.get("phase_name", ""))
              for p in obj.get("kill_chain_phases", ())
              if p.get("kill_chain_name") == "mitre-attack"]
    if phases:
        lines.append(f"Tactics: {'; '.join(phases)}")

    if platforms := _join(obj.get("x_mitre_platforms")):
        lines.append(f"Platforms: {platforms}")
    if impact := _join(obj.get("x_mitre_impact_type")):
        lines.append(f"Impact type: {impact}")
    if obj.get("x_mitre_remote_support"):
        lines.append("Remote support: yes")

    if obj.get("revoked"):
        successor = by_id.get(revoked_by.get(obj["id"], ""))
        successor_ref = _attack_ref(successor) if successor is not None else {}
        if successor is not None and successor_ref:
            lines.append(
                f"Status: REVOKED - superseded by {successor_ref['external_id']} "
                f"{successor.get('name', '')}"
            )
        else:
            lines.append("Status: REVOKED")

    version = str(obj.get("x_mitre_version", "")).strip()
    suffix = f" (ATT&CK Enterprise v{collection_version})" if collection_version else ""
    if version:
        lines.append(f"Technique version: {version}{suffix}")
    ref = _attack_ref(obj)
    if url := ref.get("url"):
        lines.append(f"URL: {url}")

    description = _strip_html(str(obj.get("description", "")))
    if description:
        lines += ["", "## Description", "", description]

    detection = _render_detection(obj, by_id, detects)
    if detection:
        lines += ["", "## Detection", ""] + detection

    return "\n".join(lines)


def _render_detection(
    obj: dict[str, Any],
    by_id: dict[str, Any],
    detects: dict[str, list[dict[str, Any]]],
) -> list[str]:
    """Walk strategy -> analytic -> log source, and flatten it to labelled lines.

    Also aggregates every data component reached into one ``Data components:``
    line. That line is the nearest honest equivalent of the old
    ``x_mitre_data_sources`` field, and it is worth stating separately from the
    per-analytic detail because "what telemetry does this technique need" is a
    question asked of a technique, not of an individual analytic.
    """
    strategies = detects.get(obj["id"], ())
    if not strategies:
        return []

    lines: list[str] = []
    components: dict[str, str] = {}

    for strategy in sorted(strategies, key=lambda s: _attack_ref(s).get("external_id", "")):
        s_ref = _attack_ref(strategy)
        s_id = s_ref.get("external_id", "DET????")
        lines.append(f"Detection strategy {s_id}: {strategy.get('name', '')}")

        for analytic_ref in strategy.get("x_mitre_analytic_refs", ()):
            analytic = by_id.get(analytic_ref)
            if analytic is None or analytic.get("x_mitre_deprecated"):
                continue
            a_id = _attack_ref(analytic).get("external_id", "AN????")
            platforms = _join(analytic.get("x_mitre_platforms"))
            scope = f" ({platforms})" if platforms else ""
            body = str(analytic.get("description", "")).strip()
            if body:
                lines.append(f"Analytic {a_id}{scope}: {body}")

            sources: list[str] = []
            for log in analytic.get("x_mitre_log_source_references", ()):
                label = str(log.get("name", "")).strip()
                if not label:
                    continue
                channel = str(log.get("channel", "")).strip()
                component = by_id.get(str(log.get("x_mitre_data_component_ref", "")))
                if component is not None:
                    c_ref = _attack_ref(component)
                    if c_ref:
                        components[c_ref["external_id"]] = str(component.get("name", ""))
                sources.append(f"{label} channel {channel}" if channel else label)
            if sources:
                lines.append(f"Log sources: {'; '.join(sources)}")

            tuning = [f"{m.get('field', '')}: {m.get('description', '')}".strip(": ")
                      for m in analytic.get("x_mitre_mutable_elements", ())
                      if m.get("field")]
            if tuning:
                lines.append(f"Tuning: {' | '.join(tuning)}")

    if components:
        joined = "; ".join(f"{cid} {components[cid]}" for cid in sorted(components))
        lines.insert(0, f"Data components: {joined}")
    return lines


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
    #: Enterprise v19.2 yields 846 (697 current plus 149 revoked). The floor is
    #: set well under that so a normal release cannot trip it, but a schema
    #: change that breaks the attack-pattern filter will.
    expect_min_docs=600,
    notes=(
        "Enterprise techniques and sub-techniques, each rendered with its T#### "
        "id adjacent to its name, its description and its URL path form — the "
        "co-occurrence the first tokenizer lost 45% on. ATT&CK v19 moved "
        "detection into x-mitre-detection-strategy and x-mitre-analytic objects, "
        "so detection text and data sources are joined back in over the "
        "'detects' relationship; that also drags in concrete log-source strings "
        "(WinEventLog:Security EventCode=4768, auditd:SYSCALL) which the old "
        "flat x_mitre_data_sources list never carried."
    ),
)
