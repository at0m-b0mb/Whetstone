"""ATT&CK threat actors, software, campaigns and mitigations — ADVERSARY register.

Free volume in a file already on disk. ``attack.py`` downloads the Enterprise
STIX bundle and emits only its 858 ``attack-pattern`` objects. The same bundle
also carries 191 intrusion sets, 733 malware families, 95 tools, 56 campaigns,
268 mitigations — and, by far the richest of them, **21,262 relationship objects
whose descriptions are the procedure examples**: "[APT29](.../groups/G0016) has
used [Cobalt Strike](.../software/S0154) to establish persistence via
[T1547.001]". That is 3.95M characters of adversary narrative with G####, S####
and T#### identifiers co-occurring inside running prose, which is exactly the
surface form that took ATT&CK ids from -45% against gpt2 to +13%.

ADVERSARY is the corpus's scarcest register — 1.0% against a 12% target, and the
binding constraint that forces the register balancer to discard four fifths of
everything else. This source roughly triples it without a single new byte
downloaded.

**Why a separate adapter rather than extending attack.py.** That file has been
through an adversarial verification pass that hardened its fetch, its truncation
guards and its HTML handling; reopening it to add a second emit path risks that
work for no benefit. This module reuses its ``_fetch`` and ``_load`` directly, so
there is still exactly one downloader and one cache, and ``build.py``'s global
fingerprint dedup means the two adapters cannot double-count a document even if
their coverage ever overlapped.
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterator

from ..source import Document, Register, Side, SourceSpec, normalise
from .attack import _BLOB, _fetch, _load, _strip_html

#: MITRE's inline source markers. Removed only to *judge* whether a description
#: has substance — the markers stay in the emitted text, where they are part of
#: how ATT&CK prose actually reads.
_CITATION = re.compile(r"\(Citation:[^)]*\)")

#: STIX types that describe an actor or a capability, mapped to the heading the
#: rendered document uses. Techniques are deliberately absent — attack.py owns
#: those, and emitting them here would be duplicated work the dedup would throw
#: away anyway.
_KINDS: dict[str, str] = {
    "intrusion-set": "Threat group",
    "malware": "Malware",
    "tool": "Tool",
    "campaign": "Campaign",
    "course-of-action": "Mitigation",
}


def _ref(obj: dict[str, Any]) -> dict[str, Any] | None:
    """The ``mitre-attack`` external reference, which carries the G/S/C/M id."""
    for ref in obj.get("external_references", ()) or ():
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref
    return None


def _documents(path: Path) -> Iterator[Document]:
    bundle = _load(path)
    objects = bundle.get("objects", ())

    by_uuid: dict[str, dict[str, Any]] = {}
    for obj in objects:
        if obj.get("id"):
            by_uuid[obj["id"]] = obj

    # Procedure examples hang off relationships. Group them by the actor or
    # capability they belong to, so each actor's document carries its own
    # narrative rather than the corpus holding 21,262 orphaned sentences.
    procedures: defaultdict[str, list[str]] = defaultdict(list)
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        description = (obj.get("description") or "").strip()
        if not description:
            continue

        # Strip citation markers before judging substance. 1,096 of the 19,925
        # described relationships are nothing but "(Citation: Foo)" — a source
        # attribution with no procedure in it. Those were landing first for
        # prolific groups and consuming the per-actor cap before any of the
        # 18,829 real narratives got in, which is how APT29's document came out
        # as a list of bare citations.
        body = _CITATION.sub("", description).strip()
        if len(body) < 25:
            continue

        source_uuid = obj.get("source_ref", "")
        target = by_uuid.get(obj.get("target_ref", ""))
        target_ref = _ref(target) if target else None
        label = ""
        if target is not None:
            ident = target_ref["external_id"] if target_ref else ""
            label = f"{ident} {target.get('name', '')}".strip()
        entry = f"- {label}: {_strip_html(description)}" if label else \
                f"- {_strip_html(description)}"
        procedures[source_uuid].append((len(body), entry))

    for obj in objects:
        kind = _KINDS.get(obj.get("type", ""))
        if kind is None or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ref = _ref(obj)
        if ref is None:
            continue

        ident = ref["external_id"]
        name = str(obj.get("name", "")).strip()
        lines = [f"{ident} {name}", "", f"ATT&CK ID: {ident}", f"Type: {kind}",
                 f"Name: {name}"]

        aliases = [a for a in (obj.get("aliases")
                               or obj.get("x_mitre_aliases") or ()) if a != name]
        if aliases:
            lines.append(f"Also known as: {', '.join(aliases)}")
        if ref.get("url"):
            lines.append(f"Reference: {ref['url']}")
        platforms = obj.get("x_mitre_platforms") or ()
        if platforms:
            lines.append(f"Platforms: {', '.join(platforms)}")

        description = _strip_html(str(obj.get("description", "")))
        if description:
            lines += ["", "## Description", "", description]

        scored = procedures.get(obj.get("id", ""), [])
        if scored:
            # The whole reason this source exists. Longest-first inside the cap,
            # so a prolific group's allowance goes to its richest narratives
            # rather than to whichever relationship happened to be earlier in
            # the bundle. Capped because a handful of groups carry hundreds of
            # entries and would otherwise dominate the register they broaden.
            examples = [e for _n, e in sorted(scored, key=lambda t: -t[0])][:60]
            lines += ["", "## Procedure examples", ""] + examples

        text = normalise("\n".join(lines))
        if len(text) < 200:
            continue
        yield Document(text=text, source="attackactors",
                       register=Register.ADVERSARY, side=Side.RED, ident=ident)


SPEC = SourceSpec(
    name="attackactors",
    license=(
        "MITRE ATT&CK Terms of Use. MITRE grants a non-exclusive, royalty-free "
        "licence to use ATT&CK for research, development and commercial "
        "purposes, provided MITRE's copyright designation and licence are "
        "reproduced: \"(c) 2026 The MITRE Corporation. This work is reproduced "
        "and distributed with the permission of The MITRE Corporation.\" ATT&CK "
        "and MITRE ATT&CK are registered trademarks of The MITRE Corporation. "
        "Terms: https://attack.mitre.org/resources/legal-and-branding/terms-of-use/"
    ),
    url="https://github.com/mitre-attack/attack-stix-data",
    register=Register.ADVERSARY,
    side=Side.RED,
    fetch=_fetch,
    documents=_documents,
    expect_min_docs=1000,
    notes=("Threat groups, malware, tools, campaigns and mitigations from the "
           "same Enterprise bundle attack.py fetches — no extra download. Each "
           "carries its procedure examples, which are the bundle's densest "
           "adversary narrative and where G/S/C ids co-occur with technique ids "
           "in running prose."),
)
