"""Elastic detection-rules — shipped SIEM logic for the DETECTION register.

This project's thesis is that a red verb which cannot name the blue control that
catches it is an unfinished thought, so the DETECTION register is load-bearing
rather than decorative: it is half of every pair the training verifier checks.
A detection register assembled only from rule *descriptions* would let the model
talk about detection without ever having written one. These 2,200 files are the
opposite of that. They are the rules Elastic Security actually ships and enables
in customer stacks — each one a real query against a real index pattern, with the
false positives its authors hit in production and the triage runbook an analyst
follows when it fires.

**The red/blue join is explicit here, in the exact form the tokenizer needs.**
Every rule carries ``[[rule.threat]]`` blocks that name an ATT&CK tactic and
technique with their identifiers beside their names — ``TA0005 Defense Evasion``,
``T1562 Impair Defenses``, ``T1562.001 Disable or Modify Tools`` — sitting in the
same document as the query that detects that behaviour. That is not a mapping
table somewhere and the detection somewhere else; it is the join itself, 3,739
tactic mappings and 4,758 technique mappings of it. The tokenizer measurement
this corpus was rebuilt around said ``T1547.001`` beside its human name moved a
sample from -45% to +13% against gpt2, and this source supplies that pairing
with a working query attached.

**It is a different surface form from Sigma, not more of it.** Sigma is already
in the corpus and Sigma is abstract: ``Image|endswith`` and a condition
expression that a backend compiles into whatever the SIEM speaks. What lands in
an Elastic stack is EQL (``process where host.os.type == "windows" and
process.name : "fltMC.exe"``), KQL, ES|QL pipelines (``from logs-azure.signinlogs*
| WHERE ... | STATS ... | KEEP``) and the occasional Lucene string. Register is
about surface form, which is what a BPE learns, so 1,096 EQL rules and 231 ES|QL
pipelines broaden the register instead of duplicating Sigma's YAML. They also
bring ECS field names (``process.parent.executable``, ``event.dataset``,
``user_agent.original``) and Elastic index patterns
(``logs-endpoint.events.process-*``, ``winlogbeat-*``) as first-class vocabulary.

**Licence: Elastic License 2.0.** Read from the repository rather than guessed.
``LICENSE.txt`` is the Elastic License 2.0 text and ``README.md`` states it
without hedging: "Everything in this repository — rules, code, etc. — is licensed
under the Elastic License v2." Five rules derive from BlueTeamLabs/sentinel-attack
under MIT and are sublicensed as Elastic v2, which ``NOTICE.txt`` records; both
files are copied into the cache so the claim above stays checkable offline. The
licence's one real limitation — no offering the software as a hosted or managed
service — does not bite a training corpus, and its "may not alter, remove, or
obscure any licensing, copyright, or other notices" clause is why ``NOTICE.txt``
travels with the cache instead of being dropped as build noise.

**TOML from the standard library.** ``tomllib`` landed in Python 3.11 and this
project already requires newer than that, so a third-party TOML dependency would
buy nothing and cost a supply-chain edge on the machine that builds the training
data. All 2,247 files parse with it, byte for byte, including the ``'''literal
strings'''`` that hold queries full of ``\\`` Windows paths — which is precisely
why upstream uses that form and why a hand-rolled parser here would be a
liability.

**Whitespace, and what is done to the fields that are prose.** Queries are laid
into the document exactly as ``tomllib`` returns them and then handed to the
shared :func:`~training.corpus.source.normalise`, which preserves horizontal
whitespace on purpose. That contract is the whole reason a multi-line EQL
``not process.parent.executable : (...)`` block keeps its hanging indent and an
ES|QL pipeline keeps its one-pipe-per-line shape. Two things the shared cleaner
does touch, stated rather than hidden: it strips trailing whitespace at line ends
(348 queries carry some, none of it meaning anything) and it caps blank-line runs
at two (one query upstream has three). Nothing is collapsed, reflowed or
re-indented, and nothing is cleaned privately in this module — a private cleaner
in one source is how a corpus stops being comparable across sources.

The single exception is ``false_positives``, and it is decoding rather than
cleaning. Those entries are TOML array elements, so upstream indents the string
body to line up inside the brackets: measured across the tree, 800 multi-line
entries are indented by exactly 4 spaces, 6 by 2, and 1 by none. That indent
belongs to the TOML file's layout, not to the sentence, so a uniform
``textwrap.dedent`` removes it — which preserves any *relative* indent a nested
bullet has. ``description``, ``note`` and ``setup`` were measured too and are
never indented, so they are passed through untouched.

**Two holdbacks, both measured, both printed at build time.**

``setup`` is dropped entirely. It reads "Go to the Kibana home page and click
'Add integrations'" — product onboarding for Elastic Agent and Fleet, not
detection logic — and it is generated: 1,303 rules carry only 342 distinct
blocks, the largest of which is 2,069 characters repeated 192 times. Keeping it
would add 1.57 MB to the source, most of it the same Kibana click-through
memorised a hundred and ninety-two times over.

The generative-AI disclaimer that opens 1,011 investigation guides is dropped
too. It is a 337-character blockquote about the guide having been AI-assisted,
making it the single most repeated string in the whole repository at 317 KB.
It is matched as a ``> **Disclaimer**:`` blockquote rather than by its exact
wording, so a reworded disclaimer next quarter is still caught.

Everything else stays. Notably the investigation guides themselves stay whole:
all 2,062 of them are distinct, they are dense with ECS field names, osquery SQL
and sibling rule ids, and they are the thing a blue-team model is actually asked
to produce. They are also 55% of this source's characters, which is a real
skew — it is printed in the build report rather than left for someone to
discover, and it is prose *bound to the query it explains in the same document*,
which is the binding a bare rule file never gives you. That is the same argument
:mod:`~training.corpus.sources.splunk` makes for keeping ``how_to_implement``
while refusing the ``stories/`` tree, and it is applied the same way here:
``hunting/`` is a separate tree of standalone threat-hunting queries and
markdown, and it is left out because it is a different artefact, not a rule.

**``$osquery_N`` and ``$investigate_N`` are resolved, not left dangling.**
Investigation guides reference ``[transform]`` tables by placeholder — 449
osquery references and 739 Kibana timeline references. Emitted raw, those are
1,188 dangling ``$``-tokens teaching the model a syntax that means nothing
outside contentctl, while the osquery SQL they point at (real ``SELECT ... FROM
services JOIN authenticode ...``) never appears at all. Each placeholder is
substituted in place, with continuation lines indented to the bullet it sits in
so the surrounding markdown survives.

**Deprecated rules are kept.** All 130 of them, labelled ``Maturity:
deprecated``. The near-duplicate worry is the right one to have and it was
measured: zero of the 128 deprecated rules that carry a query share that query,
whitespace-insensitively, with any live rule. They are retired detections whose
EQL is no less real, and the rule ids in them still turn up in old alerts.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tarfile
import textwrap
import tomllib
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from training.corpus import net
from training.corpus.source import (
    Document,
    Register,
    Side,
    SourceError,
    SourceSpec,
    normalise,
)

__all__ = ["SPEC"]

_REPO = "https://github.com/elastic/detection-rules"
#: ``main`` is the repository's default branch. A codeload tarball is one
#: request with no git binary, no history and nothing a later ``git pull`` could
#: mutate under a reproducible build. It is a fat 62 MB because the repo also
#: carries its Python tooling, its tests and its docs — only the two rule trees
#: are ever written to disk, and the tarball is deleted once unpacked.
_REF = "main"
_TARBALL = f"https://codeload.github.com/elastic/detection-rules/tar.gz/refs/heads/{_REF}"

#: Written last and only on success, so a half-extracted cache re-fetches rather
#: than being mistaken for a complete one.
#:
#: Both names are deliberately specific to this source. ``build.py`` hands every
#: adapter its own ``cache/<name>/`` directory so a generic ``content/`` and
#: ``.fetched.json`` would be safe there — but developing a source by hand means
#: calling ``SPEC.fetch()`` on the bare cache root, and two adapters in this
#: package already claim exactly those two generic names. The first hand-test of
#: this adapter wrote its tree over another source's, which is a quiet way to
#: build a corpus out of the wrong files. Named directories cost nothing and make
#: that impossible.
_MARKER = ".elastic.fetched.json"
_CONTENT = "detection-rules"

#: Trees kept, as prefixes of the repo-relative path.
#:
#: ``rules/`` is the point of the source: 2,118 rules under windows/, linux/,
#: macos/, network/, cross-platform/, integrations/ (750 files of cloud and SaaS
#: detections), ml/, promotions/, threat_intel/, apm/ and _deprecated/.
#: ``rules_building_block/`` holds 129 more in the identical schema — lower-noise
#: rules that feed correlation rather than alerting on their own, which makes
#: them ordinary detection logic for this purpose.
_RULE_TREES: tuple[str, ...] = ("rules/", "rules_building_block/")

#: Copied into the cache root so the licence claim in :data:`SPEC` stays
#: checkable offline, and because Elastic License 2.0 forbids obscuring notices.
_LICENSE_FILES: tuple[str, ...] = ("LICENSE.txt", "NOTICE.txt")

#: Left on the floor deliberately. ``hunting/`` is a parallel tree of standalone
#: threat-hunting queries plus generated markdown — a different artefact with a
#: different schema, not a detection rule, and worth its own adapter if the
#: register ever needs it. Everything else in the repo (``detection_rules/``,
#: ``tests/``, ``lib/``, ``docs/``) is the Python tooling that builds and
#: validates the rules, which is a Python corpus and not a detection one.
_SKIPPED_TREES: tuple[str, ...] = ("hunting/",)

#: 2,247 rule files were present on ``main`` when this adapter was written. A
#: floor far below that turns a renamed or moved tree into a loud fetch failure
#: instead of a mysteriously thin build report.
_MIN_RULE_FILES = 1500

#: A ceiling on one archive member, and a different kind of ceiling from
#: :data:`_MIN_CHARS` below: a rule file over this is not a quality problem, it
#: is an accident or an attack. The extraction below used to be
#: ``target.write_bytes(stream.read())``, one allocation of whatever the member
#: declared. NUL bytes gzip at roughly 1000:1, so a single ``rules/windows/
#: bogus.toml`` holding 8 GiB of them — a committed core dump, or a commit after
#: an upstream compromise — leaves the 62 MB tarball looking entirely normal and
#: then asks for an 8 GiB allocation. On this machine that is a MemoryError that
#: kills the build, or an OOM kill that picks the training run instead.
#:
#: Checked against ``member.size`` *before* extracting, which is sound rather
#: than trusting: tarfile bounds the reader it returns to exactly the declared
#: length, so a member cannot deliver more than its header claims. The largest
#: real file in this tree is 53 KB, so this leaves three hundred times the room
#: it needs and still refuses a bomb.
_MAX_MEMBER_BYTES = 16 * 1024 * 1024

#: A rendered rule is always a header plus a description, so real documents start
#: around 500 characters. Below this, something is a stub or a parse casualty.
_MIN_CHARS = 200

#: ``language`` as upstream spells it, mapped to the name the industry uses. The
#: point of naming it in the text is that a model reading a bare query has to
#: infer the dialect; a model that has read "Detection query (EQL)" above ten
#: thousand of them does not.
_LANGUAGES: dict[str, str] = {
    "eql": "EQL",
    "kuery": "KQL",
    "esql": "ES|QL",
    "lucene": "Lucene",
}

#: ``$osquery_3`` / ``$investigate_12`` — a reference into the file's own
#: ``[transform]`` tables. Every occurrence upstream sits alone on a markdown
#: bullet line (checked: 1,131 lines carry exactly one and never two), which is
#: what makes in-place substitution with a continuation indent safe.
_PLACEHOLDER = re.compile(r"\$(osquery|investigate)_(\d+)")

#: The generative-AI disclaimer blockquote that opens 1,011 investigation guides.
#: Matched as a structure — a ``> **Disclaimer**:`` line and the ``>`` lines that
#: continue it — rather than as its exact 337 characters, so a reworded version
#: is caught too. Nothing else in the tree uses a bolded blockquote label.
_DISCLAIMER = re.compile(
    r"(?m)^>[ \t]*\*\*Disclaimer\*\*:[ \t]*\n(?:^>.*\n?)*", re.IGNORECASE
)


# ---------------------------------------------------------------------------
# fetch
# ---------------------------------------------------------------------------

def _relative(member_name: str) -> str | None:
    """Repo-relative path for a tar member, or ``None`` if it is not safe.

    Tar member names are attacker-controlled data in the general case: absolute
    paths, ``..`` segments and symlinks are all expressible. The archive's single
    root component is dropped and anything that could escape is refused here,
    before a name ever reaches the filesystem — rather than trusting
    ``extractall``, whose safe ``filter="data"`` is a recent addition and whose
    failure mode is a write outside the cache.
    """
    parts = Path(member_name).parts
    if len(parts) < 2:
        return None
    relative = Path(*parts[1:])
    if relative.is_absolute() or ".." in relative.parts:
        return None
    return relative.as_posix()


def _wanted(rel: str) -> bool:
    """True for a rule file this source collects."""
    if any(rel.startswith(tree) for tree in _SKIPPED_TREES):
        return False
    return rel.endswith(".toml") and any(
        rel.startswith(tree) for tree in _RULE_TREES
    )


def _rmtree(path: Path) -> None:
    if not path.exists():
        return
    shutil.rmtree(path, ignore_errors=True)


def _fetch(cache_dir: Path) -> Path:
    """Populate ``cache_dir`` with the two rule trees; return the content root.

    Idempotent and network-free on re-run: the marker is written only after the
    staged tree has been swapped into place, so an interrupted fetch is retried
    rather than mistaken for a complete one. The download goes through
    :mod:`training.corpus.net`, which is this project's one source of verified
    TLS — three adapters once grew private trust-store helpers, and one private
    copy is all it takes for a late-night ``CERT_NONE`` to ship.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    marker = cache_dir / _MARKER
    content = cache_dir / _CONTENT
    # Both the marker *and* a real rule tree, not just the marker: the marker
    # alone would let a directory that someone emptied by hand pass for a
    # complete fetch, and the failure mode of that is a build report saying zero
    # documents with no explanation.
    if marker.is_file() and any(
        (content / tree).is_dir() for tree in _RULE_TREES
    ):
        return content

    archive = cache_dir / ".detection-rules.tar.gz"
    staging = cache_dir / ".staging"
    _rmtree(staging)

    kept: Counter[str] = Counter()
    try:
        try:
            net.download(_TARBALL, archive, timeout=900)
        except net.NetworkError as exc:
            raise SourceError(f"elastic: {exc}") from exc

        staging.mkdir(parents=True, exist_ok=True)
        resolved = staging.resolve()
        try:
            # Streamed ("r|gz") rather than seekable: the tarball is 62 MB and
            # only a third of it is ever wanted, so there is no reason to let
            # tarfile index the whole member table first.
            with tarfile.open(archive, mode="r|gz") as tar:
                for member in tar:
                    # isfile() also excludes symlinks and hardlinks, so no link
                    # enters the cache and the later walk cannot be led anywhere
                    # by one.
                    if not member.isfile():
                        continue
                    rel = _relative(member.name)
                    if rel is None:
                        continue
                    # Before extracting anything, including the licence: see
                    # _MAX_MEMBER_BYTES for why the archive's own size is no
                    # evidence about a member's.
                    if member.size > _MAX_MEMBER_BYTES:
                        continue
                    if rel in _LICENSE_FILES:
                        stream = tar.extractfile(member)
                        if stream is not None:
                            with stream, (cache_dir / rel).open("wb") as handle:
                                shutil.copyfileobj(stream, handle, 1 << 20)
                        continue
                    if not _wanted(rel):
                        continue
                    target = staging / rel
                    if not target.resolve().is_relative_to(resolved):
                        continue
                    stream = tar.extractfile(member)
                    if stream is None:
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    # Copied a megabyte at a time rather than read() into one
                    # buffer, so peak memory is a chunk and not the file. The
                    # ceiling above makes this belt and braces; the shape is
                    # here so a later edit that raises the ceiling does not
                    # silently reintroduce the allocation.
                    with stream, target.open("wb") as handle:
                        shutil.copyfileobj(stream, handle, 1 << 20)
                    kept[rel.split("/", 1)[0]] += 1
        except tarfile.TarError as exc:
            raise SourceError(
                f"elastic: malformed tarball from {_TARBALL}: {exc}"
            ) from exc

        total = sum(kept.values())
        if total < _MIN_RULE_FILES:
            raise SourceError(
                f"elastic: only {total} .toml rule files found under "
                f"{'/, '.join(_RULE_TREES)} in {_TARBALL} (expected >= "
                f"{_MIN_RULE_FILES}). The upstream layout has probably changed; "
                "fix the adapter rather than training on a fraction of the "
                "detection register."
            )

        # Swap in only once the staging tree is complete.
        _rmtree(content)
        staging.replace(content)
        marker.write_text(
            json.dumps(
                {
                    "url": _TARBALL,
                    "repo": _REPO,
                    "ref": _REF,
                    "fetched_utc": datetime.now(timezone.utc).isoformat(
                        timespec="seconds"
                    ),
                    "files_by_tree": dict(sorted(kept.items())),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    finally:
        archive.unlink(missing_ok=True)
        (cache_dir / ".detection-rules.tar.gz.part").unlink(missing_ok=True)
        _rmtree(staging)
    return content


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def _as_list(value: Any) -> list[str]:
    """Coerce a TOML scalar-or-array field into a list of strings.

    ``metadata.integration`` is an array in 2,244 files and a bare string in
    three. That kind of inconsistency is normal in a large hand-maintained tree
    and is not worth a crash.
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(value)]


def _prose(value: Any) -> str:
    """A TOML string field as prose, with the array-element indent removed.

    :func:`textwrap.dedent` strips only the *common* leading whitespace, so a
    nested bullet inside a ``false_positives`` entry keeps its relative depth
    while the four spaces that exist to line the string up inside ``[ ]`` go.
    """
    if not isinstance(value, str):
        return ""
    return textwrap.dedent(value.strip("\n")).strip()


def _section(title: str, body: list[str]) -> list[str]:
    """A titled section, or nothing at all if there is nothing to put in it.

    The emptiness test matters for the single-value sections, which pass one
    string straight through: a list holding one empty string is still truthy, and
    the result would be a bare heading with the next heading directly under it —
    structural noise that teaches a heading can be followed by nothing.

    Blank lines *inside* a non-empty body are kept, and this is not a detail. The
    first draft of this helper filtered every blank line out, which glued the
    query straight onto the ``Index patterns:`` line above it and turned two
    different things into what looks like one block of EQL. Only the leading and
    trailing blanks are trimmed, so a caller can separate the definition lines
    from the query with ``[""]`` and have that survive.
    """
    kept = list(body)
    while kept and not kept[0].strip():
        kept.pop(0)
    while kept and not kept[-1].strip():
        kept.pop()
    return ["", f"## {title}", "", *kept] if kept else []


def _bullet(text: str, indent: str = "  ") -> str:
    """A ``- `` bullet whose wrapped continuation lines are indented under it.

    ``false_positives`` and ``description`` arrive hard-wrapped at about 120
    columns by the repository's own formatter, and that wrap is kept rather than
    reflowed — this adapter does not rewrite upstream prose. But a wrapped
    sentence whose second line starts at column 0 reads as a second list item
    that happens to be missing its dash, so the continuation is indented to sit
    under the first. That is layout added around the text, never inside it.
    """
    lines = text.split("\n")
    return "\n".join([f"- {lines[0]}", *(f"{indent}{line}" for line in lines[1:])])


def _technique_url(technique_id: str, declared: str) -> str:
    """The ATT&CK URL for a technique id, preferring the one upstream wrote.

    Upstream supplies ``reference`` on every technique block today. The fallback
    exists because the URL is the *second* syntactic position this document gives
    the identifier — ``T1562.001`` once beside its name, once as
    ``techniques/T1562/001/`` — and losing that to a missing field would quietly
    halve the exposure that the tokenizer measurement actually rewarded.
    """
    if declared.strip():
        return declared.strip()
    if not technique_id:
        return ""
    return f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"


# ---------------------------------------------------------------------------
# transform placeholders
# ---------------------------------------------------------------------------

def _osquery_text(entry: dict[str, Any]) -> tuple[str, str]:
    """``(headline, body)`` for one ``[[transform.osquery]]`` table."""
    label = str(entry.get("label", "") or "").strip()
    query = str(entry.get("query", "") or "").strip()
    if not label:
        return "Osquery", query
    # Most labels upstream already read "Osquery - Retrieve All Services", so a
    # blind prefix produces "Osquery — Osquery - ...". Prefix only the ones that
    # do not name themselves.
    return (label if label.lower().startswith("osquery") else f"Osquery — {label}"), query


def _investigate_text(entry: dict[str, Any]) -> tuple[str, str]:
    """``(headline, body)`` for one ``[[transform.investigate]]`` table.

    A Kibana timeline template is a nested list of field/value providers: the
    outer list is OR, the inner is AND, ``value`` may be a ``{{mustache}}``
    reference back into the alert, and ``excluded`` negates. Flattened into one
    readable clause it is a string of ECS field names doing exactly what the
    query above it does — which is why it is worth resolving rather than
    dropping. The raw JSON is not emitted: it is Kibana's saved-object schema,
    not detection vocabulary.
    """
    label = str(entry.get("label", "") or "").strip()
    groups: list[str] = []
    for group in entry.get("providers", []) or []:
        clauses = []
        for provider in group if isinstance(group, list) else [group]:
            if not isinstance(provider, dict):
                continue
            field = str(provider.get("field", "") or "").strip()
            value = str(provider.get("value", "") or "").strip()
            if not field:
                continue
            clause = f"{field}: {value}" if value else field
            if provider.get("excluded"):
                clause = f"NOT {clause}"
            clauses.append(clause)
        if clauses:
            groups.append(" and ".join(clauses))
    body = " OR ".join(groups)
    window = " ".join(
        str(entry.get(key, "") or "").strip()
        for key in ("relativeFrom", "relativeTo")
    ).strip()
    if body and window:
        body = f"{body}  [{window.replace(' ', ' to ')}]"
    return f"Timeline — {label}" if label else "Timeline", body


def _resolve_placeholders(note: str, transform: dict[str, Any],
                          held: Counter[str]) -> str:
    """Substitute ``$osquery_N`` / ``$investigate_N`` with what they point at.

    Done line by line, because every placeholder upstream sits at the end of a
    markdown bullet (``      - $osquery_1``) and a multi-line osquery statement
    pasted in flat would break the list it lives in. The replacement's first
    line goes where the placeholder was; continuation lines are indented to the
    bullet's own depth plus two, so the SQL keeps its shape and the markdown
    keeps its structure.

    An unresolvable placeholder — a reference to a transform table that is not
    in the file — is left exactly as written and counted. Silently deleting it
    would hide an upstream inconsistency that the count makes visible.
    """
    if not note:
        return note
    tables = {
        kind: transform.get(kind, []) or []
        for kind in ("osquery", "investigate")
    }
    out: list[str] = []
    for line in note.split("\n"):
        match = _PLACEHOLDER.search(line)
        if match is None:
            out.append(line)
            continue
        kind, index = match.group(1), int(match.group(2))
        entries = tables.get(kind, [])
        if index >= len(entries) or not isinstance(entries[index], dict):
            held[f"unresolved ${kind}"] += 1
            out.append(line)
            continue
        headline, body = (
            _osquery_text(entries[index]) if kind == "osquery"
            else _investigate_text(entries[index])
        )
        indent = " " * (len(line) - len(line.lstrip()) + 2)
        out.append(line[: match.start()] + headline + line[match.end():])
        out.extend(f"{indent}{piece}" for piece in body.split("\n") if piece.strip())
        held[f"resolved ${kind}"] += 1
    return "\n".join(out)


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

def _header(rel: str, meta: dict[str, Any], rule: dict[str, Any]) -> list[str]:
    """The labelled preamble: what this rule is, where it runs, what it costs.

    The rule's name leads the document and is then repeated on its own labelled
    line, and the UUID appears once — these are the strings that identify a rule
    in an Elastic alert, in a Kibana URL and in the "Related Rules" lists inside
    other rules' investigation guides, so they are worth being able to recognise.
    """
    name = str(rule.get("name", "") or "").strip()
    rule_type = str(rule.get("type", "") or "").strip()
    language = str(rule.get("language", "") or "").strip()
    tree = rel.rsplit("/", 1)[0]

    lines = [
        f"{name} — Elastic detection rule",
        "",
        f"Rule name: {name}",
        f"Rule id: {rule.get('rule_id', '')}",
        f"Rule type: {rule_type}",
    ]
    if language:
        lines.append(
            f"Query language: {_LANGUAGES.get(language, language)} ({language})"
        )
    severity = str(rule.get("severity", "") or "").strip()
    risk = rule.get("risk_score")
    if severity or risk is not None:
        lines.append(f"Severity: {severity} (risk score {risk})")
    lines.append(f"Rule tree: {tree}")
    if maturity := str(meta.get("maturity", "") or "").strip():
        lines.append(f"Maturity: {maturity}")
    if integrations := _as_list(meta.get("integration")):
        lines.append(f"Integrations: {', '.join(integrations)}")
    if block := str(rule.get("building_block_type", "") or "").strip():
        lines.append(f"Building block rule: {block}")
    # Authors are only worth a line when they are not the house name — every
    # rule says "Elastic", and the handful that name a contributor are the only
    # ones where the field carries information.
    authors = _as_list(rule.get("author"))
    if authors and authors != ["Elastic"]:
        lines.append(f"Authors: {', '.join(authors)}")
    if tags := _as_list(rule.get("tags")):
        lines.append(f"Tags: {'; '.join(tags)}")
    lines.append(f"Source: {_REPO}/blob/{_REF}/{rel}")
    return lines


def _render_threat(rule: dict[str, Any]) -> list[str]:
    """ATT&CK mappings, with every identifier next to the name it denotes.

    Indented tactic → technique → sub-technique rather than listed flat, because
    the containment is a fact: ``T1562.001`` is a way of doing ``T1562``, which
    is a way of achieving ``TA0005``. That is the shape of the red/blue join this
    source exists to supply, and flattening it would throw away the half of it
    that is structure.

    A tactic with no techniques under it is still emitted — 134 threat blocks
    upstream map only that far, and "this query serves Defense Evasion" is a true
    and useful statement on its own.
    """
    lines: list[str] = []
    for block in rule.get("threat", []) or []:
        if not isinstance(block, dict):
            continue
        framework = str(block.get("framework", "") or "").strip() or "MITRE ATT&CK"
        tactic = block.get("tactic") or {}
        tactic_id = str(tactic.get("id", "") or "").strip()
        tactic_name = str(tactic.get("name", "") or "").strip()
        tactic_url = str(tactic.get("reference", "") or "").strip()
        if tactic_id or tactic_name:
            head = f"- {framework} tactic {tactic_id} {tactic_name}".rstrip()
            lines.append(f"{head} ({tactic_url})" if tactic_url else head)

        for technique in block.get("technique", []) or []:
            if not isinstance(technique, dict):
                continue
            tid = str(technique.get("id", "") or "").strip()
            tname = str(technique.get("name", "") or "").strip()
            url = _technique_url(tid, str(technique.get("reference", "") or ""))
            head = f"  - Technique {tid} {tname}".rstrip()
            lines.append(f"{head} ({url})" if url else head)

            for sub in technique.get("subtechnique", []) or []:
                if not isinstance(sub, dict):
                    continue
                sid = str(sub.get("id", "") or "").strip()
                sname = str(sub.get("name", "") or "").strip()
                surl = _technique_url(sid, str(sub.get("reference", "") or ""))
                head = f"    - Sub-technique {sid} {sname}".rstrip()
                lines.append(f"{head} ({surl})" if surl else head)
    return lines


def _render_definition(rule: dict[str, Any]) -> list[str]:
    """Where the query runs and how it is evaluated — the lines above the query.

    Index patterns are here rather than in the header because they belong to the
    query: ``logs-endpoint.events.process-*`` is the half of a detection that
    says which stream of events the EQL is even looking at, and a model asked to
    write an Elastic rule has to produce both.
    """
    lines: list[str] = []
    if index := _as_list(rule.get("index")):
        lines.append(f"Index patterns: {', '.join(index)}")

    schedule = []
    if interval := str(rule.get("interval", "") or "").strip():
        schedule.append(f"runs every {interval}")
    if window := str(rule.get("from", "") or "").strip():
        schedule.append(f"looks back to {window}")
    if schedule:
        lines.append(f"Schedule: {', '.join(schedule)}")

    threshold = rule.get("threshold")
    if isinstance(threshold, dict):
        fields = ", ".join(_as_list(threshold.get("field"))) or "all events"
        lines.append(
            f"Threshold: at least {threshold.get('value')} events grouped by {fields}"
        )
        for card in threshold.get("cardinality", []) or []:
            if isinstance(card, dict):
                lines.append(
                    f"Threshold cardinality: {card.get('value')} distinct "
                    f"{card.get('field')}"
                )

    new_terms = rule.get("new_terms")
    if isinstance(new_terms, dict):
        fields = ", ".join(_as_list(new_terms.get("value")))
        window = ""
        for item in new_terms.get("history_window_start", []) or []:
            if isinstance(item, dict) and item.get("value"):
                window = str(item["value"])
        lines.append(
            f"New terms: alerts on a value of {fields} not seen"
            + (f" since {window}" if window else "")
        )

    if job := rule.get("machine_learning_job_id"):
        lines.append(f"Anomaly detection job: {', '.join(_as_list(job))}")
    if (threshold := rule.get("anomaly_threshold")) is not None:
        lines.append(f"Anomaly score threshold: {threshold}")

    suppression = rule.get("alert_suppression")
    if isinstance(suppression, dict):
        parts = []
        if group := _as_list(suppression.get("group_by")):
            parts.append(f"grouped by {', '.join(group)}")
        duration = suppression.get("duration")
        if isinstance(duration, dict):
            parts.append(f"for {duration.get('value')}{duration.get('unit')}")
        if missing := str(suppression.get("missing_fields_strategy", "") or ""):
            parts.append(f"missing fields: {missing}")
        if parts:
            lines.append(f"Alert suppression: {', '.join(parts)}")

    if fields := rule.get("investigation_fields"):
        names = _as_list(fields.get("field_names") if isinstance(fields, dict) else fields)
        if names:
            lines.append(f"Investigation fields: {', '.join(names)}")

    if override := str(rule.get("timestamp_override", "") or "").strip():
        lines.append(f"Timestamp override: {override}")

    # 21 rules carry raw Elasticsearch query DSL as an extra filter. It is real
    # detection logic in a real query language, so it is kept — as compact JSON
    # on one line, because the pretty-printed form is four times the characters
    # for the same content.
    for filter_clause in rule.get("filters", []) or []:
        lines.append(f"Filter (Elasticsearch DSL): {json.dumps(filter_clause)}")
    return lines


def _render_indicator_match(rule: dict[str, Any]) -> list[str]:
    """The second half of a ``threat_match`` rule: the indicator side.

    Nine rules upstream. They are the only ones that carry two queries — one
    over events, one over an indicator index — joined field by field, and that
    join is the whole mechanism of indicator matching. Rendering only the event
    query would make them look like ordinary rules that happen to be inert.
    """
    lines: list[str] = []
    if index := _as_list(rule.get("threat_index")):
        lines.append(f"Indicator index patterns: {', '.join(index)}")
    if path := str(rule.get("threat_indicator_path", "") or "").strip():
        lines.append(f"Indicator path: {path}")
    query = str(rule.get("threat_query", "") or "").strip()
    language = str(rule.get("threat_language", "") or "").strip()
    if query:
        lines.append("")
        lines.append(
            f"Indicator query ({_LANGUAGES.get(language, language) or 'unspecified'}):"
        )
        lines.append("")
        lines.append(query)
    pairs: list[str] = []
    for mapping in rule.get("threat_mapping", []) or []:
        for entry in (mapping or {}).get("entries", []) or []:
            if isinstance(entry, dict) and entry.get("field"):
                pairs.append(f"{entry.get('field')} = {entry.get('value')}")
    if pairs:
        lines.append("")
        lines.append("Indicator match fields:")
        lines.extend(_bullet(pair) for pair in pairs)
    return lines


def _render(rel: str, data: dict[str, Any], held: Counter[str]) -> str:
    """One rule as labelled sections of plain lines.

    Section order follows how a defender reads a rule: what it is, what it
    detects, which adversary behaviour that is, the query, what makes it lie, the
    sources, and then the runbook. The investigation guide goes last on purpose —
    it carries its own ``##`` markdown headings, so anything placed after it
    would appear to be part of it.
    """
    meta = data.get("metadata") or {}
    rule = data["rule"]
    transform = data.get("transform") or {}

    lines = _header(rel, meta, rule)
    lines += _section("What it detects", [_prose(rule.get("description"))])
    lines += _section("ATT&CK mapping", _render_threat(rule))

    query = str(rule.get("query", "") or "").strip("\n")
    language = str(rule.get("language", "") or "").strip()
    pretty = _LANGUAGES.get(language, language)
    definition = _render_definition(rule)
    if query.strip():
        title = f"Detection query ({pretty})" if pretty else "Detection query"
        lines += _section(title, definition + ["", query])
    else:
        # 106 machine_learning rules have no query at all: the detection *is* an
        # anomaly job. Saying so plainly is better than either crashing on the
        # missing key or emitting a "Detection query" heading with nothing under
        # it, which would teach the model that Elastic rules sometimes have an
        # empty query — they do not.
        rule_type = str(rule.get("type", "") or "").strip() or "unknown"
        lines += _section(
            "Detection",
            [
                f"This rule runs no query. It is a {rule_type} rule: the "
                "detection is an anomaly detection job, and the rule alerts when "
                "that job's anomaly score crosses the threshold below.",
                "",
                *definition,
            ],
        )

    if str(rule.get("type", "")) == "threat_match":
        lines += _section("Indicator match", _render_indicator_match(rule))

    lines += _section(
        "False positives",
        [_bullet(_prose(item)) for item in rule.get("false_positives", []) or []
         if _prose(item)],
    )
    lines += _section(
        "References",
        [f"- {ref}" for ref in _as_list(rule.get("references"))],
    )

    note = _prose(rule.get("note"))
    if note:
        cleaned, dropped = _DISCLAIMER.subn("", note)
        if dropped:
            held["disclaimer chars"] += len(note) - len(cleaned)
            held["disclaimers"] += dropped
        cleaned = _resolve_placeholders(cleaned.strip(), transform, held)
        lines += _section("Investigation guide", [cleaned])

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# documents
# ---------------------------------------------------------------------------

def _walk(root: Path) -> Iterator[tuple[Path, str]]:
    """Every regular ``.toml`` under ``root``, sorted, never through a symlink.

    ``os.walk(followlinks=False)`` rather than ``Path.rglob``: rglob follows
    directory symlinks, and an adapter in this package once followed one onto an
    external disk and copied 180 MB of the corpus cache back into the corpus.
    Symlinked *files* are skipped explicitly too, since ``followlinks`` only
    governs descent.
    """
    for directory, subdirs, files in os.walk(root, followlinks=False):
        subdirs.sort()
        base = Path(directory)
        for name in sorted(files):
            if not name.endswith(".toml"):
                continue
            path = base / name
            if path.is_symlink() or not path.is_file():
                continue
            yield path, path.relative_to(root).as_posix()


def _documents(path: Path) -> Iterator[Document]:
    """Yield one Document per rule, in a stable sorted order.

    Accepts either the ``detection-rules/`` directory :func:`_fetch` returns or
    the cache directory above it, so a caller that passes the cache root works.

    A file that fails to parse is skipped and counted rather than aborting the
    build — one malformed rule in a tree of two thousand should not cost the
    other 2,246 — but the count is printed, because a parse failure rate that
    starts climbing is the signal that upstream has moved to a schema this
    adapter no longer understands.
    """
    root = path / _CONTENT if (path / _CONTENT).is_dir() else path
    if not root.is_dir():
        raise SourceError(f"elastic: no content tree at {root}")

    held: Counter[str] = Counter()
    by_tree: Counter[str] = Counter()
    by_type: Counter[str] = Counter()
    by_language: Counter[str] = Counter()
    note_chars = 0
    total_chars = 0
    emitted = 0
    with_attack = 0

    for file, rel in _walk(root):
        try:
            data = tomllib.loads(file.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
            held["unparseable files"] += 1
            continue
        rule = data.get("rule")
        if not isinstance(rule, dict) or not rule.get("name"):
            # No [rule] table: a schema fragment or a config file that happens to
            # live in the tree, not a detection.
            held["not a rule"] += 1
            continue

        # Held-back accounting is measured on the source field, not on the
        # rendered text, so the number reported is what upstream actually
        # carried rather than what survived rendering.
        held["setup chars"] += len(str(rule.get("setup", "") or ""))

        text = normalise(_render(rel, data, held))
        if len(text) < _MIN_CHARS:
            held["too short"] += 1
            continue

        by_tree[rel.split("/", 1)[0]] += 1
        by_type[str(rule.get("type", "") or "?")] += 1
        if language := str(rule.get("language", "") or ""):
            by_language[language] += 1
        if rule.get("threat"):
            with_attack += 1
        note_chars += len(str(rule.get("note", "") or ""))
        total_chars += len(text)
        emitted += 1

        yield Document(
            text=text,
            source="elastic",
            register=Register.DETECTION,
            side=Side.BLUE,
            # Repo-relative path: unique, stable across fetches, and legible in
            # a build report ("rules/windows/defense_evasion_...").
            ident=rel,
        )

    _report(emitted, total_chars, note_chars, with_attack,
            by_tree, by_type, by_language, held)


def _report(emitted: int, total_chars: int, note_chars: int, with_attack: int,
            by_tree: Counter[str], by_type: Counter[str],
            by_language: Counter[str], held: Counter[str]) -> None:
    """Print what was kept, what was held back, and the one real skew.

    A holdback that is not printed is a silent edit to the corpus, and a
    concentration that is measured and then deliberately left alone had better
    say so out loud rather than be discovered later in a register report.
    """
    print(f"   elastic: {emitted:,} rules from "
          + ", ".join(f"{tree}/{count:,}" for tree, count in sorted(by_tree.items())))
    print("   elastic: types — "
          + ", ".join(f"{name} {count:,}" for name, count in by_type.most_common())
          + "; languages — "
          + ", ".join(f"{name} {count:,}" for name, count in by_language.most_common()))
    if emitted:
        print(f"   elastic: {with_attack:,}/{emitted:,} rules carry an ATT&CK "
              "mapping — technique id beside technique name, next to the query "
              "that detects it.")
    if total_chars:
        print(f"   elastic: investigation guides are {note_chars / total_chars:.0%} "
              "of this source's characters. Not capped: all 2,062 are distinct, "
              "and they are triage prose bound to the query it explains in the "
              "same document.")
    if held["setup chars"]:
        print(f"   elastic: held back {held['setup chars']:,} chars of `setup` — "
              "Kibana/Fleet onboarding instructions, generated and repetitive "
              "(one 2,069-char block appears 192 times), not detection logic.")
    if held["disclaimers"]:
        print(f"   elastic: stripped {held['disclaimers']:,} generative-AI "
              f"disclaimer blockquotes ({held['disclaimer chars']:,} chars) — the "
              "single most repeated string in the repository.")
    resolved = held["resolved $osquery"] + held["resolved $investigate"]
    if resolved:
        print(f"   elastic: resolved {resolved:,} $osquery/$investigate "
              "placeholders into the queries they reference.")
    unresolved = held["unresolved $osquery"] + held["unresolved $investigate"]
    if unresolved:
        print(f"   elastic: {unresolved:,} placeholder(s) pointed at no transform "
              "table and were left verbatim — upstream inconsistency, not a cap.")
    for key in ("unparseable files", "not a rule", "too short"):
        if held[key]:
            print(f"   elastic: skipped {held[key]:,} file(s) — {key}.")


_LICENSE = (
    "Elastic License 2.0 (Elastic-2.0). Copyright 2021 Elasticsearch B.V. "
    "Upstream LICENSE.txt and NOTICE.txt were read and are copied into the "
    "cache. The repository README states it without qualification: "
    "\"Everything in this repository — rules, code, etc. — is licensed under "
    "the Elastic License v2.\" Five rules derive from "
    "BlueTeamLabs/sentinel-attack under MIT and are sublicensed as Elastic v2; "
    "NOTICE.txt records that. Licence text: "
    "https://www.elastic.co/licensing/elastic-license"
)


SPEC = SourceSpec(
    name="elastic",
    license=_LICENSE,
    url=_REPO,
    register=Register.DETECTION,
    side=Side.BLUE,
    fetch=_fetch,
    documents=_documents,
    #: 2,247 rule files were present on ``main`` when this was written (2,118
    #: under rules/, 129 under rules_building_block/), and all 2,247 render. The
    #: floor sits well below that so ordinary churn and rule retirement are
    #: quiet, while a tree that stops being walked — the realistic regression —
    #: trips it immediately.
    expect_min_docs=1800,
    notes=(
        "One document per rule, rendered from TOML with the stdlib tomllib: "
        "name, description, the ATT&CK tactic/technique/sub-technique ids beside "
        "their names and URLs, the index patterns and schedule, the query "
        "verbatim with its language named (EQL, KQL, ES|QL, Lucene), the false "
        "positives, the references and the investigation guide. Machine-learning "
        "rules have no query and say so, keeping their job id and anomaly "
        "threshold. $osquery_N and $investigate_N placeholders are resolved into "
        "the osquery SQL and timeline field/value clauses they reference. Two "
        "holdbacks, both printed at build time: `setup` is dropped entirely "
        "(1.57 MB of generated Kibana/Fleet onboarding, 342 distinct blocks "
        "across 1,303 rules) and the generative-AI disclaimer blockquote is "
        "stripped from 1,011 investigation guides (317 KB, the most repeated "
        "string upstream). Investigation guides are otherwise kept whole — all "
        "2,062 are distinct — and are 55% of the source's characters, which is "
        "reported rather than capped. hunting/ is left out: standalone hunt "
        "queries are a different artefact, not a rule."
    ),
)
