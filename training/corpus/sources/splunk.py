"""Splunk security_content — the DETECTION register's concrete surface form.

Sigma is already in this corpus, and Sigma is *abstract*: a rule says
``Image|endswith: '\\7z.exe'`` and a backend turns that into whatever the SIEM
speaks. Nobody types Sigma into a search bar. What a defender actually types is
this::

    | tstats `security_content_summariesonly` count min(_time) as firstTime
      from datamodel=Endpoint.Processes where Processes.process_name="7z.exe"
      by Processes.dest Processes.user | `drop_dm_object_name(Processes)`

Splunk's security_content repository is two thousand of those, and it is the
complement Sigma cannot be. The two sources share a topic and share almost no
surface form, which is precisely the distinction :class:`Register` was invented
to make. A model that has only met Sigma has met *descriptions* of detections;
this source is the query language itself — leading pipes, backtick macros,
``datamodel=`` references, ``tstats``/``stats``/``eval``/``rename``, the CIM
field namespace (``Processes.parent_process_name``, ``All_Risk.risk_object``),
``$token$`` drilldown interpolation and the ``_filter`` macro every analytic
ends on.

It also brings three things Sigma does not carry at all:

* **Risk scoring.** ``finding:``/``threat_objects:`` blocks with entity fields
  and numeric scores — the vocabulary of risk-based alerting.
* **``how_to_implement`` prose glued to the query it implements.** Detection
  rationale and detection code in the same document, a binding that a rule file
  alone never provides.
* **``data_sources/``**, which is a log-schema dictionary: per sourcetype, the
  full field list and a verbatim ``example_log`` — raw Windows Event XML, raw
  syslog. That is the exact material the first tokenizer measurement was
  starved of, delivered next to the searches that consume it.

**Licence.** Apache-2.0. The upstream ``LICENSE`` file was read, not guessed: it
is the standard 201-line Apache License 2.0 text, and it is copied into the
cache directory by :func:`_fetch` so the claim stays checkable offline.

**The SPL is kept verbatim, and so is the YAML around it.** No reflowing, no
re-serialising through PyYAML (which would reorder keys, re-quote scalars and
re-indent block scalars), no whitespace collapsing. ``normalise()`` from the
shared contract does the only cleaning, and it preserves horizontal whitespace
on purpose: an SPL search written as an indented pipeline loses its shape the
moment a cleaner touches it, and the shape is half of what the model is here to
learn.

**On markup (rule 6, measured rather than assumed).** This source contains
*zero* HTML — the only two matches for an HTML tag name are one ``<img...>``
literal inside an SPL comment. It does contain 5,701 angle-bracketed tokens
(1,110 distinct) and 45 entity references — ``&gt;`` x20, ``&amp;`` x16,
``&lt;`` x8, ``&#151;`` x1. Every kind was inspected and every one is real tool
output, a real query literal, or a regex:

* 4,974 of the angle tokens are Windows Event XML — ``<Data Name='...'>``,
  ``<TimeCreated ...>``, ``</System>`` — inside ``data_sources`` ``example_log``
  samples, i.e. verbatim log lines.
* Most of the remaining 727 are **named capture groups in SPL ``rex``
  commands**: ``rex field=Message "The (?<service>[-\\(\\)\\s\\w]+) service
  entered the (?<state>\\w+) state"``. A markup stripper would eat the group
  names and leave a regex that no longer compiles.
* The entities are inside SPL string literals such as
  ``TaskContent = "*&lt;Hidden&gt;true&lt;/Hidden&gt;*"``, which match the
  *escaped* XML Splunk actually indexes from Event 4698.

Unescaping or stripping would silently break the searches. So nothing is
stripped here, and that is a finding, not an omission.

**Two caps, both printed at build time.** See :data:`_BLOCK_QUOTA` and
:data:`_CSV_MAX_ROWS`, and :func:`_documents` for the report.
"""

from __future__ import annotations

import json
import os
import re
import tarfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

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

_REPO = "https://github.com/splunk/security_content"
#: ``develop`` is the repository's default branch — ``main`` does not exist
#: upstream, and a fetch against it would 404 rather than quietly return stale
#: content.
_REF = "develop"
#: codeload serves a branch tarball in one request: 15 MB, no git binary, no
#: history, and nothing a later ``git pull`` could mutate under a build.
_TARBALL = f"https://codeload.github.com/splunk/security_content/tar.gz/refs/heads/{_REF}"

#: Written last and only on success, so a half-extracted cache re-fetches
#: instead of being mistaken for a complete one.
_MARKER = ".fetched.json"

#: Trees kept, as prefixes of the repo-relative path.
#:
#: ``detections/`` is the point of the source (2,169 analytics). ``removed/``
#: holds 360 more — detections, baselines and investigations retired from the
#: shipping app, once its 17 stories are excluded by ``_SKIPPED_TREES`` —
#: whose SPL is no less real; their ids do not collide with the
#: live tree (checked: zero overlap), so they are volume with no duplication.
#: ``baselines/`` are supporting searches, ``macros/`` define the backticked
#: names every analytic calls, ``data_sources/`` is the log-schema dictionary
#: and ``lookups/`` the tables the searches join against.
_YAML_TREES: tuple[str, ...] = (
    "detections/",
    "removed/",
    "baselines/",
    "data_sources/",
    "macros/",
    "lookups/",
)

#: Trees deliberately left on the floor, and why.
#:
#: ``stories/`` (and ``removed/stories/``) are 371 files of campaign
#: *narrative* — description and narrative paragraphs, references, CVE ids. Good
#: text, wrong register: a story is PROSE wearing the same YAML skeleton as a
#: detection, and this source is declared DETECTION. ``build.py`` aggregates
#: coverage by the *source's* register, so smuggling 0.8 MB of prose in here
#: would make the one report that matters overstate the detection register by
#: that much. Every other adapter in this package yields exactly its declared
#: register and so does this one. Feeding stories to the PROSE register is a
#: separate, honest source if that register ever needs it.
#:
#: ``deprecated/`` is a MITRE mapping notebook and a copy of the YAML spec;
#: ``playbooks/``, ``dashboards/``, ``app_template/``, ``schemas/`` and
#: ``docs/`` are Phantom Python, JSON and PNGs — app plumbing, not detection.
_SKIPPED_TREES: tuple[str, ...] = ("stories/", "removed/stories/", "deprecated/")

#: Lookup CSVs are included, because the shape of a Splunk lookup table (its
#: header row, its real values) is detection vocabulary — but only down to this
#: many data rows each. One file, ``dynamic_dns_providers_default.csv``, is
#: 2.1 MB of ``*.0-1-2-3-...-18.com, True`` and would be 57% of everything the
#: lookups tree contributes: exactly the manpages-Perl failure, a single
#: sub-topic eating the source. Capping by rows keeps all 74 tables' *schemas*
#: and a sample of each, and holds back the flood. The count is printed.
_CSV_MAX_ROWS = 200

#: A top-level YAML block that is at least this long and has already appeared
#: verbatim this many times is dropped from further documents.
#:
#: Measured on the live tree: 35% of all detection characters sit in long lines
#: that repeat. Almost all of it is two generated blocks — the
#: ``drilldown_searches:`` risk-lookup template (17.2% of detection characters,
#: one 819-char block alone appearing 717 times) and the boilerplate EDR
#: ``how_to_implement:`` paragraph (563 identical copies). contentctl writes
#: those; no analyst does. Whole-document fingerprinting cannot see them because
#: the documents around them differ.
#:
#: The rule is deliberately about *repetition*, not about those two key names:
#: any block over the length floor that repeats past the quota goes, and on the
#: current tree exactly 8 distinct blocks qualify. The length floor is what
#: protects the schema — ``product:``, ``category:``, ``security_domain:``
#: repeat two thousand times each and are the YAML skeleton the model must
#: learn, so short blocks are never touched.
#:
#: **No unique text is lost.** Every distinct block still appears, up to 50
#: times; only the 51st identical copy is dropped. 50 exposures is ample for a
#: form, and the alternative is a model that has memorised one drilldown
#: paragraph 717 times. Verified by replay on the live tree: 1,771 copies
#: totalling 1,394,044 chars are dropped, and all 187 distinct
#: ``drilldown_searches`` blocks and all 860 distinct ``how_to_implement``
#: blocks are still present verbatim in the emitted corpus — zero distinct
#: blocks disappear entirely.
_BLOCK_QUOTA = 50
_BLOCK_MIN_CHARS = 300

#: A top-level mapping key at column 0. These files are yamlfmt-formatted, so
#: every continuation line of a block scalar or a wrapped quoted scalar is
#: indented — verified against ``yaml.safe_load`` on all 2,169 detections, where
#: this splitter recovered the exact key list, in order, for every file.
_TOP_KEY = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*):")

#: Below this, a file is a stub or a truncation, not content.
_MIN_CHARS = 120

#: Upstream had 2,169 detection files when this was written. A floor far below
#: that turns a renamed directory into a loud fetch failure rather than a
#: mysteriously thin build report.
_MIN_DETECTIONS = 1200


def _relative(member_name: str) -> str | None:
    """Repo-relative path for a tar member, or ``None`` if it is not safe.

    Tar member names are attacker-controlled data in the general case: absolute
    paths, ``..`` segments and symlinks are all expressible. Rather than trust
    ``TarFile.extractall`` (whose safe ``filter="data"`` is 3.12+ only), the
    archive's single root component is dropped and anything that could escape is
    refused here, before a path ever reaches the filesystem.
    """
    parts = Path(member_name).parts
    if len(parts) < 2:
        return None
    relative = Path(*parts[1:])
    if relative.is_absolute() or ".." in relative.parts:
        return None
    return relative.as_posix()


def _wanted(rel: str) -> bool:
    """True for a path this source collects."""
    if any(rel.startswith(tree) for tree in _SKIPPED_TREES):
        return False
    if rel.endswith(".yml"):
        return any(rel.startswith(tree) for tree in _YAML_TREES)
    if rel.endswith(".csv"):
        return rel.startswith("lookups/csv/")
    return False


def _fetch(cache_dir: Path) -> Path:
    """Populate ``cache_dir`` with the trees this source reads. Idempotent.

    A populated cache short-circuits before any network access: the marker file
    is written only after the staged tree has been swapped into place, so an
    interrupted run is retried rather than mistaken for a complete one. The
    download itself goes through :func:`training.corpus.net.download`, which is
    the project's one source of verified TLS and already writes via a ``.part``
    sibling — three adapters once grew private trust-store helpers and one
    private copy is all it takes for a late-night ``CERT_NONE`` to ship.

    Nothing is written outside ``cache_dir``, and the 15 MB tarball is deleted
    once unpacked.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    marker = cache_dir / _MARKER
    content = cache_dir / "content"
    if marker.is_file() and content.is_dir():
        return content

    archive = cache_dir / ".security_content.tar.gz"
    staging = cache_dir / ".staging"
    _rmtree(staging)

    kept: Counter[str] = Counter()
    skipped_files: Counter[str] = Counter()
    skipped_bytes: Counter[str] = Counter()
    try:
        try:
            net.download(_TARBALL, archive, timeout=600)
        except net.NetworkError as exc:
            raise SourceError(f"splunk: {exc}") from exc

        staging.mkdir(parents=True, exist_ok=True)
        resolved = staging.resolve()
        try:
            with tarfile.open(archive, mode="r|gz") as tar:
                for member in tar:
                    # isfile() also excludes symlinks and hardlinks, so no link
                    # ever enters the cache and the later os.walk cannot be led
                    # anywhere by one.
                    if not member.isfile():
                        continue
                    rel = _relative(member.name)
                    if rel is None:
                        continue
                    if rel == "LICENSE":
                        stream = tar.extractfile(member)
                        if stream is not None:
                            (cache_dir / "LICENSE").write_bytes(stream.read())
                        continue
                    # Count what the tree offered and we declined, without
                    # spending the bytes to extract it — the holdback report
                    # should be honest about content that never arrived too.
                    for tree in _SKIPPED_TREES:
                        if rel.startswith(tree) and rel.endswith((".yml", ".yaml")):
                            skipped_files[tree] += 1
                            skipped_bytes[tree] += member.size
                            break
                    if not _wanted(rel):
                        continue
                    target = staging / rel
                    if not target.resolve().is_relative_to(resolved):
                        continue
                    stream = tar.extractfile(member)
                    if stream is None:
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(stream.read())
                    kept[rel.split("/", 1)[0]] += 1
        except tarfile.TarError as exc:
            raise SourceError(
                f"splunk: malformed tarball from {_TARBALL}: {exc}"
            ) from exc

        if kept.get("detections", 0) < _MIN_DETECTIONS:
            raise SourceError(
                f"splunk: only {kept.get('detections', 0)} files under detections/ "
                f"in {_TARBALL} (expected >= {_MIN_DETECTIONS}). The upstream "
                "layout has probably changed; fix the adapter rather than "
                "training on a fraction of the detection register."
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
                    "held_back_trees": {
                        tree: {
                            "files": skipped_files[tree],
                            "bytes": skipped_bytes[tree],
                        }
                        for tree in _SKIPPED_TREES
                        if skipped_files[tree]
                    },
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    finally:
        archive.unlink(missing_ok=True)
        (cache_dir / ".security_content.tar.gz.part").unlink(missing_ok=True)
        _rmtree(staging)
    return content


def _rmtree(path: Path) -> None:
    """Remove a directory tree if present, without importing shutil for one call."""
    if not path.exists():
        return
    import shutil

    shutil.rmtree(path, ignore_errors=True)


def _split_blocks(raw: str) -> list[tuple[str, str]]:
    """Partition a yamlfmt-formatted file into ``(key, text)`` top-level blocks.

    Line-based rather than YAML-based on purpose: round-tripping through PyYAML
    would reorder keys, re-quote scalars and re-indent block scalars, which is
    the one thing this source must not do. ``"\\n".join(text for _, text in
    blocks) == raw`` exactly, and the invariant is asserted on every file in
    :func:`_documents` so a formatting change upstream cannot silently corrupt a
    document.

    Anything before the first top-level key (a leading comment, a ``---``) is
    returned under the empty key and is never subject to the repetition cap.
    """
    blocks: list[tuple[str, str]] = []
    key: str = ""
    buffer: list[str] = []
    for line in raw.split("\n"):
        match = _TOP_KEY.match(line)
        if match:
            if buffer or key:
                blocks.append((key, "\n".join(buffer)))
            key = match.group(1)
            buffer = [line]
        else:
            buffer.append(line)
    if buffer or key:
        blocks.append((key, "\n".join(buffer)))
    return blocks


def _cap_repeats(raw: str, rel: str, seen: Counter[tuple[str, str]],
                 held: Counter[str]) -> str:
    """Drop long top-level blocks already emitted :data:`_BLOCK_QUOTA` times.

    ``seen`` and ``held`` are carried across the whole source so the quota is
    global, not per file. The result is still valid YAML — a key is absent, not
    truncated — and every distinct block survives up to the quota.
    """
    blocks = _split_blocks(raw)
    # Not an assert: `python -O` strips asserts, and this is the invariant that
    # stands between an upstream formatting change and a corpus of silently
    # truncated YAML. It has to survive optimisation.
    if "\n".join(text for _, text in blocks) != raw:
        raise SourceError(
            f"splunk: the top-level block splitter is lossy on {rel}. Upstream "
            "formatting has changed (a top-level key now appears inside a block "
            "scalar, or a line ending survived normalisation). Fix the splitter "
            "rather than emitting truncated documents."
        )

    out: list[str] = []
    for key, text in blocks:
        if key and len(text) >= _BLOCK_MIN_CHARS:
            seen[(key, text)] += 1
            if seen[(key, text)] > _BLOCK_QUOTA:
                held[key] += len(text)
                continue
        out.append(text)
    return "\n".join(out)


def _csv_document(path: Path, rel: str, held: Counter[str]) -> str | None:
    """Header plus at most :data:`_CSV_MAX_ROWS` rows of a lookup table.

    The lookup's filename is restated on the first line. Without it a table of
    bare domains has nothing tying it to the ``| lookup remote_access_software``
    that references it, and that binding is the whole reason a lookup is worth
    collecting — the same argument the atomic adapter makes for restating a
    technique id above every command.
    """
    # utf-8-sig, not utf-8: six of these tables ship a UTF-8 BOM, and a BOM is
    # not a control byte, so normalise() leaves it in place — landing a stray
    # U+FEFF on the header line of six documents. It decodes plain UTF-8
    # identically, so this costs nothing on the other sixty-eight tables.
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError):
        return None
    lines = text.split("\n")
    if not lines:
        return None
    body = [line for line in lines[1:] if line.strip()]
    if len(body) > _CSV_MAX_ROWS:
        held["lookup rows"] += len(body) - _CSV_MAX_ROWS
        held["lookup chars"] += sum(len(line) + 1 for line in body[_CSV_MAX_ROWS:])
        body = body[:_CSV_MAX_ROWS]
    name = rel.rsplit("/", 1)[-1]
    return "\n".join([f"lookup: {name}", lines[0], *body])


def _walk(root: Path) -> Iterator[tuple[Path, str]]:
    """Every regular file under ``root``, sorted, never through a symlink.

    ``os.walk(followlinks=False)`` rather than ``Path.rglob``: rglob follows
    directory symlinks, and an adapter that did exactly that once followed a
    ``data`` symlink onto an external disk and copied 180 MB of the corpus cache
    back into the corpus. Individual symlinked *files* are skipped explicitly as
    well, since ``followlinks`` only governs descent.
    """
    for directory, subdirs, files in os.walk(root, followlinks=False):
        subdirs.sort()
        base = Path(directory)
        for name in sorted(files):
            path = base / name
            if path.is_symlink() or not path.is_file():
                continue
            yield path, path.relative_to(root).as_posix()


def _documents(path: Path) -> Iterator[Document]:
    """Yield one Document per content file, in a stable sorted order.

    Accepts either the ``content/`` directory :func:`_fetch` returns or the cache
    directory above it, so a caller that passes the cache root still works.

    The holdback report is printed after the last document: what the caps
    removed, what was never extracted, and the sub-topic concentration that was
    measured but deliberately *not* capped.
    """
    root = path / "content" if (path / "content").is_dir() else path
    if not root.is_dir():
        raise SourceError(f"splunk: no content tree at {root}")

    seen: Counter[tuple[str, str]] = Counter()
    held: Counter[str] = Counter()
    by_tree: Counter[str] = Counter()
    by_category: Counter[str] = Counter()
    chars_by_category: Counter[str] = Counter()
    emitted = 0

    for file, rel in _walk(root):
        if rel.endswith(".csv"):
            body = _csv_document(file, rel, held)
        elif rel.endswith(".yml"):
            try:
                raw = file.read_text(encoding="utf-8-sig")
            except (OSError, UnicodeDecodeError):
                continue
            body = _cap_repeats(raw, rel, seen, held)
        else:
            continue
        if body is None:
            continue

        text = normalise(body)
        if len(text) < _MIN_CHARS:
            held["short files"] += 1
            continue

        by_tree[rel.split("/", 1)[0]] += 1
        if rel.startswith("detections/"):
            parts = rel.split("/")
            by_category[parts[1]] += 1
            chars_by_category[parts[1]] += len(text)
        emitted += 1
        yield Document(
            text=text,
            source="splunk",
            register=Register.DETECTION,
            side=Side.BLUE,
            # Repo-relative path: unique, stable across fetches, and legible in
            # a build report ("detections/endpoint/...").
            ident=rel,
        )

    _report(root, emitted, by_tree, by_category, chars_by_category, seen, held)


def _report(root: Path, emitted: int, by_tree: Counter[str],
            by_category: Counter[str], chars_by_category: Counter[str],
            seen: Counter[tuple[str, str]], held: Counter[str]) -> None:
    """Print what was kept, what was capped, and what was only observed.

    A cap that is not printed is a silent edit to the corpus, and a
    concentration that is measured and left alone had better say so out loud.
    """
    print(f"   splunk: {emitted:,} docs from "
          + ", ".join(f"{tree}/{count:,}" for tree, count in sorted(by_tree.items())))

    over = [(key, text) for (key, text), count in seen.items() if count > _BLOCK_QUOTA]
    if over:
        detail = ", ".join(
            f"{key} x{count}" for key, count in sorted(Counter(k for k, _ in over).items())
        )
        capped = sum(v for k, v in held.items() if k not in {"lookup rows", "lookup chars", "short files"})
        print(f"   splunk: held back {capped:,} chars of repeated boilerplate "
              f"({len(over)} distinct blocks past {_BLOCK_QUOTA} copies: {detail}). "
              "No unique text dropped — every block still appears up to the quota.")
    if held["lookup rows"]:
        print(f"   splunk: held back {held['lookup rows']:,} lookup-CSV rows "
              f"({held['lookup chars']:,} chars) past {_CSV_MAX_ROWS} rows per table; "
              "one dynamic-DNS table was 57% of that tree on its own.")
    if held["short files"]:
        # This counter existed and was never printed, which is precisely the
        # silent edit the rest of this report is written to avoid. On the live
        # tree it is 13 lookup CSVs that ship a header row and no data.
        print(f"   splunk: dropped {held['short files']} files under {_MIN_CHARS} "
              "chars — empty lookup tables (header row, no rows).")

    marker = root.parent / _MARKER
    try:
        skipped = json.loads(marker.read_text(encoding="utf-8")).get("held_back_trees", {})
    except (OSError, ValueError):
        skipped = {}
    if skipped:
        detail = ", ".join(
            f"{tree} {info['files']} files / {info['bytes']:,} bytes"
            for tree, info in sorted(skipped.items())
        )
        print(f"   splunk: never extracted {detail} — prose register, not detection.")

    total = sum(chars_by_category.values())
    if total:
        share = ", ".join(
            f"{cat} {chars_by_category[cat] / total:.0%}"
            for cat, _ in chars_by_category.most_common(3)
        )
        print(f"   splunk: detection mix by chars — {share}. endpoint dominates and is "
              "NOT capped: those are distinct hand-written searches, not boilerplate, "
              "and the repeated-block cap above already removes the generated part.")


SPEC = SourceSpec(
    name="splunk",
    license="Apache-2.0 (Splunk Inc.; upstream LICENSE read and copied into the cache)",
    url=_REPO,
    register=Register.DETECTION,
    side=Side.BLUE,
    fetch=_fetch,
    documents=_documents,
    #: 3,317 files were collected on ``develop`` at the time of writing
    #: (2,169 detections, 360 removed, 315 data sources, 255 macros, 103 lookup
    #: definitions, 74 lookup tables, 41 baselines), yielding 3,304 documents —
    #: the 13 missing ones are lookup tables that are a header row and nothing
    #: else. The floor sits well below that so ordinary churn is quiet, while a
    #: tree that stops being walked — the realistic regression — trips it
    #: immediately.
    expect_min_docs=2800,
    notes=(
        "Raw YAML per file, verbatim: the SPL in `search:` keeps its leading "
        "pipes, backtick macros, datamodel references and CIM field names, and "
        "normalise() preserves the indentation that gives a multi-line search "
        "its shape. detections/, removed/, baselines/, data_sources/, macros/ "
        "and lookups/ are collected; stories/ and removed/stories/ are not, "
        "because they are campaign prose in a detection-shaped file and this "
        "source is declared DETECTION. Two caps, both printed at build time: "
        "an identical top-level block over 300 chars is dropped past 50 copies "
        "(the generated drilldown_searches and how_to_implement boilerplate, "
        "~12% of the source, no unique text lost), and lookup CSVs are cut to "
        "200 rows each so one 2.1 MB dynamic-DNS table cannot dominate. "
        "Nothing is unescaped: the &lt;/&gt; in these searches match the "
        "escaped XML Splunk indexes from Windows Event 4698."
    ),
)
