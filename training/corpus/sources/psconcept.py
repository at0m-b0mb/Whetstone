"""PowerShell semantics: the language spec, the SDK reference, and the deep dives.

The owner's ask named PowerShell specifically, and
:mod:`~training.corpus.sources.psdocs` already carries the cmdlet reference —
2,439 pages of ``reference/<version>/<Module>/``. What it does **not** carry is
stated in its own docstring, as a deliberate exclusion:
``reference/docs-conceptual/`` is "the other thing — install guides, .NET
interop essays, release notes — prose that would be labelled SHELL by this spec
and would be a lie about the register."

That judgement is right about the register and leaves something large on the
table, because ``docs-conceptual/`` is not only install guides. It also holds:

* **``lang-spec/``** — the sixteen chapters of the *PowerShell Language
  Specification 3.0*. Lexical structure, type conversion, variable scoping,
  operator semantics, the grammar itself. Nothing else in this corpus states
  what the language *means*; ``psdocs`` lists parameters and
  :mod:`~training.corpus.sources.powershell` shows idiom, and neither is a
  specification.
* **``developer/``** — 450 pages of the cmdlet SDK reference, and this is the
  part that matters most for what Whetstone actually does. The Windows adapter
  answers thirty verbs by handing ``pwsh`` an argv list and **parsing what comes
  back**, so the pages that describe exactly that are
  ``cmdlet-output.md``, ``cmdlet-error-reporting.md``,
  ``adding-non-terminating-error-reporting-to-your-cmdlet.md``,
  ``cmdlet-parameter-sets.md``, ``confirmation-messages.md``,
  ``cmdlet-input-processing-methods.md``, the whole of ``ets/`` (the Extended
  Type System — how PowerShell decides what shape an object has) and the whole
  of ``format/`` (the formatting system — how that object becomes the text a
  parser will read). A model that knows ``Get-Acl`` returns an object with an
  ``Access`` collection of ``FileSystemAccessRule`` can parse it; one that has
  only seen one-liners cannot.
* **``learn/deep-dives/``** — ``everything-about-pscustomobject``,
  ``everything-about-shouldprocess``, ``everything-about-exceptions``,
  ``visualize-parameter-binding``. The ``-WhatIf``/``-Confirm`` semantics the
  task asked for, written by people explaining them rather than listing them.

**This is not ``psdocs`` again, and the disjointness is structural rather than
argued.** ``psdocs`` walks ``reference/<major>.<minor>/`` directories only;
this walks ``reference/docs-conceptual/<named tree>/`` only. The two sets cannot
intersect because a path cannot be both, and :func:`_wanted` refuses anything
whose first component under ``reference/`` parses as a version number — the
check is in the code rather than in this paragraph.

**Registers are per document, and two of them are measured rather than
declared.** ``psdocs`` was right that calling the whole tree SHELL would be a
lie. Calling it all PROSE is a smaller lie in the other direction, and the
measurement says how much smaller: the median share of a page's characters that
sit inside PowerShell-or-Output fences runs ``windows-powershell/`` 0.000,
``dev-cross-plat/`` 0.032, ``security/`` 0.088, ``learn/`` 0.197,
``samples/`` 0.368 — so most of this tree really is prose, and a minority of it
really is command text with commentary. This adapter therefore refines the
judgement per page instead of making it once for the tree, exactly as
:mod:`~training.corpus.sources.malwareanalysis` does for the radare2 book
("SHELL or PROSE per page, measured by how much of the page is command text"):

* ``lang-spec/`` and ``developer/`` are :class:`~training.corpus.source.Register.SYSTEM`.
  A language specification and an SDK reference are specification and API
  reference, which is what that register is for — the same call
  :mod:`~training.corpus.sources.rfc` makes. Counted rather than assumed,
  their fenced blocks are ``xml`` 326 (``format.ps1xml`` and ``types.ps1xml``),
  ``csharp`` 187, ``syntax`` 105 and ``vb`` 16 against ``powershell`` 237 —
  so PowerShell appears in them as illustration while the bulk is schema and
  SDK code, which is not something typed at a prompt.
* Every other kept page is measured: if at least
  :data:`_SHELL_FENCE_SHARE` of its characters sit inside fenced blocks tagged
  with a PowerShell dialect or ``Output``, it is
  :class:`~training.corpus.source.Register.SHELL`; otherwise
  :class:`~training.corpus.source.Register.PROSE`. The observed split is
  reported in the build manifest, so a drift in the ratio is visible rather
  than assumed.

``Output``-tagged fences are counted toward SHELL on purpose and are the single
most valuable thing in this tree: there are **383** of them (348 in the measured
trees, 35 in the SYSTEM ones), they are **real captured command output**, and
the ROADMAP says reading output is where this corpus is thinnest — plenty of
*usage* text and very little *output* text. ``samples/`` alone contributes the
pages a parser author would pick by hand: ``Viewing-Object-Structure--Get-Member-``,
``Using-Format-Commands-to-Change-Output-View``,
``Getting-WMI-Objects--Get-CimInstance-``, ``Working-with-Registry-Entries``.

**Excluded trees, each for a stated reason.** ``community/`` is the contributor
guide and a roll of community contributors by name and handle — that is
third-party personal data and it is not coming in. ``whats-new/`` is release
notes, which is changelog boilerplate; ``install/``, ``gallery/`` and ``dsc/``
are product and deployment instructions; the loose root pages
(``overview.md``, ``how-to-use-docs.md``, ``discover-powershell.md``) are site
navigation. Together that is the material ``psdocs`` was describing when it
called this tree install guides, and it stays out.

**Licence: CC BY 4.0 for the prose and MIT for the code samples**, the same
split ``psdocs`` records because it is the same repository and upstream
publishes the halves separately. ``LICENSE.md`` ("Attribution 4.0
International") and ``LICENSE-CODE.md`` ("The MIT License (MIT) / Copyright (c)
Microsoft Corporation") are both copied into the cache under ``licenses/``.

One trap from the sibling project belongs here because this is the module about
PowerShell text: **never use ``str.format`` on PowerShell.** A PowerShell script
block is written with ``{ }``, and ``str.format`` reads those as format fields —
``"Get-Process | ForEach-Object { $_.Name }".format(x=1)`` raises ``KeyError``
at best and silently rewrites the script at worst. Nothing in this module calls
``format`` on collected text; it is all f-strings over data this module built.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tarfile
import time
from collections.abc import Iterator
from pathlib import Path

from ..net import NetworkError, download
from ..source import (
    Document,
    Register,
    Side,
    SourceError,
    SourceSpec,
    fingerprint,
    normalise,
)
from ._thirdparty import count_emails, strip_emails

_NAME = "psconcept"

_TARBALL = (
    "https://codeload.github.com/MicrosoftDocs/PowerShell-Docs/tar.gz/refs/heads/main"
)

_MARKER = ".psconcept.json"
_CACHE_VERSION = 1

#: Measured on the run that produced this adapter's counts: the download was
#: **29,311,672 bytes (27.9 MB)** and the kept tree **3,781,760 bytes
#: (3.6 MB)** across 582 pages. The whole repository is ~120 MB
#: unpacked, most of it screenshots and the ``reference/<version>/`` trees that
#: ``psdocs`` already reads; nothing narrower than the branch tarball is
#: offered, and the two adapters each fetch their own copy rather than one
#: reading the other's cache, because a source that only works when a different
#: source ran first is a source that breaks under ``--only``.
_MAX_ARCHIVE_BYTES = 192 * 1024 * 1024

#: Per member. The largest page kept is ~90 KB.
_MAX_MEMBER_BYTES = 2 * 1024 * 1024

_CONCEPTUAL = "reference/docs-conceptual"

#: Trees collected, each named rather than globbed so that a directory upstream
#: adds is a decision somebody makes.
_KEEP_TREES = (
    "developer",          # 450 pages: the cmdlet SDK, ETS and the formatter
    "lang-spec",          # 16 chapters: PowerShell Language Specification 3.0
    "learn",              # PS101 and the deep dives
    "security",           # execution policy, JEA, signing, AMSI
    "samples",            # worked tasks, heavily fenced
    "dev-cross-plat",     # .NET interop, module authoring across platforms
    "windows-powershell", # the 5.1 generation's own conceptual pages
)

#: ``reference/5.1``, ``reference/7.7`` — a version tree. Matched only so this
#: adapter can *refuse* one: those belong to ``psdocs`` and overlapping them
#: would put the same page in the corpus twice under two source names, which
#: whole-document fingerprinting would catch only after both had been counted.
_VERSION_DIR = re.compile(r"\A\d+\.\d+\Z")

#: Named with their suffixes because that is what upstream ships, and the
#: first run of this adapter refused on ``found 0`` for exactly that reason:
#: the sibling repositories in this corpus carry a bare ``LICENSE`` and this
#: one does not.
_LICENCE_FILES = ("LICENSE.md", "LICENSE-CODE.md")

#: Trees deliberately not collected, kept as data so the exclusion is checkable
#: and so :func:`_fetch` can refuse if one of them ever shows up in the cache.
#: ``community`` is the privacy one: it is a contributor roll.
_DROP_TREES = ("community", "install", "gallery", "dsc", "whats-new")

#: Registers that are not negotiable per page, by tree. See the module
#: docstring: specification and SDK reference, whose fenced code is C# and
#: ``format.ps1xml`` rather than anything typed at a prompt.
_SYSTEM_TREES = frozenset({"developer", "lang-spec"})

#: The leading ``---`` frontmatter block, non-greedy so it ends at the first
#: closing fence rather than at a horizontal rule further down the page.
_FRONTMATTER = re.compile(r"\A---[ \t]*\n(?P<block>.*?)\n---[ \t]*\n", re.DOTALL)

#: A top-level frontmatter key. Loose enough for keys containing spaces, which
#: this repository uses.
_FM_KEY = re.compile(r"\A(?P<key>[A-Za-z][A-Za-z0-9 ._'-]*?)\s*:")

#: Frontmatter keys that carry content rather than publishing machinery. A
#: keep-list rather than a drop-list for the reason ``psdocs`` gives: every key
#: upstream adds in future is far more likely to be another build directive than
#: another piece of content.
_FM_KEEP = frozenset({"title", "description", "keywords"})

#: A fenced block and its language tag. Non-greedy, and the closing fence must
#: start a line, so a ``` inside a line of prose does not open a block.
_FENCE = re.compile(r"^```(?P<lang>[A-Za-z0-9_+-]*)[ \t]*\n(?P<body>.*?)^```",
                    re.DOTALL | re.MULTILINE)

#: Fence tags that mean "this is PowerShell, or PowerShell's output". ``Output``
#: is in the set and is the point: 376 blocks in this tree are real captured
#: command output, which the ROADMAP identifies as the thing the corpus has
#: least of. ``console`` and ``ps`` are the other spellings upstream uses.
_SHELL_FENCES = frozenset({
    "powershell", "ps", "ps1", "pwsh", "posh", "console", "output",
    "powershell-console", "cmd", "bash", "shell", "syntax",
})

#: Share of a page's characters that must sit inside PowerShell-or-Output fences
#: before the page is SHELL rather than PROSE.
#:
#: **This threshold sits on a continuum, not in a gap, and that is a measured
#: correction to what the first draft of this module claimed.** The draft
#: asserted the share was "strongly bimodal — tutorial prose under 0.25,
#: worked samples over 0.55, very little between", which is the comfortable
#: thing for a threshold to be true of, and it is false. Measured over the 116
#: pages this rule applies to (``learn/``, ``security/``, ``samples/``,
#: ``dev-cross-plat/``, ``windows-powershell/``)::
#:
#:     p10  0.000    p50  0.180    p75  0.368
#:     p25  0.008    p60  0.232    p90  0.475
#:
#: The distribution is continuous and left-heavy. **28 of 116 pages (24%) sit
#: within ±0.10 of this line**, so the SHELL/PROSE split from this tree is
#: genuinely sensitive to where the line is drawn, and anybody tuning it should
#: know that rather than discover it. At 0.40 the split is 22 SHELL to 94 PROSE.
#:
#: 0.40 is kept anyway, as a stated judgement rather than a discovered fact: a
#: page that is two-fifths captured command text is more useful to the SHELL
#: register than to PROSE, and SHELL is the corpus's largest gap while PROSE is
#: a small one. The number to watch is the reported split, not this constant.
_SHELL_FENCE_SHARE = 0.40

#: Shorter than this is a stub or a redirect placeholder. Matches the floor the
#: other Markdown adapters in this package use.
_MIN_CHARS = 300


def _wanted(relative: str) -> bool:
    """True for an archive member this source collects. Pure path shape.

    The version-directory refusal is the structural half of the disjointness
    claim in the module docstring. It can never fire on today's upstream — a
    path under ``docs-conceptual`` has ``docs-conceptual`` as its first
    component, not ``7.7`` — and it is here so that the claim survives an
    upstream that moves the conceptual tree.
    """
    if relative in _LICENCE_FILES:
        return True
    if not relative.endswith(".md"):
        return False
    parts = relative.split("/")
    if len(parts) < 2 or parts[0] != "reference":
        return False
    if _VERSION_DIR.match(parts[1]):
        return False      # psdocs' territory; see the module docstring.
    if not relative.startswith(_CONCEPTUAL + "/"):
        return False
    tree = parts[2] if len(parts) > 3 else ""
    return tree in _KEEP_TREES


def _extract(archive: Path, staging: Path) -> tuple[int, int]:
    """Unpack the kept pages and both licences. Returns ``(pages, licences)``.

    Members are written one at a time with every destination proved to resolve
    inside *staging*, because ``extractall``'s ``filter="data"`` only exists
    from Python 3.12 and this package targets 3.10.
    """
    staging.mkdir(parents=True, exist_ok=True)
    resolved = staging.resolve()
    pages = licences = 0
    try:
        with tarfile.open(archive, "r:gz") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                parts = member.name.split("/")[1:]   # drop PowerShell-Docs-<ref>/
                if not parts or any(p in ("", ".", "..") or os.path.isabs(p)
                                    for p in parts):
                    continue
                relative = "/".join(parts)
                if not _wanted(relative):
                    continue
                if member.size > _MAX_MEMBER_BYTES:
                    continue
                if relative in _LICENCE_FILES:
                    out = staging / "licenses" / relative
                    licences += 1
                else:
                    out = staging / "pages" / relative[len(_CONCEPTUAL) + 1:]
                    pages += 1
                target = out.resolve()
                if not target.is_relative_to(resolved):
                    continue
                handle = tar.extractfile(member)
                if handle is None:
                    continue
                out.parent.mkdir(parents=True, exist_ok=True)
                with handle, out.open("wb") as fh:
                    shutil.copyfileobj(handle, fh, 1 << 20)
    except (tarfile.TarError, OSError) as exc:
        raise SourceError(f"{_NAME}: could not unpack {archive}: {exc}") from exc

    if licences != len(_LICENCE_FILES):
        raise SourceError(
            f"{_NAME}: expected {len(_LICENCE_FILES)} licence files and found "
            f"{licences}. This source declares CC BY 4.0 for the prose and MIT "
            "for the code samples and keeps both upstream files on disk to back "
            "the declaration; an archive that has stopped shipping one needs a "
            "human to look, not a default."
        )
    if pages < 400:
        raise SourceError(
            f"{_NAME}: {_CONCEPTUAL}/ yielded only {pages} pages (expected at "
            f"least 400 across {', '.join(_KEEP_TREES)}). The conceptual tree "
            "has moved; fix the keep set rather than training on a fraction."
        )
    return pages, licences


def _scan_for_addresses(root: Path) -> int:
    """Count mail addresses in the extracted tree, before any stripping.

    ``os.walk(followlinks=False)``, never ``rglob``: a sibling adapter once
    followed a repository symlink into the SSD and pulled the corpus cache back
    in as its own register, and only the balance report noticed.
    """
    total = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames
                             if not Path(dirpath, d).is_symlink())
        for name in sorted(filenames):
            path = Path(dirpath, name)
            if path.is_symlink():
                continue
            try:
                total += count_emails(
                    path.read_text(encoding="utf-8-sig", errors="replace"))
            except OSError:
                continue
    return total


def _fetch(cache_dir: Path) -> Path:
    """Download the tarball and keep ``docs-conceptual``'s named trees.

    Network-free on re-run; the marker carries ``cache_version`` so a change to
    the keep set re-fetches rather than being read with the wrong parser. The
    archive is deleted as soon as it is unpacked.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    marker = cache_dir / _MARKER
    pages_dir = cache_dir / "pages"
    if marker.is_file() and pages_dir.is_dir():
        try:
            recorded = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            recorded = {}
        if recorded.get("cache_version") == _CACHE_VERSION:
            return cache_dir

    staging = cache_dir / ".staging"
    archive = cache_dir / ".powershell-docs.tar.gz.part"
    shutil.rmtree(staging, ignore_errors=True)
    try:
        try:
            download(_TARBALL, archive, timeout=900,
                     max_bytes=_MAX_ARCHIVE_BYTES)
        except NetworkError as exc:
            raise SourceError(f"{_NAME}: {exc}") from None
        archive_bytes = archive.stat().st_size
        digest = _sha256(archive)
        pages, _ = _extract(archive, staging)
        present = {p.name for p in (staging / "pages").iterdir() if p.is_dir()}
        leaked = sorted(present.intersection(_DROP_TREES))
        if leaked:
            raise SourceError(
                f"{_NAME}: {', '.join(leaked)} reached the cache. Those trees "
                "are excluded deliberately — community/ is a roll of "
                "contributors by name and handle — so a keep-set that admits "
                "one has a bug that must be fixed rather than tolerated."
            )
        addresses = _scan_for_addresses(staging / "pages")

        for name in ("pages", "licenses"):
            shutil.rmtree(cache_dir / name, ignore_errors=True)
        (staging / "pages").replace(cache_dir / "pages")
        (staging / "licenses").replace(cache_dir / "licenses")

        marker.write_text(json.dumps({
            "cache_version": _CACHE_VERSION,
            "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "url": _TARBALL,
            # Observed, not verified: codeload publishes no digest for a branch
            # tarball. Records which snapshot the cache holds, nothing more.
            "archive_sha256_observed": digest,
            "archive_bytes": archive_bytes,
            "kept_bytes": _tree_bytes(cache_dir / "pages"),
            "pages": pages,
            "trees": list(_KEEP_TREES),
            # A count. No value is ever written here.
            "third_party_addresses_in_kept_tree": addresses,
        }, indent=2), encoding="utf-8")
    finally:
        archive.unlink(missing_ok=True)
        shutil.rmtree(staging, ignore_errors=True)
    return cache_dir


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tree_bytes(root: Path) -> int:
    total = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames
                             if not Path(dirpath, d).is_symlink())
        for name in filenames:
            path = Path(dirpath, name)
            if not path.is_symlink():
                try:
                    total += path.stat().st_size
                except OSError:
                    pass
    return total


def _strip_metadata(text: str) -> str:
    """Drop publishing metadata from the frontmatter and keep the content keys.

    Line-based, never ``yaml.safe_load``, for the reason ``psdocs`` found the
    hard way: this repository's frontmatter contains values PyYAML refuses to
    scan, and a parser that raises on one page loses that page's content
    entirely. A continuation line inherits the keep/drop decision of the key
    above it.
    """
    match = _FRONTMATTER.match(text)
    if match is None:
        return text
    kept: list[str] = []
    keeping = False
    for line in match.group("block").split("\n"):
        key = _FM_KEY.match(line)
        if key is not None:
            keeping = key.group("key").strip().casefold() in _FM_KEEP
        elif not line.strip():
            continue
        if keeping:
            kept.append(line)
    body = text[match.end():]
    if not kept:
        return body
    return "---\n" + "\n".join(kept) + "\n---\n" + body


def fence_share(text: str) -> float:
    """Fraction of *text* inside fenced blocks tagged as PowerShell or Output.

    A pure function, exported without an underscore, because it is the one
    judgement in this adapter that decides a register and a judgement that
    decides a register should be testable without a network fetch.

    Counts the fence bodies only, not the fence markers, so a page of many tiny
    blocks is not scored higher than its content justifies. Untagged fences do
    **not** count: in this tree an untagged fence is usually a file listing or a
    directory tree, and crediting them to SHELL would be the misreport
    ``psdocs`` warned about.
    """
    if not text:
        return 0.0
    inside = 0
    for match in _FENCE.finditer(text):
        if match.group("lang").casefold() in _SHELL_FENCES:
            inside += len(match.group("body"))
    return inside / len(text)


def _register_for(tree: str, text: str) -> Register:
    """SYSTEM by tree, otherwise SHELL or PROSE by measurement."""
    if tree in _SYSTEM_TREES:
        return Register.SYSTEM
    if fence_share(text) >= _SHELL_FENCE_SHARE:
        return Register.SHELL
    return Register.PROSE


def _documents(path: Path) -> Iterator[Document]:
    """One document per kept conceptual page, fenced code intact.

    Exact duplicates are dropped here with the same fingerprint the build uses,
    so the count this source reports is the count it contributes rather than a
    number that gets quietly reduced downstream.
    """
    pages = path / "pages"
    if not pages.is_dir():
        raise SourceError(f"{_NAME}: no pages/ under {path}; re-fetch")

    seen: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(pages, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames
                             if not Path(dirpath, d).is_symlink())
        for name in sorted(filenames):
            if not name.endswith(".md"):
                continue
            page = Path(dirpath, name)
            if page.is_symlink():
                continue
            try:
                # utf-8-sig: a minority of these files carry a BOM, and a stray
                # U+FEFF at the head of a document is a token the model would
                # learn to expect before every heading.
                raw = page.read_text(encoding="utf-8-sig", errors="replace")
            except OSError:
                continue
            relative = page.relative_to(pages).as_posix()
            tree = relative.split("/", 1)[0]
            body, _ = strip_emails(_strip_metadata(raw.replace("\r\n", "\n")))
            text = normalise(body)
            if len(text) < _MIN_CHARS:
                continue
            key = fingerprint(text)
            if key in seen:
                continue
            seen.add(key)
            yield Document(text=text, source=_NAME,
                           register=_register_for(tree, text),
                           side=Side.NEUTRAL, ident=relative)


SPEC = SourceSpec(
    name=_NAME,
    license=(
        "CC BY 4.0 (documentation prose) and MIT (code samples) — Microsoft "
        "Corporation. Read from the repository's own files rather than from a "
        "badge: LICENSE.md is the Creative Commons 'Attribution 4.0 "
        "International' legal code and LICENSE-CODE.md is 'The MIT License (MIT) "
        "/ Copyright (c) Microsoft Corporation'. Both are copied into the "
        "cache under licenses/ beside the text they cover, and fetch FAILS if "
        "either is missing from the archive. The same split psdocs records, "
        "because it is the same repository and upstream publishes the halves "
        "separately. Attribution is required and satisfied by this entry plus "
        "the per-document upstream path in ident. "
        "Source: https://github.com/MicrosoftDocs/PowerShell-Docs/blob/main/LICENSE.md"
    ),
    url="https://github.com/MicrosoftDocs/PowerShell-Docs",
    register=Register.SYSTEM,
    side=Side.NEUTRAL,
    fetch=_fetch,
    documents=_documents,
    expect_min_docs=400,
    notes=(
        "reference/docs-conceptual/, which psdocs excludes by name and for a "
        "good reason — it is not cmdlet reference and labelling the tree SHELL "
        "would misreport the register. The two sources are structurally "
        "disjoint: psdocs walks reference/<major>.<minor>/ only, this walks "
        "reference/docs-conceptual/<named tree>/ only, and _wanted refuses any "
        "path whose first component under reference/ parses as a version. What "
        "that leaves is the PowerShell semantics layer the corpus had none of: "
        "the sixteen chapters of the PowerShell Language Specification 3.0 "
        "(lang-spec/), the 450-page cmdlet SDK reference (developer/) including "
        "cmdlet-output, cmdlet-error-reporting, parameter sets, confirmation "
        "messages, the Extended Type System and the formatting system — which "
        "is precisely what the Windows adapter's parsers have to read — and the "
        "learn/deep-dives essays on PSCustomObject, ShouldProcess, exceptions "
        "and parameter binding. Registers are per document and two of the three "
        "are MEASURED, not declared: lang-spec/ and developer/ are SYSTEM "
        "(specification and API reference, the rfc call), and every other page "
        "is SHELL if at least 40% of its characters sit inside fences tagged "
        "with a PowerShell dialect or Output, else PROSE. That threshold is a "
        "stated judgement and not a discovered fact: the first draft of this "
        "adapter claimed the share was bimodal with a gap to put a line in, and "
        "measuring it said otherwise — p25 0.008, p50 0.180, p75 0.368, p90 "
        "0.475 over the 116 pages the rule applies to, continuous and "
        "left-heavy, with 24% of pages within 0.10 of the line. The split is "
        "therefore sensitive to the threshold (22 SHELL to 94 PROSE at 0.40) "
        "and the number to watch is the reported split rather than the "
        "constant. "
        "Output-tagged fences count toward SHELL deliberately: there are 383 of "
        "them across the kept trees and they are real captured command output, "
        "which the ROADMAP "
        "names as the thing this corpus has least of. Excluded with reasons: "
        "community/ is a roll of contributors by name and handle and is "
        "third-party personal data (fetch FAILS if it ever reaches the cache), "
        "whats-new/ is release-note boilerplate, install/ gallery/ dsc/ are "
        "deployment instructions, and the loose root pages are site navigation. "
        "Frontmatter is filtered line-by-line and never parsed as YAML, for the "
        "reason psdocs gives. Mail addresses are stripped and counted. Each "
        "adapter fetches its own tarball rather than reading the other's cache: "
        "a source that only works when another source ran first breaks under "
        "--only."
    ),
)
