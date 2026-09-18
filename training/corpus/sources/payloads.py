"""PayloadsAllTheThings — what an operator actually does next. ADVERSARY/RED.

ADVERSARY is the scarcest register in this corpus and the project is weighted
roughly 60/40 toward offence on purpose: the red half exists to sharpen the
defensive half, and it is the half retrieval cannot supply. A defender's
knowledge is highly retrievable — a Sigma rule, a log schema, a control
catalogue are all lookups. Red judgement is a *sequence*: try this, read what
came back, and let what came back choose the next thing to try.

This repository is the closest thing that exists to a written record of that
sequence. CWE says a weakness class exists. ATT&CK names a behaviour. CAPEC
walks an attack in the abstract. PayloadsAllTheThings says: send
``' OR '1'='1``; if the error mentions ``ORA-01756`` you are on Oracle, so use
``||`` to concatenate and ``UTL_HTTP.request`` to exfiltrate; if the response
length changed but the body did not, you are blind, so move to a time-based
probe. The ordering and the conditionals are the content. A static taxonomy
cannot contain them because a taxonomy has no next step.

**What this source is made of, measured rather than assumed.** 142 markdown
files, 1.07 MB, of which **24.7% of all characters sit inside 1,228 fenced code
blocks**. The info strings say what the register is: ``powershell`` (232 blocks),
``ps1`` (202), ``sql`` (164), ``javascript`` (113), ``js`` (75), ``xml`` (71),
``html`` (63), ``python`` (60), ``php`` (57), ``json`` (33), ``java`` (32),
``bash`` (21). A quarter of this source is executable text with a heading above
it explaining when to reach for it, which is exactly the shape the corpus
measurement in :mod:`training.corpus.source` said was missing.

**The heading hierarchy is the meaning, so nothing is flattened.** A payload
detached from the heading that names its database engine is noise:
``SELECT @@version`` under ``## MSSQL`` and ``SELECT version()`` under
``## PostgreSQL`` are only distinguishable by the line above them. Pages are
rendered in document order with every heading intact, and where a page is too
long to stay in one piece the pieces carry the heading trail they were cut from.

**The directory name is carried into the text, because the H1 frequently is not
enough.** ``Insecure Source Code Management/Git.md`` is titled ``# Git``.
``Upload Insecure Files/Configuration Apache .htaccess/README.md`` is titled
``# .htaccess``. ``XSS Injection/2 - XSS Polyglot.md`` is ``# Polyglot XSS``.
Thirty-seven of the 101 technique pages kept here have an H1 that does not name
their family at all, so every document opens with two restated lines naming the
technique family and the page. That repetition is the deliverable, for the same
reason :mod:`~training.corpus.sources.atomic` restates its ``T####`` id on every
test.

**Long pages are split at heading boundaries, never truncated.** The model
trains at ``max_seq_len`` 1024 (see :mod:`training.config`), and on text this
dense that is roughly 3–4 KB of characters per window. ``MySQL Injection.md`` is
36 KB: ten training windows, of which **nine would never see the page title**,
because :func:`training.data.tokenize_corpus` concatenates documents and samples
fixed-length windows out of the stream. So a page over
:data:`_SPLIT_ABOVE` is cut at its own headings — top level first, descending a
level at a time into any section still too large — consecutive sections packed
greedily up to :data:`_PART_TARGET`, and each part reopens with the family/page
header plus the heading trail of the sections it contains. Split points are
computed only outside fenced blocks, so a part boundary can never land in the
middle of a payload. Splitting also buys granularity that ``build.py`` needs:
its register and source budgets drop whole documents, so one 36 KB page is
all-or-nothing where seven parts degrade gracefully.

The one thing splitting will not do is cut a section that has no deeper headings
to cut at. ``File Inclusion/Wrappers.md``'s ``## Wrapper php://filter`` is 10.5
KB of flat payload listing, and it is emitted flat and oversized: four of the
211 documents exceed 8 KB for that reason, the largest at 12 KB. Overshooting a
target is a cost; dividing a payload listing on a character count is a
corruption, and the two are not comparable.

**Horizontal whitespace is preserved and that matters twice here.** This source
writes most of its fenced blocks *indented four spaces underneath a list
bullet*, so the fence regex has to tolerate leading whitespace — and the
indentation is then part of the payload's own shape. It also uses aligned
markdown tables (the ViewState format table in ``IIS-Machine-Keys.md``, the
wrapper table in ``File Inclusion/Wrappers.md``) whose columns only survive
because :func:`~training.corpus.source.normalise` deliberately does not collapse
runs of spaces. Payloads are character-exact by nature: a mangled payload is
worse than an absent one, because an absent one teaches nothing while a mangled
one teaches something false.

**Markup removal is one rule, and it was counted first.** Exactly 25 image
references appear in the whole repository and every one of them is outside a
fenced block (zero inside, checked). Those 25 are removed: the images are not extracted
and the alt text is a slug. *Nothing else* is touched. Outside fences and code
spans there are only 11 HTML tags in the entire repository; inside fences there
are 224 ``<script`` openings, 86 ``<xsl``, 61 ``<svg``. In this source an angle
bracket is overwhelmingly an XSS or XXE payload, and a pass that "cleaned HTML"
would delete the corpus in the name of tidying it.

**One class of payload is damaged, and by the corpus contract rather than by
this adapter.** :func:`~training.corpus.source.normalise` drops control bytes
that are neither tab nor newline, which is right everywhere else in the corpus
and wrong here: this repository holds six raw control bytes across three fenced
blocks, and in ``XSS Injection/1 - XSS Filter Bypass.md`` they *are* the
technique — ``<svg\\x0conload\\x0c=\\x0calert(1)>`` defeats a filter precisely
because those bytes are form feeds rather than spaces, and the rendered document
carries ``<svgonload=alert(1)>``. The contract wins, because it is corpus-wide
and this is three blocks out of 1,226; it is written down here rather than
quietly absorbed, because the whole argument for this source is that payloads
are character-exact. All 1,226 blocks were then checked against the built
documents — each one rendered through ``normalise()`` and searched for — and
every one is present, so those three control bytes are the entire delta between
this source and the corpus.

**Thirty-three pages are now redirect stubs, and this is the important finding
about the source.** The entire ``Methodology and Resources/`` tree — Windows and
Linux Privilege Escalation, Active Directory Attack, Reverse Shell Cheatsheet,
Mimikatz, Persistence, Pivoting — has been moved upstream to
``swisskyrepo/InternalAllTheThings`` and replaced with link indexes. Those are
precisely the pages that map onto this project's ``postex.*`` verbs, and they
are 91 KB of navigation with **zero code fences between them**. They are dropped
by a measured property rather than by name: no fenced block at all, and at least
:data:`_STUB_LINK_RATIO` of non-blank lines consisting of nothing but a bullet
and one markdown link. The 33 stubs score 0.42 to 0.97 on that ratio; the
highest-scoring fence-free page that is real prose scores 0.33, so the threshold
sits in a genuine gap rather than on top of the distribution. Naming the files
would have been easier and would rot the first time upstream renames one.

The same rule catches one page that was never a stub and should go anyway:
``Insecure Deserialization/README.md``, which is a link index over the six
per-language deserialization pages that this adapter yields in full. Thirty-four
pages are dropped in total, and the build log says so rather than leaving the
count to be reconstructed from a diff.

The post-exploitation register those stubs used to hold is a real hole, and this
adapter does not paper over it. ``InternalAllTheThings`` is the same author and
the same MIT licence, and it belongs in its own ``internal.py`` adapter — not
folded in here, for the reason :mod:`~training.corpus.sources.owasp` gives about
the Web Security Testing Guide: ``build.py`` attributes register and side per
:class:`~training.corpus.source.SourceSpec`, so a second body of text smuggled
through this spec would be reported under this spec's name and counted in this
spec's budget.

**Markdown only; the 11.9 MB of other files stay out.** The repository ships
images, ``.zip`` archives, polyglot ``.gif``/``.avi``/``.swf`` fixtures and
fuzzing wordlists alongside the prose. ``Directory Traversal/Intruder/
dotdotpwn.txt`` alone is 1.87 MB of mechanically generated ``../`` permutations
and ``API Key Leaks/Files/MachineKeys.txt`` is 622 KB of key material. Those are
inputs to a fuzzer, not writing: near-identical lines at that volume are the
textbook thing a small model memorises, and the one worked example in the
markdown already teaches the technique the wordlist enumerates.

**Licence: MIT**, ``Copyright (c) 2019 Swissky``, read from the repository's own
``LICENSE`` rather than from its README badge, and copied into the cache so the
claim sits beside the text it covers.

Upstream: https://github.com/swisskyrepo/PayloadsAllTheThings
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tarfile
import time
from pathlib import Path
from typing import Iterator

from ..net import NetworkError, download
from ..source import Document, Register, Side, SourceError, SourceSpec, normalise

__all__ = ["SPEC"]

_REPO = "swisskyrepo/PayloadsAllTheThings"
_REF = "master"

#: A codeload tarball rather than ``git clone --depth 1``. The instinct behind a
#: shallow clone is right — take the tree, leave the history — and this goes one
#: step further: no history, no ``.git`` directory for a stray ``git pull`` to
#: mutate under a build that is supposed to be reproducible, no dependency on a
#: git binary, and, most importantly, the transfer goes through
#: :func:`training.corpus.net.download` and therefore through the package's one
#: verifying TLS context. A subprocess clone would use git's own trust store and
#: quietly put a second, unaudited trust path into a project whose whole premise
#: is that it knows where its training data came from. 7.8 MB, one request.
_TARBALL_URL = f"https://codeload.github.com/{_REPO}/tar.gz/refs/heads/{_REF}"

_LICENSE_FILE = "LICENSE"

#: Everything extracted lands under this subdirectory of the source's cache dir,
#: so the ~70 technique-family directories (which carry spaces in their names)
#: do not scatter across the cache root next to the marker and the licence.
_PAGES_DIR = "pages"

#: Written last, after the staging tree has been swapped into place, so its
#: presence means extraction finished. An interrupted fetch re-downloads instead
#: of leaving a half tree that a later run mistakes for a warm cache — the one
#: failure that is silent everywhere, because a short corpus still trains.
_MARKER = ".payloads-complete.json"

#: 142 markdown files upstream, 135 of them inside a technique-family directory
#: and therefore extracted. A floor well below that makes an upstream
#: reorganisation fail loudly at fetch time rather than surface later as a thin
#: build report.
_MIN_EXTRACTED = 100

#: Below any real technique page. The smallest document this source yields is
#: 975 characters (``Insecure Source Code Management/Mercurial.md``, whole), and
#: the smallest part of a split page is held above it by :data:`_MIN_PART`.
_MIN_CHARS = 400

#: Split a page above this size; leave anything at or below it whole. Roughly
#: two to three 1024-token training windows of text this dense. Keeping a page
#: whole is always preferable — the try/observe/adapt flow runs across sections
#: — so the threshold is set where the flow is already being cut by the window
#: anyway rather than at some tidy round number of sections.
_SPLIT_ABOVE = 8_000

#: Target size for one part of a split page, and the size above which a section
#: is re-cut at a deeper heading level. Sections are packed greedily up to this,
#: and a section with no deeper heading to cut at is never divided, so a part
#: overshoots rather than cutting a payload listing in half. The largest section
#: in the source that cannot be cut further is 10.5 KB (``File
#: Inclusion/Wrappers.md``, ``## Wrapper php://filter``), so the overshoot is
#: bounded in practice as well as in principle.
_PART_TARGET = 6_000

#: The smallest a part may be. Greedy packing strands fragments at both ends
#: without this: a 300-character tail section (``## MYSQL Truncation`` and
#: nothing else) becomes its own document, and a page whose H1 and table of
#: contents are followed by one large section opens with a 417-character part
#: one. Either is a fragment wearing a header, with the header a third of it.
_MIN_PART = 1_200

#: Fraction of non-blank lines that must be bullet-plus-single-link before a
#: fence-free page is treated as a redirect index rather than a technique page.
#: Measured over all 142 pages: the 33 moved ``Methodology and Resources`` stubs
#: score 0.42–0.97, the fence-free pages that are real writing score at most
#: 0.33. See the module docstring.
_STUB_LINK_RATIO = 0.40

#: Directories with no technique text in them. ``_LEARNING_AND_SOCIALS`` is book,
#: Twitter and YouTube link lists; ``_template_vuln`` is the contribution
#: skeleton, whose headings are placeholders a model would learn to emit empty;
#: ``.github`` is repository machinery.
_SKIP_DIRS = frozenset({".github", "_LEARNING_AND_SOCIALS", "_template_vuln"})

#: An opening or closing code fence, **allowing leading whitespace**. This
#: source nests most of its blocks four spaces deep under a list bullet, so an
#: anchored ``^```` regex would see roughly none of them — and every rule below
#: that asks "is this line inside a payload?" would then answer wrongly.
_FENCE = re.compile(r"^[ \t]*(`{3,}|~{3,})")

#: An ATX heading at column zero. Indented headings are not a thing this source
#: writes, and requiring column zero means a ``# comment`` line inside a shell
#: block cannot be mistaken for one — belt and braces, since the fence map
#: already excludes it. Setext headings (``Title`` over ``=====``) would be
#: invisible to this: checked across all 142 files, there are none.
_HEADING = re.compile(r"^(#{1,6})[ \t]+(.+?)[ \t]*$")

#: A list item whose entire content is one markdown link — the shape a redirect
#: index and a table of contents are made of. A "Tools" entry
#: (``* [param-miner](url) - Burp extension``) has trailing prose and does not
#: match, which is what separates a page of links from a page with links in it.
_LINK_ONLY = re.compile(r"^[ \t]*(?:[-*+]|\d+\.)[ \t]+\[[^\]\n]*\]\([^)\n]*\)[ \t]*$")

#: ``![SSRF stream](https://.../SSRF_stream.png?raw=true)``. All 25 occurrences
#: sit outside fenced blocks (counted, not assumed) and are removed there only.
_IMAGE_REF = re.compile(r"!\[[^\]\n]*\]\([^)\n]*\)")


def _wanted(member_name: str) -> str | None:
    """Map a tar member to its cache-relative path, or ``None`` to skip it.

    Codeload wraps the tree in ``PayloadsAllTheThings-<ref>/``, whose name moves
    with the ref, so the first component is dropped rather than matched.

    Two rules. Markdown only: the other 11.9 MB is images, archives, polyglot
    media fixtures and fuzzing wordlists, none of which is text worth training
    on and some of which is binary. And markdown must live *inside* a family
    directory: a page at the repository root has no technique family, and the
    three that exist there are chrome — the README link table, CONTRIBUTING,
    and the legal DISCLAIMER.
    """
    parts = member_name.split("/")[1:]
    if not parts or any(part in ("", ".", "..") for part in parts):
        return None
    if len(parts) == 1:
        return parts[0] if parts[0] == _LICENSE_FILE else None
    if parts[0] in _SKIP_DIRS or not parts[-1].endswith(".md"):
        return None
    return "/".join(parts)


def _extract(archive: Path, staging: Path) -> int:
    """Unpack the markdown pages and LICENSE into *staging*.

    Returns the number of ``.md`` pages written, not the number of files, so a
    tarball that no longer carries any family directory still reports zero even
    though ``LICENSE`` came out of it. The caller's "upstream moved" diagnostic
    depends on that distinction.

    Members are written one at a time rather than through ``extractall``: the
    ``filter="data"`` argument that makes ``extractall`` safe is 3.12 and later,
    and this package targets 3.10. Only regular files are written and every
    destination is proved to resolve inside *staging* first — absolute paths,
    ``..`` segments and symlinks are all expressible in a tar member name, which
    is attacker-controlled data in the general case.
    """
    staging.mkdir(parents=True, exist_ok=True)
    staging_resolved = staging.resolve()
    written = 0
    try:
        with tarfile.open(archive, "r:gz") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                relative = _wanted(member.name)
                if relative is None:
                    continue
                target = staging / relative
                if not target.resolve().is_relative_to(staging_resolved):
                    continue  # traversal attempt; refuse the member
                source = tar.extractfile(member)
                if source is None:
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with source, target.open("wb") as handle:
                    shutil.copyfileobj(source, handle)
                if relative != _LICENSE_FILE:
                    written += 1
    except (tarfile.TarError, OSError) as exc:
        raise SourceError(f"payloads: could not unpack {archive}: {exc}") from exc
    return written


def _fetch(cache_dir: Path) -> Path:
    """Populate *cache_dir* with the markdown tree and return it.

    Idempotent and network-free on a warm cache: the build runs far more often
    than upstream changes. The short-circuit reads the marker rather than
    trusting its existence, and checks that the recorded ``ref`` and ``url``
    still match the ones this module declares — otherwise repointing
    :data:`_REF` at a tag would keep serving the old tree forever while the
    provenance file named the new one.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    marker = cache_dir / _MARKER
    pages_dir = cache_dir / _PAGES_DIR
    if marker.is_file():
        try:
            recorded = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            recorded = {}
        if (recorded.get("ref") == _REF
                and recorded.get("url") == _TARBALL_URL
                and pages_dir.is_dir()):
            return cache_dir

    archive = cache_dir / "_payloadsallthethings.tar.gz"
    staging = cache_dir / "_incoming"
    shutil.rmtree(staging, ignore_errors=True)
    try:
        try:
            # net.download writes a .part sibling and renames it, so an
            # interrupted transfer cannot leave a truncated archive behind.
            download(_TARBALL_URL, archive, timeout=300)
        except NetworkError as exc:
            raise SourceError(f"payloads: {exc}") from None

        written = _extract(archive, staging)
        if written < _MIN_EXTRACTED:
            raise SourceError(
                f"payloads: only {written} markdown pages found in "
                f"{_TARBALL_URL} (expected >= {_MIN_EXTRACTED}). The upstream "
                "layout has probably changed — fix the adapter rather than "
                "training on a fraction of the adversary register."
            )

        # The licence is moved out of the staging tree before the swap so that
        # `pages/` contains pages and nothing else, and so the licence text sits
        # at the top of the cache beside the marker that dates it.
        license_file = staging / _LICENSE_FILE
        license_text = license_file.read_bytes() if license_file.is_file() else b""
        license_file.unlink(missing_ok=True)

        # Retire the marker *before* the swap starts destroying the tree it
        # vouches for. Removing a directory and renaming another into its place
        # is not atomic, and an interruption inside that window would otherwise
        # leave a current marker on top of a half-replaced tree, which the warm
        # path above would accept. It is retired here rather than at the top of
        # the function so a failed download leaves the old cache usable offline.
        marker.unlink(missing_ok=True)
        shutil.rmtree(pages_dir, ignore_errors=True)
        staging.replace(pages_dir)
        if license_text:
            (cache_dir / _LICENSE_FILE).write_bytes(license_text)
    finally:
        archive.unlink(missing_ok=True)
        shutil.rmtree(staging, ignore_errors=True)

    marker.write_text(
        json.dumps(
            {
                "url": _TARBALL_URL,
                "repo": _REPO,
                "ref": _REF,
                "pages": written,
                "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return cache_dir


def _pages(root: Path) -> list[tuple[str, Path]]:
    """Every markdown page under *root*, as (family-relative ident, path).

    Walked with ``os.walk(..., followlinks=False)`` rather than ``rglob``. This
    tree is one the adapter extracted itself and holds no links, but the rule is
    absolute in this package: a sibling adapter once followed a symlink out of
    its own directory and copied 180 MB of the corpus cache back into the corpus
    under a different label. ``followlinks=False`` only stops the walk
    *descending* into a symlinked directory, so symlinked files are rejected
    explicitly too. Sorted, so the corpus is byte-reproducible across builds.
    """
    base = root / _PAGES_DIR
    pages: list[tuple[str, Path]] = []
    if not base.is_dir():
        return pages
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        dirnames.sort()
        for filename in sorted(filenames):
            if not filename.endswith(".md"):
                continue
            file = Path(dirpath) / filename
            if file.is_symlink() or not file.is_file():
                continue
            pages.append((file.relative_to(base).as_posix(), file))
    pages.sort()
    return pages


def _fence_map(lines: list[str]) -> list[bool]:
    """True for every line that belongs to a fenced block, delimiters included.

    This is the primitive every other rule here stands on: image stripping, the
    link-ratio measurement and the choice of split points all ask "is this line
    payload?" and all of them must answer no for a line inside a fence. Marking
    the delimiters themselves as inside is deliberate — the fence line and its
    info string (```` ```sql ````) are part of the block's context and must never
    be edited or split away from it.

    Closing follows CommonMark closely enough for this source: same fence
    character, at least as long as the opening run, and nothing else on the
    line. That strictness is what lets a ```` ``` ```` *inside* a ```` ```` ````
    block stay inside it. A page that ends while still open leaves its tail
    marked as fenced, which fails in the safe direction: the tail is passed
    through untouched and unsplit rather than cut somewhere inside a payload.
    (No page in the current tree ends open.)
    """
    flags: list[bool] = []
    marker = ""
    for line in lines:
        match = _FENCE.match(line)
        if match is None:
            flags.append(bool(marker))
            continue
        token = match.group(1)
        if not marker:
            marker = token
        elif (token[0] == marker[0] and len(token) >= len(marker)
                and line.strip() == token):
            marker = ""
        flags.append(True)
    return flags


def _strip_images(lines: list[str], fenced: list[bool]) -> list[str]:
    """Remove image references from prose lines, leaving fenced text alone.

    The images are not extracted into the corpus and their alt text is a slug
    (``![cspt-query-param](...)``), so the reference has no referent. A line
    that was nothing but an image becomes empty rather than whitespace, and
    :func:`~training.corpus.source.normalise` then folds the blank run.
    """
    out: list[str] = []
    for line, in_fence in zip(lines, fenced):
        if in_fence:
            out.append(line)
            continue
        stripped = _IMAGE_REF.sub("", line)
        out.append(stripped if stripped.strip() else "")
    return out


def _link_ratio(lines: list[str], fenced: list[bool]) -> float:
    """Share of non-blank prose lines that are a bullet and one bare link.

    The discriminator for a redirect index. Fenced lines are excluded from both
    halves of the fraction so that a page of payloads cannot be diluted into
    looking like an index, and a page of links cannot be rescued by one.
    """
    body = 0
    links = 0
    for line, in_fence in zip(lines, fenced):
        if in_fence or not line.strip():
            continue
        body += 1
        if _LINK_ONLY.match(line):
            links += 1
    return links / body if body else 0.0


#: A section of a page: the trail of headings that led to it, outermost first,
#: and its rows as ``(line, is_inside_a_fence)`` pairs. The trail is carried
#: rather than recomputed because a section cut out of the middle of a page no
#: longer has its ancestors above it, and those ancestors are what say which
#: engine or platform the payloads below target.
_Section = tuple[tuple[str, ...], list[tuple[str, bool]]]


def _size(rows: list[tuple[str, bool]]) -> int:
    """Characters a row list will occupy, newlines included."""
    return sum(len(line) + 1 for line, _ in rows)


def _cut(rows: list[tuple[str, bool]], level: int,
         path: tuple[str, ...]) -> list[_Section]:
    """Cut *rows* at ATX headings of depth *level* (or shallower at the top).

    Headings inside fenced blocks are not headings: a ``# install deps`` comment
    at the head of a bash payload must never become a split point, and this is
    where that is enforced. Anything before the first boundary keeps the caller's
    *path* — it is the parent's own preamble, not a new section.
    """
    sections: list[_Section] = []
    heading = ""
    body: list[tuple[str, bool]] = []
    for line, in_fence in rows:
        match = None if in_fence else _HEADING.match(line)
        depth = len(match.group(1)) if match is not None else 0
        # The top-level pass takes H1 and H2 as siblings (a page's H1 is its
        # title, not a level the sections hang under); deeper passes take one
        # exact level at a time, so a parent heading is not re-read as a
        # boundary and duplicated into its children's heading trail.
        boundary = depth and (depth <= level if level <= 2 else depth == level)
        if boundary:
            if heading or any(text.strip() for text, _ in body):
                sections.append((path + ((heading,) if heading else ()), body))
            heading = match.group(2).strip()
            body = [(line, in_fence)]
            continue
        body.append((line, in_fence))
    if heading or any(text.strip() for text, _ in body):
        sections.append((path + ((heading,) if heading else ()), body))
    return sections


def _sections(rows: list[tuple[str, bool]]) -> list[_Section]:
    """Cut a page into sections small enough to pack, descending as needed.

    Top-level headings first. That is enough for most pages, but not for the
    ones where a single ``## Methodology`` holds 16 KB under a dozen ``###``
    subheadings — ``SQL Injection/SQLmap.md`` and ``Insecure
    Deserialization/Java.md`` are both this shape. Left at one level the packer
    cannot divide them at all, and the resulting part spans four training
    windows with the family header on only the first, which is the exact failure
    splitting exists to prevent.

    So an oversized section is re-cut one heading level deeper, repeatedly,
    until it fits or there are no deeper headings left. A section with nothing
    to cut at any level is returned whole and oversized: overshooting the target
    is a cost, and cutting a payload in half is a corruption.
    """
    sections: list[_Section] = []
    for path, body in _cut(rows, 2, ()):
        sections.extend(_refine(path, body, 3))
    return sections


def _refine(path: tuple[str, ...], body: list[tuple[str, bool]],
            level: int) -> list[_Section]:
    """Recursively divide an oversized section at ever deeper headings."""
    if level > 6 or _size(body) <= _PART_TARGET:
        return [(path, body)]
    pieces = _cut(body, level, path)
    if len(pieces) <= 1:
        return _refine(path, body, level + 1)  # nothing at this depth; go deeper
    refined: list[_Section] = []
    for child_path, child_body in pieces:
        refined.extend(_refine(child_path, child_body, level + 1))
    return refined


def _pack(sections: list[_Section]) -> list[list[_Section]]:
    """Group consecutive sections into parts of roughly :data:`_PART_TARGET`.

    Greedy and order-preserving: an operator's page reads top to bottom and its
    conditional structure runs the same way, so neighbouring sections belong
    together and reordering to pack more tightly would destroy the very thing
    this source was collected for.

    Two floors, both for the same reason — a part below :data:`_MIN_PART` is a
    fragment wearing a header, and the header would be a third of it. A part is
    not closed early just because the *next* section is large (which otherwise
    strands a page's H1 and table of contents as a 400-character part one), and
    a short final section is folded back into its predecessor.
    """
    parts: list[list[_Section]] = []
    current: list[_Section] = []
    size = 0
    for section in sections:
        length = _size(section[1])
        if current and size >= _MIN_PART and size + length > _PART_TARGET:
            parts.append(current)
            current = []
            size = 0
        current.append(section)
        size += length
    if current:
        parts.append(current)

    if len(parts) > 1 and sum(_size(body) for _, body in parts[-1]) < _MIN_PART:
        parts[-2].extend(parts.pop())
    return parts


def _header(family: str, title: str, part: int, total: int,
            sections: list[_Section]) -> str:
    """The context block that opens every document this adapter yields.

    Two lines always, because the page's own H1 is not reliably enough to say
    what family it belongs to (``# Git``, ``# .htaccess``, ``# Bazaar``), and a
    third when the page was split, naming the part and the sections it holds.
    On parts after the first this is the *only* thing that says what engine,
    language or platform the payloads below target — the H1 is back in part one,
    a thousand tokens away and, once the corpus is windowed, in a different
    training sample entirely.
    """
    lines = [f"technique family: {family}", f"page: {title}"]
    if total > 1:
        named: list[str] = []
        for path, _ in sections:
            # The H1 is a boundary like any other heading, so without this the
            # section list would open by repeating the title it sits under.
            trail = " > ".join(heading for heading in path if heading != title)
            if trail and trail not in named:
                named.append(trail)
        label = f"part {part} of {total}"
        lines.append(f"{label}: {', '.join(named)}" if named else label)
    return "\n".join(lines)


def _title(lines: list[str], fenced: list[bool], ident: str) -> str:
    """The page's first H1, falling back to its filename.

    Every page in the current tree has one; the fallback exists so that a future
    page without one gets a usable name instead of an empty ``page:`` line.
    """
    for line, in_fence in zip(lines, fenced):
        if in_fence:
            continue
        match = _HEADING.match(line)
        if match is not None and len(match.group(1)) == 1:
            return match.group(2).strip()
    stem = ident.rsplit("/", 1)[-1][: -len(".md")]
    return stem if stem != "README" else ident.split("/")[0]


def _documents(path: Path) -> Iterator[Document]:
    """Yield the technique pages, whole where they fit and split where they do not.

    Order is the sorted repository path, so a rebuild produces the same corpus
    in the same sequence.

    A page that cannot be read raises rather than being skipped. Silently
    shipping a corpus that is short by an unknown amount is the failure this
    package is built to make impossible, and a damaged cache is a fixable
    condition that deserves to be said out loud.
    """
    pages = _pages(path)
    if not pages:
        raise SourceError(
            f"payloads: no markdown pages under {path / _PAGES_DIR}. Run fetch "
            "first, or delete the cache and re-fetch if it is damaged."
        )

    stubs = 0
    split_pages = 0
    for ident, file in pages:
        try:
            # utf-8-sig: a stray U+FEFF at the head of a page would become a
            # token the model learns to expect before every H1.
            raw = file.read_text(encoding="utf-8-sig", errors="replace")
        except OSError as exc:
            raise SourceError(
                f"payloads: {ident} was listed but could not be read ({exc}). "
                f"The cache is damaged; delete {path} and re-fetch rather than "
                "shipping a corpus that is short by an unknown amount."
            ) from exc

        # Line endings are settled before anything counts lines or fences, so a
        # CRLF page cannot defeat the strict fence-close test below.
        lines = raw.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        fenced = _fence_map(lines)
        lines = _strip_images(lines, fenced)

        whole = normalise("\n".join(lines))
        if len(whole) < _MIN_CHARS:
            continue
        # A page with no payload in it and mostly bare links is a redirect index
        # left behind by content that moved to another repository.
        if not any(fenced) and _link_ratio(lines, fenced) >= _STUB_LINK_RATIO:
            stubs += 1
            continue

        family = ident.split("/")[0]
        title = _title(lines, fenced, ident)

        if len(whole) <= _SPLIT_ABOVE:
            header = _header(family, title, 1, 1, [])
            yield Document(
                text=normalise(f"{header}\n\n{whole}"),
                source="payloads",
                register=Register.ADVERSARY,
                side=Side.RED,
                ident=ident,
            )
            continue

        parts = _pack(_sections(list(zip(lines, fenced))))
        split_pages += 1
        for index, part in enumerate(parts, start=1):
            header = _header(family, title, index, len(parts), part)
            body = normalise(
                "\n".join(line for _, rows in part for line, _ in rows)
            )
            if not body:
                continue  # a section of nothing but a heading and blank lines
            yield Document(
                text=normalise(f"{header}\n\n{body}"),
                source="payloads",
                register=Register.ADVERSARY,
                side=Side.RED,
                ident=f"{ident}#part{index}" if len(parts) > 1 else ident,
            )

    # Nothing is dropped or reshaped silently; the build log says how much.
    if stubs:
        print(f"   payloads: skipped {stubs} redirect index page(s) whose "
              "content moved to swisskyrepo/InternalAllTheThings")
    if split_pages:
        print(f"   payloads: split {split_pages} page(s) over "
              f"{_SPLIT_ABOVE:,} chars at their top-level headings")


SPEC = SourceSpec(
    name="payloads",
    license=(
        "MIT (Copyright (c) 2019 Swissky; PayloadsAllTheThings/LICENSE, copied "
        "into the cache beside the pages it covers)"
    ),
    url="https://github.com/swisskyrepo/PayloadsAllTheThings",
    register=Register.ADVERSARY,
    side=Side.RED,
    fetch=_fetch,
    documents=_documents,
    #: 142 markdown pages upstream: 7 are repository chrome or link lists and
    #: are not extracted, 34 of the remaining 135 are link indexes and are
    #: dropped, and 48 of the 101 technique pages left are split — 211 documents
    #: observed on master at fetch time. The floor sits well below that because
    #: pages are retired by being replaced with a link index and the count
    #: drifts down by ones. It is still tight enough to catch the regression
    #: that matters: a fence matcher that stops seeing indented blocks would
    #: reclassify most of this source as link indexes and halve the count.
    expect_min_docs=150,
    notes=(
        "One document per technique page, headings and fenced payloads intact, "
        "opened with the technique family and page title because the H1 alone "
        "is often just '# Git' or '# .htaccess'. Pages over 8 KB are split at "
        "their own headings, descending a level into any section still too "
        "large and never cutting inside a fence, and every part reopens with "
        "that header and its heading trail, because training windows are 1024 "
        "tokens "
        "and a 36 KB page would otherwise spend nine of its ten windows with "
        "no statement of what the payloads target. 24.7% of the text is fenced "
        "code (powershell, ps1, sql, javascript, xml, html, python, php). Only "
        "image references are stripped, and only outside fences: everywhere "
        "else an angle bracket in this source is an XSS or XXE payload rather "
        "than markup. Markdown only — the repository's 11.9 MB of images, "
        "archives and fuzzing wordlists (1.87 MB of generated '../' "
        "permutations in one file) are not text. All 33 'Methodology and "
        "Resources' pages are now link indexes pointing at "
        "swisskyrepo/InternalAllTheThings, which is where the Windows/Linux "
        "privilege escalation, Active Directory and reverse-shell material "
        "went; they are dropped by measurement (no fenced block, mostly bare "
        "links) rather than by name, and that repository deserves its own "
        "adapter rather than being smuggled through this spec, which would "
        "report it under this source's name and budget."
    ),
)
