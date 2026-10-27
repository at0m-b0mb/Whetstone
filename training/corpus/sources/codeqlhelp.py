"""CodeQL query help: a weakness, the code that has it, the code that fixed it,
and the query that finds it. ADVERSARY, DETECTION and PROSE, per document.

The owner's ask for this family was "programming knowledge so the model can
provide actual code", and the project's own answer to that is written down: the
catalogue holds the code, the model holds the judgement. Momus emits a verb id
and typed parameters, never a shell string, because a gate can reason about a
verb and cannot reason about an opaque command. So the useful form of
"code that relates to exploitation" is not a payload collection — it is
**labelled weakness patterns**, which is the shape
:mod:`~training.corpus.sources.juliet` already proved valuable here and the
shape this source extends into six more languages and into detection.

A CodeQL query pack entry is a remarkable document for this corpus because it
holds four things that live in four different places everywhere else:

* the weakness in prose, with its CWE identifiers (``external/cwe/cwe-089``),
* a **bad** code sample, in a real language, that genuinely has the flaw,
* the **good** rewrite beside it, usually in the same file so the diff is
  visible,
* and the **query** — real, executable detection-as-code — that finds the bad
  one, with its own precision and severity metadata.

``juliet`` gives the first three for C, C++, Java, C# and PHP in a synthetic
test-suite dialect. This gives all four for C, C++, C#, Go, Java, JavaScript,
Python and GitHub Actions workflows, in idiomatic code, written by the people
who maintain the analyses.

**Two documents per query, not one, and the split is the honest part.** The
temptation is a single document holding explanation, samples and query
together, because that is how a human would want to read it. But
:class:`~training.corpus.source.Register` is decided by surface form, and that
document would be a third prose, a third Java and a third QL — it has no
register, and labelling it anything would be a misreport of the kind
``source.py`` exists to make visible. So:

* the **help** document — overview, recommendation, worked examples with the
  samples inlined, references — is
  :class:`~training.corpus.source.Register.ADVERSARY`/NEUTRAL, exactly as
  ``juliet`` labels a bad/good pair. NEUTRAL rather than RED because every one
  of these carries the fix.
* the **query** document — the metadata header restated, then the ``.ql``
  source verbatim — is
  :class:`~training.corpus.source.Register.DETECTION`/BLUE, exactly as
  ``sigma`` labels a rule.

Both carry the same ``@id`` (``java/sql-injection``) in their text, so the two
halves co-occur through the identifier rather than through being glued into one
mislabelled blob. That is the same argument :mod:`~training.corpus.sources.cwe`
makes for writing ``CWE-###`` next to a bare integer.

A third tier is PROSE: ``docs/codeql/codeql-language-guides/``,
``writing-codeql-queries/`` and ``ql-language-reference/``. Tutorial and
reference prose about *how to write a detection*, which is the half of this
project the owner cares most about and a register sitting under its target.

**The licence gate is structural, and that is deliberate.** ``github/codeql``
is MIT at the root — "Copyright (c) 2006-2025 GitHub, Inc." — but the tree
also carries roughly 160 *other* licence files, every one of them under
``*/ql/test/**/vendor/``, ``*/ql/test/stubs/``, ``*/extractor/``,
``java/kotlin-extractor/deps/`` or ``misc/``: Apache-2.0 Kubernetes vendoring,
the PSF licence, javamail, junit, aspectj, an OpenSSL stub. None of those trees
is collected, and the reason nothing from them is collected is not a filter that
could be loosened by accident — it is that this source reads **only**
``<lang>/ql/src/`` and three named directories under ``docs/codeql/``, and no
third-party licence file exists under either. ``fetch`` then *checks* that
claim: if a file whose name looks like a licence lands inside the kept set, the
fetch fails rather than quietly collecting text under terms nobody read. A
structural argument that nothing verifies is a structural argument that stops
being true on the next upstream reorganisation.

Also excluded, and worth naming: ``*/ql/test/`` holds ~70 MB of ``.expected``
output and thousands of deliberately-broken third-party-shaped fixtures, and
``*/extractor/`` is compiler plumbing. The CodeQL CLI itself is licensed
separately in a different repository and is not here in any form.

**Privacy.** Mail addresses are stripped from every document by
:func:`training.corpus.sources._thirdparty.strip_emails`, the whole fetched
tree is counted before and the emitted documents counted after, and both
numbers go into the cache marker so the strip is a measurement rather than a
claim. Query metadata carries no ``@author`` field — checked, not assumed — and
the ``<references>`` sections cite published papers, CVE records and OWASP
pages by title and URL. Those references name researchers as the published
authors of published work, which is a different question from a private
individual's details, and the decision to keep them is deliberate.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tarfile
import time
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from pathlib import Path

from ..net import NetworkError, download
from ..source import Document, Register, Side, SourceError, SourceSpec, normalise
from ._thirdparty import count_emails, strip_emails

_NAME = "codeqlhelp"

_TARBALL = "https://codeload.github.com/github/codeql/tar.gz/refs/heads/main"

_MARKER = ".codeqlhelp.json"
_CACHE_VERSION = 1

#: The archive is large and most of it is discarded on the way past: the tree is
#: ~282 MB uncompressed, of which 71 MB is ``.expected`` test output and 38 MB
#: is generated database schemas. Measured on the run that produced this
#: adapter's counts: the download was **51,485,772 bytes (49.1 MB)** and the
#: kept tree **9,051,649 bytes (8.6 MB)** — 17.6% of the bytes fetched, which
#: is the price of an upstream that ships its queries interleaved with its test
#: fixtures and offers no narrower download. The ceiling below is set well above
#: that rather than snugly: its job is to stop an upstream that has become
#: something else, not to assert a size.
_MAX_ARCHIVE_BYTES = 400 * 1024 * 1024

#: Per member. The largest thing collected is a 150 KB language guide; the
#: tarball's own size is no evidence about any one member's, which is the lesson
#: five tar-reading adapters in this package learned the same afternoon.
_MAX_MEMBER_BYTES = 1024 * 1024

#: Language packs with a ``ql/src`` tree. Listed rather than discovered so that
#: a new top-level directory upstream is a decision somebody makes, not a tree
#: that silently joins the corpus.
_LANGS = ("actions", "cpp", "csharp", "go", "java", "javascript", "python")

#: Documentation trees kept, as PROSE. ``ql-training/`` is excluded: it is
#: slide-deck RST with one bullet per line and speaker notes, which reads as
#: fragments rather than prose. ``codeql-overview/`` is product orientation and
#: ``images/`` is 9 MB of screenshots.
_DOC_DIRS = (
    "docs/codeql/codeql-language-guides/",
    "docs/codeql/writing-codeql-queries/",
    "docs/codeql/ql-language-reference/",
)

#: Sample-code suffixes found under ``*/ql/src/``. An allowlist rather than
#: "anything that is not .ql" because that tree also holds ``.png`` diagrams,
#: ``.json`` pack manifests and ``.qls`` suite definitions.
_SAMPLE_SUFFIXES = (
    ".java", ".cs", ".py", ".js", ".ts", ".cpp", ".c", ".h", ".go", ".rb",
    ".aspx", ".html", ".htm", ".xml", ".properties", ".config", ".yml",
    ".yaml", ".bad", ".good", ".sql", ".php", ".swift", ".kt",
)

#: Help formats. ``.qhelp`` is the XML original; ``.md`` is the Markdown form
#: upstream has been migrating to and is now 845 files. Both are read.
_HELP_SUFFIXES = (".qhelp", ".md")

#: A licence document, by the same case-sensitive all-caps-stem rule
#: :mod:`~training.corpus.sources.golang` arrived at after a case-insensitive
#: prefix match collected mostly Go source from two repositories that happen to
#: contain licence scanners. Used here as a tripwire, not a collector.
_LICENCE_NAME = re.compile(
    r"\A(LICENSE|LICENCE|COPYING|NOTICE)([-._][A-Za-z0-9._-]*)?\Z")

#: Files that are not help even though they end in ``.md``.
_NOT_HELP = frozenset({"CHANGELOG.md", "README.md", "CONTRIBUTING.md"})

#: Path fragments carved back out of ``*/ql/src/``. ``change-notes/`` is the
#: whole reason this exists and it is a measured exclusion, not a guess: 786 of
#: the 789 Markdown files under ``ql/src`` that have no query beside them are
#: release-note fragments, most of them the single line "No user-facing
#: changes." Nothing emitted them — a help file with no ``.ql`` sibling is never
#: a document — but leaving them in the cache made ``counts["help"]`` claim
#: 2,641 help files where only 1,855 exist, and a count that overstates by 42%
#: is a floor that cannot notice an upstream reorganisation.
_SRC_DROP = ("/change-notes/",)

#: ``external/cwe/cwe-089`` as CodeQL writes it in ``@tags``. Rewritten to
#: ``CWE-89`` beside the original, for the reason ``cwe`` gives: the corpus
#: should carry the identifier in the form the world writes it, next to the
#: name of the thing it denotes.
_CWE_TAG = re.compile(r"\Aexternal/cwe/cwe-0*(\d+)\Z")

#: The ``/** ... */`` metadata block that opens every query. Non-greedy so it
#: ends at the first ``*/`` rather than at the last one in the file.
_QL_META = re.compile(r"\A\s*/\*\*(?P<body>.*?)\*/", re.DOTALL)

#: ``@key value`` inside that block, with continuation lines indented under it.
_QL_KEY = re.compile(r"^\s*\*?\s*@(?P<key>[a-z][a-z0-9.-]*)\s*(?P<value>.*)$")

#: An RST directive this source drops rather than renders. ``include`` would
#: dangle (``reusables/`` is not collected) and the rest are renderer
#: passthrough. Modelled on ``kerneldocs``, which drops ``.. raw::`` for the
#: same reason and explicitly refuses to run a generic tag stripper over RST.
_RST_DROP = re.compile(
    r"^[ \t]*\.\.[ \t]+(include|image|figure|raw|toctree|only|meta)::.*$",
    re.MULTILINE)

#: Floors. Help text below the first is a stub; a query below the second is a
#: metadata block with one ``select``, which is still a real query — the floor
#: is lower on purpose.
_MIN_HELP_CHARS = 250
_MIN_QUERY_CHARS = 180
_MIN_PROSE_CHARS = 400

#: How deep ``<include src=...>`` chasing goes. Upstream nests one level; three
#: is slack, and the cycle guard below is what actually makes it safe.
_INCLUDE_DEPTH = 3


# ---------------------------------------------------------------------------
# fetch
# ---------------------------------------------------------------------------

def _kept(relative: str) -> bool:
    """True for a member this source collects. Pure path shape, no I/O.

    This predicate *is* the licence gate described in the module docstring:
    every one of the ~160 third-party licence files in this repository sits
    under a path this function returns False for, and it returns False for them
    because of where they are rather than because of what they are called.
    """
    if relative == "LICENSE":
        return True
    if relative.startswith(_DOC_DIRS):
        return relative.endswith(".rst")
    parts = relative.split("/")
    if len(parts) < 4 or parts[0] not in _LANGS:
        return False
    if (parts[1], parts[2]) != ("ql", "src"):
        return False
    if any(fragment in f"/{relative}" for fragment in _SRC_DROP):
        return False
    name = parts[-1]
    if name in _NOT_HELP:
        return False
    return name.endswith(_HELP_SUFFIXES + (".ql",) + _SAMPLE_SUFFIXES)


def _extract(archive: Path, staging: Path) -> dict[str, int]:
    """Unpack the kept members into *staging*. Returns per-kind counts.

    Members are written individually, with every destination proved to resolve
    inside the staging tree, because ``TarFile.extractall``'s ``filter="data"``
    only exists from Python 3.12 and this package targets 3.10. A tar member is
    attacker-controlled data in principle even from a host trusted in practice.
    """
    staging.mkdir(parents=True, exist_ok=True)
    resolved = staging.resolve()
    counts = {"help": 0, "query": 0, "sample": 0, "prose": 0, "licence": 0,
              "oversize": 0}
    try:
        with tarfile.open(archive, "r:gz") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                parts = member.name.split("/")[1:]   # drop codeql-<ref>/
                if not parts or any(p in ("", ".", "..") or os.path.isabs(p)
                                    for p in parts):
                    continue
                relative = "/".join(parts)
                if not _kept(relative):
                    continue
                if member.size > _MAX_MEMBER_BYTES:
                    counts["oversize"] += 1
                    continue
                name = parts[-1]
                if relative == "LICENSE":
                    out = staging / "licenses" / "LICENSE"
                    counts["licence"] += 1
                else:
                    if _LICENCE_NAME.match(name):
                        # The tripwire. Nothing should reach here: see _kept.
                        raise SourceError(
                            f"{_NAME}: {relative} is a licence document inside "
                            "the collected set. This source's claim to be MIT "
                            "rests on collecting only <lang>/ql/src/ and three "
                            "docs/codeql/ trees, none of which carried a "
                            "third-party licence when the adapter was written. "
                            "Upstream has reorganised; a human needs to read "
                            "that file before anything under it is trained on."
                        )
                    out = staging / "files" / relative
                target = out.resolve()
                if not target.is_relative_to(resolved):
                    continue
                handle = tar.extractfile(member)
                if handle is None:
                    continue
                out.parent.mkdir(parents=True, exist_ok=True)
                # A chunk at a time: peak memory is a chunk, not the member.
                with handle, out.open("wb") as fh:
                    shutil.copyfileobj(handle, fh, 1 << 20)
                if relative.startswith(_DOC_DIRS):
                    counts["prose"] += 1
                elif name.endswith(".ql"):
                    counts["query"] += 1
                elif name.endswith(_HELP_SUFFIXES):
                    counts["help"] += 1
                else:
                    counts["sample"] += 1
    except SourceError:
        raise
    except (tarfile.TarError, OSError) as exc:
        raise SourceError(f"{_NAME}: could not unpack {archive}: {exc}") from exc

    if counts["licence"] != 1:
        raise SourceError(
            f"{_NAME}: the archive carries no root LICENSE. This source "
            "declares MIT and keeps the upstream text on disk to back the "
            "declaration; an archive that has stopped shipping it needs a "
            "human to look, not a default."
        )
    if counts["query"] < 1200 or counts["help"] < 900 or counts["prose"] < 60:
        raise SourceError(
            f"{_NAME}: yielded {counts['query']} queries, {counts['help']} help "
            f"files and {counts['prose']} guide pages (expected at least 1200, "
            "900 and 60). The upstream layout has moved; fix the keep set "
            "rather than training on a fraction of it."
        )
    return counts


def _scan_for_addresses(root: Path) -> int:
    """Count mail addresses across the extracted tree, before any stripping.

    ``os.walk(followlinks=False)``, never ``rglob``: a sibling adapter once
    followed a repository's symlink into the SSD and pulled the corpus cache
    back in as its own register, and only the balance report noticed.
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
                    path.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
    return total


def _fetch(cache_dir: Path) -> Path:
    """Download the tarball, keep ~3% of it, and record what happened.

    Network-free on re-run. The marker is written only after the staging tree
    has been swapped into place and carries ``cache_version``, so a change to
    what is collected re-fetches instead of being read with the wrong parser.

    The archive is deleted as soon as it is unpacked: it is an order of
    magnitude larger than the curated result and keeping it would be paying
    disk to avoid a download that happens once.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    marker = cache_dir / _MARKER
    files = cache_dir / "files"
    if marker.is_file() and files.is_dir():
        try:
            recorded = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            recorded = {}
        if recorded.get("cache_version") == _CACHE_VERSION:
            return cache_dir

    staging = cache_dir / ".staging"
    archive = cache_dir / ".codeql.tar.gz.part"
    shutil.rmtree(staging, ignore_errors=True)
    try:
        try:
            download(_TARBALL, archive, timeout=1800,
                     max_bytes=_MAX_ARCHIVE_BYTES)
        except NetworkError as exc:
            raise SourceError(f"{_NAME}: {exc}") from None
        archive_bytes = archive.stat().st_size
        digest = _sha256(archive)
        counts = _extract(archive, staging)
        addresses = _scan_for_addresses(staging / "files")
        qhelp_total, qhelp_failed = _parsable_help(staging / "files")
        if qhelp_total and qhelp_failed / qhelp_total > _MAX_UNPARSABLE:
            raise SourceError(
                f"{_NAME}: {qhelp_failed} of {qhelp_total} qhelp files will not "
                f"parse ({qhelp_failed / qhelp_total:.1%}, ceiling "
                f"{_MAX_UNPARSABLE:.0%}). The usual cause is a named entity the "
                "qhelp DTD declares and _ENTITIES does not yet carry; run the "
                "entity census in that constant's docstring and add it. "
                "Refusing here rather than silently rendering those pages to "
                "nothing, which is how a corpus loses a measurable slice of a "
                "source without anybody noticing."
            )

        for name in ("files", "licenses"):
            shutil.rmtree(cache_dir / name, ignore_errors=True)
        (staging / "files").replace(cache_dir / "files")
        (staging / "licenses").replace(cache_dir / "licenses")

        marker.write_text(json.dumps({
            "cache_version": _CACHE_VERSION,
            "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "url": _TARBALL,
            # Observed, not verified: codeload publishes no digest for a branch
            # tarball. This records which snapshot the cache holds and claims
            # nothing about whether it was compared with an upstream statement.
            "archive_sha256_observed": digest,
            "archive_bytes": archive_bytes,
            "kept_bytes": _tree_bytes(cache_dir / "files"),
            "counts": counts,
            "qhelp_files": qhelp_total,
            "qhelp_unparsable": qhelp_failed,
            # The privacy measurement, as a count. No value is recorded.
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


# ---------------------------------------------------------------------------
# qhelp rendering
# ---------------------------------------------------------------------------

#: The qhelp DOCTYPE names an external DTD (``qhelp.dtd``) that is not in the
#: tree. ``ElementTree`` does not fetch it — which is the behaviour we want,
#: since fetching a DTD named by downloaded data is an XXE — but it also will
#: not resolve any entity the DTD would have declared. Removing the declaration
#: makes that explicit instead of relying on a parser default.
_DOCTYPE = re.compile(r"<!DOCTYPE.*?>\s*", re.DOTALL)

#: The named entities the qhelp DTD declares and ``ElementTree`` does not.
#:
#: This map is the whole reason :func:`_parsable_help` exists, and it is the
#: clearest instrument-first finding in this adapter. With the DOCTYPE removed
#: and nothing put in its place, **31 of 1,812 qhelp files failed to parse** —
#: 1.7%, every one of them with ``undefined entity`` — and the renderer
#: returned an empty string for each, which the floor then dropped. A silent
#: 1.7% loss is exactly the kind of thing that is never noticed; the tell was
#: that the failures clustered in ``Metrics/``, ``Complexity/`` and
#: ``Naming Conventions/``, which is not how a random fault distributes.
#:
#: A census of every named entity in the tree found eleven, of which four are
#: XML built-ins the parser already knows. These are the other seven, with the
#: counts observed: sect 15, nbsp 10, ndash 7, rarr 5, mdash 4, ntilde 2,
#: hArr 1. Resolved by substitution rather than by re-declaring a DTD, because
#: handing a parser a DOCTYPE assembled from downloaded text is the wrong
#: direction of travel in a security project.
_ENTITIES = {
    "&sect;": "§", "&nbsp;": " ", "&ndash;": "–", "&mdash;": "—",
    "&rarr;": "→", "&hArr;": "⇔", "&ntilde;": "ñ",
}
_ENTITY_RE = re.compile("|".join(re.escape(k) for k in _ENTITIES))

#: Ceiling on qhelp files that still fail to parse after entity resolution,
#: as a fraction of all qhelp files. Observed after the fix: zero. The ceiling
#: is not zero because a single new entity upstream should not take a whole
#: source out of the build — but a systematic break must, and the point of
#: measuring at fetch time is that a refusal there has written nothing yet.
_MAX_UNPARSABLE = 0.01

#: Elements rendered as verbatim blocks. Their inner whitespace is the content.
_VERBATIM = frozenset({"pre", "sample"})

#: Elements that introduce a paragraph break.
_BLOCK = frozenset({"p", "li", "overview", "recommendation", "example",
                    "references", "fragment", "section", "include", "qhelp",
                    "ul", "ol", "table", "tbody", "thead", "tr", "partial",
                    "semmle-tutorial"})


def _parse_qhelp(raw: str) -> ET.Element | None:
    """Parse one qhelp document, or ``None`` if it will not parse.

    The DOCTYPE goes and the seven DTD-declared entities are substituted; see
    :data:`_ENTITIES` for the measurement that made this necessary. ``None``
    rather than an exception because one unparsable page is a dropped page and
    the *rate* is what matters — :func:`_parsable_help` measures that rate at
    fetch time, where a refusal costs nothing because nothing is written yet.
    """
    body = _ENTITY_RE.sub(lambda m: _ENTITIES[m.group(0)], _DOCTYPE.sub("", raw))
    try:
        return ET.fromstring(body)
    except ET.ParseError:
        return None


def _parsable_help(root: Path) -> tuple[int, int]:
    """Count qhelp files and how many of them will not parse.

    Called once at fetch time. Returns ``(total, failures)``.
    """
    total = failures = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames
                             if not Path(dirpath, d).is_symlink())
        for name in sorted(filenames):
            if not name.endswith(".qhelp"):
                continue
            path = Path(dirpath, name)
            if path.is_symlink():
                continue
            total += 1
            try:
                raw = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                failures += 1
                continue
            if _parse_qhelp(raw) is None:
                failures += 1
    return total, failures


def _inline(node: ET.Element) -> str:
    """Render one element's inline *prose* to text, recursively.

    ``<code>`` becomes backticked and ``<a href>`` becomes ``text (url)``: both
    are kept rather than flattened because the backticks mark which span is an
    identifier and the URL is the citation.

    **Verbatim elements render to nothing here.** ``<pre>`` and ``<sample>`` are
    code, this function's output is handed to :func:`_collapse`, and
    :func:`_collapse` strips and rejoins lines — so a code block that came
    through here would arrive in the corpus with its indentation gone.
    :func:`_render_help_xml` collects them separately and appends them already
    fenced, which keeps the one rule that matters: nothing that is code is ever
    reflowed.
    """
    parts: list[str] = []
    if node.tag in _VERBATIM:
        return ""
    if node.text:
        parts.append(node.text)
    for child in node:
        rendered = _inline(child)
        tag = child.tag
        if tag == "code":
            rendered = f"`{rendered.strip()}`"
        elif tag == "a":
            href = (child.get("href") or "").strip()
            label = rendered.strip() or href
            rendered = f"{label} ({href})" if href else label
        elif tag in _BLOCK or tag in _VERBATIM:
            rendered = f"\n{rendered}\n"
        if rendered:
            parts.append(rendered)
        if child.tail:
            parts.append(child.tail)
    return "".join(parts)


def _collapse(text: str) -> str:
    """Join hand-wrapped prose back into lines, leaving blank-line structure.

    qhelp wraps its paragraphs at whatever column the author's editor used, and
    a straight render leaves a ragged 40-to-90-column text with newlines mid
    sentence. This rejoins within a paragraph and nothing else.

    **It is only ever given prose**, and that restriction is load-bearing: this
    function strips each line and joins it to its neighbour, so handing it a
    code block would flatten the indentation that
    :func:`~training.corpus.source.normalise` exists to preserve — the same
    mistake that destroyed netstat column alignment and flattened Sigma YAML
    nesting the first time somebody tidied this corpus. Verbatim content never
    reaches here: :func:`_inline` drops every ``<pre>`` and ``<sample>``, and
    :func:`_render_help_xml` collects them separately and appends them already
    fenced. 14 of the 1,812 qhelp files carry a ``<pre>`` block, which is few
    enough to have been missed by a spot check and is exactly why the split is
    structural rather than conditional.
    """
    out: list[str] = []
    buffer: list[str] = []
    for line in text.split("\n"):
        if line.strip():
            buffer.append(line.strip())
        else:
            if buffer:
                out.append(" ".join(buffer))
                buffer = []
            if out and out[-1] != "":
                out.append("")
    if buffer:
        out.append(" ".join(buffer))
    return "\n".join(out).strip()


def _render_help_xml(path: Path, seen: frozenset[Path], depth: int,
                     fenced: list[str]) -> str:
    """Render a ``.qhelp`` file, resolving includes and inlining samples.

    *seen* is the cycle guard and *depth* the bound: an ``<include>`` chain that
    loops would otherwise recurse until the interpreter gives up, and a
    downloaded tree is exactly where a loop would come from. *fenced* collects
    the sample blocks so the caller can measure how much of the document is
    code, which is how :mod:`~training.corpus.sources.malwareanalysis` decides a
    mixed page's register and how this one reports its own composition.
    """
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    root = _parse_qhelp(raw)
    if root is None:
        return ""

    chunks: list[str] = []
    for element in root.iter():
        if element.tag == "include":
            src = (element.get("src") or "").strip()
            target = (path.parent / src).resolve() if src else None
            if (target is None or depth <= 0 or target in seen
                    or not target.is_file()):
                continue
            chunks.append(_render_help_xml(target, seen | {target}, depth - 1,
                                           fenced))
        elif element.tag == "sample":
            src = (element.get("src") or "").strip()
            block = _sample_block(path.parent, src)
            if block:
                fenced.append(block)
                chunks.append(block)
        elif element.tag == "pre":
            # A code block written inline rather than referenced as a file.
            # Only 14 of 1,812 qhelp files do this, which is precisely why it
            # is handled here and not left to be reflowed by _collapse: a
            # one-in-a-hundred path is the one a spot check misses.
            code = (element.text or "").strip("\n")
            if code.strip():
                block = f"```\n{code.rstrip()}\n```"
                fenced.append(block)
                chunks.append(block)

    body = _collapse(_inline(root))
    # Samples and includes are appended after the prose rather than spliced at
    # their position in it. Splicing would need the renderer to track character
    # offsets through a recursive walk, and getting that subtly wrong puts a
    # code block in the middle of a sentence — a failure that is invisible in a
    # spot check and poisonous in training data.
    return "\n\n".join(part for part in [body, *chunks] if part.strip())


def _sample_block(base: Path, src: str) -> str:
    """Read a referenced sample file and fence it with its name and language."""
    if not src:
        return ""
    target = (base / src).resolve()
    try:
        if not target.is_file() or target.is_symlink():
            return ""
        code = target.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    if not code.strip():
        return ""
    language = _LANGUAGE_BY_SUFFIX.get(target.suffix.lower(), "")
    return f"Example — {target.name}:\n```{language}\n{code.rstrip()}\n```"


#: Fence language hints. Not cosmetic: the fence tag is the token that tells a
#: reader (and a model) which language the block is, and the corpus already
#: relies on that convention through ``psdocs`` and ``internal``.
_LANGUAGE_BY_SUFFIX = {
    ".java": "java", ".cs": "csharp", ".py": "python", ".js": "javascript",
    ".ts": "typescript", ".cpp": "cpp", ".c": "c", ".h": "c", ".go": "go",
    ".rb": "ruby", ".php": "php", ".swift": "swift", ".kt": "kotlin",
    ".sql": "sql", ".xml": "xml", ".html": "html", ".htm": "html",
    ".aspx": "aspx", ".yml": "yaml", ".yaml": "yaml", ".ql": "ql",
}


def _render_help_md(path: Path, fenced: list[str]) -> str:
    """Markdown query help: kept as written, with its fences intact.

    Upstream has been migrating ``.qhelp`` to Markdown and 845 files have moved.
    Nothing is rendered here because nothing needs to be — the file is already
    text with fenced code in it, and the fences are the reason this source
    exists.
    """
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    fenced.extend(re.findall(r"```.*?```", raw, re.DOTALL))
    return raw


# ---------------------------------------------------------------------------
# query metadata
# ---------------------------------------------------------------------------

def _query_metadata(source: str) -> dict[str, str]:
    """Parse the ``/** @key value */`` header that opens every CodeQL query.

    Hand-parsed rather than regex-per-key because ``@tags`` is a multi-line
    value — the tags sit on their own indented continuation lines — and
    ``@description`` wraps. A line that starts a new ``@key`` ends the previous
    value; anything else continues it.
    """
    match = _QL_META.match(source)
    if match is None:
        return {}
    meta: dict[str, list[str]] = {}
    key = ""
    for line in match.group("body").split("\n"):
        found = _QL_KEY.match(line)
        if found is not None:
            key = found.group("key")
            meta.setdefault(key, []).append(found.group("value").strip())
            continue
        if key:
            stripped = re.sub(r"^\s*\*?\s?", "", line).strip()
            if stripped:
                meta[key].append(stripped)
    return {k: " ".join(v).strip() for k, v in meta.items() if any(v)}


def _cwe_line(tags: str) -> str:
    """Rewrite ``external/cwe/cwe-089`` tags as ``CWE-89``, keeping both forms.

    Both, because the corpus will be asked about ``CWE-89`` and the upstream
    writes neither that nor a bare integer. ``cwe`` makes the same move for the
    same reason, and the tokenizer measurement that started this project is the
    evidence: identifiers the corpus never carried in the world's spelling were
    where the domain tokenizer lost to gpt2 outright.
    """
    ids: list[str] = []
    for tag in tags.split():
        found = _CWE_TAG.match(tag)
        if found is not None:
            ids.append(f"CWE-{int(found.group(1))}")
    return ", ".join(dict.fromkeys(ids))


def _heading(meta: dict[str, str], ident: str, language: str) -> list[str]:
    """The shared opening block of both documents for one query."""
    lines = [meta.get("name") or ident]
    lines.append("")
    if meta.get("id"):
        lines.append(f"Query id: {meta['id']}")
    lines.append(f"Language: {language}")
    cwes = _cwe_line(meta.get("tags", ""))
    if cwes:
        lines.append(f"Weakness: {cwes}")
    if meta.get("tags"):
        lines.append(f"Tags: {' '.join(meta['tags'].split())}")
    for key, label in (("kind", "Kind"), ("problem.severity", "Severity"),
                       ("security-severity", "Security severity"),
                       ("precision", "Precision")):
        if meta.get(key):
            lines.append(f"{label}: {meta[key]}")
    if meta.get("description"):
        lines.append("")
        lines.append(meta["description"])
    return lines


# ---------------------------------------------------------------------------
# documents
# ---------------------------------------------------------------------------

def _queries(files: Path) -> Iterator[tuple[str, Path]]:
    """Yield ``(ident, path)`` for every ``.ql`` under a collected ``ql/src``.

    ``os.walk(followlinks=False)`` and an explicit symlink check per entry, for
    the reason stated in :func:`_scan_for_addresses`.
    """
    for dirpath, dirnames, filenames in os.walk(files, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames
                             if not Path(dirpath, d).is_symlink())
        for name in sorted(filenames):
            if not name.endswith(".ql"):
                continue
            path = Path(dirpath, name)
            if path.is_symlink():
                continue
            yield path.relative_to(files).as_posix(), path


def _help_for(query: Path, fenced: list[str]) -> str:
    """Find and render the help beside *query*, preferring Markdown.

    Preferring ``.md`` is not arbitrary: where both exist, upstream has migrated
    the content and the ``.qhelp`` is the older copy. Taking both would put two
    near-identical documents in a small corpus, which ``source.py`` is explicit
    is worse than taking neither.
    """
    for suffix in (".md", ".qhelp"):
        candidate = query.with_suffix(suffix)
        if candidate.name in _NOT_HELP or not candidate.is_file():
            continue
        if suffix == ".md":
            return _render_help_md(candidate, fenced)
        return _render_help_xml(candidate, frozenset({candidate.resolve()}),
                                _INCLUDE_DEPTH, fenced)
    return ""


def _documents(path: Path) -> Iterator[Document]:
    """Yield help (ADVERSARY), query (DETECTION) and guide (PROSE) documents."""
    files = path / "files"
    if not files.is_dir():
        raise SourceError(f"{_NAME}: no files/ under {path}; re-fetch")

    for ident, query in _queries(files):
        language = ident.split("/", 1)[0]
        try:
            source = query.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        meta = _query_metadata(source)
        heading = _heading(meta, ident, language)

        fenced: list[str] = []
        help_text = _help_for(query, fenced)
        if help_text.strip():
            body, _ = strip_emails("\n".join(heading + ["", help_text]))
            text = normalise(body)
            if len(text) >= _MIN_HELP_CHARS:
                yield Document(
                    text=text, source=_NAME, register=Register.ADVERSARY,
                    side=Side.NEUTRAL, ident=f"help/{ident}")

        body, _ = strip_emails("\n".join(
            heading + ["", "Detection query (CodeQL):", "", source.rstrip()]))
        text = normalise(body)
        if len(text) >= _MIN_QUERY_CHARS:
            yield Document(text=text, source=_NAME, register=Register.DETECTION,
                           side=Side.BLUE, ident=f"query/{ident}")

    yield from _prose_documents(files)


def _prose_documents(files: Path) -> Iterator[Document]:
    """One PROSE document per collected guide page, RST kept as written.

    No HTML or markup stripper runs over this. ``kerneldocs`` records what
    happens when one does to RST: a tag stripper measurably deleted sysfs
    metavariables and kernel-parameter formats, because ``<i>`` in that tree is
    a subscript and not an element. Only the directives listed in
    :data:`_RST_DROP` go, and they go because they are renderer passthrough or
    would dangle.
    """
    for directory in _DOC_DIRS:
        root = files / directory
        if not root.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames
                                 if not Path(dirpath, d).is_symlink())
            for name in sorted(filenames):
                if not name.endswith(".rst"):
                    continue
                page = Path(dirpath, name)
                if page.is_symlink():
                    continue
                try:
                    raw = page.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                body, _ = strip_emails(_RST_DROP.sub("", raw))
                text = normalise(body)
                if len(text) < _MIN_PROSE_CHARS:
                    continue
                yield Document(
                    text=text, source=_NAME, register=Register.PROSE,
                    side=Side.BLUE,
                    ident=f"docs/{page.relative_to(files / directory).as_posix()}")


SPEC = SourceSpec(
    name=_NAME,
    license=(
        "MIT — read from the repository's own LICENSE: 'MIT License / "
        "Copyright (c) 2006-2025 GitHub, Inc.', copied into the cache under "
        "licenses/LICENSE. The repository README states it directly: 'The code "
        "in this repository is licensed under the MIT License by GitHub'. "
        "NOT covered and not present here: the CodeQL CLI and engine, which "
        "live in github/codeql-cli-binaries under separate terms that require "
        "a commercial licence for closed-source analysis — this source "
        "collects query text and documentation only and runs nothing. "
        "The tree additionally carries roughly 160 third-party licence files "
        "(Apache-2.0 Kubernetes vendoring, the PSF licence, javamail, junit, "
        "aspectj, an OpenSSL stub), every one of them under */ql/test/**, "
        "*/extractor/, java/kotlin-extractor/deps/ or misc/. None of those "
        "trees is collected: this source reads only <lang>/ql/src/ and three "
        "named docs/codeql/ directories, and fetch FAILS if a licence-named "
        "file ever appears inside that set. "
        "Source: https://github.com/github/codeql/blob/main/LICENSE"
    ),
    url="https://github.com/github/codeql",
    register=Register.ADVERSARY,
    side=Side.NEUTRAL,
    fetch=_fetch,
    documents=_documents,
    expect_min_docs=3000,
    timeout=1800,
    notes=(
        "Labelled weakness patterns with their fix and their detection, for "
        "C, C++, C#, Go, Java, JavaScript, Python and GitHub Actions. The "
        "legitimate and most useful form of 'code that relates to "
        "exploitation': it teaches what a flaw looks like, which serves both "
        "halves of this project, and it is the shape juliet already proved "
        "valuable here, extended into six more languages and into "
        "detection-as-code. Two documents per query rather than one, because a "
        "single document holding prose, Java and QL has no register and "
        "labelling it anything would misreport it: the help (overview, "
        "recommendation, worked examples with the referenced samples inlined "
        "and fenced, references with their URLs) is ADVERSARY/NEUTRAL, matching "
        "juliet's bad/good pairing and NEUTRAL because every one carries the "
        "fix; the .ql source verbatim under its restated metadata is "
        "DETECTION/BLUE, matching sigma. Both carry the same @id so the halves "
        "co-occur through the identifier. external/cwe/cwe-089 tags are "
        "rewritten as CWE-89 beside the original, for the reason cwe gives. A "
        "third tier is PROSE: codeql-language-guides/, writing-codeql-queries/ "
        "and ql-language-reference/, which is prose about how to write a "
        "detection. Where a query has both .md and .qhelp help, the Markdown "
        "wins — upstream migrated the content and taking both would put two "
        "near-identical documents in a small corpus. qhelp <include> chains are "
        "resolved with a depth bound and a cycle guard; the DOCTYPE is removed "
        "before parsing so no external DTD is ever named by downloaded data. "
        "Samples are appended after the prose rather than spliced into it: "
        "splicing needs character offsets tracked through a recursive walk, and "
        "getting that subtly wrong puts a code block mid-sentence, which is "
        "invisible in a spot check. Excluded: */ql/test/ (~70 MB of .expected "
        "output and thousands of third-party-shaped fixtures, and where every "
        "nested licence lives), */extractor/ (compiler plumbing), ql-training/ "
        "(slide RST), images/ (9 MB of screenshots) and the .qll libraries. "
        "Mail addresses are stripped from every document; the fetched tree is "
        "counted into the cache marker and the emitted documents are counted "
        "by the test suite, so the strip is a measurement. Query metadata "
        "carries no @author field — checked, not assumed."
    ),
)
