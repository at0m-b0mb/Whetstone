"""The OWASP Cheat Sheet Series — the PROSE register, blue side.

This is the register the project's own output has to imitate. A Whetstone
``report.finding`` is meant to be argued and specific: here is the weakness,
here is why it matters in *this* system, here is the concrete change that
removes it. That is exactly the voice of a cheat sheet — "do not roll your own
session id, use the framework's; here is the cookie attribute set; here is what
breaks if you get ``SameSite`` wrong" — and it is a voice the corpus barely had.
The blue half of the corpus was detection logic (Sigma) and neutral reference;
blue *prose* was nearly absent, which meant the model had massed exposure to
what a defender's tooling looks like and almost none to how a defender argues.

One hundred and thirty documents is not a large source by character count, and
that is not the point of it. This is the densest defensive writing available
under a licence that can be trained on and published about, and it is uniformly
edited to one house style, so it is unusually consistent per byte.

**Licence: CC-BY-SA-4.0**, read from the repository's own ``LICENSE.md``, which
carries the line ``// SPDX-License-Identifier: CC-BY-SA-4.0`` above the Creative
Commons Attribution-ShareAlike 4.0 text. ``fetch`` copies that file into the
cache so the claim sits next to the text it covers. One page,
``Infrastructure_as_Code_Security_Cheat_Sheet.md``, carries an additional
in-document header — "Copyright 2021 Nokia … SPDX-License-Identifier:
CC-BY-SA-3.0". That header is deliberately *not* stripped: under a
ShareAlike licence the attribution notice is the obligation, and removing it to
tidy the text would be the one edit that actually matters legally.

**The fenced code stays.** 12.7% of this source is fenced blocks, and the info
strings say what they are: ``html`` (145 blocks), ``javascript`` (113), ``java``
(75), ``bash`` (59), ``python`` (58), ``csharp`` (55), ``php`` (54), ``xml``
(50). Those blocks are the remediation — a cheat sheet that said "parameterise
your queries" without showing ``PreparedStatement`` would be the worthless half
of the document. They are passed through untouched.

**Markup is stripped with a scalpel, and the reason is measured.** The contract
for this package says to remove markup that will never appear in real tool
output, after one adapter left a thousand orphaned ``<code>`` tags in its text.
Applied naively here it would be a catastrophe, because in *this* source the
angle brackets are the subject matter. Counting every ``<tag>`` in the 2.65 MB
of Markdown and excluding fenced blocks and inline code spans leaves exactly 79
tags in bare prose, of which 72 are ``<details>``/``<summary>`` collapse chrome
and 7 are the literal string ``<missing>`` in pasted ``docker history`` output.
Everything else that looks like markup — 834 tags inside fences, 160 more inside
backticks — is an XSS vector, a CSP example or a Spring config fragment. The
same holds for entities: ``&colon;``, ``&#x3c;`` and ``&NewLine;`` in
``XSS_Filter_Evasion_Cheat_Sheet.md`` *are* the payload, and a pass that decoded
them would delete the filter-evasion corpus in the name of cleaning it. So four
things are removed and nothing else:

* ``<details>`` / ``</details>`` lines (mkdocs collapse widgets, 36 of them);
* the ``<summary>`` wrapper, unwrapped to its caption text — "Bad example:
  Trusting client-supplied tenant ID" is content, the tag around it is not;
* whole-line linter directives — ``<!-- textlint-disable -->``,
  ``<!-- markdownlint-disable MD010-->`` — which are build machinery. Note how
  narrow that rule is: ``<!--#exec cmd="/bin/echo '<SCR'"-->`` and
  ``<!--[if gte IE 4]>`` in the same file are SSI and conditional-comment XSS
  vectors, and a rule that removed "HTML comments" would take them too;
* image references, all 79 of them ``![Slug](../assets/Something.png)``. The
  image is not in the corpus and the alt text is a filename, so this is the one
  place the source genuinely does carry markup with no referent.

**Drafts are included.** ``cheatsheets_draft/`` holds eight documents (123 KB)
that are unreleased only in the sense that they have not been merged into the
published index; they are finished prose under the same licence. Excluding them
would drop the source's own most detailed authorization-pattern writing for a
procedural reason that has nothing to do with text quality.

**Three of the four sub-1 KB files are redirect stubs** — "# DEPRECATED: The
Access Control cheatsheet has been deprecated. Please visit …" — and the fourth
is the same shape. They fall below the length floor and are dropped there rather
than by name, so the day upstream retires another cheat sheet the adapter does
not need editing.

**On the Web Security Testing Guide.** ``github.com/OWASP/wstg`` was checked:
its ``LICENSE`` is the same CC-BY-SA-4.0, so the licence permits it and it would
add several megabytes of genuinely red-side methodology prose. It is *not*
folded into this adapter, because ``build.py`` attributes register and side per
:class:`~training.corpus.source.SourceSpec`, not per
:class:`~training.corpus.source.Document` — ``balance_report`` sums
``stats.side``, which is the spec's. Yielding WSTG documents tagged
``Side.RED`` from a spec declared ``Side.BLUE`` would land correctly in the
JSONL and then be reported as blue in the one number the project uses to steer
the 60/40 offence balance. A source that lies to the balance report is worse
than a source that does not exist, so WSTG belongs in its own ``wstg`` adapter.

**What is not extracted, and why it is worth saying.** The upstream repository
ships ``AGENTS.md``, ``CLAUDE.md`` and a ``.claude/`` directory — instruction
files addressed to coding agents. They are skipped, partly because they are
project process rather than security guidance and would dilute what
``Register.PROSE`` means here, and partly on principle: text arriving over the
network is data to be tokenised, never instructions to be followed, and a
corpus adapter is a bad place to blur that line. ``Index*.md`` (link tables),
``templates/``, ``scripts/`` and the 158 files under ``assets/`` are skipped as
having no text worth training on.
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

_REPO = "OWASP/CheatSheetSeries"
_REF = "master"

#: A codeload tarball rather than ``git clone``: one 16 MB request, no history,
#: no git binary, and nothing on disk that a later ``git pull`` could mutate
#: underneath a build that is supposed to be reproducible.
_TARBALL_URL = f"https://codeload.github.com/{_REPO}/tar.gz/refs/heads/{_REF}"

#: The two directories that hold cheat sheets. Order matters only for the
#: reported ident prefix; pages are sorted before they are yielded.
_PAGE_DIRS: tuple[str, ...] = ("cheatsheets", "cheatsheets_draft")

_LICENSE_FILE = "LICENSE.md"

#: Written last, after the staging tree has been swapped into place, so its
#: presence means "extraction finished". An interrupted fetch therefore
#: re-downloads instead of leaving a half tree that a later run would mistake
#: for a complete cache and silently train on.
#:
#: It records ``ref``, ``url`` and the page directories that were actually
#: populated, and the warm path checks all three. Presence alone is not enough:
#: a marker that only vouches for ``cheatsheets/`` accepts a cache whose
#: ``cheatsheets_draft/`` has gone missing, which costs eight documents and
#: still clears :data:`expect_min_docs` — the one shape of loss that is loud
#: nowhere.
_MARKER = ".owasp-complete.json"

#: 122 cheat sheets plus 8 drafts were present when this was written. A floor
#: well below that turns an upstream rename of ``cheatsheets/`` into a loud
#: failure at fetch time rather than a mysteriously thin build report.
_MIN_EXTRACTED = 80

#: Above every redirect stub (the largest is 225 bytes) and far below the
#: smallest real cheat sheet (2,239 bytes), so the two separate cleanly without
#: naming any file.
_MIN_CHARS = 400

#: No single topic family may exceed this share of the source's characters.
#:
#: Measured with this module's own :func:`_family` over the 126 documents it
#: actually yields: identity and access (authentication, authorization,
#: session, SAML, OAuth, JWT, passwords) is the largest family at 17.7%, then
#: language and framework guides at 13.6%, injection at 12.6%, infrastructure
#: at 12.2%, web platform at 11.7%, process at 11.3%, AI at 7.9% and
#: cryptography at 3.1%; the remaining 9.9% is ``other``, meaning one-off topics
#: that share no family at all. Nothing is held back today.
#:
#: The cap exists anyway, as a tripwire rather than a filter. This source grows
#: by pull request, its recent growth is concentrated (six AI cheat sheets and
#: seven of the eight drafts are authorization), and the failure it guards
#: against has already happened once in this package: an uncapped SYSTEM source
#: turned out to be 54% Perl and Tcl API reference. A holdback prints, so the
#: day it fires it is visible in the build log instead of being discovered
#: later in a token histogram.
_FAMILY_CAP = 0.20

#: Keyword to family. Crude on purpose — a cleverer classifier would be a
#: second thing to keep correct, and the cap only has to catch a family large
#: enough to distort the register. Order matters: the first family whose
#: keyword appears in the filename wins, so the more specific groups come
#: first.
_FAMILIES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("ai", ("ai_", "ai-", "llm", "mcp_", "aml_", "rag_")),
    ("identity", (
        "authentication", "authorization", "access_control", "session",
        "multifactor", "saml", "oauth", "openid", "jwt", "json_web_token",
        "password", "credential", "security_questions", "identity_",
        "zero_trust", "account", "user_privacy",
    )),
    ("injection", (
        "xss", "cross_site_scripting", "dom_based", "dom_clobbering",
        "sql_injection", "injection", "query_parameterization",
        "xml_external", "deserialization", "ldap", "os_command",
        "server_side_request", "ssrf", "prototype_pollution",
        "mass_assignment", "file_upload", "unvalidated_redirect",
        "input_validation",
    )),
    ("langframework", (
        "dotnet", "java_", "jaas", "nodejs", "node_", "laravel", "django",
        "ruby", "php", "symfony", "rails", "golang", "python", "c-based",
        "nextjs", "bean_validation",
    )),
    ("infra", (
        "docker", "kubernetes", "infrastructure", "ci_cd", "secrets", "cloud",
        "virtual_patching", "network", "operating_system", "serverless",
        "github_actions", "database", "microservice",
    )),
    ("crypto", (
        "crypt", "key_management", "transport_layer", "tls", "certificate",
        "random", "pinning",
    )),
    ("web", (
        "http", "content_security", "cookie", "cors", "html5", "browser",
        "web_service", "rest", "graphql", "ajax", "third_party", "csrf",
        "cross-site_request", "clickjacking", "websocket", "grpc",
        "securing_cascading",
    )),
    ("process", (
        "threat_modeling", "abuse_case", "attack_surface", "secure_product",
        "vulnerability_disclosure", "vulnerable_dependency", "npm", "supply",
        "code_review", "devsecops", "logging", "error_handling", "forensic",
        "incident", "bug_bounty", "security_champion", "legacy_application",
        "dependency_graph", "sbom",
    )),
)

#: A whole line that is nothing but a ``<details>`` open or close tag. Anchored
#: at both ends so a ``<details>`` discussed inside a code example — which this
#: source does not currently contain, but a future HTML cheat sheet easily
#: could — is left alone unless it sits alone on its own line.
_DETAILS_LINE = re.compile(r"\A[ \t]*</?details(?:[ \t][^<>]*)?>[ \t]*\Z", re.I)

#: ``  <summary>Bad example: Trusting client-supplied tenant ID</summary>``.
#: The caption is kept, including its leading indentation: normalise() preserves
#: horizontal whitespace deliberately and this pass has no business deciding
#: otherwise.
_SUMMARY_LINE = re.compile(
    r"\A([ \t]*)<summary(?:[ \t][^<>]*)?>(.*?)</summary>[ \t]*\Z", re.I
)

#: A whole-line HTML comment that names a linter. Deliberately not "an HTML
#: comment": ``<!--#exec cmd="…"-->`` and ``<!--[if gte IE 4]>`` in
#: XSS_Filter_Evasion_Cheat_Sheet.md are attack payloads, and the broad rule
#: would quietly eat them.
_LINT_COMMENT = re.compile(
    r"\A[ \t]*<!--+[ \t]*/?(?:textlint|markdownlint|markdown-link-check|"
    r"prettier|cspell|spell-checker|vale)\b[^>]*-->[ \t]*\Z",
    re.I,
)

#: ``![XCode2](../assets/C-Based_Toolchain_Hardening_XCode2.png)`` — all 79
#: occurrences point into ``assets/``, which this adapter does not extract, and
#: all 79 sit outside fenced code (checked, not assumed). The alt text is a
#: slug, not a sentence, so the whole reference goes.
_IMAGE_REF = re.compile(r"!\[[^\]\n]*\]\([^)\n]*\)")


def _family(ident: str) -> str:
    """Group a page into a topic family for the concentration cap."""
    name = ident.rsplit("/", 1)[-1].casefold()
    for family, keywords in _FAMILIES:
        if any(keyword in name for keyword in keywords):
            return family
    return "other"


def _wanted(member_name: str) -> str | None:
    """Map a tar member name to its cache-relative path, or ``None`` to skip.

    Codeload wraps everything in ``CheatSheetSeries-<ref>/``, whose name changes
    with the ref, so the first component is dropped rather than matched.
    """
    parts = member_name.split("/")[1:]
    if not parts or any(part in ("", ".", "..") for part in parts):
        return None
    if len(parts) == 1 and parts[0] == _LICENSE_FILE:
        return parts[0]
    if parts[0] not in _PAGE_DIRS or not parts[-1].endswith(".md"):
        return None
    return "/".join(parts)


def _extract(archive: Path, staging: Path) -> int:
    """Unpack the cheat sheets and LICENSE.md into *staging*.

    Returns the number of ``.md`` pages written — not the number of files, so
    that a tarball which no longer carries a ``cheatsheets/`` tree still reports
    zero even though ``LICENSE.md`` was extracted from it. The caller's
    "upstream moved" diagnostic depends on that distinction.

    Members are written one at a time rather than through ``extractall``: the
    ``filter="data"`` argument that makes ``extractall`` safe only exists from
    Python 3.12 and this package targets 3.10. Only regular files are written,
    and every destination is proved to resolve inside *staging* first — a tar
    member name is attacker-controlled data in principle, and absolute paths,
    ``..`` segments and symlinks are all expressible in the format.
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
        raise SourceError(f"owasp: could not unpack {archive}: {exc}") from exc
    return written


def _fetch(cache_dir: Path) -> Path:
    """Populate *cache_dir* with the cheat sheet trees and return it.

    Idempotent and network-free on re-run: the build runs far more often than
    upstream changes, and a populated cache short-circuits on the marker file
    rather than on the directory, because a directory can exist and be half
    written. Nothing is created outside *cache_dir*, including the temporaries.

    The marker has to be *read*, not merely counted. Three cheap checks, each
    for a loss that is otherwise silent:

    * every page directory the marker says it populated is still a directory —
      a cache that kept ``cheatsheets/`` and lost ``cheatsheets_draft/`` yields
      118 documents instead of 126 and still clears ``expect_min_docs=100``, so
      nothing in the build log would say the drafts had gone;
    * the recorded ``ref`` and ``url`` match the ones this module declares —
      otherwise repointing :data:`_REF` at a tag keeps serving the old tree
      while the provenance file names the new one;
    * a marker written by an older version of this adapter, which recorded no
      page directories, is treated as stale. That costs exactly one re-download
      on first run after the upgrade.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    marker = cache_dir / _MARKER
    if marker.is_file():
        try:
            recorded = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            recorded = {}
        cached_dirs = recorded.get("page_dirs")
        if (isinstance(cached_dirs, list) and cached_dirs
                and recorded.get("ref") == _REF
                and recorded.get("url") == _TARBALL_URL
                and all(isinstance(name, str) and (cache_dir / name).is_dir()
                        for name in cached_dirs)):
            return cache_dir

    archive = cache_dir / "_cheatsheetseries.tar.gz"
    staging = cache_dir / "_incoming"
    shutil.rmtree(staging, ignore_errors=True)
    try:
        try:
            # net.download writes a .part sibling and renames, so an interrupted
            # transfer cannot leave a truncated archive behind.
            download(_TARBALL_URL, archive, timeout=300)
        except NetworkError as exc:
            raise SourceError(f"owasp: {exc}") from None

        written = _extract(archive, staging)
        if written < _MIN_EXTRACTED:
            raise SourceError(
                f"owasp: only {written} cheat sheet pages found in "
                f"{_TARBALL_URL} (expected >= {_MIN_EXTRACTED}). The upstream "
                "layout has probably changed — fix the adapter rather than "
                "training on a fraction of the blue prose register."
            )

        # Retire the marker BEFORE the swap starts destroying the tree it
        # vouches for. Removing the old directory and renaming the new one into
        # place is not atomic, and an interruption inside that window would
        # otherwise leave a current marker on top of a cheatsheets/ that had
        # been replaced and a cheatsheets_draft/ that had not yet been — which
        # the warm path above would accept. It is retired here rather than at
        # the top of the function so that a failed download leaves the existing
        # cache intact and usable offline.
        marker.unlink(missing_ok=True)

        # Swap into place only once the staging tree is known good, so a reader
        # never observes a partially written cheatsheets/ directory.
        populated: list[str] = []
        for subdir in _PAGE_DIRS:
            incoming = staging / subdir
            if not incoming.is_dir():
                continue
            final = cache_dir / subdir
            shutil.rmtree(final, ignore_errors=True)
            incoming.replace(final)
            populated.append(subdir)
        license_file = staging / _LICENSE_FILE
        if license_file.is_file():
            license_file.replace(cache_dir / _LICENSE_FILE)
    finally:
        archive.unlink(missing_ok=True)
        shutil.rmtree(staging, ignore_errors=True)

    marker.write_text(
        json.dumps(
            {
                "url": _TARBALL_URL,
                "repo": _REPO,
                "ref": _REF,
                # What the warm path is allowed to vouch for. Recorded rather
                # than assumed from _PAGE_DIRS: the day upstream drops
                # cheatsheets_draft/, requiring it would re-download the
                # tarball on every single build, forever.
                "page_dirs": populated,
                "pages": written,
                "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return cache_dir


def _pages(root: Path) -> list[tuple[str, Path]]:
    """Every cheat sheet under *root*, as (repo-relative ident, path), sorted.

    Walked with ``os.walk(..., followlinks=False)`` rather than ``rglob``. The
    tree here is one this adapter extracted itself and contains no links, but
    the rule is absolute in this package for a reason: a sibling adapter
    followed a ``data`` symlink out of its own directory and copied 180 MB of
    the corpus cache back into the corpus, relabelled. ``followlinks=False``
    only stops the walk *descending* into a symlinked directory, so symlinked
    files are rejected explicitly as well.
    """
    pages: list[tuple[str, Path]] = []
    for subdir in _PAGE_DIRS:
        base = root / subdir
        if not base.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            dirnames.sort()
            for filename in sorted(filenames):
                if not filename.endswith(".md"):
                    continue
                file = Path(dirpath) / filename
                if file.is_symlink() or not file.is_file():
                    continue
                pages.append((file.relative_to(root).as_posix(), file))
    pages.sort()
    return pages


def _family_budgets(pages: list[tuple[str, Path]]) -> dict[str, int]:
    """Character budget per over-represented family, from on-disk sizes.

    Byte size stands in for the post-cleaning character count. The cleaning pass
    removes well under a percent of this source, so a second full read to get an
    exact figure would buy nothing a tripwire needs.
    """
    sizes: dict[str, int] = {}
    total = 0
    for ident, file in pages:
        try:
            size = file.stat().st_size
        except OSError:
            continue
        sizes[_family(ident)] = sizes.get(_family(ident), 0) + size
        total += size
    if not total:
        return {}

    cap = int(total * _FAMILY_CAP)
    # "other" is not a family, it is the absence of one: 15 documents (9.9% of
    # the yielded characters) on unrelated topics that happen to share no
    # keyword — automotive, drones, bots, XS-Leaks, NoSQL, terminology. Capping
    # it would hold back the source's broadest coverage in the name of
    # protecting the corpus from breadth.
    #
    # The cost of that exemption, stated so it is not discovered later: a topic
    # family this crude classifier does not know about lands in "other" and is
    # therefore uncappable. Thirty new cheat sheets on one subject none of the
    # keyword lists mention would grow unchecked. If "other" ever climbs much
    # past its present share, that is the signal to teach :func:`_family` the
    # new family, not to cap the bucket.
    return {
        family: cap
        for family, size in sizes.items()
        if size > cap and family != "other"
    }


def _strip_chrome(text: str) -> str:
    """Remove publishing chrome; leave every angle bracket that means something.

    Line-oriented, and the anchors are load-bearing. ``<details>`` and
    ``<summary>`` are only recognised when they are the whole line, and an HTML
    comment is only removed when it names a linter — this source contains
    ``<!--#exec cmd="/bin/echo '<SCR'"-->`` and ``<!--[if gte IE 4]>`` as
    working XSS vectors, and the obvious "strip HTML comments" rule would
    delete them along with ``<!-- textlint-disable -->``.

    Nothing here collapses horizontal whitespace. Indentation inside fenced
    blocks is the shape of the remediation code, and a ``<summary>`` caption
    keeps whatever indent it had.
    """
    out: list[str] = []
    for line in text.split("\n"):
        if _DETAILS_LINE.match(line) or _LINT_COMMENT.match(line):
            continue
        summary = _SUMMARY_LINE.match(line)
        if summary is not None:
            caption = summary.group(2).strip()
            if caption:
                out.append(summary.group(1) + caption)
            continue
        stripped = _IMAGE_REF.sub("", line)
        # A line that was only an image reference becomes empty rather than
        # whitespace; normalise() then folds the blank run.
        out.append(stripped if stripped.strip() else "")
    return "\n".join(out)


def _documents(path: Path) -> Iterator[Document]:
    """Yield one Document per cheat sheet, in a stable sorted order.

    One document per page rather than one per ``##`` section. A cheat sheet is
    an argument that runs from threat to control to code sample, and splitting
    it at headings would hand the model the conclusion without the reasoning —
    which is precisely the half this source was added to supply.
    """
    root = path
    pages = _pages(root)
    if not pages:
        raise SourceError(
            f"owasp: no cheat sheets found under {root}. Expected "
            f"{'/, '.join(_PAGE_DIRS)}/ — run fetch first, or delete the cache "
            "and re-fetch if it is damaged."
        )

    budgets = _family_budgets(pages)
    spent: dict[str, int] = {}
    held_back: dict[str, int] = {}

    for ident, file in pages:
        try:
            # utf-8-sig: a stray U+FEFF at the head of a document would become a
            # token the model learns to expect before every heading.
            raw = file.read_text(encoding="utf-8-sig", errors="replace")
        except OSError as exc:
            raise SourceError(
                f"owasp: {ident} was listed but could not be read ({exc}). The "
                f"cache is damaged; delete {root} and re-fetch rather than "
                "shipping a corpus that is short by an unknown amount."
            ) from exc

        text = normalise(_strip_chrome(raw))
        if len(text) < _MIN_CHARS:
            continue  # deprecated redirect stubs land here

        family = _family(ident)
        cap = budgets.get(family)
        if cap is not None:
            if spent.get(family, 0) + len(text) > cap:
                held_back[family] = held_back.get(family, 0) + 1
                continue
            spent[family] = spent.get(family, 0) + len(text)

        yield Document(
            text=text,
            source="owasp",
            register=Register.PROSE,
            side=Side.BLUE,
            ident=ident,
        )

    # No silent caps: say what was held back and why.
    for family, count in sorted(held_back.items(), key=lambda kv: -kv[1]):
        print(f"   owasp: held back {count} {family} cheat sheet(s) at the "
              f"{_FAMILY_CAP:.0%} per-family cap")


SPEC = SourceSpec(
    name="owasp",
    license=(
        "CC-BY-SA-4.0 — OWASP Cheat Sheet Series, LICENSE.md "
        "(SPDX-License-Identifier: CC-BY-SA-4.0). One page, "
        "Infrastructure_as_Code_Security_Cheat_Sheet.md, additionally carries "
        "'Copyright 2021 Nokia, CC-BY-SA-3.0' in its own header, which is kept "
        "in the document text as the attribution the licence requires."
    ),
    url="https://github.com/OWASP/CheatSheetSeries",
    register=Register.PROSE,
    side=Side.BLUE,
    fetch=_fetch,
    documents=_documents,
    #: 122 published cheat sheets and 8 drafts upstream, less four deprecated
    #: redirect stubs that fall under the length floor. The floor sits below the
    #: observed 126 rather than at it, because cheat sheets are retired by being
    #: replaced with a stub and the count drifts down by ones.
    expect_min_docs=100,
    notes=(
        "cheatsheets/ and cheatsheets_draft/ as whole documents. Fenced code "
        "(12.7% of the text: html, javascript, java, bash, python, csharp, php, "
        "xml) is kept verbatim — it is the remediation half of the argument. "
        "Only four kinds of markup are removed: <details>/<summary> collapse "
        "chrome, whole-line linter comments, and ../assets image references. "
        "HTML tags and entities are otherwise left alone because in this source "
        "they are XSS payloads and CSP examples, not markup. Index*.md, "
        "templates/, scripts/, assets/ and the repository's agent-instruction "
        "files (AGENTS.md, CLAUDE.md, .claude/) are not extracted. The Web "
        "Security Testing Guide is the same licence and belongs in its own "
        "adapter: it is red-side, and build.py attributes side per spec."
    ),
)
