"""Microsoft's PowerShell cmdlet reference — the SHELL register, Windows side.

The first corpus was Python, C and Markdown, and the tokenizer comparison said
exactly what that cost: where the corpus carried the register, the domain
tokenizer won by up to 47%; where it did not, gpt2 won outright. PowerShell was
not merely under-represented, it was close to absent — and PowerShell is the
shell a Windows operator, a Windows attacker and every Windows detection rule
are all written in. A model that cannot emit ``Get-CimInstance -ClassName
Win32_Service | Where-Object State -eq 'Running'`` or read back what it printed
has no Windows capability at all, however much ATT&CK prose it has seen.

``reference/<version>/<Module>/`` is the densest PowerShell text that exists
under a licence we can train on: 32% of every cmdlet page is fenced code, and
the unfenced remainder is parameter tables, ``-ParameterName <Type[]>`` syntax
blocks and Verb-Noun names in backticks. **The fences are kept verbatim.** They
are the entire reason this source exists; a pass that stripped them would leave
prose *about* PowerShell and none of the surface form a BPE actually learns.

Three judgement calls are worth stating, because none of them is obvious:

**Only two of the five version trees are read.** Upstream ships ``5.1``, ``7.4``,
``7.5``, ``7.6`` and ``7.7`` side by side, 2439 pages in total — but the 7.x
trees are servicing branches of one another, and ``Get-Process.md`` is
*byte-identical* between 7.6 and 7.7 below the frontmatter. Taking all five
would make roughly three quarters of this source duplicated text, and
``source.py`` is explicit that duplication in a small corpus is worse than
absence because the model memorises it. So the 7.x trees collapse to one (newest
first, older versions contributing only pages the newest dropped), while ``5.1``
is kept as a genuinely separate generation: Windows PowerShell has cmdlets that
PowerShell 7 does not ship at all — ``Get-WmiObject``, ``PSScheduledJob``,
``Microsoft.PowerShell.LocalAccounts`` — and those are precisely the Windows-side
tokens the corpus was missing. Pages that survive as exact duplicates across the
two generations are dropped here rather than left for the build's fingerprint
pass, so the reported count is the honest one.

**The frontmatter is filtered line-by-line, never parsed.** Most of it is
publishing metadata — ``ms.date``, ``schema: 2.0.0``, an ``online version`` URL
carrying a ``&WT.mc_id=ps-gethelp`` tracking parameter — repeated identically on
a thousand pages. But ``aliases`` is real PowerShell surface: ``gps``, ``ps``,
``%``, ``?``, ``select`` appear *nowhere else in the page*, and they are how the
language is actually typed. Keeping them rules out ``yaml.safe_load``, because
``- %`` is an unquoted YAML directive indicator and PyYAML raises a
``ScannerError`` on it — parsing the frontmatter silently loses ``ForEach-Object``
and its ``%`` alias, one of the most-typed tokens in the language. A textual
keep-list survives malformed YAML by not caring about it.

**``About/`` is in; ``docs-conceptual/`` is out.** The ``about_*.md`` topics live
inside the module directories, ship as ``Get-Help about_Operators`` output, and
measure 22% fenced code with the remainder discussing operators, splatting and
hash-table syntax token by token. ``reference/docs-conceptual/`` is the other
thing — install guides, .NET interop essays, release notes — prose that would be
labelled SHELL by this spec and would be a lie about the register.

Licence, both halves stated because upstream splits them: the documentation
prose is **CC BY 4.0** (``LICENSE.md``) and the code samples inside it are
**MIT** (``LICENSE-CODE.md``). ``fetch`` copies both files into the cache so the
claim stays checkable next to the text it covers.
"""

from __future__ import annotations

import re
import shutil
import ssl
import tarfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Iterator

from ..net import ssl_context as _shared_ssl_context
from ..source import Document, Register, Side, SourceError, SourceSpec, fingerprint, normalise

#: A codeload tarball is one request and ~29 MB; ``git clone`` of this repo is
#: several hundred MB of history we would immediately throw away.
_TARBALL_URL = (
    "https://codeload.github.com/MicrosoftDocs/PowerShell-Docs/tar.gz/refs/heads/main"
)

#: Written last, after the extraction succeeds. Its presence — not the presence
#: of the directory — is what makes ``fetch`` skip the download, so an
#: interrupted run re-fetches instead of yielding a half tree.
_MARKER = ".psdocs-complete"

_REFERENCE = "reference"
_LICENSE_FILES = ("LICENSE.md", "LICENSE-CODE.md")

_TIMEOUT = 300

#: Trust stores to fall back on when the interpreter's own OpenSSL directory is
#: empty. The python.org macOS framework build ships with no CA bundle until
#: somebody runs ``Install Certificates.command``, so ``urlopen`` fails
#: ``CERTIFICATE_VERIFY_FAILED`` on a machine where ``curl`` works fine. These
#: are the system bundles OpenSSL would have used anyway — verification is never
#: turned off, which in a security project would be an unusually poor joke.
_CA_BUNDLES = (
    "/etc/ssl/cert.pem",                    # macOS
    "/etc/ssl/certs/ca-certificates.crt",   # Debian, Ubuntu, Alpine
    "/etc/pki/tls/certs/ca-bundle.crt",     # RHEL, Fedora
    "/etc/ssl/ca-bundle.pem",               # SUSE
)

#: ``reference/5.1``, ``reference/7.7`` — the per-version documentation trees.
_VERSION_DIR = re.compile(r"\A(?P<major>\d+)\.(?P<minor>\d+)\Z")

#: The leading ``---`` fenced YAML block, non-greedy so it ends at the first
#: closing fence rather than at a horizontal rule further down the page.
_FRONTMATTER = re.compile(r"\A---[ \t]*\n(?P<block>.*?)\n---[ \t]*\n", re.DOTALL)

#: A top-level frontmatter key. Keys here contain spaces (``Module Name``,
#: ``online version``, ``external help file``), so this is looser than a plain
#: identifier match.
_FM_KEY = re.compile(r"\A(?P<key>[A-Za-z][A-Za-z0-9 ._'-]*?)\s*:")

#: Frontmatter keys that carry content rather than publishing machinery. This is
#: a keep-list rather than a drop-list because every key upstream adds in future
#: is far more likely to be another build directive than another alias table.
_FM_KEEP = frozenset({
    "title",         # the cmdlet name, e.g. Get-Process
    "module name",   # which module ships it — real context, not metadata
    "aliases",       # gps, ps, %, ? — surface form found nowhere else on the page
    "description",   # one-line summary on provider and about_ pages
    "no-no-loc",     # a literal list of parameter names, e.g. -EncodedCommand
})

#: Short of this a page is a stub or a redirect placeholder, not documentation.
#: Matches the floor the other adapters in this package use.
_MIN_CHARS = 200


def _fetch(cache_dir: Path) -> Path:
    """Populate *cache_dir* with ``reference/**/*.md`` and return that root.

    Idempotent and cheap on re-run: if the completion marker is present the
    function returns without touching the network, because the build runs far
    more often than upstream changes.

    Only Markdown under ``reference/`` is unpacked. The repo also carries ~90 MB
    of screenshots, redirect tables and CI scripts that no corpus pass reads, and
    extracting them would cost more disk and time than the download itself.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    root = cache_dir / _REFERENCE
    if (cache_dir / _MARKER).exists() and root.is_dir():
        return root

    archive = cache_dir / "_powershell-docs.tar.gz"
    staging = cache_dir / "_incoming"
    try:
        _download(_TARBALL_URL, archive)
        if staging.exists():
            shutil.rmtree(staging)
        staging.mkdir(parents=True)
        extracted = _extract(archive, staging)
        if extracted == 0:
            raise SourceError(
                "psdocs: the tarball contained no reference/**/*.md files. "
                "Upstream has almost certainly moved the reference tree; the "
                "adapter needs updating rather than retrying."
            )

        # Swap into place only once the staging tree is known good, so a reader
        # never sees a partially written reference/.
        if root.exists():
            shutil.rmtree(root)
        (staging / _REFERENCE).rename(root)
        for name in _LICENSE_FILES:
            candidate = staging / name
            if candidate.is_file():
                candidate.replace(cache_dir / name)
    finally:
        archive.unlink(missing_ok=True)
        shutil.rmtree(staging, ignore_errors=True)

    (cache_dir / _MARKER).write_text(f"{_TARBALL_URL}\n", encoding="utf-8")
    return root


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


def _download(url: str, dest: Path) -> None:
    """Stream *url* to *dest*, failing loudly rather than leaving a stub."""
    request = urllib.request.Request(url, headers={"User-Agent": "whetstone-corpus/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT,
                                    context=_ssl_context()) as response, \
                dest.open("wb") as handle:
            shutil.copyfileobj(response, handle, length=1 << 20)
    except (urllib.error.URLError, OSError) as exc:
        dest.unlink(missing_ok=True)
        raise SourceError(f"psdocs: could not download {url}: {exc}") from exc


def _extract(archive: Path, staging: Path) -> int:
    """Unpack the Markdown and licence files, stripping the top-level directory.

    Returns the number of ``reference/`` pages written — **not** the number of
    files written. The two licence files are always extracted and would
    otherwise make the count non-zero on a tarball that no longer carries a
    reference tree at all, turning the caller's "upstream moved" diagnostic into
    a bare ``FileNotFoundError`` from the rename — after the caller had already
    deleted the previous, perfectly good cache.

    Members are written one at a time rather than via ``extractall`` so that
    path traversal is impossible on every supported Python: the ``filter="data"``
    argument that would otherwise handle it only exists from 3.12, and this
    package targets 3.10.
    """
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
                target = (staging / relative).resolve()
                if not target.is_relative_to(staging_resolved):
                    continue  # traversal attempt; silently refuse the member
                source = tar.extractfile(member)
                if source is None:
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with source, target.open("wb") as handle:
                    shutil.copyfileobj(source, handle)
                if relative.startswith(_REFERENCE + "/"):
                    written += 1
    except (tarfile.TarError, OSError) as exc:
        raise SourceError(f"psdocs: could not unpack {archive}: {exc}") from exc
    return written


def _wanted(name: str) -> str | None:
    """Map a tar member name to its cache-relative path, or ``None`` to skip.

    Codeload wraps everything in a ``PowerShell-Docs-<branch>/`` directory whose
    name changes with the branch, so the first component is dropped rather than
    matched.
    """
    parts = name.split("/")[1:]
    if not parts or any(part in ("", ".", "..") for part in parts):
        return None
    if len(parts) == 1 and parts[0] in _LICENSE_FILES:
        return parts[0]
    if parts[0] != _REFERENCE or not parts[-1].endswith(".md"):
        return None
    return "/".join(parts)


def _version_key(name: str) -> tuple[int, int] | None:
    match = _VERSION_DIR.match(name)
    if match is None:
        return None
    return int(match.group("major")), int(match.group("minor"))


def _select_pages(root: Path) -> list[tuple[str, Path]]:
    """Choose one page per (generation, module-relative path), newest version wins.

    Generation is the major version: everything under ``7.*`` is one lineage of
    the same document set, and ``5.1`` is Windows PowerShell, a different product
    with cmdlets PowerShell 7 never shipped. Keeping one page per generation
    preserves the editorial difference that matters — ``Get-Process`` really is
    documented differently on Windows PowerShell — while discarding the 7.4/7.5/7.6
    servicing copies that differ from 7.7 only in a URL inside the frontmatter.

    Walking each generation newest-first and taking the first sighting of a
    relative path also rescues the handful of pages that exist in an older 7.x
    tree but were removed from the newest one.
    """
    generations: dict[int, list[tuple[tuple[int, int], Path]]] = {}
    for child in root.iterdir():
        if not child.is_dir():
            continue
        key = _version_key(child.name)
        if key is None:
            continue  # docs-conceptual, media, includes, module, mapping, bread
        generations.setdefault(key[0], []).append((key, child))

    selected: list[tuple[str, Path]] = []
    for major in sorted(generations, reverse=True):
        seen: set[str] = set()
        for _, version_dir in sorted(generations[major], key=lambda item: item[0], reverse=True):
            for page in sorted(version_dir.rglob("*.md")):
                relative = page.relative_to(version_dir).as_posix()
                if relative in seen:
                    continue
                seen.add(relative)
                selected.append((page.relative_to(root).as_posix(), page))
    return selected


def _strip_metadata(text: str) -> str:
    """Drop publishing metadata from the frontmatter, keep the content keys.

    Line-based on purpose. A continuation line (``  - gps``) inherits the
    keep/drop decision of the key above it, which means the block survives values
    PyYAML refuses to scan — and the one page this actually saves,
    ``ForEach-Object``, has ``%`` as its alias.
    """
    match = _FRONTMATTER.match(text)
    if match is None:
        return text

    kept: list[str] = []
    keeping = False
    for line in match.group("block").split("\n"):
        key_match = _FM_KEY.match(line)
        if key_match is not None:
            keeping = key_match.group("key").strip().casefold() in _FM_KEEP
        elif not line.strip():
            continue
        if keeping:
            kept.append(line)

    body = text[match.end():]
    if not kept:
        return body
    return "---\n" + "\n".join(kept) + "\n---\n" + body


def _documents(path: Path) -> Iterator[Document]:
    """Yield one document per selected reference page, fenced code intact.

    Exact duplicates are dropped here using the same fingerprint the build uses,
    so the count this source reports is the count it contributes. Around 80
    Windows PowerShell 5.1 pages are word-for-word identical to their PowerShell 7
    counterparts; leaving them in would inflate the report and then have them
    silently removed downstream.
    """
    seen: set[str] = set()
    for ident, page in _select_pages(path):
        try:
            # utf-8-sig because a minority of these files carry a BOM, and a
            # stray U+FEFF at the head of a document is a token the model would
            # otherwise learn to expect before every cmdlet name.
            raw = page.read_text(encoding="utf-8-sig", errors="replace")
        except OSError:
            continue
        text = normalise(_strip_metadata(raw.replace("\r\n", "\n")))
        if len(text) < _MIN_CHARS:
            continue
        key = fingerprint(text)
        if key in seen:
            continue
        seen.add(key)
        yield Document(text=text, source="psdocs", register=Register.SHELL,
                       side=Side.NEUTRAL, ident=ident)


SPEC = SourceSpec(
    name="psdocs",
    license="CC BY 4.0 (documentation) and MIT (code samples) — Microsoft Corporation",
    url="https://github.com/MicrosoftDocs/PowerShell-Docs",
    register=Register.SHELL,
    side=Side.NEUTRAL,
    fetch=_fetch,
    documents=_documents,
    expect_min_docs=800,
    notes=("Cmdlet reference and about_* topics from reference/<version>/<Module>/ "
           "for Windows PowerShell 5.1 and the newest PowerShell 7.x, deduplicated "
           "across the servicing branches. Verb-Noun names, parameter syntax blocks "
           "and worked examples with their fenced code kept verbatim. "
           "reference/docs-conceptual/ is deliberately excluded: it is prose, and "
           "labelling it SHELL would misreport the register."),
)
