"""Real PowerShell source code — the SHELL register, written rather than described.

Whetstone ships a Windows adapter that *is* PowerShell:
:mod:`whetstone.adapters.windows` answers thirty verbs by handing ``pwsh`` an
argv list and parsing what comes back. So PowerShell is not a language this
model needs to recognise, it is a language this model needs to **write** — and
the two are trained by different text. The corpus already carries ``psdocs``,
Microsoft's reference documentation, at 7.8% of the whole; that is prose *about*
PowerShell, and prose about a language teaches its vocabulary without teaching
its idiom. A reference page for ``Get-CimInstance`` tells you the parameter
names. It does not show you what a two-hundred-line function that uses it looks
like: ``[CmdletBinding(SupportsShouldProcess)]`` over the ``param`` block,
``[Parameter(Mandatory, ValueFromPipelineByPropertyName)]`` on the arguments,
``[ValidateSet()]`` narrowing them, ``begin``/``process``/``end`` splitting the
pipeline, a hash table splatted with ``@params``, ``-ErrorAction Stop`` inside a
``try``/``catch`` because that is the only way a non-terminating error becomes
catchable, ``$PSCmdlet.ShouldProcess`` gating the destructive branch,
``Write-Verbose`` where a novice writes ``Write-Host``, and a
``[pscustomobject]`` returned so the next command in the pipeline has properties
to bind to. None of that is in a cmdlet reference. All of it is in the files
this adapter collects.

It is also the Windows half of closing the corpus's largest gap. SHELL is the
thinnest register in the build — 15.6% observed against a 26% target in
:data:`~training.corpus.source.REGISTER_TARGETS` — and thin *there* is the
expensive kind of thin, because SHELL is the register the model must both emit
and read back.

**Nine repositories, on purpose.** One repository teaches one team's habits, and
a model fitted to one team's habits writes that team's PowerShell everywhere.
These were chosen to disagree with each other stylistically while all being
competent, and every licence below was read from the repository rather than
inferred from a badge:

* ``PowerShell/PowerShell`` (MIT) — the shell itself. ``test/`` is the prize:
  several thousand Pester tests written by the people who define the language,
  exercising every cmdlet against expected output. ``tools/`` adds release and
  packaging automation, which is long-form procedural PowerShell of a kind tests
  never show.
* ``pester/Pester`` (Apache-2.0) — the test framework. ``src/`` is a large,
  carefully written module; ``tst/`` is that module testing itself.
* ``PowerShell/PSScriptAnalyzer`` (MIT) — the linter. Its tests encode, rule by
  rule, what the language's own maintainers consider *good* PowerShell, which is
  an unusually direct signal and hard to obtain any other way.
* ``PowerShell/PSReadLine`` (BSD-2-Clause) and ``PowerShell/platyPS`` (MIT) —
  small, but two more independent authors.
* ``PowershellFrameworkCollective/PSFramework`` (MIT) — a module-authoring
  framework; hundreds of small functions, nearly all carrying full
  comment-based help.
* ``dataplat/dbatools`` (MIT) — the largest well-maintained administration
  module in the ecosystem. Seven hundred ``Verb-Noun`` functions, each opening
  with ``<# .SYNOPSIS … .EXAMPLE #>``. This is the closest public analogue to
  the kind of code Whetstone's own Windows adapter is made of.
* ``PowerShellMafia/PowerSploit`` (BSD-3-Clause) and ``microsoft/AaronLocker``
  (MIT) — the purple pair. This corpus is weighted 60/40 toward offence by
  design, and offensive PowerShell has a distinct surface the defensive half
  never shows: ``Add-Type`` with inline C#, P/Invoke signatures,
  ``[Ref].Assembly`` reflection, token manipulation, ``Out-EncodedCommand``.
  AaronLocker is the answer to it in the same language — AppLocker and WDAC
  policy generation, ``Get-WinEvent`` XPath filters over the audit log. Both are
  published, clearly licensed tooling; PowerSploit is archived upstream, which
  affects its currency, not its licence or its idiom.

**Comment-based help is why file selection is biased the way it is.** A
``<# .SYNOPSIS … .EXAMPLE … #>`` block is prose sitting directly against the
code it describes, in one document, in the language's own convention — the
single most useful shape there is for teaching a language, because it pairs
intent with implementation without either being translated. Where a repository
is too large to take whole, files carrying help are kept in preference to files
that do not.

Traps this adapter exists to avoid, each of which was a real decision:

**Horizontal whitespace is never collapsed.** That is the contract in
:func:`~training.corpus.source.normalise` and it matters more here than
anywhere. Indentation in source code is meaning; worse, PowerShell here-strings
(``@" … "@``) contain leading spaces that are *literal data*, so flattening them
does not merely uglify the code, it changes what the script would output.

**A size cap, and it is doing real work.** ``Invoke-Mimikatz.ps1`` is 2.2 MB, of
which roughly 98% is one base64 string holding a PE file. That is not PowerShell
— it is a payload spelled in base64 — and a BPE fitted to it learns base64.
``PowerView.ps1`` and ``PowerUp.ps1`` (770 KB and 600 KB) are genuine code but
are single documents that would each outweigh a hundred ordinary functions, so
the cap takes them too, and that loss is accepted deliberately rather than
worked around. Three files in the PowerShell repository's own test and packaging
trees go the same way. Below the cap, a long-line and base64-run gate catches
encoded payloads and obfuscated one-liners small enough to slip under it; those
two gates together reject 107 of the 2,268 files that reach them, which is about
the rate you would expect and not the rate of a filter that has run amok.

**Test-fixture garbage is not test code.** PSScriptAnalyzer's ``Tests/`` tree
holds about 114 files that are not tests at all but *deliberate violations* —
``Tests/DisabledRules/AvoidUsingClearHost.ps1`` is one line reading
``Clear-Host`` — kept upstream so the linter has something to complain about.
Training on those teaches precisely the thing the repository exists to forbid.
Within that repository only ``*.tests.ps1`` and ``*.psm1`` are taken, so the bad
line is only ever seen inside an assertion naming the rule that rejects it.

**The BOM is sniffed before decoding.** Windows PowerShell's ``Out-File`` wrote
UTF-16LE by default until 6.0, so UTF-16 ``.ps1`` files are ordinary in Windows
source trees. Not one survived into the current selection — that was checked,
not assumed — but the guard stays because the failure it prevents is the silent
kind: decoding UTF-16 as UTF-8 does not raise, the interleaved NUL bytes are
stripped by ``normalise`` as control characters, and what comes out looks almost
right while every non-ASCII character has become mojibake. A trap that announces
itself can be fixed later; this one would sit in the corpus unnoticed. The only
replacement characters in the current output are 61 of them in
``Format-Hex.Tests.ps1``, which contains deliberately invalid byte sequences
because testing a hex formatter is what it is for.

**Symlinks are never followed**, via ``os.walk(followlinks=False)``. The lesson
is ``ownrepos``': it once followed a symlink into the corpus cache and pulled
180 MB of the corpus back in as training data. This adapter's own cache lives on
that same external volume.

**Deduplication spans repositories, and is mostly insurance.** These projects
vendor each other — Pester ships inside other test harnesses, several trees
carry copies of the same build scaffolding — but the path prefixes above already
exclude where most of that lands, and only three duplicates survive to be caught
in the current selection. The pass stays because prefixes are the thing most
likely to be widened by a future edit, and because
:func:`~training.corpus.source.fingerprint` case-folds and discards whitespace
before hashing: a re-indented copy collapses onto its original instead of
surviving as the near-duplicate a small corpus memorises rather than learns.

Not collected: ``.psd1`` manifests (GUIDs and version tables, machine-written),
``docs/*.md`` (``psdocs``' job, and labelling documentation SHELL would misreport
the register), and anything under ``bin``, ``obj``, ``packages`` or an ``assets``
fixture directory. The two-line ``# Copyright (c) Microsoft Corporation.``
header that opens most files in the Microsoft trees is deliberately left in
place: ``build.py``'s boilerplate pass runs across the whole corpus and is the
only thing that can see a line recurring often enough to be furniture.

**Licence.** Composite, and recorded per repository rather than averaged into a
single comfortable claim. Each upstream ``LICENSE`` file is copied into
``licences/`` in the cache beside the code it covers, and ``manifest.json``
records each tarball's SHA-256, its ref and the file count extracted, so the
claim in :data:`SPEC` stays checkable.
"""

from __future__ import annotations

import codecs
import hashlib
import json
import os
import re
import shutil
import tarfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

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


@dataclass(frozen=True, slots=True)
class _Repo:
    """One upstream repository and the part of it worth training on."""

    #: Directory name in the cache. Short, stable, and independent of the slug
    #: so renaming an upstream org does not invalidate an existing cache.
    key: str
    slug: str
    ref: str
    #: SPDX identifier, read from the repository's own LICENSE file.
    license: str
    #: Path prefixes (repository-relative, POSIX) that are extracted at all.
    #: Everything else in the tarball is dropped during extraction rather than
    #: after it — dbatools is a 95 MB snapshot that leaves 6 MB on disk.
    prefixes: tuple[str, ...]
    #: Lowercased filename suffixes kept within those prefixes. Overridden for
    #: PSScriptAnalyzer, whose Tests/ tree is half deliberate-violation fixtures.
    suffixes: tuple[str, ...] = (".ps1", ".psm1")


#: A codeload tarball rather than ``git clone --depth 1``: one request, no git
#: binary required, no working tree that a later ``git pull`` could mutate
#: underneath a reproducible build — and, unlike a clone, members can be
#: filtered *during* extraction so only the PowerShell ever reaches the disk.
_TARBALL = "https://codeload.github.com/{slug}/tar.gz/refs/heads/{ref}"

_REPOS: tuple[_Repo, ...] = (
    _Repo(key="powershell", slug="PowerShell/PowerShell", ref="master",
          license="MIT", prefixes=("test/", "tools/")),
    _Repo(key="pester", slug="pester/Pester", ref="main",
          license="Apache-2.0", prefixes=("src/", "tst/")),
    # Only the real Pester tests and modules here; see the module docstring on
    # the DisabledRules fixtures, which are violations kept on purpose.
    _Repo(key="psscriptanalyzer", slug="PowerShell/PSScriptAnalyzer", ref="main",
          license="MIT", prefixes=("Tests/", "Engine/", "PSCompatibilityCollector/"),
          suffixes=(".tests.ps1", ".psm1")),
    _Repo(key="psreadline", slug="PowerShell/PSReadLine", ref="master",
          license="BSD-2-Clause", prefixes=("PSReadLine/", "test/", "tools/")),
    _Repo(key="platyps", slug="PowerShell/platyPS", ref="main",
          license="MIT", prefixes=("src/", "test/")),
    _Repo(key="psframework", slug="PowershellFrameworkCollective/PSFramework",
          ref="development", license="MIT", prefixes=("PSFramework/",)),
    # public/ and private/ only. tests/ is another 4.4 MB, but dbatools'
    # integration tests are highly formulaic — near-identical scaffolding per
    # command — and this repository is already the one the per-repo cap bites.
    _Repo(key="dbatools", slug="dataplat/dbatools", ref="development",
          license="MIT", prefixes=("public/", "private/")),
    _Repo(key="powersploit", slug="PowerShellMafia/PowerSploit", ref="master",
          license="BSD-3-Clause",
          prefixes=("AntivirusBypass/", "CodeExecution/", "Exfiltration/",
                    "Mayhem/", "Persistence/", "Privesc/", "Recon/",
                    "ScriptModification/", "Tests/")),
    _Repo(key="aaronlocker", slug="microsoft/AaronLocker", ref="main",
          license="MIT", prefixes=("AaronLocker/",)),
)

#: Extracted alongside the code so the licence claim is checkable next to the
#: text it covers. Matched case-insensitively against the tarball root only.
_LICENCE_NAMES = frozenset({
    "license", "license.txt", "license.md",
    "licence", "licence.txt", "licence.md",
    "copying", "copying.txt", "notice", "notice.txt",
})

#: Directory names never descended into, in either extraction or the walk.
#: ``assets`` is the fixture convention in the PowerShell test tree: binaries,
#: malformed inputs and expected-output blobs, none of it code.
_SKIP_DIRS = frozenset({
    ".git", ".github", ".vs", ".vscode", "bin", "obj", "packages",
    "node_modules", "assets", "testresults", "__pycache__",
})

#: Above this a file is a vendored monolith or a payload, not a readable script.
#: See the docstring: this is what keeps a 2.2 MB base64 blob out of a corpus
#: whose whole point is surface form.
_MAX_BYTES = 128 * 1024

#: Below this there is no idiom to learn — a one-line fixture, a stub, a
#: three-line ``Export-ModuleMember``.
_MIN_CHARS = 400

#: A source line longer than this is minified, generated, or an encoded
#: payload. Real PowerShell wraps; even an unusually long pipeline stays well
#: inside it.
_MAX_LINE = 800

#: A base64 run this long is a certificate, an assembly or shellcode. It
#: catches the encoded payloads that are small enough to pass ``_MAX_BYTES``.
_BLOB = re.compile(r"[A-Za-z0-9+/]{300,}={0,2}")

#: Enough structure to be worth calling PowerShell. Deliberately generous —
#: this rejects stray data files that happen to carry a ``.ps1`` extension, not
#: unusual code.
_POWERSHELL = re.compile(
    r"(?mi)^\s*(?:function|filter|class|param|configuration|describe|context|it|"
    r"before(?:all|each)|\[cmdletbinding)\b"
    r"|\$(?:[A-Za-z_][A-Za-z0-9_]*|PSCmdlet|_)\b"
    r"|\b(?:Get|Set|New|Remove|Add|Invoke|Test|Write|Import|Export|Select|Where|"
    r"ForEach|Start|Stop|ConvertTo|ConvertFrom)-[A-Z]\w+"
)

#: Comment-based help. Its presence is the tie-breaker when a repository has
#: more files than the cap allows.
_HELP = re.compile(r"(?mi)^\s*\.(?:SYNOPSIS|DESCRIPTION|EXAMPLE)\b")

#: No single repository may contribute more than this many documents. dbatools
#: alone offers 948 usable files against 1,210 from the other eight combined;
#: uncapped it would be over half the source and the model would learn dbatools'
#: house style as *the* PowerShell style.
_MAX_FILES_PER_REPO = 600

#: …and no more than this many characters, which is the cap that actually does
#: the work. A file count is a poor proxy for weight when file sizes span thirty
#: to one: capped only at 600 *files*, dbatools still came to 7.5 MB, 44% of the
#: whole source, because its functions are long. Characters are how ``build.py``
#: measures composition, so characters are what the diversity argument should be
#: enforced in. At 5 MB the largest upstream is about a third of this source
#: rather than half, which is the balance this adapter is aiming at: enough
#: PowerShell to move the SHELL register from 15.6% toward its 26% target,
#: without the register becoming one project's voice.
_MAX_CHARS_PER_REPO = 5_000_000

#: Cache layout. Every name is prefixed with the source rather than being the
#: obvious generic one, and that is not tidiness. ``build.py`` hands each source
#: its own ``cache/<name>/`` directory, but during development this adapter was
#: run once against the shared cache *root* — and its ``manifest.json`` merged
#: itself into the RFC source's provenance file, which happened to have the same
#: generic name. Nothing was lost, and nothing announced itself either. A name
#: that says which adapter owns the file cannot collide that way.
_MANIFEST = "powershell.manifest.json"
_REPOS_DIR = "powershell-repos"
_LICENCES_DIR = "powershell-licences"
_MARKER = ".powershell-{key}-complete"


# --------------------------------------------------------------------------
# fetch
# --------------------------------------------------------------------------

def _fetch(cache_dir: Path) -> Path:
    """Populate ``<cache>/repos/<key>/`` for every repository; return that root.

    Per-repository completion markers rather than one marker for the source:
    adding a tenth repository later must not re-download the nine that are
    already on disk, and an interrupted fetch must re-run only the repository it
    died in. The marker is written last, after the extraction has been proved
    non-empty, so its presence means "this tree is complete" and not merely
    "this directory exists".

    A repository that cannot be reached is *not* fatal. Nine upstreams means
    nine chances for a transient network failure to abort a build that eight
    good trees would have satisfied; the failure is printed, the source
    continues, and ``expect_min_docs`` is what catches a genuine collapse.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    repos_root = cache_dir / _REPOS_DIR
    licences = cache_dir / _LICENCES_DIR
    repos_root.mkdir(parents=True, exist_ok=True)
    licences.mkdir(parents=True, exist_ok=True)

    failures: list[str] = []
    for repo in _REPOS:
        marker = cache_dir / _MARKER.format(key=repo.key)
        if marker.exists() and (repos_root / repo.key).is_dir():
            continue
        try:
            _fetch_one(repo, cache_dir, repos_root, licences)
        except (NetworkError, SourceError, OSError) as exc:
            failures.append(f"{repo.slug}: {exc}")
            print(f"   ! powershell: {repo.slug} unavailable — {exc}")

    if not any(child.is_dir() for child in repos_root.iterdir()):
        raise SourceError(
            "powershell: no repository could be fetched. "
            + "; ".join(failures or ["cache is empty and nothing was attempted"])
        )
    return repos_root


def _fetch_one(repo: _Repo, cache_dir: Path, repos_root: Path, licences: Path) -> None:
    """Download and unpack one repository into the cache, atomically."""
    url = _TARBALL.format(slug=repo.slug, ref=repo.ref)
    archive = cache_dir / f"_{repo.key}.tar.gz"
    staging = cache_dir / f"_{repo.key}-incoming"
    try:
        download(url, archive, timeout=600)
        digest = _sha256(archive)
        if staging.exists():
            shutil.rmtree(staging)
        staging.mkdir(parents=True)
        written = _extract(repo, archive, staging)
        if written == 0:
            raise SourceError(
                f"the tarball for {repo.slug} contained no PowerShell under "
                f"{', '.join(repo.prefixes)} — upstream has moved its layout and "
                "this adapter's prefixes need updating rather than retrying"
            )

        # Swap in only once the staging tree is known good, so a reader never
        # sees a half-written repository.
        destination = repos_root / repo.key
        if destination.exists():
            shutil.rmtree(destination)
        (staging / "_code").rename(destination)
        for name in sorted(p.name for p in staging.glob("_licence.*")):
            (staging / name).replace(licences / f"{repo.key}{Path(name).suffix}")
    finally:
        archive.unlink(missing_ok=True)
        shutil.rmtree(staging, ignore_errors=True)

    _record(cache_dir, repo, url=url, sha256=digest, files=written)
    (cache_dir / _MARKER.format(key=repo.key)).write_text(f"{url}\n", encoding="utf-8")


def _extract(repo: _Repo, archive: Path, staging: Path) -> int:
    """Unpack the wanted PowerShell into ``staging/_code``; return the count.

    Members are written one at a time rather than through ``extractall``.
    ``filter="data"``, which would handle path traversal for us, only exists
    from Python 3.12 and this package targets 3.10 — so every destination is
    proved to resolve inside the staging directory first, only regular files are
    written, and an oversized member is skipped here rather than after it has
    cost the disk 2 MB.

    The licence files are counted separately from the code for the same reason
    ``psdocs`` does it: if they counted, a tarball that had lost its entire
    source tree would still report a non-zero write and turn the caller's clear
    "upstream moved" diagnostic into an obscure rename failure.
    """
    code_root = (staging / "_code").resolve()
    code_root.mkdir(parents=True, exist_ok=True)
    written = 0
    try:
        with tarfile.open(archive, "r:gz") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                relative = _wanted(repo, member.name)
                if relative is None:
                    continue
                if relative.startswith("_licence."):
                    target = (staging / relative).resolve()
                    root = staging.resolve()
                else:
                    if member.size > _MAX_BYTES:
                        continue
                    target = (code_root / relative).resolve()
                    root = code_root
                if not target.is_relative_to(root):
                    continue  # traversal attempt; refuse the member silently
                handle = tar.extractfile(member)
                if handle is None:
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with handle, target.open("wb") as out:
                    shutil.copyfileobj(handle, out)
                if root is code_root:
                    written += 1
    except (tarfile.TarError, OSError) as exc:
        raise SourceError(f"could not unpack {archive.name}: {exc}") from exc
    return written


def _wanted(repo: _Repo, name: str) -> str | None:
    """Map a tar member to its staging-relative path, or ``None`` to skip it.

    Codeload wraps the tree in a ``<repo>-<ref>/`` directory whose name changes
    with the ref, so the first component is dropped rather than matched.
    """
    parts = name.split("/")[1:]
    if not parts or any(part in ("", ".", "..") for part in parts):
        return None
    if len(parts) == 1 and parts[0].casefold() in _LICENCE_NAMES:
        return f"_licence{Path(parts[0]).suffix or '.txt'}"
    if any(part.casefold() in _SKIP_DIRS for part in parts[:-1]):
        return None
    relative = "/".join(parts)
    if not relative.startswith(repo.prefixes):
        return None
    if not parts[-1].casefold().endswith(repo.suffixes):
        return None
    return relative


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _record(cache_dir: Path, repo: _Repo, *, url: str, sha256: str, files: int) -> None:
    """Write this repository's provenance into the shared manifest.

    Read-modify-write per repository rather than one write at the end, because
    the fetch is resumable: a run that dies after three repositories should
    leave provenance for those three, not nothing.
    """
    path = cache_dir / _MANIFEST
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        manifest = {}
    manifest.setdefault("version", 1)
    manifest.setdefault("repositories", {})
    manifest["repositories"][repo.key] = {
        "slug": repo.slug,
        "ref": repo.ref,
        "license": repo.license,
        "url": url,
        "tarball_sha256": sha256,
        "prefixes": list(repo.prefixes),
        "files": files,
        "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")


# --------------------------------------------------------------------------
# documents
# --------------------------------------------------------------------------

def _read(path: Path) -> str | None:
    """Decode a script, sniffing the BOM first.

    See the module docstring: a UTF-16 file decoded as UTF-8 does not raise, it
    quietly produces almost-right text, which is the worst possible failure for
    a corpus because nothing downstream will notice.
    """
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    # UTF-32-LE must be tested before UTF-16-LE: its BOM starts with the same
    # two bytes.
    for bom, encoding in (
        (codecs.BOM_UTF32_LE, "utf-32-le"), (codecs.BOM_UTF32_BE, "utf-32-be"),
        (codecs.BOM_UTF16_LE, "utf-16-le"), (codecs.BOM_UTF16_BE, "utf-16-be"),
    ):
        if raw.startswith(bom):
            return raw[len(bom):].decode(encoding, errors="replace")
    # utf-8-sig so a stray U+FEFF is not left at the head of the document as a
    # token the model would learn to expect before every script.
    return raw.decode("utf-8-sig", errors="replace")


def _usable(text: str) -> bool:
    """Is this a readable PowerShell script rather than a payload or a stub?"""
    if len(text) < _MIN_CHARS:
        return False
    if max((len(line) for line in text.split("\n")), default=0) > _MAX_LINE:
        return False
    if _BLOB.search(text):
        return False
    return _POWERSHELL.search(text) is not None


def _stride(items: list[tuple[str, str]], keep: int) -> list[tuple[str, str]]:
    """Take *keep* items spread evenly across *items*.

    Truncation would be simpler and wrong: these lists are sorted by path, so
    the first N of dbatools is every command from ``Add-`` to ``Get-`` and
    nothing after it — a sample biased by alphabet into a sample biased by verb.
    A stride is just as deterministic and spreads the selection across every
    directory and every verb in the module.
    """
    if keep >= len(items):
        return list(items)
    if keep <= 0:
        return []
    total = len(items)
    return [items[(index * total) // keep] for index in range(keep)]


def _fit(items: list[tuple[str, str]], files: int, chars: int) -> list[tuple[str, str]]:
    """The largest even spread of *items* that fits both budgets.

    Shrinking the stride until it fits, rather than truncating a stride-ordered
    list, because a truncated stride is not a spread at all: the first *m* of
    *k* evenly spaced positions covers only the first ``m/k`` of the list, which
    is the alphabet bias :func:`_stride` exists to avoid, reintroduced. Each
    pass strictly decreases the count so this terminates, and the overshoot
    ratio means it does so in two or three passes rather than hundreds.
    """
    keep = min(files, len(items))
    while keep > 0:
        chosen = _stride(items, keep)
        total = sum(len(text) for _, text in chosen)
        if total <= chars:
            return chosen
        keep = min(keep - 1, int(keep * chars / total))
    return []


def _limit(candidates: list[tuple[str, str]], files: int,
           chars: int) -> list[tuple[str, str]]:
    """Cap one repository's contribution, preferring files with help blocks.

    The two-tier split is the whole reason this is not a single stride:
    comment-based help is the shape that teaches a language best, so when a
    repository must be cut, the files carrying ``<# .SYNOPSIS … #>`` are cut
    last. Everything the budget still allows after those is filled from the
    rest, which is what keeps the Pester tests and the procedural scripts — code
    that documents itself by being read, not by being annotated — in the mix.
    """
    if len(candidates) <= files and sum(len(t) for _, t in candidates) <= chars:
        return candidates
    documented = [item for item in candidates if _HELP.search(item[1])]
    plain = [item for item in candidates if not _HELP.search(item[1])]
    kept = _fit(documented, files, chars)
    spent = sum(len(text) for _, text in kept)
    kept += _fit(plain, files - len(kept), chars - spent)
    kept.sort(key=lambda item: item[0])
    return kept


def _collect(repo: _Repo, repo_root: Path, root: Path,
             seen: set[str]) -> list[tuple[str, str]]:
    """Read one repository's usable scripts as ``(ident, text)`` pairs.

    ``os.walk(followlinks=False)`` rather than ``rglob``, which follows
    symlinks. Nothing this adapter extracts *is* a symlink — only regular files
    are ever written — but the guarantee is made explicitly here rather than
    relied upon two functions away, because the cache sits on the same external
    volume that once ate 180 MB of the corpus through a symlink.
    """
    candidates: list[tuple[str, str]] = []
    for dirpath, dirnames, filenames in os.walk(repo_root, followlinks=False):
        dirnames[:] = sorted(
            name for name in dirnames
            if name.casefold() not in _SKIP_DIRS
            and not Path(dirpath, name).is_symlink()
        )
        for filename in sorted(filenames):
            if not filename.casefold().endswith(repo.suffixes):
                continue
            path = Path(dirpath, filename)
            if path.is_symlink():
                continue
            try:
                # Re-checked here as well as at extraction: a cache written
                # before the cap changed would otherwise smuggle a monolith in.
                if path.stat().st_size > _MAX_BYTES:
                    continue
            except OSError:
                continue
            raw = _read(path)
            if raw is None:
                continue
            text = normalise(raw)
            if not _usable(text):
                continue
            key = fingerprint(text)
            if key in seen:
                continue
            seen.add(key)
            candidates.append((path.relative_to(root).as_posix(), text))
    return candidates


def _documents(root: Path) -> Iterator[Document]:
    """Yield one document per selected script, verbatim.

    Nothing is prepended. A provenance header — ``# PowerShell/PowerShell —
    test/…`` — was considered and rejected: it would be valid PowerShell, but it
    would also put the same comment shape at the head of two thousand documents
    and teach the model that scripts open by naming a GitHub repository. The
    path already travels with the document as ``ident``, which is what the
    contract in :mod:`~training.corpus.source` says that field is for.

    Deduplication spans repositories, not just each one, because the vendoring
    goes in every direction.
    """
    seen: set[str] = set()
    for repo in _REPOS:
        repo_root = root / repo.key
        if not repo_root.is_dir():
            continue
        for ident, text in _limit(_collect(repo, repo_root, root, seen),
                                  _MAX_FILES_PER_REPO, _MAX_CHARS_PER_REPO):
            yield Document(text=text, source="powershell", register=Register.SHELL,
                           side=Side.NEUTRAL, ident=ident)


SPEC = SourceSpec(
    name="powershell",
    license=(
        "Composite, per upstream repository, each read from its own LICENSE file: "
        "MIT — PowerShell/PowerShell, PowerShell/PSScriptAnalyzer, "
        "PowerShell/platyPS, PowershellFrameworkCollective/PSFramework, "
        "dataplat/dbatools, microsoft/AaronLocker; "
        "Apache-2.0 — pester/Pester; "
        "BSD-2-Clause — PowerShell/PSReadLine; "
        "BSD-3-Clause — PowerShellMafia/PowerSploit. "
        "Every upstream LICENSE is copied into licences/ in the cache and each "
        "tarball's SHA-256 is recorded in manifest.json."
    ),
    url="https://github.com/PowerShell/PowerShell",
    register=Register.SHELL,
    side=Side.NEUTRAL,
    fetch=_fetch,
    documents=_documents,
    # Roughly 1,900 documents across nine repositories in practice. The floor is
    # set well under that but far above any single repository's contribution, so
    # one upstream moving its layout still passes while a broken fetch or a
    # changed extension convention fails loudly.
    expect_min_docs=1200,
    notes=("Idiomatic .ps1/.psm1 source from nine permissively licensed "
           "repositories — the shell itself, Pester, PSScriptAnalyzer, PSReadLine, "
           "platyPS, PSFramework, dbatools, PowerSploit and AaronLocker — kept "
           "verbatim with comment-based help intact. Complements psdocs, which is "
           "documentation about PowerShell rather than PowerShell: this source "
           "carries the function bodies, parameter attributes, splatting, "
           "error handling and pipeline structure a reference page never shows. "
           "Payload blobs, fixture violations and oversized monoliths are excluded."),
)
