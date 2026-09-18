"""Real security tooling, as source code. SYSTEM/NEUTRAL.

The corpus already holds a great deal of writing *about* security and a great
deal of machine-readable *rules* about security. It holds almost no software
that actually does security. That is a strange gap for a project whose own
runtime is Python, whose agent must read and extend tooling, and whose model
will be asked what a scanner does before it is ever asked what a scanner is.

Python is the right language for the gap. It ships by default on Linux and
macOS, it is the lingua franca of security tooling, and — the part that matters
for a tokenizer — well-written Python is *prose next to code*. A documented
module teaches the identifier ``NTLMSSP_NEGOTIATE_SEAL`` and, one line away, an
English sentence explaining what sealing is. Neither register on its own
carries that join. The measurement this corpus was rebuilt around said the win
comes from an identifier sitting beside its human name in running prose; a
docstring, or a trailing ``#`` on the line that sets the flag, is that shape
several hundred times per file. Every file admitted here has to carry a real
quantity of it — see :data:`_MIN_PROSE_CHARS`, and the measurement that taught
this adapter not to count only docstrings.

What the six projects here demonstrate, concretely:

* how packets are crafted and parsed, field by field (``dpkt``)
* how a Windows protocol client negotiates, authenticates and fails
  (``impacket`` — SMB, Kerberos, LDAP, DCE/RPC, and the same protocol stack
  this project's Windows adapter reasons about)
* how a forensics parser walks a binary format without trusting it (``plaso``)
* how a proxy terminates, rewrites and re-originates TLS (``mitmproxy``)
* how cryptography is used *correctly*, by the people who maintain the
  primitives (``pyca/cryptography``)
* how an exploitation framework talks to a process, a socket and a shell
  (``pwntools``)

**Register: SYSTEM, not SHELL.** The choice was made from what this adapter
actually emits, not from the topic. What comes out is Python module source:
class definitions, constant tables, protocol structures, argparse surfaces and
docstrings. :class:`~training.corpus.source.Register.SHELL` is for commands and
one-liners — the things a person types at a prompt — and none of that is here,
not even in ``impacket/examples`` where the argparse block describes a command
line but the body is a library call sequence.
:class:`~training.corpus.source.Register.SYSTEM` is "how the machine works …
API references", and an SMB dialect negotiation written out in structs is
exactly that. Filing it under SHELL would have made the balance report lie
about the register this corpus is most starved of.

**Indentation is the syntax, and that is the whole risk in this adapter.**
:func:`~training.corpus.source.normalise` is explicitly contracted to preserve
horizontal whitespace, and this source is the one that would be destroyed
silently if that contract ever slipped. A Sigma rule mangled by a
space-collapsing cleaner is a degraded rule; Python mangled the same way is not
Python at all — it is a wall of text that happens to contain keywords, and a
model trained on it would learn that indentation carries no meaning. Worse, the
damage is invisible in a build report: the character count would barely move.

So the guarantee is asserted rather than assumed. Every file is proved to parse
with :func:`ast.parse` when it is cached, and proved *again* after
:func:`~training.corpus.source.normalise` has run over it in
:func:`_documents`. A file that parsed as raw source and fails to parse after
normalisation cannot be a data quirk — it can only mean the normaliser broke
the language — so that case raises :class:`SourceError` naming the file instead
of quietly dropping it. Every real file in this corpus passes both, which is
what makes the raise safe and what makes it worth keeping.

**Licensing is per project and was read, not inferred.** GitHub's own licence
detector returns NOASSERTION for four of the six, so each LICENSE file was
fetched and read, and each archive's LICENSE is copied into the cache so the
claim in :data:`SPEC` stays checkable on disk. Several obvious candidates were
left out for licence reasons alone, and they are named here so nobody spends an
afternoon re-discovering them: ``scapy`` (GPL-2.0-only) is the single most
instructive packet library in existence and is not here — ``dpkt``, BSD-3, does
the same teaching; ``sqlmap`` is GPL-2.0; ``paramiko`` is LGPL-2.1;
``fox-it/dissect`` is AGPL-3.0; and ``volatility3`` ships a bespoke Volatility
Software License 1.0 whose own summary says it "requires you to share source
code for … software that you build with it". Copyleft text in the training set
of a model this project intends to publish is a licence question nobody wants
to answer later, and the permissive substitutes lose very little.
"""

from __future__ import annotations

import ast
import fnmatch
import hashlib
import io
import json
import os
import shutil
import tarfile
import time
import tokenize
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from ..net import NetworkError, download, fetch as http_get
from ..source import (
    Document, Register, Side, SourceError, SourceSpec, fingerprint, normalise,
)

_NAME = "pythoncode"

#: Written last, so its presence means extraction finished. The adapter version
#: is part of it: when the gates below change, a cache built under the old rules
#: is stale, and silently reusing it is how an adapter's fixes fail to take
#: effect on the machine that already ran it once.
#:
#: 3 because the sdist is now checked against the digest PyPI publishes for it.
#: A cache written under 2 holds an archive that was never compared with
#: anything, and its marker records an ``archive_sha256`` that reads like a
#: verified checksum and is not one. That cache has to be refetched rather than
#: trusted, which is exactly what this number is for — the short-circuit on
#: ``cache_version`` would otherwise mean the machines that already built the
#: corpus are the ones the fix never reaches.
_MARKER = ".fetched.json"
_CACHE_VERSION = 3


@dataclass(frozen=True)
class _Project:
    """One upstream, its verified licence, and the part of it worth keeping."""

    name: str
    url: str
    #: Read from the project's own LICENSE file, not from a repository badge.
    license: str
    #: Either a codeload tarball URL, or ``pypi:<distribution>`` — see
    #: :func:`_archive_url` for why one project is fetched differently.
    archive: str
    #: Path prefixes to keep, relative to the archive root after its single
    #: top-level directory is stripped. Everything else is never even decoded.
    keep: tuple[str, ...]
    #: Prefixes carved back out of ``keep``, for licence or quality reasons.
    drop: tuple[str, ...] = ()
    #: Floor on files surviving every gate. A project that suddenly yields far
    #: fewer has moved its package directory, and should say so at fetch time
    #: rather than as a thin build report three sources later.
    min_files: int = 20


#: Six projects rather than one, deliberately. A corpus drawn from a single
#: repository teaches one author's habits — their naming, their error style,
#: their comment density — and a model that has only met those habits treats
#: them as the language. These six disagree with each other about most things:
#: dpkt is terse and struct-shaped, impacket is sprawling and protocol-literal,
#: plaso is rigorously uniform, mitmproxy is modern and typed, cryptography is
#: defensive to the point of paranoia, pwntools is chatty and doctest-heavy.
_PROJECTS: tuple[_Project, ...] = (
    _Project(
        name="dpkt",
        url="https://github.com/kbandla/dpkt",
        license="BSD-3-Clause (Copyright (c) 2004 Dug Song)",
        archive="https://codeload.github.com/kbandla/dpkt/tar.gz/refs/heads/master",
        keep=("dpkt/",),
        min_files=40,
    ),
    _Project(
        name="impacket",
        url="https://github.com/fortra/impacket",
        license=("Apache Software License 1.1, modified (Fortra; the LICENSE "
                 "file states the only changes are the substitution of "
                 "'Impacket' for 'Apache' and 'Fortra' for 'Apache Software "
                 "Foundation')"),
        archive="https://codeload.github.com/fortra/impacket/tar.gz/refs/heads/master",
        # examples/ is not filler here: secretsdump, psexec, GetUserSPNs and
        # friends are the real tools, and they show a protocol library being
        # driven end to end rather than merely defined.
        keep=("impacket/", "examples/"),
        min_files=90,
    ),
    _Project(
        name="plaso",
        url="https://github.com/log2timeline/plaso",
        license="Apache-2.0",
        # The one project not fetched from GitHub. Its repository ships a
        # forensic test corpus, so the codeload tarball is 216 MB for about
        # 4 MB of Python; the PyPI sdist carries the identical plaso/ package
        # in 2.9 MB. Seventy-four times less transfer for the same text.
        archive="pypi:plaso",
        keep=("plaso/",),
        min_files=300,
    ),
    _Project(
        name="mitmproxy",
        url="https://github.com/mitmproxy/mitmproxy",
        license="MIT (Copyright (c) 2013, Aldo Cortesi)",
        archive="https://codeload.github.com/mitmproxy/mitmproxy/tar.gz/refs/heads/main",
        keep=("mitmproxy/", "examples/"),
        # mitmproxy/contrib/ is vendored third-party and generated Kaitai
        # parsers. It is caught by the global directory skips too; naming it
        # here documents that the exclusion is intentional, not incidental.
        drop=("mitmproxy/contrib/",),
        min_files=80,
    ),
    _Project(
        name="cryptography",
        url="https://github.com/pyca/cryptography",
        license=("Apache-2.0 OR BSD-3-Clause (the LICENSE file offers either; "
                 "contributions are made under both)"),
        archive="https://codeload.github.com/pyca/cryptography/tar.gz/refs/heads/main",
        # src/rust/ is Rust and src/_cffi_src/ is C-binding build glue. The
        # Python API and its documentation live in src/cryptography/.
        keep=("src/cryptography/",),
        min_files=15,
    ),
    _Project(
        name="pwntools",
        url="https://github.com/Gallopsled/pwntools",
        license=("MIT (LICENSE-pwntools.txt; pwnlib/constants/ and pwnlib/data/ "
                 "are excluded because they are the only trees the licence "
                 "carves out as GPL or BSD-2-Clause)"),
        archive="https://codeload.github.com/Gallopsled/pwntools/tar.gz/refs/heads/dev",
        keep=("pwnlib/",),
        # Licence first — the upstream LICENSE names exactly these two
        # directories as not-MIT. They would have been dropped on quality
        # grounds anyway: constants/ is machine-generated syscall tables.
        drop=("pwnlib/constants/", "pwnlib/data/"),
        min_files=60,
    ),
)


#: Directory names that are never corpus, wherever they appear in a path.
#: ``contrib`` and ``vendor`` matter most: projects vendor each other, and a
#: vendored copy is the same text under a different licence with a different
#: path — duplicated text in a small corpus is worse than absent text.
_SKIP_DIRS = frozenset({
    "test", "tests", "testing", "test_data", "testdata", "test_lib",
    "__pycache__", ".git", "vendor", "_vendor", "vendored", "third_party",
    "thirdparty", "contrib", "node_modules", "build", "dist", ".eggs",
    "site-packages", ".tox", "migrations",
})

#: Tests as fixtures, packaging stubs and parser-generator output. A test file
#: is mostly assertions and fixture literals — the least instructive Python a
#: security project contains, and there is a lot of it.
_SKIP_FILES = (
    "test_*.py", "*_test.py", "tests.py", "conftest.py",
    "setup.py", "_version.py", "version.py", "versioneer.py",
    "*_pb2.py", "*_pb2_grpc.py", "parsetab.py", "lextab.py",
)

#: Phrases that mark a file as machine output. Checked against the head of the
#: file only, because a hand-written parser may legitimately discuss generated
#: code further down. Generated Python is real Python and would pass every
#: other gate here, so nothing but this catches it — and a syscall table or a
#: protobuf stub teaches the model repetition, not structure.
_GENERATED_MARKERS = (
    "do not edit",
    "don't edit",
    "automatically generated",
    "auto-generated",
    "autogenerated",
    "@generated",
    "generated by the protocol buffer compiler",
    "this file is generated",
    "generated file",
)
_GENERATED_HEAD_BYTES = 2048

#: Below this a file is an ``__init__`` re-export list or a stub, and carries
#: no structure worth learning. Above it a file is a constant table or a
#: generated struct dump: impacket's DCE/RPC interface modules run past 150 KB
#: of near-identical NDR declarations, and one of those outweighs thirty
#: hand-written parsers in a register it would then dominate.
_MIN_BYTES = 1_200
_MAX_BYTES = 100_000

#: Prose-next-to-code is the reason this source exists, so a file with no prose
#: in it does not qualify — measured as an absolute quantity *and* as a share of
#: the file, so that neither a one-line comment on a 40 KB constant table nor a
#: 1.5 KB stub with a single sentence gets through.
#:
#: This gate originally counted docstrings only, and it was quietly throwing
#: away the best files in the corpus. impacket documents almost everything in
#: ``#`` headers rather than docstrings: measured across its 210 admissible
#: files, 162 have under 120 characters of docstring, and among those are
#: ``GetUserSPNs.py`` and ``GetNPUsers.py`` — Kerberoasting and AS-REP roasting,
#: the two files most directly relevant to the Windows protocol reasoning this
#: corpus is for. Their explanation is real, it is just spelled ``#``. For a
#: tokenizer a comment beside an identifier is the same shape as a docstring
#: beside an identifier, so both count.
_MIN_PROSE_CHARS = 200
_MIN_PROSE_RATIO = 0.05

#: The ceiling on an archive, passed to :func:`~training.corpus.net.download`
#: as ``max_bytes`` so it is enforced against bytes as they arrive. It used to
#: be checked with ``archive.stat().st_size`` *after* the download returned,
#: back when ``download`` buffered the whole response in memory and then wrote
#: it out — which meant a 20 GB body exhausted memory and filled the disk three
#: statements before the guard that was supposed to stop it ever ran. The check
#: read as protection and provided none. A ceiling belongs where the bytes
#: arrive, not where they are counted afterwards.
_MAX_ARCHIVE_BYTES = 300 * 1024 * 1024


def _archive_url(project: _Project) -> tuple[str, str, str]:
    """Resolve ``project.archive`` to a URL, a version label and an expected digest.

    GitHub codeload tarballs are used for five of the six: one request, no git
    binary, no history, and nothing on disk that a later ``git pull`` could
    mutate underneath a reproducible build. The sixth is resolved through the
    PyPI JSON API because its repository is two orders of magnitude larger than
    its source distribution — the reason is recorded on the project entry.

    The digest is the third return value and it is empty for the codeload five,
    because GitHub publishes no hash for a branch tarball and an empty string
    says that honestly. PyPI does publish one, in the same response that gives
    the URL, and the only reason this function used to return two values is
    that nobody read it. The URL was taken on truthiness alone and handed
    straight to ``download``, while ``digests.sha256`` — the authoritative hash
    for exactly those bytes — sat unused in the same ``entry`` dict; the marker
    then recorded a hash of whatever had arrived, which looks like a verified
    checksum and proves nothing at all about the bytes you were supposed to get.

    The scheme check is here for the same reason. This URL is the one in the
    adapter that comes out of a remote response rather than a constant, and
    validating it where it is read is cheaper to reason about than trusting
    that every layer underneath will keep refusing ``ftp:``, ``file:`` and
    ``data:`` forever.
    """
    if not project.archive.startswith("pypi:"):
        return project.archive, project.archive.rsplit("/", 1)[-1], ""

    distribution = project.archive.split(":", 1)[1]
    api = f"https://pypi.org/pypi/{distribution}/json"
    try:
        payload = json.loads(http_get(api, timeout=60).decode("utf-8"))
    except (NetworkError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceError(f"{_NAME}: cannot resolve {api}: {exc}") from None

    version = str(payload.get("info", {}).get("version", "unknown"))
    for entry in payload.get("urls", []):
        if entry.get("packagetype") != "sdist":
            continue
        url = str(entry.get("url", ""))
        if not url:
            continue
        if not url.startswith("https://"):
            raise SourceError(
                f"{_NAME}: {api} offers its sdist at {url!r}, which is not "
                "https. PyPI does not do that; something between here and it "
                "does. Refusing rather than fetching."
            )
        digest = str(entry.get("digests", {}).get("sha256", ""))
        if not digest:
            raise SourceError(
                f"{_NAME}: {api} gives no digests.sha256 for {url}. That field "
                "is what makes this download checkable, and a source "
                "distribution fetched with nothing to compare it against is "
                "not worth training on."
            )
        return url, version, digest
    raise SourceError(
        f"{_NAME}: {distribution} publishes no source distribution on PyPI. "
        "It was chosen precisely because its sdist is 74x smaller than its "
        "repository tarball; if that is no longer true, point the project at "
        "codeload instead of quietly losing the source."
    )


def _sha256(path: Path) -> str:
    """Digest of a file, read a megabyte at a time.

    Chunked rather than ``hashlib.sha256(path.read_bytes())``: the ceiling on
    these archives is 300 MB and there is no reason for any of it to be
    resident at once, least of all on a machine that may be training.
    """
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def _is_generated(head: bytes) -> bool:
    lowered = head[:_GENERATED_HEAD_BYTES].lower()
    return any(marker.encode("ascii") in lowered for marker in _GENERATED_MARKERS)


def _docstring_chars(tree: ast.Module) -> int:
    """Total characters of docstring in a parsed module."""
    total = 0
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef,
                             ast.FunctionDef, ast.AsyncFunctionDef)):
            total += len(ast.get_docstring(node) or "")
    return total


def _header_block_lines(text: str) -> int:
    """Length of the comment block at the top of the file, in lines.

    That block is the licence and attribution furniture, and it is *identical*
    across every file in a project — around 500 characters of it in impacket's
    case. Counting it as explanation would let a file whose only prose is its
    copyright notice satisfy the prose gate, which is the opposite of what the
    gate is for. It is excluded from the measurement and kept in the text:
    removing it from the document would be editing someone's licence notice out
    of their source, and ``build.py``'s corpus-wide boilerplate filter is the
    right place to deal with lines that repeat everywhere.

    Defined exactly — the run of blank and ``#`` lines before the first
    statement — rather than as a fixed line budget, so a project with a
    thirty-line header and one with a two-line header are both handled without
    a magic number that fits neither.
    """
    count = 0
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            break
        count += 1
    return count


def _prose_chars(text: str, tree: ast.Module) -> int:
    """Characters of human explanation: docstrings plus body comments.

    ``tokenize`` rather than a line scan, because the most valuable comments in
    protocol code are the trailing ones — ``flags |= 0x20  # NEGOTIATE_SEAL`` —
    and a scan for lines starting with ``#`` misses every one of them. It is
    guarded anyway: the caller has already proved the text parses, so a
    tokenizer failure here would be surprising, and a surprise in a
    quality-metric helper should degrade to "no comment credit" rather than
    take a build down.
    """
    total = _docstring_chars(tree)
    header = _header_block_lines(text)
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type == tokenize.COMMENT and token.start[0] > header:
                total += len(token.string.lstrip("#").strip())
    except (tokenize.TokenError, IndentationError, SyntaxError, ValueError):
        pass
    return total


def _wanted(project: _Project, relative: Path) -> bool:
    """True if this archive member is a file this project wants to contribute."""
    if relative.suffix != ".py":
        return False
    posix = relative.as_posix()
    if not any(posix.startswith(prefix) for prefix in project.keep):
        return False
    if any(posix.startswith(prefix) for prefix in project.drop):
        return False
    if _SKIP_DIRS.intersection(relative.parts[:-1]):
        return False
    return not any(fnmatch.fnmatch(relative.name, pattern)
                   for pattern in _SKIP_FILES)


def _admit(raw: bytes) -> str | None:
    """Return the decoded source if it belongs in the corpus, else ``None``.

    The gates, in the order they are cheapest: size, strict UTF-8, the
    generated-file sniff, ``ast.parse``, and finally a real quantity of prose.
    Decoding is strict on purpose — ``errors="replace"`` would admit a Latin-1
    file as source containing replacement characters, which parses fine and
    teaches the model mojibake.

    The ``ast.parse`` gate is doing more work than it looks. It rejects Python 2
    files still lying around in old trees, half-migrated fixtures, template
    files that happen to end in ``.py``, and anything whose encoding declaration
    disagrees with its bytes. Everything downstream is then guaranteed to be
    valid Python *as cached*, which is what makes the post-normalise parse in
    :func:`_documents` a genuine test of the normaliser rather than a test of
    the upstream.
    """
    if not _MIN_BYTES <= len(raw) <= _MAX_BYTES:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if _is_generated(raw):
        return None
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return None
    prose = _prose_chars(text, tree)
    if prose < _MIN_PROSE_CHARS or prose / len(raw) < _MIN_PROSE_RATIO:
        return None
    return text


def _extract(project: _Project, archive: Path, staging: Path) -> tuple[int, int]:
    """Unpack one project's admitted ``.py`` files and its LICENSE into staging.

    Members are copied out by hand rather than with ``TarFile.extractall``.
    These tarballs are trusted in practice, but an archive member is
    attacker-controlled data in principle — absolute paths, ``..`` segments,
    symlinks and hardlinks are all expressible in tar — and the cheap defence
    is never to hand an archive's own names to the filesystem unchecked. Only
    regular files are written, and every destination is proved to resolve
    inside ``staging`` first.

    Returns ``(seen, kept)`` so the marker can record how selective the gates
    were, which is the number that tells you at a glance whether an upstream
    reorganised itself.
    """
    files_root = staging / "files" / project.name
    files_root.mkdir(parents=True, exist_ok=True)
    resolved_root = files_root.resolve()
    licence_dir = staging / "licenses"
    licence_dir.mkdir(parents=True, exist_ok=True)

    seen = kept = 0
    licences = 0
    try:
        with tarfile.open(archive, mode="r:gz") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                parts = Path(member.name).parts
                if len(parts) < 2:
                    continue
                # Drop the archive's single root directory, which is
                # "impacket-master/" for a codeload tarball and
                # "plaso-20260720/" for an sdist. Stripping it is what lets one
                # set of keep-prefixes describe both.
                relative = Path(*parts[1:])
                if relative.is_absolute() or ".." in relative.parts:
                    continue

                # The licence text itself, copied so the claim in SPEC can be
                # checked against what was actually downloaded.
                if (len(relative.parts) == 1
                        and relative.name.upper().startswith(("LICENSE", "COPYING"))
                        and member.size <= 128 * 1024):
                    handle = tar.extractfile(member)
                    if handle is not None:
                        with handle:
                            (licence_dir / f"{project.name}.{relative.name}"
                             ).write_bytes(handle.read())
                        licences += 1
                    continue

                if not _wanted(project, relative):
                    continue
                seen += 1
                if member.size > _MAX_BYTES:
                    continue
                handle = tar.extractfile(member)
                if handle is None:
                    continue
                with handle:
                    raw = handle.read()
                text = _admit(raw)
                if text is None:
                    continue

                target = files_root / relative
                if not target.resolve().is_relative_to(resolved_root):
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                # Re-encoded from the decoded text rather than copied as bytes,
                # so what lands in the cache is exactly what _admit proved to
                # be valid UTF-8 and valid Python.
                target.write_text(text, encoding="utf-8")
                kept += 1
    except (tarfile.TarError, OSError) as exc:
        raise SourceError(f"{_NAME}: could not unpack {project.name}: {exc}") from exc

    if licences == 0:
        raise SourceError(
            f"{_NAME}: {project.name} archive carries no LICENSE file at its "
            "root. Every source in this corpus declares a licence and this one "
            "keeps the upstream text on disk to back the declaration; an "
            "archive that no longer ships it needs a human to look, not a "
            "default."
        )
    if kept < project.min_files:
        raise SourceError(
            f"{_NAME}: {project.name} yielded only {kept} files from "
            f"{seen} candidates under {'/, '.join(project.keep)} (expected at "
            f"least {project.min_files}). The upstream layout has probably "
            "changed — fix the keep-prefixes rather than training on a fraction "
            "of the project."
        )
    return seen, kept


def _fetch(cache_dir: Path) -> Path:
    """Download each project, filter it, and leave a curated tree in the cache.

    Idempotent and network-free on re-run: the marker is written only after
    every project has been extracted and the staging tree swapped into place,
    so an interrupted fetch re-downloads instead of leaving a half-populated
    ``files/`` that a later run would mistake for a finished corpus.

    The archives are deleted as soon as they are unpacked. Together they are a
    few hundred megabytes of mostly-not-Python and the curated result is a few
    tens of megabytes; keeping them would be paying disk to avoid a download
    that already only happens once.

    Accepts either the per-source directory ``build.py`` hands it
    (``<cache>/pythoncode``) or the cache root, so calling this by hand during
    development does not scatter ``files/`` across the shared cache.
    """
    root = cache_dir if cache_dir.name == _NAME else cache_dir / _NAME
    root.mkdir(parents=True, exist_ok=True)

    files_dir = root / "files"
    marker = root / _MARKER
    if files_dir.is_dir() and marker.is_file():
        try:
            recorded = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            recorded = {}
        if recorded.get("cache_version") == _CACHE_VERSION:
            return root

    staging = root / ".staging"
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True, exist_ok=True)

    manifest: list[dict[str, object]] = []
    try:
        for project in _PROJECTS:
            url, version, expected = _archive_url(project)
            archive = root / f".{project.name}.tar.gz.part"
            try:
                # The ceiling goes to the transport, which enforces it against
                # bytes as they arrive and refuses an oversized Content-Length
                # before reading any of them. See _MAX_ARCHIVE_BYTES for the
                # version of this that ran after the download had finished.
                download(url, archive, timeout=600,
                         max_bytes=_MAX_ARCHIVE_BYTES)
            except NetworkError as exc:
                raise SourceError(f"{_NAME}: {project.name}: {exc}") from None
            try:
                # Hashing costs one read and buys provenance: a bare branch
                # name cannot tell you afterwards which snapshot of a moving
                # target this cache actually contains.
                digest = _sha256(archive)
                # And where the upstream published a digest of its own, the
                # hash is compared rather than merely recorded. Observing a
                # hash of the bytes that arrived says nothing about whether
                # they are the bytes PyPI meant to serve; a poisoned CDN entry
                # or a rewritten mirror object passes every other gate here,
                # since the size ceiling only catches a large file, min_files
                # only catches a restructured tree and the LICENSE check only
                # catches a missing licence.
                if expected and digest != expected:
                    raise SourceError(
                        f"{_NAME}: {project.name}: {url} hashed to {digest}, "
                        f"but the index that supplied the URL says the file's "
                        f"sha256 is {expected}. These are not the bytes the "
                        "upstream published. Refusing to unpack them."
                    )
                seen, kept = _extract(project, archive, staging)
            finally:
                archive.unlink(missing_ok=True)

            manifest.append({
                "project": project.name,
                "url": project.url,
                "archive_url": url,
                "version": version,
                "license": project.license,
                "archive_sha256": digest,
                # Spelled out rather than left implied: "observed" is what the
                # bytes hashed to, "verified" is whether that was compared with
                # an upstream claim. The codeload five have nothing to compare
                # against, and a marker that did not say so would read as if
                # they had been checked.
                "expected_sha256": expected,
                "sha256_verified": bool(expected),
                "candidates": seen,
                "kept": kept,
            })

        # Swap in only once every project succeeded.
        shutil.rmtree(files_dir, ignore_errors=True)
        (staging / "files").replace(files_dir)
        licence_src = staging / "licenses"
        if licence_src.is_dir():
            shutil.rmtree(root / "licenses", ignore_errors=True)
            licence_src.replace(root / "licenses")
        marker.write_text(
            json.dumps(
                {
                    "cache_version": _CACHE_VERSION,
                    "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "projects": manifest,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return root


def _documents(path: Path) -> Iterator[Document]:
    """Yield one Document per cached source file, verbatim, deduplicated.

    **Symlinks are never followed.** ``os.walk(followlinks=False)`` rather than
    ``rglob``, for the reason :mod:`~training.corpus.sources.ownrepos` records
    the hard way: a sibling adapter once walked a symlink into the external
    corpus cache and pulled 180 MB of other sources back in under its own
    label. This tree is written by :func:`_fetch` and should contain no links
    at all, which is exactly the situation in which an unexamined ``rglob``
    survives review and then does not survive the day someone points a symlink
    at the cache.

    The post-normalise parse is the point of this function. Every file here was
    proved to be valid Python before it was cached, so a
    :class:`SyntaxError` now can only have been introduced by
    :func:`~training.corpus.source.normalise` — a broken contract, not bad
    input — and it is raised rather than skipped. Skipping would turn "the
    normaliser mangles indentation" into a slightly smaller document count,
    which is precisely the kind of silent corpus damage this project keeps
    learning about afterwards.

    Deduplication is by :func:`~training.corpus.source.fingerprint`, whitespace-
    insensitive and case-folded, because these projects vendor one another and
    a vendored copy arrives under a different path with different wrapping.
    ``build.py`` also dedupes globally, but a source that hands it duplicates is
    a source whose own report is wrong.
    """
    root = path / "files" if (path / "files").is_dir() else path
    seen: set[str] = set()

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in _SKIP_DIRS and not Path(dirpath, d).is_symlink()
        )
        for filename in sorted(filenames):
            if not filename.endswith(".py"):
                continue
            file = Path(dirpath, filename)
            if file.is_symlink():
                continue
            try:
                raw = file.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            text = normalise(raw)
            ident = file.relative_to(root).as_posix()
            try:
                ast.parse(text)
            except SyntaxError as exc:
                raise SourceError(
                    f"{_NAME}: {ident} parsed as Python before normalise() and "
                    f"not after ({exc}). In Python the indentation is the "
                    "syntax, so a normaliser that collapses horizontal "
                    "whitespace does not degrade this register, it deletes the "
                    "language. Fix normalise(); do not filter around this."
                ) from None

            mark = fingerprint(text)
            if mark in seen:
                continue
            seen.add(mark)

            yield Document(
                text=text,
                source=_NAME,
                register=Register.SYSTEM,
                side=Side.NEUTRAL,
                # "impacket/examples/secretsdump.py" — unique, stable across
                # fetches, and legible in a build report.
                ident=ident,
            )


SPEC = SourceSpec(
    name=_NAME,
    license=("Composite, per upstream, each read from the project's own LICENSE "
             "file: dpkt BSD-3-Clause (Dug Song); impacket Apache Software "
             "License 1.1 as modified by Fortra; plaso Apache-2.0; mitmproxy "
             "MIT (Aldo Cortesi); pyca/cryptography Apache-2.0 OR BSD-3-Clause; "
             "pwntools MIT, excluding pwnlib/constants/ and pwnlib/data/ which "
             "its licence carves out as GPL or BSD-2-Clause and which are not "
             "collected. Every archive's LICENSE is copied into the cache under "
             "licenses/ so the declaration can be checked against the download."),
    # SourceSpec takes one url and this source has six. The most relevant of
    # them stands here; all six, with the exact archive fetched, the resolved
    # version, the sha256 of what arrived and whether that hash was checked
    # against one the upstream published, are written into the cache marker by
    # _fetch, and each project's url is on _PROJECTS above.
    url="https://github.com/fortra/impacket",
    register=Register.SYSTEM,
    side=Side.NEUTRAL,
    fetch=_fetch,
    documents=_documents,
    #: 829 files survived every gate when this adapter was written — 424 plaso,
    #: 125 impacket, 113 mitmproxy, 86 pwntools, 57 dpkt, 24 cryptography — and
    #: none were near-duplicates of each other. The floor sits about 20% under
    #: that so ordinary upstream churn is quiet, while a project vanishing
    #: entirely (a renamed package directory, a moved sdist) is not. Each
    #: project also carries its own floor in _Project.min_files, which fails at
    #: fetch time and names the culprit; this one is the backstop for the case
    #: where several shrink a little at once.
    expect_min_docs=650,
    notes=("Six permissively licensed security projects, .py source only, kept "
           "verbatim: packet craft/parse (dpkt), Windows protocol clients "
           "(impacket, including its examples/ tooling), forensic format "
           "parsers (plaso), TLS interception (mitmproxy), correct primitive "
           "use (pyca/cryptography) and exploitation plumbing (pwntools). "
           "Tests, generated files, vendored trees and anything over 100 KB are "
           "excluded; every file must carry at least 200 characters of prose "
           "(docstrings plus body comments, licence header excluded) amounting "
           "to 5% of the file, must parse with ast before caching, and must "
           "still parse after normalise() or the build raises."),
)
