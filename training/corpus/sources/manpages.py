"""Local UNIX man pages — the largest SYSTEM-register source available offline.

The tokenizer measurement that motivates :mod:`training.corpus.source` said the
first corpus was starved of exactly two registers: SHELL and SYSTEM. Man pages
are the canonical SYSTEM text. They are how the machine describes itself, in the
surface form the model will actually meet: option tables, ``FILES`` sections
listing real paths, ``EXIT STATUS`` blocks, ``SEE ALSO`` cross-references written
as ``ls(1)``, environment-variable names in caps, and a ``SYNOPSIS`` grammar
(``[-abc] [--long=when] file ...``) that appears nowhere else in written English.

It is also free in the sense that matters most here: it needs no network, no API
key and no rate limit. Every page is already on the disk of any UNIX machine the
model will ever run on.

Four things about this source are non-obvious and each one is a trap:

**Man pages are roff, not text.** ``/usr/share/man`` holds source markup, so
something must render it. This adapter uses ``mandoc(1)``, which ships with
macOS and every BSD and is packaged everywhere else. ``man(1)`` itself is
avoided because its output depends on the caller's ``MANPAGER``, ``MANWIDTH``
and locale — three ways for the cache to stop being reproducible.

**Rendered man pages are not plain text either.** A terminal renderer emits
*overstrike*: bold ``s`` is the three bytes ``s\\x08s`` and italic ``s`` is
``_\\x08s``, which is how emphasis reached a 1970s line printer and how it still
reaches ``less`` today. :func:`~training.corpus.source.normalise` strips
``\\x08`` as a control byte — correctly, it is one — but stripping it *without
applying it first* leaves ``NNAAMMEE`` and ``__ffiillee`` behind. That is worse
than noise: it would teach the tokenizer a doubled-letter alphabet that exists
nowhere in the real world. So overstrike is resolved here, during rendering,
before ``normalise`` ever sees the text.

**A tenth of the tree is the same text twice.** 240 pages are one-line ``.so``
aliases (``egrep`` is a copy of ``grep``, ``[`` of ``test``), and one page,
``zshall``, is a 1.5 MB concatenation of fourteen other pages that are all in
the corpus in their own right. Fingerprint dedup catches neither cheaply — the
aliases only after rendering them, the concatenation never, since it hashes to
none of its parts. Both are dropped before rendering by :func:`_drop_aliases`.
Duplicated text in a corpus this size is worse than absent text: the model
memorises it.

**The licence is genuinely plural.** A man page carries the licence of whatever
project shipped it, and ``/usr/share/man`` on this machine is a pile of 4.4BSD,
Apple APSL, GPL, Tcl/Tk and MIT pages from hundreds of upstreams. There is no
single SPDX identifier that is true of the set, so the spec does not claim one.
See the ``license`` and ``notes`` fields, and read them before publishing a
model trained on this: the corpus is fine to *train* on locally, but the raw
cache is not a blob anyone may redistribute as a unit.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import re
import shutil
import subprocess
import zlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Iterator, NamedTuple

from ..source import Document, Register, Side, SourceError, SourceSpec, normalise

#: The man hierarchies to read. Kept as a list so a caller can extend it, but
#: deliberately just the base system tree by default.
#:
#: On this machine ``/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/
#: share/man`` holds a second, larger hierarchy: its man1/man4/man5/man8 are
#: near-duplicates of these, but it also carries man2 (268 syscall pages) and
#: man3 (10,506 library pages). man2 is tempting — ``execve``, ``ptrace``,
#: ``setuid`` are prime SYSTEM text — but man3 is overwhelmingly ``.3pm`` Perl
#: module pod, and adding that root wholesale would quadruple the source and
#: hand a quarter of the entire corpus to Perl API reference. If it is ever
#: wanted, add the root here and filter sections; the rest of this file needs no
#: change.
MAN_ROOTS: tuple[Path, ...] = (Path("/usr/share/man"),)

#: Bumped whenever rendering changes in a way that invalidates cached text, so
#: an old cache is re-rendered instead of silently mixing two formats.
_CACHE_VERSION = 1

#: Pinned explicitly rather than left to mandoc's default so the cache is
#: byte-identical across machines and locales. 78 is mandoc's own default and
#: the width nearly every man page was hand-wrapped against.
_RENDER_WIDTH = 78

#: roff comment introducers. A page may open with several of these plus a
#: preprocessor line (``'\" t``) before its first real directive.
_COMMENT_PREFIXES = (r'.\"', r"'\"")

#: A roff source-inclusion directive and its target. ``'`` is roff's no-break
#: control character and is as valid as ``.`` here. Matched against bytes
#: because man pages are a mix of UTF-8 and Latin-1 and this runs before any
#: decoding decision has been made.
_SO_TARGET = re.compile(rb"^[.']so\s+(\S+)", re.MULTILINE)

#: Floor for a document worth keeping. A page rendering to nothing but its own
#: running header and footer is ~160 characters, so this sits just above that
#: while discarding no page that has a real NAME and DESCRIPTION — the shortest
#: genuine page here survives at 211.
#:
#: Note what this floor does *not* do. It is a backstop, not the duplicate
#: filter: the 253-character "See the file ..." husks that unresolvable ``.so``
#: stubs produce clear it easily, and they are dropped by
#: :func:`_drop_aliases` instead. A size threshold cannot tell a short document
#: from a non-document, so nothing here asks it to.
_MIN_CHARS = 200

#: mandoc is fast (single-digit milliseconds per page) but this is still ~2,700
#: process spawns, and each one blocks on I/O with the GIL released. A small
#: thread pool turns nine seconds into two, and matters much more if MAN_ROOTS
#: ever grows.
_WORKERS = 8


class _Page(NamedTuple):
    """One man page: where it came from and where its rendered text is cached."""

    #: Stable identity, e.g. ``man1/ls.1``. Relative to the man root, so it does
    #: not change if the root moves.
    ident: str
    #: The roff source on the live system.
    source: Path
    #: The man hierarchy ``source`` was found under. Carried explicitly because
    #: ``.so`` inclusions resolve against it, and deriving it from the page's
    #: own path would quietly break the moment a root has nested sections.
    root: Path
    #: Where the rendered plain text lives inside the cache directory.
    cached: Path


def _strip_overstrike(text: str) -> str:
    """Apply backspace overstrike rather than deleting it.

    ``mandoc -Tutf8`` writes bold as ``c\\x08c`` and italic as ``_\\x08c``,
    which is the encoding a teletype understood: print, back up, print again.
    The only correct reading is the terminal's own — a backspace deletes the
    character before it — and applying that rule uniformly resolves both cases
    to the single intended character with no special-casing.

    This is decoding, not cleaning. :func:`normalise` stays the only thing that
    touches the corpus surface form; without this step it would see doubled
    letters and faithfully preserve them.
    """
    if "\x08" not in text:
        return text
    out: list[str] = []
    for char in text:
        if char == "\x08":
            if out:
                out.pop()
        else:
            out.append(char)
    return "".join(out)


def _render(source: Path, root: Path) -> str:
    """Render one roff page to plain text via ``mandoc``.

    ``cwd`` is the man root because roff ``.so`` inclusions are written relative
    to it (``.so man1/builtin.1``); run from anywhere else they silently
    resolve to nothing.

    Gzipped pages are decompressed in memory and piped to mandoc's stdin rather
    than unpacked to disk — only a handful of pages are compressed on macOS, and
    a temporary file per page is a failure mode for no benefit.
    """
    argv = ["mandoc", "-Tutf8", f"-Owidth={_RENDER_WIDTH}"]
    if source.suffix == ".gz":
        payload = gzip.decompress(source.read_bytes())
        proc = subprocess.run(argv, cwd=root, input=payload,
                              capture_output=True, timeout=60)
    else:
        proc = subprocess.run(argv + [str(source)], cwd=root,
                              capture_output=True, timeout=60)
    # mandoc exits non-zero on *style* warnings for perfectly readable pages, so
    # the exit status is not a usable signal. stdout is; an empty stdout is the
    # real failure and the caller checks the length instead.
    text = proc.stdout.decode("utf-8", errors="replace")
    text = _strip_overstrike(text)
    # mandoc emits U+00A0 where roff asked for an unpaddable space (``\ ``).
    # It means "a space", and leaving it in would spend tokens teaching the
    # model a second, invisible space character.
    return text.replace(" ", " ")


def _is_so_stub(raw: bytes) -> bool:
    """True if the page is nothing but a ``.so`` redirect to another page.

    240 of the pages here are one-line aliases — ``man1/[.1`` is ``.so
    man1/test.1``, ``atq`` and ``atrm`` both point at ``at``. Only the *first*
    real directive is examined, because plenty of genuine pages use ``.so``
    mid-body to pull in a shared fragment.

    Both outcomes of dropping these are wanted. Where the target is in this
    tree, rendering the alias produces a byte-identical copy of a page the
    corpus already has, and duplicated text in a small corpus is memorised
    rather than learned. Where the target is *not* — 75 pages here point into
    ``/System/Library/Filesystems/acfs.fs``, which macOS ships empty — mandoc
    cannot resolve it and emits a 253-character husk: an empty ``()`` running
    header and the line "See the file ../../../../System/...". That clears the
    :data:`_MIN_CHARS` floor comfortably, so the floor alone would have let 75
    near-identical non-documents into the SYSTEM register.
    """
    for line in raw[:512].decode("utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(_COMMENT_PREFIXES):
            continue
        return stripped.startswith(".so ")
    return False


def _discover(root: Path) -> list[tuple[str, Path]]:
    """Find candidate pages under one man root, as ``(ident, path)``.

    Stat-only on purpose: this runs on every build, including the warm path
    where nothing needs rendering, so it must not read 36 MB of roff to decide
    that there is nothing to do. Content-based filtering happens in
    :func:`_drop_aliases`, which only runs when a render is actually due.

    Symlinks are skipped for the same reason ``.so`` stubs are: they are
    aliases, and their content is already in the corpus under the real name.
    """
    return [
        (str(path.relative_to(root)), path)
        for path in sorted(root.rglob("*"))
        if path.is_file()
        and not path.is_symlink()
        and path.parent.name.startswith("man")
    ]


def _drop_aliases(plan: list[_Page]) -> list[_Page]:
    """Remove pages whose content is already in the corpus under another name.

    Two shapes of duplication, one rule each:

    *Alias stubs* — the whole page is a ``.so`` redirect. See
    :func:`_is_so_stub`.

    *Meta-pages* — a page with a real ``.TH`` and its own prose that
    nonetheless ``.so``-includes other pages **that are themselves in this
    set**. ``zsh`` ships exactly one: ``zshall.1`` pulls in all fourteen
    ``zsh*`` pages, and at 1.5 MB rendered it was single-handedly 4.6% of this
    source — every byte of it a second copy of text already yielded as
    ``zshbuiltins``, ``zshoptions`` and the rest. The fingerprint dedup in
    ``build.py`` cannot catch this: a concatenation of fourteen documents
    hashes to none of them.

    The membership test is what keeps this rule safe. A page that ``.so``-pulls
    a shared fragment, or a page outside this tree, includes nothing the corpus
    already has, so it is kept and rendered normally.
    """
    siblings: dict[Path, set[str]] = {}
    for page in plan:
        siblings.setdefault(page.root, set()).add(page.ident)

    kept: list[_Page] = []
    for page in plan:
        if page.source.suffix == ".gz":
            kept.append(page)          # compressed pages are never stubs here
            continue
        try:
            raw = page.source.read_bytes()
        except OSError:
            continue
        if _is_so_stub(raw):
            continue
        included = {
            target.removeprefix("./")
            for target in (
                match.decode("utf-8", errors="replace")
                for match in _SO_TARGET.findall(raw)
            )
        }
        if included & (siblings[page.root] - {page.ident}):
            continue
        kept.append(page)
    return kept


def _signature(pages: list[tuple[str, Path]]) -> str:
    """Fingerprint the *inputs*, so an OS update invalidates the cache.

    System man pages are not immutable — an OS or Homebrew update rewrites
    them. Hashing each page's identity, size and mtime costs one stat per file
    (tens of milliseconds for the whole tree) and buys the difference between a
    cache that is merely idempotent and one that is also correct.
    """
    digest = hashlib.sha256()
    digest.update(f"v{_CACHE_VERSION}:w{_RENDER_WIDTH}\n".encode())
    for ident, path in pages:
        try:
            stat = path.stat()
        except OSError:
            continue
        digest.update(f"{ident}\x00{stat.st_size}\x00{stat.st_mtime_ns}\n".encode())
    return digest.hexdigest()


def _plan(cache_dir: Path) -> tuple[str, list[_Page]]:
    """Work out what to render and where each result goes.

    Output paths mirror the man hierarchy (``pages/man1/ls.1.txt``) so the cache
    is browsable and a bad render is trivial to find by hand. Collisions are
    resolved by hashing the page's absolute source path — not its ident —
    because two different collisions need two different names. This cache lives
    on a case-insensitive volume, where ``man1/Foo.1`` and ``man1/foo.1`` would
    otherwise overwrite each other in silence; and if :data:`MAN_ROOTS` ever
    holds more than one hierarchy, several roots will offer the very same
    ident (``man1/ls.1`` exists in both the system tree and the SDK tree). An
    ident hash gives every one of those the *same* name, so the third and
    later would overwrite the second: one document silently lost and another
    silently yielded twice. The source path is unique by construction.
    """
    pages_dir = cache_dir / "pages"
    claimed: set[str] = set()
    plan: list[_Page] = []
    discovered: list[tuple[str, Path]] = []

    for root in MAN_ROOTS:
        if not root.is_dir():
            continue
        for ident, path in _discover(root):
            discovered.append((ident, path))
            key = ident.casefold()
            name = ident
            if key in claimed:
                tag = hashlib.sha256(str(path).encode()).hexdigest()[:8]
                name = f"{ident}.{tag}"
            claimed.add(key)
            plan.append(_Page(ident, path, root, pages_dir / f"{name}.txt"))

    return _signature(discovered), plan


def _fetch(cache_dir: Path) -> Path:
    """Render every local man page into the cache. No network involved.

    Returns immediately when the cache already matches the live man tree, which
    is the common case — the build runs often and this source changes only when
    the OS does. The check is a stat walk plus one JSON read, not a re-render.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = cache_dir / "manifest.json"

    signature, plan = _plan(cache_dir)
    candidates = list(plan)
    if not plan:
        raise SourceError(
            f"manpages: no man pages found under {[str(r) for r in MAN_ROOTS]}. "
            "This source reads the local machine; on a system without man pages "
            "installed it has nothing to offer and should be dropped from the "
            "build rather than left to yield zero documents."
        )

    if manifest_path.is_file():
        try:
            cached = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            cached = {}
        # The rendered pages are checked for existence, not just counted in
        # the manifest. A cache copied between volumes, interrupted mid-write
        # or partly cleaned leaves manifest.json intact while pages/ is gone,
        # and every guard downstream is happy with that: the manifest parses,
        # it lists 2,721 pages, and the source then yields zero documents
        # without raising. One stat per entry is the same order of work as the
        # signature walk this function already does, and it turns a silent
        # 32 MB hole in the corpus into a re-render.
        pages = cached.get("pages", ())
        if (cached.get("version") == _CACHE_VERSION
                and cached.get("signature") == signature
                and len(pages) > 0
                and all((cache_dir / entry.get("file", "")).is_file()
                        for entry in pages)):
            return cache_dir

    if shutil.which("mandoc") is None:
        raise SourceError(
            "manpages: mandoc(1) not found on PATH. It ships with macOS and the "
            "BSDs and is packaged as 'mandoc' elsewhere; without a roff "
            "renderer the pages on disk are markup, not text."
        )

    # Only now, with a render actually due, is it worth reading the roff.
    plan = _drop_aliases(plan)
    if not plan:
        raise SourceError("manpages: every discovered page was an alias")

    # Rebuild from scratch so a shrinking man tree does not leave stale pages
    # behind to be yielded as documents that no longer exist on the system.
    pages_dir = cache_dir / "pages"
    if pages_dir.exists():
        shutil.rmtree(pages_dir)
    for page in plan:
        page.cached.parent.mkdir(parents=True, exist_ok=True)

    def render_one(page: _Page) -> tuple[str, str] | None:
        try:
            text = _render(page.source, page.root)
        except (OSError, subprocess.SubprocessError, gzip.BadGzipFile,
                zlib.error, EOFError):
            return None
        if len(text.strip()) < _MIN_CHARS:
            return None
        page.cached.write_text(text, encoding="utf-8")
        return page.ident, page.cached.relative_to(cache_dir).as_posix()

    with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
        results = [r for r in pool.map(render_one, plan) if r is not None]

    if not results:
        raise SourceError("manpages: mandoc rendered every page to nothing")

    manifest_path.write_text(
        json.dumps(
            {
                "version": _CACHE_VERSION,
                "signature": signature,
                "roots": [str(root) for root in MAN_ROOTS],
                "width": _RENDER_WIDTH,
                "candidates": len(candidates),
            "rendered_from": len(plan),
                "pages": [{"ident": ident, "file": rel} for ident, rel in results],
            },
            indent=1,
        ),
        encoding="utf-8",
    )
    return cache_dir


def _documents(path: Path) -> Iterator[Document]:
    """Yield one Document per rendered page, in manifest order.

    Reads only the cache, never the live system: the rendering decisions were
    made and recorded by :func:`_fetch`, and re-deriving them here would make
    the corpus depend on whether mandoc happened to be installed at build time.
    """
    manifest_path = path / "manifest.json"
    if not manifest_path.is_file():
        raise SourceError(f"manpages: no manifest at {manifest_path}; run fetch first")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    entries = list(manifest.get("pages", ()))
    budgets = _family_budgets(path, entries)
    spent: dict[str, int] = {}
    dropped: dict[str, int] = {}

    for entry in entries:
        file = path / entry["file"]
        try:
            raw = file.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            # Not skippable. The manifest is this source's own record of what
            # it rendered, so a listed page that cannot be read means the cache
            # is damaged, and quietly dropping it would shrink the SYSTEM
            # register by an unknown amount while the build reported success.
            raise SourceError(
                f"manpages: manifest lists {entry['ident']} at {file}, which "
                "could not be read. The cache is damaged; delete "
                f"{path} and re-fetch."
            ) from exc
        text = normalise(raw)
        if len(text) < _MIN_CHARS:
            continue

        family = _family(entry["ident"])
        cap = budgets.get(family)
        if cap is not None:
            if spent.get(family, 0) + len(text) > cap:
                dropped[family] = dropped.get(family, 0) + 1
                continue
            spent[family] = spent.get(family, 0) + len(text)

        yield Document(text=text, source="manpages", register=Register.SYSTEM,
                       side=Side.NEUTRAL, ident=entry["ident"])

    # No silent caps: say what was held back and why.
    for family, count in sorted(dropped.items(), key=lambda kv: -kv[1]):
        print(f"   manpages: held back {count} {family} page(s) at the "
              f"{_FAMILY_CAP:.0%} per-family cap")


#: No single topic family may exceed this share of the source's characters.
#:
#: Measured before this existed: Perl pages were 30.4% of this source and Tcl/Tk
#: another 23.6%, so 54% of the largest SYSTEM contributor was *language and
#: library API reference* rather than system documentation. ``perltoc.1`` alone
#: is 715 KB of pure table of contents. That is the same objection MAN_ROOTS
#: already uses to justify excluding the SDK's man3 root — it simply also
#: applied to what shipped.
#:
#: A cap rather than an exclusion, because a model that has never seen a Perl
#: man page is worse than one that has seen a few: the *form* is SYSTEM-register
#: and worth learning. What is not worth learning is 715 KB of one program's
#: index. The cap is general, so the next library that installs a thousand pages
#: is bounded automatically instead of being discovered by hand.
_FAMILY_CAP = 0.08


def _family(ident: str) -> str:
    """Group pages into topic families for the concentration cap.

    Crude on purpose: name prefix for the sprawling language distributions,
    section for everything else. A cleverer classifier would be a second thing
    to keep correct, and the cap only needs to catch families large enough to
    distort a register.
    """
    name = ident.rsplit("/", 1)[-1].lower()
    section = ident.split("/", 1)[0] if "/" in ident else ""
    for prefix in ("perl", "tcl", "tk", "git-", "zsh", "openssl", "ssl_", "bio_",
                   "evp_", "x509", "pkey", "curl_"):
        if name.startswith(prefix):
            return prefix.rstrip("_-")
    if section == "mann":            # Tcl/Tk ships its whole API here
        return "tcl"
    return f"section:{section}" if section else "other"


def _family_budgets(path: Path, entries: list[dict]) -> dict[str, int]:
    """Character budget per family, from the manifest's own recorded sizes.

    Computed from the manifest rather than by rendering everything twice, so the
    cap costs one pass over metadata instead of a second full read.
    """
    sizes: dict[str, int] = {}
    total = 0
    for entry in entries:
        try:
            n = (path / entry["file"]).stat().st_size
        except OSError:
            continue
        sizes[_family(entry["ident"])] = sizes.get(_family(entry["ident"]), 0) + n
        total += n
    if not total:
        return {}

    cap = int(total * _FAMILY_CAP)
    # Only *topic* families are capped. A man section is not a topic
    # concentration, it is the register itself: the first attempt at this
    # capped ``section:man1`` and held back 512 pages of core command
    # documentation — the single most valuable content in the source — while
    # dutifully protecting the corpus from too much of it. Sections are exempt.
    return {
        family: cap
        for family, size in sizes.items()
        if size > cap and not family.startswith("section:")
    }


SPEC = SourceSpec(
    name="manpages",
    license=(
        "Mixed: per-page upstream licences, read from this machine's own "
        "installed copies. The set spans 4.4BSD/BSD-3-Clause, Apple APSL-2.0, "
        "GPL-2.0-or-later, Tcl/Tk BSD-style and MIT, among others, and no single "
        "SPDX identifier is true of it. Locally installed documentation, used "
        "locally; the raw cache is NOT redistributable as one blob."
    ),
    url="file:///usr/share/man (local system man hierarchy; upstreams vary per page)",
    register=Register.SYSTEM,
    side=Side.NEUTRAL,
    fetch=_fetch,
    documents=_documents,
    expect_min_docs=2000,
    notes=(
        "Offline, no network. Rendered with mandoc(1) at a pinned 78-column "
        "width; backspace-overstrike bold/italic is applied and removed before "
        "normalise() sees it, since normalise strips \\x08 and would otherwise "
        "leave doubled letters. Skips symlinks and 240 one-line '.so' alias "
        "stubs, which would be exact duplicates. Cache is invalidated by a "
        "size/mtime signature of the man tree, so an OS update re-renders. "
        "Section man2/man3 pages live only in the CommandLineTools SDK root and "
        "are deliberately excluded — see MAN_ROOTS."
    ),
)
