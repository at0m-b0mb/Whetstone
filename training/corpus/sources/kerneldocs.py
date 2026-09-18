"""Linux kernel ``Documentation/`` — the SYSTEM register at volume.

The tokenizer measurement behind :mod:`training.corpus.source` said the first
corpus was starved of SYSTEM text: how the machine describes itself. Man pages
are the canonical example, but they describe *userland utilities*. The kernel's
own documentation tree describes the layer underneath — the one an attacker
pivots through and a defender instruments — and it does so in exactly the
surface forms the model must read:

* ``/sys`` and ``/proc`` attribute paths with their types and semantics
  (``Documentation/ABI/`` is 686 files of nothing else),
* ``sysctl`` knob names and their value ranges (``net.ipv4.tcp_syncookies``),
* kernel command-line parameters (``kernel-parameters.txt`` alone is 250 KB of
  ``name=value`` option reference),
* mount options, capability names, LSM and seccomp semantics, namespace and
  cgroup layout, netlink and ioctl definitions,
* and a very large amount of ``struct``/ioctl/uapi reference under
  ``userspace-api/``.

None of that is prose *about* systems; it is the system's own reference text,
and the surface form is the signal.

**Only ``Documentation/`` is downloaded, not the kernel.** The full source
tarball is roughly a quarter of a gigabyte and ``Documentation/`` is 15 MB of
it. The saving does not come from a server-side filter — GitHub offers none —
it comes from *where the subtree sits in the stream*. ``git archive`` emits
entries in git's own sorted tree order, and at the repository root that order
begins ``.clang-format`` … ``COPYING``, ``CREDITS``, ``Documentation/`` …
``Kbuild``, ``Kconfig``, ``LICENSES/``, ``MAINTAINERS``, ``arch/`` …. Everything
this adapter wants is in the first few percent of the archive, so the tarball is
consumed as a *stream* and the connection is dropped the moment the reader walks
past ``LICENSES/``. Measured against ``v7.2``: 14.9 MB over the wire in three
seconds, versus ~250 MB for the whole tree.

That is an ordering assumption, so it is checked rather than trusted:
:data:`_MIN_FILES` is a floor on what must have been extracted before the cache
is declared good, and the error it raises names the assumption explicitly. If
upstream ever changes how the archive is generated, this source fails loudly at
fetch time instead of quietly contributing a tenth of what it promised.

**``translations/`` is excluded.** 572 files and 4.9 MB of the tree are zh_CN,
ja_JP, ko_KR, it_IT and sp_SP renderings of documents that are already here in
English. They are duplicates *in meaning* and non-English *in form*, so they
would both dilute the register and defeat fingerprint dedup, which hashes
characters and cannot tell a translation from a new document.

**``devicetree/`` is capped, not excluded.** It is the single largest subtree —
17.4 MB in 6,296 files, a third of everything left after translations — and it
is 5,636 YAML binding schemas built from one skeleton: the same SPDX header, the
same ``$id``/``$schema``/``maintainers``/``properties``/``required``/
``additionalProperties`` frame, differing in a compatible string and a handful
of hardware properties. That is the manpages/Perl failure in a new costume, and
:data:`_SUBTREE_CAP` is the same answer: keep enough that the *form* is learned,
refuse to let one embedded-hardware sub-topic own a third of the largest SYSTEM
source. In practice 4,761 files / 13.0 MB are held back and the subtree lands at
12.3% of what ships, still spanning 88 of its second-level directories. What is
held back is printed on every build, never silent.

**Indentation is the document.** reStructuredText encodes structure entirely in
indentation: a ``.. code-block:: c`` directive's body, a definition-list term
versus its definition, the two-space continuation of an option table.
:func:`~training.corpus.source.normalise` preserves horizontal whitespace, which
is precisely why it is used here unmodified and no private cleaner exists in
this file. The ABI files depend on it just as hard — a ``What:``/``Date:``/
``Description:`` stanza with its indentation collapsed is a different document.

**Licence, counted rather than assumed.** ``COPYING`` says the kernel is
provided under ``GPL-2.0 WITH Linux-syscall-note``, and points at ``LICENSES/``
for the per-file SPDX tags that individual files carry. Both ``COPYING`` and the
whole ``LICENSES/`` directory are pulled into the cache beside the text, so the
claim in :data:`SPEC` is checkable against the evidence it came from. Tallying
the tags across the 10,612 cached files gives::

    4904  GPL-2.0 OR BSD-2-Clause          (essentially all devicetree bindings)
    2907  (untagged — falls back to COPYING)
    2110  GPL-2.0
     320  GFDL-1.1-no-invariants-or-later  (userspace-api/media/)
     151  GPL-2.0-or-later
      41  GPL-2.0-or-later OR MIT
      38  GPL-2.0 OR GFDL-1.1-no-invariants-or-later
      21  MIT            8  BSD-3-Clause          8  LGPL-2.1 OR BSD-2-Clause

Two things in that table are worth saying out loud, because guessing would have
got both wrong. The documentation-specific licence in this tree is **GFDL**, not
Creative Commons: 367 files carry a GFDL tag — 362 of them under
``userspace-api/media/``, a licence the kernel itself keeps in
``LICENSES/deprecated/`` — while ``CC-BY-4.0`` appears on exactly seven files,
always as the dual option in ``GPL-2.0+ OR CC-BY-4.0``, and ``CC-BY-SA-4.0``
does not appear at all. And the set is not uniformly GPL: a few dozen files are
MIT-only or BSD-3-Clause-only. So the spec declares the mixture, not a single
tidy identifier.

None of it is redistributed. The cache is fetched from upstream by whoever runs
the build, on their own machine; this project ships the adapter, not the corpus.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import shutil
import tarfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Iterator

from ..net import USER_AGENT, ssl_context
from ..source import Document, Register, Side, SourceError, SourceSpec, normalise

#: A pinned released tag, not a branch. ``Documentation/`` churns every merge
#: window, and an unpinned ``master`` would make two builds on two days produce
#: two different corpora with no record of which. Bump this deliberately.
_REPO = "torvalds/linux"
_REF = "v7.2"
_TARBALL_URL = f"https://codeload.github.com/{_REPO}/tar.gz/refs/tags/{_REF}"

#: The subtree that is the corpus.
_SUBTREE = "Documentation"

#: Fetched alongside it purely so the licence claim is checkable in the cache.
#: ``COPYING`` precedes ``Documentation/`` in the archive and ``LICENSES/``
#: follows it, which is why the stream runs on for the two tiny root files in
#: between rather than stopping at the end of the subtree.
_LICENSE_PATHS = ("COPYING", "LICENSES")

#: Byte-compare sentinel for the early abort. Every archive member whose
#: top-level name sorts after this one is kernel source we do not want, so the
#: first of them ends the download. See the module docstring.
_STOP_AFTER = "LICENSES"

#: Written last, after a complete extraction. Its presence — not the presence of
#: the directory — is what lets ``fetch`` skip the network, so an interrupted run
#: re-fetches instead of yielding a half tree.
_MARKER = ".kerneldocs-complete.json"

#: Bumped whenever a change here alters *which files land in the cache*, so an
#: already-populated cache is rebuilt instead of silently keeping files a newer
#: filter would have excluded. Extraction-time filtering buys a cache that is
#: exactly the corpus, but it means the filter and the cache can disagree; this
#: is what keeps them honest. (v2 dropped ``.renames.txt`` and the Sphinx config
#: files, which a v1 cache still contains.)
_CACHE_VERSION = 2

#: v7.2 shipped 11,300 files under ``Documentation/``, of which 10,612 survive
#: the filters and reach the cache. A floor at roughly a third of that does not
#: police upstream's churn; it catches the two ways this adapter breaks — the
#: archive ordering assumption failing (so the stream aborts before the subtree
#: is reached) and the subtree being renamed.
_MIN_FILES = 4000

#: Never write these into the cache. Images and stylesheets are presentation,
#: not text; a 3.7 MB pile of ``.svg`` is XML markup with no referent in any
#: tool output a model will ever read, which is the same objection that left
#: 1,014 ``<code>`` tags in another source.
_SKIP_SUFFIXES = frozenset({
    ".svg", ".png", ".gif", ".jpg", ".jpeg", ".webp", ".bmp", ".ico", ".pdf",
    ".css", ".sty", ".woff", ".woff2", ".ttf",
})

#: Sphinx build machinery that happens to live in the documentation tree.
#: ``Documentation/sphinx/`` is Python extensions for the doc build. Real files,
#: wrong register: shipping the doc toolchain's own source as SYSTEM reference
#: text teaches the model that ``kernel-doc`` extension internals are what
#: ``/sys`` documentation looks like.
_SKIP_PREFIXES = (f"{_SUBTREE}/sphinx/",)

#: Matched on basename, anywhere in the tree. Two categories, both machinery
#: rather than documentation:
#:
#: ``conf.py``, ``conf_nitpick.py``, ``docutils.conf`` and ``Makefile`` drive
#: the Sphinx build. ``.renames.txt`` is a 66 KB two-column lookup table mapping
#: every old document path to its new one — 2,000 lines of
#: ``80211/cfg80211 driver-api/80211/cfg80211`` and nothing else. It sorts first
#: in the tree, so before this list existed it was literally document zero of
#: this source: the same degenerate-table objection that keeps ``perltoc.1`` out
#: of the manpages source, and a shape the model would learn as if it were text.
_SKIP_NAMES = frozenset({
    "conf.py", "conf_nitpick.py", "docutils.conf", "Makefile",
    ".renames.txt", ".gitignore",
})

#: Mandated exclusion: a fifth of the tree is translated duplicates.
_TRANSLATIONS = f"{_SUBTREE}/translations/"

#: No subtree may exceed this share of the characters this source actually
#: yields. 12% rather than manpages' 8%: the named high-value subtrees here are
#: individually large (``admin-guide/`` is 7.8% of the tree, ``userspace-api/``
#: 6.9%), and a cap tight enough to bite them would be protecting the corpus
#: from the best thing in it. At 12% exactly one subtree is caught, which is the
#: one that needed catching. See :func:`_keeps` for why this is solved as a
#: fixed point rather than applied as a fraction of the input.
_SUBTREE_CAP = 0.12

#: Sampling granularity for a capped subtree. See :func:`_keeps`.
_BUCKETS = 10_000

#: Floor for a document worth keeping. Deliberately low: an ABI stanza is often
#: only a few hundred characters (``What:``/``Date:``/``Contact:``/
#: ``Description:``) and is some of the densest SYSTEM text in the tree. This
#: only discards stubs, index fragments and near-empty placeholders.
_MIN_CHARS = 120

_TIMEOUT = 300

#: ``.. raw:: html`` and ``.. raw:: latex`` blocks: a directive plus its
#: indented body, which is literal markup passed through to the renderer and
#: appears in no tool output anywhere. Matched with the body's indentation so
#: the whole block goes, not just its first line.
_RAW_BLOCK = re.compile(
    r"^([ \t]*)\.\.[ \t]+raw::[ \t]*(?:html|latex).*\n"
    r"(?:(?:\1[ \t]+.*)?\n)*",
    re.MULTILINE,
)

#: **There is no HTML tag stripper here, and that is a measured decision.**
#:
#: reStructuredText has no inline HTML. A ``<p>`` sitting in a ``.rst`` file is
#: not markup and Sphinx does not render it as markup; HTML can only enter a
#: document through a ``.. raw:: html`` block, which :data:`_RAW_BLOCK` already
#: removes whole. So a tag regex over this corpus has nothing true to find, and
#: two rounds of measurement say so.
#:
#: Matching *known HTML tag names* (``a|b|br|code|…|i|p|sub|u``) deleted 152
#: spans from v7.2, of which **zero were HTML**::
#:
#:     hwmon/hwmon<i>/in0_input      -> hwmon/hwmon/in0_input      (x51, ABI)
#:     Format: <a>,<b>               -> Format: ,                  (kernel-parameters)
#:     …,<flags>,<table>[,<table>+]  -> …,<flags>,[,+]             (dm-init)
#:     video=<fbname>:<sub-options…> -> video=<fbname>:            (m68k options)
#:     Philipp Zabel <p.zabel@…>     -> Philipp Zabel              (x73 e-mails)
#:
#: ``<p.zabel@pengutronix.de>`` opens with a word-bounded ``p``, and ``<i>`` in
#: a sysfs path *is* the letter i. That is precisely the SYSTEM-register
#: vocabulary this source exists to supply, destroyed by the cleaner meant to
#: protect it.
#:
#: Tightening the rule to *shape* instead of name — closing tags, self-closing
#: tags, and opening tags carrying a real ``name="value"`` attribute — is no
#: better. It matches 45 spans in v7.2 and all 45 are content too: the libvirt
#: XML an administrator must type (``networking/net_failover.rst``,
#: ``arch/s390/vfio-ap.rst``), the SVG example in ``doc-guide/sphinx.rst``, the
#: Coccinelle ``</smpl>`` delimiter, and the pseudo-tags kernel notation uses
#: for scope — ``</IRQ>`` in a stack trace, ``<interrupt>`` … ``</interrupt>``
#: in ``memory-barriers.txt``.
#:
#: Direct evidence for the tree as a whole: zero closing HTML tags, zero
#: attributed HTML tags, zero ``<br>``/``<hr>``, and all 210 ``.. raw::``
#: directives are ``latex``. Every angle-bracket construct in this corpus is a
#: metavariable, a devicetree cell literal, an e-mail address, kernel notation
#: or a documented XML/SVG example. Nothing is stripped, because there is
#: nothing to strip and the false-positive cost lands on exactly the text this
#: source was collected for.

#: Named and numeric HTML entities, resolved to the character they denote rather
#: than deleted, so ``R&amp;D`` becomes ``R&D`` and not ``RD``.
#:
#: An unrecognised name is left untouched on purpose, and that branch earns its
#: keep: all 39 ``&name;`` tokens surviving in the finished output (33 distinct)
#: are ``&linfo;``, ``&req;``, ``&resp;``, ``&sym;`` (C address-of in example
#: code: ``opts.link_info = &linfo;``) and ``&avb;``, ``&fiux;``, ``&dsp0;``,
#: ``&usb1;`` … (devicetree phandle references: ``ethernet0 = &avb;``). None is
#: an entity. A resolver that deleted whatever it could not name would have
#: quietly corrupted working C and DT source instead.
#:
#: Counted the other way, this table fires **zero** times on v7.2: no named or
#: numeric entity appears anywhere in the tree. It stays as a by-name guard
#: that cannot do harm, not because it is doing work.
_ENTITY = re.compile(r"&(?:#\d{1,5}|#[xX][0-9a-fA-F]{1,5}|[a-zA-Z][a-zA-Z0-9]{1,9});")
_ENTITIES = {
    "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"', "&apos;": "'",
    "&nbsp;": " ", "&ndash;": "-", "&mdash;": "-", "&hellip;": "...",
    "&rarr;": "->", "&larr;": "<-", "&times;": "x", "&copy;": "(c)",
    "&reg;": "(R)", "&trade;": "(TM)", "&deg;": " degrees", "&micro;": "u",
}


def _wanted(relative: str) -> bool:
    """True if this archive path belongs in the cache."""
    if relative in _LICENSE_PATHS or relative.startswith("LICENSES/"):
        return True
    if not relative.startswith(f"{_SUBTREE}/"):
        return False
    if relative.startswith(_TRANSLATIONS) or relative.startswith(_SKIP_PREFIXES):
        return False
    name = relative.rsplit("/", 1)[-1]
    if name in _SKIP_NAMES:
        return False
    return Path(name).suffix.lower() not in _SKIP_SUFFIXES


def _extract(staging: Path) -> tuple[int, int, str]:
    """Stream the tarball into ``staging``; return (files, wire bytes, prefix sha).

    Members are written by hand rather than through ``extractall``. A tar entry
    is attacker-controlled data in principle — absolute paths, ``..`` segments,
    symlinks and device nodes are all expressible — and the cheap defence is to
    never hand an archive's own names to the filesystem unchecked. Only regular
    files are written, and every destination is proved to resolve inside
    ``staging`` first. Symlinks are dropped outright rather than recreated: a
    symlink in the cache is a symlink :func:`_documents` would have to reason
    about, and the rule there is that it never follows one.

    The sha256 is of the *prefix actually read*, not of the whole tarball, since
    the whole tarball is deliberately never downloaded. It is provenance, not a
    checksum to compare against upstream: it says which bytes this cache was
    built from.
    """
    staging.mkdir(parents=True, exist_ok=True)
    root = staging.resolve()
    digest = hashlib.sha256()
    written = 0
    wire = 0

    class _Counting:
        """Tee the compressed stream through a hash and a byte counter."""

        def __init__(self, fp) -> None:
            self._fp = fp

        def read(self, size: int = -1) -> bytes:
            nonlocal wire
            chunk = self._fp.read(size)
            digest.update(chunk)
            wire += len(chunk)
            return chunk

    request = urllib.request.Request(_TARBALL_URL, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT,
                                    context=ssl_context()) as response:
            counting = _Counting(response)
            with tarfile.open(fileobj=counting, mode="r|gz") as tar:
                for member in tar:
                    parts = member.name.split("/")
                    # Drop the archive's single root directory ("linux-7.2/").
                    if len(parts) < 2 or not parts[1]:
                        continue
                    if parts[1] > _STOP_AFTER:
                        break                      # the early abort; see above
                    relative = "/".join(parts[1:])
                    if ".." in parts or relative.startswith("/"):
                        continue
                    if not member.isfile() or not _wanted(relative):
                        continue

                    target = staging / relative
                    if not target.resolve().is_relative_to(root):
                        continue
                    handle = tar.extractfile(member)
                    if handle is None:
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with handle, target.open("wb") as out:
                        shutil.copyfileobj(handle, out)
                    if relative.startswith(f"{_SUBTREE}/"):
                        written += 1
    # http.client.HTTPException is in the tuple for IncompleteRead, which a body
    # that ends early raises and which is NOT an OSError — its MRO is
    # HTTPException -> Exception. Uncaught, a truncated transfer partway through
    # a 1.5 GB stream escapes as something no caller in this package catches,
    # instead of the "could not fetch" this source is supposed to report.
    except (urllib.error.URLError, http.client.HTTPException, tarfile.TarError,
            TimeoutError, OSError) as exc:
        raise SourceError(f"kerneldocs: could not fetch {_TARBALL_URL}: {exc}") from exc

    if written < _MIN_FILES:
        raise SourceError(
            f"kerneldocs: only {written} files extracted under {_SUBTREE}/ from "
            f"{_TARBALL_URL} (expected >= {_MIN_FILES}).\n"
            "This adapter reads the tarball as a stream and stops at the first "
            f"root entry sorting after {_STOP_AFTER!r}, because git archive emits "
            "entries in sorted tree order and Documentation/ sits near the front. "
            "Either that ordering no longer holds or the subtree was renamed. Fix "
            "the adapter rather than training on a fragment of the SYSTEM register."
        )
    return written, wire, digest.hexdigest()


def _fetch(cache_dir: Path) -> Path:
    """Populate ``cache_dir`` with ``Documentation/``; return the cache root.

    Idempotent and network-free on re-run: the marker is written only after a
    complete extraction that cleared :data:`_MIN_FILES`, so a populated cache
    short-circuits on one ``is_file`` call. Extraction goes to a staging
    directory inside ``cache_dir`` and is moved into place at the end, so an
    interrupted fetch cannot leave a truncated tree that a later run mistakes
    for a finished one. Nothing is written outside ``cache_dir``.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    docs_dir = cache_dir / _SUBTREE
    marker = cache_dir / _MARKER
    if marker.is_file() and docs_dir.is_dir():
        try:
            recorded = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            recorded = {}
        if recorded.get("version") == _CACHE_VERSION and recorded.get("ref") == _REF:
            return cache_dir

    # Retire the marker BEFORE touching the tree it vouches for, so the
    # invariant "marker present implies tree complete" holds at every instant.
    # Removing the old tree and renaming the new one into place is not atomic,
    # and a run interrupted inside that window would otherwise leave a current
    # marker sitting on top of a half-deleted Documentation/ — which the warm
    # path above would accept.
    marker.unlink(missing_ok=True)

    staging = cache_dir / ".staging"
    shutil.rmtree(staging, ignore_errors=True)
    try:
        written, wire, prefix_sha = _extract(staging)

        shutil.rmtree(docs_dir, ignore_errors=True)
        (staging / _SUBTREE).replace(docs_dir)
        for name in _LICENSE_PATHS:
            source = staging / name
            if not source.exists():
                continue
            destination = cache_dir / name
            if destination.is_dir():
                shutil.rmtree(destination, ignore_errors=True)
            else:
                destination.unlink(missing_ok=True)
            source.replace(destination)

        # Marker last: it is the only thing that says "this cache is complete".
        marker.write_text(
            json.dumps(
                {
                    "version": _CACHE_VERSION,
                    "url": _TARBALL_URL,
                    "repo": _REPO,
                    "ref": _REF,
                    "files": written,
                    "wire_bytes": wire,
                    "prefix_sha256": prefix_sha,
                    "note": ("sha256 covers only the leading bytes of the tarball "
                             "that were actually read before the early abort"),
                    "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return cache_dir


def _walk(docs_dir: Path) -> list[tuple[str, int]]:
    """Every cached file as ``(tree-relative path, size)``, sorted.

    ``os.walk(followlinks=False)`` rather than ``Path.rglob``: rglob follows
    directory symlinks, and a sibling adapter once followed this repository's
    ``data`` symlink onto an external volume and copied 180 MB of the corpus
    cache back into the corpus, relabelled. :func:`_extract` already refuses to
    write symlinks, so this is the second of two locks on the same door.
    """
    out: list[tuple[str, int]] = []
    base = docs_dir.parent
    for dirpath, dirnames, filenames in os.walk(docs_dir, followlinks=False):
        here = Path(dirpath)
        dirnames[:] = sorted(
            name for name in dirnames if not (here / name).is_symlink()
        )
        for name in sorted(filenames):
            path = here / name
            if path.is_symlink():
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            out.append((path.relative_to(base).as_posix(), size))
    return out


def _subtree(ident: str) -> str:
    """The concentration family: the first directory under ``Documentation/``.

    Crude by design, and matching how the tree is actually organised — one
    directory per kernel subsystem or audience. Files sitting directly in
    ``Documentation/`` are their own family and are far too small to be capped.
    """
    parts = ident.split("/")
    return parts[1] if len(parts) > 2 else "(root)"


def _keeps(files: list[tuple[str, int]]) -> dict[str, float]:
    """Keep-probability per over-represented subtree; unconstrained ones omitted.

    Two decisions here, and both were wrong on the first attempt.

    *The budget is a fixed point, not a fraction of the input.* Capping a family
    at ``cap × total`` does not leave it holding ``cap`` of the result, because
    removing its text also shrinks the denominator. Measured: a 12% budget
    computed that way left ``devicetree/`` at **16.2%** of the built source — a
    cap that did not bound the thing it claimed to bound. Solving instead for
    the share of what actually ships, with ``n`` oversized families each given
    budget ``b`` out of a surviving remainder ``R = total - Σ sizes``::

        b = cap × (R + n·b)   ⇒   b = cap·R / (1 - cap·n)

    which for one oversized family and ``cap = 0.12`` is the intended 12%.

    *The sample is drawn by hashing the path, not by filling a budget in sorted
    order.* Truncation would spend the whole devicetree budget on
    ``bindings/arm`` through ``bindings/clock`` and yield nothing from ``net``,
    ``regulator``, ``sound`` or ``usb``: a sample biased by the alphabet is not
    a sample of the subtree. A path hash is deterministic (the same files every
    build, no RNG seed to carry), uniform across the tree, and stable when
    upstream adds files. It reaches 88 of devicetree's second-level directories.
    """
    sizes: dict[str, int] = {}
    for ident, size in files:
        sizes[_subtree(ident)] = sizes.get(_subtree(ident), 0) + size
    total = sum(sizes.values())
    if not total:
        return {}

    oversized = {f: s for f, s in sizes.items() if s > total * _SUBTREE_CAP}
    if not oversized:
        return {}
    remainder = total - sum(oversized.values())
    denominator = 1 - _SUBTREE_CAP * len(oversized)
    if denominator <= 0 or remainder <= 0:
        # Two ways the fixed point has no useful solution, and both would
        # otherwise delete the source rather than cap it.
        #
        # ``denominator <= 0``: more than 1/cap families are oversized, so they
        # cannot all be held to ``cap`` of the result — the solution is negative.
        #
        # ``remainder <= 0``: *every* family is oversized, so there is no
        # uncapped text left to be a share of and ``b = cap·R/(1-cap·n)``
        # evaluates to exactly 0 — a keep-probability of zero for every family,
        # which yields an empty source. Measured: seven equal families at 14.3%
        # each returns ``{a: 0.0 … g: 0.0}`` and 0 documents. Not reachable on
        # today's tree (only devicetree/ is oversized and the remainder is 30 MB)
        # but a reorganised Documentation/ would hit it, and silently shipping
        # nothing is the worst available failure.
        #
        # In both cases fall back to the plain fraction-of-input budget, which
        # bounds nothing but destroys nothing, and let the printed report show
        # what the cap actually achieved.
        budget = total * _SUBTREE_CAP
    else:
        budget = _SUBTREE_CAP * remainder / denominator
    return {family: budget / size for family, size in oversized.items()}


def _bucket(ident: str) -> int:
    """Stable 0..:data:`_BUCKETS` position for a path, for cap sampling."""
    return int.from_bytes(hashlib.sha256(ident.encode()).digest()[:4], "big") % _BUCKETS


def _decode(raw: bytes) -> str:
    """UTF-8, falling back to Latin-1 rather than to replacement characters.

    A handful of kernel documents are still Latin-1 (maintainer names with
    umlauts in old ``.txt`` files). ``errors="replace"`` would spend real
    vocabulary on U+FFFD; Latin-1 decodes every byte to *some* character and at
    least gets the ASCII skeleton — which is all of the document that carries
    register — exactly right.
    """
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _strip_markup(text: str) -> str:
    """Remove renderer passthrough. Everything else is the document.

    reStructuredText is the corpus here and stays untouched — directives,
    ``::`` literal blocks and indentation are structure, and the brief for this
    source is explicit that nothing structural is stripped.

    That leaves exactly one thing to remove: ``.. raw::`` blocks, which are
    literal renderer instructions (all 210 in v7.2 are ``latex`` —
    ``\\begingroup``, ``\\tiny``, ``\\setlength{\\tabcolsep}{2pt}``) and appear
    in no tool output anywhere. No tag stripping happens, for the reasons
    measured at :data:`_RAW_BLOCK`'s neighbour above; the entity resolver stays
    because it is by-name and therefore cannot corrupt, though on v7.2 it
    resolves nothing at all.
    """
    text = _RAW_BLOCK.sub("", text)
    if "&" in text:
        text = _ENTITY.sub(_entity, text)
    return text


def _entity(match: re.Match[str]) -> str:
    """Resolve one HTML entity to the character it denotes."""
    token = match.group(0)
    known = _ENTITIES.get(token.lower())
    if known is not None:
        return known
    body = token[2:-1]
    try:
        code = int(body[1:], 16) if body[:1] in "xX" else int(body)
    except ValueError:
        return token          # not an entity after all — leave the text alone
    if 0 < code < 0x110000:
        return chr(code)
    return token


def _documents(path: Path) -> Iterator[Document]:
    """Yield one Document per cached documentation file, in sorted path order.

    Accepts either the cache root or the ``Documentation/`` directory itself, so
    a caller who passes the fetch result or the subtree both work.
    """
    docs_dir = path / _SUBTREE if (path / _SUBTREE).is_dir() else path
    if not docs_dir.is_dir():
        raise SourceError(
            f"kerneldocs: no {_SUBTREE}/ tree under {path}; run fetch first"
        )

    files = _walk(docs_dir)
    if not files:
        raise SourceError(f"kerneldocs: {docs_dir} is empty; the cache is damaged")

    keeps = _keeps(files)
    held: dict[str, int] = {}
    held_chars: dict[str, int] = {}
    kept_chars: dict[str, int] = {}

    for ident, size in files:
        family = _subtree(ident)
        ratio = keeps.get(family)
        if ratio is not None and _bucket(ident) >= ratio * _BUCKETS:
            held[family] = held.get(family, 0) + 1
            held_chars[family] = held_chars.get(family, 0) + size
            continue

        try:
            raw = (docs_dir.parent / ident).read_bytes()
        except OSError:
            # Unlike manpages, this cache is not driven by a manifest of what
            # was written, so an unreadable file is a filesystem problem rather
            # than evidence of a damaged record. Skipping is the honest move;
            # the expect_min_docs floor in the build report is what catches a
            # cache that has lost enough files to matter.
            continue
        text = normalise(_strip_markup(_decode(raw)))
        if len(text) < _MIN_CHARS:
            continue
        kept_chars[family] = kept_chars.get(family, 0) + len(text)
        yield Document(
            text=text,
            source="kerneldocs",
            register=Register.SYSTEM,
            side=Side.NEUTRAL,
            ident=ident,
        )

    # No silent caps: say what was held back, and what share the cap achieved.
    total_kept = sum(kept_chars.values())
    for family, count in sorted(held.items(), key=lambda kv: -kv[1]):
        share = kept_chars.get(family, 0) / total_kept if total_kept else 0.0
        print(f"   kerneldocs: held back {count} file(s) / "
              f"{held_chars[family] / 1e6:.1f} MB from {_SUBTREE}/{family}/ — "
              f"{_SUBTREE_CAP:.0%} per-subtree cap, now {share:.1%} of the source")


SPEC = SourceSpec(
    name="kerneldocs",
    license=(
        "GPL-2.0 WITH Linux-syscall-note, per the kernel's own COPYING, which "
        "is the licence of the work as a whole and the fallback for the 2,907 "
        "cached files carrying no tag of their own. Documentation/ files are "
        "individually SPDX-tagged and the set is genuinely mixed: 4,904 are "
        "'GPL-2.0-only OR BSD-2-Clause' (the devicetree bindings), 2,110 plain "
        "GPL-2.0, 320 are GFDL-1.1-no-invariants-or-later (userspace-api/media/ "
        "— GFDL, NOT CC-BY-SA; CC-BY-4.0 appears on seven files), and a few "
        "dozen are MIT-only or BSD-3-Clause-only. Counted from the tree, not "
        "assumed. COPYING and the full LICENSES/ directory are cached beside "
        "the text so the claim is checkable. Nothing here is redistributed: "
        "each build fetches from upstream on its own machine."
    ),
    url="https://github.com/torvalds/linux/tree/v7.2/Documentation",
    register=Register.SYSTEM,
    side=Side.NEUTRAL,
    fetch=_fetch,
    documents=_documents,
    #: v7.2 yields 5,795 documents / 35.1M characters after translations are
    #: dropped, the devicetree cap is applied and short stubs are floored out.
    #: The floor sits well under that so it catches breakage, not upstream churn.
    expect_min_docs=4800,
    notes=(
        "Documentation/ only, streamed out of the codeload tarball and aborted "
        "once the reader passes LICENSES/ — 15 MB on the wire instead of ~250 MB, "
        "relying on git archive's sorted tree order and checked by a file-count "
        "floor. translations/ (zh_CN, ja_JP, ko_KR, it_IT, sp_SP) is excluded as "
        "non-English duplicates; devicetree/ is sampled down to a 12% share "
        "because 5,636 YAML binding schemas share one skeleton; images, "
        "stylesheets and the Sphinx build machinery are excluded. RST directive "
        "and code-block indentation is preserved — normalise() keeps horizontal "
        "whitespace and no private cleaner exists here. The only thing removed "
        "from the text is '.. raw::' renderer passthrough: there is no HTML in "
        "this tree, and a tag stripper measurably deletes sysfs metavariables "
        "(hwmon<i>), kernel-parameter formats (<a>,<b>), maintainer e-mails and "
        "libvirt XML examples instead."
    ),
)
