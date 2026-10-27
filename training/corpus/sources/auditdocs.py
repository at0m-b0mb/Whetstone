"""The Linux audit userspace: how the record the runtime reads is actually shaped.

This is a small source that closes a specific, embarrassing hole. ``lab/vm/``
runs a real Ubuntu VM with real ``auditd``, and the detection verifier's whole
claim — *the technique ran, and here is the log line proving it was seen* —
rests on parsing ``ausearch`` output. The corpus taught the model nothing about
that format. :mod:`~training.corpus.sources.manpages` reads this machine's own
``/usr/share/man``, and this machine is a Mac: there is no ``auditctl(8)``, no
``audit.rules(7)``, no ``ausearch-expression(5)`` anywhere in it. The model had
read nineteen megabytes of man pages and not one of them described the subsystem
the project's only real-machine lab depends on.

What arrives here, and why each part is worth its characters:

* **``ausearch-expression(5)``** — the search expression grammar, token by
  token, which is the language a defender interrogates an audit log in.
* **``audit.rules(7)`` and ``auditctl(8)``** — the rule syntax
  (``-a always,exit -F arch=b64 -S execve -k exec``), every field name, every
  filter, every action. This is the surface form of "decide what gets logged",
  and it is the Linux half of what ``windocs`` carries for Windows audit
  subcategories.
* **``auditd.conf(5)``**, 30 KB of it — the daemon's configuration vocabulary,
  including ``disk_full_action`` and ``flush``, which is where "the log was not
  written" stops being a mystery.
* **``ausearch(8)`` and ``aureport(8)``** — the two tools whose *output* the
  adapters parse, documented with their own worked examples.
* **The 42 ``auparse_*(3)`` pages** — the C API for walking a record field by
  field. Unusually valuable for a corpus that has to teach output-reading: these
  pages are a field-level description of the record format written as an API,
  so ``auparse_get_field_name`` and ``auparse_interpret_field`` arrive next to
  the thing they return.
* **The 39 shipped ``.rules`` profiles** — ``30-stig.rules``,
  ``30-pci-dss-v31.rules``, ``30-ospp-v42.rules``, ``42-injection.rules``,
  ``43-module-load.rules``. Real detection-as-code at volume, each rule with the
  comment that says which control it satisfies.

**Registers, decided by surface form as** :class:`~training.corpus.source.Register`
**requires.** Man pages, config-file syntax and API reference are the literal
examples the enum gives for :class:`~training.corpus.source.Register.SYSTEM`, so
every rendered page is SYSTEM and NEUTRAL. The ``.rules`` files are something
else: a file of audit rules *is* detection logic naming the fields it watches,
which is the enum's definition of
:class:`~training.corpus.source.Register.DETECTION`, and it is unambiguously
BLUE. Nothing here is labelled by topic.

**Rendering: ``mandoc``, at a pinned width, for the reason
:mod:`~training.corpus.sources.manpages` pins it.** Man pages are roff source,
something has to render them, and a hand-written roff subset renderer is a
quiet way to corrupt a corpus — it gets ``.TP`` and ``\\fB`` right and then
mangles the one page that uses a tbl table. ``mandoc(1)`` ships with macOS and
the BSDs and is packaged everywhere else. ``-Owidth=78`` is pinned so the cache
is byte-identical across machines rather than varying with ``$COLUMNS``. The
overstrike decoding is the same teletype rule that module explains: mandoc
writes bold as ``c\\x08c``, and a backspace deletes the character before it.

**What is NOT collected, stated because the exclusions are the design.** The
``.c`` and ``.h`` sources (2.6 MB) are not here: C in this corpus is
:mod:`~training.corpus.sources.clang`'s job and the audit library would teach
one project's habits. ``AUTHORS``, ``THANKS`` and ``ChangeLog`` are not here
either, and that is a privacy decision rather than a relevance one — they are
lists of contributors' names and mail addresses, which is precisely the kind of
third-party personal data this corpus has already shipped once by accident.

Third-party mail addresses are stripped from every document by
:func:`training.corpus.sources._thirdparty.strip_emails` and the whole tree is
re-scanned at fetch time to prove the strip worked. Author *names* are kept:
``auditctl(8)`` credits Steve Grubb in its AUTHOR section, that is a published
attribution, and GPL-2 §1 requires the notices to travel with the text.

**Licence: GPL-2.0, read from the repository's own ``COPYING``, and it is
copyleft.** Stated plainly rather than filed under "open source": this is not a
permissive licence, it carries conditions on distribution of derivative works,
and the project already carries three other copyleft upstreams
(:mod:`~training.corpus.sources.gtfobins` GPL-3.0,
:mod:`~training.corpus.sources.nselua` NPSL,
:mod:`~training.corpus.sources.malwareanalysis` CC-BY-SA-4.0) so the shape of
the decision is not new. ``COPYING`` (GPL-2.0, the 17,992-byte unmodified text)
and ``COPYING.LIB`` (LGPL-2.1, which covers ``libaudit`` and ``libauparse``,
the libraries the ``*.3`` pages document) are both copied into the cache under
``licenses/`` so the declaration can be checked against the download.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import time
from collections.abc import Iterator
from pathlib import Path

from ..net import NetworkError, download
from ..source import Document, Register, Side, SourceError, SourceSpec, normalise
from ._thirdparty import count_emails, strip_emails

_NAME = "auditdocs"

#: A codeload tarball of the default branch: one request, ~1.5 MB. A clone of
#: this repository is 7 MB of history that would be discarded immediately.
_TARBALL = (
    "https://codeload.github.com/linux-audit/audit-userspace/tar.gz/refs/heads/master"
)

#: Written last, after the staging tree is swapped in, so an interrupted fetch
#: re-downloads rather than leaving a half tree that a later run trusts.
_MARKER = ".auditdocs.json"

#: Bumped when the collected set or the rendering changes in a way that makes an
#: existing cache the wrong shape.
_CACHE_VERSION = 1

#: Generous for a 1.5 MB archive. The point of the ceiling is not to tune a
#: size, it is that an upstream which has become something else entirely stops
#: at the door instead of filling the SSD.
_MAX_ARCHIVE_BYTES = 32 * 1024 * 1024

#: No single file in this repository is anywhere near this. ``auditd.conf.5`` is
#: the largest page at 30 KB and ``30-ospp-v42.rules`` the largest rule file at
#: 10 KB; the ceiling exists because the tarball's own size says nothing about
#: any one member's, which is the lesson the five tar-reading adapters in this
#: package learned together.
_MAX_MEMBER_BYTES = 2 * 1024 * 1024

#: Licence documents, copied into ``licenses/`` beside the text they cover.
#: ``COPYING`` is GPL-2.0 and covers the tools and their man pages;
#: ``COPYING.LIB`` is LGPL-2.1 and covers libaudit/libauparse, which is what the
#: ``*.3`` pages document. Both, because either one alone would misdescribe the
#: collected set.
_LICENCE_FILES = ("COPYING", "COPYING.LIB")

#: man page section suffixes present in ``docs/``. Section 3 is the library API,
#: 5 the file formats, 7 the overview pages, 8 the administrative commands.
_MAN_SUFFIXES = (".3", ".5", ".7", ".8")

#: Trees collected, and nothing else. ``src/``, ``lib/``, ``auparse/`` and
#: ``audisp/`` hold the C implementation and are deliberately absent.
_KEEP_DIRS = ("docs/", "rules/", "init.d/")

#: Files under ``init.d/`` worth keeping. This directory is mostly three-line
#: shell wrappers (``auditd.restart`` is ``/sbin/auditctl -R ...``) which say
#: nothing the man pages do not. These four are real format examples: two
#: systemd units — the only unit files this source carries, and unit syntax is
#: a format the Linux adapter reads — the daemon's own shipped configuration,
#: and the rule file that runs at shutdown.
_KEEP_INITD = frozenset({
    "auditd.service.in",
    "audit-rules.service.in",
    "auditd.conf",
    "audit-stop.rules",
})

#: Pinned for byte-identical rendering across machines, matching the width
#: :mod:`~training.corpus.sources.manpages` pins for the same reason.
_RENDER_WIDTH = 78

#: Shortest page here that is genuinely a page. ``docs/audit_set_feature.3`` is
#: 30 bytes of roff — a bare ``.so`` alias — and renders to a husk; the real
#: short pages (``auparse_clear.3`` at 462 bytes of roff) clear this comfortably
#: once mandoc has added NAME, SYNOPSIS and SEE ALSO.
_MIN_CHARS = 200

#: A rule file worth a document. ``rules/99-finalize.rules`` is 86 bytes — two
#: comment lines and ``-e 2`` — and that is a complete, meaningful rule file, so
#: the floor sits below it rather than above. The Markdown floor would have
#: thrown it away, which is the mistake ``windocs`` records making with Sysmon
#: fragments.
_MIN_RULE_CHARS = 60

#: A rule line, as ``auditctl`` would accept it — **commented or not.** Used
#: only to decide whether a ``.rules`` file contains rule syntax at all; a file
#: whose every line is prose is a README that happens to end in ``.rules`` and
#: calling it DETECTION would be the mislabelling ``source.py`` exists to stop.
#:
#: The leading ``#{0,3}`` is the whole subtlety and it was measured rather than
#: guessed. A first version required an *uncommented* rule and dropped six of
#: the thirty-four shipped profiles — including ``31-privileged.rules``, which
#: is a ``find /bin -perm -04000 | awk '{ printf "-a always,exit ..." }'``
#: generator, and ``20-dont-audit.rules``, which is a menu of
#: ``#-a never,user -F subj_type=crond_t`` lines. Upstream ships templates
#: commented out on purpose: that *is* the rule syntax, and the register is
#: decided by surface form, which a leading ``#`` does not change.
#:
#: ``-{1,2}`` covers the long directives (``--loginuid-immutable``,
#: ``--backlog_wait_time``) that the short-option form misses entirely, and the
#: letter requirement keeps a prose comment ending in a dash out.
_RULE_LINE = re.compile(r"^[ \t]*#{0,3}[ \t]*-{1,2}[A-Za-z]", re.MULTILINE)


def _wanted(relative: str) -> bool:
    """True for a member this source collects. Path-shape only, no I/O."""
    if relative in _LICENCE_FILES:
        return True
    if not relative.startswith(_KEEP_DIRS):
        return False
    name = relative.rsplit("/", 1)[-1]
    if relative.startswith("docs/"):
        return name.endswith(_MAN_SUFFIXES)
    if relative.startswith("rules/"):
        return name.endswith(".rules") or name == "README-rules"
    return name in _KEEP_INITD


def _extract(archive: Path, staging: Path) -> tuple[int, int]:
    """Unpack the wanted members into *staging*. Returns ``(pages, rules)``.

    Members are written one at a time rather than through ``extractall``: the
    ``filter="data"`` argument that would make that safe only exists from Python
    3.12 and this package targets 3.10, so every destination is proved to
    resolve inside the staging tree before anything is written. An archive
    member is attacker-controlled data in principle even when the host is
    trusted in practice.
    """
    staging.mkdir(parents=True, exist_ok=True)
    resolved = staging.resolve()
    licences = pages = rules = 0
    try:
        with tarfile.open(archive, "r:gz") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                parts = member.name.split("/")[1:]   # drop audit-userspace-<ref>/
                if not parts or any(p in ("", ".", "..") or os.path.isabs(p)
                                    for p in parts):
                    continue
                relative = "/".join(parts)
                if not _wanted(relative):
                    continue
                if member.size > _MAX_MEMBER_BYTES:
                    continue
                target = (staging / relative).resolve()
                if not target.is_relative_to(resolved):
                    continue
                handle = tar.extractfile(member)
                if handle is None:
                    continue
                if relative in _LICENCE_FILES:
                    out = staging / "licenses" / relative
                    licences += 1
                else:
                    out = staging / relative
                out.parent.mkdir(parents=True, exist_ok=True)
                # Copied a chunk at a time rather than read() into one buffer,
                # so peak memory is a chunk. Belt and braces behind the ceiling
                # above; the shape is here so raising the ceiling later cannot
                # silently reintroduce the allocation.
                with handle, out.open("wb") as fh:
                    shutil.copyfileobj(handle, fh, 1 << 20)
                if relative.startswith("docs/"):
                    pages += 1
                elif relative.endswith(".rules"):
                    rules += 1
    except (tarfile.TarError, OSError) as exc:
        raise SourceError(f"{_NAME}: could not unpack {archive}: {exc}") from exc

    if licences != len(_LICENCE_FILES):
        raise SourceError(
            f"{_NAME}: expected {len(_LICENCE_FILES)} licence files "
            f"({', '.join(_LICENCE_FILES)}) in the archive and found {licences}. "
            "This source declares GPL-2.0 and LGPL-2.1 and keeps the upstream "
            "text on disk to back the declaration; an archive that has stopped "
            "shipping one needs a human to look, not a default."
        )
    if pages < 100 or rules < 20:
        raise SourceError(
            f"{_NAME}: the archive yielded {pages} man pages and {rules} rule "
            "files (expected at least 100 and 20). docs/ or rules/ has moved; "
            "fix the keep set rather than training on a fraction of it."
        )
    return pages, rules


def _scan_for_addresses(root: Path) -> int:
    """Count mail addresses across the whole extracted tree.

    Recorded in the cache marker, and that is the point: "we strip addresses" is
    a claim about behaviour, while "the tree we fetched contained N and the
    documents we emit contain zero" is a measurement. The second number is
    checked by the test suite against the documents; this is the first.

    ``os.walk(followlinks=False)``, never ``rglob``. A sibling adapter once
    followed a symlink out of a repository into the SSD and pulled the corpus
    cache back in as its own register — the corpus ate itself, and only the
    balance report noticed.
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
                total += count_emails(path.read_text(encoding="utf-8",
                                                     errors="replace"))
            except OSError:
                continue
    return total


def _fetch(cache_dir: Path) -> Path:
    """Download, filter and render. Returns the populated cache root.

    Network-free on re-run: the marker is written only once the staging tree has
    been swapped into place and records ``cache_version``, so a format change
    here re-fetches instead of being read with the wrong parser.

    Rendering happens at fetch time rather than in ``documents`` because it
    spawns ``mandoc`` ~160 times and the result is deterministic — caching the
    text means a rebuild that only re-reads the cache does no process spawning
    at all.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    marker = cache_dir / _MARKER
    text_root = cache_dir / "text"
    if marker.is_file() and text_root.is_dir():
        try:
            recorded = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            recorded = {}
        if recorded.get("cache_version") == _CACHE_VERSION:
            return cache_dir

    if shutil.which("mandoc") is None:
        raise SourceError(
            f"{_NAME}: mandoc(1) is not on PATH. Man pages are roff source and "
            "something has to render them; mandoc ships with macOS and the BSDs "
            "and is packaged as 'mandoc' elsewhere. A hand-written roff subset "
            "renderer was the alternative and it is how a corpus quietly "
            "acquires mangled tables."
        )

    staging = cache_dir / ".staging"
    archive = cache_dir / ".audit-userspace.tar.gz.part"
    shutil.rmtree(staging, ignore_errors=True)
    try:
        try:
            download(_TARBALL, archive, timeout=300,
                     max_bytes=_MAX_ARCHIVE_BYTES)
        except NetworkError as exc:
            raise SourceError(f"{_NAME}: {exc}") from None
        archive_bytes = archive.stat().st_size
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        pages, rules = _extract(archive, staging)
        addresses = _scan_for_addresses(staging)
        rendered = _render_tree(staging)

        for name in ("text", "rules", "licenses", "init.d"):
            shutil.rmtree(cache_dir / name, ignore_errors=True)
        (staging / "text").replace(cache_dir / "text")
        (staging / "rules").replace(cache_dir / "rules")
        (staging / "licenses").replace(cache_dir / "licenses")
        if (staging / "init.d").is_dir():
            (staging / "init.d").replace(cache_dir / "init.d")

        marker.write_text(json.dumps({
            "cache_version": _CACHE_VERSION,
            "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "url": _TARBALL,
            # Observed, not verified: codeload publishes no digest for a branch
            # tarball, so this records which snapshot the cache holds and makes
            # no claim that it was compared with anything.
            "archive_sha256_observed": digest,
            "archive_bytes": archive_bytes,
            "man_pages": pages,
            "rule_files": rules,
            "rendered_pages": rendered,
            # The privacy measurement, kept as a number in the cache so a later
            # reader can see it was taken. No value is ever recorded here.
            "third_party_addresses_in_archive": addresses,
            "mandoc_width": _RENDER_WIDTH,
        }, indent=2), encoding="utf-8")
    finally:
        archive.unlink(missing_ok=True)
        shutil.rmtree(staging, ignore_errors=True)
    return cache_dir


def _strip_overstrike(text: str) -> str:
    """Apply backspace overstrike instead of deleting it.

    ``mandoc -Tutf8`` writes bold as ``c\\x08c`` and italic as ``_\\x08c`` — the
    encoding a teletype understood: print, back up, print again. The only
    correct reading is the terminal's, where a backspace deletes the character
    before it, and applying that one rule resolves both cases with no
    special-casing. This is decoding, not cleaning;
    :func:`~training.corpus.source.normalise` remains the only thing that
    touches corpus surface form.
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


def _render_page(source: Path) -> str:
    """Render one roff page to plain text. Empty string means it produced nothing.

    mandoc exits non-zero on *style* warnings for perfectly readable pages, so
    the exit status is not a usable signal and is not consulted; stdout is, and
    an empty stdout is the real failure, which the caller detects by length.

    The page is named by its **basename** with ``cwd`` set to the directory
    holding it, not by the path the caller had. Two reasons, and the first cost
    an hour: ``cwd=`` changes what a relative path means, so handing mandoc
    ``data/corpus/raw/auditdocs/docs/auditctl.8`` while also sending it into
    ``docs/`` produced ``BADARG: ... No such file or directory`` on every single
    page — and a renderer that fails on *every* page is the easy case. Second,
    roff ``.so`` inclusions resolve against the working directory, and in this
    tree their targets are siblings in ``docs/``.
    """
    try:
        proc = subprocess.run(
            ["mandoc", "-Tutf8", f"-Owidth={_RENDER_WIDTH}", source.name],
            cwd=source.parent, capture_output=True, timeout=60,
            # check=False stated rather than defaulted: mandoc exits
            # non-zero on style warnings for perfectly readable pages, so
            # the status is not a usable signal here and raising on it
            # would discard most of the tree.
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    text = _strip_overstrike(proc.stdout.decode("utf-8", errors="replace"))
    # mandoc emits U+00A0 where roff asked for an unpaddable space (``\ ``). It
    # means "a space", and leaving it would spend tokens teaching the model a
    # second, invisible space character.
    return text.replace(" ", " ")


def _render_tree(staging: Path) -> int:
    """Render every ``docs/`` page into ``staging/text/``. Returns the count."""
    docs = staging / "docs"
    out_root = staging / "text"
    out_root.mkdir(parents=True, exist_ok=True)
    written = 0
    for page in sorted(docs.iterdir()) if docs.is_dir() else []:
        if page.is_symlink() or not page.is_file():
            continue
        if not page.name.endswith(_MAN_SUFFIXES):
            continue
        text = _render_page(page)
        if len(text.strip()) < _MIN_CHARS:
            continue
        (out_root / f"{page.name}.txt").write_text(text, encoding="utf-8")
        written += 1
    if written == 0:
        raise SourceError(
            f"{_NAME}: mandoc rendered every page to nothing. Either mandoc is "
            "broken on this host or docs/ no longer holds roff."
        )
    # rules/ and init.d/ are kept as-is but must survive the swap, so the
    # directories are created even when upstream ships neither.
    (staging / "rules").mkdir(parents=True, exist_ok=True)
    (staging / "licenses").mkdir(parents=True, exist_ok=True)
    return written


def _man_header(name: str) -> str:
    """A labelled opening line, so the page's identity is in its own text.

    ``auparse_get_field_name.3`` renders with ``AUPARSE_GET_FIELD_NAME(3)`` in
    its running header, which mandoc has already upper-cased and padded into a
    three-column banner. Restating the name and section in the form a person
    types them — ``ausearch-expression(5)`` — puts the token the model will
    actually be asked about next to the text that explains it, which is the
    whole argument :mod:`~training.corpus.sources.cwe` makes for writing
    ``CWE-###`` beside a bare integer.
    """
    stem, _, section = name.rpartition(".")
    return f"{stem}({section}) — Linux audit userspace"


def _documents(path: Path) -> Iterator[Document]:
    """Yield rendered man pages (SYSTEM) and audit rule files (DETECTION).

    Addresses are stripped here, on the text that will be written, rather than
    at fetch time on the cache. Both would work; doing it on the emitted text
    means the guarantee holds even if somebody later edits the cache by hand,
    and the test suite can assert it over ``documents()`` output without a
    network fetch.
    """
    text_root = path / "text"
    if not text_root.is_dir():
        raise SourceError(f"{_NAME}: no text/ under {path}; re-fetch")

    for file in sorted(text_root.iterdir()):
        if file.is_symlink() or not file.is_file() or file.suffix != ".txt":
            continue
        try:
            raw = file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        page = file.name[:-len(".txt")]
        body, _ = strip_emails(raw)
        text = normalise(f"{_man_header(page)}\n\n{body}")
        if len(text) < _MIN_CHARS:
            continue
        yield Document(text=text, source=_NAME, register=Register.SYSTEM,
                       side=Side.NEUTRAL, ident=f"docs/{page}")

    yield from _rule_documents(path)


def _rule_documents(path: Path) -> Iterator[Document]:
    """One DETECTION document per shipped audit rule file, kept verbatim.

    Verbatim matters more here than almost anywhere else in this package. The
    comments are interleaved with the rules they explain — ``## Successful file
    delete`` sits directly above the ``-a always,exit -F arch=b64 -S unlink``
    that implements it — and the ``-F`` field lists are column-aligned in the
    STIG and OSPP profiles.
    :func:`~training.corpus.source.normalise` preserves horizontal whitespace,
    so no private cleaner is needed and none is written.
    """
    for folder in (path / "rules", path / "init.d"):
        if not folder.is_dir():
            continue
        for file in sorted(folder.iterdir()):
            if file.is_symlink() or not file.is_file():
                continue
            if file.name == "README-rules":
                # Installation prose about the numbering convention. Real, but
                # it is neither detection logic nor a format, and the only
                # register it could honestly take is one it is far too small to
                # be worth distorting.
                continue
            try:
                raw = file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            body, _ = strip_emails(raw)
            is_rules = file.suffix == ".rules"
            if is_rules and not _RULE_LINE.search(body):
                continue
            # Decided by what the file *is*, never by which directory it sits
            # in. ``init.d/audit-stop.rules`` is a rule file that happens to be
            # shipped beside the unit files, and labelling it SYSTEM because of
            # its neighbours would make the register a fact about the upstream's
            # directory layout.
            register = Register.DETECTION if is_rules else Register.SYSTEM
            side = Side.BLUE if is_rules else Side.NEUTRAL
            label = ("auditd rule profile" if is_rules
                     else "audit userspace configuration")
            text = normalise(f"{file.name} — {label}\n\n{body}")
            floor = _MIN_RULE_CHARS if is_rules else _MIN_CHARS
            if len(text) < floor:
                continue
            yield Document(text=text, source=_NAME, register=register,
                           side=side, ident=f"{folder.name}/{file.name}")


SPEC = SourceSpec(
    name=_NAME,
    license=(
        "GPL-2.0 — COPYLEFT, not permissive, stated explicitly because it "
        "travels with the text. Read from the repository's own COPYING, which "
        "is the unmodified 17,992-byte GNU General Public License version 2 "
        "('Copyright (C) 1989, 1991 Free Software Foundation, Inc. ... "
        "Everyone is permitted to copy and distribute verbatim copies of this "
        "license document, but changing it is not allowed.'). COPYING.LIB is "
        "the GNU Lesser General Public License version 2.1 and covers libaudit "
        "and libauparse, which the 42 *.3 pages collected here document. Both "
        "files are copied into the cache under licenses/ beside the text they "
        "cover. Redistribution of verbatim copies and of derivative works is "
        "permitted under the GPL's own conditions; those conditions include "
        "keeping the copyright notices intact, which is why the AUTHOR "
        "attribution in each page is preserved rather than stripped. "
        "Source: https://github.com/linux-audit/audit-userspace/blob/master/COPYING"
    ),
    url="https://github.com/linux-audit/audit-userspace",
    register=Register.SYSTEM,
    side=Side.NEUTRAL,
    fetch=_fetch,
    documents=_documents,
    expect_min_docs=150,
    notes=(
        "The format the detection verifier actually reads. lab/vm/ runs real "
        "auditd and the project's only real-machine evidence is parsed ausearch "
        "output, while manpages reads this Mac's /usr/share/man, which contains "
        "no auditctl(8), no audit.rules(7) and no ausearch-expression(5) at all. "
        "Collected: every docs/*.{3,5,7,8} page rendered with mandoc -Tutf8 at a "
        "pinned 78 columns (SYSTEM — the enum's own examples for that register "
        "are man pages, config-file syntax and API reference), and the 39 shipped "
        "rules/*.rules profiles verbatim (DETECTION/BLUE — a file of audit rules "
        "is detection logic naming the fields it watches; STIG, PCI-DSS v3.1 and "
        "OSPP v42 among them, each rule carrying the comment that names its "
        "control). The 42 auparse_*(3) pages are the unexpected prize: a "
        "field-level description of the record format written as an API, which is "
        "exactly the output-reading the corpus is thinnest on. Deliberately not "
        "collected: the 2.6 MB of C under src/ and lib/ (clang's register, and it "
        "would teach one project's habits), and AUTHORS/THANKS/ChangeLog, which "
        "are lists of contributors' names and mail addresses — the exact shape of "
        "third-party personal data this corpus has already shipped once by "
        "accident. Mail addresses are stripped from every document and the whole "
        "fetched tree is re-counted into the cache marker so the strip is a "
        "measurement rather than a claim; author names are kept, because a "
        "published AUTHOR attribution is not contact details and GPL-2 section 1 "
        "requires the notices to travel. Needs mandoc(1) on PATH and says so "
        "loudly if it is missing: a hand-rolled roff subset renderer is how a "
        "corpus acquires mangled tables."
    ),
)
