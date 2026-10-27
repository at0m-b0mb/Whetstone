"""``--help`` text for the GNU and Linux utilities the runtime shells out to.

The ROADMAP asks for "`ss64`, busybox and **coreutils** usage text for SHELL",
against a register sitting at 15.6% of a 26% target. This is the coreutils half,
plus the six other upstreams that write their help the same way — and the
reason it is not already covered by :mod:`~training.corpus.sources.manpages` is
that manpages reads **this machine's** ``/usr/share/man``, which on macOS is the
BSD tools. BSD ``ls`` has no ``--time-style``, no ``--color=auto``, no
``--group-directories-first``; BSD ``ps`` has no ``--forest``; there is no
``ip``, ``ss``, ``lsblk``, ``findmnt``, ``lscpu`` or ``lsns`` on the disk at all.
Those are precisely the commands :mod:`whetstone.adapters.linux` runs, and the
GNU long-option vocabulary they take was simply not in the corpus.

**Why the C sources rather than the manual.** Three routes to this text exist
and only one of them is the right register:

* the texinfo manual — a 1.1 MB narrative with option tables embedded in
  paragraphs of explanation. That is SYSTEM register, the same as a man page,
  and filing it under SHELL to close a SHELL gap would be gaming the
  measurement. ``psdocs`` already draws this line when it excludes
  ``docs-conceptual/``: prose about a shell is not shell.
* running ``ls --help`` locally — gives GNU output only on a machine with GNU
  tools installed, which this one is not, and makes the corpus depend on what
  Homebrew happened to put on the PATH.
* the ``usage()`` function in the utility's own C source — which **is** the
  ``--help`` output, verbatim, option-aligned, with no prose around it, on any
  machine, with no toolchain.

So the text collected here is what the model will actually see when it runs the
command::

    Usage: ls [OPTION]... [FILE]...
    List information about the FILEs (the current directory by default).

      -a, --all                  do not ignore entries starting with .
      -A, --almost-all           do not list implied . and ..
          --author               with -l, print the author of each file
          --block-size=SIZE      with -l, scale sizes by SIZE when printing them;
                                 e.g., '--block-size=M'; see SIZE format below

Two columns, aligned with spaces, continuation lines indented to the second
column. That alignment is the signal ``normalise()`` preserves horizontal
whitespace for, and it is what lets a model tell a flag from its description.

Licence: read per **file**, not per project
-------------------------------------------

This is the part worth reading before changing anything here. Seven upstreams
contribute, and a single declaration over all of them would be false:

* coreutils, findutils, grep, sed and diffutils are GPL-3.0-or-later;
* util-linux and procps-ng are GPL-2.0-or-later — **and util-linux is not
  uniformly so.** Its tree carries, file by file, LGPL-2.1-or-later, MIT, ISC,
  BSD-2-Clause, BSD-4-Clause-UC, GPL-1.0-or-later and two files marked
  GPL-2.0-**only**, which is not upgradeable and cannot sit in the same
  distributable work as the GPL-3.0 material above. One of them is tagged
  ``GPL-2.1-or-later``, a licence that does not exist — an upstream typo, and
  the honest response to an unparseable identifier is to refuse the file rather
  than to decide what it probably meant.

So every document's licence is read out of **its own file's header**, either
from an ``SPDX-License-Identifier`` tag or from the FSF per-file notice ("either
version 3 of the License, or (at your option) any later version"), and only the
identifiers in :data:`_ACCEPTED` are collected. Everything else — including
every file with no recognisable notice at all — is refused and counted in the
build log. The accepted set is deliberately all ``-or-later`` or permissive, so
the collection is combinable under GPL-3.0 and the claim in :data:`SPEC` is true
of every row rather than true on average.

The licence string in the header is also the only thing extracted from a
header. The function body is taken and nothing else, which matters: util-linux
puts maintainer names and addresses in its file headers
(``misc-utils/lsblk.c`` carries two), and a source that swept up file headers
would be importing third-party personal data to no purpose at all. A test
asserts no address from a header reaches a document.

What is deliberately not here
-----------------------------

**bash.** Its ``--help`` is three lines; its real documentation is a GFDL
texinfo manual, which is prose and therefore SYSTEM. **gawk and gzip.** Neither
writes its help as string literals in a ``usage``-shaped function, and inventing
a second extraction path for two utilities is not worth the second thing to keep
correct. **BusyBox**, which is the same kind of text and has its own source,
because it is GPL-2.0-**only** and cannot be combined with the GPL-3.0 material
here. **ss64.com**, which the ROADMAP names: it is a website with no licence
grant of any kind — no LICENSE, no terms page permitting reuse — and an
unlicensed upstream is exactly what ``source.py`` refuses. Saying so is the
right answer rather than scraping it.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tarfile
from pathlib import Path
from typing import Iterator, NamedTuple

from ..net import NetworkError, download
from ..source import Document, Register, Side, SourceError, SourceSpec, normalise


class _Upstream(NamedTuple):
    """One release tarball to read."""

    project: str
    version: str
    url: str
    #: tarfile mode. Pinned rather than inferred so a renamed file cannot
    #: silently change how the archive is opened.
    mode: str
    #: Members whose path, relative to the archive root, is the licence text.
    licence_members: tuple[str, ...]
    #: Expected floor on utilities extracted. A project that yields nothing is
    #: a layout change, and must be loud rather than merely smaller.
    expect: int


#: Pinned versions, every one an immutable release artefact. ftp.gnu.org keeps
#: every historical release forever, so a pin here never 404s — and a pinned
#: corpus is a corpus a training run can be reproduced from.
_UPSTREAMS: tuple[_Upstream, ...] = (
    _Upstream("coreutils", "9.5",
              "https://ftp.gnu.org/gnu/coreutils/coreutils-9.5.tar.xz",
              "r:xz", ("COPYING",), 80),
    _Upstream("findutils", "4.10.0",
              "https://ftp.gnu.org/gnu/findutils/findutils-4.10.0.tar.xz",
              "r:xz", ("COPYING",), 3),
    _Upstream("grep", "3.11",
              "https://ftp.gnu.org/gnu/grep/grep-3.11.tar.xz",
              "r:xz", ("COPYING",), 1),
    _Upstream("sed", "4.9",
              "https://ftp.gnu.org/gnu/sed/sed-4.9.tar.xz",
              "r:xz", ("COPYING",), 1),
    _Upstream("diffutils", "3.10",
              "https://ftp.gnu.org/gnu/diffutils/diffutils-3.10.tar.xz",
              "r:xz", ("COPYING",), 3),
    # GNU tar is deliberately absent, and it was tried. Its usage() is four
    # lines of argp:
    #
    #     usage (int status)
    #     {
    #       argp_help (&argp, stderr, ARGP_HELP_SEE, (char*) program_name);
    #
    # The help text lives in an argp option table, so there is no literal to
    # extract and the per-project floor said so on the first run — "tar yielded
    # 0 files with a usage function". The right answer is to drop the upstream
    # rather than to lower the floor or to grow a second extraction path for one
    # utility. gawk and gzip are absent for the same reason, found the same way.
    # cdn.kernel.org directly rather than www.kernel.org, which redirects to it:
    # net.py strips caller headers across a redirect and there is no reason to
    # spend a hop finding that out.
    _Upstream("util-linux", "2.40.2",
              "https://cdn.kernel.org/pub/linux/utils/util-linux/v2.40/"
              "util-linux-2.40.2.tar.xz",
              "r:xz", ("COPYING",), 40),
    _Upstream("procps-ng", "4.0.4",
              "https://gitlab.com/procps-ng/procps/-/archive/v4.0.4/"
              "procps-v4.0.4.tar.gz",
              "r:gz", ("COPYING", "COPYING.LIB"), 5),
)

#: Measured on the wire: 5.73 + 2.14 + 1.62 + 1.33 + 1.55 + 2.21 + 8.85 + 2.17
#: = 25.6 MB in total. The per-archive ceiling is generous against that.
_MAX_ARCHIVE_BYTES = 64 * 1024 * 1024

#: A single C file this large is not a utility, it is generated or amalgamated,
#: and it is read into memory to be inspected — so the ceiling is also what
#: keeps that read bounded.
_MAX_MEMBER_BYTES = 2 * 1024 * 1024

_MARKER = ".fetched.json"
_SOURCES = "sources"
_LICENSES = "licenses"

#: Licence identifiers this source will collect, and nothing else.
#:
#: Every entry is either permissive or ``-or-later``, which is the property that
#: makes the collection combinable under GPL-3.0 and makes the SPEC's claim true
#: of each row. GPL-2.0-only, GPL-1.0-or-later, BSD-4-Clause-UC and the
#: nonexistent "GPL-2.1-or-later" all appear in util-linux and are all refused:
#: the first cannot be upgraded, the second and third carry obligations this
#: project has not examined, and the fourth is a typo whose meaning is not for
#: this module to decide.
_ACCEPTED = frozenset((
    "GPL-2.0-or-later", "GPL-3.0-or-later",
    "LGPL-2.1-or-later", "LGPL-3.0-or-later",
    "MIT", "ISC", "BSD-2-Clause", "BSD-3-Clause",
))

_SPDX = re.compile(r"SPDX-License-Identifier:\s*([A-Za-z0-9.+\-]+)")

#: The FSF per-file notice, in the two wordings that occur: "either version 3 of
#: the License, or (at your option) any later version" (coreutils, util-linux)
#: and "either version 3, or (at your option) any later version" (grep, sed,
#: tar, which omit "of the License"). The first pattern written here required
#: the longer form and silently refused grep, sed and tar — three whole
#: upstreams — which the per-project floors caught.
_FSF_NOTICE = re.compile(
    r"version\s+(\d)(?:\s+of\s+the\s+Licen[cs]e)?\s*,?\s*"
    r"or\s*\(?\s*at\s+your\s+option\s*\)?\s*,?\s*any\s+later\s+version",
    re.I)

#: A ``usage``-shaped function *definition*. Matched on the identifier
#: immediately before the parameter list, so ``skillsnice_usage`` does not
#: qualify and ``static void usage(FILE * out);`` — a forward declaration, which
#: ends in a semicolon — is excluded by the caller's check.
_USAGE_DEF = re.compile(r"\b(?:usage|print_usage|help)\s*\([^;]*\)\s*$")

#: ``%s`` and the positional ``%1$s``: the program's own name, passed at
#: runtime. util-linux and procps-ng use the positional form where one synopsis
#: names the command more than once.
_PROGRAM_SPEC = re.compile(r"%(?:\d+\$)?s")

#: A synopsis line that announces itself: ``Usage: %s [OPTION]... [FILE]...``
#: and the continuation ``  or:  %s OPTION... NAME...``. The ``or:`` form is why
#: a pattern anchored on the word "Usage" alone left 260 raw ``%s`` in the
#: output — coreutils writes the second and third synopses of a utility without
#: repeating it.
_SYNOPSIS_LABELLED = re.compile(r"^[ \t]*(?:or:|usage:)", re.I)

#: A synopsis line that does not: util-linux and procps-ng print the word
#: "Usage:" from the ``USAGE_HEADER`` macro, which is a macro and not a literal,
#: so what survives extraction is a bare `` %s [options] [<device> ...]``.
#:
#: The bracket test is what keeps this apart from the collision it would
#: otherwise cause, and the collision is real: ``date --help`` documents its
#: format fields as ``  %s   seconds since the Epoch``, which also begins with
#: whitespace and ``%s``. A synopsis carries an option grammar — ``[`` or ``<``
#: — and a format-field gloss carries prose. Substituting globally, or on
#: line-position alone, would rewrite ``date``'s own documentation of ``%s``
#: into ``date``, which is a wrong gloss on the one utility most likely to be
#: asked about it.
_SYNOPSIS_BARE = re.compile(r"^[ \t]*%(?:\d+\$)?s\b")

#: coreutils closes most help texts with a worked-examples block, and writes the
#: program's own name there as ``%s`` too::
#:
#:     Examples:
#:       %s /usr/bin/sort          -> "sort"
#:       %s include/stdio.h .h     -> "stdio"
#:
#: Those are the single most valuable lines in the whole source — intent to
#: invocation, the tldr shape — so they are worth substituting, and inside this
#: block a line-leading ``%s`` needs no bracket test because there is nothing
#: else it could be. The heading is tracked rather than the brackets because
#: ``date``'s format-field list (``  %s   seconds since the Epoch``) has the
#: same line shape and is *not* under this heading.
_EXAMPLES_HEADING = re.compile(r"^[ \t]*Examples?:[ \t]*$", re.I)

#: A C string literal, allowing escapes and the backslash-newline continuation
#: that every GNU help string is written with.
_LITERAL = re.compile(r'"((?:[^"\\]|\\.|\\\n)*)"', re.S)

#: C escapes that occur in help text. A backslash before a newline is a line
#: *continuation* and contributes nothing — mapping it to a newline, the
#: obvious-looking mistake, would break every wrapped sentence in the file.
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"',
            "'": "'", "a": "\a", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}

#: Path segments that are not utilities: gnulib and library code, the test
#: suites, the sample programs and util-linux's own documentation template. Each
#: of these carries a ``usage``-shaped function and none of them is a command
#: anybody runs.
_SKIP_SEGMENTS = frozenset((
    "lib", "gnulib", "gnulib-tests", "gl", "tests", "test", "testsuite",
    "samples", "Documentation", "doc", "libsmartcols", "libmount",
    "libblkid", "libfdisk", "libuuid", "liblastlog2", "po", "m4", "build-aux",
))

#: File stems that name a module rather than a utility. ``findutils`` puts
#: ``find``'s help in ``find/util.c``; the directory names the command.
_GENERIC_STEMS = frozenset(("util", "utils", "main", "cmd", "common",
                            "su-common", "display"))

#: Floor for a document. A usage function that yields less than this extracted
#: nothing but a one-line synopsis, which is not worth a corpus row of its own.
_MIN_CHARS = 200


def strip_comments(source: str) -> str:
    """Remove C comments, leaving string and character literals untouched.

    Necessary rather than tidy. coreutils writes translator notes inside the
    code, three of them containing double quotes::

        /* TRANSLATORS: this is the "1K-blocks" header in "df" output.  */

    Extracting literals with a regex over the raw text picks ``1K-blocks`` and
    ``df`` out of that comment and splices them into the middle of the help
    output — text no program ever printed, in the register the model is most
    likely to be believed in. Comments and literals cannot be separated by two
    independent regexes because each can contain the other's delimiter, so this
    is one scanner that knows about both.
    """
    out: list[str] = []
    index = 0
    size = len(source)
    while index < size:
        char = source[index]
        if char in ('"', "'"):
            out.append(char)
            index += 1
            while index < size:
                if source[index] == "\\" and index + 1 < size:
                    out.append(source[index:index + 2])
                    index += 2
                    continue
                out.append(source[index])
                closed = source[index] == char
                index += 1
                if closed:
                    break
            continue
        if char == "/" and index + 1 < size and source[index + 1] == "*":
            end = source.find("*/", index + 2)
            # A space, not nothing: ``foo/*c*/bar`` must not become ``foobar``.
            out.append(" ")
            index = size if end < 0 else end + 2
            continue
        if char == "/" and index + 1 < size and source[index + 1] == "/":
            end = source.find("\n", index)
            index = size if end < 0 else end
            continue
        out.append(char)
        index += 1
    return "".join(out)


def decode_literal(raw: str) -> str:
    """Decode one C string literal's body.

    Deliberately a copy of the same function in
    :mod:`~training.corpus.sources.busybox` rather than a shared import. Every
    adapter in this package is standalone, and ``discover_sources`` isolates
    import failures *per module*: a shared helper between two sources would mean
    a typo in one taking the other down with it, for fifteen lines saved.
    """
    out: list[str] = []
    index = 0
    while index < len(raw):
        char = raw[index]
        if char != "\\" or index + 1 >= len(raw):
            out.append(char)
            index += 1
            continue
        nxt = raw[index + 1]
        if nxt == "\n":
            index += 2                      # line continuation: no character
            continue
        out.append(_ESCAPES.get(nxt, nxt))
        index += 2
    return "".join(out)


def licence_of(source: str) -> str | None:
    """The licence this file declares, or ``None`` if it declares none readable.

    SPDX tag first because it is unambiguous, then the FSF prose notice. The
    notice is matched against a *comment-leader-stripped* projection of the
    header, and that detail is the whole history of this function: a version
    that normalised whitespace without removing the ``*`` at the start of each
    continuation line turned "version 2 of the License, or" into "version 2 of
    the License, or *" and matched nothing, which refused ``lsblk``,
    ``findmnt``, ``blkid`` and 86 other util-linux files while reporting a
    perfectly ordinary-looking smaller number. A physically impossible result —
    every file in a GNU project declaring no licence — is a bug in the ruler.
    """
    head = source[:8000]
    spdx = _SPDX.search(head)
    if spdx is not None:
        return spdx.group(1)
    flat = re.sub(r"\n[ \t]*\*?[ \t]*", " ", head)
    notice = _FSF_NOTICE.search(flat)
    if notice is None:
        return None
    return f"GPL-{notice.group(1)}.0-or-later"


def usage_text(source: str) -> str | None:
    """The help text out of a file's ``usage``-shaped function, or ``None``.

    The body runs from the function's opening brace to the first line that is a
    bare ``}`` in column zero, which is the formatting every one of these
    upstreams uses and which avoids a full brace-matching parser that would have
    to understand the preprocessor as well.

    Returns the concatenation of every string literal in the body, in order,
    with C escapes decoded — which *is* the ``--help`` output, minus the parts
    emitted by shared helper calls (``emit_ancillary_info()``,
    ``emit_mandatory_arg_note()``, coreutils' ``HELP_OPTION_DESCRIPTION``
    macro). Their absence is wanted, not a defect: those helpers are exactly the
    boilerplate that would otherwise appear identically in ninety-four documents.
    """
    cleaned = strip_comments(source)
    lines = cleaned.split("\n")
    start = None
    for index, line in enumerate(lines):
        if ";" in line or not _USAGE_DEF.search(line.rstrip()):
            continue
        # The brace is on this line or on the next non-empty one.
        if line.rstrip().endswith("{"):
            start = index + 1
            break
        for look in range(index + 1, min(index + 3, len(lines))):
            if lines[look].strip() == "{":
                start = look + 1
                break
            if lines[look].strip():
                break
        if start is not None:
            break
    if start is None:
        return None

    body: list[str] = []
    for line in lines[start:]:
        if line.startswith("}"):
            break
        body.append(line)
    if not body:
        return None

    text = "".join(decode_literal(match.group(1))
                   for match in _LITERAL.finditer("\n".join(body)))
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text if text.strip() else None


def utility_name(relative: str) -> str:
    """The command a source file documents, from its path in the tarball.

    The file stem, except where the stem names a module rather than a command:
    findutils keeps ``find``'s help in ``find/util.c``, and the directory is the
    command there.
    """
    path = Path(relative)
    stem = path.stem
    if stem in _GENERIC_STEMS and len(path.parts) > 1:
        return path.parts[-2]
    return stem


def substitute_program_name(text: str, utility: str) -> str:
    """Put the command's name where the C source wrote ``%s``, on synopsis lines.

    Pure and line-by-line, because the decision is per line: see
    :data:`_SYNOPSIS_LABELLED` and :data:`_SYNOPSIS_BARE` for the two shapes a
    synopsis takes and for the ``date``-shaped collision the bracket test
    avoids. Every other ``%`` in the text is left exactly as written — ``%d``,
    ``%14s``, ``%:z`` and the rest are the utility's *documentation of its own
    format strings* and rewriting them would be inventing content.
    """
    out: list[str] = []
    in_examples = False
    for line in text.split("\n"):
        if _EXAMPLES_HEADING.match(line):
            in_examples = True
            out.append(line)
            continue
        if _SYNOPSIS_LABELLED.match(line):
            out.append(_PROGRAM_SPEC.sub(utility, line))
        elif _SYNOPSIS_BARE.match(line) and (
                in_examples or "[" in line or "<" in line):
            # Only the leading specifier: a later %s on the same line is an
            # argument placeholder, not the program.
            out.append(_PROGRAM_SPEC.sub(utility, line, count=1))
        else:
            out.append(line)
    return "\n".join(out)


def render(utility: str, upstream: _Upstream, relative: str, licence: str,
           help_text: str) -> str | None:
    """Lay out one utility's help as the binary prints it, with provenance.

    The provenance block carries the project, the version, the file and the
    licence *that file* declared, so a reader of a corpus row can check the
    terms without consulting this module.
    """
    text = substitute_program_name(help_text, utility)
    text = text.strip("\n")
    if not text.strip():
        return None

    lines = [
        f"Utility: {utility}",
        f"Project: {upstream.project} {upstream.version}",
        "Platform: linux (GNU userland)",
        "",
        text,
        "",
        f"Source: {upstream.project}-{upstream.version}/{relative} ({licence})",
    ]
    rendered = normalise("\n".join(lines))
    return rendered if len(rendered) >= _MIN_CHARS else None


def _interesting(relative: Path) -> bool:
    """True if this archive member could be a utility's C source."""
    if relative.suffix != ".c":
        return False
    if relative.name.startswith(("test_", "test-", "sample-")):
        return False
    return not any(part in _SKIP_SEGMENTS for part in relative.parts[:-1])


def _fetch_one(upstream: _Upstream, staging: Path) -> tuple[int, dict[str, str]]:
    """Download one upstream into ``staging``. Returns (files kept, licences).

    Members are inspected in memory and only the ones carrying a ``usage``-shaped
    function reach the disk, so the cache holds a few hundred kilobytes per
    project instead of a few megabytes of gnulib.
    """
    archive = staging.parent / f".{upstream.project}.part"
    kept = 0
    licences: dict[str, str] = {}
    try:
        try:
            download(upstream.url, archive, timeout=600,
                     max_bytes=_MAX_ARCHIVE_BYTES)
        except NetworkError as exc:
            raise SourceError(
                f"unixhelp: cannot fetch {upstream.url}: {exc}") from None

        with tarfile.open(archive, upstream.mode) as tar:
            for member in tar:
                if not member.isfile() or member.size > _MAX_MEMBER_BYTES:
                    continue
                parts = Path(member.name).parts[1:]      # drop the archive root
                if not parts:
                    continue
                relative = Path(*parts)
                if any(part in ("..", "") or os.path.isabs(part)
                       for part in relative.parts):
                    raise SourceError(
                        f"unixhelp: archive member escapes staging: "
                        f"{member.name!r}")
                posix = relative.as_posix()
                is_licence = posix in upstream.licence_members
                if not is_licence and not _interesting(relative):
                    continue

                extracted = tar.extractfile(member)
                if extracted is None:
                    continue
                with extracted:
                    raw = extracted.read()
                body = raw.decode("utf-8", errors="replace")
                if is_licence:
                    name = f"{upstream.project}-{relative.name}"
                    (staging.parent / _LICENSES).mkdir(parents=True, exist_ok=True)
                    (staging.parent / _LICENSES / name).write_text(
                        body, encoding="utf-8")
                    licences[posix] = body[:400]
                    continue
                if "usage" not in body and "help" not in body:
                    continue
                if usage_text(body) is None:
                    continue
                target = staging / upstream.project / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(body, encoding="utf-8")
                kept += 1
    finally:
        archive.unlink(missing_ok=True)

    if not licences:
        raise SourceError(
            f"unixhelp: no {' or '.join(upstream.licence_members)} in the "
            f"{upstream.project} archive. Every document from it would carry a "
            "licence claim with no file behind it, so nothing was cached.")
    if kept < upstream.expect:
        raise SourceError(
            f"unixhelp: {upstream.project} yielded {kept} file(s) with a usage "
            f"function; expected at least {upstream.expect}. The project "
            "layout or its help idiom has changed.")
    return kept, licences


def _fetch(cache_dir: Path) -> Path:
    """Fetch every upstream. Idempotent and network-free when warm."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    home = cache_dir / "upstreams"
    if (home / _MARKER).is_file():
        return home

    staging_root = cache_dir / ".staging"
    shutil.rmtree(staging_root, ignore_errors=True)
    sources = staging_root / _SOURCES
    sources.mkdir(parents=True)

    record: dict[str, dict] = {}
    for upstream in _UPSTREAMS:
        kept, licences = _fetch_one(upstream, sources)
        record[upstream.project] = {
            "version": upstream.version,
            "url": upstream.url,
            "files": kept,
            "licence_files": sorted(licences),
        }

    shutil.rmtree(home, ignore_errors=True)
    staging_root.rename(home)
    (home / _MARKER).write_text(json.dumps(record, indent=1), encoding="utf-8")
    return home


def _documents(path: Path) -> Iterator[Document]:
    home = path if (path / _MARKER).is_file() else path / "upstreams"
    root = home / _SOURCES
    if not root.is_dir():
        raise SourceError(f"unixhelp: no {_SOURCES}/ under {home}; re-fetch")
    by_project = {upstream.project: upstream for upstream in _UPSTREAMS}

    emitted = 0
    refused: dict[str, int] = {}
    seen: set[tuple[str, str]] = set()
    per_project: dict[str, int] = {}

    # os.walk(followlinks=False), never rglob: ownrepos once followed this
    # repository's `data` symlink into the SSD and pulled the corpus cache back
    # in as PROSE — the corpus ate itself and only the balance report noticed.
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames
                             if not Path(dirpath, d).is_symlink())
        for filename in sorted(filenames):
            if not filename.endswith(".c"):
                continue
            file = Path(dirpath, filename)
            if file.is_symlink():
                continue
            relative = file.relative_to(root)
            project = relative.parts[0]
            upstream = by_project.get(project)
            if upstream is None:
                continue
            try:
                source = file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                refused["unreadable"] = refused.get("unreadable", 0) + 1
                continue

            licence = licence_of(source)
            if licence is None:
                refused["no-licence-notice"] = refused.get("no-licence-notice", 0) + 1
                continue
            if licence not in _ACCEPTED:
                key = f"licence:{licence}"
                refused[key] = refused.get(key, 0) + 1
                continue

            help_text = usage_text(source)
            if help_text is None:
                refused["no-usage-text"] = refused.get("no-usage-text", 0) + 1
                continue

            inner = Path(*relative.parts[1:])
            utility = utility_name(inner.as_posix())
            # One document per (project, utility). util-linux ships several
            # ``mkfs.*`` variants and coreutils builds some utilities from more
            # than one file; a second document for the same command would be
            # near-duplicate text, which in a corpus this size is memorised
            # rather than learned.
            if (project, utility) in seen:
                refused["duplicate-utility"] = refused.get("duplicate-utility", 0) + 1
                continue

            text = render(utility, upstream, inner.as_posix(), licence, help_text)
            if text is None:
                refused["too-short"] = refused.get("too-short", 0) + 1
                continue
            seen.add((project, utility))
            per_project[project] = per_project.get(project, 0) + 1
            emitted += 1
            yield Document(text=text, source="unixhelp", register=Register.SHELL,
                           side=Side.NEUTRAL, ident=f"{project}/{utility}")

    spread = ", ".join(f"{name} {count}"
                       for name, count in sorted(per_project.items()))
    print(f"   unixhelp: {emitted} utilities ({spread})")
    for reason, count in sorted(refused.items(), key=lambda kv: -kv[1]):
        print(f"   unixhelp: refused {count} file(s) for {reason}")


SPEC = SourceSpec(
    name="unixhelp",
    license=(
        "Composite, read per FILE rather than per project, and only "
        "redistributable-compatible identifiers are collected. Each document's "
        "licence comes from its own source file's SPDX-License-Identifier tag "
        "or FSF per-file notice, is printed in the document's provenance line, "
        "and must be one of: GPL-2.0-or-later, GPL-3.0-or-later, "
        "LGPL-2.1-or-later, LGPL-3.0-or-later, MIT, ISC, BSD-2-Clause, "
        "BSD-3-Clause. Everything else is refused and counted — including "
        "util-linux's two GPL-2.0-ONLY files (not upgradeable, so they cannot "
        "sit beside the GPL-3.0 material here), its GPL-1.0-or-later and "
        "BSD-4-Clause-UC files, its one file tagged 'GPL-2.1-or-later' (a "
        "licence that does not exist; an upstream typo is not this module's to "
        "interpret) and every file with no readable notice at all. Projects "
        "read: coreutils 9.5, findutils 4.10.0, grep 3.11, sed 4.9, diffutils "
        "3.10 (GPL-3.0-or-later); util-linux 2.40.2, procps-ng 4.0.4 "
        "(predominantly GPL-2.0-or-later). Every project's own COPYING is "
        "copied into the cache under licenses/. Since every accepted identifier "
        "is permissive or '-or-later', the collection is combinable under "
        "GPL-3.0. BusyBox is GPL-2.0-only and therefore has its own source "
        "rather than being folded in here."
    ),
    url="https://ftp.gnu.org/gnu/coreutils/ (largest of seven; see _UPSTREAMS)",
    register=Register.SHELL,
    side=Side.NEUTRAL,
    fetch=_fetch,
    documents=_documents,
    #: 94 coreutils utilities alone carry a usage() function, plus roughly 60
    #: more across util-linux, findutils, diffutils, procps-ng, grep, sed and
    #: tar. The floor sits well under the measured yield so a few files being
    #: refused on licence grounds is quiet, while a broken extractor or a
    #: reworded notice is caught first by the per-project floors in _fetch_one.
    expect_min_docs=100,
    #: Seven archives, 23.4 MB in total, each streamed and filtered member by
    #: member. Stated so a slow mirror does not look like a parser fault.
    timeout=1_800,
    notes=(
        "The literal `--help` text of ~150 GNU and Linux utilities, taken from "
        "the usage() function in each utility's own C source: the two-column "
        "flag table, the long-option vocabulary and the synopsis grammar, with "
        "no prose around it. Fills the gap manpages cannot: that source reads "
        "THIS machine's /usr/share/man, which on macOS is the BSD tools, so the "
        "GNU long options (--time-style, --color=WHEN, "
        "--group-directories-first) and the whole util-linux/procps set (ip, "
        "lsblk, findmnt, lscpu, lsns, ps --forest) were simply absent. Only the "
        "function body is read, never the file header, so the maintainer names "
        "and addresses in util-linux headers are never collected. The shared "
        "boilerplate that real --help emits through helper calls "
        "(emit_ancillary_info, HELP_OPTION_DESCRIPTION) is absent by "
        "construction, which is why this does not ship 94 copies of the same "
        "footer. %s is substituted into the Usage: line only — globally would "
        "corrupt date(1), where %s is a documented format field. Deliberately "
        "excluded: bash (its help is prose, which is SYSTEM), and tar, gawk "
        "and gzip (none of them writes its help as string literals; tar's "
        "usage() is four lines of argp), and ss64.com, which the ROADMAP names but "
        "which carries no licence grant at all."
    ),
)
