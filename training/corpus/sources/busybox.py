"""BusyBox applet usage — the shell a container actually has. SHELL register.

The ROADMAP's shopping list for the thinnest register in the build names three
things, and this is one of them: *"`ss64`, busybox and coreutils usage text for
SHELL"*. SHELL sits at 15.6% against a 26% target, and it is the register the
model must both emit and read back.

BusyBox earns its place for a reason beyond volume. Every other utility source
here documents the GNU or BSD tool as installed on a workstation; BusyBox is the
tool as installed in **everything small** — Alpine containers, initramfs,
embedded Linux, a rescue shell, the inside of most Docker images in the world.
Its applets take a *different and smaller* set of flags than their GNU
namesakes, and an agent that assumes ``ls --time-style=full-iso`` works because
it read the coreutils manual is an agent that gets an error it has never seen.
The difference is the lesson, and nothing else in this corpus carries it.

The text itself is the help output, in the form the binary prints it::

    ls [-1AaCxdLHRFplinshrSXvctu] [-w WIDTH] [FILE]...

    List directory contents

        -1      One column output
        -a      Include names starting with .
        -A      Like -a, but exclude . and ..

**That is tab-separated, and the tabs are the layout.** BusyBox writes every
flag line as ``"\\n\\t-1\\tOne column output"`` — a tab to indent, a tab between
the flag and its gloss — which is precisely the horizontal whitespace
``normalise()`` exists to preserve. The first version of ``normalise`` collapsed
runs of spaces and tabs and cost the project its best register; a source whose
entire column structure is single tabs is the cheapest possible regression test
for that lesson, and this module asserts it in :mod:`tests.test_sources_shell`.

Where the text lives, and why it is not simply ``busybox --help``
-----------------------------------------------------------------

BusyBox keeps its help text in the C sources as ``//usage:`` comments, which the
build turns into a generated header. Those comments are the canonical form and
they are *richer* than the built binary's output, because the built binary only
prints the applets and options its own ``.config`` enabled. Reading the source
gets all 434 applets and every option, rather than whichever subset the local
build happened to turn on — and it needs no toolchain.

Three shapes appear and all three are collected:

``<applet>_trivial_usage``
    The synopsis line. ``[-1AaCxd...] [-w WIDTH] [FILE]...`` — a grammar that
    appears in no other kind of written English and that the model has to be
    able to both read and produce.

``<applet>_full_usage``
    One line per option, flag then tab then gloss.

``<applet>_example_usage``
    A worked example, and **the quietly valuable one**: it is a prompt, a
    command and the command's own output, which is the shape
    :mod:`~training.corpus.sources.cmdoutput` exists to supply and which 107
    applets here carry for free::

        $ echo "foo" | sed -e 's/f[a-zA-Z]o/bar/g'
        bar

The one real trap: ``IF_NOT_`` is the other branch
--------------------------------------------------

The comments are preprocessor-conditional, wrapping optional documentation in
``IF_FEATURE_X(...)`` so the help text matches the configuration::

    //usage:        IF_FEATURE_TAR_CREATE("Create, extract, ")
    //usage:        IF_NOT_FEATURE_TAR_CREATE("Extract ")
    //usage:        "or list files from a tar file"

Keeping every literal — the obvious reading, since conditional documentation is
still documentation — splices both arms of that conditional together and yields
"Create, extract, Extract or list files from a tar file". Garbled text in a
corpus is worse than missing text: it teaches a sentence no program ever
printed. So :func:`strip_conditionals` keeps the ``IF_`` arms, which is the
default configuration and the one the distributed binary ships, and drops the
``IF_NOT_`` arms entirely, tracking nested parentheses **outside string
literals** so that ``"(De)compress using gzip"`` cannot be mistaken for
structure.

Licence: GPL-2.0-only, and the "only" is load-bearing
-----------------------------------------------------

Read from the tarball's own ``LICENSE``, which says it in as many words:

    "BusyBox is distributed under version 2 of the General Public License ...
    Version 2 is the only version of this license which this version of BusyBox
    (or modified versions derived from this one) may be distributed under."

That is why this is its own source rather than being folded into
:mod:`~training.corpus.sources.unixhelp` beside the GNU ``--help`` text it
otherwise resembles exactly. GPL-2.0-**only** cannot be combined with
GPL-3.0-or-later material into one distributable work; GPL-2.0-or-later can. One
source per licence family keeps every declaration in the build literally true
and lets this one be dropped on its own if the corpus is ever published.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tarfile
from pathlib import Path
from typing import Iterator

from ..net import NetworkError, download
from ..source import Document, Register, Side, SourceError, SourceSpec, normalise

#: Pinned to a release rather than tracking the git mirror's HEAD, because a
#: release tarball on busybox.net is immutable and a branch tip is not: a corpus
#: generation should be reproducible from the build record alone.
_VERSION = "1.37.0"
_ARCHIVE = f"https://busybox.net/downloads/busybox-{_VERSION}.tar.bz2"

#: Measured at 2.45 MB on the wire.
_MAX_ARCHIVE_BYTES = 32 * 1024 * 1024

_MARKER = ".fetched.json"
_SOURCES = "sources"
_LICENSES = "licenses"
_LICENSE_MEMBER = "LICENSE"

#: The sentence in the LICENSE that the SPEC's claim rests on. Checked at fetch
#: time because "GPL-2.0-only" is a stronger statement than "GPL" and the whole
#: reason this source stands apart from unixhelp is that the word "only" is
#: there. If upstream ever relicenses, the build should stop rather than carry a
#: stale claim.
_LICENSE_NEEDLE = "Version 2 is the only version of this license"

#: The comment marker. Everything this module reads is behind it.
_PREFIX = "//usage:"

#: ``#define ls_full_usage``. BusyBox names the three blocks by suffix.
_DEFINE = re.compile(r"#define\s+(?P<applet>[A-Za-z0-9_]+)_"
                     r"(?P<kind>trivial|full|example)_usage\b")

#: A C string literal, allowing backslash escapes (including a backslash at end
#: of line, which continues the literal and contributes nothing).
_LITERAL = re.compile(r'"((?:[^"\\]|\\.|\\\n)*)"', re.S)

#: ``IF_FEATURE_X(`` / ``IF_NOT_FEATURE_X(`` / ``IF_LONG_OPTS(`` and friends.
_IF_OPEN = re.compile(r"\bIF_(?P<negated>NOT_)?[A-Z0-9_]+\s*\(")

#: C escapes that occur in this text. ``\\\n`` is handled by the scanner, not
#: here: a line-continuation inside a literal contributes nothing at all.
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"',
            "'": "'", "0": "\0", "a": "\a", "b": "\b", "f": "\f", "v": "\v"}

#: An applet whose rendered help is shorter than this has no option table —
#: just a name and a one-line summary. Kept low because several genuinely tiny
#: applets (``true``, ``sync``, ``yes``) are real and their brevity is the fact.
_MIN_CHARS = 90


def decode_literal(raw: str) -> str:
    """Decode one C string literal's body.

    A backslash before a newline is a *line continuation*: in C it splices the
    literal and contributes no character at all. Mapping it to ``"\\n"`` — the
    obvious-looking mistake — would insert a line break into the middle of every
    wrapped sentence in the file.
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
            index += 2                        # line continuation: nothing
            continue
        out.append(_ESCAPES.get(nxt, nxt))
        index += 2
    return "".join(out)


def _without_literals(line: str) -> str:
    """``line`` with every string literal blanked out, same length kept.

    Parenthesis depth has to be counted on *this*, not on the raw line.
    ``"(De)compress using gzip"`` is an option gloss and its brackets are
    prose; ``IF_FEATURE_SEAMLESS_GZ(`` is structure. Telling them apart is the
    difference between a correct conditional reading and an off-by-one that
    swallows the rest of the applet.
    """
    return _LITERAL.sub(lambda m: " " * len(m.group(0)), line)


def strip_conditionals(lines: list[str]) -> list[str]:
    """Drop the ``IF_NOT_...`` arms, keep everything else. Returns the lines kept.

    Operates line by line because the ``//usage:`` text is line-oriented, and
    tracks depth on the literal-free projection of each line. A line that both
    opens an ``IF_NOT_`` and closes it — ``IF_NOT_FEATURE_TAR_CREATE("Extract
    ")`` — is dropped without affecting anything after it, and a block form that
    spans lines is dropped until its own closing parenthesis, however many
    ``IF_`` wrappers are nested inside it.
    """
    kept: list[str] = []
    skip_depth = 0
    for line in lines:
        bare = _without_literals(line)
        if skip_depth:
            # Inside a dropped arm: follow the depth to its end, emit nothing.
            skip_depth += bare.count("(") - bare.count(")")
            skip_depth = max(skip_depth, 0)
            continue
        negated_at = None
        for match in _IF_OPEN.finditer(bare):
            if match.group("negated"):
                negated_at = match.end()
                break
        if negated_at is None:
            kept.append(line)
            continue
        # Anything before the IF_NOT_ on this line is still wanted, but only if
        # it actually carries text: the common case is a bare wrapper line whose
        # head is whitespace, and appending that would be a no-op with a
        # misleading shape.
        head = line[:negated_at]
        if _LITERAL.search(head) is not None:
            kept.append(head)
        tail = bare[negated_at:]
        skip_depth = 1 + tail.count("(") - tail.count(")")
        skip_depth = max(skip_depth, 0)
    return kept


def parse_usage(source: str) -> dict[str, dict[str, str]]:
    """Every ``//usage:`` block in one C file, as ``{applet: {kind: text}}``.

    Pure, so the whole parser is testable against a literal without a tarball.
    """
    blocks: dict[str, dict[str, list[str]]] = {}
    current: list[str] | None = None
    for raw in source.split("\n"):
        stripped = raw.lstrip()
        if not stripped.startswith(_PREFIX):
            continue
        body = stripped[len(_PREFIX):]
        define = _DEFINE.search(body)
        if define is not None:
            applet = define.group("applet")
            kind = define.group("kind")
            current = blocks.setdefault(applet, {}).setdefault(kind, [])
            # A define line may carry text of its own: `full_usage "\n\n"`.
            body = body[define.end():]
        if current is None:
            continue
        current.append(body)

    rendered: dict[str, dict[str, str]] = {}
    for applet, kinds in blocks.items():
        for kind, lines in kinds.items():
            text = "".join(
                decode_literal(match.group(1))
                for line in strip_conditionals(lines)
                for match in _LITERAL.finditer(line)
            )
            text = text.strip("\n")
            if text.strip():
                rendered.setdefault(applet, {})[kind] = text
    return rendered


def render(applet: str, parts: dict[str, str]) -> str | None:
    """Lay out one applet as the binary would print its help, plus a header.

    The synopsis is joined to the applet name on one line, which is what
    ``busybox ls --help`` actually prints; the option table follows verbatim
    with its tabs; the example, when there is one, is labelled so the model can
    tell a transcript from a flag list.
    """
    trivial = parts.get("trivial", "").strip("\n")
    full = parts.get("full", "").strip("\n")
    example = parts.get("example", "").strip("\n")
    if not (full or trivial):
        return None

    lines = [f"BusyBox applet: {applet}", f"Platform: linux (busybox {_VERSION})", ""]
    if trivial:
        # Multi-line synopses exist (sed has an "or:" alternative form); the
        # first line attaches to the applet name, the rest keep their own.
        head, _, rest = trivial.partition("\n")
        lines.append(f"Usage: {applet} {head}".rstrip())
        if rest:
            lines.append(rest)
    else:
        lines.append(f"Usage: {applet}")
    if full:
        lines += ["", full]
    if example:
        lines += ["", "Example:", "", example]
    rendered = normalise("\n".join(lines))
    return rendered if len(rendered) >= _MIN_CHARS else None


def _fetch(cache_dir: Path) -> Path:
    """Download the release tarball and keep the C sources and the LICENSE.

    Only ``*.c`` members and ``LICENSE`` survive into the cache. The ``//usage:``
    comments are in the C files and nowhere else; the headers, Makefiles, test
    scripts and configs are of no interest, and keeping a 2.5 MB tarball's worth
    of them in the corpus cache would be 2.5 MB nobody reads.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    home = cache_dir / f"busybox-{_VERSION}"
    if (home / _MARKER).is_file():
        return home

    archive = cache_dir / ".busybox.tar.bz2.part"
    staging = cache_dir / ".busybox.staging"
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True)
    kept = 0
    licence = ""
    try:
        try:
            download(_ARCHIVE, archive, timeout=300, max_bytes=_MAX_ARCHIVE_BYTES)
        except NetworkError as exc:
            raise SourceError(f"busybox: cannot fetch {_ARCHIVE}: {exc}") from None

        with tarfile.open(archive, "r:bz2") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                parts = Path(member.name).parts[1:]      # drop busybox-N.N.N/
                if not parts:
                    continue
                relative = Path(*parts)
                is_licence = relative.as_posix() == _LICENSE_MEMBER
                if not is_licence and relative.suffix != ".c":
                    continue
                if any(part in ("..", "") or os.path.isabs(part)
                       for part in relative.parts):
                    raise SourceError(
                        f"busybox: archive member escapes staging: {member.name!r}")
                target = (staging / (_LICENSES if is_licence else _SOURCES)
                          / relative)
                extracted = tar.extractfile(member)
                if extracted is None:
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with extracted, target.open("wb") as handle:
                    shutil.copyfileobj(extracted, handle, 1 << 20)
                if is_licence:
                    licence = target.read_text(encoding="utf-8", errors="replace")
                else:
                    kept += 1
    finally:
        archive.unlink(missing_ok=True)

    if _LICENSE_NEEDLE not in licence:
        shutil.rmtree(staging, ignore_errors=True)
        raise SourceError(
            "busybox: the archive's LICENSE no longer contains "
            f"{_LICENSE_NEEDLE!r}. This source's whole reason for standing "
            "apart from unixhelp is that BusyBox is GPL-2.0-ONLY; with that "
            "sentence gone the declaration is a guess, so nothing was cached.")
    if kept < 300:
        shutil.rmtree(staging, ignore_errors=True)
        raise SourceError(
            f"busybox: cached only {kept} C file(s); expected several hundred. "
            "The tarball layout has probably changed.")

    shutil.rmtree(home, ignore_errors=True)
    staging.rename(home)
    (home / _MARKER).write_text(json.dumps(
        {"version": _VERSION, "url": _ARCHIVE, "c_files": kept,
         "license": "GPL-2.0-only"}, indent=1), encoding="utf-8")
    return home


def _documents(path: Path) -> Iterator[Document]:
    home = path if (path / _MARKER).is_file() else path / f"busybox-{_VERSION}"
    root = home / _SOURCES
    if not root.is_dir():
        raise SourceError(f"busybox: no {_SOURCES}/ under {home}; re-fetch")

    # os.walk(followlinks=False), never rglob: ownrepos once followed this
    # repository's `data` symlink into the SSD and pulled the corpus cache back
    # in as PROSE. Nothing here is a symlink; the walk refuses one anyway.
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames
                             if not Path(dirpath, d).is_symlink())
        for filename in sorted(filenames):
            if filename.endswith(".c"):
                file = Path(dirpath, filename)
                if not file.is_symlink():
                    files.append(file)

    found: dict[str, dict[str, str]] = {}
    origin: dict[str, str] = {}
    for file in files:
        try:
            source = file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if _PREFIX not in source:
            continue
        for applet, parts in parse_usage(source).items():
            # First file wins; applets are defined in exactly one place, and a
            # collision would mean the parser has mis-attributed a block.
            if applet in found:
                continue
            found[applet] = parts
            origin[applet] = file.relative_to(root).as_posix()

    if len(found) < 300:
        raise SourceError(
            f"busybox: only {len(found)} applet(s) parsed from //usage: "
            "comments; expected over 400. The comment convention has changed.")

    emitted = 0
    examples = 0
    held = 0
    for applet in sorted(found):
        text = render(applet, found[applet])
        if text is None:
            held += 1
            continue
        # Provenance travels with the document, as shellscripts does it: the
        # reader of a corpus row should be able to see where it came from and
        # under what terms without consulting this module.
        text = (f"{text}\n\nSource: busybox-{_VERSION}/{origin[applet]} "
                f"(GPL-2.0-only, BusyBox contributors)")
        examples += 1 if "example" in found[applet] else 0
        emitted += 1
        yield Document(text=text, source="busybox", register=Register.SHELL,
                       side=Side.NEUTRAL, ident=applet)

    print(f"   busybox: {emitted} applets from {len(files)} C files "
          f"({examples} with a worked example)"
          + (f"; held back {held} with no usage text" if held else ""))


SPEC = SourceSpec(
    name="busybox",
    license=(
        "GPL-2.0-only — BusyBox, read from the release tarball's own LICENSE "
        "and copied into the cache under licenses/. The file states it "
        "explicitly: \"BusyBox is distributed under version 2 of the General "
        "Public License ... Version 2 is the only version of this license "
        "which this version of BusyBox (or modified versions derived from this "
        "one) may be distributed under.\" The fetch refuses to cache anything "
        "if that sentence is gone. GPL-2.0 permits redistribution of modified "
        "works under GPL-2.0; it is NOT upgradeable, which is why this source "
        "is separate from unixhelp's GPL-3.0-or-later material rather than "
        "folded in beside it."
    ),
    url="https://busybox.net/downloads/",
    register=Register.SHELL,
    side=Side.NEUTRAL,
    fetch=_fetch,
    documents=_documents,
    #: 434 full_usage and 436 trivial_usage blocks across 353 C files at this
    #: release. The floor sits well under that so a few applets being retired is
    #: quiet, while the //usage: convention changing — which would take this to
    #: zero — trips the stricter check inside _documents first.
    expect_min_docs=350,
    #: One 2.45 MB tarball plus a walk over ~900 small C files. Fast.
    timeout=600,
    notes=(
        "One document per applet: the synopsis grammar, the tab-aligned option "
        "table and, for 107 of them, a worked example that includes the "
        "command's own output. This is the utility set an Alpine container, an "
        "initramfs or a rescue shell actually has, and its flags are a SUBSET "
        "of the GNU ones — an agent that assumes coreutils syntax here gets an "
        "error it has never seen, which is the lesson. Read from the C sources' "
        "//usage: comments rather than from `busybox --help`, because the "
        "comments carry every applet and option while a built binary carries "
        "only what its .config enabled. IF_NOT_* conditional arms are dropped "
        "and IF_* arms kept, with parenthesis depth counted outside string "
        "literals so an option gloss like \"(De)compress using gzip\" is not "
        "mistaken for structure; keeping both arms splices them into text no "
        "program ever printed. The option table is TAB-separated and the tabs "
        "are the layout — this source is the cheapest regression test the "
        "corpus has for normalise() preserving horizontal whitespace."
    ),
)
