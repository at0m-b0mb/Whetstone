"""GTFOBins — ordinary Unix binaries bent into privilege-escalation tools. SHELL/RED.

This corpus is thinnest exactly where it can least afford to be. The register
report puts SHELL at 15.6% against a 26% target (:data:`REGISTER_TARGETS`), and
SHELL is not an ornament: it is the register the model must *both* emit and read
back, and the one the first tokenizer attempt was starved of. GTFOBins is dense,
real, copy-pasteable Unix command-line tradecraft — the Unix counterpart to
LOLBAS — and it is precisely the knowledge a purple-team model needs on the side
where this project's own adapters run ``bash``.

More than volume, it is the *right shape* of shell text. Every entry answers one
concrete question — "I have this binary and I am pinned to these privileges: what
can I actually do?" — and answers it with a command, not a paragraph. That is
sequential decision-making (pick the technique the constraints allow, then run
it), not the trivia that retrieval already supplies. A single GTFOBins page binds
four things the tokenizer keeps meeting apart: the binary, the *function* it can
be abused for (spawn a shell, read a file, load a library), the *privilege
context* that gates the abuse (unprivileged / ``sudo`` / SUID bit / a Linux
capability), and the exact command. Keeping those four in one document is the
whole point; splitting them would throw away the binding that makes the source
teach anything.

**Granularity: one document per binary, not per command.** Atomic Red Team went
the other way — one document per test — because there the valuable, scarce token
is the ``T####`` identifier and it had to co-occur with every command it labels.
Here the "identifier" is the binary name (``vim``, ``python``), which is a common
token, not a scarce one, so that argument does not apply. What *does* apply is the
question the source answers, and that question is binary-centric: "I have vim
under sudo — what can I do?" A per-binary document is the literal answer, reads
coherently, and still puts the binary name beside every command because the name
is short and the document is not long. 458 binaries become 458 documents.

**Licence: GPL-3.0, and this was checked rather than assumed.** The brief that
requested this adapter asserted MIT in passing. The repository's own ``LICENSE``
file is the GNU General Public License v3.0 (GitHub's licence detector agrees),
and :mod:`~training.corpus.source` refuses a blank licence precisely so that the
declared provenance is the *true* one. So GPL-3.0 is what is declared, read off
the repo, not copied from the brief. GPL-3.0 is a copyleft licence: it permits
this research use, and the obligation it carries — attribution and share-alike —
is recorded here and the ``LICENSE`` file is copied into the cache alongside the
data, the same discipline the other sources follow.

**The files are pure YAML, and the closing marker is a trap for the naive parser.**
The brief described "markdown files with YAML front matter", and that is the
historical mental model, but the current repository stores each binary as a
Jekyll collection document that is *entirely* front matter: it opens with ``---``
and closes with ``...`` (YAML's end-of-document marker) with an empty body, and
the files carry no ``.md`` extension — they are named for the binary (``vim``,
``7z``, ``aa-exec``). The command bodies are literal block scalars (``code: |-``)
and some of them contain lines that look like ``---`` or protocol text with
embedded ``\\r\\n``. Splitting the file on ``---`` to peel off front matter would
therefore mangle those commands. So the file is handed whole to PyYAML, which
treats ``---``/``...`` as document markers and leaves anything inside an indented
block scalar untouched: parsing *is* the defensive move here, string-slicing is
the bug it avoids. A file that fails to parse, or that carries no ``functions``
mapping (20 files are pure ``alias:`` redirects — ``nvim`` → ``vim`` — with no
commands of their own), is skipped rather than raised on; a single odd file
should not fail a build, and the aggregate floor below catches real breakage.

**Whitespace is preserved because the command is the payload.** Documents pass
through :func:`~training.corpus.source.normalise`, which by contract never
collapses horizontal whitespace — the same guarantee Sigma's indentation and
netstat's columns depend on. A GTFOBins command is meaningful to the byte: the
``-p`` in ``/bin/sh -p``, the alignment of a here-document, the spacing inside a
one-liner Python or Perl payload. Command blocks are emitted flush-left under a
label, never wrapped in a decorative indent, because normalise() would keep that
indent too and it would be pure noise charged against every line of every
command — the lesson Atomic's ``_block`` already paid for.

**The category and context prose comes from the source itself.** ``_data/
functions.yml`` and ``_data/contexts.yml`` carry GTFOBins's own one-line
descriptions of each function ("This executable can spawn an interactive system
shell.") and the attacker-side helper commands for reverse shells and file
transfer (the ``nc -l -p 12345`` a reverse shell listens with). Those files are
extracted alongside the binaries and read at render time so the explanations are
the project's, not invented here; hardcoded fallbacks stand in only if a future
layout drops them, so a missing data file degrades to still-useful text instead
of a blank one.

Upstream: https://github.com/GTFOBins/GTFOBins.github.io (GPL-3.0)
"""

from __future__ import annotations

import io
import json
import shutil
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from training.corpus import net
from training.corpus.source import (
    Document,
    Register,
    Side,
    SourceError,
    SourceSpec,
    normalise,
)

__all__ = ["SPEC"]

#: codeload serves the branch tarball in one request — no git, no history. The
#: whole repository is tiny (~90 KB of YAML), so it is fetched into memory and
#: unpacked from there rather than streamed to a temp file.
_TARBALL = "https://codeload.github.com/GTFOBins/GTFOBins.github.io/tar.gz/refs/heads/master"
_REPO = "https://github.com/GTFOBins/GTFOBins.github.io"

#: The Jekyll collection of binary definitions, and the data files that describe
#: the function and context vocabularies. Both are extracted; everything else in
#: the repo (the site's HTML, CSS and JS) is left in the tarball.
_COLLECTION = "_gtfobins"
_DATA = "_data"

#: Written last, so its presence means extraction finished. A half-populated
#: cache re-fetches rather than yielding a partial corpus.
_MARKER = ".fetched.json"

#: Fetch-time floor on extracted binary files. 478 were present upstream when
#: this adapter was written (458 with commands, 20 pure aliases). A floor well
#: below that turns the realistic regression — the collection directory renamed
#: or moved, yielding nothing — into a loud failure at fetch time instead of a
#: mysteriously thin build report.
_MIN_BINARIES = 400

#: Nothing shorter than this is a useful document. Every rendered binary carries
#: at least one command, so this only rejects a degenerate render, not real data.
_MIN_CHARS = 80

#: The order GTFOBins's own ``_data/functions.yml`` declares, which reads from
#: "most access" to "least direct": interactive shells first, then file I/O, then
#: library loading and privilege escalation, and inherited functions last.
#: Unknown functions (a future addition) sort to the end alphabetically so the
#: adapter keeps rendering them rather than silently dropping them.
_FUNCTION_ORDER = (
    "shell",
    "command",
    "reverse-shell",
    "bind-shell",
    "file-write",
    "file-read",
    "upload",
    "download",
    "library-load",
    "privilege-escalation",
    "inherit",
)

#: Fallback function labels and descriptions, mirrored from ``_data/functions.yml``.
#: Used only when the live data file is missing or unparseable; the live file is
#: preferred so the wording stays the source's own.
_FALLBACK_FUNCTIONS: dict[str, tuple[str, str]] = {
    "shell": ("Shell", "This executable can spawn an interactive system shell."),
    "command": ("Command", "This executable can run non-interactive system commands."),
    "reverse-shell": (
        "Reverse shell",
        "This executable can send back a reverse system shell to a listening attacker.",
    ),
    "bind-shell": (
        "Bind shell",
        "This executable can bind a system shell to a local port waiting for an "
        "attacker to connect.",
    ),
    "file-write": ("File write", "This executable can write data to local files."),
    "file-read": ("File read", "This executable can read data from local files."),
    "upload": ("Upload", "This executable can upload local data."),
    "download": ("Download", "This executable can download remote data."),
    "library-load": (
        "Library load",
        "This executable can load shared libraries that may be used to run "
        "arbitrary code in the same execution context.",
    ),
    "privilege-escalation": (
        "Privilege escalation",
        "This executable provides a mechanism for privilege escalation by "
        "indirectly enabling elevated privileges, such as setting the SUID bit "
        "or modifying the ownership of another executable.",
    ),
    "inherit": (
        "Inherited functions",
        "This executable can inherit functions from another.",
    ),
}

#: Which entry key carries the attacker-side helper reference, per function.
#: Each key is unique to one function upstream, so the resolver below can key on
#: the field name alone.
_HELPER_FIELDS = ("listener", "connector", "receiver", "sender")

#: The privilege contexts, in the order ``_data/contexts.yml`` declares, and a
#: concise plain-words gloss of what each one means for the attacker. The gloss
#: is deliberately short: the fuller wording lives in the source, and repeating a
#: paragraph across hundreds of documents would spend the corpus budget on
#: boilerplate the model would only memorise.
_CONTEXT_ORDER = ("unprivileged", "sudo", "suid", "capabilities")
_CONTEXT_PHRASE: dict[str, str] = {
    "unprivileged": "as an unprivileged user",
    "sudo": "via sudo (privileges are not dropped, so it runs as root)",
    "suid": "with the SUID bit set (effective privileges are not dropped)",
    "capabilities": "with the required capability set (kernel permission checks are bypassed)",
}
#: The short name a context-specific command variant is labelled with, so the
#: SUID/capabilities alternate reads "SUID variant:" rather than the full phrase.
_CONTEXT_VARIANT_LABEL: dict[str, str] = {
    "unprivileged": "unprivileged",
    "sudo": "sudo",
    "suid": "SUID",
    "capabilities": "capabilities",
}


# --------------------------------------------------------------------------- #
# Fetch
# --------------------------------------------------------------------------- #
def _fetch(cache_dir: Path) -> Path:
    """Download and unpack the GTFOBins collection into ``cache_dir``. Idempotent.

    The completion marker is written only after a full extraction, so a populated
    cache short-circuits before touching the network and an interrupted fetch is
    retried rather than mistaken for a finished one.

    TLS goes through :func:`training.corpus.net.ssl_context` — the one place trust
    anchors are established — because the python.org macOS interpreter this
    project runs on ships an empty CA store and would otherwise fail every HTTPS
    fetch on a working network. Members are copied out by hand, with every
    destination proved to resolve inside the staging tree first: a tar member
    name is attacker-controlled data in principle (absolute paths, ``..``,
    symlinks are all expressible), and constructing the path ourselves makes
    traversal unrepresentable without leaning on ``filter="data"`` (3.12+ only).
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    marker = cache_dir / _MARKER
    collection = cache_dir / _COLLECTION
    if marker.is_file() and collection.is_dir():
        return cache_dir

    try:
        raw = net.fetch(_TARBALL, timeout=120)
    except net.NetworkError as exc:
        raise SourceError(f"gtfobins: {exc}") from exc

    staging = cache_dir / ".staging"
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True, exist_ok=True)
    resolved_staging = staging.resolve()
    binaries = 0
    license_written = False

    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                parts = Path(member.name).parts
                if len(parts) < 2:
                    continue
                # Drop the archive's single root directory ("GTFOBins…-master/").
                relative = Path(*parts[1:])
                if relative.is_absolute() or ".." in relative.parts:
                    continue

                top = relative.parts[0]
                keep = (
                    top == _COLLECTION
                    or (top == _DATA and relative.suffix == ".yml")
                    or relative.as_posix() == "LICENSE"
                )
                if not keep:
                    continue

                target = staging / relative
                if not target.resolve().is_relative_to(resolved_staging):
                    continue
                stream = tar.extractfile(member)
                if stream is None:
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with stream, target.open("wb") as handle:
                    shutil.copyfileobj(stream, handle)
                if top == _COLLECTION:
                    binaries += 1
                elif relative.as_posix() == "LICENSE":
                    license_written = True
    except tarfile.TarError as exc:
        raise SourceError(f"gtfobins: malformed tarball from {_TARBALL}: {exc}") from exc

    if binaries < _MIN_BINARIES:
        shutil.rmtree(staging, ignore_errors=True)
        raise SourceError(
            f"gtfobins: only {binaries} files found under {_COLLECTION}/ in "
            f"{_TARBALL} (expected >= {_MIN_BINARIES}). The upstream layout has "
            "probably changed; fix the adapter rather than training on a fraction "
            "of the source."
        )

    # Swap into place only once staging is complete, so an interrupted fetch can
    # never leave a half-populated directory a later run mistakes for finished.
    try:
        for sub in (_COLLECTION, _DATA):
            src = staging / sub
            if src.is_dir():
                dst = cache_dir / sub
                shutil.rmtree(dst, ignore_errors=True)
                src.replace(dst)
        staged_license = staging / "LICENSE"
        if staged_license.is_file():
            staged_license.replace(cache_dir / "LICENSE")
        marker.write_text(
            json.dumps(
                {
                    "url": _TARBALL,
                    "repo": _REPO,
                    "fetched_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "binary_files": binaries,
                    "license_file": license_written,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return cache_dir


# --------------------------------------------------------------------------- #
# Metadata: the source's own descriptions and helper commands
# --------------------------------------------------------------------------- #
class _Meta:
    """Function/context descriptions and network-helper commands from ``_data/``.

    Reading these from the source keeps every explanation GTFOBins's own wording
    rather than a paraphrase invented here, which is what "explain the categories
    where the source gives you the material" asks for. When the data files are
    absent the fallbacks take over so the adapter still produces useful text.
    """

    def __init__(self, functions: dict[str, Any] | None) -> None:
        self._labels: dict[str, str] = {}
        self._descriptions: dict[str, str] = {}
        # helpers[field][name] -> {"code": str, "comment": str}
        self._helpers: dict[str, dict[str, dict[str, str]]] = {f: {} for f in _HELPER_FIELDS}

        for key, (label, description) in _FALLBACK_FUNCTIONS.items():
            self._labels[key] = label
            self._descriptions[key] = description

        if isinstance(functions, dict):
            for key, spec in functions.items():
                if not isinstance(spec, dict):
                    continue
                label = spec.get("label")
                if isinstance(label, str) and label.strip():
                    self._labels[key] = label.strip()
                description = spec.get("description")
                if isinstance(description, str) and description.strip():
                    self._descriptions[key] = description.strip()
                extra = spec.get("extra")
                if not isinstance(extra, dict):
                    continue
                for field in _HELPER_FIELDS:
                    group = extra.get(field)
                    if not isinstance(group, dict):
                        continue
                    for name, detail in group.items():
                        if not isinstance(detail, dict):
                            continue
                        code = detail.get("code")
                        comment = detail.get("comment")
                        self._helpers[field][name] = {
                            "code": code if isinstance(code, str) else "",
                            "comment": comment if isinstance(comment, str) else "",
                        }

    def label(self, function: str) -> str:
        return self._labels.get(function) or function.replace("-", " ").capitalize()

    def description(self, function: str) -> str:
        return self._descriptions.get(function, "")

    def helper(self, field: str, name: str) -> dict[str, str]:
        return self._helpers.get(field, {}).get(name, {})


def _load_meta(cache_dir: Path) -> _Meta:
    """Load ``_data/functions.yml`` if present; fall back to the constants above."""
    import yaml  # local: PyYAML is only needed when this source is built

    data_file = cache_dir / _DATA / "functions.yml"
    functions: dict[str, Any] | None = None
    if data_file.is_file():
        try:
            loaded = yaml.safe_load(data_file.read_text(encoding="utf-8"))
        except (yaml.YAMLError, UnicodeDecodeError, OSError):
            loaded = None
        if isinstance(loaded, dict):
            functions = loaded
    return _Meta(functions)


# --------------------------------------------------------------------------- #
# Render
# --------------------------------------------------------------------------- #
def _as_text(value: Any) -> str:
    """Render a YAML scalar the way a reader would see it.

    ``binary``/``blind``/``shell`` come back as Python bools; the rest is coerced
    to ``str`` so a stray typed field never blows up mid-render.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    return str(value)


def _block(label: str, body: str) -> list[str]:
    """A labelled block emitted flush-left, or nothing when the body is empty.

    The body — usually a command — reaches the tokenizer with exactly the spacing
    upstream wrote. No wrapper indent, deliberately: normalise() preserves leading
    whitespace, so an indent here would be charged against every line of every
    command for no signal. This is Atomic's lesson, kept.
    """
    body = body.strip("\n")
    if not body.strip():
        return []
    return [f"{label}:", body, ""]


def _context_summary(contexts: dict[str, Any]) -> str:
    """A one-line plain-words statement of which privilege contexts allow this."""
    phrases = [
        _CONTEXT_PHRASE[name]
        for name in _CONTEXT_ORDER
        if name in contexts
    ]
    # Any context the vocabulary has not seen still gets named rather than dropped.
    phrases += [
        name for name in contexts if name not in _CONTEXT_PHRASE
    ]
    if not phrases:
        return ""
    return "Works when run " + "; ".join(phrases) + "."


def _context_details(contexts: dict[str, Any]) -> list[str]:
    """Notes and context-specific command variants attached to a technique.

    SUID and capability contexts often carry their *own* command — the SUID
    variant that keeps the ``-p`` argument, the capabilities variant that calls
    ``setuid(0)`` first — plus the list of capabilities required and the note
    about whether the binary shells out or execs directly. These are distinct,
    real commands, not decoration, so they are rendered as their own blocks.
    """
    lines: list[str] = []
    for name in _CONTEXT_ORDER:
        detail = contexts.get(name)
        if not isinstance(detail, dict):
            continue
        label = _CONTEXT_VARIANT_LABEL.get(name, name)

        caps = detail.get("list")
        if isinstance(caps, list) and caps:
            joined = ", ".join(_as_text(c) for c in caps)
            lines.append(f"requires capability: {joined}")

        shell_flag = detail.get("shell")
        if shell_flag is True:
            lines.append(
                "SUID note: this binary runs commands via the system shell, so it "
                "only works where the shell does not drop SUID privileges."
            )
        elif shell_flag is False:
            lines.append(
                "SUID note: this binary runs commands directly (e.g. via exec); on "
                "distributions whose default shell drops SUID privileges, omit the "
                "-p argument."
            )

        comment = _as_text(detail.get("comment")).strip()
        if comment:
            lines.append(comment)

        code = _as_text(detail.get("code")).strip("\n")
        if code.strip():
            lines.append(f"{label} variant:")
            lines.append(code)
    return lines


def _helper_block(entry: dict[str, Any], meta: _Meta) -> list[str]:
    """The attacker-side counterpart command (listener / uploader / etc.).

    A reverse shell without the listener that catches it, or an upload without
    the receiver that stores it, is half a technique. GTFOBins records the other
    half either inline (a mapping with its own ``code``) or by name into
    ``_data/functions.yml`` (``listener: tcp-server``); both are resolved here.
    """
    for field in _HELPER_FIELDS:
        if field not in entry:
            continue
        value = entry[field]
        if isinstance(value, dict):
            code = _as_text(value.get("code")).strip("\n")
            comment = _as_text(value.get("comment")).strip()
        elif isinstance(value, str):
            resolved = meta.helper(field, value)
            code = resolved.get("code", "").strip("\n")
            comment = resolved.get("comment", "").strip()
            if not comment:
                comment = f"attacker-side {field}: {value}"
        else:
            continue

        heading = comment or f"attacker-side {field}"
        if not code.strip():
            # Some helpers (ssh-server) are described but carry no one-liner.
            return [f"attacker's side — {heading}", ""]
        # Not _block(): the heading is a sentence, and _block's trailing colon
        # after a full stop would read "…receive the shell.:".
        return [f"attacker's side — {heading}", code, ""]
    return []


def _render_entry(entry: dict[str, Any], meta: _Meta) -> list[str]:
    """One technique: its notes, the privilege contexts, and the command(s)."""
    lines: list[str] = []

    origin = _as_text(entry.get("from")).strip()
    if origin:
        lines.append(f"inherited from {origin}:")

    comment = _as_text(entry.get("comment")).strip()
    if comment:
        lines.append(comment)

    if entry.get("binary") is False:
        lines.append(
            "note: not binary-safe — the content may be altered in transit, so it "
            "is unsuitable for arbitrary binary data."
        )
    if entry.get("blind") is True:
        lines.append(
            "note: blind — the command runs but its output is not returned to the "
            "attacker."
        )
    if entry.get("tty") is False:
        lines.append(
            "note: the spawned shell is a limited REPL, not a full interactive TTY."
        )

    version = _as_text(entry.get("version")).strip()
    if version:
        lines.append(f"version note: {version}")

    contexts = entry.get("contexts")
    if isinstance(contexts, dict) and contexts:
        summary = _context_summary(contexts)
        if summary:
            lines.append(summary)

    if lines:
        lines.append("")

    lines += _block("command", _as_text(entry.get("code")))

    if isinstance(contexts, dict) and contexts:
        detail_lines = _context_details(contexts)
        if detail_lines:
            lines += detail_lines
            lines.append("")

    lines += _helper_block(entry, meta)
    return lines


def _render(name: str, data: dict[str, Any], meta: _Meta) -> str | None:
    """Assemble one binary into the text the model will see, or ``None``.

    Returns ``None`` when the file carries no runnable command — an ``alias:``
    redirect or an empty ``functions`` map — so a header-only document is never
    emitted.
    """
    functions = data.get("functions")
    if not isinstance(functions, dict) or not functions:
        return None

    lines: list[str] = [f"gtfobins: {name}", ""]

    binary_comment = _as_text(data.get("comment")).strip()
    if binary_comment:
        lines += _block("comment", binary_comment)

    ordered = sorted(
        functions.items(),
        key=lambda kv: (
            _FUNCTION_ORDER.index(kv[0]) if kv[0] in _FUNCTION_ORDER else len(_FUNCTION_ORDER),
            kv[0],
        ),
    )

    commands = 0
    for function, entries in ordered:
        if not isinstance(entries, list) or not entries:
            continue
        rendered: list[str] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            if not _as_text(entry.get("code")).strip():
                continue
            rendered += _render_entry(entry, meta)
            commands += 1
        if not rendered:
            continue

        header = f"[{meta.label(function)}]"
        description = meta.description(function)
        if description:
            header += f" {description}"
        lines.append(header)
        lines.append("")
        lines += rendered

    if commands == 0:
        return None
    return "\n".join(lines)


def _documents(path: Path) -> Iterator[Document]:
    """Yield one :class:`Document` per abusable binary, in stable sorted order.

    Files are walked sorted by name so the corpus is byte-reproducible. A file
    that fails to parse or is not a mapping is skipped, not raised on: one odd
    file should not fail a build, and :data:`SPEC.expect_min_docs` catches the
    systemic breakage — a renamed collection directory — that actually matters.
    """
    import yaml  # local: PyYAML is only needed when this source is built

    root = path / _COLLECTION if (path / _COLLECTION).is_dir() else path
    if not root.is_dir():
        raise SourceError(f"gtfobins: no {_COLLECTION}/ directory under {path}")

    meta = _load_meta(path if (path / _DATA).is_dir() else root.parent)

    files = sorted(p for p in root.iterdir() if p.is_file())
    if not files:
        raise SourceError(f"gtfobins: {root} contains no binary files")

    for file in files:
        try:
            data = yaml.safe_load(file.read_text(encoding="utf-8"))
        except (yaml.YAMLError, UnicodeDecodeError, OSError):
            continue
        if not isinstance(data, dict):
            continue

        rendered = _render(file.name, data, meta)
        if rendered is None:
            continue
        text = normalise(rendered)
        if len(text) < _MIN_CHARS:
            continue
        yield Document(
            text=text,
            source="gtfobins",
            register=Register.SHELL,
            side=Side.RED,
            ident=file.name,
        )


SPEC = SourceSpec(
    name="gtfobins",
    license=(
        "GPL-3.0-only (GNU General Public License v3.0; the repository's LICENSE "
        "file is copied into the cache) — https://github.com/GTFOBins/GTFOBins.github.io/blob/master/LICENSE"
    ),
    url=_REPO,
    register=Register.SHELL,
    side=Side.RED,
    fetch=_fetch,
    documents=_documents,
    #: 458 binaries carried commands upstream at fetch time (478 files, 20 of them
    #: pure `alias:` redirects with no commands). The floor sits well below that
    #: so ordinary churn is quiet, while a parser that starts dropping binaries —
    #: or a renamed collection directory — trips it immediately.
    expect_min_docs=380,
    notes=(
        "One document per abusable binary: the binary name, an optional binary-"
        "level note, then each function (shell, file-read, reverse-shell, inherit, "
        "...) with GTFOBins's own one-line description, followed by every command "
        "for that function, the privilege contexts that allow it (unprivileged / "
        "sudo / SUID / capabilities) in plain words, any SUID or capability "
        "command variant, and the attacker-side listener/receiver counterpart for "
        "reverse shells and transfers. Files are pure YAML (--- ... with an empty "
        "body) parsed with PyYAML rather than split on ---, so command blocks that "
        "contain --- survive. `alias:` redirect files (nvim -> vim) are skipped. "
        "normalise() preserves the horizontal whitespace the commands depend on."
    ),
)
