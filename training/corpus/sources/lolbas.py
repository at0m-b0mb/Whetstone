"""LOLBAS — abusing the binaries Windows already trusts. SHELL register, RED side.

SHELL is the register this corpus is thinnest in. The last build measured 15.6%
actual against the 26% target in
:data:`~training.corpus.source.REGISTER_TARGETS`, and that gap is not cosmetic:
shell is the register the model must both *emit* (choose a verb, write the
command) and *read back* (parse what the command printed). Everything the
balancer throws away from the fat registers is thrown away in service of a floor
this one cannot reach. LOLBAS is the densest body of "abuse a legitimate binary
from the command line" knowledge that exists anywhere, and it is licensed.

It is the right shape three times over:

**The commands are real and they are Windows.** Two hundred and forty-eight
signed Microsoft binaries, four hundred and eighty-nine documented abuses, every
one of them a command line somebody has actually run —
``certutil.exe -urlcache -f``, ``regsvr32 /s /u /i:http://... scrobj.dll``,
``rundll32.exe comsvcs.dll, MiniDump``. Atomic Red Team already gives this corpus
attacker shell, but it gives it as a *test harness*: parameterised, wrapped in
prerequisites, written to be run by a runner. LOLBAS gives the minimum viable
line, which is what an operator types and what shows up in a
``ParentImage``/``CommandLine`` pair afterwards.

**Every command carries its ATT&CK id, beside the human name for what it does.**
This is the measurement ``source.py`` was built around: ``T1547.001`` scored -45%
against gpt2 when the corpus had never met an ATT&CK identifier, and putting the
id next to the name of the thing it denotes in running prose is what moved that
sample to +13%. LOLBAS stores the id already in wild form — 61 distinct
``T####[.###]`` values across 489 commands, no naked integers to reconstruct the
way CAPEC needed — sitting in the same YAML block as the ``Usecase`` sentence and
the command itself. So the rendering writes ``Download file from Internet,
ATT&CK T1105`` directly above the ``certutil.exe`` line it labels, and again
beside the LOLBAS category below it. Two occurrences per command, both adjacent
to a human phrase, never once on a line by itself.

**It is purple in a single document.** Each entry pairs the attacker's command
with the detection that catches it: 296 Sigma links, 282 free-text IOCs ("Useragent
Microsoft-CryptoAPI/10.0", "Certutil.exe creating new files on disk"), 87 Elastic
rules, 48 Splunk, 24 Microsoft block rules. This project's whole argument is that
a red verb and its ``detected_by`` belong in the same window — that silence there
*is* the detection gap. Nothing else in the corpus states that join upstream; here
it is the file format.

**One document per binary, not per command.** The opposite choice from
:mod:`~training.corpus.sources.atomic`, and for the reason that made that one go
the other way. Atomic prints a technique id once at the top of a file and then
thirty commands beneath it, so per-file the id would be a thousand tokens from
the last command it labels; splitting restated it. LOLBAS already restates the id
per command — the schema nests ``MitreID`` *inside* each ``Commands`` entry — so
splitting buys no identifier density. It would cost the join: the ``Detection``
block is per binary, so 489 documents would each have to carry a duplicated copy
of it (near-duplicate text in a small corpus is worse than absent text; the model
memorises it) or drop it and throw away the purple pairing that is half the
reason this source is here. Two commands per entry on average, ~3 KB a document:
the command and the Sigma rule that fires on it stay in one window.

**The archive tree is excluded, and that is not housekeeping.**
``Archive-Old-Version/LOLUtilz/`` holds superseded YAML for binaries that are
*also* live under ``yml/`` — Explorer, Netsh, Psr and Winword are in both — with
the same commands in an older schema. Whole-document fingerprinting would not
collapse them, because the old files differ in wording and field set. They would
land in the corpus as an almost-copy of a live entry, which is precisely the
near-duplicate the dedup pass cannot see. Only ``yml/`` is extracted.

**Two lines here are furniture, and that is fine.**
:mod:`training.corpus.boilerplate` strips any prose line of 40+ characters that
recurs across 25+ documents, and exactly two lines of this source qualify:
``works on: Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10, Windows
11`` (56 entries) and the credit line for the project's most prolific author (79
entries). Together they are 14 KB of 470 KB. That was checked rather than
assumed, and nothing is done about it on purpose: a source that reformats its own
text to slip past a corpus-wide filter is a source whose output no longer means
what the build report says it means. The filter is right — a version list
repeated verbatim in a fifth of the documents is furniture — and the command
lines, use cases, ATT&CK ids and IOCs that this source exists for are all either
too short, too punctuation-dense or too distinct to be touched by it.

**Whitespace.** Commands are emitted flush-left with nothing wrapped around them,
and :func:`~training.corpus.source.normalise` preserves horizontal whitespace by
contract, so every command line reaches the tokenizer byte-exact: the backslash
paths, the ``{PATH_ABSOLUTE:.dll}`` placeholders LOLBAS uses for operator-supplied
arguments, the embedded XML in the ``wsb start --config`` one-liners, and the
newlines inside the five multi-line commands that are really short scripts. That
guarantee is the reason the adapter does no cleaning of its own — a private
cleaner in one source is how a corpus stops being comparable across sources.

**Licence.** GPL-3.0. The repository's ``LICENSE`` is the verbatim GNU GPL v3
text and ``NOTICE.md`` states "The LOLBAS Project is licensed under GPL 3.0" with
no "or later" clause, so it is recorded as GPL-3.0-only rather than guessed from
the more common ``-or-later`` habit. ``NOTICE.md`` additionally reproduces MITRE's
ATT&CK terms of use, because the ``MitreID`` fields are ATT&CK; that grant is
carried into :data:`SPEC` for the same reason
:mod:`~training.corpus.sources.capec` carries it. Both files are copied into the
cache so the claim is checkable against what was actually downloaded rather than
against this docstring.

Upstream: https://github.com/LOLBAS-Project/LOLBAS
"""

from __future__ import annotations

import json
import re
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

_REPO = "https://github.com/LOLBAS-Project/LOLBAS"
#: codeload serves the branch tarball directly: one ~950 KB request, no git
#: binary, no history, and nothing a later ``git pull`` could mutate underneath
#: a build that is supposed to be reproducible.
_TARBALL = "https://codeload.github.com/LOLBAS-Project/LOLBAS/tar.gz/refs/heads/master"

#: ``<root>/yml/<Category>/<Binary>.yml`` and nothing else. The category segment
#: is captured rather than enumerated on purpose: upstream added ``OSLibraries``
#: and ``HonorableMentions`` to an originally three-way split, and a hardcoded
#: list would have silently dropped both. Unknown categories still get collected
#: and fall back to a neutral description in :func:`_kind`.
#:
#: Matching ``yml/`` specifically is also what excludes ``Archive-Old-Version/``,
#: whose superseded copies of live entries are near-duplicates the
#: fingerprint dedup cannot catch. See the module docstring.
_MEMBER = re.compile(r"^[^/]+/yml/([A-Za-z0-9_-]+)/([A-Za-z0-9._+-]+\.yml)$")
#: Provenance worth keeping beside the cache: the GPL text and the notice that
#: carries both the licence statement and MITRE's ATT&CK grant.
_LICENSE_MEMBERS = {"LICENSE": "LICENSE", "NOTICE.md": "NOTICE.md"}
_ROOTED_LICENSE = re.compile(r"^[^/]+/(LICENSE|NOTICE\.md)$")

#: A ceiling on one archive member. Extraction below used to be
#: ``write_bytes(stream.read())``, one allocation of whatever the member
#: declared, and NUL bytes gzip at roughly 1000:1 — so a single
#: ``yml/<category>/<name>.yml`` holding 8 GiB of them leaves the tarball
#: looking entirely ordinary on the wire and then asks for an 8 GiB allocation.
#: On this machine that is a MemoryError that kills the build, or an OOM kill
#: that picks whatever else is running.
#:
#: Checked against ``member.size`` *before* extracting, which is sound rather
#: than trusting: tarfile bounds the reader it returns to exactly the declared
#: length, so a member cannot deliver more than its header claims. The largest
#: real entry is 34 KB, so this leaves four hundred times the room it needs and
#: still refuses a bomb.
_MAX_MEMBER_BYTES = 16 * 1024 * 1024

#: Written only after extraction completes, so an interrupted fetch is retried
#: rather than mistaken for a populated cache.
_MARKER = ".fetched.json"

#: 248 entry files were present upstream when this adapter was written. A floor
#: well below that keeps ordinary churn quiet while a renamed or restructured
#: ``yml/`` tree — the realistic regression — fails at fetch time with a message
#: instead of producing a three-document build report nobody reads.
_MIN_FILES = 150

#: A real entry renders to a couple of thousand characters. Anything under this
#: is a stub or a truncated file; skip it rather than let the Document
#: constructor raise in the middle of a build.
_MIN_CHARS = 200

#: ``GfxDownloadWrapper.exe`` lists 156 near-identical Intel driver-store paths
#: (``...\filerepository\cui_dch.inf_amd64_<hex>\...``). That one entry holds a
#: fifth of all 774 paths in the project, and they teach the tokenizer a hex
#: suffix, not a filesystem. Everything else has a median of two paths, so the
#: cap costs nothing anywhere else and the elision is stated in the text rather
#: than hidden.
_MAX_PATHS = 10

#: Resource links are provenance — blog posts, conference talks, and a lot of
#: ``twitter.com/<handle>/status/<19 digits>``. Worth keeping a few of for
#: attribution; not worth spending the SHELL register's character budget on a
#: dozen opaque numeric ids per entry.
_MAX_RESOURCES = 6

#: ``Detection`` keys, in the order they are emitted, mapped to the phrase that
#: names them. IOCs come first deliberately: they are the one part of the block
#: that is *readable* ("Useragent CertUtil URL Agent", "Process tree: code.exe ->
#: cmd.exe -> node.exe"), so the section opens with something a model can learn a
#: behaviour from rather than with four hundred characters of commit-pinned URL.
_DETECTION_ORDER: tuple[tuple[str, str], ...] = (
    ("IOC", "IOC"),
    ("Analysis", "analysis"),
    ("Sigma", "Sigma rule"),
    ("Elastic", "Elastic rule"),
    ("Splunk", "Splunk rule"),
    ("BlockRule", "Microsoft block rule"),
)

#: Directory name -> (what the thing is, what the community calls it). The
#: sentence this feeds is the one piece of framing the adapter adds that is not
#: in the YAML, and it is the same distinction the project's own README draws:
#: native to the OS, or downloaded from Microsoft.
_KINDS: dict[str, tuple[str, str]] = {
    "OSBinaries": ("a Microsoft-signed executable that ships with Windows", "LOLBin"),
    "OSLibraries": ("a Microsoft-signed library that ships with Windows", "LOLLib"),
    "OSScripts": ("a Microsoft-signed script that ships with Windows", "LOLScript"),
    "OtherMSBinaries": (
        "a Microsoft-signed executable that is not part of Windows itself but is "
        "downloaded from Microsoft with the SDK, Office, Visual Studio or Sysinternals",
        "LOLBin",
    ),
    "HonorableMentions": (
        "a Microsoft-signed file that LOLBAS lists as an honorable mention: "
        "genuinely abusable, but it does not meet every criterion the project "
        "requires of a catalogued entry",
        "LOLBin",
    ),
}


def _kind(category: str) -> tuple[str, str]:
    """What a ``yml/`` subdirectory means, with a neutral fallback.

    An unrecognised directory is described rather than dropped. The alternative
    — skipping what the map does not know — is how a source quietly loses a
    whole new upstream category and reports only a slightly smaller number.
    """
    return _KINDS.get(
        category, ("a Microsoft-signed file catalogued by the LOLBAS project", "LOLBin")
    )


def _fetch(cache_dir: Path) -> Path:
    """Download and unpack ``yml/`` into ``cache_dir``. Idempotent, returns it.

    Re-runs are free: the marker short-circuits before the network is touched.

    The tarball body goes through :func:`training.corpus.net.download` rather
    than a private ``urlopen``. That helper is the one place TLS contexts are
    built in this project, and it exists because three adapters independently
    grew their own CA-bundle search after the python.org macOS interpreter here
    turned out to ship an empty trust store. Three copies of trust code is how
    one of them drifts into ``CERT_NONE`` at 2 a.m.; at ~950 KB this source has
    no excuse to stream around it the way ``atomic`` does with 167 MB.

    Members are written from the two components :data:`_MEMBER` captured, never
    from the archive's own name. A tar member name is attacker-controlled data
    in the general case — absolute paths, ``..`` segments and symlinks are all
    expressible — and rebuilding the destination from a validated category and
    filename makes traversal unrepresentable without depending on
    ``filter="data"``, which is 3.12+ only.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    yml_dir = cache_dir / "yml"
    marker = cache_dir / _MARKER
    if marker.is_file() and yml_dir.is_dir():
        return cache_dir

    archive = cache_dir / ".download.tar.gz"
    written = 0
    try:
        try:
            net.download(_TARBALL, archive, timeout=180)
        except net.NetworkError as exc:
            # The no-CA message from net.ssl_context() explains how to fix it;
            # do not bury it.
            raise SourceError(f"lolbas: {exc}") from exc

        try:
            with tarfile.open(archive, mode="r|gz") as tar:
                for member in tar:
                    if not member.isfile():
                        continue
                    # Before extracting anything, including the licence: see
                    # _MAX_MEMBER_BYTES for why the tarball's own size is no
                    # evidence about a member's.
                    if member.size > _MAX_MEMBER_BYTES:
                        continue
                    rooted = _ROOTED_LICENSE.match(member.name)
                    if rooted is not None:
                        stream = tar.extractfile(member)
                        if stream is not None:
                            name = _LICENSE_MEMBERS[rooted.group(1)]
                            with stream, (cache_dir / name).open("wb") as out:
                                shutil.copyfileobj(stream, out, 1 << 20)
                        continue
                    match = _MEMBER.match(member.name)
                    if match is None:
                        continue
                    stream = tar.extractfile(member)
                    if stream is None:
                        continue
                    category, filename = match.group(1), match.group(2)
                    destination = yml_dir / category
                    destination.mkdir(parents=True, exist_ok=True)
                    # Copied a megabyte at a time rather than read() into one
                    # buffer, so peak memory is a chunk and not the file. The
                    # ceiling above makes this belt and braces; the shape is
                    # here so a later edit that raises the ceiling does not
                    # silently reintroduce the allocation.
                    with stream, (destination / filename).open("wb") as out:
                        shutil.copyfileobj(stream, out, 1 << 20)
                    written += 1
        except tarfile.TarError as exc:
            raise SourceError(
                f"lolbas: malformed tarball from {_TARBALL}: {exc}"
            ) from exc
    finally:
        archive.unlink(missing_ok=True)

    if written < _MIN_FILES:
        raise SourceError(
            f"lolbas: only {written} entry files matched yml/<category>/<name>.yml "
            f"in {_TARBALL} (expected >= {_MIN_FILES}). The upstream layout has "
            "probably changed; fix the adapter rather than training on a fraction "
            "of the shell register this source was added to fill."
        )

    marker.write_text(
        json.dumps(
            {
                "url": _TARBALL,
                "repo": _REPO,
                "fetched_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "entry_files": written,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return cache_dir


def _as_text(value: Any) -> str:
    """Render a YAML scalar as the string a reader would see.

    ``Created`` parses as a :class:`datetime.date` and ``MitreID`` occasionally
    wants to be an int in a badly quoted file, so ``.strip()`` on the raw value
    is not safe. Booleans are written back in their YAML spelling rather than
    Python's, because the surface form is the thing this corpus collects.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    return str(value).strip()


def _pairs(items: Any, key: str) -> list[str]:
    """Pull ``key`` out of a LOLBAS list-of-single-key-mappings.

    The schema uses this shape everywhere — ``Full_Path`` is
    ``[{Path: ...}, {Path: ...}]``, ``Detection`` is ``[{Sigma: ...}, {IOC: ...}]``
    — so one helper covers paths, links, code samples, aliases and detections.
    Non-mapping members are skipped rather than raising: a malformed line in one
    optional block should not cost the corpus an otherwise good entry, and the
    ``expect_min_docs`` floor is the backstop for anything systemic.
    """
    out: list[str] = []
    if not isinstance(items, list):
        return out
    for item in items:
        if not isinstance(item, dict):
            continue
        value = _as_text(item.get(key))
        if value:
            out.append(value)
    return out


def _tags(command: dict[str, Any]) -> str:
    """Flatten ``Tags: [{Execute: CMD}, ...]`` to ``Execute: CMD, Download: INetCache``.

    These are the closest thing LOLBAS has to a machine-readable statement of
    *what kind of execution* a command gets you — ``Execute: DLL``,
    ``Execute: XSL``, ``Requires: Rename``, ``Download: INetCache`` — and they
    are the detail an operator picks a binary on once the category is decided.
    """
    parts: list[str] = []
    for tag in command.get("Tags") or []:
        if not isinstance(tag, dict):
            continue
        for key, value in tag.items():
            key_text, value_text = _as_text(key), _as_text(value)
            if key_text and value_text:
                parts.append(f"{key_text}: {value_text}")
            elif key_text:
                parts.append(key_text)
    return ", ".join(parts)


def _render_command(index: int, total: int, command: dict[str, Any]) -> list[str]:
    """One abuse, as the lines the model will see. Empty list if unusable.

    The header restates the use case and the ATT&CK id directly above the
    command, and the id appears a second time beside the LOLBAS category below
    it. That repetition is the deliverable: it is what puts ``T1105`` two lines
    from ``certutil.exe -urlcache -f`` in 489 separate places, with a human
    phrase on both sides of it and never a bare identifier on a line of its own.

    The command itself is emitted flush-left on its own lines, unquoted and
    unindented, so ``normalise()`` hands it to the tokenizer byte-for-byte —
    including the newlines inside the five entries whose "command" is really a
    three-line script.
    """
    body = _as_text(command.get("Command"))
    if not body:
        return []

    usecase = _as_text(command.get("Description")) or _as_text(command.get("Usecase"))
    mitre = _as_text(command.get("MitreID"))
    category = _as_text(command.get("Category"))

    heading = f"abuse {index} of {total}" if total > 1 else "abuse"
    label = _as_text(command.get("Usecase")) or category or "documented abuse"
    if mitre:
        # Upstream Usecase values are inconsistently punctuated — roughly a
        # third end in a full stop — and appending the id to one of those
        # produced "...infrastructure., ATT&CK T1219.001". The identifier has to
        # sit cleanly beside the name of what it denotes; a stray period in
        # between is exactly the kind of noise that stops a BPE learning the
        # pairing.
        label = f"{label.rstrip('.').rstrip()}, ATT&CK {mitre}"
    lines = [f"{heading}: {label}", "", body, ""]

    if usecase:
        lines.append(f"what it does: {usecase}")
    if category:
        lines.append(
            f"abuse category: {category} (ATT&CK {mitre})" if mitre
            else f"abuse category: {category}"
        )
    privileges = _as_text(command.get("Privileges"))
    if privileges:
        lines.append(f"privileges needed: {privileges}")
    operating_system = _as_text(command.get("OperatingSystem"))
    if operating_system:
        lines.append(f"works on: {operating_system}")
    tags = _tags(command)
    if tags:
        lines.append(f"tags: {tags}")
    lines.append("")
    return lines


def _render(category: str, entry: dict[str, Any]) -> str:
    """Assemble one catalogue entry into prose, commands and detections.

    Deliberately not a YAML dump. The raw file is a good machine format and a
    poor teaching text: the interesting sentence and the command it explains are
    separated by two keys and an indent level, and half the tokens are ``- ``
    and ``Description:``. What a model should take away is "this signed thing
    normally does X, and here is the line that makes it do Y, and here is what
    fires when it does" — so that is the order the text is written in.

    The opening sentences carry the binary's own name and its own description,
    which keeps them unique per document. That matters more than it looks:
    :mod:`training.corpus.boilerplate` strips any prose line of 40+ characters
    recurring across 25+ documents, so a fixed framing sentence repeated 248
    times would be deleted from the corpus after the fact — correctly, as
    furniture. Framing that names the subject survives because it is not
    furniture.
    """
    name = _as_text(entry.get("Name"))
    description = _as_text(entry.get("Description"))
    what_it_is, term = _kind(category)

    commands = [c for c in (entry.get("Commands") or []) if isinstance(c, dict)]
    rendered: list[list[str]] = []
    for position, command in enumerate(commands, start=1):
        block = _render_command(position, len(commands), command)
        if block:
            rendered.append(block)
    if not rendered:
        return ""

    lede = f"{name} is {what_it_is}."
    if description:
        lede = f"{name} is {what_it_is}. Its documented purpose: {description}"
        if not lede.endswith((".", "!", "?")):
            lede += "."
    count = len(rendered)
    if count == 1:
        second = (
            f"It is a living-off-the-land binary ({term}): the LOLBAS project "
            f"documents one way to abuse {name} from a command line, below, with "
            "the detection that catches it."
        )
    else:
        second = (
            f"It is a living-off-the-land binary ({term}): the LOLBAS project "
            f"documents {count} ways to abuse {name} from a command line, each one "
            "below with the detection that catches it."
        )
    lines = [lede, second, ""]

    aliases = _pairs(entry.get("Aliases"), "Alias")
    if aliases:
        lines += [f"also shipped as: {', '.join(aliases)}", ""]

    paths = _pairs(entry.get("Full_Path"), "Path")
    if paths:
        lines.append("on disk:")
        lines += paths[:_MAX_PATHS]
        if len(paths) > _MAX_PATHS:
            lines.append(
                f"({len(paths) - _MAX_PATHS} further near-identical paths omitted)"
            )
        lines.append("")

    for block in rendered:
        lines += block

    detections: list[str] = []
    for key, phrase in _DETECTION_ORDER:
        for value in _pairs(entry.get("Detection"), key):
            detections.append(f"{phrase}: {value}")
    if detections:
        lines.append("what catches it:")
        lines += detections
        lines.append("")

    samples = _pairs(entry.get("Code_Sample"), "Code")
    if samples:
        lines.append("code sample:")
        lines += samples
        lines.append("")

    resources = _pairs(entry.get("Resources"), "Link")
    if resources:
        lines.append("further reading:")
        lines += resources[:_MAX_RESOURCES]
        lines.append("")

    # Author and date only. The Acknowledgement block is a list of real people's
    # names and social handles: it teaches the model nothing about tradecraft,
    # and assembling a roster of named individuals into training data is not a
    # thing to do casually when the alternative costs one line of provenance.
    # One author has 79 entries, so the corpus-wide boilerplate filter will strip
    # that particular credit line and keep the rest. Correct on both counts, and
    # left alone: see the module docstring.
    author, created = _as_text(entry.get("Author")), _as_text(entry.get("Created"))
    if author and created:
        lines.append(f"catalogued for LOLBAS by {author}, {created}.")
    elif author:
        lines.append(f"catalogued for LOLBAS by {author}.")

    return "\n".join(lines)


def _documents(path: Path) -> Iterator[Document]:
    """Yield one :class:`Document` per catalogue entry, in a stable order.

    Accepts either the cache directory :func:`_fetch` returns or the ``yml/``
    tree inside it, so a caller that passes the fetch result's child still works.

    A YAML parse failure raises rather than being skipped, with the filename in
    the message. ``expect_min_docs`` exists to catch a source that has quietly
    stopped working; catching it at the file that broke is worth more than a
    build that ships thirty fewer binaries and says nothing.
    """
    import yaml  # local import: PyYAML is only needed when this source is built

    root = path / "yml" if (path / "yml").is_dir() else path
    files = sorted(root.glob("*/*.yml"))
    if not files:
        raise SourceError(f"lolbas: no yml/<category>/*.yml under {path}")

    for file in files:
        try:
            entry = yaml.safe_load(file.read_text(encoding="utf-8"))
        except (yaml.YAMLError, UnicodeDecodeError) as exc:
            raise SourceError(f"lolbas: {file.name} failed to parse: {exc}") from exc
        if not isinstance(entry, dict):
            raise SourceError(f"lolbas: {file.name} is not a mapping")
        if not isinstance(entry.get("Commands"), list):
            raise SourceError(f"lolbas: {file.name} has no Commands list")

        category = file.parent.name
        text = normalise(_render(category, entry))
        if len(text) < _MIN_CHARS:
            continue
        yield Document(
            text=text,
            source="lolbas",
            register=Register.SHELL,
            side=Side.RED,
            # Repo-relative and readable in a build report: "OSBinaries/Certutil.yml".
            ident=f"{category}/{file.name}",
        )


SPEC = SourceSpec(
    name="lolbas",
    license=(
        "GPL-3.0-only (LOLBAS Project; LICENSE and NOTICE.md are copied into the "
        "cache). The MitreID fields are MITRE ATT&CK, reproduced under MITRE's "
        "terms of use: \"(c) 2021 The MITRE Corporation. This work is reproduced "
        "and distributed with the permission of The MITRE Corporation.\""
    ),
    url=_REPO,
    register=Register.SHELL,
    side=Side.RED,
    fetch=_fetch,
    documents=_documents,
    #: 248 entries on master at fetch time (137 OSBinaries, 83 OtherMSBinaries,
    #: 18 OSLibraries, 11 OSScripts, 3 HonorableMentions). The floor sits well
    #: below that so an entry being retired is quiet, while a parser that starts
    #: dropping whole categories trips it at once.
    expect_min_docs=200,
    notes=(
        "One document per catalogued binary: what it legitimately is, where it "
        "lives on disk, then every documented abuse as a flush-left command with "
        "its use case, ATT&CK id, LOLBAS category, required privileges, affected "
        "Windows versions and execution tags, then the Sigma/Elastic/Splunk/block "
        "rules and free-text IOCs that detect it. Per binary rather than per "
        "command because the MitreID is already nested per command upstream, and "
        "splitting would duplicate the per-binary Detection block 489 times. "
        "Only yml/ is read: Archive-Old-Version/ holds superseded copies of live "
        "entries that whole-document dedup cannot recognise as duplicates. "
        "Commands keep their {PATH_ABSOLUTE:.dll} operator placeholders and their "
        "embedded newlines; nothing about them is reformatted."
    ),
)
