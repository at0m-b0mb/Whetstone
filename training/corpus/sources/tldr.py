"""tldr-pages — concentrated SHELL register.

The corpus's most starved register against its target: SHELL sits at 2.7% and
wants 28%. The first tiny training run made that visible as behaviour rather
than a number — prompted with ``Get-Process`` the model still emitted CVE
records, because advisory text outweighed shell text twelve to one.

tldr-pages is close to an ideal repair. Every page is a command followed by
worked invocations with the arguments filled in::

    # ss
    > Utility to investigate sockets
    - Show all TCP sockets with service name:
      ss --tcp --all --processes

That is the exact shape the model must learn to produce: a stated intent, then
the concrete command that satisfies it. Man pages give the same commands
embedded in paragraphs of prose; tldr gives intent-to-invocation pairs at a
density nothing else in the corpus approaches, and the mapping from "what do I
want" to "what do I type" is precisely what an agent choosing parameters needs.

It also spans all three target platforms — ``pages/linux``, ``pages/osx``,
``pages/windows`` — so one source strengthens SHELL for every adapter at once.

**Placeholder syntax is kept deliberately.** tldr writes variable arguments as
``{{path/to/file}}``. It would be easy to strip the braces or substitute
something concrete, and both would be wrong: the braces mark exactly which span
of a command is a parameter, which is the distinction the model has to learn in
order to fill one. Removing them would flatten a labelled example into an
unlabelled one.
"""

from __future__ import annotations

import io
import os
import tarfile
from pathlib import Path
from typing import Iterator

from ..net import download
from ..source import Document, Register, Side, SourceError, SourceSpec, normalise

#: The project publishes a built archive of every page per release. Taking the
#: tarball rather than walking the git tree keeps this to one request.
_URL = "https://github.com/tldr-pages/tldr/archive/refs/heads/main.tar.gz"
_ARCHIVE = "tldr-main.tar.gz"
_MARKER = ".tldr-complete"

#: English only. The repository carries the same pages translated into twenty-odd
#: languages under ``pages.<lang>/``; including them would fill a register meant
#: for shell syntax with parallel translations of the same prose, and the
#: commands inside them are byte-identical duplicates the fingerprint dedup would
#: drop anyway — after they had already skewed the corpus statistics.
_PAGES_ROOT = "pages"

_MIN_CHARS = 120


def _fetch(cache_dir: Path) -> Path:
    """Download and extract the page tree. Idempotent and network-free when warm."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    marker = cache_dir / _MARKER
    if marker.is_file() and any(cache_dir.glob("*/**/*.md")):
        return cache_dir

    archive = cache_dir / _ARCHIVE
    try:
        download(_URL, archive, timeout=300)
        with tarfile.open(archive, "r:gz") as tar:
            for member in tar.getmembers():
                if not member.isfile() or not member.name.endswith(".md"):
                    continue
                parts = Path(member.name).parts[1:]        # drop the tldr-main/ root
                if not parts or parts[0] != _PAGES_ROOT:
                    continue
                # Refuse absolute paths and any traversal: a crafted archive must
                # not be able to write outside the cache it was handed.
                if any(p in ("..", "") or os.path.isabs(p) for p in parts):
                    continue
                target = cache_dir.joinpath(*parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                extracted = tar.extractfile(member)
                if extracted is None:
                    continue
                target.write_bytes(extracted.read())
        marker.write_text("ok", encoding="utf-8")
    except Exception as exc:
        raise SourceError(f"tldr: fetch failed: {type(exc).__name__}: {exc}") from None
    finally:
        # One finally over both stages, so an interrupted extraction cannot leave
        # the archive behind for a later run to trip over.
        archive.unlink(missing_ok=True)

    return cache_dir


def parse_page(text: str, *, platform: str, name: str) -> str | None:
    """Turn one tldr markdown page into a flat intent-to-command document.

    Kept a pure function so it is testable without the network. The rendering
    puts the platform on its own labelled line because the same command often
    differs between macOS and Linux, and the model must be able to condition on
    which machine it is standing on — that is the whole reason the adapter layer
    exists, and the corpus should teach the distinction rather than blur it.
    """
    title = ""
    summary: list[str] = []
    pairs: list[tuple[str, str]] = []
    pending = ""

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("# "):
            title = line[2:].strip()
        elif line.startswith("> "):
            summary.append(line[2:].strip())
        elif line.startswith("- "):
            pending = line[2:].strip().rstrip(":")
        elif line.startswith("`") and line.endswith("`") and len(line) > 2:
            command = line[1:-1]
            if pending:
                pairs.append((pending, command))
                pending = ""
            else:
                pairs.append(("", command))

    if not pairs:
        return None

    lines = [f"{title or name} ({platform})", ""]
    if summary:
        lines += [" ".join(summary), ""]
    lines.append(f"Platform: {platform}")
    lines.append(f"Command: {title or name}")
    lines.append("")
    for intent, command in pairs:
        if intent:
            lines.append(f"{intent}:")
        lines.append(f"    {command}")
        lines.append("")
    return normalise("\n".join(lines))


def _documents(path: Path) -> Iterator[Document]:
    root = path / _PAGES_ROOT
    if not root.is_dir():
        raise SourceError(f"tldr: no {_PAGES_ROOT}/ under {path}; re-fetch")

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames
                             if not Path(dirpath, d).is_symlink())
        platform = Path(dirpath).name
        for filename in sorted(filenames):
            if not filename.endswith(".md"):
                continue
            file = Path(dirpath, filename)
            if file.is_symlink():
                continue
            try:
                raw = file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            text = parse_page(raw, platform=platform, name=file.stem)
            if not text or len(text) < _MIN_CHARS:
                continue
            yield Document(text=text, source="tldr", register=Register.SHELL,
                           side=Side.NEUTRAL, ident=f"{platform}/{file.stem}")


SPEC = SourceSpec(
    name="tldr",
    license="MIT (tldr-pages project; pages are CC-BY-4.0 per the repository's LICENSE.md)",
    url="https://github.com/tldr-pages/tldr",
    register=Register.SHELL,
    side=Side.NEUTRAL,
    fetch=_fetch,
    documents=_documents,
    expect_min_docs=2000,
    notes=("Intent-to-invocation pairs across linux/osx/windows/common. The "
           "densest mapping in the corpus from 'what do I want' to 'what do I "
           "type', which is the decision an agent filling verb parameters makes. "
           "Placeholder braces {{like/this}} are preserved: they mark which span "
           "of a command is a parameter."),
)
