"""Vulhub — reproducible vulnerable environments, one CVE at a time. ADVERSARY/RED.

The corpus knows a great deal *about* vulnerabilities and very little about
exploiting them. nvd is 35,539 documents and ghsa 14,509, and between them they
say which product was vulnerable, in which versions, with what CVSS vector. None
of them says what the request looked like.

Vulhub closes exactly that. Every directory is one CVE in one product, with the
affected version range, the upstream advisory, a compose file that stands the
vulnerable service up, and an **Exploitation** section carrying the actual
request that triggers it::

    # S2-045 Remote Code Execution Vulnerability (CVE-2017-5638)
    Affected Version: Struts 2.3.5 - 2.3.31, Struts 2.5 - 2.5.10
    ## Exploitation
    Verify the vulnerability by following request: ...

155 applications, several CVEs each — struts2 alone carries twenty. Paired
against the advisory sources already here, this is the other half of a CVE: nvd
says *what* was broken and this says *how* it breaks.

**Licence: MIT**, read from the repository's own ``LICENSE`` at fetch time and
copied into the cache beside the text it covers. Verified rather than assumed,
which in this corner of the ecosystem is not a formality: of seven candidate
vulnerable-application repositories checked while choosing this one, two
(``payloadbox/xss-payload-list`` and ``swisskyrepo/InternalAllTheThings``)
carry no licence at all, one returns NOASSERTION, and two are GPL. Vulhub is the
one that is both permissive and maintained.

**Only the English READMEs.** Each directory ships ``README.md`` and
``README.zh-cn.md`` with the same content in two languages. Taking both would
put every exploitation walkthrough into the corpus twice, in a corpus where
duplicated text is the failure this project has already paid for twice — 114
radare2 pages under two source names, and the RFC cap keeping a prefix. The
Chinese versions are dropped by suffix, which is exact, rather than by detecting
script, which is not.

**What is not taken.** The compose files, Dockerfiles and application source
under each directory are infrastructure for standing the target up, not text
that teaches anything: a three-line ``docker-compose.yml`` naming an image tag
is not a lesson about the vulnerability it exposes. The README is where the
knowledge is, and it references the version pin anyway.
"""

from __future__ import annotations

import json
import re
import shutil
import tarfile
from pathlib import Path
from typing import Iterator

from ..net import NetworkError, download
from ..source import Document, Register, Side, SourceError, SourceSpec

_REPO = "vulhub/vulhub"
_REF = "master"
_ARCHIVE = f"https://codeload.github.com/{_REPO}/tar.gz/refs/heads/{_REF}"

#: The repository is ~182 MB of images, compose files and application source;
#: the READMEs are a small fraction of it. The ceiling is generous because the
#: tarball is what it is, and a limit that trips on ordinary growth is a build
#: that fails for no reason at 3am.
_MAX_ARCHIVE_BYTES = 512 * 1024 * 1024

_MARKER = ".fetched.json"
_LICENSE_FILE = "LICENSE"

#: ``README.md`` only. ``README.zh-cn.md`` is the same walkthrough in Chinese and
#: would double every document; other suffixes appear occasionally for the same
#: reason.
_README = "README.md"

#: A README shorter than this is a placeholder — a few directories hold a title
#: and a link to an upstream advisory and nothing else.
_MIN_CHARS = 400

#: ``CVE-2017-5638`` anywhere in the title or body. Recorded in the header so a
#: document about an exploitation technique can be tied to the advisory sources
#: that describe the same identifier.
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")

#: A README with no exploitation section is a description of a product, not of
#: an attack. Matched case-insensitively against the heading text because
#: capitalisation drifts across 155 directories maintained by many hands.
#:
#: Matched on STEMS, not whole words, and that is the whole of this pattern's
#: history. It first read ``reproduce`` and dropped 137 of 341 READMEs as having
#: no reproduction section — because 126 of them head that section
#: "Vulnerability **Reproduction**", and ``reproduce`` does not occur inside
#: ``reproduction``. The expected-document floor caught it; a floor set to
#: whatever the first run happened to produce would have made the regression
#: permanent and invisible.
_EXPLOIT_HEADING = re.compile(
    r"^#{1,4}\s*(?:\w+\s+)?(exploit|poc|proof\s+of\s+concept|reproduc|"
    r"verif|attack|exp\b)", re.I | re.M)


def _fetch(cache_dir: Path) -> Path:
    """Download the repository and keep the English READMEs and the LICENCE."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    home = cache_dir / "vulhub"
    if (home / _MARKER).is_file():
        return home

    archive = cache_dir / ".vulhub.tar.gz.part"
    staging = cache_dir / ".vulhub.staging"
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True)
    try:
        try:
            download(_ARCHIVE, archive, timeout=900,
                     max_bytes=_MAX_ARCHIVE_BYTES)
        except NetworkError as exc:
            raise SourceError(f"vulhub: cannot fetch {_ARCHIVE}: {exc}") from None

        kept = 0
        licence_seen = False
        with tarfile.open(archive, "r:gz") as tf:
            for member in tf:
                if not member.isfile():
                    continue
                # codeload wraps everything in one root directory whose name
                # carries the ref; drop it so the cache layout does not move
                # when the branch is renamed.
                parts = Path(member.name).parts[1:]
                if not parts:
                    continue
                relative = Path(*parts)
                is_licence = relative.as_posix() == _LICENSE_FILE
                if not is_licence and relative.name != _README:
                    continue
                target = (staging / relative).resolve()
                if not str(target).startswith(str(staging.resolve())):
                    raise SourceError(
                        f"vulhub: archive member escapes staging: {member.name!r}")
                extracted = tf.extractfile(member)
                if extracted is None:
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(extracted.read())
                if is_licence:
                    licence_seen = True
                else:
                    kept += 1
    finally:
        archive.unlink(missing_ok=True)

    if not licence_seen:
        # The declaration below says MIT. If the file that proves it is gone,
        # the declaration is a claim rather than a reading, and this project
        # does not train on text whose terms it cannot point at.
        shutil.rmtree(staging, ignore_errors=True)
        raise SourceError(
            "vulhub: no LICENSE in the archive — the MIT declaration cannot be "
            "verified against the tree it covers, so nothing was cached")
    if kept < 200:
        shutil.rmtree(staging, ignore_errors=True)
        raise SourceError(
            f"vulhub: only {kept} README.md found; expected several hundred — "
            f"the repository layout has probably changed")

    shutil.rmtree(home, ignore_errors=True)
    staging.rename(home)
    (home / _MARKER).write_text(json.dumps(
        {"repo": _REPO, "ref": _REF, "readmes": kept, "license": "MIT"}, indent=1))
    return home


def _title(text: str, fallback: str) -> str:
    for line in text.split("\n"):
        if line.startswith("# "):
            return line[2:].strip()
    return fallback


def _documents(path: Path) -> Iterator[Document]:
    home = path if (path / _MARKER).is_file() else path / "vulhub"
    files = sorted(home.rglob(_README))
    held = {"short": 0, "no-exploit": 0}
    emitted = 0
    for file in files:
        relative = file.relative_to(home)
        if len(relative.parts) < 2:
            # The repository root README is a table of contents over the rest.
            continue
        try:
            text = file.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            continue
        if len(text) < _MIN_CHARS:
            held["short"] += 1
            continue
        if not _EXPLOIT_HEADING.search(text):
            # Kept out deliberately: without a reproduction section this is a
            # description of a product and a version number, which the advisory
            # sources already carry in far greater depth.
            held["no-exploit"] += 1
            continue

        application = relative.parts[0]
        entry = "/".join(relative.parts[1:-1]) or relative.parts[0]
        cves = list(dict.fromkeys(_CVE.findall(text)))
        header = [
            f"Vulnerable environment: {_title(text, entry)}",
            f"Application: {application}",
            f"Vulhub entry: {relative.parent.as_posix()}",
        ]
        if cves:
            # The join with the advisory half of the corpus. nvd and ghsa hold
            # these same identifiers; this is what exploiting one looks like.
            header.append(f"CVE: {', '.join(cves)}")
        header.append(
            f"Reference: https://github.com/{_REPO}/tree/{_REF}/"
            f"{relative.parent.as_posix()}")
        header.append("License: MIT, Vulhub contributors")

        yield Document(text="\n".join(header) + "\n\n" + text,
                       source="vulhub", register=Register.ADVERSARY,
                       side=Side.RED, ident=relative.parent.as_posix())
        emitted += 1

    parts = ", ".join(f"{n} {k}" for k, n in held.items() if n)
    print(f"   vulhub: {emitted} environments rendered from {len(files)} "
          f"README.md" + (f"; held back {parts}" if parts else ""))


SPEC = SourceSpec(
    name="vulhub",
    license=(
        "MIT — vulhub/vulhub, read from the repository's own LICENSE inside the "
        "fetched archive rather than from a badge, and copied into the cache "
        "beside the text it covers. The fetch refuses to cache anything if that "
        "file is absent, because the declaration would then be a claim rather "
        "than a reading. English README.md only; the README.zh-cn.md beside "
        "each one is the same walkthrough translated and would duplicate every "
        "document."
    ),
    url=f"https://github.com/{_REPO}",
    register=Register.ADVERSARY,
    side=Side.RED,
    fetch=_fetch,
    documents=_documents,
    #: 155 application directories, most holding several CVE entries, minus the
    #: ones with no reproduction section. The floor catches the regression that
    #: matters — the README naming convention changing, or the exploitation
    #: heading being reworded across the tree, either of which takes this to
    #: near zero rather than to a smaller number.
    expect_min_docs=250,
    #: One ~180 MB tarball, streamed and filtered member by member.
    timeout=1_800,
    notes=(
        "One document per vulnerable environment: affected version range, "
        "upstream advisory links, setup and the actual exploitation request. "
        "The other half of a CVE — nvd and ghsa say what was broken, this says "
        "how it breaks — and the CVE identifier is carried in the header so "
        "the two can be read together. Entries with no reproduction section "
        "are dropped rather than emitted as product descriptions."
    ),
)
