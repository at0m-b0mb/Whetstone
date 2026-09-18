"""DISABLED — InternalAllTheThings carries no licence. See the note below.

This module is named with a leading underscore on purpose: source discovery in
:mod:`training.corpus.build` skips those, so this adapter is present, complete
and working, and contributes nothing to the corpus.

**Why.** The repository was assumed to inherit PayloadsAllTheThings' MIT licence
because it has the same author and holds content moved out of that repo. It does
not. Checked rather than assumed: there is no ``LICENSE`` on ``main``, none on
``gh-pages``, not one commit in the entire history touching a path named
LICENSE, no badge, no ``copyright`` key in ``mkdocs.yml``, and GitHub's own
licence detection returns null. A licence does not travel between repositories
because they share an author, and an unlicensed public repository is
all-rights-reserved by default.

:mod:`training.corpus.source` refuses a blank licence deliberately — training on
text of unknown provenance is how a project becomes unpublishable — so honouring
that rule here matters more than the 1.19 MB this would have added, even though
it is 1.19 MB of exactly the post-exploitation material the corpus is thinnest
in. The adapter is kept rather than deleted so that nobody repeats the work and
rediscovers the same dead end, and so that it can be enabled by renaming this
file the moment upstream publishes terms.

The original module docstring follows.

InternalAllTheThings — the half of the engagement after the shell. ADVERSARY/RED.

This adapter exists because a measurement said the corpus had a hole in it, not
because the repository looked useful. Its sibling
:mod:`~training.corpus.sources.payloads` was written against
``swisskyrepo/PayloadsAllTheThings`` and found that **all 33 pages under
``Methodology and Resources/`` upstream are now redirect stubs** — 91 KB of bare
markdown links with not one code fence between them — because their content was
moved here. Those 33 pages were Windows Privilege Escalation, Linux Privilege
Escalation, Active Directory Attack, Mimikatz, Persistence, Pivoting and the
Reverse Shell Cheatsheet: precisely, and almost exclusively, the pages that map
onto this project's ``postex.*`` verbs.

So without this adapter the post-exploitation register is not thin, it is
*empty*. :mod:`whetstone.verbs` declares ``postex.credential_dump``,
``postex.persistence_install``, ``postex.privilege_escalate``,
``postex.lateral_move`` and ``postex.exfil_probe``, and every one of them pairs
to a ``detect.*`` verb — which is the whole argument of the project, that the
red half exists to prove whether the blue half noticed. A model that cannot
reason about what happens after initial access is missing the half of the
engagement where detection actually matters most: nobody's SIEM misses the
exploit and then catches the DCSync.

**The directory path is the deliverable here, and for a different reason than in
the sibling.** ``payloads.py`` restates its technique family on every document
because that repository's H1 headings are frequently useless on their own
(``# Git``, ``# .htaccess``). This repository's H1s are good — measured, 167 of
167 pages have one and they read ``# Windows - Privilege Escalation``,
``# Azure Services - Office 365``, ``# MSSQL - Linked Database``. What they do
*not* say is the engagement phase, and the path does:
``redteam/access/clickfix.md`` is titled ``# ClickFix`` and
``redteam/evasion/opsec-fails.md`` is titled ``# OPSEC``, neither of which tells
a reader whether the page is about getting in, staying in, or not being seen.
Only 64 of the 167 pages have an H1 that names its own directory area at all.
That path — ``access``, ``escalation``, ``evasion``, ``persistence``,
``pivoting`` — is the ``postex.*`` taxonomy written in someone else's words, so
every document opens with it.

**What this source is made of, measured rather than assumed.** 169 markdown
files under ``docs/``, 1.31 MB, of which **49.2% of all characters sit inside
1,747 fenced code blocks** — double the 24.7% the sibling measured, and the
densest source of executable text in this corpus. The info strings say what
register it really is: ``ps1`` (854 blocks) and ``powershell`` (644) together
account for 86% of them, then ``bash`` (74), ``sql`` (34), ``python`` (28),
``java`` (12), ``vb`` (12), ``yaml`` (11).

**It is nevertheless declared ADVERSARY, not SHELL, and that is deliberate.**
Half this text is PowerShell by surface form, but a
:class:`~training.corpus.source.Register` is a claim about what the document
*teaches*, and what these pages teach is a sequence: this Kerberos ticket, which
implies that delegation is unconstrained, which is why the next command asks the
DC to print a ticket for a user it should not. The commands are the evidence,
the ordering is the content. Declaring it SHELL would also make the build's
accounting wrong in a way nobody would notice: ``build.py`` attributes register
and side per :class:`~training.corpus.source.SourceSpec`, ADVERSARY is the
scarcest register and the binding constraint on the balancer, and moving 1.3 MB
out of it would silently force the balancer to throw away more of everything
else. Consistency with the sibling matters more than a surface-form count.

**The indented-fence trap, worse here than in the sibling.** 830 of the 1,747
opening fences — 47.5% — are indented under a list bullet rather than at column
zero. An anchored ``^```` regex would miss nearly half the code in this source,
and, far worse, every downstream rule that asks "is this line inside a payload?"
would then answer wrongly: the split points would land inside scripts and the
redirect-index measurement would read a page of PowerShell as a page of links.
:data:`_FENCE` therefore tolerates leading whitespace. The indentation is then
part of the block's own shape, and survives because
:func:`~training.corpus.source.normalise` deliberately does not collapse runs of
spaces. There is a second reason to get the fence map exactly right here:
**489 lines inside fenced blocks look like ATX headings** — ``# Create the
service``, ``## Step 2`` written as shell comments — and any one of them
mistaken for a real heading becomes a split point in the middle of a script.

**One rule this source needed and the sibling did not: machine-encoded binary is
not writing.** ``redteam/evasion/windows-amsi-bypass.md`` is 170 KB, and
**79.9% of it is five lines**. They are a DLL written out as decimal integers —
``$AmsiX64 = "77 90 144 0 3 0 0 0 4 0 0 0 255 255 0 0 184 ..."``, the MZ header
of a PE file, 29,465 characters on a single line — and two of the five are
byte-for-byte duplicates of the other two, because the page repeats the
``$AmsiX86``/``$AmsiX64`` pair in two sections. At roughly three characters per
token that is about forty complete 1024-token training windows containing
nothing but digits, out of a source of 1.31 MB. It is the same objection
``payloads.py`` raised against shipping ``dotdotpwn.txt``: mechanically
generated text at volume is the textbook thing a small model memorises, and the
surrounding prose already teaches the technique the blob only instantiates.

The separation is not a judgement call. Every in-fence line was measured for
length and for the fraction of its characters that are digits, spaces or
commas. The five blobs score 0.998–1.000 over 20,517–29,465 characters. The next
longest in-fence lines are a 7,664-character inline C# type definition at 0.044,
a 2,159-character Python reverse-shell one-liner at 0.146, and a
1,124-character ``docker run`` at 0.152 — all of them real content. The gap runs
from 0.152 to 0.998 and from 2,159 characters to 20,517, so
:data:`_BLOB_MIN_CHARS` and :data:`_BLOB_DIGIT_RATIO` both sit inside a genuine
void rather than on top of a distribution, and **both** conditions are required
so that neither a long real command nor a short byte array can be caught. The
blob line is replaced by a marker stating its size rather than deleted, because
a script that silently lost a line looks complete and is not; the rest of the
enclosing block, and the heading that says what it does, are untouched. Five
lines, 128,583 characters, 9.8% of the source.

**Long pages are split at heading boundaries, never truncated**, exactly as in
the sibling and for the same reason: the model trains at ``max_seq_len`` 1024
(see :mod:`training.config`) and :func:`training.data.tokenize_corpus`
concatenates documents and samples fixed-length windows out of the stream, so a
75 KB page would spend nineteen of its twenty windows with no statement of what
platform the commands target. A page over :data:`_SPLIT_ABOVE` is cut at its own
headings, descending a level into any section still too large, packed greedily up
to :data:`_PART_TARGET`, and every part reopens with the area, the page title and
the heading trail of the sections it holds. Split points are computed only
outside fenced blocks. A section with no deeper headings to cut at is emitted
whole and oversized, because overshooting a target is a cost and dividing a
command listing on a character count is a corruption, and the two are not
comparable. Three of the 271 documents exceed 8 KB for that reason. The largest
is 18.8 KB: ``windows-amsi-bypass.md``'s ``## Nishang all in one``, which is one
continuous 389-line PowerShell script under a page that uses no heading deeper
than ``##``, so there is nothing to cut it at and it is not cut.

**Redirect and index pages are dropped by measurement, never by name.** Upstream
reorganises — this repository *is* the reorganisation — and a hardcoded filename
list rots the first time a page moves. A page is dropped when it has no fenced
block at all *and* at least :data:`_STUB_LINK_RATIO` of its non-blank prose lines
are a bullet and one bare markdown link. Measured over all 169 pages the two that
qualify are ``active-directory/ad-adcs-esc.md`` at 0.94 (an index over the
fifteen ESC pages, all of which this adapter yields in full) and
``devops/README.md`` at 0.54; the next fence-free page scores 0.12 and is real
writing. Pages that *do* have fences reach 0.67 on the same ratio and are kept,
which is why the fence test comes first: a cheatsheet is allowed to be full of
links as long as it is also full of commands.

**Markup removal is one rule, and the reason to keep it to one rule is stronger
here than in the sibling.** Eleven image references exist in the whole
repository and all eleven sit outside fenced blocks (counted, not assumed);
those are removed and nothing else is. Outside fences there are 107
angle-bracket tokens, and the tag names are ``<Domain>``, ``<username>``,
``<password>``, ``<hash>``, ``<GPOName>``, ``<RefObjId>``, ``<token>``,
``<RID>``, ``<SKI>``. They are not HTML: they are the placeholder metavariables
this author writes inside inline code spans to show which part of a command you
substitute. A pass that "cleaned HTML" would delete the operand from a hundred
commands and leave them looking valid.

**The control-byte caveat the sibling carries does not apply here.**
:func:`~training.corpus.source.normalise` drops control bytes that are neither
tab nor newline, which damaged three fenced blocks in PayloadsAllTheThings where
form feeds inside ``<svg\\x0conload=...>`` *were* the filter-bypass technique.
This repository was checked for the same thing and contains **zero** control
bytes, inside fences or out, so nothing here is altered by that rule. Every one
of the 1,747 fenced blocks was then rendered through ``normalise()`` and searched
for in the built documents; all 1,747 are present, and the five elided blob lines
are the entire delta between this source and the corpus.

**Licence: there is none, and that is a finding, not an oversight in this
adapter.** The brief for this module said to verify the licence from the
repository's own ``LICENSE`` file rather than from a README badge, on the
assumption that it carried PayloadsAllTheThings' MIT. Verified, and the
assumption is false: there is no ``LICENSE`` file in the ``main`` tarball, no
``LICENSE`` in the only other branch (``gh-pages``), **zero commits in the
repository's entire history touching a path named LICENSE**, no licence badge,
no ``copyright`` key in ``mkdocs.yml``, and GitHub's own licence detection
returns ``null``. MIT covers the sibling repository; a licence does not travel
between repositories because they share an author.

What the repository does say is reproduced verbatim in :data:`_LICENSE` and
written into the cache beside the pages as :data:`_TERMS_FILE`, so the claim
sits next to the text it covers exactly as the sibling's copied MIT does: the
README's "Content in this repository is provided as is, for learning purpose",
and ``docs/DISCLAIMER.md``. Neither is a grant of rights. Under the Berne
Convention an unlicensed public repository is all-rights-reserved by default,
and :mod:`training.corpus.source` is explicit that "training on scraped text of
unknown provenance is how a project becomes unpublishable". This module states
the position accurately and loudly rather than laundering it into an SPDX
identifier; whether to ship the source is a decision for whoever runs the build,
and :func:`_fetch` prints the warning on every fetch so that decision is taken
deliberately. If a ``LICENSE`` ever appears upstream it is copied into the cache
and the build log says, in as many words, that :data:`_LICENSE` is now stale.

Upstream: https://github.com/swisskyrepo/InternalAllTheThings
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tarfile
import time
from pathlib import Path
from typing import Iterator

from ..net import NetworkError, download
from ..source import Document, Register, Side, SourceError, SourceSpec, normalise

__all__ = ["SPEC"]

_REPO = "swisskyrepo/InternalAllTheThings"

#: ``main``, not ``master``. The sibling repository still uses ``master`` and
#: this one does not, which is exactly the kind of difference that turns into a
#: silent 404 when an adapter is copied. Checked against the GitHub API rather
#: than guessed: the repository has two branches, ``main`` and ``gh-pages``, and
#: ``main`` is the default. ``gh-pages`` is the rendered mkdocs site — the same
#: text after a static site generator has turned every code fence into
#: ``<div class="highlight"><pre>`` and every heading into an anchor, which is
#: strictly worse input than the markdown it was built from.
_REF = "main"

#: A codeload tarball rather than ``git clone --depth 1``, for the reason the
#: sibling gives at length: no history and no ``.git`` directory for a stray
#: ``git pull`` to mutate under a build that is meant to be reproducible, no
#: dependency on a git binary, and — the part that actually matters — the
#: transfer goes through :func:`training.corpus.net.download` and therefore
#: through this package's one verifying TLS context. A subprocess clone would
#: use git's own trust store and quietly add a second, unaudited trust path to a
#: project whose whole premise is that it knows where its training data came
#: from. 1.7 MB, one request.
_TARBALL_URL = f"https://codeload.github.com/{_REPO}/tar.gz/refs/heads/{_REF}"

#: Everything under this directory upstream is the content; everything outside
#: it is the mkdocs machinery that renders it (``mkdocs.yml``, ``overrides/``,
#: ``assets/``, ``.github/``). Naming the one directory is both simpler and more
#: robust than the sibling's skip-list, because a new area directory is picked up
#: automatically while a new piece of site machinery is ignored automatically.
_DOCS_DIR = "docs"

#: Where the pages land inside the source's cache directory, so the area
#: directories do not scatter across the cache root next to the marker and the
#: terms file.
_PAGES_DIR = "pages"

#: The repository publishes no licence, so what gets copied into the cache is
#: the text that does exist: the README paragraph and ``docs/DISCLAIMER.md``.
#: See the module docstring.
_TERMS_FILE = "TERMS.md"
_DISCLAIMER = "DISCLAIMER.md"

#: Checked on every fetch. It does not exist today and never has — if it ever
#: does, it is copied into the cache and the build log says :data:`_LICENSE` is
#: stale, because a licence statement that has drifted from its source is worse
#: than no statement at all: it looks verified.
_LICENSE_FILE = "LICENSE"

#: Written last, after the staging tree has been swapped into place, so its
#: presence means extraction finished. An interrupted fetch re-downloads instead
#: of leaving a half tree that a later run mistakes for a warm cache — the one
#: failure that is silent everywhere, because a short corpus still trains.
_MARKER = ".internal-complete.json"

#: 169 markdown pages upstream, 167 of them inside an area directory under
#: ``docs/`` and therefore extracted (the other two are ``docs/README.md`` and
#: ``docs/DISCLAIMER.md``). A floor well below that makes an upstream
#: reorganisation fail at fetch time, where the diagnostic can name the URL,
#: rather than surface later as a thin line in a build report.
_MIN_EXTRACTED = 120

#: Below any real page. The smallest upstream is 470 characters
#: (``devops/cicd-buildkite.md``: three commands for dumping a CI system's
#: secrets), so this floor sits under it with room to spare. The sibling uses
#: 400; this is lower on purpose, because 470 is uncomfortably close to 400 and
#: the failure mode of a floor set too high is a page silently vanishing, which
#: is the failure mode this package exists to prevent.
_MIN_CHARS = 300

#: Split a page above this size; leave anything at or below it whole. Roughly
#: two to three 1024-token training windows of text this dense. Keeping a page
#: whole is always preferable — an attack path runs across sections and the
#: ordering is the content — so the threshold sits where the flow is already
#: being cut by the training window anyway. 34 of the 169 pages exceed it.
_SPLIT_ABOVE = 8_000

#: Target size for one part of a split page, and the size above which a section
#: is re-cut at a deeper heading level. Sections are packed greedily up to this,
#: and a section with no deeper heading to cut at is never divided, so a part
#: overshoots rather than cutting a command listing in half. The largest section
#: in this source that cannot be cut further is 13.6 KB
#: (``redteam/escalation/windows-privilege-escalation.md``, ``## EoP -
#: Impersonation Privileges``), so the overshoot is bounded in practice as well
#: as in principle.
_PART_TARGET = 6_000

#: The smallest a part may be. Greedy packing strands fragments at both ends
#: without this — a page whose H1 and summary are followed by one large section
#: would otherwise open with a 300-character part one, which is a fragment
#: wearing a header with the header a third of it.
_MIN_PART = 1_200

#: Fraction of non-blank prose lines that must be bullet-plus-single-link before
#: a fence-free page is treated as an index rather than a technique page.
#: Measured over all 169 pages: the two indexes score 0.94 and 0.54, the next
#: fence-free page scores 0.12. Pages that have fences are never tested, and
#: reach 0.67 on this ratio. See the module docstring.
_STUB_LINK_RATIO = 0.40

#: A line inside a fenced block that is at least this long **and** at least
#: :data:`_BLOB_DIGIT_RATIO` digits-and-separators is a binary literal rather
#: than a command. Both thresholds sit inside measured voids: the longest real
#: in-fence line is 7,664 characters at ratio 0.044, the longest real one-liner
#: 2,159 at 0.146, and the five blobs are 20,517-29,465 at 0.998-1.000.
#: Requiring both conditions is what makes the rule safe — a long real command
#: fails the ratio and a short byte array fails the length.
_BLOB_MIN_CHARS = 3_000
_BLOB_DIGIT_RATIO = 0.90

#: An opening or closing code fence, **allowing leading whitespace**. 830 of the
#: 1,747 opening fences in this source are indented under a list bullet, so an
#: anchored ``^```` regex would see barely half of them — and every rule below
#: that asks "is this line inside a command?" would then answer wrongly for the
#: other half.
_FENCE = re.compile(r"^[ \t]*(`{3,}|~{3,})")

#: An ATX heading at column zero. Requiring column zero is belt and braces on
#: top of the fence map, which already excludes the 489 shell-comment lines in
#: this source that begin with ``#``. Setext headings (``Title`` over ``=====``)
#: would be invisible to this; checked across all 169 files, there are none.
_HEADING = re.compile(r"^(#{1,6})[ \t]+(.+?)[ \t]*$")

#: A list item whose entire content is one markdown link — the shape an index
#: page is made of. A tools entry (``* [Rubeus](url) - C# toolset``) has
#: trailing prose and does not match, which is what separates a page of links
#: from a page with links in it.
_LINK_ONLY = re.compile(r"^[ \t]*(?:[-*+]|\d+\.)[ \t]+\[[^\]\n]*\]\([^)\n]*\)[ \t]*$")

#: ``![banner](https://.../banner.png)``. All 11 occurrences sit outside fenced
#: blocks (counted, not assumed) and are removed there only.
_IMAGE_REF = re.compile(r"!\[[^\]\n]*\]\([^)\n]*\)")

#: Leading indentation, kept when a blob line is replaced so the marker sits
#: where the statement it replaced sat.
_INDENT = re.compile(r"^[ \t]*")

#: Stated in :class:`SourceSpec` and written into the cache. Long, because the
#: honest answer is long: every other source in this package can name an SPDX
#: identifier or quote a terms-of-use page, and this one cannot, so it says what
#: was checked and what was found instead of rounding to something tidy. The
#: precedent is :mod:`~training.corpus.sources.manpages`, which declares "Mixed:
#: ... no single SPDX identifier is true of it" rather than picking the most
#: common one.
_LICENSE = (
    "NO LICENCE DECLARED UPSTREAM — verified, not assumed. The repository "
    "swisskyrepo/InternalAllTheThings ships no LICENSE file on main or "
    "gh-pages, has no commit in its history touching a path named LICENSE, "
    "carries no licence badge and no mkdocs copyright key, and GitHub's licence "
    "detection returns null. The MIT licence of the same author's "
    "PayloadsAllTheThings does not extend to it. The only terms the repository "
    "states are the README's 'Content in this repository is provided as is, for "
    "learning purpose. The author and contributors take no responsibility if "
    "you break something.' and docs/DISCLAIMER.md, both copied into the cache "
    "as TERMS.md; neither is a grant of rights, and an unlicensed public "
    "repository is all-rights-reserved by default. Recorded here rather than "
    "rounded to an SPDX identifier so the decision to train on it is taken "
    "deliberately."
)

#: Printed by :func:`_fetch` on every cold fetch. The licence string above is
#: reported once per source by ``build.py``; this is the second place, because a
#: provenance problem that scrolls past in a header line is a provenance problem
#: nobody read.
_LICENSE_WARNING = (
    "   ! internal: swisskyrepo/InternalAllTheThings declares NO LICENCE "
    "(no LICENSE file, no badge, none in its git history). Unlicensed public "
    "code is all-rights-reserved by default. The repository's own terms are "
    f"cached as {_TERMS_FILE}; decide deliberately whether to train on this."
)


def _wanted(member_name: str) -> str | None:
    """Map a tar member to its cache-relative path, or ``None`` to skip it.

    Codeload wraps the tree in ``InternalAllTheThings-<ref>/``, whose name moves
    with the ref, so the first component is dropped rather than matched.

    Markdown under ``docs/`` only, and only inside an area directory. The depth
    test is what excludes ``docs/README.md`` and ``docs/DISCLAIMER.md``: a page
    at the root of ``docs/`` belongs to no phase of the engagement, and the two
    that exist there are the repository's front page and its legal notice. The
    disclaimer is still taken, separately, into the cached terms file — it is
    provenance, not training text.
    """
    parts = member_name.split("/")[1:]
    if not parts or any(part in ("", ".", "..") for part in parts):
        return None
    if len(parts) == 1 and parts[0] == _LICENSE_FILE:
        return parts[0]          # does not exist today; see the docstring
    if parts[0] != _DOCS_DIR or not parts[-1].endswith(".md"):
        return None
    if len(parts) == 2 and parts[1] == _DISCLAIMER:
        return parts[1]          # kept as terms, not as a page
    if len(parts) < 3:
        return None
    return "/".join(parts[1:])


def _extract(archive: Path, staging: Path) -> int:
    """Unpack the markdown pages into *staging*. Returns the page count.

    The count excludes the licence and disclaimer sidecars, so a tarball that no
    longer carries any area directory still reports zero even though those two
    came out of it. The caller's "upstream moved" diagnostic depends on that
    distinction.

    Members are written one at a time rather than through ``extractall``: the
    ``filter="data"`` argument that makes ``extractall`` safe is 3.12 and later,
    and this package targets 3.10. Only regular files are written and every
    destination is proved to resolve inside *staging* first — absolute paths,
    ``..`` segments and symlinks are all expressible in a tar member name, which
    is attacker-controlled data in the general case.
    """
    staging.mkdir(parents=True, exist_ok=True)
    staging_resolved = staging.resolve()
    sidecars = {_LICENSE_FILE, _DISCLAIMER}
    written = 0
    try:
        with tarfile.open(archive, "r:gz") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                relative = _wanted(member.name)
                if relative is None:
                    continue
                target = staging / relative
                if not target.resolve().is_relative_to(staging_resolved):
                    continue  # traversal attempt; refuse the member
                source = tar.extractfile(member)
                if source is None:
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with source, target.open("wb") as handle:
                    shutil.copyfileobj(source, handle)
                if relative not in sidecars:
                    written += 1
    except (tarfile.TarError, OSError) as exc:
        raise SourceError(f"internal: could not unpack {archive}: {exc}") from exc
    return written


def _write_terms(staging: Path, cache_dir: Path) -> None:
    """Record upstream's actual terms beside the pages they cover.

    The sibling copies a LICENSE file. There is none here, so what is cached is
    the disclaimer that does exist plus a written statement of what was looked
    for and not found — which is the part a future reader needs, because the
    absence of a file is not something a cache directory can show on its own.

    A ``LICENSE`` appearing upstream is reported rather than absorbed: it would
    make :data:`_LICENSE` stale, and a licence statement that has drifted from
    its source is worse than none, because it looks verified.
    """
    license_file = staging / _LICENSE_FILE
    disclaimer = staging / _DISCLAIMER
    disclaimer_text = ""
    if disclaimer.is_file():
        disclaimer_text = disclaimer.read_text(encoding="utf-8", errors="replace")
        disclaimer.unlink()

    if license_file.is_file():
        (cache_dir / _LICENSE_FILE).write_bytes(license_file.read_bytes())
        license_file.unlink()
        print(f"   ! internal: upstream now ships a {_LICENSE_FILE} — it has "
              f"been copied to {cache_dir / _LICENSE_FILE}, and the licence "
              "string in training/corpus/sources/internal.py is now STALE. "
              "Read it and update SPEC.license.")

    (cache_dir / _TERMS_FILE).write_text(
        "# Terms for swisskyrepo/InternalAllTheThings\n\n"
        f"Fetched from {_TARBALL_URL}\n"
        f"on {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}.\n\n"
        "## Licence\n\n"
        f"{_LICENSE}\n\n"
        "## The repository's own statement (README.md)\n\n"
        "> Content in this repository is provided as is, for learning purpose.\n"
        "> The author and contributors take no responsibility if you break\n"
        "> something.\n\n"
        f"## docs/{_DISCLAIMER}\n\n"
        + (disclaimer_text or "(not present in this fetch)\n"),
        encoding="utf-8",
    )


def _fetch(cache_dir: Path) -> Path:
    """Populate *cache_dir* with the markdown tree and return it.

    Idempotent and network-free on a warm cache: the build runs far more often
    than upstream changes. The short-circuit reads the marker rather than
    trusting its existence, and checks that the recorded ``ref`` and ``url``
    still match the ones this module declares — otherwise repointing
    :data:`_REF` at a tag would keep serving the old tree forever while the
    provenance file named the new one.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    marker = cache_dir / _MARKER
    pages_dir = cache_dir / _PAGES_DIR
    if marker.is_file():
        try:
            recorded = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            recorded = {}
        if (recorded.get("ref") == _REF
                and recorded.get("url") == _TARBALL_URL
                and pages_dir.is_dir()):
            return cache_dir

    archive = cache_dir / "_internalallthethings.tar.gz"
    staging = cache_dir / "_incoming"
    shutil.rmtree(staging, ignore_errors=True)
    try:
        try:
            # net.download writes a .part sibling and renames it, so an
            # interrupted transfer cannot leave a truncated archive behind.
            download(_TARBALL_URL, archive, timeout=300)
        except NetworkError as exc:
            raise SourceError(f"internal: {exc}") from None

        written = _extract(archive, staging)
        if written < _MIN_EXTRACTED:
            raise SourceError(
                f"internal: only {written} markdown pages found under "
                f"{_DOCS_DIR}/ in {_TARBALL_URL} (expected >= "
                f"{_MIN_EXTRACTED}). The upstream layout has probably changed "
                "— fix the adapter rather than training on a fraction of the "
                "post-exploitation register, which is the only place this "
                "corpus has it."
            )

        # Sidecars are moved out of the staging tree before the swap so that
        # `pages/` contains pages and nothing else, and so the provenance sits
        # at the top of the cache beside the marker that dates it.
        _write_terms(staging, cache_dir)

        # Retire the marker *before* the swap starts destroying the tree it
        # vouches for. Removing a directory and renaming another into its place
        # is not atomic, and an interruption inside that window would otherwise
        # leave a current marker on top of a half-replaced tree, which the warm
        # path above would accept. It is retired here rather than at the top of
        # the function so a failed download leaves the old cache usable offline.
        marker.unlink(missing_ok=True)
        shutil.rmtree(pages_dir, ignore_errors=True)
        staging.replace(pages_dir)
    finally:
        archive.unlink(missing_ok=True)
        shutil.rmtree(staging, ignore_errors=True)

    marker.write_text(
        json.dumps(
            {
                "url": _TARBALL_URL,
                "repo": _REPO,
                "ref": _REF,
                "pages": written,
                "license": "none declared upstream; see " + _TERMS_FILE,
                "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(_LICENSE_WARNING)
    return cache_dir


def _pages(root: Path) -> list[tuple[str, Path]]:
    """Every markdown page under *root*, as (area-relative ident, path).

    Walked with ``os.walk(..., followlinks=False)`` rather than ``rglob``. This
    tree is one the adapter extracted itself and holds no links, but the rule is
    absolute in this package: a sibling adapter once followed a symlink out of
    its own directory and copied 180 MB of the corpus cache back into the corpus
    under a different label. ``followlinks=False`` only stops the walk
    *descending* into a symlinked directory, so symlinked files are rejected
    explicitly too. Sorted, so the corpus is byte-reproducible across builds.
    """
    base = root / _PAGES_DIR
    pages: list[tuple[str, Path]] = []
    if not base.is_dir():
        return pages
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        dirnames.sort()
        for filename in sorted(filenames):
            if not filename.endswith(".md"):
                continue
            file = Path(dirpath) / filename
            if file.is_symlink() or not file.is_file():
                continue
            pages.append((file.relative_to(base).as_posix(), file))
    pages.sort()
    return pages


def _fence_map(lines: list[str]) -> list[bool]:
    """True for every line that belongs to a fenced block, delimiters included.

    This is the primitive every other rule here stands on: image stripping, blob
    elision, the link-ratio measurement and the choice of split points all ask
    "is this line inside a command?" and all of them must answer correctly for
    the 830 blocks this source indents under a list bullet. Marking the
    delimiters themselves as inside is deliberate — the fence line and its info
    string (```` ```ps1 ````) are part of the block's context and must never be
    edited or split away from it.

    Closing follows CommonMark closely enough for this source: same fence
    character, at least as long as the opening run, and nothing else on the
    line. That strictness is what lets a ```` ``` ```` *inside* a ```` ```` ````
    block stay inside it. A page that ends while still open leaves its tail
    marked as fenced, which fails in the safe direction: the tail is passed
    through untouched and unsplit rather than cut somewhere inside a command.
    (No page in the current tree ends open.)
    """
    flags: list[bool] = []
    marker = ""
    for line in lines:
        match = _FENCE.match(line)
        if match is None:
            flags.append(bool(marker))
            continue
        token = match.group(1)
        if not marker:
            marker = token
        elif (token[0] == marker[0] and len(token) >= len(marker)
                and line.strip() == token):
            marker = ""
        flags.append(True)
    return flags


def _is_blob(line: str) -> bool:
    """True for a line that is a binary literal rather than a command.

    Length **and** composition, never either alone. The composition test counts
    digits, spaces and commas because that is what both encodings in this source
    reduce to — ``"77 90 144 0 3 ..."`` and ``@(77, 90, 144, 0, 3, ...)`` — and
    because a real command is mostly none of those. See the module docstring for
    the measured gap on both axes.
    """
    length = len(line)
    if length < _BLOB_MIN_CHARS:
        return False
    dense = sum(1 for char in line if char.isdigit() or char in " ,")
    return dense / length >= _BLOB_DIGIT_RATIO


def _clean(lines: list[str], fenced: list[bool]) -> tuple[list[str], int, int]:
    """Strip images outside fences, elide binary blobs inside them.

    Returns the rewritten lines, the number of blob lines replaced and the
    number of characters they held, so the build log can state the size of the
    excision instead of leaving it to be reconstructed from a diff.

    Images: the files are not extracted into the corpus and the alt text is a
    slug, so the reference has no referent. A line that was nothing but an image
    becomes empty rather than whitespace, and
    :func:`~training.corpus.source.normalise` then folds the blank run.

    Blobs: replaced by a marker that keeps the original indentation and states
    what was removed. Deleting the line outright would leave a script that looks
    complete and is not, which is the same objection this package raises against
    truncating a payload — a command the model could try and that cannot work is
    worse than a visible gap.
    """
    out: list[str] = []
    blobs = 0
    blob_chars = 0
    for line, in_fence in zip(lines, fenced):
        if in_fence:
            if _is_blob(line):
                blobs += 1
                blob_chars += len(line)
                indent = _INDENT.match(line).group(0)  # type: ignore[union-attr]
                out.append(
                    f"{indent}[elided: {len(line):,} characters of "
                    "machine-encoded binary]"
                )
                continue
            out.append(line)
            continue
        stripped = _IMAGE_REF.sub("", line)
        out.append(stripped if stripped.strip() else "")
    return out, blobs, blob_chars


def _link_ratio(lines: list[str], fenced: list[bool]) -> float:
    """Share of non-blank prose lines that are a bullet and one bare link.

    The discriminator for an index page. Fenced lines are excluded from both
    halves of the fraction so that a page of commands cannot be diluted into
    looking like an index, and a page of links cannot be rescued by one.
    """
    body = 0
    links = 0
    for line, in_fence in zip(lines, fenced):
        if in_fence or not line.strip():
            continue
        body += 1
        if _LINK_ONLY.match(line):
            links += 1
    return links / body if body else 0.0


#: A section of a page: the trail of headings that led to it, outermost first,
#: and its rows as ``(line, is_inside_a_fence)`` pairs. The trail is carried
#: rather than recomputed because a section cut out of the middle of a page no
#: longer has its ancestors above it, and those ancestors are what say which
#: prerequisite the commands below assume — that you already hold a ticket, that
#: the account is unconstrained, that the share is writable.
_Section = tuple[tuple[str, ...], list[tuple[str, bool]]]


def _size(rows: list[tuple[str, bool]]) -> int:
    """Characters a row list will occupy, newlines included."""
    return sum(len(line) + 1 for line, _ in rows)


def _cut(rows: list[tuple[str, bool]], level: int,
         path: tuple[str, ...]) -> list[_Section]:
    """Cut *rows* at ATX headings of depth *level* (or shallower at the top).

    Headings inside fenced blocks are not headings, and this source has 489
    lines that would break that rule if it were not enforced here: ``# Create
    the scheduled task`` at the head of a PowerShell block must never become a
    split point. Anything before the first boundary keeps the caller's *path* —
    it is the parent's own preamble, not a new section.
    """
    sections: list[_Section] = []
    heading = ""
    body: list[tuple[str, bool]] = []
    for line, in_fence in rows:
        match = None if in_fence else _HEADING.match(line)
        depth = len(match.group(1)) if match is not None else 0
        # The top-level pass takes H1 and H2 as siblings (a page's H1 is its
        # title, not a level the sections hang under); deeper passes take one
        # exact level at a time, so a parent heading is not re-read as a
        # boundary and duplicated into its children's heading trail.
        boundary = depth and (depth <= level if level <= 2 else depth == level)
        if boundary:
            if heading or any(text.strip() for text, _ in body):
                sections.append((path + ((heading,) if heading else ()), body))
            heading = match.group(2).strip()
            body = [(line, in_fence)]
            continue
        body.append((line, in_fence))
    if heading or any(text.strip() for text, _ in body):
        sections.append((path + ((heading,) if heading else ()), body))
    return sections


def _sections(rows: list[tuple[str, bool]]) -> list[_Section]:
    """Cut a page into sections small enough to pack, descending as needed.

    Top-level headings first. That is enough for most pages, but not for the
    ones where a single ``##`` holds many kilobytes under a dozen ``###``
    subheadings — ``containers/kubernetes.md`` and
    ``redteam/escalation/linux-privilege-escalation.md`` are both this shape.
    Left at one level the packer cannot divide them at all, and the resulting
    part spans several training windows with the area header on only the first,
    which is the exact failure splitting exists to prevent.

    So an oversized section is re-cut one heading level deeper, repeatedly,
    until it fits or there are no deeper headings left. A section with nothing to
    cut at any level is returned whole and oversized: overshooting the target is
    a cost, and cutting a command listing in half is a corruption.
    """
    sections: list[_Section] = []
    for path, body in _cut(rows, 2, ()):
        sections.extend(_refine(path, body, 3))
    return sections


def _refine(path: tuple[str, ...], body: list[tuple[str, bool]],
            level: int) -> list[_Section]:
    """Recursively divide an oversized section at ever deeper headings."""
    if level > 6 or _size(body) <= _PART_TARGET:
        return [(path, body)]
    pieces = _cut(body, level, path)
    if len(pieces) <= 1:
        return _refine(path, body, level + 1)  # nothing at this depth; go deeper
    refined: list[_Section] = []
    for child_path, child_body in pieces:
        refined.extend(_refine(child_path, child_body, level + 1))
    return refined


def _pack(sections: list[_Section]) -> list[list[_Section]]:
    """Group consecutive sections into parts of roughly :data:`_PART_TARGET`.

    Greedy and order-preserving. An attack path reads top to bottom — enumerate,
    find the misconfiguration, abuse it, confirm — and reordering sections to
    pack more tightly would destroy the very thing this source was collected for.

    Two floors, both for the same reason: a part below :data:`_MIN_PART` is a
    fragment wearing a header. A part is not closed early just because the
    *next* section is large, and a short final section is folded back into its
    predecessor.
    """
    parts: list[list[_Section]] = []
    current: list[_Section] = []
    size = 0
    for section in sections:
        length = _size(section[1])
        if current and size >= _MIN_PART and size + length > _PART_TARGET:
            parts.append(current)
            current = []
            size = 0
        current.append(section)
        size += length
    if current:
        parts.append(current)

    if len(parts) > 1 and sum(_size(body) for _, body in parts[-1]) < _MIN_PART:
        parts[-2].extend(parts.pop())
    return parts


def _area(ident: str) -> str:
    """The engagement phase a page belongs to, read off its directory path.

    ``redteam/escalation/windows-privilege-escalation.md`` becomes
    ``redteam / escalation``. The slugs are kept exactly as upstream writes them
    rather than prettified into prose, so the string in the corpus is the string
    somebody can grep for in the repository it came from.
    """
    parts = ident.split("/")[:-1]
    return " / ".join(parts) if parts else "(root)"


def _header(area: str, title: str, part: int, total: int,
            sections: list[_Section]) -> str:
    """The context block that opens every document this adapter yields.

    Two lines always. The page title alone is usually a good name for the
    technique in this source — unlike in the sibling — but it almost never says
    which phase of an engagement the technique belongs to, and the phase is what
    maps onto the ``postex.*`` verbs. ``# ClickFix`` and ``# OPSEC`` are the
    clearest cases: only ``redteam / access`` and ``redteam / evasion`` say what
    they are for.

    A third line when the page was split, naming the part and the sections it
    holds. On parts after the first this is the *only* thing that says what
    platform and what prerequisite the commands below assume — the H1 is back in
    part one, a thousand tokens away and, once the corpus is windowed, in a
    different training sample entirely.
    """
    lines = [f"internal area: {area}", f"page: {title}"]
    if total > 1:
        named: list[str] = []
        for path, _ in sections:
            # The H1 is a boundary like any other heading, so without this the
            # section list would open by repeating the title it sits under.
            trail = " > ".join(heading for heading in path if heading != title)
            if trail and trail not in named:
                named.append(trail)
        label = f"part {part} of {total}"
        lines.append(f"{label}: {', '.join(named)}" if named else label)
    return "\n".join(lines)


def _title(lines: list[str], fenced: list[bool], ident: str) -> str:
    """The page's first H1, falling back to its filename.

    All 167 pages in the current tree have one and they are good; the fallback
    exists so that a future page without one gets a usable name instead of an
    empty ``page:`` line.
    """
    for line, in_fence in zip(lines, fenced):
        if in_fence:
            continue
        match = _HEADING.match(line)
        if match is not None and len(match.group(1)) == 1:
            return match.group(2).strip()
    stem = ident.rsplit("/", 1)[-1][: -len(".md")]
    return stem if stem != "README" else ident.split("/")[-2]


def _documents(path: Path) -> Iterator[Document]:
    """Yield the pages, whole where they fit and split where they do not.

    Order is the sorted repository path, so a rebuild produces the same corpus
    in the same sequence.

    A page that cannot be read raises rather than being skipped. Silently
    shipping a corpus that is short by an unknown amount is the failure this
    package is built to make impossible, and a damaged cache is a fixable
    condition that deserves to be said out loud.
    """
    pages = _pages(path)
    if not pages:
        raise SourceError(
            f"internal: no markdown pages under {path / _PAGES_DIR}. Run fetch "
            "first, or delete the cache and re-fetch if it is damaged."
        )

    stubs = 0
    split_pages = 0
    blob_lines = 0
    blob_chars = 0
    for ident, file in pages:
        try:
            # utf-8-sig: a stray U+FEFF at the head of a page would become a
            # token the model learns to expect before every H1.
            raw = file.read_text(encoding="utf-8-sig", errors="replace")
        except OSError as exc:
            raise SourceError(
                f"internal: {ident} was listed but could not be read ({exc}). "
                f"The cache is damaged; delete {path} and re-fetch rather than "
                "shipping a corpus that is short by an unknown amount."
            ) from exc

        # Line endings are settled before anything counts lines or fences, so a
        # CRLF page cannot defeat the strict fence-close test below.
        lines = raw.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        fenced = _fence_map(lines)
        lines, blobs, chars = _clean(lines, fenced)
        blob_lines += blobs
        blob_chars += chars

        whole = normalise("\n".join(lines))
        if len(whole) < _MIN_CHARS:
            continue
        # A page with no command in it and mostly bare links is an index over
        # pages this adapter already yields in full.
        if not any(fenced) and _link_ratio(lines, fenced) >= _STUB_LINK_RATIO:
            stubs += 1
            continue

        area = _area(ident)
        title = _title(lines, fenced, ident)

        if len(whole) <= _SPLIT_ABOVE:
            header = _header(area, title, 1, 1, [])
            yield Document(
                text=normalise(f"{header}\n\n{whole}"),
                source="internal",
                register=Register.ADVERSARY,
                side=Side.RED,
                ident=ident,
            )
            continue

        parts = _pack(_sections(list(zip(lines, fenced))))
        split_pages += 1
        for index, part in enumerate(parts, start=1):
            header = _header(area, title, index, len(parts), part)
            body = normalise(
                "\n".join(line for _, rows in part for line, _ in rows)
            )
            if not body:
                continue  # a section of nothing but a heading and blank lines
            yield Document(
                text=normalise(f"{header}\n\n{body}"),
                source="internal",
                register=Register.ADVERSARY,
                side=Side.RED,
                ident=f"{ident}#part{index}" if len(parts) > 1 else ident,
            )

    # Nothing is dropped or reshaped silently; the build log says how much.
    if stubs:
        print(f"   internal: skipped {stubs} index page(s) with no code fence "
              "and mostly bare links")
    if blob_lines:
        print(f"   internal: elided {blob_lines} line(s) of machine-encoded "
              f"binary totalling {blob_chars:,} chars (a DLL written out as "
              "decimal bytes); the enclosing scripts are otherwise intact")
    if split_pages:
        print(f"   internal: split {split_pages} page(s) over "
              f"{_SPLIT_ABOVE:,} chars at their own headings")


SPEC = SourceSpec(
    name="internal",
    license=_LICENSE,
    url="https://github.com/swisskyrepo/InternalAllTheThings",
    register=Register.ADVERSARY,
    side=Side.RED,
    fetch=_fetch,
    documents=_documents,
    #: 169 markdown pages upstream: 2 are repository chrome at the root of
    #: ``docs/`` and are not extracted, 2 of the remaining 167 are index pages
    #: and are dropped, and 34 of the 165 left are split — 271 documents
    #: observed on main at fetch time. The floor sits below that because pages
    #: are retired by being folded into a neighbour and the count drifts down by
    #: ones, but it is tight enough to catch the regression that matters: a
    #: fence matcher that stopped seeing indented blocks would reclassify much
    #: of this source as index pages and gut the count. All 271 carry distinct
    #: fingerprints, so ``build.py``'s global dedup takes nothing off this
    #: source on its own account — but it dedups across sources as well, and the
    #: reverse-shell and Mimikatz material here overlaps other adapters, so the
    #: number it reports can be lower than the number this adapter yields. 200
    #: leaves roughly the same 25% headroom the sibling allows against its own
    #: observed count.
    expect_min_docs=200,
    notes=(
        "Where the post-exploitation register actually lives. All 33 "
        "'Methodology and Resources' pages in PayloadsAllTheThings are now "
        "redirect stubs pointing here, and they were the pages that mapped "
        "onto postex.credential_dump, postex.persistence_install, "
        "postex.privilege_escalate and postex.lateral_move — so without this "
        "source that register is empty, not thin. One document per page, "
        "headings and fenced commands intact, opened with the directory path "
        "because this repository's H1s name the technique well ('# ClickFix', "
        "'# OPSEC') and never name the phase of the engagement, which is "
        "exactly what the path does say (access, escalation, evasion, "
        "persistence, pivoting). 49.2% of the text is fenced code — the "
        "densest source in this corpus, 86% of it ps1/powershell — and 47.5% "
        "of the opening fences are indented under a list bullet, so the fence "
        "regex tolerates leading whitespace or half the code becomes invisible "
        "and every split point becomes unsafe. Pages over 8 KB are split at "
        "their own headings, descending a level into any section still too "
        "large and never cutting inside a fence. Five lines of machine-encoded "
        "binary (a DLL as decimal bytes, 29,465 characters on one line, 79.9% "
        "of the AMSI page) are replaced with a marker: measured at 0.998-1.000 "
        "digits-and-separators against 0.152 for the longest real one-liner, "
        "so the rule sits in a void rather than on a threshold. Only image "
        "references are stripped, and only outside fences: the 107 "
        "angle-bracket tokens in the prose are <username>, <password>, "
        "<Domain> and <GPOName> placeholders inside inline code, not markup. "
        "LICENCE: none. Verified against the repository rather than assumed "
        "from its sibling — no LICENSE file on either branch, nothing in the "
        "git history, no badge, GitHub's detection returns null. The terms it "
        "does state are cached as TERMS.md and neither is a grant of rights."
    ),
)
