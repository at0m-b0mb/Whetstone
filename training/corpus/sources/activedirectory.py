"""Active Directory — the attack paths, and the tradecraft that walks them. ADVERSARY/RED.

Active Directory is the enterprise attack surface. It is where the engagement
actually happens after the first shell, it is what every one of this project's
``postex.*`` verbs is really about, and until this adapter existed the corpus
contained essentially nothing about it. ``attack`` names T1558 and describes it
in two paragraphs; ``atomic`` fires one Rubeus command at it; ``sigma`` and
``elastic`` carry the detections for attacks whose *mechanics* appear nowhere in
the training data. A model can therefore recite that Kerberoasting exists and
cannot tell you why the ticket comes back RC4-encrypted, what ``msDS-Supported
EncryptionTypes`` has to do with it, or which of the two dozen ACL edges into a
user object gets you there in the first place. That gap is the reason this file
exists.

What is collected is deliberately the *sequential* half of the knowledge —
prerequisite, action, consequence, and what the action leaves behind — because
that is the half retrieval cannot supply and the half this project's thesis is
built on. Two upstreams, chosen because they cut the same domain along
perpendicular axes and neither substitutes for the other:

* **SpecterOps' BloodHound documentation** (``SpecterOps/bloodhound-docs``,
  Apache-2.0) is *privilege*-centric. One document per graph edge: what the
  edge means, how it is abused on Windows and on Linux, the **opsec
  considerations** — which is the detection side written from the attacker's
  chair — the edge schema (which node kinds it can run between, whether it is
  traversable), and the references. 134 edges covering every ACL primitive
  (``GenericAll``, ``WriteDacl``, ``WriteOwner``, ``AddKeyCredentialLink``,
  ``WriteSPN``, ``ForceChangePassword``), all thirteen ADCS escalations
  ``ADCSESC1`` through ``ADCSESC13``, delegation in all three flavours,
  ``DCSync``, ``ReadLAPSPassword``, ``ReadGMSAPassword``, ``SpoofSIDHistory``,
  the forest and same-forest trust edges, plus the Azure/Entra edges that are the
  same graph one directory over. 38 node documents carry the property tables —
  ``lastLogonTimestamp``, ``DACL_Protected``, ``servicePrincipalName``,
  ``adminCount`` — which is the LDAP attribute vocabulary joined, attribute by
  attribute, to why an attacker cares.

* **The Hacker Recipes** (``ShutdownRepo/The-Hacker-Recipes``, GPL-3.0) is
  *technique*-centric, and structurally it is two halves: a ``## Theory`` section
  that explains the protocol behaviour being abused, then a ``## Practice``
  section that is nothing but commands. 139 pages under ``ad/`` — roasting,
  delegations (unconstrained, constrained, RBCD, bronze bit, S4U2self), forged
  tickets (golden, silver, diamond, sapphire, MS14-068, RODC), pass-the-*,
  shadow credentials, unPAC-the-hash, DCSync, NTDS, LSASS, DPAPI, ADCS,
  coerced authentication (PetitPotam, PrinterBug, DFSCoerce, ShadowCoerce),
  NTLM relay, SCCM, trusts, Zerologon, and the persistence half — AdminSDHolder,
  DCShadow, DSRM, Golden gMSA, SID history, skeleton key, shadow principals.

Together: 311 upstream pages, of which 286 render, as 375 documents and 1.37 MB.
The two of them agree on almost nothing textually — one says "this ACE lets you
do X, here is what it logs", the other says "here is the protocol, here are four
tools that do X on two operating systems". Unique text is this corpus's scarcest
resource and these two overlap by topic rather than by sentence.

**Register: ADVERSARY, side RED, for the whole source.** Read the balance report
in :func:`training.corpus.build.balance_report` before arguing: ``by_reg`` and
``by_side`` are accumulated from ``BuildStats``, which carries
:class:`~training.corpus.source.SourceSpec`'s declared register and side, *not*
the per-document one. A source that mixes registers therefore makes the report
lie, and the report is the only instrument this project has for the thing it is
trying to fix. So the choice had to be one label for all of it, and ADVERSARY is
the honest one: 15.7% of The Hacker Recipes' ``ad/`` characters sit inside 613
fenced blocks (393 ``bash``, 174 ``powershell``), which is dense enough to feed
the SHELL gap and nowhere near dense enough to *be* SHELL. What these documents
teach is an ordering — this ACE implies that write, which implies this ticket,
which is why the next command works — and the commands are the evidence rather
than the content. The one place this label is a stretch is BloodHound's 38 node
documents, which are property reference tables; they are 6% of the source and
they are kept because the properties they enumerate are exactly the ones attack
paths are computed from, but the stretch is stated here rather than hidden.

**Licensing, which is the part that would sink this.** Both LICENSE files were
read from the fetched archive, not from a badge, and both are copied into the
cache beside the text they cover.

* ``bloodhound-docs`` ships one Apache-2.0 LICENSE and no other. Its README adds
  the sentence that actually matters — "Unless otherwise annotated by a
  lower-level LICENSE file or license header, all files in this repository are
  released under the ``Apache-2.0`` license" — so the tree was checked for both:
  there is no second LICENSE anywhere in it, and not one of the 248 ``.mdx``
  files taken here carries a per-file copyright or SPDX header.
* ``The-Hacker-Recipes`` ships the unmodified 674-line GPL-3.0 text and nothing
  else. GPL-3.0 is not permissive and is declared as such in :data:`SPEC`,
  exactly as ``yara`` and ``elastic`` declare theirs; the precedent for using it
  at all is ``gtfobins``, which is the same licence. Its section 4 requires that
  all notices be kept, which is why every page's ``authors:`` frontmatter is
  rendered into the document header instead of being dropped as site metadata —
  it is the only attribution these pages carry.

**The upstream that was rejected, and why, because it is the obvious one.**
``GhostPack/Rubeus`` is 218 KB of Kerberos tradecraft — kerberoast, asreproast,
golden, silver, diamond, S4U, ptt — with exact syntax and real console output,
and its LICENSE file is a clean 3-clause BSD. It is not used. The README's own
first paragraph says the tool is "**heavily** adapted from [Benjamin Delpy]'s
Kekeo project (**CC BY-NC-SA 4.0** license) and [Vincent LE TOUX]'s
MakeMeEnterpriseAdmin project (**GPL v3.0** license)". A BSD-3 LICENSE file
cannot relicense someone else's copyright, CC BY-NC-SA 4.0 forbids commercial
use outright, and the README's value is largely the output of the binary that
derives from those works. That is the "MIT repositories vendor GPL files inside
themselves" trap with the vendoring admitted in the first sentence of the
README, and this project has already refused 1.19 MB of exactly the material it
wanted over provenance (see :mod:`._internal_unlicensed`). The same paragraph
disqualifies the rest of the GhostPack family, which credits Mimikatz the same
way. ``infosecn1nja/AD-Attack-Defense`` has no LICENSE at all and is
all-rights-reserved by default, for the same reason.

**Trap 1: the angle brackets that are not markup.** BloodHound's pages are MDX,
so they are markdown with JSX components in them, and the reflex is to strip
anything shaped like ``<Name ...>``. That is wrong here and would corrupt the
highest-value lines in the source. Counted across the 172 edge and node pages,
seventeen uppercase-initial angle-bracket tokens are *placeholders inside
commands*: ``<SHA1>`` (4), ``<DOMAIN>`` (3), ``<Base64PFX>`` (2),
``<Base64PrivateKey>`` (2), ``<Domain>`` (2), ``<RC4>`` (2),
``<TargetPrincipal>`` (1), ``<NAME>`` (1). They sit in Certipy and Rubeus
invocations, they are the argument the operator has to substitute, and a
component-shaped regex eats every one of them. So this adapter only ever touches
a tag whose name is either imported by that file or is in :data:`_MINTLIFY`, a
fixed list of the documentation framework's own components; everything else
passes through byte for byte. The same rule is why the transforms are applied
only to the segments *outside* fenced blocks.

The trap has a lowercase mirror, and it is worse. The Hacker Recipes carries a
little raw HTML left over from a previous docs platform — ``<p>``, ``<a href>``,
a ``<span data-gb-custom-inline>`` wrapped round an emoji, all inside table
cells. A regex for "any lowercase HTML tag" removes those and also removes
``<assets>`` (12), ``<attribute>`` (2), ``<rid>`` (2), ``<user>``, ``<group>``
and ``<https://…>``: twenty more placeholders standing where an operator
substitutes a value. :data:`_HTML_TAG` therefore names the fourteen tags that
are markup, and nothing else is a tag. Two block constructs are removed with
their contents rather than unwrapped — ``<Frame>``, which holds a screenshot and
nothing else, and nine hand-written ``<iframe>`` YouTube embeds that are four
hundred characters each of ``allow="accelerometer; autoplay; …"``. The sentence
above each embed ("See this clip for an example of this edge being abused")
survives and says what was there.

**Trap 2: the frontmatter is not chrome.** The Hacker Recipes writes its
ATT&CK mapping into the YAML header — ``description: MITRE ATT&CK™ Sub-technique
T1558.003`` — and 21 of the 139 pages carry one. Exactly one page mentions a
technique id anywhere in its body. Stripping the frontmatter as site metadata,
which is what every markdown adapter does by default, therefore deletes the
entire join between this source and :mod:`~training.corpus.sources.attack` —
and the measurement this whole corpus was rebuilt around is that ``T1547.001``
standing beside its human name is worth +58 percentage points against gpt2. The
id is lifted out and given its own labelled line in the header.

**Trap 3: the tab labels, which are a setext heading if you look away.** The
Hacker Recipes marks its per-platform command blocks with VitePress container
syntax: ``::: tabs`` opens, ``=== UNIX-like`` and ``=== Windows`` label, ``:::``
closes. There are 287 of those labels, 206 of them naming one of those two
operating systems, and they are the *only* thing that says whether the four
commands under them are Impacket or Rubeus. Drop the container syntax and the
platform goes with it. Keep the line verbatim and it is worse than useless,
because in CommonMark a line of ``=`` under text is a setext H1 underline — every
tab label would read as a heading and the splitter below would cut at it. The
resolution is a container stack, and it is provably enough: measured over the
whole tree, all 287 labels occur inside a ``::: tabs`` container and **zero**
occur outside one, so "transform only when the innermost open container is a
tabs container" can never reach a real underline.

**Trap 4: one upstream is CRLF and the other is not.** bloodhound-docs is checked
in with Windows line endings, so every one of its lines arrives with a trailing
``\r``. Every line-oriented regex in this module is anchored with ``$`` and
applied to one line at a time, and ``$`` does not match before a lone carriage
return — so on that half of the source ``_MDX_IMPORT``, ``_CONTAINER``,
``_TAB_LABEL`` and ``_HEADING`` all matched *nothing*, silently. The first render
of this adapter shipped raw ``<ResourceEditionPill />`` tags and a literal
``import … from '/snippets/…'`` line into the corpus and looked entirely healthy
doing it, because the only symptom of a regex that matches nothing is text that
was not transformed. ``normalise`` fixes line endings too, but it runs at the end
of the pipeline, several hundred failed matches too late. :func:`_decode` does it
at read time instead, which is decoding rather than cleaning: no horizontal
whitespace is touched.

**Trap 5: a fence map is not a toggle.** One page —
``ad/movement/credentials/dumping/sam-and-lsa-secrets.md`` — is missing a closing
backtick, leaving thirteen fence lines in the file. Flip a boolean on each of
them and the fence state is inverted for the whole rest of the page: container
markers and tab labels leak through untransformed, and every heading below the
break stops being a split point. :func:`_fence_scan` implements the CommonMark
rule instead — a closing fence carries no info string and is at least as long as
the fence that opened it — under which the stray ````` ```bash ````` is content
of the block above it, the rest of the page pairs correctly, and the file ends
closed. That is also what upstream's own renderer does with it, so the one tab
label that stays inside a code block here stays inside one on their site too. A
page that still ends inside an open fence is rendered and *named* in the build
log rather than passed over.

**What is held back, counted and printed rather than dropped in silence.** Seven
Hacker Recipes pages are redirect stubs — a work-in-progress title over one or
two links, with no prose at all — and are refused by :data:`_MIN_PROSE_CHARS`,
which measures writing rather than length for the reason given there. Eighteen
BloodHound pages have a body byte-identical to another page's, because six of
the Microsoft Graph edges are described in one shared sentence and ten of the
Azure resource node pages are a title over one shared, imported property table.
Once that snippet is inlined their only unique content is the header line *this
adapter wrote*, which ``build.py``'s fingerprint dedup cannot see, and keeping
them would put the same 2.4 KB table into a 1.37 MB source ten times over. The
cost was measured rather than assumed: of the eighteen names dropped, sixteen
still appear elsewhere in the source — in ``traversable-edges`` and in other
edges' cross-references — and two, ``AZWebApp`` and ``AZFunctionApp``, do not.

**Whitespace.** :func:`~training.corpus.source.normalise` preserves horizontal
whitespace and this source needs it. BloodHound's node property tables are
hand-padded to column width — ``| Allows Unconstrained Delegation   |`` — and a
cleaner that collapsed space runs would turn a legible table into a row of
pipes. Every fenced block in both upstreams keeps its own indentation. **Nothing
in this module collapses a run of spaces**, in either direction: the only
horizontal whitespace it writes at all is what its own header lines contain.

One consequence is worth naming so it is not mistaken for damage later.
``normalise`` has its own rule for a run of 200 spaces or more — it calls that a
rendering artefact rather than layout and caps it at eight — and BloodHound's
widest description column is padded past that, so those cells come back with the
padding shortened while the narrower columns keep theirs exactly. That is the
shared contract doing what it says, applied identically to every source in the
corpus, and deliberately not worked around privately here: a private cleaner in
one adapter is how a corpus stops being comparable across adapters.

**Markdown is left as markdown.** Links are not rewritten, headings are not
rewritten, fences are not relabelled. That follows
:mod:`~training.corpus.sources.payloads`, and it is deliberate rather than lazy:
markdown link syntax is itself a surface form worth learning, and the URL half
carries provenance (``https://learn.microsoft.com/…/ms-kile/…`` beside the
sentence it supports). One measured non-intervention is worth naming. Four of
BloodHound's 304 fenced blocks are labelled ``json`` and all four hold PowerView
PowerShell (``$Guids = Get-DomainGUIDMap``), all four in ``generic-all.mdx``.
Relabelling someone else's code blocks is a larger liberty than the 1.3% of
fences it would fix, and the prose one line above each of them already names
PowerView, so they are left as upstream wrote them.

**Long pages are split at their own headings, never truncated.** The model
trains at ``max_seq_len`` 1024 and :func:`training.data.tokenize_corpus` samples
fixed-length windows out of a concatenated stream, so the 69 KB trusts page would
spend seventeen of its eighteen windows with nothing saying it is about Active
Directory trusts. Thirty-five of the 286 rendered pages are over :data:`_SPLIT_ABOVE`.
They are cut at ATX headings — computed from the fence map, so a ``# generate the
ticket`` comment inside a bash block can never become a boundary — descending a
heading level into any section still too large, packed greedily to
:data:`_PART_TARGET`, and every part reopens with the full header plus the
heading trail of the sections it holds. A section with no deeper heading to cut
at is emitted whole and oversized, because overshooting a target is a cost and
cutting a command listing in half is a corruption.

**Transport.** Two codeload tarballs, 25 MB and 82 MB, from which 1.35 MB of
markdown is extracted. That ratio is ugly and it is still the right call: the
alternative is enumerating ~200 files through the GitHub tree API, which is rate
limited to 60 requests an hour unauthenticated — it refused twice while this
adapter was being written — and then issuing two hundred separate requests whose
failure modes are individual and silent. One archive per upstream is atomic,
hashed into the marker, and reproducible. Members are copied out by hand rather
than with ``extractall``: an archive member name is attacker-controlled data in
principle, so absolute paths, ``..`` segments and non-regular members are
refused and every destination is proved to resolve inside the staging directory
first. Each upstream's completion marker is written **last**, after the staging
tree has been renamed into place, so an interrupted fetch re-fetches instead of
being mistaken for a complete cache.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tarfile
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from ..net import NetworkError, download
from ..source import (Document, Register, Side, SourceError, SourceSpec,
                      fingerprint, normalise)


# ---------------------------------------------------------------------------
# upstreams
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class _Upstream:
    """One documentation repository and everything needed to take a slice of it.

    The licence lives in this table rather than in a comment because
    :data:`SPEC`'s licence string is *generated* from it. An upstream cannot be
    added here without stating its terms, which is the same property
    :class:`~training.corpus.source.SourceSpec` enforces one level up.
    """

    #: Cache subdirectory, and the prefix on every document's ``ident``.
    key: str
    repo: str
    ref: str
    #: Human name, used in the build log and in the generated licence string.
    label: str
    #: Archive-relative prefixes to extract, first component already dropped.
    keep: tuple[str, ...]
    #: Extension of the files worth keeping under those prefixes.
    suffix: str
    #: Archive-relative path of the licence file, copied into the cache.
    license_file: str
    license_id: str
    #: The sentence that goes into the composite ``SPEC.license``.
    license_note: str
    #: The directory, relative to the upstream's cache root, holding the pages
    #: that become documents. Anything else extracted is supporting material.
    docs: str
    #: Floor on extracted file count. An upstream layout change — a renamed
    #: directory, a moved tree — must fail loudly at fetch time rather than
    #: becoming a mysteriously thin build report.
    min_files: int


#: Walked in this order, most permissive licence first. Nothing here is known to
#: overlap, but :func:`training.corpus.build` keeps the first copy of a
#: fingerprint it sees, so if the two upstreams ever do converge on a paragraph
#: the copy that survives should be the one with the fewest strings attached.
#: The same ordering argument is made at length in
#: :mod:`~training.corpus.sources.yara`.
_UPSTREAMS: tuple[_Upstream, ...] = (
    _Upstream(
        key="bloodhound",
        repo="SpecterOps/bloodhound-docs",
        ref="main",
        label="BloodHound documentation (SpecterOps)",
        # snippets/ is not a document tree — it holds the shared fragments that
        # the edge and node pages import — but it has to be cached, because a
        # page whose <NtlmRelayGuidance /> cannot be resolved silently loses a
        # paragraph of its abuse section.
        keep=("docs/resources/edges/", "docs/resources/nodes/", "docs/snippets/"),
        suffix=".mdx",
        license_file="LICENSE",
        license_id="Apache-2.0",
        license_note=(
            "SpecterOps/bloodhound-docs (docs/resources/edges, docs/resources/"
            "nodes and the snippets they import): Apache-2.0, Copyright 2025 "
            "Specter Ops, Inc. The repository holds exactly one LICENSE and no "
            "per-file licence header"
        ),
        docs="docs/resources",
        #: 134 edges + 38 nodes + 76 snippets = 248 upstream. Well below that.
        min_files=150,
    ),
    _Upstream(
        key="recipes",
        repo="ShutdownRepo/The-Hacker-Recipes",
        ref="main",
        label="The Hacker Recipes",
        # ad/ only. The repository also documents web, infra, radio, physical
        # and mobile; those are other adapters' problems and several of them
        # overlap material the corpus already holds.
        keep=("docs/src/ad/",),
        suffix=".md",
        license_file="LICENSE",
        license_id="GPL-3.0",
        license_note=(
            "ShutdownRepo/The-Hacker-Recipes (docs/src/ad only): GPL-3.0-only, "
            "the unmodified 674-line GNU GPL v3 text — NOT permissive. Per-page "
            "'authors:' attribution is preserved in every rendered document, as "
            "section 4 requires"
        ),
        docs="docs/src/ad",
        #: 139 pages upstream.
        min_files=100,
    ),
)


# ---------------------------------------------------------------------------
# transport
# ---------------------------------------------------------------------------

#: Written last, after the staging tree is renamed into place. Its presence is
#: the only thing that means "this upstream is complete"; a half-extracted cache
#: therefore re-fetches instead of yielding a fragment of the source.
_MARKER = ".fetched.json"

#: Ceiling on one archive. bloodhound-docs is 82 MB and The Hacker Recipes 25 MB,
#: both dominated by screenshots this adapter never extracts. A repository that
#: grows past this should fail loudly on the machine that builds the training
#: data rather than quietly filling the volume the corpus lives on.
_MAX_ARCHIVE_BYTES = 192 * 1024 * 1024

#: Ceiling on one member. The largest page in either tree is 69,564 bytes
#: (``ad/movement/trusts/index.md``), so this is two orders of magnitude of
#: headroom and still bounds the damage from a member whose size is an accident
#: or an attack. The read is bounded at the point the bytes arrive, not checked
#: with ``stat()`` afterwards.
_MAX_MEMBER_BYTES = 1 << 20

_COPY_CHUNK = 1 << 20


def _archive_url(upstream: _Upstream) -> str:
    return (f"https://codeload.github.com/{upstream.repo}"
            f"/tar.gz/refs/heads/{upstream.ref}")


def _fetch(cache_dir: Path) -> Path:
    """Populate ``cache_dir`` with both upstreams; return it.

    Per upstream rather than per source: each gets its own completion marker, so
    a failure fetching the second does not throw away the 82 MB the first has
    already landed. Idempotent and network-free once both markers exist, because
    the build runs often.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    for upstream in _UPSTREAMS:
        _fetch_one(cache_dir, upstream)
    return cache_dir


def _fetch_one(cache_dir: Path, upstream: _Upstream) -> Path:
    """Download and unpack one upstream into ``cache_dir/<key>``."""
    home = cache_dir / upstream.key
    if (home / _MARKER).is_file():
        return home

    url = _archive_url(upstream)
    archive = cache_dir / f".{upstream.key}.tar.gz.part"
    staging = cache_dir / f".{upstream.key}.staging"
    shutil.rmtree(staging, ignore_errors=True)
    try:
        try:
            download(url, archive, timeout=600, max_bytes=_MAX_ARCHIVE_BYTES)
        except NetworkError as exc:
            raise SourceError(
                f"activedirectory: could not fetch {url}: {exc}"
            ) from exc

        digest = _sha256(archive)
        written, oversize, licensed = _extract(archive, staging, upstream)
        if written < upstream.min_files:
            raise SourceError(
                f"activedirectory: only {written} {upstream.suffix} files under "
                f"{', '.join(upstream.keep)} in {url} (expected at least "
                f"{upstream.min_files}). The upstream layout has changed — fix "
                "the adapter rather than training on a fragment of the one "
                "register this source was written to fill."
            )
        if not licensed:
            raise SourceError(
                f"activedirectory: {url} carries no {upstream.license_file}. "
                f"{upstream.repo} is declared {upstream.license_id} in this "
                "adapter and that claim is only worth something while the file "
                "it rests on is still there."
            )

        shutil.rmtree(home, ignore_errors=True)
        staging.replace(home)
        # Marker last, after the tree is in place under its final name.
        (home / _MARKER).write_text(
            json.dumps(
                {
                    "url": url,
                    "repo": upstream.repo,
                    "ref": upstream.ref,
                    "tarball_sha256": digest,
                    "files": written,
                    "oversize_members_skipped": oversize,
                    "license": upstream.license_id,
                    "license_note": upstream.license_note,
                    "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    finally:
        archive.unlink(missing_ok=True)
        shutil.rmtree(staging, ignore_errors=True)
    return home


def _sha256(path: Path) -> str:
    """Digest of the archive, recorded in the marker.

    A branch name is not a snapshot. Without this there is no way to say
    afterwards which state of ``main`` a given cache actually holds.
    """
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_COPY_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def _extract(archive: Path, staging: Path,
             upstream: _Upstream) -> tuple[int, int, bool]:
    """Unpack the wanted members into ``staging``; return (files, skipped, licence).

    Members are copied out by hand rather than through ``TarFile.extractall``.
    The tarballs are trusted in practice, but an archive member name is
    attacker-controlled data in principle — absolute paths, ``..`` segments and
    symlinks are all expressible in tar — and the cheap defence is to never hand
    the archive's own names to the filesystem unchecked. Only regular files are
    written, every destination is proved to resolve inside ``staging`` first, and
    no member over :data:`_MAX_MEMBER_BYTES` is read at all.
    """
    staging.mkdir(parents=True, exist_ok=True)
    resolved = staging.resolve()
    written = 0
    oversize = 0
    licensed = False

    try:
        with tarfile.open(archive, mode="r:gz") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                parts = Path(member.name).parts
                if len(parts) < 2:
                    continue
                # Drop codeload's single root directory, whose name moves with
                # the ref ("bloodhound-docs-main/").
                relative = Path(*parts[1:])
                if relative.is_absolute() or ".." in relative.parts:
                    continue
                posix = relative.as_posix()

                if posix == upstream.license_file:
                    destination = staging / "LICENSE"
                elif posix.startswith(upstream.keep) and relative.suffix == upstream.suffix:
                    destination = staging / relative
                else:
                    continue

                if member.size > _MAX_MEMBER_BYTES:
                    oversize += 1
                    continue
                if not destination.resolve().is_relative_to(resolved):
                    continue
                stream = tar.extractfile(member)
                if stream is None:
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True)
                with stream, destination.open("wb") as handle:
                    shutil.copyfileobj(stream, handle, _COPY_CHUNK)
                if destination.name == "LICENSE":
                    licensed = True
                else:
                    written += 1
    except (tarfile.TarError, OSError) as exc:
        raise SourceError(
            f"activedirectory: could not unpack {archive} for "
            f"{upstream.repo}: {exc}"
        ) from exc
    return written, oversize, licensed


# ---------------------------------------------------------------------------
# shared markdown machinery
# ---------------------------------------------------------------------------

#: A code fence and its info string, **allowing leading whitespace**. Neither
#: tree indents a fence today — counted, zero of 613 in The Hacker Recipes — but
#: the anchored form is the bug that cost a sibling adapter half its code blocks
#: and every rule below asks "is this line inside a command?" before acting.
#: The info string is captured because it decides whether a fence can *close*;
#: see :func:`_fence_scan`.
_FENCE = re.compile(r"^[ \t]*(`{3,}|~{3,})[ \t]*(.*?)[ \t]*$")

#: An ATX heading at column zero. Indented headings are not a thing either tree
#: writes, and requiring column zero means a ``# install the tools`` comment in a
#: bash block cannot be mistaken for one even before the fence map is consulted.
_HEADING = re.compile(r"^(#{1,6})[ \t]+(.+?)[ \t]*$")

#: ``![diagram](/assets/image-2-72.png)``. Removed outside fences only: the
#: images are repository assets that travel with a docs site and mean nothing in
#: a text corpus.
_IMAGE_REF = re.compile(r"!\[[^\]\n]*\]\([^)\n]*\)")

#: YAML front matter. Anchored at the very start, because ``---`` also opens a
#: thematic break in the middle of a page and there are 18 of those.
_FRONTMATTER = re.compile(r"\A---[ \t]*\r?\n(.*?)\r?\n---[ \t]*(?:\r?\n|\Z)", re.S)

#: ``T1558.003``. The join to :mod:`~training.corpus.sources.attack`, and in this
#: source it lives only in the front matter — see the module docstring.
_ATTACK_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

#: Leading decoration on a page title. The Hacker Recipes prefixes
#: work-in-progress pages with a hammer-and-wrench, which belongs in the body
#: where upstream put it and not in a labelled ``Technique:`` line.
_TITLE_DECORATION = re.compile(r"^[^\w(\[]+")

#: Split a page above this. Roughly two 1024-token windows of text this dense.
#: Keeping a page whole is always preferable — theory and practice are one
#: argument and the model should meet them together — so the threshold sits where
#: the window is already cutting the page anyway.
_SPLIT_ABOVE = 8_000

#: Target size of one part, and the size above which a section is re-cut one
#: heading level deeper. Sections are packed greedily to this; a section with no
#: deeper heading is never divided.
_PART_TARGET = 6_000

#: The smallest a part may be. Greedy packing strands fragments at both ends
#: without it: a page's header plus a two-line preamble becomes part one, and a
#: 200-character trailing section becomes its own document with a header three
#: times its length.
_MIN_PART = 1_200

#: Floor on a page's *prose*, in the sense :func:`_prose_chars` measures it:
#: what is left after the headings, the markdown links and the bare URLs come
#: out. A raw character floor does not work here, because the pages that have to
#: go are not short — they are **redirect stubs**, a work-in-progress title over
#: one or two links, and ``nbt-name-overwrite.md`` is 202 bytes of which 202 are
#: a heading and a Twitter URL.
#:
#: Measured over all 306 pages the distribution has a clean void in it. Six
#: pages score 0 or 1 (``proxyshell``, ``proxylogon``, ``local-files``,
#: ``password-managers``, ``nbt-name-overwrite``, ``privexchange``),
#: ``persistence/dacl.md`` scores 19 — a title and three conference-slide links
#: — and the next page up scores 81. All seven carry upstream's own
#: work-in-progress marker in their title. The threshold sits inside the void
#: rather than on top of a distribution.
_MIN_PROSE_CHARS = 40

#: Floor on a finished document, after the header and after normalise(). Only
#: reachable by a split part that turned out to be almost nothing, which the
#: packer already prevents; it is here so a Document constructor can never raise
#: mid-build over a source-quality problem.
_MIN_CHARS = 300

#: The three things :func:`_prose_chars` discounts. A stub page is made almost
#: entirely of them.
_LINK = re.compile(r"\[[^\]\n]*\]\([^)\n]*\)")
_BARE_URL = re.compile(r"https?://\S+")
_HEADING_LINE = re.compile(r"^#{1,6}[ \t].*$", re.M)
_PUNCTUATION = re.compile(r"[\s\-*_|>#]+")

_Section = tuple[tuple[str, ...], list[tuple[str, bool]]]


def _prose_chars(body: str) -> int:
    """How much of a page is writing rather than pointing somewhere else.

    Headings, markdown links and bare URLs are removed, then the leftover
    punctuation and whitespace, and what remains is counted. Fenced code is
    *not* removed, so a page that is a heading and four commands still scores
    high — the shape being detected is the redirect stub, not brevity.

    Collapsing whitespace here is not a breach of the
    :func:`~training.corpus.source.normalise` contract. This function measures;
    it never returns text, and nothing it does reaches a document.
    """
    stripped = _HEADING_LINE.sub("", body)
    stripped = _BARE_URL.sub("", _LINK.sub("", stripped))
    return len(_PUNCTUATION.sub(" ", stripped).strip())


def _fence_scan(lines: list[str]) -> tuple[list[tuple[str, bool]], bool]:
    """Pair every line with whether it is inside a fenced block.

    Returns the rows and whether the page ended with a fence still open. The
    fence line itself counts as inside, so a heading-shaped info string can
    never be read as a heading. Computed once and carried, because the image
    strip, the container rewrites, the choice of split points and the size
    measurement all need the same answer, and four independent walks would be
    four chances to disagree.

    **This is not a toggle, and the difference is not academic.** A naive
    "flip a boolean on every fence line" scanner inverts for the rest of the
    file the moment a page has an unbalanced fence — and one page does.
    ``ad/movement/credentials/dumping/sam-and-lsa-secrets.md`` is missing a
    closing backtick before ``=== Live Windows``, leaving thirteen fence lines
    in the file. Under a toggle, every line from that point on is "inside a
    fence", so the tab labels and container markers leak through untransformed,
    the headings stop being split points, and nothing says anything is wrong —
    the symptom of a regex that matches nothing is text that was not changed.

    So the CommonMark rule is implemented instead: a closing fence carries no
    info string and is at least as long as the one that opened it. Under that
    rule the stray ````` ```bash ````` is *content* of the block above it, the
    rest of the page pairs up correctly, and the file ends closed — which is
    also exactly what the upstream's own renderer does with it.
    """
    rows: list[tuple[str, bool]] = []
    marker = ""
    for line in lines:
        match = _FENCE.match(line)
        if match is None:
            rows.append((line, bool(marker)))
            continue
        run, info = match.group(1), match.group(2)
        rows.append((line, True))
        if not marker:
            marker = run
        elif not info and run[0] == marker[0] and len(run) >= len(marker):
            marker = ""
    return rows, bool(marker)


def _fence_rows(lines: list[str]) -> list[tuple[str, bool]]:
    return _fence_scan(lines)[0]


def _strip_images(rows: list[tuple[str, bool]]) -> list[tuple[str, bool]]:
    return [(line if inside else _IMAGE_REF.sub("", line), inside)
            for line, inside in rows]


def _size(body: list[tuple[str, bool]]) -> int:
    return sum(len(line) + 1 for line, _ in body)


def _cut(rows: list[tuple[str, bool]], level: int,
         path: tuple[str, ...]) -> list[_Section]:
    """Cut *rows* at ATX headings of depth *level* (or shallower at the top).

    Headings inside fenced blocks are not headings. Anything before the first
    boundary keeps the caller's *path*: it is the parent's own preamble, not a
    new section.
    """
    sections: list[_Section] = []
    heading = ""
    body: list[tuple[str, bool]] = []
    for line, inside in rows:
        match = None if inside else _HEADING.match(line)
        depth = len(match.group(1)) if match is not None else 0
        # The first pass takes H1 and H2 as siblings — a page's H1 is its title,
        # not a level its sections hang under. Deeper passes take one exact
        # level, so a parent heading is not re-read as a boundary and duplicated
        # into its children's trail.
        boundary = depth and (depth <= level if level <= 2 else depth == level)
        if boundary:
            if heading or any(text.strip() for text, _ in body):
                sections.append((path + ((heading,) if heading else ()), body))
            heading = match.group(2).strip()
            body = [(line, inside)]
            continue
        body.append((line, inside))
    if heading or any(text.strip() for text, _ in body):
        sections.append((path + ((heading,) if heading else ()), body))
    return sections


def _refine(path: tuple[str, ...], body: list[tuple[str, bool]],
            level: int) -> list[_Section]:
    """Divide an oversized section at ever deeper headings, or give up and keep it."""
    if level > 6 or _size(body) <= _PART_TARGET:
        return [(path, body)]
    pieces = _cut(body, level, path)
    if len(pieces) <= 1:
        return _refine(path, body, level + 1)  # nothing at this depth; go deeper
    refined: list[_Section] = []
    for child_path, child_body in pieces:
        refined.extend(_refine(child_path, child_body, level + 1))
    return refined


def _sections(rows: list[tuple[str, bool]]) -> list[_Section]:
    sections: list[_Section] = []
    for path, body in _cut(rows, 2, ()):
        sections.extend(_refine(path, body, 3))
    return sections


def _pack(sections: list[_Section]) -> list[list[_Section]]:
    """Group consecutive sections into parts of roughly :data:`_PART_TARGET`.

    Greedy and order-preserving. These pages read top to bottom — theory, then
    the command, then what it looks like when it fails — and reordering to pack
    more tightly would destroy the ordering the source was collected for. A part
    is not closed early just because the next section is large, which otherwise
    strands a page's preamble as a 200-character part one, and a short final
    section is folded back into its predecessor.
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


def _trail(title: str, sections: list[_Section]) -> list[str]:
    """The heading trail of a part, for the ``Part n of m`` line.

    The page's own H1 is a boundary like any other heading, so without dropping
    it every trail would open by repeating the title it already sits under.
    """
    named: list[str] = []
    for path, _ in sections:
        trail = " > ".join(heading for heading in path
                           if _clean_title(heading) != title)
        if trail and trail not in named:
            named.append(trail)
    return named


def _frontmatter(text: str) -> tuple[dict[str, str], str]:
    """Split YAML front matter from the body.

    Parsed by hand rather than with PyYAML. The fields wanted here are five flat
    scalars and the bodies are full of unquoted colons, apostrophes and
    trademark signs; a real YAML parse buys nothing and raises on a page whose
    author wrote ``description: ESC1: alternate subject name``, which is a page
    that should be in the corpus rather than a build failure.
    """
    match = _FRONTMATTER.match(text)
    if match is None:
        return {}, text
    meta: dict[str, str] = {}
    for line in match.group(1).split("\n"):
        key, sep, value = line.partition(":")
        if not sep or not key.strip() or key.startswith((" ", "\t", "-", "#")):
            continue
        meta[key.strip().lower()] = value.strip().strip("'\"")
    return meta, text[match.end():]


def _first_heading(lines: list[str]) -> str:
    for line, inside in _fence_rows(lines):
        if inside:
            continue
        match = _HEADING.match(line)
        if match is not None:
            return match.group(2).strip()
    return ""


def _clean_title(title: str) -> str:
    cleaned = _TITLE_DECORATION.sub("", title).strip()
    return cleaned or title.strip()


# ---------------------------------------------------------------------------
# The Hacker Recipes: VitePress containers
# ---------------------------------------------------------------------------

#: ``::: tabs`` / ``::: details Notes on Bastion Forests`` / ``::: warning`` /
#: a bare ``:::`` closing one of them. The kind may abut the colons
#: (``:::tabs`` occurs twice), which is why it is not required to be preceded by
#: a space.
_CONTAINER = re.compile(r"^:::[ \t]*([A-Za-z][A-Za-z-]*)?[ \t]*(.*?)[ \t]*$")

#: A tab label. Transformed **only** when the innermost open container is a tabs
#: container — see trap 3 in the module docstring, and the measurement that says
#: this can never collide with a setext heading underline.
_TAB_LABEL = re.compile(r"^===[ \t]+(.+?)[ \t]*$")


def _recipe_lines(body: str) -> list[str]:
    """Render The Hacker Recipes' container syntax down to plain markdown.

    A container stack rather than a counter: ``::: tabs`` and ``::: details``
    nest, and a bare ``:::`` has to know which of them it is closing before a
    following ``=== Windows`` can be judged.

    Everything inside a fenced block passes through untouched, which matters
    because these pages quote shell here-documents and YAML that begin lines with
    colons.
    """
    out: list[str] = []
    stack: list[str] = []
    for line, inside in _fence_rows(body.split("\n")):
        if inside:
            out.append(line)
            continue

        container = _CONTAINER.match(line)
        if container is not None:
            kind = (container.group(1) or "").lower()
            label = container.group(2).strip()
            if kind:
                stack.append(kind)
                # A tabs container is pure layout: its label lines carry the
                # information and the wrapper itself says nothing.
                if not kind.startswith("tab"):
                    out += ["", f"**{label or kind.capitalize()}**", ""]
                else:
                    out.append("")
            else:
                if stack:
                    stack.pop()
                out.append("")
            continue

        tab = _TAB_LABEL.match(line)
        if tab is not None and stack and stack[-1].startswith("tab"):
            out += ["", f"**{tab.group(1).strip()}**", ""]
            continue

        out.append(line)
    return out


def _recipe_pages(home: Path, upstream: _Upstream,
                  held: Counter) -> Iterator[tuple[str, list[str], list[str]]]:
    """Yield (ident, header, body lines) for every Hacker Recipes ``ad/`` page."""
    root = home / upstream.docs
    for path, relative in _walk(root, upstream.suffix):
        raw = _decode(path)
        if raw is None:
            continue
        meta, body = _frontmatter(raw)
        lines = _outside_fences("\n".join(_recipe_lines(body)),
                                _inline_html).split("\n")
        if _prose_chars(body) < _MIN_PROSE_CHARS:
            held["stub"] += 1
            continue

        title = _clean_title(meta.get("title") or _first_heading(lines)
                             or relative.stem.replace("-", " ").title())
        header = [f"Active Directory technique: {title}"]
        area = " > ".join(relative.parent.parts)
        if area:
            header.append(f"Area: {area}")
        attack = _ATTACK_ID.findall(meta.get("description", ""))
        if attack:
            header.append(f"ATT&CK: {', '.join(dict.fromkeys(attack))}")
        if authors := meta.get("authors"):
            # Kept because GPL-3.0 section 4 says to keep the notices, and this
            # is the only attribution these pages carry.
            header.append(f"Authors: {authors}")
        header.append(f"Reference: {_recipe_url(relative)}")
        yield f"recipes:ad/{relative.as_posix()}", header, lines


def _recipe_url(relative: Path) -> str:
    """The page's address on thehacker.recipes.

    ``index.md`` is the directory itself, every other page drops its extension.
    Both forms were checked against the live site rather than inferred.
    """
    parts = list(relative.parts)
    if relative.stem == "index":
        tail = "/".join(parts[:-1])
        tail = f"{tail}/" if tail else ""
    else:
        tail = "/".join(parts[:-1] + [relative.stem])
    return f"https://www.thehacker.recipes/ad/{tail}"


# ---------------------------------------------------------------------------
# BloodHound: MDX
# ---------------------------------------------------------------------------

#: ``import NtlmRelayGuidance from '/snippets/edges/ntlm-relay-guidance.mdx';``
_MDX_IMPORT = re.compile(
    r"^[ \t]*import[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]+from[ \t]+"
    r"['\"]([^'\"]+)['\"][ \t]*;?[ \t]*$"
)

#: ``{/* a note to the docs team */}``
_MDX_COMMENT = re.compile(r"\{/\*.*?\*/\}", re.S)

#: A screenshot and its wrapper. Dropped together: a ``<Frame>`` in this tree
#: contains an ``<img>`` and nothing else, and an empty frame teaches a shape
#: with nothing in it.
_FRAME_BLOCK = re.compile(r"<Frame\b[^>]*>.*?</Frame>", re.S)
_IMG_TAG = re.compile(r"<img\b[^>]*/?>", re.I)

#: Nine hand-written YouTube embeds, each about four hundred characters of
#: ``allow="accelerometer; autoplay; clipboard-write; …"``. Removed with their
#: content: the sentence above them ("See this clip for an example of this edge
#: being abused") survives and says what was there, and the attribute soup would
#: otherwise be the densest run of non-security text in the source.
_EMBED_BLOCK = re.compile(r"<iframe\b[^>]*>.*?</iframe>", re.S | re.I)

_SELF_CLOSING = re.compile(r"<([A-Z][A-Za-z0-9]*)((?:\s[^>]*?)?)\s*/>", re.S)
_OPEN_TAG = re.compile(r"<([A-Z][A-Za-z0-9]*)((?:\s[^>]*?)?)>", re.S)
_CLOSE_TAG = re.compile(r"</([A-Z][A-Za-z0-9]*)[ \t]*>")
_ATTR = re.compile(r"""([A-Za-z_][A-Za-z0-9_-]*)[ \t]*=[ \t]*(?:"([^"]*)"|'([^']*)')""")

#: ``<br/>`` becomes a space, not a newline. Most of the 48 occurrences are
#: inside table cells, where a newline would break the row apart and take the
#: column alignment with it.
_BR = re.compile(r"<br[ \t]*/?>", re.I)

#: Raw HTML that survives in both trees — GitBook leftovers in The Hacker
#: Recipes' tables (``<p>``, ``<a href>``, a ``<span data-gb-custom-inline>``
#: wrapped round an emoji) and a handful of hand-written tags in BloodHound.
#: Removed tag-only, so the text between the tags survives.
#:
#: **It is a whitelist for the same reason the component list is**, and this is
#: trap 1 mirrored into lowercase. A regex for "any lowercase HTML tag" also
#: matches ``<assets>`` (12), ``<attribute>`` (2), ``<rid>`` (2), ``<user>``,
#: ``<group>`` and ``<https://…>`` — twenty more placeholders standing in a
#: command where the operator substitutes a value. Every one of those is
#: content, and naming the fourteen tags that are markup is what keeps them.
_HTML_TAG = re.compile(
    r"</?(?:p|a|em|strong|b|i|u|code|div|span|sub|sup|kbd)\b[^>]*>", re.I)


def _inline_html(chunk: str) -> str:
    """Drop the inline HTML tags, keep everything they wrap."""
    return _HTML_TAG.sub("", _BR.sub(" ", chunk))

#: The documentation framework's own components. Together with the names a file
#: imports, this is the *entire* set of tags this adapter will touch — see trap 1
#: in the module docstring. ``<SHA1>`` is not on this list and never will be.
_MINTLIFY = frozenset({
    "Accordion", "AccordionGroup", "Callout", "Card", "CardGroup", "Check",
    "CodeGroup", "Columns", "Expandable", "Frame", "Icon", "Info", "Note",
    "ParamField", "ResponseField", "Snippet", "Step", "Steps", "Tab", "Tabs",
    "Tip", "Tooltip", "Update", "Warning",
})

#: How deep a snippet may include another snippet. None does today; the guard is
#: so that the day one includes itself the build reports a thin source rather
#: than dying in recursion.
_MAX_INCLUDE_DEPTH = 4

#: A page whose title is a bare identifier is an edge or a node, and BloodHound's
#: own overview states the naming rule this reads: "all Azure and Entra ID edges
#: are prefixed with 'AZ', while Active Directory edges have no prefix". Pages
#: with a prose title ("About BloodHound Edges") are not entities and get no
#: directory line, because for those the rule says nothing.
_ENTITY_TITLE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")


def _attrs(raw: str) -> dict[str, str]:
    return {name: (double if double is not None else single) or ""
            for name, double, single in _ATTR.findall(raw or "")}


def _outside_fences(text: str, transform) -> str:
    """Apply *transform* to the parts of *text* that are not fenced code.

    The MDX transforms below are regexes over uppercase-initial tags, and the
    command blocks in this tree are full of ``<SHA1>``-shaped placeholders. The
    known-name restriction is the first defence; this is the second, and it is
    the one that would still hold if upstream ever wrote a literal ``<Note>``
    inside a PowerShell block.
    """
    out: list[str] = []
    buffer: list[str] = []

    def flush() -> None:
        # An empty run between two adjacent fences contributes nothing; without
        # this it would contribute a blank line that was never in the source.
        if buffer:
            out.append(transform("\n".join(buffer)))
            buffer.clear()

    for line, inside in _fence_rows(text.split("\n")):
        if inside:
            flush()
            out.append(line)
        else:
            buffer.append(line)
    flush()
    return "\n".join(out)


def _take_imports(body: str) -> tuple[str, dict[str, str]]:
    """Strip MDX import lines, returning what they named and where it lives."""
    imports: dict[str, str] = {}
    kept: list[str] = []
    for line in body.split("\n"):
        match = _MDX_IMPORT.match(line)
        if match is not None:
            imports[match.group(1)] = match.group(2)
            continue
        if line.startswith("export "):
            continue
        kept.append(line)
    return "\n".join(kept), imports


def _snippet_key(target: str) -> str:
    """``/snippets/edges/x.mdx`` and ``../snippets/edges/x.mdx`` alike."""
    return target.split("snippets/", 1)[-1] if "snippets/" in target else target


def _expand(body: str, imports: dict[str, str], snippets: dict[str, str],
            depth: int) -> str:
    """Inline every imported snippet, substituting the props it was given.

    A snippet is real content — ``<NtlmRelayGuidance />`` is a paragraph of
    relay advice, ``<AltSecurityIdentitiesEsc14 edgeName="GenericAll" />`` is the
    sentence that connects this edge to ESC14 — so a page whose snippet cannot be
    resolved has quietly lost part of its abuse section. Unresolvable names
    become nothing rather than being left as a bare tag, which would put JSX into
    the corpus.
    """
    if depth > _MAX_INCLUDE_DEPTH:
        return body

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        target = imports.get(name)
        if target is None:
            return match.group(0)
        raw = snippets.get(_snippet_key(target))
        if raw is None:
            return ""
        _, inner = _frontmatter(raw)
        inner, inner_imports = _take_imports(inner)
        inner = _expand(inner, inner_imports, snippets, depth + 1)
        for key, value in _attrs(match.group(2)).items():
            inner = inner.replace("{" + key + "}", value)
        return "\n" + inner.strip() + "\n"

    return _outside_fences(body, lambda chunk: _SELF_CLOSING.sub(replace, chunk))


def _unwrap(body: str, known: frozenset[str]) -> str:
    """Remove the framework's own tags, keeping their children and their labels.

    ``<Tab title="Windows">`` is not decoration: the title says which operating
    system the block under it targets, exactly as The Hacker Recipes' tab labels
    do, so it survives as a bold line. Any tag whose name is not in *known* is
    left byte for byte where it was.
    """
    def transform(chunk: str) -> str:
        chunk = _MDX_COMMENT.sub("", chunk)
        chunk = _FRAME_BLOCK.sub("", chunk)
        chunk = _EMBED_BLOCK.sub("", chunk)
        chunk = _IMG_TAG.sub("", chunk)
        chunk = _SELF_CLOSING.sub(
            lambda m: "" if m.group(1) in known else m.group(0), chunk)

        def opening(match: re.Match[str]) -> str:
            if match.group(1) not in known:
                return match.group(0)
            attributes = _attrs(match.group(2))
            label = attributes.get("title") or attributes.get("label") or ""
            return f"\n\n**{label}**\n" if label else "\n"

        chunk = _OPEN_TAG.sub(opening, chunk)
        chunk = _CLOSE_TAG.sub(
            lambda m: "\n" if m.group(1) in known else m.group(0), chunk)
        return _inline_html(chunk)

    return _outside_fences(body, transform)


def _snippets(home: Path) -> dict[str, str]:
    """Every cached snippet, keyed by its path below ``snippets/``."""
    root = home / "docs" / "snippets"
    found: dict[str, str] = {}
    for path, relative in _walk(root, ".mdx"):
        raw = _decode(path)
        if raw is not None:
            found[relative.as_posix()] = raw
    return found


def _bloodhound_pages(home: Path, upstream: _Upstream,
                      held: Counter) -> Iterator[tuple[str, list[str], list[str]]]:
    """Yield (ident, header, body lines) for every BloodHound edge and node page."""
    snippets = _snippets(home)
    root = home / upstream.docs
    for path, relative in _walk(root, upstream.suffix):
        raw = _decode(path)
        if raw is None:
            continue
        meta, body = _frontmatter(raw)
        body, imports = _take_imports(body)
        body = _expand(body, imports, snippets, 0)
        body = _unwrap(body, frozenset(imports) | _MINTLIFY)
        if _prose_chars(body) < _MIN_PROSE_CHARS:
            held["stub"] += 1
            continue

        kind = "edge" if relative.parts and relative.parts[0] == "edges" else "node"
        title = _clean_title(meta.get("title")
                             or relative.stem.replace("-", " ").title())
        header = [f"BloodHound {kind}: {title}"]
        if _ENTITY_TITLE.match(title):
            header.append("Directory: " + ("Azure / Entra ID"
                                           if title.startswith("AZ")
                                           else "Active Directory"))
        if summary := meta.get("description"):
            header.append(f"Summary: {summary}")
        header.append(
            "Reference: https://bloodhound.specterops.io/resources/"
            f"{relative.parent.as_posix()}/{relative.stem}"
        )
        yield (f"bloodhound:resources/{relative.as_posix()}", header,
               body.split("\n"))


# ---------------------------------------------------------------------------
# documents
# ---------------------------------------------------------------------------

def _walk(root: Path, suffix: str) -> Iterator[tuple[Path, Path]]:
    """Every file under *root* with *suffix*, in a stable sorted order.

    ``os.walk(followlinks=False)`` rather than ``rglob``. This tree is one the
    adapter extracted itself and holds no links, but the rule is absolute in this
    package: an adapter once followed a symlink into the corpus cache and pulled
    180 MB of corpus back in as training data. ``followlinks=False`` only stops
    the walk *descending* into a symlinked directory, so a symlinked file is
    rejected separately.
    """
    if not root.is_dir():
        raise SourceError(
            f"activedirectory: no document tree at {root} — run the source's "
            "fetch() first"
        )
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        here = Path(dirpath)
        for name in sorted(filenames):
            if not name.endswith(suffix):
                continue
            path = here / name
            if path.is_symlink() or not path.is_file():
                continue
            yield path, path.relative_to(root)


def _decode(path: Path) -> str | None:
    """Read a page as text with its line endings normalised, or ``None``.

    The line endings are not cosmetic here and this cost an hour. The two
    upstreams disagree: The Hacker Recipes is checked in with LF and
    bloodhound-docs with **CRLF**, so every ``.mdx`` in this cache arrives with a
    ``\r`` on the end of every line. Each of this module's line regexes is
    anchored with ``$`` and applied to one line at a time, and ``$`` does not
    match before a lone carriage return — so on the CRLF half, ``_MDX_IMPORT``,
    ``_CONTAINER``, ``_TAB_LABEL`` and ``_HEADING`` all silently matched
    *nothing*. The first render looked plausible and shipped raw JSX and a
    literal ``import ... from '/snippets/…'`` line into the corpus, because the
    only symptom of a regex that matches nothing is text that was not
    transformed.

    :func:`~training.corpus.source.normalise` fixes line endings too, but it runs
    at the very end of the pipeline, which is several hundred failed matches too
    late. This is decoding, not cleaning: no horizontal whitespace is touched.
    """
    try:
        raw = path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    return raw.replace("\r\n", "\n").replace("\r", "\n")


def _emit(ident: str, header: list[str],
          lines: list[str], title: str) -> Iterator[Document]:
    """Turn one rendered page into one document, or several if it is long."""
    rows, unclosed = _fence_scan(lines)
    if unclosed:
        # Loud rather than silent: a page that ends inside a fence has a broken
        # block somewhere above, and every heading under it stopped being a
        # split point. Rendered anyway — the prose and the commands are all
        # still there, in order — but not quietly.
        print(f"   activedirectory: {ident} ends inside an unclosed code "
              "fence upstream; its later headings are not split points")
    rows = _strip_images(rows)
    if _size(rows) <= _SPLIT_ABOVE:
        groups: list[list[_Section]] = [[((), rows)]]
    else:
        groups = _pack(_sections(rows))

    total = len(groups)
    for index, part in enumerate(groups, start=1):
        block = list(header)
        if total > 1:
            trail = _trail(title, part)
            suffix = f": {'; '.join(trail)}" if trail else ""
            block.append(f"Part {index} of {total}{suffix}")
        body = [line for section in part for line, _ in section[1]]
        text = normalise("\n".join([*block, "", *body]))
        if len(text) < _MIN_CHARS:
            continue
        yield Document(
            text=text,
            source="activedirectory",
            register=Register.ADVERSARY,
            side=Side.RED,
            ident=ident if total == 1 else f"{ident}#{index}",
        )


def _documents(path: Path) -> Iterator[Document]:
    """Yield BloodHound's edges and nodes, then The Hacker Recipes' ``ad/`` tree.

    Held-back pages are counted and printed rather than dropped in silence: a
    source that quietly stops rendering half its upstream looks exactly like a
    source that was always that size.
    """
    cache = _resolve(path)
    seen: dict[str, str] = {}
    emitted = 0
    for upstream in _UPSTREAMS:
        home = cache / upstream.key
        if not (home / _MARKER).is_file():
            raise SourceError(
                f"activedirectory: {upstream.repo} is not in the cache at "
                f"{home} — run the source's fetch() first"
            )
        reader = (_bloodhound_pages if upstream.key == "bloodhound"
                  else _recipe_pages)
        held: Counter = Counter()
        pages = 0
        documents = 0
        for ident, header, lines in reader(home, upstream, held):
            # Fingerprint the body *without* the header. Ten of BloodHound's
            # node pages are a title over one shared, imported properties
            # table and nothing else — AZKeyVault, AZFunctionApp,
            # AZResourceGroup and seven more — so once the snippet is inlined
            # they are ten documents whose only unique content is the line
            # this adapter wrote. build.py's own dedup cannot catch that,
            # because the differing text is inside the document. Keeping them
            # would put the same 2.4 KB table into the corpus ten times, and
            # duplicated text in a corpus this size is worse than absent text:
            # it is what a model at ninety-odd epochs learns by heart.
            body = fingerprint("\n".join(lines))
            if body in seen:
                held["duplicate body"] += 1
                continue
            seen[body] = ident
            pages += 1
            title = _clean_title(header[0].partition(": ")[2])
            for document in _emit(ident, header, lines, title):
                documents += 1
                emitted += 1
                yield document
        note = ""
        if held:
            note = "; held back " + ", ".join(
                f"{count} {reason}" for reason, count in sorted(held.items()))
        print(f"   activedirectory: {upstream.label} — {pages} pages rendered "
              f"as {documents} documents [{upstream.license_id}]{note}")
    if not emitted:
        raise SourceError(
            "activedirectory: both upstreams rendered zero documents; the "
            "cache is present but its layout is not what this adapter expects"
        )


def _resolve(path: Path) -> Path:
    """Accept the cache directory, or either upstream's home inside it."""
    if path.is_dir() and all((path / up.key).is_dir() for up in _UPSTREAMS):
        return path
    if path.is_dir() and path.parent.is_dir() and all(
            (path.parent / up.key).is_dir() for up in _UPSTREAMS):
        return path.parent
    raise SourceError(
        f"activedirectory: {path} does not hold "
        f"{' and '.join(up.key for up in _UPSTREAMS)}/ — run fetch() first"
    )


#: Generated from :data:`_UPSTREAMS` rather than written out, so an upstream
#: cannot be added to this adapter without its terms reaching the build log and
#: the provenance table. The GPL half is named as non-permissive in its own
#: sentence rather than averaged into a single summary word, which is the point
#: ``yara`` and ``elastic`` make about composite licences.
_LICENSE = " ; ".join(
    ["Two upstreams, declared separately. Each LICENSE file was read from the "
     "fetched archive rather than from a badge, and is copied into the cache "
     "beside the text it covers"]
    + [f"{up.license_note} (https://github.com/{up.repo}/blob/{up.ref}/"
       f"{up.license_file})" for up in _UPSTREAMS]
)


SPEC = SourceSpec(
    name="activedirectory",
    license=_LICENSE,
    url=" and ".join(f"https://github.com/{up.repo}" for up in _UPSTREAMS),
    register=Register.ADVERSARY,
    side=Side.RED,
    fetch=_fetch,
    documents=_documents,
    #: 286 of the 311 upstream pages render, 35 of them split, for 375
    #: documents. The floor sits well below that so ordinary churn and page
    #: retirement are quiet, while a renamed directory, a changed front-matter
    #: convention or an MDX rewrite — the realistic regressions, each of which
    #: would halve this — trips it immediately.
    expect_min_docs=300,
    notes=(
        "Active Directory attack paths and tradecraft, from two upstreams that "
        "cut the domain perpendicularly. BloodHound's documentation gives one "
        "document per graph edge — meaning, Windows and Linux abuse, opsec "
        "considerations, edge schema, references — across every ACL primitive, "
        "ADCS ESC1-ESC13, all three delegation kinds, DCSync, LAPS/gMSA, trusts "
        "and the Entra edges, plus node property tables that join LDAP "
        "attribute names to why an attacker reads them. The Hacker Recipes' "
        "ad/ tree gives one document per technique, each split into a Theory "
        "section on the protocol and a Practice section that is 613 fenced "
        "blocks of bash and PowerShell. 375 documents, 1.37 MB. Front matter "
        "is mined rather than "
        "dropped: it is the only place the ATT&CK technique ids live, and the "
        "only place the GPL-required author attribution lives. MDX components "
        "are resolved against the names each file actually imports, so the "
        "seventeen <SHA1>-shaped placeholders inside commands survive. "
        "VitePress tab labels become bold lines, because '=== Windows' is the "
        "only thing saying which of two command sets is which and a raw '===' "
        "line is a setext heading. Pages over 8 KB are cut at their own "
        "headings, never inside a fence, and every part reopens with the full "
        "header. Seven redirect stubs and eighteen pages whose body is "
        "byte-identical to another page's are held back, counted and printed."
    ),
)
