"""Incident response playbooks — what a defender does *after* the finding. PROSE/BLUE.

Every other document in this corpus stops at the discovery. ATT&CK names a
behaviour, CAPEC orders one, Sigma matches one, NVD records a flaw, CISA reports
one that already happened. Not one of them says what a human being should do in
the twenty minutes after the alert fires: who is in charge, what gets cut off
first, what evidence dies if you reboot the box, what you are allowed to tell
the customer, and how you prove afterwards that the hole is actually shut.

That is the half of the engagement this project just grew. The agent finds a
detection gap, applies a fix, and re-attacks to prove closure — and the model
driving it had never read a single sentence about remediation as a discipline.
Incident response playbooks are that reasoning written down, and they are written
as *prose*: ordered, conditional, hedged English of the form "determine the
scope, and if you cannot determine the scope, contain as though it is everything".
PROSE sits at 1.8% against a 9% target, so the register and the content gap point
at the same hole, which is why narrative quality is the thing being optimised
here rather than volume.

**Four upstreams, because no one of them is the whole shape.** They are
complementary, not redundant, and the measurement below says so rather than the
adapter assuming it:

* ``guardsight`` — 68 Playbook Battle Cards, one per attack type, each laid out
  strictly as **P-I-C-E-R-L**: Preparation, Identification, Containment,
  Eradication, Recovery, Lessons Learned. This is the response cycle as a
  repeated skeleton across 68 different incidents, which is exactly how a
  sequence becomes learnable rather than memorable. Their titles carry ATT&CK
  tactic and technique names (*Lateral Movement - Pass the Hash*), so the
  identifier vocabulary the rest of the corpus teaches is re-used here in a
  sentence about what to do about it.
* ``counteractive`` — an incident response *plan*: assess, triage, communicate,
  and four deep investigation playbooks (ransomware, phishing, defacement,
  supply chain) that read as decision trees. Where GuardSight gives a checklist,
  this gives the reasoning under it — "find the ransom note; the note names the
  family; the family tells you whether decryption is even possible".
* ``pagerduty`` — the command structure. Incident Commander, Deputy, Scribe,
  Subject Matter Expert, Internal and Customer Liaison; severity levels; what to
  say on the call and what not to; blameless post-mortems. It includes a 76 KB
  near-verbatim transcript of a spoken training course, which is the most purely
  *narrative* English in this entire corpus — first person, digressive, arguing
  with the reader — and that is worth having on its own terms in a register
  starved of running sentences.
* ``react`` — the RE&CT framework: 216 atomic Response Actions, each with an
  ``RA####`` identifier and a stage, plus the six ``RS####`` stages and a
  composed playbook. This is ATT&CK's shape applied to the defensive half: a
  closed, enumerated vocabulary of moves ("RA3403: Block process by executable
  hash", "RA2205: Extract observables from email message") that lets a response
  be *named* rather than merely described. Nothing else in the corpus carries
  the ``RA####``/``RS####`` identifier system, and an agent that has to choose a
  remediation benefits from a catalogue of remediations that has names.

**Side is BLUE, and that is stated rather than fudged.** The corpus wants more
red, and this source gives it none. It was commissioned for the prose and
remediation gap specifically, and dressing defender documents as RED to flatter
a ratio would make the balance report lie about the only thing it measures.

**Licensing, checked file by file, and it turned up two things.**

Every LICENSE was read from the upstream tarball, not from a badge, and the
adapter re-reads it on every cold fetch and refuses the upstream if the text no
longer says what :data:`_UPSTREAMS` claims. Results: GuardSight MIT, PagerDuty
Apache-2.0, RE&CT Apache-2.0, Counteractive Apache-2.0 — the last one flagged
``NOASSERTION`` by GitHub's detector only because its LICENSE file is a short
grant rather than the full Apache text, which is a good example of why the
detector is not the source of truth.

The first real finding is inside Counteractive: its ``NOTICE`` states that the
content is **derived from PagerDuty's incident response documentation and from
CERT Société Générale's IRM under CC BY 3.0**. So a repository whose LICENSE
says Apache-2.0 carries a CC-BY-3.0 attribution obligation inside it — the same
class of trap as an MIT repository vendoring GPL files. The NOTICE is fetched
into the cache beside the pages and both upstream attributions are reproduced in
:data:`_LICENSE`.

The second is what that derivation does to the *corpus*, which matters more here
than the paperwork. Shingle overlap was measured between every Counteractive
page and the whole PagerDuty tree: ``reference/glossary.md`` is 76.3% shared,
``roles/index.md`` 58.4%, and the five ``roles/role-*.md`` files run 27.4-50.2%.
Those are rewrites of text this source already carries in full from the original,
and ``build.py``'s fingerprint dedup cannot see them — a fingerprint is
whole-document, and a 50% rewrite is a different document. They are excluded by
path. The four investigation playbooks and ``during.md`` score **0.0%** and 2.6%
and are the reason this upstream is here at all.

**Velociraptor is deliberately absent.** Its documentation is the obvious DFIR
tooling candidate and its LICENSE is
**CC BY-NC-SA 4.0** — NonCommercial. A model trained on it inherits a
restriction this project cannot honour, so it is refused for the same reason
:mod:`~training.corpus.sources._internal_unlicensed` is disabled: the licence is
a fact about the text, not an obstacle to route around.

**CERT Société Générale's IRM is absent for a duller reason.** Its licence is
fine — CC BY 3.0, read from ``LICENSE.md`` — but the 2022 repository ships 22
**PDFs** and nothing else. This package has no PDF dependency and a hand-rolled
extractor would produce soup out of a multi-column layout, which is worse than
absence. The material survives here second-hand and correctly attributed, since
Counteractive's playbooks are partly derived from it and GuardSight's README
names it as the inspiration for the battle cards.

**The markup traps, in the order they bit.**

*Angle brackets are not always tags.* GuardSight's SIM-swap card contains
``"Are you trying to log in from <City>, <State>?"`` — operator placeholders
inside prose, the same species as the ``<username>`` and ``<GPOName>``
metavariables that made a blanket HTML stripper unsafe in
:mod:`~training.corpus.sources._internal_unlicensed`. So :data:`_HTML_TAG` is a
**whitelist** of element names actually measured in these trees, not a generic
``<[^>]*>``. ``<City>`` and ``<State>`` are not HTML element names and survive
untouched.

*An input/label pair can be a whole document's worth of nothing.* PagerDuty's
training course renders each of its ~250 slides as
``<input type="checkbox" id="001" /><label for="001">![001](...jpeg)</label>``.
The images are not extracted, so after image removal those lines are pure
markup with no referent; they collapse to blank and the transcript underneath —
the thing worth having — is untouched. 170 ``<label>`` and 85 ``<input>`` tags,
all of them this.

*191 of Counteractive's 414 links point at ``#TODO-link-to-actual-resource``.*
They are fill-in-the-blank markers in a template, and an anchor has no referent
at all once the page is out of its site. A link whose target is a bare fragment
becomes its own link text; ``http`` and relative links are left exactly as
written, because a URL is real text and the corpus is full of them.

*GuardSight's markdown came out of a document converter and is
backslash-escaped* — 190 ``\\[``, 190 ``\\]``, 72 ``\\_``. Unescaped, but only
outside fenced blocks and only for the CommonMark-escapable punctuation set, so
a backslash inside a command can never be eaten. Measured: Counteractive and
PagerDuty contain zero such escapes, so the rule is a no-op on them.

*43% of GuardSight is a PNG.* 61 of the 68 cards embed the project banner as a
base64 data URI inside an ordinary image reference —
``![](data:image/png;base64,iVBORw0...)``, one 2.4 KB line per card,
**150,243 characters** in total. The image rule removes it as a matter of
course, which is why those documents halve in size without losing a word; it is
the same objection :mod:`~training.corpus.sources._internal_unlicensed` raises
against a DLL written out as decimal bytes, and here it needed no special case.

*RE&CT is read from its YAML, not from its rendered Markdown.* The ``docs/``
tree is generated, and it encodes list fields as ``<ul><li>`` **inside markdown
table cells** — 1,098 ``<li>`` tags. The ``response_actions/*.yml`` sources
behind it are clean, carry the same content, and have a ``workflow: |`` literal
block whose newlines and indentation are exactly what
:func:`~training.corpus.source.normalise` is written to preserve.

*47 of RE&CT's 216 response actions still hold the contributor template*
("Description of the workflow for the Response Action in markdown format."),
and 148 of them hold the template's placeholder ``author``,
``creation_date``, ``references`` and ``automation`` values. The 47 are held back
and counted, for the reason :mod:`~training.corpus.sources.capec` holds back
deprecated categories: as documents they are 47 near-identical texts whose only
unique content is a header, and the differing identifier sits *inside* the text
where fingerprint dedup cannot reach it. The placeholder field values are
dropped everywhere they appear, because 148 copies of
``author: your name/nickname/twitter`` is 148 copies of one line in a corpus
small enough to memorise it.

**Long pages are split at their own headings, never truncated**, on the same
argument :mod:`~training.corpus.sources._internal_unlicensed` makes: training
samples fixed-length windows out of a concatenated stream, so a 76 KB course
transcript would spend seventeen of its eighteen windows with nothing saying what
it is. A section with no deeper heading to cut at is emitted whole and oversized,
because overshooting a target is a cost and cutting a procedure in half is a
corruption.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tarfile
import time
from pathlib import Path
from typing import Iterator, NamedTuple

import yaml

from ..net import NetworkError, download
from ..source import Document, Register, Side, SourceError, SourceSpec, normalise

__all__ = ["SPEC"]


class _Upstream(NamedTuple):
    """One upstream repository and everything needed to justify its presence."""

    #: Directory name inside the cache and the first component of every ident,
    #: so a document in a build report can be traced back to its repository by
    #: string alone.
    key: str
    #: ``owner/name`` on GitHub.
    slug: str
    #: Branch to snapshot. Checked against each repository's declared default
    #: rather than assumed to be ``master`` — RE&CT and GuardSight publish from
    #: ``master``, and guessing here is how an adapter 404s silently.
    ref: str
    #: SPDX identifier, read from the repository's own licence file.
    license: str
    #: Path of that licence file inside the tarball, and a distinctive substring
    #: it must still contain. Re-checked on every cold fetch: a licence
    #: statement that has drifted from its source is worse than none, because it
    #: looks verified.
    license_file: str
    license_marker: str
    #: Extra provenance to cache beside the licence (Counteractive's NOTICE,
    #: which is where the CC-BY-3.0 obligation actually lives). Empty for none.
    notice_file: str
    #: Which renderer reads it: ``"markdown"`` or ``"react"``.
    kind: str
    #: File suffix to extract.
    suffix: str
    #: Path prefixes kept from the tarball, relative to the repository root. A
    #: prefix ending in ``/`` is a directory; anything else is an exact path.
    include: tuple[str, ...]
    #: Why this repository earns a place — the register argument, not marketing.
    why: str


#: The set. Adding an upstream is one tuple; the licence fields are not optional
#: and the marker is verified against the fetched file, not trusted.
_UPSTREAMS: tuple[_Upstream, ...] = (
    _Upstream(
        key="guardsight",
        slug="guardsight/gsvsoc_cirt-playbook-battle-cards",
        ref="master",
        license="MIT",
        license_file="LICENSE",
        license_marker="Permission is hereby granted, free of charge",
        notice_file="",
        kind="markdown",
        suffix=".md",
        # The repository also ships the same 68 cards as PDF and as rendered
        # HTML. Both are the markdown after a converter has been at it, which is
        # strictly worse input than the markdown itself.
        include=("Markdown/",),
        why=("68 Playbook Battle Cards, every one laid out P-I-C-E-R-L. The "
             "response cycle as a repeated skeleton across 68 incident types, "
             "with ATT&CK tactic and technique names in the titles"),
    ),
    _Upstream(
        key="counteractive",
        slug="counteractive/incident-response-plan-template",
        ref="master",
        license="Apache-2.0",
        license_file="LICENSE",
        license_marker="Apache License, Version 2.0",
        # The NOTICE is the whole reason this upstream needed careful reading:
        # it declares content derived from PagerDuty (Apache-2.0) and from CERT
        # Societe Generale's IRM (CC BY 3.0). See the module docstring.
        notice_file="NOTICE",
        kind="markdown",
        suffix=".md",
        # Measured, not chosen by taste. ``roles/`` and ``reference/glossary.md``
        # are 27.4-76.3% shingle-shared with the PagerDuty tree this source
        # already carries in full, and ``examples/plan.md`` is a pandoc
        # concatenation of every other page in the repository — 104 KB of
        # guaranteed duplicate that whole-document fingerprinting cannot catch.
        # ``README.md`` and ``about.md`` are project chrome about how to fill the
        # template in. What is left is the plan and the playbooks, which score
        # 2.6% and 0.0% against PagerDuty.
        include=("during.md", "after.md", "playbooks/"),
        why=("an incident response plan and four deep investigation playbooks "
             "that read as decision trees — the reasoning under the checklist"),
    ),
    _Upstream(
        key="pagerduty",
        slug="PagerDuty/incident-response-docs",
        ref="master",
        license="Apache-2.0",
        license_file="LICENSE",
        license_marker="Apache License",
        notice_file="",
        kind="markdown",
        suffix=".md",
        # docs/ is the content; everything outside it is mkdocs machinery, the
        # theme, and 170 images and slide JPEGs that are not extracted.
        include=("docs/",),
        why=("incident command as a discipline — roles, severity, call "
             "etiquette, post-mortems — including a 76 KB transcript of a "
             "spoken training course, the most narrative English in the corpus"),
    ),
    _Upstream(
        key="react",
        slug="atc-project/atc-react",
        ref="master",
        license="Apache-2.0",
        license_file="LICENSE",
        license_marker="Apache License",
        notice_file="",
        kind="react",
        suffix=".yml",
        # The YAML sources, never the generated docs/ tree. See the docstring:
        # the rendered markdown encodes its list fields as <ul><li> inside table
        # cells, 1,098 of them, and carries the same content.
        include=("response_actions/", "response_playbooks/", "response_stages/"),
        why=("RE&CT: 216 atomic Response Actions under RA#### identifiers and "
             "six RS#### stages — ATT&CK's shape applied to the defensive half, "
             "so a remediation can be named rather than only described"),
    ),
)

#: ``codeload`` tarballs rather than ``git clone --depth 1``: one request per
#: repository, no git binary, nothing left in the cache for a later ``pull`` to
#: mutate under a build that claims to be reproducible, and — the part that
#: matters — the transfer goes through :mod:`training.corpus.net` and therefore
#: through this package's one verifying TLS context. The same decision
#: ``sigma``, ``shellscripts`` and ``owasp`` made.
_TARBALL = "https://codeload.github.com/{slug}/tar.gz/refs/heads/{ref}"

#: Bumped when extraction or the include lists change in a way that would alter
#: what sits in the cache, so an old cache is rebuilt rather than silently
#: mixing two filter generations.
_CACHE_VERSION = 1

#: Per-upstream completion sidecar, written **last**, after every file for that
#: upstream is on disk and the directory has been swapped into place. An
#: interrupted fetch therefore re-fetches that one upstream instead of being
#: mistaken for a complete tree — and without re-downloading the ones that did
#: finish.
_SIDECAR = ".fetched.json"

#: Where the cached licence and notice land, next to the pages they cover.
_LICENSE_DIR = "provenance"

_TIMEOUT = 300

#: Per-upstream floor on extracted files. Set well under the observed counts
#: (68 / 7 / 36 / 223) so that a normal upstream edit cannot trip them, but
#: tight enough that a renamed directory — the failure that otherwise surfaces
#: as a mysteriously thin build report — fails at fetch time where the
#: diagnostic can name the URL.
_MIN_EXTRACTED: dict[str, int] = {
    "guardsight": 50,
    "counteractive": 5,
    "pagerduty": 25,
    "react": 180,
}

#: How many of the four must arrive. A transient codeload failure on one should
#: cost that upstream's share, not the build; three of four still spans the
#: checklist, the decision tree and the command structure. Two does not.
_MIN_UPSTREAMS = 3

#: Below this a rendering is a header with nothing under it. The smallest real
#: document in the set is a short RE&CT response action at roughly 350
#: characters including its header, so this sits under that with room.
_MIN_CHARS = 260

#: Split a page above this; leave anything at or below it whole. Roughly two to
#: three 1024-token training windows. Keeping a playbook whole is always
#: preferable — containment reads in the light of identification — so the
#: threshold sits where the training window is already cutting the flow anyway.
_SPLIT_ABOVE = 8_000

#: Target size for one part, and the size above which a section is re-cut at a
#: deeper heading level. Sections are packed greedily up to this; a section with
#: no deeper heading to cut at is emitted whole and oversized.
_PART_TARGET = 6_000

#: The smallest a part may be. Without it, greedy packing strands a page's
#: title and opening paragraph as a part of their own.
_MIN_PART = 1_200

#: Fraction of non-blank, non-fenced lines that must be a bullet holding one
#: bare link before a page with no code fence is treated as an index rather than
#: as writing.
#:
#: **No page in these trees trips it today**, and that is stated rather than
#: implied: measured over all 112 markdown pages the highest score is 0.25
#: (``after/effective_post_mortems.md``), then 0.10 and 0.07. Even PagerDuty's
#: ``resources/reading.md``, which really is a bibliography, scores low because
#: every entry carries an author after the link and is therefore a sentence
#: about a book rather than a bare pointer. The rule is kept because these four
#: repositories are the kind that grow index pages — GuardSight already ships a
#: README that is nothing but links, and the day it moves into ``Markdown/`` the
#: adapter should drop it without anyone editing a filename list.
_STUB_LINK_RATIO = 0.40

#: An opening or closing code fence, **allowing leading whitespace**, because a
#: fence indented under a list bullet is still a fence and every rule below that
#: asks "is this line inside a command?" must answer correctly for it. These
#: trees are nearly fence-free today (two lines in one Counteractive page), and
#: that is exactly why the map is built rather than assumed: the day a playbook
#: gains a command block, the cleaning and splitting rules must already be
#: keeping their hands off it.
_FENCE = re.compile(r"^[ \t]*(`{3,}|~{3,})")

#: An ATX heading at column zero. GuardSight writes its single heading at H5,
#: PagerDuty's course transcript uses H3 throughout and no H1 at all, so the
#: level is read rather than required.
_HEADING = re.compile(r"^(#{1,6})[ \t]+(.+?)[ \t]*$")

#: ``![alt](path)``. The images are not extracted, so the reference has no
#: referent and the alt text in these trees is a slug or a slide number.
#:
#: This rule turns out to be doing much more than tidying. 61 of GuardSight's 68
#: cards embed the project banner as a **base64 data URI inside the image
#: reference** — ``![](data:image/png;base64,iVBORw0...)``, one 2.4 KB line per
#: card, **150,243 characters, 43% of that upstream's markdown**. That is the
#: same hazard :mod:`~training.corpus.sources._internal_unlicensed` elides by
#: hand as "machine-encoded binary is not writing", and here the ordinary image
#: rule catches it for free: mechanically generated text at volume is exactly
#: what a small model at many epochs memorises, and a PNG teaches nothing about
#: incident response. Nothing else is lost with it — the 68 cards keep every
#: word, and their character counts halve purely because the banner goes.
_IMAGE_REF = re.compile(r"!\[[^\]\n]*\]\([^)\n]*\)")

#: HTML element names actually measured across these trees, and **only** those.
#: A generic ``<[^>]*>`` would also eat ``<City>``, ``<State>``, ``<username>``
#: and every other operator placeholder written in angle brackets inside prose —
#: the trap that cost a sibling adapter a hundred commands' worth of operands.
#: Matching by name means a placeholder is invisible to this rule by
#: construction rather than by luck.
_HTML_NAMES = (
    "a|abbr|b|blockquote|br|code|dd|details|div|dl|dt|em|h1|h2|h3|h4|h5|h6|hr|"
    "i|iframe|img|input|label|li|ol|p|pre|small|span|strong|sub|summary|sup|"
    "table|tbody|td|tfoot|th|thead|tr|ul"
)
_HTML_TAG = re.compile(rf"</?(?:{_HTML_NAMES})\b[^>]*>", re.IGNORECASE)
_HTML_BR = re.compile(r"<br\b[^>]*>", re.IGNORECASE)
_HTML_LI = re.compile(r"<li\b[^>]*>", re.IGNORECASE)
#: An iframe's content is the embedded video, which is not text at all; the
#: whole element goes rather than leaving its fallback text stranded.
_HTML_IFRAME = re.compile(r"<iframe\b[^>]*>.*?</iframe>", re.IGNORECASE | re.DOTALL)

#: Python-Markdown attribute lists — ``{:target="_blank"}``, ``{: .class }``.
#: Rendering instructions, 107 of them in the PagerDuty tree, no content.
_ATTR_LIST = re.compile(r"\{:[^}\n]*\}")

#: mkdocs admonitions: ``!!! warning "Security Incident?"``, ``???+ note``. The
#: body is indented underneath and is real text, so only the marker line is
#: rewritten — into a plain labelled line that says the same thing.
_ADMONITION = re.compile(r"^(?P<indent>[ \t]*)(?:!!!|\?\?\?\+?)[ \t]*"
                         r"(?P<kind>[A-Za-z][\w-]*)"
                         r"(?:[ \t]+\"(?P<title>[^\"\n]*)\")?[ \t]*$")

#: A markdown link whose target is a bare fragment. 191 of Counteractive's links
#: are ``#TODO-link-to-actual-resource`` placeholders and every anchor loses its
#: referent the moment the page leaves its site, so the link text is kept and
#: the target dropped. ``http`` and relative targets are untouched.
_ANCHOR_LINK = re.compile(r"\[([^\]\n]*)\]\(#[^)\n]*\)")

#: CommonMark's escapable punctuation. GuardSight's markdown came out of a
#: converter and carries 452 of these; the other markdown trees carry none, so
#: unescaping is measured-safe here. Applied outside fenced blocks only, so a
#: backslash inside a command is never touched.
_MD_ESCAPE = re.compile(r"\\([!\"#$%&'()*+,\-./:;<=>?@\[\\\]^_`{|}~])")

#: A list item whose entire content is one markdown link — the shape a
#: bibliography page is made of. An entry with trailing prose does not match,
#: which is what separates a page of links from a page with links in it.
_LINK_ONLY = re.compile(
    r"^[ \t]*(?:[-*+]|\d+\.)[ \t]+\[[^\]\n]*\]\([^)\n]*\)[ \t]*$")

#: Markdown emphasis, removed from a *title* only — never from body text, where
#: the bold on "**Stay calm and professional.**" is the author telling you which
#: step matters. GuardSight writes every heading as
#: ``##### CIRT Playbook Battle Card: **GSPBC-1013 - Impact - Defacement**``, and
#: a title that keeps one asterisk pair and loses the other reads as corruption.
_EMPHASIS = re.compile(r"\*\*|__|~~|`")

#: RE&CT template placeholder values. 148 of the 216 response actions still
#: carry at least one. Emitted, they would be 148 identical lines in a corpus
#: small enough to learn them by heart; they say nothing about incident response
#: either way.
_REACT_PLACEHOLDERS = frozenset({
    "your name/nickname/twitter",
    "yyyy/mm/dd",
    "https://example.com",
    "thehive/phantom/demisto/etc",
    "name of the analytics",
    "name_of_the_analytics",
})

#: The sentence the contributor template puts in an unwritten workflow. An
#: action still carrying it has no content beyond its own header.
_REACT_TEMPLATE_WORKFLOW = "Description of the workflow for the Response Action"

#: RE&CT stage keys, in the order the framework runs them. Used to order a
#: playbook's sections and to resolve a response action's stage to its RS id;
#: an unknown key would mean upstream added a stage, which is worth saying out
#: loud rather than sorting alphabetically and hoping.
_REACT_STAGES: tuple[tuple[str, str, str], ...] = (
    ("preparation", "RS0001", "Preparation"),
    ("identification", "RS0002", "Identification"),
    ("containment", "RS0003", "Containment"),
    ("eradication", "RS0004", "Eradication"),
    ("recovery", "RS0005", "Recovery"),
    ("lessons_learned", "RS0006", "Lessons learned"),
)

#: ``attack.t1566.001`` in RE&CT's tag vocabulary is ``T1566.001`` in the form
#: the world writes it and the form the rest of this corpus teaches. Restored
#: for the reason :mod:`~training.corpus.sources.capec` restores it: emitted as
#: written, a lower-case dotted token is indistinguishable from a version
#: number and is worth nothing to a tokenizer that has to recognise the
#: identifier in a threat report.
_ATTACK_TAG = re.compile(r"^attack\.t(\d{4})(?:\.(\d{3}))?$", re.IGNORECASE)

#: Reproduced in :data:`SPEC` and written into the cache. Long, because the
#: honest answer is long: four upstreams, one of which carries a second
#: upstream's copyleft-flavoured attribution obligation inside an Apache-2.0
#: repository. The precedent is :mod:`~training.corpus.sources.netrules`, which
#: states its composite per feed rather than rounding to the most common one.
_LICENSE = (
    "Composite, one statement per upstream, each read from that repository's "
    "own licence file at fetch time and refused if the file no longer says it. "
    "(1) guardsight/gsvsoc_cirt-playbook-battle-cards: MIT, Copyright (c) 2019 "
    "GuardSight, Inc. (2) PagerDuty/incident-response-docs: Apache-2.0, "
    "Copyright 2016 PagerDuty, Inc. (3) atc-project/atc-react (RE&CT): "
    "Apache-2.0. (4) counteractive/incident-response-plan-template: Apache-2.0, "
    "Copyright 2018 Counteractive Security — and its NOTICE, cached alongside, "
    "declares content derived from PagerDuty's Incident Response Documentation "
    "(Apache-2.0) and from the CERT Societe Generale Incident Response "
    "Methodologies under the Creative Commons Attribution 3.0 Unported "
    "licence, so CC-BY-3.0 attribution to CERT Societe Generale rides along "
    "with that upstream and is reproduced here. Every LICENSE and the NOTICE "
    "are copied into the cache under provenance/."
)


# ---------------------------------------------------------------------------
# fetch
# ---------------------------------------------------------------------------

def _wanted(upstream: _Upstream, member_name: str) -> str | None:
    """Map a tar member to its cache-relative path, or ``None`` to skip it.

    Codeload wraps the tree in ``<repo>-<ref>/``, whose name moves with the ref,
    so the first component is dropped rather than matched. Traversal segments are
    refused here as well as at the filesystem, because a member name is
    attacker-controlled data in the general case and the cheap defence is to
    never hand it to the filesystem unchecked.
    """
    parts = member_name.split("/")[1:]
    if not parts or any(part in ("", ".", "..") for part in parts):
        return None
    relative = "/".join(parts)

    if relative == upstream.license_file:
        return f"{_LICENSE_DIR}/{upstream.license_file}"
    if upstream.notice_file and relative == upstream.notice_file:
        return f"{_LICENSE_DIR}/{upstream.notice_file}"

    if not relative.endswith(upstream.suffix):
        return None
    for prefix in upstream.include:
        if prefix.endswith("/"):
            if relative.startswith(prefix):
                return relative
        elif relative == prefix:
            return relative
    return None


def _extract(upstream: _Upstream, archive: Path, staging: Path) -> int:
    """Unpack one upstream's wanted members into *staging*. Returns the count.

    The count excludes the provenance sidecars, so a tarball whose content
    directory was renamed still reports zero even though its LICENSE came out of
    it — the caller's "upstream moved" diagnostic depends on that distinction.

    Members are written one at a time rather than through ``extractall``: the
    ``filter="data"`` argument that makes ``extractall`` safe is 3.12 and later,
    and this package targets 3.10. Only regular files are written and every
    destination is proved to resolve inside *staging* first.
    """
    staging.mkdir(parents=True, exist_ok=True)
    resolved = staging.resolve()
    written = 0
    try:
        with tarfile.open(archive, "r:gz") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                relative = _wanted(upstream, member.name)
                if relative is None:
                    continue
                target = staging / relative
                if not target.resolve().is_relative_to(resolved):
                    continue  # traversal attempt; refuse the member
                source = tar.extractfile(member)
                if source is None:
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with source, target.open("wb") as handle:
                    shutil.copyfileobj(source, handle)
                if not relative.startswith(f"{_LICENSE_DIR}/"):
                    written += 1
    except (tarfile.TarError, OSError) as exc:
        raise SourceError(f"dfir: could not unpack {archive}: {exc}") from exc
    return written


def _verify_license(upstream: _Upstream, staging: Path) -> None:
    """Refuse an upstream whose licence file no longer says what we claim.

    This is the check that makes :data:`_LICENSE` a statement rather than a
    memory. Three briefs in this project have named a licence wrongly and the
    only thing that caught it was reading the file; re-reading it on every cold
    fetch is the same act, automated, so that a relicensing upstream stops the
    build instead of quietly invalidating a sentence nobody re-reads.
    """
    path = staging / _LICENSE_DIR / upstream.license_file
    if not path.is_file():
        raise SourceError(
            f"dfir: {upstream.slug} no longer ships {upstream.license_file}. "
            "An upstream that has dropped its licence file is "
            "all-rights-reserved until proven otherwise; do not train on it."
        )
    text = path.read_text(encoding="utf-8", errors="replace")
    if upstream.license_marker not in text:
        raise SourceError(
            f"dfir: {upstream.slug}'s {upstream.license_file} no longer contains "
            f"{upstream.license_marker!r}. This adapter declares it as "
            f"{upstream.license}; read the new file and update _UPSTREAMS "
            "rather than training on text whose terms have changed."
        )
    if upstream.notice_file and not (
            staging / _LICENSE_DIR / upstream.notice_file).is_file():
        raise SourceError(
            f"dfir: {upstream.slug} no longer ships {upstream.notice_file}, "
            "which is where its third-party attribution obligations are "
            "declared. Read what replaced it before re-enabling this upstream."
        )


def _count_files(root: Path) -> int:
    """Count cached files under one upstream directory, sidecar excluded."""
    total = 0
    for _, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        total += sum(1 for name in filenames if name != _SIDECAR)
    return total


def _fetch_upstream(cache_dir: Path, upstream: _Upstream) -> dict | None:
    """Download and unpack one upstream. Returns its sidecar, or ``None``.

    The warm path is free and network-free: a sidecar of the current cache
    version whose recorded file count still matches what is on disk means this
    upstream is done. Counting rather than trusting the sidecar alone catches a
    cache that was copied between volumes or half cleaned — this source's cache
    lives on an external disk, where exactly that happens.
    """
    target = cache_dir / upstream.key
    sidecar = target / _SIDECAR
    if sidecar.is_file():
        try:
            recorded = json.loads(sidecar.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            recorded = {}
        # ``cached_files`` counts everything on disk, provenance included, while
        # ``files`` counts only the content. Comparing the former is what makes
        # this a check rather than a restatement: the two upstreams differ in how
        # many provenance files they carry, and a subtraction hardcoded for one
        # of them would silently accept a half-populated cache for the other.
        if (recorded.get("version") == _CACHE_VERSION
                and recorded.get("slug") == upstream.slug
                and recorded.get("ref") == upstream.ref
                and recorded.get("files", 0) > 0
                and recorded.get("cached_files") == _count_files(target)):
            return recorded

    url = _TARBALL.format(slug=upstream.slug, ref=upstream.ref)
    archive = cache_dir / f".{upstream.key}.tar.gz"
    staging = cache_dir / f".{upstream.key}.incoming"
    try:
        try:
            # net.download writes a .part sibling and renames it, so an
            # interrupted transfer cannot leave a truncated archive behind.
            download(url, archive, timeout=_TIMEOUT)
        except NetworkError as exc:
            raise SourceError(f"dfir: {upstream.slug}: {exc}") from None

        shutil.rmtree(staging, ignore_errors=True)
        written = _extract(upstream, archive, staging)
        floor = _MIN_EXTRACTED[upstream.key]
        if written < floor:
            raise SourceError(
                f"dfir: {upstream.slug} yielded only {written} {upstream.suffix} "
                f"files under {', '.join(upstream.include)} (expected >= "
                f"{floor}). The upstream layout has probably changed; fix the "
                "include list rather than training on a fragment of it."
            )
        _verify_license(upstream, staging)

        # Swap into place only once staging is known good, so a reader never
        # sees a half-unpacked upstream. The sidecar is written after the swap,
        # which is what makes an interrupted fetch re-fetch rather than look
        # complete.
        shutil.rmtree(target, ignore_errors=True)
        staging.replace(target)
        recorded = {
            "version": _CACHE_VERSION,
            "slug": upstream.slug,
            "ref": upstream.ref,
            "url": f"https://github.com/{upstream.slug}",
            "license": upstream.license,
            "license_file": f"{_LICENSE_DIR}/{upstream.license_file}",
            "notice_file": (f"{_LICENSE_DIR}/{upstream.notice_file}"
                            if upstream.notice_file else ""),
            "files": written,
            "cached_files": _count_files(target),
            # The argument for the upstream, carried into the cache. A cache
            # that cannot say why its contents are training data is one nobody
            # can audit six months later.
            "why": upstream.why,
            "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        sidecar.write_text(json.dumps(recorded, indent=1), encoding="utf-8")
        return recorded
    except Exception as exc:  # noqa: BLE001 - reported, see below
        # One upstream failing is survivable — _fetch decides whether enough of
        # the set arrived — so this reports and returns rather than raising.
        print(f"   ! dfir: {upstream.slug}: {type(exc).__name__}: {exc}")
        return None
    finally:
        archive.unlink(missing_ok=True)
        shutil.rmtree(staging, ignore_errors=True)


def _fetch(cache_dir: Path) -> Path:
    """Populate *cache_dir* with all four upstreams and return it."""
    cache_dir.mkdir(parents=True, exist_ok=True)

    fetched: list[dict] = []
    for upstream in _UPSTREAMS:
        recorded = _fetch_upstream(cache_dir, upstream)
        if recorded is not None:
            fetched.append(recorded)

    if len(fetched) < _MIN_UPSTREAMS:
        raise SourceError(
            f"dfir: only {len(fetched)} of {len(_UPSTREAMS)} upstreams could be "
            f"fetched, below the floor of {_MIN_UPSTREAMS}. This source's "
            "argument is that the checklist, the decision tree, the command "
            "structure and the named-action catalogue are four different "
            "shapes of the same knowledge; built from one of them it teaches "
            "one house's habits as if they were the discipline."
        )

    # The manifest is the last thing written, for the same reason each sidecar
    # is: its presence is the claim that the whole fetch finished.
    (cache_dir / "manifest.json").write_text(
        json.dumps({"version": _CACHE_VERSION, "license": _LICENSE,
                    "upstreams": fetched}, indent=1),
        encoding="utf-8",
    )
    return cache_dir


# ---------------------------------------------------------------------------
# shared text helpers
# ---------------------------------------------------------------------------

def _files(root: Path, suffix: str) -> list[tuple[str, Path]]:
    """Every wanted file under *root*, as ``(relative posix path, path)``.

    Walked with ``os.walk(..., followlinks=False)`` rather than ``rglob``. The
    rule is absolute in this package: a sibling adapter once followed a symlink
    out of its own directory and pulled 180 MB of the corpus cache back in as
    training data. ``followlinks=False`` only stops the walk *descending* into a
    symlinked directory, so symlinked files are rejected explicitly too. Sorted,
    so the corpus is byte-reproducible across builds.
    """
    found: list[tuple[str, Path]] = []
    if not root.is_dir():
        return found
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        if Path(dirpath).name == _LICENSE_DIR:
            continue
        for filename in sorted(filenames):
            if not filename.endswith(suffix):
                continue
            file = Path(dirpath) / filename
            if file.is_symlink() or not file.is_file():
                continue
            found.append((file.relative_to(root).as_posix(), file))
    found.sort()
    return found


def _fence_map(lines: list[str]) -> list[bool]:
    """True for every line inside a fenced block, delimiters included.

    This is the primitive the cleaning and splitting rules stand on. Marking the
    delimiters themselves as inside is deliberate: the fence line and its info
    string are part of the block and must never be edited or split away from it.
    A page that ends while still open leaves its tail marked as fenced, which
    fails safe — the tail is passed through untouched and unsplit rather than cut
    somewhere inside a command.
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


def _strip_front_matter(lines: list[str]) -> tuple[list[str], dict[str, str]]:
    """Remove a leading YAML front-matter block; return it as a flat mapping.

    All 36 PagerDuty pages carry one and it holds a one-sentence ``description``
    that is genuinely the best summary of the page — worth hoisting into the
    header rather than discarding with the ``cover:`` and ``hero:`` image paths
    around it. Parsed by hand rather than with ``yaml.safe_load`` because only
    scalar keys are wanted and a front-matter block is not required to be valid
    YAML for the page under it to be worth reading.
    """
    if not lines or lines[0].strip() != "---":
        return lines, {}
    for index in range(1, len(lines)):
        if lines[index].strip() == "---":
            meta: dict[str, str] = {}
            for line in lines[1:index]:
                key, sep, value = line.partition(":")
                if sep and key.strip() and not key.startswith((" ", "\t", "-")):
                    meta[key.strip().lower()] = value.strip().strip("\"'")
            return lines[index + 1:], meta
    # No closing delimiter: this is not front matter, it is a horizontal rule
    # on line one. Leave the page exactly as written.
    return lines, {}


def _clean_line(line: str) -> str:
    """Strip markup with no referent from one non-fenced line.

    Order matters and each step is measured in the module docstring. Iframes go
    whole; images go; whitelisted HTML tags become their inner text, with
    ``<br>`` a newline and ``<li>`` a bullet; attribute lists go; anchor-only
    links keep their text; converter backslash escapes are undone. A line left
    holding nothing but whitespace becomes empty, and
    :func:`~training.corpus.source.normalise` folds the blank run — which is how
    250 slide-widget lines in the PagerDuty course disappear without touching a
    word of the transcript around them.
    """
    line = _HTML_IFRAME.sub("", line)
    line = _IMAGE_REF.sub("", line)
    line = _HTML_BR.sub("\n", line)
    line = _HTML_LI.sub("- ", line)
    line = _HTML_TAG.sub("", line)
    line = _ATTR_LIST.sub("", line)
    line = _ANCHOR_LINK.sub(r"\1", line)
    line = _MD_ESCAPE.sub(r"\1", line)
    return line if line.strip() else ""


def _clean(lines: list[str], fenced: list[bool]) -> list[str]:
    """Clean every non-fenced line; pass fenced lines through untouched.

    An admonition marker is rewritten in place rather than dropped: ``!!! warning
    "Security Incident?"`` carries a real instruction, and its indented body
    below it is real text that would be orphaned if the marker vanished.
    """
    out: list[str] = []
    for line, in_fence in zip(lines, fenced):
        if in_fence:
            out.append(line)
            continue
        admonition = _ADMONITION.match(line)
        if admonition is not None:
            kind = admonition.group("kind").replace("-", " ").capitalize()
            title = admonition.group("title")
            body = f"{kind}: {title}" if title else f"{kind}:"
            out.append(f"{admonition.group('indent')}{body}")
            continue
        cleaned = _clean_line(line)
        # A <br> became a newline, so one input line can become several.
        out.extend(cleaned.split("\n"))
    return out


def _link_ratio(lines: list[str], fenced: list[bool]) -> float:
    """Share of non-blank, non-fenced lines that are a bullet and one bare link.

    The discriminator for a bibliography page. Fenced lines are excluded from
    both halves so a page of commands cannot be diluted into looking like an
    index, and a page of links cannot be rescued by one.
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


# ---------------------------------------------------------------------------
# splitting
# ---------------------------------------------------------------------------

#: A section of a page: the trail of headings that led to it, outermost first,
#: and its rows as ``(line, is_inside_a_fence)`` pairs. The trail is carried
#: rather than recomputed because a section cut out of the middle of a page no
#: longer has its ancestors above it, and in a playbook those ancestors are the
#: phase — a containment step read without "Containment" over it is advice with
#: its precondition removed.
_Section = tuple[tuple[str, ...], list[tuple[str, bool]]]


def _size(rows: list[tuple[str, bool]]) -> int:
    """Characters a row list will occupy, newlines included."""
    return sum(len(line) + 1 for line, _ in rows)


def _cut(rows: list[tuple[str, bool]], level: int,
         path: tuple[str, ...]) -> list[_Section]:
    """Cut *rows* at ATX headings of depth *level* (or shallower at the top).

    Headings inside fenced blocks are not headings. Anything before the first
    boundary keeps the caller's *path* — it is the parent's own preamble, not a
    new section.
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


def _refine(path: tuple[str, ...], body: list[tuple[str, bool]],
            level: int) -> list[_Section]:
    """Recursively divide an oversized section at ever deeper headings.

    A section with nothing to cut at any level is returned whole and oversized,
    because overshooting the target is a cost and cutting a procedure in half is
    a corruption, and the two are not comparable.
    """
    if level > 6 or _size(body) <= _PART_TARGET:
        return [(path, body)]
    pieces = _cut(body, level, path)
    if len(pieces) <= 1:
        return _refine(path, body, level + 1)  # nothing here; go deeper
    refined: list[_Section] = []
    for child_path, child_body in pieces:
        refined.extend(_refine(child_path, child_body, level + 1))
    return refined


def _sections(rows: list[tuple[str, bool]]) -> list[_Section]:
    """Cut a page into sections small enough to pack, descending as needed.

    PagerDuty's training course is the case that forces the descent: 76 KB with
    no H1 or H2 anywhere, one ``### Slide title`` per slide. Left at the top
    level it would be a single indivisible section and the split would do
    nothing at all.
    """
    sections: list[_Section] = []
    for path, body in _cut(rows, 2, ()):
        sections.extend(_refine(path, body, 3))
    return sections


def _pack(sections: list[_Section]) -> list[list[_Section]]:
    """Group consecutive sections into parts of roughly :data:`_PART_TARGET`.

    Greedy and order-preserving. A playbook reads top to bottom — prepare,
    identify, contain, eradicate, recover, learn — and reordering sections to
    pack more tightly would destroy the one thing this source was collected for.
    A short final part is folded back into its predecessor rather than shipped as
    a fragment wearing a header.
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


# ---------------------------------------------------------------------------
# markdown upstreams
# ---------------------------------------------------------------------------

def _title(lines: list[str], fenced: list[bool], meta: dict[str, str],
           ident: str) -> str:
    """A name for the page: front-matter title, then first heading, then path.

    Front matter wins where it exists, and only two pages in these trees have a
    ``title:`` — both of them the cases where the heading is actively wrong.
    ``docs/training/courses/incident_response.md`` opens on ``### Introduction``,
    the name of its first slide, so twelve parts of a course would all be called
    "Introduction"; its front matter says *Incident Response Training*.

    Otherwise the first heading of *any* level, not the first H1. GuardSight
    writes its single heading at H5 and the course transcript has no H1 anywhere,
    so requiring level one would hand both of them a filename instead of the name
    their author gave them. Emphasis markers are removed because GuardSight
    wraps its heading text in ``**`` and a half-stripped pair reads as damage.
    """
    if meta.get("title"):
        return meta["title"]
    for line, in_fence in zip(lines, fenced):
        if in_fence:
            continue
        match = _HEADING.match(line)
        if match is not None:
            return _EMPHASIS.sub("", match.group(2)).strip()
    stem = ident.rsplit("/", 1)[-1]
    return stem[: stem.rfind(".")] if "." in stem else stem


def _header(upstream: _Upstream, ident: str, title: str, summary: str,
            part: int, total: int, sections: list[_Section]) -> str:
    """The context block that opens every document from a markdown upstream.

    The path is on it deliberately. ``during/during_an_incident.md`` and
    ``playbooks/playbook-ransomware.md`` say which phase and which incident the
    text below belongs to, and a page's own title frequently does not — "Don't
    Panic!" is a heading in one of these files.

    A fourth line when the page was split, naming the part and the sections it
    holds. On parts after the first this is the *only* thing that says what
    incident is being responded to: the title is back in part one, a thousand
    tokens away and, once the corpus is windowed, in a different training sample
    entirely.
    """
    lines = [
        f"incident response source: {upstream.slug}",
        f"document: {ident}",
        f"title: {title}",
    ]
    if summary:
        lines.append(f"summary: {summary}")
    if total > 1:
        named: list[str] = []
        for path, _ in sections:
            trail = " > ".join(head for head in path if head and head != title)
            if trail and trail not in named:
                named.append(trail)
        label = f"part {part} of {total}"
        lines.append(f"{label}: {', '.join(named)}" if named else label)
    return "\n".join(lines)


def _markdown_documents(upstream: _Upstream,
                        root: Path) -> Iterator[tuple[Document | None, str]]:
    """Yield ``(document, note)`` for one markdown upstream, in path order.

    A file that is listed but cannot be read raises rather than being skipped.
    Silently shipping a corpus short by an unknown amount is the failure this
    package exists to make impossible, and a damaged cache is a fixable
    condition that deserves to be said out loud.
    """
    for ident, file in _files(root, upstream.suffix):
        try:
            # utf-8-sig: a stray U+FEFF at the head of a page would become a
            # token the model learns to expect before every heading.
            raw = file.read_text(encoding="utf-8-sig", errors="replace")
        except OSError as exc:
            raise SourceError(
                f"dfir: {upstream.key}/{ident} was listed but could not be read "
                f"({exc}). The cache is damaged; delete {root} and re-fetch "
                "rather than shipping a corpus short by an unknown amount."
            ) from exc

        # Line endings are settled before anything counts lines or fences, so a
        # CRLF page cannot defeat the strict fence-close test.
        lines = raw.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        lines, meta = _strip_front_matter(lines)
        fenced = _fence_map(lines)
        lines = _clean(lines, fenced)
        # The map is rebuilt because cleaning can change the line count: a <br>
        # becomes a newline and one row becomes two. Reusing the old flags would
        # misalign every rule below it by however many <br> tags came first.
        fenced = _fence_map(lines)

        whole = normalise("\n".join(lines))
        if len(whole) < _MIN_CHARS:
            continue
        if not any(fenced) and _link_ratio(lines, fenced) >= _STUB_LINK_RATIO:
            yield None, f"{upstream.key}/{ident}"
            continue

        title = _title(lines, fenced, meta, ident)
        summary = meta.get("description", "")

        if len(whole) <= _SPLIT_ABOVE:
            header = _header(upstream, ident, title, summary, 1, 1, [])
            yield Document(
                text=normalise(f"{header}\n\n{whole}"),
                source="dfir",
                register=Register.PROSE,
                side=Side.BLUE,
                ident=f"{upstream.key}/{ident}",
            ), ""
            continue

        parts = _pack(_sections(list(zip(lines, fenced))))
        for index, part in enumerate(parts, start=1):
            header = _header(upstream, ident, title, summary,
                             index, len(parts), part)
            body = normalise("\n".join(line for _, rows in part
                                       for line, _ in rows))
            if not body:
                continue  # a section of nothing but a heading and blank lines
            suffix = f"#part{index}" if len(parts) > 1 else ""
            yield Document(
                text=normalise(f"{header}\n\n{body}"),
                source="dfir",
                register=Register.PROSE,
                side=Side.BLUE,
                ident=f"{upstream.key}/{ident}{suffix}",
            ), ""


# ---------------------------------------------------------------------------
# RE&CT (YAML)
# ---------------------------------------------------------------------------

def _react_load(file: Path) -> dict:
    """Parse one RE&CT YAML file into a mapping, or raise."""
    try:
        parsed = yaml.safe_load(file.read_text(encoding="utf-8-sig",
                                               errors="replace"))
    except (OSError, yaml.YAMLError) as exc:
        raise SourceError(f"dfir: react: cannot parse {file}: {exc}") from exc
    return parsed if isinstance(parsed, dict) else {}


def _react_placeholder(value: object) -> bool:
    """True for a contributor-template value that says nothing.

    Case-folded, because the template's ``YYYY/MM/DD`` survives in the wild as
    ``yyyy/mm/dd`` too. 148 of the 216 response actions carry at least one of
    these; emitted, they are 148 identical lines.
    """
    return str(value).strip().casefold() in _REACT_PLACEHOLDERS


def _react_list(entry: dict, key: str) -> list[str]:
    """A list-valued field, placeholders and blanks removed."""
    raw = entry.get(key)
    if not isinstance(raw, list):
        return []
    return [str(item).strip() for item in raw
            if str(item).strip() and not _react_placeholder(item)]


def _react_name(stem: str) -> str:
    """``RA_1001_practice`` -> ``Practice``, the way upstream renders it.

    Upstream's own generator derives the human name of an action from its
    filename stem, and the rendered site says ``RA1001: Practice``. Deriving it
    the same way here keeps this source's ``RA####`` labels identical to the
    ones anybody reading RE&CT elsewhere will have seen.
    """
    _, _, tail = stem.partition("_")
    _, _, tail = tail.partition("_")
    words = tail.replace("_", " ").strip()
    return words[:1].upper() + words[1:] if words else stem


def _react_stage(key: str) -> tuple[str, str]:
    """``identification`` -> ``("RS0002", "Identification")``.

    An unrecognised stage is returned with an empty id rather than guessed at,
    so an upstream that adds a seventh stage shows up as a stage with no RS
    number instead of being silently filed under the wrong one.
    """
    for name, rs_id, label in _REACT_STAGES:
        if name == key:
            return rs_id, label
    return "", key.replace("_", " ").capitalize()


def _react_attack_tag(tag: str) -> str:
    """Restore an ``attack.*`` tag to the form the world writes it in.

    ``attack.t1566.001`` becomes ``T1566.001 (https://attack.mitre.org/
    techniques/T1566/001)`` — the identifier in two syntactic positions, with the
    sub-technique split across a path separator in the second, exactly as
    :mod:`~training.corpus.sources.attack` and
    :mod:`~training.corpus.sources.capec` render it. Anything else is a tactic or
    a free tag and is returned readable.
    """
    match = _ATTACK_TAG.match(tag)
    if match is None:
        body = tag[len("attack."):] if tag.lower().startswith("attack.") else tag
        return body.replace("_", " ").replace("-", " ").title()
    technique, sub = match.group(1), match.group(2)
    identifier = f"T{technique}" + (f".{sub}" if sub else "")
    path = f"T{technique}" + (f"/{sub}" if sub else "")
    return f"{identifier} (https://attack.mitre.org/techniques/{path})"


def _react_section(title: str, body: list[str]) -> list[str]:
    """A titled section, or nothing at all if there is nothing to put in it."""
    kept = [line for line in body if line.strip()]
    return ["", f"## {title}", "", *kept] if kept else []


def _react_action(entry: dict, stem: str) -> str:
    """Render one Response Action.

    The identifier leads the document, is repeated on a labelled line, and
    appears a third time inside the upstream URL — the three syntactic positions
    the tokenizer measurement in :mod:`training.corpus.source` rewarded. The
    stage is written as both its ``RS####`` id and its English name, because the
    join between a named action and the phase it belongs to is the thing a
    remediation step actually needs.
    """
    action_id = str(entry.get("id", "")).strip()
    name = _react_name(stem)
    rs_id, stage = _react_stage(str(entry.get("stage", "")).strip().lower())
    description = str(entry.get("description", "") or "").strip()

    lines = [
        f"{action_id} {name}".strip(),
        "",
        f"Response Action ID: {action_id}",
        f"Name: {name}",
        f"Stage: {rs_id} {stage}".rstrip() if rs_id else f"Stage: {stage}",
        f"URL: https://atc-project.github.io/atc-react/Response_Actions/{stem}/",
    ]
    if description:
        lines += _react_section("Description", [description])

    requirements = _react_list(entry, "requirements")
    lines += _react_section("Requirements", [f"- {item}" for item in requirements])

    automation = _react_list(entry, "automation")
    lines += _react_section("Automation", [f"- {item}" for item in automation])

    # Passed as one element rather than as split lines: _react_section drops
    # blank entries, and a workflow's blank lines are its paragraph structure.
    # Split, "Retrieve the header." and the bulleted analysis under it collapse
    # into one wall, which is the opposite of what a procedure is for.
    workflow = str(entry.get("workflow", "") or "").strip("\n")
    if workflow.strip():
        lines += _react_section("Workflow", [workflow])

    references = _react_list(entry, "references")
    lines += _react_section("References", [f"- {item}" for item in references])
    return "\n".join(lines)


def _react_stage_doc(entry: dict, actions: list[tuple[str, str, str, str]]) -> str:
    """Render one Response Stage plus the actions that belong to it.

    Worth a document of its own for the reason a CAPEC category is: the member
    list is a dense run of ``RA#### Name — description`` triples in one place,
    and the grouping knowledge ("blocking a sender and quarantining a message are
    both containment") is stated nowhere inside an individual action.

    Members are matched on the ``RS####`` id, not on the stage's English title.
    An action's ``stage:`` key is ``lessons_learned`` and the stage file's title
    is ``Lessons learned``, so a title-derived join works only as long as nobody
    upstream capitalises or rewords a heading — and when it breaks it produces an
    empty member list rather than an error.
    """
    stage_id = str(entry.get("id", "")).strip()
    title = str(entry.get("title", "")).strip()
    description = str(entry.get("description", "") or "").strip()
    wanted = ""
    for name, rs_id, _ in _REACT_STAGES:
        if rs_id == stage_id:
            wanted = name
            break

    lines = [
        f"{stage_id} {title}".strip(),
        "",
        f"Response Stage ID: {stage_id}",
        f"Name: {title}",
        "Framework: RE&CT (Response Actions, Playbooks and Stages)",
    ]
    if description:
        lines += _react_section("Description", [description])
    lines += _react_section("Response Actions in this stage", [
        f"- {action_id} {name}: {summary}" if summary else f"- {action_id} {name}"
        for action_id, name, summary, stage_key in actions
        if wanted and stage_key == wanted
    ])
    return "\n".join(lines)


def _react_playbook(entry: dict, index: dict[str, tuple[str, str, str]]) -> str:
    """Render one Response Playbook: the ordered stage-by-stage action list.

    **The per-action workflows are deliberately not repeated here.** Upstream's
    generated markdown inlines every referenced action's full text into the
    playbook, which would put roughly 20 KB of this source into the corpus twice
    under two idents — and ``build.py``'s fingerprint dedup is whole-document, so
    it would not notice. What a playbook adds over its actions is the *ordering*
    and the *selection*, and that is what is kept: which named actions, in which
    stage, in which sequence, for this incident type.
    """
    playbook_id = str(entry.get("id", "")).strip()
    description = str(entry.get("description", "") or "").strip()
    lines = [
        f"{playbook_id} {description}".strip(),
        "",
        f"Response Playbook ID: {playbook_id}",
        f"Description: {description}",
        "Framework: RE&CT (Response Actions, Playbooks and Stages)",
    ]
    for field, label in (("severity", "Severity"), ("tlp", "TLP"),
                         ("pap", "PAP")):
        value = str(entry.get(field, "") or "").strip()
        if value and not _react_placeholder(value):
            lines.append(f"{label}: {value}")

    tags = _react_list(entry, "tags")
    lines += _react_section("ATT&CK and tags",
                            [f"- {_react_attack_tag(tag)}" for tag in tags])

    workflow = str(entry.get("workflow", "") or "").strip("\n")
    if workflow.strip():
        lines += _react_section("Workflow", [workflow])

    for key, rs_id, label in _REACT_STAGES:
        members: list[str] = []
        for stem in _react_list(entry, key):
            action_id, name, summary = index.get(stem, ("", _react_name(stem), ""))
            head = f"- {action_id} {name}".rstrip()
            members.append(f"{head}: {summary}" if summary else head)
        lines += _react_section(f"{rs_id} {label}", members)
    return "\n".join(lines)


def _react_documents(upstream: _Upstream,
                     root: Path) -> Iterator[tuple[Document | None, str]]:
    """Yield RE&CT's actions, then its stages, then its playbooks.

    Actions are read first because the stage and playbook renderings both need
    an index from filename stem to ``(id, name, description)``: a playbook's
    fields are bare stems, and rendering them as stems would emit a list of
    filenames instead of the ``RA#### Name`` pairs that are the whole point.
    """
    index: dict[str, tuple[str, str, str]] = {}
    stage_members: list[tuple[str, str, str, str]] = []
    pending: list[tuple[str, Document]] = []

    for ident, file in _files(root, upstream.suffix):
        if not ident.startswith("response_actions/"):
            continue
        entry = _react_load(file)
        stem = file.name[: -len(upstream.suffix)]
        action_id = str(entry.get("id", "")).strip()
        name = _react_name(stem)
        summary = " ".join(str(entry.get("description", "") or "").split())
        index[stem] = (action_id, name, summary)
        stage_members.append((action_id, name, summary,
                              str(entry.get("stage", "")).strip().lower()))

        workflow = str(entry.get("workflow", "") or "")
        if _REACT_TEMPLATE_WORKFLOW in workflow:
            yield None, f"{upstream.key}/{ident}"
            continue
        text = normalise(_react_action(entry, stem))
        if len(text) < _MIN_CHARS:
            continue
        pending.append((ident, Document(
            text=text,
            source="dfir",
            register=Register.PROSE,
            side=Side.BLUE,
            ident=f"{upstream.key}/{ident}",
        )))

    for _, document in pending:
        yield document, ""

    for ident, file in _files(root, upstream.suffix):
        if ident.startswith("response_stages/"):
            text = normalise(_react_stage_doc(_react_load(file), stage_members))
        elif ident.startswith("response_playbooks/"):
            text = normalise(_react_playbook(_react_load(file), index))
        else:
            continue
        if len(text) < _MIN_CHARS:
            continue
        yield Document(
            text=text,
            source="dfir",
            register=Register.PROSE,
            side=Side.BLUE,
            ident=f"{upstream.key}/{ident}",
        ), ""


# ---------------------------------------------------------------------------
# documents
# ---------------------------------------------------------------------------

def _documents(path: Path) -> Iterator[Document]:
    """Yield every document, upstream by upstream in :data:`_UPSTREAMS` order.

    Nothing is dropped silently. A page held back as a bibliography index and a
    RE&CT action still holding the contributor template are both counted and
    named in the build log, because a source that quietly yields less than it
    promised is the failure mode this package is built around.
    """
    if not path.is_dir():
        raise SourceError(
            f"dfir: {path} is not a directory. Run the source's fetch() first."
        )

    held: dict[str, list[str]] = {}
    emitted = 0
    for upstream in _UPSTREAMS:
        root = path / upstream.key
        if not (root / _SIDECAR).is_file():
            print(f"   ! dfir: {upstream.key} is not in the cache; skipping it")
            continue
        render = (_markdown_documents if upstream.kind == "markdown"
                  else _react_documents)
        before = emitted
        for document, note in render(upstream, root):
            if document is None:
                held.setdefault(upstream.key, []).append(note)
                continue
            emitted += 1
            yield document
        if emitted == before:
            raise SourceError(
                f"dfir: {upstream.slug} yielded no documents from {root}. The "
                "cache is present but unreadable or empty; delete it and "
                "re-fetch rather than shipping the source short."
            )

    for key, notes in sorted(held.items()):
        if key == "react":
            print(f"   dfir: held back {len(notes)} RE&CT response action(s) "
                  "still carrying the contributor template workflow — near-"
                  "identical texts whose only unique content is the header")
        else:
            print(f"   dfir: held back {len(notes)} page(s) with no code fence "
                  f"and mostly bare links ({', '.join(sorted(notes)[:3])})")
    print(f"   dfir: {emitted} documents from "
          f"{len([u for u in _UPSTREAMS if (path / u.key / _SIDECAR).is_file()])}"
          f" of {len(_UPSTREAMS)} upstreams")


SPEC = SourceSpec(
    name="dfir",
    license=_LICENSE,
    url=("https://github.com/guardsight/gsvsoc_cirt-playbook-battle-cards, "
         "https://github.com/PagerDuty/incident-response-docs, "
         "https://github.com/atc-project/atc-react and "
         "https://github.com/counteractive/incident-response-plan-template"),
    register=Register.PROSE,
    side=Side.BLUE,
    fetch=_fetch,
    documents=_documents,
    #: Observed at the time of writing: 68 GuardSight cards, 60 PagerDuty parts
    #: from 36 pages, 19 Counteractive parts from 7 pages, and 176 RE&CT
    #: documents (169 actions, 6 stages, 1 playbook) — 323 in total, 721 KB,
    #: with no two sharing a fingerprint. The floor
    #: sits well below that because pages are retired and merged upstream and
    #: the count drifts down by ones, but it is tight enough to catch the
    #: regressions that matter: an include list that stopped matching, a licence
    #: check that started failing, or a cleaning rule that began emptying pages
    #: below the minimum length.
    expect_min_docs=240,
    notes=(
        "Incident response and DFIR playbooks: the prose form of what a "
        "defender does after the finding, which is the half of an engagement "
        "the rest of this corpus never describes. Four permissive upstreams, "
        "each a different shape of the same knowledge — GuardSight's 68 "
        "P-I-C-E-R-L battle cards (MIT), Counteractive's plan and four "
        "investigation playbooks (Apache-2.0), PagerDuty's incident command "
        "documentation including a 76 KB spoken-training transcript "
        "(Apache-2.0), and RE&CT's 216 RA####-identified response actions and "
        "six RS#### stages read from their YAML sources rather than the "
        "generated markdown (Apache-2.0). Counteractive's roles/ and glossary "
        "are excluded because they are a 27-76% shingle-share rewrite of the "
        "PagerDuty tree this source already carries in full, and its "
        "examples/plan.md is a pandoc concatenation of the whole repository; "
        "whole-document fingerprinting sees none of that. Its NOTICE declares "
        "content derived from CERT Societe Generale's IRM under CC BY 3.0, so "
        "that attribution rides along and is stated in the licence. "
        "Velociraptor's documentation is refused outright: CC BY-NC-SA 4.0 is "
        "NonCommercial. The IRM itself is PDF-only upstream and this package "
        "has no PDF dependency. HTML is stripped by an element-name whitelist, "
        "never by a generic tag regex, because <City>, <State> and their "
        "kind are operator placeholders in the prose rather than markup."
    ),
)
