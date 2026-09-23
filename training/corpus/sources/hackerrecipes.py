"""The Hacker Recipes, everything except ``ad/``. ADVERSARY/RED.

This adapter exists because the corpus measured a hole and the material to fill
it was already on disk. A per-verb scan of the built v6 corpus — 194,694
documents — found post-exploitation and offensive tradecraft present almost
entirely on the *blue* side::

    postex.credential_dump      1,526 docs   top sources: sigma, attackactors
    postex.privilege_escalate   3,821 docs   top sources: splunk, nvd, elastic
    postex.lateral_move         2,417 docs   top sources: elastic, splunk
    postex.exfil_probe          3,749 docs   top sources: netrules, elastic

Every one of those top sources is a detection ruleset or an advisory feed. The
corpus teaches what an attack looks like *in telemetry* and very little about
how it is performed, which is half a capability in a project whose argument is
that the red half exists to prove whether the blue half noticed.

:mod:`~training.corpus.sources.activedirectory` already fetches this repository
and takes ``docs/src/ad/`` — 139 pages. Its own comment names what it leaves::

    ad/ only. The repository also documents web, infra, radio, physical and
    mobile; those are other adapters' problems

They are this adapter's problem. Outside ``ad/`` the repository holds 142 more
markdown pages, as much again as the tree already taken, and they cover ground
the corpus is measurably thin in: web exploitation, infrastructure, radio,
physical, evasion and intelligence gathering.

**Why a second adapter rather than a wider ``keep`` in the first one.**
:mod:`training.corpus.build` attributes register, side, licence and budget per
:class:`~training.corpus.source.SourceSpec`. Widening ``activedirectory``'s keep
would report 55 pages of web exploitation under the name "activedirectory", and
count them against that source's share of the corpus. The same argument is made
at length in :mod:`~training.corpus.sources.payloads`, about the Web Security
Testing Guide, and it is the reason this file exists at all.

**What is deliberately not taken.**

* ``ad/`` — :mod:`~training.corpus.sources.activedirectory` owns it. Taking it
  here would put 139 pages into the corpus twice under two source names, which
  is the exact failure that cost this project 114 duplicated radare2 pages when
  ``shellcodeasm`` and ``malwareanalysis`` both shipped the same book. The
  build's whole-document fingerprint would not catch it either, because the two
  renderings would differ in their header lines while sharing every command.
* ``contributing/`` — how to write a page, not a technique.
* ``assets/`` and ``public/`` — images and site furniture, no prose.
* ``index.md`` at the root — a link table over the trees below it.

``policies/`` **is** taken. It is three pages on password, lockout and Kerberos
policy: defensive material, but written as what an attacker reads before
choosing a spray rate, and it sits inside the same red-side narrative as the
rest. Splitting three pages into their own BLUE spec would cost more in
attribution machinery than it could buy.

**Licence: GPL-3.0-only**, the unmodified 674-line GNU GPL v3 text, read from
the repository's own ``LICENSE`` at fetch time by the shared fetcher rather than
taken from a badge. Copyleft, and this project accepts copyleft for research use
while recording the obligation: the ``LICENSE`` is copied into the cache beside
the text it covers, and section 4's requirement to keep the notices is honoured
by carrying each page's ``authors:`` front-matter line into the rendered
document, which is the only attribution these pages have.

**Reuse.** The download, unpack, decode, front-matter, inline-HTML and splitting
machinery is imported from :mod:`~training.corpus.sources.activedirectory`
rather than copied. It is the same repository in the same format; two
maintained copies of that logic would drift, and the first symptom of drift
would be one adapter silently rendering pages the other one splits.
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Iterator

from ..source import Document, Register, SourceSpec
from .activedirectory import (_ATTACK_ID, _MIN_PROSE_CHARS, _Upstream, _clean_title,
                              _decode, _emit, _fetch_one, _first_heading,
                              _frontmatter, _inline_html, _outside_fences,
                              _prose_chars, _recipe_lines, _walk)
from ..source import Side

#: The trees this adapter renders, in the order the site presents them, each
#: mapped to the words that open its documents. The label is not decoration: a
#: page from ``radio/`` and a page from ``web/`` are different disciplines, and
#: the opening line is the only thing in a 1024-token window that says which
#: one the reader is in once the heading has scrolled away.
_TREES: dict[str, str] = {
    "web": "Web exploitation technique",
    "infra": "Infrastructure attack technique",
    "intelligence-gathering": "Intelligence gathering technique",
    "evasion": "Defence evasion technique",
    "physical": "Physical attack technique",
    "radio": "Radio attack technique",
    "mobile-apps": "Mobile application attack technique",
    "phishing": "Phishing technique",
    "policies": "Account policy",
}

#: ``ad/`` is absent on purpose — see the module docstring. Ordered so the
#: cache layout is stable across runs.
_UPSTREAM = _Upstream(
    key="recipes-rest",
    repo="ShutdownRepo/The-Hacker-Recipes",
    ref="main",
    label="The Hacker Recipes (outside ad/)",
    keep=tuple(f"docs/src/{tree}/" for tree in sorted(_TREES)),
    suffix=".md",
    license_file="LICENSE",
    license_id="GPL-3.0",
    license_note=(
        "ShutdownRepo/The-Hacker-Recipes (every docs/src tree EXCEPT ad/, "
        "which training.corpus.sources.activedirectory owns): GPL-3.0-only, "
        "the unmodified 674-line GNU GPL v3 text — NOT permissive. Per-page "
        "'authors:' attribution is preserved in every rendered document, as "
        "section 4 requires"
    ),
    docs="docs/src",
    #: 142 .md pages across the nine trees at the time of writing, the largest
    #: being web at 55 and infra at 39. The floor is low enough that retiring a
    #: page or two is quiet, and high enough that losing a whole tree — the
    #: realistic regression, since each is a separate ``keep`` prefix — trips.
    min_files=90,
)


def _fetch(cache_dir: Path) -> Path:
    """Download and unpack the repository, keeping only the non-``ad`` trees.

    A second, independent copy of the same repository rather than a shared one
    with :mod:`~training.corpus.sources.activedirectory`: the two adapters run
    in separate processes under the build's per-source timeout, they have
    separate cache directories by construction, and a shared tree would make
    whichever ran second depend on whether the first had succeeded. Twenty-five
    megabytes is a cheap price for two sources that cannot break each other.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    _fetch_one(cache_dir, _UPSTREAM)
    return cache_dir


def _tree_of(relative: Path) -> str | None:
    """The ``docs/src`` subdirectory a page belongs to, or ``None`` to skip it."""
    parts = relative.parts
    return parts[0] if parts and parts[0] in _TREES else None


def _page_url(tree: str, relative: Path) -> str:
    """The page's address on thehacker.recipes.

    ``index.md`` addresses the directory itself and every other page drops its
    extension — the same two forms
    :func:`~training.corpus.sources.activedirectory._recipe_url` documents,
    except that the tree is part of ``relative`` here rather than a constant in
    the format string, because this adapter spans nine of them.
    """
    parts = list(relative.parts)
    if relative.stem == "index":
        tail = "/".join(parts[:-1])
        tail = f"{tail}/" if tail else ""
    else:
        tail = "/".join(parts[:-1] + [relative.stem])
    return f"https://www.thehacker.recipes/{tail}"


def _pages(home: Path, held: Counter) -> Iterator[tuple[str, list[str], list[str], str]]:
    """Yield ``(ident, header, body lines, title)`` for every page taken."""
    root = home / _UPSTREAM.docs
    for path, relative in _walk(root, _UPSTREAM.suffix):
        tree = _tree_of(relative)
        if tree is None:
            # ad/, contributing/, assets/ and the root index. Counted rather
            # than dropped in silence: if a rename upstream moved every page
            # out of a tree this adapter names, the count is the only thing
            # that would say so before the document floor did.
            held["outside"] += 1
            continue

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
        header = [f"{_TREES[tree]}: {title}"]

        # The path below the tree, which is the page's place in a taxonomy the
        # title alone does not carry: "Padding oracle" means one thing under
        # web/inputs/ and another under infra/.
        area = " > ".join(relative.parent.parts)
        if area:
            header.append(f"Area: {area}")

        attack = _ATTACK_ID.findall(meta.get("description", ""))
        if attack:
            header.append(f"ATT&CK: {', '.join(dict.fromkeys(attack))}")
        if authors := meta.get("authors"):
            # GPL-3.0 section 4 says to keep the notices, and this is the only
            # attribution these pages carry.
            header.append(f"Authors: {authors}")
        header.append(f"Reference: {_page_url(tree, relative)}")

        yield f"recipes:{relative.as_posix()}", header, lines, title


def _documents(path: Path) -> Iterator[Document]:
    home = path / _UPSTREAM.key
    held: Counter = Counter()
    rendered = 0
    for ident, header, lines, title in _pages(home, held):
        for document in _emit(ident, header, lines, title,
                              source="hackerrecipes"):
            rendered += 1
            yield document
    if held:
        # Said out loud, in the build log, for the same reason payloads says how
        # many redirect stubs it dropped: a count that has to be reconstructed
        # from a diff is a count nobody checks.
        parts = ", ".join(f"{n} {kind}" for kind, n in sorted(held.items()))
        print(f"   hackerrecipes: {rendered} documents rendered; held back {parts}")


SPEC = SourceSpec(
    name="hackerrecipes",
    license=_UPSTREAM.license_note,
    url="https://github.com/ShutdownRepo/The-Hacker-Recipes",
    register=Register.ADVERSARY,
    side=Side.RED,
    fetch=_fetch,
    documents=_documents,
    #: 109 documents observed, from 142 upstream pages: 33 are held back as
    #: stubs and the rest render, a few of them splitting. The 33 are not a
    #: parsing failure — they are pages upstream has not written yet, most of
    #: them titled with the site's own construction emoji and carrying nothing
    #: but that heading (``infra/privilege-escalation/windows/
    #: kernel-exploitation.md`` is 25 bytes, all of it ``# 🛠️ Kernel
    #: exploitation``). Worth knowing before planning around this source: the
    #: Windows privilege-escalation tree, which is exactly the postex material
    #: this adapter was written to supply, is largely unwritten upstream.
    #: The floor sits below the observed count so that a few more pages going
    #: dark is quiet, and above the level any single lost tree would leave —
    #: web alone is 59 documents, and losing it must trip this.
    expect_min_docs=85,
    notes=(
        "One document per technique page, headings and fenced payloads intact, "
        "opened with the discipline and the page title because a bare H1 like "
        "'# Padding oracle' does not say whether the reader is in web or "
        "infra. Long pages split at their own headings, never inside a fence, "
        "and every part reopens with its header and heading trail. ad/ is "
        "excluded and belongs to the activedirectory source; taking it here "
        "would duplicate 139 pages under two names."
    ),
)
