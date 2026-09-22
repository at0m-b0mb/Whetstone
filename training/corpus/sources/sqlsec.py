"""SQL: the language attacks are written in, and the language a host is asked
questions in.

The corpus already knows what an SQL injection *payload* looks like. It has
never seen what the payload is aimed at. PayloadsAllTheThings gives it
``' OR 1=1-- -`` and ``UNION SELECT NULL,version()--``; CWE-89 gives it the
weakness in the abstract; the OWASP cheat sheets give it the sentence "use
parameterised queries". Nowhere in 29 sources is there a ``CREATE TABLE``, a
``JOIN``, a stored procedure body, a ``GRANT``, or the mechanism by which a
bound parameter is immune to a quote character. A model in that state can
recite the payload and recite the remedy and has no way to connect them,
because it has never met the thing in the middle: the query.

So this source is SQL from both ends of the same weapon.

**End one — SQL as the surface being attacked: the PostgreSQL SQL reference.**
185 ``refentry`` pages, one per statement, each carrying the grammar, the
semantics in prose, and worked examples. That set is chosen over a tutorial or
a cheat sheet because it is the only writing available under a permissive
licence that explains, in the same document, *what a statement means* and *what
it is allowed to do*: ``GRANT`` and ``REVOKE`` and ``CREATE POLICY`` are
authorisation; ``PREPARE``/``EXECUTE`` are the parameterised query itself;
``CREATE FUNCTION`` is the stored procedure, ``SECURITY DEFINER`` and all;
``COPY`` is the statement whose ``PROGRAM`` form is remote code execution.
Eleven chapters come with them, and they are where the *why* lives —
``plpgsql.sgml`` contains the canonical passage on dynamic SQL, which says in
so many words that binding values with ``USING`` "is much less prone to
SQL-injection attacks since there is no need for quoting or escaping", then
shows ``format()``'s ``%I`` for the identifier case where binding is not
available. ``syntax.sgml`` is how a string literal is terminated and how dollar
quoting avoids the question. ``catalogs.sgml`` and ``information_schema.sgml``
are the tables every enumeration stage of an injection reads. That is the
material a model needs in order to say why a fix works rather than that it
does.

**End two — SQL as the defender's instrument: osquery.** osquery exposes a
running machine as a relational database, so "detect X" becomes "ask the host a
question", which is this project's ``detect.*`` verbs written in another
syntax. Two halves are taken. The 289 ``specs/*.table`` files are the schema —
2,639 columns, each with a one-line English description sitting next to its
identifier and type, which is exactly the shape the tokenizer measurement that
rebuilt this corpus said the win comes from. They are rendered here as SQL DDL
rather than passed through as the Python DSL they are written in, because a
``CREATE TABLE`` is what the model is missing and ``Column("pid", BIGINT,
"Process (or thread) ID")`` is not one. The packs are the other half: ~460
named detections across three upstreams — 534 distinct queries after the 196
copied between them are collapsed — each a query, an interval and a sentence
saying what finding a row would mean.

**Register, decided from what is rendered and not from the topic.** The brief
this was written to offered SHELL for the queries, on the argument that a
``SELECT`` is a command in a REPL. It is not taken, for two reasons, and the
consequence should be said plainly: *this source does not help the SHELL
shortfall at all.*

The first reason is arithmetic. What actually comes out is 1.38 MB of
PostgreSQL reference pages and osquery schemas against 161 KB of pack queries;
a reference page is a language reference in exactly the sense
:class:`~training.corpus.source.Register.SYSTEM` means — "how the machine works
… API references" — and filing 1.4 MB of that under SHELL to make a number
move would put a lie into the one report this package has for spotting a
starved register.

The second is consistency. The pack queries go to
:class:`~training.corpus.source.Register.DETECTION` because
:mod:`~training.corpus.sources.splunk` already faced precisely this decision
for SPL, wrote "what a defender actually types is this", and still filed it as
DETECTION. Two adapters answering the same question two different ways would
make the register table meaningless.

What it does help is PROSE, which the corpus is short of by a factor of five.
The measured split is SYSTEM 1,375,398 chars (473 documents), PROSE 1,353,520
(271) and DETECTION 161,069 (42) — SYSTEM ahead by less than 2%, which is why
:data:`SPEC` says SYSTEM and why the number is written down here rather than
asserted. Per-document registers are what ``build.py`` counts, so the mix is
reported rather than averaged into one label.

**Licences, each read from the upstream's own file and each re-checked at fetch
time.** The brief said osquery was Apache-2.0. Its ``LICENSE`` says
``SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only`` and "If you're using
osquery you are free to choose one of the provided licenses" — a dual licence,
not a single one. Apache-2.0 is the option taken here and that election is
stated in :data:`SPEC` rather than left implicit, because "Apache-2.0" alone
would be a claim the upstream does not make. PostgreSQL's grant is in a file
called ``COPYRIGHT``, not ``LICENSE``, which is the sort of detail that makes a
licence bot report NOASSERTION and a human report nothing at all.
:func:`_check_licences` requires each named licence file to be present *and*
to still contain a phrase only that licence contains; an upstream that relicenses
fails the fetch instead of quietly changing what this corpus is built on.

**What was rejected, and why, because that is the useful half of a licence
report.** ``sqlmap`` is the obvious candidate for the offensive half and is not
here. It is GPL-2.0 — usable, since this corpus already carries GTFOBins and
LOLBAS under GPL-3.0 and the kernel docs under GPL-2.0, so copyleft is not the
objection. The objection is that :mod:`~training.corpus.sources.pythoncode`
already examined sqlmap and excluded it, that its payload taxonomy is the part
:mod:`~training.corpus.sources.payloads` already supplies under MIT, and that
re-admitting a project a sibling adapter rejected — under a heavier licence,
for text the corpus already holds — is how a package acquires two contradictory
policies. ``fleetdm/fleet`` has the largest osquery query library in existence
and a 2 GB repository with an ``/ee`` tree under a proprietary licence; the
size alone rules out the tarball fetch this package uses. ``Azure/Azure-
Sentinel`` is MIT and would have brought KQL, which the corpus genuinely lacks,
but it is an 11 GB repository and it would deepen a DETECTION surplus rather
than touch any measured gap. SQLite's documentation is public domain and is the
best short explanation of SQL semantics anywhere; it is not here because it
does not exist as a repository — the sources live in a Fossil archive as HTML
templates, and the GitHub mirror carries the C amalgamation and no docs.
OWASP's SQL injection prevention cheat sheets are already in the corpus through
:mod:`~training.corpus.sources.owasp` and are deliberately not fetched again.

**Traps, in the order they were hit.**

* ``packs/osx-attacks.conf`` is not valid JSON. It wraps long queries with a
  backslash at end of line, which is a shell continuation and an illegal JSON
  escape, and ``json.loads`` refuses the whole file — 33 macOS malware
  detections, the single most interesting pack in the set, silently absent if
  the ``JSONDecodeError`` is swallowed. :func:`_load_conf` rewrites
  backslash-newline to a ``\\n`` escape before parsing, which keeps the query's
  own line structure instead of joining it onto one line.
* One ``.table`` spec contains ``\\P`` in a description, which Python 3.12
  reports as a ``SyntaxWarning`` at compile time. Under ``-W error`` that is an
  exception and the file disappears, so the compile gate runs with warnings
  suppressed and the warning counted.
* PostgreSQL's docs reference ``&version;`` and ``&majorversion;``, which are
  defined in a ``version.sgml`` the build *generates* and the repository does
  not contain. Parsing without substituting them fails on an undefined entity.
  The value is read out of ``meson.build`` so the substitution is the tree's
  own version rather than a number written here that goes stale.
* ``<xref linkend="guc-plan-cache-mode"/>`` is by far the most common element
  in these docs after ``<para>``, ``<literal>`` and ``<replaceable>``, and
  DocBook resolves it to the target's title. Dropped, sentences lose their
  object: "when  is set to auto". Humanised from the id, they lose their
  meaning: "when guc plan cache mode is set". So :func:`_fetch` walks every
  SGML file in the doc tree — not only the ones kept — and records ``id``
  against ``xreflabel``-or-title. 4,791 ids resolve, and that sentence becomes
  "when plan_cache_mode is set to auto".
* ``xfunc.sgml`` and ``xoper.sgml`` are not XML documents. They are a run of
  top-level ``<sect1>`` elements pulled into a ``<chapter>`` declared
  elsewhere, and ``ElementTree`` rejects them with "junk after document
  element". ``xfunc`` is one of the eleven chapters chosen here *by name* — it
  is where ``SECURITY DEFINER`` and the ``search_path`` escalation live — and
  it was contributing nothing while the fetch reported success. Everything is
  parsed inside a synthetic wrapper element now; see :func:`_parse_fragment`.
* Rendering ``<synopsis>`` through ``itertext()`` silently deletes the square
  brackets that DocBook draws for ``<optional>``. The PL/pgSQL chapter's
  central synopsis came out as ``EXECUTE command-string  INTO STRICT target
  USING expression;`` — every optional clause looking mandatory, in the single
  document this source exists to carry. Verbatim blocks go through
  :func:`_inner` instead, which preserves whitespace exactly *and* knows what
  ``<optional>`` means.
* ``catalogs.sgml`` and ``information_schema.sgml`` do not use ordinary table
  rows. Each row is one ``<entry>`` holding a ``<para
  role="column_definition">`` and then the description as further paragraphs,
  so a naive cell join produced ``rolsuper bool Role has superuser
  privileges`` — correct, and with the boundary between the declaration and
  the sentence about it erased, in the 500 KB of documents that are precisely
  the schema an injection enumerates. :func:`_render_row` handles both shapes.
* The character entities were originally a hand-written table. The docs reach
  for ``&aacute;``, ``&frac12;``, ``&ldquo;`` and ``&ocirc;`` often enough that
  the table was silently deleting them, so resolution goes through
  :data:`html.entities.html5` with two overrides. Only one entity in the kept
  set now resolves to nothing — ``&dfunc;``, a file include — and the tally is
  written into the cache marker so the next one is a number rather than
  missing text.

**Paragraph text is re-wrapped; nothing else is touched.** A line break inside
a DocBook ``<para>`` is a typesetting artefact of an 80-column SGML file and
carries no meaning, so paragraphs are joined and re-wrapped.
``<programlisting>``, ``<synopsis>``, ``<screen>`` and ``<literallayout>`` are
copied out character for character and only shifted right by four spaces,
because their internal alignment is the content — a ``SELECT`` written across
five indented lines is being *shown* as well as said. The generated DDL
aligns its type and comment columns for the same reason
:func:`~training.corpus.source.normalise` refuses to collapse horizontal
whitespace: column structure is the register this corpus measured highest
against gpt2, and it costs nothing to produce it deliberately.
"""

from __future__ import annotations

import ast
import html.entities
import json
import os
import re
import shutil
import tarfile
import textwrap
import time
import warnings
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from ..net import NetworkError, download
from ..source import (
    Document, Register, Side, SourceError, SourceSpec, fingerprint, normalise,
)

_NAME = "sqlsec"

#: Written last, so its presence means every upstream was fetched, filtered and
#: swapped into place. The version is part of it because the curation rules live
#: in this module rather than in the cache: when they change, a tree built under
#: the old ones is stale, and a machine that has already built the corpus is
#: exactly the machine a fix would otherwise never reach.
_MARKER = ".fetched.json"
_CACHE_VERSION = 1

#: Ceiling handed to :func:`~training.corpus.net.download` so it is enforced
#: against bytes as they arrive rather than against a file that is already on
#: disk. PostgreSQL's tarball is the only large one here at 31 MB; the other
#: three are 4.5 MB, 38 KB and 25 KB together.
_MAX_ARCHIVE_BYTES = 120 * 1024 * 1024

#: A rendered document under this is a stub — an empty ``<sect1>`` wrapper, a
#: three-column lookup table with no description — and teaches nothing but its
#: own furniture.
_MIN_DOC_CHARS = 200

#: A ``<sect1>`` longer than this is split at ``<sect2>``. ``catalogs.sgml``
#: and ``protocol.sgml`` both carry sections past 60 KB, and a single document
#: that large is one training sample that will never fit in a context window
#: whole. Sections that have no ``<sect2>`` children are kept intact rather
#: than cut at an arbitrary character count, because a document chopped
#: mid-sentence is worse than a long one.
_MAX_SECTION_CHARS = 48_000


@dataclass(frozen=True)
class _Upstream:
    """One upstream, its verified licence, and the part of it worth keeping."""

    name: str
    url: str
    #: Read from the project's own licence file, not from a badge or a README.
    license: str
    archive: str
    #: ``(path in archive, phrase that only this licence contains)``. Both are
    #: checked at fetch time: a missing file or a changed phrase fails the
    #: build. See the module docstring for why this is not decoration.
    license_files: tuple[tuple[str, str], ...]
    #: Floor on files surviving the filters, per upstream, so a repository that
    #: moves its directory fails while naming itself instead of showing up
    #: three sources later as a thin build report.
    min_files: int = 1
    notes: str = ""


_UPSTREAMS: tuple[_Upstream, ...] = (
    _Upstream(
        name="postgres",
        url="https://github.com/postgres/postgres",
        license=(
            "PostgreSQL License (the COPYRIGHT file; a permissive BSD/MIT-style "
            "grant. Portions Copyright (c) 1996-2026, PostgreSQL Global "
            "Development Group; Portions Copyright (c) 1994, The Regents of the "
            "University of California)"
        ),
        archive="https://codeload.github.com/postgres/postgres/tar.gz/refs/heads/master",
        # Named COPYRIGHT, not LICENSE. GitHub's detector returns NOASSERTION
        # for this repository for exactly that reason.
        license_files=(
            ("COPYRIGHT", "Permission to use, copy, modify, and distribute"),
        ),
        min_files=180,
        notes="SQL command reference and the chapters in _PG_CHAPTERS",
    ),
    _Upstream(
        name="osquery",
        url="https://github.com/osquery/osquery",
        license=(
            "Apache-2.0, elected from the upstream's dual offer. osquery's own "
            "LICENSE reads 'SPDX-License-Identifier: Apache-2.0 OR "
            "GPL-2.0-only' and 'If you're using osquery you are free to choose "
            "one of the provided licenses'; Apache-2.0 is the choice made here "
            "and LICENSE-Apache-2.0 is copied into the cache beside the text it "
            "covers"
        ),
        archive="https://codeload.github.com/osquery/osquery/tar.gz/refs/heads/master",
        license_files=(
            ("LICENSE", "Apache-2.0 OR GPL-2.0-only"),
            ("LICENSE-Apache-2.0", "Apache License"),
        ),
        min_files=300,
        notes="specs/*.table, packs/*.conf, docs/wiki/**/*.md",
    ),
    _Upstream(
        name="palantir",
        url="https://github.com/palantir/osquery-configuration",
        license="MIT (LICENSE.md; Copyright (c) 2017 Palantir Technologies Inc.)",
        archive=("https://codeload.github.com/palantir/osquery-configuration/"
                 "tar.gz/refs/heads/master"),
        license_files=(("LICENSE.md", "MIT License"),),
        min_files=6,
        notes="Classic/**/*.conf only; the Fleet/ tree is the same queries again",
    ),
    _Upstream(
        name="osquery-attck",
        url="https://github.com/teoseller/osquery-attck",
        license=(
            "Apache-2.0 (LICENSE.txt is the unmodified Apache License 2.0 text, "
            "including its unfilled 'Copyright [yyyy] [name of copyright "
            "owner]' appendix — the repository names no copyright holder "
            "anywhere, which is worth knowing and is not a defect in the grant)"
        ),
        archive=("https://codeload.github.com/teoseller/osquery-attck/"
                 "tar.gz/refs/heads/master"),
        license_files=(("LICENSE.txt", "Apache License"),),
        min_files=20,
        notes="osquery packs annotated with the ATT&CK techniques they cover",
    ),
)


#: PostgreSQL chapters kept alongside the statement reference, named one by one
#: rather than taken wholesale. The manual is 8 MB of SGML and most of it —
#: index access methods, text search, replication internals, the installation
#: guide — is database engineering with nothing to say about either half of
#: this source. These eleven were each chosen for a specific reason:
_PG_CHAPTERS: dict[str, str] = {
    # How a string literal ends, what dollar quoting is for, and what an
    # identifier may contain. The lexical rules injection turns on.
    "syntax": "SQL Syntax",
    # SELECT, the join types, subqueries, set operations. UNION is a primitive
    # of injection and this is where it is defined.
    "queries": "Queries",
    # Tables, constraints, schemas, privileges, and row-level security.
    "ddl": "Data Definition",
    # Roles, membership, and what a role may do.
    "user-manag": "Database Roles",
    # Stored procedures, and the passage on dynamic SQL that is the clearest
    # published explanation of why binding a value defeats a quote.
    "plpgsql": "PL/pgSQL",
    # Server-side functions, volatility, and the SECURITY DEFINER search_path
    # problem that turns a helper function into privilege escalation.
    "xfunc": "Server Programming: Functions",
    # Views and the rewrite system, including what a view does and does not
    # hide from the caller.
    "rules": "The Rule System",
    # The standard catalogue every enumeration stage reads first.
    "information_schema": "The Information Schema",
    # The native one it reads second: pg_authid, pg_proc, pg_policy.
    "catalogs": "System Catalogs",
    # pg_hba.conf, trust/peer/scram, and what each authentication method
    # actually proves.
    "client-auth": "Client Authentication",
    # Parse/Bind/Execute on the wire. This is the mechanism that makes a
    # parameterised query safe, stated as a protocol rather than as advice.
    "protocol": "Frontend/Backend Protocol",
}

#: Kept out of the PostgreSQL reference. These 35 pages document client and
#: server *programs* — psql, pg_dump, pgbench, initdb — in man-page shape:
#: a synopsis and an option list. That register the corpus already has at
#: scale from ``manpages`` (2,000+ pages) and ``tldr``, they contain almost no
#: SQL, and they are 1.0 MB of the 3.0 MB. Dropping them costs the psql
#: meta-command table and nothing else this source is for.
_PG_SQL_REFMISCINFO = "SQL - Language Statements"

#: osquery wiki pages that are about building osquery rather than about
#: querying a host with it. The development and installation trees teach CMake
#: and package layout.
_OSQUERY_WIKI_SKIP = ("docs/wiki/development/", "docs/wiki/installation/")

#: Directory names never walked, wherever they appear.
_SKIP_DIRS = frozenset({
    ".git", "__pycache__", "node_modules", "vendor", "third_party",
})

#: DocBook elements copied out byte for byte. Their internal layout is content.
_VERBATIM = frozenset({
    "programlisting", "synopsis", "screen", "literallayout",
})

#: DocBook elements dropped with everything inside them. ``indexterm`` is the
#: index apparatus and would otherwise inject a stray noun into the middle of
#: the sentence it is anchored to; ``refmeta`` is the man-page volume number.
_DROPPED = frozenset({
    "indexterm", "remark", "titleabbrev", "anchor", "refmeta", "info",
    "bookinfo", "docinfo", "colspec", "spanspec", "indexdiv",
})

#: Entities the HTML5 table gets wrong for this corpus. ``zwsp`` is
#: PostgreSQL's own — a zero-width space its authors insert to permit a line
#: break inside a long table cell — and it must become nothing at all, because
#: leaving U+200B in the text would put an invisible character in the middle of
#: identifiers the tokenizer is meant to learn. Everything else resolves
#: through :data:`html.entities.html5`, which already knows ``&mdash;``,
#: ``&aacute;``, ``&frac12;`` and the other 2,000 the docs occasionally reach
#: for; hand-maintaining that list is how one of them ends up silently dropped.
_ENTITY_OVERRIDES: dict[str, str] = {"zwsp": "", "nbsp": " "}

_ENTITY_RE = re.compile(r"&(?!lt;|gt;|amp;|quot;|apos;|#)([A-Za-z][\w.-]*);")
_WS = re.compile(r"[ \t\r\n]+")
_BLANKS = re.compile(r"\n{3,}")
#: A backslash at the end of a line inside a JSON string. Legal in a shell,
#: illegal in JSON, and present in osquery's macOS attack pack.
_JSON_CONTINUATION = re.compile(r"\\\r?\n")


# --------------------------------------------------------------------------
# DocBook rendering
# --------------------------------------------------------------------------

def _substitute_entities(raw: str, version: str, dropped: dict[str, int]) -> str:
    """Resolve the non-XML entity references so the document will parse.

    ``&version;`` and ``&majorversion;`` are declared in a ``version.sgml``
    that the documentation build *generates*; the repository does not ship it,
    so a parser meets an undefined entity and refuses the file. Substituting a
    version read out of the tree keeps the text honest about which release it
    describes without a constant here that goes stale one release later.

    Entities that resolve to nothing are removed, and every one is counted into
    ``dropped``, which :func:`_fetch` writes into the cache marker *for the
    kept files only*. Restricting the tally is what makes it readable: the
    manual's container files — ``postgres.sgml``, ``reference.sgml``,
    ``filelist.sgml`` — are almost nothing but ``<!ENTITY createTable SYSTEM
    "create_table.sgml">`` references, so a tally taken over the whole tree is
    400 file-include names deep and says nothing about whether any *text* went
    missing.
    """
    raw = raw.replace("&version;", version)
    raw = raw.replace("&majorversion;", version.split(".")[0])

    def _one(match: re.Match[str]) -> str:
        name = match.group(1)
        if name in _ENTITY_OVERRIDES:
            return _ENTITY_OVERRIDES[name]
        replacement = html.entities.html5.get(name + ";", "")
        if not replacement:
            dropped[name] = dropped.get(name, 0) + 1
        return replacement

    return _ENTITY_RE.sub(_one, raw)


#: The element :func:`_parse_fragment` wraps every file in. Named rather than
#: anonymous so that a stray occurrence in rendered output is searchable.
_FRAGMENT_ROOT = "sqlsecfragment"


def _parse_fragment(text: str) -> ET.Element:
    """Parse one SGML file, which may not have a single root element.

    Most of these files hold one ``<refentry>`` or one ``<chapter>`` and parse
    directly. Some do not: ``xfunc.sgml`` and ``xoper.sgml`` are a *run* of
    top-level ``<sect1>`` elements, because the ``<chapter>`` that contains
    them is declared in ``extend.sgml`` and they are pulled in by entity
    reference. ``ElementTree`` calls that "junk after document element" and
    refuses the file.

    This was worth catching rather than tolerating. ``xfunc`` is one of the
    eleven chapters chosen for this source by name — it is where SECURITY
    DEFINER and the ``search_path`` escalation it enables are explained — and
    the failure mode was that it contributed zero documents while the fetch
    reported success, which is precisely the silent loss this package keeps
    rediscovering. Wrapping unconditionally costs one element and removes the
    whole class of problem.
    """
    return ET.fromstring(f"<{_FRAGMENT_ROOT}>{text}</{_FRAGMENT_ROOT}>")


def _container(root: ET.Element) -> ET.Element:
    """The element whose children are the chapter's sections.

    After :func:`_parse_fragment` the root is always the synthetic wrapper. A
    well-formed chapter file puts one ``<chapter>`` inside it; a fragment file
    puts the sections there directly.
    """
    children = list(root)
    if len(children) == 1 and children[0].tag in {"chapter", "appendix", "part"}:
        return children[0]
    return root


def _flatten(text: str) -> str:
    """Collapse the whitespace *inside one paragraph* to single spaces.

    This is the one place in this adapter where horizontal whitespace is
    touched, and the distinction matters. A newline in the middle of a DocBook
    ``<para>`` is where the SGML author's editor wrapped at 80 columns; it is
    not layout and reproducing it teaches the model an artefact of someone's
    text editor. Verbatim elements never come through here — see
    :func:`_render_blocks`, which routes them straight out of ``itertext()``.
    """
    return _WS.sub(" ", text).strip()


def _xref_label(linkend: str, ids: dict[str, str]) -> str:
    """What an ``<xref linkend="...">`` should read as in plain text.

    DocBook resolves an xref to the target's title, and these documents lean on
    it heavily — 1,883 of them in the kept set, more than any element except
    ``<para>``, ``<literal>`` and ``<replaceable>``. The map built in
    :func:`_fetch` answers most of them. The fallbacks are for targets outside
    the doc tree: ``sql-createpolicy`` is a statement name and reads correctly
    upper-cased, ``guc-work-mem`` is a configuration parameter and reads
    correctly with underscores, and anything else is humanised, which is
    imperfect but leaves a noun where the sentence needs one.
    """
    label = ids.get(linkend, "")
    if label:
        return label
    if linkend.startswith("sql-"):
        return linkend[4:].replace("-", " ").upper()
    if linkend.startswith("guc-"):
        return linkend[4:].replace("-", "_")
    if linkend.startswith(("app-", "pg", "libpq-", "catalog-")):
        return linkend.split("-", 1)[-1].replace("-", "_")
    return linkend.replace("-", " ").replace("_", " ")


def _inline(node: ET.Element, ids: dict[str, str]) -> str:
    """Render one element's content as running text, tail included."""
    tag = node.tag
    if tag in _DROPPED:
        return node.tail or ""
    if tag == "xref":
        return _xref_label(node.get("linkend", ""), ids) + (node.tail or "")
    parts: list[str] = []
    if tag == "optional":
        # No added spaces. DocBook draws the brackets; the source supplies
        # whatever padding it wants inside them, and in a <synopsis> that
        # padding is the difference between "[ INTO ]" and "[  INTO  ]".
        parts.append("[" + _inner(node, ids) + "]")
    elif tag == "quote":
        parts.append('"' + _inner(node, ids) + '"')
    else:
        parts.append(node.text or "")
        for child in node:
            parts.append(_inline(child, ids))
    parts.append(node.tail or "")
    return "".join(parts)


def _inner(node: ET.Element, ids: dict[str, str]) -> str:
    """Element content without its tail, for the wrapping cases above."""
    parts = [node.text or ""]
    for child in node:
        parts.append(_inline(child, ids))
    return "".join(parts)


def _flat(node: ET.Element, ids: dict[str, str]) -> str:
    return _flatten(_inner(node, ids))


def _wrap(text: str, indent: str, hanging: str | None = None) -> str:
    """Re-wrap a paragraph at 78 columns.

    ``break_long_words`` and ``break_on_hyphens`` are both off, and neither is
    a style preference. These documents are dense with URLs, hyphenated
    identifiers and 64-character hashes; the default settings split
    ``sensorstechforum.com/ccleaner-trojan-floxif-malware-how-to-remove/``
    across two lines at a hyphen, which produces a URL that is not a URL and a
    token boundary the model would learn as real.
    """
    wrapped = textwrap.wrap(
        text, width=78, initial_indent=indent,
        subsequent_indent=indent if hanging is None else hanging,
        break_long_words=False, break_on_hyphens=False,
    )
    return "\n".join(wrapped) if wrapped else ""


def _verbatim(node: ET.Element, ids: dict[str, str], indent: str) -> str:
    """A code block, copied out unchanged and shifted right by four spaces.

    Through :func:`_inner`, which concatenates text and tails without touching
    a single space, and *not* through ``itertext()``. That distinction cost a
    debugging pass. Inside a ``<synopsis>`` most markup is decorative —
    ``<literal>``, ``<replaceable>`` — and ``itertext()`` handles it correctly
    by returning the text between the tags. ``<optional>`` is not decorative:
    DocBook draws the square brackets that ``itertext()`` has no way to
    produce, so the PL/pgSQL chapter's central synopsis came out as ``EXECUTE
    command-string  INTO STRICT target  USING expression;`` — every optional
    clause rendered as though it were mandatory, in the one document this
    source exists to carry.

    Blank lines are emitted genuinely empty rather than indented, so
    :func:`~training.corpus.source.normalise`'s trailing-whitespace strip has
    nothing left to do.
    """
    body = _inner(node, ids).strip("\n")
    if not body.strip():
        return ""
    pad = indent + "    "
    return "\n".join(pad + line if line.strip() else "" for line in body.split("\n"))


def _cmdsynopsis(node: ET.Element, ids: dict[str, str], indent: str) -> str:
    """A command line, with the brackets DocBook would have drawn.

    Flattening this element inline produces ``psql option dbname username``,
    which reads as a sentence and is not one.

    Kept although the current selection contains exactly zero of them: all 48
    ``<cmdsynopsis>`` elements in the PostgreSQL docs live in the client- and
    server-program reference pages, which :func:`_extract_postgres` drops. It
    stays because the alternative is not "unused code" but silent loss — an
    element with no handler falls through to the default recursion, which emits
    nothing for a subtree containing no ``<para>``, so the day somebody adds a
    chapter that uses one it would disappear rather than render badly. A
    measurement backs that up: rendered output is 1.00 to 1.05 times the
    visible text of every kept file, i.e. nothing is currently being dropped,
    and this function is part of why.
    """
    def one(elem: ET.Element) -> str:
        if elem.tag == "arg":
            inner = " ".join(part for part in (one(child) for child in elem) if part)
            body = _flatten((elem.text or "") + " " + inner)
            if elem.get("rep") == "repeat":
                body += "..."
            return body if elem.get("choice") == "plain" else f"[{body}]"
        if elem.tag == "group":
            options = [one(child) for child in elem]
            body = "|".join(opt for opt in options if opt)
            return f"{{{body}}}" if elem.get("choice") == "plain" else f"[{body}]"
        return _flat(elem, ids)

    pieces = [_flat(node, ids)] if node.text and node.text.strip() else []
    pieces.extend(part for part in (one(child) for child in node) if part)
    line = _flatten(" ".join(pieces))
    return indent + "    " + line if line else ""


def _render_para(node: ET.Element, ids: dict[str, str],
                 out: list[str], indent: str) -> None:
    """A paragraph, split around any verbatim block sitting inside it.

    PostgreSQL routinely puts a ``<synopsis>`` or a ``<programlisting>`` in the
    middle of a ``<para>``. Treating the paragraph as one run of inline text
    folds the example into the sentence — the PL/pgSQL chapter's ``EXECUTE
    command-string [ INTO [ STRICT ] target ] [ USING expression ]`` ends up
    mid-clause, which is how the single most important synopsis in this source
    stops looking like code.
    """
    buffer: list[str] = [node.text or ""]

    def flush() -> None:
        text = _flatten("".join(buffer))
        if text:
            out.append(_wrap(text, indent))
        buffer.clear()

    for child in node:
        if child.tag in _VERBATIM:
            flush()
            block = _verbatim(child, ids, indent)
            if block:
                out.append(block)
            buffer.append(child.tail or "")
        else:
            buffer.append(_inline(child, ids))
    flush()


def _render_blocks(node: ET.Element, ids: dict[str, str],
                   out: list[str], indent: str = "") -> None:
    """Turn a DocBook subtree into a list of plain-text blocks."""
    tag = node.tag
    if tag in _DROPPED:
        return
    if tag in _VERBATIM:
        block = _verbatim(node, ids, indent)
        if block:
            out.append(block)
        return
    if tag in {"para", "simpara"}:
        _render_para(node, ids, out, indent)
        return
    if tag == "title":
        text = _flat(node, ids)
        if text:
            out.append(indent + text)
        return
    if tag == "cmdsynopsis":
        block = _cmdsynopsis(node, ids, indent)
        if block:
            out.append(block)
        return
    if tag == "refnamediv":
        names = [_flat(child, ids) for child in node if child.tag == "refname"]
        purpose = [_flat(child, ids) for child in node if child.tag == "refpurpose"]
        line = ", ".join(name for name in names if name)
        if purpose and purpose[0]:
            line = f"{line} — {purpose[0]}" if line else purpose[0]
        if line:
            out.append(indent + line)
        return
    if tag in {"itemizedlist", "orderedlist", "simplelist", "procedure"}:
        _render_list(node, ids, out, indent)
        return
    if tag == "variablelist":
        _render_variablelist(node, ids, out, indent)
        return
    if tag == "row":
        _render_row(node, ids, out, indent)
        return
    for child in node:
        _render_blocks(child, ids, out, indent)


def _render_row(node: ET.Element, ids: dict[str, str],
                out: list[str], indent: str) -> None:
    """One table row, in whichever of the two shapes these documents use.

    The ordinary shape is several ``<entry>`` cells and becomes one line of
    pipe-separated values, which is a table and reads like one.

    ``catalogs.sgml`` and ``information_schema.sgml`` — between them 500 KB of
    the exact schema an injection enumerates — use the other shape: a single
    ``<entry>`` holding a ``<para role="column_definition">`` with the column
    name and type, followed by one or more ``<para>`` of description. Flattened
    into one cell that becomes ``rolbypassrls bool Role bypasses every
    row-level security policy, see Row Security Policies for more
    information.`` — everything is there and the boundary between the
    declaration and the sentence about it is gone, in the one place a model is
    supposed to learn that ``pg_authid.rolsuper`` is a ``bool``. So the
    definition gets its own line and the prose is indented under it.
    """
    entries = [cell for cell in node if cell.tag == "entry"]
    if not entries:
        return
    if len(entries) == 1:
        paragraphs = [child for child in entries[0] if child.tag in {"para", "simpara"}]
        if len(paragraphs) >= 2:
            # One block, not one per paragraph: the declaration and the
            # sentence about it belong to each other, and blocks are joined
            # with a blank line.
            lines = []
            head = _flat(paragraphs[0], ids)
            if head:
                lines.append(indent + "  " + head)
            for paragraph in paragraphs[1:]:
                body = _flat(paragraph, ids)
                if body:
                    lines.append(_wrap(body, indent + "      "))
            if lines:
                out.append("\n".join(lines))
            return
    cells = [_flat(cell, ids) for cell in entries]
    if any(cells):
        out.append(indent + "  " + " | ".join(cells))


def _render_list(node: ET.Element, ids: dict[str, str],
                 out: list[str], indent: str) -> None:
    numbered = node.tag in {"orderedlist", "procedure"}
    index = 0
    for item in node:
        if item.tag not in {"listitem", "member", "step"}:
            continue
        index += 1
        inner: list[str] = []
        if item.tag == "member":
            text = _flat(item, ids)
            if text:
                inner.append(_wrap(text, indent + "    "))
        else:
            for child in item:
                _render_blocks(child, ids, inner, indent + "    ")
        bullet = f"{index}. " if numbered else "- "
        block = _bullet(bullet, inner, indent)
        if block:
            out.append(block)


def _bullet(bullet: str, blocks: list[str], indent: str) -> str:
    body = "\n\n".join(block for block in blocks if block.strip())
    if not body.strip():
        return ""
    lines = body.split("\n")
    return "\n".join([indent + bullet + lines[0].lstrip()] + lines[1:])


def _render_variablelist(node: ET.Element, ids: dict[str, str],
                         out: list[str], indent: str) -> None:
    """Term-and-definition lists, which are how these docs describe parameters.

    The term is indented two spaces and its definition six, so the shape of a
    parameter list survives as layout rather than as a wall of paragraphs. This
    is the element that carries every column description in ``catalogs.sgml``
    and every clause of every statement in the reference.
    """
    for entry in node:
        if entry.tag != "varlistentry":
            continue
        terms = [_flat(term, ids) for term in entry if term.tag == "term"]
        terms = [term for term in terms if term]
        if terms:
            out.append(indent + "  " + ", ".join(terms))
        for item in entry:
            if item.tag != "listitem":
                continue
            for child in item:
                _render_blocks(child, ids, out, indent + "      ")


def _assemble(blocks: list[str]) -> str:
    return _BLANKS.sub("\n\n", "\n\n".join(b for b in blocks if b.strip())).strip()


def _render_element(node: ET.Element, ids: dict[str, str]) -> str:
    blocks: list[str] = []
    _render_blocks(node, ids, blocks)
    return _assemble(blocks)


# --------------------------------------------------------------------------
# osquery rendering
# --------------------------------------------------------------------------

def _literal(node: ast.AST) -> object | None:
    """``ast.literal_eval`` that answers ``None`` instead of raising.

    These spec files are data written in Python syntax, but they are still
    arbitrary Python: a value can be a name, a call, an f-string. Anything that
    is not a literal is not something this renderer can print, and the right
    answer is to skip that one field rather than to lose the table.
    """
    try:
        return ast.literal_eval(node)
    except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
        return None


@dataclass
class _TableSpec:
    """One osquery table, read out of its ``.table`` file."""

    name: str = ""
    description: str = ""
    implementation: str = ""
    aliases: list[str] = field(default_factory=list)
    attributes: list[str] = field(default_factory=list)
    #: ``(platform or "", column name, type, description, annotations)``.
    columns: list[tuple[str, str, str, str, str]] = field(default_factory=list)
    foreign_keys: list[tuple[str, str]] = field(default_factory=list)
    examples: list[str] = field(default_factory=list)


def _column(call: ast.Call, platform: str) -> tuple[str, str, str, str, str] | None:
    if len(call.args) < 2:
        return None
    name = _literal(call.args[0])
    if not isinstance(name, str):
        return None
    kind = call.args[1].id if isinstance(call.args[1], ast.Name) else "TEXT"
    description = ""
    if len(call.args) > 2:
        value = _literal(call.args[2])
        description = value if isinstance(value, str) else ""
    flags = []
    for keyword in call.keywords:
        value = _literal(keyword.value)
        if value is True:
            flags.append(keyword.arg or "")
        elif keyword.arg == "aliases" and isinstance(value, list):
            flags.append("aliases=" + ",".join(str(item) for item in value))
    return platform, name, kind, _flatten(description), ", ".join(f for f in flags if f)


def _parse_table_spec(text: str, ident: str) -> _TableSpec:
    """Read a ``.table`` file without executing it.

    osquery's own build *does* execute these — they are a Python DSL whose
    ``Column`` and ``schema`` are functions the generator defines — and running
    them here would mean running code out of a downloaded archive to produce
    training data. The file is compiled to an AST instead and the top-level
    calls are read off it.

    The syntax gate is :func:`compile` rather than :func:`ast.parse`, and the
    difference is not cosmetic: ``ast.parse`` stops after the parser, so a file
    that parses and cannot be compiled — a ``return`` at module level, a
    duplicate argument name — would be admitted here and would never be caught
    anywhere else, because nothing downstream executes it either. Warnings are
    suppressed around it because one spec's description contains ``\\P``, which
    Python 3.12 reports as a ``SyntaxWarning``; under ``-W error`` that file
    would vanish from the corpus for a typo in a comment.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        compile(text, ident, "exec")
        tree = compile(text, ident, "exec", ast.PyCF_ONLY_AST)

    spec = _TableSpec()
    for statement in tree.body:
        if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
            continue
        call = statement.value
        if not isinstance(call.func, ast.Name):
            continue
        name = call.func.id
        if name == "table_name" and call.args:
            value = _literal(call.args[0])
            spec.name = value if isinstance(value, str) else spec.name
            for keyword in call.keywords:
                if keyword.arg == "aliases":
                    value = _literal(keyword.value)
                    if isinstance(value, list):
                        spec.aliases = [str(item) for item in value]
        elif name == "description" and call.args:
            value = _literal(call.args[0])
            if isinstance(value, str):
                spec.description = _flatten(value)
        elif name == "implementation" and call.args:
            value = _literal(call.args[0])
            if isinstance(value, str):
                spec.implementation = value
        elif name == "attributes":
            for keyword in call.keywords:
                if _literal(keyword.value) is True and keyword.arg:
                    spec.attributes.append(keyword.arg)
        elif name == "examples" and call.args:
            value = _literal(call.args[0])
            if isinstance(value, list):
                spec.examples = [str(item).strip() for item in value if str(item).strip()]
        elif name in {"schema", "extended_schema"}:
            platform = ""
            columns = call.args[0] if call.args else None
            if name == "extended_schema" and len(call.args) > 1:
                if isinstance(call.args[0], ast.Name):
                    platform = call.args[0].id.lower()
                columns = call.args[1]
            if not isinstance(columns, ast.List):
                continue
            for element in columns.elts:
                if not isinstance(element, ast.Call) or not isinstance(element.func, ast.Name):
                    continue
                if element.func.id == "Column":
                    column = _column(element, platform)
                    if column is not None:
                        spec.columns.append(column)
                elif element.func.id == "ForeignKey":
                    pair = {keyword.arg: _literal(keyword.value)
                            for keyword in element.keywords}
                    if pair.get("column") and pair.get("table"):
                        spec.foreign_keys.append(
                            (str(pair["column"]), str(pair["table"]))
                        )
    return spec


def _render_table_spec(spec: _TableSpec) -> str:
    """An osquery table as SQL DDL, with each column's English beside it.

    Rendered rather than passed through as the Python it is written in. The
    point of admitting these files is that the corpus has no ``CREATE TABLE``
    in it anywhere, and ``Column("pid", BIGINT, "Process (or thread) ID")`` is
    not a ``CREATE TABLE`` — it is a constructor call, and the corpus already
    has six hundred thousand of those in ``pythoncode``.

    The name, type and comment columns are padded into alignment deliberately.
    Column structure is the single register that measured best against gpt2
    when this corpus was rebuilt, ``normalise()`` is contracted to preserve it,
    and it costs nothing to emit text that has some.
    """
    lines: list[str] = []
    header = f"osquery table: {spec.name}"
    if spec.aliases:
        header += "  (aliases: " + ", ".join(spec.aliases) + ")"
    lines.append(header)
    if spec.implementation:
        lines.append(f"implementation: {spec.implementation}")
    if spec.attributes:
        lines.append("attributes: " + ", ".join(sorted(spec.attributes)))
    lines.append("")
    if spec.description:
        block = _wrap(spec.description, "-- ")
        if block:
            lines.extend(block.split("\n"))
        lines.append("")

    if spec.columns:
        name_width = min(38, max(len(column[1]) for column in spec.columns))
        # +1 so the trailing comma sits inside the padded field and the
        # comment column lines up whether or not a row is the last one.
        type_width = max(len(column[2]) for column in spec.columns) + 1
        lines.append(f"CREATE TABLE {spec.name} (")
        platform = ""
        for index, (column_platform, name, kind, description, flags) in enumerate(spec.columns):
            if column_platform != platform:
                platform = column_platform
                if platform:
                    lines.append(f"    -- {platform} only")
            comment = description
            if flags:
                comment = f"{comment}  [{flags}]" if comment else f"[{flags}]"
            field_ = kind + ("," if index < len(spec.columns) - 1 else "")
            body = f"    {name.ljust(name_width)} {field_.ljust(type_width)}"
            lines.append(f"{body}  -- {comment}" if comment else body.rstrip())
        for column, table in spec.foreign_keys:
            lines.append(f"    -- FOREIGN KEY ({column}) REFERENCES {table}")
        lines.append(");")

    if spec.examples:
        lines.append("")
        lines.append("-- example queries")
        for example in spec.examples:
            for line in example.split("\n"):
                lines.append(f"    {line.rstrip()}")
    return "\n".join(lines)


#: mkdocs collapse chrome in the osquery wiki: a whole-line ``<details>``,
#: ``</details>``, ``<p>`` or ``</p>``.
_WIKI_CHROME = re.compile(r"^[ \t]*</?(?:details|p)>[ \t]*$\n?", re.MULTILINE)
#: ``<summary>C-Math function examples:</summary>`` — the caption is content,
#: the wrapper is not.
_WIKI_SUMMARY = re.compile(r"^([ \t]*)<summary>(.*?)</summary>[ \t]*$",
                           re.MULTILINE | re.DOTALL)


def _clean_wiki(text: str) -> str:
    """Remove the four pieces of HTML chrome in the osquery wiki. Nothing else.

    Measured rather than assumed, because this is where a markup stripper does
    damage. The rendered source contains 273 tag-shaped tokens. 114 of them are
    one construct repeated: nineteen ``<details>`` / ``<summary>`` / ``<p>``
    collapse widgets, six tags each, all in a single file —
    ``introduction/sql.md``, wrapped around its SQL function examples. Those
    are removed, and the ``<summary>`` is unwrapped to its caption, which is a
    real sentence: "Trig functions examples:" introduces the block under it.

    The other 159 are content and are left exactly alone. ``<key>``,
    ``<string>``, ``<dict>``, ``<array>`` and ``<true/>`` are macOS property
    lists quoted in the deployment pages; ``<StoredKey>``, ``<ServerKey>`` and
    ``<salt>`` are SCRAM placeholders in PostgreSQL's protocol chapter;
    ``<N>`` and ``<subid>`` are metasyntax. A rule that removed "HTML tags"
    would eat every one of them and leave a property list that no longer
    parses, which is the failure this note exists to prevent somebody
    repeating.
    """
    text = _WIKI_SUMMARY.sub(lambda m: f"{m.group(1)}{m.group(2).strip()}", text)
    return _WIKI_CHROME.sub("", text)


def _load_conf(raw: str) -> dict | None:
    """Parse an osquery pack, tolerating the one way they are not JSON.

    ``packs/osx-attacks.conf`` wraps its longer queries across lines with a
    trailing backslash — a shell continuation inside a JSON string, which is an
    illegal escape, and ``json.loads`` rejects the file whole. That file is 33
    macOS malware detections and the most interesting pack osquery ships, so
    losing it to a swallowed ``JSONDecodeError`` would be an expensive silence.

    The continuation is rewritten to a ``\\n`` escape rather than to a space,
    which keeps the query's own indentation: the six-line ``WireLurker``
    ``launchd`` query stays six lines, and the corpus gets a formatted SQL
    statement instead of a 400-character one-liner.
    """
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    try:
        parsed = json.loads(_JSON_CONTINUATION.sub("\\\\n", raw))
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _render_pack(name: str, conf: dict, seen: set[str]) -> tuple[str, int]:
    """One pack as a readable block: every query with what it is looking for.

    Rendered per pack rather than per query on purpose. A query on its own is a
    ``SELECT`` with no reason attached; the pack is the unit that says *these
    fourteen questions together are how you find this adversary on a Windows
    host*, and the platform and interval only mean something in that company.

    Deduplication is by query text and runs across upstreams, because these
    three repositories copy from each other — Palantir ships its own
    ``ossec-rootkit`` with 58 of osquery's 60 queries. Returns the number of
    duplicates dropped so :func:`_documents` can report it.
    """
    queries = {}
    for section in ("queries", "schedule"):
        block = conf.get(section)
        if isinstance(block, dict):
            queries.update(block)
    if not queries:
        return "", 0

    lines = [f"osquery pack: {name}"]
    platform = conf.get("platform")
    if isinstance(platform, str) and platform:
        lines.append(f"platform: {platform}")
    version = conf.get("version")
    if isinstance(version, str) and version:
        lines.append(f"osquery version: {version}")
    description = conf.get("description")
    if isinstance(description, str) and description.strip():
        lines.append("")
        block = _wrap(_flatten(description), "-- ")
        if block:
            lines.extend(block.split("\n"))

    kept = 0
    duplicates = 0
    for query_name, body in sorted(queries.items()):
        if not isinstance(body, dict):
            continue
        sql = body.get("query")
        if not isinstance(sql, str) or not sql.strip():
            continue
        mark = fingerprint(sql)
        if mark in seen:
            duplicates += 1
            continue
        seen.add(mark)
        kept += 1
        lines.append("")
        lines.append(f"-- {query_name}")
        for key in ("description", "value"):
            text = body.get(key)
            if isinstance(text, str) and text.strip():
                block = _wrap(_flatten(text), "-- ", hanging="--   ")
                if block:
                    lines.extend(block.split("\n"))
        meta = []
        for key in ("interval", "platform", "version", "snapshot", "removed"):
            value = body.get(key)
            if value not in (None, ""):
                meta.append(f"{key}={value}")
        if meta:
            lines.append("-- " + ", ".join(meta))
        for line in sql.strip().split("\n"):
            lines.append(f"    {line.rstrip()}")
    if kept == 0:
        return "", duplicates
    return "\n".join(lines), duplicates


# --------------------------------------------------------------------------
# fetch
# --------------------------------------------------------------------------

def _safe_members(tar: tarfile.TarFile) -> Iterator[tuple[tarfile.TarInfo, str]]:
    """Regular files only, with the archive's single root directory stripped.

    Member names in a tar file are attacker-controlled data in principle:
    absolute paths, ``..`` segments, symlinks and hardlinks are all
    expressible. These four archives are trusted in practice and the cheap
    defence is still to never hand an archive's own names to the filesystem, so
    only regular files are yielded and every path is checked before it is used.
    """
    for member in tar:
        if not member.isfile():
            continue
        parts = Path(member.name).parts
        if len(parts) < 2:
            continue
        relative = Path(*parts[1:])
        if relative.is_absolute() or ".." in relative.parts:
            continue
        yield member, relative.as_posix()


def _read_member(tar: tarfile.TarFile, member: tarfile.TarInfo) -> str | None:
    handle = tar.extractfile(member)
    if handle is None:
        return None
    with handle:
        raw = handle.read()
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _write(root: Path, relative: str, text: str) -> None:
    target = root / relative
    if not target.resolve().is_relative_to(root.resolve()):
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def _collect_ids(text: str, ids: dict[str, str]) -> bool:
    """Record every ``id`` in one SGML file against the label an xref wants.

    ``xreflabel`` first, because that is the attribute DocBook provides for
    exactly this and PostgreSQL uses it on every configuration parameter —
    ``<varlistentry id="guc-plan-cache-mode" xreflabel="plan_cache_mode">``.
    Then a ``<title>``, then a ``<refname>``, then a ``<term>``. Returns False
    if the file would not parse, which the caller counts: this pass runs over
    the whole doc tree including files this source does not keep, so a handful
    of failures is expected and a sudden pile of them is not.
    """
    try:
        root = _parse_fragment(text)
    except ET.ParseError:
        return False
    for element in root.iter():
        ident = element.get("id")
        if not ident or ident in ids:
            continue
        label = element.get("xreflabel", "").strip()
        if not label:
            for tag in ("title", "refname", "term"):
                child = element.find(tag)
                if child is not None:
                    label = _flatten("".join(child.itertext()))
                    break
        if label:
            ids[ident] = label
    return True


def _extract_postgres(tar: tarfile.TarFile, staging: Path,
                      report: dict[str, object]) -> int:
    """Keep the SQL statement reference, the named chapters, and an id map.

    The version is read out of ``meson.build`` first, because ``&version;``
    appears throughout the documentation and is defined in a ``version.sgml``
    the build *generates* — the repository does not contain it, so a parser
    meets an undefined entity and refuses the file. Reading the tree's own
    number means the substitution is ``20devel`` on master today rather than a
    constant here that goes stale at the next release and stays stale silently,
    since nothing downstream would ever notice.
    """
    version = "current"
    for member, relative in _safe_members(tar):
        if relative == "meson.build":
            text = _read_member(tar, member) or ""
            match = re.search(r"version:\s*'([^']+)'", text)
            if match:
                version = match.group(1)
            break

    dropped_here: dict[str, int] = {}
    ids: dict[str, str] = {}
    unparsed: list[str] = []
    kept = 0
    applications = 0

    # One pass. The id map is built from every SGML file in the doc tree, not
    # only the kept ones, because an xref in the statement reference routinely
    # points at a chapter this source does not collect — and an xref that does
    # not resolve leaves a sentence without its object.
    for member, relative in _safe_members(tar):
        if not relative.startswith("doc/src/sgml/") or not relative.endswith(".sgml"):
            continue
        raw = _read_member(tar, member)
        if raw is None:
            continue
        per_file: dict[str, int] = {}
        text = _substitute_entities(raw, version, per_file)
        if not _collect_ids(text, ids):
            unparsed.append(relative)

        rest = relative[len("doc/src/sgml/"):]
        keep = False
        if rest.startswith("ref/"):
            if rest == "ref/allfiles.sgml":
                continue
            # Client and server program manuals. See _PG_SQL_REFMISCINFO.
            if _PG_SQL_REFMISCINFO not in text:
                applications += 1
                continue
            _write(staging / "postgres" / "ref", rest[len("ref/"):], text)
            keep = True
        elif "/" not in rest and rest[:-5] in _PG_CHAPTERS:
            _write(staging / "postgres" / "chapters", rest, text)
            keep = True
        if keep:
            kept += 1
            for name, count in per_file.items():
                dropped_here[name] = dropped_here.get(name, 0) + count

    _write(staging / "postgres", "ids.json",
           json.dumps(ids, indent=0, sort_keys=True))
    report["postgres_version"] = version
    report["postgres_ids"] = len(ids)
    report["postgres_entities_dropped"] = dict(sorted(dropped_here.items()))
    # Names, not just a count. Seven files in the tree are DTD fragments and
    # entity lists with no root element, and they are *supposed* to fail; a
    # bare number cannot tell that apart from the day a real chapter starts
    # failing to parse.
    report["postgres_unparsed_sgml"] = sorted(unparsed)
    report["postgres_application_refs_skipped"] = applications
    return kept


def _extract_osquery(tar: tarfile.TarFile, staging: Path,
                     report: dict[str, object]) -> int:
    kept = 0
    specs = packs = wiki = 0
    for member, relative in _safe_members(tar):
        text = None
        if relative.startswith("specs/") and relative.endswith(".table"):
            text = _read_member(tar, member)
            if text is None:
                continue
            _write(staging / "osquery" / "specs", relative[len("specs/"):], text)
            specs += 1
        elif relative.startswith("packs/") and relative.endswith(".conf"):
            text = _read_member(tar, member)
            if text is None:
                continue
            _write(staging / "packs" / "osquery", relative[len("packs/"):], text)
            packs += 1
        elif relative.startswith("docs/wiki/") and relative.endswith(".md"):
            if any(relative.startswith(skip) for skip in _OSQUERY_WIKI_SKIP):
                continue
            text = _read_member(tar, member)
            if text is None:
                continue
            _write(staging / "osquery" / "wiki", relative[len("docs/wiki/"):], text)
            wiki += 1
        if text is not None:
            kept += 1
    report["osquery_specs"] = specs
    report["osquery_packs"] = packs
    report["osquery_wiki"] = wiki
    return kept


def _extract_confs(tar: tarfile.TarFile, staging: Path, label: str,
                   prefixes: tuple[str, ...], report: dict[str, object]) -> int:
    kept = 0
    for member, relative in _safe_members(tar):
        if not relative.endswith(".conf"):
            continue
        if prefixes and not any(relative.startswith(p) for p in prefixes):
            continue
        text = _read_member(tar, member)
        if text is None:
            continue
        _write(staging / "packs" / label, relative.replace("/", "__"), text)
        kept += 1
    report[f"{label}_packs"] = kept
    return kept


def _check_licences(tar: tarfile.TarFile, upstream: _Upstream,
                    staging: Path) -> None:
    """Copy each upstream's licence into the cache, and verify it still says so.

    Not a formality. Three briefs written against this package named a licence
    the upstream does not carry, and the only thing that caught them was
    somebody opening the file. A check that the phrase is still there turns
    "this was true when it was written" into "this is true on the machine that
    built the corpus" — an upstream that relicenses fails the fetch rather than
    quietly changing what the model was trained on.
    """
    found: dict[str, str] = {}
    for member, relative in _safe_members(tar):
        for wanted, _phrase in upstream.license_files:
            if relative == wanted:
                text = _read_member(tar, member)
                if text is not None:
                    found[wanted] = text
    for wanted, phrase in upstream.license_files:
        text = found.get(wanted)
        if text is None:
            raise SourceError(
                f"{_NAME}: {upstream.name} no longer ships {wanted} at its "
                "root. Every source here keeps the upstream licence text on "
                "disk beside the material it covers; an archive that stopped "
                "carrying it needs a human to look, not a default."
            )
        if phrase not in text:
            raise SourceError(
                f"{_NAME}: {upstream.name}'s {wanted} no longer contains "
                f"{phrase!r}. This source declares {upstream.license!r} on the "
                "strength of that phrase. Read the new licence and update the "
                "declaration before building on it."
            )
        _write(staging / "licenses", f"{upstream.name}.{Path(wanted).name}", text)


def _fetch(cache_dir: Path) -> Path:
    """Download four archives, filter them, leave a curated tree in the cache.

    Idempotent and network-free on re-run. The marker is written last and only
    after the staging tree has been swapped into place, so an interrupted fetch
    re-downloads instead of leaving a half-populated directory that the next
    run would mistake for a finished corpus.

    Archives are deleted as soon as they are unpacked: PostgreSQL's is 31 MB of
    database engine for 3 MB of documentation, and keeping it would be paying
    disk to avoid a download that only happens once.

    Accepts either the per-source directory ``build.py`` passes
    (``<cache>/sqlsec``) or the cache root, so running this by hand during
    development does not scatter the tree across the shared cache.
    """
    root = cache_dir if cache_dir.name == _NAME else cache_dir / _NAME
    root.mkdir(parents=True, exist_ok=True)

    marker = root / _MARKER
    if marker.is_file():
        try:
            recorded = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            recorded = {}
        if recorded.get("cache_version") == _CACHE_VERSION:
            return root

    staging = root / ".staging"
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True, exist_ok=True)

    manifest: list[dict[str, object]] = []
    try:
        for upstream in _UPSTREAMS:
            archive = root / f".{upstream.name}.tar.gz.part"
            try:
                download(upstream.archive, archive, timeout=900,
                         max_bytes=_MAX_ARCHIVE_BYTES)
            except NetworkError as exc:
                raise SourceError(f"{_NAME}: {upstream.name}: {exc}") from None

            report: dict[str, object] = {}
            try:
                with tarfile.open(archive, mode="r:gz") as tar:
                    _check_licences(tar, upstream, staging)
                with tarfile.open(archive, mode="r:gz") as tar:
                    if upstream.name == "postgres":
                        kept = _extract_postgres(tar, staging, report)
                    elif upstream.name == "osquery":
                        kept = _extract_osquery(tar, staging, report)
                    elif upstream.name == "palantir":
                        kept = _extract_confs(tar, staging, "palantir",
                                              ("Classic/",), report)
                    else:
                        kept = _extract_confs(tar, staging, "osquery-attck",
                                              (), report)
            except tarfile.TarError as exc:
                raise SourceError(
                    f"{_NAME}: could not unpack {upstream.name}: {exc}"
                ) from exc
            finally:
                archive.unlink(missing_ok=True)

            if kept < upstream.min_files:
                raise SourceError(
                    f"{_NAME}: {upstream.name} yielded only {kept} files "
                    f"(expected at least {upstream.min_files}). The upstream "
                    "layout has probably changed; fix the selection rather "
                    "than training on a fraction of it."
                )
            manifest.append({
                "upstream": upstream.name,
                "url": upstream.url,
                "archive": upstream.archive,
                "license": upstream.license,
                "license_files": [name for name, _ in upstream.license_files],
                "selection": upstream.notes,
                "kept": kept,
                **report,
            })

        for name in ("postgres", "osquery", "packs", "licenses"):
            source = staging / name
            if source.is_dir():
                shutil.rmtree(root / name, ignore_errors=True)
                source.replace(root / name)
        marker.write_text(
            json.dumps(
                {
                    "cache_version": _CACHE_VERSION,
                    "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "upstreams": manifest,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return root


# --------------------------------------------------------------------------
# documents
# --------------------------------------------------------------------------

def _walk(root: Path, suffix: str) -> Iterator[Path]:
    """Every file under ``root`` with this suffix, symlinks never followed.

    ``os.walk(followlinks=False)`` rather than ``rglob``, for the reason
    :mod:`~training.corpus.sources.ownrepos` records the hard way: a sibling
    adapter once followed a symlink into the shared corpus cache and pulled
    180 MB of other sources back in under its own name. This tree is written by
    :func:`_fetch` and contains no links at all, which is exactly the situation
    in which an unexamined ``rglob`` survives review and then does not survive
    the day somebody points a link at the cache.
    """
    if not root.is_dir():
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(
            name for name in dirnames
            if name not in _SKIP_DIRS and not Path(dirpath, name).is_symlink()
        )
        for filename in sorted(filenames):
            if not filename.endswith(suffix):
                continue
            path = Path(dirpath, filename)
            if not path.is_symlink():
                yield path


def _split_chapter(root: ET.Element, ids: dict[str, str],
                   title: str) -> Iterator[tuple[str, str]]:
    """A chapter as one document per section, keyed by the section's id.

    Chapters here run to 345 KB of SGML and a chapter-sized document is one
    training sample that will never fit a context window whole. ``<sect1>`` is
    the natural cut: in ``catalogs.sgml`` it is one system catalogue per
    section, which is exactly the unit somebody would want to read. A section
    over :data:`_MAX_SECTION_CHARS` is cut again at ``<sect2>``; one with no
    ``<sect2>`` children is left long rather than sliced at a character count,
    because a document that stops mid-sentence is worse than a big one.
    """
    container = _container(root)
    sections = [child for child in container if child.tag == "sect1"]
    if not sections:
        text = _render_element(root, ids)
        if text:
            yield "", f"{title}\n\n{text}"
        return

    # Whatever sits before the first <sect1> is the chapter's own
    # introduction — the paragraph that says what the following twenty
    # sections are collectively for. Dropping it because it has no section of
    # its own would lose the framing and keep the detail.
    blocks: list[str] = []
    for child in container:
        if child.tag == "sect1":
            break
        _render_blocks(child, ids, blocks)
    intro = _assemble(blocks)
    if len(intro) >= _MIN_DOC_CHARS:
        yield "", f"{title}\n\n{intro}"

    for section in sections:
        ident = section.get("id", "")
        text = _render_element(section, ids)
        if len(text) <= _MAX_SECTION_CHARS:
            if text:
                yield ident, f"{title}\n\n{text}"
            continue
        subsections = [child for child in section if child.tag == "sect2"]
        if not subsections:
            yield ident, f"{title}\n\n{text}"
            continue
        heading = section.find("title")
        section_title = _flatten("".join(heading.itertext())) if heading is not None else ident
        # The lead-in before the first <sect2> carries the section's own
        # introduction, which is often the part that says what the following
        # subsections are for.
        lead = [child for child in section if child.tag not in {"sect2"}]
        blocks: list[str] = []
        for child in lead:
            _render_blocks(child, ids, blocks)
        preamble = _assemble(blocks)
        if len(preamble) >= _MIN_DOC_CHARS:
            yield ident, f"{title}\n\n{preamble}"
        for subsection in subsections:
            sub_ident = subsection.get("id", "") or ident
            sub_text = _render_element(subsection, ids)
            if sub_text:
                yield sub_ident, f"{title} — {section_title}\n\n{sub_text}"


def _documents(path: Path) -> Iterator[Document]:
    """Yield every rendered document, deduplicated, with per-document registers.

    The register and side vary by what the document is, and ``build.py`` counts
    the document's own values rather than the spec's, so the mix is reported
    honestly instead of averaged into one label:

    * PostgreSQL statement reference -> SYSTEM / NEUTRAL. A language reference.
    * PostgreSQL chapters -> PROSE / NEUTRAL. Explanation in sentences, which
      is the register this corpus is second-shortest of.
    * osquery table schemas -> SYSTEM / NEUTRAL. A schema is how the machine
      describes itself.
    * osquery wiki -> PROSE / BLUE. Writing about how to watch a fleet.
    * Packs -> DETECTION / BLUE, for the reason the module docstring gives.

    Deduplication runs over the whole source because these upstreams copy from
    each other, and query-level dedup inside :func:`_render_pack` runs first so
    that a pack which is 95% somebody else's still contributes its own 5%.
    """
    ids: dict[str, str] = {}
    ids_file = path / "postgres" / "ids.json"
    if ids_file.is_file():
        try:
            loaded = json.loads(ids_file.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                ids = {str(k): str(v) for k, v in loaded.items()}
        except (OSError, json.JSONDecodeError):
            ids = {}

    seen: set[str] = set()

    def emit(text: str, ident: str, register: Register, side: Side) -> Document | None:
        cleaned = normalise(text)
        if len(cleaned) < _MIN_DOC_CHARS:
            return None
        mark = fingerprint(cleaned)
        if mark in seen:
            return None
        seen.add(mark)
        return Document(text=cleaned, source=_NAME, register=register,
                        side=side, ident=ident)

    ref_root = path / "postgres" / "ref"
    for file in _walk(ref_root, ".sgml"):
        try:
            root = _parse_fragment(file.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, ET.ParseError):
            continue
        document = emit(_render_element(root, ids),
                        f"postgres/ref/{file.relative_to(ref_root).as_posix()}",
                        Register.SYSTEM, Side.NEUTRAL)
        if document is not None:
            yield document

    chapter_root = path / "postgres" / "chapters"
    for file in _walk(chapter_root, ".sgml"):
        stem = file.stem
        title = _PG_CHAPTERS.get(stem, stem)
        try:
            root = _parse_fragment(file.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, ET.ParseError):
            continue
        for ident, text in _split_chapter(root, ids, f"PostgreSQL: {title}"):
            document = emit(text, f"postgres/{stem}.sgml#{ident or 'all'}",
                            Register.PROSE, Side.NEUTRAL)
            if document is not None:
                yield document

    spec_root = path / "osquery" / "specs"
    for file in _walk(spec_root, ".table"):
        ident = f"osquery/specs/{file.relative_to(spec_root).as_posix()}"
        try:
            source = file.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        try:
            spec = _parse_table_spec(source, ident)
        except (SyntaxError, ValueError) as exc:
            raise SourceError(
                f"{_NAME}: {ident} is not compilable Python ({exc}). These "
                "files are osquery's table DSL and the whole schema half of "
                "this source is read off them; a spec that no longer compiles "
                "means the DSL changed, which needs a human, not a skip."
            ) from None
        if not spec.name or not spec.columns:
            continue
        document = emit(_render_table_spec(spec), ident,
                        Register.SYSTEM, Side.NEUTRAL)
        if document is not None:
            yield document

    wiki_root = path / "osquery" / "wiki"
    for file in _walk(wiki_root, ".md"):
        try:
            text = file.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        document = emit(_clean_wiki(text),
                        f"osquery/wiki/{file.relative_to(wiki_root).as_posix()}",
                        Register.PROSE, Side.BLUE)
        if document is not None:
            yield document

    pack_root = path / "packs"
    query_marks: set[str] = set()
    repeated = 0
    unparsable: list[str] = []
    for file in _walk(pack_root, ".conf"):
        ident = f"packs/{file.relative_to(pack_root).as_posix()}"
        try:
            conf = _load_conf(file.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError):
            continue
        if not isinstance(conf, dict):
            unparsable.append(ident)
            continue
        text, duplicates = _render_pack(file.stem, conf, query_marks)
        repeated += duplicates
        if not text:
            continue
        document = emit(text, ident, Register.DETECTION, Side.BLUE)
        if document is not None:
            yield document

    # Printed for the same reason capec and cwe print theirs: the numbers that
    # say whether the filters are still doing what they were written to do do
    # not survive into the build report, which only counts documents. A pack
    # count that collapses, or a repeated-query count that goes to zero because
    # an upstream renamed its tree, is invisible otherwise.
    print(f"   {_NAME}: {len(query_marks):,} distinct pack queries, "
          f"{repeated} repeated across the three pack repositories and kept "
          f"once; {len(ids):,} DocBook ids resolved for xref text")
    if unparsable:
        print(f"   ! {_NAME}: {len(unparsable)} pack file(s) would not parse "
              f"even after the backslash-continuation repair: "
              f"{', '.join(unparsable[:5])}")


SPEC = SourceSpec(
    name=_NAME,
    license=(
        "Composite, one statement per upstream, each read out of that "
        "upstream's own licence file at fetch time and re-checked on every "
        "fetch. postgres/postgres: the PostgreSQL License, which lives in a "
        "file called COPYRIGHT rather than LICENSE (permissive, BSD/MIT-style; "
        "Portions Copyright (c) 1996-2026 PostgreSQL Global Development Group, "
        "Portions Copyright (c) 1994 The Regents of the University of "
        "California). osquery/osquery: dual-licensed, 'SPDX-License-Identifier: "
        "Apache-2.0 OR GPL-2.0-only', with the repository stating that a user "
        "is free to choose one — Apache-2.0 is the option elected here, so "
        "nothing GPL is relied on. palantir/osquery-configuration: MIT, "
        "Copyright (c) 2017 Palantir Technologies Inc. teoseller/osquery-attck: "
        "Apache-2.0, from an unmodified LICENSE.txt whose copyright appendix "
        "the author never filled in, so the repository names no copyright "
        "holder. Every one of those files is copied into the cache under "
        "licenses/ beside the material it covers, and _check_licences refuses "
        "the fetch if a file disappears or stops containing the phrase this "
        "declaration rests on. sqlmap was considered and rejected: GPL-2.0 for "
        "text the corpus already holds under MIT via payloads."
    ),
    url="https://github.com/osquery/osquery and https://github.com/postgres/postgres",
    register=Register.SYSTEM,
    side=Side.NEUTRAL,
    fetch=_fetch,
    documents=_documents,
    #: 786 documents when this was written: 185 PostgreSQL statement
    #: references, 271 chapter sections, 288 osquery table schemas, 19 wiki
    #: pages and 42 packs. The floor sits about 20% under that, so ordinary
    #: upstream churn is quiet while a whole upstream vanishing — a renamed
    #: specs/ directory, a moved doc tree, a chapter that stops parsing — is
    #: not. Each upstream also carries its own floor in _Upstream.min_files,
    #: which fails at fetch time and names the culprit; this is the backstop
    #: for several shrinking a little at once.
    expect_min_docs=620,
    notes=(
        "SQL from both ends. PostgreSQL's SQL statement reference (185 pages: "
        "GRANT, REVOKE, CREATE POLICY, PREPARE/EXECUTE, CREATE FUNCTION, COPY) "
        "plus eleven chapters chosen for what they explain — dynamic SQL and "
        "why binding a value defeats a quote, string-literal syntax, join "
        "semantics, roles and privileges, row-level security, the system "
        "catalogues an injection enumerates, and the Parse/Bind/Execute "
        "protocol that makes a parameterised query safe. Against that, osquery: "
        "288 table specs rendered as CREATE TABLE DDL with every column's "
        "description beside it, 19 wiki pages on querying a fleet, and 534 "
        "distinct pack queries from three repositories, deduplicated by query "
        "text because they copy from each other. Registers are per document — "
        "SYSTEM for the references and schemas, PROSE for the chapters and "
        "wiki, DETECTION for the packs. PostgreSQL's client- and server-program "
        "man pages are deliberately excluded: 1.0 MB of option lists in a "
        "register manpages and tldr already cover."
    ),
)
