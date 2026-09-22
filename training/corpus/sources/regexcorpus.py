"""Regular expressions: the substrate every detection rule is written in.

Nothing in this corpus teaches the model what a regular expression *means*, and
almost everything in it is made of them. ``netrules`` holds 37,000 Suricata
rules whose ``pcre:`` option is a raw PCRE pattern. ``yara`` rules carry
``$re = /.../`` strings. Sigma's ``|re`` modifier, Splunk's ``rex``, Elastic's
KQL and every grok expression in a log pipeline are regex or regex-adjacent.
Every ``detect.*`` verb in this project's own catalogue is, underneath, a
pattern applied to a line of text. The model has met tens of thousands of
regexes as *tokens* and has never once been told that ``a*`` prefers more and
``a*?`` prefers fewer, or what the engine does when the preference turns out to
be wrong.

That second half is the part worth paying for, and it is why this source is
weighted the way it is. A syntax table is cheap and the model can half-infer one
from exposure; the *model of the engine* cannot be inferred from examples at
all. Backtracking, atomic groups, possessive quantifiers, the difference between
an assertion and a consuming match, why a linear-time engine has to refuse
backreferences — those are stated in prose or not learned.

**And catastrophic backtracking is an availability vulnerability, not a
performance note.** This repository lost seven and a half hours of a training
run to a regex whose two alternation branches could both match a backslash; the
pattern was correct, the tests passed, and the corpus build sat at 100% CPU
until someone looked. A model that reasons about detection engineering should
recognise that shape on sight, so this source deliberately carries the
engine-level explanation of *why* it is exponential (PCRE2's ``pcre2perform``
and ``pcre2pattern``), the counter-argument from an engine that refuses to have
the problem (RE2), and a catalogue of the shapes with their safe rewrites
(``eslint-plugin-regexp``'s rule documentation, which is the largest body of
"this regex is wrong, here is the right one" prose available under a permissive
licence).

Five upstreams, each doing a job the others cannot:

* **PCRE2's own documentation** — the semantics, from the engine Suricata's
  ``pcre:`` keyword, PHP's ``preg_*``, nginx and Apache all actually run.
  ``pcre2pattern`` alone is 193 KB of running English about greediness,
  atomicity, lookaround, recursion and the backtracking control verbs.
* **RE2** — the other half of the argument. Its README is the clearest short
  statement anywhere of why a production engine gives up backreferences and
  lookaround to buy linear time, and its syntax reference is the only one that
  annotates every quantifier with "prefer more" / "prefer fewer" rather than
  the useless word "greedy".
* **logstash-patterns-core** — 680 named grok patterns. This is the corpus's
  only source of the join *named pattern = regex = what it parses*, and it is
  the shape of every log-parsing problem the agent will meet.
* **OWASP Core Rule Set** — 318 WAF rules whose operator is ``@rx``, each with
  the message, the CAPEC tag and the transformation chain that says what the
  regex is looking at; plus the ``regex-assembly`` sources those rules are
  built from, which are commented regex *construction*.
* **eslint-plugin-regexp's rule docs** — 80-odd short essays on regex
  anti-patterns, each with a wrong version and a right one, including the
  ReDoS rules.

**Register is split, and this is the first source in the corpus to do it.**
Every other adapter emits one register because every other adapter has one kind
of text in it. This one genuinely has three, and collapsing them would make the
balance report lie in whichever direction was chosen. The engine-semantics pages
are :class:`~training.corpus.source.Register.PROSE` — running argument in
sentences, which is the register sitting at 1.8% against a 9% target. The grok
patterns and the CRS rules are
:class:`~training.corpus.source.Register.DETECTION`: named fields, rule ids,
tags and match logic, which is exactly what that register is for. The syntax
reference and the pages that are mostly API surface (``pcre2syntax``,
``pcre2jit``, ``pcre2partial``, ``pcre2callout``) are
:class:`~training.corpus.source.Register.SYSTEM`, because "how the machine
works … API references" is the definition and a page that spends its length on
``PCRE2_PARTIAL_HARD`` is not prose however well it is written.
:data:`SPEC` declares DETECTION because that is the plurality by document count;
:func:`_documents` is what the balancer reads, and it reads per document.

**Side is NEUTRAL, and that is worth saying out loud because the corpus is
short of red.** An engine's semantics are not offensive or defensive. The grok
and CRS documents are honestly BLUE — they are detection logic. Nothing here is
RED, and pretending otherwise to move a number would be the kind of quiet lie
that makes a balance report worthless. This source pays into PROSE and
DETECTION and costs the red share slightly; that is the trade, stated.

**What the surface form looks like, and the trap in it.** CRS ships
``regex-assembly`` files that annotate a pattern with ASCII column rulers::

    ##! Cover the CONNECT method
    ##! Meth |----- IPv4 Address ------|- Port -| Protocol |
    ^connect (?:\\d{1,3}\\.){3}\\d{1,3}\\.?(?::\\d+)?\\s+[\\w\\./]+$

The comment means nothing unless its columns line up with the pattern beneath
it. :func:`~training.corpus.source.normalise` is contracted never to collapse
horizontal whitespace and this is a source that would be silently destroyed if
that contract ever slipped — the character count would barely move and the
annotation would become gibberish. So it is checked rather than trusted:
:func:`_assert_columns_survive` proves every non-blank line of every assembly
file comes back from ``normalise`` unchanged except for trailing whitespace,
and raises naming the file if it does not.

**The trap this adapter actually hit.** The obvious way to prove a grok pattern
matches the sample log line beside it is to resolve the ``%{...}`` references,
compile the result and run it. This adapter deliberately does not. Python's
``re`` has no timeout, several resolved grok patterns are multi-kilobyte
alternations of nested quantifiers, and a corpus build that wedges at 100% CPU
on a pathological subject is *precisely* the failure this source exists to teach
about. Writing the ReDoS source by causing a ReDoS would have been a poor joke
to explain afterwards. The samples are instead taken from the upstream's own
test suite — which is the authority on what a pattern parses, and needs no
verification from here — with any sample whose surrounding test asserts a
*non*-match discarded by :func:`_harvest_samples`. The claim printed in the
document is "this line comes from the upstream's test for this pattern", which
is true whatever Python's engine would have done with it.

**Licences, each read from the upstream's own file and copied into the cache**
beside the text it covers, because a badge is not a licence:

* PCRE2 — ``LICENCE.md``, ``BSD-3-Clause WITH PCRE2-exception``. That file
  says in its own words that "The documentation for PCRE2, supplied in the
  'doc' directory, is distributed under the same terms as the software
  itself", which is the sentence that makes this source legal, since the
  documentation is all that is taken.
* RE2 — ``LICENSE``, BSD-3-Clause, Copyright (c) 2009 The RE2 Authors.
* logstash-patterns-core — ``LICENSE``, Apache-2.0.
* coreruleset — ``LICENSE``, Apache-2.0.
* eslint-plugin-regexp — ``LICENSE``, MIT, Copyright (c) 2020 Yosuke Ota.

Nothing here is copyleft, which was not a given: the first three candidates for
the ReDoS half of this source were not usable as written, and the reasons are
recorded in :data:`_REJECTED` rather than left for the next person to
rediscover.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tarfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from ..net import NetworkError, download, fetch as http_get
from ..source import (
    Document, Register, Side, SourceError, SourceSpec, fingerprint, normalise,
)

_NAME = "regexcorpus"

#: Written last, so its presence means every upstream landed. The version is
#: part of it: when the gates below change, a cache built under the old rules is
#: stale, and silently reusing it is how a fix fails to reach the machine that
#: already ran the build once.
_MARKER = ".fetched.json"
_CACHE_VERSION = 1

#: Below this a rendering is a heading with nothing under it — a malformed
#: entry, not a document. Every real one clears it comfortably.
_MIN_CHARS = 200


# ---------------------------------------------------------------------------
# upstreams
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _Upstream:
    """One project, its verified licence, and the part of it worth keeping."""

    #: Directory under the cache root. Short, because it appears in every
    #: document's ``ident``.
    dirname: str
    name: str
    url: str
    #: Read from the project's own licence file, not from a repository badge.
    license: str
    #: The licence file inside the archive, so ``_extract`` can prove it exists.
    license_file: str
    #: A codeload tarball. Empty for the one upstream fetched as raw files.
    archive: str
    #: Path prefixes to keep, relative to the archive root after its single
    #: top-level directory is stripped. Everything else is never decoded.
    keep: tuple[str, ...]
    #: Floor on files surviving extraction. An upstream that suddenly yields
    #: fewer has moved its tree and should say so at fetch time, not as a thin
    #: build report three sources later.
    min_files: int


_PCRE2 = _Upstream(
    dirname="pcre2",
    name="PCRE2",
    url="https://github.com/PCRE2Project/pcre2",
    license=(
        "BSD-3-Clause WITH PCRE2-exception — LICENCE.md, which states its own "
        "SPDX identifier and says that 'The documentation for PCRE2, supplied "
        "in the doc directory, is distributed under the same terms as the "
        "software itself'. Copyright (c) 1997-2007 University of Cambridge, "
        "(c) 2007-2024 Philip Hazel. Only doc/ is taken."
    ),
    license_file="LICENCE.md",
    # Not a tarball. The repository is tens of megabytes of C and test data for
    # two text files; doc/pcre2.txt is the whole man-page set already rendered
    # to plain text by the maintainer, which is 671 KB and exactly what is
    # wanted. Two requests against a 40 MB download is not a close call.
    archive="",
    keep=("doc/pcre2.txt",),
    min_files=1,
)

_RE2 = _Upstream(
    dirname="re2",
    name="RE2",
    url="https://github.com/google/re2",
    license="BSD-3-Clause (Copyright (c) 2009 The RE2 Authors; LICENSE read "
            "and copied into the cache)",
    license_file="LICENSE",
    archive="https://codeload.github.com/google/re2/tar.gz/refs/heads/main",
    keep=("README.md", "doc/syntax.txt"),
    min_files=2,
)

_GROK = _Upstream(
    dirname="grok",
    name="logstash-patterns-core",
    url="https://github.com/logstash-plugins/logstash-patterns-core",
    license="Apache-2.0 (Elasticsearch B.V.; LICENSE read and copied into the "
            "cache. NOTICE.TXT is kept beside it.)",
    license_file="LICENSE",
    archive="https://codeload.github.com/logstash-plugins/"
            "logstash-patterns-core/tar.gz/refs/heads/main",
    # spec/ is not filler here: it is the only place the upstream states what a
    # pattern is supposed to parse, and a named regex without a sample line is
    # half a document.
    keep=("patterns/", "spec/patterns/", "NOTICE.TXT"),
    min_files=40,
)

_CRS = _Upstream(
    dirname="crs",
    name="OWASP CRS",
    url="https://github.com/coreruleset/coreruleset",
    license="Apache-2.0 (OWASP CRS project; LICENSE read and copied into the "
            "cache)",
    license_file="LICENSE",
    archive="https://codeload.github.com/coreruleset/coreruleset/tar.gz/"
            "refs/heads/main",
    keep=("rules/", "regex-assembly/"),
    min_files=100,
)

_LINT = _Upstream(
    dirname="regexplint",
    name="eslint-plugin-regexp",
    url="https://github.com/ota-meshi/eslint-plugin-regexp",
    license="MIT (Copyright (c) 2020 Yosuke Ota; LICENSE read and copied into "
            "the cache)",
    license_file="LICENSE",
    archive="https://codeload.github.com/ota-meshi/eslint-plugin-regexp/"
            "tar.gz/refs/heads/master",
    keep=("docs/rules/",),
    min_files=60,
)

_UPSTREAMS: tuple[_Upstream, ...] = (_PCRE2, _RE2, _GROK, _CRS, _LINT)

#: Named here rather than in a commit message, because a rejection is the most
#: expensive thing to rediscover. Each of these was considered for the ReDoS and
#: engine-documentation half of this source and left out.
_REJECTED: tuple[str, ...] = (
    "perlre(1) / perlretut(1) / perlrequick(1) / perlreref(1) — Perl's own "
    "regex documentation, and the obvious first choice. Already in the corpus: "
    "the manpages adapter reads /usr/share/man/man1 from this machine, which "
    "ships all five. Re-fetching would have duplicated text the corpus "
    "already holds, and duplicated text in a small corpus is worse than absent "
    "text because the model memorises it.",

    "OWASP 'Regular expression Denial of Service' cheat sheet material — the "
    "owasp adapter already carries the Cheat Sheet Series, including the input "
    "validation page that covers ReDoS.",

    "pcre2api(3) — 250 KB, the largest page in the PCRE2 set, and excluded. It "
    "is a C function reference: pcre2_compile(), pcre2_match_data_create(), "
    "option bit tables. It would have been 37% of this source's characters and "
    "taught almost nothing about what a pattern means. The one part of it worth "
    "having, the argument that a match limit is a resource control, is stated "
    "in pcre2perform and pcre2limits, which are both kept.",

    "coreruleset tests/ — 343 FTW YAML files pairing every rule with the "
    "payloads that trip it, which would have been the single best 'here is the "
    "regex, here is a string that matches it' pairing in the corpus. Left out "
    "because the files also contain negative tests, distinguished from positive "
    "ones only by the contents of a nested output: block, and telling them "
    "apart needs a real YAML parser. PyYAML is an optional extra in this "
    "project's pyproject, not a dependency, so a build on a machine that "
    "happens to have it would produce a different corpus from one that does "
    "not. A corpus that depends on what is installed is not reproducible, and a "
    "line-oriented scanner that mislabels a negative test as a match would be "
    "teaching the model that a rule matches a string it rejects.",

    "github/codeql's js/redos and py/redos query help (MIT) — genuinely good "
    "ReDoS explanations with vulnerable and fixed examples, but they are ~30 "
    "small files scattered through a repository of several gigabytes, "
    "reachable only by fetching each raw path by hand. A list of thirty "
    "hardcoded upstream paths is a source that breaks quietly the first time "
    "anything is reorganised, which is the opposite of what expect_min_docs "
    "is for.",

    "substack/safe-regex — named in the brief as a ReDoS test corpus and NOT "
    "USABLE: the repository publishes no LICENSE file at all. package.json "
    "claims MIT, which is a claim in a metadata field and not a licence grant "
    "in the repository. An upstream with no licence file is all rights "
    "reserved until its author says otherwise, and this project already has "
    "one adapter disabled for exactly that reason.",

    "davisjam/vuln-regex-detector (MIT) and makenowjust-labs/recheck (MIT) — "
    "both cleanly licensed and both rejected on content, not licence. What "
    "they publish is machine-readable: a regex, a language tag and an attack "
    "string, with no explanation of why the pattern is exponential. The brief "
    "asked for vulnerable patterns *with* the reasoning and the safe rewrite, "
    "and a bare list of evil regexes teaches the shape without the model of "
    "the engine underneath it. eslint-plugin-regexp's docs carry both.",

    "Sieve (this project's maintainer's own regex workbench, which has a ReDoS "
    "probe) — not vendored. The brief asked for it to be said out loud if it "
    "were, and it is not: its probe is code rather than a corpus of explained "
    "patterns, and the ownrepos adapter is the place where this author's own "
    "repositories enter the corpus, under one policy, rather than leaking in "
    "through a topic source.",

    "swtch.com/~rsc/regexp — Russ Cox's three articles on regular expression "
    "theory, which RE2's own README points at and which are the best writing "
    "on this subject anywhere. Published on a personal site under no licence "
    "grant. Not taken.",
)


# ---------------------------------------------------------------------------
# PCRE2: man pages, split into sections
# ---------------------------------------------------------------------------

#: A man page boundary inside the concatenated text file. The page name is
#: repeated at both ends of the running header, which is what makes this
#: unambiguous against a line of prose that happens to be in capitals.
_PCRE2_PAGE = re.compile(r"^([A-Z0-9_]+)\(3\)\s+PCRE2\s+\1\(3\)$", re.MULTILINE)

#: A top-level section heading: all caps at column zero. Sub-headings in these
#: pages are indented three spaces and are deliberately not matched, because a
#: section like "ATOMIC GROUPING AND POSSESSIVE QUANTIFIERS" is one idea and
#: splitting it further would cut an argument in half.
_PCRE2_SECTION = re.compile(r"^([A-Z][A-Z0-9 ,()/:'-]{2,70})$", re.MULTILINE)

#: Sections that are page furniture rather than content.
_PCRE2_SKIP_SECTIONS = frozenset({
    "NAME", "SYNOPSIS", "SEE ALSO", "AUTHOR", "REVISION",
})

#: The pages kept, and the register each is honestly in. Running argument about
#: what a pattern means is PROSE; a page that spends its length on option
#: constants and function behaviour is SYSTEM, which is what that register is
#: defined to hold. Pages absent from this table are not emitted — see
#: :data:`_REJECTED` for pcre2api, and note that pcre2build, pcre2posix,
#: pcre2sample and pcre2serialize are about installing and linking the library
#: rather than about regular expressions at all.
_PCRE2_PAGES: dict[str, Register] = {
    "PCRE2": Register.PROSE,            # introduction, security considerations
    "PCRE2PATTERN": Register.PROSE,     # 193 KB; the semantics, all of them
    "PCRE2MATCHING": Register.PROSE,    # backtracking vs DFA, as algorithms
    "PCRE2PERFORM": Register.PROSE,     # where the time and the memory go
    "PCRE2COMPAT": Register.PROSE,      # where PCRE2 and Perl disagree
    "PCRE2UNICODE": Register.PROSE,
    "PCRE2LIMITS": Register.PROSE,
    "PCRE2SYNTAX": Register.SYSTEM,     # quick reference table
    "PCRE2JIT": Register.SYSTEM,
    "PCRE2PARTIAL": Register.SYSTEM,
    "PCRE2CALLOUT": Register.SYSTEM,
}

#: One line of context above every PCRE2 section, so a document that arrives on
#: its own still says which engine it describes and why this corpus has it.
_PCRE2_CONTEXT = (
    "PCRE2 is the regular expression engine behind Suricata's pcre: rule "
    "option, PHP's preg_* functions, nginx, Apache and much of the rest of the "
    "detection tooling in this corpus."
)


def _pcre2_pages(text: str) -> list[tuple[str, str]]:
    """Cut the concatenated man-page file into ``(page name, text)`` pairs.

    The file repeats a page's running header on every screenful, so the same
    name matches dozens of times; only a change of name starts a new page.
    """
    marks: list[tuple[int, str]] = []
    for match in _PCRE2_PAGE.finditer(text):
        if not marks or marks[-1][1] != match.group(1):
            marks.append((match.start(), match.group(1)))
    pages: list[tuple[str, str]] = []
    for index, (start, name) in enumerate(marks):
        end = marks[index + 1][0] if index + 1 < len(marks) else len(text)
        pages.append((name, text[start:end]))
    return pages


def _pcre2_sections(page: str) -> list[tuple[str, str]]:
    """Cut one man page into ``(heading, body)`` pairs, headings included."""
    marks = [(m.start(), m.group(1).strip())
             for m in _PCRE2_SECTION.finditer(page)]
    # The running header itself matches the all-caps rule; drop anything that is
    # a page header rather than a section heading.
    marks = [(pos, head) for pos, head in marks if "(3)" not in head]
    sections: list[tuple[str, str]] = []
    for index, (start, heading) in enumerate(marks):
        end = marks[index + 1][0] if index + 1 < len(marks) else len(page)
        sections.append((heading, page[start:end]))
    return sections


def _pcre2_documents(root: Path) -> Iterator[Document]:
    """One document per section of each kept PCRE2 man page."""
    blob = root / _PCRE2.dirname / "pcre2.txt"
    if not blob.is_file():
        return
    text = blob.read_text(encoding="utf-8", errors="replace")
    found: set[str] = set()
    for name, page in _pcre2_pages(text):
        register = _PCRE2_PAGES.get(name)
        if register is None:
            continue
        found.add(name)
        lower = name.lower()
        for heading, body in _pcre2_sections(page):
            if heading in _PCRE2_SKIP_SECTIONS:
                continue
            body = normalise(body)
            if len(body) < _MIN_CHARS:
                continue
            yield Document(
                text=(
                    f"PCRE2 documentation — {lower}(3) — {heading}\n"
                    f"{_PCRE2_CONTEXT}\n\n{body}"
                ),
                source=_NAME,
                register=register,
                side=Side.NEUTRAL,
                ident=f"pcre2/{lower}/{heading}",
            )
    missing = set(_PCRE2_PAGES) - found
    if missing:
        raise SourceError(
            f"{_NAME}: doc/pcre2.txt no longer contains "
            f"{', '.join(sorted(missing))}. The page set is the source, not "
            "decoration — fix _PCRE2_PAGES rather than quietly training on "
            "whatever survived."
        )


# ---------------------------------------------------------------------------
# RE2
# ---------------------------------------------------------------------------

#: RE2's two files and the register each belongs in. The README is an argument
#: about engine design in sentences; syntax.txt is a reference table.
_RE2_FILES: dict[str, tuple[Register, str]] = {
    "README.md": (
        Register.PROSE,
        "RE2 is Google's linear-time regular expression engine. This is its "
        "own statement of why an engine that must accept patterns from "
        "untrusted users refuses backreferences and lookaround: both are only "
        "implementable by backtracking, and backtracking is where the "
        "exponential cases live.",
    ),
    "doc/syntax.txt": (
        Register.SYSTEM,
        "RE2's syntax reference. Worth having over any other because it "
        "describes every quantifier by its preference — 'zero or more x, "
        "prefer more' for x* against 'prefer fewer' for x*? — which is what "
        "greedy and lazy actually mean, and because it marks the constructs "
        "RE2 refuses (possessive quantifiers, atomic groups, backreferences) "
        "as NOT SUPPORTED rather than omitting them.",
    ),
}


def _re2_documents(root: Path) -> Iterator[Document]:
    for relative, (register, context) in _RE2_FILES.items():
        path = root / _RE2.dirname / relative
        if not path.is_file():
            continue
        body = normalise(path.read_text(encoding="utf-8", errors="replace"))
        if len(body) < _MIN_CHARS:
            continue
        yield Document(
            text=f"RE2 — {relative}\n{context}\n\n{body}",
            source=_NAME,
            register=register,
            side=Side.NEUTRAL,
            ident=f"re2/{relative}",
        )


# ---------------------------------------------------------------------------
# grok
# ---------------------------------------------------------------------------

#: A grok pattern reference. The field name may be a bracketed ECS path —
#: ``%{INT:[http][response][status_code]:int}`` — so the inner group stops at
#: the closing brace rather than at a colon.
_GROK_REF = re.compile(r"%\{(\w+)(?::([^}]*))?\}")

#: ``NAME <pattern>`` on one line, which is the whole of the grok pattern file
#: format. Names are upper case with digits and underscores.
_GROK_DEF = re.compile(r"^([A-Z0-9_]+)\s+(\S.*)$")

#: An Oniguruma named group written directly in a pattern body, as several of
#: the mail-log patterns do. Excludes lookbehind, which shares the prefix.
_GROK_INLINE_NAME = re.compile(r"\(\?<(?![=!])([A-Za-z_][A-Za-z0-9_]*)>")

#: ``describe_pattern "NAME", ['legacy', 'ecs-v1'] do`` in the rspec files, and
#: the older ``let(:pattern) { "NAME" }`` form that a few of them still use.
_GROK_DESCRIBE = re.compile(
    r"""describe_pattern\s+"([A-Z0-9_]+)"|let\(:pattern\)\s*\{\s*["']([A-Z0-9_]+)["']"""
)

#: The two ways these specs declare the line under test. rspec allows both a
#: brace block and a ``do``/``end`` block, and the upstream uses whichever fit
#: the line length on the day — 48 of the 162 samples are braces and 85 are
#: ``do``/``end``, so reading only the obvious one silently loses two thirds of
#: the best material in this upstream.
#:
#: Neither is DOTALL, which is the point. The remaining samples are built by
#: string concatenation across lines or from a heredoc, and a pattern that
#: crossed lines would splice a Ruby ``+`` operator or a comment into the
#: middle of a log line and present the result as something grok parses. Those
#: are skipped rather than guessed at.
_GROK_MESSAGE = re.compile(
    r"""let\(:message\)\s*\{\s*(['"])(.*?)\1\s*\}"""
    r"""|let\(:message\)\s*do[ \t]*\n[ \t]*(['"])(.*?)\3[ \t]*\n[ \t]*end"""
)

#: Phrases that mean the surrounding example is a *non*-match. A sample taken
#: from one of these would be a document asserting that a pattern parses a line
#: it is documented to reject, which is worse than having no sample at all.
_GROK_NEGATIVE = (
    "to be_nil", "be_nil", "does not match", "doesn't match", "to_not match",
    "not_to match", "no match", "fails to match",
)

#: How far around a sample to look for one of those phrases. An rspec ``it``
#: block in these files runs a few hundred characters; this covers the block the
#: sample is in and errs on the side of discarding a usable sample.
_GROK_WINDOW_BEFORE = 400
_GROK_WINDOW_AFTER = 900

#: Ceiling on the rendered expansion. The lesson is that a friendly name like
#: HTTPD_COMMONLOG is a 2,435-character regex, and the document states that
#: number whatever it shows — so the cap can be tight without losing the point.
#:
#: Tight on purpose. 146 of the 679 patterns resolve past this, and what is past
#: it is overwhelmingly the same text over and over: ``IPV6`` is a 1 KB
#: alternation and it lands inside every composite that mentions an address.
#: Printing all of it would have put sixty near-identical copies of one regex
#: into a corpus whose own rule is that duplicated text is worse than absent
#: text, because the model memorises it. Truncating costs the tail of a few
#: dozen patterns; not truncating would have cost 247 KB of repetition.
_GROK_EXPANSION_CHARS = 1500
_GROK_MAX_SAMPLES = 3
_GROK_SAMPLE_CHARS = 400

#: Depth limit on reference resolution. Guards a cycle that the upstream does
#: not have today and could acquire tomorrow.
_GROK_MAX_DEPTH = 24


def _grok_flavours(root: Path) -> dict[str, dict[str, tuple[str, str]]]:
    """Read the pattern files into ``flavour -> name -> (body, file)``.

    Two flavours, and they are separate namespaces rather than one merged map:
    logstash loads ``patterns/ecs-v1`` or ``patterns/legacy`` depending on the
    ``ecs_compatibility`` setting, never both, and both define ``USERNAME``.
    Merging them would resolve an ECS composite against a legacy primitive and
    produce an expansion that no configuration of logstash would ever compute.
    """
    flavours: dict[str, dict[str, tuple[str, str]]] = {}
    base = root / _GROK.dirname / "patterns"
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        dirnames[:] = sorted(
            d for d in dirnames if not Path(dirpath, d).is_symlink()
        )
        flavour = Path(dirpath).name
        if flavour == "patterns":
            continue
        table = flavours.setdefault(flavour, {})
        for filename in sorted(filenames):
            path = Path(dirpath, filename)
            if path.is_symlink():
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            relative = f"patterns/{flavour}/{filename}"
            for line in text.splitlines():
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                match = _GROK_DEF.match(line)
                if match:
                    table[match.group(1)] = (match.group(2).rstrip(), relative)
    return flavours


def _grok_expand(body: str, table: dict[str, tuple[str, str]],
                 stack: frozenset[str], depth: int) -> str:
    """Substitute ``%{NAME...}`` references recursively.

    An unresolvable reference — undefined in this flavour, or one that would
    close a cycle, or one past the depth limit — is left exactly as written. It
    is the only honest rendering: inventing a placeholder would put a construct
    in the expansion that is not in the pattern.
    """
    if depth > _GROK_MAX_DEPTH:
        return body

    def substitute(match: re.Match[str]) -> str:
        name = match.group(1)
        if name in stack:
            return match.group(0)
        entry = table.get(name)
        if entry is None:
            return match.group(0)
        inner = _grok_expand(entry[0], table, stack | {name}, depth + 1)
        return f"(?:{inner})"

    return _GROK_REF.sub(substitute, body)


def _grok_captures(body: str) -> list[tuple[str, str]]:
    """The fields this pattern names, as ``(field, pattern it comes from)``."""
    captures: list[tuple[str, str]] = []
    for match in _GROK_REF.finditer(body):
        field = (match.group(2) or "").strip()
        if not field:
            continue
        # ``%{INT:[http][response][status_code]:int}`` — the trailing type
        # coercion is grok's, not part of the field name.
        if ":" in field:
            field, _, coercion = field.partition(":")
            field = f"{field}  (coerced to {coercion})"
        captures.append((field, match.group(1)))
    for match in _GROK_INLINE_NAME.finditer(body):
        captures.append((match.group(1), "(?<...>) written inline"))
    return captures


def _ruby_unescape(raw: str, quote: str) -> str:
    """Undo the escaping of a Ruby string literal, for the two cases that occur.

    Only ``\\\\`` and the escaped quote character are handled, plus ``\\n`` and
    ``\\t`` inside double quotes. Anything else is left as written: a log line
    is full of backslashes that mean themselves, and a general unescaper would
    silently eat the ones in a Windows path or a regex the sample contains.
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
        if nxt == "\\" or nxt == quote:
            out.append(nxt)
        elif quote == '"' and nxt == "n":
            out.append("\n")
        elif quote == '"' and nxt == "t":
            out.append("\t")
        else:
            out.append(char)
            out.append(nxt)
        index += 2
    return "".join(out)


def _harvest_samples(root: Path) -> dict[str, list[str]]:
    """Pattern name -> log lines the upstream's own tests feed it.

    Association is by position: a ``let(:message)`` belongs to the most recent
    ``describe_pattern`` above it. A sample whose surrounding window contains
    any of :data:`_GROK_NEGATIVE` is discarded — those blocks exist to assert
    that a pattern *rejects* a line, and a document claiming the opposite would
    be teaching the model something false about a rule it may later be asked to
    write.
    """
    samples: dict[str, list[str]] = {}
    spec_dir = root / _GROK.dirname / "spec" / "patterns"
    if not spec_dir.is_dir():
        return samples
    for dirpath, dirnames, filenames in os.walk(spec_dir, followlinks=False):
        dirnames[:] = sorted(
            d for d in dirnames if not Path(dirpath, d).is_symlink()
        )
        for filename in sorted(filenames):
            if not filename.endswith(".rb"):
                continue
            path = Path(dirpath, filename)
            if path.is_symlink():
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            describes = [(m.start(), m.group(1) or m.group(2))
                         for m in _GROK_DESCRIBE.finditer(text)]
            if not describes:
                continue
            for match in _GROK_MESSAGE.finditer(text):
                owner = ""
                for position, name in describes:
                    if position < match.start():
                        owner = name
                    else:
                        break
                if not owner:
                    continue
                window = text[max(0, match.start() - _GROK_WINDOW_BEFORE):
                              match.end() + _GROK_WINDOW_AFTER].lower()
                if any(phrase in window for phrase in _GROK_NEGATIVE):
                    continue
                quote = match.group(1) or match.group(3)
                sample = _ruby_unescape(match.group(2) or match.group(4), quote)
                if "#{" in sample or not sample.strip():
                    continue
                if len(sample) > _GROK_SAMPLE_CHARS:
                    # Dropped rather than truncated. Half a log line is not a
                    # log line the pattern parses.
                    continue
                bucket = samples.setdefault(owner, [])
                if sample not in bucket and len(bucket) < _GROK_MAX_SAMPLES:
                    bucket.append(sample)
    return samples


def _grok_documents(root: Path) -> Iterator[Document]:
    """One document per distinct grok pattern definition.

    Keyed on ``(name, body, expansion)`` rather than on the name alone: a
    primitive like ``USERNAME`` is byte-identical in both flavours and deserves
    one document listing both files, while ``HTTPD_COMMONLOG`` genuinely differs
    between them — the ECS flavour names its captures ``[source][address]`` and
    the legacy one names them ``clientip`` — and deserves two. The expansion is
    in the key because two flavours can share a body and still resolve
    differently, which is the case the naive key gets wrong.
    """
    flavours = _grok_flavours(root)
    if not flavours:
        return
    samples = _harvest_samples(root)

    merged: dict[tuple[str, str, str], list[str]] = {}
    for flavour in sorted(flavours):
        table = flavours[flavour]
        for name in sorted(table):
            body, relative = table[name]
            expanded = _grok_expand(body, table, frozenset({name}), 0)
            merged.setdefault((name, body, expanded), []).append(relative)

    for (name, body, expanded), files in merged.items():
        lines = [
            f"grok pattern {name}  ({_GROK.name})",
            f"defined in: {', '.join(files)}",
            "",
            "definition:",
            f"{name} {body}",
        ]

        captures = _grok_captures(body)
        if captures:
            width = max(len(field) for field, _ in captures)
            lines += ["", f"captures {len(captures)} field(s):"]
            lines += [f"  {field.ljust(width)}   from {origin}"
                      for field, origin in captures]

        direct: list[str] = []
        table = flavours[files[0].split("/")[1]]
        for match in _GROK_REF.finditer(body):
            reference = match.group(1)
            if reference in direct or reference not in table:
                continue
            direct.append(reference)
        if direct:
            lines += ["", f"references {len(direct)} other pattern(s):"]
            lines += [f"  {reference} {table[reference][0]}"
                      for reference in direct]

        if expanded != body:
            shown = expanded
            suffix = ""
            if len(shown) > _GROK_EXPANSION_CHARS:
                shown = shown[:_GROK_EXPANSION_CHARS]
                suffix = (f"   [truncated at {_GROK_EXPANSION_CHARS:,} of "
                          f"{len(expanded):,} characters]")
            lines += [
                "",
                f"fully expanded, every %{{...}} reference substituted "
                f"({len(expanded):,} characters):{suffix}",
                shown,
            ]

        harvested = samples.get(name, [])
        if harvested:
            lines += ["", "parses log lines such as these, taken from the "
                          "upstream's own test suite:"]
            lines += [f"  {sample}" for sample in harvested]

        text = normalise("\n".join(lines))
        if len(text) < _MIN_CHARS:
            continue
        yield Document(
            text=text,
            source=_NAME,
            register=Register.DETECTION,
            side=Side.BLUE,
            ident=f"grok/{files[0]}/{name}",
        )


# ---------------------------------------------------------------------------
# OWASP Core Rule Set
# ---------------------------------------------------------------------------

#: A double-quoted ModSecurity argument, with backslash escapes respected so a
#: regex containing an escaped quote does not end the argument early.
_CRS_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')

#: Actions inside the second argument. ``msg`` and friends are single-quoted;
#: ``id`` and ``phase`` are bare. Every one of these is read with ``search``
#: rather than split on commas, because a logdata template contains commas and
#: a transformation list contains colons.
_CRS_ID = re.compile(r"\bid:(\d+)")
_CRS_MSG = re.compile(r"\bmsg:'((?:[^'\\]|\\.)*)'")
_CRS_TAG = re.compile(r"\btag:'((?:[^'\\]|\\.)*)'")
_CRS_SEVERITY = re.compile(r"\bseverity:'?([A-Za-z]+)'?")
_CRS_VERSION = re.compile(r"\bver:'((?:[^'\\]|\\.)*)'")
_CRS_TRANSFORM = re.compile(r"\bt:(\w+)")
_CRS_PHASE = re.compile(r"\bphase:(\w+)")

#: ``tag:'capec/1000/152/242'`` — the last element is the CAPEC id, and the
#: corpus's tokenizer measurement says an identifier is worth several times more
#: sitting beside the form the world writes it in. CAPEC-242 is in this corpus
#: under its own adapter; capec/1000/152/242 is in no vocabulary anywhere.
_CRS_CAPEC = re.compile(r"^capec/(?:[\d/]*?/)?(\d+)$")

#: A regex-assembly comment. ``##!`` introduces prose, ``##!+`` a flag,
#: ``##!>`` an assembler directive.
_CRS_ASSEMBLY_COMMENT = re.compile(r"^##!")

#: Assembly files above this are the generated word lists — php function names,
#: config directives — which are a 13 KB alternation of bare identifiers with
#: no explanation attached. They are regex-shaped and teach repetition.
_CRS_ASSEMBLY_MAX_BYTES = 8_000

#: And below this an assembly file is one include directive pointing somewhere
#: else, which says nothing on its own.
_CRS_ASSEMBLY_MIN_COMMENTS = 2


def _crs_rules(root: Path) -> Iterator[tuple[str, dict[str, object]]]:
    """Yield ``(file, rule)`` for every ``SecRule`` whose operator is ``@rx``.

    Directives are continued with a trailing backslash, so a logical rule is
    reassembled before it is read and kept verbatim as its own lines for the
    document body. The joined form is what the action regexes run against; the
    raw form is what a model should see, because raw ModSecurity — the
    continuation backslashes, the comma-separated action list, the single-quoted
    tags — is the surface form this register is short of.
    """
    rules_dir = root / _CRS.dirname / "rules"
    if not rules_dir.is_dir():
        return
    for dirpath, dirnames, filenames in os.walk(rules_dir, followlinks=False):
        dirnames[:] = sorted(
            d for d in dirnames if not Path(dirpath, d).is_symlink()
        )
        for filename in sorted(filenames):
            if not filename.endswith(".conf"):
                continue
            path = Path(dirpath, filename)
            if path.is_symlink():
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            block: list[str] = []
            for line in text.splitlines():
                if block or line.lstrip().startswith("SecRule "):
                    block.append(line)
                    if line.rstrip().endswith("\\"):
                        continue
                    parsed = _crs_parse(block)
                    if parsed is not None:
                        yield filename, parsed
                    block = []
            if block:
                parsed = _crs_parse(block)
                if parsed is not None:
                    yield filename, parsed


def _crs_parse(block: list[str]) -> dict[str, object] | None:
    """Read one reassembled ``SecRule``, or ``None`` if it carries no regex."""
    joined = " ".join(line.rstrip().removesuffix("\\") for line in block)
    joined = joined.strip()
    if not joined.startswith("SecRule "):
        return None
    remainder = joined[len("SecRule "):].lstrip()

    if remainder.startswith('"'):
        match = _CRS_QUOTED.match(remainder)
        if match is None:
            return None
        targets, remainder = match.group(1), remainder[match.end():]
    else:
        targets, _, remainder = remainder.partition(" ")

    arguments = _CRS_QUOTED.findall(remainder)
    if len(arguments) < 2:
        return None
    operator = arguments[0].strip()
    negated = operator.startswith("!")
    if negated:
        operator = operator[1:]
    if not operator.startswith("@rx"):
        return None
    pattern = operator[len("@rx"):].strip()
    if not pattern:
        return None
    actions = arguments[1]

    identifier = _CRS_ID.search(actions)
    message = _CRS_MSG.search(actions)
    severity = _CRS_SEVERITY.search(actions)
    version = _CRS_VERSION.search(actions)
    phase = _CRS_PHASE.search(actions)
    return {
        "id": identifier.group(1) if identifier else "",
        "msg": message.group(1) if message else "",
        "severity": severity.group(1).upper() if severity else "",
        "version": version.group(1) if version else "",
        "phase": phase.group(1) if phase else "",
        "targets": targets,
        "negated": negated,
        "pattern": pattern,
        "tags": _CRS_TAG.findall(actions),
        "transforms": _CRS_TRANSFORM.findall(actions),
        "raw": "\n".join(block).rstrip(),
    }


def _crs_documents(root: Path) -> Iterator[Document]:
    """One document per ``@rx`` rule, and one per usable regex-assembly file."""
    titles: dict[str, str] = {}

    for filename, rule in _crs_rules(root):
        identifier = str(rule["id"])
        message = str(rule["msg"])
        if identifier and message:
            titles[identifier] = message

        heading = f"OWASP CRS rule {identifier or '(unnumbered)'}"
        if message:
            heading += f" — {message}"
        lines = [heading, f"file: rules/{filename}"]

        facts = []
        if rule["severity"]:
            facts.append(f"severity {rule['severity']}")
        if rule["phase"]:
            facts.append(f"phase {rule['phase']}")
        if rule["version"]:
            facts.append(f"version {rule['version']}")
        if facts:
            lines.append("  ".join(facts))

        lines += ["", f"inspects: {rule['targets']}"]
        transforms = list(dict.fromkeys(rule["transforms"]))  # type: ignore[arg-type]
        if transforms:
            lines.append(
                "after transformations: "
                + ", ".join(f"t:{name}" for name in transforms)
                + "   (the regex sees the decoded value, not the raw request)"
            )

        verb = "does NOT match" if rule["negated"] else "matches"
        lines += ["", f"regex (@rx), the rule fires when this {verb}:",
                  str(rule["pattern"])]

        tags = list(rule["tags"])  # type: ignore[arg-type]
        if tags:
            lines += ["", "tags: " + ", ".join(tags)]
            capecs = []
            for tag in tags:
                found = _CRS_CAPEC.match(tag)
                if found:
                    capecs.append(f"CAPEC-{found.group(1)}")
            if capecs:
                lines.append("classified as: " + ", ".join(dict.fromkeys(capecs)))

        lines += ["", "rule as written:", str(rule["raw"])]

        text = normalise("\n".join(lines))
        if len(text) < _MIN_CHARS:
            continue
        yield Document(
            text=text,
            source=_NAME,
            register=Register.DETECTION,
            side=Side.BLUE,
            ident=f"crs/rules/{filename}/{identifier or 'unnumbered'}",
        )

    yield from _crs_assembly_documents(root, titles)


def _crs_assembly_documents(
    root: Path, titles: dict[str, str]
) -> Iterator[Document]:
    """The commented sources the CRS toolchain assembles rules out of.

    These are the best "regex with an explanation of what it matches" text
    available anywhere under a permissive licence, because the explanation is
    an ASCII column ruler drawn directly above the pattern it labels. That is
    also why :func:`_assert_columns_survive` runs over every one of them: the
    annotation is made of horizontal whitespace and nothing else.
    """
    assembly = root / _CRS.dirname / "regex-assembly"
    if not assembly.is_dir():
        return
    for dirpath, dirnames, filenames in os.walk(assembly, followlinks=False):
        dirnames[:] = sorted(
            d for d in dirnames if not Path(dirpath, d).is_symlink()
        )
        for filename in sorted(filenames):
            if not filename.endswith(".ra"):
                continue
            path = Path(dirpath, filename)
            if path.is_symlink():
                continue
            try:
                raw = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            if len(raw.encode("utf-8")) > _CRS_ASSEMBLY_MAX_BYTES:
                continue

            comments = [line for line in raw.splitlines()
                        if _CRS_ASSEMBLY_COMMENT.match(line.strip())
                        and "coreruleset.org/docs" not in line
                        and "Please refer to the documentation" not in line]
            patterns = [line for line in raw.splitlines()
                        if line.strip() and not line.lstrip().startswith("##")]
            if len(comments) < _CRS_ASSEMBLY_MIN_COMMENTS or not patterns:
                continue

            stem = filename[:-3]
            heading = f"OWASP CRS regex assembly {filename}"
            title = titles.get(stem)
            if title:
                heading += f" — source for rule {stem}, {title}"
            body = normalise(raw)
            _assert_columns_survive(f"regex-assembly/{filename}", raw, body)
            text = (
                f"{heading}\n"
                "A .ra file is the annotated source the crs-toolchain "
                "assembles into one rule's @rx pattern. ##! lines are comments, "
                "##!+ sets a flag, ##!> is an assembler directive, and every "
                "other line is one alternative of the final regex. The column "
                "rulers in the comments line up with the pattern beneath them.\n"
                f"\n{body}"
            )
            if len(text) < _MIN_CHARS:
                continue
            yield Document(
                text=text,
                source=_NAME,
                register=Register.DETECTION,
                side=Side.BLUE,
                ident=f"crs/regex-assembly/{filename}",
            )


def _assert_columns_survive(ident: str, raw: str, cleaned: str) -> None:
    """Prove ``normalise`` left every line's internal spacing alone.

    Cheap, exact, and aimed at one specific regression. The contract in
    :func:`~training.corpus.source.normalise` is that horizontal whitespace is
    preserved; an earlier version of it collapsed runs of spaces, and this is
    the source where that would do the most damage while being least visible —
    a column ruler flattened to single spaces is still a plausible-looking
    comment, still roughly the same length, and no longer means anything.

    Raised rather than skipped, for the reason ``pythoncode`` raises on a file
    that stops parsing: if this fails it is the normaliser that broke, not the
    data, and turning that into a slightly smaller document count is how silent
    corpus damage happens.
    """
    survivors = {line.rstrip() for line in cleaned.splitlines()}
    for line in raw.splitlines():
        stripped = line.rstrip()
        if not stripped.strip():
            continue
        if stripped not in survivors:
            raise SourceError(
                f"{_NAME}: normalise() altered a line of {ident}:\n"
                f"  before: {stripped!r}\n"
                "In a CRS regex-assembly file the comment above a pattern is a "
                "column ruler, so its indentation IS its meaning. normalise() "
                "is contracted to preserve horizontal whitespace — fix it "
                "there, do not filter around this."
            )


# ---------------------------------------------------------------------------
# eslint-plugin-regexp rule documentation
# ---------------------------------------------------------------------------

#: VuePress front matter at the top of every rule page.
_LINT_FRONTMATTER = re.compile(r"\A---\n(.*?)\n---\n", re.DOTALL)
_LINT_FM_FIELD = re.compile(r'^(\w+):\s*"?(.*?)"?\s*$', re.MULTILINE)

#: Emoji shortcodes VuePress renders as icons — ``## :book: Rule Details``.
#: Applied to heading lines only, which is where all 300 of them are. Run over
#: body text it would be a liability rather than a tidy-up: ``:[a-z_]+:`` is
#: also the shape of a POSIX character class, so a sentence mentioning
#: ``[[:alpha:]]`` would come out as ``[[]]`` — this source's entire job is to
#: carry regular expressions intact, and silently eating one inside an
#: explanation of what it means is the worst available outcome.
_LINT_SHORTCODE = re.compile(r":[a-z_]+:\s*")

#: Repository chrome: the auto-generated badge lines under the H1, which say
#: which lint config enables the rule and nothing about regular expressions.
_LINT_BADGE = re.compile(r"^\s*[\U0001F300-\U0001FAFF☀-➿]")

#: The custom component wrapping every example block, and the marker that ends
#: the generated header.
_LINT_COMPONENT = re.compile(r"^\s*</?eslint-code-block\b[^>]*>\s*$")
_LINT_HTML_COMMENT = re.compile(r"^\s*<!--.*-->\s*$")

#: A VuePress container fence: ``::: warning`` … ``:::``.
_LINT_CONTAINER = re.compile(r"^:::\s*(\w+)?\s*$")

#: The final section of every page is three links to the rule's own TypeScript
#: source and tests. Useful to a contributor, noise in a corpus.
_LINT_TAIL = re.compile(r"^##\s+:mag:\s+Implementation\s*$", re.MULTILINE)

#: Not a rule page — a table of every rule in the plugin, which is a link list.
_LINT_SKIP = frozenset({"index.md"})


def _lint_documents(root: Path) -> Iterator[Document]:
    """One document per rule page, stripped of its VuePress scaffolding."""
    docs_dir = root / _LINT.dirname
    if not docs_dir.is_dir():
        return
    for dirpath, dirnames, filenames in os.walk(docs_dir, followlinks=False):
        dirnames[:] = sorted(
            d for d in dirnames if not Path(dirpath, d).is_symlink()
        )
        for filename in sorted(filenames):
            if not filename.endswith(".md") or filename in _LINT_SKIP:
                continue
            path = Path(dirpath, filename)
            if path.is_symlink():
                continue
            try:
                raw = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            title = filename[:-3]
            summary = ""
            front = _LINT_FRONTMATTER.match(raw)
            if front:
                fields = dict(_LINT_FM_FIELD.findall(front.group(1)))
                title = fields.get("title", title)
                summary = fields.get("description", "")
                raw = raw[front.end():]

            tail = _LINT_TAIL.search(raw)
            if tail:
                raw = raw[:tail.start()]

            kept: list[str] = []
            fenced = False
            for line in raw.splitlines():
                if line.lstrip().startswith("```"):
                    fenced = not fenced
                    kept.append(line)
                    continue
                if fenced:
                    # Inside a fence every character is example, including the
                    # ✓ GOOD / ✗ BAD markers that are the whole teaching device.
                    kept.append(line)
                    continue
                if _LINT_COMPONENT.match(line) or _LINT_HTML_COMMENT.match(line):
                    continue
                if _LINT_BADGE.match(line):
                    continue
                container = _LINT_CONTAINER.match(line)
                if container:
                    label = container.group(1)
                    if label:
                        kept.append(f"{label.capitalize()}:")
                    continue
                if line.startswith("#"):
                    line = _LINT_SHORTCODE.sub("", line)
                kept.append(line)

            body = normalise("\n".join(kept))
            if len(body) < _MIN_CHARS:
                continue
            header = f"{title} — {summary}" if summary else title
            yield Document(
                text=(
                    f"{header}\n"
                    f"From the eslint-plugin-regexp rule documentation "
                    f"(docs/rules/{filename}): a catalogue of regular "
                    f"expression mistakes, each with the wrong version and the "
                    f"right one.\n\n{body}"
                ),
                source=_NAME,
                register=Register.PROSE,
                side=Side.NEUTRAL,
                ident=f"regexplint/{filename}",
            )


# ---------------------------------------------------------------------------
# fetch
# ---------------------------------------------------------------------------

#: Ceiling on any one archive, passed to :func:`~training.corpus.net.download`
#: so it is enforced against bytes as they arrive rather than checked after the
#: file has already landed. The largest of the four is 620 KB; 64 MB is the
#: point at which an upstream has become something other than what this adapter
#: was written against.
_MAX_ARCHIVE_BYTES = 64 * 1024 * 1024

#: Ceiling on one extracted file. Nothing kept here is close: the largest is
#: PCRE2's 671 KB documentation blob, and the largest tarball member is CRS's
#: biggest .conf at about 90 KB.
_MAX_FILE_BYTES = 4 * 1024 * 1024

#: Directories that are never corpus, wherever they appear. These projects do
#: not vendor each other, but the habit is cheap and the day one of them
#: acquires a node_modules/ under docs/ is not a day to find out by hand.
_SKIP_DIRS = frozenset({
    "node_modules", ".git", "vendor", "third_party", "__pycache__", "dist",
    "build", "fixtures",
})


def _wanted(upstream: _Upstream, relative: Path) -> bool:
    """True when this archive member is one of ``upstream.keep``.

    A keep entry ending in ``/`` is a directory prefix; anything else must match
    the whole path. Spelled out rather than left as a bare ``startswith``, which
    would have admitted ``README.md.bak`` and ``doc/syntax.txt.orig`` on the
    strength of a prefix — a small thing until an upstream ships a generated
    sibling of a file this adapter believes it is reading.
    """
    posix = relative.as_posix()
    if any(part in _SKIP_DIRS for part in relative.parts[:-1]):
        return False
    return any(posix.startswith(keep) if keep.endswith("/") else posix == keep
               for keep in upstream.keep)


def _extract(upstream: _Upstream, archive: Path, staging: Path) -> int:
    """Unpack one upstream's kept paths and its licence into staging.

    Members are copied out by hand rather than with ``extractall``. These
    tarballs are trusted in practice, but an archive member is
    attacker-controlled data in principle — absolute paths, ``..`` segments,
    symlinks and hardlinks are all expressible in tar — and the cheap defence is
    never to hand an archive's own names to the filesystem unchecked. Only
    regular files are written, and every destination is proved to resolve inside
    ``staging`` first.
    """
    files_root = staging / "files" / upstream.dirname
    files_root.mkdir(parents=True, exist_ok=True)
    resolved_root = files_root.resolve()
    licence_dir = staging / "licenses"
    licence_dir.mkdir(parents=True, exist_ok=True)

    kept = 0
    licences = 0
    try:
        with tarfile.open(archive, mode="r:gz") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                parts = Path(member.name).parts
                if len(parts) < 2:
                    continue
                # Drop the archive's single root directory ("re2-main/"), which
                # is what lets one set of keep-prefixes describe every upstream.
                relative = Path(*parts[1:])
                if relative.is_absolute() or ".." in relative.parts:
                    continue

                if (relative.as_posix() == upstream.license_file
                        and member.size <= 256 * 1024):
                    handle = tar.extractfile(member)
                    if handle is not None:
                        with handle:
                            (licence_dir
                             / f"{upstream.dirname}.{relative.name}"
                             ).write_bytes(handle.read())
                        licences += 1
                    continue

                if not _wanted(upstream, relative) or member.size > _MAX_FILE_BYTES:
                    continue
                handle = tar.extractfile(member)
                if handle is None:
                    continue
                with handle:
                    payload = handle.read()

                target = files_root / relative
                if not target.resolve().is_relative_to(resolved_root):
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(payload)
                kept += 1
    except (tarfile.TarError, OSError) as exc:
        raise SourceError(
            f"{_NAME}: could not unpack {upstream.name}: {exc}"
        ) from exc

    if licences == 0:
        raise SourceError(
            f"{_NAME}: {upstream.name} no longer ships {upstream.license_file} "
            "at its root. Every source in this corpus declares a licence and "
            "keeps the upstream text on disk to back the declaration; an "
            "archive that stops shipping it needs a human to look, not a "
            "default."
        )
    if kept < upstream.min_files:
        raise SourceError(
            f"{_NAME}: {upstream.name} yielded only {kept} files under "
            f"{', '.join(upstream.keep)} (expected at least "
            f"{upstream.min_files}). The upstream layout has probably changed "
            "— fix the keep-prefixes rather than training on a fraction of it."
        )
    return kept


def _fetch_pcre2(staging: Path) -> int:
    """The one upstream fetched as raw files rather than an archive.

    PCRE2's repository is tens of megabytes of C, JIT assembly and test data,
    and the two files wanted from it are a rendered documentation blob and a
    licence. Reason enough on its own; the deciding factor is that the blob is
    already the whole man-page set converted to plain text by the maintainer,
    so there is nothing to render and nothing else in the archive to want.
    """
    base = "https://raw.githubusercontent.com/PCRE2Project/pcre2/master/"
    files_root = staging / "files" / _PCRE2.dirname
    files_root.mkdir(parents=True, exist_ok=True)
    licence_dir = staging / "licenses"
    licence_dir.mkdir(parents=True, exist_ok=True)

    try:
        licence = http_get(base + _PCRE2.license_file, timeout=90,
                           max_bytes=256 * 1024)
        blob = http_get(base + "doc/pcre2.txt", timeout=180,
                        max_bytes=_MAX_FILE_BYTES)
    except NetworkError as exc:
        raise SourceError(f"{_NAME}: {_PCRE2.name}: {exc}") from None

    if b"BSD-3-Clause WITH PCRE2-exception" not in licence:
        raise SourceError(
            f"{_NAME}: {_PCRE2.license_file} no longer states "
            "'BSD-3-Clause WITH PCRE2-exception'. This adapter takes only the "
            "doc/ directory, and it is that file's own sentence about the "
            "documentation being under the same terms as the software that "
            "makes doing so legal. A human reads the new licence before this "
            "runs again."
        )
    # The documentation blob is 671 KB and has only grown. A floor this far
    # below it refuses an HTML error page or a truncated transfer while leaving
    # room for a release to drop a page.
    if len(blob) < 300_000:
        raise SourceError(
            f"{_NAME}: doc/pcre2.txt came back as {len(blob):,} bytes, far "
            "under the 671 KB it has been. That is an error page or a "
            "truncated transfer, not the documentation."
        )

    (licence_dir / f"{_PCRE2.dirname}.{_PCRE2.license_file}").write_bytes(licence)
    (files_root / "pcre2.txt").write_bytes(blob)
    return 1


def _fetch(cache_dir: Path) -> Path:
    """Download every upstream and leave a curated tree in the cache.

    Idempotent and network-free on re-run: the marker is written only after
    every upstream has been extracted and the staging tree swapped into place,
    so an interrupted fetch re-downloads instead of leaving a half-populated
    ``files/`` that a later run would mistake for a finished corpus.

    Accepts either the per-source directory ``build.py`` hands it
    (``<cache>/regexcorpus``) or the cache root, so calling this by hand during
    development does not scatter ``files/`` across the shared cache.
    """
    root = cache_dir if cache_dir.name == _NAME else cache_dir / _NAME
    root.mkdir(parents=True, exist_ok=True)

    files_dir = root / "files"
    marker = root / _MARKER
    if files_dir.is_dir() and marker.is_file():
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
            if not upstream.archive:
                kept = _fetch_pcre2(staging)
            else:
                archive = root / f".{upstream.dirname}.tar.gz.part"
                try:
                    download(upstream.archive, archive, timeout=300,
                             max_bytes=_MAX_ARCHIVE_BYTES)
                except NetworkError as exc:
                    raise SourceError(
                        f"{_NAME}: {upstream.name}: {exc}"
                    ) from None
                try:
                    kept = _extract(upstream, archive, staging)
                finally:
                    archive.unlink(missing_ok=True)
            manifest.append({
                "upstream": upstream.name,
                "dir": upstream.dirname,
                "url": upstream.url,
                "source": upstream.archive or (
                    "https://raw.githubusercontent.com/PCRE2Project/pcre2/"
                    "master/doc/pcre2.txt"
                ),
                # Recorded beside the files it covers, and the file itself is in
                # licenses/ — a licence claim that cannot be checked against
                # what was actually downloaded is a claim, not a record.
                "license": upstream.license,
                "license_file": f"licenses/{upstream.dirname}."
                                f"{upstream.license_file}",
                "files": kept,
            })

        # Swap in only once every upstream succeeded.
        shutil.rmtree(files_dir, ignore_errors=True)
        (staging / "files").replace(files_dir)
        licence_src = staging / "licenses"
        if licence_src.is_dir():
            shutil.rmtree(root / "licenses", ignore_errors=True)
            licence_src.replace(root / "licenses")
        # Written last, so a half-finished fetch is never mistaken for a cache.
        marker.write_text(
            json.dumps(
                {
                    "cache_version": _CACHE_VERSION,
                    "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                time.gmtime()),
                    "upstreams": manifest,
                    "rejected": list(_REJECTED),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return root


# ---------------------------------------------------------------------------
# documents
# ---------------------------------------------------------------------------

def _documents(path: Path) -> Iterator[Document]:
    """Yield every document from the cached tree, deduplicated.

    **Symlinks are never followed.** Every walk here is
    ``os.walk(followlinks=False)`` rather than ``rglob``, for the reason
    :mod:`~training.corpus.sources.ownrepos` records the hard way: a sibling
    adapter once walked a symlink into the external corpus cache and pulled
    180 MB of other sources back in under its own label. This tree is written by
    :func:`_fetch` and should hold no links at all, which is exactly the
    situation in which an unexamined ``rglob`` survives review and then does not
    survive the day someone points a symlink at the cache.

    Deduplication is by :func:`~training.corpus.source.fingerprint`, which is
    whitespace-insensitive and case-folded. It earns its place twice here: the
    two grok flavours define many primitives identically, and PCRE2's pages
    cross-reference each other with repeated paragraphs. ``build.py`` dedupes
    globally as well, but a source that hands it duplicates is a source whose
    own report is wrong.
    """
    root = path / "files" if (path / "files").is_dir() else path
    seen: set[str] = set()
    for produce in (_pcre2_documents, _re2_documents, _grok_documents,
                    _crs_documents, _lint_documents):
        for document in produce(root):
            mark = fingerprint(document.text)
            if mark in seen:
                continue
            seen.add(mark)
            yield document


SPEC = SourceSpec(
    name=_NAME,
    license=(
        "Composite, one licence per upstream, each read from that upstream's "
        "own file and copied into the cache under licenses/. "
        "(1) PCRE2 documentation: BSD-3-Clause WITH PCRE2-exception, per "
        "LICENCE.md, which states that the doc/ directory is under the same "
        "terms as the software; Copyright (c) 1997-2007 University of "
        "Cambridge and (c) 2007-2024 Philip Hazel. "
        "(2) RE2: BSD-3-Clause, Copyright (c) 2009 The RE2 Authors. "
        "(3) logstash-patterns-core: Apache-2.0, Elasticsearch B.V. "
        "(4) OWASP Core Rule Set: Apache-2.0. "
        "(5) eslint-plugin-regexp: MIT, Copyright (c) 2020 Yosuke Ota. "
        "Nothing here is copyleft. substack/safe-regex was refused because it "
        "publishes no LICENSE file at all, which makes it all rights reserved "
        "whatever its package metadata claims."
    ),
    url=" and ".join(upstream.url for upstream in _UPSTREAMS),
    # The plurality by document count. _documents() emits three registers and
    # the balancer reads per document, not from here — see the module docstring
    # for why this is the first source in the corpus that splits.
    register=Register.DETECTION,
    side=Side.NEUTRAL,
    fetch=_fetch,
    documents=_documents,
    #: 1,088 documents and 2.25 MB observed when this was written: 454 distinct
    #: grok pattern definitions (of 679 defined across the two flavours, the
    #: rest being primitives that are byte-identical in both and collapse to
    #: one document naming both files), 315 CRS rules whose operator is @rx,
    #: 142 regex-assembly files, 93 PCRE2 man-page sections, 82 lint rule pages
    #: and 2 RE2 files. By register that is 911 DETECTION, 135 PROSE and 42
    #: SYSTEM.
    #:
    #: The floor sits at about 78% of that, matching the habit of the other
    #: multi-upstream adapters: rules are retired and patterns reorganised
    #: constantly, so ordinary churn stays quiet, while losing a whole upstream
    #: — grok is 42% of the documents, CRS 42% — trips it immediately. The
    #: sharper guards are per upstream and run earlier: _Upstream.min_files at
    #: fetch time, and the page check in _pcre2_documents, which names the
    #: PCRE2 pages that went missing rather than yielding whatever survived.
    expect_min_docs=850,
    notes=(
        "Five upstreams, three registers. PCRE2's man pages are split one "
        "document per section and carry the engine semantics (PROSE), with the "
        "syntax reference and the API-shaped pages filed as SYSTEM; RE2 "
        "supplies the counter-argument for a linear-time engine. Each grok "
        "pattern is rendered with its captures, the patterns it references and "
        "its fully expanded regex, plus log lines taken from the upstream's "
        "own test suite, with any sample whose test asserts a non-match "
        "discarded. Each CRS @rx rule is rendered with its message, targets, "
        "transformation chain and tags — capec/1000/152/242 written back as "
        "CAPEC-242 — above the directive verbatim, and the regex-assembly "
        "files are kept because their comments are column rulers aligned with "
        "the patterns beneath them. eslint-plugin-regexp's rule pages are the "
        "ReDoS and anti-pattern half, stripped of VuePress scaffolding but "
        "with every example fence intact. Deliberately not here: pcre2api "
        "(250 KB of C function reference), the CRS test corpus (positive and "
        "negative cases need a real YAML parser and PyYAML is an optional "
        "extra, so a build would depend on what is installed), and perlre, "
        "which the manpages adapter already reads off this machine."
    ),
)
