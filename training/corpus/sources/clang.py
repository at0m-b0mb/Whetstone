"""C and C++: the language the bugs are written in. SYSTEM, mostly NEUTRAL.

The corpus had no C in it at all. That is a strange hole for a project whose
model is supposed to reason about memory corruption, because every weakness the
:mod:`~training.corpus.sources.cwe` adapter catalogues in English —
use-after-free, off-by-one, integer overflow, format string, TOCTOU — is a
statement about C semantics, and the model had read thousands of words *about*
CWE-416 without ever seeing a pointer used after ``free()``. A description of a
dangling pointer and a dangling pointer are not the same text, and only one of
them is what an agent will be handed at runtime.

Four upstreams, chosen so they disagree with each other:

* **Juliet C/C++ 1.3** (NIST SARD). 64,099 test cases, each labelled with its
  CWE, each containing the flawed variant and the fixed variant *in the same
  file*, with ``/* POTENTIAL FLAW: ... */`` and ``/* FIX: ... */`` on the
  offending and the corrected line. Nothing else available under a clean licence
  is this shape. It is supervised security knowledge in source form.
* **OpenSSH portable**. Production C written by people who assume the input is
  hostile, plus ``openbsd-compat/`` — ``strlcpy``, ``strlcat``,
  ``explicit_bzero``, ``arc4random`` — which is the mitigation literature as
  implementation rather than as documentation.
* **curl**. Parsers at scale: URL, HTTP, cookie, FTP, TLS backends. Parsing
  untrusted bytes is where C goes wrong most often and curl does it in public,
  portably, with the reasoning in comments.
* **shellphish/how2heap**. Two dozen glibc heap exploitation primitives, each a
  self-contained program that narrates its own attack in ``printf`` as it runs
  and cites the glibc commit that added the mitigation it is working around.
  This is the one part of this source that is honestly RED, and its documents
  say so.

**Register: SYSTEM.** Decided from surface form, as
:class:`~training.corpus.source.Register` requires, not from topic.
:class:`~training.corpus.source.Register.SHELL` is for what a person types at a
prompt, and none of that is here even in how2heap, whose subject is offensive
and whose text is a ``main()``. What comes out of this adapter is translation
units: includes, struct definitions, pointer arithmetic, preprocessor
conditionals. That is SYSTEM — "how the machine works" — at the layer beneath
everything else the corpus holds.

**Side: NEUTRAL, and Juliet is why.** It is tempting to file 1,300 working
vulnerabilities as ADVERSARY and help the red share along, and it would be a
lie. A Juliet case is symmetric by construction: ``bad()`` and ``good()`` sit in
one file, the annotations are ``FLAW`` and ``FIX``, and the artefact exists to
measure static analysers, which is a defensive act. The register and side fields
exist so corpus composition is *measurable*
(:mod:`~training.corpus.sources.ownrepos` records what happened the last time
this project mislabelled a source), and the offence balance is the one number
that tells this project whether it hit its 60/40 target. Inflating it with
material that teaches both sides equally would corrupt exactly the measurement
it was meant to improve. how2heap is different and its documents carry
``Side.RED`` individually.

That per-document side is currently invisible in the build report, which is
worth knowing rather than worth working around: ``build.py`` aggregates the
offence balance from ``spec.side`` (``by_side[s.side] += s.chars``), so a source
that emits mixed sides is counted wholly as whatever its SPEC declares. The
per-document value does reach the corpus rows, which is what the trainer reads,
so nothing is lost downstream — but the printed balance will attribute
how2heap's characters to NEUTRAL.

**The trap: near-duplication that no text similarity can see.** Juliet is
template-generated, and its 40,617 self-contained single-file cases are 1,666
functional variants crossed with 28 control-flow variants. Measured with 5-token
shingle Jaccard on real pairs::

    type sibling      malloc_free_char_01  vs  malloc_free_int_01     0.733
    flow variant      CWE129_large_01      vs  CWE129_large_18        0.720
    different mechanism  CWE129_large_01   vs  CWE129_fgets_01        0.740
    different CWE     CWE121/...           vs  CWE416/...             0.306

The three things that must be told apart land inside four hundredths of each
other. There is no threshold. A char/int sibling is worthless and a different
source/sink pair is exactly what the source is for, and to a similarity measure
they are the same number. :func:`~training.corpus.source.fingerprint` is no help
either — it is whitespace-insensitive, not content-insensitive, and ``char``
really is not ``int``.

So the sampler ignores the text and reads the *name*, because Juliet's names
encode the taxonomy deliberately:
``CWE121_Stack_Based_Buffer_Overflow__CWE129_large_01.c`` is CWE-121, functional
variant ``CWE129_large``, flow variant ``01``. Quotas are applied to that
structure — see :func:`_juliet_select`. 105,735 members become 1,319 documents
spanning 117 of the archive's 118 CWE directories, which is the point: the label
is the CWE, so every CWE should be represented and none should own a quarter of
the source. The one that contributes nothing is CWE-500 Public Static Field Not
Final, whose single case is split across ``_01_bad.cpp`` and ``_01_good1.cpp``;
neither half contains the thing it would be labelled with, so neither is
admitted.

What comes out of the whole adapter is 2,161 documents and 15,927,338
characters: 1,319 Juliet cases, 474 files of curl, 324 of OpenSSH and 44
heap-exploitation programs. That is deliberately modest for a source that could
trivially have been two hundred megabytes. SYSTEM already runs at roughly 51% of
this corpus against a 24% target, so characters added here are characters
``_cap_register_share`` will trim from somewhere; the job is to add a language
the corpus does not have, not to win the register.

**Horizontal whitespace, and why this source is the one that proves it.**
:func:`~training.corpus.source.normalise` is contracted never to collapse it.
In C that contract is not a nicety about readability: 396 of OpenSSH's 419
source files are indented with literal tab characters, curl aligns its struct
initialisers in columns, and Juliet's nesting is how a reader tells the ``bad``
path from the ``good`` one. There is no ``ast.parse`` for C and no ``compile()``
that will take it, so the house rule "syntax-check with ``compile()``" has no
direct analogue here. What replaced it is three checks that are between them
stronger than the one that was unavailable, all run on every file:

1. :func:`_structure_ok`, a lexer that walks string literals, character
   literals, line comments and block comments and requires that the file does
   not end inside any of them and that ``()``, ``[]`` and ``{}`` balance.
2. :func:`_whitespace_preserved`, which is the real one. It asserts the exact
   property at risk: after normalisation, every non-blank line must be
   *byte-identical* to the corresponding raw line with only CR folding, control
   bytes and trailing ``[ \\t]`` removed. Not "similar", not "same length" —
   identical. A normaliser that collapsed one run of indentation anywhere in
   106,000 files would raise :class:`SourceError` naming the file instead of
   producing a slightly smaller corpus that nobody questions. It is exact rather
   than approximate because it was checked: not one file in any of the four
   upstreams contains a run of 200+ spaces, so ``normalise``'s ``_ABSURD`` rule
   never fires here and there is no second case to allow for.

There is a third check, and it exists because ``normalise`` has one licence to
change a line that C does not grant it. Stripping whitespace *after a backslash
line-continuation* converts a line that is not a continuation into one that is,
which changes what the preprocessor sees — and :func:`_whitespace_preserved`
cannot object, because trailing-whitespace removal is precisely what it is
written to permit. :func:`_continuation_safe` refuses any file where that
pattern occurs outside a comment. It costs nothing today: across the whole
selection the pattern appears exactly twice, both in
``how2heap/glibc_2.23/house_of_roman.c``, both inside a block comment where the
backslashes are ASCII decoration in an English sentence. The check turns "I
looked once" into a property.

One hazard was looked for and is **absent**, which is worth recording because it
was expected to be present. **C++11 raw string literals** (``R"delim(...)"``)
hold trailing whitespace as data, and normalisation would eat it with nothing to
complain. A first count said 28 files in OpenSSH and 28 in curl, and that count
was wrong: the pattern searched for was the two characters ``R"``, which matches
the tail of ``"SOME_ERROR"`` and a hundred things like it. Matched properly —
optional encoding prefix, ``R``, quote, delimiter, open parenthesis — there are
**zero** raw string literals in all 2,173 selected files. Both C libraries are
C, which has no such literal, and Juliet's C++ cases are older than the habit. A
measurement that produces an alarming number is worth re-reading before it is
worth acting on.

**Licensing, read from each upstream's own file, and one correction.** The
brief that asked for this source described curl as MIT. It is not. ``COPYING``
is the curl licence (SPDX ``curl``): an ISC/MIT-X derivative that adds a clause
forbidding use of a copyright holder's name in advertising. Permissive, usable,
and not MIT, and the difference is the kind of thing that only matters in the
conversation you least want to have. The other three were read the same way:
OpenSSH's ``LICENCE`` enumerates BSD-2, BSD-3 and public-domain components and
states outright that it contains no GPL code; how2heap ships a plain MIT
``LICENSE``; Juliet carries no licence file at all, and its terms live on the
SARD suite page, quoted verbatim in :data:`_JULIET_TERMS`.

The contamination check the licence question actually turns on was run rather
than assumed: every ``.c``, ``.h`` and ``.cpp`` file in all four upstreams —
106,000 of them — was searched end to end for ``General Public License``,
``LGPL``, ``AGPL``, ``Mozilla Public License``, ``CDDL`` and the BSD advertising
clause. Zero hits. Each archive's licence file is copied into the cache under
``licenses/`` so the declaration in :data:`SPEC` can be checked against what was
downloaded.

Juliet is the one download in this corpus whose bytes can be **verified rather
than merely hashed**. SARD publishes the sha256 of the 1.3 zip on the same page
as the terms of use, the suite is a frozen versioned artefact rather than a
moving branch, and :data:`_JULIET_SHA256` holds that digest. If NIST ever
re-rolls the file, this adapter stops rather than training on something else.
The other three are codeload branch tarballs; their digests are observed and
recorded, and the marker says plainly which of the two that is.

**What was rejected, and why.** Named here so nobody spends an afternoon
rediscovering it:

* **The Linux kernel.** Not on licence grounds — GPL-2.0 is usable if stated,
  and :mod:`~training.corpus.sources.kerneldocs` already carries kernel text on
  exactly that basis. It is rejected on fetch economics and register economics.
  ``kerneldocs`` is cheap because ``Documentation/`` sorts near the *front* of
  git's tree order, so the tarball can be streamed and the connection dropped
  after 15 MB. The subtrees that carry the security reasoning — ``security/``
  (the LSM hooks), ``mm/`` — sort *after* ``drivers/``, so the same trick buys
  nothing and a few megabytes of LSM code costs a ~230 MB download that is
  mostly device drivers. And SYSTEM already runs at about 51% of the corpus
  against a 24% target, so those characters would be trimmed by
  ``_cap_register_share`` before they were ever trained on.
* **musl.** MIT and permissive (``COPYRIGHT`` names the third-party portions and
  all are BSD-2, public domain or MIT-style), so the licence is fine. It was
  measured and dropped: 1,619 source files, median size **258 bytes**. musl is
  deliberately comment-free, and its 17% comment share is almost entirely the
  Sun/FreeBSD licence headers carried by ``src/math``. After the size and
  comment gates below it would have contributed a couple of hundred files of
  libm, which teaches floating point, not security.
* **OpenSSL.** Apache-2.0 on 3.x and therefore usable, but tens of megabytes
  dominated by generated perlasm, into a register that is already over budget.
  curl's ``lib/vtls/openssl.c`` shows the API in use for a fraction of the cost.
* **The CVE-linked patch corpora**, and this is the useful part of the report.
  ``CVEfixes`` is MIT *for its scraper* and offers the data under CC BY 4.0 — a
  relicensing its authors are not in a position to grant, because the data is
  patches copied out of other people's repositories, many of them GPL. ``Big-Vul``
  (MSR_20) is MIT on the repository while the actual corpus is a CSV on Google
  Drive holding functions lifted from 348 GitHub projects. ``PrimeVul`` is MIT
  and is built *from* Big-Vul, CrossVul and CVEfixes, so it inherits every one of
  those questions. ``DiverseVul`` has no LICENSE file on any branch and ships
  from Google Drive, which under the rule that disabled
  :mod:`~training.corpus.sources._internal_unlicensed` makes it
  all-rights-reserved. The pattern is worth naming once: a permissive licence on
  a dataset repository describes the collection code, not the third-party source
  inside the collection, and none of these ships a per-record licence column.
  Juliet has no such problem because NIST wrote every line of it.
* **Juliet 1.3.1 "with extra support"** (SARD suite #116) is the newer release
  and is not used: it is a 671 MB download that updates 28 of 64,099 test cases.
  1.3 is 146 MB for the same material.
"""

from __future__ import annotations

import collections
import fnmatch
import hashlib
import json
import os
import re
import shutil
import tarfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

from ..net import NetworkError, download
from ..source import (
    Document, Register, Side, SourceError, SourceSpec, fingerprint, normalise,
)

_NAME = "clang"

#: Written last, so its presence means every project finished. The version is
#: part of it: when the gates or quotas below change, a cache built under the
#: old rules is stale, and silently reusing it is how a fix fails to reach the
#: machine that already ran the build once.
_MARKER = ".fetched.json"
_CACHE_VERSION = 1

#: The sha256 SARD publishes for the Juliet C/C++ 1.3 archive, read from
#: https://samate.nist.gov/SARD/test-suites/112 — the same page that states the
#: terms in :data:`_JULIET_TERMS`. Pinning it is worth more here than anywhere
#: else in the corpus: a numbered SARD suite is frozen, so unlike a codeload
#: branch tarball there is a correct answer and any other answer is a reason to
#: stop.
_JULIET_SHA256 = "ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb"

#: Quoted verbatim from https://samate.nist.gov/SARD/test-suites/112 because the
#: archive itself ships no licence file — the doc/ directory holds two PDFs and a
#: changelog and nothing else. This string is written into the cache beside the
#: source it covers, with the URL it came from, so the claim in :data:`SPEC` has
#: something on disk behind it.
_JULIET_TERMS = """\
Juliet Test Suite for C/C++ version 1.3 — NIST Software Assurance Reference
Dataset, test suite #112, author: NSA Center for Assured Software.
Retrieved from https://samate.nist.gov/SARD/test-suites/112

Terms, quoted verbatim from that page:

    This software is not subject to copyright protection and is in the public
    domain. NIST assumes no responsibility whatsoever for its use by other
    parties, and makes no guaranties, expressed or implied, about its quality,
    reliability, or any other characteristic. Pursuant to 17 USC 105, Juliet
    Test Suite for C/C++ version 1.3 is not subject to copyright protection in
    the United States. To the extent NIST may claim Foreign Rights in Juliet
    Test Suite for C/C++ version 1.3, the Test Suite is being made available to
    you under the CC0 1.0 Public Domain License.

sha256 of the archive, as published on the same page:
    ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb
"""


# ---------------------------------------------------------------------------
# Juliet selection
# ---------------------------------------------------------------------------

#: A self-contained Juliet case: one CWE directory, one functional variant, one
#: two-digit flow variant, one translation unit. The letter-suffixed members of
#: the family (``_51a.c``, ``_52b.c``), the split ``_goodB2G``/``_bad`` fragments
#: and the ``_81.h`` class headers are all deliberately *not* matched. Each of
#: those is a fragment that means nothing alone — a ``.h`` in the 81 series is a
#: bare class declaration — and admitting fragments would put text in the corpus
#: that does not contain the thing it is labelled with.
_JULIET_CASE = re.compile(r"^(CWE\d+)_(.+?)__(.+?)_(\d\d)\.(c|cpp)$")

#: C type tokens, stripped from *anywhere* in a functional-variant name to get
#: the "shape" of a case: the source/sink mechanism with the data type removed.
#: ``c_CWE193_char_cpy`` and ``c_CWE193_wchar_t_cpy`` are one shape;
#: ``char_fscanf_add`` and ``int64_t_fscanf_add`` are another. Stripping anywhere
#: rather than only from the tail is what makes this work: measured over the
#: 1,666 families, tail-only stripping collapses 6% of them and stripping
#: anywhere collapses 46%, because Juliet writes the type in the middle of the
#: name as often as at the end.
#:
#: ``t`` is in the set because ``wchar_t`` and ``int64_t`` tokenise as
#: ``wchar``/``t`` and ``int64``/``t`` on underscore. It never means anything
#: else in a Juliet name.
_JULIET_TYPE_TOKENS = frozenset({
    "char", "wchar", "t", "int", "int8", "int16", "int32", "int64",
    "long", "short", "unsigned", "signed", "float", "double",
    "struct", "twoIntsStruct", "union", "string", "wstring", "void",
})

#: Flow variants worth a second look, in preference order. The other twenty are
#: the same idea in different clothes — Juliet has fourteen separate variants for
#: "the branch is always taken", from ``if(1)`` through ``if(GLOBAL_CONST_FIVE
#: == 5)`` — and teaching a model fourteen spellings of a constant-true predicate
#: is teaching it nothing. These five are structurally distinct: a condition the
#: compiler genuinely cannot fold (12), a switch (15), a loop (17), a ``goto``
#: (18), and data reaching the sink through a static global rather than down the
#: stack (45).
_JULIET_FLOW_EXTRA = ("12", "15", "17", "18", "45")

#: Two type instantiations per source/sink shape. One would hide that the same
#: flaw exists for wide characters and for 64-bit integers, which is a real part
#: of the subject; six is the same file six times.
_JULIET_PER_SHAPE = 2

#: Twenty baseline (flow variant 01) cases per CWE. CWE-122 Heap Based Buffer
#: Overflow has 65 distinct shapes and CWE-482 has one; without a per-CWE cap the
#: five largest weakness classes would be two thirds of the source, and the CWE
#: is the label, so every CWE deserves to be represented and none deserves to
#: dominate.
_JULIET_PER_CWE_BASELINE = 20

#: …and eight per CWE showing the same flaw reached through a different control-
#: or data-flow construct. Deliberately much smaller than the baseline quota:
#: the control-flow idea needs to be *present* in the corpus, not learned once
#: per weakness class.
_JULIET_PER_CWE_FLOW = 8

#: Juliet's shared support headers and helpers — ``std_testcase.h`` defines the
#: types every case uses and ``io.c`` defines ``printLine``, so without them the
#: cases reference identifiers the model has never seen defined. Eight small
#: files, admitted by name.
_JULIET_SUPPORT = "testcasesupport/"


def _juliet_shape(functional: str) -> str:
    """The source/sink mechanism of a functional variant, minus its data type."""
    parts = [p for p in functional.split("_") if p not in _JULIET_TYPE_TOKENS]
    return "_".join(parts) or functional


def _juliet_select(paths: list[str]) -> set[str]:
    """Choose which Juliet cases enter the corpus, from their names alone.

    Three nested quotas, applied to the taxonomy Juliet encodes in its
    filenames. Deterministic — everything is sorted — so two runs of the build
    on the same archive select the same files and the cache is reproducible.

    The order matters and is the whole design. Baselines are taken first, across
    as many distinct shapes as the per-CWE quota allows, because flow variant 01
    is the clean statement of the weakness with nothing in the way. Only then
    are the extra flow variants taken, so a CWE with many mechanisms spends its
    budget on mechanisms and a CWE with few spends what is left on control flow.

    See the module docstring for why this is done on names and not on text
    similarity: the three relationships that have to be told apart — type
    sibling, flow variant, genuinely different mechanism — differ by four
    hundredths of Jaccard, and the name separates them exactly.
    """
    cases: dict[tuple[str, str], dict[str, str]] = collections.defaultdict(dict)
    for path in paths:
        match = _JULIET_CASE.match(path.rsplit("/", 1)[-1])
        if match:
            cwe, _name, functional, flow, _ext = match.groups()
            cases[(cwe, functional)][flow] = path

    # One shape may be instantiated for six data types; keep the first two by
    # name so the choice does not depend on archive order.
    by_shape: dict[tuple[str, str], list[str]] = collections.defaultdict(list)
    for cwe, functional in sorted(cases):
        by_shape[(cwe, _juliet_shape(functional))].append(functional)
    families = sorted(
        (cwe, functional)
        for (cwe, _shape), names in by_shape.items()
        for functional in names[:_JULIET_PER_SHAPE]
    )

    chosen: set[str] = set()
    baselines: collections.Counter[str] = collections.Counter()
    for cwe, functional in families:
        variants = cases[(cwe, functional)]
        if "01" in variants and baselines[cwe] < _JULIET_PER_CWE_BASELINE:
            chosen.add(variants["01"])
            baselines[cwe] += 1

    flows: collections.Counter[str] = collections.Counter()
    for cwe, functional in families:
        if flows[cwe] >= _JULIET_PER_CWE_FLOW:
            continue
        variants = cases[(cwe, functional)]
        for flow in _JULIET_FLOW_EXTRA:
            if flow in variants:
                chosen.add(variants[flow])
                flows[cwe] += 1
                break

    chosen.update(p for p in paths
                  if p.startswith(_JULIET_SUPPORT) and p.endswith((".c", ".h")))
    return chosen


# ---------------------------------------------------------------------------
# how2heap selection
# ---------------------------------------------------------------------------

_HOW2HEAP_DIR = re.compile(r"^glibc_(\d+)\.(\d+)/")

#: A ``glibc_*`` directory needs this many techniques to count as a complete
#: port. The newest directory in the repository is usually a port in progress
#: (2.43 had 16 files against 2.40's 24), and picking "newest" blindly would
#: trade a third of the techniques for a version number.
_HOW2HEAP_MIN_FILES = 20


def _how2heap_select(paths: list[str]) -> set[str]:
    """Keep two glibc generations out of sixteen, and the root-level programs.

    The repository re-ports the same two dozen techniques for every glibc
    release, which is sixteen directories of what looks like duplication. It is
    not *entirely* duplication, and the measurement says where the line is:
    between ``glibc_2.23`` and ``glibc_2.40`` eight techniques exist only in the
    old tree (house of force, house of orange, unsorted bin attack — all killed
    by later hardening), eleven exist only in the new one (everything tcache),
    and the thirteen they share are only 0.36–0.68 similar because the attack
    has been rewritten around safe-linking and the tcache key.

    Two generations, then: the oldest, which is a pre-tcache allocator and a
    genuinely different target, and the newest complete one. The fourteen
    releases in between are adjacent ports of the same code and are dropped.
    """
    versions: dict[tuple[int, int], list[str]] = collections.defaultdict(list)
    for path in paths:
        match = _HOW2HEAP_DIR.match(path)
        if match and path.endswith(".c"):
            versions[(int(match.group(1)), int(match.group(2)))].append(path)

    keep: set[str] = set()
    if versions:
        ordered = sorted(versions)
        complete = [v for v in ordered
                    if len(versions[v]) >= _HOW2HEAP_MIN_FILES]
        for version in {ordered[0], (complete or ordered)[-1]}:
            keep.update(versions[version])

    # first_fit.c, malloc_playground.c, calc_tcache_idx.c: the explanatory
    # programs that are not a technique, at the repository root.
    keep.update(p for p in paths if "/" not in p and p.endswith(".c"))
    return keep


# ---------------------------------------------------------------------------
# Projects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Project:
    """One upstream, its verified licence, and the part of it worth keeping."""

    name: str
    url: str
    #: Read from the project's own LICENSE/LICENCE/COPYING, or — for Juliet,
    #: which ships none — quoted from the page that distributes it.
    license: str
    archive: str
    #: ``"zip"`` or ``"tar"``. Juliet is the only zip in the corpus.
    kind: str
    #: Path prefixes to keep, relative to the archive root after its single
    #: top-level directory is stripped. Empty means "the whole tree".
    keep: tuple[str, ...] = ()
    #: Prefixes carved back out of ``keep``, for licence or quality reasons.
    drop: tuple[str, ...] = ()
    #: Optional name-driven sampler, applied after ``keep``/``drop`` and before
    #: any file is decoded. Where a project's redundancy is structural rather
    #: than textual, this is where that structure is read.
    select: Callable[[list[str]], set[str]] | None = None
    #: The sha256 the upstream publishes for exactly these bytes, where it
    #: publishes one. Empty is honest for a moving branch tarball, which has no
    #: stable digest to compare against.
    sha256: str = ""
    #: Ceiling handed to :func:`~training.corpus.net.download`, enforced against
    #: bytes as they arrive. Per project rather than global because the size a
    #: source is *expected* to be is a fact about that source.
    max_archive_bytes: int = 64 * 1024 * 1024
    #: Floor on files surviving every gate. A project that suddenly yields far
    #: fewer has moved its source directory and should say so at fetch time,
    #: naming itself, rather than as a thin build report three sources later.
    min_files: int = 20
    side: Side = Side.NEUTRAL
    #: Written into the cache beside the licence text, for the human who checks.
    license_note: str = ""


_PROJECTS: tuple[_Project, ...] = (
    _Project(
        name="juliet",
        url="https://samate.nist.gov/SARD/test-suites/112",
        license=("public domain in the United States (17 USC 105); CC0-1.0 for "
                 "any foreign rights NIST may claim. Stated on the SARD suite "
                 "page, which is quoted verbatim into the cache — the archive "
                 "itself carries no licence file."),
        archive=("https://samate.nist.gov/SARD/downloads/test-suites/"
                 "2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip"),
        kind="zip",
        keep=("testcases/", "testcasesupport/"),
        select=_juliet_select,
        sha256=_JULIET_SHA256,
        # 146 MB on the wire. The ceiling is set just above it rather than
        # generously, because this is a frozen artefact: if it grows, something
        # is wrong and the download should stop rather than succeed.
        max_archive_bytes=180 * 1024 * 1024,
        min_files=900,
        license_note=_JULIET_TERMS,
    ),
    _Project(
        name="openssh",
        url="https://github.com/openssh/openssh-portable",
        license=("BSD-2-Clause and BSD-3-Clause with public-domain components, "
                 "enumerated in the LICENCE file, which states outright that "
                 "OpenSSH contains no GPL code."),
        archive=("https://codeload.github.com/openssh/openssh-portable/"
                 "tar.gz/refs/heads/master"),
        kind="tar",
        # openbsd-compat/ is not filler: strlcpy, strlcat, explicit_bzero,
        # arc4random and timingsafe_bcmp are the mitigation literature written
        # out as implementations, and they are the most-copied C in existence.
        keep=(),
        # regress/ is the test suite, contrib/ is packaging and third-party
        # helpers under their own terms.
        drop=("regress/", "contrib/"),
        min_files=200,
    ),
    _Project(
        name="curl",
        url="https://github.com/curl/curl",
        license=("curl licence (SPDX: curl) — an ISC/MIT-X derivative whose "
                 "COPYING adds a clause forbidding use of a copyright holder's "
                 "name in advertising. Permissive; not MIT, despite being "
                 "widely described as such."),
        archive="https://codeload.github.com/curl/curl/tar.gz/refs/heads/master",
        kind="tar",
        # lib/ and src/ are the library and the command-line tool.
        # include/curl/ is the public API: 136 KB of option constants each with
        # its documentation comment, which is the id-beside-its-name shape this
        # corpus was rebuilt around.
        keep=("lib/", "src/", "include/curl/"),
        # tests/ is 422 files of fixtures, and docs/ is already prose the corpus
        # has plenty of.
        drop=("tests/", "docs/"),
        min_files=200,
    ),
    _Project(
        name="how2heap",
        url="https://github.com/shellphish/how2heap",
        license="MIT (Copyright (c) 2020 Shellphish)",
        archive=("https://codeload.github.com/shellphish/how2heap/"
                 "tar.gz/refs/heads/master"),
        kind="tar",
        select=_how2heap_select,
        # Two generations of about two dozen techniques. The floor is low
        # because the source legitimately is.
        min_files=30,
        side=Side.RED,
    ),
)


# ---------------------------------------------------------------------------
# Admission gates
# ---------------------------------------------------------------------------

#: Directory names that are never corpus, wherever they appear in a path.
#: ``vendor`` and ``third_party`` matter most: C projects vendor each other
#: constantly, and a vendored copy is the same text under a different licence
#: at a different path. Duplicated text in a corpus this size is worse than
#: absent text, because the model memorises it.
_SKIP_DIRS = frozenset({
    "test", "tests", "testing", "testdata", "test_data", "regress", "fuzz",
    "fuzzing", "vendor", "_vendor", "vendored", "third_party", "thirdparty",
    "external", "contrib", "build", "dist", ".git", "node_modules", "m4",
    "packages", "plan9", "win32",
})

#: Build glue, configure output and single-symbol shims.
_SKIP_FILES = (
    "config.h", "*_config.h", "curl_config.h", "*-config.h",
    "*.pb-c.*", "y.tab.*", "lex.yy.*", "*_test.c", "test_*.c", "*_unittest.*",
)

#: Phrases that mark a file as machine output, checked against the head only —
#: a hand-written parser may legitimately discuss generated code further down.
#: Generated C is real C and passes every other gate here, so nothing but this
#: catches it. On this selection the list flags exactly three files: OpenSSH's
#: ``sntrup761.c`` (extracted from supercop), curl's ``lib/easyoptions.c`` and
#: ``src/tool_listhelp.c``.
#:
#: Two phrases were tried and removed, and both failures point the same way. A
#: bare ``"generated by"`` flagged four hand-written files. ``"do not modify"``
#: flagged six Juliet cases — the CWE-506 Embedded Malicious Code family, whose
#: ``@description`` block reads ``GoodSink: Do not modify the file's created
#: time attribute``. Neither phrase caught anything the remaining list misses.
#: A sniff that reads a file's *subject matter* as a claim about its
#: *provenance* will always do this, and the narrower the phrase the less often
#: it can.
_GENERATED_MARKERS = (
    "do not edit", "don't edit",
    "automatically generated", "auto-generated", "autogenerated",
    "generated automatically", "@generated",
    "this file is generated", "generated file",
)
_GENERATED_HEAD_BYTES = 2048

#: Below this a file is a one-function shim or a header of nothing but include
#: guards and forward declarations.
_MIN_BYTES = 1_200

#: Above this a file is a table. The number is 60% higher than the Python
#: adapter's, on purpose and not by drift: C has no module system, so a
#: translation unit legitimately runs long — ``curl/lib/http.c`` is 157 KB of
#: hand-written protocol handling and ``openssh/channels.c`` is 154 KB. A 100 KB
#: cap would have dropped the seven most instructive files in curl. The
#: generated-file sniff is what catches big *machine* output, and it does the
#: job this number is sometimes asked to do badly.
_MAX_BYTES = 160_000

#: A file must carry this much human explanation, as an absolute quantity and
#: as a share, for the same reason the Python adapter demands it: the win this
#: corpus was rebuilt around comes from an identifier sitting one line away from
#: a sentence naming it.
#:
#: The numbers are lower than that adapter's 200 chars / 5% because C's comment
#: syntax is heavier — ``/* */`` plus a leading ``*`` on every line — and because
#: C translation units are larger, so the same quantity of explanation is a
#: smaller fraction of the file.
_MIN_EXPLAIN_CHARS = 150
_MIN_EXPLAIN_RATIO = 0.03

#: A string literal this long, containing at least one space, is counted as
#: explanation alongside comments. The rule exists because how2heap does not
#: explain itself in comments — it explains itself *as it runs*::
#:
#:     printf("This file demonstrates a simple tcache poisoning attack by "
#:            "tricking malloc into returning a pointer to an arbitrary "
#:            "location (in this case, the stack).\n");
#:
#: A comments-only measure scored ``first_fit.c`` at zero characters of prose
#: and threw away ten of the forty-five heap-exploitation programs, which are
#: among the most explanatory text in this entire source. Length plus a space is
#: what separates a sentence from a format specifier, a SQL fragment or a
#: ``#define``'d path: measured across all four upstreams the rule admits ten
#: how2heap files and changes the verdict on **zero** files in Juliet, OpenSSH
#: and curl, so it buys the case it was written for and nothing else.
_MIN_EXPLAIN_STRING = 40


def _sha256(path: Path) -> str:
    """Digest of a file, read a megabyte at a time.

    Chunked rather than ``hashlib.sha256(path.read_bytes())``: the largest
    archive here is 146 MB and there is no reason for any of it to be resident
    at once, least of all on a machine that may be training.
    """
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def _is_generated(head: bytes) -> bool:
    lowered = head[:_GENERATED_HEAD_BYTES].lower()
    return any(marker.encode("ascii") in lowered for marker in _GENERATED_MARKERS)


#: One pass over a translation unit, in the four states that matter. Written as
#: a lexer rather than a regex because the states are mutually exclusive and a
#: regex alternation cannot express "a ``/*`` inside a string literal is not a
#: comment" without becoming unreadable.
def _lex(text: str) -> Iterator[tuple[str, int, int]]:
    """Yield ``(kind, start, end)`` spans: code, string, char, line, block."""
    i, n = 0, len(text)
    start = 0
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            yield "code", start, i
            j = text.find("\n", i)
            j = n if j < 0 else j
            yield "line", i, j
            i = start = j
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            yield "code", start, i
            j = text.find("*/", i + 2)
            if j < 0:
                yield "block!", i, n
                return
            yield "block", i, j + 2
            i = start = j + 2
        elif c in "\"'":
            yield "code", start, i
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == c:
                    break
                # An unescaped newline ends a string literal in C. Treating it
                # as "still open" would let one stray quote swallow the rest of
                # the file and report every subsequent brace as unbalanced.
                if text[j] == "\n":
                    yield "string!", i, j
                    i = start = j
                    break
                j += 1
            else:
                yield "string!", i, n
                return
            if j < n and text[j] == c:
                yield "string" if c == '"' else "char", i, j + 1
                i = start = j + 1
        else:
            i += 1
    yield "code", start, n


def _structure_ok(text: str) -> bool:
    """A cheap, honest stand-in for a syntax check on a language with no parser.

    Not a C parser and not pretending to be one. It asserts two things a real
    translation unit always satisfies: the file does not end inside a block
    comment or a string literal, and ``()``, ``[]`` and ``{}`` balance outside
    comments and literals.

    The brackets are *counted* rather than matched in order because C source is
    full of legitimately unbalanced fragments — a ``{`` in one arm of an ``#if``
    and its ``}`` in the other, or Juliet's ``#ifndef OMITBAD`` wrapper.
    Counting tolerates that; a stack would not.

    Both halves earn their place, measured. Truncating 200 randomly chosen files
    at 60% of their length left an unterminated comment or string in 81 of them
    and a bracket imbalance in 108; only 11 survived both. The bracket count is
    not decoration on top of the delimiter check, it is the half that catches
    the other two thirds.

    It is kept **exact** — imbalance of zero, no slack — and that costs seven
    files. Of the 2,173 selected, 2,166 balance perfectly and seven sit at one
    or two: ``openssh/scp.c``, ``openssh/gss-serv-krb5.c``,
    ``openssh/openbsd-compat/glob.c``, ``curl/lib/url.c``,
    ``curl/lib/vtls/vtls.c``, ``curl/lib/vtls/apple.c`` and
    ``curl/lib/vtls/mbedtls.c`` — every one a preprocessor conditional whose
    arms carry different brace counts. A slack of four would recover those seven
    and would also readmit 104 of the 200 truncations above. Three tenths of one
    percent is the cheaper price, because the entire value of running this check
    *again* after :func:`~training.corpus.source.normalise` is that a failure
    there can only mean one thing.
    """
    depth = {"()": 0, "[]": 0, "{}": 0}
    for kind, start, end in _lex(text):
        if kind.endswith("!"):
            return False
        if kind != "code":
            continue
        for ch in text[start:end]:
            if ch == "(":
                depth["()"] += 1
            elif ch == ")":
                depth["()"] -= 1
            elif ch == "[":
                depth["[]"] += 1
            elif ch == "]":
                depth["[]"] -= 1
            elif ch == "{":
                depth["{}"] += 1
            elif ch == "}":
                depth["{}"] -= 1
    return all(v == 0 for v in depth.values())


def _explanation_chars(text: str) -> int:
    """Characters of human explanation: comments, plus string literals that are sentences.

    Lexed rather than scanned line by line, because the most valuable comments
    in this material are the trailing ones — Juliet's ``/* POTENTIAL FLAW: ...
    */`` sits on the end of the offending line, and how2heap's
    ``// VULNERABILITY`` brackets the exploit primitive — and a scan for lines
    that *start* with a comment marker misses every one of them.

    String literals count when they are long enough to be prose and contain a
    space; see :data:`_MIN_EXPLAIN_STRING` for the measurement that made that
    necessary and for the evidence that it admits nothing else.
    """
    total = 0
    for kind, start, end in _lex(text):
        if kind == "line":
            total += len(text[start + 2:end].strip())
        elif kind == "block":
            total += len(text[start + 2:end - 2].strip())
        elif kind == "string":
            literal = text[start + 1:end - 1]
            if len(literal) >= _MIN_EXPLAIN_STRING and " " in literal:
                total += len(literal)
    return total


#: A backslash immediately followed by trailing whitespace and a newline. See
#: :func:`_continuation_safe`.
_LOOSE_CONTINUATION = re.compile(r"\\[ \t]+\n")

_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _continuation_safe(text: str) -> bool:
    """True unless normalising this file would change what the compiler sees.

    :func:`~training.corpus.source.normalise` strips trailing ``[ \\t]`` from
    every line, and that is almost always a pure saving. The exception is a
    backslash at the end of a line with whitespace after it. C joins a line to
    the next only when the backslash is the *last* character before the newline,
    so a ``#define`` whose trailing ``\\`` is followed by two spaces is not a
    continuation and the same line without them is. Stripping silently converts
    one into the other, and :func:`_whitespace_preserved` cannot object, because
    removing trailing whitespace is exactly what it is written to permit.

    Only code, string and character spans are examined. Inside a comment a
    backslash is a character in a sentence and nothing follows from it, which is
    what both occurrences in this corpus turn out to be.
    """
    return not any(_LOOSE_CONTINUATION.search(text[start:end])
                   for kind, start, end in _lex(text)
                   if kind in ("code", "string", "char"))


def _whitespace_preserved(raw: str, cleaned: str) -> bool:
    """True when normalisation left every line's leading and internal spacing alone.

    This is the check that replaces the syntax check C cannot have, and it tests
    the property that actually matters. Reproduces only the transforms
    :func:`~training.corpus.source.normalise` documents — fold CRLF, drop control
    bytes, strip trailing ``[ \\t]`` — and then requires the surviving non-blank
    lines to match **byte for byte, in order**. Blank lines are excluded on both
    sides because capping blank-line runs is a documented transform; nothing else
    is forgiven.

    It can be this strict because it was measured: no file in any of the four
    upstreams contains a run of 200 or more spaces or tabs, so ``normalise``'s
    one width-altering rule never fires on this material and there is no legal
    difference for the comparison to allow.

    Why it matters more here than anywhere else in the corpus: 396 of OpenSSH's
    419 source files indent with literal tab characters. A normaliser that
    collapsed horizontal whitespace would not degrade this register, it would
    delete the language — and the damage would be invisible in a build report,
    because the character count would barely move.
    """
    folded = _CTRL.sub("", raw.replace("\r\n", "\n").replace("\r", "\n"))
    expected = [line.rstrip(" \t") for line in folded.split("\n")]
    return ([line for line in expected if line.strip()]
            == [line for line in cleaned.split("\n") if line.strip()])


def _wanted(project: _Project, relative: str) -> bool:
    """True if this archive member is a file this project wants to contribute."""
    if not relative.endswith((".c", ".h", ".cpp", ".hpp", ".cc")):
        return False
    if project.keep and not any(relative.startswith(p) for p in project.keep):
        return False
    if any(relative.startswith(p) for p in project.drop):
        return False
    parts = relative.split("/")
    if _SKIP_DIRS.intersection(parts[:-1]):
        return False
    return not any(fnmatch.fnmatch(parts[-1], pattern)
                   for pattern in _SKIP_FILES)


def _admit(raw: bytes) -> str | None:
    """Return the decoded source if it belongs in the corpus, else ``None``.

    The gates in the order they are cheapest: size, strict UTF-8, the
    generated-file sniff, structural sanity, safety under trailing-whitespace
    removal, and a real quantity of explanation.

    Decoding is strict on purpose. ``errors="replace"`` would admit a Latin-1
    file as source containing replacement characters, and — this is the C-
    specific half — a file whose bytes are not UTF-8 at all is usually a
    codepage-encoded Windows header or an EBCDIC compatibility file, neither of
    which is text this model should learn to produce.
    """
    if not _MIN_BYTES <= len(raw) <= _MAX_BYTES:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if _is_generated(raw):
        return None
    if not _structure_ok(text) or not _continuation_safe(text):
        return None
    explanation = _explanation_chars(text)
    if (explanation < _MIN_EXPLAIN_CHARS
            or explanation / len(raw) < _MIN_EXPLAIN_RATIO):
        return None
    return text


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------

#: Licence filenames worth copying out of an archive root, so the declaration in
#: :data:`SPEC` can be checked on disk against what was actually downloaded.
_LICENCE_NAMES = ("LICENSE", "LICENCE", "COPYING", "COPYRIGHT")
_MAX_LICENCE_BYTES = 256 * 1024


def _strip_root(name: str) -> str | None:
    """A member's path with its archive's single top-level directory removed.

    Stripping that component is what lets one set of keep-prefixes describe both
    an ``openssh-portable-master/`` codeload tarball and Juliet's ``C/``.
    ``None`` means the member is not under one, or its name contains a ``..``
    segment — in either case it is skipped rather than guessed at. These
    archives are trusted in practice, but an archive member is
    attacker-controlled data in principle, and the cheap defence is never to
    hand an archive's own names to the filesystem unchecked.
    """
    parts = name.split("/")
    if len(parts) < 2 or ".." in parts or "" in parts[:-1]:
        return None
    return "/".join(parts[1:])


def _archive_names(archive: Path, kind: str) -> list[tuple[str, int]]:
    """Every regular file in an archive, as ``(relative_path, size)``.

    Separated from reading because a name-driven sampler needs the *whole* list
    of names before it can apply a quota. For Juliet that separation is the
    difference between decompressing 1,300 files and decompressing 106,000.
    """
    if kind == "zip":
        with zipfile.ZipFile(archive) as zf:
            return [(rel, info.file_size) for info in zf.infolist()
                    if not info.is_dir()
                    and (rel := _strip_root(info.filename)) is not None]
    with tarfile.open(archive, mode="r:gz") as tar:
        return [(rel, member.size) for member in tar
                if member.isfile()
                and (rel := _strip_root(member.name)) is not None]


def _archive_read(archive: Path, kind: str,
                  wanted: set[str]) -> Iterator[tuple[str, bytes]]:
    """Yield ``(relative_path, bytes)`` for the members named in ``wanted``.

    Members are read out by hand rather than with ``extractall``: nothing an
    archive says about where a file belongs is given to the filesystem, because
    absolute paths, ``..`` segments, symlinks and hardlinks are all expressible
    in both tar and zip.
    """
    if kind == "zip":
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                relative = _strip_root(info.filename)
                if relative in wanted:
                    yield relative, zf.read(info)
        return
    with tarfile.open(archive, mode="r:gz") as tar:
        for member in tar:
            if not member.isfile():
                continue
            relative = _strip_root(member.name)
            if relative not in wanted:
                continue
            handle = tar.extractfile(member)
            if handle is None:
                continue
            with handle:
                yield relative, handle.read()


def _collect(project: _Project, archive: Path,
             staging: Path) -> tuple[int, int, int]:
    """Unpack one project's admitted sources and its licence into staging.

    Returns ``(candidates, kept, licences)`` so the marker records how selective
    the gates were, which is the number that tells you at a glance whether an
    upstream reorganised itself.

    The archive is walked twice: once for names, once for the bytes of the
    members the sampler asked for. That is what keeps Juliet affordable — of
    106,000 members, about 1,300 are ever decompressed.
    """
    files_root = staging / "files" / project.name
    files_root.mkdir(parents=True, exist_ok=True)
    resolved_root = files_root.resolve()
    licence_dir = staging / "licenses"
    licence_dir.mkdir(parents=True, exist_ok=True)

    seen = kept = licences = 0
    try:
        names = _archive_names(archive, project.kind)
        sizes = dict(names)
        candidates = [rel for rel, _size in names if _wanted(project, rel)]
        selected = set(candidates)
        if project.select is not None:
            selected = project.select(candidates) & set(candidates)
        selected = {rel for rel in selected if sizes.get(rel, 0) <= _MAX_BYTES}
        seen = len(candidates)

        licence_members = {
            rel for rel, size in names
            if "/" not in rel and size <= _MAX_LICENCE_BYTES
            and rel.upper().startswith(_LICENCE_NAMES)
        }

        for relative, raw in _archive_read(archive, project.kind,
                                           selected | licence_members):
            if relative in licence_members:
                (licence_dir / f"{project.name}.{relative}").write_bytes(raw)
                licences += 1
                continue
            text = _admit(raw)
            if text is None:
                continue

            target = files_root / relative
            if not target.resolve().is_relative_to(resolved_root):
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            # Re-encoded from the decoded text rather than copied as bytes, so
            # what lands in the cache is exactly what _admit proved to be valid
            # UTF-8 and structurally whole.
            target.write_text(text, encoding="utf-8")
            kept += 1
    except (tarfile.TarError, zipfile.BadZipFile, OSError) as exc:
        raise SourceError(
            f"{_NAME}: could not unpack {project.name}: {exc}") from exc

    if project.license_note:
        (licence_dir / f"{project.name}.TERMS.txt").write_text(
            project.license_note, encoding="utf-8")
        licences += 1

    if licences == 0:
        raise SourceError(
            f"{_NAME}: {project.name} carries no licence file at its archive "
            "root. Every source in this corpus declares a licence and this one "
            "keeps the upstream text on disk to back the declaration; an "
            "archive that no longer ships it needs a human to look, not a "
            "default."
        )
    if kept < project.min_files:
        raise SourceError(
            f"{_NAME}: {project.name} yielded only {kept} files from {seen} "
            f"selected candidates (expected at least {project.min_files}). The "
            "upstream layout has probably changed — fix the keep-prefixes or "
            "the sampler rather than training on a fraction of the project."
        )
    return seen, kept, licences


def _fetch(cache_dir: Path) -> Path:
    """Download each project, filter it, and leave a curated tree in the cache.

    Idempotent and network-free on re-run: the marker is written only after
    every project has been collected and the staging tree swapped into place, so
    an interrupted fetch re-downloads instead of leaving a half-populated
    ``files/`` that a later run would mistake for a finished corpus.

    The archives are deleted as soon as they are unpacked. Together they are
    about 155 MB, of which 146 MB is a Juliet archive that yields 6 MB of text;
    keeping them would be paying disk to avoid a download that only happens
    once.

    Accepts either the per-source directory ``build.py`` hands it
    (``<cache>/clang``) or the cache root, so calling this by hand during
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
        for project in _PROJECTS:
            suffix = ".zip" if project.kind == "zip" else ".tar.gz"
            archive = root / f".{project.name}{suffix}.part"
            try:
                # The ceiling goes to the transport, which enforces it against
                # bytes as they arrive and refuses an oversized Content-Length
                # before reading any of them.
                download(project.archive, archive, timeout=900,
                         max_bytes=project.max_archive_bytes)
            except NetworkError as exc:
                raise SourceError(f"{_NAME}: {project.name}: {exc}") from None
            try:
                digest = _sha256(archive)
                # Where the upstream publishes a digest of its own, the hash is
                # compared rather than merely recorded. Observing a hash of the
                # bytes that arrived says nothing about whether they are the
                # bytes NIST meant to serve; a poisoned CDN entry or a rewritten
                # mirror object passes every other gate here, since min_files
                # only catches a restructured tree and the size ceiling only
                # catches a large file.
                if project.sha256 and digest != project.sha256:
                    raise SourceError(
                        f"{_NAME}: {project.name}: {project.archive} hashed to "
                        f"{digest}, but the page that distributes it says the "
                        f"sha256 is {project.sha256}. These are not the bytes "
                        "the upstream published. Refusing to unpack them."
                    )
                seen, kept, licences = _collect(project, archive, staging)
            finally:
                archive.unlink(missing_ok=True)

            manifest.append({
                "project": project.name,
                "url": project.url,
                "archive_url": project.archive,
                "license": project.license,
                "side": project.side.value,
                "archive_sha256": digest,
                # Spelled out rather than left implied: "observed" is what the
                # bytes hashed to, "verified" is whether that was compared with
                # an upstream claim. Three of the four have nothing to compare
                # against, and a marker that did not say so would read as if
                # they had been checked.
                "expected_sha256": project.sha256,
                "sha256_verified": bool(project.sha256),
                "licence_files": licences,
                "candidates": seen,
                "kept": kept,
            })

        # Swap in only once every project succeeded.
        shutil.rmtree(files_dir, ignore_errors=True)
        (staging / "files").replace(files_dir)
        licence_src = staging / "licenses"
        if licence_src.is_dir():
            shutil.rmtree(root / "licenses", ignore_errors=True)
            licence_src.replace(root / "licenses")
        # Marker last: its presence is the only claim that the tree above it is
        # complete.
        marker.write_text(
            json.dumps(
                {
                    "cache_version": _CACHE_VERSION,
                    "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                time.gmtime()),
                    "projects": manifest,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return root


# ---------------------------------------------------------------------------
# Documents
# ---------------------------------------------------------------------------

#: Which project a cached path belongs to, so a document can carry the side its
#: upstream earned rather than the source-wide default.
_SIDES: dict[str, Side] = {p.name: p.side for p in _PROJECTS}


def _documents(path: Path) -> Iterator[Document]:
    """Yield one Document per cached source file, verbatim, deduplicated.

    **Symlinks are never followed.** ``os.walk(followlinks=False)`` rather than
    ``rglob``, for the reason :mod:`~training.corpus.sources.ownrepos` records
    the hard way: a sibling adapter once walked a symlink into the external
    corpus cache and pulled 180 MB of other sources back in under its own label.
    This tree is written by :func:`_fetch` and should contain no links at all,
    which is exactly the situation in which an unexamined ``rglob`` survives
    review and then does not survive the day someone points a symlink at the
    cache.

    The post-normalise checks are the point of this function. Every file here
    was proved structurally whole before it was cached, so a failure now can
    only have been introduced by :func:`~training.corpus.source.normalise` — a
    broken contract, not bad input — and it is raised rather than skipped.
    Skipping would turn "the normaliser mangles indentation" into a slightly
    smaller document count, which is precisely the kind of silent corpus damage
    this project keeps learning about afterwards.

    Deduplication is by :func:`~training.corpus.source.fingerprint`. It is the
    backstop, not the defence: it is whitespace-insensitive and case-folded,
    which catches a file vendored under two paths and cannot touch Juliet's
    near-duplicates. Those were handled at selection time, from the names.
    """
    root = path / "files" if (path / "files").is_dir() else path
    seen: set[str] = set()

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in _SKIP_DIRS and not Path(dirpath, d).is_symlink()
        )
        for filename in sorted(filenames):
            if not filename.endswith((".c", ".h", ".cpp", ".hpp", ".cc")):
                continue
            file = Path(dirpath, filename)
            if file.is_symlink():
                continue
            try:
                raw = file.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            text = normalise(raw)
            ident = file.relative_to(root).as_posix()

            if not _whitespace_preserved(raw, text):
                raise SourceError(
                    f"{_NAME}: {ident} came out of normalise() with its "
                    "horizontal whitespace altered. In C the indentation and "
                    "the column alignment are the layout the reader uses to "
                    "find the flaw, and OpenSSH indents with literal tabs — a "
                    "normaliser that collapses them does not degrade this "
                    "register, it deletes it. Fix normalise(); do not filter "
                    "around this."
                )
            if not _structure_ok(text):
                raise SourceError(
                    f"{_NAME}: {ident} was structurally whole before "
                    "normalise() and is not after — an unterminated comment or "
                    "string, or unbalanced brackets. That cannot be a data "
                    "quirk; it means the cleaner ate a delimiter."
                )

            mark = fingerprint(text)
            if mark in seen:
                continue
            seen.add(mark)

            yield Document(
                text=text,
                source=_NAME,
                register=Register.SYSTEM,
                side=_SIDES.get(ident.split("/", 1)[0], Side.NEUTRAL),
                # "juliet/testcases/CWE416_Use_After_Free/..." — unique, stable
                # across fetches, and legible in a build report.
                ident=ident,
            )


SPEC = SourceSpec(
    name=_NAME,
    license=(
        "Composite, per upstream, each read from the project's own licence file "
        "except where noted: Juliet C/C++ 1.3 is public domain in the United "
        "States under 17 USC 105 and CC0-1.0 for foreign rights, stated on the "
        "NIST SARD suite page because the archive ships no licence file and "
        "quoted verbatim into the cache; OpenSSH portable is BSD-2-Clause and "
        "BSD-3-Clause with public-domain components, enumerated in its LICENCE, "
        "which states it contains no GPL code; curl is the curl licence (SPDX: "
        "curl), an ISC/MIT-X derivative with a name-in-advertising clause — "
        "permissive but not MIT; shellphish/how2heap is MIT. Every archive's "
        "licence file is copied into the cache under licenses/ so the "
        "declaration can be checked against the download, and all 106,000 "
        "source files were searched end to end for GPL, LGPL, AGPL, MPL, CDDL "
        "and the BSD advertising clause with zero hits."
    ),
    # SourceSpec takes one url and this source has four. The one that carries
    # most of the text stands here; all four, with the archive fetched, the
    # sha256 of what arrived and whether that was checked against a published
    # digest, are written into the cache marker by _fetch.
    url="https://samate.nist.gov/SARD/test-suites/112",
    register=Register.SYSTEM,
    side=Side.NEUTRAL,
    fetch=_fetch,
    documents=_documents,
    #: 2,161 documents when this adapter was written — 1,319 Juliet cases
    #: across 117 CWEs, 474 curl, 324 OpenSSH, 44 how2heap — for 15.9 MB. (45
    #: how2heap files are selected and one is a fingerprint duplicate: a
    #: technique that survived a glibc generation without needing a single
    #: character changed. That is the backstop doing its job, and it is the only
    #: place in this source where it fires.) The floor sits about 20% under
    #: that, so ordinary upstream churn is quiet
    #: while a project vanishing entirely (a renamed source directory, a moved
    #: SARD archive) is not. Juliet's contribution is fixed by quota rather than
    #: by what upstream happens to contain, so most of the churn this has to
    #: absorb comes from the three moving branches. Each project also carries
    #: its own floor in _Project.min_files, which fails at fetch time and names
    #: the culprit; this is the backstop for several shrinking at once.
    expect_min_docs=1700,
    notes=(
        "C and C++ source, kept verbatim, from four upstreams with different "
        "habits: NIST Juliet 1.3 (every case a CWE with its flawed and fixed "
        "variant side by side, sampled by a name-driven quota because its "
        "near-duplicates are invisible to text similarity), OpenSSH portable "
        "(hardened production C, and openbsd-compat/ is the mitigation "
        "literature as implementation), curl lib/src/include (parsers for "
        "untrusted input at scale) and shellphish/how2heap (glibc heap "
        "exploitation primitives, the only RED documents here). Files under "
        "1.2 KB or over 160 KB, generated files, vendored trees and anything "
        "carrying under 150 characters of comment amounting to 3% of the file "
        "are excluded. There is no C parser in the stdlib, so instead of a "
        "syntax gate every file is proved structurally whole before caching "
        "and proved again after normalise(), and normalise() is separately "
        "required to leave every line's leading and internal whitespace "
        "byte-identical — OpenSSH indents 396 of its 419 files with tabs."
    ),
)
