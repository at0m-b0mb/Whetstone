"""NSA Juliet test suites — vulnerable code and its fix, side by side. ADVERSARY/NEUTRAL.

This adapter closes two measured gaps at once. The corpus has code in seven
languages — golang 3.5%, clang 2.8%, powershell 2.4%, pythoncode 1.8%, psdocs
1.7%, nselua 1.4%, shellscripts 0.7% — and **no Java, no C# and no PHP**, which
is where a very large share of the web's real vulnerabilities live. And it has
110,000 documents of advisory text describing vulnerabilities in prose while
holding almost no examples of what one actually looks like in source.

Juliet answers both. Every test case states its CWE, gives a *bad* version and a
*good* version of the same function, and says in its own header why one is
dangerous::

    CWE: 89 SQL Injection
    BadSource: getParameter_Servlet — read data from a querystring
    GoodSource: A hardcoded string
      GoodSink: Use prepared statement and executeBatch (properly)
      BadSink : data concatenated into SQL statement used in executeBatch(),
                which could result in SQL Injection

That pairing is the thing no advisory feed provides: a CVE says a product was
vulnerable, and this says what the code looked like and what the fix was.

**Licence: public domain, stated by NIST and quoted verbatim.** The archives
ship no licence file — the Java v1.3 zip's only ``*LICENSE*`` files cover
bundled third-party JARs, and a whitespace-insensitive search of the
288,000-character user guide finds no "copyright", "licence", "public domain" or
"distribution statement". The terms are on the SARD **suite pages** instead, and
that is where :mod:`~training.corpus.sources.clang` already reads them for the
C/C++ suite::

    This software is not subject to copyright protection and is in the public
    domain... Pursuant to 17 USC 105, [the Test Suite] is not subject to
    copyright protection in the United States. To the extent NIST may claim
    Foreign Rights..., the Test Suite is being made available to you under the
    CC0 1.0 Public Domain License.

Read per suite, from ``/SARD/test-suites/111`` (Java) and ``/110`` (C#), because
per suite is the only level at which it is true. ``/114`` and ``/115``, the PHP
suites, are by Felix Schuckert, Hanno Langweg and Basel Katt — named academics,
not a US Government agency — and their pages carry no terms at all. Inferring
from the SARD domain would have taken them; reading each page does not.

**No overlap with clang.** :mod:`~training.corpus.sources.clang` already takes
Juliet **C/C++** 1.3 (SARD #112, 1,319 documents). This takes Java and C# only.
The two do not share a test case, and this is checked rather than assumed
because duplicate text under two source names is a mistake this project has
already paid for.

**Why this does not take all 28,888 test cases.** Juliet is generated. Each CWE
appears in dozens of "flow variants" — variant 01 is the direct case, variant 54
passes the same tainted value through five classes to reach the same sink. The
security content is identical across them; what differs is plumbing. Taking
every file would put tens of thousands of near-identical documents into a corpus
of 195,000, and this project has already paid for that mistake once: 114
duplicated radare2 pages shipped under two source names, and the build's
whole-document fingerprint could not see it because the renderings differed.

So this keeps at most :data:`_PER_GROUP` cases per (CWE, source, sink) group,
preferring the lowest-numbered flow variants because those are the ones where
the vulnerability is legible rather than buried in call plumbing. The result is
a few thousand dense documents instead of ninety thousand repetitive ones.

**Suites taken, and one refused.** Java v1.3 (73 MB) and C# v1.3 (66 MB) are
taken, and the small PHP XSS suite with them. The PHP **SQL-injection** suite is
**not**: it is 931 MB, which for a test suite covering one weakness class is not
a corpus, it is a combinatorial expansion. Its size is the evidence — the XSS
suite beside it, built the same way for the same language, is 0.1 MB.
"""

from __future__ import annotations

import re
import shutil
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import Iterator

from ..net import NetworkError, download
from ..source import Document, Register, Side, SourceError, SourceSpec

_BASE = "https://samate.nist.gov/SARD/downloads/test-suites"

#: ``(key, archive stem, language, source extensions)``. Sizes measured with a
#: HEAD request before the list was chosen, which is how the 931 MB PHP SQLi
#: suite disqualified itself.
_SUITES: tuple[tuple[str, str, str, tuple[str, ...]], ...] = (
    # SARD suite 111. 28,881 cases, 112 CWEs, NSA Center for Assured Software.
    ("java", "2017-10-01-juliet-test-suite-for-java-v1-3", "Java", (".java",)),
    # SARD suite 110. 28,942 cases, 105 CWEs, same author.
    ("csharp", "2020-08-01-juliet-test-suite-for-csharp-v1-3", "C#", (".cs",)),
    # NOT the PHP suites. SARD 114 and 115 are by Felix Schuckert, Hanno
    # Langweg and Basel Katt — named academics, not a US Government agency — so
    # 17 USC 105 does not reach them, and their suite pages carry no terms of
    # use at all where 110 and 111 carry the public-domain statement quoted in
    # _TERMS below. Checked per suite rather than inferred from the SARD domain,
    # which is the only way the difference is visible. (The SQL-injection suite
    # disqualified itself twice over: it is also 931 MB, against 0.1 MB for the
    # XSS suite built the same way for the same language.)
)

#: Quoted verbatim from the suite pages because the archives ship no licence
#: file, the same discipline and the same wording
#: :mod:`~training.corpus.sources.clang` uses for the C/C++ suite.
_TERMS = """This software is not subject to copyright protection and is in the
public domain. NIST assumes no responsibility whatsoever for its use by other
parties, and makes no guaranties, expressed or implied, about its quality,
reliability, or any other characteristic. Pursuant to 17 USC 105, [the Test
Suite] is not subject to copyright protection in the United States. To the
extent NIST may claim Foreign Rights in [the Test Suite], the Test Suite is
being made available to you under the CC0 1.0 Public Domain License."""

#: Cases kept per (CWE, BadSource, Sink) group. Three rather than one because
#: the good/bad pairing is expressed slightly differently across flow variants
#: and a single example teaches one phrasing; three rather than ten because
#: beyond that the variants differ only in how many classes the value passes
#: through on its way to the same sink.
_PER_GROUP = 3

#: A test case below this is a fragment — Juliet splits some variants across
#: helper files that hold a single method.
_MIN_CHARS = 400

#: And above this it is mostly generated plumbing; the header and the first
#: sinks carry the lesson.
_MAX_CHARS = 14_000

_MARKER = ".fetched.json"

#: ``CWE89_SQL_Injection__getParameter_Servlet_executeBatch_54e.java`` ->
#: cwe 89, name, source+sink, variant 54e. The variant tail is what this groups
#: on, so it has to come off the end rather than out of the middle.
_CASE = re.compile(
    r"^CWE(\d+)_([A-Za-z0-9_]+?)__([A-Za-z0-9_]+?)_(\d{1,2}[a-z]?)$")

#: The block Juliet writes at the top of every generated file. It is the reason
#: this source is worth having: it names the weakness and contrasts the safe and
#: unsafe forms in prose, immediately above the code that demonstrates both.
_DESC = re.compile(r"/\*\s*\n?\s*\*?\s*@description(.*?)\*/", re.S)


def _fetch(cache_dir: Path) -> Path:
    """Download each suite and unpack only its source files.

    Unpacked rather than kept zipped because :func:`_documents` reads every case
    and a 73 MB zip re-opened per file is slower than the disk it would save.
    Only the source extensions are extracted: the archives also carry JARs,
    PDFs and build scripts, none of which is corpus text.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    for key, stem, _language, suffixes in _SUITES:
        home = cache_dir / key
        if (home / _MARKER).is_file():
            continue
        archive = cache_dir / f".{key}.zip.part"
        url = f"{_BASE}/{stem}.zip"
        try:
            download(url, archive, timeout=900, max_bytes=256 * 1024 * 1024)
        except NetworkError as exc:
            raise SourceError(f"juliet: cannot fetch {stem}: {exc}") from None

        staging = cache_dir / f".{key}.staging"
        shutil.rmtree(staging, ignore_errors=True)
        staging.mkdir(parents=True)
        kept = 0
        try:
            with zipfile.ZipFile(archive) as zf:
                for member in zf.infolist():
                    name = member.filename
                    if member.is_dir() or not name.lower().endswith(suffixes):
                        continue
                    # An archive member name is attacker-controlled in the
                    # general case; refuse absolute paths and traversal rather
                    # than trusting a government zip because it is one.
                    target = (staging / name).resolve()
                    if not str(target).startswith(str(staging.resolve())):
                        raise SourceError(
                            f"juliet: {stem} member escapes the staging "
                            f"directory: {name!r}")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(zf.read(member))
                    kept += 1
        except zipfile.BadZipFile as exc:
            raise SourceError(f"juliet: {stem} is not a zip: {exc}") from None
        finally:
            archive.unlink(missing_ok=True)

        if kept < 10:
            raise SourceError(
                f"juliet: {stem} yielded only {kept} source file(s) — the "
                f"archive layout has probably changed upstream")
        shutil.rmtree(home, ignore_errors=True)
        staging.rename(home)
        (home / _MARKER).write_text(f'{{"suite": "{stem}", "files": {kept}}}')
    return cache_dir


def _group_key(stem: str) -> tuple[str, str] | None:
    """``(cwe_and_name, source_and_sink)`` for a case file, or ``None``.

    Returning ``None`` for anything that does not parse rather than guessing:
    the support classes Juliet ships alongside the cases (``IO.java``,
    ``AbstractTestCase.java``) share the directory and are not test cases.
    """
    match = _CASE.match(stem)
    if not match:
        return None
    cwe, name, flow, _variant = match.groups()
    return f"CWE{cwe}_{name}", flow


def _variant_rank(stem: str) -> tuple[int, str]:
    match = _CASE.match(stem)
    if not match:
        return (99, stem)
    variant = match.group(4)
    return (int(re.sub(r"[a-z]", "", variant) or 99), variant)


def _documents(path: Path) -> Iterator[Document]:
    total = kept = 0
    for key, _stem, language, suffixes in _SUITES:
        home = path / key
        if not home.is_dir():
            continue
        groups: dict[tuple[str, str], list[Path]] = defaultdict(list)
        for file in home.rglob("*"):
            if not file.is_file() or not file.name.lower().endswith(suffixes):
                continue
            total += 1
            group = _group_key(file.stem)
            if group is not None:
                groups[group].append(file)

        for (case, flow), files in sorted(groups.items()):
            files.sort(key=lambda f: _variant_rank(f.stem))
            for file in files[:_PER_GROUP]:
                try:
                    text = file.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if not _MIN_CHARS <= len(text) <= _MAX_CHARS:
                    continue
                described = _DESC.search(text)
                if not described:
                    # No @description block means no statement of what the
                    # weakness is, and the code alone is a generated function
                    # with a meaningless name. That is not worth a document.
                    continue
                cwe = case.split("_", 1)[0]
                weakness = case.split("_", 1)[1].replace("_", " ")
                header = [
                    f"Juliet test case: {cwe} {weakness}",
                    f"Language: {language}",
                    f"Data flow: {flow.replace('_', ' ')}",
                    f"Reference: https://cwe.mitre.org/data/definitions/"
                    f"{cwe.removeprefix('CWE')}.html",
                    "Source: NSA Center for Assured Software, Juliet Test "
                    "Suite, via NIST SARD",
                ]
                yield Document(text="\n".join(header) + "\n\n" + text.strip(),
                               source="juliet", register=Register.ADVERSARY,
                               side=Side.NEUTRAL, ident=f"{key}/{file.stem}")
                kept += 1
    print(f"   juliet: {kept:,} documents from {total:,} test-case files "
          f"(at most {_PER_GROUP} flow variants per CWE/source/sink group)")


SPEC = SourceSpec(
    name="juliet",
    license=(
        "Public domain — the archives ship no licence file, but SARD states the "
        "terms on each suite's own page and they are quoted verbatim in _TERMS: "
        "'This software is not subject to copyright protection and is in the "
        "public domain... Pursuant to 17 USC 105, [the Test Suite] is not "
        "subject to copyright protection in the United States. To the extent "
        "NIST may claim Foreign Rights..., the Test Suite is being made "
        "available to you under the CC0 1.0 Public Domain License.' Read from "
        "https://samate.nist.gov/SARD/test-suites/111 (Java) and /110 (C#), "
        "author NSA Center for Assured Software. This is the same statement "
        "training.corpus.sources.clang already relies on for the C/C++ suite "
        "(#112). The PHP suites (#114, #115) are NOT taken: they are by named "
        "academics rather than a US Government agency, 17 USC 105 does not "
        "reach them, and their suite pages carry no terms at all."
    ),
    url="https://samate.nist.gov/SARD/test-suites",
    register=Register.ADVERSARY,
    side=Side.NEUTRAL,
    fetch=_fetch,
    documents=_documents,
    #: 112 CWEs across Java and C#, several source/sink groups each, at most
    #: three flow variants per group. The floor catches the realistic
    #: regression, which is the filename convention changing and _CASE matching
    #: nothing — that would take this to zero, not to a smaller number.
    expect_min_docs=800,
    #: Two archives of roughly 70 MB each, unpacked file by file.
    timeout=2_400,
    notes=(
        "Paired vulnerable and fixed code with a stated CWE and a prose "
        "explanation of both sinks — the thing an advisory feed cannot give. "
        "Java and C# fill the corpus's two largest language holes. Capped at "
        "three flow variants per CWE/source/sink group because Juliet is "
        "generated and variant 54 differs from variant 01 only in how many "
        "classes the tainted value passes through. The 931 MB PHP SQL "
        "injection suite is deliberately not taken; the 0.1 MB PHP XSS suite "
        "beside it shows what that size really is."
    ),
)
