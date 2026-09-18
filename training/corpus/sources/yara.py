"""YARA rules — "here is how you recognise this exact thing". DETECTION/BLUE.

A YARA rule is the most compressed formal statement a defender writes. Sigma
says *what happened* in terms a log can answer — a process name, an EventID, a
command line. YARA says *what the thing is made of*, and it says it in bytes::

    $mz = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF }
    $s1 = "coreshell.dll" fullword wide
    $s2 = "\\\\chkdbg.log" wide
    condition:
        uint16(0) == 0x5a4d and filesize < 62KB and all of them

Nothing else in this corpus contains that register. The whole collection is
built out of things that describe behaviour — ATT&CK techniques, CAPEC attack
patterns, Sigma detections over log fields, shell one-liners, man pages. Not one
of them reasons about file and memory *contents*: a hex byte pattern with
wildcards, a string set carrying ``wide``/``ascii``/``nocase``/``fullword``
modifiers that say how the bytes are encoded rather than what they mean, and a
boolean condition built over those strings with file-offset arithmetic
(``uint16(0) == 0x5a4d`` is "this is a PE"), size bounds, counting quantifiers
(``3 of ($s*)``) and PE-module predicates (``pe.imphash()``,
``pe.number_of_signatures``). A model that has never met that surface form
cannot read a rule, let alone write one.

The second thing YARA gives is the pairing this project exists to teach. Every
rule carries a ``meta:`` block — author, date, a reference URL to the report the
rule was written from, and very often the SHA-256 of the actual sample — sitting
inches from the detection logic itself. Red technique and blue control as a
pair, in one document, written by the person who did the analysis. The
:mod:`~training.corpus.sources.lolbas` adapter had to go looking for that join;
here it is simply the file format.

**Which collections, and under what licence.** Five, in ascending order of how
much the licence constrains a downstream user — which is also the order they are
walked in, for the dedup reason given below. Every licence was read from the
upstream ``LICENSE`` file rather than taken from a GitHub badge, because the
badge is wrong often enough to matter: GitHub calls two of these "NOASSERTION",
and one of those two turns out to be the cleanest set of terms here while the
other is the only non-open one.

* ``reversinglabs/reversinglabs-yara-rules`` — **MIT**. Roughly three hundred
  rules, and an unusual shape: enormous multi-kilobyte hex patterns with ``??``
  wildcards lifted straight out of disassembled functions. Three percent of
  the rules kept here and seventeen percent of the characters. This is the
  densest byte-level material in the corpus.
* ``airbnb/binaryalert`` — **Apache-2.0**, ``rules/public/`` only. Small (85
  rules) but it is the only macOS-heavy set: keychain dumpers, macOS keyloggers,
  Mach-O structure rules. Note that BinaryAlert's ``clone_rules.py`` pulls
  signature-base and Yara-Rules in at *build* time rather than checking them in,
  which is a fair warning about how much these collections overlap.
* ``Neo23x0/signature-base`` — **DRL 1.1**, the same Detection Rule License that
  :mod:`~training.corpus.sources.sigma` ships under. GitHub reports
  "NOASSERTION"; the repository README states the switch from CC BY-NC happened
  on 2021-08-13 and the ``LICENSE`` file is the DRL text. The README adds one
  condition that has to be honoured in code, not prose: the DRL covers
  everything "except the YARA rules that explicitly indicate a different license
  (see 'license' meta data)". So the per-rule ``license`` field is parsed, and
  any rule declaring a non-commercial licence is dropped rather than quietly
  swept in under the repository's headline terms. Twelve rules currently declare
  CC BY-NC 4.0 and twelve rules are therefore discarded. Other per-rule licences
  that survive because they are permissive: CC BY 4.0, BSD-2-Clause, MIT, the UK
  Open Government Licence, and Volexity's and CAPEv2's own terms. Each one stays
  verbatim inside the rule body it belongs to, which is also what DRL clause 3
  asks for.
* ``Yara-Rules/rules`` — **GPL-2.0-only**. Copyleft rather than permissive, and
  included knowingly: :mod:`~training.corpus.sources.lolbas` already establishes
  that a strong-copyleft source is acceptable here (it is GPL-3.0-only), and the
  obligation GPL-2.0 imposes — say where it came from, keep the notice — is what
  this module and ``provenance.json`` do anyway. Its position in
  :data:`_COLLECTIONS` — after the permissive sets, before the Elastic one —
  is deliberate, for a reason given under dedup below.
* ``elastic/protections-artifacts`` — **Elastic License 2.0**, ``yara/rules/``
  only, and it is the one licence here that is not open. ELv2 is
  source-available: it grants copying, distribution and derivative works, but
  forbids providing the software "to third parties as a hosted or managed
  service". That is a field-of-use restriction, and whether model weights are a
  derivative work of their training data is unsettled law, so this one is called
  out by name in the composite licence string rather than averaged into it —
  a downstream user who needs an unencumbered corpus drops one entry from
  :data:`_COLLECTIONS` and rebuilds. It is included because
  :mod:`~training.corpus.sources.elastic` already brings Elastic's SIEM
  detection rules into this corpus under exactly the same terms, and applying
  one standard to a repository's TOML and a stricter one to its YARA would be a
  position, not a policy. Just over a thousand rules, Elastic-authored, covering
  Linux and macOS malware far more evenly than the other four.

**Splitting: brace matching, not a regex.** A ``.yar`` file usually holds many
rules — signature-base averages seven and one file holds 624 — and a rule is
the natural document, so files have to be cut apart. The tempting way to do
that is to split on ``^rule `` and read to the next ``}``, and it is wrong on
this corpus in four separate ways, all of which occur in the real files:

1. Hex strings are written ``$a = { 4D 5A 90 00 }``. Those braces nest inside
   the rule and a naive matcher closes the rule on the first one.
2. Conditions carry regular expressions, and a regex can hold both braces
   (``/[a-z]{2,8}\\.exe/``) and a ``/`` that has nothing to do with division.
3. Thousands of rules sit inside ``/* ... */`` comments. ``apt_apt10.yar`` opens
   a comment on line 14 and closes it on line 1388, with a complete rule in
   between; ``apt_flame2_orchestrator.yar`` is one commented-out rule and
   nothing else. A regex splitter emits those as live rules. It should emit
   nothing.
4. String literals contain braces and slashes and quotes of their own.

So :func:`_split_rules` is a small lexer that walks the file once, tracking line
comments, block comments, double-quoted strings with backslash escapes, and
regex literals, and counts braces only in code. Regex literals are found with
the classic "can an operand start here?" test — a ``/`` begins a regex unless the
previous significant character could end a value, which is what separates
``$re = /.../`` and ``matches /.../`` from ``filesize / 2``. Run over all 2,750
rule files in the five collections it finds 23,166 rules and never once loses
brace balance; where it disagrees with a naive ``^rule`` count, the difference
is always a commented-out rule that the naive count got wrong. If it ever does
fail on a file, that file is emitted whole as a single document rather than
dropped, because a source that silently discards what it cannot parse is a
source whose build report lies. Nothing upstream currently reaches that
fallback, which is worth saying out loud: the day something does, it shows up
in the build report as one very large document instead of as missing rules.

**Whitespace is the rule.** ``normalise()`` preserves horizontal whitespace by
contract and this is the register that proves why. Collapsing space runs would
turn ``{ 4D 5A 90 00 03 00 00 00 }`` into ``{ 4D 5A 90 00 03 00 00 00 }`` — fine
— but it would also flatten ReversingLabs' hex blocks, which are laid out
sixteen bytes to a line so a human can read them against a disassembly, and it
would destroy the column alignment of their ``meta:`` blocks
(``author              = "ReversingLabs"``). Worse, it would flatten the
indentation that distinguishes ``strings:`` from the ``$s1 = ...`` lines beneath
it, and a YARA rule's readability is almost entirely that two-level indent.
Nothing is cleaned privately here; the rule body goes through
:func:`~training.corpus.source.normalise` exactly as every other source's text
does, and nothing else.

**One consequence is measured and then accepted, not worked around.**
:mod:`training.corpus.boilerplate` strips any mostly-alphabetic line of 40+
characters that recurs across 25+ documents. Run against this source alone that
is 114 lines and 1.1 MB, 6.6% of what the adapter emits, and it is exactly the
furniture you would expect: signature-base's DRL
``license = "Detection Rule License 1.1 …"`` line in 2,869 documents, its
``author = "Florian Roth (Nextron Systems)"`` credit in 2,845, and a scatter of
report URLs that a few hundred rules cite in common — the LOLDrivers repository
in 529, one FireEye post in 156. Those lines will be cut out of the rule bodies
corpus-wide, and that is left alone on purpose: a source that reshapes its own
text to slip past a corpus-wide filter is a source whose output no longer means
what the build report says it means, and the filter is right — an identical
credit line in three thousand documents is furniture that a model this size
would spend capacity memorising.

The header restates author and date as one sentence because that is how a person
writes them, and for signature-base the per-rule date incidentally keeps the line
unique, so the attribution the DRL asks for survives in the register that reads
as attribution. That does *not* generalise, and checking rather than assuming is
the only reason it is known: 611 Elastic rules share both an author and a
creation date, so ``Written by Elastic Security on 2021-09-16.`` is furniture by
the filter's definition and will go. The claim is therefore "sometimes", not
"always", and it is written down that way.

**Dedup, and why the order of the table matters.** These repositories copy each
other relentlessly: 2,014 of Yara-Rules' rules are already in
signature-base under the same name, and BinaryAlert's ``clone_rules.py`` is
literally a script for doing it. Two keys are used together. The first is the
rule name, case-folded, which is not an arbitrary choice — YARA itself refuses
to compile two rules with the same name in one namespace, so "one document per
rule name" is the format's own uniqueness constraint rather than a heuristic
this adapter invented. The second is a whitespace-insensitive fingerprint of the
body, which catches a rule copied under a new name. Together they remove 2,027
rules. Collections are walked most-permissive-licence-first — MIT, Apache-2.0,
DRL, GPL, then the Elastic License — so when the same rule exists in two places
the copy that survives into the corpus is the one under the loosest terms. Quality
happens to agree: signature-base is the better-maintained of the two large
collections and it is ahead of Yara-Rules in that order anyway.

**Four generated dumps are excluded, and that is not housekeeping.**
``packers/peid.yar`` is 7,614 rules — 59% of everything in Yara-Rules and 2.7 MB
— mechanically converted from PEiD signature databases by a script named in its
own header. Every one of them is the same four lines with a different hex blob,
and exactly *one* of the 7,614 carries a description. ``packers/packer.yar`` is
another 1,662 of the same shape. ``certificate/blocklist.yara`` is 931 copies of
one certificate-blocklist template with the serial number swapped. And
``yara-rules_vuln_drivers_strict_renamed.yar`` is a 507-rule near-verbatim twin
of ``yara-rules_vuln_drivers_strict.yar`` — same hashes, same hex strings, the
word "renamed" inserted into the description — which neither the name key nor
the body fingerprint can see, because every one of those 507 pairs differs by
about one percent. Together they are 10,714 rules and 4.9 MB of a corpus whose
own build refuses to repeat text on the grounds that "duplicated text in a small
corpus is worse than absent text, because the model memorises it". The shapes
they teach are not lost: hundreds of ordinary packer, certificate and driver
rules remain. Yara-Rules' ``deprecated/`` tree is dropped for the same reason
the Sigma adapter drops its own.

**Each document is compilable.** A rule using ``pe.imphash()`` needs
``import "pe"``, and that import sits at the top of the file, not in the rule. So
the file's imports are re-emitted above each rule, filtered to the modules that
rule actually references. It costs thirteen characters and it means every
document is a complete, valid YARA unit rather than a fragment that would not
load — which is the form the model should learn to produce.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import tarfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from ..net import NetworkError, download
from ..source import Document, Register, Side, SourceError, SourceSpec, normalise


@dataclass(frozen=True, slots=True)
class _Collection:
    """One upstream rule repository and the terms it arrives under.

    The licence lives here rather than in a comment because :data:`SPEC`'s
    licence string is *generated* from this table. A collection cannot be added
    without declaring its terms, and the declared terms cannot drift away from
    what the code actually collects, which is the failure mode
    :class:`~training.corpus.source.SourceSpec` refuses to allow.
    """

    #: Short key. Becomes the cache directory and the first path segment of
    #: every ``ident``, so it is stable and lowercase.
    key: str
    repo: str
    ref: str
    #: SPDX identifier where one exists, for the per-document header line.
    license_id: str
    #: The sentence that goes into the composite ``SPEC.license``.
    license_note: str
    #: Archive path prefixes to extract. Everything else in the repository —
    #: IOC CSVs, terraform, test fixtures, docs — is never written to the cache.
    keep: tuple[str, ...]
    #: Paths (relative to the collection root, so after ``keep`` has been
    #: applied) that are extracted but never read. Generated dumps and
    #: near-verbatim twins; see the module docstring for the counts.
    skip: tuple[str, ...] = ()
    #: Rule files observed upstream when this adapter was written, and a floor
    #: well beneath it. A renamed directory upstream then fails loudly at fetch
    #: time instead of showing up as a mysteriously thin build report.
    observed_files: int = 0
    min_files: int = 1
    note: str = ""


#: Walked in this order, and the order is load-bearing: dedup keeps the *first*
#: copy of a rule it sees, so the most permissively licensed collection goes
#: first and the copy that survives into the corpus is the one under the loosest
#: terms. See the module docstring.
_COLLECTIONS: tuple[_Collection, ...] = (
    _Collection(
        key="reversinglabs",
        repo="reversinglabs/reversinglabs-yara-rules",
        ref="develop",
        license_id="MIT",
        license_note="reversinglabs/reversinglabs-yara-rules: MIT",
        keep=("yara/",),
        # 931 rules, one template, one swapped certificate serial each. Paths
        # here are relative to the collection root, i.e. with the kept "yara/"
        # prefix already stripped off by _keep_member.
        skip=("certificate/blocklist.yara",),
        observed_files=310,
        min_files=150,
        note="huge disassembly-derived hex patterns; 4% of the rules, 29% of "
             "the characters",
    ),
    _Collection(
        key="binaryalert",
        repo="airbnb/binaryalert",
        ref="master",
        license_id="Apache-2.0",
        license_note="airbnb/binaryalert (rules/public/ only): Apache-2.0",
        # Only Airbnb's own checked-in rules. rules/clone_rules.py fetches
        # signature-base and Yara-Rules at build time; those are collected here
        # from their own upstreams, under their own licences, not via this repo.
        keep=("rules/public/",),
        observed_files=81,
        min_files=40,
        note="the only macOS-heavy set: keychain dumpers, macOS keyloggers, "
             "Mach-O structure",
    ),
    _Collection(
        key="signature-base",
        repo="Neo23x0/signature-base",
        ref="master",
        license_id="DRL-1.1",
        license_note=(
            "Neo23x0/signature-base: DRL-1.1 (Detection Rule License 1.1, "
            "relicensed from CC BY-NC on 2021-08-13) except rules whose own "
            "license meta says otherwise; non-commercial ones are dropped"
        ),
        keep=("yara/",),
        # A 507-rule near-verbatim twin of yara-rules_vuln_drivers_strict.yar:
        # same hashes, same hex strings, "renamed" inserted in the description.
        # One percent apart, so neither dedup key can see it.
        skip=("yara-rules_vuln_drivers_strict_renamed.yar",),
        observed_files=751,
        min_files=400,
        note="the largest and best-documented collection; every rule has meta",
    ),
    _Collection(
        key="yara-rules",
        repo="Yara-Rules/rules",
        ref="master",
        license_id="GPL-2.0-only",
        license_note="Yara-Rules/rules: GPL-2.0-only (copyleft, included "
                     "knowingly — see the module docstring)",
        # Everything, minus the generated dumps and the retired tree. The repo
        # also declares git submodules (mobile_malware); a codeload tarball
        # contains no submodule content, which is fine — those rules are not
        # under this repository's licence anyway.
        keep=(),
        skip=(
            "packers/peid.yar",     # 7,614 machine-converted PEiD signatures
            "packers/packer.yar",   # 1,662 more of the same shape
            "deprecated/",          # retired, and duplicative of the live tree
        ),
        observed_files=566,
        min_files=300,
        note="the community collection; 2,014 of its rules are already in "
             "signature-base under the same name",
    ),
    _Collection(
        key="elastic",
        repo="elastic/protections-artifacts",
        ref="main",
        license_id="Elastic-2.0",
        license_note=(
            "elastic/protections-artifacts (yara/rules/ only): Elastic-2.0 — "
            "source-available, NOT open: forbids providing the software as a "
            "hosted or managed service"
        ),
        # The repository also carries behaviour/ (EQL) and ransomware/ trees
        # under the same licence. Only the YARA is taken; the behavioural rules
        # are a different register and a different adapter's business.
        keep=("yara/rules/",),
        observed_files=1042,
        min_files=600,
        note="Elastic-authored, and the most even Linux/macOS/Windows coverage "
             "of the five; last in the order because its licence binds hardest",
    ),
)

#: Collections whose licence is not an open-source one, named here so that
#: :func:`_composite_license` can flag them rather than letting a restriction
#: disappear into the middle of a long sentence. A reader of the build report
#: should be able to see at a glance that one upstream binds harder than the
#: rest, and which.
_NOT_OPEN_SOURCE = frozenset({"elastic"})

_CODELOAD = "https://codeload.github.com/{repo}/tar.gz/refs/heads/{ref}"

#: Written last, so its presence means extraction finished. A half-unpacked
#: collection therefore re-fetches instead of yielding a partial corpus. One
#: marker per collection, so a failure in the fourth repository does not throw
#: away the three that already succeeded.
_MARKER = ".fetched.json"

_RULE_SUFFIXES = (".yar", ".yara")

#: Below this a "rule" is a stub or a truncated fragment, not a detection.
#: The smallest real rule seen upstream is around 120 characters.
_MIN_BODY_CHARS = 50

#: Per-rule ``license`` meta values that forbid commercial use. Matched
#: case-folded as substrings, because the field is free text and upstream writes
#: it a dozen different ways — a bare URL, an SPDX-ish tag, a full sentence.
_NON_COMMERCIAL = (
    "non-commercial", "noncommercial", "non commercial",
    "by-nc", "by nc", "cc-nc", "nc 4.0", "nc/4.0",
)


# --------------------------------------------------------------------------
# fetch
# --------------------------------------------------------------------------

def _root(cache_dir: Path) -> Path:
    """Normalise whatever directory we were handed to one collections root.

    ``build.py`` calls ``spec.fetch(cache_dir / spec.name)`` and hands
    ``documents()`` the result, but it is useful to be able to point either
    function at the bare cache root by hand while developing. Both go through
    here, so both land in the same place and a hand-run adapter shares its cache
    with a real build instead of downloading forty megabytes a second time.
    """
    return cache_dir if cache_dir.name == "yara" else cache_dir / "yara"


def _keep_member(name: str, collection: _Collection) -> str | None:
    """Map an archive member path to its path inside the collection, or None.

    Members are filtered by hand rather than handed to ``TarFile.extractall``.
    The tarballs are trusted in practice, but an archive member is
    attacker-controlled data in principle — absolute paths, ``..`` segments and
    symlinks are all expressible in tar — and the cheap defence is to never let
    the archive choose a filename on the filesystem.
    """
    parts = Path(name).parts
    if len(parts) < 2:
        return None
    # Drop the archive's single root directory ("sigma-master/" and friends).
    relative = Path(*parts[1:])
    if relative.is_absolute() or ".." in relative.parts:
        return None
    posix = relative.as_posix()

    if posix == "LICENSE" or posix == "LICENSE.txt":
        return "LICENSE"
    if relative.suffix.lower() not in _RULE_SUFFIXES:
        return None
    if not collection.keep:
        return posix
    for prefix in collection.keep:
        if posix.startswith(prefix):
            # Strip the kept prefix so every collection's tree starts at its
            # own rules, and idents read the same shape across collections.
            return posix[len(prefix):]
    return None


def _extract(archive: Path, staging: Path, collection: _Collection) -> int:
    """Unpack the rule files of one collection into ``staging``."""
    staging.mkdir(parents=True, exist_ok=True)
    resolved = staging.resolve()
    written = 0

    try:
        with tarfile.open(archive, mode="r:gz") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                target_name = _keep_member(member.name, collection)
                if target_name is None:
                    continue
                target = staging / target_name
                if not target.resolve().is_relative_to(resolved):
                    continue
                handle = tar.extractfile(member)
                if handle is None:
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with handle, target.open("wb") as out:
                    shutil.copyfileobj(handle, out)
                if target.suffix.lower() in _RULE_SUFFIXES:
                    written += 1
    except (tarfile.TarError, OSError) as exc:
        raise SourceError(
            f"yara: could not unpack {collection.repo}: {exc}"
        ) from exc

    if written < collection.min_files:
        raise SourceError(
            f"yara: only {written} rule file(s) extracted from "
            f"{collection.repo} (expected at least {collection.min_files}; "
            f"{collection.observed_files} were present when this adapter was "
            "written). The upstream layout has probably changed — fix the keep "
            "prefixes rather than training on a fraction of the collection."
        )
    return written


def _fetch_one(root: Path, collection: _Collection) -> None:
    """Populate ``root/<key>/`` from a codeload tarball, idempotently.

    A tarball rather than ``git clone --depth 1``: it is one request instead of
    a process, it needs no git binary, it carries no history and no ``.git``
    that a later ``git pull`` could mutate underneath a reproducible build, and
    — the reason that matters most here — members can be filtered *during*
    extraction, so BinaryAlert contributes 64 KB of rules to the cache instead
    of 40 MB of terraform and test fixtures. This is the pattern
    :mod:`~training.corpus.sources.sigma` already uses.
    """
    destination = root / collection.key
    marker = destination / _MARKER
    if marker.is_file():
        return

    url = _CODELOAD.format(repo=collection.repo, ref=collection.ref)
    archive = root / f".{collection.key}.tar.gz"
    staging = root / f".{collection.key}.staging"
    shutil.rmtree(staging, ignore_errors=True)
    try:
        try:
            download(url, archive, timeout=300)
        except NetworkError as exc:
            raise SourceError(f"yara: download failed for {url}: {exc}") from exc
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        written = _extract(archive, staging, collection)

        # Swap into place only once staging is complete, so an interrupted
        # fetch never leaves a half-populated tree that a later run mistakes
        # for a finished one.
        shutil.rmtree(destination, ignore_errors=True)
        staging.replace(destination)
        marker.write_text(
            json.dumps(
                {
                    "url": url,
                    "repo": collection.repo,
                    "ref": collection.ref,
                    "license": collection.license_id,
                    "tarball_sha256": digest,
                    "rule_files": written,
                    "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                time.gmtime()),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    finally:
        archive.unlink(missing_ok=True)
        shutil.rmtree(staging, ignore_errors=True)


def _fetch(cache_dir: Path) -> Path:
    """Fetch every collection. Returns the directory holding all of them.

    A failure in one collection aborts the source rather than yielding three
    quarters of it, because a source that is quietly a quarter smaller than it
    claims is the exact failure ``build.py`` was written to make impossible.
    The completed collections stay cached, so a retry resumes rather than
    starting over.
    """
    root = _root(cache_dir)
    root.mkdir(parents=True, exist_ok=True)
    for collection in _COLLECTIONS:
        _fetch_one(root, collection)
    return root


# --------------------------------------------------------------------------
# splitting
# --------------------------------------------------------------------------

_WORD_CHAR = re.compile(r"[A-Za-z0-9_]")

#: Applied to an already-extracted rule, so it is anchored and cannot run away
#: across a file. Captures the name and the optional tag list after the colon.
_RULE_HEADER = re.compile(
    r"^\s*(?:(?:global|private)\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?::\s*([^{]*?))?\s*\{",
    re.S,
)

_IMPORT = re.compile(r'(?m)^\s*import\s*"([A-Za-z0-9_]+)"')


def _split_rules(text: str) -> list[tuple[int, int]] | None:
    """Return ``(start, end)`` for each top-level rule, or None if unparsable.

    A single left-to-right pass that counts braces *only in code*. Four things
    can hold a brace that is not a block delimiter, and all four occur in the
    upstream files, so all four are lexed properly rather than approximated:

    * ``// line comments`` and ``/* block comments */`` — and the block-comment
      case is not academic. Whole rules are commented out in these repositories,
      one of them spanning 1,374 lines. A splitter that does not track comments
      emits dead rules as live ones.
    * ``"double-quoted strings"`` with backslash escapes, which routinely
      contain braces, slashes and escaped quotes.
    * ``/regular expressions/`` in both string definitions and ``matches``
      conditions, which contain ``{2,8}`` quantifiers and ``[{}]`` classes.
    * Hex strings, ``$a = { 4D 5A ?? 00 }``. These *are* braces and they nest
      one level inside the rule, which the depth counter handles naturally —
      that is the whole reason for counting rather than searching for ``}``.

    Telling a regex literal from a division is the one genuinely ambiguous
    case, since ``filesize / 2`` is legal. The classic operand test settles it:
    a ``/`` starts a regex unless the previous significant character could have
    ended a value (an identifier or number character, or a closing bracket or
    quote). Over the 2,750 rule files of the five collections this never once
    brace balance.

    Returning None rather than raising lets the caller fall back to emitting the
    file whole, which is better than dropping it: an unparsable file is a
    signal about upstream, not licence to lose its content.
    """
    n = len(text)
    i = 0
    depth = 0
    spans: list[tuple[int, int]] = []
    start: int | None = None
    previous = " "          # last significant character seen outside skips

    while i < n:
        char = text[i]

        if char == "/" and i + 1 < n and text[i + 1] == "/":
            newline = text.find("\n", i)
            i = n if newline < 0 else newline
            continue

        if char == "/" and i + 1 < n and text[i + 1] == "*":
            close = text.find("*/", i + 2)
            i = n if close < 0 else close + 2
            continue

        if char == '"':
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == '"':
                    i += 1
                    break
                if text[i] == "\n":     # unterminated: do not swallow the file
                    break
                i += 1
            previous = '"'
            continue

        if (char == "/" and previous not in ')]"'
                and not _WORD_CHAR.match(previous)):
            end = _scan_regex(text, i)
            if end is not None:
                i = end
                previous = "/"
                continue

        if char == "{":
            depth += 1
            previous = char
            i += 1
            continue

        if char == "}":
            depth -= 1
            previous = char
            i += 1
            if depth < 0:
                return None
            if depth == 0 and start is not None:
                spans.append((start, i))
                start = None
            continue

        if depth == 0 and _WORD_CHAR.match(char):
            end = i
            while end < n and _WORD_CHAR.match(text[end]):
                end += 1
            word = text[i:end]
            if start is None and word in ("global", "private", "rule"):
                # Modifiers belong to the rule they precede, so the document
                # starts at "global"/"private" when one is there.
                start = i
            previous = text[end - 1]
            i = end
            continue

        if not char.isspace():
            previous = char
        i += 1

    if depth != 0:
        return None
    return spans


def _scan_regex(text: str, start: int) -> int | None:
    """Index just past a regex literal beginning at ``start``, or None.

    Character classes are tracked because ``/`` inside ``[...]`` does not end
    the literal, and a newline does: YARA regexes are single-line, so hitting
    one means this ``/`` was arithmetic after all and the caller should treat it
    as an ordinary character.
    """
    i = start + 1
    n = len(text)
    in_class = False
    while i < n and text[i] != "\n":
        char = text[i]
        if char == "\\":
            i += 2
            continue
        if char == "[":
            in_class = True
        elif char == "]":
            in_class = False
        elif char == "/" and not in_class:
            i += 1
            # Trailing modifiers: /foo/i, /foo/s, /foo/is
            while i < n and text[i] in "is":
                i += 1
            return i
        i += 1
    return None


# --------------------------------------------------------------------------
# metadata
# --------------------------------------------------------------------------

_META_START = re.compile(r"(?m)^[ \t]*meta[ \t]*:")
_META_END = re.compile(r"(?m)^[ \t]*(?:strings|condition)[ \t]*:")
_META_LINE = re.compile(r"^[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*(.+?)[ \t]*$")
_QUOTED = re.compile(r'^"((?:\\.|[^"\\])*)"')

#: Meta keys rendered into the prose header, grouped by what they mean. Upstream
#: spells the same idea several ways across four collections, so each group is a
#: list of aliases tried in order rather than a single key.
_DESCRIPTION_KEYS = ("description", "desc", "info", "comment")
_AUTHOR_KEYS = ("author", "authors", "created_by", "copyright")
_DATE_KEYS = ("date", "created", "last_modified", "modified", "version_date")
#: ``source`` is deliberately *not* a reference key. ReversingLabs writes
#: ``source = "ReversingLabs"`` to name the vendor, not a report, and rendering
#: that produced a "Reference: ReversingLabs" line on three hundred documents
#: that said nothing at all.
_REFERENCE_KEYS = ("reference", "references", "ref", "url", "report")
_FAMILY_KEYS = ("malware", "malware_family", "family", "tc_detection_name",
                "malware_type", "threat_name")
#: Sample-hash keys are matched at both ends, because upstream puts the noun
#: on either side of the underscore: signature-base writes ``hash1``/``hash2``
#: and Elastic writes ``reference_sample``. A prefix test alone silently
#: dropped the sample hash from all three thousand Elastic rules — which are
#: the ones where it matters most, since they carry no description and the
#: hash is the only concrete artefact in the block.
_HASH_PREFIXES = ("hash", "sample", "md5", "sha1", "sha256")
_HASH_SUFFIXES = ("_sample", "_hash", "_md5", "_sha1", "_sha256")
_LICENSE_KEYS = ("license", "licence")


def _meta_fields(body: str) -> list[tuple[str, str]]:
    """Parse a rule's ``meta:`` block into ordered ``(key, value)`` pairs.

    A list rather than a dict, and deliberately: ``hash``, ``reference`` and
    ``id`` legitimately repeat inside one block — the vulnerable-driver rules
    carry ten ``hash`` lines each — and a dict would keep only the last. Order
    is kept so the rendered header reads in the order the author wrote it.

    This is a line scanner, not a YARA parser, because a full parser is not
    worth carrying for four rendered lines of prose. The block's extent is
    found by anchoring on ``meta:`` and ``strings:``/``condition:`` at the start
    of a line, which is how all four collections write them.
    """
    opening = _META_START.search(body)
    if opening is None:
        return []
    region = body[opening.end():]
    closing = _META_END.search(region)
    if closing is not None:
        region = region[:closing.start()]

    fields: list[tuple[str, str]] = []
    for line in region.split("\n"):
        match = _META_LINE.match(line)
        if match is None:
            continue
        key = match.group(1).casefold()
        raw = match.group(2)
        quoted = _QUOTED.match(raw)
        if quoted is not None:
            value = quoted.group(1).replace('\\"', '"').replace("\\\\", "\\")
        else:
            # An unquoted value: an integer, true/false, or a bare token. Trim
            # any trailing comment upstream left on the line.
            value = re.split(r"/\*|//", raw, maxsplit=1)[0].strip()
        value = value.strip()
        if value:
            fields.append((key, value))
    return fields


def _first(fields: list[tuple[str, str]], keys: tuple[str, ...]) -> str:
    for key in keys:
        for name, value in fields:
            if name == key:
                return value
    return ""


def _all(fields: list[tuple[str, str]], keys: tuple[str, ...]) -> list[str]:
    wanted = set(keys)
    return [value for name, value in fields if name in wanted]


def _hashes(fields: list[tuple[str, str]]) -> list[str]:
    """Sample hashes, from keys spelled ``hash1``, ``sha256``, ``reference_sample``…

    Elastic's ``fingerprint`` is deliberately not matched: it identifies the
    *rule*, not a sample, and rendering it as "written from sample …" would put
    a confident false statement in the corpus.
    """
    out: list[str] = []
    for name, value in fields:
        if not (name.startswith(_HASH_PREFIXES) or name.endswith(_HASH_SUFFIXES)):
            continue
        if value not in out:
            out.append(value)
    return out


def _is_non_commercial(fields: list[tuple[str, str]]) -> bool:
    """True if the rule's own ``license`` meta forbids commercial use.

    signature-base's README is explicit that the repository's DRL 1.1 covers
    everything "except the YARA rules that explicitly indicate a different
    license", so the headline licence is not a safe answer for every rule in it.
    Twelve currently point at CC BY-NC 4.0 — usually as a bare URL, which is why
    this matches substrings of the free-text value rather than parsing an SPDX
    identifier that upstream never promised to write.
    """
    for value in _all(fields, _LICENSE_KEYS):
        folded = value.casefold()
        if any(marker in folded for marker in _NON_COMMERCIAL):
            return True
    return False


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------

def _truncate(text: str, limit: int = 400) -> str:
    """Trim a runaway meta value. Some descriptions are whole paragraphs."""
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(" ", 1)[0] + "…"


def _sentence(text: str) -> str:
    text = _truncate(text)
    if text and text[-1] not in ".!?":
        text += "."
    return text


def _header(name: str, tags: str, collection: _Collection, relative: str,
            fields: list[tuple[str, str]]) -> str:
    """Render the rule's provenance and metadata as readable prose.

    The first line carries the rule's own name, which makes it unique per
    document; that is worth doing on purpose, because
    :mod:`training.corpus.boilerplate` removes long alphabetic lines that recur
    across 25+ documents and a bare ``Collection: signature-base …`` line would
    be removed from every rule in any file holding more than 25 of them.

    Author and date are rendered as one sentence rather than two labelled
    fields for the same reason a person would write them that way — and the
    date is what keeps the line distinct, so the attribution the DRL asks for
    survives in the corpus even though the rule body's own repeated
    ``author = "…"`` line will be filtered out as furniture.
    """
    lines = [
        f"YARA rule {name}, from the {collection.key} collection "
        f"({collection.repo}, {collection.license_id}), "
        f"file {relative}."
    ]
    if tags:
        lines[0] = lines[0][:-1] + f", tagged {tags}."

    description = _first(fields, _DESCRIPTION_KEYS)
    if description:
        lines.append(_sentence(description))

    family = _first(fields, _FAMILY_KEYS)
    if family and family.casefold() not in description.casefold():
        lines.append(f"Malware family: {_truncate(family, 120)}.")

    author = _first(fields, _AUTHOR_KEYS)
    date = _first(fields, _DATE_KEYS)
    if author and date:
        lines.append(f"Written by {_truncate(author, 160)} on {_truncate(date, 40)}.")
    elif author:
        lines.append(f"Written by {_truncate(author, 160)}.")
    elif date:
        lines.append(f"Dated {_truncate(date, 40)}.")

    # A reference that is just the author's name again, or a placeholder, is a
    # line of nothing. Upstream writes all of these.
    empty = {"-", "n/a", "na", "none", "internal research", "internal",
             "unknown", author.casefold()}
    references = [r for r in _all(fields, _REFERENCE_KEYS)
                  if r.casefold() not in empty]
    if references:
        lines.append("Reference: " + "  ".join(_truncate(r, 200)
                                               for r in references[:2]))

    samples = _hashes(fields)
    if samples:
        # Two at most. Ten hashes of one driver is the meta block's business,
        # and the body below carries every one of them verbatim anyway.
        label = "sample" if len(samples[:2]) == 1 else "samples"
        lines.append(f"Written from {label} " + ", ".join(samples[:2]) + ".")

    return "\n".join(lines)


def _imports_for(body: str, imports: list[str]) -> str:
    """The file's ``import`` lines that this rule actually needs.

    A rule calling ``pe.imphash()`` will not compile without ``import "pe"``,
    and that import lives at the top of the file rather than in the rule, so
    splitting a file into rules would otherwise produce documents that are not
    valid YARA. Filtered to modules the rule references, so a rule that needs
    nothing carries nothing.
    """
    used = [module for module in imports
            if re.search(rf"\b{re.escape(module)}\s*\.", body)]
    return "\n".join(f'import "{module}"' for module in used)


# --------------------------------------------------------------------------
# documents
# --------------------------------------------------------------------------

def _read(path: Path) -> str | None:
    """Decode a rule file, tolerating the occasional non-UTF-8 byte.

    Rules quote malware strings, and malware strings are not always valid
    UTF-8. Latin-1 never fails and preserves the byte values, which is the
    right answer for text whose point is the bytes.
    """
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


@dataclass
class _Dedup:
    """Cross-collection duplicate suppression, on two keys at once.

    The name key is the format's own constraint rather than a heuristic: YARA
    refuses to compile two rules sharing a name in one namespace, so two rules
    called ``APT28_CHOPSTICK`` are the same rule regardless of how the copies
    have drifted. The body key catches the other direction — the same rule
    republished under a new name — using the corpus-wide
    :func:`~training.corpus.source.fingerprint` convention of hashing the text
    with whitespace removed and case folded.
    """

    names: set[str] = field(default_factory=set)
    bodies: set[str] = field(default_factory=set)

    def seen(self, name: str, body: str) -> bool:
        key = name.casefold()
        digest = hashlib.sha256(
            re.sub(r"\s+", "", body).casefold().encode("utf-8")
        ).hexdigest()[:32]
        if key in self.names or digest in self.bodies:
            return True
        self.names.add(key)
        self.bodies.add(digest)
        return False


def _skipped(relative: str, collection: _Collection) -> bool:
    return any(relative == entry or relative.startswith(entry)
               for entry in collection.skip)


def _documents(path: Path) -> Iterator[Document]:
    """Yield one Document per YARA rule, deduplicated across collections.

    Collections are walked in :data:`_COLLECTIONS` order and files in sorted
    order within each, so the output is deterministic and a rebuild produces
    byte-identical JSONL.
    """
    root = _root(path)
    dedup = _Dedup()

    for collection in _COLLECTIONS:
        base = root / collection.key
        if not base.is_dir():
            raise SourceError(
                f"yara: {collection.key} is missing from {root} — run fetch() "
                "first, or delete the cache directory and re-fetch."
            )

        for file in sorted(base.rglob("*")):
            if not file.is_file() or file.suffix.lower() not in _RULE_SUFFIXES:
                continue
            relative = file.relative_to(base).as_posix()
            if _skipped(relative, collection):
                continue
            text = _read(file)
            if text is None:
                continue

            spans = _split_rules(text)
            if spans is None:
                # Unparsable: emit the file whole rather than lose it. Nothing
                # upstream currently reaches this, which is the point of saying
                # so — if it ever fires, the build report shows one very large
                # document instead of silently missing rules.
                yield from _whole_file(text, collection, relative, dedup)
                continue
            if not spans:
                # No rules at all: an index file that only `include`s others, or
                # a file whose every rule is commented out.
                continue

            imports = _IMPORT.findall(text)
            for start, end in spans:
                document = _rule_document(
                    text[start:end], collection, relative, imports, dedup
                )
                if document is not None:
                    yield document


def _rule_document(body: str, collection: _Collection, relative: str,
                   imports: list[str], dedup: _Dedup) -> Document | None:
    """Build one Document from one extracted rule, or None to skip it."""
    header_match = _RULE_HEADER.match(body)
    if header_match is None or len(body) < _MIN_BODY_CHARS:
        return None
    name = header_match.group(1)
    tags = " ".join((header_match.group(2) or "").split())

    fields = _meta_fields(body)
    if _is_non_commercial(fields):
        return None
    if dedup.seen(name, body):
        return None

    parts = [_header(name, tags, collection, relative, fields)]
    needed = _imports_for(body, imports)
    if needed:
        parts.append(needed)
    # The body goes in exactly as upstream wrote it. normalise() below is the
    # corpus-wide contract — line endings, control bytes, trailing spaces,
    # blank-line runs — and it preserves horizontal whitespace, which is what
    # keeps the hex blocks and the strings:/condition: indentation intact.
    parts.append(body)

    return Document(
        text=normalise("\n\n".join(parts)),
        source="yara",
        register=Register.DETECTION,
        side=Side.BLUE,
        ident=f"{collection.key}/{relative}#{name}",
    )


def _whole_file(text: str, collection: _Collection, relative: str,
                dedup: _Dedup) -> Iterator[Document]:
    """Fallback for a file the lexer could not brace-match: emit it entire."""
    if len(text) < _MIN_BODY_CHARS:
        return
    if dedup.seen(f"{collection.key}/{relative}", text):
        return
    header = (
        f"YARA rule file {relative}, from the {collection.key} collection "
        f"({collection.repo}, {collection.license_id}). "
        "Emitted whole because its rules could not be separated safely."
    )
    yield Document(
        text=normalise(header + "\n\n" + text),
        source="yara",
        register=Register.DETECTION,
        side=Side.BLUE,
        ident=f"{collection.key}/{relative}",
    )


# --------------------------------------------------------------------------
# spec
# --------------------------------------------------------------------------

def _composite_license() -> str:
    """Build the declared licence from :data:`_COLLECTIONS`.

    Generated rather than written out, so a collection cannot be added to the
    table without its terms appearing in the licence ``build.py`` prints and
    ``provenance.json`` records. A hand-written string is a string that drifts.
    """
    parts = "; ".join(c.license_note for c in _COLLECTIONS)
    restricted = [c.repo for c in _COLLECTIONS if c.key in _NOT_OPEN_SOURCE]
    caveat = (
        " NOT all open source: " + ", ".join(restricted) +
        " is source-available only — drop that entry from _COLLECTIONS for an "
        "unencumbered corpus."
    ) if restricted else ""
    return (
        f"Composite, per upstream collection — {parts}. Rules declaring a "
        "non-commercial licence in their own meta are dropped." + caveat
    )


SPEC = SourceSpec(
    name="yara",
    license=_composite_license(),
    # Five upstreams, so no single repository URL is honest. Generated from the
    # table for the same reason the licence is: a hand-written list drifts.
    url=" and ".join(f"https://github.com/{c.repo}" for c in _COLLECTIONS),
    register=Register.DETECTION,
    side=Side.BLUE,
    fetch=_fetch,
    documents=_documents,
    #: 10,298 rules survived splitting, the non-commercial filter and dedup
    #: when this adapter was written, out of 23,166 found across the five
    #: collections. The floor sits at about 80% of that, matching the habit of
    #: the other adapters: rules are retired and files reorganised constantly,
    #: so ordinary churn stays quiet, while losing either large collection —
    #: signature-base is 52% of the documents, Elastic 29% — trips it. The
    #: sharper guard is per-collection and runs earlier: see _Collection.
    expect_min_docs=8000,
    notes=(
        "One document per rule, cut out of multi-rule files by a brace-matching "
        "lexer that skips comments, strings and regexes; the rule body is "
        "verbatim, prefixed by a prose header (provenance, description, author, "
        "date, reference, sample hashes) and by the file's imports so each "
        "document is compilable YARA. Deduplicated across collections on rule "
        "name and body fingerprint — 2,027 copies dropped, 2,014 of them "
        "Yara-Rules entries already present in signature-base. Four machine-"
        "generated dumps (PEiD signatures, malware-lu packers, the certificate "
        "blocklist, the renamed vulnerable-driver twin) are excluded: 10,714 "
        "rules of one template each. ReversingLabs is 3% of the rules and 17% "
        "of the characters — its hex patterns run to tens of kilobytes. One "
        "upstream, elastic/protections-artifacts, is source-available rather "
        "than open source; the licence string names it."
    ),
)
