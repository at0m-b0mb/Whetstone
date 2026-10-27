"""Read the finished artifact.

Every privacy finding in this corpus has the same cause, and it is not the
redactor. The redactor is correct. It was never pointed at the thing it was
supposed to protect.

The audit that prompted this module found, in order of how little code each one
needed to catch:

* ``ownrepos.py`` grew an email redactor on 2026-10-13. ``ownrepos.jsonl`` was
  written on 2026-09-23. The fix postdates the artifact by twenty days, and from
  the source tree alone a redactor that was added and never run is
  indistinguishable from one that ran and found nothing.
* ``clean-v8`` is a symlink to ``clean-v7``. "v8 was verified" was a statement
  about v7's bytes, and nothing in the build said so.
* A redaction refusal inside ``build()`` truncates the source and writes every
  earlier document to disk — documents that came from the same adapter and the
  same walk as the one caught leaking — then labels it ``parse failed``.
* ``redact_identity`` opens with ``if pattern is None: return text``. On a host
  whose identity table comes back empty (a container as root, a CI runner, an
  account name under four characters) Mac-captured text is returned unchanged
  and silently.
* Nothing between the chokepoint and the weights looks again:
  ``read_documents()`` globs ``*.jsonl`` with no redaction, ``iter_corpus()``
  likewise, and ``corpus/clean/`` holds 5,356 raw identity occurrences today.

Not one of those is a bug in a substitution. Every one of them is the absence of
a pass over the output. So this module is that pass, and it is deliberately the
dumbest thing in the tree: it does not know how the corpus was built, it does
not trust that anything upstream ran, and it answers exactly one question —
**is this machine's identity in these bytes.**

**It reports fingerprints, never values.** The audit that found these leaks
created a new one: six of its own working files wrote live MAC addresses, global
IPv6 addresses and an email address to disk as cleartext while the report
claimed it had not. That is not carelessness, it is the default behaviour of
every convenience in the language — ``repr``, ``json.dumps``, ``pickle``, a
dataclass's generated ``__repr__``, an f-string in a log line. :class:`Needles`
is the structural answer: it holds the values the scanner needs and makes every
one of those conveniences fail rather than print. His own tool Vigil holds the
same keystone property — it never prints a full secret — and this is the corpus
side of it.

**A fingerprint is not a cryptographic secret and is not claimed to be.** An
eight-character SHA-256 prefix of a seven-character account name is guessable by
anybody who already knows the account name. What it buys is that the literal is
not *written down*: a report, a CI log, a test fixture and a commit message can
all name the leak, count it, and group two occurrences as the same value,
without any of them becoming the next thing that has to be scrubbed.

Three design decisions worth naming because the obvious alternative is wrong:

**The caller decides to fail, not the scanner.** :func:`verify_corpus` returns
leaks. It does not raise. The same function therefore serves the build gate, the
CLI below and a test, instead of three detectors that drift apart — which is
precisely how ``_identity_pattern`` (``re.IGNORECASE``) and ``identity_leaks``
(plain ``.lower()``) came to disagree in both directions about the same text.

**An empty needle table is a failure, not a pass.** ``redact_identity``'s
fail-open is reachable; this module's equivalent would be a verifier that
derived nothing, scanned 625 MB, and printed "clean". :func:`main` exits **2**
for that case — *could not verify* — which is a different answer from both
*clean* (0) and *leaking* (1). A verifier that cannot tell those three apart is
the already-fixed bug in this codebase where a source trimmed to zero documents
looked identical to a source that had nothing to give.

**Needles are derived from the operating system at every run.** Not configured,
not cached to disk, not passed in. A configured list is a list of the leaks
somebody already noticed; a *persisted* list is a new leak with a filename.
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

__all__ = [
    "Leak", "Needles", "Artifact", "Survey", "Calibration",
    "KINDS", "host_needles", "scan_text", "scan_file", "verify_corpus",
    "survey", "render", "render_survey", "calibrate", "self_test", "main",
]


#: The complete kind vocabulary. Fixed, because two other modules build against
#: it and because a scanner that can invent a kind can hide one in a typo.
KINDS: tuple[str, ...] = (
    "identity",     # account name, display name, home path, host name, temp dir
    "email",        # an address configured as this machine's git identity
    "ipv6-global",  # a routable/stable IPv6 address of this host, or its /64
    "ipv4-private", # an RFC1918 address bound on this host
    "mac",          # a hardware or interface MAC of this host
    "volume",       # a mounted volume, by path or by name
    "ident-path",   # any of the above, found in a path-shaped `ident` field
    # Not a needle: a file the pass could not open or decode. It is in KINDS so
    # that it travels as a Leak and fails the gate, because "I could not read
    # it" must never be reported as "there is nothing in it". That collapse is
    # how this module reported a 625 MB corpus clean while reading none of it,
    # and it is the same discipline Momus holds to with INCONCLUSIVE vs FAILED.
    "unreadable",
)

#: Four characters, same floor as ``_identity_table``. A three-character name is
#: a substring of half the English language and substituting it shreds a corpus
#: to remove nothing.
_MIN_IDENTIFYING = 4

#: Names that identify nobody. Deliberately a superset of the set in
#: ``training/trajectories.py``: duplicated rather than imported because this
#: module must import and run on a host with no runtime installed — a container,
#: a CI job, a machine that will never train anything — and
#: ``training.trajectories`` pulls in the whole verb catalogue. The cost of the
#: duplication is that the two can drift; the guard against that is
#: :func:`host_needles`, which folds in ``_identity_table()``'s own forms when
#: the import succeeds, so this module's coverage is a superset of the
#: substituter's by construction rather than by coincidence.
_NOT_IDENTITY = frozenset({
    "root", "admin", "administrator", "user", "users", "guest", "nobody",
    "system", "daemon", "operator", "runner", "ubuntu", "debian", "fedora",
    "ec2-user", "vagrant", "docker", "localhost", "host", "hostname",
    "home", "var", "tmp", "temp", "private", "build", "test", "ci",
    "jenkins", "whetstone", "none", "null", "unknown", "default",
    # Volume names Apple ships on every Mac. A disk called "Macintosh HD"
    # identifies a hundred million machines.
    "macintosh hd", "macintosh-hd", "data", "preboot", "recovery", "vm",
    "update", "xarts", "iscpreboot", "hardware", "untitled", "time machine",
    "com.apple.timemachine.localsnapshots", "backup", "backups", "usb",
})

#: Addresses and MACs that are on every machine and identify none of them. The
#: audit's own instrument reported ``::1`` and ``fe80::1`` as leaks before it
#: learned this, which is the first thing an uncalibrated scanner does.
_UNIVERSAL = frozenset({
    "::1", "::", "fe80::1", "127.0.0.1", "0.0.0.0", "255.255.255.255",
    "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff",
})

#: Separator spellings one path takes in a rendered document.
#:
#: ``_spellings()`` in ``training/trajectories.py`` derives backslash variants
#: for Windows and nothing else, so a separator-*flattened* spelling of the home
#: path is structurally ungeneratable there and ``identity_leaks()`` calls such a
#: document clean. It is not hypothetical: the scratch directory this very
#: remediation ran in is named by flattening an absolute home path to
#: ``-Users-<account>-Documents-...``, hyphens for slashes *and* hyphens for the
#: underscore inside the account name. Any tool that builds a cache key, a log
#: filename or a session id out of a path produces one of these.
_SEPARATORS = ("/", "\\", "-", "_", ".", "+", "%2F", "%2f", "::")

#: Separator characters inside a *name* that tools swap for one another.
_NAME_SEPARATORS = ("_", "-", ".")

# A candidate IPv6 run. Deliberately permissive — `ipaddress` is the oracle, a
# hand-written IPv6 regex is not — but anchored on `hex:` so it does not fire on
# every hex blob in yara.jsonl and juliet.jsonl, which between them are 32 MB of
# hex. The lookarounds keep it off the port half of `0.0.0.0:445`.
_V6_CAND = re.compile(
    r"(?<![0-9A-Za-z:.])[0-9A-Fa-f]{1,4}:[0-9A-Fa-f:]{2,44}(?![0-9A-Za-z:.])")

_GIT_SECTION = re.compile(r"^\s*\[\s*([^\s\]]+)")
_GIT_ENTRY = re.compile(r"^\s*(name|email)\s*=\s*(.+?)\s*$", re.IGNORECASE)


def _fingerprint(value: str) -> str:
    """``len=<n>,sha256=<8 hex>`` — the only thing about a value that is ever
    written anywhere.

    Length first because it is the operationally useful half: it says how many
    bytes have to come out, and it distinguishes a bare account name from a home
    path at a glance without disclosing either.
    """
    digest = hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()
    return f"len={len(value)},sha256={digest[:8]}"


def _is_identifying(name: str) -> bool:
    return (len(name) >= _MIN_IDENTIFYING
            and name.strip().lower() not in _NOT_IDENTITY)


# --------------------------------------------------------------------------
# what a finding is
# --------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Leak:
    """One occurrence of one needle in one place.

    Every field is report-safe. ``path`` is scrubbed with the same needle set
    that produced the finding, which is not decoration: this corpus lives at
    ``/Volumes/<volume>/whetstone/corpus``, so the unscrubbed path of a leaking
    file *is itself* a volume needle, and a Leak that printed it would put the
    value back into the report that exists to keep it out.
    """

    #: One of :data:`KINDS`.
    kind: str
    #: The file it was found in, needle-scrubbed, or ``""`` for
    #: :func:`scan_text`, which is handed a string and no provenance.
    path: str
    #: 1-based line number, or ``0`` when there is no line context.
    line: int
    #: The JSON field it was found in — ``text``, ``ident``, a dotted path into
    #: a nested object, or ``raw`` for a file that is not JSONL.
    field: str
    #: ``len=<n>,sha256=<8 hex>`` of the text as it appears on disk. **Never the
    #: value.** A test asserts no field of a Leak can contain the needle.
    fingerprint: str


@dataclass(frozen=True, slots=True)
class Artifact:
    """One file a verification pass actually read."""

    #: Path relative to the surveyed directory, needle-scrubbed.
    name: str
    #: Where it really is, needle-scrubbed, after resolving every symlink.
    real: str
    size: int
    #: ``<device>:<inode>`` — identity without a value. Two artifacts with the
    #: same key are one artifact under two names.
    key: str
    is_symlink: bool
    #: False when the bytes are not decodable text, so the pass could not read
    #: them. Stated rather than skipped silently: a leak in a token shard is
    #: still in the weights, it is just not greppable from here.
    is_text: bool


@dataclass(frozen=True, slots=True)
class Survey:
    """What a verification pass read, and whether two names were one artifact.

    This exists because of ``clean-v8``. A verifier that reports leaks but not
    provenance lets "I verified v8" stand as a sentence when there is no v8 to
    verify, and that ambiguity is a finding in its own right — arguably a worse
    one than a leak, because it invalidates every other claim made about the
    generation.
    """

    given: str
    real: str
    #: The directory handed in was itself a symlink. Everything below is a
    #: statement about ``real``, and nothing is a statement about ``given`` as a
    #: distinct artifact, because there is none.
    directory_is_symlink: bool
    files: tuple[Artifact, ...]
    #: Groups of two or more names in this tree that share one inode.
    aliases: tuple[tuple[str, ...], ...]

    @property
    def text_bytes(self) -> int:
        return sum(a.size for a in self.files if a.is_text)


@dataclass(frozen=True, slots=True)
class Calibration:
    """Precision and recall against fixtures constructed before any corpus pass.

    Reported, not asserted in a docstring. An uncalibrated scanner over 625 MB
    of security text produces thousands of false positives and tells you
    nothing: this corpus contains ``192.0.2.0/24``, ``2001:db8::/32``,
    ``00:11:22:33:44:55`` and ``user@example.com`` **on purpose**, in RFCs,
    nuclei templates and YARA rules, and a verifier that counts those as leaks
    buries the 3,540 real ones. A tool with false positives gets switched off by
    the first person it annoys, and then it protects nothing.
    """

    positives: int
    positives_found: int
    negatives: int
    negatives_clean: int
    #: Fixture descriptions that were missed or wrongly flagged. Descriptions
    #: only — the fixtures are synthetic, but the habit of not printing matched
    #: text is the habit worth keeping.
    misses: tuple[str, ...]
    false_positives: tuple[str, ...]

    @property
    def recall(self) -> float:
        return self.positives_found / self.positives if self.positives else 0.0

    @property
    def precision(self) -> float:
        total = self.positives_found + len(self.false_positives)
        return self.positives_found / total if total else 0.0

    @property
    def clean(self) -> bool:
        return not self.misses and not self.false_positives

    def describe(self) -> str:
        return (f"calibration: recall {self.recall:.3f} "
                f"({self.positives_found}/{self.positives} constructed "
                f"positives), precision {self.precision:.3f} "
                f"({self.negatives_clean}/{self.negatives} constructed "
                f"negatives rejected)")


# --------------------------------------------------------------------------
# the needle table, and why it cannot be written down
# --------------------------------------------------------------------------

class _Lit:
    """One literal spelling of one needle.

    A slotted class with a redacting ``__repr__`` rather than a tuple or a
    dataclass, because both of those print their contents the moment anything
    puts them in an f-string, and "anything" includes a pytest assertion
    failure.
    """

    __slots__ = ("pattern", "kind", "rooted", "stem", "form")

    def __init__(self, form: str, pattern: str, kind: str, *, rooted: bool,
                 stem: str):
        self.form = form
        self.pattern = pattern
        self.kind = kind
        self.rooted = rooted
        self.stem = stem

    def __repr__(self) -> str:
        return f"<_Lit {self.kind} redacted>"

    __str__ = __repr__


def _guarded(form: str, guard: str) -> str:
    """A regex fragment for one literal, with the boundary class its kind needs.

    The guards are the difference between a usable verifier and a noisy one:

    ``num``
        ``10.11.12.13`` must not match inside ``210.11.12.139``, and must not
        match the version string ``3.0.11.2`` unless that *is* the address.
    ``mac``
        colon- and hyphen-separated MACs, kept off timestamps and off the
        middle of a longer hex-colon run.
    ``hex``
        the bare twelve-hex spelling of a MAC. Hex boundaries on both sides, so
        it cannot land inside a SHA-256. It *can* land inside a version-1 UUID —
        and it should: RFC 4122 v1 embeds the generating machine's MAC in the
        node field, so a UUID carrying this host's MAC is a true positive and
        one of the few leaks nobody looks for.
    ``v6``
        an IPv6 /64 prefix written without a host part. Open on the right only
        as far as a non-hex character, so the prefix of a full address is left
        to the structured pass rather than reported twice.
    ``mail``
        ``someone@example.com`` must not match inside
        ``not-someone@example.com``.
    ``none``
        names and paths, which leak precisely by appearing inside other strings
        and so take no boundary at all — the same choice ``_identity_table``
        makes, for the same reason.
    """
    body = re.escape(form)
    if guard == "num":
        return rf"(?<![\w.]){body}(?![\w.])"
    if guard == "mac":
        return rf"(?<![0-9A-Za-z:.\-]){body}(?![0-9A-Za-z:.\-])"
    if guard == "hex":
        return rf"(?<![0-9A-Fa-f]){body}(?![0-9A-Fa-f])"
    if guard == "v6":
        return rf"(?<![0-9A-Za-z:.]){body}(?![0-9A-Fa-f])"
    if guard == "mail":
        # The right guard rejects a following `.`+alphanumeric but allows a
        # bare `.`, which is the whole trade: `someone@example.invalid.evil`
        # is a different address and must not match, while "contact
        # someone@example.invalid." ends a sentence and must.
        return rf"(?<![\w.+\-]){body}(?![\w\-]|\.[A-Za-z0-9])"
    return body


class Needles:
    """Values that must not appear in a corpus. Derived from the OS at runtime.

    NEVER serialised, NEVER logged, NEVER written to disk. ``__repr__`` and
    ``__str__`` must not reveal a value -- a test asserts that, because the audit
    that found these leaks created a new one by writing its own needle table to a
    JSON file.

    **What it covers, and the part that was missing.** The identity table in
    ``training/trajectories.py`` covers four kinds — account name, display name,
    home path, host name, per-user temp dir — and states that boundary honestly
    in its docstring. The consequence, which the audit measured, is that the
    identifiers he *cannot change* were the ones *least* protected: three
    hardware MAC addresses in 1,770 documents, a current global IPv6 address
    3,540 times, its /64 prefix 10,620 times. A renamed account is an
    afternoon. A hardware MAC is the machine. So this class adds the network
    layer, the mounted volumes and the configured git identity on top of
    everything the substituter already knows about.

    **Soundness is checked, not hoped for.** Every literal is expanded from a
    *stem*, and the constructor asserts that each expanded spelling still
    contains its stem case-insensitively. That invariant is what lets the
    scanner reject a line in one cheap pass over ~40 stems instead of ~200
    spellings, and lets it do so without the possibility that an expansion
    escaped the prefilter — the failure mode where a scanner is fast and wrong
    and reports clean.

    **Case folding.** The substituter compiles with ``re.IGNORECASE`` (full
    Unicode) while ``identity_leaks`` uses a plain ``.lower()``, so they
    disagree in both directions and one trap codepoint (U+0130) makes
    ``redact_identity`` raise ``KeyError`` on text ``identity_leaks`` calls
    clean. This class matches with ``re.IGNORECASE`` *and* adds the explicit
    ``.casefold()`` spelling of any needle whose casefold differs from its lower
    — the one direction ``IGNORECASE`` does not reach, because Python's ``re``
    does not do multi-character folds. The union is strictly broader than
    either, which is the right asymmetry for a verifier: it may annoy, it may
    not miss.

    **What Python cannot do.** The values are in memory and the scanner reads
    them, so no attribute is unreachable from in-process code and this class
    does not pretend otherwise. What it guarantees is that every *accidental*
    path out — the one the audit actually took — raises or redacts: there is no
    ``__dict__``, ``repr`` and ``str`` and ``format`` reveal nothing, pickling
    raises, ``json.dumps`` raises, and there is no ``to_json``, no ``asdict``
    and no iteration that yields a raw string.
    """

    __slots__ = ("_lits", "_stem_rx", "_groups", "_anchors",
                 "_v6_anchors", "_v6_exact", "_v6_nets", "_v4_exact", "_macs",
                 "_probes", "_kinds")

    # The convenience constructors are module-level functions (`host_needles`)
    # and a classmethod (`from_values`); __init__ is private on purpose so a
    # caller cannot assemble one out of a list it read from a file.
    def __init__(self, _private: object = None, **_: object) -> None:
        raise TypeError(
            "Needles is built by host_needles() or Needles.from_values(), "
            "never by a caller holding a table. The point of this class is "
            "that no table of these values exists anywhere a file can be "
            "written from.")

    # -- construction -------------------------------------------------------

    @classmethod
    def _make(
        cls,
        *,
        lits: Sequence[_Lit],
        v6_exact: Iterable[ipaddress.IPv6Address],
        v6_nets: Iterable[ipaddress.IPv6Network],
        v4_exact: Iterable[ipaddress.IPv4Address],
        macs: Iterable[str],
        probes: Iterable[str],
    ) -> "Needles":
        self = object.__new__(cls)
        self._lits = tuple(lits)

        # One compiled pattern per STEM, not one over every spelling.
        #
        # This is the difference between a gate somebody runs and a gate
        # somebody disables. A single alternation over all ~320 spellings has
        # to try every branch at every character, and because many branches
        # open with a lookbehind the engine cannot build a first-character
        # prefilter to skip positions. Measured on trajectories.jsonl, where
        # almost every line does contain a needle and so the full pass always
        # runs: 50.9 MB in 458 s, 0.1 MB/s — over seven minutes for one file of
        # forty-seven. Grouping by stem and running only the groups whose
        # anchor is present in the line turns that into a handful of small
        # patterns per line.
        by_stem: dict[str, list[_Lit]] = {}
        for lit in self._lits:
            by_stem.setdefault(lit.stem.lower(), []).append(lit)
        self._groups = tuple(
            (anchor,
             re.compile("|".join(f"(?P<g{i}>{m.pattern})"
                                 for i, m in enumerate(members)),
                        re.IGNORECASE),
             tuple(members))
            for anchor, members in sorted(by_stem.items()))

        # The cheap first pass, and it is the SAME set as the group keys, by
        # construction rather than by two lists being kept in step. `str`
        # containment is a C substring search; a 300-branch `re` alternation
        # is not.
        self._anchors = tuple(anchor for anchor, _rx, _m in self._groups)
        if self._anchors:
            self._stem_rx = re.compile(
                "|".join(re.escape(a) for a in
                         sorted(self._anchors, key=lambda a: (-len(a), a))),
                re.IGNORECASE)
        else:
            self._stem_rx = None

        self._v6_exact = frozenset(v6_exact)
        self._v6_nets = tuple(dict.fromkeys(v6_nets))
        self._v6_anchors = tuple(sorted(
            _v6_anchor_set(self._v6_nets)
            | _v6_anchor_set(ipaddress.IPv6Network(f"{a}/64", strict=False)
                             for a in self._v6_exact)))
        self._v4_exact = frozenset(v4_exact)
        self._macs = frozenset(macs)
        self._probes = tuple(dict.fromkeys(probes))
        counts: dict[str, int] = {}
        for lit in self._lits:
            counts[lit.kind] = counts.get(lit.kind, 0) + 1
        self._kinds = counts

        # The invariant that makes the cheap prefilter sound, checked here at
        # construction because a prefilter that can miss a spelling is a
        # scanner that is fast and reports clean — and this codebase has
        # already paid for one instrument that could not tell "nothing there"
        # from "never looked".
        for lit in self._lits:
            if lit.stem.lower() not in lit.form.lower():
                raise AssertionError(
                    f"needle spelling of kind {lit.kind!r} does not contain "
                    "its own stem, so the cheap pass cannot see it")
        return self

    @classmethod
    def from_values(
        cls,
        *,
        identity: Iterable[str] = (),
        paths: Iterable[str] = (),
        email: Iterable[str] = (),
        ipv6: Iterable[str] = (),
        ipv4: Iterable[str] = (),
        mac: Iterable[str] = (),
        volumes: Iterable[str] = (),
        probes: Iterable[str] = ("from_values",),
        strict: bool = True,
    ) -> "Needles":
        """Build a table from values held in memory.

        Two legitimate callers. Tests, which must use fabricated values — a
        fixture pinned to one developer's real username tests that developer's
        machine and passes everywhere else by accident, and worse, it is the
        leak. And a human who knows a literal the OS cannot report: a machine
        renamed by hand, the display name of another local account, an old
        hostname that is still in last month's documents.

        ``strict`` applies the identifying floor and the generic-name set to
        ``identity`` and ``volumes``. Turn it off only in a test that needs a
        short synthetic needle, and understand what you are turning off: a
        three-character needle matches half the corpus.

        The argument is accepted **in memory**. Reading these values out of a
        file is how you get a file that has to be scrubbed; there is no reader
        here and there should not be one.
        """
        lits: list[_Lit] = []

        def add(form: str, kind: str, guard: str, *, rooted: bool,
                stem: str) -> None:
            if not form:
                return
            # The stem has to occur inside the spelling it anchors, or the
            # cheap first pass can reject a line the full pass would flag.
            # A transform that does not preserve its base — a casefold
            # expansion, a `\uXXXX` escape — becomes its own stem.
            if stem.lower() not in form.lower():
                stem = form
            lits.append(_Lit(form, _guarded(form, guard), kind, rooted=rooted,
                             stem=stem))

        def spellings(form: str) -> list[str]:
            """Every spelling of one literal that can reach a JSONL line.

            ``build()`` writes with ``json.dumps(..., ensure_ascii=False)``, so
            a backslash is doubled on disk and a non-ASCII character is not
            escaped — but another generation, another writer or a
            ``ensure_ascii=True`` default elsewhere escapes it, and the
            prefilter runs against the *raw* line. Both spellings go in, so a
            needle cannot hide behind the encoder.
            """
            out = [form]
            if "\\" in form:
                out.append(form.replace("\\", "\\\\"))
            if not form.isascii():
                out.append(json.dumps(form, ensure_ascii=True)[1:-1])
            if form.casefold() != form.lower():
                out.append(form.casefold())
            return list(dict.fromkeys(out))

        def add_name(value: str, kind: str, *, rooted: bool = False) -> None:
            """A bare name, plus the separator swaps tools apply to it.

            ``<identity>`` and ``<identity>`` are the same account to
            every cache-key builder and session-id generator on the machine, and
            only one of them is in ``_identity_table``.
            """
            value = value.strip()
            if not value or (strict and not _is_identifying(value)):
                return
            variants = {value}
            for a in _NAME_SEPARATORS:
                if a not in value:
                    continue
                for b in _NAME_SEPARATORS:
                    if a != b:
                        variants.add(value.replace(a, b))
            for variant in sorted(variants):
                if strict and not _is_identifying(variant):
                    continue
                for form in spellings(variant):
                    add(form, kind, "none", rooted=rooted, stem=variant)

        def add_path(value: str, kind: str) -> None:
            """A path, plus its separator-flattened spellings.

            The stem is the final component, so flattening the separators keeps
            the stem intact and the prefilter stays sound. A path whose last
            component is not identifying on its own — ``/var/folders/xy/<28
            chars>/T`` ends in ``T`` — is stemmed on its longest identifying
            component instead.
            """
            value = value.rstrip("/\\") or value
            parts = [p for p in re.split(r"[/\\]", value) if p]
            stem_parts = [p for p in parts if _is_identifying(p)]
            if not stem_parts:
                return
            stem = max(stem_parts, key=len)
            seen: set[str] = set()
            for sep in _SEPARATORS:
                flat = re.sub(r"[/\\]", lambda _m: sep, value)
                candidates = {flat}
                # The account name's own separator can be swapped at the same
                # time: `<identity>-Documents` is one string with two
                # transforms applied, and generating only one of them at a time
                # misses it.
                for a in _NAME_SEPARATORS:
                    for b in _NAME_SEPARATORS:
                        if a != b and a in stem:
                            candidates.add(flat.replace(stem,
                                                        stem.replace(a, b)))
                for cand in sorted(candidates):
                    for form in spellings(cand):
                        if form in seen or len(form) < _MIN_IDENTIFYING:
                            continue
                        seen.add(form)
                        cand_stem = stem
                        if cand_stem.casefold() not in form.casefold():
                            for a in _NAME_SEPARATORS:
                                for b in _NAME_SEPARATORS:
                                    alt = stem.replace(a, b)
                                    if (a != b and
                                            alt.casefold() in form.casefold()):
                                        cand_stem = alt
                            if cand_stem.casefold() not in form.casefold():
                                continue
                        add(form, kind, "none", rooted=True, stem=cand_stem)

        for value in identity:
            add_name(value, "identity")
        for value in paths:
            add_path(value, "identity")
        for value in volumes:
            if "/" in value or "\\" in value:
                add_path(value, "volume")
            else:
                add_name(value, "volume")
        for value in email:
            value = value.strip()
            if not value or "@" not in value:
                continue
            for form in spellings(value):
                add(form, "email", "mail", rooted=False, stem=value)

        v6_exact: list[ipaddress.IPv6Address] = []
        v6_nets: list[ipaddress.IPv6Network] = []
        for value in ipv6:
            value = value.strip().split("%")[0]
            if not value or value in _UNIVERSAL:
                continue
            try:
                addr = ipaddress.IPv6Address(value)
            except ValueError:
                continue
            v6_exact.append(addr)
            net = ipaddress.IPv6Network(f"{addr}/64", strict=False)
            v6_nets.append(net)
            # The prefix as a *literal*, for the spelling that carries no host
            # part at all. 10,620 of the audit's hits were the /64 prefix, and
            # a text that says "my prefix is 2001:db8:1:2" never parses as an
            # address, so the structured pass below cannot see it.
            prefix = str(net.network_address)
            if prefix.endswith("::"):
                bare = prefix[:-2]
                for form in {bare, bare.upper(), prefix, prefix.upper()}:
                    add(form, "ipv6-global", "v6", rooted=False, stem=bare)

        v4_exact: list[ipaddress.IPv4Address] = []
        for value in ipv4:
            value = value.strip()
            if not value or value in _UNIVERSAL:
                continue
            try:
                addr = ipaddress.IPv4Address(value)
            except ValueError:
                continue
            v4_exact.append(addr)
            # Matched as a guarded literal, not by shape. There are at most a
            # handful of bound addresses and exactly one spelling of each that
            # any tool emits, so scanning `\d+\.\d+\.\d+\.\d+` over a
            # corpus that is one-third RFCs and nuclei templates would
            # construct tens of millions of objects to answer what a literal
            # answers. `v4_exact` is kept for the count in `__len__`.
            add(str(addr), "ipv4-private", "num", rooted=False, stem=str(addr))

        macs: list[str] = []
        for value in mac:
            norm = _norm_mac(value)
            if not norm or value.strip().lower() in _UNIVERSAL:
                continue
            macs.append(norm)
            pairs = [norm[i:i + 2] for i in range(0, 12, 2)]
            for sep in (":", "-"):
                joined = sep.join(pairs)
                for form in (joined, joined.upper()):
                    add(form, "mac", "mac", rooted=False, stem=joined)
            quads = [norm[i:i + 4] for i in range(0, 12, 4)]
            for form in (".".join(quads), ".".join(quads).upper()):
                add(form, "mac", "mac", rooted=False, stem=":".join(pairs))
            for form in (norm, norm.upper()):
                add(form, "mac", "hex", rooted=False, stem=":".join(pairs))

        # Longest first. The alternation is matched leftmost-first by `re`, not
        # longest-first, so `/Users/alice` has to precede `alice` or the home
        # path is reported as a bare account name and the more serious finding
        # never surfaces. Same reasoning as `_identity_table`, same consequence
        # if it is dropped.
        return cls._make(lits=lits, v6_exact=v6_exact, v6_nets=v6_nets,
                         v4_exact=v4_exact, macs=macs, probes=probes)

    # -- the safe surface ---------------------------------------------------

    def __len__(self) -> int:
        return (len(self._lits) + len(self._v6_exact) + len(self._v6_nets)
                + len(self._v4_exact) + len(self._macs))

    def __bool__(self) -> bool:
        return len(self) > 0

    def __repr__(self) -> str:
        parts = ",".join(f"{k}={v}" for k, v in sorted(self._kinds.items()))
        return f"<Needles {len(self)} spellings [{parts or 'empty'}] redacted>"

    __str__ = __repr__

    def __format__(self, spec: str) -> str:
        # An f-string is the commonest way a value reaches a log line, and
        # `format` is the hook it goes through. It gets the same answer as
        # repr, whatever the spec asks for.
        return self.__repr__()

    def _hint(self, line: str) -> bool:
        """Could this line contain a needle? Cheap, and sound in the direction
        that matters: it may say yes wrongly, it must never say no wrongly.

        Three gates, cheapest first. A lowercase substring test per anchor; the
        IPv6 prefix anchors, which gate the structured pass; and — only for a
        line that is not pure ASCII — the stem alternation under
        ``re.IGNORECASE``, which reaches Unicode folds that ``str.lower`` does
        not (``re`` matches ``I`` against a dotless ``\u0131``; ``lower`` does
        not). Paying that regex only on non-ASCII lines is what keeps it
        affordable.
        """
        low = line.lower()
        for anchor in self._anchors:
            if anchor in low:
                return True
        for anchor in self._v6_anchors:
            if anchor in low:
                return True
        if not line.isascii() and self._stem_rx is not None:
            return self._stem_rx.search(line) is not None
        return False

    def kinds(self) -> dict[str, int]:
        """Spellings per kind. Counts, never values."""
        return dict(sorted(self._kinds.items()))

    def probes(self) -> tuple[str, ...]:
        """Which OS probes contributed. A missing probe is the fail-open."""
        return self._probes

    def fingerprints(self) -> tuple[str, ...]:
        """One fingerprint per distinct needle root, for correlating a report
        against a live table without either of them holding a value."""
        roots = {lit.stem for lit in self._lits}
        roots.update(str(a) for a in self._v6_exact)
        roots.update(str(a) for a in self._v4_exact)
        roots.update(self._macs)
        return tuple(sorted(_fingerprint(r) for r in roots))

    def gaps(self) -> tuple[str, ...]:
        """Probes that should have produced something on this platform and did
        not.

        This is the fail-open check turned on the instrument itself.
        ``redact_identity`` returns text unchanged when its table is empty;
        a verifier with an empty table returns "clean". The two failures are the
        same failure, and the only defence is to notice that the table is thin
        and say so instead of printing a reassuring number.
        """
        missing = []
        if not self._v6_exact and not self._v4_exact:
            missing.append("network")
        if not self._macs:
            missing.append("mac")
        if "account" not in self._probes:
            missing.append("account")
        if "hostname" not in self._probes:
            missing.append("hostname")
        if platform.system() == "Darwin" and "volumes" not in self._probes:
            missing.append("volumes")
        return tuple(missing)

    # -- every accidental way out, closed ----------------------------------

    def _refuse(self, *_: object, **__: object) -> Any:
        raise TypeError(
            "a Needles table must not be serialised. The audit that found "
            "these leaks wrote its own needle table to a JSON file and became "
            "the leak; derive the table at runtime instead.")

    __reduce__ = _refuse
    __reduce_ex__ = _refuse
    __getstate__ = _refuse
    __deepcopy__ = _refuse
    __copy__ = _refuse

    def __eq__(self, other: object) -> bool:
        # Identity comparison only. A value-wise __eq__ is a probe: it would let
        # a caller binary-search the table by constructing candidates.
        return self is other

    def __hash__(self) -> int:
        return object.__hash__(self)


def _v6_anchor_set(nets: Iterable[ipaddress.IPv6Network]) -> set[str]:
    """Lowercase substrings that every spelling of an address in ``nets`` must
    contain, so the structured IPv6 pass can be gated cheaply.

    An IPv6 literal always writes its first hextet. It also always writes its
    second — *unless* the second is zero, because ``::`` replaces exactly one
    run of zero groups and a run that starts at the second group swallows it.
    So two hextets when the second is non-zero, one when it is, each with and
    without its leading zeros. That is sound for every spelling, compressed,
    exploded or mixed, which matters: gating on the compressed spelling alone
    is how a scanner misses the same address written by a different tool.
    """
    anchors: set[str] = set()
    for net in nets:
        groups = net.network_address.exploded.split(":")
        first, second = groups[0], groups[1]

        def forms(group: str) -> set[str]:
            return {group, group.lstrip("0") or "0"}

        if second == "0000":
            anchors |= {f"{a}:" for a in forms(first)}
        else:
            anchors |= {f"{a}:{b}:" for a in forms(first)
                        for b in forms(second)}
    return {a.lower() for a in anchors}


def _norm_mac(value: str) -> str:
    """Twelve lowercase hex characters, or ``""``."""
    raw = re.sub(r"[^0-9A-Fa-f]", "", value or "")
    if len(raw) != 12:
        return ""
    return raw.lower()


# --------------------------------------------------------------------------
# reading the machine
# --------------------------------------------------------------------------

def _run(argv: Sequence[str], timeout: float = 10.0) -> str:
    """One command, no shell, absolute path, short deadline, never raises.

    ``_identity_table`` deliberately builds without running a command, and that
    is right for it: it runs inside a forty-minute generation loop where a
    blocking subprocess is a wedged build. This module is the opposite case — a
    gate and a CLI, run once, where the only way to learn an interface's MAC or
    a bound global IPv6 address from the standard library is to ask the
    operating system. That asymmetry is exactly why the network layer was
    missing from the substituter, and refusing to shell out here would reproduce
    the gap rather than close it.
    """
    try:
        proc = subprocess.run(list(argv), capture_output=True, text=True,
                              timeout=timeout, check=False,
                              stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return ""
    return proc.stdout or ""


def _network_values() -> tuple[list[str], list[str], list[str]]:
    """``(ipv6, ipv4-private, mac)`` for this host, from the OS.

    Returns the *interesting* ones only: loopback, link-local, unspecified and
    multicast addresses identify every machine ever made, and the audit's own
    first pass reported ``::1`` and ``fe80::1`` as leaks before it learned that.
    Unique-local IPv6 (``fc00::/7``) is kept under the ``ipv6-global`` label
    because its disclosure risk is identical — it is a stable per-host
    identifier, whatever the routing table thinks of it.
    """
    text = ""
    for exe in ("/sbin/ifconfig", "/usr/sbin/ifconfig", "/bin/ip", "/sbin/ip",
                "/usr/sbin/ip"):
        if not os.path.exists(exe):
            continue
        text = (_run([exe, "-a"]) if exe.endswith("ifconfig")
                else _run([exe, "-o", "addr"]) + _run([exe, "-o", "link"]))
        if text.strip():
            break

    v6: list[str] = []
    v4: list[str] = []
    macs: list[str] = []

    for token in re.findall(r"(?:ether|lladdr|link/ether)\s+"
                            r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", text):
        norm = _norm_mac(token)
        if norm and token.lower() not in _UNIVERSAL:
            macs.append(norm)

    for token in re.findall(r"inet6\s+([0-9A-Fa-f:]+)", text):
        try:
            addr = ipaddress.IPv6Address(token.split("%")[0])
        except ValueError:
            continue
        if (addr.is_loopback or addr.is_link_local or addr.is_multicast
                or addr.is_unspecified or addr.is_reserved):
            continue
        v6.append(str(addr))

    for token in re.findall(r"inet\s+([0-9.]+)", text):
        try:
            addr = ipaddress.IPv4Address(token)
        except ValueError:
            continue
        if (addr.is_loopback or addr.is_unspecified or addr.is_multicast
                or addr.is_link_local):
            continue
        v4.append(str(addr))

    if not v6 and not v4:
        # Last resort, and a weak one: getaddrinfo answers with whatever the
        # resolver thinks this host's name maps to, which on a laptop is often
        # nothing. Recorded as a separate probe so `gaps()` can still say the
        # network layer is thin.
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None):
                host = info[4][0]
                try:
                    addr = ipaddress.ip_address(host.split("%")[0])
                except ValueError:
                    continue
                if (addr.is_loopback or addr.is_link_local
                        or addr.is_unspecified):
                    continue
                (v6 if addr.version == 6 else v4).append(str(addr))
        except OSError:
            pass

    return (sorted(set(v6)), sorted(set(v4)), sorted(set(macs)))


def _volume_names() -> list[str]:
    """Mounted volumes, by name.

    ``<volume>`` is in 1,776 documents of the shipped corpus, inside
    an installed-application inventory of this machine. A volume name is a
    weaker identifier than a MAC and a much stronger one than it looks: it names
    a disk somebody chose a name for, and the choice is personal.

    Symlinks are skipped — ``/Volumes/Macintosh HD`` is a symlink to ``/`` on
    every Mac — and ``os.scandir`` is used rather than a glob so a dangling
    mount point cannot raise.
    """
    roots = ["/Volumes"]
    user = ""
    try:
        import getpass

        user = getpass.getuser()
    except Exception:  # pragma: no cover - getpass raises only with no passwd
        user = ""
    roots += ["/media", "/mnt", f"/media/{user}", f"/run/media/{user}"]
    names: list[str] = []
    for root in roots:
        try:
            with os.scandir(root) as it:
                for entry in it:
                    if entry.is_symlink():
                        continue
                    if _is_identifying(entry.name):
                        names.append(entry.path)
                        names.append(entry.name)
        except OSError:
            continue
    return sorted(set(names))


def _git_identities(extra_repos: Iterable[Path] = ()) -> tuple[list[str],
                                                               list[str]]:
    """``(names, emails)`` from the git configs this account actually uses.

    Read as files rather than through ``git config --list`` so this works with
    no git installed, and so it cannot be made to execute a config-supplied
    command. The repo-local configs are the ones that matter here: a project
    overriding ``user.email`` per repository is normal, and his own corpus
    adapter walks his own repositories.
    """
    paths: list[Path] = []
    env = os.environ.get("GIT_CONFIG_GLOBAL")
    if env:
        paths.append(Path(env))
    home = Path.home()
    paths += [home / ".gitconfig", home / ".config" / "git" / "config"]
    here = Path(__file__).resolve()
    for parent in [here, *here.parents]:
        cfg = parent / ".git" / "config"
        if cfg.is_file():
            paths.append(cfg)
            break
    for repo in extra_repos:
        paths.append(Path(repo) / ".git" / "config")

    names: list[str] = []
    emails: list[str] = []
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        section = ""
        for line in text.splitlines():
            head = _GIT_SECTION.match(line)
            if head:
                section = head.group(1).strip().lower()
                continue
            if section != "user":
                continue
            entry = _GIT_ENTRY.match(line)
            if not entry:
                continue
            key, value = entry.group(1).lower(), entry.group(2).strip()
            if not value:
                continue
            (emails if key == "email" else names).append(value)
    return (sorted(set(names)), sorted(set(emails)))


def host_needles(*, extra_repos: Iterable[Path] = ()) -> Needles:
    """The needle table for this machine, read fresh from the OS.

    No cache. ``_identity_table`` is ``lru_cache``'d and the audit found that
    bites: the table is assembled partly from best-effort filesystem reads, so
    it can be *silently thinner* in one process than another — a build whose
    ``TMPDIR`` points at the external volume gets seven entries, the same build
    with ``os.stat`` refusing on ``/var/folders`` gets five, and nothing says
    which one ran. A gate that is cheap to run has no excuse to memoise its own
    ground truth.

    ``_identity_table()`` is folded in when ``training.trajectories`` imports,
    so this table is a superset of the substituter's by construction rather than
    by coincidence. When the import fails — a container with no runtime, a
    gate running from a wheel — the OS-derived layer below stands on its own and
    ``probes()`` says ``identity-table`` is absent.
    """
    probes: list[str] = []
    identity: list[str] = []
    paths: list[str] = []

    try:
        import getpass

        user = getpass.getuser()
    except Exception:
        user = ""
    if user:
        identity.append(user)
        probes.append("account")

    try:
        import pwd

        gecos = pwd.getpwuid(os.getuid()).pw_gecos.split(",")[0].strip()
        if gecos:
            identity.append(gecos)
            probes.append("gecos")
    except Exception:
        pass

    try:
        home = Path.home()
        paths.append(str(home))
        probes.append("home")
    except Exception:
        pass

    hosts = {socket.gethostname(), platform.node()}
    for name in sorted(h for h in hosts if h):
        identity.append(name)
        short = name.partition(".")[0]
        if short != name:
            identity.append(short)
        probes.append("hostname")

    # Every per-user temp directory this account owns, not only the one TMPDIR
    # names right now. Pointing the build's scratch at the external volume drops
    # the /var/folders path straight out of a table keyed on the environment,
    # while every document captured before the move still carries it — that is
    # how a real `/var/folders/<x>/<hash>/T` reached a built corpus seven times
    # in one document while the build reported zero leaks.
    temps = {tempfile.gettempdir()}
    for candidate in glob.glob("/var/folders/*/*/T"):
        try:
            if os.stat(candidate).st_uid == os.getuid():
                temps.add(candidate)
        except OSError:
            continue
    generic = "C:\\Temp" if os.name == "nt" else "/tmp"
    for tmp in sorted(t for t in temps if t and t != generic):
        paths.append(tmp)
        try:
            resolved = str(Path(tmp).resolve())
        except OSError:
            resolved = tmp
        if resolved != tmp:
            paths.append(resolved)
        probes.append("tmpdir")

    v6, v4, macs = _network_values()
    if v6 or v4:
        probes.append("network")
    if macs:
        probes.append("mac")

    volumes = _volume_names()
    if volumes:
        probes.append("volumes")

    names, emails = _git_identities(extra_repos)
    identity.extend(names)
    if names or emails:
        probes.append("gitconfig")

    try:
        from training.trajectories import _identity_table

        for form, _repl in _identity_table():
            if "/" in form or "\\" in form:
                paths.append(form)
            else:
                identity.append(form)
        probes.append("identity-table")
    except Exception:
        pass

    return Needles.from_values(
        identity=identity, paths=paths, email=emails, ipv6=v6, ipv4=v4,
        mac=macs, volumes=volumes, probes=probes)


# --------------------------------------------------------------------------
# the scan
# --------------------------------------------------------------------------

def _v6_hits(text: str, needles: Needles) -> list[tuple[int, int, str]]:
    """``(start, end, matched)`` for every IPv6 needle occurrence.

    Structured, not substring. The audit's first pass compared addresses with
    ``str.count()`` and got inflated counts and missed spellings in the same
    run; the fix was to let :mod:`ipaddress` canonicalise both sides, and that
    is where the single worst finding came from. ``2001:db8:1:2::5``,
    ``2001:0db8:0001:0002:0000:0000:0000:0005`` and
    ``2001:DB8:1:2:0:0:0:5`` are one address, and only a parser knows that.

    The cheap gate before the parser is what keeps it affordable over 625 MB:
    a real IPv6 literal either contains ``::`` or has exactly seven colons, and
    a bare ``/64`` prefix has exactly three. That rejects every MAC (five
    colons, no ``::``) and every timestamp (two) without constructing an object.
    """
    if not needles._v6_exact and not needles._v6_nets:
        return []
    out: list[tuple[int, int, str]] = []
    for m in _V6_CAND.finditer(text):
        raw = m.group(0)
        body = raw.split("%")[0]
        colons = body.count(":")
        compressed = "::" in body
        if compressed or colons == 7:
            candidate = body
        elif colons == 3:
            # A /64 prefix written with no host part at all.
            candidate = body + "::"
        else:
            continue
        try:
            addr = ipaddress.IPv6Address(candidate)
        except ValueError:
            continue
        if addr in needles._v6_exact or any(addr in net
                                            for net in needles._v6_nets):
            out.append((m.start(), m.start() + len(body), body))
    return out


def _spans(value: str, needles: Needles
           ) -> list[tuple[int, int, str, str, bool]]:
    """``(start, end, kind, matched, rooted)``, sorted, non-overlapping.

    The one detector. Both the scanner and the report-scrubber go through here,
    so a value that would be reported cannot also be printed, and the two can
    never drift apart — which is the failure the whole module exists to answer:
    ``_identity_pattern`` substitutes with ``re.IGNORECASE`` while
    ``identity_leaks`` verifies with ``str.lower`` and they disagree in both
    directions about the same bytes.

    **Longest wins at each position, by explicit interval selection rather than
    by alternation order.** ``_identity_table`` has to sort itself longest-first
    because ``re`` matches a branch leftmost-first, and if it ever stopped
    sorting, ``/Users/alice`` would be half-substituted by the ``alice`` rule.
    Here the groups are separate patterns and that ordering trick is not
    available, so the span list is sorted by ``(start, -length)`` and walked
    with a cursor. The result is the same and it does not depend on a sort
    somewhere else staying correct: a home path is reported once, as a home
    path, not twice as a path and a bare account name.
    """
    low = value.lower()
    hits: list[tuple[int, int, str, str, bool]] = []

    for anchor in needles._v6_anchors:
        if anchor in low:
            for start, end, matched in _v6_hits(value, needles):
                hits.append((start, end, "ipv6-global", matched, False))
            break

    groups = [g for g in needles._groups if g[0] in low]
    if (not value.isascii() and needles._stem_rx is not None
            and needles._stem_rx.search(value)):
        # A Unicode fold `str.lower` does not reach — `re.IGNORECASE` matches
        # `I` against a dotless `\u0131` and `lower` does not. The whole group
        # set is run rather than carrying a second index for a case this rare,
        # and it is a UNION with the anchor-selected groups, not a fallback: a
        # line can carry one needle the anchors see and another they do not.
        groups = list(needles._groups)
    for _anchor, rx, members in groups:
        for m in rx.finditer(value):
            lit = members[int((m.lastgroup or "g0")[1:])]
            hits.append((m.start(), m.end(), lit.kind, m.group(0), lit.rooted))

    hits.sort(key=lambda h: (h[0], -(h[1] - h[0])))
    kept: list[tuple[int, int, str, str, bool]] = []
    cursor = -1
    for hit in hits:
        if hit[0] < cursor:
            continue
        kept.append(hit)
        cursor = hit[1]
    return kept


def _scan_value(value: str, needles: Needles, field: str
                ) -> list[tuple[str, str]]:
    """``(kind, matched)`` pairs for one string."""
    out: list[tuple[str, str]] = []
    in_ident = field.split(".")[-1] == "ident"
    for _s, _e, kind, matched, rooted in _spans(value, needles):
        # `ident` is the finding that needs its own bucket. `_redacted` redacts
        # `doc.text` only; `doc.ident` goes to disk untouched at build.py:716
        # and several adapters build it from a filesystem path. The leaked
        # value is the same value, the fix is a different fix, so the report
        # must not merge them.
        if in_ident and rooted:
            kind = "ident-path"
        out.append((kind, matched))
    return out


def _redact_for_report(text: str, needles: Needles) -> str:
    """A string safe to put in a report, with every needle span replaced by its
    kind.

    Used on file paths and on JSON field names, because this corpus lives under
    a volume whose name is a needle, in a tree under a home directory whose name
    is a needle. A Leak that printed its own unscrubbed path would put back
    exactly what the fingerprint was for — and that is not a hypothetical: the
    audit's own working files leaked by naming the files they had found leaks
    in.
    """
    spans = _spans(text, needles)
    if not spans:
        return text
    out: list[str] = []
    cursor = 0
    for start, end, kind, _matched, _rooted in spans:
        out.append(text[cursor:start])
        out.append(f"<{kind}>")
        cursor = end
    out.append(text[cursor:])
    return "".join(out)


def scan_text(text: str, *, needles: Needles, field: str = "text"
              ) -> list[Leak]:
    """Every needle in one string.

    ``path`` is ``""`` and ``line`` is ``0``: this function is handed a string
    and no provenance, and inventing either would be a lie in a report.
    :func:`scan_file` fills both.
    """
    return [Leak(kind=kind, path="", line=0, field=field,
                 fingerprint=_fingerprint(matched))
            for kind, matched in _scan_value(text, needles, field)]


def _walk_fields(obj: Any, prefix: str = "") -> Iterator[tuple[str, str]]:
    """Every string in a decoded JSON row, with a dotted field name.

    Every string, not ``text`` and ``ident``. A verifier that knows which fields
    matter is a verifier that stops working the first time a source adds one,
    and `_redacted`'s whole failure was that it knew about exactly one field.
    """
    if isinstance(obj, str):
        yield (prefix or "raw", obj)
    elif isinstance(obj, dict):
        for key, value in obj.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            yield from _walk_fields(value, name)
    elif isinstance(obj, (list, tuple)):
        for index, value in enumerate(obj):
            name = f"{prefix}[{index}]" if prefix else f"[{index}]"
            yield from _walk_fields(value, name)


def scan_file(path: str | os.PathLike[str], *, needles: Needles
              ) -> list[Leak]:
    """Stream one file and report every needle in it, with line numbers.

    **Streamed, never loaded.** 625 MB across 47 files, and a gate that reads a
    50 MB JSONL into a list is a gate that gets run once.

    **Two-stage, and the stages are provably consistent.** Stage one searches
    the *raw* line for any needle stem — roughly forty of them — and for the
    structured IPv6 shapes. Most lines fail it and are never JSON-decoded, which
    is the whole performance story: ``json.loads`` on every line of this corpus
    costs more than the scan does. Stage two decodes the line and scans every
    string field properly. The constructor's stem invariant is what makes stage
    one sound: no spelling of any needle exists that does not contain its stem,
    so a line stage one rejects cannot contain a needle stage two would find.

    A file that is not JSONL — ``PROVENANCE.md`` sits in every generation — is
    scanned line by line as raw text under the field name ``raw``. Nothing is
    skipped for not matching a glob, because ``read_documents()`` globbing
    ``*.jsonl`` is one of the reasons this module exists.
    """
    p = Path(path)
    safe = _redact_for_report(str(p), needles)
    leaks: list[Leak] = []
    is_jsonl = p.suffix == ".jsonl"
    try:
        handle = p.open("r", encoding="utf-8", errors="replace")
    except OSError as exc:
        # NOT `return leaks`. An unopenable file reporting zero leaks is a
        # fail-open that reads identically to a clean file, and it is exactly
        # what made the scrubbed-path bug invisible.
        return [Leak(kind="unreadable", path=safe, line=0, field="",
                     fingerprint=f"errno={getattr(exc, 'errno', 0)}")]
    with handle as fh:
        for number, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            if not needles._hint(line):
                continue
            row: Any = None
            if is_jsonl:
                try:
                    row = json.loads(line)
                except (ValueError, UnicodeDecodeError):
                    row = None
            if row is None:
                fields = [("raw", line.rstrip("\n"))]
            else:
                fields = list(_walk_fields(row))
            for field, value in fields:
                safe_field = _redact_for_report(field, needles)
                for kind, matched in _scan_value(value, needles, field):
                    leaks.append(Leak(kind=kind, path=safe, line=number,
                                      field=safe_field,
                                      fingerprint=_fingerprint(matched)))
    return leaks


def _walk_artifacts(root: Path, needles: Needles
                    ) -> Iterator[tuple[Path, Artifact]]:
    """Yield ``(real path, report-safe Artifact)`` for every file under ``root``.

    **One walk, two consumers, and that is the entire point of this function.**
    :func:`survey` needs the ``Artifact`` — scrubbed, because a path under this
    corpus *is itself* a volume needle, as :class:`Leak` explains. But
    :func:`verify_corpus` needs the **real** path, because it has to open the
    file.

    Keeping both on one yield is the structural fix for the worst bug this
    module has had. ``verify_corpus`` used to read ``Artifact.real`` — the
    *scrubbed display string* — so against the live corpus at
    ``/Volumes/<volume>/whetstone/corpus`` the scrubbed path named no file at
    all, ``scan_file`` swallowed the ``OSError``, and the pass reported
    **"0 leaks." and exit 0 having read nothing**, while a direct ``scan_file``
    of one of those files found 23,034. The tell was in the report the whole
    time: it claimed 625.3 MB in 0.0s — 128,000 MB/s, which no storage on earth
    does.

    The real ``Path`` is deliberately **not** a field on ``Artifact``. Artifact
    is rendered into reports, and a dataclass that carries an unscrubbed path is
    one ``repr`` away from putting the value back into the document that exists
    to keep it out.
    """
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            full = Path(dirpath) / name
            try:
                st = full.stat()
            except OSError:
                continue
            rel = str(full.relative_to(root))
            try:
                with full.open("rb") as probe:
                    is_text = b"\x00" not in probe.read(4096)
            except OSError:
                is_text = False
            yield full, Artifact(
                name=_redact_for_report(rel, needles),
                real=_redact_for_report(str(full.resolve()), needles),
                size=st.st_size, key=f"{st.st_dev}:{st.st_ino}",
                is_symlink=full.is_symlink(), is_text=is_text)


def survey(directory: str | os.PathLike[str], *,
           needles: Needles | None = None) -> Survey:
    """What is really in a corpus directory, and whether two names are one
    artifact.

    ``os.walk(followlinks=False)``, never ``rglob``. The precedent is on the
    record: ``ownrepos`` once followed this repo's ``data`` symlink into the SSD
    and pulled the corpus cache back in as PROSE — the corpus ate itself, and
    only the balance report caught it. A verifier that walked into a symlink
    would scan the same bytes twice and report a doubled count as a doubled
    leak.

    The *named* directory is a different matter and is resolved deliberately,
    because that is the ``clean-v8`` case: it is a symlink to ``clean-v7``, so a
    pass over it is a pass over v7's bytes and the only honest thing a tool can
    do is say so.
    """
    needles = host_needles() if needles is None else needles
    root = Path(directory)
    files: list[Artifact] = []
    by_key: dict[str, list[str]] = {}
    for full, art in _walk_artifacts(root, needles):
        files.append(art)
        by_key.setdefault(art.key, []).append(art.name)
    aliases = tuple(tuple(sorted(names)) for names in by_key.values()
                    if len(names) > 1)
    return Survey(
        given=_redact_for_report(str(root), needles),
        real=_redact_for_report(str(root.resolve()), needles),
        directory_is_symlink=root.is_symlink(),
        files=tuple(files), aliases=aliases)


def verify_corpus(directory: str | os.PathLike[str], *,
                  needles: Needles | None = None) -> list[Leak]:
    """Every needle in every readable file under ``directory``.

    **Returns leaks. Does not raise.** The caller decides what a leak means,
    which is what lets the build gate, the CLI below and a test share one
    scanner instead of growing three that disagree — the way
    ``_identity_pattern`` and ``identity_leaks`` disagree today about the same
    bytes.

    An empty needle table returns ``[]``, and ``[]`` from an empty table means
    *nothing was looked for*. Callers must check ``needles.gaps()``;
    :func:`main` exits 2 rather than 0 for exactly this case.
    """
    needles = host_needles() if needles is None else needles
    leaks: list[Leak] = []
    read = 0
    for full, art in _walk_artifacts(Path(directory), needles):
        if not art.is_text:
            # ``is_text=False`` conflates two different facts: the bytes are
            # binary, or the file could not be opened at all. Skipping both
            # silently is a third fail-open of the same family as the two this
            # function already had -- a chmod-000 JSONL would verify clean.
            # Binary is a stated limit (the Survey counts it, and a leak in a
            # token shard is still in the weights, just not greppable here);
            # unopenable is a finding.
            try:
                with full.open("rb"):
                    pass
            except OSError as exc:
                leaks.append(Leak(
                    kind="unreadable", path=art.name, line=0, field="",
                    fingerprint=f"errno={getattr(exc, 'errno', 0)}"))
            continue
        leaks.extend(scan_file(full, needles=needles))
        read += art.size
    # Bytes this pass actually opened, not bytes that merely exist on disk.
    # The report used to sum stat() sizes, so it printed "625.3 MB scanned"
    # for a pass that opened no files at all. A caller that wants the honest
    # figure reads it here.
    verify_corpus.last_bytes_read = read  # type: ignore[attr-defined]
    return leaks


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------

def render(leaks: list[Leak]) -> str:
    """A human summary. Fingerprints only, by construction — a Leak has no
    field that can hold a value."""
    if not leaks:
        return "0 leaks."
    groups: dict[tuple[str, str, str, str], list[int]] = {}
    for leak in leaks:
        key = (leak.kind, leak.path, leak.field, leak.fingerprint)
        groups.setdefault(key, []).append(leak.line)

    distinct = len({k[3] for k in groups})
    files = len({k[1] for k in groups})
    out = [f"{len(leaks):,} occurrence(s) of {distinct} distinct value(s) "
           f"across {len(groups)} group(s) in {files} file(s).", ""]
    width = max(len(k[0]) for k in groups)
    for key in sorted(groups, key=lambda k: (-len(groups[k]), k)):
        kind, path, field, fp = key
        lines = sorted(groups[key])
        head = ", ".join(str(n) for n in lines[:4])
        more = f", +{len(lines) - 4} more" if len(lines) > 4 else ""
        name = Path(path).name or path or "<string>"
        out.append(f"  {kind:<{width}}  {name}  {field}  {fp}  "
                   f"{len(lines):,} line(s) [{head}{more}]")

    kinds = {k[0] for k in groups}
    if "ipv4-private" in kinds:
        out += ["", "NOTE: ipv4-private is ambiguous by construction. An "
                "RFC1918 address bound on this host is also a documentation "
                "example in RFC, nuclei and Sigma text, and the two are the "
                "same bytes. Treat these as a prompt to look, not as a leak, "
                "and gate on the kinds that actually identify a machine."]
    if "ident-path" in kinds:
        out += ["", "NOTE: ident-path means the leak is in a document's "
                "`ident`, not its text. `_redacted` covers `doc.text` only, so "
                "no amount of re-running the text redactor fixes these."]
    return "\n".join(out)


def render_survey(info: Survey) -> str:
    """What was read, stated plainly, including when two names are one file."""
    out = [f"read: {info.given}"]
    if info.directory_is_symlink:
        out.append(
            f"  ! {info.given} IS A SYMLINK to {info.real}. Everything below "
            f"describes {info.real}'s bytes. There is no separate artifact at "
            f"the name you gave, so a claim that it was verified is a claim "
            f"about the target — this is the clean-v8 case.")
    readable = sum(1 for a in info.files if a.is_text)
    out.append(f"  {len(info.files)} file(s), {readable} readable as text, "
               f"{info.text_bytes / 1e6:,.1f} MB scanned")
    opaque = [a.name for a in info.files if not a.is_text]
    if opaque:
        out.append(f"  {len(opaque)} file(s) are not decodable text and were "
                   f"NOT scanned: {', '.join(opaque[:6])}"
                   f"{' …' if len(opaque) > 6 else ''}. A leak in a token "
                   f"shard is still in the weights; it is just not greppable "
                   f"from here.")
    for group in info.aliases:
        out.append(f"  ! one artifact under {len(group)} names: "
                   f"{', '.join(group)}")
    links = [a.name for a in info.files if a.is_symlink]
    if links:
        out.append(f"  ! {len(links)} symlinked file(s): {', '.join(links[:6])}")
    return "\n".join(out)


# --------------------------------------------------------------------------
# proving it bites
# --------------------------------------------------------------------------

#: Fixtures. Every value here is fabricated: RFC 5737 / RFC 3849 documentation
#: addresses, RFC 7042 documentation MACs, `.invalid` and `.example` domains.
#: The *negatives* are drawn from what this corpus genuinely contains on
#: purpose, which is the only way a precision number means anything.
_CAL_NEEDLES = dict(
    # `strau\u00df-operator` is here for one reason: its casefold is
    # `strauss-operator` and its lower is not, which is the single direction
    # `re.IGNORECASE` cannot reach because Python's `re` does no multi-character
    # folding. Without the explicit casefold spelling in `spellings()` the
    # positive below is missed, and a mutation run proves it.
    identity=["synthetic-operator", "strau\u00df-operator"],
    paths=["/Users/synthetic-operator", "/var/folders/zz/abcd1234efgh5678/T"],
    email=["someone@example.invalid"],
    # 2001:db8::/32 is documentation space and so is every negative below, which
    # is deliberate: the needle sits in 2001:db8:1:2::/64 and the negatives sit
    # in other /64s of the same /32, so a detector that matched on the /32 — the
    # obvious and wrong simplification — fails this set.
    ipv6=["2001:db8:1:2::5",
          # A second address whose SECOND hextet is zero, which is the case
          # that decides how short the IPv6 prefilter anchor may be: `::` can
          # swallow a zero run starting at the second group, so
          # `fd12::3456:0:0:0:9` and `fd12:0:0:3456::9` are one address and
          # only a one-hextet anchor sees both. Without this needle the
          # anchor rule looks over-cautious; with it, tightening the rule
          # fails calibration.
          "fd12:0:0:3456::9"],
    ipv4=["10.11.12.13"],
    mac=["00:00:5e:00:53:01"],
    volumes=["/Volumes/synthetic-disk", "synthetic-disk"],
)

_CAL_POSITIVES: tuple[tuple[str, str, str], ...] = (
    ("account name bare", "identity", "logged in as synthetic-operator"),
    ("account name upper", "identity", "USER=SYNTHETIC-OPERATOR"),
    ("account separator swap", "identity", "key=synthetic_operator.log"),
    ("home path posix", "identity", "cache at /Users/synthetic-operator/Library"),
    ("tmpdir flattened", "identity",
     "key=-var-folders-zz-abcd1234efgh5678-T-world"),
    ("tmpdir dotted", "identity", "key=.var.folders.zz.abcd1234efgh5678.T"),
    ("tmpdir url-encoded", "identity",
     "log%2Fvar%2Ffolders%2Fzz%2Fabcd1234efgh5678%2FT"),
    ("per-user tmpdir", "identity",
     "wrote /var/folders/zz/abcd1234efgh5678/T/world"),
    ("email", "email", "contact someone@example.invalid for access"),
    ("email cased", "email", "Someone@Example.Invalid"),
    ("ipv6 compressed", "ipv6-global", "bound 2001:db8:1:2::5 on en0"),
    ("ipv6 exploded", "ipv6-global",
     "peer 2001:0db8:0001:0002:0000:0000:0000:0005"),
    ("ipv6 upper", "ipv6-global", "2001:DB8:1:2:0:0:0:5 reachable"),
    ("ipv6 other host same /64", "ipv6-global", "neighbour 2001:db8:1:2::dead"),
    ("ipv6 /64 prefix bare", "ipv6-global", "delegated prefix 2001:db8:1:2"),
    ("ipv6 /64 prefix written", "ipv6-global", "route 2001:db8:1:2::/64"),
    ("ipv4 private bound", "ipv4-private", "inet 10.11.12.13 netmask 0xffffff00"),
    ("mac colon", "mac", "ether 00:00:5e:00:53:01"),
    ("mac colon upper", "mac", "ETHER 00:00:5E:00:53:01"),
    ("mac hyphen", "mac", "00-00-5E-00-53-01"),
    ("mac bare hex", "mac", "node=00005e005301"),
    ("mac inside uuid v1", "mac", "uuid 7d444840-9dc0-11d1-b245-00005e005301"),
    ("volume path", "volume", "cache on /Volumes/synthetic-disk/corpus"),
    ("volume name", "volume", "mounted synthetic-disk read-only"),
    ("email sentence final", "email", "write to someone@example.invalid."),
    ("email in angle brackets", "email", "From: <someone@example.invalid>"),
    ("email in mailto url", "email", "mailto:someone@example.invalid?subject=x"),
    ("ipv6 zero-padded prefix", "ipv6-global", "prefix 2001:0db8:0001:0002"),
    ("ipv6 mixed case", "ipv6-global", "addr 2001:Db8:1:2::5"),
    ("tmpdir resolved under /private", "identity",
     "/private/var/folders/zz/abcd1234efgh5678/T/x"),
    # U+0130 in place of the `i` in `synthetic`. `redact_identity` raises
    # KeyError on this text and `identity_leaks` calls it clean, because the
    # substituter folds with re.IGNORECASE and the verifier with str.lower.
    ("account unicode fold trap", "identity",
     "user synthet\u0130c-operator logged in"),
    # The casefold-expansion direction. The needle is spelled with an eszett
    # and the document with a double s.
    ("account casefold expansion", "identity",
     "run as strauss-operator today"),
    # A prefix followed by a colon is four colons with no `::`, which the
    # structured pass skips and only the prefix literal catches.
    ("ipv6 prefix trailing colon", "ipv6-global", "prefix 2001:db8:1:2: wan"),
    ("ipv6 zero-run compressed", "ipv6-global", "addr fd12::3456:0:0:0:9 up"),
    ("ipv6 zero-run explicit", "ipv6-global", "addr fd12:0:0:3456::9 up"),
)

#: Positives whose matched *extent* is part of the claim, not only its kind.
#:
#: A home path and a bare account name are both ``identity``, so a kind-only
#: assertion passes whichever one the span walker picks — and picking the
#: shorter means reporting ``/Users/<name>`` as a bare name, under a
#: fingerprint whose length says 18 when 25 bytes have to come out. This is
#: the ``_identity_table`` longest-first ordering requirement, restated as a
#: measurement.
_CAL_SPAN_LEN: dict[str, int] = {
    "home path posix": len("/Users/synthetic-operator"),
    "per-user tmpdir": len("/var/folders/zz/abcd1234efgh5678/T"),
    "ipv6 compressed": len("2001:db8:1:2::5"),
    "volume path": len("/Volumes/synthetic-disk"),
}

_CAL_NEGATIVES: tuple[tuple[str, str], ...] = (
    ("RFC 5737 TEST-NET-1", "connect 192.0.2.1 port 443"),
    ("RFC 5737 TEST-NET-2", "upstream 198.51.100.7"),
    ("RFC 5737 TEST-NET-3", "relay 203.0.113.42"),
    ("RFC 1918 not ours", "gateway 192.168.1.1 and 10.0.0.1 and 172.16.0.1"),
    ("ipv4 near-miss low", "host 10.11.12.1"),
    ("ipv4 near-miss embedded", "build 210.11.12.139"),
    ("version quad", "openssl 3.0.11.2 released"),
    ("snmp oid", "iso.3.6.1.2.1.1.5.0 = STRING"),
    ("ipv6 doc other /64", "example 2001:db8::1 and 2001:db8:3:4::9"),
    ("ipv6 ula sibling /64", "peer fd12:0:0:3457::9 and fd13::1"),
    ("ipv6 doc /64 sibling", "prefix 2001:db8:1:3::/64 is not ours"),
    ("ipv6 loopback", "listening on ::1 and fe80::1%lo0"),
    ("reserved mac", "ether 00:11:22:33:44:55"),
    ("deadbeef mac", "src de:ad:be:ef:00:01 dst 01:80:c2:00:00:00"),
    ("timestamp", "at 12:34:56 the job 00:00:5e started"),
    ("sha256 hex", "hash 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6"
                   "c15b0f00a08"),
    ("uuid4", "id 3f2504e0-4f89-41d3-9a0c-0305e82c3301"),
    ("yara hex string", "$a = { 00 00 5e 00 53 01 90 90 }"),
    ("nuclei template", "matchers: - type: word words: - 'synthetic'"),
    ("example.com address", "mail root@example.com and admin@example.org"),
    ("generic operator word", "the operator ran the playbook as root"),
    ("generic volume word", "data volume mounted at /Volumes/Macintosh HD"),
    ("cvss pair", "CVSS 7.5000, 9.8000 scored"),
    ("netstat columns", "tcp        0      0 0.0.0.0:445            LISTEN"),
    ("bit ruler", " 0                   1                   2         "),
    # Near-misses that attack each guard directly. The first calibration run
    # scored 1.000/1.000 and that was a statement about the fixtures, not the
    # detector, so these were added to make it work for it.
    ("ipv4 right boundary", "mask 10.11.12.130 broadcast"),
    ("ipv4 left boundary", "legacy 0010.11.12.13 notation"),
    ("ipv4 as version", "agent 10.11.12.13.4 build"),
    ("mac hex inside longer run", "hash a00005e005301b and 00005e0053012"),
    ("ipv6 sibling prefix bare", "delegated 2001:db8:1:3 not ours"),
    ("ipv6 longer prefix", "route 2001:db8:1:20::/64"),
    ("ipv6 zoned link-local", "nexthop fe80::1%en0 dev en0"),
    ("email longer local part", "mail notsomeone@example.invalid bounced"),
    ("email extended domain", "mail someone@example.invalid.evil.test"),
    ("account prefix only", "job synthetic-op finished"),
    ("eszett needle not a free pass", "run as strau-operator today"),
    ("flattened path wrong hash", "key=-var-folders-zz-0000000000000000-T"),
    ("volume name prefix only", "disk synthetic-dis offline"),
    ("home path wrong user", "cache /Users/other-operator/Library"),
    ("tmpdir wrong hash", "/var/folders/zz/zzzz0000zzzz0000/T/world"),
)


def _cal_needles() -> Needles:
    return Needles.from_values(probes=("calibration",), **_CAL_NEEDLES)


def calibrate() -> Calibration:
    """Run the detector against fixtures constructed before any corpus pass.

    Positives are one per needle kind and per spelling that a real tool emits;
    negatives are the things this corpus is *full of on purpose*. The law here
    is the project's own: check the instrument first. Three measurement bugs in
    this codebase each accused the model and all three were in the ruler.
    """
    misses: list[str] = []
    false_positives: list[str] = []
    needles = _cal_needles()

    found = 0
    for label, kind, text in _CAL_POSITIVES:
        leaks = scan_text(text, needles=needles)
        kinds = {leak.kind for leak in leaks}
        want = _CAL_SPAN_LEN.get(label)
        lengths = {leak.fingerprint.split(",")[0] for leak in leaks
                   if leak.kind == kind}
        if kind not in kinds:
            misses.append(f"{label} (expected {kind}, got "
                          f"{sorted(kinds) or 'nothing'})")
        elif want is not None and f"len={want}" not in lengths:
            # Right kind, wrong extent. Reported as a miss because a
            # fingerprint whose length is wrong sends somebody looking for the
            # wrong number of bytes.
            misses.append(f"{label} (expected {kind} spanning {want} chars, "
                          f"got {sorted(lengths)})")
        else:
            found += 1

    clean = 0
    for label, text in _CAL_NEGATIVES:
        leaks = scan_text(text, needles=needles)
        if leaks:
            false_positives.append(
                f"{label} -> {sorted({leak.kind for leak in leaks})}")
        else:
            clean += 1

    return Calibration(
        positives=len(_CAL_POSITIVES), positives_found=found,
        negatives=len(_CAL_NEGATIVES), negatives_clean=clean,
        misses=tuple(misses), false_positives=tuple(false_positives))


def self_test() -> str:
    """Plant a synthetic needle, prove it is found; remove it, prove the same
    tree comes back zero.

    Without the second half a verifier that always returns "clean" is
    indistinguishable from one that works. That is not a hypothetical failure
    mode in this codebase: a source trimmed to zero documents looked exactly
    like a source that had nothing to give, and only the balance report caught
    it. So the gate proves both directions every time it runs, on fabricated
    values, in a temp directory, and reports counts.
    """
    import shutil

    needles = _cal_needles()
    root = Path(tempfile.mkdtemp(prefix="whetstone-verify-selftest-"))
    try:
        clean_dir = root / "clean"
        clean_dir.mkdir()
        rows = [
            {"text": "tcp 0 0 0.0.0.0:445 LISTEN", "source": "s",
             "register": "system", "side": "neutral", "ident": "netstat/1"},
            {"text": "example host 2001:db8::1 and 192.0.2.1",
             "source": "s", "register": "system", "side": "neutral",
             "ident": "doc/2"},
        ]
        path = clean_dir / "s.jsonl"
        with path.open("w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        before = verify_corpus(clean_dir, needles=needles)

        dirty_dir = root / "dirty"
        shutil.copytree(clean_dir, dirty_dir)
        with (dirty_dir / "s.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "text": "ether 00:00:5e:00:53:01 inet6 2001:db8:1:2::5",
                "source": "s", "register": "system", "side": "neutral",
                "ident": "/Users/synthetic-operator/x",
            }, ensure_ascii=False) + "\n")
        after = verify_corpus(dirty_dir, needles=needles)

        link_dir = root / "alias"
        link_dir.symlink_to(dirty_dir, target_is_directory=True)
        linked = survey(link_dir, needles=needles)

        kinds = sorted({leak.kind for leak in after})
        fields = sorted({leak.field for leak in after})
        ok = (not before and len(after) >= 3 and "ident-path" in kinds
              and linked.directory_is_symlink)
        return (f"self-test {'PASS' if ok else 'FAIL'}: "
                f"clean tree {len(before)} leak(s); "
                f"one planted row -> {len(after)} leak(s) "
                f"in kinds {kinds} and fields {fields}; "
                f"symlinked directory reported as symlink "
                f"{linked.directory_is_symlink}")
    finally:
        shutil.rmtree(root, ignore_errors=True)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    """``python3 -m training.corpus.verify <dir>``

    Exit codes are three, not two, and the third is the point. **0** clean,
    **1** leaking, **2** could not verify — the table was too thin to mean
    anything. ``redact_identity`` collapses 2 into 0 and that is its fail-open;
    a gate that did the same would hand back a reassuring zero from a container
    where nothing was ever looked for.
    """
    p = argparse.ArgumentParser(
        prog="python3 -m training.corpus.verify",
        description="Read a built corpus and report this machine's identity in "
                    "it. Prints fingerprints, never values.")
    p.add_argument("directory", nargs="?", type=Path,
                   help="a corpus generation, e.g. "
                        "/Volumes/.../whetstone/corpus/clean-v7")
    p.add_argument("--calibrate", action="store_true",
                   help="report precision/recall against synthetic fixtures "
                        "and exit")
    p.add_argument("--self-test", action="store_true",
                   help="prove the scanner bites, on fabricated values, and "
                        "exit")
    p.add_argument("--ignore-kind", action="append", default=[],
                   metavar="KIND", choices=list(KINDS),
                   help="do not let this kind set the exit code. Intended for "
                        "ipv4-private, which is ambiguous by construction.")
    p.add_argument("--allow-thin-table", action="store_true",
                   help="exit 0/1 instead of 2 when the needle table is "
                        "missing a probe. Say why in the commit message.")
    args = p.parse_args(argv)

    if args.calibrate:
        cal = calibrate()
        print(cal.describe())
        for miss in cal.misses:
            print(f"  MISS {miss}")
        for fp in cal.false_positives:
            print(f"  FALSE POSITIVE {fp}")
        return 0 if cal.clean else 1

    if args.self_test:
        print(self_test())
        return 0

    if args.directory is None:
        p.error("a directory is required unless --calibrate or --self-test")

    needles = host_needles()
    print(f"needles: {needles!r}")
    print(f"probes: {', '.join(needles.probes()) or 'NONE'}")
    gaps = needles.gaps()
    if gaps:
        print(f"  ! table is THIN: no {', '.join(gaps)}. A verifier with an "
              f"empty table returns 'clean' and that is the same failure as "
              f"redact_identity's fail-open.")

    cal = calibrate()
    print(cal.describe())
    if not cal.clean:
        print("  ! the instrument failed its own calibration; the numbers "
              "below are not trustworthy")

    started = time.monotonic()
    info = survey(args.directory, needles=needles)
    leaks = verify_corpus(args.directory, needles=needles)
    elapsed = max(time.monotonic() - started, 1e-9)
    print()
    print(render_survey(info))
    mb = info.text_bytes / 1e6
    rate = mb / elapsed if elapsed > 0 else float("inf")
    print(f"  {mb:,.1f} MB in {elapsed:,.1f}s = {rate:,.1f} MB/s")
    if mb > 1.0 and rate > 20_000.0:
        # No storage reaches 20 GB/s. A rate above it means the pass did not
        # read what it claims to have read, so the verdict below is worthless.
        # This check exists because the real bug printed 128,124.5 MB/s and
        # "0 leaks." together and nobody looked at the first number.
        print(f"  IMPOSSIBLE THROUGHPUT ({rate:,.0f} MB/s) - this pass did not "
              f"read the data it reports on; treat the verdict as invalid")
        return 2
    print()
    print(render(leaks))

    gating = [leak for leak in leaks if leak.kind not in set(args.ignore_kind)]
    if gaps and not args.allow_thin_table:
        print("\nEXIT 2: could not verify. See the thin-table warning above.")
        return 2
    if not cal.clean:
        print("\nEXIT 2: could not verify. The instrument failed calibration.")
        return 2
    return 1 if gating else 0


if __name__ == "__main__":
    raise SystemExit(main())
