"""The Nmap Scripting Engine — 611 active probes and the 133 libraries under
them, as Lua source. SYSTEM/RED.

**What this source is for.** The corpus already holds detection *rules* in
quantity: Sigma, YARA, Elastic, Suricata, Splunk, and Nuclei on top of those.
Every one of them answers the same shape of question — *given this artefact,
does it match?* Almost nothing here answers the other one: *how do you obtain
the artefact in the first place?* An NSE script is that second half written out
in full. It opens a socket, speaks enough of a protocol to get a
distinguishing answer back, and decides from the answer what the service is and
whether it is broken. ``ssl-heartbleed.nse`` builds a TLS ClientHello, claims a
heartbeat payload length of ``0x4000`` while sending nineteen bytes, and
concludes from the size of what comes back. That is a whole probing method —
craft, send, read, discriminate — in one file a model can read start to finish.

It complements :mod:`~training.corpus.sources.nuclei` rather than repeating it.
Nuclei is overwhelmingly HTTP: a request template and a matcher. NSE is
protocol breadth — SMB, MS-RPC, Kerberos, LDAP, SSH, TLS, DNS, SNMP, RDP, AFP,
NFS, MS-SQL, Oracle TNS, IPMI, BACnet, EtherNet/IP, Modbus, TN3270 — written at
the level of packed structs and read loops, because none of those protocols can
be probed by filling in a URL. Measured against the rest of the package, nothing
this corpus already holds overlaps it: no other adapter fetches nmap, and none
of the thirty-one emits a line of Lua.

**The surface form is the second reason, and it is the stronger one.** NSE
mandates a structured header, so every one of the 611 scripts opens with a
plain-words statement of what it detects sitting directly above the code that
detects it. Measured across the tree:

* 611 of 611 carry a ``description = [[ ... ]]`` block — 288 KB of English
* 600 of 611 carry an ``@output`` block — **988 KB, 26% of all script bytes**
* 526 of 611 carry an ``@usage`` line, a literal ``nmap --script ...`` command
* 133 of 133 nselib modules are documented in luadoc throughout

The median file is 35% comment-and-description by character. That is the
prose-next-to-code shape :mod:`~training.corpus.source` records as the thing
that moved a tokenizer sample from -45% to +13%, and here it arrives by house
rule rather than by luck.

The ``@output`` blocks deserve their own sentence, because they are the single
most valuable thing in this source and the register label does not advertise
them. They are not descriptions of output; they are *transcripts* of it, pasted
verbatim with nmap's column alignment and its ``|`` / ``|_`` tree characters
intact::

    -- PORT    STATE SERVICE
    -- 443/tcp open  https
    -- | ssl-heartbleed:
    -- |   VULNERABLE:
    -- |     State: VULNERABLE
    -- |_      Risk factor: High

Column-aligned command output is the register that beat gpt2 by 47% in the
measurement this corpus was rebuilt around, and this source contributes roughly
a megabyte of it — paired, in the same document, with the code that produced it.
A model that has read both halves has seen not merely what a scanner prints but
why it prints that.

**Register: SYSTEM, and deliberately not SHELL.** The package this adapter was
written for is aimed at a shell gap — 8.9% observed against a 26% target — and
calling 7 MB of Lua "shell" would close that gap on paper without closing it at
all. :mod:`~training.corpus.sources.shellscripts` and
:mod:`~training.corpus.sources.powershell` file under SHELL because the artefact
*is* a shell language: the thing the model must learn to emit at a prompt. Lua
is no more a shell than Python is, and
:mod:`~training.corpus.sources.pythoncode` settled the identical question the
same way — security tooling written in a general-purpose language is SYSTEM,
"how the machine works … API references", which is precisely what an SMB dialect
negotiation written out in ``string.pack`` format strings is. Around 65% of
these bytes are Lua source, 26% are command output and 2% are command lines. The
plurality decides the label; the other 28% is stated here so that nobody reads
the balance report and concludes this source contributed no shell-shaped text.

**Side: RED, on the same argument nuclei uses and for the same reason.** Every
script here is an unsolicited packet sent at a machine that did not ask for it,
and the upstream's own categories agree without being asked: 213 ``intrusive``,
105 ``vuln``, 73 ``brute``, 45 ``exploit``, 11 ``dos``, 10 ``malware``, 3
``fuzzer``. The 350 marked ``safe`` are safe in the sense of unlikely to crash
the target, not in the sense of invited. The nselib modules get RED too, and
that is the judgement rather than the obvious call: they look like protocol
client libraries, which :mod:`~training.corpus.sources.pythoncode` files as
NEUTRAL for impacket. The difference is that impacket is a library anyone may
import into defensive tooling, whereas every module here ``require``s ``nmap``
— the C binding into the scanner process — and cannot be loaded outside it.
nselib is not a library that a scanner happens to use; it is the scanner's
inside. Labelling it neutral would describe the shape of the file rather than
what the file is.

This does move the corpus's red share, which sits at 30% against a ~60% target,
and that is worth saying out loud rather than letting it look like a happy
accident. The argument above is the reason; the balance is the consequence.

----

**The licence, which is the part of this adapter that took the longest.**

nmap is *not* GPL, is not MIT, and is not OSI-approved. It ships under the
**Nmap Public Source License Version 0.95**, read here from the repository's own
``LICENSE`` file rather than from a badge or a README sentence. Its shape:

* Section 2 licenses the software under **GPL-2.0** — reproduced in full as
  Exhibit A — "with all the exceptions, clarifications, and additions noted in
  this Main License Body", and states that where the two conflict the additions
  win, so "You may not distribute Covered Software or Derivative Works under
  plain GPL terms without special permission from Licensor."
* Section 3 defines "derivative work" far more broadly than the GPL does, and
  says so explicitly: integrating source, *reading nmap's data files*, being
  designed to execute nmap and parse its results, or linking to anything that
  does, all qualify. Derivatives must be distributed under this same licence
  "with no additional conditions or restrictions".
* Section 6 requires that anyone who externally deploys it display a notice
  saying the system uses the Nmap Security Scanner, with a link to nmap.org.
* The preamble directs companies wishing to incorporate it into their own
  products to the commercial **Nmap OEM** product instead.
* Sections 7 to 9 withhold any trademark grant, terminate the licence on a
  patent action, and fix venue in the Northern District of California.

So: **copyleft, source-available, more restrictive than the GPL it is built
from, and backed by a licensor that runs a commercial licensing business and is
known to enforce.** It is usable — it grants copying, modification and
redistribution, it has no non-commercial clause and no redistribution ban — but
it is the most encumbered upstream in this package, more so than
:mod:`~training.corpus.sources.gtfobins` (GPL-3.0-only) or the source-available
Elastic collection that :mod:`~training.corpus.sources.yara` flags. That is
recorded in :data:`SPEC` in full sentences rather than as an SPDX tag, because
there is no SPDX tag that carries it.

Two consequences are wired into the code rather than left as prose. First,
``fetch`` copies ``LICENSE``, ``docs/licenses/BSD-simplified`` and
``docs/3rd-party-licenses.txt`` into the cache beside the text they cover, so
the declaration above is checkable against the download and not merely asserted.
Second, every file's own declared ``license = "..."`` field is parsed and
tallied into the marker, because the tree is not uniform: 597 scripts and all
133 nselib modules fall under the repository licence, while **14 files are
genuinely permissive** — 13 under the simplified 2-clause BSD (confirmed by
``docs/3rd-party-licenses.txt``: "Certain Nmap Scripting Engine scripts use the
simplified BSD license in licenses/BSD-simplified") and one under
BSD-2-Clause-Patent. Those 14 are listed by name in the marker so that the
subset which survives a decision to drop NPSL can be identified without
re-deriving it.

If that decision is ever made, the way to act on it is to rename this module to
``_nselua.py``: :func:`~training.corpus.build.discover_sources` skips modules
with a leading underscore, which is exactly how
:mod:`~training.corpus.sources._internal_unlicensed` is kept present and
inert. One rename, no deletions, no other adapter touched.

----

**The trap, and why it is not the one the brief expected.**

There is no Lua parser in the standard library and no Lua interpreter on this
machine (``lua``, ``luac``, ``lua5.4`` and ``luajit`` are all absent), so the
house rule of syntax-checking with :func:`compile` does not transfer: it parses
Python and nothing else. Depending on an external ``luac -p`` would make the
corpus a function of what happens to be installed, which is worse than having no
check. So this adapter carries a small hand-written Lua lexer —
:func:`_lua_spans` — that classifies every byte as comment, string or code, and
:func:`_block_balance` counts block openers against ``end`` over the code bytes
only. Across all 744 files the balance is exactly zero, 744 times out of 744,
which is what makes it usable as a gate rather than a heuristic.

Getting there cost one specific bug, and it is worth recording because it is the
kind that a smaller sample would have hidden. A first version handled string
escapes as "backslash consumes the next character", which is right for ``\n``
and ``\\"`` and wrong for Lua's ``\\z``: ``\\z`` skips *all* following whitespace
**including newlines**, so a short string can legally span lines. Exactly one
file in the tree uses it — ``http-coldfusion-subzero.nse``, which wraps a long
ColdFusion LFI URL across four lines — and inside that URL is the query
parameter ``thisTag.executionmode=end``. The lexer fell out of the string at the
first newline, read the rest of the URL as code, counted two stray ``end``
keywords, and reported the only unbalanced file in nmap. One file in 744, and
the symptom was a balance error in a file whose Lua is fine.

**What :func:`~training.corpus.source.normalise` does here, measured rather than
assumed.** Lua is not Python: indentation is not the syntax. But column
alignment inside those ``@output`` transcripts is the entire value of the
register they belong to, and a long string can hold a protocol payload whose
exact byte layout is the payload — that is the same hazard
:mod:`~training.corpus.sources.nuclei` records for HTTP block scalars. So the
tree was measured before a rule was written. Of 744 files: none contain CRLF,
none contain a control byte, none contain a run of 200 spaces, and all are
strict UTF-8 — so the only two things ``normalise`` can do here are strip
trailing whitespace per line and collapse runs of *two or more* blank lines to
one. It does both, in exactly eight files, and in every one of the eight the
affected bytes are inside a ``description = [[ ... ]]`` block: seven scripts
left a double blank line in their English prose and ``lu-enum.nse`` left a
trailing space in a sentence. **Not one string literal that is not a
description is touched.**

The single blank line that separates an HTTP header block from its body is
*not* at risk, and saying so precisely matters more than the scarier version:
``normalise`` caps runs of three or more newlines, so one blank line survives
untouched — which is the same thing nuclei measured, 3,300 raw requests out of
3,303. What would be destroyed is a doubled blank line inside a payload, or a
line inside a fixed-width record that ends in significant spaces.

That measurement is what licenses the guard rather than replacing it.
:func:`_normalise_is_harmless` re-derives it per file at fetch time and raises
if it ever stops holding, because a payload literal damaged this way produces a
document that teaches a malformed protocol while the character count barely
moves. Then :func:`_documents` proves the contract held after the fact: the
sequence of non-blank right-stripped lines must be identical before and after,
which is a direct test that no leading or internal space moved, and the lexer
must still balance. Both raise rather than skip. A normaliser that
mangles Lua is a broken contract, not bad input, and filtering around it would
turn that into a slightly smaller document count.

**What is excluded, and what that costs.** ``nselib/data/`` is dropped whole: it
is upstream's own name for "this is data, not logic", and it holds 1.04 MB of
Lua of which 962 KB is generated lookup and signature tables —
``idnaMappings.lua`` is 622 KB of Unicode mappings and ``http-fingerprints.lua``
is 238 KB of web signatures. The cost is the remaining 16 KB: seven
``psexec/*.lua`` files that configure ``smb-psexec``, and which are mostly
commented-out module declarations rather than logic. Three admitted scripts are
themselves dominated by vendor-identifier tables — ``enip-info`` (58 KB),
``bacnet-info`` (53 KB) and ``ip-geolocation-maxmind`` (23 KB), 1.9% of this
source between them. They are kept because every prose gate tight enough to
catch them also catches terse-but-real modules like ``redis.lua`` and
``ipmi-brute.nse``, and losing working probes to filter out a vendor table is
the wrong trade. The size ceiling in :data:`_MAX_BYTES` drops nothing from
today's upstream — the largest admitted file is ``nselib/msrpc.lua`` at 194 KB,
and it is 43% prose — and that is stated plainly rather than dressed up: it is a
guard against a future data dump landing in a directory that is not
``nselib/data/``, not a filter that is currently doing work.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tarfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from ..net import NetworkError, download
from ..source import (
    Document, Register, Side, SourceError, SourceSpec, fingerprint, normalise,
)

_NAME = "nselua"

_REPO = "https://github.com/nmap/nmap"
_ARCHIVE = "https://codeload.github.com/nmap/nmap/tar.gz/refs/heads/master"

#: Written last, so its presence means extraction finished. The version is part
#: of it because the gates below are part of what the cache means: a tree
#: extracted under older rules is stale, and silently reusing it is how a fix
#: fails to reach the machine that already ran the build once.
_MARKER = ".fetched.json"
_CACHE_VERSION = 1

#: 16.7 MB when this adapter was written, for ~7 MB of admitted Lua. The
#: ceiling goes to :func:`~training.corpus.net.download`, which enforces it
#: against bytes as they arrive rather than against a file that has already
#: landed on disk.
_MAX_ARCHIVE_BYTES = 128 * 1024 * 1024

#: The two trees, and nothing else in the repository. Expressed as (directory,
#: suffix) with an exact depth of two path components, which is what keeps
#: ``nselib/data/`` out without needing a second rule about it: every file in
#: there is three components deep.
_KEEP: tuple[tuple[str, str], ...] = (
    ("scripts", ".nse"),
    ("nselib", ".lua"),
)

#: Licence and attribution text, copied into the cache so the claim in
#: :data:`SPEC` can be checked against what was actually downloaded rather than
#: against this file's docstring.
_LICENCE_FILES: tuple[str, ...] = (
    "LICENSE",
    "docs/licenses/BSD-simplified",
    "docs/3rd-party-licenses.txt",
)

#: Below this a script is a stub. The smallest real one upstream is
#: ``daytime.nse`` at 578 bytes, which is a complete and perfectly good document
#: — description, sample output, portrule, action — so the floor sits well under
#: it rather than at the 1.2 KB a Python source tree wants.
_MIN_BYTES = 400
#: See the docstring: this drops nothing today. ``nselib/msrpc.lua`` is the
#: largest admitted file at 194 KB.
_MAX_BYTES = 250_000

#: Prose is comments of every kind plus the ``description`` block, measured by
#: the lexer rather than by scanning for lines that start with ``--`` — the same
#: correction :mod:`~training.corpus.sources.pythoncode` had to make, and for
#: the same reason: the most valuable comments in protocol code are the trailing
#: ones, ``["heartbeat"] = "\\x01", -- peer_not_allowed_to_send``, and a
#: line-start scan misses every one.
#:
#: Both numbers are calibrated from the observed distribution, not chosen. The
#: median file is 35% prose and the 5th percentile is 15%, so these gates drop
#: exactly two files of 744: ``weblogic-t3-info.nse`` (3.3%) and
#: ``iec61850mms.lua`` (2.3%). That is the honest report — NSE's own house style
#: is the quality gate here and this one confirms it rather than enforcing it.
_MIN_PROSE_CHARS = 100
_MIN_PROSE_RATIO = 0.05

#: Per-file licence declarations that are *not* the repository's. Matched
#: against the ``license = "..."`` field's leading text. Everything else,
#: including a file with no field at all, falls under ``LICENSE`` — which is the
#: correct default and is recorded as such rather than left blank.
_PERMISSIVE_PREFIXES: tuple[tuple[str, str], ...] = (
    ("Simplified (2-clause) BSD", "BSD-2-Clause"),
    ("BSD-2-Clause Plus Patent", "BSD-2-Clause-Patent"),
)
_REPOSITORY_LICENCE = "NPSL-0.95 (repository LICENSE)"

_LICENSE_FIELD = re.compile(r'^license\s*=\s*"([^"]*)"', re.MULTILINE)

#: ``description = [[`` — the one long string in an NSE file that is prose
#: rather than payload, and therefore the one whose blank-line runs
#: ``normalise`` may legitimately cap. Anchored at the end because it is matched
#: against the text *preceding* the opening bracket.
_DESCRIPTION_ASSIGN = re.compile(r"(?:^|[\s;])description\s*=\s*\Z")

_TRAILING_WS = re.compile(r"[ \t]+\n")
_BLANK_RUN = re.compile(r"\n[ \t]*\n[ \t]*\n")


# --------------------------------------------------------------------------
# a small Lua lexer
# --------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class _Span:
    """One classified region of a Lua file.

    ``opens`` is where the token starts (the ``--`` of a comment, the quote or
    the ``[`` of a string); ``start``/``end`` bracket its *content*. Both are
    needed: the balance check reads code content, and the prose check has to
    look at what precedes a long bracket to tell ``description = [[`` from a
    payload.
    """

    kind: str   # "code" | "comment" | "string"
    opens: int
    start: int
    end: int


_IDENT = re.compile(r"[A-Za-z_][A-Za-z_0-9]*")

#: Lua's block openers. ``for`` and ``while`` are deliberately absent: their
#: block is opened by the ``do`` that follows, and counting both would
#: double-count every loop. ``then``, ``else`` and ``elseif`` open nothing.
_OPENERS = frozenset({"function", "if", "do"})


def _long_bracket(text: str, i: int) -> tuple[int, int, int, bool] | None:
    """Parse a Lua long bracket at ``i``: ``[[``, ``[=[``, ``[==[`` and so on.

    Returns ``(content_start, content_end, token_end, unterminated)`` or
    ``None`` when ``i`` does not open one. The level (the number of ``=``)
    matters: ``]]`` does not close ``[=[``, which is how nmap embeds Lua
    containing ``]]`` inside a long string without escaping anything.

    A newline immediately after the opening bracket is skipped, because Lua
    discards it. Keeping it would put a phantom blank first line into every
    ``description`` block and make the prose measurement wrong by one line 611
    times.
    """
    # The bounds check is not defensive padding. ``_lua_spans`` probes at
    # ``i + 2`` the moment it sees ``--``, so a text whose last two bytes are
    # ``--`` puts that probe one past the end. No file upstream ends that way
    # and the fetch-time lex is clean — but ``normalise`` strips the trailing
    # newline, and three scripts (hostmap-robtex, http-robtex-reverse-ip,
    # http-robtex-shared-ns) close with a bare ``--`` rule line, so the
    # normalised text does end there and only the second lex ever sees it.
    # Without this the failure is an IndexError out of the middle of the lexer
    # rather than the correct answer, "this comment opens no long bracket".
    if i >= len(text) or text[i] != "[":
        return None
    j = i + 1
    while j < len(text) and text[j] == "=":
        j += 1
    if j >= len(text) or text[j] != "[":
        return None
    close = "]" + "=" * (j - i - 1) + "]"
    start = j + 1
    if start < len(text) and text[start] == "\n":
        start += 1
    end = text.find(close, start)
    if end < 0:
        return start, len(text), len(text), True
    return start, end, end + len(close), False


def _lua_spans(text: str) -> tuple[list[_Span], bool]:
    """Classify every byte of ``text`` as code, comment or string.

    Returns the spans in order and whether a long bracket was left
    unterminated, which is the one lexical error this can detect on its own and
    is worth reporting separately from a balance mismatch: an unterminated
    ``[[`` swallows the rest of the file, so the balance would look wrong for a
    reason that has nothing to do with blocks.

    The ``\\z`` case is the whole reason this function is longer than it looks.
    Lua 5.2 added ``\\z`` as "skip the following whitespace, newlines
    included", so a short string may span lines. Treating a backslash as
    "consumes one character" desynchronises on exactly one file in nmap and
    reads a URL as code — see the module docstring.
    """
    spans: list[_Span] = []
    unterminated = False
    n = len(text)
    i = code_from = 0

    while i < n:
        char = text[i]

        if char == "-" and text.startswith("--", i):
            spans.append(_Span("code", code_from, code_from, i))
            long = _long_bracket(text, i + 2)
            if long is not None:
                start, end, token_end, ran_off = long
                spans.append(_Span("comment", i, start, end))
                unterminated = unterminated or ran_off
                i = token_end
            else:
                line_end = text.find("\n", i)
                line_end = n if line_end < 0 else line_end
                spans.append(_Span("comment", i, i + 2, line_end))
                i = line_end
            code_from = i
            continue

        if char in "'\"":
            spans.append(_Span("code", code_from, code_from, i))
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    if j + 1 < n and text[j + 1] == "z":
                        j += 2
                        while j < n and text[j].isspace():
                            j += 1
                        continue
                    j += 2
                    continue
                if text[j] == char or text[j] == "\n":
                    break
                j += 1
            spans.append(_Span("string", i, i + 1, min(j, n)))
            i = min(j + 1, n)
            code_from = i
            continue

        if char == "[":
            long = _long_bracket(text, i)
            if long is not None:
                start, end, token_end, ran_off = long
                spans.append(_Span("code", code_from, code_from, i))
                spans.append(_Span("string", i, start, end))
                unterminated = unterminated or ran_off
                i = token_end
                code_from = i
                continue

        i += 1

    spans.append(_Span("code", code_from, code_from, n))
    return spans, unterminated


def _block_balance(text: str, spans: list[_Span]) -> tuple[int, int]:
    """``(block_depth, repeat_depth)`` over the code bytes only.

    Both are zero for every one of nmap's 744 admissible files, which is what
    makes this a gate rather than a guess. Keywords are taken from code spans
    exclusively — ``end`` appears inside strings and comments constantly, and
    counting those is how a lexer bug turns into a false rejection.
    """
    depth = repeats = 0
    for span in spans:
        if span.kind != "code":
            continue
        for word in _IDENT.findall(text[span.start:span.end]):
            if word in _OPENERS:
                depth += 1
            elif word == "end":
                depth -= 1
            elif word == "repeat":
                repeats += 1
            elif word == "until":
                repeats -= 1
    return depth, repeats


def _prose_chars(text: str, spans: list[_Span]) -> int:
    """Characters of human explanation: all comments, plus ``description``.

    The ``description`` block is a string rather than a comment and has to be
    counted anyway — it is the mandatory plain-words statement of what the
    script detects, and it is the single most valuable paragraph in the file.
    It is identified by what precedes its opening bracket rather than by
    guessing from content, so a long string holding a payload is never mistaken
    for prose no matter how English it looks.
    """
    total = 0
    for span in spans:
        if span.kind == "comment":
            total += span.end - span.start
        elif span.kind == "string" and _is_description(text, span):
            total += span.end - span.start
    return total


def _is_description(text: str, span: _Span) -> bool:
    return bool(_DESCRIPTION_ASSIGN.search(text[max(0, span.opens - 64):span.opens]))


def _normalise_is_harmless(text: str, spans: list[_Span]) -> str | None:
    """``None`` if ``normalise`` cannot damage this file, else what it would hit.

    The two regexes are not a paraphrase of ``normalise``, they are the exact
    pair of edits it is able to make to text that is already CRLF-free,
    control-byte-free and under the 200-space ceiling — which every file here
    is proved to be before this runs. It strips trailing whitespace per line,
    and it collapses runs of three or more newlines, so **two** blank lines
    become one and a single blank line is left alone. Inside prose both edits
    are cosmetic. Inside a payload held in a long string they are not: a
    doubled blank line or a significant trailing space is content, and losing
    it produces a document that teaches a malformed protocol while the
    character count barely moves — the failure
    :mod:`~training.corpus.sources.nuclei` documents for YAML block scalars.
    The HTTP header/body separator itself is safe, being one blank line; the
    check is deliberately no wider than the damage.

    Today this returns ``None`` for all 744 files: the only literals carrying
    either pattern are seven ``description`` blocks with a double blank line and
    one with a trailing space. The check earns its keep on the day that stops
    being true, and the caller raises rather than quietly emitting the file.
    """
    for span in spans:
        if span.kind != "string" or _is_description(text, span):
            continue
        body = text[span.start:span.end]
        if _BLANK_RUN.search(body):
            return "a blank-line run inside a non-description string literal"
        if _TRAILING_WS.search(body):
            return "trailing whitespace inside a non-description string literal"
    return None


def _content_lines(text: str) -> list[str]:
    """The comparison key for "``normalise`` moved nothing".

    Non-blank lines, each right-stripped. Two texts with the same list differ
    only in trailing whitespace and blank lines — which is precisely, and
    exclusively, what ``normalise`` is contracted to change. Leading and
    internal spacing is inside the key, so a normaliser that collapsed runs of
    spaces would fail this instantly.
    """
    return [line.rstrip() for line in text.splitlines() if line.strip()]


# --------------------------------------------------------------------------
# fetch
# --------------------------------------------------------------------------

def _declared_licence(text: str) -> str:
    """The file's own ``license`` field, mapped to a short name.

    A file with no field is not unlicensed — it falls under the repository's
    ``LICENSE``, which is every one of the 133 nselib modules and six of the
    scripts. Saying so explicitly keeps the marker's tally honest: a blank entry
    would read like a gap in the audit rather than the default it is.
    """
    match = _LICENSE_FIELD.search(text)
    if match is None:
        return _REPOSITORY_LICENCE
    declared = match.group(1).strip()
    for prefix, name in _PERMISSIVE_PREFIXES:
        if declared.startswith(prefix):
            return name
    return _REPOSITORY_LICENCE


def _wanted(relative: Path) -> bool:
    """True for ``scripts/*.nse`` and ``nselib/*.lua``, and nothing else.

    Depth is part of the rule, not an afterthought. ``nselib/data/`` is 1 MB of
    generated lookup tables sharing the ``.lua`` suffix with the modules above
    it, and requiring exactly two path components excludes the whole tree
    without a second rule that could drift out of step with this one.
    """
    parts = relative.parts
    if len(parts) != 2:
        return False
    return any(parts[0] == directory and relative.suffix == suffix
               for directory, suffix in _KEEP)


def _admit(raw: bytes, ident: str) -> tuple[str, str] | None:
    """Return ``(source, declared_licence)`` if this file belongs, else ``None``.

    Gates in ascending cost: size, strict UTF-8, lexical soundness, block
    balance, prose. Decoding is strict deliberately — ``errors="replace"`` would
    admit a Latin-1 file as Lua containing replacement characters, which lexes
    fine and teaches the model mojibake.

    The one condition here that raises instead of returning ``None`` is the
    ``normalise`` safety check. A file this adapter cannot clean without
    damaging it is not a quality problem to filter away silently; it is a
    signal that the upstream has started doing something this adapter does not
    handle, and the right response is a build that stops and names the file.
    """
    if not _MIN_BYTES <= len(raw) <= _MAX_BYTES:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None

    spans, unterminated = _lua_spans(text)
    if unterminated:
        return None
    depth, repeats = _block_balance(text, spans)
    if depth or repeats:
        return None

    prose = _prose_chars(text, spans)
    if prose < _MIN_PROSE_CHARS or prose / len(raw) < _MIN_PROSE_RATIO:
        return None

    hazard = _normalise_is_harmless(text, spans)
    if hazard is not None:
        raise SourceError(
            f"{_NAME}: {ident} has {hazard}. normalise() collapses runs of "
            "two or more blank lines and strips trailing whitespace, which is "
            "cosmetic in a description block and is content inside a payload. "
            "No file upstream did this when this adapter was written, which is "
            "why the check can afford to raise. If nmap now ships payloads in "
            "long strings, slice them out verbatim the way nuclei.py does "
            "rather than widening this check to tolerate the damage."
        )
    return text, _declared_licence(text)


def _sha256(path: Path) -> str:
    """Digest of a file, read a megabyte at a time."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def _extract(archive: Path, staging: Path) -> dict[str, object]:
    """Unpack the two Lua trees and the licence texts into ``staging``.

    Members are copied out by hand rather than with ``TarFile.extractall``.
    An archive member is attacker-controlled data in principle — absolute
    paths, ``..`` segments, symlinks and hardlinks are all expressible in tar —
    and the cheap defence is never to hand an archive's own names to the
    filesystem unchecked. Only regular files are written, and every destination
    is proved to resolve inside ``staging`` first. Dropping non-regular members
    also means no symlink ever reaches the cache, which is the condition
    :func:`_documents` then relies on.
    """
    files_root = staging / "files"
    files_root.mkdir(parents=True, exist_ok=True)
    resolved_root = files_root.resolve()
    licence_dir = staging / "licenses"
    licence_dir.mkdir(parents=True, exist_ok=True)

    seen = kept = 0
    licences: list[str] = []
    per_tree: dict[str, int] = {directory: 0 for directory, _ in _KEEP}
    per_licence: dict[str, int] = {}
    permissive: list[str] = []

    try:
        with tarfile.open(archive, mode="r:gz") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                parts = Path(member.name).parts
                if len(parts) < 2:
                    continue
                # Drop the archive's single root directory, "nmap-master/",
                # so the paths below read the way the repository does.
                relative = Path(*parts[1:])
                if relative.is_absolute() or ".." in relative.parts:
                    continue

                if relative.as_posix() in _LICENCE_FILES:
                    handle = tar.extractfile(member)
                    if handle is not None:
                        with handle:
                            (licence_dir / relative.name).write_bytes(handle.read())
                        licences.append(relative.as_posix())
                    continue

                if not _wanted(relative):
                    continue
                seen += 1
                if member.size > _MAX_BYTES:
                    continue
                handle = tar.extractfile(member)
                if handle is None:
                    continue
                with handle:
                    raw = handle.read()
                admitted = _admit(raw, relative.as_posix())
                if admitted is None:
                    continue
                text, licence = admitted

                target = files_root / relative
                if not target.resolve().is_relative_to(resolved_root):
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                # Re-encoded from the decoded text rather than copied as bytes,
                # so what lands in the cache is exactly what _admit proved to be
                # valid UTF-8 and balanced Lua.
                target.write_text(text, encoding="utf-8")
                kept += 1
                per_tree[relative.parts[0]] += 1
                per_licence[licence] = per_licence.get(licence, 0) + 1
                if licence != _REPOSITORY_LICENCE:
                    permissive.append(f"{relative.as_posix()} [{licence}]")
    except (tarfile.TarError, OSError) as exc:
        raise SourceError(f"{_NAME}: could not unpack the nmap archive: {exc}") from exc

    missing = [name for name in _LICENCE_FILES if name not in licences]
    if missing:
        raise SourceError(
            f"{_NAME}: the nmap archive no longer ships {', '.join(missing)}. "
            "This source carries the most restrictive licence in the package — "
            "the Nmap Public Source License, GPL-2.0 plus additional terms — "
            "and it keeps the upstream text on disk so the declaration can be "
            "checked against the download. An upstream that has moved or "
            "dropped its own licence file needs a human to read the new one, "
            "not a default."
        )
    for directory, floor in (("scripts", 500), ("nselib", 100)):
        if per_tree[directory] < floor:
            raise SourceError(
                f"{_NAME}: {directory}/ yielded only {per_tree[directory]} "
                f"files (expected at least {floor}; upstream had 610 scripts "
                "and 132 nselib modules when this adapter was written). The "
                "layout has probably changed — fix _KEEP rather than training "
                "on a fraction of the engine."
            )

    return {
        "candidates": seen,
        "kept": kept,
        "per_tree": per_tree,
        "per_license": per_licence,
        # Listed by name, not merely counted. These are the files that survive
        # if the NPSL text is ever dropped from this corpus, and re-deriving
        # that list by hand is exactly the work this line exists to save.
        "permissively_licensed_files": sorted(permissive),
    }


def _fetch(cache_dir: Path) -> Path:
    """Download nmap, filter it, and leave a curated Lua tree in the cache.

    Idempotent and network-free on re-run: the marker is written last, after the
    staging tree has been swapped into place, so an interrupted fetch
    re-downloads instead of leaving a half-populated ``files/`` that a later run
    would mistake for a finished extraction.

    The archive is deleted as soon as it is unpacked. It is 16.7 MB of mostly
    C, and what survives is ~7 MB of Lua; keeping it would be paying disk to
    avoid a download that only happens once.

    Accepts either the per-source directory ``build.py`` hands it
    (``<cache>/nselua``) or the cache root, so running this by hand during
    development shares one cache with a real build instead of scattering
    ``files/`` across the tree.
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

    archive = root / ".nmap.tar.gz.part"
    try:
        try:
            download(_ARCHIVE, archive, timeout=600, max_bytes=_MAX_ARCHIVE_BYTES)
        except NetworkError as exc:
            raise SourceError(f"{_NAME}: {exc}") from None
        try:
            digest = _sha256(archive)
            manifest = _extract(archive, staging)
        finally:
            archive.unlink(missing_ok=True)

        shutil.rmtree(files_dir, ignore_errors=True)
        (staging / "files").replace(files_dir)
        shutil.rmtree(root / "licenses", ignore_errors=True)
        (staging / "licenses").replace(root / "licenses")
        marker.write_text(
            json.dumps(
                {
                    "cache_version": _CACHE_VERSION,
                    "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "repo": _REPO,
                    "archive_url": _ARCHIVE,
                    "archive_sha256": digest,
                    # Spelled out rather than implied. GitHub publishes no hash
                    # for a branch tarball, so this digest records *which*
                    # snapshot of a moving target is on disk and proves nothing
                    # about whether it is the one upstream meant to serve. A
                    # marker that left the distinction out would read as if the
                    # bytes had been verified.
                    "sha256_verified": False,
                    "license": _LICENCE_SUMMARY,
                    "license_files": sorted(Path(name).name for name in _LICENCE_FILES),
                    **manifest,
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

def _header(relative: Path) -> str:
    """Two comment lines of provenance, so the document stays valid Lua.

    The script's *name* is the identifier a person types, and it is not
    reliably inside the file: 85 of 611 scripts carry no ``@usage`` line at all,
    and nselib modules never name themselves. Putting it in invocation position
    — ``nmap --script ssl-heartbleed``, ``local smb = require "smb"`` — gives
    every document the identifier-beside-its-use shape that the tokenizer
    measurement rewarded, and gives it to the 85 that would otherwise have the
    name only as a filename nobody kept.

    Written as comments rather than as a prose preamble on purpose: every
    document this source emits is then still a syntactically complete Lua
    chunk, which is what lets :func:`_documents` re-lex the finished text
    instead of only the part it did not write. Both lines vary in their
    meaningful slot, so ``boilerplate.py`` — which drops long, mostly-alphabetic
    lines recurring across 25 or more documents — leaves them alone.
    """
    name = relative.stem
    if relative.parts[0] == "scripts":
        return (f"-- nmap NSE script: {name}  (nmap/{relative.as_posix()})\n"
                f"-- run: nmap --script {name} <target>\n")
    return (f"-- nmap NSE library: {name}  (nmap/{relative.as_posix()})\n"
            f'-- use: local {name} = require "{name}"\n')


def _documents(path: Path) -> Iterator[Document]:
    """Yield one Document per cached file, verbatim under a two-line header.

    **Symlinks are never followed.** ``os.walk(followlinks=False)`` rather than
    ``rglob``, for the reason :mod:`~training.corpus.sources.ownrepos` records
    the hard way: a sibling adapter once walked a symlink into the external
    corpus cache and pulled 180 MB of other sources back in under its own
    label. ``_extract`` writes only regular files, so this tree should contain
    no links at all — which is exactly the situation in which an unexamined
    ``rglob`` survives review and then does not survive the day someone points
    a symlink at the cache.

    Two invariants are proved after ``normalise`` has run, and both raise:

    * the non-blank right-stripped lines must be unchanged, which says no
      leading or internal whitespace moved anywhere in the file;
    * the Lua must still lex and still balance.

    Every file here was proved balanced before it was cached, so a failure now
    cannot be bad input — it can only be the shared normaliser breaking its own
    contract. Skipping would turn that into a slightly smaller document count,
    which is the kind of silent corpus damage this project keeps discovering
    afterwards.

    Deduplication is by :func:`~training.corpus.source.fingerprint`, which is
    whitespace-insensitive and case-folded. nmap contains no duplicates today —
    measured, zero collisions across 744 files — but a source that hands
    ``build.py`` duplicates is a source whose own report is wrong, and the
    ``*-brute.nse`` family is one refactor away from producing a pair.
    """
    root = path / "files" if (path / "files").is_dir() else path
    seen: set[str] = set()

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(
            name for name in dirnames if not Path(dirpath, name).is_symlink()
        )
        for filename in sorted(filenames):
            if not filename.endswith((".nse", ".lua")):
                continue
            file = Path(dirpath, filename)
            if file.is_symlink():
                continue
            try:
                raw = file.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            relative = file.relative_to(root)
            ident = relative.as_posix()
            document = _header(relative) + raw
            text = normalise(document)

            if _content_lines(text) != _content_lines(document):
                raise SourceError(
                    f"{_NAME}: normalise() changed the content of {ident}, not "
                    "just its trailing whitespace and blank lines. In an NSE "
                    "script the @output block is a column-aligned transcript of "
                    "what nmap prints, and that alignment is the single "
                    "highest-scoring register this corpus has. Fix normalise(); "
                    "do not filter around this."
                )
            spans, unterminated = _lua_spans(text)
            depth, repeats = _block_balance(text, spans)
            if unterminated or depth or repeats:
                raise SourceError(
                    f"{_NAME}: {ident} lexed as balanced Lua before normalise() "
                    f"and not after (depth {depth}, repeat {repeats}, "
                    f"unterminated long bracket: {unterminated}). That can only "
                    "mean the normaliser altered a string or comment delimiter."
                )

            mark = fingerprint(text)
            if mark in seen:
                continue
            seen.add(mark)

            yield Document(
                text=text,
                source=_NAME,
                register=Register.SYSTEM,
                side=Side.RED,
                ident=ident,
            )


#: Stated in full sentences rather than as an SPDX tag because there is no SPDX
#: tag that carries it, and because ``build.py`` prints this string and writes
#: it into ``provenance.json`` — which is the one place a reader is guaranteed
#: to meet the terms before shipping anything built from this corpus.
_LICENCE_SUMMARY = (
    "Nmap Public Source License Version 0.95 (NPSL), read from the "
    "repository's own LICENSE file. NOT a standard permissive licence and NOT "
    "OSI-approved: section 2 licenses the software under GPL-2.0 (reproduced "
    "as Exhibit A) plus additional terms that take precedence over it, so "
    "Covered Software and derivatives may not be redistributed under plain GPL "
    "terms without the licensor's permission; section 3 defines 'derivative "
    "work' expansively, covering integrating the source, reading nmap's data "
    "files, or being designed to execute nmap and parse its results; section 6 "
    "requires an attribution notice linking to nmap.org from anything that "
    "externally deploys it; sections 7-9 grant no trademark rights, terminate "
    "on a patent action, and fix venue in the Northern District of California. "
    "The preamble directs companies incorporating it into their own products "
    "to the commercial Nmap OEM licence instead. This is therefore copyleft and "
    "source-available, and is the most encumbered upstream in this corpus — "
    "more so than GTFOBins (GPL-3.0-only) or the source-available Elastic rules "
    "in yara. 14 of the 742 files are exceptions carrying their own permissive "
    "terms: 13 under the Simplified 2-clause BSD licence (confirmed by nmap's "
    "docs/3rd-party-licenses.txt) and one under BSD-2-Clause-Patent; they are "
    "listed by name in the cache marker. LICENSE, docs/licenses/BSD-simplified "
    "and docs/3rd-party-licenses.txt are copied into the cache under licenses/ "
    "so every claim here is checkable against the download. To exclude this "
    "source without touching anything else, rename the module to _nselua.py: "
    "discover_sources() skips a leading underscore."
)


SPEC = SourceSpec(
    name=_NAME,
    license=_LICENCE_SUMMARY,
    url=_REPO,
    register=Register.SYSTEM,
    side=Side.RED,
    fetch=_fetch,
    documents=_documents,
    #: 742 files survived every gate when this adapter was written — 610 of 611
    #: scripts and 132 of 133 nselib modules, 7.07 MB — and none were
    #: near-duplicates of each other. The floor sits about 20% under that so
    #: ordinary churn is quiet while a tree vanishing is not. The sharper guards
    #: run earlier and name the culprit: see the per-tree floors in _extract.
    expect_min_docs=600,
    notes=(
        "Every nmap NSE script (scripts/*.nse) and every NSE library module "
        "(nselib/*.lua), emitted verbatim under a two-line Lua comment giving "
        "the script name in invocation position. Each script carries nmap's "
        "mandatory header — a description block, a sample command line and a "
        "column-aligned transcript of the output it produces — directly above "
        "the probe logic that produces it; @output blocks alone are 26% of "
        "script bytes, and the median file is 35% prose. nselib/data/ is "
        "excluded as generated lookup and signature tables (1.04 MB, of which "
        "962 KB is two Unicode and web-fingerprint databases), costing seven "
        "smb-psexec configuration stubs. Files are admitted only after a "
        "hand-written Lua lexer proves them lexically sound and block-balanced "
        "(there is no Lua parser in the stdlib and compile() parses only "
        "Python), and only if normalise() provably cannot alter a non-"
        "description string literal; both properties are re-proved after "
        "normalise() runs, and a failure raises rather than dropping the file."
    ),
)
