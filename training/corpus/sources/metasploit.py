"""Metasploit Framework modules — how a named vulnerability is actually used.

ADVERSARY is the scarcest register in this corpus and the one the 60/40
offence weighting exists to buy. :mod:`~training.corpus.sources.capec` argues
that scarcity there is the binding constraint on the whole balancer, and CAPEC
answers it with *abstract* attack patterns: a pattern names a class of attack
and walks it in order. This source answers the other half. Metasploit module
metadata is the largest body of freely licensed prose that explains, in
sentences, how one *specific real* vulnerability is exploited in sequence —
which product and which versions, what has to be true before you start, what
the module does to the target, how often it works and what it leaves behind.

Four things make it worth a dedicated adapter rather than another scrape:

**It is the only source here that pairs an exploit narrative with an exploit
outcome.** ``Notes`` carries ``Stability``, ``Reliability`` and ``SideEffects``
as a closed vocabulary — ``CRASH_SERVICE_DOWN``, ``IOC_IN_LOGS``,
``ARTIFACTS_ON_DISK``, ``ACCOUNT_LOCKOUTS``. For a purple model those are not
trivia, they are the *observable trace*: the side effect a red module admits to
is precisely the artefact a blue detection has to key on. Nothing else in the
corpus states, for four thousand concrete attacks, what the attack leaves on
disk and in the log. So the constants are glossed into plain English and the
upstream token is kept beside the gloss — "writes files to the target's disk
(artifacts-on-disk)" — for the same reason ATT&CK ids are written beside their
names everywhere else here: the model should meet the identifier and its
meaning in one window, not in two different documents.

**The identifiers are dense, real, and already joined to the thing they
denote.** 3,488 ``CVE`` references, 1,571 ``OSVDB``, 980 ``BID``, 924 ``EDB``,
224 ``ZDI``, 185 ``MSB`` and 5,460 bare URLs, every one of them sitting a few
lines under the human name of the vulnerability it identifies. Metasploit
stores them split — ``['CVE', '2020-9496']`` — so a naive render would emit a
bare year-number pair and not one usable identifier; they are written back into
the wild form (``CVE-2020-9496``, ``EDB-12345``, ``MS17-010``) that the world,
and gpt2, actually writes. 307 of the references go one better and name an
ATT&CK technique, and they are the reason the reference parser has to
understand Ruby constants rather than strings: the value is
``Mitre::Attack::Technique::T1003_001_LSASS_MEMORY``, which decodes to
``T1003.001 LSASS Memory`` — an id beside the name it denotes, which is the
precise pairing the tokenizer measurement singled out, and which a string-only
parser silently replaces with the literal word "ATT&CK".

**The metadata is prose, not a schema.** ``Description`` is a hand-written
paragraph explaining the bug and the mechanism, which is exactly the register
the tokenizer measurement in :mod:`~training.corpus.source` found gpt2 winning
on. Median description length is 353 characters for exploits and 220 for
auxiliary modules.

**A second, independent tree of text exists for half of them.**
``documentation/modules/`` holds markdown with the setup a target needs, the
verification steps an operator runs, and console transcripts. 2,040 of the
modules kept here have one, and its "Vulnerable Application" section is the
"what must be true first" that the Ruby metadata never states.

**What is left out, and why.** Three of the module trees are skipped:
``payloads/`` (median description 53 characters), ``encoders/`` (99) and
``nops/`` (20). They describe the *framework's own machinery* — how a payload
is staged, how a sled is generated — rather than how a vulnerability is
exploited, their descriptions are one-liners, and they are heavily
near-duplicated across every architecture and transport variant. Duplicated
text in a small corpus is worse than absent text, which is the same argument
that keeps ``rules-emerging-threats`` out of :mod:`~training.corpus.sources.sigma`.
``Author`` is parsed but never emitted: it is handles and email addresses, it
carries no register the corpus wants, and a training corpus is a poor place to
put a few thousand people's contact details.

**Licence, stated carefully.** The framework is BSD-3-Clause, Copyright
2006-2026 Rapid7, Inc. — but its ``LICENSE`` is a Debian-copyright file with a
long list of per-file exceptions, and six of those exceptions are Ruby files
*inside* ``modules/`` that are GPL or GPLv2 rather than BSD. Declaring
"BSD-3-Clause" while quietly training on GPL text would make the declaration
false, so the exception stanzas are parsed out of the shipped ``LICENSE`` at
build time and every non-BSD path under ``modules/`` is dropped from the corpus.
The parse is unioned with a hardcoded floor of the paths known to be excepted,
so a LICENSE reformat upstream can only ever add exclusions, never silently
lose them.

**Why this one clones instead of taking a tarball.** Every other git-backed
source here pulls a codeload tarball, and that is the right default: one
request, no history, no git binary. It does not survive this repository. The
working tree is over a gigabyte — ``data/`` alone carries wordlists, templates
and prebuilt binaries — and the two trees this adapter reads are 52 MB of it. A
``--depth 1 --filter=blob:none --sparse`` clone followed by a sparse-checkout
limited to ``modules/`` and ``documentation/modules/`` fetches blobs only for
the paths asked for: 69 MB on disk including the object store, against roughly
a gigabyte for the tarball. TLS here belongs to ``git``, which reads the system
trust store; :mod:`~training.corpus.net` is deliberately *not* reached for a
context, because its whole purpose is that nobody grows a private trust store,
and shelling out to git grows none. Its user agent is reused so the request
still identifies this project honestly to GitHub.

**Parsing Ruby without running it.** The metadata lives inside a method call in
a live Ruby class, so there is no data file to load and no safe way to evaluate
it. What is here is a small hand-rolled lexer, not a regex sweep, and it is a
lexer because the shortcuts all fail on real modules:

* Ruby has nine string forms in these files — ``'``, ``"``, ``%q{}``, ``%Q{}``,
  ``%{}``, ``%()``, ``%q()``, ``%q||`` and one squiggly heredoc — and ``%q{}``
  nests its own braces, so brace counting has to be delimiter-aware.
* ``#`` starts a comment *outside* a string and is an interpolation sigil
  inside one, and comments in these files contain apostrophes and brackets
  (``'Alvaro Muñoz', # Discovery``), so a scanner that does not know where
  strings end will mismatch on the first author list.
* A heredoc body is out of band: ``assemble(X86_64.new, <<-ASM).encode_string``
  continues *on the opener line* after the body has been skipped. Resuming
  after the terminator instead swallows the closing paren and the whole
  metadata region reads as unbalanced. Exactly one module made this visible.
* ``/Inbox/`` as a hash value is a regexp literal, and later regexps in the
  same file contain unbalanced ``(`` and ``[``. A ``/`` is treated as a regexp
  only when the previous significant character puts the parser in value
  position, which is the standard disambiguation and is sufficient inside a
  metadata hash.
* Keys are only accepted at depth zero of the metadata hash. ``'Platform' =>
  'win'`` at the top is the module's platform; the identical key inside a
  ``Targets`` entry is one target's platform, and a flat regex search cannot
  tell them apart.
* Three call shapes exist — ``update_info(info, ...)`` (4,121 modules),
  ``merge_info(info, ...)`` (401) and a bare ``super('Name' => ...)`` inside
  ``def initialize`` — and 128 modules wrap the hash in explicit braces,
  ``update_info(info, { ... })``, which puts every key one level deeper.

The result parses 5,091 of the 5,098 Ruby modules. The seven it does not are
six payload stubs that carry no metadata at all (a ``CachedSize`` and one
``include``) and one external-module script that writes its metadata as a
top-level symbol-keyed hash. None of them are worth a second grammar, and a
module whose ``Description`` cannot be extracted is skipped rather than emitted
as a near-empty document.

**Whitespace.** ``%q{}`` bodies are indented to sit inside the Ruby source and
hard-wrapped at about eighty columns. Both are removed, and both removals are
*decoding* rather than cleaning, in the same sense that CAPEC drops the XML
file's pretty-printing indent: the ten leading spaces belong to the Ruby
literal, not to the sentence. Unwrapping is conservative — a paragraph is
rejoined only when every one of its lines is flush-left and prose-shaped, so an
indented code block, a bullet list or a table inside a description keeps its own
shape verbatim. Nothing is done to horizontal whitespace after that point;
:func:`~training.corpus.source.normalise` preserves it, and the command lines
and console transcripts that survive from the markdown are the reason to care.

Upstream: https://github.com/rapid7/metasploit-framework
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Iterator

from ..net import USER_AGENT
from ..source import Document, Register, Side, SourceError, SourceSpec, normalise

__all__ = ["SPEC"]

_REPO = "https://github.com/rapid7/metasploit-framework"
_CLONE_URL = f"{_REPO}.git"

#: Named for the source rather than "repo"/"checkout" so that a caller which
#: hands this adapter a *shared* cache root — as the verification snippet in
#: the task does — cannot collide with another source's tree or marker.
_CHECKOUT = "metasploit-framework"
_MARKER = ".metasploit.fetched.json"

#: The only two trees fetched. ``documentation/`` also holds developer guides
#: and wiki pages; only the per-module markdown is wanted, and narrowing the
#: sparse set is what keeps the clone at 69 MB.
_SPARSE_PATHS = ("modules", "documentation/modules")

#: Module trees kept, in the order they are walked. See the docstring for why
#: ``payloads``, ``encoders`` and ``nops`` are not here.
_TREES = ("auxiliary", "evasion", "exploits", "post")

#: ``modules/exploits/...`` on disk is ``exploit/...`` in msfconsole, and the
#: documentation tree uses the singular too. The canonical form is the one a
#: person types after ``use``, so that is the one written into the document.
_SINGULAR = {"exploits": "exploit", "payloads": "payload"}

#: 4,486 module files across the kept trees at the time of writing. The floor
#: is a fetch-time tripwire for an upstream reorganisation, not a target.
_MIN_MODULE_FILES = 3000

#: A description shorter than this is a stub label, not an explanation.
_MIN_DESCRIPTION = 40

#: Below this a document is the header plus a single clause that mostly
#: restates the module name ("This module simply attempts to login to a
#: Metasploit RPC interface"), with no reference, target or note hanging off
#: it. The number is measured rather than picked: a floor of 250 drops 87
#: renderings and only 11 of them carry a reference, target or side-effect
#: note, while raising it to 300 drops 176 of which 74 do — including entries
#: like `netdecision_tftp`, whose entire value is a CVE, an OSVDB id and a BID
#: sitting beside the words "directory traversal vulnerability in NetDecision
#: 4.2 TFTP service". Those are the documents this source exists to produce.
_MIN_CHARS = 250

_GIT_TIMEOUT = 900


# --------------------------------------------------------------------------
# Licence exceptions
# --------------------------------------------------------------------------

#: The non-BSD Ruby modules listed in ``LICENSE`` when this adapter was written.
#: :func:`_excluded_globs` re-derives this from the shipped file so new
#: exceptions are honoured automatically; this constant is the floor the parse
#: is unioned with, so a reformat upstream can add exclusions but never lose
#: them. Getting this wrong is not a style problem — it would make the licence
#: string on :data:`SPEC` a false statement about the training data.
_KNOWN_NON_BSD = frozenset({
    "modules/exploits/linux/local/bpf_priv_esc.rb",
    "modules/exploits/linux/local/ntfs3g_priv_esc.rb",
    "modules/exploits/unix/fileformat/metasploit_libnotify_cmd_injection.rb",
    "modules/exploits/windows/smb/ms04_007_killbill.rb",
    "modules/payloads/singles/windows/x64/messagebox.rb",
    "modules/post/linux/dos/xen_420_dos.rb",
})

_STANZA_FIELD = re.compile(r"^([A-Za-z-]+):[ \t]*(.*)$")


def _excluded_globs(license_file: Path) -> frozenset[str]:
    """Paths under ``modules/`` that ``LICENSE`` places under a non-BSD licence.

    ``LICENSE`` is a machine-readable Debian copyright file: blank-line
    separated stanzas of ``Files:``/``Copyright:``/``License:``, where ``Files``
    may continue onto indented lines and holds shell globs. Only the
    ``License`` value's first word matters here — anything that does not begin
    ``BSD-3`` is dropped, which is conservative in the right direction: an
    unrecognised or reworded licence excludes the file rather than including it.
    """
    globs = set(_KNOWN_NON_BSD)
    try:
        raw = license_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        # No LICENSE in the checkout is itself suspicious, but the hardcoded
        # floor still holds and the fetch already verified the tree.
        return frozenset(globs)

    for stanza in re.split(r"\n[ \t]*\n", raw):
        files: list[str] = []
        licence = ""
        field = ""
        for line in stanza.split("\n"):
            match = _STANZA_FIELD.match(line)
            if match:
                field, value = match.group(1).lower(), match.group(2).strip()
                if field == "files" and value:
                    files.append(value)
                elif field == "license":
                    licence = value
            elif line[:1] in (" ", "\t") and field == "files" and line.strip():
                files.append(line.strip())            # continuation line
        if not files or licence.upper().startswith("BSD-3"):
            continue
        globs.update(f for f in files if f.startswith("modules/"))
    return frozenset(globs)


# --------------------------------------------------------------------------
# A very small Ruby lexer
# --------------------------------------------------------------------------

_PAIRS = {"(": ")", "[": "]", "{": "}"}
_OPEN = "([{"
_CLOSE = ")]}"

#: Characters after which a ``/`` opens a regexp rather than dividing. Inside a
#: metadata hash a regexp only ever appears as a value or an array element, so
#: this short set is enough; the alternative is a full Ruby parser.
_VALUE_PREV = set("([{,=>~!|&?:;") | {None}

_HEREDOC = re.compile(
    r"<<([-~]?)(?:([A-Z_][A-Z_0-9]*)|'([^'\n]+)'|\"([^\"\n]+)\")"
)
#: ``%q``/``%w``/``%i`` and friends, normalised to three behaviours: ``q`` is a
#: raw literal, ``Q`` interpolates (same escapes for our purposes), ``w``/``i``
#: are whitespace-separated lists.
_PCT_KIND = {"q": "q", "Q": "Q", "w": "w", "W": "w", "i": "i", "I": "i",
             "r": "r", "s": "Q", "x": "Q"}


def _dedent(body: str) -> str:
    """Strip the common leading indent, ignoring blank lines.

    This is decoding, not cleaning: the indent belongs to the Ruby file's
    layout, never to the sentence. Relative indentation inside the literal — a
    code sample, a nested bullet — is preserved exactly.
    """
    lines = body.split("\n")
    widths = [len(l) - len(l.lstrip()) for l in lines if l.strip()]
    cut = min(widths) if widths else 0
    return "\n".join(l[cut:] if l.strip() else "" for l in lines)


class _Ruby:
    """A character scanner over one module's source.

    Not a parser: it knows only enough to find where literals and comments end
    so that bracket depth can be counted honestly. Everything it does not
    understand is consumed one character at a time, which is safe because the
    only question ever asked of it is "where does this group close".
    """

    def __init__(self, text: str) -> None:
        self.s = text
        self.n = len(text)
        #: newline position -> position after a heredoc body that hangs off it.
        #: A heredoc's body is out of band; see the module docstring.
        self._jump: dict[int, int] = {}

    # -- trivia ------------------------------------------------------------
    def skip(self, i: int) -> int:
        """Advance past whitespace, comments and pending heredoc bodies."""
        s, n = self.s, self.n
        while i < n:
            c = s[i]
            if c == "\n" and i in self._jump:
                i = self._jump[i]
            elif c in " \t\r\n":
                i += 1
            elif c == "#":
                j = s.find("\n", i)
                i = n if j < 0 else j       # stop *on* the newline: a heredoc
                                            # body may hang off it
            else:
                return i
        return i

    # -- literals ----------------------------------------------------------
    def literal(self, i: int, prev: str | None):
        """``(kind, decoded, end)`` if a string literal starts at ``i``."""
        s, n = self.s, self.n
        c = s[i]
        if c in "'\"":
            return self._quoted(i, c)
        if c == "%":
            # `"%s" % [x]` and `a % b` are modulo. A percent literal only ever
            # starts in value position, so refuse one straight after a value.
            if prev is not None and (prev.isalnum() or prev in ")]}_"):
                return None
            j = i + 1
            kind = "Q"
            if j < n and s[j] in _PCT_KIND:
                kind = _PCT_KIND[s[j]]
                j += 1
            if j >= n:
                return None
            delim = s[j]
            if delim.isalnum() or delim.isspace() or delim == "=":
                return None
            return self._percent(j, delim, kind)
        match = _HEREDOC.match(s, i)
        if match:
            return self._heredoc(match)
        return None

    def _quoted(self, i: int, quote: str):
        s, n = self.s, self.n
        out: list[str] = []
        j = i + 1
        while j < n:
            c = s[j]
            if c == "\\" and j + 1 < n:
                out.append(self._unescape(s[j + 1], quote))
                j += 2
                continue
            if c == quote:
                return ("q" if quote == "'" else "Q", "".join(out), j + 1)
            out.append(c)
            j += 1
        return None

    def _percent(self, i: int, delim: str, kind: str):
        """``%q{...}`` and friends. Paired delimiters nest; others do not."""
        s, n = self.s, self.n
        close = _PAIRS.get(delim, delim)
        nests = delim in _PAIRS
        out: list[str] = []
        depth, j = 1, i + 1
        while j < n:
            c = s[j]
            if c == "\\" and j + 1 < n:
                out.append(self._unescape(s[j + 1], "'" if kind in "qwi" else '"'))
                j += 2
                continue
            if nests and c == delim:
                depth += 1
            elif c == close:
                depth -= 1
                if depth == 0:
                    return (kind, "".join(out), j + 1)
            out.append(c)
            j += 1
        return None

    def _heredoc(self, match: re.Match[str]):
        """Consume a heredoc body, resuming **on the opener line**.

        ``assemble(X86_64.new, <<-ASM).encode_string`` is the case that forces
        this: the call's closing paren sits after the ``<<-ASM`` token, not
        after the terminator. Resuming past the terminator eats that paren and
        the enclosing ``update_info(`` never appears to close.
        """
        s, n = self.s, self.n
        tag = match.group(2) or match.group(3) or match.group(4)
        newline = s.find("\n", match.end())
        if newline < 0:
            return None
        lines: list[str] = []
        j = newline + 1
        while j <= n:
            end = s.find("\n", j)
            if end < 0:
                end = n
            if s[j:end].strip() == tag:
                body = "\n".join(lines)
                if match.group(1) == "~":
                    body = _dedent(body)
                self._jump[newline] = end + 1
                return ("h", body, match.end())
            lines.append(s[j:end])
            if end >= n:
                break
            j = end + 1
        return None

    @staticmethod
    def _unescape(c: str, quote: str) -> str:
        if quote == "'":
            # Single-quoted Ruby has exactly two escapes; everything else is a
            # literal backslash and must survive (Windows paths, regexes).
            return c if c in ("'", "\\") else "\\" + c
        return {"n": "\n", "t": "\t", "r": "\r", "s": " ",
                "0": "", "e": "", "a": "", "b": ""}.get(c, c)

    def _regexp(self, i: int) -> int | None:
        """End of a ``/.../`` literal, or None if it does not close on the line."""
        s, n = self.s, self.n
        j = i + 1
        in_class = False
        while j < n:
            c = s[j]
            if c == "\\":
                j += 2
                continue
            if c == "\n":
                return None
            if c == "[":
                in_class = True
            elif c == "]":
                in_class = False
            elif c == "/" and not in_class:
                j += 1
                while j < n and s[j] in "imxounse":
                    j += 1
                return j
            j += 1
        return None

    # -- one lexical unit --------------------------------------------------
    def step(self, i: int, prev: str | None):
        """``(next_i, kind, payload, prev)``; kind is open/close/comma/str/other."""
        s, n = self.s, self.n
        i = self.skip(i)
        if i >= n:
            return None
        lit = self.literal(i, prev)
        if lit is not None and lit[2] > i:
            return (lit[2], "str", lit, '"')
        c = s[i]
        if c == "/" and prev in _VALUE_PREV:
            end = self._regexp(i)
            if end is not None:
                return (end, "other", None, "/")
        if c in _OPEN:
            return (i + 1, "open", c, c)
        if c in _CLOSE:
            return (i + 1, "close", c, c)
        if c == ",":
            return (i + 1, "comma", c, c)
        return (i + 1, "other", c, c)

    def group(self, i: int):
        """``i`` is on an opener; ``(inner_start, inner_end, after)``."""
        depth, prev, j = 0, None, i
        while True:
            step = self.step(j, prev)
            if step is None:
                return None
            j, kind, _, prev = step
            if kind == "open":
                depth += 1
            elif kind == "close":
                depth -= 1
                if depth == 0:
                    return (i + 1, j - 1, j)


def _pairs(rb: _Ruby, start: int, end: int) -> list[tuple[str, str, object]]:
    """``'Key' => value`` pairs at depth zero of ``[start, end)``.

    Depth matters more than it looks. ``'Platform'`` appears both as the
    module's own platform and inside every ``Targets`` entry; taking the first
    regex hit would report a single target's platform as the module's.
    """
    s = rb.s
    out: list[tuple[str, str, object]] = []
    i, depth, prev = start, 0, None
    while i < end:
        step = rb.step(i, prev)
        if step is None:
            break
        j, kind, payload, prev = step
        if j > end:
            break
        if kind == "open":
            depth += 1
        elif kind == "close":
            depth -= 1
            if depth < 0:
                break
        elif kind == "str" and depth == 0 and payload[0] in "qQ":
            k = rb.skip(j)
            if s.startswith("=>", k):
                got = _value(rb, rb.skip(k + 2), end)
                if got is not None:
                    out.append((payload[1], got[0], got[1]))
                    i, prev = got[2], ","
                    continue
        i = j
    return out


def _value(rb: _Ruby, i: int, end: int):
    """``(kind, payload, after)`` for one hash value.

    ``str`` payloads are decoded text; ``list`` and ``hash`` payloads are the
    ``(start, end)`` span of the group's interior, re-scanned lazily by the
    caller that actually wants it; ``code`` is the raw source of a bare
    expression such as ``MSF_LICENSE`` or ``ARCH_X64``.
    """
    s = rb.s
    if i >= end:
        return None
    lit = rb.literal(i, None)
    if lit is not None and lit[2] > i:
        kind, body, j = lit
        if kind in "wi":                       # %w[win linux] is already a list
            return ("words", body.split(), j)
        return ("str", body, j)
    if s[i] in "[{":
        group = rb.group(i)
        if group is None:
            return None
        return ("list" if s[i] == "[" else "hash", (group[0], group[1]), group[2])

    j, depth, prev = i, 0, None
    while j < end:
        step = rb.step(j, prev)
        if step is None:
            break
        nxt, kind, _, char = step
        if kind == "open":
            depth += 1
        elif kind == "close":
            if depth == 0:
                break
            depth -= 1
        elif kind == "comma" and depth == 0:
            break
        j, prev = nxt, char
    return ("code", s[i:j].strip(), j)


def _items(rb: _Ruby, start: int, end: int) -> list[tuple[str, object]]:
    """Top-level elements of an array body."""
    out: list[tuple[str, object]] = []
    i = start
    while i < end:
        i = rb.skip(i)
        if i >= end:
            break
        if rb.s[i] == ",":
            i += 1
            continue
        got = _value(rb, i, end)
        if got is None or got[2] <= i:
            i += 1
            continue
        out.append((got[0], got[1]))
        i = got[2]
    return out


_META_CALL = re.compile(r"\b(?:update_info|merge_info)\s*\(")
_BARE_SUPER = re.compile(r"\bdef\s+initialize\b[^\n]*\n\s*super\s*\(")


def _region(text: str):
    """Locate the metadata hash: ``(scanner, start, end)`` or None.

    Tries ``update_info(``/``merge_info(`` first and a bare ``super(`` inside
    ``def initialize`` second, then descends through the optional ``info,``
    argument into an explicit ``{ ... }`` wrapper if one is present — 128
    modules use that form and without the descent every key sits at depth one
    and nothing is found.
    """
    rb = _Ruby(text)
    for pattern in (_META_CALL, _BARE_SUPER):
        for match in pattern.finditer(text):
            group = rb.group(match.end() - 1)
            if group is None:
                continue
            start, end = group[0], group[1]
            k = rb.skip(start)
            if text.startswith("info", k):
                k = rb.skip(k + 4)
            if k < end and text[k] == ",":
                k = rb.skip(k + 1)
            if k < end and text[k] == "{":
                inner = rb.group(k)
                if inner is not None:
                    return rb, inner[0], inner[1]
            return rb, start, end
    return None


# --------------------------------------------------------------------------
# Glosses
# --------------------------------------------------------------------------

#: Metasploit's exploit ranking, spelled out. The rank is the single most
#: compressed statement of "how well does this actually work", and as a bare
#: ``ExcellentRanking`` it teaches nothing.
_RANKS = {
    "Manual": "manual — needs the operator to configure it, or it is a denial of service",
    "Low": "low — succeeds on under half of attempts against the usual target",
    "Average": "average — generally unreliable or difficult to exploit",
    "Normal": "normal — reliable but version-specific, with no automatic targeting",
    "Good": "good — has a default target, or picks the right one automatically",
    "Great": "great — detects the target, or uses an application-specific return address",
    "Excellent": "excellent — never crashes the service",
}

#: ``Notes`` constants. These three tables are the reason this source is here:
#: each entry is a red module stating, in a closed vocabulary, the trace it
#: leaves — which is what a detection has to look for.
_STABILITY = {
    "CRASH_SAFE": "the target service is not expected to crash",
    "CRASH_SERVICE_RESTARTS": "the target service crashes but restarts itself",
    "CRASH_SERVICE_DOWN": "the target service crashes and stays down",
    "CRASH_OS_RESTARTS": "the target operating system crashes and reboots",
    "CRASH_OS_DOWN": "the target operating system crashes and stays down",
    "SERVICE_RESOURCE_LOSS": "the target service leaks a resource it does not get back",
    "OS_RESOURCE_LOSS": "the target operating system leaks a resource it does not get back",
}
_RELIABILITY = {
    "FIRST_ATTEMPT_FAIL": "the first attempt is expected to fail",
    "REPEATABLE_SESSION": "it can be run repeatedly to get another session",
    "UNRELIABLE_SESSION": "the session it returns may not be stable",
    "EVENT_DEPENDENT": "it only fires when some event happens on the target",
}
_SIDE_EFFECTS = {
    "ARTIFACTS_ON_DISK": "writes files to the target's disk",
    "CONFIG_CHANGES": "changes configuration on the target",
    "IOC_IN_LOGS": "leaves indicators in the target's logs",
    "ACCOUNT_LOCKOUTS": "can lock accounts out",
    "ACCOUNT_LOGOUT": "logs an existing user out",
    "SCREEN_EFFECTS": "is visible on the target's screen",
    "AUDIO_EFFECTS": "is audible on the target",
    "PHYSICAL_EFFECTS": "has a physical effect on the target's hardware",
}
_NOTE_TABLES = {"Stability": ("stability", _STABILITY),
                "Reliability": ("reliability", _RELIABILITY),
                "SideEffects": ("side effects", _SIDE_EFFECTS)}

#: ``LOGO`` and ``SOUNDTRACK`` are a running joke in the framework — they point
#: at an image and a YouTube video. They are references to nothing.
_REF_SKIP = frozenset({"LOGO", "SOUNDTRACK"})

#: Reference types whose value already carries its own prefix, so prefixing
#: again would invent an identifier nobody writes (``MSB-MS17-010``).
_REF_BARE = frozenset({"MSB"})

#: 307 references across 201 modules give an ATT&CK technique id as a Ruby
#: *constant* rather than a string:
#: ``['ATT&CK', Mitre::Attack::Technique::T1210_EXPLOITATION_OF_REMOTE_SERVICES]``.
#: This is the most valuable single join in the source and it is invisible to
#: any string-only parser — which emitted the literal word "ATT&CK" 307 times
#: and threw the technique away. The constant carries both halves of exactly
#: the pairing the tokenizer measurement in
#: :mod:`~training.corpus.source` singled out: ``T1547.001`` beside "Registry
#: Run Keys" moved that sample from -45% to +13% against gpt2.
_ATTACK_CONST = re.compile(
    r"\bMitre::Attack::Technique::T(\d{4})(?:_(\d{3}))?_([A-Z0-9_]+)\b"
)

#: The constant is SHOUTING_SNAKE_CASE, so the original capitalisation of the
#: technique name is not recoverable from it. Title-casing every word would
#: produce "Lsass Memory" and "Os Credential Dumping", which is a *worse*
#: surface form than the real one, so the words that are acronyms or lower-case
#: in ATT&CK's own naming are listed. The list is closed: it covers every
#: non-ordinary word in the 84 distinct constants upstream currently uses, and
#: an unlisted word simply falls through to title case.
_ATTACK_WORDS = {
    "BITS": "BITS", "DCSYNC": "DCSync", "ETC": "etc", "LSA": "LSA",
    "LSASS": "LSASS", "NTDS": "NTDS", "OS": "OS", "PASSWD": "passwd",
    "PLIST": "Plist", "POWERSHELL": "PowerShell", "PROC": "proc",
    "RC": "rc", "SMB": "SMB", "SSH": "SSH", "SYSTEMD": "systemd",
    "UDEV": "udev", "VNC": "VNC", "XDG": "XDG",
}
_ATTACK_MINOR = frozenset({"AND", "AT", "FOR", "FROM", "IN", "OF", "OR", "THE"})

#: ``UNKNOWN_STABILITY`` and friends mean "the author did not say", and about
#: half of all modules carry all three. Rendering them produces three lines of
#: "unknown" per document — 2,000 documents' worth of text that states nothing.
#: They are dropped, and a note category left with nothing is dropped whole.
_UNKNOWN_NOTE = "UNKNOWN_"


# --------------------------------------------------------------------------
# Prose assembly
# --------------------------------------------------------------------------

_LIST_LINE = re.compile(r"^\s*(?:[-*+o]\s|\d+[.)]\s|#{1,6}\s|>\s|\|)")
_FENCE = re.compile(r"^\s*(?:```|~~~)")


def _unwrap(text: str) -> str:
    """Undo the Ruby literal's indent and its hard wrapping, conservatively.

    A run of lines is rejoined into one paragraph only when every line in it is
    flush-left after dedenting and does not look like a list item, heading,
    quote or table row. Anything indented relative to the block is left exactly
    as written, which is what keeps the occasional embedded command, request
    transcript or bullet list from being smeared into a single line. Blank
    lines stay as paragraph breaks.

    **Fenced blocks are never joined**, regardless of how their lines are
    indented, and this is not a nicety. Module descriptions and the companion
    markdown both embed ``msf >`` console transcripts and request/response
    dumps inside ``` fences, and those start at column zero — so the
    flush-left test alone happily smeared a whole IPMI scanner session onto one
    line. That is exactly the damage
    :func:`~training.corpus.source.normalise` refuses to do to column-aligned
    command output, undone one layer higher up; it is no better here for being
    done by a source adapter.
    """
    text = _dedent(text.strip("\n")).strip()
    out: list[str] = []
    buf: list[str] = []
    fenced = False

    def flush() -> None:
        if buf:
            out.append(" ".join(buf))
            buf.clear()

    for line in text.split("\n"):
        if _FENCE.match(line):
            flush()
            out.append(line.rstrip())
            fenced = not fenced
            continue
        if fenced:
            flush()
            out.append(line.rstrip())
            continue
        if not line.strip():
            flush()
            out.append("")
            continue
        if line[:1] not in " \t" and not _LIST_LINE.match(line):
            buf.append(line.strip())
        else:
            flush()
            out.append(line.rstrip())
    flush()
    return "\n".join(out).strip()


def _flatten(rb: _Ruby, field, strip_prefix: str = "") -> list[str]:
    """A scalar-or-array field as a de-duplicated list of strings."""
    if field is None:
        return []
    kind, payload = field
    if kind in ("str", "code"):
        raw = [payload]
    elif kind == "words":
        raw = list(payload)
    elif kind == "list" and isinstance(payload, tuple):
        raw = [p for k, p in _items(rb, payload[0], payload[1])
               if k in ("str", "code") and isinstance(p, str)]
    else:
        return []
    out: list[str] = []
    for item in raw:
        item = item.strip().strip(",").strip()
        if strip_prefix and item.startswith(strip_prefix):
            item = item[len(strip_prefix):].lower()
        if item and item not in out:
            out.append(item)
    return out


def _attack_name(match: re.Match[str]) -> str:
    """``T1003_001_LSASS_MEMORY`` -> ``T1003.001 LSASS Memory``.

    The dotted sub-technique form is the one MITRE publishes and the one every
    other source in this corpus writes, so the constant's underscore is
    translated back rather than left as a second spelling of the same id.
    """
    technique = f"T{match.group(1)}"
    if match.group(2):
        technique += f".{match.group(2)}"
    words: list[str] = []
    for index, word in enumerate(match.group(3).split("_")):
        if word in _ATTACK_WORDS:
            words.append(_ATTACK_WORDS[word])
        elif index and word in _ATTACK_MINOR:
            words.append(word.lower())
        else:
            words.append(word.capitalize())
    return f"{technique} {' '.join(words)}"


def _references(rb: _Ruby, span: tuple[int, int]) -> list[str]:
    """``[['CVE', '2020-9496'], ...]`` rendered as identifiers people write.

    Metasploit stores the type and the value apart, so the raw data holds no
    usable identifier at all — ``'2020-9496'`` on its own is a token the model
    will never meet again. Rejoining them is the whole point of this field.
    """
    out: list[str] = []
    for kind, payload in _items(rb, span[0], span[1]):
        if kind == "str" and isinstance(payload, str) and payload.strip():
            out.append(payload.strip())
            continue
        if kind != "list" or not isinstance(payload, tuple):
            continue
        parts = [(k, p) for k, p in _items(rb, payload[0], payload[1])
                 if k in ("str", "code") and isinstance(p, str) and p.strip()]
        if len(parts) == 1 and parts[0][0] == "str":
            out.append(parts[0][1].strip())
            continue
        if len(parts) < 2 or parts[0][0] != "str":
            continue
        kind_name = parts[0][1].strip().upper()
        value_kind, value = parts[1][0], parts[1][1].strip()
        if not value or kind_name in _REF_SKIP:
            continue
        if value_kind == "code":
            # A bare Ruby constant. The ATT&CK ones decode into an identifier
            # and a name; anything else is a symbol this adapter cannot
            # resolve, and emitting the reference *type* on its own would put
            # the word "ATT&CK" in the corpus where a technique id belongs.
            attack = _ATTACK_CONST.search(value)
            if attack is not None:
                out.append(f"ATT&CK {_attack_name(attack)}")
            continue
        if kind_name == "URL":
            out.append(value)
        elif kind_name == "AKA":
            out.append(f"also known as {value}")
        elif kind_name in _REF_BARE or value.upper().startswith(kind_name):
            out.append(value)
        else:
            out.append(f"{kind_name}-{value}")
    seen: set[str] = set()
    unique: list[str] = []
    for item in out:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


def _targets(rb: _Ruby, span: tuple[int, int]) -> list[str]:
    """The *names* of a module's targets: ``['Windows 7 SP1 x64', {...}]``.

    Only the name survives. The hash beside it is return addresses, offsets and
    default options — real data, but it is Ruby constants and hex, and the
    register this source is budgeted against is prose.
    """
    names: list[str] = []
    for kind, payload in _items(rb, span[0], span[1]):
        if kind == "list" and isinstance(payload, tuple):
            inner = _items(rb, payload[0], payload[1])
            if inner and inner[0][0] == "str" and str(inner[0][1]).strip():
                names.append(str(inner[0][1]).strip())
        elif kind == "str" and isinstance(payload, str) and payload.strip():
            names.append(payload.strip())
    return names


def _note_tokens(rb: _Ruby, kind: str, payload: object) -> list[str]:
    """One ``Notes`` value as a list of strings, whatever shape it arrived in."""
    if kind == "list" and isinstance(payload, tuple):
        return [str(p).strip() for k, p in _items(rb, payload[0], payload[1])
                if k in ("str", "code") and isinstance(p, str) and p.strip()]
    if kind in ("str", "code") and isinstance(payload, str) and payload.strip():
        return [payload.strip()]
    if kind == "words" and isinstance(payload, list):
        return [str(p) for p in payload]
    return []


def _notes(rb: _Ruby, span: tuple[int, int]) -> dict[str, list[str]]:
    """``Notes`` glossed into sentences, with the upstream token kept beside it.

    ``IOC_IN_LOGS`` alone is unreadable; "leaves indicators in the target's
    logs" alone throws away a token that appears four thousand times in real
    module source. Emitting both puts the identifier and its meaning in the
    same window, which is the argument this whole corpus is built on.

    ``AKA`` is the other reason to parse this hash. It carries the name people
    actually use for an attack — Shellshock, HiveNightmare, SeriousSAM,
    ETERNALBLUE — which appears nowhere else in the module and is the string a
    human would search for.

    The parts are returned apart rather than as one block because they belong
    in different places in the document. An alias is an identity fact and sits
    with the name; ``NOCVE`` and ``RelatedModules`` sit with the references
    they stand in for. Putting them all under one "reliability and side
    effects" heading produced documents headed that way whose only line was an
    alias, which is a caption that lies about its own contents.
    """
    out: dict[str, list[str]] = {"effects": [], "aka": [], "nocve": [],
                                "related": []}
    for key, kind, payload in _pairs(rb, span[0], span[1]):
        # One module writes 'Side Effects' with a space. Normalising the key
        # costs nothing and is cheaper than losing a note to a typo.
        key = key.replace(" ", "")
        tokens = _note_tokens(rb, kind, payload)
        if not tokens:
            continue

        table = _NOTE_TABLES.get(key)
        if table is not None:
            label, glosses = table
            phrases: list[str] = []
            for token in tokens:
                if token.upper().startswith(_UNKNOWN_NOTE):
                    continue
                slug = token.lower().replace("_", "-")
                gloss = glosses.get(token.upper())
                phrases.append(f"{gloss} ({slug})" if gloss else slug)
            if phrases:
                out["effects"].append(f"{label}: " + "; ".join(phrases) + ".")
        elif key == "AKA":
            out["aka"] += tokens
        elif key == "NOCVE":
            out["nocve"].append(" ".join(tokens).strip())
        elif key == "RelatedModules":
            out["related"] += tokens
    return out


# --------------------------------------------------------------------------
# The companion markdown
# --------------------------------------------------------------------------

#: Markdown sections worth taking, mapped onto a common label. Everything else
#: — ``Options``, ``Scenarios``, ``References`` — is either a table the Ruby
#: already states better, or a long console transcript.
_DOC_SECTIONS = {
    "vulnerable application": "vulnerable application",
    "description": "description",
    "verification steps": "verification steps",
    "testing": "verification steps",
    "targets": "targets",
    "actions": "actions",
    "limitations": "limitations",
    "notes": "notes",
    "setup": "setup",
    "installation": "setup",
}
#: Up to three leading spaces still make a heading in markdown, and upstream
#: uses that: one file writes " ## Scenarios", which a column-zero-only test
#: reads as body text and then copies a console transcript into the section
#: above it.
_HEADING = re.compile(r"^ {0,3}(#{1,6})\s+(.*\S)\s*$")
_TASK_BOX = re.compile(r"^(\s*[-*+]\s+)\[[ xX]\]\s*")

#: A short fenced block in a setup or verification section is the actual
#: command sequence and is worth keeping verbatim. A long one is an
#: ``msf >`` transcript: valuable text, but SHELL-register text, and this
#: source's whole budget is charged to ADVERSARY. Dropping them keeps the
#: register accounting honest rather than quietly inflating one number with
#: another register's content.
_MAX_FENCE_LINES = 10


def _compact(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def _doc_prose(markdown: str, description: str) -> str:
    """The useful prose from ``documentation/modules/<path>.md``.

    Four things happen here. Sections outside :data:`_DOC_SECTIONS` are
    dropped. Long fenced blocks are dropped. Any paragraph the Ruby
    ``Description`` already said is dropped — 283 of these files open with a
    ``## Description`` copied verbatim from the module, and a document that
    states its own description twice teaches the model to repeat itself; the
    comparison strips every non-alphanumeric character first, because the
    markdown copy usually differs only by backticks and line wrapping. Last, a
    sub-heading left with nothing under it is dropped too. That case is created
    by the third rule rather than found in the source — deleting the duplicate
    paragraph under ``### Description`` strands the label above it — and a
    heading followed immediately by another heading is a promise the document
    does not keep.

    Body lines and headings are carried as tagged items rather than as strings
    so the last rule can ask a question strings cannot answer: whether a
    heading's own level means the next heading is its sibling (so it has no
    body) or its child (so the child's body counts as the parent's).
    """
    already = _compact(description)
    #: ('h', level, text) for a heading, ('p', line) for a body line.
    sections: list[tuple[str, list[tuple]]] = []
    current: list[tuple] | None = None
    fenced = False
    for line in markdown.replace("\r\n", "\n").split("\n"):
        if _FENCE.match(line):
            fenced = not fenced
            if current is not None:
                current.append(("p", line))
            continue
        # A `# comment` on the first line of a shell block is not a section
        # break and is not a label; inside a fence nothing is markup.
        heading = None if fenced else _HEADING.match(line)
        if heading and len(heading.group(1)) <= 2:
            title = re.sub(r"\s+", " ", heading.group(2)).strip().lower()
            current = None
            if title in _DOC_SECTIONS:
                current = []
                sections.append((_DOC_SECTIONS[title], current))
            continue
        if current is None:
            continue
        if heading:
            current.append(("h", len(heading.group(1)), heading.group(2).strip()))
        else:
            current.append(("p", _TASK_BOX.sub(r"\1", line)))

    blocks: list[str] = []
    for title, body in sections:
        items = _drop_long_fences(body)
        items = _group_paragraphs(items, already)
        items = _drop_empty_headings(items)
        rendered: list[str] = []
        for item in items:
            rendered.append(f"{item[2]}:" if item[0] == "h" else item[1])
        text = _unwrap("\n\n".join(rendered))
        if len(_compact(text)) < 60:
            continue
        blocks.append(f"{title}:\n{text}")
    return "\n\n".join(blocks)


def _drop_long_fences(items: list[tuple]) -> list[tuple]:
    """Remove fenced blocks longer than :data:`_MAX_FENCE_LINES`."""
    out: list[tuple] = []
    i = 0
    while i < len(items):
        item = items[i]
        if item[0] == "p" and _FENCE.match(item[1]):
            j = i + 1
            while j < len(items) and not (items[j][0] == "p"
                                          and _FENCE.match(items[j][1])):
                j += 1
            if (j - i - 1) <= _MAX_FENCE_LINES:
                out += items[i:j + 1]
            i = j + 1
            continue
        out.append(item)
        i += 1
    return out


def _group_paragraphs(items: list[tuple], already: str) -> list[tuple]:
    """Join body lines into paragraphs, dropping ones already said in Ruby."""
    out: list[tuple] = []
    buffer: list[str] = []

    def flush() -> None:
        if buffer:
            paragraph = "\n".join(buffer)
            buffer.clear()
            # Short paragraphs are kept unconditionally: a five-word line can
            # be a substring of the description by coincidence.
            if len(paragraph) < 40 or _compact(paragraph) not in already:
                out.append(("p", paragraph))

    for item in items:
        if item[0] == "h":
            flush()
            out.append(item)
        elif item[1].strip():
            buffer.append(item[1])
        else:
            flush()
    flush()
    return out


def _drop_empty_headings(items: list[tuple]) -> list[tuple]:
    """Drop a heading with no paragraph under it, at its level or below."""
    keep = [True] * len(items)
    for index, item in enumerate(items):
        if item[0] != "h":
            continue
        has_body = False
        for later in items[index + 1:]:
            if later[0] == "h":
                if later[1] <= item[1]:
                    break          # a sibling or an uncle: not my content
                continue           # a child: its body counts as mine
            has_body = True
            break
        keep[index] = has_body
    return [item for item, wanted in zip(items, keep) if wanted]


# --------------------------------------------------------------------------
# One module -> one document
# --------------------------------------------------------------------------

_RANK_LINE = re.compile(r"^\s*Rank\s*=\s*(\w+)Ranking\s*$", re.M)


def _render(source: str, msf_path: str, markdown: str | None) -> str | None:
    """The text for one module, or None if there is nothing worth emitting."""
    region = _region(source)
    if region is None:
        return None
    rb, start, end = region

    fields: dict[str, tuple[str, object]] = {}
    for key, kind, payload in _pairs(rb, start, end):
        fields.setdefault(key, (kind, payload))

    description = fields.get("Description")
    if (description is None or description[0] != "str"
            or len(" ".join(str(description[1]).split())) < _MIN_DESCRIPTION):
        return None

    notes_field = fields.get("Notes")
    notes: dict[str, list[str]] = {}
    if (notes_field is not None and notes_field[0] == "hash"
            and isinstance(notes_field[1], tuple)):
        notes = _notes(rb, notes_field[1])

    lines = [f"module: {msf_path}"]
    name = fields.get("Name")
    if name is not None and name[0] == "str" and str(name[1]).strip():
        lines.append(f"name: {str(name[1]).strip()}")
    if notes.get("aka"):
        lines.append("also known as: " + ", ".join(notes["aka"]))

    rank = _RANK_LINE.search(source)
    if rank is not None:
        lines.append(f"rank: {_RANKS.get(rank.group(1), rank.group(1).lower())}")

    disclosed = fields.get("DisclosureDate")
    if disclosed is not None and disclosed[0] == "str" and str(disclosed[1]).strip():
        lines.append(f"disclosed: {str(disclosed[1]).strip()}")

    platforms = _flatten(rb, fields.get("Platform"))
    if platforms:
        lines.append(f"platform: {', '.join(platforms)}")
    arches = _flatten(rb, fields.get("Arch"), strip_prefix="ARCH_")
    if arches:
        lines.append(f"architecture: {', '.join(arches)}")
    privileged = fields.get("Privileged")
    if privileged is not None and privileged[1] in ("true", "false"):
        lines.append("needs privileges on the target: "
                     + ("yes" if privileged[1] == "true" else "no"))

    lines += ["", "description:", _unwrap(str(description[1])), ""]

    targets = fields.get("Targets")
    if targets is not None and targets[0] == "list" and isinstance(targets[1], tuple):
        names = _targets(rb, targets[1])
        if names:
            lines.append("targets:")
            lines += [f"- {n}" for n in names]
            lines.append("")

    references = fields.get("References")
    rendered: list[str] = []
    if (references is not None and references[0] == "list"
            and isinstance(references[1], tuple)):
        rendered = _references(rb, references[1])
    if rendered:
        lines.append("references:")
        lines += [f"- {r}" for r in rendered]
        lines.append("")
    for reason in notes.get("nocve", []):
        lines += [f"no CVE assigned: {reason.rstrip('.')}.", ""]
    if notes.get("related"):
        lines += ["related modules: " + ", ".join(notes["related"]), ""]

    if notes.get("effects"):
        lines.append("reliability and side effects:")
        lines += notes["effects"]
        lines.append("")

    if markdown:
        prose = _doc_prose(markdown, str(description[1]))
        if prose:
            lines += [prose, ""]

    return "\n".join(lines)


# --------------------------------------------------------------------------
# Fetch
# --------------------------------------------------------------------------

def _git(*args: str, cwd: Path | None = None) -> None:
    argv = ["git", "-c", f"http.userAgent={USER_AGENT}", *args]
    # GIT_TERMINAL_PROMPT=0 is not optional here. ``capture_output`` redirects
    # the pipes but not the controlling tty, and git's credential prompt reads
    # /dev/tty — so a clone that meets an auth challenge (a proxy, rate
    # limiting, a plain 401) blocks on a username prompt for the full
    # _GIT_TIMEOUT and then fails with "timed out", a message that points at
    # the network rather than at the prompt that actually happened. Fifteen
    # silent minutes twice per fetch. Both sibling git-backed adapters set
    # these two variables for the same reason.
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"}
    try:
        proc = subprocess.run(argv, cwd=None if cwd is None else str(cwd),
                              capture_output=True, timeout=_GIT_TIMEOUT,
                              env=env)
    except FileNotFoundError as exc:
        raise SourceError(
            "metasploit: git is not installed. This source needs it: the "
            "repository's working tree is over a gigabyte and a partial, "
            "sparse clone is the only way to fetch the 52 MB of it that the "
            "corpus reads. There is no tarball short cut here."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise SourceError(
            f"metasploit: git {args[0]} timed out after {_GIT_TIMEOUT}s"
        ) from exc
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", errors="replace").strip()
        raise SourceError(
            f"metasploit: git {args[0]} failed ({proc.returncode}): "
            f"{detail[-800:] or '(no stderr)'}"
        )


def _prune_symlinks(tree: Path) -> int:
    """Unlink every symlink in ``tree``. Returns how many there were.

    This is the one adapter in the package whose transport materialises
    symlinks. Every tarball source is protected for free by
    ``if not member.isfile(): continue``, which drops link members before they
    reach the filesystem; a symlink stored in a git tree is checked out as a
    real symlink on disk and nothing filters it. So the filter is here, run on
    the staging tree before it is renamed into place, which means every later
    ``os.walk``, ``is_file`` and ``read_text`` in this module is operating on a
    tree that provably contains no links out of it.

    The count is recorded in the marker rather than raised on: upstream is free
    to carry a benign symlink, and a build that dies on one would be a worse
    failure than a build that says how many it removed. The read side in
    :func:`_module_files` guards independently, because a cache populated by a
    build from before this existed is never re-pruned — ``_fetch`` returns on
    the marker without touching the network or the tree.
    """
    removed = 0
    # topdown=False so a symlinked directory's own entry is reached after the
    # walk has finished with its level; followlinks=False so the walk never
    # descends through one in the first place.
    for dirpath, dirnames, filenames in os.walk(tree, topdown=False,
                                                followlinks=False):
        here = Path(dirpath)
        for name in (*filenames, *dirnames):
            path = here / name
            if path.is_symlink():
                path.unlink(missing_ok=True)
                removed += 1
    return removed


def _module_files(modules: Path, tree: str) -> list[Path]:
    """Every ``.rb`` file under ``modules/<tree>``, sorted, following no symlink.

    ``os.walk(followlinks=False)`` rather than ``Path.rglob``, and the reason is
    not style. ``rglob("*.rb")`` will not recurse *through* a symlinked
    subdirectory, but it does scandir the glob's own starting path — and that
    start is ``modules/<tree>``, one of four fixed names. A tree entry checking
    ``modules/post`` out as a link to ``$HOME`` would have had the walk leave
    the cache entirely, count what it found toward ``_MIN_MODULE_FILES`` so the
    floor check passed, and read every ``.rb`` under the user's home directory
    into the training corpus. At the leaf the same hole is narrower and just as
    real: ``Path.is_file()`` follows a link, so
    ``modules/exploits/linux/local/x.rb -> ~/.ssh/id_rsa`` reads the key.

    The glob root itself is therefore checked first, symlinked directories are
    pruned out of ``dirnames`` in place, and each file is checked as well.

    :func:`_fetch` counts with this and :func:`_documents` reads with it, on
    purpose: a floor that is checked against a different set of files than the
    one that is later read is a floor that can pass on files nobody emits.
    """
    root = modules / tree
    if root.is_symlink() or not root.is_dir():
        return []
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(dirpath)
        dirnames[:] = sorted(
            name for name in dirnames if not (here / name).is_symlink()
        )
        for name in sorted(filenames):
            if not name.endswith(".rb"):
                continue
            path = here / name
            if path.is_symlink() or not path.is_file():
                continue
            found.append(path)
    return sorted(found)


def _fetch(cache_dir: Path) -> Path:
    """Sparse, blobless, depth-1 clone of the two trees this source reads.

    Idempotent and network-free on re-run: the marker is written last, so an
    interrupted clone is retried rather than mistaken for a populated cache.
    The clone lands in a staging directory and is moved into place only once it
    is complete, for the same reason.

    ``--filter=blob:none`` with ``--sparse`` is what makes this affordable: git
    fetches the commit and tree objects, then downloads file contents only for
    the paths the sparse set names. The alternative — a codeload tarball, which
    every other git-backed source here uses — would be roughly a gigabyte for
    69 MB of wanted text.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    checkout = cache_dir / _CHECKOUT
    marker = cache_dir / _MARKER
    if marker.is_file() and (checkout / "modules").is_dir():
        return checkout

    staging = cache_dir / ".staging"
    shutil.rmtree(staging, ignore_errors=True)
    try:
        _git("clone", "--depth", "1", "--filter=blob:none", "--sparse",
             "--single-branch", "--quiet", _CLONE_URL, str(staging))
        # Cone mode keeps the repository-root files — which is how LICENSE
        # arrives, and LICENSE is not decoration here: it is what decides which
        # modules may legally be trained on.
        _git("sparse-checkout", "set", *_SPARSE_PATHS, cwd=staging)

        # Before anything walks the checkout. git is the only transport in this
        # package that writes symlinks to disk, and the whole tree is upstream
        # data. See :func:`_prune_symlinks`.
        pruned = _prune_symlinks(staging)

        found = sum(len(_module_files(staging / "modules", tree))
                    for tree in _TREES)
        if found < _MIN_MODULE_FILES:
            raise SourceError(
                f"metasploit: only {found} module files under modules/"
                f"{{{','.join(_TREES)}}} (expected >= {_MIN_MODULE_FILES}). The "
                "upstream layout has changed; fix the adapter rather than "
                "training on a fraction of the adversary register."
            )

        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=str(staging),
            capture_output=True, timeout=60,
        ).stdout.decode("utf-8", errors="replace").strip()

        shutil.rmtree(checkout, ignore_errors=True)
        staging.replace(checkout)
        marker.write_text(
            json.dumps(
                {
                    "url": _CLONE_URL,
                    "strategy": "git clone --depth 1 --filter=blob:none --sparse",
                    "sparse_paths": list(_SPARSE_PATHS),
                    "commit": head,
                    "module_files": found,
                    "pruned_symlinks": pruned,
                    "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return checkout


# --------------------------------------------------------------------------
# Documents
# --------------------------------------------------------------------------

def _documents(path: Path) -> Iterator[Document]:
    """One document per module, walked in a stable sorted order.

    Accepts either the checkout that :func:`_fetch` returns or the cache
    directory above it, so a caller that passes the cache root still works.
    """
    root = path / _CHECKOUT if (path / _CHECKOUT / "modules").is_dir() else path
    modules = root / "modules"
    if not modules.is_dir():
        raise SourceError(f"metasploit: no modules/ tree under {root}")

    excluded = _excluded_globs(root / "LICENSE")
    docs = root / "documentation" / "modules"
    # ``documentation/`` is checked out by the same clone as ``modules/`` and is
    # therefore the same upstream-controlled data. Resolved once here so the
    # per-module containment check below is a comparison rather than another
    # realpath, and dropped entirely if the directory is itself a link out.
    docs_root = docs.resolve() if docs.is_dir() else None
    if docs_root is not None and not docs_root.is_relative_to(root.resolve()):
        docs_root = None

    for tree in _TREES:
        for file in _module_files(modules, tree):
            relative = file.relative_to(root).as_posix()
            # A GPL module is dropped whole. See the module docstring: the
            # licence on SPEC has to be true of every document emitted.
            if any(fnmatch.fnmatch(relative, glob) for glob in excluded):
                continue

            inside = file.relative_to(modules).parts
            msf_path = "/".join((_SINGULAR.get(inside[0], inside[0]), *inside[1:]))
            msf_path = msf_path[:-len(".rb")]

            try:
                source = file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            doc_file = docs / f"{msf_path}.md"
            markdown = None
            # is_symlink() on the file alone is not enough: the link can be any
            # component of the path, and ``a -> /etc`` with a real ``b.md``
            # inside it reads as a plain file. Containment is the only check
            # that covers both, and it costs one realpath per module that
            # actually has a page.
            if (docs_root is not None and doc_file.is_file()
                    and doc_file.resolve().is_relative_to(docs_root)):
                try:
                    markdown = doc_file.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    markdown = None

            rendered = _render(source, msf_path, markdown)
            if rendered is None:
                continue
            text = normalise(rendered)
            if len(text) < _MIN_CHARS:
                continue
            yield Document(
                text=text,
                source="metasploit",
                register=Register.ADVERSARY,
                side=Side.RED,
                ident=msf_path,
            )


SPEC = SourceSpec(
    name="metasploit",
    license=(
        "BSD-3-Clause (Metasploit Framework, Copyright 2006-2026 Rapid7, Inc.; "
        "the repository LICENSE relicenses a handful of individual module files "
        "under the GPL and those files are parsed out and excluded)"
    ),
    url=_REPO,
    register=Register.ADVERSARY,
    side=Side.RED,
    fetch=_fetch,
    documents=_documents,
    #: 4,367 documents from the 4,486 module files in the four kept trees at
    #: the time of writing: 4,459 of them render, 87 fall under
    #: :data:`_MIN_CHARS`, and the rest are dropped for licence or for having
    #: no extractable Description. The floor sits well below that so ordinary
    #: churn is quiet, but the realistic regression — the Ruby scanner losing a
    #: call shape or a quoting form after an upstream style change, and
    #: silently dropping thousands of modules — trips it at once.
    expect_min_docs=3500,
    notes=(
        "One document per Metasploit module from exploits/, auxiliary/, post/ "
        "and evasion/: the msfconsole module path, the name and any AKA alias "
        "(Shellshock, HiveNightmare, ETERNALBLUE), the exploit rank spelled "
        "out, disclosure date, platform and architecture, the hand-written "
        "Description as prose, target names, References rewritten into wild "
        "identifier form (CVE-2020-9496, EDB-12345, MS17-010, and ATT&CK "
        "technique constants decoded to 'T1003.001 LSASS Memory'), and the "
        "Stability/Reliability/SideEffects notes glossed into sentences with "
        "the upstream token kept beside each gloss. Where "
        "documentation/modules/ has a companion markdown file its Vulnerable "
        "Application, Setup, Verification Steps, Targets, Limitations and "
        "Notes sections are appended, minus long console transcripts and minus "
        "any paragraph the Ruby Description already said. payloads/, encoders/ "
        "and nops/ are excluded as one-line, near-duplicate descriptions of "
        "framework machinery rather than of vulnerabilities; Author is parsed "
        "but never emitted. Ruby is lexed, never executed."
    ),
)
