"""Real captured command *output* — the half of SHELL this corpus never had.

Every other SHELL source here teaches the model what to **type**. ``tldr`` is
intent-to-invocation pairs, ``psdocs`` is cmdlet syntax, ``powershell`` and
``shellscripts`` are code, ``lolbas`` and ``gtfobins`` are abuse one-liners,
``manpages`` is the option table. Not one of them contains a single line of what
a command *printed*.

That is a strange hole, because printing is the half the runtime actually does.
Every verb in :mod:`whetstone.adapters` ends by handing stdout to a parser, and
every step the agent takes is a decision made from what the last command said.
``source.py``'s own register note is explicit about it — "SHELL and SYSTEM
dominate deliberately: those are the registers the model must both **read
(command output)** and reason about" — and the tokenizer measurement that
motivated the whole register scheme scored its single best result on exactly
this text::

    tcp        0      0 0.0.0.0:445    LISTEN     +47%   netstat output

+47% against gpt2, on a register the corpus barely contained. A model that has
never seen ``sudo -l`` refuse, or a ``systemctl show`` property block, or a
``ps`` tree, cannot parse one. It can only guess, and guessing about what a host
just said is the specific failure that makes an agent confidently wrong.

**Where this text comes from, and why it is nearly unobtainable.** Real command
output is almost absent from public corpora under a licence, because nobody
publishes their stdout: it is transient, it is boring, and when it is captured
at all it is captured into a private bug report. Four candidate upstreams were
checked by hand and three were rejected — see :data:`_REJECTED` for the
measurements. The one that works is ``jc``, a tool whose entire purpose is
converting command output to JSON and which therefore ships, as test fixtures,
**860 real captures across 26 platform trees** — CentOS 7.7, RHEL 8, five
Ubuntu releases, Debian, Fedora, Alpine, NixOS, openSUSE, FreeBSD, AIX, two
macOS versions, Raspberry Pi, Windows 10 — each paired with the structure a
parser extracted from it.

The platform spread is not incidental. ``netstat`` on macOS and ``netstat`` on
CentOS print different columns in a different order, which is the entire reason
this project has an adapter layer, and a corpus that teaches only one of them
teaches the model to misread the other.

**The paired JSON is kept where it is proportionate**, under a ``Parsed:``
heading, because it is free supervision for the exact skill at issue: here is a
column, here is the field it becomes. The key names are jc's own invention and
the model will never meet them elsewhere; the *act* of mapping a space-aligned
column to a named value is what transfers. It is bounded hard (see
:data:`_JSON_MAX_CHARS`) so the source does not quietly become a JSON corpus,
and it is **omitted whenever the output was truncated** — pairing a head of the
output with a parse of all of it would teach a mapping that is simply wrong.

**Commands are reported, never invented.** The fixture filename is a label
(``blkid-ip-udev-multi.out``), not an invocation, and ``blkid -ip-udev-multi``
is not a command anybody can run. A fabricated command line is worse than no
command line — it teaches a flag that does not exist. So the invocation is taken
from jc's own parser docstrings, which document every supported form as
``$ arp -a | jc --arp``, and is emitted **only when the fixture label normalises
to a documented form**. Otherwise the document states the utility and says
plainly that the rest is a fixture label. :func:`command_for` is the whole of
that rule and it is a pure function with tests.

Privacy — the measurements, because this source needed them
-----------------------------------------------------------

The corpus audit that preceded this work found the shipped build leaking 23,535
occurrences of 11 values, three of which were a non-consenting third party's
name and university address. So this source was scanned before it was written,
not after, and the raw fixtures are **not** clean:

====================================  =========================================
measured in the 860 raw ``.out`` files what it is
====================================  =========================================
47,969 email occurrences, 128 distinct ``git log`` histories and a Debian package
                                      index — real contributors' names and
                                      addresses, 11.2 MB of them
3 crypt(3) hashes                     two ``/etc/shadow`` captures
9 files carrying ``SSID``/``ESSID``    ``iw scan`` and ``airport -s`` — a
                                      wireless survey of whoever lived next to
                                      the machine that ran it, which is a
                                      geolocation, not a configuration
252 MAC addresses                     third-party interface hardware ids
735 global-scope IPv6 addresses        mostly public AAAA records; some are a
                                      real host's own delegated address, which
                                      is the exact value class the audit found
====================================  =========================================

Four rules follow, each fail-closed and each counted in the build log:

* a file containing **any** email address outside the reserved documentation
  domains is dropped whole — not scrubbed, dropped, because an address is a
  symptom and the document around it is somebody's commit history;
* a file containing a crypt(3) hash is dropped whole;
* a file naming an ``SSID`` is dropped whole;
* MAC addresses and global-scope IPv6 addresses are **rewritten
  length-for-length** (:func:`pseudonymise`), so every column stays where it
  was. A rewrite that cannot preserve the length drops the document rather than
  shifting a column, and says so.

Rewriting rather than dropping is deliberate and narrow. What this register
teaches is surface form — eighteen characters of colon-separated hex in a column
of its own — and a pseudonym has the identical surface form and none of the
value. What it must not do is move anything: ``normalise()`` preserves
horizontal whitespace precisely because the first attempt at it destroyed
netstat's columns for a +47% loss, and a redactor that re-introduced the same
damage through the back door would be worse than the leak it fixed.

Nothing here is a substitute for the build's own chokepoint. ``build.py`` runs
``_redacted`` over every document from every source, and it knows **this**
machine's identifiers; it cannot know a stranger's. That is what this module is
for.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tarfile
from pathlib import Path
from typing import Iterator, NamedTuple

from ..net import NetworkError, download
from ..source import Document, Register, Side, SourceError, SourceSpec, normalise

_REPO = "kellyjonbrazil/jc"
_REF = "master"
_ARCHIVE = f"https://codeload.github.com/{_REPO}/tar.gz/refs/heads/{_REF}"

#: Measured at 14.72 MB on the wire. The ceiling is generous rather than tight
#: because a limit that trips on ordinary growth is a build that fails at 3am
#: for no reason, and :func:`~training.corpus.net.download` enforces it where
#: the bytes arrive rather than on a ``stat()`` afterwards.
_MAX_ARCHIVE_BYTES = 128 * 1024 * 1024

_MARKER = ".fetched.json"
_FIXTURES = "fixtures"
_PARSERS = "parsers"
_LICENSES = "licenses"

#: jc's licence file, and the string that must still be in it. Read from the
#: archive, not from a badge: the SPEC below says MIT, and a declaration whose
#: evidence was not in the download is a claim rather than a reading.
_LICENSE_MEMBER = "LICENSE.md"
_LICENSE_NEEDLE = "MIT License"

#: Upstreams checked and NOT used, with the reason measured rather than guessed.
#: Recorded here because the task that commissioned this source asked whether
#: public command-output text exists at all, and a negative result is only worth
#: anything if it says what was looked at.
_REJECTED = (
    ("util-linux tests/expected", "GPL-2.0-or-later",
     ("97 directories of expected stdout, but it is unit-test material rather "
     "than captured output: 54 of the 58 files under column/ are variants of "
     "one synthetic input table, a third of the tree is ANSI-escape edge cases "
     "and checksum digests, and many files are under 100 bytes. High "
     "near-duplicate rate, low real-world shape.")),
    ("networktocode/ntc-templates", "Apache-2.0",
     ("Thousands of genuine 'show' captures, but from network appliances rather "
     "than hosts, so it is out of register for an adapter that shells out to a "
     "Linux/macOS/Windows machine — and lab fixtures of that kind routinely "
     "carry real hostnames, addressing plans and SNMP community strings.")),
    ("procps-ng testsuite", "GPL-2.0-or-later",
     "The expected results are DejaGnu regex patterns, not literal output."),
)

# ---------------------------------------------------------------------------
# Privacy: the four refusals and the two rewrites.
# ---------------------------------------------------------------------------

_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

#: Domains reserved for documentation and testing. An address in one of these is
#: an example by definition and is left alone — the build's own chokepoint makes
#: the same exemption for the same reason.
_RESERVED_DOMAINS = frozenset((
    "example.com", "example.org", "example.net", "example.edu",
    "example", "invalid", "test", "localhost", "localdomain", "local",
))

#: crypt(3) and friends: ``$1$``/``$5$``/``$6$`` (md5/sha256/sha512),
#: ``$2a$``/``$2b$``/``$2y$`` (bcrypt), ``$y$``/``$gy$`` (yescrypt),
#: ``$argon2*$``. Two ``/etc/shadow`` captures upstream carry real ones. Even
#: from a throwaway VM, a password hash with a live salt is not something to put
#: through a tokenizer.
_CRYPT = re.compile(r"\$(?:1|2[abxy]?|5|6|7|y|gy|argon2(?:i|d|id)?)\$[^\s:*!]{6,}")

#: A wireless survey names the networks within radio range of wherever the
#: capture was taken, which locates a dwelling to within a few metres through any
#: public BSSID database. Matched on the field name because that is what every
#: scan tool prints, whatever its column layout.
_SSID = re.compile(r"\b(?:SSID|ESSID|BSSID)\b")

#: 17 characters, colon-separated. Lower- and upper-case both appear upstream.
_MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")

#: MACs that identify no hardware and *are* structure: the broadcast address,
#: the all-zero address, IPv4 multicast (``01:00:5e:``, derived from the group
#: address) and IPv6 multicast (``33:33:``, derived from the address). Rewriting
#: these would destroy meaning and protect nobody.
_MAC_KEEP_PREFIXES = ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00",
                      "01:00:5e", "33:33")

#: Global unicast IPv6 is 2000::/3, so the first hextet begins with 2 or 3 and
#: is four digits wide. Everything else — ``fe80::`` link-local, ``fd00::``
#: unique-local, ``::1`` — identifies nothing outside the machine and is left
#: exactly as printed.
_GLOBAL6 = re.compile(r"\b[23][0-9A-Fa-f]{3}(?::[0-9A-Fa-f]{0,4}){1,7}\b")

#: A modified-EUI-64 interface identifier, which is a MAC address wearing a
#: different hat. SLAAC builds the host half of an IPv6 address out of the
#: interface's hardware address by splitting it, flipping one bit and inserting
#: ``ff:fe`` in the middle, so ``fe80::aede:48ff:fe00:1323`` *is* the MAC
#: ``ac:de:48:00:13:23`` and nothing else. The first pass through this module
#: rewrote MACs and global addresses and left those alone, on the reasoning that
#: a link-local address identifies nothing outside its own link — which is true
#: of the address and false of the hardware id embedded in it. The audit this
#: source was written after found exactly three hardware MACs in the shipped
#: corpus; leaving them in a different notation would have been the same leak
#: with better camouflage.
#:
#: The ``ff:fe`` marker is kept in place and only the four surrounding digit
#: groups are rewritten, each at its own width, so the shape that makes a SLAAC
#: address recognisable survives intact.
_EUI64 = re.compile(
    r"\b([0-9A-Fa-f]{1,4}):([0-9A-Fa-f]{0,2})ff:fe([0-9A-Fa-f]{0,2}):"
    r"([0-9A-Fa-f]{1,4})\b")

#: The documentation prefix from RFC 3849, spelled at each width a real address
#: might use for that group. ``2001:db8::/32`` is reserved precisely so that an
#: address written down cannot be anybody's — and the prefix has to be written
#: at the *original's* group widths, because the whole point is that no
#: character moves. A real global address nearly always writes its second group
#: four digits wide (``2a00:1450:``), so ``0db8`` is the common case and ``db8``
#: the one that first came to mind; getting only the second would have dropped
#: almost every address this is here to protect.
_DOC6_HEXTETS: tuple[dict[int, str], ...] = (
    {4: "2001"},
    {4: "0db8", 3: "db8"},
)


class _Unrewritable(Exception):
    """A value could not be pseudonymised without changing the text's length."""


def _hash_digits(seed: str, n: int) -> str:
    """``n`` hex digits derived from ``seed``. Deterministic across builds."""
    out = ""
    salt = 0
    while len(out) < n:
        out += hashlib.sha256(f"{seed}#{salt}".encode()).hexdigest()
        salt += 1
    return out[:n]


def _mac_pseudonym(mac: str) -> str:
    """A different MAC of exactly the same shape: 17 characters, 5 colons.

    The ``02:`` first octet sets the locally-administered bit, which is the
    honest signal that the address is synthetic — no manufacturer owns that
    prefix, so the result cannot collide with a real device's OUI.
    """
    digits = _hash_digits(mac.lower(), 10)
    pairs = ["02"] + [digits[i:i + 2] for i in range(0, 10, 2)]
    out = ":".join(pairs)
    if len(out) != len(mac):                      # 17 either way; belt and braces
        raise _Unrewritable(mac)
    return out


def _ipv6_pseudonym(addr: str) -> str:
    """An address in 2001:db8::/32 with the original's exact length and layout.

    Every colon stays at the character offset it was already at, and every run
    of hex digits keeps its own width, so an address inside a space-aligned
    ``netstat -rn`` or ``ip -6 addr`` column cannot shift the column. Only the
    *digits* change, and the first two groups are forced to the documentation
    prefix so the result is unambiguously not a real allocation.

    Raises :class:`_Unrewritable` when the first two groups are too narrow to
    hold ``2001`` and ``db8`` — a compressed form like ``2001::1`` — in which
    case the caller drops the document rather than resizing it.
    """
    groups = addr.split(":")
    if len(groups) < 2:
        raise _Unrewritable(addr)
    out: list[str] = []
    for index, group in enumerate(groups):
        if index < len(_DOC6_HEXTETS):
            want = _DOC6_HEXTETS[index].get(len(group))
            if want is None:
                # A zero-width group is ``::`` compression and a one- or
                # two-digit group cannot hold "db8" at that width. Either way
                # the length is not preservable, so the caller drops the
                # document rather than shifting a column.
                raise _Unrewritable(addr)
            out.append(want)
        elif not group:
            out.append("")                        # keep ``::`` where it was
        else:
            out.append(_hash_digits(f"{addr.lower()}:{index}", len(group)))
    result = ":".join(out)
    if len(result) != len(addr):
        raise _Unrewritable(addr)
    return result


def pseudonymise(text: str) -> tuple[str, int, int]:
    """Rewrite hardware and global addresses in place. Returns (text, macs, v6).

    Pure, length-preserving and total: either every match is rewritten with the
    text's length unchanged, or :class:`_Unrewritable` propagates and the caller
    drops the document. There is no partial outcome, because a document that is
    half-redacted is a document nobody can make a claim about.

    Three passes, in this order and for a reason. MACs first, because a MAC is
    the shortest and most specific form and matching it first keeps the IPv6
    patterns from claiming part of one. Then global-scope addresses. Then
    modified-EUI-64 interface identifiers, which are MACs again in a notation
    the first pass cannot see.
    """
    macs = 0
    v6 = 0

    def _mac(match: re.Match[str]) -> str:
        nonlocal macs
        raw = match.group(0)
        low = raw.lower()
        if any(low.startswith(prefix) for prefix in _MAC_KEEP_PREFIXES):
            return raw
        macs += 1
        return _mac_pseudonym(raw)

    def _six(match: re.Match[str]) -> str:
        nonlocal v6
        raw = match.group(0)
        if raw.lower().startswith("2001:db8"):
            return raw                            # already documentation space
        v6 += 1
        return _ipv6_pseudonym(raw)

    def _eui(match: re.Match[str]) -> str:
        nonlocal macs
        whole = match.group(0)
        digits = _hash_digits(whole.lower(), 16)
        groups = [match.group(index) for index in (1, 2, 3, 4)]
        out: list[str] = []
        taken = 0
        for group in groups:
            out.append(digits[taken:taken + len(group)])
            taken += len(group)
        macs += 1
        rebuilt = f"{out[0]}:{out[1]}ff:fe{out[2]}:{out[3]}"
        if len(rebuilt) != len(whole):
            raise _Unrewritable(whole)
        return rebuilt

    text = _MAC.sub(_mac, text)
    text = _GLOBAL6.sub(_six, text)
    text = _EUI64.sub(_eui, text)
    return text, macs, v6


def refusal(text: str) -> str | None:
    """Why this capture must not be collected, or ``None`` if it may be.

    Whole-file refusals, not scrubs. The distinction matters: an email address
    in a capture is not an isolated value to paint over, it is the signature of
    a document that is somebody's commit history or a distribution's maintainer
    table, and the right answer to "this file is a list of 4,848 strangers" is
    not to anonymise the list.
    """
    for address in _EMAIL.findall(text):
        domain = address.rsplit("@", 1)[-1].lower()
        if domain in _RESERVED_DOMAINS:
            continue
        if any(domain.endswith("." + reserved) for reserved in _RESERVED_DOMAINS):
            continue
        return "third-party-email"
    if _CRYPT.search(text):
        return "crypt-hash"
    if _SSID.search(text):
        return "wireless-survey"
    return None


# ---------------------------------------------------------------------------
# Naming: which utility printed this, and what was actually run.
# ---------------------------------------------------------------------------

#: jc titles every parser docstring in one of two shapes, and the distinction is
#: upstream's own:
#:
#:     jc - JSON Convert `ps` command output parser
#:     jc - JSON Convert INI file parser
#:
#: Only the first kind is command output. The file-format parsers (ini, X.509,
#: plist, YAML, /etc/passwd...) are config and file syntax — genuinely useful
#: text, and SYSTEM register, not SHELL. Collecting them here would misreport
#: the register this source exists to fill, which is the same objection psdocs
#: makes when it excludes docs-conceptual/.
#:
#: Not anchored to the start of a line, and that is not laziness. The title is
#: the first line *inside* the docstring, so the file's first line reads
#: ``r\"\"\"jc - JSON Convert `ps` command output parser`` and a ``^`` anchor
#: matches nothing at all. It matched nothing on the first run, the floor in
#: :func:`_parsers` said so immediately — "only 0 parsers recognised" — and the
#: fault was in the pattern rather than in upstream. A floor that reports zero
#: is the instrument working.
#:
#: Two variants of the phrase are accepted because upstream writes both:
#: "command output parser" for most, plain "command parser" for ``lsb_release``
#: and ``apt_cache_show``. Neither matches "`fstab` file parser", "INI file
#: parser", "`asciitable` parser" or "IP Address string parser", which is the
#: whole job of this pattern.
_PARSER_TITLE = re.compile(
    r"jc - JSON Convert\s+(?P<names>.*?)\s+command(?:\s+output)?\s+parser")

#: Every backticked name in a title. A title may carry several — ``ls``
#: documents "`ls` and `vdir`", ``last`` documents "`last` and `lastb`",
#: ``typeset`` documents "`typeset` and `declare`" — and a single-name pattern
#: silently lost all of their fixtures. 37 ``ls-*`` captures, the largest group
#: in the tree, went missing exactly that way on the first run.
_TITLE_NAME = re.compile(r"`([^`\n]+)`")

#: Network tools conventionally ship an IPv6 twin named for the protocol:
#: ``ping6``, ``traceroute6``, ``route -6``. jc parses those with the v4
#: parser and its title does not mention the twin, so 36 ``ping6-*`` and
#: ``traceroute6-*`` captures have no alias of their own. Stripping one trailing
#: ``6`` — and *only* when what is left is already a known alias — recovers
#: them without inventing anything. It deliberately does not generalise to
#: other suffixes: ``sha256sum`` and ``shasum`` are parsed by ``hashsum``
#: upstream and no honest rule gets there from the name, so those five captures
#: are dropped and counted rather than guessed at.
_V6_SUFFIX = "6"

#: A documented invocation inside a parser docstring: ``$ arp -a | jc --arp``.
#: The ``$ jc arp`` "magic syntax" form is deliberately not read — it documents
#: jc's own wrapper, not the command whose output is in the fixture.
_USAGE_LINE = re.compile(r"^\s*\$\s+(?P<cmd>[^|\n]+?)\s*\|\s*jc\s+--", re.M)


def _squash(text: str) -> str:
    """Normalise a command or label for comparison: letters and digits only."""
    return re.sub(r"[^a-z0-9]", "", text.lower())


def command_for(stem: str, parser: str, documented: tuple[str, ...]) -> str | None:
    """The real invocation behind a fixture name, or ``None`` if not knowable.

    ``stem`` is the fixture file's name without its suffix (``arp-a``,
    ``blkid-ip-udev-multi``), ``parser`` is the jc parser it belongs to
    (``arp``, ``blkid``), and ``documented`` is every invocation that parser's
    docstring lists.

    A fixture label is not a command. ``arp-a`` happens to be ``arp -a``;
    ``blkid-ip-udev-multi`` is three facts about how the capture was taken and
    is not runnable in any form. There is no transformation that tells those
    apart, so this function does not try: it returns a command **only** when the
    label squashes to exactly the same characters as an invocation upstream
    documents. Everything else returns ``None`` and the document says so.

    This is the one rule in the module that a cleverer author would regret
    relaxing. A corpus that teaches ``blkid -ip-udev-multi`` has taught a flag
    that does not exist, in the register the model is most likely to be believed
    in.
    """
    target = _squash(stem)
    for candidate in documented:
        if _squash(candidate) == target:
            return candidate
    return None


class _Parser(NamedTuple):
    """What one jc parser module says about itself."""

    #: jc's module name, e.g. ``net_user``. The document's ``Parser:`` line.
    module: str
    #: The utility whose output it reads, e.g. ``net user``. First backticked
    #: name in the title, or the module name when the title has none.
    utility: str
    #: Every invocation the docstring documents, verbatim.
    documented: tuple[str, ...]
    #: Squashed names this parser answers to, for fixture matching.
    aliases: frozenset[str]


def parser_facts(source: str, module: str) -> _Parser | None:
    """Read one jc parser module's docstring.

    ``None`` when the parser is not a command parser, which is how the
    file-format parsers are excluded — by upstream's own title, rather than by a
    list maintained here that would silently rot the first time jc adds one.
    """
    title = _PARSER_TITLE.search(source)
    if title is None:
        return None
    names = [name.strip() for name in _TITLE_NAME.findall(title.group("names"))]
    utility = names[0] if names else module.replace("_", " ")
    aliases = {_squash(module)} | {_squash(name) for name in names}
    aliases.discard("")
    seen: dict[str, None] = {}
    for match in _USAGE_LINE.finditer(source):
        command = " ".join(match.group("cmd").split())
        # ``cat foo.ini``, ``jc --ini`` and friends document the plumbing, not a
        # capture of a utility's own output.
        head = command.split(" ", 1)[0]
        if head in ("cat", "jc", "echo", "printf"):
            continue
        seen.setdefault(command, None)
    return _Parser(module=module, utility=utility,
                   documented=tuple(seen), aliases=frozenset(aliases))


# ---------------------------------------------------------------------------
# Size discipline.
# ---------------------------------------------------------------------------

#: Head of a capture to keep, in lines. The 807 collectable fixtures run from 60
#: bytes to 1.1 MB; the tail of that distribution is ``du`` over a home
#: directory, ``ls -alR`` over a filesystem and ``dmidecode`` over every DMI
#: table, and row 4,000 of a table teaches nothing row 300 did not. Truncation
#: is marked explicitly in the text rather than silent, because an operator
#: genuinely does see truncated output and a document that pretends otherwise is
#: lying about its own shape.
_MAX_LINES = 400
_MAX_CHARS = 40_000

#: A capture below this is a one-line answer with no structure to read — an
#: empty ``table``, a lone exit code. The floor sits under every genuine
#: multi-column capture.
_MIN_CHARS = 60

#: No single utility may exceed this share of the source's characters. ``du``,
#: ``ls``, ``dmidecode``, ``stat`` and ``lsof`` between them are most of the
#: bytes and a small fraction of the lessons, and a cap is the general answer —
#: the next upstream fixture dump is bounded automatically instead of being
#: discovered by hand later. The same mechanism and the same argument as
#: manpages' per-family cap.
_UTILITY_CAP = 0.06

#: Ceilings on the paired JSON. Both must hold: the parse may not be more than
#: three times the output it parses, and may not exceed this many characters.
#: Without the ratio the ``git log`` parses alone were 69 MB against 21 MB of
#: output, and this would have become a JSON source wearing a SHELL label.
_JSON_MAX_CHARS = 12_000
_JSON_MAX_RATIO = 3.0


class _Capture(NamedTuple):
    """One fixture: the platform it was taken on and where its text is cached."""

    platform: str
    stem: str
    out: Path
    parsed: Path | None


def _fetch(cache_dir: Path) -> Path:
    """Download jc and keep the fixtures, the parser docstrings and the licence.

    Only three kinds of member survive into the cache: ``tests/fixtures/**``
    (the captures and their parses), ``jc/parsers/*.py`` (read for the utility
    name and the documented invocations, never emitted) and ``LICENSE.md``. The
    rest of the repository is a JSON converter and is of no interest here.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    home = cache_dir / "jc"
    if (home / _MARKER).is_file():
        return home

    archive = cache_dir / ".jc.tar.gz.part"
    staging = cache_dir / ".jc.staging"
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True)
    fixtures = 0
    parsers = 0
    licence = ""
    try:
        try:
            download(_ARCHIVE, archive, timeout=600, max_bytes=_MAX_ARCHIVE_BYTES)
        except NetworkError as exc:
            raise SourceError(f"cmdoutput: cannot fetch {_ARCHIVE}: {exc}") from None

        with tarfile.open(archive, "r:gz") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                # codeload wraps the tree in one directory whose name carries
                # the ref; drop it so the cache layout survives a branch rename.
                parts = Path(member.name).parts[1:]
                if not parts:
                    continue
                relative = Path(*parts)
                posix = relative.as_posix()

                kind = None
                if posix == _LICENSE_MEMBER:
                    kind, target = "licence", staging / _LICENSES / "jc-LICENSE.md"
                elif (posix.startswith("tests/fixtures/")
                      and relative.suffix in (".out", ".json")):
                    kind = "fixture"
                    target = staging / _FIXTURES / Path(*relative.parts[2:])
                elif (posix.startswith("jc/parsers/")
                      and relative.suffix == ".py"
                      and not relative.name.startswith("_")):
                    kind = "parser"
                    target = staging / _PARSERS / relative.name
                if kind is None:
                    continue
                if any(part in ("..", "") or os.path.isabs(part)
                       for part in target.relative_to(staging).parts):
                    raise SourceError(
                        f"cmdoutput: archive member escapes staging: {member.name!r}")

                extracted = tar.extractfile(member)
                if extracted is None:
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with extracted, target.open("wb") as handle:
                    # A chunk at a time: peak memory is a chunk, not the member,
                    # and a crafted archive cannot ask for one huge allocation.
                    shutil.copyfileobj(extracted, handle, 1 << 20)
                if kind == "licence":
                    licence = target.read_text(encoding="utf-8", errors="replace")
                elif kind == "fixture":
                    fixtures += 1
                else:
                    parsers += 1
    finally:
        archive.unlink(missing_ok=True)

    if _LICENSE_NEEDLE not in licence:
        shutil.rmtree(staging, ignore_errors=True)
        raise SourceError(
            f"cmdoutput: {_LICENSE_MEMBER} in the archive does not contain "
            f"{_LICENSE_NEEDLE!r}. The SPEC declares MIT; with the evidence "
            "absent or changed that declaration would be a claim rather than a "
            "reading, so nothing was cached.")
    if fixtures < 800 or parsers < 150:
        shutil.rmtree(staging, ignore_errors=True)
        raise SourceError(
            f"cmdoutput: cached {fixtures} fixture file(s) and {parsers} parser "
            "module(s); expected well over 800 and 150. The repository layout "
            "has probably moved.")

    shutil.rmtree(home, ignore_errors=True)
    staging.rename(home)
    (home / _MARKER).write_text(json.dumps(
        {"repo": _REPO, "ref": _REF, "fixture_files": fixtures,
         "parser_modules": parsers, "license": "MIT"}, indent=1), encoding="utf-8")
    return home


def _parsers(home: Path) -> dict[str, _Parser]:
    """Every command parser, keyed by each squashed alias it answers to."""
    root = home / _PARSERS
    if not root.is_dir():
        raise SourceError(f"cmdoutput: no {_PARSERS}/ under {home}; re-fetch")
    table: dict[str, _Parser] = {}
    modules = 0
    for file in sorted(root.glob("*.py")):
        try:
            source = file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        facts = parser_facts(source, file.stem)
        if facts is None:
            continue
        modules += 1
        for alias in facts.aliases:
            # Longest module name wins a contested alias, so a specialised
            # parser (``apt_get_sqq``) is never shadowed by a general one.
            held = table.get(alias)
            if held is None or len(facts.module) > len(held.module):
                table[alias] = facts
    if modules < 100:
        raise SourceError(
            f"cmdoutput: only {modules} command parser(s) recognised from the "
            "docstring titles; upstream has reworded them and the "
            "command/file-format split is no longer being made.")
    return table


def match_parser(stem: str, table: dict[str, _Parser]) -> _Parser | None:
    """The parser a fixture belongs to, by whole-segment prefix.

    A fixture is named ``<parser>[-<variant>...]`` with ``-``, ``_`` and ``.``
    all used as separators by different parts of the tree
    (``net_localgroup.administrators``, ``apt-get-sqq-upgrade``,
    ``curl_head--ILvs-yahoo-com``). So the stem is split on all three, and the
    longest **whole-segment** prefix that equals a known alias wins.

    Whole-segment equality rather than ``startswith``, deliberately. A substring
    prefix would let ``ls`` claim ``lsblk`` and ``lsof``; segment equality gives
    ``lsblk`` to ``lsblk`` and keeps ``ls`` for ``ls-alR``. Longest-first
    resolves ``apt-get-sqq-upgrade`` to ``apt_get_sqq`` rather than to ``apt``.
    """
    segments = [part for part in re.split(r"[-_.]+", stem) if part]
    for size in range(len(segments), 0, -1):
        key = _squash("".join(segments[:size]))
        found = table.get(key)
        if found is not None:
            return found
        # The IPv6 twin: ping6 -> ping, traceroute6 -> traceroute. Only when
        # the remainder is already a real alias, so nothing is invented.
        if key.endswith(_V6_SUFFIX):
            found = table.get(key[:-len(_V6_SUFFIX)])
            if found is not None:
                return found
    return None


def _captures(home: Path) -> list[_Capture]:
    """Walk the fixture tree. ``os.walk(followlinks=False)``, never ``rglob``.

    ``ownrepos`` once followed this repository's ``data`` symlink into the SSD
    and pulled the corpus cache back in as PROSE — the corpus ate itself, and
    only the balance report noticed. Nothing in this tree is a symlink today;
    the walk refuses to follow one anyway.
    """
    root = home / _FIXTURES
    if not root.is_dir():
        raise SourceError(f"cmdoutput: no {_FIXTURES}/ under {home}; re-fetch")
    found: list[_Capture] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames
                             if not Path(dirpath, d).is_symlink())
        here = Path(dirpath)
        # ``relative_to`` returns "." for the root itself, not "". Every capture
        # upstream lives in a platform directory, so this only guards against a
        # future layout that drops one at the top level.
        relative = here.relative_to(root).as_posix()
        platform = "unknown" if relative in (".", "") else relative
        for filename in sorted(filenames):
            if not filename.endswith(".out"):
                continue
            out = here / filename
            if out.is_symlink():
                continue
            parsed = out.with_suffix(".json")
            found.append(_Capture(platform, out.stem, out,
                                  parsed if parsed.is_file() else None))
    return found


def render(capture_text: str, *, platform: str, utility: str, parser: str,
           stem: str, command: str | None,
           parsed: str | None) -> tuple[str, int, int] | None:
    """Lay out one document. Pure, so the whole shape is testable offline.

    Returns ``(text, macs_rewritten, ipv6_rewritten)``, or ``None`` when what
    survives is too short to be a document. The rewrite happens *here* rather
    than in the caller so that there is exactly one path from a raw capture to a
    corpus document, and a test of this function is a test of the redaction.

    The header is four short labelled lines rather than a sentence, for the same
    reason tldr puts the platform on its own line: the same utility prints
    different columns on different systems, and the model has to be able to
    condition on which machine it is standing on instead of averaging over all
    of them.
    """
    text, macs, v6 = pseudonymise(capture_text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    # Lines first, then characters, then one marker — in that order, so a
    # second cut cannot slice the first cut's own marker off the end.
    truncated = False
    lines = text.split("\n")
    if len(lines) > _MAX_LINES:
        text = "\n".join(lines[:_MAX_LINES])
        truncated = True
    if len(text) > _MAX_CHARS:
        head = text[:_MAX_CHARS]
        text = head.rsplit("\n", 1)[0] if "\n" in head else head
        truncated = True
    if truncated:
        text += "\n[output truncated]"

    header = [f"Utility: {utility}", f"Platform: {platform}"]
    if command:
        header.append(f"Command: {command}")
    else:
        # Said plainly rather than dressed up as an invocation. See command_for.
        header.append(f"Capture: {stem} (jc fixture label, not a command line)")
    header.append(f"Parser: jc --{parser}")
    if macs or v6:
        # Stated in the document, not only in the log: a reader of the corpus
        # should be able to see that an address here is synthetic without
        # having to know this module exists.
        note = []
        if macs:
            note.append(f"{macs} MAC address(es)")
        if v6:
            note.append(f"{v6} global IPv6 address(es)")
        header.append("Note: " + " and ".join(note)
                      + " replaced with same-length synthetic values")

    body = ["", "Output:", "", text]
    if parsed is not None and not truncated:
        body += ["", "Parsed (jc schema):", "", parsed]

    rendered = normalise("\n".join(header + body))
    if len(rendered) < _MIN_CHARS:
        return None
    return rendered, macs, v6


def _parsed_text(capture: _Capture, out_chars: int) -> str | None:
    """The paired parse, pretty-printed, or ``None`` if it is disproportionate."""
    if capture.parsed is None:
        return None
    try:
        raw = capture.parsed.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    try:
        value = json.loads(raw)
    except ValueError:
        return None
    pretty = json.dumps(value, indent=2, sort_keys=False, ensure_ascii=False)
    if len(pretty) > _JSON_MAX_CHARS or len(pretty) > out_chars * _JSON_MAX_RATIO:
        return None
    # The parse is derived from the output, so anything the output was refused
    # for would arrive here too; and a rewrite that changed the output must not
    # leave the pre-rewrite value sitting in the parse beside it.
    if refusal(pretty) is not None:
        return None
    pretty, _, _ = pseudonymise(pretty)
    return pretty


def _documents(path: Path) -> Iterator[Document]:
    home = path if (path / _MARKER).is_file() else path / "jc"
    table = _parsers(home)
    captures = _captures(home)

    held: dict[str, int] = {}
    budgets = _utility_budgets(captures, table)
    spent: dict[str, int] = {}
    emitted = 0
    macs_total = 0
    v6_total = 0
    named = 0
    paired = 0

    def _hold(reason: str) -> None:
        held[reason] = held.get(reason, 0) + 1

    for capture in captures:
        found = match_parser(capture.stem, table)
        if found is None:
            _hold("no-command-parser")
            continue
        utility = found.utility
        try:
            raw = capture.out.read_text(encoding="utf-8", errors="replace")
        except OSError:
            _hold("unreadable")
            continue
        if len(raw.strip()) < _MIN_CHARS:
            _hold("too-short")
            continue
        why = refusal(raw)
        if why is not None:
            _hold(why)
            continue

        command = command_for(capture.stem, found.module, found.documented)
        try:
            # pseudonymise() preserves length by construction, so the raw size
            # is the cleaned size and the parse can be sized against it without
            # rewriting the output twice.
            parsed = _parsed_text(capture, len(raw))
            result = render(raw, platform=capture.platform, utility=utility,
                            parser=found.module, stem=capture.stem,
                            command=command, parsed=parsed)
        except _Unrewritable:
            # A compressed global address whose length cannot be preserved.
            # Dropping the document is the only answer that neither leaks the
            # value nor shifts a column.
            _hold("unrewritable-address")
            continue
        if result is None:
            _hold("too-short")
            continue
        rendered, macs, v6 = result

        cap = budgets.get(utility)
        if cap is not None and spent.get(utility, 0) + len(rendered) > cap:
            _hold(f"utility-cap:{utility}")
            continue
        spent[utility] = spent.get(utility, 0) + len(rendered)

        macs_total += macs
        v6_total += v6
        emitted += 1
        named += 1 if command else 0
        paired += 1 if parsed is not None else 0
        yield Document(text=rendered, source="cmdoutput", register=Register.SHELL,
                       side=Side.NEUTRAL,
                       ident=f"{capture.platform}/{capture.stem}")

    refused = sum(n for reason, n in held.items()
                  if reason in ("third-party-email", "crypt-hash",
                                "wireless-survey", "unrewritable-address"))
    print(f"   cmdoutput: {emitted} captures from {len(captures)} fixtures "
          f"({named} with a documented command line, {paired} with a paired "
          f"parse); refused {refused} on privacy grounds; rewrote "
          f"{macs_total} MAC and {v6_total} global-IPv6 value(s)")
    for reason, count in sorted(held.items(), key=lambda kv: -kv[1]):
        print(f"   cmdoutput: held back {count} for {reason}")


def _utility_budgets(captures: list[_Capture],
                     table: dict[str, _Parser]) -> dict[str, int]:
    """Character budget per utility, from the fixtures' own on-disk sizes.

    Computed from ``stat()`` rather than by rendering everything twice, so the
    cap costs one pass over metadata. It over-estimates slightly — the rendered
    document is the truncated output plus a header — and that is the harmless
    direction: the cap binds a little later than it would on exact numbers.
    """
    sizes: dict[str, int] = {}
    total = 0
    for capture in captures:
        found = match_parser(capture.stem, table)
        if found is None:
            continue
        utility = found.utility
        try:
            n = min(capture.out.stat().st_size, _MAX_CHARS)
        except OSError:
            continue
        sizes[utility] = sizes.get(utility, 0) + n
        total += n
    if not total:
        return {}
    cap = int(total * _UTILITY_CAP)
    return {utility: cap for utility, size in sizes.items() if size > cap}


SPEC = SourceSpec(
    name="cmdoutput",
    license=(
        "MIT — kellyjonbrazil/jc, Copyright (c) 2020 Kelly Brazil, read from "
        "the repository's own LICENSE.md inside the fetched archive and copied "
        "into the cache under licenses/. The fetch refuses to cache anything if "
        "that file is absent or no longer says 'MIT License', because the "
        "declaration would then be a claim rather than a reading. Only "
        "tests/fixtures/ (the captures and their parses) and jc/parsers/*.py "
        "(read for the utility name and documented invocations, never emitted) "
        "are kept."
    ),
    url=f"https://github.com/{_REPO}",
    register=Register.SHELL,
    side=Side.NEUTRAL,
    fetch=_fetch,
    documents=_documents,
    #: 860 .out fixtures upstream; 53 are refused on privacy grounds and a
    #: further tail is held back by the per-utility cap and the file-format
    #: parser exclusion. The floor sits far below the measured yield so ordinary
    #: churn is quiet, while a renamed fixtures/ tree, a reworded parser
    #: docstring title or a broken fetch trips it at once.
    expect_min_docs=400,
    #: One ~15 MB tarball, streamed and filtered member by member, then a walk
    #: over ~2,000 small files. Comfortable inside the build-wide budget; stated
    #: so a slow network does not look like a parser fault.
    timeout=900,
    notes=(
        "Real captured command OUTPUT across 26 platform trees (CentOS, RHEL, "
        "five Ubuntu releases, Debian, Fedora, Alpine, NixOS, openSUSE, "
        "FreeBSD, AIX, two macOS, Raspberry Pi, Windows 10) — the half of SHELL "
        "no other source here carries: every other one teaches what to type, "
        "this one teaches what came back. Paired jc parse appended where it is "
        "proportionate and the output was NOT truncated. Invocations are only "
        "stated when the fixture label matches a form jc's own parser docstring "
        "documents; otherwise the document says the label is a label, because a "
        "fabricated flag is worse than no flag. jc's file-format parsers (ini, "
        "X.509, plist, passwd) are excluded by upstream's own docstring title: "
        "they are config syntax, which is SYSTEM, not SHELL. Privacy: files "
        "carrying a non-documentation email address, a crypt(3) hash or a "
        "wireless survey are dropped whole (53 of 860, 11.2 MB, almost all git "
        "log histories naming real contributors); MAC and global-scope IPv6 "
        "values are rewritten length-for-length so no column moves, and a "
        "rewrite that cannot preserve the length drops the document."
    ),
)
