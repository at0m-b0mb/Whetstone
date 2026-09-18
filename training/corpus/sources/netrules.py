"""Network IDS signatures — Suricata and Snort rules. DETECTION, blue side.

Every other detection source in this corpus is standing on the endpoint. Sigma
and Splunk read logs a host wrote about itself, YARA reads files sitting on a
disk, the lab's auditd rules watch syscalls. All of them answer the same shape
of question: *what did this machine do?* Network IDS rules are the only ones in
the corpus that answer a different one — *what went past on the wire?* — and
they answer it with a vocabulary nothing else here supplies: protocol names as
first-class match targets, byte offsets, ``content``/``pcre`` patterns with
their modifier stack, sticky buffers, flow state and direction, and thresholds.

That gap is not cosmetic, and it is not symmetric. This project's own red verb
catalogue includes lateral movement and exfiltration, and the honest detections
for both are network-side: the endpoint may see nothing at all, which is rather
the point of choosing them. A model whose entire notion of "detection" was
learned from host telemetry cannot propose a network control, so when the
kernel pairs a red verb against ``detected_by`` and finds silence, it would
report a detection gap that is really a *corpus* gap. Wrong in one direction,
every time, and invisible from inside the finding. This source exists so that
the model has somewhere to reach when the answer is "a sensor on the link".

**The identifier density is unusually good.** The measurement this corpus was
rebuilt around said that an identifier sitting next to its human name in running
text is worth far more than the identifier alone — ``T1547.001`` beside
"Registry Run Keys" moved a sample from -45% to +13% against gpt2. Every rule
here carries a ``sid``, a ``msg`` that names the thing in English, a
``classtype``, and usually a ``reference``. Better: 33,145 of the Emerging
Threats rules carry ``mitre_technique_id`` and ``mitre_technique_name`` in their
metadata, and 7,577 name a CVE. So one rule routinely yields
``T1210 Exploitation Of Remote Services``, ``TA0008 Lateral Movement`` and
``CVE-2019-0708`` in prose, immediately above the signature that detects it.
Those joins are written back into their **wild form** before rendering, because
ET does not store them that way: metadata values are underscore-mangled
(``cve CVE_2008_4250``, ``mitre_tactic_name Lateral_Movement``) and ``reference``
stores a bare fragment (``reference:cve,2019-0708``). Rendered naively this
source would emit thousands of identifiers in a shape that appears nowhere else
in the world, which is worse than emitting none — the same argument
:mod:`~training.corpus.sources.capec` makes about ``Entry_ID="1574.010"``.

Upstreams and their licences
----------------------------

**Emerging Threats open ruleset** — 70,564 rules, and the body of this source.
ET's own ``LICENSE`` was fetched and read rather than assumed, and it does not
say one thing; it partitions by sid::

    sids 1..3464 and 100000000..100000908   GPLv2
    sids 2000000..2799999                   BSD 3-clause (Emerging Threats)
    sids 2800000..2900000                   ETPRO — proprietary

Measured against the file: all 70,564 rules fall in the BSD range, and none in
the ETPRO range. The sid filter in :func:`_licence_of` is enforced anyway, and
refuses anything outside the ranges the licence names, so a future ruleset that
starts shipping ETPRO or unnumbered rules is dropped rather than silently
trained on. Within the BSD range there is one honest complication: the 1,690
rules whose ``msg`` begins ``GPL `` are exactly, with no overlap in either
direction, the sids 2100000..2103461 — the old Sourcefire/Snort community
ruleset renumbered into ET's block. They are declared GPL-2.0 rather than
covered by ET's blanket BSD sentence, because that is what they are.

**Suricata's own rules** — the 30 ``rules/*.rules`` files from ``OISF/suricata``
at a pinned release tag, GPL-2.0 with the rest of the engine. Only 483 rules and
107 KB, but a register the ET set does not contain at all: these do not match
bytes, they fire on what the *decoder* concluded. ``decode-event:ipv4.trunc_pkt``,
``stream-event:3whs_synack_with_wrong_ack``,
``app-layer-event:http.unexpected_request_body`` — several hundred named
protocol anomalies, which is a dictionary of ways traffic can be malformed and
has no equivalent anywhere else in this corpus. Suricata's
``etc/classification.config`` comes with them; it is not emitted as documents,
it is the lookup that turns ``classtype:attempted-admin`` into "Attempted
Administrator Privilege Gain, priority 1" in the rendered prose.

Considered and **refused**, with the reason, because a source that only lists
what it took is not telling you how it decided:

* ``ptresearch/AttackDetection`` — named in the brief, and its ``LICENSE`` is a
  proprietary EULA, not an open licence. Read in full: "personal,
  non-commercial use" only, "shall not distribute, rent or lease", "shall not
  modify... nor make any changes to the source code", governed by the law of
  the Russian Federation. GitHub's own licence detection says ``NOASSERTION``.
  Excellent rules; not ours to train on. Refused outright.
* **Snort 3 community ruleset** (``snort3-community-rules.tar.gz``) — 4,017
  rules of a genuinely third dialect, and it downloads cleanly. The archive
  ships ``LICENSE`` (GPLv2) *and* ``VRT-License.txt`` (the Cisco Snort
  Subscriber Rules License Agreement v3.1) side by side, with nothing inside
  the archive saying which of the two governs ``snort3-community.rules``.
  Cisco's website says the community set is GPLv2 and that is probably right,
  but "probably" is not a licence statement, and the cost of being wrong is a
  corpus that cannot be published. Refused on ambiguity. The loss is small:
  classic Snort syntax is already present through ET's GPL block above.
* **Zeek scripts** (BSD 3-clause, cleanly licensed) — refused on register, not
  licence. A Zeek policy script is a program in a general-purpose event-driven
  language; its surface form is C-like program text, and its detection logic
  lives in control flow rather than in a signature. This source declares
  DETECTION and ``build.py`` aggregates coverage by the source's declared
  register, so shipping a body of program text under that label would overstate
  the one report that matters — the same call :mod:`~training.corpus.sources.splunk`
  makes when it leaves ``stories/`` on the floor. Zeek belongs in its own
  source if SYSTEM ever wants it.
* **Falco rules** (Apache-2.0, cleanly licensed) — refused on scope. Falco is a
  syscall and container runtime monitor; its rules are host telemetry in YAML,
  which is both the argument this module was written *against* and a shape
  Sigma already supplies 3,000 examples of. Putting them here would make this
  file's own opening paragraph false.

Traps this adapter is built around
----------------------------------

**The URL in the brief serves the wrong ruleset.** ``open/suricata/`` and
``open/suricata-7.0.3/`` both return 200 and differ by 220 KB, and the
difference is not churn: the unversioned path is the Suricata-6-era build, which
still writes the legacy sticky-buffer syntax (``file_data;``, ``http_uri;``)
that modern Suricata deprecated in favour of ``file.data:``/``http.uri:``.
Measured by pulling the same byte range from both. Training on the legacy path
would teach a dialect that is on its way out, so :data:`_ET_VERSION` is pinned
to a versioned path and the fetch records which one it used.

**``normalise()`` must not be worked around, and here it does not need to be.**
The contract preserves horizontal whitespace, which matters for every other
source; for this one the requirement is stricter, because an ET rule is a
single line of up to 3,180 characters and *any* edit inside it is a silently
broken rule rather than an ugly one. Verified on the live file: the ET ruleset
contains zero control bytes, zero non-ASCII characters, no trailing whitespace
and no space run long enough to trip the absurd-run clamp, so ``normalise`` is
a byte-for-byte no-op on all 70,564 rule lines. Verified again at runtime, per
document, by :func:`_render` — the emitted text must still contain the rule
verbatim or the build stops. That check is not an ``assert``: ``python -O``
strips those, and this is the invariant between an upstream change and a corpus
of truncated signatures.

**Options cannot be split on ``;``.** A ``content`` value may contain anything,
including quotes and semicolons, and Suricata's escaping rules are the only
thing that makes the option list parseable. :func:`_split_options` is therefore
a scanner, not a ``split``: it consumes ``\\x`` as one unit so ``\\;`` and ``\\"``
never terminate anything, and tracks double-quote state so an unescaped ``;``
inside a string is data. On the live file that recovers a ``sid`` from 70,556 of
70,564 rules. The remaining 8 contain a **raw** ``"`` inside a ``pcre`` character
class, which desynchronises quote tracking — ET publishes them that way — so
:func:`_split_options` reports that it ended mid-string and the caller retries
with a quote-blind split on unescaped ``;``, which recovers all 8. Both counts
are printed at build time rather than quietly swallowed.

**"One rule, one line" is true of ET and false next door.** All 70,564 ET rules
are single lines; ``dnp3-events.rules`` in Suricata's own set writes 13 of its
rules across two lines with a trailing backslash. A line-per-rule reader does
not fail on those — it silently parses the first half, finds no closing
parenthesis, and reports eight real DNP3 anomaly detections as corrupt input.
:func:`_iter_rules` absorbs continuations into one block, which is kept verbatim
in the document, and parses a copy with the backslash-newlines collapsed.

**One sub-topic can eat the source.** 26,822 rules are ``ET MALWARE`` and 6,093
are ``ET DYN_DNS``, and thousands of those differ from each other in exactly one
field: the domain inside ``content:``. That is the dynamic-DNS lookup table that
:mod:`~training.corpus.sources.splunk` capped and the Perl man pages that
:mod:`~training.corpus.sources.manpages` capped, arriving a third time. See
:data:`_SKELETON_QUOTA`.

**What the source is made of, measured rather than claimed.** 57.2M characters,
of which 24.7M (43%) is rule syntax and 32.5M is the title line and the prose
paragraph. Prose being the larger half is worth stating out loud, because
:mod:`~training.corpus.sources.splunk` refused to smuggle campaign narrative
into a DETECTION-declared source and this file should be held to the same
standard. The difference is what the prose *is*: it contains no narrative and
almost no free English. Every sentence is generated from the rule beside it and
is dense with the same vocabulary — buffer names, classtype tokens, flow
directions, ``T1041``, ``CVE-2019-0708``, ``signature_severity Major`` — so it
is detection text describing detection syntax, which is the join this register
exists to supply. A reader who disagrees can lower the ratio by trimming
:func:`_render`; the numbers are here so the choice is visible.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from training.corpus import net
from training.corpus.source import (
    Document,
    Register,
    Side,
    SourceError,
    SourceSpec,
    normalise,
)

__all__ = ["SPEC"]


# ---------------------------------------------------------------------------
# upstreams
# ---------------------------------------------------------------------------

#: Pinned, and pinned deliberately — see the docstring. ET keeps every version
#: directory it has ever published, so this path does not rot, while the
#: unversioned ``open/suricata/`` alias silently tracks the legacy build.
_ET_VERSION = "suricata-7.0.3"
_ET_BASE = "https://rules.emergingthreats.net/open"
_ET_RULES_URL = f"{_ET_BASE}/{_ET_VERSION}/emerging-all.rules"
_ET_LICENSE_URL = f"{_ET_BASE}/{_ET_VERSION}/LICENSE"
_ET_BLOB = "emerging-all.rules"
_ET_LICENSE_BLOB = "emerging-LICENSE.txt"

#: 46.5 MB at the time of writing and it has only ever grown. A floor this far
#: below it refuses a truncated transfer or an HTML error page served with a
#: 200, which is the realistic way this download fails.
_ET_MIN_BYTES = 20_000_000

#: A release tag rather than a branch: the rules move with engine features, and
#: a build that cannot say which engine's rule set it read is not reproducible.
_SURICATA_REF = "suricata-8.0.7"
_SURICATA_API = (
    f"https://api.github.com/repos/OISF/suricata/contents/rules?ref={_SURICATA_REF}"
)
_SURICATA_RAW = f"https://raw.githubusercontent.com/OISF/suricata/{_SURICATA_REF}"
_SURICATA_DIR = "suricata"
_SURICATA_COPYING = "suricata-COPYING.txt"

#: The classtype dictionary, cached beside the rules. Not emitted as documents:
#: 43 lines of ``config classification:`` would be a rounding error of text and
#: would read as a config file rather than as detection. It earns its download
#: as the lookup that lets the prose say "Attempted Administrator Privilege
#: Gain, priority 1" instead of repeating the bare token already in the rule.
_CLASSIFICATION = "classification.config"

#: 30 ``.rules`` files upstream. A floor under that catches a moved directory or
#: a rate-limited API listing at fetch time, loudly, instead of as a thin build.
_MIN_SURICATA_FILES = 20

#: Written last and only on success, so a half-populated cache re-fetches rather
#: than being mistaken for a complete one.
_MARKER = ".fetched.json"


# ---------------------------------------------------------------------------
# licensing, enforced rather than declared
# ---------------------------------------------------------------------------

#: ``(low, high, licence)`` from Emerging Threats' own LICENSE file, inclusive.
#: The ETPRO block is deliberately absent: a sid that falls in no range here is
#: refused, which is the behaviour that matters, because the failure mode worth
#: designing against is ET adding rules under terms this file has never read.
_ET_SID_RANGES: tuple[tuple[int, int, str], ...] = (
    (1, 3464, "GPL-2.0"),
    (100_000_000, 100_000_908, "GPL-2.0"),
    # The renumbered Sourcefire/Snort community block, which ET's blanket BSD
    # sentence covers on paper and which is GPL-2.0 in fact. Checked against the
    # file: the 1,690 rules whose msg starts "GPL " are exactly this range, and
    # no rule outside it starts that way.
    (2_100_000, 2_103_461, "GPL-2.0"),
    (2_000_000, 2_799_999, "BSD-3-Clause"),
)

#: Proprietary. Absent from the open distribution today; refused by name anyway
#: so that the refusal survives an upstream that stops being careful.
_ETPRO_RANGE = (2_800_000, 2_900_000)


def _licence_of(sid: int) -> str | None:
    """The licence covering an ET sid, or ``None`` if the rule may not be used.

    Narrower ranges are listed first in :data:`_ET_SID_RANGES` and win, which is
    what makes the GPL block inside the BSD block expressible at all.
    """
    if _ETPRO_RANGE[0] <= sid <= _ETPRO_RANGE[1]:
        return None
    for low, high, licence in _ET_SID_RANGES:
        if low <= sid <= high:
            return licence
    return None


# ---------------------------------------------------------------------------
# the concentration cap
# ---------------------------------------------------------------------------

#: A rule *skeleton* — category, action, protocol, direction, classtype and the
#: ordered list of option keywords — may contribute at most this many documents.
#:
#: Measured on the live ET set: 70,564 rules collapse to 19,887 skeletons, and
#: the largest single skeleton has 2,569 members. Those members are not variants
#: of a detection; they are one detection applied to 2,569 different domains,
#: with the domain sitting in ``content:`` and nothing else changing. Six
#: thousand of them are ``ET DYN_DNS``, which is literally a list of dynamic-DNS
#: providers wearing rule syntax. That is the ``dynamic_dns_providers`` lookup
#: table :mod:`~training.corpus.sources.splunk` capped and the 3,000 Perl man
#: pages :mod:`~training.corpus.sources.manpages` capped, and the argument is
#: the same one: twelve exposures teach a form, six thousand teach a domain
#: list, and a model this size that memorises a domain list has spent capacity
#: on something a grep would have done better.
#:
#: The cap is on *shape*, never on content. Every one of the 19,887 distinct
#: skeletons survives, up to the quota; nothing is truncated, only whole
#: documents are declined, and the count is printed at build time.
_SKELETON_QUOTA = 12

#: …except that a rule naming a CVE is exempt. A skeleton with 1,769 members in
#: ``ET WEB_SPECIFIC_APPS`` is not one detection repeated: it is one *technique*
#: — SQL injection against a query parameter — aimed at 1,769 different products,
#: each with its own CVE. Capping those would throw away 1,757 distinct
#: vulnerability identifiers to save 1.5 MB, and identifiers in running text are
#: the single most expensive thing this corpus was missing. The exemption costs
#: 3,628 extra documents and is worth all of them.
_CVE_EXEMPT = True

#: Suricata's own 483 event rules are exempt from the cap entirely. Every
#: ``stream-event`` rule has an identical skeleton by construction, so a shape
#: quota would keep 12 of them and discard 400 named protocol anomalies — the
#: exact vocabulary they were collected for. The cap exists to stop one
#: sub-topic flooding a 37,000-document source; 484 rules cannot flood anything.

#: Below this a "rule" is a fragment. The shortest real ET rule is 257
#: characters and the rendering adds several hundred more, so this only ever
#: catches a parse that went wrong.
_MIN_CHARS = 200


# ---------------------------------------------------------------------------
# rule grammar
# ---------------------------------------------------------------------------

#: The start of a rule, enabled or commented out. ``rejectsrc``/``rejectdst``/
#: ``rejectboth`` are Suricata spellings; ``sdrop``/``activate``/``dynamic`` are
#: Snort ones, kept because ET carries renumbered Snort rules.
#:
#: The whole seven-field header is matched, up to the opening parenthesis,
#: rather than just the action word. Matching only the action treats
#: ``# alert if STARTTLS was not followed by actual SSL/TLS`` — a real English
#: comment in ``app-layer-events.rules`` — as a disabled rule, and then reports
#: it as a parse failure. Requiring an arrow and a ``(`` makes prose that opens
#: with the word "alert" a non-match instead of a false alarm, which keeps the
#: unparseable counter meaningful: it should only ever move when upstream
#: syntax actually changes.
#:
#: Address fields tolerate a bracket group containing spaces
#: (``[$HOME_NET, !10.0.0.0/8]``), which is legal and which ``\\S+`` would miss.
_RULE_LINE = re.compile(
    r"^\s*(#\s*)?"
    r"(?:alert|drop|pass|reject|rejectsrc|rejectdst|rejectboth|sdrop|log|"
    r"activate|dynamic)\s+"
    r"[A-Za-z0-9_.-]+\s+"
    r"(?:\[[^\]]*\]|\S+)\s+(?:\[[^\]]*\]|\S+)\s+"
    r"(?:->|<>|<-)\s+"
    r"(?:\[[^\]]*\]|\S+)\s+(?:\[[^\]]*\]|\S+)\s*\("
)

#: A rule continued onto the next line. Every one of the 70,564 ET rules is a
#: single line — the brief for this source said so and it is true of ET — but
#: Suricata's own ``dnp3-events.rules`` writes 13 of its rules across two lines
#: with a trailing backslash, and a reader that assumed one line per rule
#: dropped eight real DNP3 anomaly detections and reported them as corrupt.
#: So continuations are joined before parsing, while the document still shows
#: the rule laid out exactly as upstream wrote it.
_CONTINUED = re.compile(r"\\\s*$")

#: Backslash-newline plus the indentation of the continued line, collapsed to
#: one space to recover the logical rule. Safe here by measurement: no rule in
#: either upstream ends a line with an escaped backslash inside a content value,
#: which is the only way this could join something it should not.
_CONTINUATION = re.compile(r"\\\n[ \t]*")

#: Option keywords that modify or transform the *preceding* content match rather
#: than naming a buffer to match in. Needed because Suricata writes both as bare
#: valueless options — ``http.uri;`` and ``nocase;`` are syntactically identical
#: — and telling them apart is what lets the prose say which buffers a rule
#: reads. Anything valueless and not in here is treated as a buffer, so a new
#: sticky buffer is described correctly the day it appears and a new *modifier*
#: is the only thing that needs adding.
_MODIFIERS = frozenset({
    "nocase", "fast_pattern", "rawbytes", "startswith", "endswith", "bsize",
    "depth", "offset", "distance", "within", "isdataat", "dotprefix",
    "to_lowercase", "to_uppercase", "to_sha1", "to_md5", "to_sha256",
    "url_decode", "strip_whitespace", "strip_pseudo_headers",
    "header_lowercase", "xor", "compress_whitespace", "pcrexform",
    "noalert", "sameip", "base64_decode", "filestore", "ftpbounce",
})

#: Direction phrases keyed on the pair of address specifications. ``$HOME_NET``
#: and ``$EXTERNAL_NET`` are the two variables every deployment defines, so this
#: covers the overwhelming majority; anything else falls through to naming the
#: two sides literally, which is still true.
_DIRECTIONS: dict[tuple[str, str], str] = {
    ("$EXTERNAL_NET", "$HOME_NET"):
        "inbound, from outside the monitored network toward a protected host",
    ("$HOME_NET", "$EXTERNAL_NET"):
        "outbound, from a protected host toward the internet",
    ("$HOME_NET", "$HOME_NET"):
        "internal, between two hosts inside the monitored network",
    ("$EXTERNAL_NET", "$EXTERNAL_NET"):
        "external on both sides, traffic merely transiting the sensor",
    ("any", "any"): "in any direction the sensor sees",
}

#: ``flow:`` tokens in plain words. The direction tokens are the ones that
#: matter most: a rule that matches to_server and a rule that matches to_client
#: are looking for opposite halves of the same conversation, and that
#: distinction is invisible to anything that only reads the content patterns.
_FLOW_WORDS: dict[str, str] = {
    "established": "on an established flow",
    "not_established": "on a flow that is not yet established",
    "stateless": "on any packet, with or without flow state",
    "to_server": "in the client-to-server direction",
    "from_client": "in the client-to-server direction",
    "to_client": "in the server-to-client direction",
    "from_server": "in the server-to-client direction",
    "only_stream": "only on reassembled stream data",
    "no_stream": "only on raw packets, never reassembled stream data",
    "only_frag": "only on reassembled IP fragments",
    "no_frag": "only on unfragmented packets",
}

#: Keywords that fire on an engine verdict instead of on packet bytes — the
#: whole reason Suricata's own rules are worth 30 extra downloads.
_EVENT_KEYWORDS = ("decode-event", "stream-event", "app-layer-event")

#: Header-field keywords, grouped so the prose can say "IP and TCP header
#: fields" rather than listing nine keywords nobody needs spelled out.
_HEADER_KEYWORDS = frozenset({
    "itype", "icode", "icmp_id", "icmp_seq", "flags", "fragbits", "fragoffset",
    "ttl", "ipopts", "ip_proto", "window", "ack", "seq", "id", "tos",
    "stream_size", "dsize", "urilen", "filesize",
})

#: Stateful keywords: a rule using these is one step of a multi-packet
#: detection, which is a different kind of logic from a single pattern match and
#: worth naming in the prose as such.
_STATE_KEYWORDS = frozenset({"flowbits", "xbits", "flowint", "hostbits"})

_BYTE_KEYWORDS = ("byte_test", "byte_jump", "byte_extract", "byte_math")

#: ``reference:`` prefixes that denote a real identifier, and how to write it
#: the way the world writes it. ``url`` and the hash kinds are handled
#: separately since they are not identifiers in this sense.
_REFERENCE_NAMES: dict[str, str] = {
    "cve": "CVE",
    "bugtraq": "Bugtraq",
    "bid": "Bugtraq",
    "nessus": "Nessus plugin",
    "arachnids": "arachNIDS",
    "osvdb": "OSVDB",
    "secunia": "Secunia advisory",
    "mcafee": "McAfee",
    "milw0rm": "milw0rm",
    "exploitdb": "Exploit-DB",
}

_CVE_FRAGMENT = re.compile(r"^(\d{4})[-_](\d{4,})$")
_CVE_MANGLED = re.compile(r"^CVE[-_](\d{4})[-_](\d{4,})$", re.IGNORECASE)
_DATE_MANGLED = re.compile(r"^(\d{4})_(\d{2})_(\d{2})$")


# ---------------------------------------------------------------------------
# fetch
# ---------------------------------------------------------------------------

def _fetch(cache_dir: Path) -> Path:
    """Populate ``cache_dir`` with both rulesets and both licences. Idempotent.

    A populated cache short-circuits before any network access: the marker is
    written only after everything has landed, so an interrupted run retries
    rather than being mistaken for a complete one. All transfers go through
    :mod:`training.corpus.net`, which is the project's one source of verified
    TLS — and which this source needed immediately: the first attempt to pull
    the Suricata rules with a bare ``urllib.request.urlretrieve`` died with
    ``CERTIFICATE_VERIFY_FAILED`` on this machine, which is precisely the
    python.org macOS trust-store hole that module exists to close.

    Both licence files are cached beside the rules. The ET one is not
    decoration: :func:`_licence_of` enforces the sid partition it describes, and
    a reader who wants to check that claim should not have to go back to the
    network to do it.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    marker = cache_dir / _MARKER
    if marker.is_file() and (cache_dir / _ET_BLOB).is_file():
        return cache_dir

    suricata_dir = cache_dir / _SURICATA_DIR
    suricata_dir.mkdir(parents=True, exist_ok=True)

    try:
        net.download(_ET_RULES_URL, cache_dir / _ET_BLOB, timeout=600)
        net.download(_ET_LICENSE_URL, cache_dir / _ET_LICENSE_BLOB)
    except net.NetworkError as exc:
        raise SourceError(f"netrules: {exc}") from exc

    size = (cache_dir / _ET_BLOB).stat().st_size
    if size < _ET_MIN_BYTES:
        (cache_dir / _ET_BLOB).unlink(missing_ok=True)
        raise SourceError(
            f"netrules: {_ET_RULES_URL} returned {size:,} bytes, expected at "
            f"least {_ET_MIN_BYTES:,}. That is a truncated transfer or an error "
            "page served with a 200, not a ruleset; fix the fetch rather than "
            "training on whatever arrived."
        )

    # One API call for the listing, then a raw fetch per file. Enumerating
    # rather than hardcoding 30 filenames means a rules file added upstream is
    # collected instead of silently missed, which is the same argument
    # build.py's import-time source discovery makes one level up.
    try:
        listing = json.loads(net.fetch(_SURICATA_API, timeout=120))
    except (net.NetworkError, ValueError) as exc:
        raise SourceError(
            f"netrules: could not list {_SURICATA_API}: {exc}. GitHub rate-limits "
            "unauthenticated API calls to 60/hour; wait rather than skipping the "
            "engine-event rules, which no other source supplies."
        ) from exc
    if not isinstance(listing, list):
        raise SourceError(
            f"netrules: {_SURICATA_API} did not return a directory listing "
            f"(got {type(listing).__name__}). The tag or path has moved."
        )

    files = 0
    for entry in sorted(listing, key=lambda e: str(e.get("name", ""))):
        name = str(entry.get("name", ""))
        url = entry.get("download_url")
        # Names come from the network, so they never reach the filesystem
        # unchecked: a single path component ending in .rules, nothing else.
        if not name.endswith(".rules") or "/" in name or name.startswith("."):
            continue
        if not isinstance(url, str) or not url.startswith("https://"):
            continue
        try:
            net.download(url, suricata_dir / name, timeout=120)
        except net.NetworkError as exc:
            raise SourceError(f"netrules: {name}: {exc}") from exc
        files += 1

    if files < _MIN_SURICATA_FILES:
        raise SourceError(
            f"netrules: only {files} rules files under rules/ at "
            f"{_SURICATA_REF} (expected >= {_MIN_SURICATA_FILES}). The upstream "
            "layout has changed; fix the adapter."
        )

    try:
        net.download(f"{_SURICATA_RAW}/etc/classification.config",
                     cache_dir / _CLASSIFICATION)
        net.download(f"{_SURICATA_RAW}/COPYING", cache_dir / _SURICATA_COPYING)
    except net.NetworkError as exc:
        raise SourceError(f"netrules: {exc}") from exc

    marker.write_text(
        json.dumps(
            {
                "emerging_threats": {
                    "url": _ET_RULES_URL,
                    "version_path": _ET_VERSION,
                    "bytes": size,
                    "licence_url": _ET_LICENSE_URL,
                    "note": "the unversioned open/suricata/ path serves the "
                            "legacy Suricata-6 syntax build and is not used",
                },
                "suricata": {
                    "repo": "https://github.com/OISF/suricata",
                    "ref": _SURICATA_REF,
                    "rules_files": files,
                },
                "fetched_utc": datetime.now(timezone.utc).isoformat(
                    timespec="seconds"
                ),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return cache_dir


# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------

def _split_options(text: str) -> tuple[list[str], bool]:
    """Split a rule's option list on its real separators. Returns ``(opts, ok)``.

    ``ok`` is False when the scan ended inside an unterminated string, which is
    the caller's signal to retry with :func:`_split_options_unquoted`.

    A ``split(";")`` here would be wrong in two independent ways at once, and
    both occur in the live ruleset. ``content:"|3b|"`` is a semicolon expressed
    as a hex byte, which is fine, but ``content:"a\\;b"`` is a semicolon
    expressed as an escape, and ``pcre:"/foo(?=;)/"`` puts one inside a string.
    Suricata's grammar says a ``;`` or ``"`` or ``\\`` inside a quoted value is
    backslash-escaped and that a value may otherwise contain any byte, so the
    only correct reader is a scanner that consumes an escape pair as one unit
    and knows whether it is inside quotes.

    Deliberately *not* using a regex with lookbehind: ``(?<!\\\\);`` gets
    ``a\\\\;b`` wrong, where the backslash is itself escaped and the semicolon
    really is a separator. A character scan has no such blind spot.
    """
    opts: list[str] = []
    buf: list[str] = []
    quoted = False
    i = 0
    n = len(text)
    while i < n:
        char = text[i]
        if char == "\\" and i + 1 < n:
            buf.append(text[i:i + 2])
            i += 2
            continue
        if char == '"':
            quoted = not quoted
            buf.append(char)
            i += 1
            continue
        if char == ";" and not quoted:
            opts.append("".join(buf).strip())
            buf = []
            i += 1
            continue
        buf.append(char)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        opts.append(tail)
    return [o for o in opts if o], not quoted


def _split_options_unquoted(text: str) -> list[str]:
    """Fallback for the eight rules ET publishes with an unbalanced quote.

    They carry a raw ``"`` inside a ``pcre`` character class — ``[\\x22\\x27]``
    written out literally in one case, an unescaped quote in a filename pattern
    in another — which desynchronises quote tracking and merges every option
    after it into one blob. Splitting on unescaped ``;`` regardless of quotes
    recovers all eight, and is safe *for them* because none of their string
    values contains an unescaped semicolon.

    It is the fallback rather than the rule because for the other 70,556 the
    reverse is true, and a parser that is right 100% of the time on eight rules
    and wrong occasionally on seventy thousand is the worse trade.
    """
    opts: list[str] = []
    buf: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        char = text[i]
        if char == "\\" and i + 1 < n:
            buf.append(text[i:i + 2])
            i += 2
            continue
        if char == ";":
            opts.append("".join(buf).strip())
            buf = []
            i += 1
            continue
        buf.append(char)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        opts.append(tail)
    return [o for o in opts if o]


def _split_header(text: str) -> list[str]:
    """Whitespace-split a rule header, but never inside ``[...]``.

    ``alert tcp [$HOME_NET, !10.0.0.0/8] any -> $EXTERNAL_NET [80, 443]`` is
    legal, and a plain ``split()`` turns its seven fields into ten. ET does not
    currently write a space inside a bracket group, which is exactly why this
    would have been an invisible bug rather than a loud one.
    """
    fields: list[str] = []
    buf: list[str] = []
    depth = 0
    for char in text:
        if char == "[":
            depth += 1
        elif char == "]":
            depth = max(0, depth - 1)
        if char.isspace() and depth == 0:
            if buf:
                fields.append("".join(buf))
                buf = []
            continue
        buf.append(char)
    if buf:
        fields.append("".join(buf))
    return fields


class _Rule:
    """One parsed rule: the verbatim line plus enough structure to describe it.

    A class rather than a dict because the verbatim text and the parse must
    travel together — the parse exists only to write the prose above the rule,
    and a rendering that lost track of which line it was describing would be
    worse than no rendering at all.
    """

    __slots__ = ("raw", "enabled", "action", "protocol", "src", "sport",
                 "arrow", "dst", "dport", "options", "first", "multi",
                 "keywords", "clean_parse")

    def __init__(self, raw: str, enabled: bool) -> None:
        self.raw = raw
        self.enabled = enabled
        # The parse works on a logical line; the document keeps ``raw``. A
        # disabled rule may be commented on every one of its physical lines, so
        # the marker is stripped per line before the continuations are joined.
        body = raw
        if not enabled:
            body = "\n".join(re.sub(r"^\s*#\s*", "", line)
                             for line in raw.split("\n"))
        body = _CONTINUATION.sub(" ", body).strip()
        open_paren = body.find("(")
        if open_paren < 0 or not body.endswith(")"):
            raise ValueError("no option list")
        header = _split_header(body[:open_paren])
        if len(header) < 7:
            raise ValueError(f"header has {len(header)} fields, expected 7")
        (self.action, self.protocol, self.src, self.sport,
         self.arrow, self.dst, self.dport) = header[:7]

        options, ok = _split_options(body[open_paren + 1:-1])
        self.clean_parse = ok
        if not ok:
            options = _split_options_unquoted(body[open_paren + 1:-1])
        self.options = options

        #: First value seen per keyword, and every value per keyword. Both are
        #: needed: ``classtype`` appears once and ``reference`` many times, and
        #: collapsing either into the other loses something.
        self.first: dict[str, str] = {}
        self.multi: dict[str, list[str]] = {}
        self.keywords: list[str] = []
        for option in options:
            name, sep, value = option.partition(":")
            name = name.strip()
            value = value.strip() if sep else ""
            self.keywords.append(name)
            self.multi.setdefault(name, []).append(value)
            self.first.setdefault(name, value)

    @property
    def sid(self) -> int | None:
        raw = self.first.get("sid", "")
        return int(raw) if raw.isdigit() else None

    @property
    def msg(self) -> str:
        return _unquote(self.first.get("msg", ""))

    @property
    def category(self) -> str:
        """The ``ET MALWARE``-style prefix, used only as a cap dimension."""
        words = self.msg.split()
        if not words:
            return "?"
        if words[0] == "ET" and len(words) > 1:
            return f"ET {words[1]}"
        return words[0]

    @property
    def metadata(self) -> list[tuple[str, str]]:
        """``metadata:`` as ``(key, value)`` pairs, in the order written.

        ET writes ``metadata:created_at 2019_05_21, mitre_technique_id T1210``
        — comma-separated items, each a key and a space-separated value, and the
        same key may legitimately repeat (a rule can map to several techniques).
        A dict would silently keep one of them.
        """
        pairs: list[tuple[str, str]] = []
        for blob in self.multi.get("metadata", []):
            for item in blob.split(","):
                item = item.strip()
                if not item:
                    continue
                key, _, value = item.partition(" ")
                pairs.append((key.strip(), value.strip()))
        return pairs

    def skeleton(self) -> tuple:
        """The shape key the concentration cap counts. See :data:`_SKELETON_QUOTA`."""
        return (self.category, self.action, self.protocol, self.arrow,
                self.first.get("classtype", ""), tuple(self.keywords))


def _unquote(value: str) -> str:
    """Strip the surrounding quotes of an option value, keeping the inside.

    The inside is deliberately untouched: ``\\;`` and ``\\"`` stay escaped,
    because this text goes into prose sitting directly above the rule that
    contains it and rewriting one and not the other would make them disagree.
    """
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


# ---------------------------------------------------------------------------
# identifiers, written the way the world writes them
# ---------------------------------------------------------------------------

def _wild_cve(fragment: str) -> str | None:
    """``2019-0708``, ``CVE_2019_0708`` → ``CVE-2019-0708``; else ``None``.

    Both mangled forms occur: ``reference:cve,`` drops the prefix entirely and
    the ``metadata`` ``cve`` key substitutes underscores for hyphens. Neither
    shape appears anywhere outside a rules file, so emitting either verbatim
    would spend thousands of identifier mentions teaching a spelling that will
    never be seen again — and the CVE register was measured at -26% against
    gpt2 precisely because the corpus had no canonical ones.
    """
    fragment = fragment.strip()
    match = _CVE_MANGLED.match(fragment) or _CVE_FRAGMENT.match(fragment)
    if not match:
        return None
    return f"CVE-{match.group(1)}-{match.group(2)}"


def _unmangle(value: str) -> str:
    """``Exploitation_Of_Remote_Services`` → ``Exploitation Of Remote Services``.

    ET stores every metadata value with underscores for spaces because the
    metadata grammar is comma-and-space delimited and a literal space would
    break it. The underscores are an encoding artefact of that grammar, not part
    of the name, so they come out before the name goes into a sentence.
    """
    return value.replace("_", " ").strip()


def _references(rule: _Rule) -> tuple[list[str], list[str]]:
    """``(identifiers, urls)`` from the rule's ``reference:`` options.

    Split because they read differently in a sentence and because the URLs are
    long: a rule can carry four of them and they would drown the one CVE that
    matters. Identifiers always survive; URLs are capped by the caller.
    """
    identifiers: list[str] = []
    urls: list[str] = []
    for value in rule.multi.get("reference", []):
        kind, _, rest = value.partition(",")
        kind = kind.strip().lower()
        rest = rest.strip()
        if not rest:
            continue
        if kind == "url":
            urls.append(rest if rest.startswith(("http://", "https://"))
                        else f"http://{rest}")
        elif kind == "cve":
            cve = _wild_cve(rest)
            if cve and cve not in identifiers:
                identifiers.append(cve)
        elif kind in _REFERENCE_NAMES:
            label = f"{_REFERENCE_NAMES[kind]} {rest}"
            if label not in identifiers:
                identifiers.append(label)
        elif kind in {"md5", "sha1", "sha256"}:
            identifiers.append(f"{kind} {rest}")
    return identifiers, urls


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

def _classification_table(cache_dir: Path) -> dict[str, tuple[str, int]]:
    """``classtype`` → ``(description, priority)`` from Suricata's own config.

    Returns an empty mapping if the file is missing rather than failing the
    build: the classtype token is still in every rendered rule verbatim, so a
    missing lookup costs a clause of prose, not a document.
    """
    table: dict[str, tuple[str, int]] = {}
    path = cache_dir / _CLASSIFICATION
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return table
    for line in text.split("\n"):
        line = line.strip()
        if not line.startswith("config classification:"):
            continue
        body = line.split(":", 1)[1]
        parts = [p.strip() for p in body.split(",")]
        if len(parts) != 3 or not parts[2].isdigit():
            continue
        table[parts[0]] = (parts[1], int(parts[2]))
    return table


def _traffic_phrase(rule: _Rule) -> str:
    """The header in plain words: protocol, endpoints, and which way it flows."""
    def endpoint(address: str, port: str) -> str:
        where = "on any port" if port == "any" else f"on port {port}"
        return f"{address} {where}"

    both_ways = rule.arrow == "<>"
    direction = _DIRECTIONS.get((rule.src, rule.dst))
    if both_ways:
        sense = "in both directions"
    elif rule.arrow == "<-":
        sense = "reversed, from the right-hand side to the left"
    elif direction:
        sense = direction
    else:
        sense = "from the first address to the second"

    return (f"It matches {rule.protocol} traffic from {endpoint(rule.src, rule.sport)} "
            f"to {endpoint(rule.dst, rule.dport)} — {sense}")


def _flow_phrase(rule: _Rule) -> str:
    """``flow:established,to_server`` in words, or an empty string."""
    value = rule.first.get("flow", "")
    if not value:
        return ""
    words = [
        _FLOW_WORDS[token.strip()]
        for token in value.split(",")
        if token.strip() in _FLOW_WORDS
    ]
    if not words:
        return ""
    return ", and only " + " ".join(words)


def _detection_phrase(rule: _Rule) -> str:
    """How the rule actually decides, summarised without repeating the patterns.

    The patterns themselves are two lines below, verbatim, so restating them
    would only teach the model that this corpus says everything twice. What the
    summary adds is the *names of the mechanisms* — sticky buffers, anchoring
    keywords, byte tests, flow state — sitting in a sentence beside the syntax
    that expresses them, which is the join a rules file alone never provides.
    """
    counts = Counter(rule.keywords)
    clauses: list[str] = []

    buffers = [
        name for name in dict.fromkeys(rule.keywords)
        if name not in _MODIFIERS and not rule.first.get(name)
        and name not in {"msg", "sid", "rev", "metadata", "classtype"}
    ]

    n_content = counts.get("content", 0)
    if n_content:
        plural = "pattern" if n_content == 1 else "patterns"
        head = f"{n_content} content {plural}"
        if buffers:
            listed = ", ".join(buffers[:4])
            more = f" and {len(buffers) - 4} more" if len(buffers) > 4 else ""
            head += f" against the {listed}{more} buffer"
            if len(buffers) > 1:
                head += "s"
        if counts.get("fast_pattern"):
            head += ", one of them the fast_pattern"
        if counts.get("nocase"):
            head += ", case-insensitively"
        clauses.append(head)

    anchors = [k for k in ("depth", "offset", "distance", "within", "bsize",
                           "startswith", "endswith", "isdataat")
               if counts.get(k)]
    if anchors:
        clauses.append("positioned with " + "/".join(anchors))

    transforms = [k for k in ("dotprefix", "to_lowercase", "url_decode",
                              "base64_decode", "strip_whitespace", "to_sha1",
                              "header_lowercase", "pcrexform")
                  if counts.get(k)]
    if transforms:
        clauses.append("after transforming the buffer with "
                       + "/".join(transforms))

    n_pcre = counts.get("pcre", 0)
    if n_pcre == 1:
        clauses.append("one pcre")
    elif n_pcre > 1:
        clauses.append(f"{n_pcre} pcre patterns")

    byte_ops = [k for k in _BYTE_KEYWORDS if counts.get(k)]
    if byte_ops:
        clauses.append("arithmetic on raw bytes via " + "/".join(byte_ops))

    headers = [k for k in rule.keywords if k in _HEADER_KEYWORDS]
    if headers:
        clauses.append("header and size constraints ("
                       + "/".join(dict.fromkeys(headers)) + ")")

    events = [
        f"{name}:{_unquote(rule.first[name])}"
        for name in _EVENT_KEYWORDS if rule.first.get(name)
    ]
    if events:
        clauses.append("the engine event " + " and ".join(events))

    state = [k for k in rule.keywords if k in _STATE_KEYWORDS]
    if state:
        clauses.append("flow state carried across packets by "
                       + "/".join(dict.fromkeys(state)))

    if counts.get("threshold") or counts.get("detection_filter"):
        clauses.append("rate-limited by a threshold")

    if not clauses:
        return ""
    if len(clauses) == 1:
        return f" Detection is {clauses[0]}."
    if len(clauses) == 2:
        return f" Detection is {clauses[0]} and {clauses[1]}."
    return f" Detection is {', '.join(clauses[:-1])}, and {clauses[-1]}."


def _metadata_phrase(rule: _Rule, already_cited: set[str]) -> str:
    """Severity, confidence, targeting and the ATT&CK join, as sentences.

    The ATT&CK clause is the reason this function is longer than it looks like
    it should be. 33,145 ET rules carry a technique id *and* its name, and the
    whole corpus argument says those two must appear adjacent and in wild form.
    A rule can map to several techniques, so they are paired positionally in the
    order ET writes them rather than collapsed into a dict.
    """
    pairs = rule.metadata
    if not pairs:
        return ""
    by_key: dict[str, list[str]] = {}
    for key, value in pairs:
        by_key.setdefault(key, []).append(value)

    sentences: list[str] = []

    tags: list[str] = []
    for key, label in (("signature_severity", "signature severity"),
                       ("confidence", "confidence"),
                       ("deployment", "deployed at the"),
                       ("performance_impact", "performance impact"),
                       ("attack_target", "attack target"),
                       ("affected_product", "affected product"),
                       ("malware_family", "malware family")):
        values = by_key.get(key)
        if values:
            tags.append(f"{label} {_unmangle(values[0])}")
    if tags:
        sentences.append(" ET metadata records " + ", ".join(tags) + ".")

    techniques = by_key.get("mitre_technique_id", [])
    names = by_key.get("mitre_technique_name", [])
    tactics = by_key.get("mitre_tactic_id", [])
    tactic_names = by_key.get("mitre_tactic_name", [])
    if techniques:
        mapped = []
        for index, technique in enumerate(techniques):
            name = _unmangle(names[index]) if index < len(names) else ""
            mapped.append(f"{technique} {name}".strip())
        clause = " It is mapped to ATT&CK " + " and ".join(mapped)
        if tactics:
            tactic = []
            for index, identifier in enumerate(tactics):
                name = (_unmangle(tactic_names[index])
                        if index < len(tactic_names) else "")
                tactic.append(f"{identifier} {name}".strip())
            clause += ", under tactic " + " and ".join(tactic)
        sentences.append(clause + ".")

    # A CVE usually appears in both `reference:cve,` and `metadata: cve`, in
    # two different manglings of the same number. Rewritten to wild form they
    # collapse to one string, and saying it twice in one paragraph reads as a
    # rendering bug rather than as emphasis — so only a CVE the reference list
    # does not already carry earns a sentence here.
    cves = [c for c in (_wild_cve(v) for v in by_key.get("cve", []))
            if c and c not in already_cited]
    if cves:
        sentences.append(" The metadata also names " + ", ".join(cves) + ".")

    dates = []
    for key, label in (("created_at", "created"), ("updated_at", "last updated")):
        values = by_key.get(key)
        if values:
            match = _DATE_MANGLED.match(values[0])
            stamp = ("-".join(match.groups()) if match else values[0])
            dates.append(f"{label} {stamp}")
    if dates:
        sentences.append(" Rule " + ", ".join(dates) + ".")

    reason = by_key.get("deprecation_reason")
    former = by_key.get("former_category")
    if reason:
        note = f" Upstream marks it deprecated, reason {_unmangle(reason[0])}"
        if former:
            note += f"; it was formerly filed under {_unmangle(former[0])}"
        sentences.append(note + ".")
    elif former:
        sentences.append(f" It was formerly filed under {_unmangle(former[0])}.")

    return "".join(sentences)


def _render(rule: _Rule, upstream: str, licence: str,
            classification: dict[str, tuple[str, int]]) -> str:
    """One document: a title line, a prose paragraph, then the rule verbatim.

    The layout is chosen against :mod:`training.corpus.boilerplate`, which drops
    a long, mostly-alphabetic line that recurs across more than 25 documents —
    correct behaviour for an IETF copyright block, fatal here, because "It
    matches dns traffic from any on any port to any on any port" is a sentence
    thousands of these rules would legitimately share. So the sid appears in
    *every* line the renderer writes: in the title, in prose inside the
    paragraph, and in the rule's own ``sid:`` option. That makes each line
    unique, so nothing the filter sees can recur; and it independently satisfies
    the identifier argument, which wants the same id in several syntactic
    positions rather than one.

    The paragraph is a single line on purpose. Wrapping it would put a
    boilerplate-shaped fragment on its own line again, and this corpus does not
    reflow anything.
    """
    sid = rule.sid
    rev = rule.first.get("rev", "")
    title = f"Suricata rule sid:{sid}"
    if rev:
        title += f" rev:{rev}"
    if rule.msg:
        title += f" — {rule.msg}"

    state = "shipped enabled" if rule.enabled else (
        "shipped commented out, disabled by default")
    paragraph = [f"{upstream} ({licence}), sid {sid}, {state}."]
    paragraph.append(" " + _traffic_phrase(rule) + _flow_phrase(rule) + ".")

    classtype = rule.first.get("classtype", "")
    if classtype:
        described = classification.get(classtype)
        clause = f" It is classified {classtype}"
        if described:
            clause += f", {described[0]}, priority {described[1]}"
        priority = rule.first.get("priority")
        if priority:
            clause += f" (overridden to priority {priority} by the rule)"
        paragraph.append(clause + ".")

    target = rule.first.get("target")
    if target:
        side = ("the source address" if "src" in target else
                "the destination address")
        paragraph.append(f" The alert attributes the attack to {side}.")

    identifiers, urls = _references(rule)
    paragraph.append(_metadata_phrase(rule, set(identifiers)))

    if identifiers or urls:
        parts = list(identifiers)
        # Two URLs is enough to show the shape; a rule with six research links
        # would otherwise be mostly bibliography.
        parts.extend(urls[:2])
        if len(urls) > 2:
            parts.append(f"{len(urls) - 2} further links")
        paragraph.append(" References: " + ", ".join(parts) + ".")

    paragraph.append(_detection_phrase(rule))

    text = "\n\n".join([title, "".join(paragraph).strip(), rule.raw.rstrip()])
    cleaned = normalise(text)

    # Not an assert: `python -O` strips those, and this is the invariant
    # standing between an upstream change and a corpus of silently mangled
    # signatures. A Suricata rule is one line of up to 3,180 characters whose
    # every byte is load-bearing, so "the rule survived" has to be checked, not
    # believed. It holds today because the ET file is pure ASCII with no control
    # bytes and no trailing whitespace, which makes normalise() a no-op on a
    # rule line — but that is a property of the current upstream, not a promise.
    if rule.raw.rstrip() not in cleaned:
        raise SourceError(
            f"netrules: sid {sid} did not survive normalise() intact. Something "
            "in the upstream rule text is now being rewritten — a control byte, "
            "a long space run, trailing whitespace inside a content pattern. "
            "Fix the pipeline rather than emitting a rule that no longer means "
            "what it meant."
        )
    return cleaned


# ---------------------------------------------------------------------------
# documents
# ---------------------------------------------------------------------------

def _iter_rules(path: Path, counters: Counter) -> Iterator[_Rule]:
    """Parse every rule line in one file, enabled or commented out.

    Parse failures are counted rather than raised: a rules file can carry an
    example fragment or a half-written line in a comment, and one of those is
    not a reason to lose 70,000 documents. The counts are printed, because a
    parse failure rate that climbs is how an upstream syntax change announces
    itself.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise SourceError(f"netrules: cannot read {path}: {exc}") from exc

    lines = text.split("\n")
    index = 0
    while index < len(lines):
        line = lines[index]
        match = _RULE_LINE.match(line)
        if not match:
            index += 1
            continue
        # Absorb backslash continuations into one raw block, so the document
        # shows the rule the way the file writes it and the parser still sees a
        # complete option list. Bounded by the end of file: an unterminated
        # continuation consumes the remaining lines and then fails to parse,
        # which is loud, rather than looping.
        block = [line]
        while _CONTINUED.search(lines[index]) and index + 1 < len(lines):
            index += 1
            block.append(lines[index])
        index += 1
        line = "\n".join(block)
        counters["rule lines"] += 1
        try:
            rule = _Rule(line, enabled=not match.group(1))
        except ValueError:
            counters["unparseable"] += 1
            continue
        if not rule.clean_parse:
            # The eight ET rules with a raw quote inside a pcre. Counted so the
            # number is visible if it ever stops being eight.
            counters["quote-desync, reparsed"] += 1
        yield rule


def _documents(path: Path) -> Iterator[Document]:
    """Yield one Document per rule, ET first and then Suricata's own.

    Deduplication is by ``(upstream, sid)``. Two things make the upstream part
    necessary rather than pedantic: Suricata's ``files.rules`` uses ``sid:1`` as
    a worked example, and ET's block starts at 2,000,000, so a bare sid key
    would be right today and wrong the moment either changes. Rules with no
    parseable sid are dropped outright — nine of them, all commented-out
    examples in Suricata's ``files.rules`` — because a rule that cannot be
    identified cannot be deduplicated either.

    ET's enabled rules are emitted before its disabled ones so that when the
    concentration cap has to choose, a live detection wins the slot over one
    upstream has switched off. Both share the quota; they are the same ruleset.
    """
    cache_dir = path
    if not (cache_dir / _ET_BLOB).is_file():
        raise SourceError(f"netrules: no ruleset at {cache_dir / _ET_BLOB}")

    classification = _classification_table(cache_dir)
    counters: Counter[str] = Counter()
    seen: set[tuple[str, int]] = set()
    skeletons: Counter[tuple] = Counter()
    by_licence: Counter[str] = Counter()
    emitted = 0

    et_rules = list(_iter_rules(cache_dir / _ET_BLOB, counters))
    # Stable, and enabled-first: sorted() on a bool is False before True, so
    # `not enabled` puts the live rules first without disturbing file order
    # within each group.
    et_rules.sort(key=lambda r: (not r.enabled,))

    for rule in et_rules:
        sid = rule.sid
        if sid is None:
            counters["no sid"] += 1
            continue
        licence = _licence_of(sid)
        if licence is None:
            # Either the ETPRO block or a sid outside every range ET's LICENSE
            # describes. Both mean "we have not read the terms", and the answer
            # to that is not to train on it.
            counters["refused: licence not established"] += 1
            continue
        key = ("et", sid)
        if key in seen:
            counters["duplicate sid"] += 1
            continue

        shape = rule.skeleton()
        exempt = _CVE_EXEMPT and any(
            value.lower().startswith("cve,") for value in rule.multi.get("reference", [])
        )
        if not exempt:
            skeletons[shape] += 1
            if skeletons[shape] > _SKELETON_QUOTA:
                counters["held back by the shape cap"] += 1
                continue

        text = _render(rule, "Emerging Threats open ruleset", licence,
                       classification)
        if len(text) < _MIN_CHARS:
            counters["too short"] += 1
            continue
        seen.add(key)
        by_licence[licence] += 1
        emitted += 1
        yield Document(
            text=text,
            source="netrules",
            register=Register.DETECTION,
            side=Side.BLUE,
            ident=f"{_ET_BLOB}:{sid}",
        )

    suricata_dir = cache_dir / _SURICATA_DIR
    engine_files = (sorted(suricata_dir.glob("*.rules"))
                    if suricata_dir.is_dir() else [])
    for file in engine_files:
        for rule in _iter_rules(file, counters):
            sid = rule.sid
            if sid is None:
                counters["no sid"] += 1
                continue
            key = ("suricata", sid)
            if key in seen:
                counters["duplicate sid"] += 1
                continue
            # No shape cap here: see the note beside _SKELETON_QUOTA. Every
            # stream-event rule shares one skeleton and names a different
            # anomaly, which is the opposite of the flood the cap exists for.
            text = _render(rule, f"Suricata engine ruleset, {file.name}",
                           "GPL-2.0", classification)
            if len(text) < _MIN_CHARS:
                counters["too short"] += 1
                continue
            seen.add(key)
            by_licence["GPL-2.0"] += 1
            emitted += 1
            yield Document(
                text=text,
                source="netrules",
                register=Register.DETECTION,
                side=Side.BLUE,
                ident=f"{_SURICATA_DIR}/{file.name}:{sid}",
            )

    _report(emitted, counters, by_licence, skeletons)


def _report(emitted: int, counters: Counter, by_licence: Counter,
            skeletons: Counter) -> None:
    """Print what was kept, what was capped, and what was refused.

    A cap that is not printed is a silent edit to the corpus, and a *licence*
    refusal that is not printed is worse: it is the one number a reader would
    most want to check, since it is the difference between "we verified the
    terms" and "we assumed them".
    """
    print(f"   netrules: {emitted:,} docs from {counters['rule lines']:,} rule "
          f"lines — " + ", ".join(f"{name} {count:,}"
                                  for name, count in sorted(by_licence.items())))

    over = sum(1 for count in skeletons.values() if count > _SKELETON_QUOTA)
    if counters["held back by the shape cap"]:
        print(f"   netrules: held back {counters['held back by the shape cap']:,} "
              f"rules past {_SKELETON_QUOTA} per shape ({over:,} of "
              f"{len(skeletons):,} distinct shapes hit the cap). No shape lost "
              "entirely, and rules naming a CVE are exempt.")
    if counters["refused: licence not established"]:
        print("   netrules: refused "
              f"{counters['refused: licence not established']:,} rules whose sid "
              "falls outside every range Emerging Threats' LICENSE covers "
              "(ETPRO, or unnumbered).")
    if counters["quote-desync, reparsed"]:
        print(f"   netrules: {counters['quote-desync, reparsed']} rules contain a "
              "raw quote inside a pcre and were re-parsed with the quote-blind "
              "splitter.")
    for key in ("unparseable", "no sid", "duplicate sid", "too short"):
        if counters[key]:
            print(f"   netrules: {counters[key]:,} {key}")


SPEC = SourceSpec(
    name="netrules",
    license=(
        "Composite, verified per upstream and enforced by sid range rather than "
        "asserted. (1) Emerging Threats open ruleset: BSD-3-Clause, "
        "Copyright (c) 2003-2026 Emerging Threats, for sids 2000000-2799999 — "
        "which is every rule in the current open distribution — per the "
        "upstream LICENSE fetched from rules.emergingthreats.net and cached "
        "beside the rules. Within that block the 1,690 rules at sids "
        "2100000-2103461 are the renumbered Sourcefire/Snort community ruleset "
        "and are GPL-2.0; ET's LICENSE also covers sids 1-3464 and "
        "100000000-100000908 as GPL-2.0. The ETPRO block, sids "
        "2800000-2900000, is proprietary and is refused by the adapter, as is "
        "any sid outside the ranges that LICENSE names. (2) Suricata's own "
        "rules/ and etc/classification.config from OISF/suricata at tag "
        "suricata-8.0.7: GPL-2.0, COPYING cached beside them. Deliberately "
        "excluded: ptresearch/AttackDetection, whose LICENSE is a proprietary "
        "non-commercial EULA (GitHub reports NOASSERTION); and the Snort 3 "
        "community ruleset, whose archive ships GPLv2 and the Cisco Snort "
        "Subscriber Rules License Agreement side by side without saying which "
        "governs the rules."
    ),
    url="https://rules.emergingthreats.net/open/ and https://github.com/OISF/suricata",
    register=Register.DETECTION,
    side=Side.BLUE,
    fetch=_fetch,
    documents=_documents,
    #: 37,111 documents / 57.2M characters on the current upstream: 36,628 ET
    #: rules surviving the shape cap out of 70,564 (35,290 BSD-3-Clause and
    #: 1,338 from the GPL block), plus all 483 Suricata engine-event rules. The
    #: floor sits well below that so ordinary ruleset churn is quiet, while the
    #: realistic regressions — a truncated download, a broken option scanner, a
    #: renamed rules directory — trip it immediately.
    expect_min_docs=25_000,
    notes=(
        "The only source in the corpus that reasons about traffic on the wire "
        "rather than about a host's own telemetry, which is what the red "
        "catalogue's lateral-movement and exfiltration verbs need on the blue "
        "side. Each document is a title line carrying sid and msg, one prose "
        "paragraph (protocol and flow direction in plain words, classtype "
        "expanded through Suricata's classification.config, ET severity and "
        "confidence, the ATT&CK technique and tactic ids beside their names, "
        "CVE and other references rewritten into wild form, and a summary of "
        "the matching mechanisms), and then the rule VERBATIM — option list, "
        "escaped bytes, pcre and all, checked per document to have survived "
        "normalise() byte-for-byte. Options are read with an escape- and "
        "quote-aware scanner, never split on ';', with a quote-blind fallback "
        "for the eight rules ET publishes with a raw quote inside a pcre. "
        "Commented-out rules are included and rendered with their '#' intact: "
        "ET disables ~19,490 of 70,564 for noise and performance, not because "
        "the detection is wrong, and the '#' is how 'off' is spelled in a real "
        "rules file. One cap, printed at build time: a rule shape "
        "(category/action/protocol/direction/classtype/keyword sequence) "
        "contributes at most 12 documents, which stops 6,000 near-identical "
        "dynamic-DNS domain rules from becoming a third of the source; rules "
        "naming a CVE are exempt from it. ET's unversioned open/suricata/ path "
        "is NOT used — it serves the legacy Suricata-6 sticky-buffer syntax."
    ),
)
