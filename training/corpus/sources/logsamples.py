"""Real telemetry — the log lines themselves. DETECTION/BLUE.

Every ``detect.*`` verb in this project returns parsed telemetry, and the model's
job is to say what a control did or did not record. The corpus prepared it for
exactly half of that. It has read thousands of detection rules —
:mod:`~training.corpus.sources.sigma` is three thousand Sigma files,
:mod:`~training.corpus.sources.splunk` two thousand SPL analytics,
:mod:`~training.corpus.sources.elastic` two thousand EQL/KQL rules,
:mod:`~training.corpus.sources.netrules` twenty-five thousand Suricata
signatures — and between them they contain almost no *log*. A rule names
``EventID: 4688`` and ``ParentImage|endswith``; it never shows what a 4688 record
looks like when it arrives. A model trained on that has read the whole language
of detection and has never seen the thing being detected. Asked to read a real
event it has to guess, and guessing about telemetry is the specific failure that
makes an agent confidently wrong about a host.

So this source is the other half: the records themselves, verbatim, in the wire
form a collector writes them::

    <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>
    <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-...}'/>
    <EventID>4634</EventID>...<Channel>Security</Channel><Computer>EC2AMAZ-...

    type=PROCTITLE msg=audit(1723042099.699:13369): proctitle=7375646F00636174...

    {"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"Metadata",
     "requestURI":"/api/v1/namespaces/default/secrets/my-secret","verb":"get",...

    site="localhost" server="34.211.116.74" dest_port="80" src="209.17.96.90"
     status="502" http_user_agent="Mozilla/5.0 (compatible; Nimbostratus-Bot..."

None of those four is prose about logging. They are four different syntaxes —
angle-bracketed XML with ``Data Name=`` pairs, ``key=value`` with a hex-encoded
proctitle, JSON with dotted and nested keys, and quoted key-value pairs — and
surface form is what a BPE learns. The register targets were written around
exactly this argument.

**Register.** DETECTION, and the choice is worth stating because SYSTEM is the
other candidate. What decides it is vocabulary: ``EventID``, ``TargetUserName``,
``ParentCommandLine``, ``GrantedAccess``, ``eventSource``, ``objectRef``,
``id.orig_h`` are the tokens the DETECTION register is already full of, written
here on the other side of the join. DETECTION is 20.9% against a 13% target and
SYSTEM is 38.5% against 24%, so this source adds to a register that is already
over its cap and the balancer will subsample it. That is the correct outcome and
not a reason to mislabel it: raw telemetry is a surface form the corpus lacks
*within* a register it has plenty of, and the balancer works on registers, not on
surface forms. Filing telemetry as RED to flatter the offence share would
corrupt the one measurement the balance report depends on, so it is BLUE — it is
what a control recorded.

**Upstream: splunk/attack_data, Apache-2.0.** Splunk's Threat Research team runs
techniques in a range called attack_range and commits everything the sensors
wrote, indexed by ATT&CK technique. It is the corpus that Splunk's own
detections are regression-tested against, which is why the telemetry is real
rather than illustrative: a fabricated log would break their tests. The repo
carries Windows Security, Sysmon, PowerShell, System and Application channels as
Event XML; Linux auditd, ``auth.log`` and Linux Sysmon; Zeek ``conn`` records;
nginx and web access logs; AWS CloudTrail; Kubernetes audit events; Azure,
Okta, Google Workspace and osquery. That list is close to a complete answer to
what this source was asked for, from one upstream under one licence, in text —
which matters, because the obvious alternative was binary (see *Rejected* below).

**Nothing here is written by this adapter.** Records are emitted byte for byte as
upstream stored them. No reflowing, no pretty-printing, no rendering of an XML
event into a field-per-line "friendly view" — that view is a real thing Event
Viewer produces, but the version this module would produce is *not* the one any
tool emits, and a model that learned a near-miss format would read real output
through it. The only editorial acts are selection and a provenance header, both
stated in the document itself.

**Trap 1: git-lfs pointers arrive with HTTP 200.** ``datasets/**/*.{log,json,
ndjson}`` are lfs-tracked, so ``raw.githubusercontent.com`` serves a 130-byte
text file — ``version https://git-lfs.github.com/spec/v1`` and a sha256 — with a
success status. A fetch that only checks for errors gets a "successful"
download of a pointer, and the corpus quietly fills with ``oid sha256:``. The
content is at ``media.githubusercontent.com/media/...``, and which of the two a
given path needs is not uniform: files committed before the ``.gitattributes``
filter are stored inline and 404 on the media host. So the choice is made from
the blob size in the index, and then *checked against the bytes that arrive* —
:func:`_looks_like_pointer` is the authority, the size is only the hint.

**Trap 2: one file here is 378 MB.** ``T1505.003/windows-sysmon_umservices.log``
is 378,086,952 bytes; several others run past 100 MB. Downloading a dataset to
sample the top of it is not an option, so every file is fetched as an HTTP range
— the first :data:`_SLICE_BYTES` and nothing more. The ceiling passed to
:func:`~training.corpus.net.fetch` is set just above that range on purpose: if
the host ever stops honouring ``Range``, ``Content-Length`` exceeds the ceiling
and the request is refused *before* a byte is read, instead of silently pulling
a third of a gigabyte per file. A partial fetch also cuts the last line in half
and can cut a UTF-8 sequence in half, so the trailing line is dropped and the
decode is lenient.

**Trap 3: telemetry is mostly the same record again.** This is the one that
decides whether the source is worth having. The first 256 KiB of a Sysmon log is
typically two hundred records of which perhaps twenty are distinct events; the
rest is one service beaconing on a timer, differing only in timestamp, PID and
GUID. Emitted whole it would be a memorisation hazard dressed as volume — the
same argument :mod:`~training.corpus.sources.capec` makes about
``Content_History``. So records are deduplicated on a *skeleton*: digits, hex
runs and GUIDs replaced, letters kept. Two logons by the same account in the
same second collapse; two different ``CommandLine`` values do not. On top of
that, :data:`_SHAPE_PASSES` takes five records of every event family before it
takes a sixth of any, which is what stops a file's most common event from
crowding out its rarest. Measured over the fetched cache that keeps about one
record in six, and the ones it keeps are the ones that differ. The skeleton
has a bound worth knowing about — see :data:`_HEXRUN`, where erasing hex runs
wholesale collapsed fourteen distinct auditd records into one, because an
auditd ``proctitle`` *is* the command line in hex.

**Trap 4: a record is not a line.** A Windows 4672 event carries its
``PrivilegeList`` as a tab-indented block with a newline between each privilege,
so a file of 203 events holds 508 lines; 4104 script blocks and any
``CommandLine`` with a newline in it do the same. Splitting on newlines — which
is the obvious thing to do with a log, and what this module did first — emitted
305 "records" reading ``\\t\\t\\tSeDebugPrivilege`` and nothing else. That is
worse than dropping the file: a corpus collected to show what a real event looks
like would have been teaching that a Windows event is sometimes one word.

The same trap was waiting in a second format and it was much larger. A quarter
of the Windows files here are not XML at all but Splunk's ``WinEventLog``
rendering — a timestamp line, a block of ``Key=Value`` lines (``EventCode``, not
``EventID``: the same number under a different key, and a working detection
engineer has to know both), and then the event's own ``Message`` as Windows
writes it for a human, indented and running to twenty lines. Read line by line
those files are a bag of field names. Fixing it turned 49 documents of shredded
fields into 123 documents of whole events and added 1.7 MB of the most readable
telemetry in the source — the rendered 4663 that names ``lazagne.exe`` reading
``lsass.exe`` is one record, and it only exists as one record.

So :func:`_split` decides the format once per file: accumulate ``<Event`` to
``</Event>``, or accumulate JSON until it parses, or cut at the next line that
starts with a timestamp (:data:`_RECORD_STARTS`), or — only for the formats
where it is actually true — take one record per line.

**Licence.** Apache-2.0. Read from the repository's own ``LICENSE`` file, which
is the unmodified 201-line Apache text plus the standard appendix naming
``Copyright [2023] [Splunk Inc]``; the README repeats it as "Copyright 2025
Splunk Inc". :func:`_fetch` downloads that file into the cache *before* it
writes a single byte of data and refuses to continue if what arrives is not the
Apache licence, so the claim in :data:`SPEC` is re-checked every time the cache
is built rather than asserted once here.

**Rejected upstreams**, so the work is not repeated:

*sbousseaden/EVTX-ATTACK-SAMPLES* — 278 real ``.evtx`` files, and the obvious
first choice. Two reasons not to. It is binary EVTX, and nothing in this
environment can parse it: neither ``python-evtx`` nor ``evtx`` is installed, and
the brief's rule is convert faithfully or skip. Hand-rolling a binary-XML
decoder to produce training data is precisely the way to get *plausible* records
that are subtly not what Windows wrote. Its licence is also ``LICENSE.GPL`` —
GPL-3.0, not the MIT that a reader would assume from how widely it is
redistributed — which would have been usable but worth declaring.

*logpai/loghub* — its ``LICENSE`` reads "The datasets are freely available for
research or academic work", with a citation requirement. That is not a
redistribution licence, and a corpus that a model is trained and published from
is not obviously academic use. Declined on the licence, not on the data, which
is excellent.

*OTRF/Security-Datasets* (MIT, genuinely usable) — Windows telemetry as
Winlogbeat JSON with the rendered ``Message`` block, which is a surface form
this source does not carry. Not taken because attack_data already delivers the
same event channels in their native XML across a wider spread of platforms, and
a second Windows telemetry corpus would spend the corpus's scarcest resource —
unique text — on duplicate material. It is the first place to look if this
source is ever widened.

*splunk/security_content* — already in the corpus as
:mod:`~training.corpus.sources.splunk`, whose ``data_sources/`` tree carries one
``example_log`` per sourcetype. That is a schema dictionary with a specimen
attached; this is the log. Different repository, no overlap, and the pairing is
deliberate.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from ..net import NetworkError, fetch
from ..source import Document, Register, Side, SourceError, SourceSpec, normalise

_REPO = "splunk/attack_data"
_REF = "master"

#: One request for the whole file list. ``contents`` would be a request per
#: directory over a tree 3,700 entries deep; ``git/trees?recursive=1`` is the
#: same information in a single response, and :mod:`training.corpus.sources.netrules`
#: already establishes that api.github.com is a door this corpus uses.
_TREE_URL = f"https://api.github.com/repos/{_REPO}/git/trees/{_REF}?recursive=1"

#: Inline blobs. Also the only host that serves the non-data files (``LICENSE``),
#: which the media host 404s.
_RAW_URL = f"https://raw.githubusercontent.com/{_REPO}/{_REF}/{{path}}"

#: git-lfs content. Answers 206 Partial Content directly — no redirect, so the
#: ``Range`` header survives. That matters: :mod:`training.corpus.net` strips
#: caller headers across an origin hop, and a redirect here would silently turn
#: a 256 KiB range request into a request for the whole file.
_LFS_URL = f"https://media.githubusercontent.com/media/{_REPO}/{_REF}/{{path}}"

_LICENSE_PATH = "LICENSE"

#: How much of each file to take. Large enough that a chatty log still yields a
#: dozen distinct event families after deduplication, small enough to be cheap:
#: the 238 files this selects come to 19 MB on disk, once, ever, because most
#: datasets upstream are smaller than the slice and only the big ones are cut.
_SLICE_BYTES = 256 * 1024

#: Headroom over the requested range, and the guard described in *Trap 2*: a
#: host that ignores ``Range`` declares a Content-Length past this and is
#: refused before the body is read.
_SLICE_CEILING = _SLICE_BYTES + 64 * 1024

#: A pointer blob is ~130 bytes. The threshold is generous because the size is
#: only a hint for which host to try first; the bytes decide.
_POINTER_HINT_BYTES = 400
_POINTER_MAGIC = b"version https://git-lfs.github.com/spec/v1"

#: Politeness. ~250 sequential range requests at this pace is about two minutes
#: and no burst, which is the deal :mod:`training.corpus.sources.rfc` struck for
#: a far larger fetch.
_REQUEST_PAUSE = 0.15
_TIMEOUT = 90

#: Files are written under the cache mirroring their upstream path, so the walk
#: in :func:`_documents` recovers provenance without a side manifest.
_SLICES = "slices"
#: Written last: an interrupted fetch must re-fetch, not be mistaken for done.
_MARKER = ".fetched.json"
_INDEX = "tree.json"

#: Per event family, inside one file, applied as successive passes: take up to
#: five of every family, then up to fifteen, then up to forty, stopping when the
#: character budget runs out. Breadth first and depth only if there is room,
#: which is the difference between a document that shows a file's rarest event
#: and one that shows its most common event forty times. A single flat cap could
#: not do both: five was right for a Sysmon log with thirty event types and
#: threw away four fifths of an nginx log, where every line is a different
#: request and there is only one "family" to be had.
_SHAPE_PASSES = (5, 15, 40)

#: A runaway guard for the two accumulating splitters, and nothing more: an XML
#: file with no ``</Event>`` or a JSON file that never parses would otherwise
#: grow one "record" until the slice ran out. It has to sit well clear of real
#: records, which get very long — the largest in the fetched cache is a single
#: PowerShell 4104 event whose ``ScriptBlockText`` is a 544-line script. That
#: record is not noise, it is some of the best text in the source, so the bound
#: is generous and only catches a splitter that has genuinely lost its place.
_MAX_RECORD_LINES = 2_000
#: Per file, across all families, before chunking into documents.
_MAX_FILE_CHARS = 60_000
#: One document. Twenty-odd Windows XML records, or a few hundred auditd lines.
_MAX_DOC_CHARS = 20_000
#: Under this a document is a header with two lines under it, which teaches the
#: header and nothing else.
_MIN_DOC_CHARS = 300

#: Refuse a build where the transport has broken rather than one where a handful
#: of datasets moved. Expressed as a fraction of what was selected.
_MAX_FAILED_FRACTION = 0.25

#: Below this the index is not the attack_data tree — an error page, a rate-limit
#: body, or a repository that has been restructured beyond recognition.
_MIN_TREE_ENTRIES = 1_500


# ---------------------------------------------------------------------------
# selection
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class _Family:
    """One telemetry family, and how many files of it to take.

    The caps are the whole design of this source. Upstream is wildly uneven:
    measured over the index, 434 files match Windows Sysmon and 268 Windows
    Security, against 8 Zeek logs, 9 Kubernetes audit captures and 2 plain
    syslog files. Taking files in repository order would produce a corpus that
    is Sysmon with a rounding error of everything else. The model has to read
    all of these formats, not the most common one fluently, so breadth is bought
    explicitly here — a cap the small families never reach and the large ones
    always do — and the build prints what each family contributed.
    """

    name: str
    #: Matched against the lowercased basename. First match in table order wins,
    #: so narrower families are listed before the ones that would swallow them.
    pattern: str
    cap: int


#: Order is load-bearing: ``sysmon_linux.log`` must be claimed by the Linux
#: family before the Windows Sysmon pattern reaches it, and ``windows-security``
#: before the bare ``security.log`` fallback.
_FAMILIES: tuple[_Family, ...] = (
    _Family("linux-auditd", r"auditd|^audit\.log$", 26),
    _Family("linux-sysmon", r"(sysmon[-_]linux|linux[-_]sysmon)", 12),
    _Family("linux-syslog", r"^(auth|authlog|syslog|messages|secure)\.log$", 12),
    _Family("windows-security", r"(windows[-_]security|security[-_]xml|"
                                r"xml[-_]windows[-_]security|^security\.log$)", 30),
    _Family("windows-powershell", r"powershell|powersploit|mimikatz|dsinternals", 18),
    _Family("windows-sysmon", r"sysmon", 30),
    _Family("windows-channels", r"windows[-_](system|application|admon|"
                                r"directory_service|xml)", 14),
    _Family("snapattack", r"snapattack", 8),
    _Family("zeek", r"zeek|^bro[-_]|_bro\.|conn\.log$", 10),
    _Family("web-access", r"nginx|apache|httpd|web[-_]access|access\.log$|"
                          r"ui_access|_access\.", 20),
    _Family("kubernetes", r"kube", 10),
    _Family("aws", r"cloudtrail|^aws[-_]|_aws[-_]|bedrock|ecr|iam|security_lake", 22),
    _Family("cloud-identity", r"azure|o365|office|gws[-_]|gsuite|okta|gcp|"
                              r"google|github|duo", 18),
    _Family("endpoint-agents", r"osquery|crowdstrike|carbon_black|falcon|"
                               r"defender|sentinel", 10),
    _Family("network-appliances", r"cisco|suricata|palo|fortinet|firewall|"
                                  r"proxy|vpn|dns\.log$", 12),
)

_COMPILED = tuple((f, re.compile(f.pattern)) for f in _FAMILIES)

#: Only these extensions are telemetry. ``.yml`` is upstream's dataset metadata,
#: ``.py`` is its tooling, ``.pcap``/``.zip``/``.png`` are not text.
_DATA_SUFFIXES = (".log", ".json", ".ndjson")

#: Datasets live here. ``bin/``, ``.github/`` and ``environments/`` do not.
_DATA_ROOT = "datasets/"

#: ``datasets/attack_techniques/T1059.001/...`` — the one piece of context the
#: path carries that the bytes do not, and the join this corpus is built on.
_TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def _family_of(path: str) -> _Family | None:
    """Which family a repository path belongs to, or ``None`` to skip it."""
    name = path.rsplit("/", 1)[-1].lower()
    for family, pattern in _COMPILED:
        if pattern.search(name):
            return family
    return None


def _select(entries: list[dict]) -> list[tuple[str, int, str]]:
    """Choose the files to fetch: ``(path, blob size, family name)``.

    Within a family the files are sorted and then taken at a fixed stride rather
    than from the front. Sorted order is ``T1003``, ``T1003.001``, ``T1003.002``
    …, so the first thirty Sysmon logs are thirty captures of credential access;
    a stride spreads the same thirty across the whole technique range for free,
    and stays deterministic, which a random sample would not be. Re-running the
    build must select the same files or the cache is worthless.
    """
    by_family: dict[str, list[tuple[str, int]]] = {f.name: [] for f in _FAMILIES}
    for entry in entries:
        if entry.get("type") != "blob":
            continue
        path = str(entry.get("path", ""))
        if not path.startswith(_DATA_ROOT) or not path.endswith(_DATA_SUFFIXES):
            continue
        family = _family_of(path)
        if family is None:
            continue
        try:
            size = int(entry.get("size", 0))
        except (TypeError, ValueError):
            size = 0
        by_family[family.name].append((path, size))

    chosen: list[tuple[str, int, str]] = []
    for family in _FAMILIES:
        found = sorted(by_family[family.name])
        if not found:
            continue
        stride = max(1, len(found) // family.cap)
        for path, size in found[::stride][: family.cap]:
            chosen.append((path, size, family.name))
    return sorted(chosen)


# ---------------------------------------------------------------------------
# fetch
# ---------------------------------------------------------------------------

def _looks_like_pointer(body: bytes) -> bool:
    """True if this is a git-lfs pointer rather than the file it stands for."""
    return body[: len(_POINTER_MAGIC)] == _POINTER_MAGIC


def _slice_urls(path: str, size: int) -> tuple[str, str]:
    """``(first choice, fallback)`` hosts for one path.

    Pointer-sized blobs live on the media host and everything else is inline,
    but the size is a hint and not a rule — a genuinely tiny log file exists,
    and so does an inline blob that was never migrated — so both hosts are
    always available and the bytes decide which one was right.
    """
    raw, lfs = _RAW_URL.format(path=path), _LFS_URL.format(path=path)
    return (lfs, raw) if size and size <= _POINTER_HINT_BYTES else (raw, lfs)


def _fetch_slice(path: str, size: int) -> bytes:
    """The first :data:`_SLICE_BYTES` of one upstream file.

    Returns empty bytes when the file cannot be had from either host, which the
    caller counts: one dataset that moved is not a reason to fail a build, and
    a transport that has stopped working is — the difference is the failure
    fraction, checked once at the end.
    """
    headers = {"Range": f"bytes=0-{_SLICE_BYTES - 1}"}
    first, second = _slice_urls(path, size)
    for url in (first, second):
        try:
            body = fetch(url, timeout=_TIMEOUT, headers=headers,
                         max_bytes=_SLICE_CEILING)
        except NetworkError:
            continue
        if body and not _looks_like_pointer(body):
            return body
    return b""


def _write_slice(root: Path, path: str, body: bytes) -> None:
    """Store one slice under the cache, mirroring its upstream path.

    The path came from a remote API, which makes it data and not a filename.
    ``..`` segments, absolute paths and drive letters are all expressible in a
    JSON string, and the cost of trusting one is a write outside the cache — the
    same lesson :mod:`training.corpus.sources.sigma` learned about tar members,
    arriving through a different door. Every destination is proved to resolve
    inside the slice root before anything is opened.
    """
    relative = Path(path)
    if relative.is_absolute() or ".." in relative.parts:
        raise SourceError(f"logsamples: refusing suspicious upstream path {path!r}")
    target = root / relative
    if not target.resolve().is_relative_to(root.resolve()):
        raise SourceError(f"logsamples: {path!r} resolves outside the cache")
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".part")
    try:
        tmp.write_bytes(body)
        os.replace(tmp, target)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _fetch_index(cache_dir: Path) -> list[dict]:
    """The repository's file list, cached.

    ``truncated`` is checked rather than assumed: GitHub caps this response, and
    a truncated tree would silently narrow the selection to whatever came back
    first — which, sorted, is one corner of the technique range. An entry floor
    catches the other direction, where the response is an error page or a
    rate-limit body that parses as JSON perfectly well.
    """
    index = cache_dir / _INDEX
    if index.is_file():
        try:
            cached = json.loads(index.read_text(encoding="utf-8"))
            if isinstance(cached.get("tree"), list):
                return list(cached["tree"])
        except (OSError, ValueError):
            index.unlink(missing_ok=True)

    headers = {"Accept": "application/vnd.github+json"}
    # Optional and never required. The unauthenticated limit is 60 requests an
    # hour and this costs one, but a machine that has already spent them gets a
    # 403 with no way to tell that from a real failure, so an operator who has a
    # token can hand it over. net.py drops caller headers across an origin hop,
    # which is what keeps it from following a redirect onto someone else's host.
    token = (os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        body = fetch(_TREE_URL, timeout=_TIMEOUT, headers=headers)
    except NetworkError as exc:
        raise SourceError(
            f"logsamples: could not read the file index at {_TREE_URL}: {exc}. "
            "If this is 'HTTP 403 rate limit exceeded', the unauthenticated "
            "GitHub API allows 60 requests an hour — wait, or set GITHUB_TOKEN."
        ) from exc

    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise SourceError(f"logsamples: {_TREE_URL} did not return JSON: {exc}") from exc

    if payload.get("truncated"):
        raise SourceError(
            "logsamples: GitHub truncated the tree listing for "
            f"{_REPO}. Selecting from a partial index would silently take one "
            "corner of the repository; fix the adapter to page instead."
        )
    tree = payload.get("tree")
    if not isinstance(tree, list) or len(tree) < _MIN_TREE_ENTRIES:
        raise SourceError(
            f"logsamples: {_TREE_URL} listed "
            f"{len(tree) if isinstance(tree, list) else 0} entries, expected at "
            f"least {_MIN_TREE_ENTRIES}. That is not the attack_data tree."
        )
    index.write_text(json.dumps({"sha": payload.get("sha", ""), "tree": tree}),
                     encoding="utf-8")
    return tree


def _fetch_license(cache_dir: Path) -> None:
    """Put the upstream licence in the cache before any of its data.

    Ordering is the point. This project's rule is that a source states a licence
    it has read, and the cheapest way to keep that true a year from now is to
    re-read it on every cold fetch and refuse the data if the file that arrives
    is not the licence this module claims. Checked for both the Apache title and
    the version, because "Apache" alone also matches a README paragraph.
    """
    url = _RAW_URL.format(path=_LICENSE_PATH)
    try:
        body = fetch(url, timeout=_TIMEOUT)
    except NetworkError as exc:
        raise SourceError(
            f"logsamples: could not read the upstream licence at {url}: {exc}. "
            "No licence, no data — that ordering is deliberate."
        ) from exc
    text = body.decode("utf-8", errors="replace")
    if "Apache License" not in text or "Version 2.0" not in text:
        raise SourceError(
            f"logsamples: {url} is no longer the Apache License 2.0 this source "
            "declares. Re-read the upstream terms before collecting anything "
            "from it."
        )
    (cache_dir / _LICENSE_PATH).write_text(text, encoding="utf-8")


def _fetch(cache_dir: Path) -> Path:
    """Populate the cache with sliced telemetry; return the slice root.

    Idempotent in two layers. A finished cache short-circuits on the marker, and
    an unfinished one resumes per file — the slices already on disk are kept, so
    an interrupted fetch costs only what it had not yet downloaded. The marker
    is written last, which is what makes "finished" mean finished.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    slices = cache_dir / _SLICES
    marker = cache_dir / _MARKER
    if marker.is_file() and slices.is_dir():
        return slices

    _fetch_license(cache_dir)
    selected = _select(_fetch_index(cache_dir))
    if not selected:
        raise SourceError(
            "logsamples: the index matched no telemetry files at all. The "
            f"{_DATA_ROOT} layout or the naming convention has changed upstream."
        )

    slices.mkdir(parents=True, exist_ok=True)
    fetched = 0
    cached = 0
    failed: list[str] = []
    per_family: dict[str, int] = {}
    total_bytes = 0

    for path, size, family in selected:
        target = slices / path
        if target.is_file() and target.stat().st_size > 0:
            cached += 1
            per_family[family] = per_family.get(family, 0) + 1
            total_bytes += target.stat().st_size
            continue
        body = _fetch_slice(path, size)
        time.sleep(_REQUEST_PAUSE)
        if not body:
            failed.append(path)
            continue
        _write_slice(slices, path, body)
        fetched += 1
        total_bytes += len(body)
        per_family[family] = per_family.get(family, 0) + 1

    if len(failed) > max(4, int(len(selected) * _MAX_FAILED_FRACTION)):
        raise SourceError(
            f"logsamples: {len(failed)} of {len(selected)} files could not be "
            "fetched from either raw.githubusercontent.com or "
            "media.githubusercontent.com. That is a transport change, not a few "
            f"moved datasets. First failures: {failed[:5]}"
        )

    marker.write_text(
        json.dumps(
            {
                "repo": _REPO,
                "ref": _REF,
                "selected": len(selected),
                "fetched": fetched,
                "already_cached": cached,
                "failed": len(failed),
                "slice_bytes": _SLICE_BYTES,
                "bytes_on_disk": total_bytes,
                "per_family": per_family,
                "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "license": _LICENSE,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    if failed:
        print(f"   logsamples: {len(failed)} of {len(selected)} files were not "
              "available from either host and were skipped")
    return slices


# ---------------------------------------------------------------------------
# reading records
# ---------------------------------------------------------------------------

_GUID = re.compile(r"\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
                   r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?")

#: ``0x``-prefixed literals always — handles, access masks, logon ids, keyword
#: bitmaps. A *bare* hex run only when it is at most twenty characters and mixes
#: digits with letters, and the bound is not cosmetic: past twenty characters a
#: hex run stops being an identifier and becomes content. An auditd
#: ``proctitle=`` **is the command line, hex-encoded** — ``cat /etc/shadow`` and
#: ``sudo cat /etc/shadow`` differ in nothing else — and a Sysmon ``Hashes``
#: field is the identity of the file. The first version of this erased both, and
#: fourteen distinct auditd records deduplicated down to one. The digit-and-
#: letter requirement is what keeps English words made only of a-f
#: (``face``, ``deleted``, ``added``) out of it.
_HEXRUN = re.compile(r"0x[0-9a-fA-F]+|\b(?=[0-9a-fA-F]{4,20}\b)"
                     r"(?=[0-9a-fA-F]*[0-9])(?=[0-9a-fA-F]*[a-fA-F])[0-9a-fA-F]+\b")
_DIGITS = re.compile(r"\d+")


def _skeleton(line: str) -> str:
    """A record with its variable parts removed, for near-duplicate detection.

    GUIDs first, then hex runs, then digits — in that order, because a GUID is
    made of the other two and stripping digits first would leave it in pieces.
    What survives is the letters: field names, image paths, account names,
    command lines. Two Sysmon records for the same service beacon collapse to
    one skeleton; two process creations with different command lines do not.
    """
    text = _GUID.sub("#", line)
    text = _HEXRUN.sub("#", text)
    return _DIGITS.sub("#", text)


_EVENT_ID = re.compile(r"<EventID[^>]*>(\d+)</EventID>")
_PROVIDER = re.compile(r"<Provider\s+Name=['\"]([^'\"]+)['\"]")
_CHANNEL = re.compile(r"<Channel>([^<]*)</Channel>")
_COMPUTER = re.compile(r"<Computer>([^<]*)</Computer>")
#: Splunk's ``WinEventLog`` rendering names the event ``EventCode``, not
#: ``EventID`` — the same number under a different key, and a detection engineer
#: has to know both. Anchored to a line start so it cannot match the word inside
#: a rendered Message body.
_WINEVENTLOG = re.compile(r"^EventCode=(\d+)\s*$", re.MULTILINE)
_LOGNAME = re.compile(r"^LogName=(.+?)\s*$", re.MULTILINE)
_COMPUTERNAME = re.compile(r"^ComputerName=(.+?)\s*$", re.MULTILINE)
_AUDITD_TYPE = re.compile(r"^type=([A-Z0-9_]+)\s")
_SYSLOG = re.compile(r"^[A-Z][a-z]{2}\s+\d+\s[\d:]+\s+(\S+)\s+([A-Za-z0-9_./-]+)")
_KV_KEYS = re.compile(r'([A-Za-z0-9_.]+)="')

#: JSON keys that name what a record *is*, in the order they are worth trying.
#: A CloudTrail event is identified by ``eventName``, a Kubernetes audit event
#: by its verb, an osquery row by its query name. Falling through to the sorted
#: key signature is the last resort and is deliberately unreadable — it groups
#: correctly, which is all the cap needs.
_JSON_DISCRIMINATORS = ("eventName", "operationName", "verb", "name", "kind",
                        "category", "event_type", "action", "_raw", "proto")


@dataclass(frozen=True, slots=True)
class _Record:
    """One log record, its family for capping, and the facts it states about itself.

    ``family`` groups records for the per-shape cap and is never shown.
    ``tally`` is the part of it fit to print in the header summary, and is empty
    for the families whose key is a bag of field names — a document must not
    explain this module's bookkeeping to a reader.
    """

    text: str
    family: str
    label: str
    tally: str = ""
    channel: str = ""
    provider: str = ""
    host: str = ""


_XML_START = "<Event"
_XML_END = "</Event>"

#: A line that begins a record, in the formats where a record is a *block*.
#: Tried against a file's first line only; whichever matches becomes that file's
#: record boundary. The first entry is the one that matters: Splunk's
#: ``WinEventLog`` sourcetype renders a Windows event as a timestamp line, a
#: block of ``Key=Value`` lines and then the event's own ``Message`` — indented,
#: multi-paragraph, blank lines and all. Forty-nine of this source's documents
#: are that format, and read line by line they are not records at all, they are
#: a bag of field names.
_RECORD_STARTS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^\d{2}/\d{2}/\d{4} \d{1,2}:\d{2}:\d{2} [AP]M\b"),
    re.compile(r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}"),
    re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}\s"),
)


def _start_pattern(head: str) -> re.Pattern[str] | None:
    """The record boundary for a file whose first line looks like ``head``."""
    for pattern in _RECORD_STARTS:
        if pattern.match(head):
            return pattern
    return None


def _split(text: str, truncated: bool) -> list[str]:
    """Cut a slice into records, which are **not** the same thing as lines.

    This is the mistake that made the first version of this source emit
    nonsense. A Windows 4672 event carries its ``PrivilegeList`` as a
    tab-indented block with a newline between every privilege, so a file of 203
    events contains 508 lines and splitting on newlines produced 305 "records"
    that read, in full, ``\\t\\t\\tSeDebugPrivilege``. Orphan fragments like that
    are worse than missing data: the corpus exists to teach what a real record
    looks like, and those teach that a Windows event is sometimes one word.
    PowerShell 4104 script blocks and any ``CommandLine`` containing a newline
    have the same shape.

    So the format is decided once per file, from its first line, and the
    splitter for that format is the one that runs. XML accumulates from
    ``<Event`` to ``</Event>``. JSON accumulates until what it holds parses,
    which handles a pretty-printed object as well as one per line. A file whose
    first line begins with a timestamp (:data:`_RECORD_STARTS`) is cut at the
    next line that does — that is Splunk's ``WinEventLog`` rendering, where one
    event is a timestamp, a ``Key=Value`` block and an indented ``Message``
    running to twenty lines, and it is also the harmless case for an IIS log
    where every line starts with one anyway. Only what is left over — auditd,
    NCSA access logs, Falco, appliance syslog — really is one record per line.

    An unterminated accumulation at the end is the byte range's cut and is
    dropped, along with the final line in line mode, for the same reason.
    """
    lines = text.split("\n")
    head = next((line for line in lines if line.strip()), "")
    if head.lstrip().startswith(_XML_START):
        return _split_xml(lines)
    if head.lstrip().startswith("{"):
        return _split_json(lines)
    if start := _start_pattern(head):
        return _split_by_start(lines, start, truncated)
    if truncated and lines:
        lines.pop()
    return [line for line in lines if line.strip()]


def _split_by_start(lines: list[str], start: re.Pattern[str],
                    truncated: bool) -> list[str]:
    """Records delimited by a line that begins one, not by newlines.

    Lines before the first boundary are a file header — an IIS log opens with
    ``#Software:`` and ``#Fields: date time s-ip cs-method ...``, which names
    the columns of everything under it — so they are kept as a record of their
    own rather than glued onto the first event or silently dropped. A trailing
    record is only emitted when the slice was not truncated, because otherwise
    it is whatever fitted in the last few bytes.
    """
    records: list[str] = []
    current: list[str] = []
    header: list[str] = []
    for line in lines:
        if start.match(line):
            if current:
                records.append("\n".join(current))
            current = [line]
        elif current:
            current.append(line)
        elif line.strip():
            header.append(line)
    if current and not truncated:
        records.append("\n".join(current))
    return ["\n".join(header), *records] if header else records


def _split_xml(lines: list[str]) -> list[str]:
    records: list[str] = []
    current: list[str] = []
    for line in lines:
        if not current:
            if not line.lstrip().startswith(_XML_START):
                continue
            current = [line]
        else:
            current.append(line)
        if line.rstrip().endswith(_XML_END):
            records.append("\n".join(current))
            current = []
        elif len(current) > _MAX_RECORD_LINES:
            current = []
    return records


def _split_json(lines: list[str]) -> list[str]:
    records: list[str] = []
    current: list[str] = []
    for line in lines:
        if not line.strip():
            continue
        current.append(line)
        blob = "\n".join(current)
        try:
            json.loads(blob)
        except ValueError:
            if len(current) > _MAX_RECORD_LINES:
                current = []
            continue
        records.append(blob)
        current = []
    return records


def _read_record(record: str) -> _Record:
    """Classify one record without changing a byte of it.

    Everything this returns beside ``text`` is read out of the record itself.
    That is the rule for the document header too: it may state what the bytes
    say and nothing else, so that a header can never assert a channel or a
    format the records do not actually have.
    """
    stripped = record.strip()
    if stripped.startswith(_XML_START):
        event_id = (_EVENT_ID.search(record) or [None, ""])[1]
        provider = (_PROVIDER.search(record) or [None, ""])[1]
        channel = (_CHANNEL.search(record) or [None, ""])[1]
        host = (_COMPUTER.search(record) or [None, ""])[1]
        tally = f"EventID {event_id}" if event_id else ""
        return _Record(record, f"EventID {event_id or '?'}",
                       "Windows Event Log XML, one <Event> element per record",
                       tally, channel, provider, host)

    if stripped.startswith("{"):
        try:
            obj = json.loads(stripped)
        except ValueError:
            obj = None
        if isinstance(obj, dict):
            family = _json_family(obj)
            return _Record(record, family, _json_label(obj),
                           tally="" if family.startswith("keys ") else family,
                           host=str(obj.get("host")
                                    or obj.get("hostIdentifier") or ""))

    if match := _AUDITD_TYPE.match(stripped):
        return _Record(record, f"type={match.group(1)}",
                       "Linux auditd records, one per line",
                       tally=f"type={match.group(1)}")
    if match := _SYSLOG.match(stripped):
        return _Record(record, f"syslog {match.group(2)}",
                       "syslog, one line per message",
                       tally=match.group(2), host=match.group(1))
    if match := _WINEVENTLOG.search(record):
        code = match.group(1)
        channel = (_LOGNAME.search(record) or [None, ""])[1]
        host = (_COMPUTERNAME.search(record) or [None, ""])[1]
        return _Record(
            record, f"EventCode={code}",
            "Windows Event Log as a Splunk universal forwarder renders it "
            "(WinEventLog sourcetype): a timestamp, a Key=Value block, then "
            "the event's own indented Message",
            tally=f"EventCode={code}", channel=channel, host=host)
    if keys := _KV_KEYS.findall(stripped):
        return _Record(record, "kv " + ",".join(sorted(set(keys))[:4]),
                       'key="value" pairs, one record per line')
    # "per line" would be a false claim about a record that has newlines in it,
    # and the header may only say what the bytes say.
    unit = "block" if "\n" in record.strip() else "line"
    return _Record(record, "line", f"plain text, one record per {unit}")


def _json_family(obj: dict) -> str:
    for key in _JSON_DISCRIMINATORS:
        value = obj.get(key)
        if isinstance(value, str) and value:
            return f"{key}={value[:40]}"
    return "keys " + ",".join(sorted(obj)[:6])


def _json_label(obj: dict) -> str:
    """What kind of JSON this is, said only when the record itself says so."""
    api = str(obj.get("apiVersion", ""))
    if api.startswith("audit.k8s.io"):
        return f"Kubernetes audit events ({api}), one JSON object per line"
    if "eventSource" in obj and "eventName" in obj:
        return "AWS CloudTrail events, one JSON object per line"
    if "id.orig_h" in obj or "id.resp_h" in obj:
        # Named for the fields, not for the log: these keys are Zeek's
        # connection identifier and they appear in conn.log, dns.log,
        # dce_rpc.log and every other stream, so the label says stream-
        # agnostic "log records" rather than guessing at conn.
        return "Zeek log records as JSON, one object per line"
    if "event_type" in obj and "flow_id" in obj:
        return "Suricata EVE JSON events, one object per line"
    if "calendarTime" in obj and "columns" in obj:
        return "osquery result rows, one JSON object per line"
    if "operationName" in obj and "tenantId" in obj:
        return "Azure activity/sign-in records, one JSON object per line"
    return "JSON, one object per line"


def _records(text: str, truncated: bool) -> list[_Record]:
    """Every record in a slice, classified.

    The tail of a byte range is half a record by construction, and half a record
    is exactly the kind of malformed telemetry that must never reach a corpus: a
    model that has seen truncated JSON learns that JSON sometimes ends mid-key.
    :func:`_split` is where that is dropped.
    """
    return [_read_record(record) for record in _split(text, truncated)]


def _keep(records: list[_Record]) -> list[_Record]:
    """Deduplicated, capped selection in original file order.

    Three passes with a widening per-family cap (:data:`_SHAPE_PASSES`), each
    stopping at the character budget. The first pass is breadth — up to five of
    everything the file contains — and later passes only deepen what is already
    represented, so a file's rarest event can never be crowded out by its most
    common one, and a file whose records are all one "family" (an access log,
    where every line is a different request) is not cut to five lines by a cap
    designed for something else.

    Order is restored afterwards rather than grouped by family: a log is a
    sequence and the sequence is part of what has to be read. What is *not*
    preserved is contiguity, and the document header says so — it is an excerpt,
    and claiming otherwise in a corpus about telemetry would be its own small
    lie.
    """
    seen: set[str] = set()
    per_family: dict[str, int] = {}
    taken: list[tuple[int, _Record]] = []
    chars = 0
    for cap in _SHAPE_PASSES:
        for index, record in enumerate(records):
            if chars >= _MAX_FILE_CHARS:
                break
            if per_family.get(record.family, 0) >= cap:
                continue
            skeleton = _skeleton(record.text)
            if skeleton in seen:
                continue
            seen.add(skeleton)
            per_family[record.family] = per_family.get(record.family, 0) + 1
            taken.append((index, record))
            chars += len(record.text) + 1
        if chars >= _MAX_FILE_CHARS:
            break
    return [record for _, record in sorted(taken, key=lambda pair: pair[0])]


# ---------------------------------------------------------------------------
# documents
# ---------------------------------------------------------------------------

def _technique(path: str) -> str:
    for part in path.split("/"):
        if _TECHNIQUE.match(part):
            return part
    return ""


def _dataset_name(path: str) -> str:
    """The upstream directory holding the file, which is its own label for it.

    ``linux_auditd_access_credential``, ``kube_audit_get_secret``,
    ``remote_desktop_connection`` — upstream names these directories after what
    was run, and that name is the only statement of intent attached to the
    capture. The technique id next to it is the join to
    :mod:`~training.corpus.sources.attack`.
    """
    parts = path.split("/")
    return parts[-2] if len(parts) >= 2 else ""


def _summary(records: list[_Record]) -> str:
    """``EventID 4624 x3, EventID 4688 x10`` — counted over this document only.

    Counting what is in front of the reader rather than what was in the file is
    deliberate. The alternative is a header that names event ids the records
    below it do not contain, which is the one kind of error this source cannot
    afford to teach.
    """
    counts: dict[str, int] = {}
    for record in records:
        if not record.tally:
            continue
        counts[record.tally] = counts.get(record.tally, 0) + 1
        if len(counts) >= 12:
            break
    return ", ".join(f"{name} x{count}" for name, count in counts.items())


def _header(path: str, kept: list[_Record], read: int,
            part: int, parts: int) -> list[str]:
    """Provenance, and only claims the records support."""
    first = kept[0]
    lines = [
        f"Telemetry sample: {path.rsplit('/', 1)[-1]}",
        f"Source: {_REPO} {path}",
    ]
    if technique := _technique(path):
        lines.append(f"ATT&CK technique: {technique} "
                     f"(https://attack.mitre.org/techniques/{technique.replace('.', '/')})")
    if dataset := _dataset_name(path):
        lines.append(f"Dataset: {dataset}")
    lines.append(f"Format: {first.label}")
    for label, value in (("Channel", first.channel), ("Provider", first.provider)):
        if value:
            lines.append(f"{label}: {value}")
    hosts = sorted({r.host for r in kept if r.host})
    if hosts:
        lines.append(f"Hosts: {', '.join(hosts[:4])}")
    lines.append(
        f"Excerpt: {len(kept)} records shown, from {read} read in the first "
        f"{_SLICE_BYTES // 1024} KiB of the file; near-identical ones dropped"
    )
    if parts > 1:
        lines.append(f"Part {part} of {parts}")
    if summary := _summary(kept):
        lines.append(f"Records in this excerpt: {summary}")
    lines.append("")
    return lines


def _chunks(kept: list[_Record]) -> list[list[_Record]]:
    """Split one file's records into document-sized runs, in order."""
    chunks: list[list[_Record]] = []
    current: list[_Record] = []
    size = 0
    for record in kept:
        if current and size + len(record.text) > _MAX_DOC_CHARS:
            chunks.append(current)
            current, size = [], 0
        current.append(record)
        size += len(record.text) + 1
    if current:
        chunks.append(current)
    return chunks


def _slice_files(root: Path) -> list[Path]:
    """Every cached slice, sorted, following no symbolic link anywhere.

    ``os.walk(followlinks=False)`` for the descent and an explicit
    ``is_symlink`` for the leaf, because ``Path.is_file`` follows a link and
    this cache lives on a removable volume that other things also write to. The
    corpus once pulled 180 MB of itself back in as training data through a link
    like that.
    """
    found: list[Path] = []
    for directory, _, names in os.walk(root, followlinks=False):
        base = Path(directory)
        for name in names:
            if name.endswith(".part") or not name.endswith(_DATA_SUFFIXES):
                continue
            path = base / name
            if path.is_symlink() or not path.is_file():
                continue
            found.append(path)
    return sorted(found)


def _resolve(path: Path) -> Path:
    """Accept either the slice root or the cache directory above it."""
    if (path / _SLICES).is_dir():
        return path / _SLICES
    if path.is_dir():
        return path
    raise SourceError(f"logsamples: {path} is not a directory — run fetch() first")


def _documents(path: Path) -> Iterator[Document]:
    """One or more documents per cached file, in a stable sorted order.

    How many depends on the file: a dataset with four distinct records is one
    document and a Windows Security capture is five, because the split is by
    character budget rather than by count.
    """
    root = _resolve(path)
    files = _slice_files(root)
    if not files:
        raise SourceError(
            f"logsamples: no telemetry slices under {root}. The cache is empty "
            "or was written by a fetch that did not finish."
        )

    emitted = 0
    thin = 0
    per_family: dict[str, int] = {}

    for file in files:
        try:
            body = file.read_bytes()
        except OSError:
            continue
        # A byte range can cut a UTF-8 sequence in half, and the record that
        # sequence belonged to is dropped by _split anyway, so a lenient decode
        # here costs nothing and a strict one would throw away the whole file.
        text = body.decode("utf-8", errors="ignore")
        records = _records(text, truncated=len(body) >= _SLICE_BYTES)
        if not records:
            continue
        kept = _keep(records)
        if not kept:
            continue

        repo_path = file.relative_to(root).as_posix()
        family = _family_of(repo_path)
        chunks = _chunks(kept)
        for number, chunk in enumerate(chunks, start=1):
            lines = _header(repo_path, chunk, len(records),
                            number, len(chunks))
            lines += [record.text for record in chunk]
            document = normalise("\n".join(lines))
            if len(document) < _MIN_DOC_CHARS:
                thin += 1
                continue
            emitted += 1
            if family is not None:
                per_family[family.name] = per_family.get(family.name, 0) + 1
            suffix = f"#{number}" if len(chunks) > 1 else ""
            yield Document(
                text=document,
                source="logsamples",
                register=Register.DETECTION,
                side=Side.BLUE,
                ident=f"{repo_path}{suffix}",
            )

    spread = ", ".join(f"{name} {count}"
                       for name, count in sorted(per_family.items()))
    print(f"   logsamples: {emitted} documents from {len(files)} cached files; "
          f"{spread}")
    if thin:
        print(f"   logsamples: held back {thin} excerpt(s) under "
              f"{_MIN_DOC_CHARS} characters — a header with nothing under it")


_LICENSE = (
    "Apache-2.0 — splunk/attack_data ships the unmodified Apache License 2.0 "
    "text; its appendix reads 'Copyright [2023] [Splunk Inc]' and the README "
    "'Copyright 2025 Splunk Inc'. Read from "
    "https://github.com/splunk/attack_data/blob/master/LICENSE, re-checked on "
    "every cold fetch and copied into the cache as LICENSE."
)


SPEC = SourceSpec(
    name="logsamples",
    license=_LICENSE,
    url="https://github.com/splunk/attack_data",
    register=Register.DETECTION,
    side=Side.BLUE,
    fetch=_fetch,
    documents=_documents,
    #: Measured: the family caps select 239 files, 238 of which were available,
    #: and they yield 427 documents and 4.7 MB of text. The floor sits well
    #: under that because the document count legitimately moves with how chatty
    #: the logs upstream happen to be — a file with four distinct records is one
    #: document and a Sysmon capture is four. What it is here to catch is the
    #: other thing: a renamed datasets/ tree or a changed naming convention that
    #: quietly collapses the selection to a handful.
    expect_min_docs=280,
    notes=(
        "Real telemetry, verbatim: Windows Security/Sysmon/PowerShell Event "
        "XML, Linux auditd and syslog, Zeek conn records, nginx and web access "
        "logs, AWS CloudTrail, Kubernetes audit events, Azure/Okta/Google "
        "Workspace and osquery. The corpus has thousands of detection rules "
        "that name log fields and almost no logs; this is the other side of "
        "that join. Fetched as HTTP ranges because single files upstream reach "
        "378 MB, deduplicated on a digit- and GUID-stripped skeleton because "
        "raw telemetry is overwhelmingly the same record again, and capped per "
        "family so breadth survives. Nothing is reformatted or synthesised — "
        "the only editorial acts are selection and a provenance header that "
        "states only what the records themselves say."
    ),
)
