"""MISP galaxy — the threat-actor and malware naming graph. ADVERSARY/RED.

ATT&CK knows 177 threat groups. MISP galaxy knows 1,060, and — this is the
point — it knows what each of them is called by everybody else. ``APT20`` is
``VIOLIN PANDA`` to CrowdStrike, ``TH3Bug`` to Palo Alto, ``Crawling Taurus``
since their renaming, and ``RIDGE CASTLE`` to Secureworks. That aliasing is the
single most ordinary thing a human analyst does when reading threat
intelligence and nothing in this corpus taught it: ``attack`` and
``attackactors`` give one vendor's name per group with MITRE's own aliases,
which is one naming convention out of a dozen.

**What this source is for, concretely.** Three identifier-adjacent skills:

1. **Aliasing.** ``Also known as:`` lines and MISP's ``name-attribution``
   field put five to ten names for one actor in one paragraph, which is the
   adjacency that teaches "these strings denote the same thing".
2. **Breadth of the malware namespace.** 3,683 Malpedia families, 623 tools,
   2,179 ransomware families, 270 RATs, 148 botnets. The corpus's adversary
   register knew the ~860 pieces of software ATT&CK tracks; the real namespace
   is five times that and the names are the surface form an analyst reads.
3. **The commercial surveillance market**, which 615 ``surveillance-vendor``
   clusters describe at a mean of 645 characters each and which **no other
   source in this corpus mentions at all**.

**What is deliberately excluded, and why.** MISP galaxy ships 136 cluster files
and this adapter reads 14 of them. The rest fall into four piles:

* **Not cybersecurity.** ``firearms`` (2.3 MB), ``uavs`` (2.2 MB),
  ``ukhsa-culture-collections`` (4.7 MB), ``cancer``, ``nace``, ``naics``,
  ``terrorist-groups``. MISP galaxy is a general tagging vocabulary; most of its
  bulk is not this subject.
* **Already in this corpus under another name.** Every ``mitre-*`` file is a
  restatement of a bundle ``attack``, ``attackactors``, ``atlas``, ``d3fend`` or
  ``engage`` already reads from MITRE directly, ``sigma-rules.json`` (4.7 MB) is
  a restatement of ``sigma``, and the ``tidal-*`` files are a third party's
  re-publication of ATT&CK. Taking any of them would put the same text in the
  corpus twice, which in a corpus this size is worse than leaving it out: the
  model memorises what repeats.
* **Label-only.** ``stalkerware`` has 170 entries and **zero** descriptions;
  ``o365-exchange-techniques`` averages 36 characters per description. A
  document that is a name and a tag teaches nothing that co-occurs.
* **A different domain's TTPs.** ``disarm-*`` and ``misinfosec-*`` (influence
  operations), ``sparta-*`` and ``bhadra-framework`` (space systems),
  ``nice-framework-*`` (workforce roles), ``veris-framework``, ``cti-cmm``.
  Real catalogues, genuinely out of scope for a host-level purple-team agent,
  and each would dilute the register it was filed under.

**Third-party personal data: this source needs a stricter rule than its siblings
and the measurement says why.** ``ransomware.json`` carries **236 distinct email
addresses** — ransom-note contact addresses, inside the ``ransomnotes``,
``extensions`` and ``links`` metadata and sometimes in the description itself.
Those are attacker artifacts rather than researcher or victim contact details,
but an address that merely *looks* like an attacker's is indistinguishable from
one that is somebody's, and neither belongs in a training corpus. So:

* A **field whitelist** (:data:`_FIELDS`) decides what is rendered. The
  ransom-note bodies, the file-extension lists and the ``links`` field — live
  leak-site and onion URLs — are not on it. That removes the structural cause.
* A **post-render scrubber** then **drops** any document still carrying an
  address or an ``@handle``, counts it, and refuses the whole source if the drop
  rate leaves the band measured here (:data:`_MAX_DROPPED`). A drop rather than
  a refusal, because unlike ``atlas`` and ``engage`` this upstream is *known* to
  contain addresses and a build that dies on document 400 of 8,000 is a build
  nobody runs; a counted drop with a ceiling is the version that stays honest.
* **Contributor names are never rendered.** Every cluster file has a top-level
  ``authors`` array naming the people who maintain it — 5 names in
  ``threat-actor.json`` alone. It carries no signal about any adversary and is
  simply not read.
* Person-names *inside* a published CC0 threat-intel description are kept as
  published; see :func:`_cluster_document` for that decision and its limits.

**STIX UUIDs never reach the corpus.** MISP's ``related`` edges and
``name-attribution`` entries are UUID-keyed. The UUIDs are resolved to names
through a cross-file index and then discarded — a 36-character hex string beside
an actor name teaches the tokenizer a hash, and ``attack`` learned the same
lesson before this adapter existed.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Iterator

from ..net import NetworkError, download
from ..source import Document, Register, Side, SourceError, SourceSpec, normalise

_REPO = "MISP/misp-galaxy"
_REF = "main"
_RAW = f"https://raw.githubusercontent.com/{_REPO}/{_REF}"
_LICENSE_URL = f"{_RAW}/LICENSE.md"

_LICENSE_DIR = "licenses"
_MARKER = ".fetched.json"


class _Cluster:
    """One cluster file, with the heading and side it is rendered under."""

    __slots__ = ("file", "label", "side")

    def __init__(self, file: str, label: str, side: Side) -> None:
        self.file, self.label, self.side = file, label, side

    @property
    def key(self) -> str:
        return self.file.removesuffix(".json")


#: The 14 files read, with the heading each is rendered under. See the module
#: docstring for the four reasons the other 122 are not here. Ordered so the
#: actor catalogues come first and the capability catalogues after, because the
#: emission order is the corpus order and a reader of the build report should be
#: able to see the shape of the source in it.
_CLUSTERS: tuple[_Cluster, ...] = (
    _Cluster("threat-actor.json", "Threat actor", Side.RED),
    _Cluster("microsoft-activity-group.json",
             "Threat actor (Microsoft naming)", Side.RED),
    _Cluster("360net.json", "Threat actor (Qihoo 360 naming)", Side.RED),
    _Cluster("malpedia.json", "Malware family (Malpedia)", Side.RED),
    _Cluster("ransomware.json", "Ransomware family", Side.RED),
    _Cluster("rat.json", "Remote access trojan", Side.RED),
    _Cluster("banker.json", "Banking trojan", Side.RED),
    _Cluster("botnet.json", "Botnet", Side.RED),
    _Cluster("backdoor.json", "Backdoor", Side.RED),
    _Cluster("stealer.json", "Information stealer", Side.RED),
    _Cluster("exploit-kit.json", "Exploit kit", Side.RED),
    _Cluster("tool.json", "Adversary tool", Side.RED),
    _Cluster("rmm-tool.json", "Remote monitoring and management tool",
             Side.NEUTRAL),
    _Cluster("surveillance-vendor.json", "Commercial surveillance vendor",
             Side.RED),
)

#: The largest selected file is 3.8 MB. The ceiling is per-file and generous
#: enough for growth while still refusing a redirect to something else.
_MAX_FILE_BYTES = 24 * 1024 * 1024
_MAX_LICENSE_BYTES = 256 * 1024

#: Below this a cluster is a name, a label and a reference URL, and the floor
#: keeps the label-only tail of an otherwise substantial file out without
#: needing a per-file judgement about where substance begins.
#:
#: **It is measured against the body, not the whole document** — everything
#: before the ``## References`` heading. That distinction was not the first
#: design and the numbers are why it became one. Against the whole document the
#: floor passed 6,784 clusters, but the body-length distribution of those had a
#: median of 349 characters and a 25th percentile of **154**: a quarter of what
#: the floor had accepted were a name, three metadata lines and a list of URLs
#: long enough to clear 260 characters on its own. A floor that a link list can
#: satisfy is not measuring substance. Against the body it passes 4,013
#: clusters, and every one of them has a real description or real metadata
#: behind the name.
_MIN_BODY_CHARS = 260

#: The metadata fields rendered, in rendering order, with their labels. A
#: **whitelist**, which is the half of the privacy design that removes the cause
#: rather than catching the symptom: ``ransomnotes``, ``ransomnotes-filenames``,
#: ``ransomnotes-refs``, ``extensions`` and ``links`` are the fields the 236
#: measured email addresses live in, and none of them is here.
#:
#: ``links`` deserves its own sentence. In the ransomware galaxy it holds live
#: leak-site and onion URLs. Reachable attacker infrastructure is not something
#: to copy into a training corpus even once, and it teaches the model nothing a
#: family description does not.
_FIELDS: tuple[tuple[str, str], ...] = (
    ("type", "Type"),
    ("country", "Country"),
    ("since", "Active since"),
    ("date", "First seen"),
    ("motive", "Motive"),
    ("threat-actor-classification", "Classification"),
    ("capabilities", "Capabilities"),
    ("mode-of-operation", "Mode of operation"),
    ("victimology", "Victimology"),
    ("targeted-sector", "Targeted sectors"),
    ("cfr-suspected-state-sponsor", "Suspected state sponsor (CFR)"),
    ("cfr-type-of-incident", "Type of incident (CFR)"),
    ("cfr-target-category", "Target categories (CFR)"),
    ("cfr-suspected-victims", "Suspected victims (CFR)"),
    ("attribution-confidence", "Attribution confidence"),
    ("payment-method", "Payment method"),
    ("price", "Price"),
    ("encryption", "Encryption"),
    ("products", "Products"),
    ("TTP", "TTPs"),
    ("ttp", "TTPs"),
)

#: Read for the aliasing signal and rendered as names only: the field's entries
#: are ``Name:uuid`` pairs and the uuid half is a hash the tokenizer should
#: never meet.
_ATTRIBUTION_FIELD = "name-attribution"

#: See :mod:`training.corpus.sources.atlas`. Identical patterns across the
#: sources added in this family on purpose — a privacy check that differs
#: subtly per adapter is a privacy check whose guarantee cannot be stated.
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
#: The same pattern as :mod:`training.corpus.sources.atlas`, including
#: its allowlist of systems and documentation tokens; see there for why
#: ``@reboot`` and ``@property`` are not handles. The copies must stay
#: byte-identical and a test asserts that they have not diverged.
_HANDLE = re.compile(
    r"(?<![A-Za-z0-9._%+\-@/])@"
    r"(?!(?:reboot|daily|hourly|weekly|monthly|yearly|annually|midnight|"
    r"staticmethod|classmethod|property|dataclass|override|functools|"
    r"media|import|charset|font-face|supports|keyframes|namespace|"
    r"echo|param|params|returns?|throws|see|since|deprecated|author|"
    r"type|types|interface|decorator|test|patch|mock|pytest|cache|"
    r"sha256|sha1|md5|base64|xmlns|version|schema|context|id|graph)"
    r"(?![A-Za-z0-9_]))"
    r"[A-Za-z0-9_]{3,15}(?![A-Za-z0-9_@.])"
)

#: How many documents may be dropped by the scrubber before the source refuses.
#: **Measured, by running it: 25** — 15 in ransomware, 5 in malpedia, 3 in rat,
#: 2 in threat-actor, against 4,008 emitted. The field whitelist is what did
#: the work: of the 236 email addresses in ransomware.json, all but a couple of
#: dozen were in ``ransomnotes``, ``extensions`` and ``links``, which are not
#: rendered. What the scrubber still catches is addresses inside description
#: prose.
#:
#: The ceiling is the instrument check, and it is set at six times the measured
#: figure rather than at twenty: if contact data moves into a field _FIELDS
#: renders, the count jumps into the hundreds and this refuses with the number
#: in the message, instead of silently discarding a slice of the source and
#: reporting a thinner corpus as a successful build. A ceiling raised to make a
#: build pass measures nothing.
_MAX_DROPPED = 200

#: References rendered per document, in the order upstream lists them.
#:
#: This cap exists because of a measurement that was a genuine surprise.
#: Uncapped, the ``## References`` sections were **3,190,023 of this source's
#: then 6,268,938 characters — 50.9%**. Malpedia tracks every report about a
#: family, so ``Cobalt Strike`` arrived as a 69,802-character document of which
#: roughly 68,000 was a list of URLs, and five more families were over 20 KB on
#: the same grounds.
#:
#: A link dump is not training signal. It teaches URL syntax, which the corpus
#: has in quantity from every other source, while crowding out the register it
#: is filed under and inflating this source's share of the corpus with text no
#: reader would call adversary description. The distribution says where to cut:
#: 6,119 of the 6,784 clusters that cleared the original floor have ten
#: references or fewer, so a cap of twelve
#: leaves nine documents in ten untouched and takes the whole of the tail that
#: caused the problem. Upstream order is kept rather than sorting, because
#: MISP's first references are the originating report and the later ones are
#: follow-on coverage.
#:
#: Twelve was the first cap and six is the one that shipped, because twelve was
#: still not enough: with the body floor below also in place the reference
#: sections were 32.9% of the source at twelve and **28.7% at six**. That
#: number is reported rather than driven to zero, because these URLs are not
#: pure noise — the vendor domain and the report slug name the campaign, and
#: that is the one thing a reference line teaches. A third of the source is as
#: far as it is honest to push it; the rest would be deleting content to make a
#: ratio look better.
_REFERENCE_CAP = 6

#: A MISP ``related`` edge's confidence lives in an estimative-language tag.
#: Rendered in plain words because ``estimative-language:likelihood-probability=
#: "likely"`` is machine syntax wrapped around one useful word.
_ESTIMATIVE = re.compile(
    r'estimative-language:likelihood-probability="([a-z-]+)"'
)


def _short_hash(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]


def _fetch(cache_dir: Path) -> Path:
    """Download the 14 selected cluster files and the upstream LICENSE.md.

    Returns the cache directory. The marker is written last, so an interrupted
    fetch re-fetches instead of yielding a corpus missing whichever files had
    not arrived — the failure mode that is invisible in the output and obvious
    in the build report only if somebody is comparing document counts.

    ~9.4 MB over the wire on a cold cache, warm it is a local parse.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    marker = cache_dir / _MARKER
    if marker.is_file() and all(
            (cache_dir / c.file).is_file() for c in _CLUSTERS):
        return cache_dir

    licenses = cache_dir / _LICENSE_DIR
    licenses.mkdir(parents=True, exist_ok=True)
    license_file = licenses / "misp-galaxy.LICENSE.md"

    staging = cache_dir / ".staging"
    staging.mkdir(parents=True, exist_ok=True)
    try:
        download(_LICENSE_URL, license_file, timeout=60,
                 max_bytes=_MAX_LICENSE_BYTES)
        text = license_file.read_text(encoding="utf-8", errors="replace")
        # The dual licence is what makes this source usable, and the CC0 half is
        # the one relied on. Checked rather than assumed, because the SPEC
        # declaration below is a claim about this file's content.
        if "CC0 1.0 Universal" not in text:
            raise SourceError(
                "mispgalaxy: the upstream LICENSE.md no longer offers CC0 1.0 "
                f"({_LICENSE_URL}). This source is taken on the CC0 half of a "
                "dual licence; if that is gone, re-read the terms and update "
                "the declaration rather than training on the files anyway."
            )
        for cluster in _CLUSTERS:
            target = staging / cluster.file
            download(f"{_RAW}/clusters/{cluster.file}", target,
                     timeout=180, max_bytes=_MAX_FILE_BYTES)
            # Parsed at fetch time so an HTML error page delivered with a 200
            # is caught while the URL that produced it is still in scope.
            try:
                parsed = json.loads(target.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise SourceError(
                    f"mispgalaxy: {cluster.file} did not arrive as JSON from "
                    f"{_RAW}/clusters/{cluster.file}: {exc}"
                ) from None
            if not isinstance(parsed, dict) or not parsed.get("values"):
                raise SourceError(
                    f"mispgalaxy: {cluster.file} arrived with no 'values' "
                    "array. Upstream has been reorganised; fix the adapter "
                    "rather than building on what is left."
                )
        for cluster in _CLUSTERS:
            (staging / cluster.file).replace(cache_dir / cluster.file)
    except NetworkError as exc:
        raise SourceError(f"mispgalaxy: fetch failed: {exc}") from None
    finally:
        for leftover in sorted(staging.glob("*")):
            leftover.unlink(missing_ok=True)
        if staging.is_dir():
            staging.rmdir()

    marker.write_text(
        json.dumps(
            {
                "repo": _REPO,
                "ref": _REF,
                "clusters": [c.file for c in _CLUSTERS],
                "license_url": _LICENSE_URL,
                "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return cache_dir


def _load(cache_dir: Path) -> dict[str, dict[str, Any]]:
    """Read every selected cluster file. A missing one is fatal, not skipped."""
    out: dict[str, dict[str, Any]] = {}
    for cluster in _CLUSTERS:
        path = cache_dir / cluster.file
        if not path.is_file():
            raise SourceError(
                f"mispgalaxy: {path} is missing — delete {_MARKER} and "
                "re-fetch. A partial cache yields a quietly thin corpus."
            )
        try:
            parsed = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SourceError(f"mispgalaxy: could not parse {path}: {exc}") from None
        if not isinstance(parsed, dict):
            raise SourceError(f"mispgalaxy: {path} is not a cluster object")
        out[cluster.file] = parsed
    return out


def _flat(value: Any) -> list[str]:
    """A metadata value as a list of strings, whatever shape MISP used.

    MISP is inconsistent by design — it is a tagging vocabulary with hundreds of
    contributors — so the same field is a string in one cluster and a list in
    the next, and ``attribution-confidence`` is sometimes the integer ``50`` and
    sometimes the string ``"50"``. An adapter that reads one shape loses the
    others without saying so.
    """
    if value is None:
        return []
    if isinstance(value, (str, int, float)):
        text = str(value).strip()
        return [text] if text else []
    if isinstance(value, dict):
        return [f"{k}: {v}" for k, v in value.items() if str(v).strip()]
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            out += _flat(item)
        return out
    return []


class _Index:
    """Cross-file name resolution for MISP's UUID-keyed edges.

    Built across all 14 files rather than per file, because ``related`` points
    wherever it likes: a ``threat-actor`` edge of type ``uses`` lands in
    ``tool`` or ``malpedia``. A per-file index resolves the ``similar`` edges
    and silently drops the ``uses`` ones, which are the interesting half.
    """

    def __init__(self, files: dict[str, dict[str, Any]]) -> None:
        self.by_uuid: dict[str, tuple[str, str]] = {}
        for cluster in _CLUSTERS:
            payload = files[cluster.file]
            for entry in payload.get("values") or []:
                if not isinstance(entry, dict):
                    continue
                uuid = str(entry.get("uuid") or "")
                value = str(entry.get("value") or "").strip()
                if uuid and value:
                    self.by_uuid[uuid] = (value, cluster.label)

    def resolve(self, uuid: str) -> str:
        """``APT1 (Threat actor)``, or the empty string when unknown.

        Empty rather than the UUID: an unresolved edge is better left out than
        rendered as a hex string. MISP's clusters reference files this adapter
        does not read, so unresolved edges are expected and ordinary.
        """
        found = self.by_uuid.get(uuid)
        return f"{found[0]} ({found[1]})" if found else ""


def _section(title: str, body: list[str]) -> list[str]:
    return [] if not body else ["", f"## {title}", ""] + body


def _cluster_document(entry: dict[str, Any], cluster: _Cluster,
                      idx: _Index) -> tuple[str, list[str]]:
    """Render one MISP cluster value as ``(body, reference lines)``.

    Split in two rather than returned as one string because the substance floor
    is measured on the body alone — see :data:`_MIN_BODY_CHARS` for the
    measurement that forced that — and a caller that has to re-find the
    ``## References`` heading by string search to apply its own floor is a
    caller one refactor away from applying it to the wrong half.

    **On person-names inside descriptions.** These are CC0 descriptions quoted
    from published threat-intelligence reporting, and some of them name natural
    persons — an indicted operator, a vendor's founder. They are kept as
    published, and that is a deliberate decision rather than an oversight, for
    two reasons. The alternative is a name detector, and a name detector over
    threat-intelligence prose cannot tell ``Lazarus`` from a surname; it would
    either delete the subject matter or miss the thing it was built for, and a
    privacy control that does neither job reliably is worse than a stated
    limit. And the substance of these descriptions is organisational behaviour —
    who was targeted, with what, from when — which is what the register is for.

    What is *not* kept is any of it as contact data: see :data:`_FIELDS` for the
    structural exclusion and :func:`_documents` for the scrubber that drops
    whatever gets past it. Contributor names are never read at all.
    """
    value = str(entry.get("value") or "").strip()
    meta = entry.get("meta") or {}
    if not isinstance(meta, dict):
        meta = {}

    lines = [value, ""]
    lines.append("Catalogue: MISP galaxy")
    lines.append(f"Cluster: {cluster.key}")
    lines.append(f"Type: {cluster.label}")

    synonyms = _flat(meta.get("synonyms"))
    # name-attribution is the aliasing prize and it arrives as "Name:uuid".
    # Only the name half is rendered; see the module docstring on UUIDs.
    attributions = [
        name.split(":", 1)[0].strip()
        for name in _flat(meta.get(_ATTRIBUTION_FIELD))
    ]
    aliases: list[str] = []
    for name in synonyms + attributions:
        if name and name != value and name not in aliases:
            aliases.append(name)
    if aliases:
        lines.append(f"Also known as: {'; '.join(aliases)}")

    for field, label in _FIELDS:
        if field == "type" and cluster.key != "malpedia":
            # 'type' is the heading already for most clusters; in malpedia it
            # is the platform ("win.", "elf.", "apk.") and carries real
            # information, so it is rendered there and suppressed elsewhere
            # rather than printing "Type: ransomware" under "Type: Ransomware
            # family".
            continue
        rendered = _flat(meta.get(field))
        if rendered:
            lines.append(f"{label}: {'; '.join(rendered)}")

    description = str(entry.get("description") or "").strip()
    if description:
        lines += ["", description]

    body = []
    for edge in entry.get("related") or []:
        if not isinstance(edge, dict):
            continue
        target = idx.resolve(str(edge.get("dest-uuid") or ""))
        if not target:
            continue
        kind = str(edge.get("type") or "related-to")
        confidence = ""
        for tag in _flat(edge.get("tags")):
            match = _ESTIMATIVE.search(tag)
            if match:
                confidence = match.group(1).replace("-", " ")
                break
        suffix = f" — assessed {confidence}" if confidence else ""
        body.append(f"- {kind}: {target}{suffix}")
    lines += _section("Related clusters", sorted(body))

    references: list[str] = []
    for field in ("refs", "official-refs"):
        for url in _flat(meta.get(field)):
            if url not in references:
                references.append(url)
    reference_lines = [f"- {url}" for url in references[:_REFERENCE_CAP]]
    if len(references) > _REFERENCE_CAP:
        # Stated rather than silently truncated: the count is itself a fact
        # about how heavily reported a family is, and a reader of the corpus
        # should be able to tell a short reference list from a cut one.
        reference_lines.append(
            f"- ... and {len(references) - _REFERENCE_CAP} more published "
            "references"
        )
    return "\n".join(lines), reference_lines


def _documents(path: Path) -> Iterator[Document]:
    """Yield one document per cluster value, cluster file by cluster file.

    The scrubber's drop count is checked **after** the last document, which
    means the ceiling can only fire at the end of the source. That is the right
    trade: the alternative is checking a running rate, which on a file whose
    email-bearing clusters happen to sort early would refuse a build that was
    about to be fine.
    """
    cache_dir = path if path.is_dir() else path.parent
    files = _load(cache_dir)
    idx = _Index(files)

    dropped: list[str] = []
    emitted = 0

    for cluster in _CLUSTERS:
        payload = files[cluster.file]
        values = [v for v in payload.get("values") or [] if isinstance(v, dict)]
        # Sorted by the cluster's own value, so two runs over one cache produce
        # byte-identical output and "did my change alter the corpus" stays an
        # answerable question.
        for entry in sorted(values, key=lambda e: str(e.get("value") or "")):
            value = str(entry.get("value") or "").strip()
            if not value:
                continue
            body, reference_lines = _cluster_document(entry, cluster, idx)
            body = normalise(body)
            if len(body) < _MIN_BODY_CHARS:
                continue
            text = normalise("\n".join([body] + _section("References",
                                                         reference_lines)))
            leak = _EMAIL.search(text) or _HANDLE.search(text)
            if leak is not None:
                # Reported as kind + length + hash, never quoted: the whole
                # point of finding it is to not reproduce it, and an audit here
                # once put the values it found into its own output.
                found = leak.group(0)
                dropped.append(
                    f"{cluster.key}/{value}: len={len(found)} "
                    f"sha256[:8]={_short_hash(found)}"
                )
                continue
            emitted += 1
            yield Document(
                text=text,
                source="mispgalaxy",
                register=Register.ADVERSARY,
                side=cluster.side,
                ident=f"{cluster.key}/{value}",
            )

    if len(dropped) > _MAX_DROPPED:
        raise SourceError(
            f"mispgalaxy: dropped {len(dropped)} documents for carrying an "
            f"address or handle, over the ceiling of {_MAX_DROPPED} "
            f"(emitted {emitted}). Measured at {len(_CLUSTERS)} cluster files "
            "the figure was comfortably under that, so this is a change "
            "upstream — probably contact data moving into a field _FIELDS "
            "renders. Find out which field before raising this number; the "
            "ceiling is the instrument, and a ceiling raised to make a build "
            "pass measures nothing."
        )


SPEC = SourceSpec(
    name="mispgalaxy",
    license=(
        "CC0-1.0 — MISP galaxy. Upstream LICENSE.md: \"The MISP galaxy (JSON "
        "files) are dual-licensed under: CC0 1.0 Universal (CC0 1.0) - Public "
        "Domain Dedication. or [a 2-clause BSD grant]\". This source relies on "
        "the CC0 half, under which no attribution is required and "
        "redistribution of derivatives is unrestricted. Read from "
        "https://raw.githubusercontent.com/MISP/misp-galaxy/main/LICENSE.md and "
        "copied verbatim into the cache under "
        "licenses/misp-galaxy.LICENSE.md so the claim is checkable against the "
        "download. Note for anyone reading that cached file: the BSD half of "
        "the dual licence lists its copyright holders including a maintainer's "
        "email address. It stays in the cached licence file, where altering it "
        "would be worse than keeping it, and reaches no document: the licence "
        "string above omits it and the adapter never reads the cluster files' "
        "'authors' arrays."
    ),
    url="https://github.com/MISP/misp-galaxy",
    register=Register.ADVERSARY,
    side=Side.RED,
    fetch=_fetch,
    documents=_documents,
    #: Measured by running the adapter, not estimated: the 14 cluster files
    #: hold 8,381 values, of which **4,008 clear the 260-character body floor
    #: and the address scrubber, for 3,731,906 characters** — median document
    #: 835 characters, longest 8,645, and no two documents sharing a
    #: fingerprint. The largest contributors are malpedia (1,127), threat-actor
    #: (974) and surveillance-vendor (601).
    #:
    #: The floor is set at 3,200 rather than just under the observed count:
    #: MISP clusters gain and lose descriptions continuously and 4,008 is a
    #: snapshot, while 3,200 is still above what losing either malpedia or
    #: threat-actor would leave — which is the regression this is for.
    expect_min_docs=3200,
    #: Fourteen HTTPS downloads on a cold cache, one of them 3.8 MB. Warm it is
    #: a local parse of 9.4 MB of JSON and finishes in seconds.
    timeout=900,
    notes=(
        "14 of MISP galaxy's 136 cluster files, chosen as the threat-actor and "
        "malware naming graph: threat-actor (1,060 values), Microsoft and "
        "Qihoo 360 actor namings, Malpedia families, ransomware, RATs, bankers, "
        "botnets, backdoors, stealers, exploit kits, adversary tools, RMM tools "
        "and commercial surveillance vendors. The aliasing is the point — "
        "'Also known as' joins synonyms and MISP's name-attribution field so "
        "five vendor names for one actor sit in one paragraph, which no other "
        "source in this corpus teaches. Excluded: every mitre-* file (a "
        "restatement of what attack/attackactors/atlas/d3fend/engage read from "
        "MITRE directly), sigma-rules (restates the sigma source), tidal-* (a "
        "third party's re-publication of ATT&CK), the non-cyber galaxies "
        "(firearms, uavs, ukhsa-culture-collections, nace, naics...), the "
        "label-only ones (stalkerware has 170 values and zero descriptions) "
        "and other domains' TTP matrices (disarm-*, sparta-*, nice-*). "
        "Privacy: ransom-note bodies, file-extension lists and the 'links' "
        "field (live leak-site and onion URLs) are not on the rendered-field "
        "whitelist because that is where the 236 measured email addresses "
        "live; any document still carrying an address or @handle is dropped "
        "and counted (25 of 4,033 when measured), and the source refuses if "
        "that count leaves the measured band. "
        "Cluster 'authors' arrays are never read. STIX UUIDs are resolved to "
        "names through a cross-file index and discarded."
    ),
)
