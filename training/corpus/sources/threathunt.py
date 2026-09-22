"""Threat hunting and detection engineering as reasoning, not as rules. PROSE/BLUE.

This corpus holds something like six thousand detection rules — Sigma, Splunk
SPL, Elastic EQL, YARA, Suricata, Nuclei — and almost nothing about how anybody
decides what to write, where to look for it, or what it means when the search
comes back empty. That is a strange hole for *this* project to have. Whetstone's
keystone is a closed verb catalogue in which every red verb declares
``detected_by``, and a verb whose detections stay silent is reported as a
detection gap: the deliverable and the training verifier are both built on the
claim that absence of evidence is a fact about the sensor, not a fact about the
adversary. The model has never once seen that claim written down. It has seen
the answers and none of the working.

Four upstreams supply the working, and they were chosen because each is a
different *shape* of it rather than four helpings of the same one.

**MITRE CAR** is the analytic as an artefact with its reasoning still attached.
An entry states what it hopes to observe, gives the logic as CAR's own
pseudocode, then repeats that logic in Splunk, EQL, LogPoint and DNIF — the same
hypothesis in five languages, which is a translation join nothing else here
provides — and finishes with a unit test that says which commands to run to make
the analytic fire. It also rates its own ``coverage`` of each ATT&CK technique
as Low, Moderate or High, and 141 of the 159 ratings are Low or Moderate. An
analytic catalogue that mostly grades itself "partial" is the detection-gap
thesis stated by someone else, in their own numbers.

CAR's two smaller trees matter more than their size suggests. ``data_model/``
is the field dictionary a hunt is phrased in — what a *process* is, which
actions it has, which fields carry what, with an example value for every one.
``sensors/`` is the other half and is the rarest material in this source: per
sensor and version, exactly which ``(object, action)`` pairs it reports and
which fields it carries for each. A pair that does not appear is telemetry that
sensor does not produce. That is the question "does this empty result mean
anything" reduced to a table, for Sysmon 10.4, 11.0 and 13, osquery 4.1.2 and
4.6.0, auditd 2.8 and Autoruns.

**OTRF's Threat Hunter Playbook** is the hunt as a process. Every one of its 26
hunts opens on a literal ``## Hypothesis`` — "Adversaries might be leveraging WMI
Win32_Process class and method Create to execute code remotely across my
environment" — then Technical Context (how the mechanism works), Offensive
Tradecraft (how it is abused), then several numbered analytics, each one
preceded by a table naming the data source, event provider, relationship and
event ID it depends on. Picking the data source is shown as a step, which is the
step every rule repository leaves out. Its ``pre-hunt/`` pages are the blunt
version: "Others assume that their environment might not be compromised because
their query did not return anything when in reality, they are not even
collecting the right data in the first place."

**Summiting the Pyramid** is the analytic judged after the fact. It scores
published detections for robustness — how cheaply an adversary can evade them —
and the interesting part is not the score but the note beside it: "This is
looking for basic strings and environment variables that will change over time",
"it can be easily changed by an adversary". Ninety of those judgements ship as a
CSV, 87 of them carrying that note, and fifteen longer pages walk one analytic
from its original form, through the scoring, to an improved version. Detection
engineering with the revisions left in.

**Palantir's Alerting and Detection Strategy framework** is the smallest upstream
here, seventy kilobytes, and it is in for one section. Every ADS document
carries **Blind Spots and Assumptions**, which enumerates the conditions under
which the alert silently fails to fire — endpoint tooling running, module loads
recorded, logs reaching the SIEM, the SIEM indexing them — and says plainly that
violating any of them produces the same empty result as innocence. Nothing else
in this corpus writes that down.

**Register, measured rather than asserted.** This lands in PROSE, which the
build reports at 1.8% against a 9% target. Three of the four upstreams are
overwhelmingly running text — what code they carry is quoted inside an argument
about it rather than shipped to be run. CAR is the mixed one, so it was counted:
of its 302 KB of analytics, 27% is implementation code and 11 points of that 27
are CAR's own pseudocode, which leaves roughly three quarters prose. Side is
BLUE and there is no honest way to call it anything else — the red share is
under target too, at 30% against 60%, and this does not help it. A hunt document
is a hunt document. The gap it fills is the register.

**Traps, in the order they bit.**

*CAR spells its own implementation types four ways.* The ``type`` field carries
``pseudocode`` (49), ``Pseudocode`` (45), ``psuedocode`` (1, a typo upstream)
and both ``Splunk`` (60) and ``splunk`` (22). A plain ``type == "pseudocode"``
finds 49 of 95, and the failure is silent — you get a document that looks fine
and is missing half its logic. Types are case-folded and the typo is corrected
by table; the number of corrections is printed.

*The Playbook's hunts are Jupyter notebooks and most of their code is
plumbing.* 133 ```` ```{code-cell} ```` blocks across the 26 hunts are the
notebook's mechanics: download a zip from securitydatasets.com, read it into
pandas, then restate — in dataframe syntax — the exact SQL that appears
immediately above in a ```` ```{code-block} ````. Near-identical text repeated
once per hunt is the CAPEC ``Content_History`` hazard again, and this corpus is
small enough that the model would learn ``zipFileRequest = requests.get(url)``
by heart. The ``{code-cell}`` blocks go; the ``{code-block}`` blocks, which hold
the analytic logic against real Windows field names, stay. Headings left
standing over nothing are then pruned, subtree aware, so a section that still
has content under a sub-heading survives. (A 134th ``{code-cell}`` sits in
``hunts/windows/intro.md``, which is an ATT&CK Navigator ``<iframe>`` and a
pandas call that renders a clickable index — page chrome, dropped whole.)

*Seven characters in five Playbook files are mojibake* — UTF-8 em dashes and a
registered sign that were once decoded as cp1252 and re-encoded. They are
repaired by round-tripping only the matched run back through cp1252 and
accepting the result only if it decodes as valid UTF-8. A blanket
``text.encode("cp1252").decode("utf-8")`` over the document is the obvious fix
and is wrong: it corrupts any genuinely Latin-1 text it meets and throws on the
first byte that is not representable. The narrow version fires 7 times across
all four upstreams and 0 times in the other three, which is the check that it is
narrow.

*A codeload tarball carries no submodules.* CAR's ``OSSEM-CDM`` and ``bzar``
entries are gitlinks and arrive as nothing at all. That is the wanted outcome —
OSSEM-CDM is a separate project under its own licence and would be SYSTEM
register, which is 38.5% of this corpus and over its cap — but it means the
occasional ``data_model`` reference to an OSSEM path resolves to nothing in this
cache, and a reader should know that rather than discover it.

**Licences, read from the files rather than from the badges.**

* ``mitre-attack/car`` — Apache-2.0. ``LICENSE.txt`` is the standard text;
  ``NOTICE.txt`` adds MITRE's copyright and public-release case number, and both
  are copied into the cache. The NOTICE also records that CAR builds on ATT&CK
  under MITRE's ATT&CK Terms of Use.
* ``OTRF/ThreatHunter-Playbook`` — MIT, Copyright (c) 2022 Open Threat Research
  Forge, read from ``LICENSE`` on the default branch.
* ``center-for-threat-informed-defense/summiting-the-pyramid`` — Apache-2.0.
  There is no ``NOTICE`` file; the notice lives in ``README.md`` ("© 2023, 2024,
  2025 MITRE. Approved for public release. Document number(s) CT0078, CT0128,
  25-1550"), so the README is copied into the cache alongside the LICENSE.
* ``palantir/alerting-detection-strategy-framework`` — MIT, Copyright (c) 2017
  Palantir Technologies.

**And one thing an Apache-2.0 badge does not tell you.** Twelve of Summiting
the Pyramid's fifteen analytic pages quote a SigmaHQ rule verbatim as the
"Original Analytic" they then score, a thirteenth does the same inside its
robustness worked example, and the scored-analytics CSV links 90 more by commit
permalink. Those rules are not Apache-2.0; they are DRL-1.1, the Detection Rule
License, which is what :mod:`~training.corpus.sources.sigma` already declares
for the same repository. This is the pattern the project has been caught by
before — a permissively licensed repository carrying third-party files under
someone else's terms — so it is named in the declared licence string rather than
left for someone to find. The quotations stay, because removing the analytic
being scored would leave a scoring argument about nothing; but they are the one
place this source knowingly overlaps another, and they are thirteen rules out of
the three thousand ``sigma`` already holds.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import shutil
import tarfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import yaml

from ..net import NetworkError, download
from ..source import Document, Register, Side, SourceError, SourceSpec, normalise

try:  # libyaml when the wheel has it
    from yaml import CSafeLoader as _Loader  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - depends on the local PyYAML build
    from yaml import SafeLoader as _Loader  # type: ignore[assignment]


_NAME = "threathunt"

_CODELOAD = "https://codeload.github.com/{repo}/tar.gz/refs/heads/{ref}"

#: Written last, inside the finished directory, so its presence means extraction
#: completed. A half-unpacked upstream therefore re-fetches instead of being
#: mistaken for a cache that is simply thin. One marker per upstream, so a
#: failure on the fourth does not throw away the three that already landed.
_MARKER = ".fetched.json"

#: No member of these four repositories is anywhere near this large; the biggest
#: file kept is a 30 KB CSV. The ceiling exists so a tarball that is not what it
#: was cannot write an arbitrary amount into the cache while the extractor is
#: still deciding whether it likes the name.
_MAX_MEMBER_BYTES = 4 * 1024 * 1024

#: Below this a rendered document is a header with nothing under it — a
#: navigation stub, an index page that was only a toctree. Real entries in every
#: one of the four upstreams start well above it.
_MIN_CHARS = 350


@dataclass(frozen=True, slots=True)
class _Upstream:
    """One repository, what to take from it, and on whose terms.

    The keep table pairs a path prefix with the suffixes allowed under it rather
    than filtering on suffix alone, because three of these repositories hold
    large trees of material this source deliberately does not want —
    ``docs/tutorials/`` is about running Jupyter, ``DCC/`` is a spreadsheet
    tool, ``resources/cti/`` is 94 STIX files — and a bare ``*.md`` sweep would
    take all of it.
    """

    key: str
    repo: str
    ref: str
    #: ``(path prefix, allowed suffixes)``. A prefix ending in ``/`` matches a
    #: directory; one without matches that exact path.
    keep: tuple[tuple[str, tuple[str, ...]], ...]
    #: Copied verbatim into the cache so the licence claim stays checkable
    #: offline, and not counted towards ``min_files``.
    provenance: tuple[str, ...]
    #: Floor on content files extracted. Set below the observed count so
    #: ordinary churn is quiet and a renamed directory is loud.
    min_files: int
    observed_files: int
    license_note: str


_UPSTREAMS: tuple[_Upstream, ...] = (
    _Upstream(
        key="car",
        repo="mitre-attack/car",
        ref="master",
        keep=(
            ("analytics/", (".yaml",)),
            ("data_model/", (".yaml",)),
            ("sensors/", (".yaml",)),
            ("GLOSSARY.md", (".md",)),
        ),
        provenance=("LICENSE.txt", "NOTICE.txt"),
        min_files=90,
        observed_files=123,
        license_note=(
            "MITRE CAR: Apache-2.0, LICENSE.txt and NOTICE.txt read and cached "
            "(Copyright 2022 The MITRE Corporation; approved for public "
            "release, case 18-3868; builds on ATT&CK under MITRE's ATT&CK "
            "Terms of Use)"
        ),
    ),
    _Upstream(
        key="thp",
        repo="OTRF/ThreatHunter-Playbook",
        ref="master",
        keep=(
            ("docs/hunts/", (".md", ".yaml")),
            ("docs/library/", (".md",)),
            ("docs/pre-hunt/", (".md",)),
            ("docs/intro.md", (".md",)),
        ),
        provenance=("LICENSE",),
        min_files=50,
        observed_files=72,
        license_note=(
            "OTRF Threat Hunter Playbook: MIT, LICENSE read and cached "
            "(Copyright (c) 2022 Open Threat Research Forge)"
        ),
    ),
    _Upstream(
        key="stp",
        repo="center-for-threat-informed-defense/summiting-the-pyramid",
        ref="main",
        keep=(
            ("docs/", (".rst",)),
            ("docs/analytics/", (".rst", ".csv")),
        ),
        # No NOTICE file exists upstream; the notice is a section of README.md,
        # so the README is what has to be kept for the record to be complete.
        provenance=("LICENSE", "README.md"),
        min_files=55,
        observed_files=82,
        license_note=(
            "Summiting the Pyramid (MITRE Center for Threat-Informed Defense): "
            "Apache-2.0, LICENSE read and cached; no NOTICE file exists, the "
            "notice is in README.md, also cached ((c) 2023, 2024, 2025 MITRE, "
            "approved for public release, CT0078 / CT0128 / 25-1550). NOT "
            "wholly Apache-2.0 in substance: 13 of its pages quote a SigmaHQ "
            "rule verbatim as the analytic they score, and those rules are "
            "DRL-1.1 (Detection Rule License 1.1), the same licence the sigma "
            "source declares"
        ),
    ),
    _Upstream(
        key="ads",
        repo="palantir/alerting-detection-strategy-framework",
        ref="master",
        keep=(
            ("ADS-Framework.md", (".md",)),
            ("ADS-Examples/", (".md",)),
            ("README.md", (".md",)),
        ),
        provenance=("LICENSE",),
        min_files=6,
        observed_files=8,
        license_note=(
            "Palantir Alerting and Detection Strategy framework: MIT, LICENSE "
            "read and cached (Copyright (c) 2017 Palantir Technologies)"
        ),
    ),
)


# ---------------------------------------------------------------------------
# fetch
# ---------------------------------------------------------------------------

def _root(cache_dir: Path) -> Path:
    """Normalise whatever directory we were handed to one upstreams root.

    ``build.py`` calls ``spec.fetch(cache_dir / spec.name)`` and hands
    ``documents()`` the result, but it is useful while developing to point
    either function at the bare cache root by hand. Both go through here, so
    both land in the same place and a hand-run adapter shares its cache with a
    real build instead of downloading forty megabytes a second time.
    """
    return cache_dir if cache_dir.name == _NAME else cache_dir / _NAME


def _keep_member(name: str, upstream: _Upstream) -> tuple[str, bool] | None:
    """Map an archive member to ``(path inside the cache, is provenance)``.

    Members are filtered by hand rather than handed to ``TarFile.extractall``.
    These tarballs are trusted in practice, but an archive member is
    attacker-controlled data in principle — absolute paths, ``..`` segments and
    symlinks are all expressible in tar — and the cheap defence is never to let
    the archive choose a filename on the filesystem.
    """
    parts = Path(name).parts
    if len(parts) < 2:
        return None
    # Drop the archive's single root directory ("car-master/" and friends).
    relative = Path(*parts[1:])
    if relative.is_absolute() or ".." in relative.parts:
        return None
    posix = relative.as_posix()

    if posix in upstream.provenance:
        return posix, True

    suffix = relative.suffix.lower()
    for prefix, suffixes in upstream.keep:
        if suffix not in suffixes:
            continue
        if prefix.endswith("/"):
            if posix.startswith(prefix):
                return posix, False
        elif posix == prefix:
            return posix, False
    return None


def _extract(archive: Path, staging: Path, upstream: _Upstream) -> int:
    """Unpack one upstream's kept files into ``staging``; return the count."""
    staging.mkdir(parents=True, exist_ok=True)
    resolved = staging.resolve()
    written = 0
    oversize = 0

    try:
        with tarfile.open(archive, mode="r:gz") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                decided = _keep_member(member.name, upstream)
                if decided is None:
                    continue
                target_name, is_provenance = decided
                if member.size > _MAX_MEMBER_BYTES:
                    oversize += 1
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
                if not is_provenance:
                    written += 1
    except (tarfile.TarError, OSError) as exc:
        raise SourceError(
            f"{_NAME}: could not unpack {upstream.repo}: {exc}"
        ) from exc

    if oversize:
        print(f"   {_NAME}: skipped {oversize} member(s) of {upstream.repo} "
              f"over the {_MAX_MEMBER_BYTES:,} byte member ceiling")
    if written < upstream.min_files:
        raise SourceError(
            f"{_NAME}: only {written} file(s) extracted from {upstream.repo} "
            f"(expected at least {upstream.min_files}; {upstream.observed_files} "
            "were present when this adapter was written). The upstream layout "
            "has probably changed — fix the keep table rather than training on "
            "a fragment of it."
        )
    return written


def _fetch_one(root: Path, upstream: _Upstream) -> None:
    """Populate ``root/<key>/`` from a codeload tarball, idempotently.

    A tarball rather than ``git clone --depth 1``: one request instead of a
    process, no git binary needed, no history, and no ``.git`` that a later
    ``git pull`` could mutate underneath a reproducible build. Two of these
    repositories are twenty and twenty-seven megabytes of screenshots and
    recorded datasets and yield a few hundred kilobytes of text, which is an
    unhappy ratio but still one request.

    The staging tree is swapped into place only once extraction has finished,
    and the completion marker is written after that — so an interrupted fetch
    re-fetches instead of leaving a partial tree that a later run reads as
    complete.
    """
    dest = root / upstream.key
    marker = dest / _MARKER
    if marker.is_file() and dest.is_dir():
        return

    archive = root / f".{upstream.key}.tar.gz"
    staging = root / f".{upstream.key}.staging"
    shutil.rmtree(staging, ignore_errors=True)
    url = _CODELOAD.format(repo=upstream.repo, ref=upstream.ref)
    try:
        try:
            download(url, archive, timeout=300)
        except NetworkError as exc:
            raise SourceError(f"{_NAME}: could not fetch {url}: {exc}") from exc
        written = _extract(archive, staging, upstream)

        shutil.rmtree(dest, ignore_errors=True)
        dest.parent.mkdir(parents=True, exist_ok=True)
        staging.replace(dest)
        marker.write_text(
            json.dumps(
                {
                    "url": url,
                    "repo": upstream.repo,
                    "ref": upstream.ref,
                    "files": written,
                    "license": upstream.license_note,
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
    """Populate the cache with all four upstreams; return the root."""
    root = _root(cache_dir)
    root.mkdir(parents=True, exist_ok=True)
    for upstream in _UPSTREAMS:
        _fetch_one(root, upstream)
    return root


# ---------------------------------------------------------------------------
# shared rendering helpers
# ---------------------------------------------------------------------------

def _walk(base: Path, *suffixes: str) -> list[Path]:
    """Every regular file under ``base`` with one of ``suffixes``, sorted.

    ``os.walk(followlinks=False)`` rather than ``Path.rglob``: a source in this
    package once followed a symlink out of its own tree and pulled 180 MB of the
    corpus cache back in as training data. ``followlinks=False`` stops the walk
    descending a symlinked directory, and the explicit ``is_symlink`` test
    catches the other half, which it does not — a symlinked *file* is still
    listed among the filenames.
    """
    found: list[Path] = []
    wanted = tuple(s.lower() for s in suffixes)
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.is_symlink() or not path.is_file():
                continue
            if wanted and path.suffix.lower() not in wanted:
                continue
            found.append(path)
    return sorted(found)


def _read(path: Path) -> str:
    """Decode a cached file, or raise with the path that failed."""
    try:
        return path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise SourceError(f"{_NAME}: cannot read {path}: {exc}") from exc


def _load_yaml(path: Path) -> dict:
    """Parse one cached YAML file into a mapping, or raise."""
    try:
        parsed = yaml.load(_read(path), Loader=_Loader)
    except yaml.YAMLError as exc:
        raise SourceError(f"{_NAME}: {path} is not parseable YAML: {exc}") from exc
    if not isinstance(parsed, dict):
        raise SourceError(f"{_NAME}: {path} is not a YAML mapping")
    return parsed


def _section(title: str, body: list[str]) -> list[str]:
    """A titled section, or nothing at all when there is nothing to put in it.

    The blank filter is load-bearing, not belt-and-braces: several call sites
    pass ``[_clean(entry.get("description"))]`` straight through, and a list
    holding one empty string is still a truthy list. Without it a missing
    description emits a bare ``## Description`` header with the next header
    directly under it, which teaches that a heading can be followed by nothing.
    """
    kept = [line for line in body if line.strip()]
    return ["", f"## {title}", "", *kept] if kept else []


def _bullet(text: str, marker: str = "- ", indent: str = "  ") -> str:
    """One list item, continuation lines indented under the marker.

    CAR descriptions and Playbook analytics routinely run to several paragraphs
    plus a code block. Flush-left continuations leave no way — for a reader or
    for a model — to tell where one item ends and the next begins.
    """
    first, _, rest = text.partition("\n")
    if not rest:
        return marker + first
    tail = "\n".join((indent + line if line else "") for line in rest.split("\n"))
    return f"{marker}{first}\n{tail}"


def _join(values: object) -> str:
    """A scalar or a list of scalars as one comma-separated line."""
    if values is None:
        return ""
    if isinstance(values, (list, tuple)):
        return ", ".join(str(v).strip() for v in values if str(v).strip())
    return str(values).strip()


def _labelled(lines: list[str], label: str, value: object) -> None:
    """Append ``label: value`` when there is a value to append."""
    text = _join(value)
    if text:
        lines.append(f"{label}: {text}")


#: The leading run of a cp1252-rendered UTF-8 sequence, plus one or two more
#: characters. Deliberately anchored on the three lead characters that actually
#: occur (``Â``, ``Ã``, ``â``) rather than the full C2-F4 range, and every match
#: is still checked by :func:`_demojibake` before it is accepted.
_MOJIBAKE = re.compile("[ÂÃâ][^\\s]{1,2}")


def _demojibake(text: str) -> tuple[str, int]:
    """Repair UTF-8 that was once decoded as cp1252; count the repairs.

    Seven occurrences across five Threat Hunter Playbook files: four em dashes,
    two registered signs, one right single quote. Small enough to hand-code, and
    hand-coding is exactly what should not be done — the next upstream refresh
    would bring an eighth spelling nobody has a table entry for.

    The rule instead is that a candidate run is re-encoded as cp1252 and decoded
    as UTF-8, and the result is accepted **only if both steps succeed**. That
    self-validation is what keeps it narrow: real Latin-1 text in an English
    security document almost never re-decodes as valid UTF-8, and when it does
    not, the original is kept untouched. Running the same round trip over the
    whole document instead — the obvious one-liner — throws on the first
    character cp1252 cannot represent and silently mangles accented names
    everywhere else.
    """
    repairs = 0

    def fix(match: re.Match[str]) -> str:
        nonlocal repairs
        try:
            fixed = match.group(0).encode("cp1252").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            return match.group(0)
        repairs += 1
        return fixed

    return _MOJIBAKE.sub(fix, text), repairs


# ---------------------------------------------------------------------------
# ATT&CK identifiers
# ---------------------------------------------------------------------------

#: Enterprise tactic id to name. CAR and the Playbook both store tactics as bare
#: ``TA0005`` with no name anywhere in the file, and a naked identifier beside
#: nothing is worth very little to a tokenizer — the measurement this corpus was
#: rebuilt around found that ``T1547.001`` *beside its human name* moved a
#: sample from -45% to +13% against gpt2, and the id alone did not.
#:
#: Hardcoded because the alternative is making this adapter depend on the
#: attack source's 40 MB STIX bundle to look up fourteen strings. The enterprise
#: tactic list has been stable since 2020 and only ever grows; an id that is not
#: here renders as the bare id rather than as a wrong name.
_TACTICS = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
    "TA0042": "Resource Development",
    "TA0043": "Reconnaissance",
}

_TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def _tactic(raw: object) -> str:
    """``TA0005 Defense Evasion`` — the id next to what it denotes."""
    ident = str(raw or "").strip().upper()
    name = _TACTICS.get(ident, "")
    return f"{ident} {name}".strip()


def _technique_url(ident: str) -> str:
    """The ATT&CK URL for a technique id, sub-technique split on the path.

    The same id in a second syntactic position, which is the shape of exposure
    the tokenizer measurement rewarded and which the sibling adapters render the
    same way.
    """
    return "https://attack.mitre.org/techniques/" + ident.replace(".", "/")


# ---------------------------------------------------------------------------
# MITRE CAR
# ---------------------------------------------------------------------------

#: CAR writes its implementation ``type`` four ways for two languages:
#: ``pseudocode`` (49), ``Pseudocode`` (45), ``psuedocode`` (1 — a typo
#: upstream), ``Splunk`` (60) and ``splunk`` (22). Case-folding handles most of
#: it; the typo needs a table entry, and it is exactly the kind of thing that
#: silently halves a field if matched on equality. Counted and printed.
_IMPL_TYPES = {
    "pseudocode": "pseudocode",
    "psuedocode": "pseudocode",
    "splunk": "Splunk",
    "logpoint": "LogPoint",
    "dnif": "DNIF",
    "eql": "EQL",
    "elastic": "Elastic",
    "sigma": "Sigma",
}

_CAR_URL = "https://car.mitre.org/analytics/{ident}"


def _impl_type(raw: object) -> tuple[str, bool]:
    """``(canonical name, was it a misspelling)`` for an implementation type."""
    text = str(raw or "").strip()
    folded = text.casefold()
    canonical = _IMPL_TYPES.get(folded)
    if canonical is None:
        return text or "unspecified", False
    return canonical, folded == "psuedocode"


def _car_analytic(data: dict, ident: str) -> tuple[str, int]:
    """One CAR analytic, rendered as labelled sections. Returns (text, typos)."""
    title = str(data.get("title") or "").strip()
    lines = [
        f"{ident} {title}".strip(),
        "",
        f"CAR ID: {ident}",
        f"Name: {title}",
        "Entry type: CAR analytic",
    ]
    _labelled(lines, "Information domain", data.get("information_domain"))
    _labelled(lines, "Platforms", data.get("platforms"))
    _labelled(lines, "Subtypes", data.get("subtypes"))
    _labelled(lines, "Analytic types", data.get("analytic_types"))
    _labelled(lines, "Contributors", data.get("contributors"))
    _labelled(lines, "Submitted", data.get("submission_date"))
    lines.append(f"URL: {_CAR_URL.format(ident=ident)}")

    lines += _section("Description", [str(data.get("description") or "").strip()])

    coverage: list[str] = []
    for entry in data.get("coverage") or []:
        if not isinstance(entry, dict):
            continue
        technique = str(entry.get("technique") or "").strip()
        if not technique:
            continue
        level = str(entry.get("coverage") or "").strip()
        tactics = ", ".join(_tactic(t) for t in (entry.get("tactics") or []))
        head = f"{technique} ({_technique_url(technique)})"
        if level:
            head += f" — coverage {level}"
        body = f"\nTactics: {tactics}" if tactics else ""
        coverage.append(_bullet(head + body))
    lines += _section("ATT&CK Coverage", coverage)

    lines += _section("Data Model References", [
        _bullet(str(reference).strip())
        for reference in data.get("data_model_references") or []
        if str(reference).strip()
    ])

    typos = 0
    implementations: list[str] = []
    for number, entry in enumerate(data.get("implementations") or [], start=1):
        if not isinstance(entry, dict):
            continue
        kind, mistyped = _impl_type(entry.get("type"))
        typos += int(mistyped)
        block = [f"### Implementation {number} — {kind}"]
        description = str(entry.get("description") or "").strip()
        if description:
            block.append(description)
        _labelled(block, "Data model", entry.get("data_model"))
        code = str(entry.get("code") or "").rstrip()
        if code:
            block.append("")
            block.append(code)
        implementations.append("\n".join(block))
    lines += _section("Implementations", ["\n\n".join(implementations)])

    tests: list[str] = []
    for entry in data.get("unit_tests") or []:
        if not isinstance(entry, dict):
            continue
        block: list[str] = []
        _labelled(block, "Configurations", entry.get("configurations"))
        description = str(entry.get("description") or "").strip()
        if description:
            block.append(description)
        commands = [str(c) for c in (entry.get("commands") or []) if str(c).strip()]
        if commands:
            block.append("Commands:")
            block.extend(commands)
        if block:
            tests.append(_bullet("\n".join(block)))
    lines += _section("Unit Tests", tests)

    lines += _section("D3FEND Mappings", [
        _bullet(f"{str(entry.get('id') or '').strip()} "
                f"{str(entry.get('label') or '').strip()}".strip())
        for entry in data.get("d3fend_mappings") or []
        if isinstance(entry, dict) and (entry.get("id") or entry.get("label"))
    ])

    return "\n".join(lines), typos


def _car_data_model(data: dict, ident: str) -> str:
    """One CAR data model object: its actions, its fields, and the join form."""
    name = str(data.get("name") or ident).strip()
    lines = [
        f"CAR data model: {name}",
        "",
        f"Object: {ident}",
        f"Name: {name}",
        "Entry type: CAR data model object",
        f"URL: https://car.mitre.org/data_model/{ident}",
    ]
    description = str(data.get("description") or "").strip()
    if description:
        lines.append(f"Description: {description}")

    lines += _section("Actions", [
        _bullet(f"{str(action.get('name') or '').strip()}: "
                f"{str(action.get('description') or '').strip()}")
        for action in data.get("actions") or []
        if isinstance(action, dict) and str(action.get("name") or "").strip()
    ])

    fields: list[str] = []
    for field in data.get("fields") or []:
        if not isinstance(field, dict):
            continue
        field_name = str(field.get("name") or "").strip()
        if not field_name:
            continue
        body = f"{field_name}: {str(field.get('description') or '').strip()}"
        example = str(field.get("example") or "").strip()
        if example:
            body += f"\nExample: {example}"
        fields.append(_bullet(body))
    lines += _section("Fields", fields)

    # Stated once rather than as a cross product of actions and fields: an
    # analytic's data_model_references are written object/action/field, and
    # without this line the two halves above never meet the syntax that joins
    # them to every analytic in the catalogue.
    actions = [str(a.get("name") or "").strip()
               for a in (data.get("actions") or []) if isinstance(a, dict)]
    if actions and fields:
        first_field = str((data.get("fields") or [{}])[0].get("name") or "").strip()
        lines += _section("Reference Form", [
            f"Analytics cite this object as {ident}/<action>/<field>, for "
            f"example {ident}/{actions[0]}/{first_field}.",
            f"Actions: {', '.join(actions)}",
        ])
    return "\n".join(lines)


def _car_sensor(data: dict, ident: str) -> str:
    """One CAR sensor: which data model pairs it reports, and with what fields.

    The rarest thing in this source. A hunt that finds nothing has two
    explanations and they are not distinguishable from the result alone; this
    table is the one that resolves them, per sensor and per version.
    """
    name = str(data.get("sensor_name") or "").strip()
    version = str(data.get("sensor_version") or "").strip()
    lines = [
        f"CAR sensor coverage: {name} {version}".strip(),
        "",
        f"Sensor: {name}",
        f"Version: {version}",
        "Entry type: CAR sensor mapping",
    ]
    _labelled(lines, "Developer", data.get("sensor_developer"))
    _labelled(lines, "Sensor URL", data.get("sensor_url"))
    description = str(data.get("sensor_description") or "").strip()
    if description:
        lines.append(f"Description: {description}")

    mappings: list[str] = []
    for entry in data.get("mappings") or []:
        if not isinstance(entry, dict):
            continue
        obj = str(entry.get("object") or "").strip()
        action = str(entry.get("action") or "").strip()
        if not obj or not action:
            continue
        body = f"{obj}/{action}"
        notes = str(entry.get("notes") or "").strip()
        if notes:
            body += f" — {notes}"
        fields = _join(entry.get("fields"))
        if fields:
            body += f"\nFields: {fields}"
        mappings.append(_bullet(body))
    lines += _section(
        "Data model coverage (object/action pairs this sensor reports, "
        "and the fields it carries for each)",
        mappings,
    )
    lines.append("")
    lines.append(f"Reported pairs: {len(mappings)}. A CAR data model "
                 f"object/action pair that does not appear above is not "
                 f"collected by {name} {version}.".rstrip())
    return "\n".join(lines)


def _car_documents(base: Path) -> Iterator[Document]:
    """Analytics, then data model objects, then sensors, then the glossary."""
    typos = 0

    for path in _walk(base / "analytics", ".yaml"):
        data = _load_yaml(path)
        ident = str(data.get("id") or path.stem).strip()
        rendered, mistyped = _car_analytic(data, ident)
        typos += mistyped
        text = normalise(rendered)
        if len(text) < _MIN_CHARS:
            continue
        yield Document(text=text, source=_NAME, register=Register.PROSE,
                       side=Side.BLUE, ident=f"car/{ident}")

    for path in _walk(base / "data_model", ".yaml"):
        text = normalise(_car_data_model(_load_yaml(path), path.stem))
        if len(text) < _MIN_CHARS:
            continue
        yield Document(text=text, source=_NAME, register=Register.PROSE,
                       side=Side.BLUE, ident=f"car/data_model/{path.stem}")

    for path in _walk(base / "sensors", ".yaml"):
        text = normalise(_car_sensor(_load_yaml(path), path.stem))
        if len(text) < _MIN_CHARS:
            continue
        yield Document(text=text, source=_NAME, register=Register.PROSE,
                       side=Side.BLUE, ident=f"car/sensors/{path.stem}")

    glossary = base / "GLOSSARY.md"
    if glossary.is_file():
        body, _ = _markdown_to_text(_read(glossary))
        text = normalise("CAR glossary: the vocabulary of an analytic\n\n" + body)
        if len(text) >= _MIN_CHARS:
            yield Document(text=text, source=_NAME, register=Register.PROSE,
                           side=Side.BLUE, ident="car/GLOSSARY")

    if typos:
        print(f"   {_NAME}: corrected {typos} misspelled CAR implementation "
              "type(s) ('psuedocode')")


# ---------------------------------------------------------------------------
# Markdown (Threat Hunter Playbook, ADS, CAR glossary)
# ---------------------------------------------------------------------------

_FENCE = re.compile(r"^(\s*)(`{3,}|~{3,})\s*(\S.*)?$")
_HEADING = re.compile(r"^(#{1,6})\s+(.*)$")
#: A line that is nothing but images or image links — a badge row, a figure the
#: cache does not contain. Matched after every such construct is removed.
_IMAGE = re.compile(r"\[!\[[^\]]*\]\([^)]*\)\]\([^)]*\)|!\[[^\]]*\]\([^)]*\)")


def _strip_front_matter(lines: list[str]) -> list[str]:
    """Drop a leading ``---`` YAML block.

    Every Playbook page carries fourteen lines of jupytext and kernelspec
    configuration that say which Python kernel to start. Repeated verbatim
    across 28 files, it is the kind of text a small corpus memorises, and it
    describes a notebook runtime rather than a hunt.
    """
    if not lines or lines[0].strip() != "---":
        return lines
    for index in range(1, len(lines)):
        if lines[index].strip() == "---":
            return lines[index + 1:]
    return lines


def _drop_code_cells(lines: list[str]) -> tuple[list[str], int]:
    """Remove ```` ```{code-cell} ```` blocks, keeping every other fence intact.

    All fences are tracked, not just the ones being dropped, because a fenced
    block may legitimately contain a line that looks like a fence opener and a
    scanner that only watches for its own target will resume in the middle of
    somebody else's code.
    """
    out: list[str] = []
    dropped = 0
    index = 0
    total = len(lines)
    while index < total:
        opener = _FENCE.match(lines[index])
        if opener:
            info = opener.group(3) or ""
            marker, width = opener.group(2)[0], len(opener.group(2))
            block = [lines[index]]
            index += 1
            while index < total:
                closer = _FENCE.match(lines[index])
                block.append(lines[index])
                index += 1
                if (closer and closer.group(2)[0] == marker
                        and len(closer.group(2)) >= width
                        and not (closer.group(3) or "").strip()):
                    break
            if info.lstrip().startswith("{code-cell}"):
                dropped += 1
            else:
                out.extend(block)
            continue
        out.append(lines[index])
        index += 1
    return out, dropped


def _prune_empty_headings(lines: list[str]) -> list[str]:
    """Drop headings that now stand over nothing.

    Subtree aware on purpose. The naive test — is the text between this heading
    and the next one empty — deletes every parent whose content lives under its
    own sub-headings, which here is most of them. The span checked instead runs
    to the next heading of the *same or shallower* level, so ``## Analytics``
    survives on the strength of what is under ``### Analytic I`` while
    ``### Download Dataset``, whose only child was a code cell that has just
    been removed, does not.
    """
    heads = [(index, len(match.group(1)))
             for index, line in enumerate(lines)
             if (match := _HEADING.match(line))]
    drop: set[int] = set()
    for position, (index, level) in enumerate(heads):
        end = len(lines)
        for other_index, other_level in heads[position + 1:]:
            if other_level <= level:
                end = other_index
                break
        body = [line for line in lines[index + 1:end]
                if line.strip() and not _HEADING.match(line)]
        if not body:
            drop.add(index)
    return [line for index, line in enumerate(lines) if index not in drop]


def _markdown_to_text(raw: str) -> tuple[str, int]:
    """Clean one markdown page. Returns ``(text, mojibake repairs)``.

    Horizontal whitespace is never touched — indentation inside the surviving
    code blocks is the shape of the query, and a Playbook analytic's SQL is
    indented three levels deep.
    """
    fixed, repairs = _demojibake(raw.replace("\r\n", "\n").replace("\r", "\n"))
    lines = _strip_front_matter(fixed.split("\n"))
    lines, _ = _drop_code_cells(lines)
    lines = [line for line in lines
             if _IMAGE.sub("", line).strip() or not _IMAGE.search(line)]
    lines = _prune_empty_headings(lines)
    return "\n".join(lines), repairs


# ---------------------------------------------------------------------------
# Threat Hunter Playbook
# ---------------------------------------------------------------------------

def _thp_hunt(meta: dict, body: str, ident: str) -> str:
    """One hunt: its metadata header, then the notebook prose.

    The hypothesis is lifted out of ``metadata.yaml`` and stated in the header
    as well as appearing in the body, because it is the one sentence that says
    what the rest of the document is for.
    """
    title = str(meta.get("title") or "").strip()
    lines = [
        f"Threat hunt {ident}: {title}".strip(),
        "",
        f"Hunt ID: {ident}",
        f"Name: {title}",
        "Entry type: threat hunt playbook",
    ]
    _labelled(lines, "Platform", meta.get("platform"))
    _labelled(lines, "Contributors", meta.get("collaborators"))
    _labelled(lines, "Created", meta.get("creation_date"))
    _labelled(lines, "Modified", meta.get("modification_date"))

    mappings: list[str] = []
    for entry in meta.get("attack_mappings") or []:
        if not isinstance(entry, dict):
            continue
        technique = str(entry.get("technique") or "").strip()
        if not _TECHNIQUE.match(technique):
            continue
        sub = str(entry.get("sub_technique") or "").strip()
        if sub and sub.lower() not in ("none", "null"):
            technique = f"{technique}.{sub}"
        tactics = ", ".join(_tactic(t) for t in (entry.get("tactics") or []))
        line = f"{technique} ({_technique_url(technique)})"
        if tactics:
            line += f" — tactics: {tactics}"
        mappings.append(line)
    if mappings:
        lines.append("ATT&CK: " + "; ".join(mappings))

    # 23 of the 26 hunts open their notebook with a `## Hypothesis` section
    # holding this exact sentence, so stating it in the header as well would
    # duplicate a sentence inside its own document 23 times over. It is lifted
    # up only for the three that do not, where it is the one line saying what
    # the rest of the page is for.
    hypothesis = str(meta.get("hypothesis") or "").strip()
    if hypothesis and hypothesis not in body:
        lines += ["", f"Hypothesis: {hypothesis}"]

    datasets = [
        f"{str(entry.get('name') or '').strip()}: "
        f"{str(entry.get('docs') or entry.get('dataset') or '').strip()}"
        for entry in meta.get("datasets") or []
        if isinstance(entry, dict)
    ]
    lines += _section("Validation Datasets", [_bullet(d) for d in datasets if d.strip(": ")])

    lines += ["", body]
    return "\n".join(lines)


def _thp_documents(base: Path) -> Iterator[tuple[Document, int, int]]:
    """Hunts, then the Windows internals library, then the pre-hunt pages.

    Yields ``(document, code cells dropped, mojibake repairs)`` so the caller can
    report both totals once rather than printing per file.
    """
    hunts = base / "docs" / "hunts"
    for notebook in _walk(hunts, ".md"):
        # A hunt is a directory holding notebook.md beside metadata.yaml, and
        # requiring the pair is also what drops hunts/windows/intro.md — an
        # ATT&CK Navigator <iframe> and a pandas call that renders a clickable
        # index of the hunts. Page chrome, and the only .md under hunts/ that
        # is not one.
        meta_path = notebook.parent / "metadata.yaml"
        if not meta_path.is_file():
            continue
        meta = _load_yaml(meta_path)
        ident = str(meta.get("id") or notebook.parent.name).strip()
        raw = _read(notebook).replace("\r\n", "\n").replace("\r", "\n")
        fixed, repairs = _demojibake(raw)
        lines = _strip_front_matter(fixed.split("\n"))
        lines, cells = _drop_code_cells(lines)
        lines = [line for line in lines
                 if _IMAGE.sub("", line).strip() or not _IMAGE.search(line)]
        body = "\n".join(_prune_empty_headings(lines))
        text = normalise(_thp_hunt(meta, body, ident))
        if len(text) < _MIN_CHARS:
            continue
        yield (Document(text=text, source=_NAME, register=Register.PROSE,
                        side=Side.BLUE, ident=f"thp/hunts/{ident}"),
               cells, repairs)

    for folder, label in (("library", "Platform internals for hunters"),
                          ("pre-hunt", "Pre-hunt data preparation")):
        root = base / "docs" / folder
        for path in _walk(root, ".md"):
            # The library is organised one directory per platform, and a file
            # sitting loose at its root is a leftover. There is exactly one:
            # library/task_scheduler_service.md, a stale copy of
            # library/windows/task_scheduler_service.md that differs from it in
            # a single character — an EventID description reading "Task
            # Rergistration Updated" that was fixed in the version under
            # windows/. Fifteen kilobytes of duplicate text that the build's
            # fingerprint dedup cannot catch, because one typo is enough to make
            # the two documents distinct.
            if folder == "library" and path.parent == root:
                continue
            body, repairs = _markdown_to_text(_read(path))
            text = normalise(f"Threat Hunter Playbook — {label}\n\n{body}")
            if len(text) < _MIN_CHARS:
                continue
            relative = path.relative_to(base / "docs").as_posix()
            yield (Document(text=text, source=_NAME, register=Register.PROSE,
                            side=Side.BLUE, ident=f"thp/{relative}"),
                   0, repairs)

    intro = base / "docs" / "intro.md"
    if intro.is_file():
        body, repairs = _markdown_to_text(_read(intro))
        text = normalise("Threat Hunter Playbook — introduction\n\n" + body)
        if len(text) >= _MIN_CHARS:
            yield (Document(text=text, source=_NAME, register=Register.PROSE,
                            side=Side.BLUE, ident="thp/intro"),
                   0, repairs)


# ---------------------------------------------------------------------------
# Summiting the Pyramid (reStructuredText)
# ---------------------------------------------------------------------------

_RST_DIRECTIVE = re.compile(r"^(\s*)\.\.\s+([A-Za-z0-9_-]+)::\s*(.*)$")
_RST_FOOTNOTE = re.compile(r"^(\s*)\.\.\s+(\[[^\]]+\])\s+(.*)$")
_RST_HYPERLINK = re.compile(r"^\s*\.\.\s+_([^:]+):\s+(\S+)\s*$")
_RST_TARGET = re.compile(r"^\s*\.\.\s+_[^:]*:\s*$")
_RST_COMMENT = re.compile(r"^(\s*)\.\.(\s|$)")
_RST_OPTION = re.compile(r"^\s*:[A-Za-z][A-Za-z0-9_-]*:")
_RST_LINK = re.compile(r"`([^`<]+?)\s*<([^>]+)>`__?")
_RST_ROLE = re.compile(r":(?:ref|doc|term|abbr|mod|class):`([^`]*)`")
#: An rst *line block* continuation: a leading ``|`` that forces a line break
#: and is not part of the text. Told apart from a grid-table row, which also
#: starts with ``|``, by the trailing delimiter a table row has and a line block
#: does not — 201 line blocks unwrap under that rule across Summiting the
#: Pyramid and all 232 grid-table rows are left alone. The distinction matters:
#: the tables here are the scoring model, and their alignment is the document.
_RST_LINE_BLOCK = re.compile(r"^(\s*)\|(\s|$)")

#: A run of one repeated adornment character. Which construct it is depends
#: entirely on what precedes it: under a line of text it underlines a section
#: title, and after a blank line it is a transition — a horizontal rule, which
#: renders here as a row of punctuation carrying no information at all.
_RST_ADORNMENT = re.compile(r"^([=\-~^\"'`:.*+#_])\1{3,}\s*$")

#: Directives whose entire block goes. Every one of them points at something the
#: cache does not hold (a PNG, a raw HTML fragment) or is navigation rather than
#: content (``toctree`` twelve times over).
_RST_DROP = frozenset({"figure", "image", "toctree", "raw", "contents",
                       "only", "meta"})

#: Directives whose body is kept, mapped to what replaces the directive line.
#: ``{arg}`` is the directive's argument — the title of a table, the text of a
#: rubric. An empty string drops the line and keeps the body, which is right for
#: ``code-block`` (whose argument is a language name) and ``epigraph``.
_RST_KEEP = {
    "note": "Note:",
    "important": "Important:",
    "warning": "Warning:",
    "tip": "Tip:",
    "rubric": "{arg}",
    "admonition": "{arg}",
    "code-block": "",
    "epigraph": "",
    "list-table": "{arg}",
    "table": "{arg}",
    "csv-table": "{arg}",
}


def _rst_block_end(lines: list[str], start: int, indent: int) -> int:
    """Index one past a directive body: blank lines, or indented deeper."""
    index = start
    while index < len(lines):
        line = lines[index]
        if not line.strip():
            index += 1
            continue
        if len(line) - len(line.lstrip()) > indent:
            index += 1
            continue
        break
    return index


def _drop_transitions(lines: list[str]) -> list[str]:
    """Drop rst transitions and unwrap line blocks; keep underlines and tables.

    The two are the same characters and are told apart only by context: an
    adornment run under a line of text underlines that text and is how a section
    heading is spelled, while one after a blank line is a horizontal rule. The
    anchor also insists on column zero, because a transition is a top-level
    construct and everything indented is inside a directive body — which for
    ``code-block`` is somebody's YAML, where a row of dashes may well be content.
    """
    kept: list[str] = []
    for line in lines:
        if _RST_ADORNMENT.match(line) and not (kept and kept[-1].strip()):
            continue
        match = _RST_LINE_BLOCK.match(line)
        if match and not line.rstrip().endswith("|"):
            # Unwrap the line block, keeping its indentation: the marker is a
            # rendering instruction, the two spaces after it are the author's
            # own nesting inside a table cell.
            line = match.group(1) + line[match.end(1) + 1:].lstrip(" ")
        kept.append(line)
    return kept


def _rst_to_text(raw: str) -> str:
    """Render reStructuredText as plain text, keeping structure and tables.

    Section underlines, grid tables and list-table bodies are left exactly as
    written — the alignment is the table, and the contract forbids collapsing
    horizontal whitespace for precisely this reason. What goes is markup that
    points outside the cache: figures and their captions, raw HTML, toctrees,
    and internal anchor targets. Inline hyperlinks become ``text (url)`` so the
    URL survives in the same syntactic position the rest of the corpus writes
    it.
    """
    lines = raw.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    out: list[str] = []
    index = 0
    total = len(lines)

    while index < total:
        line = lines[index]

        footnote = _RST_FOOTNOTE.match(line)
        if footnote:
            out.append(f"{footnote.group(1)}{footnote.group(2)} {footnote.group(3)}")
            index += 1
            continue

        hyperlink = _RST_HYPERLINK.match(line)
        if hyperlink:
            out.append(f"{hyperlink.group(1)}: {hyperlink.group(2)}")
            index += 1
            continue

        directive = _RST_DIRECTIVE.match(line)
        if directive:
            indent, name, argument = (directive.group(1),
                                      directive.group(2).lower(),
                                      directive.group(3).strip())
            end = _rst_block_end(lines, index + 1, len(indent))
            if name in _RST_DROP:
                index = end
                continue
            template = _RST_KEEP.get(name)
            head = template.format(arg=argument).strip() if template is not None else argument
            if head:
                out.append(indent + head)
            body = index + 1
            # Option lines belong to the directive, not to the prose under it,
            # and they stop at the first blank line.
            while body < end and _RST_OPTION.match(lines[body]):
                body += 1
            out.extend(lines[body:end])
            index = end
            continue

        if _RST_TARGET.match(line):
            index += 1
            continue

        if _RST_COMMENT.match(line):
            comment_indent = len(line) - len(line.lstrip())
            index = _rst_block_end(lines, index + 1, comment_indent)
            continue

        out.append(line)
        index += 1

    text = "\n".join(_drop_transitions(out))
    text = _RST_LINK.sub(lambda m: f"{' '.join(m.group(1).split())} ({m.group(2)})", text)
    text = _RST_ROLE.sub(r"\1", text)
    return text


def _stp_scored_analytics(path: Path) -> str:
    """The scored-analytics CSV as one document of ninety-two judgements.

    The scores are shorthand and the ``Notes`` column is the content: a sentence
    per analytic saying why it scored where it did, which is the only place in
    this corpus where a published detection is criticised by name.
    """
    # The snapshot token is printed as upstream wrote it. ScoredAnalytics_
    # 12062024 and ScoredAnalytics_05062025 are both day-06, so the file names
    # themselves do not say whether the format is DDMMYYYY or MMDDYYYY, and
    # inventing a date from an ambiguous filename is how a corpus acquires a
    # fact nobody checked.
    lines = [
        f"Summiting the Pyramid: scored analytics (snapshot {path.stem.split('_')[-1]})",
        "",
        "Entry type: detection engineering robustness scoring",
        "Each entry is a published detection analytic scored for robustness "
        "against adversary evasion, with the reviewer's note on why.",
        "",
    ]
    rows = 0
    try:
        reader = csv.DictReader(io.StringIO(
            path.read_bytes().decode("utf-8-sig")))
        for row in reader:
            name = (row.get("Name") or "").strip()
            if not name:
                continue
            body = [name]
            for column, label in (("Analytic Robustness Score", "Analytic robustness"),
                                  ("Event Robustness Score", "Event robustness"),
                                  ("Filter Score", "Filter"),
                                  ("Final Score", "Final score")):
                value = (row.get(column) or "").strip()
                if value:
                    body.append(f"{label}: {value}")
            notes = " ".join((row.get("Notes") or "").split())
            if notes:
                body.append(f"Notes: {notes}")
            permalink = (row.get("Permalink") or "").strip()
            if permalink:
                body.append(f"Analytic source: {permalink}")
            lines.append(_bullet("\n".join(body)))
            rows += 1
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        raise SourceError(f"{_NAME}: cannot read {path}: {exc}") from exc
    lines.insert(4, f"Analytics scored: {rows}")
    return "\n".join(lines)


_SNAPSHOT = re.compile(r"_(\d{4})(\d{4})$")


def _snapshot_key(path: Path) -> tuple[int, int, str]:
    """Sort key that puts the most recent ``ScoredAnalytics_`` snapshot last.

    Sorting on the filename is the obvious answer and it picks the wrong file.
    The two snapshots are ``ScoredAnalytics_12062024`` and
    ``ScoredAnalytics_05062025``, and string order puts ``12…`` above ``05…`` —
    so the December 2024 scoring wins over the June 2025 one. Only the last four
    digits are unambiguous, whichever way round the day and month go, so the
    year is what this sorts on, with the leading four digits as a tiebreak.
    """
    match = _SNAPSHOT.search(path.stem)
    if not match:
        return (0, 0, path.stem)
    return (int(match.group(2)), int(match.group(1)), path.stem)


def _stp_documents(base: Path) -> Iterator[Document]:
    """Every methodology page, then the newest scored-analytics CSV.

    Only the newest CSV. Upstream keeps two snapshots of the same scoring
    exercise six months apart, and they are largely the same analytics with the
    same notes — near-duplicate text that the build's fingerprint dedup cannot
    collapse, because it compares whole documents and these differ in a handful
    of rows.
    """
    for path in _walk(base / "docs", ".rst"):
        text = normalise(_rst_to_text(_read(path)))
        if len(text) < _MIN_CHARS:
            continue
        relative = path.relative_to(base / "docs").as_posix()
        yield Document(text=text, source=_NAME, register=Register.PROSE,
                       side=Side.BLUE, ident=f"stp/{relative}")

    scored = _walk(base / "docs" / "analytics", ".csv")
    if scored:
        newest = max(scored, key=_snapshot_key)
        text = normalise(_stp_scored_analytics(newest))
        if len(text) >= _MIN_CHARS:
            yield Document(text=text, source=_NAME, register=Register.PROSE,
                           side=Side.BLUE, ident=f"stp/analytics/{newest.stem}")


# ---------------------------------------------------------------------------
# Palantir ADS
# ---------------------------------------------------------------------------

#: The nine sections every ADS document must fill, plus the optional tenth.
#: They matter here because a worked example's first heading is ``# Goal`` —
#: the first *section*, not a title — so taking the first H1 as the document's
#: name produces eight documents called "Goal".
_ADS_SECTIONS = frozenset({
    "goal", "categorization", "strategy abstract", "technical context",
    "blind spots and assumptions", "false positives", "validation",
    "priority", "response", "additional resources",
})


def _ads_documents(base: Path) -> Iterator[Document]:
    """The framework document and its worked examples."""
    for path in _walk(base, ".md"):
        body, _ = _markdown_to_text(_read(path))
        heading = next((match.group(2).strip()
                        for line in body.split("\n")
                        if (match := _HEADING.match(line))), "")
        if not heading or heading.casefold() in _ADS_SECTIONS:
            heading = path.stem.replace("-", " ")
        text = normalise(
            f"Palantir Alerting and Detection Strategy: {heading}\n\n{body}"
        )
        if len(text) < _MIN_CHARS:
            continue
        yield Document(text=text, source=_NAME, register=Register.PROSE,
                       side=Side.BLUE, ident=f"ads/{path.stem}")


# ---------------------------------------------------------------------------
# documents
# ---------------------------------------------------------------------------

def _documents(path: Path) -> Iterator[Document]:
    """Yield every upstream in a fixed order, then report what was held back."""
    root = _root(path)
    for upstream in _UPSTREAMS:
        if not (root / upstream.key).is_dir():
            raise SourceError(
                f"{_NAME}: no {upstream.key}/ directory in {root} — run the "
                "source's fetch() first"
            )

    yield from _car_documents(root / "car")

    cells = 0
    repairs = 0
    for document, dropped, fixed in _thp_documents(root / "thp"):
        cells += dropped
        repairs += fixed
        yield document

    yield from _stp_documents(root / "stp")
    yield from _ads_documents(root / "ads")

    # No silent caps: say what was held back and why.
    if cells:
        print(f"   {_NAME}: dropped {cells} Jupyter {{code-cell}} block(s) from "
              "the Threat Hunter Playbook — dataset download/read plumbing and "
              "pandas restatements of the SQL directly above them, near-"
              "identical across every hunt")
    if repairs:
        print(f"   {_NAME}: repaired {repairs} mojibake sequence(s) "
              "(UTF-8 once decoded as cp1252)")


def _composite_license() -> str:
    """Build the declared licence from :data:`_UPSTREAMS`.

    Generated rather than written out, so an upstream cannot be added to the
    table without its terms appearing in the licence ``build.py`` prints and
    ``provenance.json`` records. A hand-written string is a string that drifts.
    """
    return " | ".join(upstream.license_note for upstream in _UPSTREAMS)


SPEC = SourceSpec(
    name=_NAME,
    license=_composite_license(),
    url=" and ".join(f"https://github.com/{u.repo}" for u in _UPSTREAMS),
    register=Register.PROSE,
    side=Side.BLUE,
    fetch=_fetch,
    documents=_documents,
    #: Observed 240 at fetch time, and worth writing out because four upstreams
    #: can lose one quietly: CAR gives 102 analytics + 13 data model objects + 7
    #: sensors + 1 glossary = 123; the Playbook 26 hunts + 13 library pages + 5
    #: pre-hunt pages + 1 introduction = 45; Summiting the Pyramid 63 of its 70
    #: pages (five navigation indexes, a changelog and a publications list fall
    #: under the character floor) + 1 scored-analytics CSV = 64; and ADS 8. The
    #: floor sits well below that so ordinary churn is quiet — and a renamed
    #: directory in any one of the four trips that upstream's own file count at
    #: fetch time first, which says *which* upstream moved instead of leaving a
    #: single thin total to diagnose.
    expect_min_docs=190,
    notes=(
        "Threat hunting and detection engineering methodology from four "
        "upstreams, none of which any other adapter touches. MITRE CAR: "
        "analytics with their hypothesis, CAR pseudocode and the same logic in "
        "Splunk/EQL/LogPoint/DNIF, self-rated ATT&CK coverage, and unit tests "
        "with the commands that make them fire; plus the data model (the field "
        "dictionary a hunt is phrased in) and the sensor mappings, which say "
        "per sensor and version exactly which object/action pairs it reports "
        "— the table that distinguishes 'nothing happened' from 'nothing was "
        "watching'. OTRF Threat Hunter Playbook: 26 hunts structured as "
        "Hypothesis / Technical Context / Offensive Tradecraft / Analytics, "
        "each analytic preceded by the data source and event id it needs, plus "
        "the pre-hunt pages on data quality and documentation. Summiting the "
        "Pyramid: analytic robustness methodology, worked before/after "
        "rewrites, and 92 scored analytics with the reviewer's note on why "
        "each is evadable. Palantir ADS: the detection document template whose "
        "Blind Spots and Assumptions section enumerates the ways an alert "
        "silently fails to fire. Jupyter {code-cell} plumbing, jupytext front "
        "matter, rst figures and toctrees are dropped; {code-block} analytic "
        "logic, grid tables and every indentation are kept."
    ),
)
