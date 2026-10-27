"""MITRE Engage — adversary engagement, denial and deception. ADVERSARY/BLUE.

Engage is the framework for what a defender *does to* an adversary who is
already inside: expose them, affect them, elicit behaviour from them. It is
organised as goals (``EGO0001``), approaches (``EAP0001``), activities
(``EAC0001``) and — the part that makes this source worth having —
**adversary vulnerabilities** (``EAV0001``), which are statements of the form
"when adversaries do X, they are vulnerable to Y".

**Why it earns its place in a corpus that already has ATT&CK and D3FEND.**
Those two answer "what did the adversary do" and "what control stops it".
Neither can express the third thing, which is the one this project's runtime is
actually built around: the adversary has to *act*, acting exposes them, and the
defender can choose what to expose. Engage publishes 793 mappings of exactly
that shape — ``T1001 Data Obfuscation`` → ``EAV0016`` ("when adversaries utilize
or abuse system features, software, or other resources, they may be vulnerable
to monitoring or Man-in-the-Middle manipulation") → ``EAC0014 Software
Manipulation``. A two-hop path from an offensive technique id to a defensive
activity id, through a sentence explaining why the hop exists. Nothing else in
this corpus carries that edge.

**It is small, and the shape of the smallness is deliberate.** 625 KB of JSON
becomes 74 documents, not a few thousand. The obvious way to inflate it is to
emit one document per ATT&CK technique in ``attack_mapping.json`` —
and the counts say why that would be a mistake: 793 mapping rows carry **29
distinct ``EAV`` sentences** across **175 distinct technique ids**, so a
technique-major rendering reprints each sentence 27 times on average. That is
precisely the generated-boilerplate failure this corpus has already paid for
once, when 1.57 MB of one Elastic ``setup`` block arrived 192 times over. So
the mapping is emitted in the **reverse** direction: each
activity document carries the full list of ATT&CK techniques it engages (dense
``T####``-beside-name co-occurrence, which is the adjacency the tokenizer
needs), and each adversary-vulnerability document carries its sentence **once**
with the techniques and activities that reference it. Measured: 74 documents,
177,559 characters, no two sharing a fingerprint.

**Markup.** Measured, not guessed: the only HTML in this upstream is ``<br>``,
98 occurrences, and there are zero HTML entities. So ``<br>`` becomes a newline
and :func:`_detagged` then *refuses* on any other ``<`` rather than running a
generic tag regex over the text. The generic regex is the dangerous move in a
security corpus — ``owasp`` keeps its tags because there they are XSS payloads
rather than markup — and a refusal is what makes the measurement above stay
true as upstream changes.

**Third-party personal data.** Zero email addresses across all twelve JSON
files, measured. The 67 entries in ``references.json`` are paper titles and DOI
URLs with no author field, so no researcher names enter the corpus from this
source even incidentally. :func:`_scrubbed` is still applied to every rendered
document and still refuses, because that is a fact about this snapshot.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Iterator

from ..net import NetworkError, download
from ..source import Document, Register, Side, SourceError, SourceSpec, normalise

_REPO = "mitre/engage"
_REF = "main"
_RAW = f"https://raw.githubusercontent.com/{_REPO}/{_REF}"
_JSON_DIR = "Data/json"
_LICENSE_URL = f"{_RAW}/LICENSE.md"

#: The files actually read, each a separate request. Listed rather than
#: discovered so that an upstream reorganisation is a loud missing-file error
#: naming the file, not a quietly thinner corpus.
#:
#: ``approach_matrix.json`` and ``attack_mapping.json`` overlap: the matrix is a
#: presentation pivot of the same edges. Only the mapping is read.
_FILES = (
    "goals.json",
    "goal_details.json",
    "approaches.json",
    "approach_details.json",
    "activities.json",
    "activity_details.json",
    "attack_mapping.json",
    "attack_tactics_techniques.json",
    "references.json",
)

_LICENSE_DIR = "licenses"
_MARKER = ".fetched.json"

#: The largest of the nine is 282 KB. A megabyte each is room for growth and
#: still refuses a redirect to something that is not this data.
_MAX_FILE_BYTES = 4 * 1024 * 1024
_MAX_LICENSE_BYTES = 256 * 1024

_MIN_CHARS = 200

#: See :mod:`training.corpus.sources.atlas` for why these refuse rather than
#: strip. The patterns are deliberately identical across the sources added in
#: this family: a privacy check that is subtly different per adapter is a
#: privacy check nobody can state the guarantee of.
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

#: ``<br>``, ``<br/>``, ``<br />`` — the only markup this upstream uses.
_BR = re.compile(r"<\s*br\s*/?\s*>", re.IGNORECASE)


def _short_hash(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]


def _fetch(cache_dir: Path) -> Path:
    """Download the nine JSON files and the upstream LICENSE into ``cache_dir``.

    Returns the cache directory. Idempotent and network-free when warm — the
    marker is written last, so a fetch interrupted after six of nine files
    re-fetches rather than yielding a corpus with the mappings missing.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    marker = cache_dir / _MARKER
    if marker.is_file() and all((cache_dir / name).is_file() for name in _FILES):
        return cache_dir

    licenses = cache_dir / _LICENSE_DIR
    licenses.mkdir(parents=True, exist_ok=True)
    license_file = licenses / "engage.LICENSE.md"

    staging = cache_dir / ".staging"
    staging.mkdir(parents=True, exist_ok=True)
    try:
        download(_LICENSE_URL, license_file, timeout=60,
                 max_bytes=_MAX_LICENSE_BYTES)
        text = license_file.read_text(encoding="utf-8", errors="replace")
        if "Apache License" not in text:
            raise SourceError(
                "engage: the upstream LICENSE.md no longer reads as Apache-2.0 "
                f"({_LICENSE_URL}). The SPEC declaration is a claim about that "
                "file; re-read it rather than training on changed terms."
            )
        for name in _FILES:
            download(f"{_RAW}/{_JSON_DIR}/{name}", staging / name,
                     timeout=90, max_bytes=_MAX_FILE_BYTES)
            # Parsed here, at fetch time, so a 404 page or an HTML error
            # document that arrived with a 200 is caught while there is still
            # a URL in scope to name. A cache that holds nine files of the
            # wrong kind is indistinguishable from a cache that is fine until
            # the parse fails much later with no idea which file moved.
            try:
                json.loads((staging / name).read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise SourceError(
                    f"engage: {name} did not arrive as JSON from "
                    f"{_RAW}/{_JSON_DIR}/{name}: {exc}"
                ) from None
        for name in _FILES:
            (staging / name).replace(cache_dir / name)
    except NetworkError as exc:
        raise SourceError(f"engage: fetch failed: {exc}") from None
    finally:
        for leftover in staging.glob("*"):
            leftover.unlink(missing_ok=True)
        staging.rmdir() if staging.is_dir() else None

    marker.write_text(
        json.dumps(
            {
                "repo": _REPO,
                "ref": _REF,
                "files": list(_FILES),
                "license_url": _LICENSE_URL,
                "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return cache_dir


def _read(cache_dir: Path, name: str) -> Any:
    path = cache_dir / name
    if not path.is_file():
        raise SourceError(
            f"engage: {path} is missing — fetch did not populate it. "
            "Delete the cache marker and re-fetch rather than building a "
            "corpus from part of this upstream."
        )
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceError(f"engage: could not parse {path}: {exc}") from None


def _detagged(value: Any, ident: str) -> str:
    """``<br>`` to a newline; any other tag is a refusal.

    See the module docstring: ``<br>`` is the only markup this upstream has, and
    a generic ``<[^>]+>`` substitution is the move that quietly eats content the
    moment an upstream starts embedding anything real. Refusing names the
    adapter that needs updating instead of silently deleting text.
    """
    if value is None:
        return ""
    text = _BR.sub("\n", str(value))
    if "<" in text:
        fragment = text[text.index("<"):text.index("<") + 40]
        raise SourceError(
            f"engage: {ident} carries markup this adapter does not handle "
            f"({fragment!r}). Only <br> was present upstream when it was "
            "written. Extend _detagged deliberately — do not reach for a "
            "generic tag regex, which is how a corpus loses the content that "
            "happened to look like a tag."
        )
    return text.strip()


def _scrubbed(text: str, ident: str) -> str:
    for pattern, kind in ((_EMAIL, "email address"), (_HANDLE, "social handle")):
        match = pattern.search(text)
        if match is None:
            continue
        found = match.group(0)
        raise SourceError(
            f"engage: document {ident!r} carries what looks like a third-party "
            f"{kind} (length={len(found)}, sha256[:8]={_short_hash(found)}). "
            "Upstream had none when this adapter was written; decide "
            "deliberately rather than widening the pattern."
        )
    return text


class _Index:
    """The nine files joined into the edges this source exists to emit."""

    def __init__(self, cache_dir: Path) -> None:
        self.goals = {g["id"]: g for g in _read(cache_dir, "goals.json")
                      if isinstance(g, dict) and g.get("id")}
        self.approaches = {a["id"]: a for a in _read(cache_dir, "approaches.json")
                           if isinstance(a, dict) and a.get("id")}
        self.activities = {a["id"]: a for a in _read(cache_dir, "activities.json")
                           if isinstance(a, dict) and a.get("id")}
        self.goal_details = _read(cache_dir, "goal_details.json") or {}
        self.approach_details = _read(cache_dir, "approach_details.json") or {}
        self.activity_details = _read(cache_dir, "activity_details.json") or {}
        self.techniques = _read(cache_dir, "attack_tactics_techniques.json") or {}
        mappings = _read(cache_dir, "attack_mapping.json") or []
        references = _read(cache_dir, "references.json") or []

        if not self.activities or not mappings:
            raise SourceError(
                "engage: the activity catalogue or the ATT&CK mapping came back "
                "empty. That is the whole source; re-fetch rather than emitting "
                "the goals alone."
            )

        #: EAV id -> sentence. There are 29 distinct ones; see the module
        #: docstring for why that number governs the rendering direction.
        self.vulnerabilities: dict[str, str] = {}
        #: EAV id -> ordered, de-duplicated list of ATT&CK technique ids
        self.eav_techniques: dict[str, list[str]] = {}
        #: EAV id -> ordered, de-duplicated list of activity ids
        self.eav_activities: dict[str, list[str]] = {}
        #: activity id -> ordered list of EAV ids
        self.activity_eavs: dict[str, list[str]] = {}

        for row in mappings:
            if not isinstance(row, dict):
                continue
            eav_id = str(row.get("eav_id") or "")
            if not eav_id:
                continue
            sentence = str(row.get("eav") or "").strip()
            if sentence:
                self.vulnerabilities.setdefault(eav_id, sentence)
            for key, bucket in (("attack_id", self.eav_techniques),
                                ("eac_id", self.eav_activities)):
                value = str(row.get(key) or "")
                if value and value not in bucket.setdefault(eav_id, []):
                    bucket[eav_id].append(value)
            eac = str(row.get("eac_id") or "")
            if eac and eav_id not in self.activity_eavs.setdefault(eac, []):
                self.activity_eavs[eac].append(eav_id)

        #: Activity details also list vulnerabilities directly, and those carry
        #: the sentence for EAVs that the ATT&CK mapping never reaches. Read
        #: second so the mapping's text wins on a conflict; both sources are
        #: MITRE's and identical in practice, and "first writer wins" is only a
        #: stable rule if the order is stated.
        for activity_id, detail in sorted(self.activity_details.items()):
            if not isinstance(detail, dict):
                continue
            for entry in detail.get("vulnerabilities") or []:
                if not isinstance(entry, dict):
                    continue
                eav_id = str(entry.get("id") or "")
                sentence = str(entry.get("eav") or "").strip()
                if eav_id and sentence:
                    self.vulnerabilities.setdefault(eav_id, sentence)
                if eav_id and eav_id not in self.activity_eavs.setdefault(
                        activity_id, []):
                    self.activity_eavs[activity_id].append(eav_id)
                if eav_id and activity_id not in self.eav_activities.setdefault(
                        eav_id, []):
                    self.eav_activities[eav_id].append(activity_id)

        #: activity id -> [(REF id, title, url)]
        self.activity_refs: dict[str, list[tuple[str, str, str]]] = {}
        for ref in references:
            if not isinstance(ref, dict):
                continue
            activity_id = str(ref.get("activity_id") or "")
            if not activity_id:
                continue
            self.activity_refs.setdefault(activity_id, []).append(
                (str(ref.get("id") or ""), str(ref.get("title") or ""),
                 str(ref.get("url") or ""))
            )

        self.names: dict[str, str] = {}
        for table in (self.goals, self.approaches, self.activities):
            for ident, obj in table.items():
                self.names[ident] = str(obj.get("name") or "")
        for ident, obj in self.techniques.items():
            technique = (obj or {}).get("attack_technique") or {}
            name = str(technique.get("name") or "")
            if name:
                self.names[str(ident)] = name

    def label(self, ident: str) -> str:
        """``EAC0014 Software Manipulation``, or the bare id when unknown."""
        name = self.names.get(ident, "")
        return f"{ident} {name}".strip()

    def technique_label(self, ident: str) -> str:
        """``T1001 Data Obfuscation (Command and Control)`` where the tactic is known.

        The tactic in parentheses is joined in from
        ``attack_tactics_techniques.json`` because an engagement activity is
        chosen against a *phase* as much as against a technique, and the tactic
        name is the only thing in this upstream that says which phase.
        """
        entry = self.techniques.get(ident) or {}
        name = str((entry.get("attack_technique") or {}).get("name") or "")
        tactics = [str(t.get("name") or "")
                   for t in entry.get("attack_tactics") or []
                   if isinstance(t, dict)]
        tactics = [t for t in tactics if t]
        base = f"{ident} {name}".strip()
        return f"{base} ({', '.join(tactics)})" if tactics else base


def _header(ident: str, kind: str, name: str) -> list[str]:
    return [
        f"{ident} {name}".strip(),
        "",
        "Framework: MITRE Engage (adversary engagement, denial and deception)",
        f"Type: {kind}",
        f"Engage ID: {ident}",
    ]


def _section(title: str, body: list[str]) -> list[str]:
    return [] if not body else ["", f"## {title}", ""] + body


def _goal_document(ident: str, idx: _Index) -> str:
    goal = idx.goals[ident]
    detail = idx.goal_details.get(ident) or {}
    lines = _header(ident, "Strategic goal", str(goal.get("name") or ""))
    approaches = [str(a) for a in detail.get("approaches") or []]
    if approaches:
        lines.append(f"Approaches: {'; '.join(idx.label(a) for a in approaches)}")
    short = _detagged(goal.get("description"), ident)
    long = _detagged(goal.get("long_description") or detail.get("long_description"),
                     ident)
    if short:
        lines += ["", short]
    if long and long != short:
        lines += ["", long]
    body: list[str] = []
    for approach_id in approaches:
        body.append(f"- {idx.label(approach_id)}")
        approach_detail = idx.approach_details.get(approach_id) or {}
        activities = [str(a) for a in approach_detail.get("activities") or []]
        if activities:
            body.append(f"  Activities: "
                        f"{'; '.join(idx.label(a) for a in activities)}")
    lines += _section("Approaches under this goal", body)
    return "\n".join(lines)


def _approach_document(ident: str, idx: _Index) -> str:
    approach = idx.approaches[ident]
    detail = idx.approach_details.get(ident) or {}
    lines = _header(ident, "Approach", str(approach.get("name") or ""))
    goals = [str(g) for g in detail.get("goals") or []]
    if goals:
        lines.append(f"Goals: {'; '.join(idx.label(g) for g in goals)}")
    kind = str(detail.get("type") or "")
    if kind:
        lines.append(f"Category: {kind}")
    short = _detagged(approach.get("description"), ident)
    long = _detagged(approach.get("long_description")
                     or detail.get("long_description"), ident)
    if short:
        lines += ["", short]
    if long and long != short:
        lines += ["", long]

    body = []
    for activity_id in [str(a) for a in detail.get("activities") or []]:
        body.append(f"- {idx.label(activity_id)}")
        activity = idx.activities.get(activity_id) or {}
        description = _detagged(activity.get("description"), activity_id)
        if description:
            body.append(f"  {description}")
    lines += _section("Activities", body)
    return "\n".join(lines)


def _activity_document(ident: str, idx: _Index) -> str:
    """One activity, with every ATT&CK technique it engages.

    The technique list is the dense part and it is why this document exists:
    ``EAC0003 Lure`` arrives beside forty-odd ``T####`` ids each beside its
    name and its tactic. That adjacency — defensive activity id next to
    offensive technique id next to prose — is the thing the ADVERSARY register
    was measured to be missing, one hop out from where ``attack.py`` fixed it.
    """
    activity = idx.activities[ident]
    detail = idx.activity_details.get(ident) or {}
    lines = _header(ident, "Engagement activity", str(activity.get("name") or ""))
    goals = [str(g) for g in detail.get("goals") or []]
    if goals:
        lines.append(f"Goals: {'; '.join(idx.label(g) for g in goals)}")
    kind = str(detail.get("type") or "")
    if kind:
        lines.append(f"Category: {kind}")

    short = _detagged(activity.get("description"), ident)
    long = _detagged(activity.get("long_description"), ident)
    if short:
        lines += ["", short]
    if long and long != short:
        lines += ["", long]

    body = []
    for eav_id in idx.activity_eavs.get(ident, []):
        sentence = idx.vulnerabilities.get(eav_id, "")
        body.append(f"- {eav_id}: {sentence}" if sentence else f"- {eav_id}")
    lines += _section("Adversary vulnerabilities this exploits", body)

    techniques = [str(t.get("id") or "")
                  for t in detail.get("attack_techniques") or []
                  if isinstance(t, dict)]
    techniques = sorted({t for t in techniques if t})
    lines += _section("ATT&CK techniques engaged",
                      [f"- {idx.technique_label(t)}" for t in techniques])

    refs = idx.activity_refs.get(ident, [])
    lines += _section(
        "References",
        [f"- {ref_id} {title} {url}".strip() for ref_id, title, url in refs],
    )
    return "\n".join(lines)


def _vulnerability_document(ident: str, idx: _Index) -> str:
    """One adversary vulnerability, its activities and the techniques that expose it.

    Emitted once per ``EAV####`` rather than once per ATT&CK technique. There
    are 29 sentences and 175 techniques in the mapping; the technique-major
    rendering would have repeated each sentence 27 times on average, which is
    how a 30 MB corpus teaches a model to recite a paragraph instead of use it.
    """
    sentence = idx.vulnerabilities.get(ident, "")
    lines = _header(ident, "Adversary vulnerability", "")
    lines += ["", sentence] if sentence else []
    activities = idx.eav_activities.get(ident, [])
    lines += _section("Engagement activities that exploit it",
                      [f"- {idx.label(a)}" for a in activities])
    techniques = sorted(set(idx.eav_techniques.get(ident, [])))
    lines += _section("ATT&CK techniques that expose it",
                      [f"- {idx.technique_label(t)}" for t in techniques])
    return "\n".join(lines)


def _documents(path: Path) -> Iterator[Document]:
    """Yield goals, approaches, activities and adversary vulnerabilities.

    ADVERSARY register throughout, BLUE side throughout: every document here is
    a defender's option, but the subject of every one of them is adversary
    behaviour. That is the register this project means by ADVERSARY — behaviour
    described as behaviour — and filing a deception catalogue under DETECTION
    because it is blue would make the register report say something false.
    """
    idx = _Index(path if path.is_dir() else path.parent)

    renderers = (
        ("goal", sorted(idx.goals), _goal_document),
        ("approach", sorted(idx.approaches), _approach_document),
        ("activity", sorted(idx.activities), _activity_document),
        ("vulnerability", sorted(idx.vulnerabilities), _vulnerability_document),
    )
    for kind, idents, render in renderers:
        for ident in idents:
            text = normalise(render(ident, idx))
            if len(text) < _MIN_CHARS:
                continue
            yield Document(
                text=_scrubbed(text, ident),
                source="engage",
                register=Register.ADVERSARY,
                side=Side.BLUE,
                ident=f"{kind}/{ident}",
            )


SPEC = SourceSpec(
    name="engage",
    license=(
        "Apache-2.0 — MITRE Engage. Upstream LICENSE.md is the verbatim Apache "
        "License 2.0 text, read from "
        "https://raw.githubusercontent.com/mitre/engage/main/LICENSE.md and "
        "copied into the cache under licenses/engage.LICENSE.md so the claim is "
        "checkable against the download. MITRE Engage is a trademark of The "
        "MITRE Corporation; (c) 2022 The MITRE Corporation."
    ),
    url="https://github.com/mitre/engage",
    register=Register.ADVERSARY,
    side=Side.BLUE,
    fetch=_fetch,
    documents=_documents,
    #: Observed: 5 goals, 9 approaches, 31 activities and 16 adversary
    #: vulnerabilities = 74, for 177,559 characters and no duplicate
    #: fingerprints. This is a genuinely small source and the floor says
    #: so rather than pretending otherwise. It is set just under the observed
    #: count because losing any one kind here is a large fraction of the whole:
    #: the activities and the mapping are checked for emptiness at index time
    #: and raise with their own message, so this floor is the backstop for the
    #: quieter failure of a file that parses but has been reorganised.
    expect_min_docs=50,
    notes=(
        "MITRE Engage as ADVERSARY/BLUE: the deception and adversary-engagement "
        "half of defence, which nothing else in this corpus covers. One "
        "document per strategic goal (EGO####, with its approaches and their "
        "activities), approach (EAP####), engagement activity (EAC####, with "
        "the adversary vulnerabilities it exploits and every ATT&CK technique "
        "it engages, each beside its name and tactic) and adversary "
        "vulnerability (EAV####, with the activities and techniques on either "
        "side of it). The EAV direction is deliberate: 793 mapping rows carry "
        "29 distinct EAV sentences across 175 technique ids, so a "
        "technique-major rendering would have reprinted each sentence 27 times "
        "on average. approach_matrix.json is skipped as a presentation pivot of "
        "attack_mapping.json. The only markup upstream is <br> (98 of them, "
        "zero HTML entities); it becomes a newline and any other tag is a "
        "refusal rather than a generic regex strip. Every rendered document is "
        "checked for email addresses and @handles and the build refuses on a "
        "hit."
    ),
)
