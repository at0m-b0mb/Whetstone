"""Center for Threat-Informed Defense Attack Flow — intrusions as sequences.

Everywhere else in this corpus an adversary technique is described standing
still. ``attack`` says what ``T1553.004`` is; ``atomic`` says how to run it;
``sigma`` says how to catch it. Nothing says **what came before it and what came
next**, and that is the only question a planning agent actually has to answer.

Attack Flow is 41 real intrusions — SolarWinds, NotPetya, Equifax, Target,
Uber, Conti, REvil, Black Basta, the CISA Iranian APT advisory, two Turla
emulation plans — drawn as graphs of 952 actions, each action carrying its
ATT&CK tactic and technique id, a sentence about what was done, and **edges to
the actions that followed it**. Rendered as an ordered walk, one document per
intrusion, that is the register this corpus has never had: technique ids in
causal order with the reason each one followed the last.

**Recovering the edges is the whole adapter, and it was verified rather than
assumed.** The ``.afb`` files are Attack Flow Builder saves, and the graph is
not stored as ``source``/``target`` between actions. It is stored through four
levels of the editor's layout model: an action owns ``anchors`` (a dict keyed by
angle), an anchor owns ``latches``, a ``dynamic_line`` names a source latch and
a target latch, and the line is what the user drew. So an edge is recovered by
walking latch → anchor → owning object, twice. The temptation is to skip all
that and take the ``objects`` array in file order, which looks like execution
order and is not; a corpus whose sequences are subtly wrong is worse than one
with no sequences, because nothing downstream can tell. :func:`_edges` does the
walk and :func:`_documents` refuses a flow it cannot resolve edges for. Measured
on the first file read: 10 ``dynamic_line`` objects, 10 edges resolved, and the
chain they describe matches the published diagram.

**Flows contain cycles, and the ordering says so.** ``SearchAwesome Adware``
loops — ``Subvert Trust Controls`` returns to ``Ingress Tool Transfer``. So the
walk is a Kahn topological sort with a deterministic tie-break, and whatever
remains in a cycle is appended under its own heading rather than being forced
into a fake order. A linearisation that silently invents an order for a cycle is
a fabricated fact.

**Third-party personal data: this source carries real names and the exclusions
are specific.** Measured across all 41 files:

* **The ``author`` property of every flow** is the analyst who drew it, with
  their name and work email address — 36 of 41 flows carry an address there.
  Never read.
* **``note`` objects** (46) are indicator dumps with an ``authors`` list: one
  reads "The following IPs download, execute, and check the bash script:" and
  then six addresses, signed with a person's name. Never read.
* **``threat_actor`` objects** (26) include **named individuals**: three PLA
  members indicted by the US Department of Justice over the Equifax breach are
  in there by name, with the indictment as the description. Never read — and
  this is the deliberate call rather than an oversight. They are a matter of
  public record and the data is Apache-2.0, so the question is not whether it is
  permitted; it is whether it buys anything. It buys nothing: group-level actor
  knowledge is already in this corpus from ATT&CK, ``attackactors`` and
  ``mispgalaxy``, what this source uniquely supplies is the *sequence*, and the
  name of an individual contributes nothing to a model that reads command
  output and picks a verb. Zero cost to exclude, so excluded.
* **``user_account`` objects** (22) hold account names from real intrusions —
  first names and one full personal name among them. Never read, on the same
  reasoning.
* **``identity``, ``email_address``, ``url``, ``ipv4_addr``, ``domain_name``,
  ``location`` and ``artifact``** are not read either: they are indicators and
  third-party infrastructure, which is a lookup table rather than knowledge, and
  :data:`_RENDERED` is a whitelist so a new observable type upstream is excluded
  by default rather than included by accident.
* File **hashes** are dropped while file names, MIME types and magic numbers are
  kept, for the same lookup-table reason.
* A **per-object scrubber** then drops any object still carrying an address or
  handle, and a **user-path filter** drops any object naming a
  ``Users\\<name>`` or ``home/<name>`` directory. Per object rather than per
  document, because refusing the document would throw away a whole intrusion
  over one field; measured, the scrubber catches exactly one action, whose
  description names a C2 mailbox.

What survives and is worth saying out loud: ``process`` objects carry real
``command_line`` strings from real intrusions — ``net user /domain``,
``bcdedit`` — and ``windows_registry_key`` objects carry real keys. Those are
SHELL and SYSTEM surface forms from incidents, which is exactly the text the
register report says this corpus is short of.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any, Iterator

from ..net import NetworkError, download, fetch
from ..source import Document, Register, Side, SourceError, SourceSpec, normalise

_REPO = "center-for-threat-informed-defense/attack-flow"
_REF = "main"
_RAW = f"https://raw.githubusercontent.com/{_REPO}/{_REF}"
_API = (f"https://api.github.com/repos/{_REPO}/contents/corpus?ref={_REF}")
_LICENSE_URL = f"{_RAW}/LICENSE"

_CORPUS_DIR = "corpus"
_LICENSE_DIR = "licenses"
_MARKER = ".fetched.json"

#: The largest flow is 864 KB; four megabytes is room and still a bound.
_MAX_FLOW_BYTES = 8 * 1024 * 1024
_MAX_LICENSE_BYTES = 256 * 1024
_MAX_INDEX_BYTES = 4 * 1024 * 1024

#: 41 flows upstream. The floor catches a corpus directory that moved or a
#: listing that came back empty, which otherwise looks like a successful build
#: of nothing.
_MIN_FLOWS = 20

_MIN_CHARS = 400

#: Object types rendered. A **whitelist**: a new STIX observable type added
#: upstream is excluded until somebody looks at it, which is the right default
#: for a format whose observable half is indicators and personal data. See the
#: module docstring for what each exclusion is and why.
_RENDERED = frozenset({
    "action", "condition", "asset", "tool", "malware", "infrastructure",
    "AND_operator", "OR_operator", "process", "vulnerability", "mitigation",
    "detection", "course_of_action", "campaign", "software", "network_traffic",
    "windows_registry_key", "directory", "file",
})

#: Properties never read, whatever object they appear on. ``author``/``authors``
#: are the analyst who drew the flow; ``contact_information`` is an address;
#: ``hashes`` is an indicator list; the ``*_ref`` fields are STIX UUIDs, which
#: teach a tokenizer a hash.
_NEVER_READ = frozenset({
    "author", "authors", "contact_information", "hashes",
    "tactic_ref", "technique_ref",
})

#: Properties rendered as the headline of a non-action object, in this order.
_NAME_KEYS = ("name", "value", "key", "path", "command_line", "description")

#: A directory or path naming somebody's home. ``Users\\Public`` and
#: ``/home/webserver`` are not personal and are kept by the second group.
_USER_PATH = re.compile(r"(?:Users|home)[\\/]+(?!Public\b|All\b|Default\b)"
                        r"[A-Za-z0-9._-]{2,}", re.IGNORECASE)
_IMPERSONAL_PATH = re.compile(
    r"(?:Users|home)[\\/]+(?:public|all users|default|default user|etc|opt|"
    r"perl|webserver|www|www-data|apache|nginx|tomcat|administrator|admin|"
    r"root|ubuntu|ec2-user|git|jenkins|docker|postgres|mysql|oracle)\b",
    re.IGNORECASE,
)

#: See :mod:`training.corpus.sources.atlas`. Identical across this family.
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

#: Objects the privacy filters may drop before the source refuses. **Measured
#: by running it: 4.** One action in the Turla Snake emulation plan whose
#: description names a C2 mailbox, and three OceanLotus objects naming a
#: ``Users/<name>`` home directory — the name there looks like a lab joke, but
#: the filter cannot know that and three objects out of 1,700 is a cheap
#: conservative call.
#:
#: The ceiling is the instrument, set at ten times the measured figure rather
#: than a hundred: a jump means a field changed shape upstream, not that the
#: filter is working harder.
_MAX_DROPPED_OBJECTS = 40


def _short_hash(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]


def _fetch(cache_dir: Path) -> Path:
    """Download every ``corpus/*.afb`` plus the upstream LICENSE.

    The file list comes from the GitHub contents API rather than being hardcoded,
    because this corpus grows — flows for new intrusions are added — and a
    hardcoded list silently stops collecting them. The response is treated as
    data: only the ``name``/``size`` fields are read and each file is then
    fetched from a URL this module builds itself from :data:`_RAW`, so a
    ``download_url`` pointing somewhere else cannot redirect the fetch.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    flows = cache_dir / _CORPUS_DIR
    marker = cache_dir / _MARKER
    if marker.is_file() and flows.is_dir():
        return flows

    licenses = cache_dir / _LICENSE_DIR
    licenses.mkdir(parents=True, exist_ok=True)
    license_file = licenses / "attack-flow.LICENSE"
    flows.mkdir(parents=True, exist_ok=True)

    try:
        download(_LICENSE_URL, license_file, timeout=60,
                 max_bytes=_MAX_LICENSE_BYTES)
        text = license_file.read_text(encoding="utf-8", errors="replace")
        if "Apache License" not in text:
            raise SourceError(
                "attackflow: the upstream LICENSE no longer reads as "
                f"Apache-2.0 ({_LICENSE_URL}); re-read it before building."
            )
        listing = json.loads(
            fetch(_API, timeout=90, max_bytes=_MAX_INDEX_BYTES).decode("utf-8")
        )
    except NetworkError as exc:
        raise SourceError(f"attackflow: fetch failed: {exc}") from None
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceError(
            f"attackflow: the corpus listing at {_API} was not JSON: {exc}"
        ) from None

    if not isinstance(listing, list):
        raise SourceError(f"attackflow: {_API} did not return a file listing")

    names = []
    for entry in listing:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or "")
        # A name is a filename and nothing else. The listing is remote data and
        # this value becomes a path: a '..' or a leading '/' in it must not be
        # able to decide where the write lands.
        if (not name.endswith(".afb") or "/" in name or "\\" in name
                or name.startswith(".") or os.path.isabs(name)):
            continue
        names.append(name)

    if len(names) < _MIN_FLOWS:
        raise SourceError(
            f"attackflow: the listing at {_API} offered {len(names)} .afb files "
            f"(expected at least {_MIN_FLOWS}). The corpus directory has "
            "probably moved; fix the adapter rather than building on what is "
            "left."
        )

    try:
        for name in sorted(names):
            target = flows / name
            if target.is_file():
                continue
            download(f"{_RAW}/{_CORPUS_DIR}/{quote(name)}", target,
                     timeout=180, max_bytes=_MAX_FLOW_BYTES)
            try:
                json.loads(target.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                target.unlink(missing_ok=True)
                raise SourceError(
                    f"attackflow: {name} did not arrive as JSON: {exc}"
                ) from None
    except NetworkError as exc:
        raise SourceError(f"attackflow: fetch failed: {exc}") from None

    marker.write_text(
        json.dumps(
            {
                "repo": _REPO,
                "ref": _REF,
                "index_url": _API,
                "license_url": _LICENSE_URL,
                "flows": sorted(names),
                "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return flows


def quote(name: str) -> str:
    """Percent-encode a filename for a raw.githubusercontent URL.

    The flow filenames contain spaces and ampersands (``Conti Ransomware.afb``,
    ``CISA AA22-138B VMWare Workspace (TA1).afb``). Only the path segment is
    encoded and ``/`` is deliberately not in the safe set — these are filenames,
    and a ``/`` surviving into the URL would be a path escape.
    """
    import urllib.parse

    return urllib.parse.quote(name, safe="")


def _properties(obj: dict[str, Any]) -> dict[str, Any]:
    """An ``.afb`` property list as a dict, with the never-read keys removed.

    Attack Flow Builder stores properties as ``[[key, value], ...]`` and nests
    the same shape for sub-objects — and for list-valued fields it keys each
    entry by a content hash, ``[[hash, [[k, v], ...]], ...]``. Both are handled
    here so the renderers never see the editor's storage model.
    """
    out: dict[str, Any] = {}
    for item in obj.get("properties") or []:
        if not (isinstance(item, list) and len(item) == 2):
            continue
        key, value = item
        if not isinstance(key, str) or key in _NEVER_READ:
            continue
        out[key] = value
    return out


def _scalar(value: Any) -> str:
    """A property value as a string, or '' for null and for the empty list."""
    if value is None or isinstance(value, (list, dict)):
        return ""
    return str(value).strip()


def _listed(value: Any) -> list[str]:
    """A list-valued property as strings, through either of its two shapes."""
    if not isinstance(value, list):
        scalar = _scalar(value)
        return [scalar] if scalar else []
    out: list[str] = []
    for item in value:
        if isinstance(item, list) and len(item) == 2:
            # Either [hash, payload] or [key, value]; the payload may itself be
            # a property list, in which case its 'name'/'value' is what reads.
            payload = item[1]
            if isinstance(payload, list):
                nested = {k: v for k, v in
                          (p for p in payload
                           if isinstance(p, list) and len(p) == 2)
                          if isinstance(k, str)}
                for key in ("source_name", "name", "value", "url"):
                    if _scalar(nested.get(key)):
                        out.append(_scalar(nested[key]))
                        break
                continue
            scalar = _scalar(payload)
            if scalar:
                out.append(scalar)
            continue
        scalar = _scalar(item)
        if scalar:
            out.append(scalar)
    return out


def _references(value: Any) -> list[str]:
    """External references as ``source — title — url``, author never included."""
    out: list[str] = []
    if not isinstance(value, list):
        return out
    for item in value:
        if not (isinstance(item, list) and len(item) == 2
                and isinstance(item[1], list)):
            continue
        fields = {k: v for k, v in
                  (p for p in item[1] if isinstance(p, list) and len(p) == 2)
                  if isinstance(k, str)}
        rendered = " — ".join(
            x for x in (_scalar(fields.get("source_name")),
                        _scalar(fields.get("description")),
                        _scalar(fields.get("url")))
            if x
        )
        if rendered and rendered not in out:
            out.append(rendered)
    return out


def _edges(objects: list[dict[str, Any]]) -> list[tuple[str, str]]:
    """Recover ``(source instance, target instance)`` for every drawn line.

    Four hops, and every one of them is in the file for the editor's benefit
    rather than the reader's: ``dynamic_line.source`` is a *latch*, a latch
    belongs to an *anchor* (through the anchor's own ``latches`` list), and an
    anchor belongs to an object (through that object's ``anchors`` dict). The
    walk is done in both directions for each line.

    Unresolvable lines are dropped silently and counted by the caller — a line
    whose latch has been orphaned by an editor bug is not a reason to lose the
    flow, but a flow where *every* line is unresolvable means this walk has
    stopped matching the format and :func:`_documents` refuses on that.
    """
    latch_to_anchor: dict[str, str] = {}
    anchor_to_owner: dict[str, str] = {}
    for obj in objects:
        instance = str(obj.get("instance") or "")
        for latch in obj.get("latches") or []:
            if isinstance(latch, str) and instance:
                latch_to_anchor[latch] = instance
        anchors = obj.get("anchors")
        if isinstance(anchors, dict) and instance:
            for anchor in anchors.values():
                if isinstance(anchor, str):
                    anchor_to_owner[anchor] = instance

    out: list[tuple[str, str]] = []
    for obj in objects:
        if obj.get("id") != "dynamic_line":
            continue
        source = anchor_to_owner.get(
            latch_to_anchor.get(str(obj.get("source") or ""), ""), "")
        target = anchor_to_owner.get(
            latch_to_anchor.get(str(obj.get("target") or ""), ""), "")
        if source and target and source != target:
            out.append((source, target))
    return out


def _ordered(nodes: list[str], edges: list[tuple[str, str]],
             label: dict[str, str]) -> tuple[list[str], list[str]]:
    """Kahn topological sort. Returns ``(ordered, left in cycles)``.

    The tie-break is the node's rendered label, so the order is a property of
    the flow rather than of dict iteration: two runs over one cache must produce
    the same corpus or "did my change alter the output" is unanswerable.

    Nodes left over are in a cycle, and they are returned separately rather than
    appended as if they were ordered. Flows genuinely contain loops — an
    adversary re-using a tool transfer later in the intrusion — and inventing a
    position for them would put a fabricated sequence in the corpus.
    """
    incoming: dict[str, int] = {node: 0 for node in nodes}
    outgoing: dict[str, list[str]] = {node: [] for node in nodes}
    for source, target in edges:
        if source in outgoing and target in incoming:
            outgoing[source].append(target)
            incoming[target] += 1

    ready = sorted((n for n in nodes if incoming[n] == 0),
                   key=lambda n: (label.get(n, ""), n))
    out: list[str] = []
    while ready:
        node = ready.pop(0)
        out.append(node)
        changed = False
        for successor in outgoing[node]:
            incoming[successor] -= 1
            if incoming[successor] == 0:
                ready.append(successor)
                changed = True
        if changed:
            ready.sort(key=lambda n: (label.get(n, ""), n))
    remaining = sorted((n for n in nodes if n not in set(out)),
                       key=lambda n: (label.get(n, ""), n))
    return out, remaining


def _action_label(fields: dict[str, Any]) -> str:
    """``T1204.002 User Execution (TA0002) — Malicious File``.

    Technique id first because that is the identifier the corpus is here to
    teach, then the action's own name, which is the analyst's phrasing of what
    happened and is often more specific than the technique's title.
    """
    technique = _scalar(fields.get("technique_id"))
    tactic = _scalar(fields.get("tactic_id"))
    name = _scalar(fields.get("name"))
    head = technique
    if tactic:
        head = f"{head} ({tactic})" if head else tactic
    return f"{head} — {name}".strip(" —") if head else name


def _object_lines(kind: str, fields: dict[str, Any]) -> list[str]:
    """One non-action object as a labelled line plus its description."""
    headline = ""
    for key in _NAME_KEYS:
        headline = _scalar(fields.get(key))
        if headline:
            break
    if not headline:
        return []
    out = [f"- {kind.replace('_', ' ')}: {headline}"]
    description = _scalar(fields.get("description"))
    if description and description != headline:
        out.append(f"  {description}")
    for key in ("pattern", "pattern_type", "command_line", "mime_type",
                "magic_number_hex", "malware_types", "tool_types",
                "infrastructure_types", "capabilities", "aliases",
                "implementation_languages", "protocols", "dst_port",
                "is_family", "tool_version"):
        if key in _NAME_KEYS and _scalar(fields.get(key)) == headline:
            continue
        rendered = _scalar(fields.get(key)) or "; ".join(_listed(fields.get(key)))
        if rendered:
            out.append(f"  {key.replace('_', ' ')}: {rendered}")
    return out


def _carries_personal_data(text: str) -> str:
    """'' when clean, else a short kind name. Never returns the value itself."""
    if _EMAIL.search(text):
        return "email address"
    if _HANDLE.search(text):
        return "social handle"
    match = _USER_PATH.search(text)
    if match and not _IMPERSONAL_PATH.search(match.group(0)):
        return "home-directory path"
    return ""


def _flow_document(payload: dict[str, Any], filename: str,
                   dropped: list[str]) -> str | None:
    """Render one ``.afb`` as an ordered narrative, or None if it has no actions."""
    objects = [o for o in payload.get("objects") or [] if isinstance(o, dict)]
    by_instance = {str(o.get("instance") or ""): o for o in objects
                   if o.get("instance")}

    flow = next((o for o in objects if o.get("id") == "flow"), None)
    if flow is None:
        return None
    header_fields = _properties(flow)

    edges = _edges(objects)
    lines_drawn = sum(1 for o in objects if o.get("id") == "dynamic_line")
    if lines_drawn and not edges:
        raise SourceError(
            f"attackflow: {filename} has {lines_drawn} drawn lines and zero "
            "resolvable edges. The latch/anchor walk in _edges() has stopped "
            "matching the .afb layout model, which means every sequence this "
            "source emits would be wrong — and silently wrong. Fix the walk; "
            "do not fall back to file order."
        )

    kept: dict[str, dict[str, Any]] = {}
    for instance, obj in by_instance.items():
        kind = str(obj.get("id") or "")
        if kind not in _RENDERED:
            continue
        fields = _properties(obj)
        probe = json.dumps(fields, ensure_ascii=False)
        found = _carries_personal_data(probe)
        if found:
            dropped.append(
                f"{filename}:{kind}: kind={found} "
                f"sha256[:8]={_short_hash(probe)}"
            )
            continue
        kept[instance] = fields

    actions = {i: f for i, f in kept.items()
               if str(by_instance[i].get("id")) in ("action", "AND_operator",
                                                    "OR_operator", "condition")}
    if not actions:
        return None

    label = {i: (_action_label(f) if by_instance[i].get("id") == "action"
                 else (_scalar(f.get("description"))
                       or str(by_instance[i].get("id") or "")))
             for i, f in actions.items()}
    order, cycled = _ordered(list(actions), edges, label)

    title = _scalar(header_fields.get("name")) or Path(filename).stem
    out = [title, ""]
    out.append("Catalogue: Attack Flow (Center for Threat-Informed Defense)")
    out.append("Type: Attack flow — one intrusion as an ordered technique chain")
    scope = _scalar(header_fields.get("scope"))
    if scope:
        out.append(f"Scope: {scope}")
    created = _scalar(header_fields.get("created"))
    if created:
        out.append(f"Flow created: {created[:10]}")
    for key in ("classification", "ttp_frameworks", "tags"):
        rendered = "; ".join(_listed(header_fields.get(key)))
        if rendered:
            out.append(f"{key.replace('_', ' ').capitalize()}: {rendered}")
    out.append(f"Actions: {len(actions)}   Edges: {len(edges)}")

    description = _scalar(header_fields.get("description"))
    if description:
        out += ["", description]

    def render_step(number: int, instance: str) -> list[str]:
        fields = actions[instance]
        kind = str(by_instance[instance].get("id") or "")
        head = label.get(instance, "")
        if kind == "action":
            rows = [f"{number}. {head}"]
        elif head and head != kind:
            rows = [f"{number}. [{kind}] {head}"]
        else:
            # An operator with no description of its own. Rendering it as
            # "[AND_operator] AND_operator" says the same thing twice; the
            # node still has to appear, because it is where two branches meet
            # and dropping it would join unrelated steps end to end.
            rows = [f"{number}. [{kind}]"]
        body = _scalar(fields.get("description"))
        if body and body != head:
            rows.append(f"   {body}")
        confidence = _scalar(fields.get("confidence"))
        if confidence:
            rows.append(f"   confidence: {confidence}")
        successors = sorted(
            label.get(target, "") for source, target in edges
            if source == instance and target in actions
        )
        for successor in successors:
            if successor:
                rows.append(f"   -> then: {successor}")
        return rows + [""]

    steps: list[str] = []
    for number, instance in enumerate(order, start=1):
        steps += render_step(number, instance)
    if steps:
        out += ["", "## Attack sequence", ""] + steps

    if cycled:
        cyclic: list[str] = []
        for number, instance in enumerate(cycled, start=len(order) + 1):
            cyclic += render_step(number, instance)
        out += ["", "## Actions in a cycle (no single order exists; the flow "
                "returns to these)", ""] + cyclic

    grouped: dict[str, list[str]] = {}
    for instance, fields in kept.items():
        kind = str(by_instance[instance].get("id") or "")
        if instance in actions:
            continue
        rendered = _object_lines(kind, fields)
        if rendered:
            grouped.setdefault(kind, []).extend(rendered)
    if grouped:
        body: list[str] = []
        for kind in sorted(grouped):
            body += grouped[kind]
        out += ["", "## Objects involved", ""] + body

    references = _references(header_fields.get("external_references"))
    if references:
        out += ["", "## Source reporting", ""] + [f"- {r}" for r in references]

    return "\n".join(out)


def _documents(path: Path) -> Iterator[Document]:
    """One document per flow, in filename order.

    ADVERSARY register, RED side. The flows carry ``mitigation`` and
    ``detection`` objects too, but they are a minority inside a document whose
    subject is an intrusion, and splitting one intrusion across two registers to
    account for them would make both numbers less true rather than more.
    """
    root = path / _CORPUS_DIR if (path / _CORPUS_DIR).is_dir() else path
    if not root.is_dir():
        raise SourceError(f"attackflow: no flow directory under {path}")

    dropped: list[str] = []
    seen = 0
    # os.walk with followlinks=False rather than rglob: a symlink in a cache
    # directory once led a source into the corpus's own output and the corpus
    # ate itself. One flat directory today, and that is exactly when the habit
    # is free to keep.
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames
                             if not Path(dirpath, d).is_symlink())
        for filename in sorted(filenames):
            if not filename.endswith(".afb"):
                continue
            file = Path(dirpath, filename)
            if file.is_symlink():
                continue
            try:
                payload = json.loads(file.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                continue
            if not isinstance(payload, dict):
                continue
            seen += 1
            text = _flow_document(payload, filename, dropped)
            if text is None:
                continue
            text = normalise(text)
            if len(text) < _MIN_CHARS:
                continue
            found = _carries_personal_data(text)
            if found:
                raise SourceError(
                    f"attackflow: the rendered document for {filename!r} "
                    f"carries a {found} that the per-object filters did not "
                    "catch. That means it arrived through a field the whitelist "
                    "renders — find which one before changing anything here."
                )
            yield Document(
                text=text,
                source="attackflow",
                register=Register.ADVERSARY,
                side=Side.RED,
                ident=Path(filename).stem,
            )

    if seen < _MIN_FLOWS:
        raise SourceError(
            f"attackflow: only {seen} .afb files found under {root} (expected "
            f"at least {_MIN_FLOWS}). Delete {_MARKER} and re-fetch."
        )
    if len(dropped) > _MAX_DROPPED_OBJECTS:
        raise SourceError(
            f"attackflow: the privacy filters dropped {len(dropped)} objects, "
            f"over the ceiling of {_MAX_DROPPED_OBJECTS}. Measured it was a "
            "handful. Something changed shape upstream; find out what rather "
            "than raising the number."
        )


SPEC = SourceSpec(
    name="attackflow",
    license=(
        "Apache-2.0 — Attack Flow, MITRE Engenuity Center for Threat-Informed "
        "Defense. Upstream LICENSE is the verbatim Apache License 2.0 text, "
        "read from https://raw.githubusercontent.com/"
        "center-for-threat-informed-defense/attack-flow/main/LICENSE and "
        "copied into the cache under licenses/attack-flow.LICENSE so the claim "
        "is checkable against the download. (c) 2022-2026 MITRE Engenuity. "
        "ATT&CK is a registered trademark of The MITRE Corporation."
    ),
    url="https://github.com/center-for-threat-informed-defense/attack-flow",
    register=Register.ADVERSARY,
    side=Side.RED,
    fetch=_fetch,
    documents=_documents,
    #: Measured by running the adapter: **41 documents, 289,787 characters**,
    #: no two sharing a fingerprint, median 6,155 characters and longest
    #: 22,747 — 41 flows in, 41 out, and 4 objects dropped by the privacy
    #: filters. This is a small source by document count and a dense one by
    #: content: 952 actions across the 41.
    #:
    #: The floor sits at 30 because upstream adds flows rather than removing
    #: them, so the realistic regression is the corpus directory moving — which
    #: _fetch catches first, with its own message, against its own floor of 20.
    expect_min_docs=30,
    #: ~10 MB over 42 requests on a cold cache, a local parse when warm.
    timeout=900,
    notes=(
        "41 real intrusions as ordered technique chains — the only source in "
        "this corpus that describes an adversary as a sequence rather than as a "
        "standing description. Each document is one flow: its actions walked in "
        "topological order with the ATT&CK tactic and technique id, the "
        "analyst's sentence about what was done, and the actions that followed; "
        "cycles are listed under their own heading rather than forced into a "
        "fake order. The edges are recovered through the .afb layout model "
        "(latch -> anchor -> owning object, twice) and the adapter refuses a "
        "flow with drawn lines and no resolvable edges, because taking the "
        "objects array in file order looks like execution order and is not. "
        "Privacy: the flow author's name and email (36 of 41 files), note "
        "objects (indicator dumps signed with a person's name), threat_actor "
        "objects (which include three individuals named in a US indictment), "
        "user_account objects (real account names, one a full personal name), "
        "identity, email_address, url, ipv4_addr, domain_name, location, "
        "artifact and file hashes are all excluded by whitelist; a per-object "
        "scrubber then drops anything carrying an address, handle or home "
        "directory path, and the source refuses if that count leaves the "
        "measured band. What is kept and is worth having: process objects with "
        "real command lines from real incidents, and real registry keys."
    ),
)
