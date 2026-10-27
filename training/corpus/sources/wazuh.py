"""Wazuh's ruleset — the log-line/decoder/rule/technique join. DETECTION/BLUE.

The ROADMAP named this source first in its shopping list, and the reason it is
worth having is not that it is another pile of rules. The corpus already holds
roughly fifty thousand detections. What it does **not** hold, and what this
source supplies in one tree, is the whole chain from a raw line of log text to
the technique it evidences:

1. ``ruleset/decoders/`` — the regexes that turn a line of syslog into fields,
   each decoder file opening with a comment block of *real example log lines*
   the decoder was written against.
2. ``ruleset/rules/`` — 4,515 rules keyed on those decoded fields, 1,065 of
   them carrying ``<mitre><id>T1190</id></mitre>`` and almost all carrying
   compliance group tags (PCI DSS, NIST 800-53, GDPR, TSC, HIPAA).
3. ``ruleset/testing/tests/`` — 1,564 test cases, 2,055 of them a single
   labelled log line: *this exact text must be decoded by that decoder and must
   fire that rule at that alert level*.
4. ``ruleset/sca/`` — 11,352 Security Configuration Assessment checks, each one
   a command plus the pattern its output must match, with the rationale,
   the remediation script, and ``mitre_mitigations``/``mitre_techniques``
   mappings.

Point 3 is the reason this adapter exists. The brief for this corpus pass put it
plainly: the single biggest real win is **reading command output**, and the
corpus is weakest there — plenty of *usage* text, very little *output* text.
Wazuh's logtest corpus is output text with the answer attached, which is the
rarest shape of training data in this whole collection. Those documents are
rendered with a legend resolving every referenced rule id to its description and
its ATT&CK ids, so one document holds the line, the parser, the verdict and the
technique together instead of leaving the model to join four trees.

Point 4 is the other half of Whetstone's own loop. ``mitre_mitigations: M1050``
is a *mitigation* identifier, and the ROADMAP's open item is that nothing has
ever taught a model to defend — the trajectory format carries remediation turns
and no checkpoint has seen one. 3,275 SCA checks carry an ATT&CK technique and
a mitigation beside the command that proves whether the mitigation is in place.

**Licence: GPL-2.0, and the ruleset is explicitly in scope.** Read from the
repository's own ``LICENSE`` at the pinned tag, not from a badge — GitHub
reports NOASSERTION for this repository. The file says, verbatim:

    This program is free software; you can redistribute it and/or modify it
    under the terms of the GNU General Public License (version 2) as published
    by the FSF - Free Software Foundation.

and then, three paragraphs later, the sentence that settles whether rules are
covered at all:

    Note that this license applies to the source code, as well as decoders,
    rules and any other data file included with Wazuh (unless otherwise
    specified).

Strong copyleft, knowingly: :mod:`~training.corpus.sources.gtfobins` (GPL-3.0)
and :mod:`~training.corpus.sources.yara` (GPL-2.0 for one collection) already
establish that a copyleft upstream is acceptable here, and the obligation —
state where it came from, keep the notices — is what this module and
``provenance.json`` do anyway. Corporate copyright lines are preserved in every
verbatim body; see the privacy note below for the one kind of notice that is not.

**The pinned tag, and why not ``main``.** ``main`` is the 5.x/6.x engine, where
``ruleset/`` has been reduced to ``mitre/`` and ``sca/`` — the XML rules and
decoders are not there. The archived ``wazuh/wazuh-ruleset`` repository has not
been pushed to since September 2024. So the source is ``wazuh/wazuh`` at the
``v4.14.8`` release tag: a pinned, reproducible, currently-supported 4.x
ruleset. Measured: the whole tarball is 20.2 MB.

**Privacy, which this tree really does need.** 25 distinct personal names and
nine personal email addresses sit in ``Author:`` comment lines across the
decoders — ``ddpbsd@gmail.com``, ``peter@ifup.de``, ``jorge@br10.com.br`` and
the rest. They are stripped by :func:`~training.corpus.sources._detectionlib.scrub`,
and every document is then *proved* clean by ``assert_scrubbed`` rather than
assumed to be. Two measured traps shaped that function and are described in its
module: roughly six hundred of this tree's 717 email-shaped tokens are SSH
algorithm names (``hmac-sha2-512-etm@openssh.com``) which are detection signal
and are kept, and the first keyword sweep written here destroyed 332 lines of
CIS password-policy remediation because ``credit`` is a substring of
``dcredit = -1``.

**What is deliberately not taken.**

* ``ruleset/mitre/enterprise-attack.json`` — 27.9 MB, and it is the MITRE
  ATT&CK STIX bundle, which :mod:`~training.corpus.sources.attack` and
  :mod:`~training.corpus.sources.attackactors` already carry in full from
  MITRE's own distribution. Vendoring it twice would be 5% of the corpus spent
  on text the corpus already has. The **id-to-name mapping alone** is extracted
  at fetch time into a small file, because a technique id beside the name of
  what it denotes is worth far more than the id alone — the measurement this
  corpus was rebuilt around moved a sample from -45% to +13% against gpt2 on
  exactly that.
* ``ruleset/lists/`` — 52 KB of CDB lookup tables (``200:``, ``201:``,
  ``audit-wazuh-w:write``). Generated key/value pairs with no prose, excluded
  for the reason :mod:`~training.corpus.sources.nselua` excludes ``nselib/data``.
* XML is **not** parsed with an XML parser. Eight of the 288 rule and decoder
  files are not well-formed when wrapped in a root element — bare ``&`` and
  ``<`` inside regexes, which Wazuh's own lenient reader accepts. A block
  scanner keeps all 288 and keeps every rule body byte-for-byte; an
  ``ElementTree`` pass would have dropped eight files and silently
  re-serialised the rest.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterator

import yaml

from ..source import Document, Register, Side, SourceError, SourceSpec, normalise
from . import _detectionlib as lib

_NAME = "wazuh"
_REPO = "wazuh/wazuh"
#: A release tag, not a branch. The ruleset is the artefact and a moving branch
#: makes a build unreproducible for no benefit.
_REF = "v4.14.8"
_URL = lib.codeload_url(_REPO, _REF, tag=True)

#: Measured at 20,245,739 bytes for this tag. The ceiling is roughly triple
#: that: generous enough that ordinary growth does not fail a build at 3am,
#: tight enough that a redirect to something else entirely does.
_MAX_ARCHIVE_BYTES = 64 * 1024 * 1024

#: Subtrees kept, as first path segments under ``ruleset/``.
_KEEP_TREES = ("rules", "decoders", "testing", "sca", "rootcheck")

#: Extracted, mined for its identifier-to-name mapping, and then **deleted**.
#: It is 27.9 MB of MITRE ATT&CK STIX that the ``attack`` and ``attackactors``
#: sources already carry in full from MITRE's own distribution, so caching it
#: would spend ~5% of the corpus on text the corpus has. It passes through the
#: staging tree only because the mapping has to come from somewhere, and
#: re-downloading 28 MB on a later run to rebuild a few kilobytes of labels
#: would be the worse trade.
_ATTACK_BUNDLE = Path("ruleset/mitre/enterprise-attack.json")

#: Documents shorter than this are stubs: a rule that is three lines of
#: grouping with no condition, or a truncated test block.
_MIN_CHARS = 180

#: ``testing/*.ini`` reaches 189 KB and ``rootcheck/db/*.txt`` reaches 376 KB.
#: Training windows are 1024 tokens, so a 376 KB document spends almost all of
#: its windows with no statement of what it is — the same argument
#: :mod:`~training.corpus.sources.payloads` makes for splitting a long page at
#: its own headings. Split on the upstream's own record boundary, never mid-record.
_SPLIT_CHARS = 12_000

#: Fields of an SCA check, grouped by the register their *surface form* belongs
#: to. :class:`~training.corpus.source.Register` is explicitly about surface
#: form — "it is surface form that a BPE learns" — and an SCA check is not one
#: thing: ``condition``/``rules`` is a probe DSL, ``description``/``rationale``/
#: ``impact`` is security writing in sentences, and ``remediation`` is whichever
#: of the two it happens to be in that check (sometimes a bash script with a
#: shebang, sometimes a paragraph telling an administrator what to edit).
#:
#: So the register is measured per document instead of asserted for the tree.
#: This matters more than it looks: the build runs with
#: ``--max-register-multiple 1.6``, DETECTION already sits at 1.60x its target
#: and PROSE at 0.69x, so filing 12 MB of mostly-prose under DETECTION would
#: have the balancer trim 12 MB out of DETECTION — possibly this source's own
#: logtest documents, which are the most valuable thing in it. The rule below is
#: mine and the numbers it produces are printed at build time; anyone who
#: prefers the whole tree filed as DETECTION can delete :func:`_sca_register`.
_SCA_CHECK_FIELDS = ("condition", "rules")
_SCA_PROSE_FIELDS = ("description", "rationale", "impact")

#: What makes a ``remediation`` value code rather than guidance. Deliberately
#: crude and checked against the tree: a shebang, a command substitution, a
#: redirect, or a recognisable utility invocation.
_SHELLISH = re.compile(
    r"#!/|\$\(|\|\||&&|>>|\bsed -|\bgrep -|\bawk |\bchmod \d|\bchown |"
    r"\bsystemctl \w|\bmodprobe |\busermod |\bapt-get |\byum install|"
    r"\bdnf install",
    re.I,
)


def _sca_register(check: dict[str, object], rules: list[object]) -> Register:
    """Whichever of the two registers this check is actually mostly made of.

    Counted in characters over the fields listed above, with ``remediation``
    assigned by :data:`_SHELLISH`. Ties go to DETECTION, because the probe is
    the reason the document exists even when the prose around it is longer.
    """
    probe = len(str(check.get("condition") or "")) + sum(
        len(str(rule)) for rule in rules)
    prose = sum(len(str(check.get(field) or "")) for field in _SCA_PROSE_FIELDS)
    remediation = str(check.get("remediation") or "")
    if _SHELLISH.search(remediation):
        probe += len(remediation)
    else:
        prose += len(remediation)
    return Register.DETECTION if probe >= prose else Register.PROSE

#: One SCA policy may contribute at most this many checks. CIS RHEL-family
#: policies run to about 400, so this does not bite today; it is here so that a
#: future 5,000-check policy cannot become the source. Printed when it fires.
_SCA_PER_POLICY = 600

_RULE_OPEN = re.compile(r"<rule\b", re.I)
_RULE_CLOSE = re.compile(r"</rule\s*>", re.I)
_GROUP_OPEN = re.compile(r"<group\s+name\s*=\s*\"([^\"]*)\"", re.I)
_ATTR = re.compile(r"(\w+)\s*=\s*\"([^\"]*)\"")
_TAG_TEXT = re.compile(r"<(\w+)(?:\s+[^>]*)?>(.*?)</\1\s*>", re.S)
_DECODER_NAME = re.compile(r"<decoder\s+name\s*=\s*\"([^\"]*)\"", re.I)
_INI_CASE = re.compile(r"^\[(?P<title>.+?)\]\s*$", re.M)
_INI_RULE = re.compile(r"^\s*rule\s*=\s*(\d+)\s*$", re.M)
_RCL_ENTRY = re.compile(r"^\[", re.M)

#: The condition tags a Wazuh rule can carry, each with a one-line gloss. The
#: glosses are deliberately mechanical: they name what the tag tests, in
#: English, so that the tag and its meaning co-occur. Nothing is invented about
#: severity bands or scoring, which Wazuh documents elsewhere and which this
#: adapter has no business guessing at.
_CONDITION_GLOSS = {
    "decoded_as": "the line was parsed by the decoder named",
    "if_sid": "the parent rule that must already have matched",
    "if_group": "the rule group that must already have matched",
    "if_matched_sid": "fires only after repeated matches of the rule",
    "if_matched_group": "fires only after repeated matches of the group",
    "match": "the decoded log must contain the literal string",
    "regex": "the decoded log must match the regular expression",
    "program_name": "the syslog program name must match",
    "hostname": "the reporting hostname must match",
    "srcip": "the extracted source address must match",
    "dstip": "the extracted destination address must match",
    "user": "the extracted user name must match",
    "url": "the extracted URL must match",
    "id": "the extracted event id must match",
    "status": "the extracted status code must match",
    "extra_data": "the extracted extra_data field must match",
    "field": "a named decoded field must match",
    "list": "a CDB list lookup that must succeed",
    "srcport": "the extracted source port must match",
    "dstport": "the extracted destination port must match",
    "action": "the extracted action must match",
    "data": "the extracted data field must match",
    "system_name": "the extracted system name must match",
    "location": "the log collector location must match",
    "time": "restricted to this time of day",
    "weekday": "restricted to these days of the week",
    "different_srcip": "requires the matches to come from different addresses",
    "same_source_ip": "requires the matches to come from one address",
    "same_srcip": "requires the matches to come from one address",
    "same_user": "requires the matches to concern one user",
    "same_id": "requires the matches to share an event id",
    "description": "what the rule is for",
    "info": "further reading",
    "options": "rule options",
    "group": "classification and compliance groups",
    "mitre": "the ATT&CK techniques this rule evidences",
}


# --------------------------------------------------------------------------- #
# fetch
# --------------------------------------------------------------------------- #

def _keep(relative: Path) -> bool:
    parts = relative.parts
    if not parts or parts[0] != "ruleset":
        return False
    if len(parts) < 2:
        return False
    if relative == _ATTACK_BUNDLE:
        return True
    tree = parts[1]
    if tree not in _KEEP_TREES:
        return False
    suffix = relative.suffix.lower()
    if tree in ("rules", "decoders"):
        return suffix == ".xml"
    if tree == "testing":
        # tests/*.ini only: runtests.py and coverage.py are the harness, not
        # the corpus, and the ruleset/ subdirectory under testing/ is a copy of
        # the rules for the harness to load.
        return suffix == ".ini" and "tests" in parts
    if tree == "sca":
        return suffix == ".yml"
    if tree == "rootcheck":
        return suffix == ".txt"
    return False


def _technique_names(archive_json: Path) -> dict[str, str]:
    """Pull ``T####`` -> human name out of the vendored ATT&CK STIX bundle.

    The bundle itself is not cached — see the module docstring. This reads it
    once during the fetch and keeps only the mapping, which is a few kilobytes.
    A missing or unreadable bundle is not fatal: the documents are still correct
    without the names, merely less valuable, and failing a 20 MB fetch over a
    label table would be the wrong trade.
    """
    try:
        bundle = json.loads(archive_json.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return {}
    names: dict[str, str] = {}
    for obj in bundle.get("objects", ()):
        if not isinstance(obj, dict) or obj.get("type") != "attack-pattern":
            continue
        name = obj.get("name")
        for ref in obj.get("external_references", ()):
            if (isinstance(ref, dict)
                    and ref.get("source_name") == "mitre-attack"
                    and isinstance(ref.get("external_id"), str)
                    and isinstance(name, str)):
                names[ref["external_id"]] = name
    return names


def _fetch(cache_dir: Path) -> Path:
    """Download the tagged tarball once and keep the ruleset trees.

    Order matters at the end: the ATT&CK bundle is mined for its label table and
    then deleted, and only after that is the marker written. The marker means
    "this cache is finished", so writing it before the delete would leave a run
    that died in between with a 28 MB duplicate in the cache and a marker saying
    everything was fine.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    home = cache_dir / _NAME
    if lib.marker_path(home).is_file():
        return home

    home_dir, meta = lib.extract(
        name=_NAME,
        url=_URL,
        cache_dir=cache_dir,
        keep=_keep,
        licence_files=("LICENSE",),
        max_bytes=_MAX_ARCHIVE_BYTES,
        # 168 rules + 120 decoders + 107 tests + 77 sca + 21 rootcheck + the
        # bundle = 494. A floor well under that catches a renamed tree loudly at
        # fetch time rather than as a mysteriously thin build report.
        min_kept=380,
    )

    bundle = home_dir / _ATTACK_BUNDLE
    names = _technique_names(bundle) if bundle.is_file() else {}
    names_file = home_dir / "names" / "mitre-techniques.json"
    names_file.parent.mkdir(parents=True, exist_ok=True)
    names_file.write_text(json.dumps(names, indent=0, sort_keys=True),
                          encoding="utf-8")
    bundle.unlink(missing_ok=True)
    try:
        bundle.parent.rmdir()
    except OSError:
        pass

    meta["ref"] = _REF
    meta["repo"] = _REPO
    meta["attack_names"] = len(names)
    meta["excluded"] = [
        "ruleset/mitre/enterprise-attack.json — extracted, mined for its "
        "27.9 MB-worth of T####-to-name labels, then DELETED: it is the MITRE "
        "ATT&CK STIX bundle, which the attack and attackactors sources already "
        "carry in full from MITRE's own distribution",
        "ruleset/lists/ (CDB lookup tables, no prose)",
        "ruleset/testing/{runtests,coverage}.py and testing/ruleset/ (harness)",
    ]
    lib.write_marker(home_dir, meta)
    return home_dir


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #

def _rule_blocks(text: str) -> list[str]:
    """Every ``<rule>`` body in ``text``, verbatim, in document order.

    Written as a scanner rather than one regex because the obvious regex is
    wrong in a way that is quiet. ``<rule\\b[^>]*>.*?</rule\\s*>`` applied to a
    self-closing ``<rule id="1" />`` matches the open tag and then runs forward
    to the *next* rule's closing tag, swallowing a whole rule into its
    neighbour. No rule in the current ruleset is self-closing, so the bug would
    not have shown up as a count change — it would have shown up as two rules
    silently fused the first time upstream wrote one.
    """
    blocks: list[str] = []
    for match in _RULE_OPEN.finditer(text):
        start = match.start()
        gt = text.find(">", start)
        if gt == -1:
            continue
        head = text[start:gt + 1]
        if head.rstrip().endswith("/>"):
            blocks.append(head)
            continue
        close = _RULE_CLOSE.search(text, gt + 1)
        if close is None:
            continue
        blocks.append(text[start:close.end()])
    return blocks


def _attrs(block: str) -> dict[str, str]:
    head = block.split(">", 1)[0]
    return {k.lower(): v for k, v in _ATTR.findall(head)}


def _children(block: str) -> list[tuple[str, str]]:
    """Immediate-ish child tags of a rule block, in document order.

    A regex rather than a parser, for the reason the module docstring gives: 8
    of 288 files are not well-formed. Nesting beyond one level does not occur
    inside a Wazuh rule except for ``<mitre><id>``, which is handled by reading
    technique ids out of the raw block instead.
    """
    inner = block.split(">", 1)[1].rsplit("</", 1)[0] if ">" in block else ""
    return [(tag.lower(), text.strip()) for tag, text in _TAG_TEXT.findall(inner)]


def _compliance(groups: str) -> tuple[list[str], list[str]]:
    """Split a Wazuh ``<group>`` value into compliance tags and plain tags.

    Wazuh overloads one comma-separated field with both ``pci_dss_11.4`` and
    ``recon``. Separating them means the compliance identifiers can be printed
    as identifiers — next to the framework they belong to — instead of being
    lost in a tag soup.
    """
    compliance, plain = [], []
    for raw in groups.split(","):
        tag = raw.strip()
        if not tag:
            continue
        if re.match(r"^(pci_dss|nist_800_53|gdpr|gpg13|hipaa|tsc|mitre|"
                    r"cis|nist|soc)", tag, re.I):
            compliance.append(tag)
        else:
            plain.append(tag)
    return compliance, plain


def _render_rule(block: str, *, file: str, group: str,
                 names: dict[str, str]) -> tuple[str, str] | None:
    attrs = _attrs(block)
    rule_id = attrs.get("id", "")
    if not rule_id:
        return None
    level = attrs.get("level", "")
    children = _children(block)
    by_tag = {tag: text for tag, text in children}
    description = by_tag.get("description", "").strip().replace("\n", " ")
    description = re.sub(r"\s{2,}", " ", description)

    head = [f"Wazuh rule {rule_id}"
            + (f", alert level {level}" if level else "")
            + (f" — {description}" if description else "")]
    head.append(f"Ruleset file: {file}")
    if group:
        head.append(f"Rule file group: {group}")
    if level == "0":
        head.append("Level 0: the rule matches and groups other rules but "
                    "raises no alert of its own.")
    for key in ("frequency", "timeframe", "ignore", "overwrite", "noalert"):
        if key in attrs:
            head.append(f"Rule attribute {key}: {attrs[key]}")

    # Only the <mitre> block, never the whole rule. A Wazuh ``<id>`` tag is the
    # extracted *event* id — ``<id>^4625$</id>`` — and a rule description is
    # free text, so widening the search to the body invites a T-shaped string
    # from somewhere else being reported as a technique mapping.
    techniques = lib.attack_ids(*(t for tag, t in children if tag == "mitre"))
    if techniques:
        head.append("MITRE ATT&CK: " + ", ".join(
            f"{tid} {names[tid]}" if tid in names else tid
            for tid in techniques))

    compliance, plain = _compliance(by_tag.get("group", ""))
    if compliance:
        head.append("Compliance mapping: " + ", ".join(compliance))
    if plain:
        head.append("Classification groups: " + ", ".join(plain))

    conditions = [
        f"  {tag}: {_CONDITION_GLOSS[tag]} — {text}"
        for tag, text in children
        if tag in _CONDITION_GLOSS
        and tag not in ("description", "group", "mitre", "info")
        and text
    ]
    if conditions:
        head.append("Conditions:")
        head.extend(conditions)

    head.append("")
    head.append("Rule definition, verbatim:")
    return rule_id, "\n".join(head) + "\n" + block


def _rules(home: Path, names: dict[str, str]
           ) -> tuple[list[Document], dict[str, tuple[str, list[str]]]]:
    """Every rule as a document, plus an id -> (description, techniques) index.

    The index is what makes the logtest documents worth having: a test case says
    ``rule = 5739`` and nothing else, and resolving that to "sshd: Could not
    stat AuthorizedKeysCommand" plus its techniques is the join.
    """
    docs: list[Document] = []
    index: dict[str, tuple[str, list[str]]] = {}
    root = home / "ruleset" / "rules"
    for path in lib.walk_files(root, (".xml",)):
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = path.relative_to(home / "ruleset").as_posix()
        groups = _GROUP_OPEN.findall(raw)
        group = groups[0] if len(groups) == 1 else ", ".join(groups)
        clean = lib.scrub(raw)
        for block in _rule_blocks(clean):
            rendered = _render_rule(block, file=f"ruleset/{rel}", group=group,
                                    names=names)
            if rendered is None:
                continue
            rule_id, text = rendered
            by_tag = {t: x for t, x in _children(block)}
            index[rule_id] = (
                re.sub(r"\s+", " ", by_tag.get("description", "")).strip(),
                lib.attack_ids(by_tag.get("mitre")),
            )
            text = normalise(text)
            if len(text) < _MIN_CHARS:
                continue
            ident = f"rules/{Path(rel).name}#{rule_id}"
            lib.assert_scrubbed(_NAME, ident, text)
            docs.append(Document(text=text, source=_NAME,
                                 register=Register.DETECTION, side=Side.BLUE,
                                 ident=ident))
    return docs, index


def _decoders(home: Path) -> list[Document]:
    """One document per decoder file.

    Per *file* rather than per ``<decoder>`` on purpose. A decoder file is a
    family — ``sshd``, ``sshd-success``, ``sshd-failed`` — and it opens with a
    comment block of real example log lines the whole family was written
    against. Splitting per element would separate forty example lines from the
    thirty-line regex that parses them, which is the one join this file exists
    to supply.
    """
    docs: list[Document] = []
    root = home / "ruleset" / "decoders"
    for path in lib.walk_files(root, (".xml",)):
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = path.relative_to(home / "ruleset").as_posix()
        clean = lib.scrub(raw)
        decoders = _DECODER_NAME.findall(clean)
        head = [
            f"Wazuh decoder family: {', '.join(decoders) or Path(rel).stem}",
            f"Ruleset file: ruleset/{rel}",
            "A Wazuh decoder turns one raw log line into named fields. "
            "`program_name` and `prematch` select which lines it applies to, "
            "`regex` captures, and `order` names the captured fields in the "
            "order they were captured. Rules then match on those field names, "
            "not on the raw text.",
            "",
            "Decoder definitions, verbatim (the comment block holds the "
            "example log lines the regexes were written against):",
        ]
        text = normalise("\n".join(head) + "\n" + clean)
        if len(text) < _MIN_CHARS:
            continue
        ident = f"decoders/{Path(rel).name}"
        lib.assert_scrubbed(_NAME, ident, text)
        docs.append(Document(text=text, source=_NAME,
                             register=Register.DETECTION, side=Side.BLUE,
                             ident=ident))
    return docs


def _split_on(raw: str, boundary: re.Pattern[str], limit: int) -> list[str]:
    """Cut ``raw`` into chunks under ``limit``, only at ``boundary`` matches.

    Never mid-record: a logtest case split between its ``log`` line and its
    ``rule =`` line would train the model on a log line with no verdict, which
    is worse than not having the case at all.
    """
    starts = [m.start() for m in boundary.finditer(raw)]
    if not starts or len(raw) <= limit:
        return [raw]
    chunks: list[str] = []
    current = raw[: starts[0]]
    for i, start in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else len(raw)
        record = raw[start:end]
        if current and len(current) + len(record) > limit:
            chunks.append(current)
            current = raw[: starts[0]] + record
        else:
            current += record
    if current.strip():
        chunks.append(current)
    return chunks


def _logtests(home: Path, index: dict[str, tuple[str, list[str]]],
              names: dict[str, str]) -> list[Document]:
    """The labelled log lines, with a legend resolving every rule id referenced.

    This is the shape of data the corpus is most short of: a raw line of real
    log text with the correct reading attached. The ``.ini`` body is kept
    verbatim because its three-line form (``log 1 pass = <line>`` /
    ``rule = N`` / ``alert = L`` / ``decoder = D``) is a compact labelled
    record, and a prose header explains what that form asserts — without it
    ``log 1 pass =`` is opaque and the label teaches nothing.
    """
    docs: list[Document] = []
    root = home / "ruleset" / "testing"
    for path in lib.walk_files(root, (".ini",)):
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = path.relative_to(home / "ruleset").as_posix()
        clean = lib.scrub(raw)
        product = Path(rel).stem
        for part, chunk in enumerate(
                _split_on(clean, _INI_CASE, _SPLIT_CHARS), start=1):
            cases = _INI_CASE.findall(chunk)
            if not cases:
                continue
            head = [
                f"Wazuh logtest cases: {product}"
                + (f" (part {part})" if part > 1 else ""),
                f"Ruleset file: ruleset/{rel}",
                f"{len(cases)} case(s). Each case asserts how one real log "
                "line must be read: `log N pass = <line>` is the raw text, "
                "`decoder` is the decoder that must parse it, `rule` is the "
                "rule id that must fire, and `alert` is the level that rule "
                "raises. A `fail` line is text that must NOT match.",
                "",
            ]
            legend: list[str] = []
            for rule_id in dict.fromkeys(_INI_RULE.findall(chunk)):
                description, techniques = index.get(rule_id, ("", []))
                if not description and not techniques:
                    continue
                labelled = ", ".join(
                    f"{tid} {names[tid]}" if tid in names else tid
                    for tid in techniques)
                legend.append(
                    f"  rule {rule_id}: {description}"
                    + (f"  [ATT&CK {labelled}]" if labelled else ""))
            body = ["Cases, verbatim:", "", chunk.strip()]
            if legend:
                body += ["", "What each referenced rule means:", *legend]
            text = normalise("\n".join(head + body))
            if len(text) < _MIN_CHARS:
                continue
            ident = f"testing/{Path(rel).name}#{part}"
            lib.assert_scrubbed(_NAME, ident, text)
            docs.append(Document(text=text, source=_NAME,
                                 register=Register.DETECTION, side=Side.BLUE,
                                 ident=ident))
    return docs


def _sca_compliance(entries: object) -> list[str]:
    """Flatten SCA's list-of-single-key-dicts compliance block.

    ``[{'cis': ['1.1.1.1']}, {'mitre_techniques': ['T1005']}, ...]``. Each
    framework is printed with its own identifiers so that ``M1050`` appears as
    a mitigation id rather than as a bare number in a list.
    """
    out: list[str] = []
    if not isinstance(entries, list):
        return out
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for framework, values in entry.items():
            items = values if isinstance(values, list) else [values]
            pretty = ", ".join(str(v) for v in items if v is not None)
            if pretty:
                out.append(f"  {framework}: {pretty}")
    return out


def _sca(home: Path, names: dict[str, str]) -> tuple[list[Document], dict[str, int]]:
    """One document per SCA check, de-duplicated across policies.

    The dedup is the whole design. CIS benchmarks are copied from distro to
    distro — ``cis_alma_linux_10`` says in its own header that it is based on
    the Alma Linux 9 benchmark — and the measurement is blunt: 11,352 checks
    across 77 policies collapse to 6,039 distinct ones, a 46.8% duplicate rate,
    with one check appearing sixteen times. ``build.py``'s corpus-wide
    fingerprint cannot see any of it, because each rendered document carries its
    own policy name in the header and is therefore a distinct document. So it is
    done here, on the check body, before the header is attached.
    """
    docs: list[Document] = []
    seen: set[str] = set()
    stats = {"checks": 0, "duplicates": 0, "capped": 0, "policies": 0,
             "with_attack": 0}
    root = home / "ruleset" / "sca"
    for path in lib.walk_files(root, (".yml", ".yaml")):
        try:
            parsed = yaml.safe_load(path.read_text(encoding="utf-8",
                                                   errors="replace"))
        except (OSError, yaml.YAMLError):
            continue
        if not isinstance(parsed, dict):
            continue
        policy = parsed.get("policy") or {}
        if not isinstance(policy, dict):
            policy = {}
        checks = parsed.get("checks")
        if not isinstance(checks, list):
            continue
        stats["policies"] += 1
        rel = path.relative_to(home / "ruleset").as_posix()
        emitted_here = 0
        for check in checks:
            if not isinstance(check, dict):
                continue
            stats["checks"] += 1
            rules = check.get("rules")
            rules = rules if isinstance(rules, list) else []
            key = lib.dedup_key(check.get("title"), check.get("rationale"),
                                check.get("remediation"),
                                check.get("condition"), rules)
            if key in seen:
                stats["duplicates"] += 1
                continue
            if emitted_here >= _SCA_PER_POLICY:
                stats["capped"] += 1
                continue
            seen.add(key)
            emitted_here += 1

            compliance = _sca_compliance(check.get("compliance"))
            techniques = lib.attack_ids(check.get("compliance"))
            if techniques:
                stats["with_attack"] += 1
            head = [
                f"Wazuh SCA check {check.get('id', '?')}: "
                f"{check.get('title', '').strip()}",
                f"Policy: {policy.get('name') or Path(rel).stem}",
                f"Ruleset file: ruleset/{rel}",
            ]
            if techniques:
                head.append("MITRE ATT&CK: " + ", ".join(
                    f"{tid} {names[tid]}" if tid in names else tid
                    for tid in techniques))
            for label, field in (("Description", "description"),
                                 ("Rationale", "rationale"),
                                 ("Impact", "impact"),
                                 ("Remediation", "remediation")):
                value = check.get(field)
                if isinstance(value, str) and value.strip():
                    head.append(f"{label}: {value.strip()}")
            if compliance:
                head.append("Compliance mapping:")
                head.extend(compliance)
            head.append("")
            head.append(
                "Check logic. `condition` says how the rules combine (all / "
                "any / none). Each rule is a probe and the pattern its result "
                "must match: `c:` runs a command and matches its output, `f:` "
                "reads a file, `d:` walks a directory, `p:` looks for a "
                "process, `r:` is the pattern, and a leading `not` inverts.")
            head.append(f"condition: {check.get('condition', '')}")
            head.append("rules:")
            head.extend(f"  - {rule}" for rule in rules)

            # Scrubbed after rendering rather than before: the input here is
            # parsed YAML, so there are no comment lines to strip, but the
            # assertion below is run on every document in this family and it
            # must have something to assert about. A render that is exempt from
            # the redaction pass is how the one document with an address in it
            # gets through.
            text = normalise(lib.scrub("\n".join(head)))
            if len(text) < _MIN_CHARS:
                continue
            ident = f"sca/{Path(rel).stem}#{check.get('id', len(docs))}"
            lib.assert_scrubbed(_NAME, ident, text)
            register = _sca_register(check, rules)
            stats[f"register_{register.value}"] = (
                stats.get(f"register_{register.value}", 0) + 1)
            docs.append(Document(text=text, source=_NAME,
                                 register=register, side=Side.BLUE,
                                 ident=ident))
    return docs, stats


def _rootcheck(home: Path) -> list[Document]:
    """The legacy rootcheck policy and rootkit signature files.

    A different check language again — ``[name] [any] [] f:/etc/passwd ->
    !r:^root;`` — and the rootkit files are a signature list of paths and
    trojaned-binary strings. Small (920 KB) and nothing else in the corpus
    carries the RCL syntax.
    """
    docs: list[Document] = []
    root = home / "ruleset" / "rootcheck"
    for path in lib.walk_files(root, (".txt",)):
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = path.relative_to(home / "ruleset").as_posix()
        clean = lib.scrub(raw)
        for part, chunk in enumerate(
                _split_on(clean, _RCL_ENTRY, _SPLIT_CHARS), start=1):
            head = [
                f"Wazuh rootcheck policy file: {Path(rel).stem}"
                + (f" (part {part})" if part > 1 else ""),
                f"Ruleset file: ruleset/{rel}",
                "Rootcheck's own check language: `[title] [condition] "
                "[reference]` then one or more probes. `f:` is a file, `d:` a "
                "directory, `p:` a running process, `r:` a pattern over the "
                "contents, and `!` negates. A rootkit file instead lists "
                "known-bad paths or strings, one per line.",
                "",
            ]
            text = normalise("\n".join(head) + "\n" + chunk.strip())
            if len(text) < _MIN_CHARS:
                continue
            ident = f"rootcheck/{Path(rel).name}#{part}"
            lib.assert_scrubbed(_NAME, ident, text)
            docs.append(Document(text=text, source=_NAME,
                                 register=Register.DETECTION, side=Side.BLUE,
                                 ident=ident))
    return docs


def _documents(path: Path) -> Iterator[Document]:
    home = path if (path / "ruleset").is_dir() else path / _NAME
    if not (home / "ruleset").is_dir():
        raise SourceError(
            f"{_NAME}: no ruleset/ under {home} — the cache is not populated")

    names_file = home / "names" / "mitre-techniques.json"
    names: dict[str, str] = {}
    if names_file.is_file():
        try:
            loaded = json.loads(names_file.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                names = {k: v for k, v in loaded.items() if isinstance(v, str)}
        except (OSError, ValueError):
            names = {}

    rules, index = _rules(home, names)
    decoders = _decoders(home)
    logtests = _logtests(home, index, names)
    sca, sca_stats = _sca(home, names)
    rootcheck = _rootcheck(home)

    print(f"   {_NAME}: {len(rules)} rules, {len(decoders)} decoder families, "
          f"{len(logtests)} logtest documents, {len(sca)} SCA checks, "
          f"{len(rootcheck)} rootcheck documents")
    if sca_stats["checks"]:
        rate = sca_stats["duplicates"] / sca_stats["checks"] * 100
        print(f"   {_NAME}: SCA {sca_stats['checks']} checks across "
              f"{sca_stats['policies']} policies, {sca_stats['duplicates']} "
              f"dropped as duplicates ({rate:.1f}%) — CIS benchmarks are copied "
              f"between distributions; {sca_stats['with_attack']} carry an "
              f"ATT&CK technique")
        print(f"   {_NAME}: SCA register measured per document — "
              f"{sca_stats.get('register_detection', 0)} detection, "
              f"{sca_stats.get('register_prose', 0)} prose (a check whose "
              f"rationale and guidance outweigh its probe is security writing "
              f"in sentences, and filing it as DETECTION would misreport the "
              f"one report that matters)")
        if sca_stats["capped"]:
            print(f"   {_NAME}: SCA per-policy cap of {_SCA_PER_POLICY} dropped "
                  f"{sca_stats['capped']} further checks")
    if not names:
        print(f"   {_NAME}: no ATT&CK name table in the cache; technique ids "
              f"are emitted bare")

    yield from rules
    yield from decoders
    yield from logtests
    yield from sca
    yield from rootcheck


SPEC = SourceSpec(
    name=_NAME,
    license=(
        "GPL-2.0-only — wazuh/wazuh at tag v4.14.8, read from the repository's "
        "own LICENSE inside the fetched archive and copied into the cache under "
        "licenses/, not taken from a badge (GitHub reports NOASSERTION for this "
        "repository). The file states: \"This program is free software; you can "
        "redistribute it and/or modify it under the terms of the GNU General "
        "Public License (version 2) as published by the FSF - Free Software "
        "Foundation\", and settles the question of whether rule data is covered: "
        "\"Note that this license applies to the source code, as well as "
        "decoders, rules and any other data file included with Wazuh (unless "
        "otherwise specified).\" Strong copyleft, taken knowingly, as gtfobins "
        "(GPL-3.0) and one of yara's collections (GPL-2.0) already are. "
        "Copyright holders named in the tree are corporate throughout — "
        "Wazuh Inc., Trend Micro Inc. (the OSSEC lineage) and InfoDefense Inc. "
        "— and those notices are preserved verbatim in every rule body. "
        "Per-contributor Author: credit lines are NOT preserved: they are "
        "personal names and personal email addresses of named individuals, they "
        "carry no detection signal, and the upstream that holds the full credit "
        "is cited in every document header. ALSO: technique names printed beside "
        "ATT&CK ids come from the MITRE ATT&CK bundle this repository vendors, "
        "and are used under MITRE's Terms of Use — \"(c) 2026 The MITRE "
        "Corporation. This work is reproduced and distributed with the "
        "permission of The MITRE Corporation.\" ATT&CK is a registered trademark "
        "of The MITRE Corporation; terms at "
        "https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. "
        "The bundle itself is not cached or emitted — the attack source already "
        "carries it from MITRE's own distribution."
    ),
    url=f"https://github.com/{_REPO}/tree/{_REF}/ruleset",
    register=Register.DETECTION,
    side=Side.BLUE,
    fetch=_fetch,
    documents=_documents,
    #: Measured on v4.14.8: 4,515 rules, 120 decoder families, ~110 logtest
    #: documents, ~6,000 SCA checks after a 46.8% duplicate drop, ~40 rootcheck
    #: documents. The floor sits well below that so ordinary ruleset churn is
    #: quiet, while the realistic regressions — a renamed tree, a block scanner
    #: that stops matching, a YAML schema change — trip it immediately.
    expect_min_docs=6000,
    #: One 20 MB tarball plus a 28 MB JSON parse on the first run only.
    timeout=900,
    notes=(
        "Wazuh's 4.x ruleset at a pinned release tag, as five document kinds. "
        "Rules: one per <rule> block, cut out by a block scanner rather than an "
        "XML parser because 8 of 288 files are not well-formed (bare & and < in "
        "regexes), with the body verbatim under a header giving the alert level, "
        "the correlation parents, the ATT&CK technique ids beside their names, "
        "the compliance mappings split out of Wazuh's overloaded <group> field, "
        "and a one-line gloss for each condition tag. Decoders: one document per "
        "file, so the comment block of real example log lines stays attached to "
        "the regexes written against it. Logtest cases: 1,564 assertions that a "
        "given raw log line must be parsed by a named decoder and must fire a "
        "named rule at a named level — the scarcest shape of data in this corpus, "
        "a line of output with the correct reading attached — rendered with a "
        "legend resolving every referenced rule id to its description and "
        "techniques. SCA: one document per Security Configuration Assessment "
        "check, de-duplicated on the check body because CIS benchmarks are "
        "copied between distributions (11,352 checks collapse to 6,039, a 46.8% "
        "duplicate rate, one check appearing 16 times), carrying the command and "
        "the pattern its output must match, the remediation, and the "
        "mitre_mitigations/mitre_techniques mapping that is the defending half "
        "this project has never trained on. Rootcheck: the legacy RCL check "
        "language and the rootkit signature lists. Not taken: "
        "ruleset/mitre/enterprise-attack.json, 27.9 MB of MITRE STIX the attack "
        "source already carries (only the id-to-name mapping is kept), "
        "ruleset/lists/ CDB lookup tables, and the test harness. Author: comment "
        "lines are stripped and every document is proved free of addresses and "
        "attributions before it is emitted; the ~600 SSH algorithm names that "
        "are email-shaped (hmac-sha2-512-etm@openssh.com) are kept, because in "
        "sshd rules they are the signal."
    ),
)
