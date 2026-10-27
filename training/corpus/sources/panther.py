"""Panther detections — detection as Python, with labelled events. DETECTION/BLUE.

This is the source that most directly answers the thing the owner asked for and
the thing the corpus is measurably worst at. The brief was explicit: the single
biggest real win is **reading command output**, the corpus has plenty of usage
text and very little output text, and parsing messy output is what the runtime
does on every step. A Panther detection is, in one directory, three things that
belong together and are almost never published together:

**The decision, written in Python.** Not a rule DSL — a function::

    def rule(event):
        if not (aws_cloudtrail_success(event)
                and event.get("eventSource") == "lambda.amazonaws.com"
                and event.deep_get("responseElements", "layers")):
            return False
        identity_type = event.deep_get("userIdentity", "type", default="")
        ...

Control flow, early returns, a default when a key is missing, string methods on
a role name. Every other detection source in this corpus is declarative, and a
declarative rule cannot express "unless the assumed role's name starts with
``AWSReservedSSO_``". The corpus has a great deal of Python
(:mod:`~training.corpus.sources.pythoncode`) and a great deal of detection, and
nowhere until now has it had detection *as* Python.

**The events, with the right answer attached.** Every detection ships a
``Tests:`` block, and each test is a complete log event — real-shaped CloudTrail,
Okta, GitHub, Zoom, Crowdstrike, Kubernetes audit JSON — beside an
``ExpectedResult: true`` or ``false``. That is a labelled reading task, and the
*negative* cases are the half that is hard to find anywhere: "this is the same
API call made by a CI role, and it is fine." Both polarities are kept
deliberately; see :data:`_TESTS_PER_DETECTION`.

**The technique, the severity and the runbook.** ``Reports:`` carries
``MITRE ATT&CK: [TA0007:T1078]`` — tactic and technique in one token — plus CIS
and PCI identifiers, and ``Runbook:`` is what a responder should do next.

**Licence: Apache-2.0.** Read from the repository's own ``LICENSE.txt`` — note
the extension; ``LICENSE`` is a 404 on this repository and the first check for
it failed, which is the whole argument for reading the file rather than trusting
a badge. The text is the standard Apache License 2.0 closing with "Copyright
2023 Panther Labs, Inc.".

**Privacy, measured.** 402 distinct email-shaped tokens across 2,360
occurrences, and not one of them is a real person: ``user@example.com``,
``admin@example.com``, ``homer.simpson@duff.com``, ``peregrin.took@hobbiton.co``,
``jet.black@issp.com``. Fictional characters and reserved documentation domains,
which is what a good test fixture looks like. The uniform sweep is still applied
— the RFC 2606 reserved domains survive as provably-not-a-person, and
``duff.com`` does not, because somebody really owns it and "looks fictional" is
not a property code can check. There are zero author fields in this tree.

**The agent-instruction files are excluded, by name.** This repository ships
``AGENTS.md``, ``CLAUDE.md`` and a ``.claude/`` directory: documents whose
content is instructions addressed to an AI coding agent. They are off-register
for a detection corpus, and putting text that is shaped like a command to a
model into that model's training data is a bad idea on its own terms.
:mod:`~training.corpus.sources.owasp` set this precedent for the same files and
the same reason; it is followed here rather than rediscovered.

**What else is not taken.** ``packs/`` are generated lists of detection ids;
``lookup_tables/`` and ``indexes/`` are configuration; ``templates/`` is a
skeleton with the body left blank; ``test_scenarios/`` and ``style_guides/`` are
contributor documentation. ``global_helpers/`` and ``data_models/`` **are**
taken, filed as SYSTEM rather than DETECTION: a helper module is library code
and a data model is a field mapping, and a rule that calls
``aws_cloudtrail_success(event)`` or ``event.udm("actor_user")`` is unreadable
without them.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterator

import yaml

from ..source import Document, Register, Side, SourceError, SourceSpec, normalise
from . import _detectionlib as lib

_NAME = "panther"
_REPO = "panther-labs/panther-analysis"
_REF = "develop"
_URL = lib.codeload_url(_REPO, _REF)

#: Measured: 1,725,976 bytes for the whole tarball.
_MAX_ARCHIVE_BYTES = 64 * 1024 * 1024

_MIN_CHARS = 300

#: Directories collected, and the register each contributes. ``rules/`` and
#: ``policies/`` and ``queries/`` are detections; the other two are the
#: vocabulary those detections are written in.
_TREES: dict[str, Register] = {
    "rules": Register.DETECTION,
    "policies": Register.DETECTION,
    "queries": Register.DETECTION,
    "correlation_rules": Register.DETECTION,
    "global_helpers": Register.SYSTEM,
    "data_models": Register.SYSTEM,
}

#: Excluded by name, not by content gate. The first three are instructions
#: addressed to an AI agent — see the module docstring.
_EXCLUDE_NAMES = frozenset({"AGENTS.md", "CLAUDE.md"})
_EXCLUDE_DIRS = frozenset({".claude", ".github", ".scripts", ".vscode", ".img",
                           "packs", "lookup_tables", "indexes", "templates",
                           "test_scenarios", "style_guides"})

#: How many ``Tests:`` entries one detection contributes. Upstream reaches a
#: dozen, and ten CloudTrail events differing in one field teach the model that
#: CloudTrail events are long rather than that this detection is subtle. Four,
#: chosen to keep **both polarities**: a positive case says what the technique
#: looks like and a negative case says what the benign version of the same API
#: call looks like, and the second is far harder to find published anywhere.
_TESTS_PER_DETECTION = 4

#: ``TA0007:T1078`` — Panther packs the tactic and the technique into one token.
_REPORT_PAIR = re.compile(r"^(TA\d{4}):(T\d{4}(?:\.\d{3})?)$")

#: Keys that hold the detection's identifier, in the order they are tried.
_ID_KEYS = ("RuleID", "PolicyID", "QueryName", "GlobalID", "DataModelID",
            "AnalysisType")


def _keep(relative: Path) -> bool:
    parts = relative.parts
    if not parts:
        return False
    if parts[0] not in _TREES:
        return False
    if relative.name in _EXCLUDE_NAMES:
        return False
    if any(part in _EXCLUDE_DIRS for part in parts):
        return False
    return relative.suffix in (".yml", ".yaml", ".py")


def _fetch(cache_dir: Path) -> Path:
    cache_dir.mkdir(parents=True, exist_ok=True)
    home = cache_dir / _NAME
    if lib.marker_path(home).is_file():
        return home
    home_dir, meta = lib.extract(
        name=_NAME, url=_URL, cache_dir=cache_dir, keep=_keep,
        # LICENSE.txt, not LICENSE. Reading the file rather than trusting the
        # badge is the rule; this repository is why.
        licence_files=("LICENSE.txt",), max_bytes=_MAX_ARCHIVE_BYTES,
        min_kept=1200,
    )
    meta["ref"] = _REF
    meta["repo"] = _REPO
    meta["excluded"] = [
        "AGENTS.md, CLAUDE.md and .claude/ — instructions addressed to an AI "
        "agent: off-register, and text shaped like a command to a model does "
        "not belong in that model's training data",
        *(sorted(_EXCLUDE_DIRS - {".claude"})),
    ]
    lib.write_marker(home_dir, meta)
    return home_dir


def _reports(reports: object) -> list[str]:
    """Render ``Reports:`` so each identifier sits beside its framework."""
    out: list[str] = []
    if not isinstance(reports, dict):
        return out
    for framework, values in reports.items():
        items = values if isinstance(values, list) else [values]
        rendered: list[str] = []
        for value in items:
            token = str(value)
            pair = _REPORT_PAIR.match(token)
            if pair:
                # Split so that both identifiers are readable as identifiers.
                # "TA0007:T1078" appears nowhere in the world outside Panther's
                # own YAML, and emitting it unsplit would teach a shape that is
                # wrong everywhere else — the same argument capec makes about
                # Entry_ID="1574.010".
                rendered.append(f"{pair.group(2)} (tactic {pair.group(1)})")
            else:
                rendered.append(token)
        if rendered:
            out.append(f"  {framework}: {', '.join(rendered)}")
    return out


def _select_tests(tests: object) -> tuple[list[dict], int]:
    """Up to :data:`_TESTS_PER_DETECTION` tests, balanced across polarities."""
    if not isinstance(tests, list):
        return [], 0
    entries = [t for t in tests if isinstance(t, dict)]
    positive = [t for t in entries if t.get("ExpectedResult") is True]
    negative = [t for t in entries if t.get("ExpectedResult") is False]
    other = [t for t in entries
             if t.get("ExpectedResult") not in (True, False)]
    half = max(1, _TESTS_PER_DETECTION // 2)
    chosen = positive[:half] + negative[:half]
    if len(chosen) < _TESTS_PER_DETECTION:
        pool = positive[half:] + negative[half:] + other
        chosen += pool[: _TESTS_PER_DETECTION - len(chosen)]
    return chosen, max(0, len(entries) - len(chosen))


def _render_event(log: object) -> str:
    """The test's event, as JSON, indented and stable.

    Re-serialised rather than kept verbatim, because upstream writes these as
    YAML flow-mapping blocks whose indentation is an artefact of the YAML file
    rather than of the event. Keys keep their source order (``sort_keys`` is
    off): an event is a record and the order a provider emits its fields in is
    part of what the record looks like.
    """
    if isinstance(log, str):
        return log.strip()
    try:
        return json.dumps(log, indent=2, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(log)


def _render_detection(meta: dict, code: str | None, relative: Path) -> str:
    kind = str(meta.get("AnalysisType", "detection"))
    identifier = next((str(meta[key]) for key in _ID_KEYS
                       if isinstance(meta.get(key), str)), relative.stem)
    display = str(meta.get("DisplayName") or "").strip()

    head = [f"Panther {kind}: {identifier}"
            + (f" — {display}" if display else "")]
    head.append(f"Detection file: {relative.as_posix()}")
    for label, key in (("Severity", "Severity"),
                       ("Enabled by default", "Enabled"),
                       ("Log types", "LogTypes"),
                       ("Resource types", "ResourceTypes"),
                       ("Schedule", "ScheduledQueries"),
                       ("Tags", "Tags")):
        value = meta.get(key)
        if isinstance(value, list):
            rendered = ", ".join(str(v) for v in value)
        elif value is None:
            rendered = ""
        else:
            rendered = str(value)
        if rendered:
            head.append(f"{label}: {rendered}")

    reports = _reports(meta.get("Reports"))
    if reports:
        head.append("Framework mappings:")
        head.extend(reports)

    for label, key in (("Description", "Description"),
                       ("Runbook", "Runbook"),
                       ("Reference", "Reference")):
        value = meta.get(key)
        if isinstance(value, str) and value.strip():
            head.append(f"{label}: {re.sub(r'[ \t]*\n[ \t]*', ' ', value).strip()}")

    query = meta.get("Query")
    if isinstance(query, str) and query.strip():
        head += ["",
                 "Scheduled query. This SQL runs against the data lake on a "
                 "schedule and its rows are what the detection then examines:",
                 "", query.rstrip()]

    if code:
        head += ["",
                 "Detection logic, verbatim Python. `rule(event)` returns True "
                 "when the event is a detection; `title(event)` and "
                 "`alert_context(event)` shape the alert. `event.get(...)`, "
                 "`event.deep_get(path...)` and `event.udm(field)` read the "
                 "event — deep_get walks nested keys with a default, and udm "
                 "reads a field through the data model that normalises it "
                 "across log sources:",
                 "", code.rstrip()]

    tests, dropped = _select_tests(meta.get("Tests"))
    if tests:
        head += ["",
                 "Worked examples. Each is a complete event of the log type "
                 "above, with the verdict this detection must return for it. "
                 "The False cases matter as much as the True ones: they are "
                 "the same API call made legitimately."]
        if dropped:
            head.append(f"({dropped} further test case(s) upstream are not "
                        f"reproduced here.)")
        for test in tests:
            expected = test.get("ExpectedResult")
            verdict = ("DETECTION (returns True)" if expected is True
                       else "NOT A DETECTION (returns False)"
                       if expected is False else f"expected {expected!r}")
            head += ["",
                     f"Case: {str(test.get('Name', '')).strip() or '(unnamed)'}",
                     f"Expected verdict: {verdict}",
                     "Event:",
                     _render_event(test.get("Log", test.get("Resource")))]
    return "\n".join(head)


def _render_module(code: str, relative: Path) -> str:
    return "\n".join([
        f"Panther helper module: {relative.stem}",
        f"File: {relative.as_posix()}",
        "A global helper is imported by name from any detection in this "
        "repository. Detections call these instead of repeating the field "
        "paths of a log source, so a helper is the operational definition of "
        "what a detection means by 'successful', 'from a human' or 'in "
        "production'.",
        "",
        "Source, verbatim:",
        "",
        code.rstrip(),
    ])


def _documents(path: Path) -> Iterator[Document]:
    home = path if (path / "rules").is_dir() else path / _NAME
    if not (home / "rules").is_dir():
        raise SourceError(
            f"{_NAME}: no rules/ under {home} — the cache is not populated")

    counts: dict[str, int] = {}
    tests_kept = tests_dropped = 0
    paired = orphan = 0

    for file in lib.walk_files(home, (".yml", ".yaml")):
        relative = file.relative_to(home)
        if not _keep(relative):
            continue
        try:
            meta = yaml.safe_load(file.read_text(encoding="utf-8",
                                                 errors="replace"))
        except (OSError, yaml.YAMLError):
            continue
        if not isinstance(meta, dict):
            continue

        code: str | None = None
        filename = meta.get("Filename")
        if isinstance(filename, str) and filename:
            sibling = file.parent / filename
            # Resolved and proved to stay inside the cache: ``Filename`` is a
            # value out of a downloaded file, and a value out of a downloaded
            # file that is used to build a path is a path traversal unless
            # somebody checks.
            try:
                inside = sibling.resolve().is_relative_to(home.resolve())
            except OSError:
                inside = False
            if inside and sibling.is_file():
                try:
                    code = sibling.read_text(encoding="utf-8", errors="replace")
                    paired += 1
                except OSError:
                    code = None
            else:
                orphan += 1

        tests, dropped = _select_tests(meta.get("Tests"))
        tests_kept += len(tests)
        tests_dropped += dropped

        register = _TREES[relative.parts[0]]
        if register is Register.SYSTEM and code is not None:
            text = _render_module(code, relative)
        else:
            text = _render_detection(meta, code, relative)
        text = normalise(lib.scrub(text))
        if len(text) < _MIN_CHARS:
            continue
        ident = relative.as_posix()
        lib.assert_scrubbed(_NAME, ident, text)
        kind = str(meta.get("AnalysisType", relative.parts[0]))
        counts[kind] = counts.get(kind, 0) + 1
        yield Document(text=text, source=_NAME, register=register,
                       side=Side.BLUE, ident=ident)

    summary = ", ".join(f"{n} {k}" for k, n in sorted(counts.items(),
                                                      key=lambda kv: -kv[1]))
    print(f"   {_NAME}: {summary}")
    print(f"   {_NAME}: {paired} detections paired with their Python sibling, "
          f"{orphan} naming a Filename that is not in the cache; "
          f"{tests_kept} worked examples kept (cap {_TESTS_PER_DETECTION} per "
          f"detection, balanced across True/False), {tests_dropped} further "
          f"upstream test cases not reproduced")


SPEC = SourceSpec(
    name=_NAME,
    license=(
        "Apache-2.0 — panther-labs/panther-analysis, read from the "
        "repository's own LICENSE.txt inside the fetched archive and copied "
        "into the cache under licenses/. The extension is worth recording: "
        "LICENSE (no extension) is a 404 on this repository and the first "
        "attempt to read it failed, which is exactly why the rule here is to "
        "read the file rather than believe a badge. The text is the standard "
        "Apache License 2.0 closing with \"Copyright 2023 Panther Labs, "
        "Inc.\" — collective corporate attribution, which is what section 4(c) "
        "asks to be retained, and there are no per-detection author fields in "
        "this tree. Measured on the test fixtures: 402 distinct email-shaped "
        "tokens over 2,360 occurrences and not one belongs to a real person — "
        "RFC 2606 reserved domains and fictional characters (user@example.com, "
        "homer.simpson@duff.com, peregrin.took@hobbiton.co). The uniform sweep "
        "still runs: reserved domains survive as provably not a mailbox, and "
        "the fictional ones at real registrations do not."
    ),
    url=f"https://github.com/{_REPO}",
    register=Register.DETECTION,
    side=Side.BLUE,
    fetch=_fetch,
    documents=_documents,
    #: Measured upstream: 868 rules, 120 policies, 78 scheduled queries, 58
    #: scheduled rules, 31 correlation rules, 45 globals and 34 data models.
    #: The floor sits well below that so churn is quiet while a tree that stops
    #: being walked trips it.
    expect_min_docs=900,
    timeout=600,
    notes=(
        "Detection written as Python, with labelled events attached — the "
        "shape of data this corpus is measurably shortest of. One document "
        "per detection, joining three things upstream keeps in two files: the "
        "YAML metadata (identifier, log types, severity, the ATT&CK "
        "tactic:technique pair split so both ids read as ids, CIS/PCI "
        "mappings, description, runbook), the sibling .py verbatim — "
        "rule(event) with real control flow, early returns, deep_get defaults "
        "and udm() lookups, which no declarative rule language in this corpus "
        "can express — and up to four of the upstream Tests, each a complete "
        "CloudTrail/Okta/GitHub/Kubernetes-audit event beside the verdict the "
        "detection must return for it. Both polarities are kept on purpose: a "
        "False case is the same API call made legitimately, and that is the "
        "half that is hard to find published. global_helpers/ and data_models/ "
        "are included as SYSTEM rather than DETECTION, because a helper is "
        "library code and a data model is a field mapping, and a rule calling "
        "aws_cloudtrail_success(event) is unreadable without them. The "
        "Filename: value from the YAML is resolved and proved to stay inside "
        "the cache before it is opened. Excluded by name: AGENTS.md, CLAUDE.md "
        "and .claude/ — instructions addressed to an AI agent, off-register "
        "and not something to feed a model, following owasp.py's precedent — "
        "plus packs/ (generated id lists), lookup_tables/, indexes/, "
        "templates/, test_scenarios/ and style_guides/."
    ),
)
