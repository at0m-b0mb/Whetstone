"""Falco rules — detection at the syscall, with its macros resolved. DETECTION/BLUE.

:mod:`~training.corpus.sources.containers` looked at this upstream and left it
out, on arithmetic rather than licence: "``falcosecurity/rules`` (Apache-2.0) is
the container runtime's detection language and would be a fine source — for a
corpus whose DETECTION register was not already 20.9% against a 13% target."
That arithmetic has not changed and is reported honestly below; what has changed
is the size of the thing being weighed. This source is 240 KB of rule text, and
it buys a layer of the stack the corpus does not otherwise contain.

Every other detection source here reads something a program *wrote about
itself*. Sigma and Splunk read logs, Elastic reads indexed events, YARA reads a
file on disk, Suricata reads bytes on the wire, Wazuh reads syslog. Falco reads
**the system call**, before anything has been logged at all, and its field
vocabulary is unlike any of them::

    spawned_process and container and container.privileged=true
      and proc.name=debugfs

``evt.type``, ``evt.dir``, ``proc.pname``, ``proc.exepath``, ``proc.cmdline``,
``proc.tty``, ``fd.typechar``, ``fd.num``, ``user.loginuid``,
``container.privileged``, ``ka.verb`` for the Kubernetes audit plugin. A model
asked how a detection sees a process being created has, until this source, only
ever seen Windows Event 4688 and Sysmon Event 1 — both of which are a *log* of
the thing, with a log's latency and a log's gaps.

**Macros are resolved, and that is the point of the adapter.** A Falco rule's
``condition`` is almost never self-contained: ``Launch Privileged Container``
expands through ``container``, ``spawned_process``, ``open_write`` and a dozen
others, and ``spawned_process`` is itself
``evt.type in (execve, execveat) and evt.dir=<``. 203 macros and 166 lists
support 100 rules. Emitted raw, a rule document would be four lines naming
identifiers that are defined in a different part of a 100 KB file, and the model
would learn the names without ever meeting the semantics. So each rule document
carries its condition verbatim **and then** the transitive closure of the
macros and lists it reaches, each one's own definition printed beneath it. The
expansion is depth-limited and cycle-safe because a macro set maintained by many
hands is exactly where a cycle eventually appears, and a stack overflow inside
a corpus build is a bad way to find out.

Macros and lists are *also* emitted as documents of their own, because
``shell_binaries = [ash, bash, csh, ksh, sh, tcsh, zsh, dash]`` is a useful
thing to have met.

**Licence: Apache-2.0.** Read from the repository's own ``LICENSE`` inside the
fetched archive and copied into the cache under ``licenses/``. Every rule file
also opens with an ``SPDX-License-Identifier: Apache-2.0`` header and
``Copyright (C) 2025 The Falco Authors``, which is corporate-collective
attribution and is preserved. Measured: zero personal names and zero email
addresses anywhere in the rule files.

**ATT&CK is in the tags, mixed in with everything else.** Falco overloads one
``tags`` list with the maturity level (``maturity_stable``), the workload
(``container``, ``host``), compliance (``cis``), the kill-chain phase
(``mitre_privilege_escalation``) and the technique id (``T1611``). They are
separated out and printed as what they are, the same editorial act
:mod:`~training.corpus.sources.wazuh` performs on Wazuh's overloaded
``<group>`` field and ``netrules`` on ET's underscore-mangled metadata.

**What is not taken.** ``registry.yaml`` is the catalogue of rule files, not
rules. ``proposals/``, ``docs/``, ``mkdocs.yml``, ``OWNERS`` and the GitHub
workflows are project machinery. ``archive/`` **is** taken — those rules were
retired for noise and maturity rather than because the detection was wrong, and
their register is the same; the header says they are archived, for the same
reason ``netrules`` keeps ET's 19,490 commented-out rules with the ``#`` intact.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

import yaml

from ..source import Document, Register, Side, SourceError, SourceSpec, normalise
from . import _detectionlib as lib

_NAME = "falco"
_REPO = "falcosecurity/rules"
_REF = "main"
_URL = lib.codeload_url(_REPO, _REF)

#: Measured: the whole tarball is 278,125 bytes. The ceiling is three orders of
#: magnitude above that only because a redirect to the wrong thing should fail
#: on content, not on a byte count that happens to be tight.
_MAX_ARCHIVE_BYTES = 32 * 1024 * 1024

_MIN_CHARS = 200

#: How deep macro expansion will follow. Falco's own chains run three or four
#: deep; the limit exists for the cycle a community-maintained macro set will
#: eventually contain, not for the depth.
_MAX_DEPTH = 8

#: ``maturity_stable`` / ``maturity_incubating`` / ``maturity_sandbox`` /
#: ``maturity_deprecated`` — the adoption framework, worth stating in words.
_MATURITY = re.compile(r"^maturity_(\w+)$")
#: ``mitre_privilege_escalation`` -> the ATT&CK tactic, in words.
_TACTIC = re.compile(r"^mitre_(\w+)$")
#: Identifiers a Falco condition can reference. A macro or list name is a bare
#: word; field names always carry a dot (``proc.name``), which is what keeps
#: this from trying to expand ``evt.type`` as a macro.
_IDENT = re.compile(r"(?<![\w.])([A-Za-z_][A-Za-z0-9_]*)(?![\w.(])")


def _keep(relative: Path) -> bool:
    parts = relative.parts
    if len(parts) != 2 or parts[0] not in ("rules", "archive"):
        return False
    return relative.suffix in (".yaml", ".yml")


def _fetch(cache_dir: Path) -> Path:
    cache_dir.mkdir(parents=True, exist_ok=True)
    home = cache_dir / _NAME
    if lib.marker_path(home).is_file():
        return home
    home_dir, meta = lib.extract(
        name=_NAME, url=_URL, cache_dir=cache_dir, keep=_keep,
        licence_files=("LICENSE",), max_bytes=_MAX_ARCHIVE_BYTES,
        # 3 under rules/ and 2 under archive/.
        min_kept=4,
    )
    meta["ref"] = _REF
    meta["repo"] = _REPO
    meta["excluded"] = [
        "registry.yaml (a catalogue of rule files, not rules)",
        "proposals/, docs/, mkdocs.yml, OWNERS, tools/, .github/",
    ]
    lib.write_marker(home_dir, meta)
    return home_dir


def _load(home: Path) -> tuple[dict[str, dict], dict[str, dict], dict[str, dict]]:
    """Index every rule, macro and list across all the rule files.

    Indexed across *files* rather than per file because Falco loads them as one
    namespace: a rule in ``falco-sandbox_rules.yaml`` may use a macro defined in
    ``falco_rules.yaml``, and expanding only within one file would leave the
    rule documents that need it most unresolved.
    """
    rules: dict[str, dict] = {}
    macros: dict[str, dict] = {}
    lists: dict[str, dict] = {}
    for file in lib.walk_files(home, (".yaml", ".yml")):
        relative = file.relative_to(home)
        if not _keep(relative):
            continue
        try:
            parsed = yaml.safe_load(file.read_text(encoding="utf-8",
                                                   errors="replace"))
        except (OSError, yaml.YAMLError):
            continue
        if not isinstance(parsed, list):
            continue
        for item in parsed:
            if not isinstance(item, dict):
                continue
            item = dict(item)
            item["_file"] = relative.as_posix()
            for key, table in (("rule", rules), ("macro", macros),
                               ("list", lists)):
                name = item.get(key)
                if isinstance(name, str) and name:
                    # Later files win, which is Falco's own override semantics:
                    # an append or a redefinition of the same name replaces it.
                    table[name] = item
    return rules, macros, lists


def _expand(condition: str, macros: dict[str, dict], lists: dict[str, dict]
            ) -> list[str]:
    """The transitive closure of macros and lists ``condition`` reaches.

    Breadth-first with a seen-set and a depth limit, so a macro that references
    itself — directly or round a four-step cycle — terminates with the chain it
    managed rather than with a RecursionError in the middle of a build.
    """
    out: list[str] = []
    seen: set[str] = set()
    frontier = [(condition, 0)]
    while frontier:
        text, depth = frontier.pop(0)
        if depth >= _MAX_DEPTH:
            continue
        for name in _IDENT.findall(text or ""):
            if name in seen:
                continue
            if name in macros:
                seen.add(name)
                body = str(macros[name].get("condition", "")).strip()
                out.append(f"  macro {name}: {body}")
                frontier.append((body, depth + 1))
            elif name in lists:
                seen.add(name)
                items = lists[name].get("items")
                items = items if isinstance(items, list) else []
                rendered = ", ".join(str(i) for i in items)
                out.append(f"  list {name}: [{rendered}]")
                # A list may hold the names of other lists (Falco resolves
                # nested lists), so the frontier follows them too.
                frontier.append((rendered, depth + 1))
    return out


def _tags(tags: object) -> tuple[list[str], list[str], list[str], list[str]]:
    """Split Falco's one overloaded ``tags`` list into the four things it is."""
    maturity: list[str] = []
    tactics: list[str] = []
    techniques: list[str] = []
    other: list[str] = []
    for raw in (tags if isinstance(tags, list) else []):
        tag = str(raw)
        if (found := _MATURITY.match(tag)):
            maturity.append(found.group(1))
        elif lib.attack_ids(tag):
            techniques.append(tag)
        elif (found := _TACTIC.match(tag)):
            tactics.append(found.group(1).replace("_", " "))
        else:
            other.append(tag)
    return maturity, tactics, techniques, other


def _render_rule(name: str, item: dict, macros: dict[str, dict],
                 lists: dict[str, dict]) -> str:
    condition = str(item.get("condition", "")).strip()
    maturity, tactics, techniques, other = _tags(item.get("tags"))
    archived = item.get("_file", "").startswith("archive/")

    head = [f"Falco rule: {name}"]
    description = str(item.get("desc", "")).strip()
    description = re.sub(r"\s+", " ", description)
    if description:
        head.append(f"Description: {description}")
    head.append(f"Rules file: {item.get('_file', '?')}")
    if archived:
        head.append(
            "This rule is archived upstream. Falco retires rules for noise and "
            "for maturity, not because the detection was wrong.")
    if item.get("priority"):
        head.append(f"Priority: {item['priority']}")
    if item.get("enabled") is False:
        head.append("Shipped disabled by default (`enabled: false`).")
    if maturity:
        head.append(f"Maturity: {', '.join(maturity)} (Falco's rule adoption "
                    f"framework grades a rule stable, incubating, sandbox or "
                    f"deprecated)")
    if techniques:
        head.append(f"MITRE ATT&CK technique: {', '.join(techniques)}")
    if tactics:
        head.append(f"MITRE ATT&CK tactic: {', '.join(tactics)}")
    if other:
        head.append(f"Other tags: {', '.join(other)}")

    head.append("")
    head.append(
        "Falco evaluates this condition against the stream of system calls, "
        "not against a log. `evt.type` is the syscall, `evt.dir` its direction "
        "(`>` entering the kernel, `<` returning), `proc.*` the calling "
        "process, `fd.*` the file descriptor it touched, `user.*` the "
        "credentials it ran under, and `container.*`/`k8s.*`/`ka.*` the "
        "container, Kubernetes object or audit verb it belongs to.")
    head.append("")
    head.append(f"condition: {condition}")

    expansion = _expand(condition, macros, lists)
    if expansion:
        head.append("")
        head.append("Macros and lists this condition resolves through, with "
                    "their own definitions:")
        head.extend(expansion)

    output = str(item.get("output", "")).strip()
    if output:
        head.append("")
        head.append(
            "Alert output template. Each `%field` is substituted from the same "
            "field namespace the condition matches on, so this line is also a "
            "statement of which facts the detection reports:")
        head.append(f"  {output}")
    return "\n".join(head)


def _render_macro(name: str, item: dict, macros: dict[str, dict],
                  lists: dict[str, dict]) -> str:
    condition = str(item.get("condition", "")).strip()
    head = [
        f"Falco macro: {name}",
        f"Rules file: {item.get('_file', '?')}",
        "A Falco macro is a named, reusable fragment of a rule condition over "
        "the system-call field namespace. Rules compose them; they are not "
        "evaluated on their own.",
        "",
        f"condition: {condition}",
    ]
    expansion = _expand(condition, macros, lists)
    if expansion:
        head += ["", "Resolves through:", *expansion]
    return "\n".join(head)


def _render_list(name: str, item: dict) -> str:
    items = item.get("items")
    items = items if isinstance(items, list) else []
    return "\n".join([
        f"Falco list: {name}",
        f"Rules file: {item.get('_file', '?')}",
        "A Falco list is a named set used with the `in` operator inside a rule "
        "condition.",
        f"{len(items)} item(s).",
        "",
        "items:",
        *(f"  - {entry}" for entry in items),
    ])


def _documents(path: Path) -> Iterator[Document]:
    home = path if (path / "rules").is_dir() else path / _NAME
    if not (home / "rules").is_dir():
        raise SourceError(
            f"{_NAME}: no rules/ under {home} — the cache is not populated")

    rules, macros, lists = _load(home)
    if not rules:
        raise SourceError(
            f"{_NAME}: no rules parsed out of {home}/rules — the upstream file "
            "layout or the YAML shape has changed")

    emitted = {"rule": 0, "macro": 0, "list": 0}
    expanded = 0
    for name, item in sorted(rules.items()):
        text = normalise(lib.scrub(_render_rule(name, item, macros, lists)))
        if len(text) < _MIN_CHARS:
            continue
        if "Macros and lists this condition resolves through" in text:
            expanded += 1
        ident = f"rule/{name}"
        lib.assert_scrubbed(_NAME, ident, text)
        emitted["rule"] += 1
        yield Document(text=text, source=_NAME, register=Register.DETECTION,
                       side=Side.BLUE, ident=ident)

    for name, item in sorted(macros.items()):
        text = normalise(lib.scrub(_render_macro(name, item, macros, lists)))
        if len(text) < _MIN_CHARS:
            continue
        ident = f"macro/{name}"
        lib.assert_scrubbed(_NAME, ident, text)
        emitted["macro"] += 1
        yield Document(text=text, source=_NAME, register=Register.DETECTION,
                       side=Side.BLUE, ident=ident)

    for name, item in sorted(lists.items()):
        text = normalise(lib.scrub(_render_list(name, item)))
        if len(text) < _MIN_CHARS:
            continue
        ident = f"list/{name}"
        lib.assert_scrubbed(_NAME, ident, text)
        emitted["list"] += 1
        yield Document(text=text, source=_NAME, register=Register.DETECTION,
                       side=Side.BLUE, ident=ident)

    print(f"   {_NAME}: {emitted['rule']} rules ({expanded} of them resolving "
          f"through at least one macro or list), {emitted['macro']} macros, "
          f"{emitted['list']} lists. Documents under the {_MIN_CHARS}-character "
          f"floor are dropped — a bare two-item list is not a lesson.")


SPEC = SourceSpec(
    name=_NAME,
    license=(
        "Apache-2.0 — falcosecurity/rules, read from the repository's own "
        "LICENSE inside the fetched archive and copied into the cache under "
        "licenses/. Every rule file additionally carries an "
        "SPDX-License-Identifier: Apache-2.0 header and \"Copyright (C) 2025 "
        "The Falco Authors\"; that is collective corporate attribution and it is "
        "what Apache-2.0 section 4(c) asks to be retained. Measured: this "
        "upstream contains zero personal names and zero email addresses, so "
        "there is no third-party personal data to strip and nothing was "
        "removed."
    ),
    url=f"https://github.com/{_REPO}",
    register=Register.DETECTION,
    side=Side.BLUE,
    fetch=_fetch,
    documents=_documents,
    #: Measured upstream: 100 rules, 203 macros and 166 lists across three
    #: rule files and two archived ones. A floor at 300 clears the lists that
    #: fall under the character floor while failing loudly if a file stops
    #: parsing.
    expect_min_docs=300,
    timeout=300,
    notes=(
        "Falco's rule set: detection at the system call rather than in a log, "
        "which is a layer of the stack no other source in this corpus reaches "
        "— every other one reads something a program wrote about itself. One "
        "document per rule, macro and list. A rule carries its condition "
        "verbatim and then the transitive closure of the macros and lists that "
        "condition resolves through, each with its own definition, because a "
        "Falco condition is almost never self-contained (203 macros and 166 "
        "lists support 100 rules) and a rule emitted raw would name "
        "identifiers defined elsewhere in a 100 KB file. The expansion is "
        "breadth-first, cycle-safe and depth-limited to 8. Falco's single "
        "overloaded `tags` list is split into the four things it holds: the "
        "maturity grade, the ATT&CK tactic, the ATT&CK technique id and "
        "everything else. The alert `output` template is kept and explained, "
        "because each %field in it states which facts the detection reports. "
        "archive/ is included with its status named — Falco retires rules for "
        "noise and maturity, not because the detection was wrong — and "
        "registry.yaml, proposals/, docs/ and the project machinery are not. "
        "containers.py previously refused this upstream on register arithmetic "
        "(DETECTION was 20.9% against a 13% target, and still is 1.6x over); "
        "it is taken here at 240 KB of rule text for a register nothing else "
        "supplies, and that arithmetic is reported rather than hidden."
    ),
)
