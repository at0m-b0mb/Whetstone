"""Zeek's script tree — detection as an event-driven program. DETECTION + SYSTEM.

:mod:`~training.corpus.sources.netrules` considered Zeek and refused it, for a
reason that was right and that said what to do next: "a Zeek policy script is a
program in a general-purpose event-driven language; its surface form is C-like
program text, and its detection logic lives in control flow rather than in a
signature… Zeek belongs in its own source if SYSTEM ever wants it." This is that
source. It is separate so that the register it reports is the register it
actually is, which ``netrules`` could not have done while declaring itself
DETECTION for 37,000 Suricata signatures.

Two things here exist nowhere else in the corpus, and they are different things.

**Detection as a program with state.** Every other detection source in this
collection is declarative: a Sigma rule, an SPL search, a Suricata signature, a
YARA condition. Each one is a predicate over a single observation. Zeek's
``policy/protocols/ssh/detect-bruteforcing.zeek`` is not a predicate — it
registers a SumStats reducer over the ``ssh.login.failure`` stream, sets a
threshold, and raises ``SSH::Password_Guessing`` when the threshold is crossed
within an epoch. Thresholds, time windows, per-key accumulation, suppression
intervals and an explicit notice vocabulary. A model whose entire notion of
detection came from declarative rules has never seen detection written as a
stateful program, and "thirty failures in thirty minutes from one subnet" is not
expressible as a Sigma rule.

**The log schema with its semantics attached.** ``base/protocols/conn/main.zeek``
is the definition of ``conn.log`` — and each field carries its own ``##`` doc
comment explaining what the value means, including the five-paragraph
explanation of every ``conn_state`` code (``S0``, ``SF``, ``REJ``, ``RSTOS0``).
:mod:`~training.corpus.sources.logsamples` already carries Zeek ``conn``
records as raw JSON; this is the dictionary that says what those keys mean. The
brief for this corpus pass put the gap plainly — plenty of usage text, very
little output text, and reading messy output is what the runtime does on every
step — and a field dictionary is the half of that join the corpus had only for
Windows events.

Also here: 40 ``.sig`` files in Zeek's own signature framework syntax
(``ip-proto == tcp``, ``payload /…/``, ``enable "ssl"``), which is neither
Suricata's nor YARA's.

**Register is assigned by path, from a stated table, not by topic.** The
``policy/`` tree and the notice, intel and signature frameworks are DETECTION.
``base/protocols/`` and the remaining frameworks are SYSTEM: they define record
types, log streams and events, which is "how the machine works" and is exactly
what :class:`~training.corpus.source.Register` means by SYSTEM. Declaring the
whole tree DETECTION would have overstated the one report that matters, which is
the mistake ``netrules`` avoided by leaving Zeek out altogether.

**Licence: BSD-3-Clause.** Read from ``COPYING`` at the pinned release tag
rather than from a badge — GitHub reports NOASSERTION for this repository. The
file opens "Copyright (c) 1995-now, The Regents of the University of California
through the Lawrence Berkeley National Laboratory and the International Computer
Science Institute. All rights reserved." and states the three standard clauses.
It closes with a sentence that is honoured by construction here: "Note that some
files in the distribution may carry their own copyright notices." Every document
is the file verbatim, so a per-file notice travels with the text it covers.

**Indentation is proved, not assumed.** Zeek indents with hard tabs and its
``##`` field comments are column-aligned against the record fields beneath them.
``normalise()`` preserves horizontal whitespace by contract, and this adapter
re-proves it per file — see :func:`_indentation_survived` — because that
contract is the difference between a schema and a pile of lines, and the
regression would be invisible in a document count.

**Not taken, and why.** ``base/init-bare.zeek`` is 252 KB of bare type and
built-in-function declarations with no logic; ``base/packet-protocols/`` is 30 KB
of link-layer analyzer registration; ``base/utils/`` is string and address
helpers; ``spicy/`` and ``zeekygen/`` are the grammar runtime and the
documentation generator. ``__load__.zeek`` files are two lines of ``@load``
each. None of them is detection and none is a schema. ``testing/`` is excluded
too, and that one is a real loss worth naming: it holds thousands of btest
baseline files that are literal Zeek output. They are also the engine's
regression fixtures rather than documentation, they run to tens of megabytes,
and ``logsamples`` already supplies real Zeek records — so they are left for a
future adapter that can state its own sampling rule.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from ..source import Document, Register, Side, SourceError, SourceSpec, normalise
from . import _detectionlib as lib

_NAME = "zeek"
_REPO = "zeek/zeek"
#: The latest stable release at the time of writing. A tag, not ``master``: the
#: script tree is the artefact and a moving branch makes a build unreproducible.
_REF = "v9.0.0"
_URL = lib.codeload_url(_REPO, _REF, tag=True)

#: The ``master`` tarball measured 40,818,378 bytes; the tagged one is
#: comparable. Most of it is ``src/`` and ``testing/``, neither of which is
#: kept — the ``scripts/`` tree is 2.95 MB across 600 files.
_MAX_ARCHIVE_BYTES = 128 * 1024 * 1024

_MIN_CHARS = 300

#: Path prefixes under ``scripts/`` that are DETECTION, in the order they are
#: tested. Everything else kept is SYSTEM. The notice framework is the output
#: side of every Zeek detection (``Notice::Type``, suppression, e-mail and
#: action policy); intel is indicator matching; signatures is the byte-pattern
#: engine.
_DETECTION_PREFIXES = (
    "policy/",
    "base/frameworks/notice/",
    "base/frameworks/intel/",
    "base/frameworks/signatures/",
    "base/frameworks/sumstats/",
)

#: Excluded trees and files, with the reason in the module docstring.
_EXCLUDE_PREFIXES = (
    "base/packet-protocols/",
    "base/utils/",
    "spicy/",
    "zeekygen/",
)
_EXCLUDE_NAMES = frozenset({
    "init-bare.zeek", "init-default.zeek", "init-frameworks-and-bifs.zeek",
    "init-supervisor.zeek", "test-all-policy.zeek", "__load__.zeek",
    "CMakeLists.txt",
})

#: ``##!`` is Zeek's file-level documentation comment; ``##`` documents the
#: declaration beneath it. The first is the file's own summary of itself, which
#: is the best possible header for a document and does not have to be invented.
_SUMMARY = re.compile(r"^##!\s?(.*)$", re.M)
_MODULE = re.compile(r"^module\s+([A-Za-z_][\w:]*)\s*;", re.M)
_LOAD = re.compile(r"^@load\s+(\S+)", re.M)
#: ``redef enum Notice::Type += { Password_Guessing, Login_By_... };``
_NOTICE_BLOCK = re.compile(
    r"redef\s+enum\s+Notice::Type\s*\+=\s*\{(.*?)\}", re.S)
_LOG_ID = re.compile(r"redef\s+enum\s+Log::ID\s*\+=\s*\{([^}]*)\}")
_ENUM_MEMBER = re.compile(r"^\s*([A-Za-z_][\w:]*)\s*,?\s*$", re.M)
#: ``type Info: record {`` — the declaration of a log's columns.
_INFO_RECORD = re.compile(r"^\s*type\s+(\w+)\s*:\s*record\s*\{", re.M)
_SIGNATURE = re.compile(r"^signature\s+([\w\-.]+)\s*\{", re.M)


def _keep(relative: Path) -> bool:
    parts = relative.parts
    if not parts or parts[0] != "scripts" or len(parts) < 2:
        return False
    if relative.name in _EXCLUDE_NAMES:
        return False
    if relative.suffix not in (".zeek", ".sig"):
        return False
    inner = "/".join(parts[1:])
    return not inner.startswith(_EXCLUDE_PREFIXES)


def _fetch(cache_dir: Path) -> Path:
    cache_dir.mkdir(parents=True, exist_ok=True)
    home = cache_dir / _NAME
    if lib.marker_path(home).is_file():
        return home
    home_dir, meta = lib.extract(
        name=_NAME,
        url=_URL,
        cache_dir=cache_dir,
        keep=_keep,
        licence_files=("COPYING",),
        max_bytes=_MAX_ARCHIVE_BYTES,
        # 600 files are under scripts/ on master; the include rule drops roughly
        # 150 of them. A floor at 300 clears ordinary churn and fails loudly on
        # a renamed tree.
        min_kept=300,
    )
    meta["ref"] = _REF
    meta["repo"] = _REPO
    meta["excluded"] = [
        "src/ and testing/ (the engine and its btest baselines)",
        *(f"scripts/{prefix}" for prefix in _EXCLUDE_PREFIXES),
        *(f"scripts/**/{name}" for name in sorted(_EXCLUDE_NAMES)),
    ]
    lib.write_marker(home_dir, meta)
    return home_dir


def _indentation_survived(raw: str, cleaned: str) -> int | None:
    """None if ``normalise`` left every surviving line's indentation alone.

    Returns the 1-based line number of the first disagreement otherwise. The
    comparison is over non-blank lines only, keyed on the stripped content, so
    the blank-run capping and trailing-whitespace stripping that ``normalise``
    is *supposed* to do are not counted as damage while a collapsed run of
    leading tabs is.

    This is here because the whole value of ``base/protocols/*/main.zeek`` is a
    record declaration whose ``##`` comments are column-aligned against the
    fields they document, and the one historical bug in ``normalise`` was that
    it collapsed horizontal whitespace. If that ever comes back, this source
    should be the thing that says so, by line number, rather than the thing that
    quietly ships flattened schemas.
    """
    before = [(len(ln) - len(ln.lstrip()), ln.strip())
              for ln in raw.replace("\r\n", "\n").split("\n") if ln.strip()]
    after = [(len(ln) - len(ln.lstrip()), ln.strip())
             for ln in cleaned.split("\n") if ln.strip()]
    if len(before) != len(after):
        return min(len(before), len(after)) + 1
    for number, (first, second) in enumerate(zip(before, after), start=1):
        if first != second:
            return number
    return None


def _enum_members(block: str) -> list[str]:
    """Member names out of an enum redefinition body, doc comments dropped."""
    without_comments = re.sub(r"##.*", "", block)
    return [name for name in _ENUM_MEMBER.findall(without_comments) if name]


def _register_for(inner: str) -> Register:
    # A ``.sig`` file is DETECTION wherever it sits. 23 of the 40 live under
    # ``base/protocols/``, next to the analyzer they enable, and the path table
    # alone put them in SYSTEM — which would have filed Zeek's only byte-pattern
    # signatures as schema. Suffix first, then path.
    if inner.endswith(".sig"):
        return Register.DETECTION
    return (Register.DETECTION if inner.startswith(_DETECTION_PREFIXES)
            else Register.SYSTEM)


def _header(inner: str, raw: str, register: Register) -> list[str]:
    module = _MODULE.search(raw)
    summary = " ".join(line.strip() for line in _SUMMARY.findall(raw)).strip()

    head = [f"Zeek script: scripts/{inner}"]
    if module:
        head.append(f"Zeek module: {module.group(1)}")
    if summary:
        head.append(f"Purpose (the script's own ##! summary): {summary}")

    if inner.endswith(".sig"):
        names = _SIGNATURE.findall(raw)
        head.append(
            "Zeek signature-framework file. Each `signature NAME { … }` is a "
            "byte-level condition over a connection: header tests such as "
            "`ip-proto == tcp` and `dst-port == 80`, a `payload /…/` regular "
            "expression over the reassembled stream, and an action — `event` "
            "raises a signature match, `enable \"ssl\"` hands the connection to "
            "a protocol analyzer instead.")
        if names:
            head.append(f"Signatures defined: {', '.join(names)}")
        return head

    notices: list[str] = []
    for block in _NOTICE_BLOCK.findall(raw):
        notices.extend(_enum_members(block))
    if notices:
        qualifier = f"{module.group(1)}::" if module else ""
        head.append(
            "Notices this script can raise: "
            + ", ".join(f"{qualifier}{name}" for name in notices)
            + ". A Zeek notice is the output of a detection: the notice "
              "framework decides what happens to it (log, alarm, e-mail, "
              "suppress for an interval) separately from the logic that "
              "raised it.")

    log_ids = [name for block in _LOG_ID.findall(raw)
               for name in _enum_members(block)]
    records = _INFO_RECORD.findall(raw)
    if log_ids or records:
        if module and log_ids:
            head.append(
                f"Log stream defined: {module.group(1)}::"
                + f", {module.group(1)}::".join(log_ids))
        if records:
            head.append(
                f"Record type(s) defining the log's columns: "
                f"{', '.join(records)}. Every field marked `&log` becomes a "
                f"column in the written log, and the `##` comment above a field "
                f"is what that column means.")

    loads = _LOAD.findall(raw)
    if loads:
        head.append("Depends on: " + ", ".join(dict.fromkeys(loads)))

    head.append(
        "Detection in Zeek is an event-driven program rather than a rule: "
        "handlers fire on protocol events, state is accumulated across a "
        "connection or across an epoch, and a threshold crossing raises a "
        "notice."
        if register is Register.DETECTION else
        "This is schema and mechanism rather than detection: the record types, "
        "log streams and events that detections are written against.")
    return head


def _documents(path: Path) -> Iterator[Document]:
    home = path if (path / "scripts").is_dir() else path / _NAME
    root = home / "scripts"
    if not root.is_dir():
        raise SourceError(
            f"{_NAME}: no scripts/ under {home} — the cache is not populated")

    counts = {"detection": 0, "system": 0, "signatures": 0, "short": 0}
    chars = {"detection": 0, "system": 0}
    for file in lib.walk_files(root, (".zeek", ".sig")):
        relative = file.relative_to(home)
        if not _keep(relative):
            continue
        inner = "/".join(relative.parts[1:])
        try:
            raw = file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        clean = lib.scrub(raw)
        body = normalise(clean)
        bad_line = _indentation_survived(clean, body)
        if bad_line is not None:
            raise SourceError(
                f"{_NAME}: normalise() changed the indentation of "
                f"scripts/{inner} at line {bad_line}. Zeek indents with hard "
                "tabs and column-aligns its ## field comments against the "
                "record fields beneath them, so this is the schema being "
                "flattened. Fix normalise(), not this check."
            )

        register = _register_for(inner)
        head = _header(inner, clean, register)
        text = normalise("\n".join(head) + "\n\nSource, verbatim:\n\n" + body)
        if len(text) < _MIN_CHARS:
            counts["short"] += 1
            continue
        lib.assert_scrubbed(_NAME, inner, text)
        counts[register.value] += 1
        chars[register.value] += len(text)
        if inner.endswith(".sig"):
            counts["signatures"] += 1
        yield Document(text=text, source=_NAME, register=register,
                       # Zeek is a defender's tool end to end; nothing in this
                       # tree attacks anything.
                       side=Side.BLUE, ident=inner)

    print(f"   {_NAME}: {counts['detection']} detection documents "
          f"({chars['detection']/1e6:.2f}M chars, of which "
          f"{counts['signatures']} are signature-framework files) and "
          f"{counts['system']} system documents "
          f"({chars['system']/1e6:.2f}M chars: record types, log streams and "
          f"events). {counts['short']} file(s) under the {_MIN_CHARS}-character "
          f"floor.")


SPEC = SourceSpec(
    name=_NAME,
    license=(
        "BSD-3-Clause — zeek/zeek at tag v9.0.0, read from the repository's own "
        "COPYING inside the fetched archive and copied into the cache under "
        "licenses/, not taken from a badge (GitHub reports NOASSERTION for this "
        "repository). \"Copyright (c) 1995-now, The Regents of the University of "
        "California through the Lawrence Berkeley National Laboratory and the "
        "International Computer Science Institute. All rights reserved.\" plus "
        "the three standard clauses: retain the notice on source "
        "redistribution, reproduce it in binary redistribution, and do not use "
        "the names of the Regents, LBNL, the U.S. Dept. of Energy, ICSI or the "
        "contributors to endorse derived products. COPYING closes with \"Note "
        "that some files in the distribution may carry their own copyright "
        "notices\" — honoured by construction, because every document is the "
        "script verbatim and a per-file notice travels inside the text it "
        "covers. No personal author or contributor credit appears anywhere in "
        "this tree (measured: 0 attribution lines, and the three email-shaped "
        "tokens in it are an SSH algorithm name, a certificate-authority "
        "contact inside an X.509 test constant and an example.net placeholder)."
    ),
    url=f"https://github.com/{_REPO}/tree/{_REF}/scripts",
    register=Register.DETECTION,
    side=Side.BLUE,
    fetch=_fetch,
    documents=_documents,
    #: 600 files are under scripts/ on master and the include rule keeps roughly
    #: 420 of them. The floor sits well below that so churn in the policy tree is
    #: quiet, while a renamed tree — the realistic regression — trips the fetch's
    #: own file-count floor first and says so at fetch time.
    expect_min_docs=300,
    timeout=900,
    notes=(
        "Zeek's scripts/ tree at a pinned release tag, one document per file, "
        "the script verbatim under a header built from the file's own ##! "
        "summary: the module, the notices it can raise (the output vocabulary "
        "of a Zeek detection), the log stream and record type it defines, and "
        "what it loads. The source netrules deliberately refused on register "
        "grounds and said belonged in its own adapter, which is what this is. "
        "Two things nothing else in the corpus has: detection written as a "
        "stateful event-driven program — SumStats reducers, epochs, thresholds, "
        "per-subnet accumulation, so that 'thirty failures in thirty minutes "
        "from one subnet' is expressible at all, which it is not in Sigma — and "
        "the log schemas with their semantics attached, where every &log field "
        "of conn.log/dns.log/http.log carries the ## comment saying what the "
        "column means (logsamples has the records; this is the dictionary). "
        "Plus 40 files in Zeek's own signature-framework syntax, which is "
        "neither Suricata's nor YARA's. Register is per document from a stated "
        "path table: policy/ and the notice, intel, signature and sumstats "
        "frameworks are DETECTION, base/protocols/ and the rest are SYSTEM, "
        "because filing a record-type declaration as detection would misreport "
        "the balance report. normalise() is re-proved per file to have left "
        "every line's indentation intact — Zeek uses hard tabs and aligns its "
        "field comments in columns — and a disagreement raises with the line "
        "number rather than shipping a flattened schema. Not taken: "
        "init-bare.zeek (252 KB of bare declarations), packet-protocols/, "
        "utils/, spicy/, zeekygen/, __load__.zeek stubs, and testing/ — whose "
        "btest baselines are literal Zeek output and are a real loss, left for "
        "an adapter that can state its own sampling rule."
    ),
)
