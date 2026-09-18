"""GitHub Security Advisory Database — vulnerability prose. ADVISORY/NEUTRAL.

The ADVISORY register already has a source: :mod:`~training.corpus.sources.nvd`,
which is 16% of the corpus. A second source that merely repeated NVD's shape
would buy nothing but tokens. GHSA is worth adding precisely because the shape is
different. An NVD record is a terse structured statement written to be parsed —
one sentence of description wrapped in CPE match strings. A GitHub advisory's
``details`` field is a human being explaining a bug to the people who have to
ship a fix: what the vulnerable code does, how an attacker reaches it, usually a
fenced snippet of the offending call, and what to upgrade to. That is the
largest freely licensed body of real vulnerability *prose* available anywhere,
and the corpus is short of both advisory text and volume in general — 30.6M
tokens against a model that wants considerably more.

**Identifiers beside names, which is the measurement this corpus was rebuilt
around.** ``T1547.001`` next to its human name in running prose moved that
sample from -45% to +13% against gpt2; the same sample as a naked id lost.
GHSA is unusually dense in that join, and three of the benchmark's probes sit
directly on top of it:

* ``cvss-vector`` — 92% of reviewed advisories carry a real CVSS v3.1 or v4.0
  vector string, and this adapter renders it *on the same line* as the
  qualitative severity it encodes: ``severity: HIGH (CVSS:3.1/AV:N/AC:L/...)``.
  A vector is a rigid token sequence that appears constantly in security work
  and essentially never in general web text — exactly what a domain vocabulary
  should win on — and it is worth far more sitting beside the word it means than
  alone on a line.
* ``cve-shape`` — 87% of them carry a CVE alias, which is emitted beside the
  GHSA id (``GHSA-8h28-f46f-m87h (CVE-2018-14349)``). Two identifier grammars
  for one referent, in one line.
* ``cwe-shape`` — a ``weakness:`` line follows the severity line, mirroring the
  NVD render so the association is reinforced rather than contradicted. GHSA
  stores ``cwe_ids`` with no names, so the identifier gets its second syntactic
  position from a CWE URL instead of an invented title, the same decision (and
  for the same reason) as :mod:`~training.corpus.sources.capec`.

**github-reviewed only.** The repository holds two trees: 35,685 advisories
under ``advisories/github-reviewed/`` and 338,898 under ``advisories/unreviewed/``.
The unreviewed tree is bulk auto-import from NVD — same records, same terse
description, no human editing — so taking it would import a near-duplicate of a
source this corpus already has, at ten times the volume. Duplicated text in a
small corpus is worse than absent text, because the model memorises it. The
curated tree is where the hand-written ``details`` prose actually lives, so it is
the only tree checked out.

**Why a partial clone and not the codeload tarball** used by
:mod:`~training.corpus.sources.sigma`, :mod:`~training.corpus.sources.owasp` and
:mod:`~training.corpus.sources.psdocs`. A tarball of this repository is the whole
repository: ~375,000 files, the vast majority of them unreviewed records that get
thrown away on arrival. ``git clone --depth 1 --filter=blob:none --sparse``
followed by a sparse-checkout of one directory transfers only the tree that is
kept — about 180 MB of advisories in roughly twenty seconds, against a
multi-gigabyte download for the same result. No history, no tags, one branch.

**The document cap is deliberate, and so is how it selects.** The whole reviewed
tree renders to 77 MB — roughly 19M tokens against a corpus that currently holds
30.6M — which would let one adapter own the ADVISORY register outright and make
every build slower for text ``build.py`` would then drop anyway (it caps any
single source at 30%). So ``_MAX_DOCS`` keeps 15,000 advisories, which render to
14,509 documents and 32 MB once the skips below have taken their few percent.

The obvious way to cap is to take the newest first, and it was wrong here. The
tree holds 9,949 advisories filed in 2026 and 8,638 in 2022, so a newest-first
cut of this size covers a fourteen-month window and nothing else: one year's
ecosystems, one year's editorial style, 2017-2024 absent entirely. Measurement
said there was nothing to buy with that recency either — CVSS vector coverage is
97-99% at the recent end and still 94% across the full tree. So the cap takes an
even stride through the date-ordered tree instead, spanning 2017 to 2026, and a
concentration nobody chose does not get baked into the register.
``WHETSTONE_GHSA_MAX_DOCS`` raises it; set it high enough and the stride
disappears and the whole tree is emitted.

**Markdown is left exactly as written.** ``details`` is markdown, and roughly one
advisory in five contains a fenced code block showing the vulnerable call or the
proof of concept. Those fences are the highest-value text in the source and their
indentation is meaning, so nothing here re-flows, unwraps or strips them;
:func:`~training.corpus.source.normalise` is the only cleaner applied and it
preserves horizontal whitespace by contract. Headings (``### Impact``,
``### Patches``) stay too — that is the house style of the register.

**NEUTRAL, not BLUE.** The remediation framing is real but small: one ``fix:``
line and a clause per affected package, against paragraphs describing an
exploitable condition and, often, the code that triggers it. Filing that as blue
would inflate the defence side of the balance report with text that is mostly a
description of how something breaks, and the 60/40 offence weighting is only
meaningful if the labels are honest. NVD makes the same call for the same
reason.

**Licence: CC-BY-4.0**, per the repository's own ``README.md`` ("licensed under
the terms of the CC-BY 4.0 open source license") and its ``LICENSE.md``, whose
first line is "Attribution 4.0 International". That claim is not left to this
docstring: :func:`_fetch` reads ``LICENSE.md`` out of the fresh checkout and
refuses the source if the headline is not there, because a licence that silently
changes upstream is precisely the failure the licence rule in
:mod:`~training.corpus.source` exists to catch.

**Skipped:** withdrawn advisories (retracted as wrong or duplicated — training on
one teaches a vulnerability that does not exist), and advisories whose
``details`` is nothing but a link, which would otherwise emit a document that is
all header and no content. At the default cap that is 481 and 10 respectively,
out of 15,000.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Iterator

from ..source import Document, Register, Side, SourceError, SourceSpec, normalise

_CLONE_URL = "https://github.com/github/advisory-database.git"
_REPO = "https://github.com/github/advisory-database"

#: The curated tree. See the module docstring for why ``unreviewed/`` is not here.
_TREE = "advisories/github-reviewed"
#: The clone lives in a named subdirectory so this source never scribbles into a
#: cache root it was handed directly rather than as ``cache/ghsa``.
_CLONE_DIR = "advisory-database"
#: Written last, so its presence means "clone and checkout both finished". A
#: half-populated cone therefore re-fetches instead of yielding a thin corpus.
_MARKER = "ghsa.fetch.json"

#: First line of the repository's LICENSE.md. Checked, not assumed.
_LICENSE_HEADLINE = "Attribution 4.0 International"

#: 35,685 advisories were in the reviewed tree when this was written and the
#: database only grows. A floor this far below it exists so that an empty sparse
#: cone — the real failure mode of a blobless clone, which exits 0 having checked
#: out nothing — cannot pass for a successful fetch.
_MIN_ADVISORIES = 20_000

#: How many advisories to render, sampled by even stride across the whole
#: date-ordered tree. 15,000 is ~32 MB rendered. See the docstring for why it is
#: neither everything nor the newest N.
_MAX_DOCS = int(os.environ.get("WHETSTONE_GHSA_MAX_DOCS", "15000"))

#: The longest ``details`` observed is 30 KB, and the long tail is CVE tables and
#: changelogs rather than explanation. Cut at a line boundary well past the 90th
#: percentile (3.5 KB) so no real write-up is touched.
_MAX_DETAILS = 16_000

#: After the URLs are removed, this much prose must remain, or the advisory is a
#: bare link dressed up as a description and is skipped.
_MIN_PROSE_CHARS = 40

_MAX_PACKAGES = 8
_MAX_REFS = 6
#: Cold clone of ~180 MB. Generous, because the failure this guards against is a
#: hung transfer, not a slow one.
_CLONE_TIMEOUT = 1800

_URL_RE = re.compile(r"https?://\S+")
_ADVISORY_RE = re.compile(r"^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}\.json$")


def _git(args: list[str], *, cwd: Path | None = None) -> str:
    """Run git, or raise :class:`SourceError` explaining what failed.

    ``GIT_TERMINAL_PROMPT=0`` matters more than it looks: without it, a clone
    that hits an auth challenge (a proxy, a rate limit answered with a 401) sits
    on a credential prompt forever, and a corpus build that hangs silently is
    worse than one that fails.
    """
    exe = shutil.which("git")
    if exe is None:
        raise SourceError(
            "ghsa: git is not on PATH. This source needs it — the advisory "
            "database is only distributed as a repository, and a partial clone "
            "is what keeps it to the reviewed tree instead of 375,000 files."
        )
    try:
        done = subprocess.run(
            [exe, *args],
            cwd=str(cwd) if cwd is not None else None,
            capture_output=True, text=True, check=False,
            timeout=_CLONE_TIMEOUT,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0",
                 "GIT_LFS_SKIP_SMUDGE": "1"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SourceError(f"ghsa: git {args[0]} failed: {exc}") from None
    if done.returncode != 0:
        tail = "\n".join((done.stderr or done.stdout).strip().splitlines()[-3:])
        raise SourceError(f"ghsa: git {args[0]} exited {done.returncode}: {tail}")
    return done.stdout


def _count_advisories(tree: Path) -> int:
    """Count checked-out advisory files in one walk, following no symlinks.

    ``followlinks=False`` stops the walk descending *into* a symlinked
    directory; it does nothing about a symlinked file, which ``os.walk`` puts
    in ``files`` like any other. Both halves are needed, and the file half is
    checked here as well as in :func:`_advisory_paths` so the floor below is
    counted against exactly the set of files that will later be read. A count
    that includes entries the reader skips is a floor that passes on documents
    nobody emits.
    """
    total = 0
    for directory, _, files in os.walk(tree, followlinks=False):
        here = Path(directory)
        total += sum(1 for name in files
                     if _ADVISORY_RE.match(name) and not (here / name).is_symlink())
    return total


def _fetch(cache_dir: Path) -> Path:
    """Sparse-clone the reviewed tree into the cache; return that tree.

    Idempotent and network-free on re-run. The clone lands in a ``.part``
    sibling and is renamed into place only once the advisory count and the
    licence check have both passed, so an interrupted fetch can never leave a
    partial checkout that a later run mistakes for a finished one.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    target = cache_dir / _CLONE_DIR
    marker = cache_dir / _MARKER
    tree = target / _TREE
    if marker.is_file() and tree.is_dir():
        return tree

    staging = cache_dir / f".{_CLONE_DIR}.part"
    shutil.rmtree(staging, ignore_errors=True)
    try:
        # --filter=blob:none fetches trees and commits but no file contents, then
        # --sparse limits the working tree to root files; the sparse-checkout
        # below is what pulls blobs, and only for the one directory named.
        _git(["clone", "--depth", "1", "--single-branch", "--no-tags",
              "--filter=blob:none", "--sparse", _CLONE_URL, str(staging)])
        _git(["sparse-checkout", "set", _TREE], cwd=staging)

        found = _count_advisories(staging / _TREE)
        if found < _MIN_ADVISORIES:
            raise SourceError(
                f"ghsa: only {found} advisories checked out under {_TREE} "
                f"(expected >= {_MIN_ADVISORIES:,}). Either the upstream layout "
                "moved or the sparse cone matched nothing — fix the adapter "
                "rather than training on a fraction of the register."
            )

        licence = staging / "LICENSE.md"
        headline = ""
        if licence.is_file():
            for line in licence.read_text(encoding="utf-8",
                                          errors="replace").splitlines():
                if line.strip():
                    headline = line.strip()
                    break
        if _LICENSE_HEADLINE not in headline:
            raise SourceError(
                f"ghsa: LICENSE.md headline is {headline!r}, expected to contain "
                f"{_LICENSE_HEADLINE!r}. This source declares CC-BY-4.0; if "
                "upstream has relicensed, the declaration is now false and the "
                "adapter must be corrected before the text is used."
            )

        head = _git(["rev-parse", "HEAD"], cwd=staging).strip()
        shutil.rmtree(target, ignore_errors=True)
        staging.replace(target)
        marker.write_text(
            json.dumps(
                {
                    "repo": _REPO,
                    "tree": _TREE,
                    "commit": head,
                    "advisories": found,
                    "license_headline": headline,
                    "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return target / _TREE


def _intervals(rng: dict) -> list[tuple[str, str, str]]:
    """Decode one OSV range into (introduced, fixed, last_affected) intervals.

    OSV events are an *ordered sequence*, not a record: ``introduced 1.0,
    fixed 1.4, introduced 2.0, fixed 2.3`` describes two disjoint affected
    windows with a safe 1.4-to-2.0 gap between them. Reading the events as
    last-value-wins — the obvious way, and wrong — would render that as "from
    1.0 up to but not including 2.3" and assert that a version known to be fine
    is vulnerable. So each ``introduced`` opens an interval and the next
    ``fixed`` or ``last_affected`` closes it.
    """
    out: list[tuple[str, str, str]] = []
    introduced = ""
    open_interval = False
    for event in rng.get("events") or []:
        if "introduced" in event:
            if open_interval:
                out.append((introduced, "", ""))
            introduced = str(event.get("introduced") or "")
            open_interval = True
        elif "fixed" in event:
            out.append((introduced, str(event.get("fixed") or ""), ""))
            introduced, open_interval = "", False
        elif "last_affected" in event:
            out.append((introduced, "", str(event.get("last_affected") or "")))
            introduced, open_interval = "", False
    if open_interval:
        out.append((introduced, "", ""))
    return out


def _interval_phrase(interval: tuple[str, str, str], noun: str) -> str:
    """One affected window, in the plain words a maintainer would use."""
    introduced, fixed, last = interval
    # OSV writes "0" for "since the beginning of time", which is not a version
    # anyone ever shipped and must not be printed as one.
    beginning = introduced in ("", "0")
    if fixed and beginning:
        return f"all {noun} before {fixed}"
    if fixed:
        return f"{noun} from {introduced} up to but not including {fixed}"
    if last and beginning:
        return f"all {noun} up to and including {last}"
    if last:
        return f"{noun} from {introduced} through {last}"
    if beginning:
        return f"all {noun}"
    return f"{noun} from {introduced} onwards"


def _affected(data: dict) -> tuple[list[str], list[str]]:
    """Affected-package sentences and the per-package fix clauses.

    Entries are grouped by package first. GHSA routinely splits one package
    across several ``affected`` entries, one per release branch — http4s-client
    appears three times in a single advisory, and an ungrouped render prints the
    name three times and then issues three upgrade instructions that read like
    they contradict each other. Grouped, that same advisory says the package is
    broken in two windows and names both releases that close them, which is what
    the maintainer actually meant.
    """
    entries = data.get("affected") or []
    phrases: dict[tuple[str, str], list[str]] = {}
    fixed: dict[tuple[str, str], list[str]] = {}
    extras: dict[tuple[str, str], str] = {}

    for entry in entries:
        package = entry.get("package") or {}
        name = package.get("name") or ""
        if not name:
            continue
        key = (package.get("ecosystem") or "unknown ecosystem", name)
        here = phrases.setdefault(key, [])
        fixed.setdefault(key, [])

        for rng in entry.get("ranges") or []:
            noun = "commits" if (rng.get("type") or "").upper() == "GIT" else "versions"
            for interval in _intervals(rng):
                here.append(_interval_phrase(interval, noun))
                if interval[1]:
                    fixed[key].append(interval[1])

        if not here:
            # OSV allows an explicit version list instead of a range. Rare in
            # this tree, but an entry with neither would otherwise render as a
            # package name and nothing else.
            versions = [str(v) for v in (entry.get("versions") or [])][:6]
            here.append(f"affected versions {', '.join(versions)}" if versions
                        else "all versions")

        # Kept verbatim when present: it is a maintainer's own words about what
        # is still broken, in a range syntax the structured events cannot say.
        extra = (entry.get("database_specific") or {}).get(
            "last_known_affected_version_range")
        if extra:
            extras.setdefault(key, str(extra))

    lines: list[str] = []
    fixes: list[str] = []
    for key in list(phrases)[:_MAX_PACKAGES]:
        ecosystem, name = key
        windows = list(dict.fromkeys(phrases[key]))
        sentence = f"{ecosystem} package {name}: {'; '.join(windows)}"
        if key in extras and not fixed[key]:
            sentence += f" (last known affected version range: {extras[key]})"
        lines.append(sentence)

        versions = list(dict.fromkeys(fixed[key]))
        if len(versions) == 1:
            fixes.append(f"upgrade {name} to {versions[0]} or later")
        elif versions:
            fixes.append(
                f"upgrade {name} to {', '.join(versions[:-1])} or {versions[-1]}, "
                "whichever release branch is in use"
            )

    remaining = len(phrases) - _MAX_PACKAGES
    if remaining > 0:
        lines.append(f"and {remaining} further package(s)")
    return lines, fixes


def _severity(data: dict) -> list[str]:
    """Severity beside the vector that encodes it.

    Written as one line rather than two because the point of the source is the
    join: the qualitative word and the vector string are the same claim in two
    grammars, and the model only learns that if they sit together.
    """
    vectors: dict[str, str] = {}
    for entry in data.get("severity") or []:
        score = (entry.get("score") or "").strip()
        if score.startswith("CVSS:"):
            vectors[score.split("/", 1)[0]] = score

    label = ((data.get("database_specific") or {}).get("severity") or "").strip()
    primary = ""
    for prefix in ("CVSS:3.1", "CVSS:3.0", "CVSS:4.0"):
        if prefix in vectors:
            primary = vectors.pop(prefix)
            break
    if not primary and vectors:
        primary = vectors.pop(next(iter(vectors)))

    lines: list[str] = []
    if label and primary:
        lines.append(f"severity: {label} ({primary})")
    elif label:
        lines.append(f"severity: {label}")
    elif primary:
        lines.append(f"cvss: {primary}")
    # A second vector is a second scoring system for the same bug (v4.0 beside
    # v3.1), which is worth keeping — the two grammars differ and both appear in
    # the wild.
    for leftover in vectors.values():
        lines.append(f"cvss: {leftover}")
    return lines


def _details(raw: str) -> str:
    """The advisory prose, trimmed only if absurdly long, never re-flowed."""
    text = raw.strip()
    if len(text) <= _MAX_DETAILS:
        return text
    cut = text.rfind("\n", 0, _MAX_DETAILS)
    if cut < _MAX_DETAILS // 2:
        cut = _MAX_DETAILS
    return text[:cut].rstrip() + "\n\n[details truncated]"


def _is_bare_link(details: str) -> bool:
    """True when the "description" is just a URL with punctuation around it."""
    stripped = _URL_RE.sub("", details)
    return len(re.sub(r"[\s.,:;\-*_<>()\[\]]+", "", stripped)) < _MIN_PROSE_CHARS


def _render(data: dict) -> str:
    """One advisory as a document.

    The layout is header first (identifiers, summary, the advisory URL), then
    the machine-readable claims (severity with its vector, weakness, date), then
    the affected packages and the fix in sentences, then the prose, then the
    references. The order is not arbitrary: it puts the dense identifier
    sequences at the top where a truncated sample still contains them, and it
    reaches the ``details`` markdown only after everything that describes it,
    so the prose is never interrupted by a field.
    """
    ghsa = data.get("id") or ""
    aliases = [str(a) for a in (data.get("aliases") or [])]
    cves = [a for a in aliases if a.upper().startswith("CVE-")]
    others = [a for a in aliases if a not in cves and a != ghsa]

    header = ghsa
    if cves:
        header = f"{ghsa} ({', '.join(cves)})"
    lines = [header]

    summary = (data.get("summary") or "").strip()
    if summary:
        lines.append(summary)
    # The id in a URL path as well as on its own line: a second syntactic
    # position for the same identifier, which is what the tokenizer measurement
    # rewarded.
    lines.append(f"https://github.com/advisories/{ghsa}")
    lines.append("")

    lines.extend(_severity(data))

    cwes = [c for c in ((data.get("database_specific") or {}).get("cwe_ids") or [])
            if str(c).startswith("CWE-")]
    if cwes:
        # GHSA carries no CWE names, so the URL is what gives the identifier a
        # second syntactic position instead of leaving it a naked number.
        lines.append("weakness: " + ", ".join(
            f"{c} (https://cwe.mitre.org/data/definitions/{c.split('-')[1]}.html)"
            for c in cwes[:4]
        ))
    if others:
        lines.append(f"also known as: {', '.join(others[:4])}")
    published = (data.get("published") or "")[:10]
    if published:
        lines.append(f"published: {published}")

    affected, fixes = _affected(data)
    if affected:
        lines.append("")
        lines.append("affected:")
        lines.extend(f"  {line}" for line in affected)
    lines.append("fix: " + ("; ".join(fixes) if fixes
                            else "no fixed version is listed in this advisory"))

    lines.append("")
    lines.append(_details(data.get("details") or ""))

    refs = list(dict.fromkeys(
        r.get("url", "") for r in (data.get("references") or []) if r.get("url")
    ))[:_MAX_REFS]
    if refs:
        lines.append("")
        lines.append("references:")
        lines.extend(f"  {url}" for url in refs)

    return normalise("\n".join(lines))


def _advisory_paths(root: Path) -> list[Path]:
    """Every advisory file, newest first, from a single walk.

    One walk. There are 35,685 advisories in 35,685 directories under this tree,
    and anything that re-walked per document — or globbed per year — would cost
    more than rendering the corpus does. The path encodes the publication month
    (``.../2025/09/GHSA-.../GHSA-....json``), so sorting the relative paths in
    reverse buys a newest-first order for nothing, and it is that order the
    stride in :func:`_select` then samples.
    """
    found: list[str] = []
    prefix_len = len(str(root)) + 1
    for directory, dirnames, files in os.walk(root, followlinks=False):
        here = Path(directory)
        # ``followlinks=False`` already stops the descent; pruning the names as
        # well states the intent beside the file check rather than leaving it
        # implied by a keyword argument two lines up.
        dirnames[:] = [name for name in dirnames if not (here / name).is_symlink()]
        for name in files:
            # This is a git clone, so a symlink stored upstream is materialised
            # on disk — the ``member.isfile()`` filter that protects every
            # tarball adapter in this package does not apply here. A compromised
            # commit adding ``GHSA-aaaa-bbbb-cccc.json`` as a link to an
            # ``.npmrc``, a credentials file or another source's cache manifest
            # would otherwise be matched by name, counted toward the floor, and
            # opened and parsed by _documents on every build.
            if _ADVISORY_RE.match(name) and not (here / name).is_symlink():
                found.append(f"{directory}/{name}"[prefix_len:])
    found.sort(reverse=True)
    return [root / rel for rel in found]


def _select(paths: list[Path]) -> list[Path]:
    """Thin ``paths`` to ``_MAX_DOCS`` by even stride, newest-first order kept.

    A float stride rather than ``paths[::k]``: integer striding can only thin by
    whole multiples, so a cap of 15,000 against 35,685 files would take every
    second one and overshoot by 3,000 documents. Rounding ``i * len / cap``
    hits the requested count exactly and still lands evenly across the years.

    The selection is deterministic, so two builds at the same cap contain the
    same advisories — which matters because the corpus is deduplicated by
    fingerprint and a shifting sample would quietly change what survives.
    """
    total = len(paths)
    if total <= _MAX_DOCS:
        return paths
    step = total / _MAX_DOCS
    return [paths[min(total - 1, round(i * step))] for i in range(_MAX_DOCS)]


def _documents(path: Path) -> Iterator[Document]:
    """Yield one Document per advisory, from an even stride across the tree.

    Accepts the tree directory :func:`_fetch` returns, the clone root above it,
    or the cache directory above that, so a caller that passes the wrong one of
    the three still works.
    """
    root = next(
        (candidate for candidate in (path / _CLONE_DIR / _TREE, path / _TREE, path)
         if candidate.is_dir()),
        path,
    )

    # A few percent of the selection falls out below: at a 15,000 cap, 481
    # withdrawn advisories and 10 link-only descriptions, leaving 14,509. The
    # emitted count therefore lands just under the cap rather than on it, which
    # is why expect_min_docs is a fraction of _MAX_DOCS and not _MAX_DOCS.
    for file in _select(_advisory_paths(root)):
        try:
            data = json.loads(file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            continue
        if not isinstance(data, dict) or not data.get("id"):
            continue
        # Retracted: the advisory was wrong, duplicated or spurious. Training on
        # one teaches a vulnerability that does not exist.
        if data.get("withdrawn"):
            continue

        details = (data.get("details") or "").strip()
        if not details or _is_bare_link(details):
            continue

        text = _render(data)
        if len(text) < 200:
            continue
        yield Document(
            text=text,
            source="ghsa",
            register=Register.ADVISORY,
            side=Side.NEUTRAL,
            ident=str(data["id"]),
        )


SPEC = SourceSpec(
    name="ghsa",
    license=("CC-BY-4.0 — the GitHub Advisory Database is published under the "
             "Creative Commons Attribution 4.0 International licence; see "
             "https://github.com/github/advisory-database/blob/main/LICENSE.md "
             "and section 12 (Advisory Database) of GitHub's terms for "
             "additional products and features."),
    url=_REPO,
    register=Register.ADVISORY,
    side=Side.NEUTRAL,
    fetch=_fetch,
    documents=_documents,
    #: The cap is the binding constraint, not upstream: withdrawn advisories and
    #: link-only descriptions cost a few percent, so the floor sits just under
    #: the cap. Falling materially below it means the filters or the upstream
    #: layout changed, not that the database shrank.
    expect_min_docs=max(1, int(_MAX_DOCS * 0.9)),
    notes=("github-reviewed tree only (the unreviewed tree is bulk NVD import "
           "and redundant with the nvd source). Sparse blobless clone of one "
           "directory. Renders the CVSS vector beside the severity it encodes "
           "and the CVE alias beside the GHSA id, with the markdown details "
           "prose — code fences included — kept verbatim. Capped at 15,000 "
           "advisories sampled by even stride across 2017-2026; raise "
           "WHETSTONE_GHSA_MAX_DOCS for more."),
)
