"""This author's own security repositories — the PROSE register.

Roughly forty hand-written security tools, each with a long README arguing for
its own design: why a grading engine refuses to award an A+, why a detector
reports a ceiling instead of a verdict, what a radio can and cannot hear. That
argumentative register is genuinely rare in public corpora, which mostly contain
either terse reference material or marketing, and it is close to the register
Whetstone's own ``report.finding`` output needs to produce.

It is also the corpus that taught this project its most useful lesson. Fitted to
*only* this, the domain tokenizer beat gpt2 by 7% instead of the predicted
25-30%, because Python and Markdown are not the registers the model will meet at
runtime. So it stays — the prose is good and the target share for PROSE is 10% —
but it is now one source among several rather than the whole corpus, and
``build.py`` reports its share so it cannot quietly dominate again.

**This is the only source built from the author's own machine, and that makes it
the only source that can carry someone else's personal data.** Three separate
audits of the shipped artifact landed on the same document, and the fixes below
are all consequences of that:

* One README — a four-person university group project — listed its whole team by
  full name, role and personal ``.edu`` address: the author's own, and three
  other students'. Those three never agreed to appear in a published model's
  training data, and a published checkpoint is not greppable and not removable.
  :func:`_roster_section` now **excludes the whole document**, not just the
  addresses; see its docstring for why scrubbing was the wrong answer.
* 54.2% of the characters this source shipped were **vendored** ESP-IDF and
  PlatformIO documentation, carried under a licence string that claimed every
  repository was the author's own work. That declaration is now true because
  :data:`_SKIP_PARTS` makes it true, and a test asserts the two agree.
* Email redaction used to live here and nowhere else. It belongs at
  ``build.py``'s chokepoint, which covers all forty-seven sources rather than
  one; see :func:`_chokepoint_owns_addresses` for how this source hands the
  job over without a window where nobody does it.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterator

from ..source import Document, Register, Side, SourceSpec, normalise

#: Prose only. This source is tagged PROSE and must actually be prose.
#:
#: It originally kept ``.py``, ``.c``, ``.h``, ``.yaml`` and friends, which meant
#: thousands of files of embedded-firmware C and Python were filed under the
#: PROSE register. The register system exists so corpus composition is
#: measurable, and mislabelling source as prose breaks exactly that. The first
#: training run showed it: prompted with ``T1547.001`` the model emitted
#: ``#define RADIOLIB_CFERI 0x0900`` — Flipper Zero firmware constants, learned
#: from files claiming to be security writing.
#:
#: The argumentative READMEs are the reason this source is here at all, and they
#: are markdown. The C is not lost to anything that wanted it: no register in
#: this corpus is asking for embedded firmware source.
#: ``.txt`` is excluded too: it sweeps up CMakeLists.txt, requirements.txt and
#: other build files, which are configuration rather than writing. Code fenced
#: *inside* a README stays, and should — prose that illustrates itself with a
#: snippet is still prose.
_KEEP = {".md", ".rst"}

#: Directories whose contents are **not this author's work**: dependency trees,
#: toolchain caches, virtualenvs and build output.
#:
#: This list is the reason :data:`SPEC`'s licence declaration can be stated at
#: all. An audit of the shipped artifact measured **54.2% of its characters** as
#: vendored third-party documentation — 500 of 695 documents — almost all of it
#: ESP-IDF components under ``managed_components/`` and PlatformIO library
#: dependencies under ``.pio/libdeps/``, shipped under a licence string reading
#: "all repositories are this author's own work". Neither half of that is a
#: small problem: the declaration was false, and the LVGL and TinyUSB manuals are
#: upstream reference text that forty-six other sources already supply in better
#: form. ``build.py`` refuses a *blank* licence; nothing was checking a *false*
#: one, so the check is here.
#:
#: Entries are matched as whole directory names, and matched again against the
#: ``__``-separated segments of a flattened cache name — see :func:`_vendored`
#: for why both are needed.
#:
#: ``.piovenv`` is PlatformIO's virtualenv, and it is named here because it got
#: through an earlier pass and put generated ``Activate.ps1`` boilerplate into
#: the corpus — vendored activation scripts are identical across every project
#: that has one, so they are pure duplicated noise in a corpus this size. There
#: are fourteen markdown files under one in this tree today.
_SKIP_PARTS = {
    # Version control and tool caches.
    ".git", ".hg", ".svn", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", ".tox", ".nox",
    # Python environments and anything pip put on disk.
    ".venv", "venv", "env", ".env", ".piovenv", "site-packages",
    "dist-packages", ".eggs",
    # JavaScript and web tooling.
    "node_modules", "bower_components", ".next", ".svelte-kit",
    # Build, publish and IDE output. ``_site`` is Jekyll's; ``DerivedData`` is
    # Xcode's and holds a full copy of every dependency's documentation.
    "build", "_build", "dist", "_site", ".gradle", ".cxx", "DerivedData",
    # Trees that announce themselves as vendored.
    "vendor", "vendored", "third_party", "thirdparty", "external", "extern",
    "Godeps", "subprojects", "_deps",
    # Embedded toolchains. PlatformIO puts dependencies in ``.pio/libdeps/``;
    # ESP-IDF puts them in ``managed_components/espressif__<name>/``, and the
    # IDF component registry prefixes the author onto the directory name, so
    # ``espressif`` is matched as a segment rather than as a whole name.
    ".pio", "libdeps", "managed_components", "espressif",
    # Apple dependency managers.
    "Pods", "Carthage",
}


def _vendored(name: str) -> str | None:
    """Name the vendored directory a path came through, or ``None``.

    Two call sites, one rule. The walk in :func:`_fetch` asks about a directory
    name; :func:`_documents` asks about a *flattened* cache name, where the
    original path separators have become ``__``. Matching segments covers both.

    The previous version of this check was ``name.startswith(_SKIP_TOKENS)``,
    and on the 849-file cache sitting on disk right now it matches **zero
    files** — because a flattened name begins with the repository, not with the
    vendored directory. ``Dolos-ESP32-S3-GEEK__managed_components__espressif__
    esp_tinyusb__README.md`` starts with ``Dolos``. A prefix test on a flattened
    path can only ever catch a vendored directory sitting at the top of the
    tree, which is the one place nobody puts one. 663 of those 849 files are
    vendored.

    The segment split also resolves the ESP-IDF component naming, which is
    otherwise awkward: a registry component directory is literally called
    ``espressif__esp_tinyusb``, so the ``__`` that separates the author from the
    component is the same ``__`` the flattener uses as a path separator. Rather
    than carry a second pattern language for that one case, the first segment of
    a directory name is tested too — which is exactly what the flattener will
    produce from it anyway, so the walk and the cache reader agree by
    construction instead of by coincidence.
    """
    for segment in name.split("__"):
        if segment in _SKIP_PARTS:
            return segment
    return None


def _skip_dir(name: str) -> bool:
    """True for a directory the walk must not descend into."""
    return name in _SKIP_PARTS or name.split("__", 1)[0] in _SKIP_PARTS


#: A source file above this is generated, vendored or data — not prose. The cap
#: exists because one 5 MB JSON blob outweighs four hundred READMEs and would
#: dominate the register it was filed under.
_MAX_FILE_BYTES = 256 * 1024

#: Hard stop on how many files one walk will copy, so a tree that grows a
#: dependency checkout overnight cannot turn this source into the corpus again.
#: It is *reported* when it bites, for the reason the rest of this build already
#: states: skipped and named is honest, truncated and counted is not. A silent
#: cap is worse here than elsewhere, because :func:`_fetch` returns early on a
#: non-empty cache — so one truncated walk would be reused forever.
_MAX_FILES = 4000


def _fetch(cache_dir: Path) -> Path:
    """No download: the repositories are already on this machine.

    Returns the pre-populated cache directory if it exists, otherwise collects
    from the sibling project tree. Idempotent either way.

    **Symlinks are never followed.** The repository contains a ``data`` symlink
    pointing at the external SSD where the corpus cache lives, and ``rglob("*")``
    follows symlinks: the first run of this function walked straight through it
    and copied 180 MB of NVD JSON, Sigma YAML and PowerShell markdown back in,
    all relabelled as PROSE. The corpus ate itself, and the only reason anyone
    noticed was the balance report showing prose at 82% against a 10% target.
    ``os.walk(followlinks=False)`` is used instead of ``rglob`` because it makes
    that guarantee explicit rather than version-dependent. Both halves are
    needed and both are tested: ``followlinks=False`` stops the walk descending
    *through* a symlinked directory, and the per-entry ``is_symlink()`` checks
    stop a symlinked file or directory being copied or pruned on its target's
    behalf.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    if any(cache_dir.iterdir()):
        return cache_dir

    project_root = Path(__file__).resolve().parents[3].parent
    if not project_root.is_dir():
        return cache_dir

    copied = 0
    skipped_vendored = 0
    for dirpath, dirnames, filenames in os.walk(project_root, followlinks=False):
        # Prune in place so os.walk does not descend into them at all. Counting
        # the pruned directories is not decoration: it is the number the licence
        # declaration rests on, and it was zero for a year because the check it
        # replaced could not fire.
        keep_dirs = []
        for d in sorted(dirnames):
            if Path(dirpath, d).is_symlink():
                continue
            if _skip_dir(d):
                skipped_vendored += 1
                continue
            keep_dirs.append(d)
        dirnames[:] = keep_dirs
        for filename in sorted(filenames):
            if copied >= _MAX_FILES:
                print(f"   ownrepos: stopped at the {_MAX_FILES:,}-file cap — "
                      f"this cache is TRUNCATED, not complete, and _fetch "
                      f"reuses a non-empty cache; clear {cache_dir} to rebuild")
                return cache_dir
            path = Path(dirpath, filename)
            if path.is_symlink() or path.suffix.lower() not in _KEEP:
                continue
            try:
                if path.stat().st_size > _MAX_FILE_BYTES:
                    continue
                # Relative to the project root, so no absolute path — and so no
                # home directory and no account name — ever reaches a cache
                # name, and therefore never reaches a Document.ident. ident is
                # not covered by build.py's redaction chokepoint, which makes
                # this the source's own responsibility.
                flat = str(path.relative_to(project_root)).replace("/", "__")
                (cache_dir / flat).write_bytes(path.read_bytes())
                copied += 1
            except OSError:
                continue
    if skipped_vendored:
        print(f"   ownrepos: pruned {skipped_vendored:,} vendored/generated "
              f"director(ies) from the walk")
    return cache_dir


#: Email addresses. Redaction **belongs at the build chokepoint**, not here.
#:
#: This pattern and :func:`_redact_emails` are kept as a *fallback* with an
#: explicit handover condition, and that is deliberate rather than tidy. The
#: history is the argument: a commit adding email redaction to this file landed
#: twenty days *after* the corpus artifact it was meant to protect was written,
#: so the shipped ``ownrepos.jsonl`` contained thirteen distinct addresses and
#: zero instances of the replacement marker. A positive control — grep for the
#: marker, not for the absence of addresses — is the only thing that told the
#: two apart, because a redactor that was never invoked looks identical to one
#: that found nothing.
#:
#: So: ``build.py`` owns this for all forty-seven sources, this source checks
#: whether that has actually landed, and if it has not, this runs instead and
#: says so in the build log. Deleting the capability on the promise of a fix
#: elsewhere is how the twenty-day window happened the first time.
#:
#: The replacement keeps the shape so the surrounding prose still reads as
#: prose — a line that held a bracketed "(…@…)" still says something
#: address-shaped — without carrying anyone's identity. It is also a fixed point
#: of the pattern: redacting an already-redacted document is a no-op, so running
#: both layers costs correctness nothing.
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_EMAIL_REPLACEMENT = "contributor@example.invalid"


def _redact_emails(text: str) -> tuple[str, int]:
    """Replace every address, and say how many — silence here is the failure.

    Returned rather than logged so :func:`_documents` can report the total once
    for the source instead of once per file, and so a test can assert the count
    is what it was rather than merely that the function ran.
    """
    found = len(_EMAIL.findall(text))
    return (_EMAIL.sub(_EMAIL_REPLACEMENT, text) if found else text), found


#: ``None`` until probed, then ``True``/``False``. Probed once per process.
_chokepoint: bool | None = None

#: Local part of the handover probe. Self-describing on purpose: if it ever
#: turns up in a corpus file, the file came from a probe and not from a person.
_PROBE_LOCAL = "whetstone-chokepoint-probe"

#: TLDs to build the probe address from, best first. All four of the leading
#: entries are reserved by RFC 2606/6761 and can never resolve, which is exactly
#: why a chokepoint may legitimately *exempt* them — documentation addresses are
#: fixtures, not people, and this corpus is full of them on purpose.
#:
#: **That exemption broke the first version of this probe**, and it is the
#: project's recurring defect class: the first probe used
#: ``probe@example.invalid``, the chokepoint correctly left it alone as a
#: documentation address, and the probe concluded there was no chokepoint while
#: one was running perfectly two frames up the stack. The ruler was wrong, not
#: the thing being measured. So the TLD is now chosen as the first one the
#: chokepoint does *not* exempt, and ``.probe`` — delegated by nobody, in no
#: root zone, unroutable — is the floor.
_PROBE_TLDS = ("invalid", "test", "example", "localhost", "probe")


def _probe_address(build) -> str:
    """A fabricated address the chokepoint's own policy should not exempt.

    Built from the chokepoint's reserved-TLD set at runtime rather than written
    down, so a probe cannot be silently classified as a documentation fixture
    and answer the wrong question. Falls back to the first entry — a genuinely
    reserved TLD — when there is no such set to read, which is the right default
    for a probe that is about to be discarded anyway.
    """
    reserved = set(getattr(build, "_EMAIL_RESERVED_TLDS", ()) or ())
    tld = next((t for t in _PROBE_TLDS if t not in reserved), _PROBE_TLDS[0])
    return f"{_PROBE_LOCAL}@whetstone-probe.{tld}"


def _email_policy_says_redact() -> bool | None:
    """The structural half: what does ``build.py``'s policy say about us?

    ``True`` redact, ``False`` keep deliberately, ``None`` no policy surface at
    all. Separated from the behavioural half so each can be tested on its own —
    the interesting failure is a policy that says one thing while ``_redacted``
    does another, and a single boolean cannot express that.
    """
    try:
        from .. import build

        return not build._email_policy(SPEC.name).keep_third_party
    except Exception:                 # noqa: BLE001 - absence is the answer
        return None


def _chokepoint_owns_addresses() -> bool:
    """Has ``build.py`` taken over email policy for this source?

    Asked of the thing that actually decides — ``build._email_policy(name)`` —
    and then **confirmed behaviourally** by pushing a fabricated address through
    ``build._redacted`` and checking it is gone. Both halves are needed, and the
    reason is this source's own history: the commit that added redaction here
    landed twenty days after the artifact it was meant to protect, so the
    shipped file held thirteen distinct addresses and zero markers. A redactor
    that was never invoked looks identical to one that found nothing, and so
    does a handover to a chokepoint that claims a policy it does not apply.

    Three answers, not two:

    * **The policy says keep.** The chokepoint owns the question and has decided
      deliberately — ``rfc`` and ``kerneldocs`` keep author addresses because
      their licences are satisfied by exactly those lines. This source does not
      get a second vote on a decision recorded there with a reason.
    * **The policy says redact and the probe confirms it.** Handed over.
    * **Anything else.** Fails **closed**: no policy function, a signature that
      moved, the lazy ``training.trajectories`` import failing in a container, a
      policy that claims redaction and delivers none. This source redacts for
      itself and says so in the build log. The expensive mistake is available in
      only one direction.

    Handing over is not just tidiness. The chokepoint replaces an address with
    one of a *varied* set of plausible locals; this file replaces every address
    with a single literal. Both satisfy privacy and only one of them leaves the
    model able to read an address — a single-token substitution passes the
    privacy gate and makes the model worse, so running this layer on top of a
    working chokepoint would undo the better of the two.
    """
    global _chokepoint
    if _chokepoint is not None:
        return _chokepoint
    _chokepoint = False
    says_redact = _email_policy_says_redact()
    if says_redact is None:
        return _chokepoint
    if not says_redact:
        _chokepoint = True            # a recorded exception, not an omission
        return _chokepoint
    try:
        from .. import build

        policy = build._email_policy(SPEC.name)
        address = _probe_address(build)
        doc = Document(text=f"a report from {address} about a finding",
                       source=SPEC.name, register=Register.PROSE,
                       side=Side.NEUTRAL, ident="_probe")
        # The counter list is a throwaway: the chokepoint accumulates per-source
        # address counts for its report, and a probe must not land in them.
        for args in ((doc, policy, [0, 0]), (doc,)):
            try:
                out = build._redacted(*args)
            except TypeError:
                continue            # not this arity; try the other
            _chokepoint = address not in out.text
            break
    except Exception:                 # noqa: BLE001 - absence is the answer
        _chokepoint = False
    return _chokepoint


#: Headings that introduce a list of *people*.
#:
#: Matched at the start of a line only, so "the author of this tool" in a
#: sentence is not a roster heading. Both spellings of "acknowledgement" are
#: here because this author writes British English and the upstream READMEs in
#: his tree write American.
_ROSTER_HEADING = re.compile(
    r"(?im)^[ \t]{0,3}\#{1,6}[ \t]*(?:the[ \t]+)?"
    r"(?:team(?:[ \t]+members)?|members|contributors?|authors?"
    r"|group(?:[ \t]+members)?|credits?|acknowledge?ments?|collaborators?"
    r"|developers|maintainers|our[ \t]+team|project[ \t]+team|students"
    r"|reviewers?|supervisors?|advisors?|advisers?|mentors?|instructors?)"
    r"\b[^\n]*$")

#: Any heading, used only to find where a roster section ends.
_ANY_HEADING = re.compile(r"^[ \t]{0,3}\#{1,6}[ \t]")

#: A markdown or numbered list marker.
_LIST_MARKER = re.compile(r"^[ \t]*(?:[-*+]|\d+[.)])[ \t]+")

#: "Firstname Lastname", optionally with a middle name or initial, after any
#: leading markdown emphasis. Two capitalised word-shaped tokens is the whole
#: signal; there is no name list behind this and there must not be one, since a
#: list of the names somebody already noticed is a new copy of the leak.
#:
#: The middle element is ``[A-Z]`` plus *either* lowercase letters *or* an
#: optional period, so "Alice Q. Example" and "Bob R Specimen" both parse. The
#: first calibration run missed the second of those — one bare initial, no
#: period — which took a two-person roster down to one detected entry and under
#: the threshold. Fixed before this looked at anything real.
_PERSON_NAME = re.compile(
    r"^[*_`\s>]*([A-Z][a-z]{1,19}(?:[ \t]+[A-Z](?:[a-z]{1,19}|\.?))?"
    r"[ \t]+[A-Z][a-z]{1,19})(?=[ \t]*(?:[-–—:,(<]|\*\*|$))")

#: Final words that make a capitalised pair an organisation rather than a
#: person. Without this, "OWASP Foundation", "Espressif Systems" and "Linux
#: Foundation" — all of which appear in credit lists in this tree — read as
#: people, and the policy would start dropping documents for crediting a
#: company. Calibrated against fixtures before it was pointed at anything.
_ORG_WORDS = {
    "foundation", "institute", "inc", "inc.", "ltd", "ltd.", "llc", "gmbh",
    "corp", "corp.", "corporation", "company", "technologies", "technology",
    "systems", "labs", "lab", "laboratory", "laboratories", "university",
    "college", "school", "project", "projects", "team", "teams", "group",
    "groups", "software", "hardware", "community", "alliance", "consortium",
    "committee", "council", "society", "association", "organization",
    "organisation", "industries", "semiconductor", "semiconductors",
    "electronics", "networks", "security", "research", "engineering",
    "foundation.", "working", "authors", "contributors", "maintainers",
    "developers", "devs", "crew", "collective", "studio", "studios",
}


def _is_person_entry(line: str) -> tuple[bool, bool]:
    """``(looks like a person, carries an address)`` for one roster line.

    The name has to be an entry *label* — followed by a dash, a colon, a comma,
    a bracket, or end of line — rather than the first two words of a sentence.
    That one lookahead is what separates ``**Jane Roe** - Sensor Integration``
    from ``These Credits list the upstream projects``.
    """
    body = line[m.end():] if (m := _LIST_MARKER.match(line)) else line
    name = _PERSON_NAME.match(body)
    if name is None:
        return False, False
    if name.group(1).split()[-1].lower().strip(".,") in _ORG_WORDS:
        return False, False
    return True, bool(_EMAIL.search(body))


def _roster_section(text: str) -> str | None:
    """Name the roster heading that makes this document about other people.

    **Policy: a document with a personal roster is excluded entirely, not
    scrubbed.** That is the whole decision and it is worth stating plainly,
    because scrubbing is the cheaper-looking option and it is wrong here.

    The document that forced this was a four-person university group project
    README. Deleting the four addresses leaves four full names, each against a
    named role, under a named course code, in a document whose subject is that
    those four people built this. A reader reconstructs the roster from what is
    left; a model trained on it has learned the association regardless. The
    addresses were never the thing that identified anyone — they were the part
    that happened to be patternable. A half-scrubbed README is worse than either
    choice, because it *looks* handled.

    So the test is structural: a heading that introduces people, followed by
    **two or more** person-shaped entries, or **one** person-shaped entry that
    also carries an address. One name plus a contact address is not a
    borderline case.

    **What this cannot reach, stated plainly.** A name is not patternable the
    way an address is, and nothing here pretends otherwise:

    * A name in running prose — "thanks to Jane Roe for the review" — is not
      found. There is no heading and no entry structure to key on.
    * A roster introduced by bold text or a table instead of a heading is not
      found.
    * A mononym, a name whose family name is lowercase ("van der Berg"), a name
      in a non-Latin script, or a handle that is somebody's real name is not
      found.
    * Conversely, two capitalised words that are neither an organisation nor a
      person — a product pair, a place — will drop a document. The cost of that
      is one README out of a couple of hundred; the cost of the other error is
      somebody else's name in published weights.

    This is a floor, not a guarantee, and the honest consequence is that this
    source stays **the one that needs a human to look at what it collects**. It
    is also why the policy excludes rather than edits: an exclusion that fires
    on the wrong document loses a README, while a scrub that misses a name
    publishes it.
    """
    lines = text.split("\n")
    for index, line in enumerate(lines):
        if not _ROSTER_HEADING.match(line):
            continue
        people = 0
        with_address = 0
        # A section runs to the next heading. The 40-line bound stops a README
        # whose last heading is "Credits" from scanning its whole tail.
        for candidate in lines[index + 1:index + 41]:
            if _ANY_HEADING.match(candidate):
                break
            is_person, has_address = _is_person_entry(candidate)
            if is_person:
                people += 1
                with_address += has_address
        if people >= 2 or with_address:
            return line.strip()
    return None


def _documents(path: Path) -> Iterator[Document]:
    """Yield prose from the cache, minus other people's data and other people's
    documentation.

    Order matters in one place. :func:`_roster_section` runs **before** any
    email redaction, because an address next to a name is half of its evidence;
    redact first and a one-person roster stops being detectable. The chokepoint
    in ``build.py`` runs after ``documents()`` has yielded, so that ordering
    holds whichever layer ends up doing the redaction.
    """
    redacted = 0
    vendored = 0
    rosters: list[str] = []
    chokepoint = _chokepoint_owns_addresses()
    for file in sorted(path.iterdir()):
        if not file.is_file() or file.is_symlink():
            continue
        name = file.name
        if file.suffix.lower() not in _KEEP:
            continue
        # Second line of defence, and the one that matters for the caches
        # already on disk. _fetch prunes the walk, but it returns early on a
        # non-empty cache directory — and the two caches sitting on the SSD were
        # populated before this list grew, so 663 of 849 files in one of them are
        # vendored. A cache is an input like any other input.
        if _vendored(name):
            vendored += 1
            continue
        try:
            raw = file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        text = normalise(raw)
        if len(text) < 200:
            continue
        roster = _roster_section(text)
        if roster is not None:
            rosters.append(f"{name} ({roster})")
            continue
        if not chokepoint:
            text, n = _redact_emails(text)
            redacted += n
        yield Document(text=text, source="ownrepos", register=Register.PROSE,
                       side=Side.NEUTRAL, ident=name)
    if vendored:
        print(f"   ownrepos: skipped {vendored:,} vendored file(s) in the cache")
    for entry in rosters:
        # Named, not counted. A document dropped for carrying someone else's
        # identity is a decision the maintainer should see, and the heading is
        # enough to find it again without printing a line of it here.
        print(f"   ownrepos: EXCLUDED {entry} — third-party roster")
    if not chokepoint and redacted:
        # Loud on purpose. This line means the handover did not take and a
        # single-token substitution is being used where the chokepoint's varied
        # one should be — worth a look rather than worth ignoring.
        print(f"   ownrepos: redacted {redacted} email address(es) locally "
              f"— build.py's chokepoint did not answer for this source")


SPEC = SourceSpec(
    name="ownrepos",
    # Stated so it is checkable, not so it reads well. The previous string —
    # "all repositories are this author's own work" — was false of 54.2% of the
    # characters it shipped, which were vendored ESP-IDF and PlatformIO
    # documentation. build.py refuses a blank licence; a false one is worse than
    # a blank one, because nothing downstream has a reason to look again.
    license=("MIT — this author's own repositories only. Vendored dependency "
             "trees are excluded by _SKIP_PARTS rather than relicensed, and "
             "documents carrying third-party personal data are excluded by "
             "_roster_section rather than scrubbed."),
    url="https://github.com/at0m-b0mb",
    register=Register.PROSE,
    side=Side.NEUTRAL,
    fetch=_fetch,
    documents=_documents,
    # Was 500, which only ever cleared because vendored documentation was being
    # counted: 500 of the 695 documents in the shipped artifact came from
    # dependency trees. A walk of this tree today offers 259 first-party
    # markdown and rst files. 150 is a floor that notices a broken walk — the
    # thing this field is for — without crying wolf on every build.
    expect_min_docs=150,
    notes=("Hand-written security tooling and its design argumentation. Close in "
           "register to the report prose Whetstone must itself produce. The only "
           "source read off this machine, so the only one that can leak a third "
           "party: see _roster_section."),
)
