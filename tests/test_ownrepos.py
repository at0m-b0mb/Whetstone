"""Tests for the one source read off this machine.

Forty-six sources are public upstreams. This one walks the maintainer's own
repositories, which makes it the only adapter that can carry *another person's*
identity into the corpus — and a corpus is the thing that becomes weights, where
nothing is greppable and nothing is removable. Three separate audits of the
shipped artifact converged on the same document, so the properties below are
pinned rather than assumed:

* a third-party roster is **excluded**, not scrubbed;
* vendored dependency documentation is not collected, so the licence
  declaration is true;
* the walk does not follow a symlink, because it did once and the corpus ate
  itself;
* email redaction hands over to ``build.py``'s chokepoint without a window in
  which nobody does it.

**The source is now EXCLUDED from every build**, which is why the module is
``_ownrepos.py``: :func:`training.corpus.build.discover_sources` skips a leading
underscore. The owner's decision, and the reasoning is arithmetic rather than
squeamishness — this adapter contributed the PROSE register, which is the most
replaceable material in the corpus, while being the only source able to carry a
third party's identity into the weights, and it was measured as **54% vendored
dependency documentation** shipped under a licence asserting it was all the
author's own work.

These tests are kept rather than deleted. They pin what the adapter *would* do,
so a future decision to re-enable it starts from known behaviour instead of from
scratch — and :func:`test_the_source_is_excluded_from_every_build` pins the
exclusion itself, so re-enabling it has to be deliberate.

**Every value in this file is fabricated.** Names are invented, addresses use
the ``.invalid`` TLD that RFC 2606 reserves so it can never resolve, and no real
identifier is written anywhere — the audit that found these leaks created a new
one by writing its own needle table to a JSON file, and that mistake is not
repeated here.
"""

from __future__ import annotations

import getpass
import re
from pathlib import Path

import pytest

import training.corpus.sources._ownrepos as own
from training.corpus.source import Document, Register, Side


def test_the_source_is_excluded_from_every_build() -> None:
    """The exclusion is the point, so it is pinned and not left to a filename.

    ``discover_sources`` skips a module whose name starts with an underscore, so
    renaming the file is the documented mechanism. Renaming it *back* would
    silently return the operator's own repositories — and a third party's
    name — to a corpus that becomes weights. This test makes that a deliberate
    act with a failing suite attached.
    """
    from training.corpus import build

    discovered = {spec.name for spec in build.discover_sources()}
    assert "ownrepos" not in discovered, (
        "ownrepos is back in the build; if that is intended, the third-party "
        "roster policy and the vendored-documentation licence claim both need "
        "re-checking first"
    )
    # The counterpart assertion, so this cannot pass by discovering nothing.
    assert len(discovered) > 50, sorted(discovered)

# --------------------------------------------------------------------------
# Fabricated fixtures. Nothing below corresponds to a real person or address.
# --------------------------------------------------------------------------

#: The shape of the document the audits found: a four-person university group
#: project, every member by full name, role and personal address. Rewritten here
#: with invented people so the policy can be tested without reproducing it.
ROSTER_README = """# Smart Thermostat Security

A coursework project for a secure-software-development module.

## Team Members

- **Alice Example** - Authentication, User Management, Logging \
(alice@students.example.invalid)
- **Bob Specimen** - Sensor Integration, Weather, Diagnostics \
(bob@students.example.invalid)
- **Carol Placeholder** - HVAC Control, Profiles, Energy \
(carol@students.example.invalid)
- **Dave Fictitious** - Security Controls, Notifications \
(dave@students.example.invalid)

## Design

The thermostat exposes a REST API behind a reverse proxy. Authentication is
bcrypt over a sqlite3 store, which is adequate for a coursework deployment and
would not be adequate for anything reachable from the internet, and the report
says so rather than claiming otherwise.
"""

#: The shape of this author's *own* credit sections, which must survive. These
#: credit projects and handles, not people, and dropping them would cost the
#: PROSE register the documents it exists for.
CREDITS_README = """# Aurora

A Sub-GHz band waterfall for the Flipper Zero. The noise floor is a running
quartile rather than a mean, because a mean is dragged up by the carrier you are
trying to see and then reports that there is nothing there.

## Credits & licence

Built by **[example-owner](https://github.com/example-owner)**. Part of a family of
radio tools:

- **[Sibyl](https://github.com/example-owner/Sibyl-FlipperZero)** - signal classifier
- **[Cerberus](https://github.com/example-owner/flipper-cerberus)** - RF watchdog
- 5x8 screen font from STMicroelectronics' evaluation sources, BSD-3-Clause
- **OWASP Foundation** - for the testing guide this README argues against
"""

#: Vendored upstream documentation: real text, genuinely useful, and not this
#: author's work. 54.2% of the characters this source shipped looked like this.
VENDORED_DOC = """LVGL Profiler

The profiler measures how long each part of the rendering pipeline takes. Enable
it with LV_USE_PROFILER and provide a tick source. The output is a table of
timings per refresh, which is the only way to tell a slow draw from a slow
flush, and the two have completely different fixes.
"""

PROSE = ("A grading engine that can award an A+ has not understood the problem. "
         "Every credential in this format authenticates nothing, so the ceiling "
         "is an F and the report says why rather than hedging. " * 3)


def _write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def cache(tmp_path: Path) -> Path:
    """An empty cache directory, the shape ``_documents`` is handed."""
    d = tmp_path / "cache"
    d.mkdir()
    return d


@pytest.fixture
def tree(tmp_path: Path, monkeypatch) -> Path:
    """A scratch project tree that ``_fetch`` will walk instead of the real one.

    ``_fetch`` derives the project root from the module's ``__file__`` —
    ``parents[3].parent`` — so pointing ``__file__`` at a five-deep path under a
    scratch root redirects the walk without the function needing a parameter it
    would otherwise only have for tests.
    """
    root = tmp_path / "project"
    root.mkdir()
    monkeypatch.setattr(
        own, "__file__", str(root / "p0" / "p1" / "p2" / "p3" / "ownrepos.py"))
    return root


class TestSymlinkedWalk:
    """``os.walk(followlinks=False)``, never ``rglob``. This one cost 180 MB.

    The repository holds a ``data`` symlink pointing at the external SSD where
    the corpus cache lives. ``rglob("*")`` follows symlinks, so the first run of
    this adapter walked through it and copied NVD JSON, Sigma YAML and
    PowerShell markdown back in, all relabelled PROSE. The corpus ate itself and
    the only thing that noticed was the balance report showing prose at 82%
    against a 10% target.
    """

    def test_a_symlinked_directory_is_not_walked_through(
            self, tree: Path, tmp_path: Path, cache: Path):
        outside = tmp_path / "outside_the_tree"
        _write(outside, "POISON.md", "POISON-BEACON " + PROSE)
        _write(tree, "repo/README.md", "FIRST-PARTY " + PROSE)
        (tree / "repo" / "data").symlink_to(outside, target_is_directory=True)

        own._fetch(cache)

        names = sorted(p.name for p in cache.iterdir())
        assert any("README.md" in n for n in names), names
        assert not any("POISON" in n for n in names), names
        blob = "".join(p.read_text(encoding="utf-8") for p in cache.iterdir())
        assert "POISON-BEACON" not in blob

    def test_a_symlinked_file_is_not_copied(
            self, tree: Path, tmp_path: Path, cache: Path):
        """The walk flag covers directories; files need their own check."""
        outside = tmp_path / "outside_the_tree"
        target = _write(outside, "POISON.md", "POISON-BEACON " + PROSE)
        _write(tree, "repo/README.md", "FIRST-PARTY " + PROSE)
        (tree / "repo" / "alias.md").symlink_to(target)

        own._fetch(cache)

        blob = "".join(p.read_text(encoding="utf-8") for p in cache.iterdir())
        assert "POISON-BEACON" not in blob

    def test_a_symlinked_file_in_the_cache_is_not_read(
            self, cache: Path, tmp_path: Path):
        """And again at the read side, for a cache somebody else populated."""
        target = _write(tmp_path / "outside_the_tree", "POISON.md",
                        "POISON-BEACON " + PROSE)
        _write(cache, "Repo__README.md", "FIRST-PARTY " + PROSE)
        (cache / "Repo__alias.md").symlink_to(target)

        texts = [d.text for d in own._documents(cache)]
        assert any("FIRST-PARTY" in t for t in texts)
        assert not any("POISON-BEACON" in t for t in texts)

    def test_the_source_uses_os_walk_and_not_rglob(self):
        """A property about the code, because the cost of regressing it is 180 MB.

        ``rglob`` follows symlinks and no keyword argument turns that off, so
        the only safe form is the one that states the guarantee.

        Asserted against the code with docstrings and comments **stripped**. The
        first version of this test read the whole file, and a mutation run
        caught it passing on the word ``followlinks=False`` appearing in
        ``_fetch``'s docstring while the call itself said ``True``. A test that
        can be satisfied by prose about the fix is not a test of the fix.
        """
        src = Path(own.__spec__.origin).read_text(encoding="utf-8")
        code = re.sub(r'"""(?:.|\n)*?"""', "", src)
        code = re.sub(r"#[^\n]*", "", code)
        assert "os.walk(" in code
        assert "followlinks=False" in code, "state the guarantee at the call"
        assert "followlinks=True" not in code
        assert "rglob" not in code, "rglob follows symlinks; use os.walk"

    def test_both_symlink_guards_are_present(self):
        """``followlinks=False`` and the per-entry check are each sufficient alone.

        Which is why neither can be pinned by behaviour on its own: delete one
        and the other still stops the walk. Stated here as a code property, with
        the behavioural tests above covering what happens when both are gone,
        because the honest alternative — pretending one test covers both — is how
        a redundant guard quietly becomes a single point of failure.
        """
        src = Path(own.__spec__.origin).read_text(encoding="utf-8")
        code = re.sub(r'"""(?:.|\n)*?"""', "", src)
        code = re.sub(r"#[^\n]*", "", code)
        walk = code[code.index("def _fetch"):code.index("def _probe_address")]
        assert "followlinks=False" in walk
        assert "Path(dirpath, d).is_symlink()" in walk, "prune symlinked dirs"
        assert "path.is_symlink()" in walk, "skip symlinked files"


class TestVendoredIsNotCollected:
    """54.2% of the characters this source shipped were not its author's.

    ESP-IDF components under ``managed_components/`` and PlatformIO library
    dependencies under ``.pio/libdeps/``, carried under a licence string reading
    "all repositories are this author's own work". The old guard was
    ``name.startswith(_SKIP_TOKENS)``, which on the 849-file cache on disk today
    matches **zero** files, because a flattened path begins with the repository
    name and not with the vendored directory.
    """

    @pytest.mark.parametrize("name,expected", [
        ("Dolos__managed_components__espressif__esp_tinyusb__README.md",
         "managed_components"),
        ("Orthrus__.pio__libdeps__board__IRremote__README.md", ".pio"),
        ("Pharos__components__espressif__esp_lcd__README.md", "espressif"),
        ("App__node_modules__left-pad__README.md", "node_modules"),
        ("App__.venv__lib__site-packages__pkg__README.rst", ".venv"),
        ("iOSApp__Pods__Alamofire__README.md", "Pods"),
        ("iOSApp__Carthage__Checkouts__lib__README.md", "Carthage"),
        ("iOSApp__DerivedData__Index__README.md", "DerivedData"),
        ("Tool__.piovenv__Scripts__README.md", ".piovenv"),
        ("Lib__third_party__zlib__README.md", "third_party"),
        ("Lib__subprojects__gnulib__README.md", "subprojects"),
    ])
    def test_a_vendored_segment_is_named_wherever_it_sits(self, name, expected):
        assert own._vendored(name) == expected

    @pytest.mark.parametrize("name", [
        "Aurora-FlipperZero__README.md",
        "AirDriver__docs__chipsets.md",
        "Whetstone__training__corpus__README.md",
        "Sieve__CHANGELOG.md",
        "Pharos__components__pharos_radio__README.md",
    ])
    def test_first_party_names_are_not_vendored(self, name):
        assert own._vendored(name) is None

    def test_the_cache_reader_skips_vendored_names(self, cache: Path):
        """The test that fails against the old ``startswith`` guard.

        ``_fetch`` prunes the walk, but it returns early on a non-empty cache —
        and the caches on the SSD were populated before the skip list grew. A
        cache is an input like any other input.
        """
        _write(cache, "Aurora__README.md", PROSE)
        _write(cache, "Dolos__managed_components__espressif__usb__README.md",
               VENDORED_DOC + PROSE)
        _write(cache, "Orthrus__.pio__libdeps__b__IRremote__README.md",
               VENDORED_DOC + PROSE)

        idents = [d.ident for d in own._documents(cache)]
        assert idents == ["Aurora__README.md"], idents

    def test_the_walk_prunes_vendored_directories(self, tree: Path, cache: Path):
        _write(tree, "repo/README.md", "FIRST-PARTY " + PROSE)
        _write(tree, "repo/managed_components/espressif__tinyusb/README.md",
               "VENDOR-BEACON " + VENDORED_DOC + PROSE)
        _write(tree, "repo/.pio/libdeps/board/lib/README.md",
               "VENDOR-BEACON " + VENDORED_DOC + PROSE)
        _write(tree, "repo/components/espressif__esp_lcd/README.md",
               "VENDOR-BEACON " + VENDORED_DOC + PROSE)

        own._fetch(cache)

        blob = "".join(p.read_text(encoding="utf-8") for p in cache.iterdir())
        assert "FIRST-PARTY" in blob
        assert "VENDOR-BEACON" not in blob

    def test_an_espressif_component_directory_is_pruned_by_its_first_segment(self):
        """ESP-IDF names a registry component ``espressif__<name>``.

        The ``__`` separating author from component is the same ``__`` the
        flattener uses as a path separator, so one rule — the first segment of a
        directory name — covers the walk and the cache reader identically,
        rather than two patterns that can drift.
        """
        assert own._skip_dir("espressif__esp_tinyusb")
        assert own._skip_dir("managed_components")
        assert not own._skip_dir("pharos_radio")
        assert not own._skip_dir("components")


class TestLicenceDeclarationIsTrue:
    """``build.py`` refuses a blank licence. Nothing was checking a false one.

    A false declaration is worse than a blank one, because nothing downstream
    has a reason to look again.
    """

    def test_the_declaration_does_not_claim_everything_is_his_own_work(self):
        text = own.SPEC.license.lower()
        assert "all repositories are this author's own work" not in text

    def test_the_declaration_names_how_it_is_made_true(self):
        text = own.SPEC.license
        assert "_SKIP_PARTS" in text
        assert "_roster_section" in text

    def test_nothing_collected_contradicts_the_declaration(self, cache: Path):
        """The declaration as an assertion over output, not a string match."""
        _write(cache, "Aurora__README.md", PROSE)
        _write(cache, "Dolos__managed_components__lvgl__lvgl__docs__api.rst",
               VENDORED_DOC + PROSE)
        _write(cache, "Course__README.md", ROSTER_README)

        for doc in own._documents(cache):
            assert own._vendored(doc.ident) is None, doc.ident
            assert own._roster_section(doc.text) is None, doc.ident

    def test_the_document_floor_no_longer_counts_vendored_documentation(self):
        """500 was only ever cleared because dependency docs were counted.

        500 of the 695 documents in the shipped artifact came from vendored
        trees; a walk of the real tree offers 259 first-party markdown and rst
        files and collects 184 from the cache on disk. A floor above that is a
        warning on every build, which trains everyone to ignore the warning.
        """
        assert own.SPEC.expect_min_docs < 500
        assert own.SPEC.expect_min_docs >= 100, "still has to notice a broken walk"


class TestThirdPartyRosterIsExcluded:
    """The audits' most serious finding, and the one that is not his to fix later.

    One README listed four people by full name, role and personal ``.edu``
    address. They did not agree to appear in a published model's training data.
    """

    def test_the_roster_document_is_excluded_entirely(self, cache: Path):
        _write(cache, "Aurora__README.md", CREDITS_README + PROSE)
        _write(cache, "smart-thermostat__README.md", ROSTER_README)

        docs = list(own._documents(cache))
        idents = [d.ident for d in docs]
        assert idents == ["Aurora__README.md"], idents

    def test_exclusion_rather_than_scrubbing(self, cache: Path):
        """Removing the addresses would leave four names against four roles.

        A reader reconstructs the roster from what is left and a model has
        learned the association regardless. The addresses were never the thing
        that identified anyone — they were the part that happened to be
        patternable.
        """
        _write(cache, "Course__README.md", ROSTER_README)
        blob = "\n".join(d.text for d in own._documents(cache))
        for surname in ("Example", "Specimen", "Placeholder", "Fictitious"):
            assert surname not in blob
        assert "Team Members" not in blob
        assert "coursework project" not in blob

    @pytest.mark.parametrize("text,why", [
        ("## Team Members\n\n- **Alice Example** - auth (a@x.invalid)\n",
         "one name plus a contact address is not borderline"),
        ("## Team Members\n\n- **Alice Example** - auth\n- **Bob Specimen** - radio\n",
         "two names, no address"),
        ("### Group Members\n\n1. Alice Example - lead\n2. Bob Specimen - tester\n",
         "numbered list"),
        ("## Authors\n\n**Alice Example** - Institute of Nowhere\n\n"
         "**Bob Specimen** - [Site](http://example.invalid/)\n",
         "no list markers"),
        ("## Project Team\n\n- Alice Example: protocol\n- Bob Specimen: radio\n",
         "colon separator"),
        ("## Team\n\n- **Alice Q. Example** - crypto\n- **Bob R Specimen** - parsing\n",
         "middle initial with and without a period"),
        ("## Collaborators\n\n- Alice Example <alice@example.invalid>\n",
         "angle-bracketed address"),
    ])
    def test_rosters_fire(self, text, why):
        assert own._roster_section(text) is not None, why

    @pytest.mark.parametrize("text,why", [
        (CREDITS_README, "credits to projects and handles, which must survive"),
        ("## Credits\n\n- [ArminJo](https://github.com/ArminJo) Maintainer\n"
         "- [z3t0](https://github.com/z3t0) main contributor until 2.4.0\n",
         "bare GitHub handles are not person-shaped names"),
        ("## Acknowledgments\n\n- **OWASP Foundation** - the Top 10\n"
         "- **Espressif Systems** - the toolchain\n"
         "- **Linux Foundation** - kernel documentation\n",
         "organisations, not people"),
        ("# Contributor Covenant Code of Conduct\n\n## Our Pledge\n\n"
         "We as members pledge to make participation harassment-free.\n",
         "a code of conduct is not a roster"),
        ("## Credits\n\nThanks to Alice Example for reviewing the ASN.1 parser.\n",
         "a name in running prose is a KNOWN MISS, not a catch"),
        ("## Features\n\n- Band Waterfall - quartile noise floor\n"
         "- Replay Guard - proves the code advances\n",
         "capitalised pairs with no roster heading"),
        ("## Maintainers\n\n- [example-owner](https://github.com/example-owner)\n",
         "one handle"),
        ("## Team\n\n### How to contact us\n\nOpen an issue.\n",
         "a section that ends at the next heading"),
        ("## Credits\n\n- Hong Kong Science Park provided the bench\n",
         "a place-name pair"),
    ])
    def test_non_rosters_do_not_fire(self, text, why):
        assert own._roster_section(text) is None, why

    def test_the_section_ends_at_the_next_heading(self):
        """A roster heading must not claim entries from the section after it.

        ``## Credits`` here holds no people. The two name-shaped lines live
        under ``## Features``, which is not a roster heading, so a working
        section boundary returns ``None`` and a broken one fires.
        """
        text = ("## Credits\n\nThanks to the upstream projects.\n\n"
                "## Features\n\n- Alice Example - draft 1\n"
                "- Bob Specimen - draft 2\n")
        assert own._roster_section(text) is None

    def test_a_reviewer_list_is_a_roster(self):
        """Found by the first run of these tests, which asserted the wrong
        answer: ``## Reviewers`` was missing from the heading list.

        A section listing people who reviewed the work is a roster of third
        parties exactly like a team list, so ``reviewers``, ``supervisors``,
        ``advisors``, ``mentors`` and ``instructors`` are all in the list now —
        a coursework README names all five of those.
        """
        text = ("## Reviewers\n\n- Alice Example - draft 1\n"
                "- Bob Specimen - draft 2\n")
        assert own._roster_section(text) == "## Reviewers"

    def test_an_organisation_pair_is_not_a_person(self):
        assert own._is_person_entry("- **Linux Foundation** - kernel docs") \
            == (False, False)
        assert own._is_person_entry("- **Alice Example** - auth") == (True, False)
        assert own._is_person_entry("- **Alice Example** (a@x.invalid)") \
            == (True, True)

    def test_the_known_misses_are_documented_rather_than_implied(self):
        """An honest floor says what it cannot reach. Vigil's keystone.

        A detector whose limits are undocumented gets read as a guarantee, and
        the next person deletes the human review step that this source still
        needs.
        """
        doc = own._roster_section.__doc__ or ""
        assert "cannot reach" in doc
        assert "running prose" in doc
        assert "floor, not a guarantee" in doc


class TestEmailRedactionHandover:
    """Redaction belongs at the chokepoint. Getting there must not open a gap.

    The commit that added email redaction to this file is dated twenty days
    *after* the corpus artifact it was meant to protect was written. The shipped
    ``ownrepos.jsonl`` holds thirteen distinct addresses and zero instances of
    the replacement marker — and the only thing that told "never invoked" apart
    from "found nothing" was grepping for the marker rather than for the absence
    of addresses.
    """

    @pytest.fixture(autouse=True)
    def _reset_probe(self):
        own._chokepoint = None
        yield
        own._chokepoint = None

    def test_this_source_redacts_when_the_chokepoint_does_not(self, cache: Path,
                                                              monkeypatch):
        monkeypatch.setattr(own, "_chokepoint", False)
        _write(cache, "Tool__CONTRIBUTING.md",
               "Mail reports to reporter@example.invalid before disclosing.\n" + PROSE)

        text = "\n".join(d.text for d in own._documents(cache))
        assert "reporter@example.invalid" not in text
        assert own._EMAIL_REPLACEMENT in text

    def test_this_source_stands_down_when_the_chokepoint_exists(self, cache: Path,
                                                                monkeypatch):
        """Once the chokepoint covers all forty-seven sources, this stops.

        The text this source yields is then *pre*-chokepoint text by definition,
        so the assertion is that it is handed over unmodified rather than that
        it is clean — ``build.py`` cleans it a moment later.
        """
        monkeypatch.setattr(own, "_chokepoint", True)
        body = "Mail reports to reporter@example.invalid first.\n" + PROSE
        _write(cache, "Tool__CONTRIBUTING.md", body)

        docs = list(own._documents(cache))
        assert "reporter@example.invalid" in docs[0].text
        assert own._EMAIL_REPLACEMENT not in docs[0].text

    def test_the_probe_fails_closed(self, monkeypatch):
        """Any failure answers "no chokepoint", so this source keeps redacting.

        The expensive mistake is available in only one direction: a probe that
        guessed "yes" wrongly would stand this source down with nothing behind
        it, which is exactly the twenty-day window, re-created on purpose.
        """
        from training.corpus import build

        def boom(name):
            raise AttributeError("policy resolver renamed")

        monkeypatch.setattr(build, "_email_policy", boom)
        own._chokepoint = None
        assert own._chokepoint_owns_addresses() is False

    def test_the_policy_half_fails_closed_on_its_own(self, monkeypatch):
        """No policy surface at all answers ``None``, never "yes".

        Pinned separately from the probe as a whole because the two halves each
        fail closed independently, so a single behavioural test cannot tell
        which one is doing it — and a redundant guard nobody tests is a single
        point of failure waiting to be tidied away.
        """
        from training.corpus import build

        def gone(name):
            raise AttributeError("policy resolver renamed")

        monkeypatch.setattr(build, "_email_policy", gone)
        assert own._email_policy_says_redact() is None

    def test_the_behavioural_half_fails_closed_on_its_own(self, monkeypatch):
        """A chokepoint that raises mid-probe answers "no", not "probably".

        This is the container case the chokepoint's own lazy
        ``training.trajectories`` import makes real: the policy resolves fine,
        the redaction call blows up, and the only safe reading is that nothing
        is redacting.
        """
        from training.corpus import build

        redact = build._EmailPolicy("ownrepos", False, "default policy")
        monkeypatch.setattr(build, "_email_policy", lambda name: redact)

        def boom(*args, **kwargs):
            raise ImportError("training.trajectories unavailable in this build")

        monkeypatch.setattr(build, "_redacted", boom)
        own._chokepoint = None
        assert own._email_policy_says_redact() is True
        assert own._chokepoint_owns_addresses() is False

    def test_a_policy_that_claims_redaction_and_delivers_none_fails_closed(
            self, monkeypatch):
        """The handover gets the same positive control the redactor got.

        A chokepoint that resolves a "redact" policy and then does not apply it
        is the handover's version of a redactor that was never invoked, and the
        structural check alone cannot tell the two apart. So the probe pushes a
        fabricated address through and looks.
        """
        from training.corpus import build

        redact = build._EmailPolicy("ownrepos", False, "default policy")
        monkeypatch.setattr(build, "_email_policy", lambda name: redact)
        monkeypatch.setattr(build, "_redacted", lambda *a, **k: a[0])
        own._chokepoint = None
        assert own._email_policy_says_redact() is True
        assert own._chokepoint_owns_addresses() is False

    def test_a_deliberate_keep_decision_is_not_second_guessed(self, monkeypatch):
        """``rfc`` and ``kerneldocs`` keep author addresses, with a licence reason.

        If this source is ever moved into that table, the decision belongs to
        whoever wrote it down there. A source that overrides the chokepoint's
        recorded exception is a source nobody can reason about.
        """
        from training.corpus import build

        keep = build._EmailPolicy("ownrepos", True, "a reason written down")
        monkeypatch.setattr(build, "_email_policy", lambda name: keep)
        own._chokepoint = None
        assert own._chokepoint_owns_addresses() is True

    def test_the_probe_recognises_a_chokepoint_that_strips_addresses(self,
                                                                    monkeypatch):
        from dataclasses import replace

        from training.corpus import build

        monkeypatch.setattr(
            build, "_redacted",
            lambda doc, *rest: replace(
                doc, text=own._EMAIL.sub("x@example.invalid", doc.text)))
        own._chokepoint = None
        assert own._chokepoint_owns_addresses() is True

    def test_the_probe_agrees_with_the_real_chokepoint(self):
        """Against the real ``build.py``, the answer is the real answer.

        Not asserted as a constant: the day the chokepoint changes, this test
        must agree with it rather than fail. What is asserted is that the probe
        and the chokepoint cannot disagree.
        """
        from training.corpus import build

        address = own._probe_address(build)
        probe = Document(text=f"a report from {address} here",
                         source="ownrepos", register=Register.PROSE,
                         side=Side.NEUTRAL, ident="_probe")
        policy = build._email_policy("ownrepos")
        truth = policy.keep_third_party or (
            address not in build._redacted(probe, policy, [0, 0]).text)
        own._chokepoint = None
        assert own._chokepoint_owns_addresses() is truth

    def test_the_probe_is_not_exempt_as_a_documentation_address(self):
        """The instrument bug this probe shipped with, pinned.

        The first version used ``probe@example.invalid``. The chokepoint
        reserves ``.invalid`` and correctly left it alone as a documentation
        fixture, so the probe reported "no chokepoint" while a working one ran
        two frames up the stack — the ruler was wrong, not the thing measured.
        The address is now built from the chokepoint's own reserved set.
        """
        from training.corpus import build

        address = own._probe_address(build)
        tld = address.rsplit(".", 1)[-1]
        assert tld not in build._EMAIL_RESERVED_TLDS, address
        assert address.split("@", 1)[0] not in build._EMAIL_ROLE_LOCALS
        assert build._EMAIL.fullmatch(address), "must be address-shaped at all"

    def test_the_probe_address_cannot_resolve(self):
        """Fabricated, not merely unfamiliar.

        Every TLD this can produce is either reserved by RFC 2606/6761 or
        ``.probe``, which is delegated by nobody and in no root zone.
        """
        assert own._PROBE_TLDS[-1] == "probe"
        for tld in own._PROBE_TLDS[:-1]:
            assert tld in {"invalid", "test", "example", "localhost"}

    def test_the_probe_does_not_land_in_the_chokepoints_counters(self):
        """A probe that inflated the build's email report would be a measurement
        bug in the instrument, which is this codebase's recurring defect class.
        """
        import inspect
        src = inspect.getsource(own._chokepoint_owns_addresses)
        assert "[0, 0]" in src, "the counter argument must be a throwaway"

    def test_no_address_literal_is_written_into_this_source(self):
        """The probe address is *derived*, so there is nothing to leak.

        A literal in source is a literal in the repository, in every clone and
        in anything that greps it. This file writes a local part and a TLD list
        and assembles them at runtime; no complete address appears in it except
        the replacement marker, which is on a reserved TLD by construction.
        """
        src = Path(own.__spec__.origin).read_text(encoding="utf-8")
        for addr in set(own._EMAIL.findall(src)):
            tld = addr.rsplit(".", 1)[-1]
            assert tld in {"invalid", "test", "example", "localhost"}, addr

    def test_redacting_twice_is_the_same_as_redacting_once(self):
        """So both layers running costs correctness nothing during the handover.

        The marker is a fixed point of the pattern that produced it, which is
        the property that makes defence in depth free here.
        """
        once, n = own._redact_emails("write to someone@example.invalid today")
        twice, m = own._redact_emails(once)
        assert n == 1 and m == 1
        assert twice == once
        assert own._EMAIL_REPLACEMENT in once

    def test_the_count_is_returned_not_swallowed(self):
        """Silence is the failure mode this source already shipped once."""
        text = "a@x.invalid b@y.invalid c@z.invalid"
        _, n = own._redact_emails(text)
        assert n == 3

    def test_the_roster_check_runs_before_any_redaction(self, cache: Path,
                                                        monkeypatch):
        """Ordering, pinned: an address beside a name is half of its evidence.

        A one-person roster is detected *because* of the address. Redact first
        and the signal is gone, so the exclusion silently weakens to "two or
        more names" — and the document that started all of this would still be
        caught, while a single named classmate with a contact address would not.
        """
        monkeypatch.setattr(own, "_chokepoint", False)
        _write(cache, "Course__README.md",
               "## Contributors\n\n- **Alice Example** (alice@example.invalid)\n\n"
               + PROSE)
        assert list(own._documents(cache)) == []


class TestIdentCarriesNoPath:
    """``doc.ident`` is not covered by ``build.py``'s redaction chokepoint.

    It is written to the corpus JSONL untouched, and several adapters build it
    from a filesystem path. This one must not.
    """

    def test_ident_is_repo_relative(self, tree: Path, cache: Path):
        _write(tree, "repo/docs/design.md", PROSE)
        own._fetch(cache)

        idents = [d.ident for d in own._documents(cache)]
        assert idents, "fixture collected nothing"
        for ident in idents:
            assert not ident.startswith("/")
            assert "/" not in ident
            assert str(tree) not in ident

    def test_ident_carries_no_account_name(self, tree: Path, cache: Path):
        """Derived from the OS at runtime and never written down.

        A configured list of identifiers is a list of the leaks somebody already
        noticed; a persisted one is a new leak.
        """
        _write(tree, "repo/docs/design.md", PROSE)
        own._fetch(cache)
        user = getpass.getuser()
        for doc in own._documents(cache):
            assert user.lower() not in doc.ident.lower()


class TestFetchIsHonestAboutTruncation:
    """"Skipped and named is honest; truncated and counted is not."

    ``_fetch`` returns early on a non-empty cache, so one truncated walk is
    reused forever. The cap is allowed to bite; it is not allowed to be silent.
    """

    def test_the_cap_is_reported(self, tree: Path, cache: Path, monkeypatch,
                                 capsys):
        monkeypatch.setattr(own, "_MAX_FILES", 2)
        for i in range(5):
            _write(tree, f"repo/doc{i}.md", PROSE)

        own._fetch(cache)

        out = capsys.readouterr().out
        assert "TRUNCATED" in out
        assert str(cache) in out, "has to say which cache to clear"
        assert len(list(cache.iterdir())) == 2
