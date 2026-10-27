"""Tests for the programming-knowledge corpus adapters.

Four modules are under test — ``_thirdparty``, ``auditdocs``, ``codeqlhelp``
and ``psconcept`` — and the properties pinned here are the ones that fail
*silently*. A corpus adapter that breaks loudly costs an afternoon. One that
quietly drops 1.7% of its source, or quietly keeps a mail address, or quietly
relabels a register, costs a training run and is discovered four steps
downstream in a tokenizer comparison, if at all.

So three kinds of test live here:

* **The measured regressions.** Every one of these is a bug that actually
  happened while the adapters were written, and each test names it:
  ``mandoc`` invoked with a relative path under a changed ``cwd`` failed on
  every page; the qhelp DOCTYPE removal broke 31 of 1,812 files on undefined
  entities; a strict rule-line predicate dropped six of the thirty-four shipped
  audit profiles because upstream ships templates commented out.
* **The privacy invariants.** Addresses out, names in, and no private value
  anywhere in the module sources or the fixtures.
* **The structural laws.** ``os.walk(followlinks=False)`` and never ``rglob``;
  no ``str.format`` over collected PowerShell; a member ceiling on every tar
  read; a licence and a URL on every SPEC.

Tests that need a populated cache skip rather than fail when it is absent, so
the suite stays green on a machine that has never run a corpus build. The
properties that matter most are the pure ones, and those always run.
"""

from __future__ import annotations

import ast
import hashlib
import re
from pathlib import Path

import pytest

from training.corpus.source import Document, Register, Side, normalise
from training.corpus.sources import auditdocs, codeqlhelp, psconcept
from training.corpus.sources._thirdparty import EMAIL_MARKER, count_emails, strip_emails

#: The four files this family owns. Several structural tests sweep them.
_MODULES = (auditdocs, codeqlhelp, psconcept)
_FAMILY_FILES = ("auditdocs.py", "codeqlhelp.py", "psconcept.py",
                 "_thirdparty.py")

_SOURCES_DIR = Path(__file__).resolve().parents[1] / "training/corpus/sources"
_CACHE_ROOT = Path(__file__).resolve().parents[1] / "data/corpus/raw"


def _cached(name: str) -> Path:
    """The populated cache for *name*, or skip the test."""
    path = _CACHE_ROOT / name
    marker = {"auditdocs": ".auditdocs.json",
              "codeqlhelp": ".codeqlhelp.json",
              "psconcept": ".psconcept.json"}[name]
    if not (path / marker).is_file():
        pytest.skip(f"{name} cache not populated; run "
                    f"`python3 -m training.corpus.build --only {name}` first")
    return path


# ---------------------------------------------------------------------------


class TestStripEmails:
    """The third-party-PII scrubber. The one piece of this family that, if it
    is wrong, is wrong in the direction that already cost this project a
    corpus generation.

    **Fixture domains.** Addresses that must be *removed* use ``.internal``,
    which ICANN reserved in 2024 for private use and will never delegate, so
    the fixture cannot be anybody's public mailbox and is still outside the
    documentation set the policy keeps. Addresses that must be *kept* use the
    RFC 2606/6761 reserved names. Nothing in this file is a real person's
    address and nothing in it is an identifier of the machine it runs on.
    """

    def test_plain_address_goes(self):
        out, n = strip_emails("Contact maintainer@vendor.internal for details.")
        assert n == 1
        assert "@vendor.internal" not in out
        assert EMAIL_MARKER in out

    def test_angle_brackets_collapse(self):
        out, n = strip_emails("Steve Grubb <sgrubb@vendor.internal>")
        assert n == 1
        # The wrapper goes with the address rather than leaving "<[...]>".
        assert "<" not in out and ">" not in out
        # The NAME stays. This is the deliberate half of the policy: a
        # published AUTHOR attribution is not contact details, and GPL-2 s1
        # requires the notices to travel with the text.
        assert "Steve Grubb" in out

    def test_mailto_scheme_goes_with_it(self):
        out, _ = strip_emails("see mailto:person@vendor.internal now")
        assert "mailto:" not in out
        assert out == f"see {EMAIL_MARKER} now"

    @pytest.mark.parametrize("entity", ["&#64;", "&#x40;", "&commat;"])
    def test_entity_encoded_at_is_still_an_address(self, entity):
        out, n = strip_emails(f"author{entity}vendor.internal")
        assert n == 1
        assert "vendor.internal" not in out

    def test_a_lone_entity_is_left_alone(self):
        """Rewriting an entity that was not part of an address is an edit this
        function was not asked to make."""
        text = "The &commat; sign introduces an annotation."
        out, n = strip_emails(text)
        assert (out, n) == (text, 0)

    @pytest.mark.parametrize("address", [
        "user@example.com", "user@example.net", "user@example.org",
        "mail.user@sub.example.com", "admin@host.invalid",
        "a@b.test", "root@localhost.localhost", "x@thing.example",
    ])
    def test_reserved_documentation_domains_are_kept(self, address):
        """The measured over-reach. The first version of this module stripped
        everything that matched, and the four addresses it removed from
        codeqlhelp's tree were the placeholder addresses *inside* the CWE-640
        e-mail-header-injection samples, where the address is the example.
        build.py says it best: rewriting one 'corrupts the example while
        protecting nobody'. This policy is deliberately identical to its own.
        """
        text = f"Send to {address} and see."
        out, n = strip_emails(text)
        assert (out, n) == (text, 0), f"stripped a documentation address: {address}"
        assert count_emails(text) == 0

    def test_the_reserved_sets_match_the_build_chokepoint(self):
        """Two copies of a policy is one copy too many unless something pins
        them together. This is that something: the sets are restated in
        ``_thirdparty`` because ``build.py`` imports the sources package and a
        source importing ``build`` closes the circle, so the agreement is
        checked instead of assumed."""
        from training.corpus import build as build_mod
        from training.corpus.sources import _thirdparty
        assert _thirdparty.RESERVED_TLDS == build_mod._EMAIL_RESERVED_TLDS
        assert _thirdparty.RESERVED_DOMAINS == build_mod._EMAIL_RESERVED_DOMAINS

    @pytest.mark.parametrize("text", [
        # CodeQL query metadata is made of @ tokens. A careless pattern eats
        # the entire header of all 2,336 queries.
        "@name Query built from user-controlled sources",
        "@id java/sql-injection",
        "@tags security\n       external/cwe/cwe-089",
        "@problem.severity error",
        # Package and version pins.
        "npm install lodash@^4.17.0",
        "require foo@1.2.3",
        "pip install requests@2.31.0",
        # Java and C# annotations.
        "@Override public void run() {}",
        "@param name the thing",
        # A shell example with no TLD.
        "ssh root@hostname",
        "scp file user@10.0.0.1:/tmp",
        # Go module paths, which are full of dots and slashes.
        "import gopkg.in/yaml.v2",
        "golang.org/x/crypto/ssh",
    ])
    def test_does_not_eat_what_is_not_an_address(self, text):
        out, n = strip_emails(text)
        assert (out, n) == (text, 0), f"over-matched in {text!r}"

    def test_marker_is_not_itself_address_shaped(self):
        """A leak scan over the corpus must not be satisfiable by our own
        marker."""
        assert count_emails(EMAIL_MARKER) == 0

    def test_idempotent(self):
        once, first = strip_emails("a@vendor.internal and b@other.internal")
        twice, second = strip_emails(once)
        assert first == 2
        assert second == 0
        assert twice == once

    def test_count_agrees_with_strip(self):
        text = ("one@vendor.internal two@other.internal "
                "<three@third.internal> mailto:four@vendor.internal "
                "kept@example.com not-an-address@ @notone")
        assert count_emails(text) == 4
        cleaned, n = strip_emails(text)
        assert n == 4
        assert count_emails(cleaned) == 0
        # The documentation address survived all of that.
        assert "kept@example.com" in cleaned

    def test_surrounding_prose_survives(self):
        out, _ = strip_emails("Report bugs to bugs@vendor.internal, with a patch.")
        assert out.startswith("Report bugs to ")
        assert out.endswith(", with a patch.")


# ---------------------------------------------------------------------------


class TestAuditdocs:
    """The Linux audit userspace adapter."""

    @pytest.mark.parametrize("relative", [
        "docs/auditctl.8", "docs/audit.rules.7", "docs/ausearch-expression.5",
        "docs/auparse_get_field_name.3", "rules/30-stig.rules",
        "init.d/auditd.service.in", "COPYING", "COPYING.LIB",
    ])
    def test_wanted_keeps_the_formats(self, relative):
        assert auditdocs._wanted(relative)

    @pytest.mark.parametrize("relative", [
        # The C implementation: clang's register, and it would teach one
        # project's habits.
        "src/auditctl.c", "lib/libaudit.c", "auparse/auparse.c",
        # Contributor lists: names and addresses, which is the exact shape of
        # third-party personal data this corpus has already shipped once.
        "AUTHORS", "THANKS", "ChangeLog",
        # Build machinery.
        "docs/Makefile.am", "configure.ac", "audit.spec",
        # A shell wrapper that says nothing the man pages do not.
        "init.d/auditd.restart",
    ])
    def test_wanted_drops_the_rest(self, relative):
        assert not auditdocs._wanted(relative)

    def test_overstrike_is_applied_not_deleted(self):
        """mandoc writes bold as c\\x08c. A backspace deletes what precedes it;
        applying that one rule resolves bold and italic with no special case."""
        assert auditdocs._strip_overstrike("N\x08NA\x08AM\x08ME\x08E") == "NAME"
        assert auditdocs._strip_overstrike("_\x08i") == "i"
        assert auditdocs._strip_overstrike("plain") == "plain"

    @pytest.mark.parametrize("line", [
        "-a always,exit -F arch=b64 -S execve -k exec",
        "-w /etc/passwd -p wa -k identity",
        "-D",
        "-e 2",
        # Commented templates. Upstream ships these on purpose and they ARE
        # the rule syntax; requiring an uncommented rule dropped six of the
        # thirty-four shipped profiles, including 31-privileged.rules.
        "#-e 2",
        "# -a exit,always -F arch=b64 -F path=file -F perm=rwxa",
        "#-a never,user -F subj_type=crond_t",
        # Long directives the short-option form misses entirely.
        "--loginuid-immutable",
        "--backlog_wait_time 0",
    ])
    def test_rule_line_matches_real_rule_syntax(self, line):
        assert auditdocs._RULE_LINE.search(line), line

    @pytest.mark.parametrize("line", [
        "## Put your own watches after this point",
        "## This is for don't audit rules. We put these early because audit",
        "",
        "   ",
    ])
    def test_rule_line_does_not_match_prose(self, line):
        assert not auditdocs._RULE_LINE.search(line), line

    def test_man_header_names_the_page_as_a_person_types_it(self):
        assert auditdocs._man_header("ausearch-expression.5").startswith(
            "ausearch-expression(5)")
        assert auditdocs._man_header("auparse_init.3").startswith(
            "auparse_init(3)")

    def test_render_page_names_the_file_not_the_path(self):
        """The measured regression: ``cwd=`` changes what a relative path means,
        so passing mandoc the caller's path while also sending it into the
        page's directory produced BADARG on every single page. A renderer that
        fails on *every* page is the easy case; this pins the fix so a later
        tidy-up cannot undo it."""
        body = (_SOURCES_DIR / "auditdocs.py").read_text(encoding="utf-8")
        tree = ast.parse(body)
        func = next(n for n in ast.walk(tree)
                    if isinstance(n, ast.FunctionDef) and n.name == "_render_page")
        argv = next(n for n in ast.walk(func) if isinstance(n, ast.List))
        rendered = [ast.unparse(e) for e in argv.elts]
        assert rendered[0] == "'mandoc'"
        assert rendered[-1] == "source.name", rendered

    def test_documents_split_system_and_detection(self):
        path = _cached("auditdocs")
        docs = list(auditdocs._documents(path))
        assert len(docs) >= auditdocs.SPEC.expect_min_docs
        registers = {d.register for d in docs}
        assert registers == {Register.SYSTEM, Register.DETECTION}
        # A rules file is DETECTION/BLUE wherever upstream shipped it, and the
        # init.d one is the case that proves the register is not a fact about
        # the directory.
        rules = [d for d in docs if d.ident.endswith(".rules")]
        assert rules
        assert all(d.register is Register.DETECTION and d.side is Side.BLUE
                   for d in rules)

    def test_no_addresses_in_emitted_documents(self):
        path = _cached("auditdocs")
        leaked = [d.ident for d in auditdocs._documents(path)
                  if count_emails(d.text)]
        assert leaked == []


# ---------------------------------------------------------------------------


class TestCodeqlLicenceGate:
    """``github/codeql`` is MIT at the root and carries ~160 other licence
    files. The claim that none of them covers collected text is structural, and
    a structural claim nothing checks stops being true on the next upstream
    reorganisation.
    """

    @pytest.mark.parametrize("relative", [
        "java/ql/src/Security/CWE/CWE-089/SqlTainted.ql",
        "java/ql/src/Security/CWE/CWE-089/SqlTainted.qhelp",
        "java/ql/src/Security/CWE/CWE-089/SqlTainted.java",
        "actions/ql/src/Security/CWE-077/EnvVarInjectionCritical.md",
        "docs/codeql/ql-language-reference/types.rst",
        "LICENSE",
    ])
    def test_kept(self, relative):
        assert codeqlhelp._kept(relative)

    @pytest.mark.parametrize("relative", [
        # Every one of these is a real path from the upstream tree that sits
        # beside a third-party licence file.
        "go/ql/test/library-tests/semmle/go/frameworks/Gin/vendor/github.com/gin-gonic/gin/LICENSE",
        "go/ql/test/library-tests/semmle/go/frameworks/Gin/vendor/github.com/gin-gonic/gin/gin.go",
        "java/ql/test/stubs/javamail-api-1.6.2/LICENSE.txt",
        "java/ql/test/stubs/junit-4.13/org/junit/Test.java",
        "java/kotlin-extractor/deps/license",
        "python/extractor/LICENSE-PSF.md",
        "javascript/extractor/LICENSE-babylon.md",
        "misc/ripunzip/LICENSE.txt",
        "cpp/ql/test/experimental/stubs/openssl/license.txt",
        # Measured exclusion: 786 of 789 orphan Markdown files under ql/src are
        # release-note fragments, most of them "No user-facing changes."
        "go/ql/src/change-notes/released/1.0.5.md",
        # Not a language pack.
        "ruby/ql/src/queries/Foo.ql",
        # Generated test output, 71 MB of it.
        "java/ql/test/query-tests/Security/CWE-089/SqlTainted.expected",
        # Product orientation and 9 MB of screenshots.
        "docs/codeql/codeql-overview/supported-languages-and-frameworks.rst",
        "docs/codeql/images/vscode.png",
    ])
    def test_refused(self, relative):
        assert not codeqlhelp._kept(relative)

    def test_no_licence_file_survives_the_gate(self):
        """Belt and braces: whatever the path, a licence-named file must not be
        collectable except as the single root LICENSE."""
        for relative in (
            "java/ql/src/Security/LICENSE",
            "docs/codeql/ql-language-reference/COPYING",
            "cpp/ql/src/NOTICE",
        ):
            assert not codeqlhelp._kept(relative) or relative == "LICENSE"


class TestCodeqlParsing:
    """The renderer, and the instrument bug it was written to fix."""

    @pytest.fixture(autouse=True)
    def _tmp(self, tmp_path):
        self._tmp_path = tmp_path

    def _write(self, body: str, name: str = "q.qhelp") -> Path:
        path = self._tmp_path / name
        path.write_text(body, encoding="utf-8")
        return path

    @pytest.mark.parametrize("entity,char", [
        ("&sect;", "§"), ("&nbsp;", " "), ("&ndash;", "–"),
        ("&mdash;", "—"), ("&rarr;", "→"), ("&hArr;", "⇔"),
        ("&ntilde;", "ñ"),
    ])
    def test_dtd_entities_resolve(self, entity, char):
        """The measured bug: with the DOCTYPE removed and nothing in its place,
        31 of 1,812 qhelp files failed to parse on ``undefined entity`` and the
        renderer returned empty string for each — a silent 1.7% loss clustered
        in Metrics/, Complexity/ and Naming Conventions/, which is not how a
        random fault distributes."""
        raw = ('<!DOCTYPE qhelp PUBLIC "-//Semmle//qhelp//EN" "qhelp.dtd">'
               f"<qhelp><overview><p>See{entity}4 for detail.</p></overview></qhelp>")
        root = codeqlhelp._parse_qhelp(raw)
        assert root is not None
        assert char in codeqlhelp._inline(root)

    def test_unparsable_returns_none_rather_than_raising(self):
        assert codeqlhelp._parse_qhelp("<qhelp><unclosed></qhelp>") is None

    def test_query_metadata_handles_multiline_tags_and_description(self):
        source = (
            "/**\n"
            " * @name Query built from user-controlled sources\n"
            " * @description Building a SQL query from user-controlled sources\n"
            " *              is vulnerable to insertion of malicious code.\n"
            " * @kind path-problem\n"
            " * @problem.severity error\n"
            " * @security-severity 8.8\n"
            " * @precision high\n"
            " * @id java/sql-injection\n"
            " * @tags security\n"
            " *       external/cwe/cwe-089\n"
            " *       external/cwe/cwe-564\n"
            " */\n"
            "import java\n"
        )
        meta = codeqlhelp._query_metadata(source)
        assert meta["id"] == "java/sql-injection"
        assert meta["kind"] == "path-problem"
        assert meta["security-severity"] == "8.8"
        assert meta["tags"].split() == [
            "security", "external/cwe/cwe-089", "external/cwe/cwe-564"]
        assert meta["description"].endswith("malicious code.")

    def test_metadata_block_ends_at_the_first_close(self):
        source = "/**\n * @id a/b\n */\nselect 1 /* not metadata @id c/d */\n"
        assert codeqlhelp._query_metadata(source)["id"] == "a/b"

    def test_cwe_tags_are_rewritten_as_the_world_writes_them(self):
        assert codeqlhelp._cwe_line(
            "security external/cwe/cwe-089 external/cwe/cwe-564"
        ) == "CWE-89, CWE-564"
        assert codeqlhelp._cwe_line("security") == ""
        # Duplicates collapse, order preserved.
        assert codeqlhelp._cwe_line(
            "external/cwe/cwe-079 external/cwe/cwe-79") == "CWE-79"

    def test_include_cycle_terminates(self, tmp_path):
        a = tmp_path / "a.qhelp"
        b = tmp_path / "b.qhelp"
        a.write_text('<qhelp><overview><p>A</p>'
                     '<include src="b.qhelp"/></overview></qhelp>',
                     encoding="utf-8")
        b.write_text('<qhelp><overview><p>B</p>'
                     '<include src="a.qhelp"/></overview></qhelp>',
                     encoding="utf-8")
        text = codeqlhelp._render_help_xml(
            a, frozenset({a.resolve()}), codeqlhelp._INCLUDE_DEPTH, [])
        assert "A" in text and "B" in text
        assert text.count("B") < 5     # bounded, not recursive forever

    def test_sample_is_fenced_with_its_language(self, tmp_path):
        (tmp_path / "Bad.java").write_text(
            "class Bad { void f() { exec(input); } }\n", encoding="utf-8")
        block = codeqlhelp._sample_block(tmp_path, "Bad.java")
        assert block.startswith("Example — Bad.java:")
        assert "```java" in block
        assert "exec(input)" in block

    def test_a_missing_sample_is_not_an_empty_fence(self, tmp_path):
        assert codeqlhelp._sample_block(tmp_path, "Nope.java") == ""

    def test_a_pre_block_keeps_its_indentation(self):
        """Only 14 of 1,812 qhelp files carry an inline <pre>, which is exactly
        the kind of path a spot check misses. _collapse strips and rejoins
        lines, so a code block routed through it arrives in the corpus with its
        indentation gone — the netstat-alignment mistake, again."""
        root_text = (
            "<qhelp><overview><p>Intro.</p>"
            "<pre>\nif (x) {\n    doSomething();\n}\n</pre>"
            "</overview></qhelp>")
        path = self._write(root_text)
        text = codeqlhelp._render_help_xml(
            path, frozenset({path.resolve()}), codeqlhelp._INCLUDE_DEPTH, [])
        assert "    doSomething();" in text, text
        assert "Intro." in text
        # And it is fenced, so a reader can tell where the prose stopped.
        assert "```" in text

    def test_pre_content_is_not_duplicated(self):
        path = self._write(
            "<qhelp><overview><p>Intro.</p><pre>\nmarker_line\n</pre>"
            "</overview></qhelp>")
        text = codeqlhelp._render_help_xml(
            path, frozenset({path.resolve()}), codeqlhelp._INCLUDE_DEPTH, [])
        assert text.count("marker_line") == 1, text

    def test_prose_is_rejoined_but_code_is_not(self):
        path = self._write(
            "<qhelp><overview><p>One sentence\nwrapped by the author\n"
            "across three lines.</p></overview></qhelp>")
        text = codeqlhelp._render_help_xml(
            path, frozenset({path.resolve()}), codeqlhelp._INCLUDE_DEPTH, [])
        assert "One sentence wrapped by the author across three lines." in text

    def test_code_and_links_keep_their_markers(self):
        root = codeqlhelp._parse_qhelp(
            '<qhelp><overview><p>Call <code>exec()</code> safely. '
            'See <a href="https://example.com/x">the guide</a>.</p>'
            '</overview></qhelp>')
        text = codeqlhelp._inline(root)
        assert "`exec()`" in text
        assert "the guide (https://example.com/x)" in text


class TestCodeqlDocuments:
    """Register assignment, over the real cache."""

    def test_two_documents_per_documented_query(self):
        path = _cached("codeqlhelp")
        docs = list(codeqlhelp._documents(path))
        assert len(docs) >= codeqlhelp.SPEC.expect_min_docs
        by_register = {}
        for doc in docs:
            by_register.setdefault(doc.register, []).append(doc)
        assert set(by_register) == {Register.ADVERSARY, Register.DETECTION,
                                    Register.PROSE}
        # The help half is NEUTRAL because every one of these carries the fix;
        # the query half is BLUE because a detection is.
        assert all(d.side is Side.NEUTRAL for d in by_register[Register.ADVERSARY])
        assert all(d.side is Side.BLUE for d in by_register[Register.DETECTION])
        # Both halves of one query carry the same @id, which is how they
        # co-occur without being glued into one mislabelled document.
        helps = {d.ident[len("help/"):] for d in by_register[Register.ADVERSARY]}
        queries = {d.ident[len("query/"):] for d in by_register[Register.DETECTION]}
        assert helps <= queries

    def test_no_addresses_in_emitted_documents(self):
        path = _cached("codeqlhelp")
        leaked = [d.ident for d in codeqlhelp._documents(path)
                  if count_emails(d.text)]
        assert leaked == []


# ---------------------------------------------------------------------------


class TestPsconceptDisjointFromPsdocs:
    """Two sources, one repository. The disjointness has to be a property of
    the code, not a sentence in a docstring, because the failure mode is the
    same page in the corpus twice under two source names.
    """

    @pytest.mark.parametrize("relative", [
        "reference/5.1/Microsoft.PowerShell.Management/Get-Process.md",
        "reference/7.7/Microsoft.PowerShell.Core/About/about_Operators.md",
        "reference/7.4/Microsoft.PowerShell.Utility/Select-Object.md",
    ])
    def test_version_trees_belong_to_psdocs(self, relative):
        assert not psconcept._wanted(relative)

    @pytest.mark.parametrize("relative", [
        "reference/docs-conceptual/lang-spec/chapter-07.md",
        "reference/docs-conceptual/developer/cmdlet/cmdlet-output.md",
        "reference/docs-conceptual/developer/format/format-ps1xml-files.md",
        "reference/docs-conceptual/learn/deep-dives/everything-about-shouldprocess.md",
        "reference/docs-conceptual/samples/Sorting-Objects.md",
        "LICENSE.md",
        "LICENSE-CODE.md",
    ])
    def test_conceptual_trees_belong_here(self, relative):
        assert psconcept._wanted(relative)

    @pytest.mark.parametrize("relative", [
        # community/ is a roll of contributors by name and handle.
        "reference/docs-conceptual/community/community-support.md",
        "reference/docs-conceptual/whats-new/what-s-new-in-powershell-75.md",
        "reference/docs-conceptual/install/installing-powershell-on-windows.md",
        "reference/docs-conceptual/gallery/overview.md",
        "reference/docs-conceptual/dsc/overview.md",
        # Site navigation, not content.
        "reference/docs-conceptual/overview.md",
        "reference/docs-conceptual/how-to-use-docs.md",
        # Not Markdown.
        "reference/docs-conceptual/learn/media/shell.png",
    ])
    def test_excluded_trees_are_excluded(self, relative):
        assert not psconcept._wanted(relative)

    def test_the_two_sources_share_no_document(self):
        """Empirical, over whatever both adapters currently produce."""
        path = _cached("psconcept")
        psdocs_jsonl = (Path(__file__).resolve().parents[1]
                        / "data/corpus/clean-v7/psdocs.jsonl")
        if not psdocs_jsonl.is_file():
            pytest.skip("no psdocs generation on disk to compare against")
        import json

        from training.corpus.source import fingerprint
        mine = {d.fingerprint for d in psconcept._documents(path)}
        with psdocs_jsonl.open(encoding="utf-8") as handle:
            theirs = {fingerprint(json.loads(line)["text"]) for line in handle}
        assert not (mine & theirs)


class TestPsconceptRegisters:
    """``fence_share`` decides a register, so it is tested as a pure function."""

    def test_output_fences_count_toward_shell(self):
        text = ("Intro paragraph.\n\n```Output\n"
                + "Name    Id  CPU\n" * 20 + "```\n")
        assert psconcept.fence_share(text) > psconcept._SHELL_FENCE_SHARE

    def test_untagged_fences_do_not_count(self):
        """In this tree an untagged fence is usually a directory listing, and
        crediting it to SHELL would be the misreport psdocs warned about."""
        text = "Intro.\n\n```\n" + "some/path/here\n" * 40 + "```\n"
        assert psconcept.fence_share(text) == 0.0

    def test_csharp_fences_do_not_count(self):
        text = "Intro.\n\n```csharp\n" + "int x = 1;\n" * 40 + "```\n"
        assert psconcept.fence_share(text) == 0.0

    def test_prose_only_page_is_zero(self):
        assert psconcept.fence_share("Just words, no fences at all.") == 0.0

    def test_empty_is_zero_not_an_error(self):
        assert psconcept.fence_share("") == 0.0

    def test_closing_fence_must_start_a_line(self):
        """A ``` inside a line of prose must not open a block."""
        text = "Use the ``` marker to open a block.\n" * 5
        assert psconcept.fence_share(text) == 0.0

    def test_spec_trees_are_system_whatever_their_fences(self):
        heavy = "```powershell\nGet-Process\n```\n" * 10
        assert psconcept._register_for("developer", heavy) is Register.SYSTEM
        assert psconcept._register_for("lang-spec", heavy) is Register.SYSTEM

    def test_measured_trees_split_on_the_threshold(self):
        heavy = "x\n\n```powershell\n" + "Get-Process\n" * 60 + "```\n"
        light = "Explanation. " * 200 + "\n\n```powershell\nGet-Process\n```\n"
        assert psconcept._register_for("samples", heavy) is Register.SHELL
        assert psconcept._register_for("learn", light) is Register.PROSE

    def test_frontmatter_keeps_content_and_drops_publishing_keys(self):
        page = ("---\n"
                "description: Cmdlet Output\n"
                "ms.date: 09/13/2016\n"
                "ms.topic: reference\n"
                "title: Cmdlet Output\n"
                "---\n"
                "# Cmdlet Output\n\nBody.\n")
        out = psconcept._strip_metadata(page)
        assert "title: Cmdlet Output" in out
        assert "description: Cmdlet Output" in out
        assert "ms.date" not in out
        assert "ms.topic" not in out
        assert out.rstrip().endswith("Body.")

    def test_a_page_without_frontmatter_is_untouched(self):
        page = "# Heading\n\nBody with --- a rule later.\n"
        assert psconcept._strip_metadata(page) == page

    def test_documents_carry_the_three_registers(self):
        path = _cached("psconcept")
        docs = list(psconcept._documents(path))
        assert len(docs) >= psconcept.SPEC.expect_min_docs
        assert {d.register for d in docs} == {
            Register.SYSTEM, Register.SHELL, Register.PROSE}

    def test_no_addresses_in_emitted_documents(self):
        path = _cached("psconcept")
        leaked = [d.ident for d in psconcept._documents(path)
                  if count_emails(d.text)]
        assert leaked == []


# ---------------------------------------------------------------------------


class TestFamilyStructure:
    """Laws that hold across all four files, checked by reading them."""

    def _trees(self):
        for name in _FAMILY_FILES:
            path = _SOURCES_DIR / name
            yield name, path, ast.parse(path.read_text(encoding="utf-8"),
                                        filename=str(path))

    def test_every_spec_declares_a_licence_with_its_source(self):
        for module in _MODULES:
            spec = module.SPEC
            assert spec.license.strip(), spec.name
            assert spec.url.strip(), spec.name
            # A licence claim that cannot be checked against the upstream is a
            # claim nobody can audit, so each one carries where it was read.
            assert "http" in spec.license, (
                f"{spec.name} states a licence without saying where it was read")
            assert spec.expect_min_docs >= 1

    def test_source_names_match_module_names(self):
        for module in _MODULES:
            assert module.SPEC.name == module.__name__.rsplit(".", 1)[-1]

    def test_the_helper_declares_no_spec(self):
        """``_thirdparty`` must stay a helper. ``discover_sources`` skips a
        leading underscore, so a SPEC there would be a source that silently
        never builds."""
        from training.corpus.sources import _thirdparty
        assert not hasattr(_thirdparty, "SPEC")

    def test_no_rglob_anywhere_in_this_family(self):
        """``ownrepos`` once followed the repository's ``data`` symlink into the
        SSD and pulled the corpus cache back in as PROSE — the corpus ate
        itself, and only the balance report caught it. ``os.walk`` with
        ``followlinks=False`` is the law; ``rglob`` follows directory symlinks.
        """
        for name, _, tree in self._trees():
            for node in ast.walk(tree):
                if (isinstance(node, ast.Attribute)
                        and node.attr in {"rglob", "glob"}):
                    pytest.fail(f"{name} uses {node.attr}; use "
                                "os.walk(followlinks=False)")

    def test_every_walk_disables_link_following(self):
        checked = 0
        for name, _, tree in self._trees():
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "walk"):
                    continue
                checked += 1
                kwargs = {k.arg: ast.unparse(k.value) for k in node.keywords}
                assert kwargs.get("followlinks") == "False", (
                    f"{name}:{node.lineno} walks with link following on")
        # Without this the test passes vacuously the moment somebody replaces
        # os.walk with something else, which is precisely the regression.
        assert checked >= 6, f"only {checked} os.walk call sites found"

    def test_no_unverified_tls(self):
        for name, _, tree in self._trees():
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and node.attr in {
                        "CERT_NONE", "_create_unverified_context"}:
                    pytest.fail(f"{name}:{node.lineno} reaches for {node.attr}")

    def test_tar_readers_carry_a_member_ceiling(self):
        """The tarball's own size is no evidence about any one member's. Five
        adapters in this package learned that together."""
        for name in ("auditdocs.py", "codeqlhelp.py", "psconcept.py"):
            body = (_SOURCES_DIR / name).read_text(encoding="utf-8")
            assert "_MAX_MEMBER_BYTES" in body, f"{name} lost its member ceiling"
            assert "_MAX_ARCHIVE_BYTES" in body, f"{name} lost its archive ceiling"

    def test_no_whole_member_read_into_one_allocation(self):
        for name, _, tree in self._trees():
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "write_bytes"
                        and len(node.args) == 1):
                    continue
                arg = node.args[0]
                assert not (isinstance(arg, ast.Call)
                            and isinstance(arg.func, ast.Attribute)
                            and arg.func.attr == "read" and not arg.args), (
                    f"{name}:{node.lineno} reads a whole archive member into "
                    "one allocation")

    def test_never_str_format_on_collected_text(self):
        """A PowerShell script block is written with ``{ }`` and ``str.format``
        reads those as format fields. The sibling project learned this by
        having a payload silently rewritten. f-strings over data this package
        built are fine; ``.format`` over upstream text is not, so the method is
        simply absent."""
        for name, _, tree in self._trees():
            for node in ast.walk(tree):
                if (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "format"):
                    pytest.fail(f"{name}:{node.lineno} calls .format(); use an "
                                "f-string — PowerShell's { } are not fields")

    def test_no_private_value_in_the_module_sources(self):
        """Nothing in this family may carry a host identifier or a personal
        value — not in a constant, not in a fixture, not in a comment. The
        addresses in the test fixtures are synthetic and use reserved or
        documentation domains, which this allows for explicitly."""
        # The RFC 2606/6761 reserved names, plus the ``.internal`` fixtures
        # (ICANN-reserved for private use, never delegated) that the stripper
        # tests need in order to have something it is correct to remove.
        allowed_domains = ("example.com", "example.org", "example.net",
                           "example.invalid", "example.test", "sub.example.com",
                           "host.invalid", "b.test", "localhost.localhost",
                           "thing.example", "vendor.internal", "other.internal",
                           "third.internal")
        ipv4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        mac = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
        # Globally routable IPv6 is 2000::/3 — the shape the audit found.
        ipv6 = re.compile(r"\b2[0-9a-fA-F]{3}:[0-9a-fA-F:]{4,}\b")
        # RFC 5737 documentation space, RFC 1918 examples, and the dotted
        # version strings the fixtures quote. Listed rather than pattern-matched
        # so that adding one is a decision somebody makes.
        documentation_ips = ("0.0.0.0", "127.0.0.1", "10.0.0.1", "255.255.255.0",
                             "192.0.2.0", "192.0.2.1", "198.51.100.1",
                             "203.0.113.1", "1.2.3", "2.31.0", "4.17.0",
                             "1.6.2", "4.13")
        for name in _FAMILY_FILES + ("../../../tests/test_sources_programming.py",):
            path = (_SOURCES_DIR / name).resolve()
            text = path.read_text(encoding="utf-8")
            for found in re.finditer(
                    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text):
                assert found.group(0).rsplit("@", 1)[1] in allowed_domains, (
                    f"{name} carries a non-synthetic address")
            for found in ipv4.finditer(text):
                assert found.group(0) in documentation_ips, (
                    f"{name} carries {found.group(0)!r}")
            assert not mac.search(text), f"{name} carries a MAC address"
            assert not ipv6.search(text), f"{name} carries a global IPv6 address"

    def test_fixtures_are_not_this_machine(self):
        """A second, cheaper form of the same guarantee: the operator's own
        identifiers must not appear even by accident.

        The failure message reports ``kind + length + sha256[:8]`` rather than
        the value, because a test that prints the secret it found in order to
        complain about it has leaked the secret into CI output.
        """
        import getpass
        import socket

        candidates = [s for s in (getpass.getuser(), socket.gethostname(),
                                  socket.gethostname().split(".")[0])
                      if len(s) > 3]
        assert candidates, "nothing to check against on this host"
        for name in _FAMILY_FILES + ("../../../tests/test_sources_programming.py",):
            text = (_SOURCES_DIR / name).read_text(encoding="utf-8")
            for secret in candidates:
                assert secret not in text, (
                    f"{name} carries a host identifier: kind=local-name "
                    f"len={len(secret)} "
                    f"sha256[:8]={hashlib.sha256(secret.encode()).hexdigest()[:8]}")


class TestNormaliseContract:
    """Horizontal whitespace is signal, and these adapters collect text whose
    alignment carries meaning: audit rule ``-F`` field lists, mandoc's
    two-column option tables, fenced ``Output`` blocks.
    """

    def test_audit_rule_columns_survive(self):
        rule = ("-a always,exit -F arch=b64 -S execve     -F key=exec\n"
                "-a always,exit -F arch=b32 -S execve     -F key=exec")
        assert normalise(rule) == rule

    def test_fenced_output_alignment_survives(self):
        block = ("```Output\n"
                 "Handles  NPM(K)    PM(K)      WS(K)   CPU(s)     Id  ProcessName\n"
                 "-------  ------    -----      -----   ------     --  -----------\n"
                 "    412      25    12345      23456     1.23   4567  pwsh\n"
                 "```")
        assert normalise(block) == block

    def test_a_document_round_trips_through_the_dataclass(self):
        doc = Document(text=normalise("   indented\n        more"),
                       source="codeqlhelp", register=Register.ADVERSARY,
                       side=Side.NEUTRAL, ident="help/x")
        assert "        more" in doc.text
        assert doc.n_chars == len(doc.text)
