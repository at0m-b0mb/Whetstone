"""Tests for the detection-as-code adapters: wazuh, zeek, falco, panther.

Every test here is a bug that happened, or a property whose failure would be
silent. The corpus is the part of this project that fails quietly — a bad
adapter does not raise, it trains a slightly worse model and nobody finds out
for four steps — so the things pinned down are the ones that would otherwise be
discovered as a mysterious number much later.

Three of these were found while writing the adapters, by running them:

* :class:`TestAttributionRegexIsLinear` — the first attribution sweep did not
  return on ``"#" + "-" * 60``, which is how half the files in these upstreams
  open. Measured: no result in 200 seconds.
* :class:`TestAttributionDoesNotEatContent` — the first keyword list matched
  ``dcredit = -1`` and would have deleted 332 lines of CIS password-policy
  remediation, because ``credit`` is a substring of ``dcredit``.
* :class:`TestProtocolNamesAreNotAddresses` — ~600 of the 717 email-shaped
  tokens in Wazuh's ruleset are SSH algorithm names, and in sshd rules they are
  the detection signal.
"""

from __future__ import annotations

import os
import signal
import sys
import tarfile
import textwrap
from pathlib import Path

import pytest

from training.corpus.source import Document, Register, Side, SourceError, normalise
from training.corpus.sources import _detectionlib as lib

_FAMILY = ("wazuh", "zeek", "falco", "panther")


def _modules():
    import importlib
    return {name: importlib.import_module(f"training.corpus.sources.{name}")
            for name in _FAMILY}


# --------------------------------------------------------------------------- #
# Redaction: the two measured false-positive traps, and the real leaks
# --------------------------------------------------------------------------- #

class TestAttributionRegexIsLinear:
    """A pattern that can only be slow is a build that hangs, not a build that fails.

    The original prefix was ``(?:(?:[#;*]|//|--|<!--|-)[ \\t]*)*`` — two
    alternatives where one is a prefix of the other, under a star. Over a long
    run of dashes the partitions are Fibonacci-many, so a banner comment line
    never returned. This project has already lost seven and a half hours of an
    overnight training run to one adapter's catastrophic backtracking, and the
    build grew a process watchdog because of it. The watchdog is the safety net;
    not needing it is the fix.

    Enforced with a real alarm rather than by timing, because a timing
    assertion on a loaded machine is flaky and the thing being asserted is
    "terminates", not "is fast".
    """

    PATHOLOGICAL = [
        "#" + "-" * 60,
        "#" + "-" * 400,
        "-" * 200,
        "- " * 100,
        "<!--" + "-" * 300 + "-->",
        ";" + "-" * 250 + " no colon anywhere on this line",
        "*" * 120,
        "//" + "-" * 300,
    ]

    @pytest.mark.skipif(not hasattr(signal, "SIGALRM"),
                        reason="needs SIGALRM to bound the search")
    @pytest.mark.parametrize("line", PATHOLOGICAL)
    def test_pathological_comment_banners_terminate(self, line):
        def _bang(_signum, _frame):
            raise AssertionError(
                "the attribution pattern did not return within 5 seconds on a "
                f"{len(line)}-character comment banner — it is backtracking "
                "catastrophically, and the build's watchdog would kill this "
                "source rather than the pattern being fixed"
            )

        previous = signal.signal(signal.SIGALRM, _bang)
        signal.setitimer(signal.ITIMER_REAL, 5.0)
        try:
            assert lib._ATTRIBUTION.search(line) is None
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0.0)
            signal.signal(signal.SIGALRM, previous)

    @pytest.mark.skipif(not hasattr(signal, "SIGALRM"),
                        reason="needs SIGALRM to bound the search")
    def test_scrub_terminates_on_a_whole_pathological_file(self):
        text = "\n".join(self.PATHOLOGICAL * 20)

        def _bang(_signum, _frame):
            raise AssertionError("scrub() did not return on banner comments")

        previous = signal.signal(signal.SIGALRM, _bang)
        signal.setitimer(signal.ITIMER_REAL, 10.0)
        try:
            assert lib.scrub(text) == text
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0.0)
            signal.signal(signal.SIGALRM, previous)

    @pytest.mark.skipif(not hasattr(signal, "SIGALRM"),
                        reason="needs SIGALRM to bound the search")
    def test_address_pattern_terminates_on_long_dotted_tokens(self):
        """``user@a.b.c.d…`` with no valid TLD is the email-regex equivalent.

        The obvious grammar nests a quantifier over dot-separated labels, and
        then every label can be split many ways while the whole match still
        fails. The flat class plus a Python check cannot do that.
        """
        hostile = ["user@" + ".".join(["abcdefgh"] * 40),
                   "user@" + "a" * 300,
                   "u" * 64 + "@" + ".".join(["xy"] * 120) + "!"]

        def _bang(_signum, _frame):
            raise AssertionError("the address pattern did not return")

        previous = signal.signal(signal.SIGALRM, _bang)
        signal.setitimer(signal.ITIMER_REAL, 5.0)
        try:
            for token in hostile:
                lib.scrub(token)
                lib.assert_scrubbed("probe", "probe", lib.scrub(token))
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0.0)
            signal.signal(signal.SIGALRM, previous)


class TestAttributionDoesNotEatContent:
    """The redaction must not be the thing that deletes the corpus.

    ``dcredit = -1`` is a PAM password-quality option and appears 332 times in
    Wazuh's CIS remediation text. Zeek's SSL and file scripts carry signature
    patterns such as ``/Copyright 1985-.*Microsoft Corp/``. A sweep that matched
    either would have removed real detection content and reported it as a
    privacy win.
    """

    KEEP = [
        'remediation: "minlen = 14 dcredit = -1 ucredit = -1 ocredit = -1"',
        "password requisite pam_pwquality.so try_first_pass retry=3 lcredit=-1",
        "payload /Copyright 1985-.*Microsoft Corp/",
        "payload /copyright(\\",
        "    ## The author of a notice is not what this line says",
        "# Authorization header must be present",
        "authors are listed in the upstream repository",
        "  <field name=\"win.eventdata.author\">x</field>",
    ]

    @pytest.mark.parametrize("line", KEEP)
    def test_content_lines_survive(self, line):
        assert lib._ATTRIBUTION.search(line) is None, line
        assert lib.scrub(line) == line

    DROP = [
        "  -  Author: Daniel Cid.",
        "  -  Author: Somebody <who@where.org>.",
        "<!--  Author: Somebody  -->",
        "# Author: Nobody",
        "// Author: Nobody",
        ";   Author: Nobody",
        "  author: Nobody",
        'author = "Florian Roth"',
        "--- author: someone",
        "   Contributed by: Someone Else",
        "  Modified by: Someone",
        "* Maintainer: Someone",
    ]

    @pytest.mark.parametrize("line", DROP)
    def test_attribution_lines_are_removed(self, line):
        assert lib._ATTRIBUTION.search(line) is not None, line
        assert lib.scrub(line).strip() == ""

    def test_removing_an_attribution_does_not_weld_paragraphs(self):
        """A deleted line must not join the sentence above to the one below.

        The boilerplate filter had to be fixed for exactly this, and a redactor
        that joins two halves of a literal is also how ``build.py`` grew a
        second redaction pass after boilerplate removal.
        """
        text = ("first paragraph ends here\n"
                "  Author: Someone\n"
                "second paragraph starts here")
        out = lib.scrub(text)
        assert "here\nsecond" not in out.replace("  ", "")
        assert "first paragraph ends here" in out
        assert "second paragraph starts here" in out
        assert "Someone" not in out


class TestProtocolNamesAreNotAddresses:
    """``hmac-sha2-512-etm@openssh.com`` is an algorithm, not a mailbox.

    Roughly six hundred of the 717 email-shaped tokens in Wazuh's ruleset are
    SSH algorithm names, and they sit inside sshd rules and decoders where they
    are the thing being detected. Redacting them would have been reported as a
    six-hundred-item privacy win and would have gutted the register.
    """

    ALGORITHMS = [
        "hmac-sha2-512-etm@openssh.com",
        "aes256-gcm@openssh.com",
        "chacha20-poly1305@openssh.com",
        "umac-128-etm@openssh.com",
        "curve25519-sha256@libssh.org",
        "rijndael-cbc@lysator.liu.se",
        "zlib@openssh.com",
    ]

    @pytest.mark.parametrize("token", ALGORITHMS)
    def test_algorithm_names_survive(self, token):
        assert lib.scrub(token) == token
        lib.assert_scrubbed("probe", "probe", token)

    RESERVED = ["user@example.com", "admin@example.net", "x@example.org",
                "a@b.invalid", "c@d.test", "e@f.localhost", "g@h.example"]

    @pytest.mark.parametrize("token", RESERVED)
    def test_rfc2606_reserved_domains_survive(self, token):
        """Reserved by RFC 2606 and RFC 6761, so provably not a person's."""
        assert lib.scrub(token) == token

    LEAKS = ["ddpbsd@gmail.com", "peter@ifup.de", "jorge@br10.com.br",
             "homer.simpson@duff.com", "stwilliams@workforcesoftware.com",
             "julio.camargo@cloudfence.eu", "info@e-szigno.hu"]

    @pytest.mark.parametrize("token", LEAKS)
    def test_real_addresses_are_replaced(self, token):
        out = lib.scrub(token)
        assert token not in out
        assert out.endswith("@example.invalid")
        lib.assert_scrubbed("probe", "probe", out)

    def test_distinct_addresses_get_distinct_placeholders(self):
        """A mail log where sender and recipient collapse to one name is a lie.

        The *shape* of the record — two different parties — is signal; who they
        were is not.
        """
        out = lib.scrub("from a@real-domain.com to b@other-domain.com")
        assert "real-domain" not in out and "other-domain" not in out
        assert "user1@example.invalid" in out and "user2@example.invalid" in out

    def test_trailing_punctuation_is_preserved(self):
        """The domain class is flat, so a match can run into the punctuation."""
        out = lib.scrub("contact x@realdomain.com, or y@realdomain.com.")
        assert out.count("@example.invalid") == 2
        assert out.endswith(".")
        assert "," in out

    def test_a_very_long_dotted_token_is_left_alone_rather_than_mangled(self):
        """Over-redaction corrupts content; this refuses rather than guesses.

        The flat domain class is capped at 253 characters, so a thirty-label
        token can be truncated mid-label into something that *ends* like a
        hostname. Rewriting its first 253 characters and leaving the tail
        dangling would damage real text, so a domain with more than eight
        labels is not treated as an address at all.
        """
        token = "user@" + ".".join(["abcdefgh"] * 40)
        assert lib.scrub(token) == token


class TestAssertScrubbedProvesRatherThanTrusts:
    """The verifier that reported "0 leaks" having read zero bytes is the reason.

    ``assert_scrubbed`` is expected to be a no-op forever. The point is that it
    is checked at all, and that when it fires it reports a form and never a
    value.
    """

    def test_an_unredacted_address_raises(self):
        with pytest.raises(SourceError) as caught:
            lib.assert_scrubbed("probe", "ident", "mail me at real@person.com")
        assert "real@person.com" not in str(caught.value)
        assert "person.com" not in str(caught.value)
        assert "address/len" in str(caught.value)

    def test_a_surviving_attribution_raises(self):
        with pytest.raises(SourceError) as caught:
            lib.assert_scrubbed("probe", "ident", "# Author: A Real Name")
        assert "A Real Name" not in str(caught.value)
        assert "attribution/len" in str(caught.value)

    def test_scrubbed_text_always_passes(self):
        text = ("# Author: Someone <someone@somewhere.net>\n"
                "signature x { payload /aes256-gcm@openssh.com/ }\n"
                "mail from=victim@realcompany.io")
        lib.assert_scrubbed("probe", "ident", lib.scrub(text))

    def test_the_report_never_holds_a_value(self):
        report = lib.ScrubReport()
        lib.scrub("# Author: Someone <s@realdomain.org>", report)
        line = report.line("probe")
        assert "realdomain" not in line and "Someone" not in line
        assert "attribution/len" in line or "address/len" in line


# --------------------------------------------------------------------------- #
# Extraction
# --------------------------------------------------------------------------- #

class TestExtractIsHostileToArchives:
    """An archive member is attacker-controlled data, even a trusted one.

    Absolute paths, ``..`` segments, symlinks and hardlinks are all expressible
    in tar, and the cheap defence is never handing the archive's own names to
    the filesystem unchecked.
    """

    def _archive(self, tmp_path: Path, members) -> Path:
        archive = tmp_path / "evil.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            for name, kind, payload in members:
                info = tarfile.TarInfo(name)
                if kind == "file":
                    data = payload.encode()
                    info.size = len(data)
                    import io
                    tar.addfile(info, io.BytesIO(data))
                elif kind == "symlink":
                    info.type = tarfile.SYMTYPE
                    info.linkname = payload
                    tar.addfile(info)
        return archive

    def _extract(self, tmp_path, archive, monkeypatch, **kwargs):
        def _fake_download(url, target, **_kw):
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read_bytes())
            return target

        monkeypatch.setattr(lib, "download", _fake_download)
        defaults = dict(
            name="probe", url="https://example.invalid/a.tar.gz",
            cache_dir=tmp_path / "cache",
            keep=lambda rel: rel.suffix == ".txt",
            licence_files=("LICENSE",), max_bytes=1 << 20, min_kept=1,
        )
        defaults.update(kwargs)
        return lib.extract(**defaults)

    def test_dotdot_and_absolute_members_are_dropped(self, tmp_path, monkeypatch):
        archive = self._archive(tmp_path, [
            ("root/LICENSE", "file", "a licence"),
            ("root/good.txt", "file", "kept"),
            ("root/../../escape.txt", "file", "escaped"),
            ("/absolute.txt", "file", "escaped"),
        ])
        home, _meta = self._extract(tmp_path, archive, monkeypatch)
        assert (home / "good.txt").read_text() == "kept"
        assert not (tmp_path / "escape.txt").exists()
        assert not (tmp_path.parent / "escape.txt").exists()

    def test_symlink_members_are_never_written(self, tmp_path, monkeypatch):
        """Only regular files. A symlink in the cache is how ownrepos once
        followed this repository's own ``data`` link into the external volume
        and pulled the corpus back in as PROSE."""
        archive = self._archive(tmp_path, [
            ("root/LICENSE", "file", "a licence"),
            ("root/good.txt", "file", "kept"),
            ("root/link.txt", "symlink", "/etc/passwd"),
        ])
        home, _meta = self._extract(tmp_path, archive, monkeypatch)
        assert not (home / "link.txt").exists()
        assert (home / "good.txt").is_file()

    def test_a_missing_licence_caches_nothing(self, tmp_path, monkeypatch):
        """A declared licence that cannot be pointed at is a claim, not a reading."""
        archive = self._archive(tmp_path, [("root/good.txt", "file", "kept")])
        with pytest.raises(SourceError) as caught:
            self._extract(tmp_path, archive, monkeypatch)
        assert "licence" in str(caught.value).lower()
        assert not (tmp_path / "cache" / "probe").exists()

    def test_a_thin_archive_caches_nothing(self, tmp_path, monkeypatch):
        archive = self._archive(tmp_path, [
            ("root/LICENSE", "file", "a licence"),
            ("root/one.txt", "file", "kept"),
        ])
        with pytest.raises(SourceError) as caught:
            self._extract(tmp_path, archive, monkeypatch, min_kept=50)
        assert "layout" in str(caught.value)
        assert not (tmp_path / "cache" / "probe").exists()

    def test_the_licence_lands_under_licenses(self, tmp_path, monkeypatch):
        archive = self._archive(tmp_path, [
            ("root/LICENSE", "file", "the real terms"),
            ("root/good.txt", "file", "kept"),
        ])
        home, meta = self._extract(tmp_path, archive, monkeypatch)
        assert (home / "licenses" / "LICENSE").read_text() == "the real terms"
        assert meta["licenses"] == {"LICENSE": "LICENSE"}

    def test_the_marker_carries_no_local_path(self, tmp_path, monkeypatch):
        """A cache marker is a file somebody will paste into an issue."""
        archive = self._archive(tmp_path, [
            ("root/LICENSE", "file", "terms"),
            ("root/good.txt", "file", "kept"),
        ])
        home, meta = self._extract(tmp_path, archive, monkeypatch)
        lib.write_marker(home, meta)
        blob = lib.marker_path(home).read_text()
        assert str(tmp_path) not in blob
        assert os.path.expanduser("~") not in blob
        for banned in ("/Users/", "/Volumes/", "/home/"):
            assert banned not in blob


class TestWalkFilesDoesNotFollowLinks:
    """``os.walk(followlinks=False)``, never ``rglob``.

    ``Path.rglob`` descends through directory symlinks. In this repository that
    is not theoretical: ``ownrepos`` followed the repo's ``data`` symlink into
    the SSD and pulled the corpus cache back in as PROSE — the corpus ate
    itself, and only the balance report noticed.
    """

    def test_a_directory_symlink_is_not_descended(self, tmp_path):
        real = tmp_path / "real"
        (real / "deep").mkdir(parents=True)
        (real / "deep" / "a.zeek").write_text("x")
        tree = tmp_path / "tree"
        tree.mkdir()
        (tree / "b.zeek").write_text("y")
        try:
            (tree / "loop").symlink_to(real, target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks unavailable here")
        found = {p.name for p in lib.walk_files(tree, (".zeek",))}
        assert found == {"b.zeek"}

    def test_a_file_symlink_is_not_yielded(self, tmp_path):
        target = tmp_path / "target.zeek"
        target.write_text("x")
        tree = tmp_path / "tree"
        tree.mkdir()
        try:
            (tree / "link.zeek").symlink_to(target)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks unavailable here")
        assert list(lib.walk_files(tree, (".zeek",))) == []


class TestDedupKey:
    def test_whitespace_and_case_do_not_make_a_new_check(self):
        assert lib.dedup_key("Ensure X", "a b") == lib.dedup_key("ensure  x", "a\nb")

    def test_different_rules_are_different_keys(self):
        assert lib.dedup_key("t", ["c:a -> r:b"]) != lib.dedup_key("t", ["c:a -> r:c"])

    def test_none_and_empty_are_distinguishable_from_a_value(self):
        assert lib.dedup_key(None) != lib.dedup_key("x")


class TestAttackIds:
    def test_ids_are_written_in_the_form_the_world_writes_them(self):
        assert lib.attack_ids("T1059", "T1059.001") == ["T1059", "T1059.001"]

    def test_order_is_preserved_and_duplicates_collapse(self):
        assert lib.attack_ids("T1003 T1059 T1003") == ["T1003", "T1059"]

    def test_a_bare_number_is_not_a_technique(self):
        assert lib.attack_ids("1059", "TA0006", "4625") == []


# --------------------------------------------------------------------------- #
# wazuh
# --------------------------------------------------------------------------- #

class TestWazuhRuleBlocks:
    """XML is scanned, not parsed, and the scanner must not fuse two rules.

    8 of the 288 rule and decoder files are not well-formed when wrapped in a
    root element — bare ``&`` and ``<`` inside regexes, which Wazuh's own
    lenient reader accepts — so an ``ElementTree`` pass would silently drop
    eight files. The obvious regex replacement has its own quiet bug.
    """

    def test_a_self_closing_rule_does_not_swallow_the_next_one(self):
        from training.corpus.sources import wazuh

        xml = ('<group name="g,">\n'
               '  <rule id="1" level="0" />\n'
               '  <rule id="2" level="5">\n'
               '    <match>needle</match>\n'
               '  </rule>\n'
               '</group>\n')
        blocks = wazuh._rule_blocks(xml)
        assert len(blocks) == 2, blocks
        assert "needle" not in blocks[0]
        assert "needle" in blocks[1]

    def test_malformed_xml_still_yields_its_rules(self):
        """A bare ``&`` is why there is a scanner at all."""
        from training.corpus.sources import wazuh

        xml = ('<group name="g,">\n'
               '  <rule id="7" level="9">\n'
               '    <regex>a & b < c</regex>\n'
               '    <description>unparseable but real</description>\n'
               '  </rule>\n'
               '</group>\n')
        blocks = wazuh._rule_blocks(xml)
        assert len(blocks) == 1
        assert "a & b < c" in blocks[0]

    def test_an_event_id_is_not_mistaken_for_a_technique(self):
        """``<id>`` in a Wazuh rule is the extracted *event* id."""
        from training.corpus.sources import wazuh

        block = ('<rule id="60122" level="5">\n'
                 '  <id>^4625$</id>\n'
                 '  <description>T1110 is mentioned in this text</description>\n'
                 '</rule>')
        rendered = wazuh._render_rule(block, file="rules/x.xml", group="g",
                                      names={})
        assert rendered is not None
        _rule_id, text = rendered
        assert "MITRE ATT&CK:" not in text

    def test_a_mitre_block_is_read_and_labelled(self):
        from training.corpus.sources import wazuh

        block = ('<rule id="5701" level="8">\n'
                 '  <mitre>\n    <id>T1190</id>\n  </mitre>\n'
                 '  <description>sshd attack</description>\n'
                 '</rule>')
        _rule_id, text = wazuh._render_rule(
            block, file="rules/x.xml", group="syslog,sshd,",
            names={"T1190": "Exploit Public-Facing Application"})
        assert "T1190 Exploit Public-Facing Application" in text

    def test_compliance_tags_are_separated_from_classification_tags(self):
        from training.corpus.sources import wazuh

        compliance, plain = wazuh._compliance(
            "gdpr_IV_35.7.d,pci_dss_11.4,recon,nist_800_53_SI.4,authentication_failed,")
        assert "pci_dss_11.4" in compliance and "gdpr_IV_35.7.d" in compliance
        assert "recon" in plain and "authentication_failed" in plain
        assert not set(compliance) & set(plain)


class TestWazuhSplitting:
    """A logtest case must never be split away from its verdict."""

    def test_a_split_never_cuts_a_record(self):
        from training.corpus.sources import wazuh

        body = "".join(
            f"[case {i}]\nlog 1 pass = line {i}\nrule = {5000 + i}\nalert = 4\n\n"
            for i in range(200))
        chunks = wazuh._split_on(body, wazuh._INI_CASE, 2_000)
        assert len(chunks) > 1
        for chunk in chunks:
            # Every 'log' line in a chunk keeps the 'rule' line that labels it.
            assert chunk.count("log 1 pass") == chunk.count("rule =")

    def test_a_short_body_is_not_split(self):
        from training.corpus.sources import wazuh

        body = "[one]\nlog 1 pass = x\nrule = 1\n"
        assert wazuh._split_on(body, wazuh._INI_CASE, 10_000) == [body]


class TestWazuhScaRegisterIsMeasured:
    """Register is measured per document, and the rule is checkable.

    DETECTION sits at 1.60x its target and PROSE at 0.69x, so filing 12 MB of
    mostly-prose CIS rationale under DETECTION would have the balancer trim
    DETECTION — possibly this source's own logtest documents, which are the most
    valuable thing in it. The measurement has to be a rule, not a preference.
    """

    def test_a_probe_heavy_check_is_detection(self):
        from training.corpus.sources import wazuh

        check = {"title": "t", "rationale": "short",
                 "remediation": "Run: sed -i 's/a/b/' /etc/x && systemctl restart x",
                 "condition": "all"}
        rules = ["c:sshd -T -> r:^\\s*permitrootlogin\\s+no",
                 "f:/etc/ssh/sshd_config -> !r:^#"]
        assert wazuh._sca_register(check, rules) is Register.DETECTION

    def test_a_prose_heavy_check_is_prose(self):
        from training.corpus.sources import wazuh

        check = {"title": "t", "rationale": "x" * 2000, "impact": "y" * 1000,
                 "description": "z" * 1000,
                 "remediation": "Edit the file to conform to site policy.",
                 "condition": "all"}
        assert wazuh._sca_register(check, ["f:/etc/x -> r:y"]) is Register.PROSE

    def test_a_shell_remediation_counts_as_the_probe_half(self):
        from training.corpus.sources import wazuh

        script = "#!/usr/bin/env bash\n" + "modprobe -r x\n" * 60
        check = {"rationale": "a" * 300, "remediation": script,
                 "condition": "all"}
        assert wazuh._sca_register(check, []) is Register.DETECTION

    def test_ties_go_to_detection(self):
        from training.corpus.sources import wazuh

        check = {"rationale": "", "remediation": "", "condition": ""}
        assert wazuh._sca_register(check, []) is Register.DETECTION


# --------------------------------------------------------------------------- #
# zeek
# --------------------------------------------------------------------------- #

class TestZeekIndentation:
    """Zeek indents with hard tabs and column-aligns its ``##`` field comments.

    ``normalise()`` preserves horizontal whitespace by contract. The one
    historical bug in it was that it did not, which flattened Sigma nesting and
    destroyed netstat columns. This source re-proves the contract per file so
    that a regression says which line, instead of shipping flattened schemas
    with an unchanged document count.
    """

    def test_tab_indented_records_survive_normalise(self):
        from training.corpus.sources import zeek

        raw = ("module Conn;\n"
               "export {\n"
               "\ttype Info: record {\n"
               "\t\t## This is the time of the first packet.\n"
               "\t\tts: time &log;\n"
               "\t};\n"
               "}\n")
        assert zeek._indentation_survived(raw, normalise(raw)) is None

    def test_a_flattening_cleaner_is_caught_with_a_line_number(self):
        from training.corpus.sources import zeek

        raw = "a\n\t\tindented\n\t\tmore\n"
        flattened = "a\nindented\n\t\tmore\n"
        assert zeek._indentation_survived(raw, flattened) == 2

    def test_trailing_whitespace_stripping_is_not_called_damage(self):
        from training.corpus.sources import zeek

        raw = "module X;   \n\tfield: count;  \n"
        assert zeek._indentation_survived(raw, normalise(raw)) is None


class TestZeekRegisterTable:
    def test_policy_scripts_are_detection(self):
        from training.corpus.sources import zeek

        assert zeek._register_for(
            "policy/protocols/ssh/detect-bruteforcing.zeek") is Register.DETECTION

    def test_protocol_schemas_are_system(self):
        from training.corpus.sources import zeek

        assert zeek._register_for(
            "base/protocols/conn/main.zeek") is Register.SYSTEM

    def test_a_signature_file_is_detection_wherever_it_lives(self):
        """23 of the 40 .sig files sit under base/protocols/, beside the
        analyzer they enable. The path table alone filed Zeek's only
        byte-pattern signatures as schema."""
        from training.corpus.sources import zeek

        assert zeek._register_for(
            "base/protocols/ssl/dpd.sig") is Register.DETECTION
        assert zeek._register_for(
            "policy/frameworks/signatures/detect-windows-shells.sig"
        ) is Register.DETECTION

    def test_excluded_files_are_excluded(self):
        from training.corpus.sources import zeek

        for excluded in ("scripts/base/init-bare.zeek",
                         "scripts/base/utils/site.zeek",
                         "scripts/spicy/zeek.spicy",
                         "scripts/zeekygen/example.zeek",
                         "scripts/policy/misc/__load__.zeek"):
            assert not zeek._keep(Path(excluded)), excluded
        assert zeek._keep(Path("scripts/policy/protocols/ssh/software.zeek"))
        assert zeek._keep(Path("scripts/base/protocols/conn/main.zeek"))


# --------------------------------------------------------------------------- #
# falco
# --------------------------------------------------------------------------- #

class TestFalcoMacroExpansion:
    """A Falco condition is almost never self-contained.

    203 macros and 166 lists support 100 rules, and a rule emitted raw names
    identifiers defined elsewhere in a 100 KB file — the model would learn the
    names and never meet the semantics.
    """

    MACROS = {
        "spawned_process": {"condition": "evt.type in (execve, execveat) and evt.dir=<"},
        "container": {"condition": "container.id != host"},
        "shell_procs": {"condition": "proc.name in (shell_binaries)"},
    }
    LISTS = {
        "shell_binaries": {"items": ["ash", "bash", "sh", "zsh"]},
    }

    def test_macros_and_nested_lists_are_resolved(self):
        from training.corpus.sources import falco

        out = falco._expand("spawned_process and container and shell_procs",
                            self.MACROS, self.LISTS)
        blob = "\n".join(out)
        assert "macro spawned_process" in blob
        assert "macro container" in blob
        assert "macro shell_procs" in blob
        assert "list shell_binaries: [ash, bash, sh, zsh]" in blob

    def test_field_names_are_not_mistaken_for_macros(self):
        """``evt.type`` and ``proc.name`` carry a dot; a macro name does not."""
        from training.corpus.sources import falco

        out = falco._expand("evt.type=execve and proc.name=bash",
                            {"type": {"condition": "WRONG"},
                             "name": {"condition": "WRONG"}}, {})
        assert out == []

    def test_a_macro_cycle_terminates(self):
        """A macro set maintained by many hands is where a cycle appears."""
        from training.corpus.sources import falco

        cyclic = {"a": {"condition": "b"}, "b": {"condition": "c"},
                  "c": {"condition": "a"}}
        out = falco._expand("a", cyclic, {})
        assert {"a", "b", "c"} == {
            line.split()[1].rstrip(":") for line in out}

    def test_self_reference_terminates(self):
        from training.corpus.sources import falco

        assert len(falco._expand("loop", {"loop": {"condition": "loop"}}, {})) == 1


class TestFalcoTagSplitting:
    """One overloaded ``tags`` list holds four different things."""

    def test_maturity_tactic_technique_and_the_rest_are_separated(self):
        from training.corpus.sources import falco

        maturity, tactics, techniques, other = falco._tags(
            ["maturity_stable", "container", "cis", "process",
             "mitre_privilege_escalation", "T1611"])
        assert maturity == ["stable"]
        assert tactics == ["privilege escalation"]
        assert techniques == ["T1611"]
        assert other == ["container", "cis", "process"]

    def test_a_subtechnique_id_is_recognised(self):
        from training.corpus.sources import falco

        _m, _ta, techniques, _o = falco._tags(["T1059.004"])
        assert techniques == ["T1059.004"]

    def test_no_tags_is_not_an_error(self):
        from training.corpus.sources import falco

        assert falco._tags(None) == ([], [], [], [])


# --------------------------------------------------------------------------- #
# panther
# --------------------------------------------------------------------------- #

class TestPantherAgentInstructionFilesAreExcluded:
    """``AGENTS.md``, ``CLAUDE.md`` and ``.claude/`` are instructions to a model.

    Off-register for a detection corpus, and text shaped like a command to a
    model does not belong in that model's training data. ``owasp.py`` set this
    precedent for the same files; following it rather than rediscovering it is
    the point of the test.
    """

    @pytest.mark.parametrize("path", [
        "rules/AGENTS.md", "rules/CLAUDE.md",
        "rules/.claude/settings.yml", "packs/aws.yml",
        "lookup_tables/x.yml", "indexes/x.json", "templates/x.yml",
        "test_scenarios/x.yml", "style_guides/x.yml",
    ])
    def test_excluded(self, path):
        from training.corpus.sources import panther

        assert not panther._keep(Path(path)), path

    @pytest.mark.parametrize("path", [
        "rules/aws_cloudtrail_rules/x.yml", "rules/aws_cloudtrail_rules/x.py",
        "policies/aws_account_policies/x.yml", "queries/x.yml",
        "global_helpers/panther_aws_helpers.py", "data_models/x.yml",
        "correlation_rules/x.yml",
    ])
    def test_kept(self, path):
        from training.corpus.sources import panther

        assert panther._keep(Path(path)), path


class TestPantherFilenameIsNotATraversal:
    """``Filename:`` is a value out of a downloaded file used to build a path."""

    def test_a_traversing_filename_is_refused(self, tmp_path):
        from training.corpus.sources import panther

        home = tmp_path / "panther"
        (home / "rules" / "aws").mkdir(parents=True)
        (tmp_path / "secret.py").write_text("# not part of the corpus")
        (home / "rules" / "aws" / "r.yml").write_text(textwrap.dedent("""\
            AnalysisType: rule
            RuleID: "Probe.Traversal"
            Filename: ../../../secret.py
            Severity: Low
            Description: a probe
            """))
        docs = list(panther._documents(home))
        assert all("not part of the corpus" not in d.text for d in docs)

    def test_a_sibling_filename_is_read(self, tmp_path):
        from training.corpus.sources import panther

        home = tmp_path / "panther"
        (home / "rules" / "aws").mkdir(parents=True)
        (home / "rules" / "aws" / "r.py").write_text(
            "def rule(event):\n    return event.get('x') == 1\n")
        (home / "rules" / "aws" / "r.yml").write_text(textwrap.dedent("""\
            AnalysisType: rule
            RuleID: "Probe.Sibling"
            Filename: r.py
            Severity: Low
            LogTypes:
              - AWS.CloudTrail
            Description: a probe that is long enough to clear the character floor
              and then some, because the floor exists to drop stubs rather than
              real detections and this needs to be a real one.
            """))
        docs = list(panther._documents(home))
        assert len(docs) == 1
        assert "def rule(event):" in docs[0].text


class TestPantherWorkedExamples:
    """Both polarities, because the False case is the hard half to find."""

    def test_both_verdicts_are_represented_when_available(self):
        from training.corpus.sources import panther

        tests = ([{"Name": f"pos{i}", "ExpectedResult": True, "Log": {}}
                  for i in range(8)]
                 + [{"Name": f"neg{i}", "ExpectedResult": False, "Log": {}}
                    for i in range(8)])
        chosen, dropped = panther._select_tests(tests)
        assert len(chosen) == panther._TESTS_PER_DETECTION
        assert any(t["ExpectedResult"] is True for t in chosen)
        assert any(t["ExpectedResult"] is False for t in chosen)
        assert dropped == 16 - panther._TESTS_PER_DETECTION

    def test_an_all_positive_detection_still_fills_the_quota(self):
        from training.corpus.sources import panther

        tests = [{"Name": f"p{i}", "ExpectedResult": True, "Log": {}}
                 for i in range(6)]
        chosen, dropped = panther._select_tests(tests)
        assert len(chosen) == panther._TESTS_PER_DETECTION
        assert dropped == 2

    def test_no_tests_is_not_an_error(self):
        from training.corpus.sources import panther

        assert panther._select_tests(None) == ([], 0)

    def test_the_tactic_technique_pair_is_split(self):
        """``TA0007:T1078`` appears nowhere outside Panther's own YAML."""
        from training.corpus.sources import panther

        out = panther._reports({"MITRE ATT&CK": ["TA0007:T1078"],
                                "CIS": ["1.5", "1.6"]})
        blob = "\n".join(out)
        assert "T1078 (tactic TA0007)" in blob
        assert "TA0007:T1078" not in blob
        assert "CIS: 1.5, 1.6" in blob

    def test_event_key_order_is_preserved(self):
        """An event is a record; the order a provider emits its fields is part
        of what the record looks like."""
        from training.corpus.sources import panther

        out = panther._render_event({"eventVersion": "1.05", "awsRegion": "x",
                                     "eventName": "y"})
        assert out.index("eventVersion") < out.index("awsRegion") < out.index("eventName")


# --------------------------------------------------------------------------- #
# The family as a whole
# --------------------------------------------------------------------------- #

class TestTheFamilyHonoursTheCorpusContract:

    def test_every_module_is_discovered_with_a_matching_name(self):
        from training.corpus.build import discover_sources

        found = {spec.name for spec in discover_sources()}
        for name in _FAMILY:
            assert name in found, f"{name} is not discovered"

    def test_the_shared_library_is_not_a_source(self):
        """The leading underscore is load-bearing."""
        from training.corpus.build import discover_sources

        assert "_detectionlib" not in {s.name for s in discover_sources()}
        assert not hasattr(lib, "SPEC")

    @pytest.mark.parametrize("name", _FAMILY)
    def test_the_licence_is_specific_and_names_its_file(self, name):
        """``build.py`` refuses a blank licence; a vague one it cannot refuse.

        Every upstream in this family had its licence read from a file in the
        fetched archive, and one of them is the reason: panther's is
        ``LICENSE.txt`` and ``LICENSE`` is a 404, so the first read failed. The
        declaration therefore has to say which identifier and point at the
        evidence.
        """
        spec = _modules()[name].SPEC
        licence = spec.license
        assert len(licence) > 200, f"{name}: licence is too vague to check"
        assert any(token in licence for token in
                   ("LICENSE", "COPYING", "LICENSE.txt")), name
        assert any(token in licence for token in
                   ("GPL-2.0", "BSD-3-Clause", "Apache-2.0")), name

    @pytest.mark.parametrize("name", _FAMILY)
    def test_no_private_network_door(self, name):
        """All network I/O through ``training.corpus.net``.

        Three adapters grew their own ``_ssl_context`` before it was
        consolidated, and a second copy of the door does not get the door's
        later fixes — one of them was still following redirects with the stock
        opener, which downgrades to plaintext http.
        """
        import ast

        path = (Path(__file__).resolve().parents[1]
                / f"training/corpus/sources/{name}.py")
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        opened = [node.lineno for node in ast.walk(tree)
                  if isinstance(node, ast.Call)
                  and isinstance(node.func, ast.Attribute)
                  and node.func.attr in ("urlopen", "create_default_context",
                                         "_create_unverified_context")]
        assert not opened, f"{name} opens its own connection at {opened}"

    @pytest.mark.parametrize("name", _FAMILY)
    def test_no_rglob_in_the_family(self, name):
        """``rglob`` follows directory symlinks; ``os.walk`` can be told not to."""
        import ast

        for path in (Path(__file__).resolve().parents[1]
                     / "training/corpus/sources").glob(f"{name}.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            used = [node.lineno for node in ast.walk(tree)
                    if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr in ("rglob", "walk")
                    and not (isinstance(node.func.value, ast.Name)
                             and node.func.value.id == "os")]
            assert not used, f"{name} uses rglob at {used}"

    def test_the_shared_library_walks_without_following_links(self):
        import ast

        path = (Path(__file__).resolve().parents[1]
                / "training/corpus/sources/_detectionlib.py")
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        walks = [node for node in ast.walk(tree)
                 if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute)
                 and node.func.attr == "walk"]
        assert walks, "_detectionlib no longer walks anything"
        for call in walks:
            keywords = {kw.arg for kw in call.keywords}
            assert "followlinks" in keywords, (
                f"os.walk at line {call.lineno} does not say followlinks=False")

    @pytest.mark.parametrize("name", _FAMILY)
    def test_the_register_declared_is_one_the_source_emits(self, name):
        """A spec that claims a register nothing in it carries misreports the
        balance report, which is the one report the corpus is steered by."""
        spec = _modules()[name].SPEC
        assert isinstance(spec.register, Register)
        assert isinstance(spec.side, Side)
        assert spec.expect_min_docs >= 1

    @pytest.mark.parametrize("name", _FAMILY)
    def test_nothing_in_the_module_names_this_machine(self, name):
        """A source module is published. The corpus privacy audit found a
        machine's own mount point hard-coded as a default in ``build.py``."""
        path = (Path(__file__).resolve().parents[1]
                / f"training/corpus/sources/{name}.py")
        text = path.read_text(encoding="utf-8")
        for banned in ("/Users/", "/Volumes/", "/home/", os.path.expanduser("~")):
            if banned and banned != "~":
                assert banned not in text, f"{name} names a local path"

    def test_documents_are_well_formed_without_a_cache(self):
        """A Document with empty text raises in its own constructor, so a
        renderer that produces nothing must be caught by the character floor
        rather than by the dataclass."""
        with pytest.raises(SourceError):
            Document(text="   ", source="probe", register=Register.DETECTION,
                     side=Side.BLUE, ident="x")
