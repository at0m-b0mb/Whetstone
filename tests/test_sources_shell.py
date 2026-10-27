"""Tests for the three SHELL-register sources added to close the biggest gap.

SHELL was 15.6% of the corpus against a 26% target, and the ROADMAP's own
shopping list named busybox and coreutils usage text. These three adapters are
that, plus the thing the list did not ask for and the corpus needed most: real
captured command *output*.

What is pinned here is what each one got wrong first, because a corpus adapter
fails quietly — a wrong gloss, a spliced conditional, a collapsed column — and
the first symptom of any of them is a slightly worse model four steps
downstream. Everything below is offline: every parser is a pure function and the
network is never touched.
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from training.corpus.source import Register, Side, normalise

# ---------------------------------------------------------------------------
# cmdoutput — real captured command output
# ---------------------------------------------------------------------------

class TestCmdOutputPseudonymise:
    """Redaction that must not move a single character.

    normalise() preserves horizontal whitespace because collapsing it destroyed
    netstat's column alignment — the best register this project has measured
    (+47% against gpt2). A redactor that re-introduced that damage from inside
    would be worse than the leak it fixed, so length preservation is the
    property under test, not a nicety.
    """

    def test_mac_is_rewritten_at_identical_length(self):
        from training.corpus.sources.cmdoutput import pseudonymise
        raw = "ether 00:1c:42:9e:4f:2a"
        out, macs, v6 = pseudonymise(raw)
        assert macs == 1 and v6 == 0
        assert len(out) == len(raw)
        assert "00:1c:42:9e:4f:2a" not in out
        assert "02:" in out                     # locally administered: synthetic

    def test_column_alignment_survives_a_rewrite(self):
        from training.corpus.sources.cmdoutput import pseudonymise
        row = "en0   1500  00:1c:42:9e:4f:2a  1234567   0  89012  0"
        out, _, _ = pseudonymise(row)
        assert len(out) == len(row)
        assert normalise(out) == out            # nothing for normalise to fix
        assert out.index("1234567") == row.index("1234567")

    @pytest.mark.parametrize("keep", [
        "ff:ff:ff:ff:ff:ff",        # broadcast
        "00:00:00:00:00:00",        # unspecified
        "01:00:5e:7f:ff:fa",        # IPv4 multicast, derived from the group
        "33:33:00:00:00:01",        # IPv6 multicast, derived from the address
    ])
    def test_addresses_that_identify_no_hardware_are_left_alone(self, keep):
        from training.corpus.sources.cmdoutput import pseudonymise
        out, macs, _ = pseudonymise(f"HWaddr {keep}")
        assert keep in out and macs == 0

    def test_global_ipv6_moves_into_the_documentation_prefix(self):
        from training.corpus.sources.cmdoutput import pseudonymise
        raw = "inet6 2a00:1450:4001:81b:0:0:0:200e prefixlen 64"
        out, _, v6 = pseudonymise(raw)
        assert v6 == 1
        assert len(out) == len(raw)
        assert "2a00:1450" not in out
        assert "2001:0db8:" in out

    def test_link_local_and_unique_local_are_not_touched(self):
        from training.corpus.sources.cmdoutput import pseudonymise
        raw = "inet6 fe80::1 prefixlen 64\ninet6 fd00::5 prefixlen 48\ninet6 ::1"
        out, macs, v6 = pseudonymise(raw)
        assert out == raw and macs == 0 and v6 == 0

    def test_eui64_interface_id_is_a_mac_and_is_rewritten(self):
        """SLAAC embeds the hardware address; a link-local address can leak one.

        ``fe80::aede:48ff:fe00:1323`` *is* the MAC ``ac:de:48:00:13:23`` with a
        bit flipped and ``ff:fe`` inserted. The first version of this module
        rewrote MACs and global addresses and left these alone, which is the
        same leak in a different notation.
        """
        from training.corpus.sources.cmdoutput import pseudonymise
        raw = "inet6 fe80::aede:48ff:fe00:1323%en5 prefixlen 64"
        out, macs, _ = pseudonymise(raw)
        assert macs == 1
        assert len(out) == len(raw)
        assert "aede:48ff:fe00:1323" not in out
        assert "ff:fe" in out                   # the SLAAC shape is the lesson

    def test_an_address_whose_length_cannot_be_kept_is_refused(self):
        """Fail closed. Resizing the text is not an option it may choose."""
        from training.corpus.sources.cmdoutput import _Unrewritable, pseudonymise
        with pytest.raises(_Unrewritable):
            pseudonymise("inet6 2001::1 prefixlen 128")

    def test_rewrites_are_deterministic_across_calls(self):
        from training.corpus.sources.cmdoutput import pseudonymise
        raw = "00:1c:42:9e:4f:2a and 2a00:1450:4001:81b:0:0:0:200e"
        assert pseudonymise(raw)[0] == pseudonymise(raw)[0]

    def test_the_same_address_maps_the_same_way_in_output_and_in_its_parse(self):
        """The property the paired parse rests on.

        A document carries the capture and jc's parse of it, and they are
        redacted in two separate calls. If a MAC became one pseudonym in the
        output and a different one in the parse, the document would teach that a
        column and the field extracted from it disagree — which is a worse
        lesson than no lesson. Determinism is seeded on the value, so it holds
        by construction; it is asserted because it is load-bearing.
        """
        from training.corpus.sources.cmdoutput import pseudonymise
        out = "ether 00:1c:42:9e:4f:2a"
        parse = '[{"mac": "00:1c:42:9e:4f:2a"}]'
        clean_out, _, _ = pseudonymise(out)
        clean_parse, _, _ = pseudonymise(parse)
        pseudonym = clean_out.split()[-1]
        assert pseudonym != "00:1c:42:9e:4f:2a"
        assert pseudonym in clean_parse


class TestCmdOutputRefusal:
    """Whole-file refusals. A capture full of strangers is not a scrub job."""

    def test_a_third_party_address_refuses_the_whole_capture(self):
        from training.corpus.sources.cmdoutput import refusal
        assert refusal("Author: A Person <someone@example.co.uk>") == \
            "third-party-email"

    def test_documentation_domains_are_not_a_refusal(self):
        from training.corpus.sources.cmdoutput import refusal
        assert refusal("root ada@example.com /home/ada") is None
        assert refusal("user@localhost") is None

    def test_a_password_hash_refuses_the_capture(self):
        from training.corpus.sources.cmdoutput import refusal
        shadow = "root:$6$rounds=5000$abcdefgh$XyZ0123456789:19000:0:99999:7:::"
        assert refusal(shadow) == "crypt-hash"

    def test_a_wireless_survey_refuses_the_capture(self):
        """An ``iw scan`` names the networks around a dwelling. That is a place."""
        from training.corpus.sources.cmdoutput import refusal
        assert refusal("BSS 00:11:22:33:44:55\n\tSSID: SomebodysHouse") == \
            "wireless-survey"

    def test_ordinary_output_is_collectable(self):
        from training.corpus.sources.cmdoutput import refusal
        assert refusal("tcp   0   0 0.0.0.0:445   0.0.0.0:*   LISTEN") is None


class TestCmdOutputNaming:
    """A fabricated command line is worse than no command line."""

    def test_a_label_that_matches_a_documented_form_becomes_a_command(self):
        from training.corpus.sources.cmdoutput import command_for
        assert command_for("arp-a", "arp", ("arp", "arp -a")) == "arp -a"

    def test_a_label_that_is_not_a_command_stays_unnamed(self):
        """``blkid -ip-udev-multi`` is not runnable in any shell on earth."""
        from training.corpus.sources.cmdoutput import command_for
        assert command_for("blkid-ip-udev-multi", "blkid",
                           ("blkid", "blkid -i")) is None

    def test_parser_title_separates_command_output_from_file_formats(self):
        from training.corpus.sources.cmdoutput import parser_facts
        command = parser_facts(
            'r"""jc - JSON Convert `ps` command output parser\n\n'
            "Usage (cli):\n\n    $ ps -ef | jc --ps\n", "ps")
        assert command is not None
        assert command.utility == "ps"
        assert "ps -ef" in command.documented
        assert parser_facts(
            'r"""jc - JSON Convert INI file parser\n', "ini") is None

    def test_a_multi_name_title_registers_every_name(self):
        """37 ``ls-*`` captures — the largest group upstream — went missing to a
        single-name pattern, because the title reads "`ls` and `vdir`"."""
        from training.corpus.sources.cmdoutput import parser_facts
        facts = parser_facts(
            'r"""jc - JSON Convert `ls` and `vdir` command output parser\n', "ls")
        assert facts is not None
        assert {"ls", "vdir"} <= facts.aliases

    def test_plumbing_invocations_are_not_collected_as_commands(self):
        from training.corpus.sources.cmdoutput import parser_facts
        facts = parser_facts(
            'r"""jc - JSON Convert `ini` command output parser\n\n'
            "    $ cat foo.ini | jc --ini\n    $ jc --ini foo\n", "ini")
        assert facts is not None and facts.documented == ()

    def _table(self, *entries):
        from training.corpus.sources.cmdoutput import _Parser
        table = {}
        for module, aliases in entries:
            parser = _Parser(module=module, utility=module.replace("_", " "),
                             documented=(), aliases=frozenset(aliases))
            for alias in aliases:
                table[alias] = parser
        return table

    def test_longest_whole_segment_prefix_wins(self):
        from training.corpus.sources.cmdoutput import match_parser
        table = self._table(("apt", ("apt",)), ("apt_get_sqq", ("aptgetsqq",)))
        found = match_parser("apt-get-sqq-upgrade", table)
        assert found is not None and found.module == "apt_get_sqq"

    def test_a_substring_prefix_does_not_claim_a_different_utility(self):
        """``ls`` must not swallow ``lsblk``: the segment boundary is the rule."""
        from training.corpus.sources.cmdoutput import match_parser
        table = self._table(("ls", ("ls",)), ("lsblk", ("lsblk",)))
        assert match_parser("lsblk-pairs", table).module == "lsblk"
        assert match_parser("ls-alR", table).module == "ls"

    def test_underscores_and_dots_are_separators_too(self):
        from training.corpus.sources.cmdoutput import match_parser
        table = self._table(("net_localgroup", ("netlocalgroup",)))
        found = match_parser("net_localgroup.administrators", table)
        assert found is not None and found.module == "net_localgroup"

    def test_the_ipv6_twin_resolves_to_its_v4_parser(self):
        from training.corpus.sources.cmdoutput import match_parser
        table = self._table(("ping", ("ping",)))
        found = match_parser("ping6-hostname-O-D-p", table)
        assert found is not None and found.module == "ping"

    def test_an_unknown_utility_matches_nothing(self):
        from training.corpus.sources.cmdoutput import match_parser
        assert match_parser("nosuchtool-x", self._table(("ps", ("ps",)))) is None


class TestCmdOutputRender:
    """The document shape, including the one invariant about truncation."""

    OUT = ("Filesystem      Size  Used Avail Use% Mounted on\n"
           "/dev/sda1       1014M  233M  782M  23% /boot\n")

    def _render(self, **kwargs):
        from training.corpus.sources.cmdoutput import render
        base = {"platform": "centos-7.7", "utility": "df", "parser": "df",
                "stem": "df-h", "command": "df -h", "parsed": None}
        base.update(kwargs)
        return render(self.OUT, **base)

    def test_header_states_platform_and_command(self):
        text, _, _ = self._render()
        assert "Platform: centos-7.7" in text
        assert "Command: df -h" in text
        assert "Parser: jc --df" in text

    def test_an_unnamed_capture_says_the_label_is_a_label(self):
        text, _, _ = self._render(command=None)
        assert "Command:" not in text
        assert "not a command line" in text

    def test_output_columns_are_preserved_verbatim(self):
        text, _, _ = self._render()
        assert "/dev/sda1       1014M  233M  782M  23% /boot" in text

    def test_a_truncated_capture_never_carries_a_parse(self):
        """Pairing a head of the output with a parse of all of it teaches a
        mapping that is simply wrong, so the pairing is dropped instead."""
        from training.corpus.sources.cmdoutput import _MAX_LINES, render
        long_out = "\n".join(f"row {n:6d}  value" for n in range(_MAX_LINES + 50))
        text, _, _ = render(long_out, platform="generic", utility="ps",
                            parser="ps", stem="ps-ef", command="ps -ef",
                            parsed='[{"pid": 1}]')
        assert "[output truncated]" in text
        assert "Parsed" not in text

    def test_a_short_capture_keeps_its_parse(self):
        text, _, _ = self._render(parsed='[{"filesystem": "/dev/sda1"}]')
        assert "Parsed (jc schema)" in text
        assert '"filesystem"' in text

    def test_a_rewrite_is_announced_in_the_document(self):
        from training.corpus.sources.cmdoutput import render
        text, macs, _ = render("ether 00:1c:42:9e:4f:2a\n" * 4,
                               platform="osx-10.14.6", utility="ifconfig",
                               parser="ifconfig", stem="ifconfig",
                               command="ifconfig", parsed=None)
        assert macs == 4
        assert "synthetic values" in text


# ---------------------------------------------------------------------------
# busybox — applet usage text
# ---------------------------------------------------------------------------

class TestBusyboxLiterals:

    def test_escapes_are_decoded(self):
        from training.corpus.sources.busybox import decode_literal
        assert decode_literal(r"\n\t-1\tOne column") == "\n\t-1\tOne column"

    def test_a_line_continuation_contributes_nothing(self):
        """In C, backslash-newline splices the literal. Mapping it to a newline
        would insert a break into the middle of every wrapped sentence."""
        from training.corpus.sources.busybox import decode_literal
        assert decode_literal("one \\\ntwo") == "one two"

    def test_an_escaped_quote_survives(self):
        from training.corpus.sources.busybox import decode_literal
        assert decode_literal(r'echo \"foo\"') == 'echo "foo"'


class TestBusyboxConditionals:
    """``IF_NOT_`` is the other arm, and keeping both splices them together."""

    TAR = (
        '\tIF_FEATURE_TAR_CREATE("Create, extract, ")',
        '\tIF_NOT_FEATURE_TAR_CREATE("Extract ")',
        '     "or list files from a tar file"',
    )

    def test_the_negated_arm_is_dropped_and_the_positive_kept(self):
        from training.corpus.sources.busybox import parse_usage
        source = "\n".join(
            ["//usage:#define tar_full_usage \"\\n\\n\""]
            + [f"//usage:{line}" for line in self.TAR])
        text = parse_usage(source)["tar"]["full"]
        assert "Create, extract, or list files from a tar file" in text
        assert "Extract or list" not in text

    def test_parentheses_inside_a_literal_are_not_structure(self):
        """``"(De)compress using gzip"`` is prose. Counting its brackets as
        depth swallows the rest of the applet."""
        from training.corpus.sources.busybox import strip_conditionals
        lines = [
            '\tIF_NOT_FEATURE_X("nope")',
            '     "\\n\\t-z\\t(De)compress using gzip"',
            '     "\\n\\t-j\\t(De)compress using bzip2"',
        ]
        kept = strip_conditionals(lines)
        assert len(kept) == 2
        assert all("De)compress" in line for line in kept)

    def test_a_nested_negated_block_is_dropped_whole(self):
        from training.corpus.sources.busybox import strip_conditionals
        lines = [
            "\tIF_NOT_FEATURE_A(",
            "\tIF_FEATURE_B(",
            '     "\\n\\t--gone\\tshould not appear"',
            "\t)",
            "\t)",
            '     "\\n\\t--kept\\tshould appear"',
        ]
        kept = "\n".join(strip_conditionals(lines))
        assert "--gone" not in kept and "--kept" in kept


class TestBusyboxRender:

    SED = (
        '//usage:#define sed_trivial_usage\n'
        '//usage:       "[-i[SFX]] [-nrE] [-f FILE]... [FILE]..."\n'
        '//usage:#define sed_full_usage "\\n\\n"\n'
        '//usage:       "\\t-e CMD\\tAdd CMD to sed commands to be executed"\n'
        '//usage:     "\\n\\t-n\\tSuppress automatic printing of pattern space"\n'
        '//usage:#define sed_example_usage\n'
        '//usage:       "$ echo \\"foo\\" | sed -e \'s/foo/bar/g\'\\n"\n'
        '//usage:       "bar\\n"\n'
    )

    def test_the_three_block_kinds_are_all_collected(self):
        from training.corpus.sources.busybox import parse_usage
        parts = parse_usage(self.SED)["sed"]
        assert set(parts) == {"trivial", "full", "example"}

    def test_tabs_survive_normalise_and_the_table_keeps_its_shape(self):
        """This source is the corpus's cheapest regression test for the rule
        that normalise() must not collapse horizontal whitespace: every option
        line here is flag-TAB-description and nothing else."""
        from training.corpus.sources.busybox import parse_usage, render
        text = render("sed", parse_usage(self.SED)["sed"])
        assert "\t-e CMD\tAdd CMD" in text
        assert normalise(text) == text

    def test_the_synopsis_is_attached_to_the_applet_name(self):
        from training.corpus.sources.busybox import parse_usage, render
        text = render("sed", parse_usage(self.SED)["sed"])
        assert "Usage: sed [-i[SFX]] [-nrE]" in text

    def test_a_worked_example_keeps_its_prompt_and_its_output(self):
        from training.corpus.sources.busybox import parse_usage, render
        text = render("sed", parse_usage(self.SED)["sed"])
        assert "Example:" in text
        assert "$ echo \"foo\" | sed -e 's/foo/bar/g'" in text
        assert "\nbar" in text

    def test_an_applet_with_no_usage_text_renders_nothing(self):
        from training.corpus.sources.busybox import render
        assert render("nothing", {}) is None

    @pytest.mark.parametrize("junk", ["", "//usage:", "//usage:#define x_full_usage",
                                      '//usage:  "unterminated',
                                      "//usage:\tIF_FEATURE_X("])
    def test_malformed_input_does_not_crash(self, junk):
        from training.corpus.sources.busybox import parse_usage
        parse_usage(junk)


# ---------------------------------------------------------------------------
# unixhelp — GNU and Linux --help text out of the C sources
# ---------------------------------------------------------------------------

class TestUnixHelpComments:

    def test_quoted_text_inside_a_comment_is_not_extracted(self):
        """coreutils writes translator notes in the code, three of them with
        quotes: ``/* TRANSLATORS: this is the "1K-blocks" header ... */``.
        Regexing literals over the raw text splices ``1K-blocks`` into the
        middle of the help output."""
        from training.corpus.sources.unixhelp import strip_comments
        src = '/* TRANSLATORS: the "1K-blocks" header */ fputs ("real", out);'
        out = strip_comments(src)
        assert "1K-blocks" not in out
        assert '"real"' in out

    def test_a_comment_delimiter_inside_a_literal_is_not_a_comment(self):
        from training.corpus.sources.unixhelp import strip_comments
        src = 'fputs ("a /* not a comment */ b", out);'
        assert "not a comment" in strip_comments(src)

    def test_a_removed_comment_leaves_a_separator(self):
        from training.corpus.sources.unixhelp import strip_comments
        assert "foobar" not in strip_comments("foo/*x*/bar")


class TestUnixHelpLicence:
    """Every document's licence is read from its own file, not from the project."""

    def test_an_spdx_tag_is_read_verbatim(self):
        from training.corpus.sources.unixhelp import licence_of
        assert licence_of("/* SPDX-License-Identifier: GPL-2.0-or-later */") == \
            "GPL-2.0-or-later"

    def test_the_fsf_notice_survives_a_comment_leader(self):
        """The regression that mattered: normalising whitespace without
        stripping the ``*`` at each line start turned "or" into "or *" and
        refused lsblk, findmnt, blkid and 86 other util-linux files."""
        from training.corpus.sources.unixhelp import licence_of
        header = (
            "/*\n"
            " * lsblk(8) - list block devices\n"
            " *\n"
            " * This program is free software; you can redistribute it and/or\n"
            " * modify it under the terms of the GNU General Public License as\n"
            " * published by the Free Software Foundation; either version 2 of\n"
            " * the License, or (at your option) any later version.\n"
            " */\n")
        assert licence_of(header) == "GPL-2.0-or-later"

    def test_the_short_wording_without_of_the_license_is_recognised(self):
        """grep, sed and tar write "either version 3, or (at your option)"."""
        from training.corpus.sources.unixhelp import licence_of
        header = ("/* grep.c\n"
                  "   under the terms of the GNU General Public License;\n"
                  "   either version 3, or (at your option) any later version. */\n")
        assert licence_of(header) == "GPL-3.0-or-later"

    def test_a_file_with_no_readable_notice_declares_nothing(self):
        from training.corpus.sources.unixhelp import licence_of
        assert licence_of("/* just a copyright line */\nint main(void){}") is None

    def test_a_version_pinned_notice_is_not_read_as_or_later(self):
        from training.corpus.sources.unixhelp import licence_of
        header = ("/* under the terms of the GNU General Public License\n"
                  "   version 2 of the License. */\n")
        assert licence_of(header) is None

    def test_only_redistributable_compatible_identifiers_are_accepted(self):
        from training.corpus.sources.unixhelp import _ACCEPTED
        assert "GPL-2.0-or-later" in _ACCEPTED
        assert "GPL-3.0-or-later" in _ACCEPTED
        # Not upgradeable, so it cannot sit beside the GPL-3.0 material.
        assert "GPL-2.0-only" not in _ACCEPTED
        # An upstream typo for a licence that does not exist. Refused, not
        # interpreted.
        assert "GPL-2.1-or-later" not in _ACCEPTED
        assert "BSD-4-Clause-UC" not in _ACCEPTED
        assert "GPL-1.0-or-later" not in _ACCEPTED


class TestUnixHelpExtraction:

    LS = (
        '/* ls.c */\n'
        'static void\n'
        'usage (int status)\n'
        '{\n'
        '  printf (_("Usage: %s [OPTION]... [FILE]...\\n"), program_name);\n'
        '  fputs (_("\\\n'
        'List information about the FILEs.\\n\\\n'
        '"), stdout);\n'
        '  fputs (_("\\\n'
        '  -a, --all                  do not ignore entries starting with .\\n\\\n'
        '  -A, --almost-all           do not list implied . and ..\\n\\\n'
        '"), stdout);\n'
        '  emit_ancillary_info (PROGRAM_NAME);\n'
        '  exit (status);\n'
        '}\n'
        'int main (void) { return 0; }\n'
    )

    def test_the_help_text_is_recovered_with_its_alignment(self):
        from training.corpus.sources.unixhelp import usage_text
        text = usage_text(self.LS)
        assert text is not None
        assert "  -a, --all                  do not ignore" in text
        assert "List information about the FILEs." in text

    def test_nothing_outside_the_function_body_is_collected(self):
        from training.corpus.sources.unixhelp import usage_text
        text = usage_text(self.LS)
        assert "main" not in text

    def test_a_file_header_never_reaches_a_document(self):
        """util-linux puts maintainer addresses in its headers. Only the
        function body is read, so they are never collected."""
        from training.corpus.sources.unixhelp import usage_text
        source = (
            "/*\n * Written by A Maintainer <someone@example.org>\n */\n"
            "static void usage(void)\n{\n"
            '  fputs(_(" %s [options]\\n"), out);\n}\n')
        text = usage_text(source)
        assert text is not None and "@" not in text

    def test_a_forward_declaration_is_not_a_definition(self):
        from training.corpus.sources.unixhelp import usage_text
        source = ("static void usage(FILE * out);\n"
                  "static void usage(FILE * out)\n{\n"
                  '  fputs(_(" real help\\n"), out);\n}\n')
        assert "real help" in usage_text(source)

    def test_a_usage_function_with_no_literals_yields_nothing(self):
        """GNU tar's usage() is four lines of argp and no help text, which is
        why tar is not among the upstreams."""
        from training.corpus.sources.unixhelp import usage_text
        source = ("usage (int status)\n{\n"
                  "  argp_help (&argp, stderr, ARGP_HELP_SEE, program_name);\n"
                  "  exit (status);\n}\n")
        assert usage_text(source) is None

    def test_a_file_with_no_usage_function_yields_nothing(self):
        from training.corpus.sources.unixhelp import usage_text
        assert usage_text("int main(void) { return 0; }") is None


class TestUnixHelpProgramName:
    """``%s`` is the program on a synopsis line and content everywhere else."""

    def test_a_labelled_synopsis_is_substituted(self):
        from training.corpus.sources.unixhelp import substitute_program_name
        out = substitute_program_name("Usage: %s [OPTION]... [FILE]...", "ls")
        assert out == "Usage: ls [OPTION]... [FILE]..."

    def test_an_or_continuation_is_substituted_too(self):
        """coreutils writes a utility's second synopsis without repeating the
        word "Usage", which left 260 raw ``%s`` in the first run's output."""
        from training.corpus.sources.unixhelp import substitute_program_name
        out = substitute_program_name("  or:  %s OPTION... NAME...", "basename")
        assert "basename OPTION" in out and "%s" not in out

    def test_a_bare_synopsis_with_an_option_grammar_is_substituted(self):
        """util-linux prints "Usage:" from a macro, so only `` %s [options]``
        survives extraction."""
        from training.corpus.sources.unixhelp import substitute_program_name
        out = substitute_program_name(" %s [options] [<device> ...]", "lsblk")
        assert out == " lsblk [options] [<device> ...]"

    def test_positional_specifiers_are_substituted(self):
        from training.corpus.sources.unixhelp import substitute_program_name
        out = substitute_program_name(" %1$s [-lhV]\n %1$s -a [options]", "mount")
        assert "%1$s" not in out and out.count("mount") == 2

    def test_dates_own_documentation_of_percent_s_is_left_alone(self):
        """The collision this rule exists for. ``date --help`` documents its
        format fields, and ``%s`` there means seconds since the epoch. Turning
        it into ``date`` would be a wrong gloss on the one utility most likely
        to be asked about it."""
        from training.corpus.sources.unixhelp import substitute_program_name
        line = "  %s   seconds since the Epoch (1970-01-01 00:00 UTC)"
        assert substitute_program_name(line, "date") == line

    def test_other_format_specifiers_are_never_rewritten(self):
        from training.corpus.sources.unixhelp import substitute_program_name
        line = "  %d   day of month\n  %14s  padded\n  %%   a literal percent"
        assert substitute_program_name(line, "date") == line

    def test_an_examples_block_substitutes_without_the_bracket_test(self):
        from training.corpus.sources.unixhelp import substitute_program_name
        text = ("Examples:\n"
                '  %s /usr/bin/sort          -> "sort"\n')
        out = substitute_program_name(text, "basename")
        assert 'basename /usr/bin/sort          -> "sort"' in out


class TestUnixHelpNaming:

    def test_the_file_stem_names_the_utility(self):
        from training.corpus.sources.unixhelp import utility_name
        assert utility_name("src/ls.c") == "ls"
        assert utility_name("misc-utils/lsblk.c") == "lsblk"

    def test_a_module_stem_defers_to_its_directory(self):
        """findutils keeps ``find``'s help in ``find/util.c``."""
        from training.corpus.sources.unixhelp import utility_name
        assert utility_name("find/util.c") == "find"

    def test_library_and_test_paths_are_not_utilities(self):
        from training.corpus.sources.unixhelp import _interesting
        assert _interesting(Path("src/ls.c"))
        assert not _interesting(Path("lib/xstrtol.c"))
        assert not _interesting(Path("tests/helpers/test_mkfds.c"))
        assert not _interesting(Path("libsmartcols/samples/tree.c"))
        assert not _interesting(Path("Documentation/boilerplate.c"))
        assert not _interesting(Path("src/ls.h"))


# ---------------------------------------------------------------------------
# The three SPECs, as the build sees them
# ---------------------------------------------------------------------------

_NAMES = ("cmdoutput", "busybox", "unixhelp")


class TestSpecs:

    @pytest.mark.parametrize("name", _NAMES)
    def test_discovered_by_the_build(self, name):
        from training.corpus.build import discover_sources

        assert name in {spec.name for spec in discover_sources()}

    @pytest.mark.parametrize("name", _NAMES)
    def test_declares_shell_register_and_a_licence(self, name):
        spec = importlib.import_module(
            f"training.corpus.sources.{name}").SPEC
        assert spec.name == name
        assert spec.register is Register.SHELL
        assert spec.side is Side.NEUTRAL
        assert spec.license.strip()
        assert spec.url.strip()
        assert spec.expect_min_docs >= 100

    @pytest.mark.parametrize("name", _NAMES)
    def test_declares_a_specific_licence_rather_than_a_guess(self, name):
        """``source.py`` refuses a blank licence; a vague one passes that check
        and fails the purpose. gtfobins is GPL-3.0 and not MIT, sigma is DRL-1.1
        and not MIT, and both were nearly declared wrong."""
        import importlib
        spec = importlib.import_module(
            f"training.corpus.sources.{name}").SPEC
        assert any(token in spec.license
                   for token in ("MIT", "GPL-2.0-only", "GPL-3.0", "SPDX"))
        # The claim has to be checkable against the download.
        assert "licens" in spec.license.lower()

    @pytest.mark.parametrize("name", _NAMES)
    def test_no_absolute_host_path_is_written_into_the_adapter(self, name):
        """A source module is published. A path off this machine in one is the
        same class of leak the corpus audit found 23,535 of."""
        module = importlib.import_module(f"training.corpus.sources.{name}")
        text = Path(module.__file__).read_text(encoding="utf-8")
        for needle in ("/Users/", "/Volumes/", str(Path.home())):
            assert needle not in text

    @pytest.mark.parametrize("name", _NAMES)
    def test_network_io_goes_through_the_shared_module(self, name):
        """One source of SSL contexts. Three copies of trust code is how one of
        them drifts into CERT_NONE during a late-night debugging session."""
        module = importlib.import_module(f"training.corpus.sources.{name}")
        text = Path(module.__file__).read_text(encoding="utf-8")
        assert "from ..net import" in text
        assert "urlopen" not in text
        assert "CERT_NONE" not in text
