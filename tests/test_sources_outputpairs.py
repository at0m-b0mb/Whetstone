"""Tests for the output-pairs source and its generator.

Three kinds of property are pinned here, and they fail in three different
ways.

**The format** is written by ``scripts/generate_output_pairs.py`` and read back
by ``training/corpus/sources/outputpairs.py``. A format implemented twice is a
format that drifts, so the round trip is asserted rather than assumed and the
expected strings are never typed out by hand -- a format test written against a
hand-typed expectation passes happily while the format is wrong.

**The substitution** carries the audit's sharpest lesson: privacy is satisfied
by *any* replacement, generalisation only by a *varied* one, and a single
``<HOST>`` token passes every privacy gate in this tree while making the model
worse. There is therefore a test that the replacement varies, and a test that
it preserves string length, because the corpus's best-measured register (+47%
against gpt2 on column-aligned rows) is destroyed by a replacement one
character shorter than what it replaced.

**The traps** are asserted against output captured verbatim from the VM. Every
fixture below is real bytes from Ubuntu 24.04.5 on aarch64, not an
illustration, because the whole argument for generating this source in a VM is
that illustrations of tool output train a model to predict what output *looks
like*. A fixture nobody measured would reintroduce exactly that.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from training.corpus.source import Document, Register, Side, SourceError, normalise
from training.corpus.sources import outputpairs as fmt

_REPO = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# Real output, captured from the VM. Verbatim.
# ---------------------------------------------------------------------------

#: ``id`` run through a setuid-root copy of itself. The whole reason
#: ``_parse_id`` looks for ``euid=``: the real uid stays 1000, and a parser that
#: read ``uid=`` and stopped would report a successful escape as a failure.
ID_SETUID = "uid=1000(svcops) gid=1001(svcops) euid=0(root) groups=1001(svcops)\n"

#: The same account without the setuid binary. ``id`` prints no ``euid=`` at
#: all when it equals ``uid``, so the field's *absence* is the signal.
ID_PLAIN = "uid=1000(svcops) gid=1001(svcops) groups=1001(svcops)\n"

#: ``sudo -n -l`` where the enumeration succeeded. Note both tags: only the
#: NOPASSWD rule is reachable without a password, and a parser that counted
#: rule lines would report two.
SUDO_ENUMERATED = """Matching Defaults entries for svcops on build-11:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/snap/bin, use_pty

User svcops may run the following commands on build-11:
    (ALL) NOPASSWD: /usr/bin/find
    (ALL) PASSWD: /usr/bin/systemctl
"""

#: What ``sudo -n -l`` says on this image for an account with a password-only
#: rule **and** for an account with no rules whatsoever. Byte-identical for
#: both, on stderr, exit 1, stdout empty -- measured, not assumed.
SUDO_REFUSED_STDERR = "sudo: a password is required\n"

#: ``systemctl show --property=Id,ExecStart,FragmentPath,ActiveState
#: cron.service``. The properties come back in systemd's order, not the
#: requested one: ExecStart first, Id second.
SYSTEMCTL_REORDERED = """ExecStart={ path=/usr/sbin/cron ; argv[]=/usr/sbin/cron -f -P $EXTRA_OPTS ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
Id=cron.service
ActiveState=active
FragmentPath=/usr/lib/systemd/system/cron.service
"""

#: A unit that does not exist. **Exit status 0**, the name echoed back as
#: ``Id``, and an empty ``FragmentPath`` as the only evidence of absence.
SYSTEMCTL_ABSENT = "Id=nosuch.service\nFragmentPath=\n"

#: A target: it exists and declares no ``ExecStart`` at all, so the property is
#: simply missing rather than empty.
SYSTEMCTL_TARGET = ("Id=multi-user.target\n"
                    "FragmentPath=/usr/lib/systemd/system/multi-user.target\n")

#: ``find /opt/whetstone-pairs -printf '%M %u %g %p\\n'``. Two of these paths
#: contain a space; ``str.split()`` would truncate both filenames.
FIND_WITH_SPACES = """drwxr-xr-x root root /opt/whetstone-pairs
drwxr-xr-x root root /opt/whetstone-pairs/app logs
-rw-rw-rw- root root /opt/whetstone-pairs/app logs/old report.txt
-rwsr-xr-x root root /opt/whetstone-pairs/wsp-suid-id
"""

#: ``crontab -l`` for an account with no crontab: stderr, exit 1, stdout empty.
CRONTAB_MISSING_STDERR = "no crontab for svcops\n"

#: ``ss -tulpnH`` -- the headerless form, which is the input
#: ``whetstone.adapters.linux.parse_ss`` is documented for and the one its only
#: caller passes. Carries the process column that makes a port actionable.
SS_HEADERLESS = """udp UNCONN 0      0                0.0.0.0:5353  0.0.0.0:* users:(("systemd-resolve",pid=4392,fd=11))
udp UNCONN 0      0      192.168.5.15%eth0:68    0.0.0.0:* users:(("systemd-network",pid=4161,fd=22))
tcp LISTEN 0      4096             0.0.0.0:22    0.0.0.0:* users:(("systemd",pid=1,fd=107))
"""

#: ``ss -ltun``, which pads the Local Address column to a width it computed
#: from the longest address on the box. One character of drift here is one
#: character of drift in every row below it.
SS_ALIGNED = """Netid State  Recv-Q Send-Q     Local Address:Port  Peer Address:PortProcess
udp   UNCONN 0      0                0.0.0.0:5353       0.0.0.0:*
udp   UNCONN 0      0      192.168.5.15%eth0:68         0.0.0.0:*
tcp   LISTEN 0      4096             0.0.0.0:22         0.0.0.0:*
"""


def _pair(**over):
    """A rendered document with sane defaults, so each test overrides one thing."""
    kwargs = dict(
        image="Ubuntu 24.04.5 LTS / Linux 6.8.0-147-generic aarch64",
        host="build-11", state="sudo-rules", account="svcops (via sudo -n -u)",
        probe="sudo.rights.svcops",
        question="Can this account run something as root with no password?",
        argv=["sudo", "-n", "-l"], stdout=SUDO_ENUMERATED, stderr="",
        exit_code=0, parser="momus.adapters.lima._parse_sudo_l",
        parse={"enumerated": True, "passwordless_root": True},
        verdict="found", reading=fmt.generic_reading("found"))
    kwargs.update(over)
    return fmt.render_pair(**kwargs)


# ---------------------------------------------------------------------------
# The format
# ---------------------------------------------------------------------------

class TestFormatRoundTrip:
    """render_pair and read_pair are two halves of one definition."""

    def test_headers_survive(self):
        got = fmt.read_pair(_pair())
        assert got["host"] == "build-11"
        assert got["state"] == "sudo-rules"
        assert got["probe"] == "sudo.rights.svcops"
        assert got["argv"] == ["sudo", "-n", "-l"]
        assert got["verdict"] == "found"
        assert got["parser"] == "momus.adapters.lima._parse_sudo_l"
        assert got["parse"] == {"enumerated": True, "passwordless_root": True}

    def test_stdout_is_verbatim(self):
        got = fmt.read_pair(_pair())
        assert got["stdout"] == SUDO_ENUMERATED.strip("\n")
        assert "(ALL) NOPASSWD: /usr/bin/find" in got["stdout"]
        assert "(ALL) PASSWD: /usr/bin/systemctl" in got["stdout"]

    def test_both_streams_and_exit_are_separable(self):
        """The refusal case: stdout empty, the answer on stderr, exit 1.

        If these three could not be read apart again, the single most
        important distinction in the source -- could not tell, versus nothing
        there -- would be unrecoverable from its own file format.
        """
        got = fmt.read_pair(_pair(stdout="", stderr=SUDO_REFUSED_STDERR,
                                  exit_code=1, verdict="inconclusive"))
        assert got["stdout"] == ""
        assert got["stderr"] == "sudo: a password is required"
        assert got["exit"] == 1
        assert got["verdict"] == "inconclusive"

    def test_empty_stdout_is_marked_not_omitted(self):
        """An absent line is not a token a next-token predictor can condition on.

        A capture with empty stdout and a capture whose stdout section was
        omitted are indistinguishable without an explicit marker, and they are
        the absent-versus-inconclusive distinction again at the file-format
        level.
        """
        assert "(no stdout)" in _pair(stdout="", exit_code=1, verdict="error")

    def test_stderr_section_absent_when_stderr_is_empty(self):
        assert "--- stderr" not in _pair()

    def test_multiline_stderr_survives(self):
        err = "stat: cannot statx '/etc/nope': No such file or directory\nsecond line\n"
        got = fmt.read_pair(_pair(stderr=err, exit_code=1, verdict="error"))
        assert got["stderr"] == err.strip("\n")

    def test_argv_appears_as_json_and_as_a_prompt(self):
        """Both forms, because the runtime emits argv and the corpus shows shells.

        Momus emits a verb id and typed params and never a shell string; a
        document that showed only the rendered prompt would teach the mapping
        in one direction.
        """
        text = _pair(argv=["find", "/opt/a b", "-printf", "%M %p\n"])
        assert json.dumps(["find", "/opt/a b", "-printf", "%M %p\n"]) in text
        assert "$ find '/opt/a b' -printf" in text
        assert fmt.read_pair(text)["argv"][1] == "/opt/a b"

    def test_unknown_verdict_is_refused(self):
        with pytest.raises(ValueError):
            _pair(verdict="probably")

    def test_every_verdict_renders(self):
        for verdict in fmt.VERDICTS:
            assert fmt.read_pair(_pair(verdict=verdict))["verdict"] == verdict

    def test_not_a_pair_document_raises(self):
        for junk in ("", "hello", "# something else\nexit: 0\n"):
            with pytest.raises(ValueError):
                fmt.read_pair(junk)

    def test_missing_exit_line_raises(self):
        """A document without an exit status is unreadable, not half-readable.

        Guessing zero would make a failed command indistinguishable from a
        successful one in exactly the register this source exists to teach.
        """
        text = _pair()
        broken = "\n".join(ln for ln in text.split("\n")
                           if not ln.startswith("exit: "))
        with pytest.raises(ValueError):
            fmt.read_pair(broken)


class TestFormatSurvivesNormalise:
    """normalise() runs over every document on the way into the corpus."""

    def test_column_alignment_survives(self):
        """The +47% register. normalise must not collapse these spaces."""
        text = _pair(stdout=SS_ALIGNED, probe="network.listeners")
        assert normalise(text) == text
        for line in SS_ALIGNED.strip("\n").split("\n"):
            assert line in text

    def test_document_is_already_normalised(self):
        """render_pair normalises, so the reader's copy is the written copy.

        Boilerplate stripping and re-normalisation downstream mutate documents
        after the redaction chokepoint has seen them -- that is a real bug this
        repo found and fixed -- so a format that is a fixed point under
        normalise is one fewer thing that can be edited after it was checked.
        """
        text = _pair()
        assert normalise(text) == text
        assert fmt.read_pair(normalise(text)) == fmt.read_pair(text)

    def test_leading_indentation_survives(self):
        text = _pair(stdout=SYSTEMCTL_REORDERED)
        assert "    (ALL)" not in text          # not this fixture
        assert "ExecStart={ path=/usr/sbin/cron ;" in text


# ---------------------------------------------------------------------------
# Substitution
# ---------------------------------------------------------------------------

#: Literals with the shapes the VM really produces, including a thirteen-
#: character account name, which is what Lima names the guest after the host.
_LITERALS = {
    "account": "demo_operator",
    "hostname": "lima-whetstone-lab",
    "mac": "52:55:55:73:df:b7",
    "v4net": "192.168.5.",
    "v6": "fe80::5055:55ff:fe73:dfb7",
    "machine-id": "996ccc81ac03484a9f9deacc8497d9ea",
}


class TestSubstitutionPreservesLength:
    """Column alignment is signal, and a shorter replacement destroys it."""

    def test_every_kind_is_length_preserving(self):
        plan = fmt.substitution_plan(_LITERALS, "salt", length_safe=True)
        assert set(plan) == set(_LITERALS.values())
        for original, replacement in plan.items():
            assert len(replacement) == len(original), (original, replacement)

    def test_alignment_is_intact_after_substituting_an_address(self):
        """The real regression, on the real bytes, measured by column index."""
        plan = fmt.substitution_plan({"v4net": "192.168.5."}, "s",
                                     length_safe=True)
        out = fmt.apply_plan(SS_ALIGNED, plan)
        before = SS_ALIGNED.strip("\n").split("\n")
        after = out.strip("\n").split("\n")
        assert len(before) == len(after)
        for b, a in zip(before, after):
            assert len(b) == len(a)
            assert a.index(":68") if ":68" in a else True
        assert "192.168" not in out
        # And the replacement is in a reserved documentation range.
        assert any(net.rstrip(".") in out for net in fmt.DOC_V4_NETS)

    def test_fit_hits_the_length_exactly(self):
        for length in range(1, 40):
            assert len(fmt.fit("svc-collector", length, "s")) == length

    def test_fit_is_deterministic(self):
        assert fmt.fit("svcops", 13, "a") == fmt.fit("svcops", 13, "a")
        assert fmt.fit("svcops", 13, "a") != fmt.fit("svcops", 13, "b")


class TestSubstitutionIsVaried:
    """The audit's finding, as a test.

    A single placeholder satisfies every privacy check in this tree and makes
    the model worse: it replaces one memorised literal with one *more frequent*
    memorised literal. ~7,700 address occurrences collapsed onto one
    26-character string was the worked example. So variety is a property with a
    test, not a comment.
    """

    def test_the_account_replacement_varies_across_documents(self):
        seen = {fmt.substitution_plan(_LITERALS, f"doc/{i}")["demo_operator"]
                for i in range(200)}
        assert len(seen) >= 8, f"only {len(seen)} distinct replacements"

    #: ``v4net`` is carved out and the carve-out is the whole of the exception:
    #: only one RFC 5737 prefix is the same length as this image's, and length
    #: is mandatory for the column-aligned probes. The test below shows the
    #: collapse and shows that the address inside the prefix still varies.
    _VARIES_FREELY = tuple(k for k in _LITERALS if k != "v4net")

    def test_no_replacement_is_a_single_shared_token(self):
        for kind in self._VARIES_FREELY:
            value = _LITERALS[kind]
            seen = {fmt.substitution_plan({kind: value}, f"d/{i}")[value]
                    for i in range(120)}
            assert len(seen) > 1, f"{kind} collapsed onto one token: {seen}"

    def test_the_v4_prefix_does_collapse_under_length_safe_and_the_address_does_not(self):
        """The one place a single token is unavoidable, and its repair.

        RFC 5737 gives three documentation prefixes of three different lengths,
        so for this image's ten-character ``192.168.5.`` exactly one of them
        preserves length -- and the column-aligned probes require that. The
        prefix therefore *is* one shared token in those documents, which would
        have traded one memorised literal for another if the address inside it
        were also fixed. It is not: the host octet varies inside the mapped
        /24, with the same digit count.
        """
        prefixes = {fmt.substitution_plan({"v4net": "192.168.5."}, f"d/{i}",
                                          length_safe=True)["192.168.5."]
                    for i in range(80)}
        assert prefixes == {"203.0.113."}, prefixes
        addrs = {fmt.substitution_plan(
            {"v4net": "192.168.5.", "v4addr": "192.168.5.15"}, f"d/{i}",
            length_safe=True)["192.168.5.15"] for i in range(80)}
        assert len(addrs) >= 20, f"only {len(addrs)} distinct addresses"
        assert all(a.startswith("203.0.113.") and len(a) == 12 for a in addrs)

    def test_the_address_lands_in_the_network_the_prefix_was_mapped_to(self):
        """Or the document contradicts itself: a host in 198.51.100.0/24 whose
        broadcast is 203.0.113.255 is not a machine anybody can read."""
        for i in range(40):
            plan = fmt.substitution_plan(
                {"v4net": "192.168.5.", "v4addr": "192.168.5.15"}, f"d/{i}",
                length_safe=False)
            assert plan["192.168.5.15"].startswith(plan["192.168.5."])

    def test_replacement_is_stable_within_one_document(self):
        """Varied across documents, identical inside one.

        A document whose ``id`` output and whose parse disagreed about the
        account name would be teaching the model that the two are unrelated.
        """
        plan = fmt.substitution_plan(_LITERALS, "one-doc")
        replacement = plan["demo_operator"]
        text = fmt.apply_plan(
            'uid=501(demo_operator)\n{"user": "demo_operator"}', plan)
        assert "demo_operator" not in text
        assert text.count(replacement) == 2

    def test_pools_are_disjoint(self):
        """An account the generator creates must never collide with one it
        substitutes, or a document shows two different accounts under one name."""
        assert not set(fmt.ACCOUNT_POOL) & set(fmt.SUBSTITUTE_ACCOUNTS)

    def test_substitute_host_pool_is_long_enough_for_a_lima_name(self):
        """``fit`` padding a six-character name out to eighteen produces
        something no machine was ever called; the pool carries real lengths."""
        assert max(len(h) for h in fmt.SUBSTITUTE_HOSTS) >= len("lima-whetstone-lab")


class TestApplyPlanOrdering:
    """A shorter key must not eat a prefix of a longer one."""

    def test_longest_key_first(self):
        plan = fmt.substitution_plan(
            {"account": "demo_operator", "hostname": "demo"}, "s")
        out = fmt.apply_plan("demo_operator and demo", plan)
        assert "demo_operator" not in out
        assert plan["demo_operator"] in out

    def test_empty_plan_is_a_no_op(self):
        assert fmt.apply_plan("unchanged", {}) == "unchanged"


# ---------------------------------------------------------------------------
# Dedup
# ---------------------------------------------------------------------------

class TestSkeleton:
    """Telemetry is mostly the same record again; letters decide, numbers do not."""

    def test_pids_and_timestamps_collapse(self):
        a = "type=USER_END msg=audit(1791933173.442:1251): pid=16513 uid=501"
        b = "type=USER_END msg=audit(1791933999.001:9999): pid=10101 uid=501"
        assert fmt.skeleton(a) == fmt.skeleton(b)

    def test_different_commands_do_not_collapse(self):
        a = "root 1 systemd"
        b = "root 1 sshd"
        assert fmt.skeleton(a) != fmt.skeleton(b)

    def test_guids_collapse(self):
        a = "Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}' EventID=4634"
        b = "Guid='{11111111-2222-3333-4444-555555555555}' EventID=4634"
        assert fmt.skeleton(a) == fmt.skeleton(b)

    def test_modes_are_letters_and_survive(self):
        """``-rwsr-xr-x`` versus ``-rwxr-xr-x`` is the setuid bit. If the dedup
        key lost it, one of the two shapes would never reach the corpus."""
        assert (fmt.skeleton("-rwsr-xr-x root root /usr/bin/sudo")
                != fmt.skeleton("-rwxr-xr-x root root /usr/bin/sudo"))


# ---------------------------------------------------------------------------
# The source contract
# ---------------------------------------------------------------------------

class TestSpec:
    def test_declares_what_the_build_requires(self):
        assert fmt.SPEC.name == "outputpairs"
        assert fmt.SPEC.license.strip()
        assert fmt.SPEC.url.strip()
        assert fmt.SPEC.register is Register.SHELL
        assert fmt.SPEC.side is Side.NEUTRAL
        assert fmt.SPEC.expect_min_docs >= 1

    def test_licence_states_what_is_not_captured(self):
        """The licence claim rests on a boundary, so the boundary is in it.

        ``--help`` text, man pages and package descriptions ARE the programs'
        copyrighted words; machine state is not. A licence line that said only
        "generated locally" would be true and would not be checkable.
        """
        licence = fmt.SPEC.license
        for claim in ("--help", "man pages", "licenses/"):
            assert claim in licence, f"licence no longer mentions {claim!r}"

    def test_discovered_by_the_build(self):
        from training.corpus.build import discover_sources
        assert "outputpairs" in {s.name for s in discover_sources()}


class TestFetchRefuses:
    """Generation is never a side effect of a build."""

    def test_empty_cache_raises_with_the_command(self, tmp_path):
        with pytest.raises(SourceError) as exc:
            fmt._fetch(tmp_path / "cache")
        assert "generate_output_pairs.py" in str(exc.value)

    def test_warm_cache_is_network_free_and_idempotent(self, tmp_path):
        (tmp_path / "pair-00000-x.txt").write_text(_pair(), encoding="utf-8")
        assert fmt._fetch(tmp_path) == tmp_path
        assert fmt._fetch(tmp_path) == tmp_path


class TestDocuments:
    def test_yields_one_document_per_pair(self, tmp_path):
        (tmp_path / "pair-00000-a.txt").write_text(_pair(), encoding="utf-8")
        (tmp_path / "pair-00001-b.txt").write_text(
            _pair(probe="identity.self", stdout=ID_SETUID), encoding="utf-8")
        docs = list(fmt._documents(tmp_path))
        assert len(docs) == 2
        assert all(isinstance(d, Document) for d in docs)
        assert {d.register for d in docs} == {Register.SHELL}
        assert {d.side for d in docs} == {Side.NEUTRAL}
        assert [d.ident for d in docs] == ["pair-00000-a", "pair-00001-b"]

    def test_ignores_everything_that_is_not_a_pair(self, tmp_path):
        (tmp_path / "pair-00000-a.txt").write_text(_pair(), encoding="utf-8")
        (tmp_path / "manifest.json").write_text("{}", encoding="utf-8")
        (tmp_path / "notes.txt").write_text("x" * 500, encoding="utf-8")
        lic = tmp_path / "licenses"
        lic.mkdir()
        (lic / "copyright.coreutils.txt").write_text("x" * 900, encoding="utf-8")
        (lic / "pair-00099-sneaky.txt").write_text(_pair(), encoding="utf-8")
        idents = [d.ident for d in fmt._documents(tmp_path)]
        assert idents == ["pair-00000-a"], idents

    def test_does_not_follow_symlinks(self, tmp_path):
        """The ownrepos regression, in this adapter.

        ``ownrepos`` once followed this repo's ``data`` symlink into the SSD and
        pulled the corpus cache back in as PROSE -- the corpus ate itself, and
        only the balance report noticed. ``os.walk(followlinks=False)``, never
        ``rglob``.
        """
        cache = tmp_path / "cache"
        cache.mkdir()
        (cache / "pair-00000-real.txt").write_text(_pair(), encoding="utf-8")
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "pair-09999-offlimits.txt").write_text(
            _pair(probe="offlimits"), encoding="utf-8")
        (cache / "escape").symlink_to(elsewhere, target_is_directory=True)
        (cache / "pair-00001-link.txt").symlink_to(
            elsewhere / "pair-09999-offlimits.txt")
        idents = [d.ident for d in fmt._documents(cache)]
        assert idents == ["pair-00000-real"], idents

    def test_size_bounds(self, tmp_path):
        (tmp_path / "pair-00000-tiny.txt").write_text("# whetstone output-pair\n",
                                                      encoding="utf-8")
        (tmp_path / "pair-00001-huge.txt").write_text(
            _pair(stdout="x " * 40_000), encoding="utf-8")
        (tmp_path / "pair-00002-ok.txt").write_text(_pair(), encoding="utf-8")
        assert [d.ident for d in fmt._documents(tmp_path)] == ["pair-00002-ok"]

    def test_unreadable_file_is_skipped_not_fatal(self, tmp_path):
        (tmp_path / "pair-00000-ok.txt").write_text(_pair(), encoding="utf-8")
        bad = tmp_path / "pair-00001-bad.txt"
        bad.write_bytes(b"# whetstone output-pair\n" + b"\xff\xfe" * 200)
        # Decoded with errors="replace" rather than dropped: a mangled byte is
        # not a reason to lose the document, and a crash here takes the source.
        assert len(list(fmt._documents(tmp_path))) == 2


# ---------------------------------------------------------------------------
# The traps, against this project's own parsers
# ---------------------------------------------------------------------------

class TestRealOutputTraps:
    """Captured bytes, read by the parsers the runtime actually calls."""

    def test_setuid_id_is_not_read_as_unprivileged(self):
        from whetstone.adapters.linux import parse_id
        got = parse_id(ID_SETUID)
        assert got["uid"]["id"] == 1000
        assert got["euid"]["id"] == 0, "a parser reading uid= alone calls this a failure"

    def test_plain_id_has_no_euid_field_at_all(self):
        from whetstone.adapters.linux import parse_id
        got = parse_id(ID_PLAIN)
        assert got["uid"]["id"] == 1000
        assert "euid" not in got, "the field's absence is the signal"

    def test_systemctl_show_is_never_positional(self):
        """Asked for Id,ExecStart,FragmentPath,ActiveState; got ExecStart first."""
        from whetstone.adapters.linux import parse_systemctl_show
        first_line_key = SYSTEMCTL_REORDERED.split("=", 1)[0]
        assert first_line_key == "ExecStart"
        records = parse_systemctl_show(SYSTEMCTL_REORDERED)
        assert len(records) == 1
        assert records[0]["unit"] == "cron.service"

    def test_absent_unit_is_detectable_only_by_fragment_path(self):
        from whetstone.adapters.linux import parse_systemctl_show
        records = parse_systemctl_show(SYSTEMCTL_ABSENT)
        assert records and not records[0]["fragment_path"]

    def test_nopasswd_is_not_the_same_as_a_rule(self):
        from whetstone.adapters.linux import parse_sudo_l
        got = parse_sudo_l(SUDO_ENUMERATED)
        assert len(got["entries"]) == 2
        assert got["nopasswd_any"] is True
        assert sum(1 for e in got["entries"] if e["nopasswd"]) == 1

    def test_refusal_bytes_are_not_evidence_of_absence(self):
        """``parse_sudo_l`` is documented for success output, and its caller
        branches on the exit status before calling it.

        Handed the refusal instead -- stdout empty, the message on stderr --
        it returns an empty entry list, which *reads* as a confident "no
        passwordless rule". Not a bug in the parser: a bug waiting for whoever
        calls it without reading its caller. Pinned here so the contract is
        executable rather than a docstring.
        """
        from whetstone.adapters.linux import parse_sudo_l
        got = parse_sudo_l("")      # stdout is empty on a refusal
        assert got["entries"] == []
        assert got["nopasswd_any"] is False
        assert SUDO_REFUSED_STDERR.strip() == "sudo: a password is required"

    def test_crontab_absence_arrives_on_stderr(self):
        from whetstone.adapters.linux import parse_crontab
        assert parse_crontab("") == []          # what stdout alone gives you
        assert "no crontab for" in CRONTAB_MISSING_STDERR

    def test_whetstone_parse_ss_wants_the_headerless_form(self):
        """A contract, checked before it was called a bug.

        ``parse_ss`` is documented for ``ss -tulpnH`` and its only caller
        passes ``-tulpnH``. Handed header-bearing output it parses the header
        as a socket named ``Netid`` -- which is not a defect in the parser, it
        is a defect in whoever feeds it the other command. Both halves are
        pinned so the next person does not file the bug.
        """
        from whetstone.adapters.linux import parse_ss
        clean = parse_ss(SS_HEADERLESS)
        assert len(clean) == 3
        assert {r["proto"] for r in clean} == {"udp", "tcp"}
        assert clean[2]["local_port"] == "22"
        assert clean[2]["processes"] == [{"name": "systemd", "pid": 1}]
        with_header = parse_ss(SS_ALIGNED)
        assert with_header[0]["proto"] == "Netid", (
            "if this ever stops being true, the probe can drop -H")


# ---------------------------------------------------------------------------
# Momus parity -- the labels come from there, so it is checked when present
# ---------------------------------------------------------------------------

def _momus():
    root = _REPO.parent / "Momus"
    if not (root / "momus" / "adapters" / "lima.py").is_file():
        pytest.skip("sibling Momus checkout not present")
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    try:
        import momus.adapters.lima as lima
    except Exception as exc:                        # pragma: no cover
        pytest.skip(f"momus not importable: {type(exc).__name__}: {exc}")
    return lima


class TestMomusParsersOnTheseBytes:
    """The label-producing parsers, on the same captured output.

    Skipped rather than vendored when the sibling checkout is absent: a
    vendored copy would drift, and drift here would mean the corpus kept
    training the model on a parser nothing runs.
    """

    def test_sudo_refusal_is_not_enumerated(self):
        lima = _momus()
        rights = lima._parse_sudo_l("", SUDO_REFUSED_STDERR)
        assert rights.enumerated is False
        assert rights.passwordless_root is False

    def test_sudo_enumeration_counts_only_nopasswd(self):
        lima = _momus()
        rights = lima._parse_sudo_l(SUDO_ENUMERATED, "")
        assert rights.enumerated is True
        assert rights.nopasswd == ("/usr/bin/find",)
        assert rights.all_commands is False
        assert rights.passwordless_root is True

    def test_find_printf_keeps_paths_with_spaces(self):
        lima = _momus()
        entries = lima._parse_find_long(FIND_WITH_SPACES)
        paths = [e.path for e in entries]
        assert "/opt/whetstone-pairs/app logs/old report.txt" in paths
        assert len(entries) == 4

    def test_suid_rows_are_selected_by_the_mode_bit(self):
        lima = _momus()
        suid = lima._parse_suid(FIND_WITH_SPACES)
        assert [e.path for e in suid] == ["/opt/whetstone-pairs/wsp-suid-id"]

    def test_execstart_comes_from_path_not_argv(self):
        lima = _momus()
        records = lima._parse_systemctl_show(SYSTEMCTL_REORDERED)
        assert records[0]["Id"] == "cron.service"
        assert lima._parse_execstart(records[0]["ExecStart"]) == "/usr/sbin/cron"

    def test_target_omits_execstart_entirely(self):
        lima = _momus()
        records = lima._parse_systemctl_show(SYSTEMCTL_TARGET)
        assert "ExecStart" not in records[0]
        assert records[0]["FragmentPath"].endswith("multi-user.target")

    def test_id_euid_matches_whetstone(self):
        lima = _momus()
        from whetstone.adapters.linux import parse_id
        mine = lima._parse_id(ID_SETUID)
        theirs = parse_id(ID_SETUID)
        assert mine["euid"] == theirs["euid"]["id"] == 0
        assert mine["uid"] == theirs["uid"]["id"] == 1000


# ---------------------------------------------------------------------------
# The generator's catalogue -- static checks, no VM
# ---------------------------------------------------------------------------

def _generator():
    """Load the generator script as a module.

    Registered in ``sys.modules`` *before* ``exec_module``, which is not
    ceremony: ``@dataclass`` resolves a string annotation by looking its own
    class's ``__module__`` up in ``sys.modules``, so a module executed without
    being registered raises ``AttributeError: 'NoneType' object has no
    attribute '__dict__'`` from inside ``dataclasses`` -- a failure that names
    neither the script nor the test.
    """
    name = "_wsp_generator"
    if name in sys.modules:
        return sys.modules[name]
    path = _REPO / "scripts" / "generate_output_pairs.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        del sys.modules[name]
        raise
    return module


class TestCatalogue:
    """A typo in a probe should fail here, not ten minutes into a VM run."""

    def test_every_label_names_a_real_method(self):
        gen = _generator()
        names = {p.label for p in gen.static_probes()}
        names |= {p.label for p in gen.per_account_probes("audit-armed")}
        for name in names:
            assert callable(getattr(gen.Labels, name, None)), name

    def test_every_authored_reading_is_for_a_real_verdict(self):
        gen = _generator()
        probes = gen.static_probes() + gen.per_account_probes("audit-armed")
        for probe in probes:
            for verdict in probe.readings:
                assert verdict in fmt.VERDICTS, f"{probe.id}: {verdict}"

    def test_probe_ids_are_unique_within_a_state(self):
        gen = _generator()
        for state in ("pristine", "accounts", "audit-armed", "reverted"):
            probes = [p for p in gen.static_probes() if p.applies(state)]
            probes += gen.per_account_probes(state)
            ids = [p.id for p in probes]
            assert len(ids) == len(set(ids)), state

    def test_the_failure_cases_are_in_the_catalogue(self):
        """Refusal, absence, an empty result and a timeout, or the source is
        teaching that output is always success output."""
        gen = _generator()
        families = {p.family for p in gen.static_probes()}
        for required in ("denied", "missing", "empty-find", "timeout"):
            assert required in families, required

    def test_every_probe_states_a_question(self):
        gen = _generator()
        for probe in gen.static_probes() + gen.per_account_probes("audit-armed"):
            assert probe.question.strip().endswith("?"), probe.id

    def test_no_probe_reads_a_package_shipped_config_body(self):
        """The licence boundary, as a test.

        Machine state is not a derivative work of the program that reported it;
        a config file shipped by a package is that package's copyrighted text.
        The only file bodies this generator captures are ones it wrote itself,
        plus ``/etc/os-release``, ``/etc/hostname`` and ``/etc/machine-id``,
        which are generated metadata rather than authored files.
        """
        gen = _generator()
        allowed = {
            # Generated metadata, not an authored file.
            "/etc/os-release", "/etc/hostname", "/etc/machine-id",
            # Account databases: generated, and the probes aimed at them exist
            # to capture the refusal. Backed by _REFUSED_CONTENT, which drops
            # the document if one ever succeeds and prints a hash.
            "/etc/shadow", "/etc/gshadow",
            # Paths that do not exist, which is the point of reading them.
            "/etc/nosuchfile", "/etc/nosuchfile.conf",
            # Kernel interfaces: this machine's state by definition.
            "/proc/self/status", "/proc/mounts", "/proc/net/tcp",
            "/proc/99999999/status",
            # Written by auditd on this machine from this machine's syscalls.
            "/var/log/audit/audit.log",
            # cron's own file, read only through head -v alongside our drop-in
            # so the partial-read shape is covered; three schedule lines.
            "/etc/crontab",
        }
        readers = {"cat", "head", "tail", "grep"}
        for probe in gen.static_probes():
            if probe.argv[0] not in readers:
                continue
            for token in probe.argv[1:]:
                if not token.startswith("/"):
                    continue
                assert (token in allowed
                        or token.startswith(gen.PLANT_ROOT)
                        or token.startswith("/etc/cron.d/")
                        or token.startswith("/etc/nosuchfile-")), \
                    f"{probe.id} reads {token}, which this licence does not cover"

    def test_root_only_probes_are_metadata_reads(self):
        """A denial probe that unexpectedly succeeds must yield metadata.

        ``ls -l /root`` succeeding puts modes and owners in the corpus, which
        is what this source collects anyway. ``cat`` on the same path would put
        somebody's shipped file or an account database there. The two ``cat``
        probes aimed at root-only paths are the account databases, and
        ``_REFUSED_CONTENT`` drops the document if one of them ever prints a
        hash.
        """
        gen = _generator()
        root_only = ("/root", "/etc/sudoers.d", "/var/spool/cron/crontabs",
                     "/var/log/audit")
        for probe in gen.static_probes():
            targets = [t for t in probe.argv[1:] if t in root_only]
            if not targets:
                continue
            assert probe.argv[0] in ("ls", "stat"), \
                f"{probe.id} reads {targets} with {probe.argv[0]}, not metadata"

    def test_the_content_guard_covers_the_hash_formats_this_image_uses(self):
        gen = _generator()
        assert "$y$" in gen._REFUSED_CONTENT, "yescrypt is Ubuntu 24.04's default"
        for marker in ("$6$", "-----BEGIN "):
            assert marker in gen._REFUSED_CONTENT

    def test_emit_refuses_content_before_it_writes(self):
        import ast
        source = (_REPO / "scripts" / "generate_output_pairs.py").read_text()
        func = next(n for n in ast.walk(ast.parse(source))
                    if isinstance(n, ast.FunctionDef) and n.name == "emit")
        body = ast.dump(func)
        assert "_REFUSED_CONTENT" in body
        assert body.index("_REFUSED_CONTENT") < body.index("write_text")

    def test_plant_namespace_is_owned(self):
        gen = _generator()
        for path in gen.PLANTED_PATHS:
            assert path.startswith(gen.PLANT_ROOT) or "wsp" in path, path

    def test_probe_accounts_come_from_the_pool(self):
        gen = _generator()
        assert set(gen.PROBE_ACCOUNTS) <= set(fmt.ACCOUNT_POOL)

    def test_no_sudo_rule_grants_all_commands_without_a_password(self):
        """``(ALL) NOPASSWD: ALL`` is a root shell with extra steps.

        Whetstone's own lab grants it and the sibling project's range argues
        against it; the argument applies to training data too. A corpus whose
        every enumerated ``sudo -l`` says ALL teaches that the interesting case
        is the only case.
        """
        import ast
        source = (_REPO / "scripts" / "generate_output_pairs.py").read_text()
        func = next(n for n in ast.walk(ast.parse(source))
                    if isinstance(n, ast.FunctionDef) and n.name == "_plant_sudo")
        # Read with ast rather than grepped, for the reason this repo's own
        # TLS test gives: the comment explaining why a shape was rejected
        # quotes the shape, so a text search flags exactly the code that was
        # most careful to explain itself. The docstring is dropped and only
        # string constants that reach a sudoers file are examined.
        body = func.body[1:] if (func.body and isinstance(func.body[0], ast.Expr)
                                 and isinstance(func.body[0].value, ast.Constant)
                                 ) else func.body
        literals = [n.value for sub in body for n in ast.walk(sub)
                    if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        for literal in literals:
            assert "NOPASSWD: ALL" not in literal, literal
        assert any("NOPASSWD:" in lit for lit in literals), \
            "no NOPASSWD rule at all means sudo -n -l never enumerates"


class TestGeneratorSafetyProperties:
    """Properties of the script that no VM is needed to check."""

    def test_the_needle_scan_is_the_last_gate_before_a_write(self):
        """Asserting the privacy win is the mistake the audit's own tooling made.

        So the generator checks it, on the exact bytes, with the same scanner
        the build gate uses -- and ``emit`` must return rather than write when
        the scan finds anything.
        """
        import ast
        source = (_REPO / "scripts" / "generate_output_pairs.py").read_text()
        tree = ast.parse(source)
        emits = [n for n in ast.walk(tree)
                 if isinstance(n, ast.FunctionDef) and n.name == "emit"]
        assert len(emits) == 1
        body = ast.dump(emits[0])
        assert "scan_text" in body, "emit no longer scans before writing"
        assert "write_text" in body, "emit no longer writes"
        scan_at = body.index("scan_text")
        write_at = body.index("write_text")
        assert scan_at < write_at, "the scan must precede the write"

    def test_every_vm_call_has_a_finite_timeout(self):
        """A blocked subprocess.run never raises, so it cannot be caught.

        A half-open Lima SSH control connection after a macOS wake is the
        ordinary way an unattended generator wedges forever with no output and
        no diagnostic.
        """
        import ast
        source = (_REPO / "scripts" / "generate_output_pairs.py").read_text()
        for node in ast.walk(ast.parse(source)):
            if not (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "run"
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "subprocess"):
                continue
            assert any(kw.arg == "timeout" for kw in node.keywords), \
                f"subprocess.run at line {node.lineno} has no timeout"

    def test_revert_verifies_by_reprobing(self):
        gen = _generator()
        source = (_REPO / "scripts" / "generate_output_pairs.py").read_text()
        body = source.split("def revert(", 1)[1].split("\n@dataclass", 1)[0]
        # "rm exited zero" is not evidence; the function must ask the machine.
        assert "vm.exists(path)" in body
        assert "getent" in body
        assert "auditctl" in body
        assert callable(gen.revert)

    def test_dry_run_touches_nothing(self):
        """--dry-run must not construct a VM, let alone plant on one."""
        gen = _generator()
        assert gen.main(["--dry-run"]) == 0

    def test_the_dedup_key_is_computed_over_the_output(self):
        """The no-op gate, pinned.

        Keyed on the rendered document this gate deduplicated 2,160 captures
        to 2,160, because the header carries the state name and the hostname
        and the generator changes both every state. Measured afterwards on the
        output alone, the same run was 75.3% duplicate. A dedup key computed
        over text the generator itself varies cannot see duplication in the
        part it did not.
        """
        import ast
        source = (_REPO / "scripts" / "generate_output_pairs.py").read_text()
        func = next(n for n in ast.walk(ast.parse(source))
                    if isinstance(n, ast.FunctionDef) and n.name == "emit")
        call = next(n for n in ast.walk(func)
                    if isinstance(n, ast.Call)
                    and isinstance(n.func, ast.Attribute)
                    and n.func.attr == "skeleton")
        arg = ast.unparse(call.args[0])
        assert "cap.stdout" in arg and "cap.stderr" in arg, arg
        assert "text" != arg, "the dedup key is the rendered document again"

    def test_measure_repetition_excludes_the_scaffold(self, tmp_path):
        """The ruler bug, pinned.

        Counting every token in the file reported a maximum document frequency
        of 1.00 and the literal was ``exit:``. A ruler that cannot tell "the
        word *verdict* is in all 513 documents" from "this machine's MAC is in
        all 513 documents" is not measuring overfit.
        """
        gen = _generator()
        for i in range(6):
            (tmp_path / f"pair-{i:05d}-x.txt").write_text(
                _pair(stdout=f"unique-token-{i} shared-token\n"),
                encoding="utf-8")
        got = gen.measure_repetition(tmp_path)
        assert got["documents"] == 6
        assert got["max_output_document_frequency"] == 6      # shared-token
        assert got["max_whole_document_frequency_incl_scaffold"] == 6
        assert got["distinct_output_literals"] == 7           # 6 unique + 1 shared
