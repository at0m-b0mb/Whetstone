"""Tests for the instrument that reads the finished corpus.

``training/corpus/verify.py`` is 1,893 lines that exist because nothing ever
read the artifact. Every finding in the audit that produced it was the absence
of a pass over the output: a redactor whose fix postdated the corpus by twenty
days, a ``clean-v8`` that was a symlink to ``clean-v7``, a refusal inside
``build()`` that truncated a source and wrote its prefix to disk anyway. The
module is the pass that was missing.

An untested instrument is worse than no instrument, because it is quoted. This
codebase has already paid for that three times, and all three times the ruler
was wrong and the model was accused: a validation split that was 100% one
source (val ppl 626 -> 90 with no model change), a non-greedy regex that
truncated valid JSON and called it malformed, and length normalisation that
destroyed a closed-set ranking signal. **Check the instrument first.**
This file is that check, turned on the checker.

Four properties are load-bearing and the rest of the file is detail:

**It cannot leak.** The audit that found the leaks became one: six of its own
working files wrote live MAC addresses, global IPv6 addresses and an email
address to disk as cleartext while the report claimed otherwise. So the first
class here walks every accidental way a value escapes a Python object --
``repr``, ``str``, ``format``, ``vars``, ``__dict__``, ``pickle``, ``json``,
``dataclasses.asdict``, ``copy`` -- and asserts the needle is in none of them.

**It bites.** One synthetic needle of every kind in :data:`KINDS`, planted in a
scratch JSONL corpus, in both ``text`` and ``ident``, found.

**It says clean when the tree is clean.** A verifier that always reports a leak
is as useless as one that always reports none, and this codebase has met the
mirror image already: a source trimmed to zero documents looked exactly like a
source that had nothing to give, and only the balance report caught it.

**It does not cry wolf.** This corpus contains ``192.0.2.0/24``,
``2001:db8::/32``, ``3fff::/20``, ``00:00:5e:00:53:xx``, ``@example.com``,
SHA-256 hex, UUIDs, nuclei templates and YARA byte strings **on purpose**. A
gate with false positives is switched off by the first person it annoys and
then protects nothing.

**Every value in this file is fabricated.** ``synthetic-operator``,
``someone@example.invalid``, RFC 3849 / RFC 9637 documentation IPv6, RFC 5737
documentation IPv4, RFC 7042 documentation MACs. Nothing is read from the host
except in the two tests that are explicitly about the host probes, and those
assert on counts, probe names and fingerprints -- never on a value. A fixture
pinned to one developer's real username tests that developer's machine, passes
everywhere else by accident, and is itself the leak.

**Fixture arithmetic is computed, never remembered.** One hour before this file
was written, a sibling fixture used ``3fff:1234::1`` as "a documentation
address". It is not one: ``3fff::/20`` fixes the top four bits of the second
hextet at zero, so the block ends at ``3fff:0fff:ffff:...`` and anything from
``3fff:1000::`` up is ordinary global unicast. The classifier was right and the
fixture was wrong, and in the diff it read exactly like a false positive.
:class:`TestFixtureArithmetic` therefore asserts the boundaries of every range
this file relies on against :mod:`ipaddress` itself, so a wrong fixture fails
as a wrong fixture instead of being argued about as a detector bug.
"""

from __future__ import annotations

import copy
import dataclasses
import json
import os
import pickle
import re
import subprocess
import sys
import uuid
from ipaddress import IPv4Network, IPv6Address, IPv6Network, ip_address
from pathlib import Path

import pytest

from training.corpus import verify as V
from training.corpus.verify import (
    KINDS,
    Artifact,
    Calibration,
    Leak,
    Needles,
    Survey,
    calibrate,
    host_needles,
    render,
    render_survey,
    scan_file,
    scan_text,
    self_test,
    survey,
    verify_corpus,
)

# --------------------------------------------------------------------------
# fabricated needles
#
# Named constants rather than literals inline, for one reason that is not
# tidiness: a test that writes `"synthetic-operator"` in forty places is a test
# somebody will one day "fix" by pasting a real username into one of them. A
# single definition makes that edit visible.
# --------------------------------------------------------------------------

#: Account name. Eight characters past the four-character identifying floor,
#: and carrying a separator so the separator-swap expansions are exercised.
SYN_USER = "synthetic-operator"

#: Home path. The spelling that matters most: the audit's worst class of
#: finding was a rooted path reported as a bare name, under a fingerprint whose
#: length said 18 when 25 bytes had to come out.
SYN_HOME = f"/Users/{SYN_USER}"

#: A per-user temp directory of the shape macOS actually hands out. The hash
#: component is fabricated; the shape is not, because the flattened spelling of
#: one of these is what a cache-key builder emits.
SYN_TMP = "/var/folders/zz/abcd1234efgh5678/T"

#: ``.invalid`` is reserved by RFC 2606 and can never resolve.
SYN_EMAIL = "someone@example.invalid"

#: RFC 3849 documentation space, host part inside 2001:db8:1:2::/64. The
#: negatives below sit in *other* /64s of the same /32, so a detector that
#: matched on the /32 -- the obvious and wrong simplification -- fails.
SYN_V6 = "2001:db8:1:2::5"

#: A second address whose second hextet is zero. ``::`` can swallow a zero run
#: starting at the second group, so fd12::3456:0:0:0:9 and fd12:0:0:3456::9 are
#: one address and only a one-hextet prefilter anchor sees both.
SYN_V6_ULA = "fd12:0:0:3456::9"

#: RFC 1918. Ambiguous by construction and the module says so: an RFC1918
#: address bound on this host is also a documentation example in RFC, nuclei
#: and Sigma text, and the two are the same bytes.
SYN_V4 = "10.11.12.13"

#: RFC 7042 section 2.1.2 documentation MAC range, 00:00:5E:00:53:00-FF.
SYN_MAC = "00:00:5e:00:53:01"

#: A sibling of SYN_MAC in the same reserved range. It must NOT be reported:
#: the corpus is full of this range, and a scanner that fires on the family
#: rather than the address buries everything.
SYN_MAC_SIBLING = "00:00:5e:00:53:af"

SYN_VOLUME = "synthetic-disk"
SYN_VOLUME_PATH = f"/Volumes/{SYN_VOLUME}"

#: Probe labels a non-thin table needs. ``gaps()`` demands an address, a MAC,
#: ``account``, ``hostname``, and ``volumes`` on Darwin; a table missing any of
#: them makes :func:`main` exit 2, which is a different answer from both clean
#: and leaking and must not be produced by accident in a test about leaks.
SYN_PROBES = ("account", "hostname", "volumes", "network", "mac", "fabricated")

#: Every fabricated value, for the "did this test file itself leak" sweep and
#: for the report-safety assertions.
ALL_SYNTHETIC = (
    SYN_USER, SYN_HOME, SYN_TMP, SYN_EMAIL, SYN_V6, SYN_V6_ULA, SYN_V4,
    SYN_MAC, SYN_VOLUME, SYN_VOLUME_PATH,
)


def syn_needles(**overrides: object) -> Needles:
    """A fabricated table: one needle of every kind, no thin-table gaps."""
    kwargs: dict[str, object] = dict(
        probes=SYN_PROBES,
        identity=[SYN_USER],
        paths=[SYN_HOME, SYN_TMP],
        email=[SYN_EMAIL],
        ipv6=[SYN_V6, SYN_V6_ULA],
        ipv4=[SYN_V4],
        mac=[SYN_MAC],
        volumes=[SYN_VOLUME_PATH, SYN_VOLUME],
    )
    kwargs.update(overrides)
    return Needles.from_values(**kwargs)  # type: ignore[arg-type]


@pytest.fixture()
def needles() -> Needles:
    return syn_needles()


def write_corpus(root: Path, rows_by_file: dict[str, list[dict]]) -> Path:
    """A scratch generation: JSONL rows plus the PROVENANCE.md every real
    generation carries, because ``read_documents()`` globbing ``*.jsonl`` and
    missing that file is one of the reasons the module exists."""
    root.mkdir(parents=True, exist_ok=True)
    for name, rows in rows_by_file.items():
        with (root / name).open("w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    (root / "PROVENANCE.md").write_text(
        "built by a fabricated host for a test\n", encoding="utf-8")
    return root


def clean_row(ident: str = "netstat/1") -> dict:
    """A document made only of things this corpus contains on purpose."""
    return {
        "text": "tcp 0 0 0.0.0.0:445 LISTEN; example host 2001:db8::1 "
                "and 192.0.2.1; ether 00:11:22:33:44:55",
        "source": "fabricated", "register": "system", "side": "neutral",
        "ident": ident,
    }


def kinds_of(leaks: list[Leak]) -> set[str]:
    return {leak.kind for leak in leaks}


# --------------------------------------------------------------------------
# 0. the fixtures themselves
# --------------------------------------------------------------------------

class TestPublicSurface:
    """``__all__`` and the declared shape of each record type.

    Two other modules build against ``KINDS``, and the build gate, the CLI and
    this file share one scanner precisely so three detectors cannot drift
    apart -- which is how ``_identity_pattern`` (``re.IGNORECASE``) and
    ``identity_leaks`` (plain ``.lower()``) came to disagree in both directions
    about the same bytes. A shared surface only helps if it is pinned.
    """

    def test_everything_declared_in_all_is_importable(self) -> None:
        for name in V.__all__:
            assert hasattr(V, name), name

    def test_the_record_types_are_frozen_and_slotted(self) -> None:
        for cls in (Leak, Artifact, Survey, Calibration):
            assert dataclasses.is_dataclass(cls), cls
            assert cls.__dataclass_params__.frozen, cls
            assert "__slots__" in vars(cls), cls

    def test_leak_fields_are_exactly_the_report_safe_five(self) -> None:
        names = [f.name for f in dataclasses.fields(Leak)]
        assert names == ["kind", "path", "line", "field", "fingerprint"]

    def test_artifact_states_provenance_and_readability(self) -> None:
        names = {f.name for f in dataclasses.fields(Artifact)}
        assert names == {"name", "real", "size", "key", "is_symlink",
                         "is_text"}

    def test_survey_text_bytes_counts_only_what_was_actually_read(
            self) -> None:
        readable = Artifact(name="a.jsonl", real="a.jsonl", size=100,
                            key="1:1", is_symlink=False, is_text=True)
        opaque = Artifact(name="s.bin", real="s.bin", size=900, key="1:2",
                          is_symlink=False, is_text=False)
        info = Survey(given="g", real="g", directory_is_symlink=False,
                      files=(readable, opaque), aliases=())
        assert info.text_bytes == 100

    def test_kinds_is_a_closed_fixed_vocabulary(self) -> None:
        """Pinned by value, not by length.

        ``unreadable`` was added when ``scan_file``'s ``except OSError:
        return []`` was fixed: a file the pass could not open now travels as a
        Leak and fails the gate, because "I could not read it" must never be
        reported as "there is nothing in it". Pinning the whole tuple means a
        future kind has to be added here on purpose, and a silent reordering --
        which would not move the length -- fails too.
        """
        assert isinstance(KINDS, tuple)
        assert len(KINDS) == len(set(KINDS)) == 8
        assert KINDS == ("identity", "email", "ipv6-global", "ipv4-private",
                         "mac", "volume", "ident-path", "unreadable")
        assert all(isinstance(kind, str) for kind in KINDS)


#: Kinds that cannot be planted as a string, because they are not needles.
#: ``unreadable`` is emitted when a file cannot be *opened*, so it is produced
#: by filesystem state rather than by content, and the tests for it live in
#: :class:`TestUnreadableIsAFinding` instead of the planted-vocabulary sweep.
UNPLANTABLE = frozenset({"unreadable"})


class TestFixtureArithmetic:
    """Compute every range boundary this file leans on. Never remember one.

    The sibling fixture that got ``3fff::/20`` wrong is the whole argument for
    this class: a wrong fixture and a wrong detector produce the same red test,
    and only one of them is a bug in the code under test.
    """

    def test_3fff_slash_20_ends_at_0fff(self) -> None:
        doc = IPv6Network("3fff::/20")
        assert doc.network_address == IPv6Address("3fff::")
        assert doc.broadcast_address == IPv6Address(
            "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff")
        # In the block, including the last hextet-aligned prefix in it.
        assert IPv6Address("3fff::1") in doc
        assert IPv6Address("3fff:0fff:ffff::1") in doc
        # NOT in the block. This is the exact value a sibling fixture called a
        # documentation address one hour before this file was written.
        assert IPv6Address("3fff:1000::1") not in doc
        assert IPv6Address("3fff:1234::1") not in doc
        assert IPv6Address("3fff:1234::1").is_global

    def test_documentation_ranges_contain_the_negatives_this_file_uses(
            self) -> None:
        v4_doc = [IPv4Network("192.0.2.0/24"), IPv4Network("198.51.100.0/24"),
                  IPv4Network("203.0.113.0/24")]
        for text in ("192.0.2.1", "198.51.100.7", "203.0.113.42"):
            assert any(ip_address(text) in net for net in v4_doc), text
        v6_doc = IPv6Network("2001:db8::/32")
        for text in ("2001:db8::1", "2001:db8:3:4::9", SYN_V6):
            assert IPv6Address(text) in v6_doc, text

    def test_the_needles_sit_where_the_negatives_do_not(self) -> None:
        """The needle /64 and the negative /64s are disjoint, and they share a
        /32. A detector that matched on 2001:db8::/32 would pass a kind-only
        test and fail this set, which is why the set is built this way."""
        mine = IPv6Network(f"{SYN_V6}/64", strict=False)
        assert mine == IPv6Network("2001:db8:1:2::/64")
        for text in ("2001:db8::1", "2001:db8:3:4::9", "2001:db8:1:3::9"):
            assert IPv6Address(text) not in mine, text
        ula = IPv6Network(f"{SYN_V6_ULA}/64", strict=False)
        assert IPv6Address("fd12:0:0:3457::9") not in ula
        assert IPv6Address("fd12::3456:0:0:0:9") in ula  # same address, in

    def test_the_reserved_mac_sibling_is_a_different_address(self) -> None:
        assert SYN_MAC != SYN_MAC_SIBLING
        assert SYN_MAC[:15] == SYN_MAC_SIBLING[:15]  # same reserved range

    def test_rfc1918_needle_is_private_and_the_near_misses_are_distinct(
            self) -> None:
        """The near-misses attack the ``num`` guard from both sides: one is a
        shorter address, one extends the needle on the right, one embeds it on
        the left. All three are different addresses from the needle."""
        assert ip_address(SYN_V4).is_private
        assert ip_address("10.11.12.1") != ip_address(SYN_V4)
        assert ip_address("10.11.12.130") != ip_address(SYN_V4)
        assert ip_address("210.11.12.139") != ip_address(SYN_V4)
        # The embedding is real, which is what makes the guard necessary.
        assert SYN_V4 in "210.11.12.139" or "10.11.12.13" in "210.11.12.139"
        assert "210.11.12.139".find(SYN_V4) == 1

    def test_every_synthetic_value_is_unresolvable_or_reserved(self) -> None:
        """No fabricated value may name a real thing somebody owns."""
        assert SYN_EMAIL.endswith(".invalid")          # RFC 2606
        assert ip_address(SYN_V4).is_private           # RFC 1918
        assert IPv6Address(SYN_V6) in IPv6Network("2001:db8::/32")
        assert IPv6Address(SYN_V6_ULA).is_private      # fc00::/7
        assert SYN_MAC.startswith("00:00:5e")          # RFC 7042
        assert SYN_USER not in os.environ.get("USER", "x")


# --------------------------------------------------------------------------
# 1. Needles cannot leak.  The most important test in the file.
# --------------------------------------------------------------------------

class TestNeedlesCannotLeak:
    """Every accidental way a value escapes a Python object, closed.

    Not a style preference. The audit that found 3,540 real leaks wrote its own
    needle table to a JSON file and became the leak, and it did so through
    exactly these conveniences: a dataclass's generated ``__repr__``, an
    f-string in a log line, ``json.dumps``, ``pickle``. Each one is a
    one-character mistake away at all times, and a pytest assertion failure
    printing ``needles`` is one of them.
    """

    SECRET = "zzsynthetic-unique-needle-token"

    @pytest.fixture()
    def loaded(self) -> Needles:
        return Needles.from_values(probes=("fabricated",),
                                   identity=[self.SECRET])

    def test_repr_and_str_and_format_reveal_nothing(
            self, loaded: Needles) -> None:
        for rendered in (repr(loaded), str(loaded), f"{loaded}",
                         f"{loaded!r}", f"{loaded!s}", f"{loaded:>120}",
                         "{}".format(loaded), format(loaded, ".40")):
            assert self.SECRET not in rendered
            assert "redacted" in rendered

    def test_repr_still_says_how_many_and_of_what_kind(
            self, loaded: Needles) -> None:
        """Redaction is not silence. A report has to be able to say the table
        was thin, and a count is how it says so without a value."""
        assert "1 spellings" in repr(loaded) or "spellings" in repr(loaded)
        assert "identity=" in repr(loaded)
        assert len(loaded) >= 1
        assert loaded.kinds()["identity"] >= 1

    def test_there_is_no_instance_dict_to_walk(self, loaded: Needles) -> None:
        assert not hasattr(loaded, "__dict__")
        with pytest.raises(TypeError):
            vars(loaded)
        assert isinstance(Needles.__slots__, tuple)

    def test_pickle_refuses_rather_than_serialising(
            self, loaded: Needles) -> None:
        for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
            with pytest.raises(TypeError):
                pickle.dumps(loaded, protocol)
        with pytest.raises(TypeError):
            loaded.__reduce__()
        with pytest.raises(TypeError):
            loaded.__getstate__()

    def test_json_refuses(self, loaded: Needles) -> None:
        with pytest.raises(TypeError):
            json.dumps(loaded)
        with pytest.raises(TypeError):
            json.dumps({"needles": loaded})

    def test_dataclasses_asdict_refuses(self, loaded: Needles) -> None:
        assert not dataclasses.is_dataclass(loaded)
        with pytest.raises(TypeError):
            dataclasses.asdict(loaded)  # type: ignore[call-overload]

    def test_copy_and_deepcopy_refuse(self, loaded: Needles) -> None:
        with pytest.raises(TypeError):
            copy.copy(loaded)
        with pytest.raises(TypeError):
            copy.deepcopy(loaded)

    def test_no_public_attribute_exposes_a_value(
            self, loaded: Needles) -> None:
        """The public surface, walked exhaustively.

        The class docstring is honest that in-process code can reach the
        values -- they are in memory and the scanner reads them. What must hold
        is that nothing a caller is *invited* to touch returns one. This walk
        is the guard against a future convenience accessor.
        """
        for name in dir(loaded):
            if name.startswith("_"):
                continue
            attr = getattr(loaded, name)
            value = attr() if callable(attr) else attr
            assert self.SECRET not in repr(value), name

    def test_the_documented_escape_hatch_is_private_only(
            self, loaded: Needles) -> None:
        """Which attributes DO hold values, pinned deliberately.

        ``_anchors`` is a plain tuple of lowercase stems and ``_groups`` holds
        compiled patterns built from them, so both reveal values under
        ``repr``. That is stated in the class docstring rather than hidden, and
        it is pinned here so that promoting either to a public name, or adding
        a third such attribute, fails this test instead of shipping.
        """
        exposing = {name for name in Needles.__slots__
                    if self.SECRET in repr(getattr(loaded, name, None))}
        assert exposing == {"_anchors", "_groups"}
        assert all(name.startswith("_") for name in exposing)

    def test_iteration_yields_no_raw_string(self, loaded: Needles) -> None:
        assert not hasattr(loaded, "__iter__")
        with pytest.raises(TypeError):
            list(loaded)  # type: ignore[call-overload]

    def test_there_is_no_serialising_convenience_method(self) -> None:
        for name in ("to_json", "to_dict", "asdict", "as_dict", "dump",
                     "dumps", "save", "write", "values", "items", "keys"):
            assert not hasattr(Needles, name), name

    def test_fingerprints_are_fingerprints(self, loaded: Needles) -> None:
        for fp in loaded.fingerprints():
            assert self.SECRET not in fp
            assert re.fullmatch(r"len=\d+,sha256=[0-9a-f]{8}", fp), fp
        assert f"len={len(self.SECRET)}" in " ".join(loaded.fingerprints())

    def test_a_caller_holding_a_table_cannot_construct_one(self) -> None:
        """``__init__`` refuses on purpose: the only tables that exist are
        derived at runtime or fabricated in a test, never read from a file."""
        with pytest.raises(TypeError):
            Needles()
        with pytest.raises(TypeError):
            Needles(identity=["x"])  # type: ignore[call-arg]

    def test_equality_is_identity_so_the_table_cannot_be_probed(self) -> None:
        """A value-wise ``__eq__`` would let a caller binary-search the table
        by constructing candidates until one compared equal."""
        a = Needles.from_values(probes=("f",), identity=[self.SECRET])
        b = Needles.from_values(probes=("f",), identity=[self.SECRET])
        assert a == a
        assert a != b
        assert len({a, b}) == 2


# --------------------------------------------------------------------------
# 2. Leak carries a fingerprint, never a value
# --------------------------------------------------------------------------

class TestLeakCarriesNoValue:
    """Every field of every finding, searched for the needle that produced it.

    The path matters as much as the fingerprint. This corpus lives under a
    volume whose name is a needle, in a tree under a home directory whose name
    is a needle, so a Leak that printed its own unscrubbed path would put back
    exactly what the fingerprint exists to keep out -- and that is not
    hypothetical: the audit's own working files leaked by naming the files they
    had found leaks in.
    """

    def test_no_field_of_a_leak_holds_the_needle(
            self, needles: Needles) -> None:
        texts = [f"logged in as {SYN_USER}",
                 f"cache at {SYN_HOME}/Library",
                 f"wrote {SYN_TMP}/world",
                 f"contact {SYN_EMAIL} for access",
                 f"bound {SYN_V6} on en0",
                 f"inet {SYN_V4} netmask 0xffffff00",
                 f"ether {SYN_MAC}",
                 f"cache on {SYN_VOLUME_PATH}/corpus"]
        leaks = [leak for text in texts
                 for leak in scan_text(text, needles=needles)]
        assert leaks
        for leak in leaks:
            blob = "\x00".join(
                str(getattr(leak, f.name)) for f in dataclasses.fields(leak))
            for value in ALL_SYNTHETIC:
                assert value not in blob, (leak.kind, value)
            assert value_free(repr(leak))
            assert value_free(json.dumps(dataclasses.asdict(leak)))

    def test_fingerprint_shape_and_that_it_names_the_right_length(
            self, needles: Needles) -> None:
        leaks = scan_text(f"cache at {SYN_HOME}/Library", needles=needles)
        assert len(leaks) == 1
        assert re.fullmatch(r"len=\d+,sha256=[0-9a-f]{8}",
                            leaks[0].fingerprint)
        # The extent is part of the claim. A home path reported as a bare
        # account name sends somebody looking for 18 bytes when 25 have to go.
        assert leaks[0].fingerprint.startswith(f"len={len(SYN_HOME)},")

    def test_two_occurrences_of_one_value_group_under_one_fingerprint(
            self, needles: Needles) -> None:
        leaks = scan_text(f"{SYN_USER} and again {SYN_USER}", needles=needles)
        assert len(leaks) == 2
        assert len({leak.fingerprint for leak in leaks}) == 1

    def test_two_different_values_do_not_group(self, needles: Needles) -> None:
        a = scan_text(f"user {SYN_USER}", needles=needles)[0]
        b = scan_text(f"mail {SYN_EMAIL}", needles=needles)[0]
        assert a.fingerprint != b.fingerprint

    def test_a_leaking_path_is_scrubbed_in_the_finding(
            self, tmp_path: Path, needles: Needles) -> None:
        """The file's own name is a needle. The finding must not restate it."""
        root = tmp_path / SYN_VOLUME / "clean"
        write_corpus(root, {f"{SYN_USER}.jsonl": [
            {"text": f"ether {SYN_MAC}", "ident": "x"}]})
        leaks = scan_file(root / f"{SYN_USER}.jsonl", needles=needles)
        assert leaks
        for leak in leaks:
            assert value_free(leak.path)
            assert "<identity>" in leak.path or "<volume>" in leak.path

    def test_a_leaking_field_name_is_scrubbed(
            self, tmp_path: Path, needles: Needles) -> None:
        path = tmp_path / "weird.jsonl"
        path.write_text(json.dumps({SYN_USER: f"ether {SYN_MAC}"}) + "\n",
                        encoding="utf-8")
        leaks = scan_file(path, needles=needles)
        assert leaks
        for leak in leaks:
            assert value_free(leak.field)

    def test_render_prints_fingerprints_only(self, needles: Needles) -> None:
        leaks = [leak for text in
                 (f"user {SYN_USER}", f"ether {SYN_MAC}", f"inet {SYN_V4}",
                  f"addr {SYN_V6}", f"mail {SYN_EMAIL}",
                  f"disk {SYN_VOLUME_PATH}")
                 for leak in scan_text(text, needles=needles)]
        out = render(leaks)
        assert value_free(out)
        assert "len=" in out and "sha256=" in out
        assert "distinct" in out
        # The ipv4-private caveat is part of the instrument's honesty: those
        # bytes are also every RFC's example, so the report must say "look",
        # not "leak".
        assert "ambiguous by construction" in out

    def test_render_of_nothing_says_zero_rather_than_nothing(self) -> None:
        assert render([]) == "0 leaks."

    def test_scan_text_invents_no_provenance(self, needles: Needles) -> None:
        """Handed a string and no file, ``path`` is empty and ``line`` is 0.
        Inventing either would be a lie in a report."""
        leak = scan_text(f"user {SYN_USER}", needles=needles)[0]
        assert leak.path == ""
        assert leak.line == 0
        assert leak.field == "text"

    def test_leak_is_immutable(self, needles: Needles) -> None:
        leak = scan_text(f"user {SYN_USER}", needles=needles)[0]
        with pytest.raises(dataclasses.FrozenInstanceError):
            leak.fingerprint = "len=0,sha256=00000000"  # type: ignore[misc]


def value_free(text: str) -> bool:
    """No fabricated needle appears in ``text``."""
    return not any(value in text for value in ALL_SYNTHETIC)


# --------------------------------------------------------------------------
# 3. it bites -- and it stops biting on a clean tree
# --------------------------------------------------------------------------

#: One planted spelling per kind, and the field it has to be planted in for
#: that kind to be the answer. ``ident-path`` is the odd one and deliberately
#: so: it is not a separate needle, it is the relabelling a rooted needle gets
#: when it is found in a document's ``ident``. ``_redacted`` covers
#: ``doc.text`` only, so re-running the text redactor fixes none of those,
#: which is why the report must not merge them.
PLANTED: dict[str, str] = {
    "identity": f"logged in as {SYN_USER}",
    "email": f"contact {SYN_EMAIL} for access",
    "ipv6-global": f"bound {SYN_V6} on en0",
    "ipv4-private": f"inet {SYN_V4} netmask 0xffffff00",
    "mac": f"ether {SYN_MAC} up",
    "volume": f"mounted {SYN_VOLUME} read-only",
    "ident-path": f"{SYN_HOME}/Library/Caches/x",
}


class TestItBites:

    def test_planted_vocabulary_covers_every_declared_kind(self) -> None:
        """If ``KINDS`` grows, this file must grow with it. A scanner that can
        invent a kind can hide one in a typo, which is why the vocabulary is
        fixed -- and a test that silently skips a new kind defeats that."""
        assert set(PLANTED) == set(KINDS) - UNPLANTABLE

    @pytest.mark.parametrize(
        "kind", [k for k in KINDS if k != "ident-path" and k not in UNPLANTABLE])
    def test_each_kind_is_found_in_text(
            self, kind: str, needles: Needles) -> None:
        found = kinds_of(scan_text(PLANTED[kind], needles=needles,
                                   field="text"))
        assert kind in found, (kind, sorted(found))

    @pytest.mark.parametrize(
        "kind", [k for k in KINDS if k != "ident-path" and k not in UNPLANTABLE])
    def test_each_kind_is_found_in_ident(
            self, kind: str, needles: Needles) -> None:
        found = kinds_of(scan_text(PLANTED[kind], needles=needles,
                                   field="ident"))
        assert kind in found, (kind, sorted(found))

    def test_ident_path_is_the_ident_field_relabelling(
            self, needles: Needles) -> None:
        text = PLANTED["ident-path"]
        assert kinds_of(scan_text(text, needles=needles, field="text")) == {
            "identity"}
        assert kinds_of(scan_text(text, needles=needles, field="ident")) == {
            "ident-path"}

    def test_a_bare_name_in_ident_is_not_promoted_to_ident_path(
            self, needles: Needles) -> None:
        """Only a *rooted* needle becomes ``ident-path``. A bare account name
        in an ident is an identity leak with a different fix."""
        assert kinds_of(scan_text(f"run-{SYN_USER}", needles=needles,
                                  field="ident")) == {"identity"}

    def test_every_kind_is_found_through_a_real_corpus_pass(
            self, tmp_path: Path, needles: Needles) -> None:
        """The whole pipeline: walk, decode, scan every string field.

        Planted in both ``text`` and ``ident`` of a scratch generation, with a
        clean file beside it so the pass has to find the needle rather than
        flag the directory.
        """
        rows = [clean_row()]
        for kind, spelling in PLANTED.items():
            rows.append({"text": spelling, "source": "fabricated",
                         "register": "system", "side": "neutral",
                         "ident": spelling})
        root = write_corpus(tmp_path / "clean-fab", {
            "planted.jsonl": rows, "quiet.jsonl": [clean_row(), clean_row()]})
        leaks = verify_corpus(root, needles=needles)
        found = kinds_of(leaks)
        assert set(KINDS) - UNPLANTABLE <= found, sorted(
            set(KINDS) - UNPLANTABLE - found)
        fields = {leak.field for leak in leaks}
        assert {"text", "ident"} <= fields
        assert all(value_free(render([leak])) for leak in leaks)

    def test_a_clean_tree_returns_zero(
            self, tmp_path: Path, needles: Needles) -> None:
        """The half without which the other half means nothing.

        A verifier that always says "leak" is as useless as one that always
        says "clean", and this codebase has met the mirror image: a source
        trimmed to zero documents looked exactly like a source that had nothing
        to give, and only the balance report caught it.
        """
        root = write_corpus(tmp_path / "clean-quiet", {
            "a.jsonl": [clean_row(f"doc/{i}") for i in range(20)],
            "b.jsonl": [clean_row() for _ in range(20)]})
        assert verify_corpus(root, needles=needles) == []

    def test_a_needle_in_a_nested_field_is_found(
            self, tmp_path: Path, needles: Needles) -> None:
        """Every string, not ``text`` and ``ident``. A verifier that knows
        which fields matter stops working the first time a source adds one, and
        ``_redacted``'s whole failure was that it knew about exactly one."""
        path = tmp_path / "nested.jsonl"
        path.write_text(json.dumps({
            "meta": {"built_by": f"ether {SYN_MAC}"},
            "tags": ["ok", f"home {SYN_HOME}"]}) + "\n", encoding="utf-8")
        leaks = scan_file(path, needles=needles)
        assert {leak.field for leak in leaks} == {"meta.built_by", "tags[1]"}

    def test_a_needle_in_a_non_jsonl_file_is_found(
            self, tmp_path: Path, needles: Needles) -> None:
        """``PROVENANCE.md`` sits in every generation and ``read_documents()``
        globbing ``*.jsonl`` is one of the reasons this module exists."""
        root = tmp_path / "gen"
        root.mkdir()
        (root / "PROVENANCE.md").write_text(
            f"built on {SYN_VOLUME_PATH} by {SYN_USER}\n", encoding="utf-8")
        leaks = verify_corpus(root, needles=needles)
        assert leaks
        assert {leak.field for leak in leaks} == {"raw"}
        assert kinds_of(leaks) >= {"volume"}

    def test_a_malformed_jsonl_line_is_scanned_as_raw_not_skipped(
            self, tmp_path: Path, needles: Needles) -> None:
        """A non-greedy regex that truncated valid JSON and called it
        malformed is one of this codebase's three measurement bugs. Whatever
        the decoder thinks, the bytes are on disk and must be read."""
        path = tmp_path / "broken.jsonl"
        path.write_text('{"text": "ether ' + SYN_MAC + '" \n',
                        encoding="utf-8")
        leaks = scan_file(path, needles=needles)
        assert [(leak.kind, leak.field) for leak in leaks] == [("mac", "raw")]

    def test_line_numbers_are_one_based_and_correct(
            self, tmp_path: Path, needles: Needles) -> None:
        path = tmp_path / "lines.jsonl"
        with path.open("w", encoding="utf-8") as fh:
            fh.write(json.dumps(clean_row()) + "\n")
            fh.write("\n")
            fh.write(json.dumps({"text": f"ether {SYN_MAC}"}) + "\n")
        assert [leak.line for leak in scan_file(path, needles=needles)] == [3]

    def test_an_escaped_non_ascii_needle_is_found_either_way(
            self, tmp_path: Path) -> None:
        """``build()`` writes ``ensure_ascii=False``; another writer does not.
        Both spellings reach a line, and the prefilter runs against the raw
        line, so a needle must not be able to hide behind the encoder."""
        needle = "strauß-operator"
        table = syn_needles(identity=[SYN_USER, needle])
        path = tmp_path / "enc.jsonl"
        with path.open("w", encoding="utf-8") as fh:
            fh.write(json.dumps({"text": f"run as {needle}"},
                                ensure_ascii=False) + "\n")
            fh.write(json.dumps({"text": f"run as {needle}"},
                                ensure_ascii=True) + "\n")
            # The casefold direction re.IGNORECASE cannot reach: Python's `re`
            # does no multi-character folds, so eszett never matches "ss".
            fh.write(json.dumps({"text": "run as strauss-operator"}) + "\n")
        lines = {leak.line for leak in scan_file(path, needles=table)}
        assert lines == {1, 2, 3}

    def test_a_unicode_fold_the_substituter_raises_on_is_still_found(
            self, needles: Needles) -> None:
        """U+0130 in place of the ``i``. ``redact_identity`` raises KeyError on
        this text and ``identity_leaks`` calls it clean, because one folds with
        ``re.IGNORECASE`` and the other with ``str.lower``."""
        text = "user synthetİc-operator logged in"
        assert kinds_of(scan_text(text, needles=needles)) == {"identity"}

    def test_the_same_fold_survives_the_cheap_prefilter_in_a_real_file(
            self, tmp_path: Path, needles: Needles) -> None:
        """The two-stage scan, at the stage that can silently drop a line.

        ``scan_file`` rejects most lines with ``Needles._hint`` before paying
        for ``json.loads``, and the anchor pass inside it is a ``str.lower``
        substring test -- which does not reach this fold, because
        ``'\\u0130'.lower()`` is ``'i'`` plus a combining dot and the anchor is
        no longer a substring. Only ``_hint``'s non-ASCII ``re.IGNORECASE``
        branch sees it. :func:`scan_text` bypasses ``_hint`` entirely, so the
        test above cannot cover this and a mutation of ``_hint`` goes
        unnoticed without it: a scanner that is fast and reports clean.
        """
        trap = "user synthetİc-operator logged in"
        assert not trap.isascii()
        # The premise, asserted rather than assumed: the cheap anchor pass
        # really does miss this line.
        assert not any(anchor in trap.lower() for anchor in needles._anchors)
        assert needles._hint(trap) is True

        path = tmp_path / "fold.jsonl"
        path.write_text(json.dumps({"text": trap}, ensure_ascii=False) + "\n",
                        encoding="utf-8")
        assert kinds_of(scan_file(path, needles=needles)) == {"identity"}

    def test_a_separator_swapped_account_name_is_found(self) -> None:
        """Two spellings are one account to every cache-key builder on the
        machine, and only one of them is in ``_identity_table``."""
        table = syn_needles(identity=["fabricated_operator"],
                            paths=[], volumes=[])
        for spelling in ("fabricated_operator", "fabricated-operator",
                         "fabricated.operator"):
            assert scan_text(f"key={spelling}.log", needles=table), spelling

    def test_a_flattened_home_path_is_found(self) -> None:
        """The scratch directory the remediation itself ran in is named by
        flattening an absolute home path, hyphens for slashes and for the
        underscore inside the account name. Structurally ungeneratable in
        ``_spellings()``, so ``identity_leaks()`` calls such a document clean.
        """
        table = syn_needles()
        for spelling in ("-var-folders-zz-abcd1234efgh5678-T-world",
                         ".var.folders.zz.abcd1234efgh5678.T",
                         "log%2Fvar%2Ffolders%2Fzz%2Fabcd1234efgh5678%2FT"):
            assert scan_text(spelling, needles=table), spelling

    def test_a_mac_hidden_in_a_uuid_v1_node_field_is_found(
            self, needles: Needles) -> None:
        """RFC 4122 v1 embeds the generating machine's MAC in the node field,
        so a UUID carrying this host's MAC is a true positive -- and one of the
        few leaks nobody looks for."""
        v1 = f"7d444840-9dc0-11d1-b245-{SYN_MAC.replace(':', '')}"
        assert uuid.UUID(v1).version == 1
        assert kinds_of(scan_text(f"uuid {v1}", needles=needles)) == {"mac"}

    def test_an_empty_table_finds_nothing_and_says_so(
            self, tmp_path: Path) -> None:
        """``[]`` from an empty table means *nothing was looked for*.

        ``redact_identity`` opens with ``if pattern is None: return text`` and
        that fail-open is reachable. The verifier's equivalent would be a pass
        that derived nothing, read 625 MB and printed "clean". The module's
        answer is that the caller must check ``gaps()``.
        """
        empty = Needles.from_values(probes=())
        assert not empty
        assert len(empty) == 0
        root = write_corpus(tmp_path / "gen", {
            "a.jsonl": [{"text": f"ether {SYN_MAC} home {SYN_HOME}"}]})
        assert verify_corpus(root, needles=empty) == []
        assert set(empty.gaps()) >= {"network", "mac", "account", "hostname"}

    def test_gaps_is_empty_only_when_every_probe_contributed(self) -> None:
        assert syn_needles().gaps() == ()
        assert "mac" in syn_needles(mac=[]).gaps()
        assert "network" in syn_needles(ipv6=[], ipv4=[]).gaps()
        assert "account" in syn_needles(probes=("hostname", "volumes")).gaps()

    def test_the_identifying_floor_refuses_a_three_character_needle(
            self) -> None:
        """A three-character needle matches half the corpus, and substituting
        it shreds a corpus to remove nothing."""
        assert len(Needles.from_values(probes=("f",), identity=["abc"])) == 0
        assert len(Needles.from_values(probes=("f",), identity=["root"])) == 0
        assert len(Needles.from_values(probes=("f",),
                                       volumes=["Macintosh HD"])) == 0
        assert len(Needles.from_values(probes=("f",), identity=["abc"],
                                       strict=False)) > 0

    def test_universal_addresses_are_never_needles(self) -> None:
        table = Needles.from_values(
            probes=("f",), ipv6=["::1", "fe80::1", "::"],
            ipv4=["127.0.0.1", "0.0.0.0"],
            mac=["00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"])
        assert len(table) == 0

    def test_the_modules_own_self_test_passes(self) -> None:
        """It plants a needle, proves it is found, removes it, proves the same
        tree comes back zero -- and reports the symlink. Run here so the gate's
        own claim is in the suite rather than only in a CLI somebody ran once.
        """
        report = self_test()
        assert report.startswith("self-test PASS"), report
        assert "clean tree 0 leak(s)" in report
        assert "ident-path" in report
        assert value_free(report)

    def test_the_self_test_fails_when_its_clean_half_is_not_clean(
            self, monkeypatch: pytest.MonkeyPatch) -> None:
        """``self_test`` reports PASS only if **both** halves hold, and the
        clean half is the one that rots silently.

        Widening the table so the "clean" tree is no longer clean must flip the
        verdict. Without this test the ``not before and`` conjunct in
        ``self_test`` can be deleted and nothing notices -- which is the exact
        shape of the bug it was written against: a source trimmed to zero
        documents looked identical to a source that had nothing to give.
        """
        widened = dict(V._CAL_NEEDLES)
        widened["ipv6"] = list(widened["ipv6"]) + ["2001:db8::1"]
        monkeypatch.setattr(
            V, "_cal_needles",
            lambda: Needles.from_values(probes=("mutant",), **widened))
        report = self_test()
        assert report.startswith("self-test FAIL"), report
        assert "clean tree 1 leak(s)" in report
        assert value_free(report)

    def test_the_stem_invariant_is_enforced_at_construction(self) -> None:
        """A prefilter that can miss a spelling is a scanner that is fast and
        reports clean.

        ``scan_file`` rejects most lines on a substring test over ~40 stems and
        never decodes them, and that is sound only because no spelling of any
        needle exists that does not contain its own stem. ``from_values``
        self-heals a transform that loses its base by making the spelling its
        own stem, so the guard is only reachable through ``_make`` -- and it is
        reached here deliberately, because an unchecked invariant is the
        difference between a verifier and a number.
        """
        bad = V._Lit("abcdefgh", "abcdefgh", "identity", rooted=False,
                     stem="zzzzzzzz")
        with pytest.raises(AssertionError, match="does not contain"):
            Needles._make(lits=[bad], v6_exact=(), v6_nets=(), v4_exact=(),
                          macs=(), probes=("fabricated",))
        good = V._Lit("abcdefgh", "abcdefgh", "identity", rooted=False,
                      stem="abcd")
        assert len(Needles._make(lits=[good], v6_exact=(), v6_nets=(),
                                 v4_exact=(), macs=(),
                                 probes=("fabricated",))) == 1

    def test_from_values_self_heals_a_transform_that_loses_its_base(
            self) -> None:
        """The reason the guard above is hard to reach: a casefold expansion
        or a ``\\uXXXX`` escape does not contain the form it came from, so it
        becomes its own stem rather than an unsound anchor."""
        table = Needles.from_values(probes=("f",),
                                    identity=["strauß-operator"])
        anchors = set(table._anchors)
        assert "strauß-operator" in anchors
        assert "strauss-operator" in anchors   # the casefold, as its own stem
        for anchor in anchors:
            assert anchor == anchor.lower()


# --------------------------------------------------------------------------
# 4. no false positives on what this corpus really contains
# --------------------------------------------------------------------------

#: Things the corpus holds **on purpose**, in RFCs, nuclei templates, Sigma
#: rules and YARA. Each must come back clean against a full fabricated table.
#: A gate with false positives is switched off by the first person it annoys,
#: and then it protects nothing.
NEGATIVES: tuple[tuple[str, str], ...] = (
    # RFC 5737 documentation IPv4.
    ("TEST-NET-1", "connect 192.0.2.1 port 443"),
    ("TEST-NET-2", "upstream 198.51.100.7 timed out"),
    ("TEST-NET-3", "relay 203.0.113.42 refused"),
    # RFC 1918 that is not the bound address.
    ("rfc1918 not ours", "gateway 192.168.1.1, 10.0.0.1, 172.16.0.1"),
    ("ipv4 near-miss low octet", "host 10.11.12.1 answered"),
    ("ipv4 near-miss embedded", "build 210.11.12.139 shipped"),
    ("ipv4 right boundary", "mask 10.11.12.130 broadcast"),
    ("ipv4 trailing component", "agent 10.11.12.13.4 build"),
    # The two a previous analyst's scanner classed as routable addresses.
    ("version quad", "openssl 3.0.11.2 released"),
    ("snmp oid short", "sysUpTime 2.6.32.5 counter"),
    ("snmp oid full", "iso.3.6.1.2.1.1.5.0 = STRING"),
    ("kernel version", "Linux 2.6.32.5-amd64 #1 SMP"),
    # RFC 3849 documentation IPv6, in other /64s of the needle's own /32.
    ("ipv6 doc other /64", "example 2001:db8::1 and 2001:db8:3:4::9"),
    ("ipv6 doc sibling /64", "prefix 2001:db8:1:3::/64 is not ours"),
    ("ipv6 doc longer prefix", "route 2001:db8:1:20::/64 via x"),
    # RFC 9637 documentation IPv6. The /20 boundary is computed in
    # TestFixtureArithmetic, not remembered.
    ("ipv6 3fff doc low", "docs use 3fff::1 as an example"),
    ("ipv6 3fff doc top", "docs use 3fff:0fff:ffff::1 too"),
    # ULA siblings of the second needle.
    ("ipv6 ula sibling /64", "peer fd12:0:0:3457::9 and fd13::1"),
    ("ipv6 loopback and link-local", "listening on ::1 and fe80::1%lo0"),
    # RFC 7042 reserved MACs, including a sibling of the needle itself.
    ("reserved mac sibling", f"ether {SYN_MAC_SIBLING} up"),
    ("rfc7042 doc mac", "ether 00:11:22:33:44:55"),
    ("multicast mac", "dst 01:80:c2:00:00:00 stp"),
    ("deadbeef mac", "src de:ad:be:ef:00:01"),
    ("timestamp not a mac", "at 12:34:56 the job 00:00:5e started"),
    # Hex blobs. yara.jsonl and juliet.jsonl are 32 MB of these between them.
    ("sha256", "hash 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6"
               "c15b0f00a08"),
    ("md5", "md5 d41d8cd98f00b204e9800998ecf8427e"),
    ("uuid4", "id 3f2504e0-4f89-41d3-9a0c-0305e82c3301"),
    ("yara hex string", "$a = { 00 00 5e 00 53 af 90 90 }"),
    ("nuclei template", "matchers: - type: word words: - 'synthetic'"),
    ("sigma selection", "selection: Image|endswith: '\\\\operator.exe'"),
    # Addresses at domains reserved for examples.
    ("example.invalid other local part",
     "mail other@example.invalid bounced"),
    ("example.com", "mail root@example.com and admin@example.org"),
    ("email longer local part", f"mail not{SYN_EMAIL} bounced"),
    ("email extended domain", f"mail {SYN_EMAIL}.evil.test"),
    # Generic words in the needles' own neighbourhood.
    ("generic operator", "the operator ran the playbook as root"),
    ("generic volume", "data volume mounted at /Volumes/Macintosh HD"),
    ("account prefix only", "job synthetic-op finished"),
    ("volume name prefix only", "disk synthetic-dis offline"),
    ("home path wrong user", "cache /Users/other-operator/Library"),
    ("tmpdir wrong hash", "/var/folders/zz/zzzz0000zzzz0000/T/world"),
    ("flattened path wrong hash", "key=-var-folders-zz-0000000000000000-T"),
    ("eszett is not a free pass", "run as strau-operator today"),
    # Shapes that look like addresses and are not.
    ("cvss pair", "CVSS 7.5000, 9.8000 scored"),
    ("netstat columns", "tcp 0 0 0.0.0.0:445 0.0.0.0:* LISTEN"),
    ("bit ruler", " 0                   1                   2         "),
    ("port after address", "bind 0.0.0.0:445 and [::]:445"),
)


class TestNoFalsePositives:

    @pytest.mark.parametrize("label,text", NEGATIVES,
                             ids=[label for label, _ in NEGATIVES])
    def test_negative_is_clean(self, label: str, text: str,
                               needles: Needles) -> None:
        leaks = scan_text(text, needles=needles)
        assert not leaks, (label, sorted(kinds_of(leaks)))

    @pytest.mark.parametrize("label,text", NEGATIVES,
                             ids=[label for label, _ in NEGATIVES])
    def test_negative_is_clean_in_an_ident_field_too(
            self, label: str, text: str, needles: Needles) -> None:
        """The ``ident`` relabelling must not also widen what matches."""
        leaks = scan_text(text, needles=needles, field="ident")
        assert not leaks, (label, sorted(kinds_of(leaks)))

    def test_a_whole_corpus_of_negatives_comes_back_zero(
            self, tmp_path: Path, needles: Needles) -> None:
        rows = [{"text": text, "source": "fabricated", "register": "system",
                 "side": "neutral", "ident": f"rfc/{i}"}
                for i, (_label, text) in enumerate(NEGATIVES)]
        root = write_corpus(tmp_path / "docs", {"rfc.jsonl": rows})
        assert verify_corpus(root, needles=needles) == []

    def test_the_documentation_ipv6_the_sibling_fixture_got_wrong(
            self, needles: Needles) -> None:
        """``3fff:1234::1`` is NOT documentation space, and a verifier that
        treats it as one is wrong in the dangerous direction.

        Asserted both ways: inside ``3fff::/20`` it is clean because it is not
        a needle, and as a needle it is found -- because the classifier that
        called it global unicast was right and the fixture that called it
        documentation was wrong.
        """
        assert not scan_text("docs use 3fff:0fff:ffff::1", needles=needles)
        assert not scan_text("global 3fff:1234::1 seen", needles=needles)
        table = syn_needles(ipv6=["3fff:1234::1"])
        assert kinds_of(scan_text("global 3fff:1234::1 seen",
                                  needles=table)) == {"ipv6-global"}

    def test_a_longer_hex_run_does_not_swallow_the_bare_mac_spelling(
            self, needles: Needles) -> None:
        """The bare twelve-hex MAC takes hex boundaries on both sides, so it
        cannot land inside a SHA-256 -- but it *must* land inside a UUID v1."""
        bare = SYN_MAC.replace(":", "")
        assert not scan_text(f"hash a{bare}b", needles=needles)
        assert not scan_text(f"hash {bare}0", needles=needles)
        assert scan_text(f"node={bare}", needles=needles)


# --------------------------------------------------------------------------
# 5. symlink honesty -- the clean-v8 case
# --------------------------------------------------------------------------

class TestSymlinkHonesty:
    """``clean-v8`` is a symlink to ``clean-v7``.

    "v8 was verified" was a statement about v7's bytes and nothing in the build
    said so. A verifier that reports leaks but not provenance lets that
    sentence stand, which is arguably a worse finding than a leak because it
    invalidates every other claim made about the generation.
    """

    @pytest.fixture()
    def tree(self, tmp_path: Path, needles: Needles) -> tuple[Path, Path]:
        real = write_corpus(tmp_path / "clean-v7", {
            "a.jsonl": [clean_row(), {"text": f"ether {SYN_MAC}",
                                      "ident": f"{SYN_HOME}/x"}]})
        link = tmp_path / "clean-v8"
        link.symlink_to(real, target_is_directory=True)
        return real, link

    def test_survey_states_the_directory_is_a_symlink(
            self, tree: tuple[Path, Path], needles: Needles) -> None:
        _real, link = tree
        info = survey(link, needles=needles)
        assert info.directory_is_symlink is True
        assert info.given.endswith("clean-v8")
        assert info.real.endswith("clean-v7")
        assert info.given != info.real

    def test_survey_does_not_claim_a_symlink_where_there_is_none(
            self, tree: tuple[Path, Path], needles: Needles) -> None:
        real, _link = tree
        info = survey(real, needles=needles)
        assert info.directory_is_symlink is False
        assert Path(info.given).name == Path(info.real).name

    def test_render_survey_names_the_artifact_that_was_actually_read(
            self, tree: tuple[Path, Path], needles: Needles) -> None:
        _real, link = tree
        out = render_survey(survey(link, needles=needles))
        assert "IS A SYMLINK" in out
        assert "clean-v7" in out
        assert "clean-v8" in out
        assert "clean-v8 case" in out
        assert value_free(out)

    def test_verify_corpus_through_the_symlink_reads_the_targets_bytes(
            self, tree: tuple[Path, Path], needles: Needles) -> None:
        """Same leaks either way, because there is one artifact. The honesty is
        in the Survey, not in a different leak count."""
        real, link = tree
        through_link = verify_corpus(link, needles=needles)
        direct = verify_corpus(real, needles=needles)
        assert through_link
        assert ({(leak.kind, leak.line, leak.field) for leak in through_link}
                == {(leak.kind, leak.line, leak.field) for leak in direct})

    def test_a_symlinked_file_is_reported_as_one_artifact_under_two_names(
            self, tmp_path: Path, needles: Needles) -> None:
        root = write_corpus(tmp_path / "gen", {
            "a.jsonl": [{"text": f"ether {SYN_MAC}", "ident": "x"}]})
        (root / "alias.jsonl").symlink_to(root / "a.jsonl")
        os.link(root / "a.jsonl", root / "hard.jsonl")
        info = survey(root, needles=needles)
        names = {art.name for art in info.files}
        assert {"a.jsonl", "alias.jsonl", "hard.jsonl"} <= names
        assert info.aliases
        group = max(info.aliases, key=len)
        assert set(group) == {"a.jsonl", "alias.jsonl", "hard.jsonl"}
        assert len({art.key for art in info.files
                    if art.name in group}) == 1
        out = render_survey(info)
        assert "one artifact under 3 names" in out

    def test_the_walk_does_not_descend_into_a_directory_symlink(
            self, tmp_path: Path, needles: Needles) -> None:
        """``os.walk(followlinks=False)``, never ``rglob``. The precedent is on
        the record: ``ownrepos`` once followed this repo's ``data`` symlink
        into the SSD and pulled the corpus cache back in as prose -- the
        corpus ate itself. A verifier that walked in would scan the same
        bytes twice and report a doubled count as a doubled leak.
        """
        root = tmp_path / "parent"
        inner = write_corpus(root / "clean-v7", {
            "a.jsonl": [{"text": f"ether {SYN_MAC}", "ident": "x"}]})
        (root / "clean-v8").symlink_to(inner, target_is_directory=True)
        info = survey(root, needles=needles)
        assert not any(art.name.startswith("clean-v8")
                       for art in info.files), [a.name for a in info.files]
        leaks = verify_corpus(root, needles=needles)
        assert len(leaks) == 1

    def test_artifact_fields_are_report_safe(
            self, tmp_path: Path, needles: Needles) -> None:
        root = write_corpus(tmp_path / SYN_VOLUME / "clean", {
            f"{SYN_USER}.jsonl": [clean_row()]})
        info = survey(root, needles=needles)
        assert value_free(info.given)
        assert value_free(info.real)
        for art in info.files:
            assert value_free(art.name)
            assert value_free(art.real)
            assert value_free(art.key)
        assert value_free(render_survey(info))

    @pytest.mark.skipif(os.getuid() == 0,
                        reason="root can open a mode-000 file")
    def test_a_file_that_cannot_be_opened_is_not_claimed_as_scanned(
            self, tmp_path: Path, needles: Needles) -> None:
        """``survey`` cannot read it, so it must not say it did.

        The ``except OSError`` branch has to answer ``is_text = False``, not
        True: claiming an unreadable file as text makes it count toward
        ``text_bytes`` and vanish from the "NOT scanned" line, which is a
        verifier reporting coverage it does not have. This codebase has met
        the general case already -- ``[]`` from an empty table and ``[]`` from
        a clean corpus are the same bytes and different facts.
        """
        root = write_corpus(tmp_path / "gen", {"ok.jsonl": [clean_row()]})
        locked = root / "locked.jsonl"
        locked.write_text(json.dumps({"text": f"ether {SYN_MAC}"}) + "\n",
                          encoding="utf-8")
        locked.chmod(0o000)
        try:
            info = survey(root, needles=needles)
            states = {art.name: art.is_text for art in info.files}
            assert states["locked.jsonl"] is False, states
            assert states["ok.jsonl"] is True
            assert "NOT scanned" in render_survey(info)
            assert "locked.jsonl" in render_survey(info)
            assert info.text_bytes < sum(a.size for a in info.files)
        finally:
            locked.chmod(0o600)

    def test_an_unreadable_binary_file_is_stated_not_skipped_silently(
            self, tmp_path: Path, needles: Needles) -> None:
        """A leak in a token shard is still in the weights; it is just not
        greppable from here. Said out loud rather than dropped."""
        root = tmp_path / "tok"
        root.mkdir()
        (root / "shard.bin").write_bytes(b"\x00\x01" + SYN_MAC.encode())
        info = survey(root, needles=needles)
        assert [art.is_text for art in info.files] == [False]
        assert info.text_bytes == 0
        out = render_survey(info)
        assert "NOT scanned" in out
        assert verify_corpus(root, needles=needles) == []


# --------------------------------------------------------------------------
# 6. the CLI
# --------------------------------------------------------------------------

@pytest.fixture()
def fabricated_host(monkeypatch: pytest.MonkeyPatch) -> Needles:
    """Make the CLI's own ``host_needles()`` return a fabricated table.

    The CLI derives its table from the OS by design -- a configured list is a
    list of the leaks somebody already noticed. That makes it untestable
    without this seam, and the alternative (planting the running operator's
    real identifiers in a scratch tree) is the leak these tests exist to
    prevent.
    """
    table = syn_needles()
    monkeypatch.setattr(V, "host_needles", lambda **_kw: table)
    return table


class TestCLI:

    def test_exit_zero_and_no_value_printed_on_a_clean_tree(
            self, tmp_path: Path, fabricated_host: Needles,
            capsys: pytest.CaptureFixture[str]) -> None:
        root = write_corpus(tmp_path / "clean-v7", {
            "a.jsonl": [clean_row(f"doc/{i}") for i in range(10)]})
        assert V.main([str(root)]) == 0
        out = capsys.readouterr().out
        assert "0 leaks." in out
        assert value_free(out)
        assert "redacted" in out          # the needle table's own repr
        assert "THIN" not in out

    def test_exit_one_and_no_value_printed_on_a_leaking_tree(
            self, tmp_path: Path, fabricated_host: Needles,
            capsys: pytest.CaptureFixture[str]) -> None:
        rows = [clean_row()] + [
            {"text": spelling, "source": "fabricated", "register": "system",
             "side": "neutral", "ident": spelling}
            for spelling in PLANTED.values()]
        root = write_corpus(tmp_path / "clean-v7", {"a.jsonl": rows})
        assert V.main([str(root)]) == 1
        out = capsys.readouterr().out
        assert value_free(out)
        assert "len=" in out and "sha256=" in out
        assert "occurrence(s) of" in out
        assert "ident-path" in out

    def test_ignore_kind_changes_the_exit_code_not_the_report(
            self, tmp_path: Path, fabricated_host: Needles,
            capsys: pytest.CaptureFixture[str]) -> None:
        """``ipv4-private`` is ambiguous by construction: an RFC1918 address
        bound on this host is also every RFC's example. So it can be excluded
        from the gate -- and must still appear in the report."""
        root = write_corpus(tmp_path / "clean-v7", {
            "a.jsonl": [{"text": f"inet {SYN_V4} netmask 0xffffff00",
                         "ident": "ifconfig/1"}]})
        assert V.main([str(root)]) == 1
        capsys.readouterr()
        assert V.main([str(root), "--ignore-kind", "ipv4-private"]) == 0
        out = capsys.readouterr().out
        assert "ipv4-private" in out
        assert value_free(out)

    def test_exit_two_when_the_table_is_thin(
            self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
            capsys: pytest.CaptureFixture[str]) -> None:
        """Three exit codes, and the third is the point. ``redact_identity``
        collapses "could not verify" into "clean" and that is its fail-open; a
        gate that did the same would hand back a reassuring zero from a
        container where nothing was ever looked for."""
        thin = syn_needles(mac=[], ipv6=[], ipv4=[])
        monkeypatch.setattr(V, "host_needles", lambda **_kw: thin)
        root = write_corpus(tmp_path / "clean-v7", {"a.jsonl": [clean_row()]})
        assert V.main([str(root)]) == 2
        out = capsys.readouterr().out
        assert "THIN" in out
        assert "EXIT 2" in out
        assert value_free(out)

    def test_exit_two_beats_a_leak_because_the_count_is_not_trustworthy(
            self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
            capsys: pytest.CaptureFixture[str]) -> None:
        thin = syn_needles(mac=[])
        monkeypatch.setattr(V, "host_needles", lambda **_kw: thin)
        root = write_corpus(tmp_path / "clean-v7", {
            "a.jsonl": [{"text": f"home {SYN_HOME}", "ident": "x"}]})
        assert V.main([str(root)]) == 2
        assert value_free(capsys.readouterr().out)

    def test_allow_thin_table_restores_the_two_way_answer(
            self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
            capsys: pytest.CaptureFixture[str]) -> None:
        thin = syn_needles(mac=[])
        monkeypatch.setattr(V, "host_needles", lambda **_kw: thin)
        root = write_corpus(tmp_path / "clean-v7", {"a.jsonl": [clean_row()]})
        assert V.main([str(root), "--allow-thin-table"]) == 0
        capsys.readouterr()
        root2 = write_corpus(tmp_path / "clean-v6", {
            "a.jsonl": [{"text": f"home {SYN_HOME}", "ident": "x"}]})
        assert V.main([str(root2), "--allow-thin-table"]) == 1
        assert value_free(capsys.readouterr().out)

    def test_exit_two_when_the_instrument_fails_its_own_calibration(
            self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
            capsys: pytest.CaptureFixture[str]) -> None:
        """Check the instrument first, enforced by the instrument. A broken
        detector must not be allowed to print a reassuring zero."""
        monkeypatch.setattr(V, "host_needles", lambda **_kw: syn_needles())
        monkeypatch.setattr(V, "scan_text",
                            lambda *_a, **_k: [])
        root = write_corpus(tmp_path / "clean-v7", {"a.jsonl": [clean_row()]})
        assert V.main([str(root)]) == 2
        out = capsys.readouterr().out
        assert "failed its own calibration" in out
        assert "EXIT 2" in out

    def test_calibrate_flag_reports_and_exits_zero(
            self, capsys: pytest.CaptureFixture[str]) -> None:
        assert V.main(["--calibrate"]) == 0
        out = capsys.readouterr().out
        assert "calibration: recall" in out
        assert "MISS" not in out
        assert "FALSE POSITIVE" not in out

    def test_self_test_flag_reports_and_exits_zero(
            self, capsys: pytest.CaptureFixture[str]) -> None:
        assert V.main(["--self-test"]) == 0
        out = capsys.readouterr().out
        assert "self-test PASS" in out

    def test_a_directory_is_required(self) -> None:
        with pytest.raises(SystemExit) as excinfo:
            V.main([])
        assert excinfo.value.code == 2

    def test_an_unknown_ignore_kind_is_refused(self) -> None:
        """A scanner that can invent a kind can hide one in a typo."""
        with pytest.raises(SystemExit):
            V.main(["--ignore-kind", "not-a-kind", "."])

    def test_the_module_runs_as_a_module_and_prints_no_value(
            self, tmp_path: Path) -> None:
        """``python3 -m training.corpus.verify`` end to end, in a subprocess,
        with the real host table. The tree is a fabricated clean one, so the
        assertion is about the *printed output*, not about the exit code: on a
        host whose scratch path itself carries a needle the pass is affected by
        the ``art.real`` defect reported below, and this test deliberately does
        not depend on that.
        """
        root = write_corpus(tmp_path / "clean-v7", {"a.jsonl": [clean_row()]})
        proc = subprocess.run(
            [sys.executable, "-m", "training.corpus.verify", str(root)],
            cwd=str(Path(__file__).resolve().parents[1]),
            capture_output=True, text=True, timeout=300)
        assert proc.returncode in (0, 1, 2), proc.stderr
        blob = proc.stdout + proc.stderr
        assert "redacted" in blob
        assert "calibration: recall 1.000" in blob
        assert value_free(blob)
        assert no_host_value(blob)


def no_host_value(blob: str) -> bool:
    """No value from the *real* host table appears in ``blob``.

    Re-scanned with the live table rather than compared against a list: no
    needle ever reaches a local variable here, so the assertion can be made
    without the test becoming the next thing that has to be scrubbed. That is
    the whole argument for the module -- a report, a CI log and a test can all
    name a leak without any of them holding it.
    """
    return not scan_text(blob, needles=host_needles())


# --------------------------------------------------------------------------
# 7. calibration is honest
# --------------------------------------------------------------------------

class TestCalibrationIsHonest:
    """A calibration that always returns 1.000 is a lie with a number on it.

    ``calibrate()`` scoring 1.000/1.000 is only meaningful if a worse detector
    scores worse, so each test here breaks something specific and asserts the
    number moves in the right direction.
    """

    def test_the_shipped_calibration_is_perfect_and_non_trivial(self) -> None:
        cal = calibrate()
        assert cal.clean
        assert cal.recall == 1.0
        assert cal.precision == 1.0
        # Non-trivial: a handful of fixtures proves nothing.
        assert cal.positives >= 30
        assert cal.negatives >= 30
        assert cal.positives_found == cal.positives
        assert cal.negatives_clean == cal.negatives

    def test_the_calibration_fixtures_are_all_fabricated(self) -> None:
        """The positives must not contain a real identifier, or running
        ``--calibrate`` on any machine prints somebody's data."""
        blob = "\n".join(text for _l, _k, text in V._CAL_POSITIVES)
        blob += "\n" + "\n".join(text for _l, text in V._CAL_NEGATIVES)
        assert no_host_value(blob)

    def test_describe_states_both_numbers_and_their_denominators(self) -> None:
        text = calibrate().describe()
        assert "recall" in text and "precision" in text
        assert "constructed positives" in text
        assert "constructed negatives rejected" in text
        assert no_host_value(text)

    def test_a_detector_that_finds_nothing_scores_zero_recall(
            self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(V, "scan_text", lambda *_a, **_k: [])
        cal = calibrate()
        assert cal.recall == 0.0
        assert not cal.clean
        assert len(cal.misses) == cal.positives
        assert cal.negatives_clean == cal.negatives   # trivially

    def test_a_detector_that_flags_everything_scores_worse_precision(
            self, monkeypatch: pytest.MonkeyPatch) -> None:
        baseline = calibrate()

        def shout(text: str, **kw: object) -> list[Leak]:
            return [Leak(kind="identity", path="", line=0, field="text",
                         fingerprint="len=0,sha256=00000000")]

        monkeypatch.setattr(V, "scan_text", shout)
        cal = calibrate()
        assert cal.precision < baseline.precision
        assert not cal.clean
        assert len(cal.false_positives) == cal.negatives

    def test_a_widened_detector_is_caught_by_the_negatives(
            self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The mutation the task names: widen a detector until a documentation
        address matches. Calibration must notice, not the corpus pass."""
        widened = dict(V._CAL_NEEDLES)
        widened["ipv4"] = list(widened["ipv4"]) + ["192.0.2.1"]
        widened["ipv6"] = list(widened["ipv6"]) + ["2001:db8::1"]
        monkeypatch.setattr(
            V, "_cal_needles",
            lambda: Needles.from_values(probes=("mutant",), **widened))
        cal = calibrate()
        assert not cal.clean
        assert cal.precision < 1.0
        assert any("TEST-NET-1" in fp for fp in cal.false_positives)

    def test_a_calibration_object_with_no_fixtures_reports_zero_not_one(
            self) -> None:
        """The division-by-zero branch. A calibration with nothing in it must
        not round up to a perfect score."""
        empty = Calibration(positives=0, positives_found=0, negatives=0,
                            negatives_clean=0, misses=(), false_positives=())
        assert empty.recall == 0.0
        assert empty.precision == 0.0
        # `clean` is True with no fixtures, which is why `main` also checks
        # the needle table's own gaps -- neither signal alone is enough.
        assert empty.clean

    def test_recall_and_precision_arithmetic(self) -> None:
        cal = Calibration(positives=10, positives_found=8, negatives=10,
                          negatives_clean=8, misses=("a", "b"),
                          false_positives=("c", "d"))
        assert cal.recall == pytest.approx(0.8)
        assert cal.precision == pytest.approx(8 / 10)
        assert not cal.clean

    def test_calibration_reports_labels_and_kinds_not_matched_text(
            self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A failing calibration must name the fixture, not quote the match.

        The fixtures are synthetic so a quote would be harmless here, but the
        habit is the point: the same code path runs when somebody adds a
        fixture built from something real.
        """
        widened = dict(V._CAL_NEEDLES)
        widened["ipv4"] = list(widened["ipv4"]) + ["192.0.2.1"]
        monkeypatch.setattr(
            V, "_cal_needles",
            lambda: Needles.from_values(probes=("mutant",), **widened))
        cal = calibrate()
        assert cal.false_positives
        for report in cal.false_positives:
            label, _sep, kinds = report.partition(" -> ")
            assert any(label == lbl for lbl, _t in V._CAL_NEGATIVES), label
            # Only kind names on the right-hand side, never matched bytes.
            assert set(re.findall(r"'([^']+)'", kinds)) <= set(KINDS)
            assert "192.0.2.1" not in report
        for miss in cal.misses:
            assert any(miss.startswith(lbl)
                       for lbl, _k, _t in V._CAL_POSITIVES), miss

    def test_the_span_extent_assertions_are_load_bearing(self) -> None:
        """``_CAL_SPAN_LEN`` is the reason a kind-only calibration is not
        enough: a home path and a bare account name are both ``identity``, so
        a kind-only assertion passes whichever one the span walker picks."""
        assert V._CAL_SPAN_LEN
        table = V._cal_needles()
        for label, want in V._CAL_SPAN_LEN.items():
            text = next(t for lbl, _k, t in V._CAL_POSITIVES if lbl == label)
            lengths = {leak.fingerprint.split(",")[0]
                       for leak in scan_text(text, needles=table)}
            assert f"len={want}" in lengths, (label, sorted(lengths))

    def test_longest_span_wins_so_a_path_is_not_reported_as_a_name(
            self, needles: Needles) -> None:
        leaks = scan_text(f"cache {SYN_HOME}/Library", needles=needles)
        assert len(leaks) == 1
        assert leaks[0].fingerprint.startswith(f"len={len(SYN_HOME)},")


# --------------------------------------------------------------------------
# 8. the host probes -- asserted on counts and probe names only
# --------------------------------------------------------------------------

class TestHostProbes:
    """The one place the real machine is touched. No value is asserted on, no
    value is placed in a local, and every assertion is a count, a probe name or
    a fingerprint."""

    def test_host_needles_derives_something_and_names_its_probes(
            self) -> None:
        table = host_needles()
        assert isinstance(table, Needles)
        assert value_free(repr(table))
        assert "redacted" in repr(table)
        assert table.probes()
        assert set(table.kinds()) <= set(KINDS)

    def test_host_needles_is_not_cached(self) -> None:
        """``_identity_table`` is ``lru_cache``'d and that bites: the table is
        assembled partly from best-effort filesystem reads, so it can be
        silently thinner in one process than another and nothing says which one
        ran. A gate cheap to run has no excuse to memoise its ground truth."""
        assert host_needles() is not host_needles()

    def test_the_host_table_is_a_superset_of_the_substituters(self) -> None:
        """Folded in when ``training.trajectories`` imports, so coverage is a
        superset by construction rather than by coincidence."""
        from training.trajectories import _identity_table

        table = host_needles()
        assert "identity-table" in table.probes()
        for form, _repl in _identity_table():
            assert scan_text(f"x {form} y", needles=table), _fp(form)

    def test_no_host_probe_writes_a_value_into_its_own_report(self) -> None:
        table = host_needles()
        blob = "\n".join([repr(table), str(table), f"{table}",
                          repr(table.kinds()), repr(table.probes()),
                          repr(table.gaps()),
                          "\n".join(table.fingerprints())])
        assert not scan_text(blob, needles=table)


def _fp(value: str) -> str:
    """A report-safe label for an assertion message. Never the value."""
    return V._fingerprint(value)


# --------------------------------------------------------------------------
# 9. defects in verify.py, pinned rather than fixed
#
# This file owns tests only. Each test below is marked `xfail(strict=True)` so
# the suite stays green while the defect stands, and turns red the moment it is
# fixed -- which is the signal to delete the marker, not to re-loosen the test.
# --------------------------------------------------------------------------

class TestKnownDefects:

    def test_verify_corpus_reads_a_corpus_whose_path_is_itself_a_needle(
            self, tmp_path: Path, needles: Needles) -> None:
        root = write_corpus(tmp_path / SYN_VOLUME / "clean-v7", {
            "a.jsonl": [{"text": f"ether {SYN_MAC}", "ident": "x"}]})
        direct = scan_file(root / "a.jsonl", needles=needles)
        assert kinds_of(direct) == {"mac"}
        assert kinds_of(verify_corpus(root, needles=needles)) == {"mac"}

    def test_the_mechanism_of_that_defect_stated_as_it_stands_today(
            self, tmp_path: Path, needles: Needles) -> None:
        """``Artifact.real`` is still scrubbed, and that is now correct.

        It stays scrubbed because Artifact is rendered into reports. What
        changed is that ``verify_corpus`` no longer *reads* it:
        ``_walk_artifacts`` yields the real ``Path`` beside the report-safe
        record, so the I/O path and the display path can no longer be confused.
        This test pins the half that must not change -- a scrubbed path does not
        name a file -- which is why reading it was fatal.
        """
        root = write_corpus(tmp_path / SYN_VOLUME / "clean-v7", {
            "a.jsonl": [clean_row()]})
        art = survey(root, needles=needles).files[0]
        assert "<volume>" in art.real
        assert not Path(art.real).exists()
        assert art.real != str((root / art.name).resolve())

    def test_an_unopenable_path_is_a_finding_not_silence(
            self, tmp_path: Path, needles: Needles) -> None:
        """The other half of the same fail-open, now closed.

        ``scan_file`` used to ``return []`` on ``OSError``, which made an
        unopenable file indistinguishable from a clean one -- and that is what
        hid the scrubbed-path bug for a whole pass over 625 MB. It now returns
        an ``unreadable`` Leak so the gate fails loudly.
        """
        leaks = scan_file(tmp_path / "does-not-exist.jsonl", needles=needles)
        assert [leak.kind for leak in leaks] == ["unreadable"]
        assert leaks[0].line == 0
        assert "errno=" in leaks[0].fingerprint

    def test_an_unreadable_file_makes_a_whole_pass_report_a_finding(
            self, tmp_path: Path, needles: Needles) -> None:
        """End to end: a directory of clean files plus one unopenable file must
        not verify as clean."""
        root = write_corpus(tmp_path / "gen", {"a.jsonl": [clean_row()]})
        locked = root / "locked.jsonl"
        locked.write_text('{"text": "nothing to see"}\n', encoding="utf-8")
        locked.chmod(0o000)
        try:
            kinds = kinds_of(verify_corpus(root, needles=needles))
        finally:
            locked.chmod(0o644)
        assert "unreadable" in kinds

    def test_survey_closes_the_handles_it_opens(
            self, tmp_path: Path, needles: Needles) -> None:
        """No ResourceWarning, so ``-W error`` is usable on the gate.

        ``catch_warnings(record=True)`` rather than ``pytest.warns()``: the
        latter *requires* a warning and would fail precisely when the bug is
        fixed.
        """
        import warnings
        root = write_corpus(tmp_path / "gen", {"a.jsonl": [clean_row()]})
        with warnings.catch_warnings(record=True) as record:
            warnings.simplefilter("always")
            survey(root, needles=needles)
        assert not [w for w in record
                    if w.category is ResourceWarning], "unclosed file"


# --------------------------------------------------------------------------
# 10. this test file does not itself leak
# --------------------------------------------------------------------------

class TestThisFileDoesNotLeak:
    """The audit that found the leaks became one through its own working files.
    So the last test reads this file off disk and scans it with the live host
    table."""

    def test_the_source_of_this_file_holds_no_host_value(self) -> None:
        text = Path(__file__).resolve().read_text(encoding="utf-8")
        leaks = scan_text(text, needles=host_needles())
        assert not leaks, sorted({leak.kind for leak in leaks})

    def test_the_module_under_test_holds_no_host_value(self) -> None:
        text = Path(V.__file__).resolve().read_text(encoding="utf-8")
        leaks = scan_text(text, needles=host_needles())
        assert not leaks, sorted({leak.kind for leak in leaks})

    def test_the_module_leaks_nothing_and_that_is_now_the_pin(self) -> None:
        """This counted four occurrences on three lines while the defect stood.

        It is zero now: the three lines were rewritten through the module's own
        ``_redact_for_report``, so the prose reads ``<identity>`` and
        ``<volume>`` and says exactly what it said before. Kept as a regression
        guard rather than deleted, because ``ownrepos.py`` walks these
        repositories into the corpus as prose -- which makes this module's own
        source a candidate corpus document, and a new literal here a new leak.
        """
        leaks = scan_file(Path(V.__file__).resolve(), needles=host_needles())
        assert leaks == [], [(leak.line, leak.kind) for leak in leaks]
