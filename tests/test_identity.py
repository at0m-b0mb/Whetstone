"""Tests for the identity table: the network layer, the fail-closed path, and
the two properties that were sound and unprotected.

``tests/test_redaction.py`` already pins the question "can a document leave the
generator carrying this machine's name". This file pins the questions the audit
that followed it asked instead, and every one of them is a property of
:mod:`training.trajectories`'s identity functions rather than of the generator:

* the table reads the **network** — the addresses and hardware addresses the
  operator cannot change, which is the half that was missing;
* an empty table because a lookup **failed** is not the same thing as an empty
  table because the machine identifies nobody, and only the first may pass;
* the substituter and the verifier agree, in **both** directions, on text that
  the two case folds used to disagree about;
* a path spelled with the other separator is not clean;
* the ordering is longest-first and a second pass is a no-op.

**Every fixture in this file is synthetic**, and that is a hard rule rather
than a style. The audit that found these leaks created a new one by writing its
own needle table to a JSON file, so the values here are the ones the standards
reserve for writing down: ``2001:db8::/32`` and ``192.0.2.0/24`` for
documentation, ``00:00:5e:00:53:xx`` from RFC 7042, ``example.invalid`` for
addresses. The one place a value from this machine appears is inside an
assertion that it does *not* appear, and it is read from the table at run time
and never printed — :class:`TestNothingIsWrittenDown` is the test that enforces
that about this file and about the module itself.
"""

from __future__ import annotations

import getpass
import hashlib
import ipaddress
import os
import platform
import re
import socket
from pathlib import Path
from types import SimpleNamespace

import pytest

from training import trajectories as T

pwd = pytest.importorskip("pwd", reason="POSIX account database only")


# --------------------------------------------------------------------------
# fabricating a machine
# --------------------------------------------------------------------------

@pytest.fixture
def fresh():
    """Clear the memoised table around a test that changes what the machine is.

    Cleared on the way in *and* on the way out, so a test cannot leave a
    fabricated table behind for the rest of the session.
    ``_table_matcher`` is deliberately not cleared: it is keyed on the table it
    compiles, so a changed table cannot be answered out of the old one's cache,
    and a test that had to remember to clear a second cache is a test that will
    one day forget.
    """
    T._identity_table.cache_clear()
    T._identity_pattern.cache_clear()
    yield
    T._identity_table.cache_clear()
    T._identity_pattern.cache_clear()


def fabricate(monkeypatch, *, user="root", home="/root", gecos="root",
              hostname="localhost", temps=("/tmp",), volumes=(),
              addresses=(), failures=(), notes=()):
    """Replace every source the table reads, then clear the cache.

    One seam per source, which is why the acquisition functions are separate
    from the classifiers: a test can fabricate a machine without fabricating a
    kernel, and the classifiers can be calibrated on values no machine has.
    """
    monkeypatch.setattr(getpass, "getuser", lambda: user)
    monkeypatch.setenv("HOME", home)
    monkeypatch.setattr(pwd, "getpwuid",
                        lambda _uid: SimpleNamespace(pw_gecos=f"{gecos},,,"))
    monkeypatch.setattr(socket, "gethostname", lambda: hostname)
    monkeypatch.setattr(platform, "node", lambda: hostname)
    monkeypatch.setattr(T, "_temp_directories", lambda: (list(temps), [], []))
    monkeypatch.setattr(T, "_host_volumes", lambda: (list(volumes), [], []))
    monkeypatch.setattr(T, "_host_addresses",
                        lambda: (list(addresses), list(failures), list(notes)))
    T._identity_table.cache_clear()
    T._identity_pattern.cache_clear()


# --------------------------------------------------------------------------
# calibration: constructed before anything was pointed at the corpus
#
# An uncalibrated address scanner over 625 MB of security prose produces
# thousands of false positives and tells you nothing, because this corpus
# contains documentation addresses and reserved hardware addresses on purpose.
# So the classifiers are measured against fixtures first, and the measurement
# is an assertion rather than a paragraph.
# --------------------------------------------------------------------------

#: Hardware addresses that identify a machine. Constructed, not observed:
#: ``02:`` and ``06:`` have the locally-administered bit set, which macOS does
#: for Wi-Fi and AWDL — those are still this machine for as long as they are
#: bound, so the bit must not be used to reject. The rest count up from the
#: reserved example address.
_MAC_POSITIVE = (
    "02:00:00:11:22:33", "06:00:00:44:55:66", "0a:00:00:77:88:99",
    "0e:00:00:aa:bb:cc", "12:00:00:dd:ee:f0",
)

#: Hardware addresses that identify nobody: the null and broadcast addresses, a
#: group address, the RFC 7042 documentation range, and the made-up addresses
#: every tutorial uses.
_MAC_NEGATIVE = (
    "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:fb",
    "00:00:5e:00:53:00", "00:00:5e:00:53:42", "00:00:5e:00:53:ff",
    "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff", "12:34:56:78:9a:bc",
    "de:ad:be:ef:de:ad", "33:33:00:00:00:01", "not-a-mac",
)

#: Addresses that identify a machine. Every one is constructed here rather
#: than observed anywhere: the prefixes count up, the identifiers are
#: hand-written patterns, and ``2001:db9:`` is one hextet outside RFC 3849's
#: documentation prefix on purpose — it proves the boundary is the prefix and
#: not the shape. ``fd`` addresses are unique-local, which RFC 4193 says are
#: generated per site and routed nowhere, so a made-up one belongs to nobody.
#: The sixteen-bit identifier is the case an earlier version of the classifier
#: wrongly dropped: on a delegated prefix that is a DHCPv6 lease, not an
#: example, and the prefix entry would have rewritten the network half and left
#: the lease standing.
_V6_GLOBAL = (
    "2001:db9:1111:2222:3333:4444:5555:6666",
    "2001:db9:1111:2222::abcd",
    "2001:db9:aaaa:bbbb:1:2:3:4",
    "fd00:1111:2222:3333:4444:5555:6666:7777",
)

#: Link-local addresses with a real interface identifier. The first two are
#: EUI-64-derived — ``ff:fe`` in the middle — which is exactly why a link-local
#: address is in scope at all: it spells out a hardware address no MAC spelling
#: would catch. Both are derived from the reserved example addresses above, so
#: the derivation is visible and belongs to nobody.
_V6_LOCAL = (
    "fe80::211:22ff:fe33:4455",
    "fe80::255:66ff:fe77:8899",
    "fe80::1234:5678:9abc:def0",
)

#: Addresses that identify nobody. ``2001:db8::/32`` (RFC 3849) and
#: ``3fff::/20`` (RFC 9637) are the two prefixes the RFCs reserve for
#: documentation, ``100::`` is the discard prefix, ``2002::`` is dead 6to4, and
#: ``fe80::1`` through ``fe80::ffff`` are in every routing diagram ever drawn.
#:
#: **Mind the /20.** This fixture originally used ``3fff:1234::1``, which is
#: *not* in the documentation block: a /20 fixes the top four bits of the second
#: hextet at zero, so the range is ``3fff:0000::`` .. ``3fff:0fff:ffff:…`` and
#: anything from ``3fff:1000::`` up is ordinary global unicast. The classifier
#: was right to flag it and the fixture was wrong, which cost a precision of
#: 7/8 and read exactly like a false positive in the code.
_V6_NEGATIVE = (
    "2001:db8::1", "2001:db8:a1:1:a10b:c20d:e30f:1a2b", "2001:db8:dead:beef::5",
    "3fff:abc::1", "100::1234:5678:9abc:def0", "2002:c000:204::1",
    "2001:20:dead:beef:1:2:3:4", "::1", "::", "ff02::fb", "fe80::1",
    "fe80::2", "fe80::ffff", "not-an-address",
)

#: RFC1918 and carrier space that identifies a machine, and the documentation,
#: loopback, link-local, multicast and default space that does not. ``.1``,
#: ``.2``, ``.100`` and ``.254`` of the classic example subnets are negatives
#: because every diagram already uses them: substituting one would rewrite
#: documentation rather than remove a leak.
_V4_PRIVATE = ("10.63.17.23", "192.168.47.93", "172.19.203.17",
               "10.4.211.86", "192.168.13.37")
_V4_PUBLIC = ("100.64.0.5", "203.0.114.9")
_V4_NEGATIVE = (
    "192.0.2.1", "192.0.2.255", "198.51.100.42", "203.0.113.7", "198.18.0.1",
    "198.19.255.254", "192.0.0.8", "127.0.0.1", "169.254.1.1", "224.0.0.1",
    "0.0.0.0", "255.255.255.255", "10.0.0.1", "10.0.0.2", "10.0.0.254",
    "172.16.0.1", "172.16.0.2", "192.168.1.1", "192.168.1.100",
    "192.168.0.254", "10.10.10.10",
)

#: Dotted-quad-shaped strings that are **not negatives here**, and the reason
#: is the point. A verifier found an audit scanner routing the version string
#: ``3.0.11.2`` and the SNMP OID ``2.6.32.5`` into "public routable", and the
#: fix is not a smarter pattern — it is that the only caller of
#: :func:`~training.trajectories._identifying_ipv4` is a reader of
#: ``getifaddrs``, so a substring of prose never reaches it. Were either of
#: these genuinely bound to an interface it *would* be identity, which is what
#: the test below asserts. Anything that scans text has to answer a different
#: question and must not reuse this function to answer it.
_V4_IN_PROSE_ONLY = ("3.0.11.2", "2.6.32.5")

_VOLUME_POSITIVE = ("zephyrine-ssd", "fieldbook", "Kestrel_2024", "ananke")
_VOLUME_NEGATIVE = (
    "Macintosh HD", "Macintosh HD - Data", "Data", "Preboot", "Recovery",
    "Update", "VM", "EFI", "USB", "Backup", "Archive", "External", "Scratch",
    "Storage", "Vault", "NO NAME", "Untitled", "tmp", "home", "x",
)


def _score(predicate, positives, negatives):
    """Precision and recall of ``predicate`` over constructed fixtures."""
    true_positive = sum(1 for value in positives if predicate(value))
    false_negative = len(positives) - true_positive
    false_positive = sum(1 for value in negatives if predicate(value))
    precision = true_positive / max(true_positive + false_positive, 1)
    recall = true_positive / max(true_positive + false_negative, 1)
    return precision, recall, false_positive, false_negative


class TestClassifierCalibration:
    """Every classifier is measured before it is pointed at 625 MB.

    The failure these guard against is specific and was observed: an audit
    scanner routed the version string ``3.0.11.2`` and the SNMP OID
    ``2.6.32.5`` into "public routable", and both are in ``_V4_NEGATIVE``
    above. These classifiers cannot make that mistake because their input comes
    from the kernel rather than from text — but the fixture says so out loud,
    because the next person to reach for them may not notice the difference.
    """

    def test_mac(self):
        precision, recall, fp, fn = _score(
            T._identifying_mac, _MAC_POSITIVE, _MAC_NEGATIVE)
        assert (precision, recall) == (1.0, 1.0), (fp, fn)

    def test_ipv6(self):
        precision, recall, fp, fn = _score(
            lambda v: T._identifying_ipv6(v) is not None,
            _V6_GLOBAL + _V6_LOCAL, _V6_NEGATIVE)
        assert (precision, recall) == (1.0, 1.0), (fp, fn)

    def test_ipv6_scope(self):
        """The scope decides whether the /64 earns an entry of its own, so
        getting it backwards would either leave a delegated prefix in the
        corpus or rewrite ``fe80::`` on every machine on earth."""
        for value in _V6_GLOBAL:
            assert T._identifying_ipv6(value) == "global", value
        for value in _V6_LOCAL:
            assert T._identifying_ipv6(value) == "local", value

    def test_ipv4(self):
        precision, recall, fp, fn = _score(
            lambda v: T._identifying_ipv4(v) is not None,
            _V4_PRIVATE + _V4_PUBLIC, _V4_NEGATIVE)
        assert (precision, recall) == (1.0, 1.0), (fp, fn)

    def test_a_dotted_quad_from_prose_is_not_this_functions_input(self):
        """``3.0.11.2`` is a version string in this corpus and a routable
        address in the world, and this function answers about the world.

        It is the right answer *because of who calls it*: the only caller is
        the ``getifaddrs`` reader, so a dotted-quad-shaped substring of a
        changelog never arrives. The audit scanner that got this wrong was
        pointed at text. Asserted rather than commented, so that anyone who
        reuses this function for a text scan finds the boundary written down.
        """
        for value in _V4_IN_PROSE_ONLY:
            assert T._identifying_ipv4(value) == "public", value

    def test_ipv4_scope(self):
        for value in _V4_PRIVATE:
            assert T._identifying_ipv4(value) == "private", value
        for value in _V4_PUBLIC:
            assert T._identifying_ipv4(value) == "public", value

    def test_volume(self):
        precision, recall, fp, fn = _score(
            T._identifying_volume, _VOLUME_POSITIVE, _VOLUME_NEGATIVE)
        assert (precision, recall) == (1.0, 1.0), (fp, fn)

    def test_every_replacement_the_module_can_choose_is_a_negative(self):
        """The pools must be unreachable by the classifiers.

        A replacement a classifier calls identity would be substituted on the
        next pass, which is the deadlock the cross-pair guard exists to break —
        and it would also make a redacted corpus indistinguishable from a dirty
        one to anything downstream that re-checks.
        """
        for mac in T._DOC_MACS:
            assert not T._identifying_mac(mac), mac
        for prefix in T._DOC_V6_PREFIXES:
            for iid in T._DOC_V6_IIDS:
                value = f"{prefix}:{iid}"
                assert T._identifying_ipv6(value) is None, value
        for name in T._DOC_VOLUMES:
            assert not T._identifying_volume(name), name


# --------------------------------------------------------------------------
# the network layer
# --------------------------------------------------------------------------

class TestNetworkLayer:
    def test_a_hardware_address_is_substituted(self, monkeypatch, fresh):
        """The finding this closes: three ``anpi`` MACs in 1,770 documents of a
        built corpus, and hardware-derived, so there is no renaming them."""
        fabricate(monkeypatch, addresses=[("mac", "02:00:00:11:22:33")])
        for spelling in T._mac_forms("02:00:00:11:22:33"):
            text = f'{{"ether":"{spelling}"}}'
            assert T.identity_leaks(text), spelling
            assert spelling not in T.redact_identity(text), spelling

    def test_a_global_address_and_its_prefix_are_both_substituted(
            self, monkeypatch, fresh):
        """The prefix is the entry that reaches an address this machine never
        bound.

        The audit counted the /64 prefix 10,620 times and each individual
        address 3,540 — because two of the addresses on that prefix belong to
        *other* devices, observed over the network and impossible to enumerate
        from this machine's own interfaces. Substituting only what is bound
        leaves the subscriber line in the corpus.
        """
        bound = "2001:db9:4080:5b30:c79:3784:7ce:89a5"
        neighbour = "2001:db9:4080:5b30:dead:beef:0:1"
        fabricate(monkeypatch, addresses=[("ipv6", bound)])

        assert T.identity_leaks(bound)
        assert bound not in T.redact_identity(bound)

        # Never bound here, never enumerable, and still not allowed to carry
        # the prefix out.
        assert T.identity_leaks(neighbour)
        cleaned = T.redact_identity(neighbour)
        assert "2001:db9:4080:5b30" not in cleaned
        assert cleaned.startswith("2001:db8:")

    def test_addresses_on_one_network_keep_sharing_one_network(
            self, monkeypatch, fresh):
        """"These two addresses are on the same /64" is a fact about the text
        and a real thing to learn, so it survives redaction."""
        first = "2001:db9:4080:5b30:1111:2222:3333:4444"
        second = "2001:db9:4080:5b30:5555:6666:7777:8888"
        other = "2001:db9:9999:1111:1111:2222:3333:4444"
        fabricate(monkeypatch, addresses=[("ipv6", first), ("ipv6", second),
                                          ("ipv6", other)])
        clean = [T.redact_identity(value) for value in (first, second, other)]
        prefixes = [":".join(value.split(":")[:4]) for value in clean]
        assert prefixes[0] == prefixes[1]
        assert prefixes[2] != prefixes[0]

    def test_a_link_local_address_keeps_its_prefix(self, monkeypatch, fresh):
        """``fe80::`` is the same on every machine on earth. Rewriting it would
        be replacing a constant with a constant; the identifier is the part
        that names the interface, and on many of them it is the MAC."""
        value = "fe80::4872:76ff:fe00:1122"
        fabricate(monkeypatch, addresses=[("ipv6", value)])
        clean = T.redact_identity(value)
        assert clean.startswith("fe80::")
        assert clean != value

    def test_a_private_address_keeps_its_block(self, monkeypatch, fresh):
        """A ``10/8`` address stays a ``10/8`` address. The block is what tells
        a reader a flat home network from a routed lab, and that is signal; the
        host bits are the identity."""
        fabricate(monkeypatch, addresses=[("ipv4", "10.63.17.23"),
                                          ("ipv4", "192.168.47.93")])
        assert T.redact_identity("10.63.17.23").startswith("10.")
        assert T.redact_identity("192.168.47.93").startswith("192.168.")
        assert T.redact_identity("10.63.17.23") != "10.63.17.23"

    def test_a_volume_name_is_substituted_and_still_reads_as_one(
            self, monkeypatch, fresh):
        """``/Volumes/<owner>`` appeared in 1,776 documents. The replacement is
        a volume name rather than a hole, because the model has to learn that a
        volume path has a name in it."""
        fabricate(monkeypatch, volumes=["zephyrine-ssd"])
        clean = T.redact_identity("/Volumes/zephyrine-ssd/whetstone/corpus")
        assert "zephyrine-ssd" not in clean
        assert clean.startswith("/Volumes/")
        assert clean.endswith("/whetstone/corpus")

    def test_documentation_values_are_never_substituted(self, monkeypatch,
                                                       fresh):
        """The calibration, end to end.

        A machine that binds documentation values — a lab bridge, a CI runner
        with a reserved MAC — must contribute nothing to the table, because
        this corpus is full of those values on purpose and substituting them
        would corrupt thousands of documents to remove nothing.
        """
        fabricate(monkeypatch,
                  addresses=[("mac", mac) for mac in _MAC_NEGATIVE]
                  + [("ipv6", value) for value in _V6_NEGATIVE]
                  + [("ipv4", value) for value in _V4_NEGATIVE],
                  volumes=list(_VOLUME_NEGATIVE))
        assert T._identity_table() == ()
        assert T._identity_failures() == ()
        document = " ".join(_MAC_NEGATIVE + _V6_NEGATIVE + _V4_NEGATIVE
                            + _VOLUME_NEGATIVE)
        assert T.redact_identity(document) == document
        assert T.identity_leaks(document) == []

    def test_documentation_text_survives_an_identifying_machine(
            self, monkeypatch, fresh):
        """The other half: a machine that *does* identify itself must still
        leave the corpus's own example addresses alone."""
        fabricate(monkeypatch, user="zephyrine", home="/Users/zephyrine",
                  addresses=[("mac", "02:00:00:11:22:33"),
                             ("ipv6", "2001:db9:1:2::ea97"),
                             ("ipv4", "10.63.17.23")],
                  volumes=["fieldbook"])
        document = " ".join(_MAC_NEGATIVE + _V6_NEGATIVE + _V4_NEGATIVE)
        assert T.redact_identity(document) == document


class TestVariedReplacements:
    """Privacy is satisfied by any substitution; generalisation only by a
    varied one.

    A single ``<HOST>`` token passes every privacy gate and makes the model
    worse: 253 distinct machine literals collapsed onto one token teaches a new
    constant where there used to be a distribution. So the test is injectivity,
    not merely absence.
    """

    def test_distinct_hardware_addresses_get_distinct_replacements(
            self, monkeypatch, fresh):
        macs = [f"02:00:00:00:{n // 256:02x}:{n % 256:02x}" for n in range(24)]
        fabricate(monkeypatch, addresses=[("mac", mac) for mac in macs])
        replacements = {T.redact_identity(mac) for mac in macs}
        assert len(replacements) == len(macs)

    def test_distinct_addresses_get_distinct_replacements(self, monkeypatch,
                                                          fresh):
        values = [f"2001:db9:1:2:3:4:5:{n:x}0" for n in range(1, 17)]
        fabricate(monkeypatch,
                  addresses=[("ipv6", value) for value in values])
        replacements = {T.redact_identity(value) for value in values}
        assert len(replacements) == len(values)

    def test_the_same_literal_maps_to_the_same_replacement(self, monkeypatch,
                                                           fresh):
        """Within a build and across the children a build forks, so the text
        stays coherent: the same interface is the same interface on page two."""
        mac = "02:00:00:11:22:33"
        fabricate(monkeypatch, addresses=[("mac", mac)])
        first = T.redact_identity(mac)
        T._identity_table.cache_clear()
        T._identity_pattern.cache_clear()
        assert T.redact_identity(mac) == first

    def test_the_choice_is_digest_derived_not_hash_derived(self):
        """``hash()`` is salted per process, so two builds of one corpus would
        disagree about which replacement a literal got and the shards would
        stop being reproducible. Computed independently here rather than
        compared against a stored constant."""
        for literal in ("02:00:00:11:22:33", "2001:db9::1", "fieldbook"):
            expected = int.from_bytes(
                hashlib.sha256(literal.encode("utf-8")).digest()[:8], "big")
            assert T._digest_index(literal) == expected

    def test_an_exhausted_pool_is_a_failure_not_a_wrap_around(
            self, monkeypatch, fresh):
        """Two interfaces with the same MAC is not a world that exists.

        Reusing a replacement would keep the build running and teach the model
        a machine that cannot be built, so the pool running out is reported as
        a lookup failure and the callers refuse.
        """
        macs = [f"02:00:00:00:{n // 256:02x}:{n % 256:02x}"
                for n in range(len(T._DOC_MACS) + 1)]
        fabricate(monkeypatch, addresses=[("mac", mac) for mac in macs])
        assert "vocabulary-exhausted:mac" in T._identity_failures()
        with pytest.raises(RuntimeError, match="identity lookups failed"):
            T.redact_identity("anything")

    def test_a_pool_is_larger_than_the_count_it_has_to_cover(self):
        """The sizing rule, asserted so a later edit cannot quietly shrink a
        pool to one and reintroduce the ``<HOST>`` failure."""
        assert len(T._DOC_MACS) >= 32
        assert len(T._DOC_V6_IIDS) >= 16
        assert len(T._DOC_V6_PREFIXES) >= 8
        assert len(T._DOC_V4_TAILS) >= 12
        assert len(T._DOC_VOLUMES) >= 8


# --------------------------------------------------------------------------
# the fail-open
# --------------------------------------------------------------------------

class TestFailClosed:
    """``if pattern is None: return text`` returned Mac-captured text unchanged
    and silently whenever a lookup failed — the exact failure this module's own
    docstring calls worse than no redactor at all.

    Both branches are tested because closing it carelessly is the other
    mistake: a machine genuinely called ``operator-host`` with nothing routable
    bound is leaking nothing, and raising on it would make the module unusable
    in a container for no gain.
    """

    def test_a_machine_that_identifies_nobody_passes_through(
            self, monkeypatch, fresh):
        fabricate(monkeypatch)
        assert T._identity_table() == ()
        assert T._identity_failures() == ()
        assert T._identity_pattern() is None
        text = '{"user":"root","home":"/root","runs_as":"root"}'
        assert T.redact_identity(text) == text
        assert T.identity_leaks(text) == []

    def test_a_failed_lookup_raises_rather_than_returning_the_text(
            self, monkeypatch, fresh):
        fabricate(monkeypatch, failures=["interfaces:getifaddrs:OSError"])
        assert T._identity_table() == ()
        assert T._identity_failures() == ("interfaces:getifaddrs:OSError",)
        with pytest.raises(RuntimeError, match="identity lookups failed"):
            T.redact_identity('{"ether":"02:00:00:11:22:33"}')

    def test_a_failed_lookup_raises_even_when_the_table_is_not_empty(
            self, monkeypatch, fresh):
        """The stronger property, and the one an "empty table" framing misses.

        A table with the account name in it and no network layer looks healthy
        and certifies a document that still carries an address. What
        :func:`redact_identity` sells is "this document carries nothing of this
        machine", and a lookup that did not answer means it cannot sell it.
        """
        fabricate(monkeypatch, user="zephyrine",
                  failures=["interfaces:getifaddrs:OSError"])
        assert T._identity_table() != ()
        with pytest.raises(RuntimeError, match="identity lookups failed"):
            T.redact_identity("zephyrine")

    def test_the_verifier_refuses_too(self, monkeypatch, fresh):
        """The same fail-open reached through the checking door.

        ``lab/capture.py`` and the corpus builder call
        :func:`identity_leaks` and refuse the write on a non-empty answer. A
        verifier that answers "clean" because it could not look is the same
        hazard wearing the other hat.
        """
        fabricate(monkeypatch, failures=["interfaces:getifaddrs:OSError"])
        with pytest.raises(RuntimeError, match="nothing can be certified"):
            T.identity_leaks("02:00:00:11:22:33")

    def test_a_failure_never_carries_a_value(self, monkeypatch, fresh):
        """A failure names the lookup and the exception class. The audit that
        found these leaks created a new one by writing its needle table into a
        report, so the reporting path is tested like the redacting one."""
        fabricate(monkeypatch, user="zephyrine",
                  addresses=[("mac", "02:00:00:11:22:33")],
                  failures=["interfaces:getifaddrs:OSError"],
                  notes=["volumes:realpath:PermissionError"])
        for line in T._identity_failures() + T._identity_notes():
            assert "zephyrine" not in line
            assert "02:00" not in line
            assert re.fullmatch(r"[A-Za-z0-9_:.-]+", line), line

    def test_a_temp_candidate_that_cannot_be_classified_is_kept(self,
                                                                monkeypatch):
        """The silent half: ``except OSError: continue`` dropped exactly the
        candidate it could not rule out.

        A ``/var/folders/<x>/<28 chars>/T`` path identifies whoever owns it.
        Substituting one that turns out to belong to another account costs
        nothing; leaving one that turns out to be ours costs the corpus. So the
        unclassifiable candidate is kept and the reason recorded — and recorded
        as a note rather than a failure, because no coverage was lost and there
        is nothing for a caller to refuse over.
        """
        root = "/var/folders"
        middle = os.path.join(root, "zz")
        leaf = os.path.join(middle, "synthetic28characterconfinement")
        candidate = os.path.join(leaf, "T")
        real_scandir, real_stat = os.scandir, os.stat
        real_isdir = os.path.isdir

        class _Entry:
            def __init__(self, path: str) -> None:
                self.path = path
                self.name = os.path.basename(path)

        def scandir(path, *args, **kwargs):
            if path == root:
                return iter([_Entry(middle)])
            if path == middle:
                return iter([_Entry(leaf)])
            return real_scandir(path, *args, **kwargs)

        def stat(path, *args, **kwargs):
            if path == candidate:
                raise PermissionError(13, "fabricated")
            return real_stat(path, *args, **kwargs)

        monkeypatch.setattr(os, "scandir", scandir)
        monkeypatch.setattr(os, "stat", stat)
        monkeypatch.setattr(os.path, "isdir",
                            lambda path: path == root or real_isdir(path))
        paths, failures, notes = T._temp_directories()
        assert candidate in paths
        assert failures == []
        assert notes == ["tempdirs:stat:PermissionError"]


# --------------------------------------------------------------------------
# one matcher, no fold to disagree about
# --------------------------------------------------------------------------

#: Code points where ``re.IGNORECASE`` and ``str.lower`` disagree. U+0130 is
#: the one that matters: ``'İ'.lower()`` is two code points, so a substring
#: comparison and the regex engine answer differently about a name containing
#: ``i`` — and this account name contains one. U+212A is the Kelvin sign and
#: U+017F is the long s; both match their ASCII letter under ``re.IGNORECASE``.
_TRAPS = ("\u0130", "\u212a", "\u017f", "\u00df")


class TestOneFold:
    """The substituter used to compile with ``re.IGNORECASE`` while the
    verifier compared ``str.lower()`` substrings. They disagree in both
    directions, and both directions are a hazard: one calls a document clean
    that would have been rewritten, the other crashes the build on
    ``m.group(0).lower()`` missing from the table.

    They now share one compiled pattern and resolve by group index, so the
    property under test is not "the folds agree" but "there is one matcher":
    the verifier reports exactly what the substituter would change.
    """

    @pytest.mark.parametrize("trap", _TRAPS)
    def test_the_verifier_reports_exactly_what_the_substituter_changes(
            self, trap, monkeypatch, fresh):
        fabricate(monkeypatch, user="zephyrine")
        for text in (f"zephyr{trap}ne", "zephyrine", "ZEPHYRINE",
                     f"ZEPHYR{trap}NE", f"/home/zephyr{trap}ne/.ssh",
                     "nothing identifying here"):
            changed = T.redact_identity(text) != text
            reported = bool(T.identity_leaks(text))
            assert changed == reported, text

    def test_a_cased_trap_is_substituted_rather_than_crashing(self, monkeypatch,
                                                              fresh):
        """The live bug: the pattern matched, and the reverse lookup under
        ``m.group(0).lower()`` was not a key, so a document with this code
        point in it raised ``KeyError`` in the middle of a corpus build."""
        fabricate(monkeypatch, user="zephyrine")
        text = '{"user":"zephyr\u0130ne"}'
        clean = T.redact_identity(text)
        assert clean == '{"user":"operator"}'
        assert T.identity_leaks(clean) == []

    def test_an_upper_case_spelling_is_reported_and_substituted(
            self, monkeypatch, fresh):
        fabricate(monkeypatch, user="zephyrine")
        assert T.identity_leaks("ZEPHYRINE") == ["zephyrine"]
        assert T.redact_identity("ZEPHYRINE") == "operator"


# --------------------------------------------------------------------------
# the separator axis
# --------------------------------------------------------------------------

class TestSeparatorSpellings:
    """A separator-flattened home path was structurally ungeneratable:
    :func:`~training.trajectories._spellings` derives a backslash variant only
    when the value it was handed already has one, which is a Windows-only
    condition. ``identity_leaks`` called ``\\Users\\<name>`` clean.

    ``_spellings`` keeps its job — it is the JSON-escape axis, and a POSIX path
    really does have one escape spelling — and the separator axis is composed
    with it when the table is assembled.
    """

    def test_a_posix_path_has_a_backslash_spelling(self):
        assert T._separator_forms("/Users/alice") == [
            "/Users/alice", "\\Users\\alice"]

    def test_a_windows_path_has_a_forward_slash_spelling(self):
        assert T._separator_forms("C:\\Users\\alice") == [
            "C:\\Users\\alice", "C:/Users/alice"]

    def test_a_value_with_no_separator_has_one_spelling(self):
        for value in ("zephyrine", "02:00:00:11:22:33", "2001:db9::1"):
            assert T._separator_forms(value) == [value]

    def test_the_flattened_home_path_is_not_clean(self, monkeypatch, fresh):
        fabricate(monkeypatch, user="zephyrine", home="/Users/zephyrine")
        for text in ("/Users/zephyrine/Library/Keychains",
                     "\\Users\\zephyrine\\Library\\Keychains",
                     "\\\\Users\\\\zephyrine\\\\Library"):
            assert T.identity_leaks(text), text
            assert "zephyrine" not in T.redact_identity(text), text

    def test_the_flattened_replacement_keeps_the_separator_it_replaced(
            self, monkeypatch, fresh):
        """A backslash path must not come back with forward slashes: the model
        has to learn that a path is a path, and swapping the separator while
        swapping the name teaches it that observations change shape under
        redaction."""
        fabricate(monkeypatch, user="zephyrine", home="/Users/zephyrine")
        assert T.redact_identity("\\Users\\zephyrine\\Library") == \
            "\\Users\\operator\\Library"
        assert T.redact_identity("/Users/zephyrine/Library") == \
            "/Users/operator/Library"


# --------------------------------------------------------------------------
# the two properties that were sound and unprotected
# --------------------------------------------------------------------------

class TestOrderingAndIdempotence:
    """Both of these were confirmed sound by the audit and pinned by nothing,
    which is the state a property is in just before it stops being true."""

    def test_longest_first_on_a_fabricated_machine(self, monkeypatch, fresh):
        """Alternation in :mod:`re` is leftmost-first, not longest-first, so
        the order is what makes the longest match win. Asserted on a fabricated
        machine as well as on this one, so it holds on a reviewer's laptop and
        in a container."""
        fabricate(monkeypatch, user="zephyrine", home="/Users/zephyrine",
                  hostname="zephyr.example.invalid",
                  addresses=[("mac", "02:00:00:11:22:33"),
                             ("ipv6", "2001:db9:4080:5b30::ea97"),
                             ("ipv4", "10.63.17.23")],
                  volumes=["fieldbook"])
        lengths = [len(form) for form, _ in T._identity_table()]
        assert lengths == sorted(lengths, reverse=True)

    def test_a_full_address_outranks_its_own_prefix(self, monkeypatch, fresh):
        """The prefix is a substring of every address on it, so if it came
        first the alternation would rewrite the network half and leave the host
        half standing."""
        fabricate(monkeypatch,
                  addresses=[("ipv6", "2001:db9:4080:5b30:1:2:3:4")])
        forms = [form for form, _ in T._identity_table()]
        assert "2001:db9:4080:5b30:1:2:3:4" in forms
        assert "2001:db9:4080:5b30" in forms
        assert forms.index("2001:db9:4080:5b30:1:2:3:4") < \
            forms.index("2001:db9:4080:5b30")

    def test_every_form_is_escaped(self, monkeypatch, fresh):
        """A literal containing a regex metacharacter — ``.`` in an address,
        ``\\`` in a flattened path — must be matched as itself. An unescaped
        ``.`` would make one address match every address of the same length."""
        fabricate(monkeypatch, user="zephyrine", home="/Users/zephyrine",
                  addresses=[("ipv4", "10.63.17.23"),
                             ("mac", "02:00:00:11:22:33")],
                  volumes=["fieldbook"])
        for form, _repl in T._identity_table():
            assert re.fullmatch(re.escape(form), form), form
        pattern = T._identity_pattern()
        assert pattern.search("10x63x17x23") is None

    def test_a_second_pass_changes_nothing(self, monkeypatch, fresh):
        """14,766 already-redacted documents went through a second pass without
        one breaking, and nothing guarded it. A replacement that matched the
        pattern that produced it would rewrite the corpus on every rebuild and
        eventually deadlock the survivor check."""
        fabricate(monkeypatch, user="zephyrine", home="/Users/zephyrine",
                  hostname="zephyr.example.invalid",
                  addresses=[("mac", "02:00:00:11:22:33"),
                             ("ipv6", "2001:db9:4080:5b30::ea97"),
                             ("ipv6", "fe80::4872:76ff:fe00:1122"),
                             ("ipv4", "10.63.17.23")],
                  volumes=["fieldbook"])
        document = " ".join(form for form, _ in T._identity_table())
        once = T.redact_identity(document)
        assert T.redact_identity(once) == once
        assert T.identity_leaks(once) == []

    def test_no_replacement_contains_a_literal(self, monkeypatch, fresh):
        """The condition idempotence rests on, asserted directly.

        If a replacement contained another entry's literal the survivor check
        would fire on every document forever, and the cross-pair guard would
        break the loop by *dropping* that entry — which is a leak.
        """
        fabricate(monkeypatch, user="zephyrine", home="/Users/zephyrine",
                  addresses=[("mac", "02:00:00:11:22:33"),
                             ("ipv6", "2001:db9:4080:5b30::ea97")],
                  volumes=["fieldbook"])
        table = T._identity_table()
        joined = " ".join(repl for _form, repl in table).lower()
        for form, _repl in table:
            assert form.lower() not in joined, form


class TestThisMachine:
    """The same properties on the machine the corpus was built from.

    Nothing here prints or stores a value: the literals are read from the table
    at run time and only their count and their behaviour are asserted. A test
    that had to name one of them in order to check for it would be the leak it
    is testing for.
    """

    def test_the_table_builds_without_a_failed_lookup(self):
        assert T._identity_failures() == ()

    def test_nothing_survives_a_pass(self):
        table = T._identity_table()
        if not table:
            pytest.skip("this machine has no identifying values to leak")
        document = " ".join(form for form, _ in table)
        assert len(T.identity_leaks(document)) == len(table)
        once = T.redact_identity(document)
        assert T.identity_leaks(once) == []
        assert T.redact_identity(once) == once

    def test_the_network_layer_found_something(self):
        """The regression that matters here: the table used to have no network
        layer at all, so this assertion is the one that would have failed
        before and the one that will fail again if the reader is removed."""
        if not T._identity_table():
            pytest.skip("this machine has no identifying values to leak")
        records, failures, _notes = T._host_addresses()
        assert failures == []
        kinds = {kind for kind, _value in records}
        assert "mac" in kinds


class TestNothingIsWrittenDown:
    """The absolute rule, enforced rather than promised.

    Six working files of the audit that found these leaks wrote live addresses
    and hardware addresses to disk as cleartext literals while the report said
    it had not. So: neither this file nor the identity section of the module
    may contain one of this machine's literals, the reporting paths may not
    either, and no fixture here may be *derived* from one — which is a
    different and sneakier failure, because a derived value does not match a
    string search.
    """

    #: Where the identity section of the module starts and ends. Scoped rather
    #: than whole-file because this module also carries a CLI whose output
    #: directory default is a hardcoded ``/Volumes/<name>`` path — a real
    #: pre-existing leak, named in the test below, in a function this change
    #: is not allowed to touch.
    _SECTION = ("# redaction: what this machine is called must not reach",
                "def generate_trajectories(")

    def _section(self) -> str:
        text = Path(T.__file__).read_text(encoding="utf-8")
        return text[text.index(self._SECTION[0]):text.index(self._SECTION[1])]

    def test_the_identity_section_contains_no_literal(self):
        table = T._identity_table()
        if not table:
            pytest.skip("this machine has no identifying values to leak")
        section = self._section().lower()
        hits = [form for form, _ in table if form.lower() in section]
        assert not hits, (
            f"the identity section contains {len(hits)} of this machine's "
            "literals as cleartext; a configured list is a list of the leaks "
            "somebody already noticed and a persisted one is a new leak")

    @pytest.mark.parametrize("name", ["test_identity.py", "test_redaction.py"])
    def test_no_test_file_contains_a_literal(self, name):
        table = T._identity_table()
        if not table:
            pytest.skip("this machine has no identifying values to leak")
        text = Path(__file__).with_name(name).read_text(
            encoding="utf-8").lower()
        hits = [form for form, _ in table if form.lower() in text]
        assert not hits, f"{name} contains {len(hits)} literals as cleartext"

    def test_no_fixture_is_derived_from_one_of_this_machines_values(self):
        """The failure a string search cannot see.

        Writing this file, two "synthetic" link-local addresses and one
        "synthetic" global address were in fact this machine's, with one hextet
        changed — copied out of a probe's output while building the fixtures.
        No string comparison catches that. Comparing *components* does: an
        address shares its interface identifier, or its network half, or a MAC
        shares its OUI. Only values the classifiers call identity are compared,
        because the generic ones (``fe80::1``, ``10.0.0.1``) are shared by
        millions of hosts and are supposed to collide.
        """
        records, failures, _notes = T._host_addresses()
        if failures:
            pytest.skip("the network could not be read on this machine")
        mask = (1 << 64) - 1
        real = [ipaddress.IPv6Address(value) for kind, value in records
                if kind == "ipv6" and T._identifying_ipv6(value)]
        real_lower = {int(addr) & mask for addr in real}
        real_upper = {int(addr) >> 64 for addr in real
                      if not addr.is_link_local}
        real_ouis = {value.lower()[:8] for kind, value in records
                     if kind == "mac" and T._identifying_mac(value)}
        real_v4 = {value for kind, value in records
                   if kind == "ipv4" and T._identifying_ipv4(value)}

        for value in _V6_GLOBAL + _V6_LOCAL:
            addr = ipaddress.IPv6Address(value)
            assert (int(addr) & mask) not in real_lower, value
            assert (int(addr) >> 64) not in real_upper, value
        for value in _MAC_POSITIVE:
            assert value.lower()[:8] not in real_ouis, value
        for value in _V4_PRIVATE + _V4_PUBLIC:
            assert value not in real_v4, value

    def test_the_whole_module_contains_no_literal(self):
        """Now a passing guard rather than an xfail, because the line is fixed.

        It carried ``xfail(strict=True)`` recording that ``main()`` hardcoded a
        ``/Volumes/<name>`` path as its ``--out`` default — the same volume name
        the audit found in 1,776 corpus documents — and said "when somebody
        fixes that default this xfail starts failing, which is the point". The
        default is now the relative ``data/corpus/raw/trajectories``, matching
        how ``training/corpus/build.py`` spells its own, so the marker is gone
        and this is a plain assertion again.

        Kept rather than deleted: ``ownrepos`` used to walk this repository into
        the corpus as prose, which makes this module's own source a candidate
        corpus document, and a new literal here would be a new leak.
        """
        table = T._identity_table()
        if not table:
            pytest.skip("this machine has no identifying values to leak")
        text = Path(T.__file__).read_text(encoding="utf-8").lower()
        assert not [form for form, _ in table if form.lower() in text]

    def test_the_vocabularies_are_documentation_values(self):
        """A pool entry that was somebody's real address would make this module
        the leak. Checked against the reserved ranges rather than against a
        list of what the pools currently hold."""
        for mac in T._DOC_MACS:
            assert mac.startswith("00:00:5e:00:53:"), mac
        for prefix in T._DOC_V6_PREFIXES:
            assert ipaddress.IPv6Address(f"{prefix}::") in \
                ipaddress.ip_network("2001:db8::/32"), prefix
        for tail in T._DOC_V4_TAILS:
            assert all(2 < octet < 254 for octet in tail), tail
