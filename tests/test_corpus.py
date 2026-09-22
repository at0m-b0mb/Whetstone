"""Tests for the corpus layer.

The corpus is the part of this project that fails *silently*. A bad gate rule
raises; a bad corpus just trains a slightly worse model and nobody finds out
until a tokenizer comparison four steps downstream says 7% instead of 30%. So
the properties that matter here are pinned down rather than assumed.
"""

from __future__ import annotations

import hashlib
import importlib
import io
import itertools
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

import training.corpus.build as build_mod
from training.corpus.build import (
    DEFAULT_SOURCE_TIMEOUT,
    BuildStats,
    balance_report,
    build,
    read_documents,
)
from training.corpus.source import (
    REGISTER_TARGETS,
    Document,
    Register,
    Side,
    SourceError,
    SourceSpec,
    fingerprint,
    normalise,
)


class TestNormalise:
    """Horizontal whitespace is signal. This is the regression that matters.

    normalise() originally collapsed runs of spaces and tabs to a single space,
    which destroyed netstat column alignment (the best-scoring register against
    gpt2, +47%) and flattened YAML nesting to one space, making Sigma rule depth
    unrecoverable.
    """

    def test_column_alignment_survives(self):
        netstat = "tcp        0      0 0.0.0.0:445             0.0.0.0:*    LISTEN"
        assert normalise(netstat) == netstat

    def test_yaml_indentation_survives(self):
        rule = ("detection:\n"
                "    selection:\n"
                "        EventID: 4698\n"
                "    condition: selection")
        assert normalise(rule) == rule

    def test_nested_depth_is_distinguishable(self):
        """Four spaces and eight spaces must not become the same string."""
        out = normalise("a:\n    b: 1\n        c: 2")
        assert "\n    b" in out and "\n        c" in out

    def test_tabs_are_preserved(self):
        assert normalise("col1\tcol2\tcol3") == "col1\tcol2\tcol3"

    def test_control_bytes_are_stripped(self):
        assert normalise("man\x08page\x00text") == "manpagetext"

    def test_tab_and_newline_are_not_stripped_as_control(self):
        assert normalise("a\tb\nc") == "a\tb\nc"

    def test_trailing_whitespace_goes(self):
        assert normalise("line one   \nline two\t\t\n") == "line one\nline two"

    def test_crlf_normalised(self):
        assert normalise("a\r\nb\rc") == "a\nb\nc"

    def test_blank_line_runs_capped(self):
        assert normalise("a\n\n\n\n\n\nb") == "a\n\nb"

    def test_absurd_run_is_capped_but_still_a_gap(self):
        out = normalise("a" + " " * 500 + "b")
        assert " " * 8 in out
        assert len(out) < 100


class TestFingerprint:
    def test_whitespace_and_case_differences_collapse(self):
        """The same advisory rewrapped by two sources is one document."""
        a = "CVE-2024-21412  SmartScreen  Bypass"
        b = "cve-2024-21412\nsmartscreen\nbypass"
        assert fingerprint(a) == fingerprint(b)

    def test_different_content_differs(self):
        assert fingerprint("T1547.001") != fingerprint("T1547.002")


class TestDocument:
    def test_empty_document_refused(self):
        with pytest.raises(SourceError, match="empty document"):
            Document(text="   ", source="x", register=Register.SHELL)

    def test_carries_provenance(self):
        d = Document(text="Get-Process", source="psdocs",
                     register=Register.SHELL, side=Side.NEUTRAL, ident="a.md")
        assert d.n_chars == 11 and d.register is Register.SHELL


class TestSourceSpec:
    def _spec(self, **kw):
        base = dict(name="x", license="MIT", url="https://example.invalid",
                    register=Register.SHELL, side=Side.RED,
                    fetch=lambda p: p, documents=lambda p: iter(()))
        base.update(kw)
        return SourceSpec(**base)

    def test_blank_licence_refused(self):
        """Provenance is mandatory — an unlicensed corpus is unpublishable."""
        with pytest.raises(SourceError, match="declares no licence"):
            self._spec(license="  ")

    def test_blank_url_refused(self):
        with pytest.raises(SourceError, match="declares no url"):
            self._spec(url="")

    def test_valid_spec_builds(self):
        assert self._spec().name == "x"


class TestTargets:
    def test_register_targets_sum_to_one(self):
        assert abs(sum(REGISTER_TARGETS.values()) - 1.0) < 1e-9

    def test_every_register_has_a_target(self):
        """A register with no entry would be invisible in the balance report."""
        for reg in Register:
            assert reg in REGISTER_TARGETS

    def test_shell_and_system_dominate(self):
        """The registers the first corpus was starved of get the largest share.

        Asserted as a ranking rather than as thresholds. The earlier version
        hardcoded >= 0.25 for both and broke the moment TRAJECTORY was raised
        from 0 to 0.08 — a change that did not violate the intent at all, since
        shell and system remained the two largest. A test that fails on a
        correct change is measuring the wrong thing.
        """
        ranked = sorted(REGISTER_TARGETS.items(), key=lambda kv: -kv[1])
        top_two = {reg for reg, _share in ranked[:2]}
        assert top_two == {Register.SHELL, Register.SYSTEM}, ranked

    def test_trajectory_register_is_funded(self):
        """The task register must not sit at zero.

        It did, and the benchmark found it: action-json scored 0/5 because the
        corpus contained no trajectories at all, so the protocol tokens were in
        the vocabulary but never used. A zero here is not a neutral default, it
        is a model that never sees the job it exists to do.
        """
        assert REGISTER_TARGETS[Register.TRAJECTORY] > 0


class TestBalanceReport:
    def test_reports_share_and_drift(self):
        stats = [
            BuildStats("a", Register.SHELL, Side.RED, "MIT", docs=10, chars=600),
            BuildStats("b", Register.PROSE, Side.NEUTRAL, "MIT", docs=10, chars=400),
        ]
        out = balance_report(stats)
        assert "shell" in out and "60.0%" in out
        # PROSE at 40% against a 10% target must be flagged, not just printed.
        assert "high" in out

    def test_offence_share_computed_over_non_neutral_only(self):
        stats = [
            BuildStats("r", Register.SHELL, Side.RED, "MIT", docs=1, chars=600),
            BuildStats("b", Register.DETECTION, Side.BLUE, "DRL", docs=1, chars=400),
            BuildStats("n", Register.PROSE, Side.NEUTRAL, "MIT", docs=1, chars=9000),
        ]
        out = balance_report(stats)
        # 600/(600+400) = 60% regardless of how much neutral text exists.
        assert "60%" in out

    def test_failed_sources_are_named_not_hidden(self):
        stats = [BuildStats("broken", Register.SHELL, Side.RED, "MIT",
                            error="fetch failed: TimeoutError")]
        out = balance_report(stats)
        assert "broken" in out and "TimeoutError" in out


class TestReadDocuments:
    def _corpus(self, tmp_path: Path) -> Path:
        rows = [
            {"text": "Get-Process", "source": "a", "register": "shell", "side": "neutral", "ident": "1"},
            {"text": "EventID: 4698", "source": "b", "register": "detection", "side": "blue", "ident": "2"},
        ]
        (tmp_path / "a.jsonl").write_text(
            "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
        return tmp_path

    def test_reads_all(self, tmp_path):
        assert len(list(read_documents(self._corpus(tmp_path)))) == 2

    def test_filters_by_register(self, tmp_path):
        got = list(read_documents(self._corpus(tmp_path), registers=[Register.SHELL]))
        assert len(got) == 1 and got[0]["text"] == "Get-Process"


class TestRealSources:
    """The adapters that exist must satisfy the contract they declared."""

    def test_every_source_declares_licence_register_and_url(self):
        from training.corpus.build import discover_sources
        specs = discover_sources()
        assert specs, "no corpus sources discovered"
        for spec in specs:
            assert spec.license.strip(), spec.name
            assert spec.url.strip(), spec.name
            assert isinstance(spec.register, Register), spec.name
            assert isinstance(spec.side, Side), spec.name
            assert spec.expect_min_docs >= 1, spec.name

    def test_source_names_match_module_names(self):
        """A mismatch makes --only and the provenance table lie."""
        import importlib
        import pkgutil

        from training.corpus import sources as pkg
        for info in pkgutil.iter_modules(pkg.__path__):
            if info.name.startswith("_"):
                continue
            mod = importlib.import_module(f"{pkg.__name__}.{info.name}")
            spec = getattr(mod, "SPEC", None)
            if spec is not None:
                assert spec.name == info.name, f"{info.name} declares {spec.name!r}"


class TestNet:
    """The shared TLS helper.

    Three adapters grew their own copy of this before it was consolidated. The
    property worth pinning is not that it works — it is that it never stops
    verifying, because that is the failure mode a late-night debugging session
    introduces and nobody notices.
    """

    def test_context_verifies(self):
        import ssl as _ssl

        from training.corpus.net import ssl_context
        ctx = ssl_context()
        assert ctx.verify_mode == _ssl.CERT_REQUIRED
        assert ctx.check_hostname is True

    def test_context_is_cached(self):
        from training.corpus.net import ssl_context
        assert ssl_context() is ssl_context()

    def test_no_api_offers_to_disable_verification(self):
        """Structural: nothing here takes insecure=/verify=False."""
        import inspect

        from training.corpus import net

        banned = {"insecure", "verify", "no_verify", "unverified", "skip_tls"}
        for name in dir(net):
            obj = getattr(net, name)
            if not callable(obj) or name.startswith("_"):
                continue
            try:
                params = set(inspect.signature(obj).parameters)
            except (TypeError, ValueError):
                continue
            assert not (params & banned), f"net.{name} exposes {params & banned}"

    def test_source_never_constructs_an_unverified_context(self):
        """No adapter may reintroduce unverified TLS.

        Parsed with ast rather than grepped: several modules discuss CERT_NONE
        in prose precisely to say it is not available here, and a naive text
        search flags exactly the files that are being most careful. What matters
        is executable code, so that is what this reads.
        """
        import ast
        from pathlib import Path as _P

        root = _P(__file__).resolve().parent.parent / "training" / "corpus"
        offenders = []
        for path in sorted(root.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                # ssl.CERT_NONE / ssl._create_unverified_context referenced in code
                if isinstance(node, ast.Attribute) and node.attr in {
                    "CERT_NONE", "_create_unverified_context"
                }:
                    offenders.append(f"{path.name}:{node.lineno} {node.attr}")
                # check_hostname = False
                if isinstance(node, ast.Assign):
                    for tgt in node.targets:
                        if (isinstance(tgt, ast.Attribute)
                                and tgt.attr == "check_hostname"
                                and isinstance(node.value, ast.Constant)
                                and node.value.value is False):
                            offenders.append(f"{path.name}:{node.lineno} check_hostname=False")
        assert not offenders, f"unverified TLS in code: {offenders}"


class _FakeResponse:
    """Stand-in for an ``http.client.HTTPResponse``, delivered chunk by chunk.

    An entry in ``chunks`` that is an exception is raised instead of returned,
    which is how a truncated body is expressed here: the read that should have
    delivered the rest raises instead. ``reads`` is counted so a test can assert
    that a refusal happened *before* the body was touched.
    """

    def __init__(self, chunks, headers=None):
        self._chunks = list(chunks)
        self.headers = headers or {}
        self.reads = 0

    def read(self, amount=-1):
        self.reads += 1
        if not self._chunks:
            return b""
        item = self._chunks.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeOpener:
    """Hands back one prepared response, whatever is asked for."""

    def __init__(self, response):
        self.response = response
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append(request)
        return self.response


def _serve(monkeypatch, response):
    """Point net's cached opener at ``response`` for the duration of a test."""
    from training.corpus import net

    opener = _FakeOpener(response)
    monkeypatch.setattr(net, "_opener_cached", opener)
    return opener


class TestNetFailureContract:
    """A failed fetch is a NetworkError. No exceptions, and one in particular.

    Twenty-three adapters are written as ``except NetworkError`` and the
    contract is only worth something if it has no holes. A body that ends early
    raises ``http.client.IncompleteRead``, whose MRO is ``HTTPException ->
    Exception`` — it is not an ``OSError``, so the obvious except tuple lets the
    most ordinary network failure there is walk straight past every adapter.
    The shape it took: one flaky connection near the end of rfc.py's 9,825-file
    fetch aborted the whole source, and the build reported ``IncompleteRead``
    rather than a network error.
    """

    def test_incomplete_read_is_not_an_oserror(self):
        """The premise, pinned. If this ever changes the clauses can shrink."""
        import http.client

        assert not issubclass(http.client.IncompleteRead, OSError)
        assert issubclass(http.client.IncompleteRead, http.client.HTTPException)

    def test_truncated_body_raises_network_error(self, monkeypatch):
        import http.client

        from training.corpus import net

        _serve(monkeypatch, _FakeResponse(
            [b"half a body", http.client.IncompleteRead(b"half a body", 4000)]))
        with pytest.raises(net.NetworkError):
            net.fetch("https://example.invalid/page")

    def test_truncated_download_raises_network_error(self, monkeypatch, tmp_path):
        import http.client

        from training.corpus import net

        _serve(monkeypatch, _FakeResponse(
            [b"x" * 16, http.client.IncompleteRead(b"", 4000)]))
        with pytest.raises(net.NetworkError):
            net.download("https://example.invalid/a.tar.gz", tmp_path / "a.tar.gz")

    def test_a_failed_download_leaves_no_part_file(self, monkeypatch, tmp_path):
        """A ``.part`` left behind is a truncated cache entry waiting to happen."""
        import http.client

        from training.corpus import net

        _serve(monkeypatch, _FakeResponse(
            [b"x" * 16, http.client.IncompleteRead(b"", 4000)]))
        target = tmp_path / "cache" / "a.tar.gz"
        with pytest.raises(net.NetworkError):
            net.download("https://example.invalid/a.tar.gz", target)
        assert list(target.parent.iterdir()) == []


class TestNetRedirectPolicy:
    """Verification covers hop two as well, and secrets do not travel.

    ``context=`` protects the first request only. urllib's stock redirect
    handler allows ``http`` and ``ftp`` targets and copies every caller header
    onto the new request, so one ``302`` was enough to send nvd.py's
    ``NVD_API_KEY`` in clear text to a host this project never chose — and to do
    it silently, because from fetch()'s point of view the request succeeded and
    the body it returned was written into the corpus.
    """

    def _redirect(self, req, newurl, code=302):
        import email.message
        import io

        from training.corpus import net

        return net._HttpsOnlyRedirectHandler().redirect_request(
            req, io.BytesIO(b""), code, "Found", email.message.Message(), newurl)

    def _keyed_request(self):
        import urllib.request

        return urllib.request.Request(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            headers={"User-Agent": "whetstone-corpus", "apiKey": "SECRET-KEY"})

    def test_redirect_to_http_is_refused(self):
        import urllib.error

        with pytest.raises(urllib.error.HTTPError):
            self._redirect(self._keyed_request(), "http://collector.example/")

    def test_redirect_to_ftp_is_refused(self):
        import urllib.error

        with pytest.raises(urllib.error.HTTPError):
            self._redirect(self._keyed_request(), "ftp://collector.example/x")

    def test_cross_host_redirect_drops_the_caller_header(self):
        new = self._redirect(self._keyed_request(), "https://collector.example/x")
        assert "SECRET-KEY" not in str(new.headers)
        # The crawler still identifies itself; that is not a credential.
        assert new.headers.get("User-agent") == "whetstone-corpus"

    def test_a_different_port_is_a_different_origin(self):
        new = self._redirect(self._keyed_request(),
                             "https://services.nvd.nist.gov:8443/rest/")
        assert "SECRET-KEY" not in str(new.headers)

    def test_an_unparseable_port_strips_rather_than_keeps(self):
        """``SplitResult.port`` raises on a bad port. Unsure must mean strip."""
        new = self._redirect(self._keyed_request(),
                             "https://services.nvd.nist.gov:notaport/rest/")
        assert "SECRET-KEY" not in str(new.headers)

    def test_same_origin_redirect_keeps_the_caller_header(self):
        """Otherwise the NVD key would be dropped on NVD's own pagination."""
        new = self._redirect(self._keyed_request(),
                             "https://services.nvd.nist.gov/rest/json/cves/2.0?p=2")
        assert new.headers.get("Apikey") == "SECRET-KEY"

    def test_the_opener_speaks_only_https(self):
        """No FTP, file or data handler is reachable — by construction.

        urllib's default opener registers all three, and on any of them the
        ``context=`` argument is simply unused, so the trust store this module
        exists to establish is never consulted.
        """
        from training.corpus import net

        names = {type(h).__name__ for h in net._opener().handlers}
        assert not names & {"FTPHandler", "FileHandler", "DataHandler",
                            "HTTPHandler", "CacheFTPHandler"}
        assert "HTTPSHandler" in names

    def test_a_plaintext_url_is_refused_at_the_door(self, monkeypatch):
        from training.corpus import net

        opener = _serve(monkeypatch, _FakeResponse([b"body"]))
        with pytest.raises(net.NetworkError):
            net.fetch("http://example.invalid/page")
        assert opener.requests == []   # refused before any request was made


class TestNetCeilings:
    """A response has a size limit, enforced where the bytes arrive.

    ``fetch`` was ``return response.read()`` and ``download`` was
    ``tmp.write_bytes(fetch(...))``, so the complete body was resident before a
    byte reached disk. pythoncode's 300 MB archive ceiling — the one thing in
    the package that looked like it bounded this — was evaluated with
    ``stat()`` after the download had already finished, three statements too
    late to fire. An endless body took the machine's memory with it, which on
    this host means the training run's memory.
    """

    def test_fetch_refuses_a_body_over_the_ceiling(self, monkeypatch):
        from training.corpus import net

        _serve(monkeypatch, _FakeResponse([b"x" * 1024] * 64))
        with pytest.raises(net.NetworkError):
            net.fetch("https://example.invalid/big", max_bytes=4096)

    def test_a_body_with_no_content_length_is_still_bounded(self, monkeypatch):
        """Chunked encoding sends no length. The running total is what holds."""
        from training.corpus import net

        response = _FakeResponse([b"x" * 4096] * 1000)
        _serve(monkeypatch, response)
        with pytest.raises(net.NetworkError):
            net.fetch("https://example.invalid/endless", max_bytes=8192)
        assert response.reads < 10   # stopped early, did not drain the stream

    def test_an_oversize_content_length_is_refused_before_reading(self, monkeypatch):
        from training.corpus import net

        response = _FakeResponse([b"x" * 16],
                                 headers={"Content-Length": "20000000000"})
        _serve(monkeypatch, response)
        with pytest.raises(net.NetworkError):
            net.fetch("https://example.invalid/huge", max_bytes=1024)
        assert response.reads == 0

    def test_an_unparseable_content_length_does_not_disable_the_ceiling(self, monkeypatch):
        from training.corpus import net

        _serve(monkeypatch, _FakeResponse([b"x" * 1024] * 64,
                                          headers={"Content-Length": "banana"}))
        with pytest.raises(net.NetworkError):
            net.fetch("https://example.invalid/liar", max_bytes=4096)

    def test_download_enforces_the_ceiling_and_keeps_nothing(self, monkeypatch, tmp_path):
        from training.corpus import net

        _serve(monkeypatch, _FakeResponse([b"x" * 1024] * 64))
        target = tmp_path / "cache" / "big.tar.gz"
        with pytest.raises(net.NetworkError):
            net.download("https://example.invalid/big.tar.gz", target,
                         max_bytes=4096)
        assert list(target.parent.iterdir()) == []

    def test_a_download_within_the_ceiling_lands_whole(self, monkeypatch, tmp_path):
        from training.corpus import net

        _serve(monkeypatch, _FakeResponse([b"abc", b"def"]))
        target = tmp_path / "cache" / "ok.tar.gz"
        assert net.download("https://example.invalid/ok.tar.gz", target) == target
        assert target.read_bytes() == b"abcdef"
        assert list(target.parent.iterdir()) == [target]


class TestMetasploitSymlinks:
    """The one adapter whose transport materialises symlinks.

    Every tarball source here is protected for free by ``if not
    member.isfile(): continue``, which drops link members before they reach the
    filesystem. A symlink stored in a git tree is checked out as a real symlink,
    and this module walked the result with ``Path.rglob``, which scandirs the
    glob's own starting path — one of four fixed names under ``modules/``. A
    tree entry checking ``modules/post`` out as a link to ``$HOME`` would have
    enumerated every ``.rb`` under the user's home directory, counted them
    toward the file floor, and read them into the corpus.
    """

    def _tree(self, tmp_path):
        outside = tmp_path / "outside"
        (outside / "nested").mkdir(parents=True)
        (outside / "nested" / "stolen.rb").write_text("# not ours\n", encoding="utf-8")
        (outside / "id_rsa").write_text("-----BEGIN PRIVATE KEY-----\n", encoding="utf-8")

        checkout = tmp_path / "metasploit-framework"
        real = checkout / "modules" / "exploits" / "linux" / "local"
        real.mkdir(parents=True)
        (real / "real.rb").write_text("# a real module\n", encoding="utf-8")
        return checkout, outside

    def test_a_symlinked_tree_root_is_not_walked(self, tmp_path):
        from training.corpus.sources import metasploit

        checkout, outside = self._tree(tmp_path)
        (checkout / "modules" / "post").symlink_to(outside, target_is_directory=True)
        assert metasploit._module_files(checkout / "modules", "post") == []

    def test_a_symlinked_subdirectory_is_not_descended(self, tmp_path):
        from training.corpus.sources import metasploit

        checkout, outside = self._tree(tmp_path)
        (checkout / "modules" / "exploits" / "elsewhere").symlink_to(
            outside, target_is_directory=True)
        found = metasploit._module_files(checkout / "modules", "exploits")
        assert [p.name for p in found] == ["real.rb"]

    def test_a_symlinked_module_file_is_not_read(self, tmp_path):
        """``Path.is_file()`` follows a link, so the leaf needs its own check."""
        from training.corpus.sources import metasploit

        checkout, outside = self._tree(tmp_path)
        (checkout / "modules" / "exploits" / "linux" / "local" / "key.rb"
         ).symlink_to(outside / "id_rsa")
        found = metasploit._module_files(checkout / "modules", "exploits")
        assert [p.name for p in found] == ["real.rb"]

    def test_pruning_removes_links_and_leaves_the_tree(self, tmp_path):
        from training.corpus.sources import metasploit

        checkout, outside = self._tree(tmp_path)
        (checkout / "modules" / "post").symlink_to(outside, target_is_directory=True)
        (checkout / "modules" / "exploits" / "linux" / "local" / "key.rb"
         ).symlink_to(outside / "id_rsa")

        assert metasploit._prune_symlinks(checkout) == 2
        assert not (checkout / "modules" / "post").exists()
        assert (checkout / "modules" / "exploits" / "linux" / "local" / "real.rb").is_file()
        # The link was removed, not the file it pointed at.
        assert (outside / "id_rsa").is_file()


class TestGhsaSymlinkedAdvisories:
    """``followlinks=False`` covers the descent, not the file it lands on.

    ``os.walk`` puts symlinks-to-files in ``files`` like any other entry, and
    this is a git clone, so a link stored upstream exists on disk. An advisory
    name pointing at an ``.npmrc`` or a credentials file was matched by the
    name pattern, counted toward the floor, and opened and parsed on every
    build. The count and the read are both checked so they cannot disagree.
    """

    def _tree(self, tmp_path):
        from training.corpus.sources import ghsa

        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "creds.json").write_text('{"token": "hunter2"}', encoding="utf-8")

        root = tmp_path / "advisory-database"
        month = root / "advisories" / "reviewed" / "2026" / "09"
        (month / "GHSA-aaaa-bbbb-cccc").mkdir(parents=True)
        (month / "GHSA-aaaa-bbbb-cccc" / "GHSA-aaaa-bbbb-cccc.json").write_text(
            "{}", encoding="utf-8")
        (month / "GHSA-dddd-eeee-ffff").mkdir(parents=True)
        (month / "GHSA-dddd-eeee-ffff" / "GHSA-dddd-eeee-ffff.json").symlink_to(
            outside / "creds.json")
        return ghsa, root

    def test_a_symlinked_advisory_is_not_collected(self, tmp_path):
        ghsa, root = self._tree(tmp_path)
        names = [p.name for p in ghsa._advisory_paths(root)]
        assert names == ["GHSA-aaaa-bbbb-cccc.json"]

    def test_the_floor_counts_what_the_reader_will_read(self, tmp_path):
        ghsa, root = self._tree(tmp_path)
        assert ghsa._count_advisories(root) == len(ghsa._advisory_paths(root)) == 1


def _tar_gz(path, members):
    """Write a gzipped tar of ``{name: bytes}`` at ``path``."""
    import tarfile as _tarfile

    with _tarfile.open(path, "w:gz") as tar:
        for name, payload in members.items():
            info = _tarfile.TarInfo(name)
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))


class TestArchiveMemberCeiling:
    """One tar member may not be read into memory unbounded.

    ``target.write_bytes(stream.read())`` asks for a single allocation of
    whatever the member declares, and NUL bytes gzip at roughly 1000:1 — so an
    8 GiB member leaves the archive looking entirely ordinary on the wire and
    then asks for 8 GiB of RAM. On this machine that is a MemoryError that kills
    the build or an OOM kill that picks the training run instead.

    tldr stands in for the five adapters that shared the shape (elastic,
    splunk, atomic, lolbas, tldr) because it is the one whose fetch is a plain
    download-then-unpack with nothing else in the way. The ceiling is checked
    against ``member.size`` before extraction, which is sound rather than
    trusting: tarfile bounds the reader it hands back to exactly the declared
    length, so a member cannot deliver more than its header claims.
    """

    def _fetch_from(self, monkeypatch, tmp_path, members, ceiling):
        from training.corpus.sources import tldr

        archive = tmp_path / "prepared.tar.gz"
        _tar_gz(archive, members)

        def fake_download(url, target, **kwargs):
            target.write_bytes(archive.read_bytes())
            return target

        monkeypatch.setattr(tldr, "download", fake_download)
        monkeypatch.setattr(tldr, "_MAX_MEMBER_BYTES", ceiling)
        cache = tmp_path / "cache"
        tldr._fetch(cache)
        return cache

    def test_an_oversize_member_is_skipped_and_the_rest_arrive(self, monkeypatch, tmp_path):
        cache = self._fetch_from(monkeypatch, tmp_path, {
            "tldr-main/pages/linux/small.md": b"# small\n",
            "tldr-main/pages/linux/huge.md": b"\0" * 5000,
        }, ceiling=1000)
        assert (cache / "pages" / "linux" / "small.md").is_file()
        assert not (cache / "pages" / "linux" / "huge.md").exists()

    def test_a_member_under_the_ceiling_is_written_whole(self, monkeypatch, tmp_path):
        body = b"# a page\n" + b"x" * 500
        cache = self._fetch_from(monkeypatch, tmp_path, {
            "tldr-main/pages/linux/page.md": body,
        }, ceiling=1000)
        assert (cache / "pages" / "linux" / "page.md").read_bytes() == body

    def test_the_five_adapters_still_carry_the_guard(self):
        """Structural: ceiling present, and the unbounded read gone.

        A regression here is one edit away — ``target.write_bytes(stream.read())``
        is the shorter line and it looks harmless — so the shape is pinned as
        well as the constant.

        Parsed with ast rather than grepped, for the reason the unverified-TLS
        test above gives: the comments explaining why this shape was removed
        quote the shape, and a text search flags exactly the modules that were
        most careful to explain themselves. What matters is executable code, so
        that is what this reads.

        Named modules rather than a sweep of the package, because ast cannot
        tell a bounded read from an unbounded one and one bounded read is
        legitimate: pythoncode reads a licence member whole after proving it is
        under 128 KB. These five are the ones that had no bound at all, and
        listing them is the carve-out written down instead of implied.
        """
        import ast
        from pathlib import Path as _P

        root = _P(__file__).resolve().parents[1] / "training/corpus/sources"
        for name in ("elastic", "splunk", "atomic", "lolbas", "tldr"):
            path = root / f"{name}.py"
            body = path.read_text(encoding="utf-8")
            assert "_MAX_MEMBER_BYTES" in body, f"{name} lost its member ceiling"
            tree = ast.parse(body, filename=str(path))
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
                    f"{name}.py:{node.lineno} reads a whole archive member into "
                    "one allocation again")


class TestPrivateFetchWrappersHonourTheContract:
    """The four adapters that do not go through net still owe the same contract.

    Closing the IncompleteRead hole in the shared door does not reach the
    modules that hand-rolled their own ``urlopen``, and three of them had the
    identical except tuple: URLError, TimeoutError, OSError, and nothing for
    ``http.client.HTTPException``. A truncated body escaped each of them as an
    exception their callers do not catch.
    """

    def _truncating_urlopen(self, monkeypatch, module):
        """Make the module's urlopen raise IncompleteRead the way a peer would."""
        import http.client

        def boom(*args, **kwargs):
            raise http.client.IncompleteRead(b"half", 9000)

        monkeypatch.setattr(module.urllib.request, "urlopen", boom)

    def test_psdocs_download_reports_a_source_error(self, monkeypatch, tmp_path):
        from training.corpus.source import SourceError
        from training.corpus.sources import psdocs

        self._truncating_urlopen(monkeypatch, psdocs)
        with pytest.raises(SourceError):
            psdocs._download("https://example.invalid/a.tar.gz", tmp_path / "a.tar.gz")

    def test_sigma_download_reports_a_source_error(self, monkeypatch, tmp_path):
        from training.corpus.source import SourceError
        from training.corpus.sources import sigma

        self._truncating_urlopen(monkeypatch, sigma)
        with pytest.raises(SourceError):
            sigma._download("https://example.invalid/a.tar.gz", tmp_path / "a.tar.gz")

    def test_cisa_plain_get_reports_a_network_error(self, monkeypatch):
        from training.corpus.net import NetworkError
        from training.corpus.sources import cisa

        self._truncating_urlopen(monkeypatch, cisa)
        with pytest.raises(NetworkError):
            cisa._plain_get("https://example.invalid/kev.json")

    def test_cisa_derives_a_context_that_verifies_as_strictly(self):
        """The CA store was copied and ``verify_flags`` was not.

        A bare ``SSLContext(PROTOCOL_TLS_CLIENT)`` carries TRUSTED_FIRST alone;
        ``create_default_context`` adds PARTIAL_CHAIN and X509_STRICT. Dropping
        the last of those meant this one source accepted certificates every
        other source in the corpus rejects, while the module asserted the two
        contexts differ only in offered ciphers.
        """
        from training.corpus.net import ssl_context
        from training.corpus.sources import cisa

        derived = cisa._context()
        assert derived.verify_flags == ssl_context().verify_flags
        assert derived.verify_mode == ssl_context().verify_mode
        assert derived.check_hostname is True

    def test_atomic_keeps_no_second_copy_of_the_door(self):
        """atomic's private streaming loop is gone, not merely unused.

        It existed because ``net.download`` buffered the whole response and this
        tarball is 167 MB. ``download`` streams now, and a second copy of the
        door does not get the door's later fixes — that loop was still following
        redirects with the stock opener, which downgrades to plaintext http.
        """
        import ast
        from pathlib import Path as _P

        path = (_P(__file__).resolve().parents[1]
                / "training/corpus/sources/atomic.py")
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        calls = [n.lineno for n in ast.walk(tree)
                 if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Attribute)
                 and n.func.attr == "urlopen"]
        assert not calls, f"atomic opens its own connection again at {calls}"


class TestMetasploitGitEnvironment:
    """A build that hangs silently is worse than one that fails.

    ``capture_output`` redirects the pipes but not the controlling tty, and
    git's credential prompt reads /dev/tty. Without GIT_TERMINAL_PROMPT=0 a
    clone that meets a 401 blocks on a username prompt for the full 900s
    timeout and then reports a timeout — a message that points at the network
    rather than at the prompt that actually happened.
    """

    def test_git_runs_with_prompting_disabled(self, monkeypatch):
        import subprocess as _subprocess

        from training.corpus.sources import metasploit

        seen = {}

        def fake_run(argv, **kwargs):
            seen.update(kwargs)
            return _subprocess.CompletedProcess(argv, 0, b"", b"")

        monkeypatch.setattr(metasploit.subprocess, "run", fake_run)
        metasploit._git("clone", "https://example.invalid/x.git", "/tmp/x")
        assert seen["env"]["GIT_TERMINAL_PROMPT"] == "0"
        assert seen["env"]["GIT_LFS_SKIP_SMUDGE"] == "1"
        # The ambient environment is carried, not replaced: git needs PATH and
        # the proxy variables an operator set.
        assert "PATH" in seen["env"]


class TestPythoncodeArchiveProvenance:
    """A hash of the bytes you already have proves nothing about the right ones.

    The plaso sdist URL comes out of the PyPI JSON response, and it was taken on
    truthiness alone: no scheme check, and ``digests.sha256`` — PyPI's
    authoritative hash for exactly that artefact, in the same ``entry`` dict —
    ignored. The marker then recorded a sha256 of whatever had arrived, which
    reads like a verified checksum and is not one. Nothing else in the adapter
    covers it: the size ceiling only catches a large file, ``min_files`` only
    catches a restructured tree, and the LICENSE check only catches a missing
    licence.
    """

    def _payload(self, url, digest):
        return json.dumps({
            "info": {"version": "20260720"},
            "urls": [{"packagetype": "sdist", "url": url,
                      "digests": {"sha256": digest}}],
        }).encode("utf-8")

    def _project(self):
        from training.corpus.sources import pythoncode

        return pythoncode._Project(
            name="demo", url="https://example.invalid/demo",
            license="Apache-2.0", archive="pypi:demo", keep=("demo/",))

    def test_a_non_https_sdist_url_is_refused(self, monkeypatch):
        from training.corpus.source import SourceError
        from training.corpus.sources import pythoncode

        monkeypatch.setattr(pythoncode, "http_get", lambda *a, **k: self._payload(
            "ftp://files.example/demo.tar.gz", "a" * 64))
        with pytest.raises(SourceError, match="not"):
            pythoncode._archive_url(self._project())

    def test_the_published_digest_is_carried_back(self, monkeypatch):
        from training.corpus.sources import pythoncode

        monkeypatch.setattr(pythoncode, "http_get", lambda *a, **k: self._payload(
            "https://files.pythonhosted.org/demo.tar.gz", "b" * 64))
        url, version, digest = pythoncode._archive_url(self._project())
        assert url.startswith("https://")
        assert version == "20260720"
        assert digest == "b" * 64

    def test_an_sdist_with_no_digest_is_refused(self, monkeypatch):
        from training.corpus.source import SourceError
        from training.corpus.sources import pythoncode

        monkeypatch.setattr(pythoncode, "http_get", lambda *a, **k: self._payload(
            "https://files.pythonhosted.org/demo.tar.gz", ""))
        with pytest.raises(SourceError, match="digests.sha256"):
            pythoncode._archive_url(self._project())

    def test_a_codeload_archive_declares_no_digest_rather_than_faking_one(self):
        from training.corpus.sources import pythoncode

        project = pythoncode._Project(
            name="demo", url="https://example.invalid/demo", license="MIT",
            archive="https://codeload.github.com/x/y/tar.gz/refs/heads/main",
            keep=("y/",))
        _, _, digest = pythoncode._archive_url(project)
        assert digest == ""

    def test_a_mismatched_download_is_refused_before_it_is_unpacked(
            self, monkeypatch, tmp_path):
        """The whole point: the bytes that arrived are compared, not just hashed."""
        from training.corpus.source import SourceError
        from training.corpus.sources import pythoncode

        monkeypatch.setattr(pythoncode, "http_get", lambda *a, **k: self._payload(
            "https://files.pythonhosted.org/demo.tar.gz",
            hashlib.sha256(b"what pypi published").hexdigest()))
        monkeypatch.setattr(pythoncode, "_PROJECTS", (self._project(),))

        def fake_download(url, target, **kwargs):
            target.write_bytes(b"what the CDN served")
            return target

        monkeypatch.setattr(pythoncode, "download", fake_download)
        monkeypatch.setattr(pythoncode, "_extract", lambda *a, **k: pytest.fail(
            "unpacked an archive whose hash did not match"))

        with pytest.raises(SourceError, match="hashed to"):
            pythoncode._fetch(tmp_path / "pythoncode")

    def test_a_matching_download_is_accepted(self, monkeypatch, tmp_path):
        """The mismatch guard must not fire on the ordinary path."""
        from training.corpus.sources import pythoncode

        body = b"what pypi published"
        monkeypatch.setattr(pythoncode, "http_get", lambda *a, **k: self._payload(
            "https://files.pythonhosted.org/demo.tar.gz",
            hashlib.sha256(body).hexdigest()))
        monkeypatch.setattr(pythoncode, "_PROJECTS", (self._project(),))
        monkeypatch.setattr(pythoncode, "download",
                            lambda url, target, **k: target.write_bytes(body))

        def fake_extract(project, archive, staging):
            (staging / "files").mkdir(parents=True, exist_ok=True)
            return 10, 10

        monkeypatch.setattr(pythoncode, "_extract", fake_extract)

        root = pythoncode._fetch(tmp_path / "pythoncode")
        marker = json.loads((root / pythoncode._MARKER).read_text(encoding="utf-8"))
        entry = marker["projects"][0]
        assert entry["sha256_verified"] is True
        assert entry["archive_sha256"] == entry["expected_sha256"]

class TestShardInterleaving:
    """The validation split must be representative of the corpus.

    Needs numpy, which the data layer uses for memory-mapped shards. It is a
    dev dependency precisely so this regression is covered in ordinary CI and
    not only on a machine with the training extras installed; the skip below is
    for a minimal install, not an excuse to leave it untested.

    build.py writes one JSONL per source and they are read in sorted order, so
    an unshuffled corpus ends with whichever source sorts last. That made the
    held-out split 100% Sigma rules: validation loss measured how well the model
    predicted YAML, sat 1.3 nats above training loss, and looked exactly like
    overfitting. Nothing else in the pipeline showed it.
    """

    def _corpus(self, tmp_path):
        pytest.importorskip("numpy", reason="training.data needs numpy")
        import json as _json
        for name, body, n in (("aaa", "alpha alpha alpha", 40),
                              ("zzz", "omega omega omega", 40)):
            rows = [{"text": f"{body} {i}", "source": name,
                     "register": "prose", "side": "neutral", "ident": str(i)}
                    for i in range(n)]
            (tmp_path / f"{name}.jsonl").write_text(
                "\n".join(_json.dumps(r) for r in rows) + "\n", encoding="utf-8")
        return tmp_path

    def test_documents_are_interleaved_across_sources(self, tmp_path):
        from training.data import _interleaved

        got = list(_interleaved([self._corpus(tmp_path)], seed=1337))
        assert len(got) == 80
        # The tail must not be a single source, which is the whole bug.
        tail = {src for src, _ in got[-20:]}
        assert len(tail) == 2, f"tail is a monoculture: {tail}"

    def test_interleaving_is_deterministic(self, tmp_path):
        from training.data import _interleaved

        root = self._corpus(tmp_path)
        a = [s for s, _ in _interleaved([root], seed=7)]
        b = [s for s, _ in _interleaved([root], seed=7)]
        c = [s for s, _ in _interleaved([root], seed=8)]
        assert a == b, "same seed must give the same order"
        assert a != c, "different seeds must give different orders"

    def test_every_document_appears_exactly_once(self, tmp_path):
        from training.data import _interleaved

        texts = [t for _s, t in _interleaved([self._corpus(tmp_path)], seed=3)]
        assert len(texts) == len(set(texts)) == 80


class TestBoilerplate:
    """Corpus-wide line furniture removal, without eating diagram structure.

    The filter's whole difficulty is that packet diagrams, table borders and bit
    rulers legitimately recur thousands of times across the SYSTEM register. A
    frequency filter that counts spaces as letters flags a whitespace-padded
    ruler as prose and strips it — the exact +47% structure the corpus exists to
    keep. These tests pin the separation.
    """

    def _docs(self, n, extra=""):
        from training.corpus.source import Document, Register
        notice = "This document is subject to BCP 78 and the IETF Trust legal provisions."
        return [Document(text=f"{notice}\nUnique protocol detail number {i} here.\n{extra}",
                         source="rfc", register=Register.SYSTEM, ident=str(i))
                for i in range(n)]

    def test_legal_notice_across_many_docs_is_caught(self):
        from training.corpus.boilerplate import find_boilerplate
        bp = find_boilerplate(self._docs(40))
        assert any("bcp 78" in k for k in bp.keys)

    def test_bit_ruler_is_spared(self):
        from training.corpus.boilerplate import find_boilerplate
        ruler = "0                   1                   2                   3"
        bp = find_boilerplate(self._docs(40, extra=ruler))
        assert not any(set(k) <= set("0123 ") for k in bp.keys), \
            "a whitespace-padded bit ruler must not be treated as boilerplate"

    def test_table_border_is_spared(self):
        from training.corpus.boilerplate import find_boilerplate
        border = "|          |          |          |          |"
        bp = find_boilerplate(self._docs(40, extra=border))
        assert not any("|" in k and k.replace("|", "").strip() == "" for k in bp.keys)

    def test_stripping_does_not_weld_paragraphs(self):
        from training.corpus.boilerplate import BoilerplateFilter
        from training.corpus.boilerplate import _normalise_line
        notice = "this document is subject to bcp 78 and the ietf trust legal provisions"
        bp = BoilerplateFilter(keys=frozenset({notice}), stats={})
        text = "First real paragraph.\n" + notice.upper() + "\nSecond real paragraph."
        out = bp.strip(text)
        assert notice.upper() not in out
        assert "First real paragraph." in out and "Second real paragraph." in out
        # The two real paragraphs must stay on separate lines. Excising a notice
        # from between them must not weld them together — the same sentence-
        # welding mistake the RFC page-break handling had to be fixed for.
        lines = [ln for ln in out.split("\n") if ln.strip()]
        assert lines == ["First real paragraph.", "Second real paragraph."], lines

    def test_local_repetition_is_not_boilerplate(self):
        """A line repeated within one document is structure, not furniture."""
        from training.corpus.boilerplate import find_boilerplate
        from training.corpus.source import Document, Register
        docs = [Document(
            text="\n".join(f"    config_option_{j} = value_that_is_long_enough_here"
                           for j in range(50)),
            source="x", register=Register.SYSTEM, ident=str(i)) for i in range(3)]
        bp = find_boilerplate(docs)
        # Distinct lines, each in few docs -> nothing qualifies.
        assert bp.n_lines == 0


class TestTldrParser:
    """tldr pages are intent-to-invocation pairs, the densest SHELL form we have."""

    PAGE = """# ss

> Utility to investigate sockets.
> More information: <https://example.invalid>.

- Show all TCP sockets with service name:

`ss --tcp --all --processes`

- Filter by port:

`ss {{[-a|--all]}} sport = :{{22}}`
"""

    def test_extracts_intent_command_pairs(self):
        from training.corpus.sources.tldr import parse_page
        out = parse_page(self.PAGE, platform="linux", name="ss")
        assert "Show all TCP sockets with service name:" in out
        assert "ss --tcp --all --processes" in out
        assert "Platform: linux" in out

    def test_placeholder_braces_are_preserved(self):
        """The braces mark which span is a parameter — that is the lesson."""
        from training.corpus.sources.tldr import parse_page
        out = parse_page(self.PAGE, platform="linux", name="ss")
        assert "{{[-a|--all]}}" in out and "{{22}}" in out

    def test_page_with_no_commands_yields_nothing(self):
        from training.corpus.sources.tldr import parse_page
        assert parse_page("# empty\n\n> Just prose.\n", platform="linux", name="e") is None

    def test_malformed_page_does_not_crash(self):
        from training.corpus.sources.tldr import parse_page
        for junk in ("", "```", "- dangling intent:", "`unclosed", "#\n>\n-\n`x`"):
            parse_page(junk, platform="linux", name="j")



#: The battery runs in a process the parent is able to kill, and that is the
#: whole point rather than ceremony. A regex that has gone exponential cannot be
#: interrupted: CPython does not check for signals while ``sre`` is matching, so
#: an in-process wall clock never gets the chance to fire and the assertion
#: never runs. That is exactly how the build failed — it did not report a slow
#: source, it stopped existing — and a test suite that reproduced the hang
#: instead of reporting it would have inherited the same defect. The progress
#: line is flushed before every call so the parent can name what wedged it.
_BATTERY_RUNNER = """
import importlib.util
import json
import sys
import time

tests_path, progress_path, budget = sys.argv[1], sys.argv[2], float(sys.argv[3])

spec = importlib.util.spec_from_file_location("_whetstone_corpus_tests", tests_path)
tests = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tests)

from training.corpus.sources import windocs

case = tests.TestWindocsBacktracking
inputs = list(case.adversarial().items())
progress = open(progress_path, "w", buffering=1)
over = []


def run(name, call, label, text):
    progress.write(name + " on " + repr(label) + chr(10))
    start = time.perf_counter()
    call(text)
    spent = time.perf_counter() - start
    if spent > budget:
        over.append(name + " on " + repr(label) + ": " + format(spent, ".2f") + "s")


for name, pattern in sorted(case._patterns().items()):
    for label, text in inputs:
        run(name, lambda t, p=pattern: p.sub(case._blank, t), label, text)
for label, text in inputs:
    run("_strip_comments", windocs._strip_comments, label, text)

progress.write("finished" + chr(10))
print(json.dumps(over))
"""


class TestWindocsBacktracking:
    r"""No regex in the windocs adapter may go superlinear. This one cost a night.

    The adapter was left to build a corpus overnight and instead spun at 99.7%
    of a core for seven and a half hours without yielding a document. Every
    stack sample landed in ``sre_search`` underneath one ``re.sub``. The cause
    was the link-text alternation, written ``(?:\\.|[^\[\]])*`` — two branches
    that can both consume a backslash, so every backslash in range doubles the
    number of ways the star can match the same span. The page it died on is
    ``sysinternals/downloads/newsid.md``, which writes a literal escaped
    bracket (``**newsid /a \[newname\]**``) and then 6,139 characters of
    ordinary Windows documentation holding 27 backslashes and no ``](``
    anywhere: 2**27 paths to exhaust before the match is allowed to fail. Four
    more cached pages are shaped the same way.

    Disjoint branches fixed that one. **This test exists because inspection did
    not find the other two — measurement did.** ``_HTML_COMMENT`` and
    ``_HTML_TAG`` were each quadratic for their own reason, and neither had
    fired yet, which is the only kind of luck a build ever gets. So the rule is
    mechanical now rather than a matter of review: every compiled pattern in
    the module meets a wall clock, against input built to look like the worst
    thing a Windows documentation page could plausibly say.
    """

    #: Large enough that a quadratic pattern needs seconds where a linear one
    #: needs milliseconds — measured, the gap is three orders of magnitude — and
    #: small enough that a regression fails the suite in seconds instead of
    #: hanging it the way the build hung.
    N = 16_000

    #: The whole battery runs in 0.4 s today and its worst single case is 10 ms,
    #: so half a second is a 50x margin on the passing side, while the three
    #: spellings this replaced are 5-11x over it.
    BUDGET = 0.5

    @classmethod
    def adversarial(cls) -> dict[str, str]:
        """Text shaped like the things that actually break Markdown cleaners.

        Every entry is a real shape from this corpus taken to an unreasonable
        length, not random noise: Windows paths are why the backslash branches
        matter, escaped brackets are how a manual page writes a literal ``[``,
        and a long unbroken line is what a generated API table looks like. A
        fuzzer would have found none of these, because each one has to be *well
        formed enough* to make the pattern start matching and then never let it
        finish.
        """
        n = cls.N
        return {
            "backslash run": "\\" * n,
            "windows paths": "C:\\Windows\\System32\\drivers\\etc " * (n // 8),
            "escaped brackets": "\\[" * n,
            "escaped bracket pairs": "\\[x\\] " * (n // 4),
            "unclosed brackets": "[" * n,
            "closing brackets": "]" * n,
            "nested brackets": "[" * n + "]" * n,
            "bracket runs": "[a" * n,
            "image opens": "![" * n,
            "link opens": "[a](" * n,
            "unclosed target": "[a](" + "b\\c" * n,
            "nested parens": "[a](" + "(x)" * n,
            "paren run": "(" * n,
            "angle run": "<" * n + ">" * n,
            "tag then long line": "<a" + " " * n + "z" * n,
            "tag opens": "<a " * n,
            "comment opens": "<!--" * n,
            "comment opens then tail": "<!--x" * n + "y" * n,
            "ampersands": "&" * n,
            "entity prefixes": "&amp" * n,
            # The page that ate the night, at its real shape.
            "newsid": ("**newsid /a \\[newname\\]**\n"
                       + "SECURITY\\\\SAM\\\\Domains\\\\Account " * (n // 8)),
        }

    @staticmethod
    def _patterns() -> dict[str, re.Pattern[str]]:
        """Every compiled pattern in the module, found rather than listed.

        Enumerated out of the module's own namespace on purpose. A hand-written
        list is a list somebody forgets to extend, and forgetting is the exact
        failure this class is here to make impossible: the pattern that hung the
        build was one nobody had thought to check.
        """
        from training.corpus.sources import windocs

        found = {name: value for name, value in vars(windocs).items()
                 if isinstance(value, re.Pattern)}
        found.update({f"_FAMILIES[{key}]": value
                      for key, value in windocs._FAMILIES.items()})
        return found

    @staticmethod
    def _seconds(call, *args, repeats: int = 5) -> float:
        """Best-of-N wall clock, because the minimum is the robust estimator.

        Scheduling noise only ever ADDS time — a process descheduled mid-call
        cannot finish sooner than it would have — so the fastest of several
        runs is the closest estimate of the real cost, and the mean is not.
        That matters here because these ratios get compared against a fixed
        threshold while the machine may be saturated by a training run in
        another process, and a timing test that fails on contention is an
        instrument that cries wolf. Measured: this test passes alone and failed
        under a concurrent pretrain until the estimator was changed.
        """
        best = float("inf")
        for _ in range(repeats):
            start = time.perf_counter()
            call(*args)
            best = min(best, time.perf_counter() - start)
        return best

    @staticmethod
    def _blank(match: re.Match[str]) -> str:
        """A replacement that is valid for every pattern, group count aside."""
        return ""

    #: Comfortably more than the 1.5 s the battery needs today, and far less
    #: than the seven and a half hours it is here to prevent.
    TIMEOUT = 60

    def test_every_pattern_and_the_scanner_meet_the_clock(self, tmp_path):
        """The whole battery, in a process that can be killed if it will not stop.

        Two failures are reported differently on purpose. A pattern that is
        merely quadratic finishes and is named with its time, which is the
        common regression and the one worth a precise message. A pattern that
        has gone exponential never finishes at all, and then the timeout fires
        and the last progress line names it instead — the diagnosis the original
        hang needed a process sample to produce.
        """
        runner = tmp_path / "battery.py"
        runner.write_text(_BATTERY_RUNNER, encoding="utf-8")
        progress = tmp_path / "progress.txt"
        root = Path(__file__).resolve().parents[1]
        env = dict(os.environ, PYTHONPATH=str(root))

        try:
            done = subprocess.run(
                [sys.executable, str(runner), __file__, str(progress),
                 str(self.BUDGET)],
                cwd=root, env=env, capture_output=True, text=True,
                timeout=self.TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            seen = progress.read_text(encoding="utf-8").strip().split("\n")
            pytest.fail(
                f"the battery did not finish within {self.TIMEOUT}s. It was "
                f"still inside {seen[-1] if seen else '(nothing started)'} — "
                "that pattern is exponential, not merely slow"
            )

        assert done.returncode == 0, f"battery crashed:\n{done.stderr}"
        over = json.loads(done.stdout.strip().split("\n")[-1])
        assert not over, (
            f"patterns that went superlinear (budget {self.BUDGET}s at "
            f"n={self.N}):\n" + "\n".join(over)
        )

    def test_the_battery_covers_every_pattern_in_the_module(self):
        """A battery that silently stopped finding patterns would prove nothing."""
        patterns = self._patterns()
        assert len(patterns) >= 12, f"found only {len(patterns)} patterns"
        for required in ("_LINK", "_IMAGE", "_HTML_TAG", "_ENTITY", "_UNESCAPE"):
            assert required in patterns, f"{required} is not being exercised"

    #: The three spellings this module used to carry, kept verbatim so the clock
    #: above can be shown to have teeth. Quadrupling the input costs a linear
    #: pattern 4x and a quadratic one 16x, a gap wide enough to assert on
    #: without the flakiness of an absolute time on a loaded machine.
    PRE_FIX = {
        "_HTML_COMMENT": (
            re.compile(r"<!--.*?-->", re.DOTALL),
            lambda n: "<!--" * n,
        ),
        "_LINK": (
            re.compile(r"\[((?:\\.|[^\[\]])*)\]" + r"\((?:\\.|[^()\\])*\)"),
            lambda n: "\\[" * n,
        ),
        "_HTML_TAG": (
            re.compile(r"</?(?:span|a|p|b|i|u|br|div|code)(?:\s+[^<>]*?)?/?>",
                       re.IGNORECASE),
            lambda n: "<a" + " " * n + "z" * n,
        ),
    }

    def test_the_spellings_this_replaced_are_superlinear(self):
        """Proof the clock above is not measuring an empty room.

        Each of these is the pattern as the module actually shipped it. If a
        future edit reverts one, the test above catches it; this one checks that
        the thing being caught is real, by showing the old spelling growing with
        the square of its input where the current spelling grows with the input.
        """
        from training.corpus.sources import windocs

        current = {
            "_HTML_COMMENT": windocs._strip_comments,
            "_LINK": lambda text: windocs._LINK.sub(self._blank, text),
            "_HTML_TAG": lambda text: windocs._HTML_TAG.sub(self._blank, text),
        }
        for name, (stale, build) in self.PRE_FIX.items():
            small, large = build(1_000), build(4_000)
            was = (self._seconds(stale.sub, self._blank, large)
                   / max(self._seconds(stale.sub, self._blank, small), 1e-9))
            now = (self._seconds(current[name], large)
                   / max(self._seconds(current[name], small), 1e-9))
            assert was > 8, f"{name}: the pre-fix spelling no longer misbehaves"
            assert now < 8, (
                f"{name}: quadrupling the input cost {now:.1f}x, not ~4x — "
                "this pattern has gone superlinear again"
            )

    def test_the_link_pattern_that_hung_the_build_was_exponential(self):
        """The newsid.md shape, at a size that still finishes either way.

        Twenty-two backslashes rather than the page's twenty-seven: the old
        pattern needs 3x for every two added, so the real page is minutes and
        this is a fifteenth of a second. The current pattern does not care how
        many there are.
        """
        from training.corpus.sources import windocs

        stale = self.PRE_FIX["_LINK"][0]
        page = "**newsid /a \\[newname\\]**\n" + "SECURITY\\\\SAM " * 11
        was = self._seconds(stale.sub, self._blank, page)
        now = self._seconds(windocs._LINK.sub, self._blank, page)
        assert was > 100 * max(now, 1e-9), (
            f"the pre-fix link pattern took {was:.4f}s and the current one "
            f"{now:.6f}s — the exponential blowup is no longer reproducible, "
            "so this test has stopped proving anything"
        )

    def test_the_comment_scanner_is_the_regex_it_replaced(self):
        """Linear is only worth having if it still does the same thing."""
        from training.corpus.sources import windocs

        stale = self.PRE_FIX["_HTML_COMMENT"][0]
        for text in (
            "a<!--b-->c",
            "a<!--b-->c<!--d-->e",
            "a<!--b\nc-->d",                   # spans lines: the DOTALL case
            "a<!-- --><!-- -->b",
            "a<!--b",                          # opener with no closer: kept
            "a<!--b-->c<!--d",                 # one closed, one not
            "a-->b",                           # closer alone: kept
            "<!---->",
            "<!--<!--x-->y",                   # no nesting: the first closer wins
            "plain text with no comment at all",
        ):
            assert windocs._strip_comments(text) == stale.sub("", text), text

    def test_an_escaped_bracket_does_not_open_a_link(self):
        """``\\[`` is how these pages write a literal bracket. It is not markup.

        This is the behaviour the lookbehind adds, and it is the more faithful
        reading: the whole reason ``_clean_prose`` unescapes last is that an
        escaped bracket is deliberately not markup. Checked against the cache
        before it landed — all 5,187 pages render byte-for-byte unchanged.
        """
        from training.corpus.sources import windocs

        assert windocs._LINK.search("**newsid /a \\[newname\\]**") is None
        assert windocs._LINK.sub(r"\1", "see \\[x](y)") == "see \\[x](y)"

    def test_ordinary_links_and_images_still_collapse(self):
        from training.corpus.sources import windocs

        assert windocs._LINK.sub(r"\1", "see [the docs](/a/b) now") == "see the docs now"
        assert windocs._IMAGE.sub("", "x ![alt](media/a.png) y") == "x  y"
        # MSDN conversion escapes the parentheses inside its own targets.
        assert windocs._LINK.sub(r"\1", "[T](hh832958\\(v=vs.85\\))") == "T"
        # One level of unescaped nesting, for MSDN-era filenames.
        assert windocs._IMAGE.sub("", "![a](media/Dn783423(MSDN.10).jpg)") == ""

    def test_a_tag_still_needs_whitespace_before_its_attributes(self):
        """The rewrite kept the guard that stops e-mail addresses being eaten."""
        from training.corpus.sources import windocs

        assert windocs._HTML_TAG.sub(" ", "<p.zabel@example.com>") == "<p.zabel@example.com>"
        assert windocs._HTML_TAG.sub(" ", "<p>x</p>") == " x "
        assert windocs._HTML_TAG.sub(" ", '<a href="/x">y</a>') == " y "
        assert windocs._HTML_TAG.sub(" ", "<br/>") == " "


class TestEverySourceModuleCompiles:
    """Every module under sources/ must COMPILE, not merely parse.

    ``ast.parse`` builds a tree without enforcing the rules the compiler adds
    on top of the grammar, and the one that bites here is that ``from
    __future__`` must be the first statement in a file. A disabled adapter in
    this package was given an explanatory banner above its existing docstring,
    which turned the original docstring into a bare expression and pushed the
    future import down the file. ``ast.parse`` reported it as fine; importing
    it raised SyntaxError.

    Leading-underscore modules are the point rather than an exception. Source
    discovery skips them, and discovery also guards import errors now, so a
    broken disabled adapter is invisible twice over — until someone sweeps the
    package with ``import_module`` and it is suddenly not.
    """

    def test_all_source_modules_compile(self):
        from pathlib import Path

        root = Path(__file__).resolve().parents[1] / "training/corpus/sources"
        failures = []
        for path in sorted(root.glob("*.py")):
            try:
                compile(path.read_text(encoding="utf-8"), str(path), "exec")
            except SyntaxError as exc:
                failures.append(f"{path.name}: {exc}")
        assert not failures, "source modules that do not compile:\n" + "\n".join(failures)


# The watchdog's synthetic adapters have to live in a real, importable module.
# The child process is *spawned*, not forked, so it re-imports whatever owns
# fetch/documents by qualified name; a spec built from closures or from
# functions defined in this file's body cannot cross that boundary. Writing the
# adapter to disk is therefore not ceremony — a test that dodged the boundary
# would be testing something other than the mechanism.
_ADAPTER_PREAMBLE = """
import re
from pathlib import Path

from training.corpus.source import Document, Register, Side, SourceSpec

"""

_adapter_seq = itertools.count()


def _adapter(tmp_path: Path, monkeypatch, body: str, **spec_kwargs):
    """Materialise a throwaway adapter module and return its SPEC."""
    name = f"_whetstone_probe_{next(_adapter_seq)}"
    kwargs = dict(
        name=name,
        license="throwaway",
        url="https://example.invalid/probe",
        register="Register.PROSE",
        side="Side.NEUTRAL",
        expect_min_docs=1,
    )
    kwargs.update(spec_kwargs)
    extra = "".join(f"    {k}={v},\n" for k, v in kwargs.items()
                    if k not in {"name", "license", "url", "register", "side"})
    module = _ADAPTER_PREAMBLE + body + f"""

SPEC = SourceSpec(
    name={kwargs["name"]!r},
    license={kwargs["license"]!r},
    url={kwargs["url"]!r},
    register={kwargs["register"]},
    side={kwargs["side"]},
    fetch=_fetch,
    documents=_documents,
{extra})
"""
    (tmp_path / f"{name}.py").write_text(module, encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    importlib.invalidate_caches()
    return importlib.import_module(name).SPEC


#: Fetches instantly, yields two documents, then wedges forever inside a single
#: C-level re.sub — the outage, reproduced. The except clause is the one an
#: adapter legitimately writes and is exactly what swallows a SIGALRM-raised
#: TimeoutError, which is why the enforcement has to be a kill.
_HANGING = """
_EVIL = re.compile(r"(a+)+$")
_SUBJECT = "a" * 40 + "b"


def _fetch(cache_dir: Path) -> Path:
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def _documents(path: Path):
    for i in range(2):
        yield Document(text="a real document, long enough to clear min_chars, no %d" % i,
                       source=__name__.rsplit(".", 1)[-1],
                       register=Register.PROSE, side=Side.NEUTRAL, ident=str(i))
    while True:
        try:
            _EVIL.sub("x", _SUBJECT)
        except (OSError, UnicodeDecodeError):
            continue
"""

#: Well-behaved: three documents whose text deliberately carries the surface
#: structure this corpus exists to preserve.
_HEALTHY = """
_ROWS = [
    "tcp        0      0 0.0.0.0:445             0.0.0.0:*    LISTEN",
    "detection:\\n    selection:\\n        EventID: 4698\\n    condition: selection",
    "col1\\tcol2\\tcol3  —  naïve ünicode, ATT&CK T1547.001, CVE-2024-21412",
]


def _fetch(cache_dir: Path) -> Path:
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def _documents(path: Path):
    for i, row in enumerate(_ROWS):
        yield Document(text=row, source=__name__.rsplit(".", 1)[-1],
                       register=Register.SHELL, side=Side.RED, ident=str(i))
"""


class TestSourceWatchdog:
    """A source that never returns must not be able to hang the build.

    The build already survived a source that *raises*. It had no answer for one
    that simply never comes back: an adapter hit catastrophic regex backtracking
    and held a core at 99.7% for seven and a half hours with no output, taking
    the overnight training run with it.

    An in-process signal timeout does not fix this, and the reason is worth
    keeping written down. On CPython 3.13 a backtracking ``re.sub`` on the main
    thread *is* interruptible — SRE polls for signals inside its own loop — so
    the usual explanation is out of date. What actually defeats it is that
    ``TimeoutError`` is an ``OSError``, so the exception lands in the adapter's
    own ``except (OSError, UnicodeDecodeError): continue`` and is discarded;
    measured, that ran 52s under a 2s alarm. Enforcement has to be somewhere the
    adapter cannot catch it, which means another process and a kill.
    """

    def _build(self, tmp_path, monkeypatch, specs, **kwargs):
        monkeypatch.setattr(build_mod, "discover_sources", lambda: list(specs))
        kwargs.setdefault("max_source_share", 0.0)   # a 1-source corpus is 100%
        return build(tmp_path / "out", tmp_path / "cache", **kwargs)

    def test_hanging_source_is_killed_and_the_build_completes(self, tmp_path, monkeypatch):
        """The whole point: the build returns at all, and says why."""
        spec = _adapter(tmp_path, monkeypatch, _HANGING)
        started = time.monotonic()
        stats = self._build(tmp_path, monkeypatch, [spec], source_timeout=2.0)
        elapsed = time.monotonic() - started

        # Left alone this source runs for hours. Anything that returns has killed it.
        assert elapsed < 90, f"the watchdog did not stop the source ({elapsed:.0f}s)"
        assert len(stats) == 1
        assert "TIMED OUT" in stats[0].error, stats[0].error

    def test_timed_out_source_contributes_nothing(self, tmp_path, monkeypatch):
        """A truncated prefix is worse than an absent source.

        The hanging adapter yields two perfectly good documents before it
        wedges. Admitting them would quietly change the corpus composition by
        however far a source happened to get before the clock ran out, and the
        balance report would describe that as though it were the source.
        """
        spec = _adapter(tmp_path, monkeypatch, _HANGING)
        stats = self._build(tmp_path, monkeypatch, [spec], source_timeout=2.0)
        assert stats[0].docs == 0 and stats[0].chars == 0
        assert not (tmp_path / "out" / f"{spec.name}.jsonl").exists()

    def test_timeout_is_relisted_after_the_balance_report(self, tmp_path, monkeypatch, capsys):
        """Follows the _IMPORT_FAILURES precedent, for the same reason.

        In the report above, a source that was killed at the deadline and a
        source whose upstream is empty look identical, and they have nothing in
        common as fixes.
        """
        spec = _adapter(tmp_path, monkeypatch, _HANGING)
        self._build(tmp_path, monkeypatch, [spec], source_timeout=2.0)
        out = capsys.readouterr().out

        assert "EXCEEDED THE TIME BUDGET" in out
        # After the report, not buried in the scroll above it.
        assert out.index("EXCEEDED THE TIME BUDGET") > out.index("register coverage")
        assert spec.name in out.split("EXCEEDED THE TIME BUDGET", 1)[1]

    def test_healthy_source_is_unaffected(self, tmp_path, monkeypatch):
        """The watchdog must be invisible when nothing times out."""
        spec = _adapter(tmp_path, monkeypatch, _HEALTHY)
        stats = self._build(tmp_path, monkeypatch, [spec], min_chars=1)
        assert stats[0].error == ""
        assert stats[0].docs == 3, stats[0]

    def test_isolated_and_in_process_paths_agree_exactly(self, tmp_path, monkeypatch):
        """Same documents, same bytes, whether or not the watchdog is armed.

        ``--source-timeout 0`` keeps the pre-watchdog path for debugging, and
        two code paths that can disagree are a bug waiting to happen. They share
        the dedup loop; this pins the rest.
        """
        out = {}
        for label, timeout in (("isolated", DEFAULT_SOURCE_TIMEOUT), ("in_process", 0.0)):
            root = tmp_path / label
            spec = _adapter(tmp_path, monkeypatch, _HEALTHY)
            monkeypatch.setattr(build_mod, "discover_sources", lambda s=spec: [s])
            build(root / "out", root / "cache", min_chars=1, max_source_share=0.0,
                  source_timeout=timeout)
            out[label] = [dict(r, source="") for r in read_documents(root / "out")]
        assert out["isolated"] == out["in_process"] != []

    def test_structure_survives_the_process_boundary(self, tmp_path, monkeypatch):
        """Horizontal whitespace is signal, and now it crosses a JSONL hop.

        Column alignment scored +47% against gpt2 and YAML indentation carries
        Sigma rule depth. The child serialises documents to a temporary JSONL
        rather than a Queue, so this is the one place the new machinery could
        quietly mangle text that ``normalise`` went to such lengths to keep.
        """
        spec = _adapter(tmp_path, monkeypatch, _HEALTHY)
        self._build(tmp_path, monkeypatch, [spec], min_chars=1)
        texts = [r["text"] for r in read_documents(tmp_path / "out")]

        assert any("tcp        0      0 0.0.0.0:445" in t for t in texts), texts
        assert any("\n        EventID: 4698" in t for t in texts), texts
        assert any("col1\tcol2\tcol3" in t and "naïve ünicode" in t for t in texts), texts

    def test_per_source_override_beats_the_build_wide_budget(self, tmp_path, monkeypatch):
        """SourceSpec.timeout exists so a slow source need not raise everyone's."""
        spec = _adapter(tmp_path, monkeypatch, _HANGING, timeout=2.0)
        assert spec.timeout == 2.0
        started = time.monotonic()
        stats = self._build(tmp_path, monkeypatch, [spec], source_timeout=36_000.0)
        elapsed = time.monotonic() - started
        assert "TIMED OUT" in stats[0].error
        assert elapsed < 90, "the spec's own budget was ignored"

    def test_default_budget_clears_the_slowest_healthy_source(self):
        """rfc's fetch alone runs past eight minutes; a watchdog that fires on a
        healthy source silently removes a register and the report cannot tell
        you which of the two happened."""
        assert DEFAULT_SOURCE_TIMEOUT >= 3 * 8 * 60


#: Fails in fetch, immediately and cleanly — the ordinary way an upstream goes
#: away: a 404, a DNS failure, an expired certificate. The build has always
#: survived this; what it did not survive is what the *previous* build left on
#: disk underneath it.
_FAILING_FETCH = """
def _fetch(cache_dir: Path) -> Path:
    raise RuntimeError("upstream is gone")


def _documents(path: Path):
    yield Document(text="never reached, but long enough to clear min_chars",
                   source=__name__.rsplit(".", 1)[-1],
                   register=Register.PROSE, side=Side.NEUTRAL, ident="0")
"""

#: Three documents carrying the adapter's own module name, so that two
#: instances of it in one build are not collapsed into one by the fingerprint
#: dedup — which is what happens with _HEALTHY and would quietly turn a
#: two-source test into a one-source test.
_DISTINCT = """
def _fetch(cache_dir: Path) -> Path:
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def _documents(path: Path):
    me = __name__.rsplit(".", 1)[-1]
    for i in range(3):
        yield Document(text="%s document %d, long enough to clear min_chars" % (me, i),
                       source=me, register=Register.PROSE, side=Side.NEUTRAL,
                       ident=str(i))
"""


def _docs(name: str, count: int, size: int, register=Register.PROSE) -> list[Document]:
    """``count`` documents of ``size`` characters each, attributed to ``name``."""
    return [Document(text="x" * size, source=name, register=register,
                     side=Side.NEUTRAL, ident=f"{name}-{i}") for i in range(count)]


def _stats_for(collected: dict[str, list[Document]]) -> list[BuildStats]:
    """The BuildStats build() would be holding at the point the caps run."""
    return [BuildStats(name=name, register=docs[0].register, side=docs[0].side,
                       license="throwaway", docs=len(docs),
                       chars=sum(d.n_chars for d in docs))
            for name, docs in collected.items()]


class TestSourceCapReachesTheShareItPrints:
    """A cap that reports success without capping is worse than no cap.

    The ceiling was computed once, from the total as it stood *before* any
    trimming. Trimming shrinks the corpus, so every surviving source's share
    rises afterwards — and the print then quoted the number that had been asked
    for rather than the one the corpus ended up at. With rfc at 64% of 789k
    chars under a 30% cap, the build discarded 40% of the corpus, left rfc at
    50% of what remained, and reported that it had "trimmed to the 30%
    ceiling". _cap_register_share had already found this exact defect and
    answered it with a fixed point; this cap, the one that is on by default,
    kept the single pass.
    """

    def test_the_largest_source_ends_at_the_requested_share(self):
        collected = {
            "rfc": _docs("rfc", 5050, 100),
            "a": _docs("a", 800, 100), "b": _docs("b", 900, 100),
            "c": _docs("c", 700, 100), "d": _docs("d", 600, 100),
            "e": _docs("e", 500, 100),
        }
        stats = _stats_for(collected)
        build_mod._cap_source_share(collected, stats, 0.30)

        total = sum(s.chars for s in stats if s.docs)
        share = {s.name: s.chars / total for s in stats}
        # The single pass left this at 42%, not 30%.
        assert share["rfc"] == pytest.approx(0.30, abs=0.005), share
        # And it is a cap, not a haircut for everyone: nothing under the ceiling
        # is touched.
        assert [len(collected[n]) for n in "abcde"] == [800, 900, 700, 600, 500]

    def test_several_sources_over_the_cap_all_land_on_it(self):
        """Three over the ceiling at once was the order-dependent case.

        Each was trimmed to the same absolute ceiling derived from a total that
        no longer existed, so they came out at 32% apiece — over the cap, by an
        amount that grew with the number of sources exceeding it.
        """
        collected = {
            "big1": _docs("big1", 4000, 100), "big2": _docs("big2", 3800, 100),
            "big3": _docs("big3", 3600, 100), "small": _docs("small", 400, 100),
            "tiny": _docs("tiny", 100, 100),
        }
        stats = _stats_for(collected)
        build_mod._cap_source_share(collected, stats, 0.30)

        total = sum(s.chars for s in stats if s.docs)
        for name in ("big1", "big2", "big3"):
            st = next(s for s in stats if s.name == name)
            assert st.chars / total == pytest.approx(0.30, abs=0.005), name

    def test_an_unreachable_cap_trims_nothing_and_says_so(self, capsys):
        """Two sources cannot both sit under 30% of one corpus.

        The single pass did not know that and answered anyway: it trimmed both
        to a ceiling derived from a total that the trim itself destroyed, threw
        away 40% of the corpus, and left the largest source at 50% — further
        from the cap than doing nothing, while printing that it had capped.
        """
        collected = {"rfc": _docs("rfc", 505, 1000), "other": _docs("other", 284, 1000)}
        stats = _stats_for(collected)
        build_mod._cap_source_share(collected, stats, 0.30)

        assert [s.docs for s in stats] == [505, 284], "it trimmed toward a ceiling of zero"
        out = capsys.readouterr().out
        assert "SOURCE CAP NOT APPLIED" in out
        assert "64%" in out, "it must say where the largest source actually stands"

    def test_build_refuses_a_cap_it_cannot_meet_before_it_fetches(self, tmp_path, monkeypatch):
        """`--only sigma` against the default 30% is arithmetic with no answer.

        It used to be answered anyway, by deleting 70% of the one source it had
        been asked to build. The condition is knowable from the flags alone, so
        it is refused before the first byte is downloaded rather than after an
        hour of them.
        """
        spec = _adapter(tmp_path, monkeypatch, _HEALTHY)
        monkeypatch.setattr(build_mod, "discover_sources", lambda: [spec])
        with pytest.raises(SystemExit, match="cannot be met"):
            build(tmp_path / "out", tmp_path / "cache", min_chars=1,
                  max_source_share=0.30)
        assert not (tmp_path / "cache" / spec.name).exists(), "it fetched first"


class TestRegisterCapSharesTheCeiling:
    """A register's ceiling is divided between its sources, not raced for.

    The trim ran off one shared per-register counter, walking `collected` in
    discover_sources()' name order, so whichever source sorted first consumed
    the entire ceiling and the ones behind it were dropped document by document
    until nothing was left. Measured against the real corpus at
    `--max-register-multiple 1.0`, that removed manpages and capec from the
    build outright — and a source reduced to zero carries docs=0, chars=0 and
    error="", so balance_report's register table (`[s for s in stats if
    s.docs]`) skipped it and the failure list (`[s for s in stats if s.error]`)
    skipped it too. Two whole upstreams left the corpus and nothing said so.
    """

    def _corpus(self):
        # Both SYSTEM, in the proportion the defect was found at: kerneldocs
        # sorts first and is five times the size of manpages (34.8M against
        # 7.0M in the corpus this came out of).
        return {
            "kerneldocs": _docs("kerneldocs", 350, 1000, Register.SYSTEM),
            "manpages": _docs("manpages", 70, 1000, Register.SYSTEM),
            "sigma": _docs("sigma", 100, 1000, Register.DETECTION),
        }

    #: Only two registers are present here, covering 0.37 of the target mix, so
    #: the multiple has to clear 1/0.37 for the cap to be reachable at all —
    #: below that every register is over its ceiling at every size and the
    #: ceiling solves to zero. 3.0 puts SYSTEM over and leaves DETECTION whole,
    #: which is the shape the starvation needs.
    MULTIPLE = 3.0

    def test_the_smaller_source_is_not_starved_by_the_one_that_sorts_first(self):
        collected = self._corpus()
        stats = _stats_for(collected)
        build_mod._cap_register_share(collected, stats, self.MULTIPLE)

        by = {s.name: s for s in stats}
        assert by["manpages"].docs == 70, "the smaller SYSTEM source paid for the larger one"
        assert by["kerneldocs"].docs < 350, "the cap did not bite at all"
        assert by["sigma"].docs == 100, "an uncapped register was trimmed"

    def test_a_source_a_cap_empties_is_named(self):
        """Loudness is the second half of the fix, and it outlives the first.

        Sharing the ceiling makes starvation unlikely rather than impossible —
        a ceiling small enough still zeroes a source. The report only ever looks
        at `docs` and `error`, so the source has to appear in one of them or it
        appears nowhere.
        """
        collected = {"kerneldocs": _docs("kerneldocs", 350, 1000, Register.SYSTEM),
                     "manpages": _docs("manpages", 70, 1000, Register.SYSTEM)}
        stats = _stats_for(collected)
        build_mod._note_if_emptied(stats[1], 70, [], "--max-register-multiple 1.0")
        assert "0 documents" in stats[1].error
        assert "manpages" in balance_report(stats)

    def test_per_source_drops_are_printed_not_only_register_totals(self, capsys):
        """_apply_balance already reports who paid; this did not.

        A register's before/after totals cannot tell you which source lost,
        and which source lost is the thing that goes wrong here.
        """
        collected = self._corpus()
        build_mod._cap_register_share(collected, _stats_for(collected), self.MULTIPLE)
        out = capsys.readouterr().out
        assert "kerneldocs" in out.split("register cap at", 1)[1]

    def test_a_cap_that_solves_to_zero_is_refused(self, capsys):
        """The same reachability trap the source cap has, one level up.

        With only DETECTION present, `--max-register-multiple 1.6` gives a
        ceiling of 0.13 x 1.6 of a total that the cap itself keeps shrinking:
        the iteration is a contraction onto zero, and ten passes of it leave a
        ceiling that deletes the corpus.
        """
        collected = {"sigma": _docs("sigma", 100, 1000, Register.DETECTION)}
        stats = _stats_for(collected)
        build_mod._cap_register_share(collected, stats, 1.6)

        assert stats[0].docs == 100, "the cap solved to zero and deleted the corpus"
        assert "REGISTER CAP NOT APPLIED" in capsys.readouterr().out


class TestTheDirectoryAndTheReportDescribeOneCorpus:
    """What is on disk after a build is what the balance report just described.

    Nothing removed anything from out_dir, and read_documents() globs *.jsonl
    unconditionally. So a source that timed out, failed its fetch or was emptied
    by a cap kept its *previous* build's documents in the corpus, while the
    report — built from this run's stats — recorded it as contributing nothing.
    The watchdog's guarantee, "skipped and named is honest; truncated and
    counted is not", held in memory and not on disk: the shards, the tokenizer
    and every measurement downstream follow the directory, not the report.
    """

    def _build(self, tmp_path, monkeypatch, specs, **kw):
        monkeypatch.setattr(build_mod, "discover_sources", lambda: list(specs))
        kw.setdefault("min_chars", 1)
        kw.setdefault("max_source_share", 0.0)
        return build(tmp_path / "out", tmp_path / "cache", **kw)

    def test_a_failed_source_loses_its_previous_build(self, tmp_path, monkeypatch, capsys):
        good = _adapter(tmp_path, monkeypatch, _DISTINCT)
        self._build(tmp_path, monkeypatch, [good])
        path = tmp_path / "out" / f"{good.name}.jsonl"
        assert path.is_file(), "the first build wrote nothing to fail over"

        broken = _adapter(tmp_path, monkeypatch, _FAILING_FETCH, name=good.name)
        stats = self._build(tmp_path, monkeypatch, [broken])

        assert stats[0].docs == 0 and "fetch failed" in stats[0].error
        assert not path.exists(), "yesterday's documents are still in today's corpus"
        assert list(read_documents(tmp_path / "out")) == []
        out = capsys.readouterr().out
        assert "REMOVED" in out and good.name in out

    def test_only_keeps_the_other_sources_in_the_provenance_record(self, tmp_path, monkeypatch):
        """`--only` rebuilds one file and leaves the rest; the record must say so.

        _write_provenance was handed the *filtered* spec list, so `--only sigma`
        rewrote PROVENANCE.md down to a one-row table while fourteen other
        sources' JSONL sat in the same directory, still read by every consumer
        and now with no licence recorded anywhere. source.py names a corpus
        whose licensing cannot be reconstructed as the thing this project must
        not become.
        """
        a = _adapter(tmp_path, monkeypatch, _DISTINCT)
        b = _adapter(tmp_path, monkeypatch, _DISTINCT)
        self._build(tmp_path, monkeypatch, [a, b])
        self._build(tmp_path, monkeypatch, [a, b], only=[a.name])

        assert (tmp_path / "out" / f"{b.name}.jsonl").is_file(), \
            "--only deleted a file it was not asked to rebuild"
        prov = (tmp_path / "out" / "PROVENANCE.md").read_text(encoding="utf-8")
        assert a.name in prov and b.name in prov
        assert "Carried over" in prov, "a mixed directory has to be stated, not hidden"

    def test_a_file_no_source_claims_is_named_and_left_alone(self, tmp_path, monkeypatch, capsys):
        """A renamed or deleted adapter leaves data nothing can attribute.

        Deleting it would be guessing; staying quiet about it is worse, because
        read_documents() still reads it into the shards and no licence can be
        stated for it.
        """
        a = _adapter(tmp_path, monkeypatch, _DISTINCT)
        (tmp_path / "out").mkdir(parents=True, exist_ok=True)
        orphan = tmp_path / "out" / "byhand.jsonl"
        orphan.write_text(json.dumps({"text": "hand placed", "source": "?",
                                      "register": "prose", "side": "neutral",
                                      "ident": "0"}) + "\n", encoding="utf-8")
        self._build(tmp_path, monkeypatch, [a])

        assert orphan.is_file(), "it deleted data it could not identify"
        out = capsys.readouterr().out
        assert "byhand.jsonl" in out and "no provenance" in out.lower()
        prov = (tmp_path / "out" / "PROVENANCE.md").read_text(encoding="utf-8")
        assert "byhand.jsonl" in prov


class TestChildOutcomeIsVerified:
    """A child that died without saying so must not read as an empty source.

    _child_main's inner ``except BaseException`` sits *inside* the
    ``with docs_path.open(...)`` block, so it covers neither opening the file nor
    the implicit flush-and-close when the block exits — which is exactly where an
    ENOSPC or EIO on the external volume this corpus is built on lands. The
    status left behind is then indistinguishable from a clean run that yielded
    nothing, and the parent read it as one: docs=0, chars=0, error="". A dead
    child and an empty upstream became the same event in the report, with
    nothing in common as fixes.
    """

    def test_the_status_a_dead_child_leaves_is_the_one_this_guards(self, tmp_path):
        """Pin the premise in a real child, so the class is not theoretical.

        Out of process on purpose: _child_main's first act is os.setsid(), and
        detaching the pytest process from its own session to save a fork is not
        a trade worth making.
        """
        root = Path(__file__).resolve().parents[1]
        script = (
            "import sys\n"
            "from pathlib import Path\n"
            f"sys.path.insert(0, {str(root)!r})\n"
            "from training.corpus.build import _child_main\n"
            "from training.corpus.source import Register, Side, SourceSpec\n"
            "spec = SourceSpec(name='probe', license='throwaway',\n"
            "                  url='https://example.invalid', register=Register.PROSE,\n"
            "                  side=Side.NEUTRAL, fetch=lambda p: p,\n"
            "                  documents=lambda p: iter(()))\n"
            f"here = Path({str(tmp_path)!r})\n"
            "_child_main(spec, here, here / 'gone' / 'documents.jsonl',\n"
            "            here / 'status.json')\n"
        )
        # check=False and meant: the child is expected to die here.
        proc = subprocess.run([sys.executable, "-c", script], check=False,
                              capture_output=True, text=True)
        assert "FileNotFoundError" in proc.stderr, proc.stderr
        assert json.loads((tmp_path / "status.json").read_text(encoding="utf-8")) == {
            "phase": "documents", "error": "", "emitted": 0}

    def test_a_child_that_stopped_without_an_error_is_fatal(self, tmp_path):
        fatal = build_mod._child_fatal(
            {"phase": "documents", "error": "", "emitted": 0},
            tmp_path / "documents.jsonl", 12.0)
        assert "cannot be trusted" in fatal, fatal

    def test_a_clean_child_is_accepted(self, tmp_path):
        docs = tmp_path / "documents.jsonl"
        docs.write_text('{"a": 1}\n{"a": 2}\n', encoding="utf-8")
        assert build_mod._child_fatal(
            {"phase": "ok", "error": "", "emitted": 2}, docs, 1.0) == ""

    def test_a_source_that_raised_part_way_still_hands_over_what_it_wrote(self, tmp_path):
        """documents() raising mid-stream is the legitimate partial yield.

        It is what the in-process path does too, and the prefix is a real prefix
        of a real source that the child recorded honestly. Only an *unreported*
        ending is untrustworthy.
        """
        docs = tmp_path / "documents.jsonl"
        docs.write_text('{"a": 1}\n', encoding="utf-8")
        assert build_mod._child_fatal(
            {"phase": "documents", "error": "ValueError: bad row", "emitted": 1},
            docs, 1.0) == ""

    def test_a_jsonl_shorter_than_the_child_claims_is_refused_whole(self, tmp_path):
        """Second line of defence, for a truncation that raised nowhere.

        A truncation landing on a line boundary parses perfectly, and a short
        source counted as whole is the exact outcome the timeout path refuses.
        """
        docs = tmp_path / "documents.jsonl"
        docs.write_text('{"a": 1}\n{"a": 2}\n', encoding="utf-8")
        fatal = build_mod._child_fatal(
            {"phase": "ok", "error": "", "emitted": 5}, docs, 1.0)
        assert "truncated" in fatal, fatal


class TestIdentityChokepoint:
    """No source can put this machine's identity into the corpus.

    Redaction used to be something the trajectory generator did for itself and
    no other adapter thought about. That held until `ownrepos` walked the
    maintainer's own repositories and carried their account name and the
    per-user temp path that fingerprints one particular Mac into the corpus —
    and a corpus is the thing that becomes weights, where it is not removable.

    An audit of the shipped corpus found 1,187 leaking documents across two
    sources, one of which had never considered the problem. So it is no longer
    per-source: `build.py` redacts on the way in, once, where a future adapter
    cannot forget it.
    """

    def test_the_build_redacts_every_document(self):
        from dataclasses import dataclass

        from training.corpus.build import _redacted
        from training.trajectories import identity_leaks

        @dataclass
        class _Doc:
            text: str

        import getpass
        user = getpass.getuser()
        dirty = f"operator {user} ran a scan from /Users/{user}/work"
        assert identity_leaks(dirty), (
            "this test is vacuous unless the fixture actually leaks")

        clean = _redacted(_Doc(text=dirty))
        assert not identity_leaks(clean.text), clean.text
        assert user not in clean.text

    def test_clean_text_is_returned_unchanged(self):
        """Redaction must not rewrite documents that have nothing to redact.

        Every source pays this cost on every document, so it has to be a no-op
        when there is nothing to do — and, more importantly, a redactor that
        edits clean text is one that will eventually corrupt a payload.
        """
        from dataclasses import dataclass

        from training.corpus.build import _redacted

        @dataclass
        class _Doc:
            text: str

        original = "CVE-2024-21412 cvss: 9.8 CRITICAL\nvector: CVSS:3.1/AV:N"
        assert _redacted(_Doc(text=original)).text == original
