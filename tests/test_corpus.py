"""Tests for the corpus layer.

The corpus is the part of this project that fails *silently*. A bad gate rule
raises; a bad corpus just trains a slightly worse model and nobody finds out
until a tokenizer comparison four steps downstream says 7% instead of 30%. So
the properties that matter here are pinned down rather than assumed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from training.corpus.build import BuildStats, balance_report, read_documents
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
        """The registers the first corpus was starved of get the largest share."""
        assert REGISTER_TARGETS[Register.SHELL] >= 0.25
        assert REGISTER_TARGETS[Register.SYSTEM] >= 0.25


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
