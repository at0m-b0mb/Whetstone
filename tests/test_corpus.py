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


class TestShardInterleaving:
    """The validation split must be representative of the corpus.

    build.py writes one JSONL per source and they are read in sorted order, so
    an unshuffled corpus ends with whichever source sorts last. That made the
    held-out split 100% Sigma rules: validation loss measured how well the model
    predicted YAML, sat 1.3 nats above training loss, and looked exactly like
    overfitting. Nothing else in the pipeline showed it.
    """

    def _corpus(self, tmp_path):
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
