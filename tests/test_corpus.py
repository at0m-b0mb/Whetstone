"""Tests for the corpus layer.

The corpus is the part of this project that fails *silently*. A bad gate rule
raises; a bad corpus just trains a slightly worse model and nobody finds out
until a tokenizer comparison four steps downstream says 7% instead of 30%. So
the properties that matter here are pinned down rather than assumed.
"""

from __future__ import annotations

import importlib
import itertools
import json
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
