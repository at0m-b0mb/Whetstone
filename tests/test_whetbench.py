"""Tests for the capability benchmark — the instrument gets checked too.

Two of the seven probes in ``bench/whetbench.py`` could not fail. ``run_bench``
scored ``prompt + continuation``, the ``shell-routing`` prompt was
``PS C:\\> Get-Process | `` and the checker's marker list contains ``get-``; the
``detection-routing`` prompt was ``logsource:`` and the marker list contains
``logsource``. Both returned True before the model emitted a token, so both
reported 5/5 on every checkpoint they were ever run against, and those numbers
were shown to a human as evidence that register routing was the model's
strongest capability. A third probe, ``action-json``, wrote its own ``<|bos|>``
into a prompt that ``training.generate.generate`` then prepends another to, so
the one probe labelled THE TASK was asking the question in a two-bos dialect no
trajectory ever contained.

None of those is a bug in the model, and that is the point: each one produced a
plausible number with nothing behind it. So the tests here are not about whether
a checkpoint is good. They are about whether a probe is capable of saying no.
Each register check is exercised against a right-register continuation, a
wrong-register continuation and a verbatim echo of its own prompt, because a
small model's first failure mode is to repeat what it was given and an echo that
scores full marks is the same lie in a different shape.

The stub tokenizer and stub generator exist so this file runs in plain CI. The
alternative is that the only tests of the measuring apparatus require MLX, a
trained checkpoint and a tokenizer on an external volume — which is to say, the
tests that catch a wrong number would be the tests nobody runs.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

from bench.whetbench import (
    PROBES,
    Probe,
    ProbeDesignError,
    _ACTION_PROMPT,
    assert_probes_can_fail,
    assert_prompts_carry_no_bos,
    check_detection,
    check_shell,
    run_bench,
)
from training.tokenizer.protocol import BOS

#: The real tokenizer, when this machine has one. Everything that needs it skips
#: rather than failing: a laptop with no data volume mounted must still be able
#: to run the suite, but the id-level checks are worth having where they can run.
REAL_TOKENIZER = Path(
    "/Volumes/at0m_b0mb/whetstone/models/tokenizer-v1/tokenizer.json")

#: A continuation in each register, and one in the wrong register for each. The
#: wrong ones are deliberately fluent security text: the failure being caught is
#: not gibberish, it is the model answering a PowerShell prompt with advisory
#: prose because advisory text outweighed shell text in the corpus twelve to one.
SHELL_CONTINUATION = "Get-Service -Name Spooler | Select-Object Name, Status"
SIGMA_CONTINUATION = (
    "logsource:\n  product: windows\n  service: security\n"
    "detection:\n  selection:\n    EventID: 4698\n  condition: selection\n"
    "level: high\n")
ADVISORY_CONTINUATION = (
    "CVE-2023-4863 is a heap buffer overflow in libwebp, scored 8.8 HIGH, "
    "affecting every browser that bundles the library.")


class _FakeTokenizer:
    """Enough tokenizer to answer the one question the bos guard asks.

    Special tokens are atomic ids and everything else is one id per character.
    The character granularity is nonsense as tokenization and exactly right as a
    fixture: the guard counts bos ids, so the only property that has to be
    faithful is that ``<|bos|>`` encodes to one id and nothing else encodes to
    that id.
    """

    BOS_ID = 1
    OTHER_ID = 2

    def token_to_id(self, token: str) -> int | None:
        return self.BOS_ID if token == BOS else self.OTHER_ID

    def encode(self, text: str) -> SimpleNamespace:
        ids: list[int] = []
        for i, chunk in enumerate(text.split(BOS)):
            if i:
                ids.append(self.BOS_ID)
            ids.extend([self.OTHER_ID] * len(chunk))
        return SimpleNamespace(ids=ids)


# --------------------------------------------------------------------------
# a probe must be able to say no
# --------------------------------------------------------------------------


class TestProbesCanFail:
    def test_no_probe_passes_on_its_own_prompt(self):
        """The regression, stated as the property rather than as two examples.

        Holding for all seven is what makes the concatenation bug *harmless*
        rather than merely absent: if a prompt cannot pass its own check, then
        neither re-joining prompt and continuation nor a model that has
        collapsed into echoing its input can manufacture a pass out of nothing.
        """
        assert_probes_can_fail(PROBES)

    def test_the_old_shell_prompt_is_rejected(self):
        """`PS C:\\> Get-Process | ` supplies `get-` to its own checker."""
        with pytest.raises(ProbeDesignError, match="shell-routing"):
            assert_probes_can_fail([
                Probe("shell-routing", "PS C:\\> Get-Process | ", check_shell,
                      "stays in the shell register")])

    def test_the_old_detection_prompt_is_rejected(self):
        """`logsource:` supplies `logsource` to its own checker."""
        with pytest.raises(ProbeDesignError, match="detection-routing"):
            assert_probes_can_fail([
                Probe("detection-routing",
                      "title: Suspicious Process Creation\nlogsource:\n",
                      check_detection, "continues a detection rule")])

    def test_the_guard_names_what_it_found(self):
        """A refusal that does not say which marker leaked is a puzzle, not a
        diagnosis; whoever hits this is mid-benchmark and needs the answer."""
        with pytest.raises(ProbeDesignError, match="sudo"):
            assert_probes_can_fail([
                Probe("x", "sudo systemctl restart sshd", check_shell, "")])


class TestRegisterChecks:
    """Each check, against a right answer, a wrong answer and an echo."""

    def test_shell_check_passes_on_a_shell_continuation(self):
        ok, detail = check_shell(SHELL_CONTINUATION)
        assert ok and "get-" in detail

    def test_shell_check_fails_on_advisory_prose(self):
        """The corpus-skew failure this probe exists to catch."""
        ok, detail = check_shell(ADVISORY_CONTINUATION)
        assert not ok
        assert detail == "drifted out of shell"

    def test_shell_check_fails_on_a_sigma_continuation(self):
        assert check_shell(SIGMA_CONTINUATION)[0] is False

    @pytest.mark.parametrize("continuation", [
        "Get-Service -Name Spooler",
        "Restart-Service -Name Spooler",
        "Select-Object Name, Status",
        "Sort-Object CPU -Descending",
        "Invoke-WebRequest https://example.invalid/ -OutFile a.txt",
        "Write-Host $env:COMPUTERNAME",
        "Where-Object { $_.Status -eq 'Running' }",
        "Get-ChildItem C:\\Windows\\Temp -Recurse -ErrorAction Stop",
        "sudo systemctl status sshd",
    ])
    def test_shell_check_recognises_a_whole_command_not_just_a_pipeline_tail(
            self, continuation):
        """The marker list has to match the prompt shape, and it did not.

        While the prompt was `PS C:\\> Get-Process | ` the plausible right
        answers were pipeline fragments, so `$_` and `| select` covered them.
        The prompt now asks for a whole command, and against the old list four
        of these nine correct answers scored as drift — a probe that says the
        model left the register when it did not is reporting a wrong number in
        the other direction.
        """
        assert check_shell(continuation)[0] is True

    def test_no_shell_marker_fires_on_ordinary_advisory_prose(self):
        """Guards the additions that were considered and rejected.

        Advisory prose is the *wrong* answer this probe exists to catch, so a
        marker that occurs in it would quietly restore a probe that cannot fail.
        This sentence is built from the near misses: `-service` lives inside
        "denial-of-service", `-force` inside "brute-force", `start-` inside
        "start-up", `out-` inside "out-of-band". Adding any of them turns this
        red — and `set-`, which was in the list until this sentence caught it on
        "Set-up guidance", is why the sentence ends the way it does.
        """
        prose = ("A denial-of-service in the print spooler, reachable by "
                 "brute-force, which runs at start-up and was fixed in an "
                 "out-of-band update. Set-up guidance follows.")
        assert check_shell(prose)[0] is False

    def test_detection_check_passes_on_a_sigma_continuation(self):
        ok, detail = check_detection(SIGMA_CONTINUATION)
        assert ok and "detection:" in detail

    def test_detection_check_fails_on_a_shell_continuation(self):
        assert check_detection(SHELL_CONTINUATION)[0] is False

    def test_neither_register_probe_passes_on_its_own_prompt_echoed(self):
        """A collapsed model repeats its prompt. That must score zero.

        Distinct from ``assert_probes_can_fail`` even though the text is the
        same: that guard is about probe design at startup, this is about what
        happens at scoring time when the model does the most common degenerate
        thing a 14.6M model does.
        """
        for name in ("shell-routing", "detection-routing"):
            probe = next(p for p in PROBES if p.name == name)
            ok, _detail = probe.check(probe.prompt * 3)
            assert not ok, f"{name} scores an echo of its own prompt as a pass"


# --------------------------------------------------------------------------
# exactly one bos reaches the model
# --------------------------------------------------------------------------


class TestSingleBos:
    def test_the_action_prompt_writes_no_bos_of_its_own(self):
        """`generate` prepends one unconditionally. Two is out of distribution."""
        assert BOS not in _ACTION_PROMPT

    def test_the_guard_rejects_a_prompt_carrying_its_own_bos(self):
        with pytest.raises(ProbeDesignError, match="action-json"):
            assert_prompts_carry_no_bos(
                [Probe("action-json", f"{BOS}<|task|>do something",
                       check_shell, "")],
                _FakeTokenizer())

    def test_the_guard_refuses_a_tokenizer_with_no_bos(self):
        """Then `generate` prepends nothing and every prompt is out of
        distribution in the other direction — still not a fact about the model."""
        class _NoBos(_FakeTokenizer):
            def token_to_id(self, token: str) -> int | None:
                return None if token == BOS else self.OTHER_ID

        with pytest.raises(ProbeDesignError, match="no <\\|bos\\|> token"):
            assert_prompts_carry_no_bos(PROBES, _NoBos())

    def test_no_shipped_prompt_carries_a_bos(self):
        assert_prompts_carry_no_bos(PROBES, _FakeTokenizer())

    def test_real_tokenizer_agrees(self):
        """The string check above can only be trusted if the tokenizer really
        treats `<|bos|>` as one atomic id, which is a property of the trained
        vocabulary rather than of this file."""
        pytest.importorskip("tokenizers")
        if not REAL_TOKENIZER.is_file():
            pytest.skip(f"no tokenizer at {REAL_TOKENIZER}")
        from tokenizers import Tokenizer

        tok = Tokenizer.from_file(str(REAL_TOKENIZER))
        assert_prompts_carry_no_bos(PROBES, tok)
        bos = tok.token_to_id(BOS)
        # Mirrors training/generate.py's prepend. Duplicated on purpose: the
        # whole finding was that the two files disagreed about who writes the
        # bos, and a test that imported the answer from one of them could not
        # have noticed.
        fed = [bos] + tok.encode(_ACTION_PROMPT).ids
        assert fed.count(bos) == 1, f"model would see {fed.count(bos)} bos tokens"


# --------------------------------------------------------------------------
# run_bench scores the continuation
# --------------------------------------------------------------------------


class _Cfg:
    name = "stub"
    n_params = 14_600_000


def _stub_run(monkeypatch, tmp_path, continuation: str):
    """Run the real ``run_bench`` against a generator that returns a fixed string.

    The model, the tokenizer and MLX are all stubbed through ``sys.modules``
    because ``run_bench`` imports them inside the function. What is left running
    is the part that was wrong — which text gets handed to which checker — and
    that part needs no weights to be wrong in exactly the way it was.
    """
    fake_generate = types.ModuleType("training.generate")
    fake_generate.generate = (
        lambda model, tok, prompt, **kw: continuation)
    fake_generate.load_for_inference = lambda checkpoint: (object(), _Cfg())
    monkeypatch.setitem(sys.modules, "training.generate", fake_generate)

    fake_tokenizers = types.ModuleType("tokenizers")
    fake_tokenizers.Tokenizer = SimpleNamespace(
        from_file=lambda path: _FakeTokenizer())
    monkeypatch.setitem(sys.modules, "tokenizers", fake_tokenizers)

    checkpoint = tmp_path / "ckpt"
    checkpoint.mkdir(exist_ok=True)
    (checkpoint / "state.json").write_text('{"step": 1234}', encoding="utf-8")
    return run_bench(checkpoint, tmp_path / "tokenizer.json",
                     only=["shell-routing", "detection-routing"])


class TestRunBenchScoresTheContinuation:
    def test_advisory_prose_fails_both_register_probes(
            self, monkeypatch, tmp_path, capsys):
        """The regression for the concatenation bug, at the level it happened.

        A model that answers every prompt with CVE prose is the exact regression
        these probes exist to catch, and while ``prompt + text`` was scored it
        reported 5/5 for both — the prompts alone carried ``get-`` and
        ``logsource``. Scored on the continuation, both are zero.
        """
        probes = _stub_run(monkeypatch, tmp_path, ADVISORY_CONTINUATION)
        assert {p.name: p.passed for p in probes} == {
            "shell-routing": 0, "detection-routing": 0}
        assert all(len(p.results) == p.samples for p in probes)

    def test_a_shell_continuation_passes_only_the_shell_probe(
            self, monkeypatch, tmp_path, capsys):
        """The other half of the proof: the fixed probes can still say yes, and
        they do not both say it at once."""
        probes = _stub_run(monkeypatch, tmp_path, SHELL_CONTINUATION)
        by_name = {p.name: p.passed for p in probes}
        assert by_name["shell-routing"] == 5
        assert by_name["detection-routing"] == 0

    def test_a_sigma_continuation_passes_only_the_detection_probe(
            self, monkeypatch, tmp_path, capsys):
        probes = _stub_run(monkeypatch, tmp_path, SIGMA_CONTINUATION)
        by_name = {p.name: p.passed for p in probes}
        assert by_name["detection-routing"] == 5
        assert by_name["shell-routing"] == 0

    def test_a_second_run_does_not_accumulate_samples(
            self, monkeypatch, tmp_path, capsys):
        """PROBES is module state. Without a reset the second run reports ten
        results for five samples, which reads as a better checkpoint."""
        _stub_run(monkeypatch, tmp_path, SHELL_CONTINUATION)
        probes = _stub_run(monkeypatch, tmp_path, SHELL_CONTINUATION)
        for probe in probes:
            assert len(probe.results) == probe.samples

    def test_the_checker_never_sees_the_prompt_joined_to_the_continuation(
            self, monkeypatch, tmp_path, capsys):
        """Pins the scoring contract directly, because the probe prompts no
        longer make it observable any other way.

        Two things were fixed here and either one alone hides the other: the
        scorer stopped joining prompt to continuation, and the prompts stopped
        containing their own markers. With both in place, re-joining them scores
        the same as not joining, so no pass/fail assertion can tell the versions
        apart — which is the desired belt-and-braces and also a blind spot for a
        test. So this asserts the shape of the calls instead. The checker sees
        its prompt exactly once, from ``assert_probes_can_fail``, and then sees
        the continuation and nothing but the continuation, once per sample.
        """
        probe = next(p for p in PROBES if p.name == "shell-routing")
        seen: list[str] = []

        def recorder(text: str) -> tuple[bool, str]:
            seen.append(text)
            return False, "recorded"

        monkeypatch.setattr(probe, "check", recorder, raising=True)
        _stub_run(monkeypatch, tmp_path, SHELL_CONTINUATION)

        assert seen == [probe.prompt] + [SHELL_CONTINUATION] * probe.samples, (
            "the checker was handed something other than the bare continuation")

    def test_a_broken_probe_stops_the_run_before_the_model_loads(
            self, monkeypatch, tmp_path, capsys):
        """CHECK THE INSTRUMENT FIRST, enforced where it costs nothing."""
        monkeypatch.setattr(
            PROBES[0], "prompt", "sudo systemctl restart sshd", raising=True)
        monkeypatch.setattr(PROBES[0], "check", check_shell, raising=True)
        with pytest.raises(ProbeDesignError):
            _stub_run(monkeypatch, tmp_path, SHELL_CONTINUATION)
