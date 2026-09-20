"""Tests for the narrated cycle and the capture artifacts.

Three things are pinned here and they are not the same kind of thing.

**The invariant, restated at the output.** ``detection_fired`` returning ``None``
means the probe established nothing, and the kernel is careful never to let that
become "did not fire". Everything downstream inherits that care or throws it
away: a narration or a transcript that prints ``None`` as "silent" has published
a detection gap the kernel refused to find, and it has done it in the one file
the project hands to strangers as evidence. The kernel's own tests cannot catch
that, because it is not the kernel doing it.

**The pairing, checked rather than assumed.** Both the narration and the
transcript group the flat turn list back into attacks and fixes, and both do it
positionally. A positional match that silently mis-aligns puts one gap's fix
under another gap's heading — the same defect as crediting a fix to the wrong
gap inside the kernel, with the same ending. So the mismatch raises, and that is
tested, because a loud failure nobody ever provokes is a comment.

**The redaction, which is now the write path.** ``examples/runs/`` is public.
``tests/test_redaction.py`` already asserts that the *committed* files are
clean; these assert that the *writer* cleans them, so the property survives the
next re-capture rather than the last one.
"""

from __future__ import annotations

import getpass
import json

import pytest

import whetstone.verbs  # noqa: F401  (registers the catalogue)
from whetstone.actions import REGISTRY, Observation
from whetstone.gate.policy import Decision, Verdict
from whetstone.kernel import Episode, Finding, Remediation, Turn

from lab.capture import (CaptureMeta, capture, fix_blocks, pair_fix_blocks,
                         turns_by_phase)
from lab.run import render_cycle

_ALLOW = Decision(Verdict.ALLOW, "test.allow", "permitted for the test")


def _turn(verb_id: str, params: dict | None = None, *, phase: str = "plan",
          data: dict | None = None, ok: bool = True) -> Turn:
    """One finished turn against the real catalogue.

    Built from :data:`REGISTRY` rather than from a stub registry on purpose. The
    narration asks the registry whether a verb is red in order to tell a
    re-attack apart from the probe that judges it, so a test using invented
    verbs would pass while the real ``exploit.service_permissions`` had quietly
    stopped being ``Side.RED``.
    """
    verb = REGISTRY.get(verb_id)
    defaults = {p.name: p.default for p in verb.params if p.default is not None}
    defaults.update(params or {})
    action = verb.bind(defaults, target="127.0.0.1")
    return Turn(action=action, decision=_ALLOW, phase=phase,
                observation=Observation(
                    action=action, ok=ok,
                    data=data if data is not None else {}))


def _gap(technique: str = "T1574.010",
         produced_by: str = "exploit.service_permissions",
         expected: str = "detect.process_creation",
         remediation: Remediation | None = None) -> Finding:
    return Finding(
        kind="detection_gap", technique=technique, expected=expected,
        produced_by=produced_by, remediation=remediation,
        detail=f"{produced_by} ran and {expected} did not fire — the "
               "technique succeeded unobserved")


def _closed_cycle() -> Episode:
    """One attack, one silent probe, one gap, and a fix proven by re-attack.

    The shape the demonstration exists to show, assembled by hand so the
    assertions are about the rendering rather than about the sandbox.
    """
    episode = Episode(task="t", host="sandbox", scope="s", catalogue="c")
    episode.turns = [
        _turn("enum.host"),
        _turn("exploit.service_permissions", {"service": "acme-agent"},
              data={"image": "acme-agent"}),
        _turn("detect.process_creation", {"image": "acme-agent"},
              phase="detect", data={"events": []}),
        _turn("harden.enable_telemetry", {"source": "sandbox-eventlog"},
              phase="remediate", data={"enabled": True}),
        _turn("exploit.service_permissions", {"service": "acme-agent"},
              phase="verify", data={"image": "acme-agent"}),
        _turn("detect.process_creation", {"image": "acme-agent"},
              phase="verify", data={"events": [{"image": "acme-agent"}]}),
    ]
    episode.findings = [_gap(remediation=Remediation(
        "closed", verb="harden.enable_telemetry",
        detail="the proof is the second attack, not the fix's exit status"))]
    return episode


class TestNarratedCycle:
    def test_reads_as_attack_silence_gap_fix_reattack_closure(self):
        """The whole point of ``--cycle``: the story, in order, in one screen."""
        out = render_cycle(_closed_cycle())

        for fragment in ("-- 1. look", "-- 2. attack, and ask who saw",
                         "-- 3. fix it, then attack again",
                         "silent — the control saw nothing",
                         "GAP —", "re-attack", "fired — the control saw the "
                         "technique", "GAP CLOSED"):
            assert fragment in out, f"the narration never says {fragment!r}"

        # In that order. A screen that reports closure before the gap it closed
        # is not the cycle, it is the same facts shuffled.
        assert (out.index("silent — the control saw nothing")
                < out.index("GAP —")
                < out.index("re-attack")
                < out.index("GAP CLOSED"))

    def test_an_unestablished_probe_is_never_narrated_as_silence(self):
        """``None`` is a third answer. THE invariant, checked at the output.

        ``detection_fired`` returns ``None`` when the probe could not establish
        anything — the log was unreadable, the source was off. The kernel writes
        that as an ``observation`` finding and specifically not as a gap. A
        narration that prints it as "silent" tells the operator the control was
        blind, which is a detection gap asserted by the renderer and backed by
        nothing. It is the worst thing this tool can do and it is one dictionary
        row away at all times.
        """
        episode = _closed_cycle()
        # The adapter could not read the log: `source: none` is one of the
        # provenance markers `_source_unqueryable` recognises. The remediation
        # turns go with it — the kernel never remediates an `observation`,
        # because there is nothing established to close.
        episode.turns = episode.turns[:3]
        episode.turns[2] = _turn("detect.process_creation", {"image": "acme-agent"},
                                 phase="detect",
                                 data={"source": "none", "gap": "no rule loaded"})
        episode.findings = [Finding(
            kind="observation", technique="T1574.010",
            expected="detect.process_creation",
            produced_by="exploit.service_permissions",
            detail="detect.process_creation could not establish whether it "
                   "fired; this is not evidence of a gap")]

        out = render_cycle(episode)

        assert "could not tell" in out
        assert "silent — the control saw nothing" not in out, (
            "a probe that established nothing was narrated as silence, which "
            "publishes a detection gap the kernel did not find")
        assert "INCONCLUSIVE" in out

    def test_recon_and_kernel_evidence_are_not_run_together(self):
        """The re-attack is the agent's exploit replayed, and must read as one.

        Before the phase existed, the flat turn list showed
        ``exploit.service_permissions`` once. It now shows it twice, and a
        reader — or a benchmark — that cannot tell which one the agent chose is
        counting the kernel's evidence as the agent's behaviour.
        """
        out = render_cycle(_closed_cycle())
        assert "attack 1 of 1" in out
        assert out.count("re-attack") == 1
        # The recon block reports its own size, and the red turn is not in it.
        assert "1 observation(s) before anything was touched" in out


class TestFixBlockPairing:
    def test_blocks_are_matched_to_the_gaps_that_reached_the_gate(self):
        episode = _closed_cycle()
        blocks = fix_blocks(episode)
        assert len(blocks) == 1
        assert [t.phase for t in blocks[0]] == ["remediate", "verify", "verify"]
        pairs = pair_fix_blocks(episode.findings, blocks)
        assert pairs[0][0] is episode.findings[0]

    def test_a_count_mismatch_raises_instead_of_lining_up_what_it_can(self):
        """Loud, because the quiet version is a hole reported shut.

        ``unavailable`` is the one state the kernel reaches without submitting
        anything, so a gap in that state owns no block. If a second gap in some
        other state appeared with no block behind it, zipping would put the
        first gap's fix under the second gap's heading and nothing on the page
        would say so.
        """
        episode = _closed_cycle()
        episode.findings.append(_gap(
            technique="T1003", produced_by="postex.credential_dump",
            expected="detect.credential_access",
            remediation=Remediation("ineffective", verb="harden.enable_telemetry",
                                    detail="ran and did not work")))
        with pytest.raises(ValueError, match="reached the gate"):
            render_cycle(episode)

    def test_a_verify_turn_with_no_fix_before_it_raises(self):
        """There is no honest way to read one, so it is not read.

        The kernel submits a re-attack only after the fix it verifies, so this
        shape cannot come out of a real run. It can come out of a hand-built
        episode or a future kernel, and the tolerant version — attach it to the
        previous block — would print somebody's re-attack as another fix's
        evidence.
        """
        episode = _closed_cycle()
        episode.turns = [t for t in episode.turns if t.phase != "remediate"]
        with pytest.raises(ValueError, match="verify turn appeared before"):
            fix_blocks(episode)

    def test_a_gap_that_was_never_offered_a_fix_owns_no_block(self):
        """``unavailable`` and ``None`` produce no turns, and must not claim any."""
        episode = _closed_cycle()
        episode.findings.append(_gap(
            technique="T1003", produced_by="postex.credential_dump",
            expected="detect.credential_access",
            remediation=Remediation("unavailable", detail="nothing declares it")))
        out = render_cycle(episode)
        assert "NOTHING PROPOSED" in out
        assert "2 of 2 proven closed" not in out
        assert "1 of those 2 proven closed" in out


class TestCaptureArtifacts:
    def test_findings_json_carries_the_remediation_outcome(self, tmp_path):
        paths = capture(_closed_cycle(), _meta(), tmp_path, "run")
        payload = json.loads(paths["findings"].read_text(encoding="utf-8"))

        gap = payload["findings"][0]
        assert gap["kind"] == "detection_gap"
        assert gap["produced_by"] == "exploit.service_permissions"
        assert gap["remediation"] == {
            "state": "closed", "verb": "harden.enable_telemetry",
            "detail": "the proof is the second attack, not the fix's exit status"}
        assert payload["remediation_states"] == {"closed": 1}
        # The agent chose two of the six turns; the kernel injected four.
        assert payload["turns"] == 6
        assert payload["agent_turns"] == 2
        assert payload["turns_by_phase"] == {
            "plan": 2, "detect": 1, "remediate": 1, "verify": 2}

    def test_transcript_shows_the_fix_and_what_the_reattack_proved(self, tmp_path):
        paths = capture(_closed_cycle(), _meta(), tmp_path, "run")
        text = paths["transcript"].read_text(encoding="utf-8")

        assert "## Remediation — what was fixed, and what proved it" in text
        assert "**3. control**" not in text          # numbering is per-step prose
        assert "**fix** — `harden.enable_telemetry" in text
        assert "**re-attack** — `exploit.service_permissions" in text
        assert "**fired** — the control saw the technique" in text
        assert "**closed** —" in text
        # Kernel-injected turns are marked, so a reader can tell the agent's
        # twelve decisions from the kernel's nine pieces of evidence.
        assert "_kernel probe_" in text and "_kernel evidence_" in text

    def test_a_gap_with_no_remediation_gets_no_remediation_section(self, tmp_path):
        """Absence, rather than a heading over an empty table.

        "remediation: none" under a heading reads as a measured result. The
        header row already says the phase was off, and that is the honest place
        for it.
        """
        episode = _closed_cycle()
        episode.turns = episode.turns[:3]
        episode.findings = [_gap()]
        paths = capture(episode, _meta(remediation="off"), tmp_path, "run")
        text = paths["transcript"].read_text(encoding="utf-8")
        assert "## Remediation" not in text
        assert "| remediation | off |" in text

    def test_the_transcript_and_the_screen_tell_one_story(self, tmp_path):
        """Both read the episode through the same helpers, so both agree.

        Not a style point. The screen is what gets demonstrated and the file is
        what gets committed, and a run where those two disagree about which fix
        closed which gap is a run whose evidence cannot be checked.
        """
        episode = _closed_cycle()
        paths = capture(episode, _meta(), tmp_path, "run")
        text = paths["transcript"].read_text(encoding="utf-8")
        screen = render_cycle(episode)
        for fragment in ("harden.enable_telemetry", "exploit.service_permissions",
                         "detect.process_creation"):
            assert fragment in text and fragment in screen


class TestRedactionIsTheWritePath:
    """Not a step somebody remembers between capturing and committing."""

    def test_every_written_file_has_this_machines_identity_substituted(self, tmp_path):
        """The account name goes in through an observation and does not come out.

        A real capture leaks it through paths the adapters return —
        ``enum.persistence`` and ``vuln.credential_exposure`` both hand back
        paths under the home directory. Planting it in an observation payload is
        the same route, made deterministic.
        """
        from training.trajectories import identity_leaks

        user = getpass.getuser()
        if not identity_leaks(f"/Users/{user}"):
            pytest.skip("this machine's account name is not identifying")

        episode = _closed_cycle()
        episode.turns[0] = _turn(
            "enum.host", data={"runs_as": user, "home": f"/Users/{user}"})

        paths = capture(episode, _meta(), tmp_path, "run")
        for kind, path in paths.items():
            assert not identity_leaks(path.read_text(encoding="utf-8")), (
                f"{kind} still names this machine")

        # Substituted, not deleted. Only the two files that carry observation
        # payloads can show it — the findings file records findings, and a
        # finding never quotes a path. A redaction that left holes would teach
        # the model that observations contain holes, and would leave a reader
        # unable to tell a redacted run from a run against a different host.
        for kind in ("trajectory", "transcript"):
            assert "operator" in paths[kind].read_text(encoding="utf-8"), (
                f"{kind} lost the value instead of substituting it; the shape "
                "of an observation has to survive redaction")

    def test_the_findings_file_is_still_json_after_redaction(self, tmp_path):
        """Redaction runs on the finished document, so it can break the document.

        The replacement for the per-user temp directory is ``C:\\Temp`` on
        Windows, and a backslash substituted into serialised JSON is an invalid
        escape. Here the check simply has to hold; on the first Windows capture
        it is what turns a corrupt published file into a refusal.
        """
        paths = capture(_closed_cycle(), _meta(), tmp_path, "run")
        json.loads(paths["findings"].read_text(encoding="utf-8"))

    def test_a_write_whose_redaction_did_not_take_is_refused(self, tmp_path,
                                                             monkeypatch):
        """The refusal is the point, so provoke it rather than trust it.

        Simulates a substitution that ran and left the literal standing, which
        is what a table entry whose replacement re-introduces its own secret
        would do. Nothing may be written in that case — a published artifact
        naming the operator cannot be unpublished.
        """
        import lab.capture as C
        import training.trajectories as T

        monkeypatch.setattr(T, "redact_identity", lambda text: text)
        monkeypatch.setattr(T, "identity_leaks", lambda text: ["not-substituted"])

        out = tmp_path / "x.txt"
        with pytest.raises(RuntimeError, match="not-substituted"):
            C._write_redacted(out, "anything")
        assert not out.exists(), "a file was written despite a surviving literal"

    def test_invalid_json_after_redaction_is_refused(self, tmp_path, monkeypatch):
        """The Windows-backslash trap, provoked on a Mac.

        Without this the guard is only exercised on a platform nobody has run a
        capture on, which is the same as not being exercised.
        """
        import lab.capture as C
        import training.trajectories as T

        monkeypatch.setattr(T, "redact_identity",
                            lambda text: text.replace("/tmp", "C:\\Temp"))
        monkeypatch.setattr(T, "identity_leaks", lambda text: [])

        out = tmp_path / "x.json"
        with pytest.raises(RuntimeError, match="invalid JSON"):
            C._write_redacted(out, json.dumps({"root": "/tmp/x"}), as_json=True)
        assert not out.exists()


class TestTurnsByPhase:
    def test_counts_every_phase_including_the_ones_that_did_not_happen(self):
        """A missing key is a key somebody sums as zero one time and skips the next."""
        assert turns_by_phase(Episode(task="t", host="h", scope="s",
                                      catalogue="c")) == {
            "plan": 0, "detect": 0, "remediate": 0, "verify": 0}
        assert turns_by_phase(_closed_cycle()) == {
            "plan": 2, "detect": 1, "remediate": 1, "verify": 2}


def _meta(*, remediation: str = "on") -> CaptureMeta:
    return CaptureMeta(checkpoint="ckpt", target="sandbox", telemetry="disabled",
                       timestamp="2026-01-01T00:00:00+00:00", driver="test",
                       remediation=remediation)
