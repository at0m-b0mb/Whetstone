"""Tests for the gate — the part that must never regress.

The whole safety surface is a pure function of (engagement, verb, action,
clock), so it can be tested exhaustively with no lab, no VM and no target. That
is the point of the design and this file is the payoff.

Where a test asserts on a rule id rather than a message, that is deliberate:
messages are prose for humans and may be reworded, rule ids are a contract.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from whetstone.actions import (
    NO_DETECTION,
    Action,
    Intent,
    Param,
    SchemaError,
    Side,
    TargetKind,
    Verb,
    VerbRegistry,
)
from whetstone.gate import (
    AuditError,
    AuditLog,
    Engagement,
    EngagementError,
    Gate,
    GateRefusal,
    Verdict,
    always_confirm,
    decide,
    null_engagement,
    parse_engagement,
    verify,
)
from whetstone.gate.engagement import Authorization, Scope

NOW = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)


# --------------------------------------------------------------------------
# fixtures: a miniature registry, independent of the real catalogue so that
# adding a verb to whetstone/verbs.py can never silently change these results
# --------------------------------------------------------------------------


def _registry() -> VerbRegistry:
    r = VerbRegistry()
    r.register(Verb(
        id="enum.host", summary="Look at the host.",
        intent=Intent.OBSERVE, side=Side.NEUTRAL, target=TargetKind.HOST,
    ))
    r.register(Verb(
        id="detect.x", summary="A detection.",
        intent=Intent.OBSERVE, side=Side.BLUE, target=TargetKind.HOST,
    ))
    r.register(Verb(
        id="harden.thing", summary="Change something for the better.",
        intent=Intent.MODIFY, side=Side.BLUE, target=TargetKind.HOST,
        caution="Changes configuration.",
    ))
    r.register(Verb(
        id="exploit.thing", summary="Prove a weakness by using it.",
        intent=Intent.EXECUTE, side=Side.RED, target=TargetKind.HOST,
        attck=("T1547.001",), caution="Runs code on the target.",
        detected_by=("detect.x",),
    ))
    r.register(Verb(
        id="exploit.multi", summary="Two techniques at once.",
        intent=Intent.EXECUTE, side=Side.RED, target=TargetKind.HOST,
        attck=("T1547.001", "T1053.005"), caution="Runs code on the target.",
        detected_by=("detect.x",),
    ))
    r.register(Verb(
        id="fs.read", summary="Read a file.",
        intent=Intent.OBSERVE, side=Side.NEUTRAL, target=TargetKind.PATH,
    ))
    r.register(Verb(
        id="report.note", summary="Write down a finding.",
        intent=Intent.OBSERVE, side=Side.NEUTRAL, target=TargetKind.NONE,
    ))
    return r.freeze()


REG = _registry()


def _engagement(**kw) -> Engagement:
    base = dict(
        name="test exercise",
        authorization="TICKET-1 approved by nobody, this is a test",
        starts=NOW - timedelta(hours=1),
        expires=NOW + timedelta(hours=1),
        scope=Scope(hosts=("10.0.0.0/24", "*.lab.internal"),
                    exclude_hosts=("10.0.0.1",),
                    paths=("/tmp/lab",),
                    exclude_paths=("/tmp/lab/secrets",)),
        authorize=Authorization(red_team=True, max_intent=Intent.EXECUTE,
                                techniques=("T1547",),
                                unattended=frozenset({Intent.OBSERVE})),
    )
    base.update(kw)
    return Engagement(**base)


def _rule(engagement, verb_id, target=None, **params):
    verb = REG.get(verb_id)
    action = verb.bind(params, target=target)
    return decide(engagement, verb, action, now=NOW)


# --------------------------------------------------------------------------
# schema
# --------------------------------------------------------------------------


class TestSchema:
    def test_verb_id_must_be_dotted_lowercase(self):
        for bad in ("Enum.Host", "enumhost", "enum..host", "1enum.host", "enum.Host"):
            with pytest.raises(SchemaError, match="lowercase dotted"):
                Verb(id=bad, summary="x", intent=Intent.OBSERVE,
                     side=Side.NEUTRAL, target=TargetKind.HOST)

    def test_non_observe_verb_must_declare_caution(self):
        with pytest.raises(SchemaError, match="must declare a caution"):
            Verb(id="harden.x", summary="x", intent=Intent.MODIFY,
                 side=Side.BLUE, target=TargetKind.HOST)

    def test_red_verb_must_name_its_detection(self):
        """The purple discipline, enforced by the schema rather than by review."""
        with pytest.raises(SchemaError, match="declares no detected_by"):
            Verb(id="exploit.x", summary="x", intent=Intent.EXECUTE,
                 side=Side.RED, target=TargetKind.HOST, caution="runs code")

    def test_red_verb_may_admit_nothing_detects_it(self):
        v = Verb(id="exploit.x", summary="x", intent=Intent.EXECUTE,
                 side=Side.RED, target=TargetKind.HOST, caution="runs code",
                 detected_by=(NO_DETECTION,))
        assert v.detected_by == (NO_DETECTION,)

    def test_freeze_rejects_dangling_detection_reference(self):
        r = VerbRegistry()
        r.register(Verb(id="exploit.x", summary="x", intent=Intent.EXECUTE,
                        side=Side.RED, target=TargetKind.HOST,
                        caution="runs code", detected_by=("detect.ghost",)))
        with pytest.raises(SchemaError, match="not a registered verb"):
            r.freeze()

    def test_frozen_registry_refuses_new_verbs(self):
        with pytest.raises(SchemaError, match="frozen"):
            REG.register(Verb(id="late.arrival", summary="x",
                              intent=Intent.OBSERVE, side=Side.NEUTRAL,
                              target=TargetKind.HOST))

    def test_malformed_attck_id_rejected(self):
        with pytest.raises(SchemaError, match="ATT&CK"):
            Verb(id="exploit.x", summary="x", intent=Intent.EXECUTE,
                 side=Side.RED, target=TargetKind.HOST, caution="c",
                 detected_by=(NO_DETECTION,), attck=("T547",))

    def test_bind_rejects_unknown_parameter(self):
        with pytest.raises(SchemaError, match="no parameter"):
            REG.bind("enum.host", {"nonsense": 1}, target="10.0.0.5")

    def test_bind_requires_a_target_for_host_verbs(self):
        with pytest.raises(SchemaError, match="needs a target"):
            REG.bind("enum.host")

    def test_bind_refuses_target_for_targetless_verbs(self):
        with pytest.raises(SchemaError, match="takes no target"):
            REG.bind("report.note", target="10.0.0.5")

    def test_integer_param_rejects_bool(self):
        """True is an int in Python; accepting it would hide a model mistake."""
        p = Param("n", "integer", "count")
        with pytest.raises(SchemaError, match="got boolean"):
            p.validate(True)

    def test_parse_rejects_hallucinated_verb(self):
        """Model output that names a verb we do not have must fail loudly."""
        with pytest.raises(SchemaError, match="unknown verb"):
            REG.parse({"verb": "exploit.invented", "params": {}, "target": "h"})


# --------------------------------------------------------------------------
# engagement documents
# --------------------------------------------------------------------------


class TestEngagement:
    def test_null_engagement_is_loopback_observe_only(self):
        e = null_engagement()
        assert e.authorize.max_intent is Intent.OBSERVE
        assert e.authorize.red_team is False
        assert e.scope.allow_loopback
        assert e.scope.hosts == ()

    def test_naive_timestamp_rejected(self):
        with pytest.raises(EngagementError, match="no timezone"):
            parse_engagement({
                "engagement": {"name": "x", "authorization": "a",
                               "expires": "2026-09-20T18:00:00"},
                "scope": {"hosts": ["10.0.0.1"]},
            })

    def test_unknown_key_is_an_error_not_a_warning(self):
        with pytest.raises(EngagementError, match="unknown top-level key"):
            parse_engagement({"engagement": {"name": "x"}, "scoop": {}})

    def test_bare_string_where_list_expected_is_rejected(self):
        with pytest.raises(EngagementError, match="bare string"):
            parse_engagement({
                "engagement": {"name": "x", "authorization": "a"},
                "scope": {"hosts": "10.0.0.1"},
            })

    def test_scope_without_authorization_is_rejected(self):
        with pytest.raises(EngagementError, match="who said you could"):
            Engagement(name="x", scope=Scope(hosts=("10.0.0.1",)))

    def test_red_team_without_techniques_is_rejected(self):
        with pytest.raises(EngagementError, match="no techniques are listed"):
            parse_engagement({
                "engagement": {"name": "x", "authorization": "a"},
                "authorize": {"red_team": True},
            })

    def test_expiry_before_start_is_rejected(self):
        with pytest.raises(EngagementError, match="expires at or before"):
            Engagement(name="x", starts=NOW, expires=NOW - timedelta(hours=1))

    def test_technique_prefix_covers_subtechnique(self):
        a = Authorization(techniques=("T1547",))
        assert a.technique_allowed(("T1547.001",))
        assert not a.technique_allowed(("T1548.002",))

    def test_every_technique_must_be_allowed_not_just_one(self):
        """A verb touching two techniques where one is in scope is not half-ok."""
        a = Authorization(techniques=("T1547",))
        assert not a.technique_allowed(("T1547.001", "T1053.005"))


class TestScopeMatching:
    def test_cidr_matches_address_inside(self):
        s = Scope(hosts=("10.0.0.0/24",))
        assert s.host_included("10.0.0.7")
        assert not s.host_included("10.0.1.7")

    def test_hostname_glob(self):
        s = Scope(hosts=("*.lab.internal",))
        assert s.host_included("dc01.lab.internal")
        assert not s.host_included("dc01.prod.internal")

    def test_hostname_is_not_resolved_against_a_cidr(self):
        """Scope must not depend on DNS we do not control."""
        s = Scope(hosts=("10.0.0.0/24",))
        assert not s.host_included("dc01.lab.internal")

    def test_exclusion_beats_a_covering_range(self):
        s = Scope(hosts=("10.0.0.0/24",), exclude_hosts=("10.0.0.1",))
        assert s.host_included("10.0.0.1")       # the range does cover it
        assert s.host_excluded("10.0.0.1")       # and the exclusion wins

    def test_path_scope_survives_symlink_escape(self, tmp_path: Path):
        inside = tmp_path / "lab"
        outside = tmp_path / "elsewhere"
        inside.mkdir()
        outside.mkdir()
        (outside / "loot.txt").write_text("secret")
        link = inside / "shortcut"
        link.symlink_to(outside)

        s = Scope(paths=(str(inside),))
        assert s.path_included(str(inside / "ok.txt"))
        # The symlink resolves outside the tree, so it is not in scope.
        assert not s.path_included(str(link / "loot.txt"))

    def test_path_traversal_does_not_escape(self, tmp_path: Path):
        inside = tmp_path / "lab"
        inside.mkdir()
        s = Scope(paths=(str(inside),))
        assert not s.path_included(str(inside / ".." / "etc" / "passwd"))


# --------------------------------------------------------------------------
# policy — the rules themselves
# --------------------------------------------------------------------------


class TestPolicy:
    def test_observe_in_scope_runs_unattended(self):
        d = _rule(_engagement(), "enum.host", target="10.0.0.5")
        assert d.verdict is Verdict.ALLOW
        assert d.rule == "intent.unattended"

    def test_out_of_scope_host_denied(self):
        d = _rule(_engagement(), "enum.host", target="192.168.1.1")
        assert d.verdict is Verdict.DENY
        assert d.rule == "scope.host.unlisted"

    def test_excluded_host_denied_even_though_range_covers_it(self):
        d = _rule(_engagement(), "enum.host", target="10.0.0.1")
        assert d.verdict is Verdict.DENY
        assert d.rule == "scope.host.excluded"

    def test_expired_engagement_denies_everything(self):
        e = _engagement(expires=NOW - timedelta(minutes=1))
        d = _rule(e, "enum.host", target="10.0.0.5")
        assert d.rule == "engagement.expired"

    def test_engagement_not_yet_started_denies(self):
        e = _engagement(starts=NOW + timedelta(hours=1),
                        expires=NOW + timedelta(hours=2))
        d = _rule(e, "enum.host", target="10.0.0.5")
        assert d.rule == "engagement.early"

    def test_scope_is_checked_before_intent(self):
        """Out of scope is the more fundamental problem; say that one."""
        e = _engagement(authorize=Authorization(max_intent=Intent.OBSERVE))
        d = _rule(e, "harden.thing", target="192.168.1.1")
        assert d.rule == "scope.host.unlisted"

    def test_intent_ceiling_denies_above_it(self):
        e = _engagement(authorize=Authorization(max_intent=Intent.OBSERVE))
        d = _rule(e, "harden.thing", target="10.0.0.5")
        assert d.rule == "intent.ceiling"

    def test_red_verb_denied_without_red_team_authorization(self):
        e = _engagement(authorize=Authorization(
            red_team=False, max_intent=Intent.EXECUTE))
        d = _rule(e, "exploit.thing", target="10.0.0.5")
        assert d.rule == "red.unauthorized"

    def test_red_verb_denied_when_technique_not_authorized(self):
        e = _engagement(authorize=Authorization(
            red_team=True, max_intent=Intent.EXECUTE, techniques=("T1003",)))
        d = _rule(e, "exploit.thing", target="10.0.0.5")
        assert d.rule == "technique.unauthorized"

    def test_red_verb_denied_when_only_some_techniques_authorized(self):
        e = _engagement(authorize=Authorization(
            red_team=True, max_intent=Intent.EXECUTE, techniques=("T1547",)))
        d = _rule(e, "exploit.multi", target="10.0.0.5")
        assert d.rule == "technique.unauthorized"

    def test_authorized_red_verb_falls_through_to_confirm(self):
        d = _rule(_engagement(), "exploit.thing", target="10.0.0.5")
        assert d.verdict is Verdict.CONFIRM
        assert d.rule == "default.confirm"

    def test_caution_text_reaches_the_confirmation(self):
        d = _rule(_engagement(), "exploit.thing", target="10.0.0.5")
        assert "Runs code on the target." in d.reason

    def test_execute_can_be_made_unattended_by_the_document(self):
        """Autonomy is a property of the engagement, not a hole in the gate."""
        e = _engagement(authorize=Authorization(
            red_team=True, max_intent=Intent.EXECUTE, techniques=("T1547",),
            unattended=frozenset({Intent.OBSERVE, Intent.MODIFY, Intent.EXECUTE})))
        d = _rule(e, "exploit.thing", target="10.0.0.5")
        assert d.verdict is Verdict.ALLOW
        assert d.rule == "intent.unattended"

    def test_targetless_verb_skips_scope_entirely(self):
        d = _rule(_engagement(), "report.note")
        assert d.verdict is Verdict.ALLOW

    def test_path_verb_checked_against_path_scope(self, tmp_path):
        e = _engagement(scope=Scope(paths=(str(tmp_path),)))
        assert _rule(e, "fs.read", target=str(tmp_path / "a")).verdict is Verdict.ALLOW
        assert _rule(e, "fs.read", target="/etc/passwd").rule == "scope.path.unlisted"

    def test_null_engagement_allows_loopback_observe(self):
        d = _rule(null_engagement(), "enum.host", target="127.0.0.1")
        assert d.verdict is Verdict.ALLOW

    def test_null_engagement_denies_everything_else(self):
        e = null_engagement()
        assert _rule(e, "enum.host", target="10.0.0.5").rule == "scope.host.unlisted"
        assert _rule(e, "exploit.thing", target="127.0.0.1").rule == "intent.ceiling"

    def test_unmatched_action_defaults_to_confirm_not_allow(self):
        """The fallthrough must be restrictive; a future verb is gated by default."""
        from whetstone.gate.policy import RULES
        assert RULES[-1][0] == "unattended"
        d = _rule(_engagement(), "harden.thing", target="10.0.0.5")
        assert d.verdict is Verdict.CONFIRM

    def test_decide_rejects_mismatched_verb_and_action(self):
        action = Action(verb_id="enum.host", target="10.0.0.5")
        with pytest.raises(ValueError, match="but was ruled against"):
            decide(_engagement(), REG.get("exploit.thing"), action, now=NOW)

    def test_no_rule_accepts_an_override_argument(self):
        """Structural: there is no way to soften a denial from the outside."""
        import inspect
        sig = inspect.signature(decide)
        assert set(sig.parameters) == {"engagement", "verb", "action", "now"}


# --------------------------------------------------------------------------
# audit log
# --------------------------------------------------------------------------


class TestAudit:
    def test_chain_verifies(self, tmp_path):
        log = AuditLog(tmp_path / "a.jsonl")
        for i in range(5):
            log.note(f"entry {i}")
        ok, msg = verify(log.path)
        assert ok, msg
        assert "5 record(s)" in msg

    def test_altered_record_is_detected(self, tmp_path):
        path = tmp_path / "a.jsonl"
        log = AuditLog(path)
        log.note("first")
        log.note("incriminating")
        log.note("third")

        lines = path.read_text().splitlines()
        doctored = json.loads(lines[1])
        doctored["text"] = "harmless"
        lines[1] = json.dumps(doctored, sort_keys=True)
        path.write_text("\n".join(lines) + "\n")

        ok, msg = verify(path)
        assert not ok
        assert "record 2" in msg and "altered" in msg

    def test_removed_record_is_detected(self, tmp_path):
        path = tmp_path / "a.jsonl"
        log = AuditLog(path)
        for i in range(4):
            log.note(f"entry {i}")
        lines = path.read_text().splitlines()
        del lines[1]
        path.write_text("\n".join(lines) + "\n")

        ok, msg = verify(path)
        assert not ok
        assert "removed or reordered" in msg

    def test_reopening_continues_the_chain(self, tmp_path):
        path = tmp_path / "a.jsonl"
        first = AuditLog(path)
        first.note("before restart")
        tip = first.tip

        second = AuditLog(path)
        assert len(second) == 1
        record = second.note("after restart")
        assert record.prev == tip
        assert record.seq == 2
        assert verify(path)[0]

    def test_payload_cannot_overwrite_chain_fields(self, tmp_path):
        log = AuditLog(tmp_path / "a.jsonl")
        with pytest.raises(AuditError, match="reserved key"):
            log.append("note", hash="fake")


# --------------------------------------------------------------------------
# the gate as a whole
# --------------------------------------------------------------------------


def _executor(verb, action):
    from whetstone.actions import Observation
    return Observation(action=action, ok=True, data={"ran": True})


class TestGate:
    def test_allowed_action_executes_and_is_logged(self, tmp_path):
        gate = Gate(_engagement(), registry=REG, audit=tmp_path / "g.jsonl")
        result = gate.submit(REG.bind("enum.host", target="10.0.0.5"), _executor, now=NOW)
        assert result.ran and result.observation.ok

        kinds = [r.kind for r in gate.audit]
        assert kinds == ["note", "decision", "observation"]

    def test_denied_action_raises_and_never_reaches_the_executor(self, tmp_path):
        calls = []

        def spy(verb, action):
            calls.append(action)
            raise AssertionError("executor must not run for a denied action")

        gate = Gate(_engagement(), registry=REG, audit=tmp_path / "g.jsonl")
        with pytest.raises(GateRefusal) as exc:
            gate.submit(REG.bind("enum.host", target="192.168.1.1"), spy, now=NOW)

        assert calls == []
        assert exc.value.decision.rule == "scope.host.unlisted"

    def test_denial_is_logged_as_carefully_as_approval(self, tmp_path):
        gate = Gate(_engagement(), registry=REG, audit=tmp_path / "g.jsonl")
        with pytest.raises(GateRefusal):
            gate.submit(REG.bind("enum.host", target="192.168.1.1"), _executor, now=NOW)

        decisions = [r for r in gate.audit if r.kind == "decision"]
        assert len(decisions) == 1
        assert decisions[0].payload["verdict"] == "deny"
        assert decisions[0].payload["rule"] == "scope.host.unlisted"
        assert verify(gate.audit.path)[0]

    def test_confirm_without_a_confirmer_is_a_refusal(self, tmp_path):
        """No human attached means the restrictive reading, not the permissive one."""
        gate = Gate(_engagement(), registry=REG, audit=tmp_path / "g.jsonl")
        with pytest.raises(GateRefusal) as exc:
            gate.submit(REG.bind("exploit.thing", target="10.0.0.5"), _executor, now=NOW)
        assert exc.value.decision.rule == "confirm.declined"

    def test_confirm_with_approval_runs(self, tmp_path):
        gate = Gate(_engagement(), registry=REG, audit=tmp_path / "g.jsonl",
                    confirmer=always_confirm, operator="tester")
        result = gate.submit(REG.bind("exploit.thing", target="10.0.0.5"), _executor, now=NOW)
        assert result.ran and result.confirmed
        decision = [r for r in gate.audit if r.kind == "decision"][0]
        assert decision.payload["confirmed_by"] == "tester"

    def test_declining_is_recorded(self, tmp_path):
        gate = Gate(_engagement(), registry=REG, audit=tmp_path / "g.jsonl",
                    confirmer=lambda v, a, d: False)
        with pytest.raises(GateRefusal):
            gate.submit(REG.bind("exploit.thing", target="10.0.0.5"), _executor, now=NOW)
        decision = [r for r in gate.audit if r.kind == "decision"][0]
        assert decision.payload["verdict"] == "deny"
        assert "declined" in decision.payload["reason"]

    def test_catalogue_hides_red_verbs_when_unauthorized(self):
        e = _engagement(authorize=Authorization(
            red_team=False, max_intent=Intent.EXECUTE))
        gate = Gate(e, registry=REG)
        ids = {v.id for v in gate.catalogue()}
        assert "enum.host" in ids
        assert not any(i.startswith("exploit.") for i in ids)

    def test_catalogue_hides_verbs_above_the_intent_ceiling(self):
        e = _engagement(authorize=Authorization(max_intent=Intent.OBSERVE))
        gate = Gate(e, registry=REG)
        ids = {v.id for v in gate.catalogue()}
        assert "enum.host" in ids
        assert "harden.thing" not in ids

    def test_submit_reruns_policy_rather_than_trusting_a_decision(self):
        """No API accepts a pre-computed Decision; submit always re-rules."""
        import inspect
        sig = inspect.signature(Gate.submit)
        assert "decision" not in sig.parameters

    def test_no_public_api_takes_a_force_flag(self):
        """The safety property, asserted mechanically across the package."""
        import inspect
        import whetstone.gate as g

        banned = {"force", "override", "yes", "skip_gate", "unsafe", "bypass"}
        for name in dir(g):
            obj = getattr(g, name)
            if not callable(obj) or name.startswith("_"):
                continue
            try:
                params = set(inspect.signature(obj).parameters)
            except (TypeError, ValueError):
                continue
            assert not (params & banned), f"{name} exposes {params & banned}"


# --------------------------------------------------------------------------
# the real catalogue
# --------------------------------------------------------------------------


class TestCatalogue:
    def test_real_registry_is_frozen_and_consistent(self):
        import whetstone.verbs  # noqa: F401  (registers on import)
        from whetstone.actions import REGISTRY

        assert REGISTRY.frozen
        assert len(REGISTRY) > 20

    def test_every_red_verb_names_a_detection_or_admits_none(self):
        import whetstone.verbs  # noqa: F401
        from whetstone.actions import REGISTRY

        for verb in REGISTRY.select(side=Side.RED):
            assert verb.detected_by, f"{verb.id} names no detection"
            assert verb.attck, f"{verb.id} maps to no ATT&CK technique"
            assert verb.caution, f"{verb.id} has no caution text"

    def test_coverage_reports_the_honest_gaps(self):
        import whetstone.verbs  # noqa: F401
        from whetstone.actions import REGISTRY

        coverage = REGISTRY.coverage()
        uncovered = [k for k, v in coverage.items() if not v]
        # postex.exfil_probe deliberately admits nothing detects it. If this
        # list grows, someone added an attack without a detection.
        assert uncovered == ["postex.exfil_probe"], uncovered

    def test_there_is_no_arbitrary_shell_verb(self):
        """The shortcut that would collapse the design. It must not exist."""
        import whetstone.verbs  # noqa: F401
        from whetstone.actions import REGISTRY

        for verb in REGISTRY:
            assert "command" not in {p.name for p in verb.params}, verb.id
            assert verb.id not in {"run.shell", "exec.command", "shell.run"}
