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
        # The exclusion is written in both naming forms on purpose, and an
        # Engagement whose exclusions miss a form its hosts admit no longer
        # loads: with only `10.0.0.1` here, the same gateway was fully in scope
        # as gw.lab.internal, because scope never resolves a name.
        scope=Scope(hosts=("10.0.0.0/24", "*.lab.internal"),
                    exclude_hosts=("10.0.0.1", "gw.lab.internal"),
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


# --------------------------------------------------------------------------
# cross-platform output
# --------------------------------------------------------------------------


#: Every command that prints, including the one that prints the U+2190 arrow.
_CLI_COMMANDS = (
    ["verbs"],
    ["verbs", "--side", "red"],
    ["coverage"],
    ["-e", "examples/engagement.yaml", "check"],
    ["plan", "enum.host", "127.0.0.1"],
)


class _Cp1252:
    """A strict cp1252 text stream, in one of three shapes a console can take.

    ``kind`` picks which: ``"reconfigurable"`` is an ordinary wrapper that
    ``_force_utf8_output`` can convert to UTF-8, ``"refuses"`` raises from
    ``reconfigure`` the way a redirected or wrapped console can, and ``"absent"``
    has no ``reconfigure`` attribute at all, which is what a stdout replaced by
    a third-party wrapper looks like. The last two are the shapes in which the
    cp1252 encoding is still in force when the command prints — the only shapes
    in which the name "survives a legacy codepage" means anything.
    """

    def __init__(self, kind: str):
        import io

        self.raw = io.BytesIO()
        self.text = io.TextIOWrapper(self.raw, encoding="cp1252",
                                     errors="strict")
        self.kind = kind
        if kind == "reconfigurable":
            self.reconfigure = self.text.reconfigure
        elif kind == "refuses":
            self.reconfigure = self._refuse

    @staticmethod
    def _refuse(**_kw):
        raise ValueError("this console will not be reconfigured")

    def write(self, s: str) -> int:
        return self.text.write(s)

    def flush(self) -> None:
        self.text.flush()

    @property
    def encoding(self) -> str:
        return self.text.encoding


class TestCliEncoding:
    """Windows defaults its console to a legacy code page. CI caught this the
    hard way: `whet coverage` prints an arrow, cp1252 cannot encode it, and the
    command died with a UnicodeEncodeError on the happy path.

    The original test here installed a strict cp1252 stdout and ran five
    commands under it, and it was disarmed by the code it was testing: `main`
    calls `_force_utf8_output` as its first statement, so by the time anything
    printed the stream was UTF-8 with `errors="replace"` and an encoding failure
    had become impossible by construction. The condition the test was named for
    held for none of its five cases. What is left below is split in two: what
    that arrangement can honestly assert, and a separate test of the arrangement
    where cp1252 is still in force when the output is written.
    """

    def _run(self, argv, stream):
        import sys as _sys

        from whetstone.cli import main

        real_out, real_err = _sys.stdout, _sys.stderr
        _sys.stdout = _sys.stderr = stream
        try:
            main(argv)
            stream.flush()
        finally:
            _sys.stdout, _sys.stderr = real_out, real_err

    def test_every_command_forces_utf8_before_it_prints(self):
        """`_force_utf8_output` runs ahead of every command, not just some.

        This is what the old test was actually exercising, so it is stated as
        the property rather than left implicit: each command is entered with a
        cp1252 stream and must leave it UTF-8, which can only happen if `main`
        reached the guard before dispatching. Moving the call below the dispatch,
        or into individual subcommands, breaks this.
        """
        for argv in _CLI_COMMANDS:
            stream = _Cp1252("reconfigurable")
            self._run(argv, stream)
            assert stream.encoding == "utf-8", argv
            assert stream.raw.getvalue(), f"{argv} printed nothing"

    @pytest.mark.xfail(strict=True, reason=(
        "_force_utf8_output swallows a refusal, so a console that cannot be "
        "reconfigured keeps cp1252 and `whet coverage` dies on U+2190 while "
        "`whet check` dies on U+2192 — the CI failure in this class's docstring, "
        "in the one arrangement where it is still reachable. Live bug in "
        "whetstone/cli.py; remove this marker when the fallback lands."))
    @pytest.mark.parametrize("kind", ["refuses", "absent"])
    def test_every_command_survives_a_legacy_codepage(self, kind):
        """The arrangement the fix does not cover, written to fail while it does
        not cover it.

        `_force_utf8_output` treats both of these as best-effort: a `reconfigure`
        that raises is caught and passed over, and a stream without the attribute
        is skipped. Both leave cp1252 in force, and the commands then print into
        it. `test_reconfigure_failure_is_survivable` only establishes that
        `_force_utf8_output` itself does not raise, which is a different and much
        weaker claim than the one this class is named for.

        Two commands fail here, not one, and that is the argument for where the
        fix goes: `coverage` dies on the `←` in cli.py, and `check` dies on the
        `→` in `gate/engagement.py`'s window line. Spelling arrows out of the
        source would be chasing them — `adapters/linux.py` carries `→` and `●`
        as well, and anything that reaches stdout can add more. The fallback
        belongs on the stream: when it could not be converted, wrap it so every
        write is encoded with `errors="replace"`, which is the guarantee
        `reconfigure` was being asked for in the first place.

        Marked xfail rather than deleted because the bug is in
        `whetstone/cli.py` and not in this test. `strict=True`, so the moment
        that fallback lands this becomes a loud failure asking for the marker to
        come off, rather than sitting here green and forgotten.
        """
        for argv in _CLI_COMMANDS:
            self._run(argv, _Cp1252(kind))

    def test_reconfigure_failure_is_survivable(self):
        """A stream that refuses to reconfigure must not take the command down.

        Narrow on purpose, and narrower than it looks: it says
        `_force_utf8_output` returns rather than raising. It says nothing about
        whether the command's own output then survives, which is the question
        the test above asks and currently answers no.
        """
        import sys as _sys

        from whetstone.cli import _force_utf8_output

        class Stubborn:
            def reconfigure(self, **kw):
                raise ValueError("nope")

        real_out = _sys.stdout
        _sys.stdout = Stubborn()
        try:
            _force_utf8_output()
        finally:
            _sys.stdout = real_out


class TestCheckRehearsal:
    """`whet check` must rehearse against the engagement's own scope.

    It previously used a hardcoded 127.0.0.1, so every host verb failed on
    scope.host.unlisted and it reported "2 of 32 verbs, 0 of them red" for an
    engagement that plainly authorises eight red verbs.
    """

    def test_representative_host_comes_from_scope(self):
        from whetstone.cli import _representative_host
        e = _engagement(scope=Scope(hosts=("10.20.4.0/24",)))
        assert _representative_host(e) == "10.20.4.1"

    def test_representative_host_skips_excluded_addresses(self):
        from whetstone.cli import _representative_host
        e = _engagement(scope=Scope(hosts=("10.20.4.0/24",),
                                    exclude_hosts=("10.20.4.1", "10.20.4.2")))
        assert _representative_host(e) == "10.20.4.3"

    def test_glob_scope_yields_a_matching_name(self):
        from whetstone.cli import _representative_host
        e = _engagement(scope=Scope(hosts=("*.lab.internal",)))
        host = _representative_host(e)
        assert host and Scope(hosts=("*.lab.internal",)).host_included(host)

    def test_empty_host_scope_yields_none(self):
        from whetstone.cli import _representative_host
        e = Engagement(name="x", scope=Scope())
        assert _representative_host(e) is None

    def test_null_engagement_rehearses_against_loopback(self):
        from whetstone.cli import _representative_host
        assert _representative_host(null_engagement()) == "127.0.0.1"

    def test_check_counts_the_authorised_red_verbs(self, capsys):
        from whetstone.cli import main
        assert main(["-e", "examples/engagement.yaml", "check"]) == 0
        out = capsys.readouterr().out
        # 4 techniques authorised; exactly 3 red verbs fall inside them.
        assert "3 of them red" in out
        assert "blocked by technique.unauthorized" in out


class TestScopedParameters:
    """A parameter that names a host or a path is scope-checked like a target.

    Found by the trajectory generator, not by a test: ``postex.exfil_probe``
    declares ``sink`` as a host and its own caution told the operator the sink
    "is scope-checked like any other host" — while the rule read only
    ``action.target``. An exfiltration probe pointed at an in-scope target could
    therefore name any collector on the internet and be allowed. A caution that
    describes a check nobody implemented is worse than no caution, because it
    is relied upon.

    ``harden.fix_permissions`` had the same hole in the other direction: its target
    is not a path, so its ``path`` parameter was never compared against the path
    scope and a blue verb could write outside the engagement.
    """

    def _engagement(self):
        from datetime import datetime, timedelta, timezone

        from whetstone.actions import Intent
        from whetstone.gate.engagement import Authorization, Engagement, Scope

        now = datetime.now(timezone.utc)
        return Engagement(
            name="scoped-params",
            authorization="TEST",
            starts=now - timedelta(minutes=1),
            expires=now + timedelta(hours=1),
            scope=Scope(hosts=("127.0.0.1",), paths=("/tmp/lab",),
                        allow_loopback=True),
            authorize=Authorization(red_team=True, max_intent=Intent.EXECUTE,
                                    techniques=("T1041", "T1222"),
                                    unattended=frozenset(Intent)),
        )

    def test_exfil_sink_outside_scope_is_denied(self):
        import whetstone.verbs  # noqa: F401
        from whetstone.actions import REGISTRY
        from whetstone.gate.policy import decide

        action = REGISTRY.bind("postex.exfil_probe",
                               {"sink": "collector.evil.example"},
                               target="127.0.0.1")
        d = decide(self._engagement(), REGISTRY.get("postex.exfil_probe"),
                   action)
        assert d.verdict.name == "DENY", (
            "an in-scope target must not launder an out-of-scope sink")
        assert "sink" in d.reason

    def test_exfil_sink_inside_scope_is_not_denied_for_scope(self):
        import whetstone.verbs  # noqa: F401
        from whetstone.actions import REGISTRY
        from whetstone.gate.policy import decide

        action = REGISTRY.bind("postex.exfil_probe", {"sink": "127.0.0.1"},
                               target="127.0.0.1")
        d = decide(self._engagement(), REGISTRY.get("postex.exfil_probe"),
                   action)
        assert not d.rule.startswith("scope."), d.reason

    def test_harden_path_outside_scope_is_denied(self):
        import whetstone.verbs  # noqa: F401
        from whetstone.actions import REGISTRY
        from whetstone.gate.policy import decide

        # target=HOST with a path parameter: the path rule used to return
        # early because the TARGET was not a path, so this parameter was never
        # compared against the path scope at all.
        verb = REGISTRY.get("harden.fix_permissions")
        action = REGISTRY.bind("harden.fix_permissions",
                               {"path": "/etc/shadow"}, target="127.0.0.1")
        d = decide(self._engagement(), verb, action)
        assert d.verdict.name == "DENY", "blue verbs write too"
        assert "path" in d.reason

    def test_every_host_or_path_param_is_reachable_by_the_scope_rules(self):
        """No verb may declare a host/path parameter the rules cannot see."""
        import whetstone.verbs  # noqa: F401
        from whetstone.actions import REGISTRY
        from whetstone.gate.policy import _scoped_hosts, _scoped_paths

        for verb_id in REGISTRY.ids():
            verb = REGISTRY.get(verb_id)
            declared = {p.name for p in verb.params if p.type in ("host", "path")}
            if not declared:
                continue
            params = {p.name: "x" for p in verb.params if p.type in ("host", "path")}
            action = REGISTRY.bind(verb.id, params, target="127.0.0.1"
                                   if verb.target.name != "NONE" else None)

            class _C:
                pass

            c = _C()
            c.verb, c.action = verb, action
            seen = {n for n, _ in _scoped_hosts(c)} | {n for n, _ in _scoped_paths(c)}
            missing = declared - seen
            assert not missing, (
                f"{verb.id} declares {missing} as host/path but the scope "
                "rules would never check them")


# --------------------------------------------------------------------------
# host naming: one form for a value, both forms for a carve-out
#
# Three bypasses in the same seam, fixed as one change: an exclusion that
# cannot match the naming form the scope admits, an exclusion glob that was
# never compared against an address, and a host value that the gate and the
# adapter read as two different machines.
# --------------------------------------------------------------------------


def _open_window() -> dict:
    return {"starts": NOW - timedelta(hours=1), "expires": NOW + timedelta(hours=1)}


class TestExclusionsCannotBeInert:
    """An exclusion that cannot match is fail-open, and nothing reports it.

    The two directions of a scope fail in opposite ways. A pattern in ``hosts``
    that can never match denies everything and the operator notices within a
    minute; the same pattern in ``exclude_hosts`` denies nothing, and
    ``host_excluded`` returning None is indistinguishable from there being no
    exclusion at all. So the inert shapes are removed rather than documented:
    two of them by matching more in the exclusion direction, and the one that is
    genuinely undecidable without DNS by refusing the document at load.
    """

    def test_an_address_exclusion_alone_does_not_load_when_names_are_in_scope(self):
        """The shape the shipped example had: the gateway reachable by name."""
        with pytest.raises(EngagementError, match="by name"):
            Engagement(name="x", authorization="TICKET-1", **_open_window(),
                       scope=Scope(hosts=("10.20.4.0/24", "*.lab.internal"),
                                   exclude_hosts=("10.20.4.1",)))

    def test_a_name_exclusion_alone_does_not_load_when_addresses_are_in_scope(self):
        """The same hole mirrored: the carve-out misses the machine's IP."""
        with pytest.raises(EngagementError, match="by address"):
            Engagement(name="x", authorization="TICKET-1", **_open_window(),
                       scope=Scope(hosts=("10.20.4.0/24", "*.lab.internal"),
                                   exclude_hosts=("gw.lab.internal",)))

    def test_writing_the_carve_out_in_both_forms_loads(self):
        e = Engagement(name="x", authorization="TICKET-1", **_open_window(),
                       scope=Scope(hosts=("10.20.4.0/24", "*.lab.internal"),
                                   exclude_hosts=("10.20.4.1", "gw.lab.internal")))
        assert e.scope.host_excluded("10.20.4.1")
        assert e.scope.host_excluded("gw.lab.internal")

    def test_the_shipped_example_excludes_its_carve_outs_under_both_names(self):
        """The audit's failure case, run against the real document.

        A credential dump on the default gateway was DENY as ``10.20.4.1`` and
        ALLOW as ``gw.lab.internal`` — same machine, no human in the loop.
        """
        import whetstone.verbs  # noqa: F401
        from whetstone.actions import REGISTRY
        from whetstone.gate import load_engagement

        e = load_engagement("examples/engagement.yaml")
        verb = REGISTRY.get("postex.credential_dump")
        when = datetime(2026, 9, 17, 12, 0, tzinfo=timezone.utc)
        for target in ("10.20.4.1", "gw.lab.internal",
                       "10.20.4.50", "finance.lab.internal"):
            d = decide(e, verb, REGISTRY.bind(verb.id, {}, target=target), now=when)
            assert d.rule == "scope.host.excluded", (
                f"{target} is carved out of the engagement and got {d}")

    def test_a_glob_exclusion_covers_addresses_too(self):
        """``exclude_hosts: ["10.0.0.*"]`` used to exclude nothing whatsoever."""
        s = Scope(hosts=("10.0.0.0/24",), exclude_hosts=("10.0.0.*",))
        assert s.host_excluded("10.0.0.5") == "10.0.0.*"

    def test_an_inclusion_glob_still_refuses_to_match_an_address(self):
        """The asymmetry is deliberate and only leans one way.

        Matching more is safe in an exclusion and is a wider authorisation than
        anybody signed in an inclusion, so the glob relaxation applies to
        ``exclude_hosts`` alone.
        """
        assert not Scope(hosts=("10.0.0.*",)).host_included("10.0.0.5")

    def test_a_loopback_exclusion_covers_the_other_spelling(self):
        """Loopback is the one cross-form case decidable without asking DNS."""
        assert Scope(allow_loopback=True,
                     exclude_hosts=("127.0.0.1",)).host_excluded("localhost")
        assert Scope(allow_loopback=True,
                     exclude_hosts=("localhost",)).host_excluded("127.0.0.1")
        assert Scope(allow_loopback=True,
                     exclude_hosts=("127.0.0.0/8",)).host_excluded("localhost")


class TestCidrHostBits:
    """``strict=False`` turned one workstation into a whole subnet, silently.

    ``ip_network("192.168.1.50/24", strict=False)`` does not fail — it drops the
    host bits and returns 192.168.1.0/24. The document still said
    ``192.168.1.50/24`` and so did ``summary()``, so the 256-fold widening of a
    signed authorisation appeared nowhere. ``ip addr show`` prints exactly that
    shape, which is where an operator copies it from.
    """

    def test_an_address_with_host_bits_does_not_load(self):
        with pytest.raises(EngagementError, match="host bits"):
            Engagement(name="x", authorization="TICKET-1", **_open_window(),
                       scope=Scope(hosts=("192.168.1.50/24",)))

    def test_the_refusal_names_both_readings(self):
        """The operator has to say which one they signed for."""
        with pytest.raises(EngagementError) as exc:
            Engagement(name="x", authorization="TICKET-1", **_open_window(),
                       scope=Scope(hosts=("192.168.1.50/24",)))
        assert "192.168.1.0/24" in str(exc.value)
        assert "192.168.1.50/32" in str(exc.value)

    def test_a_raw_scope_with_host_bits_fails_closed(self):
        """Scope takes no document, so it cannot refuse — it must deny instead.

        Strict parsing leaves the pattern unparseable as a network, so it falls
        through to the glob branch and matches no address at all. Denying every
        host is the correct failure for an inclusion: it is loud within a minute
        and it widens nothing.
        """
        s = Scope(hosts=("192.168.1.50/24",))
        assert not s.host_included("192.168.1.200")
        assert not s.host_included("192.168.1.50")


class TestHostValueHasOneForm:
    """The gate has to rule on the exact string the adapter will dial.

    Every adapter re-parses a host before it opens a socket: all three strip a
    leading ``host:``, then cut a port off at a colon — macOS and Windows at the
    first colon, Linux at the last. So the gate matched
    ``evil.example.com:443.lab.internal`` against ``*.lab.internal``, said
    ALLOW, and the probe streamed to evil.example.com:443; and
    ``host:dc01.lab.internal`` walked past an exclusion on dc01, which the
    adapter then stripped back off. Authorising one string and dialling another
    is a parser differential, and the answer is not a fourth parser here but one
    legal form on which all of that re-parsing is the identity.
    """

    LAUNDERED: tuple[str, ...] = (
        "host:dc01.lab.internal",             # prefix the adapters strip
        "evil.example.com:443.lab.internal",  # the audit's sink
        "dc01.lab.internal:22",               # ordinary host:port
        "http://dc01.lab.internal",           # a URL is not a host
        "root@dc01.lab.internal",             # credentials do not belong here
        "[fe80::1]",                          # nothing unbrackets this
        "dc01.lab.internal ",                 # one adapter strips, one does not
        "*.lab.internal",                     # a pattern is not a value
    )

    def _engagement(self) -> Engagement:
        return Engagement(
            name="host-form", authorization="TICKET-1", **_open_window(),
            scope=Scope(hosts=("*.lab.internal", "10.20.4.0/24"),
                        paths=("/tmp/lab",)),
            authorize=Authorization(red_team=True, max_intent=Intent.EXECUTE,
                                    techniques=("T1003", "T1041", "T1547",
                                                "T1053", "T1021", "T1068",
                                                "T1574", "T1222"),
                                    unattended=frozenset(Intent)),
        )

    def test_a_sink_cannot_smuggle_a_second_host_past_the_scope(self):
        import whetstone.verbs  # noqa: F401
        from whetstone.actions import REGISTRY

        sink = "evil.example.com:443.lab.internal"
        # What the macOS and Windows adapters would have dialled, and the whole
        # reason the glob match on the full string meant nothing.
        assert sink.partition(":")[0] == "evil.example.com"

        verb = REGISTRY.get("postex.exfil_probe")
        action = REGISTRY.bind(verb.id, {"sink": sink}, target="ws01.lab.internal")
        d = decide(self._engagement(), verb, action, now=NOW)
        assert d.rule == "scope.host.malformed", d
        assert "sink" in d.reason

    def test_a_host_prefix_cannot_walk_past_an_exclusion(self):
        import whetstone.verbs  # noqa: F401
        from whetstone.actions import REGISTRY

        e = Engagement(
            name="prefix", authorization="TICKET-1", **_open_window(),
            scope=Scope(hosts=("*.lab.internal",),
                        exclude_hosts=("dc01.lab.internal",)),
            authorize=Authorization(red_team=True, max_intent=Intent.EXECUTE,
                                    techniques=("T1003",),
                                    unattended=frozenset(Intent)),
        )
        verb = REGISTRY.get("postex.credential_dump")
        action = REGISTRY.bind(verb.id, {}, target="host:dc01.lab.internal")
        d = decide(e, verb, action, now=NOW)
        assert d.verdict is Verdict.DENY, d
        assert d.rule in ("scope.host.malformed", "scope.host.excluded"), d

    def test_no_verb_accepts_a_laundered_host_in_any_host_slot(self):
        """Walk the registry: the class, not the one case.

        In the spirit of the general test in TestScopedParameters — a specific
        test fixes ``postex.exfil_probe``, this one holds for the verb somebody
        adds next year, whichever slot the host arrives in.
        """
        import whetstone.verbs  # noqa: F401
        from whetstone.actions import REGISTRY, TargetKind

        engagement = self._engagement()
        in_scope = {"host": "ws01.lab.internal", "path": "/tmp/lab/file"}
        checked = 0

        for verb_id in REGISTRY.ids():
            verb = REGISTRY.get(verb_id)
            slots = [p.name for p in verb.params if p.type == "host"]
            if verb.target is TargetKind.HOST:
                slots.append("target")
            if not slots:
                continue

            base = {p.name: (p.choices[0] if p.type == "enum"
                             else 1 if p.type == "integer"
                             else False if p.type == "boolean"
                             else in_scope.get(p.type, "placeholder"))
                    for p in verb.params if p.required}
            target = {TargetKind.HOST: in_scope["host"],
                      TargetKind.PATH: in_scope["path"]}.get(verb.target)

            for slot in slots:
                for bad in self.LAUNDERED:
                    params = dict(base)
                    this_target = target
                    if slot == "target":
                        this_target = bad
                    else:
                        params[slot] = bad
                    action = REGISTRY.bind(verb.id, params, target=this_target)
                    d = decide(engagement, verb, action, now=NOW)
                    assert d.rule == "scope.host.malformed", (
                        f"{verb.id} accepted {bad!r} in {slot}: {d}")
                    checked += 1

        assert checked, "the registry declared no host slots at all"

    def test_every_admitted_host_is_the_string_the_adapters_dial(self):
        """The property the form rule buys, stated as the adapters read it.

        These three re-parses are copied from whetstone/adapters/macos.py,
        windows.py and linux.py. If an adapter learns another way to chop a host
        up, this is where it has to be declared, because the gate's promise is
        that the string it authorised is the string that reaches the socket.
        """
        from whetstone.gate.engagement import host_form_error

        def strip_prefix(v: str) -> str:            # lateral_move, macos+windows
            return v.split(":", 1)[1] if v.startswith("host:") else v

        def first_colon(v: str) -> str:             # exfil sink, macos+windows
            return strip_prefix(v).partition(":")[0]

        def last_colon(v: str) -> str:              # exfil sink, linux
            return v.rpartition(":")[0] if ":" in v else v

        for value in ("dc01.lab.internal", "10.20.4.7", "sandbox-collector",
                      "localhost", "WS01.lab.internal", "printer-3f.office.internal"):
            assert host_form_error(value) is None, value
            for reparse in (strip_prefix, first_colon, last_colon):
                assert reparse(value) == value, (
                    f"an adapter would dial {reparse(value)!r}, not {value!r}")

        for bad in self.LAUNDERED:
            assert host_form_error(bad) is not None, bad

        # The one admitted form the colon splitters still cut in half. It is a
        # real host and the corpus uses IPv6 literals as ordinary out-of-scope
        # targets, so refusing them here would be an over-reach; the target path
        # handles them, and the splitters mangle rather than redirect. Closing
        # it properly means giving postex.exfil_probe its own integer `port`
        # parameter and deleting the splits, which is a change in verbs.py and
        # the three adapters, not in the gate.
        assert host_form_error("2001:db8::42") is None
        assert strip_prefix("2001:db8::42") == "2001:db8::42"
        assert first_colon("2001:db8::42") != "2001:db8::42"
