"""Tests for the three engagement profiles — red-only, blue-only, purple.

These run against the **real** registry on purpose, which is the opposite of
what ``tests/test_gate.py`` does and for a complementary reason. That file uses
a miniature registry so adding a verb cannot silently change its results; this
file walks the shipped catalogue so adding a verb cannot silently escape a mode.
Naming three verbs here would test the three verbs. Walking the registry tests
the separation, and goes red the day somebody adds a fourth on the wrong side of
it.

The load-bearing test in this file is
``TestTheProfileIsTheControl::test_red_verbs_are_denied_under_blue_by_the_profile_rule``.
Everything else could pass while the modes were still a convention — a runner
that happens not to propose the forbidden verb. That one fails unless the gate
itself refuses.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

import whetstone.verbs  # noqa: F401  (registers the catalogue this file walks)
from whetstone.actions import REGISTRY, Action, Intent, Side, TargetKind, Verb
from whetstone.gate import (Authorization, Engagement, EngagementError, Gate,
                            Profile, Scope, decide, parse_engagement)
from whetstone.gate.engagement import _PROFILE_CEILINGS

from lab.profiles import (PROFILE_NAMES, PROFILES, blue_only, engagement_for,
                          purple, red_only)

NOW = datetime(2026, 9, 19, 12, 0, tzinfo=timezone.utc)


# --------------------------------------------------------------------------
# walking the registry: one bindable, in-scope action per verb
# --------------------------------------------------------------------------


def _fill(verb: Verb, root: str) -> dict[str, object]:
    """Required parameters only, filled with values that are inside scope.

    In-scope matters more than it looks. Scope is ruled on before the profile,
    so an action aimed outside it comes back ``scope.host.unlisted`` — a real
    denial, for the wrong reason, which would let every test below pass against
    a gate that had no profile rule at all. Host-typed parameters get loopback
    and path-typed ones get the sandbox root so that the *only* thing left for
    the gate to object to is the mode.
    """
    out: dict[str, object] = {}
    for p in verb.params:
        if not p.required:
            continue
        if p.type == "host":
            out[p.name] = "127.0.0.1"
        elif p.type == "path":
            out[p.name] = root
        elif p.type == "enum":
            out[p.name] = p.choices[0]
        elif p.type == "integer":
            out[p.name] = 1
        elif p.type == "boolean":
            out[p.name] = True
        else:
            out[p.name] = "x"
    return out


def _action(verb: Verb, root: str) -> Action:
    target = {TargetKind.HOST: "127.0.0.1", TargetKind.PATH: root}.get(
        verb.target)
    return verb.bind(_fill(verb, root), target=target)


def _every(side: Side | None = None, intent: Intent | None = None) -> list[Verb]:
    return [v for v in REGISTRY
            if (side is None or v.side is side)
            and (intent is None or v.intent is intent)]


#: Every ``harden.*`` verb, found by what it is rather than by its name. A blue
#: verb that changes state is a hardening measure whatever it is called, and a
#: test that matched on the ``harden.`` prefix would miss the first one that
#: isn't.
def _harden_verbs() -> list[Verb]:
    return [v for v in REGISTRY
            if v.side is Side.BLUE and v.intent is not Intent.OBSERVE]


@pytest.fixture
def root(tmp_path) -> str:
    return str(tmp_path)


def _unprofiled(base: Engagement) -> Engagement:
    """``base`` with the mode removed and nothing else changed.

    The control condition for every "the profile is what did it" test below.
    """
    from dataclasses import replace
    return replace(base, authorize=replace(base.authorize, profile=None))


# --------------------------------------------------------------------------
# the table itself
# --------------------------------------------------------------------------


class TestProfileTable:
    def test_every_profile_has_a_row(self):
        """A profile missing from the table is a mode that decides nothing.

        Kept as a test rather than an import-time assertion because the failure
        it guards against is somebody adding a fourth ``Profile`` member and not
        the row underneath it — which is a thing found at review time, by a
        human, not at 2am by a KeyError three frames inside a policy rule.
        """
        assert set(_PROFILE_CEILINGS) == set(Profile)

    def test_every_mode_can_run_the_shared_substrate(self):
        """A row with no ``NEUTRAL`` entry is a mode that cannot ``enum.host``.

        Red and blue are the halves that differ; ``enum.*``, ``vuln.*`` and
        ``report.*`` are owned by neither and needed by both, so a mode that
        omits them is not a narrower exercise, it is one that cannot start. The
        keys are checked at the same time because a row keyed by the string
        ``"neutral"`` rather than the enum member would be an entry that looks
        right in a diff and matches nothing at decision time.
        """
        for profile, row in _PROFILE_CEILINGS.items():
            assert set(row) <= set(Side), profile
            assert all(isinstance(v, Intent) for v in row.values()), profile
            assert profile.ceiling(Side.NEUTRAL) is not None, profile

    def test_an_absent_side_is_none_not_observe(self):
        """None means "never runs" and OBSERVE means "runs, but only looks".

        Collapsing the two is the single change that would turn blue-only into
        an engagement where an exploit is merely above a ceiling rather than
        outside the mode.
        """
        assert Profile.BLUE.ceiling(Side.RED) is None
        assert Profile.RED.ceiling(Side.BLUE) is Intent.OBSERVE

    def test_describe_names_all_three_sides(self):
        for profile in Profile:
            text = profile.describe()
            for side in Side:
                assert side.value in text, (profile, side)


# --------------------------------------------------------------------------
# blue-only: no red verb reaches an adapter, ever
# --------------------------------------------------------------------------


class TestBlueOnly:
    def test_every_red_verb_in_the_registry_is_denied(self, root):
        e = blue_only(root)
        reds = _every(side=Side.RED)
        assert reds, "the registry has no red verbs; this test proves nothing"
        for verb in reds:
            d = decide(e, verb, _action(verb, root))
            assert d.verdict.blocked, f"{verb.id} was not denied under blue-only"

    def test_the_denial_names_the_mode(self, root):
        e = blue_only(root)
        for verb in _every(side=Side.RED):
            d = decide(e, verb, _action(verb, root))
            assert "blue-only" in d.reason, (
                f"{verb.id} was denied without saying which mode denied it: "
                f"{d.reason}")

    def test_blue_and_neutral_verbs_still_run(self, root):
        e = blue_only(root)
        for verb in REGISTRY:
            if verb.side is Side.RED:
                continue
            d = decide(e, verb, _action(verb, root))
            assert not d.verdict.blocked, f"{verb.id}: {d}"

    def test_hardening_is_permitted_because_that_is_the_point(self, root):
        e = blue_only(root)
        hardens = _harden_verbs()
        assert hardens, "no hardening verbs in the registry"
        for verb in hardens:
            assert not decide(e, verb, _action(verb, root)).verdict.blocked


# --------------------------------------------------------------------------
# red-only: attacks, observes, and cannot touch the defence
# --------------------------------------------------------------------------


class TestRedOnly:
    def test_every_harden_verb_is_denied(self, root):
        e = red_only(root)
        hardens = _harden_verbs()
        assert hardens, "no hardening verbs in the registry"
        for verb in hardens:
            d = decide(e, verb, _action(verb, root))
            assert d.verdict.blocked, f"{verb.id} was not denied under red-only"

    def test_the_denial_names_the_mode(self, root):
        e = red_only(root)
        for verb in _harden_verbs():
            d = decide(e, verb, _action(verb, root))
            assert "red-only" in d.reason, (
                f"{verb.id} was denied without saying which mode denied it: "
                f"{d.reason}")

    def test_red_verbs_run(self, root):
        e = red_only(root)
        for verb in _every(side=Side.RED):
            d = decide(e, verb, _action(verb, root))
            assert not d.verdict.blocked, f"{verb.id}: {d}"

    def test_detection_probes_still_run(self, root):
        """Red-only keeps ``detect.*``, and the mode is worthless without it.

        An attacker that cannot ask "did anything see that" cannot produce a
        detection gap, and the detection gap is the entire output of this
        project. What red-only takes away is the ability to *act* on the answer.
        """
        e = red_only(root)
        probes = _every(side=Side.BLUE, intent=Intent.OBSERVE)
        assert probes, "the registry has no blue observation verbs"
        for verb in probes:
            assert not decide(e, verb, _action(verb, root)).verdict.blocked


# --------------------------------------------------------------------------
# the bug this whole design exists to prevent
# --------------------------------------------------------------------------


class TestIntentAndSideAreTwoAxes:
    """Red has the higher ceiling. That must not be how it gets to harden.

    Every red verb is EXECUTE, so a red engagement's ``max_intent`` has to be
    EXECUTE — the top of the ladder. ``harden.*`` is MODIFY, one rung down. On
    a single-axis model that is an authorisation, and it is the wrong one.
    """

    def test_the_ceiling_alone_would_have_allowed_hardening(self, root):
        """The control condition: strip the mode and the hole reappears.

        This is the test that says what the profile is *for*. Same engagement,
        same ceiling, same techniques, same scope — only ``profile`` removed —
        and every hardening verb is permitted. If this ever stops failing to
        deny, the profile has stopped being the thing doing the work and
        something else is holding red-only up by accident.
        """
        e = _unprofiled(red_only(root))
        assert e.authorize.max_intent is Intent.EXECUTE
        for verb in _harden_verbs():
            d = decide(e, verb, _action(verb, root))
            assert not d.verdict.blocked, (
                f"{verb.id} was denied without a profile, so this test is no "
                f"longer demonstrating what the profile adds: {d}")

    def test_and_the_mode_closes_it(self, root):
        """The same verbs, the same everything, plus the mode: denied."""
        e = red_only(root)
        for verb in _harden_verbs():
            d = decide(e, verb, _action(verb, root))
            assert d.verdict.blocked and d.rule == "profile.intent", (
                f"{verb.id}: {d}")

    def test_blue_is_not_simply_a_lower_red(self, root):
        """The two modes are not ordered, and the fields say so out loud.

        Blue's ceiling is *lower* overall than red's and *higher* on the blue
        side. A reviewer who reads the profiles as points on one line will make
        the ceiling bug again, so the asymmetry is asserted rather than left to
        be noticed.
        """
        red, blue = red_only(root), blue_only(root)
        assert blue.authorize.max_intent.rank < red.authorize.max_intent.rank
        assert (Profile.BLUE.ceiling(Side.BLUE).rank
                > Profile.RED.ceiling(Side.BLUE).rank)


class TestTheProfileIsTheControl:
    """A mode that holds because of what a runner offers is a convention.

    These build engagements with every *other* authorisation field wide open —
    red authorised, EXECUTE ceiling, every technique listed — so that the
    profile rule is demonstrably the only thing standing between the chooser and
    the adapter. A model chooser ranks over whatever catalogue it is handed and
    will eventually rank an exploit first under a blue exercise; this is the
    test that says what happens when it does.
    """

    def _wide_open(self, root: str, profile: Profile) -> Engagement:
        return Engagement(
            name="deliberately over-authorised",
            authorization="TEST — everything on except the mode",
            starts=NOW - timedelta(hours=1), expires=NOW + timedelta(hours=1),
            scope=Scope(paths=(root,), allow_loopback=True),
            authorize=Authorization(
                red_team=True, max_intent=Intent.EXECUTE,
                techniques=tuple(sorted({t.split(".")[0]
                                         for v in REGISTRY for t in v.attck})),
                unattended=frozenset(Intent), profile=profile),
        )

    def test_red_verbs_are_denied_under_blue_by_the_profile_rule(self, root):
        """Not by ``red.unauthorized``, not by ``intent.ceiling`` — by the mode.

        The most load-bearing assertion in this file. ``red_team`` is True here
        and the ceiling is EXECUTE, so both of the older refusals are switched
        off; if the verdict is still DENY and the rule is still ``profile.*``,
        the separation is enforced by the gate and not by the engagement's other
        fields happening to be narrow.
        """
        e = self._wide_open(root, Profile.BLUE)
        for verb in _every(side=Side.RED):
            d = decide(e, verb, _action(verb, root), now=NOW)
            assert d.verdict.blocked and d.rule == "profile.side", (
                f"{verb.id}: {d}")
            assert "blue-only" in d.reason

    def test_harden_is_denied_under_red_by_the_profile_rule(self, root):
        e = self._wide_open(root, Profile.RED)
        for verb in _harden_verbs():
            d = decide(e, verb, _action(verb, root), now=NOW)
            assert d.verdict.blocked and d.rule == "profile.intent", (
                f"{verb.id}: {d}")
            assert "red-only" in d.reason

    def test_no_red_verb_reaches_an_adapter_under_blue(self, root):
        """The claim stated literally, through the path a runner actually takes.

        ``decide`` is the rule; :meth:`Gate.submit` is what a runner calls, and
        it is where the executor lives. Asserting on the executor rather than on
        the verdict closes the gap between "the gate said DENY" and "nothing
        ran" — a refusal that raises after the adapter has already been handed
        the action would satisfy every other test in this file.

        ``always_confirm`` is attached on purpose. A DENY has no override
        anywhere, so a confirmer that says yes to everything must not change the
        outcome by one verb.
        """
        from whetstone.gate import GateRefusal, always_confirm

        reached: list[str] = []

        def executor(verb, action):
            reached.append(verb.id)
            raise AssertionError(f"{verb.id} reached the adapter under blue-only")

        gate = Gate(self._wide_open(root, Profile.BLUE), registry=REGISTRY,
                    confirmer=always_confirm)
        for verb in _every(side=Side.RED):
            with pytest.raises(GateRefusal) as caught:
                gate.submit(_action(verb, root), executor, now=NOW)
            assert "blue-only" in caught.value.decision.reason
        assert reached == []

    def test_a_profile_only_ever_narrows(self, root):
        """It may turn ALLOW into DENY and must never do the reverse.

        Asserted across the whole registry and all three modes because the
        rule sits *above* ``intent.ceiling``, ``red.authorized`` and
        ``technique`` in the ordered table. A rule placed in front of three
        denials is one ``return Decision(ALLOW, ...)`` away from overriding all
        of them, which is the shape of the override this package promises
        nowhere to have.
        """
        for profile in Profile:
            profiled = self._wide_open(root, profile)
            plain = _unprofiled(profiled)
            for verb in REGISTRY:
                action = _action(verb, root)
                if decide(plain, verb, action, now=NOW).verdict.blocked:
                    assert decide(profiled, verb, action,
                                  now=NOW).verdict.blocked, (
                        f"{profile.value} promoted {verb.id} out of a denial")


# --------------------------------------------------------------------------
# purple: both halves
# --------------------------------------------------------------------------


class TestPurple:
    def test_every_verb_in_the_registry_is_permitted(self, root):
        """Red and blue both, which is the mode's whole claim.

        This doubles as the tripwire on ``lab.profiles._RED_TECHNIQUES``: a red
        verb added under a family that is not listed there comes back
        ``technique.unauthorized`` here, naming the technique, so the omission
        is found by a person who then adds it on purpose rather than by an
        exercise that quietly skipped an attack.
        """
        e = purple(root)
        for verb in REGISTRY:
            d = decide(e, verb, _action(verb, root))
            assert not d.verdict.blocked, f"{verb.id}: {d}"

    def test_attack_and_fix_are_both_available(self, root):
        e = purple(root)
        assert any(v.side is Side.RED for v in REGISTRY)
        for verb in _harden_verbs() + _every(side=Side.RED):
            assert not decide(e, verb, _action(verb, root)).verdict.blocked


# --------------------------------------------------------------------------
# an engagement without a mode behaves exactly as it did before
# --------------------------------------------------------------------------


class TestNoProfileIsInert:
    def test_the_null_engagement_has_no_profile(self):
        """It is "restricted", not "blue-only", and the two are different claims.

        Giving it a mode would be a widening dressed as a tightening: blue-only
        permits MODIFY on the blue side, and the null engagement permits nothing
        but OBSERVE anywhere.
        """
        from whetstone.gate import null_engagement
        assert null_engagement().authorize.profile is None

    def test_the_rule_is_inert_without_a_profile(self, root):
        from whetstone.gate.policy import _r_profile, _Ctx
        e = _unprofiled(purple(root))
        for verb in REGISTRY:
            ctx = _Ctx(engagement=e, verb=verb, action=_action(verb, root),
                       now=NOW)
            assert _r_profile(ctx) is None, verb.id

    def test_profile_sits_after_scope_and_before_the_ceiling(self):
        """Order is contract. Scope is the more fundamental no; the mode is the
        more *informative* one, so it must beat the ceiling and the red flag."""
        from whetstone.gate.policy import RULES
        names = [n for n, _ in RULES]
        assert names.index("scope.path") < names.index("profile")
        assert names.index("profile") < names.index("intent.ceiling")
        assert names.index("profile") < names.index("red.authorized")
        assert names[-1] == "unattended"

    def test_scope_still_beats_the_mode(self, root):
        """An out-of-scope exploit under blue-only is refused for being out of
        scope, not for the mode. The operator is told the harder problem."""
        e = blue_only(root)
        verb = REGISTRY.get("postex.lateral_move")
        action = verb.bind(_fill(verb, root), target="10.9.9.9")
        assert decide(e, verb, action).rule == "scope.host.unlisted"


# --------------------------------------------------------------------------
# the catalogue: a convenience that must agree with the rules
# --------------------------------------------------------------------------


class TestCatalogue:
    def test_blue_only_offers_no_red_verb(self, root):
        ids = {v.id for v in Gate(blue_only(root), registry=REGISTRY).catalogue()}
        assert not any(REGISTRY.get(i).side is Side.RED for i in ids)
        assert {v.id for v in _harden_verbs()} <= ids

    def test_red_only_offers_no_hardening_verb(self, root):
        """The temptation removed as well as the action refused.

        A red-only run that is still offered ``harden.*`` spends turns on
        guaranteed refusals, and a model chooser handed a fix it may never apply
        is being taught that refusals are weather. The refusal in
        :mod:`whetstone.gate.policy` is the control; this is the courtesy.
        """
        ids = {v.id for v in Gate(red_only(root), registry=REGISTRY).catalogue()}
        assert not ({v.id for v in _harden_verbs()} & ids)
        assert any(REGISTRY.get(i).side is Side.RED for i in ids)
        assert any(REGISTRY.get(i).side is Side.BLUE for i in ids), (
            "red-only lost the detection probes, so it can no longer find a gap")

    def test_purple_offers_both(self, root):
        ids = {v.id for v in Gate(purple(root), registry=REGISTRY).catalogue()}
        assert {v.id for v in _harden_verbs()} <= ids
        assert any(REGISTRY.get(i).side is Side.RED for i in ids)

    def test_the_catalogue_never_offers_what_the_rules_deny(self, root):
        """The two must not drift apart, and if they do the rules are right."""
        for build in (red_only, blue_only, purple):
            e = build(root)
            for verb in Gate(e, registry=REGISTRY).catalogue():
                d = decide(e, verb, _action(verb, root))
                assert not d.verdict.blocked, f"{e.name} offers {verb.id}: {d}"


# --------------------------------------------------------------------------
# the document, and the builders
# --------------------------------------------------------------------------


class TestDocument:
    def _doc(self, profile: str) -> dict:
        return {
            "engagement": {"name": "doc", "authorization": "TICKET-9"},
            "scope": {"allow_loopback": True},
            "authorize": {"max_intent": "modify", "profile": profile},
        }

    def test_a_mode_can_be_written_in_the_engagement_file(self):
        e = parse_engagement(self._doc("blue-only"))
        assert e.authorize.profile is Profile.BLUE

    def test_a_misspelled_mode_does_not_load(self):
        """Not defaulted to None, which would run a document that says
        "red-onyl" as one with no side separation at all."""
        with pytest.raises(EngagementError, match="is not a mode"):
            parse_engagement(self._doc("red-onyl"))

    def test_the_summary_names_the_mode(self, root):
        """On its own ``mode`` line, and carrying what the mode permits.

        Asserted against that line rather than against the whole summary, which
        is how the first version of this test managed to pass with the line
        deleted: ``red-only`` is also in ``lab red-only exercise``, so the
        assertion was reading the engagement's *name* back and reporting on a
        feature that was not there.
        """
        for build, profile in ((red_only, Profile.RED),
                               (blue_only, Profile.BLUE),
                               (purple, Profile.PURPLE)):
            lines = [ln for ln in build(root).summary().splitlines()
                     if ln.startswith("mode ")]
            assert len(lines) == 1, f"{profile.value}: {lines}"
            assert profile.value in lines[0]
            # The name alone tells an operator which mode; the description tells
            # them what it costs them. A refusal is only self-explanatory if the
            # summary they checked beforehand said what each side may do.
            assert profile.describe() in lines[0]

    def test_a_summary_without_a_mode_says_nothing_about_one(self, root):
        lines = [ln for ln in _unprofiled(purple(root)).summary().splitlines()
                 if ln.startswith("mode ")]
        assert lines == []


class TestBuilders:
    def test_the_three_names_are_the_gate_words(self):
        """One word for the flag, the document and the refusal."""
        assert set(PROFILE_NAMES) == {p.value for p in Profile}
        assert PROFILE_NAMES == ("red-only", "blue-only", "purple")

    def test_engagement_for_builds_each_one(self, root):
        for name in PROFILE_NAMES:
            e = engagement_for(name, root)
            assert e.authorize.profile is not None
            assert e.authorize.profile.value == name

    def test_an_unknown_name_says_what_the_names_are(self, root):
        with pytest.raises(ValueError, match="red-only"):
            engagement_for("attack", root)

    def test_no_root_scopes_to_the_vm_host_and_a_root_scopes_to_the_path(self, root):
        assert purple(None).scope.hosts == ("127.0.0.1",)
        assert purple(None).scope.paths == ()
        assert purple(root).scope.paths == (root,)
        assert purple(root).scope.allow_loopback

    def test_the_window_is_open_and_backdated(self, root):
        """A ``starts`` in the future denies everything as ``engagement.early``,
        and a target clock a few seconds ahead is enough to produce one."""
        for build in PROFILES.values():
            e = build(root)
            assert e.window_state() == "open"
            assert e.starts < datetime.now(timezone.utc)

    def test_an_unbounded_window_is_refused(self, root):
        """Loudly, rather than clamped: a clamp hands back an authorisation
        nobody asked for and says nothing about having done so."""
        for bad in (0, -1, 25):
            with pytest.raises(ValueError, match="lab window"):
                purple(root, hours=bad)

    def test_every_profile_records_who_authorised_it(self, root):
        for build in PROFILES.values():
            assert "LAB" in build(root).authorization
