"""Run one lab exercise against the real Lima VM — the genuine article.

    python -m lab.vm.run                          # purple: attack, find the
                                                  # gap, fix it, re-attack
    python -m lab.vm.run --profile red-only       # attack and ask who saw.
                                                  # cannot harden.
    python -m lab.vm.run --profile blue-only      # posture and hardening.
                                                  # cannot attack at all.
    python -m lab.vm.run --arm                    # load the watch by hand
                                                  # first, so there is no gap

The VM version of ``lab.run``. The sandbox demonstrates the loop on a contained
directory; this demonstrates it on Ubuntu, against auditd, over SSH. The exploit
really overwrites a root-owned binary on the VM as an unprivileged user; the
detection really asks auditd whether it saw; and the hardening really moves the
mode bits and really loads the watch rule into the running kernel.

**Three modes, three engagements.** The separation is not three ways of
configuring one runner — it is three authorisation documents, built by
:mod:`lab.profiles`, and it is enforced inside the gate by
:class:`~whetstone.gate.Profile` rather than by which verbs this file happens to
put in a plan. That distinction is the whole point. A runner that simply
declines to propose ``exploit.service_permissions`` under a blue exercise has a
convention, and the convention holds right up until somebody drives the same
gate with ``--model``, which ranks over whatever catalogue it is handed and will
eventually rank an exploit first. Under these engagements the gate answers DENY
with a reason naming the mode, and no amount of proposing changes that. The
startup banner proves it for this run rather than asserting it: every verb the
adapter implements and the mode withholds is put to :meth:`Gate.rule` and the
refusal it actually returns is printed.

``--arm`` is the real-host equivalent of the sandbox's telemetry switch. Out of
the box the provisioned VM runs auditd with no rules loaded — the common
real-world state where the tool is present and watching nothing. Arming it by
hand loads the watch, so the same exploit that went unseen is now caught and no
gap appears. Leaving it unarmed under ``--profile purple`` is the interesting
run: the gap opens, the agent's own ``harden.enable_telemetry`` closes it, and
the kernel proves the closure by attacking a second time.

**This runner re-plants the lab's weakness before every exercise**, because the
modes really change the guest and a run that inherited the last run's posture
would measure the wrong thing. See :func:`reset_lab`, which says out loud what
it undid.
"""

from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path

import whetstone.verbs  # noqa: F401  (registers the catalogue)
from whetstone.actions import REGISTRY, SchemaError, TargetKind
from whetstone.gate import Gate, always_confirm
from whetstone.gate.engagement import Engagement
from whetstone.kernel import Kernel

from lab.profiles import PROFILE_NAMES, engagement_for

from .adapter import (AUDIT_KEY, AUDIT_RULE_ARGV, SERVICE_PATH,
                      TELEMETRY_SOURCE, VMAdapter, _LIMA_HOME, _VM)

#: The path scope every VM engagement carries, handed to the profile builders as
#: their ``root``.
#:
#: The contract documents ``root=None`` for the VM, which yields a host-only
#: scope with no ``paths`` at all — and a scope with no paths denies *every*
#: path-typed parameter, because :func:`~whetstone.gate.engagement._match_path`
#: matches nothing against an empty pattern list. That is the correct default
#: and it is fatal here for one verb: ``harden.fix_permissions`` declares
#: ``path``, so under a pathless scope it comes back ``scope.path.unlisted``
#: before the adapter is ever reached, and the defending half of this lab could
#: not run at all.
#:
#: So the VM asks for the narrowest path scope that lets its one path-typed verb
#: work: the directory the lab planted its weakness in, and nothing else.
#: ``/etc/shadow`` is still denied by the same rule, which is the property worth
#: having. Note that the gate resolves this against *this* machine's filesystem
#: while the adapter acts on the guest's — see ``lab.vm.adapter._lab_path``,
#: which checks the same confinement again on the guest's own terms, because the
#: two filesystems can disagree about what a path means.
LAB_SCOPE_ROOT = "/opt/acme"

#: What the guest's provisioning puts in the planted binary. :func:`reset_lab`
#: writes it back so every exercise starts from the state the yaml describes
#: rather than from whatever the last one left.
PLANTED_BINARY = "#!/bin/sh\nexec /usr/bin/true\n"

#: The mode the weakness is planted at: world-writable, owned by root. This is
#: the finding ``vuln.weak_permissions`` reports and the bit
#: ``harden.fix_permissions`` removes.
PLANTED_MODE = "0777"


# --------------------------------------------------------------------- plans
#
# Two sequences, because a red exercise and a blue exercise are not the same
# work in a different order. The scripted sweep is a stand-in for a chooser, not
# a model: required parameters a real model would fill from an observation are
# supplied explicitly so the demonstration is deterministic.

#: Look, assess, and attack. The kernel pairs each red action with the detection
#: that claims to cover its technique on its own, so ``detect.process_creation``
#: is not listed — it arrives as an injected probe aimed from what the attack
#: reported, which is the only form of it worth running.
_RED_PLAN = (
    ("enum.host", {}), ("enum.privileges", {}), ("enum.services", {}),
    ("enum.processes", {}),
    ("vuln.weak_permissions", {}), ("vuln.credential_exposure", {}),
    ("detect.telemetry", {}),
    ("exploit.service_permissions", {"service": "acme-agent"}),
)

#: Look, assess, read the controls, then fix. No red verb appears here and none
#: would run if it did — the engagement refuses them by rule. The findings a blue
#: run produces are posture findings, not detection gaps: the kernel's detection
#: pairing returns early for anything that is not a RED verb, so there is nothing
#: for the remediation phase to act on and it is not asked to.
#:
#: ``harden.remove_persistence`` is in the plan deliberately even though nothing
#: on this guest plants persistence. Its honest ``unsupported`` — "there is no
#: such entry here, and reporting a removal would be inventing one" — is the
#: single most useful line a blue run prints, because it is the one an adapter
#: written to look busy would have got wrong.
_BLUE_PLAN = (
    ("enum.host", {}), ("enum.privileges", {}), ("enum.services", {}),
    ("enum.processes", {}),
    ("vuln.weak_permissions", {}), ("vuln.credential_exposure", {}),
    ("detect.telemetry", {}),
    ("harden.enable_telemetry", {"source": TELEMETRY_SOURCE}),
    ("harden.fix_permissions", {"path": SERVICE_PATH}),
    ("harden.remove_persistence",
     {"entry": "/etc/cron.d/whetstone-persistence"}),
)


class _Mode:
    """One profile, the plan it runs and whether the remediation phase applies.

    ``remediate`` is a property of the mode rather than a flag, because two of
    the three modes cannot use the phase and saying so here is clearer than
    letting them discover it.

    Under **red-only** the kernel's ``_fix_candidates`` draws from
    ``gate.catalogue()``, which the profile has already emptied of ``harden.*``
    — so every gap would come back ``Remediation("unavailable")``. That is a
    correct answer and a useless one: it reports "nothing in the permitted
    catalogue declares that it remediates this" for a mode whose whole definition
    is that it may not harden. A red exercise ends at the gap, which is the
    product.

    Under **blue-only** no red verb runs, so ``_check_detections`` never fires
    and no gap is ever produced. The phase would have nothing to act on.
    """

    __slots__ = ("name", "plan", "remediate", "blurb")

    def __init__(self, name: str, plan, *, remediate: bool, blurb: str) -> None:
        self.name = name
        self.plan = plan
        self.remediate = remediate
        self.blurb = blurb


MODES: dict[str, _Mode] = {
    "red-only": _Mode(
        "red-only", _RED_PLAN, remediate=False,
        blurb=("attack the guest and ask whether anything saw. the gap is the "
               "product; this engagement may not close it.")),
    "blue-only": _Mode(
        "blue-only", _BLUE_PLAN, remediate=False,
        blurb=("read the guest's posture and harden it. no adversary emulation "
               "runs, so there are no detection gaps — only what the controls "
               "say about themselves and what the fixes actually changed.")),
    "purple": _Mode(
        "purple", _RED_PLAN, remediate=True,
        blurb=("the whole loop: attack, find the gap, fix it, and attack again "
               "to prove the fix held. a fix reporting success is a claim; the "
               "re-attack is the evidence.")),
}

#: Every explicit parameter either plan supplies, merged, so the startup banner
#: can put a *withheld* verb to the gate and print the refusal it really
#: returns. Built from the plans rather than typed a second time: a banner that
#: ruled on different parameters than the run would use is a banner describing a
#: different question.
_PLAN_PARAMS: dict[str, dict] = {
    verb_id: dict(extra) for verb_id, extra in (*_RED_PLAN, *_BLUE_PLAN)
}


class Sweep:
    """Plays a fixed sequence, skipping anything refused or already run."""

    def __init__(self, plan=_RED_PLAN):
        self.plan = list(plan)

    def choose(self, episode, permitted, *, exclude, target):
        done = {t.action.verb_id for t in episode.turns} | set(exclude)
        by_id = {v.id: v for v in permitted}
        for verb_id, extra in self.plan:
            if verb_id in done or verb_id not in by_id:
                continue
            verb = by_id[verb_id]
            params = {p.name: (p.choices[0] if p.choices else p.default)
                      for p in verb.params if p.default is not None}
            params = {k: v for k, v in params.items() if v is not None}
            params.update(extra)
            return verb.bind(params,
                             target=None if verb.target is TargetKind.NONE else target)
        return None


def _vm(argv, *, timeout: int = 30, **kw):
    """Run one argv on the VM, bounded. A stalled guest must degrade, not wedge.

    These auditctl/chmod/truncate calls run outside the adapter, so ``Adapter.
    execute``'s exception-to-Observation safety net does not cover them, and a
    bare ``subprocess.run`` with no deadline blocks the runner forever on a
    half-open Lima SSH session (routine on macOS wake). Before the episode that
    hangs the process with no diagnostic; after it, ``disarm_auditd`` never
    returns, so the run looks finished but never exits and the audit rule is left
    armed on the VM. A finite timeout turns the stall into a failed
    CompletedProcess the caller can see and act on, matching ``_run_on_vm`` in
    the adapter.
    """
    try:
        return subprocess.run(
            ["limactl", "shell", "--workdir", "/", _VM, "--", *argv],
            env={**os.environ, "LIMA_HOME": _LIMA_HOME},
            capture_output=True, text=True, timeout=timeout, **kw)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(
            argv, returncode=-1, stdout="",
            stderr=f"timed out after {timeout}s")


def _vm_stdin(argv, payload: str, *, timeout: int = 30):
    """``_vm`` for a command that reads its payload from stdin, equally bounded.

    Separate so the timeout cannot be forgotten, for the reason the adapter's
    ``_run_on_vm_stdin`` gives: a blocked ``subprocess.run`` never raises, so
    nothing upstream can catch it.
    """
    return _vm(argv, timeout=timeout, input=payload)


def arm_auditd() -> None:
    """Load the file-modification watch, so the blue side actually watches.

    Whether auditd was armed is the experiment's independent variable — the whole
    run's conclusion is read against it — so asserting "armed" without checking
    the result would be asserting the very thing under test. A failed auditctl
    (missing binary, ``-e 2`` locked config, no passwordless sudo on a
    re-provisioned VM) would otherwise print "armed" while nothing watches, and
    the unrecorded exploit would then be reported as a real control that missed a
    root-binary overwrite: a fabricated indictment, the wrong-number-nobody-
    notices this project refuses to emit. So we check the returncode and fail
    loudly instead.

    The rule comes from :data:`~lab.vm.adapter.AUDIT_RULE_ARGV`, the same
    constant ``harden.enable_telemetry`` loads. The run's central comparison is
    "armed by hand, no gap" against "armed by the agent, gap closed", and two
    rules that had drifted apart would make that comparison meaningless while
    still printing a number.
    """
    r = _vm(["sudo", "auditctl", *AUDIT_RULE_ARGV])
    if r.returncode != 0:
        raise SystemExit(
            f"could not arm auditd (auditctl rc={r.returncode}): "
            f"{r.stderr.strip()[:200] or 'no error output'}")
    print(f"armed auditd by hand: file-modification watch on {SERVICE_PATH} "
          f"(key={AUDIT_KEY})\n")


def disarm_auditd() -> None:
    # Result intentionally not fatal: disarm is teardown, and a failure here must
    # not mask the episode's own report. It is still bounded by _vm's timeout so
    # it cannot hang the process on the way out. A non-zero rc is surfaced as a
    # warning rather than swallowed, so a rule left loaded on the VM is at least
    # visible to the operator.
    r = _vm(["sudo", "auditctl", "-D"])
    if r.returncode != 0:
        print(f"warning: could not disarm auditd (rc={r.returncode}); "
              f"the watch rule may still be loaded on the VM")


def reset_lab() -> None:
    """Put the guest back to the state its provisioning describes.

    Every mode here really changes the VM. Blue-only chmods the planted binary
    and loads a watch rule; purple does both on its own initiative; the exploit
    rewrites the binary and restores it. None of that is undone at exit, and it
    must not be inherited: a purple run that started on a guest a previous
    blue-only run had already hardened would find the exploit failing for a
    reason nothing in its own transcript explains, and would report a technique
    that "no longer runs" as if that were this exercise's finding.

    So the weakness is re-planted before every exercise, exactly as the yaml
    plants it — the binary's contents as well as its mode, because the exploit
    reads the current contents as its restore baseline and a file left holding a
    previous run's marker makes that baseline a tampered one.

    Loud on failure, and fatal. A run whose starting state is not the state it
    reports starting from measures something nobody asked about.
    """
    disarm_auditd()
    w = _vm_stdin(["sudo", "tee", SERVICE_PATH], PLANTED_BINARY)
    m = _vm(["sudo", "chmod", PLANTED_MODE, SERVICE_PATH])
    if w.returncode != 0 or m.returncode != 0:
        raise SystemExit(
            f"could not re-plant the lab's weakness at {SERVICE_PATH} "
            f"(tee rc={w.returncode}, chmod rc={m.returncode}): "
            f"{(w.stderr or m.stderr).strip()[:200] or 'no error output'}. "
            "The exercise would start from an unknown posture and report it as "
            "the planted one.")
    # Read it back. The exit codes above are claims about two commands that ran
    # over SSH; the mode is the evidence, and this run's entire baseline rests on
    # it.
    s = _vm(["stat", "-c", "%a", SERVICE_PATH])
    if s.stdout.strip() != PLANTED_MODE.lstrip("0"):
        raise SystemExit(
            f"{SERVICE_PATH} is mode {s.stdout.strip()!r} after re-planting, "
            f"not {PLANTED_MODE}. The weakness this exercise is about is not "
            "actually present.")
    print(f"reset: {SERVICE_PATH} re-planted at mode {PLANTED_MODE}, auditd "
          "rules cleared. anything a previous exercise changed here is gone.")


def _engagement(profile: str) -> Engagement:
    """The engagement for one mode, from :mod:`lab.profiles`.

    Built there and not here on purpose. The inline engagement this runner used
    to carry was a fourth document that happened to resemble purple, and a mode
    that exists only as a runner's habit is not a mode. See
    :data:`LAB_SCOPE_ROOT` for the one thing the VM asks of it.
    """
    try:
        return engagement_for(profile, LAB_SCOPE_ROOT)
    except ValueError as exc:               # an unknown mode names all three
        raise SystemExit(str(exc)) from None


def _rule_for(gate: Gate, verb_id: str, target: str):
    """Dry-run ruling on ``verb_id`` with the parameters the plans would use.

    Returns the :class:`~whetstone.gate.policy.Decision`, or ``None`` when the
    verb cannot be bound at all from what the plans supply — which is reported as
    itself rather than guessed past, since a placeholder parameter would produce
    a ruling on an action nobody would ever submit.

    ``Gate.rule`` neither executes nor logs, so this costs nothing and touches
    the guest not at all.
    """
    verb = REGISTRY.get(verb_id)
    params = {p.name: (p.choices[0] if p.choices else p.default)
              for p in verb.params if p.default is not None}
    params = {k: v for k, v in params.items() if v is not None}
    params.update(_PLAN_PARAMS.get(verb_id, {}))
    try:
        action = verb.bind(
            params, target=None if verb.target is TargetKind.NONE else target)
    except SchemaError:
        return None
    return gate.rule(action)


def print_mode(gate: Gate, adapter: VMAdapter, mode: _Mode, target: str) -> None:
    """Say what this mode is, and prove it for this run rather than asserting it.

    Every verb the adapter implements and the catalogue withholds is put to the
    gate and the refusal it *actually* returns is printed beside it. That turns
    the banner from a description into a measurement, and it closes the one gap
    the catalogue filter leaves open.

    ``Gate.catalogue()`` and the policy rules are two implementations of one
    filter and can drift. The catalogue's own docstring says which way round to
    resolve a disagreement — the policy rules are the ones that are right — and
    the shipped test pins the dangerous direction: the catalogue never offers
    what ``decide()`` denies. The *other* direction is not pinned anywhere, and
    it is the one this loop catches: a catalogue that hides a verb the rules
    would permit makes the mode quietly narrower than its document says, so the
    sentence printed above ("this mode does not run that") is untrue of the
    thing that actually decides. A chooser reaching past the catalogue would
    find it allowed. That is fatal here rather than a warning, because every
    other line this banner prints would then be describing a different system.
    """
    print("=" * 74)
    print(f"mode: {mode.name} — {mode.blurb}")
    print(f"gate: {gate.engagement.authorize.profile.describe()}")
    print(f"scope: {LAB_SCOPE_ROOT} on the guest, loopback host, "
          f"expires {gate.engagement.expires.isoformat(timespec='seconds')}")

    implemented = set(adapter.implemented())
    offered = {v.id for v in gate.catalogue()} & implemented
    withheld = sorted(implemented - offered)
    print(f"this VM implements {len(implemented)} verb(s); this mode offers "
          f"{len(offered)} and withholds {len(withheld)}.")
    for verb_id in withheld:
        decision = _rule_for(gate, verb_id, target)
        if decision is None:
            print(f"    withheld  {verb_id}  (no plan supplies its required "
                  "parameters, so it was not ruled on)")
            continue
        if not decision.verdict.blocked:
            raise SystemExit(
                f"the {mode.name} catalogue withholds {verb_id} but the policy "
                f"rules return {decision}. The catalogue is the convenience and "
                "the rules are the control, so this mode is quietly narrower "
                "than the document says and a chooser reaching past the "
                "catalogue would be allowed through. Fix the rules, not this "
                "banner.")
        print(f"    DENY [{decision.rule}]  {verb_id}")
    print("=" * 74)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Run one lab exercise against the real Lima VM.")
    p.add_argument("--profile", choices=PROFILE_NAMES, default="purple",
                   help="which half of the tool is live (default: purple)")
    p.add_argument("--arm", action="store_true",
                   help="load the auditd watch by hand before running, so "
                        "there is no detection gap to find")
    p.add_argument("--model", type=Path,
                   help="drive with a trained checkpoint (constrained decoding)")
    p.add_argument("--tokenizer", type=Path,
                   default=Path("/Volumes/at0m_b0mb/whetstone/models/tokenizer-v1/tokenizer.json"))
    args = p.parse_args(argv)

    mode = MODES[args.profile]
    chooser = Sweep(mode.plan)
    if args.model:
        from training.agent import load_chooser
        print(f"driving the real VM with the trained model at {args.model}\n")
        chooser = load_chooser(args.model, args.tokenizer, verbose=True)

    adapter = VMAdapter()          # raises with instructions if the VM is down
    reset_lab()
    if args.arm:
        arm_auditd()
    # Truncate the audit log AFTER arming, not before. auditctl writes a
    # ``CONFIG_CHANGE op=add_rule key=...`` record the moment the watch loads;
    # truncating first would leave that keyed rule-administration record as the
    # first line of the fresh log, sitting inside the detection window for the
    # whole run. The detector now refuses to count CONFIG_CHANGE as a write, so
    # this ordering is belt-and-suspenders — but a clean log keeps anything that
    # reads it raw honest too, and truncating last still gives each exercise the
    # fresh telemetry the disposable lab wants. The log persists across runs, so
    # a stale keyed record from a previous exercise would otherwise be counted as
    # this run's exploit being seen. A failed truncate breaks exactly that
    # freshness assumption, so it is fatal rather than silent.
    r = _vm(["sudo", "truncate", "-s", "0", "/var/log/audit/audit.log"])
    if r.returncode != 0:
        raise SystemExit(
            f"could not truncate the audit log (rc={r.returncode}): "
            f"{r.stderr.strip()[:200] or 'no error output'}")

    target = "127.0.0.1"
    gate = Gate(_engagement(args.profile), registry=REGISTRY,
                confirmer=always_confirm)
    print_mode(gate, adapter, mode, target)

    task = {
        "red-only": ("Assess this Ubuntu host, prove the writable-service "
                     "finding, and tell me whether auditd saw it."),
        "blue-only": ("Read this Ubuntu host's posture and close what is open. "
                      "Do not attack it."),
        "purple": ("Assess this Ubuntu host, prove the writable-service "
                   "finding, tell me whether auditd saw it, and then fix what "
                   "it missed and prove the fix held."),
    }[mode.name]

    episode = Kernel(gate, adapter, chooser, max_turns=20,
                     remediate=mode.remediate).run(task, target=target)

    print(episode.summary())
    gaps = [f for f in episode.findings if f.kind == "detection_gap"]
    print("\n" + "-" * 74)
    state = "ARMED by hand" if args.arm else "no rules loaded at the start"
    print(f"{mode.name}: auditd {state} -> {len(gaps)} detection gap(s) on the "
          "real VM")
    for g in gaps:
        print(f"    GAP  {g.technique}: {g.detail}")

    if mode.remediate and gaps:
        # Counted by state rather than summarised as "remediated", because "we
        # ran a fix" and "the hole is shut" are the two claims this whole phase
        # exists to keep apart.
        closed = [g for g in gaps
                  if g.remediation is not None and g.remediation.proven_closed]
        print("\n" + "-" * 74)
        print(f"remediation -> {len(closed)} of {len(gaps)} gap(s) PROVEN "
              "closed, by re-running the attack against the real guest and "
              "re-asking auditd.")
        for g in gaps:
            fix = g.remediation
            if fix is None:
                print(f"    [NOT ATTEMPTED] {g.technique}")
                continue
            print(f"    [{fix.state.upper()}] {g.technique} "
                  f"via {fix.verb or '(nothing proposed)'}")
            print(f"        {fix.detail}")
    elif gaps and not mode.remediate:
        print(f"    ({mode.name} does not close gaps; that is the mode, not a "
              "failure to run)")
    print("-" * 74)
    disarm_auditd()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
