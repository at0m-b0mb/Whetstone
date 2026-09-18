"""Generate agent trajectories by actually running the agent.

``bench/whetbench.py`` scored ``action-json`` at 0/5 before this module existed:
the model could not emit an action the verb registry would accept. That was not
a mystery and not a capacity limit. The corpus contained **zero** trajectory
data — the TRAJECTORY register sat at 0.00% — so the model had learned the
language of security and had never once seen the job it exists to do.

This module closes that gap, and the important word is *actually*.

**Nothing here is imagined.** Every ``<|act|>`` is a real action the registry
bound and validated. Every ``<|obs|>`` is the real structured payload a real
adapter returned from a real command on a real machine or a real sandbox tree.
Every ``<|gate|>`` is a real ruling from :func:`whetstone.gate.policy.decide`,
and every ``<|find|>`` is a real :class:`~whetstone.kernel.Finding` the kernel
produced from the observations that precede it. Fabricating plausible
observations would be easy and would teach the model a world that does not
exist — it would learn to predict what tool output *looks like* rather than what
this tool *returns*, and the difference only shows up when something is wired to
a live host and answers confidently about a machine it misread.

**The loop renders the trajectory, not this file.** Earlier versions of this
module assembled protocol segments by hand and appended a hand-written
``<|find|>`` dict from the scenario definition. Two things were wrong with that.
The finding was emitted whether or not the observations supported one, which is
*training the model to hallucinate a finding* — precisely the failure this
project exists to avoid. And the hand-assembled segments drifted from
:func:`whetstone.kernel.render.render_episode`: the scope line was written in a
different order and the finding dict was missing the ``kind`` field the runtime
emits. A 61.5M model has no spare capacity to absorb a serving format that
differs from its training format, so both are now produced by exactly one
function. :class:`~whetstone.kernel.Kernel` runs; :meth:`Episode.render` emits.
This file only decides *what to run*.

**Refusals are training data, not errors.** A trajectory that proposes something
the engagement does not cover, receives a DENY with its reason, and carries on
with something that is in scope teaches recovery. A corpus of clean successes
teaches a model that has never seen a correction and does not know how to make
one — and this agent will be refused constantly, because that is what the gate
is for. DENY has no override anywhere in this system, so refusal has to be
learned as an ordinary part of the work rather than as an error state. Every
rule family the policy engine can produce is exercised here: out-of-scope hosts,
explicitly excluded hosts, expired and not-yet-open engagements, intent above
the ceiling, red verbs with no red-team authorisation, techniques outside the
authorised list, and actions that need a human where no human is attached.

**Silence and "cannot tell" are different claims.** :func:`detection_fired`
returns ``None`` when a detection query could not establish anything, and the
kernel records that as an ``observation`` finding that says so in words. If that
ever collapses into "did not fire", the tool manufactures detection gaps out of
broken queries and the report becomes worthless. The corpus therefore contains
episodes where the detection query genuinely fails — the telemetry log is really
unreadable — so the model sees the inconclusive wording as often as it sees the
gap wording.

**A healthy host is a case, not an absence.** Several scenario families run
against a sandbox with nothing planted in it: tight permissions, no credential
in the config, an empty crontab, current package versions. The vulnerability
verbs really run and really return ``{"findings": []}``, and the episode ends
with no ``<|find|>`` at all. A model that has only ever seen vulnerable hosts
will invent something to say about a clean one, and that is the failure mode
that gets a tool thrown out after its first real engagement.

**Observations are truncated deliberately and visibly.** ``enum.processes`` on a
real machine returns hundreds of records; a trajectory carrying all of them
would not fit in a 1024-token window and would teach the model that an
observation is mostly noise. Payloads are capped by the runtime's own
:func:`~whetstone.kernel.render.shrink_payload` and the cap is *stated in the
text* (``"...": "+412 more"``) so the model learns that observations are
summarised rather than learning that machines have four processes.

**What is not here, and why.** There are no Windows or Linux trajectories on a
macOS machine. The adapters exist for all three, but an adapter's observations
are only real on the platform they were read from, and labelling this Mac's
answers ``windows`` would be exactly the fabrication the first paragraph rules
out. ``--vm`` is the honest route to real Linux data and needs the Lima lab
armed; failing that, the ``<|host|>`` diversity in this corpus is ``macos`` and
``sandbox`` and the report should say so rather than pad the number.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import shutil
import tempfile
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Sequence

import whetstone.verbs  # noqa: F401  (registers and freezes the catalogue)
from whetstone.actions import REGISTRY, Action, Intent, Observation, TargetKind, Verb
from whetstone.gate import (REFUSE_UNATTENDED, Gate, always_confirm,
                            null_engagement)
from whetstone.gate.engagement import Authorization, Engagement, Scope
from whetstone.kernel import Kernel
from whetstone.kernel.render import MAX_ITEMS, MAX_VALUE, shrink_payload

__all__ = ["Scenario", "Step", "SCENARIOS", "generate_trajectories"]


#: Kept as module constants because callers and tests have referred to them, but
#: they are now aliases for the runtime's own caps rather than a second copy.
#: Two truncation policies would mean the corpus is capped one way and serving
#: another, and the model would meet observation shapes at serving time that it
#: was never trained on.
_MAX_ITEMS = MAX_ITEMS
_MAX_VALUE = MAX_VALUE


def _shrink(value: Any, depth: int = 0) -> Any:
    """Cap an observation payload, saying so where it cuts.

    Delegates to the runtime. The elision marker is part of the lesson: a model
    trained on silently truncated lists learns that hosts have four services;
    one trained on lists that carry ``"+118 more"`` learns that it is reading a
    summary and that the number is the interesting part.
    """
    return shrink_payload(value, depth)


# ---------------------------------------------------------------------------
# the language half: how a task is phrased
#
# The ``<|task|>`` segment is the model's instruction, and it is the one part of
# a trajectory nothing else constrains. If every episode opens with the same
# sentence the model learns that sentence rather than the job, and at serving
# time an operator who phrases the request differently gets a model that has
# never been conditioned on anything like it. So the phrasing is generated from
# a cross product rather than a list: bare noun phrases per verb, sixteen
# sentence frames, fourteen wrappers and a set of situational preambles. That is
# a few hundred thousand reachable strings, which is enough that the frame stops
# being the signal.
# ---------------------------------------------------------------------------

#: One bare noun phrase per verb, written so that any comma-separated list of
#: them reads as English inside any of the frames below. Keyed by verb id and
#: kept complete, so adding a verb to the catalogue without adding a phrase here
#: shows up immediately as a KeyError rather than as silently duller task text.
_NOUN: dict[str, str] = {
    "enum.host": "the operating system and hostname",
    "enum.users": "the local accounts",
    "enum.privileges": "the privileges this identity holds",
    "enum.processes": "the running processes",
    "enum.services": "the services and daemons",
    "enum.persistence": "the autostart entries",
    "enum.network": "the listening sockets and routes",
    "enum.software": "the installed software",
    "enum.shares": "the exported shares",
    "vuln.patch_gap": "the patch gap",
    "vuln.weak_permissions": "the weak file permissions",
    "vuln.credential_exposure": "any exposed credentials",
    "vuln.privilege_path": "a route from here to administrator",
    "detect.telemetry": "which logging sources are actually on",
    "detect.process_creation": "whether process creation is logged",
    "detect.persistence_change": "whether autostart changes are logged",
    "detect.credential_access": "whether credential access is logged",
    "detect.authentication": "whether logons are logged",
    "detect.rule": "whether the named detection rule fires",
    "exploit.service_permissions": "the writable service binary",
    "exploit.unquoted_path": "the unquoted service path",
    "exploit.scheduled_task": "a scheduled task running as a privileged account",
    "postex.credential_dump": "what the credential store would give an intruder",
    "postex.persistence_install": "whether persistence survives a reboot",
    "postex.privilege_escalate": "the escalation chain",
    "postex.lateral_move": "whether these credentials reach another host",
    "postex.exfil_probe": "whether a megabyte can leave",
    "harden.enable_telemetry": "the logging that is switched off",
    "harden.fix_permissions": "the permissions that need tightening",
    "harden.remove_persistence": "the autostart entry that should not be there",
    "report.finding": "the write-up",
    "report.detection_gap": "the detection gap",
}

#: Sentence frames. ``{n}`` is the joined noun list; ``{N}`` the same with the
#: first letter raised, for frames that open on it.
_FRAMES: tuple[str, ...] = (
    "Check {n} on this host.",
    "I need {n}.",
    "Give me {n} and nothing else.",
    "Take a look at {n}.",
    "Walk this box: {n}.",
    "Start with {n}.",
    "The ticket asks for {n}.",
    "Baseline this machine — {n}.",
    "Cover {n}.",
    "Have a look at {n} and write it up.",
    "Establish {n} before anything else.",
    "Quick pass: {n}.",
    "Report on {n}.",
    "Pull {n} off this host.",
    "{N} — that is what I need.",
    "Find out about {n}.",
)

#: Wrappers applied to a finished sentence. Several of them say something about
#: *how* to work rather than what to look at, which is deliberate: the model
#: should see instructions about stopping, about staying observe-only and about
#: reporting what could not be checked, since all three are behaviours the
#: episodes themselves demonstrate.
_PARAPHRASE: tuple[str, ...] = (
    "{t}",
    "{t}",
    "{t} Report what you find.",
    "Objective: {t}",
    "{t} Stop when you have enough to write a finding.",
    "I need this answered: {t}",
    "Task: {t}",
    "{t} If something is refused, work around it.",
    "{t} Tell me what you could not check as well as what you could.",
    "{t} Do not touch anything you do not have to.",
    "{t} Keep it observe-only.",
    "For the handover: {t}",
    "{t} Write it up when you are done.",
    "{t} Be quick — the change window is short.",
)

#: Situational preambles. These carry no instruction the loop can act on, which
#: is the point: real tasks arrive wrapped in context, and a model that has only
#: ever seen bare imperatives treats the wrapping as noise it cannot parse.
_CONTEXT: tuple[str, ...] = (
    "", "", "", "",
    "This box was rebuilt last week. ",
    "It is a production file server, so be careful. ",
    "The owner thinks it is clean. ",
    "We have had an alert on this host and nobody can explain it. ",
    "Change freeze is on. ",
    "This is a laptop, not a server. ",
    "It is the jump host. ",
    "Nothing is known about this machine. ",
    "The last assessment here was two years ago. ",
    "Handing this over to the blue team in an hour. ",
    "The owner is on the call. ",
)


def _join(parts: Sequence[str]) -> str:
    """``a``, ``a and b``, ``a, b and c`` — an English list, not a CSV."""
    parts = list(parts)
    if len(parts) == 1:
        return parts[0]
    return ", ".join(parts[:-1]) + " and " + parts[-1]


def _phrase(rng: random.Random, verb_ids: Sequence[str]) -> str:
    """Turn a verb sequence into one plausible operator instruction."""
    nouns = _join([_NOUN[v] for v in verb_ids])
    frame = rng.choice(_FRAMES)
    sentence = frame.format(n=nouns, N=nouns[:1].upper() + nouns[1:])
    return rng.choice(_CONTEXT) + sentence


def _dress(rng: random.Random, task: str) -> str:
    """Wrap a finished task sentence the way a real request arrives."""
    return rng.choice(_PARAPHRASE).format(t=task)


# ---------------------------------------------------------------------------
# hosts that are not ours
# ---------------------------------------------------------------------------

#: Hosts outside every engagement below, so the refusal they provoke is a real
#: ruling rather than a staged one. Loopback forms are deliberately absent: the
#: null engagement allows loopback, so ``::1`` here would produce an ALLOW and a
#: real command against this machine under a target string claiming otherwise.
_OUT_OF_SCOPE: tuple[str, ...] = (
    "10.20.4.77", "192.168.1.50", "dc01.lab.internal", "172.16.8.9",
    "10.0.0.5", "fileserver.corp.internal", "192.168.0.14", "10.13.37.2",
    "backup-nas.lan", "prod-db-02", "vcenter.corp.internal", "172.20.5.31",
    "198.51.100.23", "203.0.113.9", "mail01.corp.internal", "10.44.2.8",
    "printer-3f.office.internal", "192.168.56.101", "build-agent-07",
    "sso.corp.internal", "10.20.9.200", "172.31.14.6", "gitlab.corp.internal",
    "wifi-controller.lan", "10.8.0.12", "hyperv-02.corp.internal",
    "fe80::1c2d:4eff:fe9a:3b01", "2001:db8::42", "k8s-worker-11",
    "10.20.4.1", "nas.home.arpa", "sccm.corp.internal",
)

#: Inside ``10.20.4.0/24`` — the range the scoped engagement authorises — but
#: named in its exclusion list. Exclusions beat inclusions, and that ordering is
#: a property worth teaching: a host can be inside the range you were given and
#: still be the one host you must not touch.
_EXCLUDED_HOSTS: tuple[str, ...] = (
    "10.20.4.1", "10.20.4.2", "10.20.4.254",
)

#: Rule identifiers for ``detect.rule``, which takes a required free-text rule
#: name. Real Sigma-style ids rather than placeholders, because the parameter
#: value is a token sequence the model has to produce and "placeholder" teaches
#: it to produce "placeholder".
_RULE_IDS: tuple[str, ...] = (
    "proc_creation_susp_service_path_modified",
    "file_event_credential_file_access",
    "registry_set_run_key_persistence",
    "proc_creation_lsass_access",
    "sysmon_scheduled_task_created",
    "auth_multiple_failed_logons",
    "proc_creation_encoded_powershell",
    "file_event_cron_modified",
)

#: Plausible values for required parameters that have no default and no choice
#: list. The model emits these characters, so they are written the way an
#: operator would write them rather than as filler.
_FILL: dict[tuple[str, str], tuple[Any, ...]] = {
    ("detect.rule", "rule"): _RULE_IDS,
    ("detect.process_creation", "image"): (
        "acme-agent", "powershell.exe", "launchd", "cron", "sudo"),
    ("exploit.service_permissions", "service"): (
        "acme-agent", "spooler", "acme-updater"),
    ("exploit.unquoted_path", "service"): ("acme-agent", "vendor-sync"),
    ("exploit.scheduled_task", "as_user"): ("SYSTEM", "root"),
    ("postex.privilege_escalate", "chain"): (
        "writable-service-binary", "sudo-nopasswd", "setuid-helper"),
    ("postex.lateral_move", "as_user"): ("svc_backup", "administrator", "root"),
    ("postex.exfil_probe", "sink"): ("sandbox-collector",),
    ("postex.exfil_probe", "bytes"): (1048576, 262144, 4194304),
    ("harden.enable_telemetry", "source"): (
        "process creation auditing", "credential access auditing",
        "unified log persistence"),
    ("harden.fix_permissions", "path"): (
        "/opt/acme/acme-agent", "/etc/acme.conf", "/usr/local/bin/vendor-sync"),
    ("harden.remove_persistence", "entry"): (
        "crontab:@reboot root /opt/acme/acme-agent", "launchd:com.acme.agent"),
    ("report.finding", "title"): ("World-writable service binary runs as root",),
    ("report.finding", "evidence"): ("audit seq 4-11",),
    ("report.detection_gap", "technique"): ("T1574.010", "T1003", "T1547.001"),
    ("report.detection_gap", "expected"): (
        "detect.process_creation", "detect.credential_access"),
}


def _params_for(rng: random.Random, verb: Verb,
                supplied: Mapping[str, Any]) -> dict[str, Any]:
    """Fill a verb's parameters the way a competent operator would.

    Defaults are taken from the schema so the emitted JSON matches what the
    registry would produce on its own; required parameters with no default come
    from :data:`_FILL`. Anything unlisted falls back to a typed placeholder,
    which is a bug in :data:`_FILL` rather than a design, so it is left obvious.
    """
    # The schema's own default, which is what ``REGISTRY.bind(verb, {})``
    # would produce. ``HeuristicChooser`` reaches for ``choices[0]`` instead and
    # so renders ``min_severity=low`` for a verb whose default is ``medium``;
    # matching the registry keeps the corpus's canonical form and the registry's
    # canonical form the same string.
    params: dict[str, Any] = {p.name: p.default for p in verb.params
                              if p.default is not None}

    for p in verb.params:
        if p.name in supplied or p.name in params:
            continue
        options = _FILL.get((verb.id, p.name))
        if options is not None:
            # An optional parameter is supplied only sometimes. Always filling
            # it would teach the model that ``detect.process_creation`` never
            # appears without an ``image``, and the bare form is the one the
            # registry produces and the one an agent reaches for first.
            if p.required or rng.random() < 0.4:
                params[p.name] = rng.choice(options)
        elif p.required:
            params[p.name] = (p.choices[0] if p.choices else
                              1 if p.type == "integer" else
                              False if p.type == "boolean" else "placeholder")

    # A optional enum or integer is sometimes worth varying away from its
    # default, so the model does not learn that a parameter has exactly one
    # value it ever takes.
    for p in verb.params:
        if p.choices and p.name not in supplied and rng.random() < 0.3:
            params[p.name] = rng.choice(p.choices)

    params.update(supplied)
    return params


# ---------------------------------------------------------------------------
# what to run: a scenario is a plan the chooser plays
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Step:
    """One intended action: a verb, any parameters worth pinning, a target.

    ``target`` overrides the episode's target. That is how a refusal is
    produced — the step names a host the engagement does not cover — and it is
    the only reason the field exists. Nothing that actually executes ever names
    anything but loopback or the sandbox, because an adapter runs locally
    whatever the target string says, and an observation of this machine filed
    under someone else's address would be a fabricated trajectory.
    """

    verb: str
    params: Mapping[str, Any] = field(default_factory=dict)
    target: str | None = None


@dataclass(frozen=True)
class Scenario:
    """One objective, the plan that answers it, and the world it runs in.

    ``steps`` accepts bare verb ids as well as :class:`Step` objects, because
    most scenarios only need an ordering. ``kind`` is bookkeeping for the run
    report — it never reaches the trajectory — and exists so that a rebuild can
    say how many refusal episodes, clean-host episodes and detection-gap
    episodes it actually produced rather than how many it intended to.
    """

    task: str
    steps: tuple[Step | str, ...]
    world: str = "host"
    max_turns: int = 12
    #: Whether the plan may be reordered between repeats. False for anything
    #: whose ordering is load-bearing — an exploit must follow the enumeration
    #: that justified it, and a refusal is only a refusal-then-recovery if the
    #: refusal comes first.
    shuffle: bool = True
    kind: str = "observe"

    def __post_init__(self) -> None:
        object.__setattr__(self, "steps", tuple(
            s if isinstance(s, Step) else Step(s) for s in self.steps))

    @property
    def verbs(self) -> tuple[str, ...]:
        """The verb ids in plan order. Kept for callers that only want these."""
        return tuple(s.verb for s in self.steps)      # type: ignore[union-attr]


class _PlanChooser:
    """Plays a scenario's plan, skipping whatever the loop has ruled out.

    This is the corpus's stand-in for a model, and the substitution is honest in
    the one way that matters: the kernel cannot tell the difference. It receives
    an :class:`~whetstone.kernel.Episode`, returns an ``Action`` or ``None``,
    and everything downstream — the gate ruling, the adapter call, the detection
    pairing, the rendering — is the same code path a trained checkpoint drives.

    Skipping ``exclude`` is what turns a refusal into a recovery. The kernel puts
    a denied or unsupported verb on that list and asks again; the chooser moves
    to the next thing it wanted to do, and the trajectory records a correction
    that nobody scripted.
    """

    def __init__(self, steps: Sequence[Step], rng: random.Random) -> None:
        self._steps = list(steps)
        self._rng = rng

    def choose(self, episode: Any, permitted: Sequence[Verb], *,
               exclude: Sequence[str], target: str | None) -> Action | None:
        done = {t.action.verb_id for t in episode.turns} | set(exclude)
        for step in self._steps:
            if step.verb in done:
                continue
            verb = REGISTRY.get(step.verb)
            params = _params_for(self._rng, verb, step.params)
            return verb.bind(
                params,
                target=None if verb.target is TargetKind.NONE
                else (step.target or target))
        return None


# ---------------------------------------------------------------------------
# executors: the things that really carry actions out
# ---------------------------------------------------------------------------

class _CachingExecutor:
    """The real platform adapter, with each distinct action run exactly once.

    Thirteen thousand episodes re-running ``enum.processes`` would take an hour
    and produce thirteen thousand near-identical payloads, because the machine
    does not meaningfully change between them. Memoising keeps every observation
    a real read of this host while costing one read instead of thousands.

    The cached ``Observation`` is re-stamped with the action that asked for it so
    that nothing downstream sees an observation pointing at a different
    ``Action`` object than the turn it belongs to. The rendered text is
    unaffected either way — the renderer emits ``ok``/``data``/``error`` and not
    the embedded action — but an observation whose ``action`` disagrees with its
    turn is the kind of thing that costs an afternoon later.
    """

    def __init__(self, adapter: Any) -> None:
        self._adapter = adapter
        self.platform = adapter.platform
        self._cache: dict[str, Observation] = {}

    def implemented(self) -> tuple[str, ...]:
        return self._adapter.implemented()

    def execute(self, verb: Verb, action: Action) -> Observation:
        key = json.dumps([action.verb_id, action.target,
                          sorted(action.params.items(), key=lambda kv: kv[0])],
                         default=str, sort_keys=True)
        cached = self._cache.get(key)
        if cached is None:
            cached = self._adapter.execute(verb, action)
            self._cache[key] = cached
        return replace(cached, action=action)


class _LabExecutor:
    """The sandbox adapter, plus the one red verb the lab does not implement.

    ``postex.exfil_probe`` is the only verb in the catalogue whose
    ``detected_by`` is :data:`~whetstone.actions.NO_DETECTION`, so it is the only
    way to produce a ``no_coverage`` finding — the disclosure that a technique
    ran and *nothing in this catalogue* covers it, which is a different and more
    honest statement than "we looked and saw nothing". Without it that finding
    kind would be absent from the corpus entirely and the model would never learn
    to distinguish the two.

    The probe really moves a measured volume of generated bytes to a sink, and
    the payload says plainly that the sink is a file inside the sandbox rather
    than a network path. That matters: the verb's summary is about egress
    controls, and a sandbox has none, so an observation that let the model infer
    "egress was allowed on this network" would be teaching it to overclaim from a
    test that could not have shown that.

    It lives here rather than in ``lab/adapter.py`` only because this change was
    scoped to ``training/``. ``lab/adapter.py`` is its natural home and it should
    move there.
    """

    platform = "sandbox"

    def __init__(self, target: Any) -> None:
        from lab.adapter import SandboxAdapter

        self.target = target
        self._adapter = SandboxAdapter(target)

    def implemented(self) -> tuple[str, ...]:
        return tuple(sorted(set(self._adapter.implemented())
                            | {"postex.exfil_probe"}))

    def execute(self, verb: Verb, action: Action) -> Observation:
        if verb.id != "postex.exfil_probe":
            return self._adapter.execute(verb, action)
        return self._exfil(verb, action)

    def _exfil(self, verb: Verb, action: Action) -> Observation:
        requested = int(action.params.get("bytes", 1048576))
        sink_name = str(action.params.get("sink") or "sandbox-collector")
        try:
            sink = self.target.resolve("var/egress.bin")
            delivered = sink.write_bytes(b"\x00" * requested)
            sink.unlink()
        except (OSError, ValueError) as exc:
            return Observation(action=action, ok=False, platform=self.platform,
                               error=f"{type(exc).__name__}: {exc}")
        # Logged for completeness. Nothing reads it, which is exactly the point
        # the NO_DETECTION sentinel is making.
        self.target.event("exfil", "T1041",
                          f"{delivered} synthetic bytes reached {sink_name}")
        return Observation(
            action=action, ok=True, platform=self.platform,
            data={
                "sink": sink_name,
                "transport": "file sink inside the sandbox, not a network path",
                "bytes_requested": requested,
                "bytes_delivered": delivered,
                "delivered_in_full": delivered >= requested,
                "synthetic": True,
                "note": ("Zero-filled generated bytes only; no file contents "
                         "moved. Measures volume against a sink inside the "
                         "sandbox, so it says nothing about this network's "
                         "egress controls."),
            })


# ---------------------------------------------------------------------------
# sandbox variants
#
# The lab plants weaknesses so that a finding can be checked against ground
# truth. These two variants change what is planted, not how anything is
# measured: the adapter still reads the real mode bits off a real file and the
# detection verbs still read whatever is really in the log. That is the line
# between constructing a target and faking an observation, and it is the line
# this whole module is organised around.
# ---------------------------------------------------------------------------

#: Built once and reused. The subclasses below are defined inside functions so
#: that importing this module does not require ``lab`` to be importable — the
#: host-only path (``--no-lab``) has to keep working on a machine where the
#: sandbox is unavailable — and memoising stops fourteen thousand episodes each
#: defining their own class object.
_TARGET_CLASSES: dict[str, type] = {}


def _clean_target_class() -> type:
    if "clean" in _TARGET_CLASSES:
        return _TARGET_CLASSES["clean"]
    from lab.target import SandboxTarget

    class CleanTarget(SandboxTarget):
        """A sandbox with nothing wrong with it.

        Same tree, same files, same adapter — a service binary at 0755 instead
        of 0777, a config that names a keyring instead of carrying a password,
        an empty crontab and current package versions. ``vuln.weak_permissions``
        really stats the binary and really returns an empty finding list.

        This exists because a corpus of nothing but vulnerable hosts trains a
        model to produce findings on demand. The healthy case has to be as
        ordinary in the data as the broken one or the model will never have seen
        the right answer to "is this box fine?".
        """

        def _build(self) -> None:
            (self.root / "var").mkdir(parents=True, exist_ok=True)
            (self.root / "etc").mkdir(exist_ok=True)
            (self.root / "opt" / "acme").mkdir(parents=True, exist_ok=True)
            self.log_path.write_text("", encoding="utf-8")

            svc = self.root / "opt" / "acme" / "acme-agent"
            svc.write_text("#!/bin/sh\n# legitimate service\n"
                           "exec /usr/bin/true\n", encoding="utf-8")
            svc.chmod(0o755)
            self._remember(svc)

            cfg = self.root / "etc" / "acme.conf"
            cfg.write_text("[db]\nhost = 10.20.4.9\n"
                           "credential_source = system keyring\n",
                           encoding="utf-8")
            self._remember(cfg)

            cron = self.root / "etc" / "crontab"
            cron.write_text("# m h dom mon dow user command\n", encoding="utf-8")
            self._remember(cron)

            (self.root / "etc" / "installed.json").write_text(json.dumps({
                "openssl": "3.2.1", "sudo": "1.9.15", "acme-agent": "2.1.0",
            }), encoding="utf-8")

            self.event("baseline", "lab", "clean sandbox built")

    _TARGET_CLASSES["clean"] = CleanTarget
    return CleanTarget


def _blind_target_class() -> type:
    if "blind" in _TARGET_CLASSES:
        return _TARGET_CLASSES["blind"]
    from lab.target import SandboxTarget

    class BlindTarget(SandboxTarget):
        """A vulnerable sandbox whose telemetry log cannot be read.

        The weaknesses are the standard ones; the difference is that the log
        file is left unreadable, so a detection verb that goes looking raises a
        real ``PermissionError``, the adapter turns that into ``ok=False``, and
        :func:`~whetstone.kernel.detection_fired` answers ``None``.

        That ``None`` is the whole reason this variant exists. "The control did
        not fire" and "the query that would have told us failed" are different
        claims, and a tool that reports the second as the first manufactures
        detection gaps out of its own broken plumbing. The kernel already writes
        the careful wording — *could not establish whether it fired; this is not
        evidence of a gap* — but a model only learns to produce wording it has
        seen, and before this variant the corpus contained none of it.

        Telemetry is off, which is what keeps the episode honest end to end: the
        exploit never tries to write to the unreadable file, so the failure is
        located in the detection query and nowhere else.
        """

        def _build(self) -> None:
            super()._build()
            self.log_path.chmod(0o000)

    _TARGET_CLASSES["blind"] = BlindTarget
    return BlindTarget


def _vulnerable_target_class() -> type:
    """The lab's own target, unchanged. Wrapped so every world takes a factory."""
    if "vulnerable" not in _TARGET_CLASSES:
        from lab.target import SandboxTarget

        _TARGET_CLASSES["vulnerable"] = SandboxTarget
    return _TARGET_CLASSES["vulnerable"]


# ---------------------------------------------------------------------------
# worlds: an engagement and an executor, paired
#
# A world is the pair of things that decide what a trajectory can contain: what
# the gate will authorise and what the executor can carry out. Every gate
# outcome in the corpus comes from a world constructed so that the ruling is
# genuine — an engagement that really has expired, a range that really excludes
# that host, a ceiling the verb really sits above.
# ---------------------------------------------------------------------------

#: Fixed instants, so that a DENY reason quoting a timestamp is byte-identical
#: on every rebuild. Both are safely in the past and the far future; an
#: engagement window computed from ``now`` would make the corpus depend on when
#: it was generated, which is the sort of irreproducibility that is invisible
#: until two checkpoints disagree and nobody can say why.
_EXPIRED_WINDOW = (datetime(2024, 1, 1, tzinfo=timezone.utc),
                   datetime(2024, 1, 8, tzinfo=timezone.utc))
_FUTURE_WINDOW = (datetime(2099, 6, 1, tzinfo=timezone.utc),
                  datetime(2099, 6, 8, tzinfo=timezone.utc))


class _World:
    """An engagement and an executor, and the gate that joins them.

    ``open`` hands back a (gate, executor) pair ready for a kernel; ``close``
    releases whatever the executor held. The host worlds share one cached
    executor because they all point at the same machine; the lab worlds build a
    fresh sandbox per episode because a red verb mutates state and a detection
    verb reads a log, and reusing either across episodes would let one episode's
    events answer another episode's question.
    """

    lab = False

    def __init__(self, name: str, engagement: Engagement, executor: Any, *,
                 confirmer: Callable[..., bool] = REFUSE_UNATTENDED) -> None:
        self.name = name
        self.engagement = engagement
        self.confirmer = confirmer
        self._executor = executor

    def open(self) -> tuple[Gate, Any]:
        return (Gate(self.engagement, registry=REGISTRY,
                     confirmer=self.confirmer), self._executor)

    def close(self, executor: Any) -> None:
        return None


class _LabWorld(_World):
    """A world whose executor is a freshly built sandbox.

    The sandbox root is a fixed path rather than a fresh ``mkdtemp`` so that the
    paths inside the observations are the same on every rebuild. The tree is
    wiped and rebuilt for each episode, which is cheap — five small files — and
    is the only way the telemetry log can honestly answer a question about *this*
    episode rather than about the last forty.
    """

    lab = True

    def __init__(self, name: str, engagement: Engagement, *, root: Path,
                 target_factory: Callable[[], type], telemetry: bool,
                 confirmer: Callable[..., bool] = always_confirm) -> None:
        super().__init__(name, engagement, None, confirmer=confirmer)
        self._root = root
        self._factory = target_factory
        self._telemetry = telemetry

    def open(self) -> tuple[Gate, Any]:
        shutil.rmtree(self._root, ignore_errors=True)
        self._root.mkdir(parents=True, exist_ok=True)
        target = self._factory()(telemetry=self._telemetry, root=self._root)
        gate = Gate(self.engagement, registry=REGISTRY, confirmer=self.confirmer)
        return gate, _LabExecutor(target)

    def close(self, executor: Any) -> None:
        # revert() puts back everything an exploit changed, which is the lab's
        # own proof that its cleanup works; the rmtree afterwards is belt and
        # braces for the next episode.
        try:
            executor.target.revert()
        except OSError:
            pass
        shutil.rmtree(self._root, ignore_errors=True)


def _host_worlds(executor: Any) -> dict[str, _World]:
    """Every engagement shape that can be pointed at the real machine.

    Not one of these can execute anything above OBSERVE. The null, scoped,
    expired and early engagements have an OBSERVE ceiling, so a MODIFY or
    EXECUTE verb is denied by the intent rule before it reaches an adapter. The
    ``modify`` world raises the ceiling but lists only OBSERVE as unattended and
    attaches no confirmer, so every MODIFY proposal lands on CONFIRM and
    :data:`~whetstone.gate.REFUSE_UNATTENDED` turns it into a DENY.

    That is a property worth stating because it is the safety argument for this
    whole module: generating training data must never be a reason for a laptop
    to have its audit policy changed. ``tests`` asserts it rather than trusting
    this paragraph.
    """
    scoped = Engagement(
        name="lab segment sweep",
        authorization="SEC-2291, approved by the platform owner on 2026-09-02",
        operator="whetstone",
        scope=Scope(hosts=("10.20.4.0/24",), exclude_hosts=_EXCLUDED_HOSTS,
                    allow_loopback=True),
        authorize=Authorization(red_team=False, max_intent=Intent.OBSERVE),
    )
    expired = Engagement(
        name="Q3 internal assessment",
        authorization="SEC-1877, signed by the CISO on 2023-12-20",
        starts=_EXPIRED_WINDOW[0], expires=_EXPIRED_WINDOW[1],
        scope=Scope(hosts=("10.20.4.0/24",), allow_loopback=True),
        authorize=Authorization(red_team=False, max_intent=Intent.OBSERVE),
    )
    early = Engagement(
        name="next quarter's assessment",
        authorization="SEC-3140, approved but not yet open",
        starts=_FUTURE_WINDOW[0], expires=_FUTURE_WINDOW[1],
        scope=Scope(hosts=("10.20.4.0/24",), allow_loopback=True),
        authorize=Authorization(red_team=False, max_intent=Intent.OBSERVE),
    )
    modify = Engagement(
        name="blue hardening window",
        authorization="CHG-4471, change board approved 2026-09-09",
        scope=Scope(allow_loopback=True),
        authorize=Authorization(red_team=False, max_intent=Intent.MODIFY,
                                unattended=frozenset({Intent.OBSERVE})),
    )
    return {
        "host": _World("host", null_engagement(), executor),
        "host-scoped": _World("host-scoped", scoped, executor),
        "host-expired": _World("host-expired", expired, executor),
        "host-early": _World("host-early", early, executor),
        "host-modify": _World("host-modify", modify, executor),
    }


def _lab_worlds(root: Path) -> dict[str, _World]:
    """The sandbox worlds, which are where the red half of the catalogue runs.

    Five of them, and each one exists to produce a finding shape the others
    cannot:

    ``lab-gap``      weaknesses planted, telemetry off — the exploit succeeds
                     and the paired detection finds silence, which is a
                     ``detection_gap``.
    ``lab-seen``     the same weaknesses and the same exploits with telemetry
                     on. The detection fires, the kernel records *nothing*, and
                     the episode ends with no finding. Half the purple thesis is
                     that a working control is a real outcome, and a corpus
                     where every exploit produces a gap teaches that controls
                     never work.
    ``lab-blind``    telemetry off and the log unreadable, so the detection
                     query fails and the finding is ``observation`` — cannot
                     tell — rather than a gap.
    ``lab-nocover``  the exfil probe, whose declared detection is the
                     ``detect.nothing`` sentinel, producing ``no_coverage``.
    ``lab-clean``    nothing planted. Observe-only, because there is nothing to
                     prove and proposing an exploit against a healthy host is
                     the behaviour this family exists to argue against.

    Two more worlds reuse the vulnerable sandbox with narrower authorisation,
    to produce red-team refusals against an executor that could genuinely have
    carried the action out. A refusal is more informative when the only thing
    standing between the proposal and the action is the gate.
    """
    red_techniques = ("T1574", "T1003", "T1547", "T1543", "T1053", "T1041")

    def engagement(name: str, *, red: bool = True,
                   techniques: tuple[str, ...] = red_techniques,
                   ceiling: Intent = Intent.EXECUTE) -> Engagement:
        return Engagement(
            name=name,
            authorization="LAB — self-contained sandbox, no real host in scope",
            operator="whetstone",
            # "sandbox-collector" is named explicitly because the gate now
            # scope-checks host-typed PARAMETERS, not just the target, and
            # postex.exfil_probe's sink is one. That is the correct shape for
            # an exfiltration exercise: an engagement authorising a probe to a
            # collector has to say which collector. Before the gate was fixed
            # this line was unnecessary, which was the bug — the sink went
            # unchecked and any host would have been accepted.
            scope=Scope(paths=(str(root),), hosts=("sandbox-collector",),
                        allow_loopback=True),
            authorize=Authorization(
                red_team=red, max_intent=ceiling,
                techniques=techniques if red else (),
                unattended=frozenset(Intent)),
        )

    vulnerable = _vulnerable_target_class
    purple = engagement("sandbox purple exercise")

    return {
        "lab-gap": _LabWorld(
            "lab-gap", purple, root=root / "gap",
            target_factory=vulnerable, telemetry=False),
        "lab-seen": _LabWorld(
            "lab-seen", purple, root=root / "seen",
            target_factory=vulnerable, telemetry=True),
        "lab-blind": _LabWorld(
            "lab-blind", purple, root=root / "blind",
            target_factory=_blind_target_class, telemetry=False),
        "lab-nocover": _LabWorld(
            "lab-nocover", purple, root=root / "nocover",
            target_factory=vulnerable, telemetry=False),
        "lab-clean": _LabWorld(
            "lab-clean",
            engagement("sandbox health check", red=False,
                       ceiling=Intent.OBSERVE),
            root=root / "clean",
            target_factory=_clean_target_class, telemetry=True),
        "lab-clean-dark": _LabWorld(
            "lab-clean-dark",
            engagement("sandbox health check", red=False,
                       ceiling=Intent.OBSERVE),
            root=root / "cleandark",
            target_factory=_clean_target_class, telemetry=False),
        # Red-team refused. The sandbox could carry the exploit out; the
        # engagement is the only thing saying no, which is the cleanest possible
        # demonstration that the gate is doing the work.
        "lab-noredteam": _LabWorld(
            "lab-noredteam",
            engagement("sandbox blue-only review", red=False),
            root=root / "nored", target_factory=vulnerable, telemetry=False),
        # Red-team authorised, but for one technique family only. Proposing a
        # credential dump under a T1574-only authorisation is refused by the
        # technique rule rather than the red rule, and the two reasons read
        # differently on purpose.
        "lab-narrow": _LabWorld(
            "lab-narrow",
            engagement("sandbox T1574 validation", techniques=("T1574",)),
            root=root / "narrow", target_factory=vulnerable, telemetry=False),
    }


# ---------------------------------------------------------------------------
# hand-written scenarios
#
# These anchor the shapes that matter most. The derived families below give the
# catalogue-wide coverage, but a generator that only ever emits combinations
# drifts toward the average episode, and some of the most important episodes are
# not average: the one where the engagement has expired and the right answer is
# to stop, the one where the host is fine and the right answer is to say so.
# ---------------------------------------------------------------------------

SCENARIOS: list[Scenario] = [
    # --- ordinary observation on the real host ---------------------------
    Scenario(
        "Find anything on this host that runs without a human starting it.",
        ("enum.host", "enum.persistence", "detect.persistence_change"),
    ),
    Scenario(
        "Establish what this machine is and who I am on it before doing anything else.",
        ("enum.host", "enum.privileges", "enum.users"),
    ),
    Scenario(
        "Work out whether this host could see an attack if one happened.",
        ("detect.telemetry", "detect.process_creation", "detect.credential_access"),
    ),
    Scenario(
        "Check the network exposure of this machine.",
        ("enum.network", "enum.shares", "enum.services"),
    ),
    Scenario(
        "Look for weak file permissions that could be abused for escalation.",
        ("enum.privileges", "vuln.weak_permissions", "vuln.privilege_path"),
    ),
    Scenario(
        "Find credentials sitting somewhere they should not be.",
        ("enum.users", "vuln.credential_exposure"),
    ),
    Scenario(
        "Assess this host for known-vulnerable software.",
        ("enum.host", "enum.software", "vuln.patch_gap"),
    ),
    Scenario(
        "Baseline this machine: identity, autostart, and what the logs record.",
        ("enum.privileges", "enum.persistence", "detect.telemetry"),
    ),
    Scenario(
        "One question only: is process creation being logged on this box?",
        ("detect.process_creation",),
        max_turns=4, kind="short",
    ),
    Scenario(
        "Give me the full picture of this host — everything you can reach.",
        ("enum.host", "enum.privileges", "enum.users", "enum.processes",
         "enum.services", "enum.persistence", "enum.network", "enum.software",
         "enum.shares", "detect.telemetry"),
        max_turns=16, kind="long",
    ),
    Scenario(
        "Full sweep, then tell me which of it would have been noticed.",
        ("enum.host", "enum.services", "enum.persistence",
         "vuln.weak_permissions", "vuln.credential_exposure", "vuln.patch_gap",
         "detect.telemetry", "detect.process_creation",
         "detect.persistence_change"),
        max_turns=16, kind="long",
    ),

    # --- refusal and recovery on the real host ---------------------------
    Scenario(
        "Enumerate the host, then confirm whether the logging would catch me.",
        (Step("enum.software", target="10.20.4.77"),
         "enum.processes", "detect.telemetry"),
        shuffle=False, kind="refusal",
    ),
    Scenario(
        "Map running services and check whether service changes are logged.",
        (Step("enum.shares", target="192.168.1.50"),
         "enum.services", "detect.persistence_change"),
        shuffle=False, kind="refusal",
    ),
    Scenario(
        "The domain controller is the interesting one — start there.",
        (Step("enum.users", target="dc01.lab.internal"),
         "enum.privileges", "enum.persistence"),
        shuffle=False, kind="refusal",
    ),
    Scenario(
        "Sweep the whole segment, starting with the gateway.",
        (Step("enum.network", target="10.20.4.1"),
         "enum.host", "enum.services"),
        world="host-scoped", shuffle=False, kind="refusal",
    ),
    Scenario(
        "Check the segment, and do not skip the print server.",
        (Step("enum.shares", target="10.20.4.254"),
         Step("enum.software", target="10.20.9.200"),
         "enum.host", "detect.telemetry"),
        world="host-scoped", shuffle=False, kind="refusal",
    ),
    Scenario(
        "Turn on process auditing, then confirm it took.",
        (Step("harden.enable_telemetry"), "detect.telemetry",
         "detect.process_creation"),
        world="host-modify", shuffle=False, kind="refusal",
    ),
    Scenario(
        "Fix the permissions you flagged last week and log the change.",
        (Step("harden.fix_permissions"), Step("harden.remove_persistence"),
         "enum.persistence", "vuln.weak_permissions"),
        world="host-modify", shuffle=False, kind="refusal",
    ),
    Scenario(
        "Pick up where the last assessment left off.",
        ("enum.host", "enum.persistence"),
        world="host-expired", max_turns=4, shuffle=False, kind="refusal",
    ),
    Scenario(
        "Start the assessment.",
        ("enum.privileges", "detect.telemetry"),
        world="host-expired", max_turns=4, shuffle=False, kind="refusal",
    ),
    Scenario(
        "Get a head start on next quarter's review.",
        ("enum.host", "enum.software"),
        world="host-early", max_turns=4, shuffle=False, kind="refusal",
    ),
    Scenario(
        "Escalate on this box and show me what you get.",
        (Step("postex.privilege_escalate"), "vuln.privilege_path",
         "enum.privileges"),
        shuffle=False, kind="refusal",
    ),
    Scenario(
        "Dump the credential store so we can see the blast radius.",
        (Step("postex.credential_dump"), "vuln.credential_exposure",
         "enum.users"),
        shuffle=False, kind="refusal",
    ),

    # --- the lab: prove it, then ask who saw -----------------------------
    Scenario(
        "Prove the writable service binary is really exploitable, then tell me "
        "whether anything noticed.",
        ("enum.services", "vuln.weak_permissions",
         Step("exploit.service_permissions", {"service": "acme-agent"})),
        world="lab-gap", shuffle=False, kind="gap",
    ),
    Scenario(
        "Install persistence, confirm it would survive a reboot, and check the log.",
        ("enum.persistence",
         Step("postex.persistence_install", {"mechanism": "cron"})),
        world="lab-gap", shuffle=False, kind="gap",
    ),
    Scenario(
        "Show me what an intruder would get out of the credential store here.",
        ("vuln.credential_exposure", Step("postex.credential_dump",
                                          {"redact": True})),
        world="lab-gap", shuffle=False, kind="gap",
    ),
    Scenario(
        "Run the full purple sweep on this host and report the gaps.",
        ("enum.host", "enum.privileges", "enum.services", "enum.persistence",
         "enum.software", "vuln.weak_permissions", "vuln.credential_exposure",
         "vuln.patch_gap", "detect.telemetry",
         Step("exploit.service_permissions", {"service": "acme-agent"}),
         Step("postex.credential_dump", {"redact": True}),
         Step("postex.persistence_install", {"mechanism": "cron"})),
        world="lab-gap", max_turns=22, shuffle=False, kind="gap",
    ),
    Scenario(
        "The blue team says they have coverage now. Test it.",
        ("detect.telemetry",
         Step("exploit.service_permissions", {"service": "acme-agent"}),
         Step("postex.persistence_install", {"mechanism": "cron"})),
        world="lab-seen", shuffle=False, kind="seen",
    ),
    Scenario(
        "Same three techniques as last time. Did the new logging catch them?",
        (Step("exploit.service_permissions", {"service": "acme-agent"}),
         Step("postex.credential_dump", {"redact": True}),
         Step("postex.persistence_install", {"mechanism": "cron"})),
        world="lab-seen", max_turns=16, shuffle=False, kind="seen",
    ),
    Scenario(
        "Dump credentials and tell me honestly whether the detection fired.",
        ("vuln.credential_exposure",
         Step("postex.credential_dump", {"redact": True})),
        world="lab-blind", shuffle=False, kind="inconclusive",
    ),
    Scenario(
        "Exploit the service and check the log. If you cannot tell, say so.",
        ("enum.services",
         Step("exploit.service_permissions", {"service": "acme-agent"}),
         Step("postex.persistence_install", {"mechanism": "cron"})),
        world="lab-blind", max_turns=16, shuffle=False, kind="inconclusive",
    ),
    Scenario(
        "Measure whether a megabyte could leave this host unnoticed.",
        ("enum.host",
         Step("postex.exfil_probe", {"bytes": 1048576,
                                     "sink": "sandbox-collector"})),
        world="lab-nocover", shuffle=False, kind="no_coverage",
    ),
    Scenario(
        "Full exercise: prove what you can, and be explicit about what nothing "
        "in the catalogue would have caught.",
        ("enum.host", "vuln.weak_permissions",
         Step("exploit.service_permissions", {"service": "acme-agent"}),
         Step("postex.exfil_probe", {"bytes": 262144,
                                     "sink": "sandbox-collector"})),
        world="lab-nocover", max_turns=18, shuffle=False, kind="no_coverage",
    ),
    Scenario(
        "Exploit the writable binary.",
        (Step("exploit.service_permissions", {"service": "acme-agent"}),
         "vuln.weak_permissions", "enum.services", "detect.telemetry"),
        world="lab-noredteam", shuffle=False, kind="refusal",
    ),
    Scenario(
        "Prove the credential exposure by dumping it.",
        (Step("postex.credential_dump", {"redact": True}),
         Step("postex.persistence_install", {"mechanism": "cron"}),
         "vuln.credential_exposure", "enum.users"),
        world="lab-noredteam", shuffle=False, kind="refusal",
    ),
    Scenario(
        "We are cleared for the service-hijack technique. Take it as far as it goes.",
        (Step("postex.credential_dump", {"redact": True}),
         Step("postex.persistence_install", {"mechanism": "cron"}),
         "vuln.weak_permissions",
         Step("exploit.service_permissions", {"service": "acme-agent"})),
        world="lab-narrow", max_turns=16, shuffle=False, kind="refusal",
    ),

    # --- healthy hosts ---------------------------------------------------
    Scenario(
        "Is there anything wrong with this box?",
        ("enum.services", "vuln.weak_permissions", "vuln.credential_exposure",
         "vuln.patch_gap", "enum.persistence"),
        world="lab-clean", shuffle=False, kind="clean",
    ),
    Scenario(
        "The owner says this host is clean. Check.",
        ("enum.host", "enum.privileges", "enum.software", "vuln.patch_gap",
         "vuln.weak_permissions", "detect.telemetry"),
        world="lab-clean", max_turns=14, shuffle=False, kind="clean",
    ),
    Scenario(
        "Sign this machine off if it is fine.",
        ("vuln.weak_permissions", "vuln.credential_exposure", "vuln.patch_gap"),
        world="lab-clean", max_turns=8, shuffle=False, kind="clean",
    ),
    Scenario(
        "Nothing has ever been reported on this host. Have a look anyway.",
        ("enum.persistence", "enum.services", "vuln.weak_permissions",
         "detect.telemetry"),
        world="lab-clean-dark", shuffle=False, kind="clean",
    ),
    Scenario(
        "Quick health check before we hand it back.",
        ("enum.host", "vuln.patch_gap", "vuln.credential_exposure"),
        world="lab-clean-dark", max_turns=8, shuffle=False, kind="clean",
    ),
]


# ---------------------------------------------------------------------------
# derived scenarios
#
# Hand-written scenarios cap the corpus at however many somebody typed, and a
# model trained on that learns those rather than learning that a task maps to
# *some* ordered subset of the permitted verbs. Deriving them from the registry
# means the diversity scales with the catalogue and cannot drift out of sync
# with it when a verb is added.
# ---------------------------------------------------------------------------

def _observe_pool() -> tuple[list[str], list[str], list[str], list[str]]:
    """Host-targeted OBSERVE verbs, split by the role they play in a plan."""
    pool = [v.id for v in REGISTRY.select(intent=Intent.OBSERVE)
            if REGISTRY.get(v.id).target is TargetKind.HOST]
    return (pool,
            [v for v in pool if v.startswith("enum.")],
            [v for v in pool if v.startswith("vuln.")],
            [v for v in pool if v.startswith("detect.")])


def _derived_scenarios(rng: random.Random, count: int = 1000) -> list[Scenario]:
    """Observation episodes on the real host, drawn from the catalogue.

    Only OBSERVE verbs are drawn, because these run under engagements with an
    OBSERVE ceiling and anything else would be refused. That refusal would be
    real, but a corpus of nothing but refusals teaches nothing about doing the
    work, and the refusal families have their own generator below.

    Episode length is drawn rather than fixed. A model trained on a corpus where
    every episode is four turns learns that an episode is four turns, and then
    stops after four turns on a host that needed nine. The distribution is
    deliberately skewed toward the short end — most real questions are answered
    in two or three actions — with a long tail so the model has seen an episode
    that keeps going.
    """
    pool, openers, _assessors, closers = _observe_pool()
    out: list[Scenario] = []

    for _ in range(count):
        # 2-3 turns most of the time, occasionally up to nine.
        n = rng.choices((2, 3, 4, 5, 6, 8), weights=(26, 26, 18, 14, 10, 6))[0]
        chosen = [rng.choice(openers)]
        while len(chosen) < n:
            pick = rng.choice(pool)
            if pick not in chosen:
                chosen.append(pick)
        # Roughly a third of runs end on a detection check, which is the shape
        # the agent should default to: do the thing, then ask who noticed.
        if rng.random() < 0.35:
            tail = rng.choice(closers)
            if tail not in chosen:
                chosen.append(tail)

        steps: list[Step | str] = list(chosen)
        kind = "observe"
        world = "host"
        # A third of these open on something out of scope. The refusal is real,
        # the recovery is the rest of the plan, and mixing them into the ordinary
        # family rather than isolating them is deliberate: refusal should look
        # like part of the job, not like a separate mode.
        if rng.random() < 0.33:
            world = rng.choice(("host", "host", "host-scoped"))
            bad = (rng.choice(_EXCLUDED_HOSTS) if world == "host-scoped"
                   and rng.random() < 0.55 else rng.choice(_OUT_OF_SCOPE))
            spare = [v for v in pool if v not in chosen]
            if spare:
                steps.insert(0, Step(rng.choice(spare), target=bad))
                kind = "refusal"

        out.append(Scenario(
            task=_dress(rng, _phrase(rng, chosen)),
            steps=tuple(steps),
            world=world,
            max_turns=len(steps) + 6,
            shuffle=(kind != "refusal"),
            kind=kind,
        ))
    return out


def _derived_refusals(rng: random.Random, count: int = 420) -> list[Scenario]:
    """Episodes built around a ruling the policy engine really produces.

    Every rule family in :data:`whetstone.gate.policy.RULES` that can be reached
    without executing anything on a real host is represented, at roughly even
    weight. The gate is the safety spine of this system and DENY has no override
    anywhere in it, so the model needs to have seen each reason often enough to
    treat it as ordinary. A refusal the model has never met is a refusal it will
    try to argue with.

    Each family also differs in what the right recovery is, and the episodes
    teach that difference by demonstration rather than instruction. An
    out-of-scope host leaves the rest of the plan runnable. An expired
    engagement does not: every subsequent proposal is denied by the same rule
    and the episode simply ends, which is the correct behaviour and is what an
    episode that ends in four denials looks like.
    """
    pool, _openers, _assessors, _closers = _observe_pool()
    families = (
        ("scope.host.unlisted", "host", 4),
        ("scope.host.excluded", "host-scoped", 3),
        ("engagement.expired", "host-expired", 2),
        ("engagement.early", "host-early", 1),
        ("intent.ceiling", "host", 3),
        ("confirm.declined", "host-modify", 3),
        ("red.unauthorized", "lab-noredteam", 2),
        ("technique.unauthorized", "lab-narrow", 2),
    )
    weights = [w for _r, _w2, w in families]
    out: list[Scenario] = []

    above_ceiling = [v.id for v in REGISTRY
                     if v.intent is not Intent.OBSERVE
                     and v.target is TargetKind.HOST]
    modify_verbs = [v.id for v in REGISTRY if v.intent is Intent.MODIFY]
    lab_red = ("exploit.service_permissions", "postex.credential_dump",
               "postex.persistence_install")
    lab_observe = ("enum.host", "enum.privileges", "enum.services",
                   "enum.persistence", "enum.software", "vuln.weak_permissions",
                   "vuln.credential_exposure", "vuln.patch_gap",
                   "detect.telemetry")

    for _ in range(count):
        rule, world, _w = rng.choices(families, weights=weights)[0]

        if rule in ("engagement.expired", "engagement.early"):
            # Nothing recovers from a closed window. Short by design: the model
            # should learn that the second denial is the end of the episode.
            chosen = rng.sample(pool, rng.randint(2, 3))
            steps: list[Step | str] = list(chosen)
            task_verbs = chosen

        elif rule == "scope.host.excluded":
            chosen = rng.sample(pool, rng.randint(2, 4))
            spare = [v for v in pool if v not in chosen]
            steps = [Step(rng.choice(spare or pool),
                          target=rng.choice(_EXCLUDED_HOSTS))] + list(chosen)
            task_verbs = chosen

        elif rule == "scope.host.unlisted":
            chosen = rng.sample(pool, rng.randint(2, 4))
            spare = [v for v in pool if v not in chosen]
            steps = [Step(rng.choice(spare or pool),
                          target=rng.choice(_OUT_OF_SCOPE))] + list(chosen)
            task_verbs = chosen

        elif rule == "intent.ceiling":
            # A verb above the engagement's ceiling is not in the catalogue the
            # model was shown, so this also teaches that the catalogue is the
            # catalogue. That is a slightly awkward lesson to generate — it
            # models a mistake — but the alternative is a model that meets
            # intent.ceiling for the first time in production.
            chosen = rng.sample(pool, rng.randint(2, 4))
            steps = [Step(rng.choice(above_ceiling))] + list(chosen)
            task_verbs = chosen

        elif rule == "confirm.declined":
            chosen = rng.sample(pool, rng.randint(2, 3))
            steps = [Step(rng.choice(modify_verbs))] + list(chosen)
            task_verbs = chosen

        else:                                   # red.unauthorized / technique.*
            chosen = rng.sample(lab_observe, rng.randint(2, 4))
            n_red = 2 if rule == "technique.unauthorized" else 1
            reds = rng.sample(lab_red, n_red)
            steps = [Step(r, {"service": "acme-agent"} if
                          r == "exploit.service_permissions" else
                          {"mechanism": "cron"} if
                          r == "postex.persistence_install" else {})
                     for r in reds] + list(chosen)
            task_verbs = list(reds) + chosen

        out.append(Scenario(
            task=_dress(rng, _phrase(rng, task_verbs)),
            steps=tuple(steps),
            world=world,
            max_turns=len(steps) + 4,
            shuffle=False,
            kind="refusal",
        ))
    return out


def _derived_lab(rng: random.Random, count: int = 420) -> list[Scenario]:
    """Red episodes in the sandbox, across all four finding outcomes.

    The mix is chosen so that no single outcome dominates. ``detection_gap`` is
    the headline artefact and gets the largest share, but a corpus where every
    exploit produces a gap teaches that controls never work, and a corpus with
    no inconclusive episodes teaches that a failed query is a gap. ``lab-seen``
    is weighted almost as heavily as ``lab-gap`` for exactly that reason: the
    episode that ends with no finding at all is doing as much work as the one
    that ends with three.
    """
    worlds = (("lab-gap", 8), ("lab-seen", 6), ("lab-blind", 4),
              ("lab-nocover", 3))
    names = [w for w, _ in worlds]
    weights = [n for _, n in worlds]

    recon = ("enum.host", "enum.privileges", "enum.services",
             "enum.persistence", "enum.software")
    assess = ("vuln.weak_permissions", "vuln.credential_exposure",
              "vuln.patch_gap")
    red_params = {
        "exploit.service_permissions": {"service": "acme-agent"},
        "postex.credential_dump": {"redact": True},
        "postex.persistence_install": {"mechanism": "cron"},
    }

    out: list[Scenario] = []
    for _ in range(count):
        world = rng.choices(names, weights=weights)[0]

        if world == "lab-nocover":
            reds = [Step("postex.exfil_probe",
                         {"bytes": rng.choice((1048576, 262144, 4194304)),
                          "sink": "sandbox-collector"})]
            if rng.random() < 0.4:
                extra = rng.choice(list(red_params))
                reds.insert(0, Step(extra, red_params[extra]))
        else:
            picked = rng.sample(list(red_params),
                                rng.choices((1, 2, 3), weights=(52, 33, 15))[0])
            reds = [Step(r, red_params[r]) for r in picked]

        # Each red verb costs two turns, because the kernel pairs it with the
        # detection it declared, and the finding that pairing produces is the
        # last thing in the trajectory. Budgeting the recon against the number
        # of red verbs keeps that finding inside the 1024-token window the
        # fine-tuner truncates at; without the budget roughly a third of the
        # detection gaps in this family fell off the end, and an episode that
        # shows the attack but not the silence afterwards teaches the half of
        # the job this project exists to argue against.
        lead_budget = max(0, rng.randint(0, 5) - len(reds))
        lead: list[Step | str] = []
        if lead_budget:
            lead += rng.sample(recon, min(lead_budget, rng.randint(0, 3)))
            room = lead_budget - len(lead)
            if room:
                lead += rng.sample(assess, min(room, rng.randint(0, 2)))
            if len(lead) < lead_budget and rng.random() < 0.5:
                lead.append("detect.telemetry")

        steps = tuple(lead + reds)
        kind = {"lab-gap": "gap", "lab-seen": "seen", "lab-blind": "inconclusive",
                "lab-nocover": "no_coverage"}[world]
        out.append(Scenario(
            task=_dress(rng, _phrase(rng, [s.verb if isinstance(s, Step) else s
                                           for s in steps])),
            steps=steps,
            world=world,
            # Every red verb adds a detection probe turn of its own, so the
            # budget has to leave room for them or the episode is cut off
            # between the exploit and the question the exploit exists to ask.
            max_turns=len(steps) * 2 + 6,
            shuffle=False,
            kind=kind,
        ))
    return out


def _derived_clean(rng: random.Random, count: int = 320) -> list[Scenario]:
    """Healthy-host episodes, which end with no finding and should.

    This family is easy to leave out and expensive to leave out. Every other
    family in this module runs against something with a weakness in it, and a
    model fine-tuned only on those has been shown, thousands of times, that the
    correct end of an assessment is a finding. Pointed at a well-run machine it
    will produce one anyway, because that is the only ending it has seen.

    The vulnerability verbs here really execute and really return
    ``{"findings": []}``, and the episode stops. There is no ``<|find|>`` to
    emit and the trajectory does not contain one, which is the entire lesson.
    """
    clean_pool = ("enum.host", "enum.privileges", "enum.services",
                  "enum.persistence", "enum.software",
                  "vuln.weak_permissions", "vuln.credential_exposure",
                  "vuln.patch_gap", "detect.telemetry")
    assess = ("vuln.weak_permissions", "vuln.credential_exposure",
              "vuln.patch_gap")

    out: list[Scenario] = []
    for _ in range(count):
        world = rng.choice(("lab-clean", "lab-clean", "lab-clean-dark"))
        n = rng.choices((2, 3, 4, 5, 6), weights=(18, 28, 26, 18, 10))[0]
        chosen = rng.sample(clean_pool, min(n, len(clean_pool)))
        # At least one assessment verb, or the episode never gets to the point:
        # an empty finding list is what makes this a clean-host trajectory
        # rather than a short enumeration.
        if not any(v in assess for v in chosen):
            chosen.append(rng.choice(assess))
        rng.shuffle(chosen)
        out.append(Scenario(
            task=_dress(rng, _phrase(rng, chosen)),
            steps=tuple(chosen),
            world=world,
            max_turns=len(chosen) + 4,
            shuffle=True,
            kind="clean",
        ))
    return out


# ---------------------------------------------------------------------------
# generation
# ---------------------------------------------------------------------------

def build_scenarios(rng: random.Random, *, include_lab: bool = True,
                    observe: int = 1000, refusals: int = 420,
                    lab: int = 420, clean: int = 320) -> list[Scenario]:
    """Assemble the full scenario list, hand-written and derived.

    Shuffled once at the end so that the numbered output files interleave the
    families. Nothing downstream depends on the order — the fine-tuner permutes
    every epoch — but a directory where the first two thousand files are all
    refusals is one where a truncated run silently trains on one family.
    """
    scenarios = list(SCENARIOS)
    scenarios += _derived_scenarios(rng, observe)
    scenarios += _derived_refusals(rng, refusals)
    if include_lab:
        scenarios += _derived_lab(rng, lab)
        scenarios += _derived_clean(rng, clean)
    else:
        scenarios = [s for s in scenarios if not s.world.startswith("lab")]
    rng.shuffle(scenarios)
    return scenarios


def generate_trajectories(
    *, repeats: int = 6, seed: int = 1337, verbose: bool = False,
    include_lab: bool = True, lab_root: Path | None = None,
    stats: dict[str, Any] | None = None,
    scenarios: Sequence[Scenario] | None = None,
    observe: int = 1000, refusals: int = 420, lab: int = 420, clean: int = 320,
    host_executor: Any = None,
) -> Iterator[str]:
    """Yield rendered trajectory documents, each from a real agent run.

    Every document comes out of :meth:`whetstone.kernel.Episode.render`, which
    is the same function the runtime uses, so the corpus and the serving prompt
    are produced by one implementation and cannot drift apart. This module picks
    the task, the plan and the engagement; the kernel does the rest.

    Two kinds of world are used and the split is a safety boundary rather than a
    convenience. Against the **real machine** every engagement has an OBSERVE
    ceiling or no attached confirmer, so nothing above OBSERVE can execute:
    generating training data must never be a reason for this laptop to have its
    audit policy edited. Against the **sandbox** the red half of the catalogue
    really runs, because every write it performs lands inside a temporary tree
    that is reverted and deleted afterwards. That is what makes real exploit,
    real detection and real detection-gap trajectories available at all without
    a VM and without breaking anything that matters.

    ``host_executor`` replaces the machine the host worlds run against. Left
    alone it is this machine's platform adapter, which is what a corpus build
    wants. It is a seam rather than a convenience: ``lab/vm/adapter.py`` drives
    a real Lima VM over SSH, so passing that here is how a macOS laptop produces
    genuinely *Linux* trajectories rather than trajectories labelled Linux. The
    test suite passes a stub so that CI exercises this module's logic on three
    operating systems without shelling out on any of them.

    ``stats``, if given, is filled in with per-kind and per-rule counts so the
    caller can report what the run actually produced rather than what it
    intended to.

    **Reproducibility.** Under a fixed seed the *decisions* are byte-identical
    on every run: the same scenarios in the same order, the same task strings,
    the same actions, the same gate rulings, the same findings. What is not
    identical is the content of an observation read from a live machine — the
    process table moves between two runs a minute apart, and pinning that would
    mean recording it once and replaying it, which is the fabrication this
    module is built to avoid. Sandbox observations, being reads of a tree this
    module builds at a fixed path, are byte-identical too.
    """
    from whetstone.adapters.base import get_adapter

    rng = random.Random(seed)
    counts: dict[str, Any] = stats if stats is not None else {}
    counts.setdefault("kind", {})
    counts.setdefault("world", {})
    counts.setdefault("rule", {})
    counts.setdefault("finding", {})
    counts.setdefault("duplicates", 0)
    counts.setdefault("errors", {})

    executor_for_host = _CachingExecutor(host_executor or get_adapter())
    worlds = _host_worlds(executor_for_host)

    root = Path(lab_root or Path(tempfile.gettempdir()) /
                "whetstone-trajectory-lab")
    if include_lab:
        try:
            worlds.update(_lab_worlds(root))
        except Exception as exc:                            # noqa: BLE001
            if verbose:
                print(f"   lab unavailable ({type(exc).__name__}: {exc}); "
                      "generating host worlds only")
            include_lab = False

    plan = list(scenarios) if scenarios is not None else build_scenarios(
        rng, include_lab=include_lab, observe=observe, refusals=refusals,
        lab=lab, clean=clean)
    counts["scenarios"] = len(plan)

    seen: set[bytes] = set()
    for scenario in plan:
        world = worlds.get(scenario.world)
        if world is None:                    # lab disabled, lab scenario
            continue
        tasks = _task_variants(rng, scenario, repeats)
        for rep in range(repeats):
            steps = list(scenario.steps)
            # Reordering between repeats stops the model learning that a
            # particular pair of verbs always arrives in a particular order,
            # which is a correlation the catalogue does not actually contain.
            if scenario.shuffle and rep % 3 == 1 and len(steps) > 1:
                rng.shuffle(steps)

            gate, executor = world.open()
            try:
                kernel = Kernel(gate, executor,
                                _PlanChooser(steps, rng),
                                max_turns=scenario.max_turns)
                episode = kernel.run(tasks[rep], target="127.0.0.1")
            except Exception as exc:                        # noqa: BLE001
                # A scenario that cannot run is a bug in the scenario, not a
                # reason to lose the other thirteen thousand.
                name = f"{type(exc).__name__}: {exc}"[:120]
                counts["errors"][name] = counts["errors"].get(name, 0) + 1
                if verbose:
                    print(f"   {scenario.world}/{scenario.kind}: {name}")
                continue
            finally:
                world.close(executor)

            text = episode.render()
            # blake2b rather than hash(): str hashing is salted per process, so
            # which duplicates got dropped would depend on the interpreter's
            # startup rather than on the seed.
            fingerprint = hashlib.blake2b(text.encode("utf-8"),
                                          digest_size=16).digest()
            if fingerprint in seen:
                # Identical text earns nothing and costs a gradient step. Short
                # plans with cached host observations do collide occasionally.
                counts["duplicates"] += 1
                continue
            seen.add(fingerprint)

            counts["kind"][scenario.kind] = counts["kind"].get(scenario.kind, 0) + 1
            counts["world"][scenario.world] = counts["world"].get(scenario.world, 0) + 1
            for turn in episode.turns:
                if turn.refused:
                    rule = turn.decision.rule
                    counts["rule"][rule] = counts["rule"].get(rule, 0) + 1
            for finding in episode.findings:
                counts["finding"][finding.kind] = (
                    counts["finding"].get(finding.kind, 0) + 1)

            yield text

    if include_lab:
        shutil.rmtree(root, ignore_errors=True)


def _task_variants(rng: random.Random, scenario: Scenario,
                   repeats: int) -> list[str]:
    """``repeats`` phrasings of one scenario's task, chosen not to collide.

    The first is the scenario's own sentence — hand-written scenarios are worth
    seeing verbatim at least once, and derived ones have already been dressed
    once, so wrapping them again is a second layer of variation rather than a
    redundant one. The rest walk a shuffled wrapper list instead of choosing
    independently each time. With fourteen wrappers and six repeats, independent
    choices collide more often than not, and a collision is a whole episode of
    identical text: a gradient step spent on something the model has already
    seen, and one fewer distinct episode than the run reports.
    """
    variants = [scenario.task]
    pool = [w for w in _PARAPHRASE if w != "{t}"]
    rng.shuffle(pool)
    for i in range(1, repeats):
        variants.append(pool[(i - 1) % len(pool)].format(t=scenario.task))
    return variants


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _write_dir(out: Path, texts: Iterator[str]) -> tuple[int, int]:
    """One ``trajectory-NNNNN.txt`` per episode — what the trainer consumes.

    ``training/sft.py`` and ``training/corpus/sources/trajectories.py`` both
    glob for this name, so it is a contract rather than a convention.
    """
    out.mkdir(parents=True, exist_ok=True)
    for old in out.glob("trajectory-*.txt"):
        old.unlink()
    n = chars = 0
    for i, text in enumerate(texts):
        (out / f"trajectory-{i:05d}.txt").write_text(text, encoding="utf-8")
        n += 1
        chars += len(text)
    return n, chars


def _write_jsonl(out: Path, texts: Iterator[str]) -> tuple[int, int]:
    """One ``{"text": ...}`` row per episode, for inspection and diffing.

    The directory form is what trains; this is what a person reads, counts and
    compares between two builds without unpacking fourteen thousand files.
    """
    out.parent.mkdir(parents=True, exist_ok=True)
    n = chars = 0
    with out.open("w", encoding="utf-8") as fh:
        for i, text in enumerate(texts):
            fh.write(json.dumps({"id": f"trajectory-{i:05d}", "text": text},
                                ensure_ascii=False) + "\n")
            n += 1
            chars += len(text)
    return n, chars


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Generate real agent trajectories.")
    p.add_argument("--out", type=Path,
                   default=Path("/Volumes/at0m_b0mb/whetstone/corpus/raw/trajectories"),
                   help="a directory of trajectory-*.txt files, or a path "
                        "ending in .jsonl for one row per episode")
    p.add_argument("--repeats", type=int, default=6,
                   help="episodes generated per scenario")
    p.add_argument("--seed", type=int, default=1337)
    p.add_argument("--no-lab", action="store_true",
                   help="host worlds only; drops every red, detection-gap, "
                        "inconclusive, no-coverage and clean-host episode")
    p.add_argument("--lab-root", type=Path,
                   help="where the sandbox trees are built (a fixed path keeps "
                        "the paths inside observations reproducible)")
    p.add_argument("--vm", action="store_true",
                   help="run the host worlds against the Lima lab VM instead of "
                        "this machine, which is the only honest way to produce "
                        "Linux-labelled trajectories from a Mac")
    p.add_argument("--observe", type=int, default=1000)
    p.add_argument("--refusals", type=int, default=420)
    p.add_argument("--lab", type=int, default=420)
    p.add_argument("--clean", type=int, default=320)
    args = p.parse_args(argv)

    host_executor = None
    if args.vm:
        from lab.vm.adapter import VMAdapter

        host_executor = VMAdapter()             # raises if the VM is not up
        print(f"host worlds will run against {host_executor.platform}")

    stats: dict[str, Any] = {}
    texts = generate_trajectories(
        repeats=args.repeats, seed=args.seed, verbose=True,
        include_lab=not args.no_lab, lab_root=args.lab_root, stats=stats,
        observe=args.observe, refusals=args.refusals, lab=args.lab,
        clean=args.clean, host_executor=host_executor)

    if args.out.suffix == ".jsonl":
        n, chars = _write_jsonl(args.out, texts)
    else:
        n, chars = _write_dir(args.out, texts)

    print(f"{n:,} trajectories, {chars/1e6:.2f}M chars -> {args.out}")
    print(f"  scenarios   {stats.get('scenarios', 0):,} × {args.repeats} repeats"
          f"  ({stats.get('duplicates', 0):,} identical episodes dropped)")
    for label in ("kind", "finding", "rule"):
        rows = stats.get(label) or {}
        if rows:
            body = "  ".join(f"{k}={v:,}" for k, v in sorted(rows.items()))
            print(f"  {label:<11} {body}")
    if stats.get("errors"):
        for name, count in sorted(stats["errors"].items()):
            print(f"  ERROR       {count:,}x {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
