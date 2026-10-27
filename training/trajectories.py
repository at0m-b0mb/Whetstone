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

**One thing is edited, and it is named here so the paragraph above stays
true.** Before a document leaves :func:`generate_trajectories` it passes through
:func:`redact_identity`, which substitutes this machine's account name, home
directory, host name, per-user temp directory and the account's display name for
fixed placeholders — ``operator``, ``/Users/operator``, ``operator-host``,
``/tmp``. Nothing else is touched: the service list, the package versions, the
sudo rules and the permissions are what the adapter returned. The reason is that
this corpus is what the model memorises, and a username in a text file can be
grepped out while a username in a checkpoint can only be trained out. The
substitution keeps the *shape* of every value it rewrites, because the model has
to learn that a home directory is a path with an account name in it; a redaction
that left holes would teach it that observations contain holes.

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

**Defence is half the job and the corpus contained none of it.** Every episode
here used to end at the finding: the technique ran, nothing saw it, document
over. A model trained on that has literally never seen a ``harden.*`` verb
chosen, and the constrained decoder will happily rank one it has no idea what to
do with. The remediation families fix that by turning the kernel's own
remediation phase on — :class:`~whetstone.kernel.Kernel` applies a fix, **runs
the same attack again**, and asks the same control the same question a second
time — so the harden action, the re-attack and the second probe are real gated
actions with real observations, exactly like everything else here.

**The six remediation states are the whole point of generating more than one
kind of fix.** The SFT loss mask supervises ``<|act|>`` *and* ``<|find|>``, so
the remediation dict inside a finding is text the model is trained to produce. A
corpus in which every fix came back ``"state":"closed"`` would teach a model to
write the word "closed" after a hardening verb — which is precisely the
overstatement the re-attack exists to prevent, reintroduced through the training
data instead of through the code. So the families below are constructed to reach
five of the six states for real: a fix that closes the gap, a fix that runs and
leaves the gap open, a fix the gate refuses, a fix whose success removes the
technique so closure cannot be proven, and a gap nothing in the catalogue claims
to close. None of those outcomes is written down anywhere; each is what the
sandbox actually did.

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
import ctypes
import ctypes.util
import getpass
import hashlib
import ipaddress
import json
import os
import platform
import random
import re
import shutil
import socket
import sys
import tempfile
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import (Any, Callable, Iterable, Iterator, Mapping,
                    Sequence)

import whetstone.verbs  # noqa: F401  (registers and freezes the catalogue)
from whetstone.actions import (REGISTRY, Action, Intent, Observation,
                               SchemaError, TargetKind, Verb)
from whetstone.gate import (REFUSE_UNATTENDED, Decision, Gate, always_confirm,
                            null_engagement)
from whetstone.gate.engagement import Authorization, Engagement, Scope
from whetstone.kernel import Kernel
from whetstone.kernel.render import MAX_ITEMS, MAX_VALUE, shrink_payload

__all__ = ["Scenario", "Step", "SCENARIOS", "generate_trajectories",
           "redact_identity", "identity_leaks"]


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


#: Clauses that ask for the gap to be *closed* rather than only reported, added
#: to the task of every episode generated with the remediation phase on.
#:
#: The phase is a kernel flag and not something the model reads, so nothing
#: forces these two to agree — which is exactly why they are made to. Without
#: them the corpus would contain two populations of episode with identical
#: ``<|task|>`` distributions, one that hardens after a gap and one that stops,
#: and the model's only way to tell them apart would be to guess. An operator
#: who turns remediation on is an operator who asked for fixes, so the
#: instruction says so and the model has something to condition on.
#:
#: They are attached to the no-op families too, and that is deliberate rather
#: than sloppy: being asked to fix things must not become a reason to fix
#: something. An episode whose task says "close whatever nobody saw" and whose
#: controls saw everything ends with no hardening verb at all, and that is the
#: lesson those episodes carry.
_REMEDIATE_ASK: tuple[str, ...] = (
    " Close anything nobody saw.",
    " If a control missed something, fix it and prove the fix took.",
    " I want the gaps shut, not just listed.",
    " Harden what you find and show me it worked.",
    " Do not stop at the finding — close it.",
    " Fix what you can and say plainly what you could not.",
    " Then switch on whatever turned out to be blind.",
    " Report the gaps and remediate them.",
    " Leave this host better than you found it.",
    " Anything you change, verify.",
    " The blue team wants the holes shut this window.",
    " Remediate on the spot if you are able to.",
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
    #: Run the kernel's remediation phase: offer a fix for every detection gap,
    #: apply it, re-run the original attack and re-ask the control. Off by
    #: default because it is off by default in the kernel, and for the same
    #: reason — it is the one phase that changes the target on the loop's own
    #: initiative. Only the sandbox worlds ever set it; see
    #: :func:`_derived_remediation`.
    remediate: bool = False
    #: Which hardening verb the stand-in chooser proposes, or ``""`` for the
    #: kernel's deterministic proposer.
    #:
    #: This is the only lever that reaches the states other than ``closed``. The
    #: deterministic proposer prefers the fix the *control* named — enabling the
    #: blind log source — and in this sandbox that one always closes the gap, so
    #: a corpus built on it alone would contain one outcome. Naming a different
    #: candidate is not staging the result: the verb still has to be a declared
    #: remediation for the technique, its parameters still have to come out of an
    #: observation, the gate still rules on it, the adapter still carries it out,
    #: and what happens next is whatever really happens. See
    #: :meth:`_PlanChooser.remediate`.
    fix: str = ""

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

    def __init__(self, steps: Sequence[Step], rng: random.Random,
                 fix: str = "") -> None:
        self._steps = list(steps)
        self._rng = rng
        self._fix = fix

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

    # ------------------------------------------------------------ the fix

    def remediate(self, episode: Any, finding: Any, *,
                  candidates: Sequence[Verb],
                  target: str | None) -> Action | None:
        """Propose the scenario's preferred fix, or defer to the kernel's.

        The kernel looks this method up with ``getattr``, so defining it here is
        what makes the corpus able to reach a remediation state other than
        ``closed``. Returning ``None`` hands the decision back to
        :meth:`Kernel._default_fix`, and that is the path most episodes take —
        the deterministic proposer is the baseline a trained model's defending
        will be measured against, so it has to be the commonest thing in the
        data rather than a special case.

        Two constraints are honoured deliberately, because a chooser that broke
        either would put a fabricated outcome in the corpus.

        *A verb outside ``candidates`` is never returned.* The kernel would
        record that as ``unavailable`` naming the verb, which is the right
        answer to a chooser that matched a fix to a gap by plausibility — but
        generating that on purpose would mean writing episodes whose lesson is
        an association error, and the ``<|find|>`` text is supervised. When the
        scenario's preferred verb is not a declared remediation for this
        technique the honest move is to defer, so it does.

        *Parameters come out of the evidence, exactly as the kernel's own
        proposer takes them.* The hint channel is read from the red observation
        and the probe that followed it — the two things a model reading this
        trajectory would have in front of it — and nothing is inferred from the
        payload's shape. A candidate whose required parameters are not in the
        evidence cannot be bound, and the answer is to defer rather than to
        guess: a MODIFY aimed at a made-up path is worse than a gap left open.
        """
        if not self._fix:
            return None
        verb = next((v for v in candidates if v.id == self._fix), None)
        if verb is None:
            return None

        hints = _hints_for(episode, finding.produced_by).get(verb.id, {})
        known = {p.name for p in verb.params}
        params: dict[str, Any] = {p.name: p.default for p in verb.params
                                  if p.default is not None}
        params.update({k: v for k, v in hints.items() if k in known})
        try:
            return verb.bind(
                params,
                target=None if verb.target is TargetKind.NONE else target)
        except SchemaError:
            # The evidence did not carry a required parameter. Deferring sends
            # the gap to the deterministic proposer, which will either find a
            # candidate it *can* aim or report `unavailable`; either is a true
            # statement, and a placeholder would not be.
            return None


def _hints_for(episode: Any, red_verb_id: str) -> dict[str, dict[str, Any]]:
    """Remediation hints published around one red action, merged probe-last.

    The wire format is the one the kernel documents: an observation payload may
    carry ``{"remediation": {"<harden verb id>": {"<param name>": value}}}``,
    namespaced under exactly that key and keyed by exact ids. Read here rather
    than imported from the kernel because this class is a stand-in for a model,
    and a model has the rendered trajectory and nothing else — a chooser reaching
    into runtime internals would be a chooser the trained one cannot replace.

    Only the turns belonging to *this* gap are read: the first planned turn that
    ran ``red_verb_id`` and the probe immediately after it. Later turns include
    re-attacks from gaps already closed in this episode, and a hint lifted off
    one of those would aim a fix at evidence from a different finding.

    The probe is merged second so it wins a collision, which is the kernel's
    ordering rule and holds for the kernel's reason: a detection gap is a
    statement about the control, so the control's own account of its blindness
    is the more specific answer.
    """
    turns = list(episode.turns)
    out: dict[str, dict[str, Any]] = {}
    for i, turn in enumerate(turns):
        if turn.phase != "plan" or turn.action.verb_id != red_verb_id:
            continue
        window = [turn.observation]
        if i + 1 < len(turns) and turns[i + 1].phase == "detect":
            window.append(turns[i + 1].observation)
        for obs in window:
            if obs is None or not isinstance(obs.data, dict):
                continue
            published = obs.data.get("remediation")
            if not isinstance(published, dict):
                continue
            for verb_id, params in published.items():
                if isinstance(params, dict):
                    out.setdefault(verb_id, {}).update(params)
        break
    return out


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

    def __init__(self, target: Any, hide: Sequence[str] = ()) -> None:
        from lab.adapter import SandboxAdapter

        self.target = target
        self._adapter = SandboxAdapter(target)
        #: Verbs withheld from :meth:`implemented`, which is how an executor
        #: that carries out no hardening measure is modelled. That is not a
        #: hypothetical shape: ``lab/vm/adapter.py`` implements none of the
        #: three harden verbs, so a gap found against the Lima VM has nothing
        #: in the permitted catalogue that claims to close it. Withholding is
        #: enough because the kernel only ever proposes from
        #: ``catalogue() ∩ implemented()``, so a hidden verb is never bound,
        #: never gated and never run — the episode is what it would be on an
        #: adapter that genuinely lacks it.
        self._hidden = frozenset(hide)

    def implemented(self) -> tuple[str, ...]:
        return tuple(sorted((set(self._adapter.implemented())
                             | {"postex.exfil_probe"}) - self._hidden))

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


class _ConfirmOncePerVerb:
    """A human who approves a technique the first time and declines a repeat.

    A confirmer is the seam where a person stands, and the two that existed
    before this one are the two degenerate people: :data:`always_confirm` says
    yes to everything and :data:`REFUSE_UNATTENDED` is nobody at the keyboard at
    all. Neither can produce the ruling this class exists for — a run that was
    authorised and a *re*-run of the same technique that was not.

    That person is not a contrivance. "You may execute it once so we can see
    whether the control notices" is the ordinary shape of an approval for a
    production box, and the operator who granted it has every reason to answer
    no when the same exploit comes back a second time. The kernel's verification
    step is exactly that second proposal, and what it gets here is a real
    :func:`~whetstone.gate.policy.decide` ruling on a real CONFIRM — the gate is
    not bypassed, patched or told the answer; it asks, and this answers.

    State is per episode, which is why :class:`_LabWorld` takes a factory rather
    than an instance. One of these shared across fourteen thousand episodes
    would decline every attack after the first episode's, and the corpus would
    quietly become a refusal family.

    Only the verb id is remembered, not the parameters. The question a careful
    operator is answering is "do I let you run this technique again", and an
    exploit re-aimed at a second service is the same answer; matching on
    parameters would let a repeat through on a difference the operator does not
    care about.
    """

    def __init__(self) -> None:
        self._seen: set[str] = set()

    def __call__(self, verb: Verb, action: Action, decision: Decision) -> bool:
        if action.verb_id in self._seen:
            return False
        self._seen.add(action.verb_id)
        return True


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
                 confirmer: Callable[..., bool] = always_confirm,
                 confirmer_factory: Callable[[], Callable[..., bool]] | None = None,
                 hide: Sequence[str] = ()) -> None:
        super().__init__(name, engagement, None, confirmer=confirmer)
        self._root = root
        self._factory = target_factory
        self._telemetry = telemetry
        self._hide = tuple(hide)
        #: Built fresh per episode when given, for a confirmer that remembers
        #: what it has already said yes to. The sandbox is rebuilt every episode
        #: for the same reason one turn's evidence must not answer another
        #: episode's question, and a person's decisions are evidence.
        self._confirmer_factory = confirmer_factory

    def open(self) -> tuple[Gate, Any]:
        shutil.rmtree(self._root, ignore_errors=True)
        self._root.mkdir(parents=True, exist_ok=True)
        target = self._factory()(telemetry=self._telemetry, root=self._root)
        confirmer = (self._confirmer_factory() if self._confirmer_factory
                     else self.confirmer)
        gate = Gate(self.engagement, registry=REGISTRY, confirmer=confirmer)
        return gate, _LabExecutor(target, self._hide)

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
                   ceiling: Intent = Intent.EXECUTE,
                   unattended: frozenset[Intent] | None = None) -> Engagement:
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
                unattended=(frozenset(Intent) if unattended is None
                            else unattended)),
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
        # The fix is refused. Every intent runs unattended under this
        # engagement except MODIFY, so the red half of the plan executes and
        # the hardening measure lands on the default CONFIRM rule with no
        # confirmer attached — a real `confirm.declined` on the one action the
        # episode existed to take. This is the shape of the change window that
        # has not opened yet, and it is a ruling the defending half has to have
        # met: DENY has no override here either, and a model that has only seen
        # remediation permitted will meet its first refusal in production.
        "lab-fix-denied": _LabWorld(
            "lab-fix-denied",
            engagement("sandbox purple exercise, no change authority",
                       unattended=frozenset({Intent.OBSERVE, Intent.EXECUTE})),
            root=root / "fixdenied", target_factory=vulnerable,
            telemetry=False, confirmer=REFUSE_UNATTENDED),
        # The fix is permitted and the *proof* is not. Hardening runs
        # unattended here; EXECUTE needs a person, and the person approves each
        # technique once and declines the repeat — see `_ConfirmOncePerVerb`.
        # So the attack runs, the gap is found, the fix is applied, the control
        # is read and found silent, and then the re-attack that would have
        # settled the question is denied.
        #
        # This is the one world in the corpus where the loop does everything
        # right and still cannot say a hole is shut, and it is worth having
        # because `undetermined` otherwise means one thing in the data and five
        # in the kernel. Before it, every `undetermined` in the corpus was the
        # chmod family's "the technique no longer succeeds" — a model reading
        # the corpus would learn that the word describes a fix that worked *too*
        # well, which is the cheerful half of a state that also has to cover
        # being unable to check at all.
        "lab-reattack-denied": _LabWorld(
            "lab-reattack-denied",
            engagement("sandbox purple exercise, one run per technique",
                       unattended=frozenset({Intent.OBSERVE, Intent.MODIFY})),
            root=root / "reattack", target_factory=vulnerable,
            telemetry=False, confirmer_factory=_ConfirmOncePerVerb),
        # Nothing to fix with. The executor reports no `harden.*` verb, so the
        # permitted catalogue contains no declared remediation for the
        # technique and the kernel says so instead of proposing something.
        # `lab/vm/adapter.py` really is this adapter, which is why the shape is
        # worth having in the corpus: it is what remediation against the Lima
        # VM looks like today, and the blue-side twin of `no_coverage`.
        "lab-nofix": _LabWorld(
            "lab-nofix", purple, root=root / "nofix",
            target_factory=vulnerable, telemetry=False,
            hide=("harden.enable_telemetry", "harden.fix_permissions",
                  "harden.remove_persistence")),
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


#: What each remediation family is built to produce, checked against what it
#: really produced. The construction is indirect — a flavour picks a world, a
#: red verb and a preferred fix, and the *sandbox* decides the state — so an
#: adapter change could quietly turn the ineffective family into another batch
#: of closures and the run would still print a healthy number. Generation
#: compares the two and counts every divergence into ``stats["fix_mismatch"]``,
#: which the CLI prints and a test asserts empty. A wrong number nobody notices
#: is worse than a crash.
#:
#: ``fix-none`` maps to ``None`` rather than to a state: its claim is that the
#: remediation phase ran and attached nothing, so the check is that no finding
#: in the episode carries a remediation at all.
_INTENDED_STATE: dict[str, str | None] = {
    "fix-closed": "closed",
    "fix-ineffective": "ineffective",
    "fix-undetermined": "undetermined",
    # Two families land on `undetermined`, by two different routes through
    # `_close_gap`, and that is the point of the second one rather than an
    # oversight — see the docstring below. This table checks the state; the
    # routes are checked in `tests/test_trajectories.py`, because a state
    # reached one way in every document is a state the model has learnt one
    # meaning of.
    "fix-reattack-denied": "undetermined",
    "fix-refused": "refused",
    "fix-unavailable": "unavailable",
    "fix-none": None,
}


def _derived_remediation(rng: random.Random, count: int = 260) -> list[Scenario]:
    """Episodes that do something about the gap, across five real outcomes.

    Every trajectory in this corpus used to stop at the finding, so the model
    has never seen a hardening verb chosen and cannot be expected to choose one.
    These families run the kernel's remediation phase, which means the harden
    action, the silent reading, the re-attack and the second probe are four
    more gated actions
    against the same sandbox — nothing about how they are produced differs from
    the rest of this module.

    What differs is that the *outcome* is the training signal, and there are six
    of them. Both supervised segment types carry it: the ``<|act|>`` for the
    hardening verb, and the ``remediation`` dict inside the ``<|find|>``. A
    corpus where every fix came back ``closed`` would teach a model to write
    "closed" after a harden verb, which is the claimed-fixed overstatement the
    re-attack was built to catch — reintroduced through the data rather than
    through the code, where no amount of runtime care would reach it.

    So five states are reached, each by a construction the sandbox resolves
    rather than a label this file applies:

    ``closed``
        The deterministic proposer's own choice — the control published a hint
        naming the log source it was blind on, the switch is flipped, the attack
        is performed again and the control speaks. Weighted heaviest because it
        is the baseline a trained model's defending is measured against, and
        because it is the outcome the loop is *for*.

    ``ineffective``
        ``harden.remove_persistence`` against the persistence gap, with the
        exploit's own cleanup turned off so the entry is genuinely still on disk
        for the fix to remove. The removal really succeeds — and then the
        re-attack installs the entry again and the control, still switched off,
        still says nothing. A fix that runs is a claim; this is the family where
        the claim is wrong, and a model that has not seen one has no reason to
        believe verification is worth the turns.

    ``undetermined`` (the fix worked too well)
        ``harden.fix_permissions`` against the writable-binary gap. The chmod is
        real and it works: the re-attack now fails, because the write bit the
        technique depended on is gone. That is a good outcome and it is *not*
        closure — the gap was a statement about the control, and a technique
        that cannot run tells you nothing about what would have been logged. The
        distinction is subtle enough that it has to be in the data.

    ``undetermined`` (the proof was not authorised)
        The second family reaching the same state, deliberately, because
        ``undetermined`` has five routes through :meth:`Kernel._close_gap` and
        this corpus was measured reaching exactly one of them: every one of the
        three hundred documents carrying the state said *the technique no longer
        succeeds*. A model reading that learns the word as a description of a
        fix that worked too well, and will not produce it for the case it is
        needed most — the loop being unable to check.

        So: an engagement that runs hardening unattended and asks a person
        before every EXECUTE, and a person who approves a technique once and
        declines the repeat (:class:`_ConfirmOncePerVerb`). The gap is real, the
        fix is applied, the control is read and is silent, and the re-attack
        that would have settled it is refused by the gate. Nothing is closed and
        nothing failed; the question is open, and the detail says which of the
        two it is.

        The other three routes — the control already reporting activity of this
        kind before the re-attack, the second probe failing to answer, a hit the
        probe could not attribute — are *not* reachable here, and it is worth
        writing down why rather than leaving the gap looking like laziness. Each
        needs either two gaps sharing one detection verb or a probe that breaks
        between the first reading and the second. The sandbox implements three
        red verbs and they have three different declared detections, so no two
        gaps in one episode can confound each other; and a log that stops being
        readable halfway through an episode is a state this module would have to
        manufacture. Manufacturing it is the one thing this file does not do.

    ``refused``
        The gate denies the hardening action under an engagement that runs
        everything unattended except MODIFY. Defence is not a category the gate
        makes exceptions for, and a model trained only on permitted remediation
        would learn that hardening is always allowed.

    ``unavailable``
        An executor that implements no hardening measure at all, so nothing in
        the permitted catalogue claims to close the gap and the kernel reports
        that instead of proposing something. The blue-side twin of
        ``no_coverage``.

    ``fix-none`` is the sixth family and the one that keeps the other five
    honest. The remediation phase is on, the task asks for the holes to be shut,
    and the episode produces no hardening verb because there was nothing to
    remediate: the control saw the attack (``lab-seen``), the detection could
    not be established either way (``lab-blind``), or nothing in the catalogue
    covers the technique (``lab-nocover``). Without it the model would learn
    that being asked to fix something means emitting a fix, which is the
    defending half of the failure the clean-host family exists to prevent.

    ``failed`` — the sixth state, where the hardening verb itself returns
    ``ok=False`` — is deliberately absent. The only way to reach it here is to
    propose a fix with a parameter the adapter rejects, such as a telemetry
    source this sandbox does not have, and the ``<|act|>`` segment carrying that
    parameter is supervised. Teaching the model to emit a bad parameter in order
    to teach it that bad parameters fail is a trade this corpus should not make;
    the runtime handles the state, and no trajectory asserts it cannot happen.
    """
    #: (kind, world, preferred fix, weight). The weights put closure ahead of
    #: everything else and keep the no-op family large, because between them
    #: they are the two answers that should be commonest at serving time.
    flavours: tuple[tuple[str, str, str, int], ...] = (
        ("fix-closed", "lab-gap", "", 10),
        ("fix-none", "lab-seen", "", 6),
        ("fix-ineffective", "lab-gap", "harden.remove_persistence", 5),
        ("fix-undetermined", "lab-gap", "harden.fix_permissions", 5),
        ("fix-refused", "lab-fix-denied", "", 4),
        # The second route to `undetermined`, and the smallest family that can
        # carry it. It takes no weight from the first: the chmod route is the
        # commoner situation in real use, and this one only has to be present
        # often enough that the state is not a synonym for it.
        ("fix-reattack-denied", "lab-reattack-denied", "", 3),
        ("fix-unavailable", "lab-nofix", "", 3),
    )
    weights = [w for _k, _w, _f, w in flavours]

    recon = ("enum.host", "enum.privileges", "enum.services",
             "enum.persistence", "enum.software")
    assess = ("vuln.weak_permissions", "vuln.credential_exposure",
              "vuln.patch_gap")
    red_params: dict[str, dict[str, Any]] = {
        "exploit.service_permissions": {"service": "acme-agent"},
        "postex.credential_dump": {"redact": True},
        "postex.persistence_install": {"mechanism": "cron"},
    }

    out: list[Scenario] = []
    for _ in range(count):
        kind, world, fix, _w = rng.choices(flavours, weights=weights)[0]
        reds: list[Step] = []

        if kind == "fix-ineffective":
            # cleanup=False is load-bearing and is not a convenience. The
            # exploit removes its own entry by default, and a hint pointing at a
            # line that is already gone is correctly not published — the
            # deterministic proposer would then fall back to the telemetry
            # switch and the gap would close. Leaving the entry on disk is what
            # gives `harden.remove_persistence` something real to remove.
            reds.append(Step("postex.persistence_install",
                             {"mechanism": "cron", "cleanup": False}))
        elif kind == "fix-undetermined":
            reds.append(Step("exploit.service_permissions",
                             {"service": "acme-agent"}))
        elif kind == "fix-none" and rng.random() < 0.45:
            world = rng.choice(("lab-blind", "lab-nocover"))
            if world == "lab-nocover":
                reds.append(Step("postex.exfil_probe",
                                 {"bytes": rng.choice((1048576, 262144)),
                                  "sink": "sandbox-collector"}))

        if not reds or (kind in ("fix-ineffective", "fix-undetermined")
                        and rng.random() < 0.35):
            # A second technique, after the one this family is built around.
            # Ordering is the whole reason it comes second: the first gap's fix
            # changes the host, and a telemetry switch flipped for an earlier
            # gap would make the later re-attack visible — which is true, is
            # recorded as such, and would silently take this family's intended
            # outcome away if the order were reversed.
            spare = [r for r in red_params if r not in {s.verb for s in reds}]
            picked = rng.sample(spare, rng.choices(
                (1, 2), weights=(74, 26))[0] if not reds else 1)
            reds += [Step(r, red_params[r]) for r in picked]

        # Kept short on purpose. Each gap now costs four more turns than it
        # used to — the fix, the re-attack, the second probe — and every one of
        # them is an act/obs pair competing for the same 1024-token window that
        # the finding, which carries the remediation outcome, sits at the end
        # of. The recon that would have opened the episode is what gives way.
        lead: list[Step | str] = []
        budget = max(0, rng.randint(0, 3) - len(reds))
        if budget:
            lead += rng.sample(recon, min(budget, rng.randint(0, 2)))
            if len(lead) < budget:
                lead.append(rng.choice(assess))

        steps = tuple(lead + reds)
        task = _phrase(rng, [s.verb if isinstance(s, Step) else s
                             for s in steps]) + rng.choice(_REMEDIATE_ASK)
        out.append(Scenario(
            task=_dress(rng, task),
            steps=steps,
            world=world,
            max_turns=len(steps) * 2 + 6,
            # Never shuffled. The red verb this family is built around has to
            # run first, and a reordering that put the other one ahead of it
            # would change the outcome without changing the label.
            shuffle=False,
            kind=kind,
            remediate=True,
            fix=fix,
        ))
    return out


# ---------------------------------------------------------------------------
# generation
# ---------------------------------------------------------------------------

def build_scenarios(rng: random.Random, *, include_lab: bool = True,
                    observe: int = 1000, refusals: int = 420,
                    lab: int = 420, clean: int = 320,
                    remediate: int = 260) -> list[Scenario]:
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
        scenarios += _derived_remediation(rng, remediate)
    else:
        scenarios = [s for s in scenarios if not s.world.startswith("lab")]
    rng.shuffle(scenarios)
    return scenarios


# ---------------------------------------------------------------------------
# redaction: what this machine is called must not reach the weights
#
# Every ``<|obs|>`` in this corpus is a real read of a real machine, and that is
# the point of the module — but a real read of *this* machine returns the
# operator's account name, home directory, host name and per-user temp
# directory, and this corpus is the thing the model memorises. A username in a
# text file can be grepped out an hour later. A username in a checkpoint can
# only be trained out, which means throwing away the run. So the substitution
# happens here, on the document, before it is fingerprinted, counted or handed
# to a caller — not in a cleanup pass somebody has to remember to run, and not
# in the writer, because the writer is not the only exit.
#
# Two rules shape what follows.
#
# **Substitute, never delete.** ``/Users/<name>/Public`` becomes
# ``/Users/operator/Public``, not ``<home>/Public``. The model has to learn that
# a home directory is a path with an account name in it; a corpus full of
# angle-bracket holes teaches it that observations contain angle-bracket holes,
# and at serving time it will meet a real path it has no shape for.
#
# **Never substitute a name that is not identity.** The table is built from
# whatever this machine happens to be called, so a corpus built as ``root``, or
# on CI where the account is ``runner``, would rewrite every
# ``"runs_as":"root"`` in thirteen thousand documents and teach the model a
# world in which nothing runs as root. A redactor that quietly corrupts the
# corpus is worse than the leak it was added to fix, so generic names are left
# exactly as observed and the reason is written down below.
#
# **The network layer, and why it is the half that matters.** For most of this
# module's life the table read four things — account name, display name, home
# path, per-user temp directory — and a host name. That was a stated boundary
# and it was the wrong boundary, because the identifiers it left out are the
# ones the operator *cannot change*. A host can be renamed in a second. A
# burned-in interface MAC cannot be renamed at all, and a provider-delegated
# IPv6 /64 is a geographic and subscriber identifier that reaches every device
# behind it. An audit of a built corpus found a live global-unicast IPv6
# address of this Mac in 3,540 documents, its /64 prefix in 10,620, three
# hardware MACs of the ``anpi`` interfaces in 1,770, and the name of a mounted
# external volume in 1,776 — all still valid weeks and a reboot later, and none
# of them in the table. They arrive through ordinary observations, exactly like
# the account name does: ``enum.network`` reports interfaces, a sandbox path
# names the volume it lives on. So the table now reads the network too, from
# the operating system and never from configuration, because a configured list
# is a list of the leaks somebody already noticed and a *persisted* list is a
# new leak.
#
# **The prefix is substituted as well as the address, and that is deliberate.**
# Two of the addresses the audit found belong to *other* devices on the same
# /64 — observed, not bound here, so no amount of reading this machine's
# interfaces can enumerate them. The /64 entry is the only one that reaches
# them: it rewrites the network half of an address this machine never held,
# which is the half that identifies the subscriber line.
#
# **Calibration, because an uncalibrated address scanner is useless here.**
# This is a security corpus: it is full of ``192.0.2.0/24``,
# ``198.51.100.0/24``, ``2001:db8::/32`` and reserved MAC addresses *on
# purpose*, because that is what standards documents and detection rules use
# for examples. Substituting those would corrupt thousands of documents and
# bury the real findings underneath them. Every classifier below therefore
# answers "not identity" for documentation space, and the replacements are
# drawn from documentation space so that a redacted observation and an RFC
# example agree on what an example address looks like.
#
# **Fail closed, not open.** An earlier version of this section opened with
# ``if pattern is None: return text`` — so a table that came back empty because
# a lookup failed returned Mac-captured text unchanged and silently, which is
# precisely the failure the paragraph above calls worse than no redactor at
# all. The two cases are now separated: a machine that genuinely has nothing
# identifying about it (``root`` in ``/root`` on a hex-named container with
# nothing routable bound) is leaking nothing and passes through, while a lookup
# that *failed* raises and names which lookup it was. Nothing is swallowed on
# the way either: the per-candidate ``except OSError`` in the temp-directory
# scan used to drop a candidate silently, and a candidate that cannot be
# classified is exactly the one that cannot be ruled out.
#
# **One matcher, not two folds.** The substituter used to compile the table
# with ``re.IGNORECASE`` while the verifier compared ``str.lower()``
# substrings, and those two disagree in both directions — ``re`` matches ``i``
# against U+0130 while ``.lower()`` turns U+0130 into two code points, so a
# document could be rewritten by a check that called it clean, or called clean
# by a check the substituter would have rewritten. On this account name the
# disagreement is reachable, and the substituter's own reverse lookup raises
# ``KeyError`` on it mid-build. Both now run the *same compiled pattern* and
# resolve the replacement by group index, so there is no fold left to disagree
# about: the verifier reports exactly the set of literals the substituter would
# rewrite.
#
# **Privacy and generalisation are one pass and two problems.** Privacy is
# satisfied by *any* substitution. Generalisation is satisfied only by a
# *varied* one: 253 distinct machine literals collapsed into a single
# ``<HOST>`` token passes every privacy gate and makes the model worse, because
# it teaches a new constant where there used to be a distribution. So each
# network kind draws its replacement from a small vocabulary, keyed on a digest
# of the literal — see the vocabulary block below for the sizes and the
# arithmetic behind them.
# ---------------------------------------------------------------------------

#: What an identifying account name is replaced by. ``operator`` is not an
#: arbitrary choice: the sandbox worlds in this module already call their
#: synthetic unprivileged user ``operator``, so a redacted host observation and
#: a sandbox observation agree on what a non-root account looks like instead of
#: introducing a second convention the model has to reconcile.
_OPERATOR = "operator"

#: What an identifying host name is replaced by. Deliberately not ``operator``:
#: a host name and an account name are different kinds of thing and a corpus
#: that spells them the same way teaches the model they are interchangeable.
_OPERATOR_HOST = "operator-host"

#: Names that are *not* identity and must never be substituted. Every one of
#: these is a name thousands of machines share, so it discloses nothing about
#: anybody — while substituting it would rewrite unrelated, load-bearing text.
#: ``root`` is the dangerous one (see the section comment), ``runner`` and
#: ``ubuntu`` are what CI and cloud images call their accounts, and ``operator``
#: is this module's own placeholder.
_NOT_IDENTITY = frozenset({
    "root", "admin", "administrator", "user", "users", "guest", "nobody",
    "system", "daemon", "operator", "runner", "ubuntu", "debian", "fedora",
    "ec2-user", "vagrant", "docker", "localhost", "host", "hostname",
    "home", "var", "tmp", "temp", "private", "build", "test", "ci",
    "jenkins", "whetstone",
})

#: Below this length a literal substitution does more damage than the leak it
#: repairs: a three-character account name occurs inside unrelated package
#: names, service names and paths, and every one of those occurrences would be
#: rewritten with no way to tell afterwards which were which.
_MIN_IDENTIFYING = 4


def _fold(text: str) -> str:
    """The one case fold this module compares with.

    ``str.lower`` rather than ``str.casefold`` on purpose: ``casefold`` folds
    ``ß`` to ``ss``, which would merge two genuinely different literals into
    one table entry, and a merged entry means one of them loses its
    replacement. ``lower`` is also the closest thing to what ``re.IGNORECASE``
    does.

    Nothing about *matching* depends on this any more — the substituter and the
    verifier share one compiled pattern and resolve by group index — so a
    residual disagreement between this fold and ``re.IGNORECASE`` can only
    produce a redundant table entry, never a missed literal. It is used for
    assembling the table: deduplication, and the two guards that stop a
    replacement from re-introducing a literal.
    """
    return text.lower()


def _is_identifying(name: str) -> bool:
    """True when ``name`` is specific enough that substituting it is worth it.

    The predicate is deliberately conservative in *both* directions: a name it
    rejects stays in the corpus, and a name it accepts is rewritten everywhere
    it appears. Getting it wrong in the first direction leaks; getting it wrong
    in the second corrupts. The length floor and the generic-name set are what
    keep the second kind of mistake out.
    """
    return len(name) >= _MIN_IDENTIFYING and _fold(name) not in _NOT_IDENTITY


def _spellings(secret: str, replacement: str) -> list[tuple[str, str]]:
    """The spellings one value can take **once it is inside JSON**, each paired
    with a replacement spelled the same way.

    ``render_episode`` serialises payloads with ``json.dumps``, which leaves a
    POSIX path alone but doubles the separators in a Windows one: ``Path.home()``
    returns ``C:\\Users\\alice`` and the document carries ``C:\\\\Users\\\\alice``.
    A table holding only the value Python handed us substitutes neither that nor
    the forward-slash spelling some tools report for the same directory.

    The replacement has to carry the same transform, and this is the part that
    bites: substituting a single-backslash ``C:\\Users\\operator`` into a JSON
    string produces ``\\U``, which is not a valid escape, and the document stops
    parsing. Pairing the transforms here means a caller cannot get that wrong by
    reaching for the literal.

    This function is the *escape* axis only, which is why a POSIX path really
    does have one spelling here and a test says so. The *separator* axis is
    :func:`_separator_forms`, and :func:`_identity_table` composes the two —
    see the note there for the leak that cost.
    """
    forms = [(secret, replacement)]
    if "\\" in secret:
        forms.append((secret.replace("\\", "\\\\"),
                      replacement.replace("\\", "\\\\")))
        forms.append((secret.replace("\\", "/"),
                      replacement.replace("\\", "/")))
    return forms


def _separator_forms(value: str) -> list[str]:
    """Every path-separator spelling of ``value``, primary spelling first.

    :func:`_spellings` derives a backslash variant only when the value it was
    handed already contains one, which is a Windows-only condition — so a POSIX
    home directory could not generate its separator-flattened spelling at all.
    An audit put ``\\Users\\<name>`` past the table and :func:`identity_leaks`
    called it clean, because the literal the table was looking for was spelled
    with the other separator. Tools that normalise paths, logs copied out of a
    Windows host and anything that round-trips a path through a
    Windows-flavoured library all produce that spelling, and the leak does not
    care which of them did it.

    A value with no separator in it has one spelling and is returned unchanged,
    so this is free for account names, host names, MAC addresses and
    addresses.
    """
    if "/" not in value and "\\" not in value:
        return [value]
    forms = [value]
    for alt in (value.replace("\\", "/"), value.replace("/", "\\")):
        if alt not in forms:
            forms.append(alt)
    return forms


# ---------------------------------------------------------------------------
# replacement vocabularies
#
# Sized on one measurement and one principle. The measurement: this Mac binds
# 15 distinct interface MACs and 12 addresses across 1 global prefix, holds 2
# RFC1918 addresses and mounts 2 non-boot volumes, and the audited corpus
# repeats each of those literals between 1,770 and 3,540 times. The principle:
# a pool has to be **larger than the number of distinct literals of its kind**,
# so the assignment is injective — two interfaces must not come out with the
# same MAC, because that is not a world that exists — and **very much smaller
# than the number of occurrences**, so the model meets each replacement
# thousands of times and learns the shape of an address rather than memorising
# a hapax. A pool of one is the ``<HOST>`` failure: it passes the privacy gate
# and teaches a constant. A pool as large as the occurrence count is a
# relabelling that teaches nothing. Every pool below is at least double the
# distinct count measured here, and a pool that still runs out is reported as a
# lookup failure rather than wrapping around and handing two interfaces one
# address.
# ---------------------------------------------------------------------------

#: Documentation /64 prefixes, from RFC 3849's ``2001:db8::/32``. Sixteen, for
#: one delegated prefix plus whatever tunnel prefixes a VPN adds.
_DOC_V6_PREFIXES = (
    "2001:db8:a1:1", "2001:db8:a2:12", "2001:db8:b3:23", "2001:db8:b4:34",
    "2001:db8:c5:45", "2001:db8:c6:56", "2001:db8:d7:67", "2001:db8:d8:78",
    "2001:db8:e9:89", "2001:db8:ea:9a", "2001:db8:fb:ab", "2001:db8:fc:bc",
    "2001:db8:1d:cd", "2001:db8:2e:de", "2001:db8:3f:ef", "2001:db8:40:f0",
)

#: Interface identifiers — the host half of an address. Thirty-two, for twelve
#: bound addresses with room for a laptop that wakes on a different network.
#: Deliberately varied in shape: some read like a stable SLAAC identifier, some
#: like a macOS privacy address, some short, because all three occur in a real
#: observation and a model that only ever saw one would learn that the second
#: half of an address is always eight hex digits long.
_DOC_V6_IIDS = (
    "0:0:0:1a", "0:0:0:2b", "0:0:0:3c", "0:0:0:4d",
    "a10b:c20d:e30f:1a2b", "b21c:d32e:f43a:2b3c", "c32d:e43f:a54b:3c4d",
    "d43e:f54a:b65c:4d5e", "e54f:a65b:c76d:5e6f", "f65a:b76c:d87e:6f70",
    "a76b:c87d:e98f:7081", "b87c:d98e:fa90:8192", "c98d:ea9f:0ba1:92a3",
    "da9e:fba0:1cb2:a3b4", "eba1:0cb2:2dc3:b4c5", "fcb2:1dc3:3ed4:c5d6",
    "1dc3:2ed4:4fe5:d6e7", "2ed4:3fe5:50f6:e7f8", "3fe5:40f6:6107:f809",
    "40f6:5107:7218:91a", "5107:6218:8329:1a2b", "6218:7329:943a:2b3c",
    "7329:843a:a54b:3c4d", "843a:954b:b65c:4d5e", "954b:a65c:c76d:5e6f",
    "a65c:b76d:d87e:6f70", "b76d:c87e:e98f:7081", "c87e:d98f:fa90:8192",
    "0:0:5e:53", "0:0:5e:54", "0:0:5e:55", "0:0:5e:56",
)

#: Documentation MAC addresses: RFC 7042 §2.1.2 reserves
#: ``00-00-5E-00-53-00`` through ``00-00-5E-00-53-FF`` for exactly this.
#: Sixty-four of the 256, four times the fifteen interfaces this Mac has.
_DOC_MACS = tuple(f"00:00:5e:00:53:{n:02x}" for n in range(0x40))

#: Host-octet tails for an RFC1918 address. The block is kept — a ``10/8``
#: address stays a ``10/8`` address — and only the host bits move, because the
#: block is what tells a reader a flat home network from a routed lab, and that
#: distinction is signal rather than identity. Twenty-four tuples, and no octet
#: is ``0``, ``1``, ``2``, ``100``, ``254`` or ``255``: those are the ones every
#: networking example already uses, and landing on one would make a substituted
#: address indistinguishable from a documentation address somebody wrote on
#: purpose.
_DOC_V4_TAILS = (
    (17, 43, 219), (23, 58, 131), (29, 67, 173), (31, 74, 197),
    (37, 86, 211), (41, 93, 149), (43, 107, 167), (47, 113, 181),
    (53, 127, 193), (59, 134, 157), (61, 143, 179), (67, 151, 203),
    (71, 163, 227), (73, 169, 139), (79, 177, 151), (83, 181, 163),
    (89, 191, 171), (97, 199, 183), (101, 211, 189), (103, 217, 197),
    (107, 223, 209), (109, 229, 213), (113, 233, 221), (127, 239, 231),
)

#: Volume names. Every one of these is also in :data:`_NOT_IDENTITY_VOLUMES`,
#: and that is the point: a volume really called ``Backup`` is left alone,
#: because the word discloses nothing and substituting it would rewrite every
#: occurrence of ``backup`` in 625 MB of security prose, while a volume named
#: after its owner is renamed *to* one of these and the result reads like a
#: volume name instead of like a redaction.
_DOC_VOLUMES = (
    "Backup", "Archive", "External", "Scratch", "Storage", "Transit",
    "Vault", "Workbench", "Shuttle", "Satchel", "Toolbox", "Locker",
)

#: Volume names that identify nobody. The macOS system volumes are here
#: because every Mac has them; the generic words are here for the reason
#: :data:`_DOC_VOLUMES` gives.
_NOT_IDENTITY_VOLUMES = frozenset(_fold(name) for name in (
    "Macintosh HD", "Macintosh HD - Data", "Data", "Preboot", "Recovery",
    "Update", "VM", "xarts", "iSCPreboot", "Hardware", "home", "net",
    "Time Machine Backups", "TimeMachine", "Untitled", "NO NAME", "NONAME",
    "BOOTCAMP", "EFI", "USB", "External", "Backup", "Backups", "Archive",
    "Scratch", "Storage", "Transit", "Vault", "Workbench", "Shuttle",
    "Satchel", "Toolbox", "Locker", "Media", "Music", "Photos", "Movies",
))

#: MAC addresses that identify nobody: the null and broadcast addresses, the
#: whole RFC 7042 documentation range, and the handful of made-up addresses
#: security writing uses as examples. A real interface carrying one of these is
#: carrying a value thousands of documents already contain.
_NOT_IDENTITY_MACS = frozenset(
    {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff",
     "00:11:22:33:44:55", "11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff",
     "de:ad:be:ef:de:ad", "de:ad:be:ef:00:01", "12:34:56:78:9a:bc",
     "01:23:45:67:89:ab", "00:1a:2b:3c:4d:5e", "08:00:27:00:00:00"}
    | {f"00:00:5e:00:53:{n:02x}" for n in range(256)}
)

#: RFC1918 addresses that identify nobody. ``.1`` and ``.254`` are what every
#: diagram calls the gateway, ``.2`` is what every hypervisor hands its first
#: guest, ``.100`` is the DHCP pool start in every tutorial, and the repdigit
#: addresses are what people reach for when inventing one. Substituting any of
#: them would rewrite documentation rather than remove a leak.
_NOT_IDENTITY_V4 = frozenset(
    {f"{net}.{host}"
     for net in ("10.0.0", "10.0.1", "10.1.1", "10.10.10",
                 "172.16.0", "172.16.1", "172.17.0", "172.20.0",
                 "192.168.0", "192.168.1", "192.168.2", "192.168.56",
                 "192.168.100", "192.168.122")
     for host in (0, 1, 2, 10, 100, 101, 200, 254, 255)}
    | {"10.10.10.10", "172.16.16.16", "192.168.168.168"}
)

#: The blocks RFC1918 reserves. Written out rather than taken from
#: ``is_private``, which also answers True for the documentation ranges, the
#: benchmarking range and carrier-grade NAT — exactly the space that must not
#: be touched.
_RFC1918 = tuple(ipaddress.ip_network(cidr) for cidr in
                 ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))

#: IPv4 space reserved for writing about rather than addressing with: the three
#: TEST-NET ranges, the benchmarking range, ``192.0.0.0/24`` and the
#: ``233.252.0.0/24`` multicast example block. A bound address inside one of
#: these is a lab fixture, and this corpus is full of them on purpose.
_DOC_V4_NETS = tuple(ipaddress.ip_network(cidr) for cidr in
                     ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
                      "198.18.0.0/15", "192.0.0.0/24", "233.252.0.0/24"))

#: Where a bound *public* IPv4 address is sent. TEST-NET-2, so the replacement
#: is still a non-private address and the document still reads as one.
_DOC_V4_PUBLIC = ipaddress.ip_network("198.51.100.0/24")

#: IPv6 space reserved for documentation, and for protocols whose identifiers
#: must not be mistaken for addresses: RFC 3849's prefix, RFC 9637's second
#: documentation prefix, ORCHIDv2, the discard prefix, the dead 6bone range and
#: 6to4. ``3fff::/20`` is the one worth naming: it was reserved in 2024, which
#: is recent enough that a scanner written from memory misses it, and the
#: calibration fixture caught exactly that.
_DOC_V6_NETS = tuple(ipaddress.ip_network(cidr) for cidr in
                     ("2001:db8::/32", "3fff::/20", "2001:20::/28",
                      "100::/64", "3ffe::/16", "2002::/16"))

#: Global unicast, as currently allocated, and the unique-local range. A ULA
#: prefix is randomly generated per site, so it identifies the site exactly the
#: way a delegated prefix identifies the subscriber.
_GLOBAL_V6 = ipaddress.ip_network("2000::/3")
_ULA_V6 = ipaddress.ip_network("fc00::/7")

#: Below this, a *link-local* interface identifier is a documentation shape
#: rather than a machine: ``fe80::1`` is in every routing diagram ever drawn
#: and the dozen addresses that look like it are shared by millions of hosts. A
#: real SLAAC or privacy identifier fills the low 64 bits. It is not applied to
#: global addresses — see :func:`_identifying_ipv6` for the address this cost.
_MIN_IID = 0x10000


def _digest_index(literal: str) -> int:
    """A stable index derived from ``literal``.

    ``hash()`` is salted per process, so two builds of the same corpus would
    disagree about which replacement a literal gets and the shards would stop
    being reproducible. A digest is the same everywhere, forever, which is what
    makes "the same literal maps to the same replacement" true across a build
    that forks a child per source.
    """
    return int.from_bytes(hashlib.sha256(literal.encode("utf-8")).digest()[:8],
                          "big")


def _assign(pool: Sequence[Any], literal: str, literals: Sequence[str],
            taken: set[Any], render: Callable[[Any], str] = str) -> Any:
    """Pick ``literal``'s replacement out of ``pool``, deterministically.

    Starts at a digest-derived offset so the choice is varied and stable, then
    walks forward past anything already handed out and anything whose rendered
    replacement contains a literal this table is going to substitute. That
    second check is not fussiness: if a replacement contained another entry's
    literal, the cross-pair guard at the end of :func:`_identity_table` would
    drop that entry to break the loop, and the dropped entry is a leak. It is
    also what makes a second :func:`redact_identity` pass a no-op, because no
    replacement can match the pattern that produced it.

    ``render`` composes the pool item into the replacement that will actually
    be written — a host-octet tuple into an address, an interface identifier
    into a full address — so the containment check tests the real string rather
    than the ingredient.

    Returns ``None`` when the pool is exhausted, which the caller records as a
    lookup failure rather than papering over by reusing a replacement. Two
    interfaces with the same MAC is not a world that exists, and teaching the
    model that it is would be worse than refusing the build.
    """
    folded = [_fold(item) for item in literals]
    start = _digest_index(literal)
    for offset in range(len(pool)):
        candidate = pool[(start + offset) % len(pool)]
        if candidate in taken:
            continue
        text = _fold(render(candidate))
        if any(lit in text for lit in folded):
            continue
        taken.add(candidate)
        return candidate
    return None


# ---------------------------------------------------------------------------
# reading the network, without running a command
#
# ``getifaddrs(3)`` through :mod:`ctypes` rather than parsing ``ifconfig``,
# because this module has to be able to build its table without running a
# command — the same reason the display name is read from :mod:`pwd` instead of
# from ``dscl`` and the temp directories are found by ownership instead of by
# ``getconf``. A subprocess is a second failure mode (missing binary, different
# locale, a shell in a sandbox) and it would put this machine's addresses into
# another process's argv and output, which is how a reporting pass becomes a
# leak.
# ---------------------------------------------------------------------------

#: ``AF_LINK`` on the BSDs, ``AF_PACKET`` on Linux. Neither is in :mod:`socket`
#: on macOS, so both are written down.
_AF_LINK, _AF_PACKET = 18, 17


class _IfAddrs(ctypes.Structure):
    """``struct ifaddrs`` — the same shape on macOS, the BSDs and Linux."""


_IfAddrs._fields_ = [
    ("ifa_next", ctypes.POINTER(_IfAddrs)),
    ("ifa_name", ctypes.c_char_p),
    ("ifa_flags", ctypes.c_uint),
    ("ifa_addr", ctypes.c_void_p),
    ("ifa_netmask", ctypes.c_void_p),
    ("ifa_dstaddr", ctypes.c_void_p),
    ("ifa_data", ctypes.c_void_p),
]


def _getifaddrs_records() -> list[tuple[str, str]]:
    """``(kind, value)`` for every address bound to a local interface.

    The struct layout differs in exactly one place that matters. ``sockaddr``
    on the BSDs begins with a one-byte length and then the family; on Linux the
    family is a 16-bit field at offset zero. The address itself sits at the same
    offset in both: 4 into ``sockaddr_in``, 8 into ``sockaddr_in6``. The
    hardware address is the one genuinely different structure — ``sockaddr_dl``
    carries it at ``sdl_data[sdl_nlen:]``, ``sockaddr_ll`` at a fixed offset.

    Interfaces that are down are included deliberately: a burned-in MAC is the
    machine's whether or not anything is using it, and ``enum.network`` reports
    the interface list rather than only the live ones.

    Raises :class:`OSError` when the lookup cannot be made, so the caller can
    record a failure instead of mistaking "no addresses" for "no addresses
    found".
    """
    bsd = platform.system() != "Linux"
    try:
        libc = ctypes.CDLL(None, use_errno=True)
    except OSError:
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    if not hasattr(libc, "getifaddrs"):
        raise OSError("getifaddrs is not available in libc")

    head = ctypes.POINTER(_IfAddrs)()
    if libc.getifaddrs(ctypes.byref(head)) != 0:
        raise OSError(ctypes.get_errno(), "getifaddrs failed")

    records: list[tuple[str, str]] = []
    try:
        node = head
        while node:
            entry = node.contents
            addr = entry.ifa_addr
            if addr:
                lead = ctypes.string_at(addr, 2)
                family = lead[1] if bsd else int.from_bytes(lead, sys.byteorder)
                if family == socket.AF_INET:
                    raw = ctypes.string_at(addr, 8)[4:8]
                    records.append(("ipv4", str(ipaddress.IPv4Address(raw))))
                elif family == socket.AF_INET6:
                    raw = ctypes.string_at(addr, 28)[8:24]
                    records.append(("ipv6", str(ipaddress.IPv6Address(raw))))
                elif family == (_AF_LINK if bsd else _AF_PACKET):
                    blob = ctypes.string_at(addr, 32)
                    if bsd:
                        nlen, alen = blob[5], blob[6]
                        hardware = blob[8 + nlen:8 + nlen + alen]
                    else:
                        hardware = blob[12:12 + blob[11]]
                    if len(hardware) == 6:
                        records.append(
                            ("mac", ":".join(f"{b:02x}" for b in hardware)))
            node = entry.ifa_next
    finally:
        libc.freeifaddrs(head)
    return records


def _sysfs_records() -> list[tuple[str, str]]:
    """The Linux fallback: hardware addresses from ``/sys`` and IPv6 from
    ``/proc``, both of which are ordinary file reads.

    It cannot see IPv4 — there is no procfs file that lists the addresses bound
    to an interface, only routes — so the caller records that gap as a failure
    rather than reporting a network layer it did not finish reading.
    """
    records: list[tuple[str, str]] = []
    for entry in sorted(os.scandir("/sys/class/net"), key=lambda e: e.name):
        try:
            with open(os.path.join(entry.path, "address"),
                      encoding="utf-8") as handle:
                mac = handle.read().strip()
        except OSError:
            continue
        if len(mac) == 17:
            records.append(("mac", _fold(mac)))
    try:
        with open("/proc/net/if_inet6", encoding="utf-8") as handle:
            for line in handle:
                fields = line.split()
                if not fields or len(fields[0]) != 32:
                    continue
                records.append(
                    ("ipv6", str(ipaddress.IPv6Address(
                        bytes.fromhex(fields[0])))))
    except OSError:
        pass
    return records


def _host_addresses() -> tuple[list[tuple[str, str]], list[str], list[str]]:
    """``(records, failures, notes)`` for this machine's bound addresses.

    One seam, so a test can fabricate a machine without fabricating a kernel,
    and so the two empty cases stay distinguishable: empty ``records`` with
    empty ``failures`` means this host really has nothing bound worth hiding,
    while anything in ``failures`` means the table cannot certify a document
    and :func:`redact_identity` must refuse rather than return the text.

    A failure or a note names the lookup and the exception class. Neither ever
    carries a value — the whole reason this module exists is that writing
    values down while reporting on values is how an audit becomes a leak.
    """
    try:
        return _getifaddrs_records(), [], []
    except Exception as exc:
        first = f"interfaces:getifaddrs:{type(exc).__name__}"
    if platform.system() == "Linux":
        try:
            return _sysfs_records(), ["interfaces:ipv4-unavailable"], [first]
        except OSError as exc:
            return [], [first, f"interfaces:sysfs:{type(exc).__name__}"], []
    return [], [first, "interfaces:no-reader-for-platform"], []


def _host_volumes() -> tuple[list[str], list[str], list[str]]:
    """``(names, failures, notes)`` for mounted volumes other than the boot
    volume.

    The names, not the mount paths: a volume name appears inside a sandbox
    path, inside a tool's error message and on its own, and substituting the
    name covers all three. The boot volume is excluded by resolving to ``/``
    rather than by matching ``Macintosh HD``, because a renamed boot volume is
    still the boot volume — and its name is in the generic set anyway.
    """
    darwin = platform.system() == "Darwin"
    roots = ["/Volumes"] if darwin else ["/media", "/mnt", "/run/media"]
    names: list[str] = []
    failures: list[str] = []
    notes: list[str] = []
    for root in roots:
        if not os.path.isdir(root):
            continue
        try:
            entries = list(os.scandir(root))
        except OSError as exc:
            failures.append(f"volumes:scandir:{type(exc).__name__}")
            continue
        for entry in entries:
            try:
                if os.path.realpath(entry.path) == os.sep:
                    continue
            except OSError as exc:
                # Kept rather than skipped: a name we cannot resolve is a name
                # we cannot rule out, and substituting the boot volume's name
                # by mistake costs nothing because it is generic anyway.
                notes.append(f"volumes:realpath:{type(exc).__name__}")
            names.append(entry.name)
            if root in ("/media", "/run/media"):
                # ``/media/<user>/<label>`` is where most Linux desktops mount,
                # so one level down is a volume name too. One level, not a
                # walk: deeper is the volume's own contents, and os.walk down a
                # mounted disk is how a source once pulled the corpus cache
                # back in as prose.
                try:
                    names.extend(child.name for child in os.scandir(entry.path))
                except OSError as exc:
                    notes.append(f"volumes:nested:{type(exc).__name__}")
    return names, failures, notes


def _temp_directories() -> tuple[list[str], list[str], list[str]]:
    """``(paths, failures, notes)`` for every temp directory this account owns.

    Not only the one ``TMPDIR`` names right now. ``gettempdir()`` follows
    ``TMPDIR``, so pointing the corpus build's scratch at the external volume —
    which this project now does, because forty-four sources unpacking into the
    internal disk filled it and took the machine down mid-build — drops the
    per-user ``/var/folders`` path straight out of this table, while every
    document captured before the move still carries it. That is not a
    hypothetical: it put a real ``/var/folders/<x>/<hash>/T`` into a built
    corpus, seven times in one document, and the build reported zero leaks
    because the literal it was checking for was no longer the literal that was
    there. A directory identifies its owner whether or not anything is using
    it, so the table is keyed on ownership rather than on the environment.

    Found by ownership rather than by ``getconf``: this module must build its
    table without running a command, and ``CS_DARWIN_USER_TEMP_DIR`` is not in
    every build's ``os.confstr_names``. Walked with :func:`os.scandir` rather
    than :func:`glob.glob`, because ``glob`` swallows a permission error and
    returns a short list that looks exactly like a complete one.

    A candidate that cannot be stat'ed used to be dropped by a bare
    ``except OSError: continue`` — the silent half of the fail-open this
    section is about, since the one candidate that cannot be classified is
    exactly the one that cannot be ruled out. It is now **kept** and recorded:
    a ``/var/folders/<x>/<28 chars>/T`` path identifies whoever owns it, and
    substituting one that turns out to belong to another account costs nothing,
    while leaving one that turns out to be ours costs the corpus. Because the
    candidate is kept, the record is a note rather than a failure: no coverage
    was lost, so there is nothing for a caller to refuse over.
    """
    paths = [tempfile.gettempdir()]
    failures: list[str] = []
    notes: list[str] = []
    root = "/var/folders"
    if not os.path.isdir(root):
        return paths, failures, notes
    try:
        outer = list(os.scandir(root))
    except OSError as exc:
        return paths, [f"tempdirs:scandir:{type(exc).__name__}"], notes
    for first in outer:
        try:
            inner = list(os.scandir(first.path))
        except OSError as exc:
            failures.append(f"tempdirs:scandir:{type(exc).__name__}")
            continue
        for second in inner:
            candidate = os.path.join(second.path, "T")
            try:
                mine = os.stat(candidate).st_uid == os.getuid()
            except FileNotFoundError:
                # Raced away between the scan and the stat. It cannot be in a
                # document this build is about to write, because it no longer
                # exists to be observed.
                continue
            except OSError as exc:
                notes.append(f"tempdirs:stat:{type(exc).__name__}")
                mine = True
            if mine:
                paths.append(candidate)
    return paths, failures, notes


# ---------------------------------------------------------------------------
# classifiers: what is identity and what is documentation
# ---------------------------------------------------------------------------

def _identifying_mac(value: str) -> bool:
    """True for a hardware address that belongs to this machine and to nobody
    else's documentation.

    Group addresses are rejected because they are not interface identities. The
    locally-administered bit is deliberately *not* consulted: macOS randomises
    Wi-Fi and AWDL addresses with that bit set, and those are still this
    machine for as long as they are bound.
    """
    if len(value) != 17 or _fold(value) in _NOT_IDENTITY_MACS:
        return False
    parts = value.split(":")
    if len(parts) != 6:
        return False
    try:
        octets = [int(part, 16) for part in parts]
    except ValueError:
        return False
    return not octets[0] & 0x01


def _identifying_ipv4(value: str) -> str | None:
    """``'private'``, ``'public'`` or ``None`` for an address bound here.

    The ranges are written out rather than taken from
    :attr:`ipaddress.IPv4Address.is_private`, which answers True for the
    documentation ranges this corpus is full of. The input is an address read
    from the kernel, never a token lifted out of text, which is why there is no
    risk of the mistake an audit scanner made when it routed the version string
    ``3.0.11.2`` and the SNMP OID ``2.6.32.5`` into "public routable": a
    dotted-quad-shaped substring of prose never reaches this function.
    """
    try:
        addr = ipaddress.IPv4Address(value)
    except ValueError:
        return None
    if (addr.is_loopback or addr.is_link_local or addr.is_multicast
            or addr.is_unspecified or addr.is_reserved):
        return None
    if any(addr in net for net in _DOC_V4_NETS):
        return None
    if value in _NOT_IDENTITY_V4:
        return None
    if any(addr in net for net in _RFC1918):
        return "private"
    return "public"


def _identifying_ipv6(value: str) -> str | None:
    """``'global'``, ``'local'`` or ``None`` for an address bound here.

    ``'global'`` means the /64 is the operator's to lose — a provider-delegated
    prefix, or a unique-local prefix a site generated — and the prefix
    therefore earns a table entry of its own. ``'local'`` is a link-local
    address, whose ``fe80::`` prefix is the same on every machine on earth and
    identifies nobody; only its interface identifier does, and that identifier
    is frequently derived from the MAC, which is why a link-local address is in
    scope at all.
    """
    try:
        addr = ipaddress.IPv6Address(value)
    except ValueError:
        return None
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
        return None
    if any(addr in net for net in _DOC_V6_NETS):
        return None
    if addr.is_link_local:
        # The floor applies here and only here. ``fe80::1`` and its dozen
        # neighbours are in every routing diagram ever drawn and are shared by
        # millions of hosts, so substituting one would rewrite documentation.
        # A *global* address is a different question whatever its identifier is
        # worth: ``<delegated prefix>::ea97`` is a DHCPv6 lease on this line,
        # not an example, and an earlier version of this function applied the
        # floor to both and dropped one of this machine's three real global
        # addresses because its identifier happened to be sixteen bits. The
        # prefix entry would have rewritten the network half and left the lease
        # standing.
        return "local" if int(addr) & ((1 << 64) - 1) >= _MIN_IID else None
    if addr in _GLOBAL_V6 or addr in _ULA_V6:
        return "global"
    return None


def _identifying_volume(name: str) -> bool:
    """True for a volume name that names its owner rather than its job."""
    return _is_identifying(name) and _fold(name) not in _NOT_IDENTITY_VOLUMES


# ---------------------------------------------------------------------------
# spellings for the network kinds
#
# None of these deduplicate, and that is load-bearing: the table pairs a
# literal's spellings with the replacement's spellings positionally, so the two
# lists have to stay the same length. A spelling that happens to coincide with
# another contributes a duplicate pair, which the table's own deduplication
# collapses; a list that quietly got shorter would drop a spelling of a real
# value off the end of a ``zip`` and leave it in the corpus.
# ---------------------------------------------------------------------------

def _mac_forms(value: str) -> list[str]:
    """Every spelling of a MAC address a tool in this corpus emits.

    Colons are what ``ifconfig`` and ``ip link`` print, hyphens are what
    Windows prints, the dotted form is Cisco's, and the bare form is what
    ``/sys``, a lot of JSON APIs and most log pipelines carry. Case is not a
    spelling here: the pattern is compiled case-insensitively, which covers the
    upper-case variants without doubling the table.

    The bare form is the one worth justifying, because twelve hex characters
    could in principle land inside a digest. The arithmetic: a bare form has
    16**12 ≈ 2.8e14 possible values and this corpus holds on the order of 1e8
    hex characters, so the expected number of accidental hits across fifteen
    interfaces is about 5e-6. A hardware address the operator cannot change is
    worth that.
    """
    low = _fold(value)
    plain = low.replace(":", "")
    return [low, low.replace(":", "-"),
            ".".join(plain[i:i + 4] for i in range(0, 12, 4)), plain]


def _v6_forms(addr: ipaddress.IPv6Address) -> list[str]:
    """The three spellings of an IPv6 address that occur in observations.

    ``str()`` gives the canonical zero-compressed form, ``exploded`` gives the
    fully padded one some tools print, and the third — trimmed hextets with no
    ``::`` run — is what a tool that strips leading zeros without compressing
    emits. All three are the same address and only one of them is what Python
    handed us.
    """
    hextets = addr.exploded.split(":")
    return [str(addr), addr.exploded,
            ":".join(part.lstrip("0") or "0" for part in hextets)]


def _v6_prefix_forms(addr: ipaddress.IPv6Address) -> list[str]:
    """The spellings of a /64 prefix: the first four hextets, trimmed and
    padded.

    No ``::`` form is needed — ``2001:db8:a1:1::`` begins with the trimmed
    spelling, so the trimmed entry already covers it, and a shorter entry that
    is a prefix of a longer one is exactly what the longest-first ordering in
    :func:`_identity_table` exists to resolve.
    """
    hextets = addr.exploded.split(":")[:4]
    return [":".join(part.lstrip("0") or "0" for part in hextets),
            ":".join(hextets)]


def _dedupe(values: Iterable[str]) -> list[str]:
    """Order-preserving deduplication, for the literal lists where a repeated
    entry would mean an entity is counted twice."""
    seen: dict[str, None] = {}
    for value in values:
        seen.setdefault(value, None)
    return list(seen)


def _v6_network(addr: ipaddress.IPv6Address) -> str:
    """The /64 this address sits in, as a canonical string. Used as the key
    that makes every address on one real network land on one documentation
    network — "these two addresses are on the same /64" is a fact about the
    text that should survive redaction."""
    return str(ipaddress.IPv6Address(int(addr) >> 64 << 64))


#: Set by :func:`_identity_table` on every build. Module globals rather than a
#: second :func:`lru_cache`, and the reason is a test: the fixture that clears
#: the memoised table between tests clears *that* function's cache, and a
#: separately cached failure list would survive it and poison the next test
#: with a fabricated failure. One cache, one lookup pass, one place to clear.
#:
#: A **failure** means coverage was lost: a source this table needs could not
#: be read, so no document can be certified and the callers below refuse. A
#: **note** means a candidate could not be classified and was therefore kept —
#: coverage is intact, the conservative branch was taken, and a caller has
#: nothing to refuse over but should still be able to see it happened.
_LOOKUP_FAILURES: tuple[str, ...] = ()
_LOOKUP_NOTES: tuple[str, ...] = ()


@lru_cache(maxsize=1)
def _identity_table() -> tuple[tuple[str, str], ...]:
    """Every literal this machine can leak, paired with what replaces it.

    Read from the operating system rather than configured, because a configured
    list is a list of the leaks somebody already noticed — and a *persisted*
    list is a new leak. The sources are the ones an adapter can put into an
    observation without being asked: ``enum.privileges`` returns the account
    name, ``enum.persistence`` and ``vuln.credential_exposure`` return paths
    under the home directory, ``enum.host`` returns the host name, every
    sandbox world is built under the per-user temp directory, ``enum.network``
    returns interface addresses, and a sandbox path names the volume it lives
    on.

    **What it cannot reach, stated rather than hidden.** A *derived* display
    string is only caught when it contains one of these literals. macOS
    ``ComputerName`` is usually ``<account>'s MacBook Pro``, so it goes with the
    account name — but a machine renamed by hand, and the ``real_name`` of any
    *other* local account ``enum.users`` enumerates, are names this table was
    never told and cannot invent. An address belonging to another device on the
    same network is reachable only through its /64 prefix, which is why the
    prefix is an entry in its own right. The corpus that feeds a training run
    should be read once with :func:`identity_leaks` and once with human eyes,
    and anything found that way belongs in this function rather than in a scrub
    script, because a scrub script only ever cleans the file somebody
    remembered.

    The second thing it cannot reach is a literal cut in half by
    :data:`~whetstone.kernel.render.MAX_VALUE`. Redaction runs on the rendered
    document, so a value longer than 220 characters has already been truncated
    and ``/Users/<name>`` can survive as ``/Users/<na…`` — a partial account
    name that no table entry matches. It is not fixable at the other end
    either: truncation lives in ``whetstone/kernel/render.py`` and the runtime
    deliberately does not import anything under ``training/``. What makes it
    tolerable is the arithmetic and a measurement: the longest literal on this
    machine is 62 characters (the JSON-doubled backslash spelling of the
    per-user temp directory), so a straddle needs a value with 158 characters
    of prefix before it, and a scan of the built cache found none. If that ever
    stops being true the answer is to substitute the truncated spellings too,
    not to widen what counts as clean.

    **Replacements are varied on purpose, and not everywhere.** The name
    sources get one fixed placeholder each because each of them is *one*
    literal — one account, one person, one home, one machine — so the mapping
    is already injective and there is nothing to spread; ``operator``
    additionally has to stay fixed because the sandbox worlds in this module
    name their synthetic account that, and ``examples/runs/`` is published with
    that spelling. The network sources are the opposite case: fifteen MACs and
    a dozen addresses collapsed onto one token each would teach the model that
    a machine has one address, repeated three thousand times, which passes the
    privacy gate and makes the model worse. Those draw from the pools above,
    keyed on a digest of the literal, and every address on one real /64 is
    given the same documentation /64 so that "these two addresses are on the
    same network" survives redaction as a fact about the text.

    Ordered longest first, and the order is load-bearing: the alternation
    compiled from this table is matched leftmost-first by :mod:`re`, not
    longest-first, so ``/Users/alice`` has to precede ``alice`` or the home path
    is half-substituted into ``/Users/operator`` by the shorter rule and the
    longer one never fires. The /64 prefix sits below the full addresses for
    the same reason. Ties are broken on the text so that two machines with
    equally long names still build the table in one order.
    """
    global _LOOKUP_FAILURES, _LOOKUP_NOTES
    pairs: list[tuple[str, str]] = []
    failures: list[str] = []
    notes: list[str] = []

    def add(secret: str | None, replacement: str) -> None:
        """Enter one value under every spelling it can take.

        Two axes, composed: :func:`_separator_forms` is the separator axis and
        :func:`_spellings` is the JSON-escape axis. Composing them here rather
        than widening either one is what closes the gap an audit found, where a
        POSIX home directory spelled with backslashes was structurally
        ungeneratable and :func:`identity_leaks` called it clean.
        """
        if not secret:
            return
        separators = _separator_forms(secret)
        replacements = _separator_forms(replacement)
        for index, spelling in enumerate(separators):
            paired = replacements[min(index, len(replacements) - 1)]
            for form, repl in _spellings(spelling, paired):
                if _fold(form) in _fold(repl):
                    # Substituting would be a no-op *and* the verification in
                    # redact_identity would then fire on every document
                    # forever, because the literal is still there afterwards.
                    # A machine genuinely called ``operator-host`` is not
                    # leaking anything.
                    continue
                pairs.append((form, repl))

    try:
        user = getpass.getuser()
    except Exception as exc:
        user = ""
        failures.append(f"account:{type(exc).__name__}")
    if _is_identifying(user):
        add(user, _OPERATOR)

    # The account's display name, which is a *person's* name on most machines
    # even though it happens to repeat the account name on this one.
    # ``enum.users`` puts it in ``real_name`` and it is the one value in an
    # observation that identifies a human rather than a machine. Read from
    # ``pwd`` rather than by shelling out to ``dscl``: this module must be able
    # to build its table without running a command, and ``pwd`` is absent on
    # Windows, where there is no GECOS field to read — so ImportError is a
    # platform fact and anything else is a lookup that failed.
    gecos = ""
    try:
        import pwd

        gecos = pwd.getpwuid(os.getuid()).pw_gecos.split(",")[0].strip()
    except ImportError:
        pass
    except Exception as exc:
        failures.append(f"displayname:{type(exc).__name__}")
    if _is_identifying(gecos):
        add(gecos, _OPERATOR)

    home: Path | None
    try:
        home = Path.home()
    except Exception as exc:
        home = None
        failures.append(f"home:{type(exc).__name__}")
    # Keyed on the basename rather than on ``user``: the two usually agree, and
    # when they do not it is the directory name that is written into paths.
    if home is not None and _is_identifying(home.name):
        add(str(home), str(home.parent / _OPERATOR))

    temps, temp_failures, temp_notes = _temp_directories()
    failures.extend(temp_failures)
    notes.extend(temp_notes)
    generic_tmp = "C:\\Temp" if os.name == "nt" else "/tmp"
    for tmp in sorted(set(temps)):
        if tmp == generic_tmp:
            continue
        add(tmp, generic_tmp)
        # macOS reports the same directory both with and without the /private
        # prefix depending on whether anything resolved it, and the sandbox
        # observations in this corpus contain both.
        try:
            resolved = str(Path(tmp).resolve())
        except OSError as exc:
            failures.append(f"tempdirs:resolve:{type(exc).__name__}")
            continue
        if resolved != tmp:
            add(resolved, generic_tmp)

    # ``socket.getfqdn()`` is deliberately not consulted: it can block on a
    # reverse lookup, and the name the adapters actually report is the one
    # ``hostname`` prints, which is what these two return.
    try:
        host_names = sorted({socket.gethostname(), platform.node()})
    except OSError as exc:
        host_names = []
        failures.append(f"hostname:{type(exc).__name__}")
    for name in host_names:
        if not name:
            continue
        short, dot, domain = name.partition(".")
        if _is_identifying(name):
            add(name, f"{_OPERATOR_HOST}{dot}{domain}")
        # A fully-qualified name and its bare short form are two different
        # literals and both appear: ``hostname`` prints the qualified one on
        # macOS, while ``hostname -s``, syslog lines and most tools carry the
        # short one, so substituting only what Python handed us would leave
        # every short spelling standing.
        if dot and _is_identifying(short):
            add(short, _OPERATOR_HOST)

    # ----- the network layer -------------------------------------------------
    # Every literal is collected before any replacement is chosen, because a
    # replacement must not contain another entry's literal and that cannot be
    # checked until all of them are known.
    records, address_failures, address_notes = _host_addresses()
    failures.extend(address_failures)
    notes.extend(address_notes)
    volumes, volume_failures, volume_notes = _host_volumes()
    failures.extend(volume_failures)
    notes.extend(volume_notes)

    macs = _dedupe(_fold(value) for kind, value in records
                   if kind == "mac" and _identifying_mac(value))
    v4: list[tuple[str, str]] = []
    for kind, value in records:
        if kind != "ipv4":
            continue
        scope = _identifying_ipv4(value)
        if scope is not None and (scope, value) not in v4:
            v4.append((scope, value))
    v6: list[tuple[str, ipaddress.IPv6Address]] = []
    for kind, value in records:
        if kind != "ipv6":
            continue
        scope = _identifying_ipv6(value)
        if scope is None:
            continue
        entry = (scope, ipaddress.IPv6Address(value))
        if entry not in v6:
            v6.append(entry)
    prefixes = _dedupe(_v6_network(addr) for scope, addr in v6
                       if scope == "global")
    names = _dedupe(name for name in volumes if _identifying_volume(name))

    literals = (
        [form for form, _repl in pairs]
        + [form for mac in macs for form in _mac_forms(mac)]
        + [value for _scope, value in v4]
        + [form for _scope, addr in v6 for form in _v6_forms(addr)]
        + [form for prefix in prefixes
           for form in _v6_prefix_forms(ipaddress.IPv6Address(prefix))]
        + names)

    taken: set[Any] = set()
    exhausted: set[str] = set()

    def pick(pool: Sequence[Any], literal: str, kind: str,
             render: Callable[[Any], str] = str) -> Any:
        choice = _assign(pool, literal, literals, taken, render)
        if choice is None:
            exhausted.add(kind)
        return choice

    for mac in macs:
        replacement = pick(_DOC_MACS, mac, "mac")
        if replacement is None:
            continue
        for form, repl in zip(_mac_forms(mac), _mac_forms(replacement)):
            add(form, repl)

    for scope, value in v4:
        octets = value.split(".")
        if scope == "private":
            keep = 1 if octets[0] == "10" else 2

            def render_v4(tail: tuple[int, ...],
                          octets: list[str] = octets,
                          keep: int = keep) -> str:
                return ".".join(octets[:keep]
                                + [str(part) for part in tail[keep - 1:]])
        else:
            def render_v4(tail: tuple[int, ...]) -> str:
                return str(_DOC_V4_PUBLIC.network_address + tail[-1])
        tail = pick(_DOC_V4_TAILS, value, "ipv4", render_v4)
        if tail is not None:
            add(value, render_v4(tail))

    prefix_choice: dict[str, str] = {}
    for prefix in prefixes:
        choice = pick(_DOC_V6_PREFIXES, prefix, "ipv6-prefix",
                      lambda candidate: str(
                          ipaddress.IPv6Address(f"{candidate}::")))
        if choice is None:
            continue
        prefix_choice[prefix] = choice
        for form, repl in zip(
                _v6_prefix_forms(ipaddress.IPv6Address(prefix)),
                _v6_prefix_forms(ipaddress.IPv6Address(f"{choice}::"))):
            add(form, repl)

    for scope, addr in v6:
        if scope == "local":
            # ``fe80::`` is the prefix on every machine on earth, so it is kept
            # and only the interface identifier moves. Replacing it would be
            # rewriting a constant with a constant, and the thing that
            # identifies a link-local address is its identifier — which on many
            # interfaces is derived from the MAC.
            head = "fe80:0:0:0"
        else:
            head = prefix_choice.get(_v6_network(addr))
            if head is None:
                continue

        def render_v6(iid: str, head: str = head) -> str:
            return str(ipaddress.IPv6Address(f"{head}:{iid}"))

        iid = pick(_DOC_V6_IIDS, str(addr), "ipv6-iid", render_v6)
        if iid is None:
            continue
        replacement = ipaddress.IPv6Address(render_v6(iid))
        for form, repl in zip(_v6_forms(addr), _v6_forms(replacement)):
            add(form, repl)

    for name in names:
        replacement = pick(_DOC_VOLUMES, name, "volume")
        if replacement is not None:
            add(name, replacement)

    for kind in sorted(exhausted):
        failures.append(f"vocabulary-exhausted:{kind}")

    # One entry per distinct literal, first writer wins, so a name that is both
    # the account and the short host name resolves to exactly one replacement
    # and the substitution below cannot pick a different one than the
    # verification does.
    seen: dict[str, tuple[str, str]] = {}
    for form, repl in pairs:
        seen.setdefault(_fold(form), (form, repl))

    # Drop any literal that occurs inside a replacement this module chose. The
    # per-pair guard above only catches a value that replaces itself; this
    # catches the cross-pair case, and that case deadlocks rather than degrades:
    # an account named ``host`` would be rewritten to ``operator``, the host
    # name rewritten to ``operator-host``, and then the verification in
    # redact_identity would find ``host`` inside ``operator-host`` and refuse
    # every document forever. :func:`_assign` already refuses a replacement
    # that contains a literal, so for the network kinds this is a backstop
    # rather than a filter; the only names it can still drop are ones that are
    # a substring of ``operator``, ``operator-host``, ``/tmp`` or the redacted
    # home — names that identify nobody and that substituting would have
    # shredded the corpus to remove.
    chosen = " ".join(_fold(repl) for _form, repl in seen.values())
    kept = [pair for pair in seen.values() if _fold(pair[0]) not in chosen]
    _LOOKUP_FAILURES = tuple(_dedupe(failures))
    _LOOKUP_NOTES = tuple(_dedupe(notes))
    return tuple(sorted(kept, key=lambda kv: (-len(kv[0]), kv[0])))


def _identity_failures() -> tuple[str, ...]:
    """Which lookups could not be made, named and without values.

    Empty means every source answered — including answering "nothing here",
    which is what a container with a generic account and nothing routable bound
    legitimately does. Non-empty means this module cannot certify a document,
    and both callers below refuse rather than return the text.
    """
    _identity_table()  # the one lookup pass; it sets the globals
    return _LOOKUP_FAILURES


def _identity_notes() -> tuple[str, ...]:
    """Candidates that could not be classified and were therefore kept.

    Not a failure: the conservative branch was taken and coverage is intact.
    Recorded because the alternative is the ``except OSError: continue`` this
    section replaced, and a scan that quietly looked at less than it was asked
    to is how a corpus gets certified clean by a check that never ran.
    """
    _identity_table()
    return _LOOKUP_NOTES


@lru_cache(maxsize=4)
def _table_matcher(
        table: tuple[tuple[str, str], ...]) -> re.Pattern[str] | None:
    """Compile a table into the one matcher the substituter and the verifier
    both run, or ``None`` for an empty table.

    Each alternative is its own capturing group, so the replacement is found by
    ``m.lastindex`` — by *position in the table* rather than by folding the
    matched text back into a key. That is what closes the fold mismatch: the
    previous version compiled with ``re.IGNORECASE`` and then looked the
    replacement up under ``m.group(0).lower()``, and those two disagree on
    U+0130, which is reachable on this account name and raises ``KeyError``
    mid-build.

    Case-insensitive because Windows reports the same account as ``alice`` in a
    path and ``ALICE`` in a SAM query, hex addresses are printed in both cases,
    and a case-sensitive pass would leave the second spelling in the corpus.
    Matching case-insensitively and *replacing* rather than refusing means the
    differently-cased spelling is fixed instead of aborting a forty-minute
    generation run over something the table already knows about.

    Keyed on the table itself rather than memoised with ``maxsize=1``: a test
    that fabricates a machine changes the table, and a cache keyed on the table
    cannot answer for the new one out of the old one's compiled pattern.
    """
    if not table:
        return None
    return re.compile("|".join(f"({re.escape(form)})" for form, _ in table),
                      re.IGNORECASE)


@lru_cache(maxsize=1)
def _identity_pattern() -> re.Pattern[str] | None:
    """The matcher for this machine's table, or ``None`` on a machine with
    nothing identifying to hide."""
    return _table_matcher(_identity_table())


def identity_leaks(text: str) -> list[str]:
    """The identifying literals still present in ``text``, longest first.

    Exported so that anything else which writes this machine's observations to a
    file — the corpus builder in ``training/corpus/sources/trajectories.py``,
    the run capture in ``lab/capture.py`` — can refuse the write rather than
    trust that redaction happened upstream. It answers only about the literals
    this machine can be asked for; it cannot certify that text from some other
    machine is clean, and nothing should read it as saying so.

    It runs the *same compiled pattern* as :func:`redact_identity`, so it
    reports exactly the set of literals that function would rewrite. It used to
    compare ``str.lower()`` substrings instead, which disagrees with
    ``re.IGNORECASE`` in both directions — and the direction that matters is
    the one where a document the substituter would have rewritten is called
    clean by the checker standing in for it at the file boundary.

    Raises when a lookup failed, because a verifier that answers "clean"
    because it could not look is the same fail-open this module exists to
    prevent, reached through the checking door instead of the substituting one.
    """
    failures = _identity_failures()
    if failures:
        raise RuntimeError(
            "identity lookups failed, so nothing can be certified clean: "
            f"{failures!r}. Fix the lookup rather than reading an empty table "
            "as a clean machine — a table that came back empty because a read "
            "failed is how Mac-captured text reaches a checkpoint.")
    table = _identity_table()
    matcher = _table_matcher(table)
    if matcher is None:
        return []
    hit = {match.lastindex for match in matcher.finditer(text)}
    return [table[index - 1][0] for index in sorted(hit)]


def redact_identity(text: str) -> str:
    """Replace this machine's identity in a rendered document, or refuse.

    The refusal is the point. A redactor that silently passes text through when
    its substitution did not take is worse than no redactor at all, because
    everything downstream now believes the corpus is clean — and the place that
    belief is cashed in is a checkpoint nobody can grep. So the substitution is
    followed by a scan for survivors and a survivor raises, loudly, naming what
    it found, at generation time rather than after a training run.

    There are two ways to have nothing to substitute and they are not the same
    thing. A machine with no identifying values — ``root`` in ``/root`` on a
    hex-named container with nothing routable bound — is leaking nothing, and
    returning the text unchanged is correct. A machine whose *lookups failed*
    is a machine this function knows nothing about, and the previous version
    returned Mac-captured text unchanged and silently in exactly that case.
    The first branch passes; the second raises and names the lookup.
    """
    failures = _identity_failures()
    if failures:
        raise RuntimeError(
            "identity lookups failed and this document must not be written: "
            f"{failures!r}. An empty table is only safe when every source "
            "answered; one that failed to read means the literals it would "
            "have held are still in this text.")
    pattern = _identity_pattern()
    if pattern is None:
        # Nothing identifies this host. Every lookup answered, so this is a
        # fact about the machine rather than an absence of information.
        return text
    table = _identity_table()
    out = pattern.sub(lambda m: table[m.lastindex - 1][1], text)

    survivors = identity_leaks(out)
    if survivors:
        raise RuntimeError(
            "identity survived redaction and this document must not be "
            f"written: {survivors!r}. The substitution table and the check "
            "read the same entries, so a survivor means a replacement "
            "re-introduced a literal — fix _identity_table rather than "
            "loosening this check, because what it guards is the corpus that "
            "becomes the weights.")
    return out


def generate_trajectories(
    *, repeats: int = 6, seed: int = 1337, verbose: bool = False,
    include_lab: bool = True, lab_root: Path | None = None,
    stats: dict[str, Any] | None = None,
    scenarios: Sequence[Scenario] | None = None,
    observe: int = 1000, refusals: int = 420, lab: int = 420, clean: int = 320,
    remediate: int = 260, host_executor: Any = None,
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
    #: The remediation states the sandbox actually produced, not the ones the
    #: families were built to produce. The two are compared below.
    counts.setdefault("remediation", {})
    counts.setdefault("fix_mismatch", {})
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
        lab=lab, clean=clean, remediate=remediate)
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
                                _PlanChooser(steps, rng, scenario.fix),
                                max_turns=scenario.max_turns,
                                remediate=scenario.remediate)
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

            # Redacted here rather than in the writers, and before the
            # fingerprint rather than after. Before the fingerprint because two
            # episodes that differ only in a host name are the *same* training
            # document once the host name is gone, and hashing the unredacted
            # text would let that duplicate through. Here rather than in
            # ``_write_dir`` because the writers are not the only exit: the SFT
            # builder and the tests consume this generator directly, and a
            # redaction each caller has to remember is one a caller will forget.
            text = redact_identity(episode.render())
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
            states: list[str] = []
            for finding in episode.findings:
                counts["finding"][finding.kind] = (
                    counts["finding"].get(finding.kind, 0) + 1)
                if finding.remediation is not None:
                    state = finding.remediation.state
                    states.append(state)
                    counts["remediation"][state] = (
                        counts["remediation"].get(state, 0) + 1)

            # What the family claimed against what the sandbox did. The
            # construction is indirect — a world, a red verb and a preferred
            # fix, with the outcome decided by a real chmod or a real gate
            # ruling — so a change in the adapter or the policy could turn one
            # family into a second copy of another and nothing downstream would
            # notice: the corpus would still be well formed, every action would
            # still bind, and the state distribution the whole family exists to
            # spread would have quietly collapsed. Recorded here and printed by
            # the CLI, because a wrong number nobody notices is worse than a
            # crash.
            if scenario.kind in _INTENDED_STATE:
                want = _INTENDED_STATE[scenario.kind]
                got = sorted(set(states))
                ok = (not states) if want is None else (want in states)
                if not ok:
                    label = (f"{scenario.kind} wanted "
                             f"{want or 'no remediation'}, got "
                             f"{','.join(got) or 'none'}")
                    counts["fix_mismatch"][label] = (
                        counts["fix_mismatch"].get(label, 0) + 1)

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
    # Relative, resolved through the repo's `data` symlink, exactly as
    # training/corpus/build.py spells its own --out and --cache defaults.
    #
    # It used to be an absolute /Volumes/<name>/... path, which hardcoded the
    # external volume's name into this module's source — and that name is a
    # needle: the corpus audit found it in 1,776 training documents. The corpus
    # side is covered, because the name is a table literal and the chokepoint
    # substitutes it, but a literal sitting in source is a literal in anything
    # that ships the source, and `ownrepos` used to walk this repository into
    # the corpus as prose. tests/test_identity.py carried an xfail recording
    # exactly this line and saying "when somebody fixes that default this xfail
    # starts failing, which is the point". This is that fix.
    p.add_argument("--out", type=Path,
                   default=Path("data/corpus/raw/trajectories"),
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
    p.add_argument("--remediate", type=int, default=260,
                   help="episodes that run the kernel's remediation phase: the "
                        "fix, the re-attack that tests it, and the outcome. "
                        "0 reproduces a corpus in which the model has never "
                        "seen a hardening verb chosen")
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
        clean=args.clean, remediate=args.remediate,
        host_executor=host_executor)

    if args.out.suffix == ".jsonl":
        n, chars = _write_jsonl(args.out, texts)
    else:
        n, chars = _write_dir(args.out, texts)

    print(f"{n:,} trajectories, {chars/1e6:.2f}M chars -> {args.out}")
    print(f"  scenarios   {stats.get('scenarios', 0):,} × {args.repeats} repeats"
          f"  ({stats.get('duplicates', 0):,} identical episodes dropped)")
    for label in ("kind", "finding", "rule", "remediation"):
        rows = stats.get(label) or {}
        if rows:
            body = "  ".join(f"{k}={v:,}" for k, v in sorted(rows.items()))
            print(f"  {label:<11} {body}")
    if stats.get("errors"):
        for name, count in sorted(stats["errors"].items()):
            print(f"  ERROR       {count:,}x {name}")
    # Printed as loudly as an exception and separately from `errors`, because
    # nothing raised: every one of these episodes ran, rendered and was written.
    # A family that stopped producing the outcome it exists for is a corpus that
    # has lost a state without losing a document, which is the failure mode that
    # only shows up two checkpoints later.
    for label, count in sorted(stats.get("fix_mismatch", {}).items()):
        print(f"  MISMATCH    {count:,}x {label}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
