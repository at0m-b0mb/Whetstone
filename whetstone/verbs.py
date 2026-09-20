"""The verb catalogue: everything Whetstone can do, declared in one place.

This file is simultaneously the runtime's dispatch table, the gate's policy
surface and the model's output vocabulary. Read it as the answer to "what is
this system's action space?", because that is literally what it is.

Six groups, and the order is the order an engagement moves through:

``enum``    Look at the machine. Neutral, observe-only, the substrate both
            sides share.
``vuln``    Turn observations into findings — a missing patch, a writable
            service binary, a credential sitting in a shell history file.
            Still observe-only: identifying a weakness changes nothing.
``exploit`` Prove the finding is real by using it. Red, execute.
``postex``  What an adversary does once inside: take credentials, persist,
            escalate, move. Red.
``detect``  Ask whether the blue side noticed. This is the half that makes the
            red half worth running.
``harden``  Fix what the exercise proved was broken.

**Why exploitation is in here at all.** A finding nobody validated is a finding
nobody fixes. "Port 445 is exposed and the host is unpatched" gets triaged into
next quarter; "here is the SYSTEM shell I got through it, and here is the eleven
minutes of silence from your SIEM afterwards" gets fixed on Monday. Whetstone
exploits things because proof is what moves defenders, and it pairs every
exploit with a detection check because proof that nobody noticed is the more
valuable half of the finding.

**Why there is no ``run.shell`` verb.** The obvious shortcut — one verb taking an
arbitrary command string — would collapse this whole file into four lines and
destroy every property that makes the project work. The gate could no longer
reason about what it was approving, since the meaning would be inside an opaque
string. The model would have to generate correct shell for three operating
systems instead of choosing a concept. And the detection pairing, which depends
on knowing which technique is being performed, would be impossible. The
catalogue is more work and it is the entire design.
"""

from __future__ import annotations

from .actions import (
    NO_DETECTION,
    REGISTRY,
    Intent,
    Param,
    Side,
    TargetKind,
    Verb,
)

_HOST = TargetKind.HOST
_NONE = TargetKind.NONE


def _v(**kw: object) -> Verb:
    """Define and register a verb in one step."""
    return REGISTRY.register(Verb(**kw))  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# enum — look at the machine
#
# Every one of these is OBSERVE and NEUTRAL, which means they run unattended
# under the null engagement against loopback. That is deliberate: the tutorial,
# the corpus generator and most of the test suite live entirely in this group,
# so the common path needs no authorisation ceremony at all.
# ---------------------------------------------------------------------------

_v(
    id="enum.host",
    summary="Operating system, version, architecture, hostname, uptime, domain membership.",
    intent=Intent.OBSERVE,
    side=Side.NEUTRAL,
    target=_HOST,
)

_v(
    id="enum.users",
    summary="Local accounts, group memberships, last logon, password policy.",
    intent=Intent.OBSERVE,
    side=Side.NEUTRAL,
    target=_HOST,
    params=(
        Param("include_disabled", "boolean", "List disabled accounts too.",
              required=False, default=False),
    ),
)

_v(
    id="enum.privileges",
    summary="What the current identity can do: uid/token, admin rights, sudo entries, privileges held.",
    intent=Intent.OBSERVE,
    side=Side.NEUTRAL,
    target=_HOST,
)

_v(
    id="enum.processes",
    summary="Running processes with parent, owning user, command line and binary path.",
    intent=Intent.OBSERVE,
    side=Side.NEUTRAL,
    target=_HOST,
)

_v(
    id="enum.services",
    summary="Services, daemons and launch agents, with their binary path and start type.",
    intent=Intent.OBSERVE,
    side=Side.NEUTRAL,
    target=_HOST,
)

_v(
    id="enum.persistence",
    summary="Everything that starts without a human: autoruns, scheduled tasks, cron, units, login items.",
    intent=Intent.OBSERVE,
    side=Side.NEUTRAL,
    target=_HOST,
    # One verb, three very different implementations. On Windows this sweeps the
    # Run keys, scheduled tasks, services and WMI subscriptions; on Linux it is
    # cron, systemd units and shell profiles; on macOS, launchd plists and login
    # items. The model learns the question, not the three answers — which is the
    # single largest capacity saving available at 150M parameters.
)

_v(
    id="enum.network",
    summary="Interfaces, routes, listening sockets and established connections with owning process.",
    intent=Intent.OBSERVE,
    side=Side.NEUTRAL,
    target=_HOST,
)

_v(
    id="enum.software",
    summary="Installed packages and applied patches, with versions.",
    intent=Intent.OBSERVE,
    side=Side.NEUTRAL,
    target=_HOST,
)

_v(
    id="enum.shares",
    summary="Exported file shares and their access control.",
    intent=Intent.OBSERVE,
    side=Side.NEUTRAL,
    target=_HOST,
)


# ---------------------------------------------------------------------------
# vuln — turn observations into findings
#
# Still OBSERVE: naming a weakness does not touch anything. These are the verbs
# that answer "find bugs", and note what they actually do — correlate what
# `enum` saw against known-bad patterns and known-vulnerable versions. That is
# a matching problem, which is learnable. None of them discovers a novel
# vulnerability class, and none of them claims to.
# ---------------------------------------------------------------------------

_v(
    id="vuln.patch_gap",
    summary="Installed versions against known-vulnerable ranges; reports CVEs the host is exposed to.",
    intent=Intent.OBSERVE,
    side=Side.NEUTRAL,
    target=_HOST,
    params=(
        Param("min_severity", "enum", "Lowest severity to report.",
              required=False, default="medium",
              choices=("low", "medium", "high", "critical")),
    ),
)

_v(
    id="vuln.weak_permissions",
    summary="Writable service binaries, unquoted service paths, weak ACLs on privileged files.",
    intent=Intent.OBSERVE,
    side=Side.NEUTRAL,
    target=_HOST,
)

_v(
    id="vuln.credential_exposure",
    summary="Credentials sitting in shell history, config files, environment variables or scripts.",
    intent=Intent.OBSERVE,
    side=Side.NEUTRAL,
    target=_HOST,
)

_v(
    id="vuln.privilege_path",
    summary="A concrete route from the current identity to administrator, if one exists.",
    intent=Intent.OBSERVE,
    side=Side.NEUTRAL,
    target=_HOST,
    # The chaining verb. Takes the output of the other vuln.* verbs and looks
    # for a sequence that composes — writable service binary plus a service
    # running as SYSTEM plus the right to restart it, say. Returns the chain,
    # not a score. A chain is actionable; a score is a number in a report.
)


# ---------------------------------------------------------------------------
# detect — ask whether the blue side noticed
#
# These run before an exercise to establish what telemetry exists, and after
# each red action to establish whether it fired. The 'after' call is what
# produces detection-gap findings, and it is also the verifier that labels red
# trajectories as correct or incorrect for training.
# ---------------------------------------------------------------------------

_v(
    id="detect.telemetry",
    summary="Which logging sources are actually enabled and reaching a collector.",
    intent=Intent.OBSERVE,
    side=Side.BLUE,
    target=_HOST,
    # Run this first, every time. A detection gap on a host with process
    # auditing switched off is not an interesting finding about detection
    # engineering; it is one finding about configuration, and reporting it as
    # forty missed techniques is noise that gets the whole report ignored.
)

_v(
    id="detect.process_creation",
    summary="Whether process-creation events were logged for a given time window and image name.",
    intent=Intent.OBSERVE,
    side=Side.BLUE,
    target=_HOST,
    params=(
        Param("since_seconds", "integer", "How far back to look.",
              required=False, default=300),
        Param("image", "string", "Process image name to match.", required=False),
    ),
    detects=("exploit.service_permissions", "exploit.unquoted_path",
             "postex.privilege_escalate"),
)

_v(
    id="detect.persistence_change",
    summary="Whether a new autostart entry was logged in the window.",
    intent=Intent.OBSERVE,
    side=Side.BLUE,
    target=_HOST,
    params=(
        Param("since_seconds", "integer", "How far back to look.",
              required=False, default=300),
    ),
    detects=("exploit.scheduled_task", "postex.persistence_install"),
)

_v(
    id="detect.credential_access",
    summary="Whether access to the credential store was logged in the window.",
    intent=Intent.OBSERVE,
    side=Side.BLUE,
    target=_HOST,
    params=(
        Param("since_seconds", "integer", "How far back to look.",
              required=False, default=300),
    ),
    detects=("postex.credential_dump",),
)

_v(
    id="detect.authentication",
    summary="Whether authentication events — including failures — were logged in the window.",
    intent=Intent.OBSERVE,
    side=Side.BLUE,
    target=_HOST,
    params=(
        Param("since_seconds", "integer", "How far back to look.",
              required=False, default=300),
    ),
    detects=("postex.lateral_move",),
)

_v(
    id="detect.rule",
    summary="Run a named detection rule against recent telemetry and report whether it fired.",
    intent=Intent.OBSERVE,
    side=Side.BLUE,
    target=_HOST,
    params=(
        Param("rule", "string", "Rule identifier, e.g. a Sigma rule id."),
        Param("since_seconds", "integer", "How far back to look.",
              required=False, default=300),
    ),
)


# ---------------------------------------------------------------------------
# exploit — prove the finding is real
#
# Red, EXECUTE, and every one of them names its detection. These are validated
# techniques against identified weaknesses, not a vulnerability-discovery
# engine: each takes a finding from the vuln.* group and demonstrates it.
# ---------------------------------------------------------------------------

_v(
    id="exploit.service_permissions",
    summary="Replace a writable service binary to obtain execution as the service account.",
    intent=Intent.EXECUTE,
    side=Side.RED,
    target=_HOST,
    attck=("T1574.010",),
    params=(
        Param("service", "string", "Service whose binary is writable."),
        Param("restore", "boolean", "Put the original binary back afterwards.",
              required=False, default=True),
    ),
    caution=(
        "Overwrites a service executable and restarts the service. The service "
        "is unavailable while it restarts, and if the restore step fails the "
        "original binary must be replaced by hand."
    ),
    detected_by=("detect.process_creation",),
)

_v(
    id="exploit.unquoted_path",
    summary="Plant a binary in an unquoted service path so it executes ahead of the intended target.",
    intent=Intent.EXECUTE,
    side=Side.RED,
    target=_HOST,
    attck=("T1574.009",),
    params=(
        Param("service", "string", "Service with the unquoted path."),
        Param("restore", "boolean", "Remove the planted binary afterwards.",
              required=False, default=True),
    ),
    caution=(
        "Writes an executable into a directory on a service's search path and "
        "restarts the service. Leaves a file on disk if restore fails."
    ),
    detected_by=("detect.process_creation",),
)

_v(
    id="exploit.scheduled_task",
    summary="Create a scheduled task or cron entry that runs as a more privileged account.",
    intent=Intent.EXECUTE,
    side=Side.RED,
    target=_HOST,
    attck=("T1053.003", "T1053.005"),
    params=(
        Param("as_user", "string", "Account the task should run as.",
              required=False, default="SYSTEM"),
        Param("cleanup", "boolean", "Delete the task once it has run.",
              required=False, default=True),
    ),
    caution=(
        "Creates a scheduled task or cron job. If cleanup fails the entry "
        "persists across reboots and must be removed by hand."
    ),
    detected_by=("detect.persistence_change", "detect.process_creation"),
)


# ---------------------------------------------------------------------------
# postex — what an adversary does once inside
# ---------------------------------------------------------------------------

_v(
    id="postex.credential_dump",
    summary="Read the platform credential store to demonstrate what an intruder would obtain.",
    intent=Intent.EXECUTE,
    side=Side.RED,
    target=_HOST,
    attck=("T1003",),
    params=(
        Param("redact", "boolean",
              "Report only counts and account names, never secret material.",
              required=False, default=True),
    ),
    caution=(
        "Reads the credential store. With redact=true — the default — the "
        "report names the accounts exposed and never records secret material. "
        "Setting redact=false writes recovered secrets into the audit log, "
        "which then has to be handled as a credential store in its own right."
    ),
    detected_by=("detect.credential_access",),
)

_v(
    id="postex.persistence_install",
    summary="Install an autostart entry to demonstrate survival across reboot.",
    intent=Intent.EXECUTE,
    side=Side.RED,
    target=_HOST,
    attck=("T1547.001", "T1543"),
    params=(
        Param("mechanism", "enum", "Which persistence mechanism to use.",
              choices=("autorun", "service", "cron", "launch_agent", "profile")),
        Param("cleanup", "boolean", "Remove the entry when the exercise ends.",
              required=False, default=True),
    ),
    caution=(
        "Installs something that runs without a human starting it. This is the "
        "verb most likely to leave a mess: if cleanup fails, the entry survives "
        "reboots. The audit log records exactly what was installed and where."
    ),
    detected_by=("detect.persistence_change",),
)

_v(
    id="postex.privilege_escalate",
    summary="Execute a previously identified privilege-escalation chain and confirm the result.",
    intent=Intent.EXECUTE,
    side=Side.RED,
    target=_HOST,
    attck=("T1068", "T1548"),
    params=(
        Param("chain", "string", "Identifier of the chain from vuln.privilege_path."),
    ),
    caution=(
        "Attempts to gain higher privilege by a route vuln.privilege_path "
        "already identified. Will not attempt a chain that verb did not find."
    ),
    detected_by=("detect.process_creation",),
)

_v(
    id="postex.lateral_move",
    summary="Authenticate to another in-scope host with obtained credentials and confirm access.",
    intent=Intent.EXECUTE,
    side=Side.RED,
    target=_HOST,
    attck=("T1021",),
    params=(
        Param("method", "enum", "Remote access method.",
              choices=("smb", "winrm", "ssh", "rdp")),
        Param("as_user", "string", "Account to authenticate as."),
    ),
    caution=(
        "Authenticates to a second machine. The destination is scope-checked "
        "independently of the host this runs from: reaching a machine from "
        "inside the network does not put it in scope."
    ),
    detected_by=("detect.authentication", "detect.process_creation"),
)

_v(
    id="postex.exfil_probe",
    summary="Test whether a measured volume of data can leave the network, without sending real data.",
    intent=Intent.EXECUTE,
    side=Side.RED,
    target=_HOST,
    attck=("T1041",),
    params=(
        Param("bytes", "integer", "Volume of synthetic data to attempt.",
              required=False, default=1048576),
        Param("sink", "host", "Collector to send to. Must be in scope."),
    ),
    caution=(
        "Sends synthetic, generated bytes — never file contents — to the named "
        "sink to measure whether egress controls notice the volume. The sink is "
        "scope-checked like any other host."
    ),
    detected_by=(NO_DETECTION,),
    # Honest: none of the detect.* verbs above covers egress volume. Naming the
    # sentinel rather than pointing at a vaguely-related detection keeps
    # `whet coverage` truthful, and puts a real item on the blue backlog.
)


# ---------------------------------------------------------------------------
# harden — fix what the exercise proved was broken
#
# The only MODIFY verbs in the catalogue, and the only ones the defending half
# owns. Each declares ``remediates``: the red verbs it closes. That field is how
# the kernel's remediation phase decides which fix belongs to which detection
# gap, so an omission here does not misfire — it makes the fix unreachable.
#
# Note what ``harden.enable_telemetry`` does *not* claim. It remediates every
# red verb whose detection depends on a log being written, and nothing else.
# ``postex.exfil_probe`` declares ``detect.nothing``: no control in this
# catalogue watches egress volume, so switching on a source cannot make one
# fire. Listing it would turn a genuine hole in the blue catalogue into a fix
# that "ran successfully" and changed nothing — the claimed-fixed failure the
# re-attack exists to catch, written into the schema where the re-attack cannot
# reach it.
# ---------------------------------------------------------------------------

_v(
    id="harden.enable_telemetry",
    summary="Turn on a logging source that detect.telemetry found missing.",
    intent=Intent.MODIFY,
    side=Side.BLUE,
    target=_HOST,
    params=(
        Param("source", "string", "Telemetry source to enable."),
    ),
    caution="Changes audit policy. Increases log volume, sometimes considerably.",
    remediates=("exploit.service_permissions", "exploit.unquoted_path",
                "exploit.scheduled_task", "postex.credential_dump",
                "postex.persistence_install", "postex.privilege_escalate",
                "postex.lateral_move"),
)

_v(
    id="harden.fix_permissions",
    summary="Tighten an ACL that vuln.weak_permissions flagged.",
    intent=Intent.MODIFY,
    side=Side.BLUE,
    target=_HOST,
    params=(
        Param("path", "path", "Object whose permissions to correct."),
    ),
    caution=(
        "Changes access control on a file or directory. The previous ACL is "
        "recorded in the audit log so it can be restored."
    ),
    # Both of these turn on a caller being able to write something it should
    # not: the service binary itself, or a directory earlier on an unquoted
    # search path. Removing the write removes the technique — which is a
    # different outcome from making it visible, and the remediation phase keeps
    # the two apart rather than calling either one "closed".
    remediates=("exploit.service_permissions", "exploit.unquoted_path"),
)

_v(
    id="harden.remove_persistence",
    summary="Remove an autostart entry — including one this tool installed.",
    intent=Intent.MODIFY,
    side=Side.BLUE,
    target=_HOST,
    params=(
        Param("entry", "string", "Entry identifier from enum.persistence."),
    ),
    caution=(
        "Deletes an autostart entry. Run enum.persistence first and confirm the "
        "entry is the one you mean — removing a legitimate one breaks software."
    ),
    remediates=("exploit.scheduled_task", "postex.persistence_install"),
)


# ---------------------------------------------------------------------------
# report — the deliverable
#
# TargetKind.NONE: these reach nothing, they assemble what has already been
# observed. They need no scope check because there is nothing to check.
# ---------------------------------------------------------------------------

_v(
    id="report.finding",
    summary="Record a validated finding: what was weak, how it was proven, what it allowed.",
    intent=Intent.OBSERVE,
    side=Side.NEUTRAL,
    target=_NONE,
    params=(
        Param("title", "string", "One line naming the weakness."),
        Param("severity", "enum", "Impact if exploited by a real adversary.",
              choices=("low", "medium", "high", "critical")),
        Param("evidence", "string", "Audit-log sequence numbers proving it."),
    ),
)

_v(
    id="report.detection_gap",
    summary="Record that a technique ran and no control noticed, with the telemetry that was missing.",
    intent=Intent.OBSERVE,
    side=Side.NEUTRAL,
    target=_NONE,
    params=(
        Param("technique", "string", "ATT&CK id that went unnoticed."),
        Param("expected", "string", "Detection verb that should have fired."),
        Param("missing_telemetry", "string", "Log source that would have caught it.",
              required=False),
    ),
    # The highest-value output this tool produces. An exploit proves a hole
    # exists; this proves nobody would have known. Defenders act on the second
    # one far faster than the first, and it is the artefact that justifies the
    # red half of the catalogue existing at all.
)


REGISTRY.freeze()
