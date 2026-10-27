#!/usr/bin/env python3
"""Produce (command, real output, machine-checked parse) triples in a Linux VM.

Run this when you mean to. It boots nothing and downloads nothing, but it
*does* change a virtual machine: it creates accounts, sets the hostname, plants
a sudoers drop-in, a setuid copy of ``id``, a cron drop-in, a systemd unit and
an auditd watch rule — and then removes every one of them and asks the machine
again to prove they are gone.

    python3 scripts/generate_output_pairs.py --out data/corpus/raw/outputpairs
    python3 scripts/generate_output_pairs.py --revert-only      # after a crash
    python3 scripts/generate_output_pairs.py --dry-run          # catalogue only

Why a VM at all. The corpus's TRAJECTORY register was measured at 20.64%
this-one-machine: 253 distinct literals repeated a mean 947 times each, ~89% of
which appear nowhere else in 625 MB. That is one Mac's service list memorised,
not a reading skill. The ROADMAP names the fix — "how a macOS laptop produces
genuinely *Linux* trajectories rather than trajectories labelled Linux" — and
output captured inside a disposable VM closes the privacy problem and the
generalisation problem with one move, because the operator's identifiers were
never in the VM to begin with.

Except one, and it is the whole reason this script has a substitution pass:
**Lima names the guest user after the host user.** On this machine ``id`` in the
VM prints the operator's macOS account name, and so do ``getent passwd``, the
home path, ``ps``, and 1,251 ``UID="..."`` fields in ``audit.log``. The
replacement is varied rather than a single token, because the audit's sharpest
finding was that privacy is satisfied by *any* substitution while
generalisation needs a *varied* one — a single ``<HOST>`` passes every gate here
and makes the model worse.

**Three rules this script obeys, borrowed from momus/range/plant.py, which
earned them.**

*Own your namespace.* Everything created is under :data:`PLANT_ROOT`, named
``*wsp*``, or an account from ``outputpairs.ACCOUNT_POOL``. Nothing else is
touched. The hostname is the one exception and it is saved and restored.

*Never clobber.* :func:`audit_baseline` refuses to plant if any of those
already exists with content this script did not write. A run that overwrote
somebody's file would have destroyed the baseline it was measuring against.

*Verify by re-probing.* A plant is not "the commands exited zero" and a revert
is not "the rm exited zero". Both ask the machine afterwards and raise if the
answer is wrong.

**The label is machine-produced, never hand-written.** Labels come from the
sibling attacker's pure parsers (``momus.adapters.lima``) where one exists —
the same code the runtime uses, so a document's label is wrong only if the
runtime is also wrong — and from this project's own
``whetstone.adapters.linux`` parsers elsewhere. Where both exist, **both run on
the same bytes and must agree**; a disagreement means one of them is wrong, we
do not know which, and the document is dropped and the disagreement reported.
A corpus that shipped the winner of a coin flip as ground truth would be worse
than one that shipped nothing.

**What this script does not collect.** No ``--help`` or usage output, no man
pages, no ``dpkg -l`` Description column, no bodies of package-shipped config
files. Those are the programs' own copyrighted text; this corpus already holds
the first two under their real licences. See ``outputpairs.SPEC.license``.

And no payloads. The planted sudo rule exists so that ``sudo -n -l`` has a real
enumerated form to print; the document shows the rule and the parse and stops
there. The escape is in ``gtfobins``, where a catalogue belongs: the catalogue
holds the code, the model holds the judgement.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from training.corpus.sources import outputpairs as fmt  # noqa: E402
from training.corpus.verify import host_needles, scan_text  # noqa: E402
from whetstone.adapters import linux as wlinux  # noqa: E402
from whetstone.paths import lima_home  # noqa: E402

# --------------------------------------------------------------------------
# The sibling project's parsers.
#
# Imported by path rather than vendored, so the label this script writes is
# produced by the identical function the Momus runtime calls. A vendored copy
# would drift, and the drift would be invisible: the corpus would keep training
# the model on the behaviour of a parser nothing runs any more.
#
# Absence is a hard failure and not a degrade. "Generated without the
# cross-check" is exactly the kind of quietly-weaker artifact this project has
# been bitten by -- a redactor that was added and never run looks identical
# from the source tree to one that ran and found nothing.
# --------------------------------------------------------------------------
_MOMUS_DEFAULT = _REPO.parent / "Momus"


def load_momus(root: Path):
    """Import ``momus.adapters.lima`` from *root*. Raises if it is not there."""
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    try:
        import momus.adapters.lima as lima  # type: ignore
    except Exception as exc:  # pragma: no cover - environment dependent
        raise SystemExit(
            f"cannot import momus.adapters.lima from {root}: "
            f"{type(exc).__name__}: {exc}\n"
            "The labels in this corpus are produced by the runtime's own "
            "parsers. Point --momus at the Momus checkout, or do not generate."
        ) from None
    return lima


# --------------------------------------------------------------------------
# Namespace
# --------------------------------------------------------------------------

#: Shapes that must never reach a document, whatever probe produced them.
#:
#: Belt over braces. Nothing in the catalogue reads a key or a hash: the
#: root-only probes are metadata reads (``ls -l``, ``stat``) so that a
#: misconfiguration which let one *succeed* yields modes and owners rather than
#: content, and the two ``cat`` probes aimed at root-only files exist to
#: capture the refusal. But "the probe cannot produce it" is an argument, and
#: this project's record on arguments about redaction is poor -- ``ownrepos``
#: grew a redactor that was correct and had never run. So the bytes are checked
#: instead, and a capture that carries one of these is refused and counted.
#:
#: ``$y$`` is yescrypt, Ubuntu 24.04's default; the rest are the crypt(3) ids
#: and the PEM header a private key opens with.
_REFUSED_CONTENT = ("$y$", "$6$", "$5$", "$2b$", "$1$", "-----BEGIN ")

PLANT_ROOT = "/opt/whetstone-pairs"
MARKER = f"{PLANT_ROOT}/.wsp-owned"
MARKER_TEXT = "whetstone output-pairs generator; safe to delete\n"

SUDOERS_DROPIN = "/etc/sudoers.d/60-wsp-rules"
CRON_DROPIN = "/etc/cron.d/60-wsp-maint"
UNIT_PATH = "/etc/systemd/system/wsp-agent.service"
TIMER_PATH = "/etc/systemd/system/wsp-agent.timer"
UNIT_SCRIPT = f"{PLANT_ROOT}/wsp-agent.sh"
SUID_ID = f"{PLANT_ROOT}/wsp-suid-id"
AUDIT_KEY = "wsp_watch"
WATCHED_FILE = f"{PLANT_ROOT}/watched.conf"
SPACE_DIR = f"{PLANT_ROOT}/app logs"
SPACE_FILE = f"{SPACE_DIR}/old report.txt"

#: Paths the plant creates, in the order a revert must remove them.
PLANTED_PATHS = (SUDOERS_DROPIN, CRON_DROPIN, UNIT_PATH, TIMER_PATH, PLANT_ROOT)

#: Accounts this run creates. A subset of the pool, so a second concurrent run
#: against a second VM is not forced to use identical names.
PROBE_ACCOUNTS = fmt.ACCOUNT_POOL[:6]


# --------------------------------------------------------------------------
# Transport
# --------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Capture:
    """What one command did. Verbatim, both streams, and the exit status."""

    argv: tuple[str, ...]
    stdout: str
    stderr: str
    exit_code: int
    seconds: float

    @property
    def timed_out(self) -> bool:
        """``-1`` is never a real exit code; it is the synthesised one.

        The same convention ``whetstone.adapters.linux.run`` uses, so a
        transport timeout here reads to a downstream consumer exactly as a
        transport timeout does at runtime.
        """
        return self.exit_code == -1

    @property
    def empty(self) -> bool:
        return not self.stdout.strip()


class VM:
    """``limactl shell`` with an argv list. No shell on either side.

    A parameter is a single argv entry to ``limactl``, never a fragment of a
    command line the VM's shell parses. The one unavoidable exception is a file
    write, which goes through ``tee`` reading stdin -- the payload never
    appears on a command line at all, which is stronger than quoting it.
    """

    def __init__(self, name: str, lima_home: str, *, default_timeout: int = 30):
        self.name = name
        self.lima_home = lima_home
        self.default_timeout = default_timeout
        self.calls = 0
        if shutil.which("limactl") is None:
            raise SystemExit("limactl not found; is Lima installed?")

    def _env(self) -> dict[str, str]:
        return {**os.environ, "LIMA_HOME": self.lima_home}

    def run(self, argv: Sequence[str], *, timeout: int | None = None,
            stdin: str | None = None) -> Capture:
        """One command. A finite timeout is mandatory, never optional.

        ``base.run()`` states the rule for the whole runtime and the reason is
        that a blocked ``subprocess.run`` never *raises*: a half-open Lima SSH
        control connection after a macOS wake is the ordinary way a generator
        wedges forever with no output and no diagnostic.
        """
        budget = self.default_timeout if timeout is None else timeout
        full = ["limactl", "shell", "--workdir", "/", self.name, "--", *argv]
        self.calls += 1
        start = time.monotonic()
        try:
            proc = subprocess.run(full, input=stdin, capture_output=True,
                                  text=True, timeout=budget, env=self._env(),
                                  errors="replace")
        except subprocess.TimeoutExpired:
            return Capture(tuple(argv), "", f"timed out after {budget}s", -1,
                           time.monotonic() - start)
        return Capture(tuple(argv), proc.stdout, proc.stderr, proc.returncode,
                       time.monotonic() - start)

    def sudo(self, argv: Sequence[str], **kw) -> Capture:
        """Run as root. ``-n`` so a missing rule fails instead of prompting."""
        return self.run(["sudo", "-n", *argv], **kw)

    def as_user(self, user: str, argv: Sequence[str], **kw) -> Capture:
        """Run as *user*, via root. The captured argv is what was really run."""
        return self.run(["sudo", "-n", "-u", user, "--", *argv], **kw)

    def must(self, argv: Sequence[str], **kw) -> Capture:
        """A plant step. Non-zero means the plant did not happen; raise."""
        cap = self.sudo(argv, **kw)
        if cap.exit_code != 0:
            raise RuntimeError(
                f"plant step failed: {' '.join(argv)!r} exited "
                f"{cap.exit_code}: {cap.stderr.strip()[:200]}")
        return cap

    def write_file(self, path: str, body: str, *, mode: str = "0644") -> None:
        """Write *body* to *path* as root, then chmod. Payload via stdin."""
        cap = self.run(["sudo", "-n", "tee", path], stdin=body)
        if cap.exit_code != 0:
            raise RuntimeError(f"write {path} failed: {cap.stderr.strip()[:200]}")
        self.must(["chmod", mode, path])

    def exists(self, path: str) -> bool:
        return self.sudo(["test", "-e", path]).exit_code == 0

    def read_file(self, path: str) -> str:
        cap = self.sudo(["cat", path])
        return cap.stdout if cap.exit_code == 0 else ""


# --------------------------------------------------------------------------
# Baseline audit, plant, revert
# --------------------------------------------------------------------------

def audit_baseline(vm: VM) -> None:
    """Refuse to touch a machine that is not in the state we expect.

    Two different failures hide here. A leftover plant from a crashed run is
    recoverable and says so (``--revert-only``). A path in our namespace that we
    did not write, or an account name we were about to create that already
    exists, is **somebody else's**, and planting over it would destroy the
    baseline another measurement depends on.
    """
    if vm.run(["true"], timeout=20).exit_code != 0:
        raise SystemExit(
            f"VM {vm.name!r} is not reachable. Start it:\n"
            f"  LIMA_HOME={vm.lima_home} limactl start {vm.name}")

    ours = vm.exists(PLANT_ROOT) and MARKER_TEXT in vm.read_file(MARKER)
    if vm.exists(PLANT_ROOT) and not ours:
        raise SystemExit(
            f"{PLANT_ROOT} exists on {vm.name} and does not carry this "
            f"generator's marker. Refusing to plant over content this script "
            "did not write.")
    if ours:
        print(f"  note: leftover plant found under {PLANT_ROOT}; reverting first")
        revert(vm, restore_hostname=None)

    for path in (SUDOERS_DROPIN, CRON_DROPIN, UNIT_PATH, TIMER_PATH):
        if vm.exists(path):
            raise SystemExit(f"{path} already exists on {vm.name}; refusing to clobber")
    for account in PROBE_ACCOUNTS:
        if vm.run(["getent", "passwd", account]).exit_code == 0:
            raise SystemExit(
                f"account {account!r} already exists on {vm.name}. This script "
                "creates and deletes it; refusing to adopt an account it did "
                "not make.")


def revert(vm: VM, *, restore_hostname: str | None) -> list[str]:
    """Remove everything, then prove it is gone. Returns re-probe findings.

    Ordered so that the thing which *runs* is stopped before the thing it runs
    is deleted: a timer left enabled after its script is removed writes a
    failure into the journal of a machine somebody else is measuring.
    """
    vm.sudo(["systemctl", "disable", "--now", "wsp-agent.timer"], timeout=60)
    vm.sudo(["systemctl", "stop", "wsp-agent.service"], timeout=60)
    vm.sudo(["rm", "-f", UNIT_PATH, TIMER_PATH])
    vm.sudo(["systemctl", "daemon-reload"], timeout=60)
    vm.sudo(["auditctl", "-W", WATCHED_FILE, "-p", "wa", "-k", AUDIT_KEY], timeout=30)
    vm.sudo(["rm", "-f", SUDOERS_DROPIN, CRON_DROPIN])
    for account in PROBE_ACCOUNTS:
        vm.sudo(["crontab", "-r", "-u", account], timeout=30)
        vm.sudo(["userdel", "-r", account], timeout=60)
    vm.sudo(["rm", "-rf", PLANT_ROOT])
    if restore_hostname:
        vm.sudo(["hostnamectl", "set-hostname", restore_hostname], timeout=30)

    # Verify by re-probing. "rm exited zero" is not evidence; ask the machine.
    findings: list[str] = []
    for path in PLANTED_PATHS:
        if vm.exists(path):
            findings.append(f"still present: {path}")
    for account in PROBE_ACCOUNTS:
        if vm.run(["getent", "passwd", account]).exit_code == 0:
            findings.append(f"account still present: {account}")
    units = vm.sudo(["systemctl", "list-unit-files", "--no-legend", "--plain",
                     "wsp-agent.*"], timeout=60)
    if "wsp-agent" in units.stdout:
        findings.append("wsp-agent unit files still known to systemd")
    rules = vm.sudo(["auditctl", "-l"], timeout=30)
    if AUDIT_KEY in rules.stdout:
        findings.append(f"audit rule {AUDIT_KEY} still loaded")
    if restore_hostname:
        now = vm.run(["hostname"]).stdout.strip()
        if now != restore_hostname:
            findings.append(f"hostname is {now!r}, expected {restore_hostname!r}")
    return findings


@dataclass
class Plant:
    """One cumulative state of the machine, and how to reach it."""

    name: str
    hostname: str
    apply: Callable[[VM], None]
    verify: Callable[[VM], list[str]]


def _plant_root(vm: VM) -> None:
    vm.must(["mkdir", "-p", PLANT_ROOT])
    vm.write_file(MARKER, MARKER_TEXT, mode="0644")


def _plant_accounts(vm: VM) -> None:
    for account in PROBE_ACCOUNTS:
        vm.must(["useradd", "-m", "-s", "/bin/bash", account], timeout=60)


def _plant_sudo(vm: VM) -> None:
    """One narrow rule per account, never ``(ALL) NOPASSWD: ALL``.

    ``(ALL) NOPASSWD: ALL`` is not a scenario, it is a root shell with extra
    steps -- momus/range/plant.py's argument, and it applies to training data
    too: a corpus whose every enumerated ``sudo -l`` says ``ALL`` teaches that
    the interesting case is the only case. These are the shapes a real box
    has: one binary, two binaries, a wildcard, a runas-other-user rule, a
    PASSWD rule that ``-n`` can never use, and one account with no rule at all.
    """
    lines = [
        f"{PROBE_ACCOUNTS[0]} ALL=(ALL) NOPASSWD: /usr/bin/find",
        f"{PROBE_ACCOUNTS[1]} ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart wsp-agent.service",
        f"{PROBE_ACCOUNTS[1]} ALL=(ALL) PASSWD: /usr/bin/journalctl",
        f"{PROBE_ACCOUNTS[2]} ALL=(ALL) PASSWD: ALL",
        f"{PROBE_ACCOUNTS[3]} ALL=({PROBE_ACCOUNTS[4]}) NOPASSWD: /usr/bin/id",
        f"{PROBE_ACCOUNTS[4]} ALL=(ALL) NOPASSWD: /usr/bin/stat, /usr/bin/getcap",
        # PROBE_ACCOUNTS[5] deliberately has no rule: the "could not tell"
        # case, which on this image is byte-identical to the PASSWD case.
    ]
    vm.write_file(SUDOERS_DROPIN, "\n".join(lines) + "\n", mode="0440")


def _plant_files(vm: VM) -> None:
    """Odd modes, a setuid binary, and two paths with spaces in them.

    The setuid binary is a copy of ``id`` and the choice is deliberate. It
    produces the exact output the ``euid`` trap is about -- ``uid=1000(svcops)
    ... euid=0(root)``, where a parser reading only ``uid=`` calls a successful
    escape a failure -- and ``id`` cannot execute anything, so unlike every
    binary GTFOBins lists for this it is inert. Real output, zero payload.
    """
    vm.must(["mkdir", "-p", SPACE_DIR])
    vm.write_file(SPACE_FILE, "placeholder\n", mode="0666")
    vm.write_file(WATCHED_FILE, "key = value\n", mode="0644")
    vm.must(["cp", "/usr/bin/id", SUID_ID])
    vm.must(["chmod", "4755", SUID_ID])
    for name, mode in (("sticky-dir", "1777"), ("setgid-dir", "2775"),
                       ("no-perms", "0000"), ("world-writable", "0777"),
                       ("exec-only", "0111")):
        target = f"{PLANT_ROOT}/{name}"
        if name.endswith("-dir"):
            vm.must(["mkdir", "-p", target])
        else:
            vm.write_file(target, f"{name}\n", mode="0644")
        vm.must(["chmod", mode, target])
    vm.must(["ln", "-sfn", "/etc/os-release", f"{PLANT_ROOT}/link-to-os-release"])
    vm.must(["ln", "-sfn", "/nonexistent/target", f"{PLANT_ROOT}/broken-link"])


def _plant_caps(vm: VM) -> None:
    vm.must(["cp", "/usr/bin/cat", f"{PLANT_ROOT}/wsp-cat"])
    vm.must(["setcap", "cap_dac_read_search+ep", f"{PLANT_ROOT}/wsp-cat"])


def _plant_cron(vm: VM) -> None:
    vm.write_file(f"{PLANT_ROOT}/maint.sh", "#!/bin/sh\n:\n", mode="0775")
    vm.write_file(CRON_DROPIN,
                  "SHELL=/bin/sh\n"
                  "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
                  f"*/7 * * * * root {PLANT_ROOT}/maint.sh\n"
                  f"@reboot {PROBE_ACCOUNTS[0]} /usr/bin/true\n"
                  "17 3 * * 1-5 root /usr/bin/find /tmp -mtime +7 -delete\n",
                  mode="0644")
    # A per-account crontab has no user field; reading one as if it did
    # attributes every job to the wrong account. Both shapes are wanted.
    user_cron = ("# account crontab\n"
                 "*/11 * * * * /usr/bin/true\n"
                 "@daily /usr/bin/stat /etc/os-release\n")
    cap = vm.run(["sudo", "-n", "crontab", "-u", PROBE_ACCOUNTS[0], "-"],
                 stdin=user_cron)
    if cap.exit_code != 0:
        raise RuntimeError(f"crontab install failed: {cap.stderr.strip()[:200]}")


def _plant_service(vm: VM) -> None:
    vm.write_file(UNIT_SCRIPT, "#!/bin/sh\n:\n", mode="0777")
    vm.write_file(UNIT_PATH,
                  "[Unit]\nDescription=whetstone output-pairs probe target\n\n"
                  "[Service]\nType=oneshot\n"
                  f"ExecStart={UNIT_SCRIPT}\n\n"
                  "[Install]\nWantedBy=multi-user.target\n", mode="0644")
    vm.write_file(TIMER_PATH,
                  "[Unit]\nDescription=whetstone output-pairs probe timer\n\n"
                  "[Timer]\nOnBootSec=30s\nOnUnitActiveSec=45s\n\n"
                  "[Install]\nWantedBy=timers.target\n", mode="0644")
    vm.must(["systemctl", "daemon-reload"], timeout=60)
    vm.must(["systemctl", "enable", "--now", "wsp-agent.timer"], timeout=60)
    vm.sudo(["systemctl", "start", "wsp-agent.service"], timeout=60)


def _plant_audit(vm: VM) -> None:
    vm.must(["auditctl", "-w", WATCHED_FILE, "-p", "wa", "-k", AUDIT_KEY],
            timeout=30)
    # Make the watch fire, so audit.log has records with our key in it. Without
    # this the armed state and the unarmed state produce identical output and
    # the corpus would teach that arming a control changes nothing.
    vm.write_file(WATCHED_FILE, "key = value\nchanged = yes\n", mode="0644")
    time.sleep(1.5)


def _verify_nothing(vm: VM) -> list[str]:
    return []


def _verify_accounts(vm: VM) -> list[str]:
    missing = [a for a in PROBE_ACCOUNTS
               if vm.run(["getent", "passwd", a]).exit_code != 0]
    return [f"account missing after plant: {a}" for a in missing]


def _verify_sudo(vm: VM) -> list[str]:
    """Ask from the account where it matters, not from root.

    Root can read the sudoers drop-in whatever its contents say. The claim
    being planted is "this account may run find without a password", and the
    only probe that tests that claim is the account's own ``sudo -n -l``.
    """
    cap = vm.as_user(PROBE_ACCOUNTS[0], ["sudo", "-n", "-l"])
    if "NOPASSWD: /usr/bin/find" not in cap.stdout:
        return [f"sudo rule for {PROBE_ACCOUNTS[0]} did not take effect"]
    return []


def _verify_files(vm: VM) -> list[str]:
    cap = vm.as_user(PROBE_ACCOUNTS[0], [SUID_ID])
    if "euid=0" not in cap.stdout:
        return ["setuid copy of id did not run with euid 0"]
    if not vm.exists(SPACE_FILE):
        return [f"missing: {SPACE_FILE}"]
    return []


def _verify_caps(vm: VM) -> list[str]:
    cap = vm.sudo(["getcap", f"{PLANT_ROOT}/wsp-cat"])
    if "cap_dac_read_search" not in cap.stdout:
        return ["file capability did not take effect"]
    return []


def _verify_cron(vm: VM) -> list[str]:
    if not vm.exists(CRON_DROPIN):
        return [f"missing: {CRON_DROPIN}"]
    cap = vm.sudo(["crontab", "-l", "-u", PROBE_ACCOUNTS[0]])
    if "*/11" not in cap.stdout:
        return [f"per-account crontab for {PROBE_ACCOUNTS[0]} not installed"]
    return []


def _verify_service(vm: VM) -> list[str]:
    cap = vm.sudo(["systemctl", "show", "--property=FragmentPath,ExecStart",
                   "wsp-agent.service"], timeout=60)
    if UNIT_SCRIPT not in cap.stdout:
        return ["wsp-agent.service does not declare its ExecStart"]
    return []


def _verify_audit(vm: VM) -> list[str]:
    cap = vm.sudo(["auditctl", "-l"], timeout=30)
    if AUDIT_KEY not in cap.stdout:
        return [f"audit rule {AUDIT_KEY} not loaded"]
    return []


def plant_sequence() -> list[Plant]:
    """The states, cumulative, each with a different hostname.

    Cumulative on purpose: a single pristine VM yields one service list, and
    the corpus would teach *this VM's* service list rather than how to read
    one. The hostname changes with each state because changing it genuinely is
    better than substituting it afterwards -- no length constraint, no
    half-rewritten record, and the output is what the machine actually said.

    The last state is the interesting one. Everything is removed and the same
    probes run again, so the corpus carries the matched pair: the identical
    command, once against a machine where the thing is there, once against a
    machine where it is not. That pair is the only way a model learns that
    empty output with exit 0 means *nothing there* rather than *I could not
    look* -- and the revert that produces it is the same revert that leaves the
    VM as it was found, verified by re-probe either way.
    """
    hosts = fmt.HOSTNAME_POOL
    return [
        Plant("pristine", hosts[0], _plant_root, _verify_nothing),
        Plant("accounts", hosts[1], _plant_accounts, _verify_accounts),
        Plant("sudo-rules", hosts[2], _plant_sudo, _verify_sudo),
        Plant("odd-modes", hosts[3], _plant_files, _verify_files),
        Plant("capabilities", hosts[4], _plant_caps, _verify_caps),
        Plant("cron", hosts[5], _plant_cron, _verify_cron),
        Plant("service-timer", hosts[6], _plant_service, _verify_service),
        Plant("audit-armed", hosts[7], _plant_audit, _verify_audit),
    ]


# --------------------------------------------------------------------------
# Labels
#
# A label function receives the Capture and returns
# (parser name, parse object, verdict). It may raise Disagreement, which drops
# the document and records a finding.
# --------------------------------------------------------------------------

class Disagreement(Exception):
    """Two parsers read the same bytes differently, so neither is ground truth."""


@dataclass(frozen=True)
class Label:
    parser: str
    parse: Any
    verdict: str
    #: A short clause restating *one field of the parse*, appended to the
    #: reading.
    #:
    #: It exists for two reasons that turned out to be the same reason. A
    #: reading authored per verdict is identical in every document that reaches
    #: that verdict -- the generic "found" sentence appeared in 474 of 1,018
    #: documents -- and a sentence repeated verbatim 474 times is furniture by
    #: this corpus's own definition, which ``boilerplate.py`` duly stripped. It
    #: was also uninformative, which is why it was repeatable. A clause naming
    #: the field that decided the verdict is specific to the document and tells
    #: the reader which bytes mattered.
    #:
    #: Mechanical, never interpretive: it restates a value the parse already
    #: holds. It can therefore only be wrong if the parse is wrong, which is the
    #: inheritance the module docstring states, and which the cross-checks and
    #: the Disagreement drop exist to bound.
    detail: str = ""


def _momus_name(fn: Callable) -> str:
    return f"momus.adapters.lima.{fn.__name__}"


def _whet_name(fn: Callable) -> str:
    return f"whetstone.adapters.linux.{fn.__name__}"


class Labels:
    """Label functions, bound to the imported parser modules.

    A class rather than module-level functions purely so the Momus module is a
    constructor argument: the import is checked once, at startup, instead of
    every label silently falling back to a hand-written guess if it failed.
    """

    def __init__(self, lima, whet):
        self.lima = lima
        self.whet = whet

    # -- identity ---------------------------------------------------------

    def identity(self, cap: Capture) -> Label:
        """Is this process effectively root?

        ``id`` prints ``euid=`` **only when it differs from uid**, which is
        exactly the setuid case, so a parser reading ``uid=`` and stopping
        reports a successful escape as a failure. Both parsers are asked and
        must agree on the effective id; this is the single most consequential
        cross-check in the catalogue.
        """
        if cap.timed_out or cap.exit_code != 0 and not cap.stdout.strip():
            return Label(_momus_name(self.lima._parse_id), None, "inconclusive")
        mine = self.lima._parse_id(cap.stdout)
        if mine is None:
            return Label(_momus_name(self.lima._parse_id), None, "inconclusive")
        theirs = self.whet.parse_id(cap.stdout)
        their_euid = theirs.get("euid", theirs.get("uid", {})).get("id")
        if their_euid != mine["euid"]:
            raise Disagreement(
                f"effective uid: momus={mine['euid']} whetstone={their_euid}")
        their_groups = [g["name"] for g in theirs.get("groups", [])]
        if sorted(their_groups) != sorted(mine["groups"]):
            raise Disagreement(
                f"group list: momus={sorted(mine['groups'])} "
                f"whetstone={sorted(their_groups)}")
        return Label(_momus_name(self.lima._parse_id), mine,
                     "found" if mine["euid"] == 0 else "absent",
                     detail=f"uid={mine['uid']}, euid={mine['euid']}.")

    # -- sudo -------------------------------------------------------------

    def sudo_rights(self, cap: Capture) -> Label:
        """Can this account run something as root with no password?

        ``_parse_sudo_l`` takes **both streams** because the refusal arrives on
        stderr, and ``enumerated`` is the field that matters: ``sudo: a
        password is required`` is an unfinished enumeration, not a statement
        that no NOPASSWD rule exists. Measured on this image, an account with a
        PASSWD rule and an account with **no rules at all** produce that same
        message, so the output genuinely cannot separate them.

        ``whetstone.adapters.linux.parse_sudo_l`` is cross-checked only when
        Momus says the enumeration finished. That is its documented contract --
        its caller branches on the exit status first and never hands it refusal
        bytes -- and calling it on a refusal returns an empty entry list, which
        would read as a confident "no passwordless rule" if anything believed
        it. Not a bug in the parser; a bug waiting for whoever calls it without
        reading its caller.
        """
        rights = self.lima._parse_sudo_l(cap.stdout, cap.stderr)
        parse = {"enumerated": rights.enumerated,
                 "nopasswd": list(rights.nopasswd),
                 "all_commands": rights.all_commands,
                 "passwordless_root": rights.passwordless_root}
        if not rights.enumerated:
            return Label(_momus_name(self.lima._parse_sudo_l), parse,
                         "inconclusive")
        theirs = self.whet.parse_sudo_l(cap.stdout)
        if bool(theirs["nopasswd_any"]) != bool(rights.passwordless_root):
            raise Disagreement(
                f"passwordless: momus={rights.passwordless_root} "
                f"whetstone={theirs['nopasswd_any']}")
        return Label(
            _momus_name(self.lima._parse_sudo_l), parse,
            "found" if rights.passwordless_root else "absent",
            detail=("all_commands=true." if rights.all_commands
                    else f"{len(rights.nopasswd)} NOPASSWD rule(s): "
                         f"{', '.join(rights.nopasswd) or 'none'}."))

    # -- files ------------------------------------------------------------

    def suid_sweep(self, cap: Capture) -> Label:
        """Which setuid binaries are reachable from here?

        ``find`` exits 1 having printed every match it *could* reach when a
        directory refuses it, which is a partial answer and not a failure; and
        it exits 0 with no output when it looked everywhere and found nothing,
        which is a complete negative. Those two are the reason this source
        exists, so the verdict separates them explicitly.
        """
        entries = self.lima._parse_suid(cap.stdout)
        parse = [{"mode": e.mode, "owner": e.owner, "group": e.group,
                  "path": e.path} for e in entries]
        if cap.timed_out:
            return Label(_momus_name(self.lima._parse_suid), parse, "inconclusive")
        if entries:
            return Label(_momus_name(self.lima._parse_suid), parse, "found")
        if cap.exit_code != 0:
            return Label(_momus_name(self.lima._parse_suid), parse, "inconclusive")
        return Label(_momus_name(self.lima._parse_suid), parse, "absent")

    def find_long(self, cap: Capture) -> Label:
        """``find -printf '%M %u %g %p\\n'`` rows.

        A path may contain spaces. ``str.split()`` on such a row silently
        truncates the filename to its first word, so the parse splits three
        times from the left and keeps the remainder. The plant deliberately
        creates ``app logs/old report.txt`` so this is tested against bytes and
        not against an argument.
        """
        entries = self.lima._parse_find_long(cap.stdout)
        parse = [{"mode": e.mode, "owner": e.owner, "group": e.group,
                  "path": e.path} for e in entries]
        if cap.timed_out:
            return Label(_momus_name(self.lima._parse_find_long), parse,
                         "inconclusive")
        rows = [ln for ln in cap.stdout.splitlines() if ln.strip()]
        if len(parse) != len(rows):
            raise Disagreement(
                f"{len(rows)} printed rows parsed as {len(parse)} entries")
        if entries:
            return Label(_momus_name(self.lima._parse_find_long), parse, "found")
        if cap.exit_code != 0:
            return Label(_momus_name(self.lima._parse_find_long), parse,
                         "inconclusive")
        return Label(_momus_name(self.lima._parse_find_long), parse, "absent")

    def paths(self, cap: Capture) -> Label:
        out = self.lima._parse_paths(cap.stdout)
        parse = {"count": len(out), "paths": list(out[:60])}
        if cap.timed_out:
            return Label(_momus_name(self.lima._parse_paths), parse, "inconclusive")
        if out:
            return Label(_momus_name(self.lima._parse_paths), parse, "found")
        verdict = "absent" if cap.exit_code == 0 else "inconclusive"
        return Label(_momus_name(self.lima._parse_paths), parse, verdict)

    def getcap(self, cap: Capture) -> Label:
        out = self.lima._parse_getcap(cap.stdout)
        parse = [dict(row) for row in out]
        if cap.timed_out:
            return Label(_momus_name(self.lima._parse_getcap), parse, "inconclusive")
        if out:
            return Label(_momus_name(self.lima._parse_getcap), parse, "found")
        verdict = "absent" if cap.exit_code == 0 else "inconclusive"
        return Label(_momus_name(self.lima._parse_getcap), parse, verdict)

    # -- services ---------------------------------------------------------

    def unit_exists(self, cap: Capture) -> Label:
        """Does this unit exist?

        ``systemctl show nosuch.service`` exits **0** and prints
        ``Id=nosuch.service`` with ``FragmentPath=`` empty. A caller reading the
        exit status concludes the unit exists; the only evidence that it does
        not is an empty ``FragmentPath``. Both parsers must agree on the record
        count, because the records are blank-line separated and an
        off-by-one there mis-attributes every property on the box.
        """
        records = self.lima._parse_systemctl_show(cap.stdout)
        theirs = self.whet.parse_systemctl_show(cap.stdout)
        if len(theirs) != len(records):
            raise Disagreement(
                f"record count: momus={len(records)} whetstone={len(theirs)}")
        parse = [{"id": r.get("Id", ""), "fragment_path": r.get("FragmentPath", ""),
                  "exists": bool(r.get("FragmentPath"))} for r in records]
        if cap.timed_out:
            return Label(_momus_name(self.lima._parse_systemctl_show), parse,
                         "inconclusive")
        if not records:
            return Label(_momus_name(self.lima._parse_systemctl_show), parse,
                         "inconclusive")
        names = ", ".join(p["id"] for p in parse if p["id"])[:120]
        present = sum(1 for p in parse if p["exists"])
        detail = f"{present} of {len(parse)} present: {names}."
        if present:
            return Label(_momus_name(self.lima._parse_systemctl_show), parse,
                         "found", detail=detail)
        return Label(_momus_name(self.lima._parse_systemctl_show), parse,
                     "absent", detail=detail)

    def unit_execstart(self, cap: Capture) -> Label:
        """What binary does this unit execute?

        ``systemctl show`` returns properties in **its own order**, not the
        order asked for, and omits ``ExecStart`` entirely for a unit that has
        none. Measured on this image, asking for ``Id,ExecStart,FragmentPath``
        on ``cron.service`` returns ExecStart, Id, ActiveState, FragmentPath.
        A parser reading field one as the id mis-attributes every record.

        The binary comes from ``path=`` inside the brace record, not from
        ``argv[]``: argv carries ``$EXTRA_OPTS`` unexpanded, and the file
        systemd will execute is the one that matters.
        """
        records = self.lima._parse_systemctl_show(cap.stdout)
        parse = []
        for rec in records:
            exec_raw = rec.get("ExecStart", "")
            parse.append({
                "id": rec.get("Id", ""),
                "exists": bool(rec.get("FragmentPath")),
                "declares_execstart": "ExecStart" in rec,
                "program": self.lima._parse_execstart(exec_raw) if exec_raw else "",
            })
        if cap.timed_out or not records:
            return Label(_momus_name(self.lima._parse_execstart), parse,
                         "inconclusive")
        programs = [p["program"] for p in parse if p["program"]]
        if programs:
            return Label(_momus_name(self.lima._parse_execstart), parse, "found",
                         detail="ExecStart path(s): "
                                + ", ".join(programs)[:140] + ".")
        if any(p["exists"] for p in parse):
            return Label(_momus_name(self.lima._parse_execstart), parse, "absent",
                         detail="the unit(s) exist and declare no ExecStart.")
        return Label(_momus_name(self.lima._parse_execstart), parse, "inconclusive")

    def unit_files(self, cap: Capture) -> Label:
        """Which units does systemd know about?

        **The cross-check here is narrowed to ``.service``, and the reason is a
        finding about the cross-check rather than about either parser.**
        Compared on the whole output these two disagree reproducibly — Momus's
        ``_parse_unit_files`` keeps 24 ``.timer`` rows that Whetstone's
        ``parse_systemctl_unit_files`` drops — and the first reading is that one
        of them is losing persistence mechanisms, which would matter a great
        deal: a timer is how the sibling project's own range plants one.

        Checking the instrument says otherwise. Whetstone's parser is
        documented for ``systemctl list-unit-files --type=service`` and its
        only caller passes exactly that, so against its real input the
        ``.service`` filter is not a filter at all. Momus's caller passes the
        unfiltered command and its parser keeps ``.service`` and ``.timer``.
        Both are right about the bytes they are given; what was wrong was
        feeding one of them an input its contract excludes and calling the
        result a disagreement. So the comparison is made on the subset both
        contracts cover, and the difference is recorded here instead of
        generating nine identical false findings per run.
        """
        rows = self.lima._parse_unit_files(cap.stdout)
        theirs = self.whet.parse_systemctl_unit_files(cap.stdout)
        parse = {"count": len(rows), "units": [dict(r) for r in rows[:50]]}
        momus_services = {r["unit"] for r in rows
                          if r["unit"].endswith(".service")}
        if not momus_services <= set(theirs):
            raise Disagreement(
                f"{len(momus_services - set(theirs))} .service units momus "
                "kept and whetstone dropped")
        if cap.timed_out:
            return Label(_momus_name(self.lima._parse_unit_files), parse,
                         "inconclusive")
        verdict = "found" if rows else ("absent" if cap.exit_code == 0
                                        else "inconclusive")
        return Label(_momus_name(self.lima._parse_unit_files), parse, verdict)

    # -- processes, users, network ----------------------------------------

    def ps(self, cap: Capture) -> Label:
        rows = self.lima._parse_ps(cap.stdout)
        parse = {"count": len(rows), "processes": [dict(r) for r in rows[:40]]}
        if cap.timed_out:
            return Label(_momus_name(self.lima._parse_ps), parse, "inconclusive")
        verdict = "found" if rows else ("absent" if cap.exit_code == 0
                                        else "inconclusive")
        return Label(_momus_name(self.lima._parse_ps), parse, verdict)

    def passwd(self, cap: Capture) -> Label:
        rows = self.lima._parse_passwd(cap.stdout)
        theirs = self.whet.parse_passwd(cap.stdout, include_disabled=True)
        if len(theirs) != len(rows):
            raise Disagreement(
                f"account count: momus={len(rows)} whetstone={len(theirs)}")
        parse = {"count": len(rows), "accounts": [dict(r) for r in rows]}
        if cap.timed_out:
            return Label(_momus_name(self.lima._parse_passwd), parse, "inconclusive")
        verdict = "found" if rows else ("absent" if cap.exit_code == 0
                                        else "inconclusive")
        return Label(_momus_name(self.lima._parse_passwd), parse, verdict)

    def ip_addr(self, cap: Capture) -> Label:
        rows = self.lima._parse_ip_addr(cap.stdout)
        theirs = self.whet.parse_ip_addr(cap.stdout)
        parse = [dict(r) for r in rows]
        momus_addrs = {(r["interface"], r["address"]) for r in rows}
        their_addrs = {(r.get("iface", r.get("interface", "")),
                        r.get("address", "")) for r in theirs}
        if momus_addrs - their_addrs:
            raise Disagreement(
                f"addresses momus kept and whetstone dropped: "
                f"{sorted(momus_addrs - their_addrs)[:3]}")
        if cap.timed_out:
            return Label(_momus_name(self.lima._parse_ip_addr), parse, "inconclusive")
        verdict = "found" if rows else ("absent" if cap.exit_code == 0
                                        else "inconclusive")
        return Label(_momus_name(self.lima._parse_ip_addr), parse, verdict)

    def ss(self, cap: Capture) -> Label:
        """What is listening? Header-bearing output, dropped by shape.

        ``_parse_ss`` keeps a row only if its first field is ``tcp`` or
        ``udp``, so ``Netid State Recv-Q ...`` falls out on content rather than
        on being line one -- which is the robust version, because ``ss`` omits
        the header entirely with ``-H``.

        Deliberately **not** cross-checked against
        ``whetstone.adapters.linux.parse_ss``, which is documented for
        ``ss -tulpnH`` and whose only caller passes exactly that. Handed a
        header it parses it as a socket named ``Netid`` -- correct for its
        input, wrong for this one. :meth:`ss_headerless` is the probe where
        both contracts hold and the two are compared.
        """
        rows = self.lima._parse_ss(cap.stdout)
        parse = {"count": len(rows), "sockets": [dict(r) for r in rows[:40]]}
        if cap.timed_out:
            return Label(_momus_name(self.lima._parse_ss), parse, "inconclusive")
        verdict = "found" if rows else ("absent" if cap.exit_code == 0
                                        else "inconclusive")
        return Label(_momus_name(self.lima._parse_ss), parse, verdict)

    def ss_headerless(self, cap: Capture) -> Label:
        """``ss -tulpnH``: the input both parsers are documented for.

        Whetstone's adds the owning process, pulled out of
        ``users:(("sshd",pid=812,fd=3))``, which is what makes a listening port
        actionable rather than merely present -- so its parse is the label here
        and Momus's is the cross-check on the socket count.
        """
        theirs = self.whet.parse_ss(cap.stdout)
        mine = self.lima._parse_ss(cap.stdout)
        if len(theirs) != len(mine):
            raise Disagreement(
                f"socket count: whetstone={len(theirs)} momus={len(mine)}")
        parse = {"count": len(theirs), "sockets": theirs[:40]}
        if cap.timed_out:
            return Label(_whet_name(self.whet.parse_ss), parse, "inconclusive")
        verdict = "found" if theirs else ("absent" if cap.exit_code == 0
                                          else "inconclusive")
        return Label(_whet_name(self.whet.parse_ss), parse, verdict)

    # -- cron -------------------------------------------------------------

    def crontab_user(self, cap: Capture) -> Label:
        """Does this account have scheduled jobs?

        ``crontab -l`` for an account with no crontab writes ``no crontab for
        X`` to **stderr** and exits 1, leaving stdout empty. Read as stdout
        alone that is indistinguishable from an installed-but-empty crontab,
        which is a different fact about the machine. A per-account crontab also
        has **no user field**, and reading one as if it did attributes every job
        to the wrong account.
        """
        jobs = self.lima._parse_crontab(cap.stdout, source="crontab -l",
                                        has_user_field=False)
        parse = [{"schedule": j.schedule, "user": j.user, "command": j.command,
                  "program": j.program} for j in jobs]
        if cap.timed_out:
            return Label(_momus_name(self.lima._parse_crontab), parse, "inconclusive")
        if jobs:
            return Label(_momus_name(self.lima._parse_crontab), parse, "found")
        if cap.exit_code != 0 and cap.stderr.strip() and not cap.stdout.strip():
            return Label(_momus_name(self.lima._parse_crontab), parse,
                         "inconclusive")
        return Label(_momus_name(self.lima._parse_crontab), parse, "absent")

    def crontab_system(self, cap: Capture) -> Label:
        """``/etc/cron.d`` entries, which **do** carry a user field."""
        blobs = self.lima._parse_head_v(cap.stdout)
        parse: list[dict[str, Any]] = []
        for path, body in blobs.items():
            for job in self.lima._parse_crontab(body, source=path,
                                                has_user_field=True):
                parse.append({"source": job.source, "schedule": job.schedule,
                              "user": job.user, "command": job.command,
                              "program": job.program})
        if cap.timed_out:
            return Label(_momus_name(self.lima._parse_crontab), parse,
                         "inconclusive")
        if parse:
            return Label(_momus_name(self.lima._parse_crontab), parse, "found")
        if blobs:
            return Label(_momus_name(self.lima._parse_crontab), parse, "absent")
        return Label(_momus_name(self.lima._parse_crontab), parse, "inconclusive")

    def head_v(self, cap: Capture) -> Label:
        """``head -v -- a b c``: exits 1 after printing every file it could read.

        Dropping the whole result on a non-zero exit loses the readable files
        because one entry in the list was missing -- in Momus's own measurement,
        104 cron files lost because the 105th was not there.
        """
        blobs = self.lima._parse_head_v(cap.stdout)
        parse = {"files_read": sorted(blobs),
                 "count": len(blobs),
                 "bytes": {k: len(v) for k, v in sorted(blobs.items())}}
        if cap.timed_out:
            return Label(_momus_name(self.lima._parse_head_v), parse, "inconclusive")
        if blobs:
            return Label(_momus_name(self.lima._parse_head_v), parse, "found",
                         detail=f"{len(blobs)} of the paths asked for were "
                                "readable.")
        return Label(_momus_name(self.lima._parse_head_v), parse,
                     "absent" if cap.exit_code == 0 else "inconclusive")

    # -- misc -------------------------------------------------------------

    def os_release(self, cap: Capture) -> Label:
        mine = self.lima._parse_os_release(cap.stdout)
        theirs = self.whet.parse_os_release(cap.stdout)
        for key in ("ID", "VERSION_ID"):
            if key in mine and key.lower() in theirs and mine[key] != theirs[key.lower()]:
                raise Disagreement(f"{key}: momus={mine[key]} whetstone={theirs[key.lower()]}")
        verdict = "found" if mine else ("absent" if cap.exit_code == 0
                                        else "inconclusive")
        return Label(_momus_name(self.lima._parse_os_release), mine, verdict)

    def env(self, cap: Capture) -> Label:
        mine = self.lima._parse_env(cap.stdout)
        verdict = "found" if mine else ("absent" if cap.exit_code == 0
                                        else "inconclusive")
        return Label(_momus_name(self.lima._parse_env), mine, verdict)

    def proc_status(self, cap: Capture) -> Label:
        """``/proc/<pid>/status``, read through this project's own parser.

        Momus has no equivalent, so there is nothing to cross-check and the
        label names the single parser that produced it. ``decode_caps`` turning
        a 16-hex-digit mask into capability names is the part worth learning:
        the mask is unreadable and the names are the finding.
        """
        parse = self.whet.parse_proc_status(cap.stdout)
        if cap.timed_out:
            return Label(_whet_name(self.whet.parse_proc_status), parse,
                         "inconclusive")
        if parse.get("uid"):
            caps = parse.get("cap_effective", [])
            return Label(
                _whet_name(self.whet.parse_proc_status), parse, "found",
                detail=f"effective uid {parse['uid'].get('effective')}, "
                       f"{len(caps)} effective capability/ies.")
        return Label(_whet_name(self.whet.parse_proc_status), parse,
                     "absent" if cap.exit_code == 0 else "inconclusive")

    def dpkg(self, cap: Capture) -> Label:
        parse_rows = self.whet.parse_dpkg_query(cap.stdout)
        parse = {"count": len(parse_rows), "packages": parse_rows[:40]}
        verdict = "found" if parse_rows else ("absent" if cap.exit_code == 0
                                              else "inconclusive")
        return Label(_whet_name(self.whet.parse_dpkg_query), parse, verdict)

    def auditctl(self, cap: Capture) -> Label:
        """Is a watch loaded on the file we care about?

        ``auditctl -l`` prints ``No rules`` and exits 0 when the ruleset is
        empty -- a real negative, and the one case where "nothing there" is
        stated in words rather than by silence.
        """
        parse = self.whet.parse_auditctl_l(cap.stdout)
        if cap.timed_out or cap.exit_code not in (0,):
            return Label(_whet_name(self.whet.parse_auditctl_l), parse,
                         "inconclusive")
        return Label(_whet_name(self.whet.parse_auditctl_l), parse,
                     "found" if parse else "absent")

    def ip_route(self, cap: Capture) -> Label:
        parse = self.whet.parse_ip_route(cap.stdout)
        verdict = "found" if parse else ("absent" if cap.exit_code == 0
                                         else "inconclusive")
        return Label(_whet_name(self.whet.parse_ip_route), parse, verdict)

    def uname(self, cap: Capture) -> Label:
        parse = self.whet.parse_uname(cap.stdout)
        verdict = "found" if parse else ("absent" if cap.exit_code == 0
                                         else "inconclusive")
        return Label(_whet_name(self.whet.parse_uname), parse, verdict)

    def hostnamectl(self, cap: Capture) -> Label:
        parse = self.whet.parse_hostnamectl(cap.stdout)
        verdict = "found" if parse else ("absent" if cap.exit_code == 0
                                         else "inconclusive")
        return Label(_whet_name(self.whet.parse_hostnamectl), parse, verdict)

    # -- unparsed ---------------------------------------------------------

    def textual(self, cap: Capture) -> Label:
        """No parser exists for this shape, and the structure is the label.

        Used for ``stat``, ``mount``, ``ls -l``, ``journalctl`` and raw
        ``audit.log`` reads. The parse records what is mechanically true of the
        bytes -- how many lines, which stream they arrived on, what the exit
        status was -- and nothing it cannot check. The alternative was to write
        a parser here and label the document with it, which would be labelling
        output with a guess that no runtime makes.
        """
        parse = {
            "lines": len(cap.stdout.splitlines()),
            "stderr_lines": len(cap.stderr.splitlines()),
            "exit": cap.exit_code,
            "stdout_empty": cap.empty,
        }
        if cap.timed_out:
            return Label("none (structure only)", parse, "inconclusive")
        if not cap.empty:
            return Label("none (structure only)", parse, "found",
                         detail=f"{parse['lines']} line(s) on stdout, "
                                f"exit {cap.exit_code}.")
        if cap.exit_code == 0:
            return Label("none (structure only)", parse, "absent",
                         detail="no stdout and exit 0.")
        return Label("none (structure only)", parse, "error",
                     detail=f"no stdout, exit {cap.exit_code}, "
                            f"{parse['stderr_lines']} line(s) on stderr.")


# --------------------------------------------------------------------------
# The probe catalogue
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Probe:
    """One command to run, with the question it answers and how to read it."""

    id: str
    argv: tuple[str, ...]
    question: str
    label: str                      # method name on Labels
    #: ``None`` = run as the Lima guest account; ``"root"`` = via ``sudo -n``;
    #: anything else = via ``sudo -n -u <name>``.
    account: str | None = None
    #: Column-aligned output, so substitutions must preserve string length.
    aligned: bool = False
    timeout: int = 30
    states: tuple[str, ...] = ()    # () = every state
    readings: dict[str, str] = field(default_factory=dict)
    family: str = ""

    def applies(self, state: str) -> bool:
        return not self.states or state in self.states


_AFTER_ACCOUNTS = ("accounts", "sudo-rules", "odd-modes", "capabilities",
                   "cron", "service-timer", "audit-armed", "reverted")
_AFTER_FILES = ("odd-modes", "capabilities", "cron", "service-timer",
                "audit-armed")

_READ_SUDO = {
    "found": ("sudo enumerated this account's rules without needing a "
              "password, and at least one of them runs a command as another "
              "user with no password. A foothold as this account is already "
              "that privilege."),
    "absent": ("sudo enumerated this account's rules and none of them is "
               "NOPASSWD. Every rule here needs a password that -n will never "
               "supply, so this is a real negative for passwordless "
               "escalation."),
    "inconclusive": ("sudo refused to list the rules without a password, so "
                     "this output says nothing about whether a NOPASSWD rule "
                     "exists. On this image an account with a PASSWD rule and "
                     "an account with no rules at all print this same line."),
    "error": ("sudo did not run, so nothing follows about this account's "
              "entitlements."),
}

_READ_ID = {
    "found": ("The real and effective ids differ and the effective id is 0: "
              "this process is running as root. uid= alone would have read as "
              "unprivileged."),
    "absent": ("The effective id is not 0. This process has the privileges of "
               "the account it says it does."),
    "inconclusive": "id produced nothing that can be read as an identity.",
}

_READ_SUID = {
    "found": ("Each row is a setuid file reachable from here: the s in the "
              "owner-execute slot of the mode is what makes it one."),
    "absent": ("find walked everything it was given, exited 0, and printed no "
               "rows. There are no setuid files under this root -- a negative "
               "result, not a failed search."),
    "inconclusive": ("find exited non-zero, which here means it was refused at "
                     "least one directory. The rows it printed are real; the "
                     "absence of others is not evidence."),
}

_READ_CRON = {
    "found": "The rows are this account's scheduled jobs, with no user field.",
    "absent": ("The crontab exists and holds no jobs. Empty, which is not the "
               "same as missing."),
    "inconclusive": ("crontab wrote a diagnostic to stderr and exited 1: there "
                     "is no crontab for this account at all. Read from stdout "
                     "alone this is indistinguishable from an empty crontab, "
                     "and they are different facts."),
}

_READ_UNIT_EXISTS = {
    "found": ("FragmentPath names a real unit file, so the unit exists on this "
              "machine."),
    "absent": ("FragmentPath is empty: systemd does not know this unit. Note "
               "the exit status -- systemctl show exits 0 and echoes the name "
               "back as Id, so the exit code is not the evidence."),
    "inconclusive": "No property record came back to read.",
}


def static_probes() -> list[Probe]:
    """Probes whose argv does not depend on what is on the machine."""
    probes: list[Probe] = [
        Probe("identity.self", ("id",),
              "Is this process effectively root?", "identity",
              readings=_READ_ID, family="id"),
        Probe("identity.proc", ("cat", "/proc/self/status"),
              "What are this process's ids and effective capabilities?",
              "proc_status", family="proc-status"),
        Probe("host.osrelease", ("cat", "/etc/os-release"),
              "What distribution and release is this?", "os_release",
              family="os-release"),
        Probe("host.uname", ("uname", "-a"),
              "What kernel is this machine running?", "uname", family="uname"),
        Probe("host.hostnamectl", ("hostnamectl",),
              "What does this machine call itself?", "hostnamectl",
              family="hostnamectl"),
        Probe("users.passwd", ("getent", "passwd"),
              "Which accounts exist and which have login shells?", "passwd",
              family="passwd"),
        Probe("processes.ps", ("ps", "-eo", "user:20=,pid=,comm="),
              "What is running and as whom?", "ps", aligned=True, family="ps"),
        Probe("processes.psef", ("ps", "-ef"),
              "What is running, with the full command line of each process?",
              "textual", aligned=True, family="ps-ef"),
        Probe("network.ipaddr", ("ip", "-o", "addr", "show"),
              "What addresses does this machine hold?", "ip_addr",
              family="ip-addr"),
        Probe("network.iproute", ("ip", "route"),
              "Where does traffic from this machine go?", "ip_route",
              family="ip-route"),
        Probe("network.listeners", ("ss", "-ltun"),
              "What is listening on this machine?", "ss", aligned=True,
              family="ss"),
        Probe("network.listeners_proc", ("ss", "-tulpn"),
              "What is listening, and which process owns each socket?",
              "textual", aligned=True, family="ss-p"),
        Probe("network.listeners_h", ("ss", "-tulpnH"),
              "What is listening, and which process owns each socket?",
              "ss_headerless", account="root", aligned=True, family="ss-h"),
        Probe("network.proc_tcp", ("cat", "/proc/net/tcp"),
              "What TCP sockets does the kernel hold, in its own hex form?",
              "textual", aligned=True, family="proc-net"),
        Probe("filesystem.mounts", ("cat", "/proc/mounts"),
              "What is mounted and with which options?", "textual",
              family="mounts"),
        Probe("filesystem.mount_cmd", ("mount",),
              "What is mounted, as mount(8) renders it?", "textual",
              family="mount-cmd"),
        Probe("software.dpkg", ("dpkg-query", "-W",
                                "-f=${Package}\t${Version}\t"
                                "${Architecture}\t${db:Status-Abbrev}\n"),
              "Which packages are installed, and at what versions?", "dpkg",
              aligned=True, family="dpkg"),
        Probe("services.unitfiles", ("systemctl", "list-unit-files",
                                     "--no-legend", "--plain"),
              "Which units does systemd know about, and are they enabled?",
              "unit_files", timeout=60, family="unit-files"),
        Probe("services.failed", ("systemctl", "list-units", "--failed",
                                  "--no-legend", "--plain"),
              "Has anything on this machine failed?", "textual", timeout=60,
              family="failed-units"),
        Probe("sudo.rights.guest", ("sudo", "-n", "-l"),
              "Can this account run something as root with no password?",
              "sudo_rights", readings=_READ_SUDO, family="sudo-l"),
        Probe("env.self", ("env",),
              "What environment was this command given?", "env", family="env"),

        # --- the failure cases ------------------------------------------
        Probe("denied.shadow", ("cat", "/etc/shadow"),
              "Can this account read the password hashes?", "textual",
              account=PROBE_ACCOUNTS[5], states=_AFTER_ACCOUNTS,
              family="denied",
              readings={"error": ("Permission denied on stderr with exit 1 and "
                                  "nothing on stdout: the file exists and this "
                                  "account cannot read it. That is a different "
                                  "fact from the file not existing.")}),
        Probe("denied.sudoers_dir", ("ls", "-l", "/etc/sudoers.d/"),
              "What sudo drop-ins are on this machine?", "textual",
              account=PROBE_ACCOUNTS[5], states=_AFTER_ACCOUNTS,
              family="denied"),
        Probe("missing.file", ("cat", "/etc/nosuchfile.conf"),
              "Does this configuration file exist?", "textual",
              family="missing",
              readings={"error": ("No such file or directory: the path is not "
                                  "there. Compare with a Permission denied on "
                                  "the same command -- same exit code, "
                                  "opposite meaning.")}),
        Probe("missing.binary", ("nosuchbinary", "--version"),
              "Is this tool installed?", "textual", family="missing-binary"),
        Probe("empty.find", ("find", "/etc", "-maxdepth", "1", "-name",
                             "zzz-no-such-file-*"),
              "Is there a file matching this pattern?", "paths",
              family="empty-find",
              readings={"absent": ("Exit 0 and no output. find looked and there "
                                   "is nothing matching. Empty output with a "
                                   "zero exit is an answer.")}),
        Probe("empty.grep", ("grep", "-c", "zzz-no-such-string", "/etc/os-release"),
              "Does this string appear in the file?", "textual",
              family="empty-grep"),
        Probe("timeout.vm", ("timeout", "2", "sleep", "20"),
              "Did this command finish?", "textual", timeout=30,
              family="timeout",
              readings={"absent": ("Exit 124 is timeout(1) reporting that it "
                                   "killed the command. No output was produced "
                                   "and nothing was learned.")}),
        Probe("timeout.transport", ("sleep", "30"),
              "Did this command finish?", "textual", timeout=4,
              family="timeout",
              readings={"inconclusive": ("The transport gave up before the "
                                         "command returned. Exit -1 is not a "
                                         "real exit status; it is the runtime "
                                         "saying no process produced output.")}),
        Probe("denied.auditctl", ("auditctl", "-l"),
              "Which audit rules are loaded?", "textual",
              account=PROBE_ACCOUNTS[5], states=_AFTER_ACCOUNTS,
              family="denied-audit"),
    ]

    # --- more failure cases, each a *different* diagnostic ---------------
    #
    # The first pass had plenty of failure captures and almost no failure
    # documents: ``cat /etc/nosuchfile.conf`` prints the same line in all nine
    # states, so the dedup gate correctly kept one and the written corpus came
    # out 90% success output -- which is the exact imbalance this source exists
    # to fix, reintroduced by the fix for duplication.
    #
    # The repair is more *distinct* failures rather than more copies of one.
    # Four tools refuse in four different wordings for the same underlying
    # fact, and a model that learned only ``No such file or directory`` would
    # not recognise ``cannot statx`` or ``cannot access`` as the same answer:
    #
    #     cat:  cat: /x: No such file or directory
    #     stat: stat: cannot statx '/x': No such file or directory
    #     ls:   ls: cannot access '/x': No such file or directory
    #     head: head: cannot open '/x' for reading: No such file or directory
    #
    # The denial probes are metadata reads on root-only paths, not content
    # reads. A ``cat`` that unexpectedly succeeded would put a package's
    # shipped file or an account database into the corpus; an ``ls -l`` that
    # unexpectedly succeeded puts modes and owners there, which is the data
    # this source collects anyway.
    for tool, argv in (("cat", ("cat",)), ("stat", ("stat",)),
                       ("ls", ("ls", "-l")), ("head", ("head", "-n", "3"))):
        probes.append(Probe(
            f"missing.{tool}", (*argv, f"/etc/nosuchfile-{tool}-probe"),
            "Does this path exist?", "textual", family=f"missing-{tool}",
            readings={"error": ("The diagnostic names the tool, the path and "
                                "the reason. Four tools word this differently "
                                "for the same underlying fact.")}))
    for n, target in enumerate(("/root", "/etc/sudoers.d",
                                "/var/spool/cron/crontabs", "/var/log/audit")):
        account = PROBE_ACCOUNTS[n % len(PROBE_ACCOUNTS)]
        probes.append(Probe(
            f"denied.meta.{target.strip('/').replace('/', '_')}",
            ("ls", "-la", target),
            f"What is in {target}, and may this account look?", "textual",
            account=account, aligned=True, states=_AFTER_ACCOUNTS,
            family="denied-meta",
            readings={"error": ("Permission denied, exit 2, nothing on stdout. "
                                "The directory exists and this account cannot "
                                "list it -- which is a different fact from the "
                                "directory not being there, and the two "
                                "produce the same exit code.")}))
        probes.append(Probe(
            f"denied.statmeta.{target.strip('/').replace('/', '_')}",
            ("stat", "-c", "%A %U %G %n", target),
            f"What are {target}'s mode and owner?", "textual",
            account=account, states=_AFTER_ACCOUNTS, family="denied-statmeta"))
    probes += [
        Probe("empty.journal", ("journalctl", "-u", "wsp-no-such-unit.service",
                                "--no-pager", "-n", "5"),
              "Has this unit logged anything?", "textual", account="root",
              timeout=60, family="empty-journal",
              readings={"found": ("journalctl says so in words -- "
                                  "'No entries' -- and exits 0. A tool that "
                                  "found nothing reports on stdout; a tool "
                                  "that could not look explains itself on "
                                  "stderr.")}),
        Probe("empty.getent", ("getent", "passwd", "wsp-no-such-account"),
              "Does this account exist?", "textual", family="empty-getent",
              readings={"absent": ("Exit 2 and no output. getent looked in "
                                   "every configured source and the account is "
                                   "not in any of them.")}),
        Probe("empty.pgrep", ("pgrep", "-x", "wsp-no-such-process"),
              "Is this process running?", "textual", family="empty-pgrep"),
        Probe("error.no_such_pid", ("cat", "/proc/99999999/status"),
              "What are this process's ids?", "proc_status", account="root",
              family="error-pid",
              readings={"inconclusive": ("The pid does not exist, so /proc has "
                                         "no directory for it. Nothing here is "
                                         "a statement about a process.")}),
        Probe("error.stat_pid", ("stat", "/proc/99999999/status"),
              "Does this process exist?", "textual", account="root",
              family="error-statpid"),
        Probe("denied.shadow_gshadow", ("cat", "/etc/gshadow"),
              "Can this account read the group password database?", "textual",
              account=PROBE_ACCOUNTS[4], states=_AFTER_ACCOUNTS,
              family="denied-gshadow"),
    ]


    # Root-run variants of the probes whose answer changes with privilege. The
    # same command and two different answers is the clearest possible lesson
    # that an observation is relative to the account that made it.
    probes += [
        Probe("identity.root", ("id",),
              "Is this process effectively root?", "identity", account="root",
              readings=_READ_ID, family="id"),
        Probe("suid.sweep_root", ("find", "/usr", "-xdev", "-perm", "-4000",
                                  "-printf", "%M %u %g %p\n"),
              "Which setuid binaries exist under /usr?", "suid_sweep",
              account="root", timeout=90, readings=_READ_SUID, family="suid"),
        Probe("caps.sweep_root", ("getcap", "-r", "/usr/bin", "/usr/sbin"),
              "Which binaries carry file capabilities?", "getcap",
              account="root", timeout=90, family="getcap"),
        Probe("audit.rules_root", ("auditctl", "-l"),
              "Is a watch loaded on the file we care about?", "auditctl",
              account="root", family="auditctl"),
        Probe("cron.system_root", ("head", "-v", "--", "/etc/crontab",
                                   "/etc/cron.d/60-wsp-maint",
                                   "/etc/cron.d/e2scrub_all",
                                   "/etc/cron.d/nosuchfile"),
              "What system-wide cron jobs are scheduled?", "crontab_system",
              account="root", states=_AFTER_FILES, family="cron-system"),
        Probe("cron.headv_partial", ("head", "-v", "--", "/etc/os-release",
                                     "/etc/hostname", "/etc/nosuchfile",
                                     "/etc/machine-id"),
              "Which of these files can be read?", "head_v", account="root",
              family="head-v",
              readings={"found": ("head exited 1 because one path was missing "
                                  "and still printed every file it could read. "
                                  "Dropping the result on a non-zero exit would "
                                  "lose the files that were there.")}),
        Probe("journal.recent_root", ("journalctl", "-n", "40", "--no-pager"),
              "What has the journal recorded recently?", "textual",
              account="root", timeout=60, family="journal"),
        Probe("journal.auth_root", ("journalctl", "-n", "40", "--no-pager",
                                    "-t", "sudo"),
              "What has sudo recorded?", "textual", account="root",
              timeout=60, family="journal-sudo"),
        Probe("audit.log_root", ("tail", "-n", "40", "/var/log/audit/audit.log"),
              "What did auditd write, in its own wire form?", "textual",
              account="root", timeout=60, family="audit-log"),
    ]
    return probes


def per_account_probes(state: str) -> list[Probe]:
    """The same handful of probes once per created account.

    Six real accounts with six different sets of sudo rules produce six
    genuinely different ``sudo -n -l`` outputs, including the account with no
    rule at all whose refusal is byte-identical to the account whose only rule
    needs a password. That pair cannot be manufactured; it has to be measured.
    """
    if state not in _AFTER_ACCOUNTS:
        return []
    out: list[Probe] = []
    for account in PROBE_ACCOUNTS:
        out += [
            Probe(f"sudo.rights.{account}", ("sudo", "-n", "-l"),
                  "Can this account run something as root with no password?",
                  "sudo_rights", account=account, readings=_READ_SUDO,
                  family="sudo-l"),
            Probe(f"identity.{account}", ("id",),
                  "Is this process effectively root?", "identity",
                  account=account, readings=_READ_ID, family="id"),
            Probe(f"cron.user.{account}", ("crontab", "-l"),
                  "Does this account have scheduled jobs?", "crontab_user",
                  account=account, readings=_READ_CRON, family="cron-user"),
            Probe(f"home.{account}", ("ls", "-la", f"/home/{account}"),
                  "What is in this account's home directory?", "textual",
                  account=account, aligned=True, family="home-ls"),
        ]
    if state in _AFTER_FILES:
        out += [
            Probe(f"identity.setuid.{PROBE_ACCOUNTS[0]}", (SUID_ID,),
                  "Is this process effectively root?", "identity",
                  account=PROBE_ACCOUNTS[0], readings=_READ_ID, family="id-suid"),
            Probe("suid.sweep_unpriv", ("find", "/", "-xdev", "-perm", "-4000",
                                        "-printf", "%M %u %g %p\n"),
                  "Which setuid binaries are reachable from here?",
                  "suid_sweep", account=PROBE_ACCOUNTS[5], timeout=120,
                  readings=_READ_SUID, family="suid"),
            Probe("files.plant_long", ("find", PLANT_ROOT, "-printf",
                                       "%M %u %g %p\n"),
                  "What is under this directory and with what modes?",
                  "find_long", account="root", family="find-long",
                  readings={"found": ("Two of these paths contain a space. "
                                      "Splitting a row on whitespace would "
                                      "truncate the filename to its first "
                                      "word; the parse splits three times and "
                                      "keeps the remainder.")}),
            Probe("files.plant_ls", ("ls", "-la", PLANT_ROOT),
                  "What is under this directory and with what modes?",
                  "textual", account="root", aligned=True, family="ls-l"),
            Probe("files.space_stat", ("stat", SPACE_FILE),
                  "What are this file's mode, owner and timestamps?",
                  "textual", account="root", family="stat"),
            Probe("caps.plant", ("getcap", "-r", PLANT_ROOT),
                  "Which binaries here carry file capabilities?", "getcap",
                  account="root", family="getcap"),
        ]
    return out


def discovered_probes(vm: VM, state: str, *, unit_cap: int, path_cap: int,
                      pid_cap: int, offset: int = 0) -> list[Probe]:
    """Probes built from what is actually on the machine right now.

    The volume is here, and so is the variety: a hundred ``systemctl show``
    property blocks are a hundred genuinely different records, which is the
    opposite of the corpus's measured problem (253 literals repeated 947 times
    each). Enumerated fresh per state, so a unit the plant added appears and a
    unit the revert removed stops appearing.
    """
    probes: list[Probe] = []

    def _slice(items: list[str], count: int, step: int) -> list[str]:
        """A different window of *items* per state, wrapping.

        Nine states all taking ``items[:45]`` is not nine measurements, it is
        one measurement written out nine times -- and that is where the 75%
        duplicate rate came from. Moving the window instead turns the same
        number of VM round trips into coverage: 388 units on this image, nine
        windows of 45, and a unit that the plant added or the revert removed
        still appears or stops appearing because the list is re-enumerated per
        state rather than cached.
        """
        if not items:
            return []
        start = (step * count) % len(items)
        window = items[start:start + count]
        if len(window) < count:
            window += items[: count - len(window)]
        return window

    units = _slice(_unit_names(vm), unit_cap, offset)
    for unit in units:
        probes.append(Probe(
            f"services.exists.{unit}",
            ("systemctl", "show", "--property=Id,FragmentPath,UnitFileState,"
             "LoadState,ActiveState,SubState", unit),
            f"Does the unit {unit} exist on this machine?", "unit_exists",
            account="root", timeout=45, readings=_READ_UNIT_EXISTS,
            family="unit-show"))
    for unit in units[: max(1, unit_cap // 2)]:
        probes.append(Probe(
            f"services.execstart.{unit}",
            ("systemctl", "show", "--property=Id,ExecStart,FragmentPath,"
             "User,WorkingDirectory", unit),
            f"What binary does {unit} execute?", "unit_execstart",
            account="root", timeout=45, family="unit-exec"))
    # A unit that does not exist, every state, so the exit-0 trap is always in.
    probes.append(Probe(
        "services.exists.absent",
        ("systemctl", "show", "--property=Id,FragmentPath,LoadState",
         "wsp-no-such-unit.service"),
        "Does the unit wsp-no-such-unit.service exist on this machine?",
        "unit_exists", account="root", timeout=45,
        readings=_READ_UNIT_EXISTS, family="unit-show"))
    # Batched, because asking for several units in one call is what a real
    # caller does and the records come back blank-line separated.
    for i in range(0, min(len(units), unit_cap), 6):
        group = units[i:i + 6]
        if len(group) < 2:
            continue
        probes.append(Probe(
            f"services.batch.{i:03d}",
            ("systemctl", "show", "--property=Id,FragmentPath,ExecStart,"
             "ActiveState", *group),
            "Which of these units exist and what do they execute?",
            "unit_execstart", account="root", timeout=60, family="unit-batch"))

    # Chunked *first*, then the window moves over the chunks.
    #
    # The other way round -- slide a window over the paths and chunk whatever
    # it caught -- looks identical and is a volume trick: ``stat a b c d`` and
    # ``stat b c d e`` are different bytes, so the dedup gate passes them, and
    # the corpus fills with the same records regrouped. Stable chunks mean a
    # chunk a later state reaches again produces byte-identical output and is
    # refused, which is the honest outcome.
    all_paths = _interesting_paths(vm)
    stat_chunks = [all_paths[i:i + 4] for i in range(0, len(all_paths), 4)]
    ls_chunks = [all_paths[i:i + 6] for i in range(0, len(all_paths), 6)]
    for n, group in enumerate(_chunk_window(stat_chunks, path_cap // 4, offset)):
        probes.append(Probe(
            f"files.stat.{n:03d}", ("stat", *group),
            "What are these files' modes, owners and timestamps?", "textual",
            account="root", timeout=45, family="stat"))
    for n, group in enumerate(_chunk_window(ls_chunks, path_cap // 6, offset)):
        probes.append(Probe(
            f"files.long.{n:03d}", ("ls", "-ld", *group),
            "What are these paths' modes and owners?", "textual",
            account="root", aligned=True, timeout=45, family="ls-ld"))

    dirs = _interesting_dirs(vm)
    for directory in dirs:
        probes.append(Probe(
            f"files.ls.{directory.strip('/').replace('/', '_')}",
            ("ls", "-la", directory),
            f"What is in {directory} and with what modes?", "textual",
            account="root", aligned=True, timeout=45, family="ls-l"))

    all_pids = _pids(vm)
    pid_chunks = [[f"/proc/{q}/status" for q in all_pids[i:i + 5]]
                  for i in range(0, len(all_pids), 5)]
    for n, group in enumerate(_chunk_window(pid_chunks, pid_cap // 5, offset)):
        probes.append(Probe(
            f"processes.status.{n:03d}", ("head", "-v", "-n", "14", "--", *group),
            "What are these processes' ids and capabilities?", "head_v",
            account="root", timeout=45, family="proc-status-batch"))
    pids = _slice(all_pids, pid_cap, offset)
    for pid in pids[: max(1, pid_cap // 4)]:
        probes.append(Probe(
            f"processes.one.{pid}", ("cat", f"/proc/{pid}/status"),
            "What are this process's ids and effective capabilities?",
            "proc_status", account="root", timeout=45, family="proc-status"))

    for unit in _slice(_active_units(vm), 24, offset):
        probes.append(Probe(
            f"journal.unit.{unit}",
            ("journalctl", "-u", unit, "-n", "25", "--no-pager"),
            f"What has {unit} recorded?", "textual", account="root",
            timeout=60, family="journal-unit"))

    if state == "audit-armed":
        probes += [
            Probe("audit.key_hit", ("ausearch", "-k", AUDIT_KEY, "-i"),
                  "Did the control record the change to the watched file?",
                  "textual", account="root", timeout=60, family="ausearch",
                  readings={"found": ("The watch fired: these records name the "
                                      "watched path and carry the key the rule "
                                      "was tagged with.")}),
            Probe("audit.key_miss", ("ausearch", "-k", "wsp-no-such-key"),
                  "Did a control record anything under this key?", "textual",
                  account="root", timeout=60, family="ausearch",
                  readings={"error": ("<no matches> and a non-zero exit. "
                                      "ausearch found nothing for this key. "
                                      "With the rule loaded that is silence; "
                                      "without it, it is a control that was "
                                      "never asked.")}),
            Probe("audit.raw_key", ("grep", "-h", AUDIT_KEY,
                                    "/var/log/audit/audit.log"),
                  "What did auditd write for this key, before ausearch "
                  "interpreted it?", "textual", account="root", timeout=60,
                  family="audit-raw"),
        ]
    return probes


# --------------------------------------------------------------------------
# Machine enumeration helpers
# --------------------------------------------------------------------------

def _chunk_window(chunks: list[list[str]], count: int, step: int
                  ) -> list[list[str]]:
    """*count* whole chunks from *chunks*, starting at a per-state offset."""
    if not chunks or count < 1:
        return []
    start = (step * count) % len(chunks)
    window = chunks[start:start + count]
    if len(window) < count:
        window += chunks[: count - len(window)]
    return window


def _unit_names(vm: VM) -> list[str]:
    cap = vm.sudo(["systemctl", "list-unit-files", "--no-legend", "--plain"],
                  timeout=60)
    names = [line.split()[0] for line in cap.stdout.splitlines()
             if line.split() and line.split()[0].endswith(
                 (".service", ".timer", ".socket", ".target", ".mount"))]
    return sorted(dict.fromkeys(names))


def _active_units(vm: VM) -> list[str]:
    cap = vm.sudo(["systemctl", "list-units", "--state=active", "--no-legend",
                   "--plain", "--type=service"], timeout=60)
    return [line.split()[0] for line in cap.stdout.splitlines() if line.split()]


def _pids(vm: VM) -> list[str]:
    cap = vm.sudo(["ps", "-eo", "pid="], timeout=45)
    return [p.strip() for p in cap.stdout.split() if p.strip().isdigit()]


#: Directories small enough that a whole listing is a document rather than a
#: corpus. ``/usr/bin`` and ``/usr/sbin`` are deliberately absent: ``ls -la
#: /usr/bin`` on this image is 61 KB, which is 3% of the source in one file and
#: a memorisation hazard the corpus-wide source cap cannot see inside a source
#: to catch. Those binaries are covered one at a time by the ``stat`` and
#: ``ls -ld`` probes and in bulk by the setuid and capability sweeps, which are
#: the questions anybody actually asks of them.
_DIR_CANDIDATES = (
    "/etc", "/etc/systemd/system", "/etc/cron.d", "/etc/sudoers.d", "/var/log",
    "/usr/local/bin", "/opt", "/var/tmp", "/tmp",
    "/run", "/boot", "/home", "/var/spool/cron/crontabs", "/etc/ssh",
    "/var/lib/systemd", "/usr/lib/systemd/system", "/etc/apt", "/dev",
    PLANT_ROOT, SPACE_DIR,
)


def _interesting_dirs(vm: VM) -> list[str]:
    return [d for d in _DIR_CANDIDATES if vm.exists(d)]


def _interesting_paths(vm: VM) -> list[str]:
    """Real paths worth a ``stat`` -- and one that is not there.

    The missing path is in the list on purpose: ``stat`` prints a diagnostic
    for it, exits non-zero, and still reports the files that exist. That is the
    partial-answer shape again, in a different command.
    """
    cap = vm.sudo(["find", "/etc", "-maxdepth", "1", "-type", "f", "-printf",
                   "%p\n"], timeout=45)
    found = sorted(p for p in cap.stdout.splitlines() if p.strip())
    extra = ["/usr/bin/sudo", "/usr/bin/find", "/usr/bin/passwd",
             "/usr/bin/id", "/bin/sh", "/etc/shadow", "/etc/passwd",
             "/var/log/audit/audit.log", "/proc/1/exe", "/dev/null",
             "/dev/vda1", "/etc/nosuchfile-stat-probe",
             SUID_ID, SPACE_FILE, WATCHED_FILE, f"{PLANT_ROOT}/no-perms",
             f"{PLANT_ROOT}/sticky-dir", f"{PLANT_ROOT}/broken-link"]
    return sorted(dict.fromkeys(found + extra))


# --------------------------------------------------------------------------
# Identifier discovery and substitution
# --------------------------------------------------------------------------

@dataclass
class VMIdentity:
    """The VM's own stable identifiers, which are not the operator's -- except
    one, and that one is the reason this class exists.

    Lima names the guest user after the host user. Everything else here is the
    VM's: its DHCP lease, its generated MAC, its machine-id. They are still
    repeated literals and therefore still a generalisation problem, which is
    why they are substituted too rather than only the one that is a privacy
    problem. The audit's finding was that those are the same pass and not the
    same problem.
    """

    account: str = ""
    home: str = ""
    #: The name the VM was booted with. The generator sets a varied hostname
    #: for every state, but journal and audit records written *before* the
    #: first ``hostnamectl`` call still carry the boot name, and a literal that
    #: appears in every journal slice is a literal the model memorises.
    boot_hostname: str = ""
    v4net: str = ""
    v4addr: str = ""
    v6_link: str = ""
    mac: str = ""
    machine_id: str = ""
    boot_id: str = ""

    def literals(self) -> dict[str, str]:
        out = {}
        if self.account:
            out["account"] = self.account
        if self.boot_hostname:
            out["hostname"] = self.boot_hostname
        if self.mac:
            out["mac"] = self.mac
        if self.v4net:
            out["v4net"] = self.v4net
        if self.v4addr:
            out["v4addr"] = self.v4addr
        if self.v6_link:
            out["v6"] = self.v6_link
        if self.machine_id:
            out["machine-id"] = self.machine_id
        if self.boot_id:
            out["boot-id"] = self.boot_id
        return out


def discover_identity(vm: VM, *, boot_hostname: str = "") -> VMIdentity:
    """Ask the VM what its own identifiers are. Derived, never configured.

    ``verify.py`` makes the same argument for the host: a configured list is a
    list of the leaks somebody already noticed. The same applies one level
    down -- hard-coding this VM's DHCP address would silently stop working the
    day the lease changes, and the substitution would quietly become a no-op.
    """
    ident = VMIdentity(boot_hostname=boot_hostname)
    who = vm.run(["id", "-un"]).stdout.strip()
    if who:
        ident.account = who
    home = vm.run(["getent", "passwd", who]).stdout.strip().split(":")
    if len(home) >= 6 and home[5]:
        ident.home = home[5]
    addr = vm.run(["ip", "-o", "-4", "addr", "show", "scope", "global"]).stdout
    for line in addr.splitlines():
        parts = line.replace("\\", " ").split()
        if len(parts) >= 4 and parts[2] == "inet":
            ident.v4addr = parts[3].split("/")[0]
            ident.v4net = ident.v4addr.rsplit(".", 1)[0] + "."
            break
    v6 = vm.run(["ip", "-o", "-6", "addr", "show"]).stdout
    for line in v6.splitlines():
        parts = line.replace("\\", " ").split()
        if len(parts) >= 4 and parts[2] == "inet6" and parts[3].startswith("fe80"):
            ident.v6_link = parts[3].split("/")[0]
            break
    link = vm.run(["ip", "-o", "link", "show"]).stdout
    for line in link.splitlines():
        if "link/ether" in line:
            after = line.split("link/ether", 1)[1].split()
            if after and after[0] != "00:00:00:00:00:00":
                ident.mac = after[0]
                break
    ident.machine_id = vm.run(["cat", "/etc/machine-id"]).stdout.strip()
    ident.boot_id = vm.run(["cat", "/proc/sys/kernel/random/boot_id"]).stdout.strip()
    return ident


def document_plan(ident: VMIdentity, salt: str, *, aligned: bool) -> dict[str, str]:
    """The substitution map for one document, plus the derived spellings.

    ``ps -ef`` truncates a user name to seven characters and appends ``+``, so
    the account appears in two different forms and a plan that only knew the
    long one would leave the short one in the corpus. The truncated
    replacement is built from the truncated original so the length is
    preserved and the two forms stay consistent with each other.
    """
    plan = fmt.substitution_plan(ident.literals(), salt, length_safe=aligned)
    account_repl = plan.get(ident.account, "")
    extra: dict[str, str] = {}
    if ident.account and account_repl:
        if len(ident.account) > 7:
            extra[ident.account[:7] + "+"] = account_repl[:7] + "+"
        if ident.home:
            extra[ident.home] = ident.home.replace(ident.account, account_repl)
    merged = {**plan, **extra}
    return dict(sorted(merged.items(), key=lambda kv: -len(kv[0])))


# --------------------------------------------------------------------------
# Licence provenance
# --------------------------------------------------------------------------

def copy_licences(vm: VM, out: Path, probes: Iterable[Probe]) -> dict[str, Any]:
    """Record what produced the data, and the copyright of every tool used.

    The build convention is that a source copies the upstream's own licence
    text into the cache so the SPEC's claim is checkable against the download.
    There is no download here, so the checkable thing is different: *which
    programs were invoked, which package each came from, and what that package
    declares about its own copyright.* Resolved by asking dpkg at generation
    time rather than from a hand-written list, for the reason
    :func:`discover_identity` gives.
    """
    lic = out / "licenses"
    lic.mkdir(parents=True, exist_ok=True)
    (lic / "image-provenance.txt").write_text(
        "VM image provenance for training/corpus/sources/outputpairs.py\n"
        "============================================================\n\n"
        "Lima instance config: lab/vm/whetstone-lab.yaml\n"
        "Image: https://cloud-images.ubuntu.com/releases/24.04/release/"
        "ubuntu-24.04-server-cloudimg-arm64.img\n\n"
        "/etc/os-release as reported by the guest:\n"
        + vm.run(["cat", "/etc/os-release"]).stdout
        + "\nKernel:\n" + vm.run(["uname", "-srm"]).stdout,
        encoding="utf-8")

    programs = sorted({p.argv[0] for p in probes} |
                      {"sudo", "tee", "chmod", "useradd", "userdel",
                       "hostnamectl", "auditctl", "setcap", "crontab"})
    resolved: dict[str, str] = {}
    for program in programs:
        # ``command -v`` is a shell builtin and there is no shell on this
        # boundary, so the lookup goes through the real binary.
        path = vm.run(["which", program]).stdout.strip().splitlines()[0:1]
        path = path[0] if path else ""
        if not path:
            resolved[program] = ""
            continue
        owner = vm.sudo(["dpkg", "-S", path]).stdout.strip()
        resolved[program] = owner.split(":")[0] if owner else ""

    copied: list[str] = []
    for package in sorted({p for p in resolved.values() if p}):
        body = vm.sudo(["cat", f"/usr/share/doc/{package}/copyright"]).stdout
        if not body.strip():
            continue
        safe = package.replace("/", "_")
        (lic / f"copyright.{safe}.txt").write_text(body, encoding="utf-8")
        copied.append(package)
    (lic / "programs-to-packages.txt").write_text(
        "program\tpackage (from dpkg -S on the resolved path)\n"
        + "".join(f"{k}\t{v or '(unresolved)'}\n" for k, v in sorted(resolved.items())),
        encoding="utf-8")
    return {"programs": resolved, "copyright_files": copied}


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

@dataclass
class Stats:
    captures: int = 0
    written: int = 0
    dropped_duplicate: int = 0
    dropped_short: int = 0
    dropped_leak: int = 0
    dropped_disagreement: int = 0
    dropped_secret: int = 0
    dropped_oversize: int = 0
    verdicts: Counter = field(default_factory=Counter)
    families: Counter = field(default_factory=Counter)
    exit_zero: int = 0
    exit_nonzero: int = 0
    timeouts: int = 0
    chars: int = 0
    disagreements: list[str] = field(default_factory=list)
    leaks: list[str] = field(default_factory=list)
    secrets: list[str] = field(default_factory=list)


def _header_for(vm: VM, state: str) -> tuple[str, str]:
    pretty = ""
    for line in vm.run(["cat", "/etc/os-release"]).stdout.splitlines():
        if line.startswith("PRETTY_NAME="):
            pretty = line.partition("=")[2].strip('"')
    kernel = vm.run(["uname", "-srm"]).stdout.strip()
    return f"{pretty} / {kernel}".strip(" /"), vm.run(["hostname"]).stdout.strip()


def _account_label(vm: VM, probe: Probe) -> str:
    if probe.account == "root":
        return "root (via sudo -n)"
    if probe.account:
        return f"{probe.account} (via sudo -n -u)"
    return "the login account"


def run_probe(vm: VM, probe: Probe) -> Capture:
    if probe.account == "root":
        return vm.sudo(list(probe.argv), timeout=probe.timeout)
    if probe.account:
        return vm.as_user(probe.account, list(probe.argv), timeout=probe.timeout)
    return vm.run(list(probe.argv), timeout=probe.timeout)


def generate(vm: VM, out: Path, labels: Labels, *, states: Sequence[Plant],
             unit_cap: int, path_cap: int, pid_cap: int, family_cap: int,
             needles) -> Stats:
    """Walk the states, run the probes, write the documents."""
    stats = Stats()
    seen_skeletons: set[str] = set()
    index = 0
    original_hostname = vm.run(["hostname"]).stdout.strip()
    probes_for_licences: list[Probe] = []
    # Per *state*, not per run. A single counter would let the first state's
    # ninety systemd units consume the whole budget and leave the planted and
    # reverted states -- the two that carry the matched found/absent pair this
    # source exists for -- with no unit documents at all.
    per_state: Counter = Counter()

    def emit(state: str, probe: Probe, cap: Capture, ident: VMIdentity,
             image: str, host: str) -> None:
        nonlocal index
        stats.captures += 1
        if cap.timed_out:
            stats.timeouts += 1
        elif cap.exit_code == 0:
            stats.exit_zero += 1
        else:
            stats.exit_nonzero += 1

        method = getattr(labels, probe.label)
        try:
            label = method(cap)
        except Disagreement as exc:
            stats.dropped_disagreement += 1
            stats.disagreements.append(f"{probe.id} [{state}]: {exc}")
            return
        except Exception as exc:  # a parser raising is itself a finding
            stats.dropped_disagreement += 1
            stats.disagreements.append(
                f"{probe.id} [{state}]: {type(exc).__name__} out of "
                f"{probe.label}: {exc}")
            return

        reading = probe.readings.get(label.verdict) or fmt.generic_reading(
            label.verdict)
        if label.detail:
            reading = f"{reading} {label.detail}"
        salt = f"{state}/{probe.id}/{index}"
        text = fmt.render_pair(
            image=image, host=host, state=state,
            account=_account_label(vm, probe), probe=probe.id,
            question=probe.question, argv=probe.argv,
            stdout=cap.stdout, stderr=cap.stderr, exit_code=cap.exit_code,
            parser=label.parser, parse=label.parse, verdict=label.verdict,
            reading=reading)
        text = fmt.apply_plan(text, document_plan(ident, salt,
                                                  aligned=probe.aligned))

        if len(text) < 150:
            stats.dropped_short += 1
            return
        if len(text) > fmt._MAX_CHARS:
            # The reader's ceiling, enforced by the writer. Without this the
            # source silently reads back fewer documents than the generator
            # reported writing, and "the two numbers differ and nothing says
            # so" is this project's most expensive failure shape.
            stats.dropped_oversize += 1
            return
        # The shape key is the PROBE FAMILY plus the CAPTURED OUTPUT, and not
        # the rendered document. Keying on the document made this gate a
        # no-op: the header carries the state name and the hostname, both of
        # which change every state, so every document was unique by
        # construction and 2,160 captures deduplicated to 2,160. Measured
        # afterwards on the output alone, the same run was **75.3% duplicate**
        # -- 533 distinct output shapes -- because `systemctl show cron.service`
        # prints the same block in all nine states. A dedup key computed over
        # text the generator itself varies cannot detect duplication in the
        # part it did not.
        #
        # The family is in the key because two different questions can share an
        # output: `empty.find` and `empty.grep` both print nothing and exit 0,
        # and those are two lessons, not one.
        shape = fmt.skeleton(f"{probe.family or probe.id}\n{cap.stdout}\n{cap.stderr}")
        if shape in seen_skeletons:
            stats.dropped_duplicate += 1
            return

        # The last gate before a byte is written. A document that still carries
        # one of this machine's identifiers is never written, counted instead.
        # Asserting the privacy win was the mistake the audit's own tooling
        # made; this checks it, on the exact bytes, with the same scanner the
        # build gate uses.
        carried = [m for m in _REFUSED_CONTENT if m in cap.stdout]
        if carried:
            stats.dropped_secret += 1
            stats.secrets.append(
                f"{probe.id} [{state}]: stdout matched "
                f"{len(carried)} refused-content marker(s)")
            return

        found = scan_text(text, needles=needles, field=probe.id)
        if found:
            stats.dropped_leak += 1
            stats.leaks.append(
                f"{probe.id} [{state}]: " +
                ", ".join(f"{lk.kind}:{lk.fingerprint}" for lk in found[:4]))
            return

        seen_skeletons.add(shape)
        slug = probe.id.replace("/", "_").replace(" ", "_")[:48]
        (out / f"pair-{index:05d}-{slug}.txt").write_text(text, encoding="utf-8")
        index += 1
        stats.written += 1
        stats.chars += len(text)
        stats.verdicts[label.verdict] += 1
        stats.families[probe.family or probe.id] += 1

    try:
        for step, plant in enumerate(states):
            print(f"\n== state {plant.name} (hostname {plant.hostname})")
            vm.must(["hostnamectl", "set-hostname", plant.hostname], timeout=30)
            plant.apply(vm)
            problems = plant.verify(vm)
            if problems:
                raise RuntimeError(f"plant {plant.name} did not take effect: "
                                   + "; ".join(problems))
            ident = discover_identity(vm, boot_hostname=original_hostname)
            image, host = _header_for(vm, plant.name)
            probes = ([p for p in static_probes() if p.applies(plant.name)]
                      + per_account_probes(plant.name)
                      + discovered_probes(vm, plant.name, unit_cap=unit_cap,
                                          path_cap=path_cap, pid_cap=pid_cap,
                                          offset=step))
            probes_for_licences = probes
            print(f"   {len(probes)} probes")
            per_state.clear()
            for probe in probes:
                key = probe.family or probe.id
                # Checked *before* the command runs. A cap enforced after the
                # capture spends a VM round trip to throw the result away, and
                # at ~2,000 round trips a run that is most of the wall clock.
                if per_state[key] >= family_cap:
                    continue
                per_state[key] += 1
                emit(plant.name, probe, run_probe(vm, probe), ident, image, host)
            print(f"   written so far: {stats.written}")

        # The matched negative. Everything is gone; ask the same questions.
        print("\n== state reverted (removing everything, then re-probing)")
        findings = revert(vm, restore_hostname=None)
        if findings:
            raise RuntimeError("revert incomplete: " + "; ".join(findings))
        vm.must(["hostnamectl", "set-hostname", fmt.HOSTNAME_POOL[0] + "-clean"],
                timeout=30)
        ident = discover_identity(vm, boot_hostname=original_hostname)
        image, host = _header_for(vm, "reverted")
        probes = ([p for p in static_probes() if p.applies("reverted")]
                  + discovered_probes(vm, "reverted",
                                      unit_cap=max(8, unit_cap // 4),
                                      path_cap=max(8, path_cap // 4),
                                      pid_cap=max(8, pid_cap // 4),
                                      offset=len(states)))
        print(f"   {len(probes)} probes")
        per_state.clear()
        for probe in probes:
            key = probe.family or probe.id
            if per_state[key] >= family_cap:
                continue
            per_state[key] += 1
            emit("reverted", probe, run_probe(vm, probe), ident, image, host)
    finally:
        print("\n== final revert")
        findings = revert(vm, restore_hostname=original_hostname)
        if findings:
            print("  REVERT INCOMPLETE -- the VM is not as it was found:")
            for item in findings:
                print(f"    {item}")
        else:
            print(f"  clean; hostname restored to {original_hostname!r}")

    if probes_for_licences:
        stats_licences = copy_licences(vm, out, probes_for_licences)
        (out / "manifest.json").write_text(json.dumps({
            "generated_by": "scripts/generate_output_pairs.py",
            "vm": vm.name,
            "states": [p.name for p in states] + ["reverted"],
            "documents": stats.written,
            "chars": stats.chars,
            "captures": stats.captures,
            "verdicts": dict(stats.verdicts),
            "families": dict(sorted(stats.families.items())),
            "exit_zero": stats.exit_zero,
            "exit_nonzero": stats.exit_nonzero,
            "timeouts": stats.timeouts,
            "dropped": {
                "duplicate_shape": stats.dropped_duplicate,
                "too_short": stats.dropped_short,
                "identity_leak": stats.dropped_leak,
                "parser_disagreement": stats.dropped_disagreement,
                "refused_content": stats.dropped_secret,
                "over_reader_ceiling": stats.dropped_oversize,
            },
            "refused_content": stats.secrets,
            "parser_disagreements": stats.disagreements,
            "licences": stats_licences,
            "vm_calls": vm.calls,
        }, indent=2), encoding="utf-8")
    return stats


# --------------------------------------------------------------------------
# Measurement
# --------------------------------------------------------------------------

def measure_repetition(out: Path) -> dict[str, Any]:
    """Distinct literals and the maximum per-literal document frequency.

    The number the privacy audit used to quantify the Mac-generated
    trajectories' overfit: **253 distinct literals repeated a mean 947 times
    each, ~89% of which appear nowhere else in 625 MB.** Reported here so the
    claim that generating in a VM fixes the overfit is a measurement and not an
    argument.

    **Measured over the captured output only, not the whole document.** The
    first version of this function counted every token in the file and
    confidently reported a maximum document frequency of 1.00 -- a literal in
    every single document. The literal was ``exit:``. Every document carries
    the same scaffold by construction, so including it measures the format and
    not the data, and a ruler that cannot distinguish "the word *verdict*
    appears in all 513 documents" from "this machine's MAC appears in all 513
    documents" is not measuring overfit at all. The scaffold is also the one
    part a tokenizer *should* see repeatedly: it is the protocol.

    A "literal" is a whitespace-separated token of four characters or more
    containing an alphanumeric -- deliberately crude, and deliberately the same
    crudeness as the audit's, because the comparison is between two corpora
    under one ruler rather than between two rulers.
    """
    doc_freq: Counter = Counter()
    whole_freq: Counter = Counter()
    shape_freq: Counter = Counter()
    docs = 0
    unreadable = 0
    for path in sorted(out.glob(fmt.PAIR_GLOB)):
        text = path.read_text(encoding="utf-8", errors="replace")
        whole_freq.update({t for t in text.split()
                           if len(t) >= 4 and any(c.isalnum() for c in t)})
        try:
            parsed = fmt.read_pair(text)
        except ValueError:
            unreadable += 1
            continue
        docs += 1
        observed = f"{parsed['stdout']}\n{parsed['stderr']}"
        doc_freq.update({t for t in observed.split()
                         if len(t) >= 4 and any(c.isalnum() for c in t)})
        shape_freq[fmt.skeleton(f"{parsed['probe']}\n{observed}")] += 1
    if not docs or not doc_freq:
        return {"documents": docs, "unreadable": unreadable}
    repeated = {t: n for t, n in doc_freq.items() if n > 1}
    top = doc_freq.most_common(1)[0]
    whole_top = whole_freq.most_common(1)[0]
    shapes = len(shape_freq)
    return {
        # Measured over the captured output, for the reason the dedup gate
        # gives: a rate computed over the whole document measures the header.
        "duplicate_output_rate": round(1 - shapes / docs, 4),
        "distinct_output_shapes": shapes,
        "documents": docs,
        "unreadable_as_pair": unreadable,
        "distinct_output_literals": len(doc_freq),
        "output_literals_in_more_than_one_document": len(repeated),
        "max_output_document_frequency": top[1],
        "max_output_document_frequency_share": round(top[1] / docs, 4),
        "mean_output_document_frequency": round(
            sum(doc_freq.values()) / len(doc_freq), 2),
        "mean_of_repeated_output_literals": round(
            sum(repeated.values()) / len(repeated), 2) if repeated else 0.0,
        # Kept visible so nobody has to rediscover why the two differ.
        "max_whole_document_frequency_incl_scaffold": whole_top[1],
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", type=Path,
                   default=Path("data/corpus/raw/outputpairs"),
                   help="cache directory the source adapter reads")
    p.add_argument("--vm", default=os.environ.get("WHETSTONE_PAIRS_VM",
                                                  "whetstone-lab"))
    p.add_argument("--lima-home",
                   default=str(lima_home()))
    p.add_argument("--momus", type=Path, default=_MOMUS_DEFAULT,
                   help="checkout whose adapters/lima.py provides the labels")
    p.add_argument("--unit-cap", type=int, default=45)
    p.add_argument("--path-cap", type=int, default=120)
    p.add_argument("--pid-cap", type=int, default=60)
    p.add_argument("--family-cap", type=int, default=45,
                   help="probes per family PER STATE, so one shape cannot "
                        "crowd out the rest")
    p.add_argument("--revert-only", action="store_true",
                   help="remove any leftover plant and exit")
    p.add_argument("--dry-run", action="store_true",
                   help="print the static catalogue and exit; touches nothing")
    args = p.parse_args(argv)

    if args.dry_run:
        probes = static_probes() + per_account_probes("audit-armed")
        print(f"{len(probes)} static probes")
        for probe in probes:
            print(f"  {probe.id:44s} {probe.label:16s} "
                  f"{'aligned' if probe.aligned else '':8s} "
                  f"{' '.join(probe.argv)[:70]}")
        return 0

    vm = VM(args.vm, str(args.lima_home))
    if args.revert_only:
        findings = revert(vm, restore_hostname=None)
        print("revert findings:" if findings else "revert clean")
        for item in findings:
            print(f"  {item}")
        return 1 if findings else 0

    lima = load_momus(args.momus)
    labels = Labels(lima, wlinux)
    needles = host_needles()
    if needles.gaps():
        raise SystemExit(
            "the identity needle table is incomplete: "
            f"{needles.gaps()}. An empty table means nothing is being looked "
            "for, and a generator that wrote documents past it would be the "
            "verifier-that-read-zero-bytes bug again.")
    print(f"needles: {needles}")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for stale in out.glob(fmt.PAIR_GLOB):
        stale.unlink()

    audit_baseline(vm)
    started = time.monotonic()
    stats = generate(vm, out, labels, states=plant_sequence(),
                     unit_cap=args.unit_cap, path_cap=args.path_cap,
                     pid_cap=args.pid_cap, family_cap=args.family_cap,
                     needles=needles)
    elapsed = time.monotonic() - started

    rep = measure_repetition(out)
    print("\n" + "=" * 68)
    print(f"captures              {stats.captures}")
    print(f"documents written     {stats.written}")
    print(f"characters            {stats.chars:,}")
    print(f"exit 0 / non-zero     {stats.exit_zero} / {stats.exit_nonzero}"
          f"  (+{stats.timeouts} transport timeouts)")
    print(f"verdicts              {dict(stats.verdicts)}")
    print(f"distinct output shapes {stats.written - 0} written, "
          f"{stats.dropped_duplicate} duplicate captures refused")
    print(f"dropped: dup {stats.dropped_duplicate}  short {stats.dropped_short}"
          f"  leak {stats.dropped_leak}  disagreement "
          f"{stats.dropped_disagreement}  refused-content {stats.dropped_secret}"
          f"  oversize {stats.dropped_oversize}")
    print(f"vm calls              {vm.calls} in {elapsed:.0f}s")
    print("-" * 68)
    for key, value in rep.items():
        print(f"{key:40s} {value}")
    if stats.disagreements:
        print("-" * 68)
        print("PARSER DISAGREEMENTS (documents dropped, findings kept):")
        for item in stats.disagreements[:40]:
            print(f"  {item}")
    if stats.leaks:
        print("-" * 68)
        print("DOCUMENTS REFUSED FOR CARRYING AN IDENTIFIER (fingerprints only):")
        for item in stats.leaks[:20]:
            print(f"  {item}")
    print("=" * 68)
    manifest = out / "manifest.json"
    if manifest.is_file():
        data = json.loads(manifest.read_text())
        data["repetition"] = rep
        data["elapsed_seconds"] = round(elapsed, 1)
        manifest.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
