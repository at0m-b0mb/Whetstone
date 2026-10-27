"""Command, real output, machine-checked parse — the triple the runtime reads.

This is the register gap nothing public fills. The corpus has thousands of
pages of *usage* text — :mod:`~training.corpus.sources.manpages`,
:mod:`~training.corpus.sources.tldr`, :mod:`~training.corpus.sources.lolbas`,
:mod:`~training.corpus.sources.gtfobins` all teach what a command *is* and what
flags it takes — and almost no *output* text. Yet reading output is what the
runtime does on every single step. ``recon.sudo_rights`` does not emit a
command and stop; it runs ``sudo -n -l``, gets back some lines, and has to say
whether this account can reach root. A model trained on usage text and no
output text has read the whole manual and never seen a screen.

**It also fixes a measured overfit.** The privacy audit measured
``trajectories.jsonl`` as 20.64% this-one-machine: **253 distinct literals
repeated a mean 947 times each, ~89% of which appear nowhere else in 625 MB.**
Those are not observations the model can generalise from, they are one Mac's
service list memorised. Output generated inside a disposable Linux VM has
neither problem: it is genuinely Linux rather than Linux-labelled, and it
carries none of the operator's identifiers because they were never in the VM.

**The failure cases are the point, not the garnish.** A model that has only
seen success output reads a refusal as a negative, and that single confusion is
the most expensive mistake an agent pointed at someone else's machine can make.
So every probe family here carries its refusals:

* ``sudo -n -l`` printing ``sudo: a password is required`` is an **unfinished
  enumeration**, not "no NOPASSWD rule exists". Measured on this image, an
  account with no sudo rules at all and an account with a password-required
  rule produce the *identical* message — so the output genuinely cannot
  distinguish them, and a corpus that only ever showed the enumerated form
  would teach the model that it can.
* ``crontab -l`` for an account with no crontab writes ``no crontab for X`` to
  **stderr** and exits 1, leaving stdout empty. Read as stdout alone that is
  indistinguishable from an empty crontab, which is a different fact.
* ``systemctl show nosuch.service`` exits **0** and prints ``Id=nosuch.service``
  with an empty ``FragmentPath``. A caller checking the exit code concludes the
  unit exists.
* ``find`` matching nothing exits 0 with no output — *nothing there*. ``find``
  denied a directory exits 1 having printed the matches it could reach —
  *partly could not tell*. The two look similar and mean opposite things.

So each document carries an explicit ``verdict`` of ``found`` / ``absent`` /
``inconclusive`` / ``error``, which is exactly the distinction the kernel's
``Observation`` has to make, written down next to the bytes that justify it.

**Register: SHELL.** The document is a shell transcript — a prompt, an argv, the
bytes that came back, an exit status — and SHELL is the register that is 15.6%
against a 26% target, the widest gap the balance report shows.
:mod:`~training.corpus.source` names command output under SHELL and SYSTEM
jointly ("the registers the model must both read (command output) and reason
about"), and SYSTEM is the one already far *over* its target. DETECTION was the
other candidate for the ``journalctl`` and ``audit.log`` probes, on
:mod:`~training.corpus.sources.logsamples`' vocabulary argument, and is
deliberately not taken: logsamples already owns raw record formats at a volume
this source will never reach and does it better. What this source adds for
those probes is not the record format, it is *the transcript around it* — which
command produced the records, what the exit status was, and what the parse
made of them. That is a SHELL surface form.

**Side: NEUTRAL.** ``sudo -n -l`` and ``find / -perm -4000`` read to red as an
opportunity and to blue as a misconfiguration; the skill being taught is
reading, which is neither. Filing them RED to flatter the 60/40 offence share
would corrupt the one measurement the balance report depends on — the same
discipline :mod:`~training.corpus.sources.logsamples` applies in the other
direction.

**What this source deliberately is not.** It collects *semantics* — what a
command returns and how to read it — not payloads. When the generator plants a
sudo rule in order to produce a real enumerated ``sudo -n -l``, the document
shows the rule and the parse; it does not show the escape. The escape for a
sudo-reachable binary is already in this corpus, in ``gtfobins``, where a
catalogue belongs: **the catalogue holds the code, the model holds the
judgement.** A document here that appended "and therefore run ..." would be
teaching the model to generate the payload instead of to read the output, which
is the one thing the project's boundary rests on not doing.

**Licence, honestly.** The text is machine state, produced by running commands
in a disposable Ubuntu VM. Program *output describing a machine* is not a
derivative work of the program — the FSF states this plainly for the GPL — and
the generator therefore stays strictly on the state side of that line:

* captured: what the kernel and userland report about *this* machine (``id``,
  ``ps``, ``ip``, ``ss``, ``stat``, ``find``, ``systemctl show``, ``/proc``,
  ``journalctl``, ``audit.log``);
* **not** captured: program *text* — ``--help`` and usage output, man pages,
  ``dpkg -l``'s package Description column, and the bodies of configuration
  files shipped by packages. Those are the programs' own copyrighted words,
  this corpus already has the first two under their real licences, and the
  third would have smuggled ~40 KB of several hundred packages' description
  text in under a licence line that does not cover it;
* the only configuration file bodies captured are ones the **generator itself
  wrote** (its sudoers drop-in, its cron drop-in, its unit file).

Short diagnostic strings (``cat: /etc/shadow: Permission denied``) are
reproduced as the de-minimis fragments they are, and they are the single most
load-bearing text in the source.

**Produced, never fetched.** Like :mod:`~training.corpus.sources.trajectories`,
``_fetch`` refuses rather than generating: a corpus build that silently booted
a VM and ran commands in it would be an extraordinary thing for a build to do.
Run ``scripts/generate_output_pairs.py`` when you mean to.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Iterator, Mapping, Sequence

from ..source import Document, Register, Side, SourceError, SourceSpec, normalise

__all__ = [
    "SPEC",
    "VERDICTS",
    "PAIR_GLOB",
    "ACCOUNT_POOL",
    "SUBSTITUTE_ACCOUNTS",
    "SUBSTITUTE_HOSTS",
    "HOSTNAME_POOL",
    "DOC_V4_NETS",
    "DOC_MAC_PREFIX",
    "DOC_V6_PREFIX",
    "render_pair",
    "read_pair",
    "skeleton",
    "fit",
    "varied",
    "substitution_plan",
    "apply_plan",
    "generic_reading",
]

#: The four answers an observation can carry, and the reason this source
#: exists. ``absent`` and ``inconclusive`` are the pair that matters: "I looked
#: and there is nothing" versus "I could not look". Every bench failure this
#: project has had in the ``attck-real`` family is a model collapsing those two.
VERDICTS = ("found", "absent", "inconclusive", "error")

PAIR_GLOB = "pair-*.txt"

_MIN_CHARS = 150

#: Hard ceiling on one captured document. A ``journalctl`` or ``audit.log``
#: slice can be arbitrarily long and a single 2 MB document is a memorisation
#: hazard wearing a volume costume, not a reading exercise.
#:
#: 32,000 is where two real outputs sit: ``dpkg-query -W`` over 676 packages is
#: 31 KB and ``systemctl list-unit-files`` over 388 units is 30 KB. Both are
#: whole-machine inventories, there is one of each per state, and a ceiling that
#: cut them would be cutting the two documents that show what a *complete*
#: answer looks like. ``ls -la /usr/bin`` is 61 KB and is excluded in the
#: generator instead, because that one is 3% of the source in a single file.
#:
#: The generator enforces the same number. It has to: a reader that silently
#: drops what a writer happily wrote is how 1,024 written documents became
#: 1,018 read ones with nothing saying so, which is the same family of bug as a
#: verifier that reports clean having read no bytes.
_MAX_CHARS = 32_000


# ---------------------------------------------------------------------------
# The document format.
#
# One shape, written by the generator and read back by the tests, so the format
# has exactly one definition. The generator owns the VM; this module owns the
# bytes. A format described in a docstring and implemented twice is a format
# that drifts, and the two halves here are four days of debugging apart.
# ---------------------------------------------------------------------------

_HEADER_KEYS = ("image", "host", "state", "account", "probe", "question")
_PROMPT = "$ "
_STDERR_MARK = "--- stderr"
_NO_STDOUT = "(no stdout)"
_EXIT_MARK = "exit: "
_PARSE_MARK = "parse: "
_VERDICT_MARK = "verdict: "
_READING_MARK = "reading: "
_BANNER = "# whetstone output-pair"


def render_pair(*, image: str, host: str, state: str, account: str,
                probe: str, question: str, argv: Sequence[str],
                stdout: str, stderr: str, exit_code: int,
                parser: str, parse: object, verdict: str,
                reading: str) -> str:
    """One capture as one document. Pure; no I/O, no VM, no clock.

    The argv list is printed *as JSON as well as* as a prompt line, and that
    redundancy is the pedagogy. Momus — the sibling attacker this corpus
    serves — emits a verb id and typed params and never a shell string; there
    is no ``run.shell`` and a test asserts none is ever added, because a gate
    can reason about a verb and cannot reason about an opaque command. So the
    mapping the model needs is *argv list to transcript*, in both directions,
    and a document that showed only the rendered prompt would teach it the
    wrong half.

    ``exit`` is always present and ``(no stdout)`` is explicit, because the
    absence of a line is not a token a model can condition on: a capture with
    empty stdout and a capture whose stdout section was simply omitted are
    indistinguishable to a next-token predictor, and they are the ``absent``
    versus ``inconclusive`` distinction again at the level of the file format.
    """
    if verdict not in VERDICTS:
        raise ValueError(f"unknown verdict {verdict!r}; expected one of {VERDICTS}")
    lines = [_BANNER]
    for key, value in (("image", image), ("host", host), ("state", state),
                       ("account", account), ("probe", probe),
                       ("question", question)):
        lines.append(f"{key}: {_oneline(value)}")
    lines.append(f"argv: {json.dumps(list(argv))}")
    lines.append("")
    lines.append(_PROMPT + _shell(argv))
    body = stdout.rstrip("\n")
    lines.append(body if body else _NO_STDOUT)
    err = stderr.rstrip("\n")
    if err:
        lines.append(_STDERR_MARK)
        lines.append(err)
    lines.append(f"{_EXIT_MARK}{exit_code}")
    lines.append("")
    # The probe is on the parse line as well as in the header, and that is not
    # redundancy for its own sake. ``parse: momus.adapters.lima._parse_
    # systemctl_show`` on its own is 46 characters, 85% alphabetic, and appeared
    # in 337 documents -- which is exactly what training/corpus/boilerplate.py
    # exists to strip, and it stripped it, leaving a JSON block with no
    # statement of what produced it. Naming the probe makes the line specific to
    # the question it answers, which is both more informative and under the
    # filter's 25-document threshold.
    lines.append(f"{_PARSE_MARK}{parser} on {probe}")
    lines.append(json.dumps(parse, indent=2, sort_keys=True, default=str))
    lines.append(f"{_VERDICT_MARK}{verdict}")
    lines.append(f"{_READING_MARK}{_oneline(reading)}")
    return normalise("\n".join(lines))


def read_pair(text: str) -> dict[str, object]:
    """Inverse of :func:`render_pair`, to the extent a lossless one exists.

    Exists so the tests can assert a round trip rather than assert against a
    hand-typed expected string, which is how a format test comes to pass while
    the format is wrong. It is also the reader a later consumer gets for free
    — a bench that wants to ask "given this output, what is the verdict" needs
    the fields apart again.

    Not lossless in one respect, stated rather than hidden: ``stdout`` that was
    literally ``(no stdout)`` is read back as empty. The generator never
    produces that stdout, and paying for an escape hatch to represent a capture
    that cannot occur would complicate the format for every document.
    """
    out: dict[str, object] = {}
    lines = text.split("\n")
    if not lines or lines[0].strip() != _BANNER:
        raise ValueError("not an output-pair document: missing banner")
    i = 1
    while i < len(lines) and lines[i].strip():
        key, _, value = lines[i].partition(":")
        key = key.strip()
        if key == "argv":
            out["argv"] = json.loads(value.strip())
        elif key in _HEADER_KEYS:
            out[key] = value.strip()
        i += 1
    while i < len(lines) and not lines[i].strip():
        i += 1
    if i >= len(lines) or not lines[i].startswith(_PROMPT):
        raise ValueError("output-pair document has no prompt line")
    out["command"] = lines[i][len(_PROMPT):]
    i += 1

    stdout: list[str] = []
    stderr: list[str] = []
    sink = stdout
    exit_code: int | None = None
    while i < len(lines):
        line = lines[i]
        if line == _STDERR_MARK:
            sink = stderr
            i += 1
            continue
        if line.startswith(_EXIT_MARK):
            exit_code = int(line[len(_EXIT_MARK):].strip())
            i += 1
            break
        sink.append(line)
        i += 1
    if exit_code is None:
        raise ValueError("output-pair document has no exit line")
    body = "\n".join(stdout).strip("\n")
    out["stdout"] = "" if body == _NO_STDOUT else body
    out["stderr"] = "\n".join(stderr).strip("\n")
    out["exit"] = exit_code

    rest = "\n".join(lines[i:])
    parser = re.search(rf"^{re.escape(_PARSE_MARK)}(.*)$", rest, re.M)
    verdict = re.search(rf"^{re.escape(_VERDICT_MARK)}(.*)$", rest, re.M)
    reading = re.search(rf"^{re.escape(_READING_MARK)}(.*)$", rest, re.M)
    raw_parser = parser.group(1).strip() if parser else ""
    out["parser"] = raw_parser.split(" on ")[0] if raw_parser else ""
    out["verdict"] = verdict.group(1).strip() if verdict else ""
    out["reading"] = reading.group(1).strip() if reading else ""
    if parser and verdict:
        blob = rest[parser.end():verdict.start()].strip()
        try:
            out["parse"] = json.loads(blob)
        except json.JSONDecodeError:
            out["parse"] = None
    return out


def _oneline(value: str) -> str:
    """Header values are one line. A newline in one would break the reader."""
    return " ".join(str(value).split())


_SAFE = re.compile(r"^[A-Za-z0-9_@%+=:,./-]+$")


def _shell(argv: Sequence[str]) -> str:
    """Render an argv list as the prompt line a human would have typed.

    Quoted only where quoting is *needed*, which keeps the common case looking
    like a real transcript instead of like generated text. The project never
    executes this string — it exists to be read.
    """
    out = []
    for part in argv:
        token = str(part)
        if token and _SAFE.match(token):
            out.append(token)
        else:
            out.append("'" + token.replace("'", "'\\''") + "'")
    return " ".join(out)


# ---------------------------------------------------------------------------
# Near-duplicate detection.
# ---------------------------------------------------------------------------

_DIGITS = re.compile(r"\d+")
_HEXRUN = re.compile(r"\b[0-9a-f]{8,}\b", re.I)
_GUID = re.compile(r"\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?", re.I)


def skeleton(text: str) -> str:
    """A shape key: letters kept, digits and hex runs erased.

    The same argument :mod:`~training.corpus.sources.logsamples` makes about
    telemetry applies to ``/proc/<pid>/status`` and to ``journalctl``: the
    hundredth record differs from the first only in a pid, a timestamp and a
    GUID, and emitted whole it is volume without information. Two captures with
    the same skeleton are one example; two with different ``CommandLine`` or
    different mode bits are two.

    Order matters here and it matters in one direction only — GUIDs first, then
    hex runs, then digits — because a GUID partly eaten by the digit rule
    leaves a different residue depending on which ran first, and a dedup key
    that depends on rule ordering is a dedup key that changes when somebody
    tidies the function.
    """
    shaped = _GUID.sub("G", text)
    shaped = _HEXRUN.sub("H", shaped)
    shaped = _DIGITS.sub("N", shaped)
    return hashlib.sha256(shaped.encode("utf-8")).hexdigest()[:24]


# ---------------------------------------------------------------------------
# The varied vocabularies.
#
# The audit's sharpest finding, and the one that is easiest to get wrong while
# feeling responsible: **privacy is satisfied by any substitution, while
# generalisation needs a varied one.** A single <HOST> token passes every
# privacy gate in this tree and makes the model worse, because it replaces one
# memorised literal with one *more frequent* memorised literal. So every
# replacement here comes from a pool, and the pool is chosen so that no
# document's replacement is predictable from another's.
#
# The second rule is less obvious and was learned from normalise(): the
# replacement must have **the same length as what it replaces** wherever the
# output is column-aligned. `ss`, `ps -ef` and `ps -eo user:20=` pad columns to
# a width the command computed from the real string; substituting a shorter one
# leaves the row shifted relative to its own header. Column alignment is the
# single best-scoring register this project has measured (+47% against gpt2 on
# netstat rows), so corrupting it to protect a VM's DHCP lease would be trading
# the thing we came for.
# ---------------------------------------------------------------------------

#: Accounts the generator *creates in the VM*. Real accounts, so their output
#: is real: ``id`` run as one of these prints its genuine uid and groups.
#: Chosen to avoid every account on an Ubuntu 24.04 cloud image.
ACCOUNT_POOL = (
    "svcops", "deploy", "webapp", "logship", "analyst", "batchjob",
    "ci-runner", "metrics", "backupd", "queueworker",
)

#: Replacements for the one account name the VM did not choose: Lima names the
#: guest user after the *host* user, so the operator's account name is in
#: ``id``, ``getent passwd``, ``ps``, the home path and every ``audit.log``
#: ``UID=`` field. Disjoint from :data:`ACCOUNT_POOL` so a document can never
#: show the substituted account and a created account under one name.
SUBSTITUTE_ACCOUNTS = (
    "svc-collector", "svc-telemetry", "app-telemetry", "ops-collector",
    "data-pipeline", "log-forwarder", "job-scheduler", "web-frontend",
    "mail-relay", "cache-warmer", "index-builder", "report-runner",
)

#: Hostnames the generator *sets on the VM* with ``hostnamectl``, so ``sudo``,
#: ``journalctl`` and ``audit.log`` print a real hostname that happens to vary.
#: Genuinely changing it beats substituting it: no length constraint, no risk
#: of a half-rewritten record, and the output is what the machine said.
HOSTNAME_POOL = (
    "lab-07", "web-03", "build-11", "db-02", "edge-09",
    "ci-runner-4", "app-15", "log-01",
)

#: Replacements for a hostname the generator did **not** choose — the name the
#: VM was booted with, which survives in journal and audit records written
#: before the first ``hostnamectl`` call. Longer than :data:`HOSTNAME_POOL`
#: because a Lima instance name is long (``lima-whetstone-lab`` is eighteen
#: characters) and :func:`fit` padding a six-character name out to eighteen
#: produces something no machine has ever been called.
SUBSTITUTE_HOSTS = (
    "app-prod-eu-west-1", "build-agent-linux-7", "db-replica-east-02",
    "edge-cache-sfo-004", "ci-worker-arm64-11", "log-collector-az-3",
    "api-gateway-stage2", "batch-runner-pool8",
)

#: RFC 5737 documentation ranges. ``203.0.113.`` is exactly as long as this
#: image's ``192.168.5.``, which is why it is first: for the column-aligned
#: probes it is the only one that preserves the layout.
DOC_V4_NETS = ("203.0.113.", "198.51.100.", "192.0.2.")

#: RFC 7042 §2.1.2 reserves 00-00-5E-00-53-00 .. -FF for documentation. Same
#: 17 characters as any real MAC, so always length-safe.
DOC_MAC_PREFIX = "00:00:5e:00:53:"

#: RFC 3849.
DOC_V6_PREFIX = "2001:db8:"


def varied(pool: Sequence[str], salt: str) -> str:
    """Pick from *pool* by digest of *salt*. Deterministic, no RNG state.

    Deterministic because a regenerate must be reproducible and because a
    global ``random`` sequence makes the substitution of document 400 depend
    on how many documents 1..399 happened to need — which turns a one-probe
    change into a diff across the whole corpus.
    """
    if not pool:
        raise ValueError("empty pool")
    index = int(hashlib.sha256(salt.encode("utf-8")).hexdigest()[:8], 16)
    return pool[index % len(pool)]


def fit(base: str, length: int, salt: str) -> str:
    """*base* adjusted to exactly *length* characters.

    Truncation when it is too long, a deterministic digit suffix when it is too
    short. The pools above are sized so this is usually a no-op; it exists
    because the guest account name's length is whatever the operator's macOS
    account name happens to be, and a source module that assumed 13 would break
    on the next machine with no warning at all.
    """
    if length <= 0:
        return ""
    if len(base) == length:
        return base
    if len(base) > length:
        return base[:length]
    digest = hashlib.sha256(salt.encode("utf-8")).hexdigest()
    pad = length - len(base)
    tail = "".join(ch for ch in digest if ch.isdigit())[:pad]
    while len(tail) < pad:
        tail += "0"
    return base + tail


def substitution_plan(literals: Mapping[str, str], salt: str, *,
                      length_safe: bool = True) -> dict[str, str]:
    """Map each of the VM's own identifiers to a varied stand-in.

    ``literals`` is keyed by *kind* — ``account``, ``mac``, ``v4net``,
    ``v6``, ``machine-id``, ``boot-id`` — because the replacement for a MAC and
    the replacement for an account name are different *shapes*, and a
    kind-blind substituter is how you end up rewriting a hostname into
    something that is not a legal hostname.

    ``length_safe`` is the column-alignment switch. True keeps every
    replacement the same length as the original, which is mandatory for ``ss``
    and ``ps``; False lets the IPv4 replacement come from the whole of
    :data:`DOC_V4_NETS` instead of only the length-matching member, which buys
    three times the variety for the many probes with no columns to wreck.

    Returned longest-key-first so :func:`apply_plan` can substitute without a
    shorter key eating a prefix of a longer one — ``demo`` inside
    ``demo_operator`` is the exact shape of that bug.
    """
    plan: dict[str, str] = {}
    # A fixed kind order, not the caller's insertion order. ``v4addr`` reads
    # the replacement ``v4net`` was given so the two land in one /24, and a
    # mapping that happened to list the address first would silently produce a
    # document whose host and broadcast are on different networks.
    order = {"v4net": 0, "v4addr": 1}
    for kind, value in sorted(literals.items(),
                              key=lambda kv: (order.get(kv[0], 2), kv[0])):
        if not value:
            continue
        if kind == "account":
            plan[value] = fit(varied(SUBSTITUTE_ACCOUNTS, salt + value),
                              len(value), salt)
        elif kind == "hostname":
            plan[value] = fit(varied(SUBSTITUTE_HOSTS, salt + value),
                              len(value), salt)
        elif kind == "mac":
            octet = int(hashlib.sha256((salt + value).encode()).hexdigest()[:2], 16)
            plan[value] = f"{DOC_MAC_PREFIX}{octet:02x}"
        elif kind == "v4net":
            nets = DOC_V4_NETS if not length_safe else tuple(
                n for n in DOC_V4_NETS if len(n) == len(value)) or DOC_V4_NETS[:1]
            plan[value] = varied(nets, salt + value)
        elif kind == "v4addr":
            # Varied in the host octet, inside the /24 the prefix was mapped to,
            # and with the same number of digits.
            #
            # The prefix alone is not enough. Under ``length_safe`` only one
            # documentation range is the same length as this image's
            # ``192.168.5.`` -- RFC 5737 gives three prefixes of three
            # different lengths -- so the prefix substitution collapses onto a
            # single token for every column-aligned document, and the address
            # inside them would then be the *same* address every time: one
            # memorised literal traded for another, which is the exact mistake
            # the varied vocabularies exist to avoid.
            #
            # Varying the host octet instead gives ~90 two-digit values at no
            # cost to length, and it must happen inside the mapped /24 or the
            # document contradicts itself: an address in 198.51.100.0/24 whose
            # broadcast is 203.0.113.255 is not a machine anybody can read.
            host = value.rsplit(".", 1)[-1]
            net = value[: -len(host)]
            net_repl = plan.get(net) or varied(
                tuple(n for n in DOC_V4_NETS if len(n) == len(net))
                or DOC_V4_NETS[:1], salt + net)
            span = 10 ** len(host)
            low = 10 ** (len(host) - 1) if len(host) > 1 else 1
            pick = int(hashlib.sha256((salt + value).encode()).hexdigest()[:6], 16)
            octet = low + (pick % max(1, min(span, 255) - low))
            plan[value] = f"{net_repl}{octet}"
        elif kind == "v6":
            plan[value] = _v6_stand_in(value, salt)
        elif kind in ("machine-id", "boot-id"):
            digest = hashlib.sha256((salt + kind + value).encode()).hexdigest()
            plan[value] = digest[:len(value)]
        else:
            plan[value] = fit(varied(SUBSTITUTE_ACCOUNTS, salt + kind + value),
                              len(value), salt)
    return dict(sorted(plan.items(), key=lambda kv: -len(kv[0])))


def _v6_stand_in(value: str, salt: str) -> str:
    """A documentation IPv6 address of the same length as *value*.

    Link-local addresses on this image are EUI-64 derived from the MAC, so the
    honest stand-in is a ``fe80::`` address derived from the *replacement* MAC
    — but the two do not always render to the same number of characters,
    because IPv6 text form suppresses leading zeros in each group. Rather than
    choose a MAC that happens to round-trip, the groups are generated from the
    digest and then trimmed or padded to the original length. The result is a
    legal address in a reserved range, which is all a reader needs.
    """
    digest = hashlib.sha256((salt + value).encode()).hexdigest()
    prefix = "fe80::" if value.lower().startswith("fe80") else DOC_V6_PREFIX
    groups = [digest[i:i + 4] for i in range(0, 16, 4)]
    out = prefix + ":".join(groups)
    if len(out) > len(value):
        return out[:len(value)].rstrip(":")
    while len(out) < len(value):
        out += "0"
    return out


def apply_plan(text: str, plan: Mapping[str, str]) -> str:
    """Substitute every planned literal. Longest key first, one pass each.

    Plain :meth:`str.replace` per key rather than one regex alternation,
    because the regex version has to escape every literal and the one time
    somebody forgets, a MAC address's colons become a character class and the
    substitution silently stops matching. The plan is a handful of keys; this
    is not the hot loop.
    """
    for literal, replacement in plan.items():
        if literal:
            text = text.replace(literal, replacement)
    return text


# ---------------------------------------------------------------------------
# Readings.
# ---------------------------------------------------------------------------

_GENERIC_READINGS = {
    "found": ("The command answered the question and the parse below carries "
              "the answer."),
    "absent": ("The command ran, looked, and found nothing. This is a negative "
               "result, not a failure to look."),
    "inconclusive": ("This output does not answer the question. The command "
                     "could not complete the check, so neither a positive nor "
                     "a negative conclusion follows from it."),
    "error": ("The command itself failed. Nothing about the question can be "
              "concluded from this output."),
}


def generic_reading(verdict: str) -> str:
    """The fallback sentence for a verdict a probe authored no reading for.

    Deliberately says only what is mechanically true of the verdict and
    nothing about the subject matter. A probe-specific reading is better and
    the catalogue supplies one wherever the case is interesting; the fallback
    exists so that a verdict which turns up for the first time on some future
    image produces a correct dull sentence rather than a confident wrong one.
    A wrong gloss is worse than no gloss.
    """
    if verdict not in VERDICTS:
        raise ValueError(f"unknown verdict {verdict!r}")
    return _GENERIC_READINGS[verdict]


# ---------------------------------------------------------------------------
# The source.
# ---------------------------------------------------------------------------

def _fetch(cache_dir: Path) -> Path:
    """No download and no generation. Refuses, with the command to run.

    Same contract as :mod:`~training.corpus.sources.trajectories` and for the
    same reason: a build that generated this source on demand would boot a
    virtual machine, create accounts in it, plant a sudoers drop-in and revert
    all of it, as a side effect of somebody asking for a corpus. That is a
    surprising thing for a build to do.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    if not any(cache_dir.glob(PAIR_GLOB)):
        raise SourceError(
            f"no output pairs under {cache_dir}. Generate them first:\n"
            "    python3 scripts/generate_output_pairs.py --out "
            f"{cache_dir}\n"
            "This source is produced by running real commands in a disposable "
            "Linux VM, not downloaded, and it is not generated implicitly by a "
            "corpus build."
        )
    return cache_dir


def _documents(path: Path) -> Iterator[Document]:
    """Walk the cache and yield one document per capture.

    ``os.walk(followlinks=False)``, never ``rglob``. The precedent is on the
    record in this package: ``ownrepos`` once followed this repo's ``data``
    symlink into the SSD and pulled the corpus cache back in as PROSE — the
    corpus ate itself and only the balance report noticed.
    """
    for dirpath, dirnames, filenames in os.walk(path, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames
                             if not Path(dirpath, d).is_symlink()
                             and d != "licenses")
        for filename in sorted(filenames):
            if not filename.startswith("pair-") or not filename.endswith(".txt"):
                continue
            file = Path(dirpath, filename)
            if file.is_symlink():
                continue
            try:
                raw = file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            text = normalise(raw)
            if len(text) < _MIN_CHARS or len(text) > _MAX_CHARS:
                continue
            yield Document(text=text, source="outputpairs",
                           register=Register.SHELL, side=Side.NEUTRAL,
                           ident=file.stem)


SPEC = SourceSpec(
    name="outputpairs",
    license=(
        "Generated locally by this repository (MIT) by running commands in a "
        "disposable Ubuntu 24.04 LTS Lima VM and recording what they printed. "
        "The text is machine state, not program text: program output describing "
        "a machine is not a derivative work of the program (the FSF states this "
        "for the GPL, and the Ubuntu image's packages are GPL/LGPL/BSD/MIT). "
        "Usage and --help output, man pages, dpkg package descriptions and the "
        "bodies of package-shipped config files are deliberately NOT captured, "
        "because those ARE the programs' own copyrighted text; the only config "
        "bodies present are ones the generator itself wrote. Short diagnostic "
        "strings ('Permission denied') are reproduced de minimis. The VM's "
        "provenance and the package copyright files for every binary invoked "
        "are copied into the cache under licenses/ so this claim is checkable "
        "against what produced the data."
    ),
    url="local: python3 scripts/generate_output_pairs.py",
    register=Register.SHELL,
    side=Side.NEUTRAL,
    fetch=_fetch,
    documents=_documents,
    expect_min_docs=400,
    notes=(
        "Command, verbatim output, exit code and a machine-checked parse, "
        "generated in a Linux VM rather than on the operator's Mac. Closes the "
        "corpus's largest hole — it has usage text and almost no output text — "
        "and carries the failure cases on purpose: a refusal, a denial, an "
        "empty result and a timeout each look different and mean different "
        "things, and a model trained on success output alone reads a refusal "
        "as a negative. Every document states a verdict of found / absent / "
        "inconclusive / error, which is the distinction the kernel's "
        "Observation has to make."
    ),
)
