"""The audit log: an append-only, hash-chained record of everything decided.

Two audiences read this file and they want different things, which is why it is
JSONL rather than prose.

A **human** reads it after the fact to answer "what did this thing do on my
network, and who said it could?". For that it needs to be complete, ordered, and
hard to quietly edit — hence the hash chain. Each record commits to the previous
record's digest, so removing or altering an entry breaks every link after it and
:func:`verify` says exactly where.

A hash chain cannot see its own tail being cut off. Every prefix of a valid chain
is itself a valid chain, so ``head -n -2`` deletes the two most incriminating
records — the ones written last, describing whatever the agent had just been
allowed to do — and verification stays green. That is the exact opposite of the
property this file exists for, so the log's length is committed *outside* the
log, in a sidecar ``<log>.anchor`` rewritten after every append.
:func:`verify` fails when the log is shorter than its anchor, and
:class:`AuditLog` refuses to append to a log that has fallen behind its anchor
rather than quietly starting a shorter history on top of the deletion.

Be exact about what that buys, because overstating it is how a log stops being
believed. This is tamper-EVIDENT, not tamper-proof. An attacker who can write to
the directory can rewrite the log and the anchor together and nothing local will
notice — no purely local scheme can stop that, and a scheme that claimed to would
be lying. What the anchor does is raise the cost from "truncate one file" to
"rewrite two files consistently", catch every truncation that is not a deliberate
attack on this specific design (a killed process, a partial copy, a rotation
script, a full disk), and give the operator a single value they can carry off the
box. :func:`verify` takes ``expect_seq`` and ``expect_tip`` so that a tip pinned
in a ticket at the end of an engagement can be checked against the file
afterwards; that off-box copy is the only version of this an attacker on the box
cannot reach.

The log is also, sometimes, a credential store. ``postex.credential_dump`` with
``redact=false`` writes recovered password hashes straight into an observation
record, and the adapters say so in as many words when they return it. So the log
and its anchor are created 0600, in a 0700 directory when this module creates the
directory, rather than inheriting whatever umask the operator happened to have;
and a log that already exists wider than that is narrowed before anything is
written to it.

The **training pipeline** reads it to learn. Every decision the gate makes is a
labelled example of a proposal and its correctness, and every observation is a
labelled example of an action and its result. This is the loop that makes the
model improve: the agent works, the log records what actually happened, and what
actually happened is ground truth in a way no judge model's opinion ever is. It
is worth being clear that this is the *only* mechanism by which Whetstone learns
from its own behaviour — weights are never touched at runtime.

Because the log is training data, its schema is stable and its fields are
explicit. A log you cannot parse in a year is a training set you do not have.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping

__all__ = ["AuditLog", "AuditRecord", "AuditError", "GENESIS", "verify"]


class AuditError(RuntimeError):
    """The log is unreadable, or its chain does not verify."""


#: The chain's anchor. The first record's ``prev`` is this rather than null, so
#: that a file whose first line was deleted is distinguishable from a fresh one.
GENESIS = "0" * 64

#: Fields excluded from the digest because they are computed from it.
_UNHASHED = frozenset({"hash"})

#: Modes for the log, its anchor, and any directory this module creates for
#: them. Not umask defaults, on purpose: ``redact=false`` puts recovered
#: password hashes into an observation record, and a credential store whose
#: permissions depend on whichever umask the operator happened to be running
#: under is not a credential store.
_FILE_MODE = 0o600
_DIR_MODE = 0o700

#: Suffix of the sidecar that commits to the log's length. It lives beside the
#: log rather than inside it because no record inside a file can say anything
#: about records deleted after it.
_ANCHOR_SUFFIX = ".anchor"


def _anchor_path(path: Path) -> Path:
    """Sidecar for ``path``: ``run.jsonl`` anchors in ``run.jsonl.anchor``.

    Suffix appended rather than substituted, so that ``run.jsonl`` and
    ``run.json`` cannot end up sharing one anchor and accusing each other.
    """
    return path.with_name(path.name + _ANCHOR_SUFFIX)


def _restrict(path: Path) -> None:
    """Narrow an existing file to owner-only, or refuse to use it at all.

    Called for the log and its anchor before either is written to. A file this
    module creates is already 0600 because ``os.open`` takes the mode at
    creation; this exists for a file that was there first — one written by an
    older Whetstone under a 022 umask, or one an attacker pre-created wide
    precisely so that it would stay readable once the hashes landed in it.

    It raises rather than warning when the mode cannot be narrowed. The
    alternative is writing ``/etc/shadow`` hashes into a world-readable file and
    saying nothing, which is the failure this project cares most about avoiding:
    a wrong state nobody notices. If the log has to live somewhere that does not
    enforce permissions, that is a call to make deliberately by choosing a
    different path, not one to discover from someone else's ``cat``.

    Windows is skipped entirely. ``os.chmod`` there only toggles the read-only
    bit and the POSIX bits ``stat`` reports are fiction, so checking them would
    be theatre that reports success it has not achieved; on Windows the
    containing directory's ACL is what protects the log.
    """
    if os.name != "posix" or not path.exists():
        return
    if not path.stat().st_mode & 0o077:
        return
    try:
        path.chmod(_FILE_MODE)
    except OSError as exc:
        raise AuditError(
            f"{path} is readable by other users and cannot be narrowed ({exc}). "
            "This log can hold recovered credentials, so it is not written to "
            "until it is owner-only — choose a path on a filesystem that "
            "enforces permissions."
        ) from None
    if path.stat().st_mode & 0o077:
        # chmod on a filesystem without real modes (an exFAT stick, some network
        # mounts) succeeds and changes nothing. Reading the mode back is the only
        # way to tell that apart from having actually secured the file.
        raise AuditError(
            f"{path} is still readable by other users after chmod 0600 — this "
            "filesystem does not enforce modes. This log can hold recovered "
            "credentials, so it is not written somewhere that cannot protect "
            "it; choose a different path."
        )


def _read_anchor(path: Path) -> tuple[int, str] | None:
    """Read the sidecar's committed ``(seq, tip)``, or ``None`` if there is none.

    A missing anchor is not an error. Logs written before anchors existed, and
    logs copied off a machine without their sidecar, are still perfectly good
    chains. It only means truncation cannot be ruled out, which :func:`verify`
    says out loud instead of implying by silence.

    An anchor that exists but cannot be parsed *is* an error, and deliberately
    not a recoverable one: the sidecar is the only statement of how long the log
    is supposed to be, so a damaged one is exactly what deleting records and
    scribbling on the evidence would look like.
    """
    ap = _anchor_path(path)
    if not ap.exists():
        return None
    try:
        data = json.loads(ap.read_text(encoding="utf-8"))
        return int(data["seq"]), str(data["hash"])
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise AuditError(
            f"{ap} exists but cannot be read ({exc}). It is the only record of "
            "how long the log is supposed to be, so a log with an unreadable "
            "anchor cannot be shown to be complete — keep both files and look "
            "at them by hand."
        ) from None


def _write_anchor(path: Path, seq: int, tip: str) -> None:
    """Commit the log's length, atomically, *after* the record it describes.

    Written to a temporary file and renamed, so that a reader never catches a
    half-written anchor and a crash leaves either the old value or the new one.

    The order is load-bearing and it is this way round: the log line is fsynced
    first, the anchor second. A crash between the two leaves the anchor one
    record behind the log, which reads as "the log grew past its anchor" — the
    harmless direction, and precisely the mid-write crash :class:`AuditLog`
    already promises to survive. Writing the anchor first would turn every such
    crash into a "records were removed from the end" alarm, and a verifier that
    cries wolf on ordinary crashes is one nobody reads by the third week.

    The rename is deliberately not followed by a directory fsync. After a power
    cut the anchor can therefore reappear as its previous value, which fails in
    the same harmless direction: an anchor that undercounts never accuses an
    intact log. An anchor that overcounts would.
    """
    ap = _anchor_path(path)
    tmp = ap.with_name(ap.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, _FILE_MODE)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        if hasattr(os, "fchmod"):
            # O_CREAT leaves the mode of a file that already exists alone, so a
            # leftover .tmp from a crash — or one pre-created wide — would keep
            # its old mode. Set it on the descriptor already in hand, which
            # cannot be redirected between the check and the change.
            os.fchmod(fh.fileno(), _FILE_MODE)
        # ts is for the human who finds a truncated log and needs to know whether
        # it happened during the run or last month. Nothing verifies it.
        json.dump(
            {
                "seq": seq,
                "hash": tip,
                "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            },
            fh,
            sort_keys=True,
        )
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, ap)


def _canonical(record: Mapping[str, Any]) -> bytes:
    """Serialise a record deterministically for hashing.

    Sorted keys, no whitespace, UTF-8, and ``ensure_ascii=False`` so that a
    hostname with a non-ASCII character hashes the same way it is written. Any
    change here invalidates every existing log, so it does not change.
    """
    payload = {k: v for k, v in record.items() if k not in _UNHASHED}
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _digest(record: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(record)).hexdigest()


@dataclass(frozen=True, slots=True)
class AuditRecord:
    """One line of the log."""

    seq: int
    ts: str
    kind: str
    payload: Mapping[str, Any]
    prev: str
    hash: str

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"seq": self.seq, "ts": self.ts, "kind": self.kind}
        d.update(self.payload)
        d["prev"] = self.prev
        d["hash"] = self.hash
        return d

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> AuditRecord:
        try:
            payload = {
                k: v
                for k, v in d.items()
                if k not in {"seq", "ts", "kind", "prev", "hash"}
            }
            return cls(
                seq=int(d["seq"]),
                ts=str(d["ts"]),
                kind=str(d["kind"]),
                payload=payload,
                prev=str(d["prev"]),
                hash=str(d["hash"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AuditError(f"malformed audit record: {exc}") from None

    def recompute(self) -> str:
        return _digest(self.to_dict())


class AuditLog:
    """Append-only JSONL with a hash chain, safe across threads.

    Opened in append mode and flushed per record. A crash mid-run therefore
    loses at most the record being written, and the chain over what survived
    still verifies — which is the behaviour you want from a log whose whole job
    is to be trustworthy about incomplete work.

    Each append also rewrites ``<log>.anchor`` with the new length and tip, so
    that records deleted from the end afterwards are detectable; see the module
    docstring for what that scheme does and does not defend against. The log and
    the anchor are owner-only, because ``redact=false`` can put password hashes
    in here.

    "Safe across threads" is exactly as wide as it sounds: the lock is this
    object's, so two threads sharing one instance are serialised and two
    *processes* appending to one path are not, which was already true of the
    chain before the anchor existed. One log, one writer.
    """

    def __init__(self, path: str | Path, *, readonly: bool = False) -> None:
        """Open a log for appending, or — with ``readonly`` — for inspection.

        ``readonly`` is the construction :func:`verify` uses, and it means the
        instance touches nothing on disk. That is not tidiness. A verifier must
        not mkdir a directory for a log that is simply missing, and it must not
        chmod a log it does not own, because :func:`_restrict` raises when the
        chmod fails and a verifier that raised on someone else's log would be
        reporting an intact chain as broken. It also skips the anchor check, so
        that :func:`verify` can diagnose a short log itself with the wording an
        operator needs rather than the wording an appender needs.

        (This parameter used to be ``ensure_parent``. It was renamed when it
        acquired the second and third meanings, so that nobody reads a flag
        named after directory creation and is surprised to find it governing
        permissions and chain checks.)
        """
        self.path = Path(path).expanduser()
        if not readonly:
            # mode= applies only to directories this call actually creates, and
            # mkdir(exist_ok=True) leaves an existing one alone. That asymmetry
            # is wanted: `path.parent` is very often the operator's cwd or home,
            # and chmod-ing an existing directory to 0700 because a log happens
            # to sit in it would be a far larger change than this module has any
            # business making.
            #
            # With parents=True, CPython applies mode= to the final component
            # only; intermediate directories get the umask default. That is fine
            # and is not worth working around: reaching the log still requires
            # traversing `path.parent` itself, which is the one that is 0700. Do
            # not "fix" this by walking the tree and chmod-ing upwards — that
            # narrows directories the operator created for other reasons.
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)
            _restrict(self.path)
            _restrict(_anchor_path(self.path))
        self._lock = threading.Lock()
        self._seq, self._tip = self._read_tip()
        if not readonly:
            self._check_anchor()

    def _check_anchor(self) -> None:
        """Refuse to continue a log that has fallen behind its own anchor.

        The anchor is rewritten after every append, so a log whose last record is
        older than the anchor has had records removed from the end. Appending to
        it would be the worst available response: the next append overwrites the
        anchor with the short history's tip, and the only evidence that anything
        was ever deleted is gone. So this raises and lets a human decide.

        A log *ahead* of its anchor is fine and expected — it is what a crash
        between the two writes looks like — so it is left to :func:`verify`,
        which walks the chain and can therefore check that the record the anchor
        names is still the record sitting at that position.
        """
        anchor = _read_anchor(self.path)
        if anchor is None:
            return
        seq, tip = anchor
        name = _anchor_path(self.path).name
        if seq > self._seq:
            raise AuditError(
                f"{self.path} ends at record {self._seq} but {name} commits to "
                f"record {seq} — the last {seq - self._seq} record(s) were "
                "removed from the end of the log. Refusing to append, because "
                "appending rewrites the anchor and erases the evidence; move "
                "both files aside and keep them."
            )
        if seq == self._seq and tip != self._tip:
            raise AuditError(
                f"{self.path} ends at record {seq} hashing to {self._tip[:12]}… "
                f"but {name} commits to {tip[:12]}… — the log was rewritten. "
                "Refusing to append; move both files aside and keep them."
            )

    def _read_tip(self) -> tuple[int, str]:
        """Find the last sequence number and digest without loading the file.

        Reads backwards from the end so that appending to a log with a year of
        history costs the same as appending to an empty one.

        The failure message is deliberately caller-neutral. This raises both for
        an appender opening the log and for :func:`verify` walking it, and a
        verifier that printed "refusing to append" would be telling the operator
        about a decision nobody was making.
        """
        if not self.path.exists() or self.path.stat().st_size == 0:
            return 0, GENESIS
        try:
            with self.path.open("rb") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                block = 4096
                buf = b""
                while size > 0:
                    step = min(block, size)
                    size -= step
                    fh.seek(size)
                    buf = fh.read(step) + buf
                    lines = [ln for ln in buf.split(b"\n") if ln.strip()]
                    if lines and (size == 0 or len(lines) > 1):
                        last = json.loads(lines[-1].decode("utf-8"))
                        return int(last["seq"]), str(last["hash"])
        except (OSError, ValueError, KeyError) as exc:
            raise AuditError(
                f"{self.path} exists but its last record is unreadable ({exc}). "
                "The chain can neither be continued from it nor verified through "
                "it — either a write was interrupted or the tail was edited. "
                "Move it aside if it is genuinely corrupt; do not delete it."
            ) from None
        return 0, GENESIS

    def append(self, kind: str, **payload: Any) -> AuditRecord:
        """Write one record and return it, chained to the previous."""
        with self._lock:
            seq = self._seq + 1
            record: dict[str, Any] = {
                "seq": seq,
                "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                "kind": kind,
            }
            for key in payload:
                if key in {"seq", "ts", "kind", "prev", "hash"}:
                    raise AuditError(f"payload may not override reserved key {key!r}")
            record.update(payload)
            record["prev"] = self._tip
            record["hash"] = _digest(record)

            line = json.dumps(record, sort_keys=True, ensure_ascii=False)
            # os.open rather than Path.open so that the mode is set at creation.
            # Creating the file and chmod-ing it afterwards leaves a window in
            # which a world-readable file exists at a known path, and this file
            # can hold recovered credentials the instant it is written.
            fd = os.open(
                self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, _FILE_MODE
            )
            with os.fdopen(fd, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())

            # A second fsync per record, and worth the cost: the anchor is the
            # only thing that can tell a truncated log from a short one, and an
            # anchor still sitting in the page cache when the machine dies
            # cannot. Written after the record so that a crash between the two
            # leaves the anchor behind the log, never ahead of it.
            _write_anchor(self.path, seq, record["hash"])

            self._seq = seq
            self._tip = record["hash"]
            return AuditRecord.from_dict(record)

    def decision(
        self,
        *,
        engagement: str,
        authorization: str,
        action: Mapping[str, Any],
        verdict: str,
        rule: str,
        reason: str,
        confirmed_by: str | None = None,
    ) -> AuditRecord:
        """Record a gate ruling. Called for every decision, including denials.

        Denials are logged as carefully as approvals — arguably more so. "The
        agent tried to touch the domain controller and was refused" is precisely
        the sentence an incident review needs to find, and it is also the
        highest-value negative example the training pipeline will ever get.
        """
        payload: dict[str, Any] = {
            "engagement": engagement,
            "authorization": authorization,
            "action": dict(action),
            "verdict": verdict,
            "rule": rule,
            "reason": reason,
        }
        if confirmed_by:
            payload["confirmed_by"] = confirmed_by
        return self.append("decision", **payload)

    def observation(self, *, action: Mapping[str, Any], result: Mapping[str, Any]) -> AuditRecord:
        """Record what an action actually did."""
        return self.append("observation", action=dict(action), result=dict(result))

    def note(self, text: str, **extra: Any) -> AuditRecord:
        """Record a human-authored note — scope changes, handoffs, surprises."""
        return self.append("note", text=text, **extra)

    def __iter__(self) -> Iterator[AuditRecord]:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                try:
                    yield AuditRecord.from_dict(json.loads(line))
                except (json.JSONDecodeError, AuditError) as exc:
                    raise AuditError(f"{self.path}:{lineno}: {exc}") from None

    def verify(
        self, *, expect_seq: int | None = None, expect_tip: str | None = None
    ) -> tuple[bool, str]:
        return verify(self.path, expect_seq=expect_seq, expect_tip=expect_tip)

    @property
    def tip(self) -> str:
        """Digest of the most recent record — cheap proof of log state.

        Together with :meth:`__len__` this is the pair worth writing down
        somewhere the engagement's target cannot reach. Passed back later as
        :func:`verify`'s ``expect_seq`` and ``expect_tip`` it catches the one
        thing the sidecar anchor cannot: an attacker who rewrote the log and the
        anchor to agree with each other.
        """
        return self._tip

    def __len__(self) -> int:
        return self._seq


def verify(
    path: str | Path,
    *,
    expect_seq: int | None = None,
    expect_tip: str | None = None,
) -> tuple[bool, str]:
    """Check a log's chain end to end, and its length against its anchor.

    Returns ``(ok, message)`` for every kind of damage, including damage that
    makes the log unparseable. This function never raises, and that is the whole
    contract: it is what an operator runs *because* they already suspect the log
    is broken, so a traceback out of a half-written final line would be answering
    "is this log intact?" with a stack trace instead of a verdict. Both the
    unreadable-tail check in :meth:`AuditLog._read_tip` and the malformed-line
    check in :meth:`AuditLog.__iter__` raise :class:`AuditError` by design, for
    the appender's benefit; here they are caught and turned into ``False``.

    The message names the first bad record, because "the log is broken" is
    useless and "record 412 was altered or record 411 was removed" is actionable.

    ``expect_seq`` and ``expect_tip`` check the log against an anchor held
    somewhere this machine cannot reach — a tip pinned in a ticket, a second
    store, the last page of a report. The sidecar catches every truncation that
    is not a deliberate attack on the sidecar; only an off-box value catches an
    attacker who rewrote both files, and these arguments are how one is supplied.
    """
    p = Path(path).expanduser()

    try:
        anchor = _read_anchor(p)
    except AuditError as exc:
        return False, str(exc)

    if not p.exists():
        if anchor is not None:
            return False, (
                f"no log at {p}, but {_anchor_path(p).name} commits to "
                f"{anchor[0]} record(s) — the log was deleted, not never written"
            )
        return False, f"no log at {p}"

    prev = GENESIS
    expected_seq = 1
    count = 0
    # Digest of the record the anchor names, remembered during the walk so that a
    # log which has legitimately grown past its anchor can still be checked
    # against it at the position the anchor actually speaks about.
    at_anchor: str | None = None

    try:
        for record in AuditLog(p, readonly=True):
            count += 1
            if record.seq != expected_seq:
                return False, (
                    f"record {count}: sequence jumps to {record.seq}, expected "
                    f"{expected_seq} — a record was removed or reordered"
                )
            if record.prev != prev:
                return False, (
                    f"record {record.seq}: chains to {record.prev[:12]}… but the "
                    f"previous record hashes to {prev[:12]}… — a record was "
                    "altered or removed before this one"
                )
            actual = record.recompute()
            if actual != record.hash:
                return False, (
                    f"record {record.seq}: contents hash to {actual[:12]}… but "
                    f"the record claims {record.hash[:12]}… — this record was "
                    "altered"
                )
            prev = record.hash
            if anchor is not None and record.seq == anchor[0]:
                at_anchor = record.hash
            expected_seq += 1
    except AuditError as exc:
        return False, str(exc)

    if anchor is not None:
        a_seq, a_tip = anchor
        name = _anchor_path(p).name
        if count < a_seq:
            return False, (
                f"log ends at record {count} but {name} commits to record "
                f"{a_seq} — the last {a_seq - count} record(s) were removed from "
                "the end. The chain cannot see this on its own, because a prefix "
                "of a valid chain is a valid chain; the anchor is what makes it "
                "visible."
            )
        if at_anchor is not None and at_anchor != a_tip:
            return False, (
                f"record {a_seq} hashes to {at_anchor[:12]}… but {name} commits "
                f"to {a_tip[:12]}… — the log was rebuilt from the start, which "
                "leaves a chain that verifies against itself and against nothing "
                "else"
            )

    if expect_seq is not None and count != expect_seq:
        removed = count < expect_seq
        return False, (
            f"log holds {count} record(s) but {expect_seq} were pinned — "
            f"{'records were removed' if removed else 'records were added'} "
            "after the tip was recorded off the box"
        )
    if expect_tip is not None and prev != expect_tip:
        return False, (
            f"log tips at {prev[:12]}… but {expect_tip[:12]}… was pinned — this "
            "is not the log that was recorded off the box"
        )

    if count == 0:
        return True, "log is empty"
    if anchor is None:
        return True, (
            f"{count} record(s) verified, tip {prev[:12]}… — no anchor beside "
            "the log, so records removed from the end would not show up here"
        )
    return True, f"{count} record(s) verified against its anchor, tip {prev[:12]}…"
