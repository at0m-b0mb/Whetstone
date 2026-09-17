"""The audit log: an append-only, hash-chained record of everything decided.

Two audiences read this file and they want different things, which is why it is
JSONL rather than prose.

A **human** reads it after the fact to answer "what did this thing do on my
network, and who said it could?". For that it needs to be complete, ordered, and
hard to quietly edit — hence the hash chain. Each record commits to the previous
record's digest, so removing or altering an entry breaks every link after it and
:func:`verify` says exactly where. This does not stop someone who can rewrite the
whole file (nothing local can), but it does stop the realistic case: a single
embarrassing line disappearing.

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
    """

    def __init__(self, path: str | Path, *, ensure_parent: bool = True) -> None:
        self.path = Path(path).expanduser()
        if ensure_parent:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._seq, self._tip = self._read_tip()

    def _read_tip(self) -> tuple[int, str]:
        """Find the last sequence number and digest without loading the file.

        Reads backwards from the end so that appending to a log with a year of
        history costs the same as appending to an empty one.
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
                "Refusing to append to a log whose chain cannot be continued — "
                "move it aside if it is genuinely corrupt."
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
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())

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

    def verify(self) -> tuple[bool, str]:
        return verify(self.path)

    @property
    def tip(self) -> str:
        """Digest of the most recent record — cheap proof of log state."""
        return self._tip

    def __len__(self) -> int:
        return self._seq


def verify(path: str | Path) -> tuple[bool, str]:
    """Check a log's chain end to end.

    Returns ``(ok, message)``. The message names the first bad record, because
    "the log is broken" is useless and "record 412 was altered or record 411 was
    removed" is actionable.
    """
    p = Path(path).expanduser()
    if not p.exists():
        return False, f"no log at {p}"

    prev = GENESIS
    expected_seq = 1
    count = 0

    for record in AuditLog(p, ensure_parent=False):
        count += 1
        if record.seq != expected_seq:
            return False, (
                f"record {count}: sequence jumps to {record.seq}, expected "
                f"{expected_seq} — a record was removed or reordered"
            )
        if record.prev != prev:
            return False, (
                f"record {record.seq}: chains to {record.prev[:12]}… but the "
                f"previous record hashes to {prev[:12]}… — a record was altered "
                "or removed before this one"
            )
        actual = record.recompute()
        if actual != record.hash:
            return False, (
                f"record {record.seq}: contents hash to {actual[:12]}… but the "
                f"record claims {record.hash[:12]}… — this record was altered"
            )
        prev = record.hash
        expected_seq += 1

    if count == 0:
        return True, "log is empty"
    return True, f"{count} record(s) verified, tip {prev[:12]}…"
