"""Render an episode as a trajectory in the wire protocol.

Kept separate from the loop so the loop has no opinion about training formats,
and so the runtime does not import anything under ``training/`` — the dependency
between the two halves of this project runs one way on purpose.

This is the point at which the loop closes. An episode rendered here is training
data with no conversion step: the agent works, the work is recorded, the
recording teaches the next model. Before it existed, trajectories were scripted
verb sequences written by hand, so the model was learning to imitate a list
someone else authored — which teaches the format and cannot teach the choosing.

It is also, for the same reason, a trust boundary. Everything inside an
observation was written by the target host, and a target is adversarial by
definition; because what is rendered here is trained on and later served back to
the model, a host that can write a protocol marker into a trajectory can write
the model's next turn. Every string that crosses into the wire format goes
through :func:`_neutralise` first.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from . import Episode

__all__ = ["render_episode", "render_prompt", "shrink_payload"]

#: Records kept from a list-shaped payload before eliding.
MAX_ITEMS = 4
#: Characters kept from any single stringified value.
MAX_VALUE = 220

#: The protocol markers, duplicated deliberately rather than imported from
#: ``training.tokenizer.protocol``. The runtime must not depend on the training
#: package; a mismatch would be a real bug, so it is covered by a test that
#: asserts the two definitions agree.
BOS, EOS = "<|bos|>", "<|eos|>"
TASK, HOST, SCOPE, VERBS = "<|task|>", "<|host|>", "<|scope|>", "<|verbs|>"
ACT, OBS, GATE, FIND = "<|act|>", "<|obs|>", "<|gate|>", "<|find|>"

#: Every protocol marker opens with this, and nothing else in a trajectory may.
_MARKER_OPEN = "<|"
#: What an opener found in target-supplied text is rewritten to. ASCII, and free
#: of quotes and backslashes, because the substitution runs on text that is
#: already JSON: anything with meaning inside a JSON string would produce a
#: segment that no longer parses back out.
_MARKER_ESCAPED = "<!|"


def shrink_payload(value: Any, depth: int = 0) -> Any:
    """Cap an observation, saying where it cut.

    The elision marker is part of the lesson rather than a courtesy. A model
    trained on silently truncated lists learns that hosts have four services;
    one trained on lists carrying ``"+118 more"`` learns it is reading a summary
    and that the count is the interesting part.
    """
    if isinstance(value, list):
        head = [shrink_payload(v, depth + 1) for v in value[:MAX_ITEMS]]
        if len(value) > MAX_ITEMS:
            head.append(f"+{len(value) - MAX_ITEMS} more")
        return head
    if isinstance(value, dict):
        if depth >= 3:
            return f"<{len(value)} fields>"
        return {k: shrink_payload(v, depth + 1) for k, v in list(value.items())[:10]}
    if isinstance(value, str) and len(value) > MAX_VALUE:
        return value[:MAX_VALUE] + "…"
    return value


def _neutralise(text: str) -> str:
    """Take the protocol's own markers out of text the target controls.

    An observation is written by the assessed host, which in an engagement is
    adversarial by definition: a shell history line from
    ``vuln.credential_exposure``, a cron entry from ``enum.persistence``, a
    command line from ``enum.processes``, or subprocess stderr on
    ``Observation.error``. All of it lands verbatim in a trajectory.

    ``json.dumps`` escapes quotes and backslashes and nothing else, so a planted
    ``<|act|>`` survives serialisation intact and tokenises to the real control
    token, because the markers are registered with the BPE trainer as atomic
    units. Two things then happen downstream, and both hand the target the pen.
    The SFT mask walker flips supervision *on* at any model-turn marker, so an
    ``<|act|>`` inside an observation trains the model to emit whatever the host
    planted; an ``<|eos|>`` ends the document early instead, dropping every
    ``<|find|>`` segment after it — the detection gaps, which are the point.

    Rewriting the ``<|`` opener rather than the ten marker strings named above is
    deliberate. This module duplicates only part of the training vocabulary:
    ``<|plan|>``, ``<|pad|>`` and ``<|unk|>`` are not defined here, and
    ``<|plan|>`` is one of the three segments SFT supervises — so a filter
    written against the local list would leave the most valuable injection wide
    open, and would silently reopen it again for any marker added later. No
    protocol token can exist without the opener.

    The replacement contains no opener of its own, so a substitution can never
    assemble the marker it just removed, however the input was nested.
    """
    return text.replace(_MARKER_OPEN, _MARKER_ESCAPED)


def _compact(payload: dict[str, Any]) -> str:
    """Serialise one segment payload, with target-controlled markers removed.

    The escape runs over the finished JSON rather than over each leaf so that
    keys, nested values, and any field a later caller adds are covered by
    construction. A per-value filter is a filter someone eventually forgets to
    apply to the next field, and the field they forget is the one that carries
    text from the host.
    """
    return _neutralise(
        json.dumps(payload, separators=(",", ":"), ensure_ascii=False))


def _render_context(episode: Episode) -> list[str]:
    """Everything up to but not including the next action.

    Shared by :func:`render_episode` and :func:`render_prompt` so that the text
    a model is trained on and the text it is prompted with are produced by one
    function. Train/serve skew is fatal at this model size — a 14.6M network has
    no spare capacity to absorb a serving format that differs from its training
    format by even a marker — and the cheapest guarantee against it is to never
    write the format twice.
    """
    # The header goes through the same escape as the payloads. None of these
    # four is as hostile as an observation — the task is the operator's, the
    # scope the engagement's, the catalogue the registry's, and the host is the
    # platform string an adapter reports — but they are written into the same
    # wire format, and a second path into that format is a second path to
    # remember to defend. There is one.
    parts: list[str] = [BOS, f"{TASK}{_neutralise(episode.task.strip())}",
                        f"{HOST}{_neutralise(episode.host)}",
                        f"{SCOPE}{_neutralise(episode.scope)}",
                        f"{VERBS}{_neutralise(episode.catalogue)}"]

    for turn in episode.turns:
        parts.append(f"{ACT}{_compact(turn.action.to_dict())}")

        if turn.refused:
            # The refusal and its reason, so the recovery that follows has
            # something to be a recovery *from*. A trajectory that silently
            # drops denied actions teaches a model that never needs to correct.
            parts.append(f"{GATE}{_compact({
                'verdict': turn.decision.verdict.value,
                'rule': turn.decision.rule,
                'reason': turn.decision.reason[:MAX_VALUE],
            })}")
            continue

        if turn.observation is None:
            continue
        obs = turn.observation
        payload: dict[str, Any] = {"ok": obs.ok}
        if obs.data is not None:
            payload["data"] = shrink_payload(obs.data)
        if obs.error:
            payload["error"] = obs.error[:MAX_VALUE]
        if obs.unsupported:
            payload["unsupported"] = True
        parts.append(f"{OBS}{_compact(payload)}")
    return parts


def render_prompt(episode: Episode) -> str:
    """The episode-so-far as a prompt, ending exactly where the model must act.

    The trailing ``<|act|>`` is the point: at training time the token after that
    marker was the first character of the action JSON, so at serving time the
    model continues from there and the constrained decoder reads its verb
    preference. The prompt is the identical prefix of the trajectory the loop
    would render if it stopped here, which is the whole reason both go through
    :func:`_render_context`.
    """
    return "".join(_render_context(episode)) + ACT


def render_episode(episode: Episode) -> str:
    """One trajectory document from a completed episode."""
    parts = _render_context(episode)

    for finding in episode.findings:
        parts.append(f"{FIND}{_compact(finding.to_dict())}")

    parts.append(EOS)
    return "".join(parts)
