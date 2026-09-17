"""Render an episode as a trajectory in the wire protocol.

Kept separate from the loop so the loop has no opinion about training formats,
and so the runtime does not import anything under ``training/`` — the dependency
between the two halves of this project runs one way on purpose.

This is the point at which the loop closes. An episode rendered here is training
data with no conversion step: the agent works, the work is recorded, the
recording teaches the next model. Before it existed, trajectories were scripted
verb sequences written by hand, so the model was learning to imitate a list
someone else authored — which teaches the format and cannot teach the choosing.
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


def _compact(payload: dict[str, Any]) -> str:
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)


def _render_context(episode: Episode) -> list[str]:
    """Everything up to but not including the next action.

    Shared by :func:`render_episode` and :func:`render_prompt` so that the text
    a model is trained on and the text it is prompted with are produced by one
    function. Train/serve skew is fatal at this model size — a 14.6M network has
    no spare capacity to absorb a serving format that differs from its training
    format by even a marker — and the cheapest guarantee against it is to never
    write the format twice.
    """
    parts: list[str] = [BOS, f"{TASK}{episode.task.strip()}",
                        f"{HOST}{episode.host}", f"{SCOPE}{episode.scope}",
                        f"{VERBS}{episode.catalogue}"]

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
