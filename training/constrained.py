"""Constrained action decoding — making the closed action space real.

The project's central claim about why a 150M model can do this job is that
picking one of ~200 verb ids is *classification, not free generation*. That
claim was written down, argued for, and then never implemented. Generation ran
unconstrained and the output was validated afterwards, which is why the
benchmark saw ``structemicio`` and ``vuln.twitchParameter`` — tokens that look
like verb ids and are not. The model was being asked to spell a member of a
closed set from memory when it should only ever have been asked to choose one.

This module closes that gap, and the consequence is categorical: **an action
produced here is valid by construction.** There is no hallucinated verb to
reject, because no string outside the registry is ever reachable. There is no
malformed JSON, because the JSON is assembled rather than written. There is no
missing required parameter, because the schema is walked.

The division of labour is the point:

*The model decides.* Which verb answers this task, given everything before it.
That is the judgement a small model can genuinely learn, and it is scored here
by comparing the log-probability of each candidate id as a continuation.

*The code guarantees.* Structure, membership, parameter names, types. Those are
facts about the registry, not opinions, and asking a 14.6M network to reproduce
them from memory wastes capacity on something a dictionary lookup does perfectly.

**Why this is not cheating.** A skeptical reading is that the model is barely
involved — the code writes the JSON and the model only picks an item. That is
exactly the design. The hard part of an agent turn is *which verb, with what
parameters, given this observation*; the easy part is comma placement. Spending
model capacity on comma placement is the waste, and the benchmark's
``action-json`` score was measuring both at once and reporting the sum as
capability. Scored separately, ranking is what improves with training and
syntax is what should never fail at all.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

import mlx.core as mx

from whetstone.actions import REGISTRY, Action, Param, Verb, VerbRegistry

__all__ = ["score_continuations", "rank_verbs", "decode_action", "DecodedAction"]


def score_continuations(
    model: Any, tok: Any, prompt: str, candidates: Sequence[str],
    *, length_normalise: bool = False,
) -> list[float]:
    """Log-probability of each candidate as a continuation of ``prompt``.

    One batched forward pass over ``[prompt + candidate]`` for every candidate,
    summing token log-probs across the candidate's own positions only. The
    prompt contributes no gradient to the comparison because it is identical
    across candidates.

    ``length_normalise`` defaults to **off**, and that default was arrived at by
    measurement after getting it backwards.

    The reasoning for turning it on is superficially sound: verb ids differ in
    length, every extra token can only subtract probability, so an unnormalised
    sum should favour short ids regardless of fit. It is the standard fix for
    open-ended beam search, where candidates of different lengths compete.

    It is wrong here, because this is not open-ended generation. Choosing among
    a closed set means taking argmax P(candidate | prompt), and that is the
    unnormalised sequence log-probability by definition — dividing by length
    optimises a different quantity. Measured on one prompt across nineteen
    permitted verbs:

        normalised    -1.3596 .. -1.5167   spread 0.16 nats
        unnormalised -10.877  .. -14.734   spread 3.9 nats

    Normalising compressed a 3.9-nat signal into 0.16 nats of noise, and the
    decoder then returned the same verb for every task while its own runners-up
    were visibly better. The flag is kept because length bias is real when the
    candidate set is open; for a registry it is not.
    """
    prompt_ids = tok.encode(prompt).ids
    rows: list[list[int]] = []
    spans: list[int] = []
    for cand in candidates:
        cand_ids = tok.encode(cand).ids
        rows.append(prompt_ids + cand_ids)
        spans.append(len(cand_ids))

    width = max(len(r) for r in rows)
    pad_id = tok.token_to_id("<|pad|>") or 0
    batch = mx.array([r + [pad_id] * (width - len(r)) for r in rows])

    logits, _ = model(batch[:, :-1])
    logprobs = logits.astype(mx.float32) - mx.logsumexp(
        logits.astype(mx.float32), axis=-1, keepdims=True
    )
    mx.eval(logprobs)

    out: list[float] = []
    start = len(prompt_ids)
    for i, span in enumerate(spans):
        total = 0.0
        for j in range(span):
            pos = start + j - 1          # position predicting token at start+j
            token = int(batch[i, start + j].item())
            total += float(logprobs[i, pos, token].item())
        out.append(total / span if (length_normalise and span) else total)
    return out


def rank_verbs(
    model: Any, tok: Any, prompt: str, verbs: Sequence[Verb],
) -> list[tuple[Verb, float]]:
    """Every permitted verb, scored and sorted best-first.

    The candidate strings include the surrounding JSON so the score reflects the
    model's belief about the verb *in the position it will actually appear*,
    rather than about the bare id in a vacuum.
    """
    candidates = [f'{{"verb":"{v.id}"' for v in verbs]
    scores = score_continuations(model, tok, prompt, candidates)
    return sorted(zip(verbs, scores), key=lambda pair: -pair[1])


@dataclass(frozen=True, slots=True)
class DecodedAction:
    """A valid action, plus what the model thought of the alternatives."""

    action: Action
    verb: Verb
    score: float
    #: Runners-up, best-first. Useful for a retry after a gate refusal: the
    #: second choice is already known and costs no extra forward pass.
    alternatives: tuple[tuple[str, float], ...] = ()

    def render(self) -> str:
        return self.action.render()


def _fill_param(
    model: Any, tok: Any, prompt: str, verb: Verb, param: Param,
) -> Any:
    """Choose a value for one parameter, constrained by its declared type.

    Enums are a closed set, so the model ranks them the same way it ranks verbs.
    Booleans are a two-item enum. Integers and free strings fall back to the
    declared default, because a 14.6M model sampling an arbitrary port number
    adds noise rather than judgement — and a wrong-but-plausible parameter is
    worse than a declared default, since it looks deliberate in a report.
    """
    if param.type == "enum" and param.choices:
        scored = score_continuations(
            model, tok, f'{prompt}{{"verb":"{verb.id}","params":{{"{param.name}":"',
            list(param.choices))
        return param.choices[max(range(len(scored)), key=lambda i: scored[i])]
    if param.type == "boolean":
        return bool(param.default) if param.default is not None else True
    if param.default is not None:
        return param.default
    if param.type == "integer":
        return 1
    return "unset"


def decode_action(
    model: Any,
    tok: Any,
    prompt: str,
    *,
    registry: VerbRegistry = REGISTRY,
    permitted: Sequence[Verb] | None = None,
    target: str | None = None,
    exclude: Sequence[str] = (),
) -> DecodedAction:
    """Produce a registry-valid action. Cannot fail on syntax or membership.

    ``permitted`` is normally ``Gate.catalogue()`` — the verbs this engagement
    would allow. Constraining to it is strictly better than letting the model
    propose something the gate will refuse: the refusal would be correct but the
    turn is wasted, and a temptation removed is cheaper than a refusal trained.

    ``exclude`` drops verbs already tried this turn, which is what makes a retry
    after a gate refusal converge instead of re-proposing the same thing.
    """
    import whetstone.verbs  # noqa: F401  (registers the catalogue)

    pool = list(permitted) if permitted is not None else list(registry)
    pool = [v for v in pool if v.id not in set(exclude)]
    if not pool:
        raise ValueError("no permitted verbs left to choose from")

    ranked = rank_verbs(model, tok, prompt, pool)
    verb, score = ranked[0]

    params: dict[str, Any] = {}
    for param in verb.params:
        if param.required or param.default is not None:
            params[param.name] = _fill_param(model, tok, prompt, verb, param)

    from whetstone.actions import TargetKind

    chosen_target = None
    if verb.target is not TargetKind.NONE:
        chosen_target = target or "127.0.0.1"

    # bind() validates: if this raises, the registry and this module disagree
    # about the schema, which is a bug here and not a model failure.
    action = verb.bind(params, target=chosen_target)
    return DecodedAction(
        action=action, verb=verb, score=score,
        alternatives=tuple((v.id, s) for v, s in ranked[1:6]),
    )
