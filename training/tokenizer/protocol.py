"""The wire format between the model and the runtime.

Everything the model ever sees or emits is a sequence of these segments. It is
worth getting right before a single token is trained, because changing it later
means retraining: the special-token ids are baked into the vocabulary, and the
segment structure is the only grammar a 150M model has to lean on.

A trajectory looks like this::

    <|task|>   Find anything that runs without a human starting it.
    <|host|>   windows
    <|scope|>  execute, red:T1547 T1053
    <|verbs|>  enum.persistence(); detect.telemetry(); exploit.scheduled_task(...)
    <|act|>    {"verb":"enum.persistence","target":"10.20.4.2"}
    <|obs|>    {"ok":true,"data":{"autoruns":[...]}}
    <|act|>    {"verb":"detect.telemetry","target":"10.20.4.2"}
    <|obs|>    {"ok":true,"data":{"process_creation":false}}
    <|find|>   {"title":"No process-creation logging","severity":"high"}
    <|eos|>

Three things about this design earn their place.

**The catalogue is in the context, not the weights.** ``<|verbs|>`` lists what
this engagement permits, every time. The model is never asked to remember which
verbs exist — only to pick from a list in front of it. That is a far easier
problem, it lets the catalogue grow without retraining, and it means the gate's
filtering (hiding red verbs from an engagement that has not authorised them)
actually shapes what the model considers.

**``<|gate|>`` makes refusals trainable.** When the gate denies a proposed
action, the denial comes back as a segment and the model continues from there.
So the training data contains the actual recovery — proposed, refused, reasoned,
proposed something in scope — rather than only the clean path. A model trained
only on successes has never seen a correction and does not know how to make one.

**JSON payloads, not prose.** ``<|act|>`` content is parsed by
``VerbRegistry.parse``, which raises on a hallucinated verb, a missing parameter
or an invented parameter name. The model's output is therefore *checkable*, and
a check that can fail at training time is a label.
"""

from __future__ import annotations

from typing import Final

__all__ = [
    "SPECIAL_TOKENS",
    "PAD", "BOS", "EOS", "UNK",
    "TASK", "HOST", "SCOPE", "VERBS", "PLAN", "ACT", "OBS", "GATE", "FIND",
    "render_trajectory",
]

# Reserved control tokens. Order is fixed: these occupy ids 0..n and changing
# the order invalidates every checkpoint trained against it.
PAD: Final = "<|pad|>"
BOS: Final = "<|bos|>"
EOS: Final = "<|eos|>"
UNK: Final = "<|unk|>"          # unreachable with byte-level BPE; reserved anyway

TASK: Final = "<|task|>"        # the objective, in natural language
HOST: Final = "<|host|>"        # windows | linux | macos — picks the adapter dialect
SCOPE: Final = "<|scope|>"      # what this engagement permits, compactly
VERBS: Final = "<|verbs|>"      # the catalogue the gate is willing to show
PLAN: Final = "<|plan|>"        # a short reasoning step before acting
ACT: Final = "<|act|>"          # the action, as JSON the registry can parse
OBS: Final = "<|obs|>"          # what came back
GATE: Final = "<|gate|>"        # a gate ruling — the correction signal
FIND: Final = "<|find|>"        # a finding or detection gap

#: Fed to the BPE trainer as atomic units so they never get split into pieces.
SPECIAL_TOKENS: Final[tuple[str, ...]] = (
    PAD, BOS, EOS, UNK,
    TASK, HOST, SCOPE, VERBS, PLAN, ACT, OBS, GATE, FIND,
)


def render_trajectory(segments: list[tuple[str, str]]) -> str:
    """Render ``[(token, text), ...]`` into the flat training string.

    One function, used by the corpus builder at training time and by the agent
    at serving time. Two implementations of a prompt format is how train/serve
    skew is born, and train/serve skew on a 150M model is fatal — it has no
    spare capacity to absorb a format it was not trained on.
    """
    out = [BOS]
    for token, text in segments:
        if token not in SPECIAL_TOKENS:
            raise ValueError(f"{token!r} is not a protocol token")
        out.append(token + text.strip())
    out.append(EOS)
    return "".join(out)
