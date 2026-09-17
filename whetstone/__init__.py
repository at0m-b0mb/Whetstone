"""Whetstone — a purple-team agent, and a small model trained from scratch to drive it.

A whetstone does not cut anything. It exists so the blade does its job better,
and it is useless on its own. That is the argument for the red half of this
project: the attack side is here to sharpen the defence, and nothing in it is
built to be pointed at someone who has not asked for it.

The package splits cleanly in two, and the split is worth understanding before
reading further:

``whetstone.*`` is the **runtime** — the gate, the adapters, the agent loop, the
surfaces other apps talk to. It is model-agnostic. It works today, with any
backend, and it would still work if the model half of the project were deleted.

``training/*`` is the **model** — tokenizer, architecture, pretraining, and the
loop that turns verified runtime trajectories into the next checkpoint. It
depends on the runtime, because the runtime defines the action space it is
learning to produce and generates the data it learns from. The dependency runs
one way, on purpose.

Start at :mod:`whetstone.actions` for the schema everything else is built on,
and :mod:`whetstone.gate` for the rules that decide what may run.
"""

from __future__ import annotations

from .actions import (
    REGISTRY,
    Action,
    Intent,
    Observation,
    Param,
    SchemaError,
    Side,
    TargetKind,
    Verb,
    VerbRegistry,
)
from .version import __version__

__all__ = [
    "__version__",
    "REGISTRY",
    "Action",
    "Intent",
    "Observation",
    "Param",
    "SchemaError",
    "Side",
    "TargetKind",
    "Verb",
    "VerbRegistry",
]
