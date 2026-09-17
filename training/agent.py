"""A model-driven chooser: the trained checkpoint drives the agent loop.

This is where the two halves of the project finally meet. The kernel runs a
plan-act-observe loop and asks a :class:`~whetstone.kernel.Chooser` for the next
action; :class:`ModelChooser` answers with the verb the trained model prefers,
decoded under the closed-action-space constraint so the answer is always valid.

It lives in ``training/`` and not in ``whetstone/`` on purpose. The kernel must
stay model-agnostic and must not import MLX — a laptop that only ever runs the
runtime against a scripted or rule-based chooser should never be made to install
a training stack. This chooser depends on the model, the tokenizer and the
constrained decoder, so it sits on the training side of the one-way dependency
and is handed to the kernel from outside.

The single property that matters most here is **train/serve fidelity**. The
prompt the model is given at each step is produced by
:func:`whetstone.kernel.render.render_prompt`, which shares its body with the
function that rendered the training trajectories. So the model sees, at serving
time, the exact prefix format it was trained on, ending at the ``<|act|>`` marker
where its next token was — during training — the first character of an action.
A 14.6M model has no capacity to spare on absorbing a serving format that drifts
from its training format, and the cheapest defence is to never write the format
twice.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Sequence

from whetstone.actions import Action, TargetKind, Verb
from whetstone.kernel.render import render_prompt

__all__ = ["ModelChooser", "load_chooser"]


class ModelChooser:
    """Chooses the next action by constrained decoding over a checkpoint.

    Implements the kernel's ``Chooser`` protocol structurally — the protocol is
    duck-typed, so this class satisfies it without the runtime importing
    anything from here.
    """

    def __init__(self, model: Any, tokenizer: Any, *, verbose: bool = False) -> None:
        self.model = model
        self.tok = tokenizer
        self.verbose = verbose

    def choose(
        self, episode: Any, permitted: Sequence[Verb],
        *, exclude: Sequence[str], target: str | None,
    ) -> Action | None:
        # Once every permitted verb has been tried, the sweep is done. A trained
        # model has no natural "stop" token in this protocol, so the loop is
        # bounded by exhaustion and by the kernel's max_turns — whichever comes
        # first. Filtering the pool here also keeps the decoder from wasting a
        # forward pass ranking verbs it cannot pick.
        done = {t.action.verb_id for t in episode.turns} | set(exclude)
        pool = [v for v in permitted if v.id not in done]
        if not pool:
            return None

        from .constrained import decode_action

        prompt = render_prompt(episode)
        decoded = decode_action(
            self.model, self.tok, prompt,
            permitted=pool, target=target, exclude=list(done))

        if self.verbose:
            runners = ", ".join(f"{vid}" for vid, _s in decoded.alternatives[:3])
            print(f"    model -> {decoded.verb.id:<26} (next: {runners})")

        return decoded.action


def load_chooser(checkpoint: Path, tokenizer: Path, *, verbose: bool = False) -> ModelChooser:
    """Build a :class:`ModelChooser` from a checkpoint on disk.

    A thin convenience so the lab runners do not each repeat the model-loading
    dance. Importing here rather than at module top keeps ``import training.agent``
    cheap for anything that only wants the class.
    """
    from tokenizers import Tokenizer

    from .generate import load_for_inference

    model, _cfg = load_for_inference(checkpoint)
    tok = Tokenizer.from_file(str(tokenizer))
    return ModelChooser(model, tok, verbose=verbose)
