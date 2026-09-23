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

    def __init__(self, model: Any, tokenizer: Any, *, verbose: bool = False,
                 stop_on_eos: bool = False, eos_floor: int = 16) -> None:
        self.model = model
        self.tok = tokenizer
        self.verbose = verbose
        #: Ask the model whether the episode is over before asking which verb
        #: comes next. **Defaults OFF, and the reason is the more interesting
        #: half of this.**
        #:
        #: The premise is sound: every one of the 14,766 trajectories ends in
        #: EOS, so where a sweep ends is something three SFT epochs taught, and
        #: the loop used to discard it because EOS is not a Verb. Scoring EOS
        #: against the verbs and adding a floor — EOS may not win before this
        #: much work is done, because in training it follows a COMPLETE sweep —
        #: measured well on small-sft, agentbench, 3 runs per setting:
        #:
        #:     floor   found  proved  gap-recall  closed  turns  wasted
        #:     off       4/4     3/3         3/3     3/3   18.3       3
        #:     0/8     1.5/4   2.5/3       2.5/3   2.5/3      9       1
        #:     12        4/4  2.33/3      2.33/3  2.33/3   14.7    1.33
        #:     16        4/4     3/3         3/3     3/3   16.3    1.67
        #:
        #: Floor 16 looked like a free win: every row at its ceiling with
        #: spread 0.00, and wasted turns nearly halved.
        #:
        #: It was not free, it was an ARTEFACT OF A BROKEN PROMPT. The kernel
        #: was cutting the verb catalogue mid-identifier at 400 characters, so
        #: the model was reading "...; vuln.credenti" in 87% of episodes.
        #: Fixing that cut (Kernel.run, entry-aligned at _CATALOGUE_CHARS)
        #: changed the prompt, and with it the calibration this floor was tuned
        #: against. Re-measured on the corrected prompt:
        #:
        #:     floor   found  proved  gap-recall  closed  turns  wasted
        #:     off       4/4     3/3         3/3     3/3     18       3
        #:     10     2.67/4  2.67/3      2.67/3  2.67/3   11.3       1
        #:     13        4/4  2.33/3      2.33/3  2.33/3     15    1.33
        #:     16        4/4     3/3         3/3     3/3     18       3
        #:
        #: No floor now buys turns without paying capability, and at 16 EOS
        #: simply never wins. Three turns are not worth 0.67 of proved,
        #: gap-recall and gaps-closed, so this is off.
        #:
        #: Left wired, and the flags exposed on agentbench, because the premise
        #: is still right and the thing that would make it work is a model
        #: trained with a stop DECISION rather than one inferred from a
        #: sequence end. The lesson recorded here is narrower and more useful:
        #: a threshold tuned against a prompt is a measurement of that prompt.
        self.stop_on_eos = stop_on_eos
        #: Turns that must have completed before EOS is allowed to win at all.
        #: The bare comparison stops too early because the model was taught EOS
        #: after a COMPLETE sweep; this says "you may not call it finished
        #: before you have done this much", which is the floor the training
        #: distribution implies and the score alone does not carry.
        self.eos_floor = eos_floor

    def choose(
        self, episode: Any, permitted: Sequence[Verb],
        *, exclude: Sequence[str], target: str | None,
    ) -> Action | None:
        # Once every permitted verb has been tried, the sweep is done. Filtering
        # the pool here also keeps the decoder from wasting a forward pass
        # ranking verbs it cannot pick.
        done = {t.action.verb_id for t in episode.turns} | set(exclude)
        pool = [v for v in permitted if v.id not in done]
        if not pool:
            return None

        from .constrained import decode_action

        prompt = render_prompt(episode)

        # ASK THE MODEL WHETHER IT IS FINISHED, before asking which verb.
        #
        # This comment used to say the model "has no natural stop token in this
        # protocol", and that was wrong about its own training data: every one
        # of the 14,766 trajectories ends in EOS, so where a sweep ends is
        # exactly what the model spent three SFT epochs learning. The loop then
        # threw that away, because EOS is not a Verb and `pool` holds only
        # Verbs — so the only way to stop was to run out of verbs or hit
        # max_turns. It showed up in the benchmark as three wasted turns per
        # episode against the scripted sweep's zero, and 18.3 turns against 15.
        #
        # EOS is scored as one more continuation of the same prompt, by the same
        # function that scores the verbs, so it competes on equal terms: if the
        # model believes the episode is over more strongly than it believes in
        # any remaining verb, it is over. No threshold and no tuned margin —
        # a margin here would be a second, unmeasured opinion about a judgement
        # the model has already been trained to make.
        if self.stop_on_eos and len(episode.turns) >= max(1, self.eos_floor):
            from .constrained import rank_verbs, score_continuations
            from .tokenizer.protocol import EOS

            best_verb = rank_verbs(self.model, self.tok, prompt, pool)[0][1]
            eos_score = score_continuations(
                self.model, self.tok, prompt, [EOS])[0]
            if eos_score > best_verb:
                if self.verbose:
                    print(f"    model -> STOP (eos {eos_score:.2f} > "
                          f"best verb {best_verb:.2f})")
                return None
        decoded = decode_action(
            self.model, self.tok, prompt,
            permitted=pool, target=target, exclude=list(done))

        if self.verbose:
            runners = ", ".join(f"{vid}" for vid, _s in decoded.alternatives[:3])
            print(f"    model -> {decoded.verb.id:<26} (next: {runners})")

        return decoded.action


def load_chooser(checkpoint: Path, tokenizer: Path, *, verbose: bool = False,
                 stop_on_eos: bool = False, eos_floor: int = 16) -> ModelChooser:
    """Build a :class:`ModelChooser` from a checkpoint on disk.

    A thin convenience so the lab runners do not each repeat the model-loading
    dance. Importing here rather than at module top keeps ``import training.agent``
    cheap for anything that only wants the class.
    """
    from tokenizers import Tokenizer

    from .generate import load_for_inference

    model, _cfg = load_for_inference(checkpoint)
    tok = Tokenizer.from_file(str(tokenizer))
    return ModelChooser(model, tok, verbose=verbose,
                        stop_on_eos=stop_on_eos, eos_floor=eos_floor)
