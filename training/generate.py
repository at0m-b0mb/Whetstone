"""Sample from a trained checkpoint — "does it actually work?"

Loss curves say a model is learning *something*; only generation says *what*.
This is the script you run to look at a checkpoint and decide whether the thing
has learned the shape of security text or is still producing noise that happens
to have a low number next to it.

    python -m training.generate --checkpoint data/models/checkpoints/tiny \
        --prompt "Get-Process | Where-Object"

At the tiny end of the staircase, do not expect coherent commands. Expect the
model to have learned the *surface* — that a PowerShell line is Verb-Noun with
`-Parameters`, that a Sigma rule has `detection:` and `condition:`, that a CVE
record starts with an id and a CVSS vector. That surface competence, appearing
after a few thousand steps from random initialisation, is the signal that the
pipeline works end to end. Fluency is a later, larger model's job.

Sampling is nucleus (top-p) with temperature, which for a small model matters
more than it sounds: greedy decoding collapses into a repeated loop almost
immediately at this scale, and a pure-temperature sample without the top-p cut
wanders into the long tail of a vocabulary it has barely learned. The defaults
here are the ones that make a small model look like what it actually is rather
than better or worse.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import mlx.core as mx
from tokenizers import Tokenizer

from .config import ModelConfig
from .model import Whetstone

__all__ = ["load_for_inference", "generate", "sample_next"]


def load_for_inference(checkpoint: Path) -> tuple[Whetstone, ModelConfig]:
    """Rebuild the model from a checkpoint's own recorded config.

    The config is read from the checkpoint rather than passed in, so a sample is
    always drawn from the architecture that was actually trained — mixing a
    checkpoint with the wrong config produces garbage that looks like a training
    failure and is not.
    """
    state = json.loads((checkpoint / "state.json").read_text(encoding="utf-8"))
    cfg = ModelConfig(**state["model"])
    model = Whetstone(cfg)

    from mlx.utils import tree_unflatten

    weights = mx.load(str(checkpoint / "weights.safetensors"))
    model.update(tree_unflatten(list(weights.items())))
    mx.eval(model.parameters())
    return model, cfg


def sample_next(logits: mx.array, *, temperature: float, top_p: float) -> int:
    """One nucleus-sampled token id from a final-position logit vector."""
    if temperature <= 0:
        return int(mx.argmax(logits).item())

    logits = logits.astype(mx.float32) / temperature
    probs = mx.softmax(logits, axis=-1)

    order = mx.argsort(probs)[::-1]
    ordered = probs[order]
    cumulative = mx.cumsum(ordered, axis=-1)

    # Keep the smallest prefix whose mass reaches top_p, always at least one.
    keep = (cumulative < top_p)
    keep_list = keep.tolist()
    n = 1
    for flag in keep_list:
        if flag:
            n += 1
        else:
            break
    n = min(n, ordered.shape[0])

    head_ids = order[:n]
    head_probs = ordered[:n]
    head_probs = head_probs / mx.sum(head_probs)

    choice = mx.random.categorical(mx.log(head_probs)).item()
    return int(head_ids[choice].item())


def generate(
    model: Whetstone,
    tokenizer: Tokenizer,
    prompt: str,
    *,
    max_tokens: int = 160,
    temperature: float = 0.8,
    top_p: float = 0.95,
    seed: int = 0,
) -> str:
    """Continue ``prompt`` and return the generated text (prompt excluded).

    Uses the KV cache the model already exposes for inference, so cost is linear
    in the number of tokens rather than quadratic — a small courtesy that makes
    the difference between a sample returning promptly and appearing to hang.
    """
    mx.random.seed(seed)
    from .tokenizer.protocol import BOS, EOS

    bos = tokenizer.token_to_id(BOS)
    eos = tokenizer.token_to_id(EOS)
    ids = ([bos] if bos is not None else []) + tokenizer.encode(prompt).ids

    logits, cache = model(mx.array([ids]))
    mx.eval(logits)
    out: list[int] = []

    for _ in range(max_tokens):
        nxt = sample_next(logits[0, -1], temperature=temperature, top_p=top_p)
        if nxt == eos:
            break
        out.append(nxt)
        logits, cache = model(mx.array([[nxt]]), cache=cache)
        mx.eval(logits)

    return tokenizer.decode(out)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Sample from a Whetstone checkpoint.")
    p.add_argument("--checkpoint", type=Path, required=True)
    p.add_argument("--tokenizer", type=Path, required=True)
    p.add_argument("--prompt", default="", help="text to continue")
    p.add_argument("--max-tokens", type=int, default=160)
    p.add_argument("--temperature", type=float, default=0.8)
    p.add_argument("--top-p", type=float, default=0.95)
    p.add_argument("--n", type=int, default=1, help="how many samples")
    p.add_argument("--seed", type=int, default=0)
    args = p.parse_args(argv)

    model, cfg = load_for_inference(args.checkpoint)
    tok = Tokenizer.from_file(str(args.tokenizer))
    print(f"{cfg.name}  {cfg.n_params/1e6:.1f}M params\n")

    for i in range(args.n):
        text = generate(model, tok, args.prompt,
                        max_tokens=args.max_tokens, temperature=args.temperature,
                        top_p=args.top_p, seed=args.seed + i)
        print(f"── sample {i + 1} " + "─" * 40)
        print((args.prompt + text).strip())
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
