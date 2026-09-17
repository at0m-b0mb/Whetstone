"""The transformer, in MLX.

Deliberately unoriginal. RMSNorm, pre-norm residuals, rotary position embeddings,
grouped-query attention, SwiGLU, tied embeddings, no biases — the shape everyone
converged on, because a from-scratch run has enough ways to fail without the
architecture being one of them. If this model does not learn, the bug is in the
data, the tokenizer or the schedule, and being able to say that with confidence
is worth more than any clever variant.

Two choices here are load-bearing for *this* project rather than generic:

**Tied embeddings via ``as_linear``.** At 15M parameters the embedding table is
36% of the model. Giving the output head its own copy would make it 53%, spent
on a matrix that does approximately what the input embedding already does in
reverse. MLX's ``nn.Embedding.as_linear`` shares the weight directly, so there
is one table and one gradient.

**Residual projections are down-scaled at init.** Every layer adds into the
residual stream, so with ``L`` layers the stream's variance grows like ``L``
unless the projections that write into it start small. Scaling ``o_proj`` and
the FFN's ``down_proj`` by ``1/sqrt(2L)`` keeps activations in range at step
zero. Skipping this is survivable at 8 layers and is the reason a 22-layer run
diverges in the first few hundred steps.
"""

from __future__ import annotations

import math
from typing import Any

import mlx.core as mx
import mlx.nn as nn

from .config import ModelConfig

__all__ = ["Whetstone", "Attention", "FeedForward", "Block"]


class Attention(nn.Module):
    """Grouped-query attention with rotary positions.

    ``n_kv_heads`` < ``n_heads`` means several query heads share one key/value
    head. The parameter saving is modest at these widths; the saving that
    matters is the KV cache at inference, which is what decides whether the
    finished model answers from a laptop's memory or thrashes.
    """

    def __init__(self, cfg: ModelConfig) -> None:
        super().__init__()
        self.n_heads = cfg.n_heads
        self.n_kv_heads = cfg.n_kv_heads
        self.head_dim = cfg.head_dim
        self.scale = self.head_dim ** -0.5
        self.rope_base = cfg.rope_base

        d = cfg.d_model
        self.q_proj = nn.Linear(d, cfg.n_heads * self.head_dim, bias=False)
        self.k_proj = nn.Linear(d, cfg.n_kv_heads * self.head_dim, bias=False)
        self.v_proj = nn.Linear(d, cfg.n_kv_heads * self.head_dim, bias=False)
        self.o_proj = nn.Linear(cfg.n_heads * self.head_dim, d, bias=False)

    def __call__(
        self,
        x: mx.array,
        mask: Any = None,
        cache: tuple[mx.array, mx.array] | None = None,
    ) -> tuple[mx.array, tuple[mx.array, mx.array]]:
        B, L, _ = x.shape

        q = self.q_proj(x).reshape(B, L, self.n_heads, self.head_dim).transpose(0, 2, 1, 3)
        k = self.k_proj(x).reshape(B, L, self.n_kv_heads, self.head_dim).transpose(0, 2, 1, 3)
        v = self.v_proj(x).reshape(B, L, self.n_kv_heads, self.head_dim).transpose(0, 2, 1, 3)

        # Rotary positions must continue from wherever the cache left off, or a
        # generated token is told it is at position 0 and the model produces
        # fluent nonsense — a bug that never shows up in training loss.
        offset = cache[0].shape[2] if cache is not None else 0
        q = mx.fast.rope(q, self.head_dim, traditional=False, base=self.rope_base,
                         scale=1.0, offset=offset)
        k = mx.fast.rope(k, self.head_dim, traditional=False, base=self.rope_base,
                         scale=1.0, offset=offset)

        if cache is not None:
            k = mx.concatenate([cache[0], k], axis=2)
            v = mx.concatenate([cache[1], v], axis=2)

        out = mx.fast.scaled_dot_product_attention(q, k, v, scale=self.scale, mask=mask)
        out = out.transpose(0, 2, 1, 3).reshape(B, L, -1)
        return self.o_proj(out), (k, v)


class FeedForward(nn.Module):
    """SwiGLU: ``down(silu(gate(x)) * up(x))``.

    Three matrices rather than two, which is why ``ffn_dim`` is 8/3·d_model
    rather than 4·d_model — it keeps the parameter count the same as a plain
    two-matrix FFN would have had.
    """

    def __init__(self, cfg: ModelConfig) -> None:
        super().__init__()
        d, f = cfg.d_model, cfg.ffn_dim
        self.gate_proj = nn.Linear(d, f, bias=False)
        self.up_proj = nn.Linear(d, f, bias=False)
        self.down_proj = nn.Linear(f, d, bias=False)

    def __call__(self, x: mx.array) -> mx.array:
        return self.down_proj(nn.silu(self.gate_proj(x)) * self.up_proj(x))


class Block(nn.Module):
    """One pre-norm transformer layer."""

    def __init__(self, cfg: ModelConfig) -> None:
        super().__init__()
        self.attn_norm = nn.RMSNorm(cfg.d_model, eps=cfg.norm_eps)
        self.attn = Attention(cfg)
        self.ffn_norm = nn.RMSNorm(cfg.d_model, eps=cfg.norm_eps)
        self.ffn = FeedForward(cfg)

    def __call__(
        self,
        x: mx.array,
        mask: Any = None,
        cache: tuple[mx.array, mx.array] | None = None,
    ) -> tuple[mx.array, tuple[mx.array, mx.array]]:
        h, new_cache = self.attn(self.attn_norm(x), mask, cache)
        x = x + h
        x = x + self.ffn(self.ffn_norm(x))
        return x, new_cache


class Whetstone(nn.Module):
    """The model.

    Takes token ids ``(B, L)`` and returns logits ``(B, L, vocab)``. The loss
    lives in the trainer rather than here so that this class stays usable for
    generation, scoring and probing without carrying a training concern around.
    """

    def __init__(self, cfg: ModelConfig) -> None:
        super().__init__()
        self.cfg = cfg
        self.embed = nn.Embedding(cfg.vocab_size, cfg.d_model)
        self.layers = [Block(cfg) for _ in range(cfg.n_layers)]
        self.norm = nn.RMSNorm(cfg.d_model, eps=cfg.norm_eps)
        self._init_weights()

        # Initialise in float32 and cast once, so the random draws are identical
        # whichever dtype we end up training in — otherwise a bf16 run and an
        # fp32 run of the same seed are not comparable, and the first thing you
        # want when a run misbehaves is to re-run it in fp32 and see if the
        # problem follows.
        if cfg.dtype != "float32":
            self.set_dtype(getattr(mx, cfg.dtype))

    # ------------------------------------------------------------------ init

    def _init_weights(self) -> None:
        """Normal(0, 0.02), with residual writers scaled down by 1/sqrt(2L).

        See the module docstring: without the residual scaling the deeper rungs
        of the staircase diverge in the first few hundred steps, and the failure
        looks like a bad learning rate rather than a bad init.
        """
        cfg = self.cfg
        residual_scale = 0.02 / math.sqrt(2 * cfg.n_layers)

        def normal(shape: tuple[int, ...], std: float) -> mx.array:
            return mx.random.normal(shape=shape, loc=0.0, scale=std)

        self.embed.weight = normal(self.embed.weight.shape, 0.02)

        for block in self.layers:
            for proj in (block.attn.q_proj, block.attn.k_proj, block.attn.v_proj,
                         block.ffn.gate_proj, block.ffn.up_proj):
                proj.weight = normal(proj.weight.shape, 0.02)
            # The two projections that write into the residual stream.
            for proj in (block.attn.o_proj, block.ffn.down_proj):
                proj.weight = normal(proj.weight.shape, residual_scale)

    # --------------------------------------------------------------- forward

    def __call__(
        self,
        ids: mx.array,
        cache: list[tuple[mx.array, mx.array]] | None = None,
    ) -> tuple[mx.array, list[tuple[mx.array, mx.array]]]:
        x = self.embed(ids)

        # A single-token step with a populated cache needs no mask: the one
        # query attends to every cached key, all of which precede it.
        mask: Any = None
        if ids.shape[1] > 1:
            mask = "causal"

        caches = cache if cache is not None else [None] * len(self.layers)
        new_caches = []
        for layer, layer_cache in zip(self.layers, caches):
            x, updated = layer(x, mask, layer_cache)
            new_caches.append(updated)

        x = self.norm(x)
        # Tied head — one weight, one gradient. See the module docstring.
        return self.embed.as_linear(x), new_caches

    # ----------------------------------------------------------------- utils

    def loss(self, ids: mx.array, targets: mx.array) -> mx.array:
        """Mean cross-entropy over the batch.

        Kept here rather than in the trainer only because evaluation wants it
        too, and two copies of a loss function is how they drift apart.
        """
        logits, _ = self(ids)
        return nn.losses.cross_entropy(
            logits.astype(mx.float32).reshape(-1, self.cfg.vocab_size),
            targets.reshape(-1),
            reduction="mean",
        )

    def n_params(self) -> int:
        """Count what is actually allocated, rather than what config predicts.

        These two numbers agreeing is a real check — a mismatch means the class
        built something the config does not describe, and every FLOP and
        wall-clock estimate downstream is then wrong.
        """
        from mlx.utils import tree_flatten
        return sum(v.size for _, v in tree_flatten(self.parameters()))
