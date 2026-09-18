"""Model configurations — the 15M → 60M → 150M staircase.

Nobody should debug a training pipeline on a four-day run. Every bug worth
finding — a mis-shaped mask, a loader that silently repeats a shard, a schedule
that never warms up — shows itself in twenty minutes at 15M just as clearly as
it would in four days at 150M, and costs twenty minutes to find. The staircase
exists so that the only thing the big run is testing is the hypothesis that more
capacity helps.

**Why the vocabulary is 16,384 and not 32k or 50k.**

At this scale the embedding table is not a rounding error, it is the budget. A
32k vocab at ``d_model=320`` is 10.5M parameters — most of a 15M model spent
before a single transformer block exists. Halving the vocabulary halves that,
and a domain model can afford it: Whetstone's text is shell, log lines, config
and security prose, not the whole internet. A general-purpose tokenizer has to
reserve room for Chinese, emoji, LaTeX and a long tail of languages we will
never see. We spend those slots on ``Get-WmiObject``, ``HKLM\\SOFTWARE``,
``T1547.001`` and ``/etc/systemd/system`` instead.

The tradeoff is real and runs the other way too: a smaller vocabulary means more
tokens per document, so the same corpus costs more compute to train on. 16k is
the point where, on a security corpus, the compression win from domain merges
still outweighs the loss from fewer slots. ``training/tokenizer/`` measures this
rather than assuming it — see ``compare_vocab_sizes``.

**MEASURED, on this machine, before committing to any long run.**

An M4 Pro with 24 GB of unified memory, AdamW, real forward+backward steps::

    variant                tok/s   TFLOP/s   peak GB     days
    fp32  ctx2048  B2      1,914      1.73     18.69     36.5
    bf16  ctx2048  B2      3,383      3.07      9.70     20.7
    bf16  ctx1024  B2      4,137      3.75      4.28     16.9
    bf16  ctx1024  B8      4,493      4.07     13.68     15.6

Two things fell out of that table, and neither was a guess anyone would have
got right:

*bfloat16 is not an optimisation, it is the project.* It halves peak memory and
nearly doubles throughput. In fp32 at ctx 2048 the base model peaks at 18.7 GB,
which on a 24 GB machine with a desktop running means swap — and a run that has
started swapping is not slow, it is finished. An earlier pass measured 75 tok/s
for exactly this reason, an 86x collapse that looked like a broken model and was
a full disk cache.

*40 tokens per parameter was too ambitious.* It put the base run at 15+ days.
Chinchilla-optimal is 20, which is where the default now sits, and it puts base
at roughly 8 days at ctx 1024. Small models genuinely do benefit from training
well past compute-optimal — SmolLM and TinyLlama both sit above 100 tokens per
parameter — so raise it if the machine is free. Just raise it deliberately.

**Why embeddings are tied.** Untying costs another ``V·D`` parameters for the
output head, which at 15M is another third of the model spent on a matrix that
does roughly what the input embedding already does in reverse. Tying is close to
free in quality at this scale and is not optional here.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Iterator

__all__ = ["ModelConfig", "TrainConfig", "STAIRCASE", "get_config"]


def _round_to(value: float, multiple: int) -> int:
    """Round up to a multiple — kernels prefer aligned shapes."""
    return int(((value + multiple - 1) // multiple) * multiple)


@dataclass(frozen=True, slots=True)
class ModelConfig:
    """A decoder-only transformer, in the shape everything modern converged on.

    RMSNorm rather than LayerNorm, pre-norm rather than post-norm, RoPE rather
    than learned positions, SwiGLU rather than GELU, grouped-query attention, and
    no biases anywhere. None of these are novel and that is the point: a
    from-scratch run has enough ways to fail without the architecture being one
    of them.
    """

    name: str
    vocab_size: int = 16384
    d_model: int = 320
    n_layers: int = 8
    n_heads: int = 8
    #: Grouped-query attention. Fewer KV heads shrinks the KV cache at inference
    #: and costs little quality. At these sizes the parameter saving is modest;
    #: the inference-memory saving on a laptop is not.
    n_kv_heads: int = 4
    #: SwiGLU's hidden width. Left as None to derive 8/3·d_model, the ratio that
    #: keeps a gated FFN's parameter count equal to a plain 4·d_model one.
    d_ff: int | None = None
    max_seq_len: int = 1024
    rope_base: float = 10000.0
    norm_eps: float = 1e-5
    #: Tied input embedding and output head. See the module docstring.
    tie_embeddings: bool = True
    #: Compute dtype. bfloat16 is not a tuning knob, it is the difference
    #: between this project fitting on the machine and not — see MEASURED below.
    dtype: str = "bfloat16"

    def __post_init__(self) -> None:
        if self.d_model % self.n_heads:
            raise ValueError(
                f"{self.name}: d_model {self.d_model} is not divisible by "
                f"n_heads {self.n_heads}"
            )
        if self.n_heads % self.n_kv_heads:
            raise ValueError(
                f"{self.name}: n_heads {self.n_heads} is not divisible by "
                f"n_kv_heads {self.n_kv_heads}"
            )
        if not self.tie_embeddings:
            raise ValueError(
                f"{self.name}: untied embeddings cost another vocab_size × "
                "d_model parameters, which at this scale is a third of the "
                "model spent on a matrix the input embedding already covers. "
                "If you genuinely want this, remove the check and say why."
            )

    @property
    def head_dim(self) -> int:
        return self.d_model // self.n_heads

    @property
    def ffn_dim(self) -> int:
        if self.d_ff is not None:
            return self.d_ff
        return _round_to(self.d_model * 8 / 3, 64)

    # ------------------------------------------------------------- counting

    @property
    def embedding_params(self) -> int:
        return self.vocab_size * self.d_model

    @property
    def params_per_layer(self) -> int:
        d, hd = self.d_model, self.head_dim
        q = d * (self.n_heads * hd)
        k = d * (self.n_kv_heads * hd)
        v = k
        o = (self.n_heads * hd) * d
        ffn = 3 * d * self.ffn_dim          # gate, up, down
        norms = 2 * d                        # attention norm + ffn norm
        return q + k + v + o + ffn + norms

    @property
    def n_params(self) -> int:
        """Total trainable parameters, embeddings included (they are tied)."""
        return (
            self.embedding_params
            + self.n_layers * self.params_per_layer
            + self.d_model          # final norm
        )

    @property
    def n_params_non_embedding(self) -> int:
        """The number people usually mean when comparing model 'size'.

        Worth watching alongside the total: a model that is mostly embedding
        table has far less capacity for behaviour than its headline suggests,
        which is exactly the trap this project is designed around.
        """
        return self.n_params - self.embedding_params

    @property
    def measured_tokens_per_sec(self) -> float:
        """Throughput actually observed on an M4 Pro / 24 GB, not estimated.

        See MEASURED in the module docstring for the full table and the two
        things it caught.
        """
        return _MEASURED_TPS.get(self.name, 4_000.0)

    def measured_days(self, n_tokens: int) -> float:
        return n_tokens / self.measured_tokens_per_sec / 86400

    def flops_per_token(self) -> int:
        """Forward+backward FLOPs per token, the 6·N approximation.

        Attention's quadratic term is excluded, as it is in the usual estimate.
        At ``max_seq_len`` 1024 and these widths it is a small correction; the
        number is here to plan wall-clock, not to publish.
        """
        return 6 * self.n_params

    def training_days(self, n_tokens: int, tflops_sustained: float = 3.0) -> float:
        """Wall-clock estimate for a run of ``n_tokens``.

        ``tflops_sustained`` defaults to a deliberately pessimistic 3.0 for an
        M4 Pro: peak is higher, but a real loop spends time on the optimizer,
        the data loader and memory traffic, and a schedule built on peak numbers
        is a schedule that slips.
        """
        total = self.flops_per_token() * n_tokens
        return total / (tflops_sustained * 1e12) / 86400

    def summary(self) -> str:
        m = self.n_params / 1e6
        ne = self.n_params_non_embedding / 1e6
        emb_pct = 100 * self.embedding_params / self.n_params
        return (
            f"{self.name:<10} {m:6.1f}M params  ({ne:5.1f}M non-embedding, "
            f"{emb_pct:4.1f}% embedding)\n"
            f"           d_model {self.d_model}  layers {self.n_layers}  "
            f"heads {self.n_heads}/{self.n_kv_heads}kv  head_dim {self.head_dim}  "
            f"ffn {self.ffn_dim}  ctx {self.max_seq_len}"
        )


@dataclass(frozen=True, slots=True)
class TrainConfig:
    """Optimisation settings.

    The defaults are the boring, well-attested ones. AdamW with beta2 0.95
    rather than 0.999 because short runs on small models benefit from a faster-
    adapting second moment; cosine decay to a tenth of peak; warmup as a
    fraction of total steps rather than a fixed count so the staircase scales;
    gradient clipping at 1.0 because a from-scratch run *will* meet a bad batch
    and the alternative is losing a day to a single spike.
    """

    batch_tokens: int = 65_536      # tokens per optimizer step, across accumulation
    micro_batch: int = 8            # sequences per forward pass — fits 24 GB
    learning_rate: float = 3e-4
    min_lr_ratio: float = 0.1
    warmup_ratio: float = 0.02
    weight_decay: float = 0.1
    beta1: float = 0.9
    beta2: float = 0.95
    grad_clip: float = 1.0
    #: Chinchilla-optimal. Small models are routinely trained far past this,
    #: because inference cost rather than training cost is what matters for
    #: something you will run constantly — SmolLM and TinyLlama both sit above
    #: 100 tokens per parameter. This started at 40 and came down after the
    #: measurement in config's MEASURED table put the base run at 15+ days.
    #: Raise it if the machine is free overnight; just raise it on purpose.
    tokens_per_param: int = 20
    seed: int = 1337
    checkpoint_every: int = 500
    eval_every: int = 250
    log_every: int = 10
    #: How many validation windows one evaluation scores. The val set is a
    #: FIXED, deterministic set of windows — see ``training.pretrain
    #: .val_window_starts`` — and not a fresh random draw, because a val curve
    #: whose sample moves every time measures the sampler as much as the model,
    #: and "best checkpoint" then means "luckiest draw". 512 is *exhaustive*
    #: for every corpus this project has built: the v5 val split is 498,386
    #: tokens, which is 486 non-overlapping windows of 1,025. The cap therefore
    #: costs nothing today and exists only so that a corpus ten times larger
    #: cannot quietly turn an evaluation that is 1% of wall clock into one that
    #: is 17%.
    val_windows: int = 512

    def total_tokens(self, model: ModelConfig) -> int:
        return self.tokens_per_param * model.n_params

    def total_steps(self, model: ModelConfig) -> int:
        # Divided by the batch the run actually takes, not the one configured.
        # Dividing a token budget by a batch 6% larger than reality is how a
        # run reaches its step count having trained on 6% less than Chinchilla
        # asked for, with nothing anywhere saying so.
        return max(1, self.total_tokens(model) // self.effective_batch_tokens(model))

    def grad_accum_steps(self, model: ModelConfig) -> int:
        """Micro-batches summed into one optimizer step.

        Floor division, so a ``micro_batch * max_seq_len`` that does not divide
        ``batch_tokens`` yields a *smaller* batch than the configured one: at
        ``micro_batch=6`` and ctx 1024 this returns 10, for 61,440 tokens
        against the 65,536 the learning rate was chosen for. A count of
        micro-batches cannot be fractional, so the truncation itself has to
        stay. What must not happen is the rest of the program going on to
        report 65,536 anyway — which is what it did, in the step budget, in the
        tokens/step line and in the wall-clock estimate, all three confidently
        wrong while the loss curve looked unremarkable. Every number derived
        from batch size now comes from ``effective_batch_tokens``, so nobody
        can reintroduce that by reading ``batch_tokens`` directly.
        """
        per_micro = self.micro_batch * model.max_seq_len
        return max(1, self.batch_tokens // per_micro)

    def effective_batch_tokens(self, model: ModelConfig) -> int:
        """Tokens per optimizer step this config actually delivers.

        Equal to ``batch_tokens`` only when ``micro_batch * max_seq_len``
        divides it. It can also come out *larger*: a micro_batch whose single
        forward pass already exceeds ``batch_tokens`` clamps accumulation to 1
        and doubles the batch instead of halving it. Both directions are
        silent in the loss curve, which is why this is a named property rather
        than an assumption anyone is expected to hold in their head.
        """
        return self.grad_accum_steps(model) * self.micro_batch * model.max_seq_len


#: The staircase. Climb it in order; do not skip a rung because the previous one
#: looked fine — "looked fine" is what a loader bug looks like at 15M.
STAIRCASE: dict[str, ModelConfig] = {
    # ~20 minutes. Proves the pipeline end to end: does loss go down, does a
    # checkpoint round-trip, does resume land on the same number.
    "tiny": ModelConfig(
        name="tiny", d_model=320, n_layers=8, n_heads=8, n_kv_heads=4,
        max_seq_len=1024,
    ),
    # ~half a day. The first checkpoint that should produce structurally valid
    # actions often enough to measure on whetstone-bench.
    "small": ModelConfig(
        name="small", d_model=512, n_layers=18, n_heads=8, n_kv_heads=4,
        max_seq_len=1024,
    ),
    # ~four to five days. The target.
    "base": ModelConfig(
        name="base", d_model=768, n_layers=22, n_heads=12, n_kv_heads=4,
        # ctx 1024 rather than 2048: the longer context costs ~25% throughput
        # and three extra days, and a 151M model has little to spend it on.
        # Trajectories are kept inside 1024 by summarising observations; if the
        # finished model needs more reach, RoPE extension is cheaper after the
        # fact than paying for it across the whole run.
        max_seq_len=1024,
    ),
}

#: Tokens/second measured on an M4 Pro / 24 GB at the batch size each rung
#: actually trains with. Used for schedule estimates so that "days" means the
#: number this machine produced rather than a number from a spec sheet.
_MEASURED_TPS: dict[str, float] = {
    "tiny": 18_886.0,
    "small": 6_495.0,
    "base": 4_493.0,
}


def get_config(name: str) -> ModelConfig:
    try:
        return STAIRCASE[name]
    except KeyError:
        raise SystemExit(
            f"unknown model {name!r}; choose one of {', '.join(STAIRCASE)}"
        ) from None


def iter_staircase() -> Iterator[ModelConfig]:
    yield from STAIRCASE.values()


if __name__ == "__main__":
    train = TrainConfig()
    print("Whetstone model staircase\n")
    for cfg in iter_staircase():
        tokens = train.total_tokens(cfg)
        print(cfg.summary())
        print(
            f"           {tokens/1e9:5.2f}B tokens at {train.tokens_per_param}/param"
            f"  ·  {train.total_steps(cfg):,} steps"
            f"  ·  ~{cfg.measured_days(tokens):.1f} days at a measured "
            f"{cfg.measured_tokens_per_sec:,.0f} tok/s\n"
        )
