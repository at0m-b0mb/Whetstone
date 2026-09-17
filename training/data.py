"""Corpus → token shards → batches.

Three jobs, kept in one file because they share a format and drifting apart
would be silent: tokenise text into flat binary shards, memory-map those shards
at training time, and hand out batches.

**uint16, not uint32.** The vocabulary is 16,384, which fits in 16 bits with
room to spare, so every token costs two bytes instead of four. On a 3B-token
corpus that is 6 GB rather than 12 — the difference between the training set
living in the page cache and being read off the disk every epoch. The
:func:`write_shard` guard makes the assumption explicit, because the day someone
raises the vocabulary past 65,535 this file must fail loudly rather than wrap
tokens around to zero and produce a model that has learned nonsense.

**Sampling is with replacement, from a global index.** A loader that walks
shards in order and restarts is the classic silent bug: the model sees shard 0
far more often than shard 9, and the loss curve looks perfectly healthy while
the data distribution is quietly wrong. Here every batch draws uniformly across
the whole concatenated corpus, so shard boundaries have no effect on what the
model sees. :meth:`Dataset.coverage_report` exists so that claim is checkable
rather than trusted.

**The validation split is held out by position, not by shuffling.** The last
``val_fraction`` of the token stream is reserved and never sampled for training.
Splitting after shuffling would put near-duplicate passages — the same advisory
text quoted in two documents — on both sides, and a validation loss measured
against text the model has effectively seen is worse than no validation at all.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Sequence

import numpy as np

__all__ = ["write_shard", "tokenize_corpus", "Dataset", "ShardIndex"]

#: Tokens are stored as uint16. See the module docstring.
TOKEN_DTYPE = np.uint16
MAX_VOCAB = np.iinfo(TOKEN_DTYPE).max + 1


def write_shard(path: Path, tokens: Sequence[int] | np.ndarray) -> int:
    """Write one shard of token ids, returning how many were written."""
    arr = np.asarray(tokens, dtype=np.int64)
    if arr.size and int(arr.max()) >= MAX_VOCAB:
        raise ValueError(
            f"token id {int(arr.max())} does not fit in {TOKEN_DTYPE.__name__} "
            f"(max {MAX_VOCAB - 1}). Either shrink the vocabulary or widen "
            "TOKEN_DTYPE — do not let this wrap, it would silently corrupt "
            "every shard written afterwards."
        )
    if arr.size and int(arr.min()) < 0:
        raise ValueError("negative token id")
    path.parent.mkdir(parents=True, exist_ok=True)
    arr.astype(TOKEN_DTYPE).tofile(path)
    return int(arr.size)


def tokenize_corpus(
    corpus_dirs: list[Path],
    tokenizer_path: Path,
    out_dir: Path,
    *,
    shard_tokens: int = 50_000_000,
    eos_between_documents: bool = True,
) -> ShardIndex:
    """Tokenise every file under ``corpus_dirs`` into shards under ``out_dir``.

    Documents are separated by the EOS token so the model learns that documents
    end. Without it, training windows straddle unrelated documents and the model
    spends capacity learning to predict the start of an arbitrary next file from
    the end of the previous one — a mapping that does not exist.
    """
    from tokenizers import Tokenizer

    from .tokenizer.protocol import EOS
    from .tokenizer.train_tokenizer import iter_corpus

    tok = Tokenizer.from_file(str(tokenizer_path))
    eos_id = tok.token_to_id(EOS)
    if eos_between_documents and eos_id is None:
        raise ValueError(f"tokenizer has no {EOS} token")

    out_dir.mkdir(parents=True, exist_ok=True)
    for stale in out_dir.glob("shard-*.bin"):
        stale.unlink()

    shards: list[dict] = []
    buffer: list[int] = []
    total = 0
    docs = 0

    def flush(index: int) -> None:
        nonlocal buffer
        if not buffer:
            return
        path = out_dir / f"shard-{index:04d}.bin"
        n = write_shard(path, buffer)
        shards.append({"file": path.name, "tokens": n})
        print(f"  {path.name}  {n:,} tokens")
        buffer = []

    for text in iter_corpus(corpus_dirs):
        ids = tok.encode(text).ids
        if not ids:
            continue
        buffer.extend(ids)
        if eos_between_documents:
            buffer.append(eos_id)
        docs += 1
        total += len(ids) + (1 if eos_between_documents else 0)
        if len(buffer) >= shard_tokens:
            flush(len(shards))

    flush(len(shards))

    index = ShardIndex(root=out_dir, shards=shards, total_tokens=total,
                       documents=docs, vocab_size=tok.get_vocab_size())
    index.save()
    print(f"\n{total:,} tokens from {docs:,} documents "
          f"across {len(shards)} shard(s) → {out_dir}")
    return index


@dataclass
class ShardIndex:
    """What was written, so training does not have to rediscover it."""

    root: Path
    shards: list[dict]
    total_tokens: int
    documents: int
    vocab_size: int

    def save(self) -> None:
        (self.root / "index.json").write_text(json.dumps({
            "shards": self.shards,
            "total_tokens": self.total_tokens,
            "documents": self.documents,
            "vocab_size": self.vocab_size,
        }, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, root: Path) -> ShardIndex:
        meta = json.loads((root / "index.json").read_text(encoding="utf-8"))
        return cls(root=root, shards=meta["shards"],
                   total_tokens=meta["total_tokens"],
                   documents=meta["documents"],
                   vocab_size=meta["vocab_size"])


class Dataset:
    """Memory-mapped token stream with uniform random-window sampling."""

    def __init__(
        self,
        root: Path,
        seq_len: int,
        *,
        val_fraction: float = 0.005,
        split: str = "train",
        seed: int = 1337,
    ) -> None:
        self.index = ShardIndex.load(root)
        self.seq_len = seq_len
        self.split = split
        self._rng = np.random.default_rng(seed)

        self._maps: list[np.memmap] = []
        self._starts: list[int] = []
        offset = 0
        for shard in self.index.shards:
            path = root / shard["file"]
            mm = np.memmap(path, dtype=TOKEN_DTYPE, mode="r")
            if mm.size != shard["tokens"]:
                raise ValueError(
                    f"{path.name} holds {mm.size:,} tokens but the index claims "
                    f"{shard['tokens']:,}. The shard was rewritten without "
                    "updating the index; re-run tokenize_corpus."
                )
            self._maps.append(mm)
            self._starts.append(offset)
            offset += mm.size
        self.total = offset

        if self.total <= seq_len + 1:
            raise ValueError(
                f"corpus holds {self.total:,} tokens, which is not enough for "
                f"even one window of {seq_len + 1}"
            )

        # Held out by position, not by shuffling. See the module docstring.
        boundary = int(self.total * (1 - val_fraction))
        if split == "train":
            self.lo, self.hi = 0, boundary
        elif split == "val":
            self.lo, self.hi = boundary, self.total
        else:
            raise ValueError(f"unknown split {split!r}")

        if self.hi - self.lo <= seq_len + 1:
            raise ValueError(
                f"{split} split holds {self.hi - self.lo:,} tokens, too few for "
                f"a window of {seq_len + 1}. Lower val_fraction or add corpus."
            )

    def _read(self, start: int, length: int) -> np.ndarray:
        """Read ``length`` tokens from the global position ``start``.

        Windows may straddle a shard boundary, so this stitches. Returning a
        short window instead would bias the sampler toward the interiors of
        shards, which is the subtle version of the bug the module docstring
        warns about.
        """
        out = np.empty(length, dtype=np.int64)
        written = 0
        shard = int(np.searchsorted(self._starts, start, side="right") - 1)
        pos = start - self._starts[shard]
        while written < length:
            mm = self._maps[shard]
            take = min(length - written, mm.size - pos)
            out[written:written + take] = mm[pos:pos + take]
            written += take
            shard += 1
            pos = 0
            if shard >= len(self._maps):
                break
        if written < length:                       # ran off the end; wrap
            out[written:] = self._maps[0][:length - written]
        return out

    def batch(self, batch_size: int) -> tuple[np.ndarray, np.ndarray]:
        """One batch of ``(inputs, targets)``, each ``(batch_size, seq_len)``."""
        span = self.hi - self.lo - self.seq_len - 1
        starts = self._rng.integers(self.lo, self.lo + span, size=batch_size)
        window = np.stack([self._read(int(s), self.seq_len + 1) for s in starts])
        return window[:, :-1], window[:, 1:]

    def iter_batches(self, batch_size: int, n: int) -> Iterator[tuple[np.ndarray, np.ndarray]]:
        for _ in range(n):
            yield self.batch(batch_size)

    def coverage_report(self, batch_size: int = 32, batches: int = 200) -> str:
        """Sample the sampler and report how evenly shards are visited.

        The loader bug this guards against does not announce itself: the loss
        curve looks fine while the model sees the first shard ten times as often
        as the last. Run this once after building shards, not never.
        """
        counts = np.zeros(len(self._maps), dtype=np.int64)
        span = self.hi - self.lo - self.seq_len - 1
        rng = np.random.default_rng(0)
        for _ in range(batches):
            for s in rng.integers(self.lo, self.lo + span, size=batch_size):
                counts[int(np.searchsorted(self._starts, int(s), side="right") - 1)] += 1
        sizes = np.array([m.size for m in self._maps], dtype=np.float64)
        expected = sizes / sizes.sum()
        actual = counts / max(counts.sum(), 1)
        lines = [f"{'shard':<14}{'tokens':>14}{'expected':>10}{'actual':>9}{'drift':>8}"]
        for i, shard in enumerate(self.index.shards):
            lines.append(
                f"{shard['file']:<14}{shard['tokens']:>14,}"
                f"{expected[i]:>9.1%}{actual[i]:>9.1%}"
                f"{actual[i]-expected[i]:>+8.1%}"
            )
        worst = float(np.max(np.abs(actual - expected))) if len(counts) else 0.0
        lines.append(f"\nworst drift {worst:.2%} "
                     f"({'uniform' if worst < 0.02 else 'CHECK THE SAMPLER'})")
        return "\n".join(lines)

    def __repr__(self) -> str:
        return (f"Dataset({self.split}, {self.hi - self.lo:,} tokens, "
                f"seq_len={self.seq_len}, {len(self._maps)} shard(s))")
