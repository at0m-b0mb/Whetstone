r"""Train the security-domain BPE.

The claim this file has to earn: a tokenizer fitted to security text buys back
enough capacity to justify training from scratch at all. That claim is
measurable, so ``--compare`` measures it rather than asserting it.

Why it should be true. A general tokenizer allocates its vocabulary across
everything people write — Chinese, emoji, LaTeX, medical Latin, a long tail of
languages Whetstone will never see. Every one of those slots is a merge rule we
paid for and cannot use. Fitting the vocabulary to shell, registry paths, log
lines, config syntax and security prose should spend all 16,384 slots on text
that actually occurs.

**Where the claim currently stands: unproven.** Trained on ~10 MB of this
author's own repositories, the tokenizer beats gpt2 by **7%** overall — far
short of what the argument above predicts. The per-sample breakdown says why,
and it is not subtle:

    tcp  0  0  0.0.0.0:445 ... LISTEN      +47%   netstat output
    HKLM\SOFTWARE\Microsoft\...\Run        +36%   registry paths
    auditctl -w /etc/passwd -p wa          +17%   audit config
    T1547.001 Registry Run Keys            -45%   ATT&CK ids
    CVE-2024-21412 CVSS 8.1                -26%   CVE ids

Where the training corpus contained the register, the win is large. Where it did
not, gpt2 wins outright — it has seen ATT&CK and CVE identifiers on the web and
this tokenizer never has, because the corpus it was fitted to is Python, C and
Markdown. A tokenizer can only learn merges for text it has met.

So the honest reading is that 7% is a floor measured against the wrong corpus,
not a verdict on the approach. Re-run ``--compare`` once
``training/corpus/build.py`` has assembled the real thing. If the number does
not move substantially, the domain fit is not earning its place and a
general-purpose tokenizer is the better answer — that is a real possible outcome
and much better discovered now than after four days of GPU time.

Byte-level, so nothing is ever out-of-vocabulary. Log files contain arbitrary
bytes — truncated UTF-8, latin-1 hostnames, raw binary in a hexdump — and a
tokenizer that can fail on input is a runtime that can crash on evidence.

    python -m training.tokenizer.train_tokenizer --corpus data/corpus/clean --out data/models/tokenizer
    python -m training.tokenizer.train_tokenizer --compare
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Iterator

from tokenizers import Regex, Tokenizer, decoders, models, pre_tokenizers, trainers

from .protocol import SPECIAL_TOKENS

__all__ = ["train", "SECURITY_SPLIT", "SAMPLES"]


#: The pre-tokenization pattern. Text is split on this first; BPE only ever
#: merges *within* a piece, so this regex decides what the tokenizer is even
#: allowed to learn.
#:
#: Derived from the GPT-4/Llama-3 pattern. The leading alternation keeps a
#: punctuation prefix attached to the following word, which is what makes
#: ``-WmiObject``, ``/etc``, ``\\SOFTWARE`` and ``--verbose`` single pieces
#: rather than two.
#:
#: **Measured, not assumed.** The digit rule was originally ``\p{N}{1,2}`` on
#: the theory that security text is dense with ids that want to be compared
#: exactly. An ablation against gpt2 over the samples below says the choice
#: barely registers:
#:
#: =====================  ===========  ==========
#: digit rule             all samples  ID-heavy
#: =====================  ===========  ==========
#: ``\p{N}{1,2}``         7%           12%
#: ``\p{N}{1,3}``         6%           11%
#: ``\p{N}+``             8%           14%
#: =====================  ===========  ==========
#:
#: Within noise, with ``\p{N}+`` marginally ahead and simplest, so it wins. The
#: useful part of that experiment was the negative result: it ruled out the
#: pre-tokenizer as the reason compression was mediocre, which left the corpus.
SECURITY_SPLIT = Regex(
    r"""(?i:'s|'t|'re|'ve|'m|'ll|'d)"""
    r"""|[^\r\n\p{L}\p{N}]?\p{L}+"""
    r"""|\p{N}+"""
    r"""| ?[^\s\p{L}\p{N}]+[\r\n]*"""
    r"""|\s*[\r\n]+"""
    r"""|\s+(?!\S)"""
    r"""|\s+"""
)


#: Representative text for the comparison, and a smoke test when no corpus
#: exists yet. Deliberately spans the registers the model will actually meet:
#: PowerShell, bash, registry paths, log lines, YAML, and the action protocol.
SAMPLES: tuple[str, ...] = (
    r"Get-WmiObject -Class Win32_Service | Where-Object { $_.StartMode -eq 'Auto' }",
    r"Get-ScheduledTask | Select-Object TaskName, TaskPath, State",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce /s",
    r"systemctl list-unit-files --type=service --state=enabled",
    r"find / -perm -4000 -type f 2>/dev/null",
    r"launchctl list | grep -v com.apple",
    r"cat /etc/systemd/system/multi-user.target.wants/sshd.service",
    r"auditctl -w /etc/passwd -p wa -k identity_change",
    r'{"verb":"enum.persistence","params":{},"target":"10.20.4.2"}',
    r'{"verb":"postex.credential_dump","params":{"redact":true}}',
    r"T1547.001 Registry Run Keys / Startup Folder",
    r"T1053.005 Scheduled Task, T1003 OS Credential Dumping",
    r"EventID 4688 A new process has been created. CommandLine: powershell.exe -enc",
    r"Sysmon Event 1: ProcessCreate ParentImage=C:\Windows\System32\services.exe",
    r"detection: selection: EventID: 4698\n  condition: selection",
    r"CVE-2024-21412 CVSS 8.1 SmartScreen Prompt Security Feature Bypass",
    r"tcp        0      0 0.0.0.0:445             0.0.0.0:*               LISTEN",
    r"chmod 755 /usr/local/bin/agent && chown root:wheel /usr/local/bin/agent",
    r"iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT",
)


def iter_corpus(paths: list[Path], sample_limit: int | None = None) -> Iterator[str]:
    """Yield text from the given roots.

    A root holding ``*.jsonl`` is read as a **built corpus** — the output of
    ``training/corpus/build.py``, with register and side metadata intact.
    Anything else is globbed as raw text files. Supporting both matters: the
    raw path is how a new source gets smoke-tested before it has an adapter,
    and the built path is the one that carries the register information the
    first tokenizer attempt was missing.
    """
    seen = 0
    for root in paths:
        if root.is_dir() and any(root.glob("*.jsonl")):
            from ..corpus.build import read_documents
            for row in read_documents(root):
                yield row["text"]
                seen += 1
                if sample_limit and seen >= sample_limit:
                    return
            continue

        files = [root] if root.is_file() else sorted(
            p for p in root.rglob("*") if p.is_file()
        )
        for path in files:
            if path.suffix.lower() in {".bin", ".npy", ".png", ".jpg", ".zip", ".gz"}:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if not text.strip():
                continue
            yield text
            seen += 1
            if sample_limit and seen >= sample_limit:
                return


def build_tokenizer(vocab_size: int) -> tuple[Tokenizer, trainers.BpeTrainer]:
    tok = Tokenizer(models.BPE(unk_token=None, byte_fallback=False))
    tok.pre_tokenizer = pre_tokenizers.Sequence([
        pre_tokenizers.Split(pattern=SECURITY_SPLIT, behavior="isolated"),
        # Byte-level after splitting: every byte becomes a printable stand-in,
        # so any input at all is representable and decode is exact.
        pre_tokenizers.ByteLevel(add_prefix_space=False, use_regex=False),
    ])
    tok.decoder = decoders.ByteLevel()

    trainer = trainers.BpeTrainer(
        vocab_size=vocab_size,
        special_tokens=list(SPECIAL_TOKENS),
        initial_alphabet=pre_tokenizers.ByteLevel.alphabet(),
        # Two occurrences is enough at this vocabulary size. Raising it throws
        # away rare-but-structural strings (an uncommon cmdlet, a specific
        # registry hive) that are exactly what the domain fit is meant to keep.
        min_frequency=2,
        show_progress=True,
    )
    return tok, trainer


def train(corpus: list[Path], out: Path, vocab_size: int = 16384) -> Tokenizer:
    tok, trainer = build_tokenizer(vocab_size)

    texts = list(iter_corpus(corpus)) if corpus else []
    if not texts:
        print("no corpus found — training on the built-in samples only.\n"
              "This is a smoke test, not a usable tokenizer: build the corpus "
              "first with training/corpus/build.py.", file=sys.stderr)
        texts = list(SAMPLES) * 50

    tok.train_from_iterator(texts, trainer=trainer)

    out.mkdir(parents=True, exist_ok=True)
    tok.save(str(out / "tokenizer.json"))
    (out / "meta.json").write_text(json.dumps({
        "vocab_size": tok.get_vocab_size(),
        "special_tokens": list(SPECIAL_TOKENS),
        "documents": len(texts),
    }, indent=2), encoding="utf-8")
    print(f"\nwrote {out/'tokenizer.json'}  ({tok.get_vocab_size()} tokens, "
          f"{len(texts)} documents)")
    return tok


def compare(tok: Tokenizer | None) -> None:
    """Measure compression against a general-purpose tokenizer.

    The whole argument for a domain vocabulary is this table. If the numbers do
    not separate, the domain fit is not earning its place and a general
    tokenizer is the better answer — that is a real possible outcome and worth
    knowing before spending four days of GPU on it.
    """
    try:
        from tokenizers import Tokenizer as T
        gpt2 = T.from_pretrained("gpt2")
    except Exception as exc:                                  # offline, etc.
        print(f"cannot fetch the reference tokenizer for comparison ({exc}).",
              file=sys.stderr)
        return

    print(f"\n{'sample':<58} {'gpt2':>6} {'ours':>6} {'saved':>7}")
    print("-" * 80)
    tot_g = tot_o = 0
    for s in SAMPLES:
        g = len(gpt2.encode(s).ids)
        o = len(tok.encode(s).ids) if tok else g
        tot_g += g
        tot_o += o
        shown = s if len(s) <= 56 else s[:53] + "..."
        pct = f"{100*(g-o)/g:+.0f}%" if g else "  -"
        print(f"{shown:<58} {g:>6} {o:>6} {pct:>7}")
    print("-" * 80)
    saved = 100 * (tot_g - tot_o) / tot_g if tot_g else 0
    print(f"{'total':<58} {tot_g:>6} {tot_o:>6} {saved:>6.0f}%")
    print(f"\nA {saved:.0f}% reduction is {saved:.0f}% more corpus per training "
          f"hour and {saved:.0f}% more log output per context window.")


#: Roughly one document in this many is withheld from tokenizer training and
#: used only for the compression measurement.
HOLDOUT_EVERY = 20

#: How a document's side of the split is decided. Recorded in meta.json so that
#: a later ``--compare`` can prove it is measuring the same partition the
#: tokenizer was fitted against — a tokenizer trained under one rule and
#: measured under another has no holdout at all. Change the rule below, change
#: this string, and every tokenizer fitted under the old one is refused instead
#: of quietly mismeasured.
HOLDOUT_SCHEME = "fingerprint"


def corpus_identity(clean_dir: Path) -> str:
    """Name the exact corpus build a tokenizer was fitted to, from one stat each.

    File names and sizes, hashed. Deliberately not a content digest: reading half
    a gigabyte to label a measurement would cost more than the measurement does.
    Any rebuild that changes what a source contributed changes that source's file
    size, which is the whole of what this has to notice.
    """
    h = hashlib.sha256()
    for path in sorted(clean_dir.glob("*.jsonl")):
        h.update(f"{path.name}:{path.stat().st_size}\n".encode())
    return h.hexdigest()[:16]


def iter_split(clean_dir: Path, *, holdout: bool) -> Iterator[tuple[str, str]]:
    """Yield ``(register, text)`` from the built corpus, train or holdout side.

    A document's side is decided by its own content, never by where it sits in
    the directory.

    Position was the original rule — ``i % HOLDOUT_EVERY == 0`` over
    ``read_documents`` — and it was deterministic in precisely the way that does
    not help. ``i`` counts every document preceding this one across the sorted
    ``*.jsonl``, so inserting, dropping or reordering a single document anywhere
    shifts every index after it and ROTATES the partition: what was training
    becomes holdout. Rebuilding the corpus was therefore enough to turn the
    held-out compression number into a memorisation check, with nothing said,
    and this corpus is rebuilt often. ``tokenizer-v5``'s meta.json records
    115,849 training documents against a ``clean/`` directory that now holds
    46,835 — a ``--compare --clean`` against it today would have no holdout in
    it at all, and that number is the one the from-scratch case rests on.

    Hashing the text fixes the only property that matters: a document's side must
    not move when its neighbours do. It reuses the corpus's own dedup fingerprint
    rather than introducing a second hash, so two copies of one document can
    never land on opposite sides of the split.

    What this does **not** fix, and is worth not pretending about: a held-out
    document's near neighbours are still on the training side. A hash scatters
    the split as thoroughly as every-20th did, and sources like sigma group
    related rules by directory, so a held-out rule's siblings are usually in
    training. Measured on the built corpus with ``difflib`` over a 449-pair
    sample of adjacent sigma.jsonl documents, 9% of neighbouring pairs exceed
    0.6 similarity. Closing that needs the split keyed on a group rather than a
    document, and ``ident`` is not reliably a path to group by.
    """
    from ..corpus.build import read_documents
    from ..corpus.source import fingerprint

    for row in read_documents(clean_dir):
        is_holdout = (int(fingerprint(row["text"]), 16) % HOLDOUT_EVERY) == 0
        if is_holdout == holdout:
            yield row.get("register", "unknown"), row["text"]


def compare_on_corpus(tok: Tokenizer, clean_dir: Path, *, meta: dict | None = None,
                      max_chars_per_register: int = 400_000) -> None:
    """Measure compression against gpt2 on **held-out real corpus text**, by register.

    This is the measurement that actually settles the domain-tokenizer question,
    and it replaces a weaker one. The :data:`SAMPLES` comparison uses twenty
    strings written by hand while designing the tokenizer — which is close to
    marking your own homework, since the samples and the pre-tokenizer were
    chosen together. Held-out documents from the real corpus cannot be gamed
    that way.

    Per-register matters as much as the total. The first attempt's 7% hid a
    +47%/-45% spread, and an aggregate number would have hidden it again. A
    register that loses to gpt2 is a register the corpus is still starved of.

    ``meta`` is the tokenizer's own meta.json, and it is checked before anything
    is measured. The number below is only held out if this tokenizer was fitted
    against the same split rule :func:`iter_split` applies now, so a missing or
    disagreeing record is refused rather than reported. That is the harsher
    option on purpose: this figure feeds the decision gate at the bottom of this
    function, and a measurement that has quietly stopped being held out is worse
    than no measurement — it reads as a win.
    """
    recorded = (meta or {}).get("holdout")
    if not isinstance(recorded, dict):
        raise SystemExit(
            "this tokenizer's meta.json records no holdout rule, so there is no "
            "way to tell which documents it was trained on. It was fitted before "
            "the split was keyed on content, under the positional rule whose "
            "partition rotates every time the corpus is rebuilt — measuring it "
            f"against {clean_dir} now would report compression on its own "
            "training text. Refit the tokenizer against this corpus.")
    if (recorded.get("scheme"), recorded.get("every")) != (HOLDOUT_SCHEME, HOLDOUT_EVERY):
        raise SystemExit(
            f"this tokenizer was fitted with the holdout rule "
            f"{recorded.get('scheme')!r}/{recorded.get('every')!r}; this code "
            f"splits with {HOLDOUT_SCHEME!r}/{HOLDOUT_EVERY!r}. The two "
            f"partitions do not agree, so the held-out side would contain "
            f"documents the tokenizer trained on. Refit the tokenizer.")

    identity = corpus_identity(clean_dir)
    if recorded.get("corpus") and recorded["corpus"] != identity:
        # Not fatal, and the distinction is the point. Because the split is keyed
        # on content, a document that was on the training side of the old corpus
        # is on the training side of this one too — so the holdout below really
        # is held out and the total is sound. What has changed is the register
        # MIX being measured, which is not the mix this tokenizer was fitted to,
        # and the per-register rows have to be read as a comparison across two
        # corpora rather than a report on one.
        print(f"\nNOTE: fitted to corpus build {recorded['corpus']}, measuring "
              f"against {identity}. The split is keyed on document content, so "
              f"this is still genuinely held out — but the register mix below is "
              f"not the mix the tokenizer was fitted to.", file=sys.stderr)

    try:
        from tokenizers import Tokenizer as T
        gpt2 = T.from_pretrained("gpt2")
    except Exception as exc:
        print(f"cannot fetch the reference tokenizer ({exc}).", file=sys.stderr)
        return

    buckets: dict[str, list[str]] = {}
    sizes: dict[str, int] = {}
    for register, text in iter_split(clean_dir, holdout=True):
        if sizes.get(register, 0) >= max_chars_per_register:
            continue
        buckets.setdefault(register, []).append(text)
        sizes[register] = sizes.get(register, 0) + len(text)

    if not buckets:
        print(f"no held-out documents under {clean_dir}. Build the corpus first.",
              file=sys.stderr)
        return

    print(f"\ncompression on HELD-OUT corpus text "
          f"(~1 document in {HOLDOUT_EVERY}, chosen by content hash)")
    print(f"{'register':<12}{'chars':>11}{'gpt2 tok':>11}{'ours':>10}{'saved':>8}")
    print("-" * 54)

    tot_c = tot_g = tot_o = 0
    rows = []
    for register, texts in sorted(buckets.items()):
        chars = sum(len(t) for t in texts)
        g = sum(len(gpt2.encode(t).ids) for t in texts)
        o = sum(len(tok.encode(t).ids) for t in texts)
        tot_c += chars
        tot_g += g
        tot_o += o
        saved = 100 * (g - o) / g if g else 0.0
        rows.append((register, saved))
        print(f"{register:<12}{chars:>11,}{g:>11,}{o:>10,}{saved:>7.0f}%")

    print("-" * 54)
    overall = 100 * (tot_g - tot_o) / tot_g if tot_g else 0.0
    print(f"{'TOTAL':<12}{tot_c:>11,}{tot_g:>11,}{tot_o:>10,}{overall:>7.0f}%")

    losers = [r for r, s in rows if s < 0]
    if losers:
        print(f"\nLosing to gpt2 on: {', '.join(losers)}. Those registers are still "
              "under-represented in the corpus — collect more source for them "
              "rather than adjusting the tokenizer.")
    if overall < 15:
        print(f"\n{overall:.0f}% overall. The argument for a domain vocabulary "
              "predicts 25-30%. Below ~15% a general-purpose tokenizer is the "
              "better answer and the from-scratch case weakens accordingly — "
              "that is a real possible outcome, not a bug to tune away.")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Train the Whetstone security BPE.")
    p.add_argument("--corpus", type=Path, nargs="*", default=[],
                   help="directories or files of cleaned corpus text")
    p.add_argument("--out", type=Path, default=Path("data/models/tokenizer"))
    p.add_argument("--vocab-size", type=int, default=16384)
    p.add_argument("--compare", action="store_true",
                   help="measure compression against gpt2 and exit")
    p.add_argument("--clean", type=Path,
                   help="built corpus directory (*.jsonl) — enables the "
                        "per-register held-out measurement, which is the one "
                        "that actually settles the domain-tokenizer question")
    args = p.parse_args(argv)

    existing = args.out / "tokenizer.json"
    if args.compare and existing.is_file():
        tok = Tokenizer.from_file(str(existing))
        compare(tok)
        if args.clean:
            # The held-out measurement is only meaningful alongside the record of
            # how this tokenizer's split was drawn, so it is read from beside the
            # tokenizer rather than assumed to match the code running now.
            meta_path = args.out / "meta.json"
            meta = (json.loads(meta_path.read_text(encoding="utf-8"))
                    if meta_path.is_file() else {})
            compare_on_corpus(tok, args.clean, meta=meta)
        return 0

    # Train on the training side of the split only, so the held-out measurement
    # below is genuinely held out rather than a memorisation check.
    if args.clean:
        tok, trainer = build_tokenizer(args.vocab_size)
        # Stream rather than materialise. Collecting the training side into a
        # list held the whole corpus in memory as Python strings, which was
        # survivable at 30M tokens and is not at ten times that — and an OOM
        # here kills a tokenizer that a night of pretraining is waiting on.
        # `train_from_iterator` consumes an iterator directly; counting as it
        # passes keeps the document total honest without a second read.
        seen = 0

        def _training_texts():
            nonlocal seen
            for _reg, text in iter_split(args.clean, holdout=False):
                seen += 1
                yield text

        print(f"training on the corpus under {args.clean} "
              f"(~1 document in {HOLDOUT_EVERY} held out for measurement, "
              f"chosen by content hash so a rebuild cannot move it)")
        tok.train_from_iterator(_training_texts(), trainer=trainer)
        if not seen:
            raise SystemExit(f"no documents under {args.clean}")
        print(f"trained on {seen:,} documents")
        texts = None  # noqa: F841  — nothing below may rely on the materialised list
        args.out.mkdir(parents=True, exist_ok=True)
        tok.save(str(args.out / "tokenizer.json"))
        # The holdout block replaces the bare `holdout_every` this used to write.
        # A number on its own could not say which RULE produced the partition or
        # which corpus it was drawn over, which is exactly what a later
        # --compare has to know before it can claim the measurement is held out.
        meta = {
            "vocab_size": tok.get_vocab_size(),
            "special_tokens": list(SPECIAL_TOKENS),
            "documents": seen,
            "holdout": {
                "scheme": HOLDOUT_SCHEME,
                "every": HOLDOUT_EVERY,
                "corpus": corpus_identity(args.clean),
                "dir": str(args.clean),
            },
        }
        (args.out / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        print(f"wrote {args.out/'tokenizer.json'} ({tok.get_vocab_size()} tokens)")
        compare(tok)
        compare_on_corpus(tok, args.clean, meta=meta)
        return 0

    tok = train(args.corpus, args.out, args.vocab_size)
    compare(tok)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
