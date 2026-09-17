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
    """Yield text from every readable file under the given roots."""
    seen = 0
    for root in paths:
        if root.is_file():
            files = [root]
        else:
            files = sorted(p for p in root.rglob("*") if p.is_file())
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


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Train the Whetstone security BPE.")
    p.add_argument("--corpus", type=Path, nargs="*", default=[],
                   help="directories or files of cleaned corpus text")
    p.add_argument("--out", type=Path, default=Path("data/models/tokenizer"))
    p.add_argument("--vocab-size", type=int, default=16384)
    p.add_argument("--compare", action="store_true",
                   help="measure compression against gpt2 and exit")
    args = p.parse_args(argv)

    existing = args.out / "tokenizer.json"
    if args.compare and existing.is_file():
        compare(Tokenizer.from_file(str(existing)))
        return 0

    tok = train(args.corpus, args.out, args.vocab_size)
    compare(tok)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
