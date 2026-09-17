"""Assemble the corpus, and report what it is actually made of.

    python -m training.corpus.build --out data/corpus/clean
    python -m training.corpus.build --report          # read an existing build

Discovers every ``SPEC`` under ``training/corpus/sources/``, fetches, cleans,
deduplicates, and writes JSONL with provenance intact. Then — the part that
earns this file's existence — prints the **balance report**.

The first Whetstone corpus was ~10 MB of this author's own repositories. It
looked fine. The tokenizer fitted to it beat gpt2 by 7% instead of the 25-30%
the argument predicted, and only a per-sample breakdown revealed why: the corpus
was Python, C and Markdown, so ATT&CK ids scored -45% and CVE ids -26% while
netstat output scored +47%. The corpus had been starved of entire registers and
nothing said so until four steps downstream.

So this build refuses to be quiet about composition. Every document carries a
:class:`~training.corpus.source.Register`, every build prints observed share
against :data:`~training.corpus.source.REGISTER_TARGETS`, and a corpus that has
drifted is visible in the terminal before a single token is trained.

**On balancing.** ``--balance`` subsamples over-represented registers toward
their target. It never *repeats* an under-represented one: duplicated text in a
small corpus is worse than missing text, because the model memorises it and the
validation loss lies to you about it. Under-representation is therefore reported
as a gap to go and collect more source for, never papered over — and everything
dropped is logged, because a silent cap reads as "we covered it" when we did not.
"""

from __future__ import annotations

import argparse
import importlib
import json
import pkgutil
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

from .source import (
    REGISTER_TARGETS,
    Document,
    Register,
    Side,
    SourceError,
    SourceSpec,
)

__all__ = ["discover_sources", "build", "read_documents", "balance_report"]


def discover_sources() -> list[SourceSpec]:
    """Import every adapter under ``sources/`` and collect its SPEC.

    Import-time discovery rather than a hand-maintained list: a source that
    exists but was forgotten in a registry is exactly the kind of silent
    omission this module is written to prevent.
    """
    from . import sources as sources_pkg

    specs: list[SourceSpec] = []
    for info in pkgutil.iter_modules(sources_pkg.__path__):
        if info.name.startswith("_"):
            continue
        module = importlib.import_module(f"{sources_pkg.__name__}.{info.name}")
        spec = getattr(module, "SPEC", None)
        if spec is None:
            print(f"  ! {info.name} defines no SPEC — skipped", file=sys.stderr)
            continue
        if not isinstance(spec, SourceSpec):
            raise SourceError(f"{info.name}.SPEC is not a SourceSpec")
        specs.append(spec)
    return sorted(specs, key=lambda s: s.name)


@dataclass
class BuildStats:
    """What one source contributed, after dedup."""

    name: str
    register: Register
    side: Side
    license: str
    docs: int = 0
    chars: int = 0
    duplicates: int = 0
    dropped_for_balance: int = 0
    error: str = ""


def build(
    out_dir: Path,
    cache_dir: Path,
    *,
    only: list[str] | None = None,
    balance: bool = False,
    min_chars: int = 40,
) -> list[BuildStats]:
    """Fetch, clean, dedupe and write the corpus. Returns per-source stats."""
    out_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)

    specs = discover_sources()
    if only:
        specs = [s for s in specs if s.name in only]
    if not specs:
        raise SystemExit(
            "no corpus sources found under training/corpus/sources/. "
            "Each adapter exports a module-level SPEC = SourceSpec(...)."
        )

    print(f"{len(specs)} source(s): {', '.join(s.name for s in specs)}\n")

    seen: set[str] = set()
    stats: list[BuildStats] = []
    collected: dict[str, list[Document]] = {}

    for spec in specs:
        st = BuildStats(name=spec.name, register=spec.register, side=spec.side,
                        license=spec.license)
        stats.append(st)
        print(f"── {spec.name}  [{spec.register.value}/{spec.side.value}]  {spec.license}")
        try:
            path = spec.fetch(cache_dir / spec.name)
        except Exception as exc:                       # a source is allowed to fail
            st.error = f"fetch failed: {type(exc).__name__}: {exc}"
            print(f"   ! {st.error}")
            continue

        kept: list[Document] = []
        try:
            for doc in spec.documents(path):
                if doc.n_chars < min_chars:
                    continue
                fp = doc.fingerprint
                if fp in seen:
                    st.duplicates += 1
                    continue
                seen.add(fp)
                kept.append(doc)
                st.docs += 1
                st.chars += doc.n_chars
        except Exception as exc:
            st.error = f"parse failed after {st.docs} docs: {type(exc).__name__}: {exc}"
            print(f"   ! {st.error}")

        collected[spec.name] = kept
        note = f"   {st.docs:,} docs  {st.chars/1e6:.2f}M chars"
        if st.duplicates:
            note += f"  ({st.duplicates:,} duplicates dropped)"
        print(note)
        if st.docs < spec.expect_min_docs:
            print(f"   ! expected at least {spec.expect_min_docs:,} docs but got "
                  f"{st.docs:,} — upstream layout may have changed")

    if balance:
        _apply_balance(collected, stats)

    # Write after balancing so what lands on disk is what the report describes.
    for spec in specs:
        docs = collected.get(spec.name, [])
        if not docs:
            continue
        path = out_dir / f"{spec.name}.jsonl"
        with path.open("w", encoding="utf-8") as fh:
            for doc in docs:
                fh.write(json.dumps({
                    "text": doc.text,
                    "source": doc.source,
                    "register": doc.register.value,
                    "side": doc.side.value,
                    "ident": doc.ident,
                }, ensure_ascii=False) + "\n")

    _write_provenance(out_dir, specs, stats)
    print("\n" + balance_report(stats))
    return stats


def _apply_balance(collected: dict[str, list[Document]], stats: list[BuildStats]) -> None:
    """Subsample over-represented registers toward target. Never repeats.

    Repetition is the tempting fix for an under-represented register and it is
    the wrong one: in a corpus this size the model memorises repeated passages,
    and held-out loss then reports a number that has nothing to do with
    generalisation. Under-representation stays visible in the report as a gap to
    collect more source for.
    """
    by_register: dict[Register, int] = Counter()
    for docs in collected.values():
        for d in docs:
            by_register[d.register] += d.n_chars
    total = sum(by_register.values())
    if not total:
        return

    # The binding constraint: the register furthest BELOW its target sets the
    # scale everything else can be trimmed to. Trimming to an absolute target
    # would throw away most of the corpus for no reason.
    scale = min(
        (by_register[r] / (REGISTER_TARGETS[r] * total)
         for r in by_register
         if REGISTER_TARGETS.get(r, 0) > 0 and by_register[r] > 0),
        default=1.0,
    )
    if scale <= 0:
        return

    budget = {r: REGISTER_TARGETS.get(r, 0) * total * scale for r in by_register}
    spent: dict[Register, float] = Counter()
    st_by_name = {s.name: s for s in stats}

    for name, docs in collected.items():
        keep: list[Document] = []
        for doc in docs:
            allowance = budget.get(doc.register, 0)
            if allowance and spent[doc.register] + doc.n_chars > allowance:
                st_by_name[name].dropped_for_balance += 1
                continue
            spent[doc.register] += doc.n_chars
            keep.append(doc)
        collected[name] = keep
        st_by_name[name].docs = len(keep)
        st_by_name[name].chars = sum(d.n_chars for d in keep)

    dropped = sum(s.dropped_for_balance for s in stats)
    if dropped:
        # No silent caps: say exactly what went, and from where.
        print(f"\nbalance: dropped {dropped:,} documents to approach register targets")
        for s in stats:
            if s.dropped_for_balance:
                print(f"  -{s.dropped_for_balance:,} from {s.name} ({s.register.value})")

        kept = sum(s.chars for s in stats)
        lost = 1 - (kept / total) if total else 0
        if lost > 0.5:
            scarcest = min(
                (r for r in by_register if REGISTER_TARGETS.get(r, 0) > 0),
                key=lambda r: by_register[r] / REGISTER_TARGETS[r],
            )
            print(
                f"\n  WARNING: balancing discarded {lost:.0%} of the corpus.\n"
                f"  The binding constraint is {scarcest.value!r} — every other register\n"
                f"  is scaled down to match the one that is scarcest relative to target.\n"
                f"  For PRETRAINING this is usually the wrong trade: unique text is the\n"
                f"  scarce resource at this model size, and a perfectly balanced corpus\n"
                f"  a fifth the size trains a worse model than a skewed larger one.\n"
                f"  Prefer: build unbalanced for the language model, use --balance only\n"
                f"  for fitting the tokenizer (where the register mix decides the merges\n"
                f"  and the cost of dropping text is near zero), and treat the register\n"
                f"  report as a shopping list for what to collect next."
            )


def _write_provenance(out_dir: Path, specs: list[SourceSpec], stats: list[BuildStats]) -> None:
    """Record where every byte came from and under what licence.

    Written on every build, next to the data, because a provenance file that
    lives somewhere else drifts out of date and a corpus whose licensing cannot
    be reconstructed is a corpus that cannot be published.
    """
    by_name = {s.name: s for s in stats}
    lines = [
        "# Corpus provenance",
        "",
        "Generated by `training/corpus/build.py`. Every source states its upstream",
        "licence; the build refuses a source that declares none.",
        "",
        "| Source | Register | Side | Documents | Chars | Licence | Upstream |",
        "|---|---|---|---:|---:|---|---|",
    ]
    for spec in specs:
        st = by_name[spec.name]
        lines.append(
            f"| `{spec.name}` | {spec.register.value} | {spec.side.value} | "
            f"{st.docs:,} | {st.chars:,} | {spec.license} | {spec.url} |"
        )
    notes = [f"- **{s.name}** — {s.notes}" for s in specs if s.notes]
    if notes:
        lines += ["", "## Notes", ""] + notes
    (out_dir / "PROVENANCE.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def balance_report(stats: list[BuildStats]) -> str:
    """Observed composition against target. The output that matters.

    Read this before every training run. A register far under target is the
    tokenizer result from the first attempt, visible in advance instead of
    four steps downstream.
    """
    ok = [s for s in stats if s.docs]
    total_chars = sum(s.chars for s in ok) or 1

    by_reg: Counter[Register] = Counter()
    by_side: Counter[Side] = Counter()
    for s in ok:
        by_reg[s.register] += s.chars
        by_side[s.side] += s.chars

    lines = ["register coverage", "-" * 58,
             f"{'register':<12}{'chars':>12}{'share':>9}{'target':>9}{'drift':>10}"]
    for reg in Register:
        target = REGISTER_TARGETS.get(reg, 0.0)
        if not target and not by_reg[reg]:
            continue
        share = by_reg[reg] / total_chars
        drift = share - target
        flag = "" if abs(drift) < 0.05 else ("  LOW" if drift < 0 else "  high")
        lines.append(f"{reg.value:<12}{by_reg[reg]:>12,}{share:>8.1%}"
                     f"{target:>9.0%}{drift:>+9.1%}{flag}")

    red = by_side[Side.RED] / total_chars
    blue = by_side[Side.BLUE] / total_chars
    neutral = by_side[Side.NEUTRAL] / total_chars
    offensive = red / (red + blue) if (red + blue) else 0.0

    lines += [
        "", "offence / defence balance", "-" * 58,
        f"red {red:.1%}   blue {blue:.1%}   neutral {neutral:.1%}",
        f"red share of the non-neutral corpus: {offensive:.0%}  (target ~60%)",
        "", f"total: {total_chars/1e6:.1f}M chars across {sum(s.docs for s in ok):,} documents",
    ]

    failed = [s for s in stats if s.error]
    if failed:
        lines += ["", "sources that failed", "-" * 58]
        lines += [f"  {s.name}: {s.error}" for s in failed]

    return "\n".join(lines)


def read_documents(clean_dir: Path, *, registers: Iterable[Register] | None = None) -> Iterator[dict]:
    """Stream built documents back, optionally filtered by register.

    The tokenizer and the shard writer both read through here rather than
    globbing raw text, so metadata survives all the way to the point where it
    can be used — which is what lets a tokenizer be fitted to a deliberately
    chosen register mix instead of whatever happened to be on disk.
    """
    wanted = {r.value for r in registers} if registers else None
    for path in sorted(clean_dir.glob("*.jsonl")):
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                row = json.loads(line)
                if wanted and row.get("register") not in wanted:
                    continue
                yield row


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Build the Whetstone corpus.")
    p.add_argument("--out", type=Path,
                   default=Path("/Volumes/at0m_b0mb/whetstone/corpus/clean"))
    p.add_argument("--cache", type=Path,
                   default=Path("/Volumes/at0m_b0mb/whetstone/corpus/raw"))
    p.add_argument("--only", nargs="*", help="build only these sources")
    p.add_argument("--balance", action="store_true",
                   help="subsample over-represented registers toward target")
    p.add_argument("--report", action="store_true",
                   help="report on an existing build without fetching")
    args = p.parse_args(argv)

    if args.report:
        counts: dict[tuple[str, str, str], list[int]] = {}
        for row in read_documents(args.out):
            key = (row["source"], row["register"], row["side"])
            slot = counts.setdefault(key, [0, 0])
            slot[0] += 1
            slot[1] += len(row["text"])
        stats = [
            BuildStats(name=n, register=Register(r), side=Side(s), license="",
                       docs=c[0], chars=c[1])
            for (n, r, s), c in sorted(counts.items())
        ]
        print(balance_report(stats))
        return 0

    build(args.out, args.cache, only=args.only, balance=args.balance)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
