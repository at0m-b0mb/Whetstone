"""Corpus-wide line boilerplate detection.

``build.py`` deduplicates whole *documents* by fingerprint, which catches the
same advisory reproduced in two sources. It cannot catch a line that repeats
*inside* thousands of otherwise-distinct documents — and that is exactly the RFC
failure mode the corpus growth pass surfaced: the IETF copyright block appears
4,592 times, the RFC 2119 key-words paragraph 4,770 times, "Information about the
current status of this document" 4,255 times. None of those documents is a
duplicate; each simply carries the same 15 lines of legal furniture. Left in, it
teaches the model to recite a copyright notice, and at this model size that is
capacity actively spent on noise.

The hard part is not removing repeated lines. It is *not* removing the repeated
lines that are signal. A corpus of packet diagrams and register maps is full of
lines that legitimately recur thousands of times::

    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5|

and a naive frequency filter would strip the ASCII-art rulers that are the whole
point of the SYSTEM register. So this filter is deliberately conservative on two
axes at once: a line is dropped only when it is **long enough to be prose**, is
**mostly alphabetic** (structure and diagrams are punctuation-dense), and recurs
**across many distinct documents** rather than many times within one. Boilerplate
is prose that appears verbatim everywhere; signal is either short, symbolic, or
local. The three tests together separate them, and each one alone would not.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Iterable

from .source import Document

__all__ = ["BoilerplateFilter", "find_boilerplate"]

#: A candidate boilerplate line must be at least this long. Short lines are where
#: the false positives live — headers, labels, table cells, the "NAME" line of a
#: man page — and dropping a recurring short line saves almost nothing while
#: risking real structure.
_MIN_LEN = 40

#: …and at least this fraction letters-and-spaces. Diagram rulers, hex dumps and
#: MIB definitions are punctuation-dense and fall below it; a legal sentence sits
#: well above. This is the test that protects the +47% netstat/diagram register
#: from the copyright-notice filter.
_MIN_ALPHA = 0.65

#: A line must recur across at least this many *distinct documents* to count.
#: Intra-document repetition (a config key repeated down a file) is left alone;
#: only text that spans the corpus is furniture.
_MIN_DOCS = 25


def _alpha_ratio(line: str) -> float:
    """Fraction of *non-space* characters that are letters.

    Spaces are excluded from both numerator and denominator, and this is the
    whole correctness of the filter. An earlier version counted spaces as
    letters "so prose with spaces scores high" — but that made a whitespace-
    padded diagram ruler score high too. ``0          1          2          3``
    (the RFC packet-diagram bit ruler) and ``|          |          |`` (a table
    border) are almost all spaces with a few symbols, so counting spaces as
    letters flagged them as prose and the filter stripped the exact SYSTEM-
    register structure it exists to protect. Letters over non-space chars puts a
    legal sentence near 0.85 and a diagram ruler at 0.0, which is the separation
    that was intended.
    """
    non_space = [c for c in line if not c.isspace()]
    if not non_space:
        return 0.0
    letters = sum(c.isalpha() for c in non_space)
    return letters / len(non_space)


def _normalise_line(line: str) -> str:
    """Fold a line to a comparison key: stripped, internal runs collapsed.

    Collapsing runs *here* is correct even though the corpus cleaner must never
    do it, because this string is only ever used as a dictionary key for
    counting — it is never written back into the corpus. Two copies of a notice
    that differ only in wrapping should count as the same line.
    """
    return re.sub(r"\s+", " ", line).strip().casefold()


@dataclass
class BoilerplateFilter:
    """A set of line-keys judged to be corpus-wide furniture."""

    keys: frozenset[str]
    #: Kept for the build report: key -> (documents, total chars it occupied).
    stats: dict[str, tuple[int, int]]

    def strip(self, text: str) -> str:
        """Remove boilerplate lines from one document.

        A run of removed lines collapses to a single blank rather than vanishing,
        so a notice excised from the middle of a document does not weld the
        paragraph before it onto the paragraph after — the same sentence-welding
        mistake the RFC page-break handling had to be fixed for.
        """
        out: list[str] = []
        removed_run = False
        for line in text.split("\n"):
            if _normalise_line(line) in self.keys:
                removed_run = True
                continue
            if removed_run and out and out[-1] != "":
                out.append("")
            removed_run = False
            out.append(line)
        return "\n".join(out).strip()

    @property
    def n_lines(self) -> int:
        return len(self.keys)

    @property
    def chars_removed(self) -> int:
        return sum(chars for _docs, chars in self.stats.values())

    def report(self, limit: int = 8) -> str:
        if not self.keys:
            return "no corpus-wide boilerplate found"
        rows = sorted(self.stats.items(), key=lambda kv: -kv[1][1])
        lines = [f"corpus-wide boilerplate: {self.n_lines} line(s), "
                 f"{self.chars_removed/1e6:.1f}M chars across the corpus"]
        for key, (docs, chars) in rows[:limit]:
            preview = key[:64] + ("…" if len(key) > 64 else "")
            lines.append(f"  {docs:>6} docs  {chars/1e6:>5.1f}M  {preview}")
        if len(rows) > limit:
            lines.append(f"  … and {len(rows) - limit} more")
        return "\n".join(lines)


def find_boilerplate(
    documents: Iterable[Document],
    *,
    min_docs: int = _MIN_DOCS,
    min_len: int = _MIN_LEN,
    min_alpha: float = _MIN_ALPHA,
) -> BoilerplateFilter:
    """Scan documents once and return the lines that are corpus-wide furniture.

    Counts *distinct documents* a line appears in, not raw occurrences, so a line
    repeated fifty times inside one file does not qualify on its own — that is
    local structure, and only text that spans many documents is boilerplate.
    """
    doc_count: Counter[str] = Counter()
    char_total: defaultdict[str, int] = defaultdict(int)

    for doc in documents:
        seen_here: set[str] = set()
        for raw in doc.text.split("\n"):
            line = raw.strip()
            if len(line) < min_len or _alpha_ratio(line) < min_alpha:
                continue
            key = _normalise_line(line)
            if key not in seen_here:
                seen_here.add(key)
                doc_count[key] += 1
            char_total[key] += len(raw)

    keys = {k for k, n in doc_count.items() if n >= min_docs}
    stats = {k: (doc_count[k], char_total[k]) for k in keys}
    return BoilerplateFilter(keys=frozenset(keys), stats=stats)
