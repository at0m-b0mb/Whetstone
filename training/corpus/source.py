"""The corpus contract: what a source is, and what it must declare.

This file exists because of a measurement. Fitted to ~10 MB of this author's own
repositories, the domain tokenizer beat gpt2 by only 7% — far short of what the
argument for a domain vocabulary predicts. The per-sample breakdown said why, and
it was not subtle::

    tcp 0 0 0.0.0.0:445 ... LISTEN     +47%   netstat output
    HKLM\\SOFTWARE\\Microsoft\\...\\Run    +36%   registry paths
    T1547.001 Registry Run Keys        -45%   ATT&CK ids
    CVE-2024-21412 CVSS 8.1            -26%   CVE ids

Where the corpus contained the register, the win was large. Where it did not,
gpt2 won outright — it has met ATT&CK and CVE identifiers on the web and our
tokenizer never had, because the corpus was Python, C and Markdown. An ablation
ruled out the pre-tokenizer as the cause. The corpus was the cause.

So the lesson is encoded here rather than written in a comment somewhere: every
document carries a :class:`Register`, and the build reports coverage per
register. A corpus that is 90% prose is now a *visible* failure before training
starts, not a mystery discovered afterwards in a tokenizer comparison.

:class:`Side` does the same job for the offence/defence balance. The project
deliberately weights toward offence — roughly 60/40 — on the argument that blue
knowledge (Sigma rules, log schemas, control catalogues) is highly retrievable
while red judgement is sequential decision-making retrieval cannot supply. A
target that nothing measures is a wish, so the build measures it.

**Licensing is mandatory, not decoration.** Every source declares one, and
``build.py`` refuses to run a source whose licence is blank. Training on
scraped text of unknown provenance is how a project becomes unpublishable, and
the point at which that is cheap to get right is now.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Iterator, Protocol

__all__ = [
    "Register", "Side", "Document", "SourceSpec", "SourceError",
    "normalise", "fingerprint", "REGISTER_TARGETS",
]


class SourceError(RuntimeError):
    """A source could not be fetched or parsed."""


class Register(Enum):
    """The kind of text, which is the axis the tokenizer actually cares about.

    Two documents can both be "security content" and tokenise completely
    differently. A Sigma rule and a threat-intel blog post share a topic and
    share almost no surface form — and it is surface form that a BPE learns.
    Grouping by register is what makes corpus coverage a checkable property
    rather than a vibe.
    """

    #: Commands, scripts, cmdlets, one-liners. PowerShell, bash, zsh, cmd.
    SHELL = "shell"
    #: Detection logic and the log fields it references — Sigma, queries,
    #: event schemas, EventIDs.
    DETECTION = "detection"
    #: Adversary behaviour described as behaviour: technique prose, ATT&CK ids,
    #: procedure narratives.
    ADVERSARY = "adversary"
    #: Vulnerability records: CVE ids, CVSS strings, affected-version ranges.
    ADVISORY = "advisory"
    #: How the machine works: man pages, service definitions, registry paths,
    #: config file syntax, API references.
    SYSTEM = "system"
    #: Security writing in sentences — methodology, explanation, reports.
    PROSE = "prose"
    #: Agent trajectories in the wire protocol. Generated, not collected; the
    #: only register that grows from the runtime's own logs.
    TRAJECTORY = "trajectory"


class Side(Enum):
    RED = "red"
    BLUE = "blue"
    NEUTRAL = "neutral"


#: Target share of the corpus per register, as a fraction. These are the
#: hypothesis, not a law — they encode "a model that picks verbs and reads
#: command output needs far more shell and system text than prose". The build
#: prints observed-vs-target so a corpus that drifts is visible immediately.
#:
#: SHELL and SYSTEM dominate deliberately: those are the registers the model
#: must both read (command output) and reason about, and they are precisely
#: where the first tokenizer attempt was starved.
REGISTER_TARGETS: dict[Register, float] = {
    Register.SHELL: 0.28,
    Register.SYSTEM: 0.26,
    Register.DETECTION: 0.14,
    Register.ADVERSARY: 0.12,
    Register.ADVISORY: 0.10,
    Register.PROSE: 0.10,
    Register.TRAJECTORY: 0.00,   # grows later, from the runtime's audit logs
}


_TRAILING = re.compile(r"[ \t]+$", re.MULTILINE)
_ABSURD = re.compile(r"[ \t]{200,}")
_NL = re.compile(r"\n{3,}")
#: Control bytes minus \t and \n, which are structural here, not noise.
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def normalise(text: str) -> str:
    """Light cleaning only. **Horizontal whitespace is preserved.**

    Aggressive cleaning is how a security corpus loses the exact thing it was
    collected for: the alignment of netstat columns, the indentation of a YAML
    rule, the shape of a registry path. Those are signal.

    This function originally collapsed runs of spaces and tabs to a single
    space, which is the obvious "tidy the text" move and was exactly wrong::

        tcp        0      0 0.0.0.0:445    LISTEN     ->  tcp 0 0 0.0.0.0:445 LISTEN
        detection:\\n    selection:\\n        EventID  ->  detection:\\n selection:\\n EventID

    The first destroys the column structure that scored +47% against gpt2 in
    the tokenizer measurement — the single best register this project has. The
    second flattens YAML nesting to one space, making rule *depth*
    unrecoverable, which would have quietly gutted the entire DETECTION
    register before anyone looked at a token count.

    So: line endings normalised, control bytes dropped (tab and newline kept,
    they are structure), trailing whitespace stripped per line (it carries no
    signal and only bloats the token count), blank-line runs capped. Leading and
    internal spacing is left exactly as the source wrote it.
    """
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _CTRL.sub("", text)
    # A run this long is a rendering artefact, not layout — keep enough to show
    # it was a gap without spending hundreds of tokens on it.
    text = _ABSURD.sub(" " * 8, text)
    text = _TRAILING.sub("", text)
    text = _NL.sub("\n\n", text)
    return text.strip()


def fingerprint(text: str) -> str:
    """A stable hash for near-duplicate detection.

    Case-folded and stripped of all whitespace before hashing, so the same
    advisory reproduced with different wrapping in two sources collapses to one
    fingerprint. Exact-hash dedup would miss those entirely, and duplicated text
    in a small corpus is worse than absent text: the model memorises it.
    """
    compact = re.sub(r"\s+", "", text).casefold()
    return hashlib.sha256(compact.encode("utf-8")).hexdigest()[:32]


@dataclass(frozen=True, slots=True)
class Document:
    """One unit of corpus text, with the provenance the build needs."""

    text: str
    source: str
    register: Register
    side: Side = Side.NEUTRAL
    #: Stable identifier within the source (a path, a technique id, a rule id).
    #: Used for reporting and for reproducible ordering, not for dedup.
    ident: str = ""

    def __post_init__(self) -> None:
        if not self.text.strip():
            raise SourceError(f"{self.source}: empty document {self.ident!r}")

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.text)

    @property
    def n_chars(self) -> int:
        return len(self.text)


@dataclass(frozen=True, slots=True)
class SourceSpec:
    """A declared corpus source.

    ``fetch`` is separated from ``documents`` so the network step is cached and
    idempotent: a build re-run does not re-download 200 MB of STIX, and a source
    can be developed offline against an already-fetched cache.
    """

    name: str
    #: SPDX identifier or an explicit short statement. Blank is refused.
    license: str
    #: Where it came from, so the claim above is checkable.
    url: str
    register: Register
    side: Side
    #: Download into the cache directory. Returns the path it populated. May be
    #: a no-op for sources that read from the local machine.
    fetch: Callable[[Path], Path]
    #: Yield cleaned documents from whatever ``fetch`` produced.
    documents: Callable[[Path], Iterator[Document]]
    #: Rough expected size, for a sanity check on the build report. A source
    #: that yields two documents when it promised thousands has silently broken
    #: — usually an upstream layout change — and should be loud about it.
    expect_min_docs: int = 1
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.license.strip():
            raise SourceError(
                f"source {self.name!r} declares no licence. Every source states "
                "one — training on text of unknown provenance is how a project "
                "becomes unpublishable, and this is the cheap moment to fix it."
            )
        if not self.url.strip():
            raise SourceError(f"source {self.name!r} declares no url")
