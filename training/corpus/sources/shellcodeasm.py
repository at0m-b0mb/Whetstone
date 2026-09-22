"""Assembly: what an instruction sequence means, and how to read a listing.

The corpus had never shown the model an instruction. Not one. It holds tens of
thousands of detection rules, a full CVE database, two attack taxonomies, six
Python security projects and eleven shell repositories — and between all of
them there is no ``mov``, no ``svc 0``, no ``pop rdi ; ret``, and no line of the
form ``0x00401136  4889e5  mov rbp, rsp``. A model in that state can repeat the
word "shellcode" and cannot say what one *is*. Asked to reason about an exploit,
a stripped binary or a malware sample, it has to work entirely from prose about
the artefact, never from the artefact. That is the gap this source closes.

**The line this source draws, because a reader will ask.** The brief that
produced it said working exploit payloads for current software are not what this
corpus needs, and that is right, but the line has to be drawn somewhere precise
or it is not a line. Here it is: *architecture facts are in; vulnerability facts
are out.*

What an ``execve`` stub looks like on aarch64, which register the kernel reads
the syscall number out of, how a ``ret`` walks a stack you control, what the GOT
is for — these are properties of a processor and an ABI. They are documented in
the vendor manuals, they are the same for a defender reading a sample and an
attacker writing one, and a model that cannot follow them cannot read a
disassembly listing at all. Those are in.

What is out is anything whose value depends on a *particular vulnerable build*:
CVE proof-of-concept code, ROP chains with gadget addresses from a specific
binary, heap-grooming sequences tuned to a specific allocator version. Those
teach the model one target rather than one mechanism, they go stale within a
release cycle, and they are the part that makes a corpus a liability. Two
otherwise attractive upstreams were refused on exactly this line, and they are
named in the rejection list at the bottom of this docstring.

The four upstreams, and what each one is for:

* **pwntools shellcraft** — annotated shellcode. Every template is assembly with
  its intent attached: a ``<%docstring>`` saying what the payload does, often
  with the assembled output pasted in beside it, comment by comment
  (``push SYS_execve /* 0x3b */``). This is the single clearest statement in
  open source of *shellcode as a thing a person writes on purpose*, and it
  spans amd64, i386, aarch64, arm, thumb, mips, riscv64, loongarch64 and
  powerpc, on Linux, FreeBSD, Darwin, Windows and CGC.
* **musl libc** — the syscall stub and the calling convention, per architecture.
  ``arch/<arch>/syscall_arch.h`` is the convention itself, written as inline asm
  with the register constraints spelled out: on aarch64 the number goes in
  ``x8`` and the arguments in ``x0..x5``; on x86-64 it is ``rax`` and
  ``rdi, rsi, rdx, r10, r8, r9`` — note ``r10``, not ``rcx``, and
  ``src/thread/x86_64/syscall_cp.s`` shows the four-instruction shuffle that
  fact forces on every caller. That one difference is most of what separates
  somebody who can read a syscall stub from somebody who cannot.
  ``arch/<arch>/bits/syscall.h.in`` is the syscall number table for nineteen
  architectures, which is the other half of reading one.
* **CTF101** — the exploitation primitives explained as mechanism. Stack layout,
  calling conventions, the GOT and the PLT, ROP, canaries, RELRO, NX, ASLR,
  format strings; and on the reverse-engineering side, what a disassembler and a
  decompiler actually do. Short, plain, and drawn with column-aligned stack
  diagrams that step a ``pop rdi ; ret`` gadget one instruction at a time.
* **The radare2 book** — disassembly listings with commentary. Real
  ``[0x00000000]> pdf`` transcripts, real ESIL, real function analysis, and the
  running explanation of what the columns mean. It is the only permissively
  reusable body of *listing* text this project found; everything else that
  teaches listing-reading is a paper book.

**Register: SYSTEM overall, ADVERSARY per document, and the label is not a
rounding.** The brief asked for ADVERSARY if it could be had honestly, because
ADVERSARY is short. It cannot be had for the whole source. Measured on what this
adapter actually emits, roughly a fifth of the characters are shellcode and
exploitation mechanism — those documents are labelled
:class:`~training.corpus.source.Register.ADVERSARY` / ``RED`` individually, and
the balancer counts them there. The rest is syscall tables, ABI headers and
disassembly transcripts, which are
:class:`~training.corpus.source.Register.SYSTEM` / ``NEUTRAL`` by any reading:
they belong to the processor, not to a side. Labelling the whole source
ADVERSARY to help a number would have put 1.35 MB of ABI headers into the
register the balancer is trying to protect, which is the one failure mode
:mod:`~training.corpus.source` was written to prevent. :data:`SPEC` therefore
declares the majority and every document declares the truth.

**The trap, and it is the whole risk in this adapter.** There is no compiler
here. :mod:`~training.corpus.sources.pythoncode` can prove its register survived
cleaning by parsing every file before and after
:func:`~training.corpus.source.normalise`; assembly has no such check that can
be run on a mixed tree of ``.asm`` templates, ``.s`` files, C headers and
Markdown, and the damage that matters would be invisible in a build report
anyway. A disassembly listing whose columns have been collapsed still contains
every mnemonic and every address — the character count barely moves — and it has
stopped being a listing. So the invariant is asserted directly, on every
document, in :func:`_prove_columns`: the sequence of non-blank lines, each with
only its *trailing* whitespace removed, must be identical before and after
normalisation. That is an exact statement rather than a heuristic, because the
gates in :func:`_admit` remove the only two things that could make it
approximate — a control byte (which ``normalise`` deletes) and a run of two
hundred spaces (which it collapses). Any other difference can only be a
normaliser that has started eating horizontal whitespace, and that raises.

``compile()`` earns its place on top of that, on the one part of this corpus
that is executable. A shellcraft template embeds Python in ``<% ... %>`` blocks,
and 570 of the 576 such blocks compile when wrapped in a function. Those that do
are compiled again after normalisation and must still compile. ``compile()``
rather than ``ast.parse()`` is not style: ``ast.parse("return 1")`` succeeds and
``compile("return 1", "<s>", "exec")`` raises, so a check built on ``ast`` would
silently accept a block Python itself rejects. The six that do not compile
beforehand are not rejected — they are Mako, where ``continue`` may appear
inside a block that the template engine nests in a ``%for`` loop, and a
template's right to be Mako is not this adapter's business.

**Symlinks, twice.** Nothing here follows one. :func:`_walk` uses
``os.walk(followlinks=False)`` rather than ``rglob`` for the reason
:mod:`~training.corpus.sources.ownrepos` records the hard way — a sibling
adapter once walked a link into the shared cache and pulled 180 MB of other
sources back in under its own label. The second place is less obvious and it
fired for real: :func:`_extract` writes only regular tar members, and the
shellcraft template tree contains **31 symlinks** — ``amd64/linux/kill.asm ->
../../common/linux/kill.asm``, ``aarch64/trap.asm -> breakpoint.asm`` — so an
adapter that resolved them would have written fifteen byte-identical copies into
the cache and then relied on fingerprint dedup to notice. The targets are all
inside the tree and are collected once, on their own path, which is the right
answer and is also what the counts in :data:`SPEC` are measured against.

**Licences, each read from the upstream's own file and copied into the cache
beside what it covers.** pwntools is MIT by ``LICENSE-pwntools.txt``, which
carves out ``pwnlib/constants/`` and ``pwnlib/data/`` as GPL or BSD-2 — neither
is collected here, and the check that they are the *only* carve-outs is that
those two directories are precisely where the repository's own nested
``LICENSE.txt`` files live. musl is MIT by ``COPYRIGHT``, whose named exceptions
are all permissive and are listed in :data:`SPEC` rather than summarised away —
and of them only two survive this adapter's path filter:
``src/string/arm/memcpy.S`` (BSD-2-Clause, The Android Open Source Project) and
``src/string/aarch64/*`` (Arm Limited). TRE and the Sun/FreeBSD math code sit
under trees that :data:`_MUSL_DROP` and :func:`_want_musl` never reach. CTF101
is MIT. The radare2 book is **CC-BY-SA-4.0** — copyleft, stated as copyleft, and
kept for the reason :mod:`~training.corpus.sources.owasp` keeps a CC-BY-SA cheat
sheet: the obligation is attribution and share-alike on the text, the text is
reproduced whole, and there is no permissive substitute for it.

**Rejected, with reasons, so nobody spends an afternoon rediscovering them.**

* ``ctf-wiki/ctf-wiki`` — CC-BY-**NC**-SA-4.0. The NonCommercial clause is a
  field-of-use restriction on a corpus this project intends to be publishable.
  Refused on licence. This is the largest single body of exploitation writing
  that was otherwise a perfect fit.
* ``guyinatuxedo/nightmare`` and ``Ir0nstone/binary-exploitation-notes`` — no
  LICENSE file at all. An unlicensed repository is all rights reserved no matter
  how public it is. Refused on licence.
* ``shellphish/how2heap`` — MIT, so the licence is fine, and it is refused on
  the analytical/operational line above: it is working heap exploitation against
  named glibc versions, which teaches one allocator build rather than one
  mechanism. CTF101's heap pages carry the mechanism.
* ``NationalSecurityAgency/ghidra`` — Apache-2.0 and genuinely wanted. Its
  SLEIGH processor specifications are the best permissively licensed statement
  of x86 and AArch64 instruction *semantics* in existence, and each AArch64
  constructor even cites its ARM ARM section and encoding mask. It is not here
  for two reasons: the repository is 400 MB for the two files worth having, so
  it would have to be fetched by hard-coded raw URLs that break silently when
  the upstream renames one; and ``ia.sinc`` plus ``AARCH64base.sinc`` are 900 KB
  of a specification DSL that resembles nothing else in this corpus, which would
  make a quarter of this source one artificial language. It deserves its own
  adapter with its own budget, not a corner of this one.
* Ghidra's *documentation*, as distinct from its specifications, is PDF course
  material and generated HTML help. Nothing to extract.
* ``pwntools/docs/`` — MIT and already fetched, and still dropped: every file is
  a Sphinx ``automodule`` stub. The prose it renders lives in the ``pwnlib``
  docstrings, which :mod:`~training.corpus.sources.pythoncode` already collects.
* Metasploit's ``external/source/shellcode/`` — BSD-3, well commented, and
  exactly on topic. Not taken because
  :mod:`~training.corpus.sources.metasploit` pays for a 69 MB sparse checkout of
  that repository whose cone covers ``modules/`` only; collecting the shellcode
  would mean a second, much larger fetch of the same upstream. It is the best
  candidate for the next pass at this register.
* ``exploit-db`` — GPL-2.0 *and* a working-exploit archive. Both grounds.
* ``scapy``, ``sqlmap``, ``radare2`` itself, ``rizin`` — GPL-2.0, GPL-2.0,
  LGPL-3.0, LGPL-3.0. The radare2 *book* is a separate repository under a
  separate licence, which is why it is here and the engine is not.
* ``NASM`` — BSD-2-Clause, so admissible, and skipped on value: the manual is
  written in a bespoke ``rdsrc`` markup this adapter would have to learn, and
  the ``test/*.asm`` files are encoder torture tests with almost no prose.
* ``glibc`` (LGPL-2.1) and the Linux kernel's own ``arch/`` trees (GPL-2.0) both
  hold better assembly than musl does. musl was chosen over both because it is
  MIT and small enough to read.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tarfile
import textwrap
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

from ..net import NetworkError, download
from ..source import (
    Document, Register, Side, SourceError, SourceSpec, fingerprint, normalise,
)

_NAME = "shellcodeasm"

#: Written last, so its presence means every upstream was unpacked and the
#: staging tree swapped into place. The adapter version is part of it: when the
#: gates below change, a cache built under the old rules is stale, and silently
#: reusing it is how a fix fails to take effect on the machine that already ran
#: the build once.
_MARKER = ".fetched.json"
_CACHE_VERSION = 1

#: Directory names that are never corpus, wherever they appear. These four
#: projects vendor each other and everything else — pwntools carries a copy of
#: parts of capstone's tables, the radare2 book ships its own mdbook theme —
#: and a vendored copy is the same text under a different path. Duplicated text
#: in a small corpus is worse than absent text: the model memorises it.
_SKIP_DIRS = frozenset({
    ".git", ".github", "node_modules", "vendor", "_vendor", "vendored",
    "third_party", "thirdparty", "contrib", "build", "dist", "__pycache__",
    "site-packages", "theme", "book_cover", "images", "img",
})

#: Control bytes that :func:`~training.corpus.source.normalise` deletes. A file
#: containing one is refused here rather than cleaned, because deleting a byte
#: is the one normaliser behaviour that would make :func:`_prove_columns`
#: approximate instead of exact — and a ``.asm`` or ``.md`` file with a form
#: feed in it is not text this corpus wants either way. ``\r`` is absent from
#: the class on purpose: line endings are normalised in :func:`_admit`.
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

#: A run this long is a rendering artefact, and ``normalise`` collapses it to
#: eight spaces. Same reasoning as above: refused rather than tolerated, so the
#: column invariant has no exceptions to carry.
_ABSURD = re.compile(r"[ \t]{200,}")

#: Nothing here comes near this. It exists so that an upstream that starts
#: shipping a generated 4 MB table under a path this adapter keeps fails a file
#: at a time instead of putting one document the size of a source into the
#: corpus. The largest file actually admitted is the radare2 book's
#: ``analysis/code_analysis.md`` at 26 KB.
_MAX_BYTES = 200_000

#: The ceiling handed to :func:`~training.corpus.net.download`, enforced against
#: bytes as they arrive rather than checked afterwards with ``stat()``. The four
#: archives together are about 36 MB; the ceiling is per archive and is set
#: where "this upstream has grown a binary test corpus" becomes true.
_MAX_ARCHIVE_BYTES = 64 * 1024 * 1024

# --------------------------------------------------------------------------
# What each upstream contributes
# --------------------------------------------------------------------------

#: The generated half of shellcraft. ``pwnlib/data/syscalls/generate.py`` emits
#: one template per Linux syscall, and the 491 of them share about 3.2 KB of
#: identical Mako out of an average 3.5 KB file. Emitted whole they would be
#: 1.7 MB — over eighty percent of this source — teaching the model one code
#: generator. Emitted not at all, the corpus loses the only Linux syscall
#: *signature* table it has: musl gives numbers and this gives prototypes, and
#: the machine this corpus is built on is a Mac whose ``man 2`` pages are BSD's.
#: So the docstring is kept and the boilerplate is not — see
#: :func:`_syscall_signature_documents`.
_PWN_GENERATED = "pwnlib/shellcraft/templates/common/linux/syscalls/"
_PWN_TEMPLATES = "pwnlib/shellcraft/templates/"

#: musl assembly this source does not want. ``src/math`` and ``src/complex`` are
#: 97 of musl's 332 assembly files and they are floating point: x87 sequences on
#: i386 and x86-64, ``fcvtzs``/``frintx`` on aarch64. They are real assembly and
#: they are not this corpus's subject — a model reasoning about exploitation and
#: reverse engineering meets ``fyl2xp1`` approximately never — and they are also
#: the one part of musl whose MIT claim is not simply Rich Felker's: the
#: COPYRIGHT file assigns that tree to Sun, FreeBSD and Arm under separate
#: permissive terms. Dropping it costs nothing this source was written to teach
#: and leaves every remaining musl file covered by either the plain MIT grant or
#: one of the two string routines named in :data:`SPEC`.
_MUSL_DROP = ("src/math/", "src/complex/")

#: musl files that are about the machine rather than about libc. ``syscall_arch``
#: is the calling convention, ``crt_arch`` is what runs before ``main`` and how
#: the stack looks when it does, ``atomic_arch`` is the lock-prefixed and
#: load-exclusive idioms a disassembly is full of, ``pthread_arch`` is the
#: thread pointer register — ``fs`` on x86-64, ``tpidr_el0`` on aarch64 — which
#: is where the stack canary a reader keeps seeing at ``fs:0x28`` comes from,
#: and ``reloc`` is the relocation types that make GOT and PLT reasoning
#: concrete.
_MUSL_ARCH_FILES = frozenset({
    "syscall_arch.h", "crt_arch.h", "atomic_arch.h", "pthread_arch.h",
    "reloc.h",
})

#: The same, one level down under ``bits/``. ``syscall.h.in`` is the syscall
#: number table; ``user.h`` and ``signal.h`` carry the register-file layouts
#: (``user_regs_struct``, ``mcontext_t``) that name every register a debugger or
#: a core dump will show, in the order the kernel stores them.
_MUSL_BITS_FILES = frozenset({"syscall.h.in", "user.h", "signal.h"})

#: Book chapters that are not about binaries: how to install radare2 on eight
#: platforms, and who wrote it. Dropped so the source's topic stays honest —
#: build instructions are a fine register and they are not the one this adapter
#: was written to add.
_R2_DROP = ("src/install/", "src/credits/", "src/SUMMARY.md", "src/COVER.md")

#: CTF101 is a whole CTF primer; only two of its sections are this source's
#: subject. The cryptography, forensics and web-exploitation pages are good
#: short PROSE and belong to whichever brief covers that register, not to a file
#: about assembly. Taking them here would pad this source with material a reader
#: of the module name would not expect to find in it.
_CTF101_KEEP = ("docs/binary-exploitation/", "docs/reverse-engineering/")

#: Mako code blocks: ``<% ... %>`` but not ``<%docstring>``, ``<%page .../>``,
#: ``<%def>`` or a closing ``</%...>``. Only the bare form holds Python.
_MAKO_BLOCK = re.compile(r"<%(?![%a-zA-Z/])(.*?)%>", re.S)
_MAKO_DOCSTRING = re.compile(r"<%docstring>(.*?)</%docstring>", re.S)


@dataclass(frozen=True)
class _Upstream:
    """One project, its verified licence, and the part of it worth keeping."""

    name: str
    url: str
    #: Read from the project's own LICENSE/COPYRIGHT file, not from a badge.
    license: str
    archive: str
    #: True if this archive member is a file this upstream contributes.
    #: Takes the path with the archive's single root directory already removed.
    wanted: Callable[[Path], bool]
    #: Turns this upstream's cached tree into documents. Separate per upstream
    #: because two of them do not emit one document per file, and hiding that
    #: behind a flag would be less readable than four named functions.
    build: Callable[[Path], Iterator[Document]]
    #: Floor on admitted files. Below it the upstream has moved something and
    #: should say so at fetch time, naming itself, rather than turning up as a
    #: thin line in a build report three sources later.
    min_files: int
    #: Smallest file worth keeping, per upstream because the honest answer
    #: differs by an order of magnitude. A 54-byte shellcraft template is
    #: ``<%docstring>A trap instruction.</%docstring>`` over ``teq $zero,
    #: $zero``, which is the purest instruction-with-intent in the whole
    #: source; a 54-byte Markdown file is a stub someone forgot to write.
    min_bytes: int
    #: Enforced when set. Only a pinned release tarball can carry one.
    sha256: str = ""


def _want_pwntools(rel: Path) -> bool:
    """Shellcraft templates only — assembly, not the Python around it.

    ``pwnlib/`` as a whole is already in the corpus: it is one of the six
    projects :mod:`~training.corpus.sources.pythoncode` collects, under a
    ``.py``-only filter that never sees a ``.asm`` file. So the two adapters
    partition the same repository cleanly, and this one deliberately does not
    take ``pwnlib/rop/rop.py`` or ``pwnlib/asm.py`` however relevant they look.
    Cross-source duplication would be caught by ``build.py``'s global dedup, but
    a source that hands it duplicates is a source whose own report is wrong.
    """
    return rel.suffix == ".asm" and rel.as_posix().startswith(_PWN_TEMPLATES)


def _musl_arch(rel: Path) -> str | None:
    """The architecture an assembly file belongs to, or ``None``.

    musl's layout puts it at a fixed depth: ``src/<subsystem>/<arch>/<file>.s``
    and ``crt/<arch>/<file>.s``. Every one of the 332 assembly files in the 1.2
    series sits at one of those two shapes, which is what makes the grouping in
    :func:`_musl_documents` well defined rather than a guess.
    """
    parts = rel.parts
    if parts[0] == "src" and len(parts) == 4:
        return parts[2]
    if parts[0] == "crt" and len(parts) == 3:
        return parts[1]
    return None


def _want_musl(rel: Path) -> bool:
    """Per-architecture assembly, plus the headers that describe the machine.

    Not the C library. musl's ``src/stdio``, ``src/network`` and the rest are
    ordinary portable C and this corpus already has a great deal of that; what
    is unique here is the part that had to be written per architecture because
    the architecture is the subject.
    """
    posix = rel.as_posix()
    if posix.startswith(_MUSL_DROP):
        return False
    if rel.suffix in (".s", ".S"):
        return _musl_arch(rel) is not None
    parts = rel.parts
    if parts[0] != "arch" or len(parts) < 3:
        return False
    if len(parts) == 3:
        return rel.name in _MUSL_ARCH_FILES
    return len(parts) == 4 and parts[2] == "bits" and rel.name in _MUSL_BITS_FILES


def _want_ctf101(rel: Path) -> bool:
    posix = rel.as_posix()
    return rel.suffix == ".md" and posix.startswith(_CTF101_KEEP)


def _want_r2book(rel: Path) -> bool:
    posix = rel.as_posix()
    if rel.suffix != ".md" or not posix.startswith("src/"):
        return False
    return not posix.startswith(_R2_DROP)


# --------------------------------------------------------------------------
# Admission and the whitespace proof
# --------------------------------------------------------------------------


def _admit(raw: bytes, min_bytes: int) -> str | None:
    """Return the decoded text if it belongs in the cache, else ``None``.

    Gates in the order they are cheapest: size, strict UTF-8, control bytes,
    absurd space runs. Decoding is strict on purpose — ``errors="replace"``
    would admit a Latin-1 file as text containing replacement characters, which
    passes every other gate here and teaches the model mojibake.

    Line endings are normalised here rather than left to
    :func:`~training.corpus.source.normalise`, so that what lands in the cache
    is already ``\\n``-only and :func:`_prove_columns` has one fewer
    transformation to reason about.
    """
    if not min_bytes <= len(raw) <= _MAX_BYTES:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if _CTRL.search(text) or _ABSURD.search(text):
        return None
    return text


def _prove_columns(before: str, after: str, ident: str) -> None:
    """Assert that normalisation did not touch a single column.

    This is the contract in :func:`~training.corpus.source.normalise` turned
    into a test, on the register where breaking it would be both fatal and
    invisible. Assembly is column-structured by convention; a disassembly
    listing is column-structured by definition — address, bytes, mnemonic,
    operands, comment — and CTF101 draws stack frames as ASCII tables where the
    indentation *is* the diagram::

            0xffff0010: 0x400c03            // the pop rsi gadget
    RSP ->  0xffff0008: 0xdeadbeef          // value popped into rdi

    Collapse the runs of spaces in that and every token survives. The character
    count moves by a few percent. The picture is gone, and nothing in a build
    report would say so.

    The comparison is exact, not approximate, and that is worth stating because
    a heuristic here would be worse than nothing. ``normalise`` does five things:
    normalises line endings (already done in :func:`_admit`), deletes control
    bytes (refused in :func:`_admit`), collapses runs of 200+ spaces (refused in
    :func:`_admit`), strips trailing whitespace per line, and caps blank-line
    runs before stripping the whole string. The last two are what this function
    models — trailing whitespace removed from every line, blank lines ignored,
    the result stripped — so any surviving difference can only be a normaliser
    that has begun eating horizontal whitespace, and there is no reading of that
    which is not a bug.
    """
    expected = "\n".join(
        line.rstrip() for line in before.split("\n") if line.strip()
    ).strip()
    observed = "\n".join(line for line in after.split("\n") if line.strip())
    if expected == observed:
        return
    raise SourceError(
        f"{_NAME}: {ident} lost horizontal whitespace in normalise(). In a "
        "disassembly listing the columns are the meaning and in assembly the "
        "indentation is the convention, so a normaliser that collapses runs of "
        "spaces does not degrade this register, it deletes what the register "
        "was collected for — while barely moving the character count, which is "
        "why this is asserted rather than assumed. Fix normalise(); do not "
        "filter around this."
    )


def _mako_blocks(text: str) -> list[str]:
    """Every ``<% ... %>`` Python block in a shellcraft template, wrapped.

    Wrapped in a function because that is what Mako does with them: a block is
    compiled into the body of the render function, so ``return`` is legal inside
    one and illegal at module level. Dedented for the same reason — Mako does
    not care what column a block starts in.
    """
    out = []
    for body in _MAKO_BLOCK.findall(text):
        if not body.strip():
            continue
        out.append(
            "def _mako_block():\n"
            + textwrap.indent(textwrap.dedent(body).strip("\n"), "    ")
            + "\n"
        )
    return out


def _prove_python_survives(before: str, after: str, ident: str) -> None:
    """Any embedded Python that compiled before normalisation must compile after.

    ``compile`` rather than ``ast.parse``, and the difference is not academic:
    ``ast.parse("return 1")`` succeeds while ``compile`` raises, because only
    ``compile`` runs the pass that checks a statement is legal where it stands.
    A check built on ``ast`` would report success on blocks the interpreter
    refuses, which makes it an expensive way to prove nothing.

    Blocks that do not compile beforehand are skipped rather than rejected. Six
    of the 598 in shellcraft are in that state and all six are legitimate Mako:
    a ``continue`` inside a block the engine will nest in a ``%for`` loop, and
    one template that indents with tabs and spaces. They are still real
    templates and still real assembly; they simply cannot be checked this way,
    and inventing a reason to drop them would be the tail wagging the dog.
    """
    for source, target in zip(_mako_blocks(before), _mako_blocks(after)):
        try:
            compile(source, ident, "exec")
        except (SyntaxError, ValueError):
            continue
        try:
            compile(target, ident, "exec")
        except (SyntaxError, ValueError) as exc:
            raise SourceError(
                f"{_NAME}: {ident} embeds Python that compiled before "
                f"normalise() and not after ({exc}). Mako blocks are indented "
                "Python, so this is the same failure _prove_columns describes, "
                "caught by a compiler instead of by a comparison."
            ) from None


# --------------------------------------------------------------------------
# Document builders, one per upstream
# --------------------------------------------------------------------------


def _emit(text: str, ident: str, register: Register, side: Side,
          *, check_python: bool = False) -> Document:
    """Normalise, prove nothing was lost, and wrap in a Document."""
    cleaned = normalise(text)
    _prove_columns(text, cleaned, ident)
    if check_python:
        _prove_python_survives(text, cleaned, ident)
    return Document(text=cleaned, source=_NAME, register=register,
                    side=side, ident=ident)


def _walk(root: Path, suffixes: tuple[str, ...]) -> Iterator[tuple[Path, str]]:
    """Every cached file under ``root``, sorted, following no symlink.

    ``os.walk(followlinks=False)`` rather than ``rglob``, for the reason
    :mod:`~training.corpus.sources.ownrepos` records the hard way: a sibling
    adapter once walked a symlink into the shared corpus cache and pulled 180 MB
    of other sources back in under its own label. This tree is written by
    :func:`_fetch` and contains no links at all, which is exactly the situation
    in which an unexamined ``rglob`` survives review and then does not survive
    the day somebody points a symlink at the cache.
    """
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in _SKIP_DIRS and not Path(dirpath, d).is_symlink()
        )
        for filename in sorted(filenames):
            file = Path(dirpath, filename)
            if file.is_symlink() or file.suffix not in suffixes:
                continue
            try:
                yield file.relative_to(root), file.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue


def _syscall_signature_documents(root: Path) -> Iterator[Document]:
    """The Linux syscall table, as prototypes, from the generated templates.

    Each generated template's ``<%docstring>`` is a complete signature — name,
    C types, argument names, return type, and a pointer at the man page::

        execve(path, argv, envp) -> str

        Invokes the syscall execve.

        See 'man 2 execve' for more information.

        Arguments:
            path(char*): path
            argv(char**): argv
            envp(char**): envp
        Returns:
            int

    The 3.2 KB of identical Mako underneath it is discarded. Grouped forty to a
    document rather than emitted one apiece because a 300-character document is
    not a document — it is a row, and a corpus of rows teaches sequence length
    rather than content. Forty of them is a page of reference material at about
    13 KB, which is the size the rest of this source is.

    Alphabetical order and a stated range in the header, so the grouping is
    reproducible across fetches and legible in a build report.
    """
    directory = root / _PWN_GENERATED
    if not directory.is_dir():
        return
    signatures: list[tuple[str, str]] = []
    for rel, text in _walk(directory, (".asm",)):
        match = _MAKO_DOCSTRING.search(text)
        if match is None:
            continue
        body = match.group(1).strip("\n")
        if body.strip():
            signatures.append((rel.stem, body))

    group = 40
    for start in range(0, len(signatures), group):
        chunk = signatures[start:start + group]
        header = (
            f"Linux syscall signatures as pwntools shellcraft declares them, "
            f"{chunk[0][0]} to {chunk[-1][0]}"
        )
        text = header + "\n\n" + "\n\n".join(body for _, body in chunk)
        yield _emit(
            text,
            f"pwntools/syscall-signatures/{chunk[0][0]}-{chunk[-1][0]}",
            # SYSTEM, not ADVERSARY: a syscall prototype is an interface
            # definition. It is the same text whether the caller is a shell or
            # a stager, which is the definition of NEUTRAL.
            Register.SYSTEM, Side.NEUTRAL,
        )


def _pwntools_documents(root: Path) -> Iterator[Document]:
    """One document per hand-written shellcraft template, plus the signatures.

    ADVERSARY/RED and no hedging about it. A shellcraft template is a payload
    with an explanation attached; that is adversary behaviour described as
    behaviour, which is what the register is for. The corpus is short of exactly
    this and it is short of it because material like this is normally either
    unlicensed or operational.
    """
    yield from _syscall_signature_documents(root)
    for rel, text in _walk(root / _PWN_TEMPLATES, (".asm",)):
        if rel.as_posix().startswith("common/linux/syscalls/"):
            continue
        yield _emit(text, f"pwntools/{rel.as_posix()}",
                    Register.ADVERSARY, Side.RED, check_python=True)


def _musl_documents(root: Path) -> Iterator[Document]:
    """Headers one per file; assembly bundled per architecture.

    The bundling is the only synthesis in this adapter and it is there because
    musl's assembly files are tiny — 332 of them averaging 440 bytes, many under
    a dozen lines. Individually they are fragments: ``src/setjmp/aarch64/
    longjmp.s`` on its own says nothing that the file beside it does not. Read
    together, an architecture's whole assembly surface — the syscall trampoline,
    the thread-creation stub, the setjmp register save, the string routines —
    *is* the ABI, and the ABI is the thing worth learning. So there is one
    document per architecture, each file introduced by a comment naming its
    path.

    ``/* ... */`` because GNU ``as`` accepts C-style comments on every target,
    where ``#``, ``//``, ``;`` and ``@`` each mean a comment on some
    architectures and something else on others. The separator is a fact about
    the file it precedes, not editorial text, and it keeps the concatenation
    honest: a reader can see where one program ends and the next begins.
    """
    bundles: dict[str, list[str]] = {}
    for rel, text in _walk(root, (".s", ".S", ".h", ".in")):
        arch = _musl_arch(rel)
        if arch is not None:
            bundles.setdefault(arch, []).append(
                f"/* musl {rel.as_posix()} */\n{text.strip()}"
            )
            continue
        yield _emit(text, f"musl/{rel.as_posix()}",
                    Register.SYSTEM, Side.NEUTRAL)

    for arch in sorted(bundles):
        yield _emit("\n\n".join(bundles[arch]), f"musl/asm/{arch}",
                    Register.SYSTEM, Side.NEUTRAL)


def _ctf101_documents(root: Path) -> Iterator[Document]:
    """Exploitation and reverse-engineering mechanism. ADVERSARY/RED.

    RED rather than NEUTRAL, and the distinction is worth making because a
    defender reads these pages too. The test this corpus uses is not who reads
    a document but what it is written to enable, and these are written to take
    control of a process: the buffer-overflow page ends at a shell, the ROP page
    steps a gadget chain to a call the author chose. That the same knowledge
    makes a better defender is why the corpus wants it, not a reason to relabel
    it.
    """
    for rel, text in _walk(root, (".md",)):
        yield _emit(text, f"ctf101/{rel.as_posix()}",
                    Register.ADVERSARY, Side.RED)


def _r2book_documents(root: Path) -> Iterator[Document]:
    """The radare2 book, one document per chapter. SYSTEM/NEUTRAL.

    SYSTEM rather than SHELL, which was the other candidate and is not quite
    right. The book's surface is a console transcript — ``[0x00000000]> pdf``
    and its output — so the command lines are genuinely SHELL-shaped. But the
    characters are overwhelmingly in the *output*: addresses, opcode bytes,
    mnemonics, operands, cross-references and the analysis tables radare2
    prints. That is a machine description, which is what SYSTEM means here, and
    filing eight hundred kilobytes of disassembly under SHELL to help a number
    would make the balance report lie about the register the corpus is most
    starved of.

    NEUTRAL for the same sort of reason. Reading a binary is what a malware
    analyst, an exploit developer and a firmware auditor all do with the same
    commands; the book takes no side and neither does this label.
    """
    for rel, text in _walk(root, (".md",)):
        yield _emit(text, f"radare2book/{rel.as_posix()}",
                    Register.SYSTEM, Side.NEUTRAL)


_UPSTREAMS: tuple[_Upstream, ...] = (
    _Upstream(
        name="pwntools",
        url="https://github.com/Gallopsled/pwntools",
        license=(
            "MIT (LICENSE-pwntools.txt, Copyright (c) 2015 Gallopsled et al.). "
            "That file carves out pwnlib/constants/ and pwnlib/data/ as GPL or "
            "BSD-2-Clause; neither is collected here, and the repository's only "
            "nested LICENSE.txt files sit in exactly those two directories, "
            "which is how the carve-out was confirmed rather than assumed."
        ),
        archive="https://codeload.github.com/Gallopsled/pwntools/tar.gz/refs/heads/dev",
        wanted=_want_pwntools,
        build=_pwntools_documents,
        # 817 .asm templates at the time of writing, of which 491 are the
        # generated syscall wrappers. A drop below 600 means the template tree
        # has moved.
        min_files=600,
        min_bytes=50,
    ),
    _Upstream(
        name="musl",
        url="https://musl.libc.org/",
        license=(
            "MIT (COPYRIGHT, Copyright (c) 2005-2020 Rich Felker et al.). The "
            "file names permissive exceptions, all of which are compatible and "
            "none of which this adapter avoids: TRE regex BSD-2-Clause; the "
            "math library from Sun, FreeBSD and Arm; src/string/arm/memcpy.S "
            "BSD-2-Clause (The Android Open Source Project); src/string/"
            "aarch64/* Copyright (c) 1999-2019 Arm Limited. The COPYRIGHT file "
            "is copied into the cache under licenses/."
        ),
        # A pinned release, not a branch: musl publishes numbered tarballs from
        # its own host, and pinning one makes this fetch reproducible in a way
        # a moving branch cannot be. The digest below is enforced, which is the
        # reason to prefer a release in the first place.
        archive="https://musl.libc.org/releases/musl-1.2.6.tar.gz",
        wanted=_want_musl,
        build=_musl_documents,
        # ~332 assembly files plus ~150 arch headers across nineteen
        # architectures. Below 300 an architecture directory has moved.
        min_files=300,
        min_bytes=40,
        # Observed on the 1,082,499-byte tarball this adapter was written
        # against. Stated for what it is: musl signs releases with a PGP key and
        # publishes no checksum, so this pins the *bytes* — it makes a swapped
        # or truncated tarball a loud failure and a reproducible build possible
        # — and it does not authenticate them, because verifying the signature
        # would need a trust anchor this project does not ship. Say what a check
        # proves; a hash presented as a signature is worse than no hash.
        sha256="d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a",
    ),
    _Upstream(
        name="ctf101",
        url="https://github.com/osirislab/ctf101",
        license="MIT (LICENSE, Copyright (c) 2024 OSIRIS Lab)",
        archive="https://codeload.github.com/osirislab/ctf101/tar.gz/refs/heads/master",
        wanted=_want_ctf101,
        build=_ctf101_documents,
        # Two sections, 24 pages. Small, and the floor is small with it; the
        # point of the floor here is to catch the docs/ tree being renamed.
        min_files=18,
        min_bytes=300,
    ),
    _Upstream(
        name="radare2book",
        url="https://github.com/radareorg/radare2book",
        license=(
            "CC-BY-SA-4.0 (LICENSE: Creative Commons "
            "Attribution-ShareAlike 4.0 International). COPYLEFT, stated as "
            "such: the share-alike obligation attaches to the text and travels "
            "with it. Kept because there is no permissively licensed body of "
            "annotated disassembly listings to substitute, and because "
            "training.corpus.sources.owasp already establishes that CC-BY-SA "
            "text is acceptable here when it is reproduced whole and "
            "attributed. The radare2 engine itself is LGPL-3.0 and is NOT "
            "collected; the book is a separate repository under this separate "
            "licence."
        ),
        archive="https://codeload.github.com/radareorg/radare2book/tar.gz/refs/heads/master",
        wanted=_want_r2book,
        build=_r2book_documents,
        min_files=140,
        min_bytes=300,
    ),
)


# --------------------------------------------------------------------------
# Fetch
# --------------------------------------------------------------------------


def _sha256(path: Path) -> str:
    """Digest of a file, read a megabyte at a time.

    Chunked rather than ``hashlib.sha256(path.read_bytes())``: these archives
    run to tens of megabytes and there is no reason for any of it to be resident
    at once, least of all on a machine that may be training.
    """
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def _extract(upstream: _Upstream, archive: Path,
             staging: Path) -> tuple[int, int]:
    """Unpack one upstream's admitted files and its licence into staging.

    Members are copied out by hand rather than with ``TarFile.extractall``.
    These tarballs are trusted in practice, but an archive member is
    attacker-controlled data in principle — absolute paths, ``..`` segments,
    symlinks and hardlinks are all expressible in tar — and the cheap defence is
    never to hand an archive's own names to the filesystem unchecked. Only
    regular files are written, and every destination is proved to resolve inside
    ``staging`` first.

    Returns ``(seen, kept)``, which is the pair that tells you at a glance
    whether an upstream reorganised itself.
    """
    files_root = staging / "files" / upstream.name
    files_root.mkdir(parents=True, exist_ok=True)
    resolved_root = files_root.resolve()
    licence_dir = staging / "licenses"
    licence_dir.mkdir(parents=True, exist_ok=True)

    seen = kept = licences = 0
    try:
        with tarfile.open(archive, mode="r:gz") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                parts = Path(member.name).parts
                if len(parts) < 2:
                    continue
                # Drop the archive's single root directory — "musl-1.2.6/" for
                # the release tarball, "pwntools-dev/" for a codeload one.
                # Stripping it is what lets one set of predicates describe both.
                rel = Path(*parts[1:])
                if rel.is_absolute() or ".." in rel.parts:
                    continue

                # The licence text itself, copied so the claim in SPEC can be
                # checked on disk against what was actually downloaded.
                if (len(rel.parts) == 1
                        and rel.name.upper().startswith(
                            ("LICENSE", "COPYING", "COPYRIGHT"))
                        and member.size <= 128 * 1024):
                    handle = tar.extractfile(member)
                    if handle is not None:
                        with handle:
                            (licence_dir / f"{upstream.name}.{rel.name}"
                             ).write_bytes(handle.read())
                        licences += 1
                    continue

                if _SKIP_DIRS.intersection(rel.parts[:-1]):
                    continue
                if not upstream.wanted(rel):
                    continue
                seen += 1
                if member.size > _MAX_BYTES:
                    continue
                handle = tar.extractfile(member)
                if handle is None:
                    continue
                with handle:
                    text = _admit(handle.read(), upstream.min_bytes)
                if text is None:
                    continue

                target = files_root / rel
                if not target.resolve().is_relative_to(resolved_root):
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                # Re-encoded from the decoded text rather than copied as bytes,
                # so what lands in the cache is exactly what _admit proved to be
                # valid UTF-8 with no control bytes and LF line endings — the
                # three facts _prove_columns depends on.
                target.write_text(text, encoding="utf-8")
                kept += 1
    except (tarfile.TarError, OSError) as exc:
        raise SourceError(
            f"{_NAME}: could not unpack {upstream.name}: {exc}") from exc

    if licences == 0:
        raise SourceError(
            f"{_NAME}: the {upstream.name} archive carries no licence file at "
            "its root. Every source in this corpus declares a licence and this "
            "one keeps the upstream text on disk to back the declaration; an "
            "archive that has stopped shipping it needs a human to look, not a "
            "default."
        )
    if kept < upstream.min_files:
        raise SourceError(
            f"{_NAME}: {upstream.name} yielded only {kept} files from {seen} "
            f"candidates (expected at least {upstream.min_files}). The upstream "
            "layout has probably changed — fix the path predicate rather than "
            "training on a fraction of the project."
        )
    return seen, kept


def _fetch(cache_dir: Path) -> Path:
    """Download each upstream, filter it, and leave a curated tree in the cache.

    Idempotent and network-free on re-run: the marker is written only after
    every upstream has been extracted and the staging tree swapped into place,
    so an interrupted fetch re-downloads instead of leaving a half-populated
    ``files/`` that a later run would mistake for a finished corpus.

    The archives are deleted as soon as they are unpacked. Together they are
    about 36 MB of mostly-not-assembly and the curated result is about 2 MB;
    keeping them would be paying disk to avoid a download that only happens
    once.

    Accepts either the per-source directory ``build.py`` hands it
    (``<cache>/shellcodeasm``) or the cache root, so calling this by hand during
    development does not scatter ``files/`` across the shared cache.
    """
    root = cache_dir if cache_dir.name == _NAME else cache_dir / _NAME
    root.mkdir(parents=True, exist_ok=True)

    files_dir = root / "files"
    marker = root / _MARKER
    if files_dir.is_dir() and marker.is_file():
        try:
            recorded = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            recorded = {}
        if recorded.get("cache_version") == _CACHE_VERSION:
            return root

    staging = root / ".staging"
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True, exist_ok=True)

    manifest: list[dict[str, object]] = []
    try:
        for upstream in _UPSTREAMS:
            archive = root / f".{upstream.name}.tar.gz.part"
            try:
                # The ceiling goes to the transport, which enforces it against
                # bytes as they arrive and refuses an oversized Content-Length
                # before reading any of them.
                download(upstream.archive, archive, timeout=600,
                         max_bytes=_MAX_ARCHIVE_BYTES)
            except NetworkError as exc:
                raise SourceError(f"{_NAME}: {upstream.name}: {exc}") from None
            try:
                digest = _sha256(archive)
                if upstream.sha256 and digest != upstream.sha256:
                    raise SourceError(
                        f"{_NAME}: {upstream.name}: {upstream.archive} hashed "
                        f"to {digest}, but this adapter pins "
                        f"{upstream.sha256}. A numbered release tarball does "
                        "not change its bytes. Either the upstream republished "
                        "it or something between here and it did; refusing to "
                        "unpack either way."
                    )
                seen, kept = _extract(upstream, archive, staging)
            finally:
                archive.unlink(missing_ok=True)

            manifest.append({
                "upstream": upstream.name,
                "url": upstream.url,
                "archive_url": upstream.archive,
                "license": upstream.license,
                "archive_sha256": digest,
                # Spelled out rather than left implied. "observed" is what the
                # bytes hashed to; "pinned" is whether that was compared with
                # anything. The three codeload tarballs track a branch and have
                # nothing to compare against, and a marker that did not say so
                # would read as if they had been checked.
                "pinned_sha256": upstream.sha256,
                "sha256_enforced": bool(upstream.sha256),
                "candidates": seen,
                "kept": kept,
            })

        # Swap in only once every upstream succeeded.
        shutil.rmtree(files_dir, ignore_errors=True)
        (staging / "files").replace(files_dir)
        licence_src = staging / "licenses"
        if licence_src.is_dir():
            shutil.rmtree(root / "licenses", ignore_errors=True)
            licence_src.replace(root / "licenses")
        # Written last: its presence is the claim that everything above
        # finished.
        marker.write_text(
            json.dumps(
                {
                    "cache_version": _CACHE_VERSION,
                    "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                time.gmtime()),
                    "upstreams": manifest,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return root


def _documents(path: Path) -> Iterator[Document]:
    """Yield every document, deduplicated across all four upstreams.

    Deduplication is by :func:`~training.corpus.source.fingerprint`, which is
    whitespace-insensitive and case-folded. It earns its keep here: these
    projects quote each other constantly — the radare2 book and CTF101 both
    reproduce the same ``pop rdi ; ret`` idiom, and shellcraft's per-architecture
    ``nop`` templates are one line that several architectures spell identically.
    ``build.py`` also dedupes globally, but a source that hands it duplicates is
    a source whose own report is wrong.
    """
    root = path / "files" if (path / "files").is_dir() else path
    seen: set[str] = set()
    for upstream in _UPSTREAMS:
        directory = root / upstream.name
        if not directory.is_dir():
            continue
        for doc in upstream.build(directory):
            mark = fingerprint(doc.text)
            if mark in seen:
                continue
            seen.add(mark)
            yield doc


SPEC = SourceSpec(
    name=_NAME,
    license=(
        "Composite, per upstream, each read from the project's own licence file "
        "and copied into the cache under licenses/. pwntools: MIT "
        "(LICENSE-pwntools.txt, Gallopsled et al.), which carves out "
        "pwnlib/constants/ and pwnlib/data/ as GPL or BSD-2-Clause — neither is "
        "collected. musl: MIT (COPYRIGHT, Rich Felker et al.), whose named "
        "exceptions are all permissive, and only two of them fall inside what "
        "this adapter collects: src/string/arm/memcpy.S (BSD-2-Clause, The "
        "Android Open Source Project) and src/string/aarch64/* (Arm Limited). "
        "TRE (BSD-2-Clause) and the Sun/FreeBSD/Arm math code are not "
        "collected. CTF101: MIT "
        "(OSIRIS Lab). radare2book: CC-BY-SA-4.0 — COPYLEFT, attribution and "
        "share-alike, stated explicitly because it travels with the text. The "
        "radare2 engine (LGPL-3.0) is not collected; only its separately "
        "licensed book is."
    ),
    # SourceSpec takes one url and this source has four. The one that carries
    # the most of what the source exists for stands here; all four, with the
    # exact archive fetched, the sha256 of what arrived and whether that hash
    # was enforced, are written into the cache marker by _fetch, and each
    # upstream's url is on _UPSTREAMS above.
    url="https://github.com/Gallopsled/pwntools",
    # The majority register by characters, and the honest one. The ADVERSARY/RED
    # documents — shellcraft templates and the CTF101 exploitation pages — carry
    # their own labels and the balancer counts them there; see the module
    # docstring for why the whole source is not filed under ADVERSARY.
    register=Register.SYSTEM,
    side=Side.NEUTRAL,
    fetch=_fetch,
    documents=_documents,
    #: 655 documents and 1,737,059 characters when this adapter was written:
    #: 311 shellcraft templates and 13 syscall-signature pages (pwntools), 143
    #: arch headers and 18 per-architecture assembly bundles (musl), 22 CTF101
    #: pages and 170 radare2 book chapters, less 22 near-duplicates. The floor
    #: sits about 20% under that so ordinary upstream churn is quiet, while an
    #: entire upstream vanishing is not. Each upstream also carries its own
    #: floor in _Upstream.min_files, which fails at fetch time and names the
    #: culprit; this one is the backstop for several shrinking at once.
    expect_min_docs=520,
    notes=(
        "Assembly and the reading of it, from four permissively or explicitly "
        "copyleft-licensed upstreams: pwntools shellcraft templates (annotated "
        "shellcode for nine architectures, plus the Linux syscall prototype "
        "table recovered from its generated templates and grouped forty to a "
        "page), musl's per-architecture syscall stubs, calling conventions, "
        "syscall number tables and hand-written assembly (bundled one document "
        "per architecture because the files average 440 bytes; src/math and "
        "src/complex are excluded as floating-point arcana this corpus has no "
        "use for), CTF101's "
        "binary-exploitation and reverse-engineering pages (stack layout, "
        "GOT/PLT, ROP, canaries, RELRO, NX, ASLR), and the radare2 book's "
        "disassembly listings with commentary. Architecture facts are in; "
        "vulnerability-specific exploit code is out. Every document is proved "
        "to have lost no horizontal whitespace to normalise(), and every Mako "
        "block that compiled before normalisation must compile after."
    ),
)
