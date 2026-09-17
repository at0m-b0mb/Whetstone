"""This author's own security repositories — the PROSE register.

Roughly forty hand-written security tools, each with a long README arguing for
its own design: why a grading engine refuses to award an A+, why a detector
reports a ceiling instead of a verdict, what a radio can and cannot hear. That
argumentative register is genuinely rare in public corpora, which mostly contain
either terse reference material or marketing, and it is close to the register
Whetstone's own ``report.finding`` output needs to produce.

It is also the corpus that taught this project its most useful lesson. Fitted to
*only* this, the domain tokenizer beat gpt2 by 7% instead of the predicted
25-30%, because Python and Markdown are not the registers the model will meet at
runtime. So it stays — the prose is good and the target share for PROSE is 10% —
but it is now one source among several rather than the whole corpus, and
``build.py`` reports its share so it cannot quietly dominate again.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator

from ..source import Document, Register, Side, SourceSpec, normalise

#: Prose only. This source is tagged PROSE and must actually be prose.
#:
#: It originally kept ``.py``, ``.c``, ``.h``, ``.yaml`` and friends, which meant
#: thousands of files of embedded-firmware C and Python were filed under the
#: PROSE register. The register system exists so corpus composition is
#: measurable, and mislabelling source as prose breaks exactly that. The first
#: training run showed it: prompted with ``T1547.001`` the model emitted
#: ``#define RADIOLIB_CFERI 0x0900`` — Flipper Zero firmware constants, learned
#: from files claiming to be security writing.
#:
#: The argumentative READMEs are the reason this source is here at all, and they
#: are markdown. The C is not lost to anything that wanted it: no register in
#: this corpus is asking for embedded firmware source.
#: ``.txt`` is excluded too: it sweeps up CMakeLists.txt, requirements.txt and
#: other build files, which are configuration rather than writing. Code fenced
#: *inside* a README stays, and should — prose that illustrates itself with a
#: snippet is still prose.
_KEEP = {".md", ".rst"}

#: Virtualenv and toolchain directories. ``.piovenv`` is PlatformIO's, and it is
#: named here because it got through an earlier pass and put generated
#: ``Activate.ps1`` boilerplate into the corpus — vendored activation scripts are
#: identical across every project that has one, so they are pure duplicated
#: noise in a corpus this size.
_SKIP_PARTS = {".git", ".venv", "venv", ".piovenv", "env", ".env",
               "node_modules", "site-packages", "__pycache__", "vendor",
               "build", "dist", ".eggs", ".pytest_cache", "_site", "third_party"}

#: The corpus sample was flattened into single files whose names encode the
#: original path with "__" separators, so directory-based skipping has to look
#: at the flattened name too.
_SKIP_TOKENS = tuple(f"{part}__" for part in _SKIP_PARTS)


#: A source file above this is generated, vendored or data — not prose. The cap
#: exists because one 5 MB JSON blob outweighs four hundred READMEs and would
#: dominate the register it was filed under.
_MAX_FILE_BYTES = 256 * 1024


def _fetch(cache_dir: Path) -> Path:
    """No download: the repositories are already on this machine.

    Returns the pre-populated cache directory if it exists, otherwise collects
    from the sibling project tree. Idempotent either way.

    **Symlinks are never followed.** The repository contains a ``data`` symlink
    pointing at the external SSD where the corpus cache lives, and ``rglob("*")``
    follows symlinks: the first run of this function walked straight through it
    and copied 180 MB of NVD JSON, Sigma YAML and PowerShell markdown back in,
    all relabelled as PROSE. The corpus ate itself, and the only reason anyone
    noticed was the balance report showing prose at 82% against a 10% target.
    ``os.walk(followlinks=False)`` is used instead of ``rglob`` because it makes
    that guarantee explicit rather than version-dependent.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    if any(cache_dir.iterdir()):
        return cache_dir

    project_root = Path(__file__).resolve().parents[3].parent
    if not project_root.is_dir():
        return cache_dir

    copied = 0
    for dirpath, dirnames, filenames in os.walk(project_root, followlinks=False):
        # Prune in place so os.walk does not descend into them at all.
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in _SKIP_PARTS and not Path(dirpath, d).is_symlink()
        )
        for filename in sorted(filenames):
            if copied >= 4000:
                return cache_dir
            path = Path(dirpath, filename)
            if path.is_symlink() or path.suffix.lower() not in _KEEP:
                continue
            try:
                if path.stat().st_size > _MAX_FILE_BYTES:
                    continue
                flat = str(path.relative_to(project_root)).replace("/", "__")
                (cache_dir / flat).write_bytes(path.read_bytes())
                copied += 1
            except OSError:
                continue
    return cache_dir


def _documents(path: Path) -> Iterator[Document]:
    for file in sorted(path.iterdir()):
        if not file.is_file():
            continue
        name = file.name
        if file.suffix.lower() not in _KEEP or name.startswith(_SKIP_TOKENS):
            continue
        try:
            raw = file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        text = normalise(raw)
        if len(text) < 200:
            continue
        yield Document(text=text, source="ownrepos", register=Register.PROSE,
                       side=Side.NEUTRAL, ident=name)


SPEC = SourceSpec(
    name="ownrepos",
    license="MIT (all repositories are this author's own work, MIT licensed)",
    url="https://github.com/at0m-b0mb",
    register=Register.PROSE,
    side=Side.NEUTRAL,
    fetch=_fetch,
    documents=_documents,
    expect_min_docs=500,
    notes=("Hand-written security tooling and its design argumentation. Close in "
           "register to the report prose Whetstone must itself produce."),
)
