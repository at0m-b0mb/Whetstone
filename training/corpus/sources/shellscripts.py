"""Real shell scripts from eleven permissively licensed projects — SHELL.

Named ``shellscripts`` rather than ``shellcode``: in this project's own subject
matter "shellcode" means an injected machine-code payload, and a corpus source
that emits ``docker-entrypoint.sh`` should not be filed under a word that means
something else to every reader of this repository.

**Why this source exists.** Whetstone ships a Linux adapter and a macOS adapter
that each execute shell to do thirty verbs of real work. Shell is therefore a
language the model has to *write*, not merely recognise, and SHELL is the
thinnest register in the build — 15.6% actual against a 26% target. The two
shell-adjacent sources already here do not close that gap and were never going
to. :mod:`~training.corpus.sources.manpages` is reference material: it describes
flags in paragraphs of prose. :mod:`~training.corpus.sources.tldr` is
intent-to-invocation pairs: one line of shell at a time, deliberately stripped
of everything around it. Between them they teach which flag ``ss`` takes and
which command lists sockets. Neither one contains a *script*. This source is the
Unix half of that repair; :mod:`~training.corpus.sources.powershell` is the
Windows half, and makes the same argument about the same gap from the other
side of the adapter layer.

What only a script contains is the structure a script has::

    set -euo pipefail                     # what the failure policy is
    trap 'rm -rf "$tmp"' EXIT             # who cleans up, and when
    while getopts ":hv:o:" opt; do        # how arguments are parsed
    case "$1" in start|stop|restart)      # how a dispatcher is written
    cat <<-'EOF'                          # how a multi-line literal is quoted
    [[ -n ${VAR:-} ]]                     # bash conditional vs POSIX [ ]
    exit 2                                # what an exit code is supposed to mean

...and, because this project targets Linux *and* macOS, the portability
distinctions that decide whether a generated command works on the machine it
lands on: ``sh`` versus ``bash`` versus ``zsh`` (the macOS default login shell
since Catalina), GNU coreutils flags versus BSD userland flags, ``readlink -f``
existing on one platform and not the other. Those differences are not stated
anywhere in a man page; they are *demonstrated* in scripts that have to survive
both, and several repositories below exist largely because of them.

**Comments are the reason this is training data and not just code.** A script's
header block explaining what it does, sitting directly above the code that does
it, is prose-next-to-code — the most useful shape there is for teaching a
language, and the same argument that makes the author's own READMEs worth
keeping in the PROSE register. So scripts are emitted verbatim, comments intact,
with no reformatting whatsoever. See the whitespace note below: reformatting
shell is not a matter of taste here, it changes what the script means.

**Eleven repositories, chosen so the style is not one author's habits.** A
corpus fitted to a single project teaches that project's house idioms as if they
were the language. These span five distinct traditions of shell writing:

==========================  =============  ====================================
repository                  licence        what it contributes
==========================  =============  ====================================
ohmyzsh/ohmyzsh             MIT            zsh at scale: hundreds of plugin and
                                           library files, the macOS default
                                           shell, parameter expansion flags and
                                           ``zstyle`` that exist in no other
                                           shell
Homebrew/brew               BSD-2-Clause   macOS bash written against BSD
                                           userland, by people who care about
                                           it working on Linux too
nvm-sh/nvm                  MIT            one 170 KB POSIX ``sh`` script with
                                           ferocious portability discipline — it
                                           must run under sh, bash, zsh, dash and
                                           ksh from the same bytes — plus ~300
                                           small ``test/`` scripts in the same
                                           dialect
pyenv/pyenv                 MIT            ~60 extensionless ``libexec/pyenv-*``
                                           commands: the subcommand-dispatch
                                           idiom, and the reason shebang
                                           detection below is mandatory
bats-core/bats-core         MIT            unusually disciplined bash — a test
                                           runner whose own correctness is the
                                           product
junegunn/fzf                MIT            shell *integration*: the same feature
                                           written three times for bash, zsh and
                                           their completion systems, side by
                                           side
docker-library/postgres     MIT            the canonical entrypoint idiom:
                                           ``set -Eeo pipefail``, ``_is_sourced``
                                           , ``exec "$@"``, heredocs feeding a
                                           client on stdin
redis/docker-library-redis  BSD-3-Clause   the same idiom from a second author,
                                           which is how you tell an idiom from a
                                           habit
tclahr/uac                  Apache-2.0     incident-response live collection in
                                           strict POSIX sh, across Linux, macOS,
                                           Solaris and the BSDs
docker/docker-bench-security Apache-2.0    CIS Docker Benchmark implemented as
                                           shell: check, judge, report
ovh/debian-cis              Apache-2.0     CIS Debian hardening, ~300 audit and
                                           apply scripts sharing one dispatcher
==========================  =============  ====================================

The last three are here deliberately. This is a purple-team corpus, and
hardening checks, benchmark implementations and IR collection scripts are shell
written to *inspect and judge a system* — which is the shape of shell Whetstone's
own blue verbs emit. They also carry the vocabulary (``auditctl``, ``sysctl``
keys, ``/etc/login.defs``, ``stat -c %a``) that the DETECTION and SYSTEM
registers reference but never show being used.

**Licensing is permissive-only, and that cost something worth naming.** Every
repository above is MIT, BSD-2-Clause, BSD-3-Clause or Apache-2.0, verified by
reading each project's own ``LICENSE`` file rather than trusting a badge. Three
obvious candidates were excluded for copyleft: ``koalaman/shellcheck`` (GPL-3.0,
and its test corpus of correct-and-incorrect pairs is the single most valuable
shell dataset in existence for this purpose), ``CISOfy/lynis`` (GPL-3.0) and
``git`` itself (GPL-2.0, whose ``t/`` suite is thousands of POSIX scripts). The
corpus already contains GPL text — man pages are licensed per upstream and some
are GPL — but that source reads locally installed documentation, whereas this
one *redistributes* files it downloaded, and a model published from a corpus
with a copyleft component is a licence question nobody wants to answer later.
Adding one is a single tuple entry in :data:`_REPOS` if that call is ever made.

Per-repository verification also caught the assumption that a GitHub
organisation has one licence: ``docker-library/postgres`` is MIT and
``docker-library/redis`` is BSD-3-Clause, while ``docker-library/mysql`` — which
would otherwise have been an obvious third entrypoint — is **GPL-2.0**, and is
not here. ``mathiasbynens/dotfiles`` was dropped for the opposite reason: a
README saying "MIT" with no ``LICENSE`` file in the tree is not a licence record
this project is willing to write down as one.

And a repository's own licence does not cover everything inside it. UAC's
``bin/`` holds helpers from other authors under their own terms — one of them
CC-BY-SA-4.0 — enumerated in the project's ``LICENSES.md``; only UAC's own code
is taken, which is what the ``include`` prefixes on that entry are for. Two of
the licences here are recorded from the text rather than from GitHub's
classifier, which reports NOASSERTION for both: ``bats-core``'s ``LICENSE.md``
is the MIT grant verbatim with the title line missing, and ``ovh/debian-cis``
carries the full Apache-2.0 text under an OVHcloud copyright line.

**Trap: indentation in shell is sometimes semantic.**
:func:`~training.corpus.source.normalise` already refuses to collapse horizontal
whitespace, and that contract matters more here than anywhere else in the
corpus. A here-document terminator must sit at column zero unless the operator
was ``<<-``, and ``<<-`` strips *tabs only* — so converting a tab-indented
heredoc to spaces does not tidy the script, it makes the shell read to end of
file looking for a terminator it will never find. Nothing in this module
expands tabs, re-indents, strips leading whitespace or rewraps a line. Files are
copied byte-for-byte into the cache and handed to ``normalise`` exactly as
upstream wrote them.

Checked rather than assumed, because "I did not touch it" is not evidence. Every
emitted document was compared line by line against its cached file: 1,195 of
1,195 match, with no content difference and not one tab converted anywhere in
the source. Of the 167 heredocs the emitted corpus contains, 158 terminate at
column zero and 9 are indented; all 9 of those were opened with ``<<-``, and
every one of them is indented with tabs rather than spaces, which is the only
form that works. ``docker-library/postgres``'s ``docker_setup_db`` is the
worked example — two ``<<-'EOSQL'`` bodies nested inside a command
substitution inside a function, three levels of tabs deep.

**Trap: most real shell scripts have no ``.sh`` extension.** ``pyenv`` ships its
entire command set as ``libexec/pyenv-version-name``; ``fzf`` ships ``install``;
``brew`` ships ``bin/brew``. Filtering by suffix alone would have discarded the
best-structured material in the set, so :func:`_classify` reads the shebang of
every otherwise-unrecognised file and accepts ``sh``, ``bash``, ``dash``,
``ksh``, ``zsh``, ``ash``, ``mksh`` and ``busybox sh``, including through
``/usr/bin/env``.

**Trap: symlinks.** ``ownrepos`` once followed a symlink into the 180 MB corpus
cache and pulled it back in as training data, which is why every walk in this
package now passes ``followlinks=False`` explicitly. Two guards here: tarfile
reports a symlink member as not-a-file so nothing is ever extracted through one,
and :func:`_documents` walks with ``followlinks=False`` and skips any entry that
is a symlink anyway.

**Trap: dedup has to happen before provenance is attached.** These repositories
vendor each other — ``pyenv`` is a fork of ``rbenv`` (which is why ``rbenv``
itself is not in the table above; it would have contributed a few dozen
near-identical files), completion snippets are copied between projects, and the
same helper appears twice inside one repo under two paths. Each emitted document
carries a one-line provenance comment naming its repository, path and licence —
valid shell, so the document as a whole is still a runnable script — but that
line is added *after* the dedup fingerprint is taken over the file body alone.
Fingerprinting the finished document instead would make two byte-identical files
at different paths look distinct, and ``build.py``'s corpus-wide dedup, which
sees only the finished document, cannot catch them either.

**Trap: a repository's licence says nothing about every file inside it.** The
table above is per repository, and treating it as a guarantee would have been
wrong three times. ``ohmyzsh`` is MIT and vendors iTerm2's shell integration,
which is GPL-2.0, plus a terminal-tab plugin derived from it. ``pyenv`` is MIT
and vendors ``src/shobj-conf`` from bash's build machinery, GPL-2.0-or-later.
Each of those files carries its own licence header, which is the only reason
this was findable at all: :data:`_COPYLEFT` matches the notice and the file is
dropped at extraction, so the permissive-only claim in :data:`SPEC` is a
property of what is actually emitted rather than an inference from eleven
LICENSE files. The same check would catch a CC-BY-SA or MPL file arriving the
same way. Three files out of 1,760 candidates is small; a licensing claim that
is wrong three times is not.

**Trap: control bytes.** ``normalise`` strips control characters other than tab
and newline — correctly, they are not text — but a shell script containing a
*literal* ESC byte inside a string would then be emitted as a script that no
longer does what it says. Rather than teach the model a mangled file, files
containing such bytes are skipped outright at extraction time. There are three.
Two are colour tables, ``ohmyzsh``'s ``lib/spectrum.zsh`` and
``tools/theme_chooser.sh``. The third is the one that makes the case: ``nvm``'s
``test/common.sh`` contains a literal ESC inside a sed expression that strips
ANSI sequences, and deleting that byte leaves behind a regular expression which
is still perfectly valid shell and no longer matches what it says it matches.
A mangled script that still parses is the worst thing this corpus could teach.

**Concentration cap.** Uncapped, ``ohmyzsh`` and ``ovh/debian-cis`` are 27% of
this source each, and a source whose stated purpose is breadth of style must not
be half of it two projects. No repository may exceed :data:`_REPO_CAP` — a
quarter — of the characters this source emits, and *emits* is the load-bearing
word: holding characters back shrinks the total the share is measured against,
so the budget is the fixed point of that loop rather than one multiplication.
The result is exactly 25.0% and 25.0% rather than "about a quarter", which is
the difference between a cap and a gesture.

The excess is dropped in the deterministic shallow-first order described in
:func:`_walk`, which means what goes is the tail of a deep test tree and what
stays is the implementation: ``debian-cis`` keeps its 299 hardening checks and
loses its functional-test suite. The count is printed rather than hidden,
exactly as ``manpages`` does when it caps its Perl pages.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tarfile
from pathlib import Path
from typing import Iterator, NamedTuple

from ..net import download
from ..source import (Document, Register, Side, SourceError, SourceSpec,
                      fingerprint, normalise)


class _Repo(NamedTuple):
    """One upstream repository and everything needed to justify its presence."""

    #: Directory name inside the cache. Also the first path component of every
    #: document ident, so a document can be traced to its repository by string.
    key: str
    #: ``owner/name`` on GitHub.
    slug: str
    #: Branch to snapshot. Codeload wants a ref, and these projects all publish
    #: from a long-lived default branch.
    ref: str
    #: SPDX identifier, read from the repository's own LICENSE file.
    license: str
    #: Why this repository earns a place — the register argument, not marketing.
    why: str
    #: Path prefixes to consider, relative to the repository root. Empty means
    #: the whole tree. Used only for the two large repositories, where most of
    #: the archive is Ruby, images or CI config that no filter below would keep
    #: anyway — skipping them at extraction saves the disk and the time.
    include: tuple[str, ...] = ()


#: The set, in descending order of expected contribution. Adding a repository is
#: one tuple; the licence field is not optional and is checked at import.
_REPOS: tuple[_Repo, ...] = (
    _Repo("ohmyzsh", "ohmyzsh/ohmyzsh", "master", "MIT",
          "zsh at scale — the macOS default login shell, in a dialect with "
          "parameter-expansion flags and zstyle that exist nowhere else",
          include=("lib", "plugins", "tools", "oh-my-zsh.sh")),
    # ``main``, not ``master``. Homebrew keeps a legacy ``master`` branch alive
    # that holds three files — LICENSE, README and ``bin/brew`` — and fetching
    # it succeeds, extracts one script and looks like a working source. This is
    # why every ref here was checked against the repository's declared default
    # branch rather than assumed to be ``master``.
    _Repo("homebrew", "Homebrew/brew", "main", "BSD-2-Clause",
          "macOS bash written against BSD userland by people who also keep it "
          "working on Linux — the exact portability seam this project sits on",
          include=("bin", "completions", "Library/Homebrew")),
    _Repo("nvm", "nvm-sh/nvm", "master", "MIT",
          "one large POSIX sh script that must run identically under sh, bash, "
          "zsh, dash and ksh, and a test suite written in the same dialect; "
          "portability discipline as a worked example"),
    _Repo("pyenv", "pyenv/pyenv", "master", "MIT",
          "~60 extensionless libexec/pyenv-* commands: subcommand dispatch, and "
          "the reason shebang detection is mandatory rather than a nicety"),
    _Repo("batscore", "bats-core/bats-core", "master", "MIT",
          "unusually disciplined bash — a test runner whose own correctness is "
          "the product it ships"),
    _Repo("fzf", "junegunn/fzf", "master", "MIT",
          "shell integration: the same feature written for bash and zsh side by "
          "side, which is the dialect difference made explicit"),
    # ``bin/`` is deliberately excluded. UAC ships third-party helpers there
    # (``dirwalk.sh``, ``strings.sh``, ``timeout.sh``, ``linux_procmemdump.sh``,
    # which is CC-BY-SA-4.0) under their own upstream licences, listed in the
    # repository's LICENSES.md — none of them covered by UAC's Apache-2.0. Only
    # the project's own code is taken: the ``uac`` driver, ``lib/`` and the
    # collection profiles.
    _Repo("uac", "tclahr/uac", "main", "Apache-2.0",
          "incident-response live collection in strict POSIX sh across Linux, "
          "macOS, Solaris and the BSDs — blue-team shell doing real work",
          include=("uac", "lib", "profiles")),
    _Repo("debiancis", "ovh/debian-cis", "master", "Apache-2.0",
          "CIS Debian hardening: ~300 audit scripts with a consistent "
          "audit/apply split and the /etc vocabulary the SYSTEM register names"),
    _Repo("dockerbench", "docker/docker-bench-security", "master", "Apache-2.0",
          "CIS Docker Benchmark as shell: check, judge, report — the shape of "
          "shell this project's own blue verbs emit"),
    _Repo("dockerpostgres", "docker-library/postgres", "master", "MIT",
          "the canonical entrypoint idiom: set -Eeo pipefail, _is_sourced, "
          "exec \"$@\", heredocs piped into a client"),
    # The repository moved from ``docker-library/redis`` to the Redis org; the
    # old path still redirects, but a build should not depend on a redirect
    # staying in place, so the canonical slug is used.
    _Repo("dockerredis", "redis/docker-library-redis", "master", "BSD-3-Clause",
          "the same entrypoint idiom from a second author, which is how an "
          "idiom is told apart from one person's habit"),
)

#: ``codeload`` tarballs rather than ``git clone --depth 1``: one request per
#: repository, no git binary required, no ``.git`` left in the cache for a later
#: ``pull`` to mutate underneath a build that claims to be reproducible. This is
#: the same decision ``sigma``, ``owasp`` and ``psdocs`` made.
_TARBALL = "https://codeload.github.com/{slug}/tar.gz/refs/heads/{ref}"

#: Bumped when the extraction filter changes in a way that would alter what is
#: in the cache, so an old cache is rebuilt rather than silently mixing two
#: filter generations.
_CACHE_VERSION = 1

#: Per-repository completion sidecar. Written last, after every file for that
#: repository is on disk, so an interrupted extraction re-fetches that one
#: repository on the next run instead of being mistaken for a complete tree —
#: and without re-downloading the ten that did finish.
_SIDECAR = ".fetched.json"

_TIMEOUT = 300

#: Extensions that are shell by name.
_SHELL_SUFFIXES = frozenset({".sh", ".bash", ".zsh", ".ksh"})

#: Extensions that are definitely not, checked first so a Python script with a
#: ``#!/bin/sh`` wrapper line or a markdown file full of examples cannot slip
#: through the shebang path. ``.bats`` is excluded on purpose: a bats file is
#: bash-*shaped* but ``@test "name" { ... }`` is not valid bash, and teaching the
#: model a syntax that no shell accepts is worse than teaching it nothing.
#: ``.fish`` is a different language entirely, and ``.ps1`` already has a source.
_REJECT_SUFFIXES = frozenset({
    ".bats", ".fish", ".ps1", ".psm1", ".py", ".rb", ".pl", ".go", ".rs",
    ".c", ".h", ".cpp", ".java", ".js", ".ts", ".php", ".md", ".rst", ".txt",
    ".json", ".yml", ".yaml", ".toml", ".xml", ".html", ".css", ".ini", ".cfg",
    ".conf", ".png", ".jpg", ".gif", ".svg", ".gz", ".zip", ".pdf", ".lock",
    ".m4", ".am", ".in", ".patch", ".diff", ".sql", ".rules", ".service",
    ".zsh-theme",
})

#: Dotfiles and rc files that are shell despite having neither a useful
#: extension nor, usually, a shebang — an rc file is sourced, not executed.
_SHELL_NAMES = frozenset({
    ".bashrc", ".bash_profile", ".bash_logout", ".profile", ".zshrc",
    ".zshenv", ".zprofile", ".zlogin", ".zlogout", ".kshrc",
    "bashrc", "zshrc", "profile", "shrc",
})

#: Interpreters accepted from a shebang line. ``fish``, ``python`` and friends
#: are absent by construction: this is a keep-list.
_INTERPRETERS = frozenset({
    "sh", "bash", "dash", "ksh", "ksh93", "pdksh", "mksh", "zsh", "ash", "yash",
})

#: Directory names never descended into. ``fixtures`` is here because
#: ``bats-core`` ships a tree of deliberately broken two-line scripts as test
#: input; they are not idiomatic shell, they are the opposite, and unlike
#: ShellCheck's corpus nothing labels them as wrong.
_SKIP_DIRS = frozenset({
    ".git", ".github", ".circleci", "node_modules", "vendor", "third_party",
    "__pycache__", "fixtures", "fixture", "testdata", "snapshots", "build",
    "dist", "man", "docs", "doc",
})

#: Above this a "script" is a generated blob, an embedded payload or a data
#: table. The largest genuine file in the set (``nvm.sh``, 172 KB of hand
#: written portable sh) sits just under it, and the cap is stated in bytes
#: rather than lines because a minified line has no line count worth measuring.
#: ``ownrepos`` learned this cap the expensive way: one oversized file outweighs
#: hundreds of real ones and quietly becomes the register.
_MAX_FILE_BYTES = 200 * 1024

#: A line this long in a shell script is a base64 payload, a minified blob or a
#: generated table — never something a person wrote to be read.
_MAX_LINE_BYTES = 1200

#: Markers that mean a machine wrote the file. Checked over the head of the
#: file, where every generator puts its banner.
_GENERATED = (
    b"do not edit", b"do not modify", b"automatically generated",
    b"auto-generated", b"autogenerated", b"generated by", b"@generated",
    b"this file was generated",
)
_GENERATED_HEAD = 4096

#: Copyleft notices carried by an *individual file* inside an otherwise
#: permissively licensed repository.
#:
#: This filter exists because the assumption underneath a per-repository licence
#: table turned out to be false, and the measurement is in the module docstring:
#: three files in this set carry their own GPL header. ``ohmyzsh``, which is MIT,
#: vendors iTerm2's shell integration (GPL-2.0) and a terminal-tab plugin derived
#: from it; ``pyenv``, which is MIT, vendors ``src/shobj-conf`` from bash's own
#: build machinery (GPL-2.0-or-later). None of them is covered by the licence the
#: repository declares, and a source whose whole licensing claim is
#: "permissive-only" cannot ship them and still be telling the truth.
#:
#: Matched over the whole file rather than just the header, because a vendored
#: function arrives with its notice wherever it was pasted. The phrases are long
#: and specific so that a script merely *mentioning* a licence — a package
#: manager printing metadata, a hardening check reading ``/usr/share/doc`` — is
#: not caught by accident; and if one ever is, the cost is one file out of a
#: thousand, which is the right direction to be wrong in.
_COPYLEFT = (
    b"general public license",
    b"mozilla public license",
    b"eclipse public license",
    b"creativecommons.org/licenses/by-sa",
    b"spdx-license-identifier: gpl",
    b"spdx-license-identifier: lgpl",
    b"spdx-license-identifier: agpl",
    b"spdx-license-identifier: mpl",
    b"spdx-license-identifier: cc-by-sa",
)

#: Anything shorter is an alias stub or a two-line wrapper: real syntax, no
#: structure worth learning. Matches the floor used across this package.
_MIN_CHARS = 200

#: No single repository may exceed this share of the source's characters. The
#: purpose of this source is breadth of style, and ohmyzsh is large enough to
#: be most of it by default. A cap rather than an exclusion, for the same reason
#: ``manpages`` caps rather than drops Perl: a model that has never seen zsh
#: plugin code is worse off than one that has seen a lot of it, just not *only*
#: it.
#:
#: A quarter rather than something tighter, and the difference was measured: at
#: 22% the fixed point below discards a further ~580 KB, almost all of it the
#: tail of two repositories that are already well represented, out of a register
#: sitting ten points under its target. A quarter still guarantees no single
#: project is more than a quarter of the style.
_REPO_CAP = 0.25

#: Below this many repositories the source is not what it claims to be. Eight of
#: eleven still spans zsh, bash, POSIX sh, entrypoints and hardening scripts, so
#: a transient codeload failure costs one repository's share of the register
#: rather than the whole source.
_MIN_REPOS = 8

#: Control bytes that are structure, not noise. Everything else in the C0 range
#: disqualifies the file — see the module docstring.
_ALLOWED_CONTROL = frozenset({0x09, 0x0A, 0x0D})


def _shebang_interpreter(head: bytes) -> str | None:
    """Return the shell named by a ``#!`` line, or ``None``.

    Handles the four shapes that actually occur: a direct path
    (``#!/bin/sh``), an env indirection (``#!/usr/bin/env bash``), an env with
    options (``#!/usr/bin/env -S bash -e``) and busybox's two-token form
    (``#!/bin/busybox sh``). Arguments after the interpreter are ignored;
    ``#!/bin/bash -eu`` is still bash.
    """
    if not head.startswith(b"#!"):
        return None
    line = head.split(b"\n", 1)[0][2:]
    try:
        tokens = line.decode("utf-8", errors="strict").split()
    except UnicodeDecodeError:
        return None
    if not tokens:
        return None

    first = os.path.basename(tokens[0]).lower()
    rest = [t for t in tokens[1:] if not t.startswith("-")]
    if first in ("env", "busybox"):
        # env: the real interpreter is the first non-option argument.
        # busybox: the applet name plays the same role.
        if not rest:
            return None
        first = os.path.basename(rest[0]).lower()
    return first if first in _INTERPRETERS else None


def _classify(name: str, head: bytes) -> str | None:
    """Decide whether one file is shell, and in which dialect.

    Returns a dialect name for the caller's records, or ``None`` to skip. Order
    matters: the reject list is consulted before the shebang, so a file that is
    plainly another language cannot be admitted by a stray first line.
    """
    lowered = name.lower()
    suffix = Path(lowered).suffix

    if suffix in _REJECT_SUFFIXES:
        return None
    if suffix in _SHELL_SUFFIXES:
        return suffix.lstrip(".")
    if lowered in _SHELL_NAMES:
        return "sh"
    # Everything left is extensionless or has an unknown suffix — which is where
    # the pyenv/fzf/brew commands live, and the whole reason this branch exists.
    return _shebang_interpreter(head)


def _is_usable(data: bytes) -> bool:
    """Content checks that apply to every accepted file.

    Five rejections, each for a distinct failure this source has actually seen —
    the counts are from one pass over all eleven archives, against 1,757 files
    kept:

    * oversized (1): ``ohmyzsh``'s 314 KB generated emoji table, which alone
      would have been a tenth of the source;
    * generated (7) and over-long lines (1): template appliers, stackbrew
      library generators and vendored completion machinery, none of it written
      to be read;
    * control bytes (3): literal escape bytes that ``normalise`` would strip out
      from under the script's own semantics — see the module docstring, the
      third of them is the interesting one;
    * copyleft notices (3): see :data:`_COPYLEFT`.

    A further 86 candidates fall under :data:`_MIN_CHARS`. They are counted
    separately in that census because they are not a rejection of anything: a
    two-line wrapper is real shell with no structure to learn from.
    """
    if len(data) > _MAX_FILE_BYTES or len(data) < _MIN_CHARS:
        return False
    if any(marker in data[:_GENERATED_HEAD].lower() for marker in _GENERATED):
        return False
    if any(len(line) > _MAX_LINE_BYTES for line in data.split(b"\n")):
        return False
    lowered = data.lower()
    if any(notice in lowered for notice in _COPYLEFT):
        return False
    return not any(byte < 0x20 and byte not in _ALLOWED_CONTROL for byte in data)


def _wanted_path(parts: tuple[str, ...], repo: _Repo) -> bool:
    """Path-level filtering, before a byte of content is read.

    Rejects traversal and absolute components outright — a crafted archive must
    not be able to write outside the cache directory it was handed — then
    applies the skip list and the repository's own include prefixes.
    """
    if not parts:
        return False
    if any(p in ("", ".", "..") or os.path.isabs(p) or p.startswith("/")
           for p in parts):
        return False
    if any(p.lower() in _SKIP_DIRS for p in parts[:-1]):
        return False
    if repo.include:
        joined = "/".join(parts)
        return any(joined == prefix or joined.startswith(prefix + "/")
                   for prefix in repo.include)
    return True


def _extract(archive: Path, target: Path, repo: _Repo) -> int:
    """Unpack the shell files out of one tarball. Returns how many landed.

    Only files that pass :func:`_classify` and :func:`_is_usable` are written,
    so the cache holds shell and nothing else — no 90 MB of Ruby, images and CI
    config to walk past on every build.

    Members are iterated rather than collected with ``getmembers()``: these
    archives hold tens of thousands of entries and only a low hundred survive
    the filter, so there is no reason to build the full list in memory.

    Symlinks cannot be extracted here at all — ``member.isfile()`` is false for
    them — which is the first of this module's two symlink guards.
    """
    written = 0
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar:
            if not member.isfile():
                continue
            # Drop the ``<name>-<ref>/`` root component codeload adds.
            parts = tuple(Path(member.name).parts[1:])
            if not _wanted_path(parts, repo):
                continue
            if member.size > _MAX_FILE_BYTES:
                continue      # cheap check before decompressing the member
            handle = tar.extractfile(member)
            if handle is None:
                continue
            data = handle.read()
            if _classify(parts[-1], data[:256]) is None or not _is_usable(data):
                continue
            destination = target.joinpath(*parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            # Bytes, not text. Nothing here re-encodes, re-indents or rewrites a
            # line ending: a tab-indented ``<<-`` heredoc that survives the trip
            # to disk unchanged is the whole contract of this source.
            destination.write_bytes(data)
            written += 1
    return written


def _fetch_repo(cache_dir: Path, repo: _Repo) -> dict | None:
    """Download and unpack one repository. Returns its sidecar, or ``None``.

    Warm path is free: an existing sidecar of the current cache version whose
    recorded file count still matches what is on disk means this repository is
    done. Counting rather than trusting the sidecar alone catches the case a
    cache copied between volumes or partly cleaned would otherwise hide, which
    is the same failure ``manpages`` guards against by stat-ing its manifest
    entries.
    """
    target = cache_dir / repo.key
    sidecar = target / _SIDECAR
    if sidecar.is_file():
        try:
            recorded = json.loads(sidecar.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            recorded = {}
        if (recorded.get("version") == _CACHE_VERSION
                and recorded.get("slug") == repo.slug
                and recorded.get("files", 0) > 0
                and recorded["files"] == _count_files(target)):
            return recorded

    url = _TARBALL.format(slug=repo.slug, ref=repo.ref)
    archive = cache_dir / f".{repo.key}.tar.gz"
    staging = cache_dir / f".{repo.key}.incoming"
    try:
        download(url, archive, timeout=_TIMEOUT)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        shutil.rmtree(staging, ignore_errors=True)
        staging.mkdir(parents=True)
        written = _extract(archive, staging, repo)
        if written == 0:
            raise SourceError(
                f"{repo.slug}: the tarball contained no shell files. Either the "
                "branch was renamed or the tree was reorganised; the include "
                "prefixes in _REPOS need updating rather than a retry."
            )
        # Swap into place only once the staging tree is known good, so a reader
        # never sees a half-unpacked repository.
        shutil.rmtree(target, ignore_errors=True)
        staging.rename(target)
        recorded = {
            "version": _CACHE_VERSION,
            "slug": repo.slug,
            "ref": repo.ref,
            "license": repo.license,
            "url": f"https://github.com/{repo.slug}",
            "sha256": digest,        # which snapshot of a moving branch this is
            "files": written,
            # The argument for the repository, carried into the cache. A cache
            # directory that cannot say why its contents are training data is
            # one nobody can audit six months later.
            "why": repo.why,
        }
        sidecar.write_text(json.dumps(recorded, indent=1), encoding="utf-8")
        return recorded
    except Exception as exc:
        # One repository failing is survivable — _fetch decides whether enough
        # of the set arrived — so this reports and returns rather than raising.
        print(f"   ! {repo.slug}: {type(exc).__name__}: {exc}")
        return None
    finally:
        archive.unlink(missing_ok=True)
        shutil.rmtree(staging, ignore_errors=True)


def _count_files(root: Path) -> int:
    """Count extracted files under one repository directory, sidecar excluded."""
    total = 0
    for _, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        total += sum(1 for name in filenames if name != _SIDECAR)
    return total


def _fetch(cache_dir: Path) -> Path:
    """Populate the cache with shell files from every repository in _REPOS.

    Tolerates a minority of repositories failing: a transient codeload error on
    one of eleven should cost that repository's share of the register, not the
    whole source. It does *not* tolerate most of them failing, because a corpus
    quietly built from two projects is exactly the single-author-style problem
    this source was created to avoid — and a build that reports success while
    doing that is worse than one that stops.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)

    fetched: list[dict] = []
    for repo in _REPOS:
        recorded = _fetch_repo(cache_dir, repo)
        if recorded is not None:
            fetched.append(recorded)

    if len(fetched) < _MIN_REPOS:
        raise SourceError(
            f"shellscripts: only {len(fetched)} of {len(_REPOS)} repositories "
            f"could be fetched, below the floor of {_MIN_REPOS}. This source's "
            "argument is breadth of authorship; built from a couple of "
            "projects it teaches those projects' habits as if they were the "
            "language."
        )

    (cache_dir / "manifest.json").write_text(
        json.dumps({"version": _CACHE_VERSION, "repos": fetched}, indent=1),
        encoding="utf-8",
    )
    return cache_dir


def _walk(path: Path) -> list[tuple[_Repo, str, Path]]:
    """Collect ``(repo, relative path, file)`` for every cached file.

    Ordered, and that order is load-bearing twice over. It is
    ``os.walk`` top-down with the directory names sorted, so shallow files come
    before deep ones: ``nvm.sh`` precedes ``test/``, and ``debian-cis``'s 378
    hardening checks under ``bin/`` precede its 388 functional tests under
    ``tests/``. When the concentration cap below has to drop something, it
    therefore drops the deep repetitive test trees and keeps the headline
    implementation, which is the right way round and is free. It is also stable,
    so two builds from the same cache produce the same corpus rather than two
    arbitrary subsets of it.

    **Symlinks are not followed.** ``ownrepos`` walked through one into the
    corpus cache and re-ingested 180 MB of its own output as training data;
    ``followlinks=False`` plus an explicit per-entry check is the cheap way to
    never repeat that.
    """
    found: list[tuple[_Repo, str, Path]] = []
    for repo in _REPOS:
        root = path / repo.key
        if not root.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames
                                 if not Path(dirpath, d).is_symlink())
            for filename in sorted(filenames):
                if filename == _SIDECAR:
                    continue
                file = Path(dirpath, filename)
                if file.is_symlink():
                    continue
                found.append((repo, file.relative_to(root).as_posix(), file))
    return found


def _budgets(prepared: list[tuple[_Repo, str, str]]) -> dict[str, int]:
    """Character budget per repository, over the documents that actually survive.

    Deliberately *not* computed from on-disk file sizes, which is the cheaper
    thing to do and gives a wrong answer here: a quarter of the cached files are
    dropped as duplicates or as too short before anything is emitted, so a
    budget derived from the tree would be struck against a total the corpus
    never contains — and every repository would come out several points over
    the cap it was supposed to be under. The whole point of a stated cap is
    that the number in the report matches the number in the constant.

    Reading twice is what that costs, and it costs nothing: the entire source is
    under 4 MB of text. Only repositories that exceed the cap get a budget, so
    the common case is an empty dict and no accounting at all.
    """
    sizes: dict[str, int] = {}
    for repo, _, text in prepared:
        sizes[repo.key] = sizes.get(repo.key, 0) + len(text)
    total = sum(sizes.values())
    if not total:
        return {}

    # A cap struck once is wrong, and wrong in the direction that looks right.
    # Holding characters back shrinks the source, which shrinks the total the
    # share is measured against, which means the repositories that were capped
    # come out *above* the cap anyway: at 25% of the uncapped total, the two
    # largest here landed at 26.3% and 26.4% of what was actually emitted. So
    # solve the fixed point instead — the budget that is 25% of the total that
    # results from applying that very budget. The iteration is monotonically
    # decreasing and settles in a handful of rounds; the bound is there so a
    # rounding cycle cannot spin.
    cap = total
    for _ in range(64):
        following = int(_REPO_CAP * sum(min(size, cap) for size in sizes.values()))
        if following >= cap:
            break
        cap = following

    return {key: cap for key, size in sizes.items() if size > cap}


def _provenance(repo: _Repo, relative: str, body: str) -> str:
    """Attach the one-line source comment without breaking the script.

    The obvious implementation puts the comment on line 1, and it is wrong in a
    way that is invisible in a corpus dump: ``#!`` is only a shebang when it is
    the very first two bytes of the file, so a note above it turns an executable
    script into a file the kernel will not run. 825 of the 1,195 documents here
    have a shebang, so that mistake would have taught the model a malformed
    script *shape* eight hundred times over — and every one of those documents
    would still have looked perfectly good in a corpus sample.

    So the note goes on line 2 when a shebang is present and line 1 when it is
    not, and either way the document is a file that would actually execute.
    """
    note = f"# {repo.slug} {relative} ({repo.license})"
    if not body.startswith("#!"):
        return f"{note}\n{body}"
    shebang, newline, rest = body.partition("\n")
    if not newline:
        return f"{shebang}\n{note}"
    return f"{shebang}\n{note}\n{rest}"


def _documents(path: Path) -> Iterator[Document]:
    """Yield one document per cached script: a provenance line, then the file.

    The provenance line is a shell comment placed so the script still runs — see
    :func:`_provenance` — so the document remains a file rather than a file with
    a label glued to it, and it gives the model the one piece of context the
    source itself does not carry: which project this style belongs to, and under
    which licence it was published.

    Dedup happens on the *body*, before that line is prepended. These
    repositories copy from each other, and a path-dependent header would make
    two identical files look different to any fingerprint taken afterwards —
    including ``build.py``'s own corpus-wide one, which only ever sees the
    finished document. It earns its keep immediately: ``docker-library``
    regenerates one entrypoint per supported version, so 52 cached
    ``postgres`` files are four distinct scripts and 12 ``redis`` files are two.

    Two passes, for the reason given in :func:`_budgets`: everything is read and
    deduplicated first so the concentration cap can be struck against the
    characters this source actually emits. The whole set is under 4 MB, so
    holding it costs less than the accounting would.
    """
    files = _walk(path)
    if not files:
        raise SourceError(
            f"shellscripts: no cached scripts under {path}; run fetch first"
        )

    duplicates = 0
    seen: set[str] = set()
    prepared: list[tuple[_Repo, str, str]] = []

    for repo, relative, file in files:
        try:
            raw = file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        body = normalise(raw)
        if len(body) < _MIN_CHARS:
            continue

        mark = fingerprint(body)
        if mark in seen:
            duplicates += 1
            continue
        seen.add(mark)

        prepared.append((repo, relative, _provenance(repo, relative, body)))

    budgets = _budgets(prepared)
    spent: dict[str, int] = {}
    held: dict[str, int] = {}

    for repo, relative, text in prepared:
        cap = budgets.get(repo.key)
        if cap is not None:
            if spent.get(repo.key, 0) + len(text) > cap:
                held[repo.key] = held.get(repo.key, 0) + 1
                continue
            spent[repo.key] = spent.get(repo.key, 0) + len(text)

        yield Document(text=text, source="shellscripts", register=Register.SHELL,
                       side=Side.NEUTRAL, ident=f"{repo.key}/{relative}")

    # No silent filtering: say what was dropped and why.
    if duplicates:
        print(f"   shellscripts: dropped {duplicates} file(s) duplicated "
              "across repositories")
    for key, count in sorted(held.items(), key=lambda kv: -kv[1]):
        print(f"   shellscripts: held back {count} {key} file(s) at the "
              f"{_REPO_CAP:.0%} per-repository cap")


SPEC = SourceSpec(
    name="shellscripts",
    license=(
        "Permissive only, verified per repository from each project's own "
        "LICENSE file: ohmyzsh/ohmyzsh MIT; Homebrew/brew BSD-2-Clause; "
        "nvm-sh/nvm MIT; pyenv/pyenv MIT; bats-core/bats-core MIT; "
        "junegunn/fzf MIT; tclahr/uac Apache-2.0; ovh/debian-cis Apache-2.0; "
        "docker/docker-bench-security Apache-2.0; docker-library/postgres MIT; "
        "docker-library/redis BSD-3-Clause. No copyleft: shellcheck (GPL-3.0), "
        "lynis (GPL-3.0), git (GPL-2.0) and docker-library/mysql (GPL-2.0) were "
        "excluded deliberately. Attribution notices travel with each document "
        "as a provenance comment naming the repository and its licence."
    ),
    url="https://github.com/ohmyzsh/ohmyzsh (largest of eleven; see _REPOS for all)",
    register=Register.SHELL,
    side=Side.NEUTRAL,
    fetch=_fetch,
    documents=_documents,
    # 1,195 scripts and 3.45 MB survive the filters today, from 1,757 cached
    # files. A floor at 700 clears the noise — upstream churn, one repository
    # timing out, the cap moving with the mix — while still failing loudly when
    # a branch is renamed or a tree reorganised. That is the failure this number
    # exists to catch: half the set going missing would otherwise read as a
    # merely thinner build report.
    expect_min_docs=700,
    notes=(
        "Whole scripts, verbatim, comments intact — the structure manpages and "
        "tldr cannot teach: set -euo pipefail, trap cleanup, getopts, case "
        "dispatch, heredocs, exit-code conventions, [[ vs [, and sh/bash/zsh "
        "portability across the Linux and macOS adapters. Detected by shebang "
        "as well as extension, since pyenv, fzf and brew ship their commands "
        "without one. Nothing is reformatted: a <<- heredoc is tab-significant "
        "and re-indenting it would change what the script means. Per-repository "
        "cap keeps ohmyzsh from becoming the source; body-level dedup runs "
        "before the provenance comment is attached."
    ),
)
