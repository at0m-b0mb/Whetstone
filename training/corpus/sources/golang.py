"""Go, as source. The language modern security tooling is actually written in.
SYSTEM/NEUTRAL.

The corpus reads well and writes nothing. It holds 13,536 Nuclei *templates* and
not one line of the engine that executes them; it holds 32 MB of GHSA advisories
and nothing that consumes one; it holds Python security tooling, which is the
right choice for the lingua franca of *scripting* and the wrong one for the
question "what is this scanner doing". Over the last decade the answer moved to
Go, and it moved almost completely: nuclei, trivy, gitleaks, subfinder, httpx,
naabu, kube-bench, syft, grype, Velociraptor, gVisor, Kubernetes itself and the
whole cloud-native control plane are Go programs. A model asked to read, explain
or extend current tooling has, until this source, never met the language any of
it is written in.

**Why Go specifically teaches well.** Two properties, both about surface form
rather than topic:

*The doc comment is a language convention, not a courtesy.* Go's rule is a
sentence above every exported identifier, beginning with the identifier's own
name — ``// ParseCertificate parses a single certificate from the given ASN.1
DER data.`` That is the exact shape the measurement in
:mod:`~training.corpus.source` says the tokenizer pays for: an identifier
sitting beside its human name in running prose. Python has the same shape in
docstrings but does not enforce it; Go's tooling nags until it is there, so the
density is uniform across five projects with nothing else in common. Of 3,596
candidate files, 2,409 reach the prose gate and 1,870 clear it — and the gate is
not a low bar, being the same 200 characters at 5% of the file that
:mod:`~training.corpus.sources.pythoncode` applies, with the licence header
excluded from the count in both.

*Tabs are the indentation and gofmt is not optional.* Every file here has been
through one formatter with no configuration, so the corpus gets a single
consistent layout across five unrelated projects — tab indentation, aligned
struct-field comments, one brace style. That is a cleaner signal for a BPE than
five house styles, and it makes the whitespace contract below checkable to the
byte.

**The five projects, and what each is here to teach.**

* ``nuclei`` — the template engine. This is the one the corpus most conspicuously
  lacked: :mod:`~training.corpus.sources.nuclei` supplies thousands of YAML
  checks, and this supplies ``pkg/protocols/http``, ``pkg/operators/matchers``,
  ``pkg/operators/extractors`` and the DSL that give those files meaning. The
  pairing is the point — a template and its interpreter in one corpus.
* ``trivy`` — a scanner with real architecture. Image and filesystem walkers,
  fourteen ecosystem package parsers (dpkg status files, Gemfile.lock, pom.xml,
  Cargo.lock, go.sum), vulnerability matching against advisory databases, SBOM
  emission in CycloneDX and SPDX, and IaC misconfiguration scanning. It is the
  consumer side of the advisory data the corpus already holds.
* ``gitleaks`` — what a live credential looks like in text. Its
  ``cmd/generate/config/rules/`` tree is one file per secret format, each pairing
  a regex with the human name of the thing it matches and a real example.
* ``gvisor`` — the Linux syscall surface, reimplemented in userspace with
  comments. ``pkg/abi/linux`` is the ABI as annotated constant tables,
  ``pkg/sentry/syscalls`` is the semantics of individual syscalls written out in
  prose and code, ``pkg/seccomp`` is a BPF filter compiler, ``pkg/tcpip`` is a
  complete TCP/IP stack, and ``runsc`` is an OCI runtime. Nothing else available
  under a permissive licence explains the kernel boundary at this resolution.
* ``golang/go``'s ``crypto``, ``net``, ``os`` and ``syscall`` trees — the
  best-documented security-relevant code that exists, by some distance.
  ``crypto/tls`` is a handshake state machine with the RFC citations inline;
  ``crypto/x509`` is certificate and chain-building logic with the
  counter-examples named; ``net/http`` is the protocol most of the rest of this
  corpus attacks and defends.

**Register: SYSTEM. Side: NEUTRAL.** Both follow
:mod:`~training.corpus.sources.pythoncode`, for the same reason and after the
same argument. What comes out of here is package source — type declarations,
interface definitions, constant tables, protocol structures and doc comments —
and not commands typed at a prompt, so SHELL would be wrong however badly the
build report wants shell. The side is the harder call, because the corpus is
short of red and declaring some of this RED would help the number. It is
NEUTRAL because the number should not be helped that way: knowing how ``execve``
is dispatched, how a TLS ``ClientHello`` is parsed or how a dpkg status file is
laid out serves both sides identically, and that is most of the text here. The
one project where the artefact is genuinely offensive — nuclei's engine, which
exists to fire unsolicited requests at machines that did not ask for them — is
labelled RED per document, matching the call
:mod:`~training.corpus.sources.nuclei` already made about its templates, and
trivy is labelled BLUE per document as vulnerability management. Those
per-document labels ride in the build manifest; the source-level NEUTRAL keeps
this text out of the offence ratio entirely, which is the honest answer for a
source that is mostly neither.

**Licensing was read from each upstream's own LICENSE file, and one candidate
was refused on it.** Velociraptor is AGPL-3.0 — verified against
``Velocidex/velociraptor``'s ``LICENSE``, which opens "GNU AFFERO GENERAL PUBLIC
LICENSE / Version 3" — and it is not here. It is the best DFIR codebase in Go
and losing it hurts, but network copyleft in the training set of a model this
project intends to publish is a question nobody wants to answer after the fact,
and :mod:`~training.corpus.sources.pythoncode` already refused scapy, sqlmap,
paramiko and volatility3 on the same principle. Consistency is the whole value
of that principle.

Nested licences were looked for rather than assumed, because a permissive root
LICENSE does not cover a subtree somebody dropped in under other terms. Seven
were found. Six are unremarkable: nuclei's ``pkg/js/libs/LICENSE.md`` is
Apache-2.0 inside an MIT repository; gvisor carries Go Authors BSD-3-Clause under
``pkg/safecopy``, ``pkg/sentry/time`` and ``pkg/sync``, none of which is in the
keep set; and Go ships ``PATENTS`` beside its LICENSE.

The seventh is the one that would have been got wrong by anybody who read the
headline and stopped. ``src/crypto/internal/boring/LICENSE`` sits *inside* a kept
prefix, and it reproduces the OpenSSL licence, the original SSLeay licence, an
ISC licence and an Intel licence — including SSLeay's advertising clause, which
is exactly the kind of term that should stop a training corpus. Its own first
sentence settles it: "The Go source code and supporting files in this directory
are covered by the usual Go license", and everything after that applies only
"when building with GOEXPERIMENT=boringcrypto", to a prebuilt
``goboringcrypto_linux_amd64.syso`` object file. No ``.syso`` is a ``.go`` file,
so nothing under those terms is collected, and the ten BoringCrypto ``.go`` files
that are collected are BSD-3-Clause like the rest of the distribution. Reading
two sentences of a licence is the difference between shipping that tree and
deleting ten good files about FIPS-mode crypto for no reason.

Every LICENSE, COPYING, NOTICE and PATENTS file outside a skipped directory is
copied into ``<cache>/golang/licenses/``, named for the project and the path it
covers, so each of these claims can be checked against what was actually
downloaded rather than against this paragraph.

**The trap: a copyleft grep flags exactly the wrong files.** Scanning 5,207
candidate ``.go`` files for ``GPL``, ``AGPL``, ``LGPL``, ``MPL`` and friends
returns 22 hits, and every single one is a false positive of the same kind —
``pkg/licensing/expression/category.go`` in trivy and
``tools/licensecheck/licensecheck.go`` in gvisor are *licence classifiers*, so
their subject matter is the string ``GPL-3.0-only`` and their own licence is
Apache-2.0. The check that matters is the LICENSE file beside the code, not a
grep through it; a grep run without reading the hits would have deleted trivy's
SPDX expression parser, which is one of the more interesting files in the set.

The same trap fired a second time on a different question, which is why it is
worth naming as a pattern rather than an anecdote. The generated-file gate
started out as this package's usual list of loose phrases — ``auto-generated``,
``do not edit``, ``automatically generated`` — layered on top of Go's own
convention. Measured, the loose layer dropped eight files that the convention
did not and caught nothing the convention missed, and all eight were files
*about* code generation: ``crypto/internal/fips140/mlkem/mlkem768.go``, whose
doc comment says the ML-KEM-1024 implementation "is auto-generated from this
file", gvisor's ``pkg/tcpip/header/ipv6.go`` explaining SLAAC "auto-generated
addresses", and ``syscall/dll_windows.go`` on "autogenerated functions". The
loose layer is gone; see :data:`_GENERATED_RE`. A security corpus is made of
text whose subject is the words you are searching for, and a substring search
over it is a search for files that discuss the topic well.

**The other trap: there is no ``compile()`` for Go.** The house rule elsewhere
in this package is to syntax-check with :func:`compile` rather than
:func:`ast.parse`, because ``compile`` catches what the parser lets through.
Nothing in the Python standard library parses Go at all, and making the build
depend on a ``gofmt`` binary would mean the corpus a machine produces depends on
whether a Go toolchain happens to be installed on it — different training data
from the same commit, which is worse than a weaker check. So the stand-in is
:func:`_scan`, a small Go lexer written here, followed by a delimiter-balance
test over the code it emits with comments, interpreted strings, raw backtick
strings and rune literals removed.

It was measured rather than assumed, and a Go toolchain was used to do the
measuring even though the adapter refuses to depend on one at build time. Over
all 1,870 files this admits, ``gofmt -e`` reports zero parse errors, and the
lexer rejects nothing ``gofmt`` accepts — the two agree on every file. Run again
over the same 1,870 files *after*
:func:`~training.corpus.source.normalise` has been over them, ``gofmt`` still
reports zero: the real Go parser confirms that what this source writes into the
corpus is Go.

The limits are worth stating rather than rounding up. Truncating 300 admitted
files to 60% of their length, the balance test catches 234; the other 66 were cut
where the braces happened to balance. It will not notice a misplaced ``else`` at
all.

What it is emphatically *not* is a check on whitespace. Collapsing every run of
spaces and tabs in those same 300 files leaves all 300 balanced and lexing
cleanly — the exact corruption this corpus most fears is invisible to a
syntactic check, which is why :func:`_whitespace_survived` exists beside it
rather than instead of it. The two gates overlap nowhere.

**The whitespace contract is proved per file, not trusted.**
:func:`~training.corpus.source.normalise` is documented to preserve horizontal
whitespace, and Go is a language where that matters twice over: tabs carry the
indentation, and gofmt's column alignment carries the association between a
struct field and the comment explaining it. :func:`_whitespace_survived` checks
the contract exactly rather than approximately, which is possible because
:func:`_admit` first refuses any file containing a carriage return, a control
byte other than tab or newline, or a run of 200 or more spaces — the three
inputs on which ``normalise`` is licensed to rewrite a line. After that gate the
only edits it may make are stripping trailing whitespace, capping blank-line
runs and stripping the ends, so every non-blank line of the output must equal
the corresponding ``rstrip()``-ed line of the input, byte for byte. Anything
else raises :class:`SourceError` naming the file.

That precondition cost exactly two files out of 3,596 candidates, and both were
a gain: gitleaks' ``huggingface.go`` and ``jwt.go`` embed raw FASTQ quality
strings and padded JWTs as false-positive fixtures for their own regexes, which
is several kilobytes of binary noise inside a raw string literal and is not text
anyone should train on.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import shutil
import tarfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from ..net import NetworkError, download, fetch as http_get
from ..source import (
    Document, Register, Side, SourceError, SourceSpec, fingerprint, normalise,
)

_NAME = "golang"

#: Written last, so its presence means every project finished extracting. The
#: version is part of the marker for the reason
#: :mod:`~training.corpus.sources.pythoncode` records: when the gates below
#: change, a cache built under the old rules is stale, and the short-circuit on
#: a marker's existence is exactly how a fix fails to reach the machine that
#: already ran the build once.
_MARKER = ".fetched.json"
_CACHE_VERSION = 1


@dataclass(frozen=True)
class _Project:
    """One upstream, its verified licence, and the part of it worth keeping."""

    name: str
    url: str
    #: Read from the project's own LICENSE file, not from a badge or a README.
    license: str
    #: A codeload tarball URL, or ``godl:`` — see :func:`_archive_url` for why
    #: the Go distribution is resolved differently.
    archive: str
    #: Path prefixes to keep, relative to the archive root once its single
    #: top-level directory is stripped. Everything else is never decoded.
    keep: tuple[str, ...]
    #: Prefixes carved back out of ``keep``.
    drop: tuple[str, ...] = ()
    #: Per-document side. The source declares NEUTRAL overall; these are the
    #: cases where one project is honestly not neutral, and they are recorded
    #: per document so the build manifest carries the distinction.
    side: Side = Side.NEUTRAL
    #: Floor on files surviving every gate. A project that suddenly yields far
    #: fewer has moved a package directory and should say so at fetch time,
    #: naming itself, rather than as a thin total three sources later.
    min_files: int = 20


#: Five projects rather than one, for the reason
#: :mod:`~training.corpus.sources.pythoncode` gives: a corpus drawn from a single
#: repository teaches one team's habits as if they were the language. gofmt
#: removes the layout differences between these five and leaves everything else —
#: nuclei is interface-heavy and reflective, trivy is generics-era and
#: aggressively factored, gitleaks is small and declarative, gvisor writes
#: systems Go with unsafe pointers and build tags, and the standard library is
#: conservative pre-generics Go with the most careful comments in the ecosystem.
_PROJECTS: tuple[_Project, ...] = (
    _Project(
        name="nuclei",
        url="https://github.com/projectdiscovery/nuclei",
        license=("MIT (LICENSE.md: 'MIT License / Copyright (c) 2025 "
                 "ProjectDiscovery, Inc.'). pkg/js/libs/ carries its own "
                 "LICENSE.md and is Apache-2.0; both are copied into the cache."),
        archive="https://codeload.github.com/projectdiscovery/nuclei/tar.gz/refs/heads/dev",
        # lib/ is the embeddable SDK and cmd/ the binaries; both show the engine
        # being driven rather than merely defined, which is the half of a
        # codebase that a library-only keep-prefix loses.
        keep=("pkg/", "internal/", "lib/", "cmd/"),
        side=Side.RED,
        min_files=250,
    ),
    _Project(
        name="trivy",
        url="https://github.com/aquasecurity/trivy",
        license="Apache-2.0 (LICENSE, with NOTICE: 'Copyright 2019-2020 Aqua "
                "Security Software Ltd.')",
        archive="https://codeload.github.com/aquasecurity/trivy/tar.gz/refs/heads/main",
        keep=("pkg/", "internal/", "rpc/"),
        # integration/ and magefiles/ are the build and end-to-end harness, and
        # the tree under pkg/*/testdata/ is ~40 MB of fixture container images
        # and lockfiles. The global skips catch testdata; these are named so the
        # exclusion reads as a decision.
        drop=("pkg/fanal/test/",),
        side=Side.BLUE,
        min_files=220,
    ),
    _Project(
        name="gitleaks",
        url="https://github.com/gitleaks/gitleaks",
        license="MIT (LICENSE: 'MIT License / Copyright (c) 2019 Zachary Rice')",
        archive="https://codeload.github.com/gitleaks/gitleaks/tar.gz/refs/heads/master",
        keep=("cmd/", "detect/", "report/", "sources/", "config/", "regexp/",
              "logging/"),
        # The smallest project here by an order of magnitude, and kept for one
        # tree: cmd/generate/config/rules/ is ~170 files that each name a
        # credential format, give the regex that matches it and a real sample.
        min_files=30,
    ),
    _Project(
        name="gvisor",
        url="https://github.com/google/gvisor",
        license=("Apache-2.0 (LICENSE). pkg/safecopy/, pkg/sentry/time/ and "
                 "pkg/sync/ each carry a Go Authors BSD-3-Clause LICENSE; none "
                 "of the three is in the keep set, so nothing under them is "
                 "collected."),
        archive="https://codeload.github.com/google/gvisor/tar.gz/refs/heads/master",
        # Named subtree by subtree rather than "pkg/", because the whole of pkg/
        # is 1,757 Go files and would have been half this source on its own —
        # one repository's habits taught as the language, which is the failure
        # the five-project split exists to avoid. What is kept is the part that
        # explains the kernel boundary: the ABI, the syscall layer, the memory
        # and VFS managers, the seccomp compiler, the network stack, and the
        # runtime that assembles them.
        keep=("pkg/abi/linux/", "pkg/seccomp/", "pkg/sentry/arch/",
              "pkg/sentry/control/", "pkg/sentry/kernel/", "pkg/sentry/mm/",
              "pkg/sentry/socket/", "pkg/sentry/strace/",
              "pkg/sentry/syscalls/", "pkg/sentry/vfs/", "pkg/tcpip/",
              "runsc/"),
        # pkg/sentry/fsimpl/ is deliberately absent and it is the largest thing
        # given up here: 138 files and 1.65 MB of per-filesystem driver
        # plumbing (9p, overlay, proc, sys, tmpfs). The VFS *interface* those
        # drivers implement is kept in pkg/sentry/vfs/, which is the part that
        # teaches the boundary; the drivers mostly teach gvisor.
        side=Side.NEUTRAL,
        min_files=450,
    ),
    _Project(
        name="go",
        url="https://go.dev/dl/",
        license=("BSD-3-Clause (LICENSE: 'Copyright 2009 The Go Authors', the "
                 "three-clause form with the Google LLC non-endorsement "
                 "clause), plus PATENTS. src/crypto/internal/boring/LICENSE "
                 "reproduces the OpenSSL, SSLeay, ISC and Intel licences, but "
                 "only for the prebuilt .syso object file it names; its first "
                 "sentence puts the Go source in that directory under the usual "
                 "Go licence, and only .go files are collected."),
        archive="godl:",
        # crypto/ and net/ are the brief's ask and the obvious value. os/ and
        # syscall/ are here because they are where Go states the operating
        # system contract — file modes, process credentials, signal numbers,
        # errno tables — and that register is thin in this corpus outside
        # manpages, which describe the same surface in an entirely different
        # form.
        keep=("src/crypto/", "src/net/", "src/os/", "src/syscall/"),
        min_files=320,
    ),
)

#: Directory names that are never corpus, wherever they appear. ``testdata`` is
#: first because it is a Go *convention* — the toolchain ignores it — so every
#: project here uses it, and between them it holds container images, lockfiles,
#: PCAPs and certificate fixtures measured in tens of megabytes. ``vendor`` is
#: the one that protects the corpus rather than its size: Go modules vendor
#: their dependencies into the tree, and a vendored copy is the same text under
#: a different licence at a different path.
_SKIP_DIRS = frozenset({
    "testdata", "test_data", "tests", "test", "vendor", "_vendor", "vendored",
    "third_party", "thirdparty", "node_modules", ".git", "build", "dist",
    "mocks", "mock", "fixtures", "integration",
})

#: Generated Go, by naming convention. ``_test.go`` is first and is most of the
#: volume: Go keeps tests beside the code, so roughly a third of every tree here
#: is table-driven assertions and fixture literals. ``zz_``, ``.pb.go``,
#: ``_string.go`` and ``_autogen.go`` are the outputs of controller-gen, protoc,
#: stringer and gvisor's own template expander.
_SKIP_FILES = (
    "*_test.go", "export_test.go", "main_test.go",
    "zz_*.go", "*.pb.go", "*.pb.gw.go", "*_string.go", "*_generated.go",
    "*_autogen.go", "*_easyjson.go", "*_vfsdata.go", "bindata.go",
    "mock_*.go", "*_mock.go", "doc_gen.go",
)

#: Go's marker for machine output. Unlike Python, Go *specifies* this: the
#: convention at https://go.dev/s/generatedcode is a line matching exactly this
#: shape, near the top of the file, and every generator in the ecosystem emits
#: it. That is why this is the whole test, where
#: :mod:`~training.corpus.sources.pythoncode` also needs a list of loose phrases
#: — there, no convention exists to rely on.
#:
#: Having the loose list as well was tried here and it was a straight loss. On
#: these five projects it dropped 8 files that the convention did not, caught
#: zero true positives the convention missed, and all 8 were the same false
#: positive as the copyleft grep above: a file whose *subject* is code
#: generation. Go's own ``crypto/internal/fips140/mlkem/mlkem768.go`` says the
#: ML-KEM-1024 implementation "is auto-generated from this file"; gvisor's
#: ``pkg/tcpip/header/ipv6.go`` explains SLAAC "auto-generated addresses";
#: ``syscall/dll_windows.go`` mentions "autogenerated functions". Those are three
#: genuinely good files, and a substring search deleted all three for describing
#: the thing rather than being it.
_GENERATED_RE = re.compile(r"^//\s*Code generated .* DO NOT EDIT\.\s*$", re.M)

#: How far in to look for it, and the window is load-bearing rather than an
#: optimisation. A code *generator* contains the line it writes — ``mkasm.go``,
#: ``gen_encoding_table.go`` and ``generate1024.go`` all do — so searching the
#: whole file finds 167 matches where the head finds 166, and the extra one is
#: ``crypto/internal/fips140/nistec/fiat/generate.go``, which is hand-written.
#: Bounding the search is what tells the generator apart from its output.
_GENERATED_HEAD_BYTES = 4096

#: Below this a Go file is a two-type ``doc.go`` or an interface stub. Above it,
#: it is a table: gvisor's ``pkg/abi/linux`` errno lists and the Go standard
#: library's ``zerrors_*`` files run past 100 KB of near-identical const
#: declarations, and one of those outweighs thirty hand-written parsers in a
#: register it would then dominate. The ceiling costs real text — ``net/http``'s
#: ``server.go`` and gvisor's ``runsc/sandbox/sandbox.go`` are both just over it
#: and both are excellent — and it is kept anyway, at the same value
#: :mod:`~training.corpus.sources.pythoncode` uses, because a size rule that
#: varies per source is a rule nobody can reason about.
_MIN_BYTES = 1_200
_MAX_BYTES = 100_000

#: Prose-next-to-code is why this source exists, so a file without prose does
#: not qualify. Measured as an absolute quantity *and* as a share, so neither a
#: single sentence on a 40 KB constant table nor a 1.5 KB stub with one comment
#: gets through. Same numbers as the Python adapter, deliberately: the two
#: sources are measuring the same property and a difference here would make
#: their document counts incomparable.
_MIN_PROSE_CHARS = 200
_MIN_PROSE_RATIO = 0.05

#: The ceiling on one archive, handed to
#: :func:`~training.corpus.net.download` so it is enforced against bytes as they
#: arrive rather than against a ``stat()`` after the damage. The largest today
#: is trivy at 57 MB, then gvisor at 43 MB and the Go source distribution at
#: 35 MB; 120 MB is roughly double the biggest, which leaves room for ordinary
#: growth and still refuses a tarball that has become something else.
_MAX_ARCHIVE_BYTES = 120 * 1024 * 1024

#: Where the Go distribution's releases are listed, with a sha256 per file.
#: Used instead of ``codeload.github.com/golang/go`` for one reason worth more
#: than the convenience: this endpoint publishes the digest of the exact bytes,
#: so the download is *checked* rather than merely hashed. GitHub publishes no
#: hash for a branch tarball, so the other four here cannot be.
_GO_RELEASES = "https://go.dev/dl/?mode=json"
_GO_DOWNLOAD_PREFIX = "https://go.dev/dl/"

#: A source distribution filename, matched strictly because the name arrives
#: from a remote response and is then joined onto a URL. Nothing with a slash,
#: a dot-dot or a scheme in it can satisfy this.
_GO_SRC_NAME = re.compile(r"^go1\.\d+(\.\d+)?(rc\d+|beta\d+)?\.src\.tar\.gz$")

#: The three inputs on which :func:`~training.corpus.source.normalise` is
#: licensed to rewrite the interior of a line, and therefore the three things a
#: file must not contain for :func:`_whitespace_survived` to be an exact test
#: rather than an approximate one. Real Go has none of them: across 3,596
#: candidate files, two matched and both were binary noise. See the module
#: docstring.
_CR_OR_CTRL = re.compile(r"[\r\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_ABSURD_RUN = re.compile(r"[ \t]{200,}")


def _scan(text: str) -> tuple[list[tuple[int, str]], str] | None:
    """Lex Go into (comments, code), or ``None`` if the lexical structure breaks.

    A hand-written scanner because there is no Go parser in the Python standard
    library and this adapter refuses to make its output depend on whether a Go
    toolchain is installed — see the module docstring. It is small because Go's
    lexical grammar is small, and it exists to get two things right that a
    regex cannot:

    * a raw string literal is delimited by backticks, spans newlines and
      contains no escapes at all, so ``` `http://x` ``` is a string and not a
      comment, and ``` `}` ``` is a string and not a closing brace;
    * an interpreted string may not span a newline, so a file where one appears
      to is a file that has been truncated or mangled.

    Comments are returned with the line they started on, because
    :func:`_prose_chars` has to tell a licence header from a package doc
    comment and the difference is *where they are*. Code is returned with every
    comment and literal removed, which is what makes the balance test in
    :func:`_balanced` mean anything.

    ``None`` rather than an exception: an unterminated comment or literal is a
    file this source does not want, not a build failure. The one caller that
    treats it as a failure is :func:`_documents`, where the same file already
    lexed cleanly once.
    """
    comments: list[tuple[int, str]] = []
    code: list[str] = []
    i, n, line = 0, len(text), 1
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            code.append("\n")
            i += 1
        elif c == "/" and i + 1 < n and text[i + 1] == "/":
            end = text.find("\n", i)
            end = n if end < 0 else end
            comments.append((line, text[i + 2:end]))
            i = end
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            if end < 0:
                return None
            body = text[i + 2:end]
            comments.append((line, body))
            line += body.count("\n")
            i = end + 2
        elif c == "`":
            end = text.find("`", i + 1)
            if end < 0:
                return None
            line += text.count("\n", i, end)
            i = end + 1
        elif c in "\"'":
            i = _skip_quoted(text, i, c)
            if i < 0:
                return None
        else:
            code.append(c)
            i += 1
    return comments, "".join(code)


def _skip_quoted(text: str, start: int, quote: str) -> int:
    """Index just past an interpreted string or rune literal, or ``-1``.

    Split out of :func:`_scan` because the two cases are byte-identical in Go —
    both take backslash escapes, neither may contain a bare newline — and
    writing them twice is how one of them silently loses the escape handling.
    A newline before the closing quote answers ``-1``: in Go that is not a long
    string, it is a syntax error, and here it means the file is not intact.
    """
    j, n = start + 1, len(text)
    while j < n:
        ch = text[j]
        if ch == "\\":
            j += 2
            continue
        if ch == quote:
            return j + 1
        if ch == "\n":
            return -1
        j += 1
    return -1


def _balanced(code: str) -> bool:
    """True when every bracket in the comment-free, literal-free code closes.

    The nearest thing to a syntax check available here. It is genuinely weaker
    than a parse — a misplaced ``else`` sails through — and it is not weak where
    it counts: a tar member cut short, a Go template rendered into a ``.go``
    file, and a normaliser that has begun deleting characters all show up as an
    imbalance immediately.
    """
    stack: list[str] = []
    opening = {")": "(", "]": "[", "}": "{"}
    for ch in code:
        if ch in "([{":
            stack.append(ch)
        elif ch in opening:
            if not stack or stack.pop() != opening[ch]:
                return False
    return not stack


#: What makes a leading comment block furniture rather than explanation.
_HEADERISH = re.compile(r"copyright|licen[sc]e|SPDX", re.I)


def _header_comment_lines(text: str) -> int:
    """Length of the licence header at the top of the file, in lines.

    Zero when there is no such header, which is the common case in nuclei and
    trivy and never the case in gvisor or the standard library. The block is
    identical across every file in a project — around 500 characters of it in
    gvisor's case, across 2,478 files — so counting it as prose would let a file
    whose only explanation is its copyright notice satisfy the prose gate.

    Defined as the *first contiguous run of* ``//`` *lines*, and only when that
    run mentions copyright, a licence or an SPDX tag. Both halves matter. The
    run must stop at the blank line, because what follows the blank line is the
    package doc comment — the single most valuable prose in a Go file, and the
    thing that the obvious "skip comment lines until code" implementation eats
    whole. And the ``copyright`` test must be there, because a file whose very
    first line is ``// Package seccomp provides a BPF filter compiler`` has no
    header at all and its package doc must not be mistaken for one.

    The header is measured and kept, not removed: deleting it would be editing
    someone's licence notice out of their source, and ``build.py`` has a
    corpus-wide boilerplate filter for lines that repeat everywhere.
    """
    lines = text.splitlines()
    count = 0
    while count < len(lines) and lines[count].startswith("//"):
        count += 1
    if count == 0:
        return 0
    return count if _HEADERISH.search("\n".join(lines[:count])) else 0


def _prose_chars(text: str, comments: list[tuple[int, str]]) -> int:
    """Characters of human explanation: every comment past the licence header.

    Both comment forms count and both are worth the same. Go's doc convention
    produces ``//`` runs above declarations, but the trailing comment on a
    constant — ``ENOTRECOVERABLE = 131 // state not recoverable`` — is the same
    shape for a tokenizer and is how ``pkg/abi/linux`` documents most of the
    Linux ABI. Counting only leading runs would have thrown away the densest
    identifier-beside-its-name text in the source.
    """
    header = _header_comment_lines(text)
    return sum(len(body.strip()) for line, body in comments if line > header)


def _is_generated(text: str) -> bool:
    """True if the file declares itself machine output, by Go's own convention.

    One test, on purpose, and the reasoning is on :data:`_GENERATED_RE` and
    :data:`_GENERATED_HEAD_BYTES`: the convention is specified and universally
    followed, so anything looser costs good files and catches nothing.
    """
    return _GENERATED_RE.search(text[:_GENERATED_HEAD_BYTES]) is not None


def _admit(raw: bytes) -> str | None:
    """Return the decoded source if it belongs in the corpus, else ``None``.

    The gates in the order they are cheapest: size, strict UTF-8, the
    normalise-contract preconditions, the generated-file sniff, the lex, the
    balance test, and finally a real quantity of prose.

    Decoding is strict on purpose. ``errors="replace"`` would admit a
    Latin-1 file as source full of replacement characters, which lexes fine and
    teaches the model mojibake.

    The carriage-return and control-byte gate is the one that is not obvious. It
    is not about hygiene — it is what makes :func:`_whitespace_survived` an
    exact test of the normaliser instead of an approximate one, because those
    bytes plus a 200-space run are precisely the inputs on which ``normalise``
    is allowed to rewrite the interior of a line. Gating them here means that
    for everything downstream, ``normalise`` may only strip trailing whitespace
    and cap blank runs, and any other difference is a bug worth raising on.
    """
    if not _MIN_BYTES <= len(raw) <= _MAX_BYTES:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if _CR_OR_CTRL.search(text) or _ABSURD_RUN.search(text):
        return None
    if _is_generated(text):
        return None
    scanned = _scan(text)
    if scanned is None:
        return None
    comments, code = scanned
    if not _balanced(code):
        return None
    prose = _prose_chars(text, comments)
    if prose < _MIN_PROSE_CHARS or prose / len(raw) < _MIN_PROSE_RATIO:
        return None
    return text


def _wanted(project: _Project, relative: Path) -> bool:
    """True if this archive member is a file this project wants to contribute."""
    if relative.suffix != ".go":
        return False
    posix = relative.as_posix()
    if not any(posix.startswith(prefix) for prefix in project.keep):
        return False
    if any(posix.startswith(prefix) for prefix in project.drop):
        return False
    if _SKIP_DIRS.intersection(relative.parts[:-1]):
        return False
    return not any(fnmatch.fnmatch(relative.name, pattern)
                   for pattern in _SKIP_FILES)


def _archive_url(project: _Project) -> tuple[str, str, str]:
    """Resolve ``project.archive`` to a URL, a version label and a digest.

    GitHub codeload tarballs for four of the five: one request, no git binary,
    no history, and nothing on disk a later ``git pull`` could mutate under a
    reproducible build. The digest is empty for those four, honestly — GitHub
    publishes no hash for a branch tarball, and an empty string says so rather
    than implying a check that did not happen.

    Go itself comes from ``go.dev/dl/?mode=json``, which lists releases and
    gives a sha256 for each file, so this one download is verified against a
    number the upstream published rather than merely hashed after the fact.

    The filename is matched against :data:`_GO_SRC_NAME` before it is joined
    onto a URL prefix, because it is the one string in this adapter that comes
    out of a remote response rather than a constant. The URL is then built here
    from a constant prefix instead of taken from the response, so a rewritten
    index cannot redirect the download at all — the strongest form of the check
    :mod:`~training.corpus.sources.pythoncode` had to make by validating a URL
    it was handed.
    """
    if not project.archive.startswith("godl:"):
        return project.archive, project.archive.rsplit("/", 1)[-1], ""

    try:
        payload = json.loads(http_get(_GO_RELEASES, timeout=60).decode("utf-8"))
    except (NetworkError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceError(f"{_NAME}: cannot resolve {_GO_RELEASES}: {exc}") from None
    if not isinstance(payload, list):
        raise SourceError(
            f"{_NAME}: {_GO_RELEASES} answered {type(payload).__name__}, not the "
            "list of releases it has always answered. Look before trusting it."
        )

    for release in payload:
        if not isinstance(release, dict) or not release.get("stable"):
            continue
        version = str(release.get("version", "unknown"))
        for entry in release.get("files", []):
            if not isinstance(entry, dict) or entry.get("kind") != "source":
                continue
            filename = str(entry.get("filename", ""))
            if not _GO_SRC_NAME.fullmatch(filename):
                continue
            digest = str(entry.get("sha256", ""))
            if not digest:
                raise SourceError(
                    f"{_NAME}: {_GO_RELEASES} lists {filename} with no sha256. "
                    "That field is the whole reason this project is fetched "
                    "from here rather than from codeload; a distribution "
                    "downloaded with nothing to compare it against is not worth "
                    "training on."
                )
            return _GO_DOWNLOAD_PREFIX + filename, version, digest

    raise SourceError(
        f"{_NAME}: {_GO_RELEASES} lists no stable release carrying a "
        "'go1.N.src.tar.gz' source file. Either the endpoint changed shape or "
        "the source distribution moved; both need a human, not a fallback."
    )


def _sha256(path: Path) -> str:
    """Digest of a file, read a megabyte at a time.

    Chunked rather than ``hashlib.sha256(path.read_bytes())``: the ceiling here
    is 120 MB and there is no reason for any of it to be resident at once,
    least of all on a machine that may be training.
    """
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


#: A licence file by the convention every project here actually follows: an
#: all-caps stem, optionally suffixed, with a plain-text extension or none.
#: Case-sensitive on purpose — see :func:`_is_licence_file`.
_LICENCE_NAME = re.compile(
    r"^(LICENSE|LICENCE|COPYING|NOTICE|PATENTS)([-._][A-Za-z0-9._-]*)?$")
_LICENCE_SUFFIX = frozenset({"", ".md", ".txt", ".rst"})


def _is_licence_file(relative: Path) -> bool:
    """True for a licence document, at the archive root or nested in the tree.

    Nested as well as root, and that is the point. A permissive root LICENSE
    says nothing about a subtree somebody dropped in under different terms.
    nuclei's ``pkg/js/libs/LICENSE.md`` is Apache-2.0 inside an MIT repository,
    gvisor has three Go Authors BSD-3-Clause trees under an Apache-2.0 root, and
    the Go distribution's ``src/crypto/internal/boring/LICENSE`` — the only one
    of the seven that sits inside a keep prefix — reproduces four third-party
    licences that turn out to cover a binary this adapter never touches. That
    last one is written up in the module docstring, because it is the case where
    collecting the file and reading it changed the answer. Collecting them is
    what turns the claims in :data:`SPEC` into something a reader can check
    against the download instead of taking on trust.

    The case sensitivity is not fussiness, it is the whole rule working. The
    first version of this matched ``name.upper().startswith("LICENSE")`` and
    collected sixty-one files, of which roughly half were source code:
    ``pkg/licensing/expression/licenses.json`` and ``pkg/fanal/types/license.go``
    from trivy, ``tools/licensecheck/licensecheck.go`` from gvisor,
    ``pkg/notification/notice.go``. Trivy and gvisor both *contain a licence
    scanner*, so a case-insensitive prefix match on this particular corpus finds
    mostly Go. Worse, the ``licences == 0`` guard in :func:`_extract` — which is
    there to notice an upstream that has stopped shipping its licence — would
    have been satisfied by a file called ``license.go``.

    Every real licence document in all five archives is an all-caps stem with a
    plain-text extension or none, so that is what this matches, and the sixty-one
    files became the twelve that are actually licences.

    Files under :data:`_SKIP_DIRS` are excluded for the same reason their code
    is: a ``LICENSE`` under ``vendor/`` or ``testdata/`` covers a tree from which
    nothing is collected. The Go distribution alone ships nineteen of those —
    ``src/cmd/vendor/golang.org/x/*``, ``src/vendor/golang.org/x/*`` and one
    under ``runtime/testdata`` — and recording them beside the seven that
    actually govern collected code would bury the signal the ``licenses/``
    directory exists to carry.
    """
    if relative.suffix.lower() not in _LICENCE_SUFFIX:
        return False
    if not _LICENCE_NAME.fullmatch(relative.name):
        return False
    return not _SKIP_DIRS.intersection(relative.parts[:-1])


def _extract(project: _Project, archive: Path, staging: Path) -> tuple[int, int]:
    """Unpack one project's admitted ``.go`` files and its licences into staging.

    Members are copied out by hand rather than with ``TarFile.extractall``.
    These tarballs are trusted in practice, but an archive member is
    attacker-controlled data in principle — absolute paths, ``..`` segments,
    symlinks and hardlinks are all expressible in tar — and the cheap defence is
    never to hand an archive's own names to the filesystem unchecked. Only
    regular files are written, and every destination is proved to resolve inside
    ``staging`` first.

    Returns ``(seen, kept)`` so the marker records how selective the gates were.
    That ratio is the number that tells you at a glance whether an upstream has
    reorganised itself: a keep-prefix that no longer matches shows up as ``seen``
    collapsing, while a new generated-code convention shows up as ``kept``
    collapsing while ``seen`` holds.
    """
    files_root = staging / "files" / project.name
    files_root.mkdir(parents=True, exist_ok=True)
    resolved_root = files_root.resolve()
    licence_dir = staging / "licenses"
    licence_dir.mkdir(parents=True, exist_ok=True)

    seen = kept = root_licences = 0
    try:
        with tarfile.open(archive, mode="r:gz") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                parts = Path(member.name).parts
                if len(parts) < 2:
                    continue
                # Drop the archive's single root directory: "nuclei-dev/" for a
                # codeload tarball, "go/" for the Go source distribution.
                # Stripping it is what lets one set of keep-prefixes describe
                # both.
                relative = Path(*parts[1:])
                if relative.is_absolute() or ".." in relative.parts:
                    continue

                if _is_licence_file(relative) and member.size <= 256 * 1024:
                    # Flattened into one directory with the project name and the
                    # path it covers in the filename, so "which licence applied
                    # to which tree" survives as a fact on disk rather than as a
                    # sentence in SPEC that nobody can check.
                    handle = tar.extractfile(member)
                    if handle is not None:
                        flat = relative.as_posix().replace("/", "__")
                        with handle:
                            (licence_dir / f"{project.name}__{flat}"
                             ).write_bytes(handle.read())
                        if len(relative.parts) == 1:
                            root_licences += 1
                    continue

                if not _wanted(project, relative):
                    continue
                seen += 1
                if member.size > _MAX_BYTES:
                    continue
                handle = tar.extractfile(member)
                if handle is None:
                    continue
                with handle:
                    raw = handle.read()
                text = _admit(raw)
                if text is None:
                    continue

                target = files_root / relative
                if not target.resolve().is_relative_to(resolved_root):
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                # Re-encoded from the decoded text rather than copied as bytes,
                # so what lands in the cache is exactly what _admit proved to be
                # valid UTF-8, intact Go and free of the bytes that would make
                # the normalise-contract check inexact.
                target.write_text(text, encoding="utf-8")
                kept += 1
    except (tarfile.TarError, OSError) as exc:
        raise SourceError(
            f"{_NAME}: could not unpack {project.name}: {exc}") from exc

    if root_licences == 0:
        raise SourceError(
            f"{_NAME}: the {project.name} archive carries no LICENSE file at its "
            "root. Every source in this corpus declares a licence and this one "
            "keeps the upstream text on disk to back the declaration; an archive "
            "that no longer ships it needs a human to look, not a default. The "
            "count is of root licences specifically, because a nested one covers "
            "a subtree and says nothing about the project."
        )
    if kept < project.min_files:
        raise SourceError(
            f"{_NAME}: {project.name} yielded only {kept} files from {seen} "
            f"candidates under {', '.join(project.keep)} (expected at least "
            f"{project.min_files}). The upstream layout has probably changed — "
            "fix the keep-prefixes rather than training on a fraction of the "
            "project."
        )
    return seen, kept


def _fetch(cache_dir: Path) -> Path:
    """Download each project, filter it, and leave a curated tree in the cache.

    Idempotent and network-free on re-run: the marker is written only after
    every project has been extracted and the staging tree swapped into place, so
    an interrupted fetch re-downloads instead of leaving a half-populated
    ``files/`` that a later run would mistake for a finished corpus.

    The archives are deleted as soon as they are unpacked. Together they are
    about 148 MB of mostly-not-Go — trivy's tarball alone is 57 MB, of which the
    admitted source is 2.2 MB — and the curated result is 20 MB on disk holding
    17.0 M characters. Keeping them would be paying disk to avoid a download
    that only happens once, and which takes about fifteen seconds.

    Accepts either the per-source directory ``build.py`` hands it
    (``<cache>/golang``) or the cache root, so calling this by hand during
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
        for project in _PROJECTS:
            url, version, expected = _archive_url(project)
            archive = root / f".{project.name}.tar.gz.part"
            try:
                # The ceiling goes to the transport, which enforces it against
                # bytes as they arrive and refuses an oversized Content-Length
                # before reading any of them.
                download(url, archive, timeout=900,
                         max_bytes=_MAX_ARCHIVE_BYTES)
            except NetworkError as exc:
                raise SourceError(f"{_NAME}: {project.name}: {exc}") from None
            try:
                # Hashing costs one read and buys provenance: a bare branch name
                # cannot tell you afterwards which snapshot of a moving target
                # this cache holds.
                digest = _sha256(archive)
                # Where the upstream published a digest, the hash is *compared*
                # rather than merely recorded. Observing what arrived says
                # nothing about whether it is what the upstream meant to serve,
                # and a poisoned mirror object passes every other gate here: the
                # size ceiling only catches a large file, min_files only catches
                # a restructured tree, and the LICENSE check only catches a
                # missing licence.
                if expected and digest != expected:
                    raise SourceError(
                        f"{_NAME}: {project.name}: {url} hashed to {digest}, but "
                        f"the index that named the file says its sha256 is "
                        f"{expected}. These are not the bytes the upstream "
                        "published. Refusing to unpack them."
                    )
                seen, kept = _extract(project, archive, staging)
            finally:
                archive.unlink(missing_ok=True)

            manifest.append({
                "project": project.name,
                "url": project.url,
                "archive_url": url,
                "version": version,
                "license": project.license,
                "side": project.side.value,
                "archive_sha256": digest,
                # Spelled out rather than implied: "observed" is what the bytes
                # hashed to, "verified" is whether that was compared with an
                # upstream claim. Four of the five have nothing to compare
                # against, and a marker that did not say so would read as if
                # they had been checked.
                "expected_sha256": expected,
                "sha256_verified": bool(expected),
                "candidates": seen,
                "kept": kept,
            })

        # Swap in only once every project succeeded.
        shutil.rmtree(files_dir, ignore_errors=True)
        (staging / "files").replace(files_dir)
        licence_src = staging / "licenses"
        if licence_src.is_dir():
            shutil.rmtree(root / "licenses", ignore_errors=True)
            licence_src.replace(root / "licenses")
        marker.write_text(
            json.dumps(
                {
                    "cache_version": _CACHE_VERSION,
                    "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "projects": manifest,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return root


def _whitespace_survived(raw: str, cleaned: str) -> str | None:
    """``None`` if ``normalise`` kept every byte of horizontal whitespace.

    Otherwise a short description of the first line where it did not.

    This is an *exact* comparison, not a heuristic, and it can be because
    :func:`_admit` has already refused every file containing a carriage return,
    a control byte or a 200-space run. With those gone,
    :func:`~training.corpus.source.normalise` is contractually permitted to do
    three things and no more: strip trailing ``[ \\t]`` from each line, collapse
    runs of blank lines, and strip the ends. All three are invisible to a
    comparison of the non-blank lines after ``rstrip()``. Anything else — and
    the failure this guards against is a run of spaces or tabs collapsing to one
    — changes a line and is caught on the first file that contains one.

    Written as a comparison rather than as ``assert normalise(x) == expected``
    so the caller can name the file and the line. A corpus bug that reports
    itself as "something moved, somewhere" is a corpus bug nobody fixes.
    """
    before = [line.rstrip() for line in raw.split("\n")]
    before = [line for line in before if line]
    after = [line for line in cleaned.split("\n") if line.strip()]
    if len(before) != len(after):
        return (f"{len(before)} non-blank lines before normalise(), "
                f"{len(after)} after")
    for index, (was, now) in enumerate(zip(before, after), start=1):
        if was != now:
            return (f"non-blank line {index} changed: {was!r} -> {now!r}")
    return None


#: Project name (the first path component under ``files/``) to the side its
#: documents carry. Built from :data:`_PROJECTS` rather than written out again,
#: because two lists of the same five names is one list too many.
_SIDES: dict[str, Side] = {p.name: p.side for p in _PROJECTS}


def _documents(path: Path) -> Iterator[Document]:
    """Yield one Document per cached Go file, verbatim, deduplicated.

    **Symlinks are never followed.** ``os.walk(followlinks=False)`` rather than
    ``rglob``, for the reason :mod:`~training.corpus.sources.ownrepos` records
    the hard way: a sibling adapter once walked a symlink into the external
    corpus cache and pulled 180 MB of other sources back in under its own label.
    This tree is written by :func:`_fetch` and should contain no links at all,
    which is exactly the situation in which an unexamined ``rglob`` survives
    review and then does not survive the day someone points a symlink at the
    cache.

    Two checks run after :func:`~training.corpus.source.normalise` and both
    raise rather than skip, because every file here was proved intact before it
    was cached and so a failure now can only mean the normaliser broke
    something. :func:`_whitespace_survived` is the direct test of the horizontal-
    whitespace contract; re-lexing and re-balancing is the backstop for damage
    that is not whitespace at all. Skipping either would turn "the normaliser
    eats structure" into a slightly smaller document count, which is exactly the
    kind of silent corpus damage this project keeps discovering after training.

    Deduplication is by :func:`~training.corpus.source.fingerprint`,
    whitespace-insensitive and case-folded. It earns its place here rather than
    being ceremony: gvisor carries Go-Authors-derived code, the Go distribution
    is where that code came from, and trivy and nuclei share upstream helpers
    through their module graphs. ``build.py`` dedupes globally as well, but a
    source that hands it duplicates is a source whose own report is wrong.
    """
    root = path / "files" if (path / "files").is_dir() else path
    seen: set[str] = set()

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in _SKIP_DIRS and not Path(dirpath, d).is_symlink()
        )
        for filename in sorted(filenames):
            if not filename.endswith(".go"):
                continue
            file = Path(dirpath, filename)
            if file.is_symlink():
                continue
            try:
                raw = file.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            ident = file.relative_to(root).as_posix()
            text = normalise(raw)

            damage = _whitespace_survived(raw, text)
            if damage is not None:
                raise SourceError(
                    f"{_NAME}: normalise() altered {ident} beyond stripping "
                    f"trailing whitespace — {damage}. In Go the tab is the "
                    "indentation and gofmt's column alignment is what ties a "
                    "struct field to the comment explaining it, so a normaliser "
                    "that collapses horizontal whitespace does not degrade this "
                    "register, it deletes the layout the whole language agrees "
                    "on. Fix normalise(); do not filter around this."
                )
            scanned = _scan(text)
            if scanned is None or not _balanced(scanned[1]):
                raise SourceError(
                    f"{_NAME}: {ident} lexed as intact Go before normalise() and "
                    "not after. The file was proved balanced when it was cached, "
                    "so this is the normaliser removing something structural, "
                    "not bad input."
                )

            mark = fingerprint(text)
            if mark in seen:
                continue
            seen.add(mark)

            yield Document(
                text=text,
                source=_NAME,
                register=Register.SYSTEM,
                # "nuclei/pkg/protocols/http/request.go" — the first component
                # is the project, which is what makes this lookup work and what
                # makes a build report readable.
                side=_SIDES.get(ident.split("/", 1)[0], Side.NEUTRAL),
                ident=ident,
            )


SPEC = SourceSpec(
    name=_NAME,
    license=("Composite, per upstream, each read from the project's own LICENSE "
             "file rather than from a badge: nuclei MIT (ProjectDiscovery, Inc.) "
             "with pkg/js/libs/ Apache-2.0 under its own nested LICENSE.md; "
             "trivy Apache-2.0 (Aqua Security Software Ltd.); gitleaks MIT "
             "(Zachary Rice); gvisor Apache-2.0 (its three BSD-3-Clause "
             "subtrees — pkg/safecopy, pkg/sentry/time, pkg/sync — are outside "
             "the keep set and are not collected); the Go distribution "
             "BSD-3-Clause (The Go Authors, plus PATENTS), where "
             "src/crypto/internal/boring/LICENSE reproduces the OpenSSL, SSLeay, "
             "ISC and Intel terms for a prebuilt .syso object file only and "
             "states that the Go source in that directory is under the usual Go "
             "licence — no .syso is collected. Velociraptor was rejected on "
             "licence: its LICENSE is AGPL-3.0. Every LICENSE, COPYING, NOTICE "
             "and PATENTS file outside a skipped directory is copied into "
             "licenses/ in the cache, named for the project and the path it "
             "covers, so each declaration can be checked against the download."),
    # SourceSpec takes one url and this source has five. The most relevant
    # stands here — it is the engine for the 13,536 templates the corpus
    # already holds. All five, with the archive fetched, the resolved version,
    # the sha256 of what arrived and whether that was checked against a hash the
    # upstream published, are written into the cache marker by _fetch.
    url="https://github.com/projectdiscovery/nuclei",
    register=Register.SYSTEM,
    side=Side.NEUTRAL,
    fetch=_fetch,
    documents=_documents,
    #: 1,870 files survived every gate when this adapter was written — 670
    #: gvisor, 466 Go distribution, 354 nuclei, 331 trivy, 48 gitleaks — of which
    #: exactly one was a near-duplicate of another, leaving 1,869 documents and
    #: 17.0 M characters. That one hit is worth recording rather than rounding
    #: away: the projects here do *not* vendor each other's source into their
    #: trees the way the Python six did, because Go modules keep dependencies in
    #: ``vendor/`` (skipped) or out of the repository entirely. The dedup pass
    #: stays because ``build.py``'s global pass is not a substitute for a source
    #: being able to report its own size honestly.
    #:
    #: The floor sits about 25% under the total so ordinary upstream churn is
    #: quiet while a project vanishing entirely is not. Each project also carries
    #: its own floor in _Project.min_files, which fails at fetch time and names
    #: the culprit; this is the backstop for several shrinking at once.
    expect_min_docs=1_400,
    notes=("Five permissively licensed Go projects, .go source only, kept "
           "verbatim: the Nuclei template engine (pairing with the 13,536 "
           "templates the corpus already holds), trivy's scanner and ecosystem "
           "package parsers, gitleaks' secret-format rules, gvisor's Linux ABI, "
           "syscall layer, seccomp compiler, netstack and OCI runtime, and the "
           "Go distribution's crypto, net, os and syscall trees. Tests, "
           "testdata, vendored trees, generated files and anything over 100 KB "
           "are excluded; every file must carry at least 200 characters of "
           "comment prose (licence header excluded) amounting to 5% of the "
           "file, must lex as intact Go with balanced delimiters before it is "
           "cached, and must survive normalise() with every byte of horizontal "
           "whitespace intact or the build raises naming the file and the line. "
           "Register is SYSTEM and the source side is NEUTRAL; nuclei's "
           "documents carry RED and trivy's BLUE.")
)
