"""Containers and Kubernetes — the platform the corpus had never seen.

Nothing in the other twenty-nine sources knows what a Pod is. ``manpages`` and
``kerneldocs`` describe the machine a container is carved out of, ``sigma`` and
``elastic`` describe hosts and Windows event logs, ``metasploit`` and ``capec``
describe services reachable over a network. None of them contains the word
``kubectl``, a ``securityContext``, a service-account token, a hostPath mount or
an admission webhook. That is a hole where most of the industry's compute now
runs, and it shows up in the two places this project measures: the model cannot
tokenise the vocabulary, and it cannot reason about the one privilege boundary —
container to host — that has no analogue in the single-machine material the
corpus is otherwise made of.

**Why this source is shaped the way it is.** SHELL is the corpus's biggest gap,
8.9% against a 26% target, and ``kubectl`` is a command line. So the selection
was made on surface form rather than on topic: the pages that earn their place
fastest are the ones that are *made of commands*, and the ``kubectl`` and
``kubeadm`` reference trees are three thousand invocations with their flags and
their worked examples beside them. The offensive half was chosen the same way —
``badPods`` and ``deepce`` are red-team material that happens to be written
almost entirely in shell, which is the intersection of the two starved axes.

Four upstreams, three licences, every one read out of the repository rather than
off a badge:

=============================  ============  =====================================
upstream                       licence       what it contributes
=============================  ============  =====================================
kubernetes/website             CC-BY-4.0     ``content/en/docs``: kubectl and
                                             kubeadm reference, the component
                                             flag dumps, RBAC and admission and
                                             authentication reference, Pod
                                             Security Standards, the hardening
                                             guides, and every task page's
                                             manifests inlined from
                                             ``content/en/examples``
BishopFox/badPods              MIT           eight classes of over-permissioned
                                             Pod, each with the manifest that
                                             creates it and the walk from
                                             ``kubectl apply`` to a root shell
                                             on the node
stealthcopter/deepce           Apache-2.0    container enumeration and escape as
                                             one large POSIX ``sh`` program —
                                             the Docker socket, the privileged
                                             flag, CVE-2019-5736, cgroup
                                             ``release_agent``
aquasecurity/kube-hunter       Apache-2.0    the KHV### knowledge base: one
                                             short adversary-side article per
                                             finding, issue then remediation
=============================  ============  =====================================

**The register is measured, not asserted.** :class:`~training.corpus.source.Register`
is about surface form, so guessing a register from a page's topic would be the
same mistake as guessing a licence from a badge. Every document here is
classified from what it is actually made of: the fenced blocks are counted by
language, and a document whose fences are a fifth shell is SHELL, a document
that is mostly YAML or a generated flag reference is SYSTEM, and what is left —
running sentences about how access control works — is PROSE. The counting
happens on the *rendered* document, after example manifests have been inlined,
because that is the text the tokenizer will see. :data:`_SHELL_SHARE` and
:data:`_CONFIG_SHARE` are the two thresholds and they are the only tunable
things in the classification.

Measured over the current upstreams — 1,205 documents, 7.5 MB — it lands at 79%
PROSE, 14% SYSTEM, 6% SHELL and 1% ADVERSARY, and that result is worth stating
plainly rather than dressing up. Kubernetes documentation *is* mostly
explanation in sentences; the commands are the smaller part of it. PROSE is the
register this corpus is most starved of in relative terms — 1.8% against a 9%
target — so 5.9 MB of it is the largest single thing this source contributes,
and it is also a large single-topic injection into a register that currently
holds about 7 MB. That is a real judgement call and it belongs in the open: the
alternative was to reclassify concept pages as SYSTEM to look more balanced,
which would have been a worse corpus described more flatteringly. The SHELL
contribution is 450 KB — modest against a gap of tens of megabytes, but it is
the only ``kubectl`` in the corpus.

**Side is NEUTRAL for the Kubernetes documentation, and that is deliberate
under-claiming.** A page describing the Pod Security Standards could be filed
BLUE — it is defensive guidance — and the corpus's blue share would go up while
the red share, which is 30% against a 60% target, went down. Filing it NEUTRAL
is both the honest reading (it is reference documentation for a mechanism, the
same kind of text as a man page) and the one that does not quietly make the
imbalance this corpus already has worse. ``badPods``, ``deepce`` and
``kube-hunter`` are RED, because they are written from the attacker's chair and
say so on the first line.

**Trap: Hugo shortcodes, and the one that hides the manifests.** The Kubernetes
site is Hugo, and its markdown is full of ``{{< … >}}`` and ``{{% … %}}``
directives. Most are cosmetic. One is not::

    {{% code_sample file="pods/security/security-context.yaml" %}}

That shortcode is how *every* task page includes the manifest it is teaching.
376 of them are resolved on the current snapshot, and the YAML they name lives
in a completely different tree, ``content/en/examples/``. An adapter that renders shortcodes as nothing —
which is what dropping unknown directives does — produces a corpus of Kubernetes
task pages in which the sentence "create the following Pod" is followed by
nothing at all, and not one ``securityContext:`` block survives. So this module
resolves that shortcode by reading the file and inlining it as a fenced block
labelled with its path, and treats a reference to a missing example as a fault
worth counting rather than a blank to skip past.

The other shortcodes are decoded rather than deleted where they carry text:
``{{< glossary_tooltip text="Pods" term_id="pod" >}}`` becomes ``Pods`` (1,185
occurrences — dropped instead, the prose loses a noun in every other sentence),
``{{< feature-state for_k8s_version="v1.26" state="stable" >}}`` becomes the
line the site renders, and ``{{% heading "synopsis" %}}`` becomes the heading
the ``kubectl`` reference pages are structured by. ``{{< include
"task-tutorial-prereqs.md" >}}`` is the exception that is deliberately dropped:
it is the same "you need a cluster with at least two nodes" paragraph 168 times,
and text repeated 168 times in a 400 MB corpus is something a model memorises
rather than learns. The count is printed, and the heading it leaves empty is
removed with it — see :func:`_drop_empty_sections`, which exists because a
heading followed immediately by the next heading teaches that a heading can be
followed by nothing.

**Trap: shortcodes and HTML must not be touched inside a fenced block.** The
docs are full of Helm and Go-template examples, which are themselves written in
``{{ }}``, and of shell fences containing ``<pod-name>`` placeholders. So the
document is split into fenced and unfenced segments first, and every rewrite in
this module runs only on the unfenced ones.

With exactly one exception, and it is the interesting half of the trap. Hugo
expands shortcodes *before* the markdown renderer runs, so a shortcode inside a
fence is live, and the docs use that to splice the release number into commands
the reader is meant to paste: ``apt-get install -y
kubeadm='{{< skew currentVersion >}}.x-*'``. Leaving those is template syntax in
shell; dropping them gives ``kubeadm='.x-*'``, which still parses and is wrong.
:func:`_fence_versions` resolves that one family inside fences and nothing else,
and the narrowness is what makes it safe: ``{{<`` and ``{{%`` are Hugo's own
delimiters, and a Go, Helm or Kustomize template is plain ``{{ … }}``, a form
the pattern cannot match. The ``skew`` arithmetic is reimplemented from
upstream's ``layouts/shortcodes/skew.html`` rather than approximated.

That fix was found by counting what survived: a scan of the finished documents
for ``{{`` left 77 hits, and the fix took it to 6 — all of them Hugo's *escaped*
form ``{{</* mermaid */>}}``, which is a page deliberately displaying a
shortcode rather than calling one, and is therefore correct as it stands.

**Trap: ``<pod-name>`` is not a tag.** The obvious HTML stripper is
``re.sub(r"<[^>]+>", "", text)`` and it is wrong here in a way that is invisible
in a corpus sample: ``kubectl exec <pod-name> -- bash`` in running prose comes
out as ``kubectl exec  -- bash``, a command that looks perfectly well formed and
cannot work. Only the tags in :data:`_HTML_TAGS` — an explicit whitelist of real
HTML element names — are removed, so a placeholder in angle brackets survives
and a ``<td style="…">`` does not.

**Trap: the option tables are HTML, and they are most of the reference.** Every
generated ``kubectl`` and component page puts its flags in a raw ``<table>``
with the flag in a ``colspan="2"`` cell and its description in the second cell
of the following row. Stripped of tags, that renders as a wall of alternating
unrelated lines. :func:`_flatten_table` reads the row structure and emits the
flag on its own line with the description indented four spaces under it, which
is the shape a man page uses and the shape the SYSTEM register is already full
of. Whitespace *inside a flattened cell* is collapsed, which looks like it
violates the contract in :func:`~training.corpus.source.normalise` and does not:
that whitespace is the HTML file's own indentation between ``<p>`` tags, never
layout the author chose, and the same argument CAPEC's ``_keep`` makes applies
here. Nothing outside a table cell is collapsed.

**Trap: 57% of the ``kubectl`` reference is the same table.** Every one of the
111 generated ``kubectl`` pages ends with "Options inherited from parent
commands" — the complete list of global flags, byte-identical on all of them.
That is 336 KB of duplicated text, and it does two kinds of damage. It is a
memorisation hazard, the argument :mod:`~training.corpus.sources.capec` makes
about CAPEC's Content_History. And it *drowns the signal*: those pages are
command references, and with the table attached only 8 of 111 were shell-dense
enough to classify as SHELL. :func:`_collapse_repeats` writes any section body
that appears in ten or more documents out once and leaves a pointer in the rest,
which is stated by measurement rather than by name — ``kubeadm``'s equivalent is
collapsed too without this module knowing that ``kubeadm`` exists. The corpus-
wide dedup in ``build.py`` cannot see this at all: the pages differ, only a
section inside them repeats.

**Trap: near-identical manifests.** ``badPods`` ships each of its eight Pod
classes as eight Kubernetes workload kinds — Deployment, DaemonSet, CronJob,
Job, ReplicaSet, ReplicationController, StatefulSet and bare Pod — times two
variants, which is 128 YAML files whose differences are the four lines of
wrapper around one identical Pod spec. Only the bare ``pod/`` manifests are
taken, 16 files, and the READMEs that explain them keep the ``kubectl apply``
lines for every other kind. The fingerprint dedup cannot catch these, because
the wrapper really is different text.

**Trap: the GitHub API is not usable here.** ``kubernetes/website`` is a 320 MB
tarball for about 12 MB of English documentation, which is a terrible ratio, and
the obvious fix is to list the tree through ``api.github.com`` and fetch the
few hundred files that matter. That path was measured and rejected: the
unauthenticated API allows 60 requests an hour per address and was *already
exhausted on this machine* while this adapter was being written, so a build
would fail for a reason that has nothing to do with the build. The tarball has
no such limit, arrives in seventeen seconds, and is deleted as soon as the
filtered tree is extracted. :func:`_fetch` passes an explicit ``max_bytes``
because the archive is larger than :data:`~training.corpus.net.MAX_DOWNLOAD_BYTES`,
and says so at the call site, which is what that parameter exists for.

**Licensing.** Four LICENSE files were read in full; each is copied into the
cache beside the tree it covers.

* ``kubernetes/website`` — Creative Commons Attribution 4.0 International. The
  repository's ``LICENSE`` is the CC BY 4.0 legal code verbatim. Attribution is
  a condition, so every document carries a provenance line naming the
  repository, the file and the licence.
* ``BishopFox/badPods`` — MIT, Copyright (c) 2020 sart-bf.
* ``stealthcopter/deepce`` and ``aquasecurity/kube-hunter`` — Apache-2.0, with
  Aqua Security's ``NOTICE`` file carried into the cache for kube-hunter as that
  licence's clause 4(d) requires.

**Licensing: what was rejected, and why it matters.** Two obvious candidates for
this source are *not* here and neither refusal was a guess.

``aquasecurity/kube-bench`` is Apache-2.0 and is 300 YAML files of audit
commands — ``stat -c %a $apiserverconf``, ``ps -ef | grep kubelet`` — with a
remediation paragraph under each. It is, on its face, exactly what this brief
asked for. But the ``text:`` and ``remediation:`` fields are the CIS Kubernetes
Benchmark's own recommendation titles and remediation prose, and CIS publishes
its Benchmarks to non-members under **CC BY-NC-SA 4.0**: non-commercial use
only, share-alike, commercial use "subject to the prior approval of the Center
for Internet Security". Aqua's Apache-2.0 covers Aqua's code; it cannot
relicense someone else's document that the code transcribes. This is the same
shape as the trap that caught GTFOBins and Metasploit in this package, one layer
further in: the repository licence was right and the *content* licence was not.

``Hacking-the-Cloud/hackingthe.cloud`` — the best-written body of Kubernetes and
container attack technique documentation on the public web — is CC BY-NC-SA 4.0
as well, confirmed by reading its ``LICENSE``, whose first line is the
Attribution-NonCommercial-ShareAlike legal code. Not usable.

And the material this source would most like to have is already refused
elsewhere in this package. ``swisskyrepo/PayloadsAllTheThings`` has pages named
``Container - Kubernetes Pentest.md`` and ``Container - Docker Pentest.md``;
both are 800-byte redirect stubs pointing at InternalAllTheThings, which is
unlicensed and disabled here for that reason — see
:mod:`~training.corpus.sources._internal_unlicensed`. ``badPods`` and ``deepce``
exist in this source largely to fill that particular hole with text this project
is allowed to publish.
"""

from __future__ import annotations

import html
import json
import os
import re
import shutil
import tarfile
import time
from pathlib import Path
from typing import Iterator, NamedTuple

import yaml

from ..net import MAX_DOWNLOAD_BYTES, NetworkError, download
from ..source import (
    Document,
    Register,
    Side,
    SourceError,
    SourceSpec,
    fingerprint,
    normalise,
)

try:  # libyaml when the wheel has it; front matter is parsed ~2,000 times
    from yaml import CSafeLoader as _Loader  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - depends on the local PyYAML build
    from yaml import SafeLoader as _Loader  # type: ignore[assignment]


class _Repo(NamedTuple):
    """One upstream, and everything needed to justify its presence."""

    #: Directory name inside the cache, and the first component of every ident
    #: this repository produces, so a document can be traced back by string.
    key: str
    #: ``owner/name`` on GitHub.
    slug: str
    #: Branch to snapshot. Checked against each project's declared default
    #: branch rather than assumed — ``shellscripts`` was bitten by a repository
    #: that keeps a stale three-file ``master`` alive beside its real ``main``.
    ref: str
    #: SPDX identifier, read from the repository's own LICENSE file.
    license: str
    #: Which side of the engagement this upstream writes from.
    side: Side
    #: Path prefixes to keep, relative to the repository root.
    include: tuple[str, ...]
    #: Why this repository earns a place — the register argument, not marketing.
    why: str


_REPOS: tuple[_Repo, ...] = (
    _Repo(
        key="k8sdocs",
        slug="kubernetes/website",
        ref="main",
        license="CC-BY-4.0",
        side=Side.NEUTRAL,
        # ``examples`` is not optional decoration: it is where every manifest a
        # task page teaches actually lives. See the code_sample note above.
        include=("content/en/docs/", "content/en/examples/", "hugo.toml"),
        why=("the kubectl and kubeadm command surface, the component flag "
             "reference, and the access-control and Pod-security mechanisms — "
             "the vocabulary no other source in this corpus contains"),
    ),
    _Repo(
        key="badpods",
        slug="BishopFox/badPods",
        ref="main",
        license="MIT",
        side=Side.RED,
        include=("manifests/", "scripts/", "README.md"),
        why=("eight classes of over-permissioned Pod walked from kubectl apply "
             "to a root shell on the node — container-to-host escalation as a "
             "sequence of commands, which is the shape retrieval cannot supply"),
    ),
    _Repo(
        key="deepce",
        slug="stealthcopter/deepce",
        ref="main",
        license="Apache-2.0",
        side=Side.RED,
        include=("deepce.sh", "docker-wrapper.sh", "lxc-wrapper.sh",
                 "guides/", "tests/", "README.md"),
        why=("container enumeration and escape written as one large POSIX sh "
             "program: the Docker socket, --privileged, CVE-2019-5736 and the "
             "cgroup release_agent, as code rather than as description"),
    ),
    _Repo(
        key="kubehunter",
        slug="aquasecurity/kube-hunter",
        ref="main",
        license="Apache-2.0",
        side=Side.RED,
        include=("docs/_kb/",),
        why=("the KHV### knowledge base: one short article per finding, issue "
             "then remediation, in the ADVERSARY register this corpus is "
             "thinnest in"),
    ),
)

#: ``codeload`` tarballs rather than ``git clone``: one request per repository,
#: no git binary, and no ``.git`` left in the cache for a later ``pull`` to
#: mutate underneath a build that claims to be reproducible. The same decision
#: ``sigma``, ``shellscripts`` and ``owasp`` made.
_TARBALL = "https://codeload.github.com/{slug}/tar.gz/refs/heads/{ref}"

#: ``kubernetes/website`` is 320 MB of tarball — translations into forty
#: languages, every diagram, the whole Hugo theme — for about 12 MB of English
#: documentation. That is over :data:`~training.corpus.net.MAX_DOWNLOAD_BYTES`,
#: so the ceiling is raised here, at the call site, with the number the source
#: is actually expected to be. The alternative is in the module docstring: the
#: GitHub trees API, whose 60-requests-an-hour limit was already exhausted on
#: this machine before the first build ran.
_MAX_ARCHIVE_BYTES = 512 * 1024 * 1024

_TIMEOUT = 600

#: Bumped when the extraction filter changes in a way that alters what lands in
#: the cache, so an old cache is refetched rather than silently mixing two
#: filter generations. Every bump so far came from checking the output rather
#: than from a change of mind: v2 stopped applying the documentation tree's
#: extension list to ``content/en/examples``, which had been silently dropping
#: the Python, Go and Dockerfile examples four task pages inline; v3 added
#: ``hugo.toml``, which carries the release string those pages splice into API
#: reference URLs; v4 dropped ``docs/test.md``, the site's own lorem-ipsum
#: rendering smoke test.
_CACHE_VERSION = 4

#: Per-repository completion sidecar. Written **last**, after every file for
#: that repository is on disk, so an interrupted extraction re-fetches that one
#: repository next time instead of being mistaken for a finished tree — and
#: without re-downloading the three that did finish.
_SIDECAR = ".fetched.json"

#: Below this a rendering is a landing page or a stub: a title, a table of
#: contents, and nothing to learn from. Matches the floor used across this
#: package.
_MIN_CHARS = 250

#: Above this a "document" is a generated dump rather than a page. The largest
#: genuine file kept is ``reference/labels-annotations-taints/_index.md`` at
#: 119 KB, which is a real reference of every label Kubernetes defines. The one
#: file this excludes is ``reference/instrumentation/metrics.md``, 463 KB of
#: generated metric rows that would be a tenth of this source on its own.
_MAX_FILE_BYTES = 200 * 1024

#: Subtrees of ``content/en/docs`` that are dropped at extraction.
#:
#: ``reference/kubernetes-api`` is 6.3 MB of generated API field tables — real
#: vocabulary, but SYSTEM is the register this corpus is *over* target on, and
#: 162 near-identical documents of ``<td>fieldName</td><td>type</td>`` is the
#: memorisation hazard :mod:`~training.corpus.sources.capec` describes.
#: ``contribute`` is documentation about writing documentation, and it is also
#: the one tree that contains Hugo shortcodes written out as literal examples,
#: which would defeat the rewriting below. ``images`` holds no prose.
#:
#: ``test.md`` is the one entry here that was not predicted: it is the site's
#: own rendering smoke test, and it is 12 KB of *lorem ipsum* with a tour of
#: every markdown construct. It sorts first in the walk, so it was the first
#: document this source ever emitted — which is the argument for reading a
#: sample with your own eyes rather than trusting a document count.
#:
#: Prefixes ending in ``/`` match a subtree; the rest match one file exactly.
_K8S_SKIP = (
    "content/en/docs/contribute/",
    "content/en/docs/reference/kubernetes-api/",
    "content/en/docs/images/",
    "content/en/docs/test.md",
)

#: Extensions kept from each archive. Everything else — images, fonts, the Hugo
#: theme, CSS — is dropped before it touches the disk.
_KEEP_SUFFIXES = frozenset({".md", ".yaml", ".yml", ".json", ".sh"})

#: …and the extra shapes an *example* can take, which is a longer list because
#: ``content/en/examples`` holds whatever a page needs to demonstrate. This was
#: not guesswork: the first run reported four ``code_sample`` references naming
#: a file that was not in the cache, and all four were the Python, Go and
#: Dockerfile examples this set adds. The counter in :func:`_documents` exists
#: precisely so a hole like that is a printed number rather than four task pages
#: quietly missing the thing they teach.
_EXAMPLE_SUFFIXES = _KEEP_SUFFIXES | {
    ".py", ".go", ".conf", ".properties", ".txt", ".xml", ".ini", ".toml",
}
_EXAMPLE_NAMES = frozenset({"Dockerfile", "redis-config"})

#: Always kept, whatever the include prefixes say: the licence text has to live
#: in the cache beside what it covers.
_LICENSE_NAMES = frozenset({"LICENSE", "LICENSE.md", "LICENSE.txt", "NOTICE",
                            "NOTICE.md", "NOTICE.txt"})


# ---------------------------------------------------------------------------
# fetch
# ---------------------------------------------------------------------------

def _wanted(parts: tuple[str, ...], repo: _Repo) -> bool:
    """Path-level filtering, before a byte of content is read.

    Traversal and absolute components are refused outright — an archive member
    is attacker-controlled data in principle, and the cheap defence is never to
    hand its names to the filesystem unchecked.
    """
    if not parts:
        return False
    if any(p in ("", ".", "..") or os.path.isabs(p) or p.startswith("/")
           for p in parts):
        return False

    joined = "/".join(parts)
    name = parts[-1]
    if name in _LICENSE_NAMES and len(parts) == 1:
        return True
    if joined == "hugo.toml":
        return repo.key == "k8sdocs"
    if joined.startswith("content/en/examples/"):
        if (Path(name).suffix.lower() not in _EXAMPLE_SUFFIXES
                and name not in _EXAMPLE_NAMES):
            return False
    elif Path(name).suffix.lower() not in _KEEP_SUFFIXES:
        return False
    if repo.key == "k8sdocs" and any(joined.startswith(s) for s in _K8S_SKIP):
        return False
    # Only the bare Pod manifests from badPods. The other seven workload kinds
    # are the same Pod spec inside a different four-line wrapper — see the
    # module docstring; 112 of the 128 files there are that.
    if (repo.key == "badpods" and joined.startswith("manifests/")
            and joined.endswith(".yaml") and "/pod/" not in joined):
        return False
    return any(joined == prefix.rstrip("/") or joined.startswith(prefix)
               for prefix in repo.include)


def _extract(archive: Path, target: Path, repo: _Repo) -> int:
    """Unpack the wanted files out of one tarball. Returns how many landed.

    Members are iterated rather than collected with ``getmembers()``: the
    Kubernetes website archive holds fifteen thousand entries and two thousand
    survive the filter, so there is no reason to build the full list in memory.

    Only regular files are written, which is also this module's first symlink
    guard — ``member.isfile()`` is false for a link member, so nothing can ever
    be extracted through one.
    """
    resolved = target.resolve()
    written = 0
    try:
        with tarfile.open(archive, "r:gz") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                # Drop the ``<name>-<ref>/`` root component codeload adds.
                parts = tuple(Path(member.name).parts[1:])
                if not _wanted(parts, repo):
                    continue
                if member.size > _MAX_FILE_BYTES:
                    continue        # cheap check before decompressing
                destination = target.joinpath(*parts)
                if not destination.resolve().is_relative_to(resolved):
                    continue
                handle = tar.extractfile(member)
                if handle is None:
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True)
                # Bytes, not text. Nothing here re-encodes or re-indents: a
                # YAML manifest whose nesting survives the trip to disk
                # unchanged is most of what this source is for.
                with handle, destination.open("wb") as out:
                    shutil.copyfileobj(handle, out)
                written += 1
    except (tarfile.TarError, OSError) as exc:
        raise SourceError(f"containers: could not unpack {archive}: {exc}") from exc
    return written


def _count_files(root: Path) -> int:
    """Count extracted files under one repository directory, sidecar excluded."""
    total = 0
    for _, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        total += sum(1 for name in filenames if name != _SIDECAR)
    return total


def _fetch_repo(cache_dir: Path, repo: _Repo) -> dict | None:
    """Download and unpack one repository. Returns its sidecar, or ``None``.

    Warm path is free: a sidecar of the current cache version whose recorded
    file count still matches what is on disk means this repository is done.
    Counting rather than trusting the sidecar alone catches a cache that was
    copied between volumes or partly cleaned, which is the failure
    ``shellscripts`` and ``manpages`` both guard against the same way.
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
        shutil.rmtree(staging, ignore_errors=True)
        staging.mkdir(parents=True)
        try:
            download(url, archive, timeout=_TIMEOUT,
                     max_bytes=_MAX_ARCHIVE_BYTES if repo.key == "k8sdocs"
                     else MAX_DOWNLOAD_BYTES)
        except NetworkError as exc:
            raise SourceError(f"{repo.slug}: {exc}") from exc
        written = _extract(archive, staging, repo)
        if written < _MIN_EXTRACTED[repo.key]:
            raise SourceError(
                f"{repo.slug}: only {written} file(s) survived the extraction "
                f"filter, below the floor of {_MIN_EXTRACTED[repo.key]}. The "
                "branch was renamed or the tree was reorganised; fix the "
                "include prefixes rather than retrying."
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
            "files": written,
            "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            # The argument for the repository, carried into the cache. A cache
            # directory that cannot say why its contents are training data is
            # one nobody can audit six months later.
            "why": repo.why,
        }
        # Last, after every file is on disk. An interrupted fetch therefore
        # re-fetches rather than being mistaken for complete.
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


#: Per-repository extraction floor. Each is well under the observed count and
#: well over what a renamed branch or a reorganised tree would leave behind.
#: Upstream today: 1,944 / 27 / 30 / 40.
_MIN_EXTRACTED: dict[str, int] = {
    "k8sdocs": 800,
    "badpods": 15,
    "deepce": 8,
    "kubehunter": 25,
}

#: The Kubernetes documentation is 95% of this source's characters. Losing it
#: silently would leave a source that still succeeds, still emits documents, and
#: no longer contains a single ``kubectl`` invocation.
_REQUIRED = ("k8sdocs",)


def _fetch(cache_dir: Path) -> Path:
    """Populate the cache from every repository in :data:`_REPOS`.

    Tolerates a minority failing — a transient codeload error on one of four
    should cost that upstream's contribution, not the source — but not the loss
    of :data:`_REQUIRED`, without which what remains is 200 KB of red-team shell
    filed under a name that promises Kubernetes.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)

    fetched: list[dict] = []
    for repo in _REPOS:
        recorded = _fetch_repo(cache_dir, repo)
        if recorded is not None:
            fetched.append(recorded)

    arrived = {row["slug"].split("/")[-1] for row in fetched}
    missing = [r.key for r in _REPOS
               if r.key in _REQUIRED and r.slug.split("/")[-1] not in arrived]
    if missing:
        raise SourceError(
            f"containers: {', '.join(missing)} could not be fetched, and it is "
            "the upstream this source is mostly made of. A build without it "
            "would report success while containing no Kubernetes documentation "
            "at all."
        )

    (cache_dir / "manifest.json").write_text(
        json.dumps({"version": _CACHE_VERSION, "repos": fetched}, indent=1),
        encoding="utf-8",
    )
    return cache_dir


# ---------------------------------------------------------------------------
# markdown: fenced segments
# ---------------------------------------------------------------------------

#: A fence opener or closer. Info strings are only meaningful on the opener;
#: ``~~~`` is accepted because CommonMark allows it and a handful of pages use
#: it to wrap blocks that themselves contain backticks.
_FENCE = re.compile(r"^([ \t]*)(`{3,}|~{3,})([^\n`]*)$")


class _Segment(NamedTuple):
    """One run of the document: either prose, or the body of a fenced block."""

    code: bool
    #: For a code segment, the info string (``yaml``, ``shell``, or empty).
    info: str
    text: str


def _segments(body: str) -> list[_Segment]:
    """Split markdown into alternating prose and fenced-code segments.

    Everything this module rewrites — shortcodes, HTML, entities — runs on the
    prose segments only. The docs contain Helm charts and Go templates written
    in ``{{ }}``, shell fences full of ``<pod-name>`` placeholders, and YAML
    whose indentation is the whole point; a rewrite that reached inside a fence
    would corrupt all three, and would do it invisibly.

    Fence closing follows CommonMark: the closer must use the same character
    and be at least as long as the opener, and may carry no info string. A
    document that ends inside a fence — the docs have a few — closes at EOF
    rather than swallowing the rest as prose.
    """
    out: list[_Segment] = []
    prose: list[str] = []
    code: list[str] = []
    marker = ""
    info = ""

    for line in body.split("\n"):
        match = _FENCE.match(line)
        if not marker:
            if match:
                out.append(_Segment(False, "", "\n".join(prose)))
                prose = []
                marker = match.group(2)
                info = match.group(3).strip()
                code = []
                continue
            prose.append(line)
        else:
            closer = (match is not None
                      and match.group(2)[0] == marker[0]
                      and len(match.group(2)) >= len(marker)
                      and not match.group(3).strip())
            if closer:
                out.append(_Segment(True, info, "\n".join(code)))
                marker = ""
                info = ""
                code = []
                continue
            code.append(line)

    if marker:
        out.append(_Segment(True, info, "\n".join(code)))
    elif prose:
        out.append(_Segment(False, "", "\n".join(prose)))
    return out


_HEADING = re.compile(r"^#{1,6}\s")


def _drop_empty_sections(parts: list[_Segment]) -> list[_Segment]:
    """Remove a heading that ends up with nothing under it.

    ``{{< include "task-tutorial-prereqs.md" >}}`` is dropped above, and on 169
    task pages it was the entire body of the "Before you begin" section. What
    survives without this is a heading followed immediately by the next
    heading, which is the exact structural noise
    :func:`~training.corpus.sources.capec._section` was rewritten to avoid: it
    teaches that a heading can be followed by nothing.

    Code segments count as content, so a section whose only body is a fenced
    block is kept. Only the heading line is removed, never anything after it.
    """
    lines: list[tuple[int, str]] = []
    for index, part in enumerate(parts):
        if part.code:
            lines.append((index, "\x00code"))
            continue
        for line in part.text.split("\n"):
            lines.append((index, line))

    drop: set[int] = set()
    for position, (_, line) in enumerate(lines):
        if not _HEADING.match(line):
            continue
        for _, following in lines[position + 1:]:
            if not following.strip():
                continue
            if _HEADING.match(following):
                drop.add(position)
            break
        else:
            drop.add(position)

    if not drop:
        return parts

    rebuilt: list[_Segment] = []
    kept: dict[int, list[str]] = {}
    for position, (index, line) in enumerate(lines):
        if position in drop:
            continue
        kept.setdefault(index, []).append(line)
    for index, part in enumerate(parts):
        if part.code:
            rebuilt.append(part)
        else:
            rebuilt.append(_Segment(False, "", "\n".join(kept.get(index, []))))
    return rebuilt


def _reassemble(parts: list[_Segment]) -> str:
    """Put prose and fences back together, fences restored with backticks."""
    out: list[str] = []
    for part in parts:
        if part.code:
            out.append(f"```{part.info}\n{part.text}\n```")
        else:
            out.append(part.text)
    return "\n".join(out)


# ---------------------------------------------------------------------------
# markdown: Hugo shortcodes
# ---------------------------------------------------------------------------

#: One shortcode call. Hugo has two delimiters — ``{{< >}}`` passes the body
#: through as HTML, ``{{% %}}`` renders it as markdown — and they are
#: interchangeable for the purpose of stripping them.
_SHORTCODE = re.compile(
    # The space after the slash is not paranoia: upstream writes
    # "{{</ note >}}" sixteen times, and a pattern that insists on "{{< /note >}}"
    # leaves every one of them in the corpus as literal template syntax.
    r"\{\{[<%]-?\s*(?P<close>/?)\s*(?P<name>[A-Za-z0-9_][A-Za-z0-9_/.-]*)"
    r"(?P<args>(?:[^{}]|\{[^{]|\}[^}])*?)\s*-?[>%]\}\}"
)

#: Shortcodes whose *body* is dropped along with the tags. A mermaid graph is
#: diagram syntax that renders as a picture, and reads as noise.
_DROP_BLOCKS = re.compile(
    r"\{\{[<%]-?\s*(mermaid|comment)\s*-?[>%]\}\}.*?"
    r"\{\{[<%]-?\s*/\s*\1\s*-?[>%]\}\}",
    re.DOTALL,
)

#: Callout shortcodes: the tag goes, the body stays, with a label so the
#: distinction between a note and a warning survives.
_CALLOUTS = {
    "note": "Note:", "caution": "Caution:", "warning": "Warning:",
    "tip": "Tip:", "important": "Important:", "quote": "",
}

#: ``{{% heading "synopsis" %}}`` is how every generated tool-reference page
#: names its sections. Rendered as nothing, a ``kubectl`` page becomes a synopsis,
#: a block of examples and a flag table with no headings between them.
_HEADINGS = {
    "synopsis": "Synopsis",
    "examples": "Examples",
    "options": "Options",
    "parentoptions": "Options inherited from parent commands",
    "optionsfrominheritedcommands": "Options inherited from parent commands",
    "seealso": "See also",
    "prerequisites": "Before you begin",
    "objectives": "Objectives",
    "cleanup": "Cleaning up",
    "whatsnext": "What's next",
    "feedback": "Feedback",
    "editthispagewarning": "",
}

_ATTR = re.compile(r'([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*"([^"]*)"')

#: A positional argument: a quoted string, or a bare token. The bare form is
#: not optional — Hugo accepts ``{{< skew currentVersion >}}`` unquoted and the
#: Kubernetes docs write it that way every time, so a reader that only
#: understands quoted arguments resolves none of the 76 version splices and
#: leaves template syntax inside shell commands.
_TOKEN = re.compile(r'"[^"]*"|\S+')

#: Suffix to fence-language, for an inlined example file.
_EXAMPLE_LANG = {
    ".yaml": "yaml", ".yml": "yaml", ".json": "json", ".py": "python",
    ".sh": "shell", ".go": "go", ".xml": "xml", ".txt": "", ".conf": "",
    ".properties": "properties", ".ini": "ini", ".toml": "toml",
}

#: Comment syntax per fence language, for the path line written inside an
#: inlined example. ``//`` in a YAML manifest is not a comment, and a manifest
#: this corpus emits ought to be one ``kubectl apply -f -`` would accept.
_EXAMPLE_COMMENT = {"go": "//", "json": "//", "xml": "<!--"}


#: The two site params that appear inside a URL path rather than mid-sentence.
#: ``/docs/reference/generated/kubernetes-api/{{< param "version" >}}/#pod-v1-core``
#: is a real link in a real page, and dropping the shortcode leaves a doubled
#: slash — a URL that is wrong in a way nothing downstream can detect. The value
#: is read from the site's own ``hugo.toml`` rather than hardcoded, so it tracks
#: whatever release the fetched snapshot documents.
_PARAM_KEYS = ("latest", "version")

_TOML_PARAM = re.compile(r'^\s*(latest|version)\s*=\s*"([^"]+)"', re.MULTILINE)


def _site_params(root: Path) -> dict[str, str]:
    """Read ``latest``/``version`` out of the Kubernetes site's Hugo config.

    A three-line TOML reader rather than a TOML parser: the file declares the
    same keys again inside a dozen ``[[params.versions]]`` tables for the
    archived releases, and the first occurrence — the top-level ``[params]`` —
    is the current one. ``tomllib`` would be correct and would also make this
    module fail on a config whose syntax Hugo accepts and the stdlib does not,
    for a value that decorates a URL.
    """
    config = root / "hugo.toml"
    try:
        raw = config.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    found: dict[str, str] = {}
    for key, value in _TOML_PARAM.findall(raw):
        found.setdefault(key, value)
    return found


def _args(raw: str) -> tuple[dict[str, str], list[str]]:
    """Split a shortcode's argument string into named and positional parts."""
    named = {key: value for key, value in _ATTR.findall(raw)}
    positional = [token[1:-1] if len(token) > 1 and token[0] == token[-1] == '"'
                  else token
                  for token in _TOKEN.findall(_ATTR.sub(" ", raw))]
    return named, positional


def _example_block(named: dict[str, str], examples: Path,
                   missing: list[str]) -> str:
    """Inline the manifest a ``code_sample`` shortcode names.

    The path is relative to ``content/en/examples``; some pages write it with a
    leading slash and some without, and both mean the same thing.

    A reference to a file that is not there is recorded rather than silently
    rendered as a blank. That is the failure this whole function exists to
    prevent, so it would be perverse to let a *partial* version of it pass
    unremarked.
    """
    reference = (named.get("file") or "").strip().lstrip("/")
    if not reference:
        return ""
    target = examples / reference
    try:
        if not target.is_file() or target.is_symlink():
            raise OSError("not a regular file")
        payload = target.read_text(encoding="utf-8", errors="replace")
    except OSError:
        missing.append(reference)
        return ""
    language = named.get("language") or _EXAMPLE_LANG.get(
        target.suffix.lower(), "")
    # The path is emitted as a comment inside the block rather than as a line
    # above it, so the document stays an alternation of prose and code and the
    # manifest keeps its provenance if it is ever read on its own.
    comment = _EXAMPLE_COMMENT.get(language, "#")
    trailer = " -->" if comment == "<!--" else ""
    return (f"\n```{language}\n{comment} content/en/examples/{reference}{trailer}\n"
            f"{payload.rstrip()}\n```\n")


def _skew(positional: list[str], params: dict[str, str]) -> str:
    """Resolve the site's ``skew`` shortcode the way the site resolves it.

    Reimplemented from ``layouts/shortcodes/skew.html`` rather than guessed,
    because these appear *inside command lines* — ``kubeadm upgrade apply
    v{{< skew currentVersion >}}.0`` — where dropping the shortcode produces
    ``kubeadm upgrade apply v.0``: a command that is syntactically fine, plainly
    wrong, and indistinguishable from a real one to anything downstream. Both
    the minor arithmetic and the separator argument are upstream's.

    ``currentPatchVersion`` is the one approximation. The site reads the newest
    patch out of ``data/releases/schedule.yaml``; this uses the shortcode's own
    documented fallback, ``<current>.0``, which is a real release string in the
    right shape rather than an invented one.
    """
    if not positional:
        return ""
    which = positional[0].strip()
    latest = params.get("latest", "").lstrip("v")
    current = params.get("version", "").lstrip("v")
    if not latest or not current:
        return ""
    try:
        major, minor = latest.split(".")[0], int(latest.split(".")[1])
        current_minor = int(current.split(".")[1])
    except (IndexError, ValueError):
        return ""

    if which == "latestVersion":
        return latest
    if which == "currentVersion":
        return current
    if which == "currentPatchVersion":
        return f"{current}.0"
    if which == "nextMinorVersion":
        return f"{major}.{minor + 1}"
    if which == "prevMinorVersion":
        return f"{major}.{minor - 1}"
    if which == "oldestMinorVersion":
        return f"{major}.{minor - 2}"
    if which in ("latestVersionAddMinor", "currentVersionAddMinor"):
        base = minor if which.startswith("latest") else current_minor
        try:
            offset = int(positional[1])
        except (IndexError, ValueError):
            return ""
        separator = positional[2] if len(positional) > 2 else "."
        return f"{major}{separator or '.'}{base + offset}"
    return ""


def _fence_versions(text: str, params: dict[str, str]) -> str:
    """The one rewrite allowed inside a fenced code block.

    Hugo expands shortcodes *before* the markdown renderer runs, so a shortcode
    inside a fence is live — and the Kubernetes docs use that, 76 times, to
    splice the release number into commands the reader is meant to paste::

        sudo apt-mark unhold kubeadm && apt-get install -y kubeadm='{{< skew currentVersion >}}.x-*'

    Leaving it is a corpus full of template syntax in shell. Dropping it is
    worse: ``kubeadm='.x-*'``, which still parses. So the version family is
    resolved here and nothing else is, and the narrowness is what makes it safe:
    ``{{<`` and ``{{%`` are Hugo's own delimiters, and the Go, Helm and
    Kustomize templates these fences are otherwise full of are plain ``{{ … }}``
    — a form this pattern cannot match.
    """
    if not params:
        return text

    def replace(match: re.Match[str]) -> str:
        name = match.group("name").lower()
        if match.group("close") or name not in ("skew", "param"):
            return match.group(0)
        named, positional = _args(match.group("args"))
        if name == "param":
            key = (positional[0] if positional else named.get("name", "")).strip()
            return params.get(key, match.group(0)) if key in _PARAM_KEYS \
                else match.group(0)
        return _skew(positional, params) or match.group(0)

    return _SHORTCODE.sub(replace, text)


def _shortcodes(text: str, examples: Path, counts: dict[str, int],
                missing: list[str], params: dict[str, str]) -> str:
    """Rewrite one prose segment's Hugo shortcodes into plain text.

    Unknown shortcodes lose their tags and keep whatever was between them,
    which is the right default: Hugo's own convention is that a shortcode wraps
    content it decorates. The named cases below are the ones where dropping the
    tag alone loses something the corpus wanted.
    """
    text = _DROP_BLOCKS.sub("", text)

    def replace(match: re.Match[str]) -> str:
        name = match.group("name").lower()
        closing = bool(match.group("close"))
        named, positional = _args(match.group("args"))

        if closing:
            return ""
        if name in ("code_sample", "codenew", "code"):
            counts["code_sample"] = counts.get("code_sample", 0) + 1
            return _example_block(named, examples, missing)
        if name == "include":
            # The same "you need a cluster with at least two nodes" paragraph,
            # 135 times. Repetition at that rate is memorised, not learned.
            counts["include"] = counts.get("include", 0) + 1
            return ""
        if name == "glossary_tooltip":
            return named.get("text") or named.get("term_id", "")
        if name == "glossary_definition":
            return ""
        if name in ("feature-state", "feature-state-validation"):
            version = named.get("for_k8s_version", "")
            state = named.get("state", "")
            label = f"FEATURE STATE: Kubernetes {version} [{state}]"
            return label.replace("Kubernetes  ", "Kubernetes ").strip()
        if name == "heading":
            key = (positional[0] if positional else "").lower()
            return _HEADINGS.get(key, key.title())
        if name in _CALLOUTS:
            return _CALLOUTS[name]
        if name in ("ref", "relref"):
            # Inside a link target: keep the path so the link still says where
            # it points, which is a real Kubernetes docs path and therefore
            # vocabulary.
            return positional[0] if positional else (named.get("path", ""))
        if name == "tab":
            label = named.get("name", "")
            return f"\n{label}:" if label else ""
        if name == "param":
            key = (positional[0] if positional else named.get("name", "")).strip()
            return params.get(key, "") if key in _PARAM_KEYS else ""
        if name == "skew":
            return _skew(positional, params)
        if name in ("figure", "img", "youtube", "table", "tabs", "blocks",
                    "toc", "api-reference", "release-data", "cve-feed",
                    "thirdparty-content", "third-party-content", "alert",
                    "card", "index", "docs", "highlight", "rawhtml"):
            return ""
        return ""

    return _SHORTCODE.sub(replace, text)


# ---------------------------------------------------------------------------
# markdown: embedded HTML
# ---------------------------------------------------------------------------

_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_SCRIPTISH = re.compile(r"<(script|style)\b[^>]*>.*?</\1\s*>", re.DOTALL | re.IGNORECASE)

#: Real HTML element names, and nothing else. See the module docstring: the
#: obvious ``<[^>]+>`` stripper eats ``kubectl exec <pod-name>`` and leaves a
#: command that still looks valid.
_HTML_TAGS = (
    "a|abbr|b|blockquote|br|button|caption|center|cite|code|col|colgroup|dd|"
    "del|details|div|dl|dt|em|figcaption|figure|font|form|h1|h2|h3|h4|h5|h6|"
    "hr|i|iframe|img|input|ins|kbd|label|li|mark|nobr|ol|p|picture|pre|q|s|"
    "samp|section|small|source|span|strong|sub|summary|sup|table|tbody|td|"
    "header|tt|"
    "tfoot|th|thead|tr|u|ul|var|video|wbr"
)
_TAG = re.compile(rf"</?(?:{_HTML_TAGS})\b(?:\s[^<>]*?)?/?>", re.IGNORECASE)
_BREAKS = re.compile(r"</?(?:br|p|div|tr|ul|ol|table|h[1-6])\b[^<>]*?/?>", re.IGNORECASE)
_LIST_ITEM = re.compile(r"<li\b[^<>]*?>", re.IGNORECASE)

_TABLE = re.compile(r"<table\b[^<>]*?>(.*?)</table\s*>", re.DOTALL | re.IGNORECASE)
_ROW = re.compile(r"<tr\b[^<>]*?>(.*?)</tr\s*>", re.DOTALL | re.IGNORECASE)
_CELL = re.compile(r"<t[dh]\b[^<>]*?>(.*?)</t[dh]\s*>", re.DOTALL | re.IGNORECASE)

#: Entity references, matched narrowly. ``html.unescape`` run over the whole
#: text also rewrites entity-*shaped* fragments of real payloads and query
#: strings — ``?x=1&globalVar=evil`` — which is the mistake
#: :mod:`~training.corpus.sources.capec` documents. A trailing semicolon is
#: required here, so those are untouched.
_ENTITY = re.compile(r"&(?:[A-Za-z][A-Za-z0-9]{1,10}|#[0-9]{1,7}|#[xX][0-9A-Fa-f]{1,6});")

_WS_RUN = re.compile(r"[ \t\n]+")


_CELL_BREAKS = re.compile(
    r"</?(?:p|br|div|ul|ol|dl|dd|dt|h[1-6]|pre|blockquote)\b[^<>]*?/?>", re.IGNORECASE)


def _cell_lines(raw: str) -> list[str]:
    """One table cell, as the lines it is really made of.

    A cell in these tables is rarely a value. The Pod Security Standards table
    puts a paragraph, a ``Restricted Fields`` list of a dozen ``spec.…`` paths
    and an ``Allowed Values`` list inside a single ``<td>``, and joining all of
    that into one line runs the field paths together into a sentence-shaped
    thing that is neither prose nor a list. So block tags become line breaks
    and ``<li>`` becomes a bullet, before anything else happens.

    Whitespace *within* a resulting line is collapsed, and this is the only
    place in this module where that happens. It is decoding, not cleaning: what
    is being collapsed is the markdown file's own indentation of its HTML
    between two ``<p>`` tags, never spacing an author chose to be read — the
    same argument :func:`~training.corpus.sources.capec._keep` makes about
    pretty-printed XML. The blast radius is the inside of one ``<td>``, and
    :func:`~training.corpus.source.normalise`'s guarantee over everything else
    is untouched.
    """
    text = _SCRIPTISH.sub("", raw)
    text = _LIST_ITEM.sub("\n- ", text)
    text = _CELL_BREAKS.sub("\n", text)
    text = _unescape(_TAG.sub("", text))
    return [line for line in (_WS_RUN.sub(" ", part).strip()
                              for part in text.split("\n")) if line]


def _flatten_table(match: re.Match[str]) -> str:
    """Render one HTML table as indented text.

    The generated ``kubectl`` and component reference pages are mostly this: a
    flag in a ``colspan="2"`` cell, then a row whose first cell is empty and
    whose second holds the description. Emitting the flag on its own line with
    the description indented under it reproduces the shape of a man page's
    OPTIONS section, which is a shape this corpus already contains thousands of
    — and it is the same shape a multi-line cell gets, so one rule covers both
    the flag tables and the Pod Security Standards control tables.

    A table whose rows cannot be parsed falls back to stripped text rather than
    disappearing.
    """
    inner = match.group(1)
    rows = _ROW.findall(inner)
    if not rows:
        return "\n" + "\n".join(_cell_lines(inner)) + "\n"

    lines: list[str] = []
    for row in rows:
        cells = [_cell_lines(cell) for cell in _CELL.findall(row)]
        while cells and not cells[-1]:
            cells.pop()
        if not cells:
            continue
        if not cells[0] and len(cells) >= 2:
            # The description row of a flag table: no label, so everything is
            # continuation of the label above it.
            body = [line for cell in cells[1:] for line in cell]
        else:
            heads = [cell[0] for cell in cells if cell]
            body = [line for cell in cells for line in cell[1:]]
            lines.append("  |  ".join(heads))
        lines.extend("    " + line for line in body)
    return "\n" + "\n".join(lines) + "\n"


def _unescape(text: str) -> str:
    return _ENTITY.sub(lambda m: html.unescape(m.group(0)), text)


def _dehtml(text: str) -> str:
    """Turn one prose segment's embedded HTML into text.

    Order matters: comments and script bodies go first so their contents cannot
    be mistaken for structure, tables are flattened by their own reader before
    the generic tag stripper can destroy the row boundaries, block-level tags
    become newlines so paragraphs do not run together, and only then are the
    remaining whitelisted tags removed.
    """
    text = _COMMENT.sub("", text)
    text = _SCRIPTISH.sub("", text)
    text = _TABLE.sub(_flatten_table, text)
    text = _LIST_ITEM.sub("\n- ", text)
    text = _BREAKS.sub("\n", text)
    text = _TAG.sub("", text)
    return _unescape(text)


# ---------------------------------------------------------------------------
# markdown: front matter and rendering
# ---------------------------------------------------------------------------

_FRONT = re.compile(r"\A---\n(.*?)\n---\s*\n", re.DOTALL)


def _front_matter(raw: str) -> tuple[dict, str]:
    """Split YAML front matter from the body.

    Front matter is site machinery — reviewers, weights, layout hints — with
    two fields worth keeping. Parsed with the YAML loader rather than by
    pattern, because ``description:`` is routinely a folded block scalar
    spanning three lines and a regex would keep the first of them.
    """
    match = _FRONT.match(raw)
    if not match:
        return {}, raw
    try:
        parsed = yaml.load(match.group(1), Loader=_Loader)
    except yaml.YAMLError:
        parsed = None
    return (parsed if isinstance(parsed, dict) else {}), raw[match.end():]


def _render_markdown(raw: str, examples: Path, counts: dict[str, int],
                     missing: list[str],
                     params: dict[str, str] | None = None) -> tuple[str, dict]:
    """Render one Hugo markdown file to plain text. Returns (text, front matter).

    Two segmentation passes. The first splits the file so shortcodes and HTML
    are rewritten only outside fenced code. Inlining a ``code_sample`` adds
    *new* fences in the middle of a prose segment, so the result is reassembled
    and the caller segments it again to measure the register — which is right,
    because the register has to be measured over the text the tokenizer sees,
    manifests and all.
    """
    front, body = _front_matter(raw)

    rendered: list[_Segment] = []
    for segment in _segments(body):
        if segment.code:
            rendered.append(_Segment(True, segment.info,
                                     _fence_versions(segment.text, params or {})))
            continue
        text = _shortcodes(segment.text, examples, counts, missing, params or {})
        rendered.append(_Segment(False, "", _dehtml(text)))

    header: list[str] = []
    title = str(front.get("title") or "").strip()
    if title:
        header.append(f"# {title}")
    description = str(front.get("description") or "").strip()
    if description:
        header.append("")
        header.append(description)

    return "\n".join(header + ["", _reassemble(_drop_empty_sections(rendered))]), front


# ---------------------------------------------------------------------------
# register classification
# ---------------------------------------------------------------------------

#: Fence info strings that are a shell. ``console`` and ``shell-session`` carry
#: the prompt as well as the command, which is if anything more useful: reading
#: command *output* is half of what this model has to do.
_SHELL_LANGS = frozenset({
    "shell", "bash", "sh", "zsh", "console", "shell-session", "shellsession",
    "terminal", "cmd", "bat", "batch", "powershell", "ps1", "posh",
})

#: Fence info strings that are configuration or structured data. This is the
#: SYSTEM register's own definition — "config file syntax, API references".
_CONFIG_LANGS = frozenset({
    "yaml", "yml", "json", "toml", "ini", "xml", "proto", "hcl", "conf",
    "properties", "http", "cel",
})

#: Lines that start a shell command, used to classify an untagged fence. The
#: generated ``kubectl`` reference is the reason this exists: its Examples
#: section is a bare ``` fence with no language on it, which is precisely the
#: most shell-dense block in the whole source.
_COMMANDISH = re.compile(
    r"^\s*(?:[$#>]\s+|sudo\s+|(?:kubectl|kubeadm|crictl|ctr|nerdctl|docker|"
    r"podman|helm|etcdctl|systemctl|journalctl|openssl|curl|wget|kubelet|"
    r"chmod|chown|stat|ps|grep|cat|echo|export|cd|ls|mkdir|rm|cp|mv|nc|ncat|"
    r"nsenter|mount|umount|chroot|apt|apt-get|yum|dnf|apk|brew|git|make|go|"
    r"python3?|bash|sh|env|kubie|kubectx|base64|jq|awk|sed|find|ssh|scp)\b)"
)
_YAMLISH = re.compile(r"^\s*(?:apiVersion|kind|metadata|spec|- name|-\s+\w+:)\b|^[A-Za-z][\w.-]*:\s")

#: A document whose fenced blocks are at least this share shell is SHELL. A
#: fifth rather than a half: a Kubernetes task page is prose *around* commands,
#: and the commands are the part that is scarce.
_SHELL_SHARE = 0.20

#: …and, failing that, a document this much configuration is SYSTEM. Higher,
#: because a single inlined manifest should not turn a page of explanation into
#: a config document.
_CONFIG_SHARE = 0.35


def _sniff(body: str) -> str:
    """Classify an untagged fence by what its lines look like."""
    lines = [line for line in body.split("\n") if line.strip()]
    if not lines:
        return "other"
    commandish = sum(1 for line in lines if _COMMANDISH.match(line))
    yamlish = sum(1 for line in lines if _YAMLISH.match(line))
    if commandish >= yamlish and commandish >= max(1, len(lines) // 3):
        return "shell"
    if yamlish > commandish and yamlish >= max(1, len(lines) // 2):
        return "config"
    return "other"


def _measure(text: str) -> tuple[float, float]:
    """(shell share, config share) of one rendered document, by characters."""
    total = max(len(text), 1)
    shell = config = 0
    for segment in _segments(text):
        if not segment.code:
            continue
        words = segment.info.split()
        language = words[0].lower().lstrip("{.") if words else ""
        kind = ("shell" if language in _SHELL_LANGS else
                "config" if language in _CONFIG_LANGS else
                _sniff(segment.text) if not language else "other")
        if kind == "shell":
            shell += len(segment.text)
        elif kind == "config":
            config += len(segment.text)
    return shell / total, config / total


def _register(text: str, *, generated: bool, red: bool) -> Register:
    """Decide a document's register from its measured surface form.

    ``generated`` is the ``auto_generated: true`` front-matter flag the
    Kubernetes reference pages carry. It only matters for the ones with no
    shell in them at all — ``kube-apiserver.md`` is a single enormous flag
    table with no fenced block anywhere, and without this it would be filed as
    PROSE, which it very much is not.

    ``red`` routes the offensive upstreams' non-shell documents to ADVERSARY
    rather than PROSE. A badPods README that is more explanation than command
    is a procedure narrative — behaviour described as behaviour — which is the
    ADVERSARY register's own definition.
    """
    shell, config = _measure(text)
    if shell >= _SHELL_SHARE:
        return Register.SHELL
    if generated:
        return Register.SYSTEM
    if config >= _CONFIG_SHARE:
        return Register.SYSTEM
    return Register.ADVERSARY if red else Register.PROSE


# ---------------------------------------------------------------------------
# documents
# ---------------------------------------------------------------------------

def _walk(root: Path) -> list[Path]:
    """Every cached file under one repository, in a stable order.

    ``os.walk(followlinks=False)``, never ``rglob``: a source in this package
    once followed a symlink into the corpus cache and pulled 180 MB of the
    corpus back in as training data. The per-entry check is there too, because
    ``followlinks`` governs the descent and not the file the walk lands on.
    """
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames
                             if not Path(dirpath, d).is_symlink())
        for name in sorted(filenames):
            if name == _SIDECAR or name in _LICENSE_NAMES:
                continue
            path = Path(dirpath, name)
            if path.is_symlink():
                continue
            found.append(path)
    return found


def _provenance(repo: _Repo, relative: str, text: str, *,
                comment: str | None) -> str:
    """Attach the one-line attribution the licences require.

    CC BY 4.0 makes attribution a condition, so this is not decoration. For
    YAML and shell the line is a comment, so the document remains a file that
    would actually parse or run; ``shellscripts`` learned the hard way that a
    note placed above a ``#!`` line turns an executable script into one the
    kernel will not start, so a shebang keeps line 1.
    """
    note = f"{repo.slug} {relative} ({repo.license})"
    if comment is None:
        return f"Source: {note}\n\n{text}"
    if not text.startswith("#!"):
        return f"{comment} {note}\n{text}"
    shebang, newline, rest = text.partition("\n")
    if not newline:
        return f"{shebang}\n{comment} {note}"
    return f"{shebang}\n{comment} {note}\n{rest}"


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


#: A section body has to appear in at least this many documents before it is
#: treated as boilerplate rather than as a coincidence. Ten is far above any
#: honest repetition and far below the numbers this actually catches.
_SECTION_REPEAT = 10

_SECTION_HEAD = re.compile(r"^#{2,3}\s")


def _split_sections(text: str) -> list[tuple[str, str]]:
    """Split a rendered page into ``(heading line, body)`` pairs, fence-aware.

    The leading part before the first heading comes back with an empty heading.
    A ``##`` line inside a fenced block is a comment in a shell script, not a
    heading, which is why this walks segments instead of running a regex over
    the whole document.
    """
    lines: list[str] = []
    for part in _segments(text):
        if part.code:
            lines.append(f"```{part.info}")
            lines.extend(part.text.split("\n"))
            lines.append("```")
        else:
            lines.extend(part.text.split("\n"))

    sections: list[tuple[str, list[str]]] = [("", [])]
    inside = ""
    for line in lines:
        fence = _FENCE.match(line)
        if inside:
            if fence and fence.group(2)[0] == inside[0] \
                    and len(fence.group(2)) >= len(inside):
                inside = ""
        elif fence:
            inside = fence.group(2)
        elif _SECTION_HEAD.match(line):
            sections.append((line, []))
            continue
        sections[-1][1].append(line)
    return [(head, "\n".join(body)) for head, body in sections]


def _collapse_repeats(pages: list[_Rendered]) -> tuple[list[_Rendered], int, int]:
    """Emit a section that is identical across many pages once, not many times.

    This is not a general tidy-up, it is a measured repair. 111 of the generated
    ``kubectl`` reference pages carry the same "Options inherited from parent
    commands" table — every global flag ``kubectl`` accepts, ``--kubeconfig``
    through ``--tls-server-name`` — and it is **57% of the characters in that
    whole tree**. Two separate harms follow. The obvious one is memorisation:
    376 KB of byte-identical text in a 400 MB corpus is the kind of repetition a
    model at many epochs learns by heart, which is the argument
    :mod:`~training.corpus.sources.capec` makes about CAPEC's Content_History.
    The subtle one is that the boilerplate *drowns the signal*: those pages are
    command references, and with the inherited table attached only 8 of 111 had
    a high enough shell share to be classified SHELL. With it collapsed they are
    what they actually are.

    Corpus-wide dedup cannot see this — the pages differ, only a section inside
    them repeats — and the rule is stated by measurement rather than by name, so
    the same collapse happens to ``kubeadm``'s equivalent without this function
    knowing that ``kubeadm`` exists.

    The section survives in full in the first page that carries it, which keeps
    every one of those flag names in the corpus, and the rest get a pointer.
    """
    bodies: dict[str, list[tuple[int, int]]] = {}
    split = [_split_sections(page.text) for page in pages]
    for index, sections in enumerate(split):
        for position, (head, body) in enumerate(sections):
            if not head or len(body.strip()) < 200:
                continue
            bodies.setdefault(fingerprint(head + body), []).append((index, position))

    held = chars = 0
    replaced: dict[tuple[int, int], str] = {}
    for occurrences in bodies.values():
        if len(occurrences) < _SECTION_REPEAT:
            continue
        keeper = pages[occurrences[0][0]].relative
        for index, position in occurrences[1:]:
            head = split[index][position][0].strip("# ").strip()
            replaced[(index, position)] = (
                f"(Identical to the \"{head}\" section of {keeper}, "
                f"repeated on {len(occurrences)} pages and written out there.)")
            held += 1
            chars += len(split[index][position][1])

    if not replaced:
        return pages, 0, 0

    out: list[_Rendered] = []
    for index, page in enumerate(pages):
        rebuilt: list[str] = []
        for position, (head, body) in enumerate(split[index]):
            if head:
                rebuilt.append(head)
            note = replaced.get((index, position))
            rebuilt.append(f"\n{note}\n" if note else body)
        out.append(page._replace(text=normalise("\n".join(rebuilt))))
    return out, held, chars


class _Rendered(NamedTuple):
    """One finished body, before attribution is attached to it."""

    #: Repository-relative path, which becomes the ident and the attribution.
    relative: str
    text: str
    register: Register
    #: Comment marker for the attribution line, or ``None`` for a plain header.
    comment: str | None


def _k8s_documents(root: Path, counts: dict[str, int],
                   missing: list[str]) -> Iterator[_Rendered]:
    """Render ``content/en/docs``; ``content/en/examples`` is inlined, not emitted.

    An example manifest reached from a task page is already in that page's
    document, beside the paragraph that explains it. Emitting it a second time
    on its own would duplicate text in a corpus small enough that duplication is
    memorised — and would do it in a way the fingerprint dedup cannot see,
    because the inlined copy carries a path comment the standalone one does not.

    Two passes, and the whole tree is held in memory between them, which costs
    about 8 MB. :func:`_collapse_repeats` has to see every page before it can
    know which section bodies repeat, and the register cannot be measured until
    after that, because on the generated ``kubectl`` pages the repeated section
    is more than half the characters the measurement would divide by.
    """
    docs = root / "content" / "en" / "docs"
    examples = root / "content" / "en" / "examples"
    params = _site_params(root)
    if not docs.is_dir():
        raise SourceError(
            f"containers: no content/en/docs under {root}; run fetch() first"
        )

    pages: list[_Rendered] = []
    generated: list[bool] = []
    for path in _walk(docs):
        if path.suffix.lower() != ".md":
            continue
        raw = _read(path)
        if raw is None:
            continue
        text, front = _render_markdown(raw, examples, counts, missing, params)
        text = normalise(text)
        if len(text) < _MIN_CHARS:
            continue
        pages.append(_Rendered(
            relative=path.relative_to(root).as_posix(),
            text=text,
            # Placeholder: the register is measured below, after the repeated
            # sections are gone.
            register=Register.PROSE,
            comment=None,
        ))
        generated.append(bool(front.get("auto_generated")))

    pages, sections, chars = _collapse_repeats(pages)
    if sections:
        counts["sections"] = sections
        counts["section_chars"] = chars

    for page, is_generated in zip(pages, generated):
        if len(page.text) < _MIN_CHARS:
            continue
        yield page._replace(
            register=_register(page.text, generated=is_generated, red=False))


def _plain_documents(root: Path, repo: _Repo) -> Iterator[_Rendered]:
    """badPods and kube-hunter: ordinary markdown, plus their manifests.

    Neither site is Hugo, so there is nothing to resolve — but kube-hunter's
    knowledge base is Jekyll and writes its own title as ``{{ page.vid }} -
    {{ page.title }}``, a Liquid expression that would otherwise be the first
    line of all 39 documents. The front matter holds the real values, so the
    heading is rebuilt from them and the finding's identifier (``KHV036``) ends
    up in the text where a tokenizer can learn it, exactly as ``capec`` argues
    for its own ids.
    """
    for path in _walk(root):
        raw = _read(path)
        if raw is None:
            continue
        suffix = path.suffix.lower()
        relative = path.relative_to(root).as_posix()

        if suffix in (".yaml", ".yml"):
            # A manifest is configuration, whoever wrote it and for whatever
            # purpose. badPods' hostPath Pod is SYSTEM by surface form and RED
            # by side, and those two axes are supposed to disagree.
            text, comment, register = normalise(raw), "#", Register.SYSTEM
        elif suffix == ".sh":
            text, comment, register = normalise(raw), "#", Register.SHELL
        elif suffix == ".md":
            front, body = _front_matter(raw)
            # The KB templates its own heading as Liquid — "# {{ page.vid }} -
            # {{ page.title }}" — so the real values are rebuilt from the front
            # matter and the template line is removed.
            body = re.sub(r"^#+\s*\{\{[^}]*\}\}.*$", "", _dehtml(body), flags=re.MULTILINE)
            header: list[str] = []
            label = " - ".join(str(front[key]).strip()
                               for key in ("vid", "title") if front.get(key))
            if label:
                header.append(f"# {label}")
            for key in ("categories", "severity"):
                value = front.get(key)
                if value:
                    if isinstance(value, list):
                        value = ", ".join(str(v) for v in value)
                    header.append(f"{key.title()}: {value}")
            text = normalise("\n".join(header + ["", body]))
            comment = None
            register = _register(text, generated=False,
                                 red=repo.side is Side.RED)
        else:
            continue

        if len(text) < _MIN_CHARS:
            continue
        yield _Rendered(relative=relative, text=text, register=register,
                        comment=comment)


def _documents(path: Path) -> Iterator[Document]:
    """Yield every cached page, deduplicated, with provenance attached.

    Dedup runs on the *body*, before the attribution line is prepended. These
    trees copy from each other — badPods repeats a manifest across workload
    kinds, the Kubernetes docs repeat a prerequisites block — and a
    path-dependent header makes two identical bodies look distinct to any
    fingerprint taken afterwards, including ``build.py``'s own corpus-wide one,
    which only ever sees the finished document.
    """
    counts: dict[str, int] = {}
    missing: list[str] = []
    seen: set[str] = set()
    duplicates = 0
    by_register: dict[str, int] = {}

    for repo in _REPOS:
        root = path / repo.key
        if not root.is_dir():
            continue

        produced = (_k8s_documents(root, counts, missing) if repo.key == "k8sdocs"
                    else _plain_documents(root, repo))

        for item in produced:
            mark = fingerprint(item.text)
            if mark in seen:
                duplicates += 1
                continue
            seen.add(mark)
            text = _provenance(repo, item.relative, item.text,
                               comment=item.comment)
            by_register[item.register.value] = (
                by_register.get(item.register.value, 0) + len(text))
            yield Document(
                text=text,
                source="containers",
                register=item.register,
                side=repo.side,
                ident=f"{repo.key}/{item.relative}",
            )

    # No silent filtering: say what happened.
    if counts.get("code_sample"):
        print(f"   containers: inlined {counts['code_sample']:,} example "
              "manifests from content/en/examples into the pages that teach them")
    if counts.get("sections"):
        print(f"   containers: collapsed {counts['sections']:,} repeated "
              f"section(s) worth {counts['section_chars']:,} chars — chiefly "
              "the global-flag table every generated kubectl page carries")
    if counts.get("include"):
        print(f"   containers: dropped {counts['include']:,} repeated "
              "prerequisite include(s) — the same paragraph every time")
    if duplicates:
        print(f"   containers: dropped {duplicates} duplicate document(s)")
    if missing:
        unique = sorted(set(missing))
        print(f"   ! containers: {len(unique)} code_sample reference(s) named a "
              f"file that is not in content/en/examples, e.g. {unique[0]}")
    if by_register:
        breakdown = ", ".join(
            f"{name} {size / max(sum(by_register.values()), 1):.0%}"
            for name, size in sorted(by_register.items(), key=lambda kv: -kv[1])
        )
        print(f"   containers: measured register mix — {breakdown}")


_LICENSE = (
    "Composite, verified per upstream by reading each repository's own LICENSE "
    "file, which is copied into the cache beside the tree it covers: "
    "kubernetes/website CC-BY-4.0 (attribution is a condition and travels with "
    "every document as a provenance line); BishopFox/badPods MIT (Copyright "
    "(c) 2020 sart-bf); stealthcopter/deepce Apache-2.0; "
    "aquasecurity/kube-hunter Apache-2.0 (Aqua Security's NOTICE is cached). "
    "aquasecurity/kube-bench was rejected despite its Apache-2.0 repository "
    "licence: its check text and remediation prose are the CIS Kubernetes "
    "Benchmark, which CIS publishes to non-members under CC BY-NC-SA 4.0 — "
    "non-commercial, and Aqua cannot relicense it. "
    "Hacking-the-Cloud/hackingthe.cloud was rejected for the same licence, read "
    "from its LICENSE file."
)


SPEC = SourceSpec(
    name="containers",
    license=_LICENSE,
    url="https://github.com/kubernetes/website (largest of four; see _REPOS)",
    register=Register.SHELL,
    side=Side.NEUTRAL,
    fetch=_fetch,
    documents=_documents,
    #: 1,205 documents survive today: 1,112 Kubernetes pages from 1,512 cached
    #: markdown files — the other 400 are landing pages and feature-gate stubs
    #: under the 250-character floor — plus 93 from the three red upstreams. A
    #: floor at 900 clears ordinary upstream churn and the drift of that floor,
    #: while still failing loudly at the thing this number exists to catch: a
    #: renamed branch or a reorganised content tree, which would otherwise read
    #: as a merely thinner build report.
    expect_min_docs=900,
    notes=(
        "Kubernetes and container security, which no other source in this "
        "corpus contains: kubectl/kubeadm command reference, component flag "
        "dumps, RBAC, admission control, service-account tokens, Pod Security "
        "Standards — plus the offensive half, eight classes of over-"
        "permissioned Pod walked to a root shell on the node (badPods), "
        "container escape as a POSIX sh program (deepce) and the kube-hunter "
        "KHV knowledge base. Hugo shortcodes are resolved rather than dropped, "
        "which is what inlines each task page's manifest from "
        "content/en/examples; HTML option tables are flattened to a man-page "
        "shape; both rewrites run only outside fenced code. Register is "
        "measured from each rendered document's fence composition rather than "
        "assumed from its topic."
    ),
)
