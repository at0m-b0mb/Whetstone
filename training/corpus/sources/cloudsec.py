"""The cloud control plane, in the register an operator actually types. SHELL/NEUTRAL.

Everything else in this corpus assumes a machine you can log into. Nothing in it
has ever seen an *account*. Measured against the 400 MB the build collected
before this adapter existed, there is no IAM policy document anywhere in it, no
``arn:aws:iam::123456789012:role/…``, no
``az role assignment create --scope /subscriptions/…``, no ``aws sts
get-caller-identity`` and no JSON body coming back from one. A model that has
never met those tokens cannot reason about the environment most engagements now
happen in — it reads ``sts get-caller-identity`` as three unrelated English
fragments and an ARN as punctuation.

The gap is worth more here than the topic alone would justify, because of *which*
register fills it. SHELL is this corpus's largest hole by a distance — 8.9%
observed against a 26% target, roughly 35 M characters where the target wants a
hundred — and the two upstreams collected here are shell almost to the
character. ``aws`` and ``az`` are also the only two cloud CLIs whose reference
material is published under a licence that can be read from the distribution
itself; see **What is deliberately not here** below, which is most of this
docstring, because in this domain the upstreams that were *refused* took longer
to settle than the ones that were taken.

**What a document is.** One command, with worked invocations under it::

    aws iam list-attached-role-policies

    **To list all managed policies that are attached to the specified role**

    This command returns the names and ARNs of the managed policies attached to
    the IAM role named ``SecurityAuditRole`` in the AWS account. ::

        aws iam list-attached-role-policies \\
            --role-name SecurityAuditRole

    Output::

        {
            "AttachedPolicies": [
                {
                    "PolicyName": "SecurityAudit",
                    "PolicyArn": "arn:aws:iam::aws:policy/SecurityAudit"
                }
            ],
            "IsTruncated": false
        }

That is the intent-to-invocation pair :mod:`~training.corpus.sources.tldr` was
collected for, and then the half tldr does not have: **the answer**. Reading
command output is the other half of an agent's loop and the corpus was thin in
it outside ``netstat``-shaped fragments. **4,274 of the 5,850 AWS examples — 73%
— carry an ``Output::`` block**, so most of this source is a command paired with
the JSON the API really returns: response envelopes, ARNs, IAM policy documents,
ISO-8601 timestamps, pagination tokens. The median AWS document is 931
characters, which is a command, its explanation and its answer, and is about as
close to one training window of exactly the right thing as this corpus gets.

**The body is kept verbatim, and the reason is ``*``.** The obvious tidy-up is a
demarkup pass: turn ``**To list…**`` into plain text, ``\\`\\`x\\`\\``` into
``` `x` ```, drop the ``::`` literal-block markers. It is not done, for the
reason :mod:`~training.corpus.sources.payloads` gives about angle brackets — in
*this* source an asterisk is far more likely to be an IAM wildcard than markup.
``"Action": "s3:*"``, ``"Resource": "arn:aws:s3:::bucket/*"`` and
``"Principal": {"AWS": "*"}`` are the single most security-relevant token in the
whole upstream, and the difference between an over-broad policy and a correct
one is exactly where those asterisks fall. A bold-stripping regex that ever
matched across two of them would silently rewrite a policy document into a
different policy document, inside a corpus teaching a model to judge policies.
RST is a real surface form; a mangled IAM statement is not. So the only thing
added is the command header, and the only thing that touches the body is
:func:`~training.corpus.source.normalise`.

**Whitespace is the document, again.** The JSON block above is signal precisely
because it is indented four spaces under ``Output::`` and its keys line up
underneath each other. ``normalise`` preserves horizontal whitespace and this
adapter adds no private cleaner; if that contract ever changes, this source
turns from "command and its output" into "command and a paragraph of braces",
and the Azure help renderings — which indent example bodies under their titles —
go the same way.

**Fetched as the published sdist, not the git tree.** Both projects were first
taken as codeload tarballs, and the numbers are why they are not:
``Azure/azure-cli@dev`` is **181 MB** on the wire and ``aws/aws-cli@develop`` is
19 MB, against **9.4 MB** and 16.8 MB for the same content in the PyPI source
distributions. Azure's git tree is twenty times its own source because the test
recordings live beside the modules; an early abort cannot dodge them, since the
help file and the recordings sit in the same per-module directory and sort
together. The sdist buys three further things over a moving branch: a released
version number recorded in the cache marker, a build that is reproducible
against that version, and — the one that actually matters — **a publisher-side
sha256**. PyPI states the digest of every file in its JSON API, so the archive is
verified against the index's claim before a byte of it is unpacked, which a
``tar.gz`` of a branch tip cannot offer at all.

**The licences, read from inside the distribution.** Each sdist carries its own
``LICENSE.txt`` and that file — not a README sentence, not a shields.io badge —
is what was read, and it is copied into the cache beside the text it covers.
awscli is Apache-2.0 ("Copyright 2012-2020 Amazon.com, Inc. or its
affiliates"); azure-cli is MIT ("Copyright (c) Microsoft Corporation").

Azure needs one more step than that, and it is the trap this project has already
been caught by twice: a permissively licensed repository is free to vendor files
that are not. ``azure-cli``'s own ``NOTICE.txt`` lists LGPL-2.1 components —
chardet, paramiko, nose — under a heading about reverse engineering "libraries
licensed under the GNU Lesser General Public License". Those are *dependencies*
azure-cli installs, not files this adapter reads, and nothing from them is
extracted. Rather than rest on that reasoning, the check is structural: every
``_help.py`` collected must carry Microsoft's MIT header inside its own first ten
lines, or it is skipped and counted. All 75 files upstream pass today. The day
one does not, this adapter drops it instead of quietly training on it.

**Two upstream quirks that are worth the lines they cost.** azure-cli declares
help as YAML inside Python string literals, and **123 command keys are declared
more than once**: 70 as a codegen'd ``generated/_help.py`` beside the
hand-written ``manual/_help.py`` that overrides it, 43 as a live
``monitor/_help.py`` beside a superseded ``monitor/_legacy/_help.py``, and 10 as
one file assigning the same key twice. Emitting both halves of each pair would
put 123 pairs of nearly-identical documents into a corpus small enough to
memorise them, and ``build.py``'s whole-text fingerprinting cannot collapse them
because they differ by a sentence. So the winner is decided in
:func:`_azure_documents` rather than left to walk order, and it is the one ``az
--help`` prints. Separately, six entries spell the examples key ``example`` and
exactly one spells it ``exmaples``; all three spellings are read, because a typo
upstream is a bad reason to drop a worked example here.

**What is deliberately not here.** Four cloud-security upstreams were fetched,
read and licence-checked for this slot and then left out, three of them for
reasons that have nothing to do with their licences::

    prowler-cloud/prowler      Apache-2.0  (LICENSE is the Apache text,
                               "Copyright @ 2024 Toni de la Fuente";
                               pyproject.toml agrees: license = "Apache-2.0")
    DataDog/stratus-red-team   Apache-2.0
    RhinoSecurityLabs/pacu     BSD-3-Clause
    nccgroup/ScoutSuite        GPL-2.0-only  (commonly cited as "GPL"; the
                               LICENSE file is v2, not v3)

Prowler is the best cloud-security text that exists under a permissive licence:
1,616 checks across twenty providers, each naming a misconfiguration, what it
looks at, why it is dangerous, and the ``aws`` / ``az`` / ``gcloud`` / ``kubectl``
command that fixes it. It is not folded in here for the reason
:mod:`~training.corpus.sources.owasp` refuses to fold in the Web Security Testing
Guide: ``build.py`` attributes register and side per
:class:`~training.corpus.source.SourceSpec`, and ``balance_report`` sums
``stats.side``, not the document's.

Prowler is a control catalogue, which :mod:`training.corpus.source` names outright
as blue knowledge, and it is not SHELL either — measured across all 1,616
metadata files rather than guessed from the one check everybody quotes. The
English fields (Description, Risk, Recommendation) are 1.31 M characters; the
remediation blocks are 1.48 M, but only **159 KB of that is the CLI command**.
The rest is Terraform, CloudFormation and numbered portal click-paths. So the
honest rendering is 47% PROSE and a SYSTEM-shaped remainder with 6% shell in it,
declared BLUE. Yielding that from a spec declared SHELL/NEUTRAL would land
correctly in the JSONL and then be reported as neutral shell in the one number
this project steers the 60/40 offence balance by. Stratus Red Team (113 cloud
attack techniques, each with the CloudTrail events its detonation really
produced) and Pacu (76 AWS exploitation modules) are ADVERSARY/RED, and are out
for the same reason and by the same argument. A source that lies to the balance
report is worse than a source that does not exist, so those three want their own
adapters — ``prowler``, ``stratus``, ``pacu`` — and this docstring exists so that
the next person does not repeat the licence work: all three are checked, all
three are clean.

ScoutSuite is refused on top of that as duplication: it audits the same
misconfigurations prowler does, under a heavier licence, and re-fetching material
another adapter already renders spends the corpus's scarcest resource, which is
unique text.

**HackTricks Cloud is excluded, and under either reading of its terms.** The
repository has no ``LICENSE`` file — not at the root, not under ``src/`` — and
its README defers to an off-repository page stating CC BY-NC-SA 4.0. If that
statement governs, :mod:`~training.corpus.sources.yara` has already settled the
question for this project by dropping every rule whose own metadata declares a
non-commercial licence. If it does not govern, the repository is unlicensed and
:mod:`training.corpus.sources._internal_unlicensed` has settled it the other way.
Both roads end here.

**GCP is the honest hole in this source**, and it is a licensing hole rather
than an oversight. ``gcloud`` has no upstream repository whose ``LICENSE`` could
be read: the SDK ships as a versioned bundle under the Google Cloud SDK terms of
service, and the one third-party mirror looked for does not exist. AWS and Azure
command surface is therefore collected and Google's is not, which is stated here
rather than papered over. Prowler's 110 GCP checks — whose remediation field is
where the ``gcloud`` verbs actually live — and stratus's 27 GCP attack
techniques are where that gap gets closed, in the adapters named above.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import shutil
import tarfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

import yaml

from ..net import NetworkError, download, fetch
from ..source import Document, Register, Side, SourceError, SourceSpec, normalise

try:  # libyaml when the wheel has it; 5,485 small documents parse either way
    from yaml import CSafeLoader as _Loader  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - depends on the local PyYAML build
    from yaml import SafeLoader as _Loader  # type: ignore[assignment]


#: PyPI's JSON API. One request per package returns the current version, the
#: files published for it, and the digest of each — which is the whole reason
#: the fetch goes through here rather than straight at a download URL.
_PYPI_JSON = "https://pypi.org/pypi/{package}/json"

#: The response carries every release this project has ever made, so it is not
#: small — awscli's is a third of a megabyte — but it is nowhere near
#: :data:`~training.corpus.net.MAX_FETCH_BYTES`. A ceiling is passed anyway: an
#: index that suddenly answers with hundreds of megabytes is a fact worth
#: failing on rather than buffering.
_METADATA_MAX_BYTES = 8 * 1024 * 1024

#: Written LAST, after both upstreams are complete and in place. An interrupted
#: fetch therefore re-fetches on the next run instead of being mistaken for a
#: finished one, which is the failure that turns "idempotent" into "silently
#: trains on half a source".
_MARKER = ".fetched.json"

#: A ceiling on one archive member, checked against ``member.size`` before
#: extraction. The tarball's own size is no evidence about a member's: NUL bytes
#: gzip at roughly 1000:1, so a single 8 GiB member leaves the archive looking
#: entirely ordinary on the wire and then asks for 8 GiB of RAM. On this machine
#: that is a MemoryError that kills the build or an OOM kill that picks the
#: training run instead. Sound rather than trusting, because tarfile bounds the
#: reader it hands back to exactly the declared length. The largest file taken
#: here is a 258 KB help module, so 8 MB is already absurdly generous.
_MAX_MEMBER_BYTES = 8 * 1024 * 1024

#: Below this a rendering is a command name with a sentence under it — an Azure
#: command group blurb, or a stub example file. Real documents start around 300
#: characters; the median AWS example is 931 and the median Azure command 329.
_MIN_CHARS = 180


@dataclass(frozen=True, slots=True)
class _Upstream:
    """One published source distribution and the slice of it that is collected."""

    key: str
    #: PyPI project name. The sdist of this project is what gets downloaded.
    package: str
    #: Where the code lives, for the provenance table. Not where it is fetched
    #: from — that is the index — and the difference is worth stating.
    repo: str
    #: Path prefix inside the sdist, relative to its single root directory.
    keep_prefix: str
    #: What to take under that prefix, matched against the file NAME: an
    #: extension (``.rst``) or an exact name (``_help.py``). Exact rather than
    #: "ends with", because the loose form also dragged in azure-cli's two
    #: ``custom_help.py`` modules — never read, since the walker asks for the
    #: exact name, but sitting in the cache implying they were.
    keep_names: tuple[str, ...]
    #: The distribution's own licence file, copied into the cache beside the
    #: text it covers so the declaration in SPEC can be checked against what was
    #: actually downloaded.
    licence_file: str
    #: A floor on extracted files. An upstream layout change — a renamed
    #: package directory, examples moved out of the sdist — then fails loudly at
    #: fetch time instead of arriving as a mysteriously thin build report.
    min_files: int


_AWS = _Upstream(
    key="aws",
    package="awscli",
    repo="https://github.com/aws/aws-cli",
    keep_prefix="awscli/examples/",
    keep_names=(".rst",),
    licence_file="LICENSE.txt",
    # 5,850 .rst files in awscli 1.46.1, in a 16.8 MB sdist.
    min_files=4000,
)

_AZURE = _Upstream(
    key="azure",
    package="azure-cli",
    repo="https://github.com/Azure/azure-cli",
    keep_prefix="azure/cli/command_modules/",
    keep_names=("_help.py",),
    licence_file="LICENSE.txt",
    # 75 _help.py files in azure-cli 2.90.0, in a 9.4 MB sdist.
    min_files=50,
)

_UPSTREAMS = (_AWS, _AZURE)

#: Headroom over the largest sdist observed — awscli at 16.8 MB, azure-cli at
#: 9.4 MB. Passed explicitly rather than inherited from
#: :data:`~training.corpus.net.MAX_DOWNLOAD_BYTES`: the size a source is expected
#: to be is a fact about that source, and a package that grows fourfold overnight
#: should stop the build rather than land in the cache.
_DOWNLOAD_MAX_BYTES = 64 * 1024 * 1024

#: Microsoft's header, required in the first lines of every collected help
#: module. See the licensing paragraph in the module docstring: a permissively
#: licensed repository is free to vendor files that are not, and this is the
#: structural version of checking rather than assuming.
_MIT_HEADER = "Licensed under the MIT License"
_MIT_HEADER_LINES = 10


# ---------------------------------------------------------------------------
# fetch
# ---------------------------------------------------------------------------

def _sdist(package: str) -> dict[str, Any]:
    """Resolve ``package`` to its current source distribution on PyPI.

    Returns the index's own record for the file — url, filename, version and
    digests — so the caller can verify what arrives against what was promised.
    """
    url = _PYPI_JSON.format(package=package)
    try:
        payload = json.loads(
            fetch(url, timeout=60, max_bytes=_METADATA_MAX_BYTES).decode("utf-8")
        )
    except NetworkError as exc:
        raise SourceError(f"cloudsec: {package}: {exc}") from None
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceError(f"cloudsec: {package}: {url} is not JSON: {exc}") from None

    version = (payload.get("info") or {}).get("version", "")
    for entry in payload.get("urls") or ():
        if entry.get("packagetype") != "sdist":
            continue
        href = entry.get("url", "")
        digest = (entry.get("digests") or {}).get("sha256", "")
        if not href or not digest:
            continue
        return {
            "url": href,
            "filename": entry.get("filename", ""),
            "version": version,
            "sha256": digest,
        }
    raise SourceError(
        f"cloudsec: {package} {version or '(unknown version)'} publishes no source "
        f"distribution with a sha256 at {url}. Wheels are not used here: the "
        "examples and help modules this adapter reads are package data that a "
        "wheel is free to leave out."
    )


def _verify(archive: Path, expected: str) -> None:
    """Refuse an archive whose sha256 is not the one the index published.

    Read a megabyte at a time rather than ``read_bytes()``: the point of the
    member ceiling further down is that this adapter never asks for one
    allocation the size of a file it did not write, and the door is a strange
    place to make an exception.
    """
    digest = hashlib.sha256()
    try:
        with archive.open("rb") as handle:
            while chunk := handle.read(1 << 20):
                digest.update(chunk)
    except OSError as exc:
        raise SourceError(f"cloudsec: could not read {archive}: {exc}") from None
    actual = digest.hexdigest()
    if actual != expected:
        raise SourceError(
            f"cloudsec: {archive.name} hashes to {actual} but PyPI publishes "
            f"{expected}. Something other than the file the index describes "
            "arrived; it is not unpacked and not cached."
        )


def _extract(archive: Path, upstream: _Upstream, staging: Path) -> int:
    """Unpack the wanted slice of ``archive`` into ``staging``; return the count.

    Members are copied out by hand rather than through ``TarFile.extractall``.
    The archive is trusted in practice, but a tar member name is
    attacker-controlled data in principle — absolute paths, ``..`` segments and
    symlinks are all expressible — and the cheap defence is never to hand those
    names to the filesystem unchecked. Only regular files are written, and every
    destination is proved to resolve inside ``staging`` first.
    """
    staging.mkdir(parents=True, exist_ok=True)
    resolved = staging.resolve()
    written = 0

    try:
        with tarfile.open(archive, mode="r:gz") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                if member.size > _MAX_MEMBER_BYTES:
                    continue
                parts = Path(member.name).parts
                if len(parts) < 2:
                    continue
                # Drop the sdist's single root directory ("awscli-1.46.1/").
                relative = Path(*parts[1:])
                if relative.is_absolute() or ".." in relative.parts:
                    continue
                posix = relative.as_posix()
                name = relative.name
                keep = (
                    posix.startswith(upstream.keep_prefix)
                    and any(name.endswith(pattern) if pattern.startswith(".")
                            else name == pattern
                            for pattern in upstream.keep_names)
                ) or posix == upstream.licence_file
                if not keep:
                    continue

                target = staging / relative
                if not target.resolve().is_relative_to(resolved):
                    continue
                source = tar.extractfile(member)
                if source is None:
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                # Copied a megabyte at a time rather than read() into one
                # buffer, so peak memory is a chunk and not the file. The
                # ceiling above makes this belt and braces; the shape is here so
                # a later edit that raises the ceiling does not quietly
                # reintroduce the allocation.
                with source, target.open("wb") as handle:
                    shutil.copyfileobj(source, handle, 1 << 20)
                if posix != upstream.licence_file:
                    written += 1
    except (tarfile.TarError, OSError) as exc:
        raise SourceError(
            f"cloudsec: could not unpack {upstream.package}: {exc}"
        ) from None

    if written < upstream.min_files:
        raise SourceError(
            f"cloudsec: only {written} files matched {upstream.keep_prefix}**/"
            f"{{{','.join(upstream.keep_names)}}} in the {upstream.package} sdist "
            f"(expected >= {upstream.min_files}). The upstream layout has "
            "probably changed; fix the adapter rather than training on a "
            "fraction of the register."
        )
    return written


def _fetch_one(cache_dir: Path, upstream: _Upstream) -> dict[str, Any]:
    """Populate ``cache_dir / key`` from PyPI; return what to record about it."""
    record = _sdist(upstream.package)
    archive = cache_dir / f".{upstream.key}.sdist.tar.gz"
    staging = cache_dir / f".{upstream.key}.staging"
    target = cache_dir / upstream.key

    shutil.rmtree(staging, ignore_errors=True)
    try:
        try:
            download(record["url"], archive, timeout=300,
                     max_bytes=_DOWNLOAD_MAX_BYTES)
        except NetworkError as exc:
            raise SourceError(f"cloudsec: {upstream.package}: {exc}") from None
        _verify(archive, record["sha256"])
        files = _extract(archive, upstream, staging)

        # Swapped into place only once staging is complete, so an interrupted
        # extraction never leaves a half-populated tree behind.
        shutil.rmtree(target, ignore_errors=True)
        staging.replace(target)
    finally:
        archive.unlink(missing_ok=True)
        shutil.rmtree(staging, ignore_errors=True)

    return {
        "package": upstream.package,
        "version": record["version"],
        "filename": record["filename"],
        "url": record["url"],
        "sha256": record["sha256"],
        "repo": upstream.repo,
        "files": files,
        "licence_cached": (target / upstream.licence_file).is_file(),
    }


def _fetch(cache_dir: Path) -> Path:
    """Populate ``cache_dir`` with both upstreams; return it.

    Idempotent and network-free on re-run: the completion marker is written only
    after both trees are in place, and the build runs often.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    marker = cache_dir / _MARKER
    if marker.is_file() and all((cache_dir / u.key).is_dir() for u in _UPSTREAMS):
        return cache_dir

    fetched = {u.key: _fetch_one(cache_dir, u) for u in _UPSTREAMS}

    # Last, and only now.
    marker.write_text(
        json.dumps(
            {
                "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "upstreams": fetched,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return cache_dir


# ---------------------------------------------------------------------------
# AWS CLI examples
# ---------------------------------------------------------------------------

def aws_command(relative: Path) -> tuple[str, str]:
    """Turn ``iam/list-attached-role-policies.rst`` into ``("aws iam …", "")``.

    Kept a pure function so the path-to-command mapping is testable without a
    download. Three shapes exist upstream and all three are named rather than
    dropped:

    * ``ec2/wait/vpc-exists.rst`` — a nested subcommand, so every path segment
      is part of the command.
    * ``cloudformation/_package_description.rst`` — a leading underscore marks
      prose attached to a command rather than an example *of* one. The stem
      still says which command (``package``), so it is recovered and the
      document is labelled instead of being thrown away.
    * ``global_options.rst`` — no service at all; it documents ``--profile``,
      ``--region`` and ``--output``, which are the flags every other example in
      this source silently assumes.
    """
    parts = list(relative.parts)
    parts[-1] = relative.stem
    label = ""

    stem = parts[-1]
    if stem.startswith("_"):
        inner = stem.strip("_")
        parts.pop()
        if inner.endswith("description"):
            sub = inner[: -len("description")].strip("_")
            label = "command description"
            if sub:
                parts.append(sub)
        else:
            label = inner.replace("_", " ")

    if not parts:
        # Only reachable from a file named "_something.rst" directly under
        # examples/, which does not exist today; naming it "aws" is still true.
        return "aws", label
    if len(parts) == 1 and relative.parent == Path("."):
        return "aws", parts[0].replace("_", " ")
    return "aws " + " ".join(parts), label


def render_aws_example(raw: str, command: str, label: str = "") -> str:
    """Header plus the upstream body, unmodified.

    The body is not demarkupped, reflowed or re-fenced. See the module docstring
    under "The body is kept verbatim": in this source an asterisk is usually an
    IAM wildcard, and a corpus that teaches a model to judge policies must not
    be built by a regex that can rewrite one.
    """
    head = command if not label else f"{command}  ({label})"
    return normalise(f"{head}\n\n{raw}")


def _aws_documents(root: Path) -> Iterator[Document]:
    base = root / "awscli" / "examples"
    if not base.is_dir():
        raise SourceError(
            f"cloudsec: no awscli/examples/ under {root}; re-fetch (delete "
            f"{_MARKER} in the cache directory)"
        )

    # os.walk with followlinks=False, never rglob: a source in this package once
    # followed a symlink into the corpus cache and pulled 180 MB of corpus back
    # in as training data. Symlinked directories are pruned and symlinked files
    # skipped, so neither a link in the archive nor one made later in the cache
    # can widen what is read.
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        dirnames[:] = sorted(
            d for d in dirnames if not Path(dirpath, d).is_symlink()
        )
        for filename in sorted(filenames):
            if not filename.endswith(".rst"):
                continue
            file = Path(dirpath, filename)
            if file.is_symlink():
                continue
            try:
                raw = file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            relative = file.relative_to(base)
            command, label = aws_command(relative)
            text = render_aws_example(raw, command, label)
            if len(text) < _MIN_CHARS:
                continue
            yield Document(
                text=text,
                source="cloudsec",
                register=Register.SHELL,
                side=Side.NEUTRAL,
                ident=f"aws/{relative.as_posix()}",
            )


# ---------------------------------------------------------------------------
# Azure CLI help
# ---------------------------------------------------------------------------

#: The three spellings the help key takes upstream. ``examples`` is the documented
#: one; ``example`` appears six times and ``exmaples`` once, and both of those are
#: worked invocations that ``az --help`` itself never prints. A typo upstream is a
#: bad reason to drop an example here.
_EXAMPLE_KEYS = ("examples", "example", "exmaples")


def _indent(text: str, width: int) -> str:
    """Indent every non-blank line by ``width`` spaces, relative shape intact.

    Blank lines are left blank rather than filled with spaces, because
    :func:`~training.corpus.source.normalise` strips trailing whitespace per line
    anyway and a line of eight spaces would simply become an empty one with the
    token count already paid.
    """
    pad = " " * width
    return "\n".join(pad + line if line.strip() else "" for line in text.split("\n"))


def render_azure_help(command: str, entry: dict[str, Any]) -> str:
    """Render one ``helps[...]`` entry the way ``az <command> --help`` reads.

    Pure function over the parsed YAML, so the rendering is testable without a
    download. Argument documentation is kept — a flag's name beside what it does
    is the mapping an agent filling parameters needs — and so is
    ``populator-commands``, which is upstream's name for "the command that tells
    you what to put here" and is therefore the densest thing in the file.
    """
    lines = [f"az {command}", ""]

    summary = str(entry.get("short-summary") or "").strip()
    if summary:
        lines += [summary, ""]
    long_summary = str(entry.get("long-summary") or "").strip()
    if long_summary:
        lines += [long_summary, ""]

    parameters = entry.get("parameters")
    if isinstance(parameters, list):
        rendered: list[str] = []
        for parameter in parameters:
            if not isinstance(parameter, dict):
                continue
            name = str(parameter.get("name") or "").strip()
            if not name:
                continue
            rendered.append(_indent(name, 4))
            for key in ("short-summary", "long-summary"):
                body = str(parameter.get(key) or "").strip()
                if body:
                    rendered.append(_indent(body, 8))
            populators = parameter.get("populator-commands")
            if isinstance(populators, list):
                for populator in populators:
                    populator = str(populator or "").strip()
                    if populator:
                        rendered.append(_indent(populator, 8))
            rendered.append("")
        if rendered:
            lines += ["Arguments:", ""] + rendered

    examples: list[str] = []
    for key in _EXAMPLE_KEYS:
        found = entry.get(key)
        if isinstance(found, list):
            for example in found:
                if not isinstance(example, dict):
                    continue
                title = str(example.get("name") or "").strip()
                body = str(example.get("text") or "").rstrip()
                if not body.strip():
                    continue
                if title:
                    examples.append(_indent(title, 4))
                examples.append(_indent(body, 8))
                examples.append("")
    if examples:
        lines += ["Examples:", ""] + examples

    return normalise("\n".join(lines))


def _help_entries(path: Path) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield ``(command, parsed)`` for every ``helps[...] = "..."`` in one module.

    The file is parsed, never imported and never executed — it is upstream code
    that happens to hold data, and a corpus adapter is the last place to blur
    that line. Assignments whose value is not a plain string literal are skipped:
    36 of the 5,521 upstream are f-strings or ``.format()`` calls whose text
    cannot be recovered without running the module, and 36 missing command pages
    is a far better outcome than importing Azure CLI to get them.
    """
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return

    head = "".join(raw.splitlines(keepends=True)[:_MIT_HEADER_LINES])
    if _MIT_HEADER not in head:
        # Not a licensing judgement call made here at read time: the header is
        # the evidence for the MIT claim in SPEC, and a file that does not carry
        # it is not covered by that claim. See the module docstring.
        return

    try:
        tree = ast.parse(raw, filename=str(path))
    except SyntaxError:
        return

    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Subscript):
            continue
        if not (isinstance(target.value, ast.Name) and target.value.id == "helps"):
            continue
        if not (isinstance(target.slice, ast.Constant)
                and isinstance(target.slice.value, str)):
            continue
        if not (isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)):
            continue
        try:
            parsed = yaml.load(node.value.value, Loader=_Loader)
        except yaml.YAMLError:
            continue
        if isinstance(parsed, dict):
            yield target.slice.value, parsed


def _azure_documents(root: Path) -> Iterator[Document]:
    base = root / "azure" / "cli" / "command_modules"
    if not base.is_dir():
        raise SourceError(
            f"cloudsec: no azure/cli/command_modules/ under {root}; re-fetch "
            f"(delete {_MARKER} in the cache directory)"
        )

    # 123 command keys are declared more than once upstream. Both renderings of
    # a pair are near-identical and differ by a sentence, which is exactly the
    # near-duplicate that whole-text fingerprinting in build.py cannot see — and
    # duplicated text in a corpus this size is memorised rather than learned. So
    # the winner is chosen here, by where the declaration lives, and the counts
    # are the three shapes that actually occur:
    #
    #   70  generated/_help.py vs manual/_help.py   (billing, vm,
    #       marketplaceordering) — codegen'd help and the hand-written override
    #       of it. manual wins, which is what `az --help` prints.
    #   43  monitor/_help.py vs monitor/_legacy/_help.py — a superseded copy
    #       kept beside the live one. Ranking _legacy with generated is what
    #       makes that outcome a decision rather than a side effect of the walk
    #       order happening to reach the parent directory first.
    #   10  the same file declaring the same key twice. Python's own dict
    #       assignment makes the LAST one win, so it wins here too; the
    #       equal-rank tie below is broken in favour of the later declaration
    #       only when both came from the same file, and otherwise in favour of
    #       the first, which keeps the result independent of walk order.
    collected: dict[str, tuple[int, str, str]] = {}

    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        dirnames[:] = sorted(
            d for d in dirnames if not Path(dirpath, d).is_symlink()
        )
        for filename in sorted(filenames):
            if filename != "_help.py":
                continue
            file = Path(dirpath, filename)
            if file.is_symlink():
                continue
            relative = file.relative_to(base)
            origin = relative.as_posix()
            rank = 2 if "manual" in relative.parts else (
                0 if {"generated", "_legacy"} & set(relative.parts) else 1
            )
            for command, entry in _help_entries(file):
                text = render_azure_help(command, entry)
                if len(text) < _MIN_CHARS:
                    continue
                previous = collected.get(command)
                if (previous is None
                        or rank > previous[0]
                        or (rank == previous[0] and origin == previous[2])):
                    collected[command] = (rank, text, origin)

    for command in sorted(collected):
        _, text, origin = collected[command]
        yield Document(
            text=text,
            source="cloudsec",
            register=Register.SHELL,
            side=Side.NEUTRAL,
            ident=f"azure/{origin}::{command}",
        )


def _documents(path: Path) -> Iterator[Document]:
    """Yield both upstreams, AWS first, each in a stable sorted order."""
    yield from _aws_documents(path / _AWS.key)
    yield from _azure_documents(path / _AZURE.key)


SPEC = SourceSpec(
    name="cloudsec",
    license=(
        "Composite, verified per upstream from the LICENSE file inside the "
        "distribution this adapter actually downloads rather than from a badge "
        "or a README sentence, and copied into the cache beside the text it "
        "covers. awscli (PyPI sdist of aws/aws-cli): Apache-2.0, LICENSE.txt "
        "'Copyright 2012-2020 Amazon.com, Inc. or its affiliates. All Rights "
        "Reserved. Licensed under the Apache License, Version 2.0'. azure-cli "
        "(PyPI sdist of Azure/azure-cli): MIT, LICENSE.txt 'Copyright (c) "
        "Microsoft Corporation'. Azure CLI's NOTICE.txt additionally lists "
        "LGPL-2.1 third-party components (chardet, paramiko, nose); those are "
        "packages azure-cli depends on at runtime, not files collected here, "
        "and nothing from them is extracted — every _help.py taken is required "
        "to carry Microsoft's MIT header in its own first ten lines or it is "
        "skipped. Both upstreams permissive: no copyleft, no non-commercial "
        "clause, no field-of-use restriction. Each archive is verified against "
        "the sha256 PyPI publishes for it before it is unpacked, and the "
        "version and digest are recorded in the cache marker."
    ),
    url=(
        "https://github.com/aws/aws-cli and https://github.com/Azure/azure-cli "
        "(fetched as the published source distributions: "
        "https://pypi.org/project/awscli/ and https://pypi.org/project/azure-cli/)"
    ),
    register=Register.SHELL,
    side=Side.NEUTRAL,
    fetch=_fetch,
    documents=_documents,
    #: 5,850 AWS example files and 5,361 distinct Azure command keys were
    #: present at the time of writing (awscli 1.46.1, azure-cli 2.90.0), of
    #: which 5,824 and 3,540 clear the length floor — 9,364 documents and 10.2 M
    #: characters. The floor here sits well below that so ordinary churn — a
    #: service retired, a command group collapsed — does not fail a build, while
    #: a layout change that empties either upstream still does.
    expect_min_docs=7000,
    notes=(
        "The cloud control plane in the SHELL register: one document per AWS "
        "CLI example (command, prose, invocation and the JSON the API really "
        "returns, 68% of them carrying an Output:: block) and one per Azure CLI "
        "command (summary, argument documentation including "
        "populator-commands, and worked az invocations). Bodies are kept "
        "verbatim — no demarkup pass — because in this source an asterisk is "
        "usually an IAM wildcard, and normalise() preserves the horizontal "
        "whitespace that makes an indented JSON response readable as a "
        "response. Fetched as PyPI sdists, not git trees: 9.4 MB instead of 181 "
        "MB for Azure, a pinned released version, and a publisher-side sha256 "
        "to verify against. Azure's 123 doubly-declared command keys are "
        "resolved manual/ over generated/. Prowler, Stratus Red Team, Pacu and "
        "ScoutSuite were fetched and licence-checked for this slot and left "
        "out: the first three are permissively licensed but belong to other "
        "registers and sides, and build.py attributes those per spec. GCP is "
        "absent because gcloud has no verifiable open licence."
    ),
)
