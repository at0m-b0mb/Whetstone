"""SigmaHQ detection rules — the DETECTION register, blue side.

Sigma is the closest thing the industry has to a lingua franca for detection
logic, and that is exactly why it belongs in this corpus. Three thousand rules
written to one schema give the tokenizer massed, consistent exposure to the
vocabulary a defender actually types: ``logsource`` categories, ``EventID: 4688``,
Windows log field names (``ParentImage``, ``TargetObject``, ``CommandLine``),
the pipe-modifier syntax (``Image|endswith``, ``CommandLine|contains|all``), and
condition expressions (``all of selection_* and not 1 of filter_*``). None of
that is prose about detection; it *is* detection, and the surface form is the
signal.

It is also the register where the first tokenizer attempt was blindest. That
corpus was Python, C and Markdown, so a rule body was tokenised as if it were
English with punctuation accidents. Every rule here is a document whose shape
the model will meet again the moment it is asked to read or write a detection.

**Licence.** The rules are released under the Detection Rule License (DRL) 1.1
— not MIT. The repository's own LICENSE file distinguishes three things: the
Sigma *specification* and logo are public domain, while "the rules contained in
the SigmaHQ repository are released under the Detection Rule License (DRL)
1.1". Only the rules are collected here, so DRL 1.1 is the licence that is
declared, verbatim from upstream rather than guessed from the repo's most
visible badge.

**Indentation is the document.** These documents are stored as the raw YAML,
passed through :func:`~training.corpus.source.normalise` as the contract
requires — and that helper preserves horizontal whitespace, which for this
source is the difference between a corpus and a pile of lines. A Sigma rule
encodes its structure entirely in indentation depth: ``selection:`` at one
level and ``EventID:`` at two are not the same token sequence, and a cleaner
that collapsed space runs would flatten both to one space and make rule nesting
unrecoverable. Line structure, key order, quoting, backslash paths, modifier
syntax and nesting depth all survive intact. Nothing is worked around privately
here — a private cleaner in one source is how a corpus stops being comparable
across sources — so if that guarantee ever changes in ``normalise``, this
register is the first place it will show up as damage.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import ssl
import tarfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Iterator

import yaml

from ..source import Document, Register, Side, SourceError, SourceSpec, normalise

try:  # libyaml when the wheel has it: ~5x faster over three thousand files
    from yaml import CSafeLoader as _Loader  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - depends on the local PyYAML build
    from yaml import SafeLoader as _Loader  # type: ignore[assignment]

#: A codeload tarball instead of ``git clone``: one 9 MB request, no history,
#: no git binary, and nothing left behind that a later ``git pull`` could
#: mutate underneath a reproducible build.
_REPO = "SigmaHQ/sigma"
_REF = "master"
_TARBALL_URL = f"https://codeload.github.com/{_REPO}/tar.gz/refs/heads/{_REF}"

#: Only the main ``rules/`` tree. The repository also ships
#: ``rules-emerging-threats/``, ``rules-threat-hunting/``, ``rules-compliance/``,
#: ``rules-dfir/``, ``rules-placeholder/``, ``deprecated/`` and ``unsupported/``
#: under the same licence. They are excluded because the main tree is the
#: curated, production-quality corpus; the emerging-threats tree in particular
#: is dense with near-duplicate rules for one campaign, and duplicated text in a
#: small corpus is worse than absent text. Widening the source is one constant.
_ARCHIVE_SUBDIR = "rules"

#: Written last, so its presence means "extraction finished". A half-unpacked
#: cache therefore re-fetches instead of silently yielding a partial corpus.
_MARKER = ".fetched.json"

#: Upstream had 3144 rule files when this adapter was written. A floor well
#: below that catches a layout change (a renamed directory, a moved tree)
#: loudly at fetch time rather than as a mysteriously thin build report.
_MIN_EXTRACTED = 1000

#: No real Sigma rule is this short; the guard exists so a stub or a truncated
#: file becomes a skip rather than a Document constructor raising mid-build.
_MIN_CHARS = 120

_TIMEOUT = 120
_USER_AGENT = "whetstone-corpus/1.0 (+https://github.com/SigmaHQ/sigma)"

#: CA bundles to fall back on, in order, when OpenSSL's own default store is
#: empty. macOS ships the first; Homebrew's OpenSSL the second; Linux distros
#: the rest.
_CA_BUNDLES = (
    "/etc/ssl/cert.pem",
    "/opt/homebrew/etc/openssl@3/cert.pem",
    "/usr/local/etc/openssl@3/cert.pem",
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
)


def _ssl_context() -> ssl.SSLContext:
    """A verifying TLS context that also works on a python.org macOS build.

    The framework Python from python.org points OpenSSL at
    ``…/Python.framework/Versions/3.x/etc/openssl/cert.pem``, which does not
    exist until someone runs "Install Certificates.command". On a machine where
    nobody has, :func:`ssl.create_default_context` produces a context with zero
    trust anchors and *every* HTTPS fetch dies with CERTIFICATE_VERIFY_FAILED —
    which is exactly what happened here on the first run, while ``curl`` to the
    same URL worked because it reads the system store.

    So: use certifi's bundle when it happens to be importable, otherwise the
    first CA bundle the OS actually ships, otherwise OpenSSL's default. certifi
    is a soft preference, never a requirement — the fallbacks are stdlib-only.
    Verification is never turned off; an unverifiable download of code the model
    will be trained on is not worth having.
    """
    try:
        import certifi  # noqa: PLC0415 - optional, probed at call time
    except ImportError:
        pass
    else:
        return ssl.create_default_context(cafile=certifi.where())

    for bundle in _CA_BUNDLES:
        if Path(bundle).is_file():
            return ssl.create_default_context(cafile=bundle)
    return ssl.create_default_context()


def _download(url: str, dest: Path) -> str:
    """Stream ``url`` to ``dest``, returning the sha256 of what arrived.

    Hashing during the write costs nothing and buys provenance: the marker file
    records which snapshot of a moving branch this cache actually contains,
    which a bare "master" reference cannot tell you afterwards.
    """
    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    digest = hashlib.sha256()
    try:
        with urllib.request.urlopen(
            request, timeout=_TIMEOUT, context=_ssl_context()
        ) as response:
            with dest.open("wb") as handle:
                while chunk := response.read(1 << 20):
                    digest.update(chunk)
                    handle.write(chunk)
    except (urllib.error.URLError, OSError) as exc:
        raise SourceError(f"sigma: download failed from {url}: {exc}") from exc
    return digest.hexdigest()


def _extract_rules(archive: Path, staging: Path) -> int:
    """Unpack only ``rules/**/*.yml`` (plus LICENSE) into ``staging``.

    Members are copied out by hand rather than via ``TarFile.extractall``. The
    tarball is trusted in practice, but an archive member is attacker-controlled
    data in principle: absolute paths, ``..`` segments and symlinks are all
    expressible in tar, and the cheap defence is to never hand the archive's own
    names to the filesystem unchecked. Only regular files are written, and every
    destination is proved to resolve inside ``staging`` first.
    """
    staging.mkdir(parents=True, exist_ok=True)
    resolved_staging = staging.resolve()
    written = 0

    try:
        with tarfile.open(archive, mode="r:gz") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                parts = Path(member.name).parts
                if len(parts) < 2:
                    continue
                # Drop the archive's single root directory ("sigma-master/").
                relative = Path(*parts[1:])
                if relative.is_absolute() or ".." in relative.parts:
                    continue
                keep = (
                    relative.parts[0] == _ARCHIVE_SUBDIR
                    and relative.suffix == ".yml"
                ) or relative.as_posix() == "LICENSE"
                if not keep:
                    continue

                target = staging / relative
                if not target.resolve().is_relative_to(resolved_staging):
                    continue
                source = tar.extractfile(member)
                if source is None:
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with source, target.open("wb") as handle:
                    shutil.copyfileobj(source, handle)
                if relative.suffix == ".yml":
                    written += 1
    except (tarfile.TarError, OSError) as exc:
        raise SourceError(f"sigma: could not unpack {archive}: {exc}") from exc

    if written < _MIN_EXTRACTED:
        raise SourceError(
            f"sigma: only {written} rule files found under {_ARCHIVE_SUBDIR}/ in "
            f"{_TARBALL_URL} (expected >= {_MIN_EXTRACTED}). The upstream layout "
            "has probably changed; fix the adapter rather than training on a "
            "tenth of the detection register."
        )
    return written


def _fetch(cache_dir: Path) -> Path:
    """Populate ``cache_dir`` with the Sigma ``rules/`` tree; return that tree.

    Idempotent and network-free on re-run: the completion marker is written only
    after a full extraction, so a populated cache short-circuits immediately.
    The build runs often and this source is 9 MB over the wire.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    rules_dir = cache_dir / _ARCHIVE_SUBDIR
    marker = cache_dir / _MARKER
    if marker.is_file() and rules_dir.is_dir():
        return rules_dir

    archive = cache_dir / ".sigma.tar.gz.part"
    staging = cache_dir / ".staging"
    shutil.rmtree(staging, ignore_errors=True)
    try:
        sha256 = _download(_TARBALL_URL, archive)
        written = _extract_rules(archive, staging)

        # Swap into place only once the staging tree is complete, so an
        # interrupted fetch never leaves a half-populated rules/ directory that
        # a later run would mistake for a finished one.
        shutil.rmtree(rules_dir, ignore_errors=True)
        (staging / _ARCHIVE_SUBDIR).replace(rules_dir)
        license_file = staging / "LICENSE"
        if license_file.is_file():
            license_file.replace(cache_dir / "LICENSE")
        marker.write_text(
            json.dumps(
                {
                    "url": _TARBALL_URL,
                    "repo": _REPO,
                    "ref": _REF,
                    "tarball_sha256": sha256,
                    "rule_files": written,
                    "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    finally:
        archive.unlink(missing_ok=True)
        shutil.rmtree(staging, ignore_errors=True)
    return rules_dir


def _is_sigma_rule(raw: str) -> bool:
    """True if the YAML really is a rule, not a template, index or fragment.

    Parsed with ``load_all`` because the Sigma specification allows a file to
    hold several documents joined by an ``action: global`` header. No file in
    the current ``rules/`` tree uses that form, but a parser that assumes one
    document per file would silently drop those rules the day one does.
    """
    try:
        parsed = list(yaml.load_all(raw, Loader=_Loader))
    except yaml.YAMLError:
        return False
    for document in parsed:
        if not isinstance(document, dict):
            continue
        keys = document.keys()
        if "detection" in keys or "correlation" in keys:
            return True
        if "logsource" in keys and "title" in keys:
            return True
    return False


def _documents(path: Path) -> Iterator[Document]:
    """Yield one Document per rule file, in a stable sorted order.

    Accepts either the ``rules/`` directory that :func:`_fetch` returns or the
    cache directory above it, so a caller that passes the cache root instead of
    the fetch result still works.
    """
    root = path / _ARCHIVE_SUBDIR if (path / _ARCHIVE_SUBDIR).is_dir() else path
    base = root.parent

    for file in sorted(root.rglob("*.yml")):
        if not file.is_file():
            continue
        try:
            raw = file.read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if not _is_sigma_rule(raw):
            continue
        text = normalise(raw)
        if len(text) < _MIN_CHARS:
            continue
        yield Document(
            text=text,
            source="sigma",
            register=Register.DETECTION,
            side=Side.BLUE,
            # Repo-relative path: unique, stable across fetches, and readable in
            # a build report ("rules/windows/process_creation/...").
            ident=file.relative_to(base).as_posix(),
        )


SPEC = SourceSpec(
    name="sigma",
    license="DRL-1.1 (Detection Rule License 1.1) — "
            "https://github.com/SigmaHQ/Detection-Rule-License",
    url="https://github.com/SigmaHQ/sigma",
    register=Register.DETECTION,
    side=Side.BLUE,
    fetch=_fetch,
    documents=_documents,
    #: 3144 rule files were present upstream at the time of writing; rules are
    #: also retired into deprecated/, so the floor sits below the observed count
    #: rather than at it.
    expect_min_docs=2800,
    notes=("The main rules/ tree only (emerging-threats, threat-hunting, "
           "compliance, dfir, placeholder, deprecated and unsupported are left "
           "out). Raw YAML is kept as the document text: logsource blocks, "
           "EventIDs, Windows field names, pipe modifiers and condition "
           "expressions are the point, and normalise() preserves the "
           "indentation that carries a rule's nesting depth."),
)
