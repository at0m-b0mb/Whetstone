"""Shared plumbing for the detection-as-code adapters. NOT a source.

The leading underscore is load-bearing: ``discover_sources()`` skips it, so this
module is library code for :mod:`~training.corpus.sources.wazuh`,
:mod:`~training.corpus.sources.zeek`, :mod:`~training.corpus.sources.falco` and
:mod:`~training.corpus.sources.panther` and is never itself a corpus source.

It exists for the reason :mod:`training.corpus.net` gives for existing. Four
adapters landed in one pass, all four unpack a codeload tarball and all four
have to strip third-party contact details out of upstream text. The alternative
to one copy is four, and four copies of a *redaction* routine is how one of them
quietly stops firing — which is not a hypothetical in this repository. The
corpus privacy audit found 23,535 occurrences of eleven values in a shipped
generation, and then found that the verifier written to catch that had reported
"0 leaks, exit 0" having read zero bytes. So the redaction here is one function,
tested directly, and it **proves** its own result rather than asserting it: see
:func:`scrub` and :func:`assert_scrubbed`.

Two false-positive traps are designed around, and both were measured in the
real trees rather than imagined.

**An SSH algorithm name is email-shaped.** ``hmac-sha2-512-etm@openssh.com``,
``aes256-gcm@openssh.com``, ``curve25519-sha256@libssh.org`` and
``rijndael-cbc@lysator.liu.se`` all match any reasonable address pattern. In
Wazuh's ruleset there are 717 email-shaped tokens and roughly six hundred of
them are algorithm names sitting inside sshd rules and decoders, where they are
the detection signal. A sweep that redacted them would report a six-hundred-item
privacy win and silently gut the register. Those namespaces are allowlisted by
domain in :data:`_PROTOCOL_DOMAINS`, which is a short, closed list of domains
used by protocol registries to namespace algorithm names and not to carry mail.

**``dcredit = -1`` is not an attribution line.** The first keyword sweep written
for this family matched ``credits?\\s*[:=]`` and hit 332 lines of CIS
password-quality remediation — ``minlen = 14 dcredit = -1 ucredit = -1 ocredit =
-1 lcredit = -1`` — because ``credit`` is a substring of ``dcredit``. Zeek has
the mirror-image trap: its SSL and file-analysis scripts carry signature regexes
such as ``/Copyright 1985-.*Microsoft Corp/`` and ``copyright(\\``, so anything
matching "copyright" or "author" anywhere in a line would delete pattern text.
:data:`_ATTRIBUTION` is therefore anchored at the start of a line, after
comment punctuation only, with word boundaries on every keyword — and
``test_sources_detection.py`` pins both cases.

**What is removed, and the judgement behind it.** Personal contact details go,
without exception: an address carries no detection signal and the project has
already paid for third-party addresses in a shipped corpus. Author *credits* go
too, which is the discretionary half. A named contributor to a public GPL
ruleset is published professional attribution rather than a private individual,
so this is a choice and not an obligation — the choice is that a rule is not
better understood for knowing who typed it, the upstream URL that carries the
full credit is printed in every document header, and corporate copyright lines
(``Copyright (C) 2015, Wazuh Inc.``) are kept because those *are* licence
notices. Anyone publishing a model trained on this should know the per-rule
author credits were dropped from the text and live at the cited upstream.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import tarfile
import time
from pathlib import Path
from typing import Callable, Iterable, Iterator

from ..net import NetworkError, download
from ..source import SourceError

__all__ = [
    "codeload_url", "extract", "write_marker", "marker_path",
    "scrub", "assert_scrubbed", "ScrubReport",
    "attack_ids", "dedup_key",
]

#: Written last, so its presence means "extraction finished". A half-unpacked
#: cache therefore re-fetches instead of yielding a partial corpus — the same
#: contract :mod:`~training.corpus.sources.sigma` uses.
_MARKER = ".fetched.json"


def marker_path(home: Path) -> Path:
    return home / _MARKER


def codeload_url(repo: str, ref: str, *, tag: bool = False) -> str:
    """The tarball URL for one ref of ``repo``.

    codeload rather than ``git clone``: one request, no history, no git binary,
    and nothing left behind that a later ``git pull`` could mutate underneath a
    reproducible build.
    """
    kind = "tags" if tag else "heads"
    return f"https://codeload.github.com/{repo}/tar.gz/refs/{kind}/{ref}"


def extract(
    *,
    name: str,
    url: str,
    cache_dir: Path,
    keep: Callable[[Path], bool],
    licence_files: Iterable[str],
    max_bytes: int,
    min_kept: int,
    timeout: int = 900,
) -> tuple[Path, dict[str, object]]:
    """Fetch ``url`` once, keep the members ``keep`` accepts, return the home dir.

    Members are copied out by hand rather than via ``TarFile.extractall``. The
    tarball is trusted in practice, but an archive member is attacker-controlled
    data in principle: absolute paths, ``..`` segments, symlinks and hardlinks
    are all expressible in tar. Only regular files are written and every
    destination is proved to resolve inside the staging tree first.

    The licence files named are copied to ``licenses/`` inside the cache and the
    fetch **refuses to cache anything** if none of them arrived. A declared
    licence that cannot be pointed at inside the tree it covers is a claim, not
    a reading, and this project does not train on text whose terms it has only
    been told about.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    home = cache_dir / name
    if marker_path(home).is_file():
        return home, json.loads(marker_path(home).read_text(encoding="utf-8"))

    archive = cache_dir / f".{name}.tar.gz.part"
    staging = cache_dir / f".{name}.staging"
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True)
    wanted = {f.rsplit("/", 1)[-1]: f for f in licence_files}
    found: dict[str, str] = {}
    kept = 0
    digest = "unknown"

    try:
        try:
            download(url, archive, timeout=timeout, max_bytes=max_bytes)
        except NetworkError as exc:
            raise SourceError(f"{name}: cannot fetch {url}: {exc}") from None

        # Hashing the archive costs one pass over a file already on disk and
        # buys provenance a bare branch name cannot: which snapshot of a moving
        # ref this cache actually holds.
        sha = hashlib.sha256()
        with archive.open("rb") as handle:
            while chunk := handle.read(1 << 20):
                sha.update(chunk)
        digest = sha.hexdigest()

        resolved = staging.resolve()
        try:
            with tarfile.open(archive, "r:gz") as tar:
                for member in tar:
                    if not member.isfile():
                        continue
                    parts = Path(member.name).parts
                    if len(parts) < 2:
                        continue
                    # codeload wraps everything in one root directory carrying
                    # the ref; drop it so the cache layout does not move when
                    # the branch or tag is renamed.
                    relative = Path(*parts[1:])
                    if relative.is_absolute() or ".." in relative.parts:
                        continue
                    licence_key = relative.name if relative.name in wanted else None
                    if licence_key is not None:
                        target = staging / "licenses" / relative.name
                    elif keep(relative):
                        target = staging / relative
                    else:
                        continue
                    if not target.resolve().is_relative_to(resolved):
                        raise SourceError(
                            f"{name}: archive member escapes staging: "
                            f"{member.name!r}")
                    extracted = tar.extractfile(member)
                    if extracted is None:
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with extracted, target.open("wb") as handle:
                        shutil.copyfileobj(extracted, handle)
                    if licence_key is not None:
                        found[licence_key] = relative.as_posix()
                    else:
                        kept += 1
        except (tarfile.TarError, OSError) as exc:
            raise SourceError(f"{name}: could not unpack {url}: {exc}") from exc

        if not found:
            shutil.rmtree(staging, ignore_errors=True)
            raise SourceError(
                f"{name}: none of {sorted(wanted)} were in the archive, so the "
                "declared licence cannot be checked against the tree it covers. "
                "Nothing was cached."
            )
        if kept < min_kept:
            shutil.rmtree(staging, ignore_errors=True)
            raise SourceError(
                f"{name}: only {kept} files matched the include rule (expected "
                f">= {min_kept}). The upstream layout has probably changed; fix "
                "the adapter rather than training on a fraction of the source."
            )

        shutil.rmtree(home, ignore_errors=True)
        staging.replace(home)
    finally:
        archive.unlink(missing_ok=True)
        shutil.rmtree(staging, ignore_errors=True)

    meta: dict[str, object] = {
        "url": url,
        "tarball_sha256": digest,
        "files_kept": kept,
        "licenses": found,
        "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    return home, meta


def write_marker(home: Path, meta: dict[str, object]) -> None:
    """Record provenance, last, so the marker means "extraction finished".

    Nothing from this machine goes in here. The fields are the upstream URL, the
    archive digest, counts and a UTC timestamp — no paths, no account name, no
    host identifier. A cache marker is a file somebody will eventually paste
    into an issue.
    """
    marker_path(home).write_text(json.dumps(meta, indent=2), encoding="utf-8")


# --------------------------------------------------------------------------- #
# Redaction
# --------------------------------------------------------------------------- #

#: Domains that protocol registries use to namespace algorithm and extension
#: names. A token like ``hmac-sha2-512-etm@openssh.com`` is email-shaped and is
#: not an address; in sshd rules and decoders it is the thing being detected.
#: Closed list, by domain, verified against the trees these adapters read:
#: Wazuh's ruleset carries ~600 of them and Zeek's scripts one.
_PROTOCOL_DOMAINS = frozenset({
    "openssh.com",
    "libssh.org",
    "lysator.liu.se",
    "ssh.com",
    "tartarus.org",
})

#: Domains and TLDs reserved by RFC 2606 and RFC 6761 for documentation and
#: testing. An address here is *provably* not a person's, which is why these
#: survive while ``homer.simpson@duff.com`` — fictional, but at a domain
#: somebody really owns — does not.
_RESERVED_DOMAINS = frozenset({"example.com", "example.net", "example.org"})
_RESERVED_TLDS = ("example", "invalid", "test", "localhost")

#: An address-shaped token. **Flat on purpose**: one bounded class for the local
#: part, one bounded class for the whole domain, and no nested quantifier
#: anywhere. Whether the domain is really a hostname is then decided in Python
#: by :func:`_split_address`, not by the engine.
#:
#: The obvious grammar — ``[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?(?:\.…)*
#: \.[A-Za-z]{2,24}`` — is a nested quantifier over dot-separated labels, which
#: is exponential on any ``user@a.b.c.d.e.f`` that does not end in a valid TLD.
#: There is no shortage of those in a corpus of file paths and regexes, and this
#: project has already lost seven and a half hours of a training run to one
#: adapter's catastrophic backtracking. A pattern that can only be slow is not
#: worth the two characters it saves.
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9][A-Za-z0-9.\-]{0,253}")

#: The last label of a hostname: all letters, 2 to 24 of them.
_TLD = re.compile(r"^[A-Za-z]{2,24}$")

#: Keywords that introduce an attribution. **Anchored at line start**, after at
#: most one short run of comment punctuation, with ``\b`` on every keyword, and
#: requiring a following ``:`` or ``=``.
#:
#: Every clause of that is a bug that was measured here.
#:
#: * Without ``\b`` the alternative ``credits?`` matched ``dcredit = -1`` and
#:   deleted 332 lines of CIS password-policy remediation, because ``credit`` is
#:   a substring of ``dcredit``.
#: * Without the line anchor, Zeek's signature patterns —
#:   ``/Copyright 1985-.*Microsoft Corp/`` — matched, and a detection pattern
#:   would have been silently truncated.
#: * Without the ``:``/``=`` requirement, ordinary prose mentioning an author
#:   matches.
#: * And the comment prefix is ``[-#;*/<!]{1,8}``, one bounded run, rather than
#:   the alternation ``(?:[#;*]|//|--|<!--|-)[ \t]*)*`` it started as. That
#:   version offered both ``--`` and ``-`` inside a star, so a line of
#:   ``#------------------------------------------------------------`` — which
#:   is how half the files in these upstreams open — could be partitioned
#:   Fibonacci-many ways and the search never returned. Measured: 60 dashes did
#:   not finish in 200 seconds. Two alternatives where one is a prefix of the
#:   other, under a star, over a long homogeneous run.
_ATTRIBUTION = re.compile(
    r"^[ \t]*(?:[-#;*/<!]{1,8}[ \t]*)?"
    r"\b(?:author|authors|autor|contributed\s+by|contributor|contributors|"
    r"modified\s+by|written\s+by|created\s+by|thanks\s+to|submitted\s+by|"
    r"maintainer|maintained\s+by)\b[ \t]*[:=]",
    re.IGNORECASE,
)


def _split_address(token: str) -> tuple[str, str, str] | None:
    """``token`` -> (address, domain, trailing punctuation), or None.

    The domain half of :data:`_EMAIL` is a flat character class, so a match can
    run past the address into the punctuation that follows it (``...@host.com.``
    at the end of a sentence, ``@host.com,`` in a list). Trailing dots and
    hyphens are peeled off and handed back so the caller can re-attach them, and
    the remainder is checked for the one property that makes it an address
    rather than a fragment: at least one dot, and a last label that is 2 to 24
    letters. All of that is linear in the length of the token.
    """
    trimmed = token.rstrip(".-")
    if "@" not in trimmed:
        return None
    _local, _, domain = trimmed.rpartition("@")
    labels = domain.split(".")
    if len(labels) < 2 or len(labels) > 8:
        # Two labels is the minimum for a hostname and eight is already absurd
        # for a mailbox. The ceiling matters because the domain class above is
        # flat and capped at 253 characters, so a very long dotted token can be
        # truncated mid-label into something that *ends* like a hostname:
        # ``user@abcdefgh.abcdefgh.…`` thirty labels deep would otherwise have
        # its first 253 characters rewritten and the tail left dangling. That
        # is over-redaction of something that is not an address, which mangles
        # real content; refusing it leaves the token alone.
        return None
    if not all(1 <= len(label) <= 63 for label in labels):
        return None
    if not _TLD.match(labels[-1]):
        return None
    return trimmed, domain.lower(), token[len(trimmed):]


class ScrubReport:
    """What :func:`scrub` removed, counted by kind rather than by value.

    Never holds a redacted value. The privacy audit's own write-up leaked,
    because reporting what you found means writing it down somewhere; the way
    out is that the report records ``kind + length + sha256[:8]`` and nothing
    else, which is enough to tell two leaks apart and not enough to be one.
    """

    __slots__ = ("addresses", "attributions", "samples")

    def __init__(self) -> None:
        self.addresses = 0
        self.attributions = 0
        #: ``(kind, length, sha256[:8])`` for at most a handful, for the log.
        self.samples: list[tuple[str, int, str]] = []

    def note(self, kind: str, value: str) -> None:
        self.addresses += kind == "address"
        self.attributions += kind == "attribution"
        if len(self.samples) < 6:
            fp = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
            self.samples.append((kind, len(value), fp))

    def __bool__(self) -> bool:
        return bool(self.addresses or self.attributions)

    def line(self, source: str) -> str:
        shapes = " ".join(f"{k}/len{n}/{fp}" for k, n, fp in self.samples)
        return (f"   {source}: redacted {self.addresses} address(es) and "
                f"{self.attributions} attribution line(s)"
                + (f"; shapes {shapes}" if shapes else ""))


def _allowed(domain: str) -> bool:
    """True for a domain that is email-shaped but provably not a mailbox host.

    Protocol algorithm namespaces, and the documentation domains RFC 2606 and
    RFC 6761 reserve. Everything else is treated as somebody's address even if
    it looks fictional, because "looks fictional" is not a property code can
    check and ``duff.com`` is a real registration.
    """
    if domain in _PROTOCOL_DOMAINS or domain in _RESERVED_DOMAINS:
        return True
    return domain.rsplit(".", 1)[-1] in _RESERVED_TLDS


def scrub(text: str, report: ScrubReport | None = None) -> str:
    """Remove third-party contact details and author credits from ``text``.

    Addresses are replaced rather than deleted, with a distinct placeholder per
    distinct address *within this document*, because in a mail-log sample the
    fact that sender and recipient differ is part of the record's shape while
    who they were is not. Attribution lines are deleted whole: a line that
    exists only to say who wrote the rule has nothing else on it.

    An empty line is left where an attribution line was removed only if that
    would not weld two paragraphs together — the same sentence-welding mistake
    :class:`~training.corpus.boilerplate.BoilerplateFilter` had to be fixed for.
    """
    report = report if report is not None else ScrubReport()

    kept_lines: list[str] = []
    removed_run = False
    for line in text.split("\n"):
        if _ATTRIBUTION.search(line):
            report.note("attribution", line.strip())
            removed_run = True
            continue
        # A run of removed lines collapses to one blank rather than vanishing,
        # so an attribution excised from between two sentences does not weld
        # them together. Copied in behaviour from
        # :meth:`~training.corpus.boilerplate.BoilerplateFilter.strip`, which
        # had to be fixed for exactly this; ``normalise`` caps the blank run
        # afterwards, so nothing accumulates.
        if removed_run and kept_lines and kept_lines[-1].strip():
            kept_lines.append("")
        removed_run = False
        kept_lines.append(line)
    text = "\n".join(kept_lines)

    seen: dict[str, str] = {}

    def _one(match: re.Match[str]) -> str:
        token = match.group(0)
        split = _split_address(token)
        if split is None:
            return token
        address, domain, tail = split
        if _allowed(domain):
            return token
        if address not in seen:
            seen[address] = f"user{len(seen) + 1}@example.invalid"
            report.note("address", address)
        return seen[address] + tail

    return _EMAIL.sub(_one, text)


def assert_scrubbed(source: str, ident: str, text: str) -> None:
    """Prove the strip, rather than trusting that it ran.

    Called on every document on the way out of every adapter in this family. It
    is expected to be a no-op forever, and that is exactly why it is here: the
    alternative is an argument that no rendering step can reintroduce an address
    after :func:`scrub`, and an invariant resting on an argument about a
    transform somebody will add later is not an invariant.

    The failure message names the **form** — kind, length, digest prefix — and
    never the value, for the reason :class:`ScrubReport` gives.
    """
    for match in _EMAIL.finditer(text):
        split = _split_address(match.group(0))
        if split is None:
            continue
        address, domain, _tail = split
        if _allowed(domain):
            continue
        fp = hashlib.sha256(address.encode("utf-8")).hexdigest()[:8]
        raise SourceError(
            f"{source}: an unredacted address survived into {ident!r} "
            f"(address/len{len(address)}/{fp}). scrub() ran before rendering or "
            "did not run at all; fix the adapter rather than the assertion."
        )
    for line in text.split("\n"):
        if _ATTRIBUTION.search(line):
            fp = hashlib.sha256(line.strip().encode("utf-8")).hexdigest()[:8]
            raise SourceError(
                f"{source}: an attribution line survived into {ident!r} "
                f"(attribution/len{len(line.strip())}/{fp})"
            )


# --------------------------------------------------------------------------- #
# Small shared readers
# --------------------------------------------------------------------------- #

#: ``T1059``, ``T1059.001``. Written back in the form the world writes it so the
#: identifier co-occurs with the behaviour it names — the measurement this
#: corpus was rebuilt around (``T1547.001`` beside "Registry Run Keys" moved a
#: sample from -45% to +13% against gpt2).
_TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def attack_ids(*blobs: object) -> list[str]:
    """Every ATT&CK technique id in ``blobs``, de-duplicated, order preserved."""
    out: list[str] = []
    for blob in blobs:
        if blob is None:
            continue
        for found in _TECHNIQUE.findall(str(blob)):
            if found not in out:
                out.append(found)
    return out


def dedup_key(*parts: object) -> str:
    """A whitespace- and case-insensitive digest over ``parts``.

    Used inside an adapter rather than relying on ``build.py``'s corpus-wide
    document fingerprint, because a rendered document carries its own policy
    name in the header: two byte-identical CIS checks from ``cis_rhel9`` and
    ``cis_alma_linux_10`` produce two different documents and the corpus-wide
    dedup never sees them. Measured on Wazuh's SCA tree: 11,352 checks collapse
    to 6,039, a 46.8% duplicate rate, with one check appearing sixteen times.
    """
    blob = "\x1f".join("" if p is None else str(p) for p in parts)
    return hashlib.sha256(
        re.sub(r"\s+", "", blob).casefold().encode("utf-8")
    ).hexdigest()[:32]


def walk_files(root: Path, suffixes: tuple[str, ...]) -> Iterator[Path]:
    """Every file under ``root`` with one of ``suffixes``, in sorted order.

    ``os.walk(followlinks=False)`` and never ``rglob``. ``Path.rglob`` follows
    directory symlinks, and in this repository that is not a theoretical
    difference: ``ownrepos`` once followed the repo's own ``data`` symlink into
    the external volume and pulled the corpus cache back in as PROSE. The
    corpus ate itself and only the balance report noticed.
    """
    import os

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for filename in sorted(filenames):
            if filename.endswith(suffixes):
                path = Path(dirpath) / filename
                if path.is_file() and not path.is_symlink():
                    yield path
