"""The one source of SSL contexts and HTTP fetches for the corpus.

This module exists because the same bug was solved three times in one afternoon.
Python installed from python.org on macOS ships an OpenSSL whose default CA file
is simply absent — ``ssl.get_default_verify_paths().cafile`` is ``None`` until
somebody runs ``Install Certificates.command`` — so ``urllib.urlopen`` dies with
``CERTIFICATE_VERIFY_FAILED`` against a perfectly valid certificate on a machine
where ``curl`` works fine, because curl uses the system keychain instead.

Two corpus adapters hit that independently and each grew its own ``_ssl_context``
helper with its own list of candidate CA bundle paths. A third was about to.
Three copies of security-critical trust code is how one of them quietly drifts
into ``verify_mode = CERT_NONE`` during a late-night debugging session, so they
collapse to here.

**Verification is never disabled.** Not behind a flag, not for one host, not as
a fallback. If no certificate authority can be found, :func:`ssl_context` raises
with instructions rather than returning a context that trusts anything. A
project that downloads its own training data over an unauthenticated channel has
a supply-chain problem, and a security project doing it has an embarrassing one.
"""

from __future__ import annotations

import os
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from typing import Final

__all__ = ["ssl_context", "fetch", "download", "NetworkError", "USER_AGENT"]


class NetworkError(RuntimeError):
    """A fetch failed, or no trust anchor could be established."""


USER_AGENT: Final = (
    "whetstone-corpus/0.1 (security research; "
    "+https://github.com/at0m-b0mb/Whetstone)"
)

#: System CA bundles, in the order they are worth trying. Covers macOS with
#: Homebrew OpenSSL, the common Linux distributions, and the BSDs.
_CA_BUNDLES: Final[tuple[str, ...]] = (
    "/etc/ssl/cert.pem",                     # macOS, FreeBSD
    "/etc/ssl/certs/ca-certificates.crt",    # Debian, Ubuntu, Alpine
    "/etc/pki/tls/certs/ca-bundle.crt",      # RHEL, Fedora, CentOS
    "/etc/ssl/ca-bundle.pem",                # SUSE
    "/opt/homebrew/etc/ca-certificates/cert.pem",   # Homebrew, Apple silicon
    "/usr/local/etc/ca-certificates/cert.pem",      # Homebrew, Intel
    "/usr/local/etc/openssl/cert.pem",
)

_cached: ssl.SSLContext | None = None


def ssl_context() -> ssl.SSLContext:
    """A verifying TLS context, or raise trying.

    Order of preference: whatever Python already knows about, then ``certifi``
    if installed, then a system bundle. Cached, because building one costs a
    file read and adapters call this per request.
    """
    global _cached
    if _cached is not None:
        return _cached

    # An operator's explicit override wins over everything else.
    env_file = os.environ.get("SSL_CERT_FILE", "").strip()
    if env_file and Path(env_file).is_file():
        _cached = ssl.create_default_context(cafile=env_file)
        return _cached

    context = ssl.create_default_context()
    # cert_store_stats() rather than `get_default_verify_paths().cafile`: the
    # latter only says a path was *configured*, not that anything was loaded
    # from it. A configured-but-missing bundle reports a path and trusts
    # nothing, which fails later and confusingly.
    if context.cert_store_stats().get("x509_ca", 0) > 0:
        _cached = context
        return context

    try:
        import certifi  # type: ignore[import-not-found]

        context.load_verify_locations(cafile=certifi.where())
        _cached = context
        return context
    except Exception:
        pass

    for candidate in _CA_BUNDLES:
        path = Path(candidate)
        if not path.is_file():
            continue
        try:
            context.load_verify_locations(cafile=str(path))
            _cached = context
            return context
        except (OSError, ssl.SSLError):
            continue

    raise NetworkError(
        "no certificate authorities available to verify HTTPS downloads.\n"
        "Fix one of these, in order of preference:\n"
        "  1. run '/Applications/Python 3.13/Install Certificates.command'\n"
        "  2. pip install certifi\n"
        "  3. install your distribution's ca-certificates package\n"
        "Verification is never disabled here: a security project that fetches "
        "its own training data over an unauthenticated channel has a supply-"
        "chain problem."
    )


def fetch(url: str, *, timeout: int = 90, headers: dict[str, str] | None = None) -> bytes:
    """GET ``url`` over verified TLS and return the body."""
    request = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, **(headers or {})}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout,
                                    context=ssl_context()) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        raise NetworkError(f"{url}: HTTP {exc.code} {exc.reason}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise NetworkError(f"{url}: {exc}") from None


def download(url: str, target: Path, *, timeout: int = 300,
             headers: dict[str, str] | None = None) -> Path:
    """Fetch ``url`` to ``target``, atomically. Returns the target.

    Written to a temporary sibling and renamed, so an interrupted download
    cannot leave a truncated file that a later run mistakes for a complete
    cache entry — the failure mode there is a corpus that is silently missing
    half a source.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".part")
    tmp.write_bytes(fetch(url, timeout=timeout, headers=headers))
    tmp.replace(target)
    return target
