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

That claim used to cover the first request only. Passing ``context=`` to
``urllib.request.urlopen`` says nothing about hops 2..10 of a redirect chain,
which the stock opener follows to ``http://`` and ``ftp://`` with the caller's
headers attached. So this module stopped using the stock opener: requests go
through :func:`_opener`, which speaks HTTPS and nothing else and which strips
caller headers when a redirect leaves the origin host. See
:class:`_HttpsOnlyRedirectHandler` for what that was hiding.

**A failed fetch is always a** :class:`NetworkError`. Twenty-three adapters are
written as ``except NetworkError``, and that contract is only worth anything if
it has no holes: a truncated body arrives as ``http.client.IncompleteRead``,
which is *not* an ``OSError``, and used to escape every one of them.
"""

from __future__ import annotations

import http.client
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Final

__all__ = [
    "ssl_context", "fetch", "download", "NetworkError", "USER_AGENT",
    "MAX_FETCH_BYTES", "MAX_DOWNLOAD_BYTES",
]


class NetworkError(RuntimeError):
    """A fetch failed, or no trust anchor could be established."""


USER_AGENT: Final = (
    "whetstone-corpus/0.1 (security research; "
    "+https://github.com/at0m-b0mb/Whetstone)"
)

#: How much of a response :func:`fetch` will hold in memory before giving up.
#: Everything fetched this way is a JSON page or a small docs tarball; the
#: largest today is a few megabytes. The number is not a tuning knob, it is the
#: point at which an endless body stops being the caller's problem — without it
#: a compromised or merely broken endpoint can grow ``bytes`` until the machine
#: swaps, and on this host that memory belongs to a training run.
MAX_FETCH_BYTES: Final = 64 * 1024 * 1024

#: The same ceiling for :func:`download`, which streams to disk and so is
#: bounded by free space rather than RAM. Larger because archives are: the
#: biggest in the corpus today is elastic's 62 MB tarball. An adapter that
#: legitimately needs more passes ``max_bytes=`` and says so at the call site,
#: which is the whole point — the size a source is *expected* to be is a fact
#: about that source and belongs in its adapter, not in a default here.
MAX_DOWNLOAD_BYTES: Final = 256 * 1024 * 1024

#: Read size for the streaming loops. One megabyte is large enough that the
#: syscall count is irrelevant and small enough that the ceiling checks below
#: cannot overshoot by anything that matters.
_CHUNK_BYTES: Final = 1 << 20

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


def _same_origin(first: str, second: str) -> bool:
    """True only when both URLs name the same host and port.

    Anything that will not parse answers False — ``SplitResult.port`` raises
    ``ValueError`` on a malformed port rather than returning ``None``, and that
    is a redirect target an attacker controls. False means the caller strips
    headers, so the branch taken when we cannot tell is the one that keeps the
    API key at home. The expensive direction of this decision is the leak.
    """
    try:
        this, that = urllib.parse.urlsplit(first), urllib.parse.urlsplit(second)
        return (((this.hostname or "").lower(), this.port)
                == ((that.hostname or "").lower(), that.port))
    except ValueError:
        return False


class _HttpsOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirects stay on HTTPS, and caller headers stay on the origin host.

    urllib's stock handler allows ``http``, ``https`` and ``ftp`` as redirect
    targets and copies every request header except the content ones onto the
    new request. Both halves of that are a problem here. ``nvd.py`` passes
    ``{"apiKey": <NVD_API_KEY>}`` to :func:`fetch`, so a single ``302 Location:
    http://collector.example/`` was enough to send an operator's key in clear
    text to a host this project never chose — and to do it silently, because
    from the caller's point of view the request simply succeeded and the body
    it returned got written into the corpus.

    Refusing the downgrade is not enough on its own: an ``https`` redirect to
    another host is still somewhere the caller did not agree to send a secret,
    so the caller's headers are dropped on any cross-origin hop. The
    ``User-Agent`` survives, because it identifies this crawler to the people
    running the servers and is not a credential.
    """

    # Signature fixed by the base class; left unannotated for that reason.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme.lower() != "https":
            # Raised, not returned as None: None means "some other handler may
            # take this", and a refusal to downgrade has to be final. HTTPError
            # is what the stdlib raises for a scheme it rejects, and it is what
            # :func:`_open` already maps onto NetworkError.
            raise urllib.error.HTTPError(
                newurl, code,
                f"refused a redirect from {req.full_url} to non-HTTPS {newurl}",
                headers, fp,
            )
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is None or _same_origin(req.full_url, newurl):
            return new
        # Rebuilt rather than mutating ``new.headers``: this way the set of
        # headers that survives a cross-origin hop is stated in one place and
        # is a whitelist, so a caller header added later cannot leak by
        # default. get_method() is preserved because the base class is the one
        # entitled to decide that a 303 turns a POST into a GET.
        return urllib.request.Request(
            newurl,
            method=new.get_method(),
            headers={"User-Agent": req.headers.get("User-agent", USER_AGENT)},
            origin_req_host=req.origin_req_host,
            unverifiable=True,
        )


_opener_cached: urllib.request.OpenerDirector | None = None


def _opener() -> urllib.request.OpenerDirector:
    """The one opener every request in this project goes through.

    Assembled by hand instead of calling ``urllib.request.urlopen``, whose
    default opener registers ``FTPHandler``, ``FileHandler``, ``DataHandler``
    and a plaintext ``HTTPHandler``. Those are not theoretical: they are what a
    redirect resolves against, and on any of them the ``context=`` argument is
    simply unused, so the trust store this module exists to establish is not
    consulted at all. Registering only HTTPS makes the downgrade
    unrepresentable rather than merely discouraged.

    ``UnknownHandler`` is kept so a scheme nothing handles raises ``URLError``
    instead of ``OpenerDirector.open`` returning ``None`` to a caller expecting
    a response. ``ProxyHandler`` is kept because an operator behind a proxy
    configured it deliberately and HTTPS through a proxy is a CONNECT tunnel —
    the TLS session, and therefore the verification, is still end to end.
    """
    global _opener_cached
    if _opener_cached is None:
        opener = urllib.request.OpenerDirector()
        for handler in (
            urllib.request.ProxyHandler(),
            urllib.request.UnknownHandler(),
            urllib.request.HTTPSHandler(context=ssl_context()),
            urllib.request.HTTPDefaultErrorHandler(),
            _HttpsOnlyRedirectHandler(),
            urllib.request.HTTPErrorProcessor(),
        ):
            opener.add_handler(handler)
        _opener_cached = opener
    return _opener_cached


def _open(url: str, *, timeout: int,
          headers: dict[str, str] | None) -> http.client.HTTPResponse:
    """Start a GET over verified TLS, with every failure arriving as NetworkError.

    ``http.client.HTTPException`` is in the except clause on purpose and the
    reason is easy to lose: a body that ends early raises
    ``http.client.IncompleteRead``, whose MRO is ``HTTPException -> Exception``
    — it is **not** an ``OSError``, so the obvious three-exception tuple lets
    the single most ordinary network failure there is escape as something no
    adapter catches. It can be raised here and not only in :func:`_body`,
    because the redirect handler reads and closes the intermediate response
    inside ``open()``.
    """
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme != "https":
        raise NetworkError(
            f"{url}: refusing to fetch over {scheme or '(no scheme)'} — this "
            "module only speaks HTTPS, because an unverified channel for "
            "training data is a supply-chain problem. If a URL arrived from a "
            "remote API rather than a constant, validate it where it is read."
        )
    request = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, **(headers or {})}
    )
    try:
        return _opener().open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        raise NetworkError(f"{url}: HTTP {exc.code} {exc.reason}") from None
    except (urllib.error.URLError, http.client.HTTPException,
            TimeoutError, OSError) as exc:
        raise NetworkError(f"{url}: {exc}") from None


def _body(url: str, response: http.client.HTTPResponse,
          max_bytes: int) -> Iterator[bytes]:
    """Yield the body in chunks, refusing to read past ``max_bytes``.

    A generator rather than a loop inside each caller so that the exception
    mapping wraps the socket read and *nothing else*. The consumer's work — a
    ``handle.write`` in :func:`download` — happens with this frame suspended at
    the ``yield``, outside the ``try``, so a full disk is still reported as the
    ``OSError`` it is instead of being relabelled a network failure. A wrong
    diagnosis is its own kind of silent corruption.

    ``Content-Length`` is checked first but never trusted afterwards: it is a
    claim by the peer, absent under chunked encoding, and free to understate
    what follows. It buys an early, cheap refusal; the running total is what
    actually enforces the ceiling.
    """
    declared = (response.headers or {}).get("Content-Length")
    try:
        advertised = None if declared is None else int(declared)
    except ValueError:
        advertised = None   # unparseable; the running total below still holds
    if advertised is not None and advertised > max_bytes:
        raise NetworkError(
            f"{url}: declares {advertised:,} bytes, over the {max_bytes:,} "
            "byte ceiling — refused before reading any of it"
        )

    total = 0
    while True:
        try:
            chunk = response.read(_CHUNK_BYTES)
        except (urllib.error.URLError, http.client.HTTPException,
                TimeoutError, OSError) as exc:
            raise NetworkError(f"{url}: {exc}") from None
        if not chunk:
            return
        total += len(chunk)
        if total > max_bytes:
            raise NetworkError(
                f"{url}: body passed the {max_bytes:,} byte ceiling and was "
                "cut off. Either the upstream is not what it was, or this "
                "caller needs to pass a larger max_bytes and justify it."
            )
        yield chunk


def fetch(url: str, *, timeout: int = 90, headers: dict[str, str] | None = None,
          max_bytes: int = MAX_FETCH_BYTES) -> bytes:
    """GET ``url`` over verified TLS and return the body.

    The body is accumulated in memory, which is why ``max_bytes`` exists and
    why its default is small. Anything archive-shaped belongs in
    :func:`download`, which streams.
    """
    body = bytearray()
    with _open(url, timeout=timeout, headers=headers) as response:
        for chunk in _body(url, response, max_bytes):
            body += chunk
    return bytes(body)


def download(url: str, target: Path, *, timeout: int = 300,
             headers: dict[str, str] | None = None,
             max_bytes: int = MAX_DOWNLOAD_BYTES) -> Path:
    """Fetch ``url`` to ``target``, atomically. Returns the target.

    Written to a temporary sibling and renamed, so an interrupted download
    cannot leave a truncated file that a later run mistakes for a complete
    cache entry — the failure mode there is a corpus that is silently missing
    half a source.

    Streamed a chunk at a time rather than built on :func:`fetch`. It used to
    be ``tmp.write_bytes(fetch(...))``, which meant the complete file was
    resident in memory before a byte reached disk — four adapters had already
    hand-rolled their own streaming ``urlopen`` loop to get away from it, and
    ``pythoncode``'s 300 MB archive ceiling was evaluated on ``stat()`` after
    the download had already finished, so the one guard that looked like it
    bounded this could not fire until the damage was done. The ceiling belongs
    where the bytes arrive.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".part")
    try:
        with _open(url, timeout=timeout, headers=headers) as response:
            with tmp.open("wb") as handle:
                for chunk in _body(url, response, max_bytes):
                    handle.write(chunk)
    except BaseException:
        # One clause for every way out: a refused redirect, a body over the
        # ceiling, a dead socket, a KeyboardInterrupt mid-stream. Whatever it
        # was, the partial file goes with it rather than sitting in the cache
        # for a later run to trip over.
        tmp.unlink(missing_ok=True)
        raise
    tmp.replace(target)
    return target
