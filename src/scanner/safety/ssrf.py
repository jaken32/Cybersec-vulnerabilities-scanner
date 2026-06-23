"""SSRF protection: URL validation, IP-range guarding, and a safe HTTP client.

Threat model: the *target* URL is attacker-influenced. A naive fetcher can be
coerced into hitting internal services (cloud metadata, localhost admin panels,
RFC1918 hosts) or be tricked via DNS rebinding / open redirects.

Defenses implemented here:
  * Scheme allow-list (http/https only).
  * Hostname resolution + rejection of every private/reserved/loopback/
    link-local/multicast range, including cloud metadata (169.254.169.254).
  * IP *pinning*: we resolve once, validate, then connect to the validated IP
    while preserving the original Host header and TLS SNI. This closes the
    rebinding window between validation and connection.
  * Manual redirect handling: every hop is re-validated; a redirect to an
    internal address is blocked.
  * Hard per-request timeout and max response size.

The functions take an injectable ``resolver`` so the test-suite can exercise
hostname logic fully offline and deterministically.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Callable, Iterable
from urllib.parse import urlparse, urlsplit, urlunsplit

import httpx

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ALLOWED_SCHEMES = frozenset({"http", "https"})

#: Cloud-metadata endpoints that must never be reachable.
METADATA_HOSTS = frozenset({"169.254.169.254", "fd00:ec2::254", "metadata.google.internal"})

#: Networks that are never legitimate scan targets. ``ipaddress`` already flags
#: most of these via its ``is_private`` / ``is_*`` properties, but we enumerate
#: the explicitly-required ranges so the guard is auditable and testable.
BLOCKED_NETWORKS: tuple[ipaddress._BaseNetwork, ...] = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",          # "this" network
        "10.0.0.0/8",         # RFC1918
        "100.64.0.0/10",      # RFC6598 carrier-grade NAT
        "127.0.0.0/8",        # loopback
        "169.254.0.0/16",     # link-local (incl. cloud metadata)
        "172.16.0.0/12",      # RFC1918
        "192.0.0.0/24",       # IETF protocol assignments
        "192.0.2.0/24",       # TEST-NET-1
        "192.88.99.0/24",     # 6to4 relay anycast
        "192.168.0.0/16",     # RFC1918
        "198.18.0.0/15",      # benchmarking
        "198.51.100.0/24",    # TEST-NET-2
        "203.0.113.0/24",     # TEST-NET-3
        "224.0.0.0/4",        # multicast
        "240.0.0.0/4",        # reserved
        "255.255.255.255/32", # broadcast
        "::1/128",            # IPv6 loopback
        "::/128",             # unspecified
        "::ffff:0:0/96",      # IPv4-mapped IPv6
        "64:ff9b::/96",       # NAT64
        "100::/64",           # discard-only
        "2001:db8::/32",      # documentation
        "fc00::/7",           # unique local
        "fe80::/10",          # link-local
        "ff00::/8",           # multicast
    )
)

DEFAULT_TIMEOUT = 10.0
DEFAULT_MAX_BYTES = 5 * 1024 * 1024  # 5 MiB
DEFAULT_MAX_REDIRECTS = 4


class SSRFError(ValueError):
    """Raised when a target URL fails a safety gate. Message is user-safe."""


# ---------------------------------------------------------------------------
# IP / hostname validation
# ---------------------------------------------------------------------------

Resolver = Callable[[str], Iterable[str]]


def system_resolver(host: str) -> list[str]:
    """Resolve a hostname to all A/AAAA addresses using the system resolver.

    Mirrors what the connection layer would do, so validation and connection
    agree on the address set.
    """
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:  # pragma: no cover - network dependent
        raise SSRFError(f"Could not resolve hostname: {host}") from exc
    addrs = {info[4][0] for info in infos}
    if not addrs:  # pragma: no cover - defensive
        raise SSRFError(f"Could not resolve hostname: {host}")
    return sorted(addrs)


def ip_is_blocked(ip_str: str) -> bool:
    """Return True if *ip_str* falls in any disallowed range."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        # Not a literal IP -> caller should resolve first; treat as blocked here.
        return True

    # Normalise IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1) to its IPv4 form.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped

    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return True
    # IPv6 may not flag site-local/ULA via is_private in every stdlib version.
    if getattr(ip, "is_site_local", False):
        return True
    return any(ip in net for net in BLOCKED_NETWORKS)


def assert_ip_allowed(ip_str: str) -> None:
    if ip_is_blocked(ip_str):
        raise SSRFError(
            "Target resolves to a private, reserved, or internal address, "
            "which is not permitted."
        )


@dataclass(frozen=True)
class ValidatedTarget:
    """A target that has passed every safety gate."""

    url: str
    scheme: str
    host: str
    port: int
    pinned_ip: str

    @property
    def is_https(self) -> bool:
        return self.scheme == "https"


def normalize_url(raw: str) -> str:
    """Best-effort normalisation: trim, add scheme if missing, validate shape."""
    if not raw or not raw.strip():
        raise SSRFError("Please enter a URL.")
    candidate = raw.strip()
    # Reject obvious control characters / whitespace embedded in the URL.
    if any(ord(c) < 0x20 or c in " \t\r\n" for c in candidate):
        raise SSRFError("URL contains invalid whitespace or control characters.")
    if "://" not in candidate:
        candidate = "https://" + candidate
    return candidate


def validate_url(
    raw: str,
    *,
    resolver: Resolver | None = None,
) -> ValidatedTarget:
    """Validate a user-supplied URL and pin a safe IP to connect to.

    Raises :class:`SSRFError` (with a user-safe message) on any violation.
    """
    resolver = resolver or system_resolver
    url = normalize_url(raw)

    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise SSRFError("That does not look like a valid URL.") from exc

    scheme = (parts.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise SSRFError(
            f"Scheme '{scheme or '(none)'}' is not allowed. Only http and https "
            "are permitted."
        )

    host = parts.hostname
    if not host:
        raise SSRFError("The URL is missing a hostname.")

    # Userinfo (user:pass@host) is a common SSRF/parser-confusion vector.
    if parts.username or parts.password:
        raise SSRFError("Credentials in the URL are not permitted.")

    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise SSRFError("The URL has an invalid port.") from exc
    if not (0 < port < 65536):
        raise SSRFError("The URL has an invalid port.")

    host_l = host.lower().rstrip(".")
    if host_l in METADATA_HOSTS:
        raise SSRFError("That host is a cloud-metadata endpoint and is blocked.")

    # If the host is a literal IP, validate it directly.
    try:
        literal = ipaddress.ip_address(host_l)
    except ValueError:
        literal = None

    if literal is not None:
        assert_ip_allowed(str(literal))
        pinned = str(literal)
    else:
        if "." not in host_l and host_l != "localhost":
            # bare single-label hosts (e.g. "intranet") can resolve internally.
            pass
        if host_l == "localhost":
            raise SSRFError("Scanning localhost is not permitted.")
        addrs = list(resolver(host_l))
        if not addrs:
            raise SSRFError(f"Could not resolve hostname: {host}")
        for addr in addrs:
            assert_ip_allowed(addr)
        # Pin the first validated address for connection.
        pinned = addrs[0]

    return ValidatedTarget(
        url=url,
        scheme=scheme,
        host=host_l,
        port=port,
        pinned_ip=pinned,
    )


# ---------------------------------------------------------------------------
# Safe HTTP client
# ---------------------------------------------------------------------------


def _pin_request_to_ip(url: str, pinned_ip: str) -> tuple[str, dict]:
    """Rewrite *url* so httpx connects to ``pinned_ip`` while preserving the
    original Host header and TLS SNI. Returns (connect_url, extensions).
    """
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = parts.port
    # IPv6 literals must be bracketed in the netloc.
    ip_netloc = f"[{pinned_ip}]" if ":" in pinned_ip else pinned_ip
    if port:
        ip_netloc = f"{ip_netloc}:{port}"
    connect_url = urlunsplit(
        (parts.scheme, ip_netloc, parts.path or "/", parts.query, parts.fragment)
    )
    host_header = host if not port else f"{host}:{port}"
    extensions = {"sni_hostname": host}
    return connect_url, host_header, extensions


class SafeClient:
    """An async HTTP client that fetches only validated, IP-pinned targets and
    re-validates every redirect hop.

    Use as an async context manager::

        async with SafeClient() as client:
            resp = await client.get("https://example.com")
    """

    def __init__(
        self,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        max_bytes: int = DEFAULT_MAX_BYTES,
        max_redirects: int = DEFAULT_MAX_REDIRECTS,
        resolver: Resolver | None = None,
        user_agent: str = "websec-scanner/1.0 (+passive-security-scan)",
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.max_redirects = max_redirects
        self.resolver = resolver or system_resolver
        self.user_agent = user_agent
        self._transport = transport  # for tests; production uses the default
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "SafeClient":
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout),
            follow_redirects=False,  # we follow manually with re-validation
            verify=True,
            http2=False,
            transport=self._transport,
            limits=httpx.Limits(max_connections=8, max_keepalive_connections=4),
        )
        return self

    async def __aexit__(self, *exc) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _read_capped(self, response: httpx.Response) -> bytes:
        chunks: list[bytes] = []
        total = 0
        async for chunk in response.aiter_bytes():
            total += len(chunk)
            if total > self.max_bytes:
                await response.aclose()
                raise SSRFError(
                    f"Response exceeded the maximum allowed size "
                    f"({self.max_bytes} bytes)."
                )
            chunks.append(chunk)
        return b"".join(chunks)

    async def request(
        self,
        method: str,
        raw_url: str,
        *,
        headers: dict | None = None,
    ) -> httpx.Response:
        """Perform a request with full SSRF guarding and manual redirects."""
        if self._client is None:  # pragma: no cover - misuse
            raise RuntimeError("SafeClient must be used as an async context manager.")

        history: list[httpx.Response] = []
        current = raw_url
        for _hop in range(self.max_redirects + 1):
            target = validate_url(current, resolver=self.resolver)
            connect_url, host_header, extensions = _pin_request_to_ip(
                target.url, target.pinned_ip
            )
            req_headers = {
                "User-Agent": self.user_agent,
                "Accept": "*/*",
                "Host": host_header,
                **(headers or {}),
            }
            response = await self._client.request(
                method,
                connect_url,
                headers=req_headers,
                extensions=extensions,
            )
            # Read+cap body, then re-attach so callers can use .text/.content.
            body = await self._read_capped(response)
            response._content = body  # noqa: SLF001 - httpx stores body here
            response.history = list(history)  # type: ignore[attr-defined]
            # Preserve the logical (hostname) URL; the wire URL uses the pinned IP.
            response._logical_url = target.url  # type: ignore[attr-defined]

            if response.is_redirect and "location" in response.headers:
                location = response.headers["location"]
                # Resolve relative redirects against the *current* URL.
                next_url = httpx.URL(target.url).join(location)
                history.append(response)
                current = str(next_url)
                continue
            return response

        raise SSRFError("Too many redirects.")

    async def get(self, raw_url: str, *, headers: dict | None = None) -> httpx.Response:
        return await self.request("GET", raw_url, headers=headers)
