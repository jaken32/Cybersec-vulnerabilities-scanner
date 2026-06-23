"""Check ABC and the ScanContext shared by every check.

The engine gathers shared evidence once (the main response, parsed HTML, TLS and
DNS facts) into a :class:`ScanContext`. Checks are then pure analysers over that
context: they may perform *light, non-destructive* extra probes via
``ctx.probe`` (e.g. requesting a well-known path) but never fuzz or exploit.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import httpx

from ..models import Finding
from ..safety.ssrf import SafeClient, ValidatedTarget


@dataclass
class TLSInfo:
    """Facts gathered from the TLS handshake / certificate."""

    supported: bool = False
    negotiated_version: str | None = None
    cipher: str | None = None
    forward_secrecy: bool = False
    cert_subject: str | None = None
    cert_issuer: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    days_to_expiry: int | None = None
    hostname_valid: bool = True
    chain_error: str | None = None
    legacy_protocols: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class DnsInfo:
    """Facts gathered from DNS lookups for the registrable domain."""

    domain: str = ""
    spf: str | None = None
    dmarc: str | None = None
    caa: list[str] = field(default_factory=list)
    has_mx: bool = False
    dkim_checked: bool = False
    dkim_found: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class ScanContext:
    """Everything a check needs to do its job without re-fetching."""

    target: ValidatedTarget
    response: httpx.Response
    body_text: str
    soup: object  # BeautifulSoup; typed loosely to avoid hard import here
    final_url: str
    history: list[httpx.Response]
    tls: TLSInfo
    dns: DnsInfo
    detected_server: str = "generic"
    server_banner: str | None = None
    powered_by: str | None = None
    _client: Optional[SafeClient] = None
    _probe_cache: dict[str, Optional[httpx.Response]] = field(default_factory=dict)

    async def probe(self, path: str) -> Optional[httpx.Response]:
        """Light, non-destructive GET of a path relative to the target origin.

        Returns the response, or ``None`` if the probe could not be performed
        (network error, blocked, etc.). Results are cached per path.
        """
        if path in self._probe_cache:
            return self._probe_cache[path]
        result: Optional[httpx.Response] = None
        if self._client is not None:
            origin = f"{self.target.scheme}://{self.target.host}"
            if self.target.port not in (80, 443):
                origin += f":{self.target.port}"
            url = origin + (path if path.startswith("/") else "/" + path)
            try:
                result = await self._client.get(url)
            except Exception:  # noqa: BLE001 - probes are best-effort
                result = None
        self._probe_cache[path] = result
        return result


class Check(abc.ABC):
    """Abstract base for every security check.

    Subclasses declare ``id``/``name``/``category`` and implement :meth:`run`,
    returning a list of :class:`Finding`. An empty list means "nothing to
    report" (i.e. the check passed).
    """

    id: str = ""
    name: str = ""
    category: str = ""

    @abc.abstractmethod
    async def run(self, ctx: ScanContext) -> list[Finding]:  # pragma: no cover
        raise NotImplementedError
