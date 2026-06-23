"""Shared test fixtures. Everything here is fully offline and deterministic."""

from __future__ import annotations

import httpx
import pytest
from bs4 import BeautifulSoup

from scanner.checks.base import DnsInfo, ScanContext, TLSInfo
from scanner.safety.ssrf import ValidatedTarget


def make_response(
    *,
    url: str = "https://example.com/",
    status: int = 200,
    headers: list[tuple[str, str]] | dict | None = None,
    body: str = "<html></html>",
) -> httpx.Response:
    """Build an httpx.Response with no network access.

    ``headers`` may be a list of (name, value) tuples to allow repeated headers
    (e.g. multiple Set-Cookie).
    """
    req = httpx.Request("GET", url)
    resp = httpx.Response(
        status_code=status,
        headers=headers or [],
        content=body.encode("utf-8"),
        request=req,
    )
    return resp


def make_context(
    *,
    url: str = "https://example.com/",
    scheme: str = "https",
    host: str = "example.com",
    port: int = 443,
    headers: list[tuple[str, str]] | dict | None = None,
    body: str = "<html></html>",
    tls: TLSInfo | None = None,
    dns: DnsInfo | None = None,
    detected_server: str = "nginx",
) -> ScanContext:
    resp = make_response(url=url, headers=headers, body=body)
    target = ValidatedTarget(
        url=url, scheme=scheme, host=host, port=port, pinned_ip="93.184.216.34"
    )
    return ScanContext(
        target=target,
        response=resp,
        body_text=body,
        soup=BeautifulSoup(body, "html.parser"),
        final_url=url,
        history=[],
        tls=tls or TLSInfo(error="not gathered in test"),
        dns=dns or DnsInfo(domain=host),
        detected_server=detected_server,
    )


@pytest.fixture
def ctx_factory():
    return make_context
