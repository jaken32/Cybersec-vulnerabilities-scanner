"""Exhaustive SSRF guard tests. Fully offline (DNS is injected).

Asserts that loopback, every private range, link-local, cloud metadata, reserved/
multicast ranges, non-http(s) schemes, and redirect-to-internal are ALL rejected,
and that ordinary public hostnames pass.
"""

from __future__ import annotations

import httpx
import pytest

from scanner.safety.ssrf import (
    SSRFError,
    ip_is_blocked,
    validate_url,
    SafeClient,
)

# --------------------------------------------------------------------------- #
# IP-range guard
# --------------------------------------------------------------------------- #

BLOCKED_IPS = [
    # loopback
    "127.0.0.1", "127.1.1.1", "127.255.255.255",
    "::1",
    # private (RFC1918)
    "10.0.0.1", "10.255.255.255",
    "172.16.0.1", "172.31.255.255",
    "192.168.0.1", "192.168.1.1",
    # carrier-grade NAT
    "100.64.0.1", "100.127.255.255",
    # link-local + cloud metadata
    "169.254.0.1", "169.254.169.254",
    # IPv6 ULA / link-local
    "fc00::1", "fd00::1", "fe80::1",
    # multicast
    "224.0.0.1", "239.255.255.255", "ff02::1",
    # reserved / special
    "0.0.0.0", "240.0.0.1", "255.255.255.255",
    # documentation / test-net
    "192.0.2.1", "198.51.100.1", "203.0.113.1",
    # unspecified IPv6
    "::",
    # IPv4-mapped IPv6 pointing at loopback
    "::ffff:127.0.0.1",
]

PUBLIC_IPS = ["93.184.216.34", "1.1.1.1", "8.8.8.8", "2606:2800:220:1:248:1893:25c8:1946"]


@pytest.mark.parametrize("ip", BLOCKED_IPS)
def test_blocked_ips_are_blocked(ip):
    assert ip_is_blocked(ip) is True


@pytest.mark.parametrize("ip", PUBLIC_IPS)
def test_public_ips_are_allowed(ip):
    assert ip_is_blocked(ip) is False


def test_garbage_is_blocked():
    assert ip_is_blocked("not-an-ip") is True


# --------------------------------------------------------------------------- #
# Scheme allow-list
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_INFO",
        "ftp://example.com/x",
        "data:text/html,<script>alert(1)</script>",
        "ldap://internal/",
        "dict://127.0.0.1:11211/",
    ],
)
def test_non_http_schemes_rejected(url):
    with pytest.raises(SSRFError):
        validate_url(url, resolver=lambda h: ["93.184.216.34"])


# --------------------------------------------------------------------------- #
# Hostname validation (DNS injected)
# --------------------------------------------------------------------------- #

def public_resolver(host):
    return ["93.184.216.34"]


def internal_resolver(host):
    return ["127.0.0.1"]


def mixed_resolver(host):
    # A public-looking host that secretly resolves to an internal address
    # (DNS-rebinding style). Must be rejected.
    return ["10.0.0.5"]


def test_public_hostname_passes():
    t = validate_url("https://example.com/path", resolver=public_resolver)
    assert t.host == "example.com"
    assert t.scheme == "https"
    assert t.pinned_ip == "93.184.216.34"
    assert t.port == 443


def test_hostname_resolving_internal_is_rejected():
    with pytest.raises(SSRFError):
        validate_url("https://evil.example/", resolver=internal_resolver)


def test_dns_rebinding_style_private_answer_rejected():
    with pytest.raises(SSRFError):
        validate_url("https://totally-legit.example/", resolver=mixed_resolver)


def test_metadata_hostname_rejected():
    with pytest.raises(SSRFError):
        validate_url("http://metadata.google.internal/", resolver=public_resolver)


def test_metadata_ip_rejected():
    with pytest.raises(SSRFError):
        validate_url("http://169.254.169.254/latest/meta-data/", resolver=public_resolver)


def test_localhost_rejected():
    with pytest.raises(SSRFError):
        validate_url("http://localhost:8000/", resolver=public_resolver)


def test_literal_private_ip_rejected():
    with pytest.raises(SSRFError):
        validate_url("http://192.168.1.1/", resolver=public_resolver)


def test_credentials_in_url_rejected():
    with pytest.raises(SSRFError):
        validate_url("https://user:pass@example.com/", resolver=public_resolver)


def test_empty_url_rejected():
    with pytest.raises(SSRFError):
        validate_url("   ", resolver=public_resolver)


def test_missing_scheme_defaults_to_https_and_passes():
    t = validate_url("example.com", resolver=public_resolver)
    assert t.scheme == "https"


def test_whitespace_control_chars_rejected():
    with pytest.raises(SSRFError):
        validate_url("https://exa\nmple.com/", resolver=public_resolver)


# --------------------------------------------------------------------------- #
# Redirect re-validation (offline, via MockTransport)
# --------------------------------------------------------------------------- #

def rebinding_resolver(host):
    mapping = {
        "external.test": ["93.184.216.34"],   # public
        "internal.test": ["127.0.0.1"],       # internal -> must be blocked
    }
    return mapping.get(host, ["93.184.216.34"])


@pytest.mark.asyncio
async def test_redirect_to_internal_is_blocked():
    def handler(request: httpx.Request) -> httpx.Response:
        # First (and only legitimate) hop redirects to an internal host.
        return httpx.Response(302, headers={"Location": "http://internal.test/admin"})

    transport = httpx.MockTransport(handler)
    async with SafeClient(resolver=rebinding_resolver, transport=transport) as client:
        with pytest.raises(SSRFError):
            await client.get("http://external.test/")


@pytest.mark.asyncio
async def test_normal_redirect_to_public_is_followed():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(302, headers={"Location": "http://external.test/final"})
        return httpx.Response(200, content=b"ok")

    transport = httpx.MockTransport(handler)
    async with SafeClient(resolver=rebinding_resolver, transport=transport) as client:
        resp = await client.get("http://external.test/")
    assert resp.status_code == 200
    assert resp.text == "ok"


@pytest.mark.asyncio
async def test_max_response_size_enforced():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"A" * 2048)

    transport = httpx.MockTransport(handler)
    async with SafeClient(
        resolver=public_resolver, transport=transport, max_bytes=1024
    ) as client:
        with pytest.raises(SSRFError):
            await client.get("https://example.com/big")
