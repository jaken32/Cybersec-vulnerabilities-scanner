"""Unit tests for every check, against synthetic (offline) contexts."""

from __future__ import annotations

from datetime import timedelta

import pytest

from scanner.checks.base import DnsInfo, TLSInfo
from scanner.checks.content import ContentCheck
from scanner.checks.cookies import CookieCheck
from scanner.checks.disclosure import DisclosureCheck
from scanner.checks.dns_email import DnsEmailCheck
from scanner.checks.fingerprint import FingerprintCheck
from scanner.checks.headers import SecurityHeadersCheck
from scanner.checks.tls import TLSCheck
from scanner.models import Severity, utcnow

from conftest import make_context


def ids(findings):
    return {f.id for f in findings}


# --------------------------------------------------------------- headers
@pytest.mark.asyncio
async def test_headers_all_missing_flags_each():
    ctx = make_context(headers=[])
    findings = await SecurityHeadersCheck().run(ctx)
    got = ids(findings)
    assert "missing-hsts" in got
    assert "missing-csp" in got
    assert "missing-x-frame-options" in got
    assert "missing-x-content-type-options" in got
    assert "missing-referrer-policy" in got
    assert "missing-permissions-policy" in got


@pytest.mark.asyncio
async def test_headers_all_present_no_findings():
    headers = [
        ("strict-transport-security", "max-age=31536000; includeSubDomains"),
        ("content-security-policy", "default-src 'self'; frame-ancestors 'self'"),
        ("x-frame-options", "SAMEORIGIN"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "strict-origin-when-cross-origin"),
        ("permissions-policy", "geolocation=()"),
    ]
    ctx = make_context(headers=headers)
    findings = await SecurityHeadersCheck().run(ctx)
    assert findings == []


@pytest.mark.asyncio
async def test_weak_hsts_detected():
    ctx = make_context(headers=[("strict-transport-security", "max-age=100")])
    got = ids(await SecurityHeadersCheck().run(ctx))
    assert "weak-hsts" in got


# --------------------------------------------------------------- tls
@pytest.mark.asyncio
async def test_tls_expired_cert_is_critical():
    tls = TLSInfo(
        supported=True,
        negotiated_version="TLSv1.3",
        cipher="ECDHE-RSA-AES128-GCM-SHA256",
        forward_secrecy=True,
        not_after=utcnow() - timedelta(days=5),
        days_to_expiry=-5,
    )
    ctx = make_context(tls=tls)
    findings = await TLSCheck().run(ctx)
    by_id = {f.id: f for f in findings}
    assert "tls-cert-expired" in by_id
    assert by_id["tls-cert-expired"].severity is Severity.CRITICAL


@pytest.mark.asyncio
async def test_tls_deprecated_protocol_and_no_fs():
    tls = TLSInfo(
        supported=True,
        negotiated_version="TLSv1.2",
        cipher="AES128-SHA",
        forward_secrecy=False,
        legacy_protocols=["TLSv1", "TLSv1.1"],
        days_to_expiry=200,
    )
    ctx = make_context(tls=tls)
    got = ids(await TLSCheck().run(ctx))
    assert "tls-deprecated-protocol" in got
    assert "tls-no-forward-secrecy" in got


@pytest.mark.asyncio
async def test_plain_http_flagged():
    ctx = make_context(url="http://example.com/", scheme="http", port=80)
    got = ids(await TLSCheck().run(ctx))
    assert "no-https" in got


# --------------------------------------------------------------- cookies
@pytest.mark.asyncio
async def test_cookies_missing_flags():
    headers = [("set-cookie", "sid=abc; Path=/")]
    ctx = make_context(headers=headers)
    got = ids(await CookieCheck().run(ctx))
    assert "cookie-missing-secure" in got
    assert "cookie-missing-httponly" in got
    assert "cookie-missing-samesite" in got


@pytest.mark.asyncio
async def test_cookies_fully_secured_pass():
    headers = [("set-cookie", "sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax")]
    ctx = make_context(headers=headers)
    findings = await CookieCheck().run(ctx)
    assert findings == []


# --------------------------------------------------------------- disclosure
@pytest.mark.asyncio
async def test_disclosure_banners_and_listing():
    headers = [("server", "nginx/1.18.0"), ("x-powered-by", "PHP/8.1.2")]
    body = "<html><head><title>Index of /</title></head><body></body></html>"
    ctx = make_context(headers=headers, body=body)
    got = ids(await DisclosureCheck().run(ctx))
    assert "server-version-banner" in got
    assert "x-powered-by-banner" in got
    assert "directory-listing" in got


@pytest.mark.asyncio
async def test_disclosure_clean_server_no_banner():
    ctx = make_context(headers=[("server", "nginx")])  # no version
    got = ids(await DisclosureCheck().run(ctx))
    assert "server-version-banner" not in got


# --------------------------------------------------------------- dns/email
@pytest.mark.asyncio
async def test_dns_missing_records():
    dns = DnsInfo(domain="example.com", spf=None, dmarc=None, caa=[], has_mx=True)
    ctx = make_context(dns=dns)
    got = ids(await DnsEmailCheck().run(ctx))
    assert "missing-spf" in got
    assert "missing-dmarc" in got
    assert "missing-caa" in got
    assert "missing-dkim" in got  # advisory because MX present, no DKIM found


@pytest.mark.asyncio
async def test_dns_all_present_pass():
    dns = DnsInfo(
        domain="example.com",
        spf="v=spf1 -all",
        dmarc="v=DMARC1; p=reject",
        caa=['0 issue "letsencrypt.org"'],
        has_mx=True,
        dkim_found=["default"],
    )
    ctx = make_context(dns=dns)
    findings = await DnsEmailCheck().run(ctx)
    assert findings == []


# --------------------------------------------------------------- content
@pytest.mark.asyncio
async def test_content_mixed_and_sri():
    body = (
        "<html><body>"
        '<img src="http://insecure.example/x.png">'
        '<script src="https://cdn.other.example/lib.js"></script>'
        "</body></html>"
    )
    ctx = make_context(body=body)
    got = ids(await ContentCheck().run(ctx))
    assert "mixed-content" in got
    assert "missing-sri" in got


@pytest.mark.asyncio
async def test_content_clean_pass():
    body = (
        "<html><body>"
        '<script src="/local.js"></script>'
        '<script src="https://cdn.other.example/lib.js" integrity="sha384-x" crossorigin="anonymous"></script>'
        "</body></html>"
    )
    ctx = make_context(body=body)
    findings = await ContentCheck().run(ctx)
    assert findings == []


# --------------------------------------------------------------- fingerprint
@pytest.mark.asyncio
async def test_fingerprint_detects_and_flags_outdated():
    body = (
        '<html><head><meta name="generator" content="WordPress 6.0">'
        '<script src="/js/jquery-1.12.4.min.js"></script></head><body>'
        "wp-content</body></html>"
    )
    ctx = make_context(headers=[("server", "Apache/2.4.41")], body=body)
    findings = await FingerprintCheck().run(ctx)
    got = ids(findings)
    assert "tech-fingerprint" in got
    assert "outdated-component" in got
