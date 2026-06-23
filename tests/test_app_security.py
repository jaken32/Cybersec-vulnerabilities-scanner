"""Dogfood + hardening tests for the web app itself.

Proves the app emits strict security headers (so it scores A on its own
scanner) and enforces input validation and the authorization gate without ever
touching the network.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# Make the repo root importable so we can load the (non-packaged) web app.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

os.environ.setdefault("WEBSEC_ENABLE_HSTS", "true")

from fastapi.testclient import TestClient  # noqa: E402

from web.app import app  # noqa: E402

client = TestClient(app)


def test_index_serves_strict_security_headers():
    r = client.get("/")
    assert r.status_code == 200
    h = r.headers
    csp = h["content-security-policy"]
    assert "default-src 'self'" in csp
    assert "object-src 'none'" in csp
    assert "frame-ancestors 'self'" in csp
    assert "'unsafe-inline'" not in csp  # strict: no inline script/style
    assert h["x-content-type-options"] == "nosniff"
    assert h["referrer-policy"] == "strict-origin-when-cross-origin"
    assert "geolocation=()" in h["permissions-policy"]
    assert h["x-frame-options"] == "SAMEORIGIN"
    assert "max-age=31536000" in h["strict-transport-security"]
    # No version banner is leaked.
    assert "x-powered-by" not in {k.lower() for k in h.keys()}
    assert h.get("server") == "websec-scanner"


def test_scan_requires_authorization():
    r = client.post("/api/scan", json={"url": "https://example.com", "authorized": False})
    assert r.status_code == 400
    assert "authorized" in r.json()["error"].lower()


def test_scan_rejects_missing_url():
    r = client.post("/api/scan", json={"authorized": True})
    assert r.status_code == 400


def test_scan_rejects_bad_json():
    r = client.post(
        "/api/scan",
        content="not json",
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code == 400


def test_report_404_for_unknown_id():
    r = client.get("/report/does-not-exist")
    assert r.status_code == 404


def test_healthz():
    assert client.get("/healthz").text == "ok"


@pytest.mark.asyncio
async def test_dogfood_app_scores_A_on_its_own_controllable_surface():
    """The app must score an A on its own scanner.

    We exercise the checks the application itself controls (security headers,
    cookies, information disclosure, content integrity, fingerprint) against the
    app's real response, simulating an HTTPS deployment. TLS and DNS depend on
    the deployment host/domain, not on this codebase.
    """
    from conftest import make_context
    from scanner.checks.content import ContentCheck
    from scanner.checks.cookies import CookieCheck
    from scanner.checks.disclosure import DisclosureCheck
    from scanner.checks.fingerprint import FingerprintCheck
    from scanner.checks.headers import SecurityHeadersCheck
    from scanner.scoring import score_findings

    r = client.get("/")
    headers = [(k, v) for k, v in r.headers.items()]
    ctx = make_context(
        url="https://scanner.example/",
        host="scanner.example",
        headers=headers,
        body=r.text,
        detected_server="generic",
    )

    findings = []
    for check in (
        SecurityHeadersCheck(),
        CookieCheck(),
        DisclosureCheck(),
        ContentCheck(),
        FingerprintCheck(),
    ):
        findings.extend(await check.run(ctx))

    score, grade = score_findings(findings)
    # No non-INFO findings on the app's own surface -> perfect score, grade A.
    non_info = [f for f in findings if f.severity.slug != "info"]
    assert non_info == [], f"unexpected self-findings: {[f.id for f in non_info]}"
    assert grade == "A"
    assert score == 100
