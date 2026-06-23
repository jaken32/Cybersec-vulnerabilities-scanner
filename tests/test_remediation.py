"""Tests for the data-driven remediation engine."""

from __future__ import annotations

import pytest

from scanner.remediation.fixes import REMEDIATIONS, SERVER_KEYS, resolve_remediation


def test_every_entry_has_all_server_variants_and_generic():
    for fid, data in REMEDIATIONS.items():
        assert "generic" in data["snippets"], f"{fid} missing generic"
        assert data["why"], f"{fid} missing why"
        assert isinstance(data["references"], list)


def test_resolve_picks_detected_server():
    rem = resolve_remediation("missing-hsts", "nginx")
    assert rem.detected == "nginx"
    assert "add_header Strict-Transport-Security" in rem.snippets["nginx"]
    # all four variants are always available for the UI toggle
    for key in SERVER_KEYS:
        assert key in rem.snippets and rem.snippets[key]


def test_hsts_apache_and_cloudflare_are_tailored():
    rem = resolve_remediation("missing-hsts", "apache")
    assert rem.detected == "apache"
    assert "Header always set Strict-Transport-Security" in rem.snippets["apache"]
    assert "SSL/TLS" in rem.snippets["cloudflare"]


def test_unknown_server_falls_back_to_generic():
    rem = resolve_remediation("missing-csp", "iis")
    assert rem.detected == "generic"
    assert rem.snippets["generic"]


def test_unknown_finding_id_returns_usable_fallback():
    rem = resolve_remediation("does-not-exist", "nginx")
    assert rem.why
    assert rem.snippets["nginx"]
    assert rem.snippets["generic"]


def test_primary_snippet_matches_detected():
    rem = resolve_remediation("exposed-env", "nginx")
    assert rem.primary_snippet() == rem.snippets["nginx"]


@pytest.mark.parametrize(
    "fid",
    [
        "missing-hsts", "missing-csp", "missing-x-frame-options",
        "missing-x-content-type-options", "missing-referrer-policy",
        "missing-permissions-policy", "no-https", "tls-deprecated-protocol",
        "tls-no-forward-secrecy", "tls-cert-expired", "cookie-missing-secure",
        "cookie-missing-httponly", "cookie-missing-samesite",
        "server-version-banner", "x-powered-by-banner", "exposed-git",
        "exposed-env", "directory-listing", "missing-spf", "missing-dmarc",
        "missing-caa", "missing-dkim", "mixed-content", "missing-sri",
        "outdated-component",
    ],
)
def test_known_findings_have_bespoke_remediation(fid):
    assert fid in REMEDIATIONS
    rem = resolve_remediation(fid, "nginx")
    assert rem.snippets["nginx"]
    assert rem.snippets["apache"]
    assert rem.snippets["cloudflare"]
