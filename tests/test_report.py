"""The downloadable report must be XSS-safe against hostile scanned content."""

from __future__ import annotations

from scanner.models import Finding, ScanResult, Severity, utcnow
from scanner.remediation import resolve_remediation
from scanner.reporting.html import render_report


def _malicious_result() -> ScanResult:
    payload = '<script>alert(1)</script>"><img src=x onerror=alert(2)>'
    finding = Finding(
        id="server-version-banner",
        title=f"Banner {payload}",
        severity=Severity.LOW,
        category="Information Disclosure",
        evidence=f"Server: {payload}",
        description=f"Description {payload}",
        references=["https://example.com/ref"],
    )
    finding.remediation = resolve_remediation(finding.id, "nginx")
    now = utcnow()
    return ScanResult(
        target=f"https://victim.example/{payload}",
        findings=[finding],
        score=96,
        grade="A",
        detected_server="nginx",
        started_at=now,
        finished_at=now,
    )


def test_report_escapes_hostile_content():
    html = render_report(_malicious_result())
    # No raw, executable HTML tag from the scanned site may appear in the doc.
    assert "<script>alert(1)</script>" not in html
    assert "<img src=x onerror" not in html
    assert '"><img' not in html
    # The payload must appear only in fully-escaped form.
    assert "&lt;script&gt;" in html
    assert "&lt;img src=x onerror=alert(2)&gt;" in html


def test_report_is_standalone_document():
    html = render_report(_malicious_result())
    assert html.lstrip().startswith("<!DOCTYPE html>")
    assert "<style>" in html  # CSS inlined -> renders offline
    assert "Download" not in html  # report itself has no app-only controls
    assert "A" in html
