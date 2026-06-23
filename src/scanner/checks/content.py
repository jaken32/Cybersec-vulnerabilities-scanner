"""Content checks: mixed content on HTTPS pages and external scripts missing
Subresource Integrity (SRI).
"""

from __future__ import annotations

from urllib.parse import urlparse

from ..models import Finding, Severity
from .base import Check, ScanContext

CAT = "Content Integrity"


def _iter(soup, name, **attrs):
    try:
        return soup.find_all(name, **attrs)
    except Exception:  # noqa: BLE001 - defensive against odd soup states
        return []


class ContentCheck(Check):
    id = "content"
    name = "Content integrity (mixed content, SRI)"
    category = CAT

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        soup = ctx.soup
        if soup is None:
            return findings

        is_https = ctx.target.is_https
        page_host = ctx.target.host

        # --- mixed content ---------------------------------------------
        if is_https:
            mixed: list[str] = []
            for tag, attr in (
                ("script", "src"),
                ("link", "href"),
                ("img", "src"),
                ("iframe", "src"),
                ("audio", "src"),
                ("video", "src"),
                ("source", "src"),
            ):
                for el in _iter(soup, tag):
                    val = el.get(attr)
                    if val and val.lower().startswith("http://"):
                        mixed.append(f"<{tag} {attr}={val}>")
            if mixed:
                sample = "; ".join(mixed[:5])
                more = f" (+{len(mixed) - 5} more)" if len(mixed) > 5 else ""
                findings.append(
                    Finding(
                        id="mixed-content",
                        title="Mixed content loaded over HTTP on an HTTPS page",
                        severity=Severity.MEDIUM,
                        category=CAT,
                        evidence=sample + more,
                        description=(
                            "Loading sub-resources over plaintext HTTP on a "
                            "secure page lets attackers tamper with scripts and "
                            "styles, and browsers may block or warn on them."
                        ),
                    )
                )

        # --- Subresource Integrity -------------------------------------
        no_sri: list[str] = []
        for el in _iter(soup, "script"):
            src = el.get("src")
            if not src:
                continue
            host = urlparse(src).hostname
            is_external = host is not None and host.lower() != page_host
            if is_external and not el.get("integrity"):
                no_sri.append(src)
        if no_sri:
            sample = "; ".join(no_sri[:5])
            more = f" (+{len(no_sri) - 5} more)" if len(no_sri) > 5 else ""
            findings.append(
                Finding(
                    id="missing-sri",
                    title="External scripts loaded without Subresource Integrity",
                    severity=Severity.LOW,
                    category=CAT,
                    evidence=sample + more,
                    description=(
                        "Without an integrity hash, a compromised third-party or "
                        "CDN can serve malicious JavaScript that your page will "
                        "execute with full trust."
                    ),
                )
            )

        return findings
