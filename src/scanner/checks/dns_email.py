"""DNS & email-authentication checks: SPF, DMARC, CAA, and a DKIM advisory.

Facts are gathered in ``ctx.dns`` (a :class:`DnsInfo`) by the engine, so this
check is pure and offline-testable.
"""

from __future__ import annotations

from ..models import Finding, Severity
from .base import Check, ScanContext

CAT = "DNS & Email"


class DnsEmailCheck(Check):
    id = "dns-email"
    name = "DNS & email authentication"
    category = CAT

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        dns = ctx.dns

        if dns.error and not (dns.spf or dns.dmarc or dns.caa):
            findings.append(
                Finding(
                    id="dns-lookup-failed",
                    title="DNS records could not be queried",
                    severity=Severity.INFO,
                    category=CAT,
                    evidence=dns.error,
                    description=(
                        "The scanner could not resolve DNS records for the "
                        "domain, so email-authentication and CAA checks were "
                        "skipped."
                    ),
                )
            )
            return findings

        # --- SPF --------------------------------------------------------
        if not dns.spf:
            findings.append(
                Finding(
                    id="missing-spf",
                    title="No SPF record published",
                    severity=Severity.MEDIUM,
                    category=CAT,
                    evidence=f"No 'v=spf1' TXT record found for {dns.domain}.",
                    description=(
                        "Without SPF, attackers can more easily spoof email "
                        "from your domain, aiding phishing against your users."
                    ),
                )
            )

        # --- DMARC ------------------------------------------------------
        if not dns.dmarc:
            findings.append(
                Finding(
                    id="missing-dmarc",
                    title="No DMARC record published",
                    severity=Severity.MEDIUM,
                    category=CAT,
                    evidence=f"No '_dmarc.{dns.domain}' TXT record found.",
                    description=(
                        "DMARC tells receiving servers what to do with mail that "
                        "fails SPF/DKIM and gives you visibility into spoofing. "
                        "Without it, domain abuse goes unreported and unblocked."
                    ),
                )
            )

        # --- CAA --------------------------------------------------------
        if not dns.caa:
            findings.append(
                Finding(
                    id="missing-caa",
                    title="No CAA record published",
                    severity=Severity.LOW,
                    category=CAT,
                    evidence=f"No CAA record found for {dns.domain}.",
                    description=(
                        "A CAA record restricts which certificate authorities "
                        "may issue certificates for your domain, reducing the "
                        "risk of unauthorised or mis-issued certificates."
                    ),
                )
            )

        # --- DKIM advisory ---------------------------------------------
        # DKIM lives at selector-specific records we cannot enumerate
        # passively, so we surface this as guidance rather than a defect.
        if dns.has_mx and not dns.dkim_found:
            findings.append(
                Finding(
                    id="missing-dkim",
                    title="DKIM could not be confirmed (advisory)",
                    severity=Severity.INFO,
                    category=CAT,
                    evidence=(
                        "Common DKIM selectors were not found; DKIM uses "
                        "selector-specific records that cannot be enumerated "
                        "passively."
                    ),
                    description=(
                        "DKIM cryptographically signs outgoing mail. Confirm "
                        "your mail provider's selector is published; it is "
                        "required for a strong DMARC posture."
                    ),
                )
            )

        return findings
