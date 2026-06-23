"""TLS/SSL checks driven by facts gathered in ``ctx.tls`` (a :class:`TLSInfo`).

The check itself is pure: all network I/O happens in the engine's gatherer so
this logic is fully unit-testable with synthetic TLSInfo objects.
"""

from __future__ import annotations

from ..models import Finding, Severity
from .base import Check, ScanContext

CAT = "TLS / SSL"

DEPRECATED_PROTOCOLS = {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3"}


class TLSCheck(Check):
    id = "tls"
    name = "TLS / SSL configuration"
    category = CAT

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        if not ctx.target.is_https:
            findings.append(
                Finding(
                    id="no-https",
                    title="Site is served over plaintext HTTP",
                    severity=Severity.HIGH,
                    category=CAT,
                    evidence=f"Target scheme is '{ctx.target.scheme}'.",
                    description=(
                        "Traffic is transmitted unencrypted and can be read or "
                        "modified by anyone on the network path."
                    ),
                )
            )
            return findings

        tls = ctx.tls
        if not tls.supported:
            # Could not complete a handshake; report as advisory, don't crash.
            findings.append(
                Finding(
                    id="tls-handshake-failed",
                    title="Could not establish a TLS connection",
                    severity=Severity.INFO,
                    category=CAT,
                    evidence=tls.error or "TLS handshake did not complete.",
                    description=(
                        "The scanner could not negotiate TLS with the host, so "
                        "certificate and protocol checks were skipped. Verify "
                        "the certificate manually."
                    ),
                )
            )
            return findings

        # --- deprecated protocols --------------------------------------
        legacy = [p for p in tls.legacy_protocols if p in DEPRECATED_PROTOCOLS]
        if legacy:
            findings.append(
                Finding(
                    id="tls-deprecated-protocol",
                    title="Deprecated TLS protocol versions enabled",
                    severity=Severity.HIGH,
                    category=CAT,
                    evidence="Server accepted: " + ", ".join(sorted(set(legacy))),
                    description=(
                        "TLS 1.0/1.1 and SSL are cryptographically broken and "
                        "must be disabled; they expose users to downgrade and "
                        "decryption attacks (BEAST, POODLE)."
                    ),
                )
            )

        # --- forward secrecy -------------------------------------------
        if not tls.forward_secrecy:
            findings.append(
                Finding(
                    id="tls-no-forward-secrecy",
                    title="Cipher suite does not provide forward secrecy",
                    severity=Severity.MEDIUM,
                    category=CAT,
                    evidence=f"Negotiated cipher: {tls.cipher or 'unknown'}",
                    description=(
                        "Without forward secrecy (ECDHE/DHE), a future "
                        "compromise of the server's private key lets an attacker "
                        "decrypt all previously recorded traffic."
                    ),
                )
            )

        # --- certificate expiry ----------------------------------------
        if tls.days_to_expiry is not None:
            if tls.days_to_expiry < 0:
                findings.append(
                    Finding(
                        id="tls-cert-expired",
                        title="TLS certificate has expired",
                        severity=Severity.CRITICAL,
                        category=CAT,
                        evidence=(
                            f"Certificate expired on "
                            f"{tls.not_after.isoformat() if tls.not_after else 'unknown'}."
                        ),
                        description=(
                            "An expired certificate breaks trust: browsers show "
                            "a full-page warning and the connection is "
                            "effectively unusable and unauthenticated."
                        ),
                    )
                )
            elif tls.days_to_expiry < 21:
                findings.append(
                    Finding(
                        id="tls-cert-expiring",
                        title="TLS certificate is expiring soon",
                        severity=Severity.MEDIUM,
                        category=CAT,
                        evidence=f"Certificate expires in {tls.days_to_expiry} day(s).",
                        description=(
                            "A certificate that lapses will take the site "
                            "offline for all users. Renew and automate renewal."
                        ),
                    )
                )

        # --- hostname / chain ------------------------------------------
        if not tls.hostname_valid:
            findings.append(
                Finding(
                    id="tls-hostname-mismatch",
                    title="Certificate does not match the hostname",
                    severity=Severity.HIGH,
                    category=CAT,
                    evidence=f"Certificate subject: {tls.cert_subject or 'unknown'}",
                    description=(
                        "The certificate is not valid for this hostname, so "
                        "clients cannot verify they are talking to the real "
                        "server."
                    ),
                )
            )
        if tls.chain_error:
            findings.append(
                Finding(
                    id="tls-chain-issue",
                    title="TLS certificate chain problem",
                    severity=Severity.HIGH,
                    category=CAT,
                    evidence=tls.chain_error,
                    description=(
                        "An incomplete or untrusted chain causes verification "
                        "failures for some clients even when the leaf "
                        "certificate is valid."
                    ),
                )
            )

        return findings
