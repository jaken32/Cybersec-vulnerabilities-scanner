"""Security-header checks: HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
Referrer-Policy, Permissions-Policy.
"""

from __future__ import annotations

import re

from ..models import Finding, Severity
from .base import Check, ScanContext

CAT = "Security Headers"


def _get(ctx: ScanContext, name: str) -> str | None:
    return ctx.response.headers.get(name)


class SecurityHeadersCheck(Check):
    id = "security-headers"
    name = "HTTP security headers"
    category = CAT

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        h = ctx.response.headers
        is_https = ctx.target.is_https

        # --- HSTS -------------------------------------------------------
        hsts = _get(ctx, "strict-transport-security")
        if is_https:
            if not hsts:
                findings.append(
                    Finding(
                        id="missing-hsts",
                        title="Missing HTTP Strict Transport Security (HSTS)",
                        severity=Severity.HIGH,
                        category=CAT,
                        evidence="No Strict-Transport-Security response header.",
                        description=(
                            "Without HSTS, a network attacker can downgrade the "
                            "connection to plaintext HTTP and intercept traffic "
                            "or steal cookies."
                        ),
                    )
                )
            else:
                m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
                max_age = int(m.group(1)) if m else 0
                if max_age < 15552000:  # < 180 days
                    findings.append(
                        Finding(
                            id="weak-hsts",
                            title="Weak HSTS max-age",
                            severity=Severity.LOW,
                            category=CAT,
                            evidence=f"Strict-Transport-Security: {hsts}",
                            description=(
                                "A short HSTS max-age leaves a window during "
                                "which downgrade attacks remain possible. Use at "
                                "least 6 months (recommended 1 year)."
                            ),
                        )
                    )

        # --- CSP --------------------------------------------------------
        csp = _get(ctx, "content-security-policy")
        if not csp:
            findings.append(
                Finding(
                    id="missing-csp",
                    title="Missing Content-Security-Policy",
                    severity=Severity.MEDIUM,
                    category=CAT,
                    evidence="No Content-Security-Policy response header.",
                    description=(
                        "A Content-Security-Policy is the strongest defence-in-"
                        "depth against cross-site scripting and data injection. "
                        "Without it, any injected script runs unrestricted."
                    ),
                )
            )

        # --- X-Frame-Options / frame-ancestors -------------------------
        xfo = _get(ctx, "x-frame-options")
        has_frame_ancestors = bool(csp and re.search(r"frame-ancestors", csp, re.I))
        if not xfo and not has_frame_ancestors:
            findings.append(
                Finding(
                    id="missing-x-frame-options",
                    title="Missing clickjacking protection (X-Frame-Options)",
                    severity=Severity.MEDIUM,
                    category=CAT,
                    evidence=(
                        "Neither X-Frame-Options nor a CSP frame-ancestors "
                        "directive is present."
                    ),
                    description=(
                        "The page can be embedded in a hostile iframe, enabling "
                        "clickjacking attacks that trick users into actions they "
                        "did not intend."
                    ),
                )
            )

        # --- X-Content-Type-Options ------------------------------------
        xcto = _get(ctx, "x-content-type-options")
        if not xcto or xcto.strip().lower() != "nosniff":
            findings.append(
                Finding(
                    id="missing-x-content-type-options",
                    title="Missing X-Content-Type-Options: nosniff",
                    severity=Severity.LOW,
                    category=CAT,
                    evidence=f"X-Content-Type-Options: {xcto or '(absent)'}",
                    description=(
                        "Browsers may MIME-sniff responses and execute content "
                        "as a different type than declared, enabling some XSS "
                        "and drive-by attacks."
                    ),
                )
            )

        # --- Referrer-Policy -------------------------------------------
        ref = _get(ctx, "referrer-policy")
        if not ref:
            findings.append(
                Finding(
                    id="missing-referrer-policy",
                    title="Missing Referrer-Policy",
                    severity=Severity.LOW,
                    category=CAT,
                    evidence="No Referrer-Policy response header.",
                    description=(
                        "Without a Referrer-Policy the full URL (which may "
                        "contain sensitive tokens or IDs) can leak to third-"
                        "party sites via the Referer header."
                    ),
                )
            )

        # --- Permissions-Policy ----------------------------------------
        pp = _get(ctx, "permissions-policy") or _get(ctx, "feature-policy")
        if not pp:
            findings.append(
                Finding(
                    id="missing-permissions-policy",
                    title="Missing Permissions-Policy",
                    severity=Severity.LOW,
                    category=CAT,
                    evidence="No Permissions-Policy response header.",
                    description=(
                        "A Permissions-Policy lets you disable powerful browser "
                        "features (camera, microphone, geolocation) that the "
                        "site does not use, shrinking the attack surface."
                    ),
                )
            )

        return findings
