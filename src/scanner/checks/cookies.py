"""Cookie attribute checks: Secure, HttpOnly, SameSite."""

from __future__ import annotations

from http.cookies import SimpleCookie

from ..models import Finding, Severity
from .base import Check, ScanContext

CAT = "Cookies"


def _parse_set_cookies(raw_values: list[str]) -> list[tuple[str, dict]]:
    """Parse Set-Cookie header values into (name, attrs) pairs.

    Returns attribute keys lower-cased; ``samesite`` maps to its value.
    """
    out: list[tuple[str, dict]] = []
    for raw in raw_values:
        jar = SimpleCookie()
        try:
            jar.load(raw)
        except Exception:  # noqa: BLE001 - tolerate malformed cookies
            continue
        for name, morsel in jar.items():
            attrs = {
                "secure": bool(morsel["secure"]),
                "httponly": bool(morsel["httponly"]),
                "samesite": (morsel["samesite"] or "").strip().lower() or None,
            }
            out.append((name, attrs))
    return out


class CookieCheck(Check):
    id = "cookies"
    name = "Cookie security attributes"
    category = CAT

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        raw_cookies = ctx.response.headers.get_list("set-cookie")
        if not raw_cookies:
            return findings

        cookies = _parse_set_cookies(raw_cookies)
        is_https = ctx.target.is_https

        insecure, no_httponly, no_samesite = [], [], []
        for name, attrs in cookies:
            if is_https and not attrs["secure"]:
                insecure.append(name)
            if not attrs["httponly"]:
                no_httponly.append(name)
            if not attrs["samesite"]:
                no_samesite.append(name)

        if insecure:
            findings.append(
                Finding(
                    id="cookie-missing-secure",
                    title="Cookies set without the Secure flag",
                    severity=Severity.MEDIUM,
                    category=CAT,
                    evidence="Cookies missing Secure: " + ", ".join(insecure),
                    description=(
                        "Without the Secure flag, cookies can be sent over "
                        "plaintext HTTP and captured by a network attacker."
                    ),
                )
            )
        if no_httponly:
            findings.append(
                Finding(
                    id="cookie-missing-httponly",
                    title="Cookies set without the HttpOnly flag",
                    severity=Severity.MEDIUM,
                    category=CAT,
                    evidence="Cookies missing HttpOnly: " + ", ".join(no_httponly),
                    description=(
                        "Cookies without HttpOnly are readable by JavaScript, so "
                        "any cross-site scripting flaw can steal session tokens."
                    ),
                )
            )
        if no_samesite:
            findings.append(
                Finding(
                    id="cookie-missing-samesite",
                    title="Cookies set without a SameSite attribute",
                    severity=Severity.LOW,
                    category=CAT,
                    evidence="Cookies missing SameSite: " + ", ".join(no_samesite),
                    description=(
                        "An explicit SameSite attribute (Lax or Strict) reduces "
                        "the risk of cross-site request forgery by limiting when "
                        "the cookie is sent on cross-site requests."
                    ),
                )
            )

        return findings
