"""Fingerprinting -> advisory check.

Identifies the server, CMS, and common JS libraries (with versions where
exposed) and flags clearly out-of-date components with advisory links. This is
informational/advisory only — it never attempts exploitation.
"""

from __future__ import annotations

import re

from ..models import Finding, Severity
from .base import Check, ScanContext

CAT = "Fingerprint"

# Minimal, conservative "known clearly-old" thresholds for popular libraries.
# We only flag when a version is confidently parsed and well behind current.
JS_LIB_PATTERNS = [
    ("jQuery", re.compile(r"jquery[-.]?(\d+\.\d+(?:\.\d+)?)", re.I), (3, 0, 0)),
    ("AngularJS", re.compile(r"angular[-.]?(\d+\.\d+(?:\.\d+)?)", re.I), (1, 8, 0)),
    ("Bootstrap", re.compile(r"bootstrap[-.]?(\d+\.\d+(?:\.\d+)?)", re.I), (4, 0, 0)),
]


def _ver_tuple(s: str) -> tuple[int, ...]:
    return tuple(int(p) for p in s.split(".") if p.isdigit())


class FingerprintCheck(Check):
    id = "fingerprint"
    name = "Technology fingerprint"
    category = CAT

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        h = ctx.response.headers
        bits: list[str] = []

        server = h.get("server")
        if server:
            bits.append(f"Server: {server}")
        powered = h.get("x-powered-by")
        if powered:
            bits.append(f"X-Powered-By: {powered}")

        # CMS detection via generator meta tag.
        cms = None
        soup = ctx.soup
        if soup is not None:
            try:
                gen = soup.find("meta", attrs={"name": "generator"})
                if gen and gen.get("content"):
                    cms = gen["content"]
                    bits.append(f"Generator: {cms}")
            except Exception:  # noqa: BLE001
                pass
            # WordPress hint.
            if "wp-content" in (ctx.body_text or ""):
                if not cms or "wordpress" not in cms.lower():
                    bits.append("Detected WordPress (wp-content paths)")

        if bits:
            findings.append(
                Finding(
                    id="tech-fingerprint",
                    title="Detected technology stack",
                    severity=Severity.INFO,
                    category=CAT,
                    evidence="; ".join(bits),
                    description=(
                        "Informational: this is the technology the scanner could "
                        "identify from public responses. Keep every component "
                        "patched and current."
                    ),
                )
            )

        # Outdated JS libraries.
        body = ctx.body_text or ""
        srcs = []
        if soup is not None:
            for el in _iter_scripts(soup):
                src = el.get("src")
                if src:
                    srcs.append(src)
        haystack = "\n".join(srcs) + "\n" + body
        seen: set[str] = set()
        for name, pat, min_ver in JS_LIB_PATTERNS:
            m = pat.search(haystack)
            if not m:
                continue
            ver = m.group(1)
            if name in seen:
                continue
            seen.add(name)
            try:
                if _ver_tuple(ver) < min_ver:
                    findings.append(
                        Finding(
                            id="outdated-component",
                            title=f"Outdated JavaScript library: {name} {ver}",
                            severity=Severity.LOW,
                            category=CAT,
                            evidence=f"Detected {name} version {ver} in page assets.",
                            description=(
                                f"{name} {ver} is several major versions behind "
                                "and may contain publicly-known vulnerabilities. "
                                "Upgrade to a currently-supported release."
                            ),
                            references=[
                                "https://owasp.org/www-project-top-ten/2021/A06_2021-Vulnerable_and_Outdated_Components/",
                            ],
                        )
                    )
            except Exception:  # noqa: BLE001
                continue

        return findings


def _iter_scripts(soup):
    try:
        return soup.find_all("script")
    except Exception:  # noqa: BLE001
        return []
