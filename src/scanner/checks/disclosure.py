"""Information-disclosure checks.

Covers version banners (Server / X-Powered-By), and light, non-destructive
probes for commonly-exposed sensitive paths (/.git/, /.env, backup files) and
directory listing. Probes are GET requests for well-known static paths only —
no fuzzing, no parameter manipulation, no exploitation.
"""

from __future__ import annotations

import re

from ..models import Finding, Severity
from .base import Check, ScanContext

CAT = "Information Disclosure"

VERSION_RE = re.compile(r"\d+\.\d+")

#: Well-known sensitive paths and how to confirm a true positive.
SENSITIVE_PROBES = [
    {
        "path": "/.git/HEAD",
        "id": "exposed-git",
        "title": "Exposed .git repository",
        "severity": Severity.HIGH,
        "confirm": lambda text: text.strip().startswith("ref:")
        or re.match(r"^[0-9a-f]{40}", text.strip() or ""),
        "desc": (
            "An exposed .git directory lets anyone download your full source "
            "code, history, and any secrets ever committed."
        ),
    },
    {
        "path": "/.env",
        "id": "exposed-env",
        "title": "Exposed .env configuration file",
        "severity": Severity.CRITICAL,
        "confirm": lambda text: bool(
            re.search(r"^[A-Z][A-Z0-9_]+\s*=", text or "", re.M)
        )
        and ("<html" not in (text or "").lower()),
        "desc": (
            "A readable .env file typically contains database credentials, API "
            "keys, and secret tokens — a direct path to full compromise."
        ),
    },
]


class DisclosureCheck(Check):
    id = "disclosure"
    name = "Information disclosure"
    category = CAT

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        h = ctx.response.headers

        # --- version banners -------------------------------------------
        server = h.get("server")
        if server and VERSION_RE.search(server):
            findings.append(
                Finding(
                    id="server-version-banner",
                    title="Server version disclosed in Server header",
                    severity=Severity.LOW,
                    category=CAT,
                    evidence=f"Server: {server}",
                    description=(
                        "Exposing the exact server software and version helps "
                        "attackers match your stack to known exploits."
                    ),
                )
            )

        powered = h.get("x-powered-by")
        if powered:
            findings.append(
                Finding(
                    id="x-powered-by-banner",
                    title="Technology disclosed in X-Powered-By header",
                    severity=Severity.LOW,
                    category=CAT,
                    evidence=f"X-Powered-By: {powered}",
                    description=(
                        "The X-Powered-By header reveals the application "
                        "framework/runtime (and often its version), aiding "
                        "targeted attacks. It serves no functional purpose."
                    ),
                )
            )

        # --- sensitive path probes -------------------------------------
        for probe in SENSITIVE_PROBES:
            resp = await ctx.probe(probe["path"])
            if resp is None or resp.status_code != 200:
                continue
            try:
                text = resp.text[:4096]
            except Exception:  # noqa: BLE001
                text = ""
            if probe["confirm"](text):
                findings.append(
                    Finding(
                        id=probe["id"],
                        title=probe["title"],
                        severity=probe["severity"],
                        category=CAT,
                        evidence=(
                            f"GET {probe['path']} returned 200 with matching "
                            f"content."
                        ),
                        description=probe["desc"],
                    )
                )

        # --- directory listing -----------------------------------------
        # Inspect the main response body for an Apache/nginx autoindex page.
        body = ctx.body_text or ""
        if re.search(r"<title>\s*Index of /", body, re.I) or (
            "<h1>Index of /" in body
        ):
            findings.append(
                Finding(
                    id="directory-listing",
                    title="Directory listing is enabled",
                    severity=Severity.MEDIUM,
                    category=CAT,
                    evidence="The response body is an automatic directory index.",
                    description=(
                        "Automatic directory listings expose file names and "
                        "structure, often revealing backups, source, or other "
                        "files not meant to be public."
                    ),
                )
            )

        return findings
