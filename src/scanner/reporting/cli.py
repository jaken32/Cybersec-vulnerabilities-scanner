"""Command-line interface: ``websec-scan <url>``.

Mirrors the web app's authorization gate: the user must affirm authorization
(via ``--authorized`` or an interactive prompt) before any scan runs.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from .. import __version__
from ..engine import scan
from ..models import ScanResult, Severity
from ..safety.ssrf import SSRFError
from .html import render_report

_COLORS = {
    "critical": "\033[1;31m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "info": "\033[2m",
    "reset": "\033[0m",
    "bold": "\033[1m",
}
_GLYPH = {"critical": "▲▲", "high": "▲", "medium": "■", "low": "●", "info": "ℹ"}

LEGAL = (
    "LEGAL: Only scan systems you own or are explicitly authorized to test. "
    "Unauthorized scanning may be illegal."
)


def _c(text: str, key: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{_COLORS.get(key, '')}{text}{_COLORS['reset']}"


def _confirm_authorization(args) -> bool:
    if args.authorized:
        return True
    if not sys.stdin.isatty():
        print(
            "Refusing to scan without authorization. Re-run with --authorized "
            "to affirm you are permitted to scan this target.",
            file=sys.stderr,
        )
        return False
    print(LEGAL)
    answer = input("Type 'yes' to confirm you are authorized to scan this target: ")
    return answer.strip().lower() in ("y", "yes")


def _print_human(result: ScanResult, color: bool) -> None:
    bar = "=" * 60
    print(bar)
    print(_c(f"  Target: {result.target}", "bold", color))
    print(
        f"  Grade:  {_c(result.grade, 'bold', color)}   "
        f"Score: {result.score}/100   "
        f"Server: {result.detected_server}"
    )
    counts = result.counts
    summary = "  ".join(
        f"{_GLYPH[s.slug]} {counts.get(s.slug, 0)} {s.label}"
        for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
    )
    print("  " + summary)
    print(bar)
    if not result.findings:
        print("  No findings reported.")
    for f in result.findings:
        sev = f.severity.slug
        print()
        print(
            _c(f"[{f.severity.label.upper()}] {_GLYPH[sev]} {f.title}", sev, color)
        )
        print(f"  Category: {f.category}")
        print(f"  Evidence: {f.evidence}")
        if f.remediation:
            print(f"  Why:      {f.remediation.why}")
            snip = f.remediation.primary_snippet()
            print(f"  Fix ({f.remediation.detected}):")
            for line in snip.splitlines():
                print(f"      {line}")
            for ref in (f.references + f.remediation.references)[:2]:
                print(f"  Ref:      {ref}")
    if result.notes:
        print("\n  Notes:")
        for n in result.notes:
            print(f"   - {n}")
    print()
    print(
        "  Note: automated scanning catches configuration/surface issues only; "
        "it cannot find business-logic, auth-bypass, or most injection flaws."
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="websec-scan",
        description="Passive web security scanner with tailored remediation. "
        + LEGAL,
    )
    p.add_argument("url", help="Target URL (http/https) you are authorized to scan.")
    p.add_argument(
        "--authorized",
        action="store_true",
        help="Affirm you are authorized to scan the target (skips the prompt).",
    )
    p.add_argument("--json", action="store_true", help="Output JSON instead of text.")
    p.add_argument(
        "-o", "--output", metavar="FILE", help="Write a standalone HTML report to FILE."
    )
    p.add_argument(
        "--server",
        choices=("nginx", "apache", "cloudflare", "generic"),
        help="Override detected server for remediation snippets.",
    )
    p.add_argument("--no-color", action="store_true", help="Disable coloured output.")
    p.add_argument("--version", action="version", version=f"websec-scanner {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not _confirm_authorization(args):
        return 2

    try:
        result = asyncio.run(scan(args.url, server_override=args.server))
    except SSRFError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"error: scan failed: {exc}", file=sys.stderr)
        return 1

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(render_report(result))
            print(f"Report written to {args.output}", file=sys.stderr)
        except OSError as exc:
            print(f"error: could not write report: {exc}", file=sys.stderr)
            return 1

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        _print_human(result, color=not args.no_color and sys.stdout.isatty())

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
