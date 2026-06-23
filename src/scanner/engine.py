"""Scan engine: validate target, gather shared evidence, run checks, score.

The engine only orchestrates. It never decides *what* is wrong (checks do) nor
*how* to render results (reporting does) nor *how* to fix things (remediation
does). It gathers the main response, TLS facts, and DNS facts once, then fans the
checks out concurrently.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone

from bs4 import BeautifulSoup

from .checks import ALL_CHECKS
from .checks.base import DnsInfo, ScanContext, TLSInfo
from .models import Finding, ScanResult, Severity, utcnow
from .remediation import resolve_remediation
from .safety.ssrf import SafeClient, SSRFError, ValidatedTarget, validate_url
from .scoring import score_findings, severity_counts

DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "mail", "dkim", "s1")


# ---------------------------------------------------------------------------
# Server detection
# ---------------------------------------------------------------------------

def detect_server(headers) -> tuple[str, str | None, str | None]:
    """Return (detected_key, server_banner, powered_by)."""
    server = headers.get("server")
    powered = headers.get("x-powered-by")
    s = (server or "").lower()
    if "cloudflare" in s or "cf-ray" in {k.lower() for k in headers.keys()}:
        key = "cloudflare"
    elif "nginx" in s:
        key = "nginx"
    elif "apache" in s or "httpd" in s:
        key = "apache"
    else:
        key = "generic"
    return key, server, powered


# ---------------------------------------------------------------------------
# TLS gathering (blocking; run via asyncio.to_thread)
# ---------------------------------------------------------------------------

def _parse_cert_time(value: str) -> datetime | None:
    try:
        # e.g. 'Jun  1 12:00:00 2025 GMT'
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
    except Exception:  # noqa: BLE001
        return None


def _has_forward_secrecy(version: str | None, cipher_name: str | None) -> bool:
    # All TLS 1.3 cipher suites are forward-secret (ephemeral key exchange only).
    if version == "TLSv1.3":
        return True
    name = (cipher_name or "").upper()
    return "ECDHE" in name or "DHE" in name


def _probe_legacy_protocols(host: str, ip: str, port: int, timeout: float) -> list[str]:
    legacy: list[str] = []
    candidates = [
        ("TLSv1", getattr(ssl.TLSVersion, "TLSv1", None)),
        ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
    ]
    for label, version in candidates:
        if version is None:
            continue
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = version
            ctx.maximum_version = version
        except (ValueError, OSError):
            continue
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    if ssock.version() in ("TLSv1", "TLSv1.1"):
                        legacy.append(label)
        except Exception:  # noqa: BLE001 - unsupported == good
            continue
    return legacy


def gather_tls_sync(host: str, ip: str, port: int, timeout: float = 8.0) -> TLSInfo:
    info = TLSInfo()
    # First: a verifying handshake to learn hostname/chain validity.
    verify_ctx = ssl.create_default_context()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with verify_ctx.wrap_socket(sock, server_hostname=host) as ssock:
                info.supported = True
                info.negotiated_version = ssock.version()
                cipher = ssock.cipher()
                if cipher:
                    info.cipher = cipher[0]
                info.forward_secrecy = _has_forward_secrecy(
                    info.negotiated_version, info.cipher
                )
                info.hostname_valid = True
    except ssl.SSLCertVerificationError as exc:
        info.chain_error = str(getattr(exc, "verify_message", "") or exc)
        if "hostname mismatch" in str(exc).lower() or "doesn't match" in str(exc).lower():
            info.hostname_valid = False
    except (ssl.SSLError, socket.timeout, OSError) as exc:
        info.error = str(exc)

    # Second: a non-verifying handshake to read certificate facts even if the
    # verified handshake failed (so we can still report expiry, etc.).
    raw_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    raw_ctx.check_hostname = False
    raw_ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with raw_ctx.wrap_socket(sock, server_hostname=host) as ssock:
                info.supported = True
                if not info.negotiated_version:
                    info.negotiated_version = ssock.version()
                if not info.cipher:
                    cipher = ssock.cipher()
                    if cipher:
                        info.cipher = cipher[0]
                info.forward_secrecy = _has_forward_secrecy(
                    info.negotiated_version, info.cipher
                )
                cert = ssock.getpeercert()
                if cert:
                    subject = dict(x[0] for x in cert.get("subject", []) if x)
                    issuer = dict(x[0] for x in cert.get("issuer", []) if x)
                    info.cert_subject = subject.get("commonName")
                    info.cert_issuer = issuer.get("commonName") or issuer.get(
                        "organizationName"
                    )
                    info.not_before = _parse_cert_time(cert.get("notBefore", ""))
                    info.not_after = _parse_cert_time(cert.get("notAfter", ""))
                    if info.not_after:
                        delta = info.not_after - datetime.now(timezone.utc)
                        info.days_to_expiry = delta.days
    except Exception as exc:  # noqa: BLE001
        if not info.supported:
            info.error = info.error or str(exc)

    if info.supported:
        info.legacy_protocols = _probe_legacy_protocols(host, ip, port, timeout)

    return info


# ---------------------------------------------------------------------------
# DNS gathering (blocking; run via asyncio.to_thread)
# ---------------------------------------------------------------------------

def _registrable_domain(host: str) -> str:
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    return ".".join(labels[-2:])


def gather_dns_sync(host: str, timeout: float = 5.0) -> DnsInfo:
    info = DnsInfo(domain=_registrable_domain(host))
    try:
        import dns.resolver  # local import keeps engine import light
    except Exception as exc:  # noqa: BLE001 - dnspython missing
        info.error = f"DNS library unavailable: {exc}"
        return info

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    domain = info.domain

    def _txt(name: str) -> list[str]:
        try:
            answers = resolver.resolve(name, "TXT")
        except Exception:  # noqa: BLE001 - NXDOMAIN/timeout/etc.
            return []
        out = []
        for r in answers:
            try:
                out.append(b"".join(r.strings).decode("utf-8", "replace"))
            except Exception:  # noqa: BLE001
                out.append(str(r))
        return out

    queried_any = False
    try:
        for rec in _txt(domain):
            queried_any = True
            if rec.lower().startswith("v=spf1"):
                info.spf = rec
                break
        for rec in _txt(f"_dmarc.{domain}"):
            queried_any = True
            if rec.lower().startswith("v=dmarc1"):
                info.dmarc = rec
                break
        try:
            caa = resolver.resolve(domain, "CAA")
            queried_any = True
            info.caa = [str(r) for r in caa]
        except Exception:  # noqa: BLE001
            pass
        try:
            mx = resolver.resolve(domain, "MX")
            queried_any = True
            info.has_mx = len(list(mx)) > 0
        except Exception:  # noqa: BLE001
            pass
        if info.has_mx:
            info.dkim_checked = True
            for sel in DKIM_SELECTORS:
                if _txt(f"{sel}._domainkey.{domain}"):
                    info.dkim_found.append(sel)
    except Exception as exc:  # noqa: BLE001
        info.error = str(exc)

    if not queried_any and not info.error:
        info.error = "No DNS records could be retrieved."
    return info


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


async def scan(
    raw_url: str,
    *,
    timeout: float = 10.0,
    max_bytes: int = 5 * 1024 * 1024,
    resolver=None,
    server_override: str | None = None,
    on_progress=None,
) -> ScanResult:
    """Run a full passive scan and return a :class:`ScanResult`.

    Raises :class:`SSRFError` if the target fails validation (caller should turn
    this into a user-safe 400 response).

    ``on_progress`` (optional) is called with ``(pct: int, message: str)`` at
    each milestone so the UI can show real progress.
    """
    started = utcnow()
    notes: list[str] = []

    def _emit(pct: int, message: str) -> None:
        if on_progress is not None:
            try:
                on_progress(pct, message)
            except Exception:  # noqa: BLE001 - progress must never break a scan
                pass

    _emit(4, "Validating target and applying SSRF guard")
    # Gate 1: validate + pin before any network egress.
    target: ValidatedTarget = validate_url(raw_url, resolver=resolver)

    async with SafeClient(
        timeout=timeout, max_bytes=max_bytes, resolver=resolver
    ) as client:
        _emit(15, f"Fetching {target.scheme}://{target.host}")
        try:
            response = await client.get(target.url)
        except SSRFError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise SSRFError(f"Could not fetch the target: {exc}") from exc

        try:
            body_text = response.text
        except Exception:  # noqa: BLE001
            body_text = ""
        try:
            soup = BeautifulSoup(body_text, "html.parser")
        except Exception:  # noqa: BLE001
            soup = None

        detected, server_banner, powered_by = detect_server(response.headers)
        if server_override and server_override in ("nginx", "apache", "cloudflare", "generic"):
            detected = server_override

        final_url = getattr(response, "_logical_url", None) or target.url

        # Gather TLS + DNS concurrently (both blocking -> threads).
        tls_task = (
            asyncio.to_thread(gather_tls_sync, target.host, target.pinned_ip, target.port)
            if target.is_https
            else None
        )
        dns_task = asyncio.to_thread(gather_dns_sync, target.host)

        _emit(35, "Inspecting TLS certificate and DNS records")
        if tls_task is not None:
            tls_info, dns_info = await asyncio.gather(tls_task, dns_task)
        else:
            tls_info = TLSInfo(error="Not an HTTPS target.")
            dns_info = await dns_task

        ctx = ScanContext(
            target=target,
            response=response,
            body_text=body_text,
            soup=soup,
            final_url=final_url,
            history=list(getattr(response, "history", []) or []),
            tls=tls_info,
            dns=dns_info,
            detected_server=detected,
            server_banner=server_banner,
            powered_by=powered_by,
            _client=client,
        )

        # Run every check concurrently; one failing check never aborts the scan.
        checks = [cls() for cls in ALL_CHECKS]
        total = len(checks)
        done = 0
        lock = asyncio.Lock()

        async def _run_one(check):
            nonlocal done
            try:
                return await check.run(ctx)
            finally:
                async with lock:
                    done += 1
                    pct = 45 + int(45 * done / total)
                    _emit(pct, f"Completed check: {check.name}")

        results = await asyncio.gather(
            *(_run_one(c) for c in checks), return_exceptions=True
        )

    findings: list[Finding] = []
    checks_run: list[str] = []
    for check, result in zip(checks, results):
        checks_run.append(check.id)
        if isinstance(result, Exception):
            notes.append(f"Check '{check.id}' failed: {result}")
            continue
        findings.extend(result)

    # Attach tailored remediation to each finding.
    for f in findings:
        f.remediation = resolve_remediation(f.id, detected)

    # Stable, severity-first ordering.
    findings.sort(key=lambda f: (f.severity.rank, f.category, f.title))

    _emit(95, "Scoring and generating remediation")
    score, grade = score_findings(findings)
    finished = utcnow()
    _emit(100, "Done")

    return ScanResult(
        target=final_url or target.url,
        findings=findings,
        score=score,
        grade=grade,
        detected_server=detected,
        started_at=started,
        finished_at=finished,
        checks_run=checks_run,
        counts=severity_counts(findings),
        notes=notes,
    )
