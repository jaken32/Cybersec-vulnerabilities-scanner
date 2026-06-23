# websec-scanner

[![tests](https://github.com/jaken32/Cybersec-vulnerabilities-scanner/actions/workflows/tests.yml/badge.svg)](https://github.com/jaken32/Cybersec-vulnerabilities-scanner/actions/workflows/tests.yml)

A passive web-security posture scanner with **server-tailored, copy-paste
remediation**. Point it at a site you own, and it returns an A–F grade, a
categorized list of findings (each with severity, plain-English risk, the
evidence found, and a fix snippet for *your* stack), and a downloadable
standalone HTML report.

It ships as both a web app and a CLI.

> ⚠️ **Legal / authorization notice.** This is a **defensive tool for authorized
> use only.** Only scan systems you own or have explicit, written permission to
> test. Unauthorized scanning may be illegal in your jurisdiction. The web app
> requires you to affirm authorization before each scan and logs that consent
> with a timestamp. The scanner performs **passive analysis** of publicly
> returned data plus **light, non-destructive** checks — never exploitation,
> brute-forcing, fuzzing, or destructive actions.

---

## What it checks

| Category | Checks |
|---|---|
| **Security headers** | HSTS (missing/weak), CSP, X-Frame-Options / `frame-ancestors`, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| **TLS / SSL** | Plaintext HTTP, deprecated protocols (TLS 1.0/1.1), forward secrecy, certificate expiry/validity, hostname match, chain issues |
| **Cookies** | Missing `Secure`, `HttpOnly`, `SameSite` |
| **Information disclosure** | `Server` / `X-Powered-By` version banners, exposed `/.git/`, exposed `/.env`, directory listing |
| **DNS & email** | SPF, DMARC, CAA, DKIM advisory |
| **Content integrity** | Mixed content on HTTPS, external scripts missing Subresource Integrity (SRI) |
| **Fingerprint → advisory** | Detects server / CMS / JS libraries and flags clearly out-of-date components |

Each finding maps to a concrete remediation with **nginx**, **Apache**,
**Cloudflare**, and **generic** variants — the detected server is shown first.

---

## Quick start

Requires **Python 3.11+**. From a clean clone:

```bash
git clone <this-repo> websec-scanner
cd websec-scanner

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -e ".[dev]"          # installs the package, CLI, and test deps
cp .env.example .env             # optional; sane defaults work out of the box
```

### Run the web app

```bash
uvicorn web.app:app --host 127.0.0.1 --port 8000 --no-server-header
```

Open <http://127.0.0.1:8000>, enter a URL, tick the authorization box, and run a
scan. `--no-server-header` stops uvicorn adding its own `Server: uvicorn` banner
so the app emits only its own hardened headers.

> **Deploy behind TLS.** The app is designed to be served over HTTPS (e.g. behind
> nginx/Caddy/Cloudflare). HSTS is sent by default; set `WEBSEC_ENABLE_HSTS=false`
> only for plain-HTTP local development.

### Run the CLI

```bash
# Human-readable report (requires you to affirm authorization)
websec-scan https://example.com --authorized

# Pick the server variant for fixes, write a standalone HTML report, emit JSON
websec-scan https://example.com --authorized --server nginx -o report.html --json
```

`websec-scan --help` lists every option. Without `--authorized` in an interactive
terminal it prompts for consent; in a non-interactive context it refuses to run.

---

## Configuration

All configuration is via environment variables (see [`.env.example`](.env.example)).
No secrets are required to run; `.env` is git-ignored.

| Variable | Default | Purpose |
|---|---|---|
| `WEBSEC_RATE_LIMIT` | `10/minute` | Per-IP request limit (slowapi syntax) |
| `WEBSEC_TARGET_COOLDOWN_SECONDS` | `30` | Minimum gap between scans of the same target |
| `WEBSEC_SCAN_TIMEOUT` | `12` | Per-request timeout (seconds) |
| `WEBSEC_MAX_RESPONSE_BYTES` | `5242880` | Max bytes read from a target |
| `WEBSEC_ENABLE_HSTS` | `true` | Send HSTS on our own responses |
| `WEBSEC_RESULT_TTL_SECONDS` | `1800` | How long a generated report stays downloadable |
| `WEBSEC_LOG_LEVEL` | `INFO` | Log level (consent logging included) |

---

## Architecture

```
websec-scanner/
├── src/scanner/
│   ├── models.py            # Severity, Remediation, Finding, ScanResult
│   ├── scoring.py           # severity weighting -> score + A–F grade
│   ├── engine.py            # validate -> gather (HTTP/TLS/DNS) -> run checks -> score
│   ├── safety/ssrf.py       # URL validation, IP-range guard, IP-pinned SafeClient
│   ├── checks/
│   │   ├── base.py          # Check ABC + ScanContext (+ TLSInfo / DnsInfo)
│   │   ├── headers.py  tls.py  cookies.py  disclosure.py
│   │   ├── dns_email.py  content.py  fingerprint.py
│   │   └── __init__.py      # ALL_CHECKS registry
│   ├── remediation/fixes.py # data-driven id+server -> tailored fix snippets
│   └── reporting/
│       ├── html.py          # standalone, escaped HTML report
│       └── cli.py           # console entry point (websec-scan)
├── web/
│   ├── app.py               # FastAPI: routes, rate limiting, security headers
│   ├── templates/index.html
│   └── static/css/app.css   static/js/app.js   # hand-written design system
├── tests/                   # pytest, fully offline & deterministic
└── .github/workflows/tests.yml
```

**Design rule.** Every check implements the same `Check` interface and returns
`Finding` objects of a fixed shape (`id, title, severity, category, evidence,
remediation, references`). The **engine only orchestrates**, **remediation only
maps fixes**, and **reporting only renders**. Adding a check = adding one module
and registering it in `ALL_CHECKS`. Adding a fix = adding one entry to
`REMEDIATIONS`.

### How the scanner protects itself

- **SSRF guard** (`safety/ssrf.py`): http/https only; rejects any target that
  resolves to private, loopback, link-local, reserved, multicast, or CGNAT
  ranges and the cloud-metadata IP `169.254.169.254`; **pins** the validated IP
  for the connection (preserving Host + TLS SNI) to defeat DNS rebinding;
  follows redirects **manually**, re-validating every hop; enforces per-request
  timeout and a max response size.
- **XSS-safe reporting**: every byte captured from a scanned site is treated as
  hostile. The HTML report escapes all dynamic content (`html.escape`); the live
  UI builds DOM with `createElement` + `textContent` only — never `innerHTML`
  with scan data.
- **Hardened own headers**: strict CSP (no inline script/style), HSTS, nosniff,
  Referrer-Policy, Permissions-Policy, frame protection; no version banners; no
  insecure cookies. The app is built to score an **A on its own scanner** (see
  `tests/test_app_security.py::test_dogfood_app_scores_A_on_its_own_controllable_surface`).
- **Rate limiting**: per-IP limits *and* a per-target cooldown, returning `429`
  with a clear message.
- **Authorization gate + consent logging** on every scan.

---

## Limitations (read this)

Automated scanning is a **starting point, not a guarantee.** This tool catches
**configuration and surface-level issues** — headers, TLS settings, cookie flags,
DNS/email records, information disclosure, and outdated front-end components.

It **cannot** find:

- business-logic flaws,
- authentication / authorization bypasses,
- most injection vulnerabilities (SQLi, command injection, SSRF in *your* app),
- access-control problems, or anything requiring authenticated or stateful
  interaction.

Those require **manual testing** by a qualified person. A passing grade means the
*checked* configuration looks good — it does **not** mean the site is secure.
Some checks (e.g. DKIM) are advisory because they cannot be verified passively.

---

## Testing

```bash
pytest            # 100+ tests, fully offline & deterministic
```

- `test_ssrf.py` — **exhaustive** SSRF coverage: loopback, every private range,
  link-local, cloud metadata, reserved/multicast, non-http(s) schemes, and
  redirect-to-internal are all asserted rejected; ordinary public hostnames pass.
- `test_checks.py` — each check against synthetic responses (no live network).
- `test_scoring.py` — scoring and grade bands.
- `test_remediation.py` — every finding maps to tailored, non-empty fixes.
- `test_report.py` — the report is XSS-safe against hostile scanned content.
- `test_app_security.py` — the app emits strict headers and enforces the
  authorization gate (the dogfood "scores an A" test).

CI runs the suite on every push/PR via GitHub Actions (Python 3.11 & 3.12).

---

## License

[MIT](LICENSE).
