"""Data-driven remediation catalog.

A single mapping of ``finding id -> remediation data`` keeps remediation logic
out of the checks. ``resolve_remediation`` selects the snippet variant for the
detected server (falling back to ``generic``) and returns a frozen
:class:`~scanner.models.Remediation`.

Each entry provides:
  * ``why``  – one-sentence risk explanation.
  * ``snippets`` – {nginx, apache, cloudflare, generic} copy-paste fixes.
  * ``references`` – authoritative links (OWASP / MDN / vendor docs).
"""

from __future__ import annotations

from ..models import Remediation

SERVER_KEYS = ("nginx", "apache", "cloudflare", "generic")

OWASP_HEADERS = "https://owasp.org/www-project-secure-headers/"
MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers"


def _r(why: str, snippets: dict[str, str], references: list[str]) -> dict:
    # Ensure every entry can resolve to *something* for every server key.
    if "generic" not in snippets:
        raise ValueError("remediation must define a 'generic' snippet")
    return {"why": why, "snippets": snippets, "references": references}


REMEDIATIONS: dict[str, dict] = {
    # ----------------------------------------------------------------- headers
    "missing-hsts": _r(
        "HSTS prevents protocol-downgrade and cookie-hijacking by forcing "
        "browsers to use HTTPS only.",
        {
            "nginx": 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
            "apache": 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"',
            "cloudflare": "Dashboard -> SSL/TLS -> Edge Certificates -> enable HTTP Strict Transport Security (HSTS) with max-age 12 months and Include subdomains.",
            "generic": 'Send the response header:  Strict-Transport-Security: max-age=31536000; includeSubDomains',
        },
        [
            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
            f"{MDN}/Strict-Transport-Security",
        ],
    ),
    "weak-hsts": _r(
        "A short HSTS lifetime leaves a downgrade window; use at least 6 months "
        "(1 year recommended).",
        {
            "nginx": 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
            "apache": 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"',
            "cloudflare": "Dashboard -> SSL/TLS -> Edge Certificates -> HSTS -> set max-age to 12 months.",
            "generic": "Increase the Strict-Transport-Security max-age to 31536000 (1 year).",
        },
        [
            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
        ],
    ),
    "missing-csp": _r(
        "A Content-Security-Policy is the strongest defence-in-depth against "
        "cross-site scripting.",
        {
            "nginx": "add_header Content-Security-Policy \"default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'\" always;",
            "apache": "Header always set Content-Security-Policy \"default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'\"",
            "cloudflare": "Add a Transform Rule (Modify Response Header) setting Content-Security-Policy to: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'. Tune the policy to your app, then tighten.",
            "generic": "Send a Content-Security-Policy header. Start in report-only mode, tune to your app, then enforce: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
        },
        [
            "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
            f"{MDN}/Content-Security-Policy",
        ],
    ),
    "missing-x-frame-options": _r(
        "Prevents clickjacking by stopping the page being embedded in a hostile "
        "iframe.",
        {
            "nginx": 'add_header X-Frame-Options "SAMEORIGIN" always;\n# Preferred modern equivalent (add to your CSP):\n# add_header Content-Security-Policy "frame-ancestors \'self\'" always;',
            "apache": 'Header always set X-Frame-Options "SAMEORIGIN"\n# Preferred modern equivalent: add frame-ancestors \'self\' to your CSP.',
            "cloudflare": "Add a Transform Rule setting X-Frame-Options to SAMEORIGIN, or add frame-ancestors 'self' to your Content-Security-Policy.",
            "generic": "Send X-Frame-Options: SAMEORIGIN, and/or add frame-ancestors 'self' to your Content-Security-Policy (the modern replacement).",
        },
        [
            "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
            f"{MDN}/X-Frame-Options",
        ],
    ),
    "missing-x-content-type-options": _r(
        "Stops browsers MIME-sniffing responses into an executable type.",
        {
            "nginx": 'add_header X-Content-Type-Options "nosniff" always;',
            "apache": 'Header always set X-Content-Type-Options "nosniff"',
            "cloudflare": "Add a Transform Rule setting X-Content-Type-Options to nosniff.",
            "generic": "Send the header:  X-Content-Type-Options: nosniff",
        },
        [f"{MDN}/X-Content-Type-Options", OWASP_HEADERS],
    ),
    "missing-referrer-policy": _r(
        "Stops sensitive URLs leaking to third parties via the Referer header.",
        {
            "nginx": 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
            "apache": 'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
            "cloudflare": "Add a Transform Rule setting Referrer-Policy to strict-origin-when-cross-origin.",
            "generic": "Send the header:  Referrer-Policy: strict-origin-when-cross-origin",
        },
        [f"{MDN}/Referrer-Policy", OWASP_HEADERS],
    ),
    "missing-permissions-policy": _r(
        "Disables powerful browser features your site does not use, shrinking the "
        "attack surface.",
        {
            "nginx": 'add_header Permissions-Policy "geolocation=(), camera=(), microphone=()" always;',
            "apache": 'Header always set Permissions-Policy "geolocation=(), camera=(), microphone=()"',
            "cloudflare": "Add a Transform Rule setting Permissions-Policy to: geolocation=(), camera=(), microphone=()",
            "generic": "Send the header:  Permissions-Policy: geolocation=(), camera=(), microphone=()",
        },
        [f"{MDN}/Permissions-Policy", OWASP_HEADERS],
    ),
    # --------------------------------------------------------------------- TLS
    "no-https": _r(
        "Plaintext HTTP can be read and modified by anyone on the network path.",
        {
            "nginx": "server {\n    listen 80;\n    server_name example.com;\n    return 301 https://$host$request_uri;\n}\n# Then serve the site on listen 443 ssl; with a valid certificate (e.g. certbot).",
            "apache": "<VirtualHost *:80>\n    ServerName example.com\n    Redirect permanent / https://example.com/\n</VirtualHost>\n# Obtain a certificate with certbot and enable the :443 vhost.",
            "cloudflare": "Dashboard -> SSL/TLS -> Overview -> set mode to Full (strict), then enable 'Always Use HTTPS' under Edge Certificates.",
            "generic": "Obtain a TLS certificate (e.g. free via Let's Encrypt / certbot) and 301-redirect all HTTP traffic to HTTPS.",
        },
        ["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"],
    ),
    "tls-deprecated-protocol": _r(
        "TLS 1.0/1.1 and SSL are broken and enable downgrade/decryption attacks.",
        {
            "nginx": "ssl_protocols TLSv1.2 TLSv1.3;",
            "apache": "SSLProtocol -all +TLSv1.2 +TLSv1.3",
            "cloudflare": "Dashboard -> SSL/TLS -> Edge Certificates -> Minimum TLS Version -> set to TLS 1.2.",
            "generic": "Configure the server to accept only TLS 1.2 and TLS 1.3; disable SSLv2/3 and TLS 1.0/1.1.",
        },
        ["https://wiki.mozilla.org/Security/Server_Side_TLS"],
    ),
    "tls-no-forward-secrecy": _r(
        "Without forward secrecy, a future key compromise decrypts all past "
        "recorded traffic.",
        {
            "nginx": "ssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers off;\nssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;",
            "apache": "SSLProtocol -all +TLSv1.2 +TLSv1.3\nSSLHonorCipherOrder off\nSSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384",
            "cloudflare": "Cloudflare's edge already negotiates ECDHE (forward-secret) ciphers; ensure SSL/TLS mode is Full (strict) so the origin connection is also modern.",
            "generic": "Prefer ECDHE/DHE cipher suites (e.g. the Mozilla 'intermediate' list) so every session uses ephemeral keys.",
        },
        ["https://ssl-config.mozilla.org/"],
    ),
    "tls-cert-expired": _r(
        "An expired certificate makes the site untrusted and effectively "
        "unusable for visitors.",
        {
            "nginx": "# Renew immediately, e.g. with certbot:\nsudo certbot renew --force-renewal\nsudo systemctl reload nginx",
            "apache": "# Renew immediately, e.g. with certbot:\nsudo certbot renew --force-renewal\nsudo systemctl reload apache2",
            "cloudflare": "Dashboard -> SSL/TLS -> Edge Certificates: confirm a Universal/Advanced certificate is active; for the origin, renew the origin certificate.",
            "generic": "Renew the certificate now and automate renewal (e.g. certbot timer) so it never lapses again.",
        },
        ["https://letsencrypt.org/docs/"],
    ),
    "tls-cert-expiring": _r(
        "A lapsing certificate will take the site offline for all users.",
        {
            "nginx": "# Automate renewal so this never lapses:\nsudo certbot renew --dry-run   # verify the timer works",
            "apache": "# Automate renewal so this never lapses:\nsudo certbot renew --dry-run   # verify the timer works",
            "cloudflare": "Cloudflare auto-renews edge certificates; if you manage the origin cert, schedule automated renewal.",
            "generic": "Renew the certificate and ensure automated renewal is configured and monitored.",
        },
        ["https://letsencrypt.org/docs/"],
    ),
    "tls-hostname-mismatch": _r(
        "Clients cannot verify the server's identity when the certificate does "
        "not match the hostname.",
        {
            "nginx": "# Issue a certificate that covers this hostname (and www/SAN as needed):\nsudo certbot --nginx -d example.com -d www.example.com",
            "apache": "# Issue a certificate that covers this hostname (and www/SAN as needed):\nsudo certbot --apache -d example.com -d www.example.com",
            "cloudflare": "Ensure the hostname is proxied (orange cloud) and covered by the Universal/Advanced certificate; add it as a SAN if using a custom cert.",
            "generic": "Obtain a certificate whose Common Name / SAN list includes the exact hostname being served.",
        },
        ["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"],
    ),
    "tls-chain-issue": _r(
        "An incomplete chain causes verification failures for some clients even "
        "when the leaf certificate is valid.",
        {
            "nginx": "# Use the full-chain file (leaf + intermediates):\nssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;\nssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;",
            "apache": "SSLCertificateFile /etc/letsencrypt/live/example.com/fullchain.pem\nSSLCertificateKeyFile /etc/letsencrypt/live/example.com/privkey.pem",
            "cloudflare": "Set SSL/TLS mode to Full (strict) and install a complete chain on the origin (fullchain), or use a Cloudflare Origin CA certificate.",
            "generic": "Serve the complete certificate chain (leaf plus all intermediates) — not just the leaf certificate.",
        },
        ["https://whatsmychaincert.com/"],
    ),
    # ----------------------------------------------------------------- cookies
    "cookie-missing-secure": _r(
        "Without Secure, cookies can be sent over plaintext HTTP and captured.",
        {
            "nginx": "# Set Secure in your application when issuing cookies, or for proxied\n# upstreams rewrite them:\nproxy_cookie_flags ~ secure samesite=lax;",
            "apache": "# Apache 2.4.11+: force Secure on all Set-Cookie headers:\nHeader always edit Set-Cookie ^(.*)$ \"$1; Secure\"",
            "cloudflare": "Set the Secure attribute in your application code; Cloudflare cannot reliably add it to arbitrary Set-Cookie headers.",
            "generic": "Add the Secure attribute to every cookie (best done in application code where the cookie is set).",
        },
        ["https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"],
    ),
    "cookie-missing-httponly": _r(
        "Cookies without HttpOnly are readable by JavaScript, so any XSS can "
        "steal session tokens.",
        {
            "nginx": "# Best set in application code. For proxied upstreams:\nproxy_cookie_flags ~ httponly;",
            "apache": 'Header always edit Set-Cookie ^(.*)$ "$1; HttpOnly"',
            "cloudflare": "Set HttpOnly in your application code when issuing the cookie.",
            "generic": "Add the HttpOnly attribute to session/auth cookies (set it in application code).",
        },
        ["https://owasp.org/www-community/HttpOnly"],
    ),
    "cookie-missing-samesite": _r(
        "An explicit SameSite attribute reduces cross-site request forgery risk.",
        {
            "nginx": "proxy_cookie_flags ~ samesite=lax;",
            "apache": 'Header always edit Set-Cookie ^(.*)$ "$1; SameSite=Lax"',
            "cloudflare": "Set SameSite=Lax (or Strict) in your application code when issuing cookies.",
            "generic": "Add SameSite=Lax (or Strict for sensitive cookies) to every cookie.",
        },
        [f"{MDN}/Set-Cookie/SameSite"],
    ),
    # ------------------------------------------------------------- disclosure
    "server-version-banner": _r(
        "Exposing exact software versions helps attackers match your stack to "
        "known exploits.",
        {
            "nginx": "server_tokens off;   # in the http {} block",
            "apache": "ServerTokens Prod\nServerSignature Off",
            "cloudflare": "Add a Transform Rule (Modify Response Header) to Remove the Server/version header, or strip it at the origin.",
            "generic": "Suppress or genericise the Server header so it does not reveal the exact version.",
        },
        [OWASP_HEADERS],
    ),
    "x-powered-by-banner": _r(
        "X-Powered-By reveals your framework/runtime and version for no "
        "functional benefit.",
        {
            "nginx": 'proxy_hide_header X-Powered-By;   # when proxying an app\n# or remove it in the application (e.g. Express: app.disable("x-powered-by"))',
            "apache": "Header always unset X-Powered-By",
            "cloudflare": "Add a Transform Rule to Remove the X-Powered-By response header.",
            "generic": "Remove the X-Powered-By header in your application or at the proxy.",
        },
        [OWASP_HEADERS],
    ),
    "exposed-git": _r(
        "An exposed .git directory lets anyone download your full source code and "
        "any committed secrets.",
        {
            "nginx": "location ~ /\\.git { deny all; return 404; }",
            "apache": '<DirectoryMatch "/\\.git">\n    Require all denied\n</DirectoryMatch>',
            "cloudflare": "Create a WAF custom rule to block requests whose URI path contains /.git, and remove the directory from the web root.",
            "generic": "Remove the .git directory from the web root and deny access to dotfiles/VCS directories.",
        },
        ["https://owasp.org/www-community/attacks/Forced_browsing"],
    ),
    "exposed-env": _r(
        "A readable .env file usually exposes credentials and API keys — a direct "
        "path to full compromise.",
        {
            "nginx": "location ~ /\\.(env|git|svn|ht) { deny all; return 404; }",
            "apache": '<FilesMatch "^\\.env">\n    Require all denied\n</FilesMatch>',
            "cloudflare": "Add a WAF rule to block paths ending in .env, AND move the file outside the web root and rotate every exposed secret.",
            "generic": "Move .env outside the web root, deny access to dotfiles, and rotate every secret that was exposed.",
        },
        ["https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"],
    ),
    "directory-listing": _r(
        "Automatic directory listings expose file names and structure, often "
        "revealing backups or source.",
        {
            "nginx": "autoindex off;",
            "apache": "Options -Indexes",
            "cloudflare": "Disable directory listing at the origin (autoindex off / Options -Indexes); Cloudflare serves what the origin returns.",
            "generic": "Disable automatic directory indexing on the web server.",
        },
        ["https://owasp.org/www-community/attacks/Forced_browsing"],
    ),
    # ------------------------------------------------------------- dns / email
    "missing-spf": _r(
        "Without SPF, attackers can more easily spoof email from your domain.",
        {
            "nginx": 'Publish a DNS TXT record at the apex:\nexample.com.  IN TXT "v=spf1 include:_spf.yourprovider.com -all"',
            "apache": 'Publish a DNS TXT record at the apex:\nexample.com.  IN TXT "v=spf1 include:_spf.yourprovider.com -all"',
            "cloudflare": 'Dashboard -> DNS -> Records -> Add TXT record, Name "@", Content: v=spf1 include:_spf.yourprovider.com -all',
            "generic": 'Add a TXT record at the domain apex: v=spf1 include:_spf.yourprovider.com -all  (list the senders you use, end with -all).',
        },
        ["https://cheatsheetseries.owasp.org/cheatsheets/Email_Spoofing_Prevention.html"],
    ),
    "missing-dmarc": _r(
        "DMARC instructs receivers how to handle spoofed mail and reports abuse "
        "back to you.",
        {
            "nginx": 'Publish a TXT record:\n_dmarc.example.com.  IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"',
            "apache": 'Publish a TXT record:\n_dmarc.example.com.  IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"',
            "cloudflare": 'Dashboard -> DNS -> Add TXT record, Name "_dmarc", Content: v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com',
            "generic": 'Add a TXT record at _dmarc.<domain>: v=DMARC1; p=quarantine; rua=mailto:you@domain  (start with p=none to monitor, then tighten).',
        },
        ["https://cheatsheetseries.owasp.org/cheatsheets/Email_Spoofing_Prevention.html"],
    ),
    "missing-caa": _r(
        "A CAA record restricts which certificate authorities may issue certs for "
        "your domain.",
        {
            "nginx": 'Publish a CAA record:\nexample.com.  IN CAA 0 issue "letsencrypt.org"',
            "apache": 'Publish a CAA record:\nexample.com.  IN CAA 0 issue "letsencrypt.org"',
            "cloudflare": "Dashboard -> DNS -> Add record -> Type CAA -> Tag: issue -> CA domain: letsencrypt.org (add one per CA you use).",
            "generic": 'Add a CAA record naming each CA you use, e.g.: 0 issue "letsencrypt.org"',
        },
        ["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"],
    ),
    "missing-dkim": _r(
        "DKIM cryptographically signs outgoing mail and is required for a strong "
        "DMARC posture.",
        {
            "nginx": "Enable DKIM with your mail provider, then publish the selector TXT record they give you (e.g. selector._domainkey.example.com).",
            "apache": "Enable DKIM with your mail provider, then publish the selector TXT record they give you (e.g. selector._domainkey.example.com).",
            "cloudflare": "Add the DKIM TXT record from your mail provider under DNS (name like selector._domainkey).",
            "generic": "Turn on DKIM signing at your mail provider and publish the provided selector record in DNS.",
        },
        ["https://cheatsheetseries.owasp.org/cheatsheets/Email_Spoofing_Prevention.html"],
    ),
    # ----------------------------------------------------------------- content
    "mixed-content": _r(
        "HTTP sub-resources on an HTTPS page can be tampered with and may be "
        "blocked by browsers.",
        {
            "nginx": '# Serve all assets over HTTPS, then optionally enforce upgrades:\nadd_header Content-Security-Policy "upgrade-insecure-requests" always;',
            "apache": 'Header always set Content-Security-Policy "upgrade-insecure-requests"',
            "cloudflare": "Dashboard -> SSL/TLS -> Edge Certificates -> enable 'Automatic HTTPS Rewrites', and fix hard-coded http:// asset URLs.",
            "generic": "Change every sub-resource URL to https:// (or protocol-relative) and add 'upgrade-insecure-requests' to your CSP.",
        },
        [f"{MDN}/CSP/upgrade-insecure-requests"],
    ),
    "missing-sri": _r(
        "Without an integrity hash, a compromised CDN can serve malicious script "
        "your page will trust.",
        {
            "nginx": 'Add integrity + crossorigin attributes to external <script>/<link> tags, e.g.:\n<script src="https://cdn.example/lib.js" integrity="sha384-..." crossorigin="anonymous"></script>',
            "apache": 'Add integrity + crossorigin attributes to external <script>/<link> tags, e.g.:\n<script src="https://cdn.example/lib.js" integrity="sha384-..." crossorigin="anonymous"></script>',
            "cloudflare": "Add Subresource Integrity (integrity + crossorigin) attributes to externally-hosted scripts and styles in your HTML.",
            "generic": "Add an SRI integrity attribute (and crossorigin) to every externally-hosted script and stylesheet.",
        },
        ["https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html", f"{MDN}/Subresource_Integrity"],
    ),
    # ------------------------------------------------------------- fingerprint
    "outdated-component": _r(
        "Outdated client libraries often carry publicly-known, easily-exploited "
        "vulnerabilities.",
        {
            "nginx": "Upgrade the library to a currently-supported release and re-deploy your assets.",
            "apache": "Upgrade the library to a currently-supported release and re-deploy your assets.",
            "cloudflare": "Upgrade the library at the origin to a supported release; serving it via Cloudflare does not patch it.",
            "generic": "Upgrade the component to a supported version and add it to a regular dependency-update process.",
        },
        ["https://owasp.org/www-project-top-ten/2021/A06_2021-Vulnerable_and_Outdated_Components/"],
    ),
    # ---------------------------------------------- informational / advisory
    "tech-fingerprint": _r(
        "Informational only — knowing your own exposed stack helps you keep it "
        "patched.",
        {
            "nginx": "No action required. Keep all components patched and minimise version disclosure (server_tokens off).",
            "apache": "No action required. Keep all components patched and minimise version disclosure (ServerTokens Prod).",
            "cloudflare": "No action required. Keep origin components patched; consider stripping version headers via Transform Rules.",
            "generic": "No action required. Keep every component current and avoid disclosing exact versions.",
        },
        [OWASP_HEADERS],
    ),
    "tls-handshake-failed": _r(
        "Advisory — the scanner could not complete TLS, so verify the "
        "certificate and protocol settings manually.",
        {
            "nginx": "Verify with:  openssl s_client -connect example.com:443 -servername example.com",
            "apache": "Verify with:  openssl s_client -connect example.com:443 -servername example.com",
            "cloudflare": "Check SSL/TLS -> Overview and ensure mode is Full (strict) with a valid origin certificate.",
            "generic": "Manually verify the TLS configuration (e.g. with openssl s_client or an external SSL test).",
        },
        ["https://ssl-config.mozilla.org/"],
    ),
    "dns-lookup-failed": _r(
        "Advisory — DNS could not be queried, so email/CAA checks were skipped.",
        {
            "nginx": "Verify DNS resolves correctly (e.g. dig example.com) and re-run the scan.",
            "apache": "Verify DNS resolves correctly (e.g. dig example.com) and re-run the scan.",
            "cloudflare": "Confirm the domain's DNS is active in the Cloudflare dashboard, then re-run the scan.",
            "generic": "Confirm the domain resolves publicly, then re-run the scan to evaluate SPF/DMARC/CAA.",
        },
        [],
    ),
}

# Generic fallback for any finding id without a bespoke entry.
_FALLBACK = _r(
    "Review this finding against current security best practice for your stack.",
    {
        "nginx": "Consult the referenced guidance and apply the recommended nginx configuration.",
        "apache": "Consult the referenced guidance and apply the recommended Apache configuration.",
        "cloudflare": "Consult the referenced guidance and apply the recommended Cloudflare settings.",
        "generic": "Consult the referenced guidance and apply the recommended configuration for your server.",
    },
    [OWASP_HEADERS],
)


def resolve_remediation(finding_id: str, detected_server: str) -> Remediation:
    """Return a :class:`Remediation` for *finding_id* tailored to *detected_server*.

    Falls back to a generic-but-useful entry for unknown ids, and to the
    ``generic`` snippet for unknown servers.
    """
    data = REMEDIATIONS.get(finding_id, _FALLBACK)
    server = detected_server if detected_server in SERVER_KEYS else "generic"
    snippets = dict(data["snippets"])
    # Guarantee all four keys exist so the UI can always offer every variant.
    for key in SERVER_KEYS:
        snippets.setdefault(key, snippets.get("generic", ""))
    return Remediation(
        why=data["why"],
        snippets=snippets,
        references=list(data["references"]),
        detected=server,
    )
