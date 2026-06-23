"""Standalone, self-contained, XSS-safe HTML report generator.

Every byte captured from the scanned site is treated as hostile and escaped with
:func:`html.escape` (quote=True) before it touches the document. The report has
no external dependencies so it renders offline when saved to disk.
"""

from __future__ import annotations

from html import escape

from ..models import ScanResult, Severity

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

# Colourblind-safe severity palette (Okabe-Ito derived) — never color alone:
# each severity is also labelled and carries a glyph.
SEV_COLOR = {
    "critical": "#9b2226",
    "high": "#bb5500",
    "medium": "#9a7d00",
    "low": "#2a6f97",
    "info": "#5a5f6a",
}
SEV_GLYPH = {
    "critical": "▲▲",
    "high": "▲",
    "medium": "■",
    "low": "●",
    "info": "ℹ",
}
SERVER_LABEL = {
    "nginx": "nginx",
    "apache": "Apache",
    "cloudflare": "Cloudflare",
    "generic": "Generic",
}


def _e(value: object) -> str:
    return escape(str(value), quote=True)


def render_report(result: ScanResult) -> str:
    """Render *result* into a complete standalone HTML document (string)."""
    counts = result.counts
    findings = result.findings
    real_issues = [f for f in findings if f.severity is not Severity.INFO]

    rows = []
    for f in findings:
        sev = f.severity.slug
        refs = "".join(
            f'<li><a href="{_e(u)}" rel="noopener noreferrer nofollow" target="_blank">{_e(u)}</a></li>'
            for u in (f.references + (f.remediation.references if f.remediation else []))
        )
        snippet_blocks = ""
        if f.remediation:
            detected = f.remediation.detected
            tabs = []
            panes = []
            for key in ("nginx", "apache", "cloudflare", "generic"):
                snip = f.remediation.snippets.get(key, "")
                if not snip:
                    continue
                active = " is-active" if key == detected else ""
                tabs.append(
                    f'<button class="rtab{active}" data-fix="{_e(f.id)}" '
                    f'data-server="{_e(key)}" type="button">{_e(SERVER_LABEL[key])}'
                    f'{" (detected)" if key == detected else ""}</button>'
                )
                panes.append(
                    f'<pre class="snippet{active}" data-fix="{_e(f.id)}" '
                    f'data-server="{_e(key)}"><code>{_e(snip)}</code></pre>'
                )
            snippet_blocks = (
                f'<div class="why"><strong>Why this matters:</strong> '
                f'{_e(f.remediation.why)}</div>'
                f'<div class="rtabs">{"".join(tabs)}</div>'
                f'{"".join(panes)}'
            )

        rows.append(
            f"""
            <article class="finding sev-{_e(sev)}">
              <header class="finding-head">
                <span class="badge badge-{_e(sev)}">
                  <span class="glyph" aria-hidden="true">{_e(SEV_GLYPH[sev])}</span>
                  {_e(f.severity.label)}
                </span>
                <h3>{_e(f.title)}</h3>
                <span class="cat">{_e(f.category)}</span>
              </header>
              <p class="desc">{_e(f.description)}</p>
              <div class="evidence"><span class="lbl">Evidence</span>
                <pre><code>{_e(f.evidence)}</code></pre>
              </div>
              {snippet_blocks}
              {f'<ul class="refs">{refs}</ul>' if refs else ''}
            </article>
            """
        )

    summary_chips = "".join(
        f'<span class="chip chip-{s.slug}">'
        f'<span class="glyph" aria-hidden="true">{SEV_GLYPH[s.slug]}</span> '
        f'{counts.get(s.slug, 0)} {s.label}</span>'
        for s in SEVERITY_ORDER
    )

    notes_html = ""
    if result.notes:
        notes_html = (
            '<div class="notes"><strong>Scanner notes:</strong><ul>'
            + "".join(f"<li>{_e(n)}</li>" for n in result.notes)
            + "</ul></div>"
        )

    grade = _e(result.grade)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security report — {_e(result.target)}</title>
<style>{_REPORT_CSS}</style>
</head>
<body>
<main class="report">
  <header class="report-head">
    <div>
      <p class="kicker">Passive security report</p>
      <h1>{_e(result.target)}</h1>
      <p class="meta">Scanned {_e(result.finished_at.strftime('%Y-%m-%d %H:%M UTC'))}
        &middot; detected server: {_e(SERVER_LABEL.get(result.detected_server, result.detected_server))}
        &middot; {len(real_issues)} issue(s)</p>
    </div>
    <div class="grade grade-{grade.lower()}" role="img"
         aria-label="Overall grade {grade}, score {result.score} out of 100">
      <span class="grade-letter">{grade}</span>
      <span class="grade-score">{result.score}/100</span>
    </div>
  </header>

  <section class="chips" aria-label="Findings by severity">{summary_chips}</section>
  {notes_html}

  <section class="findings">
    {''.join(rows) if rows else '<p class="empty">No findings were reported.</p>'}
  </section>

  <footer class="report-foot">
    <p><strong>Scope &amp; honesty.</strong> This automated scan covers
    configuration and surface-level issues (headers, TLS, cookies, DNS/email,
    information disclosure, outdated components). It <em>cannot</em> find
    business-logic flaws, authentication/authorization bypasses, or most
    injection vulnerabilities — those require manual testing. A passing grade is
    not a guarantee of security.</p>
    <p class="legal">Generated by websec-scanner for authorized, defensive use
    only. Scanning systems without authorization may be illegal.</p>
  </footer>
</main>
<script>{_REPORT_JS}</script>
</body>
</html>
"""


_REPORT_CSS = """
:root{
  --bg:#0f1216; --panel:#171b21; --panel-2:#1d222a; --border:#2a313b;
  --ink:#e7ebf0; --ink-dim:#9aa4b2; --accent:#3a8fb7;
  --crit:#e5616a; --high:#e08a3c; --med:#d8b84a; --low:#5aa9d6; --info:#9aa4b2;
  --mono:ui-monospace,"SFMono-Regular",Menlo,Consolas,monospace;
  --sans:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  --sp:16px; --radius:10px;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);
  line-height:1.55;font-size:15px}
.report{max-width:920px;margin:0 auto;padding:32px 20px 64px}
a{color:var(--low)}
.report-head{display:flex;justify-content:space-between;align-items:flex-start;
  gap:24px;border-bottom:1px solid var(--border);padding-bottom:24px;
  flex-wrap:wrap}
.kicker{text-transform:uppercase;letter-spacing:.12em;font-size:11px;
  color:var(--ink-dim);margin:0 0 6px}
h1{font-size:22px;margin:0;word-break:break-all}
.meta{color:var(--ink-dim);font-size:13px;margin:8px 0 0}
.grade{min-width:120px;text-align:center;border-radius:14px;padding:14px 18px;
  border:1px solid var(--border);background:var(--panel)}
.grade-letter{display:block;font-size:52px;font-weight:700;line-height:1}
.grade-score{display:block;color:var(--ink-dim);font-size:13px;margin-top:4px}
.grade-a{border-color:#2f6f4f;background:#13251c}
.grade-b{border-color:#3a6f4a;background:#16231a}
.grade-c{border-color:#7a6a2a;background:#22200f}
.grade-d{border-color:#7a4a2a;background:#241710}
.grade-f{border-color:#7a2f33;background:#241013}
.chips{display:flex;gap:10px;flex-wrap:wrap;margin:24px 0}
.chip{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--border);
  background:var(--panel);border-radius:999px;padding:6px 12px;font-size:13px}
.chip .glyph{font-size:11px}
.chip-critical{border-color:var(--crit)} .chip-high{border-color:var(--high)}
.chip-medium{border-color:var(--med)} .chip-low{border-color:var(--low)}
.notes{background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);
  padding:12px 16px;margin:16px 0;color:var(--ink-dim);font-size:13px}
.findings{display:flex;flex-direction:column;gap:16px;margin-top:8px}
.finding{background:var(--panel);border:1px solid var(--border);
  border-left:4px solid var(--border);border-radius:var(--radius);padding:18px 20px}
.finding.sev-critical{border-left-color:var(--crit)}
.finding.sev-high{border-left-color:var(--high)}
.finding.sev-medium{border-left-color:var(--med)}
.finding.sev-low{border-left-color:var(--low)}
.finding.sev-info{border-left-color:var(--info)}
.finding-head{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.finding-head h3{font-size:16px;margin:0;flex:1 1 240px}
.cat{color:var(--ink-dim);font-size:12px;text-transform:uppercase;
  letter-spacing:.08em}
.badge{display:inline-flex;align-items:center;gap:6px;font-size:12px;
  font-weight:600;padding:3px 9px;border-radius:6px;border:1px solid}
.badge .glyph{font-size:10px}
.badge-critical{color:var(--crit);border-color:var(--crit)}
.badge-high{color:var(--high);border-color:var(--high)}
.badge-medium{color:var(--med);border-color:var(--med)}
.badge-low{color:var(--low);border-color:var(--low)}
.badge-info{color:var(--info);border-color:var(--info)}
.desc{margin:10px 0;color:var(--ink)}
.evidence .lbl,.why strong{font-size:12px;text-transform:uppercase;
  letter-spacing:.08em;color:var(--ink-dim)}
pre{background:var(--panel-2);border:1px solid var(--border);border-radius:8px;
  padding:12px 14px;overflow:auto;font-family:var(--mono);font-size:13px;margin:6px 0}
.why{margin:14px 0 8px}
.rtabs{display:flex;gap:6px;flex-wrap:wrap;margin:6px 0}
.rtab{background:var(--panel-2);color:var(--ink-dim);border:1px solid var(--border);
  border-radius:6px;padding:5px 11px;font-size:12px;cursor:pointer}
.rtab.is-active{color:var(--ink);border-color:var(--accent);background:#10222b}
.snippet{display:none}
.snippet.is-active{display:block}
.refs{margin:10px 0 0;padding-left:18px;font-size:13px;color:var(--ink-dim)}
.report-foot{margin-top:40px;border-top:1px solid var(--border);padding-top:20px;
  color:var(--ink-dim);font-size:13px}
.legal{font-style:italic}
.empty{color:var(--ink-dim)}
@media (max-width:560px){.report-head{flex-direction:column}.grade{align-self:stretch}}
"""

_REPORT_JS = """
document.addEventListener('click',function(ev){
  var t=ev.target;
  if(!t.classList||!t.classList.contains('rtab'))return;
  var id=t.getAttribute('data-fix'), srv=t.getAttribute('data-server');
  document.querySelectorAll('.rtab[data-fix="'+id+'"]').forEach(function(b){
    b.classList.toggle('is-active', b.getAttribute('data-server')===srv);});
  document.querySelectorAll('.snippet[data-fix="'+id+'"]').forEach(function(p){
    p.classList.toggle('is-active', p.getAttribute('data-server')===srv);});
});
"""
