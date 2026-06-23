/* websec-scanner front-end.
 *
 * Security note: every value rendered here originates from a scanned (hostile)
 * site. We build DOM with document.createElement + textContent ONLY — never
 * innerHTML with scan data — so the report cannot be XSS'd by a malicious target.
 */
"use strict";

(function () {
  const $ = (sel, root) => (root || document).querySelector(sel);

  const form = $("#scan-form");
  const urlInput = $("#url");
  const urlError = $("#url-error");
  const authBox = $("#authorized");
  const consentError = $("#consent-error");
  const serverSel = $("#server");
  const submitBtn = $("#submit");

  const states = {
    empty: $("#state-empty"),
    progress: $("#state-progress"),
    error: $("#state-error"),
    result: $("#state-result"),
  };
  const progressBar = $("#progress-bar");
  const progressMsg = $("#progress-msg");
  const progressLog = $("#progress-log");
  const progressEl = $(".progress");
  const cancelBtn = $("#cancel");
  const retryBtn = $("#retry");
  const errorMsg = $("#error-msg");

  const findingsEl = $("#findings");
  const chipsEl = $("#chips");
  const findingTmpl = $("#tmpl-finding");

  const SEV = {
    critical: { glyph: "▲▲", label: "Critical" },
    high: { glyph: "▲", label: "High" },
    medium: { glyph: "■", label: "Medium" },
    low: { glyph: "●", label: "Low" },
    info: { glyph: "ℹ", label: "Info" },
  };
  const SERVER_LABEL = { nginx: "nginx", apache: "Apache", cloudflare: "Cloudflare", generic: "Generic" };
  const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

  let controller = null;

  function show(name) {
    Object.keys(states).forEach((k) => { states[k].hidden = k !== name; });
  }

  // ---- validation -------------------------------------------------------
  function validUrl(value) {
    if (!value) return false;
    let v = value.trim();
    if (!/^https?:\/\//i.test(v)) v = "https://" + v;
    try {
      const u = new URL(v);
      return u.protocol === "http:" || u.protocol === "https:";
    } catch (e) {
      return false;
    }
  }

  function setUrlError(msg) {
    if (msg) {
      urlError.textContent = msg;
      urlError.hidden = false;
      urlInput.setAttribute("aria-invalid", "true");
    } else {
      urlError.hidden = true;
      urlInput.removeAttribute("aria-invalid");
    }
  }

  urlInput.addEventListener("input", () => setUrlError(""));
  authBox.addEventListener("change", () => { consentError.hidden = true; });

  // ---- copy -------------------------------------------------------------
  function attachCopy(btn, getText) {
    btn.addEventListener("click", async () => {
      const text = getText();
      try {
        await navigator.clipboard.writeText(text);
      } catch (e) {
        // Fallback for browsers without clipboard API / insecure context.
        const ta = document.createElement("textarea");
        ta.value = text; document.body.appendChild(ta); ta.select();
        try { document.execCommand("copy"); } catch (_) {}
        document.body.removeChild(ta);
      }
      const old = btn.textContent;
      btn.textContent = "Copied";
      btn.classList.add("copied");
      setTimeout(() => { btn.textContent = old; btn.classList.remove("copied"); }, 1400);
    });
  }

  // ---- rendering (XSS-safe) ---------------------------------------------
  function renderChips(counts) {
    chipsEl.textContent = "";
    SEV_ORDER.forEach((s) => {
      const n = counts[s] || 0;
      const chip = document.createElement("span");
      chip.className = "chip chip-" + s + (n === 0 ? " is-zero" : "");
      const g = document.createElement("span");
      g.className = "g"; g.setAttribute("aria-hidden", "true");
      g.textContent = SEV[s].glyph;
      chip.appendChild(g);
      chip.appendChild(document.createTextNode(" " + n + " " + SEV[s].label));
      chipsEl.appendChild(chip);
    });
  }

  function renderRemediation(node, finding) {
    const rem = finding.remediation;
    const wrap = $(".remediation", node);
    if (!rem) { wrap.hidden = true; return; }
    wrap.hidden = false;
    $(".why-text", node).textContent = rem.why;

    const tabsEl = $(".rtabs", node);
    const codeEl = $(".snippet-code", node);
    const order = ["nginx", "apache", "cloudflare", "generic"];
    const available = order.filter((k) => rem.snippets[k]);
    let current = available.includes(rem.detected) ? rem.detected : available[0];

    function paint() {
      codeEl.textContent = rem.snippets[current] || "";
      Array.from(tabsEl.children).forEach((b) => {
        const active = b.dataset.server === current;
        b.classList.toggle("is-active", active);
        b.setAttribute("aria-selected", active ? "true" : "false");
      });
    }

    tabsEl.textContent = "";
    available.forEach((k) => {
      const b = document.createElement("button");
      b.type = "button"; b.className = "rtab"; b.setAttribute("role", "tab");
      b.dataset.server = k;
      b.textContent = SERVER_LABEL[k] + (k === rem.detected ? " · detected" : "");
      b.addEventListener("click", () => { current = k; paint(); });
      tabsEl.appendChild(b);
    });
    paint();
    attachCopy($(".copy-btn", node), () => rem.snippets[current] || "");

    const refsEl = $(".refs", node);
    refsEl.textContent = "";
    const refs = (finding.references || []).concat(rem.references || []);
    Array.from(new Set(refs)).forEach((u) => {
      const li = document.createElement("li");
      const a = document.createElement("a");
      a.href = u; a.textContent = u;
      a.rel = "noopener noreferrer nofollow"; a.target = "_blank";
      li.appendChild(a);
      refsEl.appendChild(li);
    });
  }

  function renderFinding(finding) {
    const frag = findingTmpl.content.cloneNode(true);
    const article = $(".finding", frag);
    const sev = finding.severity;
    article.dataset.sev = sev;
    article.dataset.severity = sev;

    const badge = $(".badge", frag);
    badge.dataset.sev = sev;
    $(".badge-glyph", frag).textContent = SEV[sev].glyph;
    $(".badge-label", frag).textContent = finding.severity_label || SEV[sev].label;

    $(".finding-title", frag).textContent = finding.title;
    $(".finding-cat", frag).textContent = finding.category;
    $(".finding-desc", frag).textContent = finding.description || "";
    $(".evidence-code", frag).textContent = finding.evidence || "";

    renderRemediation(frag, finding);
    return article;
  }

  function renderResult(data) {
    const r = data.result;
    show("result");

    const card = $("#grade-card");
    card.className = "grade-card grade-" + (r.grade || "f").toLowerCase();
    card.setAttribute("aria-label", "Overall grade " + r.grade + ", score " + r.score + " out of 100");
    $("#grade-letter").textContent = r.grade;
    $("#grade-score").textContent = r.score + "/100";

    $("#result-target").textContent = r.target;
    const issues = (r.findings || []).filter((f) => f.severity !== "info").length;
    $("#result-sub").textContent =
      "Detected server: " + (SERVER_LABEL[r.detected_server] || r.detected_server) +
      " · " + issues + " issue(s) · scanned in " + r.duration_seconds + "s";

    renderChips(r.counts || {});

    const dl = $("#download");
    dl.href = "/report/" + encodeURIComponent(data.id);

    findingsEl.textContent = "";
    (r.findings || []).forEach((f) => findingsEl.appendChild(renderFinding(f)));
    applyFilter(currentFilter);
  }

  // ---- filtering --------------------------------------------------------
  let currentFilter = "all";
  function applyFilter(name) {
    currentFilter = name;
    Array.from(findingsEl.children).forEach((el) => {
      el.hidden = !(name === "all" || el.dataset.severity === name);
    });
    document.querySelectorAll(".filter").forEach((b) => {
      const active = b.dataset.filter === name;
      b.classList.toggle("is-active", active);
      b.setAttribute("aria-selected", active ? "true" : "false");
    });
  }
  document.querySelectorAll(".filter").forEach((b) => {
    b.addEventListener("click", () => applyFilter(b.dataset.filter));
  });

  // ---- progress ---------------------------------------------------------
  function setProgress(pct, msg) {
    progressBar.style.width = pct + "%";
    progressEl.setAttribute("aria-valuenow", String(pct));
    if (msg) {
      progressMsg.textContent = msg;
      const li = document.createElement("li");
      li.textContent = msg;
      progressLog.appendChild(li);
      progressLog.scrollTop = progressLog.scrollHeight;
    }
  }

  function setLoading(on) {
    submitBtn.disabled = on;
    submitBtn.classList.toggle("is-loading", on);
  }

  function fail(msg) {
    show("error");
    errorMsg.textContent = msg;
  }

  // ---- submit -----------------------------------------------------------
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    let ok = true;
    if (!validUrl(urlInput.value)) {
      setUrlError("Enter a valid http or https URL, e.g. https://example.com");
      ok = false;
    }
    if (!authBox.checked) {
      consentError.textContent = "You must confirm authorization before scanning.";
      consentError.hidden = false;
      ok = false;
    }
    if (!ok) return;

    setLoading(true);
    show("progress");
    progressLog.textContent = "";
    setProgress(2, "Submitting…");

    controller = new AbortController();
    try {
      const resp = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/x-ndjson" },
        body: JSON.stringify({
          url: urlInput.value.trim(),
          authorized: authBox.checked,
          server: serverSel.value,
        }),
        signal: controller.signal,
      });

      if (!resp.ok) {
        let m = "The scan request was rejected.";
        try { const j = await resp.json(); if (j && j.error) m = j.error; } catch (e) {}
        setLoading(false);
        fail(m);
        return;
      }

      // Stream NDJSON progress events.
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      let gotResult = false;
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        let nl;
        while ((nl = buf.indexOf("\n")) >= 0) {
          const line = buf.slice(0, nl).trim();
          buf = buf.slice(nl + 1);
          if (!line) continue;
          let evt;
          try { evt = JSON.parse(line); } catch (e) { continue; }
          if (evt.type === "progress") {
            setProgress(evt.pct, evt.message);
          } else if (evt.type === "result") {
            gotResult = true;
            setProgress(100, "Done");
            renderResult(evt);
          } else if (evt.type === "error") {
            fail(evt.message || "The scan failed.");
          }
        }
      }
      if (!gotResult && states.error.hidden) {
        fail("The scan ended unexpectedly. Please try again.");
      }
    } catch (e) {
      if (e.name === "AbortError") {
        show("empty");
      } else {
        fail("Could not reach the scanner. Check your connection and try again.");
      }
    } finally {
      setLoading(false);
      controller = null;
    }
  });

  cancelBtn.addEventListener("click", () => {
    if (controller) controller.abort();
    show("empty");
    setLoading(false);
  });
  retryBtn.addEventListener("click", () => show("empty"));
})();
