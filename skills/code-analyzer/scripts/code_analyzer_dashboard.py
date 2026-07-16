#!/usr/bin/env python3
"""Self-contained HTML dashboard rendering for Code Analyzer reports."""

from __future__ import annotations

import json
from typing import Any, Dict, Optional


def _json_for_html(value: Dict[str, Any]) -> str:
    """Serialize report data without allowing it to terminate the JSON script tag."""
    payload = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return (
        payload.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def html_report(summary: Dict[str, Any], max_findings: Optional[int] = None) -> str:
    """Render every normalized result in one offline HTML file.

    ``max_findings`` is retained for compatibility with the original renderer.
    It now limits only the Markdown report; the dashboard always carries the
    complete normalized result set and paginates findings in the browser.
    """
    del max_findings
    return _DASHBOARD_TEMPLATE.replace("__CODE_ANALYZER_DATA__", _json_for_html(summary))


_DASHBOARD_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <title>Code Analyzer Dashboard</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f3f6fb;
      --surface: #ffffff;
      --surface-soft: #f8fafc;
      --ink: #152033;
      --muted: #5f6c80;
      --line: #d8dfeb;
      --brand: #2447d8;
      --brand-soft: #e9edff;
      --critical: #8c1d40;
      --high: #c2392d;
      --medium: #b36800;
      --low: #2774a6;
      --info: #557083;
      --unknown: #6b7280;
      --ok: #16734a;
      --warning: #a45b00;
      --danger: #b42318;
      --shadow: 0 12px 32px rgba(28, 45, 80, .08);
    }
    * { box-sizing: border-box; }
    html { scroll-behavior: smooth; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font: 14px/1.5 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    a { color: var(--brand); }
    button, input, select { font: inherit; }
    button, select, input {
      border: 1px solid var(--line);
      border-radius: .55rem;
      background: var(--surface);
      color: var(--ink);
      padding: .55rem .7rem;
    }
    button { cursor: pointer; }
    button:hover:not(:disabled) { border-color: var(--brand); }
    button:disabled { cursor: not-allowed; opacity: .5; }
    :focus-visible { outline: 3px solid rgba(36, 71, 216, .3); outline-offset: 2px; }
    .hero {
      color: #fff;
      background: linear-gradient(135deg, #121d35 0%, #243d79 70%, #3157c8 100%);
      padding: 2.25rem max(1.25rem, calc((100vw - 1440px) / 2));
    }
    .hero-top { display: flex; justify-content: space-between; align-items: flex-start; gap: 1rem; }
    .eyebrow { margin: 0 0 .3rem; color: #bfcaf0; font-size: .78rem; font-weight: 700; letter-spacing: .12em; text-transform: uppercase; }
    h1 { margin: 0; font-size: clamp(1.8rem, 4vw, 2.8rem); line-height: 1.1; }
    .project { margin: .65rem 0 0; color: #dbe3ff; overflow-wrap: anywhere; }
    .hero-meta { display: flex; flex-wrap: wrap; gap: .55rem 1.2rem; margin-top: 1.25rem; color: #dbe3ff; }
    .hero a { color: #fff; }
    .nav {
      position: sticky;
      top: 0;
      z-index: 10;
      display: flex;
      gap: .35rem;
      overflow-x: auto;
      background: rgba(255, 255, 255, .96);
      border-bottom: 1px solid var(--line);
      padding: .6rem max(1.25rem, calc((100vw - 1440px) / 2));
      backdrop-filter: blur(10px);
    }
    .nav a { color: var(--ink); text-decoration: none; padding: .4rem .65rem; border-radius: .45rem; white-space: nowrap; }
    .nav a:hover { background: var(--brand-soft); color: var(--brand); }
    main { width: min(1440px, calc(100% - 2.5rem)); margin: 1.5rem auto 3rem; }
    section { scroll-margin-top: 4.5rem; margin: 1.5rem 0; }
    .section-head { display: flex; align-items: baseline; justify-content: space-between; gap: 1rem; margin-bottom: .75rem; }
    h2 { margin: 0; font-size: 1.35rem; }
    h3 { margin: 0 0 .8rem; font-size: 1rem; }
    .muted { color: var(--muted); }
    .cards { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: .8rem; }
    .card, .panel, .tool-card {
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: .8rem;
      box-shadow: var(--shadow);
    }
    .card { padding: 1rem; min-height: 7rem; }
    .card-label { color: var(--muted); font-weight: 600; }
    .card-value { display: block; margin-top: .3rem; font-size: 2rem; line-height: 1; font-weight: 750; }
    .card-note { display: block; margin-top: .45rem; color: var(--muted); font-size: .82rem; }
    .chart-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: .8rem; }
    .panel { padding: 1rem; min-width: 0; }
    .bar-chart { display: grid; gap: .65rem; }
    .bar-row { display: grid; grid-template-columns: minmax(6rem, 35%) 1fr auto; align-items: center; gap: .65rem; }
    .bar-label { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .bar-track { height: .65rem; overflow: hidden; border-radius: 999px; background: #e9edf4; }
    .bar-fill { display: block; height: 100%; min-width: 2px; border-radius: inherit; background: var(--brand); }
    .bar-value { color: var(--muted); font-variant-numeric: tabular-nums; }
    .tools { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: .8rem; }
    .tool-card { padding: 1rem; border-top: 4px solid var(--info); }
    .tool-card.status-ok { border-top-color: var(--ok); }
    .tool-card.status-failed, .tool-card.status-timed_out { border-top-color: var(--danger); }
    .tool-card.status-skipped { border-top-color: var(--warning); }
    .tool-title { display: flex; align-items: center; justify-content: space-between; gap: .75rem; }
    .tool-grid { display: grid; grid-template-columns: auto 1fr; gap: .35rem .8rem; margin: .9rem 0; }
    .tool-grid dt { color: var(--muted); }
    .tool-grid dd { margin: 0; overflow-wrap: anywhere; }
    .reason { border-left: 3px solid var(--warning); background: #fff7e7; padding: .55rem .7rem; overflow-wrap: anywhere; }
    .links { display: flex; flex-wrap: wrap; gap: .6rem; }
    .badge {
      display: inline-block;
      border-radius: 999px;
      padding: .16rem .5rem;
      background: #e8edf5;
      color: #344258;
      font-size: .76rem;
      font-weight: 750;
      text-transform: uppercase;
      letter-spacing: .03em;
      white-space: nowrap;
    }
    .badge-critical { background: #f7d8e3; color: var(--critical); }
    .badge-high, .badge-failed, .badge-timed_out { background: #fee4e2; color: var(--danger); }
    .badge-medium, .badge-skipped { background: #fff0cc; color: #845000; }
    .badge-low { background: #dceef9; color: #165d85; }
    .badge-info, .badge-unknown { background: #e8edf5; color: #45566d; }
    .badge-ok { background: #d9f4e7; color: var(--ok); }
    .scope-grid { display: grid; grid-template-columns: minmax(16rem, .8fr) minmax(0, 1.2fr); gap: 1rem; }
    .key-values { display: grid; grid-template-columns: auto 1fr; gap: .45rem 1rem; }
    .key-values dt { color: var(--muted); }
    .key-values dd { margin: 0; overflow-wrap: anywhere; }
    details { margin-top: .8rem; }
    summary { cursor: pointer; font-weight: 650; }
    .file-list { max-height: 22rem; overflow: auto; margin: .75rem 0 0; padding-left: 1.5rem; }
    .file-list li { margin: .18rem 0; overflow-wrap: anywhere; }
    .table-wrap { overflow-x: auto; border: 1px solid var(--line); border-radius: .7rem; background: var(--surface); }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: .65rem .7rem; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }
    th { position: sticky; top: 0; z-index: 1; background: var(--surface-soft); color: #344258; font-size: .78rem; text-transform: uppercase; letter-spacing: .04em; }
    tbody tr:last-child td { border-bottom: 0; }
    tbody tr:hover { background: #f8faff; }
    td.location, td.message { min-width: 14rem; overflow-wrap: anywhere; }
    td.message { min-width: 20rem; }
    .ai-detail { max-width: 32rem; }
    .ai-detail p { margin: .35rem 0; }
    .code-evidence { white-space: pre-wrap; overflow-wrap: anywhere; font: .82rem/1.45 ui-monospace, SFMono-Regular, Consolas, monospace; }
    .controls {
      display: grid;
      grid-template-columns: minmax(14rem, 2fr) repeat(4, minmax(8rem, 1fr)) auto;
      gap: .65rem;
      align-items: end;
      margin-bottom: .75rem;
    }
    .control { display: grid; gap: .25rem; color: var(--muted); font-size: .78rem; font-weight: 650; }
    .control input, .control select { width: 100%; color: var(--ink); font-weight: 400; }
    .filter-state { display: none; align-items: center; justify-content: space-between; gap: .75rem; margin: 0 0 .75rem; padding: .65rem .8rem; border: 1px solid #b8c5f8; border-radius: .6rem; background: var(--brand-soft); }
    .filter-state.active { display: flex; }
    .pagination { display: flex; align-items: center; justify-content: space-between; gap: .75rem; margin-top: .75rem; }
    .pagination-buttons { display: flex; gap: .5rem; }
    .empty { color: var(--muted); padding: 1rem; text-align: center; }
    .footnote { margin-top: 1.25rem; color: var(--muted); font-size: .85rem; }
    @media (max-width: 1050px) {
      .cards { grid-template-columns: repeat(3, minmax(0, 1fr)); }
      .tools { grid-template-columns: 1fr; }
      .controls { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    }
    @media (max-width: 720px) {
      .hero-top, .section-head { display: block; }
      main { width: min(100% - 1.25rem, 1440px); }
      .cards, .chart-grid, .scope-grid, .controls { grid-template-columns: 1fr; }
      .bar-row { grid-template-columns: minmax(5rem, 40%) 1fr auto; }
      .hero-meta { display: grid; gap: .35rem; }
    }
    @media (prefers-reduced-motion: reduce) { html { scroll-behavior: auto; } }
    @media print {
      .nav, .controls, .pagination, button { display: none !important; }
      body { background: #fff; }
      .card, .panel, .tool-card { box-shadow: none; break-inside: avoid; }
    }
  </style>
</head>
<body>
  <header class="hero">
    <div class="hero-top">
      <div>
        <p class="eyebrow">Static analysis report</p>
        <h1>Code Analyzer Dashboard</h1>
        <p class="project" id="project">Loading report…</p>
      </div>
      <a href="summary.json">Open combined JSON</a>
    </div>
    <div class="hero-meta" id="run-meta"></div>
  </header>
  <nav class="nav" aria-label="Dashboard sections">
    <a href="#overview">Overview</a>
    <a href="#distribution">Distribution</a>
    <a href="#tool-status">Tools</a>
    <a href="#ai-review">AI review</a>
    <a href="#scan-scope">Scope</a>
    <a href="#overlap">Overlap</a>
    <a href="#diagnostics">Diagnostics</a>
    <a href="#findings">Findings</a>
  </nav>
  <main>
    <section id="overview">
      <div class="section-head"><h2>Overview</h2><span class="muted">All selected analyzers</span></div>
      <div class="cards" id="summary-cards"></div>
    </section>

    <section id="distribution">
      <div class="section-head"><h2>Finding distribution</h2><span class="muted">Counts are not deduplicated</span></div>
      <div class="chart-grid">
        <article class="panel"><h3>By severity</h3><div class="bar-chart" id="severity-chart"></div></article>
        <article class="panel"><h3>By analyzer</h3><div class="bar-chart" id="tool-chart"></div></article>
        <article class="panel"><h3>Top CWE</h3><div class="bar-chart" id="cwe-chart"></div></article>
        <article class="panel"><h3>Top files</h3><div class="bar-chart" id="file-chart"></div></article>
      </div>
    </section>

    <section id="tool-status">
      <div class="section-head"><h2>Tool status</h2><span class="muted">Reports and raw analyzer logs</span></div>
      <div class="tools" id="tool-cards"></div>
    </section>

    <section id="ai-review" hidden>
      <div class="section-head"><h2>AI review protocol</h2><span class="muted">Independent multi-round evidence</span></div>
      <div class="panel scope-grid">
        <div><h3>Execution</h3><dl class="key-values" id="ai-values"></dl></div>
        <div><h3>Candidate outcomes</h3><div class="bar-chart" id="ai-candidate-chart"></div></div>
      </div>
      <div class="section-head"><h3>Review candidates</h3><span class="muted" id="ai-candidate-count"></span></div>
      <div class="table-wrap"><table><thead><tr><th>Status</th><th>ID</th><th>Category</th><th>Confidence</th><th>Location</th><th>Conclusion</th><th>Verification</th></tr></thead><tbody id="ai-candidate-body"></tbody></table></div>
    </section>

    <section id="scan-scope">
      <div class="section-head"><h2>Scan scope</h2><span class="muted">Shared source manifest</span></div>
      <div class="panel scope-grid">
        <div><dl class="key-values" id="scope-values"></dl><details id="source-details"><summary id="source-summary">Source files</summary><ol class="file-list" id="source-files"></ol></details></div>
        <div><h3>File types</h3><div class="bar-chart" id="suffix-chart"></div></div>
      </div>
    </section>

    <section id="overlap">
      <div class="section-head"><h2>Cross-tool overlap</h2><span class="muted" id="overlap-count"></span></div>
      <div class="table-wrap"><table><thead><tr><th>Category</th><th>Location</th><th>Tools</th><th>Evidence</th><th>Action</th></tr></thead><tbody id="overlap-body"></tbody></table></div>
    </section>

    <section id="diagnostics">
      <div class="section-head"><h2>Tool diagnostics</h2><span class="muted" id="diagnostic-count"></span></div>
      <div class="table-wrap"><table><thead><tr><th>Severity</th><th>Tool</th><th>Category</th><th>Fatal</th><th>Location</th><th>Message</th></tr></thead><tbody id="diagnostic-body"></tbody></table></div>
    </section>

    <section id="findings">
      <div class="section-head"><h2>Findings</h2><span class="muted" id="finding-total"></span></div>
      <div class="controls">
        <label class="control">Search<input id="search" type="search" placeholder="Rule, CWE, file, or message"></label>
        <label class="control">Severity<select id="severity"><option value="">All severities</option></select></label>
        <label class="control">Analyzer<select id="tool"><option value="">All analyzers</option></select></label>
        <label class="control">CWE<select id="cwe"><option value="">All CWE</option></select></label>
        <label class="control">Sort<select id="sort"><option value="priority">Priority</option><option value="location">Location</option><option value="tool">Analyzer</option><option value="rule">Rule</option></select></label>
        <button id="reset" type="button">Reset</button>
      </div>
      <div class="filter-state" id="overlap-filter"><span id="overlap-filter-label"></span><button id="clear-overlap" type="button">Clear overlap filter</button></div>
      <div class="table-wrap"><table><thead><tr><th>Severity</th><th>Analyzer</th><th>Rule</th><th>CWE</th><th>Location</th><th>Message</th><th>Evidence</th></tr></thead><tbody id="finding-body"></tbody></table></div>
      <div class="pagination">
        <span class="muted" id="page-status" aria-live="polite"></span>
        <div class="pagination-buttons">
          <label class="control">Rows<select id="page-size"><option>25</option><option selected>50</option><option>100</option><option>250</option></select></label>
          <button id="previous" type="button">Previous</button><button id="next" type="button">Next</button>
        </div>
      </div>
      <p class="footnote">Static-analysis findings require confirmation against the source and build configuration before code changes.</p>
    </section>
  </main>
  <noscript><p class="empty">JavaScript is required to render this offline dashboard. The complete report remains available in <a href="summary.json">summary.json</a>.</p></noscript>
  <script id="report-data" type="application/json">__CODE_ANALYZER_DATA__</script>
  <script>
  "use strict";
  (() => {
    const report = JSON.parse(document.getElementById("report-data").textContent);
    const byId = (id) => document.getElementById(id);
    const number = (value) => new Intl.NumberFormat().format(Number(value || 0));
    const make = (tag, className, value) => {
      const node = document.createElement(tag);
      if (className) node.className = className;
      if (value !== undefined && value !== null) node.textContent = String(value);
      return node;
    };
    const appendPair = (list, label, value) => {
      list.append(make("dt", "", label), make("dd", "", value === "" || value === null || value === undefined ? "—" : value));
    };
    const location = (item) => {
      const file = item.canonical_path || item.file || "<unknown>";
      const line = item.line ? `:${item.line}` : "";
      const column = item.column ? `:${item.column}` : "";
      return `${file}${line}${column}`;
    };
    const severityOrder = ["critical", "high", "medium", "low", "info", "unknown"];
    const safeTone = (value) => severityOrder.includes(value) ? value : "unknown";
    const statusTone = (value) => ["ok", "failed", "timed_out", "skipped"].includes(value) ? value : "unknown";
    const badge = (value, status = false) => make("span", `badge badge-${status ? statusTone(value) : safeTone(value)}`, value || "unknown");
    const empty = (container, text, columns) => {
      if (columns) {
        const row = make("tr");
        const cell = make("td", "empty", text);
        cell.colSpan = columns;
        row.append(cell);
        container.append(row);
      } else {
        container.append(make("p", "empty", text));
      }
    };
    const safeReportHref = (path) => {
      if (typeof path !== "string" || !path || path.startsWith("/") || path.includes("\\") || path.includes(":")) return null;
      const parts = path.split("/");
      if (parts.some((part) => !part || part === "." || part === ".." || !/^[A-Za-z0-9._-]+$/.test(part))) return null;
      return "../" + parts.map(encodeURIComponent).join("/");
    };
    const reportLink = (label, path) => {
      const href = safeReportHref(path);
      if (!href) return null;
      const link = make("a", "", label);
      link.href = href;
      return link;
    };

    byId("project").textContent = report.project || "Unknown project";
    const projectName = String(report.project || "Code Analyzer").split(/[\\/]/).filter(Boolean).pop() || "Code Analyzer";
    document.title = `${projectName} · Code Analyzer`;
    const run = report.run || {};
    const runMeta = byId("run-meta");
    [
      ["Run", run.id || "unknown"],
      ["Started", run.started_at ? new Date(run.started_at).toLocaleString() : "unknown"],
      ["Completed", run.completed_at ? new Date(run.completed_at).toLocaleString() : "unknown"],
      ["Schema", report.schema_version || "unknown"],
    ].forEach(([label, value]) => {
      const item = make("span");
      item.append(make("strong", "", `${label}: `), document.createTextNode(value));
      runMeta.append(item);
    });

    const tools = report.tools || {};
    const toolEntries = Object.entries(tools);
    const manifest = report.source_manifest || {};
    const failedTools = toolEntries.filter(([, value]) => ["failed", "timed_out"].includes(value.status)).length;
    const cards = [
      ["Source files", manifest.total_files, `${number(manifest.excluded_paths)} paths excluded`],
      ["Findings", report.total_findings, "Original analyzer evidence"],
      ["Diagnostics", report.total_diagnostics, "Tool and configuration issues"],
      ["Overlap groups", (report.overlap_groups || []).length, "Related cross-tool locations"],
      ["Failed tools", failedTools, `${toolEntries.length} analyzer${toolEntries.length === 1 ? "" : "s"} selected`],
    ];
    const summaryCards = byId("summary-cards");
    cards.forEach(([label, value, note]) => {
      const card = make("article", "card");
      card.append(make("span", "card-label", label), make("strong", "card-value", number(value)), make("span", "card-note", note));
      summaryCards.append(card);
    });

    const renderBars = (id, entries, tone = "brand") => {
      const container = byId(id);
      const values = entries.filter((entry) => Number(entry[1]) > 0);
      if (!values.length) { empty(container, "No data available."); return; }
      const maximum = Math.max(...values.map((entry) => Number(entry[1])), 1);
      values.forEach(([label, count]) => {
        const row = make("div", "bar-row");
        row.setAttribute("role", "img");
        row.setAttribute("aria-label", `${label}: ${count}`);
        const labelNode = make("span", "bar-label", label || "<unknown>");
        labelNode.title = String(label || "<unknown>");
        const track = make("span", "bar-track");
        const fill = make("span", "bar-fill");
        fill.style.width = `${Math.max(1, Number(count) / maximum * 100)}%`;
        if (tone === "severity") fill.style.background = `var(--${safeTone(String(label))})`;
        track.append(fill);
        row.append(labelNode, track, make("span", "bar-value", number(count)));
        container.append(row);
      });
    };
    renderBars("severity-chart", severityOrder.map((item) => [item, (report.severity_counts || {})[item] || 0]), "severity");
    renderBars("tool-chart", toolEntries.map(([tool, value]) => [tool, value.total_findings || 0]));
    renderBars("cwe-chart", (report.top_cwes || []).map((item) => [item.cwe, item.count]));
    renderBars("file-chart", (report.top_files || []).map((item) => [item.file, item.count]));

    const toolCards = byId("tool-cards");
    toolEntries.forEach(([tool, data]) => {
      const tone = statusTone(data.status);
      const card = make("article", `tool-card status-${tone}`);
      const title = make("div", "tool-title");
      title.append(make("h3", "", tool), badge(data.status, true));
      const values = make("dl", "tool-grid");
      appendPair(values, "Findings", number(data.total_findings));
      appendPair(values, "Diagnostics", number(data.total_diagnostics));
      appendPair(values, "Version", data.version);
      appendPair(values, "Duration", data.duration_seconds === null || data.duration_seconds === undefined ? "—" : `${Number(data.duration_seconds).toFixed(2)} s`);
      appendPair(values, "Sources", data.source_count);
      appendPair(values, "Exit code", data.returncode);
      if (data.ai_review) {
        appendPair(values, "AI rounds", `${data.ai_review.rounds_completed || 0}/${data.ai_review.rounds_requested || 0}`);
        appendPair(values, "AI coverage", data.ai_review.coverage && data.ai_review.coverage.complete ? "Complete" : "Incomplete");
      }
      card.append(title, values);
      if (data.reason) card.append(make("p", "reason", data.reason));
      const links = make("div", "links");
      const candidates = [
        reportLink("Tool summary", data.summary),
        reportLink("Standard output", data.stdout_log ? `${tool}/${data.stdout_log}` : ""),
        reportLink("Standard error", data.stderr_log ? `${tool}/${data.stderr_log}` : ""),
        reportLink("Review ledger", data.ai_review ? data.ai_review.ledger : ""),
      ].filter(Boolean);
      if (candidates.length) links.append(...candidates);
      else links.append(make("span", "muted", "No report files available"));
      card.append(links);
      toolCards.append(card);
    });
    if (!toolEntries.length) empty(toolCards, "No analyzer status was recorded.");

    const aiReview = report.ai_review || null;
    if (aiReview) {
      byId("ai-review").hidden = false;
      const aiValues = byId("ai-values");
      const configuration = aiReview.configuration || {};
      const coverage = aiReview.coverage || {};
      appendPair(aiValues, "Mode", configuration.mode);
      appendPair(aiValues, "Provider", configuration.provider);
      appendPair(aiValues, "Model", configuration.model);
      appendPair(aiValues, "Rounds", `${aiReview.rounds_completed || 0}/${aiReview.rounds_requested || 0}`);
      appendPair(aiValues, "First-round coverage", `${number(coverage.covered_files)}/${number(coverage.total_files)} files`);
      appendPair(aiValues, "Coverage complete", coverage.complete ? "Yes" : "No");
      renderBars("ai-candidate-chart", Object.entries(aiReview.candidate_counts || {}));
      const aiCandidates = aiReview.candidates || [];
      byId("ai-candidate-count").textContent = `${number(aiCandidates.length)} candidate${aiCandidates.length === 1 ? "" : "s"}`;
      const aiBody = byId("ai-candidate-body");
      aiCandidates.forEach((item) => {
        const row = make("tr");
        row.append(
          make("td", "", item.verification_status || "unknown"),
          make("td", "", item.candidate_id || "—"),
          make("td", "", item.category || "other"),
          make("td", "", item.confidence === undefined ? "—" : Number(item.confidence).toFixed(2)),
          make("td", "location", location({canonical_path: item.file, line: item.line_start})),
          make("td", "message", item.conclusion || item.title || "—"),
          make("td", "message", item.verification_notes || (item.validation_errors || []).join("; ") || "—")
        );
        aiBody.append(row);
      });
      if (!aiCandidates.length) empty(aiBody, "No AI review candidates were recorded.", 7);
    }

    const scopeValues = byId("scope-values");
    appendPair(scopeValues, "Included files", number(manifest.total_files));
    appendPair(scopeValues, "Excluded paths", number(manifest.excluded_paths));
    appendPair(scopeValues, "Default excludes", manifest.default_excludes === false ? "Disabled" : "Enabled");
    appendPair(scopeValues, "Include patterns", (manifest.include_patterns || []).join(", ") || "All source files");
    appendPair(scopeValues, "Exclude patterns", (manifest.exclude_patterns || []).join(", ") || "None");
    renderBars("suffix-chart", Object.entries(manifest.suffix_counts || {}));
    const sourceFiles = manifest.files || [];
    byId("source-summary").textContent = `Source files (${number(sourceFiles.length)})`;
    byId("source-details").addEventListener("toggle", (event) => {
      if (!event.currentTarget.open || event.currentTarget.dataset.rendered) return;
      const list = byId("source-files");
      sourceFiles.forEach((path) => list.append(make("li", "", path)));
      if (!sourceFiles.length) list.append(make("li", "muted", "No source files recorded."));
      event.currentTarget.dataset.rendered = "true";
    });

    const state = { page: 1, overlapFingerprints: null, overlapLabel: "" };
    const overlapGroups = report.overlap_groups || [];
    byId("overlap-count").textContent = `${number(overlapGroups.length)} group${overlapGroups.length === 1 ? "" : "s"}`;
    const overlapBody = byId("overlap-body");
    overlapGroups.forEach((group) => {
      const row = make("tr");
      row.append(make("td", "", group.category || "unknown"), make("td", "location", `${group.canonical_path || "<unknown>"}:${group.line || ""}`), make("td", "", (group.tools || []).join(", ")), make("td", "", number((group.fingerprints || []).length)));
      const action = make("td");
      const button = make("button", "", "View findings");
      button.type = "button";
      button.addEventListener("click", () => {
        state.overlapFingerprints = new Set(group.fingerprints || []);
        state.overlapLabel = `${group.category || "unknown"} at ${group.canonical_path || "<unknown>"}:${group.line || ""}`;
        state.page = 1;
        renderFindings();
        byId("findings").scrollIntoView();
      });
      action.append(button);
      row.append(action);
      overlapBody.append(row);
    });
    if (!overlapGroups.length) empty(overlapBody, "No cross-tool overlap groups.", 5);

    const diagnostics = report.diagnostics || [];
    byId("diagnostic-count").textContent = `${number(diagnostics.length)} diagnostic${diagnostics.length === 1 ? "" : "s"}`;
    const diagnosticBody = byId("diagnostic-body");
    diagnostics.forEach((item) => {
      const row = make("tr");
      const severity = make("td"); severity.append(badge(item.severity));
      row.append(severity, make("td", "", item.tool), make("td", "", item.category), make("td", "", item.fatal ? "Yes" : "No"), make("td", "location", location(item)), make("td", "message", item.message));
      diagnosticBody.append(row);
    });
    if (!diagnostics.length) empty(diagnosticBody, "No tool diagnostics.", 6);

    const findings = report.findings || [];
    byId("finding-total").textContent = `${number(findings.length)} finding${findings.length === 1 ? "" : "s"}`;
    const controls = {
      search: byId("search"), severity: byId("severity"), tool: byId("tool"),
      cwe: byId("cwe"), sort: byId("sort"), pageSize: byId("page-size"),
    };
    severityOrder.filter((value) => findings.some((item) => item.severity === value)).forEach((value) => controls.severity.append(make("option", "", value)));
    toolEntries.forEach(([value]) => controls.tool.append(make("option", "", value)));
    [...new Set(findings.map((item) => item.cwe).filter(Boolean))].sort().forEach((value) => controls.cwe.append(make("option", "", value)));
    [controls.severity, controls.tool, controls.cwe].forEach((select) => [...select.options].forEach((option) => { option.value = option.textContent.startsWith("All ") ? "" : option.textContent; }));

    const lineNumber = (value) => {
      const parsed = Number.parseInt(value, 10);
      return Number.isFinite(parsed) ? parsed : Number.MAX_SAFE_INTEGER;
    };
    const compareText = (left, right) => String(left || "").localeCompare(String(right || ""));
    const filteredFindings = () => {
      const query = controls.search.value.trim().toLocaleLowerCase();
      const selectedSeverity = controls.severity.value;
      const selectedTool = controls.tool.value;
      const selectedCwe = controls.cwe.value;
      const selected = findings.filter((item) => {
        if (state.overlapFingerprints && !state.overlapFingerprints.has(item.fingerprint)) return false;
        if (selectedSeverity && item.severity !== selectedSeverity) return false;
        if (selectedTool && item.tool !== selectedTool) return false;
        if (selectedCwe && item.cwe !== selectedCwe) return false;
        if (!query) return true;
        return [item.tool, item.severity, item.rule_id, item.cwe, item.category, item.canonical_path, item.line, item.message, item.impact, item.trigger, item.recommendation].some((value) => String(value || "").toLocaleLowerCase().includes(query));
      });
      const mode = controls.sort.value;
      selected.sort((left, right) => {
        if (mode === "location") return compareText(left.canonical_path, right.canonical_path) || lineNumber(left.line) - lineNumber(right.line) || compareText(left.tool, right.tool);
        if (mode === "tool") return compareText(left.tool, right.tool) || Number(right.rank || 0) - Number(left.rank || 0) || compareText(left.canonical_path, right.canonical_path);
        if (mode === "rule") return compareText(left.rule_id, right.rule_id) || Number(right.rank || 0) - Number(left.rank || 0);
        return Number(right.rank || 0) - Number(left.rank || 0) || compareText(left.tool, right.tool) || compareText(left.canonical_path, right.canonical_path) || lineNumber(left.line) - lineNumber(right.line);
      });
      return selected;
    };
    function renderFindings() {
      const selected = filteredFindings();
      const pageSize = Number(controls.pageSize.value);
      const pages = Math.max(1, Math.ceil(selected.length / pageSize));
      state.page = Math.min(Math.max(1, state.page), pages);
      const start = (state.page - 1) * pageSize;
      const visible = selected.slice(start, start + pageSize);
      const body = byId("finding-body");
      body.replaceChildren();
      visible.forEach((item) => {
        const row = make("tr");
        const severity = make("td"); severity.append(badge(item.severity));
        const evidence = make("td");
        const link = reportLink("Tool report", item.source_report);
        evidence.append(link || document.createTextNode("—"));
        const message = make("td", "message", item.message);
        if (item.tool === "ai-review") {
          const details = make("details", "ai-detail");
          details.append(make("summary", "", `${item.category || "other"} · confidence ${Number(item.confidence || 0).toFixed(2)} · ${item.verification_status || "unknown"}`));
          [["Impact", item.impact], ["Trigger", item.trigger], ["Recommendation", item.recommendation], ["Verification", item.verification_notes]].forEach(([label, value]) => {
            const paragraph = make("p");
            paragraph.append(make("strong", "", `${label}: `), document.createTextNode(value || "—"));
            details.append(paragraph);
          });
          if (item.evidence) details.append(make("pre", "code-evidence", item.evidence));
          message.append(details);
        }
        row.append(severity, make("td", "", item.tool), make("td", "", item.rule_id || "—"), make("td", "", item.cwe || "—"), make("td", "location", location(item)), message, evidence);
        body.append(row);
      });
      if (!visible.length) empty(body, "No findings match the current filters.", 7);
      byId("page-status").textContent = selected.length ? `Showing ${number(start + 1)}–${number(Math.min(start + pageSize, selected.length))} of ${number(selected.length)} · Page ${state.page} of ${pages}` : "0 matching findings";
      byId("previous").disabled = state.page <= 1;
      byId("next").disabled = state.page >= pages;
      const filterState = byId("overlap-filter");
      filterState.classList.toggle("active", Boolean(state.overlapFingerprints));
      byId("overlap-filter-label").textContent = state.overlapFingerprints ? `Overlap filter: ${state.overlapLabel}` : "";
    }
    const resetPage = () => { state.page = 1; renderFindings(); };
    let searchTimer = null;
    controls.search.addEventListener("input", () => { window.clearTimeout(searchTimer); searchTimer = window.setTimeout(resetPage, 100); });
    [controls.severity, controls.tool, controls.cwe, controls.sort, controls.pageSize].forEach((control) => control.addEventListener("change", resetPage));
    byId("previous").addEventListener("click", () => { state.page -= 1; renderFindings(); });
    byId("next").addEventListener("click", () => { state.page += 1; renderFindings(); });
    byId("clear-overlap").addEventListener("click", () => { state.overlapFingerprints = null; state.overlapLabel = ""; resetPage(); });
    byId("reset").addEventListener("click", () => {
      controls.search.value = ""; controls.severity.value = ""; controls.tool.value = ""; controls.cwe.value = ""; controls.sort.value = "priority"; controls.pageSize.value = "50";
      state.overlapFingerprints = null; state.overlapLabel = ""; resetPage();
    });
    renderFindings();
  })();
  </script>
</body>
</html>
"""
