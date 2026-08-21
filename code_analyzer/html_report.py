"""Offline dashboard renderer.

The rendered page is one self-contained file: no network access, exactly two
executable scripts around one JSON data island, and every dynamic string
reaches the DOM through textContent. The export pipeline re-parses the island
tag verbatim, so its spelling is a production contract, not a style choice.
"""

from __future__ import annotations

import json
from typing import Any

from .grading import grading_reference


def _json_for_html(value: dict[str, Any]) -> str:
    payload = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return (
        payload.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
        .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    )


# Bounds the inline dashboard payload on very large scans; the complete
# finding set always remains available in review/summary.json.
MAX_EMBED_FINDINGS = 2000


def render(manifest: dict[str, Any], review: dict[str, Any] | None = None) -> str:
    data = dict(review or {
        "review_schema_version": 3, "findings": [], "diagnostics": [],
        "tools": manifest.get("tools", {}),
        "source_manifest": {"total_files": manifest.get("source_inventory", {}).get("total", 0), "files": []},
        "overlap_groups": [], "total_findings": 0, "total_diagnostics": 0,
        "finding_counts": {"total": 0, "build-aware": 0, "source-only": 0},
        "grading_reference": grading_reference(),
        "review_level_counts": {}, "review_level_counts_by_context": {"build-aware": {}, "source-only": {}},
        "report_integrity": {"status": "complete", "omitted_units": []}, "coverage_gaps": [],
    })
    findings = data.get("findings")
    if isinstance(findings, list) and len(findings) > MAX_EMBED_FINDINGS:
        data["findings"] = findings[:MAX_EMBED_FINDINGS]
        data["findings_omitted"] = len(findings) - MAX_EMBED_FINDINGS
    data["execution_manifest"] = manifest
    return _TEMPLATE.replace("__CODE_ANALYZER_DATA__", _json_for_html(data))


# Palette note: the severity and review-level hues below were validated for
# adjacent-pair colorblind separation and surface contrast on both the light
# and the dark surface. Change them as a set, not one at a time.
_CSS = r"""
:root{
  color-scheme:light;
  --bg:#f3efe7; --surface:#fdfcf9; --soft:#f5f1e8; --ink:#221d15; --muted:#6d6659;
  --line:#d9d2c2; --hairline:#e8e2d4; --track:#ece6d8;
  --sev-critical:#8a1f62; --sev-high:#b23a1e; --sev-medium:#a57b00;
  --sev-low:#1f5f9e; --sev-info:#24855d; --sev-unknown:#8a67b0;
  --rl-error:#b23a1e; --rl-warning:#a57b00; --rl-style:#1f5f9e;
  --rl-information:#24855d; --rl-unmapped:#8a67b0;
  --ok:#2f7a50; --warn:#996c10; --bad:#b23a1e; --bar-neutral:#7a7264;
  --bar-build:#4a463d; --bar-source:#a89e8c;
  --serif:Georgia,"Times New Roman","Songti SC","Noto Serif CJK SC",SimSun,serif;
  --mono:ui-monospace,"SF Mono",Menlo,Consolas,"Cascadia Mono","Courier New",monospace;
}
@media(prefers-color-scheme:dark){
  :root{
    color-scheme:dark;
    --bg:#191713; --surface:#211f1c; --soft:#282520; --ink:#eae4d8; --muted:#a49b8a;
    --line:#3b362d; --hairline:#312d26; --track:#322e27;
    --sev-critical:#c353a4; --sev-high:#c8481f; --sev-medium:#b78c15;
    --sev-low:#4285c9; --sev-info:#2f9e68; --sev-unknown:#9678bf;
    --rl-error:#c8481f; --rl-warning:#b78c15; --rl-style:#4285c9;
    --rl-information:#2f9e68; --rl-unmapped:#9678bf;
    --ok:#4f9d70; --warn:#c39a3a; --bad:#c8481f; --bar-neutral:#958c7b;
    --bar-build:#cfc7b6; --bar-source:#736c60;
  }
}

*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.6 system-ui,-apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;
  font-variant-numeric:tabular-nums}
a{color:var(--ink);text-decoration:underline;text-underline-offset:2px}
a:hover{color:var(--muted)}
:focus-visible{outline:2px solid var(--ink);outline-offset:2px}
.mono{font-family:var(--mono);font-size:.92em}
.muted{color:var(--muted)}
button,input,select{font:inherit;border:1px solid var(--line);border-radius:3px;
  background:var(--surface);color:var(--ink);padding:.45rem .6rem}
button{cursor:pointer}
button:hover{border-color:var(--muted)}

/* The whole report sits on one continuous sheet, like a printed dossier. */
.sheet{max-width:1180px;margin:1.6rem auto;background:var(--surface);
  border:1px solid var(--line);padding:0 clamp(1rem,4vw,3rem) 3rem}

.masthead{border-top:4px solid var(--ink);border-bottom:1px solid var(--ink);
  padding:1.6rem 0 1.2rem;margin-bottom:.2rem}
.mast-top{display:flex;justify-content:space-between;align-items:flex-start;gap:1rem;flex-wrap:wrap}
.eyebrow{margin:0;font-family:var(--mono);font-size:.78rem;letter-spacing:.22em;
  text-transform:uppercase;color:var(--muted)}
.masthead h1{margin:.3rem 0 .5rem;font-family:var(--serif);font-weight:600;
  font-size:clamp(1.5rem,3.4vw,2.1rem);letter-spacing:.01em}
#project{margin:0;font-family:var(--mono);font-size:.92rem;color:var(--muted);word-break:break-all}
.mast-right{display:flex;flex-direction:column;align-items:flex-end;gap:.5rem}
.run-no{margin:0;font-family:var(--mono);font-size:1.05rem;letter-spacing:.06em}
.mast-actions{display:flex;gap:.6rem;align-items:center;flex-wrap:wrap}
.mast-meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(11rem,1fr));
  gap:.2rem 1.4rem;margin:1rem 0 0;border-top:1px solid var(--hairline);padding-top:.8rem}
.mast-meta dt{font-family:inherit;font-size:.78rem;letter-spacing:.06em;color:var(--muted)}
.mast-meta dd{margin:0 0 .4rem;font-family:var(--mono);font-size:.9rem;word-break:break-all}

.nav{position:sticky;top:0;z-index:2;display:flex;gap:1.1rem;overflow:auto;
  padding:.55rem 0;background:var(--surface);border-bottom:1px solid var(--hairline)}
.nav a{white-space:nowrap;text-decoration:none;font-size:.9rem;color:var(--muted)}
.nav a:hover{color:var(--ink)}
.nav .sec-no{margin-right:.3rem}

main{padding-top:.4rem}
section{scroll-margin-top:3.4rem;margin:2rem 0}
h2{font-family:var(--serif);font-weight:600;font-size:1.35rem;margin:0 0 .9rem;
  padding-bottom:.45rem;border-bottom:1px solid var(--hairline)}
h3{font-family:var(--serif);font-weight:600;font-size:1.02rem;margin:0 0 .6rem}
.sec-no{font-family:var(--mono);font-weight:400;font-size:.72em;
  letter-spacing:.08em;color:var(--muted);margin-right:.55rem}
.section-head{display:flex;justify-content:space-between;align-items:baseline;gap:1rem}

.notice{border-left:3px solid var(--warn);padding:.6rem .9rem;background:var(--soft);margin:.8rem 0}

/* Verdict hero */
.verdict{display:flex;gap:1.8rem;align-items:center;flex-wrap:wrap;
  border:1px solid var(--line);background:var(--soft);padding:1.2rem 1.4rem}
.stamp{font-family:var(--mono);text-align:center;border:2px solid var(--muted);
  color:var(--muted);padding:.7rem 1.1rem;min-width:9rem}
.stamp strong{display:block;font-size:1.15rem;letter-spacing:.18em;text-transform:uppercase}
.stamp span{display:block;font-size:.8rem;margin-top:.25rem;letter-spacing:.1em}
.stamp.ok{color:var(--ok);border-color:var(--ok)}
.stamp.warn{color:var(--warn);border-color:var(--warn)}
.stamp.bad{color:var(--bad);border-color:var(--bad)}
.hero{flex:1;min-width:19rem;display:flex;flex-direction:column;gap:.55rem}
.hero-line{display:flex;align-items:baseline;gap:.55rem}
.hero-count{font-family:var(--serif);font-size:2.1rem;font-weight:600;line-height:1}
.hero-label{color:var(--muted)}
.stack{display:flex;gap:2px;height:20px}
.stack i{display:block;border-radius:2px;flex-basis:4px}
.stack.thin{height:11px}
.stack-labels{display:flex;flex-wrap:wrap;gap:.3rem 1rem;font-size:.85rem}
.verdict-chips{flex-basis:100%;display:flex;flex-wrap:wrap;gap:.4rem 1.3rem;
  border-top:1px solid var(--hairline);padding-top:.7rem;margin-top:.3rem}
.reasons{margin:.15rem 0 0;padding-left:1.1rem;color:var(--muted);font-size:.88rem;flex-basis:100%}

.chip{display:inline-flex;align-items:center;gap:.4rem;font-family:var(--mono);font-size:.9em}
.dot{width:.55rem;height:.55rem;border-radius:50%;background:var(--muted);flex:none}
.tone-ok{background:var(--ok)}.tone-warn{background:var(--warn)}.tone-bad{background:var(--bad)}
.tone-muted{background:var(--muted)}.tone-neutral{background:var(--bar-neutral)}
.tone-sev-critical{background:var(--sev-critical)}.tone-sev-high{background:var(--sev-high)}
.tone-sev-medium{background:var(--sev-medium)}.tone-sev-low{background:var(--sev-low)}
.tone-sev-info{background:var(--sev-info)}.tone-sev-unknown{background:var(--sev-unknown)}
.tone-rl-error{background:var(--rl-error)}.tone-rl-warning{background:var(--rl-warning)}
.tone-rl-style{background:var(--rl-style)}.tone-rl-information{background:var(--rl-information)}
.tone-rl-unmapped{background:var(--rl-unmapped)}

.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(10rem,1fr));gap:1rem 1.6rem;margin-top:1.2rem}
.stat{border-top:2px solid var(--line);padding-top:.5rem}
.stat .lbl{display:block;font-size:.78rem;letter-spacing:.05em;color:var(--muted)}
.stat strong{display:block;font-family:var(--serif);font-size:1.5rem;font-weight:600;margin-top:.1rem}
.stat .duo{display:flex;justify-content:space-between;gap:.6rem;font-family:var(--mono);
  font-size:.95rem;margin-top:.3rem}
.split{display:flex;gap:2px;height:5px;border-radius:2px;overflow:hidden;background:var(--track);margin-top:.35rem}
.split i{display:block;flex-basis:2px}

.panel{border:1px solid var(--hairline);background:var(--surface);padding:1rem 1.1rem}
.charts{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:.7rem}
.charts .panel{grid-column:span 2}
.charts .panel.wide{grid-column:1/-1}
.bar{display:grid;grid-template-columns:minmax(5.5rem,32%) 1fr auto;gap:.6rem;
  align-items:center;margin:.4rem 0}
.bar-label{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.rank{display:inline-block;min-width:1.3rem;color:var(--muted);font-size:.82em}
.track{height:10px;background:var(--track);border-radius:2px;overflow:hidden}
.fill{display:block;height:100%;background:var(--bar-neutral);border-radius:0 4px 4px 0}
.bar-count{min-width:2.2rem;text-align:right}
.tone-build{background:var(--bar-build)}
.tone-source{background:var(--bar-source)}
.legend{display:flex;gap:1.1rem;font-size:.8rem;color:var(--muted);margin:.1rem 0 .5rem}
.comp-row{margin:.7rem 0}
.comp-row .ctx{font-size:.85rem;color:var(--muted);margin-bottom:.3rem}
.comp-row .stack{margin-bottom:.35rem}
.grp{margin:.65rem 0}
.grp .g-name{font-family:var(--mono);font-size:.9rem;margin-bottom:.15rem}
.grp .bar{margin:.12rem 0;grid-template-columns:4.6rem 1fr auto}
.grp .bar .bar-label{font-size:.78rem;color:var(--muted)}
.hm{display:grid;gap:2px;font-size:.85rem;
  grid-template-columns:minmax(8rem,1.6fr) repeat(6,minmax(2.4rem,1fr)) minmax(2.8rem,auto)}
.hm-h{color:var(--muted);font-size:.75rem;text-align:center;padding:.15rem .1rem}
.hm-h.first{text-align:left}
.hm-f{font-family:var(--mono);font-size:.82rem;overflow:hidden;text-overflow:ellipsis;
  white-space:nowrap;padding:.28rem .35rem;direction:rtl;text-align:left}
.hm-c{text-align:center;font-family:var(--mono);padding:.28rem .15rem;border-radius:2px}
.hm-t{text-align:right;font-family:var(--mono);color:var(--muted);padding:.28rem .3rem}
.hm-note{margin:.5rem 0 0;font-size:.8rem;color:var(--muted)}

.tools{display:grid;grid-template-columns:repeat(auto-fit,minmax(20rem,1fr));gap:.7rem}
.tool-card{border:1px solid var(--hairline);background:var(--surface);padding:1rem 1.1rem}
.tool-card h3{display:inline;font-family:var(--mono);font-size:1rem}
.badge{display:inline-block;font-family:var(--mono);font-size:.78rem;border:1px solid var(--line);
  border-radius:2px;padding:.08rem .45rem;margin-left:.5rem;color:var(--muted)}
.badge.ok{color:var(--ok);border-color:var(--ok)}
.badge.warn{color:var(--warn);border-color:var(--warn)}
.badge.bad{color:var(--bad);border-color:var(--bad)}
.tool-values{display:grid;grid-template-columns:auto 1fr;gap:.15rem .8rem;margin:.7rem 0 0}
.tool-values dt{color:var(--muted);font-size:.88rem}
.tool-values dd{margin:0;font-family:var(--mono);font-size:.9rem}
.unit-strip{display:flex;height:8px;border-radius:2px;overflow:hidden;background:var(--track);margin:.5rem 0 .2rem}
.unit-strip i{display:block}
.unit-caption{margin:.15rem 0 0;font-family:var(--mono);font-size:.8rem;color:var(--muted)}
.links{display:flex;gap:.7rem;flex-wrap:wrap;margin-top:.7rem;font-family:var(--mono);font-size:.85rem}

.table-wrap{overflow:auto;border:1px solid var(--hairline);background:var(--surface)}
table{border-collapse:collapse;width:100%}
th,td{padding:.55rem .65rem;border-bottom:1px solid var(--hairline);text-align:left;vertical-align:top}
th{background:var(--soft);position:sticky;top:0;font-weight:600;font-size:.85rem;white-space:nowrap}
tbody tr:hover td{background:var(--soft)}
.loc{white-space:nowrap;font-family:var(--mono);font-size:.88em}
.file-list{max-height:18rem;overflow:auto;font-family:var(--mono);font-size:.88rem}
.empty{text-align:center;color:var(--muted);padding:1rem}

.controls{display:grid;grid-template-columns:2fr repeat(6,1fr) auto;gap:.55rem;margin-bottom:.7rem}
.control{display:grid;gap:.2rem;font-size:.85rem;color:var(--muted)}
.pagination{display:flex;justify-content:space-between;align-items:center;margin-top:.7rem;gap:.7rem;flex-wrap:wrap}

@media(max-width:900px){
  .tools{grid-template-columns:1fr}
  .charts .panel{grid-column:1/-1}
  .controls{grid-template-columns:1fr 1fr}
  .verdict{flex-direction:column;align-items:stretch}
  .mast-right{align-items:flex-start}
}
@media(max-width:560px){
  .stats,.controls{grid-template-columns:1fr 1fr}
  .section-head{display:block}
  .sheet{margin:0;border:none}
}
@media print{
  .nav,.controls,.pagination,button,.mast-actions{display:none!important}
  body{background:#fff}
  .sheet{border:none;margin:0;max-width:none}
  section,.panel,.tool-card{break-inside:avoid}
}
"""


_JS_GUARD = r"""
"use strict";
(() => {
  const state = { ready: false, timer: null };
  const show = message => {
    if (state.ready) return;
    state.ready = true;
    if (state.timer !== null) window.clearTimeout(state.timer);
    const project = document.getElementById("project");
    if (project) project.textContent = "\u4eea\u8868\u76d8\u4e0d\u53ef\u7528 / Dashboard unavailable";
    const main = document.querySelector("main");
    const notice = document.createElement("p");
    notice.id = "dashboard-error";
    notice.className = "notice";
    notice.append(document.createTextNode(message + " \u8bf7\u6253\u5f00 / open "));
    [["manifest.json", "manifest.json"], ["review/summary.json", "review/summary.json"]].forEach(([label, path], index) => {
      if (index) notice.append(document.createTextNode(" / "));
      const link = document.createElement("a");
      link.href = path;
      link.textContent = label;
      notice.append(link);
    });
    notice.append(document.createTextNode(" \u67e5\u770b\u539f\u59cb\u62a5\u544a\u6570\u636e\u3002"));
    if (main) main.prepend(notice);
  };
  window.__codeAnalyzerDashboard = {
    ready: () => {
      state.ready = true;
      if (state.timer !== null) window.clearTimeout(state.timer);
    },
    fail: show,
  };
  window.addEventListener("error", event => show(
    "\u4eea\u8868\u76d8\u521d\u59cb\u5316\u5931\u8d25 / Dashboard initialization failed: " + (event.message || "unknown script error") + "."));
  window.addEventListener("unhandledrejection", () => show(
    "\u4eea\u8868\u76d8\u521d\u59cb\u5316\u5931\u8d25 / Dashboard initialization failed with an unhandled error."));
  state.timer = window.setTimeout(() => show(
    "\u4eea\u8868\u76d8\u521d\u59cb\u5316\u672a\u5b8c\u6210 / Dashboard initialization did not complete."), 1000);
})();
"""


_JS_MAIN = r"""
"use strict";
(() => {
  const review = JSON.parse(document.getElementById("report-data").textContent);
  const manifest = review.execution_manifest || {};

  const id = x => document.getElementById(x);
  const make = (tag, cls, value) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (value !== undefined && value !== null) n.textContent = String(value);
    return n;
  };

  /* ---------- i18n ---------- */
  const I18N = {
    zh: {
      report_title: "静态分析证据报告",
      open_json: "查看原始 JSON",
      disclaimer: "派生的 findings 不具权威性。请对照其链接的原生工具报告与实际的构建配置逐条确认。",
      sec_overview: "总体判定", sec_distribution: "发现分布",
      sec_tools: "执行与原生证据", sec_scope: "扫描范围", sec_overlap: "跨工具邻近重叠",
      sec_diagnostics: "工具诊断", sec_findings: "发现明细",
      meta_analyzer: "分析器版本", meta_finished: "完成时间", meta_duration: "运行时长",
      duration_value: "{m} 分 {s} 秒",
      verdict_status: "运行状态", verdict_integrity: "报告完整性", verdict_gate: "质量门禁",
      verdict_stable: "源码稳定性", verdict_context: "分析上下文",
      gate_disabled: "未启用", gate_pass: "未触发", gate_fail: "已触发",
      stable_yes: "扫描期间未变化", stable_no: "扫描期间发生变化",
      card_source_files: "源文件", card_context_split: "构建感知 / 仅源码",
      card_mapping_split: "已映射 / 未映射参考等级",
      card_diagnostics: "诊断", card_valid_reports: "有效报告",
      hero_label: "条发现 · 全部证据层",
      integrity_notice: "出于完整性原因省略了 {units} 个报告单元;{files} 个文件被排除或未分析。",
      omitted_notice: "有 {n} 条发现超出仪表盘内嵌上限,未在此显示;完整数据仍在 review/summary.json 中。",
      chart_rl_comp: "评分等级构成", chart_sev_comp: "规范化严重度构成",
      chart_heatmap: "文件 × 严重度", chart_tools: "各分析器",
      chart_top_rules: "规则 · 前列", chart_top_cwes: "CWE · 前列",
      heat_total: "合计",
      heat_partial: "矩阵基于内嵌的前 {n} 条发现;完整数据见 review/summary.json。",
      legend_build: "构建感知", legend_source: "仅源码",
      no_data: "暂无数据",
      tool_build_findings: "构建感知发现", tool_source_findings: "仅源码发现",
      tool_diagnostics: "诊断", tool_version: "版本", tool_coverage: "有效覆盖",
      tool_attempted: "尝试分析", tool_excluded: "排除", tool_valid_reports: "有效报告",
      tool_units: "分析单元", tool_no_artifacts: "无原生工件",
      unit_planned: "计划", unit_completed: "完成", unit_failed: "失败",
      unit_timed_out: "超时", unit_unscheduled: "未调度",
      scope_inventory: "清单文件", scope_compile_db: "编译数据库条目",
      scope_context: "分析上下文", scope_stable: "源码稳定",
      yes: "是", no: "否",
      source_files_n: "源文件({n})",
      th_category: "类别", th_location: "位置", th_tools: "工具", th_evidence: "证据",
      th_action: "操作", th_severity: "严重度", th_tool: "分析器", th_diag_category: "类别",
      th_fatal: "致命", th_message: "消息", th_review_level: "评分等级", th_native: "原生等级",
      th_context: "上下文", th_rule: "规则", th_cwe: "CWE",
      overlap_view: "查看发现", overlap_groups_n: "{n} 组", diag_n: "{n} 条诊断",
      findings_n: "{n} 条发现", fatal_yes: "是", fatal_no: "否",
      no_overlap: "无跨工具重叠组。", no_diags: "无工具诊断。",
      no_findings: "没有符合筛选条件的发现。",
      search_label: "搜索", search_placeholder: "规则、CWE、文件或消息",
      filter_context: "上下文", opt_all_contexts: "全部上下文", opt_build: "构建感知", opt_source: "仅源码",
      filter_review_level: "评分等级", opt_all_levels: "全部等级",
      filter_severity: "规范化严重度", opt_all_sev: "全部严重度",
      filter_tool: "分析器", opt_all_tools: "全部分析器",
      filter_cwe: "CWE", opt_all_cwe: "全部 CWE",
      filter_sort: "排序", opt_sort_priority: "优先级", opt_sort_location: "位置",
      opt_sort_tool: "分析器", opt_sort_rule: "规则",
      reset: "重置", prev: "上一页", next: "下一页",
      page_status: "{results} 条结果 · 第 {page}/{pages} 页",
      context_notice: "默认展示构建感知证据。另有 {n} 条仅源码发现可通过上下文筛选查看。",
      unknown_source: "未知源",
    },
    en: {
      report_title: "Static Analysis Evidence Report",
      open_json: "Open review JSON",
      disclaimer: "Derived findings are non-authoritative. Confirm every item against its linked native artifact and the analyzed build configuration.",
      sec_overview: "Overall verdict",
      sec_distribution: "Finding distribution", sec_tools: "Execution and native evidence",
      sec_scope: "Scan scope", sec_overlap: "Cross-tool nearby overlap",
      sec_diagnostics: "Tool diagnostics", sec_findings: "Findings",
      meta_analyzer: "Analyzer", meta_finished: "Finished", meta_duration: "Duration",
      duration_value: "{m}m {s}s",
      verdict_status: "Run status", verdict_integrity: "Report integrity", verdict_gate: "Quality gate",
      verdict_stable: "Source stability", verdict_context: "Analysis context",
      gate_disabled: "not enabled", gate_pass: "not triggered", gate_fail: "triggered",
      stable_yes: "unchanged during scan", stable_no: "changed during scan",
      card_source_files: "Source files", card_context_split: "Build-aware / source-only",
      card_mapping_split: "Mapped / unmapped reference level",
      card_diagnostics: "Diagnostics", card_valid_reports: "Valid reports",
      hero_label: "findings · all evidence layers",
      integrity_notice: "{units} report unit(s) were omitted for integrity reasons; {files} file(s) are excluded or unanalyzed.",
      omitted_notice: "{n} finding(s) beyond the dashboard embed limit are omitted here; the complete set remains in review/summary.json.",
      chart_rl_comp: "Review level composition", chart_sev_comp: "Normalized severity composition",
      chart_heatmap: "Files × severity", chart_tools: "By analyzer",
      chart_top_rules: "Top rules", chart_top_cwes: "Top CWE",
      heat_total: "total",
      heat_partial: "Matrix based on the {n} embedded findings; the complete data remains in review/summary.json.",
      legend_build: "build-aware", legend_source: "source-only",
      no_data: "No data available.",
      tool_build_findings: "Build-aware findings", tool_source_findings: "Source-only findings",
      tool_diagnostics: "Diagnostics", tool_version: "Version", tool_coverage: "Effective coverage",
      tool_attempted: "Attempted", tool_excluded: "Excluded", tool_valid_reports: "Valid reports",
      tool_units: "Units", tool_no_artifacts: "No native artifacts",
      unit_planned: "planned", unit_completed: "completed", unit_failed: "failed",
      unit_timed_out: "timed out", unit_unscheduled: "unscheduled",
      scope_inventory: "Inventory files", scope_compile_db: "Compile DB entries",
      scope_context: "Analysis context", scope_stable: "Source stable",
      yes: "yes", no: "no",
      source_files_n: "Source files ({n})",
      th_category: "Category", th_location: "Location", th_tools: "Tools", th_evidence: "Evidence",
      th_action: "Action", th_severity: "Severity", th_tool: "Analyzer", th_diag_category: "Category",
      th_fatal: "Fatal", th_message: "Message", th_review_level: "Review level", th_native: "Native level",
      th_context: "Context", th_rule: "Rule", th_cwe: "CWE",
      overlap_view: "View findings", overlap_groups_n: "{n} groups", diag_n: "{n} diagnostics",
      findings_n: "{n} findings", fatal_yes: "yes", fatal_no: "no",
      no_overlap: "No cross-tool overlap groups.", no_diags: "No tool diagnostics.",
      no_findings: "No findings match the filters.",
      search_label: "Search", search_placeholder: "Rule, CWE, file, or message",
      filter_context: "Context", opt_all_contexts: "All contexts", opt_build: "Build-aware", opt_source: "Source-only",
      filter_review_level: "Review level", opt_all_levels: "All review levels",
      filter_severity: "Normalized severity", opt_all_sev: "All severities",
      filter_tool: "Analyzer", opt_all_tools: "All analyzers",
      filter_cwe: "CWE", opt_all_cwe: "All CWE",
      filter_sort: "Sort", opt_sort_priority: "Priority", opt_sort_location: "Location",
      opt_sort_tool: "Analyzer", opt_sort_rule: "Rule",
      reset: "Reset", prev: "Previous", next: "Next",
      page_status: "{results} results · page {page}/{pages}",
      context_notice: "Showing build-aware evidence by default. {n} source-only finding(s) remain available in the Context filter.",
      unknown_source: "Unknown source",
    },
  };
  let lang = "zh";
  try {
    const saved = window.localStorage.getItem("codeAnalyzerLang");
    if (saved === "en" || saved === "zh") lang = saved;
  } catch (err) { /* storage may be unavailable on some file systems */ }
  const t = key => {
    const table = I18N[lang] || I18N.zh;
    return table[key] !== undefined ? table[key] : (I18N.zh[key] !== undefined ? I18N.zh[key] : key);
  };
  const fmt = (key, params) => t(key).replace(/\{(\w+)\}/g, (whole, name) =>
    params[name] !== undefined ? String(params[name]) : whole);
  const number = x => new Intl.NumberFormat(lang === "zh" ? "zh-CN" : "en-US").format(Number(x || 0));

  /* ---------- shared helpers ---------- */
  const safeHref = path => {
    if (typeof path !== "string" || !path || path.startsWith("/") || path.includes("\\") || path.includes(":")) return null;
    const parts = path.split("/");
    if (parts.some(p => !p || p === "." || p === ".." || !/^[A-Za-z0-9._-]+$/.test(p))) return null;
    return parts.map(encodeURIComponent).join("/");
  };
  const link = (label, path) => {
    const href = safeHref(path);
    if (!href) return make("span", "muted", "—");
    const a = make("a", "", label);
    a.href = href;
    return a;
  };
  const locText = x => (x.canonical_path || x.file || "?") + (x.line ? ":" + x.line : "") + (x.column ? ":" + x.column : "");
  const chip = (tone, text) => {
    const span = make("span", "chip");
    span.append(make("i", "dot " + tone), document.createTextNode(String(text)));
    return span;
  };
  const sevOrder = ["critical", "high", "medium", "low", "info", "unknown"];
  const rawReviewLevels = ["error", "warning", "style", "information", "unmapped"];
  const sevTone = s => "tone-sev-" + (sevOrder.includes(s) ? s : "unknown");
  const rlTone = l => "tone-rl-" + (rawReviewLevels.includes(l) ? l : "unmapped");
  const statusTone = s => s === "complete" || s === "completed" ? "ok"
    : (s === "failed" ? "bad" : (s === "partial" || s === "interrupted" ? "warn" : "muted"));
  const tableEmpty = (body, columns, text) => {
    const tr = make("tr");
    const td = make("td", "empty", text);
    td.colSpan = columns;
    tr.append(td);
    body.append(tr);
  };

  /* ---------- model: schema fallbacks concentrated here ---------- */
  const findings = (review.findings || []).map(x => ({
    ...x,
    evidence_context: x.evidence_context || "source-only",
    review_level: x.review_level || "unmapped",
  }));
  const countBy = (list, key) => list.reduce((out, item) => {
    const value = item[key] || "unknown";
    out[value] = (out[value] || 0) + 1;
    return out;
  }, {});
  const fallbackLevelCounts = rawReviewLevels.reduce((out, level) => {
    out[level] = findings.filter(x => x.review_level === level).length;
    return out;
  }, {});
  const levelCounts = review.review_level_counts || fallbackLevelCounts;
  const levelByContext = review.review_level_counts_by_context
    || { "build-aware": {}, "source-only": levelCounts };
  const sevCounts = review.severity_counts || countBy(findings, "severity");
  let sevByContext = review.severity_counts_by_context;
  if (!sevByContext) {
    if (!review.findings_omitted && findings.length) {
      sevByContext = {
        "build-aware": countBy(findings.filter(x => x.evidence_context === "build-aware"), "severity"),
        "source-only": countBy(findings.filter(x => x.evidence_context === "source-only"), "severity"),
      };
    } else {
      sevByContext = { "build-aware": {}, "source-only": sevCounts };
    }
  }
  const run = review.run || {};
  const startedAt = manifest.started_at || run.started_at;
  const finishedAt = manifest.finished_at || run.completed_at;
  const duration = (() => {
    const a = Date.parse(startedAt || "");
    const b = Date.parse(finishedAt || "");
    if (!isFinite(a) || !isFinite(b) || b < a) return null;
    const seconds = Math.round((b - a) / 1000);
    return { m: Math.floor(seconds / 60), s: seconds % 60 };
  })();
  const unmappedCount = Number(levelCounts.unmapped || 0);
  const counts = review.finding_counts || {};

  /* ---------- static chrome ---------- */
  const applyLanguage = () => {
    document.documentElement.lang = lang === "zh" ? "zh-CN" : "en";
    document.querySelectorAll("[data-i18n]").forEach(el => {
      el.textContent = t(el.dataset.i18n);
    });
    id("search").placeholder = t("search_placeholder");
    id("lang-toggle").textContent = lang === "zh" ? "English" : "中文";
  };

  const projectName = review.project || manifest.source;
  document.title = (String(projectName || "Code Analyzer").split(/[\\/]/).filter(Boolean).pop() || "Code Analyzer") + " · Code Analyzer";

  const renderMasthead = () => {
    id("project").textContent = projectName || t("unknown_source");
    id("run-no").textContent = manifest.run_id || "";
    const meta = id("run-meta");
    meta.replaceChildren();
    const pair = (label, value) => {
      meta.append(make("dt", "", label), make("dd", "", value === undefined || value === null || value === "" ? "—" : value));
    };
    pair(t("meta_analyzer"), manifest.analyzer_version);
    pair(t("meta_finished"), finishedAt);
    pair(t("meta_duration"), duration ? fmt("duration_value", duration) : undefined);
  };

  /* Stacked proportion bar shared by the hero and the composition panels. */
  const stackedBar = (countsByKey, order, tone, thin) => {
    let total = 0;
    order.forEach(key => { total += Number(countsByKey[key] || 0); });
    if (!total) return null;
    const wrap = make("div");
    const bar = make("div", "stack" + (thin ? " thin" : ""));
    const labels = make("div", "stack-labels");
    order.forEach(key => {
      const value = Number(countsByKey[key] || 0);
      if (!value) return;
      const seg = make("i", tone(key));
      seg.style.flexGrow = String(value);
      bar.append(seg);
      labels.append(chip(tone(key), key + " " + number(value)));
    });
    wrap.append(bar, labels);
    return wrap;
  };

  /* ---------- verdict hero ---------- */
  const renderVerdict = () => {
    const root = id("verdict");
    root.replaceChildren();
    const status = manifest.status || "unknown";
    const stamp = make("div", "stamp " + statusTone(status));
    stamp.append(make("strong", "", status), make("span", "", "exit " + (manifest.exit_code ?? "—")));
    const hero = make("div", "hero");
    const heroLine = make("div", "hero-line");
    heroLine.append(make("strong", "hero-count", number(review.total_findings)),
      make("span", "hero-label", t("hero_label")));
    hero.append(heroLine);
    const composition = stackedBar(sevCounts, sevOrder, sevTone, false);
    if (composition) hero.append(composition);
    const chips = make("div", "verdict-chips");
    const item = (labelKey, node) => {
      const cell = make("span");
      cell.append(make("span", "muted", t(labelKey) + ": "), node);
      chips.append(cell);
    };
    const integrity = (review.report_integrity || {}).status;
    item("verdict_integrity", integrity
      ? chip(integrity === "complete" ? "tone-ok" : "tone-warn", integrity)
      : make("span", "muted", "—"));
    const gate = manifest.gate;
    if (gate && gate.policy && gate.policy !== "none") {
      item("verdict_gate", chip(gate.triggered ? "tone-bad" : "tone-ok",
        gate.policy + " · " + (gate.triggered ? t("gate_fail") : t("gate_pass"))));
    } else {
      item("verdict_gate", chip("tone-muted", t("gate_disabled")));
    }
    const stable = (manifest.source_inventory || {}).stable;
    item("verdict_stable", stable === true ? chip("tone-ok", t("stable_yes"))
      : (stable === false ? chip("tone-bad", t("stable_no")) : make("span", "muted", "—")));
    item("verdict_context", chip(manifest.analysis_context === "full" ? "tone-ok"
      : (manifest.analysis_context === "degraded" ? "tone-warn" : "tone-muted"),
      manifest.analysis_context || "—"));
    root.append(stamp, hero, chips);
    const reasons = manifest.analysis_context_reasons || [];
    if (reasons.length) {
      const list = make("ul", "reasons");
      reasons.forEach(reason => list.append(make("li", "", reason)));
      root.append(list);
    }
  };

  const renderNotices = () => {
    const root = id("integrity-warning");
    root.replaceChildren();
    const omitted = (review.report_integrity || {}).omitted_units || [];
    const gaps = review.coverage_gaps || [];
    if (omitted.length || gaps.length) {
      root.append(make("p", "notice", fmt("integrity_notice", {
        units: omitted.length,
        files: gaps.reduce((n, x) => n + Number(x.excluded || 0) + Number(x.unanalyzed || 0), 0),
      })));
    }
    if (review.findings_omitted) {
      root.append(make("p", "notice", fmt("omitted_notice", { n: number(review.findings_omitted) })));
    }
  };

  const renderStats = () => {
    const root = id("cards");
    root.replaceChildren();
    const stat = (labelKey, node) => {
      const cell = make("article", "stat");
      cell.append(make("span", "lbl", t(labelKey)), node);
      root.append(cell);
    };
    const single = value => make("strong", "", number(value));
    const splitTile = (a, b, toneA, toneB) => {
      const wrap = make("div");
      const duo = make("div", "duo");
      duo.append(chip(toneA, number(a)), chip(toneB, number(b)));
      wrap.append(duo);
      if (Number(a || 0) + Number(b || 0) > 0) {
        const bar = make("div", "split");
        [[a, toneA], [b, toneB]].forEach(([value, toneCls]) => {
          if (Number(value || 0) > 0) {
            const seg = make("i", toneCls);
            seg.style.flexGrow = String(Number(value));
            bar.append(seg);
          }
        });
        wrap.append(bar);
      }
      return wrap;
    };
    stat("card_source_files", single((review.source_manifest || {}).total_files));
    const sourceOnly = counts["source-only"] !== undefined ? counts["source-only"] : review.total_findings;
    stat("card_context_split", splitTile(counts["build-aware"] || 0, sourceOnly || 0, "tone-build", "tone-source"));
    stat("card_mapping_split", splitTile(
      Math.max(0, Number(review.total_findings || 0) - unmappedCount), unmappedCount,
      "tone-neutral", "tone-rl-unmapped"));
    stat("card_diagnostics", single(review.total_diagnostics));
    stat("card_valid_reports", single(
      Object.values(manifest.tools || {}).reduce((n, x) => n + Number(x.valid_reports || 0), 0)));
  };

  /* ---------- distribution charts ---------- */
  const bars = (target, entries, tone, ranked) => {
    const root = id(target);
    root.replaceChildren();
    const valid = entries.filter(x => Number(x[1]) > 0);
    if (!valid.length) {
      root.append(make("p", "empty", t("no_data")));
      return;
    }
    const max = Math.max(1, ...valid.map(x => Number(x[1])));
    valid.forEach(([label, count], index) => {
      const row = make("div", "bar");
      const name = make("span", "bar-label mono");
      if (ranked) name.append(make("span", "rank", String(index + 1)));
      name.append(document.createTextNode(String(label || "—")));
      const track = make("span", "track");
      const fill = make("span", "fill" + (tone ? " " + tone(label) : ""));
      fill.style.width = Math.max(1, Number(count) / max * 100) + "%";
      track.append(fill);
      row.append(name, track, make("span", "bar-count mono", number(count)));
      root.append(row);
    });
  };
  const compPanel = (target, byContext, order, tone) => {
    const root = id(target);
    root.replaceChildren();
    let any = false;
    [["build-aware", "legend_build"], ["source-only", "legend_source"]].forEach(([context, labelKey]) => {
      const stackNode = stackedBar(byContext[context] || {}, order, tone, true);
      if (!stackNode) return;
      const row = make("div", "comp-row");
      row.append(make("div", "ctx", t(labelKey)), stackNode);
      root.append(row);
      any = true;
    });
    if (!any) root.append(make("p", "empty", t("no_data")));
  };
  const renderHeatmap = () => {
    const root = id("heatmap");
    root.replaceChildren();
    if (!findings.length) {
      root.append(make("p", "empty", t("no_data")));
      return;
    }
    const perFile = new Map();
    findings.forEach(x => {
      const file = x.canonical_path || x.file || "—";
      if (!perFile.has(file)) perFile.set(file, { total: 0 });
      const entry = perFile.get(file);
      const sev = sevOrder.includes(x.severity) ? x.severity : "unknown";
      entry[sev] = (entry[sev] || 0) + 1;
      entry.total += 1;
    });
    const rows = [...perFile.entries()]
      .sort((a, b) => (b[1].total - a[1].total) || (a[0] < b[0] ? -1 : 1))
      .slice(0, 12);
    const max = Math.max(1, ...rows.map(pair => Math.max(...sevOrder.map(s => pair[1][s] || 0))));
    const grid = make("div", "hm");
    grid.append(make("span", "hm-h first"));
    sevOrder.forEach(s => grid.append(make("span", "hm-h", s)));
    grid.append(make("span", "hm-h", t("heat_total")));
    rows.forEach(([file, entry]) => {
      const cellFile = make("span", "hm-f", file);
      cellFile.title = file;
      grid.append(cellFile);
      sevOrder.forEach(s => {
        const value = entry[s] || 0;
        if (value) {
          const cell = make("span", "hm-c", number(value));
          const pct = Math.round(10 + 55 * value / max);
          cell.style.background = "color-mix(in srgb, var(--sev-" + s + ") " + pct + "%, transparent)";
          grid.append(cell);
        } else {
          grid.append(make("span", "hm-c muted", "·"));
        }
      });
      grid.append(make("span", "hm-t", number(entry.total)));
    });
    root.append(grid);
    if (review.findings_omitted) {
      root.append(make("p", "hm-note", fmt("heat_partial", { n: number(findings.length) })));
    }
  };
  const renderToolChart = () => {
    const root = id("tool-chart");
    root.replaceChildren();
    const entries = Object.entries(review.tools || {}).map(([name, data]) => {
      const fc = data.finding_counts || {};
      const source = fc["source-only"] !== undefined ? fc["source-only"] : (data.total_findings || 0);
      return [name, Number(fc["build-aware"] || 0), Number(source || 0)];
    }).filter(x => x[1] > 0 || x[2] > 0);
    if (!entries.length) {
      root.append(make("p", "empty", t("no_data")));
      return;
    }
    const legend = make("div", "legend");
    legend.append(chip("tone-build", t("legend_build")), chip("tone-source", t("legend_source")));
    root.append(legend);
    const max = Math.max(1, ...entries.map(x => Math.max(x[1], x[2])));
    entries.forEach(([name, build, source]) => {
      const group = make("div", "grp");
      group.append(make("div", "g-name", name));
      [[build, "tone-build", t("legend_build")], [source, "tone-source", t("legend_source")]]
        .forEach(([value, toneCls, label]) => {
          const row = make("div", "bar");
          const track = make("span", "track");
          const fill = make("span", "fill " + toneCls);
          fill.style.width = value ? Math.max(1, value / max * 100) + "%" : "0%";
          track.append(fill);
          row.append(make("span", "bar-label", label), track, make("span", "bar-count mono", number(value)));
          group.append(row);
        });
      root.append(group);
    });
  };
  const renderCharts = () => {
    compPanel("rl-comp", levelByContext, rawReviewLevels, rlTone);
    compPanel("sev-comp", sevByContext, sevOrder, sevTone);
    renderHeatmap();
    renderToolChart();
    bars("rule-chart", (review.top_rules || []).map(x => [x.rule_id, x.count]), null, true);
    bars("cwe-chart", (review.top_cwes || []).map(x => [x.cwe, x.count]), null, true);
  };

  /* ---------- tool cards ---------- */
  const renderTools = () => {
    const root = id("tool-cards");
    root.replaceChildren();
    Object.entries(review.tools || {}).forEach(([tool, data]) => {
      const card = make("article", "tool-card");
      const head = make("div");
      const badge = make("span", "badge " + statusTone(data.status), data.status || "unknown");
      head.append(make("h3", "", tool), badge);
      card.append(head);
      const dl = make("dl", "tool-values");
      const pair = (label, value) => dl.append(make("dt", "", label),
        make("dd", "", value === undefined || value === null ? "—" : value));
      const coverage = data.coverage || {};
      const fc = data.finding_counts || {};
      pair(t("tool_build_findings"), number(fc["build-aware"]));
      pair(t("tool_source_findings"), number(fc["source-only"] !== undefined ? fc["source-only"] : data.total_findings));
      pair(t("tool_diagnostics"), number(data.total_diagnostics));
      pair(t("tool_version"), data.version);
      pair(t("tool_coverage"),
        (coverage.analyzed ?? coverage.covered ?? 0) + "/" + (coverage.effective_total ?? coverage.total ?? 0));
      pair(t("tool_attempted"), coverage.attempted ?? coverage.covered ?? 0);
      pair(t("tool_excluded"), coverage.excluded || 0);
      pair(t("tool_valid_reports"), data.valid_reports);
      card.append(dl);
      const uc = Object.assign({}, ((manifest.tools || {})[tool] || {}).unit_counts, data.unit_counts);
      const planned = Number(uc.planned || 0);
      if (planned > 0) {
        const strip = make("div", "unit-strip");
        let shown = 0;
        [["completed", "tone-ok"], ["failed", "tone-bad"], ["timed_out", "tone-bad"], ["unscheduled", "tone-warn"]]
          .forEach(([key, toneCls]) => {
            const value = Number(uc[key] || 0);
            if (value > 0) {
              const seg = make("i", toneCls);
              seg.style.flexGrow = String(value);
              strip.append(seg);
              shown += value;
            }
          });
        if (shown < planned) {
          const filler = make("i", "tone-neutral");
          filler.style.flexGrow = String(planned - shown);
          filler.style.opacity = "0.25";
          strip.append(filler);
        }
        card.append(strip);
        card.append(make("p", "unit-caption",
          [["unit_planned", "planned"], ["unit_completed", "completed"], ["unit_failed", "failed"],
           ["unit_timed_out", "timed_out"], ["unit_unscheduled", "unscheduled"]]
            .filter(([_, key]) => key === "planned" || key === "completed" || Number(uc[key] || 0) > 0)
            .map(([labelKey, key]) => t(labelKey) + " " + number(uc[key] || 0)).join(" · ")));
      }
      if (data.reason) card.append(make("p", "", data.reason));
      (data.units || []).filter(unit => unit.status !== "completed").forEach(unit =>
        card.append(make("p", "notice", unit.id + ": " + unit.status + (unit.reason ? " — " + unit.reason : ""))));
      const links = make("div", "links");
      (data.units || []).forEach(unit => (unit.artifacts || []).forEach(a => links.append(link(a.path, a.path))));
      if (!links.childNodes.length) links.append(make("span", "muted", t("tool_no_artifacts")));
      card.append(links);
      root.append(card);
    });
  };

  /* ---------- scope ---------- */
  const renderScope = () => {
    const sm = review.source_manifest || {};
    const scope = id("scope-values");
    scope.replaceChildren();
    const pair = (label, value) => scope.append(make("dt", "", label), make("dd", "", value));
    pair(t("scope_inventory"), number(sm.total_files));
    pair(t("scope_compile_db"), number((manifest.compile_database || {}).filtered_entries));
    pair(t("scope_context"), manifest.analysis_context || "—");
    const stable = (manifest.source_inventory || {}).stable;
    pair(t("scope_stable"), stable === true ? t("yes") : (stable === false ? t("no") : "—"));
    id("source-summary").textContent = fmt("source_files_n", { n: number((sm.files || []).length) });
    const list = id("source-files");
    list.replaceChildren();
    (sm.files || []).forEach(x => list.append(make("li", "", x)));
  };

  /* ---------- overlap ---------- */
  const state = { page: 1, fingerprints: null };
  const renderOverlap = () => {
    id("overlap-count").textContent = fmt("overlap_groups_n", { n: number((review.overlap_groups || []).length) });
    const body = id("overlap-body");
    body.replaceChildren();
    (review.overlap_groups || []).forEach(group => {
      const tr = make("tr");
      const action = make("td");
      const button = make("button", "", t("overlap_view"));
      button.onclick = () => {
        state.fingerprints = new Set(group.fingerprints || []);
        state.page = 1;
        renderFindings();
        window.location.hash = "findings";
      };
      action.append(button);
      tr.append(
        make("td", "", group.category),
        make("td", "loc", group.canonical_path + ":" + group.line),
        make("td", "", (group.tools || []).join(", ")),
        make("td", "", number((group.fingerprints || []).length)),
        action);
      body.append(tr);
    });
    if (!body.childNodes.length) tableEmpty(body, 5, t("no_overlap"));
  };

  /* ---------- diagnostics ---------- */
  const renderDiagnostics = () => {
    id("diagnostic-count").textContent = fmt("diag_n", { n: number((review.diagnostics || []).length) });
    const body = id("diagnostic-body");
    body.replaceChildren();
    (review.diagnostics || []).forEach(x => {
      const tr = make("tr");
      const evidence = make("td");
      evidence.append(link("native", x.source_artifact));
      const sevCell = make("td");
      sevCell.append(chip(sevTone(x.severity), x.severity || "unknown"));
      tr.append(
        sevCell,
        make("td", "mono", x.tool),
        make("td", "", x.category),
        make("td", "", x.fatal ? t("fatal_yes") : t("fatal_no")),
        make("td", "loc", locText(x)),
        make("td", "", x.message),
        evidence);
      body.append(tr);
    });
    if (!body.childNodes.length) tableEmpty(body, 7, t("no_diags"));
  };

  /* ---------- findings ---------- */
  const addOptions = (select, values) => {
    [...new Set(values.filter(Boolean))].sort().forEach(value => {
      const option = make("option", "", value);
      option.value = value;
      select.append(option);
    });
  };
  addOptions(id("review-level"), findings.map(x => x.review_level));
  addOptions(id("severity"), findings.map(x => x.severity));
  addOptions(id("tool"), findings.map(x => x.tool));
  addOptions(id("cwe"), findings.map(x => x.cwe));
  const buildCount = findings.filter(x => x.evidence_context === "build-aware").length;
  const sourceCount = findings.filter(x => x.evidence_context === "source-only").length;
  if (buildCount) id("context").value = "build-aware";

  const renderContextNotice = () => {
    const notice = id("context-notice");
    if (buildCount && sourceCount) {
      notice.hidden = false;
      notice.textContent = fmt("context_notice", { n: number(sourceCount) });
    } else {
      notice.hidden = true;
    }
  };

  function renderFindings() {
    id("finding-total").textContent = fmt("findings_n", { n: number(findings.length) });
    const q = id("search").value.toLowerCase();
    const context = id("context").value;
    const reviewLevel = id("review-level").value;
    const sev = id("severity").value;
    const tool = id("tool").value;
    const cwe = id("cwe").value;
    const sort = id("sort").value;
    let rows = findings.filter(x =>
      (!state.fingerprints || state.fingerprints.has(x.fingerprint))
      && (!context || x.evidence_context === context)
      && (!reviewLevel || x.review_level === reviewLevel)
      && (!sev || x.severity === sev)
      && (!tool || x.tool === tool)
      && (!cwe || x.cwe === cwe)
      && (!q || [x.rule_id, x.cwe, x.canonical_path, x.message].some(v => String(v || "").toLowerCase().includes(q))));
    rows = [...rows].sort((a, b) =>
      sort === "location" ? locText(a).localeCompare(locText(b))
        : sort === "tool" ? String(a.tool || "").localeCompare(String(b.tool || ""))
          : sort === "rule" ? String(a.rule_id || "").localeCompare(String(b.rule_id || ""))
            : (Number(b.rank || 0) - Number(a.rank || 0)));
    const size = Number(id("page-size").value);
    const pages = Math.max(1, Math.ceil(rows.length / size));
    state.page = Math.min(state.page, pages);
    const body = id("finding-body");
    body.replaceChildren();
    rows.slice((state.page - 1) * size, state.page * size).forEach(x => {
      const tr = make("tr");
      const evidence = make("td");
      evidence.append(link("native", x.source_artifact));
      const levelCell = make("td");
      levelCell.append(chip(rlTone(x.review_level), x.review_level));
      const sevCell = make("td");
      sevCell.append(chip(sevTone(x.severity), x.severity || "unknown"));
      tr.append(
        levelCell,
        sevCell,
        make("td", "mono", x.original_severity === undefined || x.original_severity === null ? "—" : x.original_severity),
        make("td", "", x.evidence_context),
        make("td", "mono", x.tool),
        make("td", "mono", x.rule_id),
        make("td", "mono", x.cwe || "—"),
        make("td", "loc", locText(x)),
        make("td", "", x.message),
        evidence);
      body.append(tr);
    });
    if (!body.childNodes.length) tableEmpty(body, 10, t("no_findings"));
    id("page-status").textContent = fmt("page_status", { results: number(rows.length), page: state.page, pages: pages });
    id("previous").disabled = state.page <= 1;
    id("next").disabled = state.page >= pages;
  }

  /* ---------- wiring ---------- */
  ["search", "context", "review-level", "severity", "tool", "cwe", "sort", "page-size"].forEach(x =>
    id(x).addEventListener("input", () => { state.page = 1; renderFindings(); }));
  id("previous").onclick = () => { state.page--; renderFindings(); };
  id("next").onclick = () => { state.page++; renderFindings(); };
  id("reset").onclick = () => {
    ["search", "context", "review-level", "severity", "tool", "cwe"].forEach(x => { id(x).value = ""; });
    id("sort").value = "priority";
    state.page = 1;
    state.fingerprints = null;
    renderFindings();
  };
  const renderAll = () => {
    applyLanguage();
    renderMasthead();
    renderVerdict();
    renderNotices();
    renderStats();
    renderCharts();
    renderTools();
    renderScope();
    renderOverlap();
    renderDiagnostics();
    renderContextNotice();
    renderFindings();
  };
  id("lang-toggle").onclick = () => {
    lang = lang === "zh" ? "en" : "zh";
    try {
      window.localStorage.setItem("codeAnalyzerLang", lang);
    } catch (err) { /* ignore unavailable storage */ }
    renderAll();
  };
  renderAll();
  window.__codeAnalyzerDashboard.ready();
})();
"""


_HTML_BODY = r"""<div class="sheet">
<header class="masthead">
<div class="mast-top">
<div>
<p class="eyebrow">Code Analyzer</p>
<h1 data-i18n="report_title">静态分析证据报告</h1>
<p id="project">正在载入报告…</p>
</div>
<div class="mast-right">
<p class="run-no" id="run-no"></p>
<div class="mast-actions">
<button id="lang-toggle" type="button">English</button>
<a href="review/summary.json" data-i18n="open_json">查看原始 JSON</a>
</div>
</div>
</div>
<dl class="mast-meta" id="run-meta"></dl>
</header>
<nav class="nav">
<a href="#overview"><span class="sec-no">1</span><span data-i18n="sec_overview">总体判定</span></a>
<a href="#distribution"><span class="sec-no">2</span><span data-i18n="sec_distribution">发现分布</span></a>
<a href="#tools"><span class="sec-no">3</span><span data-i18n="sec_tools">执行与原生证据</span></a>
<a href="#scope"><span class="sec-no">4</span><span data-i18n="sec_scope">扫描范围</span></a>
<a href="#overlap"><span class="sec-no">5</span><span data-i18n="sec_overlap">跨工具邻近重叠</span></a>
<a href="#diagnostics"><span class="sec-no">6</span><span data-i18n="sec_diagnostics">工具诊断</span></a>
<a href="#findings"><span class="sec-no">7</span><span data-i18n="sec_findings">发现明细</span></a>
</nav>
<main>
<p class="notice" data-i18n="disclaimer">派生的 findings 不具权威性。请对照其链接的原生工具报告与实际的构建配置逐条确认。</p>
<section id="overview">
<h2><span class="sec-no">§ 1</span><span data-i18n="sec_overview">总体判定</span></h2>
<div class="verdict" id="verdict"></div>
<div id="integrity-warning"></div>
<div class="stats" id="cards"></div>
</section>
<section id="distribution">
<h2><span class="sec-no">§ 2</span><span data-i18n="sec_distribution">发现分布</span></h2>
<div class="charts">
<article class="panel wide"><h3 data-i18n="chart_rl_comp">评分等级构成</h3><div id="rl-comp"></div></article>
<article class="panel wide"><h3 data-i18n="chart_sev_comp">规范化严重度构成</h3><div id="sev-comp"></div></article>
<article class="panel wide"><h3 data-i18n="chart_heatmap">文件 × 严重度</h3><div id="heatmap"></div></article>
<article class="panel"><h3 data-i18n="chart_tools">各分析器</h3><div id="tool-chart"></div></article>
<article class="panel"><h3 data-i18n="chart_top_rules">规则 · 前列</h3><div id="rule-chart"></div></article>
<article class="panel"><h3 data-i18n="chart_top_cwes">CWE · 前列</h3><div id="cwe-chart"></div></article>
</div>
</section>
<section id="tools">
<h2><span class="sec-no">§ 3</span><span data-i18n="sec_tools">执行与原生证据</span></h2>
<div class="tools" id="tool-cards"></div>
</section>
<section id="scope">
<h2><span class="sec-no">§ 4</span><span data-i18n="sec_scope">扫描范围</span></h2>
<article class="panel">
<dl class="tool-values" id="scope-values"></dl>
<details><summary id="source-summary">源文件</summary><ol class="file-list" id="source-files"></ol></details>
</article>
</section>
<section id="overlap">
<div class="section-head">
<h2><span class="sec-no">§ 5</span><span data-i18n="sec_overlap">跨工具邻近重叠</span></h2>
<span class="muted" id="overlap-count"></span>
</div>
<div class="table-wrap"><table><thead><tr>
<th data-i18n="th_category">类别</th>
<th data-i18n="th_location">位置</th>
<th data-i18n="th_tools">工具</th>
<th data-i18n="th_evidence">证据</th>
<th data-i18n="th_action">操作</th>
</tr></thead><tbody id="overlap-body"></tbody></table></div>
</section>
<section id="diagnostics">
<div class="section-head">
<h2><span class="sec-no">§ 6</span><span data-i18n="sec_diagnostics">工具诊断</span></h2>
<span class="muted" id="diagnostic-count"></span>
</div>
<div class="table-wrap"><table><thead><tr>
<th data-i18n="th_severity">严重度</th>
<th data-i18n="th_tool">分析器</th>
<th data-i18n="th_diag_category">类别</th>
<th data-i18n="th_fatal">致命</th>
<th data-i18n="th_location">位置</th>
<th data-i18n="th_message">消息</th>
<th data-i18n="th_evidence">证据</th>
</tr></thead><tbody id="diagnostic-body"></tbody></table></div>
</section>
<section id="findings">
<div class="section-head">
<h2><span class="sec-no">§ 7</span><span data-i18n="sec_findings">发现明细</span></h2>
<span class="muted" id="finding-total"></span>
</div>
<p class="notice" id="context-notice" hidden></p>
<div class="controls">
<label class="control"><span data-i18n="search_label">搜索</span><input id="search" type="search" placeholder="规则、CWE、文件或消息"></label>
<label class="control"><span data-i18n="filter_context">上下文</span><select id="context">
<option value="" data-i18n="opt_all_contexts">全部上下文</option>
<option value="build-aware" data-i18n="opt_build">构建感知</option>
<option value="source-only" data-i18n="opt_source">仅源码</option>
</select></label>
<label class="control"><span data-i18n="filter_review_level">评分等级</span><select id="review-level">
<option value="" data-i18n="opt_all_levels">全部等级</option>
</select></label>
<label class="control"><span data-i18n="filter_severity">规范化严重度</span><select id="severity">
<option value="" data-i18n="opt_all_sev">全部严重度</option>
</select></label>
<label class="control"><span data-i18n="filter_tool">分析器</span><select id="tool">
<option value="" data-i18n="opt_all_tools">全部分析器</option>
</select></label>
<label class="control"><span data-i18n="filter_cwe">CWE</span><select id="cwe">
<option value="" data-i18n="opt_all_cwe">全部 CWE</option>
</select></label>
<label class="control"><span data-i18n="filter_sort">排序</span><select id="sort">
<option value="priority" data-i18n="opt_sort_priority">优先级</option>
<option value="location" data-i18n="opt_sort_location">位置</option>
<option value="tool" data-i18n="opt_sort_tool">分析器</option>
<option value="rule" data-i18n="opt_sort_rule">规则</option>
</select></label>
<button id="reset" type="button" data-i18n="reset">重置</button>
</div>
<div class="table-wrap"><table><thead><tr>
<th data-i18n="th_review_level">评分等级</th>
<th data-i18n="th_severity">严重度</th>
<th data-i18n="th_native">原生等级</th>
<th data-i18n="th_context">上下文</th>
<th data-i18n="th_tool">分析器</th>
<th data-i18n="th_rule">规则</th>
<th data-i18n="th_cwe">CWE</th>
<th data-i18n="th_location">位置</th>
<th data-i18n="th_message">消息</th>
<th data-i18n="th_evidence">证据</th>
</tr></thead><tbody id="finding-body"></tbody></table></div>
<div class="pagination">
<span id="page-status" class="muted"></span>
<span>
<select id="page-size"><option>25</option><option selected>50</option><option>100</option><option>250</option></select>
<button id="previous" data-i18n="prev">上一页</button>
<button id="next" data-i18n="next">下一页</button>
</span>
</div>
</section>
</main>
<noscript><p class="notice">需要启用 JavaScript;完整数据仍在 <a href="review/summary.json">review/summary.json</a> 中。JavaScript is required; the complete data remains in review/summary.json.</p></noscript>
</div>
"""


_TEMPLATE = "".join([
    '<!doctype html>\n<html lang="zh-CN"><head><meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width,initial-scale=1">',
    '<meta name="color-scheme" content="light dark">',
    "<title>Code Analyzer · 静态分析证据报告</title>\n<style>",
    _CSS,
    "</style></head><body>\n",
    _HTML_BODY,
    "<script>",
    _JS_GUARD,
    "</script>",
    '<script id="report-data" type="application/json">__CODE_ANALYZER_DATA__</script>',
    "<script>",
    _JS_MAIN,
    "</script></body></html>",
])
