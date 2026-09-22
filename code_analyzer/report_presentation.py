"""Read-only presentation helpers. Never import an LLM runtime here."""
from __future__ import annotations

import hashlib
import html
import json
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote

from .persist import json_bytes
from .summary_digest import build_digest

SUMMARY_PATH = "audit/summary.json"
SUMMARY_NOTICE = (
    "AI 辅助意见，不改变原始证据或退出码。 / AI-assisted opinion; "
    "does not change evidence or exit codes."
)
STATUS_LABELS = {
    "complete": "完整 / complete", "completed": "已完成 / completed",
    "partial": "部分完成 / partial", "failed": "失败 / failed",
    "interrupted": "中断 / interrupted", "unknown": "未记录 / not recorded",
    "not_requested": "未请求 / not requested", "not_applicable": "不适用 / not applicable",
    "CONFIRMED": "模型确认 / CONFIRMED", "LIKELY": "可能成立 / LIKELY",
    "UNCERTAIN": "不确定 / UNCERTAIN", "FALSE_POSITIVE": "模型判为误报 / FALSE_POSITIVE",
    "unvalidated": "未核验 / unvalidated",
    "missing": "未生成 / not generated", "invalid": "总结损坏或格式不支持 / invalid summary",
    "matched": "摘要输入一致 / digest inputs match",
    "changed": "输入已变化或脱敏 / inputs changed or redacted",
    "unverified": "无法核验摘要输入 / digest inputs cannot be verified",
}
COVERAGE_LABELS = {
    "input_coverage": "输入文件 / Input files",
    "tu_report_coverage": "有报告的编译单元 / Translation units with reports",
    "llm_unit_coverage": "LLM 扫描单元 / LLM scan units",
}


def status_label(value: Any) -> str:
    return STATUS_LABELS.get(str(value or "unknown"), str(value))


def load_run_summary(run_dir: Path, manifest: dict[str, Any], review: dict[str, Any] | None,
                     assessment: dict[str, Any] | None) -> dict[str, Any]:
    """An optional opinion, checked against exactly the input digest it saw."""
    block = manifest.get("summary") if isinstance(manifest.get("summary"), dict) else {}
    if block.get("status") == "failed":
        return {"status": "failed"}  # A previous success must not mask a failed retry.
    try:
        document = json.loads((run_dir / SUMMARY_PATH).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"status": "missing"}
    except (OSError, UnicodeError, ValueError):
        return {"status": "invalid"}
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        return {"status": "invalid"}
    if not isinstance(document.get("headline"), str) or not document["headline"].strip():
        return {"status": "invalid"}
    for key in ("themes", "priorities", "coverage_caveats", "disagreements", "unknowns"):
        values = document.get(key, [])
        kind = dict if key in {"themes", "priorities"} else str
        if not isinstance(values, list) or not all(isinstance(v, kind) for v in values):
            return {"status": "invalid"}
    verification = "unverified"
    if review is not None and document.get("run_digest_sha256"):
        try:
            current = hashlib.sha256(json_bytes(build_digest(manifest, review, assessment or {}))).hexdigest()
            verification = "matched" if current == document["run_digest_sha256"] else "changed"
        except (TypeError, ValueError, AttributeError):
            pass  # An older optional data shape must not break the evidence report.
    return {"status": "available", "verification": verification, "document": document}


def safe_relative_path(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    decoded = unquote(value)
    if (decoded.startswith(("/", "\\")) or ":" in decoded or "\\" in decoded
            or any(part in {"", ".", ".."} for part in decoded.split("/"))
            or any(ord(c) < 32 for c in decoded)):
        return None
    return value


def artifact_availability(manifest: dict[str, Any]) -> dict[str, str]:
    """Only path/status, never hashes: including our own digest prevents fixed points."""
    result = {item["path"]: "available" for item in manifest.get("artifacts", [])
              if isinstance(item, dict) and safe_relative_path(item.get("path"))}
    result["manifest.json"] = "available"
    for item in (manifest.get("export") or {}).get("omitted_artifacts", []):
        if isinstance(item, dict) and item.get("entry") not in result:
            result[str(item.get("entry"))] = "omitted"
    return result


def md_text(value: Any) -> str:
    text = html.escape(str(value if value is not None else "—"), quote=False)
    for char in ("\\", "`", "*", "_", "[", "]", "|", "#"):
        text = text.replace(char, "\\" + char)
    return text.replace("\r", "").replace("\n", "<br>")


def md_link(label: str, path: Any, manifest: dict[str, Any], *, parent: str = "..",
            availability: dict[str, str] | None = None) -> str:
    safe = safe_relative_path(path)
    available = artifact_availability(manifest) if availability is None else availability
    if not safe or safe not in available or available[safe] != "available":
        reason = "已省略 / omitted" if available.get(str(path)) == "omitted" else "不可用或未记录 / unavailable or unrecorded"
        return f"{md_text(label)}: {md_text(path or '—')} ({reason})"
    return f"[{md_text(label)}]({parent}/{quote(safe, safe='/')})"


def summary_markdown(run_summary: dict[str, Any] | None, *, manifest: dict[str, Any],
                     heading: str = "##") -> list[str]:
    info = run_summary or {"status": "missing"}
    lines = [f"{heading} AI 总体汇总 / AI Run Summary", "", f"> {SUMMARY_NOTICE}", ""]
    if info.get("status") != "available":
        return lines + [status_label(info.get("status")), ""]
    document = info["document"]
    lines += [f"{md_text(status_label(info.get('verification')))}", "",
              f"- 模型 / Model: {md_text(document.get('model'))}",
              f"- 摘要指纹 / Digest: {md_text(document.get('run_digest_sha256'))}",
              f"- 来源 / Source: {md_link('AI JSON', SUMMARY_PATH, manifest)}", "",
              f"**{md_text(document.get('headline'))}**", "",
              f"模型意见 / Model posture: {md_text(document.get('posture'))}", ""]
    for key, label in (
        ("themes", "主要模式 / Themes"), ("coverage_caveats", "覆盖保留意见 / Coverage caveats"),
        ("disagreements", "分歧 / Disagreements"), ("unknowns", "尚未解决 / Unknowns"),
        ("priorities", "建议的下一步 / Suggested next steps"),
    ):
        items = document.get(key) or []
        if not items:
            continue
        lines += [f"{heading}# {label}", ""]
        for item in items:
            if isinstance(item, dict):
                if key == "themes":
                    parts = [item.get(k) for k in ("title", "what", "weight", "why_it_matters") if item.get(k)]
                    where = item.get("where")
                    if isinstance(where, list):
                        parts.append("涉及 / Where: " + ", ".join(str(v) for v in where))
                else:
                    parts = [item.get(k) for k in ("do", "because") if item.get(k)]
                lines.append("- " + " — ".join(md_text(part) for part in parts))
            else:
                lines.append("- " + md_text(item))
        lines.append("")
    return lines


def standalone_summary_markdown(run_summary: dict[str, Any], manifest: dict[str, Any]) -> str:
    lines = ["# 总体汇总 / AI Run Summary", "",
             f"- 项目 / Project: {md_text(manifest.get('source'))}",
             f"- 运行 / Run: {md_text(manifest.get('run_id'))}",
             f"- 当前运行状态 / Current run status: {status_label(manifest.get('status'))}", ""]
    return "\n".join(lines + summary_markdown(run_summary, manifest=manifest)).rstrip() + "\n"


def review_markdown(review: dict[str, Any], scope_text: str, max_findings: int, *,
                    manifest: dict[str, Any] | None = None, assessment: dict[str, Any] | None = None,
                    run_summary: dict[str, Any] | None = None) -> str:
    manifest = manifest or {}
    availability = artifact_availability(manifest)

    def evidence_link(label: str, path: Any) -> str:
        return md_link(label, path, manifest, availability=availability)

    metrics = (assessment or {}).get("metrics") or {}
    findings = review.get("findings") or []
    shown = findings[:max(0, max_findings)]
    candidates = (assessment or {}).get("candidates") or []
    stable = (manifest.get("source_inventory") or {}).get("stable")
    stable_label = "是 / yes" if stable is True else "否 / no" if stable is False else "未记录 / not recorded"
    gate = manifest.get("gate") or {}
    gate_label = ("未启用 / disabled" if not gate.get("policy") or gate.get("policy") == "none"
                  else "触发 / triggered" if gate.get("triggered") else "未触发 / not triggered")
    member_index: dict[str, list[dict[str, Any]]] = {}
    for candidate in candidates:
        for fingerprint in candidate.get("member_fingerprints") or []:
            member_index.setdefault(fingerprint, []).append(candidate)
    lines = ["# 代码分析证据报告 / Code Analysis Evidence Report", "",
             "## 审计概览 / Audit Overview", "",
             f"- 项目 / Project: {md_text(review.get('project'))}",
             f"- 运行 / Run: {md_text((review.get('run') or {}).get('id') or manifest.get('run_id'))}",
             f"- 运行状态 / Run status: {status_label(manifest.get('status') or (review.get('run') or {}).get('status'))}",
             f"- 退出码 / Exit code: {md_text(manifest.get('exit_code'))}",
             f"- 证据收集完整性 / Evidence integrity: {status_label((review.get('report_integrity') or {}).get('status'))}",
             f"- 源码稳定性 / Source stability: {stable_label}",
             f"- 质量门禁 / Quality gate: {gate_label}; {md_text(gate.get('policy', 'none'))}",
             f"- 原始发现 / Total findings: {review.get('total_findings', len(findings))}",
             f"- 关联候选 / Candidates: {metrics.get('candidates_total', '未记录 / not recorded')}",
             f"- 已核验 / Validated: {metrics.get('validated', '未记录 / not recorded')}; "
             f"未核验 / Unvalidated: {metrics.get('unvalidated', '未记录 / not recorded')}", "",
             "> 运行状态、证据完整性和扫描覆盖范围分别衡量不同事项；完成不表示代码安全。 / "
             "Run completion, evidence integrity and scan coverage are distinct; completion does not establish code safety.", "",
             "## 扫描范围与缺口 / Scan Scope and Gaps", "", f"扫描范围 / Scan scope: {scope_text}", "",
             f"分析上下文 / Analysis context: {md_text(manifest.get('analysis_context', '未记录 / not recorded'))}", ""]
    for reason in manifest.get("analysis_context_reasons") or []:
        lines.append("- " + md_text(reason))
    lines += ["", "| 分析器 / Analyzer | 状态 / Status | 统计口径 / Basis | 覆盖 / Covered | 单元：完成 / 计划 / Units: done / planned |",
              "| --- | --- | --- | --- | --- |"]
    producers = {**(review.get("tools") or {}), **(review.get("scanners") or {})}
    for name, block in producers.items():
        coverage = block.get("coverage") or {}
        denominator = coverage.get("effective_total", coverage.get("total", "未记录 / not recorded"))
        numerator = coverage.get("analyzed", coverage.get("covered", "未记录 / not recorded"))
        units = block.get("unit_counts") or {}
        basis = COVERAGE_LABELS.get(coverage.get("metric"), coverage.get("metric") or "未记录 / not recorded")
        lines.append(f"| {md_text(name)} | {md_text(status_label(block.get('status')))} | {md_text(basis)} | {numerator} / {denominator} "
                     f"| {units.get('completed', '—')} / {units.get('planned', '—')} |")
    lines.append("")
    for name, block in producers.items():
        if block.get("reason"):
            lines.append(f"- {md_text(name)}: {md_text(block['reason'])}")
        units = block.get("unit_counts") or {}
        failures = [f"{label}: {units[key]}" for key, label in (
            ("failed", "失败 / failed"), ("timed_out", "超时 / timed out"),
            ("unscheduled", "未调度 / unscheduled"), ("interrupted", "中断 / interrupted")) if units.get(key)]
        if failures:
            lines.append(f"- {md_text(name)}: " + "; ".join(failures))
        coverage = block.get("coverage") or {}
        if "analysis_reached" in coverage:
            lines.append(f"- {md_text(name)}: 实际进入分析 / Analysis reached: "
                         f"{coverage['analysis_reached']} / {coverage.get('effective_total', coverage.get('total', '—'))}")
    for gap in review.get("coverage_gaps") or []:
        lines.append(f"- {md_text(gap.get('tool'))}: 排除 / excluded {gap.get('excluded', 0)}; "
                     f"未分析 / unanalyzed {gap.get('unanalyzed', 0)}")
        for path in gap.get("excluded_files") or []:
            lines.append("  - " + md_text(path))
    for unit in (review.get("report_integrity") or {}).get("omitted_units") or []:
        lines.append("- 省略单元 / Omitted unit: " + "; ".join(
            f"{md_text(key)}: {md_text(value)}" for key, value in unit.items()))
    if review.get("llm_coverage"):
        lines += ["", "| LLM 覆盖维度 / Coverage basis | 已扫描 / Scanned | 总数 / Total |",
                  "| --- | --- | --- |"]
        for key, label in (("files", "文件 / Files"), ("functions", "函数 / Functions"), ("bytes", "字节 / Bytes")):
            values = review["llm_coverage"].get(key) or {}
            lines.append(f"| {label} | {values.get('scanned', '—')} | {values.get('total', '—')} |")
    lines += ["", "## 候选核验 / Candidate Validation", "", f"> {SUMMARY_NOTICE}", "",
              "| 辅助判定 / Model verdict | 数量 / Count |", "| --- | --- |"]
    for label, count in (metrics.get("by_verdict") or {}).items():
        lines.append(f"| {status_label(label)} | {count} |")
    lines.append("")
    for candidate in candidates[:max(0, max_findings)]:
        verdict = candidate.get("verdict") or {}
        lines += [f"### {md_text(candidate.get('id'))} · {md_text(candidate.get('category'))}", "",
                  f"- 位置 / Location: {md_text(candidate.get('canonical_path'))}:{candidate.get('line_start', '?')}",
                  f"- 来源 / Origin: {md_text(candidate.get('origin'))}; {md_text(', '.join(candidate.get('sources') or []))}",
                  f"- 辅助判定 / Model verdict: {status_label(verdict.get('label', 'unvalidated'))}"]
        for key, label in (("rationale", "核验理由 / Rationale"), ("decisive_line", "关键行 / Decisive line"),
                           ("remediation", "修复建议 / Remediation")):
            if verdict.get(key):
                lines.append(f"- {label}: {md_text(verdict[key])}")
        lines += ["- 成员指纹 / Member fingerprints: " + md_text(", ".join(candidate.get("member_fingerprints") or [])), ""]
    if not assessment:
        lines += ["未生成关联核验数据 / No assessment available.", ""]
    lines += [f"候选已列出 / Candidates listed: {min(len(candidates), max(0, max_findings))} / {len(candidates)}. "
              + evidence_link("完整核验数据 / Full assessment", "audit/assessment.json"), ""]
    lines += summary_markdown(run_summary, manifest=manifest)
    lines += ["## 原始发现 / Original Findings", "",
              f"全量 / Total: {review.get('total_findings', len(findings))}; 已列出 / Listed: {len(shown)}; "
              f"未列出 / Omitted: {max(0, len(findings) - len(shown))}.", "",
              "[完整发现 / Full findings](summary.json)", ""]
    for finding in shown:
        lines += [f"### {md_text(finding.get('canonical_path') or finding.get('file'))}:{md_text(finding.get('line'))}", "",
                  md_text(finding.get("message")), ""]
        for key, label in (("review_level", "审查等级 / Review level"), ("severity", "严重度 / Severity"),
                           ("original_severity", "原生等级 / Native level"), ("tool", "分析器 / Analyzer"),
                           ("engine", "引擎 / Engine"), ("evidence_context", "上下文 / Context"),
                           ("rule_id", "规则 / Rule"), ("cwe", "CWE"), ("fingerprint", "指纹 / Fingerprint"),
                           ("model", "模型 / Model"), ("confidence", "置信度 / Confidence")):
            if key in finding:
                lines.append(f"- {label}: {md_text(finding[key])}")
        lines.append("- " + evidence_link("原始证据 / Native evidence", finding.get("source_artifact")))
        related = member_index.get(finding.get("fingerprint", ""), [])
        if related:
            lines.append("- 关联候选 / Candidates: " + md_text(", ".join(c["id"] for c in related)))
        lines.append("")
    lines += ["## 统计与执行附录 / Statistics and Execution Appendix", ""]
    for key, label in (("severity_counts", "严重度 / Severity"), ("review_level_counts", "审查等级 / Review levels"),
                       ("finding_counts_by_engine", "引擎 / Engines")):
        lines += [f"### {label}", "", "| 分组 / Group | 数量 / Count |", "| --- | --- |"]
        lines.extend(f"| {md_text(group)} | {count} |" for group, count in (review.get(key) or {}).items())
        lines.append("")
    lines += ["", "### 工具诊断 / Tool Diagnostics", ""]
    for item in review.get("diagnostics") or []:
        lines.append(f"- {md_text(item.get('tool'))} · {md_text(item.get('category'))}: {md_text(item.get('message'))} · "
                     + evidence_link("证据 / Evidence", item.get("source_artifact")))
    if not review.get("diagnostics"):
        lines.append("无工具诊断 / No tool diagnostics.")
    lines += ["", "### 邻近重叠 / Nearby Overlap", ""]
    for group in review.get("overlap_groups") or []:
        lines.append(f"- {md_text(group.get('canonical_path'))}:{md_text(group.get('line'))} · "
                     + md_text(", ".join(group.get("tools") or [])))
    reference = review.get("grading_reference") or {}
    if reference:
        document = reference.get("document") or {}
        lines += ["", "### 分级参考 / Grading Reference", "",
                  f"- 文档 / Document: {md_text(document.get('file_name'))}",
                  f"- SHA-256: {md_text(document.get('sha256'))}"]
        for level in reference.get("levels") or []:
            lines.append(f"- {md_text(level.get('label') or level.get('id'))}: {md_text(level.get('description'))}")
    lines += ["", "Manual verification is required; a tool level is not an automatic vulnerability verdict.",
              "邻近重叠不合并原始证据 / Nearby overlap never merges evidence rows.", ""]
    return "\n".join(lines)
