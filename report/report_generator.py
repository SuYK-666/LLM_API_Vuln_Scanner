import json
import logging
from pathlib import Path
from typing import Any, Dict

from jinja2 import Environment, FileSystemLoader, select_autoescape

logger = logging.getLogger(__name__)

LABELS = {
    "zh": {
        "title": "LLM API 越权漏洞分析报告",
        "summary_endpoints": "测试接口数",
        "summary_findings": "发现风险数",
        "summary_overall": "总体风险",
        "summary_counts": "高/中/低",
        "findings": "风险明细",
        "no_findings": "未发现风险项",
        "risk_object": "风险对象",
        "api": "接口",
        "trigger": "触发条件",
        "trigger_payload": "触发载荷",
        "evidence": "风险证据（重点）",
        "status_compare": "状态码对比",
        "similarity": "内容相似度",
        "schema_overlap": "JSON 结构重合度",
        "sensitive_hits": "敏感命中",
        "evidence_highlight": "证据摘要",
        "evidence_reasons": "判定理由",
        "baseline_preview": "基线响应预览",
        "attack_preview": "攻击响应预览",
        "impact": "影响分析",
        "conclusion": "展示结论",
        "mitigation": "防护与缓解建议 (Mitigation & Prevention)",
        "summary": "摘要",
        "immediate": "即时修复",
        "engineering": "工程加固",
        "monitoring": "监控与检测",
        "source": "建议来源",
        "finding_prefix": "风险项",
    },
    "en": {
        "title": "LLM API Broken Access Control Report",
        "summary_endpoints": "Endpoints Tested",
        "summary_findings": "Findings",
        "summary_overall": "Overall Risk",
        "summary_counts": "High/Medium/Low",
        "findings": "Findings",
        "no_findings": "No findings detected",
        "risk_object": "Risk Object",
        "api": "API",
        "trigger": "Trigger Condition",
        "trigger_payload": "Trigger Payload",
        "evidence": "Risk Evidence (Key)",
        "status_compare": "Status Compare",
        "similarity": "Similarity",
        "schema_overlap": "JSON Schema Overlap",
        "sensitive_hits": "Sensitive Hits",
        "evidence_highlight": "Evidence Highlight",
        "evidence_reasons": "Reasons",
        "baseline_preview": "Baseline Preview",
        "attack_preview": "Attack Preview",
        "impact": "Impact Analysis",
        "conclusion": "Conclusion",
        "mitigation": "Mitigation & Prevention",
        "summary": "Summary",
        "immediate": "Immediate Fixes",
        "engineering": "Engineering Hardening",
        "monitoring": "Detection and Monitoring",
        "source": "Suggestion Source",
        "finding_prefix": "Finding",
    },
}


def _format_override_fields(payload: Dict[str, Any]) -> str:
    parts = []
    query = payload.get("query", {}) if isinstance(payload, dict) else {}
    body = payload.get("json_body", {}) if isinstance(payload, dict) else {}
    form = payload.get("form_body", {}) if isinstance(payload, dict) else {}
    headers = payload.get("headers", {}) if isinstance(payload, dict) else {}

    if query:
        parts.append(f"Query参数变更: {json.dumps(query, ensure_ascii=False)}")
    if body:
        parts.append(f"JSON Body变更: {json.dumps(body, ensure_ascii=False)}")
    if form:
        parts.append(f"Form参数变更: {json.dumps(form, ensure_ascii=False)}")
    if headers:
        parts.append(f"Header变更: {json.dumps(headers, ensure_ascii=False)}")

    return "；".join(parts) if parts else "未发现具体字段变更"


def _build_trigger_condition(finding: Dict[str, Any]) -> str:
    evidence = finding.get("evidence", {})
    payload = evidence.get("payload", {}) if isinstance(evidence, dict) else {}
    payload_name = evidence.get("payload_name", "unknown-payload")
    override_desc = _format_override_fields(payload)
    return (
        "将身份认证Header保持不变，使用LLM生成的Payload "
        f"[{payload_name}] 对请求进行参数篡改，{override_desc}。"
    )


def _build_sensitive_summary(sensitive_hits: Dict[str, Any]) -> str:
    if not sensitive_hits:
        return "未匹配到手机号/邮箱/身份证等敏感模式。"

    hit_desc = ", ".join(f"{k}={v}" for k, v in sensitive_hits.items())
    if sensitive_hits.get("phone", 0):
        return (
            "检测到越权请求成功返回200，并从中正则匹配到了未授权的手机号记录；"
            f"敏感命中统计: {hit_desc}。"
        )
    return f"检测到越权请求返回疑似敏感数据，命中统计: {hit_desc}。"


def _build_impact_analysis(finding: Dict[str, Any]) -> str:
    risk_level = str(finding.get("risk_level", "Info"))
    score = int(finding.get("risk_score", 0))
    sensitive_hits = finding.get("evidence", {}).get("sensitive_hits", {})

    if risk_level == "High" or (score >= 75 and sensitive_hits):
        return "攻击者可利用可枚举标识批量遍历接口对象，导致全量用户隐私泄露，风险为高危。"
    if risk_level == "Medium":
        return "攻击者可在授权边界外读取或探测其他用户资源，若结合枚举脚本可进一步扩大数据泄露面。"
    if risk_level == "Low":
        return "当前存在越权可疑信号，建议尽快补齐对象级鉴权并复测，防止演变为可利用漏洞。"
    return "本次未观察到明确越权成功证据，但应持续进行鉴权策略验证与监控。"


def _build_report_findings(analysis: Dict[str, Any]) -> Dict[str, Any]:
    enriched = dict(analysis)
    findings = analysis.get("findings", [])
    report_findings = []

    for finding in findings:
        endpoint = finding.get("endpoint", {})
        evidence = finding.get("evidence", {})
        sensitive_hits = evidence.get("sensitive_hits", {})
        schema_overlap = evidence.get("schema_overlap", {}) if isinstance(evidence, dict) else {}

        schema_metrics = {
            "available": bool(schema_overlap.get("available", False)),
            "shared_keys": int(schema_overlap.get("shared_keys", 0)),
            "baseline_keys": int(schema_overlap.get("baseline_keys", 0)),
            "attack_keys": int(schema_overlap.get("attack_keys", 0)),
            "overlap_ratio": float(schema_overlap.get("overlap_ratio", 0.0)),
        }

        report_findings.append(
            {
                **finding,
                "risk_object": f"{endpoint.get('method', 'UNKNOWN')} {endpoint.get('url', '')}",
                "trigger_condition": finding.get("trigger_condition") or _build_trigger_condition(finding),
                "sensitive_summary": finding.get("sensitive_summary") or _build_sensitive_summary(sensitive_hits),
                "impact_analysis": finding.get("impact_analysis") or _build_impact_analysis(finding),
                "conclusion": finding.get("conclusion")
                or f"Risk Level: {finding.get('risk_level')} (Score: {finding.get('risk_score')})",
                "schema_metrics": schema_metrics,
            }
        )

    enriched["report_findings"] = report_findings
    return enriched


def generate_markdown_report(analysis: Dict[str, Any], output_path: str, language: str = "zh") -> None:
    """Write a markdown report for scan findings."""
    labels = LABELS.get(language, LABELS["zh"])
    render_model = _build_report_findings(analysis)
    lines = [
        f"# {labels['title']}",
        "",
        f"- {labels['summary_endpoints']}: {render_model.get('total_endpoints_tested', 0)}",
        f"- {labels['summary_findings']}: {render_model.get('total_findings', 0)}",
        f"- {labels['summary_overall']}: {render_model.get('overall_risk', 'Unknown')}",
        f"- {labels['summary_counts']}: "
        f"High={render_model.get('risk_counts', {}).get('high', 0)}, "
        f"Medium={render_model.get('risk_counts', {}).get('medium', 0)}, "
        f"Low={render_model.get('risk_counts', {}).get('low', 0)}",
        "",
        f"## {labels['findings']}",
    ]

    findings = render_model.get("report_findings", [])
    if not findings:
        lines.append(f"- {labels['no_findings']}")
    else:
        for idx, finding in enumerate(findings, start=1):
            evidence = finding.get("evidence", {})
            mitigation = finding.get("mitigation", {})
            schema_metrics = finding.get("schema_metrics", {})

            lines.extend(
                [
                    f"### {labels['finding_prefix']} {idx}",
                    "",
                    f"#### {labels['risk_object']}",
                    f"- {labels['api']}: {finding.get('risk_object')}",
                    "",
                    f"#### {labels['trigger']}",
                    f"- {finding.get('trigger_condition')}",
                    f"- {labels['trigger_payload']}: {evidence.get('payload_name')}",
                    "",
                    f"#### {labels['evidence']}",
                    f"- {labels['status_compare']}: baseline={evidence.get('baseline_status')} / attack={evidence.get('attack_status')}",
                    f"- {labels['similarity']}: {evidence.get('similarity')}",
                    f"- {labels['sensitive_hits']}: {evidence.get('sensitive_hits')}",
                    f"- {labels['schema_overlap']}:",
                    f"  - shared_keys={schema_metrics.get('shared_keys', 0)}",
                    f"  - baseline_keys={schema_metrics.get('baseline_keys', 0)}",
                    f"  - attack_keys={schema_metrics.get('attack_keys', 0)}",
                    f"  - overlap_ratio={schema_metrics.get('overlap_ratio', 0.0):.2f}",
                    f"- {labels['evidence_highlight']}: {finding.get('sensitive_summary')}",
                    f"- {labels['evidence_reasons']}:",
                ]
            )
            for reason in evidence.get("reasons", []):
                lines.append(f"  - {reason}")

            lines.extend(
                [
                    f"- {labels['baseline_preview']}:",
                    f"  - {evidence.get('baseline_preview', '')}",
                    f"- {labels['attack_preview']}:",
                    f"  - {evidence.get('attack_preview', '')}",
                    "",
                    f"#### {labels['impact']}",
                    f"- {finding.get('impact_analysis')}",
                    "",
                    f"#### {labels['conclusion']}",
                    f"- {finding.get('conclusion')}",
                    "",
                    f"### {labels['mitigation']}",
                    f"- {labels['summary']}: {mitigation.get('summary', '')}",
                    f"- {labels['immediate']}:",
                ]
            )
            for item in mitigation.get("immediate_fixes", []):
                lines.append(f"  - {item}")

            lines.append(f"- {labels['engineering']}:")
            for item in mitigation.get("engineering_hardening", []):
                lines.append(f"  - {item}")

            lines.append(f"- {labels['monitoring']}:")
            for item in mitigation.get("detection_and_monitoring", []):
                lines.append(f"  - {item}")

            lines.extend(
                [
                    f"- {labels['source']}: {mitigation.get('source', 'unknown')}",
                    "",
                ]
            )

    Path(output_path).write_text("\n".join(lines), encoding="utf-8")
    logger.info("Markdown report written: %s", output_path)


def generate_html_report(
    analysis: Dict[str, Any],
    output_path: str,
    template_dir: str = "report/templates",
    template_name: str = "report_template.html",
    language: str = "zh",
) -> None:
    """Render an HTML report using Jinja2 template."""
    render_model = _build_report_findings(analysis)
    labels = LABELS.get(language, LABELS["zh"])
    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template(template_name)
    html = template.render(analysis=render_model, labels=labels, lang=language)
    Path(output_path).write_text(html, encoding="utf-8")
    logger.info("HTML report written: %s", output_path)
