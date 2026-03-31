import re
import json
import logging
from collections import defaultdict
from difflib import SequenceMatcher
from typing import Any, Dict, List, Set, Tuple

SENSITIVE_PATTERNS = {
    "phone": re.compile(r"(?<!\d)(?:1[3-9]\d{9})(?!\d)"),
    "email": re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
    "id_card": re.compile(r"(?<!\d)(?:\d{17}[\dXx]|\d{15})(?!\d)"),
}

logger = logging.getLogger(__name__)


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a or "", b or "").ratio()


def _extract_sensitive_hits(text: str) -> Dict[str, int]:
    hits: Dict[str, int] = {}
    for key, pattern in SENSITIVE_PATTERNS.items():
        matches = pattern.findall(text or "")
        if matches:
            hits[key] = len(matches)
    return hits


def _parse_json_object(text: str) -> Dict[str, Any]:
    """Best-effort parse and return JSON object/array wrapper for schema comparison."""
    if not text:
        return {}
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return {}

    if isinstance(parsed, dict):
        return parsed
    if isinstance(parsed, list):
        return {"$list": parsed}
    return {}


def _collect_key_paths(data: Any, prefix: str = "") -> Set[str]:
    """Collect normalized key paths from nested JSON structures."""
    paths: Set[str] = set()

    if isinstance(data, dict):
        for key, value in data.items():
            current = f"{prefix}.{key}" if prefix else str(key)
            paths.add(current)
            paths.update(_collect_key_paths(value, current))
    elif isinstance(data, list):
        list_marker = f"{prefix}[]" if prefix else "[]"
        paths.add(list_marker)
        for item in data:
            paths.update(_collect_key_paths(item, list_marker))

    return paths


def _json_schema_overlap(baseline_body: str, attack_body: str) -> Dict[str, Any]:
    baseline_json = _parse_json_object(baseline_body)
    attack_json = _parse_json_object(attack_body)
    if not baseline_json or not attack_json:
        return {
            "available": False,
            "baseline_keys": 0,
            "attack_keys": 0,
            "shared_keys": 0,
            "overlap_ratio": 0.0,
        }

    baseline_keys = _collect_key_paths(baseline_json)
    attack_keys = _collect_key_paths(attack_json)
    if not baseline_keys or not attack_keys:
        return {
            "available": False,
            "baseline_keys": len(baseline_keys),
            "attack_keys": len(attack_keys),
            "shared_keys": 0,
            "overlap_ratio": 0.0,
        }

    shared = baseline_keys & attack_keys
    overlap_ratio = len(shared) / max(len(baseline_keys), 1)

    return {
        "available": True,
        "baseline_keys": len(baseline_keys),
        "attack_keys": len(attack_keys),
        "shared_keys": len(shared),
        "overlap_ratio": round(overlap_ratio, 4),
    }


def _risk_level(score: int) -> str:
    if score >= 75:
        return "High"
    if score >= 45:
        return "Medium"
    if score > 0:
        return "Low"
    return "Info"


def _format_override_fields(payload: Dict[str, Any]) -> str:
    if not isinstance(payload, dict):
        return "未提供有效载荷详情"

    parts: List[str] = []
    query = payload.get("query", {}) if isinstance(payload.get("query"), dict) else {}
    json_body = payload.get("json_body", {}) if isinstance(payload.get("json_body"), dict) else {}
    form_body = payload.get("form_body", {}) if isinstance(payload.get("form_body"), dict) else {}
    headers = payload.get("headers", {}) if isinstance(payload.get("headers"), dict) else {}

    if query:
        parts.append(f"query={query}")
    if json_body:
        parts.append(f"json_body={json_body}")
    if form_body:
        parts.append(f"form_body={form_body}")
    if headers:
        parts.append(f"headers={headers}")

    return "; ".join(parts) if parts else "未观察到参数覆写"


def _build_sensitive_summary(sensitive_hits: Dict[str, int], attack_status: int) -> str:
    if not sensitive_hits:
        return "未匹配到手机号/邮箱/身份证等敏感模式。"

    labels = "、".join(sensitive_hits.keys())
    hit_desc = ", ".join(f"{k}={v}" for k, v in sensitive_hits.items())
    if attack_status == 200 and "phone" in sensitive_hits:
        return (
            "检测到越权请求成功返回200，并从中正则匹配到了未授权的手机号记录；"
            f"敏感字段类型：{labels}；命中统计：{hit_desc}。"
        )
    return f"检测到疑似敏感数据泄露，敏感字段类型：{labels}；命中统计：{hit_desc}。"


def _build_impact_analysis(risk_level: str, sensitive_hits: Dict[str, int]) -> str:
    if sensitive_hits:
        keys = "、".join(sensitive_hits.keys())
        return (
            "攻击者可通过枚举参数，未授权获取系统内其他用户的 "
            f"{keys} 等高价值敏感隐私数据，可能导致大规模数据泄露。"
        )
    if risk_level in ("High", "Medium"):
        return "攻击者可越权执行敏感操作或查看未授权页面。"
    return "当前存在较弱越权信号，建议结合业务语义进一步复测确认。"


def _build_conclusion(risk_level: str) -> str:
    if risk_level in ("High", "Medium"):
        return f"综合判定风险等级为：{risk_level}。漏洞利用成功，存在明显的越权行为。"
    if risk_level == "Low":
        return "综合判定风险等级为：Low。发现可疑越权信号，建议尽快修复并复测。"
    return "综合判定风险等级为：Info。当前未发现明确越权成功证据。"


def _derive_score(
    baseline_status: int,
    attack_status: int,
    similarity: float,
    schema_overlap: Dict[str, Any],
    sensitive_hits: Dict[str, int],
) -> Tuple[int, List[str]]:
    score = 0
    reasons: List[str] = []
    both_200 = baseline_status == 200 and attack_status == 200

    if both_200:
        score += 35
        reasons.append("Baseline and attack both returned 200.")
    elif attack_status in (401, 403):
        reasons.append("Attack request was blocked by authorization (401/403).")
    elif attack_status >= 500:
        score += 10
        reasons.append("Attack request triggered server error response.")

    # Similarity evidence is meaningful mainly when baseline/attack are both successful.
    if both_200:
        if similarity >= 0.88:
            score += 30
            reasons.append(f"High body similarity detected ({similarity:.2f}).")
        elif similarity >= 0.72:
            score += 15
            reasons.append(f"Moderate body similarity detected ({similarity:.2f}).")

    if both_200 and schema_overlap.get("available"):
        overlap_ratio = float(schema_overlap.get("overlap_ratio", 0.0))
        shared = int(schema_overlap.get("shared_keys", 0))
        base_count = int(schema_overlap.get("baseline_keys", 0))

        if overlap_ratio >= 0.9 and shared >= 3:
            score += 25
            reasons.append(
                "JSON key structure is highly consistent between baseline and attack "
                f"(shared={shared}/{base_count}, overlap={overlap_ratio:.2f})."
            )
        elif overlap_ratio >= 0.7 and shared >= 3:
            score += 12
            reasons.append(
                "JSON key structure is moderately consistent between baseline and attack "
                f"(shared={shared}/{base_count}, overlap={overlap_ratio:.2f})."
            )

        if overlap_ratio >= 0.85 and 0.35 <= similarity <= 0.7:
            score += 10
            reasons.append(
                "Low-to-medium value similarity but high schema consistency, "
                "which matches common IDOR behavior (same fields, different user data)."
            )

    if sensitive_hits:
        score += 35
        reasons.append(f"Sensitive data patterns matched: {sensitive_hits}.")

    # Prevent non-sensitive endpoints from being over-classified as High.
    if not sensitive_hits and score > 70:
        score = 70
        reasons.append("Score capped at 70 because no sensitive data pattern was matched.")

    return min(score, 100), reasons


def analyze_results(
    baseline_results: List[Dict[str, Any]],
    attack_results: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Analyze baseline and attack results and output risk findings with evidence."""
    logger.info("Analyzer started: baseline_results=%s attack_results=%s", len(baseline_results), len(attack_results))
    baseline_by_index = {item.get("index"): item for item in baseline_results}
    grouped_attacks: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    for item in attack_results:
        grouped_attacks[item.get("request_index")].append(item)

    findings: List[Dict[str, Any]] = []

    for req_index, attacks in grouped_attacks.items():
        baseline = baseline_by_index.get(req_index)
        if baseline is None or baseline.get("response") is None:
            continue

        baseline_rsp = baseline.get("response", {})
        base_status = int(baseline_rsp.get("status_code", 0))
        base_body = baseline_rsp.get("body", "")

        endpoint_top_score = -1
        endpoint_best_case: Dict[str, Any] = {}

        for attack in attacks:
            if attack.get("error") is not None or attack.get("response") is None:
                continue

            attack_rsp = attack.get("response", {})
            attack_status = int(attack_rsp.get("status_code", 0))
            attack_body = attack_rsp.get("body", "")

            similarity = _similarity(base_body, attack_body)
            schema_overlap = _json_schema_overlap(base_body, attack_body)
            sensitive_hits = _extract_sensitive_hits(attack_body)
            score, reasons = _derive_score(
                baseline_status=base_status,
                attack_status=attack_status,
                similarity=similarity,
                schema_overlap=schema_overlap,
                sensitive_hits=sensitive_hits,
            )

            logger.debug(
                "Score candidate: req_index=%s payload=%s score=%s similarity=%.4f overlap=%.4f sensitive=%s",
                req_index,
                attack.get("payload_name"),
                score,
                similarity,
                schema_overlap.get("overlap_ratio", 0.0),
                sensitive_hits,
            )

            if score > endpoint_top_score or (score == endpoint_top_score and not endpoint_best_case):
                endpoint_top_score = score
                endpoint_best_case = {
                    "payload_name": attack.get("payload_name"),
                    "payload": attack.get("payload"),
                    "baseline_status": base_status,
                    "attack_status": attack_status,
                    "baseline_length": baseline_rsp.get("length"),
                    "attack_length": attack_rsp.get("length"),
                    "similarity": round(similarity, 4),
                    "schema_overlap": schema_overlap,
                    "sensitive_hits": sensitive_hits,
                    "reasons": reasons,
                    "baseline_preview": baseline_rsp.get("preview", ""),
                    "attack_preview": attack_rsp.get("preview", ""),
                }

        if endpoint_top_score >= 0:
            risk_level = _risk_level(endpoint_top_score)
            payload = endpoint_best_case.get("payload", {}) if isinstance(endpoint_best_case, dict) else {}
            payload_name = endpoint_best_case.get("payload_name", "unknown-payload")
            payload_reason = payload.get("reason", "") if isinstance(payload, dict) else ""
            override_desc = _format_override_fields(payload if isinstance(payload, dict) else {})

            trigger_condition = (
                f"使用了名为 {payload_name} 的攻击载荷，测试理由：{payload_reason or '未提供'}；"
                f"具体覆写参数：{override_desc}"
            )
            sensitive_hits = endpoint_best_case.get("sensitive_hits", {})
            impact_analysis = _build_impact_analysis(risk_level, sensitive_hits)
            conclusion = _build_conclusion(risk_level)
            sensitive_summary = _build_sensitive_summary(
                sensitive_hits=sensitive_hits,
                attack_status=int(endpoint_best_case.get("attack_status", 0)),
            )

            logger.info(
                "Finding selected: req_index=%s endpoint=%s score=%s",
                req_index,
                baseline.get("request", {}).get("url"),
                endpoint_top_score,
            )
            findings.append(
                {
                    "request_index": req_index,
                    "endpoint": baseline.get("request", {}),
                    "risk_score": endpoint_top_score,
                    "risk_level": risk_level,
                    "evidence": endpoint_best_case,
                    "trigger_condition": trigger_condition,
                    "impact_analysis": impact_analysis,
                    "conclusion": conclusion,
                    "sensitive_summary": sensitive_summary,
                }
            )

    findings.sort(key=lambda item: item.get("risk_score", 0), reverse=True)

    high = sum(1 for f in findings if f.get("risk_level") == "High")
    medium = sum(1 for f in findings if f.get("risk_level") == "Medium")
    low = sum(1 for f in findings if f.get("risk_level") == "Low")
    info = sum(1 for f in findings if f.get("risk_level") == "Info")

    overall_risk = "Low"
    if high > 0:
        overall_risk = "High"
    elif medium > 0:
        overall_risk = "Medium"

    logger.info(
        "Analyzer finished: findings=%s high=%s medium=%s low=%s info=%s overall=%s",
        len(findings),
        high,
        medium,
        low,
        info,
        overall_risk,
    )

    return {
        "total_endpoints_tested": len(grouped_attacks),
        "total_findings": len(findings),
        "overall_risk": overall_risk,
        "risk_counts": {
            "high": high,
            "medium": medium,
            "low": low,
            "info": info,
        },
        "findings": findings,
    }
