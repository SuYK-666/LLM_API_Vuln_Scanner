import json
import logging
import os
import re
import time
import copy
from pathlib import Path
from typing import Any, Dict, List, Optional

from openai import OpenAI

logger = logging.getLogger(__name__)


def _load_prompt(prompt_path: str) -> str:
    path = Path(prompt_path)
    if not path.exists():
        raise FileNotFoundError(f"Prompt file not found: {prompt_path}")
    return path.read_text(encoding="utf-8").strip()


def _build_user_message(request_data: Dict[str, Any], max_payloads: int) -> str:
    compact_req = {
        "method": request_data.get("method"),
        "url": request_data.get("url"),
        "headers": request_data.get("headers"),
        "query": request_data.get("query"),
        "json_body": request_data.get("json_body"),
        "form_body": request_data.get("form_body"),
        "body_text": request_data.get("body_text"),
    }
    return (
        "Target HTTP request (JSON):\n"
        f"{json.dumps(compact_req, ensure_ascii=False, indent=2)}\n\n"
        "Return exactly a JSON array with at most "
        f"{max_payloads} payload objects."
    )


def _extract_first_json_array(text: str) -> Optional[str]:
    if not text:
        return None

    fenced = re.search(r"```(?:json)?\s*(\[.*?\])\s*```", text, flags=re.DOTALL)
    if fenced:
        return fenced.group(1)

    start = text.find("[")
    if start == -1:
        return None

    depth = 0
    in_string = False
    escape = False
    for idx in range(start, len(text)):
        ch = text[idx]

        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
        elif ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                return text[start : idx + 1]

    return None


def _extract_first_json_object(text: str) -> Optional[str]:
    if not text:
        return None

    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, flags=re.DOTALL)
    if fenced:
        return fenced.group(1)

    start = text.find("{")
    if start == -1:
        return None

    depth = 0
    in_string = False
    escape = False
    for idx in range(start, len(text)):
        ch = text[idx]

        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : idx + 1]

    return None


def _normalize_payloads(raw: Any, max_payloads: int) -> List[Dict[str, Any]]:
    if isinstance(raw, dict) and isinstance(raw.get("payloads"), list):
        raw = raw["payloads"]

    if not isinstance(raw, list):
        raise ValueError("LLM output is not a JSON array")

    normalized: List[Dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        normalized.append(
            {
                "name": item.get("name") or "idor-candidate",
                "query": item.get("query") if isinstance(item.get("query"), dict) else {},
                "json_body": item.get("json_body") if isinstance(item.get("json_body"), dict) else {},
                "form_body": item.get("form_body") if isinstance(item.get("form_body"), dict) else {},
                "headers": item.get("headers") if isinstance(item.get("headers"), dict) else {},
                "reason": item.get("reason", ""),
                "mitigation": item.get("mitigation", ""),
            }
        )
        if len(normalized) >= max_payloads:
            break

    if not normalized:
        raise ValueError("No valid payload objects found in LLM output")
    return normalized


def generate_payloads_for_request(
    request_data: Dict[str, Any],
    config: Dict[str, Any],
    prompt_path: str = "prompts/idor_prompt.txt",
) -> List[Dict[str, Any]]:
    """Generate IDOR payloads for one API request using DeepSeek-compatible chat API."""
    api_key = os.getenv("DEEPSEEK_API_KEY") or config.get("api_key", "")
    if not api_key:
        raise ValueError("DeepSeek API key missing. Set DEEPSEEK_API_KEY or config api_key.")

    base_url = config.get("base_url", "https://api.deepseek.com")
    model = config.get("model", "deepseek-chat")
    llm_timeout = int(config.get("llm_timeout", 30))
    max_payloads = int(config.get("max_payloads_per_api", 5))
    retry_times = int(config.get("llm_retry_times", 3))
    temperature = float(config.get("temperature", 0.2))

    system_prompt = _load_prompt(prompt_path)
    user_message = _build_user_message(request_data=request_data, max_payloads=max_payloads)
    logger.info(
        "LLM payload generation start: method=%s url=%s model=%s max_payloads=%s",
        request_data.get("method"),
        request_data.get("url"),
        model,
        max_payloads,
    )
    client = OpenAI(api_key=api_key, base_url=base_url, timeout=llm_timeout)

    last_error = "unknown error"
    for attempt in range(1, retry_times + 1):
        try:
            logger.debug("LLM payload generation attempt=%s/%s", attempt, retry_times)
            response = client.chat.completions.create(
                model=model,
                temperature=temperature,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message},
                ],
            )
            raw_text = response.choices[0].message.content or ""
            logger.debug("LLM raw payload response chars=%s", len(raw_text))

            try:
                parsed = json.loads(raw_text)
                logger.debug("LLM payload response parsed directly as JSON")
            except json.JSONDecodeError:
                extracted = _extract_first_json_array(raw_text)
                if extracted is None:
                    raise ValueError("LLM response does not contain a valid JSON array")
                parsed = json.loads(extracted)
                logger.debug("LLM payload response parsed via extracted JSON array")

            normalized = _normalize_payloads(raw=parsed, max_payloads=max_payloads)
            logger.info(
                "LLM payload generation success: method=%s url=%s payload_count=%s",
                request_data.get("method"),
                request_data.get("url"),
                len(normalized),
            )
            return normalized
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
            logger.warning("LLM payload generation failed on attempt %s: %s", attempt, last_error)
            if attempt < retry_times:
                time.sleep(min(2 ** attempt, 5))
                continue

    raise RuntimeError(f"Failed to generate payloads after retries: {last_error}")


def generate_payloads_batch(
    requests_data: List[Dict[str, Any]],
    config: Dict[str, Any],
    prompt_path: str = "prompts/idor_prompt.txt",
) -> List[Dict[str, Any]]:
    """Generate payloads for each parsed request and preserve per-request status."""
    batch_results: List[Dict[str, Any]] = []

    for idx, req in enumerate(requests_data, start=1):
        try:
            logger.info("Batch payload generation for request_index=%s", idx)
            payloads = generate_payloads_for_request(
                request_data=req,
                config=config,
                prompt_path=prompt_path,
            )
            batch_results.append(
                {
                    "index": idx,
                    "request": {
                        "method": req.get("method"),
                        "url": req.get("url"),
                    },
                    "payload_count": len(payloads),
                    "payloads": payloads,
                    "error": None,
                }
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Batch payload generation failed for request_index=%s: %s", idx, exc)
            batch_results.append(
                {
                    "index": idx,
                    "request": {
                        "method": req.get("method"),
                        "url": req.get("url"),
                    },
                    "payload_count": 0,
                    "payloads": [],
                    "error": {
                        "type": exc.__class__.__name__,
                        "message": str(exc),
                    },
                }
            )

    return batch_results


def _build_mitigation_user_message(finding: Dict[str, Any]) -> str:
    compact = {
        "endpoint": finding.get("endpoint", {}),
        "risk_level": finding.get("risk_level"),
        "risk_score": finding.get("risk_score"),
        "evidence": finding.get("evidence", {}),
    }
    return (
        "Generate mitigation and prevention guidance for this broken access control finding.\n"
        "Return JSON object only with keys: summary, immediate_fixes, engineering_hardening, detection_and_monitoring.\n"
        "Each list key should be an array of short bullet strings.\n\n"
        f"Finding JSON:\n{json.dumps(compact, ensure_ascii=False, indent=2)}"
    )


def _normalize_mitigation(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("Mitigation output must be a JSON object")

    def _ensure_list(value: Any) -> List[str]:
        if not isinstance(value, list):
            return []
        return [str(item) for item in value if str(item).strip()]

    return {
        "summary": str(raw.get("summary", "")).strip(),
        "immediate_fixes": _ensure_list(raw.get("immediate_fixes")),
        "engineering_hardening": _ensure_list(raw.get("engineering_hardening")),
        "detection_and_monitoring": _ensure_list(raw.get("detection_and_monitoring")),
    }


def generate_mitigation_for_finding(
    finding: Dict[str, Any],
    config: Dict[str, Any],
    prompt_path: str = "prompts/mitigation_prompt.txt",
) -> Dict[str, Any]:
    """Generate targeted mitigation guidance for one finding via DeepSeek."""
    api_key = os.getenv("DEEPSEEK_API_KEY") or config.get("api_key", "")
    if not api_key:
        raise ValueError("DeepSeek API key missing. Set DEEPSEEK_API_KEY or config api_key.")

    base_url = config.get("base_url", "https://api.deepseek.com")
    model = config.get("model", "deepseek-chat")
    llm_timeout = int(config.get("llm_timeout", 30))
    retry_times = int(config.get("llm_retry_times", 3))
    temperature = float(config.get("mitigation_temperature", 0.2))

    system_prompt = _load_prompt(prompt_path)
    user_message = _build_mitigation_user_message(finding)
    logger.info(
        "LLM mitigation generation start: endpoint=%s risk=%s score=%s",
        finding.get("endpoint", {}).get("url"),
        finding.get("risk_level"),
        finding.get("risk_score"),
    )
    client = OpenAI(api_key=api_key, base_url=base_url, timeout=llm_timeout)

    last_error = "unknown error"
    for attempt in range(1, retry_times + 1):
        try:
            logger.debug("LLM mitigation attempt=%s/%s", attempt, retry_times)
            response = client.chat.completions.create(
                model=model,
                temperature=temperature,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message},
                ],
            )
            raw_text = response.choices[0].message.content or ""
            logger.debug("LLM raw mitigation response chars=%s", len(raw_text))

            try:
                parsed = json.loads(raw_text)
            except json.JSONDecodeError:
                extracted = _extract_first_json_object(raw_text)
                if extracted is None:
                    raise ValueError("LLM response does not contain a valid JSON object")
                parsed = json.loads(extracted)

            return _normalize_mitigation(parsed)
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
            logger.warning("LLM mitigation generation failed on attempt %s: %s", attempt, last_error)
            if attempt < retry_times:
                time.sleep(min(2 ** attempt, 5))
                continue

    raise RuntimeError(f"Failed to generate mitigation after retries: {last_error}")


def attach_mitigation_to_findings(
    analysis: Dict[str, Any],
    config: Dict[str, Any],
    prompt_path: str = "prompts/mitigation_prompt.txt",
    min_risk_score: int = 45,
) -> Dict[str, Any]:
    """Attach mitigation suggestions to findings using payload hints + optional LLM refinement."""
    findings = analysis.get("findings", [])
    if not isinstance(findings, list):
        return analysis

    for finding in findings:
        evidence = finding.get("evidence", {})
        payload = evidence.get("payload", {}) if isinstance(evidence, dict) else {}
        payload_mitigation = payload.get("mitigation", "") if isinstance(payload, dict) else ""

        mitigation_block: Dict[str, Any] = {
            "summary": payload_mitigation.strip(),
            "immediate_fixes": [],
            "engineering_hardening": [],
            "detection_and_monitoring": [],
            "source": "payload_hint" if payload_mitigation else "none",
        }

        risk_score = int(finding.get("risk_score", 0))
        logger.info(
            "Attach mitigation: endpoint=%s risk_score=%s threshold=%s",
            finding.get("endpoint", {}).get("url"),
            risk_score,
            min_risk_score,
        )
        if risk_score >= min_risk_score:
            try:
                llm_mitigation = generate_mitigation_for_finding(
                    finding=finding,
                    config=config,
                    prompt_path=prompt_path,
                )
                mitigation_block = {
                    **llm_mitigation,
                    "source": "llm_mitigation_pass",
                }
                logger.info("Mitigation attached from LLM for endpoint=%s", finding.get("endpoint", {}).get("url"))
            except Exception as exc:  # noqa: BLE001
                mitigation_block["source"] = f"fallback_due_to_error: {exc.__class__.__name__}"
                logger.warning(
                    "Mitigation fallback used for endpoint=%s due to error=%s",
                    finding.get("endpoint", {}).get("url"),
                    exc,
                )

        finding["mitigation"] = mitigation_block

    analysis["findings"] = findings
    return analysis


def _contains_cjk(text: str) -> bool:
    return bool(re.search(r"[\u4e00-\u9fff]", text or ""))


def _should_translate_text(text: str, target_lang: str) -> bool:
    if not text:
        return False
    has_cjk = _contains_cjk(text)
    if target_lang == "zh":
        return not has_cjk
    if target_lang == "en":
        return has_cjk
    return False


def _translate_text_batch(
    text_map: Dict[str, Any],
    target_lang: str,
    config: Dict[str, Any],
) -> Dict[str, Any]:
    api_key = os.getenv("DEEPSEEK_API_KEY") or config.get("api_key", "")
    if not api_key:
        return text_map

    base_url = config.get("base_url", "https://api.deepseek.com")
    model = config.get("model", "deepseek-chat")
    llm_timeout = int(config.get("llm_timeout", 30))
    retry_times = int(config.get("llm_retry_times", 3))
    temperature = float(config.get("translation_temperature", 0.0))

    target_name = "Simplified Chinese" if target_lang == "zh" else "English"
    system_prompt = (
        "You are a precise security report translator. "
        "Translate all values to target language while preserving JSON keys, structure, API paths, IDs, numbers, "
        "and technical acronyms such as IDOR/RBAC/ABAC/JWT. Output JSON only."
    )
    user_prompt = (
        f"Target language: {target_name}.\n"
        "Return the same JSON structure with translated string values.\n\n"
        f"Input JSON:\n{json.dumps(text_map, ensure_ascii=False, indent=2)}"
    )

    client = OpenAI(api_key=api_key, base_url=base_url, timeout=llm_timeout)
    last_error = "unknown error"
    for attempt in range(1, retry_times + 1):
        try:
            response = client.chat.completions.create(
                model=model,
                temperature=temperature,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            )
            content = response.choices[0].message.content or ""
            try:
                parsed = json.loads(content)
            except json.JSONDecodeError:
                extracted = _extract_first_json_object(content)
                if extracted is None:
                    raise ValueError("Translation response does not contain JSON object")
                parsed = json.loads(extracted)
            if isinstance(parsed, dict):
                return parsed
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
            logger.warning("Translation attempt %s failed: %s", attempt, last_error)
            if attempt < retry_times:
                time.sleep(min(2 ** attempt, 5))
                continue

    logger.warning("Translation fallback used due to errors: %s", last_error)
    return text_map


def localize_analysis_language(
    analysis: Dict[str, Any],
    config: Dict[str, Any],
    target_lang: str,
) -> Dict[str, Any]:
    """Return a localized copy of analysis for zh/en report generation."""
    localized = copy.deepcopy(analysis)
    findings = localized.get("findings", [])
    if not isinstance(findings, list):
        return localized

    for finding in findings:
        evidence = finding.get("evidence", {}) if isinstance(finding.get("evidence"), dict) else {}
        payload = evidence.get("payload", {}) if isinstance(evidence.get("payload"), dict) else {}
        mitigation = finding.get("mitigation", {}) if isinstance(finding.get("mitigation"), dict) else {}

        text_map = {
            "trigger_condition": finding.get("trigger_condition", ""),
            "impact_analysis": finding.get("impact_analysis", ""),
            "conclusion": finding.get("conclusion", ""),
            "sensitive_summary": finding.get("sensitive_summary", ""),
            "reasons": evidence.get("reasons", []),
            "payload_reason": payload.get("reason", ""),
            "mitigation_summary": mitigation.get("summary", ""),
            "mitigation_immediate_fixes": mitigation.get("immediate_fixes", []),
            "mitigation_engineering_hardening": mitigation.get("engineering_hardening", []),
            "mitigation_detection_and_monitoring": mitigation.get("detection_and_monitoring", []),
        }

        flat_texts: List[str] = [
            str(text_map.get("trigger_condition", "")),
            str(text_map.get("impact_analysis", "")),
            str(text_map.get("conclusion", "")),
            str(text_map.get("sensitive_summary", "")),
            str(text_map.get("payload_reason", "")),
            str(text_map.get("mitigation_summary", "")),
        ]
        flat_texts.extend([str(x) for x in text_map.get("reasons", []) if isinstance(x, str)])
        flat_texts.extend([str(x) for x in text_map.get("mitigation_immediate_fixes", []) if isinstance(x, str)])
        flat_texts.extend([str(x) for x in text_map.get("mitigation_engineering_hardening", []) if isinstance(x, str)])
        flat_texts.extend([str(x) for x in text_map.get("mitigation_detection_and_monitoring", []) if isinstance(x, str)])

        if not any(_should_translate_text(t, target_lang) for t in flat_texts):
            continue

        translated = _translate_text_batch(text_map=text_map, target_lang=target_lang, config=config)

        finding["trigger_condition"] = translated.get("trigger_condition", finding.get("trigger_condition", ""))
        finding["impact_analysis"] = translated.get("impact_analysis", finding.get("impact_analysis", ""))
        finding["conclusion"] = translated.get("conclusion", finding.get("conclusion", ""))
        finding["sensitive_summary"] = translated.get("sensitive_summary", finding.get("sensitive_summary", ""))

        if isinstance(evidence, dict):
            evidence["reasons"] = translated.get("reasons", evidence.get("reasons", []))
            if isinstance(payload, dict):
                payload["reason"] = translated.get("payload_reason", payload.get("reason", ""))
                evidence["payload"] = payload
            finding["evidence"] = evidence

        if isinstance(mitigation, dict):
            mitigation["summary"] = translated.get("mitigation_summary", mitigation.get("summary", ""))
            mitigation["immediate_fixes"] = translated.get("mitigation_immediate_fixes", mitigation.get("immediate_fixes", []))
            mitigation["engineering_hardening"] = translated.get("mitigation_engineering_hardening", mitigation.get("engineering_hardening", []))
            mitigation["detection_and_monitoring"] = translated.get("mitigation_detection_and_monitoring", mitigation.get("detection_and_monitoring", []))
            finding["mitigation"] = mitigation

    localized["findings"] = findings
    return localized
