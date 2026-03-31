from time import perf_counter
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlsplit, urlunsplit

import requests

logger = logging.getLogger(__name__)


def _build_proxy_config(proxy: str) -> Optional[Dict[str, str]]:
    if not proxy:
        return None
    return {"http": proxy, "https": proxy}


def _normalize_headers(headers: Dict[str, Any]) -> Dict[str, str]:
    return {str(k): str(v) for k, v in headers.items()}


def _merge_dict(base: Optional[Dict[str, Any]], override: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    result = dict(base or {})
    for key, value in (override or {}).items():
        result[key] = value
    return result


def _split_url_and_query(url: str) -> tuple[str, Dict[str, Any]]:
    """Split URL into base URL(without query) and parsed query dict."""
    split = urlsplit(url)
    base_url = urlunsplit((split.scheme, split.netloc, split.path, "", split.fragment))
    query_dict: Dict[str, Any] = {}
    for key, value in parse_qsl(split.query, keep_blank_values=True):
        query_dict[key] = value
    return base_url, query_dict


def _build_request_payload(
    req: Dict[str, Any],
    timeout: int,
    verify_ssl: bool,
    allow_redirects: bool,
    proxies: Optional[Dict[str, str]],
    payload: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    raw_url = req.get("url", "")
    base_url, query_from_url = _split_url_and_query(raw_url)

    headers = _normalize_headers(req.get("headers", {}))
    query = _merge_dict(query_from_url, req.get("query") or {})
    json_body = req.get("json_body") if isinstance(req.get("json_body"), dict) else None
    form_body = req.get("form_body") if isinstance(req.get("form_body"), dict) else None
    body_text = req.get("body_text", "")

    if payload:
        headers = _merge_dict(headers, payload.get("headers"))
        query = _merge_dict(query, payload.get("query"))

        payload_json = payload.get("json_body")
        if isinstance(payload_json, dict):
            json_body = _merge_dict(json_body, payload_json)

        payload_form = payload.get("form_body")
        if isinstance(payload_form, dict):
            form_body = _merge_dict(form_body, payload_form)

    request_kwargs: Dict[str, Any] = {
        "method": req.get("method", "GET"),
        "url": base_url,
        "headers": headers,
        "params": query or None,
        "timeout": timeout,
        "allow_redirects": allow_redirects,
        "verify": verify_ssl,
    }
    if proxies:
        request_kwargs["proxies"] = proxies

    if json_body is not None:
        request_kwargs["json"] = json_body
    elif form_body is not None:
        request_kwargs["data"] = form_body
    elif body_text:
        request_kwargs["data"] = body_text

    return request_kwargs


def _send_request(
    session: requests.Session,
    request_kwargs: Dict[str, Any],
    capture_body_max_chars: int,
) -> Dict[str, Any]:
    started_at = perf_counter()
    logger.debug(
        "Sending request: method=%s url=%s params=%s",
        request_kwargs.get("method"),
        request_kwargs.get("url"),
        request_kwargs.get("params"),
    )
    try:
        response = session.request(**request_kwargs)
        elapsed_ms = int((perf_counter() - started_at) * 1000)
        body = response.text

        return {
            "response": {
                "status_code": response.status_code,
                "length": len(body),
                "elapsed_ms": elapsed_ms,
                "preview": body[:300].replace("\n", " "),
                "body": body[:capture_body_max_chars],
            },
            "error": None,
        }
    except requests.RequestException as exc:
        elapsed_ms = int((perf_counter() - started_at) * 1000)
        return {
            "response": None,
            "error": {
                "type": exc.__class__.__name__,
                "message": str(exc),
                "elapsed_ms": elapsed_ms,
            },
        }


def replay_original_requests(
    requests_data: List[Dict[str, Any]],
    timeout: int = 15,
    proxy: str = "",
    verify_ssl: bool = True,
    allow_redirects: bool = True,
    capture_body_max_chars: int = 20000,
) -> List[Dict[str, Any]]:
    """Replay normalized API requests and collect response metrics."""
    logger.info("Baseline replay started: requests=%s", len(requests_data))
    proxies = _build_proxy_config(proxy)
    results: List[Dict[str, Any]] = []

    with requests.Session() as session:
        for index, req in enumerate(requests_data, start=1):
            method = req.get("method", "GET")
            url = req.get("url", "")
            request_kwargs = _build_request_payload(
                req=req,
                timeout=timeout,
                verify_ssl=verify_ssl,
                allow_redirects=allow_redirects,
                proxies=proxies,
                payload=None,
            )
            result = _send_request(
                session=session,
                request_kwargs=request_kwargs,
                capture_body_max_chars=capture_body_max_chars,
            )
            if result["error"] is None:
                logger.debug(
                    "Baseline request #%s completed: status=%s len=%s",
                    index,
                    result["response"].get("status_code"),
                    result["response"].get("length"),
                )
            else:
                logger.warning("Baseline request #%s failed: %s", index, result["error"])
            results.append(
                {
                    "index": index,
                    "request": {
                        "method": method,
                        "url": url,
                    },
                    "response": result["response"],
                    "error": result["error"],
                }
            )

            logger.info("Baseline replay finished: results=%s", len(results))

    return results


def replay_attack_requests(
    requests_data: List[Dict[str, Any]],
    payload_results: List[Dict[str, Any]],
    timeout: int = 15,
    proxy: str = "",
    verify_ssl: bool = True,
    allow_redirects: bool = True,
    capture_body_max_chars: int = 20000,
) -> List[Dict[str, Any]]:
    """Replay attack requests by applying LLM payload overrides on original requests."""
    logger.info("Attack replay started: endpoints=%s", len(requests_data))
    proxies = _build_proxy_config(proxy)
    attack_results: List[Dict[str, Any]] = []

    by_index = {item.get("index"): item for item in payload_results}

    with requests.Session() as session:
        for req_index, req in enumerate(requests_data, start=1):
            payload_bundle = by_index.get(req_index)
            if not payload_bundle:
                continue

            if payload_bundle.get("error") is not None:
                logger.warning(
                    "Skipping attack replay for request_index=%s due to payload generation error",
                    req_index,
                )
                attack_results.append(
                    {
                        "request_index": req_index,
                        "request": {
                            "method": req.get("method"),
                            "url": req.get("url"),
                        },
                        "payload_name": None,
                        "payload": None,
                        "response": None,
                        "error": {
                            "type": "PayloadGenerationError",
                            "message": payload_bundle.get("error", {}).get("message", "payload generation failed"),
                        },
                    }
                )
                continue

            for payload in payload_bundle.get("payloads", []):
                logger.debug(
                    "Replaying attack payload: request_index=%s payload_name=%s",
                    req_index,
                    payload.get("name", "idor-candidate"),
                )
                request_kwargs = _build_request_payload(
                    req=req,
                    timeout=timeout,
                    verify_ssl=verify_ssl,
                    allow_redirects=allow_redirects,
                    proxies=proxies,
                    payload=payload,
                )
                result = _send_request(
                    session=session,
                    request_kwargs=request_kwargs,
                    capture_body_max_chars=capture_body_max_chars,
                )
                if result["error"] is None:
                    logger.debug(
                        "Attack replay success: request_index=%s payload_name=%s status=%s",
                        req_index,
                        payload.get("name", "idor-candidate"),
                        result["response"].get("status_code"),
                    )
                else:
                    logger.warning(
                        "Attack replay failed: request_index=%s payload_name=%s error=%s",
                        req_index,
                        payload.get("name", "idor-candidate"),
                        result["error"],
                    )
                attack_results.append(
                    {
                        "request_index": req_index,
                        "request": {
                            "method": req.get("method"),
                            "url": req.get("url"),
                        },
                        "payload_name": payload.get("name", "idor-candidate"),
                        "payload": payload,
                        "response": result["response"],
                        "error": result["error"],
                    }
                )

    logger.info("Attack replay finished: total_results=%s", len(attack_results))

    return attack_results
