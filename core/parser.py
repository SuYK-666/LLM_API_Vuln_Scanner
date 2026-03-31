import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs

logger = logging.getLogger(__name__)

STATIC_EXTENSIONS = {
    ".js",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".map",
}


def _headers_to_dict(headers: List[Dict[str, str]]) -> Dict[str, str]:
    return {
        h.get("name", "").strip(): h.get("value", "")
        for h in headers
        if h.get("name")
    }


def _extract_json_body(text: str) -> Optional[Dict[str, Any]]:
    if not text:
        return None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    if isinstance(parsed, dict):
        return parsed
    return None


def _extract_form_body(text: str) -> Optional[Dict[str, Any]]:
    if not text:
        return None
    parsed = parse_qs(text, keep_blank_values=True)
    if not parsed:
        return None
    return {k: v[0] if len(v) == 1 else v for k, v in parsed.items()}


def _is_api_candidate(url: str, content_type: str, mime_type: str) -> bool:
    lower_url = url.lower()
    if any(lower_url.endswith(ext) for ext in STATIC_EXTENSIONS):
        return False

    combined_type = f"{content_type} {mime_type}".lower()
    if "json" in combined_type:
        return True

    api_keywords = ("/api/", "/v1/", "/v2/", "/graphql")
    return any(keyword in lower_url for keyword in api_keywords)


def parse_har_file(har_path: str, max_entries: Optional[int] = None) -> List[Dict[str, Any]]:
    """Parse a HAR file and return normalized API request records."""
    path = Path(har_path)
    if not path.exists():
        raise FileNotFoundError(f"HAR file not found: {har_path}")

    logger.info("Parsing HAR file: %s", har_path)

    data = json.loads(path.read_text(encoding="utf-8"))
    entries = data.get("log", {}).get("entries", [])
    logger.debug("HAR entries total: %s", len(entries))
    normalized: List[Dict[str, Any]] = []

    for entry in entries:
        request = entry.get("request", {})
        response = entry.get("response", {})
        url = request.get("url", "")
        method = request.get("method", "GET").upper()

        req_headers = _headers_to_dict(request.get("headers", []))
        res_content = response.get("content", {})
        content_type = req_headers.get("Content-Type", "")
        mime_type = res_content.get("mimeType", "")

        if not _is_api_candidate(url=url, content_type=content_type, mime_type=mime_type):
            logger.debug("Filtered non-API request: %s %s", method, url)
            continue

        post_data = request.get("postData", {})
        body_text = post_data.get("text", "")
        json_body = _extract_json_body(body_text)
        form_body = _extract_form_body(body_text) if json_body is None else None

        normalized.append(
            {
                "method": method,
                "url": url,
                "headers": req_headers,
                "query": {
                    item.get("name", ""): item.get("value", "")
                    for item in request.get("queryString", [])
                    if item.get("name")
                },
                "body_text": body_text,
                "json_body": json_body,
                "form_body": form_body,
                "content_type": content_type,
            }
        )
        logger.debug("Accepted API request: %s %s", method, url)

        if max_entries is not None and len(normalized) >= max_entries:
            logger.info("Reached max_entries=%s while parsing HAR", max_entries)
            break

    logger.info("HAR parsing done: accepted_api_requests=%s", len(normalized))

    return normalized
