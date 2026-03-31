from __future__ import annotations

import json
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import parse_qsl, urlparse

import requests

BASE_URL = "http://127.0.0.1:8000"
OUTPUT_HAR = Path("data/input/local_lab.har")

BASE_HEADERS = {
    "Accept": "application/json",
    "User-Agent": "LLM-API-Vuln-Scanner-Lab",
    "Authorization": "Bearer user_A_token",
}

TARGETS = [
    {
        "method": "GET",
        "url": f"{BASE_URL}/api/v1/user/profile?uid=1001",
        "headers": {},
    },
    {
        "method": "GET",
        "url": f"{BASE_URL}/api/v1/order/detail?order_id=50001",
        "headers": {},
    },
    {
        "method": "GET",
        "url": f"{BASE_URL}/api/v1/admin/audit",
        "headers": {},
    },
    {
        "method": "GET",
        "url": f"{BASE_URL}/api/v1/user/avatar?uid=1001",
        "headers": {},
    },
    {
        "method": "GET",
        "url": f"{BASE_URL}/api/v1/user/settings?uid=1001",
        "headers": {},
    },
    {
        "method": "GET",
        "url": f"{BASE_URL}/api/v1/file/download?file_id=f-1001",
        "headers": {},
    },
    {
        "method": "GET",
        "url": f"{BASE_URL}/api/v1/payment/cards?uid=1001",
        "headers": {"X-Owner-Uid": "1001"},
    },
    {
        "method": "GET",
        "url": f"{BASE_URL}/api/v1/system/announcements?id=1",
        "headers": {},
    },
]


def _headers_list(headers: Dict[str, str]) -> List[Dict[str, str]]:
    return [{"name": k, "value": v} for k, v in headers.items()]


def _query_list(url: str) -> List[Dict[str, str]]:
    query = urlparse(url).query
    return [{"name": k, "value": v} for k, v in parse_qsl(query, keep_blank_values=True)]


def _entry(method: str, url: str, headers: Dict[str, str], response: requests.Response) -> Dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    body_text = response.text
    return {
        "startedDateTime": now,
        "time": int(response.elapsed.total_seconds() * 1000),
        "request": {
            "method": method,
            "url": url,
            "httpVersion": "HTTP/1.1",
            "headers": _headers_list(headers),
            "queryString": _query_list(url),
            "headersSize": -1,
            "bodySize": -1,
        },
        "response": {
            "status": response.status_code,
            "statusText": response.reason,
            "httpVersion": "HTTP/1.1",
            "headers": _headers_list(dict(response.headers)),
            "content": {
                "size": len(body_text),
                "mimeType": response.headers.get("Content-Type", "application/json"),
                "text": body_text,
            },
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": len(body_text),
        },
        "cache": {},
        "timings": {
            "send": 0,
            "wait": int(response.elapsed.total_seconds() * 1000),
            "receive": 0,
        },
    }


def main() -> None:
    session = requests.Session()
    entries: List[Dict[str, Any]] = []
    targets = list(TARGETS)
    random.shuffle(targets)

    for target in targets:
        method = target["method"]
        url = target["url"]
        headers = dict(BASE_HEADERS)
        headers.update(target.get("headers", {}))

        response = session.request(method=method, url=url, headers=headers, timeout=10)
        entries.append(_entry(method=method, url=url, headers=headers, response=response))
        print(f"Captured: {method} {url} -> {response.status_code}")

    har_data = {
        "log": {
            "version": "1.2",
            "creator": {"name": "local-lab-generator", "version": "1.0"},
            "entries": entries,
        }
    }

    OUTPUT_HAR.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_HAR.write_text(json.dumps(har_data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"HAR generated at: {OUTPUT_HAR}")


if __name__ == "__main__":
    main()
