from __future__ import annotations

import random
import time

from flask import Flask, jsonify, request

app = Flask(__name__)

TOKENS = {
    "user_A_token": {"uid": "1001", "role": "user", "name": "zhangsan"},
    "user_B_token": {"uid": "1002", "role": "user", "name": "lisi"},
    "admin_token": {"uid": "9000", "role": "admin", "name": "sec_admin"},
}

USERS = {
    "1001": {
        "uid": "1001",
        "name": "Zhang San",
        "phone": "13800138001",
        "id_card": "110101199001011234",
        "address": "Shanghai Pudong District",
        "email": "zhangsan@example.com",
        "nickname": "zs_dev",
        "avatar_url": "https://cdn.example.local/avatar/1001.png",
        "bio": "I love secure coding and coffee.",
        "theme": "light",
    },
    "1002": {
        "uid": "1002",
        "name": "Li Si",
        "phone": "13900139002",
        "id_card": "110101199202023456",
        "address": "Beijing Haidian District",
        "email": "lisi@example.com",
        "nickname": "lisi_runner",
        "avatar_url": "https://cdn.example.local/avatar/1002.png",
        "bio": "Enjoys APIs, hiking and city walks.",
        "signature": "Keep it simple.",
    },
    "1003": {
        "uid": "1003",
        "name": "Wang Wu",
        "phone": "13700137003",
        "id_card": "110101199303034567",
        "address": "Guangzhou Tianhe District",
        "email": "wangwu@example.com",
        "nickname": "ww_ops",
        "avatar_url": "https://cdn.example.local/avatar/1003.png",
        "bio": "Operations first, reliability always.",
        "style": "minimal",
    },
}

ORDERS = {
    "50001": {"order_id": "50001", "uid": "1001", "amount": 199.0, "phone": "13800138001"},
    "50002": {"order_id": "50002", "uid": "1002", "amount": 499.0, "phone": "13900139002"},
}

ANNOUNCEMENTS = {
    "1": {"id": "1", "title": "System maintenance", "content": "Public maintenance notice."},
    "2": {"id": "2", "title": "Feature release", "content": "Public release notes."},
    "3": {"id": "3", "title": "Holiday schedule", "content": "Public holiday information."},
}


def _get_auth_subject() -> dict | None:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth.replace("Bearer ", "", 1).strip()
    return TOKENS.get(token)


@app.get("/health")
def health() -> tuple[dict, int]:
    return {"status": "ok"}, 200


@app.get("/api/v1/user/profile")
def get_profile():
    actor = _get_auth_subject()
    if actor is None:
        return jsonify({"error": "unauthorized"}), 401

    uid = request.args.get("uid", "")
    user = USERS.get(uid)
    if user is None:
        return jsonify({"error": "user not found"}), 404

    # Intentionally vulnerable: no ownership check between actor['uid'] and requested uid.
    return jsonify(
        {
            "code": 0,
            "msg": "ok",
            "data": {
                "uid": user["uid"],
                "name": user["name"],
                "phone": user["phone"],
                "id_card": user["id_card"],
                "address": user["address"],
                "email": user["email"],
            },
        }
    ), 200


@app.get("/api/v1/order/detail")
def get_order_detail():
    actor = _get_auth_subject()
    if actor is None:
        return jsonify({"error": "unauthorized"}), 401

    order_id = request.args.get("order_id", "")
    order = ORDERS.get(order_id)
    if order is None:
        return jsonify({"error": "order not found"}), 404

    # Intentionally vulnerable: missing check `order['uid'] == actor['uid']`.
    return jsonify({"code": 0, "msg": "ok", "data": order}), 200


@app.get("/api/v1/admin/audit")
def get_admin_audit():
    actor = _get_auth_subject()
    if actor is None:
        return jsonify({"error": "unauthorized"}), 401

    # Intentionally vulnerable: role is not checked, normal users can read audit data.
    return (
        jsonify(
            {
                "code": 0,
                "msg": "ok",
                "data": {
                    "service": "payment",
                    "ops_phone": "13600136000",
                    "ops_email": "ops_team@example.com",
                    "ticket_id": "AUD-2026-0042",
                },
            }
        ),
        200,
    )


@app.get("/api/v1/user/avatar")
def get_user_avatar():
    actor = _get_auth_subject()
    if actor is None:
        return jsonify({"error": "unauthorized"}), 401

    uid = request.args.get("uid", "")
    user = USERS.get(uid)
    if user is None:
        return jsonify({"error": "user not found"}), 404

    # Intentionally vulnerable: avatar card can be read across users without ownership check.
    # Keep schema partially inconsistent across users to produce medium score instead of high.
    if uid == "1001":
        data = {
            "uid": uid,
            "nickname": user["nickname"],
            "avatar_url": user["avatar_url"],
            "bio": user["bio"],
        }
    elif uid == "1002":
        data = {
            "uid": uid,
            "nick_name": user["nickname"],
            "avatar": user["avatar_url"],
            "signature": user.get("signature", ""),
            "theme": "sport",
        }
    else:
        data = {
            "uid": uid,
            "display_name": user["nickname"],
            "photo": user["avatar_url"],
            "about": user["bio"],
            "style": user.get("style", "default"),
        }

    return jsonify({"code": 0, "msg": "ok", "data": data}), 200


@app.get("/api/v1/user/settings")
def get_user_settings():
    actor = _get_auth_subject()
    if actor is None:
        return jsonify({"error": "unauthorized"}), 401

    # Defensive behavior: ignore query uid and always use actor uid.
    user = USERS.get(actor["uid"])
    if user is None:
        return jsonify({"error": "user not found"}), 404

    # Add per-request dynamic key to reduce text similarity and keep this endpoint near medium.
    trace_key = f"trace_{int(time.time() * 1000)}_{random.randint(100, 999)}"
    data = {
        "uid": user["uid"],
        "nickname": user["nickname"],
        "theme": user.get("theme", "default"),
        "notification": {"email": True, "sms": False},
        trace_key: "request-bound",
    }
    return jsonify({"code": 0, "msg": "ok", "data": data}), 200


@app.get("/api/v1/file/download")
def file_download():
    actor = _get_auth_subject()
    if actor is None:
        return jsonify({"error": "unauthorized"}), 401

    file_id = request.args.get("file_id", "")
    if file_id.startswith("f-"):
        # Baseline path: keep it non-200 with random plain text to avoid false high scores.
        nonce = random.randint(100000, 999999)
        return f"partial-content:{file_id}:nonce={nonce}", 206

    # Intentionally weak error handling simulation: leak internals on malformed IDs.
    try:
        int(file_id)
        raise RuntimeError("internal file resolver mismatch")
    except Exception as exc:
        return (
            jsonify(
                {
                    "error": "internal server error",
                    "type": exc.__class__.__name__,
                    "detail": str(exc),
                    "trace": "FileService.download -> parse_file_id -> resolver.map",
                }
            ),
            500,
        )


@app.get("/api/v1/payment/cards")
def get_payment_cards():
    actor = _get_auth_subject()
    if actor is None:
        return jsonify({"error": "unauthorized"}), 401

    uid = request.args.get("uid", "")
    if uid != actor["uid"]:
        return jsonify({"error": "Forbidden"}), 403

    # Return non-200 and dynamic plain text to keep secure endpoint score near zero.
    nonce = random.randint(100000, 999999)
    return f"accepted:masked-card-view:uid={uid}:nonce={nonce}", 202


@app.get("/api/v1/system/announcements")
def get_announcements():
    announcement_id = request.args.get("id", "1")
    item = ANNOUNCEMENTS.get(announcement_id, ANNOUNCEMENTS["1"])

    # Public endpoint: dynamic plain text, no sensitive data, no auth needed.
    noise = random.randint(1000, 9999)
    return f"public-announcement:{item['id']}:{item['title']}:noise={noise}", 206


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=False)
