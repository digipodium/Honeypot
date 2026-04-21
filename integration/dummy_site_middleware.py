"""
Dummy website middleware for sending request logs to HoneyTrap.

Usage in dummy Flask app:
    from integration.dummy_site_middleware import register_honeytrap_logging
    register_honeytrap_logging(app)
"""

from datetime import datetime
import os
import threading

import requests
from flask import g, request


HONEYTRAP_API_URL = os.getenv("HONEYTRAP_API_URL", "http://127.0.0.1:5000/api/logs")
HONEYTRAP_API_KEY = os.getenv("HONEYTRAP_API_KEY", "")
DUMMY_SOURCE_NAME = os.getenv("DUMMY_SOURCE_NAME", "dummy-site-1")
HONEYTRAP_TIMEOUT_SEC = float(os.getenv("HONEYTRAP_TIMEOUT_SEC", "2"))


SUSPICIOUS_TOKENS = (
    "' or 1=1",
    "union select",
    "drop table",
    "<script",
    "javascript:",
    "onerror=",
)


def _guess_status(path, response_status_code, body):
    lowered_path = (path or "").lower()
    lowered_body = (body or "").lower()

    if response_status_code >= 400:
        return "failed"
    if "/login" in lowered_path and any(token in lowered_body for token in ("invalid", "wrong", "denied", "failed")):
        return "failed"
    return "success"


def _send_async(payload):
    if not HONEYTRAP_API_KEY:
        return

    headers = {
        "Content-Type": "application/json",
        "X-API-KEY": HONEYTRAP_API_KEY,
    }
    try:
        requests.post(HONEYTRAP_API_URL, json=payload, headers=headers, timeout=HONEYTRAP_TIMEOUT_SEC)
    except requests.RequestException:
        # Do not break dummy app if HoneyTrap is unavailable.
        return


def register_honeytrap_logging(app):
    @app.before_request
    def capture_request_payload():
        g.honeytrap_body = request.get_data(as_text=True)[:2000]

    @app.after_request
    def ship_log(response):
        if request.path.startswith("/static/"):
            return response

        ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
        user_agent = request.headers.get("User-Agent", "")
        payload = request.query_string.decode("utf-8", errors="ignore")[:1000]
        body = getattr(g, "honeytrap_body", "")
        if body:
            payload = f"{payload} | body={body}" if payload else body

        status = _guess_status(request.path, response.status_code, body)
        lowered_payload = payload.lower()
        if any(token in lowered_payload for token in SUSPICIOUS_TOKENS):
            status = "failed"

        log_payload = {
            "source": DUMMY_SOURCE_NAME,
            "ip": ip,
            "user_agent": user_agent,
            "endpoint": request.path,
            "method": request.method,
            "status": status,
            "payload": payload[:2000],
            "timestamp": datetime.utcnow().isoformat(),
        }

        thread = threading.Thread(target=_send_async, args=(log_payload,), daemon=True)
        thread.start()
        return response
