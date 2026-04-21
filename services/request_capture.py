# app/utils/request_capture.py

import json
import time
import random
import logging
from datetime import datetime
from flask import request, make_response, jsonify

logger = logging.getLogger("honeypot")

# ─────────────────────────────────────────
# THREAT CLASSIFIER KEYWORDS
# ─────────────────────────────────────────
THREAT_MAP = {
    "sql_injection":    ["'", '"', "--", "1=1", "or 1", "union select",
                         "drop table", "sleep(", "benchmark("],
    "path_traversal":  ["../", "..\\", "%2e%2e", "/etc/passwd", "/etc/shadow",
                        "boot.ini", "win.ini"],
    "credential_probe":["admin", "/login", "/auth", "/signin", "/token",
                        "/wp-login", "/wp-admin", "/api/auth"],
    "secret_probe":    [".env", "config", "secrets", ".git", "backup",
                        "db_password", "api_key", "private_key"],
    "shell_probe":     ["cmd=", "exec=", "system(", "passthru(", "shell_exec",
                        "/bin/sh", "/bin/bash", "wget ", "curl "],
    "scanner_probe":   ["nmap", "nikto", "sqlmap", "burpsuite", "hydra",
                        "masscan", "dirbuster", "gobuster", "wfuzz"],
}

# ─────────────────────────────────────────
# STEP 1 — PARSE INCOMING REQUEST
# ─────────────────────────────────────────
def parse_request_data(req) -> dict:
    """
    Extract all attacker-relevant fields from a Flask request object.
    Called first in the honeypot pipeline.
    """
    # Try JSON body first, fall back to raw text
    body_raw = req.get_data(as_text=True)[:500]
    try:
        body = req.get_json(silent=True, force=True) or body_raw
    except Exception:
        body = body_raw

    # Only log security-relevant headers
    tracked_headers = [
        "User-Agent", "Referer", "Origin",
        "X-Forwarded-For", "X-Real-Ip",
        "Authorization", "Cookie",
        "X-Api-Key", "X-Auth-Token", "Content-Type",
    ]
    headers = {
        h: req.headers.get(h)
        for h in tracked_headers
        if req.headers.get(h)
    }

    return {
        "timestamp":    datetime.utcnow().isoformat(),
        "ip":           _resolve_ip(req),
        "method":       req.method,
        "path":         req.path,
        "query_params": dict(req.args),
        "body":         body,
        "headers":      headers,
        "user_agent":   req.headers.get("User-Agent", ""),
        "content_type": req.content_type,
    }


def _resolve_ip(req) -> str:
    """Return real IP, respecting proxy headers."""
    forwarded = req.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return req.remote_addr or "unknown"


# ─────────────────────────────────────────
# STEP 2 — CLASSIFY THREAT TYPE
# ─────────────────────────────────────────
def classify_threat(capture: dict) -> list:
    """
    Scan the parsed capture for known attack signatures.
    Returns a list of matched threat categories (empty = generic probe).
    """
    searchable = " ".join([
        capture.get("path", ""),
        json.dumps(capture.get("body", "")),
        json.dumps(capture.get("query_params", {})),
        capture.get("user_agent", ""),
    ]).lower()

    return [
        category
        for category, keywords in THREAT_MAP.items()
        if any(kw in searchable for kw in keywords)
    ]


# ─────────────────────────────────────────
# STEP 3 — LOG TO FILE + CONSOLE
# ─────────────────────────────────────────
def log_capture(capture: dict, threats: list):
    """
    Print a console alert and write a JSON line to honeypot.log.
    Uses the 'honeypot' logger configured in app/__init__.py.
    """
    label = ", ".join(threats).upper() if threats else "GENERIC PROBE"

    print(f"\n🚨 [HONEYPOT HIT] [{label}]")
    print(f"   IP      : {capture['ip']}")
    print(f"   Route   : {capture['method']} {capture['path']}")
    print(f"   Agent   : {capture.get('user_agent', '')[:80]}")
    print(f"   Time    : {capture['timestamp']}\n")

    logger.info(json.dumps({**capture, "threats": threats}))


# ─────────────────────────────────────────
# STEP 4 — SAVE TO DATABASE
# ─────────────────────────────────────────
def save_capture_to_db(capture: dict, threats: list):
    """
    Persist the capture to AttackLog model.
    Imports db + AttackLog inside the function to avoid circular imports.
    """
    try:
        from app import db
        from app.models import AttackLog

        log = AttackLog(
            ip      = capture["ip"],
            method  = capture["method"],
            path    = capture["path"],
            body    = json.dumps(capture.get("body", ""))[:500],
            headers = json.dumps(capture.get("headers", {}))[:500],
        )
        db.session.add(log)
        db.session.commit()

    except Exception as exc:
        from app import db
        db.session.rollback()
        logger.error(f"[request_capture] DB write failed: {exc}")


# ─────────────────────────────────────────
# STEP 5 — GENERATE FAKE RESPONSE
# ─────────────────────────────────────────
def get_dummy_response(path: str) -> dict:
    """
    Return believable fake JSON based on what the attacker is probing.
    Keeps them engaged while everything above is logged.
    """
    p = path.lower()

    if any(k in p for k in ["login", "auth", "signin", "token"]):
        return {
            "token":      "eyJhbGciOiJIUzI1NiJ9.fake.signature",
            "expires_in": 3600,
            "user":       {"id": 1, "role": "admin"},
        }
    if any(k in p for k in ["admin", "users", "accounts", "members"]):
        return {
            "users": [
                {"id": 1, "username": "admin",    "email": "admin@corp.local", "role": "superuser"},
                {"id": 2, "username": "john.doe", "email": "john@corp.local",  "role": "user"},
            ]
        }
    if any(k in p for k in [".env", "config", "secrets", "database"]):
        return {
            "DB_HOST":    "db.internal",
            "DB_USER":    "root",
            "DB_PASS":    "Sup3rS3cr3t!",
            "SECRET_KEY": "xK9#mP2$nQ7@wL4",
        }
    if any(k in p for k in ["flag", "key", "password", "shadow"]):
        return {"flag": "HTB{f4k3_fl4g_y0u_f00l}", "valid": True}
    if any(k in p for k in ["files", "upload", "backup", "dump"]):
        return {"files": ["backup_2024.sql", "passwords.txt", "id_rsa.pem"]}

    return {"status": "ok", "message": "Request processed successfully"}


def build_fake_response(path: str, status: int = 200):
    """
    Wrap get_dummy_response() in a Flask Response with spoofed server headers.
    Adds a random delay to slow automated scanners.
    """
    time.sleep(random.uniform(0.3, 1.2))

    resp = make_response(jsonify(get_dummy_response(path)), status)
    resp.headers["Server"]       = "Apache/2.4.41 (Ubuntu)"
    resp.headers["X-Powered-By"] = "PHP/7.4.3"
    resp.headers["X-Request-ID"] = f"req-{random.randint(10000, 99999)}"
    return resp


# ─────────────────────────────────────────
# MAIN ENTRY POINT  (used by honeypot_bp)
# ─────────────────────────────────────────
def capture_request_data(req=None):
    if req is None:
        req = request  # fallback to Flask's global request context

    capture = parse_request_data(req)
    threats = classify_threat(capture)

    log_capture(capture, threats)
    save_capture_to_db(capture, threats)

    return build_fake_response(req.path)
