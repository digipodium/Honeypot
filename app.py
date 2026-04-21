from collections import Counter
from datetime import datetime, timedelta
import ipaddress
import json
import logging
import os
import random
import secrets
import smtplib
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from smtplib import SMTPAuthenticationError

from flask import (
    Flask,
    flash,
    g,
    jsonify,
    make_response,
    redirect,
    render_template, 
    request,
    session,
    url_for,
    send_from_directory,
)
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from sqlalchemy import or_
from werkzeug.security import check_password_hash, generate_password_hash

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

if load_dotenv:
    load_dotenv()


app = Flask(__name__)
app.config["SECRET_KEY"] = "secret_key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SMTP_HOST"] = os.getenv("SMTP_HOST", "smtp.gmail.com")
app.config["SMTP_PORT"] = int(os.getenv("SMTP_PORT", "587"))
app.config["SMTP_USERNAME"] = os.getenv("SMTP_USERNAME", "")
app.config["SMTP_PASSWORD"] = os.getenv("SMTP_PASSWORD", "")
app.config["SMTP_FROM"] = os.getenv("SMTP_FROM", app.config["SMTP_USERNAME"])
app.config["SMTP_USE_TLS"] = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
app.config["PASSWORD_RESET_CODE_TTL"] = int(os.getenv("PASSWORD_RESET_CODE_TTL", "600"))
app.config["LOG_API_KEY"] = os.getenv("LOG_API_KEY", "")
app.config["EXTERNAL_FAILED_LOGIN_THRESHOLD"] = int(os.getenv("EXTERNAL_FAILED_LOGIN_THRESHOLD", "5"))
app.config["EXTERNAL_FAILED_LOGIN_WINDOW_SEC"] = int(os.getenv("EXTERNAL_FAILED_LOGIN_WINDOW_SEC", "300"))

db = SQLAlchemy(app)

logging.basicConfig(
    filename="honeypot.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class LegacyUser(db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(100))


class AttackLog(db.Model):
    __tablename__ = "attack_logs"

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(50), nullable=False, index=True)
    method = db.Column(db.String(10), nullable=False)
    path = db.Column(db.String(500), nullable=False)
    body = db.Column(db.Text)
    headers = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)


class ExternalLog(db.Model):
    __tablename__ = "external_logs"

    id = db.Column(db.Integer, primary_key=True)
    source = db.Column(db.String(80), nullable=False, default="dummy-site", index=True)
    ip_address = db.Column(db.String(64), nullable=False, index=True)
    user_agent = db.Column(db.String(512))
    endpoint = db.Column(db.String(500), nullable=False, index=True)
    method = db.Column(db.String(16), nullable=False, index=True)
    status = db.Column(db.String(40), nullable=False, default="unknown", index=True)
    payload = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    is_alert = db.Column(db.Boolean, nullable=False, default=False, index=True)
    alert_reason = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)


class AlertState(db.Model):
    __tablename__ = "alert_states"

    attack_log_id = db.Column(db.Integer, db.ForeignKey("attack_logs.id"), primary_key=True)
    is_read = db.Column(db.Boolean, nullable=False, default=False)
    is_dismissed = db.Column(db.Boolean, nullable=False, default=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(120), nullable=False, default="system", index=True)
    ip = db.Column(db.String(50), nullable=False, default="unknown", index=True)
    method = db.Column(db.String(10), nullable=False, default="GET")
    path = db.Column(db.String(255), nullable=False, default="/")
    action = db.Column(db.String(120), nullable=False, index=True)
    target = db.Column(db.String(255), nullable=False, default="system")
    status = db.Column(db.String(40), nullable=False, default="Success")
    status_code = db.Column(db.Integer, nullable=False, default=200)
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)


with app.app_context():
    db.create_all()


def ensure_demo_user():
    demo_email = "admin@honeypot.local"
    demo_password = "Admin@123"
    demo_user = User.query.filter_by(email=demo_email).first()

    if demo_user is None:
        demo_user = User(
            name="Admin",
            email=demo_email,
            password=generate_password_hash(demo_password),
        )
        db.session.add(demo_user)
        db.session.commit()


with app.app_context():
    ensure_demo_user()


def login_required(route):
    @wraps(route)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login to access this page", "error")
            return redirect(url_for("login"))
        return route(*args, **kwargs)

    return wrapped


def render_auth_page(active_tab="login"):
    return render_template("login.html", active_tab=active_tab)


def generate_verification_code():
    return f"{secrets.randbelow(1000000):06d}"


def clear_password_reset_session():
    for key in (
        "password_reset_email",
        "password_reset_code_hash",
        "password_reset_expires_at",
        "password_reset_verified",
    ):
        session.pop(key, None)


def send_password_reset_code(recipient_email, code):
    smtp_username = str(app.config["SMTP_USERNAME"]).strip()
    smtp_password = str(app.config["SMTP_PASSWORD"]).strip()
    smtp_from = str(app.config["SMTP_FROM"]).strip() or smtp_username

    if not smtp_username or not smtp_password or not smtp_from:
        logging.warning(
            "Password reset email not sent because SMTP is not configured for %s",
            recipient_email,
        )
        return False, "SMTP is not configured yet. Add SMTP settings first."

    message = MIMEMultipart()
    message["From"] = smtp_from
    message["To"] = recipient_email
    message["Subject"] = "Honeypot password reset verification code"

    html_body = f"""
    <html>
      <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #111827;">
        <h2>Password reset verification</h2>
        <p>You requested to reset your Honeypot account password.</p>
        <p>Your verification code is:</p>
        <div style="font-size: 28px; font-weight: 700; letter-spacing: 6px; margin: 16px 0; color: #0f766e;">
          {code}
        </div>
        <p>This code expires in 10 minutes.</p>
        <p>If you did not request this, you can ignore this email.</p>
      </body>
    </html>
    """
    message.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(app.config["SMTP_HOST"], app.config["SMTP_PORT"]) as server:
            if app.config["SMTP_USE_TLS"]:
                server.starttls()
            server.login(smtp_username, smtp_password)
            server.sendmail(smtp_from, recipient_email, message.as_string())
    except SMTPAuthenticationError:
        logging.exception("SMTP authentication failed for password reset email")
        return (
            False,
            "Email login failed. For Gmail, use your full Gmail address in SMTP_USERNAME, "
            "use a Google App Password in SMTP_PASSWORD, and keep SMTP_FROM the same as SMTP_USERNAME.",
        )
    except Exception as exc:
        logging.exception("Failed to send password reset email to %s", recipient_email)
        return False, "Failed to send verification code. Check your SMTP settings and try again."

    return True, None


def get_pending_reset_user():
    email = session.get("password_reset_email")
    if not email:
        return None
    return User.query.filter_by(email=email).first()


def mask_email(email):
    if "@" not in email:
        return email
    name_part, domain_part = email.split("@", 1)
    visible = name_part[:2] if len(name_part) > 2 else name_part[:1]
    return f"{visible}{'*' * max(len(name_part) - len(visible), 1)}@{domain_part}"


def find_current_user(identifier):
    lowered_identifier = identifier.lower()
    return (
        User.query.filter(
            or_(
                db.func.lower(User.email) == lowered_identifier,
                db.func.lower(User.name) == lowered_identifier,
            )
        ).first()
    )


def find_legacy_user(identifier):
    lowered_identifier = identifier.lower()
    return (
        LegacyUser.query.filter(
            or_(
                db.func.lower(LegacyUser.email) == lowered_identifier,
                db.func.lower(LegacyUser.name) == lowered_identifier,
            )
        ).first()
    )


def migrate_legacy_user(legacy_user, plain_password):
    existing_user = User.query.filter(
        db.func.lower(User.email) == (legacy_user.email or "").lower()
    ).first()
    if existing_user:
        return existing_user

    user = User(
        name=legacy_user.name or legacy_user.email or "User",
        email=(legacy_user.email or "").strip().lower(),
        password=generate_password_hash(plain_password),
    )
    db.session.add(user)
    db.session.commit()
    return user


def detect_attack_type(path, body=""):
    data = f"{path} {body}".lower()

    if any(token in data for token in ("drop table", "union select", " or 1=1", "select ", "admin'--")):
        return "SQLi"
    if any(token in data for token in ("<script", "javascript:", "onerror=", "onmouseover=")):
        return "XSS"
    if any(token in data for token in ("wget ", "curl ", "cmd=", "/bin/bash", "/bin/sh", "shell.php")):
        return "RCE"
    if any(
        token in data
        for token in (
            "wp-admin",
            "wp-login",
            "/login",
            "login",
            "signin",
            "sign-in",
            "/admin",
            "/auth",
            "/token",
            "username=",
            "user=",
            "email=",
            "password=",
            "passwd=",
            "pwd=",
            "otp=",
        )
    ):
        return "Brute"
    if any(token in data for token in (".env", ".git", "backup", "config", "passwd", "shadow")):
        return "Recon"
    if any(token in data for token in ("flood", "ddos", "masscan", "nmap")):
        return "DDoS"
    return "Recon"


def detect_severity(path, body=""):
    threat = detect_attack_type(path, body)
    if threat in {"SQLi", "RCE", "DDoS"}:
        return "Critical"
    if threat == "Brute":
        return "High"
    if threat == "XSS":
        return "Medium"
    return "Low"


def detect_status(path, body=""):
    severity = detect_severity(path, body)
    return {
        "Critical": "Blocked",
        "High": "Blocked",
        "Medium": "Alerted",
        "Low": "Passed",
    }[severity]


def serialise_attack_log(log):
    body = log.body or ""
    headers = {}
    if log.headers:
        try:
            headers = json.loads(log.headers)
        except (TypeError, json.JSONDecodeError):
            headers = {}

    return {
        "id": log.id,
        "ip": log.ip,
        "method": log.method,
        "path": log.path,
        "body": body,
        "headers": headers,
        "timestamp": log.timestamp.isoformat(),
        "time": log.timestamp.strftime("%H:%M:%S"),
        "ts": log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "threat": detect_severity(log.path, body).upper(),
        "type": detect_attack_type(log.path, body),
        "sev": detect_severity(log.path, body),
        "status": detect_status(log.path, body),
        "target": log.path,
        "payload": body[:180],
        "country": "Unknown",
    }


def get_ip_type(ip):
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return "Unknown"

    if parsed.is_loopback:
        return "Internal"
    if parsed.is_private:
        return "Internal"
    return "External"


def summarise_ip_logs(logs):
    grouped = {}
    for log in logs:
        item = serialise_attack_log(log)
        ip = item["ip"]
        record = grouped.setdefault(
            ip,
            {
                "ip": ip,
                "label": "Observed Source",
                "status": "Watching",
                "threat": "Low",
                "type": get_ip_type(ip),
                "country": "Unknown",
                "requests": 0,
                "blocked": 0,
                "unique_paths": set(),
                "lastSeen": item["time"],
                "lastTimestamp": item["timestamp"],
                "last_path": item["path"],
            },
        )
        record["requests"] += 1
        if item["status"] == "Blocked":
            record["blocked"] += 1
        record["unique_paths"].add(item["path"])
        if item["timestamp"] > record["lastTimestamp"]:
            record["lastTimestamp"] = item["timestamp"]
            record["lastSeen"] = item["time"]
            record["last_path"] = item["path"]

        severity = item["sev"]
        if severity == "Critical":
            record["threat"] = "Critical"
            record["status"] = "Blocked"
        elif severity == "High" and record["threat"] not in {"Critical"}:
            record["threat"] = "High"
            if record["status"] != "Blocked":
                record["status"] = "Watching"
        elif severity == "Medium" and record["threat"] not in {"Critical", "High"}:
            record["threat"] = "Medium"
        elif severity == "Low" and record["threat"] == "Low":
            record["status"] = "Online" if record["type"] == "Internal" else "Watching"

        attack_type = item["type"]
        if attack_type == "SQLi":
            record["label"] = "SQL Injection Source"
        elif attack_type == "RCE":
            record["label"] = "Remote Execution Probe"
        elif attack_type == "Brute":
            record["label"] = "Credential Attack Source"
        elif attack_type == "XSS":
            record["label"] = "XSS Probe Source"
        elif attack_type == "DDoS":
            record["label"] = "Flood Source"
        elif attack_type == "Recon" and record["label"] == "Observed Source":
            record["label"] = "Recon Source"

    response = []
    for index, record in enumerate(
        sorted(grouped.values(), key=lambda value: (value["blocked"], value["requests"]), reverse=True),
        start=1,
    ):
        response.append(
            {
                "id": index,
                "ip": record["ip"],
                "label": record["label"],
                "status": record["status"],
                "threat": record["threat"],
                "type": record["type"],
                "country": record["country"],
                "requests": record["requests"],
                "blocked": record["blocked"],
                "unique_paths": len(record["unique_paths"]),
                "lastSeen": record["lastSeen"],
                "last_path": record["last_path"],
            }
        )
    return response


def get_alert_state_map(log_ids):
    if not log_ids:
        return {}

    states = AlertState.query.filter(AlertState.attack_log_id.in_(log_ids)).all()
    return {state.attack_log_id: state for state in states}


def build_alert_from_log(log, state=None):
    event = serialise_attack_log(log)
    severity = event["sev"]
    attack_type = event["type"]
    title_map = {
        "SQLi": "SQL injection attempt detected",
        "XSS": "Cross-site scripting probe detected",
        "RCE": "Remote code execution probe detected",
        "Brute": "Credential attack detected",
        "Recon": "Reconnaissance activity detected",
        "DDoS": "Flood activity detected",
    }
    description = (
        f'{event["ip"]} targeted {event["path"]} using {event["method"]}. '
        f'The request was classified as {severity} severity and marked {event["status"]}.'
    )

    return {
        "id": event["id"],
        "log_id": event["id"],
        "sev": severity,
        "type": attack_type,
        "title": title_map.get(attack_type, "Suspicious activity detected"),
        "desc": description,
        "ip": event["ip"],
        "country": event["country"],
        "time": event["time"],
        "timestamp": event["timestamp"],
        "target": event["target"],
        "action": event["status"],
        "read": state.is_read if state else False,
        "details": {
            "method": event["method"],
            "path": event["path"],
            "status": event["status"],
            "payload": event["payload"] or "No payload captured",
            "threat": event["threat"],
        },
    }


def list_live_alerts(limit=200, include_dismissed=False):
    logs = AttackLog.query.order_by(AttackLog.timestamp.desc()).limit(limit).all()
    states = get_alert_state_map([log.id for log in logs])

    alerts = []
    for log in logs:
        state = states.get(log.id)
        if state and state.is_dismissed and not include_dismissed:
            continue
        alerts.append(build_alert_from_log(log, state))
    return alerts


def severity_rank(value):
    return {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}.get(value, 0)


def build_analysis_payload(hours=24):
    cutoff = datetime.utcnow().timestamp() - (hours * 3600)
    logs = AttackLog.query.order_by(AttackLog.timestamp.desc()).all()
    serialised = [
        item for item in (serialise_attack_log(log) for log in logs)
        if datetime.fromisoformat(item["timestamp"]).timestamp() >= cutoff
    ]

    total = len(serialised)
    unique_ips = len({item["ip"] for item in serialised})
    blocked = sum(1 for item in serialised if item["status"] == "Blocked")
    critical = sum(1 for item in serialised if item["sev"] == "Critical")
    block_rate = round((blocked / total) * 100, 1) if total else 0
    risk_score = min(
        100,
        round(
            (critical * 3)
            + (sum(1 for item in serialised if item["sev"] == "High") * 2)
            + (unique_ips * 1.5)
        ),
    )

    hours_to_show = min(hours, 24)
    labels = [f"{index:02d}:00" for index in range(hours_to_show)]
    timeline_counts = {label: 0 for label in labels}
    severity_trend = {
        label: {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for label in labels
    }
    weekday_labels = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    heatmap_rows = {
        day: [{"hour": hour, "count": 0} for hour in range(24)]
        for day in weekday_labels
    }

    type_counter = Counter()
    endpoint_counter = Counter()
    ip_counter = Counter()

    for item in serialised:
        parsed = datetime.fromisoformat(item["timestamp"])
        hour_label = parsed.strftime("%H:00")
        if hour_label in timeline_counts:
            timeline_counts[hour_label] += 1
            severity_trend[hour_label][item["sev"]] += 1
        heatmap_rows[parsed.strftime("%a")][parsed.hour]["count"] += 1
        type_counter[item["type"]] += 1
        endpoint_counter[item["path"]] += 1
        ip_counter[item["ip"]] += 1

    top_ips = []
    for ip, hits in ip_counter.most_common(8):
        related = [item for item in serialised if item["ip"] == ip]
        top_ips.append(
            {
                "ip": ip,
                "hits": hits,
                "type": Counter(item["type"] for item in related).most_common(1)[0][0],
                "severity": max((item["sev"] for item in related), key=severity_rank),
                "country": related[0]["country"],
            }
        )

    insights = []
    if total:
        most_targeted_path, path_hits = endpoint_counter.most_common(1)[0]
        top_ip, top_ip_hits = ip_counter.most_common(1)[0]
        insights.append(
            {
                "level": "danger" if critical else "info",
                "title": "Most targeted endpoint",
                "message": f"{most_targeted_path} was probed {path_hits} times in the selected window.",
            }
        )
        insights.append(
            {
                "level": "warning" if top_ip_hits >= 3 else "info",
                "title": "Noisiest source IP",
                "message": f"{top_ip} generated {top_ip_hits} captured requests.",
            }
        )
        insights.append(
            {
                "level": "success" if block_rate >= 80 else "warning",
                "title": "Blocking effectiveness",
                "message": f"{block_rate}% of captured requests were blocked automatically.",
            }
        )

    return {
        "summary": {
            "total_attacks": total,
            "blocked": blocked,
            "unique_ips": unique_ips,
            "avg_response": "0.8s",
            "critical_events": critical,
            "risk_score": risk_score,
            "risk_label": "High risk" if risk_score >= 60 else "Medium risk" if risk_score >= 30 else "Low risk",
            "block_rate": block_rate,
        },
        "timeline": {
            "labels": labels,
            "counts": [timeline_counts[label] for label in labels],
            "label": f"last {hours} hours",
        },
        "types": [{"type": name, "count": count} for name, count in type_counter.most_common()],
        "top_ips": top_ips,
        "countries": [{"country": country, "count": count} for country, count in Counter(item["country"] for item in serialised).most_common(8)],
        "heatmap": [{"day": day, "hours": hours_data} for day, hours_data in heatmap_rows.items()],
        "severity_trend": {
            "labels": labels,
            "series": {
                "Critical": [severity_trend[label]["Critical"] for label in labels],
                "High": [severity_trend[label]["High"] for label in labels],
                "Medium": [severity_trend[label]["Medium"] for label in labels],
                "Low": [severity_trend[label]["Low"] for label in labels],
            },
        },
        "endpoints": [{"path": path, "count": count} for path, count in endpoint_counter.most_common(8)],
        "insights": insights,
        "recent_critical": [
            item for item in serialised
            if item["sev"] in {"Critical", "High"}
        ][:6],
    }


def serialise_audit_log(log):
    return {
        "id": log.id,
        "user": log.user_name,
        "ip": log.ip,
        "method": log.method,
        "path": log.path,
        "action": log.action,
        "target": log.target,
        "status": log.status,
        "status_code": log.status_code,
        "details": log.details or "",
        "timestamp": log.timestamp.isoformat(),
        "ts": log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
    }


def write_audit_log(action, target, status="Success", details=None, status_code=200):
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    entry = AuditLog(
        user_name=session.get("user_name", "system"),
        ip=ip,
        method=request.method,
        path=request.path,
        action=action,
        target=target,
        status=status,
        status_code=status_code,
        details=json.dumps(details) if isinstance(details, (dict, list)) else details,
    )
    db.session.add(entry)
    db.session.commit()
    return entry


AUDIT_EXCLUDED_PATHS = {
    "/honeypot-logs",
    "/api/logs",
    "/api/external-logs",
    "/api/external-logs/stats",
    "/api/dashboard/summary",
    "/api/ip-monitor",
    "/api/analysis",
    "/api/alerts",
    "/api/audit-logs",
}


def resolve_audit_action(path, method):
    if path == "/login" and method == "POST":
        return ("Login", "session")
    if path == "/register" and method == "POST":
        return ("Register", "account")
    if path == "/logout":
        return ("Logout", "session")
    if path == "/settings":
        return ("Viewed Settings", "settings")
    if path == "/reports":
        return ("Viewed Reports", "reports")
    if path == "/dashboard":
        return ("Viewed Dashboard", "dashboard")
    if path == "/attacklogs":
        return ("Viewed Attack Logs", "attacklogs")
    if path == "/analysis":
        return ("Viewed Analysis", "analysis")
    if path == "/alerts":
        return ("Viewed Alerts", "alerts")
    if path == "/IPmonitor":
        return ("Viewed IP Monitor", "ip-monitor")
    if path == "/api/alerts/mark-all-read" and method == "POST":
        return ("Marked All Alerts Read", "alerts")
    if path == "/api/alerts/clear" and method == "DELETE":
        return ("Cleared Alerts", "alerts")
    if path.startswith("/api/alerts/") and path.endswith("/read") and method == "POST":
        return ("Marked Alert Read", path.rsplit("/", 2)[1])
    if path.startswith("/api/alerts/") and method == "DELETE":
        return ("Dismissed Alert", path.rsplit("/", 1)[1])
    if path == "/api/audit-logs/cleanup" and method == "DELETE":
        return ("Cleaned Audit Logs", "audit-logs")
    return (None, None)


@app.after_request
def auto_audit_request(response):
    try:
        if request.endpoint == "static":
            return response
        if request.path.startswith("/honeypot"):
            return response
        if request.path in AUDIT_EXCLUDED_PATHS and request.method == "GET":
            return response

        action, target = resolve_audit_action(request.path, request.method)
        if action is None:
            return response

        status = getattr(g, "audit_status", "Success" if response.status_code < 400 else "Failed")
        write_audit_log(
            action=action,
            target=target or request.path,
            status=status,
            status_code=response.status_code,
            details={"endpoint": request.path, "method": request.method},
        )
    except Exception:
        db.session.rollback()
    return response


def get_dummy_response(path):
    probe = path.lower()

    if any(token in probe for token in ("login", "auth", "signin", "token")):
        return {
            "token": "eyJhbGciOiJIUzI1NiJ9.fake.signature",
            "expires_in": 3600,
            "user": {"id": 1, "role": "admin"},
        }
    if any(token in probe for token in ("admin", "users", "accounts", "members")):
        return {
            "users": [
                {"id": 1, "username": "admin", "email": "admin@corp.local", "role": "superuser"},
                {"id": 2, "username": "john.doe", "email": "john@corp.local", "role": "user"},
            ]
        }
    if any(token in probe for token in (".env", "config", "secrets", "db", "database")):
        return {
            "DB_HOST": "db.internal",
            "DB_USER": "root",
            "DB_PASS": "Sup3rS3cr3t!",
            "DB_NAME": "production",
            "SECRET_KEY": "xK9#mP2$nQ7@wL4",
        }
    if any(token in probe for token in ("flag", "key", "password", "passwd", "shadow")):
        return {"flag": "HTB{f4k3_fl4g_y0u_f00l}", "valid": True}
    if any(token in probe for token in ("files", "upload", "backup", "dump")):
        return {"files": ["backup_2024.sql", "passwords.txt", "id_rsa.pem", "dump.zip"]}

    return {"status": "ok", "message": "Request processed successfully"}


def log_attack(req):
    path = req.path.lower()
    if "login" in path or "register" in path:
        return None

    body = req.get_data(as_text=True)[:500]
    headers = {
        key: value
        for key, value in req.headers.items()
        if key in {"User-Agent", "Referer", "Origin", "Content-Type", "X-Forwarded-For"}
    }

    entry = AttackLog(
        ip=req.headers.get("X-Forwarded-For", req.remote_addr or "unknown").split(",")[0].strip(),
        method=req.method,
        path=req.path,
        body=body,
        headers=json.dumps(headers),
    )
    db.session.add(entry)
    db.session.commit()

    logging.info(
        json.dumps(
            {
                "time": entry.timestamp.isoformat(),
                "ip": entry.ip,
                "method": entry.method,
                "path": entry.path,
                "body": body,
                "headers": headers,
            }
        )
    )
    g.attack_logged = True
    return entry


MONITORED_SENSITIVE_PATHS = (
    "/admin",
    "/wp-login",
    "/wp-admin",
    "/api/auth",
)

REQUEST_LOG_EXCLUDED_PREFIXES = (
    "/static/",
)

REQUEST_LOG_EXCLUDED_PATHS = {
    "/favicon.ico",
    "/honeypot-logs",
    "/api/logs",
    "/api/external-logs",
    "/api/external-logs/stats",
    "/api/dashboard/summary",
    "/api/ip-monitor",
    "/api/analysis",
    "/api/alerts",
    "/api/audit-logs",
}


def build_request_capture(req):
    body = req.get_data(as_text=True)[:500]
    query_string = req.query_string.decode("utf-8", errors="ignore")[:300]
    headers = {
        key: value
        for key, value in req.headers.items()
        if key in {"User-Agent", "Referer", "Origin", "Content-Type", "X-Forwarded-For"}
    }
    ip = req.headers.get("X-Forwarded-For", req.remote_addr or "unknown").split(",")[0].strip()

    return {
        "ip": ip,
        "method": req.method,
        "path": req.path,
        "body": body,
        "query": query_string,
        "headers": headers,
        "user_agent": headers.get("User-Agent", ""),
    }


def classify_suspicious_request(capture):
    searchable = " ".join(
        [
            capture.get("path", ""),
            capture.get("query", ""),
            capture.get("body", ""),
            capture.get("user_agent", ""),
        ]
    ).lower()

    matches = []
    if any(token in searchable for token in ("drop table", "union select", " or 1=1", "select ", "admin'--", "sleep(", "benchmark(")):
        matches.append("SQLi")
    if any(token in searchable for token in ("<script", "javascript:", "onerror=", "onmouseover=", "alert(")):
        matches.append("XSS")
    if any(token in searchable for token in ("wget ", "curl ", "cmd=", "/bin/bash", "/bin/sh", "shell.php", "system(", "passthru(", "shell_exec")):
        matches.append("RCE")
    if any(token in searchable for token in ("wp-admin", "wp-login", "/admin", "password=", "passwd=", "username=", "otp=", "signin", "credential", "basic ")):
        matches.append("Brute")
    if any(token in searchable for token in (".env", ".git", "backup", "config", "passwd", "shadow", "secrets", "private_key", "/etc/passwd", "/etc/shadow")):
        matches.append("Recon")
    if any(token in searchable for token in ("flood", "ddos", "masscan", "nmap", "nikto", "sqlmap", "hydra", "gobuster", "wfuzz")):
        matches.append("DDoS")

    seen = set()
    return [item for item in matches if not (item in seen or seen.add(item))]


EXTERNAL_ALERT_PATTERNS = (
    ("SQLi", ("' or 1=1", " or 1=1", "union select", "drop table", "information_schema", "'--", "\"--")),
    ("XSS", ("<script", "javascript:", "onerror=", "onload=", "alert(")),
    ("RCE", (";wget ", ";curl ", "cmd=", "&&", "| bash", "/bin/sh", "powershell ")),
)


def parse_external_timestamp(value):
    if not value:
        return datetime.utcnow()
    if isinstance(value, datetime):
        return value
    try:
        parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        if parsed.tzinfo is not None:
            return parsed.astimezone().replace(tzinfo=None)
        return parsed
    except ValueError:
        return datetime.utcnow()


def serialise_external_log(log):
    return {
        "id": log.id,
        "source": log.source,
        "ip_address": log.ip_address,
        "user_agent": log.user_agent or "",
        "endpoint": log.endpoint,
        "method": log.method,
        "status": log.status,
        "payload": log.payload or "",
        "timestamp": log.timestamp.isoformat(),
        "is_alert": log.is_alert,
        "alert_reason": log.alert_reason or "",
    }


def detect_external_alert(ip_address, endpoint, status, payload, user_agent, event_ts):
    searchable = " ".join([endpoint or "", payload or "", user_agent or "", status or ""]).lower()
    reasons = []

    for attack_type, tokens in EXTERNAL_ALERT_PATTERNS:
        if any(token in searchable for token in tokens):
            reasons.append(f"{attack_type} pattern detected")

    is_login_path = "/login" in (endpoint or "").lower() or "/signin" in (endpoint or "").lower()
    failed_status = (status or "").lower() in {"failed", "error", "denied", "blocked"}

    if is_login_path and failed_status:
        window_start = event_ts - timedelta(seconds=app.config["EXTERNAL_FAILED_LOGIN_WINDOW_SEC"])
        failed_count = (
            ExternalLog.query.filter(
                ExternalLog.ip_address == ip_address,
                ExternalLog.endpoint.ilike("%login%"),
                ExternalLog.status.in_(["failed", "error", "denied", "blocked"]),
                ExternalLog.timestamp >= window_start,
            ).count()
        )
        if failed_count + 1 >= app.config["EXTERNAL_FAILED_LOGIN_THRESHOLD"]:
            reasons.append(
                f"Too many failed login attempts from same IP (>= {app.config['EXTERNAL_FAILED_LOGIN_THRESHOLD']})"
            )

    if not reasons:
        return False, ""
    return True, " | ".join(reasons)


def should_log_suspicious_request(req, capture=None):
    if req.method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
        return False
    if any(req.path.startswith(prefix) for prefix in REQUEST_LOG_EXCLUDED_PREFIXES):
        return False
    if req.path in REQUEST_LOG_EXCLUDED_PATHS:
        return False
    
    lowered_path = req.path.lower()
    if "login" in lowered_path or "register" in lowered_path:
        return False

    if req.path.startswith("/honeypot"):
        return False
    if request.endpoint == "static":
        return False

    capture = capture or build_request_capture(req)
    matches = classify_suspicious_request(capture)
    lowered_path = req.path.lower()
    is_sensitive_target = any(token in lowered_path for token in MONITORED_SENSITIVE_PATHS)
    if lowered_path in {"/login", "/register", "/logout"} and not matches:
        is_sensitive_target = False
    return bool(matches or is_sensitive_target)


def log_security_event(req, note=None, force=False):
    if getattr(g, "attack_logged", False):
        return None

    path = req.path.lower()
    if "login" in path or "register" in path:
        return None

    capture = build_request_capture(req)
    if not force and not should_log_suspicious_request(req, capture):
        return None

    detail_parts = []
    if note:
        detail_parts.append(f"event={note}")
    if capture["query"]:
        detail_parts.append(f"query={capture['query']}")
    if capture["body"]:
        detail_parts.append(f"body={capture['body']}")
    body = " | ".join(detail_parts)[:500]

    entry = AttackLog(
        ip=capture["ip"],
        method=capture["method"],
        path=capture["path"],
        body=body,
        headers=json.dumps(capture["headers"]),
    )
    db.session.add(entry)
    db.session.commit()

    logging.info(
        json.dumps(
            {
                "time": entry.timestamp.isoformat(),
                "ip": entry.ip,
                "method": entry.method,
                "path": entry.path,
                "body": body,
                "headers": capture["headers"],
                "note": note or "suspicious_request",
            }
        )
    )
    g.attack_logged = True
    return entry


@app.before_request
def capture_suspicious_requests():
    if getattr(g, "attack_logged", False):
        return
    log_security_event(request)


@app.route("/")
def index():
    return render_template("honeypot_homepage.html")


@app.route("/script.js")
def script_js():
    return send_from_directory(os.path.join(app.root_path, "static"), "script.js")


@app.route("/style.css")
def style_css():
    return send_from_directory(os.path.join(app.root_path, "static"), "style.css")


@app.route("/static/<path:filename>")
def static_files(filename):
    return send_from_directory(os.path.join(app.root_path, "static"), filename)



@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_auth_page("register")

    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    confirm = request.form.get("confirm_password", "")

    if not name or not email or not password:
        g.audit_status = "Failed"
        flash("All fields are required", "error")
        return redirect(url_for("register"))
    if password != confirm:
        g.audit_status = "Failed"
        flash("Passwords do not match", "error")
        return redirect(url_for("register"))
    if User.query.filter_by(email=email).first() or LegacyUser.query.filter_by(email=email).first():
        g.audit_status = "Failed"
        flash("Email already exists. Please login.", "error")
        return redirect(url_for("login"))

    user = User(name=name, email=email, password=generate_password_hash(password))
    db.session.add(user)
    db.session.commit()

    g.audit_status = "Success"
    flash("Account created successfully", "success")
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_auth_page("login")

    identifier = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    user = find_current_user(identifier)

    password_ok = False
    if user:
        try:
            password_ok = check_password_hash(user.password, password)
        except ValueError:
            password_ok = user.password == password
            if password_ok:
                user.password = generate_password_hash(password)
                db.session.commit()

    if not user or not password_ok:
        legacy_user = find_legacy_user(identifier)
        if legacy_user and legacy_user.password == password:
            user = migrate_legacy_user(legacy_user, password)
            password_ok = True

    if not user or not password_ok:
        attempted_identifier = identifier[:120] if identifier else "unknown"
        log_security_event(
            request,
            note=f"failed_login identifier={attempted_identifier}",
            force=True,
        )
        g.audit_status = "Failed"
        flash("Invalid username/email or password", "error")
        return redirect(url_for("login"))

    session["user_id"] = user.id
    session["user_name"] = user.name or user.email
    g.audit_status = "Success"
    flash("Signin successful", "success")
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    g.audit_status = "Success"
    session.clear()
    flash("Logged out successfully", "success")
    return redirect(url_for("login"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "GET":
        return render_template("forgot_password.html")

    email = request.form.get("email", "").strip().lower()
    if not email:
        g.audit_status = "Failed"
        flash("Please enter your email address", "error")
        return redirect(url_for("forgot_password"))

    user = User.query.filter_by(email=email).first()
    if user is None:
        g.audit_status = "Failed"
        flash("No account was found with that email address", "error")
        return redirect(url_for("forgot_password"))

    code = generate_verification_code()
    sent, error_message = send_password_reset_code(user.email, code)
    if not sent:
        g.audit_status = "Failed"
        flash(error_message, "error")
        return redirect(url_for("forgot_password"))

    session["password_reset_email"] = user.email
    session["password_reset_code_hash"] = generate_password_hash(code)
    session["password_reset_expires_at"] = int(time.time()) + app.config["PASSWORD_RESET_CODE_TTL"]
    session["password_reset_verified"] = False

    g.audit_status = "Success"
    flash("Verification code sent to your registered email address", "success")
    return redirect(url_for("verify_reset_code"))


@app.route("/verify-reset-code", methods=["GET", "POST"])
def verify_reset_code():
    user = get_pending_reset_user()
    expires_at = session.get("password_reset_expires_at")

    if user is None or expires_at is None:
        g.audit_status = "Failed"
        flash("Start with your registered email to reset your password", "error")
        return redirect(url_for("forgot_password"))

    if int(time.time()) > int(expires_at):
        clear_password_reset_session()
        g.audit_status = "Failed"
        flash("Verification code expired. Please request a new code.", "error")
        return redirect(url_for("forgot_password"))

    if request.method == "GET":
        return render_template("verify_reset_code.html", email=mask_email(user.email))

    code = request.form.get("code", "").strip()
    stored_code_hash = session.get("password_reset_code_hash")

    if not code:
        g.audit_status = "Failed"
        flash("Please enter the verification code", "error")
        return redirect(url_for("verify_reset_code"))
    if not stored_code_hash or not check_password_hash(stored_code_hash, code):
        g.audit_status = "Failed"
        flash("Invalid verification code", "error")
        return redirect(url_for("verify_reset_code"))

    session["password_reset_verified"] = True
    g.audit_status = "Success"
    return redirect(url_for("reset_password"))


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    user = get_pending_reset_user()
    expires_at = session.get("password_reset_expires_at")
    is_verified = session.get("password_reset_verified", False)

    if user is None or expires_at is None:
        g.audit_status = "Failed"
        flash("Start with your registered email to reset your password", "error")
        return redirect(url_for("forgot_password"))

    if int(time.time()) > int(expires_at):
        clear_password_reset_session()
        g.audit_status = "Failed"
        flash("Verification code expired. Please request a new code.", "error")
        return redirect(url_for("forgot_password"))

    if not is_verified:
        g.audit_status = "Failed"
        flash("Verify your code first before setting a new password", "error")
        return redirect(url_for("verify_reset_code"))

    if request.method == "GET":
        return render_template("reset_password.html", email=mask_email(user.email))

    password = request.form.get("password", "")
    confirm = request.form.get("confirm_password", "")

    if not password or not confirm:
        g.audit_status = "Failed"
        flash("Please fill in both password fields", "error")
        return redirect(url_for("reset_password"))
    if len(password) < 8:
        g.audit_status = "Failed"
        flash("Password must be at least 8 characters long", "error")
        return redirect(url_for("reset_password"))
    if password != confirm:
        g.audit_status = "Failed"
        flash("Passwords do not match", "error")
        return redirect(url_for("reset_password"))

    user.password = generate_password_hash(password)
    db.session.commit()
    clear_password_reset_session()

    g.audit_status = "Success"
    flash("Password updated successfully. Please login.", "success")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/attacklogs")
@login_required
def attacklogs():
    return render_template("attacklogs.html")


@app.route("/alerts")
@login_required
def alerts():
    return render_template("alerts.html")


@app.route("/analysis")
@login_required
def analysis():
    return render_template("Analysis.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/IPmonitor")
@login_required
def ip_monitor():
    return render_template("IPmonitor.html")


@app.route("/logs")
@login_required
def logs():
    return render_template("logs.html")


@app.route("/reports")
@login_required
def reports():
    return render_template("reports.html")


@app.route("/settings")
@login_required
def settings():
    current_user = User.query.get(session.get("user_id"))
    return render_template("Settings.html", current_user=current_user)


@app.route("/honeypot-logs")
@login_required
def honeypot_logs():
    logs = AttackLog.query.order_by(AttackLog.timestamp.desc()).limit(100).all()
    return jsonify([serialise_attack_log(log) for log in logs])


@app.route("/api/logs", methods=["GET", "POST"])
def api_logs():
    if request.method == "GET":
        if "user_id" not in session:
            return jsonify({"error": "Authentication required"}), 401
        logs = AttackLog.query.order_by(AttackLog.timestamp.desc()).limit(500).all()
        return jsonify([serialise_attack_log(log) for log in logs])

    expected_api_key = app.config["LOG_API_KEY"]
    received_api_key = request.headers.get("X-API-KEY", "").strip()
    if not expected_api_key:
        return jsonify({"error": "Ingestion API key is not configured on HoneyTrap"}), 503
    if received_api_key != expected_api_key:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    endpoint = (data.get("endpoint") or data.get("url") or "").strip()
    method = (data.get("method") or "GET").strip().upper()[:16]
    status = (data.get("status") or "unknown").strip().lower()[:40]
    ip_address = (data.get("ip") or data.get("ip_address") or request.remote_addr or "unknown").strip()
    user_agent = (data.get("user_agent") or request.headers.get("User-Agent") or "").strip()[:512]
    source = (data.get("source") or "dummy-site").strip()[:80]
    payload = data.get("payload")

    if isinstance(payload, (dict, list)):
        payload = json.dumps(payload)
    payload = (payload or "")[:2000]
    event_ts = parse_external_timestamp(data.get("timestamp"))

    if not endpoint:
        return jsonify({"error": "Missing required field: endpoint"}), 400
    
    # Do not log login or register interactions
    lowered_endpoint = endpoint.lower()
    if "login" in lowered_endpoint or "register" in lowered_endpoint:
        return jsonify({"status": "ignored", "reason": "login/register interaction"}), 200

    is_alert, reason = detect_external_alert(
        ip_address=ip_address,
        endpoint=endpoint,
        status=status,
        payload=payload,
        user_agent=user_agent,
        event_ts=event_ts,
    )

    entry = ExternalLog(
        source=source,
        ip_address=ip_address,
        user_agent=user_agent,
        endpoint=endpoint[:500],
        method=method,
        status=status,
        payload=payload,
        timestamp=event_ts,
        is_alert=is_alert,
        alert_reason=reason[:255] if reason else None,
    )
    db.session.add(entry)
    db.session.commit()

    return jsonify({"status": "ok", "id": entry.id, "is_alert": entry.is_alert, "alert_reason": entry.alert_reason}), 201


@app.route("/api/external-logs")
@login_required
def external_logs_data():
    ip_filter = request.args.get("ip", "").strip()
    status_filter = request.args.get("status", "").strip().lower()
    endpoint_filter = request.args.get("endpoint", "").strip()
    alert_only = request.args.get("alert_only", "").strip().lower() in {"1", "true", "yes"}
    limit = min(request.args.get("limit", 200, type=int), 1000)

    query = ExternalLog.query
    if ip_filter:
        query = query.filter(ExternalLog.ip_address.contains(ip_filter))
    if status_filter:
        query = query.filter(ExternalLog.status == status_filter)
    if endpoint_filter:
        query = query.filter(ExternalLog.endpoint.contains(endpoint_filter))
    if alert_only:
        query = query.filter(ExternalLog.is_alert.is_(True))

    logs = query.order_by(ExternalLog.timestamp.desc()).limit(limit).all()
    return jsonify([serialise_external_log(log) for log in logs])


@app.route("/api/external-logs/stats")
@login_required
def external_logs_stats():
    minutes = max(1, min(request.args.get("minutes", 60, type=int), 720))
    cutoff = datetime.utcnow() - timedelta(minutes=minutes)
    logs = ExternalLog.query.filter(ExternalLog.timestamp >= cutoff).order_by(ExternalLog.timestamp.asc()).all()

    per_minute_counter = Counter(log.timestamp.strftime("%H:%M") for log in logs)
    labels = []
    values = []
    cursor = cutoff.replace(second=0, microsecond=0)
    end = datetime.utcnow().replace(second=0, microsecond=0)
    while cursor <= end:
        key = cursor.strftime("%H:%M")
        labels.append(key)
        values.append(per_minute_counter.get(key, 0))
        cursor += timedelta(minutes=1)

    return jsonify(
        {
            "total": len(logs),
            "alerts": sum(1 for log in logs if log.is_alert),
            "failed": sum(1 for log in logs if log.status in {"failed", "error", "denied", "blocked"}),
            "labels": labels,
            "values": values,
        }
    )

@app.route("/api/dashboard/summary")
@login_required
def dashboard_summary():
    logs = AttackLog.query.order_by(AttackLog.timestamp.desc()).all()
    serialised = [serialise_attack_log(log) for log in logs]
    unique_ips = len({log["ip"] for log in serialised})
    unique_paths = len({log["path"] for log in serialised})
    threat_counter = Counter(log["threat"] for log in serialised)

    return jsonify(
        {
            "total_attacks": len(serialised),
            "unique_ips": unique_ips,
            "paths_probed": unique_paths,
            "dummy_responses": len(serialised),
            "high_threats": threat_counter.get("CRITICAL", 0) + threat_counter.get("HIGH", 0),
        }
    )

@app.route("/api/ip-monitor")
@login_required
def ip_monitor_data():
    logs = AttackLog.query.order_by(AttackLog.timestamp.desc()).limit(500).all()
    serialised_logs = [serialise_attack_log(log) for log in logs]
    ips = summarise_ip_logs(logs)

    recent_activity = [
        {
            "time": log["time"],
            "ip": log["ip"],
            "path": log["path"],
            "threat": log["threat"].title(),
            "message": f'{log["ip"]} hit {log["path"]}',
        }
        for log in serialised_logs[:8]
    ]

    countries = Counter(ip["country"] for ip in ips)
    metrics = {
        "total_ips": len(ips),
        "online": sum(1 for ip in ips if ip["status"] == "Online"),
        "blocked": sum(1 for ip in ips if ip["status"] == "Blocked"),
        "watching": sum(1 for ip in ips if ip["status"] == "Watching"),
        "critical": sum(1 for ip in ips if ip["threat"] == "Critical"),
        "total_requests": sum(ip["requests"] for ip in ips),
    }

    top_countries = [
        {"country": country, "count": count}
        for country, count in countries.most_common(6)
    ]

    return jsonify(
        {
            "metrics": metrics,
            "ips": ips,
            "countries": top_countries,
            "recent_activity": recent_activity,
        }
    )


@app.route("/api/alerts")
@login_required
def api_alerts():
    alerts = list_live_alerts()
    unread = sum(1 for alert in alerts if not alert["read"])
    summary = {
        "total": len(alerts),
        "unread": unread,
        "critical": sum(1 for alert in alerts if alert["sev"] == "Critical"),
        "high": sum(1 for alert in alerts if alert["sev"] == "High"),
        "medium": sum(1 for alert in alerts if alert["sev"] == "Medium"),
        "low": sum(1 for alert in alerts if alert["sev"] == "Low"),
    }
    return jsonify({"alerts": alerts, "summary": summary})


@app.route("/api/alerts/<int:alert_id>/read", methods=["POST"])
@login_required
def mark_alert_read(alert_id):
    state = db.session.get(AlertState, alert_id)
    if state is None:
        state = AlertState(attack_log_id=alert_id, is_read=True, is_dismissed=False)
        db.session.add(state)
    else:
        state.is_read = True
    state.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"status": "ok"})


@app.route("/api/alerts/mark-all-read", methods=["POST"])
@login_required
def mark_all_alerts_read():
    logs = AttackLog.query.all()
    states = get_alert_state_map([log.id for log in logs])
    for log in logs:
        state = states.get(log.id)
        if state is None:
            db.session.add(AlertState(attack_log_id=log.id, is_read=True, is_dismissed=False))
        else:
            state.is_read = True
            state.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"status": "ok"})


@app.route("/api/alerts/<int:alert_id>", methods=["DELETE"])
@login_required
def dismiss_alert(alert_id):
    state = db.session.get(AlertState, alert_id)
    if state is None:
        state = AlertState(attack_log_id=alert_id, is_read=True, is_dismissed=True)
        db.session.add(state)
    else:
        state.is_read = True
        state.is_dismissed = True
    state.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"status": "deleted"})


@app.route("/api/alerts/clear", methods=["DELETE"])
@login_required
def clear_alerts():
    logs = AttackLog.query.all()
    states = get_alert_state_map([log.id for log in logs])
    for log in logs:
        state = states.get(log.id)
        if state is None:
            db.session.add(AlertState(attack_log_id=log.id, is_read=True, is_dismissed=True))
        else:
            state.is_read = True
            state.is_dismissed = True
            state.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"status": "cleared"})


@app.route("/api/analysis")
@login_required
def analysis_data():
    hours = request.args.get("hours", 24, type=int)
    if hours not in {1, 24, 168, 720}:
        hours = 24
    return jsonify(build_analysis_payload(hours))


@app.route("/api/audit-logs")
@login_required
def audit_logs():
    limit = request.args.get("limit", 100, type=int)
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(limit).all()
    return jsonify([serialise_audit_log(log) for log in logs])


@app.route("/api/audit-logs/cleanup", methods=["DELETE"])
@login_required
def cleanup_audit_logs():
    days = request.args.get("days", 30, type=int)
    cutoff = datetime.utcnow().timestamp() - (days * 86400)
    logs = AuditLog.query.all()
    deleted = 0
    for log in logs:
        if log.timestamp.timestamp() < cutoff:
            db.session.delete(log)
            deleted += 1
    db.session.commit()
    return jsonify({"status": "ok", "deleted": deleted})


@app.route("/honeypot", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
@app.route("/honeypot/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def honeypot(path):
    log_attack(request)
    time.sleep(random.uniform(0.3, 1.2))

    response = make_response(jsonify(get_dummy_response(path or request.path)), 200)
    response.headers["Server"] = "Apache/2.4.41 (Ubuntu)"
    response.headers["X-Powered-By"] = "PHP/7.4.3"
    response.headers["X-Request-ID"] = f"req-{random.randint(10000, 99999)}"
    return response


if __name__ == "__main__":
    app.run(debug=True)
