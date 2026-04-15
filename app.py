from collections import Counter
from datetime import datetime
import ipaddress
import json
import logging
import random
import time

from flask import (
    Flask,
    flash,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from sqlalchemy import or_
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)
app.config["SECRET_KEY"] = "secret_key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

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
    if any(token in data for token in ("wp-admin", "wp-login", "/login", "/admin", "/auth", "/token")):
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


@app.route("/")
def index():
    return render_template("honeypot_homepage.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_auth_page("register")

    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    confirm = request.form.get("confirm_password", "")

    if not name or not email or not password:
        flash("All fields are required", "error")
        return redirect(url_for("register"))
    if password != confirm:
        flash("Passwords do not match", "error")
        return redirect(url_for("register"))
    if User.query.filter_by(email=email).first() or LegacyUser.query.filter_by(email=email).first():
        flash("Email already exists. Please login.", "error")
        return redirect(url_for("login"))

    user = User(name=name, email=email, password=generate_password_hash(password))
    db.session.add(user)
    db.session.commit()

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
        flash("Invalid username/email or password", "error")
        return redirect(url_for("login"))

    session["user_id"] = user.id
    session["user_name"] = user.name or user.email
    flash("Signin successful", "success")
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully", "success")
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
    return render_template("Settings.html")


@app.route("/honeypot-logs")
@login_required
def honeypot_logs():
    logs = AttackLog.query.order_by(AttackLog.timestamp.desc()).limit(100).all()
    return jsonify([serialise_attack_log(log) for log in logs])


@app.route("/api/logs")
@login_required
def api_logs():
    logs = AttackLog.query.order_by(AttackLog.timestamp.desc()).limit(500).all()
    return jsonify([serialise_attack_log(log) for log in logs])


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
