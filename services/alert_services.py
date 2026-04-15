"""
╔══════════════════════════════════════════════════════════════════════╗
║           HoneyShield — Alert Services Module                        ║
║                                                                      ║
║  Fully integrated with intrusion_analysis.py                        ║
║                                                                      ║
║  Services covered:                                                   ║
║   1.  AlertRule         — configurable detection rules               ║
║   2.  AlertEngine       — evaluates every log against all rules      ║
║   3.  AlertEscalation   — escalates unresolved alerts over time      ║
║   4.  AlertNotifier     — email / webhook / console delivery         ║
║   5.  AlertThrottle     — prevents duplicate / spam alerts           ║
║   6.  AlertScheduler    — background thread for periodic checks      ║
║   7.  AlertStats        — statistics for the alerts dashboard        ║
║   8.  AlertService      — unified facade used by Flask routes        ║
║   9.  Flask API routes  — /api/alerts/* endpoints                    ║
╚══════════════════════════════════════════════════════════════════════╝

Usage
-----
Import and register this blueprint in intrusion_analysis.py::

    from alert_services import alert_bp, AlertScheduler
    app.register_blueprint(alert_bp)

    with app.app_context():
        AlertScheduler.start(app)        # start background jobs
"""

import os
import smtplib
import threading
import time
import json
import logging
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import requests as http_requests
from flask import Blueprint, jsonify, request, current_app
from flask_sqlalchemy import SQLAlchemy

# ── Shared db instance imported from intrusion_analysis ──────────────
# When running standalone (for testing) we create a minimal Flask app.
# When used inside the main app, `db` and the models are shared.
try:
    from intrusion_analysis import (
        db,
        Alert,
        IntrusionLog,
        BlockedIP,
        DatabaseManager,
    )
    _STANDALONE = False
except ImportError:
    # Standalone mode — create own Flask + db for isolated testing
    from flask import Flask as _Flask
    from flask_sqlalchemy import SQLAlchemy as _SQLAlchemy

    _standalone_app = _Flask(__name__)
    _standalone_app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///honeyshield.db"
    _standalone_app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db = _SQLAlchemy(_standalone_app)
    _STANDALONE = True

    # Minimal model stubs so the file parses cleanly
    class Alert(db.Model):  # type: ignore
        __tablename__ = "alerts"
        id          = db.Column(db.Integer, primary_key=True)
        timestamp   = db.Column(db.DateTime, default=datetime.utcnow)
        title       = db.Column(db.String(256))
        description = db.Column(db.Text)
        ip_address  = db.Column(db.String(45))
        severity    = db.Column(db.String(10), default="high")
        threat_type = db.Column(db.String(50))
        is_read     = db.Column(db.Boolean, default=False)
        is_resolved = db.Column(db.Boolean, default=False)

        def to_dict(self):
            return {c.name: getattr(self, c.name) for c in self.__table__.columns}

    class IntrusionLog(db.Model):  # type: ignore
        __tablename__ = "intrusion_logs"
        id          = db.Column(db.Integer, primary_key=True)
        timestamp   = db.Column(db.DateTime, default=datetime.utcnow)
        ip_address  = db.Column(db.String(45))
        severity    = db.Column(db.String(10))
        threat_type = db.Column(db.String(50))
        path        = db.Column(db.String(512))
        is_blocked  = db.Column(db.Boolean, default=False)
        action_taken= db.Column(db.String(20))
        country     = db.Column(db.String(64))

    class BlockedIP(db.Model):  # type: ignore
        __tablename__ = "blocked_ips"
        id         = db.Column(db.Integer, primary_key=True)
        ip_address = db.Column(db.String(45), unique=True)
        reason     = db.Column(db.String(256))
        blocked_at = db.Column(db.DateTime, default=datetime.utcnow)
        blocked_by = db.Column(db.String(32), default="system")

    class DatabaseManager:
        @staticmethod
        def insert_alert(data):
            a = Alert(**data); db.session.add(a); db.session.commit(); return a
        @staticmethod
        def block_ip(ip, reason="", by="system"):
            if not BlockedIP.query.filter_by(ip_address=ip).first():
                db.session.add(BlockedIP(ip_address=ip, reason=reason, blocked_by=by))
                db.session.commit()


# ── Logging ──────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s  %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("HoneyShield.Alerts")


# ══════════════════════════════════════════════════════════════════════
# CONFIGURATION
# All tunable thresholds live here — change them without touching logic
# ══════════════════════════════════════════════════════════════════════

class AlertConfig:
    """Central configuration for the alert services layer."""

    # ── Thresholds ────────────────────────────────────────────────────
    BRUTE_FORCE_HITS        = 10      # hits from one IP within BRUTE_FORCE_WINDOW
    BRUTE_FORCE_WINDOW_MIN  = 10      # minutes
    CRED_PROBE_HITS         = 5       # credential probes before alert
    CRED_PROBE_WINDOW_MIN   = 5
    CRITICAL_REPEAT_COUNT   = 3       # criticals from one IP within CRITICAL_REPEAT_HOURS
    CRITICAL_REPEAT_HOURS   = 1
    DDOS_HITS_PER_MIN       = 200     # hits/min from one IP = DDoS
    SCANNER_PATHS           = 15      # distinct paths from one IP = scanner
    SCANNER_WINDOW_MIN      = 10
    HIGH_RISK_SCORE         = 70      # risk score threshold for system alert
    AUTO_BLOCK_ON_CRITICAL  = True    # auto-block IPs with 3+ criticals
    AUTO_BLOCK_ON_DDOS      = True    # auto-block DDoS sources

    # ── Escalation ────────────────────────────────────────────────────
    ESCALATE_AFTER_MIN      = 15      # escalate unresolved High+ after N minutes
    ESCALATE_CRITICAL_MIN   = 5       # faster escalation for Critical

    # ── Throttle ─────────────────────────────────────────────────────
    THROTTLE_SAME_IP_MIN    = 5       # don't re-alert same IP+type within N minutes
    THROTTLE_SAME_TYPE_MIN  = 2       # don't re-alert same type from different IPs

    # ── Notification ─────────────────────────────────────────────────
    EMAIL_ENABLED           = False   # set True and fill credentials to use
    EMAIL_FROM              = os.getenv("ALERT_EMAIL_FROM", "honeyshield@yourdomain.com")
    EMAIL_TO                = os.getenv("ALERT_EMAIL_TO",   "admin@yourdomain.com")
    EMAIL_SMTP_HOST         = os.getenv("SMTP_HOST",        "smtp.gmail.com")
    EMAIL_SMTP_PORT         = int(os.getenv("SMTP_PORT",    "587"))
    EMAIL_PASSWORD          = os.getenv("SMTP_PASSWORD",    "")

    WEBHOOK_ENABLED         = False   # set True and fill URL for Slack / Teams / Discord
    WEBHOOK_URL             = os.getenv("ALERT_WEBHOOK_URL", "")

    CONSOLE_ENABLED         = True    # always log to console

    # ── Scheduler ────────────────────────────────────────────────────
    SCHEDULER_INTERVAL_SEC  = 30      # how often background jobs run


# ══════════════════════════════════════════════════════════════════════
# 1. ALERT RULE — defines a single detection rule
# ══════════════════════════════════════════════════════════════════════

class AlertRule:
    """
    A single detection rule with an ID, human label,
    severity level, and an evaluation function.
    """

    def __init__(self, rule_id: str, name: str, severity: str,
                 threat_type: str, description: str, enabled: bool = True):
        self.rule_id     = rule_id
        self.name        = name
        self.severity    = severity       # critical / high / medium / low
        self.threat_type = threat_type
        self.description = description
        self.enabled     = enabled

    def to_dict(self) -> dict:
        return {
            "rule_id":     self.rule_id,
            "name":        self.name,
            "severity":    self.severity,
            "threat_type": self.threat_type,
            "description": self.description,
            "enabled":     self.enabled,
        }


# ── Rule Registry ─────────────────────────────────────────────────────
ALERT_RULES: dict[str, AlertRule] = {

    "R001": AlertRule(
        "R001", "Critical Threat Detected", "critical", "Any",
        "Fires immediately when any single event is classified as Critical severity.",
    ),
    "R002": AlertRule(
        "R002", "Brute Force Attack", "high", "Brute Force",
        f"Same IP makes {AlertConfig.BRUTE_FORCE_HITS}+ requests "
        f"within {AlertConfig.BRUTE_FORCE_WINDOW_MIN} minutes.",
    ),
    "R003": AlertRule(
        "R003", "Credential Stuffing", "high", "Credential Probe",
        f"Same IP hits authentication endpoints {AlertConfig.CRED_PROBE_HITS}+ times "
        f"in {AlertConfig.CRED_PROBE_WINDOW_MIN} minutes.",
    ),
    "R004": AlertRule(
        "R004", "Persistent Attacker", "critical", "Persistent Attack",
        f"Same IP triggers {AlertConfig.CRITICAL_REPEAT_COUNT}+ critical events "
        f"within {AlertConfig.CRITICAL_REPEAT_HOURS} hour(s). Auto-block triggered.",
    ),
    "R005": AlertRule(
        "R005", "DDoS / Flood Detected", "critical", "DDoS",
        f"Single IP exceeds {AlertConfig.DDOS_HITS_PER_MIN} requests/minute.",
    ),
    "R006": AlertRule(
        "R006", "Automated Scanner", "medium", "Scanner Probe",
        f"Single IP probes {AlertConfig.SCANNER_PATHS}+ distinct paths "
        f"in {AlertConfig.SCANNER_WINDOW_MIN} minutes.",
    ),
    "R007": AlertRule(
        "R007", "SQL Injection Attempt", "critical", "SQL Injection",
        "Event payload contains SQL injection patterns (UNION SELECT, DROP TABLE, etc.).",
    ),
    "R008": AlertRule(
        "R008", "Remote Code Execution", "critical", "Shell Probe",
        "Event payload contains shell/RCE patterns (wget, bash, exec).",
    ),
    "R009": AlertRule(
        "R009", "Path Traversal", "critical", "Path Traversal",
        "Request path contains directory traversal sequences (../../).",
    ),
    "R010": AlertRule(
        "R010", "XSS Injection", "high", "XSS Attempt",
        "Payload contains cross-site scripting patterns (<script>, onerror, javascript:).",
    ),
    "R011": AlertRule(
        "R011", "High Risk Score", "high", "System",
        f"Overall system risk score exceeds {AlertConfig.HIGH_RISK_SCORE}/100.",
    ),
    "R012": AlertRule(
        "R012", "New Country Detected", "low", "Recon",
        "Intrusion attempt from a country not seen before in this session.",
    ),
    "R013": AlertRule(
        "R013", "SSH Honeypot Hit", "medium", "SSH Probe",
        "A connection was made to the SSH honeypot listener.",
    ),
    "R014": AlertRule(
        "R014", "Sensitive Path Access", "high", "Scanner Probe",
        "Access attempt to sensitive paths: /.env, /.git, /backup, /phpinfo.",
    ),
    "R015": AlertRule(
        "R015", "After-Hours Activity", "medium", "Behavioral",
        "Intrusion events detected outside business hours (22:00–06:00 UTC).",
    ),
}


# ══════════════════════════════════════════════════════════════════════
# 2. ALERT THROTTLE — prevents duplicate / spam alerts
# ══════════════════════════════════════════════════════════════════════

class AlertThrottle:
    """
    In-memory throttle cache.
    Stores (ip+rule_id → last_alert_time) to suppress duplicates.
    """

    _cache: dict[str, datetime] = {}
    _lock  = threading.Lock()

    @classmethod
    def is_throttled(cls, key: str, window_minutes: int) -> bool:
        """Return True if this key was already alerted within the window."""
        with cls._lock:
            last = cls._cache.get(key)
            if last and datetime.utcnow() - last < timedelta(minutes=window_minutes):
                return True
            return False

    @classmethod
    def record(cls, key: str):
        """Record that we just fired an alert for this key."""
        with cls._lock:
            cls._cache[key] = datetime.utcnow()

    @classmethod
    def clear_expired(cls, max_age_minutes: int = 60):
        """Housekeeping — remove old entries from the cache."""
        cutoff = datetime.utcnow() - timedelta(minutes=max_age_minutes)
        with cls._lock:
            cls._cache = {k: v for k, v in cls._cache.items() if v > cutoff}


# ══════════════════════════════════════════════════════════════════════
# 3. ALERT NOTIFIER — delivers alerts through configured channels
# ══════════════════════════════════════════════════════════════════════

class AlertNotifier:
    """
    Dispatches alert notifications through:
      - Console (always on)
      - Email  (SMTP — configure AlertConfig)
      - Webhook (Slack / Teams / Discord — configure AlertConfig)
    """

    SEV_EMOJI = {
        "critical": "🚨",
        "high":     "⚠️",
        "medium":   "🔶",
        "low":      "🔵",
    }

    @classmethod
    def notify(cls, alert: Alert):
        """Send notifications through all enabled channels."""
        if AlertConfig.CONSOLE_ENABLED:
            cls._console(alert)
        if AlertConfig.EMAIL_ENABLED:
            cls._email(alert)
        if AlertConfig.WEBHOOK_ENABLED and AlertConfig.WEBHOOK_URL:
            cls._webhook(alert)

    @classmethod
    def _console(cls, alert: Alert):
        """Print structured alert to console / log."""
        emoji = cls.SEV_EMOJI.get(alert.severity, "🔔")
        log.warning(
            f"{emoji} ALERT [{alert.severity.upper()}] "
            f"Rule: {alert.threat_type} | "
            f"IP: {alert.ip_address or 'N/A'} | "
            f"{alert.title}"
        )

    @classmethod
    def _email(cls, alert: Alert):
        """Send alert via SMTP email."""
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[HoneyShield] {alert.severity.upper()} — {alert.title}"
            msg["From"]    = AlertConfig.EMAIL_FROM
            msg["To"]      = AlertConfig.EMAIL_TO

            html_body = f"""
            <html><body style="font-family:sans-serif;background:#0f1117;color:#e2e8f0;padding:24px;">
              <h2 style="color:#f87171;">🚨 HoneyShield Alert</h2>
              <table style="border-collapse:collapse;width:100%;max-width:600px;">
                <tr><td style="padding:8px;color:#64748b;width:140px;">Severity</td>
                    <td style="padding:8px;font-weight:bold;color:#f87171;">{alert.severity.upper()}</td></tr>
                <tr><td style="padding:8px;color:#64748b;">Title</td>
                    <td style="padding:8px;">{alert.title}</td></tr>
                <tr><td style="padding:8px;color:#64748b;">Threat Type</td>
                    <td style="padding:8px;">{alert.threat_type}</td></tr>
                <tr><td style="padding:8px;color:#64748b;">Source IP</td>
                    <td style="padding:8px;font-family:monospace;">{alert.ip_address or 'N/A'}</td></tr>
                <tr><td style="padding:8px;color:#64748b;">Description</td>
                    <td style="padding:8px;">{alert.description}</td></tr>
                <tr><td style="padding:8px;color:#64748b;">Timestamp</td>
                    <td style="padding:8px;">{alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')} UTC</td></tr>
              </table>
              <p style="margin-top:16px;color:#475569;font-size:12px;">
                HoneyShield Intrusion Detection System
              </p>
            </body></html>
            """

            msg.attach(MIMEText(html_body, "html"))

            with smtplib.SMTP(AlertConfig.EMAIL_SMTP_HOST, AlertConfig.EMAIL_SMTP_PORT) as server:
                server.starttls()
                server.login(AlertConfig.EMAIL_FROM, AlertConfig.EMAIL_PASSWORD)
                server.sendmail(AlertConfig.EMAIL_FROM, AlertConfig.EMAIL_TO, msg.as_string())

            log.info(f"[EMAIL] Alert sent to {AlertConfig.EMAIL_TO}")

        except Exception as e:
            log.error(f"[EMAIL] Failed to send alert email: {e}")

    @classmethod
    def _webhook(cls, alert: Alert):
        """
        POST alert to a Slack / Teams / Discord compatible webhook.
        Slack format — works with Slack Incoming Webhooks out of the box.
        """
        color_map = {"critical": "#f87171", "high": "#fb923c", "medium": "#fbbf24", "low": "#4ade80"}
        color     = color_map.get(alert.severity, "#94a3b8")
        emoji     = cls.SEV_EMOJI.get(alert.severity, "🔔")

        payload = {
            "text": f"{emoji} *HoneyShield Alert — {alert.severity.upper()}*",
            "attachments": [{
                "color": color,
                "fields": [
                    {"title": "Title",       "value": alert.title,                        "short": False},
                    {"title": "Threat Type", "value": alert.threat_type or "N/A",         "short": True},
                    {"title": "Source IP",   "value": alert.ip_address  or "N/A",         "short": True},
                    {"title": "Description", "value": alert.description or "",            "short": False},
                    {"title": "Timestamp",   "value": alert.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"), "short": True},
                ],
                "footer": "HoneyShield IDS",
            }],
        }

        try:
            resp = http_requests.post(
                AlertConfig.WEBHOOK_URL,
                json=payload,
                timeout=5,
            )
            resp.raise_for_status()
            log.info(f"[WEBHOOK] Alert delivered (HTTP {resp.status_code})")
        except Exception as e:
            log.error(f"[WEBHOOK] Delivery failed: {e}")


# ══════════════════════════════════════════════════════════════════════
# 4. ALERT ENGINE — evaluates every intrusion log against all rules
# ══════════════════════════════════════════════════════════════════════

class AlertEngine:
    """
    Core rule evaluation engine.
    Call AlertEngine.evaluate(log) after every IntrusionLog is written.
    Each rule check is independent — multiple rules can fire per event.
    """

    # Sensitive paths that trigger R014
    SENSITIVE_PATHS = ["/.env", "/.git", "/backup", "/phpinfo", "/config.php",
                       "/wp-config", "/.htaccess", "/server-status"]

    # Countries seen this session (for R012 new-country detection)
    _seen_countries: set = set()
    _lock = threading.Lock()

    @classmethod
    def evaluate(cls, intrusion_log: IntrusionLog):
        """
        Evaluate all enabled rules against the given intrusion log.
        Creates Alert records and sends notifications for any that fire.
        """
        for rule_id, rule in ALERT_RULES.items():
            if not rule.enabled:
                continue
            try:
                cls._check_rule(rule, intrusion_log)
            except Exception as exc:
                log.error(f"[ENGINE] Rule {rule_id} check failed: {exc}")

    @classmethod
    def _fire(cls, rule: AlertRule, intrusion_log: IntrusionLog,
              title: str, description: str, throttle_key: str,
              throttle_minutes: int = AlertConfig.THROTTLE_SAME_IP_MIN):
        """
        Internal: Create alert record + notify if not throttled.
        """
        if AlertThrottle.is_throttled(throttle_key, throttle_minutes):
            log.debug(f"[ENGINE] Rule {rule.rule_id} throttled for key={throttle_key}")
            return

        alert_data = {
            "title":       title,
            "description": description,
            "ip_address":  intrusion_log.ip_address,
            "severity":    rule.severity,
            "threat_type": rule.threat_type,
        }
        alert = DatabaseManager.insert_alert(alert_data)
        AlertThrottle.record(throttle_key)
        AlertNotifier.notify(alert)
        log.info(f"[ENGINE] Fired rule {rule.rule_id} — {title}")

    @classmethod
    def _check_rule(cls, rule: AlertRule, l: IntrusionLog):
        """Dispatch to the correct check method for this rule."""
        dispatch = {
            "R001": cls._r001_critical_threat,
            "R002": cls._r002_brute_force,
            "R003": cls._r003_credential_stuffing,
            "R004": cls._r004_persistent_attacker,
            "R005": cls._r005_ddos,
            "R006": cls._r006_scanner,
            "R007": cls._r007_sqli,
            "R008": cls._r008_rce,
            "R009": cls._r009_path_traversal,
            "R010": cls._r010_xss,
            "R011": cls._r011_risk_score,
            "R012": cls._r012_new_country,
            "R013": cls._r013_ssh_honeypot,
            "R014": cls._r014_sensitive_path,
            "R015": cls._r015_after_hours,
        }
        fn = dispatch.get(rule.rule_id)
        if fn:
            fn(rule, l)

    # ── Individual Rule Implementations ─────────────────────────────

    @classmethod
    def _r001_critical_threat(cls, rule, l):
        """R001 — any Critical severity event."""
        if l.severity != "critical":
            return
        cls._fire(
            rule, l,
            title=f"Critical threat — {l.threat_type}",
            description=(
                f"IP {l.ip_address} triggered a Critical event ({l.threat_type}) "
                f"on path '{l.path}'. Action taken: {l.action_taken}."
            ),
            throttle_key=f"R001:{l.ip_address}:{l.threat_type}",
            throttle_minutes=AlertConfig.THROTTLE_SAME_IP_MIN,
        )

    @classmethod
    def _r002_brute_force(cls, rule, l):
        """R002 — N+ hits from same IP within window."""
        window = datetime.utcnow() - timedelta(minutes=AlertConfig.BRUTE_FORCE_WINDOW_MIN)
        count  = IntrusionLog.query.filter(
            IntrusionLog.ip_address == l.ip_address,
            IntrusionLog.timestamp  >= window,
        ).count()
        if count < AlertConfig.BRUTE_FORCE_HITS:
            return
        cls._fire(
            rule, l,
            title=f"Brute force detected — {l.ip_address}",
            description=(
                f"IP {l.ip_address} made {count} requests in the last "
                f"{AlertConfig.BRUTE_FORCE_WINDOW_MIN} minutes. "
                f"Possible automated brute-force or credential stuffing attack."
            ),
            throttle_key=f"R002:{l.ip_address}",
            throttle_minutes=AlertConfig.THROTTLE_SAME_IP_MIN,
        )

    @classmethod
    def _r003_credential_stuffing(cls, rule, l):
        """R003 — repeated credential probes from same IP."""
        if l.threat_type != "Credential Probe":
            return
        window = datetime.utcnow() - timedelta(minutes=AlertConfig.CRED_PROBE_WINDOW_MIN)
        count  = IntrusionLog.query.filter(
            IntrusionLog.ip_address  == l.ip_address,
            IntrusionLog.threat_type == "Credential Probe",
            IntrusionLog.timestamp   >= window,
        ).count()
        if count < AlertConfig.CRED_PROBE_HITS:
            return
        cls._fire(
            rule, l,
            title=f"Credential stuffing — {l.ip_address}",
            description=(
                f"IP {l.ip_address} probed authentication endpoints {count} times "
                f"in {AlertConfig.CRED_PROBE_WINDOW_MIN} minutes. "
                f"Recommend blocking and enabling CAPTCHA."
            ),
            throttle_key=f"R003:{l.ip_address}",
            throttle_minutes=AlertConfig.THROTTLE_SAME_IP_MIN,
        )

    @classmethod
    def _r004_persistent_attacker(cls, rule, l):
        """R004 — 3+ criticals from same IP within 1 hour → auto-block."""
        window = datetime.utcnow() - timedelta(hours=AlertConfig.CRITICAL_REPEAT_HOURS)
        count  = IntrusionLog.query.filter(
            IntrusionLog.ip_address == l.ip_address,
            IntrusionLog.severity   == "critical",
            IntrusionLog.timestamp  >= window,
        ).count()
        if count < AlertConfig.CRITICAL_REPEAT_COUNT:
            return
        if AlertConfig.AUTO_BLOCK_ON_CRITICAL:
            DatabaseManager.block_ip(
                l.ip_address,
                reason=f"Auto-blocked: {count} critical events in {AlertConfig.CRITICAL_REPEAT_HOURS}h",
                by="system",
            )
        cls._fire(
            rule, l,
            title=f"Persistent attacker auto-blocked — {l.ip_address}",
            description=(
                f"IP {l.ip_address} triggered {count} critical events in the last "
                f"{AlertConfig.CRITICAL_REPEAT_HOURS} hour(s). "
                f"IP has been {'automatically blocked' if AlertConfig.AUTO_BLOCK_ON_CRITICAL else 'flagged'}."
            ),
            throttle_key=f"R004:{l.ip_address}",
            throttle_minutes=60,
        )

    @classmethod
    def _r005_ddos(cls, rule, l):
        """R005 — DDoS: N+ hits from one IP in last 1 minute."""
        window = datetime.utcnow() - timedelta(minutes=1)
        count  = IntrusionLog.query.filter(
            IntrusionLog.ip_address == l.ip_address,
            IntrusionLog.timestamp  >= window,
        ).count()
        if count < AlertConfig.DDOS_HITS_PER_MIN:
            return
        if AlertConfig.AUTO_BLOCK_ON_DDOS:
            DatabaseManager.block_ip(
                l.ip_address,
                reason=f"Auto-blocked: DDoS — {count} req/min",
                by="system",
            )
        cls._fire(
            rule, l,
            title=f"DDoS flood — {l.ip_address}",
            description=(
                f"IP {l.ip_address} sent {count} requests in 1 minute "
                f"({count} req/min). DDoS mitigation triggered. "
                f"IP auto-blocked: {AlertConfig.AUTO_BLOCK_ON_DDOS}."
            ),
            throttle_key=f"R005:{l.ip_address}",
            throttle_minutes=10,
        )

    @classmethod
    def _r006_scanner(cls, rule, l):
        """R006 — automated scanner: N+ distinct paths in window."""
        window = datetime.utcnow() - timedelta(minutes=AlertConfig.SCANNER_WINDOW_MIN)
        paths  = db.session.query(IntrusionLog.path).filter(
            IntrusionLog.ip_address == l.ip_address,
            IntrusionLog.timestamp  >= window,
        ).distinct().count()
        if paths < AlertConfig.SCANNER_PATHS:
            return
        cls._fire(
            rule, l,
            title=f"Automated scanner — {l.ip_address}",
            description=(
                f"IP {l.ip_address} probed {paths} distinct paths in "
                f"{AlertConfig.SCANNER_WINDOW_MIN} minutes. "
                f"Consistent with an automated vulnerability scanner."
            ),
            throttle_key=f"R006:{l.ip_address}",
            throttle_minutes=AlertConfig.SCANNER_WINDOW_MIN,
        )

    @classmethod
    def _r007_sqli(cls, rule, l):
        """R007 — SQL injection payload detected."""
        if l.threat_type != "SQL Injection":
            return
        cls._fire(
            rule, l,
            title=f"SQL injection — {l.ip_address}",
            description=(
                f"IP {l.ip_address} sent an SQL injection payload targeting '{l.path}'. "
                f"WAF intercept status: {l.action_taken}."
            ),
            throttle_key=f"R007:{l.ip_address}",
            throttle_minutes=AlertConfig.THROTTLE_SAME_IP_MIN,
        )

    @classmethod
    def _r008_rce(cls, rule, l):
        """R008 — remote code execution / shell probe."""
        if l.threat_type != "Shell Probe":
            return
        cls._fire(
            rule, l,
            title=f"RCE / shell probe — {l.ip_address}",
            description=(
                f"IP {l.ip_address} attempted remote code execution on '{l.path}'. "
                f"Payload contains shell command signatures. Action: {l.action_taken}."
            ),
            throttle_key=f"R008:{l.ip_address}",
            throttle_minutes=AlertConfig.THROTTLE_SAME_IP_MIN,
        )

    @classmethod
    def _r009_path_traversal(cls, rule, l):
        """R009 — path traversal / LFI attempt."""
        if l.threat_type != "Path Traversal":
            return
        cls._fire(
            rule, l,
            title=f"Path traversal — {l.ip_address}",
            description=(
                f"IP {l.ip_address} attempted directory traversal on '{l.path}'. "
                f"Request pattern matches LFI / path traversal attack."
            ),
            throttle_key=f"R009:{l.ip_address}",
            throttle_minutes=AlertConfig.THROTTLE_SAME_IP_MIN,
        )

    @classmethod
    def _r010_xss(cls, rule, l):
        """R010 — XSS payload."""
        if l.threat_type != "XSS Attempt":
            return
        cls._fire(
            rule, l,
            title=f"XSS injection — {l.ip_address}",
            description=(
                f"IP {l.ip_address} injected a cross-site scripting payload on '{l.path}'. "
                f"Input sanitization status: {l.action_taken}."
            ),
            throttle_key=f"R010:{l.ip_address}",
            throttle_minutes=AlertConfig.THROTTLE_SAME_IP_MIN,
        )

    @classmethod
    def _r011_risk_score(cls, rule, l):
        """R011 — overall risk score exceeded threshold."""
        # Compute a quick inline risk score
        since  = datetime.utcnow() - timedelta(hours=24)
        logs   = IntrusionLog.query.filter(IntrusionLog.timestamp >= since).all()
        total  = len(logs)
        if total == 0:
            return
        crits   = sum(1 for x in logs if x.severity == "critical")
        unique  = len({x.ip_address for x in logs})
        blocked = sum(1 for x in logs if x.is_blocked)
        score   = int(
            min(crits / max(total, 1) * 100, 100) * 0.40 +
            min(unique / 50, 1)                  * 100 * 0.25 +
            min(total / 200, 1)                  * 100 * 0.20 +
            (1 - blocked / max(total, 1))         * 100 * 0.15
        )
        if score < AlertConfig.HIGH_RISK_SCORE:
            return
        cls._fire(
            rule, l,
            title=f"System risk score elevated — {score}/100",
            description=(
                f"The overall HoneyShield risk score has reached {score}/100 "
                f"(threshold: {AlertConfig.HIGH_RISK_SCORE}). "
                f"Review active attacks and consider tightening firewall rules."
            ),
            throttle_key="R011:system",
            throttle_minutes=30,
        )

    @classmethod
    def _r012_new_country(cls, rule, l):
        """R012 — intrusion from a previously unseen country."""
        country = l.country or "Unknown"
        if country == "Unknown":
            return
        with cls._lock:
            if country in cls._seen_countries:
                return
            cls._seen_countries.add(country)
        cls._fire(
            rule, l,
            title=f"New source country — {country}",
            description=(
                f"First intrusion attempt from {country} detected this session. "
                f"IP: {l.ip_address}. Threat: {l.threat_type}."
            ),
            throttle_key=f"R012:{country}",
            throttle_minutes=60,
        )

    @classmethod
    def _r013_ssh_honeypot(cls, rule, l):
        """R013 — SSH honeypot connection."""
        if l.service != "SSH":
            return
        cls._fire(
            rule, l,
            title=f"SSH honeypot hit — {l.ip_address}",
            description=(
                f"IP {l.ip_address} connected to the SSH honeypot listener. "
                f"Fake banner delivered. Attacker behavior being logged."
            ),
            throttle_key=f"R013:{l.ip_address}",
            throttle_minutes=15,
        )

    @classmethod
    def _r014_sensitive_path(cls, rule, l):
        """R014 — access to sensitive paths."""
        path = (l.path or "").lower()
        if not any(s in path for s in cls.SENSITIVE_PATHS):
            return
        cls._fire(
            rule, l,
            title=f"Sensitive path probe — {l.ip_address}",
            description=(
                f"IP {l.ip_address} attempted to access '{l.path}'. "
                f"This path may expose configuration or secrets."
            ),
            throttle_key=f"R014:{l.ip_address}:{l.path}",
            throttle_minutes=AlertConfig.THROTTLE_SAME_IP_MIN,
        )

    @classmethod
    def _r015_after_hours(cls, rule, l):
        """R015 — activity outside business hours (22:00–06:00 UTC)."""
        hour = l.timestamp.hour
        if not (hour >= 22 or hour < 6):
            return
        cls._fire(
            rule, l,
            title=f"After-hours intrusion — {l.ip_address}",
            description=(
                f"Intrusion event at {l.timestamp.strftime('%H:%M')} UTC "
                f"(outside 06:00–22:00 business window). "
                f"Threat: {l.threat_type} on '{l.path}'."
            ),
            throttle_key=f"R015:{l.ip_address}:{hour}",
            throttle_minutes=60,
        )


# ══════════════════════════════════════════════════════════════════════
# 5. ALERT ESCALATION — escalates unresolved alerts over time
# ══════════════════════════════════════════════════════════════════════

class AlertEscalation:
    """
    Periodically checks for unresolved High/Critical alerts
    that have not been acknowledged and escalates them.
    """

    @staticmethod
    def run():
        """
        Called by the scheduler every N seconds.
        Escalates alerts that have been open too long.
        """
        now = datetime.utcnow()

        # Escalate unread Critical alerts after ESCALATE_CRITICAL_MIN
        crit_cutoff = now - timedelta(minutes=AlertConfig.ESCALATE_CRITICAL_MIN)
        unread_crits = Alert.query.filter(
            Alert.severity    == "critical",
            Alert.is_read     == False,
            Alert.is_resolved == False,
            Alert.timestamp   <= crit_cutoff,
        ).all()

        for alert in unread_crits:
            age_min = int((now - alert.timestamp).total_seconds() / 60)
            throttle_key = f"ESC:crit:{alert.id}"
            if not AlertThrottle.is_throttled(throttle_key, 10):
                escalation = Alert(
                    title=f"[ESCALATED] {alert.title}",
                    description=(
                        f"Original alert #{alert.id} has been unacknowledged for {age_min} minutes. "
                        f"Immediate action required. IP: {alert.ip_address}."
                    ),
                    ip_address=alert.ip_address,
                    severity="critical",
                    threat_type=alert.threat_type,
                )
                db.session.add(escalation)
                db.session.commit()
                AlertNotifier.notify(escalation)
                AlertThrottle.record(throttle_key)
                log.warning(f"[ESCALATION] Alert #{alert.id} escalated after {age_min} min unacknowledged.")

        # Escalate unread High alerts after ESCALATE_AFTER_MIN
        high_cutoff = now - timedelta(minutes=AlertConfig.ESCALATE_AFTER_MIN)
        unread_highs = Alert.query.filter(
            Alert.severity    == "high",
            Alert.is_read     == False,
            Alert.is_resolved == False,
            Alert.timestamp   <= high_cutoff,
        ).all()

        for alert in unread_highs:
            age_min = int((now - alert.timestamp).total_seconds() / 60)
            throttle_key = f"ESC:high:{alert.id}"
            if not AlertThrottle.is_throttled(throttle_key, 20):
                escalation = Alert(
                    title=f"[ESCALATED] {alert.title}",
                    description=(
                        f"High-severity alert #{alert.id} unacknowledged for {age_min} minutes. "
                        f"IP: {alert.ip_address}."
                    ),
                    ip_address=alert.ip_address,
                    severity="high",
                    threat_type=alert.threat_type,
                )
                db.session.add(escalation)
                db.session.commit()
                AlertNotifier.notify(escalation)
                AlertThrottle.record(throttle_key)
                log.warning(f"[ESCALATION] High alert #{alert.id} escalated after {age_min} min.")


# ══════════════════════════════════════════════════════════════════════
# 6. ALERT SCHEDULER — background thread for periodic checks
# ══════════════════════════════════════════════════════════════════════

class AlertScheduler:
    """
    Runs background jobs every N seconds:
      - AlertEscalation.run()
      - AlertThrottle.clear_expired()
    """

    _thread: threading.Thread = None
    _running: bool = False

    @classmethod
    def start(cls, flask_app):
        """Start the scheduler thread. Pass the Flask app for app context."""
        if cls._running:
            return
        cls._running = True

        def _loop():
            log.info("[SCHEDULER] Background alert scheduler started.")
            while cls._running:
                try:
                    with flask_app.app_context():
                        AlertEscalation.run()
                        AlertThrottle.clear_expired()
                except Exception as exc:
                    log.error(f"[SCHEDULER] Error in background job: {exc}")
                time.sleep(AlertConfig.SCHEDULER_INTERVAL_SEC)

        cls._thread = threading.Thread(target=_loop, daemon=True, name="AlertScheduler")
        cls._thread.start()

    @classmethod
    def stop(cls):
        cls._running = False
        log.info("[SCHEDULER] Stopped.")


# ══════════════════════════════════════════════════════════════════════
# 7. ALERT STATS — statistics for the alerts dashboard page
# ══════════════════════════════════════════════════════════════════════

class AlertStats:
    """
    Computes statistics consumed by the /alerts dashboard.
    """

    @staticmethod
    def summary() -> dict:
        """Overall alert counts by severity and status."""
        all_alerts = Alert.query.all()
        total      = len(all_alerts)
        unread     = sum(1 for a in all_alerts if not a.is_read)
        resolved   = sum(1 for a in all_alerts if a.is_resolved)

        by_severity = Counter(a.severity for a in all_alerts)

        return {
            "total":    total,
            "unread":   unread,
            "resolved": resolved,
            "open":     total - resolved,
            "by_severity": {
                "critical": by_severity.get("critical", 0),
                "high":     by_severity.get("high",     0),
                "medium":   by_severity.get("medium",   0),
                "low":      by_severity.get("low",      0),
            },
        }

    @staticmethod
    def by_hour(hours: int = 24) -> list:
        """Alert counts bucketed by hour for the last N hours."""
        since   = datetime.utcnow() - timedelta(hours=hours)
        alerts  = Alert.query.filter(Alert.timestamp >= since).all()
        buckets = defaultdict(int)
        for a in alerts:
            buckets[a.timestamp.strftime("%H:00")] += 1
        return [{"hour": h, "count": c} for h, c in sorted(buckets.items())]

    @staticmethod
    def top_offending_ips(limit: int = 10) -> list:
        """IPs that generated the most alerts."""
        alerts     = Alert.query.filter(Alert.ip_address.isnot(None)).all()
        ip_counter = Counter(a.ip_address for a in alerts)
        return [{"ip": ip, "count": c} for ip, c in ip_counter.most_common(limit)]

    @staticmethod
    def recent(limit: int = 50) -> list:
        """Most recent alerts (all fields) for the feed."""
        alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(limit).all()
        return [a.to_dict() for a in alerts]

    @staticmethod
    def rule_hit_counts() -> list:
        """How many times each threat type has triggered an alert."""
        alerts       = Alert.query.all()
        type_counter = Counter(a.threat_type or "Unknown" for a in alerts)
        result = []
        for rule in ALERT_RULES.values():
            count = type_counter.get(rule.threat_type, 0)
            result.append({**rule.to_dict(), "hit_count": count})
        return result


# ══════════════════════════════════════════════════════════════════════
# 8. ALERT SERVICE — unified facade used by all Flask routes
# ══════════════════════════════════════════════════════════════════════

class AlertService:
    """
    High-level service facade.
    All Flask route handlers and external callers use this class.
    """

    @staticmethod
    def process_intrusion(intrusion_log: IntrusionLog):
        """
        Main entry point: evaluate a freshly logged intrusion
        against all alert rules. Call this from IntrusionLogger.
        """
        AlertEngine.evaluate(intrusion_log)

    @staticmethod
    def get_all_alerts(page: int = 1, per_page: int = 20,
                       severity: str = None, is_read: bool = None,
                       threat_type: str = None) -> dict:
        """Paginated, filtered alert list."""
        q = Alert.query.order_by(Alert.timestamp.desc())
        if severity:
            q = q.filter(Alert.severity == severity)
        if is_read is not None:
            q = q.filter(Alert.is_read == is_read)
        if threat_type:
            q = q.filter(Alert.threat_type == threat_type)
        paginated = q.paginate(page=page, per_page=per_page, error_out=False)
        return {
            "total":   paginated.total,
            "page":    paginated.page,
            "pages":   paginated.pages,
            "alerts":  [a.to_dict() for a in paginated.items],
        }

    @staticmethod
    def get_alert(alert_id: int) -> dict | None:
        a = Alert.query.get(alert_id)
        return a.to_dict() if a else None

    @staticmethod
    def mark_read(alert_id: int) -> bool:
        a = Alert.query.get(alert_id)
        if not a:
            return False
        a.is_read = True
        db.session.commit()
        return True

    @staticmethod
    def mark_all_read():
        Alert.query.filter_by(is_read=False).update({"is_read": True})
        db.session.commit()

    @staticmethod
    def resolve(alert_id: int) -> bool:
        a = Alert.query.get(alert_id)
        if not a:
            return False
        a.is_resolved = True
        a.is_read     = True
        db.session.commit()
        return True

    @staticmethod
    def resolve_all():
        Alert.query.update({"is_resolved": True, "is_read": True})
        db.session.commit()

    @staticmethod
    def delete(alert_id: int) -> bool:
        a = Alert.query.get(alert_id)
        if not a:
            return False
        db.session.delete(a)
        db.session.commit()
        return True

    @staticmethod
    def clear_all():
        Alert.query.delete()
        db.session.commit()

    @staticmethod
    def get_rules() -> list:
        return [r.to_dict() for r in ALERT_RULES.values()]

    @staticmethod
    def toggle_rule(rule_id: str, enabled: bool) -> bool:
        rule = ALERT_RULES.get(rule_id)
        if not rule:
            return False
        rule.enabled = enabled
        log.info(f"[SERVICE] Rule {rule_id} {'enabled' if enabled else 'disabled'}.")
        return True

    @staticmethod
    def get_stats() -> dict:
        return {
            "summary":     AlertStats.summary(),
            "by_hour":     AlertStats.by_hour(),
            "top_ips":     AlertStats.top_offending_ips(),
            "rule_hits":   AlertStats.rule_hit_counts(),
        }

    @staticmethod
    def create_manual_alert(title: str, description: str,
                            severity: str, ip: str = None,
                            threat_type: str = "Manual") -> dict:
        """Allow admin to manually create an alert."""
        data = {
            "title":       title,
            "description": description,
            "ip_address":  ip,
            "severity":    severity,
            "threat_type": threat_type,
        }
        alert = DatabaseManager.insert_alert(data)
        AlertNotifier.notify(alert)
        return alert.to_dict()


# ══════════════════════════════════════════════════════════════════════
# 9. FLASK BLUEPRINT — /api/alerts/* routes
# ══════════════════════════════════════════════════════════════════════

alert_bp = Blueprint("alerts", __name__, url_prefix="/api/alerts")


@alert_bp.route("", methods=["GET"])
def api_get_alerts():
    """
    GET /api/alerts
    Query params: page, per_page, severity, is_read, threat_type
    """
    page        = request.args.get("page",        1,    type=int)
    per_page    = request.args.get("per_page",    20,   type=int)
    severity    = request.args.get("severity",    None)
    threat_type = request.args.get("threat_type", None)
    is_read_str = request.args.get("is_read",     None)
    is_read     = None
    if is_read_str is not None:
        is_read = is_read_str.lower() == "true"

    result = AlertService.get_all_alerts(
        page=page, per_page=per_page,
        severity=severity, is_read=is_read, threat_type=threat_type,
    )
    return jsonify(result)


@alert_bp.route("/recent", methods=["GET"])
def api_recent_alerts():
    """GET /api/alerts/recent — last 50 alerts for the live feed."""
    limit  = request.args.get("limit", 50, type=int)
    alerts = AlertStats.recent(limit)
    return jsonify(alerts)


@alert_bp.route("/stats", methods=["GET"])
def api_alert_stats():
    """GET /api/alerts/stats — summary counts, by-hour, top IPs, rule hits."""
    return jsonify(AlertService.get_stats())


@alert_bp.route("/unread-count", methods=["GET"])
def api_unread_count():
    """GET /api/alerts/unread-count — quick badge count for the nav."""
    count = Alert.query.filter_by(is_read=False).count()
    return jsonify({"unread": count})


@alert_bp.route("/<int:alert_id>", methods=["GET"])
def api_get_alert(alert_id):
    """GET /api/alerts/<id> — single alert detail."""
    data = AlertService.get_alert(alert_id)
    if not data:
        return jsonify({"error": "Alert not found"}), 404
    return jsonify(data)


@alert_bp.route("/<int:alert_id>/read", methods=["POST"])
def api_mark_read(alert_id):
    """POST /api/alerts/<id>/read"""
    ok = AlertService.mark_read(alert_id)
    return jsonify({"status": "ok" if ok else "not_found"})


@alert_bp.route("/mark-all-read", methods=["POST"])
def api_mark_all_read():
    """POST /api/alerts/mark-all-read"""
    AlertService.mark_all_read()
    return jsonify({"status": "ok"})


@alert_bp.route("/<int:alert_id>/resolve", methods=["POST"])
def api_resolve(alert_id):
    """POST /api/alerts/<id>/resolve"""
    ok = AlertService.resolve(alert_id)
    return jsonify({"status": "ok" if ok else "not_found"})


@alert_bp.route("/resolve-all", methods=["POST"])
def api_resolve_all():
    """POST /api/alerts/resolve-all"""
    AlertService.resolve_all()
    return jsonify({"status": "ok"})


@alert_bp.route("/<int:alert_id>", methods=["DELETE"])
def api_delete_alert(alert_id):
    """DELETE /api/alerts/<id>"""
    ok = AlertService.delete(alert_id)
    if not ok:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"status": "deleted"})


@alert_bp.route("/clear", methods=["DELETE"])
def api_clear_alerts():
    """DELETE /api/alerts/clear — wipe all alerts."""
    AlertService.clear_all()
    return jsonify({"status": "cleared"})


@alert_bp.route("/rules", methods=["GET"])
def api_get_rules():
    """GET /api/alerts/rules — list all detection rules."""
    return jsonify(AlertService.get_rules())


@alert_bp.route("/rules/<rule_id>/toggle", methods=["POST"])
def api_toggle_rule(rule_id):
    """POST /api/alerts/rules/<rule_id>/toggle  body: {"enabled": true/false}"""
    data    = request.get_json() or {}
    enabled = data.get("enabled", True)
    ok      = AlertService.toggle_rule(rule_id, enabled)
    if not ok:
        return jsonify({"error": "Rule not found"}), 404
    return jsonify({"status": "ok", "rule_id": rule_id, "enabled": enabled})


@alert_bp.route("/manual", methods=["POST"])
def api_manual_alert():
    """
    POST /api/alerts/manual
    Body: { title, description, severity, ip, threat_type }
    """
    data = request.get_json() or {}
    title       = data.get("title", "Manual alert")
    description = data.get("description", "")
    severity    = data.get("severity", "medium")
    ip          = data.get("ip")
    threat_type = data.get("threat_type", "Manual")

    if severity not in ("critical", "high", "medium", "low"):
        return jsonify({"error": "Invalid severity. Use critical/high/medium/low"}), 400

    alert = AlertService.create_manual_alert(title, description, severity, ip, threat_type)
    return jsonify(alert), 201


@alert_bp.route("/notify-test", methods=["POST"])
def api_notify_test():
    """
    POST /api/alerts/notify-test
    Sends a test notification through all enabled channels.
    """
    test_alert = Alert(
        id=0,
        timestamp=datetime.utcnow(),
        title="HoneyShield test notification",
        description="This is a test alert to verify notification channels are working correctly.",
        ip_address="127.0.0.1",
        severity="low",
        threat_type="System",
        is_read=False,
        is_resolved=False,
    )
    AlertNotifier.notify(test_alert)
    return jsonify({"status": "test notification sent"})


# ══════════════════════════════════════════════════════════════════════
# STANDALONE ENTRY POINT
# Run this file directly to test the alert service in isolation
# ══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if _STANDALONE:
        from flask import Flask as _TestFlask
        test_app = _TestFlask(__name__)
        test_app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///honeyshield_test.db"
        test_app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
        db.init_app(test_app)
        test_app.register_blueprint(alert_bp)

        with test_app.app_context():
            db.create_all()
            print("[TEST] Database tables created.")

            # Seed a fake intrusion log and run all rules
            fake_log = IntrusionLog(
                ip_address="91.134.22.87",
                port=80, service="HTTP", method="POST",
                path="/login?id=1 OR 1=1--",
                payload="' OR 1=1--",
                country="France",
                threat_type="SQL Injection",
                severity="critical",
                action_taken="Blocked",
                is_blocked=True,
                timestamp=datetime.utcnow(),
            )
            db.session.add(fake_log)
            db.session.commit()

            print("[TEST] Running AlertEngine on fake log...")
            AlertEngine.evaluate(fake_log)

            print("[TEST] Alert stats:")
            print(json.dumps(AlertStats.summary(), indent=2))

        AlertScheduler.start(test_app)

        print("[TEST] Starting Flask on http://localhost:5001")
        test_app.run(debug=True, port=5001, use_reloader=False)
