# app/models.py
"""
Models
──────
SQLAlchemy ORM models for the HoneyShield Flask application.

Tables:
  • User       – registered dashboard users (admin / analyst roles)
  • AttackLog  – every honeypot hit captured by request_capture.py

Import anywhere with:
    from app.models import User, AttackLog
"""

import json
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from app import db


# ════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════

# Valid roles — extend as needed
ROLE_ADMIN   = "admin"
ROLE_ANALYST = "analyst"
ROLE_VIEWER  = "viewer"
ALL_ROLES    = (ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER)

# Severity levels used by AttackLog
SEV_CRITICAL = "critical"
SEV_HIGH     = "high"
SEV_MEDIUM   = "medium"
SEV_LOW      = "low"
ALL_SEVERITIES = (SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW)


# ════════════════════════════════════════════════════════════════════════════
# USER MODEL
# ════════════════════════════════════════════════════════════════════════════
class User(db.Model):
    """
    Dashboard user account.

    Columns
    ───────
    id            PK
    name          Display name
    email         Unique login identifier
    password_hash Bcrypt hash (never store plain text)
    role          admin | analyst | viewer
    is_active     Soft-disable without deleting
    created_at    Account creation timestamp (UTC)
    last_login    Most recent successful login (UTC)
    """

    __tablename__ = "users"

    # ── Columns ─────────────────────────────────────────────────────────────
    id            = db.Column(db.Integer,     primary_key=True)
    name          = db.Column(db.String(100), nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role          = db.Column(db.String(20),  nullable=False, default=ROLE_VIEWER)
    is_active     = db.Column(db.Boolean,     nullable=False, default=True)
    created_at    = db.Column(db.DateTime,    nullable=False, default=datetime.utcnow)
    last_login    = db.Column(db.DateTime,    nullable=True)

    # ── Password helpers ─────────────────────────────────────────────────────
    def set_password(self, plain_text: str) -> None:
        """Hash and store the password. Call before db.session.commit()."""
        if not plain_text or len(plain_text) < 6:
            raise ValueError("Password must be at least 6 characters.")
        self.password_hash = generate_password_hash(plain_text)

    def check_password(self, plain_text: str) -> bool:
        """Return True if plain_text matches the stored hash."""
        return check_password_hash(self.password_hash, plain_text)

    # ── Role helpers ─────────────────────────────────────────────────────────
    def is_admin(self) -> bool:
        return self.role == ROLE_ADMIN

    def is_analyst(self) -> bool:
        return self.role in (ROLE_ADMIN, ROLE_ANALYST)

    def set_role(self, role: str) -> None:
        if role not in ALL_ROLES:
            raise ValueError(f"Invalid role '{role}'. Choose from: {ALL_ROLES}")
        self.role = role

    # ── Login tracking ────────────────────────────────────────────────────────
    def record_login(self) -> None:
        """Update last_login to now. Call after a successful login."""
        self.last_login = datetime.utcnow()

    # ── Serialisation ────────────────────────────────────────────────────────
    def to_dict(self) -> dict:
        """Safe dict representation (password hash excluded)."""
        return {
            "id":         self.id,
            "name":       self.name,
            "email":      self.email,
            "role":       self.role,
            "is_active":  self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
        }

    # ── Class-level finders ──────────────────────────────────────────────────
    @classmethod
    def find_by_email(cls, email: str):
        """Return the User with this email, or None."""
        return cls.query.filter_by(email=email.strip().lower()).first()

    @classmethod
    def find_by_id(cls, user_id: int):
        """Return the User with this PK, or None."""
        return cls.query.get(user_id)

    @classmethod
    def get_all_active(cls) -> list:
        """Return all accounts where is_active=True."""
        return cls.query.filter_by(is_active=True).order_by(cls.name).all()

    @classmethod
    def create(cls, name: str, email: str, password: str, role: str = ROLE_VIEWER):
        """
        Factory method — build, hash password, and return a new User.
        You still need to add + commit it yourself:
            user = User.create(...)
            db.session.add(user)
            db.session.commit()
        """
        user = cls(
            name  = name.strip(),
            email = email.strip().lower(),
            role  = role,
        )
        user.set_password(password)
        return user

    # ── Dunder ───────────────────────────────────────────────────────────────
    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email} role={self.role}>"


# ════════════════════════════════════════════════════════════════════════════
# ATTACK LOG MODEL
# ════════════════════════════════════════════════════════════════════════════
class AttackLog(db.Model):
    """
    One row per honeypot hit, written by request_capture.save_capture_to_db().

    Columns
    ───────
    id         PK
    ip         Attacker's resolved IP address
    method     HTTP method (GET / POST / etc.)
    path       Request path probed
    body       Raw / JSON request body (truncated to 500 chars)
    headers    JSON-encoded security-relevant headers
    severity   Derived severity: critical | high | medium | low
    timestamp  UTC datetime of the hit
    """

    __tablename__ = "attack_logs"

    # ── Columns ─────────────────────────────────────────────────────────────
    id        = db.Column(db.Integer,     primary_key=True)
    ip        = db.Column(db.String(50),  nullable=False, index=True)
    method    = db.Column(db.String(10),  nullable=False)
    path      = db.Column(db.String(500), nullable=False)
    body      = db.Column(db.Text,        nullable=True)
    headers   = db.Column(db.Text,        nullable=True)
    severity  = db.Column(db.String(20),  nullable=False, default=SEV_LOW, index=True)
    timestamp = db.Column(db.DateTime,    nullable=False, default=datetime.utcnow, index=True)

    # ── Parsed property helpers ───────────────────────────────────────────────
    @property
    def parsed_headers(self) -> dict:
        """Return headers column as a Python dict (safe fallback to {})."""
        try:
            return json.loads(self.headers) if self.headers else {}
        except (json.JSONDecodeError, TypeError):
            return {}

    @property
    def parsed_body(self):
        """Return body as dict if JSON, else raw string."""
        try:
            return json.loads(self.body) if self.body else ""
        except (json.JSONDecodeError, TypeError):
            return self.body or ""

    @property
    def user_agent(self) -> str:
        """Convenience: pull User-Agent from parsed headers."""
        return self.parsed_headers.get("User-Agent", "")

    # ── Severity badge helper ─────────────────────────────────────────────────
    def severity_badge_class(self) -> str:
        """
        Return a CSS class name matching your badge styles in analysis.html.
            critical → badge-red
            high     → badge-yellow
            medium   → badge-cyan
            low      → badge-green
        """
        return {
            SEV_CRITICAL: "badge-red",
            SEV_HIGH:     "badge-yellow",
            SEV_MEDIUM:   "badge-cyan",
            SEV_LOW:      "badge-green",
        }.get(self.severity, "badge-green")

    # ── Serialisation ─────────────────────────────────────────────────────────
    def to_dict(self) -> dict:
        """Flat dict safe for jsonify() and Jinja templates."""
        return {
            "id":        self.id,
            "ip":        self.ip,
            "method":    self.method,
            "path":      self.path,
            "body":      self.parsed_body,
            "headers":   self.parsed_headers,
            "severity":  self.severity,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "user_agent":self.user_agent,
            "badge_class": self.severity_badge_class(),
        }

    # ── Class-level finders ───────────────────────────────────────────────────
    @classmethod
    def find_by_ip(cls, ip: str, limit: int = 100) -> list:
        """All logs from one IP, newest first."""
        return (
            cls.query
            .filter_by(ip=ip)
            .order_by(cls.timestamp.desc())
            .limit(limit)
            .all()
        )

    @classmethod
    def recent(cls, limit: int = 50) -> list:
        """The N most recent attack log entries."""
        return cls.query.order_by(cls.timestamp.desc()).limit(limit).all()

    @classmethod
    def by_severity(cls, severity: str, limit: int = 100) -> list:
        """All logs matching a specific severity level."""
        if severity not in ALL_SEVERITIES:
            raise ValueError(f"Invalid severity. Choose from {ALL_SEVERITIES}")
        return (
            cls.query
            .filter_by(severity=severity)
            .order_by(cls.timestamp.desc())
            .limit(limit)
            .all()
        )

    @classmethod
    def create(cls, ip: str, method: str, path: str,
               body: str = "", headers: str = "", severity: str = SEV_LOW):
        """
        Factory — build and return a new AttackLog (not yet committed).
            log = AttackLog.create(...)
            db.session.add(log)
            db.session.commit()
        """
        return cls(
            ip       = ip,
            method   = method.upper(),
            path     = path,
            body     = body[:500] if body else "",
            headers  = headers[:500] if headers else "",
            severity = severity if severity in ALL_SEVERITIES else SEV_LOW,
        )

    # ── Dunder ────────────────────────────────────────────────────────────────
    def __repr__(self) -> str:
        return (
            f"<AttackLog id={self.id} ip={self.ip} "
            f"method={self.method} path={self.path} sev={self.severity}>"
        )
