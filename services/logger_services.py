# app/services/log_service.py
"""
Log Service
───────────
Centralised service layer for everything related to AttackLog records.

Responsibilities:
  • Query   – fetch, filter, paginate, search attack logs from DB
  • Analyse – aggregate stats, top IPs, threat breakdowns, hourly heatmap
  • Export  – serialise logs to dict / JSON / CSV
  • Purge   – delete old records on a rolling retention window

Import in blueprints:
    from app.services.log_service import LogService
"""

import csv
import io
import json
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Optional

# ── Threat categories (must match request_capture.THREAT_MAP keys) ──────────
THREAT_CATEGORIES = [
    "sql_injection",
    "path_traversal",
    "credential_probe",
    "secret_probe",
    "shell_probe",
    "scanner_probe",
]

SEVERITY_MAP = {
    "sql_injection":    "critical",
    "shell_probe":      "critical",
    "path_traversal":   "critical",
    "credential_probe": "high",
    "secret_probe":     "high",
    "scanner_probe":    "medium",
}


# ── Lazy imports to avoid circular references ────────────────────────────────
def _get_db_and_model():
    from app import db
    from app.models import AttackLog
    return db, AttackLog


# ════════════════════════════════════════════════════════════════════════════
# LOG SERVICE CLASS
# ════════════════════════════════════════════════════════════════════════════
class LogService:
    """
    All public methods are @staticmethod so you can call them without
    instantiating:  LogService.get_recent(limit=20)
    """

    # ────────────────────────────────────────────────────────────────────────
    # SECTION 1 — QUERIES
    # ────────────────────────────────────────────────────────────────────────

    @staticmethod
    def get_all(order: str = "desc") -> list:
        """
        Return every AttackLog row.
        order: 'asc' | 'desc'  (by timestamp)
        """
        _, AttackLog = _get_db_and_model()
        col = AttackLog.timestamp.desc() if order == "desc" else AttackLog.timestamp.asc()
        return AttackLog.query.order_by(col).all()


    @staticmethod
    def get_recent(limit: int = 50) -> list:
        """Return the N most recent attack log entries."""
        _, AttackLog = _get_db_and_model()
        return (
            AttackLog.query
            .order_by(AttackLog.timestamp.desc())
            .limit(limit)
            .all()
        )


    @staticmethod
    def get_paginated(page: int = 1, per_page: int = 25, filters: Optional[dict] = None):
        """
        Paginated query with optional filters.

        filters dict keys (all optional):
            ip          – exact IP match
            method      – GET / POST / etc.
            threat      – keyword present in 'body' or 'path'
            date_from   – datetime object
            date_to     – datetime object
            search      – free-text search across path + body + ip

        Returns Flask-SQLAlchemy Pagination object.
        Usage:
            pagination = LogService.get_paginated(page=2, filters={'ip': '1.2.3.4'})
            logs       = pagination.items
            total      = pagination.total
            pages      = pagination.pages
        """
        _, AttackLog = _get_db_and_model()
        query = AttackLog.query

        if filters:
            if filters.get("ip"):
                query = query.filter(AttackLog.ip == filters["ip"])

            if filters.get("method"):
                query = query.filter(AttackLog.method == filters["method"].upper())

            if filters.get("date_from"):
                query = query.filter(AttackLog.timestamp >= filters["date_from"])

            if filters.get("date_to"):
                query = query.filter(AttackLog.timestamp <= filters["date_to"])

            if filters.get("search"):
                term = f"%{filters['search']}%"
                query = query.filter(
                    AttackLog.path.ilike(term)  |
                    AttackLog.body.ilike(term)  |
                    AttackLog.ip.ilike(term)
                )

            if filters.get("threat"):
                term = f"%{filters['threat']}%"
                query = query.filter(
                    AttackLog.path.ilike(term) | AttackLog.body.ilike(term)
                )

        return query.order_by(AttackLog.timestamp.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )


    @staticmethod
    def get_by_id(log_id: int):
        """Return a single AttackLog by primary key, or None."""
        _, AttackLog = _get_db_and_model()
        return AttackLog.query.get(log_id)


    @staticmethod
    def get_by_ip(ip: str, limit: int = 100) -> list:
        """Return all logs from a specific IP address."""
        _, AttackLog = _get_db_and_model()
        return (
            AttackLog.query
            .filter_by(ip=ip)
            .order_by(AttackLog.timestamp.desc())
            .limit(limit)
            .all()
        )


    @staticmethod
    def get_by_date_range(date_from: datetime, date_to: datetime) -> list:
        """Return logs between two datetime objects (inclusive)."""
        _, AttackLog = _get_db_and_model()
        return (
            AttackLog.query
            .filter(AttackLog.timestamp >= date_from)
            .filter(AttackLog.timestamp <= date_to)
            .order_by(AttackLog.timestamp.desc())
            .all()
        )


    @staticmethod
    def get_last_n_hours(hours: int = 24) -> list:
        """Shortcut: logs from the last N hours."""
        since = datetime.utcnow() - timedelta(hours=hours)
        _, AttackLog = _get_db_and_model()
        return (
            AttackLog.query
            .filter(AttackLog.timestamp >= since)
            .order_by(AttackLog.timestamp.desc())
            .all()
        )


    # ────────────────────────────────────────────────────────────────────────
    # SECTION 2 — ANALYTICS
    # ────────────────────────────────────────────────────────────────────────

    @staticmethod
    def total_count() -> int:
        """Total number of logged attack events."""
        _, AttackLog = _get_db_and_model()
        return AttackLog.query.count()


    @staticmethod
    def count_last_n_hours(hours: int = 24) -> int:
        """Count events in the last N hours."""
        since = datetime.utcnow() - timedelta(hours=hours)
        _, AttackLog = _get_db_and_model()
        return AttackLog.query.filter(AttackLog.timestamp >= since).count()


    @staticmethod
    def unique_ip_count() -> int:
        """Number of distinct attacker IPs."""
        from sqlalchemy import func
        _, AttackLog = _get_db_and_model()
        return AttackLog.query.with_entities(
            func.count(func.distinct(AttackLog.ip))
        ).scalar() or 0


    @staticmethod
    def top_ips(limit: int = 10) -> list:
        """
        Return top attacking IPs sorted by hit count.

        Returns:
            [ {"ip": "1.2.3.4", "hits": 42}, ... ]
        """
        from sqlalchemy import func
        _, AttackLog = _get_db_and_model()
        rows = (
            AttackLog.query
            .with_entities(AttackLog.ip, func.count(AttackLog.id).label("hits"))
            .group_by(AttackLog.ip)
            .order_by(func.count(AttackLog.id).desc())
            .limit(limit)
            .all()
        )
        return [{"ip": r.ip, "hits": r.hits} for r in rows]


    @staticmethod
    def top_paths(limit: int = 10) -> list:
        """
        Most-probed URL paths.

        Returns:
            [ {"path": "/admin", "hits": 30}, ... ]
        """
        from sqlalchemy import func
        _, AttackLog = _get_db_and_model()
        rows = (
            AttackLog.query
            .with_entities(AttackLog.path, func.count(AttackLog.id).label("hits"))
            .group_by(AttackLog.path)
            .order_by(func.count(AttackLog.id).desc())
            .limit(limit)
            .all()
        )
        return [{"path": r.path, "hits": r.hits} for r in rows]


    @staticmethod
    def method_breakdown() -> dict:
        """
        Count of each HTTP method used by attackers.

        Returns:
            {"GET": 120, "POST": 80, "PUT": 5, ...}
        """
        from sqlalchemy import func
        _, AttackLog = _get_db_and_model()
        rows = (
            AttackLog.query
            .with_entities(AttackLog.method, func.count(AttackLog.id).label("cnt"))
            .group_by(AttackLog.method)
            .all()
        )
        return {r.method: r.cnt for r in rows}


    @staticmethod
    def threat_breakdown(logs: Optional[list] = None) -> dict:
        """
        Count how many logs match each threat category keyword.
        Pass a pre-fetched list to avoid a second DB hit, or leave
        None to fetch the last 24 h automatically.

        Returns:
            {
              "sql_injection":    61,
              "credential_probe": 79,
              ...
            }
        """
        if logs is None:
            logs = LogService.get_last_n_hours(24)

        counts = defaultdict(int)
        for log in logs:
            combined = f"{(log.path or '')} {(log.body or '')}".lower()
            for category in THREAT_CATEGORIES:
                keywords = _get_threat_keywords(category)
                if any(kw in combined for kw in keywords):
                    counts[category] += 1

        return dict(counts)


    @staticmethod
    def hourly_heatmap(hours: int = 24) -> list:
        """
        Event count bucketed by hour for the last N hours.
        Useful for rendering the 24-cell heatmap on the analysis page.

        Returns:
            [ {"hour": "00", "count": 3}, {"hour": "01", "count": 0}, ... ]
            (always 24 items, zero-filled)
        """
        logs = LogService.get_last_n_hours(hours)
        bucket = defaultdict(int)
        for log in logs:
            h = log.timestamp.strftime("%H")
            bucket[h] += 1

        return [
            {"hour": f"{i:02d}", "count": bucket.get(f"{i:02d}", 0)}
            for i in range(24)
        ]


    @staticmethod
    def daily_trend(days: int = 7) -> list:
        """
        Attack count per day for the last N days.

        Returns:
            [ {"date": "2025-04-09", "count": 45}, ... ]
        """
        since = datetime.utcnow() - timedelta(days=days)
        logs  = LogService.get_by_date_range(since, datetime.utcnow())
        bucket = defaultdict(int)
        for log in logs:
            day = log.timestamp.strftime("%Y-%m-%d")
            bucket[day] += 1

        result = []
        for i in range(days):
            d = (datetime.utcnow() - timedelta(days=days - 1 - i)).strftime("%Y-%m-%d")
            result.append({"date": d, "count": bucket.get(d, 0)})
        return result


    @staticmethod
    def severity_counts(logs: Optional[list] = None) -> dict:
        """
        Count logs bucketed by severity (critical / high / medium / low).
        Severity is derived from SEVERITY_MAP via threat category matching.

        Returns:
            {"critical": 55, "high": 45, "medium": 30, "low": 0}
        """
        if logs is None:
            logs = LogService.get_last_n_hours(24)

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for log in logs:
            sev = _classify_severity(log)
            counts[sev] += 1
        return counts


    @staticmethod
    def dashboard_summary() -> dict:
        """
        One-shot method that returns everything the analysis/dashboard
        page needs in a single dict — minimises DB round-trips.

        Returns:
            {
              "total_events":    248,
              "unique_ips":      37,
              "last_24h":        112,
              "top_ips":         [...],
              "top_paths":       [...],
              "method_breakdown":{...},
              "threat_breakdown":{...},
              "hourly_heatmap":  [...],
              "daily_trend":     [...],
              "severity_counts": {...},
              "recent_logs":     [...],   ← serialised dicts
            }
        """
        logs_24h = LogService.get_last_n_hours(24)

        return {
            "total_events":     LogService.total_count(),
            "unique_ips":       LogService.unique_ip_count(),
            "last_24h":         len(logs_24h),
            "top_ips":          LogService.top_ips(10),
            "top_paths":        LogService.top_paths(10),
            "method_breakdown": LogService.method_breakdown(),
            "threat_breakdown": LogService.threat_breakdown(logs_24h),
            "hourly_heatmap":   LogService.hourly_heatmap(24),
            "daily_trend":      LogService.daily_trend(7),
            "severity_counts":  LogService.severity_counts(logs_24h),
            "recent_logs":      [LogService.serialize(l) for l in logs_24h[:20]],
        }


    # ────────────────────────────────────────────────────────────────────────
    # SECTION 3 — SERIALISATION
    # ────────────────────────────────────────────────────────────────────────

    @staticmethod
    def serialize(log) -> dict:
        """
        Convert an AttackLog ORM object to a plain dict.
        Safe to pass to jsonify() or a Jinja template.
        """
        # Parse stored JSON fields safely
        try:
            headers = json.loads(log.headers) if log.headers else {}
        except (json.JSONDecodeError, TypeError):
            headers = {}

        try:
            body = json.loads(log.body) if log.body else ""
        except (json.JSONDecodeError, TypeError):
            body = log.body or ""

        threats  = _detect_threats(log)
        severity = _classify_severity(log)

        return {
            "id":        log.id,
            "ip":        log.ip,
            "method":    log.method,
            "path":      log.path,
            "body":      body,
            "headers":   headers,
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            "threats":   threats,
            "severity":  severity,
        }


    @staticmethod
    def serialize_many(logs: list) -> list:
        """Serialize a list of AttackLog objects."""
        return [LogService.serialize(l) for l in logs]


    @staticmethod
    def to_json(logs: list) -> str:
        """Return a JSON string from a list of AttackLog objects."""
        return json.dumps(LogService.serialize_many(logs), indent=2, default=str)


    @staticmethod
    def to_csv(logs: list) -> str:
        """
        Return a CSV string from a list of AttackLog objects.
        Columns: id, ip, method, path, threats, severity, timestamp
        """
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["id", "ip", "method", "path", "threats", "severity", "timestamp"])
        for log in logs:
            s = LogService.serialize(log)
            writer.writerow([
                s["id"],
                s["ip"],
                s["method"],
                s["path"],
                ", ".join(s["threats"]),
                s["severity"],
                s["timestamp"],
            ])
        return output.getvalue()


    # ────────────────────────────────────────────────────────────────────────
    # SECTION 4 — WRITE / PURGE
    # ────────────────────────────────────────────────────────────────────────

    @staticmethod
    def delete_by_id(log_id: int) -> bool:
        """
        Delete a single log entry by ID.
        Returns True on success, False if not found.
        """
        db, AttackLog = _get_db_and_model()
        log = AttackLog.query.get(log_id)
        if not log:
            return False
        try:
            db.session.delete(log)
            db.session.commit()
            return True
        except Exception:
            db.session.rollback()
            return False


    @staticmethod
    def purge_older_than(days: int = 30) -> int:
        """
        Delete all logs older than `days` days.
        Returns the number of rows deleted.
        """
        db, AttackLog = _get_db_and_model()
        cutoff = datetime.utcnow() - timedelta(days=days)
        try:
            deleted = (
                AttackLog.query
                .filter(AttackLog.timestamp < cutoff)
                .delete(synchronize_session=False)
            )
            db.session.commit()
            return deleted
        except Exception:
            db.session.rollback()
            return 0


    @staticmethod
    def purge_by_ip(ip: str) -> int:
        """
        Delete all logs from a specific IP.
        Returns the number of rows deleted.
        """
        db, AttackLog = _get_db_and_model()
        try:
            deleted = (
                AttackLog.query
                .filter_by(ip=ip)
                .delete(synchronize_session=False)
            )
            db.session.commit()
            return deleted
        except Exception:
            db.session.rollback()
            return 0


    @staticmethod
    def purge_all() -> int:
        """
        ⚠ Delete EVERY log entry from the database.
        Returns the number of rows deleted.
        """
        db, AttackLog = _get_db_and_model()
        try:
            deleted = AttackLog.query.delete(synchronize_session=False)
            db.session.commit()
            return deleted
        except Exception:
            db.session.rollback()
            return 0


# ════════════════════════════════════════════════════════════════════════════
# PRIVATE HELPERS  (module-level, not part of the public API)
# ════════════════════════════════════════════════════════════════════════════

# Inline keyword lists (mirrors request_capture.THREAT_MAP)
_KEYWORD_MAP = {
    "sql_injection":    ["'", '"', "--", "1=1", "or 1", "union select", "drop table", "sleep("],
    "path_traversal":  ["../", "..\\", "%2e%2e", "/etc/passwd", "/etc/shadow"],
    "credential_probe":["admin", "/login", "/auth", "/signin", "/token", "/wp-login", "/wp-admin"],
    "secret_probe":    [".env", "config", "secrets", ".git", "backup", "api_key"],
    "shell_probe":     ["cmd=", "exec=", "system(", "shell_exec", "/bin/sh", "/bin/bash"],
    "scanner_probe":   ["nmap", "nikto", "sqlmap", "burpsuite", "hydra", "gobuster", "wfuzz"],
}


def _get_threat_keywords(category: str) -> list:
    return _KEYWORD_MAP.get(category, [])


def _detect_threats(log) -> list:
    """Return list of matched threat categories for a single log row."""
    combined = f"{(log.path or '')} {(log.body or '')}".lower()
    return [
        cat for cat, keywords in _KEYWORD_MAP.items()
        if any(kw in combined for kw in keywords)
    ]


def _classify_severity(log) -> str:
    """
    Derive severity from the first matched threat category.
    Falls back to 'low' if nothing matches.
    """
    threats = _detect_threats(log)
    for t in threats:
        if SEVERITY_MAP.get(t) == "critical":
            return "critical"
    for t in threats:
        if SEVERITY_MAP.get(t) == "high":
            return "high"
    for t in threats:
        if SEVERITY_MAP.get(t) == "medium":
            return "medium"
    return "low"
