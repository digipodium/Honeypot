# app/models.py

from datetime import datetime
from app import db


class User(db.Model):
    __tablename__ = "users"

    id       = db.Column(db.Integer, primary_key=True)
    name     = db.Column(db.String(100))
    email    = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(200))


class AttackLog(db.Model):
    __tablename__ = "attack_logs"

    id          = db.Column(db.Integer, primary_key=True)

    # Attacker info
    ip          = db.Column(db.String(50))
    user_agent  = db.Column(db.String(300))

    # Request details
    method      = db.Column(db.String(10))
    path        = db.Column(db.String(200))
    body        = db.Column(db.Text)
    headers     = db.Column(db.Text)

    # Attack classification
    attack_type = db.Column(db.String(100), default="Unknown")

    # Status
    is_suspicious = db.Column(db.Boolean, default=True)

    # Timestamp
    timestamp   = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "ip": self.ip,
            "method": self.method,
            "path": self.path,
            "attack_type": self.attack_type,
            "time": self.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        }