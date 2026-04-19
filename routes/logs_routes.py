from flask import Blueprint, render_template, session, redirect, url_for, jsonify
from models import db

logs_bp = Blueprint('logs', __name__)

# -------------------------
# LOGIN CHECK DECORATOR
# -------------------------
from functools import wraps

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return wrapper


# -------------------------
# LOG MODEL (if not created)
# -------------------------
class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(100))
    status = db.Column(db.String(50))   # blocked / suspicious
    endpoint = db.Column(db.String(200))
    timestamp = db.Column(db.String(100))


# -------------------------
# VIEW LOGS PAGE
# -------------------------
@logs_bp.route('/logs')
@login_required
def view_logs():
    logs = Log.query.order_by(Log.id.desc()).all()
    return render_template('logs.html', logs=logs)


# -------------------------
# API: GET LOGS (JSON)
# -------------------------
@logs_bp.route('/api/logs')
@login_required
def get_logs():
    logs = Log.query.order_by(Log.id.desc()).all()

    logs_data = []
    for log in logs:
        logs_data.append({
            "ip": log.ip_address,
            "status": log.status,
            "endpoint": log.endpoint,
            "time": log.timestamp
        })

    return jsonify(logs_data)


# -------------------------
# ADD LOG (Honeypot usage)
# -------------------------
def add_log(ip, status, endpoint):
    new_log = Log(
        ip_address=ip,
        status=status,
        endpoint=endpoint,
        timestamp=str(__import__('datetime').datetime.now())
    )
    db.session.add(new_log)
    db.session.commit()