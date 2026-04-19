from flask import Blueprint, jsonify, session, redirect, url_for, request
from functools import wraps
import platform
import datetime

helper = Blueprint('helper', __name__)

# -------------------------
# LOGIN REQUIRED DECORATOR
# -------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return wrapper


# -------------------------
# HEALTH CHECK (API)
# -------------------------
@helper.route('/api/health')
def health_check():
    return jsonify({
        "status": "running",
        "time": str(datetime.datetime.now())
    })


# -------------------------
# SYSTEM INFO
# -------------------------
@helper.route('/api/system-info')
@login_required
def system_info():
    return jsonify({
        "system": platform.system(),
        "node": platform.node(),
        "release": platform.release(),
        "python_version": platform.python_version()
    })


# -------------------------
# CURRENT USER INFO
# -------------------------
@helper.route('/api/me')
@login_required
def current_user():
    return jsonify({
        "user_id": session.get('user_id'),
        "status": "active"
    })


# -------------------------
# CLIENT REQUEST INFO
# -------------------------
@helper.route('/api/request-info')
def request_info():
    return jsonify({
        "ip": request.remote_addr,
        "method": request.method,
        "path": request.path,
        "user_agent": request.headers.get('User-Agent')
    })


# -------------------------
# TEST ROUTE (DEBUGGING)
# -------------------------
@helper.route('/test')
def test():
    return "Helper routes working!"