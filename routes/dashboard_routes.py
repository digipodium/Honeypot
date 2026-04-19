from flask import Blueprint, render_template, session, redirect, url_for
from models import User

dashboard = Blueprint('main', __name__)

# -------------------------
# DASHBOARD (Protected)
# -------------------------
@dashboard.route('/dashboard')
def dashboard_home():
    # check login
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    user = User.query.get(session['user_id'])

    return render_template('dashboard.html', user=user)


# -------------------------
# LOGS PAGE (for honeypot)
# -------------------------
@dashboard.route('/logs')
def logs():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    # yahan tum future me logs fetch karoge (DB ya file se)
    logs_data = [
        {"ip": "192.168.1.1", "status": "blocked", "time": "10:30 AM"},
        {"ip": "10.0.0.5", "status": "suspicious", "time": "11:00 AM"},
    ]

    return render_template('logs.html', logs=logs_data)


# -------------------------
# PROFILE PAGE
# -------------------------
@dashboard.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    user = User.query.get(session['user_id'])
    return render_template('profile.html', user=user)