from flask import Blueprint, request, jsonify, session, redirect, url_for, render_template
import requests

ip_tracker = Blueprint('ip_tracker', __name__)

# -------------------------
# LOGIN PROTECTION
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
# GET IP DETAILS (API)
# -------------------------
@ip_tracker.route('/api/ip/<ip>')
@login_required
def get_ip_info(ip):
    try:
        # using free IP API
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()

        result = {
            "ip": ip,
            "country": data.get("country"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "timezone": data.get("timezone"),
            "status": data.get("status")
        }

        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -------------------------
# TRACK CURRENT VISITOR
# -------------------------
@ip_tracker.route('/track-me')
def track_me():
    ip = request.remote_addr

    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()

        return jsonify({
            "ip": ip,
            "location": f"{data.get('city')}, {data.get('country')}",
            "isp": data.get("isp")
        })

    except:
        return jsonify({"error": "Unable to fetch data"})


# -------------------------
# VIEW TRACKER PAGE
# -------------------------
@ip_tracker.route('/ip-tracker')
@login_required
def ip_tracker_page():
    return render_template('ip_tracker.html')