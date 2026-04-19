from datetime import datetime
from flask import request
from logs_routes import add_log

# -------------------------
# GET CLIENT IP
# -------------------------
def get_client_ip():
    # proxy / real IP handling
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr


# -------------------------
# CAPTURE ATTACK
# -------------------------
def capture_attack(status="suspicious"):
    ip = get_client_ip()
    endpoint = request.path
    method = request.method
    user_agent = request.headers.get('User-Agent')

    log_data = {
        "ip": ip,
        "status": status,
        "endpoint": endpoint,
        "method": method,
        "user_agent": user_agent,
        "time": str(datetime.now())
    }

    # save in DB
    add_log(ip, status, endpoint)

    return log_data


# -------------------------
# DETECT SUSPICIOUS PATTERNS
# -------------------------
def is_suspicious():
    suspicious_keywords = [
        "admin", "login", "wp", ".env",
        "config", "phpmyadmin", "db"
    ]

    path = request.path.lower()

    for keyword in suspicious_keywords:
        if keyword in path:
            return True

    return False


# -------------------------
# AUTO HANDLE REQUEST
# -------------------------
def handle_honeypot():
    """
    Auto-detect + log attacker
    """
    if is_suspicious():
        return capture_attack(status="suspicious")
    else:
        return capture_attack(status="normal")


# -------------------------
# BLOCK REPEATED IPs (basic)
# -------------------------
blocked_ips = set()
ip_attempts = {}

def track_ip_attempts(ip):
    if ip not in ip_attempts:
        ip_attempts[ip] = 1
    else:
        ip_attempts[ip] += 1

    # block after 5 attempts
    if ip_attempts[ip] >= 5:
        blocked_ips.add(ip)


def is_blocked(ip):
    return ip in blocked_ips