# app/utils/detector.py

def detect_attack_type(path, body):
    data = (path + " " + body).lower()

    if "admin" in data:
        return "Admin Panel Access"
    if "login" in data and "password" in data:
        return "Brute Force Attempt"
    if "select" in data or "drop" in data:
        return "SQL Injection"
    if "<script>" in data:
        return "XSS Attack"
    if ".env" in data or "config" in data:
        return "Sensitive File Access"

    return "Unknown"