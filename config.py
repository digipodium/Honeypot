import os

class Config:
    # -------------------------
    # BASIC CONFIG
    # -------------------------
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'super-secret-key'
    
    # -------------------------
    # DATABASE CONFIG
    # -------------------------
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///database.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # -------------------------
    # SESSION CONFIG
    # -------------------------
    SESSION_TYPE = 'filesystem'
    PERMANENT_SESSION_LIFETIME = 3600  # seconds

    # -------------------------
    # HONEYPOT SETTINGS
    # -------------------------
    HONEYPOT_ACTIVE = True
    MAX_IP_ATTEMPTS = 5
    AUTO_BLOCK = True

    # fake endpoints attackers try
    TRAP_ROUTES = [
        '/admin',
        '/login',
        '/wp-admin',
        '/phpmyadmin',
        '/.env',
        '/config',
        '/db'
    ]

    # -------------------------
    # LOGGING SETTINGS
    # -------------------------
    LOG_LEVEL = 'INFO'
    LOG_FILE = 'honeypot.log'

    # -------------------------
    # IP TRACKING API
    # -------------------------
    IP_API_URL = "http://ip-api.com/json/"

    # -------------------------
    # SECURITY SETTINGS
    # -------------------------
    BLOCKED_IPS = set()   # runtime blocking
    ALLOWED_IPS = []      # whitelist (optional)

    # -------------------------
    # DEBUG MODE
    # -------------------------
    DEBUG = True