import os
import logging
import json
from flask import Flask, redirect, render_template, request, url_for
from flask_cors import CORS
from dotenv import load_dotenv

# Load configuration
load_dotenv('redirector.env')

app = Flask(__name__)
CORS(app)

# Configuration
HONEYPOT_URL = os.getenv('HONEYPOT_URL', 'http://localhost:5000/honeypot')
PORT = int(os.getenv('REDIRECTOR_PORT', 5001))
DEBUG = os.getenv('DEBUG', 'True').lower() == 'true'

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("redirector.log"),
        logging.StreamHandler()
    ]
)

# Lists of suspicious patterns
SUSPICIOUS_PATHS = [
    '/.env', '/wp-admin', '/config', '/.git', '/etc/passwd', 
    '/admin', '/db', '/backup', '/shell.php', '/eval-stdin.php'
]

SUSPICIOUS_KEYWORDS = [
    'union select', 'or 1=1', '<script', 'wget', 'curl', '../', 'drop table', 'truncate'
]

@app.before_request
def check_for_attacks():
    """
    Hook to check every incoming request for attack signatures.
    Scans URL path, query parameters, AND POST form data.
    """
    path = request.path
    query = request.query_string.decode('utf-8').lower()
    
    # Skip detection for health check and static assets if any
    if path == '/health' or path.startswith('/static'):
        return None

    is_suspicious = False
    reason = ""

    # 1. Check path for sensitive file probes
    if any(p in path for p in SUSPICIOUS_PATHS):
        is_suspicious = True
        reason = f"Suspicious Path: {path}"
        
    # 2. Check query string for SQLi/XSS/RCE signatures
    if any(k in query for k in SUSPICIOUS_KEYWORDS):
        is_suspicious = True
        reason = f"Attack Payload in Query: {query}"

    # 3. Check POST data for malicious payloads
    if request.method == 'POST':
        for key, value in request.form.items():
            val_lower = value.lower()
            if any(k in val_lower for k in SUSPICIOUS_KEYWORDS):
                is_suspicious = True
                reason = f"Attack Payload in Form Field '{key}': {value}"
                break

    if is_suspicious:
        # Construct the target URL on the honeypot
        clean_path = path.lstrip('/')
        target = f"{HONEYPOT_URL}/{clean_path}"
        if query:
            target += f"?{query}"
            
        logging.warning(f"SECURITY ALERT - REDIRECTING [{reason}]. Source IP: {request.remote_addr}")
        return redirect(target, code=302)

# --- PUBLIC ROUTES (The Facade) ---

@app.route('/')
def index():
    """Landing Page"""
    return render_template('index.html')

@app.route('/products')
def products():
    """Product Catalog (Contains ID lures)"""
    return render_template('products.html')

@app.route('/about')
def about():
    """Company About Page"""
    return render_template('index.html') # Reusing index for demo simplicity

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    """Contact Form with POST monitoring"""
    if request.method == 'POST':
        # If the request reaches here, it means no attack was detected in before_request
        return render_template('contact.html', success=True)
    return render_template('contact.html')

@app.route('/login')
def login():
    """Fake Login Page Lure"""
    return "Login Service Temporarily Unavailable", 503

@app.route('/debug-console')
def debug_console():
    """The Hidden Test Dashboard"""
    return render_template('tester.html')

@app.route('/health')
def health():
    return {"status": "ok", "service": "nova-tech-portal"}, 200

# --- SERVER STARTUP ---

def serve_production():
    """Run the server using Waitress."""
    from waitress import serve
    logging.info(f"Nova-Tech Portal starting on http://0.0.0.0:{PORT}")
    serve(app, host='0.0.0.0', port=PORT)

if __name__ == '__main__':
    if DEBUG:
        logging.info(f"Nova-Tech Portal (DEV) starting on http://localhost:{PORT}")
        app.run(host='0.0.0.0', port=PORT, debug=True)
    else:
        serve_production()
