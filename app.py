from flask import Flask, render_template, url_for, request, redirect, flash, session, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import logging, json, time, random
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'honeypot_secret_123'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.secret_key = 'secret_key'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ─────────────────────────────────────────
# DATABASE MODEL
# ─────────────────────────────────────────
class User(db.Model):
    id       = db.Column(db.Integer, primary_key=True)
    name     = db.Column(db.String(100))
    email    = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(100))

# 🆕 Honeypot attack logs table
class AttackLog(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    ip         = db.Column(db.String(50))
    method     = db.Column(db.String(10))
    path       = db.Column(db.String(200))
    body       = db.Column(db.Text)
    headers    = db.Column(db.Text)
    timestamp  = db.Column(db.DateTime, default=datetime.utcnow)

with app.app_context():
    db.create_all()

# ─────────────────────────────────────────
# FILE LOGGER (honeypot.log)
# ─────────────────────────────────────────
logging.basicConfig(
    filename="honeypot.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

# ─────────────────────────────────────────
# LOGIN REQUIRED DECORATOR
# ─────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):           # ← bug fix: *args **kwargs
        if 'user_id' not in session:
            flash('Please login to access this page', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# ─────────────────────────────────────────
# HONEYPOT HELPERS
# ─────────────────────────────────────────
def log_attack(req):
    """Log attacker details to DB + file + console."""
    entry = {
        "time":    datetime.utcnow().isoformat(),
        "ip":      req.remote_addr,
        "method":  req.method,
        "path":    req.path,
        "body":    req.get_data(as_text=True)[:500],
        "headers": str(dict(req.headers))[:500],
    }
    # 1. Console alert
    print(f"\n🚨 [HONEYPOT HIT]")
    print(f"   IP     : {entry['ip']}")
    print(f"   Route  : {entry['method']} {entry['path']}")
    print(f"   Body   : {entry['body'][:80]}")
    print(f"   Time   : {entry['time']}\n")

    # 2. File log
    logging.info(json.dumps(entry))

    # 3. Database log
    try:
        log = AttackLog(
            ip      = req.remote_addr,
            method  = req.method,
            path    = req.path,
            body    = req.get_data(as_text=True)[:500],
            headers = str(dict(req.headers))[:500],
        )
        db.session.add(log)
        db.session.commit()
    except:
        db.session.rollback()


def get_dummy_response(path):
    """Return believable fake data based on what attacker is probing."""
    p = path.lower()

    if any(k in p for k in ["login", "auth", "signin", "token"]):
        return {
            "token":      "eyJhbGciOiJIUzI1NiJ9.fake.signature",
            "expires_in": 3600,
            "user":       {"id": 1, "role": "admin"}
        }
    if any(k in p for k in ["admin", "users", "accounts", "members"]):
        return {
            "users": [
                {"id": 1, "username": "admin",    "email": "admin@corp.local",  "role": "superuser"},
                {"id": 2, "username": "john.doe", "email": "john@corp.local",   "role": "user"},
            ]
        }
    if any(k in p for k in [".env", "config", "secrets", "db", "database"]):
        return {
            "DB_HOST":     "db.internal",
            "DB_USER":     "root",
            "DB_PASS":     "Sup3rS3cr3t!",
            "DB_NAME":     "production",
            "SECRET_KEY":  "xK9#mP2$nQ7@wL4"
        }
    if any(k in p for k in ["flag", "key", "password", "passwd", "shadow"]):
        return {
            "flag":  "HTB{f4k3_fl4g_y0u_f00l}",
            "valid": True
        }
    if any(k in p for k in ["files", "upload", "backup", "dump"]):
        return {
            "files": ["backup_2024.sql", "passwords.txt", "id_rsa.pem", "dump.zip"]
        }

    # Default
    return {"status": "ok", "message": "Request processed successfully"}


# ─────────────────────────────────────────
# YOUR EXISTING ROUTES (unchanged)
# ─────────────────────────────────────────
@app.route('/')
def index():
    return render_template('honeypot_homepage.html')


def render_auth_page(active_tab="login"):
    return render_template("login.html", active_tab=active_tab)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_auth_page("register")

    name = request.form['name']
    email = request.form['email']
    password = request.form['password']
    confirm = request.form['confirm_password']

    if password != confirm:
        flash("Password not match")
        return redirect("/")

    user = User(name=name, email=email, password=password)
    db.session.add(user)
    db.session.commit()

    flash("Account created successfully")
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_auth_page("login")

    email = request.form['email']
    password = request.form['password']

    user = User.query.filter_by(email=email, password=password).first()

    if user:
        session['user_id'] = user.id
        session['user_name'] = user.name or user.email
        flash("Signin successful", "success")
        return redirect(url_for("dashboard"))

    else:
        flash("Invalid credentials", "error")
        return redirect(url_for("login"))


'''@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name             = request.form['name']
        email            = request.form['email']
        password         = request.form['password']
        confirm_password = request.form['confirm_password']

        if not name or len(name.strip()) < 2:
            flash('Name must be at least 2 characters long', 'error')
            return redirect(url_for('login'))
        if not email or '@' not in email:
            flash('Invalid email', 'error')
            return redirect(url_for('login'))
        if (not password or len(password) < 8
                or not any(c.isalpha()  for c in password)
                or not any(c.isdigit()  for c in password)
                or not any(not c.isalnum() for c in password)):
            flash('Password must be 8+ chars with letters, numbers & special chars', 'error')
            return redirect(url_for('login'))
        if confirm_password != password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('login'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists. Please login.', 'error')
            return redirect(url_for('login'))

        hashed_password = generate_password_hash(password)
        new_user = User(
            name     = name.strip(),
            email    = email.strip(),
            password = hashed_password
        )
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful. Proceed to signin.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Some error occurred while registering', 'error')
            return redirect(url_for('login'))

    return redirect(url_for('login'))'''


# ─────────────────────────────────────────
# 🆕 HONEYPOT — CATCH ALL UNKNOWN ROUTES
# ─────────────────────────────────────────
@app.route('/honeypot', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def honeypot(path):
    # Log the attacker
    log_attack(request)

    # Small random delay (slows brute-force scanners)
    time.sleep(random.uniform(0.3, 1.2))

    # Send believable fake response
    resp = make_response(jsonify(get_dummy_response(path)), 200)
    resp.headers["Server"]       = "Apache/2.4.41 (Ubuntu)"
    resp.headers["X-Powered-By"] = "PHP/7.4.3"
    resp.headers["X-Request-ID"] = f"req-{random.randint(10000, 99999)}"
    return resp


# 🆕 OPTIONAL: View all attack logs (admin only, protect this in production!)
@app.route('/attacklogs')
@login_required
def attacklogs():
    # logs = AttackLog.query.order_by(AttackLog.timestamp.desc()).limit(50).all()
    # result = []
    # for log in logs:
    #     result.append({
    #         "ip":        log.ip,
    #         "method":    log.method,
    #         "path":      log.path,
    #         "body":      log.body,
    #         "timestamp": log.timestamp.isoformat()
    #     })
    #     return jsonify(result)
    return render_template('attacklogs.html')


'''-----------------------------------------------------------------'''
@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/alerts')
@login_required
def alerts():
    return render_template('alerts.html')

@app.route('/analysis')
@login_required
def analysis():
    return render_template('analysis.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

@app.route('/IPmonitor')
@login_required
def IPmonitor():
    return render_template('IPmonitor.html')

@app.route('/logs')
@login_required
def logs():
    return render_template('logs.html')

@app.route('/reports')
@login_required
def reports():
    return render_template('reports.html')

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

if __name__ == '__main__':
    app.run(debug=True)
