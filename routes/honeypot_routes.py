from flask import Blueprint, request, render_template_string
from logs_routes import add_log

honeypot = Blueprint('honeypot', __name__)

# -------------------------
# FAKE ADMIN LOGIN PAGE
# -------------------------
@honeypot.route('/admin', methods=['GET', 'POST'])
def fake_admin():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # log attacker attempt
        add_log(
            ip=request.remote_addr,
            status="blocked",
            endpoint="/admin"
        )

        return "Access Denied", 403

    # fake login page (looks real)
    return render_template_string("""
        <h2>Admin Login</h2>
        <form method="POST">
            <input type="text" name="username" placeholder="Username"/><br><br>
            <input type="password" name="password" placeholder="Password"/><br><br>
            <button type="submit">Login</button>
        </form>
    """)


# -------------------------
# FAKE SSH / CONFIG ACCESS
# -------------------------
@honeypot.route('/.env')
def fake_env():
    add_log(request.remote_addr, "suspicious", "/.env")
    return "Permission Denied", 403


@honeypot.route('/config')
def fake_config():
    add_log(request.remote_addr, "suspicious", "/config")
    return "Forbidden", 403


# -------------------------
# FAKE DATABASE ACCESS
# -------------------------
@honeypot.route('/db')
def fake_db():
    add_log(request.remote_addr, "blocked", "/db")
    return "Database access denied", 403


# -------------------------
# CATCH ALL (IMPORTANT 🔥)
# -------------------------
@honeypot.route('/<path:unknown>')
def catch_all(unknown):
    add_log(
        ip=request.remote_addr,
        status="suspicious",
        endpoint=f"/{unknown}"
    )

    return "404 Not Found", 404