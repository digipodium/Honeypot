# app/__init__.py

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import logging

# Database object (global)
db = SQLAlchemy()


def create_app():
    app = Flask(__name__)

    # ───────────────────────────────
    # CONFIGURATION
    # ───────────────────────────────
    app.config['SECRET_KEY'] = 'secret_key'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Initialize DB
    db.init_app(app)

    # ───────────────────────────────
    # LOGGING SETUP (honeypot.log)
    # ───────────────────────────────
    logging.basicConfig(
        filename="honeypot.log",
        level=logging.INFO,
        format="%(asctime)s - %(message)s"
    )

    # ───────────────────────────────
    # REGISTER BLUEPRINTS
    # ───────────────────────────────
    from app.routes.auth import auth
    from app.routes.main import main
    from app.routes.honeypot import honeypot_bp
    from app.utils.request_capture import capture_request_data

    app.register_blueprint(auth)
    app.register_blueprint(main)
    app.register_blueprint(honeypot_bp)

    # ───────────────────────────────
    # CREATE DATABASE
    # ───────────────────────────────
    with app.app_context():
        from app.models import User, AttackLog
        db.create_all()

    return app