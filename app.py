"""OptiRate — Entry Point (Phase 1 Auth + Phase 2 Financial Data)."""

import json

from flask import Flask, jsonify, request
from config import Config
from extensions import db, jwt, bcrypt, cors
import threading
import time
from services.engine.history_engine import sync_daily_history


def _seed_users(app):
    """Create default test accounts if they don't already exist."""
    from models.user import User

    seed_accounts = [
        {"username": "admin",   "email": "admin@test.com",   "password": "123456", "role": "admin"},
        {"username": "premium", "email": "premium@test.com", "password": "123456", "role": "premium"},
        {"username": "free",    "email": "free@test.com",    "password": "123456", "role": "free"},
    ]

    with app.app_context():
        for acct in seed_accounts:
            if User.query.filter_by(email=acct["email"]).first():
                continue
            hashed_pw = bcrypt.generate_password_hash(acct["password"]).decode("utf-8")
            user = User(
                username=acct["username"],
                email=acct["email"],
                password=hashed_pw,
                role=acct["role"],
            )
            db.session.add(user)
            app.logger.info("Seeded user: %s (%s)", acct["email"], acct["role"])
        db.session.commit()


def create_app():
    """Application factory."""
    app = Flask(__name__)
    app.config.from_object(Config)

    # ── Initialise extensions ────────────────────────────────────────────
    db.init_app(app)
    jwt.init_app(app)
    bcrypt.init_app(app)

    # CORS — restrict to the Vite dev server (reads from Config)
    allowed_origins = [
        o.strip() for o in app.config.get("CORS_ORIGINS", "http://localhost:5173").split(",")
    ]
    cors.init_app(app, resources={r"/api/*": {"origins": allowed_origins}})

    # ── JWT identity serialisation (sub must be a string) ────────────────
    @jwt.user_identity_loader
    def user_identity_lookup(identity):
        """Serialize dict identity → JSON string for the JWT 'sub' claim."""
        if isinstance(identity, dict):
            return json.dumps(identity)
        return str(identity)

    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        """Deserialize the 'sub' claim back to a dict for current_user."""
        sub = jwt_data["sub"]
        try:
            return json.loads(sub)
        except (json.JSONDecodeError, TypeError):
            return sub

    # ── Register blueprints ──────────────────────────────────────────────
    from routes.auth import auth_bp, protected_bp
    from routes.health import health_bp
    from routes.v2 import v2_bp
    from routes.v3 import v3_bp
    from routes.admin import admin_bp, admin_public_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(protected_bp)
    app.register_blueprint(health_bp)
    app.register_blueprint(v2_bp)
    app.register_blueprint(v3_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(admin_public_bp)

    # ── Global error handlers (unified schema) ───────────────────────────
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"status": "error", "message": "Resource not found."}), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({"status": "error", "message": "Method not allowed."}), 405

    @app.errorhandler(500)
    def internal_error(e):
        return jsonify({"status": "error", "message": "Internal server error."}), 500

    # ── JWT custom error responses (unified schema) ──────────────────────
    @jwt.unauthorized_loader
    def missing_token(reason):
        return jsonify({"status": "error", "message": "Authorization token is missing."}), 401

    @jwt.invalid_token_loader
    def invalid_token(reason):
        return jsonify({"status": "error", "message": "Invalid token."}), 401

    @jwt.expired_token_loader
    def expired_token(jwt_header, jwt_payload):
        return jsonify({"status": "error", "message": "Token has expired."}), 401

    # ── Create tables & seed ─────────────────────────────────────────────
    with app.app_context():
        from models.user import User  # noqa: F401 — ensure model is registered
        from models.exchange_history import ExchangeHistory  # noqa: F401
        from models.logs import PredictionLog, RecommendationLog # noqa: F401
        db.create_all()

    _seed_users(app)

    # ── Background Daily Sync ────────────────────────────────────────────
    from apscheduler.schedulers.background import BackgroundScheduler
    
    def run_daily_sync_job():
        try:
            sync_daily_history(app)
        except Exception as e:
            app.logger.error(f"Daily history sync failed: {e}")

    scheduler = BackgroundScheduler()
    # Run scraper at least once per day (e.g., every day at 10:00 AM)
    # Using interval for now or cron. Let's use cron for once per day.
    scheduler.add_job(func=run_daily_sync_job, trigger="cron", hour=10, minute=0)
    
    # Also run once at startup to ensure we have today's data right away
    scheduler.add_job(func=run_daily_sync_job, trigger="date")
    
    scheduler.start()
    app.logger.info("APScheduler started for daily history sync.")

    # ── Global Subscription Guard ────────────────────────────────────────
    @app.before_request
    def subscription_guard():
        """Auto-downgrade expired premium subscriptions on every request."""
        from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
        from models.user import User
        from datetime import datetime

        # Only check on API routes that require auth
        if not request.path.startswith("/api/"):
            return
        try:
            verify_jwt_in_request(optional=True)
            raw = get_jwt_identity()
            if not raw:
                return
            identity = json.loads(raw) if isinstance(raw, str) else raw
            uid = identity.get("id")
            if not uid:
                return
            user = User.query.get(uid)
            if user and user.plan == "premium" and user.subscription_expires:
                if datetime.utcnow() > user.subscription_expires:
                    user.plan = "free"
                    user.role = "free"
                    user.subscription_expires = None
                    db.session.commit()
                    app.logger.info(
                        "Subscription Guard: Auto-downgraded user %s.", user.username
                    )
        except Exception:
            pass  # Don't block requests if guard fails

    return app



# ── Run ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    application = create_app()
    application.run(host="0.0.0.0", port=5000, debug=True)
