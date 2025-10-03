# update_server/__init__.py
from __future__ import annotations

import os
from urllib.parse import urlparse
from uuid import uuid4

from flask import Flask, jsonify, request, g, render_template, redirect, send_from_directory, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
import structlog

from .extensions import db, migrate, jwt, limiter, swagger, metrics, login_manager, csrf
from .admin.views import admin_bp
from .api.views import api_bp
from .auth.views import auth_bp
from .setup import setup_bp
from .artifacts import ensure_artifact_root
from .tasks.scheduler import init_scheduler
import datetime as dt
from update_server.version import __version__

from update_server.observability import configure_logging, add_updates_http_logging, register_health
from update_server.config import load_config

try:
    from dotenv import load_dotenv, find_dotenv
    load_dotenv(find_dotenv(), override=False)
except Exception:
    pass

def create_app():
    app = Flask(__name__, instance_relative_config=True, static_folder="static")

    app.config["APP_VERSION"] = __version__

    @app.context_processor
    def inject_version():
        return {"app_version": __version__}
    
    @app.context_processor
    def inject_globals():
        return {
            "current_year": dt.datetime.utcnow().year
        }

    
    os.makedirs(app.instance_path, exist_ok=True)
    load_config(app)

    if app.config.get("TRUST_PROXY", False):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    ensure_artifact_root(app.config.get("ARTIFACTS_ROOT", "instance/artifacts"))

    configure_logging(app)
    add_updates_http_logging(app)

    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    limiter.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    csrf.init_app(app)
    swagger.init_app(app)
    metrics.init_app(app)
    
    
    if not any(r.rule == "/health" for r in app.url_map.iter_rules()):
        @app.get("/health")
        def _health_fallback():
            # απλό liveness; δεν αγγίζει το heartbeat API
            return {"status": "ok"}, 200

    from flask_wtf.csrf import generate_csrf, CSRFError

    @app.context_processor
    def inject_csrf_token():
        return dict(csrf_token=generate_csrf)

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        return render_template("csrf_error.html", reason=e.description), 400

    app.config.setdefault('WTF_CSRF_TIME_LIMIT', None)

    app.register_blueprint(setup_bp)                    # /setup
    app.register_blueprint(auth_bp)                     # /auth
    app.register_blueprint(admin_bp)                    # admin UI
    app.register_blueprint(api_bp, url_prefix="/api")  # machine-to-machine
    csrf.exempt(api_bp)
    
     # --- DEBUG: dump routes (remove after you’re done) ---
    print("== URL MAP ==")
    for r in app.url_map.iter_rules():
        print(f"{r.endpoint:30s}  {r.rule}")

    register_health(app)
    init_scheduler(app)

    @app.before_request
    def _bind_rid():
        g.rid = request.headers.get("X-Request-ID") or uuid4().hex[:12]
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(rid=g.rid, path=request.path)

    @login_manager.unauthorized_handler
    def _unauthorized():
        # API requests: return JSON 401
        if request.path.startswith("/api/"):
            return jsonify(error="unauthorized"), 401

        # For browser requests: redirect to login with a safe "next"
        next_url = ""
        # Only attach next for GETs and avoid loops
        if request.method == "GET" and request.endpoint != "auth.login":
            # full_path preserves the query string
            next_url = request.full_path
            # Remove trailing '?' if there was no query
            if next_url.endswith("?"):
                next_url = next_url[:-1]
            # SECURITY: only allow same-site relative paths
            if urlparse(next_url).netloc:
                next_url = ""

        # Build redirect to the real login endpoint (no more "/auth/login")
        if next_url:
            return redirect(url_for("auth.login", next=next_url))
        return redirect(url_for("auth.login"))

    @app.route("/favicon.ico")
    def favicon():
        try:
            return send_from_directory(app.static_folder, "favicon.ico", mimetype="image/x-icon")
        except Exception:
            return ("", 204)

    @app.after_request
    def set_security_headers(resp):
        if app.config.get("REQUIRE_HTTPS", True):
            resp.headers["Strict-Transport-Security"] = (
                f"max-age={app.config.get('HSTS_DAYS',180)*24*3600}; includeSubDomains"
            )
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-XSS-Protection"] = "1; mode=block"
        return resp

    @app.before_request
    def _inject_user_roles():
        from flask_login import current_user
        g.roles = []
        if getattr(current_user, 'is_authenticated', False):
            from .models import UserRole, Role
            urs = UserRole.query.filter_by(user_id=current_user.id).all()
            names = []
            for ur in urs:
                r = Role.query.get(ur.role_id)
                if r:
                    names.append(r.name)
            g.roles = names

    return app

