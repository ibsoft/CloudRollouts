# update_server/__init__.py
from __future__ import annotations

import os
import datetime as dt
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
from .admin_api import admin_api_bp
from .artifacts import ensure_artifact_root
from .tasks.scheduler import init_scheduler
from .stats.views import stats_api_bp  # /api/stats/*
from update_server.version import __version__
from update_server.billing import billing_bp
from update_server.observability import configure_logging, add_updates_http_logging, register_health
from update_server.config import load_config

# ── Optional .env (non-fatal)
try:
    from dotenv import load_dotenv, find_dotenv
    load_dotenv(find_dotenv(), override=False)
except Exception:
    pass


def create_app():
    app = Flask(__name__, instance_relative_config=True, static_folder="static")

    # ── App config & basic context
    app.config["APP_VERSION"] = __version__

    @app.context_processor
    def inject_version():
        return {"app_version": __version__}

    @app.context_processor
    def inject_globals():
        return {"current_year": dt.datetime.utcnow().year}

    os.makedirs(app.instance_path, exist_ok=True)
    
    load_config(app)
    
    ui_links = app.config.get("UI_LINKS") or {}
    docs_url = (
        app.config.get("DOCS_URL")
        or (ui_links.get("docs") if isinstance(ui_links, dict) else None)
        or "https://example.com/docs"
    )
    support_url = (
        app.config.get("SUPPORT_URL")
        or (ui_links.get("support") if isinstance(ui_links, dict) else None)
        or "mailto:support@example.com"
    )
    app.config["DOCS_URL"] = docs_url
    app.config["SUPPORT_URL"] = support_url

    # ── Reverse proxy trust
    if app.config.get("TRUST_PROXY", False):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    # ── Artifact root
    ensure_artifact_root(app.config.get("ARTIFACTS_ROOT", "instance/artifacts"))

    # ── Observability
    configure_logging(app)
    add_updates_http_logging(app)

    # ── Init extensions
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    limiter.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    csrf.init_app(app)
    swagger.init_app(app)
    metrics.init_app(app)

    # ── Blueprints (register exactly once each)
    app.register_blueprint(billing_bp, url_prefix="/billing")
    app.register_blueprint(api_bp, url_prefix="/api")
    csrf.exempt(api_bp)                 # M2M APIs (API keys) no CSRF
    app.register_blueprint(stats_api_bp)
    csrf.exempt(stats_api_bp)           # SSE/GET
    app.register_blueprint(setup_bp)    # /setup
    app.register_blueprint(auth_bp)     # /auth
    app.register_blueprint(admin_bp)    # /admin UI
    app.register_blueprint(admin_api_bp)  # /api/admin
    csrf.exempt(admin_api_bp)

    # ── Health fallback (if not registered elsewhere)
    if not any(r.rule == "/health" for r in app.url_map.iter_rules()):
        @app.get("/health")
        def _health_fallback():
            return {"status": "ok"}, 200

    # ── CSRF helpers & errors
    from flask_wtf.csrf import generate_csrf, CSRFError

    @app.context_processor
    def inject_csrf_token():
        return dict(csrf_token=generate_csrf)

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        return render_template("csrf_error.html", reason=e.description), 400

    app.config.setdefault("WTF_CSRF_TIME_LIMIT", None)

    # ── Health registration for metrics/liveness
    register_health(app)

    # ── Start scheduler infra (APScheduler container)
    init_scheduler(app)

    # ── Request correlation
    @app.before_request
    def _bind_rid():
        g.rid = request.headers.get("X-Request-ID") or uuid4().hex[:12]
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(rid=g.rid, path=request.path)

    # ── Unauthorized handling for mixed UI/API
    @login_manager.unauthorized_handler
    def _unauthorized():
        if request.path.startswith("/api/"):
            return jsonify(error="unauthorized"), 401
        next_url = ""
        if request.method == "GET" and request.endpoint != "auth.login":
            next_url = request.full_path
            if next_url.endswith("?"):
                next_url = next_url[:-1]
            if urlparse(next_url).netloc:
                next_url = ""
        if next_url:
            return redirect(url_for("auth.login", next=next_url))
        return redirect(url_for("auth.login"))

    # ── Favicon (non-fatal)
    @app.route("/favicon.ico")
    def favicon():
        try:
            return send_from_directory(app.static_folder, "favicon.ico", mimetype="image/x-icon")
        except Exception:
            return ("", 204)

    # ── Security & cache headers (disable HTML caching across users)
    @app.after_request
    def set_security_headers(resp):
        if app.config.get("REQUIRE_HTTPS", True):
            resp.headers["Strict-Transport-Security"] = (
                f"max-age={app.config.get('HSTS_DAYS', 180)*24*3600}; includeSubDomains"
            )
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-XSS-Protection"] = "1; mode=block"

        try:
            ct = resp.headers.get("Content-Type", "")
            if "text/html" in ct:
                resp.headers["Cache-Control"] = "no-store, max-age=0"
                resp.headers["Pragma"] = "no-cache"
                cur_vary = resp.headers.get("Vary")
                if cur_vary:
                    if "Cookie" not in cur_vary:
                        resp.headers["Vary"] = cur_vary + ", Cookie"
                else:
                    resp.headers["Vary"] = "Cookie"
        except Exception:
            pass

        return resp

    # ── Inject user roles & tenant context to g (for templates/nav guards)
    @app.before_request
    def _inject_user_context():
        from flask import g, request, session
        from flask_login import current_user

        g.roles = []
        g.tenant_ctx_id = None
        g.tenant_ctx_name = None

        # Allow public/API requests gracefully
        if not getattr(current_user, "is_authenticated", False):
            return

        # --- Roles
        try:
            from .models import Role, UserRole
            g.roles = [
                name for (name,) in (
                    db.session.query(Role.name)
                    .join(UserRole, UserRole.role_id == Role.id)
                    .filter(UserRole.user_id == current_user.id)
                    .all()
                )
            ]
        except Exception:
            g.roles = []

        is_admin = "Admin" in g.roles

        # --- If browser session switched to another user, clear sticky tenant
        prev_uid = session.get("tenant_ctx_uid")
        if prev_uid != getattr(current_user, "id", None):
            session.pop("tenant_ctx_id", None)
            session.pop("tenant_ctx_name", None)
            session["tenant_ctx_uid"] = getattr(current_user, "id", None)

        # --- Collect allowed tenant ids for this user
        def _user_tenant_ids() -> list[int]:
            tids: list[int] = []
            # Prefer a helper if your admin UI defines it
            try:
                from update_server.admin.views import _user_tenant_ids as _utids
                tids = _utids(current_user.id) or []
            except Exception:
                pass
            # Fallback: single-tenant users via current_user.tenant_id
            if not tids and getattr(current_user, "tenant_id", None):
                try:
                    tids = [int(current_user.tenant_id)]
                except Exception:
                    tids = []
            # unique + ints
            seen = set()
            clean = []
            for x in tids:
                try:
                    xi = int(x)
                    if xi and xi not in seen:
                        clean.append(xi)
                        seen.add(xi)
                except Exception:
                    continue
            return clean

        user_tids = _user_tenant_ids()

        # --- Accept both ?tenant= and ?tenant_id=
        tid_param = request.args.get("tenant", type=int) or request.args.get("tenant_id", type=int)
        if tid_param:
            if is_admin or (tid_param in user_tids):
                from .models import Tenant
                t = db.session.get(Tenant, tid_param)
                if t:
                    g.tenant_ctx_id = t.id
                    g.tenant_ctx_name = t.name
                    session["tenant_ctx_id"] = t.id
                    session["tenant_ctx_name"] = t.name
                    session["tenant_ctx_uid"] = getattr(current_user, "id", None)
                    return
            # unauthorized tenant switch attempt => ignore and continue

        # --- Sticky session selection must be valid for this user
        tid_session = session.get("tenant_ctx_id")
        if tid_session:
            if is_admin or (tid_session in user_tids):
                from .models import Tenant
                t = db.session.get(Tenant, tid_session)
                if t:
                    g.tenant_ctx_id = t.id
                    g.tenant_ctx_name = t.name
                    return
            # Not valid anymore => clear it
            session.pop("tenant_ctx_id", None)
            session.pop("tenant_ctx_name", None)

        # --- Defaults
        from .models import Tenant  # noqa: F401

        if is_admin:
            # Admin default: global view unless explicitly selected
            g.tenant_ctx_name = "All tenants"
            return

        # Non-admin defaults
        if len(user_tids) == 1:
            t = db.session.get(Tenant, user_tids[0])
            if t:
                g.tenant_ctx_id = t.id
                g.tenant_ctx_name = t.name
                session["tenant_ctx_id"] = t.id
                session["tenant_ctx_name"] = t.name
                session["tenant_ctx_uid"] = getattr(current_user, "id", None)
                return
        elif len(user_tids) > 1:
            g.tenant_ctx_name = f"{len(user_tids)} tenants"
            return
        else:
            # No memberships known; leave empty
            return

    return app
