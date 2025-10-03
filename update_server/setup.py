# update_server/setup.py
from __future__ import annotations

from flask import Blueprint, render_template, request, redirect, url_for, flash
from .models import ensure_bootstrap_admin, create_initial_admin

setup_bp = Blueprint("setup", __name__, template_folder="templates")

@setup_bp.before_app_request
def _force_setup_if_needed():
    """
    Αν λείπει ο αρχικός Admin (ensure_bootstrap_admin() == True), ανακατεύθυνα στο /setup
    μόνο για UI routes. Μην αγγίζεις /api, /static, /auth, /health ποτέ.
    """
    try:
        needs_setup = bool(ensure_bootstrap_admin())
    except Exception:
        needs_setup = True

    if not needs_setup:
        return None

    p = (request.path or "/").rstrip("/") or "/"
    if (
        p.startswith("/api/") or
        p.startswith("/static/") or
        p.startswith("/auth/") or
        p.startswith("/health") or
        p == "/setup" or
        p == "/favicon.ico"
    ):
        return None

    return redirect(url_for("setup.setup_get"))

@setup_bp.get("/setup")
def setup_get():
    if not ensure_bootstrap_admin():
        return redirect(url_for("admin.dashboard"))
    try:
        return render_template("setup_admin.html")
    except Exception:
        return (
            "<!doctype html><meta charset='utf-8'>"
            "<h1>Setup wizard</h1>"
            "<form method='post' action='/setup'>"
            "<input name='email' type='email' placeholder='admin@example.com' required>"
            "<input name='password' type='password' placeholder='Password' required>"
            "<button type='submit'>Create Admin</button>"
            "</form>",
            200,
            {"Content-Type": "text/html; charset=utf-8"},
        )

@setup_bp.post("/setup")
def setup_post():
    if not ensure_bootstrap_admin():
        return redirect(url_for("admin.dashboard"))
    email = request.form.get("email","").strip().lower()
    password = request.form.get("password","")
    if not email or not password:
        flash("Email & password required", "danger")
        return redirect(url_for("setup.setup_get"))
    u = create_initial_admin(email, password)
    if u is None:
        flash("User already exists", "warning")
        return redirect(url_for("setup.setup_get"))
    flash("Admin user created. Please log in.", "success")
    return redirect(url_for("auth.login"))
