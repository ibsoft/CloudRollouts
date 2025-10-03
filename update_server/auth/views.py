from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required
from werkzeug.security import check_password_hash
from ..extensions import db, login_manager
from ..models import User

auth_bp = Blueprint("auth", __name__, template_folder="../templates")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@auth_bp.get("/login")
def login():
    return render_template("login.html")

@auth_bp.post("/login")
def login_post():
    email = request.form.get("email","").strip().lower()
    password = request.form.get("password","")
    u = User.query.filter_by(email=email).first()
    if not u or not check_password_hash(u.password_hash, password):
        flash("Invalid email or password", "danger")
        return redirect(url_for("auth.login"))
    if u.status != "active":
        flash("User is not active", "warning")
        return redirect(url_for("auth.login"))
    login_user(u, remember=True)
    return redirect(url_for("admin.dashboard"))

@auth_bp.get("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))
