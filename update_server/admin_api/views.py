from __future__ import annotations

import re
import secrets
from flask import Blueprint, request, jsonify, current_app
from sqlalchemy import select
from werkzeug.security import generate_password_hash

from ..extensions import db
from ..models import Tenant, User
from .auth import require_global_admin_key
from .schemas import TenantCreateDTO, UserCreateDTO

from sqlalchemy import select, text as sqltext

admin_api_bp = Blueprint("admin_api", __name__, url_prefix="/api/admin")

def _json():
    if not request.is_json:
        return None, (jsonify(error="bad-request", message="Content-Type must be application/json"), 415)
    return request.get_json(silent=True) or {}, None

def _slugify(s: str) -> str:
    s = s.strip().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    s = re.sub(r"^-+|-+$", "", s)
    return s or secrets.token_hex(4)

@admin_api_bp.route("/tenants", methods=["POST"])
@require_global_admin_key
def create_tenant():
    payload, err = _json()
    if err:
        return err
    name = (payload.get("name") or "").strip()
    slug = (payload.get("slug") or _slugify(name))
    active = bool(payload.get("active", True))
    if not name:
        return jsonify(error="validation", message="name is required"), 400

    existing = db.session.execute(select(Tenant).where(Tenant.name == name)).scalar_one_or_none()
    if existing:
        return jsonify(id=existing.id, name=existing.name, slug=existing.slug, status=existing.status), 200

    t = Tenant(name=name, slug=slug, status="active" if active else "disabled")
    db.session.add(t)
    db.session.commit()
    return jsonify(id=t.id, name=t.name, slug=t.slug, status=t.status), 201

@admin_api_bp.route("/tenants/<int:tenant_id>", methods=["DELETE"])
@require_global_admin_key
def delete_tenant(tenant_id: int):
    t = db.session.get(Tenant, tenant_id)
    if not t:
        return jsonify(error="not-found", message="tenant not found"), 404
    db.session.delete(t)
    db.session.commit()
    return jsonify(status="deleted", id=tenant_id), 200

@admin_api_bp.route("/tenants/<int:tenant_id>/enable", methods=["PATCH"])
@require_global_admin_key
def enable_tenant(tenant_id: int):
    t = db.session.get(Tenant, tenant_id)
    if not t:
        return jsonify(error="not-found", message="tenant not found"), 404
    t.status = "active"
    db.session.commit()
    return jsonify(id=t.id, status=t.status), 200

@admin_api_bp.route("/tenants/<int:tenant_id>/disable", methods=["PATCH"])
@require_global_admin_key
def disable_tenant(tenant_id: int):
    t = db.session.get(Tenant, tenant_id)
    if not t:
        return jsonify(error="not-found", message="tenant not found"), 404
    t.status = "disabled"
    db.session.commit()
    return jsonify(id=t.id, status=t.status), 200

@admin_api_bp.route("/tenants", methods=["GET"])
@require_global_admin_key
def list_tenants():
    q = Tenant.query
    status = request.args.get("status")
    if status:
        q = q.filter(Tenant.status == status)
    items = q.order_by(Tenant.id.asc()).all()
    return jsonify([{"id": t.id, "name": t.name, "slug": t.slug, "status": t.status} for t in items]), 200

@admin_api_bp.route("/users", methods=["POST"])
@require_global_admin_key
def create_user():
    payload, err = _json()
    if err:
        return err
    email = (payload.get("email") or "").strip().lower()
    full_name = (payload.get("full_name") or "").strip() or None
    password = payload.get("password") or secrets.token_urlsafe(12)
    tenant_id = payload.get("tenant_id")
    active = bool(payload.get("active", True))

    if not email or tenant_id is None:
        return jsonify(error="validation", message="email and tenant_id are required"), 400

    if db.session.execute(select(User).where(User.email == email)).scalar_one_or_none():
        return jsonify(error="conflict", message="email already exists"), 409

    if not db.session.get(Tenant, tenant_id):
        return jsonify(error="not-found", message="tenant not found"), 404

    user = User(email=email, full_name=full_name, tenant_id=int(tenant_id),
                password_hash=generate_password_hash(password),
                status="active" if active else "disabled")
    db.session.add(user)
    db.session.commit()
    return jsonify(id=user.id, email=user.email, tenant_id=user.tenant_id, status=user.status, temp_password=password if payload.get("password") is None else None), 201

@admin_api_bp.route("/users/<int:user_id>", methods=["DELETE"])
@require_global_admin_key
def delete_user(user_id: int):
    u = db.session.get(User, user_id)
    if not u:
        return jsonify(error="not-found", message="user not found"), 404
    db.session.delete(u)
    db.session.commit()
    return jsonify(status="deleted", id=user_id), 200

@admin_api_bp.route("/users/<int:user_id>/enable", methods=["PATCH"])
@require_global_admin_key
def enable_user(user_id: int):
    u = db.session.get(User, user_id)
    if not u:
        return jsonify(error="not-found", message="user not found"), 404
    u.status = "active"
    db.session.commit()
    return jsonify(id=u.id, status=u.status), 200

@admin_api_bp.route("/users/<int:user_id>/disable", methods=["PATCH"])
@require_global_admin_key
def disable_user(user_id: int):
    u = db.session.get(User, user_id)
    if not u:
        return jsonify(error="not-found", message="user not found"), 404
    u.status = "disabled"
    db.session.commit()
    return jsonify(id=u.id, status=u.status), 200

@admin_api_bp.route("/users", methods=["GET"])
@require_global_admin_key
def list_users():
    from ..models import Tenant  # local import to avoid cycles
    q = db.session.query(User, Tenant).join(Tenant, User.tenant_id == Tenant.id, isouter=True)
    tenant_id = request.args.get("tenant_id")
    status = request.args.get("status")
    if tenant_id is not None:
        q = q.filter(User.tenant_id == int(tenant_id))
    if status:
        q = q.filter(User.status == status)
    rows = q.order_by(User.id.asc()).all()
    out = []
    for u, t in rows:
        out.append({
            "id": u.id,
            "email": u.email,
            "full_name": u.full_name,
            "status": u.status,
            "tenant_id": u.tenant_id,
            "tenant_name": getattr(t, "name", None) if t else None,
            "tenant_slug": getattr(t, "slug", None) if t else None,
        })
    return jsonify(out), 200

# NEW: Billing (admin-only) – get current cost & reset (upon payment)
# ---------------------------------------------------------------------
@admin_api_bp.get("/tenants/<int:tenant_id>/billing")
@require_global_admin_key
def tenant_billing_info(tenant_id: int):
    """
    Returns billing info for a tenant:
    - pricing_rate_cents (rate per device)
    - outstanding_cents (current cost)
    """
    t = db.session.get(Tenant, tenant_id)
    if not t:
        return jsonify(error="not-found", message="tenant not found"), 404

    row = db.session.execute(
        sqltext("SELECT pricing_rate_cents, outstanding_cents, name FROM tenant WHERE id=:id"),
        {"id": tenant_id},
    ).first()

    rate = int(row[0] or 0) if row else 0
    out = int(row[1] or 0) if row else 0
    name = row[2] if row else t.name

    resp = jsonify(
        {
            "tenant_id": tenant_id,
            "tenant_name": name,
            "currency": current_app.config.get("CURRENCY", "eur"),
            "rate_cents": rate,
            "rate": rate / 100,
            "outstanding_cents": out,
            "outstanding": out / 100,
        }
    )
    resp.headers["Cache-Control"] = "no-store"
    return resp, 200


@admin_api_bp.post("/tenants/<int:tenant_id>/billing/reset")
@require_global_admin_key
def tenant_billing_reset(tenant_id: int):
    """
    Resets the outstanding balance for a tenant to 0 (e.g., after payment).
    Optional JSON payload can include a 'note' or 'receipt' for your logs (not stored here).
    """
    t = db.session.get(Tenant, tenant_id)
    if not t:
        return jsonify(error="not-found", message="tenant not found"), 404

    payload, err = _json()
    if err and request.data:
        # if body exists but bad content-type
        return err

    # read previous outstanding
    row = db.session.execute(
        sqltext("SELECT COALESCE(outstanding_cents,0) FROM tenant WHERE id=:id"),
        {"id": tenant_id},
    ).first()
    prev_out = int(row[0] or 0) if row else 0

    # reset to zero
    db.session.execute(
        sqltext("UPDATE tenant SET outstanding_cents=0 WHERE id=:id"),
        {"id": tenant_id},
    )
    db.session.commit()

    resp = jsonify(
        {
            "tenant_id": tenant_id,
            "previous_outstanding_cents": prev_out,
            "previous_outstanding": prev_out / 100,
            "new_outstanding_cents": 0,
            "new_outstanding": 0.0,
            "note": (payload or {}).get("note"),
            "receipt": (payload or {}).get("receipt"),
        }
    )
    resp.headers["Cache-Control"] = "no-store"
    return resp, 200
