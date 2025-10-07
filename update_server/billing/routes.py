# update_server/billing/routes.py
from __future__ import annotations

import decimal
from flask import current_app, request, jsonify, abort, g, session as flask_session
from flask_login import login_required, current_user
from sqlalchemy.orm import Session
from sqlalchemy import text as sqltext
from update_server.extensions import db

try:
    from update_server.extensions import csrf
except Exception:
    csrf = None

from update_server.models import Tenant
from . import billing_bp



# ---------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------
def _s() -> Session:
    return db.session


def _tenant_or_404(s: Session, tenant_id: int) -> Tenant:
    t = s.get(Tenant, tenant_id)
    if not t:
        abort(404, "Tenant not found")
    return t


def _is_admin() -> bool:
    roles = getattr(g, "roles", None) or getattr(current_user, "roles", None) or []
    if isinstance(roles, str):
        roles = [r.strip() for r in roles.split(",")]
    try:
        return "Admin" in roles
    except Exception:
        return False


def _get_rate_outstanding(s: Session, tenant_id: int) -> tuple[int, int]:
    row = s.execute(
        sqltext("SELECT pricing_rate_cents, outstanding_cents FROM tenant WHERE id=:id"),
        {"id": tenant_id},
    ).first()
    if not row:
        return 0, 0
    rate = int(row[0] or 0)
    out = int(row[1] or 0)
    return rate, out


def _set_outstanding(s: Session, tenant_id: int, value: int):
    s.execute(
        sqltext("UPDATE tenant SET outstanding_cents=:v WHERE id=:id"),
        {"v": int(value), "id": tenant_id},
    )
    s.commit()


def _set_rate(s: Session, tenant_id: int, cents: int):
    s.execute(
        sqltext("UPDATE tenant SET pricing_rate_cents=:v WHERE id=:id"),
        {"v": int(cents), "id": tenant_id},
    )
    s.commit()


# Determine the effective tenant for user-facing JSON endpoint safely.
def _effective_tenant_id_for_user() -> int:
    qs_tid = request.args.get("tenant_id", type=int)
    user_tid = getattr(current_user, "tenant_id", None)
    is_admin = _is_admin()

    # If a tenant_id is explicitly requested:
    if qs_tid is not None:
        if is_admin:
            return int(qs_tid)
        if user_tid and int(user_tid) == int(qs_tid):
            return int(qs_tid)
        abort(403, "forbidden_tenant")

    tid = (
        (user_tid if user_tid is not None else None)
        or getattr(g, "tenant_ctx_id", None)
        or flask_session.get("tenant_ctx_id")
    )
    try:
        return int(tid) if tid is not None else 0
    except Exception:
        return 0


# ---------------------------------------------------------------------
# Bind tenant context from session for convenience
# ---------------------------------------------------------------------
@billing_bp.before_app_request
def _bind_tenant_ctx_from_session():
    try:
        if not getattr(g, "tenant_ctx_id", None):
            g.tenant_ctx_id = flask_session.get("tenant_ctx_id") or getattr(current_user, "tenant_id", None)
    except Exception:
        pass


# ---------------------------------------------------------------------
# Admin JSON endpoints (no templates here)
# ---------------------------------------------------------------------
@billing_bp.post("/admin/set_rate")
@login_required
def admin_set_rate():
    tenant_id = request.values.get("tenant_id", type=int)
    rate_eur = request.values.get("rate_eur")
    if not tenant_id or rate_eur is None:
        abort(400, "tenant_id and rate_eur required")
    try:
        cents = int(decimal.Decimal(rate_eur) * 100)
        if cents < 0:
            raise ValueError()
    except Exception:
        abort(400, "invalid rate_eur")
    s = _s()
    _tenant_or_404(s, tenant_id)
    _set_rate(s, tenant_id, cents)
    resp = jsonify({"ok": True, "tenant_id": tenant_id, "rate_cents": cents, "rate": cents / 100})
    resp.headers["Cache-Control"] = "no-store"
    return resp


@billing_bp.get("/admin/get_rate")
@login_required
def admin_get_rate():
    tenant_id = request.args.get("tenant_id", type=int)
    if not tenant_id:
        abort(400, "tenant_id required")
    s = _s()
    t = _tenant_or_404(s, tenant_id)
    rate, _ = _get_rate_outstanding(s, tenant_id)
    resp = jsonify({"tenant_id": t.id, "tenant_name": t.name, "rate_cents": rate, "rate": rate / 100})
    resp.headers["Cache-Control"] = "no-store"
    return resp


@billing_bp.get("/admin/current_cost")
@login_required
def admin_current_cost():
    tenant_id = request.args.get("tenant_id", type=int)
    if not tenant_id:
        abort(400, "tenant_id required")
    s = _s()
    t = _tenant_or_404(s, tenant_id)
    rate, out = _get_rate_outstanding(s, tenant_id)
    resp = jsonify(
        {
            "tenant_id": t.id,
            "tenant_name": t.name,
            "currency": current_app.config.get("CURRENCY", "eur"),
            "rate_cents": rate,
            "outstanding_cents": out,
            "rate": rate / 100,
            "outstanding": out / 100,
        }
    )
    resp.headers["Cache-Control"] = "no-store"
    return resp


@billing_bp.get("/admin/totals")
@login_required
def admin_totals():
    if not _is_admin():
        abort(403)
    s = _s()
    rows = s.execute(
        sqltext(
            """
            SELECT id AS tenant_id, name AS tenant_name,
                   COALESCE(outstanding_cents,0) AS outstanding_cents,
                   COALESCE(pricing_rate_cents,0) AS pricing_rate_cents
            FROM tenant
            ORDER BY name
            """
        )
    ).mappings().all()
    total_outstanding = sum(int(r["outstanding_cents"] or 0) for r in rows)
    resp = jsonify(
        {
            "total_outstanding_cents": total_outstanding,
            "total_outstanding": total_outstanding / 100,
            "tenants": [
                {
                    "tenant_id": int(r["tenant_id"]),
                    "tenant_name": r["tenant_name"],
                    "outstanding_cents": int(r["outstanding_cents"] or 0),
                    "outstanding": (int(r["outstanding_cents"] or 0)) / 100,
                    "rate_cents": int(r["pricing_rate_cents"] or 0),
                    "rate": (int(r["pricing_rate_cents"] or 0)) / 100,
                }
                for r in rows
            ],
        }
    )
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ---------------------------------------------------------------------
# User-facing JSON endpoint (rate + outstanding for current tenant)
# ---------------------------------------------------------------------
@billing_bp.get("/user/price_and_cost")
@login_required
def user_price_and_cost():
    s: Session = db.session
    tenant_id = _effective_tenant_id_for_user()
    tenant_name = None

    if tenant_id:
        t = _tenant_or_404(s, tenant_id)
        tenant_name = t.name
        rate_cents, outstanding_cents = _get_rate_outstanding(s, tenant_id)
    else:
        rate_cents = 0
        outstanding_cents = 0

    resp = jsonify({
        "tenant_id": tenant_id or None,
        "tenant_name": tenant_name,
        "rate_cents": int(rate_cents or 0),
        "rate": (int(rate_cents or 0)) / 100,
        "outstanding_cents": int(outstanding_cents or 0),
        "outstanding": (int(outstanding_cents or 0)) / 100,
    })
    resp.headers["Cache-Control"] = "no-store"
    return resp



# ---------------------------------------------------------------------
# Machine endpoint (no login): increment outstanding by one device-update rate
# ---------------------------------------------------------------------
@billing_bp.post("/device_update_charge")
#@login_required
#@require_global_admin_key
def device_update_charge():
    tenant_id = request.values.get("tenant_id", type=int)
    device_id = request.values.get("deviceId")
    if not tenant_id or not device_id:
        abort(400, "tenant_id and deviceId required")
    s = _s()
    _tenant_or_404(s, tenant_id)
    rate, out = _get_rate_outstanding(s, tenant_id)
    new_out = out + rate
    _set_outstanding(s, tenant_id, new_out)
    resp = jsonify({"ok": True, "tenant_id": tenant_id, "charged_cents": rate, "outstanding_cents": new_out})
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ---------------------------------------------------------------------
# CSRF exemptions for machine endpoints
# ---------------------------------------------------------------------
if csrf:
    try:
        csrf.exempt(device_update_charge)
    except Exception:
        pass
