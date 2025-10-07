# update_server/billing/routes_admin_ui.py
from __future__ import annotations

import decimal
from dataclasses import dataclass

from flask import render_template, request, redirect, url_for, flash, abort
from flask_login import login_required
from sqlalchemy.orm import Session
from sqlalchemy import select, text as sqltext

from update_server.extensions import db
from update_server.models import Tenant
from . import billing_bp

try:
    from flask_wtf.csrf import generate_csrf
except Exception:  # pragma: no cover
    generate_csrf = lambda: ""  # type: ignore


# ---------------------------
# Helpers
# ---------------------------
def _s() -> Session:
    return db.session


def _tenant_or_404(s: Session, tenant_id: int) -> Tenant:
    t = s.get(Tenant, tenant_id)
    if not t:
        abort(404, "Tenant not found")
    return t


def _get_rate_cents(s: Session, tenant_id: int) -> int:
    row = s.execute(
        sqltext("SELECT pricing_rate_cents FROM tenant WHERE id=:id"),
        {"id": tenant_id},
    ).first()
    return int(row[0]) if row and row[0] is not None else 0


def _set_rate_cents(s: Session, tenant_id: int, cents: int) -> None:
    s.execute(
        sqltext("UPDATE tenant SET pricing_rate_cents=:c WHERE id=:id"),
        {"c": int(cents), "id": tenant_id},
    )
    s.commit()


def _reset_outstanding_to_zero(s: Session, tenant_id: int) -> None:
    s.execute(
        sqltext("UPDATE tenant SET outstanding_cents=0 WHERE id=:id"),
        {"id": tenant_id},
    )
    s.commit()


@dataclass
class Pagination:
    page: int
    per: int
    total: int

    @property
    def pages(self) -> int:
        if self.per <= 0:
            return 1
        return (self.total + self.per - 1) // self.per

    @property
    def has_prev(self) -> bool:
        return self.page > 1

    @property
    def has_next(self) -> bool:
        return self.page < self.pages


# ---------------------------
# Admin UI routes
# ---------------------------
@billing_bp.get("/admin/billing")
@login_required
def admin_billing_page():
    """
    Admin pricing console:
      - Select tenant
      - Edit rate
      - Reset outstanding
      - Table with all tenants + pagination
    """
    s = _s()

    # List of tenants for the dropdown
    tenants = s.execute(select(Tenant).order_by(Tenant.name.asc())).scalars().all()
    if not tenants:
        abort(404, "No tenants")

    # Selected tenant (from query or first)
    tenant_id = request.args.get("tenant_id", type=int) or tenants[0].id
    tenant = _tenant_or_404(s, tenant_id)
    rate_cents = _get_rate_cents(s, tenant.id)

    # Pagination for the table
    page = request.args.get("page", type=int) or 1
    per = request.args.get("per", type=int) or 10
    if per not in (10, 20, 30, 50):
        per = 10
    if page < 1:
        page = 1
    offset = (page - 1) * per

    total = s.execute(sqltext("SELECT COUNT(*) FROM tenant")).scalar() or 0

    rows = s.execute(
        sqltext(
            """
            SELECT id AS tenant_id,
                   name AS tenant_name,
                   COALESCE(pricing_rate_cents,0) AS rate_cents,
                   COALESCE(outstanding_cents,0) AS outstanding_cents
            FROM tenant
            ORDER BY name
            LIMIT :lim OFFSET :off
            """
        ),
        {"lim": per, "off": offset},
    ).mappings().all()

    pagination = Pagination(page=page, per=per, total=int(total))

    # NOTE: template path is relative to blueprint's template_folder
    return render_template(
        "admin_billing.html",
        tenants=tenants,
        tenant=tenant,
        rate_eur=rate_cents / 100,
        rows=rows,
        pagination=pagination,
        csrf_token=generate_csrf(),
    )


@billing_bp.post("/admin/billing/save")
@login_required
def admin_billing_save():
    """Save rate for the selected tenant."""
    tenant_id = request.form.get("tenant_id", type=int)
    rate_eur = request.form.get("rate_eur")
    if not tenant_id or rate_eur is None:
        abort(400, "tenant_id and rate_eur required")

    try:
        cents = int(decimal.Decimal(rate_eur) * 100)
        if cents < 0:
            raise ValueError()
    except Exception:
        flash("Invalid rate value", "warning")
        return redirect(url_for("billing.admin_billing_page", tenant_id=tenant_id))

    s = _s()
    _tenant_or_404(s, tenant_id)
    _set_rate_cents(s, tenant_id, cents)
    flash("Pricing updated", "success")
    return redirect(url_for("billing.admin_billing_page", tenant_id=tenant_id))


@billing_bp.post("/admin/billing/reset")
@login_required
def admin_reset_outstanding():
    """Reset outstanding to 0 for the selected tenant."""
    tenant_id = request.form.get("tenant_id", type=int)
    if not tenant_id:
        abort(400, "tenant_id required")

    s = _s()
    _tenant_or_404(s, tenant_id)
    _reset_outstanding_to_zero(s, tenant_id)
    flash("Outstanding reset to 0.00 EUR", "success")
    return redirect(url_for("billing.admin_billing_page", tenant_id=tenant_id))
