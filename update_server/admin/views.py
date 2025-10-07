# update_server/admin/views.py
from __future__ import annotations

"""
Admin UI routes (Flask Blueprint).

Goals of this refactor:
- Keep **exact** behavior, only improve structure, comments, and readability.
- Centralize multitenancy/RBAC helpers (derive effective tenant, scope checks).
- Make tenant scoping explicit for list/data endpoints.
- Keep backward-compat endpoint aliases (e.g., admin.packages) so templates don't break.
- Add robust artifact handling & safe deletes (with fallbacks if helpers are missing).
"""

# ──────────────────────────────────────────────────────────────────────────────
# Standard library
# ──────────────────────────────────────────────────────────────────────────────
import re
import json
import datetime as dt
import secrets
import hashlib
from pathlib import Path
from typing import Optional, Set

from flask import request, render_template, url_for
from flask_login import login_required, current_user
from sqlalchemy import func, or_, literal_column
import datetime as dt


from update_server.roles import require_roles
from update_server.extensions import db
from update_server.models import Device, Tenant, Package, Rollout

# ──────────────────────────────────────────────────────────────────────────────
# Flask / Extensions
# ──────────────────────────────────────────────────────────────────────────────
from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    current_app,
    send_from_directory,
    abort,
)
from werkzeug.utils import secure_filename
from flask_login import login_required, current_user

from ..extensions import db
from ..roles import require_roles
from ..artifacts import sha256_of_file


# Optional helpers (present if you added them); safe fallbacks if import fails
try:
    from ..artifacts import safe_unlink, prune_empty_dirs  # type: ignore
except Exception:  # pragma: no cover
    def safe_unlink(path_str: str) -> bool:
        """
        Safely unlink a file only if it lives under configured artifacts roots.
        Returns True on deletion, False otherwise.
        """
        try:
            if not path_str:
                return False
            p = Path(path_str)
            if p.exists() and p.is_file():
                roots = [
                    Path(current_app.config.get("ARTIFACTS_ROOT", "instance/artifacts")).resolve(),
                    Path("artifacts").resolve(),
                ]
                rp = p.resolve()
                if any(str(rp).startswith(str(root)) for root in roots):
                    p.unlink()
                    return True
        except Exception:
            pass
        return False

    def prune_empty_dirs(start: Path, stop_at: Optional[Path] = None) -> None:
        """
        Walk upward from 'start' and remove empty directories until reaching a root.
        Non-fatal; best effort.
        """
        try:
            cur = Path(start).resolve()
            if cur.is_file():
                cur = cur.parent
        except Exception:
            return
        roots = [
            Path(current_app.config.get("ARTIFACTS_ROOT", "instance/artifacts")).resolve(),
            Path("artifacts").resolve(),
        ]
        if stop_at is not None:
            roots.append(Path(stop_at).resolve())

        while True:
            try:
                if not cur.exists():
                    break
                if any(cur.iterdir()):
                    break
                parent = cur.parent
                cur.rmdir()
                if parent == cur:
                    break
                cur = parent
                if not any(str(cur).startswith(str(root)) for root in roots):
                    break
            except Exception:
                break

# ──────────────────────────────────────────────────────────────────────────────
# Models
# ──────────────────────────────────────────────────────────────────────────────
from ..models import (
    Tenant,
    Fleet,
    Device,
    Package,
    PackageVersion,
    Rollout,
    RolloutTarget,
    DeviceInstallation,
    User,
    Role,
    UserRole,
)

# Optional: nudge the scheduler after rollout changes
try:
    from ..tasks.scheduler import run_tick  # type: ignore
    _CAN_NUDGE_SCHED = True
except Exception:
    _CAN_NUDGE_SCHED = False

# ──────────────────────────────────────────────────────────────────────────────
# Blueprint
# ──────────────────────────────────────────────────────────────────────────────
admin_bp = Blueprint(
    "admin",
    __name__,
    template_folder="../templates",
    static_folder="../static",
)

@admin_bp.app_context_processor
def inject_nav_counts():
    # Default zeros
    data = {"tenants": 0, "devices": 0, "packages": 0, "rollouts": 0}

    try:
        from ..models import Tenant, Device, Package, Rollout
        from flask_login import current_user

        def _tids_for_user(uid: int):
            rows = (
                db.session.query(UserRole.tenant_id)
                .filter(UserRole.user_id == uid, UserRole.tenant_id.isnot(None))
                .all()
            )
            return {tid for (tid,) in rows if tid is not None}

        is_admin = False
        try:
            # cheap role check
            names = (
                db.session.query(Role.name)
                .join(UserRole, Role.id == UserRole.role_id)
                .filter(UserRole.user_id == current_user.id)
                .all()
            )
            is_admin = any(n == ("Admin",)[0] for n in names)
        except Exception:
            pass

        if is_admin:
            data["tenants"]  = db.session.query(Tenant).count()
            data["devices"]  = db.session.query(Device).count()
            data["packages"] = db.session.query(Package).count()
            data["rollouts"] = db.session.query(Rollout).count()
        else:
            tids = _tids_for_user(current_user.id)
            if tids:
                data["tenants"]  = db.session.query(Tenant).filter(Tenant.id.in_(tids)).count()
                data["devices"]  = db.session.query(Device).filter(Device.tenant_id.in_(tids)).count()
                data["packages"] = db.session.query(Package).filter(Package.tenant_id.in_(tids)).count()
                data["rollouts"] = db.session.query(Rollout).filter(Rollout.tenant_id.in_(tids)).count()
    except Exception:
        pass

    return {"nav_counts": data}


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║ RBAC / Multitenancy helpers                                              ║
# ╚══════════════════════════════════════════════════════════════════════════╝
def _user_role_names(user_id: int) -> Set[str]:
    """
    Return the set of role names for the user.
    """
    rows = (
        db.session.query(Role.name)
        .join(UserRole, Role.id == UserRole.role_id)
        .filter(UserRole.user_id == user_id)
        .all()
    )
    return {name for (name,) in rows}





def _user_tenant_ids(user_id: int) -> Set[int]:
    """
    Return tenant IDs the user is scoped to (empty set if none).
    Admins are considered global (empty set doesn't imply admin; use _is_admin()).
    """
    rows = (
        db.session.query(UserRole.tenant_id)
        .filter(UserRole.user_id == user_id, UserRole.tenant_id.isnot(None))
        .all()
    )
    return {tid for (tid,) in rows if tid is not None}


def _is_admin(user_id: int) -> bool:
    """
    Whether the user has the 'Admin' role.
    """
    return "Admin" in _user_role_names(user_id)


def _effective_tenant_id_for_user_or_403() -> int:
    """
    Resolve a single effective tenant for the current user.

    Rules:
      - If the user has roles for exactly one tenant, use it.
      - Else, if the user model has tenant_id set, use it.
      - Else, abort 403 (no unambiguous tenant context).
    """
    urs = UserRole.query.filter_by(user_id=current_user.id).all()
    tids = sorted({ur.tenant_id for ur in urs if ur.tenant_id is not None})
    if len(tids) == 1:
        return tids[0]
    if getattr(current_user, "tenant_id", None):
        return current_user.tenant_id
    abort(403, description="No tenant context for this user")


def _must_be_in_scope(tenant_id: int) -> None:
    """
    Abort 403 if a non-admin user tries to act outside their tenant scope.
    """
    if _is_admin(current_user.id):
        return
    allowed = _user_tenant_ids(current_user.id)
    if tenant_id not in allowed:
        abort(403, description="Out-of-tenant scope")


def _filter_by_scope(model, tenant_field):
    """
    Return a query filtered by the caller's tenant scope unless the user is Admin.
    For non-admins with no tenants, return a query that matches nothing.
    """
    if _is_admin(current_user.id):
        return db.session.query(model)
    tids = _user_tenant_ids(current_user.id)
    if not tids:
        return db.session.query(model).filter(False)
    return db.session.query(model).filter(getattr(model, tenant_field).in_(tids))


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║ Misc helpers                                                             ║
# ╚══════════════════════════════════════════════════════════════════════════╝
def _artifacts_root() -> Path:
    """
    Root directory for stored artifacts.
    """
    return Path(current_app.config.get("ARTIFACTS_ROOT", "instance/artifacts"))


def _parse_version_from_filename(filename: str) -> str:
    """
    Heuristic: try to extract semver-looking suffix from filename stem;
    fallback to the stem if no match.
    """
    stem = Path(filename).stem
    m = re.search(r"(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9\.-]+)?)$", stem)
    return m.group(1) if m else stem


def _ensure_package(tenant_id: int, name: str) -> Package:
    """
    Get-or-create a Package by (tenant_id, name).
    """
    pkg = Package.query.filter_by(tenant_id=tenant_id, name=name).first()
    if not pkg:
        pkg = Package(tenant_id=tenant_id, name=name, description="")
        db.session.add(pkg)
        db.session.commit()
    return pkg


def _artifact_dest_for(tenant_id: int, package_id: int, semver: str, filename: str) -> Path:
    """
    Deterministic artifact path:
      ARTIFACTS_ROOT/<tenant>/<package_id>/<semver>.<ext>
    """
    root = _artifacts_root()
    dest_dir = root / str(tenant_id) / str(package_id)
    dest_dir.mkdir(parents=True, exist_ok=True)
    ext = Path(filename).suffix or ".zip"
    return dest_dir / f"{semver}{ext}"


def _nudge_scheduler():
    """
    Best-effort scheduler nudge (no hard failure).
    """
    if _CAN_NUDGE_SCHED:
        try:
            from flask import current_app as _app
            run_tick(_app)
        except Exception:
            pass


def _sanitize_policy_json(raw: str) -> str:
    """
    Normalize/sanitize rollout policy JSON:
      - Ensure dict.
      - Coerce/validate keys: waveIndex, allowedWeekdays, throttleSeconds,
        deferOutsideWindow, maxRetriesPerDevice, minAgentVersion.
      - Produce compact JSON string.
    """
    try:
        pol = json.loads(raw) if raw and raw.strip() else {}
        if not isinstance(pol, dict):
            pol = {}
    except Exception:
        pol = {}

    pol.setdefault("waveIndex", 0)

    aw = pol.get("allowedWeekdays")
    if isinstance(aw, list):
        cleaned = []
        for x in aw:
            try:
                v = int(x)
                if 1 <= v <= 7:
                    cleaned.append(v)
            except Exception:
                pass
        if cleaned:
            pol["allowedWeekdays"] = cleaned
        else:
            pol.pop("allowedWeekdays", None)
    else:
        pol.pop("allowedWeekdays", None)

    ts = pol.get("throttleSeconds")
    try:
        ts = int(ts)
        ts = max(0, ts)
        if ts > 0:
            pol["throttleSeconds"] = ts
        else:
            pol.pop("throttleSeconds", None)
    except Exception:
        pol.pop("throttleSeconds", None)

    pol["deferOutsideWindow"] = bool(pol.get("deferOutsideWindow", True))

    mrd = pol.get("maxRetriesPerDevice")
    try:
        mrd = int(mrd)
        if mrd >= 0:
            pol["maxRetriesPerDevice"] = mrd
        else:
            pol.pop("maxRetriesPerDevice", None)
    except Exception:
        pol.pop("maxRetriesPerDevice", None)

    if "minAgentVersion" in pol:
        v = pol.get("minAgentVersion")
        if isinstance(v, str) and v.strip():
            pol["minAgentVersion"] = v.strip()
        else:
            pol.pop("minAgentVersion", None)

    return json.dumps(pol, separators=(",", ":"))


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║ Dashboard (tenant-scoped counts for non-admins)                          ║
# ╚══════════════════════════════════════════════════════════════════════════╝
# update_server/admin/views.py

@admin_bp.get("/")
@login_required
@require_roles("Viewer", "Ops", "Admin")
def dashboard():
    """
    Admin: global counts + όλα τα connected devices (paginated).
    Non-admin: counts & connected devices scoped στους tenant(s) του χρήστη.
    Υποστηρίζει αναζήτηση ?q= (ID ή μέρος IP) και pagination ?page=&per=.
    """
    # --- pagination & search params ---
    page = request.args.get("page", default=1, type=int)
    per_page = request.args.get("per", default=10, type=int)
    per_page = max(5, min(per_page, 50))
    q = (request.args.get("q") or "").strip()

    # --- connected window (τελευταία 5') ---
    now = dt.datetime.utcnow()
    connected_since = now - dt.timedelta(minutes=5)

    # --- δυναμικός εντοπισμός IP columns στο Device ---
    ip_columns = []
    for attr in ("ip", "ip_address", "last_ip", "last_seen_ip"):
        if hasattr(Device, attr):
            ip_columns.append(getattr(Device, attr))

    # ασφαλές ip_eff για SQLite: 0/1/≥2 ορίσματα
    if len(ip_columns) == 0:
        ip_eff = literal_column("NULL")
    elif len(ip_columns) == 1:
        ip_eff = ip_columns[0]
    else:
        ip_eff = func.coalesce(*ip_columns)

    # --- counts & base query, με scoping ανά ρόλο ---
    if _is_admin(current_user.id):
        tenants = db.session.query(func.count(Tenant.id)).scalar()
        devices = db.session.query(func.count(Device.id)).scalar()
        pkgs = db.session.query(func.count(Package.id)).scalar()
        rollouts = db.session.query(func.count(Rollout.id)).scalar()

        base = (
            db.session.query(
                Device,
                ip_eff.label("ip_eff"),
                Tenant.name.label("tenant_name"),
                Tenant.slug.label("tenant_slug"),
            )
            .outerjoin(Tenant, Device.tenant_id == Tenant.id)
            .filter(Device.last_seen_at >= connected_since)
        )
    else:
        tids = _user_tenant_ids(current_user.id)
        if not tids:
            tenants = devices = pkgs = rollouts = 0
            base = (
                db.session.query(
                    Device,
                    ip_eff.label("ip_eff"),
                    Tenant.name.label("tenant_name"),
                    Tenant.slug.label("tenant_slug"),
                )
                .outerjoin(Tenant, Device.tenant_id == Tenant.id)
                .filter(False)  # empty set
            )
        else:
            tenants = db.session.query(func.count(Tenant.id)).filter(Tenant.id.in_(tids)).scalar()
            devices = db.session.query(func.count(Device.id)).filter(Device.tenant_id.in_(tids)).scalar()
            pkgs = db.session.query(func.count(Package.id)).filter(Package.tenant_id.in_(tids)).scalar()
            rollouts = db.session.query(func.count(Rollout.id)).filter(Rollout.tenant_id.in_(tids)).scalar()

            base = (
                db.session.query(
                    Device,
                    ip_eff.label("ip_eff"),
                    Tenant.name.label("tenant_name"),
                    Tenant.slug.label("tenant_slug"),
                )
                .outerjoin(Tenant, Device.tenant_id == Tenant.id)
                .filter(Device.tenant_id.in_(tids), Device.last_seen_at >= connected_since)
            )

    # --- search filter (ID ή IP) ---
    if q:
        if q.isdigit():
            base = base.filter(Device.id == int(q))
        else:
            ql = f"%{q.lower()}%"
            like_clauses = [func.lower(col).like(ql) for col in ip_columns]
            if like_clauses:
                base = base.filter(or_(*like_clauses))
            else:
                # αν δεν υπάρχουν IP columns δεν μπορεί να εφαρμοστεί IP search
                base = base.filter(False)

    # --- ordering, pagination ---
    base = base.order_by(Device.last_seen_at.desc())
    total = base.count()
    rows = base.offset((page - 1) * per_page).limit(per_page).all()

    items = [
        {"device": d, "ip_eff": ip, "tenant_name": tn, "tenant_slug": ts}
        for (d, ip, tn, ts) in rows
    ]

    pages = (total + per_page - 1) // per_page
    has_prev = page > 1
    has_next = page < pages

    def _page_url(p: int) -> str:
        params = {"page": p, "per": per_page}
        if q:
            params["q"] = q
        return url_for("admin.dashboard", **params)

    devices_page = {
        "items": items,
        "page": page,
        "per_page": per_page,
        "total": total,
        "pages": pages,
        "has_prev": has_prev,
        "has_next": has_next,
        "prev_url": _page_url(page - 1) if has_prev else None,
        "next_url": _page_url(page + 1) if has_next else None,
    }

    return render_template(
        "dashboard.html",
        tenants=tenants,
        devices=devices,
        pkgs=pkgs,
        rollouts=rollouts,
        devices_page=devices_page,
        q=q,
    )




# ╔══════════════════════════════════════════════════════════════════════════╗
# ║ Tenants (Admins only)                                                    ║
# ╚══════════════════════════════════════════════════════════════════════════╝
@admin_bp.get("/tenants", endpoint="tenants")
@login_required
@require_roles("Admin")
def tenants_list():
    """
    List all tenants (Admin only).
    """
    
    items = Tenant.query.order_by(Tenant.id.asc()).all()
    return render_template("tenants.html", items=items)

# Extra endpoint names to be tolerant with templates
try:
    admin_bp.add_url_rule("/tenants", endpoint="tenants_list", view_func=tenants_list)
except Exception:
    pass

@admin_bp.post("/tenants")
@login_required
@require_roles("Admin")
def tenants_create():
    """
    Create a tenant with unique slug.
    """
    name = (request.form.get("name") or "").strip()
    slug = (request.form.get("slug") or "").strip()
    if not name or not slug:
        flash("Name & slug are required", "danger")
        return redirect(url_for("admin.tenants"))
    if Tenant.query.filter_by(slug=slug).first():
        flash("Slug already exists", "warning")
        return redirect(url_for("admin.tenants"))
    t = Tenant(name=name, slug=slug)
    db.session.add(t)
    db.session.commit()
    flash("Tenant created", "success")
    return redirect(url_for("admin.tenants"))


@admin_bp.post("/tenants/<int:t_id>/delete")
@login_required
@require_roles("Admin")
def tenant_delete(t_id):
    """
    Delete a tenant only if it has no devices or packages.
    """
    t = Tenant.query.get_or_404(t_id)
    if Device.query.filter_by(tenant_id=t.id).count() or Package.query.filter_by(tenant_id=t.id).count():
        flash("Cannot delete tenant with devices or packages", "warning")
        return redirect(url_for("admin.tenants"))
    db.session.delete(t)
    db.session.commit()
    flash("Tenant deleted", "success")
    return redirect(url_for("admin.tenants"))


@admin_bp.get("/tenants/<int:t_id>/edit")
@login_required
@require_roles("Admin")
def tenants_edit(t_id):
    """
    Edit tenant page.
    """
    t = Tenant.query.get_or_404(t_id)
    return render_template("tenant_edit.html", t=t)


@admin_bp.post("/tenants/<int:t_id>/edit")
@login_required
@require_roles("Admin")
def tenants_update(t_id):
    """
    Update tenant name/slug with uniqueness check.
    """
    t = Tenant.query.get_or_404(t_id)
    name = (request.form.get("name") or "").strip()
    slug = (request.form.get("slug") or "").strip()
    if not name or not slug:
        flash("Name & slug are required", "danger")
        return redirect(url_for("admin.tenants_edit", t_id=t.id))
    other = Tenant.query.filter(Tenant.slug == slug, Tenant.id != t.id).first()
    if other:
        flash("Slug already exists", "warning")
        return redirect(url_for("admin.tenants_edit", t_id=t.id))
    t.name = name
    t.slug = slug
    db.session.commit()
    flash("Tenant updated", "success")
    return redirect(url_for("admin.tenants"))


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║ Users (Admins only; each user must be tied to a tenant via UserRole)     ║
# ╚══════════════════════════════════════════════════════════════════════════╝
@admin_bp.get("/users")
@login_required
@require_roles("Admin")
def users_list():
    """
    List users + roles + tenants for creation UI.
    Συμπληρώνει προσωρινά τυχόν κενά user.tenant_id από UserRole.tenant_id,
    ώστε το template να εμφανίζει σωστά τον Tenant χωρίς αλλαγή δεδομένων.
    """
    from update_server.extensions import db
    from update_server.models import UserRole  # αποφεύγουμε κυκλικά imports

    users = User.query.order_by(User.id.asc()).all()
    roles = Role.query.order_by(Role.name.asc()).all()
    tenants = Tenant.query.order_by(Tenant.name.asc()).all()

    # Χτίσε map user_id -> tenant_id από UserRole (παίρνουμε τον πρώτο που βρεθεί)
    q = (
        db.session.query(UserRole.user_id, UserRole.tenant_id)
        .filter(UserRole.tenant_id.isnot(None))
    )
    ur_map = {}
    for uid, tid in q.all():
        if uid not in ur_map and tid is not None:
            ur_map[uid] = tid

    # Συμπλήρωσε προσωρινά μόνο για rendering (ΧΩΡΙΣ commit)
    for u in users:
        if getattr(u, "tenant_id", None) is None:
            tid = ur_map.get(u.id)
            if tid is not None:
                try:
                    # Θέλουμε μόνο να φανεί στο template· δεν κάνουμε persist.
                    object.__setattr__(u, "tenant_id", tid)
                except Exception:
                    # Fallback αν ο mapper μπλοκάρει object.__setattr__
                    setattr(u, "tenant_id", tid)

    return render_template("users.html", users=users, roles=roles, tenants=tenants)

# tolerant alias
try:
    admin_bp.add_url_rule("/users", endpoint="users", view_func=users_list)
except Exception:
    pass



@admin_bp.post("/users")
@login_required
@require_roles("Admin")
def users_create():
    """
    Create a user + assign initial role scoped to a tenant.

    Form accepts (with a few aliases tolerated):
      - email (required)
      - full_name (optional)
      - password (required)
      - role (Viewer/Ops/Admin; default Viewer)
      - tenant_id (required)  ← ensures scoping
    """
    form = request.form
    email = (form.get("email") or form.get("user_email") or "").strip().lower()
    name = (form.get("full_name") or form.get("name") or "").strip()
    password = (form.get("password") or form.get("password1") or form.get("pwd") or "").strip()
    role_name = (form.get("role") or "Viewer").strip()

    tenant_raw = form.get("tenant_id") or form.get("tenant")
    try:
        tenant_id = int(tenant_raw)
    except Exception:
        tenant_id = None

    if not email or not password or not tenant_id:
        flash("Email, password & tenant are required", "danger")
        return redirect(url_for("admin.users_list"))

    from werkzeug.security import generate_password_hash
    if User.query.filter_by(email=email).first():
        flash("Email already exists", "warning")
        return redirect(url_for("admin.users_list"))

    u = User(
        email=email,
        full_name=name,
        password_hash=generate_password_hash(password),
        status="active",
    )
    db.session.add(u)
    db.session.commit()

    r = Role.query.filter_by(name=role_name).first()
    if not r:
        r = Role(name=role_name)
        db.session.add(r)
        db.session.commit()

    db.session.add(UserRole(user_id=u.id, role_id=r.id, tenant_id=tenant_id))
    db.session.commit()

    flash("User created", "success")
    return redirect(url_for("admin.users_list"))


@admin_bp.post("/users/<int:user_id>/toggle")
@login_required
@require_roles("Admin")
def users_toggle(user_id):
    """
    Toggle user status active/disabled.
    """
    u = User.query.get_or_404(user_id)
    u.status = "disabled" if u.status == "active" else "active"
    db.session.commit()
    return redirect(url_for("admin.users_list"))


@admin_bp.post("/users/<int:user_id>/delete")
@login_required
@require_roles("Admin")
def users_delete(user_id):
    """
    Delete user (no cascade here; keep it simple).
    """
    u = User.query.get_or_404(user_id)
    db.session.delete(u)
    db.session.commit()
    flash("User deleted", "success")
    return redirect(url_for("admin.users_list"))


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║ Static assets / favicon                                                  ║
# ╚══════════════════════════════════════════════════════════════════════════╝
@admin_bp.get("/assets/<path:filename>")
def assets(filename):
    return send_from_directory(admin_bp.static_folder, filename)


@admin_bp.get("/favicon.ico")
def favicon():
    return ("", 204)


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║ Packages (Ops/Admin; tenant scoped)                                      ║
# ╚══════════════════════════════════════════════════════════════════════════╝
@admin_bp.get("/packages")
@login_required
@require_roles("Ops", "Admin")
def packages_list():
    """
    Show ONLY packages for the current user's effective tenant.
    """
    
    # HARD GUARD
    if _is_admin(current_user.id):
        abort(403, description="Admins cannot query devices")
    
    tenant_ctx_id = _effective_tenant_id_for_user_or_403()
    t = Tenant.query.get(tenant_ctx_id)
    tenant_ctx_name = t.name if t else f"#{tenant_ctx_id}"

    items = (
        Package.query
        .filter_by(tenant_id=tenant_ctx_id)
        .order_by(Package.id.desc())
        .all()
    )

    latest_sizes: dict[int, int] = {}
    latest_versions: dict[int, str] = {}
    version_counts: dict[int, int] = {}

    if items:
        pkg_ids = [p.id for p in items]

        # count versions per package
        rows = (
            db.session.query(PackageVersion.package_id, db.func.count(PackageVersion.id))
            .filter(PackageVersion.package_id.in_(pkg_ids))
            .group_by(PackageVersion.package_id)
            .all()
        )
        version_counts = {pid: cnt for pid, cnt in rows}

        # latest version per package
        subq = (
            db.session.query(
                PackageVersion.package_id,
                db.func.max(PackageVersion.id).label("max_id"),
            )
            .filter(PackageVersion.package_id.in_(pkg_ids))
            .group_by(PackageVersion.package_id)
            .subquery()
        )
        latest = (
            db.session.query(PackageVersion)
            .join(subq, PackageVersion.id == subq.c.max_id)
            .all()
        )
        for pv in latest:
            latest_sizes[pv.package_id] = pv.size_bytes or 0
            latest_versions[pv.package_id] = pv.semver

    return render_template(
        "packages.html",
        items=items,
        latest_sizes=latest_sizes,
        latest_versions=latest_versions,
        version_counts=version_counts,
        tenant_ctx_id=tenant_ctx_id,
        tenant_ctx_name=tenant_ctx_name,
    )


@admin_bp.post("/packages/upload")
@login_required
@require_roles("Ops", "Admin")
def packages_upload():
    """
    Upload a package artifact bound to the *current user's tenant*.

    - Ignores any tenant_id coming from the form.
    - Ensures Package by (tenant_id, name).
    - Stores file at: ARTIFACTS_ROOT/<tenant>/<package_id>/<semver>.<ext>
    - Upserts PackageVersion with sha256 and size.
    """
    
    # HARD GUARD
    if _is_admin(current_user.id):
        abort(403, description="Admins cannot query devices")
    
    # Resolve tenant from current user (strict)
    urs = UserRole.query.filter_by(user_id=current_user.id).all()
    tids = sorted({ur.tenant_id for ur in urs if ur.tenant_id is not None})
    tenant_id = None
    if len(tids) == 1:
        tenant_id = tids[0]
    elif getattr(current_user, "tenant_id", None):
        tenant_id = current_user.tenant_id
    else:
        flash("Your account has no single-tenant assignment; cannot upload.", "danger")
        return redirect(url_for("admin.packages_list"))

    # Form fields (tenant is ignored)
    package_name = (request.form.get("name") or "").strip()
    if not package_name:
        flash("Package name is required", "danger")
        return redirect(url_for("admin.packages_list"))

    semver = (request.form.get("version") or "").strip()
    description = (request.form.get("description") or "").strip()
    file = request.files.get("file")

    if not file or file.filename == "":
        flash("Choose a .zip file to upload", "danger")
        return redirect(url_for("admin.packages_list"))

    fname = secure_filename(file.filename)
    if not semver:
        # Fallback: parse from filename if user didn’t provide version
        semver = _parse_version_from_filename(fname)

    # Ensure/create Package
    pkg = _ensure_package(tenant_id, package_name)
    if description:
        try:
            pkg.description = description
            db.session.commit()
        except Exception:
            db.session.rollback()
            flash("Could not update package description", "warning")

    # Decide final artifact path (deterministic)
    dest_path = _artifact_dest_for(tenant_id, pkg.id, semver, fname)
    dest_path.parent.mkdir(parents=True, exist_ok=True)

    # Save to temp then atomically move to final
    tmp_path = dest_path.with_suffix(dest_path.suffix + ".part")
    file.save(tmp_path)
    tmp_path.replace(dest_path)

    # Compute hash/size
    h = sha256_of_file(str(dest_path))
    size = dest_path.stat().st_size

    # Upsert PackageVersion
    pv = (
        PackageVersion.query
        .filter_by(package_id=pkg.id, semver=semver)
        .first()
    )
    if not pv:
        pv = PackageVersion(
            package_id=pkg.id,
            semver=semver,
            hash_sha256=h,
            size_bytes=size,
            signed=False,
            release_notes="",
            storage_path=str(dest_path),
            created_at=dt.datetime.utcnow(),
        )
        db.session.add(pv)
    else:
        pv.hash_sha256 = h
        pv.size_bytes = size
        pv.storage_path = str(dest_path)
    db.session.commit()

    mb = f"{size/1048576.0:.1f} MB"
    flash(f"Uploaded v{semver} for '{pkg.name}' (sha256 {h[:8]}…, {mb})", "success")
    return redirect(url_for("admin.packages_list"))


@admin_bp.post("/packages/<int:p_id>/delete")
@login_required
@require_roles("Ops", "Admin")
def package_delete(p_id):
    """
    Delete a package and all its versions/artifacts (tenant-scoped for non-admin).
    """
    # HARD GUARD
    if _is_admin(current_user.id):
        abort(403, description="Admins cannot query devices")
        
    p = Package.query.get_or_404(p_id)
    if not _is_admin(current_user.id):
        _must_be_in_scope(p.tenant_id)

    pvs = PackageVersion.query.filter_by(package_id=p.id).all()
    removed = 0
    for pv in pvs:
        path = getattr(pv, "storage_path", None) or getattr(pv, "file_path", None)
        if path and safe_unlink(path):
            removed += 1
        db.session.delete(pv)

    db.session.delete(p)
    db.session.commit()

    root = _artifacts_root()
    prune_empty_dirs(root / str(p.tenant_id) / str(p.id))
    flash(f"Package and versions deleted (removed {removed} file(s))", "success")
    return redirect(url_for("admin.packages_list"))


@admin_bp.post("/packages/<int:p_id>/versions/<int:pv_id>/delete")
@login_required
@require_roles("Ops", "Admin")
def package_version_delete(p_id, pv_id):
    """
    Delete a single package version (and its artifact if present).
    """
    # HARD GUARD
    if _is_admin(current_user.id):
        abort(403, description="Admins cannot query devices")
    
    pv = PackageVersion.query.filter_by(id=pv_id, package_id=p_id).first_or_404()
    pkg = Package.query.get(p_id)
    if pkg and not _is_admin(current_user.id):
        _must_be_in_scope(pkg.tenant_id)

    path = getattr(pv, "storage_path", None) or getattr(pv, "file_path", None)
    db.session.delete(pv)
    db.session.commit()

    removed = False
    if path:
        removed = safe_unlink(path)
        try:
            prune_empty_dirs(Path(path).parent)
        except Exception:
            pass
    flash(f"Version deleted. Artifact removed: {'yes' if removed else 'no'}", "success")
    return redirect(url_for("admin.packages_list"))


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║ Rollouts (Ops/Admin; tenant scoped)                                      ║
# ╚══════════════════════════════════════════════════════════════════════════╝
@admin_bp.get("/rollouts")
@login_required
@require_roles("Ops", "Admin", "Viewer")  # viewers may view list
def rollouts_list():
    """
    List rollouts in scope; show package name alongside.
    """
    q = _filter_by_scope(Rollout, "tenant_id")
    items = q.order_by(Rollout.id.desc()).all()
    data = []
    for r in items:
        pkg = Package.query.get(r.package_id)
        data.append((r, pkg.name if pkg else f"#{r.package_id}"))
    return render_template("rollouts.html", items=data)


@admin_bp.get("/rollouts/new")
@login_required
@require_roles("Ops", "Admin")
def rollouts_new():
    """
    Create-form for rollouts, locked to the user's effective tenant.
    """
    # HARD GUARD
    if _is_admin(current_user.id):
        abort(403, description="Admins cannot query devices")
    
    tenant_ctx_id = _effective_tenant_id_for_user_or_403()
    pkgs = Package.query.filter_by(tenant_id=tenant_ctx_id).order_by(Package.name.asc()).all()
    pvers = (
        db.session.query(PackageVersion)
        .join(Package, PackageVersion.package_id == Package.id)
        .filter(Package.tenant_id == tenant_ctx_id)
        .order_by(PackageVersion.id.desc())
        .all()
    )
    t = Tenant.query.get(tenant_ctx_id)
    tenant_ctx_name = t.name if t else f"#{tenant_ctx_id}"

    # We no longer pass a list of tenants to the template; the tenant is fixed.
    return render_template(
        "rollout_form.html",
        tenant_ctx_id=tenant_ctx_id,
        tenant_ctx_name=tenant_ctx_name,
        pkgs=pkgs,
        pvers=pvers,
    )


@admin_bp.post("/rollouts/new")
@login_required
@require_roles("Ops", "Admin")
def rollouts_create():
    """
    Create a rollout for the user's effective tenant (ignores tenant input in form).
    """
    
    # HARD GUARD
    if _is_admin(current_user.id):
        abort(403, description="Admins cannot query devices")
    
    from datetime import datetime

    tenant_id = _effective_tenant_id_for_user_or_403()

    try:
        package_id = int(request.form.get("package_id"))
    except Exception:
        flash("Package is required", "danger")
        return redirect(url_for("admin.rollouts_new"))

    # Verify package belongs to tenant
    pkg = Package.query.get(package_id)
    if not pkg or pkg.tenant_id != tenant_id:
        flash("Invalid package for your tenant", "danger")
        return redirect(url_for("admin.rollouts_new"))

    version = (request.form.get("version") or "").strip()
    if not version:
        flash("Version is required", "danger")
        return redirect(url_for("admin.rollouts_new"))

    start_at = request.form.get("start_at")
    waves = request.form.get("waves", "[100]")
    try:
        concurrency_limit = int(request.form.get("concurrency_limit", "50"))
    except Exception:
        concurrency_limit = 50
    maintenance_window = request.form.get("maintenance_window", "any")
    policy_json_raw = request.form.get("policy_json", "{}")
    policy_json = _sanitize_policy_json(policy_json_raw)
    status = "scheduled"

    try:
        if start_at and "T" in start_at:
            dt_start = datetime.fromisoformat(start_at)
        elif start_at:
            dt_start = datetime.strptime(start_at, "%Y-%m-%d %H:%M")
        else:
            dt_start = datetime.utcnow()
    except Exception:
        dt_start = datetime.utcnow()

    r = Rollout(
        tenant_id=tenant_id,
        package_id=package_id,
        version=version,
        start_at=dt_start,
        waves=waves,
        concurrency_limit=concurrency_limit,
        maintenance_window=maintenance_window,
        policy_json=policy_json,
        status=status,
    )
    db.session.add(r)
    db.session.commit()

    # Targets (IDs/tags)
    def _parse_ids(s: Optional[str]):
        return [int(x) for x in re.split(r"[\s,]+", s.strip()) if x.strip().isdigit()] if s and s.strip() else []

    def _parse_tags(s: Optional[str]):
        return [x.strip() for x in re.split(r"[\s,]+", s.strip()) if x.strip()] if s and s.strip() else []

    fleets = _parse_ids(request.form.get("target_fleets"))
    devices = _parse_ids(request.form.get("target_devices"))
    tags = _parse_tags(request.form.get("target_tags"))

    for fid in fleets:
        db.session.add(RolloutTarget(rollout_id=r.id, fleet_id=fid))
    for did in devices:
        db.session.add(RolloutTarget(rollout_id=r.id, device_id=did))
    for tag in tags:
        db.session.add(RolloutTarget(rollout_id=r.id, tag=tag))
    db.session.commit()

    _nudge_scheduler()
    flash(f"Rollout #{r.id} created", "success")
    return redirect(url_for("admin.rollouts_list"))


@admin_bp.get("/rollouts/<int:r_id>")
@login_required
@require_roles("Ops", "Admin", "Viewer")
def rollouts_view(r_id):
    """
    Rollout status page with per-device installation rows.
    """
    # HARD GUARD
    if _is_admin(current_user.id):
        abort(403, description="Admins cannot query devices")
    
    r = Rollout.query.get_or_404(r_id)
    if not _is_admin(current_user.id):
        _must_be_in_scope(r.tenant_id)
    pkg = Package.query.get(r.package_id)

    base = DeviceInstallation.query.filter(DeviceInstallation.rollout_id == r.id)
    total = base.count()
    pending = base.filter(DeviceInstallation.status.in_(["pending", "in_progress", "installing", "running"])).count()
    succeeded = base.filter(DeviceInstallation.status.in_(["succeeded", "success", "ok", "completed", "done"])).count()
    failed = base.filter(DeviceInstallation.status.in_(["failed", "fail", "error"])).count()

    rows = (
        db.session.query(DeviceInstallation, Device)
        .join(Device, DeviceInstallation.device_id == Device.id, isouter=True)
        .filter(DeviceInstallation.rollout_id == r.id)
        .order_by(DeviceInstallation.id.asc())
        .all()
    )
    table = []
    for di, d in rows:
        table.append({
            "device_id": di.device_id,
            "hostname": getattr(d, "hostname", f"#{di.device_id}"),
            "ip": getattr(d, "last_ip", "") or "",
            "status": di.status,
            "started_at": di.started_at,
            "finished_at": di.finished_at,
            "agent_version": getattr(d, "agent_version", "") or "",
            "os_version": getattr(d, "os_version", "") or "",
        })

    return render_template(
        "rollout_status.html",
        r=r,
        pkg=pkg,
        total=total,
        succ=succeeded,
        fail=failed,
        pend=pending,
        device_rows=table,
    )


@admin_bp.post("/rollouts/<int:r_id>/status")
@login_required
@require_roles("Ops", "Admin")
def rollouts_change_status(r_id):
    """
    Pause/resume/cancel rollout (tenant scope enforced for non-admins).
    """
    
    # HARD GUARD
    if _is_admin(current_user.id):
        abort(403, description="Admins cannot query devices")
    
    r = Rollout.query.get_or_404(r_id)
    if not _is_admin(current_user.id):
        _must_be_in_scope(r.tenant_id)

    action = request.form.get("action")
    if action == "pause":
        r.status = "paused"
    elif action == "resume":
        r.status = "running"
    elif action == "cancel":
        r.status = "cancelled"
    db.session.commit()
    _nudge_scheduler()
    return redirect(url_for("admin.rollouts_view", r_id=r.id))


@admin_bp.get("/rollouts/<int:r_id>/edit", endpoint="rollouts_edit")
@login_required
@require_roles("Ops", "Admin")
def rollouts_edit(r_id):
    """
    Edit rollout (admin can switch tenant/package; non-admin stays in-scope data only).
    """
    
    # HARD GUARD
    if _is_admin(current_user.id):
        abort(403, description="Admins cannot query devices")
    
    r = Rollout.query.get_or_404(r_id)
    if not _is_admin(current_user.id):
        _must_be_in_scope(r.tenant_id)

    if _is_admin(current_user.id):
        tenants = Tenant.query.all()
        pkgs = Package.query.all()
        pvers = PackageVersion.query.all()
    else:
        tids = _user_tenant_ids(current_user.id)
        tenants = Tenant.query.filter(Tenant.id.in_(tids)).all() if tids else []
        pkgs = Package.query.filter(Package.tenant_id.in_(tids)).all() if tids else []
        pvers = (
            PackageVersion.query
            .join(Package, Package.id == PackageVersion.package_id)
            .filter(Package.tenant_id.in_(tids)).all() if tids else []
        )

    targets = RolloutTarget.query.filter_by(rollout_id=r.id).all()
    fleets = ",".join(str(t.fleet_id) for t in targets if t.fleet_id)
    devices = ",".join(str(t.device_id) for t in targets if t.device_id)
    tags = ",".join(t.tag for t in targets if t.tag)

    return render_template(
        "rollout_edit.html",
        r=r,
        tenants=tenants,
        pkgs=pkgs,
        pvers=pvers,
        fleets=fleets,
        devices=devices,
        tags=tags,
    )


@admin_bp.post("/rollouts/<int:r_id>/edit", endpoint="rollouts_update_post")
@login_required
@require_roles("Ops", "Admin")
def rollouts_update_post(r_id):
    """
    Persist rollout edits (respect scope for non-admins).
    """
    # HARD GUARD
    if _is_admin(current_user.id):
        abort(403, description="Admins cannot query devices")
    
    r = Rollout.query.get_or_404(r_id)
    if not _is_admin(current_user.id):
        _must_be_in_scope(r.tenant_id)
    from datetime import datetime

    r.tenant_id = int(request.form.get("tenant_id", r.tenant_id))
    r.package_id = int(request.form.get("package_id", r.package_id))
    r.version = (request.form.get("version", r.version) or "").strip()

    start_at = (request.form.get("start_at") or "").strip()
    try:
        if start_at and "T" in start_at:
            r.start_at = datetime.fromisoformat(start_at)
        elif start_at:
            r.start_at = datetime.strptime(start_at, "%Y-%m-%d %H:%M")
    except Exception:
        pass

    r.waves = request.form.get("waves", r.waves)
    try:
        r.concurrency_limit = int(request.form.get("concurrency_limit", r.concurrency_limit))
    except Exception:
        pass
    r.maintenance_window = request.form.get("maintenance_window", r.maintenance_window)

    policy_json_raw = request.form.get("policy_json", r.policy_json or "{}")
    r.policy_json = _sanitize_policy_json(policy_json_raw)

    db.session.commit()

    # Targets
    def _parse_ids(s: Optional[str]):
        return [int(x) for x in re.split(r"[\s,]+", s.strip()) if x.strip().isdigit()] if s and s.strip() else []

    def _parse_tags(s: Optional[str]):
        return [x.strip() for x in re.split(r"[\s,]+", s.strip()) if x.strip()] if s and s.strip() else []

    fleets = _parse_ids(request.form.get("target_fleets"))
    devices = _parse_ids(request.form.get("target_devices"))
    tags = _parse_tags(request.form.get("target_tags"))

    RolloutTarget.query.filter_by(rollout_id=r.id).delete()
    for fid in fleets:
        db.session.add(RolloutTarget(rollout_id=r.id, fleet_id=fid))
    for did in devices:
        db.session.add(RolloutTarget(rollout_id=r.id, device_id=did))
    for tag in tags:
        db.session.add(RolloutTarget(rollout_id=r.id, tag=tag))
    db.session.commit()

    _nudge_scheduler()
    flash("Rollout updated", "success")
    return redirect(url_for("admin.rollouts_view", r_id=r.id))


@admin_bp.post("/rollouts/<int:r_id>/delete")
@login_required
@require_roles("Ops", "Admin")
def rollouts_delete(r_id):
    """
    Delete a rollout if not running (scope enforced for non-admins).
    """
    # HARD GUARD
    if _is_admin(current_user.id):
        abort(403, description="Admins cannot query devices")
        
    r = Rollout.query.get_or_404(r_id)
    if not _is_admin(current_user.id):
        _must_be_in_scope(r.tenant_id)
    if r.status == "running":
        flash("Cancel or pause the rollout before deleting", "warning")
        return redirect(url_for("admin.rollouts_view", r_id=r.id))

    RolloutTarget.query.filter_by(rollout_id=r.id).delete(synchronize_session=False)
    DeviceInstallation.query.filter_by(rollout_id=r.id).delete(synchronize_session=False)
    db.session.delete(r)
    db.session.commit()

    flash("Rollout deleted", "success")
    return redirect(url_for("admin.rollouts_list"))


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║ Rollout status JSON (tenant scoped)                                      ║
# ╚══════════════════════════════════════════════════════════════════════════╝
@admin_bp.get("/rollouts/<int:r_id>/status.json")
@login_required
@require_roles("Ops", "Admin", "Viewer")
def rollouts_status_json(r_id):
    """
    JSON status for a rollout with device counters and device rows.
    """
    
    # HARD GUARD
    if _is_admin(current_user.id):
        abort(403, description="Admins cannot query devices")
        
    r = Rollout.query.get_or_404(r_id)
    if not _is_admin(current_user.id):
        _must_be_in_scope(r.tenant_id)

    base = DeviceInstallation.query.filter(DeviceInstallation.rollout_id == r.id)
    pending_q = base.filter(DeviceInstallation.status.in_(["pending", "in_progress", "installing", "running"]))
    succeeded_q = base.filter(DeviceInstallation.status.in_(["succeeded", "success", "ok", "completed", "done"]))
    failed_q = base.filter(DeviceInstallation.status.in_(["failed", "fail", "error"]))

    rows = (
        db.session.query(
            DeviceInstallation.device_id,
            DeviceInstallation.status,
            DeviceInstallation.started_at,
            DeviceInstallation.finished_at,
            Device.hostname,
            Device.last_ip,
            Device.agent_version,
            Device.os_version,
        )
        .join(Device, Device.id == DeviceInstallation.device_id, isouter=True)
        .filter(DeviceInstallation.rollout_id == r.id)
        .order_by(DeviceInstallation.device_id.asc())
        .all()
    )

    def _iso(x):
        return x.isoformat(timespec="seconds") + "Z" if x else None

    return {
        "rollout": {
            "id": r.id,
            "status": r.status,
            "start_at": _iso(r.start_at),
            "waves": r.waves,
            "concurrency_limit": r.concurrency_limit,
            "maintenance_window": r.maintenance_window,
            "policy_json": r.policy_json,
        },
        "counters": {
            "total": base.count(),
            "pending": pending_q.count(),
            "succeeded": succeeded_q.count(),
            "failed": failed_q.count(),
        },
        "devices": [
            {
                "device_id": d.device_id,
                "hostname": d.hostname,
                "ip": d.last_ip,
                "status": d.status,
                "started_at": _iso(d.started_at),
                "finished_at": _iso(d.finished_at),
                "agent_version": d.agent_version,
                "os_version": d.os_version,
            }
            for d in rows
        ],
    }


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║ Endpoint aliases (keep templates backwards-compatible)                   ║
# ╚══════════════════════════════════════════════════════════════════════════╝
try:
    admin_bp.add_url_rule("/packages", endpoint="packages", view_func=packages_list)
except Exception:
    pass
try:
    admin_bp.add_url_rule("/rollouts", endpoint="rollouts", view_func=rollouts_list)
except Exception:
    pass


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║ Devices JSON (tenant-scoped picker, paginated)                           ║
# ╚══════════════════════════════════════════════════════════════════════════╝
@admin_bp.get("/devices.json")
@login_required
@require_roles("Ops", "Admin")
def devices_json():
    """
    Always returns devices **only** from the current user's effective tenant.
    Ignores a tenant_id query string if provided. Supports search, online-only,
    and pagination.
    """
    # HARD GUARD
    if _is_admin(current_user.id):
        abort(403, description="Admins cannot query devices")
        
    from sqlalchemy import or_, func

    tenant_id = _effective_tenant_id_for_user_or_403()

    # Paging
    def clamp(v, lo, hi, dflt):
        try:
            v = int(v)
        except Exception:
            return dflt
        return max(lo, min(hi, v))

    page = clamp(request.args.get("page", 1), 1, 1_000_000, 1)
    per_page = clamp(request.args.get("per_page", 20), 1, 100, 20)

    q = (request.args.get("q") or "").strip()
    online_only = (request.args.get("online_only", "1").lower() in {"1", "true", "yes"})
    online_minutes = clamp(request.args.get("online_minutes", 10), 1, 1440, 10)

    base = Device.query.filter(Device.tenant_id == tenant_id)

    if q:
        # id exact OR hostname ilike
        try:
            id_match = int(q)
        except Exception:
            id_match = None
        ql = q.lower()
        if id_match is not None:
            base = base.filter(or_(Device.id == id_match, func.lower(Device.hostname).like(f"%{ql}%")))
        else:
            base = base.filter(func.lower(Device.hostname).like(f"%{ql}%"))

    if online_only:
        since = dt.datetime.utcnow() - dt.timedelta(minutes=online_minutes)
        base = base.filter(Device.last_seen_at != None, Device.last_seen_at >= since)  # noqa: E711

    items_q = base.order_by(Device.last_seen_at.desc().nullslast(), Device.id.desc())
    total = items_q.count()
    items = items_q.offset((page - 1) * per_page).limit(per_page).all()

    def _fmt_ts(x):
        return x.isoformat(timespec="seconds") + "Z" if x else None

    return {
        "meta": {
            "tenant_id": tenant_id,  # transparency
            "page": page,
            "per_page": per_page,
            "total": total,
            "pages": (total + per_page - 1) // per_page if per_page else 1,
        },
        "items": [
            {
                "id": d.id,
                "hostname": d.hostname,
                "fleet_id": d.fleet_id,
                "last_seen_at": _fmt_ts(d.last_seen_at),
                "last_ip": d.last_ip,
                "agent_version": d.agent_version,
                "os_version": d.os_version,
            }
            for d in items
        ],
    }


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║ API Keys (per-tenant & global)                                           ║
# ╚══════════════════════════════════════════════════════════════════════════╝
@admin_bp.get("/tenants/<int:t_id>/keys")
@login_required
@require_roles("Admin")
def tenant_keys(t_id):
    """
    Per-tenant API keys listing.
    """
    from ..models import ApiKey
    t = Tenant.query.get_or_404(t_id)
    keys = ApiKey.query.filter_by(tenant_id=t.id).order_by(ApiKey.created_at.desc()).all()
    new_key_plain = request.args.get("k")
    return render_template("tenant_keys.html", t=t, keys=keys, new_key_plain=new_key_plain)


@admin_bp.post("/tenants/<int:t_id>/keys")
@login_required
@require_roles("Admin")
def tenant_keys_create(t_id):
    """
    Create an API key for a tenant. Plaintext is shown only once via flash.
    """
    from ..models import ApiKey
    t = Tenant.query.get_or_404(t_id)

    name = (request.form.get("name") or "UI-generated").strip()
    exp = (request.form.get("expires_at") or "").strip()
    expires_at = None
    if exp:
        try:
            if "T" in exp:
                expires_at = dt.datetime.fromisoformat(exp)
            else:
                expires_at = dt.datetime.strptime(exp, "%Y-%m-%d")
        except Exception:
            expires_at = None

    raw_key = "uk_" + secrets.token_urlsafe(40)
    hash_hex = hashlib.sha256(raw_key.encode()).hexdigest()

    ak = ApiKey(
        tenant_id=t.id,
        name=name,
        last4=raw_key[-4:],
        hash=hash_hex,
        created_at=dt.datetime.utcnow(),
        expires_at=expires_at,
        scopes="agents",
    )
    db.session.add(ak)
    db.session.commit()

    flash("API key created. This is the ONLY time you'll see the plaintext.", "success")
    return redirect(url_for("admin.tenant_keys", t_id=t.id, k=raw_key))


@admin_bp.post("/tenants/<int:t_id>/keys/<int:key_id>/delete")
@login_required
@require_roles("Admin")
def tenant_keys_delete(t_id, key_id):
    """
    Delete a tenant API key.
    """
    from ..models import ApiKey
    _ = Tenant.query.get_or_404(t_id)
    ak = ApiKey.query.filter_by(id=key_id, tenant_id=t_id).first_or_404()
    db.session.delete(ak)
    db.session.commit()
    flash("API key deleted", "success")
    return redirect(url_for("admin.tenant_keys", t_id=t_id))


@admin_bp.route("/admin/global-api-keys", methods=["GET", "POST"])
@login_required
@require_roles("Admin")
def global_api_keys():
    """
    Global API keys management (requires model to have an 'is_global' boolean).
    """
    from ..models import ApiKey, _mk_api_key
    if request.method == "POST":
        name = request.form.get("name", "Global")
        raw, last4, digest = _mk_api_key()
        # NOTE: This assumes your ApiKey model exposes `is_global`.
        ak = ApiKey(tenant_id=None, is_global=True, name=name, last4=last4, hash=digest, scopes="admin")
        db.session.add(ak)
        db.session.commit()
        flash(f"Global API key created. Save it now: {raw}", "success")
        return redirect(url_for("admin.global_api_keys"))
    keys = ApiKey.query.filter_by(is_global=True).order_by(ApiKey.created_at.desc()).all()
    return render_template("admin/global_api_keys.html", keys=keys)


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║ Convenience redirects (metrics/health)                                   ║
# ╚══════════════════════════════════════════════════════════════════════════╝
@admin_bp.get("/metrics-redirect", endpoint="metrics")
@login_required
@require_roles("Admin")
def metrics_alias():
    """
    Redirect to /metrics (served by metrics extension).
    """
    return redirect("/metrics")


@admin_bp.get("/health-redirect", endpoint="health")
@login_required
@require_roles("Admin")
def health_alias():
    """
    Redirect to /health if you have a health endpoint registered elsewhere.
    """
    return redirect("/health")


# ───────── helper κοινός για dashboard & fragment ─────────
def _connected_devices_page(q: str, page: int, per_page: int, user_id: int):
    import datetime as _dt
    from sqlalchemy import func, or_, literal_column

    connected_since = _dt.datetime.utcnow() - _dt.timedelta(minutes=5)

    # ip columns → ip_eff (ασφαλές για SQLite)
    ip_columns = [getattr(Device, a) for a in ("ip", "ip_address", "last_ip", "last_seen_ip") if hasattr(Device, a)]
    if   len(ip_columns) == 0: ip_eff = literal_column("NULL")
    elif len(ip_columns) == 1: ip_eff = ip_columns[0]
    else:                      ip_eff = func.coalesce(*ip_columns)

    if _is_admin(user_id):
        base = (
            db.session.query(
                Device,
                ip_eff.label("ip_eff"),
                Tenant.name.label("tenant_name"),
                Tenant.slug.label("tenant_slug"),
            )
            .outerjoin(Tenant, Device.tenant_id == Tenant.id)
            .filter(Device.last_seen_at >= connected_since)
        )
    else:
        tids = _user_tenant_ids(user_id)
        if not tids:
            base = (
                db.session.query(
                    Device,
                    ip_eff.label("ip_eff"),
                    Tenant.name.label("tenant_name"),
                    Tenant.slug.label("tenant_slug"),
                )
                .outerjoin(Tenant, Device.tenant_id == Tenant.id)
                .filter(False)
            )
        else:
            base = (
                db.session.query(
                    Device,
                    ip_eff.label("ip_eff"),
                    Tenant.name.label("tenant_name"),
                    Tenant.slug.label("tenant_slug"),
                )
                .outerjoin(Tenant, Device.tenant_id == Tenant.id)
                .filter(Device.tenant_id.in_(tids), Device.last_seen_at >= connected_since)
            )

    if q:
        if q.isdigit():
            base = base.filter(Device.id == int(q))
        else:
            ql = f"%{q.lower()}%"
            like_clauses = [func.lower(col).like(ql) for col in ip_columns]
            base = base.filter(or_(*like_clauses)) if like_clauses else base.filter(False)

    base = base.order_by(Device.last_seen_at.desc())
    total = base.count()
    rows  = base.offset((page - 1) * per_page).limit(per_page).all()
    items = [{"device": d, "ip_eff": ip, "tenant_name": tn, "tenant_slug": ts} for (d, ip, tn, ts) in rows]
    pages = (total + per_page - 1) // per_page

    return {
        "items": items,
        "page": page,
        "per_page": per_page,
        "total": total,
        "pages": pages,
        "has_prev": page > 1,
        "has_next": page < pages,
        "prev_page": page - 1 if page > 1 else None,
        "next_page": page + 1 if page < pages else None,
    }

# ───────── fragment route για AJAX ─────────
@admin_bp.get("/connected-devices.fragment")
@login_required
@require_roles("Viewer", "Ops", "Admin")
def connected_devices_fragment():
    page = request.args.get("page", default=1, type=int)
    per  = request.args.get("per",  default=10, type=int)
    q    = (request.args.get("q") or "").strip()
    per  = max(5, min(per, 50))

    devices_page = _connected_devices_page(q=q, page=page, per_page=per, user_id=current_user.id)
    # επιστρέφουμε ΜΟΝΟ το εσωτερικό της κάρτας
    return render_template("partials/connected_devices_fragment.html",
                           devices_page=devices_page, q=q)


