# update_server/models.py
from __future__ import annotations

from datetime import datetime
import secrets
import hashlib

from flask_login import UserMixin
from werkzeug.security import generate_password_hash

from .extensions import db


# ---------------------------
# Core domain models
# ---------------------------
class Tenant(db.Model):
    __tablename__ = "tenant"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, unique=True)
    slug = db.Column(db.String(80), nullable=False, unique=True)
    status = db.Column(db.String(20), default="active")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # relationship to ApiKey (tenant-scoped keys)
    api_keys = db.relationship("ApiKey", backref="tenant", lazy=True)


class Fleet(db.Model):
    __tablename__ = "fleet"

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)


class Device(db.Model):
    __tablename__ = "device"

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=True)
    fleet_id = db.Column(db.Integer, db.ForeignKey("fleet.id"), nullable=False)
    hostname = db.Column(db.String(120), nullable=False)
    tags = db.Column(db.Text)
    os_version = db.Column(db.String(80))
    agent_version = db.Column(db.String(40))
    last_seen_at = db.Column(db.DateTime)
    status = db.Column(db.String(20), default="idle")
    # από migration: νέο πεδίο
    last_ip = db.Column(db.String(45), nullable=True)


class Package(db.Model):
    __tablename__ = "package"

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)


class PackageVersion(db.Model):
    __tablename__ = "package_version"

    id = db.Column(db.Integer, primary_key=True)
    package_id = db.Column(db.Integer, db.ForeignKey("package.id"), nullable=False)
    semver = db.Column(db.String(20), nullable=False)
    hash_sha256 = db.Column(db.String(64), nullable=False)
    size_bytes = db.Column(db.Integer, nullable=False)
    signed = db.Column(db.Boolean, default=False)
    release_notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    storage_path = db.Column(db.String(512), nullable=False)


class Rollout(db.Model):
    __tablename__ = "rollout"

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=True)
    package_id = db.Column(db.Integer, db.ForeignKey("package.id"), nullable=False)
    version = db.Column(db.String(20), nullable=False)
    start_at = db.Column(db.DateTime, nullable=False)
    freeze_at = db.Column(db.DateTime)
    waves = db.Column(db.Text)
    concurrency_limit = db.Column(db.Integer, default=50)
    maintenance_window = db.Column(db.String(80))
    policy_json = db.Column(db.Text)
    status = db.Column(db.String(20), default="scheduled")


class RolloutTarget(db.Model):
    __tablename__ = "rollout_target"

    id = db.Column(db.Integer, primary_key=True)
    rollout_id = db.Column(db.Integer, db.ForeignKey("rollout.id"), nullable=False)
    fleet_id = db.Column(db.Integer)
    device_id = db.Column(db.Integer)
    tag = db.Column(db.String(80))


class DeviceInstallation(db.Model):
    __tablename__ = "device_installation"

    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey("device.id"), nullable=False)
    # από migration: rollout_id nullable + indexed
    rollout_id = db.Column(db.Integer, db.ForeignKey("rollout.id"), index=True, nullable=True)
    package_id = db.Column(db.Integer, db.ForeignKey("package.id"), nullable=False)
    version = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default="pending")
    attempts = db.Column(db.Integer, default=0)
    error_code = db.Column(db.String(40))
    logs_uri = db.Column(db.String(255))
    started_at = db.Column(db.DateTime)
    finished_at = db.Column(db.DateTime)
    previous_version = db.Column(db.String(20))


class ApiKey(db.Model):
    __tablename__ = "api_key"

    id = db.Column(db.Integer, primary_key=True)
    # από migration add_is_global_1759477018: tenant_id nullable, is_global boolean
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=True)
    is_global = db.Column(db.Boolean, nullable=False, default=False, server_default="0")

    name = db.Column(db.String(120), nullable=False)
    last4 = db.Column(db.String(4), nullable=False)
    hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    scopes = db.Column(db.Text)

    def is_expired(self) -> bool:
        return bool(self.expires_at and self.expires_at <= datetime.utcnow())


class AuditLog(db.Model):
    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=True)
    user_id = db.Column(db.Integer, nullable=True)
    action = db.Column(db.String(80), nullable=False)
    entity = db.Column(db.String(80), nullable=False)
    entity_id = db.Column(db.String(80), nullable=True)
    data_json = db.Column(db.Text)
    correlation_id = db.Column(db.String(64))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ---------------------------
# Users & Roles
# ---------------------------
class Role(db.Model):
    __tablename__ = "role"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.Text)


class User(db.Model, UserMixin):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=True)
    email = db.Column(db.String(180), unique=True, nullable=False)
    full_name = db.Column(db.String(120))
    password_hash = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), default="active")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class UserRole(db.Model):
    __tablename__ = "user_role"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey("role.id"), nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=True)


# ---------------------------
# Bootstrap helpers
# ---------------------------
def _mk_api_key(prefix: str = "uk_", nbytes: int = 40):
    """
    Επιστρέφει (raw, last4, digest). Το raw δεν αποθηκεύεται στη DB.
    Χρησιμοποιούμε sha256 ώστε να ταιριάζει με τον κώδικα του admin view.
    """
    raw = prefix + secrets.token_urlsafe(nbytes)
    last4 = raw[-4:]
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return raw, last4, digest


def seed_demo():
    if Tenant.query.count() > 0:
        return
    t = Tenant(name="Demo Corp", slug="demo", status="active")
    db.session.add(t)
    db.session.commit()

    raw, last4, digest = _mk_api_key()
    ak = ApiKey(tenant_id=t.id, name="Default", last4=last4, hash=digest, scopes="agents,admin")
    db.session.add(ak)

    f = Fleet(tenant_id=t.id, name="Default Fleet", description="All devices")
    db.session.add(f)
    db.session.commit()

    for i in range(1, 6):
        d = Device(
            tenant_id=t.id,
            fleet_id=f.id,
            hostname=f"DESKTOP-{i:03d}",
            tags="win10,branchA",
            os_version="10.0.19045",
            agent_version="1.0.0",
        )
        db.session.add(d)

    p = Package(tenant_id=t.id, name="AcmeApp", description="Main LOB app")
    db.session.add(p)
    db.session.commit()

    db.session.commit()
    print("Demo seeded. Save this API KEY (only printed once!):", raw)


def ensure_bootstrap_admin() -> bool:
    """
    Χρησιμοποιείται από το setup wizard για να καταλάβει αν χρειάζεται initial admin.
    """
    return User.query.count() == 0


def create_initial_admin(email: str, password: str):
    if User.query.filter_by(email=email.lower()).first():
        return None
    for rname in ["Admin", "Ops", "Viewer"]:
        if not Role.query.filter_by(name=rname).first():
            db.session.add(Role(name=rname, description=f"Role {rname}"))
    db.session.commit()
    u = User(email=email.lower(), full_name="Administrator", password_hash=generate_password_hash(password))
    db.session.add(u)
    db.session.commit()
    admin_role = Role.query.filter_by(name="Admin").first()
    # ο bootstrap admin είναι global (tenant scope = None)
    db.session.add(UserRole(user_id=u.id, role_id=admin_role.id, tenant_id=None))
    db.session.commit()
    return u


