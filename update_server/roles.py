from functools import wraps
from flask import abort
from flask_login import current_user
from .models import UserRole, Role

def require_roles(*role_names):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            user_roles = UserRole.query.filter_by(user_id=current_user.id).all()
            names = set()
            for ur in user_roles:
                r = Role.query.get(ur.role_id)
                if r: names.add(r.name)
            if names.intersection(set(role_names)) or ("Admin" in names):
                return fn(*args, **kwargs)
            abort(403)
        return wrapper
    return decorator

def user_tenant_ids(user):
    urs = UserRole.query.filter_by(user_id=user.id).all()
    tids = set([ur.tenant_id for ur in urs if ur.tenant_id is not None])
    return tids

def require_role_in_tenant(*role_names):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            # Admin bypass
            admin = False
            urs = UserRole.query.filter_by(user_id=current_user.id).all()
            role_names_user = set()
            tids = set()
            for ur in urs:
                r = Role.query.get(ur.role_id)
                if r:
                    role_names_user.add(r.name)
                if ur.tenant_id is not None:
                    tids.add(ur.tenant_id)
            if "Admin" in role_names_user:
                return fn(*args, **kwargs)
            if not role_names_user.intersection(set(role_names)):
                abort(403)
            from flask import g
            if getattr(g, "tenant_id", None) and g.tenant_id not in tids:
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return decorator
