from functools import wraps
from flask import request, jsonify, g
from .models import ApiKey

def require_api_key(scope="agents"):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            api_key = request.headers.get("X-API-Key")
            if not api_key:
                return jsonify({"error":"missing_api_key"}), 401
            from hashlib import sha512
            digest = sha512(api_key.encode()).hexdigest()
            ak = ApiKey.query.filter_by(hash=digest).first()
            if not ak:
                return jsonify({"error":"invalid_api_key"}), 401
            if ak.scopes and scope not in (ak.scopes or "").split(","):
                return jsonify({"error":"insufficient_scope"}), 403
            g.tenant_id = ak.tenant_id
            g.is_global_api_key = bool(getattr(ak, "is_global", False))
            return fn(*args, **kwargs)
        return wrapper
    return decorator

def require_tenant(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        from flask import jsonify, g
        if not getattr(g, "tenant_id", None):
            return jsonify({"error":"tenant_required"}), 400
        return fn(*args, **kwargs)
    return wrapper
