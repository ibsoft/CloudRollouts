from __future__ import annotations
from functools import wraps
from flask import request, jsonify
import hmac
import hashlib
from datetime import datetime

from ..extensions import db
from ..models import ApiKey

ADMIN_HEADER = "X-Admin-API-Key"

def _find_global_key_by_raw(raw: str) -> ApiKey | None:
    if not raw:
        return None
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    ak = db.session.query(ApiKey).filter(
        ApiKey.hash == digest,
        ApiKey.is_global.is_(True)
    ).first()
    if not ak:
        return None
    # expiry check
    if ak.expires_at and ak.expires_at <= datetime.utcnow():
        return None
    return ak

def require_global_admin_key(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        provided = request.headers.get(ADMIN_HEADER, "")
        ak = _find_global_key_by_raw(provided)
        if not ak:
            return jsonify(error="unauthorized", message=f"Missing or invalid {ADMIN_HEADER}"), 401
        return fn(*args, **kwargs)
    return wrapper
