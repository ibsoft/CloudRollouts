# update_server/api/auth.py
from __future__ import annotations

import os
import re
import hashlib
import datetime as dt
import logging
from functools import wraps
from typing import Optional, Iterable

from flask import request, jsonify, g
from sqlalchemy import func

from ..models import ApiKey, Tenant

log = logging.getLogger("update_server.auth")

# Optional: allow matching plaintext against ApiKey.hash for legacy rows
DEV_ALLOW_PLAINTEXT_KEYS = os.getenv("DEV_ALLOW_PLAINTEXT_KEYS", "0") in ("1", "true", "True")


# -------------------- extraction helpers --------------------

def _extract_api_key() -> Optional[str]:
    """
    Supports:
      - X-API-Key / X-Api-Key: <raw>
      - Authorization: ApiKey <raw>  OR Bearer <raw>
      - ?api_key=<raw> or ?key=<raw>
      - JSON body: {"apiKey":"<raw>"}
    """
    # Common header names
    key = request.headers.get("X-API-Key") or request.headers.get("X-Api-Key")
    if key and key.strip():
        return key.strip()

    # Authorization
    auth = request.headers.get("Authorization", "")
    if auth:
        parts = auth.strip().split(None, 1)
        if len(parts) == 2:
            scheme, token = parts[0].lower(), parts[1].strip()
            if scheme in ("apikey", "bearer") and token:
                return token
        elif len(parts) == 1 and parts[0].strip():
            # Rare: token only
            return parts[0].strip()

    # Query params
    raw = (request.args.get("api_key") or request.args.get("key") or "").strip()
    if raw:
        return raw

    # JSON body
    if request.is_json:
        try:
            body = request.get_json(silent=True) or {}
            raw = (body.get("apiKey") or "").strip()
            if raw:
                return raw
        except Exception:
            pass

    return None


def _scopes_list(scopes: Optional[str]) -> list[str]:
    if not scopes:
        return []
    return [s.strip() for s in scopes.split(",") if s.strip()]


# -------------------- matching helpers --------------------

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def _normalize(s: Optional[str]) -> str:
    return (s or "").strip()


def _matches_stored_hash(raw: str, stored: str) -> bool:
    """
    Compare raw key against stored ApiKey.hash by detecting stored format:
      - 64 hex chars  -> sha256(raw)
      - 128 hex chars -> sha512(raw)
      - else          -> plaintext compare (only if DEV_ALLOW_PLAINTEXT_KEYS or obviously not hex)
    """
    raw = _normalize(raw)
    stored = _normalize(stored)

    # Detect hex length
    is_hex = bool(_HEX_RE.match(stored))
    n = len(stored)

    try:
        if is_hex and n == 64:  # sha256
            h = hashlib.sha256(raw.encode()).hexdigest()
            return h.lower() == stored.lower()
        if is_hex and n == 128:  # sha512
            h = hashlib.sha512(raw.encode()).hexdigest()
            return h.lower() == stored.lower()
    except Exception:
        pass

    # plaintext fallback
    if DEV_ALLOW_PLAINTEXT_KEYS or not is_hex:
        return raw == stored
    return False


def _find_apikey_record(raw: str) -> Optional[ApiKey]:
    """
    Robust lookup strategy:
      1) Direct compare with sha256(raw)
      2) Direct compare with sha512(raw)
      3) Candidate search by last4 == raw[-4:], then verify in Python via _matches_stored_hash
      4) (dev fallback) plaintext DB compare if DEV_ALLOW_PLAINTEXT_KEYS
    """
    raw = _normalize(raw)
    if not raw:
        return None

    h256 = hashlib.sha256(raw.encode()).hexdigest().lower()
    h512 = hashlib.sha512(raw.encode()).hexdigest().lower()

    # 1) sha256
    ak = ApiKey.query.filter(func.lower(func.trim(ApiKey.hash)) == h256).first()
    log.debug("auth.lookup sha256 prefix=%s found=%s", h256[:12], bool(ak))
    if ak:
        return ak

    # 2) sha512
    ak = ApiKey.query.filter(func.lower(func.trim(ApiKey.hash)) == h512).first()
    log.debug("auth.lookup sha512 prefix=%s found=%s", h512[:12], bool(ak))
    if ak:
        return ak

    # 3) narrow by last4, then verify in Python
    last4 = raw[-4:] if len(raw) >= 4 else raw
    if last4:
        candidates = ApiKey.query.filter(func.trim(ApiKey.last4) == last4).all()
        log.debug("auth.lookup by_last4 last4=%s candidates=%d", last4, len(candidates))
        for cand in candidates:
            if _matches_stored_hash(raw, cand.hash):
                log.debug("auth.lookup by_last4 verified api_key_id=%s", cand.id)
                return cand

    # 4) dev-only plaintext DB compare
    if DEV_ALLOW_PLAINTEXT_KEYS:
        ak = ApiKey.query.filter(func.lower(func.trim(ApiKey.hash)) == func.lower(func.trim(raw))).first()
        log.debug("auth.lookup plaintext_fallback enabled=%s found=%s", True, bool(ak))
        if ak:
            return ak

    return None


def _load_into_g(ak: ApiKey) -> None:
    g.tenant_id = ak.tenant_id
    g.api_key_id = ak.id
    g.api_key_last4 = ak.last4
    g.api_key_scopes = _scopes_list(ak.scopes)


# -------------------- request guards --------------------

def resolve_tenant_from_api_key():
    """
    Use in @api_bp.before_request.
    Validates API key and loads g.*. Return None on success.
    """
    raw = _extract_api_key()
    if not raw:
        log.warning("auth.missing_api_key path=%s", request.path)
        return jsonify({"error": "unauthorized", "code": "missing_api_key"}), 401

    ak = _find_apikey_record(raw)
    if not ak:
        last4 = raw[-4:] if len(raw) >= 4 else "????"
        log.warning("auth.invalid_api_key path=%s last4=%s", request.path, last4)
        return jsonify({"error": "unauthorized", "code": "invalid_api_key"}), 401

    # expiry (UTC)
    now = dt.datetime.utcnow()
    if getattr(ak, "expires_at", None) and ak.expires_at <= now:
        log.warning("auth.expired_api_key path=%s api_key_id=%s last4=%s", request.path, ak.id, ak.last4)
        return jsonify({"error": "unauthorized", "code": "expired_api_key"}), 401

    # tenant active
    t = Tenant.query.get(ak.tenant_id)
    status = getattr(t, "status", "active") if t else "missing"
    if not t or status != "active":
        log.warning("auth.tenant_inactive path=%s tenant_id=%s status=%s", request.path, ak.tenant_id, status)
        return jsonify({"error": "unauthorized", "code": "tenant_inactive"}), 401

    _load_into_g(ak)
    log.info("auth.ok path=%s tenant_id=%s api_key_id=%s scopes=%s",
             request.path, g.tenant_id, g.api_key_id, ",".join(g.api_key_scopes or []))
    return None


def require_api_key(required_scope: str = ""):
    """
    Decorator that ensures a valid key and (optionally) a specific scope.
    Respects data already set by resolve_tenant_from_api_key().
    """
    def _decorator(fn):
        @wraps(fn)
        def _wrapped(*args, **kwargs):
            if getattr(g, "api_key_id", None) is None:
                raw = _extract_api_key()
                if not raw:
                    log.warning("auth.missing_api_key.decorator path=%s", request.path)
                    return jsonify({"error": "unauthorized", "code": "missing_api_key"}), 401

                ak = _find_apikey_record(raw)
                if not ak:
                    last4 = raw[-4:] if len(raw) >= 4 else "????"
                    log.warning("auth.invalid_api_key.decorator path=%s last4=%s", request.path, last4)
                    return jsonify({"error": "unauthorized", "code": "invalid_api_key"}), 401

                now = dt.datetime.utcnow()
                if getattr(ak, "expires_at", None) and ak.expires_at <= now:
                    log.warning("auth.expired_api_key.decorator path=%s api_key_id=%s last4=%s",
                                request.path, ak.id, ak.last4)
                    return jsonify({"error": "unauthorized", "code": "expired_api_key"}), 401

                _load_into_g(ak)

            if required_scope:
                scopes = getattr(g, "api_key_scopes", []) or []
                if required_scope not in scopes:
                    log.warning("auth.insufficient_scope path=%s api_key_id=%s required=%s have=%s",
                                request.path, g.api_key_id, required_scope, ",".join(scopes))
                    return jsonify({"error": "forbidden", "code": "insufficient_scope"}), 403

            return fn(*args, **kwargs)
        return _wrapped
    return _decorator
