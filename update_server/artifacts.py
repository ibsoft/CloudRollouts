# update_server/artifacts.py
from __future__ import annotations

import os
import mimetypes
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional, Tuple

from flask import current_app, Response, request, abort, make_response

# -----------------------------
# Configuration helpers
# -----------------------------

def _artifact_roots() -> tuple[Path, ...]:
    """
    Allowed directories to read artifacts from.
    Primary: current_app.config["ARTIFACTS_ROOT"] (default: instance/artifacts)
    Secondary: ./artifacts (to support your existing layouts)
    """
    cfg_root = current_app.config.get("ARTIFACTS_ROOT", "instance/artifacts")
    roots = [Path(cfg_root), Path("artifacts")]
    # Keep only unique, existing (or potential) paths
    uniq: list[Path] = []
    for r in roots:
        try:
            rp = r.resolve()
        except Exception:
            rp = r
        if rp not in uniq:
            uniq.append(rp)
    return tuple(uniq)

def ensure_artifact_root(root: str | os.PathLike) -> None:
    Path(root).mkdir(parents=True, exist_ok=True)

# -----------------------------
# Hash utilities
# -----------------------------

def sha256_of_file(path: str | os.PathLike, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()

# -----------------------------
# Path safety
# -----------------------------

def _resolve_safe(path: str | os.PathLike) -> Path:
    """
    Resolve to an absolute path and ensure it's inside one of the allowed roots.
    """
    p = Path(path).resolve()
    roots = tuple(r.resolve() for r in _artifact_roots())
    if not any(str(p).startswith(str(root) + os.sep) or p == root for root in roots):
        current_app.logger.warning(f"Blocked artifact access outside roots: {p}")
        abort(403)
    return p

# -----------------------------
# HTTP helpers
# -----------------------------

def _httpdate(ts: float) -> str:
    # RFC 1123 date
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")

def _guess_mime(path: Path, default: str = "application/octet-stream") -> str:
    mt, _ = mimetypes.guess_type(str(path))
    return mt or default

def _make_etag(size: int, mtime: float) -> str:
    # lightweight strong ETag: size + mtime
    return f'"{size:x}-{int(mtime):x}"'

def _parse_range(range_header: str, file_size: int) -> Optional[Tuple[int, int]]:
    """
    Parse a single-range "bytes=start-end" header.
    Return (start, end) inclusive, or None if invalid/unsatisfiable.
    We serve only a single range; if multiple ranges requested, we ignore and return None.
    """
    try:
        units, rng = range_header.split("=", 1)
    except ValueError:
        return None
    if units.strip().lower() != "bytes":
        return None
    # Disallow multiple ranges (comma)
    if "," in rng:
        return None
    start_str, _, end_str = rng.partition("-")
    start_str = start_str.strip()
    end_str = end_str.strip()
    if start_str == "" and end_str == "":
        return None
    if start_str == "":  # suffix range "-N"
        length = int(end_str)
        if length <= 0:
            return None
        if length > file_size:
            length = file_size
        return (file_size - length, file_size - 1)
    start = int(start_str) if start_str else 0
    end = int(end_str) if end_str else file_size - 1
    if start >= file_size:
        return None
    if end < start:
        return None
    if end >= file_size:
        end = file_size - 1
    return (start, end)

def _iter_file(path: Path, start: int, end: int, chunk_size: int) -> Iterable[bytes]:
    remaining = end - start + 1
    with open(path, "rb") as f:
        f.seek(start)
        while remaining > 0:
            chunk = f.read(min(chunk_size, remaining))
            if not chunk:
                break
            remaining -= len(chunk)
            yield chunk

# -----------------------------
# Main streaming entrypoint
# -----------------------------

def stream_file(
    path: str | os.PathLike,
    mime: Optional[str] = None,
    download_name: Optional[str] = None,
) -> Response:
    """
    Stream a file with support for:
      - HEAD and GET
      - Range requests (resume)
      - If-Range, If-None-Match, If-Modified-Since
      - ETag, Last-Modified
      - Accept-Ranges, Content-Length
    Path is validated to reside under allowed artifact roots.
    """

    # Optional acceleration (offload to nginx/apache) via config:
    #   SEND_X_ACCEL_REDIRECT = True
    #   X_ACCEL_PREFIX = "/protected-artifacts"   (nginx location)
    # or:
    #   SEND_X_SENDFILE = True   (Apache/mod_xsendfile or uwsgi)
    send_accel = bool(current_app.config.get("SEND_X_ACCEL_REDIRECT"))
    accel_prefix = current_app.config.get("X_ACCEL_PREFIX", "/")  # must map to artifact roots in your web server
    send_xsendfile = bool(current_app.config.get("SEND_X_SENDFILE"))

    CHUNK = int(current_app.config.get("STREAM_CHUNK_SIZE", 1024 * 1024))  # 1MB default

    p = _resolve_safe(path)
    if not p.exists() or not p.is_file():
        abort(404)

    stat = p.stat()
    file_size = stat.st_size
    mtime = stat.st_mtime
    etag = _make_etag(file_size, mtime)
    last_mod = _httpdate(mtime)
    mime = mime or _guess_mime(p)
    download_name = download_name or p.name

    # Conditional requests (only for full GET)
    if request.method == "GET" and not request.headers.get("Range"):
        inm = request.headers.get("If-None-Match")
        ims = request.headers.get("If-Modified-Since")
        if inm and inm.strip() == etag:
            resp = make_response("", 304)
            resp.headers["ETag"] = etag
            resp.headers["Last-Modified"] = last_mod
            resp.headers["Accept-Ranges"] = "bytes"
            return resp
        if ims:
            # If-Modified-Since is weak; ignore parsing errors
            try:
                # Compare on seconds
                since_dt = ims
                # Simple string compare: if equal to last_mod, treat as not modified
                if ims == last_mod:
                    resp = make_response("", 304)
                    resp.headers["ETag"] = etag
                    resp.headers["Last-Modified"] = last_mod
                    resp.headers["Accept-Ranges"] = "bytes"
                    return resp
            except Exception:
                pass

    # HEAD short-circuit (no body)
    if request.method == "HEAD":
        resp = make_response("", 200)
        resp.headers["Content-Type"] = mime
        resp.headers["Content-Length"] = str(file_size)
        resp.headers["Accept-Ranges"] = "bytes"
        resp.headers["Content-Disposition"] = f'attachment; filename="{download_name}"'
        resp.headers["ETag"] = etag
        resp.headers["Last-Modified"] = last_mod
        return resp

    # Handle Range / If-Range
    rng_hdr = request.headers.get("Range")
    if rng_hdr:
        # If-Range validator
        if_range = request.headers.get("If-Range")
        if if_range:
            # If matches current ETag (or equals Last-Modified), honor Range; else serve full
            if if_range.strip() not in (etag, last_mod):
                rng_hdr = None  # ignore range

    # Optional acceleration (full file only)
    if not rng_hdr and (send_accel or send_xsendfile):
        resp = make_response("", 200)
        resp.headers["Content-Type"] = mime
        resp.headers["Content-Length"] = str(file_size)
        resp.headers["Accept-Ranges"] = "bytes"
        resp.headers["Content-Disposition"] = f'attachment; filename="{download_name}"'
        resp.headers["ETag"] = etag
        resp.headers["Last-Modified"] = last_mod
        if send_accel:
            # Map filesystem path to internal URL; you must configure your web server to match.
            # Example: if artifacts live under /var/app/instance/artifacts and nginx has:
            #   location /protected-artifacts/ { internal; alias /var/app/instance/artifacts/; }
            # set X_ACCEL_PREFIX="/protected-artifacts"
            internal_uri = str(p)
            # naive mapping: try to strip common root and prepend prefix
            roots = [r.resolve() for r in _artifact_roots()]
            for root in roots:
                try:
                    rel = p.resolve().relative_to(root)
                    internal_uri = str(Path(accel_prefix).joinpath(rel)).replace("\\", "/")
                    break
                except Exception:
                    continue
            resp.headers["X-Accel-Redirect"] = internal_uri
        if send_xsendfile:
            resp.headers["X-Sendfile"] = str(p)
        return resp

    # Ranged or full streaming from Python
    if rng_hdr:
        rng = _parse_range(rng_hdr, file_size)
        if rng is None:
            # Unsatisfiable
            return Response(status=416, headers={"Content-Range": f"bytes */{file_size}"})
        start, end = rng
        length = end - start + 1
        resp = Response(_iter_file(p, start, end, CHUNK), status=206, mimetype=mime, direct_passthrough=True)
        resp.headers["Content-Range"] = f"bytes {start}-{end}/{file_size}"
        resp.headers["Accept-Ranges"] = "bytes"
        resp.headers["Content-Length"] = str(length)
        resp.headers["Content-Disposition"] = f'attachment; filename="{download_name}"'
        resp.headers["ETag"] = etag
        resp.headers["Last-Modified"] = last_mod
        return resp

    # Full body stream
    resp = Response(_iter_file(p, 0, file_size - 1, CHUNK), mimetype=mime, direct_passthrough=True)
    resp.headers["Content-Length"] = str(file_size)
    resp.headers["Accept-Ranges"] = "bytes"
    resp.headers["Content-Disposition"] = f'attachment; filename="{download_name}"'
    resp.headers["ETag"] = etag
    resp.headers["Last-Modified"] = last_mod
    return resp
