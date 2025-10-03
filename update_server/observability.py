# update_server/observability.py
from __future__ import annotations

import os
import json
import logging
from logging.handlers import TimedRotatingFileHandler, RotatingFileHandler
from typing import Optional, Any

import structlog
from flask import Flask, request

# Redact these headers when wire-logging
_REDACT_HEADERS = {"authorization", "x-api-key", "cookie", "set-cookie"}


def _cfg(app: Flask, key: str, default=None):
    return app.config.get(key, default)


def _ensure_dir(path: str) -> None:
    try:
        os.makedirs(path, exist_ok=True)
    except Exception:
        pass


def _build_stdlib_handlers(app: Flask, filename_base: str) -> list[logging.Handler]:
    """
    File handlers under LOG_DIR with time rotation, optionally size rotation,
    and an optional console handler — όλα από app.config.
    """
    handlers: list[logging.Handler] = []
    log_dir = _cfg(app, "LOG_DIR", "logs")
    level = _cfg(app, "LOG_LEVEL", "INFO").upper()
    rotate_when = _cfg(app, "LOG_ROTATE_WHEN", "midnight")
    rotate_utc = bool(_cfg(app, "LOG_ROTATE_UTC", True))
    backup_count = int(_cfg(app, "LOG_BACKUP_COUNT", 14))
    max_bytes = int(_cfg(app, "LOG_MAX_BYTES", 0))
    backup_count_size = int(_cfg(app, "LOG_BACKUP_COUNT_SIZE", 5))
    log_console = bool(_cfg(app, "LOG_CONSOLE", True))

    base_path = os.path.join(log_dir, filename_base)

    # Time-rotating file handler
    time_handler = TimedRotatingFileHandler(
        base_path,
        when=rotate_when,
        backupCount=backup_count,
        utc=rotate_utc,
        encoding="utf-8",
    )
    time_handler.setLevel(level)
    handlers.append(time_handler)

    # Optional size-based rotation (extra)
    if max_bytes and max_bytes > 0:
        size_handler = RotatingFileHandler(
            base_path,
            maxBytes=max_bytes,
            backupCount=backup_count_size,
            encoding="utf-8",
        )
        size_handler.setLevel(level)
        handlers.append(size_handler)

    # Optional console
    if log_console:
        stream = logging.StreamHandler()
        stream.setLevel(level)
        handlers.append(stream)

    return handlers


def _structlog_processors(app: Flask):
    procs = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    if bool(_cfg(app, "LOG_JSON", False)):
        procs.append(structlog.processors.JSONRenderer())
    else:
        procs.append(structlog.dev.ConsoleRenderer(colors=True))
    return procs


def configure_logging(app: Optional[Flask] = None) -> None:
    """
    Configure stdlib root logger + structlog using app.config only.
    Creates:
      - <LOG_DIR>/app.log
      - <LOG_DIR>/updates.log  (agent wire logs)
    """
    if app is None:
        raise RuntimeError("configure_logging requires Flask app")

    log_dir = _cfg(app, "LOG_DIR", "logs")
    level = _cfg(app, "LOG_LEVEL", "INFO").upper()
    _ensure_dir(log_dir)

    # --- stdlib root ---
    logging.captureWarnings(True)
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level, logging.INFO))

    # Drop preexisting handlers to avoid duplicates on reload
    for h in list(root_logger.handlers):
        root_logger.removeHandler(h)

    # App handlers
    for h in _build_stdlib_handlers(app, "app.log"):
        h.setFormatter(logging.Formatter("%(message)s"))
        root_logger.addHandler(h)

    # Quiet/noisy libs if desired
    logging.getLogger("werkzeug").setLevel(_cfg(app, "LOG_LEVEL", "INFO").upper())

    # --- structlog ---
    structlog.configure(
        processors=_structlog_processors(app),
        wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, level, logging.INFO)),
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # “updates” dedicated logger
    updates_logger = logging.getLogger("updates")
    updates_logger.setLevel(getattr(logging, level, logging.INFO))
    for h in _build_stdlib_handlers(app, "updates.log"):
        h.setFormatter(logging.Formatter("%(message)s"))
        updates_logger.addHandler(h)

    # Bind handlers to Flask app logger too
    app.logger.handlers = root_logger.handlers
    app.logger.setLevel(getattr(logging, level, logging.INFO))

    structlog.get_logger("app").info(
        "logging-configured",
        log_dir=log_dir,
        level=level,
        json=bool(_cfg(app, "LOG_JSON", False)),
        rotate_when=_cfg(app, "LOG_ROTATE_WHEN", "midnight"),
        rotate_utc=bool(_cfg(app, "LOG_ROTATE_UTC", True)),
        backup_count=int(_cfg(app, "LOG_BACKUP_COUNT", 14)),
        max_bytes=int(_cfg(app, "LOG_MAX_BYTES", 0)),
        backup_count_size=int(_cfg(app, "LOG_BACKUP_COUNT_SIZE", 5)),
        console=bool(_cfg(app, "LOG_CONSOLE", True)),
        updates_debug=bool(_cfg(app, "UPDATES_DEBUG", False)),
    )


def _redact_headers(h: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in (h or {}).items():
        lk = k.lower()
        if lk in _REDACT_HEADERS:
            out[k] = "***"
        else:
            out[k] = v
    return out


def add_updates_http_logging(app: Flask) -> None:
    """
    Αν UPDATES_DEBUG=True στο config, γράφουμε request/response bodies για /api/agents/*
    στο <LOG_DIR>/updates.log. Bodies capped & sensitive headers redacted.
    """
    updates = structlog.get_logger("updates")

    def _cap(s: str | bytes | None, limit: int = 4096) -> str | None:
        if s is None:
            return None
        if isinstance(s, bytes):
            s = s.decode("utf-8", errors="replace")
        return s if len(s) <= limit else (s[:limit] + f"... <{len(s)-limit} bytes truncated>")

    @app.before_request
    def _log_inbound():
        if not bool(_cfg(app, "UPDATES_DEBUG", False)):
            return
        path = (request.path or "")
        # πιο ανεκτικό check ώστε να παίζει και με reverse-proxy prefixes (π.χ. /updates/api/agents/..)
        if "/api/agents/" not in path:
            return
        try:
            js = request.get_json(silent=True)
        except Exception:
            js = None
        try:
            headers = _redact_headers(dict(request.headers))
        except Exception:
            headers = {}
        updates.info(
            "agent-in",
            method=request.method,
            path=path,
            remote=request.headers.get("X-Forwarded-For") or request.remote_addr,
            headers=headers,
            json=js if js is not None else _cap(request.get_data(cache=True)),
        )

    @app.after_request
    def _log_outbound(resp):
        if not bool(_cfg(app, "UPDATES_DEBUG", False)):
            return resp
        path = (request.path or "")
        if "/api/agents/" not in path:
            return resp

        body_obj: Optional[Any] = None
        content_type = (resp.headers.get("Content-Type") or "").lower()
        try:
            if "application/json" in content_type and resp.direct_passthrough is False:
                data = resp.get_data(as_text=True)
                try:
                    body_obj = json.loads(data)
                except Exception:
                    body_obj = _cap(data)
            elif "text/" in content_type and resp.direct_passthrough is False:
                body_obj = _cap(resp.get_data(as_text=True))
        except Exception:
            body_obj = None

        updates.info(
            "agent-out",
            status=resp.status_code,
            path=path,
            json=body_obj,
        )
        return resp


def register_health(app: Flask) -> None:
    """Health endpoint που επιβεβαιώνει ότι τα logs είναι εγγράψιμα."""
    @app.get("/healthz")
    def _healthz():
        log_dir = _cfg(app, "LOG_DIR", "logs")
        writable = False
        try:
            _ensure_dir(log_dir)
            test_path = os.path.join(log_dir, ".healthcheck")
            with open(test_path, "a", encoding="utf-8") as f:
                f.write("ok\n")
            writable = True
        except Exception:
            writable = False
        app_log_path = os.path.join(log_dir, "app.log")
        return {
            "status": "ok",
            "time": os.path.getmtime(app_log_path) if os.path.exists(app_log_path) else None,

        }
