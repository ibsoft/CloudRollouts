# update_server/config.py
from __future__ import annotations
import os
import pathlib
import tomllib
from typing import Any, Mapping

def _bool(v: Any, default: bool) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        s = v.strip().lower()
        if s in ("1", "true", "yes", "on"):
            return True
        if s in ("0", "false", "no", "off"):
            return False
    return default

def load_config(app, toml_path: str | os.PathLike | None = None) -> Mapping[str, Any]:
    """
    Φορτώνει ρυθμίσεις από TOML και τις εφαρμόζει στο app.config.
    Υποστηρίζει δύο σχήματα:
      α) Sectioned (app/database/logging/security/limiter/prometheus/scheduler/debug)
      β) Flat κλειδιά τύπου [app].SECRET_KEY, [logging].LOG_DIR κ.λπ. (όπως στο τρέχον δικό σου TOML)
    Δεν αγγίζει blueprints ή endpoints (π.χ. heartbeat).
    """
    # Defaults ασφαλείας
    defaults: dict[str, Any] = {
        "SECRET_KEY": "change-me",
        "JWT_SECRET_KEY": "change-me-jwt",
        "PREFERRED_URL_SCHEME": "http",
        "SERVER_NAME": None,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///instance/app.db",
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        "SQLALCHEMY_ENGINE_OPTIONS": {},
        "RATELIMIT_STORAGE_URI": "memory://",
        "RATELIMIT_DEFAULT": "200 per minute",
        "PROMETHEUS_ENABLED": True,
        "PROMETHEUS_PATH": "/metrics",
        "TRUST_PROXY": False,
        "REQUIRE_HTTPS": True,
        "HSTS_DAYS": 180,
        "ARTIFACTS_ROOT": "instance/artifacts",
        "ARTIFACTS_MAX_UPLOAD_MB": 2048,
        "ISSUER": "UpdateServer",
        "AUDIENCE": "Agents",
        "TOKEN_MINUTES": 60,
        "TENANT_RATE_LIMIT_PER_MINUTE": 120,
        "UPDATES_DEBUG": False,
        "LOGGING": {
            "dir": "logs",
            "level": "info",
            "json": True,
            "rotate_when": "midnight",
            "rotate_utc": True,
            "backup_count": 14,
            "max_bytes": 10_000_000,
            "backup_count_size": 5,
            "console": True,
            "updates_debug": False,
        },
        "SCHEDULER": {
            "enabled": True,
            "timezone": "UTC",
            "jobstores": {},
            "executors": {},
            "job_defaults": {},
        },
    }

    # Εντοπισμός αρχείου: προεπιλογή instance/config.toml
    if toml_path is None:
        toml_path = pathlib.Path(app.instance_path) / "config.toml"
    else:
        toml_path = pathlib.Path(toml_path)
        if not toml_path.is_absolute():
            # Αν είναι σχετικό, ψάξε πρώτα στο instance/, αλλιώς στη ρίζα project
            candidate = pathlib.Path(app.instance_path) / toml_path
            if candidate.exists():
                toml_path = candidate
            else:
                project_root = pathlib.Path(app.root_path).parent
                toml_path = project_root / toml_path

    loaded: dict[str, Any] = {}
    if toml_path.exists():
        with open(toml_path, "rb") as f:
            data = tomllib.load(f)

        # Διαβάζουμε sectioned schema
        app_cfg   = data.get("app", {})
        db_cfg    = data.get("database", {})
        log_cfg   = data.get("logging", {})
        sec_cfg   = data.get("security", {})
        lim_cfg   = data.get("limiter", {})
        prom_cfg  = data.get("prometheus", {})
        sched_cfg = data.get("scheduler", {})
        dbg_cfg   = data.get("debug", {})

        # Υποστήριξη flat κλειδιών στο [app] (όπως στο αρχείο σου)
        # π.χ. SECRET_KEY, SQLALCHEMY_DATABASE_URI, JWT_SECRET_KEY, ARTIFACTS_ROOT, REQUIRE_HTTPS, HSTS_DAYS κ.λπ.
        SECRET_KEY  = app_cfg.get("SECRET_KEY", sec_cfg.get("secret_key", defaults["SECRET_KEY"]))
        JWT_SECRET  = app_cfg.get("JWT_SECRET_KEY", sec_cfg.get("jwt_secret_key", defaults["JWT_SECRET_KEY"]))
        SQLA_URI    = app_cfg.get("SQLALCHEMY_DATABASE_URI", db_cfg.get("uri", defaults["SQLALCHEMY_DATABASE_URI"]))
        ART_ROOT    = app_cfg.get("ARTIFACTS_ROOT", defaults["ARTIFACTS_ROOT"])
        ART_MAX_MB  = app_cfg.get("ARTIFACTS_MAX_UPLOAD_MB", defaults["ARTIFACTS_MAX_UPLOAD_MB"])
        REQ_HTTPS   = _bool(app_cfg.get("REQUIRE_HTTPS", defaults["REQUIRE_HTTPS"]), defaults["REQUIRE_HTTPS"])
        HSTS_DAYS   = int(app_cfg.get("HSTS_DAYS", defaults["HSTS_DAYS"]))
        ISSUER      = app_cfg.get("ISSUER", defaults["ISSUER"])
        AUDIENCE    = app_cfg.get("AUDIENCE", defaults["AUDIENCE"])
        TOKEN_MIN   = int(app_cfg.get("TOKEN_MINUTES", defaults["TOKEN_MINUTES"]))
        TENANT_RLM  = int(app_cfg.get("TENANT_RATE_LIMIT_PER_MINUTE", defaults["TENANT_RATE_LIMIT_PER_MINUTE"]))
        TRUST_PROXY = _bool(app_cfg.get("TRUST_PROXY", defaults["TRUST_PROXY"]), defaults["TRUST_PROXY"])

        # Logging: υποστήριξη flat LOG_* κλειδιών
        LOGGING = {
            **defaults["LOGGING"],
            "dir":             log_cfg.get("LOG_DIR",     log_cfg.get("dir", defaults["LOGGING"]["dir"])),
            "level":           str(log_cfg.get("LOG_LEVEL", log_cfg.get("level", defaults["LOGGING"]["level"]))).lower(),
            "json":            _bool(log_cfg.get("LOG_JSON",  log_cfg.get("json", defaults["LOGGING"]["json"])), defaults["LOGGING"]["json"]),
            "console":         _bool(log_cfg.get("LOG_CONSOLE", log_cfg.get("console", defaults["LOGGING"]["console"])), defaults["LOGGING"]["console"]),
            "rotate_when":     log_cfg.get("LOG_ROTATE_WHEN", log_cfg.get("rotate_when", defaults["LOGGING"]["rotate_when"])),
            "rotate_utc":      _bool(log_cfg.get("LOG_ROTATE_UTC", log_cfg.get("rotate_utc", defaults["LOGGING"]["rotate_utc"])), defaults["LOGGING"]["rotate_utc"]),
            "backup_count":    int(log_cfg.get("LOG_BACKUP_COUNT", log_cfg.get("backup_count", defaults["LOGGING"]["backup_count"]))),
            "max_bytes":       int(log_cfg.get("LOG_MAX_BYTES", log_cfg.get("max_bytes", defaults["LOGGING"]["max_bytes"]))),
            "backup_count_size": int(log_cfg.get("LOG_BACKUP_COUNT_SIZE", log_cfg.get("backup_count_size", defaults["LOGGING"]["backup_count_size"]))),
        }

        # Limiter: υποστήριξη και sectioned και flat
        RATELIMIT_STORAGE_URI = lim_cfg.get("storage_uri", defaults["RATELIMIT_STORAGE_URI"])
        RATELIMIT_DEFAULT     = lim_cfg.get("default", defaults["RATELIMIT_DEFAULT"])

        # Prometheus
        PROMETHEUS_ENABLED = _bool(prom_cfg.get("enabled", defaults["PROMETHEUS_ENABLED"]), defaults["PROMETHEUS_ENABLED"])
        PROMETHEUS_PATH    = prom_cfg.get("path", defaults["PROMETHEUS_PATH"])

        # Scheduler
        SCHEDULER = {
            **defaults["SCHEDULER"],
            **({} if not isinstance(sched_cfg, dict) else sched_cfg),
        }

        # Debug flags
        UPDATES_DEBUG = _bool(dbg_cfg.get("UPDATES_DEBUG", defaults["UPDATES_DEBUG"]), defaults["UPDATES_DEBUG"])
        LOGGING["updates_debug"] = UPDATES_DEBUG
        
        raw_server_name = app_cfg.get("server_name", defaults["SERVER_NAME"])
        if isinstance(raw_server_name, str) and not raw_server_name.strip():
            raw_server_name = None


        loaded.update({
            "SECRET_KEY": SECRET_KEY,
            "JWT_SECRET_KEY": JWT_SECRET,
            "PREFERRED_URL_SCHEME": app_cfg.get("preferred_url_scheme", defaults["PREFERRED_URL_SCHEME"]),
            "SERVER_NAME": app_cfg.get("server_name", defaults["SERVER_NAME"]),
            "SQLALCHEMY_DATABASE_URI": SQLA_URI,
            "SQLALCHEMY_ENGINE_OPTIONS": db_cfg.get("engine_options", defaults["SQLALCHEMY_ENGINE_OPTIONS"]),
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
            "RATELIMIT_STORAGE_URI": RATELIMIT_STORAGE_URI,
            "RATELIMIT_DEFAULT": RATELIMIT_DEFAULT,
            "PROMETHEUS_ENABLED": PROMETHEUS_ENABLED,
            "PROMETHEUS_PATH": PROMETHEUS_PATH,
            "TRUST_PROXY": TRUST_PROXY,
            "REQUIRE_HTTPS": REQ_HTTPS,
            "HSTS_DAYS": HSTS_DAYS,
            "ARTIFACTS_ROOT": ART_ROOT,
            "ARTIFACTS_MAX_UPLOAD_MB": ART_MAX_MB,
            "ISSUER": ISSUER,
            "AUDIENCE": AUDIENCE,
            "TOKEN_MINUTES": TOKEN_MIN,
            "TENANT_RATE_LIMIT_PER_MINUTE": TENANT_RLM,
            "UPDATES_DEBUG": UPDATES_DEBUG,
            "LOGGING": LOGGING,
            "SCHEDULER": SCHEDULER,
        })

    # Τελική συγχώνευση: defaults ← loaded
    merged = {**defaults, **loaded}
    app.config.update(merged)
    return merged
