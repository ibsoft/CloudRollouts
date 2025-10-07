# update_server/api/views.py
from __future__ import annotations


"""
API layer για agents, artifacts και rollouts.

Στόχοι οργάνωσης:
- Κεντρικό auth gate για όλα τα API routes (API key + tenant scoping).
- Σαφή helpers για windows/policies/targeting χωρίς side-effects.
- Προσεκτικός χειρισμός χρόνου: αποθήκευση σε naive UTC όταν το schema είναι naive,
  και χρήση ZoneInfo μόνο για αξιολόγηση windows/policies.
- Καμία αλλαγή στη λειτουργικότητα του /agents/heartbeat· μόνο σχολιασμός/τάξη.

Σημείωση: Το blueprint καταχωρείται στο app με url_prefix="/api".
"""

import os
import json
import mimetypes
import datetime as dt
from datetime import datetime as _dt
from glob import glob
from typing import Optional
from sqlalchemy import select, text as sqltext
from flask import Blueprint, request, jsonify, g, current_app

from ..extensions import db, limiter
from ..models import (
    Device,
    Package,
    PackageVersion,
    DeviceInstallation,
    Rollout,
    RolloutTarget,
)
from ..artifacts import stream_file
from ..security import require_tenant  # υφιστάμενο guard tenant
from .auth import resolve_tenant_from_api_key, require_api_key

import zoneinfo
from zoneinfo import ZoneInfo
from packaging.version import Version, InvalidVersion  # pip install packaging


# -------------------------------------------------------------------
# Blueprint
# -------------------------------------------------------------------
api_bp = Blueprint("api", __name__)


# -------------------------------------------------------------------
# Παγκόσμια θύρα ελέγχου αυθεντικοποίησης για ΟΛΑ τα API routes.
# Επιστρέφει None στην επιτυχία, αλλιώς κατάλληλο response για σφάλμα.
# -------------------------------------------------------------------
@api_bp.before_request
def _api_auth_gate():
    """
    Ενιαία είσοδος ελέγχου API-κλειδιού και tenant scoping.

    Επιτρέπει τα CORS preflight (OPTIONS) ανέπαφα.
    Εφαρμόζει resolve_tenant_from_api_key, που αναλαμβάνει:
      • έλεγχο Authorization header
      • επιβολή scopes
      • δέσιμο του g.tenant_id (ή ανάγνωση από global API key αν υποστηρίζεται)
    """
    if request.method == "OPTIONS":
        return None
    return resolve_tenant_from_api_key()  # None => proceed


# -------------------------------------------------------------------
# Βοηθητικές συναρτήσεις χωρίς παρενέργειες
# -------------------------------------------------------------------
def _device_matches_rollout_targets(rollout: Rollout, device_id: int) -> bool:
    """
    Αποφασίζει αν μία συσκευή ταιριάζει στους στόχους ενός rollout.
    Κανόνες:
      • Χωρίς targets => global => True.
      • Αν target device_id => match σε κατά λέξη ταυτότητα.
      • Αν target fleet_id => match σε ισότητα στόλου.
    """
    targets = RolloutTarget.query.filter_by(rollout_id=rollout.id).all()
    if not targets:
        return True  # global rollout

    d = Device.query.get(device_id)
    if not d:
        return False

    for t in targets:
        if t.device_id and t.device_id == device_id:
            return True
        if t.fleet_id and t.fleet_id == getattr(d, "fleet_id", None):
            return True
    return False


def _now_in_window(win: str, *, now_utc: Optional[dt.datetime] = None) -> bool:
    """
    Έλεγχος maintenance window.

    Μορφές:
      • "any" => πάντα True.
      • "HH:MM-HH:MM <IANA TZ>" (π.χ. "22:00-04:00 Europe/Athens").
        Κανόνες: inclusive start, exclusive end, υποστηρίζεται τύλιγμα μετά τα μεσάνυχτα.

    Σε invalid τιμές, επιστρέφει False (ασφαλής άρνηση).
    """
    win = (win or "any").strip().lower()
    if win == "any":
        return True

    try:
        times_part, tz_part = win.rsplit(" ", 1)
        start_s, end_s = [s.strip() for s in times_part.split("-", 1)]
        tz = zoneinfo.ZoneInfo(tz_part)
        now_utc = now_utc or dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc)
        now_local = now_utc.astimezone(tz)

        sh, sm = map(int, start_s.split(":"))
        eh, em = map(int, end_s.split(":"))
        start_local = now_local.replace(hour=sh, minute=sm, second=0, microsecond=0)
        end_local = now_local.replace(hour=eh, minute=em, second=0, microsecond=0)

        if end_local <= start_local:
            # window που περνάει μεσάνυχτα
            return (now_local >= start_local) or (now_local < end_local)
        else:
            return (now_local >= start_local) and (now_local < end_local)
    except Exception:
        return False


def _get_window_tz(win: str) -> ZoneInfo:
    """
    Επιστρέφει το ZoneInfo που χρησιμοποιείται για αξιολόγηση maintenance-window
    και policy χρονικών κανόνων σε τοπικό χρόνο. Σε αδυναμία, επιστρέφει UTC.
    """
    try:
        if not win or win.strip().lower() == "any":
            return ZoneInfo("UTC")
        _, tz_part = win.rsplit(" ", 1)
        return ZoneInfo(tz_part)
    except Exception:
        return ZoneInfo("UTC")


def _parse_policy(text: str) -> dict:
    """
    Ασφαλής JSON parse πολιτικής. Μη dict ή invalid => κενό dict.
    """
    try:
        pol = json.loads(text) if text and text.strip() else {}
        return pol if isinstance(pol, dict) else {}
    except Exception:
        return {}


def _policy_allows_now(pol: dict, *, now_local: dt.datetime, device: Device) -> tuple[bool, int, str]:
    """
    Εφαρμογή απλών policy gates.

    Επιστρέφει τριάδα (allowed, throttleSeconds, reason).
    Υποστηριζόμενα κλειδιά:
      • allowedWeekdays: λίστα από 1..7 (Δευτέρα=1 .. Κυριακή=7)
      • minAgentVersion: συμβολοσειρά semver που απαιτεί ελάχιστη έκδοση agent
      • throttleSeconds: ακέραιος >= 0 (hint προς τον agent)
      • maxRetriesPerDevice: δεν εφαρμόζεται εδώ, μπορεί να αξιοποιηθεί αν χρειαστεί
      • deferOutsideWindow: bool, default True (ελέγχεται μέσω _now_in_window)
    """
    wk = pol.get("allowedWeekdays")
    if isinstance(wk, list) and wk:
        try:
            wk_set = {int(x) for x in wk}
        except Exception:
            wk_set = set()
        if wk_set and now_local.isoweekday() not in wk_set:
            return False, 60, "weekday_block"

    minv = pol.get("minAgentVersion")
    if isinstance(minv, str) and minv.strip() and (device.agent_version or "").strip():
        try:
            if Version(device.agent_version.strip()) < Version(minv.strip()):
                return False, 300, "min_agent_version"
        except InvalidVersion:
            # Κακοδιατυπωμένη έκδοση => αγνόησε αυτό το gate
            pass

    thr = pol.get("throttleSeconds", 0)
    try:
        thr = max(0, int(thr))
    except Exception:
        thr = 0

    return True, thr, ""


# -------------------------------------------------------------------
# Agent endpoints
# -------------------------------------------------------------------
@api_bp.post("/agents/register")
@limiter.limit("300/minute")
@require_api_key("agents")
@require_tenant
def register_agent():
    """
    Καταχώριση/ενημέρωση συσκευής με βάση hostname και fleet_id.
    Απαιτείται κλειδί με scope "agents" και σωστό tenant context (g.tenant_id).
    """
    data = request.get_json(silent=True) or {}
    hostname = (data.get("hostname") or "").strip()
    fleet_id = data.get("fleetId")

    try:
        fleet_id = int(fleet_id)
    except (TypeError, ValueError):
        fleet_id = 0

    if not hostname or fleet_id <= 0:
        return jsonify({"error": "hostname_and_fleetId_required"}), 400

    d = Device.query.filter_by(tenant_id=g.tenant_id, hostname=hostname).first()
    if not d:
        d = Device(
            tenant_id=g.tenant_id,
            fleet_id=fleet_id,
            hostname=hostname,
            status="idle",
        )
        db.session.add(d)
        db.session.commit()

    return jsonify({"deviceId": d.id, "status": d.status})


@api_bp.post("/agents/heartbeat")
@limiter.limit("1200/minute")
@require_api_key("agents")
@require_tenant
def heartbeat():
    """
    ΣΗΜΑΝΤΙΚΟ: Η συμπεριφορά του endpoint παραμένει αμετάβλητη. Προστέθηκαν μόνο σχόλια.

    Λογική:
    1) Εντοπισμός συσκευής βάσει deviceId και tenant.
    2) Ενημέρωση telemetry (IP, last_seen_at, agent/os version).
    3) Εξέταση εκκρεμούς εγκατάστασης που είναι due (rollout status, start time, window, targets).
    4) Αυτόματη δημιουργία pending εγκατάστασης αν δεν υπάρχει applicable pending, με αποφυγή διπλοεγγραφών.
    5) Επιστροφή action "install" αν είναι εντός window τη στιγμή της απάντησης, μαζί με throttle hint από policy.

    Headers debug:
      • X-Debug-Now: ISO8601 UTC (π.χ. "2025-10-01T19:30:00Z") για τεστ window χωρίς να βασιστούμε στο ρολόι του server.
    """
    data = request.get_json(silent=True) or {}
    try:
        device_id = int(data.get("deviceId", 0))
    except (TypeError, ValueError):
        device_id = 0

    d = Device.query.filter_by(id=device_id, tenant_id=g.tenant_id).first()
    if not d:
        # 404 για άγνωστη συσκευή στο tenant αυτό
        return jsonify({"actions": [], "throttleSeconds": 0}), 404

    # Επιλογή "now" για αξιολόγηση windows. Επιτρέπεται header override αποκλειστικά για δοκιμές.
    debug_now = (request.headers.get("X-Debug-Now") or "").strip()
    now_utc = None
    if debug_now:
        try:
            if debug_now.endswith("Z"):
                debug_now = debug_now[:-1] + "+00:00"
            now_utc = dt.datetime.fromisoformat(debug_now)
            if now_utc.tzinfo is None:
                now_utc = now_utc.replace(tzinfo=dt.timezone.utc)
            else:
                now_utc = now_utc.astimezone(dt.timezone.utc)
        except Exception:
            now_utc = None
    if not now_utc:
        now_utc = dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc)

    # Telemetry/last seen: αποθηκεύουμε naive UTC timestamp αν το schema είναι naive.
    xff = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    d.last_ip = xff or request.remote_addr
    d.last_seen_at = now_utc.replace(tzinfo=None)
    if data.get("agentVersion"):
        d.agent_version = data["agentVersion"]
    if data.get("osVersion"):
        d.os_version = data["osVersion"]
    db.session.commit()

    # Εσωτερικός helper targeting με υποστήριξη "AND" για fleets+devices, "OR" όταν υπάρχει μόνο ένα από τα δύο.
    def _matches_targets(r: Rollout, dev: Device) -> bool:
        ts = RolloutTarget.query.filter_by(rollout_id=r.id).all()
        fleet_ids = {t.fleet_id for t in ts if t.fleet_id}
        device_ids = {t.device_id for t in ts if t.device_id}
        has_f = bool(fleet_ids)
        has_d = bool(device_ids)

        if not has_f and not has_d:
            return True  # global
        if has_f and has_d:
            return (dev.fleet_id in fleet_ids) and (dev.id in device_ids)
        if has_f:
            return dev.fleet_id in fleet_ids
        return dev.id in device_ids

    # Εντοπισμός εκκρεμούς εγκατάστασης που είναι due (rollout ok + targets + window).
    naive_now = now_utc.replace(tzinfo=None)
    inst = (
        db.session.query(DeviceInstallation)
        .join(Rollout, Rollout.id == DeviceInstallation.rollout_id)
        .filter(
            DeviceInstallation.device_id == d.id,
            DeviceInstallation.status == "pending",
            Rollout.tenant_id == g.tenant_id,
            Rollout.status.in_(["running", "scheduled"]),
            Rollout.start_at <= naive_now,
        )
        .order_by(DeviceInstallation.id.desc())
        .first()
    )

    if inst:
        r = Rollout.query.get(inst.rollout_id)
        if not r or not _matches_targets(r, d) or not _now_in_window(r.maintenance_window, now_utc=now_utc):
            inst = None

    # Καθαρισμός orphan pending (rollout_id=None) ώστε να μην απαντώνται ψευδο-actions.
    if not inst:
        orphan = (
            DeviceInstallation.query
            .filter_by(device_id=d.id, status="pending", rollout_id=None)
            .order_by(DeviceInstallation.id.desc())
            .first()
        )
        if orphan:
            orphan.status = "failed"  # ή "cancelled" αν υποστηρίζεται
            orphan.finished_at = naive_now
            db.session.commit()

    # Αυτόματη δημιουργία pending, τηρώντας window/targets και αποφυγή διπλών εγγραφών για ίδιο pkg/version.
    if not inst:
        due_rollouts = (
            Rollout.query
            .filter(
                Rollout.tenant_id == g.tenant_id,
                Rollout.status.in_(["running", "scheduled"]),
                Rollout.start_at <= naive_now,
            )
            .order_by(Rollout.id.asc())
            .all()
        )

        for r in due_rollouts:
            if not _now_in_window(r.maintenance_window, now_utc=now_utc):
                continue

            if r.status == "scheduled":
                r.status = "running"
                db.session.flush()

            pv = PackageVersion.query.filter_by(package_id=r.package_id, semver=r.version).first()
            if not pv:
                continue

            if not _matches_targets(r, d):
                continue

            existing = (
                DeviceInstallation.query
                .filter_by(device_id=d.id, package_id=r.package_id, version=r.version)
                .order_by(DeviceInstallation.id.desc())
                .first()
            )
            if existing:
                if existing.status == "pending":
                    inst = existing
                    break
                if existing.status in {"in_progress", "installing", "running"}:
                    continue
                if existing.status == "succeeded":
                    continue
                # failed -> allow retry

            inst = DeviceInstallation(
                device_id=d.id,
                package_id=r.package_id,
                version=r.version,
                status="pending",
                rollout_id=r.id,
                started_at=None,
                finished_at=None,
            )
            db.session.add(inst)
            db.session.flush()
            break

        db.session.commit()

    # Κατασκευή actions. Εφαρμόζεται ξανά το window την ώρα της απάντησης.
    actions: list[dict] = []
    if inst and inst.status == "pending":
        r = Rollout.query.get(inst.rollout_id) if inst.rollout_id else None
        if (r is None) or _now_in_window(r.maintenance_window, now_utc=now_utc):
            actions.append({
                "action": "install",
                "packageId": inst.package_id,
                "version":   inst.version,
            })

    # Απόσπαση throttle hint από policy, με σεβασμό maintenance window και minAgentVersion.
    throttle = 0
    if inst and inst.rollout_id:
        r = Rollout.query.get(inst.rollout_id)
        if r and getattr(r, "policy_json", None):
            pol = _parse_policy(r.policy_json)
            tz = _get_window_tz(getattr(r, "maintenance_window", "any"))
            now_local = now_utc.astimezone(tz) if now_utc.tzinfo else now_utc.replace(tzinfo=dt.timezone.utc).astimezone(tz)
            allowed, thr, _ = _policy_allows_now(pol, now_local=now_local, device=d)
            if not allowed:
                actions = []
            throttle = max(throttle, thr or 0)

    return jsonify({"actions": actions, "throttleSeconds": throttle})


@api_bp.route("/updates/<int:package_id>/<version>", methods=["GET", "HEAD"])
@require_api_key("agents")
@require_tenant
def download_package(package_id: int, version: str):
    """
    Εξυπηρέτηση artifact για package/version με ανθεκτική αναζήτηση.

    Προτεραιότητες:
      1) storage_path (ή file_path) από DB, εφόσον υπάρχει και είναι αρχείο.
      2) Συνήθη patterns κάτω από instance/artifacts και artifacts.
      3) Αναδρομικό glob στο artifacts/<package_id>/** για .zip, με προτεραιότητα στα paths που περιέχουν το version.

    Υποστηρίζει HEAD και GET. Το GET γίνεται με stream_file ώστε να παίζει range requests.
    """
    def _abs(p: str) -> str:
        return p if os.path.isabs(p) else os.path.abspath(p)

    roots = [os.getenv("UPDATE_ARTIFACT_ROOT", "instance/artifacts"), "artifacts"]

    pv = (
        PackageVersion.query.join(Package, PackageVersion.package_id == Package.id)
        .filter(
            Package.tenant_id == g.tenant_id,
            PackageVersion.package_id == package_id,
            (getattr(PackageVersion, "semver", None) == version)
            if hasattr(PackageVersion, "semver")
            else (getattr(PackageVersion, "version") == version),
        ).first()
    )

    db_path = getattr(pv, "storage_path", None) or getattr(pv, "file_path", None) if pv is not None else None
    tried: list[str] = []

    cand_list: list[str] = []
    if db_path:
        cand_list.append(_abs(db_path))
        if db_path.startswith("instance" + os.sep):
            cand_list.append(_abs(db_path[len("instance" + os.sep):]))
        else:
            cand_list.append(_abs(os.path.join("instance", db_path)))

    for root_dir in roots:
        cand_list.extend([
            _abs(f"{root_dir}/{package_id}/{version}.zip"),
            _abs(f"{root_dir}/{package_id}/{version}/artifact.zip"),
            _abs(f"{root_dir}/{package_id}/{version}/{package_id}-{version}.zip"),
        ])

    for root_dir in roots:
        base = _abs(os.path.join(root_dir, str(package_id)))
        if os.path.isdir(base):
            zips = glob(os.path.join(base, "**", "*.zip"), recursive=True)
            zips = sorted(zips, key=lambda p: (version not in p, len(p)))
            cand_list.extend([_abs(z) for z in zips])

    real_path = None
    for c in cand_list:
        tried.append(c)
        if os.path.isfile(c):
            real_path = c
            break

    if real_path is None:
        return jsonify({"error": "package_version_artifact_not_found", "tried": tried, "db_path": db_path}), 404

    if request.method == "HEAD":
        size = os.path.getsize(real_path)
        mt = mimetypes.guess_type(real_path)[0] or "application/octet-stream"
        resp = current_app.response_class(status=200, mimetype=mt)
        resp.headers["Content-Length"] = str(size)
        resp.headers["Accept-Ranges"] = "bytes"
        resp.headers["Content-Disposition"] = f'attachment; filename="{os.path.basename(real_path)}"'
        return resp

    return stream_file(real_path)


# -------------------------------------------------------------------
# Install results — normalization status και συσχέτιση με rollout όπου γίνεται
# -------------------------------------------------------------------
_TERMINAL_OK = {"success", "succeeded", "ok", "completed", "done"}
_TERMINAL_FAIL = {"fail", "failed", "error"}


def _normalize_status(s: str) -> str:
    """
    Ομαλοποίηση status από agent σε τυπικές τιμές.
    """
    s = (s or "").strip().lower()
    if s in _TERMINAL_OK:
        return "succeeded"
    if s in _TERMINAL_FAIL:
        return "failed"
    if s in {"pending", "in_progress", "installing", "running"}:
        return "in_progress"
    return "in_progress"


@api_bp.post("/agents/install-results")
@require_api_key("agents")
@require_tenant
def agents_install_results():
    """
    Παραλαβή αποτελεσμάτων εγκατάστασης από agent. Γίνεται ομαλοποίηση status,
    αντιστοίχιση με rollout όπου είναι δυνατό, και ενημέρωση χρονικών στιγμών.
    Επιπλέον: όταν μια εγκατάσταση μεταβαίνει σε 'succeeded', χρεώνεται ο tenant
    κατά το admin-fixed rate ανά συσκευή (μία φορά).
    """
    data = request.get_json(silent=True) or {}
    device_id = data.get("deviceId")
    package_id = data.get("packageId")
    version = (data.get("version") or "").strip()
    status = _normalize_status(data.get("status"))

    try:
        device_id = int(device_id)
    except (TypeError, ValueError):
        device_id = 0
    try:
        package_id = int(package_id)
    except (TypeError, ValueError):
        package_id = 0

    if not (device_id and package_id and version):
        return jsonify({"error": "bad_request", "code": "missing_fields"}), 400

    di = (
        DeviceInstallation.query
        .filter_by(device_id=device_id, package_id=package_id, version=version)
        .order_by(DeviceInstallation.id.desc())
        .first()
    )
    if not di:
        di = DeviceInstallation(
            device_id=device_id,
            package_id=package_id,
            version=version,
            status="in_progress",
            started_at=_dt.utcnow(),
        )
        db.session.add(di)

    if not getattr(di, "rollout_id", None):
        r = (
            Rollout.query
            .filter_by(tenant_id=g.tenant_id, package_id=package_id, version=version)
            .order_by(Rollout.id.desc())
            .first()
        )
        if r and _device_matches_rollout_targets(r, device_id):
            di.rollout_id = r.id

    prev_status = di.status
    di.status = status
    if status in {"succeeded", "failed"} and getattr(di, "finished_at", None) is None:
        di.finished_at = _dt.utcnow()

    # Γράψε τις αλλαγές του DI στο transaction state πριν το billing
    db.session.flush()

    if status == "succeeded" and prev_status != "succeeded":
        try:
            row = db.session.execute(
                sqltext("SELECT COALESCE(pricing_rate_cents,0), COALESCE(outstanding_cents,0) FROM tenant WHERE id=:id"),
                {"id": g.tenant_id},
            ).first()
            if row:
                rate = int(row[0] or 0)
                if rate > 0:
                    db.session.execute(
                        sqltext("UPDATE tenant SET outstanding_cents = COALESCE(outstanding_cents,0) + :r WHERE id=:id"),
                        {"r": rate, "id": g.tenant_id},
                    )
                    current_app.logger.info("billing.charge ok tenant_id=%s +%s cents", g.tenant_id, rate)
                else:
                    current_app.logger.info("billing.charge skipped tenant_id=%s rate=0", g.tenant_id)
            else:
                current_app.logger.warning("billing.charge skipped: tenant %s not found", g.tenant_id)
        except Exception:
            current_app.logger.exception("billing.charge failed tenant_id=%s", g.tenant_id)

    db.session.commit()
    return jsonify({"ok": True})

