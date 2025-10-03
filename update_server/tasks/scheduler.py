# update_server/tasks/scheduler.py

from __future__ import annotations

import datetime as dt
from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask
from ..extensions import db
from ..models import Rollout, DeviceInstallation, Device

_scheduler: BackgroundScheduler | None = None


def run_tick(app: Flask) -> None:
    """
    Periodic job: promote due rollouts to 'running' and enqueue DeviceInstallation
    records (naively targets all devices in the rollout's tenant).
    """
    with app.app_context():
        now = dt.datetime.utcnow()

        # Find rollouts that should be running now
        rollouts = (
            Rollout.query
            .filter(
                Rollout.status.in_(["scheduled", "running"]),
                Rollout.start_at <= now,
            )
            .all()
        )

        if not rollouts:
            return

        try:
            # Mark newly due rollouts as running
            updated_any = False
            for r in rollouts:
                if r.status != "running":
                    r.status = "running"
                    updated_any = True
            if updated_any:
                db.session.flush()  # don't commit yet—batch with installations

            # For each rollout, enqueue pending installs for all devices in tenant
            for r in rollouts:
                targets = Device.query.filter_by(tenant_id=r.tenant_id).all()
                for d in targets:
                    exists = DeviceInstallation.query.filter_by(
                        device_id=d.id,
                        package_id=r.package_id,
                        version=r.version,
                    ).first()
                    if not exists:
                        di = DeviceInstallation(
                            device_id=d.id,
                            package_id=r.package_id,
                            version=r.version,
                            status="pending",
                        )
                        db.session.add(di)

            db.session.commit()

        except Exception:
            db.session.rollback()
            raise


def init_scheduler(app: Flask) -> BackgroundScheduler:
    """
    Initialize the background scheduler once per process.
    Hooks shutdown safely on app teardown and at process exit.
    """
    global _scheduler
    if _scheduler and getattr(_scheduler, "running", False):
        return _scheduler

    _scheduler = BackgroundScheduler(daemon=True)
    # coalesce=True avoids backlog bursts if the process was paused
    _scheduler.add_job(
        run_tick,
        trigger="interval",
        seconds=15,
        id="rollout_tick",
        coalesce=True,
        max_instances=1,
        args=[app],
        replace_existing=True,
    )
    _scheduler.start()

    @app.teardown_appcontext
    def _shutdown_scheduler(exc):
        # Avoid raising if already stopped or never started
        try:
            if _scheduler and getattr(_scheduler, "running", False):
                _scheduler.shutdown(wait=False)
        except Exception:
            pass

    # Also register atexit for non-WSGI/CLI runs
    import atexit

    def _atexit_shutdown():
        try:
            if _scheduler and getattr(_scheduler, "running", False):
                _scheduler.shutdown(wait=False)
        except Exception:
            pass

    atexit.register(_atexit_shutdown)
    return _scheduler
