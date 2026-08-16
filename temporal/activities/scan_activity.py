"""Temporal activity: runs the scan engine inside a real Flask app context.

Reuses project.scan_service.run_scan so the execution path is identical to the
local fallback. The activity heartbeats progress so the workflow can detect
stalls; failures are retried by the workflow's retry policy.
"""

from __future__ import annotations

import logging
from temporalio import activity

from project import create_app
from project.scan_service import run_scan

logger = logging.getLogger("guardian.temporal.activity")


@activity.defn(name="run_scan_activity")
async def run_scan_activity(scan_id: str, user_id: int, target: str, scan_type: str) -> dict:
    app = create_app()
    activity.heartbeat("starting")
    run_scan(app, scan_id, user_id, target, scan_type)
    activity.heartbeat("done")

    with app.app_context():
        from project.models import Scan
        scan = Scan.query.get(scan_id)
        return scan.to_dict() if scan else {"scan_id": scan_id, "status": "unknown"}
