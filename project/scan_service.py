"""Scan orchestration service.

Coordinates a scan lifecycle:
  submit -> Scan row (queued) -> Redis status -> Kafka scan-requests
         -> run scanner (locally in a worker thread, or via Temporal when enabled)
         -> persist result -> Kafka scan-results (notification pipeline)

This module is importable by both the API gateway and the Temporal activity,
so the *same* scanning engine runs regardless of execution path.
"""

from __future__ import annotations

import os
import sys
import uuid
import logging
import threading
from datetime import datetime, timezone

# make top-level packages (scanner/, libs/) importable regardless of cwd
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from . import db
from .models import Scan, User
from scanner import Scanner

logger = logging.getLogger("guardian.scan")

USE_TEMPORAL = os.environ.get("USE_TEMPORAL", "false").lower() == "true"


def _now():
    return datetime.now(timezone.utc)


def submit_scan(app, user_id: int, target: str, scan_type: str) -> str:
    with app.app_context():
        scan = Scan(
            id=str(uuid.uuid4()),
            user_id=user_id,
            target=target,
            scan_type=scan_type,
            status="queued",
        )
        db.session.add(scan)
        db.session.commit()
        scan_id = scan.id

    # cache initial status for fast polling
    from libs.redis_client import redis_client
    redis_client.set_scan_status(scan_id, {
        "scan_id": scan_id, "target": target, "scan_type": scan_type,
        "status": "queued", "result": None,
    })

    # notify the pipeline
    from libs.kafka_client import kafka_gateway, SCAN_REQUESTS
    kafka_gateway.publish(SCAN_REQUESTS, {
        "scan_id": scan_id, "user_id": user_id,
        "target": target, "scan_type": scan_type,
    })

    if USE_TEMPORAL:
        import asyncio

        from temporal.client import start_scan_workflow

        try:
            # start_scan_workflow is a coroutine; it must be awaited.
            asyncio.run(start_scan_workflow(scan_id, user_id, target, scan_type))
        except Exception:
            logger.exception("Temporal workflow start failed; falling back to local run")
            t = threading.Thread(
                target=run_scan, args=(app, scan_id, user_id, target, scan_type),
                daemon=True,
            )
            t.start()
    else:
        t = threading.Thread(
            target=run_scan, args=(app, scan_id, user_id, target, scan_type),
            daemon=True,
        )
        t.start()

    return scan_id


def run_scan(app, scan_id: str, user_id: int, target: str, scan_type: str) -> None:
    from libs.redis_client import redis_client
    from libs.kafka_client import kafka_gateway, SCAN_RESULTS

    with app.app_context():
        scan = db.session.get(Scan, scan_id)
        if scan is None:
            return
        scan.status = "running"
        db.session.commit()
        redis_client.set_scan_status(scan_id, {
            "scan_id": scan_id, "target": target, "scan_type": scan_type,
            "status": "running", "result": None,
        })

        try:
            result = Scanner().run(target, scan_type)
            scan.result_json = result.to_dict()
            scan.status = "completed"
            scan.finished_at = _now()
            db.session.commit()

            user = db.session.get(User, user_id)
            email = user.email if user else None
        except Exception as e:  # capture failure, don't lose the Scan row
            logger.exception("Scan %s failed", scan_id)
            scan.status = "failed"
            scan.result_json = {"error": str(e)}
            scan.finished_at = _now()
            db.session.commit()
            email = None

        redis_client.set_scan_status(scan_id, {
            "scan_id": scan_id, "target": target, "scan_type": scan_type,
            "status": scan.status, "result": scan.result_json,
        })

        kafka_gateway.publish(SCAN_RESULTS, {
            "scan_id": scan_id, "user_id": user_id, "email": email,
            "target": target, "status": scan.status,
        })
