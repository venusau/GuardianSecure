"""Temporal client entrypoint.

When USE_TEMPORAL=true the API gateway calls `start_scan_workflow`, which starts
a durable ScanWorkflow. The workflow guarantees the scan runs to completion
(retries, timeouts, visibility) even if the gateway restarts. The activity
simply reuses the same run_scan engine used by the local fallback path.
"""

from __future__ import annotations

import os
import logging
from datetime import timedelta

from temporalio.client import Client
from temporalio.common import WorkflowIDReusePolicy

from temporal.workflows.scan_workflow import ScanWorkflow

logger = logging.getLogger("guardian.temporal")

TEMPORAL_ADDRESS = os.environ.get("TEMPORAL_ADDRESS", "localhost:7233")
TASK_QUEUE = os.environ.get("TEMPORAL_TASK_QUEUE", "guardian-scan-queue")


async def start_scan_workflow(scan_id: str, user_id: int, target: str, scan_type: str) -> None:
    client = await Client.connect(TEMPORAL_ADDRESS)
    await client.start_workflow(
        ScanWorkflow.run,
        args=[scan_id, user_id, target, scan_type],
        id=f"scan-{scan_id}",
        task_queue=TASK_QUEUE,
        id_reuse_policy=WorkflowIDReusePolicy.REJECT_DUPLICATE,
        execution_timeout=timedelta(minutes=30),
    )
    logger.info("Started Temporal workflow for scan %s", scan_id)
