"""Scan Workflow definition.

The workflow is intentionally thin: it orchestrates the durable activity that
performs the actual crawling + analysis. Temporal provides retries, heartbeats,
timeouts and a full audit trail of every scan.
"""

from __future__ import annotations

import logging
from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

logger = logging.getLogger("guardian.temporal.workflow")

with workflow.unsafe.imports_passed_through():
    from temporal.activities.scan_activity import run_scan_activity


@workflow.defn(name="ScanWorkflow")
class ScanWorkflow:
    @workflow.run
    async def run(self, scan_id: str, user_id: int, target: str, scan_type: str) -> dict:
        result = await workflow.execute_activity(
            run_scan_activity,
            args=[scan_id, user_id, target, scan_type],
            start_to_close_timeout=timedelta(minutes=25),
            retry_policy=RetryPolicy(
                maximum_attempts=3,
                initial_interval=timedelta(seconds=10),
                maximum_interval=timedelta(minutes=2),
            ),
        )
        return result
