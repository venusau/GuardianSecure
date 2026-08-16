"""Temporal worker process.

Run with:  python temporal/worker.py
It registers the ScanWorkflow + activities on the configured task queue and
polls the Temporal server. Scale horizontally by running more workers.
"""

from __future__ import annotations

import os
import sys
import asyncio
import logging

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from temporalio.client import Client
from temporalio.worker import Worker

from temporal.workflows.scan_workflow import ScanWorkflow
from temporal.activities.scan_activity import run_scan_activity

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("guardian.worker")

TEMPORAL_ADDRESS = os.environ.get("TEMPORAL_ADDRESS", "localhost:7233")
TASK_QUEUE = os.environ.get("TEMPORAL_TASK_QUEUE", "guardian-scan-queue")


async def main():
    logger.info("Connecting to Temporal at %s", TEMPORAL_ADDRESS)
    client = await Client.connect(TEMPORAL_ADDRESS)
    worker = Worker(
        client,
        task_queue=TASK_QUEUE,
        workflows=[ScanWorkflow],
        activities=[run_scan_activity],
    )
    logger.info("Worker started on task queue '%s'", TASK_QUEUE)
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
