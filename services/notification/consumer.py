"""Notification worker.

Consumes `scan-results` from Kafka and emails the user a link to their report.
Runs as an independent, horizontally-scalable process:

    python services/notification/consumer.py
"""

from __future__ import annotations

import os
import sys
import logging

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from flask_mail import Message

from libs.kafka_client import kafka_gateway, SCAN_RESULTS
from project import create_app, mail

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("guardian.notifications")


def handle(message: dict) -> None:
    app = create_app()
    with app.app_context():
        email = message.get("email")
        scan_id = message.get("scan_id")
        target = message.get("target")
        status = message.get("status")
        if not email or not scan_id:
            return
        try:
            msg = Message(
                subject="Your GuardianSecure scan is complete",
                recipients=[email],
            )
            msg.body = (
                f"Your scan of {target} finished with status: {status}.\n"
                f"View the full report: {os.environ.get('APP_PUBLIC_URL', 'http://localhost:5500')}/api/scans/{scan_id}/report\n"
            )
            mail.send(msg)
            logger.info("Notified %s for scan %s", email, scan_id)
        except Exception as e:
            logger.exception("Failed to notify %s: %s", email, e)


def main() -> None:
    logger.info("Notification worker listening on '%s'", SCAN_RESULTS)
    kafka_gateway.consume(SCAN_RESULTS, "guardian-notifications", handle)


if __name__ == "__main__":
    main()
