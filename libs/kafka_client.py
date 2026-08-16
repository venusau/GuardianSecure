"""Kafka client: producers & consumers for the scan pipeline.

Topics:
  scan-requests  : API gateway -> (Temporal trigger or scanner workers)
  scan-results   : scanner workers -> notification service
  scan-events    : audit/log stream for observability

In production these are partitioned for parallelism; in dev a single broker
is sufficient. The client degrades gracefully (no-op) when Kafka is absent so
the app still runs locally.
"""
from __future__ import annotations

from __future__ import annotations

import os
import json
import logging
from typing import Callable

from kafka import KafkaProducer, KafkaConsumer
from kafka.errors import KafkaError

logger = logging.getLogger("guardian.kafka")

SCAN_REQUESTS = "scan-requests"
SCAN_RESULTS = "scan-results"
SCAN_EVENTS = "scan-events"


class KafkaGateway:
    def __init__(self, bootstrap_servers: str | None = None):
        self.bootstrap = bootstrap_servers or os.environ.get(
            "KAFKA_BOOTSTRAP", "localhost:9092"
        )
        self._producer = None

    @property
    def enabled(self) -> bool:
        return os.environ.get("KAFKA_ENABLED", "false").lower() == "true"

    def _ensure_producer(self):
        if self._producer is None:
            self._producer = KafkaProducer(
                bootstrap_servers=self.bootstrap,
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                retries=3,
                acks="all",
            )
        return self._producer

    def publish(self, topic: str, message: dict) -> bool:
        if not self.enabled:
            return False
        try:
            self._ensure_producer().send(topic, message).get(timeout=10)
            return True
        except KafkaError as e:
            logger.error("Kafka publish failed on %s: %s", topic, e)
            return False

    def consume(self, topic: str, group: str, handler: Callable[[dict], None]):
        consumer = KafkaConsumer(
            topic,
            group_id=group,
            bootstrap_servers=self.bootstrap,
            value_deserializer=lambda v: json.loads(v.decode("utf-8")),
            auto_offset_reset="earliest",
            enable_auto_commit=True,
        )
        logger.info("Consuming %s as %s", topic, group)
        for msg in consumer:
            try:
                handler(msg.value)
            except Exception as e:  # keep the consumer alive
                logger.exception("Handler error: %s", e)


kafka_gateway = KafkaGateway()
