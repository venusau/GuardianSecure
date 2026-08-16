"""Redis client: caching, session backing store, rate limiting and scan-status cache.

Used by the API gateway for:
  * per-IP / per-user rate limiting (token bucket-ish sliding window)
  * fast scan-status lookups while a scan is in flight (before it lands in Postgres)
"""

from __future__ import annotations

import os
import time
import json
import redis


class RedisClient:
    def __init__(self, url: str | None = None):
        self.url = url or os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        self._client = redis.Redis.from_url(
            self.url, decode_responses=True, socket_connect_timeout=3
        )

    @property
    def client(self) -> redis.Redis:
        return self._client

    def health(self) -> bool:
        try:
            return self._client.ping()
        except Exception:
            return False

    # ---- Rate limiting: fixed-window counter ----
    def rate_limit(self, key: str, limit: int, window: int = 60) -> tuple[bool, int]:
        """Return (allowed, remaining). Increments a counter for `key`.

        Degrades to "allow" when Redis is unavailable so the service still
        works in local/dev mode (no Redis running).
        """
        try:
            rk = f"ratelimit:{key}"
            pipe = self._client.pipeline()
            pipe.incr(rk)
            pipe.expire(rk, window)
            count, _ = pipe.execute()
            if count == 1:
                self._client.expire(rk, window)
            allowed = count <= limit
            return allowed, max(limit - count, 0)
        except Exception:
            return True, limit

    # ---- Scan status cache ----
    def set_scan_status(self, scan_id: str, payload: dict, ttl: int = 3600) -> None:
        try:
            self._client.set(f"scan:{scan_id}", json.dumps(payload, default=str), ex=ttl)
        except Exception:
            pass

    def get_scan_status(self, scan_id: str) -> dict | None:
        try:
            raw = self._client.get(f"scan:{scan_id}")
            return json.loads(raw) if raw else None
        except Exception:
            return None

    def cache_get(self, key: str):
        try:
            raw = self._client.get(key)
            return json.loads(raw) if raw else None
        except Exception:
            return None

    def cache_set(self, key: str, value, ttl: int = 300) -> None:
        try:
            self._client.set(key, json.dumps(value, default=str), ex=ttl)
        except Exception:
            pass

    def invalidate(self, key: str) -> None:
        try:
            self._client.delete(key)
        except Exception:
            pass


redis_client = RedisClient()
