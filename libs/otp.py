"""OTP generation, storage and rate limiting.

Design notes (industry best-practice):
  * Codes are generated with `secrets` (cryptographically strong RNG).
  * Stored server-side in Redis with a short TTL (~10 min) and consumed
    (deleted) on first successful verification -> single-use.
  * Sending is rate-limited per identity to throttle abuse.
"""

from __future__ import annotations

import secrets

from libs.redis_client import redis_client

OTP_TTL = 600  # seconds


def generate_otp() -> str:
    """Return a 6-digit one-time code."""
    return str(secrets.randbelow(900000) + 100000)


def _key(identity: str, purpose: str) -> str:
    return f"otp:{purpose}:{identity.strip().lower()}"


def store_otp(identity: str, purpose: str, otp: str, ttl: int = OTP_TTL) -> None:
    try:
        redis_client.client.set(_key(identity, purpose), str(otp), ex=ttl)
    except Exception:
        pass


def verify_otp(identity: str, purpose: str, otp: str) -> bool:
    try:
        key = _key(identity, purpose)
        stored = redis_client.client.get(key)
        if not stored:
            return False
        ok = secrets.compare_digest(stored, str(otp))
        if ok:
            redis_client.client.delete(key)  # single-use
        return ok
    except Exception:
        return False


def rate_limit_otp(
    identity: str, purpose: str, limit: int = 5, window: int = 300
) -> tuple[bool, int]:
    return redis_client.rate_limit(
        f"otpsend:{purpose}:{identity.strip().lower()}", limit, window
    )
