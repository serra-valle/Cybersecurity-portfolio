from __future__ import annotations

import hashlib
import hmac
import time


class SignatureError(ValueError):
    """Raised when a webhook signature is absent, stale or invalid."""


def sign_request(body: bytes, timestamp: str, secret: bytes) -> str:
    message = timestamp.encode("ascii") + b"." + body
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def verify_request(
    body: bytes,
    timestamp: str | None,
    signature: str | None,
    secret: bytes,
    max_clock_skew_seconds: int = 300,
    now: int | None = None,
) -> None:
    if not timestamp or not signature:
        raise SignatureError("Missing request signature headers")

    try:
        request_time = int(timestamp)
    except (TypeError, ValueError) as exc:
        raise SignatureError("Invalid request timestamp") from exc

    current_time = int(time.time()) if now is None else now
    if abs(current_time - request_time) > max_clock_skew_seconds:
        raise SignatureError("Request timestamp is outside the accepted window")

    expected = sign_request(body, timestamp, secret)
    if not hmac.compare_digest(expected, signature.lower()):
        raise SignatureError("Request signature verification failed")
