#!/usr/bin/env python3
"""Sign and deliver queued Wazuh alerts; retain transient failures for retry."""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import shutil
import time
import urllib.error
import urllib.request
from pathlib import Path

SPOOL_ROOT = Path(os.getenv("AEGIS_SOAR_SPOOL_ROOT", "/var/ossec/queue/aegis-soar"))
PENDING = SPOOL_ROOT / "pending"
DEAD_LETTER = SPOOL_ROOT / "dead-letter"
LOCK_FILE = SPOOL_ROOT / "dispatcher.lock"
SECRET_FILE = Path(os.getenv(
    "AEGIS_SOAR_HMAC_SECRET_FILE",
    "/etc/aegis-soar/hmac.key",
))
WEBHOOK_URL = os.getenv(
    "AEGIS_SOAR_WEBHOOK_URL",
    "http://127.0.0.1:18080/v1/alerts",
)
TIMEOUT_SECONDS = 8


def _sign(body: bytes, timestamp: str, secret: bytes) -> str:
    message = timestamp.encode("ascii") + b"." + body
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def _deliver(path: Path, secret: bytes) -> bool:
    body = path.read_bytes()
    timestamp = str(int(time.time()))
    request = urllib.request.Request(
        WEBHOOK_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Aegis-Timestamp": timestamp,
            "X-Aegis-Signature": _sign(body, timestamp, secret),
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            if response.status in (200, 202):
                path.unlink(missing_ok=True)
                print(
                    f"aegis_dispatch delivered event_file={path.name} status={response.status}"
                )
                return True
            print(
                f"aegis_dispatch retained event_file={path.name} status={response.status}"
            )
            return False
    except urllib.error.HTTPError as exc:
        if exc.code in (400, 413, 422):
            DEAD_LETTER.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.move(str(path), str(DEAD_LETTER / path.name))
            print(
                f"aegis_dispatch dead_letter event_file={path.name} status={exc.code}"
            )
            return True
        print(
            f"aegis_dispatch retained event_file={path.name} status={exc.code}"
        )
        return False
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print(
            f"aegis_dispatch delivery_unavailable event_file={path.name} error={type(exc).__name__}"
        )
        return False


def main() -> int:
    PENDING.mkdir(mode=0o700, parents=True, exist_ok=True)
    SPOOL_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock_descriptor = os.open(LOCK_FILE, os.O_CREAT | os.O_RDWR, 0o600)

    try:
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(lock_descriptor)
        return 0

    try:
        secret = SECRET_FILE.read_bytes().strip()
        if len(secret) < 32:
            print("aegis_dispatch secret_missing_or_too_short")
            return 1

        for path in sorted(PENDING.glob("*.json")):
            if not _deliver(path, secret):
                # Preserve ordering and avoid hammering an unavailable endpoint.
                return 1
        return 0
    except OSError as exc:
        print(f"aegis_dispatch startup_error error={type(exc).__name__}")
        return 1
    finally:
        os.close(lock_descriptor)


if __name__ == "__main__":
    raise SystemExit(main())
