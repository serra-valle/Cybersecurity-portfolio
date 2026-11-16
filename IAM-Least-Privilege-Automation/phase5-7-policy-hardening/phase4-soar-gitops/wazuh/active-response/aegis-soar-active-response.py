#!/usr/bin/env python3
"""Durably enqueue allowlisted Wazuh Active Response alerts for Aegis SOAR."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

MAX_INPUT_BYTES = 1_048_576
ALLOWED_AGENT = os.getenv("AEGIS_ALLOWED_AGENT", "kali-aegis-lab")
ALLOWED_RULE_IDS = {"100501", "100502"}
SPOOL = Path(os.getenv(
    "AEGIS_SOAR_SPOOL_DIR",
    "/var/ossec/queue/aegis-soar/pending",
))


def _write_durable(body: bytes, event_id: str) -> None:
    SPOOL.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(SPOOL, 0o700)
    digest = hashlib.sha256(event_id.encode("utf-8")).hexdigest()
    destination = SPOOL / f"{digest}.json"
    if destination.exists():
        return

    descriptor, temporary_name = tempfile.mkstemp(prefix=".aegis-", dir=SPOOL)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, destination)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def main() -> int:
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        print("aegis_active_response rejected oversized input", file=sys.stderr)
        return 1

    try:
        message: Any = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        print("aegis_active_response rejected invalid JSON", file=sys.stderr)
        return 1

    if not isinstance(message, dict) or message.get("command") != "add":
        return 0

    parameters = message.get("parameters")
    alert = parameters.get("alert") if isinstance(parameters, dict) else None
    if not isinstance(alert, dict):
        return 0

    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    rule_id = str(rule.get("id", ""))
    agent_name = str(agent.get("name", ""))

    if rule_id not in ALLOWED_RULE_IDS or agent_name != ALLOWED_AGENT:
        return 0

    body = json.dumps(alert, sort_keys=True, separators=(",", ":")).encode("utf-8")
    event_id = str(alert.get("id") or hashlib.sha256(body).hexdigest())

    try:
        _write_durable(body, event_id)
    except OSError as exc:
        print(
            f"aegis_active_response enqueue_failed error={type(exc).__name__}",
            file=sys.stderr,
        )
        return 1

    print(
        f"aegis_active_response enqueued rule_id={rule_id} event_id={hashlib.sha256(event_id.encode()).hexdigest()[:16]}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
