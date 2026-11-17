from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

LOG = logging.getLogger("aegis-gatekeeper-audit")
CONSTRAINTS = {
    "K8sAegisContainerSecurity": "k8saegiscontainersecurity",
    "K8sAegisImageIntegrity": "k8saegisimageintegrity",
}
API_GROUP = "constraints.gatekeeper.sh"
API_VERSION = "v1beta1"
STATE_SCHEMA_VERSION = 1
DEFAULT_STATE_FILE = "/var/lib/aegis-gatekeeper-exporter/state.json"


def _identity(kind: str, constraint_name: str, violation: dict[str, Any]) -> dict[str, str]:
    resource = violation.get("resource") if isinstance(violation.get("resource"), dict) else {}
    return {
        "constraint_kind": kind,
        "constraint_name": constraint_name,
        "resource_kind": str(violation.get("kind") or resource.get("kind") or ""),
        "resource_name": str(violation.get("name") or resource.get("name") or ""),
        "resource_namespace": str(
            violation.get("namespace") or resource.get("namespace") or ""
        ),
        "message": str(violation.get("message") or ""),
    }


def records_from_constraint(
    kind: str,
    constraint: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    metadata = constraint.get("metadata") or {}
    status = constraint.get("status") or {}
    constraint_name = str(metadata.get("name") or "unknown")
    violations = status.get("violations") or []
    records: dict[str, dict[str, Any]] = {}

    if not isinstance(violations, list):
        return records

    for violation in violations:
        if not isinstance(violation, dict):
            continue
        identity = _identity(kind, constraint_name, violation)
        if not identity["resource_name"] or not identity["message"]:
            continue
        canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"))
        event_id = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        records[event_id] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "aegis_event_id": event_id,
            "aegis_gatekeeper_kind": identity["constraint_kind"],
            "aegis_gatekeeper_name": identity["constraint_name"],
            "aegis_violation_kind": identity["resource_kind"],
            "aegis_violation_name": identity["resource_name"],
            "aegis_violation_namespace": identity["resource_namespace"],
            "aegis_violation_message": identity["message"],
            "aegis_violation_status": "active",
        }
    return records


def _audit_snapshot(
    kind: str,
    constraint: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], str | None]:
    """Return normalized violations and whether this audit snapshot is complete."""
    metadata = constraint.get("metadata")
    status = constraint.get("status")
    if not isinstance(metadata, dict) or not isinstance(status, dict):
        return {}, "status_unavailable"

    constraint_name = metadata.get("name")
    audit_timestamp = status.get("auditTimestamp")
    total_violations = status.get("totalViolations")
    if not isinstance(constraint_name, str) or not constraint_name:
        return {}, "constraint_identity_unavailable"
    if not isinstance(audit_timestamp, str) or not audit_timestamp.strip():
        return {}, "audit_not_completed"
    if (
        not isinstance(total_violations, int)
        or isinstance(total_violations, bool)
        or total_violations < 0
    ):
        return {}, "total_violations_unavailable"

    violations = status.get("violations", [])
    if violations is None:
        violations = []
    if not isinstance(violations, list):
        return {}, "violations_malformed"

    for violation in violations:
        if not isinstance(violation, dict):
            return {}, "violation_record_malformed"
        identity = _identity(kind, constraint_name, violation)
        if not identity["resource_name"] or not identity["message"]:
            return {}, "violation_record_incomplete"

    records = records_from_constraint(kind, constraint)
    if total_violations > len(violations):
        # Gatekeeper bounds status.violations. Missing entries are not evidence
        # that previously observed violations have been resolved.
        return records, "violations_truncated"
    if total_violations < len(violations):
        return {}, "total_violations_inconsistent"
    return records, None


def load_state(state_file: Path) -> dict[str, dict[str, Any]]:
    """Load the last committed active-violation set.

    A malformed checkpoint is an operator-visible failure. Silently resetting it
    would replay every currently active violation and could create alert noise.
    """
    try:
        payload = json.loads(state_file.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}

    if not isinstance(payload, dict):
        raise ValueError("checkpoint_root_must_be_an_object")
    if payload.get("schema_version") != STATE_SCHEMA_VERSION:
        raise ValueError("checkpoint_schema_version_unsupported")

    active = payload.get("active")
    if not isinstance(active, dict):
        raise ValueError("checkpoint_active_must_be_an_object")

    validated: dict[str, dict[str, Any]] = {}
    for event_id, record in active.items():
        if (
            not isinstance(event_id, str)
            or len(event_id) != 64
            or any(character not in "0123456789abcdef" for character in event_id)
            or not isinstance(record, dict)
            or record.get("aegis_event_id") != event_id
            or record.get("aegis_violation_status") != "active"
            or record.get("aegis_gatekeeper_kind") not in CONSTRAINTS
            or not isinstance(record.get("aegis_gatekeeper_name"), str)
        ):
            raise ValueError("checkpoint_contains_invalid_active_record")
        validated[event_id] = record
    return validated


def save_state(state_file: Path, active: dict[str, dict[str, Any]]) -> None:
    """Atomically persist active findings after their JSONL transitions are written."""
    state_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = {
        "schema_version": STATE_SCHEMA_VERSION,
        "active": active,
    }
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{state_file.name}.",
        suffix=".tmp",
        dir=state_file.parent,
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(temporary_name, state_file)
        directory_descriptor = os.open(
            state_file.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def _append_jsonl(output: Path, record: dict[str, Any]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    encoded = (
        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(output, flags, 0o640)
    try:
        remaining = memoryview(encoded)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("short_write_to_gatekeeper_jsonl")
            remaining = remaining[written:]
        # The checkpoint must never advance before the event record is durable.
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(output, 0o640)


def _resolution_record(event_id: str, old_record: dict[str, Any]) -> dict[str, Any]:
    resolved = dict(old_record)
    resolved["timestamp"] = datetime.now(timezone.utc).isoformat()
    resolved["aegis_violation_status"] = "resolved"
    resolved["aegis_event_id"] = hashlib.sha256(
        (event_id + "|resolved").encode("utf-8")
    ).hexdigest()
    return resolved


def collect_once(
    api: Any,
    output: Path,
    previous: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    current = dict(previous)

    for kind, plural in CONSTRAINTS.items():
        try:
            response = api.list_cluster_custom_object(
                group=API_GROUP,
                version=API_VERSION,
                plural=plural,
            )
        except ApiException as exc:
            LOG.error(
                "constraint_list_failed kind=%s status=%s",
                kind,
                exc.status,
            )
            continue
        except Exception as exc:
            LOG.error(
                "constraint_list_failed kind=%s error=%s",
                kind,
                type(exc).__name__,
            )
            continue

        items = response.get("items") if isinstance(response, dict) else None
        if not isinstance(items, list):
            LOG.error("constraint_list_invalid_response kind=%s", kind)
            continue
        if any(
            not isinstance(item, dict)
            or not isinstance(item.get("metadata"), dict)
            or not isinstance(item["metadata"].get("name"), str)
            or not item["metadata"]["name"]
            for item in items
        ):
            LOG.error("constraint_list_contains_invalid_identity kind=%s", kind)
            continue

        previous_for_kind = {
            key: value
            for key, value in previous.items()
            if value.get("aegis_gatekeeper_kind") == kind
        }
        seen_constraints: set[str] = set()

        for constraint in items:
            constraint_name = constraint["metadata"]["name"]
            seen_constraints.add(constraint_name)
            observed, incomplete_reason = _audit_snapshot(kind, constraint)
            previous_for_constraint = {
                key: value
                for key, value in previous_for_kind.items()
                if value.get("aegis_gatekeeper_name") == constraint_name
            }

            if incomplete_reason:
                LOG.warning(
                    "constraint_audit_incomplete kind=%s constraint=%s reason=%s",
                    kind,
                    constraint_name,
                    incomplete_reason,
                )
                # New visible findings can still be exported, but an incomplete
                # snapshot must never resolve an older finding.
                for event_id, record in observed.items():
                    if event_id not in previous_for_constraint:
                        _append_jsonl(output, record)
                        current[event_id] = record
                continue

            for event_id, record in observed.items():
                if event_id not in previous_for_constraint:
                    _append_jsonl(output, record)
                    current[event_id] = record

            for event_id, old_record in previous_for_constraint.items():
                if event_id not in observed:
                    _append_jsonl(output, _resolution_record(event_id, old_record))
                    current.pop(event_id, None)

        # A successful complete list that no longer contains a constraint means
        # that constraint was deleted. Resolve its previously active findings.
        for event_id, old_record in previous_for_kind.items():
            if old_record.get("aegis_gatekeeper_name") not in seen_constraints:
                _append_jsonl(output, _resolution_record(event_id, old_record))
                current.pop(event_id, None)

    return current


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Export persisted Aegis Gatekeeper constraint violations as JSONL"
    )
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--context", default=None)
    parser.add_argument("--output", default="/var/log/aegis/gatekeeper-audit.jsonl")
    parser.add_argument("--state-file", default=DEFAULT_STATE_FILE)
    parser.add_argument("--interval", type=int, default=30)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()

    if args.interval < 5:
        parser.error("--interval must be at least 5 seconds")

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    state_file = Path(args.state_file)
    try:
        previous = load_state(state_file)
    except (OSError, ValueError) as exc:
        LOG.critical(
            "checkpoint_load_failed error=%s; refusing to reset active-violation state",
            type(exc).__name__,
        )
        return 1

    config.load_kube_config(config_file=args.kubeconfig, context=args.context)
    api = client.CustomObjectsApi()
    output = Path(args.output)

    while True:
        current = collect_once(api, output, previous)
        if current != previous:
            save_state(state_file, current)
            LOG.info("checkpoint_saved active_violations=%d", len(current))
        previous = current

        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
