from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
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


def _append_jsonl(output: Path, record: dict[str, Any]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
    try:
        os.write(descriptor, encoded)
    finally:
        os.close(descriptor)
    os.chmod(output, 0o640)


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
            LOG.error("constraint_list_failed kind=%s error=%s", kind, type(exc).__name__)
            continue

        observed: dict[str, dict[str, Any]] = {}
        for constraint in response.get("items", []):
            observed.update(records_from_constraint(kind, constraint))

        previous_for_kind = {
            key: value
            for key, value in previous.items()
            if value.get("aegis_gatekeeper_kind") == kind
        }

        for event_id, record in observed.items():
            if event_id not in previous_for_kind:
                _append_jsonl(output, record)
                LOG.info(
                    "violation_observed kind=%s constraint=%s resource=%s/%s",
                    kind,
                    record["aegis_gatekeeper_name"],
                    record["aegis_violation_namespace"],
                    record["aegis_violation_name"],
                )

        for event_id, old_record in previous_for_kind.items():
            if event_id not in observed:
                resolved = dict(old_record)
                resolved["timestamp"] = datetime.now(timezone.utc).isoformat()
                resolved["aegis_violation_status"] = "resolved"
                resolved["aegis_event_id"] = hashlib.sha256(
                    (event_id + "|resolved").encode("utf-8")
                ).hexdigest()
                _append_jsonl(output, resolved)

        current = {
            key: value
            for key, value in current.items()
            if value.get("aegis_gatekeeper_kind") != kind
        }
        current.update(observed)

    return current


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Export persisted Aegis Gatekeeper constraint violations as JSONL"
    )
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--context", default=None)
    parser.add_argument("--output", default="/var/log/aegis/gatekeeper-audit.jsonl")
    parser.add_argument("--interval", type=int, default=30)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()

    if args.interval < 5:
        parser.error("--interval must be at least 5 seconds")

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    config.load_kube_config(config_file=args.kubeconfig, context=args.context)
    api = client.CustomObjectsApi()
    output = Path(args.output)
    previous: dict[str, dict[str, Any]] = {}

    while True:
        previous = collect_once(api, output, previous)
        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
