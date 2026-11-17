import json
import stat
import tempfile
import unittest
from pathlib import Path

from collectors.gatekeeper_audit_exporter import (
    CONSTRAINTS,
    collect_once,
    load_state,
    records_from_constraint,
    save_state,
)


def container_constraint(violations=None, total_violations=None, audit_timestamp="2026-11-17T10:00:00Z"):
    if violations is None:
        violations = [{
            "kind": "Pod",
            "name": "bad-pod",
            "namespace": "aegis-unified-policy",
            "message": "container app must set readOnlyRootFilesystem=true",
        }]
    status = {
        "totalViolations": len(violations) if total_violations is None else total_violations,
        "violations": violations,
    }
    if audit_timestamp is not None:
        status["auditTimestamp"] = audit_timestamp
    return {
        "metadata": {"name": "aegis-unified-container-security"},
        "status": status,
    }


def image_constraint():
    return {
        "metadata": {"name": "aegis-unified-image-integrity"},
        "status": {
            "auditTimestamp": "2026-11-17T10:00:00Z",
            "totalViolations": 1,
            "violations": [{
                "resource": {
                    "kind": "Pod",
                    "name": "unpinned-pod",
                    "namespace": "aegis-unified-policy",
                },
                "message": "container app must use an explicit sha256 digest",
            }],
        },
    }


class FakeApi:
    def __init__(self, responses):
        self.responses = responses

    def list_cluster_custom_object(self, group, version, plural):
        response = self.responses[plural]
        if isinstance(response, Exception):
            raise response
        return response


def api_with(container_items=None, image_items=None, container_error=None, image_error=None):
    return FakeApi({
        CONSTRAINTS["K8sAegisContainerSecurity"]: (
            container_error if container_error is not None
            else {"items": container_items if container_items is not None else []}
        ),
        CONSTRAINTS["K8sAegisImageIntegrity"]: (
            image_error if image_error is not None
            else {"items": image_items if image_items is not None else []}
        ),
    })


class GatekeeperAuditNormalizationTests(unittest.TestCase):
    def test_container_security_violation_is_normalized(self):
        records = records_from_constraint(
            "K8sAegisContainerSecurity",
            container_constraint(),
        )
        self.assertEqual(len(records), 1)
        record = next(iter(records.values()))
        self.assertEqual(record["aegis_gatekeeper_kind"], "K8sAegisContainerSecurity")
        self.assertEqual(record["aegis_violation_name"], "bad-pod")
        self.assertEqual(record["aegis_violation_namespace"], "aegis-unified-policy")
        self.assertEqual(record["aegis_violation_status"], "active")

    def test_image_integrity_violation_is_normalized(self):
        records = records_from_constraint(
            "K8sAegisImageIntegrity",
            image_constraint(),
        )
        record = next(iter(records.values()))
        self.assertEqual(record["aegis_gatekeeper_kind"], "K8sAegisImageIntegrity")
        self.assertEqual(record["aegis_violation_name"], "unpinned-pod")

    def test_incomplete_violation_is_ignored_by_normalizer(self):
        records = records_from_constraint(
            "K8sAegisContainerSecurity",
            {
                "metadata": {"name": "constraint"},
                "status": {"violations": [{"message": "missing identity"}]},
            },
        )
        self.assertEqual(records, {})


class GatekeeperAuditCheckpointTests(unittest.TestCase):
    def test_active_violation_is_not_replayed_after_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "gatekeeper-audit.jsonl"
            checkpoint = Path(directory) / "state" / "active.json"
            first_state = collect_once(
                api_with(container_items=[container_constraint()]),
                output,
                {},
            )
            save_state(checkpoint, first_state)

            restarted_state = load_state(checkpoint)
            second_state = collect_once(
                api_with(container_items=[container_constraint()]),
                output,
                restarted_state,
            )

            records = [
                json.loads(line)
                for line in output.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["aegis_violation_status"], "active")
            self.assertEqual(second_state, first_state)

    def test_disappearing_violation_emits_resolution_and_reappearance_is_new(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "gatekeeper-audit.jsonl"
            checkpoint = Path(directory) / "state" / "active.json"

            active = collect_once(
                api_with(container_items=[container_constraint()]),
                output,
                {},
            )
            save_state(checkpoint, active)

            resolved = collect_once(
                api_with(container_items=[container_constraint(violations=[])]),
                output,
                load_state(checkpoint),
            )
            save_state(checkpoint, resolved)

            reappeared = collect_once(
                api_with(container_items=[container_constraint()]),
                output,
                load_state(checkpoint),
            )

            records = [
                json.loads(line)
                for line in output.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(
                [record["aegis_violation_status"] for record in records],
                ["active", "resolved", "active"],
            )
            self.assertEqual(records[0]["aegis_event_id"], records[2]["aegis_event_id"])
            self.assertNotEqual(records[0]["aegis_event_id"], records[1]["aegis_event_id"])
            self.assertEqual(len(reappeared), 1)

    def test_truncated_snapshot_never_resolves_omitted_violation(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "gatekeeper-audit.jsonl"
            previous = collect_once(
                api_with(container_items=[container_constraint()]),
                output,
                {},
            )
            second_violation = {
                "kind": "Pod",
                "name": "second-pod",
                "namespace": "aegis-unified-policy",
                "message": "container app must set readOnlyRootFilesystem=true",
            }
            truncated = container_constraint(
                violations=[second_violation],
                total_violations=2,
                audit_timestamp="2026-11-17T10:01:00Z",
            )
            current = collect_once(
                api_with(container_items=[truncated]),
                output,
                previous,
            )
            self.assertEqual(len(current), 2)
            statuses = [
                json.loads(line)["aegis_violation_status"]
                for line in output.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(statuses, ["active", "active"])

    def test_incomplete_violation_does_not_resolve_previous_state(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "gatekeeper-audit.jsonl"
            previous = collect_once(
                api_with(container_items=[container_constraint()]),
                output,
                {},
            )
            incomplete = container_constraint(
                violations=[{"message": "resource identity missing"}],
                total_violations=1,
                audit_timestamp="2026-11-17T10:01:00Z",
            )
            current = collect_once(
                api_with(container_items=[incomplete]),
                output,
                previous,
            )
            self.assertEqual(current, previous)
            self.assertEqual(len(output.read_text(encoding="utf-8").splitlines()), 1)

    def test_audit_without_timestamp_does_not_resolve_previous_state(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "gatekeeper-audit.jsonl"
            previous = collect_once(
                api_with(container_items=[container_constraint()]),
                output,
                {},
            )
            not_audited = container_constraint(
                violations=[],
                total_violations=0,
                audit_timestamp=None,
            )
            current = collect_once(
                api_with(container_items=[not_audited]),
                output,
                previous,
            )
            self.assertEqual(current, previous)
            self.assertEqual(len(output.read_text(encoding="utf-8").splitlines()), 1)

    def test_api_failure_does_not_mark_previous_violations_resolved(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "gatekeeper-audit.jsonl"
            previous = collect_once(
                api_with(container_items=[container_constraint()]),
                output,
                {},
            )
            current = collect_once(
                api_with(container_error=RuntimeError("temporary API failure")),
                output,
                previous,
            )
            self.assertEqual(current, previous)
            self.assertEqual(len(output.read_text(encoding="utf-8").splitlines()), 1)

    def test_malformed_api_response_does_not_mark_violations_resolved(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "gatekeeper-audit.jsonl"
            previous = collect_once(
                api_with(container_items=[container_constraint()]),
                output,
                {},
            )
            malformed = FakeApi({
                CONSTRAINTS["K8sAegisContainerSecurity"]: {},
                CONSTRAINTS["K8sAegisImageIntegrity"]: {"items": []},
            })
            current = collect_once(malformed, output, previous)
            self.assertEqual(current, previous)
            self.assertEqual(len(output.read_text(encoding="utf-8").splitlines()), 1)

    def test_checkpoint_is_private_and_reloadable(self):
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory) / "state" / "active.json"
            active = collect_once(
                api_with(container_items=[container_constraint()]),
                Path(directory) / "events.jsonl",
                {},
            )
            save_state(checkpoint, active)
            self.assertEqual(stat.S_IMODE(checkpoint.stat().st_mode), 0o600)
            self.assertEqual(load_state(checkpoint), active)

    def test_corrupt_checkpoint_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory) / "state.json"
            checkpoint.write_text("{not-json", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_state(checkpoint)


if __name__ == "__main__":
    unittest.main()
