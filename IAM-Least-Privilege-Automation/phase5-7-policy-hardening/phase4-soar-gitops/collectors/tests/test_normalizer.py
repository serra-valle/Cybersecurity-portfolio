import unittest

from collectors.gatekeeper_audit_exporter import records_from_constraint


class GatekeeperAuditNormalizationTests(unittest.TestCase):
    def test_container_security_violation_is_normalized(self):
        constraint = {
            "metadata": {"name": "aegis-unified-container-security"},
            "status": {
                "violations": [{
                    "kind": "Pod",
                    "name": "bad-pod",
                    "namespace": "aegis-unified-policy",
                    "message": "container app must set readOnlyRootFilesystem=true",
                }]
            },
        }
        records = records_from_constraint("K8sAegisContainerSecurity", constraint)
        self.assertEqual(len(records), 1)
        record = next(iter(records.values()))
        self.assertEqual(record["aegis_gatekeeper_kind"], "K8sAegisContainerSecurity")
        self.assertEqual(record["aegis_violation_name"], "bad-pod")
        self.assertEqual(record["aegis_violation_namespace"], "aegis-unified-policy")
        self.assertEqual(record["aegis_violation_status"], "active")

    def test_image_integrity_violation_is_normalized(self):
        constraint = {
            "metadata": {"name": "aegis-unified-image-integrity"},
            "status": {
                "violations": [{
                    "resource": {
                        "kind": "Pod",
                        "name": "unpinned-pod",
                        "namespace": "aegis-unified-policy",
                    },
                    "message": "container app must use an explicit sha256 digest",
                }]
            },
        }
        records = records_from_constraint("K8sAegisImageIntegrity", constraint)
        record = next(iter(records.values()))
        self.assertEqual(record["aegis_gatekeeper_kind"], "K8sAegisImageIntegrity")
        self.assertEqual(record["aegis_violation_name"], "unpinned-pod")

    def test_incomplete_violation_is_ignored(self):
        records = records_from_constraint(
            "K8sAegisContainerSecurity",
            {"metadata": {"name": "constraint"}, "status": {"violations": [{"message": "missing identity"}]}},
        )
        self.assertEqual(records, {})


if __name__ == "__main__":
    unittest.main()
