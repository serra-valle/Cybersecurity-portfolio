import json
import unittest

from aegis_soar.normalizer import InvalidAlert, normalize_alert


class AlertNormalizationTests(unittest.TestCase):
    def setUp(self):
        self.alert = {
            "id": "wazuh-event-001",
            "timestamp": "2026-11-12T08:00:00.000+0000",
            "agent": {"name": "kali-aegis-lab"},
            "rule": {"id": "100501"},
            "full_log": json.dumps({
                "time": "2026-11-12T08:00:00.000Z",
                "rule": "Aegis Test Pod Write Below Etc",
                "output_fields": {
                    "k8s.ns.name": "aegis-policy-test",
                    "k8s.pod.name": "falco-runtime-test-active",
                },
            }),
        }

    def test_normalizes_expected_fields(self):
        event = normalize_alert(self.alert)
        self.assertEqual(event.rule_id, "100501")
        self.assertEqual(event.agent_name, "kali-aegis-lab")
        self.assertEqual(event.namespace, "aegis-policy-test")
        self.assertEqual(event.pod_name, "falco-runtime-test-active")
        self.assertEqual(event.event_id, "wazuh-event-001")

    def test_missing_pod_identity_is_rejected(self):
        broken = dict(self.alert)
        broken["full_log"] = json.dumps({
            "output_fields": {"k8s.ns.name": "aegis-policy-test"}
        })
        with self.assertRaises(InvalidAlert):
            normalize_alert(broken)

    def test_non_json_full_log_is_rejected(self):
        broken = dict(self.alert)
        broken["full_log"] = "not-json"
        with self.assertRaises(InvalidAlert):
            normalize_alert(broken)


if __name__ == "__main__":
    unittest.main()
