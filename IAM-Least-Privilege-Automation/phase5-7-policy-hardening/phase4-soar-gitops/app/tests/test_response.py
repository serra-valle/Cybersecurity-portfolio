import unittest
from pathlib import Path
from types import SimpleNamespace

from aegis_soar.config import Settings
from aegis_soar.normalizer import NormalizedAlert
from aegis_soar.response import ResponseBlocked, quarantine_pod


def make_settings(**overrides):
    values = {
        "secret_file": Path("/tmp/aegis-test-key"),
        "allowed_agent": "kali-aegis-lab",
        "allowed_rule_ids": frozenset({"100501", "100502"}),
        "evict_rule_ids": frozenset({"100502"}),
        "allowed_namespaces": frozenset({"aegis-unified-policy"}),
        "target_label_key": "aegis.security/response-target",
        "target_label_value": "true",
        "endpoint_label_key": "aegis.security/endpoint-enabled",
        "endpoint_enabled_value": "true",
        "endpoint_disabled_value": "false",
        "quarantine_label_key": "aegis.security/status",
        "quarantine_label_value": "quarantined",
        "quarantine_policy_name": "aegis-quarantine-default-deny",
        "network_policy_enforcement_confirmed": True,
        "delete_unmanaged_pods": True,
        "max_clock_skew_seconds": 300,
        "max_request_bytes": 1048576,
    }
    values.update(overrides)
    return Settings(**values)


def make_event(rule_id="100501"):
    return NormalizedAlert(
        event_id="event-test-001",
        rule_id=rule_id,
        agent_name="kali-aegis-lab",
        namespace="aegis-unified-policy",
        pod_name="aegis-response-target-test",
        falco_rule="Aegis test rule",
        event_time="2026-11-16T10:00:00Z",
    )


def make_policy():
    return SimpleNamespace(spec=SimpleNamespace(
        pod_selector=SimpleNamespace(match_labels={
            "aegis.security/status": "quarantined",
        }),
        policy_types=["Ingress", "Egress"],
        ingress=[],
        egress=[],
    ))


class FakeNetworkingAPI:
    def __init__(self, policy=None):
        self.policy = policy or make_policy()

    def read_namespaced_network_policy(self, name, namespace):
        return self.policy


class FakeCoreAPI:
    def __init__(self, labels=None, owner_references=None):
        self.pod = SimpleNamespace(metadata=SimpleNamespace(
            labels=labels or {
                "aegis.security/response-target": "true",
                "aegis.security/endpoint-enabled": "true",
            },
            annotations={},
            resource_version="7",
            owner_references=owner_references or [],
        ))
        self.patch = None
        self.deleted = None

    def read_namespaced_pod(self, name, namespace):
        return self.pod

    def patch_namespaced_pod(self, **kwargs):
        self.patch = kwargs
        return self.pod

    def delete_namespaced_pod(self, **kwargs):
        self.deleted = kwargs


class ResponseTests(unittest.TestCase):
    def test_quarantine_disables_service_endpoint_label(self):
        core = FakeCoreAPI()
        result = quarantine_pod(core, FakeNetworkingAPI(), make_event(), make_settings())
        self.assertEqual(result["status"], "quarantined")
        labels = core.patch["body"]["metadata"]["labels"]
        self.assertEqual(labels["aegis.security/status"], "quarantined")
        self.assertEqual(labels["aegis.security/endpoint-enabled"], "false")
        self.assertIsNone(core.deleted)

    def test_high_risk_unmanaged_pod_is_evicted_immediately(self):
        core = FakeCoreAPI()
        result = quarantine_pod(
            core, FakeNetworkingAPI(), make_event("100502"), make_settings()
        )
        self.assertEqual(result["status"], "evicted")
        self.assertEqual(core.deleted["grace_period_seconds"], 0)
        self.assertEqual(core.deleted["propagation_policy"], "Background")

    def test_duplicate_high_risk_event_retries_eviction(self):
        core = FakeCoreAPI(labels={
            "aegis.security/response-target": "true",
            "aegis.security/endpoint-enabled": "false",
            "aegis.security/status": "quarantined",
        })
        result = quarantine_pod(
            core, FakeNetworkingAPI(), make_event("100502"), make_settings()
        )
        self.assertEqual(result["status"], "evicted")
        self.assertEqual(core.deleted["grace_period_seconds"], 0)

    def test_controller_managed_pod_is_quarantined_not_evicted(self):
        owner = [SimpleNamespace(kind="ReplicaSet", name="app-rs")]
        core = FakeCoreAPI(owner_references=owner)
        result = quarantine_pod(
            core, FakeNetworkingAPI(), make_event("100502"), make_settings()
        )
        self.assertEqual(result["status"], "quarantined")
        self.assertEqual(result["reason"], "controller_managed_pod_preserved")
        self.assertIsNone(core.deleted)

    def test_missing_dataplane_attestation_fails_closed(self):
        with self.assertRaises(ResponseBlocked):
            quarantine_pod(
                FakeCoreAPI(),
                FakeNetworkingAPI(),
                make_event(),
                make_settings(network_policy_enforcement_confirmed=False),
            )

    def test_non_default_deny_policy_fails_closed(self):
        bad_policy = SimpleNamespace(spec=SimpleNamespace(
            pod_selector=SimpleNamespace(match_labels={
                "aegis.security/status": "quarantined",
            }),
            policy_types=["Ingress"],
            ingress=[{}],
            egress=[],
        ))
        with self.assertRaises(ResponseBlocked):
            quarantine_pod(
                FakeCoreAPI(),
                FakeNetworkingAPI(bad_policy),
                make_event(),
                make_settings(),
            )

    def test_unlabelled_pod_is_not_mutated(self):
        core = FakeCoreAPI(labels={"app": "unrelated"})
        result = quarantine_pod(core, FakeNetworkingAPI(), make_event(), make_settings())
        self.assertEqual(result["status"], "ignored")
        self.assertIsNone(core.patch)


if __name__ == "__main__":
    unittest.main()
