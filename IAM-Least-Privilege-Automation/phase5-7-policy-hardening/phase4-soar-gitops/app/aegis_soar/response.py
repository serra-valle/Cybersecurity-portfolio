from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from kubernetes.client.exceptions import ApiException

from .config import Settings
from .normalizer import NormalizedAlert


class ResponseBlocked(RuntimeError):
    """Raised when a required containment safety condition is not met."""


def _policy_is_default_deny(policy: Any, settings: Settings) -> bool:
    spec = getattr(policy, "spec", None)
    if spec is None:
        return False

    selector = getattr(spec, "pod_selector", None)
    labels = getattr(selector, "match_labels", None) or {}
    policy_types = set(getattr(spec, "policy_types", None) or [])

    ingress = getattr(spec, "ingress", None) or []
    egress = getattr(spec, "egress", None) or []

    return (
        labels.get(settings.quarantine_label_key)
        == settings.quarantine_label_value
        and {"Ingress", "Egress"}.issubset(policy_types)
        and len(ingress) == 0
        and len(egress) == 0
    )


def quarantine_pod(
    core_api: Any,
    networking_api: Any,
    event: NormalizedAlert,
    settings: Settings,
) -> dict[str, str]:
    if event.namespace not in settings.allowed_namespaces:
        return {"status": "ignored", "reason": "namespace_not_allowlisted"}

    if not settings.network_policy_enforcement_confirmed:
        raise ResponseBlocked(
            "NetworkPolicy dataplane enforcement has not been attested"
        )

    try:
        policy = networking_api.read_namespaced_network_policy(
            name=settings.quarantine_policy_name,
            namespace=event.namespace,
        )
    except ApiException as exc:
        if exc.status == 404:
            raise ResponseBlocked(
                "Required quarantine NetworkPolicy is absent"
            ) from exc
        raise

    if not _policy_is_default_deny(policy, settings):
        raise ResponseBlocked(
            "Quarantine NetworkPolicy does not match the required deny-all selector"
        )

    try:
        pod = core_api.read_namespaced_pod(
            name=event.pod_name,
            namespace=event.namespace,
        )
    except ApiException as exc:
        if exc.status == 404:
            return {"status": "not_found", "reason": "pod_no_longer_exists"}
        raise

    metadata = pod.metadata
    labels = dict(metadata.labels or {})
    annotations = dict(metadata.annotations or {})

    if labels.get(settings.target_label_key) != settings.target_label_value:
        return {"status": "ignored", "reason": "pod_not_an_approved_response_target"}

    if labels.get(settings.quarantine_label_key) == settings.quarantine_label_value:
        return {"status": "already_quarantined", "reason": "idempotent_noop"}

    quarantined_at = datetime.now(timezone.utc).isoformat()
    annotations.update({
        "aegis.security/quarantine-event-id": event.event_id[:128],
        "aegis.security/quarantine-rule-id": event.rule_id,
        "aegis.security/quarantined-at": quarantined_at,
        "aegis.security/quarantine-source-agent": "kali-aegis-lab",
    })
    labels[settings.quarantine_label_key] = settings.quarantine_label_value

    patch = {
        "metadata": {
            "resourceVersion": metadata.resource_version,
            "labels": labels,
            "annotations": annotations,
        }
    }
    core_api.patch_namespaced_pod(
        name=event.pod_name,
        namespace=event.namespace,
        body=patch,
        _content_type="application/merge-patch+json",
    )

    owner_references = metadata.owner_references or []
    if settings.delete_unmanaged_pods and not owner_references:
        core_api.delete_namespaced_pod(
            name=event.pod_name,
            namespace=event.namespace,
            grace_period_seconds=30,
            propagation_policy="Background",
        )
        return {"status": "quarantined_and_deleted", "reason": "unmanaged_pod"}

    if owner_references:
        return {
            "status": "quarantined",
            "reason": "controller_managed_pod_preserved",
        }

    return {"status": "quarantined", "reason": "network_policy_selected"}
