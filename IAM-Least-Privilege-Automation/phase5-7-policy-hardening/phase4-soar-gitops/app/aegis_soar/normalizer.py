from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


class InvalidAlert(ValueError):
    """Raised when a Wazuh alert cannot be safely normalized."""


@dataclass(frozen=True)
class NormalizedAlert:
    event_id: str
    rule_id: str
    agent_name: str
    namespace: str
    pod_name: str
    falco_rule: str
    event_time: str


def _nested_or_dotted(source: dict[str, Any], dotted_key: str) -> Any:
    if dotted_key in source:
        return source[dotted_key]

    value: Any = source
    for component in dotted_key.split("."):
        if not isinstance(value, dict) or component not in value:
            return None
        value = value[component]
    return value


def _falco_record(alert: dict[str, Any]) -> dict[str, Any]:
    full_log = alert.get("full_log")
    if isinstance(full_log, str) and full_log.strip():
        try:
            record = json.loads(full_log)
        except json.JSONDecodeError as exc:
            raise InvalidAlert("Wazuh full_log is not valid Falco JSON") from exc
        if isinstance(record, dict):
            return record

    data = alert.get("data")
    if isinstance(data, dict) and isinstance(data.get("output_fields"), dict):
        return data

    raise InvalidAlert("Wazuh alert does not contain a structured Falco record")


def normalize_alert(alert: dict[str, Any]) -> NormalizedAlert:
    if not isinstance(alert, dict):
        raise InvalidAlert("Wazuh alert must be a JSON object")

    rule = alert.get("rule")
    agent = alert.get("agent")
    if not isinstance(rule, dict) or not isinstance(agent, dict):
        raise InvalidAlert("Wazuh alert is missing rule or agent metadata")

    rule_id = str(rule.get("id", "")).strip()
    agent_name = str(agent.get("name", "")).strip()
    if not rule_id or not agent_name:
        raise InvalidAlert("Wazuh rule ID and agent name are required")

    record = _falco_record(alert)
    output_fields = record.get("output_fields")
    if not isinstance(output_fields, dict):
        raise InvalidAlert("Falco output_fields are required")

    namespace = _nested_or_dotted(output_fields, "k8s.ns.name")
    pod_name = _nested_or_dotted(output_fields, "k8s.pod.name")
    if not isinstance(namespace, str) or not namespace.strip():
        raise InvalidAlert("Falco namespace field is missing")
    if not isinstance(pod_name, str) or not pod_name.strip():
        raise InvalidAlert("Falco Pod name field is missing")

    raw_event_id = alert.get("id")
    if raw_event_id is None:
        raw_event_id = hashlib.sha256(
            json.dumps(alert, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    return NormalizedAlert(
        event_id=str(raw_event_id),
        rule_id=rule_id,
        agent_name=agent_name,
        namespace=namespace,
        pod_name=pod_name,
        falco_rule=str(record.get("rule", "")),
        event_time=str(record.get("time", alert.get("timestamp", ""))),
    )
