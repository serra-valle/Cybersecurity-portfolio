from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _csv_set(value: str, default: str) -> frozenset[str]:
    source = value if value.strip() else default
    return frozenset(part.strip() for part in source.split(",") if part.strip())


def _bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes"}:
        return True
    if normalized in {"0", "false", "no"}:
        return False
    raise ValueError("Boolean environment values must be true or false")


@dataclass(frozen=True)
class Settings:
    secret_file: Path
    allowed_agent: str
    allowed_rule_ids: frozenset[str]
    allowed_namespaces: frozenset[str]
    target_label_key: str
    target_label_value: str
    quarantine_label_key: str
    quarantine_label_value: str
    quarantine_policy_name: str
    network_policy_enforcement_confirmed: bool
    delete_unmanaged_pods: bool
    max_clock_skew_seconds: int

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            secret_file=Path(os.getenv(
                "AEGIS_HMAC_SECRET_FILE",
                "/var/run/secrets/aegis-soar/key",
            )),
            allowed_agent=os.getenv("AEGIS_ALLOWED_AGENT", "kali-aegis-lab"),
            allowed_rule_ids=_csv_set(
                os.getenv("AEGIS_ALLOWED_RULE_IDS", ""),
                "100501,100502",
            ),
            allowed_namespaces=_csv_set(
                os.getenv("AEGIS_ALLOWED_NAMESPACES", ""),
                "aegis-policy-test,aegis-unified-policy",
            ),
            target_label_key=os.getenv(
                "AEGIS_TARGET_LABEL_KEY",
                "aegis.security/response-target",
            ),
            target_label_value=os.getenv("AEGIS_TARGET_LABEL_VALUE", "true"),
            quarantine_label_key=os.getenv(
                "AEGIS_QUARANTINE_LABEL_KEY",
                "aegis.security/status",
            ),
            quarantine_label_value=os.getenv(
                "AEGIS_QUARANTINE_LABEL_VALUE",
                "quarantined",
            ),
            quarantine_policy_name=os.getenv(
                "AEGIS_QUARANTINE_POLICY_NAME",
                "aegis-quarantine-default-deny",
            ),
            network_policy_enforcement_confirmed=_bool(
                os.getenv("AEGIS_NETWORK_POLICY_ENFORCEMENT_CONFIRMED"),
                default=False,
            ),
            delete_unmanaged_pods=_bool(
                os.getenv("AEGIS_DELETE_UNMANAGED_PODS"),
                default=False,
            ),
            max_clock_skew_seconds=int(
                os.getenv("AEGIS_MAX_CLOCK_SKEW_SECONDS", "300")
            ),
        )
