from __future__ import annotations

import json
import logging
from contextlib import suppress
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from kubernetes import client, config
from kubernetes.config.config_exception import ConfigException

from .config import Settings
from .normalizer import InvalidAlert, normalize_alert
from .response import ResponseBlocked, quarantine_pod
from .security import SignatureError, verify_request

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
)
logger = logging.getLogger("aegis-soar")


def _audit_log(**fields: Any) -> None:
    logger.info(json.dumps(fields, sort_keys=True, separators=(",", ":")))


def create_app(
    settings: Settings | None = None,
    core_api: Any | None = None,
    networking_api: Any | None = None,
) -> FastAPI:
    active_settings = settings or Settings.from_env()
    app = FastAPI(
        title="Aegis SOAR",
        version="1.0.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.core_api = core_api
    app.state.networking_api = networking_api

    @app.on_event("startup")
    def initialize_kubernetes() -> None:
        if app.state.core_api is not None and app.state.networking_api is not None:
            return
        try:
            config.load_incluster_config()
        except ConfigException:
            _audit_log(event="startup_error", reason="in_cluster_config_unavailable")
            return
        app.state.core_api = client.CoreV1Api()
        app.state.networking_api = client.NetworkingV1Api()

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    def readyz() -> dict[str, str]:
        if not active_settings.secret_file.is_file():
            raise HTTPException(status_code=503, detail="HMAC secret is unavailable")
        if not active_settings.network_policy_enforcement_confirmed:
            raise HTTPException(
                status_code=503,
                detail="NetworkPolicy dataplane enforcement is not attested",
            )
        if app.state.core_api is None or app.state.networking_api is None:
            raise HTTPException(status_code=503, detail="Kubernetes API is unavailable")
        return {"status": "ready"}

    @app.post("/v1/alerts", status_code=202)
    async def ingest_alert(request: Request) -> dict[str, str]:
        body = await request.body()
        timestamp = request.headers.get("X-Aegis-Timestamp")
        signature = request.headers.get("X-Aegis-Signature")

        try:
            secret = active_settings.secret_file.read_bytes().strip()
        except OSError as exc:
            raise HTTPException(status_code=503, detail="HMAC secret is unavailable") from exc

        if not secret:
            raise HTTPException(status_code=503, detail="HMAC secret is empty")

        try:
            verify_request(
                body=body,
                timestamp=timestamp,
                signature=signature,
                secret=secret,
                max_clock_skew_seconds=active_settings.max_clock_skew_seconds,
            )
        except SignatureError as exc:
            _audit_log(event="request_rejected", reason="signature_invalid")
            raise HTTPException(status_code=401, detail="Webhook authentication failed") from exc

        try:
            alert = json.loads(body)
            event = normalize_alert(alert)
        except (json.JSONDecodeError, InvalidAlert) as exc:
            _audit_log(event="request_rejected", reason="alert_invalid")
            raise HTTPException(status_code=422, detail="Wazuh alert is invalid") from exc

        if event.agent_name != active_settings.allowed_agent:
            return {"status": "ignored", "reason": "agent_not_allowlisted"}
        if event.rule_id not in active_settings.allowed_rule_ids:
            return {"status": "ignored", "reason": "rule_not_allowlisted"}
        if event.namespace not in active_settings.allowed_namespaces:
            return {"status": "ignored", "reason": "namespace_not_allowlisted"}

        if app.state.core_api is None or app.state.networking_api is None:
            raise HTTPException(status_code=503, detail="Kubernetes API is unavailable")

        try:
            result = quarantine_pod(
                core_api=app.state.core_api,
                networking_api=app.state.networking_api,
                event=event,
                settings=active_settings,
            )
        except ResponseBlocked as exc:
            _audit_log(
                event="response_blocked",
                event_id=event.event_id,
                rule_id=event.rule_id,
                namespace=event.namespace,
                pod=event.pod_name,
                reason=str(exc),
            )
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except Exception as exc:
            _audit_log(
                event="response_error",
                event_id=event.event_id,
                rule_id=event.rule_id,
                namespace=event.namespace,
                pod=event.pod_name,
                error_type=type(exc).__name__,
            )
            raise HTTPException(status_code=503, detail="Kubernetes response failed") from exc

        _audit_log(
            event="response_completed",
            event_id=event.event_id,
            rule_id=event.rule_id,
            namespace=event.namespace,
            pod=event.pod_name,
            status=result["status"],
            reason=result["reason"],
        )
        return result

    return app


app = create_app()
