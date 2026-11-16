# Aegis Phase 4: SOAR Containment, Gatekeeper Audit Telemetry and GitOps

**Repository:** \`serra-valle/Cybersecurity-portfolio\`  
**Delivery branch:** \`aegis-phase4-soar-gitops-20261112\`  
**Status:** Source implementation and validation package prepared. Live deployment and runtime acceptance are not claimed.

## Objective

Phase 4 adds a controlled response path from the existing Falco/Wazuh detections to Kubernetes containment, exports persisted Gatekeeper audit violations to Wazuh, and defines a unified namespace where Kubernetes Pod Security Admission (PSS) and the existing Aegis Gatekeeper controls operate together.

This package is separate from the older \`IAM-Least-Privilege-Automation/project-aegis-phase4/\` project. That directory is not changed.

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the data-flow diagram and [docs/DEPLOYMENT_RUNBOOK.md](docs/DEPLOYMENT_RUNBOOK.md) for deployment steps.

### Runtime response path

1. Falco emits the existing Aegis filesystem-write rule (100501) or the built-in \`Terminal shell in container\` event (100502).
2. Wazuh Manager Active Response receives only rules 100501 and 100502.
3. The Active Response script accepts only agent \`kali-aegis-lab\`, allowlisted rule IDs and the \`add\` command, then writes the alert to a durable local spool.
4. A systemd timer retries delivery. The dispatcher signs the exact JSON body with HMAC-SHA256 and posts it to the manager's loopback endpoint.
5. A reverse SSH tunnel from Kali exposes the manager's loopback port to a Kali-local port-forward into the Phase 4 SOAR Deployment.
6. The FastAPI service verifies the signature, agent, rule ID and namespace before calling the Kubernetes API.

The service fails closed unless the named quarantine NetworkPolicy exists, selects \`aegis.security/status=quarantined\`, has both Ingress and Egress policy types, and contains no allow rules. The dataplane-attestation setting is false by default and must remain false until traffic isolation has been tested.

### Containment actions

- **Rule 100501:** quarantine the explicitly labelled response-target Pod.
- **Rule 100502:** quarantine the explicitly labelled response-target Pod. If configured for eviction, the service immediately deletes an unmanaged target Pod with \`grace_period_seconds=0\`.
- Controller-managed Pods are quarantined but not deleted. Deleting a controller-owned Pod without changing its workload template can create a replacement that is not quarantined.
- Quarantine also changes \`aegis.security/endpoint-enabled\` to \`false\`. Target Services must include \`aegis.security/endpoint-enabled: "true"\` in their selectors to remove quarantined Pods from their EndpointSlices. NetworkPolicy is the actual ingress/egress isolation control; a label change alone is not isolation.

### Gatekeeper audit path

The read-only exporter polls the two Aegis constraint kinds, normalizes \`status.violations\`, writes JSONL records, and emits a resolution record when a previously observed violation disappears. Wazuh agent JSON collection forwards the records to Manager rules 100503 and 100504.

## Repository layout

- \`app/aegis_soar/\`: authenticated FastAPI webhook, alert normalizer, settings and Kubernetes response logic.
- \`app/tests/\`: signature, normalization and mocked Kubernetes response tests.
- \`collectors/\`: read-only Gatekeeper audit exporter and unit tests.
- \`platform/kubernetes/\`: namespaces, PSS labels, unified Gatekeeper constraints, quarantine NetworkPolicies, RBAC and SOAR Deployment.
- \`platform/kubernetes/unified-policy-test/\`: positive and negative admission fixtures.
- \`platform/falco/\`: Phase 4 Falco rule source and ConfigMap generator.
- \`wazuh/active-response/\`: durable Active Response enqueue and HMAC dispatcher.
- \`wazuh/manager/\`: Active Response configuration fragment and Gatekeeper rules 100503/100504.
- \`wazuh/agent/\`: JSON localfile collection fragment.
- \`wazuh/systemd/\`: manager-side retry service and timer.
- \`ops/systemd/\`: Kali port-forward, reverse tunnel and audit-exporter service units.
- \`docs/\`: architecture, acceptance matrix, deployment runbook and status record.
- \`.github/workflows/aegis-phase4-ci.yml\`: Python tests, OPA regression, Falco rule validation and PSS/Gatekeeper admission tests.

## Important deployment gates

1. The image reference in \`platform/kubernetes/soar-deployment.yaml\` is a placeholder. Build and publish the image, then replace it with the immutable GHCR digest before deployment.
2. Create the HMAC secret outside Git. The same high-entropy secret must be installed on Wazuh Manager and mounted into the SOAR Deployment.
3. Apply the existing Phase 2 ConstraintTemplates before the Phase 4 constraints.
4. Keep \`AEGIS_NETWORK_POLICY_ENFORCEMENT_CONFIRMED=false\` until both ingress and egress denial are demonstrated against quarantined Pods in the target Calico dataplane.
5. Configure target application Services to select \`aegis.security/endpoint-enabled: "true"\` and verify EndpointSlice removal.
6. Falco's ConfigMap is source-controlled, but applying it does not automatically reconcile an existing Helm DaemonSet. Merge the ConfigMap data into the current chart configuration and preserve all existing Helm values. Do not load a second copy of the Phase 3 write rule alongside the existing rule.
7. Confirm Wazuh rule IDs 100503 and 100504 are unused before installing the Gatekeeper rules file.

## Validation boundary

The GitHub Actions workflow is the intended automated validation path. Its results must be inspected after the pull request is opened; the workflow definition itself is not evidence of a passing run.

No Phase 4 live cluster deployment, Calico packet-isolation test, SOAR webhook execution, Wazuh Active Response execution, Gatekeeper-to-Wazuh ingestion, or containment log is represented as completed in this repository. No synthetic output is presented as live evidence.

The earlier Phase 3 observations remain limited to the specific controlled events recorded in \`phase3-runtime-detection/evidence/wazuh-integration/\`. They are not Phase 4 containment evidence.

See:
- [Architecture](docs/ARCHITECTURE.md)
- [Acceptance matrix](docs/ACCEPTANCE_MATRIX.md)
- [Deployment runbook](docs/DEPLOYMENT_RUNBOOK.md)
- [Delivery status](docs/DELIVERY_STATUS.md)
