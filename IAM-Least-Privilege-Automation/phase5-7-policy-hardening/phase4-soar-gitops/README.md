# Aegis Phase 4: SOAR Containment, Gatekeeper Audit Telemetry and GitOps

**Repository:** \`serra-valle/Cybersecurity-portfolio\`  
**Delivery branch:** \`aegis-phase4-soar-gitops-20261112\`  
**Status:** Source, CI and immutable image supply chain validated. Phase 4 live deployment and runtime acceptance remain outstanding.

## Objective

Phase 4 adds a controlled response path from the existing Falco/Wazuh detections to Kubernetes containment, exports persisted Gatekeeper audit violations to Wazuh, and defines a unified namespace where Kubernetes Pod Security Admission (PSS) and the existing Aegis Gatekeeper controls operate together.

This package is separate from the older \`IAM-Least-Privilege-Automation/project-aegis-phase4/\` project. That directory is not changed.

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the data-flow diagram, [docs/DEPLOYMENT_RUNBOOK.md](docs/DEPLOYMENT_RUNBOOK.md) for deployment steps, and [docs/IMAGE_SECURITY_REVIEW.md](docs/IMAGE_SECURITY_REVIEW.md) for the verified container image, full Trivy results and provenance. The consolidated [Phase 4 submission report](docs/PHASE4_SUBMISSION_REPORT.md) records delivered work, CI evidence and outstanding live acceptance gates.

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

The read-only exporter polls the two Aegis constraint kinds, normalizes \`status.violations\`, writes JSONL records, and emits a resolution record when a previously observed violation disappears from a complete audit snapshot. The exporter requires \`status.auditTimestamp\` and \`status.totalViolations\`; it does not infer resolution from an unaudited, malformed or truncated status. Gatekeeper bounds the number of violation details retained in constraint status, so a snapshot with \`totalViolations\` greater than the returned \`violations\` count is treated as incomplete and cannot resolve omitted findings.

The active-violation checkpoint is atomically stored at \`/var/lib/aegis-gatekeeper-exporter/state.json\`. A normal service restart does not replay already checkpointed findings. A malformed checkpoint causes the exporter to stop rather than silently resetting state and replaying every active finding. JSONL records are fsynced before the checkpoint advances; a crash between the append and checkpoint can still produce a duplicate on restart, so delivery is at-least-once. Wazuh agent JSON collection forwards the records to Manager rules 100503 and 100504.

## Repository layout

- \`app/aegis_soar/\`: authenticated FastAPI webhook, alert normalizer, settings and Kubernetes response logic.
- \`app/tests/\`: signature, normalization and mocked Kubernetes response tests.
- \`collectors/\`: read-only Gatekeeper audit exporter, durable checkpoint and unit tests.
- \`platform/kubernetes/\`: namespaces, PSS labels, unified Gatekeeper constraints, quarantine NetworkPolicies, RBAC and SOAR Deployment.
- \`platform/kubernetes/unified-policy-test/\`: positive and negative admission fixtures.
- \`platform/falco/\`: Phase 4 Falco rule source and ConfigMap generator.
- \`wazuh/active-response/\`: durable Active Response enqueue and HMAC dispatcher.
- \`wazuh/manager/\`: Active Response configuration fragment and Gatekeeper rules 100503/100504.
- \`wazuh/agent/\`: JSON localfile collection fragment.
- \`wazuh/systemd/\`: manager-side retry service and timer.
- \`ops/systemd/\`: Kali port-forward, reverse tunnel and audit-exporter service units.
- \`docs/\`: architecture, acceptance matrix, deployment runbook, image security review, submission report and status record.
- \`.github/workflows/aegis-phase4-ci.yml\`: Python tests, OPA regression, Falco rule validation and PSS/Gatekeeper admission tests.

## Important deployment gates

1. \`platform/kubernetes/soar-deployment.yaml\` now pins the verified immutable GHCR image digest. The image passed full Trivy scans on AMD64 and ARM64 and runtime smoke tests, but it has not been deployed. Do not replace the digest with a mutable tag.
2. Create the HMAC secret outside Git. The same high-entropy secret must be installed on Wazuh Manager and mounted into the SOAR Deployment.
3. Apply the existing Phase 2 ConstraintTemplates before the Phase 4 constraints.
4. Keep \`AEGIS_NETWORK_POLICY_ENFORCEMENT_CONFIRMED=false\` until both ingress and egress denial are demonstrated against quarantined Pods in the target Calico dataplane.
5. Configure target application Services to select \`aegis.security/endpoint-enabled: "true"\` and verify EndpointSlice removal.
6. Falco's ConfigMap is source-controlled, but applying it does not automatically reconcile an existing Helm DaemonSet. Merge the ConfigMap data into the current chart configuration and preserve all existing Helm values. Do not load a second copy of the Phase 3 write rule alongside the existing rule.
7. Confirm Wazuh rule IDs 100503 and 100504 are unused before installing the Gatekeeper rules file.
8. Verify the live Falco driver mode before describing the runtime path as eBPF-backed. The Phase 4 source and CI validate the Falco rule syntax; they do not prove which driver the live DaemonSet is using.

## Validation boundary

[Consolidated-head push run 44137127343](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/44137127343) passed all three jobs on commit \`3c40483b2714c09e74405662f983eecb1e4a596b\`. The source and policy checks, Kubernetes 1.33.12 / Gatekeeper 3.23.1 admission matrix, and multi-architecture image pipeline all passed. The new image was smoke-tested on AMD64 and ARM64, scanned by Trivy 0.76.2 with zero vulnerability, misconfiguration or secret findings on both architectures, and published with an SBOM and Sigstore-signed provenance.

The consolidated-head image digest is \`ghcr.io/serra-valle/aegis-soar@sha256:6993a33a9e0873f5b7b37a255740e6e7d0dbc7e3286b85725d8ad7fb4c2cc05d\`. Its full reports are retained as [artifact 14352298031](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/44137127343/artifacts/14352298031), with [GitHub provenance attestation 68736375](https://github.com/serra-valle/Cybersecurity-portfolio/attestations/68736375) and [Rekor entry 3950054994](https://search.sigstore.dev?logIndex=3950054994).

The Deployment manifest remains pinned to the separately verified digest \`sha256:7cfb86923d5110aeec3241641fee94eef9324a7bfeaaa751d50fb6f4f856f0dc\` from [run 44134158272](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/44134158272). The newer digest is independently verified but has not been promoted into the manifest. [PR validation run 44137140455](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/44137140455) and [policy regression run 44137140567](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/44137140567) also passed.

The earlier [CI baseline run 43828411989](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/43828411989) is retained as historical source and policy validation evidence.

These are source, image and CI admission tests only. No Phase 4 live cluster deployment, Calico packet-isolation test, SOAR webhook execution, Wazuh Active Response execution, Gatekeeper-to-Wazuh ingestion, or containment event is represented as completed in this repository. No synthetic output is presented as live evidence.

The Phase 4 Falco driver mode has not been reverified in a live cluster. Do not describe this delivery as an eBPF-validated containment path until the deployed Falco driver is captured and confirmed.

The earlier Phase 3 observations remain limited to the specific controlled events recorded in \`phase3-runtime-detection/evidence/wazuh-integration/\`. They are not Phase 4 containment evidence.

See:
- [Architecture](docs/ARCHITECTURE.md)
- [Acceptance matrix](docs/ACCEPTANCE_MATRIX.md)
- [Deployment runbook](docs/DEPLOYMENT_RUNBOOK.md)
- [Delivery status](docs/DELIVERY_STATUS.md)
- [Image security review](docs/IMAGE_SECURITY_REVIEW.md)
