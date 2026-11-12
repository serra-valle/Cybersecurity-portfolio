# Aegis Phase 4: SOAR Containment, Gatekeeper Audit Telemetry and GitOps

**Delivery branch:** aegis-phase4-soar-gitops-20261112  
**Implementation scope:** Phase 4 requirements from the 28 October 2026 technical handoff  
**Status:** Implementation package prepared; live acceptance is not claimed

## Purpose

Phase 4 extends Aegis from preventive infrastructure and Kubernetes controls into controlled runtime response and policy-violation telemetry. It adds an authenticated Wazuh-to-SOAR path, a fail-closed Kubernetes quarantine action, Gatekeeper audit export to Wazuh, combined Pod Security Admission and Gatekeeper controls, and declarative deployment configuration.

The package is deliberately separate from the older Terraform/OPA project at IAM-Least-Privilege-Automation/project-aegis-phase4/. That directory is not modified.

## Architecture

~~~text
Falco event in an approved workload
        |
        v
Wazuh agent on Kali
        |
        v
Wazuh Manager on AWS
  rules 100501 / 100502
        |
        v
Wazuh custom integration
  durable local alert spool
        |
        v
Dispatcher + HMAC-SHA256
        |
        v
AWS loopback port 18080
        |
        | SSH reverse tunnel initiated from Kali
        v
Kali loopback port 18081
        |
        | kubectl port-forward
        v
Aegis SOAR Service in aegis-soar-system
        |
        | dedicated Kubernetes ServiceAccount
        v
Approved Pod in aegis-policy-test or aegis-unified-policy
        |
        +--> verify target label and quarantine NetworkPolicy
        +--> apply quarantine label and audit annotations
        +--> optional deletion of unmanaged Pods only
~~~

Gatekeeper audit telemetry is a separate read-only path:

~~~text
Gatekeeper Constraint status.violations
        |
        v
Read-only audit exporter on Kali
        |
        v
/var/log/aegis/gatekeeper-audit.jsonl
        |
        v
Wazuh agent JSON localfile collection
        |
        v
Wazuh rules 100503 / 100504
~~~

## Security invariants

1. The SOAR endpoint accepts only HMAC-authenticated requests with a bounded timestamp window.
2. Only Wazuh agent kali-aegis-lab and rule IDs 100501/100502 are eligible for response.
3. Only namespaces explicitly listed in configuration are eligible.
4. A Pod must carry the exact label aegis.security/response-target=true before it can be quarantined.
5. The named quarantine NetworkPolicy must exist and have an empty ingress and egress rule set, selecting aegis.security/status=quarantined.
6. The service refuses to mutate a Pod unless AEGIS_NETWORK_POLICY_ENFORCEMENT_CONFIRMED is true. This setting must remain false until Calico dataplane isolation has been demonstrated in the target cluster.
7. Deletion is disabled by default. If explicitly enabled, only unmanaged Pods with no owner references can be deleted. Controller-managed Pods remain quarantined and are not deleted, preventing immediate controller recreation from bypassing containment.
8. The SOAR service has namespace-scoped Pod permissions only. The Gatekeeper audit reader has read-only access to the two Aegis constraint kinds.
9. The manager-side integration uses a durable queue. Temporary tunnel or service outages do not silently discard an alert.
10. Secrets, kubeconfig tokens, raw alerts and private host data are not committed.

## Repository layout

- app/aegis_soar/: FastAPI webhook, HMAC verification, alert normalization and Kubernetes response logic.
- app/tests/: unit tests for signature verification and Wazuh/Falco event normalization.
- platform/kubernetes/: namespaces, combined Gatekeeper constraints, quarantine policies, service account/RBAC and SOAR Deployment.
- platform/kubernetes/audit-test/: isolated dry-run constraints and a persisted audit fixture. It is not part of the production Kustomize base.
- collectors/: Gatekeeper constraint-status exporter and systemd unit.
- wazuh/: Gatekeeper rules, localfile stanza and manager-side durable integration spool/dispatcher.
- ops/systemd/: Kali port-forward and SSH reverse-tunnel units.
- ops/scripts/: response-target labeling and restricted audit-token bootstrap helpers.
- docs/: acceptance matrix and delivery status.

## Deployment dependencies

The intended target is the dedicated Phase 4 Kind cluster, context kind-aegis-phase4-lab. The existing handoff records Calico 3.33.0 in that cluster. The Phase 3 cluster, kind-aegis-policy-lab, must not be repurposed or have its CNI changed as part of this deployment.

The target cluster must have:
- Kubernetes 1.33.x or compatible.
- Calico or another NetworkPolicy-enforcing CNI, with dataplane behavior verified.
- Gatekeeper 3.23.1.
- The existing Aegis ConstraintTemplates from phase2-advanced/kubernetes/gatekeeper/.
- Aegis Wazuh manager rules 100501 and 100502 already installed.
- A Wazuh Manager reachable from Kali over the existing SSH path.

The SOAR image must be built and published before applying the Deployment. The image reference in the manifest is a release tag placeholder until the built image digest is recorded. Before production use, replace the tag with the exact immutable digest produced by the release build.

## Apply order

1. Review docs/DELIVERY_STATUS.md and docs/ACCEPTANCE_MATRIX.md.
2. Build and publish the SOAR image. Record its immutable digest and update the Deployment image reference.
3. Apply the existing Phase 2 ConstraintTemplates from the canonical source directory.
4. Apply the Phase 4 production Kustomize base.
5. Provision the HMAC secret outside Git and install the same secret on the Wazuh Manager.
6. Install the Kali port-forward and reverse-tunnel units, then the manager-side spool dispatcher.
7. Install the read-only Gatekeeper audit-reader token and start the exporter.
8. Keep AEGIS_NETWORK_POLICY_ENFORCEMENT_CONFIRMED=false until the acceptance criteria for both permitted and denied traffic are completed. Do not enable automated containment before that gate.
9. Run the acceptance matrix in a controlled lab window, capture raw outputs, sanitize them, and add checksums.

The package does not include credentials or apply itself to either cluster.

## Falco declarative parity

The canonical custom Falco rule remains in phase3-runtime-detection/falco/aegis-runtime-write.yaml. It is extended to cover the Phase 4 response target while preserving the original Phase 3 test-pod match. The live Helm release must be upgraded with the existing values retained. Do not replace the current Helm values file with a partial overlay.

For Helm chart 9.2.0, merge the reviewed rule into the chart customRules value using the file as the source. Review the rendered manifest before applying it. The prior handoff recorded live-versus-Helm drift; this source update alone does not prove that the live ConfigMap has been reconciled.

## Validation boundary

No Phase 4 live cluster, Wazuh integration, network-isolation or SOAR execution test is represented as completed by this delivery. Unit tests, acceptance manifests and CI validation are included as implementation artifacts. A manifest existing in Git is not proof that the cluster enforces it. A successful API response is not proof that packets are blocked.

The existing Phase 3 observations remain the baseline:
- Wazuh rule 100501 matched one controlled filesystem-write event.
- Wazuh rule 100502 matched one controlled interactive-shell event.
- Their observed event-to-alert timestamp differences were approximately 774 ms and 252 ms respectively. These are individual observations, not a latency benchmark.
- Phase 3 Wazuh indexer/dashboard visibility and final evidence-integrity items remain outstanding in the prior handoff.

See docs/DELIVERY_STATUS.md for the exact status and docs/ACCEPTANCE_MATRIX.md for the release gates.
