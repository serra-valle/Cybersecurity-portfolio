# Aegis Guardrail Phase 4 Delivery Report

**Prepared:** 16 November 2026  
**Prepared by:** Security Engineering  
**Repository:** `serra-valle/Cybersecurity-portfolio`  
**Branch:** `aegis-phase4-soar-gitops-20261112`  
**Pull request:** [#2, Aegis Phase 4](https://github.com/serra-valle/Cybersecurity-portfolio/pull/2)

## 1. Executive summary

I prepared the Phase 4 implementation package for automated Kubernetes response, Gatekeeper audit telemetry and declarative policy delivery. The package now includes the SOAR webhook, Kubernetes response controls, Wazuh Active Response integration files, Gatekeeper audit exporter, Falco rule source, unified PSS and Gatekeeper policy fixtures, CI validation and deployment documentation.

The automated source and admission checks passed in GitHub Actions. I have not deployed the Phase 4 package into the target lab or run the end-to-end Wazuh-to-SOAR-to-Kubernetes containment path. I am keeping those items separate from the verified CI results rather than presenting them as completed.

## 2. Work delivered

### 2.1 SOAR webhook and Kubernetes response

I extended the FastAPI service with:

- HMAC-SHA256 request authentication and timestamp validation.
- A request-size limit and strict agent, Wazuh rule ID and namespace allowlists.
- Kubernetes API access through a dedicated ServiceAccount.
- A precondition check for the named quarantine NetworkPolicy. The policy must select the quarantine label, include both ingress and egress policy types, and contain no allow rules.
- Pod quarantine labels and audit annotations.
- A separate endpoint-eligibility label so Services configured with the required selector can remove quarantined Pods from their EndpointSlices.
- Immediate zero-second deletion for the configured high-risk rule 100502, limited to unmanaged response-target Pods.

I kept controller-managed Pods out of the deletion path. Deleting a controller-owned Pod without changing its workload template can result in an unquarantined replacement. Those Pods are quarantined and preserved instead.

The service fails closed while NetworkPolicy dataplane enforcement is not attested. The deployment configuration currently leaves `AEGIS_NETWORK_POLICY_ENFORCEMENT_CONFIRMED=false`.

### 2.2 Wazuh Active Response delivery

I added a Wazuh Active Response script that accepts only the configured agent and rules 100501/100502, then writes the alert to a durable local spool. A separate dispatcher retries delivery and signs the request with the shared HMAC key.

The connection is designed around a loopback-only manager listener, a reverse SSH tunnel initiated from Kali, and a local Kubernetes port-forward. The webhook is not designed to be exposed publicly.

The Active Response and dispatcher files are source-controlled. They have not been installed or executed on the live Wazuh Manager.

### 2.3 Gatekeeper audit telemetry

I added a read-only exporter for:

- `K8sAegisContainerSecurity`
- `K8sAegisImageIntegrity`

The exporter reads persisted Gatekeeper constraint violations, normalizes them to JSONL, and emits resolution records when a previously observed violation disappears. Wazuh localfile collection and custom rules 100503/100504 are included.

The exporter normalization tests passed. Live Gatekeeper polling, Wazuh agent ingestion and manager alert generation remain outstanding.

### 2.4 Falco and policy GitOps

I added a Phase 4 Falco rule source and a ConfigMap generator. The write rule retains the existing Aegis rule identity and extends its scope to the Phase 4 response-target workload. The built-in Falco `Terminal shell in container` rule remains the event source for rule 100502.

I also added declarative Kubernetes namespaces, RBAC, quarantine NetworkPolicies, the SOAR Deployment and the unified Gatekeeper constraints. The existing Phase 2 ConstraintTemplates remain the canonical templates and are reused without changing the older project directory.

The Falco ConfigMap has not been reconciled into the live Helm release. The deployment operator must merge it with the current chart configuration and avoid loading a duplicate copy of the existing write rule.

### 2.5 Unified PSS and Gatekeeper controls

I defined `aegis-unified-policy` with native Pod Security Admission `restricted:v1.33` and both Aegis Gatekeeper constraints.

The CI admission matrix covered:

| Test | Expected result | CI result |
|---|---|---|
| Secure non-root Pod, read-only root filesystem and digest-pinned image | Admitted by PSS and Gatekeeper | Passed |
| Privileged Pod | Rejected by native PSS | Passed |
| PSS-compatible Pod with writable root filesystem | Rejected by Gatekeeper | Passed |
| PSS-compatible Pod with tag-only image | Rejected by Gatekeeper | Passed |

These were server-side dry-run admission checks in a disposable CI cluster. The positive fixture uses a syntactically valid placeholder digest and is not a pullable image.

## 3. Automated validation results

[GitHub Actions run 43828411989](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/43828411989) passed both jobs on commit `1f8b6cebf476396b5830d05d6c5d02fb3dc8478c`.

| Validation | Result |
|---|---|
| SOAR and Gatekeeper exporter Python unit tests | 19 passed |
| Python compilation of application, collector and Active Response scripts | Passed |
| Wazuh XML configuration parsing | Passed |
| OPA 0.62.1 regression | 10/10 passed |
| Falco 0.45.0 rule validation | Passed |
| Kubernetes Kustomize build | Passed |
| Falco ConfigMap Kustomize build | Passed |
| Kubernetes 1.33.12 and Gatekeeper 3.23.1 admission matrix | All four expected outcomes passed |

The current branch contains documentation and status updates after the tested commit. No application, policy, manifest or test-fixture behavior changed after that successful run.

## 4. Items still required for live acceptance

I have not marked Phase 4 as fully complete because these tasks still require execution and evidence:

1. Build and publish the SOAR image, then replace the placeholder image tag with the immutable GHCR digest.
2. Provision the same high-entropy HMAC secret on Wazuh Manager and as the Kubernetes Secret.
3. Apply the Phase 4 manifests to the dedicated Phase 4 lab.
4. Prove Calico blocks both ingress and egress to quarantined Pods.
5. Verify that application Services use the endpoint-eligibility selector and that quarantined Pods disappear from EndpointSlices.
6. Execute the Wazuh Active Response path and confirm durable retry behavior during a controlled webhook outage.
7. Confirm Gatekeeper JSONL records reach Wazuh and rules 100503/100504 generate the expected alerts.
8. Reconcile the Falco ConfigMap into the live Helm release and verify that the existing rule is not duplicated.
9. Capture the deployed Falco driver mode. I have not verified that the live Phase 4 path is using eBPF, so I am not describing it as eBPF-validated.
10. Capture genuine end-to-end containment logs and attach them to the evidence package.

The SOAR dataplane-attestation setting must remain false until the ingress, egress and EndpointSlice checks are complete.

## 5. Submission status

I opened [draft PR #2](https://github.com/serra-valle/Cybersecurity-portfolio/pull/2) against the Phase 3 branch. It is intentionally stacked on [Phase 3 PR #1](https://github.com/serra-valle/Cybersecurity-portfolio/pull/1), so Phase 3 should be merged first. Phase 4 can then be retargeted to `main`.

The assigned target date was 13 November 2026. This report is dated 16 November 2026 and does not backdate implementation, deployment or acceptance.

**Current conclusion:** the Phase 4 source package and automated CI admission suite are prepared and passing. Live deployment, network containment, Wazuh integration and runtime evidence are still required before I can report full operational acceptance.
