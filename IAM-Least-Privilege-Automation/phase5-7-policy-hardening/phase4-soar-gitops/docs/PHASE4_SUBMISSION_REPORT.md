# Aegis Guardrail Phase 4 Delivery Report

**Prepared:** 17 November 2026  
**Prepared by:** Security Engineering  
**Repository:** `serra-valle/Cybersecurity-portfolio`  
**Branch:** `aegis-phase4-soar-gitops-20261112`  
**Pull request:** [#2, Aegis Phase 4](https://github.com/serra-valle/Cybersecurity-portfolio/pull/2)

## 1. Executive summary

I prepared the Phase 4 implementation package for automated Kubernetes response, Gatekeeper audit telemetry and declarative policy delivery. The package now includes the SOAR webhook, Kubernetes response controls, Wazuh Active Response integration files, Gatekeeper audit exporter, Falco rule source, unified PSS and Gatekeeper policy fixtures, CI validation and deployment documentation.

The automated source, policy admission and multi-architecture image checks passed in GitHub Actions. I built and scanned the SOAR image, tested its hardened runtime behavior on both architectures, attached an SBOM and signed provenance, and pinned the approved digest in the Deployment manifest. I subsequently installed Gatekeeper 3.23.1 in the dedicated Phase 4 Kind lab (Kubernetes v1.37.0 / Calico 3.33.0), applied the Phase 4 templates and unified constraints, and verified actual admission-webhook enforcement with positive and negative server-side dry-run tests. The SOAR Deployment and end-to-end Wazuh-to-SOAR containment path have not been deployed or validated. The AWS-hosted Wazuh Manager is unavailable because the AWS account is closed. I distinguish these runtime results and limitations from the CI evidence.

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

The exporter has 12 passing unit tests covering normalization, checkpoint persistence, duplicate replay, resolution transitions, truncated snapshots and failure handling. Gatekeeper audit snapshots were also read successfully from the live Phase 4 constraints. The exporter service itself has not been deployed, and Wazuh agent ingestion and manager alert generation remain outstanding because the AWS-hosted Manager is unavailable.

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

These CI checks were server-side dry-run admission tests in a disposable cluster. The positive fixture uses a syntactically valid placeholder digest and is not a pullable image. I subsequently repeated the positive and negative admission checks against the dedicated Phase 4 lab: the secure Pod was admitted; writable-root-filesystem and tag-only-image Pods were rejected by the Gatekeeper validation webhook; and the privileged Pod was rejected by native Pod Security Admission. The Phase 4 constraints report `enforced: true` across the Gatekeeper pods. The audit controller also produced timestamped snapshots for both constraints, with zero violations at the recorded observation. These tests establish policy admission and audit API operation, not SOAR containment or Wazuh delivery.

### 2.6 Container image supply chain

I replaced the Debian slim base after the first complete Trivy report identified 47 HIGH OS-package findings across 11 CVEs with no fixed Trixie package versions available at scan time. The replacement uses the immutable `python:3.12.16-alpine3.24` base digest. I also upgraded pip to 26.2.0 for dependency installation, then removed pip and its bundled installer from the runtime image.

The final image is:

```text
ghcr.io/serra-valle/aegis-soar@sha256:7cfb86923d5110aeec3241641fee94eef9324a7bfeaaa751d50fb6f4f856f0dc
```

The image was published for `linux/amd64` and `linux/arm64`. Both architecture smoke tests ran the service as UID/GID 10001 with a read-only root filesystem, all capabilities dropped and no-new-privileges. The health endpoint returned HTTP 200. Readiness returned the expected HTTP 503 while the HMAC secret was absent, confirming the service remained fail-closed.

Trivy 0.76.2 scanned all severities with vulnerability, misconfiguration and secret scanners on both architecture manifests. The final reports contained zero findings on AMD64 and ARM64. The full JSON reports are retained as workflow artifact [14351327524](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/44134158272).

The image includes a BuildKit SBOM and a Sigstore-signed provenance attestation. The attestation was uploaded to [GitHub](https://github.com/serra-valle/Cybersecurity-portfolio/attestations/68730154), GHCR and the [Rekor transparency log](https://search.sigstore.dev?logIndex=3949778857). The immutable digest is pinned in the Kubernetes Deployment manifest.

This validates the image artifact only. The Deployment has not been rolled out and no live containment has occurred.

### 2.7 Consolidated-head CI revalidation

After consolidating the delivery documentation and improving the ARM64 smoke-test diagnostics, I ran the Phase 4 pipeline again against commit `3c40483b2714c09e74405662f983eecb1e4a596b`.

[Push run 44137127343](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/44137127343) passed all three jobs. [PR run 44137140455](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/44137140455) passed both Phase 4 pull-request checks, and [policy regression run 44137140567](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/44137140567) passed both policy-regression jobs.

The consolidated-head push produced an additional multi-architecture image:

```text
ghcr.io/serra-valle/aegis-soar@sha256:6993a33a9e0873f5b7b37a255740e6e7d0dbc7e3286b85725d8ad7fb4c2cc05d
```

Both architecture smoke tests passed with the service running as UID/GID 10001, a read-only root filesystem, all capabilities dropped and no-new-privileges. Trivy 0.76.2 reported zero vulnerability, misconfiguration and secret findings on AMD64 and ARM64. The full reports are retained as [artifact 14352298031](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/44137127343/artifacts/14352298031). Signed provenance was uploaded to [GitHub](https://github.com/serra-valle/Cybersecurity-portfolio/attestations/68736375), GHCR and [Rekor](https://search.sigstore.dev?logIndex=3950054994).

The first consolidated push attempt, [run 44136227347](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/44136227347), did not pass because the ARM64 health endpoint failed to respond within the original 30-second smoke-test window. That run stopped before Trivy scanning and provenance attestation. I increased the startup deadline to 120 seconds and added container state, exit-code, log and health-response capture for future failures. The subsequent run passed on both architectures. This is consistent with startup-time sensitivity under emulation; I did not treat the first timeout as proof of an application defect.

The Deployment manifest remains pinned to the earlier verified image digest `sha256:7cfb86923d5110aeec3241641fee94eef9324a7bfeaaa751d50fb6f4f856f0dc` from run 44134158272. The new digest is independently verified but has not been promoted into the manifest. Neither image has been deployed.

## 3. Automated validation results

[GitHub Actions run 44137127343](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/44137127343) passed all three jobs on consolidated commit `3c40483b2714c09e74405662f983eecb1e4a596b`. The Phase 4 [PR run 44137140455](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/44137140455) and [policy regression run 44137140567](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/44137140567) also passed. The earlier [run 43828411989](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/43828411989) remains the original source and policy baseline, while run 44134158272 validates the image digest currently pinned in the Deployment manifest.

| Validation | Result |
|---|---|
| SOAR application unit tests | 16 passed in code validation run 44142985557 |
| Gatekeeper exporter unit tests | 12 passed in code validation run 44142985557 and local regression run |
| Python compilation of application, collector and Active Response scripts | Passed |
| Wazuh XML configuration parsing | Passed |
| OPA 0.62.1 regression | 10/10 passed |
| Falco 0.45.0 rule validation | Passed |
| Kubernetes Kustomize build | Passed |
| Falco ConfigMap Kustomize build | Passed |
| Kubernetes 1.33.12 and Gatekeeper 3.23.1 admission matrix | All four expected outcomes passed |
| Multi-architecture image build | AMD64 and ARM64 published |
| Hardened runtime smoke tests | Both architectures passed under non-root, read-only-root, no-capability and no-new-privileges settings |
| Trivy 0.76.2 full scan | Zero vulnerability, misconfiguration and secret findings on both architectures |
| SBOM and provenance | BuildKit SBOM attached; Sigstore-signed provenance uploaded to GitHub, GHCR and Rekor |

The consolidated-head run validates the current application, policy, manifests and image pipeline at commit `3c40483b2714c09e74405662f983eecb1e4a596b`. The additional image digest from that run is independently verified, while the Deployment manifest continues to pin the previously verified digest `7cfb86923d5110aeec3241641fee94eef9324a7bfeaaa751d50fb6f4f856f0dc`. These CI results do not constitute a live Phase 4 deployment or runtime network-isolation test.

## 4. Items still required for live acceptance

I have not marked Phase 4 as operationally complete. The remaining acceptance gaps are:

1. Complete exporter freshness hardening and deploy the collector with a dedicated, renewable read-only Kubernetes identity. The current exporter tests pass, but the systemd service is not deployed.
2. Provision the HMAC secret securely in Kubernetes and on a restored Wazuh Manager. Keep it outside Git.
3. Restore Wazuh Manager infrastructure. The previous AWS-hosted Manager is unavailable because the AWS account is closed; therefore Active Response, dispatcher delivery, Gatekeeper JSONL ingestion and rules 100503/100504 cannot currently be exercised.
4. Deploy the SOAR workload only after its secret and runtime prerequisites are available.
5. Prove Calico ingress and egress isolation, Service selector eligibility and EndpointSlice removal.
6. Reconcile the Falco ConfigMap into the live Helm release, avoid duplicate rules, and capture the actual Falco driver mode.
7. Execute controlled SOAR containment and capture genuine end-to-end evidence.

The SOAR dataplane-attestation setting must remain false until the ingress, egress and EndpointSlice checks are complete.

## 5. Submission status

I opened [draft PR #2](https://github.com/serra-valle/Cybersecurity-portfolio/pull/2) against the Phase 3 branch. It is intentionally stacked on [Phase 3 PR #1](https://github.com/serra-valle/Cybersecurity-portfolio/pull/1), so Phase 3 should be merged first. Phase 4 can then be retargeted to `main`.

The assigned target date was 13 November 2026. This report is dated 17 November 2026 and does not backdate implementation, deployment or acceptance.

**Current conclusion:** the Phase 4 source package, CI admission suite, immutable SOAR image supply chain, Gatekeeper installation, unified constraint enforcement and Gatekeeper audit snapshot retrieval are validated. The SOAR Deployment, exporter service, Wazuh integration, Calico dataplane isolation and end-to-end containment remain unverified. The AWS account closure prevents access to the previous Wazuh Manager. This is a partially accepted engineering delivery, not a claim of completed operational SOAR.
