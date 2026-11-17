# Aegis Guardrail Phase 4 Engineering Delivery Report

**Prepared:** 17 November 2026  
**Prepared by:** Security Engineering  
**Repository:** `serra-valle/Cybersecurity-portfolio`  
**Branch:** `aegis-phase4-soar-gitops-20261112`  
**Pull request:** [#2, Aegis Phase 4](https://github.com/serra-valle/Cybersecurity-portfolio/pull/2)

## 1. Executive summary

Phase 4 expanded Aegis Guardrail from policy validation and security telemetry into a broader Kubernetes security engineering platform. The work brought together automated response design, Kubernetes workload controls, Wazuh integration, Gatekeeper audit collection, Falco rule delivery, policy-as-code, container hardening, multi-architecture image publishing, software supply-chain evidence and repeatable CI validation.

I implemented the FastAPI SOAR service and its response safeguards, built the Wazuh Active Response and durable delivery components, developed a Gatekeeper audit exporter with persistent state and resolution tracking, and authored the Kubernetes and Falco GitOps resources. I also established a dedicated Phase 4 Kind environment, recovered and stabilized its Calico networking components, installed Gatekeeper, applied the unified policy controls and verified the expected admission decisions against the live admission webhooks.

A major part of the delivery was the SOAR container supply chain. I replaced the initial base image after identifying 47 HIGH OS-package findings across 11 CVEs, hardened the runtime, published AMD64 and ARM64 images, completed full Trivy scans on the approved builds, generated an SBOM and published Sigstore-signed provenance. The deployment references an immutable image digest rather than a mutable tag.

The code and policy work is backed by automated tests and repeated GitHub Actions validation. The latest consolidated code validation recorded 16 SOAR tests, 12 exporter tests and 10/10 OPA regression tests passing, alongside Python compilation, Wazuh XML parsing, Falco rule validation, Kustomize builds and the disposable-cluster admission matrix. The dedicated Phase 4 lab then provided additional live Kubernetes admission and Gatekeeper audit evidence.

The remaining work is concentrated in connecting the completed components to restored Wazuh infrastructure and completing live containment acceptance. Those integration steps are recorded separately so the report accurately distinguishes implementation, automated validation and lab verification from operational deployment.

## 2. Objectives and engineering scope

The Phase 4 assignment focused on five connected outcomes:

1. **Automated Kubernetes response:** receive authenticated Wazuh alerts, validate their origin and scope, and apply controlled quarantine actions to approved Pods.
2. **Gatekeeper audit telemetry:** collect persisted constraint violations, normalize them into structured events and make them available for Wazuh analysis.
3. **Declarative policy delivery:** manage Falco rules, Kubernetes resources, response policies and unified admission controls as version-controlled artifacts.
4. **Unified workload security:** combine native Pod Security Admission with the existing Aegis Gatekeeper controls.
5. **Repeatable validation and evidence:** test application behavior, policy decisions, deployment artifacts and container supply-chain controls through CI and a dedicated Kubernetes lab.

The implementation reused the established Phase 2 Gatekeeper ConstraintTemplates and Phase 3 Wazuh detection foundation. Phase 4 kept the earlier project work intact while adding a separate lab, response architecture and delivery branch.

## 3. Architecture and event flow

The solution is organized around two related event paths.

### 3.1 Runtime detection and response path

```text
Falco / Wazuh detection
        |
        v
Wazuh Active Response (rules 100501 / 100502)
        |
        v
Durable local alert spool
        |
        v
Retrying dispatcher + HMAC-SHA256 request
        |
        v
Private tunnel / local Kubernetes forwarding
        |
        v
FastAPI SOAR webhook
        |
        v
Authentication, timestamp, allowlist and safety checks
        |
        v
Kubernetes API via dedicated ServiceAccount/RBAC
        |
        v
Quarantine labels, endpoint eligibility and controlled response
        |
        +----> NetworkPolicy enforcement
        |
        +----> Service EndpointSlice exclusion
```

The design keeps the webhook private rather than exposing it publicly. The manager-side listener is intended to bind to loopback, with a reverse SSH tunnel from Kali and a local Kubernetes port-forward providing the controlled path.

### 3.2 Gatekeeper audit telemetry path

```text
Gatekeeper constraint audit status
        |
        v
Read-only Gatekeeper audit exporter
        |
        v
Snapshot validation + state/checkpoint comparison
        |
        v
Normalized JSONL active / resolved events
        |
        v
Wazuh agent localfile collection
        |
        v
Wazuh rules 100503 / 100504
```

The exporter reads persisted audit results from the two Aegis constraint kinds, validates snapshot completeness and tracks changes between observations. The Wazuh rules and localfile configuration are included in the delivery package.

## 4. SOAR webhook and Kubernetes response engineering

I extended the FastAPI service with a security-focused request and response workflow.

### 4.1 Request authentication and validation

The webhook implements:

- HMAC-SHA256 request authentication.
- Timestamp validation to reject stale requests.
- Request-size restrictions.
- Explicit allowlists for the Wazuh agent, rule IDs and Kubernetes namespace.
- Validation of the response target before any Kubernetes mutation.
- Fail-closed behavior when required security prerequisites are not attested.

The accepted response rules are 100501 and 100502, scoped to the configured lab agent and approved namespace. These controls reduce the chance that an arbitrary or replayed request can trigger a Kubernetes action.

### 4.2 Kubernetes identity and permissions

The service uses a dedicated Kubernetes ServiceAccount and scoped RBAC rather than a cluster-admin identity. The manifests define the service-side permissions and the namespace resources required by the response workflow.

### 4.3 Quarantine and workload safeguards

The response logic applies quarantine labels and audit annotations to eligible Pods. It separately changes endpoint eligibility so Services configured with the required selector can remove quarantined workloads from their EndpointSlices.

Before changing a workload, the service checks for the named quarantine NetworkPolicy. The policy must select the quarantine label, include both ingress and egress policy types and contain no allow rules. The service also checks the dataplane-attestation setting before enabling destructive response.

Controller-managed Pods are deliberately excluded from the deletion path. Deleting a controller-owned Pod without updating its workload template can cause the controller to recreate it without the quarantine state. Such Pods are quarantined and preserved. Immediate zero-second deletion is limited to configured high-risk rule 100502 and unmanaged response-target Pods.

The current configuration keeps `AEGIS_NETWORK_POLICY_ENFORCEMENT_CONFIRMED=false`. This is an intentional safety control until live ingress, egress and EndpointSlice tests establish the expected dataplane behavior.

### 4.4 Application validation

The SOAR application suite passed **16 tests** in consolidated code validation run [44142985557](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/44142985557). The tests exercise the implemented request and response behavior at the application/test boundary. They are not represented as proof of live Kubernetes containment.

## 5. Wazuh Active Response and reliable delivery

I added the Wazuh Active Response integration script for the configured agent and detection rules 100501/100502. Rather than relying on a single synchronous network request, the script writes accepted alerts to a durable local spool.

A separate dispatcher reads the queued events, retries delivery and signs requests with the shared HMAC key. This separates alert capture from webhook availability and provides a recoverable delivery path during tunnel or service interruptions.

The private connectivity design uses:

- A loopback-only listener on the Wazuh Manager.
- A reverse SSH tunnel initiated from Kali.
- A local Kubernetes port-forward to the SOAR service.
- A shared high-entropy HMAC key stored outside source control.

The Active Response and dispatcher scripts are included in the repository and passed Python compilation in CI. Wazuh configuration fragments are included and passed XML parsing. The scripts have not yet been installed and exercised on a restored live Manager, so this report does not claim live alert delivery.

## 6. Gatekeeper audit exporter and telemetry engineering

I developed `collectors/gatekeeper_audit_exporter.py` to turn Gatekeeper's persisted audit status into structured events suitable for downstream monitoring.

### 6.1 Supported constraints and event model

The exporter reads:

- `K8sAegisContainerSecurity`
- `K8sAegisImageIntegrity`

It validates the constraint status fields, including `status.auditTimestamp`, `status.totalViolations` and `status.violations`, before treating a snapshot as suitable for state transitions. Findings are normalized into JSONL records. The exporter emits active and resolved transitions so that a violation disappearing from a later complete audit can be represented explicitly.

### 6.2 State integrity and reliability controls

The implementation includes:

- Persistent checkpoint state at `/var/lib/aegis-gatekeeper-exporter/state.json`.
- Atomic checkpoint replacement and filesystem synchronization.
- Restrictive state-file permissions.
- Append-only JSONL output with `O_NOFOLLOW`, synchronization and controlled file permissions.
- Duplicate replay protection.
- Active-to-resolved transition tracking.
- Validation that prevents incomplete, malformed or truncated snapshots from falsely resolving previously observed findings.

Gatekeeper can limit the number of violation details retained in constraint status. The exporter therefore compares the reported total with the returned violation records and avoids inferring that omitted findings have been resolved when a snapshot is incomplete.

### 6.3 Testing and live API evidence

The exporter suite passed **12 tests** in CI run [44142985557](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/44142985557) and in local regression. The tests cover normalization, checkpoint persistence, duplicate replay, resolution transitions, truncated snapshots and failure handling.

Separately, I retrieved actual audit snapshots from both Phase 4 constraints in the dedicated lab. The snapshots contained audit timestamps and reported zero violations at the recorded observation. This verifies that Gatekeeper audit status was available through the Kubernetes API. The exporter systemd service and downstream Wazuh JSONL ingestion are deployment-stage work.

## 7. Dedicated Kubernetes lab, Calico and unified policy enforcement

### 7.1 Dedicated Phase 4 environment

I established a separate Kind environment to isolate Phase 4 testing from the earlier Phase 3 cluster:

| Component | Phase 4 lab |
|---|---|
| Kubernetes | v1.37.0 |
| Container runtime | containerd 2.3.4 |
| CNI | Calico 3.33.0 |
| Policy engine | Gatekeeper 3.23.1 |
| Cluster context | `kind-aegis-phase4-lab` |

The lab build required recovery work during Calico installation, including investigation of webhook service refusal, readiness and liveness timeouts, Pod sandbox recreation and TLS/readiness issues. The cluster was subsequently brought to a Ready state, with the principal Calico components available and Gatekeeper controller and audit deployments healthy.

This work established the dedicated environment used for the subsequent Phase 4 policy installation and admission tests. Calico policy dataplane isolation is assessed separately from CNI installation health.

### 7.2 Unified PSS and Gatekeeper policy

I created the `aegis-unified-policy` namespace with native Pod Security Admission set to `restricted:v1.33`. The namespace is protected by both Aegis constraints:

- `aegis-unified-container-security`
- `aegis-unified-image-integrity`

The Phase 2 ConstraintTemplates were reused as the canonical policy definitions. The Phase 4 constraints were scoped to the unified policy namespace, keeping the earlier Phase 3 and Phase 2 test environments separate.

### 7.3 Admission verification

The admission matrix exercised four meaningful outcomes:

| Workload fixture | Expected enforcement | Observed result |
|---|---|---|
| Secure non-root Pod, read-only root filesystem and digest-pinned image | Admitted | Admitted |
| Privileged Pod | Native restricted PSS denial | Denied by Pod Security Admission |
| PSS-compatible Pod with writable root filesystem | Gatekeeper container-security denial | Denied by Gatekeeper validation webhook |
| PSS-compatible Pod with tag-only image | Gatekeeper image-integrity denial | Denied by Gatekeeper validation webhook |

The matrix passed in CI against Kubernetes 1.33.12 and Gatekeeper 3.23.1. I then repeated the positive and negative server-side dry-run admission checks in the dedicated Phase 4 lab running Kubernetes 1.37.0 and Gatekeeper 3.23.1.

Both constraints reported `enforced: true` across the Gatekeeper pods. Audit snapshots were retrieved for both constraints with valid timestamps and zero violations at the recorded observation. The positive fixture used a syntactically valid placeholder digest and was submitted only through server-side dry-run; it was not deployed or pulled as a workload image.

These results provide direct evidence of the combined native PSS and Gatekeeper admission behavior in the dedicated Phase 4 lab.

## 8. Falco rule engineering and declarative delivery

I added a Phase 4 Falco rule source and ConfigMap generator. The write rule retains the existing Aegis rule identity and extends its scope to the Phase 4 response-target workload. The built-in Falco `Terminal shell in container` rule remains the source for Wazuh rule 100502.

The repository also includes declarative Kubernetes resources for:

- The `aegis-unified-policy` and `aegis-soar-system` namespaces.
- Namespace-scoped SOAR RBAC and ServiceAccount resources.
- Quarantine NetworkPolicies.
- The SOAR Deployment and service configuration.
- Unified Gatekeeper constraints.
- Falco rule ConfigMap generation.

Falco 0.45.0 accepted the Phase 4 rule during CI validation, and the Falco ConfigMap Kustomize build passed. The Kubernetes Kustomize build also passed. The source-controlled Falco ConfigMap has not yet been reconciled into the live Helm-managed release. That reconciliation must preserve the existing chart configuration and avoid loading a duplicate copy of the Aegis write rule.

The Phase 4 deployed Falco driver mode was not captured. The report therefore records rule validation and declarative delivery, but does not claim that Phase 4 runtime events were proven to be eBPF-backed.

## 9. Container hardening and software supply-chain security

The SOAR image work was a substantial delivery stream in its own right.

### 9.1 Base-image investigation and remediation

The first complete Trivy assessment identified **47 HIGH OS-package findings across 11 CVEs** in the Debian slim base. Fixed Trixie package versions were not available at the time of the assessment. I replaced that base with an immutable `python:3.12.16-alpine3.24` digest and adjusted the build so pip was upgraded for dependency installation, then removed along with its bundled installer from the final runtime image.

The pinned base used for the manifest-approved build was:

```text
python:3.12.16-alpine3.24@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89
```

### 9.2 Runtime hardening

The published image runs as UID/GID 10001 and is tested with:

- A read-only root filesystem.
- All Linux capabilities dropped.
- No-new-privileges enabled.
- Health and readiness endpoints.
- Fail-closed readiness when the HMAC secret is absent.

The health endpoint returned HTTP 200 on both architectures. The readiness endpoint returned the expected HTTP 503 when the HMAC secret was not provisioned. This demonstrated that the image did not report itself ready without a required authentication dependency.

### 9.3 Multi-architecture builds and scanning

The image was built and published for `linux/amd64` and `linux/arm64`. Trivy 0.76.2 scanned all severities across vulnerability, misconfiguration and secret categories. The manifest-approved image reports contained zero findings for both architectures.

The approved immutable image digest pinned in the Kubernetes Deployment is:

```text
ghcr.io/serra-valle/aegis-soar@sha256:7cfb86923d5110aeec3241641fee94eef9324a7bfeaaa751d50fb6f4f856f0dc
```

The complete per-architecture reports are retained in [workflow artifact 14351327524](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/44134158272).

### 9.4 SBOM and signed provenance

The build generated a BuildKit SBOM and Sigstore-signed provenance. The attestation was published to [GitHub](https://github.com/serra-valle/Cybersecurity-portfolio/attestations/68730154), GHCR and the [Rekor transparency log](https://search.sigstore.dev?logIndex=3949778857).

The consolidated-head pipeline also produced independently verified image builds and attestations. The additional digests were:

| CI run | Image digest | Evidence |
|---|---|---|
| 44137127343 | `sha256:6993a33a9e0873f5b7b37a255740e6e7d0dbc7e3286b85725d8ad7fb4c2cc05d` | [Artifact 14352298031](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/44137127343/artifacts/14352298031), [attestation 68736375](https://github.com/serra-valle/Cybersecurity-portfolio/attestations/68736375) |
| 44142985557 | `sha256:8d4569811f1d44d0aa7b0d797c17960dbd5846e5a0c4a0836e4ad738bcfa5662` | [Artifact 14355492115](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/44142985557/artifacts/14355492115), [attestation 68748948](https://github.com/serra-valle/Cybersecurity-portfolio/attestations/68748948) |

These are separate verified rebuilds. The Deployment remains pinned to the earlier manifest-approved digest. The later digests were not silently promoted into the manifest.

## 10. CI/CD, regression and validation record

The project uses CI to validate the application, policy, deployment configuration and image supply chain. The checks are intentionally separated so that a successful source test is not confused with a successful image build or live cluster acceptance.

### 10.1 Consolidated code validation

The latest consolidated source validation, [run 44142985557](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/44142985557), passed:

| Validation | Result |
|---|---|
| SOAR application unit tests | 16 passed |
| Gatekeeper exporter unit tests | 12 passed |
| Python compilation of application, collector and Active Response scripts | Passed |
| Wazuh XML configuration parsing | Passed |
| OPA 0.62.1 regression suite | 10/10 passed |
| Falco 0.45.0 rule validation | Passed |
| Kubernetes Kustomize build | Passed |
| Falco ConfigMap Kustomize build | Passed |
| Disposable Kubernetes 1.33.12 / Gatekeeper 3.23.1 admission matrix | All four expected outcomes passed |

The associated [PR validation run 44143002713](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/44143002713) and [policy regression run 44143002456](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/44143002456) were also recorded as passing in the delivery status.

### 10.2 Image and consolidated-head pipeline history

| Run | Purpose and outcome |
|---|---|
| [43828411989](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/43828411989) | Historical source and policy baseline; Python, OPA, Falco, Kustomize and admission checks passed |
| [44134158272](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/44134158272) | Manifest-pinned AMD64/ARM64 image build, hardened runtime smoke tests, zero-finding Trivy reports, SBOM and signed provenance |
| [44136227347](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/44136227347) | Initial consolidated image attempt exposed an ARM64 startup-timeout issue in the 30-second smoke-test window |
| [44137127343](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/44137127343) | Consolidated-head push pipeline passed; multi-architecture smoke tests, zero-finding scans and signed provenance |
| [44137140455](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/44137140455) | Phase 4 pull-request validation passed |
| [44137140567](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/44137140567) | Policy regression passed |
| [44138533504](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/44138533504) | Subsequent consolidated-head image validation passed; reports retained as artifact 14353566620 and attestation 68739365 |
| [44142985557](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/44142985557) | Latest consolidated source validation and multi-architecture image pipeline; 16 SOAR tests, 12 exporter tests and 10/10 OPA tests passed |
| [44143002713](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/44143002713) | Phase 4 PR validation |
| [44143002456](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/44143002456) | Policy regression |

The first consolidated image attempt failed because the ARM64 health endpoint did not respond within the original 30-second startup window. I increased the startup deadline to 120 seconds and added container-state, exit-code, log and health-response diagnostics. The subsequent consolidated build passed. The earlier timeout was treated as an environment/startup sensitivity under emulation, not as a confirmed application defect.

### 10.3 Validation boundaries

The evidence in this report falls into four categories:

- **Source and unit validation:** application, exporter, policy and configuration behavior tested in CI.
- **Artifact validation:** multi-architecture image builds, hardened runtime smoke tests, vulnerability scanning, SBOM and provenance.
- **Kubernetes lab validation:** Gatekeeper installation, constraint enforcement, server-side dry-run admission decisions and audit snapshot retrieval.
- **Operational integration:** live Wazuh event ingestion, deployed exporter service, SOAR rollout and genuine containment. These require restored Wazuh infrastructure and the remaining runtime acceptance procedures.

This separation preserves the value of each completed test while keeping the final operational claims accurate.

## 11. Engineering challenges, decisions and improvements

Several engineering decisions materially improved the security and reliability of the delivery.

| Area | Engineering challenge | Decision or improvement |
|---|---|---|
| Response safety | A quarantine label alone does not prove network isolation | Require a named deny-all policy, correct selector and both ingress/egress policy types; keep dataplane attestation false until tested |
| Kubernetes controllers | Deleting a controller-owned Pod can cause an unquarantined replacement | Preserve controller-managed Pods and limit immediate deletion to eligible unmanaged targets |
| Service routing | A quarantined Pod may remain eligible for Service traffic | Add a separate endpoint-eligibility label and explicit Service selector contract |
| Alert delivery | A transient tunnel or webhook failure can lose a synchronous event | Add durable local spooling, a separate retrying dispatcher and signed requests |
| Audit state | A partial Gatekeeper snapshot can make active findings appear resolved | Validate audit timestamps and violation totals; detect truncation; preserve state and avoid false resolution |
| Checkpoint integrity | A process restart or corrupted state can cause replay or incorrect transitions | Use atomic state replacement, filesystem synchronization, restrictive permissions and explicit failure handling |
| Container vulnerabilities | Initial Debian slim image exposed 47 HIGH package findings | Move to an immutable Alpine base digest, update build dependencies and remove pip from the final runtime |
| ARM64 smoke testing | Emulated startup exceeded the initial 30-second deadline | Increase the deadline to 120 seconds and capture diagnostics on failure |
| Policy scope | Phase 4 needed unified controls without disrupting earlier work | Reuse canonical Phase 2 templates and scope the new constraints to the dedicated unified namespace |
| Evidence quality | CI success can be mistaken for live deployment | Separate source, artifact, lab and operational acceptance evidence throughout the report |

The dedicated Phase 4 lab also required CNI installation recovery before policy testing could proceed. That investigation and recovery enabled the subsequent Gatekeeper and admission work in the dedicated environment.

## 12. Delivery artifacts

The Phase 4 branch contains the implementation and supporting material for the workstreams described above, including:

- FastAPI SOAR application and application tests.
- Wazuh Active Response and dispatcher scripts.
- Wazuh configuration fragments and custom Gatekeeper rules 100503/100504.
- Gatekeeper audit exporter, dependencies and tests.
- Kubernetes namespaces, RBAC, ServiceAccount, NetworkPolicies, Deployment and service resources.
- Unified Gatekeeper constraint resources reusing the established Phase 2 templates.
- Falco Phase 4 rule source and ConfigMap generator.
- CI workflows for application, policy, admission and image validation.
- Deployment runbook, acceptance matrix, delivery status and image security evidence.

The supporting documents are maintained alongside the implementation so that another engineer can understand the architecture, reproduce the checks and continue the deployment without relying on undocumented assumptions.

## 13. Operational integration and next stage

The engineering package, automated validation and dedicated-lab policy checks are in place. The next stage connects these components to operational infrastructure and completes the remaining runtime acceptance.

The AWS-hosted Wazuh Manager is unavailable because the AWS account is closed. The Active Response scripts, dispatcher, Gatekeeper rules and agent collection configuration therefore have not been installed and exercised against that Manager. The Gatekeeper exporter has passed its test suite and live audit snapshots have been retrieved, but its service and Wazuh JSONL ingestion still need deployment.

The dedicated Phase 4 lab has Calico installed and Gatekeeper admission enforcement verified. A controlled ingress/egress baseline and quarantine test is still required to demonstrate dataplane isolation and EndpointSlice removal. The SOAR Deployment has not been rolled out, and no genuine end-to-end containment event or containment log is claimed. The Falco rule passes syntax validation and its ConfigMap builds, while reconciliation into the live Helm release and capture of the Phase 4 driver mode remain deployment tasks.

For safety, `AEGIS_NETWORK_POLICY_ENFORCEMENT_CONFIRMED=false` must remain in place until the live network-isolation and EndpointSlice checks pass. Destructive response must remain disabled until its corresponding safeguards and live acceptance tests are complete.

These are integration and operational acceptance tasks for the next stage. They do not negate the completed application engineering, automated test coverage, image security work, supply-chain attestations or live Gatekeeper policy enforcement already documented in this report.

## 14. Submission and repository status

I opened [draft PR #2](https://github.com/serra-valle/Cybersecurity-portfolio/pull/2) against the Phase 3 branch. It is intentionally stacked on [Phase 3 PR #1](https://github.com/serra-valle/Cybersecurity-portfolio/pull/1), so Phase 3 should be merged first. Phase 4 can then be retargeted to `main`.

The assigned target date was 13 November 2026. This report is dated 17 November 2026 and records the work and validation evidence available at that point. It does not backdate implementation, deployment or acceptance.

## 15. Final assessment

Phase 4 delivered a substantial security engineering package across Kubernetes response automation, Wazuh integration design, Gatekeeper audit telemetry, policy-as-code, Falco configuration, container security and software supply-chain assurance.

The strongest verified outcomes are:

- A hardened SOAR application with authenticated requests, strict input controls, Kubernetes RBAC integration and guarded response logic.
- Durable Wazuh alert handling and a private delivery architecture.
- A Gatekeeper audit exporter with persistent checkpoints, replay protection, truncation handling and active/resolved event tracking.
- A dedicated Kubernetes lab with Calico and Gatekeeper installed, unified PSS and Aegis constraints applied, and positive and negative admission outcomes verified.
- A multi-architecture SOAR image with hardened runtime settings, zero findings in the manifest-approved Trivy reports, an SBOM and signed provenance.
- Repeatable CI validation covering application tests, exporter tests, OPA, Falco, Wazuh XML, Kustomize, admission behavior and image supply-chain checks.

The work has moved Aegis beyond policy authoring into a connected security engineering design with tested application components, repeatable controls, a verified image supply chain and live policy admission evidence. The remaining stage is to restore the external Wazuh dependency, deploy the integration services and capture the controlled end-to-end containment evidence.

**Overall assessment:** substantial Phase 4 engineering delivery with strong automated validation, verified container supply-chain controls and live Gatekeeper policy enforcement in the dedicated lab. Operational SOAR acceptance is the next integration stage.
