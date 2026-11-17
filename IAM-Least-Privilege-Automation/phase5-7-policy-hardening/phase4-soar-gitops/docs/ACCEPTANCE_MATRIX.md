# Aegis Phase 4 Acceptance Matrix

This matrix defines the expected evidence. A source file, unit test, CI workflow definition or successful Kubernetes API response is not a substitute for live runtime evidence.

| ID | Requirement | Positive condition | Negative condition | Current evidence state |
|---|---|---|---|---|
| AR-01 | Webhook authentication | Valid HMAC and current timestamp accepted | Missing, stale or tampered signature rejected | Unit tests passed in CI run 44137127343 |
| AR-02 | Alert allowlisting | Agent \`kali-aegis-lab\`, rule 100501/100502 and approved namespace accepted | Other agent, rule or namespace ignored | Source implementation present; endpoint integration test pending |
| AR-03 | Quarantine preconditions | Explicit response-target Pod and verified deny-all NetworkPolicy | Missing policy, wrong selector, missing policy type or unattested dataplane blocks mutation | Mocked response tests passed in CI run 44137127343; live test pending |
| AR-04 | Pod quarantine | Quarantine label and audit annotations applied | Unlabelled Pod remains unchanged | Mocked response test passed in CI run 44137127343; live test pending |
| AR-05 | Service endpoint exclusion | Endpoint label changes to false and configured Service selector removes the Pod | A Service without the required selector is not assumed to exclude the Pod | Code and selector contract present; EndpointSlice test pending |
| AR-06 | Network isolation | Calico blocks ingress and egress to/from quarantined Pod | Any successful packet path fails acceptance | Not tested; attestation remains false |
| AR-07 | High-risk eviction | Rule 100502 deletes an unmanaged target Pod with zero-second grace | Controller-managed Pod is quarantined and not deleted | Mocked response tests passed in CI run 44137127343; live test pending |
| GT-01 | Gatekeeper audit export | Persisted container-security violations become JSONL events | Incomplete or malformed violation records are ignored | 12 exporter tests passed; live Gatekeeper audit snapshot retrieved; exporter service and JSONL delivery not deployed |
| GT-02 | Gatekeeper image audit | Persisted image-integrity violations become JSONL events | Missing digest violation is not silently dropped | 12 exporter tests passed; live image-integrity constraint audit snapshot retrieved; exporter service and JSONL delivery not deployed |
| GT-03 | Audit snapshot integrity and restart safety | Completed, untruncated audit snapshots produce active/resolved transitions; checkpoint survives service restart | Missing audit timestamp, malformed/truncated status or corrupt checkpoint must not clear prior active findings | 12 collector tests passed in CI run 44142985557 and locally; Gatekeeper audit timestamps and totals observed live; exporter restart test not run |
| WZ-01 | Wazuh rule 100503 | Active container-security violation creates manager alert | Resolved event does not trigger active-violation rule | Rule source and XML validation present; manager analysis and ingestion blocked because AWS-hosted Wazuh Manager is unavailable |
| WZ-02 | Wazuh rule 100504 | Active image-integrity violation creates manager alert | Resolved event does not trigger active-violation rule | Rule source and XML validation present; manager analysis and ingestion blocked because AWS-hosted Wazuh Manager is unavailable |
| PSS-01 | Unified positive Pod | Restricted PSS and both Gatekeeper constraints admit a secure, digest-pinned Pod | N/A | Passed in CI and Phase 4 lab server-side dry run |
| PSS-02 | Native PSS denial | Restricted PSS rejects privileged Pod | Privileged Pod must not be admitted | Passed in CI and Phase 4 lab; native Pod Security Admission denied the privileged fixture |
| PSS-03 | Gatekeeper container security | PSS-compatible Pod with writable root filesystem is denied by Gatekeeper | Writable root filesystem must not be admitted | Passed in CI and Phase 4 lab; Gatekeeper validation webhook denied the fixture |
| PSS-04 | Gatekeeper image integrity | PSS-compatible image without explicit SHA-256 digest is denied | Tag-only image must not be admitted | Passed in CI and Phase 4 lab; Gatekeeper validation webhook denied the fixture |
| GI-01 | Falco rule validation | \`falco --validate <rules-file>\` accepts the Phase 4 write rule | Invalid rule syntax fails CI | Falco 0.45.0 validation passed in CI run 44137127343 |
| GI-02 | OPA regression | Existing Aegis Rego unit suite passes | Any regression fails CI | OPA 0.62.1 regression passed 10/10 in CI run 44137127343 |
| GI-03 | Deployment artifact validation | Python source compiles and Wazuh XML fragments parse | Syntax or XML errors fail CI | Passed in CI run 44137127343 |
| IMG-01 | Immutable multi-architecture SOAR image | GHCR image is pinned by digest for AMD64 and ARM64; base image digest, SBOM and signed provenance are recorded | Mutable image tag or failed build/scan/attestation blocks promotion | Passed in CI run 44134158272; digest pinned in Deployment manifest; not deployed |
| IMG-02 | Runtime container hardening | Both architectures start as UID/GID 10001 with read-only root filesystem, all capabilities dropped and no-new-privileges | Health endpoint failure or unexpected readiness state fails smoke test | Passed in CI run 44134158272; /healthz returned 200 and /readyz returned expected 503 without HMAC secret |
| IMG-03 | Vulnerability, misconfiguration and secret scanning | Trivy scans all severities on both architectures and produces zero findings | Fixable HIGH/CRITICAL findings fail the workflow; other findings require review before promotion | Zero vulnerability, misconfiguration and secret findings on AMD64 and ARM64 in CI run 44134158272; reports retained as artifact 14351327524 |
| IMG-04 | Consolidated-head image rebuild and smoke-test resilience | Current head builds for AMD64 and ARM64, passes hardened runtime smoke tests, full Trivy scans and signed provenance | Startup timeout or any scan/attestation failure blocks image approval | Passed in CI run 44138533504; zero vulnerability, misconfiguration and secret findings on both architectures; reports artifact 14353566620; attestation 68739365; additional digest not promoted into Deployment manifest |
| EBPF-01 | Falco driver mode | Live Falco reports the intended eBPF driver and runtime events are captured | A different or unverified driver must not be described as eBPF | Not verified in Phase 4 |

The positive Pod fixture uses a syntactically valid placeholder digest and is only submitted with Kubernetes server-side dry-run. It is not a pullable image and must not be deployed.


## Recorded Phase 4 lab evidence

The dedicated `kind-aegis-phase4-lab` runs Kubernetes v1.37.0 with Calico 3.33.0 and Gatekeeper 3.23.1. Both Aegis ConstraintTemplates compiled and both constraints were enforced by the Gatekeeper admission webhook in `aegis-unified-policy`.

Server-side dry-run results: the secure Pod was admitted; the writable-root-filesystem Pod was denied by `aegis-unified-container-security`; the tag-only image Pod was denied by `aegis-unified-image-integrity`; and the privileged Pod was denied by native Pod Security Admission. Gatekeeper audit snapshots were retrieved for both constraints with valid audit timestamps and zero violations at the recorded observation.

This verifies admission and audit snapshot availability only. It does not establish exporter service deployment, Wazuh ingestion, SOAR containment, Calico traffic isolation or EndpointSlice removal. The AWS-hosted Wazuh Manager is unavailable because the AWS account is closed.

## Required live network-isolation procedure

Before setting \`AEGIS_NETWORK_POLICY_ENFORCEMENT_CONFIRMED=true\`:

1. Create a controlled source Pod and a controlled destination Pod in the target namespace.
2. Prove the test path succeeds before quarantine, recording the exact source/destination and protocol.
3. Label only the destination Pod as an approved response target and configure its Service selector with \`aegis.security/endpoint-enabled=true\`.
4. Apply the quarantine label and endpoint-disabled label through the SOAR response path.
5. Verify the Pod is absent from the Service's EndpointSlices.
6. Prove ingress and egress traffic are both denied by the Calico dataplane.
7. Capture the relevant NetworkPolicy, Pod labels, EndpointSlice state, and failed connection output with timestamps.
8. Repeat after a fresh Pod creation to check that the workload controller does not recreate an unquarantined replacement.

Until all applicable checks pass, the SOAR readiness endpoint must remain unready and automated containment must not be enabled.
