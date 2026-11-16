# Aegis Phase 4 Acceptance Matrix

This matrix defines the expected evidence. A source file, unit test, CI workflow definition or successful Kubernetes API response is not a substitute for live runtime evidence.

| ID | Requirement | Positive condition | Negative condition | Current evidence state |
|---|---|---|---|---|
| AR-01 | Webhook authentication | Valid HMAC and current timestamp accepted | Missing, stale or tampered signature rejected | Unit tests authored; CI run pending |
| AR-02 | Alert allowlisting | Agent \`kali-aegis-lab\`, rule 100501/100502 and approved namespace accepted | Other agent, rule or namespace ignored | Source implementation present; endpoint integration test pending |
| AR-03 | Quarantine preconditions | Explicit response-target Pod and verified deny-all NetworkPolicy | Missing policy, wrong selector, missing policy type or unattested dataplane blocks mutation | Mocked response tests authored; live test pending |
| AR-04 | Pod quarantine | Quarantine label and audit annotations applied | Unlabelled Pod remains unchanged | Mocked response test authored; live test pending |
| AR-05 | Service endpoint exclusion | Endpoint label changes to false and configured Service selector removes the Pod | A Service without the required selector is not assumed to exclude the Pod | Code and selector contract present; EndpointSlice test pending |
| AR-06 | Network isolation | Calico blocks ingress and egress to/from quarantined Pod | Any successful packet path fails acceptance | Not tested; attestation remains false |
| AR-07 | High-risk eviction | Rule 100502 deletes an unmanaged target Pod with zero-second grace | Controller-managed Pod is quarantined and not deleted | Mocked response tests authored; live test pending |
| GT-01 | Gatekeeper audit export | Persisted container-security violations become JSONL events | Incomplete or malformed violation records are ignored | Normalization tests authored; live API polling pending |
| GT-02 | Gatekeeper image audit | Persisted image-integrity violations become JSONL events | Missing digest violation is not silently dropped | Normalization tests authored; live API polling pending |
| WZ-01 | Wazuh rule 100503 | Active container-security violation creates manager alert | Resolved event does not trigger active-violation rule | Rule source present; manager analysis test pending |
| WZ-02 | Wazuh rule 100504 | Active image-integrity violation creates manager alert | Resolved event does not trigger active-violation rule | Rule source present; manager analysis test pending |
| PSS-01 | Unified positive Pod | Restricted PSS and both Gatekeeper constraints admit a secure, digest-pinned Pod | N/A | CI fixture and workflow authored; run pending |
| PSS-02 | Native PSS denial | Restricted PSS rejects privileged Pod | Privileged Pod must not be admitted | CI fixture and workflow authored; run pending |
| PSS-03 | Gatekeeper container security | PSS-compatible Pod with writable root filesystem is denied by Gatekeeper | Writable root filesystem must not be admitted | CI fixture and workflow authored; run pending |
| PSS-04 | Gatekeeper image integrity | PSS-compatible image without explicit SHA-256 digest is denied | Tag-only image must not be admitted | CI fixture and workflow authored; run pending |
| GI-01 | Falco rule validation | \`falco --validate\` accepts the Phase 4 write rule | Invalid rule syntax fails CI | CI workflow authored; run pending |
| GI-02 | OPA regression | Existing Aegis Rego unit suite passes | Any regression fails CI | CI workflow authored; run pending |

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
