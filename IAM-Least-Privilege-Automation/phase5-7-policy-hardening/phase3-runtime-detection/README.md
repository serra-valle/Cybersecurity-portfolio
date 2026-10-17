# Aegis Phase 3: Runtime Detection and Pod Security Validation

**Validation date:** 17 October 2026
**Status:** Falco runtime detection, isolated PSS validation, Gatekeeper admission enforcement, and Falco-to-Wazuh ingestion with a custom alert for a controlled filesystem-write event demonstrated. A fresh event from the active test Pod matched Wazuh manager rule `100501` (level `8`). Sanitized Falco collector and Wazuh manager alert excerpts are committed. Shell-event forwarding and Wazuh indexer/dashboard visibility remain unverified.

## Summary

This phase adds runtime threat detection with Falco and validates Kubernetes Pod Security Standards (PSS) in an isolated test namespace.

Falco ran on the Kind cluster using modern eBPF. Its DaemonSet was available, and the Falco Pod was running with both containers ready and no restarts at the time of inspection.

Controlled runtime testing generated a custom alert for a write below `/etc` by the Aegis test Pod. A shell-execution detection was also observed during earlier controlled testing. Forwarding of that shell event through Wazuh has not yet been verified.

Native Kubernetes Pod Security Admission was tested with the `restricted:v1.33` profile. The compliant Pod was admitted and reached Ready state. Five negative test cases were rejected. The corrected privileged-container test was required because the first manifest combined incompatible security settings and did not establish a PSS denial.

## Validation results

| Test | Result |
|---|---|
| Compliant Pod server-side admission | Pass |
| Compliant Pod reaches Ready | Pass |
| Privilege escalation enabled | Rejected by PSS |
| Privileged container | Rejected by PSS |
| `runAsNonRoot: false` | Rejected by PSS |
| Missing required seccomp profile | Rejected by PSS |
| Missing `capabilities.drop: ["ALL"]` | Rejected by PSS |
| Gatekeeper compliant Pod server-side dry-run | Pass |
| Gatekeeper noncompliant Pod server-side dry-run | Rejected with four expected findings |
| Gatekeeper audit cycles | Completed in captured logs |
| Gatekeeper detection of persisted violations | Not demonstrated |

The authoritative test output is in `evidence/pss-admission-validation.txt`. Individual negative-test responses are retained beside it.

## Policy boundary

The Gatekeeper constraints are scoped to `aegis-policy-test`. Their enforcement configuration uses `enforcementAction: scoped`, with `deny` configured at `validation.gatekeeper.sh` and `audit.gatekeeper.sh`. The PSS validation remains isolated in `aegis-pss-test`; combined PSS and Gatekeeper enforcement has not yet been tested in the same namespace.

PSS provides baseline restrictions including non-root execution, disabling privilege escalation, dropping Linux capabilities, requiring an acceptable seccomp profile, and prohibiting privileged containers.

Gatekeeper remains necessary for Aegis-specific requirements not provided by PSS `restricted`, including:

- Requiring `readOnlyRootFilesystem: true`.
- Requiring explicit SHA-256 image digests.
- Prohibiting the `:latest` image tag.

There is also a policy difference to resolve before any consolidation: the existing Gatekeeper template checks `runAsNonRoot` on each container's own security context, while PSS can accept the setting at Pod level. No existing Gatekeeper policy was removed or weakened in this phase.

## Observed limitations and tuning work

- Falco reported that it could not attach TOCTOU mitigation programs for the `creat` and `open` syscalls because the expected tracepoints were unavailable. Detection continues, but the affected mitigation may not work.
- Falco emitted critical `mount` execution alerts during normal container startup. These require investigation and careful tuning before suppressing them.
- Host sensitive-file alerts were observed for an XFCE screensaver process reading PAM configuration files. Validate process context and rule behavior before deciding whether exclusions are appropriate.

These observations are documented as limitations and tuning work, not as confirmed malicious activity.

## SIEM integration status

A fresh controlled Falco filesystem-write event from the active test Pod was successfully ingested by the existing Wazuh deployment and matched a custom manager rule on 17 October 2026.

### Demonstrated event path

1. Falco detected a controlled write below `/etc/aegis-test` inside the `falco-runtime-test-active` Pod. This was not a write to the Kubernetes node's host `/etc`. The rule was updated to match the active test Pod while preserving the original test Pod match.
2. The Kali forwarder appended Falco JSON to `/var/log/aegis/falco-events.jsonl`.
3. The Wazuh agent `kali-aegis-lab` monitored that file using JSON log collection and forwarded the event to the manager.
4. Wazuh manager rule `100501`, level `8`, matched the event and generated an alert in `/var/ossec/logs/alerts/alerts.json`. The alert's source location was `/var/log/aegis/falco-events.jsonl`.

### Fresh verification result (17 October 2026)

The latest controlled write event was observed in the manager alert output:

- Falco event timestamp: `2026-10-17T10:18:02.097373391Z`
- Wazuh manager alert timestamp: `2026-10-17T10:18:02.871+0000`
- Calculated event-to-alert timestamp difference: `773.626609 ms` (approximately `774 ms`)
- Wazuh rule: `100501`, level `8`
- File: `/etc/aegis-test/runtime-proof.txt`
- Pod/namespace: `falco-runtime-test-active` / `aegis-policy-test`
- Runtime UID: `65532`

This is one successful observed event, not a latency benchmark or guarantee. Sanitized normalized excerpts from the actual collector query and manager alert query are stored at `evidence/wazuh-integration/falco-event-sanitized.json` and `evidence/wazuh-integration/wazuh-alert-sanitized.json`. Raw host logs and unrelated container identifiers are not committed.

The tested deployment used Wazuh `4.14.9-1` on the Ubuntu manager and the Kali agent. This demonstrates end-to-end ingestion and rule matching for the specific controlled filesystem-write event. It does not establish comprehensive runtime coverage or production alerting readiness.

### Remaining SIEM validation

- **Falco shell-event forwarding:** not yet verified end to end. Falco detection alone does not prove Wazuh ingestion.
- **Indexer/dashboard visibility:** not yet verified. Manager-side connector logs included warnings about missing keystore credentials and retries for `wazuh-states-*`; these warnings did not prevent the confirmed manager alert, but indexing and dashboard presentation still need separate validation.
- **Evidence packaging:** sanitized collector-event and manager-alert excerpts are committed. UTC clock state, service/configuration captures, JSONL validation counts, and the final checksum manifest still need to be captured and reviewed before the portfolio evidence package is complete.

The capture procedure and evidence boundary are documented in `evidence/wazuh-integration/README.md`.

## Gatekeeper admission enforcement validation

The two Aegis Gatekeeper constraints enforce container security and image
integrity in the `aegis-policy-test` namespace.

### Admission tests

A compliant Pod passed server-side dry-run admission with exit code `0`.
The manifest used a digest-pinned BusyBox image and configured non-root
execution, a read-only root filesystem, disabled privilege escalation,
dropped all Linux capabilities, and RuntimeDefault seccomp.

A deliberately noncompliant Pod was rejected during server-side dry-run
with exit code `1`. The captured response contained four findings:

- `allowPrivilegeEscalation` must be `false`.
- `readOnlyRootFilesystem` must be `true`.
- `runAsNonRoot` must be `true`.
- The image must be pinned with an explicit SHA-256 digest.

Neither test required creating a persistent test Pod.

### Constraint and audit status

Both constraints reported `enforced: true` for their audit and webhook
controller status entries, with `observedGeneration: 2`. Their latest
captured audit timestamp was `2026-10-15T22:23:12Z`, and both reported
zero violations.

Repeated audit cycles completed in the captured logs. The previous
`K8sNativeValidation engine is missing` / `vap.k8s.io` warning was not
found in the captured log sample. This observation applies to that sample
and does not guarantee the warning cannot recur.

### Audit validation limitation

Detection of a pre-existing noncompliant object by the audit process has
not been demonstrated. The deliberately noncompliant Pod was rejected
during admission and was never persisted, so zero audit violations is
consistent with the test design. A separate, safely isolated audit test
is required before claiming audit violation discovery is validated.

Detailed artifacts and checksums are in
`evidence/gatekeeper-admission/`. Falco runtime artifacts are in
`evidence/runtime-write/`.

## Next steps

1. Capture UTC clock state, service/configuration checks, JSONL validation counts, and final checksums. Sanitized collector and manager excerpts are recorded in `evidence/wazuh-integration/falco-event-sanitized.json` and `evidence/wazuh-integration/wazuh-alert-sanitized.json`.
2. Trigger a controlled shell event and verify that it reaches the Wazuh manager and matches the expected alerting logic.
3. Validate indexer and dashboard visibility; investigate the recorded connector warnings without disturbing the working manager alert path.
4. Tune only confirmed benign noise and preserve before/after evidence for every rule change.
5. Reassess the Gatekeeper and PSS overlap before expanding enforcement scope.
6. Safely validate Gatekeeper audit discovery of a pre-existing noncompliant object before claiming that capability is demonstrated.

**Completion statement:** Falco runtime detections, isolated native PSS admission tests, Gatekeeper admission enforcement, and Wazuh ingestion/rule matching for a controlled filesystem-write event have been demonstrated. Phase 3 remains in validation until evidence is packaged, shell-event forwarding and indexer/dashboard visibility are checked, and the documented audit limitation is addressed.
