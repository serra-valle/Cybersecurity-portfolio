# Aegis Phase 3: Runtime Detection and Pod Security Validation

**Validation date:** 15 October 2026
**Status:** Falco runtime detection, isolated PSS validation, and Gatekeeper admission enforcement demonstrated. SIEM integration remains blocked by infrastructure.

## Summary

This phase adds runtime threat detection with Falco and validates Kubernetes Pod Security Standards (PSS) in an isolated test namespace.

Falco ran on the Kind cluster using modern eBPF. Its DaemonSet was available, and the Falco Pod was running with both containers ready and no restarts at the time of inspection.

Controlled runtime testing generated a custom alert for a write below `/etc` by the Aegis test Pod. A shell-execution detection was also observed during earlier controlled testing.

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

Wazuh was not installed. The assessed Ubuntu VM had an ARM64 architecture, 4 CPU cores, 3.8 GiB RAM, 10 GiB free disk, and no Docker installation.

Wazuh ingestion and end-to-end alert correlation were therefore not demonstrated. This is an infrastructure blocker, not a successful integration.

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

1. Provision a host with sufficient memory and disk capacity for the selected Wazuh deployment.
2. Configure ingestion of Falco runtime alerts and relevant Kubernetes audit or admission-denial evidence.
3. Verify a controlled shell event and filesystem-write event arrive in the SIEM with useful Kubernetes metadata.
4. Validate alert rules and correlation, then tune confirmed benign noise.
5. Reassess the Gatekeeper and PSS overlap before expanding enforcement scope.

**Completion statement:** Falco runtime detections and isolated native PSS admission tests were demonstrated. Aegis Phase 3 is not fully complete until SIEM ingestion and end-to-end correlation are verified.
