# Gatekeeper Admission and Policy Enforcement Evidence

## Scope

This evidence records the Phase 3 Gatekeeper admission-policy validation
performed in the local Aegis Kubernetes lab.

The constraints cover container security settings and image integrity.
Their configured enforcement actions are `deny` at the
`validation.gatekeeper.sh` and `audit.gatekeeper.sh` enforcement points.

## Validation results

### Positive admission test

The compliant test Pod passed server-side dry-run admission with exit code
0. It used a SHA-256-pinned BusyBox image and configured non-root execution,
a read-only root filesystem, disabled privilege escalation, dropped
Linux capabilities, and RuntimeDefault seccomp.

Because server-side dry-run was used, the test did not require creating a
persistent test Pod.

### Negative admission test

The deliberately noncompliant test Pod was rejected with exit code 1.
The captured output records four policy findings:

1. Privilege escalation must be disabled.
2. The root filesystem must be read-only.
3. The container must run as non-root.
4. The image must use an explicit SHA-256 digest.

The request was rejected during server-side dry-run and was not persisted.

### Constraint status and audit

The two constraints reported `enforced: true` for the audit and webhook
controller status entries, with observed generation 2.

The latest captured constraint audit timestamp was
2026-10-15T22:23:12Z. Both constraints reported zero violations.

The previous `K8sNativeValidation engine is missing` / `vap.k8s.io`
warning was not found in the captured audit-log sample. This is evidence
about that sample, not a guarantee that the warning can never recur.

## Outstanding limitation

The zero-violation result does not demonstrate that Gatekeeper audit detects
a pre-existing noncompliant resource. The deliberately noncompliant Pod
was rejected at admission and was never persisted. Audit violation
discovery remains a separate validation item.

## Evidence files

- `container-security-constraint.yaml`
- `image-integrity-constraint.yaml`
- `container-security-template.yaml`
- `image-integrity-template.yaml`
- `container-security-status.json`
- `image-integrity-status.json`
- `gatekeeper-pods.txt`
- `gatekeeper-audit-last-15m.log`
- `compliant-admission-dry-run.txt`
- `noncompliant-admission-dry-run.txt`
- `SHA256SUMS.txt`

Runtime detection artifacts are stored in the sibling `runtime-write`
evidence directory.
