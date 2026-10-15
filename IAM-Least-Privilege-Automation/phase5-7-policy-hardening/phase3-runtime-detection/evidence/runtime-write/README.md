# Falco Runtime Detection Evidence

## Scope

This evidence records controlled runtime tests in the Aegis Phase 3
Kind cluster. The test workload ran in the `aegis-policy-test` namespace
as `falco-runtime-test`.

The test Pod used a SHA-256-pinned BusyBox image, UID/GID 65532,
non-root execution, a read-only root filesystem, disabled privilege
escalation, dropped Linux capabilities, RuntimeDefault seccomp, and no
service-account token. An `emptyDir` volume was mounted at
`/etc/aegis-test`.

## Confirmed detections

### Filesystem write

The test workload wrote `runtime-proof.txt` below `/etc/aegis-test`.
The custom Falco rule generated an event containing the file path,
process and user metadata, Pod name, and namespace.

This was a controlled write within the test container's filesystem
namespace. It was not a write to the Kubernetes node's host `/etc`.

### Shell execution

A separate controlled shell command generated a Falco
`Terminal shell in container` event.

These tests demonstrate detection of the specific controlled events.
They do not establish comprehensive runtime threat coverage or
production alerting readiness.

## Evidence files

- `falco-runtime-write-event.jsonl`: custom filesystem-write event
- `falco-terminal-shell-event.jsonl`: shell-execution event
- `falco-runtime-test-pod.yaml`: test Pod manifest
- `runtime-proof.txt`: file created by the controlled write
- `test-pod.log`: test workload output
- `SHA256SUMS.txt`: checksums for the evidence files and this README

Review the event records alongside the custom Falco rule and Pod
manifest when reproducing these tests.
