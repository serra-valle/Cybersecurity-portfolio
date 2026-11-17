# Aegis SOAR Container Image Security Review

**Review date:** 17 November 2026  
**Reviewed commit:** `d262829cf0df0d9974b024edd9fd2699897035ed`  
**Workflow:** [GitHub Actions run 44134158272](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/44134158272)  
**Image:** `ghcr.io/serra-valle/aegis-soar@sha256:7cfb86923d5110aeec3241641fee94eef9324a7bfeaaa751d50fb6f4f856f0dc`  
**Base image:** `python:3.12.16-alpine3.24@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89`  
**Architectures:** `linux/amd64`, `linux/arm64`

## 1. Review decision

I approved this immutable image artifact for use in the Phase 4 Kubernetes manifest after both architecture builds, runtime smoke tests, full Trivy scans and provenance attestation passed.

This approval is limited to the image artifact. It does not mean the Phase 4 Deployment has been applied, that the HMAC secret is provisioned, or that automated containment is operational.

The verified digest is pinned in `platform/kubernetes/soar-deployment.yaml`. The manifest continues to keep:

- `AEGIS_DELETE_UNMANAGED_PODS=false`
- `AEGIS_NETWORK_POLICY_ENFORCEMENT_CONFIRMED=false`

## 2. Previous Debian image findings and remediation

The preceding Debian 13.7 slim image, `ghcr.io/serra-valle/aegis-soar@sha256:25982a688e9d9ea553b1b99cdc1ec2208ebafb839088b186070d9d023e3f77d6`, produced 47 HIGH OS-package vulnerability instances across 11 unique CVEs. It had zero CRITICAL findings and no remaining Python application-package findings after the Starlette dependency remediation.

The findings were not suppressed. The report grouped them as follows:

| Source package | HIGH instances | CVEs |
|---|---:|---|
| ncurses | 4 | [CVE-2025-69720](https://security-tracker.debian.org/tracker/CVE-2025-69720) |
| sqlite3 | 3 | [CVE-2026-119373](https://security-tracker.debian.org/tracker/CVE-2026-119373), [CVE-2026-119374](https://security-tracker.debian.org/tracker/CVE-2026-119374), [CVE-2026-119379](https://security-tracker.debian.org/tracker/CVE-2026-119379) |
| systemd | 2 | [CVE-2026-16742](https://security-tracker.debian.org/tracker/CVE-2026-16742) |
| acl | 1 | [CVE-2026-54369](https://security-tracker.debian.org/tracker/CVE-2026-54369) |
| util-linux | 36 | [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642), [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408), [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409), [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410) |
| perl-base | 1 | [CVE-2026-9538](https://security-tracker.debian.org/tracker/CVE-2026-9538) |
| **Total** | **47** | **11 unique CVEs** |

At the time of the scan, the Trivy report had no fixed Trixie package versions for these findings. The package-level scanner mapping did not prove that every vulnerable utility or code path was reachable through the SOAR HTTP service. I did not treat that uncertainty as proof of non-exploitability. I replaced the base image instead of suppressing the findings.

## 3. Final image construction

The final image uses the immutable Python 3.12.16 Alpine 3.24.4 base digest. The Dockerfile:

1. Upgrades the Alpine packages and installs CA certificates.
2. Upgrades pip to 26.2.0 before dependency installation.
3. Installs the pinned application requirements and runs `pip check`.
4. Verifies the Starlette security floor.
5. Removes pip and the bundled `ensurepip` installer from the runtime image.
6. Verifies that the pip module is no longer importable.
7. Runs the application as numeric UID/GID 10001.

The Kubernetes Deployment additionally specifies a non-root security context, RuntimeDefault seccomp, read-only root filesystem, no privilege escalation and all Linux capabilities dropped.

## 4. Full Trivy results

Trivy 0.76.2 scanned the published multi-architecture image by explicitly selecting each platform. The reports included all severities and the vulnerability, misconfiguration and secret scanners.

| Platform | Vulnerabilities | Misconfigurations | Secrets |
|---|---:|---:|---:|
| linux/amd64 | 0 | 0 | 0 |
| linux/arm64 | 0 | 0 | 0 |

The full JSON reports are retained in workflow artifact [14351327524](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/44134158272). The workflow fails on fixable HIGH or CRITICAL findings on either architecture. The full report remains available even when findings are not in the blocking severity range.

## 5. Runtime smoke tests

The workflow pulled and ran each architecture image separately. Both smoke tests used:

- UID/GID 10001.
- Read-only container root filesystem.
- A bounded writable `/tmp` tmpfs.
- All Linux capabilities dropped.
- `no-new-privileges`.

Both architecture tests passed:

| Check | Expected result | Result |
|---|---|---|
| Container identity | `10001:10001` | Passed |
| `/healthz` | HTTP 200 | Passed on AMD64 and ARM64 |
| `/readyz` without HMAC secret | HTTP 503, fail closed | Passed on AMD64 and ARM64 |

The readiness failure is expected in this smoke test because no HMAC Secret was supplied. It confirms that the image does not become ready when the required secret is absent. It is not a live Kubernetes readiness test.

## 6. SBOM and provenance

The Buildx build generated and attached an SBOM and BuildKit provenance. The workflow then created a Sigstore-signed provenance attestation for the exact image digest.

- [GitHub attestation](https://github.com/serra-valle/Cybersecurity-portfolio/attestations/68730154)
- [Rekor transparency log entry](https://search.sigstore.dev?logIndex=3949778857)
- GHCR attestation subject: `ghcr.io/serra-valle/aegis-soar@sha256:7cfb86923d5110aeec3241641fee94eef9324a7bfeaaa751d50fb6f4f856f0dc`

The attestation identifies source commit `d262829cf0df0d9974b024edd9fd2699897035ed` and the Phase 4 workflow. The image digest, not the mutable commit tag, is the deployment reference.

## 7. Remaining limitations

- The image has not been deployed to the Phase 4 Kind cluster.
- The HMAC secret has not been provisioned in Kubernetes or on Wazuh Manager.
- No Wazuh Active Response event has reached the SOAR service.
- Calico ingress and egress isolation and EndpointSlice removal have not been demonstrated.
- `AEGIS_NETWORK_POLICY_ENFORCEMENT_CONFIRMED` remains false.
- `AEGIS_DELETE_UNMANAGED_PODS` remains false.
- Falco driver mode has not been verified as eBPF in the live Phase 4 cluster.

A clean image scan and successful container smoke test do not substitute for these operational acceptance tests. The image artifact is approved; Phase 4 operational acceptance remains open.
