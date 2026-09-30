# Project Aegis: Advanced Policy-as-Code and Multi-Cloud Guardrails

[![Aegis Security Guardrail](https://github.com/serra-valle/Cybersecurity-portfolio/actions/workflows/aegis-guardrail.yml/badge.svg)](https://github.com/serra-valle/Cybersecurity-portfolio/actions/workflows/aegis-guardrail.yml)

Project Aegis is a security engineering implementation for enforcing infrastructure and Kubernetes security controls through Policy-as-Code.

The project began as a deterministic Terraform AWS networking guardrail and was expanded to cover advanced Rego engineering, AWS IAM least privilege, AWS data protection, Azure Storage security, Kubernetes admission control with OPA Gatekeeper, adversarial testing, and automated CI/CD validation.

## Final Outcome

Aegis now provides two enforcement layers:

```text
Terraform HCL
    |
    v
Terraform Plan
    |
    v
Plan JSON
    |
    v
OPA / Rego + Conftest
    |
    +--> COMPLIANT --> CI PASS
    |
    +--> VIOLATION --> CI FAIL
```

```text
Pod Manifest
    |
    v
Kubernetes API Server
    |
    v
OPA Gatekeeper
    |
    +--> COMPLIANT --> ADMIT
    |
    +--> VIOLATION --> DENY
```

### Validation Summary

| Area | Result |
|---|---:|
| Original policy hardening baseline | 16/16 PASS |
| Advanced network helper tests | 17/17 PASS |
| IAM least-privilege tests | 6/6 PASS |
| AWS storage tests | 5/5 PASS |
| Azure Storage tests | 5/5 PASS |
| Complete Terraform/Rego regression | **49/49 PASS** |
| GitHub Policy-as-Code Regression | **PASS** |
| GitHub Kubernetes Gatekeeper Admission | **PASS** |

## Security Controls

### Network Security

Reusable Rego helper logic evaluates IPv4 and IPv6 CIDRs and distinguishes public exposure from private and special-purpose address space.

Coverage includes public IPv4/IPv6 exposure, RFC1918 networks, loopback, link-local, IPv6 ULA, documentation networks, restricted port ranges, wildcard protocols, inline security-group rules, and standalone security-group rules.

Restricted ports include SSH `22`, MySQL `3306`, RDP `3389`, and PostgreSQL `5432`.

Primary implementation:

`phase2-advanced/policy/network_utils.rego`

### AWS IAM Least Privilege

Aegis rejects IAM `Allow` statements combining unrestricted actions and resources:

```json
{
  "Effect": "Allow",
  "Action": "*",
  "Resource": "*"
}
```

Terraform represents managed IAM policies as JSON-encoded strings in plan data, so the Rego policy decodes the document before inspecting statements.

Primary implementation:

`phase2-advanced/policy/iam_least_privilege.rego`

### AWS Data Protection

Aegis enforces:

- explicit S3 server-side encryption
- `block_public_acls = true`
- `block_public_policy = true`
- `ignore_public_acls = true`
- `restrict_public_buckets = true`
- EBS volume encryption
- RDS storage encryption

S3 security resources are correlated through Terraform configuration references rather than naming conventions.

Primary implementation:

`phase2-advanced/policy/aws_storage.rego`

### Azure Storage

The Azure guardrail enforces:

- infrastructure encryption
- prevention of nested items being configured for public access
- private Blob container access

The policies were validated against Terraform plans generated with the AzureRM provider. No `terraform apply` was required.

Primary implementation:

`phase2-advanced/policy/azure_storage.rego`

## Kubernetes Admission Control

Aegis extends Policy-as-Code into Kubernetes using OPA Gatekeeper.

A dedicated Kind cluster was used to validate admission policies before workloads were accepted by the Kubernetes API.

### Container Security

Containers must configure:

```yaml
securityContext:
  runAsNonRoot: true
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
```

### Image Integrity

Aegis rejects images using the `:latest` tag and requires an explicit SHA-256 digest:

```text
registry/image@sha256:<64-character-digest>
```

The policy evaluates:

- normal containers
- init containers
- ephemeral containers

Gatekeeper policies:

`phase2-advanced/kubernetes/gatekeeper/`

Test manifests:

`phase2-advanced/kubernetes/manifests/`

### Admission Test Scenarios

| Scenario | Expected Result |
|---|---|
| Secure digest-pinned Pod | ALLOW |
| `runAsNonRoot: false` | DENY |
| `readOnlyRootFilesystem: false` | DENY |
| `allowPrivilegeEscalation: true` | DENY |
| `:latest` image | DENY |
| Tagged image without SHA-256 digest | DENY |
| Secure first container with insecure second container | DENY |

The multi-container test verifies that an insecure secondary container cannot bypass admission controls.

## CI/CD Security Gate

The GitHub Actions workflow contains two security validation jobs.

### Policy-as-Code Regression

The pipeline:

1. installs Terraform, OPA, and Conftest
2. generates Terraform plans for test fixtures
3. validates Rego policies
4. runs the complete regression suite
5. tests compliant configurations
6. confirms deliberately insecure configurations are denied

### Kubernetes Gatekeeper Admission

The pipeline:

1. creates a disposable Kind cluster
2. installs OPA Gatekeeper
3. registers the Aegis ConstraintTemplates
4. activates the constraints
5. verifies a compliant Pod is admitted
6. submits deliberately insecure Pods
7. verifies each expected admission rejection

Negative tests capture both the command return code and expected denial message so unrelated execution failures cannot be mistaken for successful security enforcement.

Workflow:

[`.github/workflows/aegis-guardrail.yml`](../../.github/workflows/aegis-guardrail.yml)

## Evidence

Validation evidence is stored under:

`phase2-advanced/evidence/`

Key evidence includes:

- `aws-storage-unit-tests.txt`
- `aws-storage-positive-plan.txt`
- `aws-storage-negative-plan.txt`
- `azure-storage-unit-tests.txt`
- `azure-storage-positive-plan.txt`
- `azure-storage-negative-plan.txt`
- `regression-after-azure-storage.txt`
- `gatekeeper-status.txt`
- `gatekeeper-secure-pod.txt`
- `gatekeeper-deny-security-context.txt`
- `gatekeeper-deny-latest.txt`
- `gatekeeper-deny-no-digest.txt`
- `gatekeeper-deny-multicontainer.txt`

## Repository Structure

```text
phase5-7-policy-hardening/
|
├── phase2-advanced/
│   ├── evidence/
│   ├── fixtures/
│   │   ├── iam/
│   │   ├── aws-storage/
│   │   └── azure-storage/
│   ├── kubernetes/
│   │   ├── gatekeeper/
│   │   ├── kind/
│   │   └── manifests/
│   ├── policy/
│   └── tests/
├── tf-test/
├── negative-test/
└── README.md
```

## Engineering Challenges Resolved

### Terraform IAM Representation

Terraform exposed the generated IAM policy as JSON encoded inside a string. The Rego implementation decodes the document before inspecting individual statements.

### S3 Cross-Resource Correlation

S3 encryption and Public Access Block controls exist as separate Terraform resources. Aegis correlates them through Terraform configuration references.

### Rego Variable Safety

Early reusable helper designs produced unsafe-variable errors under the validated OPA environment. The rules were restructured so variables are grounded inside the rule body.

### ARM64 and AMD64 CI

The local Kali environment uses ARM64 while GitHub Actions uses AMD64. The expanded CI workflow initially exposed a Terraform provider checksum mismatch between the two environments. The CI initialization process was corrected while keeping provider versions pinned.

### Kubernetes Admission Engineering

Gatekeeper required working with Kubernetes admission control, CRDs, ConstraintTemplates, Constraints, security contexts, image integrity, and namespaces. This was the most challenging part of the implementation and is an area identified for continued technical development.

## Validated Toolchain

| Component | Version |
|---|---|
| Terraform | 1.6.3 |
| OPA | 0.62.1 |
| Conftest | 0.50.0 |
| AWS Provider | 6.60.0 |
| AzureRM Provider | 5.4.0 |
| Kind | 0.33.0 |
| kubectl | 1.33.4 |
| OPA Gatekeeper | 3.23.1 |

These are the versions used during validation, not a claim that they are the latest available releases.

## Quick Regression

From this directory:

```bash
conftest verify --policy .
```

Validated baseline:

```text
49 tests, 49 passed
```

The GitHub Actions workflow also reproduces Terraform policy validation and Kubernetes admission tests on a separate CI runner.

## Scope and Limitations

This project demonstrates deterministic security enforcement, not a complete enterprise cloud or Kubernetes security platform.

Current boundaries include:

- Terraform policies evaluate planned infrastructure before deployment
- no AWS or Azure production deployment is required for policy validation
- Gatekeeper enforcement is validated primarily against Pod admission
- Kubernetes testing uses a dedicated Kind environment
- Gatekeeper provides admission-time enforcement, not behavioral runtime threat detection
- organization-wide rollout, exception management, controller-template coverage, and production policy governance would require additional design and validation

## Skills Demonstrated

- Policy-as-Code engineering
- Rego development
- Terraform plan analysis
- AWS IAM security
- AWS network security
- S3 security controls
- EBS and RDS encryption
- Azure Storage security
- multi-cloud IaC validation
- OPA Gatekeeper
- Kubernetes admission control
- container hardening
- container image integrity
- adversarial security testing
- CI/CD security gates
- cross-architecture troubleshooting

## Status

**Project Aegis Phase 2: Complete**

- Terraform/Rego regression: **49/49 PASS**
- Policy-as-Code CI: **PASS**
- Kubernetes Gatekeeper CI: **PASS**
- AWS and Azure controls: **VALIDATED**
- Kubernetes admission enforcement: **VALIDATED**
