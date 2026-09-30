# Cybersecurity Engineering Portfolio

Security engineering portfolio focused on **cloud security, IAM, Policy-as-Code, detection engineering, security automation, and incident response**.

My projects are built around practical security controls, reproducible testing, documented evidence, and automation rather than isolated lab exercises.

[![Aegis Security Guardrail](https://github.com/serra-valle/Cybersecurity-portfolio/actions/workflows/aegis-guardrail.yml/badge.svg)](https://github.com/serra-valle/Cybersecurity-portfolio/actions/workflows/aegis-guardrail.yml)

---

## Featured Project

### Project Aegis Phase 2: Advanced Policy-as-Code & Multi-Cloud Guardrails

Expanded an AWS Terraform networking guardrail into a broader security enforcement framework spanning **AWS, Azure, and Kubernetes**.

The project combines Terraform plan analysis, OPA/Rego, Conftest, OPA Gatekeeper, Kind, and GitHub Actions to enforce security controls before infrastructure deployment and during Kubernetes admission.

**Key controls**
- IPv4 and IPv6 public-exposure detection
- restricted-port and wildcard-protocol enforcement
- AWS IAM least-privilege guardrails
- S3 encryption and Public Access Block validation
- EBS and RDS encryption enforcement
- Azure Storage encryption and public-access controls
- Kubernetes container security contexts
- rejection of `:latest` images
- mandatory SHA-256 image digest pinning
- multi-container admission testing
- automated positive and negative security testing in CI

**Validation**
- **49/49 Terraform/Rego regression tests passed**
- **Policy-as-Code Regression: PASS**
- **Kubernetes Gatekeeper Admission: PASS**
- secure configurations accepted
- deliberately insecure configurations rejected for the expected policy reason

**Tools:** Terraform · OPA/Rego · Conftest · AWS · AzureRM · Kubernetes · OPA Gatekeeper · Kind · GitHub Actions

[View Aegis Phase 2](IAM-Least-Privilege-Automation/phase5-7-policy-hardening/README.md)

[View CI Workflow](.github/workflows/aegis-guardrail.yml)

---

## Cloud & IAM Security

### IAM Least Privilege Automation

Implemented IAM Access Analyzer and a custom least-privilege automation pipeline on AWS.

Analyzed CloudTrail activity to identify excessive IAM permissions, automated unused-permission analysis with Python and boto3, and used Terraform to refactor roles into narrower task-specific policies.

The project demonstrates practical IAM review, cloud logging, security automation, and Infrastructure-as-Code remediation.

**Tools:** AWS IAM Access Analyzer · CloudTrail · Python · boto3 · Terraform · AWS CLI · Kali Linux

[View Project](IAM-Least-Privilege-Automation/)

### Related Aegis Engineering

- [Continuous Identity Guarding](IAM-Least-Privilege-Automation/continuous-identity-guarding/)  
  Lambda automation, ghost-role detection, SNS reporting, and SCP controls.

- [Project Aegis: CSPM Engine](IAM-Least-Privilege-Automation/project-aegis/)  
  Security hardening across IAM, S3, Security Groups, and cross-account trust.

- [Project Aegis: Inline Policy Enforcement](IAM-Least-Privilege-Automation/project-aegis-phase3/)  
  OPA/Rego pre-deployment guardrails and proactive policy enforcement.

---

## Detection Engineering

### Sigma Detection Rules

Developed Sigma rules from hands-on attack simulation and mapped them to MITRE ATT&CK techniques.

| Rule | Tactic | Technique | Level |
|---|---|---|---|
| [SSH Brute Force](sigma-rules/rules/credential_access/ssh_brute_force.yml) | Credential Access | T1110.001 | High |
| [Network Port Scan](sigma-rules/rules/discovery/nmap_port_scan.yml) | Discovery | T1046 | Medium |
| [SQL Injection Attempt](sigma-rules/rules/initial_access/sql_injection_attempt.yml) | Initial Access | T1190 | High |
| [Phishing Malicious Attachment](sigma-rules/rules/initial_access/phishing_malicious_attachment.yml) | Initial Access | T1566.001 | High |

[View Sigma Rules](sigma-rules/README.md)

---

## Security Operations & Incident Response

### Full Security Stack Lab

Built an offensive and defensive security environment combining vulnerable applications, a honeypot, web application firewall, centralized logging, and attack simulation.

Attack activity was captured and correlated in Kibana, with supporting incident-response documentation and architecture evidence.

**Tools:** DVWA · Cowrie · ModSecurity · OWASP CRS · ELK Stack · Filebeat · Kibana · Nmap · sqlmap · Metasploit · Kali Linux

### Network Attack Detection & Reporting

Deployed a Cowrie SSH honeypot on Ubuntu, performed reconnaissance and SSH attack simulation from Kali Linux, captured traffic with Wireshark, and documented the resulting activity in an incident report.

**Tools:** Cowrie · Nmap · Wireshark · iptables · Kali Linux

[View Project](project-1-honeypot/)

---

## Engineering Approach

Across the portfolio, I focus on controls that can be tested and defended with evidence.

Typical workflow:

```text
Security Requirement
        |
        v
Implementation
        |
        v
Positive Test
        |
        v
Negative / Adversarial Test
        |
        v
Evidence
        |
        v
CI / Automation
```

For infrastructure projects, this means validating what a tool such as Terraform actually plans to create rather than relying only on static source inspection.

For Kubernetes, this includes admission-time enforcement so non-compliant workloads are denied before being accepted by the cluster.

---

## Core Skills

### Cloud Security & IAM
- AWS IAM and least-privilege engineering
- IAM Access Analyzer
- CloudTrail analysis
- AWS Lambda, EventBridge, and SNS
- Service Control Policies
- S3, EBS, and RDS security controls
- Azure Storage security
- Terraform Infrastructure-as-Code

### Policy-as-Code & Platform Security
- OPA/Rego
- Conftest
- Terraform plan JSON analysis
- OPA Gatekeeper
- Kubernetes admission control
- container security contexts
- image integrity and digest pinning
- Kind
- GitHub Actions security gates

### Detection & Security Operations
- Sigma rules
- MITRE ATT&CK mapping
- ELK Stack
- Filebeat
- Kibana
- Cowrie
- Wireshark
- incident-response documentation

### Security Validation & Automation
- Python
- boto3
- Linux
- Git
- Nmap
- sqlmap
- Metasploit
- adversarial positive/negative testing

---

## Current Focus

I am continuing to deepen my work in:

- cloud security engineering
- IAM engineering
- detection engineering
- Kubernetes security
- Microsoft security technologies
- security automation and CI/CD controls

---

## Author

**Olamilekan Adigun**  
Cloud Security Engineer · CompTIA Security+  
Lagos, Nigeria

[LinkedIn](https://www.linkedin.com/in/olamilekan-adigun/)
