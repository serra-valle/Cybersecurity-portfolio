# Aegis Phase 4 Deployment Runbook

This runbook is an implementation guide. It does not state that any step has already been executed. Run it only in the dedicated Phase 4 lab and review each command against the current cluster and Wazuh configuration.

## 1. Preconditions

- Dedicated Kind context: \`kind-aegis-phase4-lab\`.
- A NetworkPolicy-enforcing CNI. The recorded Phase 4 lab is Kubernetes v1.37.0 with Calico 3.33.0. The CI admission matrix currently tests Kubernetes 1.33.12 / Gatekeeper 3.23.1; validate the \`restricted:v1.33\` PSS label and Gatekeeper compatibility on the live v1.37.0 cluster before applying manifests.
- Gatekeeper 3.23.1.
- Existing namespace \`aegis-policy-test\`.
- Existing Phase 2 ConstraintTemplates:
  - \`phase2-advanced/kubernetes/gatekeeper/container-security-template.yaml\`
  - \`phase2-advanced/kubernetes/gatekeeper/image-integrity-template.yaml\`
- Wazuh Manager rules 100501 and 100502 already installed and verified from Phase 3.
- Wazuh Manager can accept a loopback-only reverse SSH forward from Kali.
- A dedicated HMAC key, stored outside Git and shared securely between the manager and Kubernetes Secret.
- A built SOAR container image published to GHCR.

Do not repurpose the Phase 3 Kind cluster or change its CNI as part of this deployment.

## 2. Verify the pinned SOAR image

The Deployment manifest now references the verified immutable image:

\`\`\`text
ghcr.io/serra-valle/aegis-soar@sha256:7cfb86923d5110aeec3241641fee94eef9324a7bfeaaa751d50fb6f4f856f0dc
\`\`\`

The image was built from the immutable base \`python:3.12.16-alpine3.24@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89\`. The Dockerfile upgrades Alpine packages, installs the application dependencies with pip 26.2.0, then removes pip and its bundled installer from the runtime image. The process runs as UID/GID 10001.

[CI run 44134158272](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/44134158272) built and published both \`linux/amd64\` and \`linux/arm64\`. Runtime smoke tests passed on both architectures with a read-only root filesystem, all capabilities dropped and no-new-privileges. The health endpoint returned HTTP 200; readiness returned the expected HTTP 503 while the HMAC Secret was absent.

Trivy 0.76.2 scanned all severities and vulnerability, misconfiguration and secret scanners on both architecture manifests. Both reports returned zero findings. The full JSON reports are retained as workflow artifact [14351327524](https://github.com/serra-valle/Cybersecurity-portfolio/actions/runs/44134158272). The image also has a BuildKit SBOM and a Sigstore-signed provenance attestation uploaded to [GitHub](https://github.com/serra-valle/Cybersecurity-portfolio/attestations/68730154), GHCR and [Rekor](https://search.sigstore.dev?logIndex=3949778857).

This is image-artifact verification only. The Deployment has not been rolled out. Before any rollout, provision the HMAC Secret securely on Kubernetes and Wazuh Manager, verify the target cluster context and complete the remaining live acceptance gates.

For a future rebuild, use \`.github/workflows/aegis-phase4-ci.yml\`. Promote only the digest produced by a complete successful run with both architecture smoke tests, full Trivy reports, the vulnerability gate, SBOM and signed provenance. A failed scan may leave an image in GHCR, but that image is not approved. Never deploy a mutable tag or the old \`phase4-pending-build\` placeholder.

## 3. Provision the HMAC secret

Generate a high-entropy key on a trusted administrative host:

\`\`\`bash
umask 077
openssl rand -hex 32 > aegis-soar-hmac.key
chmod 0600 aegis-soar-hmac.key
\`\`\`

Transfer the file securely to the Kubernetes operator and Wazuh Manager. Do not commit it, paste it into chat, or include it in logs.

On the Kubernetes operator host:

\`\`\`bash
kubectl --context kind-aegis-phase4-lab create namespace aegis-soar-system --dry-run=client -o yaml | kubectl --context kind-aegis-phase4-lab apply -f -
kubectl --context kind-aegis-phase4-lab -n aegis-soar-system create secret generic aegis-soar-hmac --from-file=key=./aegis-soar-hmac.key
\`\`\`

On Wazuh Manager, install the same key at \`/etc/aegis-soar/hmac.key\` with owner \`root\`, group \`wazuh\`, and mode \`0640\`. The dispatcher requires at least 32 bytes.

## 4. Apply Gatekeeper templates and Phase 4 manifests

From the Phase 4 directory:

\`\`\`bash
PHASE2_GATEKEEPER=../phase2-advanced/kubernetes/gatekeeper

kubectl --context kind-aegis-phase4-lab apply -f "$PHASE2_GATEKEEPER/container-security-template.yaml"
kubectl --context kind-aegis-phase4-lab apply -f "$PHASE2_GATEKEEPER/image-integrity-template.yaml"

kubectl --context kind-aegis-phase4-lab wait --for=condition=Established crd/k8saegiscontainersecurity.constraints.gatekeeper.sh --timeout=120s
kubectl --context kind-aegis-phase4-lab wait --for=condition=Established crd/k8saegisimageintegrity.constraints.gatekeeper.sh --timeout=120s

kubectl --context kind-aegis-phase4-lab apply -f platform/kubernetes/namespaces.yaml
kubectl --context kind-aegis-phase4-lab apply -k platform/kubernetes
\`\`\`

The \`aegis-policy-test\` namespace must already exist. Review the rendered Kustomize output before applying:

\`\`\`bash
kubectl kustomize platform/kubernetes
\`\`\`

Confirm the two Phase 4 Gatekeeper constraints, both quarantine NetworkPolicies, RoleBindings and SOAR Deployment:

\`\`\`bash
kubectl --context kind-aegis-phase4-lab get k8saegiscontainersecurity,k8saegisimageintegrity
kubectl --context kind-aegis-phase4-lab -n aegis-policy-test get networkpolicy aegis-quarantine-default-deny
kubectl --context kind-aegis-phase4-lab -n aegis-unified-policy get networkpolicy aegis-quarantine-default-deny
kubectl --context kind-aegis-phase4-lab -n aegis-soar-system get deploy,svc,pods
\`\`\`

The Deployment manifest already pins the verified immutable image digest, but it has not been rolled out. The HMAC Secret must exist before the Pod can start.

## 5. Keep containment disabled until dataplane acceptance

The ConfigMap deliberately sets:

\`\`\`text
AEGIS_NETWORK_POLICY_ENFORCEMENT_CONFIRMED=false
\`\`\`

Run the complete network-isolation procedure in [ACCEPTANCE_MATRIX.md](ACCEPTANCE_MATRIX.md). Confirm both ingress and egress denial and EndpointSlice removal. Only after the evidence has been reviewed should the operator change the ConfigMap value to \`true\` and restart the Deployment:

\`\`\`bash
kubectl --context kind-aegis-phase4-lab -n aegis-soar-system patch configmap aegis-soar-config --type merge -p '{"data":{"AEGIS_NETWORK_POLICY_ENFORCEMENT_CONFIRMED":"true"}}'
kubectl --context kind-aegis-phase4-lab -n aegis-soar-system rollout restart deployment/aegis-soar
kubectl --context kind-aegis-phase4-lab -n aegis-soar-system rollout status deployment/aegis-soar
\`\`\`

Do not set the attestation flag merely because a NetworkPolicy object exists.

Target application Services must include \`aegis.security/endpoint-enabled: "true"\` in their selectors. Confirm the EndpointSlice no longer lists the quarantined Pod. The NetworkPolicy remains the actual network isolation control.

## 6. Configure the Wazuh Active Response path

Install the scripts on Wazuh Manager:

- \`wazuh/active-response/aegis-soar-active-response.py\` to \`/var/ossec/active-response/bin/aegis-soar-active-response.py\`.
- \`wazuh/active-response/aegis-soar-dispatcher.py\` to \`/var/ossec/integrations/aegis-soar-dispatcher.py\`.
- \`wazuh/manager/aegis-gatekeeper-rules.xml\` to \`/var/ossec/etc/rules/aegis-gatekeeper-rules.xml\`.

Set the scripts executable and owner/group according to the existing Wazuh installation. Confirm the Wazuh group name and manager path before copying.

Merge the \`command\` and \`active-response\` elements inside \`wazuh/manager/ossec.conf-aegis-active-response.xml\` into the existing manager \`ossec.conf\` root. Do not replace the whole file. Confirm rule IDs 100503 and 100504 are not already assigned elsewhere.

Install the systemd service and timer from \`wazuh/systemd/\`, then:

\`\`\`bash
sudo systemctl daemon-reload
sudo systemctl enable --now aegis-soar-dispatcher.timer
sudo /var/ossec/bin/wazuh-analysisd -t
\`\`\`

Restart Wazuh Manager only after the configuration test passes. Confirm the Active Response command is registered and the timer is active. The durable spool must remain on disk during tunnel or webhook outages.

## 7. Configure the Kali tunnel

Install the user services from \`ops/systemd/\` under \`~/.config/systemd/user/\`. Create \`~/.config/aegis-soar/tunnel.env\` with these local values:

\`\`\`text
AEGIS_WAZUH_MANAGER_USER=<SSH user>
AEGIS_WAZUH_MANAGER_HOST=<manager host>
AEGIS_SSH_KEY=<absolute path to SSH private key>
\`\`\`

Protect the file with mode 0600. Do not place the key or host-specific credentials in Git.

Enable the services:

\`\`\`bash
systemctl --user daemon-reload
systemctl --user enable --now aegis-soar-port-forward.service
systemctl --user enable --now aegis-soar-reverse-tunnel.service
systemctl --user status aegis-soar-port-forward.service aegis-soar-reverse-tunnel.service
\`\`\`

The manager-side listener must remain bound to \`127.0.0.1:18080\`. Do not expose the webhook publicly. The port-forward targets the Deployment directly so it can be reached while the readiness probe is correctly failing closed.

## 8. Configure Gatekeeper audit export

Create a dedicated kubeconfig for ServiceAccount \`aegis-gatekeeper-audit-reader\` using the ClusterRole in \`platform/kubernetes/gatekeeper-audit-reader-rbac.yaml\`. Do not reuse a cluster-admin kubeconfig for the exporter. The ServiceAccount token and CA material must remain outside Git. Rotate short-lived tokens according to the lab's credential policy.

Install the collector dependencies and script:

\`\`\`bash
python3 -m pip install --requirement collectors/requirements.txt
\`\`\`

Install \`collectors/gatekeeper_audit_exporter.py\` at \`/opt/aegis-phase4/collectors/gatekeeper_audit_exporter.py\`. Create the empty environment file required by the systemd unit, then install and enable it:

\`\`\`bash
sudo install -m 0600 /dev/null /etc/aegis-gatekeeper-exporter.env
sudo systemctl daemon-reload
sudo systemctl enable --now aegis-gatekeeper-audit-exporter.service
\`\`\`

The systemd unit creates a root-only state directory at \`/var/lib/aegis-gatekeeper-exporter\`; the active-violation checkpoint is \`state.json\` inside it. Keep this checkpoint across routine restarts. If it is malformed, the exporter stops and requires operator review rather than resetting state and replaying every active violation.

The exporter only infers a resolution from a completed Gatekeeper audit snapshot with \`status.auditTimestamp\`, \`status.totalViolations\`, and a complete \`status.violations\` list. Gatekeeper bounds the number of violation details stored in constraint status. If \`totalViolations\` exceeds the number of returned violation records, the snapshot is treated as truncated: visible new findings can be exported, but omitted findings are not marked resolved. Review Gatekeeper's \`--constraint-violations-limit\` setting if truncation occurs.

The output file is \`/var/log/aegis/gatekeeper-audit.jsonl\`. Merge \`wazuh/agent/aegis-gatekeeper-localfile.xml\` into the existing Kali Wazuh agent configuration. Validate the agent configuration and restart the agent. Install the manager rules 100503/100504 before expecting Wazuh alerts.

## 9. Reconcile Falco declaratively

Build the ConfigMap:

\`\`\`bash
kubectl kustomize platform/falco
\`\`\`

The output is a source-controlled ConfigMap containing the Aegis write rule. The built-in Falco \`Terminal shell in container\` rule remains the source for rule 100502.

Before applying, inspect the live Falco Helm release and current ConfigMap. Merge the Phase 4 write rule into the existing chart configuration, preserve all existing custom rules and values, and avoid loading two copies of \`Aegis Test Pod Write Below Etc\`. Render the Helm manifests and review the diff before upgrading. A ConfigMap existing in Git is not proof that the Falco DaemonSet has loaded it.

Capture the live Falco driver mode and confirm whether it is using the intended eBPF driver before describing the event path as eBPF-backed. Rule syntax validation does not establish driver mode.

## 10. Acceptance and evidence

Run the workflow and the live tests in [ACCEPTANCE_MATRIX.md](ACCEPTANCE_MATRIX.md). Capture only real output from the target cluster and Wazuh services. Include timestamps, command context, relevant resource state and SHA-256 checksums. Do not create synthetic logs to fill an evidence gap.

The release remains incomplete until all required runtime tests pass and the status record is updated with actual evidence.
