# Aegis Phase 4 Deployment Runbook

This runbook is an implementation guide. It does not state that any step has already been executed. Run it only in the dedicated Phase 4 lab and review each command against the current cluster and Wazuh configuration.

## 1. Preconditions

- Dedicated Kind context: `kind-aegis-phase4-lab`.
- A NetworkPolicy-enforcing CNI. The recorded Phase 4 lab is Kubernetes v1.37.0 with Calico 3.33.0. The CI admission matrix currently tests Kubernetes 1.33.12 / Gatekeeper 3.23.1; validate the `restricted:v1.33` PSS label and Gatekeeper compatibility on the live v1.37.0 cluster before applying manifests.
- Gatekeeper 3.23.1.
- Existing namespace `aegis-policy-test`.
- Existing Phase 2 ConstraintTemplates:
  - `phase2-advanced/kubernetes/gatekeeper/container-security-template.yaml`
  - `phase2-advanced/kubernetes/gatekeeper/image-integrity-template.yaml`
- Wazuh Manager rules 100501 and 100502 already installed and verified from Phase 3.
- Wazuh Manager can accept a loopback-only reverse SSH forward from Kali.
- A dedicated HMAC key, stored outside Git and shared securely between the manager and Kubernetes Secret.
- A built SOAR container image published to GHCR.

Do not repurpose the Phase 3 Kind cluster or change its CNI as part of this deployment.

## 2. Build and pin the SOAR image

The existing repository workflow `.github/workflows/aegis-phase4-ci.yml` builds the image after both Phase 4 source-validation and unified PSS/Gatekeeper jobs pass on a push to the Phase 4 branch. Pull-request runs validate source and policy but do not publish images. It:

- Resolves the Python 3.12.16 slim Trixie base tag to an immutable registry digest and passes that digest to the Docker build.
- Builds `linux/amd64` and `linux/arm64` images.
- Publishes a commit-SHA tag to GHCR, with an SBOM and BuildKit provenance.
- Scans the published digest with Trivy 0.76.2. HIGH or CRITICAL findings fail the workflow.
- Attests build provenance after the scan succeeds.

Wait for the complete workflow to pass. A failed scan can leave an image in GHCR, but that image is not approved for deployment. Copy the immutable digest from the workflow summary and update `platform/kubernetes/soar-deployment.yaml` to use:

```yaml
image: ghcr.io/serra-valle/aegis-soar@sha256:<64-character-published-digest>
```

Do not deploy the `phase4-pending-build` placeholder or rely on a mutable tag. Record the exact digest, Trivy result, SBOM and provenance evidence in the delivery record.

## 3. Provision the HMAC secret

Generate a high-entropy key on a trusted administrative host:

```bash
umask 077
openssl rand -hex 32 > aegis-soar-hmac.key
chmod 0600 aegis-soar-hmac.key
```

Transfer the file securely to the Kubernetes operator and Wazuh Manager. Do not commit it, paste it into chat, or include it in logs.

On the Kubernetes operator host:

```bash
kubectl --context kind-aegis-phase4-lab create namespace aegis-soar-system --dry-run=client -o yaml | kubectl --context kind-aegis-phase4-lab apply -f -
kubectl --context kind-aegis-phase4-lab -n aegis-soar-system create secret generic aegis-soar-hmac --from-file=key=./aegis-soar-hmac.key
```

On Wazuh Manager, install the same key at `/etc/aegis-soar/hmac.key` with owner `root`, group `wazuh`, and mode `0640`. The dispatcher requires at least 32 bytes.

## 4. Apply Gatekeeper templates and Phase 4 manifests

From the Phase 4 directory:

```bash
PHASE2_GATEKEEPER=../phase2-advanced/kubernetes/gatekeeper

kubectl --context kind-aegis-phase4-lab apply -f "$PHASE2_GATEKEEPER/container-security-template.yaml"
kubectl --context kind-aegis-phase4-lab apply -f "$PHASE2_GATEKEEPER/image-integrity-template.yaml"

kubectl --context kind-aegis-phase4-lab wait --for=condition=Established crd/k8saegiscontainersecurity.constraints.gatekeeper.sh --timeout=120s
kubectl --context kind-aegis-phase4-lab wait --for=condition=Established crd/k8saegisimageintegrity.constraints.gatekeeper.sh --timeout=120s

kubectl --context kind-aegis-phase4-lab apply -f platform/kubernetes/namespaces.yaml
kubectl --context kind-aegis-phase4-lab apply -k platform/kubernetes
```

The `aegis-policy-test` namespace must already exist. Review the rendered Kustomize output before applying:

```bash
kubectl kustomize platform/kubernetes
```

Confirm the two Phase 4 Gatekeeper constraints, both quarantine NetworkPolicies, RoleBindings and SOAR Deployment:

```bash
kubectl --context kind-aegis-phase4-lab get k8saegiscontainersecurity,k8saegisimageintegrity
kubectl --context kind-aegis-phase4-lab -n aegis-policy-test get networkpolicy aegis-quarantine-default-deny
kubectl --context kind-aegis-phase4-lab -n aegis-unified-policy get networkpolicy aegis-quarantine-default-deny
kubectl --context kind-aegis-phase4-lab -n aegis-soar-system get deploy,svc,pods
```

The Deployment image placeholder must be replaced with the immutable image digest before rollout. The HMAC Secret must exist before the Pod can start.

## 5. Keep containment disabled until dataplane acceptance

The ConfigMap deliberately sets:

```text
AEGIS_NETWORK_POLICY_ENFORCEMENT_CONFIRMED=false
```

Run the complete network-isolation procedure in [ACCEPTANCE_MATRIX.md](ACCEPTANCE_MATRIX.md). Confirm both ingress and egress denial and EndpointSlice removal. Only after the evidence has been reviewed should the operator change the ConfigMap value to `true` and restart the Deployment:

```bash
kubectl --context kind-aegis-phase4-lab -n aegis-soar-system patch configmap aegis-soar-config --type merge -p '{"data":{"AEGIS_NETWORK_POLICY_ENFORCEMENT_CONFIRMED":"true"}}'
kubectl --context kind-aegis-phase4-lab -n aegis-soar-system rollout restart deployment/aegis-soar
kubectl --context kind-aegis-phase4-lab -n aegis-soar-system rollout status deployment/aegis-soar
```

Do not set the attestation flag merely because a NetworkPolicy object exists.

Target application Services must include `aegis.security/endpoint-enabled: "true"` in their selectors. Confirm the EndpointSlice no longer lists the quarantined Pod. The NetworkPolicy remains the actual network isolation control.

## 6. Configure the Wazuh Active Response path

Install the scripts on Wazuh Manager:

- `wazuh/active-response/aegis-soar-active-response.py` to `/var/ossec/active-response/bin/aegis-soar-active-response.py`.
- `wazuh/active-response/aegis-soar-dispatcher.py` to `/var/ossec/integrations/aegis-soar-dispatcher.py`.
- `wazuh/manager/aegis-gatekeeper-rules.xml` to `/var/ossec/etc/rules/aegis-gatekeeper-rules.xml`.

Set the scripts executable and owner/group according to the existing Wazuh installation. Confirm the Wazuh group name and manager path before copying.

Merge the `command` and `active-response` elements inside `wazuh/manager/ossec.conf-aegis-active-response.xml` into the existing manager `ossec.conf` root. Do not replace the whole file. Confirm rule IDs 100503 and 100504 are not already assigned elsewhere.

Install the systemd service and timer from `wazuh/systemd/`, then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now aegis-soar-dispatcher.timer
sudo /var/ossec/bin/wazuh-analysisd -t
```

Restart Wazuh Manager only after the configuration test passes. Confirm the Active Response command is registered and the timer is active. The durable spool must remain on disk during tunnel or webhook outages.

## 7. Configure the Kali tunnel

Install the user services from `ops/systemd/` under `~/.config/systemd/user/`. Create `~/.config/aegis-soar/tunnel.env` with these local values:

```text
AEGIS_WAZUH_MANAGER_USER=<SSH user>
AEGIS_WAZUH_MANAGER_HOST=<manager host>
AEGIS_SSH_KEY=<absolute path to SSH private key>
```

Protect the file with mode 0600. Do not place the key or host-specific credentials in Git.

Enable the services:

```bash
systemctl --user daemon-reload
systemctl --user enable --now aegis-soar-port-forward.service
systemctl --user enable --now aegis-soar-reverse-tunnel.service
systemctl --user status aegis-soar-port-forward.service aegis-soar-reverse-tunnel.service
```

The manager-side listener must remain bound to `127.0.0.1:18080`. Do not expose the webhook publicly. The port-forward targets the Deployment directly so it can be reached while the readiness probe is correctly failing closed.

## 8. Configure Gatekeeper audit export

Create a dedicated kubeconfig for ServiceAccount `aegis-gatekeeper-audit-reader` using the ClusterRole in `platform/kubernetes/gatekeeper-audit-reader-rbac.yaml`. Do not reuse a cluster-admin kubeconfig for the exporter. The ServiceAccount token and CA material must remain outside Git. Rotate short-lived tokens according to the lab's credential policy.

Install the collector dependencies and script:

```bash
python3 -m pip install --requirement collectors/requirements.txt
```

Install `collectors/gatekeeper_audit_exporter.py` at `/opt/aegis-phase4/collectors/gatekeeper_audit_exporter.py`. Create the empty environment file required by the systemd unit, then install and enable it:

```bash
sudo install -m 0600 /dev/null /etc/aegis-gatekeeper-exporter.env
sudo systemctl daemon-reload
sudo systemctl enable --now aegis-gatekeeper-audit-exporter.service
```

The output file is `/var/log/aegis/gatekeeper-audit.jsonl`. Merge `wazuh/agent/aegis-gatekeeper-localfile.xml` into the existing Kali Wazuh agent configuration. Validate the agent configuration and restart the agent. Install the manager rules 100503/100504 before expecting Wazuh alerts.

## 9. Reconcile Falco declaratively

Build the ConfigMap:

```bash
kubectl kustomize platform/falco
```

The output is a source-controlled ConfigMap containing the Aegis write rule. The built-in Falco `Terminal shell in container` rule remains the source for rule 100502.

Before applying, inspect the live Falco Helm release and current ConfigMap. Merge the Phase 4 write rule into the existing chart configuration, preserve all existing custom rules and values, and avoid loading two copies of `Aegis Test Pod Write Below Etc`. Render the Helm manifests and review the diff before upgrading. A ConfigMap existing in Git is not proof that the Falco DaemonSet has loaded it.

Capture the live Falco driver mode and confirm whether it is using the intended eBPF driver before describing the event path as eBPF-backed. Rule syntax validation does not establish driver mode.

## 10. Acceptance and evidence

Run the workflow and the live tests in [ACCEPTANCE_MATRIX.md](ACCEPTANCE_MATRIX.md). Capture only real output from the target cluster and Wazuh services. Include timestamps, command context, relevant resource state and SHA-256 checksums. Do not create synthetic logs to fill an evidence gap.

The release remains incomplete until all required runtime tests pass and the status record is updated with actual evidence.
