# Aegis Phase 4 Architecture

## End-to-end topology

\`\`\`mermaid
flowchart LR
  subgraph Runtime["Kubernetes runtime"]
    F["Falco event<br/>100501 / 100502"]
    P["Target Pod"]
    NP["Quarantine NetworkPolicy<br/>deny ingress + egress"]
    EP["Service EndpointSlice<br/>endpoint-enabled selector"]
  end

  subgraph Wazuh["Wazuh Manager"]
    AR["Active Response<br/>rules 100501 / 100502"]
    Q["Durable alert spool"]
    D["HMAC-SHA256 dispatcher"]
    R["Gatekeeper rules<br/>100503 / 100504"]
  end

  subgraph Kali["Kali collector / control host"]
    T["Reverse SSH tunnel"]
    PF["kubectl port-forward"]
    S["Aegis SOAR FastAPI"]
    G["Gatekeeper audit exporter"]
    J["gatekeeper-audit.jsonl"]
    A["Wazuh agent JSON collection"]
  end

  F --> AR
  AR --> Q --> D --> T --> PF --> S
  S -->|"patch quarantine + endpoint label"| P
  P -->|"selected by label"| NP
  P -->|"label false; Service selector must opt in"| EP
  G -->|"read-only constraint status"| J --> A --> R
\`\`\`

## Control-plane boundaries

- Wazuh Manager runs the Active Response enqueue script and retry dispatcher.
- The dispatcher can reach only the manager's loopback listener on port 18080. A reverse SSH tunnel initiated from Kali forwards that listener to Kali loopback port 18081.
- Kali runs a \`kubectl port-forward\` to the Phase 4 SOAR Deployment in \`aegis-soar-system\`.
- The SOAR Pod uses a dedicated ServiceAccount with namespace-scoped Pod \`get/patch/delete\` and NetworkPolicy \`get\` permissions in the two allowlisted workload namespaces.
- The Gatekeeper exporter uses a separate read-only ServiceAccount with \`get/list\` access to only the two Aegis constraint kinds.
- The SOAR webhook accepts only signed JSON, agent \`kali-aegis-lab\`, rule IDs 100501/100502, and namespaces \`aegis-policy-test\` and \`aegis-unified-policy\`.

## Quarantine semantics

A Pod label does not itself block packets. The response implementation performs three related operations:

1. Adds \`aegis.security/status=quarantined\`.
2. Sets \`aegis.security/endpoint-enabled=false\`. Application Services must select \`aegis.security/endpoint-enabled=true\` for this label to remove the Pod from Service EndpointSlices.
3. Relies on the verified quarantine NetworkPolicy to deny both ingress and egress.

The service checks that the named policy selects the quarantine label, declares both policy types, and has no ingress or egress allow rules. It refuses mutation if the operator has not explicitly attested to dataplane enforcement.

## High-risk eviction

Rule 100502 is configured as the immediate-eviction class in the Deployment ConfigMap. Deletion is restricted to unmanaged, explicitly labelled response-target Pods and uses a zero-second grace period. Controller-managed Pods are quarantined but preserved because their controllers may recreate a replacement Pod without the quarantine label. Rule 100501 is quarantine-only.

## GitOps boundary

- Falco rule source and its ConfigMap generator are under \`platform/falco/\`.
- Kubernetes namespace, constraints, RBAC, NetworkPolicies and Deployment are under \`platform/kubernetes/\`.
- Existing Phase 2 ConstraintTemplates remain the canonical templates and are applied from their existing source directory.
- GitHub Actions validates the Falco rule, OPA regression, Python tests, and PSS/Gatekeeper admission fixtures.
- A source-controlled ConfigMap does not prove that a live Falco DaemonSet has mounted or loaded it. The existing Helm release must be reconciled separately and its rendered/live configuration inspected.
