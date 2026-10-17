# Falco-to-Wazuh Integration Evidence

## Purpose

This directory is for sanitized, reproducible evidence of the Phase 3 path from a controlled Falco runtime event to a Wazuh manager alert. It must contain only artifacts actually captured from the lab. Do not add fabricated sample output or copy credentials, tokens, private keys, or unrelated host logs.

## Current validation status

The live test demonstrated this path for a controlled filesystem-write event:

1. Falco detected a write below `/etc/aegis-test` inside the active `falco-runtime-test-active` Pod. The test process ran as UID/GID `65532`.
2. The Kali forwarder appended Falco JSON to `/var/log/aegis/falco-events.jsonl`.
3. Wazuh agent `kali-aegis-lab` collected the file as JSON and forwarded it.
4. Wazuh manager rule `100501` at level `8` generated an alert in `/var/ossec/logs/alerts/alerts.json`.

This is evidence of ingestion and manager rule matching for the specific controlled events. It is not proof of comprehensive runtime coverage or production readiness.

For the filesystem-write test, a manager alert was observed at `2026-10-17T10:18:02.871+0000` for a Falco event timestamped `2026-10-17T10:18:02.097373391Z`, a difference of `773.626609 ms` (approximately `774 ms`). For the shell test, the manager alert was observed at `2026-10-17T10:37:46.008+0000` for a Falco event timestamped `2026-10-17T10:37:45.756102876Z`, a difference of approximately `251.897 ms`. Each is a single event-timestamp comparison, not a latency benchmark; capture both hosts' UTC clock state before making broader timing claims.

Sanitized normalized excerpts from the collector and manager queries are committed as `falco-event-sanitized.json`, `wazuh-alert-sanitized.json`, `shell-event-sanitized.json`, and `shell-alert-sanitized.json`. The reviewed custom rule source is stored at `../../falco/aegis-runtime-write.yaml`; the live ConfigMap change should be incorporated into the deployment's declarative configuration before future Helm upgrades or cluster recreation. Wazuh indexer ingestion and dashboard visibility are not yet verified. UTC clock state, service/configuration captures, JSONL validation counts, and the final checksum manifest remain to be added.

## Evidence capture checklist

Capture from the Kali VM and the Ubuntu Wazuh manager separately. Keep the raw source event and alert only if reviewed for sensitive data. Prefer a minimal sanitized excerpt containing event timestamp, rule name, relevant file path, Pod/namespace, agent name, Wazuh rule ID and level. Redact public/private addresses, usernames, host identifiers, and unrelated event fields where they are not needed to reproduce the finding.

### Kali VM

Record:

- UTC/local clock state and Unix epoch, to support later timestamp comparisons.
- Forwarder systemd status and the specific forwarder configuration/script version used.
- Wazuh agent status and the localfile JSON collection stanza for `/var/log/aegis/falco-events.jsonl`.
- JSONL validation counts: total lines, valid JSON records, and invalid records.
- Fresh controlled filesystem-write and shell-event Falco records identified by unique markers, not merely the newest events in the file.
- SHA-256 checksums for the sanitized evidence files.

Example safe inspection commands:

```bash
date
date -u
date +%s
timedatectl
systemctl is-active aegis-falco-forwarder
systemctl is-active wazuh-agent
```

For JSONL validation, use a line-by-line parser so the result includes the number of valid records and any malformed line numbers:

```bash
python3 - <<'PY'
import json
from pathlib import Path
p = Path("/var/log/aegis/falco-events.jsonl")
total = valid = 0
invalid = []
with p.open() as f:
    for n, line in enumerate(f, 1):
        if not line.strip():
            continue
        total += 1
        try:
            json.loads(line)
            valid += 1
        except json.JSONDecodeError:
            invalid.append(n)
print(f"nonempty_lines={total} valid_json={valid} invalid_json={len(invalid)}")
if invalid:
    print("invalid_line_numbers=" + ",".join(map(str, invalid[:50])))
PY
```

### Ubuntu Wazuh manager

Record:

- UTC/local clock state and Unix epoch.
- Successful validation of Wazuh analysis configuration.
- Sanitized alerts for rules `100501` and `100502` matching their respective fresh marker events.
- Alert count for rule `100501` before and after the test, if this can be obtained without exposing unrelated alerts.
- Service status and any relevant indexer/dashboard check results.
- SHA-256 checksums for the sanitized evidence files.

Example checks:

```bash
date
date -u
date +%s
timedatectl
sudo /var/ossec/bin/wazuh-analysisd -t
sudo jq -c 'select(.rule.id == "100501")' /var/ossec/logs/alerts/alerts.json | tail -n 1
```

The alert file is newline-delimited JSON, so `jq` can process each alert record. If the query returns no output, do not infer that an alert exists. Inspect the actual record and verify the `rule.id`, `rule.level`, agent, source location, unique event marker, and original Falco timestamp. Field types can vary; adjust the rule-ID comparison only after inspecting a real record.

## Suggested artifact names

Use only after creating the corresponding real artifacts:

- `kali-clock-and-service-status.txt`
- `falco-event-sanitized.json` (captured and committed)
- `wazuh-agent-config-sanitized.xml`
- `manager-clock-and-analysis-check.txt`
- `wazuh-alert-sanitized.json`
- `shell-event-sanitized.json`
- `shell-alert-sanitized.json`
- `SHA256SUMS.txt`

## Integrity and scope

After sanitizing and reviewing each captured artifact, run `sha256sum` over the evidence files and save the output as `SHA256SUMS.txt`. Recompute the checksum file whenever its contents change. Do not claim that a checksum proves authenticity; it supports integrity checking after capture.

This evidence is a lab validation record. It does not claim detection of all container threats, production-scale reliability, complete alert correlation, or confirmed dashboard/indexer delivery unless those are separately tested and evidenced.
