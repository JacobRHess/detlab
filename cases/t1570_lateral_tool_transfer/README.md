# T1570 — Lateral Tool Transfer

**Tactic:** Lateral Movement
**Technique:** [T1570 — Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570/)
**Tools simulated:** SMB writes, scp, robocopy, raw HTTP uploads

## What the attacker does

Copies the operator's toolkit between compromised hosts. Internal east-west large-uplink transfers are unusual — legitimate east-west bulk usually flows file-server → user, not user → user.

## What the defender sees in Zeek / Suricata

Per Zeek conn.log record between two RFC-1918 hosts where orig_bytes >= 5 MB. Flag any such record. The per-record style (no aggregation) keeps the rule cheap.

## Detection logic

| Field | Threshold |
|---|---|
| `orig_bytes (uplink)` | ≥ 5 MB |
    | `both src and dest` | RFC 1918 (internal-internal) |

The Python detector
(`src/detlab/detector.py:detect_lateral_tool_transfer`) is the testable spec; the SPL macro
in `detection/macros.conf` is production.

## Files

- [`detection/search.spl`](detection/search.spl) — canonical reference
- [`detection/macros.conf`](detection/macros.conf) — `lateral_tool_transfer` macro
- [`detection/savedsearches.conf`](detection/savedsearches.conf) — schedule + Splunk ES integration
- [`detection/sigma.yml`](detection/sigma.yml) — Sigma cross-reference
- [`tests/test_detection.py`](tests/test_detection.py) — pytest case
- [`tests/positive_conn.log`](tests/positive_conn.log) — synthetic positive fixture
- [`tests/negative_conn.log`](tests/negative_conn.log) — synthetic negative fixture
- [`attack/`](attack/) — reproduction in the lab

## False-positive notes

- Backup software pushing to a backup target
- VM image / artifact distribution from a build host
- Database replication (allow-list known DB hosts)

## Tuning knobs

| Knob | Effect |
|---|---|
| `min_orig_bytes` | Lower → catches smaller transfers, more FPs |
