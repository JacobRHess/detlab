# T1133 — External Remote Services abuse

**Tactic:** Persistence
**Technique:** [T1133 — External Remote Services](https://attack.mitre.org/techniques/T1133/)
**Tools simulated:** mstsc, FreeRDP, OpenVPN client, IKEv2 client

## What the attacker does

Uses stolen credentials to log in via the corporate VPN or RDP from an external IP. The DFIR Report calls valid-account-via-external-remote-services the #1 ransomware delivery path in 2024-2025 incidents.

## What the defender sees in Zeek / Suricata

External (non-RFC-1918) sources connecting inbound to internal hosts on remote-services ports {3389, 1194, 500, 4500, 1723}. In environments where the VPN concentrator is the only sanctioned external entry point, even one such connection is suspicious.

## Detection logic

| Field | Threshold |
|---|---|
| `source IP` | external (non-RFC-1918) |
    | `destination IP` | internal (RFC-1918) |
    | `dest port` | in {3389, 1194, 500, 4500, 1723} |
    | `distinct destinations per src per hour` | ≥ 1 |

The Python detector
(`src/detlab/detector.py:detect_external_remote_services`) is the testable spec; the SPL macro
in `detection/macros.conf` is production.

## Files

- [`detection/search.spl`](detection/search.spl) — canonical reference
- [`detection/macros.conf`](detection/macros.conf) — `external_remote_services` macro
- [`detection/savedsearches.conf`](detection/savedsearches.conf) — schedule + Splunk ES integration
- [`detection/sigma.yml`](detection/sigma.yml) — Sigma cross-reference
- [`tests/test_detection.py`](tests/test_detection.py) — pytest case
- [`tests/positive_conn.log`](tests/positive_conn.log) — synthetic positive fixture
- [`tests/negative_conn.log`](tests/negative_conn.log) — synthetic negative fixture
- [`attack/`](attack/) — reproduction in the lab

## False-positive notes

- Sanctioned VPN concentrator IP (allowlist as the only valid dest)
- Vendor / MSP IPs for managed-services contracts
- External pen-test engagement source IPs (coordinate before)

## Tuning knobs

| Knob | Effect |
|---|---|
| `remote_ports` | Add Citrix Gateway / etc. per environment |
    | `min_distinct_destinations` | Higher → require pivoting, fewer FPs |
