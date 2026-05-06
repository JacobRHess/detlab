# T1595.002 — Vulnerability scanning

**Tactic:** Reconnaissance
**Technique:** [T1595.002 — Active Scanning: Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002/)
**Tools simulated:** Nessus, Qualys, Nikto, OpenVAS, sqlmap, nuclei, zgrab

## What the attacker does

Scans the public-facing surface for known CVEs and misconfigurations before launching exploits. Loud and easy to spot when the IDS catches the scanner's User-Agent or signature.

## What the defender sees in Zeek / Suricata

Suricata IDS alerts whose signature mentions a scanner tool name (nessus / qualys / nikto / openvas / scan / scanner) AND fall in scan-shape categories. Per (1-h window, src), count distinct signatures; >= 5 distinct = a sweep, not a one-off.

## Detection logic

| Field | Threshold |
|---|---|
| `distinct scanner signatures per src per hour` | ≥ 5 |
    | `alert.category` | scan-shape (Information Leak / Web Attack / etc.) |
    | `signature keyword` | scan / scanner / nessus / qualys / nikto / openvas |

The Python detector
(`src/detlab/detector.py:detect_vuln_scan`) is the testable spec; the SPL macro
in `detection/macros.conf` is production.

## Files

- [`detection/search.spl`](detection/search.spl) — canonical reference
- [`detection/macros.conf`](detection/macros.conf) — `vuln_scanning` macro
- [`detection/savedsearches.conf`](detection/savedsearches.conf) — schedule + Splunk ES integration
- [`detection/sigma.yml`](detection/sigma.yml) — Sigma cross-reference
- [`tests/test_detection.py`](tests/test_detection.py) — pytest case
- [`tests/positive_eve.log`](tests/positive_eve.log) — synthetic positive fixture
- [`tests/negative_eve.log`](tests/negative_eve.log) — synthetic negative fixture
- [`attack/`](attack/) — reproduction in the lab

## False-positive notes

- Internal vulnerability-management infrastructure (allowlist)
- Bug bounty researchers with sanctioned scope
- Continuous-asset-discovery tools (Censys / Shodan workers)

## Tuning knobs

| Knob | Effect |
|---|---|
| `min_distinct_signatures` | Higher → require sustained scanning, fewer FPs |
    | `scan_signature_keywords` | Add new scanner-tool names per environment |
