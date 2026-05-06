# T1090.001 — Internal proxy / SOCKS chaining

**Tactic:** Defense Evasion
**Technique:** [T1090.001 — Proxy: Internal Proxy](https://attack.mitre.org/techniques/T1090/001/)
**Tools simulated:** chisel, SSF, tinyproxy, custom Python proxies

## What the attacker does

Stands up an internal pivot to obfuscate east-west traffic — SOCKS proxy on a compromised host that the operator routes lateral connections through. Defeats simple src→dest IP-pair reasoning.

## What the defender sees in Zeek / Suricata

Per (1-h window, src) on internal proxy ports {1080, 3128, 8080, 8888, 9050}, count distinct internal destinations. Operators chain through 3+ pivot hosts; benign tools hit at most one.

## Detection logic

| Field | Threshold |
|---|---|
| `distinct internal pivot destinations` | ≥ 3 |

The Python detector
(`src/detlab/detector.py:detect_internal_proxy`) is the testable spec; the SPL macro
in `detection/macros.conf` is production.

## Files

- [`detection/search.spl`](detection/search.spl) — canonical reference
- [`detection/macros.conf`](detection/macros.conf) — `internal_proxy_chain` macro
- [`detection/savedsearches.conf`](detection/savedsearches.conf) — schedule + Splunk ES integration
- [`detection/sigma.yml`](detection/sigma.yml) — Sigma cross-reference
- [`tests/test_detection.py`](tests/test_detection.py) — pytest case
- [`tests/positive_conn.log`](tests/positive_conn.log) — synthetic positive fixture
- [`tests/negative_conn.log`](tests/negative_conn.log) — synthetic negative fixture
- [`attack/`](attack/) — reproduction in the lab

## False-positive notes

- Allowed corporate proxy clients (allowlist by src IP)
- Internal CI/CD agents that route through a fixed proxy
- Mobile / VPN clients with a forced internal proxy config

## Tuning knobs

| Knob | Effect |
|---|---|
| `min_distinct_destinations` | Lower → catches narrower pivots, more FPs |
    | `window_seconds` | Larger → catches slower pivoting, slower to alert |
    | `proxy_ports` | Add internal known proxy ports per environment |
