# T1046 — Network Service Discovery

**Tactic:** Discovery
**Technique:** [T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046/)
**Tools simulated:** [nmap](https://nmap.org), [masscan](https://github.com/robertdavidgraham/masscan)

## What the attacker does

After a foothold, attackers map out reachable services on the local network.
The fastest way is a TCP SYN scan: a half-open probe to each candidate port,
read the response, move on. nmap's `-sS` and masscan default to this
behaviour. The result is one source touching tens-to-hundreds of distinct
destination ports on a single host (or a few hosts) inside a tight time
window.

## What the defender sees in Zeek

Per (src, dest) within a single time bucket:

- High distinct-destination-port cardinality (≥ 100 in 60 s is well outside
  any normal traffic to a single host)
- Most connections never complete the TCP handshake — Zeek records
  `conn_state` of `S0` (SYN, no reply), `REJ` (port closed), `RSTO` (peer
  RST after SYN), etc. Successful sessions (`SF`) are a minority
- Very short per-connection durations and zero or near-zero payload bytes

A single noisy field is easy to fake; the *combination* — high port
cardinality plus a high incomplete-handshake fraction — is the scan
signature.

## Detection logic

Group Zeek `conn.log` by `(60-s bucket, src, dest)`. For each group:

| Field | Threshold |
|---|---|
| `distinct_ports` | ≥ 100 |
| `incomplete_fraction` (S0/REJ/RSTO/RSTOS0/RSTRH/RSTR/SH/SHR) | ≥ 0.7 |

The Python detector (`src/detlab/detector.py:detect_port_scan`) is the
testable spec; the SPL macro in `detection/macros.conf` is production.

## Files

- [`detection/search.spl`](detection/search.spl) — canonical reference
- [`detection/macros.conf`](detection/macros.conf) — `network_service_discovery` macro
- [`detection/savedsearches.conf`](detection/savedsearches.conf) — schedule
- [`detection/sigma.yml`](detection/sigma.yml) — Sigma cross-reference
- [`tests/test_detection.py`](tests/test_detection.py) — pytest case
- [`tests/positive_conn.log`](tests/positive_conn.log) — synthetic SYN scan, 200 ports / 30 s
- [`tests/negative_conn.log`](tests/negative_conn.log) — mixed benign HTTP/HTTPS conns
- [`attack/`](attack/) — reproduction in the lab

## False-positive notes

Before alerting in production, exclude:

- Vulnerability scanners (Nessus, Qualys, internal pentest agents) — these
  produce identical telemetry by design; populate
  `scanner_allowlist.csv` with their source IPs
- Service health-check sweeps from monitoring platforms
- Load-balancer / API-gateway hosts that legitimately probe many backend
  ports (uncommon but seen)

## Tuning knobs

| Knob | Effect |
|---|---|
| `min_distinct_ports` | Lower → catches stealthier short scans, more FPs |
| `min_incomplete_fraction` | Lower → catches connect-scans (full handshake), more FPs |
| `window_seconds` | Larger → catches slow scans, slower to alert |
