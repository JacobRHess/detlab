# T1499.001 — Direct Network Flood

**Tactic:** Impact
**Technique:** [T1499.001 — Endpoint Denial of Service: OS Exhaustion Flood](https://attack.mitre.org/techniques/T1499/001/)
**Tools simulated:** `hping3`, `t50`, `pktgen-dpdk` (any volumetric flood
generator)

## What the attacker does

Hammers a single victim with a torrent of TCP SYN, UDP, or ICMP packets
to exhaust the OS connection table or saturate the upstream link.
Distinct from a scan: a flood targets *one port* (often 80 / 443) with
*many connections per second*; a scan targets *many ports* with *few
connections per port*.

## What the defender sees in Zeek

Per (src, dest, dest_port) inside a single one-second window:

- 100+ connection attempts in 1 s
- Connections terminate fast — `conn_state` of `S0` (no SYN-ACK) for
  closed-port floods, `SF` (rapid handshake) for stress-tests against
  open ports
- Tiny per-record byte counts because the attacker isn't trying to send
  data, just exhaust resources

The "one source, one (dest, port), many connections per second" pattern
is the cleanest flood signature on conn.log.

## Detection logic

Group Zeek `conn.log` by `(1-second bucket, src, dest, dest_port)`. For
each group:

| Field | Threshold |
|---|---|
| `connection_count` | ≥ 100 |

The Python detector
(`src/detlab/detector.py:detect_volumetric_flood`) is the testable spec;
the SPL macro in `detection/macros.conf` is production.

This rule is **distinct** from T1046 port scanning (port-cardinality vs.
single-port volume) and T1110.001 SSH brute force (60-s window for
auth-rate vs. 1-s window for flood).

## Files

- [`detection/search.spl`](detection/search.spl) — canonical reference
- [`detection/macros.conf`](detection/macros.conf) — `volumetric_flood` macro
- [`detection/savedsearches.conf`](detection/savedsearches.conf) — schedule
- [`detection/sigma.yml`](detection/sigma.yml) — Sigma cross-reference
- [`tests/test_detection.py`](tests/test_detection.py) — pytest case
- [`tests/positive_conn.log`](tests/positive_conn.log) — synthetic 200-pps SYN flood
- [`tests/negative_conn.log`](tests/negative_conn.log) — benign mixed traffic
- [`attack/`](attack/) — reproduction in the lab

## False-positive notes

- Load-test traffic from CI / staging environments hitting one production
  endpoint
- Buggy clients in retry storms (mobile apps with no exponential backoff)
- Internal queue-flush spikes from misbehaving services

The macro accepts a `flood_allowlist.csv` lookup hook for known
load-generator sources.

## Tuning knobs

| Knob | Effect |
|---|---|
| `min_connections` | Lower → catches smaller floods, more FPs |
| `window_seconds` | Larger → catches slower-cadence floods, slower to alert |
