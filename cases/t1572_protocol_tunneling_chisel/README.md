# T1572 — Protocol Tunneling (chisel)

**Tactic:** Command and Control
**Technique:** [T1572 — Protocol Tunneling](https://attack.mitre.org/techniques/T1572/)
**Tool simulated:** [chisel](https://github.com/jpillora/chisel) (also matches gost,
[wstunnel](https://github.com/erebe/wstunnel), and other HTTP/WebSocket tunnels)

## What the attacker does

Tunnels arbitrary TCP traffic through a single long-lived HTTP(S)
WebSocket. The server lives on `:80` or `:443` so egress firewalls treat
it like normal web traffic; the implant pipes interactive shells, port
forwards, or SOCKS proxying through that one connection. Unlike a beacon
this is a *persistent* flow — a single TCP session that stays up for
minutes, hours, or days while the operator works.

## What the defender sees in Zeek

Per Zeek `conn.log` record:

- A single TCP flow on port 80, 443, 8080, or 8443
- `duration` measured in minutes-to-hours, not seconds
- Both `orig_bytes` and `resp_bytes` in the millions or higher — far past
  what a normal browser session moves in one connection
- `service` = `http` or `ssl` and `conn_state` = `SF` so the connection
  itself looks unremarkable

## Detection logic

Per-record (no aggregation needed): flag any conn.log entry where
*all* hold:

| Field | Threshold |
|---|---|
| `id.resp_p` | ∈ {80, 443, 8080, 8443} |
| `duration` | ≥ 600 s (10 min) |
| `orig_bytes + resp_bytes` | ≥ 10 MB |

The Python detector
(`src/detlab/detector.py:detect_protocol_tunnel`) is the testable spec;
the SPL macro in `detection/macros.conf` is production.

## Files

- [`detection/search.spl`](detection/search.spl) — canonical reference
- [`detection/macros.conf`](detection/macros.conf) — `protocol_tunnel_chisel` macro
- [`detection/savedsearches.conf`](detection/savedsearches.conf) — schedule
- [`detection/sigma.yml`](detection/sigma.yml) — Sigma cross-reference
- [`tests/test_detection.py`](tests/test_detection.py) — pytest case
- [`tests/positive_conn.log`](tests/positive_conn.log) — synthetic 2-hour, ~200 MB tunnel flow
- [`tests/negative_conn.log`](tests/negative_conn.log) — benign HTTPS browsing
- [`attack/`](attack/) — reproduction in the lab

## False-positive notes

Before alerting in production, exclude:

- Long-running streaming media (Twitch, YouTube live, large video calls)
- Software updates and large downloads — single-direction byte ratios make
  these distinguishable, but the simple threshold here will flag them
- VPN/SaaS clients that hold a persistent HTTPS session (Zoom keep-alives,
  Slack websockets) — typically modest bytes; populate
  `tunnel_allowlist.csv` per environment
- CI runner / build agent connections to artifact stores

## Tuning knobs

| Knob | Effect |
|---|---|
| `min_duration_seconds` | Lower → catches shorter tunnels, more FPs |
| `min_total_bytes` | Lower → catches low-throughput interactive tunnels, more FPs |
| `common_ports` | Add 22, 53, etc. to widen coverage; these have their own FP profiles |
