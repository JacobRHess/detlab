# T1071.001 — HTTP Beaconing (Sliver)

**Tactic:** Command and Control
**Technique:** [T1071.001 — Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
**Tool simulated:** [Sliver](https://github.com/BishopFox/sliver) (also matches Cobalt Strike default profiles, Empire, Mythic-stock HTTP)

## What the attacker does

Sliver implants check in to an HTTP/HTTPS C2 listener at a configured
interval (default 60s, randomised by a `Jitter` percentage). Each call
fetches new tasking; the implant returns output via POST. Defaults: GET to
`/` plus a few path variants, User-Agent rotated from a small list. The
*timing* is the strongest signal — humans don't browse on a metronome.

## What the defender sees in Zeek

Per (src, dest) pair, over a long-enough window:

- High connection count (30+ over 10 min with a 60s default callback)
- Inter-connection intervals are tightly clustered (low coefficient of
  variation: `stddev(intervals) / mean(intervals)` < 0.1)
- Average interval looks like a callback cadence (10s–10min)

A jittered beacon (e.g. Sliver `--jitter 30`) raises the CoV; a 30% jitter
typically pushes CoV past 0.15 and we miss it without lowering the
threshold. The detection's tuning knobs let you trade FP rate against
jitter coverage.

## Detection logic

Group Zeek `conn.log` (or `http.log`) by `(src, dest)`. For each group:

| Field | Threshold |
|---|---|
| `connection_count` | ≥ 30 |
| `avg_interval` | ≤ 600 s (10 min) |
| `coefficient_of_variation` | ≤ 0.1 |
| `duration` | ≥ 600 s (window must span enough to be meaningful) |

The Python detector (`src/detlab/detector.py:detect_beaconing`) is the
testable spec; the SPL macro in `detection/macros.conf` is production.

## Files

- [`detection/search.spl`](detection/search.spl) — canonical reference
- [`detection/macros.conf`](detection/macros.conf) — `http_beacon_jitter` macro
- [`detection/savedsearches.conf`](detection/savedsearches.conf) — schedule
- [`detection/sigma.yml`](detection/sigma.yml) — Sigma cross-reference
- [`tests/test_detection.py`](tests/test_detection.py) — pytest case
- [`tests/positive_conn.log`](tests/positive_conn.log) — synthetic Sliver-shape conns
- [`tests/negative_conn.log`](tests/negative_conn.log) — synthetic mixed-traffic conns
- [`attack/`](attack/) — reproduction in the lab

## False-positive notes

- Health-check pollers (Pingdom, internal monitoring agents)
- NTP / time sync (very regular by design — exclude port 123)
- IoT firmware update checks
- Cloud agents that beacon home (AWS SSM, Azure Arc, Datadog)

The macro filters obvious management traffic by destination port; populate
`beacon_allowlist.csv` per environment for src→dest pairs that are
legitimately on a metronome.

## Tuning knobs

| Knob | Effect |
|---|---|
| `min_connections` | Lower → catches shorter sessions, more FPs |
| `max_coefficient_of_variation` | Higher → catches jittered beacons, more FPs |
| `max_avg_interval` | Higher → catches very slow beacons |
| `min_duration_seconds` | Higher → fewer FPs, slower to alert |
