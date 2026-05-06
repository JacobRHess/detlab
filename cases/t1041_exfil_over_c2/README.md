# T1041 — Exfiltration Over C2 Channel

**Tactic:** Exfiltration
**Technique:** [T1041 — Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)
**Tools simulated:** Sliver, Cobalt Strike, custom HTTPS implants — any
operator who reuses the established C2 channel to exfiltrate data instead
of standing up a separate exfil destination.

## What the attacker does

After the implant is installed and beaconing, operators dump files,
credentials, and DB exports back through the *same* C2 connection
they're using for command-and-control. The destination is already
allow-listed (the beacon's been talking for hours); the byte volume is
the only signal that something heavier than periodic check-ins is
happening.

## Why this case is structurally different

This is detlab's first **chained detection** — it depends on
`detect_beaconing` (T1071.001) having already flagged the (src, dest)
pair as a C2 channel. The detector then looks for high-`orig_bytes`
connections to those flagged pairs and emits a single high-severity
alert that names *both* pieces of evidence.

This is the "risk accumulation" pattern Splunk Enterprise Security
shops use in practice. Beaconing alone is medium-confidence (some
legitimate apps beacon); large uplink volume alone is medium-confidence
(some legitimate apps push big data). The intersection — beaconing
*and* a large uplink to the *same* destination — is high-confidence and
worth waking up the on-call SOC analyst.

## What the defender sees in Zeek

Per (src, dest) pair already flagged by the beacon rule:

- One or more conn.log records with `orig_bytes` ≥ 10 KB (an order of
  magnitude larger than typical beacon check-ins, which are 200–2000 B)
- Cumulative `orig_bytes` ≥ 100 KB across the window (filters out
  one-off retry packets that crossed the per-record threshold)

## Detection logic

Two stages:

1. **Beacon prerequisite:** run the T1071.001 detection (loose threshold:
   `min_connections=30`, `max_coefficient_of_variation=0.15` — slightly
   more permissive than the standalone rule to catch lightly-jittered
   beacons).
2. **Exfil signal among beacon pairs:** for each connection to a
   beaconing (src, dest), keep records with `orig_bytes ≥ 10_000`. Sum
   per pair; alert if total ≥ 100 KB.

| Field | Threshold |
|---|---|
| beacon connections | ≥ 30 |
| beacon CoV | ≤ 0.15 |
| per-record `orig_bytes` | ≥ 10 000 |
| cumulative `orig_bytes` | ≥ 100 000 |

The Python detector
(`src/detlab/detector.py:detect_c2_exfil`) is the testable spec. The
SPL macro (`detection/macros.conf`) implements the chain via a Splunk
subsearch — that's how Splunk does composition idiomatically.

## Files

- [`detection/search.spl`](detection/search.spl) — canonical reference
- [`detection/macros.conf`](detection/macros.conf) — `c2_exfil` macro (uses subsearch over `http_beacon_jitter`)
- [`detection/savedsearches.conf`](detection/savedsearches.conf) — schedule + Splunk ES notable + risk
- [`detection/sigma.yml`](detection/sigma.yml) — Sigma cross-reference
- [`tests/test_detection.py`](tests/test_detection.py) — pytest case
- [`tests/positive_conn.log`](tests/positive_conn.log) — synthetic beacon + exfil-burst overlay
- [`tests/negative_conn.log`](tests/negative_conn.log) — benign traffic + a big file download (must NOT fire)
- [`attack/`](attack/) — reproduction in the lab

## False-positive notes

- Cloud-agent uploads on a fixed cadence (Datadog, Splunk forwarders,
  AWS CloudWatch agent) — these legitimately beacon AND legitimately
  push bytes. Populate `c2_exfil_allowlist.csv` with known
  agent-source pairs
- VPN keep-alives + bulk transfers through the VPN tunnel
- Backup software that maintains a persistent control channel + uses it
  for the actual data movement

## Tuning knobs

| Knob | Effect |
|---|---|
| `min_exfil_total_bytes` | Lower → catches drip-style exfil, more FPs |
| `min_exfil_orig_bytes_per_record` | Lower → catches smaller chunks, more FPs |
| beacon CoV threshold | Higher → catches jittered beacons, more candidate pairs to evaluate |
