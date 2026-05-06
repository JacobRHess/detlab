# T1110.001 — SSH Brute Force (password guessing)

**Tactic:** Credential Access
**Technique:** [T1110.001 — Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
**Tools simulated:** [hydra](https://github.com/vanhauser-thc/thc-hydra),
[medusa](https://github.com/jmk-foofus/medusa),
[ncrack](https://nmap.org/ncrack/)

## What the attacker does

Throws a wordlist of credentials at an exposed SSH server, hoping one
sticks. Each attempt is a complete TCP handshake (TCP looks healthy) but
auth fails — the tool closes the connection and tries the next pair.
Public-internet SSH endpoints see this constantly; the lab signal is the
*rate* and *volume* of short-duration SSH connections from a single
source.

## What the defender sees in Zeek

Per (src, dest, dest_port=22) inside a short window:

- 20+ connections in 60 s (most brute forcers run faster than 1 attempt
  per second; `hydra -t 16` does 16 parallel)
- Each connection is short — ≤ 5 s on average — because the auth fail
  path closes quickly
- `conn_state` = `SF` (full handshake) is the common case; auth happens
  inside the encrypted channel so Zeek can't see the result

## Detection logic

Group Zeek `conn.log` by `(60-s window, src, dest)` filtered to
`id.resp_p = 22`. For each group:

| Field | Threshold |
|---|---|
| `connection_count` | ≥ 20 |
| `avg_duration_seconds` | ≤ 5 |

The Python detector (`src/detlab/detector.py:detect_ssh_brute_force`) is
the testable spec; the SPL macro in `detection/macros.conf` is
production.

This rule is **distinct** from T1046 port scanning by port-cardinality
(1 port here vs. 100+ for a scan) and from T1071.001 beaconing by the
short-duration shape (Sliver beacons are sparse, brute force is dense
and short).

## Files

- [`detection/search.spl`](detection/search.spl) — canonical reference
- [`detection/macros.conf`](detection/macros.conf) — `ssh_brute_force` macro
- [`detection/savedsearches.conf`](detection/savedsearches.conf) — schedule
- [`detection/sigma.yml`](detection/sigma.yml) — Sigma cross-reference
- [`tests/test_detection.py`](tests/test_detection.py) — pytest case
- [`tests/positive_conn.log`](tests/positive_conn.log) — synthetic hydra-shape, 60 attempts / 60 s
- [`tests/negative_conn.log`](tests/negative_conn.log) — benign SSH usage, long sessions
- [`attack/`](attack/) — reproduction in the lab

## False-positive notes

Before alerting in production, exclude:

- Automated CI/CD jobs that reconnect frequently (Ansible, runbooks)
- Health-check pollers that probe SSH on a cadence
- Bastion/jump hosts that fan out from one source IP to many backends —
  the *count* may match but the dest set distinguishes them

The macro accepts a `ssh_allowlist.csv` lookup hook for known automation
sources.

## Tuning knobs

| Knob | Effect |
|---|---|
| `min_attempts` | Lower → catches stealthy slow brute force, more FPs |
| `max_avg_duration_seconds` | Higher → catches "patient" tools, more FPs |
| `dest_port` | Repurpose for RDP (3389), SMB (445), etc. |
