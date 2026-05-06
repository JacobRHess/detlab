# T1021.001 — Remote Desktop Protocol (lateral)

**Tactic:** Lateral Movement
**Technique:** [T1021.001 — Remote Services: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/)
**Tools simulated:** mstsc, FreeRDP, Hydra (after credential success), any
ransomware operator's RDP-pivot playbook.

## What the attacker does

After landing a foothold and harvesting credentials, the operator pivots
laterally via Remote Desktop. RDP is allow-listed on most internal
Windows networks (sysadmins use it daily) so the binary doesn't fire
EDR and the destination port is unremarkable. The signal is the
*pattern of pivoting*: one source touching multiple distinct internal
Windows boxes in a short window.

The DFIR Report has documented this as the dominant lateral-movement
signature in 2023–2025 ransomware engagements (BlackCat, Akira, Royal,
LockBit), often paired with credential dumps from LSASS or Mimikatz.

## What the defender sees in Zeek

Per source over a 1-hour window, filtered to TCP/3389:

- 3+ distinct internal destinations contacted
- `conn_state` = `SF` (full handshakes; auth happens inside TLS)
- Multi-minute durations on each session (operator hands-on-keyboard)
- High `resp_bytes` (the operator pulls remote-desktop framebuffers)

## Distinct from T1110.001 SSH brute force

Both are remote-services detections, but the shapes are different:

| | T1110.001 SSH brute | T1021.001 RDP lateral |
|---|---|---|
| Port | 22 | 3389 |
| Pattern | One src → one dest, many short conns | One src → many dests, few long conns |
| Timing | ≥ 20 attempts in 60 s | ≥ 3 distinct dests in 1 h |
| Bytes | Small (auth flows) | Large (framebuffer streams) |

## Detection logic

Group Zeek `conn.log` by `(1-h window, src)` filtered to
`id.resp_p = 3389`. For each group:

| Field | Threshold |
|---|---|
| `distinct_destinations` | ≥ 3 |

The Python detector
(`src/detlab/detector.py:detect_rdp_lateral`) is the testable spec; the
SPL macro in `detection/macros.conf` is production.

## Files

- [`detection/search.spl`](detection/search.spl) — canonical reference
- [`detection/macros.conf`](detection/macros.conf) — `rdp_lateral` macro
- [`detection/savedsearches.conf`](detection/savedsearches.conf) — schedule + Splunk ES notable + risk
- [`detection/sigma.yml`](detection/sigma.yml) — Sigma cross-reference
- [`tests/test_detection.py`](tests/test_detection.py) — pytest case
- [`tests/positive_conn.log`](tests/positive_conn.log) — synthetic 5-host pivot
- [`tests/negative_conn.log`](tests/negative_conn.log) — benign IT-admin RDP usage
- [`attack/`](attack/) — reproduction in the lab

## False-positive notes

- IT admins / jump hosts that legitimately RDP into many machines.
  Populate `rdp_admin_allowlist.csv` with their source IPs.
- Vulnerability scanners + asset inventory tools that RDP-probe many
  hosts (less common — most scanners use port-probe-only).
- Scheduled Patch Tuesday workflows where automation hits many machines.

## Tuning knobs

| Knob | Effect |
|---|---|
| `min_distinct_destinations` | Lower → catches narrower pivots, more FPs |
| `window_seconds` | Larger → catches slower pivoting, slower to alert |
| `dest_port` | Repurpose for VNC (5900), WinRM (5985/5986) |
