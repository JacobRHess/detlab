# T1021.002 — SMB admin shares (psexec / wmiexec)

**Tactic:** Lateral Movement
**Technique:** [T1021.002 — Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
**Tools simulated:** PsExec, wmiexec.py, SMBExec.py, Impacket

## What the attacker does

After credential acquisition, pivots laterally via SMB admin shares (ADMIN$ / IPC$). psexec / wmiexec / SMBExec all leave a tight conn.log fingerprint — one src touching many internal Windows boxes on TCP/445.

## What the defender sees in Zeek / Suricata

Per (1-h window, src) on TCP/445, count distinct internal destinations. Same shape as T1021.001 RDP but on SMB. Real production rule layers Zeek smb_files.log to require ADMIN$ / IPC$ pipe access.

## Detection logic

| Field | Threshold |
|---|---|
| `distinct internal SMB destinations` | ≥ 3 |

The Python detector
(`src/detlab/detector.py:detect_smb_lateral`) is the testable spec; the SPL macro
in `detection/macros.conf` is production.

## Files

- [`detection/search.spl`](detection/search.spl) — canonical reference
- [`detection/macros.conf`](detection/macros.conf) — `smb_lateral` macro
- [`detection/savedsearches.conf`](detection/savedsearches.conf) — schedule + Splunk ES integration
- [`detection/sigma.yml`](detection/sigma.yml) — Sigma cross-reference
- [`tests/test_detection.py`](tests/test_detection.py) — pytest case
- [`tests/positive_conn.log`](tests/positive_conn.log) — synthetic positive fixture
- [`tests/negative_conn.log`](tests/negative_conn.log) — synthetic negative fixture
- [`attack/`](attack/) — reproduction in the lab

## False-positive notes

- Backup software hitting many file shares on a schedule
- Patching / config-management orchestration (Ansible, GPO push)
- Bastion / jump hosts that fan out to many backends

## Tuning knobs

| Knob | Effect |
|---|---|
| `min_distinct_destinations` | Lower → catches narrower pivots, more FPs |
    | `window_seconds` | Larger → catches slower pivoting |
