# T1567.002 — Exfiltration to Cloud Storage Service

**Tactic:** Exfiltration
**Technique:** [T1567.002 — Exfiltration Over Web Service: Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002/)
**Tools simulated:** rclone, robocopy + cloud sync, native cloud-storage
clients (Mega, Dropbox, WeTransfer, AnonFiles, Gofile, Transfer.sh,
pCloud, MediaFire, etc.)

## What the attacker does

Stages stolen data on commodity cloud storage before encryption /
ransom. The destination is a legitimate, often-allowlisted SaaS — the
operator chose it precisely because the egress firewall doesn't block
it and EDR doesn't flag the binary. The DFIR Report and CISA have
catalogued this as the standard pre-encryption exfil step in 2023–2025
ransomware engagements (BlackCat, LockBit, Akira, Royal).

## What the defender sees in Zeek

Per source over a 1-hour window:

- One or more conn.log records to a known cloud-storage IP
- `orig_bytes` per record well above normal browsing (≥ 1 MB)
- Cumulative `orig_bytes` across all such records crossing 50 MB
- Direction matters — large *uplink* (orig_bytes), not large download
  (resp_bytes). A user pulling a 50 MB Dropbox file does not fire this
  rule

## Why uplink, not download?

The IP-IOC alone is too noisy — many users legitimately read from
Dropbox / Mega. The volume gate on `orig_bytes` selects for the
*data-staging* pattern specifically. Combined, the false-positive rate
collapses to known-IT-staff workstations only (allow-list those).

## Detection logic

Group Zeek `conn.log` by `(1-h window, src, cloud_service)` filtered to
records where `id.resp_h` is in the cloud-storage IP lookup. For each
group:

| Field | Threshold |
|---|---|
| `orig_bytes` per record | ≥ 1 MB |
| cumulative `orig_bytes` | ≥ 50 MB |

The Python detector
(`src/detlab/detector.py:detect_cloud_exfil`) is the testable spec; the
SPL macro in `detection/macros.conf` is production and uses the
`cloud_storage_ips.csv` lookup that ships under `app/lookups/`.

## Files

- [`detection/search.spl`](detection/search.spl) — canonical reference
- [`detection/macros.conf`](detection/macros.conf) — `cloud_exfil` macro
- [`detection/savedsearches.conf`](detection/savedsearches.conf) — schedule + Splunk ES notable + risk
- [`detection/sigma.yml`](detection/sigma.yml) — Sigma cross-reference
- [`tests/test_detection.py`](tests/test_detection.py) — pytest case
- [`tests/positive_conn.log`](tests/positive_conn.log) — synthetic 75 MB rclone-shape uplink to Mega
- [`tests/negative_conn.log`](tests/negative_conn.log) — benign traffic + big downloads (must NOT fire)
- [`attack/`](attack/) — reproduction in the lab

## False-positive notes

- Sanctioned cloud-storage workflows (sales sharing decks via WeTransfer,
  marketing posting to Dropbox). Populate `cloud_user_allowlist.csv` per
  environment
- DevOps / build pipelines that push artifacts to cloud blobs from a
  build runner — pin those source IPs as expected
- Backup software pushing to cloud destinations on a schedule

## Tuning knobs

| Knob | Effect |
|---|---|
| `min_orig_bytes_per_record` | Lower → catches drip-style staging, more FPs |
| `min_total_orig_bytes` | Lower → catches smaller heists, more FPs |
| `window_seconds` | Larger → catches very slow exfil, slower to alert |
| Lookup freshness | New cloud-storage SaaS spawns regularly; review the IP set quarterly |
