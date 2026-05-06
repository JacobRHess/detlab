# T1048.003 — Exfiltration Over Unencrypted Non-C2 Protocol (DNS)

**Tactic:** Exfiltration
**Technique:** [T1048.003 — Exfiltration Over Unencrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/003/)
**Tools simulated:** [iodine](https://github.com/yarrick/iodine),
[dnsteal](https://github.com/m57/dnsteal),
[dns-shell](https://github.com/sensepost/godoh)

## What the attacker does

Encodes data to exfiltrate inside the leftmost label of DNS queries, sends
queries against an attacker-controlled base domain, and reads zero or
trivial responses (an `A` record is enough — the goal is to *push* bytes,
not pull). Distinct from `dnscat2`-style C2 (T1071.004): exfiltration is
volume-driven and frequently uses **`A` records** specifically to dodge
detections that key on `TXT` traffic.

## What the defender sees in Zeek

Per (src, base_domain) over a short window:

- High aggregate subdomain-byte volume — well past 30 KB/min for any
  meaningful exfil. Vanilla DNS rarely puts more than a kilobyte of label
  bytes through one base domain in a minute even at peak
- Subdomains routinely run near the 63-byte label limit
- `qtype` = `A` is the common case (the technique deliberately avoids the
  TXT-record signal that flagged dnscat2)
- The tool fires fast — a few seconds to a minute of bursty queries to
  push a small file out

## Detection logic

Group Zeek `dns.log` by `(60-s bucket, src, base_domain)`. For each group:

| Field | Threshold |
|---|---|
| `query_count` | ≥ 30 |
| `total_subdomain_bytes` | ≥ 30 000 (≈ 500 B/s sustained) |
| `avg_sub_len` | ≥ 50 (DNS label max is 63 — anything ≥ 50 is pathological) |

The Python detector
(`src/detlab/detector.py:detect_dns_exfil`) is the testable spec; the
SPL macro in `detection/macros.conf` is production.

This rule is **complementary** to T1071.004 dnscat2: T1071.004 keys on
TXT/MX/CNAME qtypes + entropy + structure; T1048.003 keys on raw byte
volume regardless of qtype. A real DNS-tunnel tool may fire both.

## Files

- [`detection/search.spl`](detection/search.spl) — canonical reference
- [`detection/macros.conf`](detection/macros.conf) — `dns_exfil_volume` macro
- [`detection/savedsearches.conf`](detection/savedsearches.conf) — schedule
- [`detection/sigma.yml`](detection/sigma.yml) — Sigma cross-reference
- [`tests/test_detection.py`](tests/test_detection.py) — pytest case
- [`tests/positive_dns.log`](tests/positive_dns.log) — synthetic A-record exfil, ~80 KB / 60 s
- [`tests/negative_dns.log`](tests/negative_dns.log) — mixed benign DNS
- [`attack/`](attack/) — reproduction in the lab

## False-positive notes

Before alerting in production, exclude:

- DNSBL / RBL lookups (long randomised subdomains by design)
- Cloud antivirus / EDR DNS-reputation services (Cisco Umbrella, Akamai EDC)
- DNS-based content delivery that embeds tokens or manifests in subdomain labels
- Legitimate authoritative-DNS health-check probes

## Tuning knobs

| Knob | Effect |
|---|---|
| `min_total_subdomain_bytes` | Lower → catches slower exfil, more FPs |
| `min_avg_sub_len` | Lower → catches shorter-label exfil tools, more FPs |
| `window_seconds` | Larger → catches very slow drains, slower to alert |
