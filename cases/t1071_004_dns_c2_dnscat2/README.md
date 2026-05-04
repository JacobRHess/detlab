# T1071.004 — DNS C2 via dnscat2

**Tactic:** Command and Control
**Technique:** [T1071.004 — Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/)
**Tool simulated:** [dnscat2](https://github.com/iagox86/dnscat2)

## What the attacker does

dnscat2 establishes a command-and-control channel over DNS by tunnelling
encoded payload bytes inside DNS queries. The server is authoritative for an
attacker-controlled domain (`c2.evil.example` here); the implant sends one
query per command/response chunk, encoding data in the leftmost label of each
query name. To maximise per-query bandwidth dnscat2 prefers `TXT` records
(largest response payload) and packs each subdomain near the 63-byte label
limit.

## What the defender sees in Zeek

Per source host, against a single base domain, over a short window:

- High query volume (50+ queries / 5 min is well outside normal DNS for any
  single base domain from a single host)
- Subdomains that are long (≥20 chars on average, often 40+) and look random
  (high Shannon entropy, ≥3.5 — base32-ish encoded data, not English)
- Most queries are `TXT` (or `MX`, `CNAME`, `NULL`)
- Each query is unique (no repeats — every query carries fresh payload)

Any one of those signals alone is noisy. The combination is dnscat2-shaped.

## Detection logic

Group Zeek `dns.log` records by `(5-min bucket, src, base_domain)`. For each
group compute:

| Field | Threshold |
|---|---|
| `query_count` | ≥ 50 |
| `avg_sub_len` | ≥ 20 |
| `avg_entropy` | ≥ 3.5 |
| `unique_queries` | ≥ 30 |
| `qtypes ∩ {TXT, MX, CNAME, NULL}` | non-empty |

All five conditions must hold. The Python detector
(`src/detlab/detector.py:detect_dns_tunnel`) is the testable spec; the SPL
in `detection/search.spl` is the production artifact.

## Files

- [`detection/search.spl`](detection/search.spl) — production SPL search
- [`detection/savedsearches.conf`](detection/savedsearches.conf) — schedule + alert action
- [`detection/macros.conf`](detection/macros.conf) — `shannon_entropy` SPL macro
- [`detection/sigma.yml`](detection/sigma.yml) — portable Sigma cross-reference
- [`tests/test_detection.py`](tests/test_detection.py) — pytest case
- [`tests/positive_dns.log`](tests/positive_dns.log) — synthetic dnscat2 traffic
- [`tests/negative_dns.log`](tests/negative_dns.log) — synthetic benign DNS
- [`attack/`](attack/) — how to reproduce in the lab

## False-positive notes

Before alerting in production, exclude:

- DNSBL / RBL lookups (lots of long randomized subdomains by design)
- Cloud antivirus / EDR DNS-based reputation (Cisco Umbrella, Akamai EDC)
- Some CDN auth / token flows that embed long tokens in subdomains
- DNS-over-HTTPS resolver health checks

The SPL ships with a `dns_allowlist` lookup hook — populate it per
environment.

## Tuning knobs

| Knob | Effect |
|---|---|
| `min_query_count` | Lower → catches slower beacons, more FPs |
| `min_avg_entropy` | Lower → catches non-base32 encodings, more FPs |
| `window_seconds` | Larger → catches very slow beacons, slower to alert |
