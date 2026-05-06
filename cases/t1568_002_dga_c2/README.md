# T1568.002 — Domain Generation Algorithms (DGA)

**Tactic:** Command and Control
**Technique:** [T1568.002 — Dynamic Resolution: Domain Generation Algorithms](https://attack.mitre.org/techniques/T1568/002/)
**Tools simulated:** Conficker, Necurs, Murofet, Banjori (any
DGA-driven malware family)

## What the attacker does

Generates a daily list of pseudo-random domain names with a deterministic
seed, queries them all, finds the one the operator pre-registered, and
uses it for C2. The operator only needs to register one of the day's
domains; the implant tries them in order until something resolves. The
defender sees a single host fire tens-to-hundreds of unique base-domain
queries — most resolving NXDOMAIN — over a short window.

## What the defender sees in Zeek

Per source over a short window:

- 30+ distinct *base* domains queried (e.g. `kqxzbvm.com`, `wjqzpx.net`,
  `mfntqxc.org`) — base entropy is high, no English words
- Most queries return NXDOMAIN (≥ 50%)
- The second-level label (`kqxzbvm` in `kqxzbvm.com`) has high Shannon
  entropy — well above 3.5 bits/char vs. English-like domains

Distinct from T1071.004 dnscat2: dnscat2 fires high-entropy *subdomain*
queries against a single base domain. DGA fires queries against many
high-entropy *base* domains.

## Detection logic

Group Zeek `dns.log` by `(5-min window, src)`. For each group:

| Field | Threshold |
|---|---|
| `distinct_domains` | ≥ 30 |
| `avg_domain_entropy` (per second-level label) | ≥ 3.3 |
| `nxdomain_fraction` | ≥ 0.5 |

The Python detector
(`src/detlab/detector.py:detect_dga_domains`) is the testable spec; the
SPL macro in `detection/macros.conf` is production.

## Files

- [`detection/search.spl`](detection/search.spl) — canonical reference
- [`detection/macros.conf`](detection/macros.conf) — `dga_c2_lookup` macro
- [`detection/savedsearches.conf`](detection/savedsearches.conf) — schedule
- [`detection/sigma.yml`](detection/sigma.yml) — Sigma cross-reference
- [`tests/test_detection.py`](tests/test_detection.py) — pytest case
- [`tests/positive_dns.log`](tests/positive_dns.log) — synthetic DGA burst, 50 unique high-entropy domains
- [`tests/negative_dns.log`](tests/negative_dns.log) — mixed benign DNS
- [`attack/`](attack/) — reproduction in the lab

## False-positive notes

Before alerting in production, exclude:

- CDN / content delivery domains that use random-looking 2nd-level labels
  (some Akamai, Fastly, Cloudflare patterns)
- Email-tracking / pixel-tracking domains
- Microsoft / Apple telemetry endpoints (some look DGA-shape)
- Rapidly-spawned ephemeral cloud workload DNS

The macro accepts a `dga_allowlist.csv` lookup hook for known noisy
domains.

## Tuning knobs

| Knob | Effect |
|---|---|
| `min_distinct_domains` | Lower → catches small DGA bursts, more FPs |
| `min_avg_entropy` | Lower → catches less-random DGA families, more FPs |
| `min_nxdomain_fraction` | Lower → catches DGAs whose operator registers many domains, more FPs |
| `window_seconds` | Larger → catches very slow DGAs, slower to alert |
