# T1583.001 — Newly-Registered Domain (NRD) resolution

**Tactic:** Resource Development
**Technique:** [T1583.001 — Acquire Infrastructure: Domains](https://attack.mitre.org/techniques/T1583/001/)
**Tools simulated:** attacker-side: any registrar; defender-side: WHOXY, DomainTools, Farsight

## What the attacker does

Registers a fresh domain immediately before campaign launch — phishing, malware C2, or watering-hole — to dodge static blocklists. The domain has no reputation history because it didn't exist a week ago.

## What the defender sees in Zeek / Suricata

Per (24-h window, src) on Zeek dns.log, lookup base_domain against newly_registered_domains.csv (refreshed nightly from a WHOIS feed). Catches the first outbound resolution to any domain registered in the last 7 days.

## Detection logic

| Field | Threshold |
|---|---|
| `distinct NRD resolutions per src per day` | ≥ 1 |

The Python detector
(`src/detlab/detector.py:detect_newly_registered_domain`) is the testable spec; the SPL macro
in `detection/macros.conf` is production.

## Files

- [`detection/search.spl`](detection/search.spl) — canonical reference
- [`detection/macros.conf`](detection/macros.conf) — `nrd_resolution` macro
- [`detection/savedsearches.conf`](detection/savedsearches.conf) — schedule + Splunk ES integration
- [`detection/sigma.yml`](detection/sigma.yml) — Sigma cross-reference
- [`tests/test_detection.py`](tests/test_detection.py) — pytest case
- [`tests/positive_dns.log`](tests/positive_dns.log) — synthetic positive fixture
- [`tests/negative_dns.log`](tests/negative_dns.log) — synthetic negative fixture
- [`attack/`](attack/) — reproduction in the lab

## False-positive notes

- Marketing campaigns that intentionally use fresh microsite domains
- CI/CD / cloud orchestration that creates throwaway DNS names
- Ephemeral CDN / cache subdomains

## Tuning knobs

| Knob | Effect |
|---|---|
| `min_distinct_nrd` | Higher → require multiple NRD hits, fewer FPs |
    | `nrd_set` | Refresh feed nightly via cron |
