# T1595.003 — Web wordlist scanning

**Tactic:** Reconnaissance
**Technique:** [T1595.003 — Active Scanning: Wordlist Scanning](https://attack.mitre.org/techniques/T1595/003/)
**Tools simulated:** gobuster, dirb, ffuf

## What the attacker does

Walks a wordlist of common URI paths against a target web app. Most paths 404; the few that 200 are the foothold. The defender sees the 404 burst — a bot trying hundreds of paths in seconds.

## What the defender sees in Zeek / Suricata

Per (60-s window, src, dest), filter Zeek http.log to status_code=404 and count distinct URI paths. Wordlist scanners hit dozens of unique paths in seconds; benign 404s never cluster.

## Detection logic

| Field | Threshold |
|---|---|
| `distinct 404 URI paths` | ≥ 50 |

The Python detector
(`src/detlab/detector.py:detect_web_wordlist`) is the testable spec; the SPL macro
in `detection/macros.conf` is production.

## Files

- [`detection/search.spl`](detection/search.spl) — canonical reference
- [`detection/macros.conf`](detection/macros.conf) — `web_wordlist_scan` macro
- [`detection/savedsearches.conf`](detection/savedsearches.conf) — schedule + Splunk ES integration
- [`detection/sigma.yml`](detection/sigma.yml) — Sigma cross-reference
- [`tests/test_detection.py`](tests/test_detection.py) — pytest case
- [`tests/positive_http.log`](tests/positive_http.log) — synthetic positive fixture
- [`tests/negative_http.log`](tests/negative_http.log) — synthetic negative fixture
- [`attack/`](attack/) — reproduction in the lab

## False-positive notes

- Search engines / good-citizen crawlers (allowlist by User-Agent)
- Internal QA / functional-testing harnesses
- Stale browser bookmarks for a relaunched app

## Tuning knobs

| Knob | Effect |
|---|---|
| `min_distinct_404_paths` | Lower → catches narrower scans, more FPs |
    | `window_seconds` | Larger → catches slower scans, slower to alert |
