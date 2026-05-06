# T1213.002 — Information-Repository bulk read (Confluence / SharePoint)

**Tactic:** Collection
**Technique:** [T1213.002 — Data from Information Repositories: Sharepoint](https://attack.mitre.org/techniques/T1213/002/)
**Tools simulated:** Confluence-Thief, SharePoint-Pillager, custom Python+requests

## What the attacker does

Systematically scrapes internal Confluence / SharePoint for credentials, runbooks, network diagrams, and administrator documentation during the post-compromise discovery phase. The DFIR Report has documented this in multiple ransomware engagements as a primary pre-encryption recon step.

## What the defender sees in Zeek / Suricata

Per (1-h window, src, dest) where dest is a known internal info-repo host (confluence.lab, sharepoint.lab, wiki.lab), count distinct URI paths. Tooling hits hundreds of paths in minutes — humans read maybe a dozen.

## Detection logic

| Field | Threshold |
|---|---|
| `distinct URI paths per src per hour` | ≥ 100 |

The Python detector
(`src/detlab/detector.py:detect_info_repo_bulk_read`) is the testable spec; the SPL macro
in `detection/macros.conf` is production.

## Files

- [`detection/search.spl`](detection/search.spl) — canonical reference
- [`detection/macros.conf`](detection/macros.conf) — `info_repo_bulk_read` macro
- [`detection/savedsearches.conf`](detection/savedsearches.conf) — schedule + Splunk ES integration
- [`detection/sigma.yml`](detection/sigma.yml) — Sigma cross-reference
- [`tests/test_detection.py`](tests/test_detection.py) — pytest case
- [`tests/positive_http.log`](tests/positive_http.log) — synthetic positive fixture
- [`tests/negative_http.log`](tests/negative_http.log) — synthetic negative fixture
- [`attack/`](attack/) — reproduction in the lab

## False-positive notes

- Confluence search-bots / link-checkers (allowlist by User-Agent)
- Backup / export jobs that walk the page tree
- Migration tooling (CQL exports, Confluence-to-Notion etc.)

## Tuning knobs

| Knob | Effect |
|---|---|
| `min_distinct_paths` | Lower → catches narrower scrapes, more FPs |
    | `info_repo_hosts` | Per-environment list of internal info repos |
