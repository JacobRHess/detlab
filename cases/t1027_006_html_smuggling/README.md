# T1027.006 — HTML Smuggling delivery

**Tactic:** Execution
**Technique:** [T1027.006 — Obfuscated Files or Information: HTML Smuggling](https://attack.mitre.org/techniques/T1027/006/)
**Tools simulated:** Phishing kits, Mythic / SharpFiles, custom JS-encoded HTML loaders

## What the attacker does

Phishing payloads delivered as JavaScript-encoded blobs that decode client-side via blob.url + SaveAs. Bypasses WAF / proxy file-type checks because the wire payload is HTML+JS, not the ZIP / EXE that ends up on disk.

## What the defender sees in Zeek / Suricata

Suricata IDS alerts whose signature mentions HTML smuggling / blob.url / SaveAs blob patterns. ET signatures cover the well-known kit families; per (1-h window, src, dest), aggregate.

## Detection logic

| Field | Threshold |
|---|---|
| `Suricata alert signature contains keywords` | html smuggl / blob.url / SaveAs blob |
    | `alerts per (src, dest, window)` | ≥ 1 |

The Python detector
(`src/detlab/detector.py:detect_html_smuggling`) is the testable spec; the SPL macro
in `detection/macros.conf` is production.

## Files

- [`detection/search.spl`](detection/search.spl) — canonical reference
- [`detection/macros.conf`](detection/macros.conf) — `html_smuggling` macro
- [`detection/savedsearches.conf`](detection/savedsearches.conf) — schedule + Splunk ES integration
- [`detection/sigma.yml`](detection/sigma.yml) — Sigma cross-reference
- [`tests/test_detection.py`](tests/test_detection.py) — pytest case
- [`tests/positive_eve.log`](tests/positive_eve.log) — synthetic positive fixture
- [`tests/negative_eve.log`](tests/negative_eve.log) — synthetic negative fixture
- [`attack/`](attack/) — reproduction in the lab

## False-positive notes

- Legitimate web apps that genuinely use blob.url (Google Drive uploaders, etc.)
- Internal pen-test / phishing-simulation traffic

## Tuning knobs

| Knob | Effect |
|---|---|
| `keywords` | Tune per environment as new HTML-smuggling techniques emerge |
