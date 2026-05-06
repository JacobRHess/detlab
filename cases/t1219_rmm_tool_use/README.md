# T1219 — Remote Access Software (RMM)

**Tactic:** Command and Control
**Technique:** [T1219 — Remote Access Software](https://attack.mitre.org/techniques/T1219/)
**Tools simulated:** TeamViewer, AnyDesk, ScreenConnect, ConnectWise,
Splashtop, LogMeIn, Atera (any "trusted" remote-management SaaS)

## What the attacker does

Modern ransomware crews avoid dropping bespoke implants whenever possible.
Once they get a foothold, they install or re-use a legitimate Remote
Monitoring & Management (RMM) tool — usually a SaaS product — and operate
hands-on through it. Because the tool is signed, the binary is allow-listed
by EDR, the C2 traffic is normal-looking TLS to a normal-looking SaaS
domain. The defender has to look at the *fact of the connection itself*.

The DFIR Report and CISA have catalogued this technique extensively in
2023–2025 ransomware engagements — [BlackCat / ALPHV][1], LockBit, Royal,
and Akira have all leaned on AnyDesk and ScreenConnect as the
post-exploitation remote-access channel.

[1]: https://thedfirreport.com/2023/01/09/exchange-rmm-and-ransom/

## What the defender sees in Zeek

Per source over a 5-min window:

- One or more DNS resolutions of an RMM-tool domain
  (`*.teamviewer.com`, `*.anydesk.com`, `*.screenconnect.com`, etc.)
- The IPs returned are CDN-shaped (Akamai, Cloudflare, AWS) so destination-IP
  IOCs decay fast — domain-based detection ages better
- For users where RMM is *not* normal, even one resolution is interesting.
  For known help-desk hosts, populate `rmm_user_allowlist.csv`

This is the highest-signal IOC play in current SOC content because:

1. The domain list is small (~10 vendors cover ~95% of incidents).
2. The list is stable (vendors don't rotate domains the way C2 operators do).
3. False positives are operationally trivial to allow-list (HR knows who runs
   these tools legitimately).

## Detection logic

Group Zeek `dns.log` by `(5-min window, src)`, restricted to queries whose
base domain matches the RMM-domain lookup. For each group:

| Field | Threshold |
|---|---|
| `distinct_rmm_domains` | ≥ 1 |

The Python detector
(`src/detlab/detector.py:detect_rmm_tool_use`) is the testable spec; the
SPL macro in `detection/macros.conf` is production and uses the
`rmm_domains.csv` lookup that ships under `app/lookups/`.

## Files

- [`detection/search.spl`](detection/search.spl) — canonical reference
- [`detection/macros.conf`](detection/macros.conf) — `rmm_tool_use` macro
- [`detection/savedsearches.conf`](detection/savedsearches.conf) — schedule + Splunk ES risk action
- [`detection/sigma.yml`](detection/sigma.yml) — Sigma cross-reference
- [`tests/test_detection.py`](tests/test_detection.py) — pytest case
- [`tests/positive_dns.log`](tests/positive_dns.log) — synthetic RMM resolutions
- [`tests/negative_dns.log`](tests/negative_dns.log) — benign mixed DNS
- [`attack/`](attack/) — reproduction in the lab

## False-positive notes

Before alerting in production, exclude:

- Known help-desk / IT staff workstations with sanctioned RMM use
  (populate `rmm_user_allowlist.csv` per environment)
- Endpoints managed by an MSP — talk to the MSP first; their RMM is
  expected
- Software-installer telemetry that probes vendor domains during the
  binary's signature-check or update path

## Tuning knobs

| Knob | Effect |
|---|---|
| `min_distinct_rmm_domains` | 1 → most sensitive · 2+ → require multiple tools / sessions, fewer FPs |
| `window_seconds` | Smaller → catch tighter operator activity; larger → catch slow drips |
| Lookup freshness | New RMM products spin up regularly; review the list quarterly |
