# T1090.003 — Multi-hop Proxy / Tor

**Tactic:** Command and Control
**Technique:** [T1090.003 — Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003/)
**Tool simulated:** [Tor](https://www.torproject.org/) (also matches I2P-style multi-relay
clients; the detection logic generalises to any IOC-driven relay enrichment).

## What the attacker does

Tor (and similar multi-hop proxies) routes a victim's traffic through three
relay hops chosen from the public consensus. Operators use Tor to anonymise
C2, beacon over `meek` or `obfs4` bridges, or pivot from a compromised host
into anonymous infrastructure. Clients rotate entry guards over the long
term and rebuild circuits every ~10 minutes, so over an hour a single Tor
client typically touches several distinct relay IPs.

## What the defender sees in Zeek

Per source over a long-enough window:

- Multiple connections to IPs that appear on a public relay/exit list
  (`torbulkexitlist`, onionoo)
- Per-connection duration and byte volume look like vanilla TLS — there is
  *no* signal in the payload (Tor encrypts both flows), so payload-based
  detections fail. The signal is the destination IP set
- Distinct relay IPs touched in a short window grow quickly because of
  consensus-rotation + circuit rebuilds; benign hosts almost never touch
  even one Tor relay IP

## Detection logic

Group Zeek `conn.log` by `(1-h bucket, src)`, restricted to destinations
that match the Tor relay lookup. For each group:

| Field | Threshold |
|---|---|
| `distinct_relays` | ≥ 3 |

The Python detector
(`src/detlab/detector.py:detect_tor_relay_use`) is the testable spec. The
SPL macro in `detection/macros.conf` is production and uses the
`tor_relays.csv` lookup that ships under `app/lookups/`.

The lab ships **synthetic** lab-only relay IPs in
[`app/lookups/tor_relays.csv`](../../app/lookups/tor_relays.csv) so tests
are hermetic. In production replace this lookup with a feed driven by
[`torbulkexitlist`](https://check.torproject.org/torbulkexitlist) on a
cron — the relay set rotates and a stale lookup is the most common
cause of false negatives.

## Files

- [`detection/search.spl`](detection/search.spl) — canonical reference
- [`detection/macros.conf`](detection/macros.conf) — `tor_relay_use` macro
- [`detection/savedsearches.conf`](detection/savedsearches.conf) — schedule
- [`detection/sigma.yml`](detection/sigma.yml) — Sigma cross-reference
- [`tests/test_detection.py`](tests/test_detection.py) — pytest case
- [`tests/positive_conn.log`](tests/positive_conn.log) — synthetic Tor client touching 6 lab relays
- [`tests/negative_conn.log`](tests/negative_conn.log) — benign HTTPS browsing, zero relay overlap
- [`attack/`](attack/) — reproduction in the lab

## False-positive notes

Before alerting in production, exclude:

- Researchers / employees with sanctioned Tor use (CTI teams, journalism
  programs) — populate `tor_user_allowlist.csv` per environment
- VPN or proxy providers that route through Tor exits as part of their
  anti-abuse mitigations
- Threat-intel platforms that ingest the Tor consensus and probe relays
  for liveness — these will walk the relay set by design

## Tuning knobs

| Knob | Effect |
|---|---|
| `min_distinct_relays` | Lower → catches casual Tor users, more FPs |
| `window_seconds` | Larger → catches very slow clients, slower to alert |
| Lookup freshness | Stale lookup → silent failure; refresh on a cron |
