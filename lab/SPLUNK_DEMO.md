# End-to-end Splunk demo

Drives a live Splunk instance to prove every shipped detection actually
fires on its own fixture. The Python detector mirror in
`src/detlab/detector.py` validates detection *logic* in CI; this demo
validates detection *deployment* — the SPL macros, saved searches, and
ATT&CK metadata round-trip through a real Splunk + HEC + REST API.

## What you'll have at the end

A Splunk instance with:

- The detlab app installed under `/opt/splunk/etc/apps/detlab/`
- All 13 case fixtures ingested into `index=zeek` and `index=suricata`
  via the HTTP Event Collector
- All 13 saved searches dispatched, polled, and reporting alert counts
- Dashboards live at <http://localhost:8000/en-US/app/detlab/overview>

The expected output of `splunk_demo.py run`:

```
detlab Splunk demo · running 13 saved searches
  target: https://localhost:8089

  ✓ DNS Tunnel — High-Volume High-Entropy Subdomain                 1 alert  (T1071.004)
  ✓ HTTP Beaconing — Low-Jitter Periodic Connections                1 alert  (T1071.001)
  ✓ Network Service Discovery — High-Cardinality Port Probing       1 alert  (T1046)
  ✓ Protocol Tunneling — Long-Lived High-Throughput HTTP/S Flow     1 alert  (T1572)
  ✓ Tor / Multi-hop Proxy — Distinct Relay Count                    1 alert  (T1090.003)
  ✓ DNS Exfiltration — High-Volume Subdomain Bytes                  1 alert  (T1048.003)
  ✓ SSH Brute Force — High-Rate Short SSH Connections               1 alert  (T1110.001)
  ✓ DGA C2 — High-Cardinality NXDOMAIN Bursts                       1 alert  (T1568.002)
  ✓ Remote Access Software (RMM) — DNS Resolution                   1 alert  (T1219)
  ✓ Volumetric Network Flood — Single-Target Connection Burst       1 alert  (T1499.001)
  ✓ Exploit Attempt — Suricata IDS Alert Aggregation                3 alerts (T1190)
  ✓ Exfiltration Over C2 Channel — Beacon + High Uplink Bytes       1 alert  (T1041)
  ✓ Cloud Storage Exfiltration — High Uplink to Cloud-Storage IPs   1 alert  (T1567.002)

✓ 13/13 fired   ·   total alerts: 15
  Open dashboards: http://localhost:8000/en-US/app/detlab/overview
```

## Prereqs

- Docker Desktop (Windows / macOS) or Docker Engine (Linux) running
- Python 3.11+ (for `py scripts/...`)
- ~4 GB free RAM for the Splunk container

## Walkthrough

### 1. Build the detlab app

```bash
py scripts/build_app.py
```

Produces `app/default/{macros,savedsearches,correlationsearches,
analyticstories,eventtypes,tags,workflow_actions}.conf`,
`app/lookups/detlab_cases.csv`, and the `.spl` tarball under `build/`.

### 2. Bring up the lab

```bash
cd lab
docker compose up -d
```

The compose file mounts `../app/` into the Splunk container at
`/opt/splunk/etc/apps/detlab/`, so the app is available the moment
Splunk finishes starting (about 90 seconds the first time).

Watch the startup:

```bash
docker logs -f detlab-splunk
# Wait for: "Ansible playbook complete, will begin streaming splunkd_stderr.log"
```

### 3. Configure HEC

Splunk Web at <http://localhost:8000> (login `admin` / `changemenow`):

1. **Settings → Data Inputs → HTTP Event Collector**
2. Click **Global Settings** → set **All Tokens** = enabled, **Default Source Type** = whatever, **Default Index** = `main`. Save.
3. Click **New Token**. Name = `detlab-demo`. Source type = automatic.
   Allowed indexes = `zeek` + `suricata` + `main`. Save.
4. Copy the token value (looks like `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`).

The first time you do this, also create the indexes:

1. **Settings → Indexes → New Index**
2. Create `zeek` (default app: detlab, default everything else)
3. Create `suricata` (same)

### 4. Drive the demo

Export the HEC token, then run:

```bash
export SPLUNK_HEC_TOKEN=<token-from-step-3>
# Bash on Windows: same syntax above. PowerShell:
#   $env:SPLUNK_HEC_TOKEN = "<token>"

# Load all positive fixtures into Splunk
py scripts/splunk_demo.py load

# Wait ~5 s for Splunk to index them, then fire every saved search
py scripts/splunk_demo.py run

# Or do both in one go (waits 5 s automatically between)
py scripts/splunk_demo.py all
```

### 5. Open the dashboards

After the run finishes, every case has an alert in Splunk. Open:

- <http://localhost:8000/en-US/app/detlab/overview> — KPI cards + recent
  detections feed
- <http://localhost:8000/en-US/app/detlab/detections> — filterable feed
  of all alerts
- <http://localhost:8000/en-US/app/detlab/attack_coverage> — ATT&CK
  coverage matrix
- Per-case dashboards from the **Cases** menu

### 6. Tear down

```bash
cd lab && docker compose down -v
```

The `-v` drops the named volumes too — next start will be fresh.

## What's wired up automatically

The compose file mounts `../app/` into the Splunk container, so
**reinstalling** the app is just `py scripts/build_app.py` followed by a
container restart (`docker compose restart splunk`). No upload, no REST
API call, no `splunk apply cluster-bundle`. Splunk picks up the changed
confs on next start.

The detlab app's `props.conf` ships the Zeek + Suricata sourcetype
definitions, so HEC events with `"sourcetype": "zeek:dns"` etc. land
with the right field aliases (`src`, `dest`, etc.) the moment they're
indexed — no per-environment configuration required.

## Troubleshooting

**HEC: "Token is required" or HTTP 401**
- HEC isn't enabled globally, or the token is disabled. Step 3 above.

**`splunk_demo.py run` returns 0 alerts for everything**
- Splunk hasn't finished indexing yet. Wait 10 s and re-run.
- Time range mismatch — fixtures use synthetic 2024 timestamps. Override:
  `py scripts/splunk_demo.py run --earliest 2024-01-01T00:00:00 --latest now`

**HTTP 401 from `splunk_demo.py run`**
- Management password isn't the compose default. Set
  `SPLUNK_PASSWORD=<your-password>` and re-run.

**SSL verification errors**
- The script trusts self-signed certs by default (`_ssl_ctx()` in
  `splunk_demo.py`). For production you should swap that for a
  verified-cert context.

## Recording / sharing the demo

Run the demo once locally, screenshot the terminal output of
`splunk_demo.py run` and the **Overview** dashboard, drop them into
the README. The terminal output is the strongest single artifact —
13 saved searches firing on real Splunk via REST is much better
evidence than "trust me, the SPL works".
