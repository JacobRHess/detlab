# Attack reproduction — Tor client

Run a Tor client on a lab host so Zeek records connections to the public
relay set; pull a fresh `torbulkexitlist` and load it as the Splunk lookup
so the detection has the matching IOCs.

## Prereqs

- Lab compose stack running (Splunk + Zeek)
- Tor Browser or the standalone `tor` daemon on a victim host

## Run (high level)

```bash
# Quick path — Tor Browser auto-bootstraps and connects out
# (any Linux/Mac/Windows host on the lab subnet)
tor-browser --headless &

# OR the daemon
tor &
```

## Refresh the relay lookup

```bash
curl -fsSL https://check.torproject.org/torbulkexitlist \
  | awk 'BEGIN{print "ip,relay_type"} {print $1",exit"}' \
  > app/lookups/tor_relays.csv

# In production, schedule this hourly and reload via Splunk REST.
```

## Capture telemetry into a fixture

```bash
docker exec detlab-zeek cat /usr/local/zeek/logs/current/conn.log \
  | jq -c "select((.\"id.resp_h\" | IN($TOR_IPS)) and (.\"id.orig_h\" == \"<victim_ip>\"))" \
  > /tmp/tor_capture.log
head -200 /tmp/tor_capture.log > tests/positive_conn.log
```

## Safety / scope

- Lab use only. Tor itself is legal in most jurisdictions; running it for
  detection development is unambiguously defensive work.
- The synthetic `tests/positive_conn.log` and lab relay IPs in the lookup
  are generated so the test suite is hermetic and the lookup has no
  external dependency. Replace the lookup with a real `torbulkexitlist`
  feed before relying on this in production.
