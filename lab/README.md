# Lab

Docker-Compose stack that runs Splunk + Zeek + Suricata so you can replay
captured PCAPs (or generate fresh attack telemetry) and watch detections fire
end-to-end.

## Bring-up

```bash
# From repo root:
cd lab
LAB_IFACE=eth0 docker compose up -d   # set LAB_IFACE to your sensor interface

# Wait ~30s for Splunk first-run init, then:
open http://localhost:8000      # admin / changemenow
```

## Replaying a fixture into Splunk

Each case ships positive/negative Zeek dns.log fixtures under
`cases/<id>/tests/`. To replay one against the live Splunk:

```bash
# Copy the fixture into the path Splunk monitors
cp ../cases/t1071_004_dns_c2_dnscat2/tests/positive_dns.log \
   ./data/zeek/current/dns.log

# Then run the saved search from the Splunk UI, or from the CLI:
docker exec detlab-splunk /opt/splunk/bin/splunk search \
  '| savedsearch "DNS Tunnel — High-Entropy Subdomain Volume"' \
  -auth admin:changemenow
```

## Caveats

- `network_mode: host` on Zeek and Suricata means they need a real interface
  to listen on. On Windows / Docker Desktop, prefer running Zeek directly on
  a captured PCAP instead: `zeek -r mycap.pcap local.zeek`.
- Splunk Enterprise runs on the perpetual free tier here (500MB/day index
  volume). Plenty for a lab; will throttle if you ingest a large pcap.
- Don't expose this stack to the internet — `SPLUNK_PASSWORD` is in plaintext
  in the compose file and admin auth is on by default but lab-grade.
