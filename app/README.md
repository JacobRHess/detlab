# detlab — Splunk app

A deployable Splunk app aggregating all detlab detections, macros, and
dashboards. Built from `cases/` by `scripts/build_app.py`.

## Install

```bash
# From repo root: build the app
py scripts/build_app.py

# Output: build/detlab-<version>.tar.gz

# Install on Splunk (REST):
curl -k -u admin:<pw> -X POST https://<splunk>:8089/services/apps/local \
    -d filename=true -d update=true \
    --data-urlencode "name=$(pwd)/build/detlab-0.2.0.tar.gz"

# OR via UI: Apps > Manage Apps > Install app from file
```

After install, restart Splunk and visit
`http://<splunk>:8000/en-US/app/detlab/overview`.

## Layout

```
app/
├── default/
│   ├── app.conf
│   ├── savedsearches.conf      # built — aggregates all cases/*/detection/savedsearches.conf
│   ├── macros.conf             # built — aggregates all cases/*/detection/macros.conf
│   └── data/ui/
│       ├── nav/default.xml
│       └── views/
│           ├── overview.xml
│           ├── detections.xml
│           ├── attack_coverage.xml
│           ├── case_dnscat2.xml
│           └── case_http_beacon.xml
├── metadata/default.meta
└── README.md
```

`savedsearches.conf` and `macros.conf` are gitignored where they're built —
the canonical source is each case's `detection/` folder. Run `build_app.py`
to regenerate before packaging.

## Required indexes

The app expects these indexes on the target Splunk (see
`lab/splunk/indexes.conf` for definitions):

- `zeek` — Zeek JSON logs (sourcetypes: zeek:dns, zeek:conn, zeek:http, zeek:ssl)
- `suricata` — Suricata eve.json (sourcetype: suricata:eve)

## Required field aliases

Detections use the Splunk Zeek TA convention (`src`, `dest`) — `props.conf`
in `lab/splunk/` provides these aliases for fresh installs.
