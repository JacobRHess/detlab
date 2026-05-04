# detlab

[![CI](https://github.com/JacobRHess/detlab/actions/workflows/ci.yml/badge.svg)](https://github.com/JacobRHess/detlab/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)

**A network-detection lab for Splunk.** Each *case* is a self-contained folder
that pairs a reproducible network attack with the Splunk detection that
catches it on real captured telemetry — every rule ships with the thing it
catches. The repo also ships a deployable Splunk app (dashboards, saved
searches, ATT&CK coverage matrix) built from the per-case content.

Focused on **network-visible** ATT&CK techniques: Command & Control,
Exfiltration, Discovery, Lateral Movement.

## Why this exists

Most public Sigma repos give you a rule and call it done. This repo answers
"how do you know it actually works?" by shipping each detection alongside:

1. A reproducible attack (script, container, or hardware setup)
2. Captured telemetry from running that attack
3. A Splunk-native detection (SPL macro + saved search + Sigma cross-reference)
4. A per-case Splunk dashboard with input filters and drill-downs
5. Positive / negative test fixtures + CI that proves the rule fires on
   the attack and stays quiet on benign traffic

The result is a portfolio of detections that are *demonstrable*, not just
*declared*.

## Layout

```
detlab/
├── lab/                              # docker-compose: Splunk + Zeek + Suricata
│   ├── docker-compose.yml            # mounts app/ into Splunk for live dev
│   ├── splunk/                       # indexes.conf, inputs.conf, props.conf
│   └── zeek/local.zeek
├── src/detlab/                       # Python detection runner (Shannon entropy,
│                                     # Zeek loader, detect_dns_tunnel, detect_beaconing)
├── cases/
│   ├── t1071_004_dns_c2_dnscat2/     # one ATT&CK technique per folder
│   │   ├── README.md
│   │   ├── attack/
│   │   ├── detection/                # search.spl, macros.conf, savedsearches.conf, sigma.yml
│   │   └── tests/                    # positive_*.log, negative_*.log, test_detection.py
│   └── t1071_001_http_beacon_sliver/
├── shared/macros.conf                # cross-case macros (detlab_all_alerts)
├── app/                              # Splunk app — built from cases/ + shared/
│   ├── default/
│   │   ├── app.conf
│   │   └── data/ui/
│   │       ├── nav/default.xml
│   │       └── views/                # overview, detections, attack_coverage, per-case
│   ├── lookups/                      # detlab_cases.csv (built)
│   └── metadata/default.meta
├── scripts/
│   ├── build_app.py                  # cases/ + shared/ -> app/ + .spl tarball
│   └── generate_fixtures.py          # synthetic Zeek fixtures (regen as needed)
├── tests/                            # cross-cutting tests + build pipeline tests
├── .github/workflows/ci.yml          # ruff + pytest + build, py 3.11/3.12
└── pyproject.toml
```

## Quickstart

```bash
git clone https://github.com/JacobRHess/detlab && cd detlab
pip install -e ".[dev]"

# Run the test suite (validates every case's detection logic against fixtures)
pytest -q

# Build the deployable Splunk app
py scripts/build_app.py
# -> build/detlab-<version>.tar.gz, ready to install via Splunk UI/REST

# Spin up the lab (Splunk on http://localhost:8000, admin / changemenow)
cd lab && LAB_IFACE=eth0 docker compose up -d
# The compose file mounts app/ into /opt/splunk/etc/apps/detlab for live dev.
```

After install, browse to `http://localhost:8000/en-US/app/detlab/overview`
for the main dashboard.

## Dashboards (in the Splunk app)

| View | Purpose |
|---|---|
| **Overview** | KPI cards (alerts, sources, techniques covered), timechart by case, recent-detections table with drill-down |
| **Detections** | Filterable feed of all alerts (by case / source / time) with severity colour-coding |
| **ATT&CK Coverage** | Matrix of techniques mapped to cases — shipped vs planned, drills to per-case dashboard or attack.mitre.org |
| **Per-case** | Filtered drill-down for each technique with detection details, raw-event viz, and FP notes |

## Cases

| Case | ATT&CK | Tactic | Status |
|---|---|---|---|
| [DNS C2 via dnscat2](cases/t1071_004_dns_c2_dnscat2/) | T1071.004 | Command & Control | **shipped** |
| [HTTP beaconing (Sliver)](cases/t1071_001_http_beacon_sliver/) | T1071.001 | Command & Control | **shipped** |
| Protocol tunneling (chisel)   | T1572     | Command & Control | planned |
| Tor proxy use                 | T1090.003 | Command & Control | planned |
| Network service discovery     | T1046     | Discovery         | planned |
| Exfil over DNS                | T1048.003 | Exfiltration      | planned |

## How tests work

CI loads each case's positive/negative fixtures and runs the Python detection
in `src/detlab/detector.py`, asserting positive fires and negative stays
silent. The SPL macros in `cases/<id>/detection/macros.conf` are the
production source of truth; the Python detector is the testable specification
of what the SPL means. Drift between the two is a bug.

The build pipeline (`scripts/build_app.py`) is also tested: it concatenates
per-case `macros.conf` and `savedsearches.conf` into the deployable app,
generates the `detlab_cases.csv` lookup that powers the dashboards, validates
that every saved search references a defined macro, and packages everything
as a `.spl` tarball.

## Adding a new case

1. `mkdir -p cases/tXXXX_YYY_short_name/{attack,detection,tests}`
2. Write `detection/macros.conf` with the detection macro and a final `eval`
   stanza setting `case_id`, `case_title`, `view_name`, `mitre_technique`,
   `mitre_tactic`, `severity`
3. Write `detection/savedsearches.conf`, `detection/sigma.yml`,
   `detection/search.spl`
4. Add a `detect_<technique>` function to `src/detlab/detector.py`
5. Add a fixture generator to `scripts/generate_fixtures.py` and a per-case
   dashboard at `app/default/data/ui/views/<view_name>.xml`
6. Add the view to `app/default/data/ui/nav/default.xml`
7. `pytest && py scripts/build_app.py`

## License

MIT — see [LICENSE](LICENSE).
