# detlab

[![CI](https://github.com/JacobRHess/detlab/actions/workflows/ci.yml/badge.svg)](https://github.com/JacobRHess/detlab/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)

**A network-detection lab for Splunk.** Each *case* is a self-contained folder
that pairs a reproducible network attack with the Splunk detection that catches
it on real captured telemetry — every rule ships with the thing it catches.

Focused on **network-visible** ATT&CK techniques: Command & Control,
Exfiltration, Discovery, and Lateral Movement signal in Zeek / Suricata /
network event logs ingested into Splunk.

## Why this exists

Most public Sigma repos give you a rule and call it done. This repo answers
"how do you know it actually works?" by shipping each detection alongside:

1. A reproducible attack (script, container, or hardware setup)
2. Captured telemetry from running that attack
3. A Splunk-native detection (SPL search + savedsearches.conf + macros)
4. A portable Sigma cross-reference
5. Positive / negative test fixtures and a CI test that proves the rule
   fires on the attack and stays quiet on benign traffic

The result is a portfolio of detections that are *demonstrable*, not just
*declared*.

## Layout

```
detlab/
├── lab/                              # docker-compose stack: Splunk + Zeek + Suricata
│   ├── docker-compose.yml
│   ├── splunk/                       # indexes.conf, inputs.conf, props.conf
│   └── zeek/local.zeek
├── src/detlab/                       # Python helpers (entropy, Zeek loader, detector runner)
├── cases/
│   └── t1071_004_dns_c2_dnscat2/     # one ATT&CK technique per folder
│       ├── README.md                 # technique mapping, detection logic, FP notes
│       ├── attack/                   # how to reproduce the attack
│       ├── detection/                # search.spl, savedsearches.conf, macros.conf, sigma.yml
│       └── tests/                    # positive_*.log, negative_*.log, test_detection.py
├── scripts/generate_fixtures.py      # synthetic-fixture generator (regen as needed)
├── tests/                            # cross-cutting tests for src/detlab
├── .github/workflows/ci.yml          # ruff + pytest on 3.10/3.11/3.12
└── pyproject.toml
```

## Quickstart

```bash
git clone https://github.com/JacobRHess/detlab && cd detlab

# Run the test suite (validates every case's detection logic against fixtures)
PYTHONPATH=src py -m pytest -q

# Lint
py -m ruff check src tests

# Spin up the lab (Splunk on http://localhost:8000, admin / changemenow)
cd lab && docker compose up -d
```

## Cases

| Case | ATT&CK | Tactic | Status |
|---|---|---|---|
| [DNS C2 via dnscat2](cases/t1071_004_dns_c2_dnscat2/) | T1071.004 | Command & Control | shipped |
| HTTP beaconing (Sliver)        | T1071.001 | Command & Control  | planned |
| Protocol tunneling (chisel)    | T1572     | Command & Control  | planned |
| Tor proxy use                  | T1090.003 | Command & Control  | planned |
| Network service discovery      | T1046     | Discovery          | planned |
| Exfil over DNS                 | T1048.003 | Exfiltration       | planned |

## How tests work

The CI test for each case loads the captured-telemetry fixtures and runs the
detection logic against them in Python — `src/detlab/detector.py` mirrors the
SPL semantics so we can assert outcomes without standing up a live Splunk in
CI. The SPL in `detection/search.spl` is the source of truth for production;
the Python detector is the testable specification of what the SPL is supposed
to do. Drift between the two is a bug.

For end-to-end validation against a real Splunk, spin up `lab/` and ingest the
fixtures into the `zeek` index, then run the saved search.

## Status

v0.1 — repo scaffold, lab compose, one fully-built case (DNS C2). v0.2 will
add HTTP beaconing and Tor detection. See per-case READMEs for technique
detail.

## License

MIT — see [LICENSE](LICENSE).
