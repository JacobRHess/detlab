"""End-to-end test for the T1021.001 RDP Lateral Movement detection.

Loads positive (synthetic 5-host pivot) and negative (benign IT-admin
RDP usage where no single src crosses the threshold) fixtures and runs
the Python detector. Asserts at least one alert on positive, zero on
negative, plus that the rule does NOT confuse SSH-brute-force shapes
(many conns to one host on a different port) with lateral-movement.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from detlab.detector import detect_rdp_lateral
from detlab.zeek_loader import load_zeek_dns

CASE_DIR = Path(__file__).parent
POSITIVE = CASE_DIR / "positive_conn.log"
NEGATIVE = CASE_DIR / "negative_conn.log"


@pytest.fixture(scope="module")
def positive_records():
    return load_zeek_dns(POSITIVE)


@pytest.fixture(scope="module")
def negative_records():
    return load_zeek_dns(NEGATIVE)


def test_positive_fires(positive_records):
    alerts = detect_rdp_lateral(positive_records)
    assert len(alerts) >= 1, "Expected at least one alert on RDP pivot"
    a = alerts[0]
    assert a.distinct_destinations >= 3
    assert a.total_connections >= a.distinct_destinations


def test_negative_silent(negative_records):
    alerts = detect_rdp_lateral(negative_records)
    assert alerts == [], f"Expected no alerts on benign RDP usage, got: {alerts}"


def test_off_port_traffic_does_not_fire():
    """A burst of connections from one src to many dests on TCP/22 (SSH)
    must NOT trigger — the rule is RDP-specific."""
    base_ts = 1715040000.0
    records = []
    for i in range(10):
        records.append(
            {
                "ts": base_ts + i * 30,
                "id.orig_h": "10.0.0.5",
                "id.resp_h": f"192.168.1.{10 + i}",
                "id.resp_p": 22,  # SSH, not RDP
                "duration": 60.0,
                "conn_state": "SF",
            }
        )
    assert detect_rdp_lateral(records) == []


def test_one_src_to_two_dests_does_not_fire():
    """Below-threshold pivot — IT admin touching 2 hosts is normal."""
    base_ts = 1715040000.0
    records = []
    for i, dest in enumerate(["192.168.1.10", "192.168.1.20"]):
        for j in range(5):
            records.append(
                {
                    "ts": base_ts + i * 100 + j * 20,
                    "id.orig_h": "10.0.0.5",
                    "id.resp_h": dest,
                    "id.resp_p": 3389,
                    "duration": 120.0,
                    "conn_state": "SF",
                }
            )
    assert detect_rdp_lateral(records) == []


def test_threshold_unreachable(positive_records):
    alerts = detect_rdp_lateral(positive_records, min_distinct_destinations=100)
    assert alerts == []
