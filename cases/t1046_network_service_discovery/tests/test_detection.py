"""End-to-end test for the T1046 Network Service Discovery detection.

Loads positive (synthetic nmap-shape SYN scan) and negative (mixed benign
HTTP/S) fixtures and runs the Python detector. Asserts at least one alert
on positive, zero on negative.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from detlab.detector import detect_port_scan
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
    alerts = detect_port_scan(positive_records)
    assert len(alerts) >= 1, "Expected at least one alert on nmap-shape scan"
    a = alerts[0]
    assert a.distinct_ports >= 100
    assert a.incomplete_fraction >= 0.7


def test_negative_silent(negative_records):
    alerts = detect_port_scan(negative_records)
    assert alerts == [], f"Expected no alerts on benign conn traffic, got: {alerts}"


def test_threshold_ablation_high_port_count(positive_records):
    """A stricter port-count threshold should still fire on a 200-port scan."""
    alerts = detect_port_scan(positive_records, min_distinct_ports=150)
    assert len(alerts) >= 1


def test_threshold_ablation_unreachable_threshold(positive_records):
    alerts = detect_port_scan(positive_records, min_distinct_ports=10_000)
    assert alerts == []


def test_completed_handshakes_dont_fire():
    """A scan with all SF (complete handshakes) must miss the incomplete-fraction gate."""
    records = []
    for i in range(150):
        records.append(
            {
                "ts": 1715000000.0 + i * 0.1,
                "id.orig_h": "10.0.0.99",
                "id.resp_h": "192.168.1.10",
                "id.resp_p": 1000 + i,
                "conn_state": "SF",
            }
        )
    assert detect_port_scan(records) == []
