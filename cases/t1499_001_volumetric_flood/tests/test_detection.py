"""End-to-end test for the T1499.001 Volumetric Flood detection.

Loads positive (synthetic 200-pps SYN flood) and negative (benign mixed
traffic) fixtures and runs the Python detector. Asserts at least one
alert on positive, zero on negative, and that the rule does NOT confuse
itself with port-scan-shaped traffic (many ports, low volume per port).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from detlab.detector import detect_volumetric_flood
from detlab.zeek_loader import load_zeek_dns

CASE_DIR = Path(__file__).parent
POSITIVE = CASE_DIR / "positive_conn.log"
NEGATIVE = CASE_DIR / "negative_conn.log"
PORTSCAN_POSITIVE = (
    CASE_DIR.parent.parent / "t1046_network_service_discovery" / "tests" / "positive_conn.log"
)


@pytest.fixture(scope="module")
def positive_records():
    return load_zeek_dns(POSITIVE)


@pytest.fixture(scope="module")
def negative_records():
    return load_zeek_dns(NEGATIVE)


def test_positive_fires(positive_records):
    alerts = detect_volumetric_flood(positive_records)
    assert len(alerts) >= 1, "Expected at least one alert on flood-shape conn burst"
    a = alerts[0]
    assert a.connection_count >= 100
    assert a.pps > 50  # 200 conns in <1 s is well above 50 pps


def test_negative_silent(negative_records):
    alerts = detect_volumetric_flood(negative_records)
    assert alerts == [], f"Expected no alerts on benign mixed traffic, got: {alerts}"


def test_portscan_fixture_does_not_fire_flood():
    """Port-scan traffic hits MANY ports at moderate rate, not ONE port at high rate.
    The flood rule must stay quiet on it — otherwise the two are duplicative."""
    records = load_zeek_dns(PORTSCAN_POSITIVE)
    alerts = detect_volumetric_flood(records)
    assert alerts == [], (
        f"Volumetric flood rule fired on port-scan fixture — the two should target "
        f"different shapes (port-cardinality vs. single-port volume). Alerts: {alerts}"
    )


def test_threshold_higher_min_unreachable(positive_records):
    alerts = detect_volumetric_flood(positive_records, min_connections=10_000)
    assert alerts == []


def test_low_rate_does_not_fire():
    """30 connections to one port across 60s — definitely not a flood."""
    base_ts = 1715000000.0
    records = [
        {
            "ts": base_ts + i * 2.0,
            "id.orig_h": "10.0.0.5",
            "id.resp_h": "192.168.1.10",
            "id.resp_p": 80,
            "duration": 0.05,
            "conn_state": "S0",
        }
        for i in range(30)
    ]
    assert detect_volumetric_flood(records) == []
