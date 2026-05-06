"""End-to-end test for the T1090.003 Tor relay detection.

Loads positive (synthetic Tor client touching multiple lab relay IPs) and
negative (benign HTTPS browsing with zero relay overlap) fixtures and runs
the Python detector. Asserts at least one alert on positive, zero on
negative.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from detlab.detector import LAB_TOR_RELAY_IPS, detect_tor_relay_use
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
    alerts = detect_tor_relay_use(positive_records)
    assert len(alerts) >= 1, "Expected at least one alert on Tor-shape relay traffic"
    a = alerts[0]
    assert a.distinct_relays >= 3
    assert a.total_connections >= 3


def test_negative_silent(negative_records):
    alerts = detect_tor_relay_use(negative_records)
    assert alerts == [], f"Expected no alerts on benign browsing, got: {alerts}"


def test_threshold_ablation_strict(positive_records):
    """Even a strict threshold (5 relays) should fire on the synthetic 6-relay fixture."""
    alerts = detect_tor_relay_use(positive_records, min_distinct_relays=5)
    assert len(alerts) >= 1


def test_threshold_ablation_unreachable(positive_records):
    alerts = detect_tor_relay_use(positive_records, min_distinct_relays=100)
    assert alerts == []


def test_empty_relay_set_silences_detection(positive_records):
    """An empty IOC set must not produce alerts no matter what the input looks like."""
    alerts = detect_tor_relay_use(positive_records, tor_relay_ips=frozenset())
    assert alerts == []


def test_lab_relay_set_is_non_empty():
    assert len(LAB_TOR_RELAY_IPS) >= 5
