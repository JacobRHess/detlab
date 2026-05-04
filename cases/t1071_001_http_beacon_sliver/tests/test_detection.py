"""End-to-end test for the T1071.001 HTTP beaconing detection.

Loads positive (synthetic Sliver-shape conn.log) and negative (synthetic
benign conn.log) fixtures and runs the Python detector. Asserts at least
one alert on positive, zero on negative.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from detlab.detector import detect_beaconing
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
    alerts = detect_beaconing(positive_records)
    assert len(alerts) >= 1, "Expected at least one alert on Sliver-shape beacon"
    a = alerts[0]
    assert a.connection_count >= 30
    assert 30.0 <= a.avg_interval <= 600.0
    assert a.coefficient_of_variation <= 0.1
    assert a.duration_seconds >= 600.0


def test_negative_silent(negative_records):
    alerts = detect_beaconing(negative_records)
    assert alerts == [], f"Expected no alerts on benign conn traffic, got: {alerts}"


def test_threshold_ablation_cov_strict(positive_records):
    """A very strict CoV threshold (zero variance) must still fire on this synthetic beacon."""
    alerts = detect_beaconing(positive_records, max_coefficient_of_variation=0.05)
    assert len(alerts) >= 1, "Synthetic beacon has CoV well below 0.05"


def test_threshold_ablation_count_too_high(positive_records):
    alerts = detect_beaconing(positive_records, min_connections=10_000)
    assert alerts == []
