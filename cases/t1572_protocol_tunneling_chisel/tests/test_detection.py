"""End-to-end test for the T1572 Protocol Tunneling detection.

Loads positive (synthetic 2-hour, ~200 MB chisel-shape flow) and negative
(benign HTTPS browsing) fixtures and runs the Python detector. Asserts at
least one alert on positive, zero on negative.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from detlab.detector import detect_protocol_tunnel
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
    alerts = detect_protocol_tunnel(positive_records)
    assert len(alerts) >= 1, "Expected at least one alert on chisel-shape long flow"
    a = alerts[0]
    assert a.duration_seconds >= 600
    assert a.total_bytes >= 10_000_000
    assert a.dest_port in (80, 443, 8080, 8443)


def test_negative_silent(negative_records):
    alerts = detect_protocol_tunnel(negative_records)
    assert alerts == [], f"Expected no alerts on benign browsing, got: {alerts}"


def test_threshold_ablation_short_duration_unreachable(positive_records):
    """Bumping the duration threshold past the fixture should silence the alert."""
    alerts = detect_protocol_tunnel(positive_records, min_duration_seconds=10_000)
    assert alerts == []


def test_off_port_does_not_fire():
    """A long high-throughput flow on a non-web port must not trigger."""
    record = {
        "ts": 1715000000.0,
        "id.orig_h": "10.0.0.5",
        "id.resp_h": "203.0.113.99",
        "id.resp_p": 22,
        "duration": 7200.0,
        "orig_bytes": 50_000_000,
        "resp_bytes": 50_000_000,
        "service": "ssh",
    }
    assert detect_protocol_tunnel([record]) == []
