"""End-to-end test for the T1041 chained C2 exfil detection.

Loads positive (Sliver-shape beacon + 4 uplink bursts) and negative
(benign mixed traffic + a no-beacon big download) fixtures and runs the
Python detector. Asserts at least one alert on positive, zero on negative,
and verifies the chain — without a beacon prerequisite, the rule must NOT
fire even if uplink bytes are huge.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from detlab.detector import detect_c2_exfil
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
    alerts = detect_c2_exfil(positive_records)
    assert len(alerts) >= 1, "Expected at least one alert on beacon + exfil burst"
    a = alerts[0]
    assert a.beacon_connection_count >= 30
    assert a.total_orig_bytes >= 100_000
    assert a.exfil_record_count >= 1


def test_negative_silent(negative_records):
    """Benign mixed traffic + a non-beaconing big download must not fire."""
    alerts = detect_c2_exfil(negative_records)
    assert alerts == [], f"Expected no alerts, got: {alerts}"


def test_uplink_without_beacon_does_not_fire():
    """A huge orig_bytes record with no beaconing prerequisite must stay quiet —
    that's the whole point of chaining the detection."""
    base_ts = 1715000000.0
    records = [
        # One single huge upload — no beacon pattern at all.
        {
            "ts": base_ts,
            "id.orig_h": "10.0.0.5",
            "id.resp_h": "203.0.113.7",
            "id.resp_p": 443,
            "duration": 30.0,
            "orig_bytes": 5_000_000,
            "resp_bytes": 1000,
        },
    ]
    assert detect_c2_exfil(records) == []


def test_beacon_without_uplink_does_not_fire():
    """A clean beacon with only tiny check-ins (no uplink chunks above 10 KB)
    is exactly what T1071.001 catches; T1041 must NOT fire on it."""
    base_ts = 1715000000.0
    records = []
    for i in range(60):
        records.append(
            {
                "ts": base_ts + i * 60.0,
                "id.orig_h": "10.0.0.5",
                "id.resp_h": "203.0.113.7",
                "id.resp_p": 443,
                "duration": 0.5,
                "orig_bytes": 800,  # below the 10_000 threshold
                "resp_bytes": 1500,
            }
        )
    assert detect_c2_exfil(records) == []


def test_threshold_unreachable(positive_records):
    alerts = detect_c2_exfil(positive_records, min_exfil_total_bytes=10_000_000)
    assert alerts == []
