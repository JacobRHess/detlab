"""End-to-end test for the T1110.001 SSH Brute Force detection.

Loads positive (synthetic hydra-shape, 60 attempts / 60 s) and negative
(benign SSH usage, long sessions) fixtures and runs the Python detector.
Asserts at least one alert on positive, zero on negative.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from detlab.detector import detect_ssh_brute_force
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
    alerts = detect_ssh_brute_force(positive_records)
    assert len(alerts) >= 1, "Expected at least one alert on hydra-shape brute force"
    a = alerts[0]
    assert a.connection_count >= 20
    assert a.avg_duration_seconds <= 5.0


def test_negative_silent(negative_records):
    alerts = detect_ssh_brute_force(negative_records)
    assert alerts == [], f"Expected no alerts on benign SSH usage, got: {alerts}"


def test_threshold_ablation_unreachable(positive_records):
    alerts = detect_ssh_brute_force(positive_records, min_attempts=10_000)
    assert alerts == []


def test_off_port_does_not_fire():
    """A burst of fast connections on a non-SSH port must not trigger."""
    base_ts = 1715000000.0
    records = [
        {
            "ts": base_ts + i,
            "id.orig_h": "10.0.0.5",
            "id.resp_h": "192.168.1.10",
            "id.resp_p": 80,
            "duration": 0.5,
            "conn_state": "SF",
        }
        for i in range(50)
    ]
    assert detect_ssh_brute_force(records) == []


def test_long_sessions_dont_fire():
    """Many *long* SSH connections from one src should not fire — interactive use, not auth spam."""
    base_ts = 1715000000.0
    records = [
        {
            "ts": base_ts + i * 5,
            "id.orig_h": "10.0.0.5",
            "id.resp_h": "192.168.1.10",
            "id.resp_p": 22,
            "duration": 300.0,  # 5-min sessions
            "conn_state": "SF",
        }
        for i in range(30)
    ]
    assert detect_ssh_brute_force(records) == []
