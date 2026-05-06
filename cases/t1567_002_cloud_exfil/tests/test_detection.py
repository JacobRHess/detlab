"""End-to-end test for the T1567.002 cloud-storage exfil detection.

Loads positive (synthetic 75 MB rclone-shape staging to Mega) and negative
(benign mixed traffic + big downloads) fixtures and runs the Python
detector. Asserts at least one alert on positive, zero on negative, and
verifies that downloads (large resp_bytes, modest orig_bytes) do NOT fire.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from detlab.detector import LAB_CLOUD_STORAGE_IPS, detect_cloud_exfil
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
    alerts = detect_cloud_exfil(positive_records)
    assert len(alerts) >= 1, "Expected at least one alert on rclone-shape uplink"
    a = alerts[0]
    assert a.cloud_service == "Mega"
    assert a.total_orig_bytes >= 50_000_000


def test_negative_silent(negative_records):
    alerts = detect_cloud_exfil(negative_records)
    assert alerts == [], f"Expected no alerts on benign / download-heavy traffic, got: {alerts}"


def test_downloads_do_not_fire():
    """A user pulling a 100 MB Dropbox file (high resp_bytes, low orig_bytes)
    must NOT trigger — the rule is uplink-keyed, not bidirectional volume."""
    records = [
        {
            "ts": 1715000000.0 + i,
            "id.orig_h": "10.0.0.5",
            "id.resp_h": "203.0.113.60",  # Dropbox in the lab IP set
            "id.resp_p": 443,
            "duration": 30.0,
            "orig_bytes": 4_000,  # tiny upload — HTTP request only
            "resp_bytes": 100_000_000,  # huge download
        }
        for i in range(5)
    ]
    assert detect_cloud_exfil(records) == []


def test_off_target_uplink_does_not_fire():
    """100 MB uplink to an IP NOT in the cloud-storage lookup must stay silent."""
    records = [
        {
            "ts": 1715000000.0 + i,
            "id.orig_h": "10.0.0.5",
            "id.resp_h": "93.184.216.34",  # not in LAB_CLOUD_STORAGE_IPS
            "id.resp_p": 443,
            "duration": 30.0,
            "orig_bytes": 25_000_000,
            "resp_bytes": 4_000,
        }
        for i in range(5)
    ]
    assert detect_cloud_exfil(records) == []


def test_lab_cloud_ips_is_non_empty():
    assert len(LAB_CLOUD_STORAGE_IPS) >= 5
    assert any(svc == "Mega" for svc in LAB_CLOUD_STORAGE_IPS.values())


def test_threshold_unreachable(positive_records):
    alerts = detect_cloud_exfil(positive_records, min_total_orig_bytes=10_000_000_000)
    assert alerts == []
