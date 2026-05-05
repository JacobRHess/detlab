"""End-to-end test for the T1048.003 DNS Exfiltration detection.

Loads positive (synthetic A-record exfil burst, ~80 KB / 60 s) and
negative (mixed benign DNS) fixtures and runs the Python detector.
Asserts at least one alert on positive, zero on negative, and verifies
that the dnscat2 fixture does *not* trigger this rule (the two
detections are designed to be complementary, not duplicative).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from detlab.detector import detect_dns_exfil
from detlab.zeek_loader import load_zeek_dns

CASE_DIR = Path(__file__).parent
POSITIVE = CASE_DIR / "positive_dns.log"
NEGATIVE = CASE_DIR / "negative_dns.log"
DNSCAT_POSITIVE = (
    CASE_DIR.parent.parent / "t1071_004_dns_c2_dnscat2" / "tests" / "positive_dns.log"
)


@pytest.fixture(scope="module")
def positive_records():
    return load_zeek_dns(POSITIVE)


@pytest.fixture(scope="module")
def negative_records():
    return load_zeek_dns(NEGATIVE)


def test_positive_fires(positive_records):
    alerts = detect_dns_exfil(positive_records)
    assert len(alerts) >= 1, "Expected at least one alert on A-record exfil burst"
    a = alerts[0]
    assert a.total_subdomain_bytes >= 30_000
    assert a.avg_sub_len >= 50
    assert a.bytes_per_second > 0


def test_negative_silent(negative_records):
    alerts = detect_dns_exfil(negative_records)
    assert alerts == [], f"Expected no alerts on benign DNS, got: {alerts}"


def test_dnscat2_fixture_does_not_fire_exfil():
    """The dnscat2 case is C2 (low volume per minute); the volume-based exfil
    rule should not fire on its fixture, otherwise the two detections become
    duplicative instead of complementary."""
    records = load_zeek_dns(DNSCAT_POSITIVE)
    alerts = detect_dns_exfil(records)
    assert alerts == [], (
        f"Volume-based exfil rule fired on dnscat2 fixture — the two rules should "
        f"target different signals. Alerts: {alerts}"
    )


def test_threshold_ablation_unreachable(positive_records):
    alerts = detect_dns_exfil(positive_records, min_total_subdomain_bytes=10_000_000)
    assert alerts == []


def test_short_label_traffic_does_not_fire():
    """High-volume but short-label DNS (e.g., heavy A-record polling) must not trigger."""
    records = []
    base_ts = 1715000000.0
    for i in range(200):
        records.append(
            {
                "ts": base_ts + i * 0.1,
                "id.orig_h": "10.0.0.5",
                "query": f"www{i % 5}.example.com",
                "qtype_name": "A",
            }
        )
    assert detect_dns_exfil(records) == []
