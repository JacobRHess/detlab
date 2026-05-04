"""End-to-end test for the T1071.004 DNS C2 detection.

Loads the positive (synthetic dnscat2-shape) and negative (synthetic benign
DNS) Zeek dns.log fixtures and runs the Python detector. Asserts at least
one alert on the positive fixture and zero alerts on the negative.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from detlab.detector import detect_dns_tunnel
from detlab.zeek_loader import load_zeek_dns

CASE_DIR = Path(__file__).parent
POSITIVE = CASE_DIR / "positive_dns.log"
NEGATIVE = CASE_DIR / "negative_dns.log"


@pytest.fixture(scope="module")
def positive_records():
    return load_zeek_dns(POSITIVE)


@pytest.fixture(scope="module")
def negative_records():
    return load_zeek_dns(NEGATIVE)


def test_positive_fires(positive_records):
    alerts = detect_dns_tunnel(positive_records)
    assert len(alerts) >= 1, "Expected at least one alert on dnscat2-shape traffic"
    a = alerts[0]
    assert a.query_count >= 50
    assert a.avg_sub_len >= 20
    assert a.avg_entropy >= 3.5
    assert a.unique_queries >= 30
    assert any(q in a.qtypes for q in ("TXT", "MX", "CNAME", "NULL"))


def test_negative_silent(negative_records):
    alerts = detect_dns_tunnel(negative_records)
    assert alerts == [], f"Expected no alerts on benign DNS, got: {alerts}"


def test_threshold_ablation_query_count(positive_records):
    """Setting the count threshold above what the fixture contains must silence the rule."""
    alerts = detect_dns_tunnel(positive_records, min_query_count=10_000)
    assert alerts == []


def test_threshold_ablation_entropy(negative_records):
    """Even at a permissive entropy threshold, benign traffic shouldn't fire (volume gates)."""
    alerts = detect_dns_tunnel(negative_records, min_avg_entropy=0.0)
    assert alerts == []
