"""End-to-end test for the T1568.002 DGA C2 detection.

Loads positive (synthetic 50-domain DGA burst, mostly NXDOMAIN) and
negative (mixed benign DNS) fixtures and runs the Python detector.
Asserts at least one alert on positive, zero on negative, and verifies
that the dnscat2 fixture does *not* fire DGA — the two rules target
different signals (subdomain entropy vs base-domain entropy).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from detlab.detector import detect_dga_domains
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
    alerts = detect_dga_domains(positive_records)
    assert len(alerts) >= 1, "Expected at least one alert on DGA-shape DNS burst"
    a = alerts[0]
    assert a.distinct_domains >= 30
    assert a.avg_domain_entropy >= 3.3
    assert a.nxdomain_fraction >= 0.5


def test_negative_silent(negative_records):
    alerts = detect_dga_domains(negative_records)
    assert alerts == [], f"Expected no alerts on benign DNS, got: {alerts}"


def test_dnscat2_fixture_does_not_fire_dga():
    """dnscat2 fires high-entropy subdomains under one base domain — DGA
    should NOT fire because there's only one distinct base domain in that
    fixture. The two rules target different signals; this asserts the
    intended separation."""
    records = load_zeek_dns(DNSCAT_POSITIVE)
    alerts = detect_dga_domains(records)
    assert alerts == [], (
        f"DGA rule fired on dnscat2 fixture — the two rules should target different "
        f"signals (subdomain entropy vs base-domain entropy). Alerts: {alerts}"
    )


def test_low_nxdomain_does_not_fire():
    """Many high-entropy domains that all resolve NOERROR (hosted by an
    operator-controlled DNS) shouldn't trigger — the NXDOMAIN signal is
    the one that distinguishes DGA from rare-but-real domain bursts."""
    records = []
    base_ts = 1715040000.0
    for i in range(50):
        records.append(
            {
                "ts": base_ts + i,
                "id.orig_h": "10.0.0.5",
                "query": f"abcdefghij{i:03d}.com",
                "rcode_name": "NOERROR",
            }
        )
    assert detect_dga_domains(records) == []


def test_threshold_ablation_unreachable(positive_records):
    alerts = detect_dga_domains(positive_records, min_distinct_domains=10_000)
    assert alerts == []
