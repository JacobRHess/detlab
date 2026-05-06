"""End-to-end test for the T1219 RMM tool detection.

Loads positive (synthetic RMM-tool DNS resolutions) and negative (benign
mixed DNS) fixtures and runs the Python detector. Asserts at least one
alert on positive, zero on negative, plus the IOC-set parameter shape.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from detlab.detector import LAB_RMM_DOMAINS, detect_rmm_tool_use
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
    alerts = detect_rmm_tool_use(positive_records)
    assert len(alerts) >= 1, "Expected at least one alert on RMM-shape DNS"
    a = alerts[0]
    assert a.distinct_rmm_domains >= 1
    assert any("TeamViewer" in t or "AnyDesk" in t for t in a.matched_tools)


def test_negative_silent(negative_records):
    alerts = detect_rmm_tool_use(negative_records)
    assert alerts == [], f"Expected no alerts on benign DNS, got: {alerts}"


def test_empty_lookup_silences_detection(positive_records):
    """An empty IOC dict must yield zero alerts — the detector is purely lookup-driven."""
    alerts = detect_rmm_tool_use(positive_records, rmm_domains={})
    assert alerts == []


def test_lab_rmm_domains_is_non_empty():
    assert len(LAB_RMM_DOMAINS) >= 5


def test_threshold_two_distinct_domains_required():
    """Lab fixture has >= 2 distinct base domains; bumping the floor to 2 should still fire."""
    records = [
        {"ts": 1715040000.0, "id.orig_h": "10.0.0.5", "query": "ping.teamviewer.com"},
        {"ts": 1715040030.0, "id.orig_h": "10.0.0.5", "query": "boot.anydesk.com"},
    ]
    alerts = detect_rmm_tool_use(records, min_distinct_rmm_domains=2)
    assert len(alerts) >= 1


def test_unrelated_dns_does_not_match():
    records = [
        {"ts": 1715040000.0, "id.orig_h": "10.0.0.5", "query": "www.example.com"},
        {"ts": 1715040030.0, "id.orig_h": "10.0.0.5", "query": "api.github.com"},
    ]
    assert detect_rmm_tool_use(records) == []
