"""End-to-end test for the T1068 RPC coercion (PetitPotam, DFSCoerce) detection.

Loads positive (synthetic shape) and negative (benign / shape-adjacent)
fixtures and runs the Python detector. Asserts at least one alert on
positive, zero on negative.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from detlab.detector import detect_rpc_coercion
from detlab.zeek_loader import load_zeek_dns

CASE_DIR = Path(__file__).parent
POSITIVE = CASE_DIR / "positive_dce_rpc.log"
NEGATIVE = CASE_DIR / "negative_dce_rpc.log"


@pytest.fixture(scope="module")
def positive_records():
    return load_zeek_dns(POSITIVE)


@pytest.fixture(scope="module")
def negative_records():
    return load_zeek_dns(NEGATIVE)


def test_positive_fires(positive_records):
    alerts = detect_rpc_coercion(positive_records)
    assert len(alerts) >= 1, "Expected at least one alert on positive fixture"
    a = alerts[0]
    assert a.distinct_operations >= 1


def test_negative_silent(negative_records):
    alerts = detect_rpc_coercion(negative_records)
    assert alerts == [], f"Expected no alerts on negative fixture, got: {alerts}"
