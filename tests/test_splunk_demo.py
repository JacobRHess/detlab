"""Tests for the Splunk demo CLI.

Pure-unit tests on helpers — no live Splunk required. The HTTP-talking
code is exercised only by the e2e demo itself; this suite covers the
fixture-routing, payload-construction, and saved-search-discovery logic.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import splunk_demo  # noqa: E402

# ---------- Auth header construction ----------


def test_basic_auth_header_encodes_credentials():
    h = splunk_demo.basic_auth_header("admin", "changemenow")
    assert h.startswith("Basic ")
    decoded = base64.b64decode(h.split()[1]).decode()
    assert decoded == "admin:changemenow"


def test_hec_auth_header_uses_splunk_scheme():
    assert splunk_demo.hec_auth_header("xxx-yyy-zzz") == "Splunk xxx-yyy-zzz"


# ---------- Fixture sourcetype routing ----------


def test_fixture_sourcetype_routes_zeek_dns():
    p = Path("cases/x/tests/positive_dns.log")
    assert splunk_demo.fixture_sourcetype(p, "zeek_json") == ("zeek", "zeek:dns")


def test_fixture_sourcetype_routes_zeek_conn():
    p = Path("cases/x/tests/positive_conn.log")
    assert splunk_demo.fixture_sourcetype(p, "zeek_json") == ("zeek", "zeek:conn")


def test_fixture_sourcetype_routes_suricata_eve():
    p = Path("cases/x/tests/positive_eve.log")
    assert splunk_demo.fixture_sourcetype(p, "suricata_eve") == (
        "suricata",
        "suricata:eve",
    )


def test_fixture_sourcetype_unknown_flavor_raises():
    p = Path("cases/x/tests/positive_garbage.log")
    with pytest.raises(ValueError, match="unknown flavor"):
        splunk_demo.fixture_sourcetype(p, "zeek_json")


# ---------- HEC payload construction ----------


def test_hec_event_payload_wraps_zeek_record_with_time():
    rec = {"ts": 1715000000.5, "id.orig_h": "10.0.0.5", "query": "x.com"}
    payload = splunk_demo.hec_event_payload(rec, sourcetype="zeek:dns", index="zeek")
    assert payload["event"] == rec
    assert payload["sourcetype"] == "zeek:dns"
    assert payload["index"] == "zeek"
    assert payload["time"] == 1715000000.5


def test_hec_event_payload_handles_suricata_record_without_ts():
    rec = {"timestamp": "2026-05-06T12:00:00.000+0000", "event_type": "alert"}
    payload = splunk_demo.hec_event_payload(rec, sourcetype="suricata:eve", index="suricata")
    assert "time" not in payload, "Suricata records carry their own timestamp string"
    assert payload["event"] == rec


def test_hec_event_payload_does_not_mutate_input():
    rec = {"ts": 100.0, "x": 1}
    snapshot = json.dumps(rec, sort_keys=True)
    splunk_demo.hec_event_payload(rec, sourcetype="zeek:dns", index="zeek")
    assert json.dumps(rec, sort_keys=True) == snapshot


# ---------- Saved search discovery ----------


def test_saved_search_names_round_trips_each_shipped_case():
    """For every case in app/lookups/detlab_cases.csv, the script should
    surface (case_id, title, technique, saved_search_name)."""
    saves = splunk_demo._saved_search_names()
    assert len(saves) >= 1, "expected at least one shipped case"
    for case_id, _title, technique, ss_name in saves:
        assert case_id.startswith("t1")
        assert technique.startswith("T")
        assert ss_name, f"{case_id} resolved to empty saved-search name"
        # Sanity: the resolved saved-search name must exist verbatim in
        # that case's savedsearches.conf (`[Stanza]` header).
        ss_conf = (
            ROOT / "cases" / case_id / "detection" / "savedsearches.conf"
        ).read_text(encoding="utf-8")
        assert f"[{ss_name}]" in ss_conf


def test_saved_search_names_are_sorted_by_technique():
    saves = splunk_demo._saved_search_names()
    techniques = [t for _id, _title, t, _name in saves]
    assert techniques == sorted(techniques)
