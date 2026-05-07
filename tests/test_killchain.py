"""Tests for the cross-detector kill-chain meta-detector."""

from __future__ import annotations

import pytest

from detlab.killchain import (
    CHAIN_REGISTRY,
    detect_attack_chain,
)


def _dnscat_records(src: str, base_ts: float = 1_700_000_000.0) -> list[dict]:
    """Synthesize 60 dnscat-shape DNS queries from `src` into a single
    base domain. Mirrors what dnscat2 produces — long, high-entropy
    base32-ish labels plus a TXT qtype."""
    return [
        {
            "ts": base_ts + i,
            "id.orig_h": src,
            "id.resp_h": "10.0.0.53",
            "query": f"vqfh3rsx7zaby4nklm5q6t7u8wp9c2g{i:04d}.evilc2.example",
            "qtype_name": "TXT",
            "rcode_name": "NOERROR",
        }
        for i in range(60)
    ]


def _portscan_records(src: str, base_ts: float = 1_700_000_500.0) -> list[dict]:
    """Synthesize 120 conn-log records: one source touching 120 distinct
    destination ports on one target with mostly-incomplete handshakes."""
    return [
        {
            "ts": base_ts + i * 0.1,
            "id.orig_h": src,
            "id.resp_h": "10.0.0.50",
            "id.resp_p": 1024 + i,
            "proto": "tcp",
            "duration": 0.01,
            "orig_bytes": 0,
            "resp_bytes": 0,
            "conn_state": "REJ",
        }
        for i in range(120)
    ]


def _rmm_records(src: str, base_ts: float = 1_700_001_000.0) -> list[dict]:
    """Synthesize a DNS resolution for an RMM domain. Mirrors what the
    rmm_domains.csv lookup considers RMM C2 infrastructure."""
    return [
        {
            "ts": base_ts + i,
            "id.orig_h": src,
            "id.resp_h": "10.0.0.53",
            "query": "anydesk.com",
            "qtype_name": "A",
            "rcode_name": "NOERROR",
        }
        for i in range(2)
    ]


def test_chain_fires_when_multiple_techniques_present():
    src = "10.0.0.42"
    records = _dnscat_records(src) + _portscan_records(src) + _rmm_records(src)

    chains = detect_attack_chain(records)

    assert len(chains) == 1
    chain = chains[0]
    assert chain.src == src
    assert chain.technique_count >= 2
    techniques = {t.technique for t in chain.timeline}
    # DNS C2 + port scan should always be present; RMM is the third.
    assert "T1071.004" in techniques
    assert "T1046" in techniques


def test_chain_silent_on_single_technique():
    """A single firing detector must not produce a kill-chain alert."""
    records = _dnscat_records("10.0.0.99")
    assert detect_attack_chain(records) == []


def test_chain_silent_on_benign_records():
    """Records that look like nothing produce no chains."""
    benign = [
        {
            "ts": 1_700_000_000.0 + i,
            "id.orig_h": "10.0.0.10",
            "id.resp_h": "10.0.0.53",
            "query": "google.com",
            "qtype_name": "A",
            "rcode_name": "NOERROR",
        }
        for i in range(5)
    ]
    assert detect_attack_chain(benign) == []


def test_chain_groups_by_source_ip():
    """Two distinct attackers, each running two techniques — expect two
    chains, not one merged."""
    records = (
        _dnscat_records("10.0.0.41")
        + _portscan_records("10.0.0.41")
        + _dnscat_records("10.0.0.42", base_ts=1_700_010_000.0)
        + _portscan_records("10.0.0.42", base_ts=1_700_010_500.0)
    )
    chains = detect_attack_chain(records)
    assert len(chains) == 2
    sources = {c.src for c in chains}
    assert sources == {"10.0.0.41", "10.0.0.42"}


def test_chain_window_excludes_far_apart_techniques():
    """Two techniques 30 days apart from the same src should not chain
    when the window is 24h (the default)."""
    src = "10.0.0.50"
    early = _dnscat_records(src, base_ts=1_700_000_000.0)
    late = _portscan_records(src, base_ts=1_700_000_000.0 + 30 * 86_400)
    records = early + late
    chains = detect_attack_chain(records, window_seconds=86_400)
    assert chains == []


def test_chain_swallows_malformed_input_without_raising():
    """A record with wrong types (e.g. ts=None) propagates a TypeError
    out of any per-record detector — the killchain wrapper narrows on
    TypeError/ValueError/KeyError/AttributeError so that one bad
    detector invocation doesn't sink the whole run. We assert no
    exception escapes; an empty chain list is acceptable."""
    malformed = [
        {"ts": None, "id.orig_h": "10.0.0.66", "id.resp_h": "10.0.0.50", "id.resp_p": 22}
    ]
    # Smoke test: must not raise.
    chains = detect_attack_chain(malformed)
    assert chains == []


def test_chain_window_picks_longest_in_window_run():
    """A burst of three close-together techniques + one far-future
    technique should yield a single chain containing only the burst —
    the sliding-window scan picks the longest run that fits the window
    and discards the outlier."""
    src = "10.0.0.55"
    base = 1_700_000_000.0
    in_window = (
        _dnscat_records(src, base_ts=base)
        + _portscan_records(src, base_ts=base + 60)
        + _rmm_records(src, base_ts=base + 120)
    )
    far_future = _portscan_records(src, base_ts=base + 30 * 86_400)
    chains = detect_attack_chain(in_window + far_future, window_seconds=3_600)
    assert len(chains) == 1
    chain = chains[0]
    # The far-future port-scan dedupes against the in-window one (same
    # technique id), so we expect the three-technique in-window chain.
    assert chain.technique_count >= 2
    assert chain.duration_seconds <= 3_600


def test_chain_min_distinct_techniques_threshold():
    """Bumping the gate to 3 should suppress 2-technique chains."""
    src = "10.0.0.51"
    records = _dnscat_records(src) + _portscan_records(src)
    chains = detect_attack_chain(records, min_distinct_techniques=3)
    assert chains == []


def test_registry_references_real_detectors():
    """Every registry entry must name a function that exists in detlab.detector."""
    from detlab import detector

    for entry in CHAIN_REGISTRY:
        assert hasattr(detector, entry["fn"]), (
            f"CHAIN_REGISTRY entry {entry['case_id']} references missing detector {entry['fn']}"
        )


def test_registry_matches_cases_csv():
    """Every CHAIN_REGISTRY case_id must appear in app/lookups/detlab_cases.csv
    so the chain visualization can deep-link back to the case page."""
    import csv
    from pathlib import Path

    csv_path = Path(__file__).parent.parent / "app" / "lookups" / "detlab_cases.csv"
    with csv_path.open() as fh:
        case_ids = {row["case_id"] for row in csv.DictReader(fh)}

    registry_ids = {entry["case_id"] for entry in CHAIN_REGISTRY}
    missing = registry_ids - case_ids
    assert not missing, f"CHAIN_REGISTRY references unknown cases: {sorted(missing)}"


@pytest.mark.parametrize(
    "field",
    ["fn", "case_id", "technique", "tactic", "title"],
)
def test_registry_entries_have_required_fields(field):
    for entry in CHAIN_REGISTRY:
        assert entry.get(field), f"entry {entry} missing {field}"
