"""Tests for the per-case rich metadata registry.

Drift catcher: if a new case ships under cases/ without a matching entry
in scripts/case_metadata.CASE_METADATA, the lookup CSV / web JSON ends
up with placeholder zeros. These tests fail loudly so the author
remembers to add the metadata."""

from __future__ import annotations

import csv
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from case_metadata import CASE_METADATA, DATA_SOURCES, PYRAMID_TIERS  # noqa: E402

CASES_CSV = ROOT / "app" / "lookups" / "detlab_cases.csv"


@pytest.fixture(scope="module")
def shipped_case_ids() -> set[str]:
    if not CASES_CSV.exists():
        pytest.skip("detlab_cases.csv missing — run `py scripts/build_app.py`")
    with CASES_CSV.open() as fh:
        return {row["case_id"] for row in csv.DictReader(fh)}


def test_every_shipped_case_has_metadata(shipped_case_ids):
    """Every case in the lookup CSV must have a matching CASE_METADATA entry."""
    missing = shipped_case_ids - set(CASE_METADATA.keys())
    assert not missing, (
        f"{len(missing)} cases ship without rich metadata: {sorted(missing)}. "
        "Add entries to scripts/case_metadata.CASE_METADATA."
    )


def test_metadata_doesnt_reference_unknown_cases(shipped_case_ids):
    """Metadata must not reference cases that don't ship — that's stale data."""
    extra = set(CASE_METADATA.keys()) - shipped_case_ids
    assert not extra, (
        f"CASE_METADATA references {len(extra)} unknown cases: {sorted(extra)}"
    )


@pytest.mark.parametrize("case_id,meta", list(CASE_METADATA.items()))
def test_each_metadata_entry_has_required_fields(case_id, meta):
    assert "risk_score" in meta, f"{case_id} missing risk_score"
    assert 0 < meta["risk_score"] <= 100, (
        f"{case_id} risk_score {meta['risk_score']} out of 1..100"
    )
    assert meta.get("risk_object_type") in {"system", "user", "other"}, (
        f"{case_id} risk_object_type must be system|user|other"
    )
    assert 1 <= meta.get("pyramid_tier", 0) <= 6, (
        f"{case_id} pyramid_tier must be 1..6"
    )
    assert isinstance(meta.get("data_sources", []), list) and meta["data_sources"], (
        f"{case_id} data_sources must be a non-empty list"
    )
    for ds in meta["data_sources"]:
        assert ds in DATA_SOURCES, (
            f"{case_id} data_source {ds!r} not in DATA_SOURCES catalogue"
        )
    assert isinstance(meta.get("threat_groups", []), list), (
        f"{case_id} threat_groups must be a list (empty allowed)"
    )
    triage = meta.get("triage", {})
    assert isinstance(triage.get("steps", []), list)
    assert isinstance(triage.get("false_positives", []), list)
    assert isinstance(triage.get("containment", []), list)


def test_pyramid_tiers_complete():
    assert set(PYRAMID_TIERS.keys()) == {1, 2, 3, 4, 5, 6}, (
        "PYRAMID_TIERS must define exactly tiers 1-6"
    )
    for tier, meta in PYRAMID_TIERS.items():
        assert meta["label"], f"tier {tier} missing label"
        assert meta["color"].startswith("#") or meta["color"].startswith("var("), (
            f"tier {tier} color must be hex or CSS var"
        )


def test_data_sources_have_categories():
    for ds_id, meta in DATA_SOURCES.items():
        assert meta.get("category"), f"data source {ds_id} missing category"
        assert meta.get("label"), f"data source {ds_id} missing label"
        assert meta.get("description"), f"data source {ds_id} missing description"
