"""Tests for the web data build pipeline.

Mirrors test_build_app.py: catches the most common breakage between
cases/ and the JSON the portfolio site consumes.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import build_web_data  # noqa: E402


def test_summary_payload_has_expected_top_level_keys():
    summary, _full = build_web_data.build_summary_payload()
    assert summary["schema_version"] == build_web_data.SCHEMA_VERSION
    assert "generated_at" in summary
    assert isinstance(summary["cases"], list) and summary["cases"], "no shipped cases"
    assert isinstance(summary["planned"], list)


def test_each_shipped_case_has_summary_and_full_content():
    summary, fulls = build_web_data.build_summary_payload()
    full_by_id = {f["id"]: f for f in fulls}
    for c in summary["cases"]:
        # Summary side
        assert c["mitre_technique"]
        assert c["mitre_tactic"]
        assert c["mitre_url"].startswith("https://attack.mitre.org/")
        assert c["fixture_record_counts"]["positive"] > 0
        assert c["fixture_record_counts"]["negative"] > 0
        # Full side
        full = full_by_id[c["id"]]
        assert full["readme_md"], f"{c['id']} missing README"
        assert full["detection"]["spl"], f"{c['id']} missing search.spl"
        assert full["detection"]["sigma_yaml"], f"{c['id']} missing sigma.yml"
        assert full["fixtures"]["positive"], f"{c['id']} missing positive fixture"
        assert full["fixtures"]["negative"], f"{c['id']} missing negative fixture"


def test_every_shipped_case_has_playground_wiring():
    """If a new case ships without CASE_WIRING, the playground silently breaks."""
    summary, _full = build_web_data.build_summary_payload()
    for c in summary["cases"]:
        assert c["wiring"], f"{c['id']} has no CASE_WIRING entry in build_web_data.py"
        assert c["wiring"].get("detector_function"), f"{c['id']} missing detector_function"
        assert c["wiring"].get("fixture_kind"), f"{c['id']} missing fixture_kind"


def test_summary_cases_are_sorted_by_tactic_then_technique():
    summary, _full = build_web_data.build_summary_payload()
    pairs = [(c["mitre_tactic"], c["mitre_technique"]) for c in summary["cases"]]
    assert pairs == sorted(pairs), "cases should be deterministically sorted"


def test_attack_url_format():
    assert build_web_data._attack_url("T1071.004") == "https://attack.mitre.org/techniques/T1071/004/"
    assert build_web_data._attack_url("T1046") == "https://attack.mitre.org/techniques/T1046/"


def test_planned_cases_have_url_and_status():
    for p in (build_web_data.build_planned(x) for x in build_web_data.PLANNED):
        assert p["status"] == "planned"
        assert p["mitre_url"].startswith("https://attack.mitre.org/")


def test_copy_py_runtime_copies_all_files(tmp_path, monkeypatch):
    """The Pyodide playground depends on detector.py / entropy.py / zeek_loader.py
    being present at web/public/py/. If the source moves, the copy step breaks
    loudly here instead of silently shipping a stale runtime."""
    dest = tmp_path / "py"
    monkeypatch.setattr(build_web_data, "PY_DEST", dest)
    build_web_data.copy_py_runtime()
    for name in build_web_data.PY_FILES:
        assert (dest / name).exists(), f"{name} not copied"
        assert (dest / name).read_text(encoding="utf-8")


def test_every_case_wiring_function_exists_in_detector():
    """The Pyodide playground calls detector.<detector_function>(records, **kwargs).
    A typo in CASE_WIRING silently breaks the in-browser detector — this test
    catches it as a unit failure instead."""
    import inspect

    from detlab import detector as _detector

    public_detect_fns = {
        name for name, _obj in inspect.getmembers(_detector, inspect.isfunction)
        if name.startswith("detect_")
    }
    for case_id, wiring in build_web_data.CASE_WIRING.items():
        fn_name = wiring.get("detector_function")
        assert fn_name, f"{case_id} CASE_WIRING missing detector_function"
        assert fn_name in public_detect_fns, (
            f"{case_id} wired to {fn_name!r} but detlab.detector has no such function. "
            f"Available: {sorted(public_detect_fns)}"
        )


def test_every_public_detector_has_a_case():
    """If a new detect_* function lands in detector.py without a case to back
    it, the playground UI has no way to invoke it. This guards against drift
    in the other direction."""
    import inspect

    from detlab import detector as _detector

    public_detect_fns = {
        name for name, _obj in inspect.getmembers(_detector, inspect.isfunction)
        if name.startswith("detect_")
    }
    wired_fns = {w["detector_function"] for w in build_web_data.CASE_WIRING.values()}
    orphans = public_detect_fns - wired_fns
    assert not orphans, (
        f"detect_* functions with no CASE_WIRING entry: {sorted(orphans)}. "
        f"Either wire them to a case or rename them so they don't start with detect_."
    )
