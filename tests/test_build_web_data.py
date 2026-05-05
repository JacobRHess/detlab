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


def test_payload_has_expected_top_level_keys():
    payload = build_web_data.build_payload()
    assert payload["schema_version"] == 1
    assert "generated_at" in payload
    assert isinstance(payload["cases"], list) and payload["cases"], "no shipped cases"
    assert isinstance(payload["planned"], list)


def test_each_shipped_case_has_full_content():
    payload = build_web_data.build_payload()
    for c in payload["cases"]:
        assert c["readme_md"], f"{c['id']} missing README"
        assert c["detection"]["spl"], f"{c['id']} missing search.spl"
        assert c["detection"]["sigma_yaml"], f"{c['id']} missing sigma.yml"
        assert c["fixtures"]["positive"], f"{c['id']} missing positive fixture"
        assert c["fixtures"]["negative"], f"{c['id']} missing negative fixture"
        assert c["fixtures"]["positive"]["line_count"] > 0
        assert c["fixtures"]["negative"]["line_count"] > 0


def test_every_shipped_case_has_playground_wiring():
    """If a new case ships without CASE_WIRING, the playground silently breaks."""
    payload = build_web_data.build_payload()
    for c in payload["cases"]:
        assert c["wiring"], f"{c['id']} has no CASE_WIRING entry in build_web_data.py"
        assert c["wiring"].get("detector_function"), f"{c['id']} missing detector_function"
        assert c["wiring"].get("fixture_kind"), f"{c['id']} missing fixture_kind"


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
