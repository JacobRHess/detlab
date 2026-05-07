"""Tests for the web data build pipeline.

Mirrors test_build_app.py: catches the most common breakage between
cases/ and the JSON the portfolio site consumes.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

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


def test_macros_catalogue_includes_shared_and_per_case():
    """The /macros page consumes summary['macros'] — must be populated for all cases."""
    summary, _full = build_web_data.build_summary_payload()
    cat = summary["macros"]
    assert isinstance(cat["shared"], list) and len(cat["shared"]) >= 4, (
        "expected ≥4 shared macros (kill_chain, all_alerts, cim_zeek_conn, cim_zeek_dns)"
    )
    expected_shared_names = {"detlab_kill_chain", "detlab_all_alerts"}
    found_shared = {m["name"] for m in cat["shared"]}
    assert expected_shared_names <= found_shared, (
        f"shared macros missing: {expected_shared_names - found_shared}"
    )
    # Every shared macro must have a description and definition.
    for m in cat["shared"]:
        assert m["description"], f"shared macro {m['name']} has no description"
        assert m["definition"], f"shared macro {m['name']} has no definition"
    # Per-case bucket: exactly one macro per shipped case (current convention).
    case_ids_in_macros = {m["case_id"] for m in cat["per_case"]}
    case_ids_shipped = {c["id"] for c in summary["cases"]}
    assert case_ids_in_macros == case_ids_shipped, (
        f"macro<->case mismatch: missing={case_ids_shipped - case_ids_in_macros}, "
        f"extra={case_ids_in_macros - case_ids_shipped}"
    )


def test_every_shipped_case_has_schedule():
    """The /schedule heatmap depends on every saved-search case
    declaring a `cron_schedule` directive — drift catcher."""
    summary, _full = build_web_data.build_summary_payload()
    missing = [c["id"] for c in summary["cases"] if c.get("schedule") is None]
    assert not missing, f"cases without cron_schedule: {missing}"


def test_schedule_metadata_has_required_fields():
    summary, _full = build_web_data.build_summary_payload()
    for c in summary["cases"]:
        sched = c.get("schedule")
        if sched is None:
            continue
        assert sched["cron"], f"{c['id']}: empty cron"
        assert sched["stanza"], f"{c['id']}: empty stanza name"
        # earliest is sometimes empty for ad-hoc cases — allow blank.


def test_macros_parser_attaches_preceding_comment_block():
    """Drift catcher for the comment-association heuristic in
    _parse_macros_block. Synthetic input covers the three real layout
    patterns (comment-blank-stanza, no comment, multi-line comment)."""
    text = """# Description for first.
# Continuation line.

[first_macro]
definition = | search foo \\
| stats count
iseval = 0

[no_doc_macro]
definition = | search bar
iseval = 0

# Description for third.
[third_macro]
definition = | search baz
"""
    out = build_web_data._parse_macros_block(text)
    assert len(out) == 3
    assert out[0]["name"] == "first_macro"
    assert out[0]["description"] == "Description for first. Continuation line."
    assert "search foo" in out[0]["definition"]
    assert out[1]["name"] == "no_doc_macro"
    assert out[1]["description"] == ""
    assert out[2]["name"] == "third_macro"
    assert out[2]["description"] == "Description for third."


def test_summary_cases_are_sorted_by_tactic_then_technique():
    summary, _full = build_web_data.build_summary_payload()
    pairs = [(c["mitre_tactic"], c["mitre_technique"]) for c in summary["cases"]]
    assert pairs == sorted(pairs), "cases should be deterministically sorted"


def test_planned_cases_carry_rationale_and_sketch():
    """Roadmap page surfaces these — empty strings would render as awkward
    blank cells. Each planned case must explain *why* and *how*."""
    required_fields = (
        "title",
        "mitre_technique",
        "mitre_tactic",
        "effort",
        "rationale",
        "detection_sketch",
    )
    for p in build_web_data.PLANNED:
        for required in required_fields:
            assert p.get(required), f"PLANNED entry {p.get('mitre_technique')} missing {required}"
        assert p["effort"] in ("S", "M", "L"), f"unknown effort {p['effort']!r}"


def test_tactic_meta_covers_all_enterprise_tactics():
    """Every Enterprise ATT&CK tactic surfaces in the heatmap, even the ones
    with no detlab coverage — the *out-of-scope rationale* is the point."""
    expected = {
        "reconnaissance",
        "resource-development",
        "initial-access",
        "execution",
        "persistence",
        "privilege-escalation",
        "defense-evasion",
        "credential-access",
        "discovery",
        "lateral-movement",
        "collection",
        "command-and-control",
        "exfiltration",
        "impact",
    }
    assert set(build_web_data.TACTIC_META.keys()) == expected


def test_summary_payload_emits_tactic_metadata():
    summary, _full = build_web_data.build_summary_payload()
    assert "tactics" in summary
    by_slug = {t["slug"]: t for t in summary["tactics"]}
    # C2 has lots of cases shipped, no plans -> covered
    assert by_slug["command-and-control"]["status"] == "covered"
    # Lateral movement has 3 shipped (T1021.001 + .002 + T1570), no plans -> covered
    assert by_slug["lateral-movement"]["status"] == "covered"
    # Reconnaissance has T1046 + T1595.002 + T1595.003 shipped -> covered
    assert by_slug["reconnaissance"]["status"] == "covered"
    # Every tactic must carry a non-empty scope_note.
    for t in summary["tactics"]:
        assert t["scope_note"], f"{t['slug']} missing scope_note"


def test_validate_tactics_rejects_unknown_tactic():
    """Guards against the silent-drop bug where a case with a typo'd
    mitre_tactic would never appear on Roadmap / Tactic-detail pages."""
    bogus = [{"id": "x", "mitre_technique": "T9999", "mitre_tactic": "imaginary"}]
    with pytest.raises(ValueError, match="unknown tactics"):
        build_web_data._validate_tactics(bogus, [])


def test_every_full_case_payload_carries_references():
    """The CaseDetail references bar surfaces these — sigma.yml is the
    source. Most cases have at least the ATT&CK technique URL plus tool
    references; a missing block usually means the case is malformed."""
    _summary, fulls = build_web_data.build_summary_payload()
    for full in fulls:
        assert isinstance(full["references"], list), (
            f"{full['id']} references must be a list"
        )
        # Every shipped case's sigma.yml carries at least the ATT&CK URL.
        assert len(full["references"]) >= 1, (
            f"{full['id']} has no references — missing or malformed sigma.yml block?"
        )
        for url in full["references"]:
            assert url.startswith(("http://", "https://")), (
                f"{full['id']} reference {url!r} doesn't look like a URL"
            )


def test_every_enterprise_tactic_has_at_least_one_case_shipped_or_planned():
    """The matrix should have *something* in every cell — that's the lab's
    breadth-of-work claim. Out_of_scope tactics are still allowed; this test
    just asserts no tactic is silently empty (no shipped, no planned, no
    rationale)."""
    summary, _full = build_web_data.build_summary_payload()
    for t in summary["tactics"]:
        if t["status"] == "out_of_scope":
            # The scope note is the rationale — must be substantive.
            assert len(t["scope_note"]) >= 60, (
                f"{t['slug']} is out_of_scope but its scope_note is too thin "
                f"({len(t['scope_note'])} chars)"
            )
        else:
            assert t["shipped_count"] + t["planned_count"] >= 1, (
                f"{t['slug']} status={t['status']} but no cases attached"
            )


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
