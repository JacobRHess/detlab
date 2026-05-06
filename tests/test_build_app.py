"""Tests for the Splunk app build pipeline.

The build pipeline is the seam between source-of-truth (cases/) and the
deployable Splunk app (app/). These tests catch the most common breakage:
- savedsearches reference macros that don't exist
- detlab_cases.csv loses cases when a new case lands
- the packaged tarball is missing structural pieces a Splunk app needs
"""

from __future__ import annotations

import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import build_app  # noqa: E402


def test_build_macros_includes_shared_and_per_case():
    macros = build_app.build_macros()
    assert "[detlab_all_alerts]" in macros, "shared macro not included"
    assert "[dns_tunnel_dnscat2]" in macros, "dnscat2 case macro not included"
    assert "[http_beacon_jitter]" in macros, "http beacon case macro not included"
    assert "[network_service_discovery]" in macros, "port scan case macro not included"
    assert "[protocol_tunnel_chisel]" in macros, "chisel tunnel case macro not included"
    assert "[tor_relay_use]" in macros, "tor relay case macro not included"
    assert "[dns_exfil_volume]" in macros, "dns exfil case macro not included"
    assert "[ssh_brute_force]" in macros, "ssh brute force case macro not included"
    assert "[dga_c2_lookup]" in macros, "dga case macro not included"
    assert "[rmm_tool_use]" in macros, "rmm case macro not included"
    assert "[volumetric_flood]" in macros, "volumetric flood macro not included"
    assert "[suricata_exploit_attempt]" in macros, "suricata exploit macro not included"
    assert "[c2_exfil]" in macros, "c2 exfil chained macro not included"
    assert "[cloud_exfil]" in macros, "cloud exfil macro not included"
    assert "[rdp_lateral]" in macros, "rdp lateral macro not included"
    # CIM helper macros
    assert "[detlab_cim_zeek_conn]" in macros, "CIM helper macro for conn missing"
    assert "[detlab_cim_zeek_dns]" in macros, "CIM helper macro for dns missing"


def test_build_savedsearches_concatenates_cases():
    s = build_app.build_savedsearches()
    assert "[DNS Tunnel" in s
    assert "[HTTP Beaconing" in s
    assert "[Network Service Discovery" in s
    assert "[Protocol Tunneling" in s
    assert "[Tor /" in s
    assert "[DNS Exfiltration" in s
    assert "[SSH Brute Force" in s
    assert "[DGA C2" in s
    assert "[Remote Access Software" in s
    assert "[Volumetric" in s
    assert "[Exploit Attempt" in s
    assert "[Exfiltration Over C2" in s
    assert "[Cloud Storage Exfiltration" in s
    assert "[RDP Lateral Movement" in s


def test_validate_passes_on_clean_build():
    macros = build_app.build_macros()
    savedsearches = build_app.build_savedsearches()
    cases_csv = build_app.build_cases_lookup()
    errors = build_app.validate(macros, savedsearches, cases_csv)
    assert errors == [], f"Validation failed: {errors}"


def test_validate_catches_undefined_macro_reference():
    macros = "[only_defined]\ndefinition = ...\n"
    savedsearches = "[bad]\nsearch = `undefined_macro`\n"
    cases_csv = "case_id\nfoo\n"
    errors = build_app.validate(macros, savedsearches, cases_csv)
    assert any("undefined" in e for e in errors)


def test_cases_lookup_has_expected_cases():
    csv_text = build_app.build_cases_lookup()
    assert "t1071_004_dns_c2_dnscat2" in csv_text
    assert "t1071_001_http_beacon_sliver" in csv_text
    assert "t1046_network_service_discovery" in csv_text
    assert "t1572_protocol_tunneling_chisel" in csv_text
    assert "t1090_003_tor_relay_use" in csv_text
    assert "t1048_003_dns_exfil" in csv_text
    assert "t1110_001_ssh_brute_force" in csv_text
    assert "t1568_002_dga_c2" in csv_text
    assert "t1219_rmm_tool_use" in csv_text
    assert "t1499_001_volumetric_flood" in csv_text
    assert "t1190_suricata_exploit" in csv_text
    assert "t1041_exfil_over_c2" in csv_text
    assert "t1567_002_cloud_exfil" in csv_text
    assert "t1021_001_rdp_lateral" in csv_text
    assert "T1071.004" in csv_text
    assert "T1046" in csv_text
    assert "T1572" in csv_text
    assert "T1090.003" in csv_text
    assert "T1048.003" in csv_text
    assert "T1110.001" in csv_text
    assert "T1568.002" in csv_text
    assert "T1219" in csv_text
    assert "T1499.001" in csv_text
    assert "T1190" in csv_text
    assert "T1041" in csv_text
    assert "T1071.001" in csv_text
    assert "T1567.002" in csv_text
    assert "T1021.001" in csv_text


def test_full_build_produces_tarball(tmp_path, monkeypatch):
    """End-to-end: run main(), verify tarball contains a deployable structure."""
    monkeypatch.setattr(build_app, "BUILD_DIR", tmp_path / "build")
    rc = build_app.main([])
    assert rc == 0

    version = build_app.get_version()
    tarball = tmp_path / "build" / f"detlab-{version}.tar.gz"
    assert tarball.exists()

    with tarfile.open(tarball, "r:gz") as tar:
        names = tar.getnames()

    required = [
        "detlab/default/app.conf",
        "detlab/default/macros.conf",
        "detlab/default/savedsearches.conf",
        # ES integration files emitted by build_app
        "detlab/default/correlationsearches.conf",
        "detlab/default/analyticstories.conf",
        "detlab/default/eventtypes.conf",
        "detlab/default/tags.conf",
        "detlab/default/workflow_actions.conf",
        # Static — ships in repo so the .spl works in any Splunk install.
        "detlab/default/props.conf",
        # Splunk Web app launcher icons.
        "detlab/static/appIcon.svg",
        "detlab/static/appIcon_2x.svg",
        "detlab/static/appIconAlt.svg",
        "detlab/default/data/ui/nav/default.xml",
        "detlab/default/data/ui/views/overview.xml",
        "detlab/default/data/ui/views/case_dnscat2.xml",
        "detlab/default/data/ui/views/case_http_beacon.xml",
        "detlab/lookups/detlab_cases.csv",
        "detlab/metadata/default.meta",
    ]
    missing = [r for r in required if r not in names]
    assert not missing, f"App tarball missing required files: {missing}"


# ---------- Splunk ES integration ----------


def test_correlationsearches_has_one_stanza_per_saved_search():
    cs = build_app.build_correlationsearches()
    ss = build_app.build_savedsearches()
    saved_search_count = sum(1 for ln in ss.splitlines() if ln.startswith("[") and ln.endswith("]"))
    correlation_count = sum(1 for ln in cs.splitlines() if ln.startswith("[") and ln.endswith("]"))
    assert correlation_count == saved_search_count, (
        f"correlationsearches stanzas ({correlation_count}) must match saved-search "
        f"count ({saved_search_count})"
    )


def test_correlationsearches_includes_attack_annotations():
    cs = build_app.build_correlationsearches()
    assert "annotations" in cs
    assert "mitre_attack" in cs
    assert "T1071.004" in cs


def test_analyticstories_groups_by_tactic():
    text = build_app.build_analyticstories()
    assert "Command and Control" in text
    assert "Initial Access" in text
    assert "Exfiltration" in text
    assert "Impact" in text
    assert "detection_searches =" in text


def test_eventtypes_define_alert_groupings():
    text = build_app.build_eventtypes()
    assert "[detlab_alert]" in text
    assert "[detlab_command_and_control_alert]" in text
    assert "[detlab_credential_access_alert]" in text


def test_tags_apply_cim_tags_to_eventtypes():
    text = build_app.build_tags()
    assert "[eventtype=detlab_alert]" in text
    assert "alert = enabled" in text
    assert "attack = enabled" in text
    assert "[eventtype=detlab_command_and_control_alert]" in text
    assert "network = enabled" in text


def test_workflow_actions_includes_pivot_actions():
    text = build_app.build_workflow_actions()
    assert "[detlab_pivot_src]" in text
    assert "[detlab_pivot_attack_mitre]" in text
    assert "attack.mitre.org/techniques/$mitre_technique$/" in text
    assert "github.com/JacobRHess/detlab/tree/main/cases/$case_id$" in text


def test_validate_skips_backticks_in_comments():
    """Markdown-style backticks inside ``# comment`` lines must not be parsed
    as macro references. Guards against a real bug where a comment said
    ``# Tune `risk_score` to match...`` and tripped the validator."""
    macros = "[real_macro]\ndefinition = search ...\n"
    savedsearches = (
        "[Some Rule]\n"
        "# Tune `risk_score` field — backticks here must not be macro refs.\n"
        "search = `real_macro`\n"
    )
    cases_csv = "case_id\nfoo\n"
    errors = build_app.validate(macros, savedsearches, cases_csv)
    assert errors == [], f"Unexpected validate errors: {errors}"


@pytest.mark.parametrize(
    "case_dir_name", ["t1071_004_dns_c2_dnscat2", "t1071_001_http_beacon_sliver"]
)
def test_each_case_has_required_files(case_dir_name):
    case = ROOT / "cases" / case_dir_name
    required = [
        case / "README.md",
        case / "detection" / "macros.conf",
        case / "detection" / "savedsearches.conf",
        case / "detection" / "search.spl",
        case / "detection" / "sigma.yml",
        case / "tests" / "test_detection.py",
    ]
    missing = [p for p in required if not p.exists()]
    assert not missing, f"Case {case_dir_name} missing files: {[str(p) for p in missing]}"
