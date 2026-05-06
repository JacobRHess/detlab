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
    assert "T1071.004" in csv_text
    assert "T1046" in csv_text
    assert "T1572" in csv_text
    assert "T1090.003" in csv_text
    assert "T1048.003" in csv_text
    assert "T1110.001" in csv_text
    assert "T1568.002" in csv_text
    assert "T1071.001" in csv_text


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
        "detlab/default/data/ui/nav/default.xml",
        "detlab/default/data/ui/views/overview.xml",
        "detlab/default/data/ui/views/case_dnscat2.xml",
        "detlab/default/data/ui/views/case_http_beacon.xml",
        "detlab/lookups/detlab_cases.csv",
        "detlab/metadata/default.meta",
    ]
    missing = [r for r in required if r not in names]
    assert not missing, f"App tarball missing required files: {missing}"


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
