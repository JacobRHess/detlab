"""Build web/src/data/cases.json from cases/ + app/lookups/detlab_cases.csv.

The static portfolio site (web/) consumes this file. cases/ stays the single
source of truth — this script is read-only against case content.

Usage: py scripts/build_web_data.py
Prereq: app/lookups/detlab_cases.csv must exist (run scripts/build_app.py first).
"""

from __future__ import annotations

import csv
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CASES_DIR = ROOT / "cases"
LOOKUP = ROOT / "app" / "lookups" / "detlab_cases.csv"
OUT = ROOT / "web" / "src" / "data" / "cases.json"

# Pyodide playground fetches detlab.detector + its stdlib-only deps from
# /py/<name>. We copy them at build time so the in-browser detector runs the
# *same* code CI runs — no parallel JS port to drift against.
PY_SRC = ROOT / "src" / "detlab"
PY_DEST = ROOT / "web" / "public" / "py"
PY_FILES = ("detector.py", "entropy.py", "zeek_loader.py")

# Per-case wiring for the in-browser Pyodide playground.
# Tells the web app which function from detlab.detector to call and how to
# parse the bundled fixtures. Add an entry when shipping a new case.
CASE_WIRING: dict[str, dict[str, str]] = {
    "t1071_004_dns_c2_dnscat2": {
        "detector_function": "detect_dns_tunnel",
        "fixture_kind": "zeek_json",
    },
    "t1071_001_http_beacon_sliver": {
        "detector_function": "detect_beaconing",
        "fixture_kind": "zeek_json",
    },
    "t1046_network_service_discovery": {
        "detector_function": "detect_port_scan",
        "fixture_kind": "zeek_json",
    },
    "t1572_protocol_tunneling_chisel": {
        "detector_function": "detect_protocol_tunnel",
        "fixture_kind": "zeek_json",
    },
    "t1090_003_tor_relay_use": {
        "detector_function": "detect_tor_relay_use",
        "fixture_kind": "zeek_json",
    },
    "t1048_003_dns_exfil": {
        "detector_function": "detect_dns_exfil",
        "fixture_kind": "zeek_json",
    },
}

# Planned cases not yet in app/lookups/detlab_cases.csv (which only lists shipped).
# Empty for now — all README-listed cases ship in this branch.
PLANNED: list[dict[str, str]] = []


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.exists() else ""


def _attack_url(technique: str) -> str:
    """T1071.004 -> https://attack.mitre.org/techniques/T1071/004/"""
    parts = technique.split(".")
    return "https://attack.mitre.org/techniques/" + "/".join(parts) + "/"


def _fixture(case_dir: Path, kind: str) -> dict | None:
    tests = case_dir / "tests"
    matches = sorted(tests.glob(f"{kind}_*.log"))
    if not matches:
        return None
    f = matches[0]
    text = _read(f)
    line_count = len([ln for ln in text.splitlines() if ln.strip()])
    return {
        "filename": f.name,
        "line_count": line_count,
        "content": text,
    }


def build_case(row: dict[str, str]) -> dict:
    case_id = row["case_id"]
    case_dir = CASES_DIR / case_id
    if not case_dir.is_dir():
        sys.exit(f"missing case dir: {case_dir}")

    detection = case_dir / "detection"
    return {
        "id": case_id,
        "title": row["case_title"],
        "view_name": row["view_name"],
        "mitre_technique": row["mitre_technique"],
        "mitre_tactic": row["mitre_tactic"],
        "mitre_url": _attack_url(row["mitre_technique"]),
        "severity": row["severity"],
        "status": row["status"],
        "readme_md": _read(case_dir / "README.md"),
        "attack_md": _read(case_dir / "attack" / "README.md"),
        "detection": {
            "spl": _read(detection / "search.spl"),
            "macros_conf": _read(detection / "macros.conf"),
            "savedsearches_conf": _read(detection / "savedsearches.conf"),
            "sigma_yaml": _read(detection / "sigma.yml"),
        },
        "fixtures": {
            "positive": _fixture(case_dir, "positive"),
            "negative": _fixture(case_dir, "negative"),
        },
        "wiring": CASE_WIRING.get(case_id, {}),
    }


def build_planned(p: dict[str, str]) -> dict:
    return {
        **p,
        "status": "planned",
        "mitre_url": _attack_url(p["mitre_technique"]),
    }


def build_payload() -> dict:
    if not LOOKUP.exists():
        raise FileNotFoundError(f"missing {LOOKUP} — run `py scripts/build_app.py` first")

    with LOOKUP.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    return {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "cases": [build_case(r) for r in rows],
        "planned": [build_planned(p) for p in PLANNED],
    }


def copy_py_runtime() -> None:
    PY_DEST.mkdir(parents=True, exist_ok=True)
    for name in PY_FILES:
        src = PY_SRC / name
        if not src.exists():
            sys.exit(f"missing python source: {src}")
        (PY_DEST / name).write_text(src.read_text(encoding="utf-8"), encoding="utf-8")


def main() -> int:
    payload = build_payload()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    copy_py_runtime()
    rel = OUT.relative_to(ROOT)
    print(
        f"wrote {rel} ({len(payload['cases'])} shipped, {len(payload['planned'])} planned); "
        f"copied {len(PY_FILES)} py modules to web/public/py/"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
