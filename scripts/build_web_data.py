"""Build the data the static portfolio site under web/ consumes.

cases/ stays the single source of truth — this script is read-only against
case content. It produces three things at build time:

  1. web/src/data/cases.json            (lean summary, bundled with the site)
  2. web/public/cases/<id>.json         (per-case detail, fetched on demand)
  3. web/public/py/{detector,entropy,zeek_loader}.py  (Pyodide runtime)

Splitting summary from per-case content keeps the home/Stats pages small
no matter how many cases land — only the case the user opens pays the
network cost for its fixtures and SPL.

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

# Bundled with the site at build time. Lean — summary fields only.
SUMMARY_OUT = ROOT / "web" / "src" / "data" / "cases.json"

# Fetched on demand by CaseDetail. One file per case — heavy fields
# (README, SPL, fixtures) live here so the home/Stats pages stay small.
PER_CASE_DEST = ROOT / "web" / "public" / "cases"

# Pyodide playground fetches detlab.detector + its stdlib-only deps from
# /py/<name>. Copied at build time so the in-browser detector runs the
# same code CI runs — no parallel JS port to drift against.
PY_SRC = ROOT / "src" / "detlab"
PY_DEST = ROOT / "web" / "public" / "py"
PY_FILES = ("detector.py", "entropy.py", "zeek_loader.py")

# Bumped when the JSON shape changes in a non-back-compatible way.
SCHEMA_VERSION = 2

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
    "t1110_001_ssh_brute_force": {
        "detector_function": "detect_ssh_brute_force",
        "fixture_kind": "zeek_json",
    },
    "t1568_002_dga_c2": {
        "detector_function": "detect_dga_domains",
        "fixture_kind": "zeek_json",
    },
}

# Planned cases not yet in app/lookups/detlab_cases.csv. Keep in sync with
# the README cases table.
PLANNED: list[dict[str, str]] = []


# ---------- File helpers ----------


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.exists() else ""


def _attack_url(technique: str) -> str:
    """Build the canonical attack.mitre.org URL: T1071.004 -> .../techniques/T1071/004/."""
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


# ---------- Data builders ----------


def build_case_full(row: dict[str, str]) -> dict:
    """Heavy per-case payload — written to web/public/cases/<id>.json."""
    case_id = row["case_id"]
    case_dir = CASES_DIR / case_id
    if not case_dir.is_dir():
        sys.exit(f"missing case dir: {case_dir}")

    detection = case_dir / "detection"
    return {
        "id": case_id,
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
    }


def build_case_summary(row: dict[str, str], full: dict) -> dict:
    """Lightweight per-case row — bundled with the site. Includes precomputed
    fixture record counts so the Stats page renders without parsing fixtures."""
    pos = full["fixtures"]["positive"]
    neg = full["fixtures"]["negative"]
    return {
        "id": row["case_id"],
        "title": row["case_title"],
        "view_name": row["view_name"],
        "mitre_technique": row["mitre_technique"],
        "mitre_tactic": row["mitre_tactic"],
        "mitre_url": _attack_url(row["mitre_technique"]),
        "severity": row["severity"],
        "status": row["status"],
        "fixture_record_counts": {
            "positive": pos["line_count"] if pos else 0,
            "negative": neg["line_count"] if neg else 0,
        },
        "wiring": CASE_WIRING.get(row["case_id"], {}),
    }


def build_planned(p: dict[str, str]) -> dict:
    return {
        **p,
        "status": "planned",
        "mitre_url": _attack_url(p["mitre_technique"]),
    }


def _sort_key(c: dict) -> tuple[str, str]:
    """Sort cases by tactic then technique ID for deterministic UI ordering."""
    return (c.get("mitre_tactic", ""), c.get("mitre_technique", ""))


# ---------- Outputs ----------


def build_summary_payload() -> tuple[dict, list[dict]]:
    """Return the summary payload + the per-case full dicts ready to write."""
    if not LOOKUP.exists():
        raise FileNotFoundError(f"missing {LOOKUP} — run `py scripts/build_app.py` first")

    with LOOKUP.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    full_payloads = [build_case_full(r) for r in rows]
    summaries = [build_case_summary(r, f) for r, f in zip(rows, full_payloads, strict=True)]

    summaries.sort(key=_sort_key)
    summary_payload = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "cases": summaries,
        "planned": [build_planned(p) for p in PLANNED],
    }
    return summary_payload, full_payloads


def write_summary(payload: dict) -> None:
    SUMMARY_OUT.parent.mkdir(parents=True, exist_ok=True)
    SUMMARY_OUT.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def write_per_case(full_payloads: list[dict]) -> None:
    PER_CASE_DEST.mkdir(parents=True, exist_ok=True)
    for case in full_payloads:
        path = PER_CASE_DEST / f"{case['id']}.json"
        path.write_text(
            json.dumps(case, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )


def copy_py_runtime() -> None:
    PY_DEST.mkdir(parents=True, exist_ok=True)
    for name in PY_FILES:
        src = PY_SRC / name
        if not src.exists():
            sys.exit(f"missing python source: {src}")
        (PY_DEST / name).write_text(src.read_text(encoding="utf-8"), encoding="utf-8")


def main() -> int:
    summary, full_payloads = build_summary_payload()
    write_summary(summary)
    write_per_case(full_payloads)
    copy_py_runtime()
    rel = SUMMARY_OUT.relative_to(ROOT)
    print(
        f"wrote {rel} ({len(summary['cases'])} shipped, {len(summary['planned'])} planned); "
        f"wrote {len(full_payloads)} per-case files to web/public/cases/; "
        f"copied {len(PY_FILES)} py modules to web/public/py/"
    )
    return 0


# ---------- Compatibility shims for tests ----------


def build_payload() -> dict:
    """Back-compat for older tests — combines summary + per-case content into
    one payload. New code should call build_summary_payload() and treat the
    two outputs separately."""
    summary, fulls = build_summary_payload()
    full_by_id = {f["id"]: f for f in fulls}
    cases_combined = []
    for s in summary["cases"]:
        cases_combined.append({**s, **full_by_id.get(s["id"], {})})
    return {
        **summary,
        "cases": cases_combined,
    }


def build_case(row: dict[str, str]) -> dict:
    """Back-compat for older tests — rebuilds a combined summary + full case dict."""
    full = build_case_full(row)
    summary = build_case_summary(row, full)
    return {**summary, **full}


if __name__ == "__main__":
    raise SystemExit(main())
