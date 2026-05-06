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
    "t1219_rmm_tool_use": {
        "detector_function": "detect_rmm_tool_use",
        "fixture_kind": "zeek_json",
    },
    "t1499_001_volumetric_flood": {
        "detector_function": "detect_volumetric_flood",
        "fixture_kind": "zeek_json",
    },
    "t1190_suricata_exploit": {
        "detector_function": "detect_suricata_exploits",
        "fixture_kind": "suricata_eve",
    },
    "t1041_exfil_over_c2": {
        "detector_function": "detect_c2_exfil",
        "fixture_kind": "zeek_json",
    },
    "t1567_002_cloud_exfil": {
        "detector_function": "detect_cloud_exfil",
        "fixture_kind": "zeek_json",
    },
}

# Planned cases not yet in app/lookups/detlab_cases.csv. Each entry carries
# enough metadata to render the Roadmap page — the rationale ("why ship
# this") and detection sketch ("how would it work") are the parts a
# detection engineer cares about when scoping work.
#
# Effort: S = 1-day case, M = 2-3 days, L = a week+ (often needs new
# fixture-generation infrastructure or a new telemetry source).
PLANNED: list[dict[str, str]] = [
    # Reconnaissance — Suricata is already wired up so vuln-scanning + web
    # wordlist scanning piggy-back on the T1190 telemetry path.
    {
        "title": "Vulnerability scanning",
        "mitre_technique": "T1595.002",
        "mitre_tactic": "reconnaissance",
        "effort": "M",
        "rationale": (
            "Public-internet-exposed services see this constantly; SOC teams "
            "want a non-noisy filter. Pairs with the existing T1190 Suricata case."
        ),
        "detection_sketch": (
            "Aggregate Suricata IDS alerts in the 'Attempted Information Leak' / "
            "'Web Application Attack' categories per (src, signature_id_prefix) "
            "with a per-source rate threshold."
        ),
    },
    {
        "title": "Web wordlist / directory scanning (gobuster, dirb, ffuf)",
        "mitre_technique": "T1595.003",
        "mitre_tactic": "reconnaissance",
        "effort": "S",
        "rationale": (
            "Cheap-and-loud signal that catches red-team recon and curious "
            "external bots. Zeek http.log makes it trivial."
        ),
        "detection_sketch": (
            "Per (src, dest, host), count distinct URI paths with status code 404 "
            "in a 60-s window. Threshold >= 50 distinct 404s; suppress search "
            "engines via UA allowlist."
        ),
    },
    # Persistence — only the network-visible piece (T1133 covers VPN / "
    # external remote services).
    {
        "title": "External Remote Services (VPN, RDP from unusual sources)",
        "mitre_technique": "T1133",
        "mitre_tactic": "persistence",
        "effort": "M",
        "rationale": (
            "Initial-access via VPN/RDP credential abuse is the #1 ransomware "
            "delivery path in 2024-25 incident reports. Geo-anomaly + "
            "first-time-source pattern is well understood."
        ),
        "detection_sketch": (
            "Conn.log on dest_ports {3389, 1194, 4500, 500, 443+SNI=vpn.*}: "
            "compare src ASN/geo against historical baseline lookup; alert on "
            "first-time-seen src for that dest."
        ),
    },
    # Defense Evasion — sibling of the Tor case.
    {
        "title": "Internal proxy / SOCKS chaining",
        "mitre_technique": "T1090.001",
        "mitre_tactic": "defense-evasion",
        "effort": "S",
        "rationale": (
            "Operators stand up an internal pivot to obfuscate east-west "
            "traffic. Sibling of the T1090.003 Tor case; same lookup-driven "
            "shape with internal IP candidates."
        ),
        "detection_sketch": (
            "Per src, count distinct internal-network destinations on "
            "common SOCKS / HTTP-CONNECT ports (1080, 3128, 8080) over 1 h. "
            "Threshold >= 3 distinct internal pivots."
        ),
    },
    # Lateral Movement — the most fertile network surface for new cases.
    {
        "title": "Remote Desktop Protocol (RDP) lateral",
        "mitre_technique": "T1021.001",
        "mitre_tactic": "lateral-movement",
        "effort": "M",
        "rationale": (
            "Post-compromise pivot via RDP is one of the most-observed "
            "lateral-movement signatures across DFIR-Report engagements. "
            "Complements T1110.001 SSH brute force on the credential-access "
            "side."
        ),
        "detection_sketch": (
            "Conn.log on dest_port=3389 between internal hosts: per (src, dest), "
            "first-seen-pair detection over 30-day baseline; suppress allow-listed "
            "admin-jumphost pairs."
        ),
    },
    {
        "title": "SMB admin shares (T1021.002 — psexec / SMB lateral)",
        "mitre_technique": "T1021.002",
        "mitre_tactic": "lateral-movement",
        "effort": "M",
        "rationale": (
            "psexec / SMBExec / wmiexec all leave Zeek smb.log fingerprints. "
            "High-confidence detection of post-compromise pivoting on Windows networks."
        ),
        "detection_sketch": (
            "Zeek smb_files.log: track named-pipe usage (svcctl, scerpc, atsvc) "
            "between internal hosts; alert on first-seen src→dest pair touching "
            "ADMIN$ or IPC$ outside known admin paths."
        ),
    },
    {
        "title": "Lateral Tool Transfer",
        "mitre_technique": "T1570",
        "mitre_tactic": "lateral-movement",
        "effort": "M",
        "rationale": (
            "Operators copy their toolkit between compromised hosts. "
            "Internal-east-west file transfers with PE-shape headers are a "
            "loud signal."
        ),
        "detection_sketch": (
            "Zeek files.log: track file transfers between internal hosts where "
            "mime_type indicates executable content (PE, ELF, scripts). Alert "
            "on first-seen src→dest pair carrying executable bytes."
        ),
    },
]


# Tactic-level metadata. Drives the Stats heatmap status colouring and
# /tactic/:slug detail pages. Tactics with zero shipped + zero planned cases
# get an `out_of_scope` label + a sentence explaining *why* — the lab has a
# defensible network-detection charter, and the GUI should advertise that.
TACTIC_META: dict[str, dict[str, str]] = {
    "reconnaissance": {
        "name": "Reconnaissance",
        "description": (
            "Pre-attack info gathering — port scans, vuln scans, web fuzzing, "
            "DNS enumeration."
        ),
        "scope_note": (
            "Network-visible; covered by T1046 today and planned coverage above."
        ),
    },
    "resource-development": {
        "name": "Resource Development",
        "description": (
            "Adversary infrastructure setup — domain registration, SSL cert "
            "acquisition, capability development."
        ),
        "scope_note": (
            "Mostly off-network — domain registration is observable only via passive "
            "DNS / WHOIS feeds, capability development is an OSINT problem. Out of "
            "scope for a network-detection lab; pair detlab with a CTI feed."
        ),
    },
    "initial-access": {
        "name": "Initial Access",
        "description": (
            "Getting the foothold — phishing, exploits, valid-account abuse, "
            "supply chain."
        ),
        "scope_note": (
            "T1190 (Suricata IDS exploit) covers the network-visible exploit path; "
            "phishing is process/email telemetry."
        ),
    },
    "execution": {
        "name": "Execution",
        "description": (
            "Running the payload — PowerShell, scheduled tasks, Office macros, "
            "native APIs."
        ),
        "scope_note": (
            "Predominantly process-level (Sysmon, EDR). Out of scope for a "
            "network-detection lab; pair detlab with a Sysmon-driven detection set."
        ),
    },
    "persistence": {
        "name": "Persistence",
        "description": (
            "Maintaining access — registry run keys, services, valid accounts, "
            "external remote services."
        ),
        "scope_note": (
            "T1133 (External Remote Services) is network-visible and planned. "
            "Most other persistence techniques are process / AD telemetry."
        ),
    },
    "privilege-escalation": {
        "name": "Privilege Escalation",
        "description": (
            "Getting higher privileges — UAC bypass, token manipulation, "
            "exploit-for-priv-esc, valid accounts."
        ),
        "scope_note": (
            "Almost entirely process / OS-level. Network-detection lab can't see "
            "this without endpoint telemetry; out of scope by design."
        ),
    },
    "defense-evasion": {
        "name": "Defense Evasion",
        "description": (
            "Hiding from detection — obfuscation, masquerading, proxy chains, "
            "valid accounts."
        ),
        "scope_note": (
            "T1090.003 Tor ships today; T1090.001 internal proxy is planned. "
            "Process-level evasion (T1027 etc.) out of scope."
        ),
    },
    "credential-access": {
        "name": "Credential Access",
        "description": (
            "Stealing creds — brute force, OS credential dumping, kerberoasting, MITM."
        ),
        "scope_note": (
            "T1110.001 SSH brute force ships today. Most credential-access "
            "techniques are process / AD telemetry."
        ),
    },
    "discovery": {
        "name": "Discovery",
        "description": (
            "Mapping the environment — port scans, share enumeration, AD reconnaissance."
        ),
        "scope_note": (
            "T1046 network service discovery ships today. AD-side discovery "
            "(T1018, T1087.002) needs Sysmon / AD logs."
        ),
    },
    "lateral-movement": {
        "name": "Lateral Movement",
        "description": (
            "Moving across the environment — RDP, SMB, SSH, WinRM, remote services."
        ),
        "scope_note": (
            "Highly network-visible; three planned cases cover RDP / SMB / "
            "lateral tool transfer."
        ),
    },
    "collection": {
        "name": "Collection",
        "description": (
            "Gathering data of interest — local files, screenshots, keylogging, "
            "info repos."
        ),
        "scope_note": (
            "Almost entirely process-level. Some borderline cases (T1213 info "
            "repository scraping over HTTP) could fit here but are below "
            "priority. Out of scope for now."
        ),
    },
    "command-and-control": {
        "name": "Command and Control",
        "description": (
            "Operator-implant comms — beacons, tunnels, DNS-C2, proxies, RMM, DGAs."
        ),
        "scope_note": (
            "Most-covered tactic — six shipped cases across five detection styles."
        ),
    },
    "exfiltration": {
        "name": "Exfiltration",
        "description": (
            "Getting the loot out — DNS exfil, cloud-storage staging, "
            "exfil over C2 channel."
        ),
        "scope_note": (
            "Three shipped cases including the chained T1041 "
            "(beacon prerequisite + uplink bytes)."
        ),
    },
    "impact": {
        "name": "Impact",
        "description": (
            "Disrupting / destroying / extorting — ransomware, DoS, "
            "data destruction, encryption."
        ),
        "scope_note": (
            "T1499.001 volumetric flood ships today. Encryption-for-impact "
            "(T1486 ransomware) is process / file-system telemetry — out of "
            "scope for a network-detection lab."
        ),
    },
}


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


def build_tactic_meta(summaries: list[dict], planned: list[dict]) -> list[dict]:
    """Per-tactic metadata for the Roadmap + /tactic/:slug pages.

    Buckets the lab's coverage so the Stats heatmap and Roadmap can advertise
    the lab's *charter*: shipped vs partial vs planned vs out-of-scope. A
    tactic is `out_of_scope` only if TACTIC_META carries no plans AND no
    cases ship — that's the "we know we don't cover this and here's why"
    signal."""
    out: list[dict] = []
    for slug, meta in TACTIC_META.items():
        shipped = sum(1 for c in summaries if c["mitre_tactic"] == slug)
        planned_count = sum(1 for p in planned if p["mitre_tactic"] == slug)
        if shipped > 0 and planned_count > 0:
            status = "partial"
        elif shipped > 0:
            status = "covered"
        elif planned_count > 0:
            status = "planned"
        else:
            status = "out_of_scope"
        out.append(
            {
                "slug": slug,
                "name": meta["name"],
                "description": meta["description"],
                "scope_note": meta["scope_note"],
                "status": status,
                "shipped_count": shipped,
                "planned_count": planned_count,
            }
        )
    return out


def build_summary_payload() -> tuple[dict, list[dict]]:
    """Return the summary payload + the per-case full dicts ready to write."""
    if not LOOKUP.exists():
        raise FileNotFoundError(f"missing {LOOKUP} — run `py scripts/build_app.py` first")

    with LOOKUP.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    full_payloads = [build_case_full(r) for r in rows]
    summaries = [build_case_summary(r, f) for r, f in zip(rows, full_payloads, strict=True)]

    summaries.sort(key=_sort_key)
    planned = [build_planned(p) for p in PLANNED]
    tactics = build_tactic_meta(summaries, planned)
    summary_payload = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "cases": summaries,
        "planned": planned,
        "tactics": tactics,
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
