"""Kill-chain meta-detector — composes every per-case detector and finds
source IPs where multiple distinct ATT&CK techniques fire in sequence.

The standalone detectors look at one technique at a time. A real intrusion
leaves a trail across several: T1190 (exploit) → T1133 (external remote
service) → T1078 (valid account) → T1021 (lateral movement) → T1041
(C2 exfil). Catching any single step is useful; catching the *chain* is
what gives a SOC analyst confidence the activity is a real intrusion and
not a noisy single-detector false positive.

The chain detector runs every detector in `CHAIN_REGISTRY` against the
input records, groups the alerts by source IP, and emits a `KillChainAlert`
for each src that fires >=N distinct techniques inside a sliding window.

The Splunk-side mirror is the `detlab_kill_chain` macro in
`shared/macros.conf`, which performs the same aggregation across the
union of all per-case macros via `detlab_all_alerts`.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from detlab import detector

# Single source of truth for the cross-detector chain analysis. Each entry
# binds a detector function to its ATT&CK metadata so we can present the
# kill chain in ATT&CK-coverage terms. Ordered loosely by where the
# technique tends to appear in an intrusion (recon → impact).
CHAIN_REGISTRY: list[dict[str, str]] = [
    # Reconnaissance
    {
        "fn": "detect_vuln_scan",
        "case_id": "t1595_002_vuln_scanning",
        "technique": "T1595.002",
        "tactic": "reconnaissance",
        "title": "Vulnerability scanning",
    },
    {
        "fn": "detect_web_wordlist",
        "case_id": "t1595_003_web_wordlist",
        "technique": "T1595.003",
        "tactic": "reconnaissance",
        "title": "Web wordlist scanning",
    },
    {
        "fn": "detect_port_scan",
        "case_id": "t1046_network_service_discovery",
        "technique": "T1046",
        "tactic": "discovery",
        "title": "Network Service Discovery",
    },
    # Resource development
    {
        "fn": "detect_newly_registered_domain",
        "case_id": "t1583_001_nrd_resolution",
        "technique": "T1583.001",
        "tactic": "resource-development",
        "title": "Newly-Registered Domain resolution",
    },
    # Initial access
    {
        "fn": "detect_suricata_exploits",
        "case_id": "t1190_suricata_exploit",
        "technique": "T1190",
        "tactic": "initial-access",
        "title": "Exploit Public-Facing Application",
    },
    # Execution
    {
        "fn": "detect_html_smuggling",
        "case_id": "t1027_006_html_smuggling",
        "technique": "T1027.006",
        "tactic": "execution",
        "title": "HTML Smuggling delivery",
    },
    # Persistence
    {
        "fn": "detect_external_remote_services",
        "case_id": "t1133_external_remote",
        "technique": "T1133",
        "tactic": "persistence",
        "title": "External Remote Services abuse",
    },
    # Privilege escalation
    {
        "fn": "detect_rpc_coercion",
        "case_id": "t1068_rpc_coercion",
        "technique": "T1068",
        "tactic": "privilege-escalation",
        "title": "RPC coercion (PetitPotam, DFSCoerce)",
    },
    # Credential access
    {
        "fn": "detect_ssh_brute_force",
        "case_id": "t1110_001_ssh_brute_force",
        "technique": "T1110.001",
        "tactic": "credential-access",
        "title": "SSH Brute Force",
    },
    # Lateral movement
    {
        "fn": "detect_rdp_lateral",
        "case_id": "t1021_001_rdp_lateral",
        "technique": "T1021.001",
        "tactic": "lateral-movement",
        "title": "RDP Lateral Movement",
    },
    {
        "fn": "detect_smb_lateral",
        "case_id": "t1021_002_smb_lateral",
        "technique": "T1021.002",
        "tactic": "lateral-movement",
        "title": "SMB admin shares",
    },
    {
        "fn": "detect_lateral_tool_transfer",
        "case_id": "t1570_lateral_tool_transfer",
        "technique": "T1570",
        "tactic": "lateral-movement",
        "title": "Lateral Tool Transfer",
    },
    # Collection
    {
        "fn": "detect_info_repo_bulk_read",
        "case_id": "t1213_002_info_repo_bulk",
        "technique": "T1213.002",
        "tactic": "collection",
        "title": "Information-Repository bulk read",
    },
    # Command and control
    {
        "fn": "detect_dns_tunnel",
        "case_id": "t1071_004_dns_c2_dnscat2",
        "technique": "T1071.004",
        "tactic": "command-and-control",
        "title": "DNS C2 (dnscat2)",
    },
    {
        "fn": "detect_beaconing",
        "case_id": "t1071_001_http_beacon_sliver",
        "technique": "T1071.001",
        "tactic": "command-and-control",
        "title": "HTTP Beaconing (Sliver)",
    },
    {
        "fn": "detect_dga_domains",
        "case_id": "t1568_002_dga_c2",
        "technique": "T1568.002",
        "tactic": "command-and-control",
        "title": "DGA C2",
    },
    {
        "fn": "detect_protocol_tunnel",
        "case_id": "t1572_protocol_tunneling_chisel",
        "technique": "T1572",
        "tactic": "command-and-control",
        "title": "Protocol Tunneling (chisel)",
    },
    {
        "fn": "detect_tor_relay_use",
        "case_id": "t1090_003_tor_relay_use",
        "technique": "T1090.003",
        "tactic": "command-and-control",
        "title": "Multi-hop Proxy / Tor",
    },
    {
        "fn": "detect_internal_proxy",
        "case_id": "t1090_001_internal_proxy",
        "technique": "T1090.001",
        "tactic": "defense-evasion",
        "title": "Internal proxy / SOCKS chaining",
    },
    {
        "fn": "detect_rmm_tool_use",
        "case_id": "t1219_rmm_tool_use",
        "technique": "T1219",
        "tactic": "command-and-control",
        "title": "Remote Access Software (RMM)",
    },
    # Exfiltration
    {
        "fn": "detect_dns_exfil",
        "case_id": "t1048_003_dns_exfil",
        "technique": "T1048.003",
        "tactic": "exfiltration",
        "title": "DNS Exfiltration (volume)",
    },
    {
        "fn": "detect_c2_exfil",
        "case_id": "t1041_exfil_over_c2",
        "technique": "T1041",
        "tactic": "exfiltration",
        "title": "Exfiltration Over C2",
    },
    {
        "fn": "detect_cloud_exfil",
        "case_id": "t1567_002_cloud_exfil",
        "technique": "T1567.002",
        "tactic": "exfiltration",
        "title": "Exfiltration to Cloud Storage",
    },
    # Impact
    {
        "fn": "detect_volumetric_flood",
        "case_id": "t1499_001_volumetric_flood",
        "technique": "T1499.001",
        "tactic": "impact",
        "title": "Volumetric Network Flood",
    },
]


@dataclass
class ChainTechnique:
    """A single technique firing inside a kill chain."""

    technique: str
    tactic: str
    detector_function: str
    case_id: str
    case_title: str
    timestamp: float
    """Earliest known firing time (unix seconds). 0.0 when the underlying
    alert dataclass aggregates over the full input window without
    preserving a per-alert timestamp."""
    detail: str
    """One-line summary of the underlying alert (e.g. "3 distinct dests")."""


@dataclass
class KillChainAlert:
    """Cross-detector finding: one source IP, multiple ATT&CK techniques."""

    src: str
    technique_count: int
    tactic_count: int
    earliest_ts: float
    latest_ts: float
    duration_seconds: float
    timeline: list[ChainTechnique] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)


def _alert_timestamp(alert: Any) -> float:
    return float(getattr(alert, "window_start", 0.0) or 0.0)


def _alert_detail(alert: Any) -> str:
    """Best-effort one-line description of an alert dataclass instance."""
    fields_priority = (
        "query_count",
        "connection_count",
        "distinct_destinations",
        "distinct_ports",
        "distinct_relays",
        "distinct_paths",
        "distinct_signatures",
        "distinct_404_paths",
        "distinct_operations",
        "alert_count",
        "attempts",
        "exfil_record_count",
        "total_bytes",
        "total_orig_bytes",
        "orig_bytes",
    )
    parts: list[str] = []
    dest = getattr(alert, "dest", None)
    if dest:
        parts.append(f"→{dest}")
    for fname in fields_priority:
        val = getattr(alert, fname, None)
        if val is not None and val != 0:
            parts.append(f"{fname}={val}")
            break
    return " ".join(parts) if parts else type(alert).__name__


def detect_attack_chain(
    records: Iterable[dict],
    *,
    min_distinct_techniques: int = 2,
    window_seconds: int = 86_400,
) -> list[KillChainAlert]:
    """Run every detector in CHAIN_REGISTRY against `records`, group all
    resulting alerts by source IP, and emit one KillChainAlert per src that
    fires >=`min_distinct_techniques` distinct techniques inside a sliding
    `window_seconds` window.

    Detectors that don't recognise the records (wrong source — e.g. running
    `detect_dns_tunnel` against http.log) just produce zero alerts and drop
    out cleanly.
    """
    record_list = list(records)

    # Per-src timeline of (technique, ChainTechnique). We dedupe by
    # technique-id so two firings of the same detector for the same src
    # collapse to the earliest (a single technique never multiplies the
    # chain length).
    by_src: dict[str, dict[str, ChainTechnique]] = {}

    for entry in CHAIN_REGISTRY:
        fn_name = entry["fn"]
        fn: Callable[..., list[Any]] | None = getattr(detector, fn_name, None)
        if fn is None:  # registry references a detector that doesn't exist
            continue
        try:
            alerts = fn(record_list)
        except (TypeError, ValueError, KeyError, AttributeError):
            # Defensive against malformed input rows; real bugs (e.g.
            # ImportError, NameError) still surface so we notice them.
            continue

        for alert in alerts:
            src = getattr(alert, "src", None)
            if not src:
                continue
            tech = ChainTechnique(
                technique=entry["technique"],
                tactic=entry["tactic"],
                detector_function=fn_name,
                case_id=entry["case_id"],
                case_title=entry["title"],
                timestamp=_alert_timestamp(alert),
                detail=_alert_detail(alert),
            )
            existing = by_src.setdefault(src, {}).get(entry["technique"])
            if existing is None or tech.timestamp < existing.timestamp:
                by_src[src][entry["technique"]] = tech

    chains: list[KillChainAlert] = []
    for src, by_tech in by_src.items():
        techs = sorted(by_tech.values(), key=lambda t: (t.timestamp, t.technique))
        if len(techs) < min_distinct_techniques:
            continue
        # Apply the sliding-window constraint: walk the sorted timeline
        # and find the longest run of distinct techniques whose timestamps
        # fit within `window_seconds`. We only emit if that run also meets
        # the minimum-count gate.
        best = _longest_window_run(techs, window_seconds)
        if len(best) < min_distinct_techniques:
            continue
        timestamps = [t.timestamp for t in best if t.timestamp > 0]
        earliest = min(timestamps) if timestamps else 0.0
        latest = max(timestamps) if timestamps else 0.0
        tactics_seen: list[str] = []
        for t in best:
            if t.tactic not in tactics_seen:
                tactics_seen.append(t.tactic)
        chains.append(
            KillChainAlert(
                src=src,
                technique_count=len(best),
                tactic_count=len(tactics_seen),
                earliest_ts=earliest,
                latest_ts=latest,
                duration_seconds=max(0.0, latest - earliest),
                timeline=best,
                tactics=tactics_seen,
            )
        )

    chains.sort(key=lambda c: (-c.technique_count, c.src))
    return chains


def _longest_window_run(techs: list[ChainTechnique], window_seconds: int) -> list[ChainTechnique]:
    """Pick the largest contiguous slice (sorted by timestamp) whose
    span fits in `window_seconds`. Techniques with timestamp 0 (alerts
    that aggregate over the whole input) are treated as "always within
    window" and included unconditionally."""
    if not techs:
        return []
    timed = [t for t in techs if t.timestamp > 0]
    untimed = [t for t in techs if t.timestamp <= 0]
    if not timed:
        return list(techs)

    timed.sort(key=lambda t: t.timestamp)
    best_lo, best_hi = 0, 0
    lo = 0
    for hi in range(len(timed)):
        while timed[hi].timestamp - timed[lo].timestamp > window_seconds:
            lo += 1
        if hi - lo > best_hi - best_lo:
            best_lo, best_hi = lo, hi
    return untimed + timed[best_lo : best_hi + 1]
