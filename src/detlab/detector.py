"""Generic detection runner — Python mirror of the per-case SPL searches.

Each case ships a `detect_<technique>(records)` function that returns a list
of alert dicts. CI tests assert: positive fixtures produce >=1 alert,
negative fixtures produce 0. The SPL macros in each case's `macros.conf`
are the production artifact; this module is the testable specification of
what those macros mean.
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from itertools import pairwise

from detlab.entropy import shannon_entropy
from detlab.zeek_loader import base_domain, leftmost_label


@dataclass
class DnsTunnelAlert:
    window_start: float
    src: str
    base_domain: str
    query_count: int
    unique_queries: int
    avg_sub_len: float
    max_sub_len: int
    avg_entropy: float
    qtypes: list[str] = field(default_factory=list)


def detect_dns_tunnel(
    records: Iterable[dict],
    *,
    window_seconds: int = 300,
    min_query_count: int = 50,
    min_avg_sub_len: float = 20.0,
    min_avg_entropy: float = 3.5,
    min_unique_queries: int = 30,
    suspicious_qtypes: tuple[str, ...] = ("TXT", "MX", "CNAME", "NULL"),
) -> list[DnsTunnelAlert]:
    """Detect DNS tunneling (e.g. dnscat2) by aggregating Zeek dns.log records.

    Group by (time-bucket, source IP, base domain). Flag groups with high
    query volume + long, high-entropy subdomain labels — the signal pattern
    produced by tunneling tools that encode payloads in DNS labels.
    """
    groups: dict[tuple[int, str, str], list[dict]] = defaultdict(list)

    for r in records:
        ts = r.get("ts", 0)
        src = r.get("id.orig_h") or r.get("src") or "unknown"
        query = r.get("query", "")
        if not query:
            continue
        bucket = int(ts // window_seconds) * window_seconds
        bd = base_domain(query)
        groups[(bucket, src, bd)].append(r)

    alerts: list[DnsTunnelAlert] = []
    for (bucket, src, bd), recs in groups.items():
        labels = [leftmost_label(r["query"]) for r in recs]
        sub_lens = [len(label) for label in labels]
        entropies = [shannon_entropy(label) for label in labels]
        unique_queries = len({r["query"] for r in recs})
        qtypes = sorted({r.get("qtype_name", "") for r in recs if r.get("qtype_name")})

        avg_len = sum(sub_lens) / len(sub_lens) if sub_lens else 0
        avg_ent = sum(entropies) / len(entropies) if entropies else 0

        has_suspicious_qtype = any(q in suspicious_qtypes for q in qtypes)

        if (
            len(recs) >= min_query_count
            and avg_len >= min_avg_sub_len
            and avg_ent >= min_avg_entropy
            and unique_queries >= min_unique_queries
            and has_suspicious_qtype
        ):
            alerts.append(
                DnsTunnelAlert(
                    window_start=float(bucket),
                    src=src,
                    base_domain=bd,
                    query_count=len(recs),
                    unique_queries=unique_queries,
                    avg_sub_len=avg_len,
                    max_sub_len=max(sub_lens),
                    avg_entropy=avg_ent,
                    qtypes=qtypes,
                )
            )

    return alerts


@dataclass
class BeaconAlert:
    src: str
    dest: str
    connection_count: int
    avg_interval: float
    interval_stddev: float
    coefficient_of_variation: float
    duration_seconds: float


def detect_beaconing(
    records: Iterable[dict],
    *,
    min_connections: int = 30,
    max_avg_interval: float = 600.0,
    max_coefficient_of_variation: float = 0.1,
    min_duration_seconds: float = 600.0,
) -> list[BeaconAlert]:
    """Detect periodic beaconing in Zeek conn.log / http.log records.

    Beacons (Sliver, Cobalt Strike default profiles, Empire, etc.) connect
    on a steady cadence — high count, low interval variance. We group by
    (src, dest) and compute the coefficient of variation (stddev / mean) of
    inter-connection intervals; below a threshold means the timing is
    unnaturally regular.
    """
    groups: dict[tuple[str, str], list[float]] = defaultdict(list)

    for r in records:
        ts = r.get("ts", 0)
        src = r.get("id.orig_h") or r.get("src") or "unknown"
        # Prefer destination host header for HTTP, otherwise the resolved IP.
        dest = r.get("host") or r.get("id.resp_h") or r.get("dest") or "unknown"
        if src == "unknown" or dest == "unknown":
            continue
        groups[(src, dest)].append(float(ts))

    alerts: list[BeaconAlert] = []
    for (src, dest), times in groups.items():
        times.sort()
        if len(times) < min_connections:
            continue

        intervals = [t2 - t1 for t1, t2 in pairwise(times) if t2 > t1]
        if len(intervals) < 2:
            continue

        avg = statistics.fmean(intervals)
        if avg <= 0 or avg > max_avg_interval:
            continue

        stddev = statistics.pstdev(intervals)
        cov = stddev / avg
        duration = times[-1] - times[0]

        if cov <= max_coefficient_of_variation and duration >= min_duration_seconds:
            alerts.append(
                BeaconAlert(
                    src=src,
                    dest=dest,
                    connection_count=len(times),
                    avg_interval=avg,
                    interval_stddev=stddev,
                    coefficient_of_variation=cov,
                    duration_seconds=duration,
                )
            )

    return alerts


@dataclass
class PortScanAlert:
    window_start: float
    src: str
    dest: str
    distinct_ports: int
    total_connections: int
    incomplete_fraction: float
    duration_seconds: float
    sample_ports: list[int] = field(default_factory=list)


# Zeek conn_state values for sessions that never completed a normal handshake —
# SYN with no reply (S0), connection rejected (REJ), various RST patterns.
# Port scanners produce these in bulk; legitimate browsing produces SF.
INCOMPLETE_CONN_STATES: tuple[str, ...] = (
    "S0",
    "REJ",
    "RSTO",
    "RSTOS0",
    "RSTRH",
    "RSTR",
    "SH",
    "SHR",
)


def detect_port_scan(
    records: Iterable[dict],
    *,
    window_seconds: int = 60,
    min_distinct_ports: int = 100,
    min_incomplete_fraction: float = 0.7,
    incomplete_states: tuple[str, ...] = INCOMPLETE_CONN_STATES,
) -> list[PortScanAlert]:
    """Detect TCP port scanning (T1046) by aggregating Zeek conn.log records.

    Group by (time-bucket, src, dest). Flag groups with high distinct-port
    cardinality and a high fraction of incomplete sessions. nmap / masscan
    against a host produce 100s of distinct dest ports in a window where
    almost no connection completes.
    """
    groups: dict[tuple[int, str, str], list[dict]] = defaultdict(list)
    for r in records:
        ts = r.get("ts", 0)
        src = r.get("id.orig_h") or r.get("src") or "unknown"
        dest = r.get("id.resp_h") or r.get("dest") or "unknown"
        if src == "unknown" or dest == "unknown":
            continue
        bucket = int(ts // window_seconds) * window_seconds
        groups[(bucket, src, dest)].append(r)

    alerts: list[PortScanAlert] = []
    for (bucket, src, dest), recs in groups.items():
        ports = [r.get("id.resp_p") for r in recs if r.get("id.resp_p") is not None]
        distinct_ports = len(set(ports))
        if distinct_ports < min_distinct_ports:
            continue
        incomplete = sum(1 for r in recs if r.get("conn_state") in incomplete_states)
        frac = incomplete / len(recs)
        if frac < min_incomplete_fraction:
            continue

        ts_list = sorted(r.get("ts", 0) for r in recs)
        duration = float(ts_list[-1] - ts_list[0])

        alerts.append(
            PortScanAlert(
                window_start=float(bucket),
                src=src,
                dest=dest,
                distinct_ports=distinct_ports,
                total_connections=len(recs),
                incomplete_fraction=frac,
                duration_seconds=duration,
                sample_ports=sorted({int(p) for p in ports})[:10],
            )
        )

    return alerts


@dataclass
class TunnelAlert:
    src: str
    dest: str
    dest_port: int
    duration_seconds: float
    orig_bytes: int
    resp_bytes: int
    total_bytes: int
    service: str


# Ports where users normally see short-lived HTTP/HTTPS requests. A long-lived,
# multi-megabyte conversation here is the chisel/HTTP-tunnel signature.
COMMON_HTTP_PORTS: tuple[int, ...] = (80, 443, 8080, 8443)


def detect_protocol_tunnel(
    records: Iterable[dict],
    *,
    min_duration_seconds: float = 600.0,
    min_total_bytes: int = 10_000_000,
    common_ports: tuple[int, ...] = COMMON_HTTP_PORTS,
) -> list[TunnelAlert]:
    """Detect protocol tunneling over HTTP/HTTPS (T1572 — chisel, websocket tunnels).

    Per Zeek conn.log record: flag long-lived high-throughput sessions on
    standard HTTP/HTTPS ports. Normal browsing closes connections in seconds
    and rarely moves more than a few MB; chisel-style tunnels keep one TCP
    flow open for minutes-to-hours and shuttle traffic both directions.
    """
    alerts: list[TunnelAlert] = []
    for r in records:
        port = r.get("id.resp_p")
        if port is None or int(port) not in common_ports:
            continue
        duration = float(r.get("duration") or 0)
        orig = int(r.get("orig_bytes") or 0)
        resp = int(r.get("resp_bytes") or 0)
        total = orig + resp
        if duration < min_duration_seconds or total < min_total_bytes:
            continue
        src = r.get("id.orig_h") or r.get("src") or "unknown"
        dest = r.get("id.resp_h") or r.get("dest") or "unknown"
        if src == "unknown" or dest == "unknown":
            continue
        alerts.append(
            TunnelAlert(
                src=src,
                dest=dest,
                dest_port=int(port),
                duration_seconds=duration,
                orig_bytes=orig,
                resp_bytes=resp,
                total_bytes=total,
                service=r.get("service", "") or "",
            )
        )
    return alerts


@dataclass
class TorRelayAlert:
    window_start: float
    src: str
    distinct_relays: int
    total_connections: int
    duration_seconds: float
    sample_relays: list[str] = field(default_factory=list)


# Synthetic "lab Tor relays" used by the test fixtures and the in-browser
# playground default. Production uses a Splunk lookup populated from
# torbulkexitlist (https://check.torproject.org/torbulkexitlist) or
# onionoo.torproject.org/details — refreshed on a cron, not embedded in code.
LAB_TOR_RELAY_IPS: frozenset[str] = frozenset(
    {
        "203.0.113.10",
        "203.0.113.11",
        "203.0.113.12",
        "203.0.113.13",
        "203.0.113.14",
        "203.0.113.15",
        "198.51.100.20",
        "198.51.100.21",
        "198.51.100.22",
        "198.51.100.23",
    }
)


def detect_tor_relay_use(
    records: Iterable[dict],
    *,
    tor_relay_ips: frozenset[str] = LAB_TOR_RELAY_IPS,
    window_seconds: int = 3600,
    min_distinct_relays: int = 3,
) -> list[TorRelayAlert]:
    """Detect Tor client activity (T1090.003) via known-relay-IP enrichment.

    Tor clients rotate through entry guards and rebuild 3-hop circuits over
    time. A single source touching three or more distinct known-relay IPs in
    an hour is highly indicative of an active Tor client — vanilla browsing
    never matches more than one relay IP because none of them are.
    """
    if not tor_relay_ips:
        return []

    groups: dict[tuple[int, str], list[dict]] = defaultdict(list)
    for r in records:
        ts = r.get("ts", 0)
        src = r.get("id.orig_h") or r.get("src")
        dest = r.get("id.resp_h") or r.get("dest")
        if not src or not dest or dest not in tor_relay_ips:
            continue
        bucket = int(ts // window_seconds) * window_seconds
        groups[(bucket, src)].append(r)

    alerts: list[TorRelayAlert] = []
    for (bucket, src), recs in groups.items():
        relays = sorted({r.get("id.resp_h") or r.get("dest") or "" for r in recs})
        if len(relays) < min_distinct_relays:
            continue
        ts_list = sorted(r.get("ts", 0) for r in recs)
        duration = float(ts_list[-1] - ts_list[0])
        alerts.append(
            TorRelayAlert(
                window_start=float(bucket),
                src=src,
                distinct_relays=len(relays),
                total_connections=len(recs),
                duration_seconds=duration,
                sample_relays=relays[:5],
            )
        )
    return alerts


@dataclass
class DnsExfilAlert:
    window_start: float
    src: str
    base_domain: str
    query_count: int
    total_subdomain_bytes: int
    avg_sub_len: float
    bytes_per_second: float
    qtypes: list[str] = field(default_factory=list)


def detect_dns_exfil(
    records: Iterable[dict],
    *,
    window_seconds: int = 60,
    min_total_subdomain_bytes: int = 30_000,
    min_avg_sub_len: float = 50.0,
    min_query_count: int = 30,
) -> list[DnsExfilAlert]:
    """Detect bulk data exfiltration over DNS (T1048.003).

    Distinct from dnscat2-style C2 (T1071.004): exfil is volume-driven —
    the goal is to push bytes out, not maintain a bidirectional channel.
    Signal: sustained high subdomain-byte rate per (src, base_domain) over
    a short window, dwarfing any normal DNS pattern. Common exfil tools
    (iodine, dns-shell, custom exfilrators) often use A records to dodge
    TXT-volume detections, so this rule is qtype-agnostic.
    """
    groups: dict[tuple[int, str, str], list[dict]] = defaultdict(list)
    for r in records:
        ts = r.get("ts", 0)
        src = r.get("id.orig_h") or r.get("src") or "unknown"
        query = r.get("query", "")
        if not query or src == "unknown":
            continue
        bucket = int(ts // window_seconds) * window_seconds
        bd = base_domain(query)
        groups[(bucket, src, bd)].append(r)

    alerts: list[DnsExfilAlert] = []
    for (bucket, src, bd), recs in groups.items():
        if len(recs) < min_query_count:
            continue
        sub_lens = [len(leftmost_label(r["query"])) for r in recs]
        total_bytes = sum(sub_lens)
        avg_len = total_bytes / len(sub_lens) if sub_lens else 0.0
        if total_bytes < min_total_subdomain_bytes or avg_len < min_avg_sub_len:
            continue
        qtypes = sorted({r.get("qtype_name", "") for r in recs if r.get("qtype_name")})
        alerts.append(
            DnsExfilAlert(
                window_start=float(bucket),
                src=src,
                base_domain=bd,
                query_count=len(recs),
                total_subdomain_bytes=total_bytes,
                avg_sub_len=avg_len,
                bytes_per_second=total_bytes / window_seconds,
                qtypes=qtypes,
            )
        )
    return alerts


@dataclass
class SshBruteForceAlert:
    window_start: float
    src: str
    dest: str
    connection_count: int
    avg_duration_seconds: float
    duration_seconds: float
    sf_fraction: float


def detect_ssh_brute_force(
    records: Iterable[dict],
    *,
    window_seconds: int = 60,
    dest_port: int = 22,
    min_attempts: int = 20,
    max_avg_duration_seconds: float = 5.0,
) -> list[SshBruteForceAlert]:
    """Detect SSH (or other auth-protocol) brute force on Zeek conn.log.

    Brute-force tools (hydra, medusa, ncrack) hammer one src->dest:22 over
    and over: open TCP, send credentials, get rejected, close, repeat. Each
    attempt is a short, complete connection. The signal is the *count* of
    short-duration connections to the same (src, dest, port) inside a window.

    Distinct from T1046 port scanning by port-cardinality (1 port here vs.
    100+ for a scan) and from T1071.001 beaconing by per-attempt
    short-duration shape (<5s vs. cadence-based variance test).
    """
    groups: dict[tuple[int, str, str], list[dict]] = defaultdict(list)
    for r in records:
        port = r.get("id.resp_p")
        if port is None or int(port) != dest_port:
            continue
        ts = r.get("ts", 0)
        src = r.get("id.orig_h") or r.get("src")
        dest = r.get("id.resp_h") or r.get("dest")
        if not src or not dest:
            continue
        bucket = int(ts // window_seconds) * window_seconds
        groups[(bucket, src, dest)].append(r)

    alerts: list[SshBruteForceAlert] = []
    for (bucket, src, dest), recs in groups.items():
        if len(recs) < min_attempts:
            continue
        durations = [float(r.get("duration") or 0) for r in recs]
        avg_dur = sum(durations) / len(durations)
        if avg_dur > max_avg_duration_seconds:
            continue
        ts_list = sorted(r.get("ts", 0) for r in recs)
        span = float(ts_list[-1] - ts_list[0])
        sf = sum(1 for r in recs if r.get("conn_state") == "SF")
        alerts.append(
            SshBruteForceAlert(
                window_start=float(bucket),
                src=src,
                dest=dest,
                connection_count=len(recs),
                avg_duration_seconds=avg_dur,
                duration_seconds=span,
                sf_fraction=sf / len(recs),
            )
        )
    return alerts


@dataclass
class DgaAlert:
    window_start: float
    src: str
    distinct_domains: int
    total_queries: int
    avg_domain_entropy: float
    nxdomain_count: int
    nxdomain_fraction: float
    sample_domains: list[str] = field(default_factory=list)


def detect_dga_domains(
    records: Iterable[dict],
    *,
    window_seconds: int = 300,
    min_distinct_domains: int = 30,
    min_avg_entropy: float = 3.3,
    min_nxdomain_fraction: float = 0.5,
) -> list[DgaAlert]:
    """Detect Domain Generation Algorithm (DGA) C2 (T1568.002).

    Distinct from T1071.004 dnscat2 (which queries one C2 base domain with
    high-entropy *subdomains*): a DGA computes many pseudo-random *base*
    domains and queries them all looking for the live one. The defender
    sees a single source firing tens-to-hundreds of distinct base-domain
    queries inside a window, most resolving NXDOMAIN, with high entropy
    in the second-level label.
    """
    groups: dict[tuple[int, str], list[dict]] = defaultdict(list)
    for r in records:
        ts = r.get("ts", 0)
        src = r.get("id.orig_h") or r.get("src")
        query = r.get("query", "")
        if not src or not query:
            continue
        bucket = int(ts // window_seconds) * window_seconds
        groups[(bucket, src)].append(r)

    alerts: list[DgaAlert] = []
    for (bucket, src), recs in groups.items():
        domains = {base_domain(r["query"]) for r in recs}
        if len(domains) < min_distinct_domains:
            continue
        # Entropy is computed on the second-level label (everything to the left of the TLD).
        entropies = [shannon_entropy(d.split(".")[0]) for d in domains]
        avg_ent = sum(entropies) / len(entropies) if entropies else 0.0
        if avg_ent < min_avg_entropy:
            continue
        nx = sum(
            1 for r in recs if r.get("rcode_name") == "NXDOMAIN" or r.get("rcode") == 3
        )
        nx_frac = nx / len(recs)
        if nx_frac < min_nxdomain_fraction:
            continue
        alerts.append(
            DgaAlert(
                window_start=float(bucket),
                src=src,
                distinct_domains=len(domains),
                total_queries=len(recs),
                avg_domain_entropy=avg_ent,
                nxdomain_count=nx,
                nxdomain_fraction=nx_frac,
                sample_domains=sorted(domains)[:5],
            )
        )
    return alerts


@dataclass
class RmmToolAlert:
    window_start: float
    src: str
    distinct_rmm_domains: int
    total_queries: int
    matched_tools: list[str] = field(default_factory=list)
    sample_domains: list[str] = field(default_factory=list)


# Common-known Remote Monitoring & Management (RMM) tool domains.
# Modern ransomware operators routinely abuse these for persistence —
# detection is one of the highest-signal IOC plays in current SOC content.
# Production replacement: a maintained feed (e.g. red-canary's RMM list,
# DFIR-Report IOCs, or your vendor's cloud-app inventory).
LAB_RMM_DOMAINS: dict[str, str] = {
    "teamviewer.com": "TeamViewer",
    "anydesk.com": "AnyDesk",
    "screenconnect.com": "ScreenConnect",
    "connectwise.com": "ConnectWise",
    "splashtop.com": "Splashtop",
    "logmein.com": "LogMeIn",
    "gotoassist.com": "GoToAssist",
    "remotepc.com": "RemotePC",
    "n-able.com": "N-able",
    "atera.com": "Atera",
}


def detect_rmm_tool_use(
    records: Iterable[dict],
    *,
    rmm_domains: dict[str, str] = LAB_RMM_DOMAINS,
    window_seconds: int = 300,
    min_distinct_rmm_domains: int = 1,
) -> list[RmmToolAlert]:
    """Detect Remote Monitoring & Management (RMM) tool usage (T1219).

    DNS-driven IOC enrichment: any host that resolves a domain belonging to
    a known RMM platform is suspicious in the absence of an allowlist.
    Modern ransomware crews rely on TeamViewer / AnyDesk / ScreenConnect for
    persistence and pivoting; flagging the DNS lookup is the cheapest place
    in the kill chain to catch them before tooling lands on the host.
    """
    if not rmm_domains:
        return []

    groups: dict[tuple[int, str], list[tuple[str, str]]] = defaultdict(list)
    for r in records:
        ts = r.get("ts", 0)
        src = r.get("id.orig_h") or r.get("src")
        query = r.get("query", "")
        if not src or not query:
            continue
        bd = base_domain(query)
        tool = rmm_domains.get(bd)
        if not tool:
            continue
        bucket = int(ts // window_seconds) * window_seconds
        groups[(bucket, src)].append((bd, tool))

    alerts: list[RmmToolAlert] = []
    for (bucket, src), entries in groups.items():
        domains = sorted({bd for bd, _t in entries})
        tools = sorted({t for _bd, t in entries})
        if len(domains) < min_distinct_rmm_domains:
            continue
        alerts.append(
            RmmToolAlert(
                window_start=float(bucket),
                src=src,
                distinct_rmm_domains=len(domains),
                total_queries=len(entries),
                matched_tools=tools,
                sample_domains=domains[:5],
            )
        )
    return alerts


@dataclass
class VolumetricFloodAlert:
    window_start: float
    src: str
    dest: str
    dest_port: int
    connection_count: int
    pps: float
    duration_seconds: float


def detect_volumetric_flood(
    records: Iterable[dict],
    *,
    window_seconds: int = 1,
    min_connections: int = 100,
) -> list[VolumetricFloodAlert]:
    """Detect volumetric network DoS (T1499.001 — Direct Network Flood).

    Distinct from T1046 port scanning: a flood is one src hammering one
    src→(dest, port) pair with hundreds of connections per *second*. Port
    scans hit many distinct ports; floods hit one port hard. The 1-second
    window keeps the threshold tight and catches SYN/UDP floods quickly.
    """
    groups: dict[tuple[int, str, str, int], list[float]] = defaultdict(list)
    for r in records:
        ts = r.get("ts", 0)
        src = r.get("id.orig_h") or r.get("src")
        dest = r.get("id.resp_h") or r.get("dest")
        port = r.get("id.resp_p")
        if not src or not dest or port is None:
            continue
        bucket = int(ts // window_seconds) * window_seconds
        groups[(bucket, src, dest, int(port))].append(float(ts))

    alerts: list[VolumetricFloodAlert] = []
    for (bucket, src, dest, port), times in groups.items():
        if len(times) < min_connections:
            continue
        times.sort()
        duration = times[-1] - times[0] if len(times) > 1 else float(window_seconds)
        # pps over the actual span — degenerate to len/window if all timestamps coincide.
        pps = len(times) / max(duration, 0.001)
        alerts.append(
            VolumetricFloodAlert(
                window_start=float(bucket),
                src=src,
                dest=dest,
                dest_port=port,
                connection_count=len(times),
                pps=pps,
                duration_seconds=duration,
            )
        )
    return alerts


@dataclass
class SuricataExploitAlert:
    window_start: float
    src: str
    dest: str
    category: str
    alert_count: int
    distinct_signatures: int
    max_severity: int
    sample_signatures: list[str] = field(default_factory=list)


# Suricata categories that indicate post-recon exploit attempts (T1190).
# These are the tunes that consistently fire on Emerging Threats / ETPRO
# rulesets when something is genuinely trying to break into a service.
SURICATA_EXPLOIT_CATEGORIES: tuple[str, ...] = (
    "Web Application Attack",
    "Attempted Administrator Privilege Gain",
    "Attempted User Privilege Gain",
    "Successful Administrator Privilege Gain",
    "Successful User Privilege Gain",
    "A Network Trojan was detected",
    "Attempted Information Leak",
    "Exploit Kit Activity Detected",
)


def _parse_iso_ts(ts: str) -> float:
    """Suricata timestamps are ISO-8601 with a numeric tz suffix.

    Returns a unix epoch seconds float, or 0.0 if the string is unparseable
    (so a malformed record doesn't sink an entire fixture)."""
    if not ts:
        return 0.0
    try:
        # datetime.fromisoformat handles "+0000" and "+00:00" since 3.11.
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return 0.0
    return dt.timestamp()


def detect_suricata_exploits(
    records: Iterable[dict],
    *,
    window_seconds: int = 300,
    exploit_categories: tuple[str, ...] = SURICATA_EXPLOIT_CATEGORIES,
    min_alerts: int = 1,
) -> list[SuricataExploitAlert]:
    """Detect exploit attempts (T1190) via Suricata IDS alert events.

    Different telemetry source from the rest of the lab — this consumes
    Suricata eve.json (`event_type=alert`), not Zeek logs. The fields are
    `src_ip`/`dest_ip`/`alert.{category,signature_id,severity}` instead of
    Zeek's `id.orig_h`/`id.resp_h`. The detector is otherwise the same shape:
    aggregate per (window, src, dest, category), threshold, alert.

    Production deployment: Suricata writes eve.json straight into Splunk
    via `[suricata:eve]` (see lab/splunk/{inputs,props}.conf). The Splunk-
    side macro filters event_type=alert and aggregates the same way.
    """
    groups: dict[tuple[int, str, str, str], list[dict]] = defaultdict(list)
    for r in records:
        if r.get("event_type") != "alert":
            continue
        alert_obj = r.get("alert", {}) or {}
        category = alert_obj.get("category", "")
        if exploit_categories and category not in exploit_categories:
            continue
        src = r.get("src_ip") or r.get("src")
        dest = r.get("dest_ip") or r.get("dest")
        if not src or not dest:
            continue
        ts = _parse_iso_ts(r.get("timestamp", ""))
        bucket = int(ts // window_seconds) * window_seconds
        groups[(bucket, src, dest, category)].append(alert_obj)

    alerts: list[SuricataExploitAlert] = []
    for (bucket, src, dest, category), recs in groups.items():
        if len(recs) < min_alerts:
            continue
        signatures = sorted({r.get("signature", "") for r in recs if r.get("signature")})
        max_sev = max((int(r.get("severity") or 99) for r in recs), default=99)
        alerts.append(
            SuricataExploitAlert(
                window_start=float(bucket),
                src=src,
                dest=dest,
                category=category,
                alert_count=len(recs),
                distinct_signatures=len(signatures),
                max_severity=max_sev,
                sample_signatures=signatures[:3],
            )
        )
    return alerts


@dataclass
class C2ExfilAlert:
    src: str
    dest: str
    beacon_connection_count: int
    beacon_avg_interval_seconds: float
    exfil_record_count: int
    total_orig_bytes: int
    avg_orig_bytes_per_record: float


def detect_c2_exfil(
    records: Iterable[dict],
    *,
    # Beacon-detection params (reused as-is from detect_beaconing)
    min_beacon_connections: int = 30,
    max_avg_interval: float = 600.0,
    max_coefficient_of_variation: float = 0.15,
    min_beacon_duration_seconds: float = 600.0,
    # Exfil thresholds
    min_exfil_orig_bytes_per_record: int = 10_000,
    min_exfil_total_bytes: int = 100_000,
) -> list[C2ExfilAlert]:
    """Detect exfiltration through an established C2 channel (T1041).

    Composed detection — depends on `detect_beaconing` having identified
    (src, dest) pairs that look like a C2 beacon. Among connections to
    those flagged pairs, this rule looks for records with abnormally high
    `orig_bytes` (the implant pushing data uplink). The alert names BOTH
    the beacon evidence and the exfil-volume evidence so a SOC analyst
    has the full picture.

    This is the "risk accumulation" pattern Splunk ES shops use in
    practice: a low-confidence behavioural detection (beaconing) gets
    paired with a high-confidence volume signal (uplink bytes) to
    produce a single high-severity alert.
    """
    # Stage 1: who's beaconing?
    beacons = detect_beaconing(
        records,
        min_connections=min_beacon_connections,
        max_avg_interval=max_avg_interval,
        max_coefficient_of_variation=max_coefficient_of_variation,
        min_duration_seconds=min_beacon_duration_seconds,
    )
    if not beacons:
        return []

    beacon_by_pair: dict[tuple[str, str], object] = {(b.src, b.dest): b for b in beacons}

    # Stage 2: among records to those pairs, sum the high-uplink-bytes ones.
    exfil_groups: dict[tuple[str, str], list[int]] = defaultdict(list)
    for r in records:
        src = r.get("id.orig_h") or r.get("src") or "unknown"
        dest = r.get("host") or r.get("id.resp_h") or r.get("dest") or "unknown"
        key = (src, dest)
        if key not in beacon_by_pair:
            continue
        orig = int(r.get("orig_bytes") or 0)
        if orig < min_exfil_orig_bytes_per_record:
            continue
        exfil_groups[key].append(orig)

    alerts: list[C2ExfilAlert] = []
    for key, uplinks in exfil_groups.items():
        total = sum(uplinks)
        if total < min_exfil_total_bytes:
            continue
        beacon = beacon_by_pair[key]  # type: ignore[index]
        # mypy/pyright friendly access — beacon is a BeaconAlert dataclass
        alerts.append(
            C2ExfilAlert(
                src=key[0],
                dest=key[1],
                beacon_connection_count=getattr(beacon, "connection_count", 0),
                beacon_avg_interval_seconds=getattr(beacon, "avg_interval", 0.0),
                exfil_record_count=len(uplinks),
                total_orig_bytes=total,
                avg_orig_bytes_per_record=total / len(uplinks),
            )
        )
    return alerts


@dataclass
class CloudExfilAlert:
    window_start: float
    src: str
    cloud_service: str
    distinct_destinations: int
    record_count: int
    total_orig_bytes: int
    avg_orig_bytes_per_record: float
    sample_destinations: list[str] = field(default_factory=list)


# Synthetic lab IP set for known cloud-storage / file-sharing services.
# Populated for tests + the in-browser playground; production replaces it
# with a maintained feed (Cisco Umbrella categorisation, Zscaler app
# inventory, vendor cloud-app catalogue). Modern ransomware groups
# routinely stage data through these — the DFIR Report has documented
# rclone → Mega.nz / Dropbox / Wasabi as the post-encryption exfil step.
LAB_CLOUD_STORAGE_IPS: dict[str, str] = {
    "203.0.113.50": "Mega",
    "203.0.113.51": "Mega",
    "203.0.113.60": "Dropbox",
    "203.0.113.61": "Dropbox",
    "203.0.113.70": "WeTransfer",
    "203.0.113.80": "AnonFiles",
    "203.0.113.81": "Gofile",
    "203.0.113.82": "Transfer.sh",
    "203.0.113.90": "pCloud",
    "203.0.113.91": "MediaFire",
}


def detect_cloud_exfil(
    records: Iterable[dict],
    *,
    cloud_storage_ips: dict[str, str] = LAB_CLOUD_STORAGE_IPS,
    window_seconds: int = 3600,
    min_orig_bytes_per_record: int = 1_000_000,
    min_total_orig_bytes: int = 50_000_000,
) -> list[CloudExfilAlert]:
    """Detect data staging to cloud-storage services (T1567.002).

    Two-signal: destination IP matches a known cloud-storage / file-sharing
    service, AND cumulative `orig_bytes` from a single source over the
    window crosses 50 MB. Modern ransomware crews use this pattern to
    stage stolen data before encryption — rclone to Mega.nz, robocopy to
    Dropbox, etc. The signal is durable because the IP set is small and
    rotates slowly (vendor infra, not C2 infra).
    """
    if not cloud_storage_ips:
        return []

    groups: dict[tuple[int, str, str], list[dict]] = defaultdict(list)
    for r in records:
        ts = r.get("ts", 0)
        src = r.get("id.orig_h") or r.get("src")
        dest = r.get("id.resp_h") or r.get("dest")
        if not src or not dest:
            continue
        service = cloud_storage_ips.get(dest)
        if not service:
            continue
        orig = int(r.get("orig_bytes") or 0)
        if orig < min_orig_bytes_per_record:
            continue
        bucket = int(ts // window_seconds) * window_seconds
        groups[(bucket, src, service)].append({"dest": dest, "orig": orig})

    alerts: list[CloudExfilAlert] = []
    for (bucket, src, service), recs in groups.items():
        total = sum(r["orig"] for r in recs)
        if total < min_total_orig_bytes:
            continue
        dests = sorted({r["dest"] for r in recs})
        alerts.append(
            CloudExfilAlert(
                window_start=float(bucket),
                src=src,
                cloud_service=service,
                distinct_destinations=len(dests),
                record_count=len(recs),
                total_orig_bytes=total,
                avg_orig_bytes_per_record=total / len(recs),
                sample_destinations=dests[:5],
            )
        )
    return alerts


@dataclass
class RdpLateralAlert:
    window_start: float
    src: str
    distinct_destinations: int
    total_connections: int
    duration_seconds: float
    sample_destinations: list[str] = field(default_factory=list)


def detect_rdp_lateral(
    records: Iterable[dict],
    *,
    dest_port: int = 3389,
    window_seconds: int = 3600,
    min_distinct_destinations: int = 3,
) -> list[RdpLateralAlert]:
    """Detect RDP lateral movement (T1021.001).

    A single source pivoting via Remote Desktop touches multiple distinct
    internal destinations on TCP/3389 in a tight window — the signature of
    post-compromise lateral movement. Pure-IT-admin baseline traffic stays
    under the threshold; allowlist known jumphosts in production.

    Distinct from T1110.001 SSH brute force in two ways: port (3389 not 22)
    and signal (distinct *destinations*, not connection count to one host).
    """
    groups: dict[tuple[int, str], list[tuple[str, float]]] = defaultdict(list)
    for r in records:
        port = r.get("id.resp_p")
        if port is None or int(port) != dest_port:
            continue
        ts = r.get("ts", 0)
        src = r.get("id.orig_h") or r.get("src")
        dest = r.get("id.resp_h") or r.get("dest")
        if not src or not dest:
            continue
        bucket = int(ts // window_seconds) * window_seconds
        groups[(bucket, src)].append((dest, float(ts)))

    alerts: list[RdpLateralAlert] = []
    for (bucket, src), recs in groups.items():
        dests = sorted({d for d, _ in recs})
        if len(dests) < min_distinct_destinations:
            continue
        timestamps = sorted(t for _, t in recs)
        duration = timestamps[-1] - timestamps[0] if timestamps else 0.0
        alerts.append(
            RdpLateralAlert(
                window_start=float(bucket),
                src=src,
                distinct_destinations=len(dests),
                total_connections=len(recs),
                duration_seconds=duration,
                sample_destinations=dests[:5],
            )
        )
    return alerts


# ============================================================================
# Newly-shipped detections (the planned-cases batch).
# Each is intentionally tight — same shape as the existing detectors,
# documented in cases/<id>/README.md, fixture-tested under cases/<id>/tests/.
# ============================================================================


@dataclass
class WebWordlistAlert:
    window_start: float
    src: str
    dest: str
    distinct_404_paths: int
    total_404s: int


def detect_web_wordlist(
    records: Iterable[dict],
    *,
    window_seconds: int = 60,
    min_distinct_404_paths: int = 50,
) -> list[WebWordlistAlert]:
    """T1595.003 — web wordlist / directory scanning (gobuster, dirb, ffuf).

    Filter Zeek http.log to status_code=404, group by (window, src, dest),
    count distinct URI paths. A scanner walking a wordlist hits dozens of
    paths; benign 404s never cluster like this."""
    groups: dict[tuple[int, str, str], list[str]] = defaultdict(list)
    for r in records:
        if r.get("status_code") != 404:
            continue
        ts = r.get("ts", 0)
        src = r.get("id.orig_h") or r.get("src")
        dest = r.get("host") or r.get("id.resp_h") or r.get("dest")
        uri = r.get("uri", "")
        if not src or not dest or not uri:
            continue
        bucket = int(ts // window_seconds) * window_seconds
        groups[(bucket, src, dest)].append(uri)

    alerts: list[WebWordlistAlert] = []
    for (bucket, src, dest), uris in groups.items():
        distinct = len(set(uris))
        if distinct < min_distinct_404_paths:
            continue
        alerts.append(
            WebWordlistAlert(
                window_start=float(bucket),
                src=src,
                dest=dest,
                distinct_404_paths=distinct,
                total_404s=len(uris),
            )
        )
    return alerts


@dataclass
class InternalProxyAlert:
    window_start: float
    src: str
    distinct_destinations: int
    total_connections: int
    sample_destinations: list[str] = field(default_factory=list)


# Common SOCKS / HTTP-CONNECT ports operators use for internal proxy chains.
INTERNAL_PROXY_PORTS: tuple[int, ...] = (1080, 3128, 8080, 8888, 9050)


def detect_internal_proxy(
    records: Iterable[dict],
    *,
    proxy_ports: tuple[int, ...] = INTERNAL_PROXY_PORTS,
    window_seconds: int = 3600,
    min_distinct_destinations: int = 3,
) -> list[InternalProxyAlert]:
    """T1090.001 — internal proxy / SOCKS chaining.

    Operators stand up an internal pivot to obfuscate east-west traffic.
    Per (1-h window, src), count distinct internal destinations contacted
    on SOCKS / HTTP-CONNECT ports; threshold >=3 = pivoting."""
    groups: dict[tuple[int, str], list[str]] = defaultdict(list)
    for r in records:
        port = r.get("id.resp_p")
        if port is None or int(port) not in proxy_ports:
            continue
        ts = r.get("ts", 0)
        src = r.get("id.orig_h") or r.get("src")
        dest = r.get("id.resp_h") or r.get("dest")
        if not src or not dest:
            continue
        bucket = int(ts // window_seconds) * window_seconds
        groups[(bucket, src)].append(dest)

    alerts: list[InternalProxyAlert] = []
    for (bucket, src), dests in groups.items():
        distinct = sorted(set(dests))
        if len(distinct) < min_distinct_destinations:
            continue
        alerts.append(
            InternalProxyAlert(
                window_start=float(bucket),
                src=src,
                distinct_destinations=len(distinct),
                total_connections=len(dests),
                sample_destinations=distinct[:5],
            )
        )
    return alerts


@dataclass
class SmbLateralAlert:
    window_start: float
    src: str
    distinct_destinations: int
    total_connections: int
    sample_destinations: list[str] = field(default_factory=list)


def detect_smb_lateral(
    records: Iterable[dict],
    *,
    dest_port: int = 445,
    window_seconds: int = 3600,
    min_distinct_destinations: int = 3,
) -> list[SmbLateralAlert]:
    """T1021.002 — SMB admin shares / lateral movement (psexec / wmiexec).

    Per (1-h window, src) on TCP/445, count distinct internal destinations.
    psexec / wmiexec / SMBExec-style lateral hits multiple hosts via
    ADMIN$ / IPC$ in tight succession. Same shape as the RDP lateral case
    but on SMB."""
    groups: dict[tuple[int, str], list[str]] = defaultdict(list)
    for r in records:
        port = r.get("id.resp_p")
        if port is None or int(port) != dest_port:
            continue
        ts = r.get("ts", 0)
        src = r.get("id.orig_h") or r.get("src")
        dest = r.get("id.resp_h") or r.get("dest")
        if not src or not dest:
            continue
        bucket = int(ts // window_seconds) * window_seconds
        groups[(bucket, src)].append(dest)

    alerts: list[SmbLateralAlert] = []
    for (bucket, src), dests in groups.items():
        distinct = sorted(set(dests))
        if len(distinct) < min_distinct_destinations:
            continue
        alerts.append(
            SmbLateralAlert(
                window_start=float(bucket),
                src=src,
                distinct_destinations=len(distinct),
                total_connections=len(dests),
                sample_destinations=distinct[:5],
            )
        )
    return alerts


@dataclass
class LateralToolTransferAlert:
    src: str
    dest: str
    orig_bytes: int
    duration_seconds: float
    service: str


# RFC 1918 prefixes — used to limit lateral-tool-transfer to internal-internal flows.
RFC1918_PREFIXES: tuple[str, ...] = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                                     "172.20.", "172.21.", "172.22.", "172.23.",
                                     "172.24.", "172.25.", "172.26.", "172.27.",
                                     "172.28.", "172.29.", "172.30.", "172.31.",
                                     "192.168.")


def _is_internal(ip: str) -> bool:
    return any(ip.startswith(p) for p in RFC1918_PREFIXES)


def detect_lateral_tool_transfer(
    records: Iterable[dict],
    *,
    min_orig_bytes: int = 5_000_000,
) -> list[LateralToolTransferAlert]:
    """T1570 — lateral tool transfer.

    Per-record: flag conn.log records carrying >=5 MB orig_bytes between
    two internal (RFC 1918) hosts. Operators copy their toolkit between
    compromised boxes; legitimate east-west flows that big are usually
    backups (allow-list those)."""
    alerts: list[LateralToolTransferAlert] = []
    for r in records:
        src = r.get("id.orig_h") or r.get("src") or ""
        dest = r.get("id.resp_h") or r.get("dest") or ""
        if not _is_internal(src) or not _is_internal(dest):
            continue
        orig = int(r.get("orig_bytes") or 0)
        if orig < min_orig_bytes:
            continue
        alerts.append(
            LateralToolTransferAlert(
                src=src,
                dest=dest,
                orig_bytes=orig,
                duration_seconds=float(r.get("duration") or 0),
                service=r.get("service", "") or "",
            )
        )
    return alerts


@dataclass
class ExternalRemoteServicesAlert:
    window_start: float
    src: str
    distinct_destinations: int
    dest_ports: list[int] = field(default_factory=list)
    sample_destinations: list[str] = field(default_factory=list)


# Ports commonly exposed externally for VPN/RDP/RAS — abused by initial-access
# operators with stolen creds. Real production rule layers an asset-criticality
# lookup on top.
EXTERNAL_REMOTE_PORTS: tuple[int, ...] = (
    3389,  # RDP
    1194,  # OpenVPN
    443,   # Pulse Secure / Fortinet / generic VPN-over-TLS (noisy without SNI filter)
    500,   # IKE
    4500,  # IKE NAT-T
    1723,  # PPTP
)


def detect_external_remote_services(
    records: Iterable[dict],
    *,
    remote_ports: tuple[int, ...] = (3389, 1194, 500, 4500, 1723),
    window_seconds: int = 3600,
    min_distinct_destinations: int = 1,
) -> list[ExternalRemoteServicesAlert]:
    """T1133 — external remote services abuse.

    Group conn.log by (1-h window, src) where src is *external* (not
    RFC 1918) and dest is *internal* and dest_port is in the remote-services
    set. Even one such connection is suspicious in environments where the
    VPN concentrator is the only sanctioned external entry point."""
    groups: dict[tuple[int, str], list[tuple[str, int]]] = defaultdict(list)
    for r in records:
        port = r.get("id.resp_p")
        if port is None or int(port) not in remote_ports:
            continue
        src = r.get("id.orig_h") or r.get("src") or ""
        dest = r.get("id.resp_h") or r.get("dest") or ""
        if _is_internal(src) or not _is_internal(dest):
            continue
        ts = r.get("ts", 0)
        bucket = int(ts // window_seconds) * window_seconds
        groups[(bucket, src)].append((dest, int(port)))

    alerts: list[ExternalRemoteServicesAlert] = []
    for (bucket, src), pairs in groups.items():
        dests = sorted({d for d, _ in pairs})
        if len(dests) < min_distinct_destinations:
            continue
        ports = sorted({p for _, p in pairs})
        alerts.append(
            ExternalRemoteServicesAlert(
                window_start=float(bucket),
                src=src,
                distinct_destinations=len(dests),
                dest_ports=ports,
                sample_destinations=dests[:5],
            )
        )
    return alerts


@dataclass
class NewlyRegisteredDomainAlert:
    window_start: float
    src: str
    distinct_nrd_resolutions: int
    sample_domains: list[str] = field(default_factory=list)


# Synthetic lab "newly registered" domain set (replace with a daily WHOXY /
# DomainTools feed in production). Domains here would have been registered
# in the last 7 days according to that feed.
LAB_NEWLY_REGISTERED_DOMAINS: frozenset[str] = frozenset({
    "fresh-malware-c2.com",
    "phishlanding-x.net",
    "newkit.online",
    "today-payload.click",
    "yesterday-staging.io",
})


def detect_newly_registered_domain(
    records: Iterable[dict],
    *,
    nrd_set: frozenset[str] = LAB_NEWLY_REGISTERED_DOMAINS,
    window_seconds: int = 86400,
    min_distinct_nrd: int = 1,
) -> list[NewlyRegisteredDomainAlert]:
    """T1583.001 — newly-registered domain (NRD) resolution.

    Pure IOC-enrichment: per (24-h window, src), count distinct queries to
    domains in the NRD feed. Operators register domains right before a
    campaign launches; pairing internal DNS with a daily NRD list catches
    the first outbound resolution."""
    if not nrd_set:
        return []
    groups: dict[tuple[int, str], list[str]] = defaultdict(list)
    for r in records:
        ts = r.get("ts", 0)
        src = r.get("id.orig_h") or r.get("src")
        query = r.get("query", "")
        if not src or not query:
            continue
        bd = base_domain(query)
        if bd not in nrd_set:
            continue
        bucket = int(ts // window_seconds) * window_seconds
        groups[(bucket, src)].append(bd)

    alerts: list[NewlyRegisteredDomainAlert] = []
    for (bucket, src), domains in groups.items():
        distinct = sorted(set(domains))
        if len(distinct) < min_distinct_nrd:
            continue
        alerts.append(
            NewlyRegisteredDomainAlert(
                window_start=float(bucket),
                src=src,
                distinct_nrd_resolutions=len(distinct),
                sample_domains=distinct[:5],
            )
        )
    return alerts


@dataclass
class InfoRepoBulkReadAlert:
    window_start: float
    src: str
    dest: str
    distinct_paths: int
    total_requests: int


def detect_info_repo_bulk_read(
    records: Iterable[dict],
    *,
    info_repo_hosts: frozenset[str] = frozenset({"confluence.lab", "sharepoint.lab", "wiki.lab"}),
    window_seconds: int = 3600,
    min_distinct_paths: int = 100,
) -> list[InfoRepoBulkReadAlert]:
    """T1213.002 — Confluence / SharePoint bulk read.

    Per (1-h window, src, dest) for known internal info-repo hosts,
    count distinct URI paths. Operators systematically scrape these for
    credentials and runbooks during post-compromise discovery; tooling
    hits hundreds of distinct paths in minutes."""
    groups: dict[tuple[int, str, str], list[str]] = defaultdict(list)
    for r in records:
        host = r.get("host") or r.get("id.resp_h")
        if not host or host not in info_repo_hosts:
            continue
        uri = r.get("uri", "")
        src = r.get("id.orig_h") or r.get("src")
        if not src or not uri:
            continue
        ts = r.get("ts", 0)
        bucket = int(ts // window_seconds) * window_seconds
        groups[(bucket, src, host)].append(uri)

    alerts: list[InfoRepoBulkReadAlert] = []
    for (bucket, src, dest), uris in groups.items():
        distinct = len(set(uris))
        if distinct < min_distinct_paths:
            continue
        alerts.append(
            InfoRepoBulkReadAlert(
                window_start=float(bucket),
                src=src,
                dest=dest,
                distinct_paths=distinct,
                total_requests=len(uris),
            )
        )
    return alerts


@dataclass
class VulnScanAlert:
    window_start: float
    src: str
    distinct_signatures: int
    alert_count: int
    sample_signatures: list[str] = field(default_factory=list)


# Suricata categories that scanners light up. Distinct from the T1190
# exploit set — these are attempted-recon, not attempted-exploitation.
VULN_SCAN_CATEGORIES: tuple[str, ...] = (
    "Attempted Information Leak",
    "Information Leak",
    "Network Scan",
    "Misc activity",
    "Web Application Attack",
)


def detect_vuln_scan(
    records: Iterable[dict],
    *,
    scan_categories: tuple[str, ...] = VULN_SCAN_CATEGORIES,
    scan_signature_keywords: tuple[str, ...] = (
        "scan", "scanner", "nessus", "qualys", "nikto", "openvas",
    ),
    window_seconds: int = 3600,
    min_distinct_signatures: int = 5,
) -> list[VulnScanAlert]:
    """T1595.002 — vulnerability scanning.

    Filter Suricata eve.json alert events whose category is scan-shape OR
    whose signature mentions a scanner tool name. Per (1-h window, src),
    count distinct signatures; threshold >= 5 distinct = a scan in
    progress (one signature is a one-off, many is a sweep)."""
    groups: dict[tuple[int, str], list[str]] = defaultdict(list)
    for r in records:
        if r.get("event_type") != "alert":
            continue
        alert_obj = r.get("alert", {}) or {}
        category = alert_obj.get("category", "")
        signature = alert_obj.get("signature", "").lower()
        scan_match = (
            category in scan_categories
            and any(kw in signature for kw in scan_signature_keywords)
        )
        if not scan_match:
            continue
        src = r.get("src_ip") or r.get("src")
        if not src:
            continue
        ts = _parse_iso_ts(r.get("timestamp", ""))
        bucket = int(ts // window_seconds) * window_seconds
        groups[(bucket, src)].append(alert_obj.get("signature", ""))

    alerts: list[VulnScanAlert] = []
    for (bucket, src), signatures in groups.items():
        distinct = sorted({s for s in signatures if s})
        if len(distinct) < min_distinct_signatures:
            continue
        alerts.append(
            VulnScanAlert(
                window_start=float(bucket),
                src=src,
                distinct_signatures=len(distinct),
                alert_count=len(signatures),
                sample_signatures=distinct[:3],
            )
        )
    return alerts


@dataclass
class HtmlSmugglingAlert:
    window_start: float
    src: str
    dest: str
    alert_count: int
    sample_signatures: list[str] = field(default_factory=list)


def detect_html_smuggling(
    records: Iterable[dict],
    *,
    keywords: tuple[str, ...] = ("html smuggl", "html smuggling", "blob.url", "saveas blob"),
    window_seconds: int = 3600,
) -> list[HtmlSmugglingAlert]:
    """T1027.006 — HTML smuggling delivery.

    Filter Suricata alerts whose signature mentions HTML smuggling /
    JS-blob-decode patterns. Phishing payloads delivered as JS-encoded
    blobs that decode client-side bypass WAF / proxy file-type checks;
    Suricata signatures catch them at the wire."""
    groups: dict[tuple[int, str, str], list[str]] = defaultdict(list)
    for r in records:
        if r.get("event_type") != "alert":
            continue
        alert_obj = r.get("alert", {}) or {}
        signature = alert_obj.get("signature", "").lower()
        if not any(kw in signature for kw in keywords):
            continue
        src = r.get("src_ip") or r.get("src")
        dest = r.get("dest_ip") or r.get("dest")
        if not src or not dest:
            continue
        ts = _parse_iso_ts(r.get("timestamp", ""))
        bucket = int(ts // window_seconds) * window_seconds
        groups[(bucket, src, dest)].append(alert_obj.get("signature", ""))

    alerts: list[HtmlSmugglingAlert] = []
    for (bucket, src, dest), sigs in groups.items():
        if not sigs:
            continue
        alerts.append(
            HtmlSmugglingAlert(
                window_start=float(bucket),
                src=src,
                dest=dest,
                alert_count=len(sigs),
                sample_signatures=sorted({s for s in sigs if s})[:3],
            )
        )
    return alerts


@dataclass
class RpcCoercionAlert:
    window_start: float
    src: str
    dest: str
    distinct_operations: int
    total_calls: int
    sample_operations: list[str] = field(default_factory=list)


# RPC operation names produced by PetitPotam / DFSCoerce / similar coercion
# tooling. Real Zeek dce_rpc.log includes operation names directly; we
# pattern-match against r.get("operation") in the fixture shape.
RPC_COERCION_OPERATIONS: tuple[str, ...] = (
    "EfsRpcOpenFileRaw",
    "EfsRpcDecryptFileSrv",
    "EfsRpcEncryptFileSrv",
    "NetrDfsAddStdRoot",
    "NetrDfsRemoveStdRoot",
)


def detect_rpc_coercion(
    records: Iterable[dict],
    *,
    coercion_ops: tuple[str, ...] = RPC_COERCION_OPERATIONS,
    window_seconds: int = 600,
    min_distinct_operations: int = 1,
) -> list[RpcCoercionAlert]:
    """T1068 — RPC coercion (PetitPotam, DFSCoerce, NTLM relay path).

    Filter Zeek dce_rpc.log records to coercion-style operations. Per
    (10-min window, src, dest), count distinct operations; alert on >=1.
    Operations like EfsRpcOpenFileRaw and NetrDfsAddStdRoot are how
    operators force a domain controller to authenticate to an attacker
    relay — high-confidence privilege-escalation path on AD networks."""
    groups: dict[tuple[int, str, str], list[str]] = defaultdict(list)
    for r in records:
        op = r.get("operation", "")
        if op not in coercion_ops:
            continue
        src = r.get("id.orig_h") or r.get("src")
        dest = r.get("id.resp_h") or r.get("dest")
        if not src or not dest:
            continue
        ts = r.get("ts", 0)
        bucket = int(ts // window_seconds) * window_seconds
        groups[(bucket, src, dest)].append(op)

    alerts: list[RpcCoercionAlert] = []
    for (bucket, src, dest), ops in groups.items():
        distinct = sorted(set(ops))
        if len(distinct) < min_distinct_operations:
            continue
        alerts.append(
            RpcCoercionAlert(
                window_start=float(bucket),
                src=src,
                dest=dest,
                distinct_operations=len(distinct),
                total_calls=len(ops),
                sample_operations=distinct[:3],
            )
        )
    return alerts
