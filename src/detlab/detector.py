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

        intervals = [t2 - t1 for t1, t2 in zip(times, times[1:], strict=False) if t2 > t1]
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
        frac = incomplete / len(recs) if recs else 0.0
        if frac < min_incomplete_fraction:
            continue

        ts_list = sorted(r.get("ts", 0) for r in recs)
        duration = float(ts_list[-1] - ts_list[0]) if ts_list else 0.0

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
        duration = float(ts_list[-1] - ts_list[0]) if ts_list else 0.0
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
        avg_dur = sum(durations) / len(durations) if durations else 0.0
        if avg_dur > max_avg_duration_seconds:
            continue
        ts_list = sorted(r.get("ts", 0) for r in recs)
        span = float(ts_list[-1] - ts_list[0]) if ts_list else 0.0
        sf = sum(1 for r in recs if r.get("conn_state") == "SF")
        alerts.append(
            SshBruteForceAlert(
                window_start=float(bucket),
                src=src,
                dest=dest,
                connection_count=len(recs),
                avg_duration_seconds=avg_dur,
                duration_seconds=span,
                sf_fraction=sf / len(recs) if recs else 0.0,
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
        nx_frac = nx / len(recs) if recs else 0.0
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
