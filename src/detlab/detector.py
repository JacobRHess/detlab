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
