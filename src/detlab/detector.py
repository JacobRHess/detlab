"""Generic detection runner — Python mirror of the per-case SPL searches.

Each case ships a `detect(records)` function that returns a list of alert
dicts. CI tests assert: positive fixtures produce >=1 alert, negative
fixtures produce 0. The SPL in `detection/search.spl` is the production
artifact; this module is the testable specification of what the SPL means.
"""

from __future__ import annotations

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
