"""Load Zeek dns.log JSON-formatted records into Python dicts.

Zeek emits one JSON object per line when configured with `redef LogAscii::use_json = T`.
Field names follow Zeek's dotted convention (e.g. `id.orig_h`); we preserve those keys.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from pathlib import Path


def load_zeek_dns(path: str | Path) -> list[dict]:
    p = Path(path)
    return list(_iter_zeek_dns(p))


def _iter_zeek_dns(p: Path) -> Iterator[dict]:
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            yield json.loads(line)


def base_domain(query: str) -> str:
    """Return the registrable base ('foo.example.com' -> 'example.com').

    Naive last-two-labels split — adequate for lab fixtures. For production,
    swap in tldextract.
    """
    parts = query.rstrip(".").split(".")
    if len(parts) < 2:
        return query
    return ".".join(parts[-2:])


def leftmost_label(query: str) -> str:
    parts = query.rstrip(".").split(".")
    return parts[0] if parts else ""


def filter_by_window(records: Iterable[dict], start_ts: float, span_seconds: float) -> list[dict]:
    end = start_ts + span_seconds
    return [r for r in records if start_ts <= r.get("ts", 0) < end]
