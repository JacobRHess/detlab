"""Refresh app/lookups/tor_relays.csv from a public Tor relay feed.

The lab ships a synthetic relay set so tests are hermetic and the
playground works without an external dependency. In production you'd run
this script on a cron (hourly is sane — relay set rotates) and reload the
lookup via the Splunk REST API.

Default feed: torbulkexitlist (https://check.torproject.org/torbulkexitlist).
That endpoint returns plain-text IPs, one per line — no auth required, but
it's a public Tor service so plan for rate-limiting and intermittent
unreachability.

Usage:
    py scripts/refresh_tor_relays.py
    py scripts/refresh_tor_relays.py --feed https://example.org/feed --merge

Flags:
    --feed URL     URL to fetch (default: torbulkexitlist)
    --merge        keep the existing rows and add new ones (default: replace)
    --dry-run      print what would be written, don't touch the file
"""

from __future__ import annotations

import argparse
import csv
import sys
import urllib.request
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOOKUP = ROOT / "app" / "lookups" / "tor_relays.csv"
DEFAULT_FEED = "https://check.torproject.org/torbulkexitlist"


def fetch_feed(url: str, *, timeout: float = 30.0) -> list[str]:
    """Fetch the relay-IP feed and return the deduped IP list, sorted."""
    req = urllib.request.Request(url, headers={"User-Agent": "detlab/refresh"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - public feed
        body = r.read().decode("utf-8", errors="replace")

    ips: set[str] = set()
    for line in body.splitlines():
        ip = line.strip()
        # Skip blanks, comments, and obvious non-IPs.
        if not ip or ip.startswith("#") or " " in ip:
            continue
        ips.add(ip)
    return sorted(ips)


def read_existing_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def render_csv(rows: list[dict[str, str]]) -> str:
    buf = StringIO()
    writer = csv.DictWriter(buf, fieldnames=["ip", "relay_type"])
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Refresh app/lookups/tor_relays.csv")
    parser.add_argument("--feed", default=DEFAULT_FEED, help="URL to fetch (default: torbulkexitlist)")
    parser.add_argument(
        "--merge",
        action="store_true",
        help="Merge fetched IPs with existing lab rows instead of replacing",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print output, don't write")
    args = parser.parse_args(argv)

    print(f"Fetching {args.feed}…")
    try:
        ips = fetch_feed(args.feed)
    except Exception as e:  # noqa: BLE001 - top-level CLI
        print(f"  ERROR: {e}", file=sys.stderr)
        return 2
    if not ips:
        print("  ERROR: feed returned no IPs", file=sys.stderr)
        return 3

    fresh_rows = [{"ip": ip, "relay_type": "exit"} for ip in ips]

    if args.merge:
        existing = read_existing_rows(LOOKUP)
        existing_ips = {r["ip"] for r in existing}
        merged = list(existing) + [r for r in fresh_rows if r["ip"] not in existing_ips]
        rows = merged
    else:
        rows = fresh_rows

    csv_text = render_csv(rows)
    if args.dry_run:
        print(csv_text)
        print(f"  (dry-run) would write {len(rows)} rows to {LOOKUP}")
        return 0

    LOOKUP.write_text(csv_text, encoding="utf-8")
    print(f"  wrote {len(rows)} rows to {LOOKUP.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
