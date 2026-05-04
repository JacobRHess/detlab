"""Generate synthetic Zeek dns.log fixtures for each case.

These stand in for real captures so the test suite is hermetic. Replace any
fixture with a real lab capture (trimmed) once you have one — the file
format is identical. Determinism: a fixed seed makes runs reproducible.

Usage:
    py scripts/generate_fixtures.py
"""

from __future__ import annotations

import json
import random
import string
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CASE_DNSCAT = ROOT / "cases" / "t1071_004_dns_c2_dnscat2" / "tests"


def _zeek_dns_record(
    ts: float,
    src: str,
    query: str,
    *,
    qtype: str = "A",
    rcode: str = "NOERROR",
    answers: list[str] | None = None,
    uid_seed: int = 0,
) -> dict:
    return {
        "ts": ts,
        "uid": f"C{uid_seed:010d}",
        "id.orig_h": src,
        "id.orig_p": 50000 + (uid_seed % 10000),
        "id.resp_h": "10.0.0.53",
        "id.resp_p": 53,
        "proto": "udp",
        "trans_id": uid_seed % 65535,
        "query": query,
        "qclass": 1,
        "qclass_name": "C_INTERNET",
        "qtype": {"A": 1, "AAAA": 28, "TXT": 16, "MX": 15, "CNAME": 5}.get(qtype, 1),
        "qtype_name": qtype,
        "rcode": 0 if rcode == "NOERROR" else 3,
        "rcode_name": rcode,
        "AA": False,
        "TC": False,
        "RD": True,
        "RA": True,
        "Z": 0,
        "answers": answers or [],
        "TTLs": [60.0] if answers else [],
        "rejected": False,
    }


def _random_b32_label(rng: random.Random, length: int) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(rng.choice(alphabet) for _ in range(length))


def generate_dnscat2_positive(out_path: Path, *, seed: int = 1337) -> None:
    """dnscat2-shape: one src, one domain, ~60 TXT queries with long high-entropy subdomains."""
    rng = random.Random(seed)
    src = "10.0.0.5"
    base_domain = "c2.evil.example"
    # Align to a 300s bucket boundary so all 65 records land in one window.
    start_ts = 1715000100.0

    records = []
    n_queries = 65
    for i in range(n_queries):
        sub_len = rng.randint(35, 50)
        label = _random_b32_label(rng, sub_len)
        # Multi-label encoding sometimes used by tunnelers; mostly single-label here.
        query = f"{label}.{base_domain}"
        ts = start_ts + i * 2.5  # ~queries every 2.5s -> ~65 over ~160s, fits one 5-min window
        records.append(
            _zeek_dns_record(
                ts=ts,
                src=src,
                query=query,
                qtype="TXT",
                answers=[_random_b32_label(rng, 200)],
                uid_seed=i,
            )
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    print(f"wrote {len(records)} records -> {out_path}")


def generate_benign_negative(out_path: Path, *, seed: int = 4242) -> None:
    """Mixed benign DNS: many sources, many domains, short common subdomains, mixed qtypes."""
    rng = random.Random(seed)
    sources = [f"10.0.0.{i}" for i in range(20, 60)]
    base_domains = [
        "google.com",
        "github.com",
        "cloudflare.com",
        "microsoft.com",
        "amazonaws.com",
        "akamai.net",
        "fastly.net",
        "apple.com",
        "wikipedia.org",
        "stackoverflow.com",
        "reddit.com",
        "linkedin.com",
        "office365.com",
        "spotify.com",
        "ubuntu.com",
        "python.org",
        "npmjs.com",
        "nytimes.com",
        "bbc.co.uk",
        "twitch.tv",
    ]
    subdomains = ["www", "mail", "api", "cdn", "static", "assets", "auth", "login", "img", "m"]
    qtypes = ["A", "A", "A", "AAAA", "AAAA", "TXT", "MX", "CNAME"]

    start_ts = 1715000000.0
    records = []
    n = 240  # enough volume that any single (window, src, base) group stays small
    for i in range(n):
        bd = rng.choice(base_domains)
        sub = rng.choice(subdomains)
        # Sometimes a 2-deep label for realism (e.g. cdn.images.example.com)
        if rng.random() < 0.2:
            sub = f"{rng.choice(subdomains)}.{sub}"
        query = f"{sub}.{bd}"
        ts = start_ts + i * 1.0
        records.append(
            _zeek_dns_record(
                ts=ts,
                src=rng.choice(sources),
                query=query,
                qtype=rng.choice(qtypes),
                answers=[f"93.184.216.{rng.randint(1, 254)}"],
                uid_seed=10_000 + i,
            )
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    print(f"wrote {len(records)} records -> {out_path}")


def main() -> None:
    generate_dnscat2_positive(CASE_DNSCAT / "positive_dns.log")
    generate_benign_negative(CASE_DNSCAT / "negative_dns.log")


if __name__ == "__main__":
    main()
