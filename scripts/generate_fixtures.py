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
CASE_BEACON = ROOT / "cases" / "t1071_001_http_beacon_sliver" / "tests"
CASE_PORTSCAN = ROOT / "cases" / "t1046_network_service_discovery" / "tests"
CASE_TUNNEL = ROOT / "cases" / "t1572_protocol_tunneling_chisel" / "tests"
CASE_TOR = ROOT / "cases" / "t1090_003_tor_relay_use" / "tests"
CASE_DNSEXFIL = ROOT / "cases" / "t1048_003_dns_exfil" / "tests"


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


def _zeek_conn_record(
    ts: float,
    src: str,
    dest: str,
    *,
    dest_port: int = 443,
    proto: str = "tcp",
    duration: float = 0.5,
    orig_bytes: int = 512,
    resp_bytes: int = 1024,
    conn_state: str = "SF",
    history: str = "ShADadFf",
    service: str | None = None,
    uid_seed: int = 0,
) -> dict:
    if service is None:
        service = "http" if dest_port in (80, 8080) else "ssl"
    return {
        "ts": ts,
        "uid": f"C{uid_seed:010d}",
        "id.orig_h": src,
        "id.orig_p": 40000 + (uid_seed % 20000),
        "id.resp_h": dest,
        "id.resp_p": dest_port,
        "proto": proto,
        "service": service,
        "duration": duration,
        "orig_bytes": orig_bytes,
        "resp_bytes": resp_bytes,
        "conn_state": conn_state,
        "missed_bytes": 0,
        "history": history,
        "orig_pkts": 5,
        "orig_ip_bytes": orig_bytes + 200,
        "resp_pkts": 6,
        "resp_ip_bytes": resp_bytes + 240,
    }


def generate_sliver_beacon_positive(out_path: Path, *, seed: int = 7777) -> None:
    """Sliver-shape beacon: one src, one dest, 60s interval +/- 1.5s jitter, 60 conns."""
    rng = random.Random(seed)
    src = "10.0.0.42"
    dest = "203.0.113.7"
    start_ts = 1715000000.0
    interval = 60.0
    jitter = 1.5
    n = 60

    records = []
    for i in range(n):
        # Tight jitter -> low CoV. stddev ~= jitter * sqrt(2/3) for uniform noise.
        ts = start_ts + i * interval + rng.uniform(-jitter, jitter)
        records.append(
            _zeek_conn_record(
                ts=ts, src=src, dest=dest, dest_port=443, uid_seed=i,
            )
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    print(f"wrote {len(records)} records -> {out_path}")


def generate_benign_conn_negative(out_path: Path, *, seed: int = 9999) -> None:
    """Mixed benign HTTP/S: many sources, many destinations, irregular timing."""
    rng = random.Random(seed)
    sources = [f"10.0.0.{i}" for i in range(20, 60)]
    destinations = [f"93.184.216.{i}" for i in range(1, 60)]
    ports = [80, 443, 443, 443, 443, 8443]

    start_ts = 1715000000.0
    records = []
    n = 400
    # Spread connections across many (src, dest) pairs so no pair has enough volume.
    for i in range(n):
        # Big random gaps -> high CoV in any single pair.
        ts = start_ts + i * rng.uniform(0.1, 30.0)
        records.append(
            _zeek_conn_record(
                ts=ts,
                src=rng.choice(sources),
                dest=rng.choice(destinations),
                dest_port=rng.choice(ports),
                uid_seed=20_000 + i,
            )
        )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    print(f"wrote {len(records)} records -> {out_path}")


def generate_port_scan_positive(out_path: Path, *, seed: int = 5555) -> None:
    """nmap-shape SYN scan: one src -> one dest, ~200 distinct ports in ~30s, all S0."""
    rng = random.Random(seed)
    src = "10.0.0.99"
    dest = "192.168.1.10"
    start_ts = 1715000000.0

    # nmap default top ports + filler to reach 200 distinct.
    ports = sorted({rng.randint(1, 65000) for _ in range(220)})[:200]
    rng.shuffle(ports)

    records = []
    for i, p in enumerate(ports):
        ts = start_ts + i * 0.15  # ~6.7 ports/sec, ~30s total
        records.append(
            _zeek_conn_record(
                ts=ts,
                src=src,
                dest=dest,
                dest_port=p,
                duration=0.0,
                orig_bytes=0,
                resp_bytes=0,
                conn_state="S0",
                history="S",
                service="-",
                uid_seed=30_000 + i,
            )
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    print(f"wrote {len(records)} records -> {out_path}")


def generate_port_scan_negative(out_path: Path, *, seed: int = 6666) -> None:
    """Mixed benign traffic: many src/dest pairs, few ports per pair, all SF."""
    rng = random.Random(seed)
    sources = [f"10.0.0.{i}" for i in range(20, 60)]
    destinations = [f"93.184.216.{i}" for i in range(1, 80)]
    ports = [80, 443, 443, 443, 443, 8443, 22, 53]

    start_ts = 1715000000.0
    records = []
    n = 350
    for i in range(n):
        ts = start_ts + i * rng.uniform(0.1, 5.0)
        records.append(
            _zeek_conn_record(
                ts=ts,
                src=rng.choice(sources),
                dest=rng.choice(destinations),
                dest_port=rng.choice(ports),
                duration=rng.uniform(0.1, 2.0),
                conn_state="SF",
                uid_seed=40_000 + i,
            )
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    print(f"wrote {len(records)} records -> {out_path}")


def generate_protocol_tunnel_positive(out_path: Path, *, seed: int = 8888) -> None:
    """chisel-shape: one long-lived high-throughput TCP flow on port 443."""
    rng = random.Random(seed)
    src = "10.0.0.77"
    dest = "203.0.113.42"
    start_ts = 1715000000.0

    # One marathon flow: ~2h duration, ~80 MB up / ~120 MB down.
    long_flow = _zeek_conn_record(
        ts=start_ts,
        src=src,
        dest=dest,
        dest_port=443,
        duration=7200.0,
        orig_bytes=80_000_000,
        resp_bytes=120_000_000,
        conn_state="SF",
        history="ShADadFf",
        service="ssl",
        uid_seed=50_000,
    )
    records = [long_flow]

    # Add some adjacent normal traffic so the fixture isn't a single record.
    for i in range(40):
        ts = start_ts + rng.uniform(0, 7200)
        records.append(
            _zeek_conn_record(
                ts=ts,
                src=src,
                dest=f"93.184.216.{rng.randint(1, 254)}",
                dest_port=rng.choice([80, 443]),
                duration=rng.uniform(0.1, 5.0),
                orig_bytes=rng.randint(200, 4000),
                resp_bytes=rng.randint(500, 50_000),
                uid_seed=50_001 + i,
            )
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    print(f"wrote {len(records)} records -> {out_path}")


def generate_protocol_tunnel_negative(out_path: Path, *, seed: int = 9090) -> None:
    """Benign HTTPS browsing: short connections, modest bytes, no long flows."""
    rng = random.Random(seed)
    sources = [f"10.0.0.{i}" for i in range(20, 60)]
    destinations = [f"93.184.216.{i}" for i in range(1, 80)]

    start_ts = 1715000000.0
    records = []
    n = 200
    for i in range(n):
        ts = start_ts + i * rng.uniform(0.1, 30.0)
        records.append(
            _zeek_conn_record(
                ts=ts,
                src=rng.choice(sources),
                dest=rng.choice(destinations),
                dest_port=rng.choice([80, 443, 443, 443]),
                duration=rng.uniform(0.05, 30.0),
                orig_bytes=rng.randint(200, 8000),
                resp_bytes=rng.randint(500, 200_000),
                uid_seed=60_000 + i,
            )
        )

    # Sprinkle one larger-but-still-short download so the fixture isn't trivial.
    records.append(
        _zeek_conn_record(
            ts=start_ts + 1500.0,
            src=rng.choice(sources),
            dest=rng.choice(destinations),
            dest_port=443,
            duration=120.0,           # 2 min, well under threshold
            orig_bytes=20_000,
            resp_bytes=8_000_000,     # 8 MB, well under threshold
            uid_seed=60_999,
        )
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    print(f"wrote {len(records)} records -> {out_path}")


# --- T1090.003 Tor relay use ---

# Must match LAB_TOR_RELAY_IPS in src/detlab/detector.py and app/lookups/tor_relays.csv.
LAB_TOR_RELAYS: tuple[str, ...] = (
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
)


def generate_tor_relay_positive(out_path: Path, *, seed: int = 1010) -> None:
    """Tor client: 10.0.0.66 touches 6 distinct lab relays over ~30 min."""
    rng = random.Random(seed)
    src = "10.0.0.66"
    start_ts = 1715000000.0

    # 60 connections across 6 distinct relays — circuit rebuilds + retries.
    relays = list(LAB_TOR_RELAYS[:6])
    records = []
    for i in range(60):
        relay = rng.choice(relays)
        ts = start_ts + i * 30 + rng.uniform(-3, 3)
        records.append(
            _zeek_conn_record(
                ts=ts,
                src=src,
                dest=relay,
                dest_port=443,
                duration=rng.uniform(0.5, 6.0),
                orig_bytes=rng.randint(800, 8000),
                resp_bytes=rng.randint(2000, 50_000),
                uid_seed=70_000 + i,
            )
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    print(f"wrote {len(records)} records -> {out_path}")


def generate_tor_relay_negative(out_path: Path, *, seed: int = 2020) -> None:
    """Benign HTTPS browsing — no destination IP overlaps the lab relay set."""
    rng = random.Random(seed)
    sources = [f"10.0.0.{i}" for i in range(20, 60)]
    # IPs in a different /24 from the lab relays; zero overlap by construction.
    destinations = [f"172.16.{rng.randint(0, 30)}.{rng.randint(1, 254)}" for _ in range(50)]

    start_ts = 1715000000.0
    records = []
    n = 200
    for i in range(n):
        ts = start_ts + i * rng.uniform(0.5, 18.0)
        records.append(
            _zeek_conn_record(
                ts=ts,
                src=rng.choice(sources),
                dest=rng.choice(destinations),
                dest_port=rng.choice([80, 443, 443, 443]),
                duration=rng.uniform(0.1, 4.0),
                uid_seed=80_000 + i,
            )
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    print(f"wrote {len(records)} records -> {out_path}")


# --- T1048.003 DNS Exfil ---


def generate_dns_exfil_positive(out_path: Path, *, seed: int = 3030) -> None:
    """A-record DNS exfil: 10.0.0.5 pushes ~80 KB of encoded data through one
    base domain in 30 s using A queries with near-max-length labels.

    The 30-s burst is bracketed by a 60-s bucket-aligned start_ts so all
    records land in one window regardless of how the detector buckets ts.
    """
    rng = random.Random(seed)
    src = "10.0.0.5"
    base_domain = "exfil.evil.example"
    # 60-s bucket-aligned: 1715000040 = 60 * 28583334.
    start_ts = 1715000040.0

    records = []
    n_queries = 600  # ~20 qps over 30s
    burst_seconds = 30.0
    for i in range(n_queries):
        # Long random label, near the 63-byte DNS label limit.
        label_len = rng.randint(58, 63)
        label = _random_b32_label(rng, label_len)
        # Chain a short index label so the exfil tool can sequence chunks.
        seq = f"{i:04x}"
        query = f"{label}.{seq}.{base_domain}"
        ts = start_ts + i * (burst_seconds / n_queries) + rng.uniform(-0.02, 0.02)
        records.append(
            _zeek_dns_record(
                ts=ts,
                src=src,
                query=query,
                qtype="A",
                answers=[f"203.0.113.{rng.randint(1, 254)}"],
                uid_seed=90_000 + i,
            )
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    print(f"wrote {len(records)} records -> {out_path}")


def generate_dns_exfil_negative(out_path: Path, *, seed: int = 4040) -> None:
    """Mixed benign DNS — already proven safe against detect_dns_tunnel; same shape."""
    # Reuse the existing benign DNS generator for parity. A separate file keeps
    # case fixtures self-contained even though the contents would be similar.
    generate_benign_negative(out_path, seed=seed)


def main() -> None:
    generate_dnscat2_positive(CASE_DNSCAT / "positive_dns.log")
    generate_benign_negative(CASE_DNSCAT / "negative_dns.log")
    generate_sliver_beacon_positive(CASE_BEACON / "positive_conn.log")
    generate_benign_conn_negative(CASE_BEACON / "negative_conn.log")
    generate_port_scan_positive(CASE_PORTSCAN / "positive_conn.log")
    generate_port_scan_negative(CASE_PORTSCAN / "negative_conn.log")
    generate_protocol_tunnel_positive(CASE_TUNNEL / "positive_conn.log")
    generate_protocol_tunnel_negative(CASE_TUNNEL / "negative_conn.log")
    generate_tor_relay_positive(CASE_TOR / "positive_conn.log")
    generate_tor_relay_negative(CASE_TOR / "negative_conn.log")
    generate_dns_exfil_positive(CASE_DNSEXFIL / "positive_dns.log")
    generate_dns_exfil_negative(CASE_DNSEXFIL / "negative_dns.log")


if __name__ == "__main__":
    main()
