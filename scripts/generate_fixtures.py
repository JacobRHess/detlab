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
CASE_BRUTE = ROOT / "cases" / "t1110_001_ssh_brute_force" / "tests"
CASE_DGA = ROOT / "cases" / "t1568_002_dga_c2" / "tests"
CASE_RMM = ROOT / "cases" / "t1219_rmm_tool_use" / "tests"
CASE_DOS = ROOT / "cases" / "t1499_001_volumetric_flood" / "tests"
CASE_SURICATA = ROOT / "cases" / "t1190_suricata_exploit" / "tests"
CASE_C2EXFIL = ROOT / "cases" / "t1041_exfil_over_c2" / "tests"
CASE_CLOUDEXFIL = ROOT / "cases" / "t1567_002_cloud_exfil" / "tests"


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


# --- T1110.001 SSH brute force ---


def generate_ssh_brute_force_positive(out_path: Path, *, seed: int = 1100) -> None:
    """hydra-shape brute force: 10.0.0.55 hits 192.168.1.20:22 with 60 fast SF conns / 60 s."""
    rng = random.Random(seed)
    src = "10.0.0.55"
    dest = "192.168.1.20"
    start_ts = 1715000000.0
    n = 60

    records = []
    for i in range(n):
        # ~1 attempt/sec with jitter — duration ~1s, full TCP handshake (SF) but auth fails.
        ts = start_ts + i + rng.uniform(-0.1, 0.1)
        records.append(
            _zeek_conn_record(
                ts=ts,
                src=src,
                dest=dest,
                dest_port=22,
                duration=rng.uniform(0.4, 1.6),
                orig_bytes=rng.randint(800, 2000),
                resp_bytes=rng.randint(900, 2400),
                conn_state="SF",
                history="ShAdDaFf",
                service="ssh",
                uid_seed=100_000 + i,
            )
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    print(f"wrote {len(records)} records -> {out_path}")


def generate_ssh_brute_force_negative(out_path: Path, *, seed: int = 1101) -> None:
    """Benign SSH usage: a few legitimate sessions per (src, dest, 22) over the window."""
    rng = random.Random(seed)
    sources = [f"10.0.0.{i}" for i in range(20, 40)]
    destinations = [f"10.0.0.{i}" for i in range(100, 120)]
    start_ts = 1715000000.0

    records = []
    n = 80
    for i in range(n):
        ts = start_ts + i * rng.uniform(2.0, 30.0)
        records.append(
            _zeek_conn_record(
                ts=ts,
                src=rng.choice(sources),
                dest=rng.choice(destinations),
                dest_port=22,
                duration=rng.uniform(30.0, 600.0),
                orig_bytes=rng.randint(2000, 200_000),
                resp_bytes=rng.randint(2000, 800_000),
                conn_state="SF",
                service="ssh",
                uid_seed=110_000 + i,
            )
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    print(f"wrote {len(records)} records -> {out_path}")


# --- T1568.002 DGA ---

# Common TLDs that DGA families use in the wild — mostly cheap, easy to register at scale.
_DGA_TLDS = ("com", "net", "org", "info", "biz", "pw", "ru")


def _random_dga_label(rng: random.Random, length: int) -> str:
    """Letters only — most DGA families produce alphabetic labels."""
    return "".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(length))


def generate_dga_positive(out_path: Path, *, seed: int = 5050) -> None:
    """DGA-shape: 10.0.0.7 fires 50 high-entropy base-domain queries / 5 min, mostly NXDOMAIN."""
    rng = random.Random(seed)
    src = "10.0.0.7"
    # 5-min bucket alignment: 1715040000 = 300 * 5716800.
    start_ts = 1715040000.0
    n = 50

    records = []
    for i in range(n):
        # Random alphabetic 2nd-level label, 15-22 chars, high entropy.
        sld = _random_dga_label(rng, rng.randint(15, 22))
        tld = rng.choice(_DGA_TLDS)
        bd = f"{sld}.{tld}"
        # Most resolve NXDOMAIN; one in twenty hits a live record.
        is_live = rng.random() < 0.05
        ts = start_ts + i * (300.0 / n) + rng.uniform(-0.3, 0.3)
        records.append(
            _zeek_dns_record(
                ts=ts,
                src=src,
                query=bd,
                qtype="A",
                rcode="NOERROR" if is_live else "NXDOMAIN",
                answers=[f"203.0.113.{rng.randint(1, 254)}"] if is_live else [],
                uid_seed=120_000 + i,
            )
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    print(f"wrote {len(records)} records -> {out_path}")


def generate_dga_negative(out_path: Path, *, seed: int = 6060) -> None:
    """Benign DNS: low entropy domains, mostly NOERROR. Reuses generate_benign_negative shape."""
    generate_benign_negative(out_path, seed=seed)


# --- T1219 RMM tool use ---

LAB_RMM_DOMAIN_LIST = (
    "teamviewer.com",
    "anydesk.com",
    "screenconnect.com",
    "connectwise.com",
    "splashtop.com",
)


def generate_rmm_positive(out_path: Path, *, seed: int = 7700) -> None:
    """One internal host resolves several RMM-tool subdomains in a 5-min window."""
    rng = random.Random(seed)
    src = "10.0.0.88"
    start_ts = 1715040000.0  # 5-min bucket aligned

    records = []
    # Realistic mix: workstation reaching out to TeamViewer + AnyDesk during a
    # ransomware operator's hands-on-keyboard session.
    queries = [
        "ping.teamviewer.com",
        "router8.teamviewer.com",
        "master9.teamviewer.com",
        "boot.anydesk.com",
        "relay-fra.anydesk.com",
        "boot.anydesk.com",
        "relay.anydesk.com",
        "gateway.screenconnect.com",
    ]
    for i, q in enumerate(queries):
        ts = start_ts + i * (300.0 / len(queries)) + rng.uniform(-1, 1)
        records.append(
            _zeek_dns_record(
                ts=ts,
                src=src,
                query=q,
                qtype="A",
                answers=[f"203.0.113.{rng.randint(1, 254)}"],
                uid_seed=130_000 + i,
            )
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    print(f"wrote {len(records)} records -> {out_path}")


def generate_rmm_negative(out_path: Path, *, seed: int = 7701) -> None:
    """Benign DNS — no RMM domains. Reuses the existing benign DNS shape."""
    generate_benign_negative(out_path, seed=seed)


# --- T1499.001 Volumetric flood ---


def generate_volumetric_flood_positive(out_path: Path, *, seed: int = 8800) -> None:
    """SYN flood: one src hammers one dest:80 with 200 connections in <0.5 s."""
    rng = random.Random(seed)
    src = "10.0.0.13"
    dest = "192.168.1.42"
    start_ts = 1715000000.0
    n = 200

    records = []
    for i in range(n):
        # 0-2 ms apart — bunches into a single 1-s bucket.
        ts = start_ts + i * 0.0015 + rng.uniform(0, 0.0005)
        records.append(
            _zeek_conn_record(
                ts=ts,
                src=src,
                dest=dest,
                dest_port=80,
                duration=0.0,
                orig_bytes=40,
                resp_bytes=0,
                conn_state="S0",
                history="S",
                service="-",
                uid_seed=140_000 + i,
            )
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    print(f"wrote {len(records)} records -> {out_path}")


def generate_volumetric_flood_negative(out_path: Path, *, seed: int = 8801) -> None:
    """Benign HTTP/S — many src/dest pairs spread out, no single second tightly clusters."""
    generate_benign_conn_negative(out_path, seed=seed)


# --- T1190 Suricata IDS exploit alerts ---


def _suricata_alert(
    ts_iso: str,
    *,
    src_ip: str,
    src_port: int,
    dest_ip: str,
    dest_port: int,
    proto: str,
    signature_id: int,
    signature: str,
    category: str,
    severity: int,
    flow_id: int,
) -> dict:
    return {
        "timestamp": ts_iso,
        "flow_id": flow_id,
        "in_iface": "eth0",
        "event_type": "alert",
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "proto": proto,
        "tx_id": 0,
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": signature_id,
            "rev": 1,
            "signature": signature,
            "category": category,
            "severity": severity,
        },
        "http": {
            "hostname": "victim.lab.local",
            "url": "/login.php",
            "http_user_agent": "Mozilla/5.0",
            "http_method": "GET",
        },
    }


def generate_suricata_positive(out_path: Path, *, seed: int = 9900) -> None:
    """Three categories of Suricata exploit alerts from one external attacker."""
    rng = random.Random(seed)
    src = "203.0.113.99"
    dest = "10.0.0.10"
    base_ts = "2026-05-05T12:00:"

    samples = [
        # SQLi attempts
        (2025463, "ET WEB_SPECIFIC_APPS Generic SQL Injection", "Web Application Attack", 1),
        (2025464, "ET WEB_SPECIFIC_APPS UNION SELECT in URI", "Web Application Attack", 1),
        (2025465, "ET WEB_SPECIFIC_APPS sqlmap-like User-Agent", "Web Application Attack", 1),
        # Admin priv-gain
        (
            2018959,
            "ET WEB_SERVER Possible Strut2 RCE",
            "Attempted Administrator Privilege Gain",
            1,
        ),
        (
            2018960,
            "ET WEB_SERVER Apache Struts2 ContentTypeUtil RCE",
            "Attempted Administrator Privilege Gain",
            1,
        ),
        # Trojan callback
        (2030001, "ET TROJAN Generic C2 callback observed", "A Network Trojan was detected", 2),
    ]
    records = []
    for i, (sid, sig, cat, sev) in enumerate(samples):
        seconds = i * 5
        ts_iso = f"{base_ts}{seconds:02d}.{rng.randint(0, 999_999):06d}+0000"
        records.append(
            _suricata_alert(
                ts_iso=ts_iso,
                src_ip=src,
                src_port=40000 + i,
                dest_ip=dest,
                dest_port=443,
                proto="TCP",
                signature_id=sid,
                signature=sig,
                category=cat,
                severity=sev,
                flow_id=900_000 + i,
            )
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    print(f"wrote {len(records)} records -> {out_path}")


def generate_suricata_negative(out_path: Path, *, seed: int = 9901) -> None:
    """Mixed Suricata events — flow / dns / non-exploit categories. Should not trigger."""
    rng = random.Random(seed)
    base_ts = "2026-05-05T12:00:"

    records = []
    # A few flow events (no alerts)
    for i in range(8):
        records.append(
            {
                "timestamp": f"{base_ts}{i:02d}.000000+0000",
                "flow_id": 800_000 + i,
                "event_type": "flow",
                "src_ip": f"10.0.0.{20 + i}",
                "src_port": 50000 + i,
                "dest_ip": "203.0.113.5",
                "dest_port": 443,
                "proto": "TCP",
            }
        )
    # A "Not Suspicious Traffic" alert (not an exploit category)
    records.append(
        _suricata_alert(
            ts_iso=f"{base_ts}10.000000+0000",
            src_ip="10.0.0.50",
            src_port=49231,
            dest_ip="93.184.216.34",
            dest_port=443,
            proto="TCP",
            signature_id=2025500,
            signature="ET POLICY HTTP traffic on uncommon port",
            category="Not Suspicious Traffic",
            severity=3,
            flow_id=800_100,
        )
    )
    # An ICMP alert (informational)
    records.append(
        _suricata_alert(
            ts_iso=f"{base_ts}20.000000+0000",
            src_ip="10.0.0.51",
            src_port=0,
            dest_ip="10.0.0.10",
            dest_port=0,
            proto="ICMP",
            signature_id=1234567,
            signature="GPL ICMP_INFO PING BSDtype",
            category="Misc activity",
            severity=3,
            flow_id=800_101,
        )
    )

    rng.shuffle(records)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    print(f"wrote {len(records)} records -> {out_path}")


# --- T1041 Exfil over C2 channel (chained detection) ---


def generate_c2_exfil_positive(out_path: Path, *, seed: int = 4400) -> None:
    """Sliver-shape beacon (60 conns / 60-s metronome) where 4 of the beacons
    happen to carry exfil-grade uplink bytes. Same metronome timestamps so the
    beacon detector still matches on CoV; just the orig_bytes vary.

    This shape is closer to reality — a real implant uses the same beacon
    channel for everything and the operator queues a download, so the
    next beacon's orig_bytes spikes."""
    rng = random.Random(seed)
    src = "10.0.0.42"
    dest = "203.0.113.7"
    start_ts = 1715000000.0
    n = 60
    exfil_indices = {12, 24, 36, 48}  # which beacons carry the exfil chunks

    records = []
    for i in range(n):
        ts = start_ts + i * 60.0 + rng.uniform(-1.5, 1.5)
        if i in exfil_indices:
            orig_bytes = rng.randint(30_000, 60_000)
            duration = rng.uniform(2.0, 4.0)
        else:
            orig_bytes = rng.randint(400, 800)
            duration = 0.5
        records.append(
            _zeek_conn_record(
                ts=ts,
                src=src,
                dest=dest,
                dest_port=443,
                duration=duration,
                orig_bytes=orig_bytes,
                resp_bytes=rng.randint(800, 1500),
                uid_seed=200_000 + i,
            )
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    print(f"wrote {len(records)} records -> {out_path}")


def generate_c2_exfil_negative(out_path: Path, *, seed: int = 4401) -> None:
    """Benign mixed conn.log — same shape as the existing benign negative fixture
    but with one large download mixed in to ensure the rule does NOT fire on
    plain large-transfer traffic that lacks the beacon prerequisite."""
    rng = random.Random(seed)
    sources = [f"10.0.0.{i}" for i in range(20, 60)]
    destinations = [f"93.184.216.{i}" for i in range(1, 60)]
    ports = [80, 443, 443, 443, 443, 8443]
    start_ts = 1715000000.0

    records = []
    for i in range(400):
        ts = start_ts + i * rng.uniform(0.1, 30.0)
        records.append(
            _zeek_conn_record(
                ts=ts,
                src=rng.choice(sources),
                dest=rng.choice(destinations),
                dest_port=rng.choice(ports),
                uid_seed=220_000 + i,
            )
        )

    # One huge download to one destination — no beaconing here, so chained
    # detector must stay quiet.
    for i in range(3):
        records.append(
            _zeek_conn_record(
                ts=start_ts + 5000 + i * 50,
                src="10.0.0.30",
                dest="93.184.216.42",
                dest_port=443,
                duration=120.0,
                orig_bytes=rng.randint(80_000, 200_000),
                resp_bytes=rng.randint(2_000_000, 8_000_000),
                uid_seed=230_000 + i,
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
    generate_ssh_brute_force_positive(CASE_BRUTE / "positive_conn.log")
    generate_ssh_brute_force_negative(CASE_BRUTE / "negative_conn.log")
    generate_dga_positive(CASE_DGA / "positive_dns.log")
    generate_dga_negative(CASE_DGA / "negative_dns.log")
    generate_rmm_positive(CASE_RMM / "positive_dns.log")
    generate_rmm_negative(CASE_RMM / "negative_dns.log")
    generate_volumetric_flood_positive(CASE_DOS / "positive_conn.log")
    generate_volumetric_flood_negative(CASE_DOS / "negative_conn.log")
    generate_suricata_positive(CASE_SURICATA / "positive_eve.log")
    generate_suricata_negative(CASE_SURICATA / "negative_eve.log")
    generate_c2_exfil_positive(CASE_C2EXFIL / "positive_conn.log")
    generate_c2_exfil_negative(CASE_C2EXFIL / "negative_conn.log")
    generate_cloud_exfil_positive(CASE_CLOUDEXFIL / "positive_conn.log")
    generate_cloud_exfil_negative(CASE_CLOUDEXFIL / "negative_conn.log")


# --- T1567.002 Cloud-storage exfil ---


def generate_cloud_exfil_positive(out_path: Path, *, seed: int = 5500) -> None:
    """rclone-shape staging: 10.0.0.55 uploads ~75 MB across 5 connections to
    Mega.nz IPs in 30 minutes. The IP set matches LAB_CLOUD_STORAGE_IPS in
    src/detlab/detector.py."""
    rng = random.Random(seed)
    src = "10.0.0.55"
    dests = ("203.0.113.50", "203.0.113.51")  # Mega's lab IPs
    # 3600-aligned bucket (1715040000 = 3600 * 476400) so all records land
    # in one window for the 1-h aggregation.
    start_ts = 1715040000.0

    records = []
    # 5 large uploads — 12 to 18 MB each, total ~75 MB.
    for i in range(5):
        # Spread across the first ~30 min of the bucket; positive jitter only.
        ts = start_ts + 60 + i * 360 + rng.uniform(0, 30)
        records.append(
            _zeek_conn_record(
                ts=ts,
                src=src,
                dest=rng.choice(dests),
                dest_port=443,
                duration=rng.uniform(20, 60),
                orig_bytes=rng.randint(12_000_000, 18_000_000),
                resp_bytes=rng.randint(2_000, 8_000),
                uid_seed=300_000 + i,
            )
        )

    # Background noise — small benign requests interspersed (must not
    # accidentally cross the 50 MB threshold).
    for i in range(20):
        ts = start_ts + rng.uniform(0, 1800)
        records.append(
            _zeek_conn_record(
                ts=ts,
                src=src,
                dest=f"93.184.216.{rng.randint(1, 254)}",
                dest_port=443,
                duration=rng.uniform(0.1, 5.0),
                orig_bytes=rng.randint(500, 4_000),
                resp_bytes=rng.randint(2_000, 80_000),
                uid_seed=310_000 + i,
            )
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    print(f"wrote {len(records)} records -> {out_path}")


def generate_cloud_exfil_negative(out_path: Path, *, seed: int = 5501) -> None:
    """Benign mixed conn.log + a couple of large downloads (resp_bytes high,
    orig_bytes modest) — must not fire because uplink is the keyed signal."""
    rng = random.Random(seed)
    sources = [f"10.0.0.{i}" for i in range(20, 60)]
    destinations = [f"93.184.216.{i}" for i in range(1, 80)]
    start_ts = 1715000000.0

    records = []
    for i in range(300):
        ts = start_ts + i * rng.uniform(0.1, 30.0)
        records.append(
            _zeek_conn_record(
                ts=ts,
                src=rng.choice(sources),
                dest=rng.choice(destinations),
                dest_port=443,
                duration=rng.uniform(0.1, 60.0),
                orig_bytes=rng.randint(500, 8_000),
                # Some big downloads — large resp_bytes, low orig_bytes.
                resp_bytes=(
                    rng.randint(2_000, 50_000_000)
                    if i % 30 == 0
                    else rng.randint(2_000, 200_000)
                ),
                uid_seed=320_000 + i,
            )
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    print(f"wrote {len(records)} records -> {out_path}")


if __name__ == "__main__":
    main()
