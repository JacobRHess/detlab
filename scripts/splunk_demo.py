"""End-to-end Splunk demo for detlab.

Drives a live Splunk (the lab's docker-compose stack by default) over its
HTTPS REST API. Two subcommands:

  load — Stream every shipped case's positive fixture into Splunk via HTTP
         Event Collector (HEC), mapped to the right index + sourcetype
         (zeek:dns / zeek:conn / suricata:eve).
  run  — Fire every saved search the detlab app ships, poll for completion,
         and print "fired ✓ N alerts" per case.

Together they prove the SPL works end-to-end against a real Splunk
instance, not just the Python mirror in src/detlab/detector.py.

Stdlib only — no `requests` dependency.

Prereq:
  1. `cd lab && docker compose up -d`              (brings up Splunk + Zeek + Suricata)
  2. Build + load the detlab app:
        py scripts/build_app.py
     The compose file already mounts ../app into Splunk's apps dir, so a
     restart picks it up automatically.
  3. Enable HEC + create a token in Splunk Web (Settings → Data Inputs →
     HTTP Event Collector → New Token), then export it:
        export SPLUNK_HEC_TOKEN=<your-token>
  4. (Optional) override management password if you changed it from the
     compose default of `changemenow`:
        export SPLUNK_PASSWORD=<your-password>

Usage:
    py scripts/splunk_demo.py load
    py scripts/splunk_demo.py run
    py scripts/splunk_demo.py all     # load + run in one shot
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CASES_DIR = ROOT / "cases"
LOOKUP = ROOT / "app" / "lookups" / "detlab_cases.csv"

DEFAULT_HEC_URL = "https://localhost:8088/services/collector/event"
DEFAULT_MGMT_URL = "https://localhost:8089"
DEFAULT_USER = "admin"
DEFAULT_PASSWORD = "changemenow"  # matches lab/docker-compose.yml

# Mapping: which index + sourcetype each case's fixtures land in. The Splunk
# app's props.conf already understands these sourcetypes so field aliases
# fire automatically.
FIXTURE_KIND_TO_SOURCETYPE = {
    "zeek_json": {
        "dns": ("zeek", "zeek:dns"),
        "conn": ("zeek", "zeek:conn"),
    },
    "suricata_eve": {
        "eve": ("suricata", "suricata:eve"),
    },
}


# ---------- HTTP helpers ----------


def _ssl_ctx() -> ssl.SSLContext:
    """The lab Splunk uses self-signed certs; production callers should
    swap this for verified-cert context."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def basic_auth_header(user: str, password: str) -> str:
    raw = f"{user}:{password}".encode()
    return "Basic " + base64.b64encode(raw).decode()


def hec_auth_header(token: str) -> str:
    return f"Splunk {token}"


def http_post_json(
    url: str,
    *,
    body: bytes,
    headers: dict[str, str],
    timeout: float = 30.0,
) -> dict:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout) as resp:  # noqa: S310
        text = resp.read().decode("utf-8", errors="replace")
    return json.loads(text) if text.strip() else {}


def http_get_json(url: str, *, headers: dict[str, str], timeout: float = 30.0) -> dict:
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout) as resp:  # noqa: S310
        text = resp.read().decode("utf-8", errors="replace")
    return json.loads(text) if text.strip() else {}


# ---------- HEC ingest ----------


def fixture_sourcetype(fixture_path: Path, fixture_kind: str) -> tuple[str, str]:
    """Decide which index + sourcetype a fixture file should land in.

    Filename convention: positive_<flavor>.log / negative_<flavor>.log where
    flavor is `dns`, `conn`, or `eve`."""
    flavor = fixture_path.stem.split("_", 1)[1] if "_" in fixture_path.stem else ""
    table = FIXTURE_KIND_TO_SOURCETYPE.get(fixture_kind, {})
    if flavor not in table:
        raise ValueError(
            f"unknown flavor {flavor!r} for fixture {fixture_path.name} "
            f"(expected one of {sorted(table.keys())})"
        )
    return table[flavor]


def hec_event_payload(record: dict, *, sourcetype: str, index: str) -> dict:
    """Build the JSON envelope HEC expects for a single event."""
    payload: dict = {
        "event": record,
        "sourcetype": sourcetype,
        "index": index,
    }
    # Suricata events carry their own ISO timestamp; let HEC parse it from
    # the event. Zeek events carry epoch `ts` — the indexed-extraction +
    # TIME_PREFIX in props.conf handles that, so no explicit time field here.
    if "ts" in record and isinstance(record["ts"], (int, float)):
        payload["time"] = record["ts"]
    return payload


def stream_fixture_to_hec(
    fixture_path: Path,
    *,
    fixture_kind: str,
    hec_url: str,
    hec_token: str,
) -> int:
    """Post every JSON-line in `fixture_path` to Splunk HEC. Returns count."""
    index, sourcetype = fixture_sourcetype(fixture_path, fixture_kind)
    headers = {
        "Authorization": hec_auth_header(hec_token),
        "Content-Type": "application/json",
    }

    sent = 0
    chunks: list[str] = []
    with fixture_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            chunks.append(json.dumps(hec_event_payload(rec, sourcetype=sourcetype, index=index)))
            # HEC accepts batched events — newline-delimited JSON in one POST.
            if len(chunks) >= 100:
                http_post_json(hec_url, body="\n".join(chunks).encode(), headers=headers)
                sent += len(chunks)
                chunks.clear()
    if chunks:
        http_post_json(hec_url, body="\n".join(chunks).encode(), headers=headers)
        sent += len(chunks)
    return sent


# ---------- Saved-search execution ----------


def _saved_search_names() -> list[tuple[str, str, str, str]]:
    """Return [(case_id, case_title, mitre_technique, saved_search_name), ...]
    sorted by mitre_technique. saved_search_name is the [stanza] header from
    the case's savedsearches.conf."""
    if not LOOKUP.exists():
        sys.exit(f"missing {LOOKUP} — run `py scripts/build_app.py` first")
    rows = list(csv.DictReader(LOOKUP.open(newline="", encoding="utf-8")))
    out: list[tuple[str, str, str, str]] = []
    import re

    stanza_re = re.compile(r"^\[(?P<name>[^\]]+)\]\s*$", re.MULTILINE)
    for row in rows:
        case_dir = CASES_DIR / row["case_id"]
        ss_path = case_dir / "detection" / "savedsearches.conf"
        if not ss_path.exists():
            continue
        names = stanza_re.findall(ss_path.read_text(encoding="utf-8"))
        if not names:
            continue
        # First stanza is the canonical saved search for the case.
        out.append((row["case_id"], row["case_title"], row["mitre_technique"], names[0]))
    out.sort(key=lambda r: r[2])  # by technique ID
    return out


def dispatch_saved_search(
    name: str,
    *,
    mgmt_url: str,
    user: str,
    password: str,
    app: str = "detlab",
    earliest: str = "-24h",
    latest: str = "now",
) -> str:
    """POST to /servicesNS/<user>/<app>/saved/searches/<name>/dispatch and
    return the SID."""
    safe_name = urllib.parse.quote(name, safe="")
    url = f"{mgmt_url}/servicesNS/{user}/{app}/saved/searches/{safe_name}/dispatch"
    body = urllib.parse.urlencode(
        {
            "output_mode": "json",
            "dispatch.earliest_time": earliest,
            "dispatch.latest_time": latest,
        }
    ).encode()
    headers = {
        "Authorization": basic_auth_header(user, password),
        "Content-Type": "application/x-www-form-urlencoded",
    }
    resp = http_post_json(url, body=body, headers=headers)
    return resp["sid"]


def wait_for_job(
    sid: str, *, mgmt_url: str, user: str, password: str, timeout: float = 120
) -> dict:
    """Poll the job until isDone=1 or timeout."""
    url = f"{mgmt_url}/services/search/jobs/{sid}?output_mode=json"
    headers = {"Authorization": basic_auth_header(user, password)}
    started = time.monotonic()
    while True:
        meta = http_get_json(url, headers=headers)
        entry = meta["entry"][0]
        if str(entry["content"].get("isDone", "0")) == "1":
            return entry["content"]
        if time.monotonic() - started > timeout:
            raise TimeoutError(f"saved search {sid} did not finish in {timeout}s")
        time.sleep(1.0)


def fetch_results_count(sid: str, *, mgmt_url: str, user: str, password: str) -> int:
    """Return the number of result rows for a finished job."""
    url = f"{mgmt_url}/services/search/jobs/{sid}/results?output_mode=json&count=0"
    headers = {"Authorization": basic_auth_header(user, password)}
    resp = http_get_json(url, headers=headers)
    return len(resp.get("results", []))


# ---------- CLI ----------


def cmd_load(args: argparse.Namespace) -> int:
    if not args.hec_token:
        print("ERROR: HEC token required (--hec-token or SPLUNK_HEC_TOKEN env)", file=sys.stderr)
        return 2

    cases = list(_iter_cases_with_wiring())
    if not cases:
        print(f"no cases found under {CASES_DIR}", file=sys.stderr)
        return 2

    print(f"detlab Splunk demo · loading fixtures from {len(cases)} cases via HEC")
    print(f"  target: {args.hec_url}")
    print()
    total = 0
    for _case_id, fixture_kind, technique, fixtures in cases:
        for path in fixtures:
            sent = stream_fixture_to_hec(
                path,
                fixture_kind=fixture_kind,
                hec_url=args.hec_url,
                hec_token=args.hec_token,
            )
            print(f"  {technique:>10s}  {path.relative_to(ROOT)}  → {sent} events")
            total += sent
    print()
    print(f"✓ {total} events posted to Splunk")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    saves = _saved_search_names()
    if not saves:
        print("no saved searches found — run `py scripts/build_app.py` first", file=sys.stderr)
        return 2

    print(f"detlab Splunk demo · running {len(saves)} saved searches")
    print(f"  target: {args.mgmt_url}")
    print()

    fired = 0
    total_alerts = 0
    width = max(len(name) for _id, _t, _tech, name in saves)
    for _case_id, _title, technique, ss_name in saves:
        try:
            sid = dispatch_saved_search(
                ss_name,
                mgmt_url=args.mgmt_url,
                user=args.user,
                password=args.password,
                earliest=args.earliest,
                latest=args.latest,
            )
            wait_for_job(sid, mgmt_url=args.mgmt_url, user=args.user, password=args.password)
            n = fetch_results_count(
                sid, mgmt_url=args.mgmt_url, user=args.user, password=args.password
            )
        except urllib.error.HTTPError as e:
            print(f"  ✗ {ss_name:<{width}}  HTTP {e.code} — {e.reason}", file=sys.stderr)
            continue
        flag = "✓" if n >= 1 else "·"
        if n >= 1:
            fired += 1
            total_alerts += n
        print(
            f"  {flag} {ss_name:<{width}}  {n} alert{'s' if n != 1 else ''} ({technique})"
        )
    print()
    print(f"✓ {fired}/{len(saves)} fired   ·   total alerts: {total_alerts}")
    print("  Open dashboards: http://localhost:8000/en-US/app/detlab/overview")
    return 0


def cmd_all(args: argparse.Namespace) -> int:
    rc = cmd_load(args)
    if rc != 0:
        return rc
    print("\nWaiting 5s for Splunk to index the fresh events…\n")
    time.sleep(5)
    return cmd_run(args)


def _iter_cases_with_wiring() -> Iterable[tuple[str, str, str, list[Path]]]:
    """Yield (case_id, fixture_kind, mitre_technique, [fixture_paths]) tuples
    for every shipped case. fixture_kind comes from CASE_WIRING in
    build_web_data.py — that's the canonical source for fixture format."""
    sys.path.insert(0, str(ROOT / "scripts"))
    import build_web_data  # noqa: E402
    if not LOOKUP.exists():
        sys.exit(f"missing {LOOKUP} — run `py scripts/build_app.py` first")
    rows = list(csv.DictReader(LOOKUP.open(newline="", encoding="utf-8")))
    for row in rows:
        case_id = row["case_id"]
        wiring = build_web_data.CASE_WIRING.get(case_id, {})
        kind = wiring.get("fixture_kind") or "zeek_json"
        tech = row["mitre_technique"]
        fixtures = sorted((CASES_DIR / case_id / "tests").glob("positive_*.log"))
        if fixtures:
            yield case_id, kind, tech, fixtures


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Drive the lab Splunk to demo detlab end-to-end.")
    p.add_argument(
        "--hec-url",
        default=os.environ.get("SPLUNK_HEC_URL", DEFAULT_HEC_URL),
        help="HEC endpoint URL (default: %(default)s)",
    )
    p.add_argument(
        "--hec-token",
        default=os.environ.get("SPLUNK_HEC_TOKEN", ""),
        help="HEC token (default: $SPLUNK_HEC_TOKEN)",
    )
    p.add_argument(
        "--mgmt-url",
        default=os.environ.get("SPLUNK_MGMT_URL", DEFAULT_MGMT_URL),
        help="Splunk management URL (default: %(default)s)",
    )
    p.add_argument(
        "--user",
        default=os.environ.get("SPLUNK_USER", DEFAULT_USER),
        help="Splunk admin user (default: %(default)s)",
    )
    p.add_argument(
        "--password",
        default=os.environ.get("SPLUNK_PASSWORD", DEFAULT_PASSWORD),
        help="Splunk admin password (default from lab/docker-compose.yml)",
    )
    p.add_argument(
        "--earliest", default="-24h", help="Saved-search earliest time (default: %(default)s)"
    )
    p.add_argument(
        "--latest", default="now", help="Saved-search latest time (default: %(default)s)"
    )

    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("load", help="Post every positive fixture to Splunk via HEC")
    sub.add_parser("run", help="Fire every shipped saved search via REST")
    sub.add_parser("all", help="load + run in sequence")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "load":
        return cmd_load(args)
    if args.cmd == "run":
        return cmd_run(args)
    if args.cmd == "all":
        return cmd_all(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
