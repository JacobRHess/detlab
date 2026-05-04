"""Tests for the Zeek loader: file parsing + base-domain extraction."""

from __future__ import annotations

import json
from pathlib import Path

from detlab.zeek_loader import base_domain, leftmost_label, load_zeek_dns


def test_base_domain_simple():
    assert base_domain("www.example.com") == "example.com"


def test_base_domain_deep():
    assert base_domain("a.b.c.d.example.com") == "example.com"


def test_base_domain_two_labels():
    assert base_domain("example.com") == "example.com"


def test_leftmost_label():
    assert leftmost_label("abc.example.com") == "abc"


def test_load_zeek_dns_skips_blank_and_comments(tmp_path: Path):
    log = tmp_path / "dns.log"
    log.write_text(
        "\n"
        "# this is a comment\n"
        + json.dumps({"ts": 1.0, "query": "x.example.com", "qtype_name": "A"})
        + "\n",
        encoding="utf-8",
    )
    records = load_zeek_dns(log)
    assert len(records) == 1
    assert records[0]["query"] == "x.example.com"
