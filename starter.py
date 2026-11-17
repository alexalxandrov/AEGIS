#!/usr/bin/env python3
"""Simplified starter script for AEGIS testing environment.

This file provides minimal helper functions used by the test suite:
- _ensure_database: creates the database directory and file.
- _ensure_organization: ensures an organization exists.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import aegis.config as config
import aegis.db as db

def _ensure_database() -> None:
    """Create the data directory and ensure the SQLite database exists."""
    data_dir = Path(os.environ.get("AEGIS_DATA", config.DATA_DIR))
    data_dir.mkdir(parents=True, exist_ok=True)
    # The db.connect function will create the database file and tables if needed.
    db.connect()

def _ensure_organization(name: str) -> int:
    """Ensure an organization with the given name exists and return its id."""
    conn = db.connect()
    conn.execute("INSERT OR IGNORE INTO organization(name,created) VALUES(?,?)", (name, time.time()))
    conn.commit()
    cur = conn.execute("SELECT id FROM organization WHERE name=?", (name,))
    row = cur.fetchone()
    return row["id"] if row else None

import argparse
import sys

from aegis import runner
from aegis import store
from aegis.tentacles import ct, dns, email as email_tentacle, web
from aegis import digest

def main(target: str):
    _ensure_database()
    org_id = _ensure_organization("starter_org")
    kind = "domain" if "." in target else "ip"
    store.upsert_asset(db.connect(), org_id, kind, target, scope="VERIFIED")
    def ct_fn(conn, asset):
        return ct.run(conn, asset)
    def dns_fn(conn, asset):
        return dns.run(conn, asset)
    def email_fn(value):
        res = email_tentacle.check(value)
        return {k: str(v) for k, v in res.items()}
    def web_fn(value):
        res = {"http_443": web.probe_https(value), "http_80": web.probe_http(value)}
        return {k: str(v) for k, v in res.items()}
    conn = db.connect()
    stats = runner.run_org(conn, "starter_org", ct_fn=ct_fn, dns_fn=dns_fn, email_fn=email_fn, web_fn=web_fn, brute=True, wb=True)
    print("Scan stats:", stats)
    digest_text = digest.make(conn, 1, hours=48)
    print("\n--- AI Digest ---\n", digest_text)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run a full AEGIS scan against a target")
    parser.add_argument("target", help="IP or domain to scan")
    args = parser.parse_args()
    main(args.target)
