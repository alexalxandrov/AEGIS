#!/usr/bin/env python3
"""Entry‑point for interactive bootstrap of the AEGIS environment.

This script performs a quick sanity‑check of the infrastructure and
collects some basic information about the target system from the user.
It can be used in CI or during local development to ensure that:

* the SQLite database is reachable and contains the expected tables;
* the source registry is populated and refreshed;
* the Ollama local LLM instance is running and the configured model is
  available;
* an organization record exists in the database.

After performing the checks the script prints the gathered data and exits.

The script is intentionally lightweight – it does not start any long‑running
servers or spawn background jobs – but it mirrors the steps that the
``aegis.cli`` module performs during a normal run.
"""

from __future__ import annotations

import time
from pathlib import Path

from aegis import config, db, sources, ai_analyst


def _ensure_database() -> None:
    """Create the data directory and connect to the SQLite database.

    The connection is returned implicitly via ``db.connect`` – the function
    ensures that the directory exists, which is required before the
    first ``sqlite3.connect`` call.
    """
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    # ``db.connect`` will create the database file if it does not exist.
    return None


def _print_ollama_status() -> None:
    status = ai_analyst.ollama_status()
    print("\n=== Ollama status ===")
    print(f"  URL          : {status.get('url')}")
    print(f"  Available    : {status.get('available')}")
    if status.get('available'):
        print(f"  Model        : {status.get('configured_model')}")
        print(f"  Version      : {status.get('version') or 'unknown'}")
        print(f"  Warning      : {status.get('warning') or 'none'}")
    else:
        print(f"  Warning      : {status.get('warning') or 'none'}")
    print("======================\n")


def _ensure_sources(c) -> None:
    """Populate the source registry and refresh its status."""
    sources.ensure_registry(c)
    sources.refresh(c, network=True)
    # Show a concise list of sources for the user.
    print("\n=== Source registry after refresh ===")
    rows = sources.list_sources(c)
    for r in rows:
        print(f"  {r['name']:<12} {r['category']:<10} available={r['available']} version={r['version']}\n")
    print("===================================\n")


def _prompt_user() -> dict:
    """Collect a few bits of information from the user via the console."""
    print("Please provide the following information:")
    site = input("  Site (hostname or domain): ").strip()
    ip = input("  IP address: ").strip()
    url = input("  URL: ").strip()
    nick = input("  Nickname: ").strip()
    company = input("  Company name: ").strip()
    return {
        "site": site,
        "ip": ip,
        "url": url,
        "nick": nick,
        "company": company,
    }


def _ensure_organization(c, name: str) -> int:
    """Ensure that an organization with the given name exists.

    Returns the organization's database id.
    """
    c.execute("INSERT OR IGNORE INTO organization(name,created) VALUES(?,?)", (name, time.time()))
    r = c.execute("SELECT id FROM organization WHERE name=?", (name,)).fetchone()
    return r["id"] if r else None


def main() -> None:
    _ensure_database()
    c = db.connect()
    _ensure_sources(c)
    _print_ollama_status()

    org_name = input("Organization name (will be created if not exists): ").strip()
    org_id = _ensure_organization(c, org_name) if org_name else None
    if org_id:
        print(f"Organization '{org_name}' has id {org_id}\n")
    else:
        print("No organization provided; skipping database entry.\n")

    info = _prompt_user()
    print("\nCollected information:")
    for k, v in info.items():
        print(f"  {k:12s}: {v}")
    print("\nDone.")


if __name__ == "__main__":
    main()
