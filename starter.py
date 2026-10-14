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
import datetime
import sys
import os
import argparse

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
    """Parse command‑line arguments, perform sanity checks and launch a short
    analysis pipeline.

    The CLI accepts the same information that was previously collected via
    ``input()``.  All parameters are optional; when omitted the interactive
    prompts will be used.  For CI scenarios you can invoke the script with
    ``--org <name> [--site <site>] [--ip <ip>] [--url <url>] [--nick <nick>]``.
    """
    parser = argparse.ArgumentParser(description="Bootstrap AEGIS for a single org")
    parser.add_argument("--org", help="Organization name (will be created if not exists)")
    parser.add_argument("--site", help="Hostname or domain")
    parser.add_argument("--ip", help="IP address")
    parser.add_argument("--url", help="URL of the target")
    parser.add_argument("--nick", help="Nickname for the target")
    parser.add_argument("--company", help="Company name")
    parser.add_argument("--limit", type=int, default=300, help="Limit number of assets to scan")
    parser.add_argument("--no-wayback", action="store_true", help="Skip Wayback probing")
    parser.add_argument("--output-dir", help="Optional explicit output directory for this run")
    args = parser.parse_args()

    # ----- Create a per‑run workspace -------------------------------------
    # ``starter.py`` is the single entry point that is executed when a user
    # starts a new scan.  We create a dedicated sub‑folder inside the directory
    # that contains ``starter.py``.  The folder name contains the target
    # site/domain and a UTC timestamp so that runs never collide and the
    # artefacts are automatically archived.
    if args.output_dir:
        workspace = Path(args.output_dir).expanduser().resolve()
    else:
        # Default naming convention: scan-<YYYYMMDD_HHMMSS>_<site>
        ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        site_clean = args.site.replace(".", "_") if args.site else "unknown"
        workspace_name = f"scan-{ts}_{site_clean}"
        workspace = Path(__file__).parent / workspace_name
    workspace.mkdir(parents=True, exist_ok=True)

    # Point the global configuration to this new workspace.
    os.environ["AEGIS_DATA"] = str(workspace)
    # Ensure the configuration module reads the new environment variable.
    import importlib
    importlib.reload(config)
    # Ensure that the DB file lives inside the workspace.

    # Redirect stdout/stderr to files inside the workspace.
    def _redirect_logs() -> None:
        logs_dir = workspace / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        sys.stdout = open(logs_dir / "stdout.log", "w", encoding="utf-8")
        sys.stderr = open(logs_dir / "stderr.log", "w", encoding="utf-8")

    _redirect_logs()

    # Ensure the DB directory exists (``db.connect`` will create the file).
    _ensure_database()
    c = db.connect()
    _ensure_sources(c)
    _print_ollama_status()

    # Determine organization name – interactive fallback if not supplied.
    org_name = args.org or input("Organization name (will be created if not exists): ").strip()
    if not org_name:
        print("No organization provided; skipping database entry.")
        org_id = None
    else:
        org_id = _ensure_organization(c, org_name)
        print(f"Organization '{org_name}' has id {org_id}\n")

    # Collect target data.
    info = {
        "site": args.site or input("  Site (hostname or domain): ").strip(),
        "ip": args.ip or input("  IP address: ").strip(),
        "url": args.url or input("  URL: ").strip(),
        "nick": args.nick or input("  Nickname: ").strip(),
        "company": args.company or input("  Company name: ").strip(),
    }
    print("\nCollected information:")
    for k, v in info.items():
        print(f"  {k:12s}: {v}")

    # Insert seed data if the org exists.
    if org_id:
        # Seed domain asset.
        c.execute(
            "INSERT OR IGNORE INTO seed(org_id,kind,value,verified) VALUES(?,?,?,?)",
            (org_id, "domain", info["site"], 1),
        )
        c.execute(
            "INSERT OR IGNORE INTO asset(org_id,kind,value,scope,first_seen,last_seen) VALUES(?,?,?,?,strftime('%s','now'),strftime('%s','now'))",
            (org_id, "domain", info["site"], "verified",),
        )
        # If an IP address was provided, seed it as a candidate asset.
        ip_addr = info.get("ip")
        if ip_addr:
            c.execute(
                "INSERT OR IGNORE INTO asset(org_id,kind,value,scope,first_seen,last_seen) VALUES(?,?,?,?,strftime('%s','now'),strftime('%s','now'))",
                (org_id, "ip", ip_addr, "candidate",),
            )
        # No explicit commit; ``sqlite3`` is in autocommit mode.

    # Run a lightweight scan.
    try:
        from aegis import runner
        print("\nRunning initial scan (may take a few seconds)...")
        runner.run_org(c, org_name, limit=args.limit, brute=False, wb=not args.no_wayback)
    except Exception as e:
        print("Error during scan:", e)

    # Demo AI ask – only if LLM is available.
    status = ai_analyst.ollama_status()
    if status.get("available") and status.get("preferred_present"):
        print("\nAsking AI for a quick summary...")
        answer = ai_analyst.ask(c, org_id, "Summarize findings for this organization.")
        print("AI answer:", answer.get("answer"))
    else:
        print("Ollama not available; skipping AI ask.")

    print("\nDone.")


if __name__ == "__main__":
    main()
