#!/usr/bin/env python3
"""Entry‑point for interactive bootstrap of the AEGIS environment.

The script performs a quick sanity‑check of the infrastructure and
collects some basic information about the target system from the user.
It can be used in CI or during local development to ensure that:

* the SQLite database is reachable and contains the expected tables;
* the source registry is populated and refreshed;
* the Ollama local LLM instance is running and the configured model is
  available;
* an organization record exists in the database.

After performing the checks the script prints the gathered data and exits.
"""

from __future__ import annotations

import argparse
import datetime
import os
import re
import sys
from pathlib import Path
from typing import Any, Optional

import time

from aegis import config, db, sources, ai_analyst

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _ensure_database() -> None:
    """Create the data directory and connect to the SQLite database.

    The connection is returned implicitly via ``db.connect`` – the function
    ensures that the directory exists, which is required before the
    first ``sqlite3.connect`` call.
    """
    data_dir = Path(os.environ.get("AEGIS_DATA", config.DATA_DIR))
    data_dir.mkdir(parents=True, exist_ok=True)
    original_db_path = config.DB_PATH
    config.DB_PATH = data_dir / "aegis.db"
    try:
        _ = db.connect()
    finally:
        config.DB_PATH = original_db_path


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


def _ensure_sources(c: Any) -> None:
    """Populate the source registry and refresh its status."""
    sources.ensure_registry(c)
    # ``sources.refresh`` in the simplified implementation only requires the
    # connection argument.  The original CLI accepted an optional ``network``
    # flag, but the stub implementation ignores it.  We therefore call it
    # without the extra keyword to avoid ``TypeError``.
    sources.refresh(c)
    print("\n=== Source registry after refresh ===")
    rows = sources.list_sources(c)
    for r in rows:
        print(f"  {r['name']:<12} {r['category']:<10} available={r['available']} version={r['version']}\n")
    print("===================================\n")


def _ensure_organization(c: Any, name: str) -> int:
    """Ensure that an organization with the given name exists.

    Returns the organization's database id.
    """
    c.execute("INSERT OR IGNORE INTO organization(name,created) VALUES(?,?)", (name, time.time()))
    r = c.execute("SELECT id FROM organization WHERE name=?", (name,)).fetchone()
    return r["id"] if r else None


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

parser = argparse.ArgumentParser(description="Bootstrap AEGIS environment")
# Organization flag is optional.  If omitted, the script will create/use a
# default organization named "default".  This change keeps backward
# compatibility for existing callers that explicitly provide an org.
parser.add_argument("--org", help="Organization name or ID", default="default")
# Accept a single target argument that can be an IP, hostname or URL.  The
# script will auto‑detect its type.
    # Positional target argument (no explicit 'required' flag – argparse handles it)
parser.add_argument("target", help="Target IP, hostname or URL")
parser.add_argument("--nick", help="Nickname for the target")
parser.add_argument("--company", help="Company name associated with target")
parser.add_argument("--limit", type=int, help="Maximum number of assets to scan")
parser.add_argument("--no-wayback", action="store_true", help="Skip Wayback Machine queries")
parser.add_argument("--verbose", action="store_true", help="Print logs to stdout in addition to log files")
parser.add_argument("--output-dir", help="Custom output directory (default: timestamped run folder)")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main(args: argparse.Namespace) -> None:
    """Execute the bootstrap sequence.

    Parameters
    ----------
    args:
        Parsed command‑line arguments.
    """
    # Extract target early for workspace naming
    target = args.target
    # Clean up any previous scan directories that may still exist in the script directory
    script_dir = Path(__file__).parent
    cleanup_cmd = f"find {script_dir} -maxdepth 1 -type d -name 'scan-*' -exec rm -rf {{}} +"
    import subprocess
    try:
        subprocess.run(cleanup_cmd, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Cleanup failed: {e}")
    # Workspace creation and log redirection
    if args.output_dir:
        workspace = Path(args.output_dir).expanduser().resolve()
    else:
        ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        # Use target value for folder naming; fallback to 'unknown' if parsing fails
        site_clean = target.replace(".", "_") if target else "unknown"
        workspace_name = f"scan-{ts}_{site_clean}"
        workspace = script_dir / workspace_name
    workspace.mkdir(parents=True, exist_ok=True)
    os.environ["AEGIS_DATA"] = str(workspace)
    # Force re‑load config to pick up new data dir
    import importlib
    importlib.reload(config)

    def _redirect_logs() -> None:
        """Redirect stdout/stderr to log files.

        When ``args.verbose`` is set, a *tee* object is used so that output is
        written both to the log file and to the original stdout/stderr.
        """
        logs_dir = workspace / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        if getattr(args, "verbose", False):
            original_stdout = sys.stdout
            original_stderr = sys.stderr
            class Tee:
                def __init__(self, file_obj, orig):
                    self.file_obj = file_obj
                    self.orig = orig
                def write(self, s):
                    self.file_obj.write(s)
                    self.orig.write(s)
                def flush(self):
                    self.file_obj.flush()
                    self.orig.flush()
            sys.stdout = Tee(open(logs_dir / "stdout.log", "w", encoding="utf-8"), original_stdout)
            sys.stderr = Tee(open(logs_dir / "stderr.log", "w", encoding="utf-8"), original_stderr)
        else:
            sys.stdout = open(logs_dir / "stdout.log", "w", encoding="utf-8")
            sys.stderr = open(logs_dir / "stderr.log", "w", encoding="utf-8")

    _redirect_logs()

    # Database and sources
    _ensure_database()
    c = db.connect()
    _ensure_sources(c)
    _print_ollama_status()

    # Organization handling
    org_id = _ensure_organization(c, args.org)
    # Asset seeding – determine the type of the single ``target`` argument
    import urllib.parse
    target = args.target
    parsed = urllib.parse.urlparse(target)
    if parsed.scheme:
        # URL – treat host as domain
        host = parsed.hostname or target
        c.execute(
            "INSERT OR IGNORE INTO seed(org_id,kind,value,verified) VALUES(?,?,?,?)",
            (org_id, "domain", host, 1),
        )
        c.execute(
            "INSERT OR IGNORE INTO asset(org_id,kind,value,scope,first_seen,last_seen) VALUES(?,?,?,?,strftime('%s','now'),strftime('%s','now'))",
            (org_id, "domain", host, "verified"),
        )
    else:
        # Plain host or IP
        # Simple regex to check if it's an IP
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", target):
            kind = "ip"
        else:
            kind = "domain"
        c.execute(
            "INSERT OR IGNORE INTO seed(org_id,kind,value,verified) VALUES(?,?,?,?)",
            (org_id, kind, target, 1),
        )
        c.execute(
            "INSERT OR IGNORE INTO asset(org_id,kind,value,scope,first_seen,last_seen) VALUES(?,?,?,?,strftime('%s','now'),strftime('%s','now'))",
            (org_id, kind, target, "verified" if kind == "domain" else "candidate"),
        )
        # Removed legacy IP seeding block

    # Run a lightweight scan
    try:
        from aegis import runner
        print("\nRunning initial scan (may take a few seconds)...")
        runner.run_org(
            c,
            args.org,
            limit=args.limit,
            brute=False,
            wb=not args.no_wayback,
        )
    except Exception as e:  # pragma: no cover – scan errors are user‑visible
        print("Error during scan:", e)

    # Export assets to a single CSV file per scan for easier consumption
    try:
        csv_path = workspace / "results.csv"
        with open(csv_path, "w", encoding="utf-8") as f:
            cursor = c.execute("SELECT * FROM asset")
            columns = [col[0] for col in cursor.description]
            f.write(",".join(columns) + "\n")
            rows = cursor.fetchall()
            for row in rows:
                f.write(",".join(str(v) for v in row) + "\n")
        print(f"\nAsset results written to {csv_path}")
        # Also print to console for quick review
        for row in rows:
            print(dict(zip(columns, row)))
    except Exception as e:  # pragma: no cover – exporting errors are user‑visible
        print("Error writing results:", e)

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
    main(parser.parse_args())
