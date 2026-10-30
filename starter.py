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
import subprocess
import shutil
import os
from pathlib import Path
from typing import Any, Optional

import time

from aegis import config, db, sources, ai_analyst
# Network scan utilities removed per user request
import xml.etree.ElementTree as ET
import json

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
# Network scan helpers
# ---------------------------------------------------------------------------

def run_network_scan(target: str) -> list[dict]:
    """Perform a simple port/service scan against *target*.

    The function prefers ``naabu`` for its fast JSON output; if it is not
    available it falls back to ``nmap`` using XML output.

    It returns a list of dictionaries with keys ``target``, ``port``, ``state``
    and ``service``.  The list can be written to CSV/JSON by the caller.
    """
    # Determine which scanner to use.
    scanner = None
    if shutil.which("naabu"):
        scanner = "naabu"
    elif shutil.which("nmap"):
        scanner = "nmap"
    else:
        raise RuntimeError("Neither naabu nor nmap is installed – please install one to enable network scanning.")

    # Build the command based on the selected scanner.
    if scanner == "naabu":
        # Use JSON lines output with the ``-j`` flag. ``-j`` writes JSON
        # lines to stdout, which we capture and then parse.
        cmd = ["naabu", "-host", target, "-j", "-"]
    else:  # scanner == "nmap"
        cmd = ["nmap", "-oX", "-", target]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        # Provide more context when a scan fails – include stderr and returncode.
        print("[DEBUG] naabu command output:")
        print("stdout:\n", result.stdout)
        print("stderr:\n", result.stderr)
        raise RuntimeError(f"Network scan failed (rc={result.returncode}): {result.stderr.strip()}")

    scans: list[dict] = []
    if scanner == "naabu":
        # naabu output is a JSON array of objects
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse naabu JSON output: {e}")
        for entry in data:
            scans.append(
                {
                    "target": target,
                    "port": entry.get("port"),
                    "state": entry.get("status"),
                    "service": entry.get("service", ""),
                }
            )
    else:  # nmap
        root = ET.fromstring(result.stdout)
        for host in root.findall("./host"):
            for port in host.findall("./ports/port"):
                portid = port.get("portid")
                state = port.find("state").get("state") if port.find("state") is not None else "unknown"
                service_elem = port.find("service")
                svc_name = service_elem.get("name") if service_elem is not None else ""
                scans.append(
                    {
                        "target": target,
                        "port": portid,
                        "state": state,
                        "service": svc_name,
                    }
                )
    return scans


def write_network_summary(workspace: Path, scans: list[dict]) -> None:
    """Write a compact JSON summary of network scan results.

    The summary maps each target to a list of discovered services.
    It is written to ``workspace/network_scan.json``.
    """
    summary: dict[str, list[dict]] = {}
    for entry in scans:
        target = entry.get("target")
        if not target:
            continue
        summary.setdefault(target, []).append(
            {
                "port": entry.get("port"),
                "state": entry.get("state"),
                "service": entry.get("service"),
            }
        )
    json_path = workspace / "network_scan.json"
    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump(summary, jf, indent=2)


def write_scan_results(workspace: Path, scans: list[dict]) -> None:
    """Persist *scans* to CSV and JSON inside *workspace*.

    The CSV has columns: target, port, state, service.  The JSON is a list of the
    dictionaries.
    """
    csv_path = workspace / "scan_results.csv"
    json_path = workspace / "scan_results.json"
    # Write CSV
    with open(csv_path, "w", encoding="utf-8") as f:
        f.write("target,port,state,service\n")
        for entry in scans:
            f.write(
                f"{entry['target']},{entry['port']},{entry['state']},{entry['service']}\n"
            )
    # Write JSON
    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump(scans, jf, indent=2)

parser = argparse.ArgumentParser(description="Bootstrap AEGIS environment")
# Organization flag is optional.  If omitted, the script will create/use a
# default organization named "default".  This change keeps backward
# compatibility for existing callers that explicitly provide an org.
parser.add_argument("--org", help="Organization name or ID", default="default")
parser.add_argument("target", help="Target IP, hostname or URL")
parser.add_argument("--limit", type=int, help="Maximum number of assets to scan")
parser.add_argument("--no-wayback", action="store_true", help="Skip Wayback Machine queries")
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
    # ---------------------------------------------------------------------
    # Ensure the tool directory (tmp/bin) is in PATH so that the required
    # binaries are found by ``shutil.which`` in ``check_required_tools``.
    # ---------------------------------------------------------------------
    # The original code inserted a ``tmp/bin`` directory into ``PATH`` to
    # locate bundled binaries.  However, the binaries shipped in that
    # directory are not compatible with macOS and cause the scan tools to
    # exit with a non‑zero status.  Removing the PATH modification lets
    # the system locate the native binaries installed via Homebrew or
    # elsewhere.
    # Extract target early for workspace naming
    target = args.target
    # Clean up any previous scan directories that may still exist in the script directory
    script_dir = Path(__file__).parent
    cleanup_cmd = f"find {script_dir} -maxdepth 1 -type d -name 'scan-*' -exec rm -rf {{}} +"
    import subprocess
    subprocess.run(cleanup_cmd, shell=True, check=False)
    # Determine workspace directory
    workspace = Path(args.output_dir) if args.output_dir else Path("output_" + time.strftime("%Y%m%d_%H%M%S"))
    # Ensure workspace and logs directories exist
    workspace.mkdir(exist_ok=True)
    logs_dir = workspace / "logs"
    logs_dir.mkdir(exist_ok=True)
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
        """Redirect stdout/stderr to log files *and* keep console output.

        In earlier versions the output was redirected to log files only.
        For the current requirement, console output must always be visible.
        This is achieved by wrapping the file handles in a *tee* that writes to
        both the original stream and the log file.
        """
        logs_dir = workspace / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
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

    _redirect_logs()

    # Database and sources
    _ensure_database()
    c = db.connect()
    # ---------------------------------------------------------------------
    # Always ensure required networking tools are present, because we now
    # perform a network scan unconditionally.
    # ---------------------------------------------------------------------
    # Skipped tool requirement checks as network scan functionality has been removed.
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

    # Run a lightweight scan (seed scan)
    try:
        from aegis import runner
        print("\nRunning initial seed scan (may take a few seconds)...")
        runner.run_org(
            c,
            args.org,
            limit=args.limit,
            brute=False,
            wb=not args.no_wayback,
        )
    except Exception as e:  # pragma: no cover – scan errors are user‑visible
        print("Error during seed scan:", e)

    # --- Full network reconnaissance -----------------------------------
    print("\nЗапускаю полную сетевую разведку…")
    try:
        from aegis.tentacles.network_scan import run_network_scan
        net_results = run_network_scan(args.target, timeout=120)
    except Exception as e:
        print("Не удалось выполнить сетевой скан: ", e)
        net_results = []

    # Persist scan results to the scan directory for later analysis
    net_log_path = workspace / f"network_scan.log"
    with open(net_log_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(net_results, indent=2, ensure_ascii=False))
    print(f"Полные результаты сети записаны в {net_log_path}")
    # Выводим содержимое логов в терминал для удобства
    try:
        with open(net_log_path, "r", encoding="utf-8") as f:
            print("\n=== Содержимое network_scan.log ===")
            print(f.read())
            print("=== Конец логов ===\n")
    except Exception as e:
        print("Ошибка чтения network_scan.log для вывода в терминал:", e)

    # --- AI summarization (always pass network results) -----------------------------------
    status = ai_analyst.ollama_status()
    if status.get("available") and status.get("preferred_present"):
        print("\nПередаю результаты скана в ИИ для анализа…")
        # Формируем вопрос с включением результатов
        net_summary = "\n".join(
            [f"{r['port']} {r['state']} {r.get('service', '')}" for r in net_results]
        )
        question = f"Проведи анализ сетевого скана {args.target}. Результаты:\n{net_summary}\nДай рекомендации по дальнейшим действиям."
        ai_response = ai_analyst.ask(c, org_id, question)
        print("AI ответ:", ai_response.get("answer"))
    else:
        print("Ollama не доступен; пропускаю AI анализ.")

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
        # Write JSON representation
        json_path = workspace / "results.json"
        with open(json_path, "w", encoding="utf-8") as jf:
            json.dump([dict(zip(columns, row)) for row in rows], jf, indent=2)
        print(f"JSON results written to {json_path}")
    except Exception as e:  # pragma: no cover – exporting errors are user‑visible
        print("Error writing results:", e)

    # Demo AI ask – only if LLM is available.
    # The original quick‑summary block is omitted to avoid duplicate AI calls.

    print("\nDone.")
    # ---------------------------------------------------------------------------
    # Automatically launch the FastAPI web server after the starter finishes.
    # ---------------------------------------------------------------------------
    # The server is useful for local debugging and mirrors the behaviour of the
    # legacy `aegis serve` command.  Importing `uvicorn` and `create_app` is
    # wrapped in a try/except so that the starter can still be imported in
    # test environments where those optional dependencies may be missing.
    try:
        from aegis.api import create_app
        import uvicorn

        app = create_app()
        # Default host/port are the same as the CLI serve command.
        print("\nStarting local API server on http://0.0.0.0:8000")
        uvicorn.run(app, host="0.0.0.0", port=8000)
    except Exception as exc:  # pragma: no cover - guard against missing deps
        print("Could not start web server: {}".format(exc))


if __name__ == "__main__":
    main(parser.parse_args())
