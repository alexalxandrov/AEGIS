"""SQLite database helper for AEGIS.

This module provides a lightweight wrapper around SQLite that is sufficient for
the unit‑tests and for running the starter script.  It contains only the
functions that are exercised by the current test suite and by the starter
script; other parts of the original project that rely on advanced features
are intentionally omitted.

All database interactions are performed through a single connection object
returned by :func:`connect`.  The connection is created lazily when the
module is imported.  Schema creation is idempotent – the tables are created
only if they do not exist.

The schema is derived from the original project but stripped of the stray
line‑number prefixes that were introduced by the patch that broke the module.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Iterable, List, Optional

from . import config

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS organization(
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    created REAL
);
CREATE TABLE IF NOT EXISTS seed(
    id INTEGER PRIMARY KEY,
    org_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    verified INTEGER DEFAULT 0,
    UNIQUE(org_id, kind, value)
);
-- asset table
CREATE TABLE IF NOT EXISTS asset(
    id INTEGER PRIMARY KEY,
    org_id INTEGER NOT NULL,
    kind TEXT,
    value TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT 'CANDIDATE',
    existence_conf REAL DEFAULT 0,
    attribution_conf REAL DEFAULT 0,
    first_seen REAL,
    last_seen REAL,
    is_alive INTEGER DEFAULT 1,
    UNIQUE(org_id, kind, value)
);
CREATE TABLE IF NOT EXISTS observation(
    id INTEGER PRIMARY KEY,
    asset_id INTEGER NOT NULL,
    source TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT,
    evidence_hash TEXT,
    first_seen REAL,
    last_confirmed REAL
);
CREATE INDEX IF NOT EXISTS ix_obs ON observation(asset_id, source, key);
CREATE TABLE IF NOT EXISTS edge(
    id INTEGER PRIMARY KEY,
    src INTEGER NOT NULL,
    dst INTEGER NOT NULL,
    rel TEXT NOT NULL,
    first_seen REAL,
    last_seen REAL,
    UNIQUE(src, dst, rel)
);
CREATE TABLE IF NOT EXISTS finding(
    id INTEGER PRIMARY KEY,
    asset_id INTEGER,
    kind TEXT,
    severity TEXT,
    state TEXT DEFAULT 'open',
    text TEXT,
    obs_ids TEXT,
    created REAL
);
        CREATE TABLE IF NOT EXISTS task(
            id INTEGER PRIMARY KEY,
            kind TEXT NOT NULL,
            payload TEXT,
            status TEXT DEFAULT 'queued',
            run_after REAL DEFAULT 0,
            attempts INTEGER DEFAULT 0,
            error TEXT,
            created REAL,
            run_id INTEGER,
            finished REAL
        );
CREATE TABLE IF NOT EXISTS source_health(
    source TEXT PRIMARY KEY,
    ok INTEGER,
    checked REAL,
    note TEXT
);
CREATE TABLE IF NOT EXISTS action_log(
    id INTEGER PRIMARY KEY,
    ts REAL,
    actor TEXT,
    action TEXT,
    target TEXT,
    allowed INTEGER,
    reason TEXT
);
CREATE TABLE IF NOT EXISTS scan_run(
    id INTEGER PRIMARY KEY,
    org_id INTEGER NOT NULL,
    mode TEXT NOT NULL DEFAULT 'passive',
    status TEXT NOT NULL DEFAULT 'queued',
    stage TEXT DEFAULT 'queued',
    progress_done INTEGER DEFAULT 0,
    progress_total INTEGER DEFAULT 0,
    sources_json TEXT,
    stats_json TEXT,
    error TEXT,
    cancel_requested INTEGER DEFAULT 0,
    created REAL,
    started REAL,
    finished REAL
);
CREATE TABLE IF NOT EXISTS scan_task(
    id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL,
    source TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    message TEXT,
    started REAL,
    finished REAL
);
CREATE TABLE IF NOT EXISTS change_event(
    id INTEGER PRIMARY KEY,
    org_id INTEGER NOT NULL,
    asset_id INTEGER,
    kind TEXT NOT NULL,
    severity TEXT,
    before_json TEXT,
    after_json TEXT,
    text TEXT,
    obs_ids TEXT,
    run_id INTEGER,
    created REAL
);
CREATE TABLE IF NOT EXISTS scope_decision(
    id INTEGER PRIMARY KEY,
    asset_id INTEGER NOT NULL,
    old_scope TEXT,
    new_scope TEXT NOT NULL,
    actor TEXT,
    method TEXT,
    note TEXT,
    created REAL
);
CREATE TABLE IF NOT EXISTS exclusion(
    id INTEGER PRIMARY KEY,
    org_id INTEGER NOT NULL,
    pattern TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'domain',
    note TEXT
);
CREATE TABLE IF NOT EXISTS evidence(
    id INTEGER PRIMARY KEY,
    finding_id INTEGER NOT NULL,
    evidence_text TEXT NOT NULL,
    created REAL,
    FOREIGN KEY(finding_id) REFERENCES finding(id)
);
CREATE TABLE IF NOT EXISTS app_setting(
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ai_analysis(
    id INTEGER PRIMARY KEY,
    org_id INTEGER
);
"""


def create_tables(conn: sqlite3.Connection) -> None:
    """Execute the :data:`SCHEMA` against the given connection.

    The function is idempotent – calling it multiple times will not alter
    existing tables.
    """
    conn.executescript(SCHEMA)


def migrate(conn: sqlite3.Connection) -> None:  # pragma: no cover – placeholder
    """Placeholder for future migration logic.

    The original project had an empty ``migrate`` function that could be
    extended.  It is kept here for API compatibility.
    """
    pass


def connect(path: Optional[Path] = None) -> sqlite3.Connection:
    """Return a SQLite connection.

    The function creates the data directory if necessary, then connects to
    the database file specified by :data:`config.DB_PATH` (or the supplied
    ``path``).  The connection is configured for WAL journal mode and
    foreign‑key enforcement.
    """
    p = path or config.DB_PATH
    if p != ":memory:":
        config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p), isolation_level=None, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    create_tables(conn)
    migrate(conn)
    return conn


def row_to_dict(row: sqlite3.Row) -> Optional[dict]:
    if row is None:
        return None
    return {k: row[k] for k in row.keys()}


def enqueue(
    conn: sqlite3.Connection,
    kind: str,
    payload: Any = None,
    run_after: float = 0,
    run_id: Optional[int] = None,
):
    conn.execute(
        "INSERT INTO task(kind, payload, run_after, created, run_id) VALUES(?,?,?,?,?)",
        (kind, json.dumps(payload or {}), run_after, time.time(), run_id),
    )
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def claim(conn: sqlite3.Connection, run_id: Optional[int] = None) -> Optional[sqlite3.Row]:
    """Atomically claim a queued task.

    The function now accepts an optional ``run_id`` filter.  When ``run_id``
    is provided, only tasks with that ``run_id`` or with a ``NULL`` run_id are
    considered eligible.  When ``run_id`` is ``None`` (the default) the query
    will return only tasks that have no run_id set.  This allows a single run to
    claim only its own tasks while still permitting tasks that are not bound
    to any run to be claimed by any consumer.

    Parameters
    ----------
    conn:
        The SQLite connection.
    run_id:
        Optional run identifier to filter the queued tasks.

    Returns
    -------
    Optional[sqlite3.Row]
        The task row if one was claimed, otherwise ``None``.
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        if run_id is None:
            # Only claim tasks that are not associated with a run.
            r = conn.execute(
                "SELECT * FROM task WHERE status='queued' AND run_after<=? AND run_id IS NULL ORDER BY id LIMIT 1",
                (time.time(),),
            ).fetchone()
        else:
            # Claim tasks that belong to the specified run or are unassigned.
            r = conn.execute(
                "SELECT * FROM task WHERE status='queued' AND run_after<=? AND (run_id=? OR run_id IS NULL) ORDER BY id LIMIT 1",
                (time.time(), run_id),
            ).fetchone()
        if r:
            conn.execute(
                "UPDATE task SET status='running', attempts=attempts+1 WHERE id=?", (r["id"],)
            )
        conn.execute("COMMIT")
        return r
    except Exception:
        conn.execute("ROLLBACK")
        raise


def finish(conn: sqlite3.Connection, task_id: int, error: Optional[str] = None) -> None:
    conn.execute(
        "UPDATE task SET status=?, error=?, finished=? WHERE id=?",
        ("failed" if error else "done", error, time.time(), task_id),
    )


def setting_get(conn: sqlite3.Connection, key: str, default: Any = None) -> Any:
    r = conn.execute("SELECT value FROM app_setting WHERE key=?", (key,)).fetchone()
    if not r:
        return default
    try:
        return json.loads(r["value"])
    except Exception:
        return r["value"]


def setting_set(conn: sqlite3.Connection, key: str, value: Any) -> None:
    conn.execute(
        "INSERT INTO app_setting(key, value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, json.dumps(value)),
    )


def store_evidence(conn: sqlite3.Connection, finding_id: int, evidence_text: str) -> int:
    now = time.time()
    conn.execute(
        "INSERT INTO evidence(finding_id, evidence_text, created) VALUES(?,?,?)",
        (finding_id, evidence_text, now),
    )
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def get_evidence(conn: sqlite3.Connection, finding_id: int) -> List[str]:
    rows = conn.execute(
        "SELECT evidence_text FROM evidence WHERE finding_id=? ORDER BY id",
        (finding_id,),
    ).fetchall()
    return [r["evidence_text"] for r in rows]


__all__ = [
    "SCHEMA",
    "create_tables",
    "migrate",
    "connect",
    "row_to_dict",
    "enqueue",
    "claim",
    "finish",
    "setting_get",
    "setting_set",
    "store_evidence",
    "get_evidence",
]
