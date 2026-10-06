"""SQLite (WAL) + очередь задач. Без внешних зависимостей, без docker."""
import sqlite3, time, json
from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS organization(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, created REAL);
CREATE TABLE IF NOT EXISTS seed(id INTEGER PRIMARY KEY, org_id INTEGER NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL,
  verified INTEGER DEFAULT 0, UNIQUE(org_id,kind,value));
CREATE TABLE IF NOT EXISTS asset(id INTEGER PRIMARY KEY, org_id INTEGER NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL,
  scope TEXT NOT NULL DEFAULT 'CANDIDATE', existence_conf REAL DEFAULT 0, attribution_conf REAL DEFAULT 0,
  first_seen REAL, last_seen REAL, is_alive INTEGER DEFAULT 1, UNIQUE(org_id,kind,value));
CREATE TABLE IF NOT EXISTS observation(id INTEGER PRIMARY KEY, asset_id INTEGER NOT NULL, source TEXT NOT NULL,
  key TEXT NOT NULL, value TEXT, evidence_hash TEXT, first_seen REAL, last_confirmed REAL);
CREATE INDEX IF NOT EXISTS ix_obs ON observation(asset_id,source,key);
CREATE TABLE IF NOT EXISTS edge(id INTEGER PRIMARY KEY, src INTEGER NOT NULL, dst INTEGER NOT NULL, rel TEXT NOT NULL,
  first_seen REAL, last_seen REAL, UNIQUE(src,dst,rel));
CREATE TABLE IF NOT EXISTS finding(id INTEGER PRIMARY KEY, asset_id INTEGER, kind TEXT, severity TEXT, state TEXT DEFAULT 'open',
  obs_ids TEXT, created REAL);
CREATE TABLE IF NOT EXISTS task(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, payload TEXT, status TEXT DEFAULT 'queued',
  run_after REAL DEFAULT 0, attempts INTEGER DEFAULT 0, error TEXT, created REAL);
CREATE TABLE IF NOT EXISTS source_health(source TEXT PRIMARY KEY, ok INTEGER, checked REAL, note TEXT);
CREATE TABLE IF NOT EXISTS action_log(id INTEGER PRIMARY KEY, ts REAL, actor TEXT, action TEXT, target TEXT, allowed INTEGER, reason TEXT);
"""

def connect(path=None):
    p = path or config.DB_PATH
    if p != ":memory:":
        config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(p), isolation_level=None, timeout=30)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL"); c.execute("PRAGMA foreign_keys=ON")
    c.executescript(SCHEMA)
    return c

def enqueue(c, kind, payload=None, run_after=0):
    c.execute("INSERT INTO task(kind,payload,run_after,created) VALUES(?,?,?,?)",
              (kind, json.dumps(payload or {}), run_after, time.time()))

def claim(c):
    """Атомарно берёт одну задачу (аналог SKIP LOCKED)."""
    c.execute("BEGIN IMMEDIATE")
    try:
        r = c.execute("SELECT * FROM task WHERE status='queued' AND run_after<=? ORDER BY id LIMIT 1", (time.time(),)).fetchone()
        if r:
            c.execute("UPDATE task SET status='running',attempts=attempts+1 WHERE id=?", (r["id"],))
        c.execute("COMMIT")
        return r
    except Exception:
        c.execute("ROLLBACK"); raise

def finish(c, task_id, error=None):
    c.execute("UPDATE task SET status=?,error=? WHERE id=?", ("failed" if error else "done", error, task_id))
