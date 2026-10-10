"""SQLite (WAL) + очередь задач. Без docker. Миграции аддитивные — данные не удаляются."""
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
  note TEXT,
  created REAL,
  UNIQUE(org_id, kind, pattern)
);
CREATE TABLE IF NOT EXISTS app_setting(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ai_analysis(
  id INTEGER PRIMARY KEY,
  org_id INTEGER,
  kind TEXT,
  question TEXT,
  answer TEXT,
  cites_json TEXT,
  model TEXT,
  created REAL
);
CREATE TABLE IF NOT EXISTS source_registry(
  name TEXT PRIMARY KEY,
  category TEXT,
  mode TEXT,
  available INTEGER DEFAULT 0,
  version TEXT,
  last_ok REAL,
  last_error TEXT,
  requires_key INTEGER DEFAULT 0,
  license_note TEXT,
  capabilities TEXT,
  meta_json TEXT
);
CREATE TABLE IF NOT EXISTS risk_assessment(
  id INTEGER PRIMARY KEY,
  org_id INTEGER NOT NULL,
  asset_id INTEGER,
  score REAL NOT NULL,
  level TEXT,
  rationale TEXT,
  factors_json TEXT,
  created REAL
);
CREATE INDEX IF NOT EXISTS ix_asset_org ON asset(org_id);
CREATE INDEX IF NOT EXISTS ix_finding_asset ON finding(asset_id);
CREATE INDEX IF NOT EXISTS ix_scan_org ON scan_run(org_id);
CREATE INDEX IF NOT EXISTS ix_change_org ON change_event(org_id);
"""

MIGRATIONS = [
    ("finding", "text", "ALTER TABLE finding ADD COLUMN text TEXT"),
    ("finding", "note", "ALTER TABLE finding ADD COLUMN note TEXT"),
    ("finding", "rationale", "ALTER TABLE finding ADD COLUMN rationale TEXT"),
    ("finding", "recommendation", "ALTER TABLE finding ADD COLUMN recommendation TEXT"),
    ("finding", "is_hypothesis", "ALTER TABLE finding ADD COLUMN is_hypothesis INTEGER DEFAULT 0"),
    ("finding", "first_seen", "ALTER TABLE finding ADD COLUMN first_seen REAL"),
    ("finding", "last_seen", "ALTER TABLE finding ADD COLUMN last_seen REAL"),
    ("observation", "confidence", "ALTER TABLE observation ADD COLUMN confidence REAL DEFAULT 0.8"),
    ("observation", "status", "ALTER TABLE observation ADD COLUMN status TEXT DEFAULT 'confirmed'"),
    ("observation", "raw_ref", "ALTER TABLE observation ADD COLUMN raw_ref TEXT"),
    ("edge", "confidence", "ALTER TABLE edge ADD COLUMN confidence REAL DEFAULT 0.7"),
    ("edge", "evidence_obs", "ALTER TABLE edge ADD COLUMN evidence_obs TEXT"),
    ("seed", "created", "ALTER TABLE seed ADD COLUMN created REAL"),
    ("asset", "criticality", "ALTER TABLE asset ADD COLUMN criticality TEXT DEFAULT 'medium'"),
    ("asset", "verified_by", "ALTER TABLE asset ADD COLUMN verified_by TEXT"),
    ("asset", "verified_at", "ALTER TABLE asset ADD COLUMN verified_at REAL"),
    ("asset", "verified_method", "ALTER TABLE asset ADD COLUMN verified_method TEXT"),
    ("task", "run_id", "ALTER TABLE task ADD COLUMN run_id INTEGER"),
    ("task", "finished", "ALTER TABLE task ADD COLUMN finished REAL"),
    ("scan_run", "message", "ALTER TABLE scan_run ADD COLUMN message TEXT"),
]


def _cols(c, table):
    return {r[1] for r in c.execute(f"PRAGMA table_info({table})")}


def migrate(c):
    for table, col, sql in MIGRATIONS:
        try:
            if col not in _cols(c, table):
                c.execute(sql)
        except sqlite3.OperationalError:
            pass  # table may not exist yet on first boot before SCHEMA


def connect(path=None):
    p = path or config.DB_PATH
    if p != ":memory:":
        config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(p), isolation_level=None, timeout=30, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA foreign_keys=ON")
    c.executescript(SCHEMA)
    migrate(c)
    return c


def row_to_dict(r):
    if r is None:
        return None
    return {k: r[k] for k in r.keys()}


def enqueue(c, kind, payload=None, run_after=0, run_id=None):
    c.execute(
        "INSERT INTO task(kind,payload,run_after,created,run_id) VALUES(?,?,?,?,?)",
        (kind, json.dumps(payload or {}), run_after, time.time(), run_id),
    )
    return c.execute("SELECT last_insert_rowid()").fetchone()[0]


def claim(c):
    """Атомарно берёт одну задачу (аналог SKIP LOCKED)."""
    c.execute("BEGIN IMMEDIATE")
    try:
        r = c.execute(
            "SELECT * FROM task WHERE status='queued' AND run_after<=? ORDER BY id LIMIT 1",
            (time.time(),),
        ).fetchone()
        if r:
            c.execute("UPDATE task SET status='running',attempts=attempts+1 WHERE id=?", (r["id"],))
        c.execute("COMMIT")
        return r
    except Exception:
        c.execute("ROLLBACK")
        raise


def finish(c, task_id, error=None):
    c.execute(
        "UPDATE task SET status=?,error=?,finished=? WHERE id=?",
        ("failed" if error else "done", error, time.time(), task_id),
    )


def setting_get(c, key, default=None):
    r = c.execute("SELECT value FROM app_setting WHERE key=?", (key,)).fetchone()
    if not r:
        return default
    try:
        return json.loads(r["value"])
    except Exception:
        return r["value"]


def setting_set(c, key, value):
    c.execute(
        "INSERT INTO app_setting(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, json.dumps(value)),
    )
