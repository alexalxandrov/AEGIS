#!/usr/bin/env python3
"""SQLite persistence and honest startup progress reporting for NOMAD."""
from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

Progress = Callable[[dict[str, Any]], None]


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class SQLiteStorage:
    """A normal SQLite database readable by SQLiteStudio, DB Browser and Python."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._connection: sqlite3.Connection | None = None
        self._lock = threading.RLock()
        self.last_error: str | None = None

    def _report(
        self, callback: Progress, stage: str, message: str,
        completed: int | None = None, total: int | None = None,
        current: str | None = None, unit: str | None = None,
    ) -> None:
        callback({
            "stage": stage, "message": message, "completed": completed,
            "total": total, "current": current, "unit": unit,
            "updated_at": _utcnow(),
        })

    def _connect(self) -> sqlite3.Connection:
        if self._connection is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self.path), timeout=15.0, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=15000")
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            self._connection = conn
        return self._connection

    def _create_schema(self) -> None:
        conn = self._connect()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS entities (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                label TEXT NOT NULL,
                first_seen TEXT,
                last_seen TEXT,
                updated_at TEXT,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS routes (
                id TEXT PRIMARY KEY,
                observed_at TEXT,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS observations (
                id TEXT PRIMARY KEY,
                time TEXT,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                time TEXT,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS active_results (
                id TEXT PRIMARY KEY,
                time TEXT,
                method TEXT,
                target TEXT,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS file_hashes (
                path TEXT PRIMARY KEY,
                sha256 TEXT NOT NULL,
                size INTEGER NOT NULL,
                checked_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_entities_kind ON entities(kind);
            CREATE INDEX IF NOT EXISTS idx_observations_time ON observations(time);
            CREATE INDEX IF NOT EXISTS idx_events_time ON events(time);
            CREATE INDEX IF NOT EXISTS idx_active_results_time ON active_results(time);
        """)
        conn.commit()

    def initialize(self, root: Path, callback: Progress) -> dict[str, Any]:
        """Open DB, hash project files, run SQLite integrity_check and restore state."""
        with self._lock:
            self._report(callback, "database", "Открытие SQLite и проверка схемы", 0, 1)
            conn = self._connect()
            self._create_schema()
            self._report(callback, "database", "SQLite открыта; схема проверена", 1, 1)

            hash_report = self._hash_project_files(Path(root), callback)

            integrity_steps = 0
            def vm_progress() -> int:
                nonlocal integrity_steps
                integrity_steps += 10000
                self._report(
                    callback, "integrity",
                    f"SQLite integrity_check выполняется · обработано VM-инструкций: {integrity_steps:,}",
                    integrity_steps, None, str(self.path), "vm_instructions",
                )
                return 0

            self._report(callback, "integrity", "Проверка страниц и связности SQLite (integrity_check)", 0, None, str(self.path), "vm_instructions")
            conn.set_progress_handler(vm_progress, 10000)
            try:
                integrity_rows = [str(row[0]) for row in conn.execute("PRAGMA integrity_check").fetchall()]
            finally:
                conn.set_progress_handler(None, 0)
            integrity_ok = integrity_rows == ["ok"]
            self._report(
                callback, "integrity",
                "SQLite integrity_check завершена: " + ("OK" if integrity_ok else "обнаружены ошибки"),
                integrity_steps, None, str(self.path), "vm_instructions",
            )
            if not integrity_ok:
                raise RuntimeError("SQLite integrity_check failed: " + "; ".join(integrity_rows[:12]))

            restored = self._restore_records(callback)
            db_size = self.path.stat().st_size if self.path.exists() else 0
            counts = self._counts()
            return {
                **restored,
                "integrity": {"ok": integrity_ok, "details": integrity_rows, "vm_instructions": integrity_steps},
                "hashes": hash_report,
                "counts": counts,
                "db_path": str(self.path.resolve()),
                "db_size_bytes": db_size,
            }

    def _hash_project_files(self, root: Path, callback: Progress) -> dict[str, Any]:
        names = (
            "start.py", "storage.py", "index.html", "config.json",
            "requirements.txt", "selftest.py", "README.md",
            ".github/workflows/package.yml",
        )
        files = [(name, root / name) for name in names if (root / name).is_file()]
        total_bytes = sum(path.stat().st_size for _, path in files)
        done_bytes = 0
        conn = self._connect()
        previous = {row["path"]: row["sha256"] for row in conn.execute("SELECT path, sha256 FROM file_hashes")}
        current: dict[str, tuple[str, int]] = {}
        changed: list[str] = []
        new_files: list[str] = []
        self._report(callback, "file_hash", "SHA-256: проверка файлов приложения", 0, total_bytes, None, "bytes")
        for name, path in files:
            digest = hashlib.sha256()
            size = 0
            with path.open("rb") as stream:
                while True:
                    block = stream.read(1024 * 1024)
                    if not block:
                        break
                    digest.update(block)
                    size += len(block)
                    done_bytes += len(block)
                    self._report(callback, "file_hash", f"SHA-256: {name}", done_bytes, total_bytes, name, "bytes")
            value = digest.hexdigest()
            current[name] = (value, size)
            if name not in previous:
                new_files.append(name)
            elif previous[name] != value:
                changed.append(name)

        missing = sorted(set(previous) - set(current))
        checked_at = _utcnow()
        with conn:
            for name, (digest, size) in current.items():
                conn.execute(
                    """INSERT INTO file_hashes(path, sha256, size, checked_at) VALUES(?,?,?,?)
                       ON CONFLICT(path) DO UPDATE SET sha256=excluded.sha256,
                       size=excluded.size, checked_at=excluded.checked_at""",
                    (name, digest, size, checked_at),
                )
        self._report(callback, "file_hash", "SHA-256: все доступные файлы проверены", total_bytes, total_bytes, None, "bytes")
        return {
            "files_checked": len(files), "bytes_checked": done_bytes,
            "changed": changed, "new": new_files, "missing": missing,
            "baseline_established": not bool(previous),
            "note": "SHA-256 сравнивается с предыдущим локальным запуском; это контроль изменений, а не цифровая подпись доверенного издателя.",
        }

    def _restore_records(self, callback: Progress) -> dict[str, Any]:
        conn = self._connect()
        specifications = (
            ("entities", "SELECT * FROM entities ORDER BY rowid", None),
            ("routes", "SELECT * FROM routes ORDER BY rowid", None),
            ("observations", "SELECT * FROM observations ORDER BY rowid DESC", 300),
            ("events", "SELECT * FROM events ORDER BY rowid DESC", 350),
            ("active_results", "SELECT * FROM active_results ORDER BY rowid DESC", 100),
        )
        totals: dict[str, int] = {}
        for table, _, limit in specifications:
            count = int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            totals[table] = min(count, limit) if limit is not None else count
        total_records = sum(totals.values())
        completed = 0
        restored: dict[str, Any] = {
            "entities": {}, "routes": {}, "observations": [], "events": [], "active_results": [],
        }
        self._report(callback, "restore", "Чтение и восстановление записей из SQLite", 0, total_records, None, "records")
        for table, base_query, _ in specifications:
            count = totals[table]
            offset = 0
            while offset < count:
                query = base_query + " LIMIT 250 OFFSET ?"
                rows = conn.execute(query, (offset,)).fetchall()
                if not rows:
                    break
                for row in rows:
                    try:
                        item = json.loads(row["payload"])
                    except (TypeError, json.JSONDecodeError) as exc:
                        raise RuntimeError(f"SQLite content check failed: invalid JSON in {table} row {row['id']}") from exc
                    if not isinstance(item, dict):
                        raise RuntimeError(f"SQLite content check failed: {table} row {row['id']} is not a JSON object")
                    payload_id = item.get("id")
                    if payload_id is not None and str(payload_id) != str(row["id"]):
                        raise RuntimeError(f"SQLite content check failed: {table} row key does not match payload id {payload_id}")
                    if table == "entities":
                        restored["entities"][str(row["id"])] = item
                    elif table == "routes":
                        restored["routes"][str(row["id"])] = item
                    else:
                        restored[table].append(item)
                offset += len(rows)
                completed += len(rows)
                self._report(callback, "restore", f"Проверка содержимого и чтение SQLite: {table}", completed, total_records, table, "records")
        self._report(callback, "restore", "Содержимое SQLite проверено; записи восстановлены", total_records, total_records, None, "records")
        restored["content_check"] = {
            "ok": True, "validated_records": completed,
            "tables": {name: value for name, value in totals.items()},
            "note": "Каждый сохранённый payload декодирован как JSON-объект; идентификаторы строк сверены с идентификаторами payload.",
        }
        return restored

    def _counts(self) -> dict[str, int]:
        conn = self._connect()
        return {
            table: int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in ("entities", "routes", "observations", "events", "active_results")
        }

    def summary(self) -> dict[str, Any]:
        # Never make /api/status wait behind startup hashing, restore or integrity_check.
        if not self._lock.acquire(blocking=False):
            return {"ready": False, "initializing": True, "path": str(self.path)}
        try:
            if self._connection is None:
                return {"ready": False, "path": str(self.path)}
            return {
                "ready": True, "path": str(self.path.resolve()),
                "size_bytes": self.path.stat().st_size if self.path.exists() else 0,
                "counts": self._counts(),
                "journal_mode": str(self._connect().execute("PRAGMA journal_mode").fetchone()[0]).upper(),
                "integrity": "OK",
                "last_error": self.last_error,
            }
        finally:
            self._lock.release()

    def _write(self, sql: str, values: tuple[Any, ...]) -> None:
        with self._lock:
            if self._connection is None:
                return
            try:
                with self._connection:
                    self._connection.execute(sql, values)
            except Exception as exc:
                self.last_error = f"{type(exc).__name__}: {exc}"
                logging.exception("NOMAD SQLite write failed")

    @staticmethod
    def _json(item: dict[str, Any]) -> str:
        return json.dumps(item, ensure_ascii=False, separators=(",", ":"), default=str)

    def save_entity(self, item: dict[str, Any]) -> None:
        self._write(
            """INSERT INTO entities(id,kind,label,first_seen,last_seen,updated_at,payload)
               VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
               kind=excluded.kind,label=excluded.label,first_seen=excluded.first_seen,
               last_seen=excluded.last_seen,updated_at=excluded.updated_at,payload=excluded.payload""",
            (str(item["id"]), str(item.get("kind", "unknown")), str(item.get("label", "")),
             item.get("first_seen"), item.get("last_seen"), item.get("updated_at"), self._json(item)),
        )

    def save_route(self, item: dict[str, Any]) -> None:
        self._write(
            """INSERT INTO routes(id,observed_at,payload) VALUES(?,?,?)
               ON CONFLICT(id) DO UPDATE SET observed_at=excluded.observed_at,payload=excluded.payload""",
            (str(item["id"]), item.get("observed_at"), self._json(item)),
        )

    def save_observation(self, item: dict[str, Any]) -> None:
        self._write(
            "INSERT OR REPLACE INTO observations(id,time,payload) VALUES(?,?,?)",
            (str(item["id"]), item.get("time"), self._json(item)),
        )

    def save_event(self, item: dict[str, Any]) -> None:
        self._write(
            "INSERT OR REPLACE INTO events(id,time,payload) VALUES(?,?,?)",
            (str(item["id"]), item.get("time"), self._json(item)),
        )

    def save_active_result(self, item: dict[str, Any]) -> None:
        self._write(
            "INSERT OR REPLACE INTO active_results(id,time,method,target,payload) VALUES(?,?,?,?,?)",
            (str(item["id"]), item.get("time"), item.get("method"), item.get("target"), self._json(item)),
        )

    def backup(self, destination: Path) -> Path:
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            source = self._connect()
            target = sqlite3.connect(str(destination))
            try:
                source.backup(target)
            finally:
                target.close()
        return destination

    def close(self) -> None:
        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None
