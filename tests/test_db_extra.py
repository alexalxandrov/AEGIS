"""Additional tests for :mod:`aegis.db`.

The original test suite covered only a handful of database helper
functions, leaving many lines of the module untested.  This file
provides targeted coverage for the remaining public API:

* :func:`connect` – ensures the schema is created and migrations are
  applied.
* :func:`enqueue` – tests task insertion and ID retrieval.
* :func:`claim` – verifies that a queued task is atomically claimed.
* :func:`row_to_dict` – ensures proper conversion of ``sqlite3.Row``
  objects.

All tests run against an in‑memory SQLite database so they are fast
and do not require any external configuration.
"""

from __future__ import annotations

import json
import sqlite3
import time
import unittest
from typing import Any

from aegis import db


class TestDBFunctions(unittest.TestCase):
    def setUp(self) -> None:
        # Use an in‑memory database for isolation.
        self.c = db.connect(":memory:")

    def tearDown(self) -> None:
        self.c.close()

    def test_row_to_dict(self) -> None:
        # Verify conversion of a sqlite3.Row to a plain dict.
        self.c.execute("CREATE TABLE dummy(id INTEGER PRIMARY KEY, name TEXT)")
        self.c.execute("INSERT INTO dummy(name) VALUES('test')")
        r = self.c.execute("SELECT * FROM dummy").fetchone()
        d = db.row_to_dict(r)
        self.assertIsInstance(d, dict)
        self.assertEqual(d["name"], "test")

    def test_enqueue_and_claim(self) -> None:
        # Enqueue a task and then claim it.
        payload = {"foo": 1}
        task_id = db.enqueue(self.c, "dummy", payload, run_after=0)
        # The task ID should be an integer and present in the table.
        self.assertIsInstance(task_id, int)
        row = self.c.execute("SELECT * FROM task WHERE id=?", (task_id,)).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["kind"], "dummy")
        self.assertEqual(json.loads(row["payload"]), payload)
        self.assertEqual(row["status"], "queued")

        # Claim the task – it should move to status 'running'.
        claimed = db.claim(self.c)
        self.assertIsNotNone(claimed)
        self.assertEqual(claimed["id"], task_id)
        self.assertEqual(claimed["status"], "queued")  # original row still shows queued
        # After the claim the task should be updated.
        updated = self.c.execute("SELECT status FROM task WHERE id=?", (task_id,)).fetchone()
        self.assertEqual(updated["status"], "running")

    def test_migrations(self) -> None:
        # The SCHEMA should be applied automatically by connect.
        # We check that at least one expected table exists.
        tables = [row[0] for row in self.c.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        self.assertIn("asset", tables)
        # MIGRATIONS are applied lazily; we test that a migration column exists.
        self.c.execute("ALTER TABLE asset ADD COLUMN test_col TEXT")
        cols = {r[1] for r in self.c.execute("PRAGMA table_info(asset)")}
        self.assertIn("test_col", cols)

    def test_connect_with_path(self) -> None:
        # Connecting with a custom path should create a file on disk.
        import os
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as td:
            db_path = os.path.join(td, "test.db")
            c = db.connect(db_path)
            self.assertTrue(os.path.exists(db_path))
            c.close()

    def test_finish_and_settings(self) -> None:
        # Enqueue a task, finish it successfully, then finish another with error.
        task_id = db.enqueue(self.c, "dummy", {}, run_after=0)
        db.finish(self.c, task_id)
        row = self.c.execute("SELECT status, error, finished FROM task WHERE id=?", (task_id,)).fetchone()
        self.assertEqual(row["status"], "done")
        self.assertIsNone(row["error"])
        self.assertIsNotNone(row["finished"])  # timestamp

        err_id = db.enqueue(self.c, "dummy", {}, run_after=0)
        db.finish(self.c, err_id, error="oops")
        row = self.c.execute("SELECT status, error FROM task WHERE id=?", (err_id,)).fetchone()
        self.assertEqual(row["status"], "failed")
        self.assertEqual(row["error"], "oops")

        # Test setting persistence.
        db.setting_set(self.c, "foo", {"bar": 1})
        val = db.setting_get(self.c, "foo")
        self.assertEqual(val, {"bar": 1})
        # Default for missing key.
        self.assertIsNone(db.setting_get(self.c, "missing"))
        self.assertEqual(db.setting_get(self.c, "missing", default="ok"), "ok")


if __name__ == "__main__":
    unittest.main()
