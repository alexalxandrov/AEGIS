"""Tests for task claiming with ``run_id`` filtering.

These tests verify that tasks can be enqueued with an optional ``run_id`` and
that :func:`aegis.db.claim` respects this field when claiming.

The semantics are:

* When ``run_id`` is ``None`` (default), only tasks that are **not** bound to a
  run (``run_id IS NULL``) are returned.
* When a specific ``run_id`` is supplied, tasks that belong to that run or that are
  unassigned are returned.
* A task that has a ``run_id`` different from the one requested will not be
  claimed.

The test creates two tasks – one bound to a run and one unassigned – and then
asserts that claiming behaves as expected.
"""

from __future__ import annotations

import unittest

from aegis import db


class TestTaskRunId(unittest.TestCase):
    def setUp(self) -> None:
        # Use an in‑memory SQLite database for isolation.
        self.c = db.connect(":memory:")

    def tearDown(self) -> None:
        self.c.close()

    def test_claim_with_run_id_filter(self) -> None:
        # Enqueue two tasks: one tied to run_id=1 and one unassigned.
        task1_id = db.enqueue(self.c, "task1", {"x": 1}, run_after=0, run_id=1)
        task2_id = db.enqueue(self.c, "task2", {"y": 2}, run_after=0)

        # Claim with run_id=2 should return the unassigned task.
        claimed = db.claim(self.c, run_id=2)
        self.assertIsNotNone(claimed)
        self.assertEqual(claimed["id"], task2_id)
        self.assertEqual(claimed["kind"], "task2")

        # Claim again with run_id=2 should now return None (no more unassigned tasks).
        self.assertIsNone(db.claim(self.c, run_id=2))

        # Claim with run_id=1 should return the task bound to run 1.
        claimed = db.claim(self.c, run_id=1)
        self.assertIsNotNone(claimed)
        self.assertEqual(claimed["id"], task1_id)
        self.assertEqual(claimed["kind"], "task1")

        # Claim with run_id=1 again should return None.
        self.assertIsNone(db.claim(self.c, run_id=1))

        # Finally, claim with no run_id should find no queued tasks.
        self.assertIsNone(db.claim(self.c))


if __name__ == "__main__":
    unittest.main()