"""Evidence persistence helpers.

This module provides a lightweight repository pattern around the raw SQL
functions added to :mod:`aegis.db`.  The functions are intentionally simple
because the rest of the code base uses direct SQLite connections.
"""

from __future__ import annotations

import sqlite3
from typing import List

from . import config, db


class EvidenceRepository:
    """Simple wrapper around :mod:`aegis.db` evidence functions."""

    def __init__(self, connection: sqlite3.Connection | None = None):
        self._conn = connection or db.connect(config.DB_PATH)

    def add(self, finding_id: int, evidence_text: str) -> int:
        return db.store_evidence(self._conn, finding_id, evidence_text)

    def list_for(self, finding_id: int) -> List[str]:
        return db.get_evidence(self._conn, finding_id)
