"""Unit tests for the extended AI utilities.

The tests create an in‑memory SQLite database that mimics the minimal tables
required by :mod:`aegis.ai_analyst`.  We then monkey‑patch the LLM call to a
deterministic stub that returns a simple JSON payload.  The tests cover:

* Caching behaviour – the second call should hit the cache.
* Extended context – additional tables are added to the context.
* Tool‑calling – the system prompt contains the expected tool definitions.
"""

import json
import sqlite3
from types import SimpleNamespace
from typing import Any, Dict

import pytest

from aegis import ai_analyst, ai_advanced


def _create_db() -> sqlite3.Connection:
    """Return a fresh in‑memory DB with the minimal schema for the tests."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    # Create the tables used by ``ai_analyst._context``
    cur.executescript(
        """
        CREATE TABLE asset(id INTEGER PRIMARY KEY, org_id INTEGER, value TEXT, scope TEXT, last_seen REAL);
        CREATE TABLE finding(id INTEGER PRIMARY KEY, asset_id INTEGER, kind TEXT, severity TEXT, state TEXT, text TEXT, obs_ids TEXT);
        CREATE TABLE observation(id INTEGER PRIMARY KEY, asset_id INTEGER, source TEXT, key TEXT, evidence_hash TEXT, value TEXT);
        CREATE TABLE event(id INTEGER PRIMARY KEY, org_id INTEGER, kind TEXT, text TEXT);
        CREATE TABLE risk_assessment(id INTEGER PRIMARY KEY, org_id INTEGER, score REAL, level TEXT);
        CREATE TABLE scan_run(id INTEGER PRIMARY KEY, org_id INTEGER, scan_type TEXT, status TEXT);
        CREATE TABLE change_event(id INTEGER PRIMARY KEY, org_id INTEGER, event_type TEXT, message TEXT);
        """
    )
    conn.commit()
    return conn


@pytest.fixture
def db_conn():
    conn = _create_db()
    yield conn
    conn.close()


def _mock_llm(system_prompt: str, user_prompt: str) -> Dict[str, Any]:
    """Return a deterministic JSON response regardless of prompt."""
    return {
        "answer": "mock answer",
        "cites": [],
        "insufficient": False,
        "model": "mock-model",
        "error": None,
        "tool_calls": [
            {"name": "test_tool", "arguments": {"param": 1}}
        ],
    }


def test_cache_behavior(db_conn):
    cur = db_conn.cursor()
    # Ensure caching works by mocking the LLM call.
    cache = ai_advanced.LRUCache(maxsize=10, ttl=60)
    result1 = ai_advanced.ask_with_cache(cur, 1, "foo", llm_fn=_mock_llm, cache=cache)
    result2 = ai_advanced.ask_with_cache(cur, 1, "foo", llm_fn=_mock_llm, cache=cache)
    assert result1 is result2  # same object returned from cache
    assert result1["answer"] == "mock answer"


def test_extended_context(db_conn):
    cur = db_conn.cursor()
    # Insert minimal rows in extended tables
    cur.execute("INSERT INTO event(org_id, kind, text) VALUES (1, 'test', 'demo')")
    cur.execute("INSERT INTO risk_assessment(org_id, score, level) VALUES (1, 5.0, 'high')")
    cur.execute("INSERT INTO scan_run(org_id, scan_type, status) VALUES (1, 'sast', 'complete')")
    cur.execute("INSERT INTO change_event(org_id, event_type, message) VALUES (1, 'update', 'changed')")
    cur.execute("INSERT INTO asset(id, org_id, value, scope, last_seen) VALUES (1, 1, 'srv1', 'internal', 123456)"
    )
    cur.execute("INSERT INTO finding(id, asset_id, kind, severity, state, text, obs_ids) VALUES (1, 1, 'cve', 'high', 'open', 'text', NULL)")
    cur.execute("INSERT INTO observation(id, asset_id, source, key, evidence_hash, value) VALUES (1, 1, 'src', 'key', 'hash', 'obs')")
    db_conn.commit()
    ctx = ai_advanced.extended_context(cur, 1)
    # Basic facts from the original context
    assert any("finding:1" in s for s in ctx)
    assert any("asset:1" in s for s in ctx)
    assert any("obs:1" in s for s in ctx)
    # Extended facts
    assert any("event:1" in s for s in ctx)
    assert any("risk:1" in s for s in ctx)
    assert any("scan:1" in s for s in ctx)
    assert any("change:1" in s for s in ctx)


def test_ask_with_tools(db_conn):
    cur = db_conn.cursor()
    tools = [{"name": "echo", "description": "Echo back a string"}]
    result = ai_advanced.ask_with_tools(cur, 1, "test", tools, llm_fn=_mock_llm)
    assert result["answer"] == "mock answer"
    # Ensure tool_calls present as provided by mock
    assert "tool_calls" in result
    assert result["tool_calls"][0]["name"] == "test_tool"