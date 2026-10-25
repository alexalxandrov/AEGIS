# Advanced AI Utilities

The original `aegis.ai_analyst` module provides a straightforward way to ask a local
Ollama model about the state of the AEGIS database.  The `ai_advanced` package
extends this functionality with:

* **Tool‑calling** – the ability to declare custom tools and have the model
  return a JSON array of ``tool_calls``.
* **Reasoning extraction** – if the model includes a ``reasoning`` field it is
  preserved.
* **Extended context** – additional tables such as `event`, `risk_assessment`,
  `scan_run` and `change_event` are automatically included in the prompt.
* **Caching** – a simple LRU cache with TTL to avoid repeating expensive LLM
  calls.

## API Overview

```python
from aegis import ai_advanced

conn = db.connect()  # sqlite3.Connection
cur = conn.cursor()

# Cached query
resp = ai_advanced.ask_with_cache(cur, org_id=1, question="Describe the last risk.")
print(resp["answer"])

# Query with tool calling support
tools = [
    {"name": "list_assets", "description": "Return all assets for an org."},
]
resp = ai_advanced.ask_with_tools(cur, 1, "Show assets.", tools)
print(resp.get("tool_calls"))
```

All functions return the same dictionary shape as the original `ask` call, plus
an optional ``tool_calls`` key when tool‑calling is used.

## Running Tests

The test suite uses an in‑memory SQLite database and a deterministic LLM
stub.  To run the tests, simply execute:

```bash
pytest -q
```

This verifies caching, context enrichment and tool‑calling integration.
