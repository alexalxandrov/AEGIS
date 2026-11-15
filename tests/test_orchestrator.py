import json
import os
import tempfile
import sqlite3

import pytest

# Set up a temporary database before importing project modules
temp_dir = tempfile.TemporaryDirectory()
os.environ["AEGIS_DATA"] = temp_dir.name
# Ensure config picks up the new location
from aegis import config, db, orchestrator


def test_orchestrator_register_and_run(tmp_path):
    """Verify that an orchestrator can register a dummy module, load a
    simple plan, execute it, and record the step in the SQLite database.
    """
    # Create a minimal plan file
    plan = {
        "steps": [
            {
                "name": "dummy",
                "args": {}
            }
        ]
    }
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan))

    # Instantiate orchestrator
    orch = orchestrator.Orchestrator()

    # Register a dummy module that simply returns a fixed string
    orch.register("dummy", lambda **kw: "ok")

    # Load the plan file
    orch.load_plan(str(plan_path))

    # Run the orchestrator
    orch.run()

    # Verify that a step was persisted with status "completed"
    conn = db.connect()
    step = conn.execute(
        "SELECT step_name, status FROM orchestrator_step WHERE step_name=? ORDER BY ts DESC LIMIT 1",
        ("dummy",)
    ).fetchone()
    assert step is not None
    assert step["status"] == "completed"
