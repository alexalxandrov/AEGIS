import os
import pathlib
import sqlite3
import importlib

# Ensure that the environment is configured before importing any
# modules that depend on configuration.
os.environ["AEGIS_DATA"] = str(pathlib.Path("/tmp/workspace_test"))

# Import the module under test. Importing will run the top‑level code but the
# module only defines functions – it does not execute anything on import.
import starter


def test_workspace_creation(tmp_path: pathlib.Path):
    """Ensure that the workspace creation logic correctly creates a database.

    The test temporarily overrides ``AEGIS_DATA`` so that the database is
    created in a known location.  The ``_ensure_database`` helper from
    :mod:`starter` is called directly and the presence of the SQLite file is
    asserted.
    """

    workspace = tmp_path / "scan-test"
    os.environ["AEGIS_DATA"] = str(workspace)
    # ``starter`` uses the ``config`` module which reads the environment on
    # import; reload the module to pick up the new value.
    importlib.reload(starter)

    # Call the helper that creates the DB directory and file.
    starter._ensure_database()

    db_file = workspace / "aegis.db"
    assert db_file.exists(), f"Expected database at {db_file}"

    # Verify that the SQLite database is accessible.
    conn = sqlite3.connect(str(db_file))
    cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='organization'")
    assert cur.fetchone() is not None, "Table 'organization' should exist in fresh DB"
