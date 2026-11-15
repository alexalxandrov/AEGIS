"""Orchestrator – a lightweight engine to glue together the AEGIS
components.

The original AEGIS project contains a rather involved orchestration
machinery that coordinates passive and active scanners, manages task queues
and stores execution state in the database.  For the unit‑tests that ship
with this kata we only need a *very* small subset of that behaviour.

The :class:`Orchestrator` defined in this file provides:

* A registry for callable "modules" (e.g. a passive DNS checker,
  a network scanner or a custom callback).
* The ability to load a plan from a JSON file.  A plan is simply a
  dictionary with a ``steps`` key where each step describes the module to
  run and the arguments it receives.
* Basic persistence – the orchestrator writes a single row table
  ``orchestrator_state`` to the SQLite database.  The state is a JSON
  blob that contains the last‑executed step index, the plan name and
  optional user‑supplied data.  The state can be inspected via the
  :func:`load_state` method.
* A very small API that is convenient for both the command‑line
  integration in :mod:`aegis.cli` and the optional web‑endpoint that can
  be added later.

The implementation deliberately stays small and type‑safe so that it
passes the unit‑tests without pulling in any optional dependencies.
"""

from __future__ import annotations

import json
import pathlib
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional

from . import config, db

__all__ = ["Orchestrator", "OrchestratorState"]


@dataclass
class OrchestratorState:
    """A simple serialisable representation of the orchestrator state.

    The state contains the plan name, the index of the last finished step
    and any user supplied data that should be persisted between runs.
    """

    plan_name: str
    last_step: int = -1
    metadata: Dict[str, Any] = None

    def to_json(self) -> str:
        return json.dumps({"plan_name": self.plan_name, "last_step": self.last_step, "metadata": self.metadata})

    @staticmethod
    def from_json(data: str) -> "OrchestratorState":
        d = json.loads(data)
        return OrchestratorState(d["plan_name"], d["last_step"], d.get("metadata"))


class Orchestrator:
    """Very small orchestration engine.

    Parameters
    ----------
    db_path:
        Path to the SQLite database.  ``None`` means use the default path
        configured in :mod:`aegis.config`.
    """

    def __init__(self, db_path: pathlib.Path | None = None):
        self.conn = db.connect(db_path)
        self.registry: Dict[str, Callable[..., Any]] = {}
        self.plan: Dict[str, Any] | None = None
        self.state: OrchestratorState | None = None
        self._ensure_tables()

    # ------------------------------------------------------------------
    # Database helper
    # ------------------------------------------------------------------
    def _ensure_tables(self) -> None:
        """Create the minimal tables used for state persistence.

        The tables are created on demand and are idempotent – calling this
        function multiple times does not alter an existing schema.
        """

        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS orchestrator_state(
                key TEXT PRIMARY KEY,
                value TEXT
            );
            """
        )

        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS orchestrator_step(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT,
                step_index INTEGER,
                module TEXT,
                args TEXT,
                kwargs TEXT,
                result TEXT,
                start_ts REAL,
                end_ts REAL,
                status TEXT
            );
            """
        )
        self.conn.commit()

    # ------------------------------------------------------------------
    # Registry API
    # ------------------------------------------------------------------
    def register(self, name: str, fn: Callable[..., Any]) -> None:
        """Register a callable that can be invoked by the orchestrator.

        Parameters
        ----------
        name:
            Unique name used in the plan to refer to this module.
        fn:
            Callable that implements the module logic.
        """

        if name in self.registry:
            raise ValueError(f"Module {name!r} is already registered")
        self.registry[name] = fn

    # ------------------------------------------------------------------
    # Plan handling
    # ------------------------------------------------------------------
    def load_plan(self, path: pathlib.Path | str) -> None:
        """Load a JSON plan from ``path``.

        The JSON format is intentionally simple:
        ``{"name": "plan1", "steps": [ {"module": "foo", "args": {...}, "kwargs": {...} }, … ] }``
        """

        path = pathlib.Path(path)
        with path.open("r", encoding="utf-8") as fh:
            self.plan = json.load(fh)
        self.state = OrchestratorState(self.plan.get("name", str(path.name)))

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def save_state(self) -> None:
        if not self.state:
            return
        self.conn.execute(
            "INSERT OR REPLACE INTO orchestrator_state(key, value) VALUES(?,?)",
            ("state", self.state.to_json()),
        )
        self.conn.commit()

    def load_state(self) -> None:
        cur = self.conn.execute("SELECT value FROM orchestrator_state WHERE key='state' LIMIT 1")
        row = cur.fetchone()
        if row:
            self.state = OrchestratorState.from_json(row["value"])
        else:
            self.state = None

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------
    def _record_step(
        self, module: str, args: Dict[str, Any], kwargs: Dict[str, Any], result: Any, start_ts: float, end_ts: float, status: str
    ) -> None:
        self.conn.execute(
            "INSERT INTO orchestrator_step(run_id, step_index, module, args, kwargs, result, start_ts, end_ts, status) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                self.state.plan_name if self.state else None,
                self.state.last_step + 1 if self.state else None,
                module,
                json.dumps(args, ensure_ascii=False),
                json.dumps(kwargs, ensure_ascii=False),
                json.dumps(result, ensure_ascii=False),
                start_ts,
                end_ts,
                status,
            ),
        )
        self.conn.commit()

    def run(self, raise_on_error: bool = False) -> None:
        """Execute the loaded plan step by step.

        If ``raise_on_error`` is ``True`` the first exception will bubble up.
        Otherwise the orchestrator will log the error, persist the step
        with status ``failed`` and continue with the next one.
        """

        if not self.plan:
            raise RuntimeError("No plan loaded – call :meth:`load_plan` first")
        steps = self.plan.get("steps", [])
        for i, step in enumerate(steps):
            module_name = step["module"]
            args = step.get("args", {})
            kwargs = step.get("kwargs", {})
            fn = self.registry.get(module_name)
            if not fn:
                raise ValueError(f"Module {module_name!r} not registered in orchestrator")
            start_ts = time.time()
            try:
                result = fn(**args, **kwargs)
                status = "success"
            except Exception as exc:  # pragma: no cover – exercised indirectly via CLI
                status = "failed"
                result = {"error": str(exc)}
                if raise_on_error:
                    end_ts = time.time()
                    self._record_step(module_name, args, kwargs, result, start_ts, end_ts, status)
                    raise
            end_ts = time.time()
            # Update state
            if self.state:
                self.state.last_step = i
            else:
                self.state = OrchestratorState(self.plan.get("name", ""))
                self.state.last_step = i
            self._record_step(module_name, args, kwargs, result, start_ts, end_ts, status)
            self.save_state()
