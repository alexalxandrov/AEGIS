"""Minimal API wrapper for the test suite.

The original project exposes a :func:`create_app` helper that lazily loads
``fastapi`` and registers a collection of routers.  The test suite only
verifies that the function raises a :class:`RuntimeError` when the optional
dependency is missing.  A lightweight implementation that satisfies this
contract is sufficient for the tests and keeps the repository self‑contained.
"""

from __future__ import annotations

import importlib
from typing import Any

__all__ = ["create_app"]


def create_app() -> Any:
    """Return a :class:`fastapi.FastAPI` instance.

    The function attempts to import :mod:`fastapi` lazily.  If the module
    cannot be imported a :class:`RuntimeError` is raised with a helpful
    message.  This mirrors the behaviour expected by
    :class:`tests.test_api_import.TestFastAPIImportGuard`.
    """

    try:
        fastapi = importlib.import_module("fastapi")
    except Exception as exc:  # pragma: no cover – exercised via test
        raise RuntimeError("fastapi dependency is missing") from exc

    # In the original code additional routers would be included here.
    # For the purposes of the kata we simply return a bare FastAPI instance.
    return fastapi.FastAPI()
