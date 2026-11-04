"""Minimal FastAPI application for the starter.

The original project contains a fairly involved web API module that pulls in
multiple routers and depends on the optional :mod:`fastapi` dependency.
For the purposes of the unit tests and the starter script we only need a
simple application instance that can be created without side effects.
"""

from __future__ import annotations

from fastapi import FastAPI

__all__ = ["create_app"]


def create_app() -> FastAPI:
    """Return a bare :class:`fastapi.FastAPI` instance.

    The function intentionally does *not* include any routers.  The starter
    script does not exercise the API routes; it simply starts the server for
    debugging.  This lightweight implementation satisfies the import contract
    without pulling in optional dependencies.
    """
    return FastAPI()
