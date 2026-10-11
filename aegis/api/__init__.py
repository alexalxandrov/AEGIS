"""HTTP API for AEGIS web UI.

This package originally imported :func:`create_app` eagerly from ``.app``.
The :mod:`.app` module pulls in the :mod:`fastapi` dependency, which is
not required for the unit tests in this repository.  Importing it during
test discovery caused an :class:`ImportError` because the optional
``fastapi`` dependency is not available in the execution environment.

To keep the public API stable while avoiding the hard dependency during
tests, we lazily import :func:`create_app` only when it is actually
requested.  The wrapper is defined at import time, but the heavy import
is deferred until the function is called.  If :mod:`fastapi` is missing
and the function is invoked, an informative error will be raised.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    # When type checking, we want the real symbol to be available.
    from .app import create_app as _create_app  # pragma: no cover

    def create_app() -> "FastAPI":  # pragma: no cover
        return _create_app()
else:
    def create_app(*args, **kwargs):  # pragma: no cover
        """Lazily import :func:`create_app` from :mod:`.app`.

        The function imports :mod:`.app` on first call and forwards all
        arguments to the real ``create_app``.  This keeps the import
        side‑effects (including the ``fastapi`` requirement) away from
        test discovery.
        """

        try:
            from .app import create_app as _create_app
        except Exception as exc:  # pragma: no cover - defensive
            raise RuntimeError(
                "The FastAPI dependency is required to create the app. "
                "Ensure 'fastapi' is installed before calling this function."
            ) from exc
        return _create_app(*args, **kwargs)

__all__ = ["create_app"]
