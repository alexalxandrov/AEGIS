"""A lightweight stub of the FastAPI package used only for unit testing.

The real project depends on the real FastAPI library, but the execution
environment for the kata does not provide it.  The stub implements just enough
surface area for the tests to import :mod:`aegis.api.app` without raising
``ModuleNotFoundError``.

Only the classes and functions used by the application are defined:

* :class:`FastAPI` – a dummy class that records routes but does nothing.
* :class:`HTTPException` – simple container for status code and detail.
* :func:`Query` – returns the value unchanged.
* :mod:`middleware.cors` – provides a ``CORSMiddleware`` placeholder.
* :mod:`responses` – simple stubs for the response types.
* :mod:`staticfiles` – a ``StaticFiles`` placeholder.

If a future test relies on more advanced behaviour, the stub can be
expanded incrementally.
"""

from __future__ import annotations

__all__ = ["FastAPI", "HTTPException", "Query", "middleware", "responses", "staticfiles"]

class HTTPException(Exception):
    """Minimal HTTPException used by the API handlers."""

    def __init__(self, status_code: int, detail: str):  # pragma: no cover
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"{status_code}: {detail}")


def Query(value=None, **kwargs):  # pragma: no cover
    """Return the provided value – mirrors FastAPI's ``Query`` behaviour."""

    return value


class FastAPI:
    """Very small FastAPI‑like application.

    It stores the routes in ``self.routes`` for introspection but does not
    implement any actual request handling.
    """

    def __init__(self, *args, **kwargs):  # pragma: no cover
        self.routes = []

    def add_middleware(self, middleware_cls, **kwargs):  # pragma: no cover
        # Store middleware type for potential introspection in tests
        self.routes.append(("middleware", middleware_cls, kwargs))

    def on_event(self, event):  # pragma: no cover
        def decorator(fn):
            self.routes.append(("event", event, fn))
            return fn

        return decorator

    # Route decorators return a simple wrapper that records the path
    def get(self, path, **kwargs):  # pragma: no cover
        def decorator(fn):
            self.routes.append(("get", path, fn))
            return fn

        return decorator

    def post(self, path, **kwargs):  # pragma: no cover
        def decorator(fn):
            self.routes.append(("post", path, fn))
            return fn

        return decorator


# --- Sub‑modules -----------------------------------------------------------

# middleware package
class CORSMiddleware:  # pragma: no cover
    def __init__(self, *args, **kwargs):
        pass

# responses package
class FileResponse:  # pragma: no cover
    def __init__(self, *args, **kwargs):
        pass

class HTMLResponse:  # pragma: no cover
    def __init__(self, *args, **kwargs):
        pass

class PlainTextResponse:  # pragma: no cover
    def __init__(self, *args, **kwargs):
        pass

class StreamingResponse:  # pragma: no cover
    def __init__(self, *args, **kwargs):
        pass

# staticfiles package
class StaticFiles:  # pragma: no cover
    def __init__(self, *args, **kwargs):
        pass
