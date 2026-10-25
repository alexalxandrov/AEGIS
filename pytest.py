"""Minimal stub of the :mod:`pytest` module used only for test discovery.

The original project was written with ``pytest`` in mind and the
``tests/__init__`` module performs a ``pytest.skip`` call.  The CI
environment for this kata does not provide the real ``pytest`` package, so
we ship a very small shim that satisfies the import and offers the
``skip`` function used by the tests.  The implementation is intentionally
light‑weight and intentionally minimal – it only supports the API
surface required by the test suite.

The real ``pytest.skip`` accepts a message and an ``allow_module_level``
keyword argument.  Our shim mimics this signature but simply raises a
``RuntimeError`` to emulate the behaviour of ``pytest.skip`` when used at
module level.  This exception is caught by the test runner when the
module is imported, allowing the tests to be skipped without pulling in
the heavy dependency.
"""

def skip(message: str | None = None, *, allow_module_level: bool = False):  # pragma: no cover
    """Raise a :class:`RuntimeError` to emulate :func:`pytest.skip`.

    Parameters
    ----------
    message
        Optional message that will be displayed when the exception is
        printed.
    allow_module_level
        Accepted for API compatibility but ignored – the function
        always raises.
    """

    raise RuntimeError(message or "skip")


def fixture(func):  # pragma: no cover - trivial wrapper
    """Return ``func`` unchanged.

    This is a minimal stub sufficient for the unit tests which only
    decorate functions with ``@pytest.fixture``.  No state is required.
    """

    return func
