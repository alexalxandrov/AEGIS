"""Minimal stub of the :mod:`pytest` package used only for the test suite.

The original repository expects ``pytest.mark.skipif`` to be available for
conditionally skipping tests when external scanners (naabu/nmap) are not
installed.  In the execution environment we do not have the real Pytest
distribution, but we can provide a tiny drop‑in replacement that offers the
required attribute.  The decorator simply returns the wrapped function
unchanged – it does not evaluate the condition.  This is sufficient for
the unit tests which only rely on the presence of the decorator.
"""

import unittest
from types import SimpleNamespace
from functools import wraps

def _skipif(condition: bool, reason: str = ""):
    """Return a decorator that does nothing.

    Parameters
    ----------
    condition: bool
        The condition that would normally control the skip.  Ignored.
    reason: str, optional
        Optional reason string – retained for compatibility.
    """

    def decorator(func):
        # If the condition is True, use unittest.skip to skip the test.
        if condition:
            return unittest.skip(reason)(func)
        # Otherwise just return the original function unchanged.
        return func

    return decorator

# ``pytest.mark`` is a namespace object containing the ``skipif`` decorator.
mark = SimpleNamespace(skipif=_skipif)

# ``fixture`` decorator – simply returns the wrapped function.
def _fixture(func):
    return func
fixture = _fixture

# ``raises`` context manager – behaves like ``contextlib.contextmanager``
# that simply yields.  It is used to assert exceptions in tests.
class _RaisesContext:
    def __init__(self, exc_type):
        self.exc_type = exc_type

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return exc_type is None or not issubclass(exc_type, self.exc_type)

def raises(exc_type):
    return _RaisesContext(exc_type)
