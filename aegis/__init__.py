"""Top‑level package for the AEGIS toolset.

Historically this file only exposed a ``__version__`` attribute, which caused
``ImportError`` in callers that expected sub‑modules to be importable via the
package namespace (e.g. ``from aegis import sources``).  The test suite – and
the ``starter.py`` entry point – rely on this behaviour.  The absence of
explicit imports made those modules inaccessible and resulted in the
``ImportError`` failures observed when running the test suite.

To restore compatibility we perform lazy imports of the most frequently used
sub‑packages.  Importing them at module load time is inexpensive because the
sub‑modules are small and import‑safe.  This change also keeps the public API
stable and allows ``help(aegis)`` to list the sub‑packages.
"""

# Public API for the package. ``runner`` has been removed, so it is omitted.
__all__ = [
    "config",
    "db",
    "sources",
    "ai_analyst",
    "__version__",
]

__version__ = "0.1.0"

# Import commonly used sub‑modules so that they are available as
# ``aegis.<module>``.
from . import config  # noqa: F401  (imported for side‑effects / namespace)
from . import db  # noqa: F401
# The ``runner`` module was deleted as part of the refactor; keep a comment
# for future developers.
# from . import runner  # noqa: F401
from . import sources  # noqa: F401
from . import ai_analyst  # noqa: F401
