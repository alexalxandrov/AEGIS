"""Public exports for :mod:`aegis.tentacles`.

The tentacles package contains a collection of passive enrichment modules
used by AEGIS.  To keep the import paths short, the most frequently
used classes are re‑exported from this package level.  Importing
``aegis.tentacles`` therefore provides direct access to
``Subtakeover`` and can be extended in the future as needed.
"""

from .subtakeover import Subtakeover  # noqa: F401
from .tls import TLS  # noqa: F401