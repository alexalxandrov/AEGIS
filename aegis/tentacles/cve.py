"""CVEs lookup – stub.
"""

from __future__ import annotations

import logging
from typing import List, Dict

logger = logging.getLogger("aegis.tentacles.cve")

# ``cve`` is the public symbol expected by :mod:`aegis.tentacles.__init__`.
# The original implementation exposed a ``lookup`` function, but the
# ``__init__`` imports ``cve`` directly.  To preserve backward
# compatibility and avoid ImportError during test collection we expose the
# function under both names.
__all__ = ["lookup", "cve"]


def lookup(product: str, version: str) -> List[Dict[str, str]]:
    """Return CVE data for *product* and *version*.

    Stub – logs a warning and returns an empty list.
    """
    logger.warning("CVE lookup stub for %s %s", product, version)
    return []

# Alias used by ``aegis.tentacles.__init__``
cve = lookup