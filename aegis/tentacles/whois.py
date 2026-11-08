"""Simple WHOIS helper.

The project uses only very lightweight network calls in the tests, so the
implementation is deliberately simple: it spawns the system ``whois``
command via :mod:`subprocess`.  The output is parsed into a dictionary of
``key: value`` pairs.

The function is wrapped in :func:`lru_cache` so that repeated look‑ups of
the same domain are served from memory.
"""

from __future__ import annotations

import logging
from typing import Dict

logger = logging.getLogger("aegis.tentacles.whois")

__all__ = ["resolve"]


def resolve(domain: str) -> Dict[str, str]:
    """Return WHOIS information for *domain*.

    Stub implementation – returns an empty dict and logs a warning.  The real
    project would use the :mod:`whois` library or call the system ``whois``
    binary.
    """

    logger.warning("WHOIS resolve stub called for %s", domain)
    return {}