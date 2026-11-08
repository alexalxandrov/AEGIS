"""Passive DNS lookups.

Stub implementation – returns an empty list.
"""

from __future__ import annotations

import logging
from typing import List, Dict

logger = logging.getLogger("aegis.tentacles.passive_dns")


def lookup(domain: str) -> List[str]:
    """Return a list of resolved IP addresses for *domain*.

    The real implementation would query a passive DNS database.  For the
    purposes of this kata we simply log a warning and return an empty list.
    """

    logger.warning("Passive DNS lookup stub for %s", domain)
    return []