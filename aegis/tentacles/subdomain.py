"""Subdomain hunter – stub.
"""

from __future__ import annotations

import logging
from typing import List

logger = logging.getLogger("aegis.tentacles.subdomain")

# Public API for the subdomain hunter.
# Historically the module exposed a ``subdomain`` symbol for backward
# compatibility, but the actual implementation is the ``hunt`` function.
# We keep ``hunt`` as the preferred name and provide ``subdomain`` as an
# alias to satisfy existing imports.
__all__ = ["hunt", "subdomain"]


def hunt(domain: str) -> List[str]:
    """Return a list of discovered subdomains for *domain*.

    Stub – logs a warning and returns an empty list.
    """
    logger.warning("Subdomain hunt stub called for %s", domain)
    return []

# Alias for backward compatibility.
subdomain = hunt