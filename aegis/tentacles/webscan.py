"""Web technology scanner – stub.
"""

from __future__ import annotations

import logging
from typing import Dict

logger = logging.getLogger("aegis.tentacles.webscan")

__all__ = ["scan"]


def scan(url: str) -> Dict[str, str]:
    """Return web tech data for *url*.

    Stub – logs a warning and returns empty dict.
    """
    logger.warning("Webscan stub called for %s", url)
    return {}