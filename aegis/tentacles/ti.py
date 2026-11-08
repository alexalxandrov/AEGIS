"""Threat‑intelligence helper functions.

In the real AEGIS project these would query external APIs such as
VirusTotal, AbuseIPDB, etc.  In this kata the platform has no network
access, so each function simply returns an empty list/dict and logs a
warning that the feature is a stub.
"""

from __future__ import annotations

import logging
from typing import Dict, List

logger = logging.getLogger("aegis.tentacles.ti")


def query_ip(ip: str) -> List[Dict[str, str]]:
    """Return threat intel for an IP address.

    The real implementation would perform a HTTP request.  Here we return
    an empty list and log that the call is a stub.
    """

    logger.warning("query_ip called – stub implementation; no data returned for %s", ip)
    return []


def query_domain(domain: str) -> List[Dict[str, str]]:
    """Return threat intel for a domain.
    """
    logger.warning("query_domain called – stub implementation; no data returned for %s", domain)
    return []


def query_url(url: str) -> List[Dict[str, str]]:
    """Return threat intel for a URL.
    """
    logger.warning("query_url called – stub implementation; no data returned for %s", url)
    return []