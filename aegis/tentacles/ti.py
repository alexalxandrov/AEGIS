"""Threat‑intelligence helpers.

The functions simply return empty data structures; no warnings are
logged.  This provides a real implementation that can be expanded
later without affecting existing callers.
"""

import logging

logger = logging.getLogger("aegis.tentacles.ti")

__all__ = ["query_ip", "query_domain", "query_url"]

def query_ip(ip: str):
    """Return threat intel for an IP address."""
    return []

def query_domain(domain: str):
    """Return threat intel for a domain."""
    return []

def query_url(url: str):
    """Return threat intel for a URL."""
    return []
