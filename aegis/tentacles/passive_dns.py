"""Passive DNS lookups.

The :func:`lookup(domain)` function resolves *domain* using the standard
socket library and returns a sorted list of unique IPv4 and IPv6 addresses.
"""

import socket
import logging

logger = logging.getLogger("aegis.tentacles.passive_dns")

__all__ = ["lookup"]

def lookup(domain: str):
    """Return list of resolved IP addresses for *domain*."""
    try:
        ips = set()
        for res in socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP):
            ip = res[4][0]
            ips.add(ip)
        return sorted(ips)
    except Exception as exc:
        logger.warning("Passive DNS lookup error for %s: %s", domain, exc)
        return []
