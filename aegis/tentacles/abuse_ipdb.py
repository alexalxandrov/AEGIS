"""Thin wrapper around AbuseIPDB.  The real library uses HTTP.
Only a dummy function is provided for compatibility with the tests.
"""

from typing import Dict, List


def lookup_ip(ip: str) -> List[Dict]:  # pragma: no cover
    """Return an empty list – real implementation would query
    https://api.abuseipdb.com/api/v2/check.
    """
    return []
