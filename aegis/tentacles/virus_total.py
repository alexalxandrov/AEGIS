"""Very small wrapper around the VirusTotal API.

The real project contains many more features and uses an HTTP client.
For the purposes of this kata we expose only the two helper functions
that the unit tests might call.
"""

from typing import List, Dict


def lookup_hash(h: str) -> List[Dict]:  # pragma: no cover
    """Placeholder – in a real environment this would query
    https://www.virustotal.com/api/v3/files/{h}.  The function returns an
    empty list if the API key is not configured or the network is not
    reachable.
    """
    return []
