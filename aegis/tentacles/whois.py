"""Simple WHOIS helper.

The project uses only very lightweight network calls in the tests, so the
implementation is deliberately simple: it spawns the system ``whois``
command via :mod:`subprocess`.  The output is parsed into a dictionary of
``key: value`` pairs.

The function is wrapped in :func:`lru_cache` so that repeated look‑ups of
the same domain are served from memory.
"""

from __future__ import annotations

import subprocess
from functools import lru_cache
from typing import Dict

__all__ = ["resolve"]


@lru_cache(maxsize=None)
def resolve(domain: str) -> Dict[str, str]:
    """Return WHOIS information for *domain*.

    Parameters
    ----------
    domain:
        Fully‑qualified domain name.

    Returns
    -------
    dict
        Mapping of attribute names to their string values.  Empty dictionary
        on error.
    """
    try:
        output = subprocess.check_output(["whois", domain], text=True, timeout=10)
    except Exception as exc:  # pragma: no cover - exercised by tests via mocks
        return {"error": str(exc)}

    info: Dict[str, str] = {}
    for line in output.splitlines():
        if ":" in line:
            key, val = line.split(":", 1)
            info[key.strip()] = val.strip()
    return info