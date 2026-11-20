"""WHOIS lookup using system whois command.

This module provides a simple `resolve(domain)` function that runs the
``whois`` binary and parses the output into a dictionary of
``key: value`` pairs.  The implementation is intentionally
minimal and does not require any third‑party libraries.
"""

import subprocess
import logging

logger = logging.getLogger("aegis.tentacles.whois")

__all__ = ["resolve"]

def resolve(domain: str):
    """Return WHOIS information for *domain*.

    The function executes ``whois <domain>`` and parses the output into
    a dictionary of key/value pairs.  Lines that do not contain a colon
    are ignored.  The dictionary keys are lower‑cased to provide a
    consistent API.
    """
    try:
        result = subprocess.run(
            ["whois", domain], capture_output=True, text=True, timeout=15
        )
        if result.returncode != 0:
            logger.warning("whois command failed for %s: %s", domain, result.stderr)
            return {}
        data = {}
        for line in result.stdout.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            data[key.strip().lower()] = value.strip()
        return data
    except Exception as exc:
        logger.warning("whois lookup error for %s: %s", domain, exc)
        return {}
