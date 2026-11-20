"""Subdomain enumeration using crt.sh.

The `hunt(domain)` function returns a list of discovered subdomains
for *domain* by querying the public crt.sh service and parsing the JSON
response.  The result is sorted and de‑duplicated.
"""

import httpx
import logging

logger = logging.getLogger("aegis.tentacles.subdomain")

__all__ = ["hunt", "subdomain"]

def hunt(domain: str):
    """Return a list of discovered subdomains for *domain*."""
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = httpx.get(url, timeout=20)
        if resp.status_code != 200:
            logger.warning("crt.sh returned %s for %s", resp.status_code, domain)
            return []
        data = resp.json()
        subs = set()
        for entry in data:
            name_value = entry.get("name_value", "")
            for name in name_value.splitlines():
                name = name.strip().lower()
                if name.endswith("." + domain) or name == domain:
                    subs.add(name.rstrip("."))
        return sorted(subs)
    except Exception as exc:
        logger.warning("subdomain hunt error for %s: %s", domain, exc)
        return []

# Backwards compatible alias
subdomain = hunt
