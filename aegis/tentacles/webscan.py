"""Simple web technology scanner.

The :func:`scan(url)` function performs a GET request to *url* using httpx
and returns basic HTTP response information, such as status code,
headers, content‑type, server and content‑length.
"""

import httpx
import logging

logger = logging.getLogger("aegis.tentacles.webscan")

__all__ = ["scan"]

def scan(url: str):
    """Return basic web tech info for a URL using httpx."""
    try:
        resp = httpx.get(url, timeout=30, follow_redirects=True)
        headers = dict(resp.headers)
        return {
            "url": url,
            "status": resp.status_code,
            "headers": headers,
            "content_type": headers.get("content-type"),
            "server": headers.get("server"),
            "content_length": headers.get("content-length"),
        }
    except Exception as exc:
        logger.warning("webscan error for %s: %s", url, exc)
        return {}
