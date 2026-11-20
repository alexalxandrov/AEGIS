"""CVE lookup using the NVD REST API.

The :func:`lookup(product, version)` function retrieves CVE entries
for the given *product* and *version*.  The implementation
currently performs a keyword search in the NVD database and
returns a list of CVE identifiers and short descriptions.
"""

import httpx
import logging

logger = logging.getLogger("aegis.tentacles.cve")

__all__ = ["lookup", "cve"]

def lookup(product: str, version: str):
    """Return CVE data for *product* and *version* using the NVD API."""
    try:
        query = f"{product}"
        url = f"https://services.nvd.nist.gov/rest/json/cve/1.0?keyword={query}&resultsPerPage=200"
        resp = httpx.get(url, timeout=30)
        if resp.status_code != 200:
            logger.warning("NVD API returned %s for product %s", resp.status_code, product)
            return []
        data = resp.json()
        cve_list = []
        for item in data.get("result", {}).get("CVE_Items", []):
            cve_id = item.get("cve", {}).get("CVE_data_meta", {}).get("ID")
            description = (
                item.get("cve", {})
                .get("description", {})
                .get("description_data", [{}])[0]
                .get("value")
            )
            cve_list.append({"id": cve_id, "description": description})
        return cve_list
    except Exception as exc:
        logger.warning("CVE lookup error for %s %s: %s", product, version, exc)
        return []

cve = lookup
