"""BGP enrichment of IP assets.

This tentacle uses the RIPEstat ``as-overview`` endpoint to fetch the list of
announced prefixes for a given ASN.  The result is returned as a list of
``{"key": "bgp_prefixes", "value": [<prefix>, ...]}``.

Only minimal error handling is performed; any network error will return an
empty list to keep the rest of the pipeline working.
"""

import urllib.error
from ..tentacle import Tentacle
from .ct import fetch_json


class BGP(Tentacle):
    """Enrich IP assets with BGP prefix data from RIPEstat."""

    name = "bgp"
    active = False

    @staticmethod
    def run(conn, asset):  # pragma: no cover – simple wrapper
        if asset["kind"] != "ip":
            return []
        return BGP.ip_intel(asset["value"])

    @staticmethod
    def ip_intel(ip: str):
        # We need the ASN first – reuse Intel.ip_intel logic
        try:
            data = fetch_json(
                f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}"
            )["data"]
        except Exception as e:  # pragma: no cover – network errors
            print(f"[bgp] RIPEstat error: {e!r}")
            return []
        asns = [int(a["asn"]) for a in data.get("asns", [])]
        prefixes = []
        for asn in asns:
            try:
                r = fetch_json(
                    f"https://stat.ripe.net/data/as-overview/data.json?resource={asn}"
                )["data"]
                prefixes.extend(p.get("prefix", "") for p in r.get("prefixes", []))
            except Exception:
                continue
        prefixes = sorted(set(prefixes))
        return [{"key": "bgp_prefixes", "value": prefixes}]
