"""Пассивное обогащение: RIPEstat (ASN), Shodan InternetDB, RDAP. Стоп-лист CDN/облаков."""
import urllib.error
from .ct import fetch_json
from ..tentacle import Tentacle
# только чистые CDN/WAF-прокси. Хостинги/облака (Linode, AWS EC2, DO) сюда НЕ входят: там сервер клиента.
CDN_ASNS = {13335, 209242, 132892, 394536, 20940, 16625, 54113, 19551, 30148, 60068, 20446}
CDN_WORDS = ("cloudflare", "fastly", "cloudfront", "incapsula", "imperva", "sucuri")
SLD = {"co", "com", "org", "net", "gov", "edu", "ac"}

def registrable(name):
    l = name.lower().rstrip(".").split(".")
    return ".".join(l[-3:] if len(l) >= 3 and len(l[-1]) == 2 and l[-2] in SLD else l[-2:])

def is_third_party(asn, holder):
    return int(asn) in CDN_ASNS or any(w in (holder or "").lower() for w in CDN_WORDS)

class Intel(Tentacle):
    """Passive enrichment of IP and domain assets using public data‑sources."""
    name = "intel"
    active = False

    def run(self, conn, asset):
        """Return enrichment records for the supplied asset.

        ``asset`` must contain ``value`` and ``kind`` keys.
        """
        if asset["kind"] == "ip":
            return self.ip_intel(asset["value"])
        if asset["kind"] == "domain":
            return self.domain_intel(asset["value"])

    @staticmethod
    def ip_intel(ip):
        out = []
        try:
            d = fetch_json(
                f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}"
            )["data"]
        except Exception as e:
            print(f"[intel] RIPEstat error: {e!r}")
            d = {"resource": ip, "asns": []}
        asns = [
            {"asn": int(a["asn"]), "holder": a.get("holder", "")}
            for a in d.get("asns", [])
        ]
        out.append(
            {
                "key": "bgp",
                "value": {"prefix": d.get("resource"), "asns": asns},
            }
        )
        try:
            try:
                j = fetch_json(f"https://internetdb.shodan.io/{ip}")
            except Exception as e:
                print(f"[intel] Shodan InternetDB error: {e!r}")
                j = {}
            out.append(
                {
                    "key": "internetdb",
                    "value": {
                        k: sorted(j.get(k, []))
                        for k in ("ports", "cpes", "hostnames", "tags", "vulns")
                    },
                }
            )
        except urllib.error.HTTPError as e:
            if e.code != 404:
                raise
            out.append({"key": "internetdb", "value": {}})
        return out

    @staticmethod
    def domain_intel(name):
        try:
            d = fetch_json(f"https://rdap.org/domain/{registrable(name)}")
        except Exception as e:
            print(f"[intel] RDAP error: {e!r}")
            # Any failure (network, HTTP error, JSON decode) results in an
            # empty RDAP record so the caller can proceed.
            return [{"key": "rdap", "value": {}}]
        ev = {
            e.get("eventAction"): e.get("eventDate")
            for e in d.get("events", [])
        }
        return [
            {
                "key": "rdap",
                "value": {
                    "registered": ev.get("registration"),
                    "expires": ev.get("expiration"),
                    "status": sorted(d.get("status", [])),
                    "ns": sorted(
                        n.get("ldhName", "").lower() for n in d.get("nameservers", [])
                    ),
                },
            }
        ]
