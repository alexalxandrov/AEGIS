"""Пассивное обогащение: RIPEstat (ASN), Shodan InternetDB, RDAP. Стоп-лист CDN/облаков."""
import urllib.error
from .ct import fetch_json
# только чистые CDN/WAF-прокси. Хостинги/облака (Linode, AWS EC2, DO) сюда НЕ входят: там сервер клиента.
CDN_ASNS = {13335, 209242, 132892, 394536, 20940, 16625, 54113, 19551, 30148, 60068, 20446}
CDN_WORDS = ("cloudflare", "fastly", "cloudfront", "incapsula", "imperva", "sucuri")
SLD = {"co", "com", "org", "net", "gov", "edu", "ac"}

def registrable(name):
    l = name.lower().rstrip(".").split(".")
    return ".".join(l[-3:] if len(l) >= 3 and len(l[-1]) == 2 and l[-2] in SLD else l[-2:])

def is_third_party(asn, holder):
    return int(asn) in CDN_ASNS or any(w in (holder or "").lower() for w in CDN_WORDS)

def ip_intel(ip):
    out = []
    d = fetch_json(f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}")["data"]
    asns = [{"asn": int(a["asn"]), "holder": a.get("holder", "")} for a in d.get("asns", [])]
    out.append({"key": "bgp", "value": {"prefix": d.get("resource"), "asns": asns}})
    try:
        j = fetch_json(f"https://internetdb.shodan.io/{ip}")
        out.append({"key": "internetdb", "value": {k: sorted(j.get(k, [])) for k in ("ports", "cpes", "hostnames", "tags", "vulns")}})
    except urllib.error.HTTPError as e:
        if e.code != 404: raise
        out.append({"key": "internetdb", "value": {}})
    return out

def domain_intel(name):
    try: d = fetch_json(f"https://rdap.org/domain/{registrable(name)}")
    except urllib.error.HTTPError as e:
        if e.code == 404: return [{"key": "rdap", "value": {}}]
        raise
    ev = {e.get("eventAction"): e.get("eventDate") for e in d.get("events", [])}
    return [{"key": "rdap", "value": {"registered": ev.get("registration"), "expires": ev.get("expiration"),
             "status": sorted(d.get("status", [])), "ns": sorted(n.get("ldhName", "").lower() for n in d.get("nameservers", []))}}]
