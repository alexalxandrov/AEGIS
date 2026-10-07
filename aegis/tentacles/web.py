"""Активные HTTP/TLS-пробы: один GET / на порт. ТОЛЬКО через scope.require_active (VERIFIED)."""
import http.client, ssl, re, datetime
from .. import config
from ..tentacle import Tentacle

SEC = {"hsts": "strict-transport-security", "csp": "content-security-policy", "xfo": "x-frame-options",
       "xcto": "x-content-type-options", "refpol": "referrer-policy"}

def _name(t):
    d = {k: v for rdn in t for k, v in rdn}
    return d.get("commonName") or d.get("organizationName") or ""

def _fetch(conn, host):
    conn.request("GET", "/", headers={"Host": host, "User-Agent": config.USER_AGENT, "Accept": "text/html,*/*"})
    r = conn.getresponse(); body = r.read(65536).decode("utf-8", "ignore")
    h = {k.lower(): v for k, v in r.getheaders()}
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    return {"status": r.status, "server": h.get("server", ""), "powered": h.get("x-powered-by", ""), "location": h.get("location", ""),
            "title": (m.group(1).strip()[:120] if m else ""), "sec": {k: (v in h) for k, v in SEC.items()}}

def probe_https(host, port=443, timeout=None):
    t = timeout or config.HTTP_TIMEOUT; out = {"http": None, "tls": None}
    try:
        conn = http.client.HTTPSConnection(host, port, timeout=t, context=ssl.create_default_context())
        out["http"] = _fetch(conn, host); s = conn.sock; c = s.getpeercert()
        out["tls"] = {"issuer": _name(c.get("issuer", ())), "subject": _name(c.get("subject", ())), "serial": c.get("serialNumber", ""),
                      "not_after": datetime.datetime.fromtimestamp(ssl.cert_time_to_seconds(c["notAfter"]), datetime.timezone.utc).isoformat(),
                      "san": sorted(v.lower() for k, v in c.get("subjectAltName", ()) if k == "DNS"), "version": s.version(), "valid": True}
        conn.close()
    except ssl.SSLCertVerificationError as e:
        out["tls"] = {"valid": False, "error": e.verify_message}
        try:  # заголовки всё равно собираем, но без проверки сертификата
            u = ssl.create_default_context(); u.check_hostname = False; u.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=t, context=u); out["http"] = _fetch(conn, host); conn.close()
        except Exception as e2: out["http"] = {"error": type(e2).__name__}
    except Exception as e:
        out["http"] = {"error": type(e).__name__}
    return out

def probe_http(host, port=80, timeout=None):
    try:
        conn = http.client.HTTPConnection(host, port, timeout=timeout or config.HTTP_TIMEOUT)
        r = _fetch(conn, host); conn.close(); return r
    except Exception as e:
        return {"error": type(e).__name__}

class Web(Tentacle):
    name = "web"; active = True
    def run(self, conn, asset, ports=(443, 80)):
        h = asset["value"]; items = []
        s = probe_https(h, ports[0])
        if s["http"]: items.append({"key": "http_443", "value": s["http"]})
        if s["tls"]: items.append({"key": "tls", "value": s["tls"]})
        items.append({"key": "http_80", "value": probe_http(h, ports[1])})
        return items
