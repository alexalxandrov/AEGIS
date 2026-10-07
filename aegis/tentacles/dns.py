"""DNS через несколько резолверов (dig). Фиксируем расхождения. Пассивный (публичные резолверы)."""
import subprocess, shutil, socket
from ..tentacle import Tentacle
RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
TYPES = ["A", "AAAA", "CNAME", "NS", "MX", "TXT"]

DOH = {"1.1.1.1": "https://cloudflare-dns.com/dns-query", "8.8.8.8": "https://dns.google/resolve"}

def doh(name, rtype, resolver):
    """DNS-over-HTTPS: работает, когда порт 53 до публичных резолверов закрыт. None = недоступен."""
    import json, urllib.request, urllib.parse
    url = DOH.get(resolver)
    if not url: return None
    try:
        req = urllib.request.Request(f"{url}?name={urllib.parse.quote(name)}&type={rtype}", headers={"accept": "application/dns-json"})
        d = json.load(urllib.request.urlopen(req, timeout=8))
        codes = {"A": 1, "AAAA": 28, "CNAME": 5, "NS": 2, "MX": 15, "TXT": 16}
        return sorted({a["data"].strip('"').lower().rstrip(".") for a in d.get("Answer", []) if a.get("type") == codes[rtype]})
    except Exception:
        return None

def sock(name, rtype):
    if rtype not in ("A", "AAAA"): return []
    fam = socket.AF_INET if rtype == "A" else socket.AF_INET6
    try: return sorted({x[4][0] for x in socket.getaddrinfo(name, None, fam)})
    except OSError: return []

def dig(name, rtype, resolver):
    r = _dig(name, rtype, resolver)
    return r if (r is not None or resolver == "system") else doh(name, rtype, resolver)

def _dig(name, rtype, resolver):
    if resolver == "system":
        if shutil.which("dig"):
            try:
                p = subprocess.run(["dig", "+short", "+time=3", "+tries=1", name, rtype], capture_output=True, text=True, timeout=8)
                if p.returncode == 0:
                    return sorted({l.strip().lower().rstrip(".") for l in p.stdout.splitlines() if l.strip() and not l.startswith(";")})
            except Exception: pass
        return sock(name, rtype)
    if not shutil.which("dig"):
        if rtype in ("A", "AAAA"):
            fam = socket.AF_INET if rtype == "A" else socket.AF_INET6
            try: return sorted({x[4][0] for x in socket.getaddrinfo(name, None, fam)})
            except OSError: return []
        return []
    try:
        p = subprocess.run(["dig", "+short", "+time=2", "+tries=1", f"@{resolver}", name, rtype],
                           capture_output=True, text=True, timeout=6)
        if p.returncode != 0 or "timed out" in p.stdout or "no servers" in p.stdout: return None  # резолвер недоступен
        return sorted({l.strip().lower().rstrip(".") for l in p.stdout.splitlines() if l.strip() and not l.startswith(";")})
    except Exception:
        return None  # ошибка резолвера

def resolve(name, rtype, resolvers=RESOLVERS, fn=dig):
    res = {r: fn(name, rtype, r) for r in resolvers}
    ok = {r: v for r, v in res.items() if v is not None}
    if not ok:  # публичные резолверы недоступны (фаервол/VPN) — системный резолвер
        res["system"] = fn(name, rtype, "system"); ok = {"system": res["system"]}
    union = sorted({x for v in ok.values() for x in v})
    agree = len({tuple(v) for v in ok.values()}) <= 1
    return {"values": union, "agree": agree, "per_resolver": res}

class DNS(Tentacle):
    name = "dns"
    def __init__(self, types=None): self.types = types or TYPES
    def run(self, conn, asset):
        out = []
        for t in self.types:
            r = resolve(asset["value"], t)
            if r["values"] or r["agree"]:
                out.append({"key": f"dns_{t}", "value": r["values"], "agree": r["agree"]})
        return out
