"""DNS через несколько резолверов (dig). Фиксируем расхождения. Пассивный (публичные резолверы)."""
import subprocess, shutil, socket
from ..tentacle import Tentacle
RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
TYPES = ["A", "AAAA", "CNAME", "NS", "MX", "TXT"]

def dig(name, rtype, resolver):
    if not shutil.which("dig"):
        if rtype in ("A", "AAAA"):
            fam = socket.AF_INET if rtype == "A" else socket.AF_INET6
            try: return sorted({x[4][0] for x in socket.getaddrinfo(name, None, fam)})
            except OSError: return []
        return []
    try:
        p = subprocess.run(["dig", "+short", "+time=3", "+tries=1", f"@{resolver}", name, rtype],
                           capture_output=True, text=True, timeout=10)
        return sorted({l.strip().lower().rstrip(".") for l in p.stdout.splitlines() if l.strip() and not l.startswith(";")})
    except Exception:
        return None  # ошибка резолвера

def resolve(name, rtype, resolvers=RESOLVERS, fn=dig):
    res = {r: fn(name, rtype, r) for r in resolvers}
    ok = {r: v for r, v in res.items() if v is not None}
    union = sorted({x for v in ok.values() for x in v})
    agree = len({tuple(v) for v in ok.values()}) <= 1
    return {"values": union, "agree": agree, "per_resolver": res}

class DNS(Tentacle):
    name = "dns"
    def run(self, conn, asset):
        out = []
        for t in TYPES:
            r = resolve(asset["value"], t)
            if r["values"]:
                out.append({"key": f"dns_{t}", "value": r["values"], "agree": r["agree"]})
        return out
