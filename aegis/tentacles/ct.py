"""CT через crt.sh: кэш на диске + ретраи. Пассивный."""
import json, time, hashlib, urllib.request, urllib.parse
from .. import config
from ..tentacle import Tentacle

def fetch_json(url, retries=3):
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    cf = config.DATA_DIR / ("cache_" + hashlib.md5(url.encode()).hexdigest() + ".json")
    if cf.exists() and time.time() - cf.stat().st_mtime < 6 * 3600:
        return json.loads(cf.read_text())
    err = None
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": config.USER_AGENT})
            data = json.load(urllib.request.urlopen(req, timeout=60))
            cf.write_text(json.dumps(data)); return data
        except Exception as e:
            err = e; time.sleep(2 * (i + 1))
    raise err

def names_from_rows(rows, domain):
    out = {}
    for r in rows:
        for n in str(r.get("name_value", "")).splitlines():
            n = n.strip().lower().lstrip("*.").rstrip(".")
            if n == domain or n.endswith("." + domain):
                o = out.setdefault(n, {"certs": set(), "issuer": r.get("issuer_name", "")})
                o["certs"].add(r.get("id"))
    return out

class CT(Tentacle):
    name = "ct"
    def run(self, conn, asset):
        d = asset["value"]
        rows = fetch_json("https://crt.sh/?q=" + urllib.parse.quote("%." + d) + "&output=json")
        return [{"asset_kind": "domain", "asset_value": n, "key": "ct_certs", "value": sorted(v["certs"])[:50]}
                for n, v in names_from_rows(rows, d).items()]
