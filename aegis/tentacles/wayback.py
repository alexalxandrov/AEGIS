"""Пассивный источник: архивированные хосты из Wayback Machine CDX API."""
import json, time, urllib.request, urllib.parse
from .. import config

def hosts(domain, retries=2):
    url = (f"https://web.archive.org/cdx/search/cdx?url={urllib.parse.quote('*.'+domain)}"
           "&output=json&fl=original&collapse=urlkey&limit=3000")
    err = None
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": config.USER_AGENT})
            rows = json.load(urllib.request.urlopen(req, timeout=20))
            out = set()
            for r in rows[1:] if rows else []:
                try: h = urllib.parse.urlparse(r[0] if isinstance(r, list) else r).hostname
                except Exception: continue
                if h and (h == domain or h.endswith("." + domain)): out.add(h.lower())
            return out
        except Exception as e:
            err = e; time.sleep(2 * (i + 1))
    raise err
