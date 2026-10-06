"""Оркестрация Phase 1: seed-домен -> CT -> поддомены -> DNS (параллельно, с возобновлением) -> граф."""
import time
from concurrent.futures import ThreadPoolExecutor
from . import store
from .tentacles import ct, dns

RECHECK = 6 * 3600

def run_org(c, org_name, log=print, ct_fn=None, dns_fn=None, limit=300, workers=16):
    o = c.execute("SELECT id FROM organization WHERE name=?", (org_name,)).fetchone()
    if not o: raise SystemExit("нет организации")
    org = o["id"]; stats = {"assets_new": 0, "obs_new": 0, "obs_same": 0, "dns_checked": 0, "dns_left": 0}
    seeds = c.execute("SELECT a.* FROM seed s JOIN asset a ON a.org_id=s.org_id AND a.kind='domain' AND a.value=lower(s.value) "
                      "WHERE s.org_id=? AND s.kind='domain'", (org,)).fetchall()
    seed_ids = {s["id"] for s in seeds}
    for seed in seeds:
        try: items = (ct_fn or ct.CT().run)(c, seed)
        except Exception as e:
            log(f"[ct] {seed['value']}: сбой {type(e).__name__}")
            c.execute("INSERT OR REPLACE INTO source_health VALUES('crt.sh',0,strftime('%s','now'),?)", (str(e)[:100],)); items = []
        items = sorted(items, key=lambda i: (i["asset_value"].count("."), i["asset_value"]))
        if len(items) > limit: log(f"[ct] {seed['value']}: {len(items)} имён, беру {limit} (--limit)")
        for it in items[:limit]:
            aid, new = store.upsert_asset(c, org, "domain", it["asset_value"], existence=0.8, attribution=0.6)
            stats["assets_new"] += new
            if aid != seed["id"]: store.edge(c, seed["id"], aid, "has_subdomain")
            ch = store.observe(c, aid, "ct", it["key"], it["value"]); stats["obs_new" if ch else "obs_same"] += 1
    cutoff = time.time() - RECHECK
    todo = [a for a in c.execute("SELECT * FROM asset WHERE org_id=? AND kind='domain' ORDER BY id", (org,)).fetchall()
            if not c.execute("SELECT 1 FROM observation WHERE asset_id=? AND source='dns' AND last_confirmed>?", (a["id"], cutoff)).fetchone()
            and not c.execute("SELECT 1 FROM source_health WHERE source='dns:'||? AND checked>?", (a["value"], cutoff)).fetchone()]
    stats["dns_left"] = max(0, len(todo) - limit); todo = todo[:limit]
    log(f"[dns] проверяю {len(todo)} имён, потоков {workers}")
    def work(a):
        try: return a, (dns_fn or dns.DNS(None if a["id"] in seed_ids else ["A", "AAAA", "CNAME"]).run)(None, a)
        except Exception: return a, None
    with ThreadPoolExecutor(workers) as ex:
        for n, (a, res) in enumerate(ex.map(work, todo), 1):
            if n % 25 == 0: log(f"[dns] {n}/{len(todo)}")
            stats["dns_checked"] += 1
            c.execute("INSERT OR REPLACE INTO source_health VALUES('dns:'||?,1,strftime('%s','now'),'')", (a["value"],))
            for it in res or []:
                ch = store.observe(c, a["id"], "dns", it["key"], it["value"]); stats["obs_new" if ch else "obs_same"] += 1
                if not it["agree"]: store.observe(c, a["id"], "dns", it["key"] + "_disagree", True)
                if it["key"] in ("dns_A", "dns_AAAA"):
                    for ip in it["value"]:
                        ipid, new = store.upsert_asset(c, org, "ip", ip, existence=0.9, attribution=0.5); stats["assets_new"] += new
                        store.edge(c, a["id"], ipid, "resolves_to")
    log(f"готово: {stats}" + (" — запустите run ещё раз для остатка" if stats["dns_left"] else "")); return stats
