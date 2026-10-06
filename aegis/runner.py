"""Оркестрация Phase 1: seed-домен -> CT -> поддомены -> DNS -> граф."""
import json
from . import db, store
from .tentacles import ct, dns

def run_org(c, org_name, log=print, ct_fn=None, dns_fn=None):
    o = c.execute("SELECT id FROM organization WHERE name=?", (org_name,)).fetchone()
    if not o: raise SystemExit("нет организации")
    org = o["id"]
    stats = {"assets_new": 0, "obs_new": 0, "obs_same": 0}
    for seed in c.execute("SELECT * FROM asset WHERE org_id=? AND kind='domain' AND value NOT LIKE '%.%.%' ", (org,)).fetchall():
        try:
            items = (ct_fn or ct.CT().run)(c, seed)
        except Exception as e:
            log(f"[ct] {seed['value']}: сбой {type(e).__name__}"); c.execute("INSERT OR REPLACE INTO source_health VALUES('crt.sh',0,strftime('%s','now'),?)", (str(e)[:100],)); items = []
        for it in items:
            aid, new = store.upsert_asset(c, org, "domain", it["asset_value"], existence=0.8, attribution=0.6)
            stats["assets_new"] += new
            store.edge(c, seed["id"], aid, "has_subdomain") if aid != seed["id"] else None
            ch = store.observe(c, aid, "ct", it["key"], it["value"]); stats["obs_new" if ch else "obs_same"] += 1
    for a in c.execute("SELECT * FROM asset WHERE org_id=? AND kind='domain'", (org,)).fetchall():
        for it in (dns_fn or dns.DNS().run)(c, a):
            ch = store.observe(c, a["id"], "dns", it["key"], it["value"]); stats["obs_new" if ch else "obs_same"] += 1
            if not it["agree"]: store.observe(c, a["id"], "dns", it["key"] + "_disagree", True)
            if it["key"] in ("dns_A", "dns_AAAA"):
                for ip in it["value"]:
                    ipid, new = store.upsert_asset(c, org, "ip", ip, existence=0.9, attribution=0.5); stats["assets_new"] += new
                    store.edge(c, a["id"], ipid, "resolves_to")
    log(f"готово: {stats}"); return stats
