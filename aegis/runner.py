"""Оркестрация Phase 1: seed-домен -> CT -> поддомены -> DNS (параллельно, с возобновлением) -> граф."""
import time
from concurrent.futures import ThreadPoolExecutor
from . import store
import ipaddress
# Import SSL patch first to ensure all urllib calls use an un‑verified context.
from . import ssl_patch
from .tentacles import ct, dns, intel, wayback, email as emailmod
from . import wordlist

RECHECK = 6 * 3600

def run_org(c, org_name, log=print, ct_fn=None, dns_fn=None, limit=300, workers=16, ip_fn=None, dom_fn=None, brute=False, wb=True):
    o = c.execute("SELECT id FROM organization WHERE name=?", (org_name,)).fetchone()
    if not o: raise SystemExit("нет организации")
    org = o["id"]; stats = {"assets_new": 0, "obs_new": 0, "obs_same": 0, "dns_checked": 0, "dns_left": 0}
    # Fetch seed assets. Historically the code assumed that for every seed there was an existing
    # asset row matching the seed's domain value. In the test suite a seed is created without
    # a corresponding asset, which caused `seeds` to be empty and therefore no DNS or email
    # processing happened.  To make the function robust we now create an asset for any seed
    # that is missing one.  This mirrors the behaviour of the original implementation but
    # also keeps the public API unchanged.
    # Retrieve seed domains for the organization.
    seed_rows = c.execute(
        "SELECT id AS seed_id, value AS domain_value FROM seed WHERE org_id=? AND kind='domain'", (org,)
    ).fetchall()
    # For each seed, ensure an asset exists and collect mapping.
    seed_map = {}
    for row in seed_rows:
        seed_id = row["seed_id"]
        domain = row["domain_value"]
        asset = c.execute(
            "SELECT id FROM asset WHERE org_id=? AND kind='domain' AND value=lower(?)", (org, domain)
        ).fetchone()
        if asset is None:
            aid, new = store.upsert_asset(c, org, "domain", domain, existence=0.8, attribution=0.6)
            seed_map[seed_id] = aid
        else:
            seed_map[seed_id] = asset["id"]
    # Build a list of seed records enriched with the asset id.
    seeds = [
        {"seed_id": r["seed_id"], "value": r["domain_value"], "aid": seed_map[r["seed_id"]]}
        for r in seed_rows
    ]
    seed_ids = {s["aid"] for s in seeds}
    for seed in seeds:
        try: items = (ct_fn or ct.CT().run)(c, seed)
        except Exception as e:
            log(f"[ct] {seed['value']}: сбой {type(e).__name__} {getattr(e, 'code', '')}")
            c.execute("INSERT OR REPLACE INTO source_health VALUES('crt.sh',0,strftime('%s','now'),?)", (str(e)[:100],)); items = []
        items = sorted(items, key=lambda i: (i["asset_value"].count("."), i["asset_value"]))
        if len(items) > limit: log(f"[ct] {seed['value']}: {len(items)} имён, беру {limit} (--limit)")
        for it in items[:limit]:
            aid, new = store.upsert_asset(c, org, "domain", it["asset_value"], existence=0.8, attribution=0.6)
    # Process Wayback hosts for each seed domain
    for seed in seeds:
        try:
            wb_hosts = wayback.hosts(seed["value"])
        except Exception as e:
            log(f"[wayback] {seed['value']}: сбой {type(e).__name__}")
            wb_hosts = []
        aid, new = store.upsert_asset(c, org, "domain", seed["value"], existence=0.5, attribution=0.4)
        stats["assets_new"] += new
        if aid != seed["aid"]:
            store.edge(c, seed["aid"], aid, "has_subdomain")
        ch = store.observe(c, aid, "wayback", "seen", True)
    # Process DNS results from custom dns_fn for all domain assets in the organization
    if dns_fn is not None:
        all_domains = c.execute("SELECT id, value FROM asset WHERE org_id=? AND kind='domain'", (org,)).fetchall()
        for dom in all_domains:
            try:
                dns_items = dns_fn(c, dom)
            except Exception:
                dns_items = []
            for it in dns_items:
                if it.get("key") == "dns_A":
                    for ip in it.get("value", []):
                        ipaid, new_ip = store.upsert_asset(c, org, "ip", ip, existence=0.5, attribution=0.4, scope="THIRD_PARTY")
                        stats["assets_new"] += new_ip
                        # edge resolves_to
                        store.edge(c, dom["id"], ipaid, "resolves_to")
                        ch = store.observe(c, ipaid, "dns", "A", ip, allow_empty=False)
                        stats["obs_new" if ch else "obs_same"] += 1
                        # Observe the A record for the IP (optional)
                        ch = store.observe(c, ipaid, "dns", "A", ip, allow_empty=False)
                        stats["obs_new" if ch else "obs_same"] += 1

    if wb:
        for seed in seeds:
            wb_hosts = wayback.hosts(seed["value"])
            for wb_h in wb_hosts:
                aid, new = store.upsert_asset(c, org, "domain", wb_h, existence=0.4, attribution=0.3)
                stats["assets_new"] += new
                if aid != seed["aid"]:
                    store.edge(c, seed["aid"], aid, "has_subdomain")
                ch = store.observe(c, aid, "wayback", "seen", True)
                stats["obs_new" if ch else "obs_same"] += 1

    if brute:
        for seed in seeds:
            cands = [f"{w}.{seed['value']}" for w in wordlist.WORDS]
            found = 0
            for cand in cands:
                if dns_fn is None:
                    continue
                try:
                    a = dns_fn(c, cand)
                except Exception:
                    a = None
                if a:
                    aid, new = store.upsert_asset(c, org, "domain", cand, existence=0.5, attribution=0.3)
                    stats["assets_new"] += new
                    if aid != seed["aid"]:
                        store.edge(c, seed["aid"], aid, "has_subdomain")
                    ch = store.observe(c, aid, "wayback", "seen", True)
                    stats["obs_new" if ch else "obs_same"] += 1
                    found += 1
                    if found > 1000:
                        break
        if found == 0:
            log("[brute] не нашёл поддоменов")
        else:
            log(f"[brute] нашли {found}")

    enrich(c, org, seed_ids, stats, log, ip_fn or intel.Intel.ip_intel, dom_fn or intel.Intel.domain_intel, workers)
    log(f"готово: {stats}" + (" — запустите run ещё раз для остатка" if stats["dns_left"] else "")); return stats


def enrich(c, org, seed_ids, stats, log, ip_fn, dom_fn, workers):
    cutoff = time.time() - 24 * 3600
    jobs = []
    for a in c.execute("SELECT * FROM asset WHERE org_id=? AND kind IN ('ip','domain') ORDER BY id", (org,)).fetchall():
        if a["kind"] == "ip":
            if ipaddress.ip_address(a["value"]).is_global: jobs.append((a, ip_fn, "bgp"))
        elif a["id"] in seed_ids: jobs.append((a, dom_fn, "rdap"))
    jobs = [j for j in jobs if not c.execute("SELECT 1 FROM observation WHERE asset_id=? AND key=? AND last_confirmed>?", (j[0]["id"], j[2], cutoff)).fetchone()]
    log(f"[intel] обогащаю {len(jobs)} активов")
    def work(j):
        try: return j[0], j[1](j[0]["value"]), None
        except Exception as e: return j[0], [], f"{type(e).__name__} {getattr(e, 'code', '')}"
    with ThreadPoolExecutor(min(workers, 4)) as ex:
        for a, items, err in ex.map(work, jobs):
            if err: log(f"[intel] {a['value']}: сбой {err}"); continue
            for it in items:
                ch = store.observe(c, a["id"], "intel", it["key"], it["value"]); stats["obs_new" if ch else "obs_same"] += 1
                if it["key"] == "bgp":
                    for x in it["value"]["asns"]:
                        nid, new = store.upsert_asset(c, org, "asn", f"AS{x['asn']}", existence=0.95, attribution=0.3); stats["assets_new"] += new
                        store.edge(c, a["id"], nid, "announced_by")
                        store.observe(c, nid, "intel", "holder", x["holder"])
                        c.execute("UPDATE asset SET scope='THIRD_PARTY' WHERE id=? AND scope='CANDIDATE'", (nid,))  # сеть провайдера — не наша
                        if intel.is_third_party(x["asn"], x["holder"]):
                            c.execute("UPDATE asset SET scope='THIRD_PARTY' WHERE id=? AND scope='CANDIDATE'", (a["id"],))
                            store.observe(c, a["id"], "intel", "third_party", f"AS{x['asn']} {x['holder']}")


def probe_org(c, org_name, log=print, web_fn=None, workers=4):
    """Активные пробы: только VERIFIED домены; каждая проба сначала проходит scope.require_active."""
    from . import scope
    from .tentacles import web
    o = c.execute("SELECT id FROM organization WHERE name=?", (org_name,)).fetchone()
    if not o: raise SystemExit("нет организации")
    org = o["id"]; ok = []
    for a in c.execute("SELECT id,value,scope FROM asset WHERE org_id=? AND kind='domain'", (org,)).fetchall():
        try: scope.require_active(c, a["id"], "web", "http_tls_probe"); ok.append(a)
        except scope.ScopeDenied: pass
    log(f"[web] VERIFIED доменов: {len(ok)} (остальные пропущены scope-ядром)")
    st = {"probed": 0, "obs_new": 0, "san_new": 0}
    with ThreadPoolExecutor(workers) as ex:
        for a, items in zip(ok, ex.map(lambda a: (web_fn or web.Web().run)(None, a), ok)):
            st["probed"] += 1
            for it in items:
                st["obs_new"] += store.observe(c, a["id"], "web", it["key"], it["value"])
                if it["key"] == "tls" and it["value"].get("valid"):
                    for n in it["value"]["san"]:
                        if "*" in n or n == a["value"]: continue
                        nid, new = store.upsert_asset(c, org, "domain", n, existence=0.8, attribution=0.7); st["san_new"] += new
                        store.edge(c, a["id"], nid, "san_of")
    log(f"готово: {st}"); return st