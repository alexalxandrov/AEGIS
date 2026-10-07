import argparse, json, sys, urllib.request, socket
from . import config, db, scope, __version__

def cmd_init(a):
    c = db.connect(); print("БД готова:", config.DB_PATH)

def cmd_org(a):
    c = db.connect()
    c.execute("INSERT OR IGNORE INTO organization(name,created) VALUES(?,strftime('%s','now'))", (a.name,))
    print("ok")

def cmd_seed(a):
    c = db.connect()
    o = c.execute("SELECT id FROM organization WHERE name=?", (a.org,)).fetchone()
    if not o: sys.exit("нет такой организации; сначала: aegis org <имя>")
    c.execute("INSERT OR IGNORE INTO seed(org_id,kind,value,verified) VALUES(?,?,?,?)", (o["id"], a.kind, a.value, int(a.verified)))
    c.execute("INSERT OR IGNORE INTO asset(org_id,kind,value,scope,first_seen,last_seen) VALUES(?,?,?,?,strftime('%s','now'),strftime('%s','now'))",
              (o["id"], a.kind, a.value, scope.VERIFIED if a.verified else scope.CANDIDATE))
    print("seed добавлен", "(VERIFIED)" if a.verified else "(CANDIDATE)")

def cmd_probe(a):
    """Тест scope: попытка активной пробы актива."""
    c = db.connect()
    try:
        print("РАЗРЕШЕНО:", scope.require_active(c, a.asset_id, "cli", "probe"))
    except scope.ScopeDenied as e:
        print("ОТКЛОНЕНО:", e); sys.exit(2)

def cmd_check(a):
    print(f"AEGIS {__version__}")
    try: db.connect(); print("[ok] БД")
    except Exception as e: print("[!!] БД:", e)
    try:
        r = urllib.request.urlopen(config.OLLAMA_URL + "/api/tags", timeout=3)
        names = [m["name"] for m in json.load(r).get("models", [])]
        print("[ok] Ollama, модели:", ", ".join(names) or "нет (ollama pull ...)")
    except Exception as e: print("[--] Ollama недоступна:", type(e).__name__)
    srcs = {"crt.sh": "https://crt.sh/?q=example.com&output=json", "RDAP": "https://rdap.org/domain/example.com",
            "RIPEstat": "https://stat.ripe.net/data/as-overview/data.json?resource=AS3333",
            "InternetDB": "https://internetdb.shodan.io/1.1.1.1", "Wayback": "https://web.archive.org/cdx/search/cdx?url=example.com&limit=1"}
    c = db.connect()
    for n, u in srcs.items():
        try:
            urllib.request.urlopen(urllib.request.Request(u, headers={"User-Agent": config.USER_AGENT}), timeout=config.HTTP_TIMEOUT)
            ok, note = 1, ""
        except Exception as e: ok, note = 0, type(e).__name__
        c.execute("INSERT OR REPLACE INTO source_health VALUES(?,?,strftime('%s','now'),?)", (n, ok, note))
        print(f"[{'ok' if ok else '!!'}] {n} {note}")

def cmd_run(a):
    from . import runner
    runner.run_org(db.connect(), a.org, limit=a.limit)

def cmd_assets(a):
    c = db.connect()
    for r in c.execute("SELECT id,kind,value,scope,existence_conf e,attribution_conf a FROM asset ORDER BY kind,value"):
        print(f"{r['id']:>4} {r['kind']:<7} {r['scope']:<11} e={r['e']:.1f} a={r['a']:.1f}  {r['value']}")

def cmd_scope(a):
    c = db.connect(); scope.set_scope(c, a.asset_id, a.state); print("ok")

def cmd_dns(a):
    from .tentacles import dns
    for t in ("A", "AAAA", "NS", "MX"):
        r = dns.resolve(a.name, t); print(t, r["values"], "согласны" if r["agree"] else "РАСХОЖДЕНИЕ", r["per_resolver"])

def cmd_diff(a):
    import time
    from . import diff
    c = db.connect(); o = c.execute("SELECT id FROM organization WHERE name=?", (a.org,)).fetchone()
    if not o: sys.exit("нет организации")
    ev = diff.compute(c, o["id"], time.time() - a.hours * 3600)
    new = diff.save(c, ev)
    print(f"событий: {len(ev)}, новых findings: {len(new)}")
    for e in sorted(ev, key=lambda e: diff.ORDER[e["severity"]]): print(f"[{e['severity']:<8}] {e['kind']:<16} {e['text']}")

def cmd_findings(a):
    c = db.connect()
    for r in c.execute("SELECT f.id,f.severity,f.kind,f.state,a.value FROM finding f JOIN asset a ON a.id=f.asset_id ORDER BY f.id DESC LIMIT 50"):
        print(f"#{r['id']} {r['severity']:<8} {r['kind']:<16} {r['state']:<6} {r['value']}")

def cmd_web(a):
    from . import runner
    runner.probe_org(db.connect(), a.org)

def cmd_digest(a):
    from . import digest
    c = db.connect(); o = c.execute("SELECT id FROM organization WHERE name=?", (a.org,)).fetchone()
    if not o: sys.exit("нет организации")
    md = digest.make(c, o["id"], a.hours, use_llm=not a.no_llm)
    import datetime
    f = config.DATA_DIR / f"digest_{a.org}_{datetime.date.today()}.md"; f.write_text(md); print(md); print("\nсохранено:", f)

def do_scan(org, hours=48, use_llm=True, limit=300):
    import time, datetime
    from . import runner, diff, digest
    c = db.connect()
    runner.run_org(c, org, limit=limit); runner.probe_org(c, org)
    o = c.execute("SELECT id FROM organization WHERE name=?", (org,)).fetchone()
    new = diff.save(c, diff.compute(c, o["id"], time.time() - hours * 3600))
    print(f"[scan] новых findings: {len(new)}")
    md = digest.make(c, o["id"], hours, use_llm=use_llm)
    f = config.DATA_DIR / f"digest_{org}_{datetime.date.today()}.md"; f.write_text(md); print("[scan] дайджест:", f)

def cmd_scan(a): do_scan(a.org, a.hours, not a.no_llm, a.limit)

def cmd_watch(a):
    import time
    print(f"[watch] каждые {a.every} ч; Ctrl-C — стоп")
    while True:
        try: do_scan(a.org, max(a.every * 2, 24), not a.no_llm)
        except Exception as e: print("[watch] сбой итерации:", type(e).__name__, e)
        try: time.sleep(a.every * 3600)
        except KeyboardInterrupt: print("\n[watch] стоп"); return

def main():
    p = argparse.ArgumentParser("aegis"); s = p.add_subparsers(dest="cmd", required=True)
    s.add_parser("init").set_defaults(f=cmd_init)
    s.add_parser("check").set_defaults(f=cmd_check)
    x = s.add_parser("org"); x.add_argument("name"); x.set_defaults(f=cmd_org)
    x = s.add_parser("seed"); x.add_argument("org"); x.add_argument("kind", choices=["domain", "asn", "cidr"]); x.add_argument("value")
    x.add_argument("--verified", action="store_true"); x.set_defaults(f=cmd_seed)
    x = s.add_parser("probe"); x.add_argument("asset_id", type=int); x.set_defaults(f=cmd_probe)
    x = s.add_parser("run"); x.add_argument("org"); x.add_argument("--limit", type=int, default=300); x.set_defaults(f=cmd_run)
    s.add_parser("assets").set_defaults(f=cmd_assets)
    x = s.add_parser("scope"); x.add_argument("asset_id", type=int); x.add_argument("state", choices=sorted(scope.STATES)); x.set_defaults(f=cmd_scope)
    x = s.add_parser("dns"); x.add_argument("name"); x.set_defaults(f=cmd_dns)
    x = s.add_parser("diff"); x.add_argument("org"); x.add_argument("--hours", type=float, default=24); x.set_defaults(f=cmd_diff)
    s.add_parser("findings").set_defaults(f=cmd_findings)
    x = s.add_parser("web"); x.add_argument("org"); x.set_defaults(f=cmd_web)
    x = s.add_parser("digest"); x.add_argument("org"); x.add_argument("--hours", type=float, default=48); x.add_argument("--no-llm", action="store_true"); x.set_defaults(f=cmd_digest)
    x = s.add_parser("scan"); x.add_argument("org"); x.add_argument("--hours", type=float, default=48); x.add_argument("--limit", type=int, default=300); x.add_argument("--no-llm", action="store_true"); x.set_defaults(f=cmd_scan)
    x = s.add_parser("watch"); x.add_argument("org"); x.add_argument("--every", type=float, default=6); x.add_argument("--no-llm", action="store_true"); x.set_defaults(f=cmd_watch)
    a = p.parse_args(); a.f(a)

if __name__ == "__main__": main()
