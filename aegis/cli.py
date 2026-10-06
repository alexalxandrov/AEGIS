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

def main():
    p = argparse.ArgumentParser("aegis"); s = p.add_subparsers(dest="cmd", required=True)
    s.add_parser("init").set_defaults(f=cmd_init)
    s.add_parser("check").set_defaults(f=cmd_check)
    x = s.add_parser("org"); x.add_argument("name"); x.set_defaults(f=cmd_org)
    x = s.add_parser("seed"); x.add_argument("org"); x.add_argument("kind", choices=["domain", "asn", "cidr"]); x.add_argument("value")
    x.add_argument("--verified", action="store_true"); x.set_defaults(f=cmd_seed)
    x = s.add_parser("probe"); x.add_argument("asset_id", type=int); x.set_defaults(f=cmd_probe)
    a = p.parse_args(); a.f(a)

if __name__ == "__main__": main()
