"""Запись в граф: наблюдение пишется только при изменении, иначе обновляется last_confirmed."""
import time, json, hashlib

def now(): return time.time()

def upsert_asset(c, org_id, kind, value, existence=0.0, attribution=0.0, scope="CANDIDATE"):
    value = value.strip().lower().rstrip(".")
    t = now()
    r = c.execute("SELECT id,existence_conf,attribution_conf FROM asset WHERE org_id=? AND kind=? AND value=?", (org_id, kind, value)).fetchone()
    if r:
        c.execute("UPDATE asset SET last_seen=?,is_alive=1,existence_conf=MAX(existence_conf,?),attribution_conf=MAX(attribution_conf,?) WHERE id=?",
                  (t, existence, attribution, r["id"]))
        return r["id"], False
    cur = c.execute("INSERT INTO asset(org_id,kind,value,scope,existence_conf,attribution_conf,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?)",
                    (org_id, kind, value, scope, existence, attribution, t, t))
    return cur.lastrowid, True

def observe(c, asset_id, source, key, value):
    """Возвращает True, если значение изменилось/новое (создана новая запись)."""
    v = json.dumps(value, sort_keys=True, ensure_ascii=False)
    h = hashlib.sha256(v.encode()).hexdigest()[:16]
    t = now()
    last = c.execute("SELECT id,evidence_hash FROM observation WHERE asset_id=? AND source=? AND key=? ORDER BY id DESC LIMIT 1",
                     (asset_id, source, key)).fetchone()
    if last and last["evidence_hash"] == h:
        c.execute("UPDATE observation SET last_confirmed=? WHERE id=?", (t, last["id"])); return False
    c.execute("INSERT INTO observation(asset_id,source,key,value,evidence_hash,first_seen,last_confirmed) VALUES(?,?,?,?,?,?,?)",
              (asset_id, source, key, v, h, t, t))
    return True

def edge(c, src, dst, rel):
    t = now()
    c.execute("INSERT INTO edge(src,dst,rel,first_seen,last_seen) VALUES(?,?,?,?,?) ON CONFLICT(src,dst,rel) DO UPDATE SET last_seen=?",
              (src, dst, rel, t, t, t))
