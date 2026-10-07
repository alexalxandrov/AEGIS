"""Diff по истории наблюдений: что появилось/изменилось с момента since. Правила -> findings."""
import json, time
from datetime import datetime, timezone

def _j(v):
    try: return json.loads(v)
    except Exception: return v

def _days_left(iso):
    try:
        d = datetime.fromisoformat(iso.replace("Z", "+00:00")); return (d - datetime.now(timezone.utc)).days
    except Exception: return None

def classify(asset, key, old, new):
    """Возвращает (kind, severity, text) или None."""
    n = asset["value"]
    if old is None:
        if key in ("dns_A", "dns_AAAA") : return ("DNS_NEW", "info", f"{n}: появилась {key[4:]} {new}")
        if key == "internetdb" and new.get("ports"): return ("PORTS_SEEN", "info", f"{n}: порты {new['ports']}")
        return None
    if key in ("dns_A", "dns_AAAA"): return ("DNS_CHANGE", "medium", f"{n}: {key[4:]} {old} -> {new}")
    if key == "dns_NS": return ("NS_CHANGE", "high", f"{n}: NS {old} -> {new}")
    if key == "dns_MX": return ("MX_CHANGE", "medium", f"{n}: MX {old} -> {new}")
    if key == "dns_TXT": return ("TXT_CHANGE", "low", f"{n}: TXT изменён")
    if key == "dns_CNAME": return ("CNAME_CHANGE", "medium", f"{n}: CNAME {old} -> {new}")
    if key == "internetdb":
        op, np_ = set(old.get("ports", [])), set(new.get("ports", []))
        if np_ - op: return ("NEW_PORT", "high", f"{n}: новые порты {sorted(np_ - op)}")
        if op - np_: return ("PORT_CLOSED", "info", f"{n}: закрылись {sorted(op - np_)}")
        if set(new.get("vulns", [])) - set(old.get("vulns", [])): return ("NEW_VULN", "high", f"{n}: новые CVE {sorted(set(new['vulns']) - set(old.get('vulns', [])))}")
    if key == "bgp":
        oa, na = {x["asn"] for x in old["asns"]}, {x["asn"] for x in new["asns"]}
        if oa != na: return ("ASN_CHANGE", "high", f"{n}: ASN {sorted(oa)} -> {sorted(na)}")
    if key == "rdap" and new:
        if old.get("ns") != new.get("ns"): return ("RDAP_NS_CHANGE", "high", f"{n}: NS в RDAP {old.get('ns')} -> {new.get('ns')}")
        if old.get("status") != new.get("status"): return ("RDAP_STATUS", "medium", f"{n}: статус {old.get('status')} -> {new.get('status')}")
    if key == "ct_certs": return ("NEW_CERTS", "info", f"{n}: новые сертификаты ({len(new)} всего)")
    return None

def static_checks(c, org_id):
    """Не требует истории: срок домена."""
    out = []
    for r in c.execute("SELECT a.id,a.value,o.value v FROM asset a JOIN observation o ON o.asset_id=a.id AND o.key='rdap' "
                       "WHERE a.org_id=? AND o.id=(SELECT MAX(id) FROM observation WHERE asset_id=a.id AND key='rdap')", (org_id,)):
        v = _j(r["v"]); d = _days_left(v.get("expires")) if isinstance(v, dict) else None
        if d is not None and d < 30:
            out.append({"asset_id": r["id"], "kind": "DOMAIN_EXPIRING", "severity": "high" if d >= 0 else "critical",
                        "text": f"{r['value']}: домен истекает через {d} дн.", "obs": []})
    return out

def compute(c, org_id, since):
    ev = []
    rows = c.execute("SELECT o.*,a.value aval,a.kind akind,a.scope FROM observation o JOIN asset a ON a.id=o.asset_id "
                     "WHERE a.org_id=? AND o.first_seen>=? ORDER BY o.id", (org_id, since)).fetchall()
    for o in rows:
        prev = c.execute("SELECT value FROM observation WHERE asset_id=? AND source=? AND key=? AND id<? ORDER BY id DESC LIMIT 1",
                         (o["asset_id"], o["source"], o["key"], o["id"])).fetchone()
        r = classify({"value": o["aval"]}, o["key"], _j(prev["value"]) if prev else None, _j(o["value"]))
        if r: ev.append({"asset_id": o["asset_id"], "kind": r[0], "severity": r[1], "text": r[2], "obs": [o["id"]]})
    for a in c.execute("SELECT * FROM asset WHERE org_id=? AND first_seen>=? AND kind IN ('domain','ip')", (org_id, since)):
        ev.append({"asset_id": a["id"], "kind": "NEW_ASSET", "severity": "info", "text": f"новый актив {a['kind']} {a['value']}", "obs": []})
    return ev + static_checks(c, org_id)

def save(c, events):
    """Записывает findings без дублей (по asset+kind+obs)."""
    new = []
    for e in events:
        key = json.dumps(e["obs"])
        if c.execute("SELECT 1 FROM finding WHERE asset_id=? AND kind=? AND obs_ids=? AND state='open'", (e["asset_id"], e["kind"], key)).fetchone(): continue
        c.execute("INSERT INTO finding(asset_id,kind,severity,state,obs_ids,created) VALUES(?,?,?,?,?,?)",
                  (e["asset_id"], e["kind"], e["severity"], "open", key, time.time())); new.append(e)
    return new

ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
