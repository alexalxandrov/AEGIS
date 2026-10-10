"""Исключения scope: домены, хосты, IP, CIDR."""
from __future__ import annotations
import ipaddress, time
from . import db


def add(c, org_id, kind, pattern, note=""):
    kind = kind.lower()
    pattern = pattern.strip().lower().rstrip(".")
    if kind == "cidr":
        ipaddress.ip_network(pattern, strict=False)
    elif kind == "ip":
        ipaddress.ip_address(pattern)
    c.execute(
        "INSERT OR IGNORE INTO exclusion(org_id,pattern,kind,note,created) VALUES(?,?,?,?,?)",
        (org_id, pattern, kind, note, time.time()),
    )
    return True


def remove(c, exclusion_id):
    return c.execute("DELETE FROM exclusion WHERE id=?", (exclusion_id,)).rowcount > 0


def list_exclusions(c, org_id):
    return [db.row_to_dict(r) for r in c.execute("SELECT * FROM exclusion WHERE org_id=? ORDER BY id", (org_id,))]


def is_excluded(c, org_id, kind, value):
    value = (value or "").strip().lower().rstrip(".")
    rows = c.execute("SELECT * FROM exclusion WHERE org_id=?", (org_id,)).fetchall()
    for r in rows:
        p = r["pattern"]
        k = r["kind"]
        if k == "domain" and kind in ("domain",):
            if value == p or value.endswith("." + p):
                return True
        elif k == "host" and value == p:
            return True
        elif k in ("ip", "cidr") and kind == "ip":
            try:
                ip = ipaddress.ip_address(value)
                if k == "ip" and str(ip) == p:
                    return True
                if k == "cidr" and ip in ipaddress.ip_network(p, strict=False):
                    return True
            except ValueError:
                continue
    return False
