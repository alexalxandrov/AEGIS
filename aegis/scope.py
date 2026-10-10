"""Scope-ядро: активные пробы разрешены только по VERIFIED. Каждое решение — в журнал."""
import time
from . import exclusions

VERIFIED, CANDIDATE, THIRD_PARTY, OUT_OF_SCOPE = "VERIFIED", "CANDIDATE", "THIRD_PARTY", "OUT_OF_SCOPE"
STATES = {VERIFIED, CANDIDATE, THIRD_PARTY, OUT_OF_SCOPE}

class ScopeDenied(Exception):
    pass


def set_scope(c, asset_id, state, actor="operator", method="manual", note=""):
    if state not in STATES:
        raise ValueError(state)
    r = c.execute("SELECT scope, org_id, kind, value FROM asset WHERE id=?", (asset_id,)).fetchone()
    if not r:
        raise ValueError("unknown asset")
    old = r["scope"]
    if exclusions.is_excluded(c, r["org_id"], r["kind"], r["value"]) and state == VERIFIED:
        raise ScopeDenied(f"{r['value']}: excluded from scope")
    c.execute("UPDATE asset SET scope=? WHERE id=?", (state, asset_id))
    if state == VERIFIED:
        c.execute(
            "UPDATE asset SET verified_by=?, verified_at=?, verified_method=? WHERE id=?",
            (actor, time.time(), method, asset_id),
        )
    c.execute(
        "INSERT INTO scope_decision(asset_id,old_scope,new_scope,actor,method,note,created) VALUES(?,?,?,?,?,?,?)",
        (asset_id, old, state, actor, method, note, time.time()),
    )
    return True


def _log(c, actor, action, target, allowed, reason):
    c.execute(
        "INSERT INTO action_log(ts,actor,action,target,allowed,reason) VALUES(?,?,?,?,?,?)",
        (time.time(), actor, action, target, int(allowed), reason),
    )


def require_active(c, asset_id, actor, action):
    """Вызывать перед ЛЮБОЙ активной пробой. Бросает ScopeDenied вне VERIFIED."""
    r = c.execute("SELECT id,value,scope,kind,org_id FROM asset WHERE id=?", (asset_id,)).fetchone()
    if r is None:
        _log(c, actor, action, f"asset#{asset_id}", False, "unknown asset")
        raise ScopeDenied("unknown asset")
    if exclusions.is_excluded(c, r["org_id"], r["kind"], r["value"]):
        _log(c, actor, action, r["value"], False, "excluded")
        raise ScopeDenied(f"{r['value']}: excluded")
    if r["scope"] != VERIFIED:
        _log(c, actor, action, r["value"], False, f"scope={r['scope']}")
        raise ScopeDenied(f"{r['value']}: scope={r['scope']}, нужен VERIFIED")
    # повторная проверка непосредственно перед действием — уже здесь
    _log(c, actor, action, r["value"], True, "ok")
    return r["value"]
