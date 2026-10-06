"""Scope-ядро: активные пробы разрешены только по VERIFIED. Каждое решение — в журнал."""
import time
VERIFIED, CANDIDATE, THIRD_PARTY, OUT_OF_SCOPE = "VERIFIED", "CANDIDATE", "THIRD_PARTY", "OUT_OF_SCOPE"
STATES = {VERIFIED, CANDIDATE, THIRD_PARTY, OUT_OF_SCOPE}

class ScopeDenied(Exception): pass

def set_scope(c, asset_id, state):
    if state not in STATES: raise ValueError(state)
    c.execute("UPDATE asset SET scope=? WHERE id=?", (state, asset_id))

def _log(c, actor, action, target, allowed, reason):
    c.execute("INSERT INTO action_log(ts,actor,action,target,allowed,reason) VALUES(?,?,?,?,?,?)",
              (time.time(), actor, action, target, int(allowed), reason))

def require_active(c, asset_id, actor, action):
    """Вызывать перед ЛЮБОЙ активной пробой. Бросает ScopeDenied вне VERIFIED."""
    r = c.execute("SELECT value,scope FROM asset WHERE id=?", (asset_id,)).fetchone()
    if r is None:
        _log(c, actor, action, f"asset#{asset_id}", False, "unknown asset"); raise ScopeDenied("unknown asset")
    if r["scope"] != VERIFIED:
        _log(c, actor, action, r["value"], False, f"scope={r['scope']}")
        raise ScopeDenied(f"{r['value']}: scope={r['scope']}, нужен VERIFIED")
    _log(c, actor, action, r["value"], True, "ok")
    return r["value"]
