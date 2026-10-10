"""Объяснимый risk engine поверх findings и контекста актива."""
from __future__ import annotations
import json, time
from . import diff

LEVELS = [
    (80, "critical"),
    (55, "high"),
    (30, "medium"),
    (10, "low"),
    (0, "info"),
]

SEV_BASE = {"critical": 70, "high": 50, "medium": 30, "low": 15, "info": 5}


def _level(score: float) -> str:
    for thr, name in LEVELS:
        if score >= thr:
            return name
    return "info"


def assess_finding(c, finding_id: int):
    f = c.execute(
        """SELECT f.*, a.value, a.scope, a.existence_conf, a.attribution_conf, a.kind akind, a.org_id
           FROM finding f JOIN asset a ON a.id=f.asset_id WHERE f.id=?""",
        (finding_id,),
    ).fetchone()
    if not f:
        return None
    factors = []
    score = float(SEV_BASE.get(f["severity"], 10))
    factors.append({"name": "severity_base", "value": f["severity"], "delta": score})

    # evidence
    try:
        obs_ids = json.loads(f["obs_ids"] or "[]")
    except Exception:
        obs_ids = []
    if obs_ids:
        score += 8
        factors.append({"name": "has_observations", "value": obs_ids, "delta": 8})
    else:
        score -= 10
        factors.append({"name": "no_direct_observations", "value": [], "delta": -10})

    if f["scope"] == "VERIFIED":
        score += 10
        factors.append({"name": "verified_asset", "delta": 10})
    elif f["scope"] == "THIRD_PARTY":
        score -= 25
        factors.append({"name": "third_party", "delta": -25})
    elif f["scope"] == "OUT_OF_SCOPE":
        score -= 40
        factors.append({"name": "out_of_scope", "delta": -40})

    attr = float(f["attribution_conf"] or 0)
    score += attr * 10
    factors.append({"name": "attribution_confidence", "value": attr, "delta": round(attr * 10, 2)})

    if f["akind"] in ("domain", "ip") and f["scope"] == "VERIFIED":
        score += 5
        factors.append({"name": "externally_relevant", "delta": 5})

    # never invent CVSS/EPSS/KEV — only if present in linked observations
    for oid in obs_ids[:10]:
        o = c.execute("SELECT key,value FROM observation WHERE id=?", (oid,)).fetchone()
        if not o:
            continue
        if o["key"] == "internetdb":
            try:
                v = json.loads(o["value"] or "{}")
            except Exception:
                v = {}
            vulns = v.get("vulns") or []
            if vulns:
                score += min(20, 5 * len(vulns))
                factors.append(
                    {
                        "name": "internetdb_vulns_hint",
                        "value": vulns[:10],
                        "delta": min(20, 5 * len(vulns)),
                        "note": "Hint from InternetDB only; not confirmed CVSS/EPSS/KEV",
                    }
                )

    score = max(0, min(100, score))
    level = _level(score)
    rationale = (
        f"Score {score:.0f}/100 → {level}. "
        + "; ".join(f"{x['name']}={x.get('delta')}" for x in factors)
    )
    rec = {
        "critical": "Немедленно проверить актив и связанные наблюдения; подтвердить или закрыть finding.",
        "high": "Приоритетно разобрать доказательства и ограничить экспозицию при необходимости.",
        "medium": "Запланировать проверку в ближайшем цикле мониторинга.",
        "low": "Учесть в backlog; мониторить повторные изменения.",
        "info": "Информационное событие; действий может не требоваться.",
    }[level]

    c.execute(
        """INSERT INTO risk_assessment(org_id,asset_id,score,level,rationale,factors_json,created)
           VALUES(?,?,?,?,?,?,?)""",
        (f["org_id"], f["asset_id"], score, level, rationale, json.dumps(factors), time.time()),
    )
    c.execute(
        "UPDATE finding SET rationale=?, recommendation=? WHERE id=?",
        (rationale, rec, finding_id),
    )
    return {
        "finding_id": finding_id,
        "score": score,
        "level": level,
        "rationale": rationale,
        "recommendation": rec,
        "factors": factors,
        "is_hypothesis": bool(f["is_hypothesis"]) if "is_hypothesis" in f.keys() else False,
        "obs_ids": obs_ids,
        "cvss": None,
        "epss": None,
        "kev": None,
        "note": "CVSS/EPSS/KEV not invented when absent from sources",
    }


def org_overview(c, org_id):
    total, top = diff.risk(c, org_id)
    by_sev = {}
    for r in c.execute(
        """SELECT f.severity, count(*) n FROM finding f JOIN asset a ON a.id=f.asset_id
           WHERE a.org_id=? AND f.state='open' GROUP BY f.severity""",
        (org_id,),
    ):
        by_sev[r["severity"]] = r["n"]
    return {"score": total, "top_assets": top[:10], "open_by_severity": by_sev}
