"""Локальный AI-аналитик: объясняет только с цитатами на реальные ID."""
from __future__ import annotations
import json, re, time, urllib.request
from . import config, db, llm, digest

SYS_CHAT = (
    "Ты локальный аналитик внешней поверхности атаки AEGIS. "
    "Используй ТОЛЬКО переданный CONTEXT. Не выдумывай активы, CVE, IP, домены, findings. "
    "Каждое существенное утверждение снабжай cites — списком ID вида obs:123, finding:45, asset:7. "
    "Если данных недостаточно — явно скажи об этом. Не предлагай эксплуатацию, brute force или обход защит. "
    "Ответ строго JSON: {\"answer\": str, \"cites\": [str], \"insufficient\": bool}."
)


def ollama_status():
    try:
        r = urllib.request.urlopen(config.OLLAMA_URL + "/api/tags", timeout=3)
        models = [m["name"] for m in json.load(r).get("models", [])]
        preferred = config.MODEL
        has_preferred = any(preferred == m or m.startswith(preferred.split(":")[0]) for m in models)
        return {
            "available": True,
            "url": config.OLLAMA_URL,
            "models": models,
            "configured_model": preferred,
            "preferred_present": has_preferred or preferred in models,
            "warning": None
            if (has_preferred or preferred in models)
            else f"Configured model {preferred} not installed; refuse silent downgrade",
        }
    except Exception as e:
        return {
            "available": False,
            "url": config.OLLAMA_URL,
            "models": [],
            "configured_model": config.MODEL,
            "preferred_present": False,
            "warning": type(e).__name__,
        }


def _context(c, org_id, limit_findings=30, limit_assets=40):
    facts = []
    for f in c.execute(
        """SELECT f.id,f.kind,f.severity,f.state,f.text,f.obs_ids,a.id aid,a.value
           FROM finding f JOIN asset a ON a.id=f.asset_id
           WHERE a.org_id=? ORDER BY f.id DESC LIMIT ?""",
        (org_id, limit_findings),
    ):
        facts.append(
            f"finding:{f['id']} [{f['severity']}] {f['kind']} state={f['state']} asset:{f['aid']} {f['value']}: {f['text']}"
        )
    for a in c.execute(
        """SELECT id,kind,value,scope FROM asset WHERE org_id=? ORDER BY last_seen DESC LIMIT ?""",
        (org_id, limit_assets),
    ):
        facts.append(f"asset:{a['id']} {a['kind']} {a['value']} scope={a['scope']}")
    for o in c.execute(
        """SELECT o.id,o.source,o.key,o.evidence_hash,a.id aid,a.value
           FROM observation o JOIN asset a ON a.id=o.asset_id
           WHERE a.org_id=? ORDER BY o.id DESC LIMIT 40""",
        (org_id,),
    ):
        facts.append(
            f"obs:{o['id']} source={o['source']} key={o['key']} asset:{o['aid']} {o['value']} hash={o['evidence_hash']}"
        )
    return facts


_CITE = re.compile(r"^(obs|finding|asset):(\d+)$")


def _validate_cites(c, org_id, cites):
    ok = []
    for cite in cites or []:
        m = _CITE.match(str(cite).strip())
        if not m:
            continue
        kind, i = m.group(1), int(m.group(2))
        if kind == "obs":
            r = c.execute(
                "SELECT o.id FROM observation o JOIN asset a ON a.id=o.asset_id WHERE o.id=? AND a.org_id=?",
                (i, org_id),
            ).fetchone()
        elif kind == "finding":
            r = c.execute(
                "SELECT f.id FROM finding f JOIN asset a ON a.id=f.asset_id WHERE f.id=? AND a.org_id=?",
                (i, org_id),
            ).fetchone()
        else:
            r = c.execute("SELECT id FROM asset WHERE id=? AND org_id=?", (i, org_id)).fetchone()
        if r:
            ok.append(f"{kind}:{i}")
    return ok


def ask(c, org_id, question: str, llm_fn=None):
    st = ollama_status()
    if not st["available"]:
        return {
            "answer": "Локальная модель недоступна. Установите Ollama и загрузите модель, либо работайте без AI.",
            "cites": [],
            "insufficient": True,
            "model": None,
            "error": st["warning"],
        }
    if not st["preferred_present"]:
        return {
            "answer": (
                f"Настроенная модель `{st['configured_model']}` не найдена среди установленных: "
                f"{', '.join(st['models']) or 'нет моделей'}. "
                f"Выполните `ollama pull {st['configured_model']}` или измените AEGIS_MODEL. "
                "Автоматический переход на меньшую модель отключён."
            ),
            "cites": [],
            "insufficient": True,
            "model": st["configured_model"],
            "error": "model_missing",
        }

    ctx = _context(c, org_id)
    if not ctx:
        return {
            "answer": "Недостаточно данных: у организации пока нет активов, наблюдений или findings.",
            "cites": [],
            "insufficient": True,
            "model": st["configured_model"],
            "error": None,
        }

    user = "CONTEXT:\n" + "\n".join(ctx) + "\n\nQUESTION:\n" + question[:4000]
    try:
        data = (llm_fn or llm.chat_json)(SYS_CHAT, user)
    except Exception as e:
        return {
            "answer": f"Ошибка обращения к Ollama: {type(e).__name__}",
            "cites": [],
            "insufficient": True,
            "model": st["configured_model"],
            "error": str(e)[:200],
        }

    cites = _validate_cites(c, org_id, data.get("cites") or [])
    answer = (data.get("answer") or "").strip()
    if not answer:
        answer = "Модель вернула пустой ответ."
    # drop invented entity tokens not present in context when no cites
    if data.get("insufficient") or not cites:
        if not cites:
            answer = answer + "\n\n(Недостаточно подтверждённых ссылок на наблюдения/findings в базе.)"

    c.execute(
        "INSERT INTO ai_analysis(org_id,kind,question,answer,cites_json,model,created) VALUES(?,?,?,?,?,?,?)",
        (org_id, "chat", question, answer, json.dumps(cites), st["configured_model"], time.time()),
    )
    return {
        "answer": answer,
        "cites": cites,
        "insufficient": bool(data.get("insufficient")) or not cites,
        "model": st["configured_model"],
        "error": None,
    }


def explain_finding(c, finding_id):
    f = c.execute(
        """SELECT f.*, a.org_id, a.value aval FROM finding f JOIN asset a ON a.id=f.asset_id WHERE f.id=?""",
        (finding_id,),
    ).fetchone()
    if not f:
        return {"error": "not found"}
    q = f"Объясни finding:{f['id']} простым языком и что проверить оператору. Текст: {f['text']}"
    return ask(c, f["org_id"], q)
