"""LLM-дайджест с проверкой: каждое утверждение обязано ссылаться на факты, а IP/домены/числа — совпадать с ними."""
import re, json, time, datetime
from . import diff, config

SYS = ("Ты аналитик внешней поверхности атаки. Используй ТОЛЬКО перечисленные факты. Ничего не выдумывай: "
       "не добавляй IP, домены, порты, числа и CVE, которых нет в цитируемых фактах. Описывай только наблюдаемое: не делай предположений о назначении, причинах и взломе (никаких \"может быть backdoor\"). Severity пункта не выше severity цитируемых фактов. Каждый пункт обязан содержать cites — список id фактов (например [\"F1\",\"F3\"]). "
       "Пиши по-русски, кратко. Ответ строго JSON: {\"summary\": str, \"items\": [{\"text\": str, \"severity\": \"critical|high|medium|low|info\", \"cites\": [str]}], "
       "\"next_steps\": [{\"text\": str, \"cites\": [str]}]}. summary — 1-2 предложения без новых чисел.")

def snapshot(c, org_id, cap=30):
    out = []
    for a in c.execute("SELECT id,kind,value,scope FROM asset WHERE org_id=? AND kind IN ('domain','ip') ORDER BY (scope='VERIFIED') DESC, id LIMIT ?", (org_id, cap)):
        parts = []
        for r in c.execute("SELECT key,value FROM observation WHERE asset_id=? AND id IN (SELECT MAX(id) FROM observation WHERE asset_id=? GROUP BY source,key)", (a["id"], a["id"])):
            v = json.loads(r["value"]) if r["value"] else None
            if r["key"] in ("dns_A", "dns_AAAA"): parts.append(f"{r['key'][4:]}={v}")
            elif r["key"] == "internetdb" and v: parts.append(f"порты={v.get('ports')}")
            elif r["key"] == "tls" and v: parts.append(f"tls издатель={v.get('issuer')} до={v.get('not_after')}" if v.get("valid") else f"tls ошибка={v.get('error')}")
            elif r["key"] in ("http_443", "http_80") and v and "status" in v: parts.append(f"{r['key']} статус={v['status']}")
        out.append(f"{a['kind']} {a['value']} (scope={a['scope']}): " + "; ".join(parts))
    return out

def build_facts(c, org_id, hours):
    ev = sorted(diff.visible(c, diff.compute(c, org_id, time.time() - hours * 3600)), key=lambda e: diff.ORDER[e["severity"]])
    facts = [f"[{e['severity']}] {e['kind']}: {e['text']}" for e in ev[:50]] + snapshot(c, org_id)
    return {f"F{i}": t for i, t in enumerate(facts, 1)}

ENT = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b|\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\b|\b\d{2,5}\b|CVE-\d+-\d+", re.I)

def validate(data, facts):
    """Возвращает (items, next_steps, dropped_count). Отбрасывает пункты без ссылок или с неподтверждёнными сущностями."""
    dropped = 0
    def ok(x):
        cites = [k for k in x.get("cites", []) if k in facts]
        if not cites or not x.get("text"): return False
        src = " ".join(facts[k] for k in cites).lower()
        return all(m.lower() in src for m in ENT.findall(x["text"]))
    def cap(i):  # severity пункта не может быть выше, чем у цитируемых фактов
        sev = [diff.ORDER[m.group(1)] for k in i["cites"] if k in facts and (m := re.match(r"\[(\w+)\]", facts[k])) and m.group(1) in diff.ORDER]
        lim = min(sev) if sev else diff.ORDER["info"]
        if diff.ORDER.get(i.get("severity", "info"), 4) < lim: i["severity"] = {v: k for k, v in diff.ORDER.items()}[lim]
        return i
    items = [cap(i) for i in data.get("items", []) if ok(i) or not (dropped := dropped + 1)]
    steps = [i for i in data.get("next_steps", []) if ok(i) or not (dropped := dropped + 1)]
    return items, steps, dropped

def plain(facts):
    return "\n".join(f"- {t}" for k, t in facts.items() if t.startswith("["))

def render(summary, items, steps, facts, note=""):
    from .diff import ORDER
    L = [f"# AEGIS — дайджест {datetime.date.today()}", "", summary or "", ""]
    for i in sorted(items, key=lambda i: ORDER.get(i.get("severity", "info"), 4)):
        L.append(f"- **{i.get('severity','info')}**: {i['text']} {i['cites']}")
    if steps: L += ["", "## Что сделать"] + [f"- {s['text']} {s['cites']}" for s in steps]
    L += ["", "## Факты-источники"] + [f"- {k}: {v}" for k, v in facts.items() if k in {c for i in items + steps for c in i["cites"]}]
    if note: L += ["", f"_{note}_"]
    return "\n".join(L)

def make(c, org_id, hours=48, llm_fn=None, use_llm=True):
    facts = build_facts(c, org_id, hours)
    if not use_llm:
        return "# AEGIS — события (без LLM)\n\n" + plain(facts)
    try:
        from . import llm
        data = (llm_fn or llm.chat_json)(SYS, "ФАКТЫ:\n" + "\n".join(f"{k}: {v}" for k, v in facts.items()))
    except Exception as e:
        return f"# AEGIS — события (LLM недоступна: {type(e).__name__})\n\n" + plain(facts)
    items, steps, dropped = validate(data, facts)
    if not items:
        return "# AEGIS — события (ответ LLM не прошёл проверку)\n\n" + plain(facts)
    return render(data.get("summary", ""), items, steps, facts, f"Проверка: отброшено пунктов — {dropped}" if dropped else "Проверка цитат пройдена")
