"""Клиент Ollama (нативный, без docker)."""
import json, urllib.request, urllib.error
from . import config

def _post(body):
    req = urllib.request.Request(config.OLLAMA_URL + "/api/chat", json.dumps(body).encode(), {"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=config.LLM_TIMEOUT))

def chat_json(system, user):
    body = {"model": config.MODEL, "stream": False, "format": "json", "think": "low", "options": {"temperature": 0.1, "num_predict": 3000},
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
    try: r = _post(body)
    except urllib.error.HTTPError as e:
        if e.code != 400: raise
        body.pop("think"); r = _post(body)  # старая версия Ollama без параметра think
    t = r["message"]["content"].strip()
    t = t[t.find("{"): t.rfind("}") + 1]
    return json.loads(t)
