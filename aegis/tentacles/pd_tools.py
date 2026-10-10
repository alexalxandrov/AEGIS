"""Опциональные адаптеры ProjectDiscovery / Amass. Без бинарника — деградация, не падение."""
from __future__ import annotations
import json, shutil, subprocess
from .. import store


def _run_json_lines(cmd, timeout=120):
    if not shutil.which(cmd[0]):
        raise FileNotFoundError(cmd[0])
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if p.returncode not in (0, 1):
        raise RuntimeError((p.stderr or p.stdout or f"exit {p.returncode}")[:300])
    out = []
    for line in (p.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            out.append({"host": line})
    return out


def available(name: str) -> bool:
    return bool(shutil.which(name))


def enrich_subfinder(c, org_id, org_name, limit=300):
    """Пассивный subfinder по seed-доменам. Возвращает число новых активов."""
    if not available("subfinder"):
        raise FileNotFoundError("subfinder")
    seeds = c.execute(
        "SELECT value FROM seed WHERE org_id=? AND kind='domain'", (org_id,)
    ).fetchall()
    new_total = 0
    for s in seeds:
        domain = s["value"].lower()
        try:
            rows = _run_json_lines(
                ["subfinder", "-d", domain, "-silent", "-json", "-timeout", "30"],
                timeout=90,
            )
        except Exception:
            # fallback: plain lines
            p = subprocess.run(
                ["subfinder", "-d", domain, "-silent", "-timeout", "30"],
                capture_output=True,
                text=True,
                timeout=90,
            )
            rows = [{"host": l.strip()} for l in p.stdout.splitlines() if l.strip()]
        seed_asset = c.execute(
            "SELECT id FROM asset WHERE org_id=? AND kind='domain' AND value=?",
            (org_id, domain),
        ).fetchone()
        for i, row in enumerate(rows[:limit]):
            host = (row.get("host") or row.get("fqdn") or "").lower().rstrip(".")
            if not host or not (host == domain or host.endswith("." + domain)):
                continue
            aid, is_new = store.upsert_asset(c, org_id, "domain", host, existence=0.75, attribution=0.55)
            new_total += int(is_new)
            store.observe(c, aid, "subfinder", "discovered", True)
            if seed_asset and aid != seed_asset["id"]:
                store.edge(c, seed_asset["id"], aid, "has_subdomain")
    return new_total


def probe_httpx(hosts, timeout=60):
    """Активный httpx — вызывающий код обязан проверить scope."""
    if not available("httpx"):
        raise FileNotFoundError("httpx")
    if not hosts:
        return []
    # stdin list, JSON output
    p = subprocess.run(
        ["httpx", "-silent", "-json", "-timeout", "5", "-retries", "1"],
        input="\n".join(hosts),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    out = []
    for line in (p.stdout or "").splitlines():
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out
