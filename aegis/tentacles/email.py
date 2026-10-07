"""Пассивная проверка почтовой защиты домена: SPF, DMARC, DKIM-селекторы (частые)."""
from . import dns as dnsmod

DKIM_SELECTORS = ["google", "selector1", "selector2", "default", "k1", "s1", "dkim"]

def check(name):
    out = {"spf": None, "dmarc": None, "dkim": []}
    for v in dnsmod.resolve(name, "TXT")["values"]:
        if v.strip('"').lower().startswith("v=spf1"): out["spf"] = v.strip('"')
    for v in dnsmod.resolve("_dmarc." + name, "TXT")["values"]:
        if v.strip('"').lower().startswith("v=dmarc1"): out["dmarc"] = v.strip('"')
    for sel in DKIM_SELECTORS:
        if dnsmod.resolve(f"{sel}._domainkey.{name}", "TXT")["values"]: out["dkim"].append(sel)
    return out
