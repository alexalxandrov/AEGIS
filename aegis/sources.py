"""Реестр источников: метаданные, health, graceful degradation."""
from __future__ import annotations
import json, shutil, subprocess, time, urllib.request
from . import config, db

REGISTRY = [
    {
        "name": "crt.sh",
        "category": "certificate_transparency",
        "mode": "passive",
        "requires_key": 0,
        "license_note": "Public CT search; rate limits apply",
        "capabilities": ["subdomain_discovery", "certificate_history"],
        "check": "http",
        "url": "https://crt.sh/?q=example.com&output=json",
    },
    {
        "name": "certspotter",
        "category": "certificate_transparency",
        "mode": "passive",
        "requires_key": 0,
        "license_note": "Public API with rate limits",
        "capabilities": ["subdomain_discovery"],
        "check": "http",
        "url": "https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names",
    },
    {
        "name": "dns",
        "category": "dns",
        "mode": "passive",
        "requires_key": 0,
        "license_note": "Public resolvers / system resolver",
        "capabilities": ["dns_resolve", "disagreement_detection"],
        "check": "builtin",
    },
    {
        "name": "rdap",
        "category": "whois",
        "mode": "passive",
        "requires_key": 0,
        "license_note": "RDAP public",
        "capabilities": ["domain_registration"],
        "check": "http",
        "url": "https://rdap.org/domain/example.com",
    },
    {
        "name": "ripestat",
        "category": "bgp",
        "mode": "passive",
        "requires_key": 0,
        "license_note": "RIPEstat terms",
        "capabilities": ["asn", "prefix"],
        "check": "http",
        "url": "https://stat.ripe.net/data/as-overview/data.json?resource=AS3333",
    },
    {
        "name": "internetdb",
        "category": "ports",
        "mode": "passive",
        "requires_key": 0,
        "license_note": "Shodan InternetDB free",
        "capabilities": ["ports", "cves_hint"],
        "check": "http",
        "url": "https://internetdb.shodan.io/1.1.1.1",
    },
    {
        "name": "wayback",
        "category": "archive",
        "mode": "passive",
        "requires_key": 0,
        "license_note": "Internet Archive CDX",
        "capabilities": ["historical_hosts"],
        "check": "http",
        "url": "https://web.archive.org/cdx/search/cdx?url=example.com&limit=1",
    },
    {
        "name": "email_policy",
        "category": "email",
        "mode": "passive",
        "requires_key": 0,
        "license_note": "DNS TXT lookups",
        "capabilities": ["spf", "dmarc", "dkim"],
        "check": "builtin",
    },
    {
        "name": "http_tls",
        "category": "active_probe",
        "mode": "active",
        "requires_key": 0,
        "license_note": "Operator-authorized probes only",
        "capabilities": ["http_headers", "tls_cert"],
        "check": "builtin",
    },
    {
        "name": "ollama",
        "category": "ai",
        "mode": "local",
        "requires_key": 0,
        "license_note": "Local only; data stays on host",
        "capabilities": ["explain", "summarize"],
        "check": "ollama",
    },
    {
        "name": "subfinder",
        "category": "projectdiscovery",
        "mode": "passive",
        "requires_key": 0,
        "license_note": "MIT; optional binary",
        "capabilities": ["subdomain_discovery"],
        "check": "binary",
        "binary": "subfinder",
    },
    {
        "name": "dnsx",
        "category": "projectdiscovery",
        "mode": "passive",
        "requires_key": 0,
        "license_note": "MIT; optional binary",
        "capabilities": ["dns_resolve"],
        "check": "binary",
        "binary": "dnsx",
    },
    {
        "name": "httpx",
        "category": "projectdiscovery",
        "mode": "active",
        "requires_key": 0,
        "license_note": "MIT; optional; VERIFIED only",
        "capabilities": ["http_probe"],
        "check": "binary",
        "binary": "httpx",
    },
    {
        "name": "nuclei",
        "category": "projectdiscovery",
        "mode": "active",
        "requires_key": 0,
        "license_note": "MIT; safe profiles only; operator opt-in",
        "capabilities": ["misconfig_detect"],
        "check": "binary",
        "binary": "nuclei",
    },
    {
        "name": "naabu",
        "category": "projectdiscovery",
        "mode": "active",
        "requires_key": 0,
        "license_note": "MIT; disabled by default",
        "capabilities": ["port_scan"],
        "check": "binary",
        "binary": "naabu",
    },
    {
        "name": "amass",
        "category": "osint",
        "mode": "passive",
        "requires_key": 0,
        "license_note": "Apache-2.0; optional binary",
        "capabilities": ["subdomain_discovery"],
        "check": "binary",
        "binary": "amass",
    },
]


def _bin_version(name: str):
    path = shutil.which(name)
    if not path:
        return None, "binary not found"
    try:
        p = subprocess.run([name, "-version"], capture_output=True, text=True, timeout=5)
        out = (p.stdout or p.stderr or "").strip().splitlines()
        ver = out[0][:120] if out else "installed"
        if p.returncode != 0 and not out:
            p2 = subprocess.run([name, "--help"], capture_output=True, text=True, timeout=5)
            if p2.returncode not in (0, 1, 2) and not (p2.stdout or p2.stderr):
                return None, f"unusable binary (exit {p.returncode})"
            ver = "installed"
        return ver, ""
    except Exception as e:
        return None, type(e).__name__


def _http_ok(url: str):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": config.USER_AGENT})
        urllib.request.urlopen(req, timeout=min(config.HTTP_TIMEOUT, 8))
        return True, ""
    except Exception as e:
        return False, type(e).__name__


def _ollama():
    try:
        r = urllib.request.urlopen(config.OLLAMA_URL + "/api/tags", timeout=3)
        names = [m["name"] for m in json.load(r).get("models", [])]
        return True, ",".join(names) if names else "no models"
    except Exception as e:
        return False, type(e).__name__


def ensure_registry(c):
    for s in REGISTRY:
        c.execute(
            """INSERT INTO source_registry(name,category,mode,available,requires_key,license_note,capabilities,meta_json)
               VALUES(?,?,?,?,?,?,?,?)
               ON CONFLICT(name) DO UPDATE SET
                 category=excluded.category, mode=excluded.mode, requires_key=excluded.requires_key,
                 license_note=excluded.license_note, capabilities=excluded.capabilities""",
            (
                s["name"],
                s["category"],
                s["mode"],
                0,
                s["requires_key"],
                s["license_note"],
                json.dumps(s["capabilities"]),
                json.dumps({"check": s["check"], "binary": s.get("binary"), "url": s.get("url")}),
            ),
        )


def probe_source(s: dict):
    kind = s["check"]
    if kind == "builtin":
        return True, "builtin", ""
    if kind == "http":
        ok, note = _http_ok(s["url"])
        return ok, "", note
    if kind == "ollama":
        ok, note = _ollama()
        return ok, note if ok else "", note if not ok else ""
    if kind == "binary":
        ver, err = _bin_version(s["binary"])
        return bool(ver), ver or "", err
    return False, "", "unknown check"


def refresh(c=None, network=True):
    own = c is None
    if own:
        c = db.connect()
    ensure_registry(c)
    results = []
    for s in REGISTRY:
        if not network and s["check"] in ("http", "ollama"):
            available, version, err = False, "", "skipped (offline check)"
        else:
            available, version, err = probe_source(s)
        now = time.time()
        c.execute(
            """UPDATE source_registry SET available=?, version=?, last_ok=CASE WHEN ? THEN ? ELSE last_ok END,
               last_error=? WHERE name=?""",
            (int(available), version or None, int(available), now, err or None, s["name"]),
        )
        c.execute(
            "INSERT OR REPLACE INTO source_health VALUES(?,?,?,?)",
            (s["name"], int(available), now, err or version or ""),
        )
        results.append({"name": s["name"], "available": available, "version": version, "error": err})
    return results


def list_sources(c):
    ensure_registry(c)
    rows = c.execute("SELECT * FROM source_registry ORDER BY category, name").fetchall()
    out = []
    for r in rows:
        d = db.row_to_dict(r)
        try:
            d["capabilities"] = json.loads(d["capabilities"] or "[]")
        except Exception:
            d["capabilities"] = []
        try:
            d["meta"] = json.loads(d.pop("meta_json") or "{}")
        except Exception:
            d["meta"] = {}
        out.append(d)
    return out
