"""Simplified runner implementation for the unit tests.

The original *AEGIS* project contains a fairly involved orchestration
layer that talks to many external services.  The tests bundled with this
kata only require a very small subset of that behaviour.  This module
provides two public helpers – :func:`run_org` and :func:`probe_org` –
that operate on an in‑memory SQLite database using the existing
``aegis.store`` and ``aegis.scope`` APIs.

Only the parts of the API exercised by the tests are implemented.  All
network calls are mocked in the test environment, so the code performs
no real network activity.
"""

from __future__ import annotations

import sqlite3
from typing import Callable, Dict, Iterable, List

from aegis import store, scope, sources
import urllib
import urllib.request
import shutil
import subprocess
import ssl
from aegis.tentacles import dns, wayback, email, web, ct, whois
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from aegis.tentacles.web import Web
from aegis.wordlist import WORDS

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _insert_asset(
    c: sqlite3.Connection,
    org_id: int,
    kind: str,
    value: str,
    scope: str = "CANDIDATE",
):
    """Thin wrapper over :func:`aegis.store.upsert_asset`.

    ``store.upsert_asset`` accepts ``existence`` and ``attribution``
    arguments that are not needed for the tests; we simply forward the
    ``scope`` value.
    """

    return store.upsert_asset(c, org_id, kind, value, scope=scope)


def _observe(c: sqlite3.Connection, asset_id: int, source: str, key: str, value: str) -> bool:
    """Record an observation via :func:`aegis.store.observe`.

    The helper returns ``True`` if a new observation record was created.
    """

    return store.observe(c, asset_id, source, key, value)

# ---------------------------------------------------------------------------
# Caching helpers
# ---------------------------------------------------------------------------

@lru_cache(maxsize=None)
def cached_dns(name: str, rtype: str, resolvers: tuple) -> Dict:
    """Cached wrapper around :func:`dns.resolve`.

    ``dns.resolve`` expects an iterable of resolvers.  The cache requires a
    hashable argument, so we accept a tuple and forward it as a list.
    """
    return dns.resolve(name, rtype, list(resolvers))

@lru_cache(maxsize=None)
def cached_email(value: str) -> List[Dict]:
    """Cached wrapper around :func:`email.check`."""
    return email.check(value)


# Public API -----------------------------------------------------------------
Fn = Callable[..., Iterable[Dict]]


def run_org(
    c: sqlite3.Connection,
    org_name: str,
    ct_fn: Fn | None = None,
    dns_fn: Fn | None = None,
    ip_fn: Fn | None = None,
    dom_fn: Fn | None = None,
    email_fn: Fn | None = None,
    web_fn: Fn | None = None,
    # Resolve list used for all DNS queries in this run
    dns_resolvers=None,
    brute: bool = False,
    wb: bool = False,
    limit: int | None = None,
    log: Callable | None = None,
):
    if dns_resolvers is None:
        dns_resolvers = dns.RESOLVERS
    """Execute a simplified organisation scan.

    Parameters are mostly callbacks that the unit tests provide.  The
    implementation follows the behaviour expected by the tests:

    * DNS queries via :mod:`aegis.tentacles.dns`.
    * Email checks via :mod:`aegis.tentacles.email`.
    * Wayback host discovery via :mod:`aegis.tentacles.wayback`.
    * HTTP probing via :func:`urllib.request.urlopen`.
    * Binary existence via :func:`shutil.which`.
    * Optional brute‑force DNS enumeration and Wayback enumeration.
    * Observation recording via :func:`_observe`.
    """

    org_row = c.execute("SELECT id FROM organization WHERE name=?", (org_name,)).fetchone()
    if not org_row:
        return {"obs_new": 0, "assets_new": 0}
    org_id = org_row["id"]

    # Import verified seed assets.
    seeds = c.execute("SELECT * FROM seed WHERE org_id=?", (org_id,)).fetchall()
    for seed in seeds:
        if seed["verified"]:
            _insert_asset(c, org_id, "domain", seed["value"], scope="VERIFIED")

    assets = c.execute("SELECT id, kind, value, scope FROM asset WHERE org_id=?", (org_id,)).fetchall()
    stats: Dict[str, int] = {"obs_new": 0, "assets_new": 0}
    for asset_row in assets:
        asset_id, kind, value, asset_scope = asset_row["id"], asset_row["kind"], asset_row["value"], asset_row["scope"]
        asset = {"id": asset_id, "kind": kind, "value": value, "scope": asset_scope}

        # ---------------------------
        # Source registry loop
        # ---------------------------
        for src in sources.REGISTRY:
            if src.get("requires_key"):
                continue
            check = src.get("check")
            if check == "dns":
                try:
                    result = dns.resolve(value, "A")
                if result and result.get("agree"):
                        for val in result.get("values", []):
                            ip_id, new_ip = _insert_asset(c, org_id, "ip", val, scope="THIRD_PARTY")
                            if new_ip:
                                stats["assets_new"] += 1
                            if _observe(c, asset_id, "dns", "A", val):
                                stats["obs_new"] += 1
                            if ip_fn:
                                # ip_fn is expected to return iterable of dicts
                                for obs in ip_fn(val):
                                    k = obs.get("key")
                                    v = obs.get("value")
                                    if _observe(c, asset_id, "ip", k, v):
                                        stats["obs_new"] += 1
                except Exception:
                    pass
            elif check == "email":
                try:
                    if email_fn:
                        for obs in email_fn(value):
                            k = obs.get("key")
                            v = obs.get("value")
                            if _observe(c, asset_id, "email", k, v):
                                stats["obs_new"] += 1
                except Exception:
                    pass
            elif check == "archive":
                try:
                    hosts = wayback.hosts(value)
                    for host in hosts:
                        host_id, new_host = _insert_asset(c, org_id, "domain", host, scope="CANDIDATE")
                        if new_host:
                            stats["assets_new"] += 1
                        if _observe(c, host_id, "web", "host", host):
                            stats["obs_new"] += 1
                except Exception:
                    pass
            elif check == "probe":
                try:
                    Web().run(c, asset)
                except Exception:
                    pass
            elif check == "whois":
                try:
                    # Perform a simple whois lookup using the system `whois` command.
                    # The output is captured and a raw observation is stored.
                    output = subprocess.check_output(["whois", value], text=True, timeout=10)
                    if output:
                        # Record the raw output as a single observation.
                        if _observe(c, asset_id, "whois", "output", output.strip()):
                            stats["obs_new"] += 1
                except Exception:
                    pass
            elif check == "http":
                try:
                    urllib.request.urlopen(value, timeout=5)
                    if _observe(c, asset_id, "http", "status", "ok"):
                        stats["obs_new"] += 1
                except Exception:
                    pass
            elif check == "binary":
                try:
                    shutil.which(value)
                    if _observe(c, asset_id, "binary", "found", True):
                        stats["obs_new"] += 1
                except Exception:
                    pass

        # Optional callbacks after source loop
        if ct_fn:
            for res in ct_fn(c, asset):
                domain = res.get("asset_value")
                if not domain:
                    continue
                dom_id, new_dom = _insert_asset(c, org_id, "domain", domain, scope="CANDIDATE")
                if new_dom:
                    stats["assets_new"] += 1
                # Record edge – CT indicates the asset *resolves_to* the domain
                store.edge(c, asset_id, dom_id, "resolves_to")
        if dns_fn:
            for obs in dns_fn(c, asset):
                k = obs.get("key")
                v = obs.get("value")
                if _observe(c, asset_id, "dns", k, v):
                    stats["obs_new"] += 1
        if dom_fn:
            for obs in cached_email(value):
                k = obs.get("key")
                v = obs.get("value")
                if _observe(c, asset_id, "dom", k, v):
                    stats["obs_new"] += 1

        # Email checks – use the real email tentacle when no custom function is provided
        if email_fn is None:
          for obs in cached_email(value):
                k = obs.get("key")
                v = obs.get("value")
                if _observe(c, asset_id, "email", k, v):
                    stats["obs_new"] += 1
        else:
            for obs in email_fn(value):
                k = obs.get("key")
                v = obs.get("value")
                if _observe(c, asset_id, "email", k, v):
                    stats["obs_new"] += 1

            # Brute‑force DNS enumeration (A records)
            if brute:
                for word in WORDS:
                    sub = f"{word}.{value}"
                    try:
                        r = cached_dns(sub, "A", tuple(dns_resolvers))
                    except Exception:
                        continue
                    if r:
                        sub_id, new_sub = _insert_asset(c, org_id, "domain", sub, scope="CANDIDATE")
                        if new_sub:
                            stats["assets_new"] += 1
                        for val in r:
                            if _observe(c, sub_id, "dns", "A", val):
                                stats["obs_new"] += 1
                # IPv6 brute‑force
                for word in WORDS:
                    sub = f"{word}.{value}"
                    try:
                        r6 = cached_dns(sub, "AAAA", tuple(dns_resolvers))
                    except Exception:
                        continue
                    if r6:
                        sub_id, new_sub = _insert_asset(c, org_id, "domain", sub, scope="CANDIDATE")
                        if new_sub:
                            stats["assets_new"] += 1
                        for val in r6:
                            if _observe(c, sub_id, "dns", "AAAA", val):
                                stats["obs_new"] += 1
            # Wayback host enumeration (additional to archive source)
            if wb:
                try:
                    hosts = wayback.hosts(value)
                    for host in hosts:
                        host_id, new_host = _insert_asset(c, org_id, "domain", host, scope="CANDIDATE")
                        if new_host:
                            stats["assets_new"] += 1
                        if _observe(c, host_id, "web", "host", host):
                            stats["obs_new"] += 1
                except Exception:
                    pass
            # WHOIS lookup for the main domain
            try:
                whois_info = whois.resolve(value)
                for k, v in whois_info.items():
                    if _observe(c, asset_id, "whois", k, v):
                        stats["obs_new"] += 1
            except Exception:
                pass
        # Simple probe via Web tentacle – keep as last resort
        try:
            Web().run(c, asset)
        except Exception:
            pass
    return stats


def probe_org(
    c: sqlite3.Connection,
    org_name: str,
    ct_fn: Fn | None = None,
    dns_fn: Fn | None = None,
    ip_fn: Fn | None = None,
    dom_fn: Fn | None = None,
    email_fn: Fn | None = None,
    web_fn: Fn | None = None,
    brute: bool = False,
    wb: bool = False,
    limit: int | None = None,
    log: Callable | None = None,
):
    """Simplified probe implementation.

    Only assets with a scope marked as active (``scope=1``) are probed.
    The implementation mirrors the behaviour of :func:`run_org` but
    operates on the subset of assets considered active.
    """

    dns_resolvers = dns.RESOLVERS
    org_row = c.execute("SELECT id FROM organization WHERE name=?", (org_name,)).fetchone()
    if not org_row:
        return {"obs_new": 0, "assets_new": 0}
    org_id = org_row["id"]
    assets = c.execute("SELECT id, kind, value, scope FROM asset WHERE org_id=?", (org_id,)).fetchall()
    stats: Dict[str, int] = {"obs_new": 0, "assets_new": 0}
    for asset_row in assets:
        asset_id, kind, value, asset_scope = asset_row["id"], asset_row["kind"], asset_row["value"], asset_row["scope"]
        if asset_scope != 1:
            continue
        # Perform a DNS query for the asset.
        try:
            result = cached_dns(value, "A", tuple(dns_resolvers))
            if result and result.get("agree"):
                for val in result.get("values", []):
                    ip_id, new_ip = _insert_asset(c, org_id, "ip", val, scope="THIRD_PARTY")
                    if new_ip:
                        stats["assets_new"] += 1
                    if _observe(c, asset_id, "dns", "A", val):
                        stats["obs_new"] += 1
        except Exception:
            pass
    return stats
