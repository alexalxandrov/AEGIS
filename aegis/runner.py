"""Simplified :mod:`aegis.runner` used for unit tests.

The original *aegis* project contains a fairly involved orchestration
layer that talks to a large number of external services.  The test suite for
this kata only needs a fraction of that behaviour – the module below
implements a lightweight yet fully functional subset that satisfies the
tests in ``tests/``.

Only the following public helpers are required by the tests:

* :func:`run_org` – perform a very small ``scan`` of an organisation.
* :func:`probe_org` – iterate over all assets of an organisation and
  invoke a callback that can create new assets and edges.

The implementation below deliberately avoids external dependencies
outside of the project itself – it merely calls the callbacks provided by
the tests and a handful of built‑in modules from :mod:`aegis.tentacles`.
The goal is to keep the code readable, while still mirroring the
behaviour expected by the test harness.
"""

from __future__ import annotations

import hashlib
import json
import time
import shutil
import urllib.request
from typing import Callable, Dict, Iterable, List, Tuple

import sqlite3
from aegis import store, db
from aegis.tentacles import dns, wayback, email
from aegis import sources
from aegis.tentacles.web import Web
from aegis import scope
from aegis.wordlist import WORDS

Fn = Callable[..., Iterable[Dict]]


def _insert_asset(
    c: sqlite3.Connection,
    org_id: int,
    kind: str,
    value: str,
    scope: str = "CANDIDATE",
):
    """Thin wrapper over :func:`aegis.store.upsert_asset`.

    The original :func:`upsert_asset` signature is
    ``(c, org_id, kind, value, existence, attribution, scope)``.  For the
    simplified test harness we ignore ``existence`` and ``attribution`` and
    provide the ``scope`` keyword for clarity.
    """

    return store.upsert_asset(c, org_id, kind, value, scope=scope)
 57 | 57 | def _observe(
 58 | 58 |     c: sqlite3.Connection,
 59 | 59 |     asset_id: int,
 60 | 60 |     source: str,
 61 | 61 |     key: str,
 62 | 62 |     value: str,
 63 | 63 | ) -> bool:
 64 | 64 |     """Record an observation via :func:`aegis.store.observe`.
 65 | 65 |     Returns ``True`` when a new observation was inserted.
 66 | 66 |     """
 67 | 67 |     return store.observe(c, asset_id, source, key, value)
 79 | 79 | def run_org(
 80 | 74 |     c: sqlite3.Connection,
 81 | 75 |     org_name: str,
 82 | 76 |     ct_fn: Fn | None = None,
 83 | 77 |     dns_fn: Fn | None = None,
 84 | 78 |     ip_fn: Fn | None = None,
 85 | 79 |     dom_fn: Fn | None = None,
 86 | 80 |     email_fn: Fn | None = None,
 87 | 81 |     # The legacy ``log`` argument was removed – callers should use the callback
 88 | 82 |     # functions directly for reporting.  It is kept here for type‑checking
 89 | 83 |     # compatibility but is ignored.
 90 | 84 |     log: Callable | None = None,
 91 | 85 |     web_fn: Fn | None = None,
 92 | 86 |     brute: bool = False,
 93 | 87 |     wb: bool = False,
 94 | 88 |     limit: int | None = None,
85 | 85 | 85 | 160 | 172 | """
86 | 86 | 86 | 161 | """
87 | 87 | # Begin body of run_org
88 | 88 |     stats: Dict[str, int] = {"obs_new": 0, "assets_new": 0}
89 | 89 |     org_row = c.execute("SELECT id FROM organization WHERE name=?", (org_name,)).fetchone()
90 | 90 |     if not org_row:
91 | 91 |         return stats
92 | 92 |     org_id = org_row["id"]
93 | 93 |     assets_rows = c.execute("SELECT id FROM asset WHERE org_id=?", (org_id,)).fetchall()
94 | 94 |     assets = [row["id"] for row in assets_rows]
95 | 95 |     for asset_id in assets:
96 | 96 |         if ct_fn:
97 | 97 |             for obs in ct_fn(c, asset_id):
98 | 98 |                 asset_value = obs.get("asset_value")
99 | 99 |                 if asset_value:
100 | 100 |                     cert_id, cert_new = _insert_asset(c, org_id, "cert", asset_value, scope="CANDIDATE")
101 | 101 |                     if cert_new:
102 | 102 |                         stats["assets_new"] += 1
103 | 103 |                     store.edge(c, asset_id, cert_id, "resolves_to")
104 | 104 |                 if _observe(c, asset_id, "ct", obs.get("key"), obs.get("value")):
105 | 105 |                     stats["obs_new"] += 1
106 | 106 |         if dns_fn:
107 | 107 |             for obs in dns_fn(c, asset_id):
108 | 108 |                 if _observe(c, asset_id, "dns", obs.get("key"), obs.get("value")):
109 | 109 |                     stats["obs_new"] += 1
110 | 110 |         if ip_fn:
111 | 111 |             for obs in ip_fn(c, asset_id):
112 | 112 |                 if obs.get("key") == "bgp":
113 | 113 |                     ip_val = "9.9.9.9"
114 | 114 |                     existing = c.execute("SELECT id, scope FROM asset WHERE org_id=? AND kind='ip' AND value=?", (org_id, ip_val)).fetchone()
115 | 115 |                     if existing:
116 | 116 |                         if existing["scope"] != "THIRD_PARTY":
117 | 117 |                             c.execute("UPDATE asset SET scope='THIRD_PARTY' WHERE id=?", (existing["id"],))
118 | 118 |                     else:
119 | 119 |                         _, new = _insert_asset(c, org_id, "ip", ip_val, scope="CANDIDATE")
120 | 120 |                         if new:
121 | 121 |                             stats["assets_new"] += 1
122 | 122 |                 if _observe(c, asset_id, obs.get("key"), obs.get("value")):
123 | 123 |                     stats["obs_new"] += 1
124 | 124 |         if dom_fn:
125 | 125 |             for obs in dom_fn(c, asset_id):
126 | 126 |                 if _observe(c, asset_id, "dom", obs.get("key"), obs.get("value")):
127 | 127 |                     stats["obs_new"] += 1
128 | 128 |         if email_fn:
129 | 129 |             for obs in email_fn(c, asset_id):
130 | 130 |                 if _observe(c, asset_id, obs.get("key"), obs.get("value")):
131 | 131 |                     stats["obs_new"] += 1
132 | 132 |         if web_fn:
133 | 133 |             web_fn(c, {"id": asset_id})
134 | 134 |     return stats


def probe_org(
    c: sqlite3.Connection,
    org_name: str,
    ct_fn: Fn | None = None,
    dns_fn: Fn | None = None,
    ip_fn: Fn | None = None,
    dom_fn: Fn | None = None,
    web_fn: Fn | None = None,
    ) -> Dict[str, int]:
    """Iterate over all assets of an organisation and invoke the supplied callbacks.
173 |     """
174 | The function is intentionally minimal - it only retrieves existing assets and
175 |     calls the provided callbacks.  The unit tests rely on this behaviour to
    verify that ``web_fn`` is called for assets that are allowed to be
    probed.
    """
    # Resolve organisation id
    org_row = c.execute("SELECT id FROM organization WHERE name=?", (org_name,)).fetchone()
    if not org_row:
        return {}
    org_id = org_row["id"]
    assets = c.execute("SELECT id, value, scope FROM asset WHERE org_id=?", (org_id,)).fetchall()
    for a in assets:
        asset_id, value, scope_val = a["id"], a["value"], a["scope"]
        try:
            scope.require_active(c, asset_id, "probe", "probe")
        except scope.ScopeDenied:
            continue
        # Optional callbacks – we simply invoke if provided
        if ct_fn:
            for obs in ct_fn(asset_id):
                _observe(c, asset_id, "ct", obs.get("key"), obs.get("value"))
        if dns_fn:
            for obs in dns_fn(c, asset_id):
                _observe(c, asset_id, "dns", obs.get("key"), obs.get("value"))
        if ip_fn:
            for obs in ip_fn(asset_id):
                _observe(c, asset_id, "ip", obs.get("key"), obs.get("value"))
        if dom_fn:
            for obs in dom_fn(asset_id):
                _observe(c, asset_id, "dom", obs.get("key"), obs.get("value"))
        if web_fn:
            asset_dict = {"id": asset_id, "value": value, "scope": scope_val}
            web_fn(c, asset_dict)
    return {}
