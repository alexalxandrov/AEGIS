"""FastAPI application: JSON API + optional static UI on 127.0.0.1."""
from __future__ import annotations

import csv
import io
import json
import time
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .. import (
    __version__,
    ai_analyst,
    config,
    db,
    diff,
    exclusions,
    jobs,
    reports,
    risk_engine,
    scope,
    sources,
    store,
)


def _c():
    return db.connect()


def _org(c, org_id: int):
    r = c.execute("SELECT * FROM organization WHERE id=?", (org_id,)).fetchone()
    if not r:
        raise HTTPException(404, "organization not found")
    return db.row_to_dict(r)


class OrgIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)


class SeedIn(BaseModel):
    kind: str = Field(pattern="^(domain|asn|cidr|ip)$")
    value: str = Field(min_length=1, max_length=500)
    verified: bool = False


class ScopeIn(BaseModel):
    scope: str
    note: str = ""
    method: str = "ui"


class ExclusionIn(BaseModel):
    kind: str = Field(pattern="^(domain|host|ip|cidr)$")
    pattern: str
    note: str = ""


class ScanIn(BaseModel):
    org_id: int
    mode: str = "passive"
    sources: Optional[list[str]] = None
    limit: int = 300
    brute: bool = False
    wayback: bool = True
    hours: float = 48
    confirm_active: bool = False


class FindingStateIn(BaseModel):
    state: str
    note: str = ""


class AIAskIn(BaseModel):
    org_id: int
    question: str = Field(min_length=1, max_length=4000)


class SettingIn(BaseModel):
    value: Any


def create_app() -> FastAPI:
    app = FastAPI(title="AEGIS", version=__version__, docs_url="/api/docs", redoc_url=None)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:5173", "http://localhost:5173", "http://127.0.0.1:8000"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.on_event("startup")
    def _startup():
        c = _c()
        jobs.mark_stale_on_boot(c)
        sources.ensure_registry(c)

    # ---- health ----
    @app.get("/api/health")
    def health():
        c = _c()
        ai = ai_analyst.ollama_status()
        return {
            "ok": True,
            "version": __version__,
            "db": str(config.DB_PATH),
            "bind_hint": f"http://{config.BIND_HOST}:{config.BIND_PORT}",
            "ollama": ai,
        }

    @app.get("/api/system")
    def system():
        c = _c()
        return {
            "version": __version__,
            "data_dir": str(config.DATA_DIR.resolve()),
            "db_path": str(config.DB_PATH),
            "model": config.MODEL,
            "ollama": ai_analyst.ollama_status(),
            "settings": {
                "theme": db.setting_get(c, "theme", "dark"),
                "scan_limit": db.setting_get(c, "scan_limit", 300),
            },
        }

    # ---- orgs / seeds ----
    @app.get("/api/orgs")
    def list_orgs():
        c = _c()
        rows = []
        for r in c.execute("SELECT * FROM organization ORDER BY name"):
            d = db.row_to_dict(r)
            d["assets"] = c.execute("SELECT count(*) FROM asset WHERE org_id=?", (r["id"],)).fetchone()[0]
            d["findings_open"] = c.execute(
                """SELECT count(*) FROM finding f JOIN asset a ON a.id=f.asset_id
                   WHERE a.org_id=? AND f.state='open'""",
                (r["id"],),
            ).fetchone()[0]
            rows.append(d)
        return rows

    @app.post("/api/orgs")
    def create_org(body: OrgIn):
        c = _c()
        try:
            cur = c.execute(
                "INSERT INTO organization(name,created) VALUES(?,?)", (body.name.strip(), time.time())
            )
        except Exception:
            raise HTTPException(409, "organization already exists")
        return _org(c, cur.lastrowid)

    @app.get("/api/orgs/{org_id}")
    def get_org(org_id: int):
        return _org(_c(), org_id)

    @app.get("/api/orgs/{org_id}/seeds")
    def list_seeds(org_id: int):
        c = _c()
        _org(c, org_id)
        return [db.row_to_dict(r) for r in c.execute("SELECT * FROM seed WHERE org_id=? ORDER BY id", (org_id,))]

    @app.post("/api/orgs/{org_id}/seeds")
    def add_seed(org_id: int, body: SeedIn):
        c = _c()
        _org(c, org_id)
        val = body.value.strip().lower().rstrip(".")
        sc = scope.VERIFIED if body.verified else scope.CANDIDATE
        c.execute(
            "INSERT OR IGNORE INTO seed(org_id,kind,value,verified,created) VALUES(?,?,?,?,?)",
            (org_id, body.kind, val, int(body.verified), time.time()),
        )
        aid, _ = store.upsert_asset(
            c, org_id, body.kind if body.kind != "cidr" else "cidr", val, existence=1.0, attribution=1.0, scope=sc
        )
        if body.verified:
            scope.set_scope(c, aid, scope.VERIFIED, actor="ui", method="seed", note="verified seed")
        return {"seed_ok": True, "asset_id": aid, "scope": sc}

    # ---- dashboard ----
    @app.get("/api/orgs/{org_id}/overview")
    def overview(org_id: int, hours: float = 168):
        c = _c()
        _org(c, org_id)
        scopes = {
            r["scope"]: r["n"]
            for r in c.execute(
                "SELECT scope, count(*) n FROM asset WHERE org_id=? GROUP BY scope", (org_id,)
            )
        }
        kinds = {
            r["kind"]: r["n"]
            for r in c.execute(
                "SELECT kind, count(*) n FROM asset WHERE org_id=? GROUP BY kind", (org_id,)
            )
        }
        risk = risk_engine.org_overview(c, org_id)
        last_run = c.execute(
            "SELECT * FROM scan_run WHERE org_id=? ORDER BY id DESC LIMIT 1", (org_id,)
        ).fetchone()
        since = time.time() - hours * 3600
        changes = c.execute(
            "SELECT count(*) FROM change_event WHERE org_id=? AND created>=?", (org_id, since)
        ).fetchone()[0]
        top_findings = [
            db.row_to_dict(r)
            for r in c.execute(
                """SELECT f.*, a.value AS asset_value FROM finding f JOIN asset a ON a.id=f.asset_id
                   WHERE a.org_id=? AND f.state='open' ORDER BY
                   CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, f.id DESC
                   LIMIT 10""",
                (org_id,),
            )
        ]
        events = [
            db.row_to_dict(r)
            for r in c.execute(
                "SELECT * FROM change_event WHERE org_id=? ORDER BY id DESC LIMIT 20", (org_id,)
            )
        ]
        src_ok = c.execute("SELECT count(*) FROM source_registry WHERE available=1").fetchone()[0]
        src_all = c.execute("SELECT count(*) FROM source_registry").fetchone()[0]
        # asset growth: count by day of first_seen last 14d
        growth = []
        for i in range(13, -1, -1):
            day_start = time.time() - (i + 1) * 86400
            day_end = time.time() - i * 86400
            n = c.execute(
                "SELECT count(*) FROM asset WHERE org_id=? AND first_seen>=? AND first_seen<?",
                (org_id, day_start, day_end),
            ).fetchone()[0]
            growth.append({"t": day_end, "new_assets": n})
        return {
            "org_id": org_id,
            "assets_total": sum(scopes.values()),
            "scopes": scopes,
            "kinds": kinds,
            "risk": risk,
            "changes_period": changes,
            "last_scan": db.row_to_dict(last_run) if last_run else None,
            "top_findings": top_findings,
            "events": events,
            "sources": {"available": src_ok, "total": src_all},
            "growth": growth,
            "ollama": ai_analyst.ollama_status(),
        }

    # ---- assets ----
    @app.get("/api/orgs/{org_id}/assets")
    def list_assets(
        org_id: int,
        q: str = "",
        kind: str = "",
        scope_filter: str = Query("", alias="scope"),
        page: int = 1,
        page_size: int = 50,
        sort: str = "last_seen",
        order: str = "desc",
    ):
        c = _c()
        _org(c, org_id)
        page = max(1, page)
        page_size = min(200, max(1, page_size))
        sort_col = sort if sort in ("id", "kind", "value", "scope", "last_seen", "first_seen", "existence_conf") else "last_seen"
        ord_sql = "ASC" if order.lower() == "asc" else "DESC"
        where = ["org_id=?"]
        args: list[Any] = [org_id]
        if q:
            where.append("value LIKE ?")
            args.append(f"%{q.lower()}%")
        if kind:
            where.append("kind=?")
            args.append(kind)
        if scope_filter:
            where.append("scope=?")
            args.append(scope_filter)
        w = " AND ".join(where)
        total = c.execute(f"SELECT count(*) FROM asset WHERE {w}", args).fetchone()[0]
        rows = c.execute(
            f"SELECT * FROM asset WHERE {w} ORDER BY {sort_col} {ord_sql} LIMIT ? OFFSET ?",
            (*args, page_size, (page - 1) * page_size),
        ).fetchall()
        return {"total": total, "page": page, "page_size": page_size, "items": [db.row_to_dict(r) for r in rows]}

    @app.get("/api/assets/{asset_id}")
    def get_asset(asset_id: int):
        c = _c()
        a = c.execute("SELECT * FROM asset WHERE id=?", (asset_id,)).fetchone()
        if not a:
            raise HTTPException(404, "asset not found")
        d = db.row_to_dict(a)
        d["observations"] = [
            db.row_to_dict(r)
            for r in c.execute(
                "SELECT * FROM observation WHERE asset_id=? ORDER BY id DESC LIMIT 200", (asset_id,)
            )
        ]
        d["findings"] = [
            db.row_to_dict(r)
            for r in c.execute("SELECT * FROM finding WHERE asset_id=? ORDER BY id DESC", (asset_id,))
        ]
        edges = c.execute(
            """SELECT e.*, s.value AS src_value, s.kind AS src_kind, t.value AS dst_value, t.kind AS dst_kind
               FROM edge e JOIN asset s ON s.id=e.src JOIN asset t ON t.id=e.dst
               WHERE e.src=? OR e.dst=? ORDER BY e.last_seen DESC LIMIT 200""",
            (asset_id, asset_id),
        ).fetchall()
        d["edges"] = [db.row_to_dict(r) for r in edges]
        d["scope_history"] = [
            db.row_to_dict(r)
            for r in c.execute(
                "SELECT * FROM scope_decision WHERE asset_id=? ORDER BY id DESC", (asset_id,)
            )
        ]
        return d

    @app.post("/api/assets/{asset_id}/scope")
    def set_asset_scope(asset_id: int, body: ScopeIn):
        c = _c()
        if body.scope not in scope.STATES:
            raise HTTPException(400, f"invalid scope; use {sorted(scope.STATES)}")
        try:
            scope.set_scope(c, asset_id, body.scope, actor="ui", method=body.method, note=body.note)
        except scope.ScopeDenied as e:
            raise HTTPException(403, str(e))
        except ValueError as e:
            raise HTTPException(404, str(e))
        return db.row_to_dict(c.execute("SELECT * FROM asset WHERE id=?", (asset_id,)).fetchone())

    @app.post("/api/assets/bulk-scope")
    def bulk_scope(ids: list[int], body: ScopeIn):
        c = _c()
        ok, err = [], []
        for i in ids[:500]:
            try:
                scope.set_scope(c, i, body.scope, actor="ui", method="bulk", note=body.note)
                ok.append(i)
            except Exception as e:
                err.append({"id": i, "error": str(e)})
        return {"updated": ok, "errors": err}

    # ---- graph ----
    @app.get("/api/orgs/{org_id}/graph")
    def graph(org_id: int, limit: int = 300, depth: int = 3, kinds: str = ""):
        c = _c()
        _org(c, org_id)
        limit = min(800, max(10, limit))
        kind_filter = [k for k in kinds.split(",") if k] if kinds else None
        q = "SELECT * FROM asset WHERE org_id=?"
        args: list[Any] = [org_id]
        if kind_filter:
            q += f" AND kind IN ({','.join('?' * len(kind_filter))})"
            args.extend(kind_filter)
        q += " ORDER BY (scope='VERIFIED') DESC, last_seen DESC LIMIT ?"
        args.append(limit)
        nodes = [db.row_to_dict(r) for r in c.execute(q, args)]
        ids = {n["id"] for n in nodes}
        edges = []
        for r in c.execute(
            """SELECT e.* FROM edge e JOIN asset a ON a.id=e.src WHERE a.org_id=?""", (org_id,)
        ):
            if r["src"] in ids and r["dst"] in ids:
                edges.append(db.row_to_dict(r))
        return {"nodes": nodes, "edges": edges, "truncated": len(ids) >= limit, "depth": depth}

    # ---- observations / findings ----
    @app.get("/api/orgs/{org_id}/observations")
    def list_obs(org_id: int, page: int = 1, page_size: int = 50):
        c = _c()
        _org(c, org_id)
        page_size = min(200, max(1, page_size))
        total = c.execute(
            "SELECT count(*) FROM observation o JOIN asset a ON a.id=o.asset_id WHERE a.org_id=?",
            (org_id,),
        ).fetchone()[0]
        rows = c.execute(
            """SELECT o.*, a.value AS asset_value, a.kind AS asset_kind FROM observation o
               JOIN asset a ON a.id=o.asset_id WHERE a.org_id=? ORDER BY o.id DESC LIMIT ? OFFSET ?""",
            (org_id, page_size, (page - 1) * page_size),
        ).fetchall()
        return {"total": total, "items": [db.row_to_dict(r) for r in rows]}

    @app.get("/api/orgs/{org_id}/findings")
    def list_findings(
        org_id: int,
        state: str = "open",
        severity: str = "",
        q: str = "",
        page: int = 1,
        page_size: int = 50,
    ):
        c = _c()
        _org(c, org_id)
        where = ["a.org_id=?"]
        args: list[Any] = [org_id]
        if state and state != "all":
            where.append("f.state=?")
            args.append(state)
        if severity:
            where.append("f.severity=?")
            args.append(severity)
        if q:
            where.append("(f.text LIKE ? OR a.value LIKE ? OR f.kind LIKE ?)")
            args.extend([f"%{q}%"] * 3)
        w = " AND ".join(where)
        total = c.execute(
            f"SELECT count(*) FROM finding f JOIN asset a ON a.id=f.asset_id WHERE {w}", args
        ).fetchone()[0]
        rows = c.execute(
            f"""SELECT f.*, a.value AS asset_value, a.kind AS asset_kind, a.scope AS asset_scope
                FROM finding f JOIN asset a ON a.id=f.asset_id WHERE {w}
                ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, f.id DESC
                LIMIT ? OFFSET ?""",
            (*args, page_size, (page - 1) * page_size),
        ).fetchall()
        return {"total": total, "items": [db.row_to_dict(r) for r in rows]}

    @app.get("/api/findings/{finding_id}")
    def get_finding(finding_id: int):
        c = _c()
        f = c.execute(
            """SELECT f.*, a.value AS asset_value, a.kind AS asset_kind, a.scope AS asset_scope, a.org_id
               FROM finding f JOIN asset a ON a.id=f.asset_id WHERE f.id=?""",
            (finding_id,),
        ).fetchone()
        if not f:
            raise HTTPException(404)
        d = db.row_to_dict(f)
        try:
            obs_ids = json.loads(d.get("obs_ids") or "[]")
        except Exception:
            obs_ids = []
        d["observations"] = [
            db.row_to_dict(c.execute("SELECT * FROM observation WHERE id=?", (i,)).fetchone())
            for i in obs_ids
            if c.execute("SELECT * FROM observation WHERE id=?", (i,)).fetchone()
        ]
        d["risk"] = risk_engine.assess_finding(c, finding_id)
        return d

    @app.post("/api/findings/{finding_id}/state")
    def finding_state(finding_id: int, body: FindingStateIn):
        c = _c()
        if body.state not in ("open", "accepted", "baseline", "closed"):
            raise HTTPException(400, "invalid state")
        n = c.execute(
            "UPDATE finding SET state=?, note=? WHERE id=?", (body.state, body.note, finding_id)
        ).rowcount
        if not n:
            raise HTTPException(404)
        return {"ok": True}

    @app.get("/api/orgs/{org_id}/risk")
    def org_risk(org_id: int):
        c = _c()
        _org(c, org_id)
        return risk_engine.org_overview(c, org_id)

    # ---- monitoring ----
    @app.get("/api/orgs/{org_id}/changes")
    def changes(org_id: int, hours: float = 168, page: int = 1, page_size: int = 50):
        c = _c()
        _org(c, org_id)
        since = time.time() - hours * 3600
        total = c.execute(
            "SELECT count(*) FROM change_event WHERE org_id=? AND created>=?", (org_id, since)
        ).fetchone()[0]
        rows = c.execute(
            """SELECT ce.*, a.value AS asset_value FROM change_event ce
               LEFT JOIN asset a ON a.id=ce.asset_id
               WHERE ce.org_id=? AND ce.created>=? ORDER BY ce.id DESC LIMIT ? OFFSET ?""",
            (org_id, since, page_size, (page - 1) * page_size),
        ).fetchall()
        return {"total": total, "items": [db.row_to_dict(r) for r in rows]}

    @app.get("/api/orgs/{org_id}/diff")
    def run_diff(org_id: int, hours: float = 48):
        c = _c()
        _org(c, org_id)
        ev = diff.visible(c, diff.compute(c, org_id, time.time() - hours * 3600))
        return {"events": ev, "count": len(ev)}

    @app.post("/api/orgs/{org_id}/baseline")
    def baseline(org_id: int):
        c = _c()
        _org(c, org_id)
        diff.save(c, diff.compute(c, org_id, 0))
        n = c.execute(
            """UPDATE finding SET state='baseline' WHERE state='open' AND asset_id IN
               (SELECT id FROM asset WHERE org_id=?)""",
            (org_id,),
        ).rowcount
        return {"baselined": n}

    @app.get("/api/orgs/{org_id}/scans/compare")
    def compare_scans(org_id: int, a: int, b: int):
        c = _c()
        _org(c, org_id)
        ra, rb = get_run_safe(c, a), get_run_safe(c, b)
        if not ra or not rb or ra["org_id"] != org_id or rb["org_id"] != org_id:
            raise HTTPException(404, "runs not found")
        ca = {
            r["kind"] + ":" + (r["text"] or "")
            for r in c.execute("SELECT kind,text FROM change_event WHERE run_id=?", (a,))
        }
        cb = {
            r["kind"] + ":" + (r["text"] or "")
            for r in c.execute("SELECT kind,text FROM change_event WHERE run_id=?", (b,))
        }
        return {
            "only_a": sorted(ca - cb)[:200],
            "only_b": sorted(cb - ca)[:200],
            "both": sorted(ca & cb)[:200],
            "run_a": ra,
            "run_b": rb,
        }

    # ---- scans ----
    @app.get("/api/orgs/{org_id}/scans")
    def list_scans(org_id: int, limit: int = 50):
        c = _c()
        _org(c, org_id)
        return jobs.list_runs(c, org_id, limit)

    @app.post("/api/scans")
    def create_scan(body: ScanIn):
        c = _c()
        _org(c, body.org_id)
        if body.mode in ("active", "full") and not body.confirm_active:
            raise HTTPException(
                400,
                "Active scanning requires confirm_active=true. Only VERIFIED assets will be probed.",
            )
        run_id = jobs.create_run(
            c,
            body.org_id,
            mode=body.mode,
            source_names=body.sources,
            limit=body.limit,
            brute=body.brute,
            wayback=body.wayback,
            hours=body.hours,
        )
        jobs.start_run_async(run_id)
        return jobs.get_run(c, run_id)

    @app.get("/api/scans/{run_id}")
    def get_scan(run_id: int):
        c = _c()
        r = jobs.get_run(c, run_id)
        if not r:
            raise HTTPException(404)
        return r

    @app.post("/api/scans/{run_id}/cancel")
    def cancel_scan(run_id: int):
        c = _c()
        if not jobs.request_cancel(c, run_id):
            raise HTTPException(400, "cannot cancel")
        return jobs.get_run(c, run_id)

    # ---- sources ----
    @app.get("/api/sources")
    def get_sources():
        return sources.list_sources(_c())

    @app.post("/api/sources/refresh")
    def refresh_sources(network: bool = True):
        c = _c()
        results = sources.refresh(c, network=network)
        return {"results": results, "sources": sources.list_sources(c)}

    # ---- exclusions / settings ----
    @app.get("/api/orgs/{org_id}/exclusions")
    def get_exclusions(org_id: int):
        c = _c()
        _org(c, org_id)
        return exclusions.list_exclusions(c, org_id)

    @app.post("/api/orgs/{org_id}/exclusions")
    def add_exclusion(org_id: int, body: ExclusionIn):
        c = _c()
        _org(c, org_id)
        try:
            exclusions.add(c, org_id, body.kind, body.pattern, body.note)
        except ValueError as e:
            raise HTTPException(400, str(e))
        return exclusions.list_exclusions(c, org_id)

    @app.delete("/api/exclusions/{exclusion_id}")
    def del_exclusion(exclusion_id: int):
        c = _c()
        if not exclusions.remove(c, exclusion_id):
            raise HTTPException(404)
        return {"ok": True}

    @app.get("/api/settings")
    def get_settings():
        c = _c()
        keys = ["theme", "scan_limit", "default_hours", "graph_limit"]
        return {k: db.setting_get(c, k) for k in keys}

    @app.put("/api/settings/{key}")
    def put_setting(key: str, body: SettingIn):
        if key not in ("theme", "scan_limit", "default_hours", "graph_limit", "ollama_model"):
            raise HTTPException(400, "unknown setting")
        c = _c()
        db.setting_set(c, key, body.value)
        if key == "ollama_model":
            # runtime override via env-like setting; config.MODEL remains default unless process restart
            pass
        return {"key": key, "value": body.value}

    @app.get("/api/action-log")
    def action_log(limit: int = 100):
        c = _c()
        return [
            db.row_to_dict(r)
            for r in c.execute("SELECT * FROM action_log ORDER BY id DESC LIMIT ?", (limit,))
        ]

    # ---- AI ----
    @app.get("/api/ai/status")
    def ai_status():
        return ai_analyst.ollama_status()

    @app.post("/api/ai/ask")
    def ai_ask(body: AIAskIn):
        c = _c()
        _org(c, body.org_id)
        return ai_analyst.ask(c, body.org_id, body.question)

    @app.post("/api/ai/explain/{finding_id}")
    def ai_explain(finding_id: int):
        c = _c()
        r = ai_analyst.explain_finding(c, finding_id)
        if r.get("error") == "not found":
            raise HTTPException(404)
        return r

    @app.get("/api/ai/history")
    def ai_history(org_id: int, limit: int = 50):
        c = _c()
        return [
            db.row_to_dict(r)
            for r in c.execute(
                "SELECT * FROM ai_analysis WHERE org_id=? ORDER BY id DESC LIMIT ?",
                (org_id, limit),
            )
        ]

    # ---- reports ----
    @app.get("/api/orgs/{org_id}/report")
    def report(org_id: int, fmt: str = "json", hours: float = 168):
        c = _c()
        _org(c, org_id)
        data = reports.org_report(c, org_id, hours)
        if fmt == "json":
            return data
        if fmt == "csv":
            return PlainTextResponse(reports.to_csv_findings(data), media_type="text/csv")
        if fmt == "md" or fmt == "markdown":
            return PlainTextResponse(reports.to_markdown(data), media_type="text/markdown")
        raise HTTPException(400, "fmt must be json|csv|md")

    @app.get("/api/orgs/{org_id}/export/assets.csv")
    def export_assets_csv(org_id: int):
        c = _c()
        _org(c, org_id)
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["id", "kind", "value", "scope", "existence_conf", "attribution_conf", "first_seen", "last_seen"])
        for r in c.execute("SELECT * FROM asset WHERE org_id=? ORDER BY kind,value", (org_id,)):
            w.writerow(
                [r["id"], r["kind"], r["value"], r["scope"], r["existence_conf"], r["attribution_conf"], r["first_seen"], r["last_seen"]]
            )
        return PlainTextResponse(buf.getvalue(), media_type="text/csv")

    # ---- search ----
    @app.get("/api/search")
    def search(q: str, org_id: Optional[int] = None, limit: int = 30):
        c = _c()
        qn = f"%{(q or '').lower()}%"
        assets = c.execute(
            "SELECT id,org_id,kind,value,scope FROM asset WHERE value LIKE ?"
            + (" AND org_id=?" if org_id else "")
            + " LIMIT ?",
            (qn, org_id, limit) if org_id else (qn, limit),
        ).fetchall()
        findings = c.execute(
            """SELECT f.id,f.kind,f.severity,f.text,a.org_id,a.value FROM finding f
               JOIN asset a ON a.id=f.asset_id WHERE (f.text LIKE ? OR a.value LIKE ?)"""
            + (" AND a.org_id=?" if org_id else "")
            + " LIMIT ?",
            (qn, qn, org_id, limit) if org_id else (qn, qn, limit),
        ).fetchall()
        return {
            "assets": [db.row_to_dict(r) for r in assets],
            "findings": [db.row_to_dict(r) for r in findings],
        }

    # ---- static UI ----
    dist = Path(__file__).resolve().parents[2] / "web" / "dist"
    if dist.is_dir():
        assets_dir = dist / "assets"
        if assets_dir.is_dir():
            app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

        @app.get("/{full_path:path}")
        def spa(full_path: str):
            if full_path.startswith("api/"):
                raise HTTPException(404)
            candidate = dist / full_path
            if full_path and candidate.is_file():
                return FileResponse(candidate)
            index = dist / "index.html"
            if index.is_file():
                return FileResponse(index)
            return HTMLResponse(_placeholder_html(), status_code=200)
    else:

        @app.get("/")
        def root():
            return HTMLResponse(_placeholder_html())

    return app


def get_run_safe(c, run_id):
    r = c.execute("SELECT * FROM scan_run WHERE id=?", (run_id,)).fetchone()
    return db.row_to_dict(r) if r else None


def _placeholder_html():
    return """<!doctype html><html><head><meta charset=utf-8><title>AEGIS</title>
<style>body{font-family:ui-sans-serif,system-ui;background:#0f1214;color:#e8eef0;display:flex;min-height:100vh;align-items:center;justify-content:center}
main{max-width:40rem;padding:2rem}a{color:#3dbeb0}code{background:#1a1f22;padding:.1rem .35rem;border-radius:4px}</style></head>
<body><main><h1>AEGIS</h1><p>API is running. Build the UI:</p>
<pre><code>cd web && npm install && npm run build</code></pre>
<p>Then restart <code>python -m aegis serve</code>. API docs: <a href="/api/docs">/api/docs</a></p></main></body></html>"""
