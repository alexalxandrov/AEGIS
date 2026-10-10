"""Фоновые сканы: статусы, стадии, отмена, устойчивость к перезапуску."""
from __future__ import annotations
import json, threading, time, traceback
from . import db, runner, diff, sources, scope

_lock = threading.Lock()
_threads: dict[int, threading.Thread] = {}
_cancel: dict[int, bool] = {}


def _conn():
    return db.connect()


def mark_stale_on_boot(c=None):
    """После рестарта незавершённые runs не продолжаются бесконтрольно."""
    own = c is None
    if own:
        c = _conn()
    c.execute(
        """UPDATE scan_run SET status='interrupted', stage='interrupted',
           finished=COALESCE(finished,?), error=COALESCE(error,'process restarted')
           WHERE status IN ('queued','running')""",
        (time.time(),),
    )
    c.execute(
        """UPDATE task SET status='failed', error='interrupted on restart', finished=?
           WHERE status IN ('queued','running')""",
        (time.time(),),
    )


def list_runs(c, org_id=None, limit=50):
    if org_id:
        rows = c.execute(
            "SELECT * FROM scan_run WHERE org_id=? ORDER BY id DESC LIMIT ?", (org_id, limit)
        ).fetchall()
    else:
        rows = c.execute("SELECT * FROM scan_run ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [_run_dict(r) for r in rows]


def get_run(c, run_id):
    r = c.execute("SELECT * FROM scan_run WHERE id=?", (run_id,)).fetchone()
    if not r:
        return None
    d = _run_dict(r)
    tasks = c.execute("SELECT * FROM scan_task WHERE run_id=? ORDER BY id", (run_id,)).fetchall()
    d["tasks"] = [db.row_to_dict(t) for t in tasks]
    return d


def _run_dict(r):
    d = db.row_to_dict(r)
    for k in ("sources_json", "stats_json"):
        try:
            d[k.replace("_json", "")] = json.loads(d.pop(k) or ("[]" if "sources" in k else "{}"))
        except Exception:
            d[k.replace("_json", "")] = [] if "sources" in k else {}
    return d


def create_run(c, org_id, mode="passive", source_names=None, limit=300, brute=False, wayback=True, hours=48):
    if mode not in ("passive", "active", "full"):
        raise ValueError("mode must be passive|active|full")
    srcs = source_names or _default_sources(mode)
    now = time.time()
    cur = c.execute(
        """INSERT INTO scan_run(org_id,mode,status,stage,sources_json,stats_json,created,progress_done,progress_total)
           VALUES(?,?,?,?,?,?,?,?,?)""",
        (org_id, mode, "queued", "queued", json.dumps(srcs), "{}", now, 0, max(1, len(srcs) + 2)),
    )
    run_id = cur.lastrowid
    for s in srcs:
        c.execute(
            "INSERT INTO scan_task(run_id,source,status) VALUES(?,?,?)",
            (run_id, s, "queued"),
        )
    payload = {
        "org_id": org_id,
        "mode": mode,
        "limit": limit,
        "brute": brute,
        "wayback": wayback,
        "hours": hours,
    }
    db.enqueue(c, "scan", payload, run_id=run_id)
    return run_id


def _default_sources(mode):
    base = ["crt.sh", "dns", "wayback", "email_policy", "rdap", "ripestat", "internetdb"]
    if mode in ("active", "full"):
        base += ["http_tls"]
    return base


def request_cancel(c, run_id):
    r = c.execute("SELECT status FROM scan_run WHERE id=?", (run_id,)).fetchone()
    if not r:
        return False
    if r["status"] not in ("queued", "running"):
        return False
    c.execute("UPDATE scan_run SET cancel_requested=1, message='cancel requested' WHERE id=?", (run_id,))
    with _lock:
        _cancel[run_id] = True
    return True


def _cancelled(run_id):
    with _lock:
        if _cancel.get(run_id):
            return True
    c = _conn()
    r = c.execute("SELECT cancel_requested FROM scan_run WHERE id=?", (run_id,)).fetchone()
    return bool(r and r["cancel_requested"])


def _set_stage(c, run_id, stage, done=None, total=None, message=None, status=None):
    parts = ["stage=?"]
    args = [stage]
    if done is not None:
        parts.append("progress_done=?")
        args.append(done)
    if total is not None:
        parts.append("progress_total=?")
        args.append(total)
    if message is not None:
        parts.append("message=?")
        args.append(message)
    if status is not None:
        parts.append("status=?")
        args.append(status)
    args.append(run_id)
    c.execute(f"UPDATE scan_run SET {', '.join(parts)} WHERE id=?", args)


def _task_status(c, run_id, source, status, message=""):
    c.execute(
        """UPDATE scan_task SET status=?, message=?,
           started=CASE WHEN ?='running' THEN COALESCE(started,?) ELSE started END,
           finished=CASE WHEN ? IN ('done','failed','skipped') THEN ? ELSE finished END
           WHERE run_id=? AND source=?""",
        (status, message, status, time.time(), status, time.time(), run_id, source),
    )


def execute_run(run_id: int):
    c = _conn()
    run = c.execute("SELECT * FROM scan_run WHERE id=?", (run_id,)).fetchone()
    if not run:
        return
    if run["status"] == "interrupted":
        return
    org = c.execute("SELECT name FROM organization WHERE id=?", (run["org_id"],)).fetchone()
    if not org:
        c.execute(
            "UPDATE scan_run SET status='failed', error='org missing', finished=? WHERE id=?",
            (time.time(), run_id),
        )
        return

    payload_row = c.execute(
        "SELECT * FROM task WHERE run_id=? AND kind='scan' ORDER BY id DESC LIMIT 1", (run_id,)
    ).fetchone()
    payload = json.loads(payload_row["payload"]) if payload_row else {}
    mode = run["mode"]
    limit = int(payload.get("limit", 300))
    brute = bool(payload.get("brute", False))
    wayback = bool(payload.get("wayback", True))
    hours = float(payload.get("hours", 48))
    srcs = json.loads(run["sources_json"] or "[]")

    c.execute(
        "UPDATE scan_run SET status='running', started=?, stage='starting' WHERE id=?",
        (time.time(), run_id),
    )
    stats = {"partial": False, "errors": [], "runner": {}, "probe": {}, "findings_new": 0}
    done = 0
    total = max(1, len(srcs) + 2)

    def log(msg):
        _set_stage(c, run_id, msg[:80], message=msg[:240])

    try:
        if _cancelled(run_id):
            raise InterruptedError("cancelled")

        # passive discovery via existing runner
        if any(s in srcs for s in ("crt.sh", "dns", "wayback", "email_policy", "rdap", "ripestat", "internetdb", "subfinder")):
            _task_status(c, run_id, "crt.sh" if "crt.sh" in srcs else srcs[0], "running")
            _set_stage(c, run_id, "passive_discovery", done, total, "passive discovery")
            try:
                # optional PD subfinder before CT
                if "subfinder" in srcs:
                    try:
                        from .tentacles import pd_tools
                        n = pd_tools.enrich_subfinder(c, run["org_id"], org["name"])
                        stats["subfinder"] = n
                        _task_status(c, run_id, "subfinder", "done", f"hosts+={n}")
                    except Exception as e:
                        stats["partial"] = True
                        stats["errors"].append(f"subfinder:{type(e).__name__}")
                        _task_status(c, run_id, "subfinder", "failed", type(e).__name__)

                st = runner.run_org(
                    c,
                    org["name"],
                    log=log,
                    limit=limit,
                    brute=brute,
                    wb=wayback and "wayback" in srcs,
                )
                stats["runner"] = st
                for s in srcs:
                    if s in ("http_tls", "nuclei", "naabu", "httpx"):
                        continue
                    if s == "subfinder" and "subfinder" in stats:
                        continue
                    _task_status(c, run_id, s, "done")
            except Exception as e:
                stats["partial"] = True
                stats["errors"].append(f"runner:{type(e).__name__}:{e}")
                for s in srcs:
                    if s not in ("http_tls",):
                        _task_status(c, run_id, s, "failed", type(e).__name__)
            done += 1
            _set_stage(c, run_id, "passive_done", done, total)

        if _cancelled(run_id):
            raise InterruptedError("cancelled")

        # active probes — only VERIFIED, re-check scope
        if mode in ("active", "full") and "http_tls" in srcs:
            _task_status(c, run_id, "http_tls", "running")
            _set_stage(c, run_id, "active_probes", done, total, "active HTTP/TLS (VERIFIED only)")
            # re-verify scope immediately before probes
            verified = c.execute(
                "SELECT id FROM asset WHERE org_id=? AND scope=?",
                (run["org_id"], scope.VERIFIED),
            ).fetchall()
            for a in verified:
                try:
                    scope.require_active(c, a["id"], "scan", "http_tls_probe")
                except scope.ScopeDenied:
                    pass
            try:
                st = runner.probe_org(c, org["name"], log=log)
                stats["probe"] = st
                _task_status(c, run_id, "http_tls", "done", f"probed={st.get('probed', 0)}")
            except Exception as e:
                stats["partial"] = True
                stats["errors"].append(f"probe:{type(e).__name__}")
                _task_status(c, run_id, "http_tls", "failed", type(e).__name__)
            done += 1
        elif "http_tls" in srcs:
            _task_status(c, run_id, "http_tls", "skipped", "active mode not selected")

        if _cancelled(run_id):
            raise InterruptedError("cancelled")

        _set_stage(c, run_id, "diff_risk", done, total, "computing changes & findings")
        events = diff.compute(c, run["org_id"], time.time() - hours * 3600)
        new = diff.save(c, events)
        stats["findings_new"] = len(new)
        # persist change events
        for e in events:
            c.execute(
                """INSERT INTO change_event(org_id,asset_id,kind,severity,before_json,after_json,text,obs_ids,run_id,created)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (
                    run["org_id"],
                    e["asset_id"],
                    e["kind"],
                    e["severity"],
                    None,
                    None,
                    e["text"],
                    json.dumps(e.get("obs") or []),
                    run_id,
                    time.time(),
                ),
            )
        done = total
        status = "partial" if stats["partial"] else "done"
        c.execute(
            """UPDATE scan_run SET status=?, stage=?, progress_done=?, progress_total=?,
               stats_json=?, finished=?, message=? WHERE id=?""",
            (
                status,
                "complete",
                done,
                total,
                json.dumps(stats),
                time.time(),
                "completed with source errors" if stats["partial"] else "ok",
                run_id,
            ),
        )
        if payload_row:
            db.finish(c, payload_row["id"])
    except InterruptedError:
        c.execute(
            """UPDATE scan_run SET status='cancelled', stage='cancelled', finished=?,
               stats_json=?, message='cancelled by operator' WHERE id=?""",
            (time.time(), json.dumps(stats), run_id),
        )
        if payload_row:
            db.finish(c, payload_row["id"], "cancelled")
    except Exception as e:
        c.execute(
            """UPDATE scan_run SET status='failed', stage='failed', finished=?, error=?, stats_json=? WHERE id=?""",
            (time.time(), f"{type(e).__name__}: {e}", json.dumps({**stats, "trace": traceback.format_exc()[-800:]}), run_id),
        )
        if payload_row:
            db.finish(c, payload_row["id"], str(e))


def start_run_async(run_id: int):
    with _lock:
        t = _threads.get(run_id)
        if t and t.is_alive():
            return

        def _wrap():
            try:
                execute_run(run_id)
            finally:
                with _lock:
                    _threads.pop(run_id, None)
                    _cancel.pop(run_id, None)

        th = threading.Thread(target=_wrap, name=f"aegis-scan-{run_id}", daemon=True)
        _threads[run_id] = th
        th.start()


def kick_queued(c=None):
    """Запускает потоки для queued runs (после create или ручного вызова). Не возобновляет interrupted."""
    own = c is None
    if own:
        c = _conn()
    for r in c.execute("SELECT id FROM scan_run WHERE status='queued' ORDER BY id").fetchall():
        start_run_async(r["id"])
