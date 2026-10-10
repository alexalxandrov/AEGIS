"""Экспорт отчётов: JSON, CSV, Markdown."""
from __future__ import annotations
import csv, io, json, time
from . import db, diff


def org_report(c, org_id, hours=168):
    org = db.row_to_dict(c.execute("SELECT * FROM organization WHERE id=?", (org_id,)).fetchone())
    assets = [db.row_to_dict(r) for r in c.execute("SELECT * FROM asset WHERE org_id=? ORDER BY kind,value", (org_id,))]
    findings = [
        db.row_to_dict(r)
        for r in c.execute(
            """SELECT f.*, a.value AS asset_value, a.kind AS asset_kind FROM finding f
               JOIN asset a ON a.id=f.asset_id WHERE a.org_id=? ORDER BY f.id DESC""",
            (org_id,),
        )
    ]
    changes = [
        db.row_to_dict(r)
        for r in c.execute(
            "SELECT * FROM change_event WHERE org_id=? AND created>=? ORDER BY id DESC LIMIT 500",
            (org_id, time.time() - hours * 3600),
        )
    ]
    total, top = diff.risk(c, org_id)
    return {
        "organization": org,
        "generated_at": time.time(),
        "hours": hours,
        "risk_score": total,
        "risk_top": top[:20],
        "asset_count": len(assets),
        "finding_count": len(findings),
        "assets": assets,
        "findings": findings,
        "changes": changes,
    }


def to_json(report) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2, default=str)


def to_csv_findings(report) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "severity", "kind", "state", "asset", "text", "is_hypothesis"])
    for f in report["findings"]:
        w.writerow(
            [
                f.get("id"),
                f.get("severity"),
                f.get("kind"),
                f.get("state"),
                f.get("asset_value"),
                f.get("text"),
                f.get("is_hypothesis"),
            ]
        )
    return buf.getvalue()


def to_markdown(report) -> str:
    org = report["organization"] or {}
    lines = [
        f"# AEGIS report — {org.get('name', '?')}",
        "",
        f"Risk score: **{report['risk_score']}/100**",
        f"Assets: {report['asset_count']}, findings: {report['finding_count']}",
        "",
        "## Top risk assets",
    ]
    for v, s in report["risk_top"][:15]:
        lines.append(f"- {v}: {s}")
    lines += ["", "## Open findings"]
    for f in report["findings"]:
        if f.get("state") != "open":
            continue
        lines.append(f"- **{f.get('severity')}** `{f.get('kind')}` {f.get('asset_value')}: {f.get('text')}")
    lines += ["", "## Recent changes"]
    for ch in report["changes"][:40]:
        lines.append(f"- [{ch.get('severity')}] {ch.get('kind')}: {ch.get('text')}")
    return "\n".join(lines)
