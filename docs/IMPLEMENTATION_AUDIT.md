# AEGIS — Implementation Audit

Date: 2026-10-10  
Backup: `backups/aegis.db.*` (existing `data/aegis.db` preserved)

## What exists and works

| Area | Status | Notes |
|---|---|---|
| SQLite schema | Working | org, seed, asset, observation, edge, finding, task, source_health, action_log |
| Scope core | Working | VERIFIED/CANDIDATE/THIRD_PARTY/OUT_OF_SCOPE; `require_active`; action_log |
| Store (upsert/observe/edge) | Working | Change-only observations + last_confirmed; dedupe |
| CLI | Working | init/check/org/seed/run/web/diff/findings/baseline/risk/scan/watch/digest |
| CT (crt.sh + CertSpotter) | Working | Disk cache + retries |
| DNS | Working | dig / DoH / system fallback; disagreement detection |
| Intel (RDAP, RIPEstat, InternetDB) | Working | CDN third-party marking |
| Wayback CDX | Working | Passive hosts |
| Email SPF/DKIM/DMARC | Working | Via DNS |
| Active HTTP/TLS | Working | Scope-gated via `probe_org` |
| Diff + findings | Working | DNS/TLS/HTTP/BGP/RDAP change rules + static checks |
| Risk score | Working | Weighted open findings per asset |
| LLM digest | Working | Ollama + citation validation |
| Tests | Partial | unittest suite; `test_dedupe_run` can hang if Wayback is not mocked (`wb=True`) |
| Existing data | Present | 1 org, 1 seed, 4 assets, 8 observations, 7 findings |

## Gaps vs product goal

1. **No web UI** — CLI only; `aegis web` means HTTP probe, not a server.
2. **No HTTP API** — UI cannot attach.
3. **Task queue incomplete** — tables exist; no durable scan runs, cancel, progress, stages.
4. **Schema incomplete** — missing scan_run, evidence blob refs, exclusions, settings, AI analysis, change_event, source registry metadata.
5. **Collector contract thin** — no readiness, rate limits, mode metadata, graceful registry.
6. **No ProjectDiscovery adapters** — subfinder/dnsx/httpx/etc. absent.
7. **No exclusions / depth limits** as first-class config.
8. **Docker mentioned in roadmap Phase 0** — product decision: **no Docker**; local Python + SQLite.
9. **README still says Postgres** for $0/self-hosted principle — SQLite is the default runtime.
10. **No frontend build/serve path**.

## Decisions

1. Extend existing modules; do not rewrite CT/DNS/web/diff/scope.
2. Add FastAPI (`python -m aegis serve`) on `127.0.0.1:8000`, serving built React UI from `web/dist`.
3. Additive SQLite migrations in `db.connect()`; never drop user tables/data.
4. Rename UX: CLI keeps `web` = probe; new `serve` = product UI+API.
5. Optional PD tools via adapters; missing binaries → degraded source status, not crash.
6. Ollama optional; AI never invents facts without observation/finding IDs.
7. Fix runner: skip live Wayback when `wb=False` or when tests inject collectors.

## Recovery

```bash
cp backups/aegis.db.<timestamp> data/aegis.db
```
