import { Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Play, Radio } from "lucide-react";
import { api } from "../api/client";
import { useRequireOrg } from "../context/OrgContext";
import { Badge, EmptyState, ErrorState, Skeleton } from "../components/ui/StateViews";
import { formatRelative, formatTs, scopeColor, severityColor } from "../lib/utils";

export function OverviewPage() {
  const { orgId } = useRequireOrg();
  const qc = useQueryClient();

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ["overview", orgId],
    queryFn: () => api.overview(orgId),
    refetchInterval: 30_000,
  });

  const scan = useMutation({
    mutationFn: () =>
      api.createScan({ org_id: orgId, mode: "passive", confirm_active: false }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["scans", orgId] });
      qc.invalidateQueries({ queryKey: ["overview", orgId] });
    },
  });

  if (isLoading) {
    return (
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Skeleton className="h-32 lg:col-span-3" />
        <Skeleton className="h-48" />
        <Skeleton className="h-48" />
        <Skeleton className="h-48" />
      </div>
    );
  }
  if (isError || !data) return <ErrorState message="Could not load overview" onRetry={() => refetch()} />;

  const chartData = data.growth.map((g) => ({
    label: new Date(g.t * 1000).toLocaleDateString(undefined, { month: "short", day: "numeric" }),
    new_assets: g.new_assets,
  }));

  const ollamaOk = data.ollama.available && data.ollama.preferred_present;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">Overview</h1>
          <p className="text-sm text-[var(--text-muted)]">
            {data.assets_total} assets · {data.changes_period} changes (7d) · risk{" "}
            {data.risk.level ?? "—"} ({data.risk.score ?? 0})
          </p>
        </div>
        <button
          type="button"
          className="btn-primary"
          disabled={scan.isPending}
          onClick={() => scan.mutate()}
        >
          <Play className="w-4 h-4" />
          Start passive scan
        </button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
        {Object.entries(data.scopes).map(([scope, n]) => (
          <div key={scope} className="panel p-3">
            <p className="label">Scope</p>
            <Badge className={scopeColor(scope)}>{scope}</Badge>
            <p className="text-2xl font-semibold mt-2 tabular-nums">{n}</p>
          </div>
        ))}
        <div className="panel p-3">
          <p className="label">Sources</p>
          <p className="text-2xl font-semibold tabular-nums">
            {data.sources.available}/{data.sources.total}
          </p>
          <p className="text-xs text-[var(--text-muted)]">available</p>
        </div>
        <div className="panel p-3">
          <p className="label">LLM</p>
          <div className="flex items-center gap-2 mt-1">
            <Radio className={`w-4 h-4 ${ollamaOk ? "text-accent" : "text-amber-400"}`} />
            <span className="text-sm">{ollamaOk ? "Ollama ready" : "Local model issue"}</span>
          </div>
          {!ollamaOk && (
            <p className="text-xs text-[var(--text-muted)] mt-1">{data.ollama.warning ?? "Check Ollama"}</p>
          )}
        </div>
      </div>

      <div className="grid lg:grid-cols-2 gap-4">
        <div className="panel p-4">
          <h2 className="text-sm font-semibold mb-3">Asset growth (14d)</h2>
          {chartData.every((d) => d.new_assets === 0) ? (
            <EmptyState title="No new assets" description="Run a scan to discover assets." />
          ) : (
            <div className="h-52">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData}>
                  <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
                  <XAxis dataKey="label" tick={{ fill: "var(--text-muted)", fontSize: 11 }} />
                  <YAxis tick={{ fill: "var(--text-muted)", fontSize: 11 }} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{
                      background: "var(--bg-panel)",
                      border: "1px solid var(--border)",
                      borderRadius: 8,
                    }}
                  />
                  <Area type="monotone" dataKey="new_assets" stroke="#3dbeb0" fill="#3dbeb0" fillOpacity={0.15} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        <div className="panel p-4">
          <h2 className="text-sm font-semibold mb-3">Last scan</h2>
          {data.last_scan ? (
            <dl className="text-sm space-y-2 font-mono">
              <div className="flex justify-between">
                <dt className="text-[var(--text-muted)]">Status</dt>
                <dd>{data.last_scan.status}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-[var(--text-muted)]">Stage</dt>
                <dd>{data.last_scan.stage}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-[var(--text-muted)]">Started</dt>
                <dd>{formatTs(data.last_scan.created)}</dd>
              </div>
              <Link to={`/orgs/${orgId}/scans`} className="text-accent text-sm inline-block mt-2">
                View scan history
              </Link>
            </dl>
          ) : (
            <EmptyState title="No scans yet" description="Start a passive scan from the button above." />
          )}
        </div>
      </div>

      <div className="grid lg:grid-cols-2 gap-4">
        <div className="panel p-4">
          <h2 className="text-sm font-semibold mb-3">Top open findings</h2>
          {data.top_findings.length === 0 ? (
            <EmptyState title="No open findings" />
          ) : (
            <ul className="space-y-2">
              {data.top_findings.map((f) => (
                <li key={f.id}>
                  <Link
                    to={`/orgs/${orgId}/findings/${f.id}`}
                    className="flex gap-2 items-start hover:bg-[var(--bg-elevated)] p-2 rounded-md -mx-2"
                  >
                    <Badge className={severityColor(f.severity)}>{f.severity}</Badge>
                    <div className="min-w-0">
                      <p className="text-sm truncate">{f.text}</p>
                      <p className="text-xs text-[var(--text-muted)] font-mono truncate">{f.asset_value}</p>
                    </div>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="panel p-4">
          <h2 className="text-sm font-semibold mb-3">Recent events</h2>
          {data.events.length === 0 ? (
            <EmptyState title="No change events" />
          ) : (
            <ul className="space-y-2 max-h-80 overflow-auto">
              {data.events.map((e) => (
                <li key={e.id} className="text-sm border-b border-[var(--border)] pb-2 last:border-0">
                  <span className="font-mono text-xs text-accent">{e.kind}</span>
                  <p className="truncate">{e.text}</p>
                  <p className="text-xs text-[var(--text-muted)]">{formatRelative(e.created)}</p>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
