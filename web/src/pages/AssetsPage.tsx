import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ChevronLeft, ChevronRight } from "lucide-react";
import { api } from "../api/client";
import { useRequireOrg } from "../context/OrgContext";
import { Badge, EmptyState, ErrorState, Skeleton } from "../components/ui/StateViews";
import { formatTs, SCOPES, scopeColor } from "../lib/utils";
import { AssetDetailPanel } from "./AssetDetailPanel";

export function AssetsPage() {
  const { orgId } = useRequireOrg();
  const { assetId } = useParams();
  const [q, setQ] = useState("");
  const [kind, setKind] = useState("");
  const [scope, setScope] = useState("");
  const [page, setPage] = useState(1);
  const [sort, setSort] = useState("last_seen");
  const [order, setOrder] = useState("desc");

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ["assets", orgId, q, kind, scope, page, sort, order],
    queryFn: () =>
      api.listAssets(orgId, { q, kind, scope, page, page_size: 50, sort, order }),
  });

  const totalPages = data ? Math.max(1, Math.ceil(data.total / (data.page_size || 50))) : 1;

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Assets</h1>

      <div className="flex flex-wrap gap-2">
        <input
          className="input max-w-xs"
          placeholder="Search value…"
          value={q}
          onChange={(e) => {
            setQ(e.target.value);
            setPage(1);
          }}
        />
        <select className="input w-32" value={kind} onChange={(e) => setKind(e.target.value)}>
          <option value="">All kinds</option>
          <option value="domain">domain</option>
          <option value="host">host</option>
          <option value="ip">ip</option>
          <option value="cidr">cidr</option>
        </select>
        <select className="input w-40" value={scope} onChange={(e) => setScope(e.target.value)}>
          <option value="">All scopes</option>
          {SCOPES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <select
          className="input w-36"
          value={`${sort}:${order}`}
          onChange={(e) => {
            const [s, o] = e.target.value.split(":");
            setSort(s);
            setOrder(o);
          }}
        >
          <option value="last_seen:desc">Last seen ↓</option>
          <option value="last_seen:asc">Last seen ↑</option>
          <option value="first_seen:desc">First seen ↓</option>
          <option value="value:asc">Value A–Z</option>
        </select>
      </div>

      {isLoading && <Skeleton className="h-96" />}
      {isError && <ErrorState message="Failed to load assets" onRetry={() => refetch()} />}
      {data && data.items.length === 0 && (
        <EmptyState title="No assets" description="Add seeds or run a scan." />
      )}

      {data && data.items.length > 0 && (
        <div className="panel overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-[var(--bg-elevated)] text-left text-xs uppercase text-[var(--text-muted)]">
              <tr>
                <th className="px-3 py-2">Kind</th>
                <th className="px-3 py-2">Value</th>
                <th className="px-3 py-2">Scope</th>
                <th className="px-3 py-2">Last seen</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((a) => (
                <tr key={a.id} className="border-t border-[var(--border)] hover:bg-[var(--bg-elevated)]/50">
                  <td className="px-3 py-2 font-mono text-xs">{a.kind}</td>
                  <td className="px-3 py-2">
                    <Link to={`/orgs/${orgId}/assets/${a.id}`} className="text-accent hover:underline">
                      {a.value}
                    </Link>
                  </td>
                  <td className="px-3 py-2">
                    <Badge className={scopeColor(a.scope)}>{a.scope}</Badge>
                  </td>
                  <td className="px-3 py-2 text-[var(--text-muted)]">{formatTs(a.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {data && data.total > 0 && (
        <div className="flex items-center justify-between text-sm">
          <span className="text-[var(--text-muted)]">
            {data.total} total · page {page}/{totalPages}
          </span>
          <div className="flex gap-2">
            <button type="button" className="btn-ghost" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button
              type="button"
              className="btn-ghost"
              disabled={page >= totalPages}
              onClick={() => setPage((p) => p + 1)}
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {assetId && <AssetDetailPanel assetId={Number(assetId)} />}
    </div>
  );
}
