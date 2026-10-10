import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { useRequireOrg } from "../context/OrgContext";
import { Badge, EmptyState, ErrorState, Skeleton } from "../components/ui/StateViews";
import { FINDING_STATES, SEVERITIES, severityColor } from "../lib/utils";
import { FindingDetailPanel } from "./FindingDetailPanel";

export function FindingsPage() {
  const { orgId } = useRequireOrg();
  const { findingId } = useParams();
  const [state, setState] = useState("open");
  const [severity, setSeverity] = useState("");
  const [q, setQ] = useState("");
  const [page, setPage] = useState(1);

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ["findings", orgId, state, severity, q, page],
    queryFn: () =>
      api.listFindings(orgId, { state, severity, q, page, page_size: 50 }),
  });

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Findings</h1>
      <div className="flex flex-wrap gap-2">
        <select className="input w-32" value={state} onChange={(e) => setState(e.target.value)}>
          {FINDING_STATES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <select className="input w-32" value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">All severities</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <input
          className="input max-w-sm flex-1"
          placeholder="Search text or asset…"
          value={q}
          onChange={(e) => {
            setQ(e.target.value);
            setPage(1);
          }}
        />
      </div>

      {isLoading && <Skeleton className="h-96" />}
      {isError && <ErrorState message="Failed to load findings" onRetry={() => refetch()} />}
      {data?.items.length === 0 && <EmptyState title="No findings match filters" />}

      {data && data.items.length > 0 && (
        <div className="panel divide-y divide-[var(--border)]">
          {data.items.map((f) => (
            <Link
              key={f.id}
              to={`/orgs/${orgId}/findings/${f.id}`}
              className="flex gap-3 p-3 hover:bg-[var(--bg-elevated)] block"
            >
              <Badge className={severityColor(f.severity)}>{f.severity}</Badge>
              <div className="min-w-0 flex-1">
                <p className="text-sm">{f.text}</p>
                <p className="text-xs text-[var(--text-muted)] font-mono mt-1">
                  {f.asset_value} · {f.state}
                </p>
              </div>
            </Link>
          ))}
        </div>
      )}

      {findingId && <FindingDetailPanel findingId={Number(findingId)} />}
    </div>
  );
}
