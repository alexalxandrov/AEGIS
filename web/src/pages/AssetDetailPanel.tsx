import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { X } from "lucide-react";
import { api, ApiError } from "../api/client";
import { useRequireOrg } from "../context/OrgContext";
import { Badge, Skeleton } from "../components/ui/StateViews";
import { formatTs, SCOPES, scopeColor, severityColor } from "../lib/utils";

export function AssetDetailPanel({ assetId }: { assetId: number }) {
  const { orgId } = useRequireOrg();
  const qc = useQueryClient();
  const [scope, setScope] = useState("");
  const [note, setNote] = useState("");
  const [err, setErr] = useState<string | null>(null);

  const { data, isLoading, isError } = useQuery({
    queryKey: ["asset", assetId],
    queryFn: () => api.getAsset(assetId),
  });

  const mutation = useMutation({
    mutationFn: () =>
      api.setAssetScope(assetId, { scope: scope || data!.scope, note, method: "ui" }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["asset", assetId] });
      qc.invalidateQueries({ queryKey: ["assets", orgId] });
      setErr(null);
    },
    onError: (e) => setErr(e instanceof ApiError ? e.message : "Scope update failed"),
  });

  if (isLoading) return <Skeleton className="fixed inset-y-0 right-0 w-full max-w-xl z-40 m-4 h-auto" />;
  if (isError || !data) return null;

  const selectedScope = scope || data.scope;

  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-black/40" role="dialog" aria-modal>
      <div className="panel w-full max-w-xl h-full overflow-auto m-0 rounded-none border-l shadow-xl p-6 space-y-6">
        <div className="flex justify-between items-start gap-4">
          <div>
            <p className="label">Asset</p>
            <h2 className="text-xl font-mono break-all">{data.value}</h2>
            <Badge className={`mt-2 ${scopeColor(data.scope)}`}>{data.scope}</Badge>
          </div>
          <Link to={`/orgs/${orgId}/assets`} className="btn-ghost p-2" aria-label="Close">
            <X className="w-5 h-5" />
          </Link>
        </div>

        <section>
          <h3 className="text-sm font-semibold mb-2">Set scope</h3>
          {selectedScope === "VERIFIED" && (
            <p className="text-xs text-amber-400 mb-2">
              VERIFIED assets may be probed during active scans. Confirm intent before widening scope.
            </p>
          )}
          <div className="flex flex-wrap gap-2">
            <select className="input w-44" value={selectedScope} onChange={(e) => setScope(e.target.value)}>
              {SCOPES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
            <input
              className="input flex-1 min-w-[8rem]"
              placeholder="Note (optional)"
              value={note}
              onChange={(e) => setNote(e.target.value)}
            />
            <button
              type="button"
              className="btn-primary"
              disabled={mutation.isPending}
              onClick={() => mutation.mutate()}
            >
              Apply
            </button>
          </div>
          {err && <p className="text-sm text-red-400 mt-2">{err}</p>}
        </section>

        <section>
          <h3 className="text-sm font-semibold mb-2">Findings ({data.findings.length})</h3>
          <ul className="space-y-2 max-h-40 overflow-auto">
            {data.findings.map((f) => (
              <li key={f.id}>
                <Link to={`/orgs/${orgId}/findings/${f.id}`} className="flex gap-2 text-sm hover:text-accent">
                  <Badge className={severityColor(f.severity)}>{f.severity}</Badge>
                  <span className="truncate">{f.text}</span>
                </Link>
              </li>
            ))}
          </ul>
        </section>

        <section>
          <h3 className="text-sm font-semibold mb-2">Edges</h3>
          <ul className="text-xs font-mono space-y-1 max-h-32 overflow-auto">
            {data.edges.map((e) => (
              <li key={e.id}>
                {e.src === assetId ? (
                  <>
                    → {e.dst_value}{" "}
                    <span className="text-[var(--text-muted)]">({e.kind})</span>
                  </>
                ) : (
                  <>
                    ← {e.src_value}{" "}
                    <span className="text-[var(--text-muted)]">({e.kind})</span>
                  </>
                )}
              </li>
            ))}
          </ul>
        </section>

        <section>
          <h3 className="text-sm font-semibold mb-2">Observations</h3>
          <ul className="space-y-2 max-h-60 overflow-auto text-sm">
            {data.observations.map((o) => (
              <li key={o.id} id={`obs-${o.id}`} className="border border-[var(--border)] rounded p-2">
                <p className="font-mono text-xs text-accent">
                  obs:{o.id} · {o.source}/{o.key}
                </p>
                <pre className="text-xs mt-1 overflow-auto max-h-24 text-[var(--text-muted)]">
                  {o.payload_json ?? "—"}
                </pre>
                <p className="text-xs text-[var(--text-muted)]">{formatTs(o.created)}</p>
              </li>
            ))}
          </ul>
        </section>
      </div>
    </div>
  );
}
