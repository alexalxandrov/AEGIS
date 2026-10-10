import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  type Node,
  type Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { api } from "../api/client";
import { useRequireOrg } from "../context/OrgContext";
import { EmptyState, ErrorState, Skeleton } from "../components/ui/StateViews";
import { scopeColor } from "../lib/utils";

export function GraphPage() {
  const { orgId } = useRequireOrg();
  const nav = useNavigate();
  const [limit, setLimit] = useState(200);
  const [kinds, setKinds] = useState("");

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ["graph", orgId, limit, kinds],
    queryFn: () => api.graph(orgId, limit, kinds || undefined),
  });

  const layoutNodes = useMemo(() => {
    if (!data) return { nodes: [] as Node[], edges: [] as Edge[] };
    const cols = Math.ceil(Math.sqrt(data.nodes.length));
    const nodes: Node[] = data.nodes.map((n, i) => ({
      id: String(n.id),
      position: { x: (i % cols) * 180, y: Math.floor(i / cols) * 72 },
      data: { label: `${n.kind}: ${n.value}`, asset: n },
      style: {
        fontSize: 10,
        border: "1px solid var(--border)",
        background: "var(--bg-panel)",
        color: "var(--text)",
        padding: 6,
        borderRadius: 6,
        maxWidth: 160,
      },
    }));
    const edges: Edge[] = data.edges.map((e) => ({
      id: String(e.id),
      source: String(e.src),
      target: String(e.dst),
      label: e.kind,
      style: { stroke: "#3dbeb0", strokeWidth: 1 },
      labelStyle: { fill: "var(--text-muted)", fontSize: 9 },
    }));
    return { nodes, edges };
  }, [data]);

  const [nodes, setNodes, onNodesChange] = useNodesState(layoutNodes.nodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(layoutNodes.edges);

  useEffect(() => {
    setNodes(layoutNodes.nodes);
    setEdges(layoutNodes.edges);
  }, [layoutNodes, setNodes, setEdges]);

  const onNodeClick = useCallback(
    (_: React.MouseEvent, node: Node) => {
      nav(`/orgs/${orgId}/assets/${node.id}`);
    },
    [nav, orgId],
  );

  return (
    <div className="space-y-4 h-[calc(100vh-8rem)] flex flex-col">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <h1 className="text-2xl font-semibold">Asset graph</h1>
        <div className="flex gap-2">
          <input
            className="input w-24"
            type="number"
            min={10}
            max={800}
            value={limit}
            onChange={(e) => setLimit(Number(e.target.value))}
            aria-label="Node limit"
          />
          <input
            className="input w-40"
            placeholder="Kinds (comma)"
            value={kinds}
            onChange={(e) => setKinds(e.target.value)}
          />
        </div>
      </div>

      {data?.truncated && (
        <p className="text-xs text-amber-400">Graph truncated at {limit} nodes. Narrow filters or increase limit.</p>
      )}

      {isLoading && <Skeleton className="flex-1" />}
      {isError && <ErrorState message="Graph load failed" onRetry={() => refetch()} />}
      {data && data.nodes.length === 0 && (
        <EmptyState title="No graph data" description="Run a scan to populate assets and edges." />
      )}

      {data && data.nodes.length > 0 && (
        <div className="panel flex-1 min-h-[400px]">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onNodeClick={onNodeClick}
            fitView
            proOptions={{ hideAttribution: true }}
          >
            <Background color="var(--border)" gap={16} />
            <Controls />
            <MiniMap
              nodeColor={(n) => {
                const scope = (n.data as { asset?: { scope: string } }).asset?.scope;
                if (scope === "VERIFIED") return "#3dbeb0";
                return "#2a3238";
              }}
            />
          </ReactFlow>
        </div>
      )}
      <p className="text-xs text-[var(--text-muted)]">
        Click a node to open the asset. Scope colors:{" "}
        {["VERIFIED", "CANDIDATE"].map((s) => (
          <span key={s} className={`inline-block mx-1 px-1 border rounded ${scopeColor(s)}`}>
            {s}
          </span>
        ))}
      </p>
    </div>
  );
}
