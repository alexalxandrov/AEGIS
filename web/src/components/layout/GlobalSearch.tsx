import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Search } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../api/client";
import { useOrg } from "../../context/OrgContext";
import { cn, severityColor } from "../../lib/utils";

export function GlobalSearch() {
  const { orgId } = useOrg();
  const [q, setQ] = useState("");
  const [open, setOpen] = useState(false);
  const nav = useNavigate();
  const wrap = useRef<HTMLDivElement>(null);

  const { data } = useQuery({
    queryKey: ["search", q, orgId],
    queryFn: () => api.search(q.trim(), orgId ?? undefined),
    enabled: q.trim().length >= 2,
  });

  useEffect(() => {
    const onDoc = (e: MouseEvent) => {
      if (!wrap.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        wrap.current?.querySelector("input")?.focus();
        setOpen(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const hasResults =
    data && (data.assets.length > 0 || data.findings.length > 0);

  return (
    <div ref={wrap} className="relative flex-1 max-w-md">
      <div className="relative">
        <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-muted)]" />
        <input
          type="search"
          className="input pl-9 pr-16"
          placeholder="Search assets & findings"
          aria-label="Global search"
          value={q}
          onChange={(e) => {
            setQ(e.target.value);
            setOpen(true);
          }}
          onFocus={() => setOpen(true)}
        />
        <kbd className="absolute right-2 top-1/2 -translate-y-1/2 text-[10px] font-mono text-[var(--text-muted)] border border-[var(--border)] rounded px-1">
          ⌘K
        </kbd>
      </div>
      {open && q.trim().length >= 2 && (
        <div className="absolute z-50 mt-1 w-full panel shadow-lg max-h-80 overflow-auto">
          {!hasResults && (
            <p className="p-3 text-sm text-[var(--text-muted)]">No matches</p>
          )}
          {data?.assets.map((a) => (
            <button
              key={`a-${a.id}`}
              type="button"
              className="w-full text-left px-3 py-2 hover:bg-[var(--bg-elevated)] text-sm flex gap-2"
              onClick={() => {
                nav(`/orgs/${a.org_id}/assets/${a.id}`);
                setOpen(false);
                setQ("");
              }}
            >
              <span className="font-mono text-xs text-[var(--text-muted)]">{a.kind}</span>
              <span className="truncate">{a.value}</span>
            </button>
          ))}
          {data?.findings.map((f) => (
            <button
              key={`f-${f.id}`}
              type="button"
              className="w-full text-left px-3 py-2 hover:bg-[var(--bg-elevated)] text-sm flex gap-2 items-center"
              onClick={() => {
                nav(`/orgs/${f.org_id}/findings/${f.id}`);
                setOpen(false);
                setQ("");
              }}
            >
              <span className={cn("text-xs border rounded px-1", severityColor(f.severity))}>
                {f.severity}
              </span>
              <span className="truncate">{f.text}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
