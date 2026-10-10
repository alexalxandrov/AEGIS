import { Link } from "react-router-dom";

export function renderAnswerWithCites(text: string, orgId: number) {
  const parts = text.split(/(\b(?:obs|finding|asset):\d+\b)/g);
  return parts.map((part, i) => {
    const m = part.match(/^(obs|finding|asset):(\d+)$/);
    if (!m) return <span key={i}>{part}</span>;
    const [, kind, id] = m;
    let to = `/orgs/${orgId}/assets/${id}`;
    if (kind === "finding") to = `/orgs/${orgId}/findings/${id}`;
    if (kind === "obs") to = `#obs-${id}`;
    return (
      <Link key={i} to={to} className="text-accent hover:underline font-mono text-xs">
        {part}
      </Link>
    );
  });
}

export function CiteList({ cites, orgId }: { cites: string[]; orgId: number }) {
  if (!cites.length) return null;
  return (
    <div className="flex flex-wrap gap-2 mt-2">
      {cites.map((c) => {
        const m = c.match(/^(obs|finding|asset):(\d+)$/);
        if (!m) return null;
        const [, kind, id] = m;
        let to = `/orgs/${orgId}/assets/${id}`;
        if (kind === "finding") to = `/orgs/${orgId}/findings/${id}`;
        return (
          <Link key={c} to={to} className="text-xs font-mono border border-accent/40 rounded px-2 py-0.5 text-accent">
            {c}
          </Link>
        );
      })}
    </div>
  );
}
