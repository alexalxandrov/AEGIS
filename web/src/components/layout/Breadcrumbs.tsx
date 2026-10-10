import { Link, useLocation, useParams } from "react-router-dom";
import { ChevronRight } from "lucide-react";
import { useOrg } from "../../context/OrgContext";

const labels: Record<string, string> = {
  overview: "Overview",
  assets: "Assets",
  graph: "Graph",
  findings: "Findings",
  monitoring: "Monitoring",
  scans: "Scans",
  sources: "Sources",
  reports: "Reports",
  ai: "AI Analyst",
  settings: "Settings",
};

export function Breadcrumbs() {
  const { org } = useOrg();
  const { orgId } = useParams();
  const loc = useLocation();
  const parts = loc.pathname.split("/").filter(Boolean);
  const page = parts[2];

  if (!orgId) return null;

  return (
    <nav aria-label="Breadcrumb" className="flex items-center gap-1 text-sm text-[var(--text-muted)] mb-4">
      <Link to={`/orgs/${orgId}/overview`} className="hover:text-accent">
        {org?.name ?? "Org"}
      </Link>
      {page && labels[page] && (
        <>
          <ChevronRight className="w-3.5 h-3.5" />
          <span className="text-[var(--text)]">{labels[page]}</span>
        </>
      )}
    </nav>
  );
}
