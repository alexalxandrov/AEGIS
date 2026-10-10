import { NavLink, Outlet, useLocation } from "react-router-dom";
import {
  Activity,
  Bot,
  FileText,
  GitBranch,
  LayoutDashboard,
  Moon,
  Scan,
  Server,
  Settings,
  ShieldAlert,
  Sun,
  Table2,
} from "lucide-react";
import { useOrg } from "../../context/OrgContext";
import { useTheme } from "../../context/ThemeContext";
import { cn } from "../../lib/utils";
import { GlobalSearch } from "./GlobalSearch";
import { Breadcrumbs } from "./Breadcrumbs";
import { Onboarding } from "../Onboarding";

const nav = [
  { to: "overview", label: "Overview", icon: LayoutDashboard },
  { to: "assets", label: "Assets", icon: Table2 },
  { to: "graph", label: "Graph", icon: GitBranch },
  { to: "findings", label: "Findings", icon: ShieldAlert },
  { to: "monitoring", label: "Monitoring", icon: Activity },
  { to: "scans", label: "Scans", icon: Scan },
  { to: "sources", label: "Sources", icon: Server },
  { to: "reports", label: "Reports", icon: FileText },
  { to: "ai", label: "AI Analyst", icon: Bot },
  { to: "settings", label: "Settings", icon: Settings },
];

export function AppShell() {
  const { orgs, orgId, setOrgId, isLoading } = useOrg();
  const { theme, toggle } = useTheme();
  const loc = useLocation();

  if (!isLoading && orgs.length === 0) {
    return <Onboarding />;
  }

  const base = orgId ? `/orgs/${orgId}` : "";

  return (
    <div className="min-h-screen flex">
      <aside
        className="w-56 shrink-0 border-r border-[var(--border)] bg-[var(--bg-panel)] flex flex-col"
        aria-label="Primary navigation"
      >
        <div className="px-4 py-5 border-b border-[var(--border)]">
          <div className="flex items-center gap-2">
            <img src="/aegis.svg" alt="" className="w-8 h-8" />
            <span className="text-xl font-semibold tracking-tight">AEGIS</span>
          </div>
          <p className="text-[10px] uppercase tracking-widest text-[var(--text-muted)] mt-1">
            External attack surface
          </p>
        </div>
        <nav className="flex-1 p-2 space-y-0.5 overflow-y-auto">
          {nav.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={`${base}/${to}`}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-2.5 px-3 py-2 rounded-md text-sm transition-colors",
                  isActive
                    ? "bg-accent/15 text-accent font-medium"
                    : "text-[var(--text-muted)] hover:text-[var(--text)] hover:bg-[var(--bg-elevated)]",
                )
              }
            >
              <Icon className="w-4 h-4 shrink-0" strokeWidth={1.75} />
              {label}
            </NavLink>
          ))}
        </nav>
      </aside>

      <div className="flex-1 flex flex-col min-w-0">
        <header className="h-14 shrink-0 border-b border-[var(--border)] bg-[var(--bg-panel)] px-4 flex items-center gap-4">
          <label className="sr-only" htmlFor="org-select">
            Organization
          </label>
          <select
            id="org-select"
            className="input w-48 shrink-0"
            value={orgId ?? ""}
            onChange={(e) => setOrgId(Number(e.target.value))}
          >
            {orgs.map((o) => (
              <option key={o.id} value={o.id}>
                {o.name}
              </option>
            ))}
          </select>
          <GlobalSearch />
          <button
            type="button"
            className="btn-ghost p-2"
            onClick={toggle}
            aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
          >
            {theme === "dark" ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
          </button>
        </header>

        <main className="flex-1 overflow-auto p-6" key={loc.pathname}>
          <Breadcrumbs />
          <Outlet />
        </main>
      </div>
    </div>
  );
}
