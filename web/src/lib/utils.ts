import clsx, { type ClassValue } from "clsx";

export function cn(...inputs: ClassValue[]) {
  return clsx(inputs);
}

export function formatTs(ts: number | null | undefined): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

export function formatRelative(ts: number | null | undefined): string {
  if (!ts) return "—";
  const diff = Date.now() / 1000 - ts;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export const SCOPES = ["VERIFIED", "CANDIDATE", "THIRD_PARTY", "OUT_OF_SCOPE"] as const;
export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export const FINDING_STATES = ["open", "accepted", "baseline", "closed", "all"] as const;

export function severityColor(sev: string): string {
  switch (sev) {
    case "critical":
      return "text-red-400 border-red-400/40 bg-red-400/10";
    case "high":
      return "text-orange-400 border-orange-400/40 bg-orange-400/10";
    case "medium":
      return "text-amber-400 border-amber-400/40 bg-amber-400/10";
    case "low":
      return "text-sky-400 border-sky-400/40 bg-sky-400/10";
    default:
      return "text-[var(--text-muted)] border-[var(--border)] bg-[var(--bg-elevated)]";
  }
}

export function scopeColor(scope: string): string {
  switch (scope) {
    case "VERIFIED":
      return "text-accent border-accent/40 bg-accent/10";
    case "CANDIDATE":
      return "text-amber-300 border-amber-300/40 bg-amber-300/10";
    case "THIRD_PARTY":
      return "text-violet-300 border-violet-300/40 bg-violet-300/10";
    default:
      return "text-[var(--text-muted)] border-[var(--border)]";
  }
}
