import { AlertCircle, Inbox, RefreshCw } from "lucide-react";
import { cn } from "../../lib/utils";

export function Skeleton({ className }: { className?: string }) {
  return (
    <div
      className={cn("animate-pulse rounded-md bg-[var(--bg-elevated)]", className)}
      aria-hidden
    />
  );
}

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description?: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="panel p-10 flex flex-col items-center text-center gap-3">
      <Inbox className="w-10 h-10 text-[var(--text-muted)]" strokeWidth={1.25} />
      <h3 className="text-lg font-semibold">{title}</h3>
      {description && <p className="text-sm text-[var(--text-muted)] max-w-md">{description}</p>}
      {action}
    </div>
  );
}

export function ErrorState({
  message,
  onRetry,
}: {
  message: string;
  onRetry?: () => void;
}) {
  return (
    <div className="panel p-8 flex flex-col items-center gap-3 text-center border-red-400/30">
      <AlertCircle className="w-9 h-9 text-red-400" strokeWidth={1.25} />
      <p className="text-sm">{message}</p>
      {onRetry && (
        <button type="button" className="btn-ghost" onClick={onRetry}>
          <RefreshCw className="w-4 h-4" />
          Retry
        </button>
      )}
    </div>
  );
}

export function Badge({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border",
        className,
      )}
    >
      {children}
    </span>
  );
}
