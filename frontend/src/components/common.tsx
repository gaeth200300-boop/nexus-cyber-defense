import { type ReactNode } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, FolderPlus, Loader2, RefreshCw } from "lucide-react";
import { useTranslation } from "react-i18next";
import { useProject } from "../context/ProjectContext";
import { cn, severityClasses, severityDot, titleCase } from "../lib/utils";
import { Button, buttonClass, Card, EmptyState, Skeleton } from "./ui";

export function ProjectGate({ children }: { children: ReactNode }) {
  const { t } = useTranslation();
  const { selectedProject, loading } = useProject();

  if (loading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-28 w-full rounded-2xl" />
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          {[0, 1, 2, 3].map((key) => (
            <Skeleton key={key} className="h-28 w-full rounded-2xl" />
          ))}
        </div>
        <Skeleton className="h-72 w-full rounded-2xl" />
      </div>
    );
  }

  if (!selectedProject) {
    return (
      <Card className="p-2">
        <EmptyState
          icon={FolderPlus}
          title={t("common.noProjectTitle")}
          description={t("common.noProjectBody")}
          action={
            <Link to="/projects?new=1" className={buttonClass("primary")}>
              <FolderPlus className="h-4 w-4" />
              {t("common.createFirstProject")}
            </Link>
          }
        />
      </Card>
    );
  }

  return <>{children}</>;
}

export function SectionCard({
  title,
  subtitle,
  actions,
  children,
  className,
  bodyClassName,
  icon: Icon
}: {
  title?: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
  icon?: React.ComponentType<{ className?: string }>;
}) {
  return (
    <Card className={cn("overflow-hidden", className)}>
      {title || actions ? (
        <div className="flex flex-wrap items-start justify-between gap-3 border-b border-line/60 px-4 py-3.5 sm:px-5">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              {Icon ? (
                <span className="grid h-6 w-6 place-items-center rounded-md bg-accent/10 text-accent">
                  <Icon className="h-3.5 w-3.5" />
                </span>
              ) : null}
              <h3 className="truncate text-xs font-semibold text-ink">{title}</h3>
            </div>
            {subtitle ? <p className="mt-1 text-[10px] leading-relaxed text-muted">{subtitle}</p> : null}
          </div>
          {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
        </div>
      ) : null}
      <div className={bodyClassName}>{children}</div>
    </Card>
  );
}

export function DataLoading({ label }: { label?: string }) {
  const { t } = useTranslation();
  return (
    <div className="flex items-center justify-center gap-2 py-12 text-xs text-muted">
      <Loader2 className="h-4 w-4 animate-spin text-accent" />
      {label || t("common.loading")}
    </div>
  );
}

export function DataError({
  message,
  onRetry,
  className
}: {
  message?: string;
  onRetry?: () => void;
  className?: string;
}) {
  const { t } = useTranslation();
  return (
    <div className={cn("flex flex-col items-center justify-center px-5 py-10 text-center", className)}>
      <span className="grid h-10 w-10 place-items-center rounded-xl border border-rose-400/20 bg-rose-400/10 text-rose-300">
        <AlertTriangle className="h-5 w-5" />
      </span>
      <p className="mt-3 text-xs font-medium text-ink">{t("common.errorTitle")}</p>
      <p className="mt-1 max-w-lg text-[11px] leading-relaxed text-muted">
        {message || t("common.errorDescription")}
      </p>
      {onRetry ? (
        <Button variant="secondary" size="sm" className="mt-3" icon={RefreshCw} onClick={onRetry}>
          {t("common.retry")}
        </Button>
      ) : null}
    </div>
  );
}

export function SeverityLegend({ counts }: { counts: Record<string, number> }) {
  const order = ["critical", "high", "medium", "low", "info"];
  return (
    <div className="flex flex-wrap items-center gap-2">
      {order.map((severity) => (
        <span
          key={severity}
          className={cn("inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-[9px] font-medium", severityClasses[severity])}
        >
          <span className={cn("h-1.5 w-1.5 rounded-full", severityDot[severity])} />
          {titleCase(severity)}
          <span className="font-mono tabular-nums opacity-75">{counts[severity] || 0}</span>
        </span>
      ))}
    </div>
  );
}

export function StatusDot({ active, className }: { active?: boolean; className?: string }) {
  return (
    <span className={cn("relative flex h-2 w-2 shrink-0", className)}>
      {active ? (
        <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-50" />
      ) : null}
      <span className={cn("relative inline-flex h-2 w-2 rounded-full", active ? "bg-emerald-400" : "bg-slate-500")} />
    </span>
  );
}

export function MiniStat({
  label,
  value,
  tone
}: {
  label: ReactNode;
  value: ReactNode;
  tone?: string;
}) {
  return (
    <div className="rounded-xl border border-line/60 bg-panel2/50 p-3">
      <p className="text-[9px] uppercase tracking-[0.1em] text-faint">{label}</p>
      <p className={cn("mt-1 font-display text-lg font-semibold tabular-nums text-ink", tone)}>{value}</p>
    </div>
  );
}
