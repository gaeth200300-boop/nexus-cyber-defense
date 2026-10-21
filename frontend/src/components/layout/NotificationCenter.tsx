import { useMemo, useState } from "react";
import * as Popover from "@radix-ui/react-popover";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  Bell,
  BellOff,
  Bug,
  BriefcaseBusiness,
  CheckCheck,
  CircleAlert,
  ScanLine,
  ShieldAlert,
  Siren,
  Workflow,
  X
} from "lucide-react";
import { useTranslation } from "react-i18next";
import { apiFetch, errorMessage } from "../../lib/api";
import { cn, fromNow, severityDot } from "../../lib/utils";
import { currentLang } from "../../lib/i18n";
import { useProject } from "../../context/ProjectContext";
import { useToast } from "../../context/ToastContext";
import { notificationRoute } from "../../lib/links";
import type { NotificationItem, Lang } from "../../types";
import { Badge, IconButton, Skeleton } from "../ui";
import { useNavigate } from "react-router-dom";

interface NotificationsResponse {
  items: NotificationItem[];
  unread: number;
  counts: { by_kind: Record<string, number>; by_severity: Record<string, number> };
  window_days: number;
}

const icons: Record<string, typeof Bell> = {
  finding: Bug,
  alert: Siren,
  incident: ShieldAlert,
  scan: ScanLine,
  asset_change: Activity,
  job: Workflow
};

const filters = [
  { key: "all", label: "notifications.all", kinds: null },
  { key: "findings", label: "notifications.findings", kinds: ["finding"] },
  { key: "alerts", label: "notifications.alerts", kinds: ["alert", "incident"] },
  { key: "changes", label: "notifications.changes", kinds: ["asset_change"] },
  { key: "failures", label: "notifications.scanFailures", kinds: ["scan", "job"] }
];

export function NotificationCenter({ collapsed }: { collapsed?: boolean }) {
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const queryClient = useQueryClient();
  const toast = useToast();
  const navigate = useNavigate();
  const { setSelectedProject } = useProject();
  const [open, setOpen] = useState(false);
  const [filter, setFilter] = useState("all");

  const query = useQuery({
    queryKey: ["notifications"],
    queryFn: () => apiFetch<NotificationsResponse>("/system/notifications"),
    refetchInterval: open ? 20_000 : 45_000,
    staleTime: 10_000
  });

  const dismissMutation = useMutation({
    mutationFn: (ids: string[]) =>
      apiFetch<{ dismissed: number; remaining: number }>("/system/notifications/dismiss", {
        method: "POST",
        body: { ids }
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["notifications"] });
      toast.toast({ title: t("notifications.dismissed"), variant: "success" });
    },
    onError: (error) =>
      toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" })
  });

  const items = useMemo(() => {
    const all = query.data?.items || [];
    const current = filters.find((entry) => entry.key === filter);
    if (!current?.kinds) return all;
    return all.filter((item) => current.kinds?.includes(item.kind));
  }, [query.data, filter]);

  const unread = query.data?.unread || 0;

  return (
    <Popover.Root open={open} onOpenChange={setOpen}>
      <Popover.Trigger asChild>
        <button
          type="button"
          className={cn(
            "relative grid h-9 w-9 place-items-center rounded-xl text-muted transition hover:bg-panel2 hover:text-ink focus-ring",
            collapsed && "w-full"
          )}
          aria-label={t("common.notifications")}
        >
          <Bell className="h-[18px] w-[18px]" />
          {unread > 0 ? (
            <span className="absolute right-1.5 top-1.5 grid min-w-4 place-items-center rounded-full bg-accent px-1 text-[8px] font-bold leading-4 text-white ring-2 ring-bg">
              {unread > 99 ? "99+" : unread}
            </span>
          ) : null}
        </button>
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Content
          align="end"
          sideOffset={10}
          className="z-[90] w-[min(420px,calc(100vw-1.5rem))] overflow-hidden rounded-2xl border border-line bg-panel shadow-panel outline-none animate-scale-in"
        >
          <div className="border-b border-line/70 p-4">
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-sm font-semibold text-ink">{t("notifications.title")}</h3>
                  {unread > 0 ? <Badge tone="accent">{unread}</Badge> : null}
                </div>
                <p className="mt-1 text-[11px] text-muted">{t("notifications.derived")}</p>
              </div>
              <button
                type="button"
                onClick={() => dismissMutation.mutate([])}
                disabled={dismissMutation.isPending || !items.length}
                className="inline-flex items-center gap-1 rounded-lg border border-line px-2 py-1 text-[10px] text-muted transition hover:text-ink disabled:opacity-40"
              >
                <CheckCheck className="h-3 w-3" />
                {t("notifications.dismissAll")}
              </button>
            </div>
            <div className="no-scrollbar mt-3 flex gap-1 overflow-x-auto">
              {filters.map((entry) => (
                <button
                  key={entry.key}
                  type="button"
                  onClick={() => setFilter(entry.key)}
                  className={cn(
                    "shrink-0 rounded-full px-2.5 py-1 text-[10px] font-medium transition",
                    filter === entry.key ? "bg-accent/15 text-accent" : "text-faint hover:text-ink"
                  )}
                >
                  {t(entry.label)}
                </button>
              ))}
            </div>
          </div>

          <div className="max-h-[min(430px,62vh)] overflow-y-auto">
            {query.isLoading ? (
              <div className="space-y-3 p-4">
                {[0, 1, 2].map((index) => (
                  <div key={index} className="flex gap-3">
                    <Skeleton className="h-8 w-8 rounded-lg" />
                    <div className="flex-1 space-y-2">
                      <Skeleton className="h-3 w-4/5" />
                      <Skeleton className="h-2.5 w-2/3" />
                    </div>
                  </div>
                ))}
              </div>
            ) : !items.length ? (
              <div className="px-6 py-10 text-center">
                <BellOff className="mx-auto h-7 w-7 text-faint" />
                <p className="mt-3 text-xs font-medium text-ink">{t("notifications.emptyTitle")}</p>
                <p className="mt-1 text-[11px] text-muted">{t("notifications.emptyBody")}</p>
              </div>
            ) : (
              <ul className="divide-y divide-line/50">
                {items.slice(0, 40).map((item: NotificationItem) => {
                  const Icon = icons[item.kind] || CircleAlert;
                  return (
                    <li key={item.id} className="group relative">
                      <button
                        type="button"
                        onClick={() => {
                          if (item.project_id) setSelectedProject(item.project_id);
                          navigate(notificationRoute(item));
                          setOpen(false);
                        }}
                        className="flex w-full items-start gap-3 p-3.5 pe-9 text-start transition hover:bg-panel2/70"
                      >
                        <span className="relative mt-0.5 grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-line bg-panel2">
                          <Icon className="h-3.5 w-3.5 text-muted" />
                          <span
                            className={cn(
                              "absolute -end-0.5 -top-0.5 h-2 w-2 rounded-full ring-2 ring-panel",
                              severityDot[item.severity] || severityDot.info
                            )}
                          />
                        </span>
                        <span className="min-w-0 flex-1">
                          <span className="line-clamp-1 text-xs font-medium text-ink">{item.title}</span>
                          <span className="mt-0.5 line-clamp-2 text-[11px] leading-relaxed text-muted">
                            {item.message}
                          </span>
                          <span className="mt-1 flex items-center gap-2 text-[9px] uppercase tracking-wider text-faint">
                            <span>{item.project_name || item.kind}</span>
                            <span>·</span>
                            <span>{fromNow(item.ts, lang)}</span>
                          </span>
                        </span>
                      </button>
                      <button
                        type="button"
                        aria-label={t("common.close")}
                        onClick={(event) => {
                          event.stopPropagation();
                          dismissMutation.mutate([item.id]);
                        }}
                        className="absolute end-2 top-3 grid h-6 w-6 place-items-center rounded-md text-faint opacity-0 transition hover:bg-panel3 hover:text-ink group-hover:opacity-100"
                      >
                        <X className="h-3.5 w-3.5" />
                      </button>
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
          <div className="flex items-center justify-between border-t border-line/70 bg-panel2/40 px-4 py-2.5">
            <span className="text-[10px] text-faint">
              {t("notifications.window", { days: query.data?.window_days || "—" })}
            </span>
            <button
              type="button"
              onClick={() => {
                navigate("/admin?tab=settings");
                setOpen(false);
              }}
              className="text-[10px] font-medium text-accent hover:underline"
            >
              {t("common.filters")}
            </button>
          </div>
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
}
