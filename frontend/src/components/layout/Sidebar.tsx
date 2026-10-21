import { NavLink, useLocation } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import {
  ChevronLeft,
  ChevronsLeft,
  ChevronsRight,
  CircleDot,
  Command,
  ShieldCheck,
  X
} from "lucide-react";
import { navGroups } from "../../config/nav";
import { useAuth } from "../../context/AuthContext";
import { useProject } from "../../context/ProjectContext";
import { cn } from "../../lib/utils";
import { apiFetch } from "../../lib/api";
import type { Health } from "../../types";
import { Logo } from "../Logo";
import { Avatar, Tooltip } from "../ui";

export function Sidebar({
  collapsed,
  onToggleCollapsed,
  mobileOpen,
  onCloseMobile
}: {
  collapsed: boolean;
  onToggleCollapsed: () => void;
  mobileOpen: boolean;
  onCloseMobile: () => void;
}) {
  const { t } = useTranslation();
  const location = useLocation();
  const { user } = useAuth();
  const { projects } = useProject();
  const isAdmin = ["owner", "admin"].includes(user?.role || "");
  const health = useQuery({
    queryKey: ["health"],
    queryFn: () => apiFetch<Health>("/system/health", { auth: false }),
    refetchInterval: 45_000,
    staleTime: 15_000
  });

  const activeFor = (to: string) => {
    const [path, query] = to.split("?");
    if (query) {
      return location.pathname === path && location.search.includes(query);
    }
    if (path === "/dashboard") return location.pathname === "/" || location.pathname === "/dashboard";
    return location.pathname === path || location.pathname.startsWith(`${path}/`);
  };

  const healthy = health.data?.database_ok !== false && health.data?.status === "ok";

  return (
    <>
      <div
        className={cn(
          "fixed inset-0 z-40 bg-black/60 backdrop-blur-sm transition-opacity lg:hidden",
          mobileOpen ? "opacity-100" : "pointer-events-none opacity-0"
        )}
        onClick={onCloseMobile}
        aria-hidden="true"
      />
      <aside
        className={cn(
          "app-sidebar fixed inset-y-0 start-0 z-50 flex w-[272px] flex-col border-e border-line/60 bg-panel/95 shadow-panel backdrop-blur-xl transition-[width,transform] duration-300 lg:translate-x-0",
          collapsed ? "lg:w-[80px]" : "lg:w-[272px]",
          mobileOpen ? "translate-x-0" : "-translate-x-full rtl:translate-x-full"
        )}
      >
        <div
          className={cn(
            "flex h-[72px] shrink-0 items-center border-b border-line/60 px-4",
            collapsed ? "lg:justify-center lg:px-2" : "justify-between"
          )}
        >
          <NavLink to="/dashboard" className="group flex min-w-0 items-center gap-3" onClick={onCloseMobile}>
            <div className="relative grid h-10 w-10 shrink-0 place-items-center">
              <div className="absolute inset-0 rounded-xl bg-accent/15 blur-lg transition group-hover:bg-accent/25" />
              <Logo size={38} className="relative" />
            </div>
            <div className={cn("min-w-0 transition-opacity", collapsed && "lg:hidden")}>
              <div className="flex items-center gap-1.5">
                <span className="font-display text-[17px] font-bold tracking-[0.16em] text-ink">NEXUS</span>
                <span className="rounded border border-accent2/20 bg-accent2/10 px-1 py-0.5 font-mono text-[7px] font-semibold uppercase tracking-wider text-accent2">
                  v1
                </span>
              </div>
              <p className="mt-0.5 text-[8px] font-semibold uppercase tracking-[0.28em] text-faint">
                {t("app.tagline")}
              </p>
            </div>
          </NavLink>
          <button
            type="button"
            onClick={onCloseMobile}
            className="grid h-8 w-8 place-items-center rounded-lg text-muted transition hover:bg-panel2 hover:text-ink lg:hidden"
            aria-label={t("nav.closeMenu")}
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="no-scrollbar flex-1 overflow-y-auto px-3 py-4">
          <div className="space-y-5">
            {navGroups.map((group) => {
              const items = group.items.filter((item) => !item.adminOnly || isAdmin);
              if (!items.length) return null;
              return (
                <div key={group.labelKey}>
                  {!collapsed ? (
                    <p className="sidebar-nav-label mb-1.5">{t(group.labelKey)}</p>
                  ) : (
                    <div className="mx-auto mb-3 h-px w-7 bg-line/70 lg:block" />
                  )}
                  <nav className="space-y-0.5">
                    {items.map((item) => {
                      const active = activeFor(item.to);
                      const Icon = item.icon;
                      const content = (
                        <NavLink
                          to={item.to}
                          onClick={onCloseMobile}
                          className={cn(
                            "group relative flex h-9 items-center gap-2.5 rounded-lg px-2.5 text-[12px] font-medium transition duration-200",
                            collapsed && "lg:justify-center lg:px-0",
                            active
                              ? "bg-accent/12 text-ink shadow-[inset_0_0_0_1px_rgb(var(--accent)/.14)]"
                              : "text-muted hover:bg-panel2/80 hover:text-ink"
                          )}
                        >
                          {active ? (
                            <span className="absolute inset-y-2 start-0 w-0.5 rounded-full bg-gradient-to-b from-accent to-accent2" />
                          ) : null}
                          <Icon
                            className={cn(
                              "h-4 w-4 shrink-0 transition",
                              active ? "text-accent" : "text-faint group-hover:text-muted"
                            )}
                          />
                          <span className={cn("truncate", collapsed && "lg:hidden")}>{t(item.labelKey)}</span>
                          {item.to === "/projects" && projects.length && !collapsed ? (
                            <span className="ms-auto rounded-full bg-panel3 px-1.5 py-0.5 text-[9px] tabular-nums text-faint">
                              {projects.length}
                            </span>
                          ) : null}
                        </NavLink>
                      );
                      return collapsed ? (
                        <Tooltip key={item.to} content={t(item.labelKey)}>
                          <div>{content}</div>
                        </Tooltip>
                      ) : (
                        <div key={item.to}>{content}</div>
                      );
                    })}
                  </nav>
                </div>
              );
            })}
          </div>

          {!collapsed ? (
            <div className="mt-5 rounded-xl border border-accent/15 bg-gradient-to-br from-accent/[0.08] to-accent2/[0.03] p-3">
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-accent" />
                <p className="text-[10px] font-semibold text-ink">{t("footer.policy")}</p>
              </div>
              <p className="mt-1.5 text-[10px] leading-relaxed text-muted">{t("projects.policyBody")}</p>
            </div>
          ) : null}
        </div>

        <div className="shrink-0 border-t border-line/60 p-3">
          <div className={cn("flex items-center gap-2", collapsed && "lg:flex-col")}>
            <div
              className={cn(
                "flex min-w-0 flex-1 items-center gap-2 rounded-lg px-1 py-1",
                collapsed && "lg:flex-none lg:justify-center"
              )}
              title={healthy ? t("common.live") : t("common.unknown")}
            >
              <span className="relative flex h-2 w-2 shrink-0">
                <span
                  className={cn(
                    "absolute inline-flex h-full w-full rounded-full opacity-60",
                    healthy ? "animate-ping bg-emerald-400" : "bg-amber-400"
                  )}
                />
                <span
                  className={cn(
                    "relative inline-flex h-2 w-2 rounded-full",
                    healthy ? "bg-emerald-400" : "bg-amber-400"
                  )}
                />
              </span>
              <div className={cn("min-w-0", collapsed && "lg:hidden")}>
                <p className="truncate text-[10px] font-medium text-ink">
                  {healthy ? t("common.live") : t("common.unknown")}
                </p>
                <p className="truncate text-[9px] text-faint">
                  {health.data?.environment || "—"} · {health.data?.version || ""}
                </p>
              </div>
            </div>
            <button
              type="button"
              onClick={onToggleCollapsed}
              className={cn(
                "hidden h-8 w-8 shrink-0 place-items-center rounded-lg text-faint transition hover:bg-panel2 hover:text-ink lg:grid",
                collapsed && "lg:mt-1"
              )}
              title={collapsed ? t("nav.expand") : t("nav.collapse")}
            >
              {collapsed ? (
                <ChevronsRight className="h-4 w-4 rtl:flip-x" />
              ) : (
                <ChevronsLeft className="h-4 w-4 rtl:flip-x" />
              )}
            </button>
          </div>
          <div className={cn("mt-2 flex items-center gap-2 border-t border-line/40 px-1 pt-2.5", collapsed && "lg:justify-center")}>
            <Avatar name={user?.full_name || user?.email} size="sm" />
            <div className={cn("min-w-0 flex-1", collapsed && "lg:hidden")}>
              <p className="truncate text-[10px] font-medium text-ink">{user?.full_name || "—"}</p>
              <p className="truncate text-[9px] text-faint">{user?.role || ""}</p>
            </div>
            {!collapsed ? (
              <span className="text-[8px] uppercase tracking-[0.15em] text-faint">v1.0</span>
            ) : null}
          </div>
        </div>
      </aside>
    </>
  );
}
