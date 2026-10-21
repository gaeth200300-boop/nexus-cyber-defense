import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import {
  ArrowRight,
  Boxes,
  Bug,
  CornerDownLeft,
  FileSearch,
  FileText,
  Fingerprint,
  FlaskConical,
  Globe2,
  Loader2,
  Radar,
  ScanLine,
  Search,
  ShieldCheck,
  Siren,
  Sparkles,
  X
} from "lucide-react";
import { apiFetch } from "../../lib/api";
import { cn } from "../../lib/utils";
import { useDebouncedValue } from "../../hooks";
import { useAuth } from "../../context/AuthContext";
import { useProject } from "../../context/ProjectContext";
import { allNavItems, adminNavItems, type NavItem } from "../../config/nav";
import { searchRoute } from "../../lib/links";
import type { SearchItem, SearchResults } from "../../types";
import { Modal } from "../ui";

const typeIcons: Record<string, typeof Search> = {
  project: ShieldCheck,
  asset: Boxes,
  finding: Bug,
  scan: ScanLine,
  alert: Siren,
  report: FileText,
  lab: FlaskConical,
  intel: Fingerprint,
  cve: Fingerprint,
  alert_incident: Siren
};

const typeLabels: Record<string, string> = {
  projects: "nav.projects",
  assets: "nav.assets",
  findings: "nav.findings",
  scans: "nav.scans",
  alerts: "soc.alerts",
  reports: "nav.reports",
  labs: "nav.labs",
  intel: "nav.intel"
};

interface PaletteItem {
  id: string;
  kind: "nav" | "result";
  title: string;
  subtitle?: string;
  icon: typeof Search;
  path: string;
  projectId?: string | null;
  group: string;
}

export function CommandPalette({
  open,
  onOpenChange
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const { user } = useAuth();
  const { setSelectedProject } = useProject();
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const debounced = useDebouncedValue(query.trim(), 280);
  const listRef = useRef<HTMLDivElement | null>(null);
  const isAdmin = ["owner", "admin"].includes(user?.role || "");

  useEffect(() => {
    if (!open) {
      setQuery("");
      setActive(0);
    }
  }, [open]);

  const searchQuery = useQuery({
    queryKey: ["global-search", debounced],
    queryFn: () =>
      apiFetch<SearchResults>("/system/search", {
        query: { q: debounced, limit: 5 }
      }),
    enabled: open && debounced.length >= 2,
    staleTime: 20_000
  });

  const navItems = useMemo(() => {
    const items = allNavItems.filter((item) => !item.adminOnly || isAdmin);
    const q = query.trim().toLowerCase();
    const filtered = q ? items.filter((item) => `${t(item.labelKey)} ${item.to}`.toLowerCase().includes(q)) : items;
    return filtered.slice(0, q ? 8 : 7);
  }, [isAdmin, query, t]);

  const resultGroups = useMemo(() => {
    const groups = searchQuery.data?.groups || {};
    const ordered = ["findings", "assets", "scans", "alerts", "projects", "reports", "intel", "labs"];
    return ordered
      .filter((key) => (groups[key] || []).length)
      .map((key) => ({
        key,
        label: t(typeLabels[key] || key),
        items: groups[key] || []
      }));
  }, [searchQuery.data, t]);

  const flatItems = useMemo<PaletteItem[]>(() => {
    const nav: PaletteItem[] = navItems.map((item) => ({
      id: `nav:${item.to}`,
      kind: "nav",
      title: t(item.labelKey),
      subtitle: item.to,
      icon: item.icon,
      path: item.to,
      group: t("command.quickNav")
    }));
    const results: PaletteItem[] = [];
    for (const group of resultGroups) {
      for (const item of group.items) {
        results.push({
          id: `result:${group.key}:${item.id}`,
          kind: "result",
          title: item.title,
          subtitle: item.subtitle,
          icon: typeIcons[item.type] || typeIcons[group.key] || FileSearch,
          path: searchRoute(item),
          projectId: item.project_id,
          group: group.label
        });
      }
    }
    return [...nav, ...results];
  }, [navItems, resultGroups, t]);

  useEffect(() => {
    setActive(0);
  }, [query, searchQuery.data]);

  useEffect(() => {
    const node = listRef.current?.querySelector<HTMLElement>(`[data-index="${active}"]`);
    node?.scrollIntoView({ block: "nearest" });
  }, [active]);

  const choose = (item: PaletteItem) => {
    if (item.projectId) setSelectedProject(item.projectId);
    navigate(item.path);
    onOpenChange(false);
  };

  const handleKeyDown = (event: React.KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setActive((current) => (flatItems.length ? (current + 1) % flatItems.length : 0));
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setActive((current) => (flatItems.length ? (current - 1 + flatItems.length) % flatItems.length : 0));
    } else if (event.key === "Enter") {
      event.preventDefault();
      const item = flatItems[active];
      if (item) choose(item);
    } else if (event.key === "Escape") {
      onOpenChange(false);
    }
  };

  const quickAdmin = useMemo<NavItem[]>(
    () => (isAdmin ? adminNavItems : []),
    [isAdmin]
  );

  let currentIndex = -1;

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title={t("command.title")}
      description={t("command.hint")}
      size="lg"
      icon={Search}
    >
      <div className="-mx-5 -mt-5">
        <div className="flex items-center gap-3 border-b border-line/70 px-4">
          <Search className="h-4 w-4 shrink-0 text-accent" />
          <input
            autoFocus
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={handleKeyDown}
            placeholder={t("command.placeholder")}
            className="h-14 min-w-0 flex-1 bg-transparent text-sm text-ink outline-none placeholder:text-faint"
            spellCheck={false}
          />
          {query ? (
            <button
              type="button"
              onClick={() => setQuery("")}
              className="grid h-7 w-7 place-items-center rounded-lg text-faint hover:bg-panel2 hover:text-ink"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          ) : null}
          <kbd className="hidden rounded-md border border-line bg-panel2 px-1.5 py-0.5 text-[9px] text-faint sm:block">
            ESC
          </kbd>
        </div>

        <div ref={listRef} className="max-h-[min(460px,58vh)] overflow-y-auto p-2">
          {query && navItems.length === 0 && !searchQuery.isFetching && flatItems.length === 0 ? (
            <div className="p-10 text-center">
              <FileSearch className="mx-auto h-7 w-7 text-faint" />
              <p className="mt-3 text-xs text-muted">{t("command.noResults")}</p>
            </div>
          ) : null}

          {navItems.length ? (
            <div className="mb-1">
              <p className="px-3 py-1.5 text-[9px] font-semibold uppercase tracking-[0.15em] text-faint">
                {t("command.quickNav")}
              </p>
              {navItems.map((item) => {
                currentIndex += 1;
                const index = currentIndex;
                const Icon = item.icon;
                return (
                  <button
                    key={item.to}
                    type="button"
                    data-index={index}
                    onMouseEnter={() => setActive(index)}
                    onClick={() => choose(flatItems[index])}
                    className={cn(
                      "flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-start transition",
                      active === index ? "bg-accent/10 text-ink" : "text-muted hover:bg-panel2"
                    )}
                  >
                    <span
                      className={cn(
                        "grid h-8 w-8 shrink-0 place-items-center rounded-lg border",
                        active === index
                          ? "border-accent/25 bg-accent/10 text-accent"
                          : "border-line bg-panel2 text-muted"
                      )}
                    >
                      <Icon className="h-3.5 w-3.5" />
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block text-xs font-medium">{t(item.labelKey)}</span>
                      <span className="block font-mono text-[9px] text-faint">{item.to}</span>
                    </span>
                    <ArrowRight className="h-3.5 w-3.5 opacity-40 rtl:flip-x" />
                  </button>
                );
              })}
            </div>
          ) : null}

          {quickAdmin.length && !query ? (
            <div className="mb-1">
              <p className="px-3 py-1.5 text-[9px] font-semibold uppercase tracking-[0.15em] text-faint">
                {t("admin.eyebrow")}
              </p>
              <div className="flex flex-wrap gap-1.5 px-2 pb-2">
                {quickAdmin.map((item) => {
                  const Icon = item.icon;
                  return (
                    <button
                      key={item.to}
                      type="button"
                      onClick={() => {
                        navigate(item.to);
                        onOpenChange(false);
                      }}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-line bg-panel2 px-2.5 py-1.5 text-[10px] text-muted transition hover:border-accent/30 hover:text-ink"
                    >
                      <Icon className="h-3 w-3" />
                      {t(item.labelKey)}
                    </button>
                  );
                })}
              </div>
            </div>
          ) : null}

          {debounced.length >= 2 && searchQuery.isFetching ? (
            <div className="flex items-center justify-center py-5 text-xs text-muted">
              <Loader2 className="me-2 h-4 w-4 animate-spin text-accent" />
              {t("common.loading")}
            </div>
          ) : null}

          {debounced.length >= 2 && searchQuery.isError ? (
            <div className="p-5 text-center text-xs text-rose-300">{t("command.searchError")}</div>
          ) : null}

          {resultGroups.map((group) => (
            <div key={group.key} className="mb-1">
              <p className="px-3 py-1.5 text-[9px] font-semibold uppercase tracking-[0.15em] text-faint">
                {group.label}
              </p>
              {group.items.map((item: SearchItem) => {
                currentIndex += 1;
                const index = currentIndex;
                const Icon = typeIcons[item.type] || typeIcons[group.key] || FileSearch;
                return (
                  <button
                    key={`${group.key}-${item.id}`}
                    type="button"
                    data-index={index}
                    onMouseEnter={() => setActive(index)}
                    onClick={() => choose(flatItems[index])}
                    className={cn(
                      "flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-start transition",
                      active === index ? "bg-accent/10" : "hover:bg-panel2"
                    )}
                  >
                    <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-line bg-panel2">
                      <Icon className="h-3.5 w-3.5 text-muted" />
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-xs font-medium text-ink">{item.title}</span>
                      <span className="mt-0.5 block truncate text-[10px] text-muted">
                        {item.subtitle}
                        {item.project_name ? ` · ${item.project_name}` : ""}
                      </span>
                    </span>
                    {active === index ? <CornerDownLeft className="h-3.5 w-3.5 text-accent rtl:flip-x" /> : null}
                  </button>
                );
              })}
            </div>
          ))}

          {!query ? (
            <div className="mt-1 flex items-center gap-2 rounded-xl border border-line/60 bg-panel2/40 px-3 py-2.5">
              <Sparkles className="h-3.5 w-3.5 text-accent2" />
              <p className="text-[10px] leading-relaxed text-faint">{t("command.hint")}</p>
            </div>
          ) : null}
        </div>
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-line/70 bg-panel2/40 px-4 py-2 text-[9px] text-faint">
          <div className="flex items-center gap-3">
            <span className="flex items-center gap-1">
              <kbd className="rounded border border-line bg-panel px-1 py-0.5">↑↓</kbd>
              {t("command.navigate")}
            </span>
            <span className="flex items-center gap-1">
              <kbd className="rounded border border-line bg-panel px-1 py-0.5">↵</kbd>
              {t("command.open")}
            </span>
          </div>
          <span>{t("command.shortcut")}</span>
        </div>
      </div>
    </Modal>
  );
}
