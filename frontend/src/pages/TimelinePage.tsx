import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import {
  AlertTriangle,
  Clock3,
  Download,
  Filter,
  History,
  Layers3,
  RefreshCw,
  Search,
  Zap
} from "lucide-react";
import { apiFetch } from "../lib/api";
import { cn, formatDateTime, severityDot, titleCase } from "../lib/utils";
import { useDocumentTitle } from "../hooks";
import { useRequiredProjectId } from "../context/ProjectContext";
import { DataError, ProjectGate, SectionCard } from "../components/common";
import { Badge, Button, Card, EmptyState, Input, PageHeader, Skeleton, StatCard } from "../components/ui";
import type { Lang, TimelineResponse } from "../types";

const SEVERITIES = ["critical", "high", "medium", "low", "info"];

export default function TimelinePage() {
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const projectId = useRequiredProjectId();
  const [search, setSearch] = useState("");
  const [activeSources, setActiveSources] = useState<string[]>([]);
  const [activeSeverities, setActiveSeverities] = useState<string[]>([]);
  const [granularity, setGranularity] = useState<"hour" | "day">("hour");
  useDocumentTitle(t("timeline.title"));

  const query = useQuery({
    queryKey: ["timeline", projectId, activeSources, activeSeverities, granularity],
    queryFn: () =>
      apiFetch<TimelineResponse>(`/projects/${projectId}/timeline/events`, {
        query: {
          sources: activeSources.join(",") || undefined,
          severities: activeSeverities.join(",") || undefined,
          granularity
        }
      }),
    enabled: Boolean(projectId)
  });

  const events = query.data?.events || [];

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    if (!needle) return events;
    return events.filter((event) =>
      `${event.title} ${event.description} ${event.reference}`.toLowerCase().includes(needle)
    );
  }, [events, search]);

  const toggle = (value: string, list: string[], setter: (next: string[]) => void) => {
    setter(list.includes(value) ? list.filter((item) => item !== value) : [...list, value]);
  };

  const exportCsv = () => {
    const header = ["timestamp", "source", "kind", "severity", "title", "reference"];
    const rows = filtered.map((event) => [
      event.ts || "",
      event.source,
      event.kind,
      event.severity,
      event.title.replace(/"/g, '""'),
      event.reference
    ]);
    const csv = [header, ...rows].map((row) => row.map((cell) => `"${cell}"`).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `nexus-timeline-${projectId.slice(0, 8)}.csv`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  };

  return (
    <ProjectGate>
      <div className="space-y-5">
        <PageHeader
          eyebrow={t("timeline.eyebrow")}
          icon={History}
          title={t("timeline.title")}
          subtitle={t("timeline.subtitle")}
          actions={
            <>
              <div className="inline-flex items-center rounded-xl border border-line bg-panel2 p-0.5">
                {(["hour", "day"] as const).map((value) => (
                  <button
                    key={value}
                    type="button"
                    onClick={() => setGranularity(value)}
                    className={cn(
                      "rounded-lg px-2.5 py-1.5 text-[10px] font-medium transition",
                      granularity === value ? "bg-panel3 text-ink" : "text-muted hover:text-ink"
                    )}
                  >
                    {t(`timeline.${value}`)}
                  </button>
                ))}
              </div>
              <Button
                variant="secondary"
                size="sm"
                icon={Download}
                onClick={exportCsv}
                disabled={!filtered.length}
              >
                {t("timeline.export")}
              </Button>
              <Button
                variant="secondary"
                size="sm"
                icon={RefreshCw}
                onClick={() => void query.refetch()}
                disabled={query.isFetching}
              >
                {t("common.refresh")}
              </Button>
            </>
          }
        />

        {query.isLoading ? (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
              {[0, 1, 2, 3].map((key) => (
                <Skeleton key={key} className="h-24 rounded-2xl" />
              ))}
            </div>
            <Skeleton className="h-96 rounded-2xl" />
          </div>
        ) : query.isError ? (
          <Card>
            <DataError
              message={query.error instanceof Error ? query.error.message : undefined}
              onRetry={() => void query.refetch()}
            />
          </Card>
        ) : (
          <>
            <section className="grid grid-cols-2 gap-3 lg:grid-cols-4">
              <StatCard
                label={t("timeline.events")}
                value={query.data?.stats.total ?? 0}
                sub={t("timeline.eventsSub")}
                icon={Clock3}
                tone="accent"
              />
              <StatCard
                label={t("timeline.anomalies")}
                value={query.data?.stats.anomalies ?? 0}
                sub={t("timeline.anomaliesSub")}
                icon={Zap}
                tone="warning"
              />
              <StatCard
                label={t("timeline.sources")}
                value={Object.keys(query.data?.stats.by_source || {}).length}
                sub={t("timeline.sourcesSub")}
                icon={Layers3}
                tone="cyan"
              />
              <StatCard
                label={t("timeline.window")}
                value={query.data?.stats.window_start ? formatDateTime(query.data.stats.window_start, lang) : "—"}
                sub={query.data?.stats.window_end ? formatDateTime(query.data.stats.window_end, lang) : "—"}
                icon={History}
                tone="muted"
              />
            </section>

            <section className="grid gap-4 xl:grid-cols-12">
              <SectionCard
                className="xl:col-span-4"
                title={t("timeline.filters")}
                subtitle={t("timeline.filtersSubtitle")}
                icon={Filter}
                bodyClassName="space-y-4 p-4"
              >
                <div className="space-y-1.5">
                  <label className="text-[9px] uppercase tracking-[0.1em] text-faint" htmlFor="timeline-search">
                    {t("common.search")}
                  </label>
                  <div className="relative">
                    <Search className="pointer-events-none absolute start-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-faint" />
                    <Input
                      id="timeline-search"
                      value={search}
                      onChange={(event) => setSearch(event.target.value)}
                      placeholder={t("timeline.searchPlaceholder")}
                      className="ps-9"
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  <p className="text-[9px] uppercase tracking-[0.1em] text-faint">{t("timeline.bySeverity")}</p>
                  <div className="flex flex-wrap gap-1.5">
                    {SEVERITIES.map((severity) => (
                      <button
                        key={severity}
                        type="button"
                        onClick={() => toggle(severity, activeSeverities, setActiveSeverities)}
                        className={cn(
                          "inline-flex items-center gap-1.5 rounded-lg border px-2 py-1 text-[10px] transition",
                          activeSeverities.includes(severity)
                            ? "border-accent/30 bg-accent/10 text-accent"
                            : "border-line bg-panel2 text-muted hover:text-ink"
                        )}
                      >
                        <span className={cn("h-1.5 w-1.5 rounded-full", severityDot[severity])} />
                        {t(`severity.${severity}`)}
                        <span className="font-mono tabular-nums opacity-70">
                          {query.data?.stats.by_severity[severity] || 0}
                        </span>
                      </button>
                    ))}
                  </div>
                </div>

                <div className="space-y-2">
                  <p className="text-[9px] uppercase tracking-[0.1em] text-faint">{t("timeline.bySource")}</p>
                  <div className="space-y-1">
                    {(query.data?.sources || []).map((source) => {
                      const count = query.data?.stats.by_source[source.key] || 0;
                      const active = activeSources.includes(source.key);
                      return (
                        <button
                          key={source.key}
                          type="button"
                          onClick={() => toggle(source.key, activeSources, setActiveSources)}
                          className={cn(
                            "flex w-full items-center justify-between rounded-lg border px-2.5 py-1.5 text-[10px] transition",
                            active
                              ? "border-accent/30 bg-accent/10 text-accent"
                              : "border-line bg-panel2 text-muted hover:text-ink"
                          )}
                        >
                          <span>{source.label}</span>
                          <span className="font-mono tabular-nums opacity-70">{count}</span>
                        </button>
                      );
                    })}
                  </div>
                </div>

                <p className="text-[10px] leading-relaxed text-faint">{query.data?.note}</p>
              </SectionCard>

              <SectionCard
                className="xl:col-span-8"
                title={t("timeline.streamTitle")}
                subtitle={t("timeline.streamSubtitle")}
                icon={History}
                bodyClassName="max-h-[720px] overflow-y-auto"
              >
                {filtered.length ? (
                  <ol className="divide-y divide-line/40">
                    {filtered.map((event, index) => (
                      <li
                        key={`${event.source}-${event.ts}-${index}`}
                        className={cn(
                          "flex gap-3 px-4 py-3 transition hover:bg-panel2/40",
                          event.anomaly && "bg-rose-400/[0.03]"
                        )}
                      >
                        <div className="flex w-24 shrink-0 flex-col items-end gap-1 pt-0.5">
                          <span className="font-mono text-[10px] tabular-nums text-muted">
                            {event.ts ? formatDateTime(event.ts, lang) : "—"}
                          </span>
                          <span className="rounded-md border border-line bg-panel2 px-1.5 py-0.5 text-[9px] text-faint">
                            {event.source_label}
                          </span>
                        </div>
                        <div className="relative flex min-w-0 flex-1 gap-3">
                          <span className="relative flex w-3 shrink-0 justify-center">
                            <span
                              className={cn(
                                "mt-1.5 h-2 w-2 shrink-0 rounded-full ring-4 ring-panel",
                                severityDot[event.severity]
                              )}
                            />
                            {index < filtered.length - 1 ? (
                              <span className="absolute top-4 h-full w-px bg-line/70" />
                            ) : null}
                          </span>
                          <div className="min-w-0 flex-1">
                            <div className="flex flex-wrap items-center gap-1.5">
                              <p className="truncate text-[11px] font-medium text-ink">{event.title}</p>
                              {event.anomaly ? (
                                <Badge tone="danger">
                                  <AlertTriangle className="h-2.5 w-2.5" />
                                  {t("timeline.anomaly")}
                                </Badge>
                              ) : null}
                            </div>
                            {event.description ? (
                              <p className="mt-0.5 line-clamp-2 text-[10px] leading-relaxed text-muted">
                                {event.description}
                              </p>
                            ) : null}
                            {event.reference ? (
                              <p className="mt-1 truncate font-mono text-[9px] text-faint">{event.reference}</p>
                            ) : null}
                          </div>
                          <span className="hidden shrink-0 text-[9px] uppercase tracking-wider text-faint sm:block">
                            {titleCase(event.kind)}
                          </span>
                        </div>
                      </li>
                    ))}
                  </ol>
                ) : (
                  <EmptyState
                    icon={History}
                    title={t("timeline.empty")}
                    description={t("timeline.emptyBody")}
                  />
                )}
              </SectionCard>
            </section>
          </>
        )}
      </div>
    </ProjectGate>
  );
}
