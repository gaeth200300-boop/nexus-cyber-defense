import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { BookOpen, Fingerprint, GitBranch, RefreshCw, ShieldCheck, Waypoints } from "lucide-react";
import { apiFetch } from "../lib/api";
import { cn, formatDateTime } from "../lib/utils";
import { useDocumentTitle } from "../hooks";
import { DataError, ProjectGate, SectionCard } from "../components/common";
import { Badge, Button, Card, EmptyState, PageHeader, Skeleton, StatCard } from "../components/ui";
import type { KnowledgeGraph, Lang } from "../types";

const KIND_COLOR: Record<string, string> = {
  cve: "#f472b6",
  cwe: "#a78bfa",
  kev: "#f43f5e",
  detection: "#22d3ee",
  technique: "#fbbf24",
  lesson: "#34d399"
};

export default function KnowledgePage() {
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const [kindFilter, setKindFilter] = useState<string>("all");
  useDocumentTitle(t("knowledge.title"));

  const query = useQuery({
    queryKey: ["knowledge-graph"],
    queryFn: () => apiFetch<KnowledgeGraph>("/knowledge")
  });

  const kinds = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const node of query.data?.nodes || []) {
      counts[node.kind] = (counts[node.kind] || 0) + 1;
    }
    return Object.entries(counts).sort((a, b) => b[1] - a[1]);
  }, [query.data]);

  const filtered = useMemo(() => {
    const graph = query.data;
    if (!graph) return { nodes: [], edges: [] };
    if (kindFilter === "all") return { nodes: graph.nodes, edges: graph.edges };
    const visible = new Set(graph.nodes.filter((node) => node.kind === kindFilter).map((node) => node.id));
    return {
      nodes: graph.nodes.filter((node) => visible.has(node.id)),
      edges: graph.edges.filter((edge) => visible.has(edge.source) && visible.has(edge.target))
    };
  }, [query.data, kindFilter]);

  return (
    <ProjectGate>
      <div className="space-y-5">
        <PageHeader
          eyebrow={t("knowledge.eyebrow")}
          icon={Waypoints}
          title={t("knowledge.title")}
          subtitle={t("knowledge.subtitle")}
          actions={
            <Button
              variant="secondary"
              size="sm"
              icon={RefreshCw}
              onClick={() => void query.refetch()}
              disabled={query.isFetching}
            >
              {t("common.refresh")}
            </Button>
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
                label={t("knowledge.cves")}
                value={query.data?.stats.cves ?? 0}
                sub={t("knowledge.cvesSub")}
                icon={Fingerprint}
                tone="accent"
              />
              <StatCard
                label={t("knowledge.kev")}
                value={query.data?.stats.kev ?? 0}
                sub={t("knowledge.kevSub")}
                icon={ShieldCheck}
                tone="danger"
              />
              <StatCard
                label={t("knowledge.detections")}
                value={query.data?.stats.detections ?? 0}
                sub={t("knowledge.detectionsSub")}
                icon={GitBranch}
                tone="cyan"
              />
              <StatCard
                label={t("knowledge.lessons")}
                value={query.data?.stats.lessons ?? 0}
                sub={t("knowledge.lessonsSub")}
                icon={BookOpen}
                tone="success"
              />
            </section>

            <section className="grid gap-4 xl:grid-cols-12">
              <SectionCard
                className="xl:col-span-7"
                title={t("knowledge.map")}
                subtitle={t("knowledge.mapSubtitle")}
                icon={Waypoints}
                actions={
                  <div className="flex flex-wrap items-center gap-1.5">
                    <button
                      type="button"
                      onClick={() => setKindFilter("all")}
                      className={cn(
                        "rounded-lg border px-2 py-1 text-[10px] transition",
                        kindFilter === "all"
                          ? "border-accent/30 bg-accent/10 text-accent"
                          : "border-line bg-panel2 text-muted hover:text-ink"
                      )}
                    >
                      {t("common.all")}
                    </button>
                    {kinds.map(([kind, count]) => (
                      <button
                        key={kind}
                        type="button"
                        onClick={() => setKindFilter(kind === kindFilter ? "all" : kind)}
                        className={cn(
                          "inline-flex items-center gap-1.5 rounded-lg border px-2 py-1 text-[10px] transition",
                          kindFilter === kind
                            ? "border-accent/30 bg-accent/10 text-accent"
                            : "border-line bg-panel2 text-muted hover:text-ink"
                        )}
                      >
                        <span
                          className="h-1.5 w-1.5 rounded-full"
                          style={{ background: KIND_COLOR[kind] || "#64748b" }}
                        />
                        {kind}
                        <span className="font-mono tabular-nums opacity-70">{count}</span>
                      </button>
                    ))}
                  </div>
                }
                bodyClassName="p-2"
              >
                {filtered.nodes.length ? (
                  <ul className="grid max-h-[560px] gap-1.5 overflow-y-auto sm:grid-cols-2">
                    {filtered.nodes.slice(0, 400).map((node) => (
                      <li
                        key={node.id}
                        className="flex items-start gap-2 rounded-lg border border-line/50 bg-panel2/30 px-2.5 py-2"
                      >
                        <span
                          className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full"
                          style={{ background: KIND_COLOR[node.kind] || "#64748b" }}
                        />
                        <div className="min-w-0 flex-1">
                          <p className="truncate text-[10px] font-medium text-ink">{node.label}</p>
                          <p className="mt-0.5 text-[9px] text-faint">
                            {node.kind}
                            {node.updated_at ? ` · ${formatDateTime(node.updated_at, lang)}` : ""}
                          </p>
                        </div>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <EmptyState icon={Waypoints} title={t("knowledge.empty")} description={t("knowledge.emptyBody")} />
                )}
              </SectionCard>

              <div className="space-y-4 xl:col-span-5">
                <SectionCard
                  title={t("knowledge.relations")}
                  subtitle={t("knowledge.relationsSubtitle")}
                  icon={GitBranch}
                  bodyClassName="divide-y divide-line/40"
                >
                  {filtered.edges.slice(0, 80).map((edge) => (
                    <div key={edge.id} className="px-4 py-2.5">
                      <div className="flex items-center justify-between gap-2">
                        <span className="truncate text-[10px] text-ink">{edge.source.split(":")[1]}</span>
                        <Badge tone="default">{edge.kind}</Badge>
                        <span className="truncate text-[10px] text-ink">{edge.target.split(":")[1]}</span>
                      </div>
                      <p className="mt-0.5 truncate font-mono text-[9px] text-faint">{edge.origin}</p>
                    </div>
                  ))}
                  {!filtered.edges.length ? (
                    <EmptyState icon={GitBranch} title={t("knowledge.noRelations")} description={t("knowledge.noRelationsBody")} />
                  ) : null}
                </SectionCard>

                <SectionCard
                  title={t("knowledge.sources")}
                  subtitle={t("knowledge.sourcesSubtitle")}
                  icon={Fingerprint}
                  bodyClassName="divide-y divide-line/40"
                >
                  {(query.data?.sources || []).map((source) => (
                    <div key={source.name} className="flex items-center justify-between gap-3 px-4 py-3">
                      <div className="min-w-0">
                        <p className="text-[11px] text-ink">{source.name}</p>
                        <p className="mt-0.5 text-[9px] text-faint">{source.kind}</p>
                      </div>
                      <span className="shrink-0 font-mono text-[9px] text-muted">
                        {source.updated_at ? formatDateTime(source.updated_at, lang) : "—"}
                      </span>
                    </div>
                  ))}
                  <p className="px-4 py-3 text-[10px] leading-relaxed text-faint">{query.data?.note}</p>
                </SectionCard>
              </div>
            </section>
          </>
        )}
      </div>
    </ProjectGate>
  );
}
