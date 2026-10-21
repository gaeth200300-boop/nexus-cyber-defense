import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import {
  AlertTriangle,
  Boxes,
  Bug,
  Crosshair,
  FileSearch,
  Fingerprint,
  GitBranch,
  Radar,
  RefreshCw,
  ScanLine,
  ShieldAlert,
  Siren,
  UserRound
} from "lucide-react";
import { apiFetch } from "../lib/api";
import { cn, formatDateTime, titleCase } from "../lib/utils";
import { useDocumentTitle } from "../hooks";
import { useRequiredProjectId } from "../context/ProjectContext";
import { DataError, ProjectGate, SectionCard } from "../components/common";
import { Badge, Button, Card, EmptyState, PageHeader, Skeleton, StatCard } from "../components/ui";
import type { GraphEdge, GraphNode, Lang, SecurityGraph } from "../types";

interface Placed extends GraphNode {
  x: number;
  y: number;
}

const KIND_STYLE: Record<string, { color: string; icon: typeof Boxes; label: string }> = {
  project: { color: "#8b5cf6", icon: ShieldAlert, label: "Project" },
  asset: { color: "#22d3ee", icon: Boxes, label: "Asset" },
  service: { color: "#38bdf8", icon: Radar, label: "Service" },
  finding: { color: "#fb7185", icon: Bug, label: "Finding" },
  alert: { color: "#f59e0b", icon: Siren, label: "Detection" },
  incident: { color: "#f43f5e", icon: AlertTriangle, label: "Incident" },
  evidence: { color: "#a78bfa", icon: FileSearch, label: "Evidence" },
  scan: { color: "#34d399", icon: ScanLine, label: "Assessment" },
  log_source: { color: "#94a3b8", icon: Fingerprint, label: "Log source" },
  log_event: { color: "#64748b", icon: Fingerprint, label: "Log event" },
  user: { color: "#fbbf24", icon: UserRound, label: "User" },
  cve: { color: "#f472b6", icon: Fingerprint, label: "CVE" },
  job: { color: "#4ade80", icon: ScanLine, label: "Job" },
  change: { color: "#facc15", icon: GitBranch, label: "Change" }
};

const CONFIDENCE_STYLE: Record<string, string> = {
  certain: "text-emerald-300",
  firm: "text-cyan-300",
  tentative: "text-amber-300"
};

const CONFIDENCE_OPACITY: Record<string, number> = {
  certain: 0.55,
  firm: 0.38,
  tentative: 0.22
};

/**
 * Deterministic force-directed layout.
 *
 * The simulation is seeded by node id so the same graph always renders the same
 * way - a graph that reorders itself on every refresh is unusable for
 * comparing two moments in time.
 */
function layout(nodes: GraphNode[], edges: GraphEdge[], width: number, height: number): Placed[] {
  const index = new Map(nodes.map((node, i) => [node.id, i]));
  const count = nodes.length;
  if (!count) return [];

  const positions = nodes.map((node, i) => {
    const angle = (i / count) * Math.PI * 2;
    const radius = Math.min(width, height) * 0.32 * (0.45 + ((node.degree || 1) % 5) / 5);
    return {
      id: node.id,
      x: width / 2 + Math.cos(angle) * radius,
      y: height / 2 + Math.sin(angle) * radius,
      vx: 0,
      vy: 0
    };
  });

  const links = edges
    .map((edge) => ({
      s: index.get(edge.source),
      t: index.get(edge.target)
    }))
    .filter((link) => link.s !== undefined && link.t !== undefined) as { s: number; t: number }[];

  const iterations = Math.min(220, 90 + count * 2);
  for (let step = 0; step < iterations; step += 1) {
    const cooling = 1 - step / iterations;

    // Repulsion between every pair.
    for (let i = 0; i < count; i += 1) {
      for (let j = i + 1; j < count; j += 1) {
        const a = positions[i];
        const b = positions[j];
        let dx = a.x - b.x;
        let dy = a.y - b.y;
        let dist = Math.hypot(dx, dy);
        if (dist < 0.01) {
          dx = (i - j) * 0.1 + 0.05;
          dy = 0.05;
          dist = 0.1;
        }
        const force = (2600 * cooling) / (dist * dist);
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        a.vx += fx;
        a.vy += fy;
        b.vx -= fx;
        b.vy -= fy;
      }
    }

    // Attraction along edges.
    for (const link of links) {
      const a = positions[link.s];
      const b = positions[link.t];
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const dist = Math.max(1, Math.hypot(dx, dy));
      const force = (dist - 130) * 0.012 * cooling;
      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;
      a.vx += fx;
      a.vy += fy;
      b.vx -= fx;
      b.vy -= fy;
    }

    // Gravity toward the centre keeps disconnected nodes on screen.
    for (const point of positions) {
      point.vx += (width / 2 - point.x) * 0.012 * cooling;
      point.vy += (height / 2 - point.y) * 0.012 * cooling;
      point.x += Math.max(-18, Math.min(18, point.vx));
      point.y += Math.max(-18, Math.min(18, point.vy));
      point.vx *= 0.72;
      point.vy *= 0.72;
    }
  }

  return nodes.map((node, i) => ({
    ...node,
    x: Math.max(24, Math.min(width - 24, positions[i].x)),
    y: Math.max(24, Math.min(height - 24, positions[i].y))
  }));
}

export default function GraphPage() {
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const projectId = useRequiredProjectId();
  const [selected, setSelected] = useState<string | null>(null);
  const [kindFilter, setKindFilter] = useState<string>("all");
  useDocumentTitle(t("graph.title"));

  const query = useQuery({
    queryKey: ["security-graph", projectId],
    queryFn: () => apiFetch<SecurityGraph>(`/projects/${projectId}/graph`),
    enabled: Boolean(projectId)
  });

  const width = 860;
  const height = 520;

  const placed = useMemo(() => {
    const graph = query.data;
    if (!graph) return [] as Placed[];
    const nodes =
      kindFilter === "all" ? graph.nodes : graph.nodes.filter((node) => node.kind === kindFilter);
    const visible = new Set(nodes.map((node) => node.id));
    const edges = graph.edges.filter((edge) => visible.has(edge.source) && visible.has(edge.target));
    return layout(nodes, edges, width, height);
  }, [query.data, kindFilter]);

  const positions = useMemo(() => new Map(placed.map((node) => [node.id, node])), [placed]);

  const neighbours = useMemo(() => {
    if (!selected || !query.data) return new Set<string>();
    const set = new Set<string>([selected]);
    for (const edge of query.data.edges) {
      if (edge.source === selected) set.add(edge.target);
      if (edge.target === selected) set.add(edge.source);
    }
    return set;
  }, [selected, query.data]);

  const selectedNode = useMemo(
    () => placed.find((node) => node.id === selected) || null,
    [placed, selected]
  );

  const selectedEdges = useMemo(() => {
    if (!selected || !query.data) return [] as GraphEdge[];
    return query.data.edges.filter((edge) => edge.source === selected || edge.target === selected);
  }, [selected, query.data]);

  const kinds = useMemo(() => {
    const counts = query.data?.stats.by_kind || {};
    return Object.entries(counts).sort((a, b) => b[1] - a[1]);
  }, [query.data]);

  return (
    <ProjectGate>
      <div className="space-y-5">
        <PageHeader
          eyebrow={t("graph.eyebrow")}
          icon={GitBranch}
          title={t("graph.title")}
          subtitle={t("graph.subtitle")}
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
            <Skeleton className="h-[520px] rounded-2xl" />
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
                label={t("graph.nodes")}
                value={query.data?.stats.nodes ?? 0}
                sub={t("graph.nodesSub")}
                icon={GitBranch}
                tone="accent"
              />
              <StatCard
                label={t("graph.edges")}
                value={query.data?.stats.edges ?? 0}
                sub={t("graph.edgesSub")}
                icon={Crosshair}
                tone="cyan"
              />
              <StatCard
                label={t("graph.assets")}
                value={query.data?.stats.assets ?? 0}
                sub={t("graph.assetsSub")}
                icon={Boxes}
                tone="success"
              />
              <StatCard
                label={t("graph.paths")}
                value={query.data?.attack_paths?.length ?? 0}
                sub={t("graph.pathsSub")}
                icon={AlertTriangle}
                tone="warning"
              />
            </section>

            <section className="grid gap-4 xl:grid-cols-12">
              <SectionCard
                className="xl:col-span-8"
                title={t("graph.canvasTitle")}
                subtitle={t("graph.canvasSubtitle")}
                icon={GitBranch}
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
                    {kinds.slice(0, 7).map(([kind, count]) => {
                      const style = KIND_STYLE[kind] || KIND_STYLE.log_event;
                      return (
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
                          <span className="h-1.5 w-1.5 rounded-full" style={{ background: style.color }} />
                          {style.label}
                          <span className="font-mono tabular-nums opacity-70">{count}</span>
                        </button>
                      );
                    })}
                  </div>
                }
                bodyClassName="p-2"
              >
                {placed.length ? (
                  <svg
                    viewBox={`0 0 ${width} ${height}`}
                    className="h-[520px] w-full touch-none select-none"
                    role="img"
                    aria-label={t("graph.canvasTitle")}
                  >
                    <defs>
                      <radialGradient id="graph-vignette" cx="50%" cy="45%" r="70%">
                        <stop offset="0%" stopColor="rgba(139,92,246,0.10)" />
                        <stop offset="100%" stopColor="rgba(2,6,23,0)" />
                      </radialGradient>
                    </defs>
                    <rect width={width} height={height} fill="url(#graph-vignette)" />

                    {query.data?.edges.map((edge) => {
                      const from = positions.get(edge.source);
                      const to = positions.get(edge.target);
                      if (!from || !to) return null;
                      const active =
                        selected !== null &&
                        (edge.source === selected || edge.target === selected);
                      const dim = selected !== null && !active;
                      return (
                        <line
                          key={edge.id}
                          x1={from.x}
                          y1={from.y}
                          x2={to.x}
                          y2={to.y}
                          stroke={active ? "#8b5cf6" : "#64748b"}
                          strokeWidth={active ? 1.6 : 0.8}
                          strokeOpacity={
                            dim ? 0.05 : active ? 0.85 : CONFIDENCE_OPACITY[edge.confidence] ?? 0.3
                          }
                        />
                      );
                    })}

                    {placed.map((node) => {
                      const style = KIND_STYLE[node.kind] || KIND_STYLE.log_event;
                      const dim = selected !== null && !neighbours.has(node.id);
                      const active = selected === node.id;
                      const radius = Math.min(17, 6 + Math.sqrt(node.degree || 1) * 2.4);
                      return (
                        <g
                          key={node.id}
                          transform={`translate(${node.x} ${node.y})`}
                          opacity={dim ? 0.22 : 1}
                          className="cursor-pointer"
                          onClick={() => setSelected(active ? null : node.id)}
                        >
                          {active ? (
                            <circle r={radius + 8} fill={style.color} opacity={0.14} />
                          ) : null}
                          <circle
                            r={radius}
                            fill="rgba(10,15,30,0.92)"
                            stroke={style.color}
                            strokeWidth={active ? 2.2 : 1.2}
                          />
                          <circle r={Math.max(2, radius * 0.28)} fill={style.color} />
                          <text
                            y={radius + 13}
                            textAnchor="middle"
                            className="fill-slate-300"
                            style={{ fontSize: 9.5 }}
                          >
                            {node.label.length > 26 ? `${node.label.slice(0, 25)}…` : node.label}
                          </text>
                        </g>
                      );
                    })}
                  </svg>
                ) : (
                  <EmptyState
                    icon={GitBranch}
                    title={t("graph.empty")}
                    description={t("graph.emptyBody")}
                  />
                )}
              </SectionCard>

              <div className="space-y-4 xl:col-span-4">
                <SectionCard
                  title={selectedNode ? t("graph.selected") : t("graph.legend")}
                  subtitle={selectedNode ? selectedNode.kind : t("graph.legendSubtitle")}
                  icon={Crosshair}
                >
                  {selectedNode ? (
                    <div className="space-y-3 p-4">
                      <div>
                        <p className="text-xs font-semibold text-ink">{selectedNode.label}</p>
                        {selectedNode.sublabel ? (
                          <p className="mt-0.5 font-mono text-[10px] text-faint">{selectedNode.sublabel}</p>
                        ) : null}
                      </div>
                      <dl className="space-y-1.5">
                        {Object.entries(selectedNode.meta)
                          .filter(([, value]) => value !== null && value !== "" && value !== undefined)
                          .slice(0, 8)
                          .map(([key, value]) => (
                            <div key={key} className="flex items-start justify-between gap-3 text-[10px]">
                              <dt className="shrink-0 text-faint">{titleCase(key)}</dt>
                              <dd className="min-w-0 break-words text-end text-muted">
                                {typeof value === "object" ? JSON.stringify(value) : String(value)}
                              </dd>
                            </div>
                          ))}
                        {selectedNode.observed_at ? (
                          <div className="flex items-start justify-between gap-3 text-[10px]">
                            <dt className="shrink-0 text-faint">{t("common.lastSeen")}</dt>
                            <dd className="text-end text-muted">{formatDateTime(selectedNode.observed_at, lang)}</dd>
                          </div>
                        ) : null}
                      </dl>

                      <div className="rounded-xl border border-line/60 bg-panel2/40 p-3">
                        <p className="text-[9px] uppercase tracking-[0.1em] text-faint">
                          {t("graph.relationships")}
                        </p>
                        <ul className="mt-2 space-y-1.5">
                          {selectedEdges.slice(0, 8).map((edge) => (
                            <li key={edge.id} className="text-[10px] leading-relaxed text-muted">
                              <span className="text-ink">{edge.label}</span>
                              <span className={cn("ms-1.5 font-mono text-[9px]", CONFIDENCE_STYLE[edge.confidence])}>
                                {edge.confidence}
                              </span>
                              <span className="block truncate font-mono text-[9px] text-faint">{edge.origin}</span>
                            </li>
                          ))}
                          {!selectedEdges.length ? (
                            <li className="text-[10px] text-faint">{t("graph.noRelations")}</li>
                          ) : null}
                        </ul>
                      </div>

                      <Button size="sm" variant="secondary" onClick={() => setSelected(null)}>
                        {t("graph.clearSelection")}
                      </Button>
                    </div>
                  ) : (
                    <div className="space-y-2 p-4">
                      {Object.entries(KIND_STYLE).map(([kind, style]) => {
                        const count = query.data?.stats.by_kind[kind] || 0;
                        if (!count) return null;
                        return (
                          <div key={kind} className="flex items-center justify-between gap-2 text-[10px]">
                            <span className="flex items-center gap-2 text-muted">
                              <span className="h-2 w-2 rounded-full" style={{ background: style.color }} />
                              {style.label}
                            </span>
                            <span className="font-mono tabular-nums text-ink">{count}</span>
                          </div>
                        );
                      })}
                      <p className="pt-2 text-[10px] leading-relaxed text-faint">{query.data?.note}</p>
                    </div>
                  )}
                </SectionCard>

                <SectionCard
                  title={t("graph.pathsTitle")}
                  subtitle={t("graph.pathsSubtitle")}
                  icon={AlertTriangle}
                  bodyClassName="divide-y divide-line/50"
                >
                  {query.data?.attack_paths?.length ? (
                    query.data.attack_paths.slice(0, 6).map((path) => (
                      <div key={path.entry + path.length} className="px-4 py-3">
                        <div className="flex items-center justify-between gap-2">
                          <span className="truncate text-[11px] font-medium text-ink">{path.entry}</span>
                          <Badge tone={path.weakest_link === "certain" ? "success" : "warning"}>
                            {path.length} {t("graph.hops")}
                          </Badge>
                        </div>
                        <ol className="mt-2 space-y-1">
                          {path.steps.map((step, index) => (
                            <li key={`${step.kind}-${index}`} className="flex items-center gap-1.5 text-[10px]">
                              <span className="h-1 w-1 shrink-0 rounded-full bg-accent/60" />
                              <span className="truncate text-muted">{step.to}</span>
                              <span className="font-mono text-[9px] text-faint">{step.kind}</span>
                            </li>
                          ))}
                        </ol>
                      </div>
                    ))
                  ) : (
                    <EmptyState
                      icon={Crosshair}
                      title={t("graph.noPaths")}
                      description={t("graph.noPathsBody")}
                    />
                  )}
                </SectionCard>
              </div>
            </section>
          </>
        )}
      </div>
    </ProjectGate>
  );
}
