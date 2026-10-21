import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  Boxes,
  CheckCircle2,
  ChevronRight,
  Clock3,
  Eye,
  Globe2,
  Layers3,
  Network,
  Play,
  Radar,
  RefreshCw,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  Siren
} from "lucide-react";
import { apiFetch, errorMessage } from "../lib/api";
import { cn, formatDateTime, fromNow } from "../lib/utils";
import { useProject } from "../context/ProjectContext";
import { useToast } from "../context/ToastContext";
import { labelOf, useDebouncedValue, useDocumentTitle, useMeta } from "../hooks";
import type { AssetChange, Lang, Paged } from "../types";
import { BarChart, DonutChart } from "../components/charts";
import { ProjectGate } from "../components/common";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  InlineAlert,
  Input,
  PageHeader,
  Pagination,
  Select,
  SeverityBadge,
  Skeleton,
  StatusBadge,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger
} from "../components/ui";

interface AsmOverview {
  assets: {
    total: number;
    by_type: Record<string, number>;
    by_risk: Record<string, number>;
    by_state: Record<string, number>;
    monitored: number;
    new_last_7d: number;
    with_open_findings: number;
  };
  services: {
    open: number;
    top_ports: { port: number; protocol: string; count: number }[];
    by_name: { name: string; count: number }[];
  };
  changes: { last_30d: number; by_kind: Record<string, number>; unacknowledged: number };
  coverage: { last_discovery_at: string | null; stale: boolean };
  policy: { global_private_targets: boolean; project_private_targets: boolean };
}

interface ExposureItem {
  service_id: string;
  asset: { id: string; value: string; type: string };
  port: number;
  protocol: string;
  name: string;
  product: string;
  version: string;
  tls: Record<string, unknown>;
  worst_severity: string;
  open_findings: number;
  last_seen_at: string;
}

interface MonitorItem {
  id: string;
  type: string;
  value: string;
  risk_severity: string;
  last_seen_at: string;
  last_scanned_at: string | null;
  discovered_by_scan_id: string | null;
}

interface RescanResponse {
  scans: { scan_id: string; kind: string; targets: number }[];
  skipped: { asset_id: string; value: string; reason: string; detail: string }[];
  note: string;
}

const colors = {
  critical: "#f43f5e",
  high: "#fb923c",
  medium: "#f59e0b",
  low: "#38bdf8",
  info: "#64748b"
};

export default function ASMPage() {
  return (
    <ProjectGate>
      <ASMContent />
    </ProjectGate>
  );
}

function ASMContent() {
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const { selectedProject, canWrite } = useProject();
  const meta = useMeta();
  const navigate = useNavigate();
  const toast = useToast();
  const queryClient = useQueryClient();
  const projectId = selectedProject?.id || "";
  const [tab, setTab] = useState("overview");
  const [q, setQ] = useState("");
  const debouncedQ = useDebouncedValue(q, 300);
  const [minSeverity, setMinSeverity] = useState("");
  const [limit, setLimit] = useState(25);
  const [offset, setOffset] = useState(0);
  const [changeFilter, setChangeFilter] = useState<"unacknowledged" | "all">("unacknowledged");
  const [monitorOffset, setMonitorOffset] = useState(0);
  useDocumentTitle(t("asm.title"));

  useEffect(() => setOffset(0), [debouncedQ, minSeverity]);

  const overview = useQuery({
    queryKey: ["asm-overview", projectId],
    queryFn: () => apiFetch<AsmOverview>(`/projects/${projectId}/asm/overview`),
    enabled: Boolean(projectId)
  });

  const exposure = useQuery({
    queryKey: ["asm-exposure", projectId, debouncedQ, minSeverity, limit, offset],
    queryFn: () =>
      apiFetch<Paged<ExposureItem>>(`/projects/${projectId}/asm/exposure`, {
        query: { q: debouncedQ, min_severity: minSeverity || undefined, limit, offset }
      }),
    enabled: Boolean(projectId) && tab === "inventory"
  });

  const changesQuery = useQuery({
    queryKey: ["asm-changes", projectId, changeFilter, limit, offset],
    queryFn: () =>
      apiFetch<Paged<AssetChange>>(`/projects/${projectId}/changes`, {
        query: { acknowledged: changeFilter === "unacknowledged" ? false : undefined, limit, offset }
      }),
    enabled: Boolean(projectId)
  });

  const monitors = useQuery({
    queryKey: ["asm-monitors", projectId, monitorOffset],
    queryFn: () => apiFetch<Paged<MonitorItem> & { note: string }>(`/projects/${projectId}/asm/monitors`, { query: { limit: 25, offset: monitorOffset } }),
    enabled: Boolean(projectId) && tab === "monitors"
  });

  const rescan = useMutation({
    mutationFn: (assetIds: string[] = []) =>
      apiFetch<RescanResponse>(`/projects/${projectId}/asm/rescan`, {
        method: "POST",
        body: { asset_ids: assetIds, ports: [] }
      }),
    onSuccess: async (result) => {
      if (result.skipped.length) {
        toast.toast({
          title: t("asm.rescan"),
          description: `${result.skipped.length} ${t("common.skipped")}`,
          variant: "warning"
        });
      } else {
        toast.toast({ title: t("asm.rescan"), description: result.note, variant: "success" });
      }
      await queryClient.invalidateQueries({ queryKey: ["asm-overview", projectId] });
      await queryClient.invalidateQueries({ queryKey: ["asm-monitors", projectId] });
      await queryClient.invalidateQueries({ queryKey: ["scans", projectId] });
      if (result.scans.length === 1) navigate(`/scans/${result.scans[0].scan_id}`);
    },
    onError: (error) => toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" })
  });

  const acknowledge = useMutation({
    mutationFn: (changeId: string) => apiFetch(`/projects/${projectId}/changes/${changeId}/ack`, { method: "POST" }),
    onSuccess: async () => {
      toast.toast({ title: t("asm.acknowledged"), variant: "success" });
      await queryClient.invalidateQueries({ queryKey: ["asm-changes", projectId] });
      await queryClient.invalidateQueries({ queryKey: ["asm-overview", projectId] });
    },
    onError: (error) => toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" })
  });

  const acknowledgeAll = useMutation({
    mutationFn: () => apiFetch<{ acknowledged: number }>(`/projects/${projectId}/changes/ack-all`, { method: "POST" }),
    onSuccess: async (result) => {
      toast.toast({ title: t("asm.allAcknowledged"), description: String(result.acknowledged), variant: "success" });
      await queryClient.invalidateQueries({ queryKey: ["asm-changes", projectId] });
      await queryClient.invalidateQueries({ queryKey: ["asm-overview", projectId] });
    },
    onError: (error) => toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" })
  });

  const data = overview.data;
  const serviceRows = exposure.data?.items || [];
  const serviceTotal = exposure.data?.total || 0;
  const changeRows = changesQuery.data?.items || [];
  const changeTotal = changesQuery.data?.total || 0;
  const monitorRows = monitors.data?.items || [];

  const riskData = useMemo(
    () =>
      ["critical", "high", "medium", "low", "info"].map((severity) => ({
        name: t(`severity.${severity}`),
        value: data?.assets.by_risk[severity] || 0,
        color: colors[severity as keyof typeof colors]
      })),
    [data?.assets.by_risk, t]
  );

  const typeData = useMemo(
    () =>
      Object.entries(data?.assets.by_type || {}).map(([type, value], index) => ({
        name: type,
        value,
        color: ["#8b5cf6", "#22d3ee", "#34d399", "#f59e0b", "#f43f5e", "#64748b"][index % 6]
      })),
    [data?.assets.by_type]
  );

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow={t("nav.intelligence")}
        icon={Activity}
        title={t("asm.title")}
        subtitle={t("asm.subtitle")}
        actions={
          <>
            <Button variant="secondary" icon={Boxes} onClick={() => navigate("/assets")}>
              {t("nav.assets")}
            </Button>
            <Button
              icon={RefreshCw}
              loading={rescan.isPending}
              disabled={!canWrite || !data?.assets.monitored}
              onClick={() => rescan.mutate([])}
            >
              {t("asm.rescan")}
            </Button>
          </>
        }
      />

      {data?.coverage.stale ? (
        <InlineAlert tone="warning" title={t("asm.overview")}>
          {t("asm.coverageStale")}
        </InlineAlert>
      ) : null}

      <section className="grid grid-cols-2 gap-2.5 xl:grid-cols-5">
        {[
          { label: t("asm.assets"), value: data?.assets.total, icon: Boxes, tone: "text-accent" },
          { label: t("asm.monitored"), value: data?.assets.monitored, icon: Eye, tone: "text-accent2" },
          { label: t("asm.exposedServices"), value: data?.services.open, icon: Server, tone: "text-amber-300" },
          { label: t("asm.changes"), value: data?.changes.unacknowledged, icon: Activity, tone: "text-rose-300" },
          { label: t("asm.riskAssets"), value: data?.assets.with_open_findings, icon: ShieldAlert, tone: "text-orange-300" }
        ].map((card) => (
          <div key={card.label} className="surface-card p-3.5">
            <div className="flex items-center justify-between">
              <span className="text-[9px] font-semibold uppercase tracking-[0.1em] text-muted">{card.label}</span>
              <card.icon className={cn("h-4 w-4", card.tone)} />
            </div>
            <p className="mt-2 font-display text-2xl font-semibold tabular-nums text-ink">
              {card.value === undefined ? "—" : card.value}
            </p>
          </div>
        ))}
      </section>

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="overview" icon={Radar}>
            {t("asm.tabs.overview")}
          </TabsTrigger>
          <TabsTrigger value="inventory" icon={Layers3} count={data?.services.open}>
            {t("asm.tabs.assets")}
          </TabsTrigger>
          <TabsTrigger value="changes" icon={Activity} count={data?.changes.unacknowledged}>
            {t("asm.tabs.changes")}
          </TabsTrigger>
          <TabsTrigger value="monitors" icon={Eye} count={data?.assets.monitored}>
            {t("asm.tabs.monitors")}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="mt-4 space-y-4">
          {overview.isLoading ? (
            <div className="grid gap-4 lg:grid-cols-3">
              {[0, 1, 2].map((key) => (
                <Skeleton key={key} className="h-64 rounded-2xl" />
              ))}
            </div>
          ) : overview.isError ? (
            <Card className="p-2">
              <EmptyState
                icon={AlertTriangle}
                title={t("common.errorTitle")}
                description={overview.error instanceof Error ? overview.error.message : t("common.errorDescription")}
                action={
                  <Button variant="secondary" onClick={() => void overview.refetch()}>
                    {t("common.retry")}
                  </Button>
                }
              />
            </Card>
          ) : (
            <>
              <div className="grid gap-4 xl:grid-cols-12">
                <Card className="p-4 xl:col-span-4">
                  <h3 className="text-xs font-semibold text-ink">{t("asm.assetTypes")}</h3>
                  <p className="mt-0.5 text-[10px] text-muted">{t("asm.subtitle")}</p>
                  {typeData.length ? (
                    <DonutChart data={typeData} height={240} centerLabel={t("asm.assets")} centerValue={data?.assets.total} />
                  ) : (
                    <p className="py-16 text-center text-[10px] text-faint">{t("asm.noAssets")}</p>
                  )}
                </Card>
                <Card className="p-4 xl:col-span-4">
                  <h3 className="text-xs font-semibold text-ink">{t("asm.riskAssets")}</h3>
                  <p className="mt-0.5 text-[10px] text-muted">{t("asm.riskAssets")}</p>
                  {data?.assets.total ? (
                    <DonutChart data={riskData} height={240} centerLabel={t("asm.assets")} centerValue={data.assets.total} />
                  ) : (
                    <p className="py-16 text-center text-[10px] text-faint">{t("asm.noAssets")}</p>
                  )}
                </Card>
                <Card className="p-4 xl:col-span-4">
                  <h3 className="text-xs font-semibold text-ink">{t("asm.exposureTrend")}</h3>
                  <p className="mt-0.5 text-[10px] text-muted">{t("network.ports")}</p>
                  {data?.services.top_ports.length ? (
                    <BarChart
                      labels={data.services.top_ports.map((item) => `${item.port}/${item.protocol}`)}
                      values={data.services.top_ports.map((item) => item.count)}
                      horizontal
                      height={240}
                    />
                  ) : (
                    <p className="py-16 text-center text-[10px] text-faint">{t("network.noServices")}</p>
                  )}
                </Card>
              </div>

              <div className="grid gap-4 xl:grid-cols-12">
                <Card className="overflow-hidden xl:col-span-7">
                  <div className="flex items-center justify-between border-b border-line/60 px-4 py-3">
                    <div>
                      <h3 className="text-xs font-semibold text-ink">{t("asm.recentChanges")}</h3>
                      <p className="mt-0.5 text-[10px] text-muted">{t("asm.changeTimeline")}</p>
                    </div>
                    <Button size="sm" variant="ghost" onClick={() => setTab("changes")}>
                      {t("dashboard.viewAll")}
                    </Button>
                  </div>
                  {changeRows.length ? (
                    <div className="divide-y divide-line/50">
                      {changeRows.slice(0, 6).map((change) => (
                        <div key={change.id} className="flex items-center gap-2.5 px-4 py-3">
                          <span className={cn("h-2 w-2 shrink-0 rounded-full", {
                            "bg-rose-400": change.severity === "critical",
                            "bg-orange-400": change.severity === "high",
                            "bg-amber-400": change.severity === "medium",
                            "bg-sky-400": change.severity === "low",
                            "bg-slate-400": change.severity === "info"
                          })} />
                          <div className="min-w-0 flex-1">
                            <p className="truncate text-[10px] font-medium text-ink">{change.summary}</p>
                            <p className="mt-0.5 text-[9px] text-faint">{change.kind} · {fromNow(change.detected_at, lang)}</p>
                          </div>
                          {!change.acknowledged_at && canWrite ? (
                            <Button size="sm" variant="ghost" onClick={() => acknowledge.mutate(change.id)}>
                              {t("asm.acknowledge")}
                            </Button>
                          ) : (
                            <CheckCircle2 className="h-3 w-3 text-emerald-300" />
                          )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <EmptyState icon={Activity} title={t("asm.emptyChanges")} />
                  )}
                </Card>
                <Card className="p-4 xl:col-span-5">
                  <h3 className="text-xs font-semibold text-ink">{t("asm.overview")}</h3>
                  <p className="mt-0.5 text-[10px] text-muted">{t("asm.scopeBody")}</p>
                  <div className="mt-3 space-y-2">
                    <div className="flex items-center justify-between rounded-lg border border-line/50 bg-panel2/30 px-3 py-2">
                      <span className="text-[10px] text-muted">{t("asm.lastDiscovery")}</span>
                      <span className="text-[10px] text-ink">{data?.coverage.last_discovery_at ? fromNow(data.coverage.last_discovery_at, lang) : t("common.never")}</span>
                    </div>
                    <div className="flex items-center justify-between rounded-lg border border-line/50 bg-panel2/30 px-3 py-2">
                      <span className="text-[10px] text-muted">{t("asm.newLast7d")}</span>
                      <span className="font-mono text-[11px] text-ink">{data?.assets.new_last_7d || 0}</span>
                    </div>
                    <div className="flex items-center justify-between rounded-lg border border-line/50 bg-panel2/30 px-3 py-2">
                      <span className="text-[10px] text-muted">{t("asm.changes")} · 30d</span>
                      <span className="font-mono text-[11px] text-ink">{data?.changes.last_30d || 0}</span>
                    </div>
                    <div className="flex items-center justify-between rounded-lg border border-line/50 bg-panel2/30 px-3 py-2">
                      <span className="text-[10px] text-muted">{t("projects.allowPrivate")}</span>
                      <Badge tone={data?.policy.project_private_targets ? "warning" : "success"}>
                        {data?.policy.project_private_targets ? t("common.enabled") : t("common.disabled")}
                      </Badge>
                    </div>
                  </div>
                  <div className="mt-3 flex items-center gap-2 text-[9px] text-faint">
                    <ShieldCheck className="h-3 w-3 text-emerald-300" />
                    {t("asm.scopeBody")}
                  </div>
                </Card>
              </div>
            </>
          )}
        </TabsContent>

        <TabsContent value="inventory" className="mt-4">
          <Card className="overflow-hidden">
            <div className="flex flex-wrap items-center gap-2 border-b border-line/60 p-3.5">
              <div className="relative min-w-[200px] flex-1">
                <Search className="pointer-events-none absolute start-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-faint" />
                <Input value={q} onChange={(event) => setQ(event.target.value)} placeholder={t("assets.searchPlaceholder")} className="ps-9" />
              </div>
              <Select
                value={minSeverity}
                onChange={(event) => {
                  setMinSeverity(event.target.value);
                  setOffset(0);
                }}
                className="w-auto"
              >
                <option value="">{t("common.severity")} · {t("common.all")}</option>
                {["critical", "high", "medium", "low", "info"].map((severity) => (
                  <option key={severity} value={severity}>{t(`severity.${severity}`)}</option>
                ))}
              </Select>
              <span className="ms-auto text-[9px] text-faint">{t("projects.total", { count: serviceTotal })}</span>
            </div>
            {exposure.isLoading ? (
              <div className="space-y-2 p-4">
                {[0, 1, 2, 3].map((key) => <Skeleton key={key} className="h-10 rounded-lg" />)}
              </div>
            ) : exposure.isError ? (
              <EmptyState
                icon={AlertTriangle}
                title={t("common.errorTitle")}
                description={exposure.error instanceof Error ? exposure.error.message : t("common.errorDescription")}
              />
            ) : serviceRows.length ? (
              <>
                <div className="divide-y divide-line/50">
                  {serviceRows.map((service) => (
                    <div key={service.service_id} className="flex flex-wrap items-center gap-3 px-4 py-3">
                      <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-line bg-panel2 text-accent2">
                        {service.tls && Object.keys(service.tls).length ? <ShieldCheck className="h-3.5 w-3.5 text-emerald-300" /> : <Network className="h-3.5 w-3.5" />}
                      </span>
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <p className="truncate font-mono text-[10px] text-ink">{service.asset.value}:{service.port}/{service.protocol}</p>
                          <span className="text-[9px] text-faint">{service.asset.type}</span>
                        </div>
                        <p className="mt-0.5 text-[9px] text-faint">
                          {service.name || "—"} {service.product ? `· ${service.product}` : ""} {service.version || ""}
                        </p>
                      </div>
                      <SeverityBadge severity={service.worst_severity} />
                      <span className={cn("w-10 text-end font-mono text-[10px]", service.open_findings ? "text-rose-300" : "text-faint")}>
                        {service.open_findings}
                      </span>
                      <button
                        type="button"
                        onClick={() => navigate(`/assets?asset=${service.asset.id}`)}
                        className="text-faint hover:text-ink"
                        title={t("common.view")}
                      >
                        <ArrowUpRight className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  ))}
                </div>
                <Pagination
                  page={Math.floor(offset / limit) + 1}
                  pageSize={limit}
                  total={serviceTotal}
                  onPageChange={(page) => setOffset((page - 1) * limit)}
                  labels={{ previous: t("common.previous"), next: t("common.next"), page: t("common.page"), of: t("common.of") }}
                />
              </>
            ) : (
              <EmptyState icon={Network} title={t("network.noServices")} description={t("asm.scopeBody")} />
            )}
          </Card>
        </TabsContent>

        <TabsContent value="changes" className="mt-4">
          <Card className="overflow-hidden">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line/60 p-3.5">
              <div>
                <h3 className="text-xs font-semibold text-ink">{t("asm.recentChanges")}</h3>
                <p className="mt-0.5 text-[10px] text-muted">{t("asm.changeTimeline")}</p>
              </div>
              <div className="flex items-center gap-2">
                <Select
                  value={changeFilter}
                  onChange={(event) => {
                    setChangeFilter(event.target.value as typeof changeFilter);
                    setOffset(0);
                  }}
                  className="w-auto"
                >
                  <option value="unacknowledged">{t("asm.acknowledge")}</option>
                  <option value="all">{t("common.all")}</option>
                </Select>
                <Button
                  size="sm"
                  variant="secondary"
                  loading={acknowledgeAll.isPending}
                  disabled={!canWrite || !(data?.changes.unacknowledged || 0)}
                  onClick={() => acknowledgeAll.mutate()}
                >
                  {t("asm.acknowledgeAll")}
                </Button>
              </div>
            </div>
            {changesQuery.isLoading ? (
              <div className="space-y-2 p-4">
                {[0, 1, 2, 3].map((key) => <Skeleton key={key} className="h-10 rounded-lg" />)}
              </div>
            ) : changesQuery.isError ? (
              <EmptyState
                icon={AlertTriangle}
                title={t("common.errorTitle")}
                description={changesQuery.error instanceof Error ? changesQuery.error.message : t("common.errorDescription")}
              />
            ) : changeRows.length ? (
              <>
                <div className="divide-y divide-line/50">
                  {changeRows.map((change) => (
                    <div key={change.id} className="flex flex-wrap items-center gap-3 px-4 py-3.5">
                      <span className={cn("h-2 w-2 shrink-0 rounded-full", {
                        "bg-rose-400": change.severity === "critical",
                        "bg-orange-400": change.severity === "high",
                        "bg-amber-400": change.severity === "medium",
                        "bg-sky-400": change.severity === "low",
                        "bg-slate-400": change.severity === "info"
                      })} />
                      <div className="min-w-0 flex-1">
                        <p className="text-[10px] font-medium text-ink">{change.summary}</p>
                        <p className="mt-0.5 text-[9px] text-faint">
                          {change.kind} · {fromNow(change.detected_at, lang)}
                          {change.acknowledged_at ? ` · ${t("asm.acknowledged")}` : ""}
                        </p>
                      </div>
                      <StatusBadge status={change.severity} label={t(`severity.${change.severity}`)} />
                      <button
                        type="button"
                        onClick={() => navigate(`/assets?asset=${change.asset_id}`)}
                        className="text-faint hover:text-accent2"
                      >
                        <ArrowUpRight className="h-3.5 w-3.5" />
                      </button>
                      {!change.acknowledged_at && canWrite ? (
                        <Button size="sm" variant="ghost" loading={acknowledge.isPending && acknowledge.variables === change.id} onClick={() => acknowledge.mutate(change.id)}>
                          {t("asm.acknowledge")}
                        </Button>
                      ) : null}
                    </div>
                  ))}
                </div>
                <Pagination
                  page={Math.floor(offset / limit) + 1}
                  pageSize={limit}
                  total={changeTotal}
                  onPageChange={(page) => setOffset((page - 1) * limit)}
                  labels={{ previous: t("common.previous"), next: t("common.next"), page: t("common.page"), of: t("common.of") }}
                />
              </>
            ) : (
              <EmptyState icon={Activity} title={t("asm.emptyChanges")} />
            )}
          </Card>
        </TabsContent>

        <TabsContent value="monitors" className="mt-4">
          <Card className="overflow-hidden">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line/60 p-3.5">
              <div>
                <h3 className="text-xs font-semibold text-ink">{t("asm.monitorsTitle")}</h3>
                <p className="mt-0.5 text-[10px] text-muted">{t("asm.monitorsBody")}</p>
              </div>
              <Button
                size="sm"
                variant="secondary"
                icon={RefreshCw}
                loading={rescan.isPending}
                disabled={!canWrite || !monitorRows.length}
                onClick={() => rescan.mutate(monitorRows.map((row) => row.id))}
              >
                {t("asm.rescan")}
              </Button>
            </div>
            {monitors.isLoading ? (
              <div className="space-y-2 p-4">
                {[0, 1, 2].map((key) => <Skeleton key={key} className="h-12 rounded-lg" />)}
              </div>
            ) : monitors.isError ? (
              <EmptyState
                icon={AlertTriangle}
                title={t("common.errorTitle")}
                description={monitors.error instanceof Error ? monitors.error.message : t("common.errorDescription")}
              />
            ) : monitorRows.length ? (
              <>
                <div className="divide-y divide-line/50">
                  {monitorRows.map((asset) => (
                    <div key={asset.id} className="flex flex-wrap items-center gap-3 px-4 py-3">
                      <Eye className="h-4 w-4 shrink-0 text-accent2" />
                      <div className="min-w-0 flex-1">
                        <p className="truncate font-mono text-[10px] text-ink">{asset.value}</p>
                        <p className="mt-0.5 text-[9px] text-faint">
                          {asset.type} · {t("asm.lastDiscovery")}: {asset.last_scanned_at ? fromNow(asset.last_scanned_at, lang) : t("common.never")}
                        </p>
                      </div>
                      <SeverityBadge severity={asset.risk_severity} />
                      <Button size="sm" variant="ghost" onClick={() => navigate(`/assets?asset=${asset.id}`)}>
                        {t("common.details")}
                      </Button>
                      <Button
                        size="sm"
                        variant="secondary"
                        icon={Play}
                        loading={rescan.isPending}
                        disabled={!canWrite}
                        onClick={() => rescan.mutate([asset.id])}
                      >
                        {t("asm.rescan")}
                      </Button>
                    </div>
                  ))}
                </div>
                <Pagination
                  page={Math.floor(monitorOffset / 25) + 1}
                  pageSize={25}
                  total={monitors.data?.total || 0}
                  onPageChange={(page) => setMonitorOffset((page - 1) * 25)}
                  labels={{ previous: t("common.previous"), next: t("common.next"), page: t("common.page"), of: t("common.of") }}
                />
              </>
            ) : (
              <EmptyState
                icon={Eye}
                title={t("asm.monitorAssets")}
                description={t("asm.monitorsBody")}
                action={
                  <Button variant="secondary" onClick={() => navigate("/assets")}>
                    {t("nav.assets")}
                  </Button>
                }
              />
            )}
            <div className="border-t border-line/50 px-4 py-2.5 text-[9px] leading-relaxed text-faint">
              {monitors.data?.note || t("asm.monitorsBody")}
            </div>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
