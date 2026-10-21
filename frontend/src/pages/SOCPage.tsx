import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  BellRing,
  BookOpen,
  CheckCircle2,
  ChevronRight,
  Clock3,
  Database,
  FileSearch,
  FileUp,
  Filter,
  Fingerprint,
  GitBranch,
  Layers3,
  Plus,
  RefreshCw,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  Siren,
  ToggleLeft,
  ToggleRight,
  Trash2,
  Users,
  X
} from "lucide-react";
import { apiFetch, errorMessage } from "../lib/api";
import { cn, formatDateTime, fromNow } from "../lib/utils";
import { useProject } from "../context/ProjectContext";
import { useToast } from "../context/ToastContext";
import { useDebouncedValue, useDocumentTitle, useMeta } from "../hooks";
import type {
  Alert,
  DetectionRule,
  Incident,
  Lang,
  LogEvent,
  LogSource,
  Paged
} from "../types";
import { DonutChart } from "../components/charts";
import { ProjectGate } from "../components/common";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  Field,
  InlineAlert,
  Input,
  KeyValue,
  Modal,
  PageHeader,
  Pagination,
  Select,
  SeverityBadge,
  Skeleton,
  StatusBadge,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
  Textarea
} from "../components/ui";

interface AlertResponse extends Paged<Alert> {
  counts: { by_status: Record<string, number>; open_by_severity: Record<string, number> };
}

interface IncidentResponse extends Paged<Incident> {
  counts: { by_status: Record<string, number> };
}

interface EventsResponse extends Paged<LogEvent> {
  counts: { by_severity: Record<string, number> };
}

interface AlertDetailResponse {
  alert: Alert;
  rule: DetectionRule | null;
  events: LogEvent[];
}

interface IncidentEvent {
  id: number;
  ts: string;
  kind: string;
  actor: string;
  body: string;
  meta: Record<string, unknown>;
}

interface IncidentDetailResponse {
  incident: Incident;
  timeline: IncidentEvent[];
  alerts: Alert[];
}

const tabs = ["overview", "alerts", "incidents", "events", "sources", "rules"] as const;
const alertStatuses = ["new", "acknowledged", "investigating", "closed", "false_positive"];
const incidentStatuses = ["open", "contained", "eradicated", "recovering", "closed"];
const severityColors: Record<string, string> = {
  critical: "#f43f5e",
  high: "#fb923c",
  medium: "#f59e0b",
  low: "#38bdf8",
  info: "#64748b"
};

export default function SOCPage() {
  return (
    <ProjectGate>
      <SOCContent />
    </ProjectGate>
  );
}

function SOCContent() {
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const { selectedProject, canWrite, isProjectAdmin } = useProject();
  const meta = useMeta();
  const toast = useToast();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const projectId = selectedProject?.id || "";
  useDocumentTitle(t("soc.title"));

  const [tab, setTab] = useState<(typeof tabs)[number]>("overview");
  const [selectedAlert, setSelectedAlert] = useState<string | null>(null);
  const [selectedIncident, setSelectedIncident] = useState<string | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<number | null>(null);
  const [uploadOpen, setUploadOpen] = useState(false);
  const [ruleOpen, setRuleOpen] = useState(false);
  const [incidentOpen, setIncidentOpen] = useState(false);
  const [alertStatus, setAlertStatus] = useState("");
  const [alertSeverity, setAlertSeverity] = useState("");
  const [incidentStatus, setIncidentStatus] = useState("");
  const [incidentSeverity, setIncidentSeverity] = useState("");
  const [eventQuery, setEventQuery] = useState("");
  const debouncedEventQuery = useDebouncedValue(eventQuery, 300);
  const [eventSeverity, setEventSeverity] = useState("");
  const [eventSource, setEventSource] = useState("");
  const [limit, setLimit] = useState(25);
  const [offset, setOffset] = useState(0);
  const [eventOffset, setEventOffset] = useState(0);
  const [incidentOffset, setIncidentOffset] = useState(0);

  useEffect(() => setOffset(0), [alertStatus, alertSeverity]);
  useEffect(() => setEventOffset(0), [debouncedEventQuery, eventSeverity, eventSource]);
  useEffect(() => setIncidentOffset(0), [incidentStatus, incidentSeverity]);

  const overviewAlerts = useQuery({
    queryKey: ["soc-overview-alerts", projectId],
    queryFn: () => apiFetch<AlertResponse>(`/projects/${projectId}/soc/alerts`, { query: { limit: 6, offset: 0 } }),
    enabled: Boolean(projectId)
  });
  const overviewIncidents = useQuery({
    queryKey: ["soc-overview-incidents", projectId],
    queryFn: () => apiFetch<IncidentResponse>(`/projects/${projectId}/soc/incidents`, { query: { limit: 6, offset: 0 } }),
    enabled: Boolean(projectId)
  });
  const overviewEvents = useQuery({
    queryKey: ["soc-overview-events", projectId],
    queryFn: () =>
      apiFetch<EventsResponse>(`/projects/${projectId}/soc/events`, {
        query: { date_from: new Date(Date.now() - 24 * 3600 * 1000).toISOString(), limit: 6, offset: 0 }
      }),
    enabled: Boolean(projectId)
  });
  const sources = useQuery({
    queryKey: ["soc-sources", projectId],
    queryFn: () => apiFetch<{ items: LogSource[]; total?: number }>(`/projects/${projectId}/soc/sources`),
    enabled: Boolean(projectId)
  });
  const rules = useQuery({
    queryKey: ["soc-rules", projectId],
    queryFn: () => apiFetch<{ items: DetectionRule[] }>(`/projects/${projectId}/soc/rules`),
    enabled: Boolean(projectId)
  });

  const alerts = useQuery({
    queryKey: ["soc-alerts", projectId, alertStatus, alertSeverity, limit, offset],
    queryFn: () =>
      apiFetch<AlertResponse>(`/projects/${projectId}/soc/alerts`, {
        query: { status: alertStatus || undefined, severity: alertSeverity || undefined, limit, offset }
      }),
    enabled: Boolean(projectId) && tab === "alerts"
  });
  const incidents = useQuery({
    queryKey: ["soc-incidents", projectId, incidentStatus, incidentSeverity, limit, incidentOffset],
    queryFn: () =>
      apiFetch<IncidentResponse>(`/projects/${projectId}/soc/incidents`, {
        query: { status: incidentStatus || undefined, severity: incidentSeverity || undefined, limit, offset: incidentOffset }
      }),
    enabled: Boolean(projectId) && tab === "incidents"
  });
  const events = useQuery({
    queryKey: ["soc-events", projectId, debouncedEventQuery, eventSeverity, eventSource, limit, eventOffset],
    queryFn: () =>
      apiFetch<EventsResponse>(`/projects/${projectId}/soc/events`, {
        query: {
          q: debouncedEventQuery,
          severity: eventSeverity || undefined,
          source_id: eventSource || undefined,
          limit,
          offset: eventOffset
        }
      }),
    enabled: Boolean(projectId) && tab === "events"
  });

  const alertDetail = useQuery({
    queryKey: ["soc-alert", projectId, selectedAlert],
    queryFn: () => apiFetch<AlertDetailResponse>(`/projects/${projectId}/soc/alerts/${selectedAlert}`),
    enabled: Boolean(projectId && selectedAlert)
  });
  const incidentDetail = useQuery({
    queryKey: ["soc-incident", projectId, selectedIncident],
    queryFn: () => apiFetch<IncidentDetailResponse>(`/projects/${projectId}/soc/incidents/${selectedIncident}`),
    enabled: Boolean(projectId && selectedIncident)
  });
  const eventDetail = useQuery({
    queryKey: ["soc-event", projectId, selectedEvent],
    queryFn: () => apiFetch<{ event: LogEvent }>(`/projects/${projectId}/soc/events/${selectedEvent}`),
    enabled: Boolean(projectId && selectedEvent)
  });

  const updateAlert = useMutation({
    mutationFn: ({ alertId, body }: { alertId: string; body: Record<string, unknown> }) =>
      apiFetch<{ alert: Alert }>(`/projects/${projectId}/soc/alerts/${alertId}`, { method: "PATCH", body }),
    onSuccess: async () => {
      toast.toast({ title: t("soc.statusUpdated"), variant: "success" });
      await queryClient.invalidateQueries({ queryKey: ["soc-alert", projectId] });
      await queryClient.invalidateQueries({ queryKey: ["soc-alerts", projectId] });
      await queryClient.invalidateQueries({ queryKey: ["soc-overview-alerts", projectId] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    },
    onError: (error) => toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" })
  });

  const promoteAlert = useMutation({
    mutationFn: (alertId: string) =>
      apiFetch<{ incident: Incident; alert: Alert }>(`/projects/${projectId}/soc/alerts/${alertId}/promote`, { method: "POST" }),
    onSuccess: async (result) => {
      toast.toast({ title: t("soc.promoted"), variant: "success" });
      setSelectedAlert(null);
      setSelectedIncident(result.incident.id);
      await queryClient.invalidateQueries({ queryKey: ["soc-alerts", projectId] });
      await queryClient.invalidateQueries({ queryKey: ["soc-incidents", projectId] });
      await queryClient.invalidateQueries({ queryKey: ["soc-overview-alerts", projectId] });
      await queryClient.invalidateQueries({ queryKey: ["soc-overview-incidents", projectId] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    },
    onError: (error) => toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" })
  });

  const updateIncident = useMutation({
    mutationFn: ({ incidentId, body }: { incidentId: string; body: Record<string, unknown> }) =>
      apiFetch<{ incident: Incident }>(`/projects/${projectId}/soc/incidents/${incidentId}`, { method: "PATCH", body }),
    onSuccess: async () => {
      toast.toast({ title: t("soc.statusUpdated"), variant: "success" });
      await queryClient.invalidateQueries({ queryKey: ["soc-incident", projectId] });
      await queryClient.invalidateQueries({ queryKey: ["soc-incidents", projectId] });
      await queryClient.invalidateQueries({ queryKey: ["soc-overview-incidents", projectId] });
    },
    onError: (error) => toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" })
  });

  const addNote = useMutation({
    mutationFn: ({ incidentId, body }: { incidentId: string; body: string }) =>
      apiFetch<{ event: IncidentEvent }>(`/projects/${projectId}/soc/incidents/${incidentId}/notes`, {
        method: "POST",
        body: { body }
      }),
    onSuccess: async () => {
      toast.toast({ title: t("soc.noteAdded"), variant: "success" });
      await queryClient.invalidateQueries({ queryKey: ["soc-incident", projectId] });
    },
    onError: (error) => toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" })
  });

  const toggleRule = useMutation({
    mutationFn: ({ ruleId, enabled }: { ruleId: string; enabled: boolean }) =>
      apiFetch<{ rule: DetectionRule }>(`/projects/${projectId}/soc/rules/${ruleId}`, {
        method: "PATCH",
        body: { enabled }
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["soc-rules", projectId] });
    },
    onError: (error) => toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" })
  });

  const deleteSource = useMutation({
    mutationFn: (sourceId: string) =>
      apiFetch<null>(`/projects/${projectId}/soc/sources/${sourceId}`, { method: "DELETE" }),
    onSuccess: async () => {
      toast.toast({ title: t("toasts.deleted"), variant: "success" });
      await queryClient.invalidateQueries({ queryKey: ["soc-sources", projectId] });
      await queryClient.invalidateQueries({ queryKey: ["soc-overview-events", projectId] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    },
    onError: (error) => toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" })
  });

  const sourceRows = sources.data?.items || [];
  const ruleRows = rules.data?.items || [];
  const overviewAlertRows = overviewAlerts.data?.items || [];
  const overviewIncidentRows = overviewIncidents.data?.items || [];
  const overviewEventRows = overviewEvents.data?.items || [];
  const alertRows = alerts.data?.items || [];
  const incidentRows = incidents.data?.items || [];
  const eventRows = events.data?.items || [];
  const openAlerts =
    (overviewAlerts.data?.counts.by_status.new || 0) +
    (overviewAlerts.data?.counts.by_status.acknowledged || 0) +
    (overviewAlerts.data?.counts.by_status.investigating || 0);
  const openIncidents = overviewIncidents.data?.counts.by_status.open || 0;
  const activeRules = ruleRows.filter((rule) => rule.enabled).length;
  const eventCount = overviewEvents.data?.total || 0;

  const alertChart = useMemo(
    () =>
      Object.entries(overviewAlerts.data?.counts.open_by_severity || {})
        .filter(([, value]) => value > 0)
        .map(([severity, value]) => ({
          name: t(`severity.${severity}`),
          value,
          color: severityColors[severity] || "#64748b"
        }))
        .sort((a, b) => b.value - a.value),
    [overviewAlerts.data?.counts.open_by_severity, t]
  );

  const incidentChart = useMemo(
    () =>
      Object.entries(overviewIncidents.data?.counts.by_status || {}).map(([status, value], index) => ({
        name: t(`status.${status}`),
        value,
        color: ["#8b5cf6", "#22d3ee", "#f59e0b", "#34d399", "#64748b"][index % 5]
      })),
    [overviewIncidents.data?.counts.by_status, t]
  );

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow={t("nav.soc")}
        icon={Siren}
        title={t("soc.title")}
        subtitle={t("soc.subtitle")}
        actions={
          <>
            <Button variant="secondary" onClick={() => setIncidentOpen(true)} disabled={!canWrite}>
              {t("soc.incidentTitle")}
            </Button>
            <Button icon={FileUp} onClick={() => setUploadOpen(true)} disabled={!canWrite}>
              {t("soc.uploadLogs")}
            </Button>
          </>
        }
      />

      <section className="grid grid-cols-2 gap-2.5 xl:grid-cols-5">
        {[
          { label: t("soc.events24h"), value: eventCount, icon: Activity, tone: "text-accent" },
          { label: t("soc.openAlerts"), value: openAlerts, icon: BellRing, tone: "text-amber-300" },
          { label: t("soc.openIncidents"), value: openIncidents, icon: Siren, tone: "text-rose-300" },
          { label: t("soc.sources"), value: sourceRows.length, icon: Database, tone: "text-accent2" },
          { label: t("soc.activeRules"), value: activeRules, icon: ShieldCheck, tone: "text-emerald-300" }
        ].map((card) => (
          <div key={card.label} className="surface-card p-3.5">
            <div className="flex items-center justify-between">
              <span className="text-[9px] font-semibold uppercase tracking-[0.1em] text-muted">{card.label}</span>
              <card.icon className={cn("h-4 w-4", card.tone)} />
            </div>
            <p className="mt-2 font-display text-2xl font-semibold tabular-nums text-ink">{card.value}</p>
          </div>
        ))}
      </section>

      <Tabs
        value={tab}
        onValueChange={(value) => {
          setTab(value as (typeof tabs)[number]);
          setOffset(0);
          setEventOffset(0);
          setIncidentOffset(0);
        }}
      >
        <TabsList>
          <TabsTrigger value="overview" icon={Activity}>
            {t("soc.tabs.overview")}
          </TabsTrigger>
          <TabsTrigger value="alerts" icon={BellRing} count={openAlerts}>
            {t("soc.tabs.alerts")}
          </TabsTrigger>
          <TabsTrigger value="incidents" icon={Siren} count={openIncidents}>
            {t("soc.tabs.incidents")}
          </TabsTrigger>
          <TabsTrigger value="events" icon={FileSearch}>
            {t("soc.tabs.events")}
          </TabsTrigger>
          <TabsTrigger value="sources" icon={Database}>
            {t("soc.tabs.sources")}
          </TabsTrigger>
          <TabsTrigger value="rules" icon={ShieldCheck} count={activeRules}>
            {t("soc.tabs.rules")}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="mt-4 space-y-4">
          {!sourceRows.length && !overviewEvents.isLoading ? (
            <InlineAlert tone="info" title={t("soc.uploadLogs")}>
              {t("soc.uploadHint")}
            </InlineAlert>
          ) : null}

          <div className="grid gap-4 xl:grid-cols-12">
            <Card className="p-4 xl:col-span-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-xs font-semibold text-ink">{t("soc.severity")}</h3>
                  <p className="mt-0.5 text-[10px] text-muted">{t("soc.alertsSubtitle")}</p>
                </div>
                <ShieldAlert className="h-4 w-4 text-rose-300" />
              </div>
              {alertChart.length ? (
                <DonutChart data={alertChart} height={235} centerLabel={t("soc.openAlerts")} centerValue={openAlerts} />
              ) : (
                <EmptyState icon={ShieldCheck} title={t("soc.noAlerts")} />
              )}
            </Card>
            <Card className="p-4 xl:col-span-4">
              <h3 className="text-xs font-semibold text-ink">{t("soc.openIncidents")}</h3>
              <p className="mt-0.5 text-[10px] text-muted">{t("soc.incidentsSubtitle")}</p>
              {incidentChart.length ? (
                <DonutChart data={incidentChart} height={235} centerLabel={t("soc.incidents")} centerValue={overviewIncidents.data?.total || 0} />
              ) : (
                <EmptyState icon={CheckCircle2} title={t("soc.noIncidents")} />
              )}
            </Card>
            <Card className="overflow-hidden xl:col-span-4">
              <div className="flex items-center justify-between border-b border-line/60 px-4 py-3">
                <div>
                  <h3 className="text-xs font-semibold text-ink">{t("soc.recentAlerts")}</h3>
                  <p className="mt-0.5 text-[10px] text-muted">{t("soc.alertsSubtitle")}</p>
                </div>
                <Button size="sm" variant="ghost" onClick={() => setTab("alerts")}>
                  {t("dashboard.viewAll")}
                </Button>
              </div>
              {overviewAlerts.isLoading ? (
                <div className="space-y-2 p-4">
                  {[0, 1, 2].map((key) => <Skeleton key={key} className="h-10 rounded-lg" />)}
                </div>
              ) : overviewAlertRows.length ? (
                <div className="divide-y divide-line/50">
                  {overviewAlertRows.slice(0, 4).map((alert) => (
                    <button
                      key={alert.id}
                      type="button"
                      onClick={() => setSelectedAlert(alert.id)}
                      className="flex w-full items-center gap-2.5 px-4 py-3 text-start hover:bg-panel2/40"
                    >
                      <SeverityBadge severity={alert.severity} />
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-[10px] font-medium text-ink">{alert.title}</span>
                        <span className="mt-0.5 block text-[9px] text-faint">{fromNow(alert.last_seen_at, lang)}</span>
                      </span>
                      <ChevronRight className="h-3 w-3 text-faint rtl:rotate-180" />
                    </button>
                  ))}
                </div>
              ) : (
                <EmptyState icon={ShieldCheck} title={t("soc.noAlerts")} />
              )}
            </Card>
          </div>

          <div className="grid gap-4 xl:grid-cols-12">
            <Card className="overflow-hidden xl:col-span-7">
              <div className="flex items-center justify-between border-b border-line/60 px-4 py-3">
                <div>
                  <h3 className="text-xs font-semibold text-ink">{t("soc.recentEvents")}</h3>
                  <p className="mt-0.5 text-[10px] text-muted">{t("soc.events24h")}</p>
                </div>
                <Button size="sm" variant="ghost" onClick={() => setTab("events")}>
                  {t("dashboard.viewAll")}
                </Button>
              </div>
              {overviewEvents.isLoading ? (
                <div className="space-y-2 p-4">
                  {[0, 1, 2].map((key) => <Skeleton key={key} className="h-10 rounded-lg" />)}
                </div>
              ) : overviewEventRows.length ? (
                <div className="divide-y divide-line/50">
                  {overviewEventRows.map((event) => (
                    <button
                      key={event.id}
                      type="button"
                      onClick={() => setSelectedEvent(event.id)}
                      className="flex w-full items-center gap-3 px-4 py-3 text-start hover:bg-panel2/40"
                    >
                      <SeverityBadge severity={event.severity} />
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-[10px] font-medium text-ink">{event.message || event.event_type}</span>
                        <span className="mt-0.5 block truncate font-mono text-[8px] text-faint">
                          {event.src_ip || "—"} {event.method ? `· ${event.method}` : ""} {event.url || ""}
                        </span>
                      </span>
                      <span className="whitespace-nowrap text-[9px] text-faint">{fromNow(event.ts || event.ingested_at, lang)}</span>
                    </button>
                  ))}
                </div>
              ) : (
                <EmptyState
                  icon={FileSearch}
                  title={t("soc.noEvents")}
                  description={t("soc.uploadHint")}
                  action={
                    <Button size="sm" icon={FileUp} onClick={() => setUploadOpen(true)} disabled={!canWrite}>
                      {t("soc.uploadLogs")}
                    </Button>
                  }
                />
              )}
            </Card>
            <Card className="overflow-hidden xl:col-span-5">
              <div className="flex items-center justify-between border-b border-line/60 px-4 py-3">
                <div>
                  <h3 className="text-xs font-semibold text-ink">{t("soc.sourcesTitle")}</h3>
                  <p className="mt-0.5 text-[10px] text-muted">{t("soc.sourcesSubtitle")}</p>
                </div>
                <Button size="sm" variant="ghost" onClick={() => setTab("sources")}>
                  {t("dashboard.viewAll")}
                </Button>
              </div>
              {sourceRows.length ? (
                <div className="divide-y divide-line/50">
                  {sourceRows.slice(0, 5).map((source) => (
                    <div key={source.id} className="flex items-center gap-3 px-4 py-3">
                      <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-line bg-panel2 text-accent2">
                        <Database className="h-3.5 w-3.5" />
                      </span>
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-[10px] font-medium text-ink">{source.name}</p>
                        <p className="mt-0.5 text-[9px] text-faint">
                          {source.format} · {source.event_count} {t("soc.events")}
                          {source.parse_errors ? ` · ${source.parse_errors} ${t("common.errors")}` : ""}
                        </p>
                      </div>
                      <span className="text-[9px] text-faint">{source.last_event_at ? fromNow(source.last_event_at, lang) : t("common.never")}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState icon={Database} title={t("soc.noSources")} />
              )}
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="alerts" className="mt-4">
          <Card className="overflow-hidden">
            <div className="flex flex-wrap items-center gap-2 border-b border-line/60 p-3.5">
              <div className="min-w-0 flex-1">
                <h3 className="text-xs font-semibold text-ink">{t("soc.alertsTitle")}</h3>
                <p className="mt-0.5 text-[10px] text-muted">{t("soc.alertsSubtitle")}</p>
              </div>
              <Select value={alertStatus} onChange={(event) => setAlertStatus(event.target.value)} className="w-auto">
                <option value="">{t("soc.alertStatus")} · {t("common.all")}</option>
                {alertStatuses.map((status) => (
                  <option key={status} value={status}>{t(`status.${status}`)}</option>
                ))}
              </Select>
              <Select value={alertSeverity} onChange={(event) => setAlertSeverity(event.target.value)} className="w-auto">
                <option value="">{t("common.severity")} · {t("common.all")}</option>
                {["critical", "high", "medium", "low", "info"].map((severity) => (
                  <option key={severity} value={severity}>{t(`severity.${severity}`)}</option>
                ))}
              </Select>
              <span className="text-[9px] text-faint">{t("projects.total", { count: alerts.data?.total || 0 })}</span>
            </div>
            {alerts.isLoading ? (
              <div className="space-y-2 p-4">{[0, 1, 2, 3].map((key) => <Skeleton key={key} className="h-14 rounded-lg" />)}</div>
            ) : alerts.isError ? (
              <EmptyState
                icon={AlertTriangle}
                title={t("common.errorTitle")}
                description={alerts.error instanceof Error ? alerts.error.message : t("common.errorDescription")}
              />
            ) : alertRows.length ? (
              <>
                <div className="divide-y divide-line/50">
                  {alertRows.map((alert) => (
                    <button
                      key={alert.id}
                      type="button"
                      onClick={() => setSelectedAlert(alert.id)}
                      className="flex w-full flex-wrap items-center gap-3 px-4 py-3.5 text-start transition hover:bg-panel2/40"
                    >
                      <span className={cn("h-2 w-2 shrink-0 rounded-full", {
                        "bg-rose-400": alert.severity === "critical",
                        "bg-orange-400": alert.severity === "high",
                        "bg-amber-400": alert.severity === "medium",
                        "bg-sky-400": alert.severity === "low",
                        "bg-slate-400": alert.severity === "info"
                      })} />
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <p className="truncate text-[11px] font-medium text-ink">{alert.title}</p>
                          <StatusBadge status={alert.status} />
                          {alert.incident_id ? <Badge tone="info">{t("soc.incident")}</Badge> : null}
                        </div>
                        <p className="mt-0.5 line-clamp-1 text-[9px] text-faint">{alert.description}</p>
                      </div>
                      <div className="text-end">
                        <p className="font-mono text-[10px] text-muted">{alert.event_count} {t("soc.events")}</p>
                        <p className="mt-0.5 text-[8px] text-faint">{fromNow(alert.last_seen_at, lang)}</p>
                      </div>
                      <ChevronRight className="h-3.5 w-3.5 text-faint rtl:rotate-180" />
                    </button>
                  ))}
                </div>
                <Pagination
                  page={Math.floor(offset / limit) + 1}
                  pageSize={limit}
                  total={alerts.data?.total || 0}
                  onPageChange={(page) => setOffset((page - 1) * limit)}
                  labels={{ previous: t("common.previous"), next: t("common.next"), page: t("common.page"), of: t("common.of") }}
                />
              </>
            ) : (
              <EmptyState icon={ShieldCheck} title={t("soc.noAlerts")} />
            )}
          </Card>
        </TabsContent>

        <TabsContent value="incidents" className="mt-4">
          <Card className="overflow-hidden">
            <div className="flex flex-wrap items-center gap-2 border-b border-line/60 p-3.5">
              <div className="min-w-0 flex-1">
                <h3 className="text-xs font-semibold text-ink">{t("soc.incidentsTitle")}</h3>
                <p className="mt-0.5 text-[10px] text-muted">{t("soc.incidentsSubtitle")}</p>
              </div>
              <Select value={incidentStatus} onChange={(event) => setIncidentStatus(event.target.value)} className="w-auto">
                <option value="">{t("soc.incidentStatus")} · {t("common.all")}</option>
                {incidentStatuses.map((status) => (
                  <option key={status} value={status}>{t(`status.${status}`)}</option>
                ))}
              </Select>
              <Select value={incidentSeverity} onChange={(event) => setIncidentSeverity(event.target.value)} className="w-auto">
                <option value="">{t("common.severity")} · {t("common.all")}</option>
                {["critical", "high", "medium", "low", "info"].map((severity) => (
                  <option key={severity} value={severity}>{t(`severity.${severity}`)}</option>
                ))}
              </Select>
              <Button size="sm" icon={Plus} onClick={() => setIncidentOpen(true)} disabled={!canWrite}>
                {t("soc.incidentTitle")}
              </Button>
            </div>
            {incidents.isLoading ? (
              <div className="space-y-2 p-4">{[0, 1, 2].map((key) => <Skeleton key={key} className="h-14 rounded-lg" />)}</div>
            ) : incidents.isError ? (
              <EmptyState
                icon={AlertTriangle}
                title={t("common.errorTitle")}
                description={incidents.error instanceof Error ? incidents.error.message : t("common.errorDescription")}
              />
            ) : incidentRows.length ? (
              <>
                <div className="divide-y divide-line/50">
                  {incidentRows.map((incident) => (
                    <button
                      key={incident.id}
                      type="button"
                      onClick={() => setSelectedIncident(incident.id)}
                      className="flex w-full flex-wrap items-center gap-3 px-4 py-3.5 text-start transition hover:bg-panel2/40"
                    >
                      <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-rose-400/20 bg-rose-400/[0.06] text-rose-300">
                        <Siren className="h-3.5 w-3.5" />
                      </span>
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-[11px] font-medium text-ink">{incident.title}</p>
                        <p className="mt-0.5 text-[9px] text-faint">
                          {t("soc.opened")} {fromNow(incident.opened_at, lang)} · {incident.summary || t("common.noDescription")}
                        </p>
                      </div>
                      <SeverityBadge severity={incident.severity} />
                      <StatusBadge status={incident.status} />
                      <ChevronRight className="h-3.5 w-3.5 text-faint rtl:rotate-180" />
                    </button>
                  ))}
                </div>
                <Pagination
                  page={Math.floor(incidentOffset / limit) + 1}
                  pageSize={limit}
                  total={incidents.data?.total || 0}
                  onPageChange={(page) => setIncidentOffset((page - 1) * limit)}
                  labels={{ previous: t("common.previous"), next: t("common.next"), page: t("common.page"), of: t("common.of") }}
                />
              </>
            ) : (
              <EmptyState icon={CheckCircle2} title={t("soc.noIncidents")} />
            )}
          </Card>
        </TabsContent>

        <TabsContent value="events" className="mt-4">
          <Card className="overflow-hidden">
            <div className="flex flex-wrap items-center gap-2 border-b border-line/60 p-3.5">
              <div className="relative min-w-[190px] flex-1">
                <Search className="pointer-events-none absolute start-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-faint" />
                <Input
                  value={eventQuery}
                  onChange={(event) => setEventQuery(event.target.value)}
                  placeholder={t("common.search")}
                  className="ps-9"
                />
              </div>
              <Select value={eventSeverity} onChange={(event) => setEventSeverity(event.target.value)} className="w-auto">
                <option value="">{t("common.severity")} · {t("common.all")}</option>
                {["critical", "high", "medium", "low", "info"].map((severity) => (
                  <option key={severity} value={severity}>{t(`severity.${severity}`)}</option>
                ))}
              </Select>
              <Select value={eventSource} onChange={(event) => setEventSource(event.target.value)} className="w-auto">
                <option value="">{t("soc.source")} · {t("common.all")}</option>
                {sourceRows.map((source) => (
                  <option key={source.id} value={source.id}>{source.name}</option>
                ))}
              </Select>
              <Button size="sm" icon={FileUp} onClick={() => setUploadOpen(true)} disabled={!canWrite}>
                {t("soc.uploadLogs")}
              </Button>
              <span className="text-[9px] text-faint">{t("projects.total", { count: events.data?.total || 0 })}</span>
            </div>
            {events.isLoading ? (
              <div className="space-y-2 p-4">{[0, 1, 2, 3].map((key) => <Skeleton key={key} className="h-10 rounded-lg" />)}</div>
            ) : events.isError ? (
              <EmptyState
                icon={AlertTriangle}
                title={t("common.errorTitle")}
                description={events.error instanceof Error ? events.error.message : t("common.errorDescription")}
              />
            ) : eventRows.length ? (
              <>
                <div className="hidden md:block">
                  <table className="w-full text-start text-[10px]">
                    <thead>
                      <tr className="border-b border-line/60 bg-panel2/30 text-[9px] uppercase tracking-[0.08em] text-faint">
                        <th className="px-4 py-2.5 text-start font-medium">{t("soc.time")}</th>
                        <th className="px-3 py-2.5 text-start font-medium">{t("common.severity")}</th>
                        <th className="px-3 py-2.5 text-start font-medium">{t("soc.event")}</th>
                        <th className="px-3 py-2.5 text-start font-medium">{t("soc.sourceIp")}</th>
                        <th className="px-3 py-2.5 text-start font-medium">{t("soc.message")}</th>
                        <th className="px-3 py-2.5 text-start font-medium">{t("soc.ruleMatches")}</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-line/50">
                      {eventRows.map((event) => (
                        <tr
                          key={event.id}
                          onClick={() => setSelectedEvent(event.id)}
                          className="cursor-pointer transition hover:bg-panel2/40"
                        >
                          <td className="whitespace-nowrap px-4 py-2.5 text-[9px] text-muted">{formatDateTime(event.ts || event.ingested_at, lang)}</td>
                          <td className="px-3 py-2.5"><SeverityBadge severity={event.severity} /></td>
                          <td className="max-w-[180px] truncate px-3 py-2.5 font-mono text-[9px] text-accent2">{event.event_type}</td>
                          <td className="px-3 py-2.5 font-mono text-[9px] text-muted">{event.src_ip || "—"}</td>
                          <td className="max-w-[360px] px-3 py-2.5">
                            <p className="truncate text-[10px] text-ink">{event.message || "—"}</p>
                            <p className="mt-0.5 truncate font-mono text-[8px] text-faint">
                              {event.method} {event.url} {event.status_code ? `· ${event.status_code}` : ""}
                            </p>
                          </td>
                          <td className="px-3 py-2.5">
                            {event.rule_hits.length ? (
                              <span className="inline-flex items-center gap-1 text-[9px] text-rose-300">
                                <ShieldAlert className="h-3 w-3" /> {event.rule_hits.length}
                              </span>
                            ) : (
                              <span className="text-[9px] text-faint">—</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <div className="divide-y divide-line/50 md:hidden">
                  {eventRows.map((event) => (
                    <button
                      key={event.id}
                      type="button"
                      onClick={() => setSelectedEvent(event.id)}
                      className="w-full p-3.5 text-start hover:bg-panel2/40"
                    >
                      <div className="flex items-center gap-2">
                        <SeverityBadge severity={event.severity} />
                        <span className="font-mono text-[8px] text-accent2">{event.event_type}</span>
                        <span className="ms-auto text-[8px] text-faint">{fromNow(event.ts || event.ingested_at, lang)}</span>
                      </div>
                      <p className="mt-1 line-clamp-2 text-[10px] text-ink">{event.message || event.url}</p>
                      <p className="mt-0.5 font-mono text-[8px] text-faint">{event.src_ip || "—"}</p>
                    </button>
                  ))}
                </div>
                <Pagination
                  page={Math.floor(eventOffset / limit) + 1}
                  pageSize={limit}
                  total={events.data?.total || 0}
                  onPageChange={(page) => setEventOffset((page - 1) * limit)}
                  labels={{ previous: t("common.previous"), next: t("common.next"), page: t("common.page"), of: t("common.of") }}
                />
              </>
            ) : (
              <EmptyState
                icon={FileSearch}
                title={t("soc.noEvents")}
                description={t("soc.uploadHint")}
                action={
                  <Button icon={FileUp} onClick={() => setUploadOpen(true)} disabled={!canWrite}>
                    {t("soc.uploadLogs")}
                  </Button>
                }
              />
            )}
          </Card>
        </TabsContent>

        <TabsContent value="sources" className="mt-4">
          <Card className="overflow-hidden">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line/60 p-3.5">
              <div>
                <h3 className="text-xs font-semibold text-ink">{t("soc.sourcesTitle")}</h3>
                <p className="mt-0.5 text-[10px] text-muted">{t("soc.sourcesSubtitle")}</p>
              </div>
              <Button size="sm" icon={FileUp} onClick={() => setUploadOpen(true)} disabled={!canWrite}>
                {t("soc.uploadLogs")}
              </Button>
            </div>
            {sources.isLoading ? (
              <div className="space-y-2 p-4">{[0, 1, 2].map((key) => <Skeleton key={key} className="h-12 rounded-lg" />)}</div>
            ) : sources.isError ? (
              <EmptyState
                icon={AlertTriangle}
                title={t("common.errorTitle")}
                description={sources.error instanceof Error ? sources.error.message : t("common.errorDescription")}
              />
            ) : sourceRows.length ? (
              <div className="divide-y divide-line/50">
                {sourceRows.map((source) => (
                  <div key={source.id} className="flex flex-wrap items-center gap-3 px-4 py-3.5">
                    <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-line bg-panel2 text-accent2">
                      <Database className="h-4 w-4" />
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <p className="truncate text-[11px] font-medium text-ink">{source.name}</p>
                        <Badge tone="default">{source.format}</Badge>
                        {source.parse_errors ? <Badge tone="danger">{source.parse_errors} {t("common.errors")}</Badge> : null}
                      </div>
                      <p className="mt-0.5 text-[9px] text-faint">
                        {source.event_count} {t("soc.events")} · {(source.size_bytes / 1024).toFixed(1)} KB · {source.filename || "—"} · {fromNow(source.created_at, lang)}
                      </p>
                    </div>
                    <Button
                      size="sm"
                      variant="ghost"
                      icon={Trash2}
                      loading={deleteSource.isPending && deleteSource.variables === source.id}
                      disabled={!isProjectAdmin}
                      onClick={() => {
                        if (window.confirm(t("soc.deleteSourceConfirm"))) deleteSource.mutate(source.id);
                      }}
                    >
                      {t("common.delete")}
                    </Button>
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState
                icon={Database}
                title={t("soc.noSources")}
                action={
                  <Button icon={FileUp} onClick={() => setUploadOpen(true)} disabled={!canWrite}>
                    {t("soc.uploadLogs")}
                  </Button>
                }
              />
            )}
          </Card>
        </TabsContent>

        <TabsContent value="rules" className="mt-4">
          <Card className="overflow-hidden">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line/60 p-3.5">
              <div>
                <h3 className="text-xs font-semibold text-ink">{t("soc.rulesTitle")}</h3>
                <p className="mt-0.5 text-[10px] text-muted">{t("soc.rulesSubtitle")}</p>
              </div>
              <Button size="sm" icon={Plus} onClick={() => setRuleOpen(true)} disabled={!canWrite}>
                {t("soc.addRule")}
              </Button>
            </div>
            {rules.isLoading ? (
              <div className="space-y-2 p-4">{[0, 1, 2].map((key) => <Skeleton key={key} className="h-16 rounded-lg" />)}</div>
            ) : rules.isError ? (
              <EmptyState
                icon={AlertTriangle}
                title={t("common.errorTitle")}
                description={rules.error instanceof Error ? rules.error.message : t("common.errorDescription")}
              />
            ) : ruleRows.length ? (
              <div className="divide-y divide-line/50">
                {ruleRows.map((rule) => (
                  <div key={rule.id} className="flex flex-wrap items-center gap-3 px-4 py-3.5">
                    <span className={cn("grid h-9 w-9 shrink-0 place-items-center rounded-lg border", rule.enabled ? "border-accent/20 bg-accent/[0.06] text-accent" : "border-line bg-panel2 text-faint")}>
                      <ShieldCheck className="h-4 w-4" />
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <p className="text-[11px] font-medium text-ink">{rule.name}</p>
                        <Badge tone={rule.is_builtin ? "info" : "accent"}>{rule.is_builtin ? t("soc.builtin") : t("soc.custom")}</Badge>
                        <Badge tone={rule.enabled ? "success" : "default"}>{rule.enabled ? t("common.enabled") : t("common.disabled")}</Badge>
                      </div>
                      <p className="mt-0.5 line-clamp-1 text-[9px] text-faint">{rule.description || t("common.noDescription")}</p>
                      <p className="mt-1 font-mono text-[8px] text-faint">
                        {rule.trigger_count} {t("soc.ruleMatches")} · {rule.last_triggered_at ? fromNow(rule.last_triggered_at, lang) : t("common.never")}
                      </p>
                    </div>
                    <SeverityBadge severity={rule.severity} />
                    <Button
                      size="sm"
                      variant="ghost"
                      icon={rule.enabled ? ToggleRight : ToggleLeft}
                      loading={toggleRule.isPending && toggleRule.variables?.ruleId === rule.id}
                      disabled={!canWrite}
                      onClick={() => toggleRule.mutate({ ruleId: rule.id, enabled: !rule.enabled })}
                    >
                      {rule.enabled ? t("common.disabled") : t("common.enabled")}
                    </Button>
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState icon={ShieldCheck} title={t("soc.noRules")} />
            )}
            <div className="border-t border-line/50 px-4 py-2.5 text-[9px] leading-relaxed text-faint">
              {t("soc.ruleBody")}
            </div>
          </Card>
        </TabsContent>
      </Tabs>

      <UploadModal open={uploadOpen} onOpenChange={setUploadOpen} projectId={projectId} />

      <AlertDetailModal
        open={Boolean(selectedAlert)}
        onClose={() => setSelectedAlert(null)}
        data={alertDetail.data}
        loading={alertDetail.isLoading}
        error={alertDetail.error}
        onRetry={() => void alertDetail.refetch()}
        onUpdate={(body) => selectedAlert && updateAlert.mutate({ alertId: selectedAlert, body })}
        updating={updateAlert.isPending}
        onPromote={() => selectedAlert && promoteAlert.mutate(selectedAlert)}
        promoting={promoteAlert.isPending}
        canWrite={canWrite}
        onEvent={setSelectedEvent}
      />

      <IncidentDetailModal
        open={Boolean(selectedIncident)}
        onClose={() => setSelectedIncident(null)}
        data={incidentDetail.data}
        loading={incidentDetail.isLoading}
        error={incidentDetail.error}
        onRetry={() => void incidentDetail.refetch()}
        onStatus={(status) => selectedIncident && updateIncident.mutate({ incidentId: selectedIncident, body: { status } })}
        updating={updateIncident.isPending}
        onNote={(body) => selectedIncident && addNote.mutate({ incidentId: selectedIncident, body })}
        noting={addNote.isPending}
        canWrite={canWrite}
        onOpenAlert={(id) => {
          setSelectedIncident(null);
          setSelectedAlert(id);
        }}
      />

      <EventModal
        open={Boolean(selectedEvent)}
        onClose={() => setSelectedEvent(null)}
        data={eventDetail.data?.event}
        loading={eventDetail.isLoading}
        error={eventDetail.error}
        onRetry={() => void eventDetail.refetch()}
      />

      <RuleModal
        open={ruleOpen}
        onOpenChange={setRuleOpen}
        projectId={projectId}
        onCreated={() => {
          setRuleOpen(false);
          void queryClient.invalidateQueries({ queryKey: ["soc-rules", projectId] });
        }}
      />

      <IncidentCreateModal
        open={incidentOpen}
        onOpenChange={setIncidentOpen}
        projectId={projectId}
        onCreated={(incident) => {
          setIncidentOpen(false);
          setSelectedIncident(incident.id);
          void queryClient.invalidateQueries({ queryKey: ["soc-incidents", projectId] });
          void queryClient.invalidateQueries({ queryKey: ["soc-overview-incidents", projectId] });
        }}
      />
    </div>
  );
}

function UploadModal({
  open,
  onOpenChange,
  projectId
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  projectId: string;
}) {
  const { t } = useTranslation();
  const meta = useMeta();
  const toast = useToast();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [file, setFile] = useState<File | null>(null);
  const [name, setName] = useState("");
  const [format, setFormat] = useState("auto");
  const [error, setError] = useState("");

  useEffect(() => {
    if (!open) return;
    setFile(null);
    setName("");
    setFormat("auto");
    setError("");
  }, [open]);

  const upload = useMutation({
    mutationFn: async () => {
      if (!file) throw new Error("file_required");
      const form = new FormData();
      form.append("file", file);
      form.append("name", name.trim());
      form.append("format", format);
      return apiFetch<{ scan_id: string; job_id: string | null; upload: Record<string, unknown>; note: string }>(
        `/projects/${projectId}/soc/sources`,
        { method: "POST", rawBody: form }
      );
    },
    onSuccess: async (result) => {
      toast.toast({ title: t("soc.uploaded"), description: result.note, variant: "success" });
      onOpenChange(false);
      await queryClient.invalidateQueries({ queryKey: ["soc-sources", projectId] });
      await queryClient.invalidateQueries({ queryKey: ["soc-overview-events", projectId] });
      await queryClient.invalidateQueries({ queryKey: ["scans", projectId] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
      navigate(`/scans/${result.scan_id}`);
    },
    onError: (caught) => setError(errorMessage(caught))
  });

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title={t("soc.uploadLogs")}
      description={t("soc.uploadHint")}
      icon={FileUp}
      size="md"
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>{t("common.cancel")}</Button>
          <Button icon={FileUp} loading={upload.isPending} disabled={!file} onClick={() => { setError(""); upload.mutate(); }}>
            {t("soc.upload")}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label={t("soc.selectFile")} required>
          <Input
            type="file"
            accept=".log,.txt,.json,.csv,.tsv,.xml,.evtx,.gz,.njson"
            onChange={(event) => {
              setFile(event.target.files?.[0] || null);
              if (event.target.files?.[0] && !name) setName(event.target.files[0].name.replace(/\.[^.]+$/, ""));
            }}
            className="py-2 file:me-2 file:rounded-md file:border-0 file:bg-accent/15 file:px-2 file:py-1 file:text-[10px] file:text-accent"
          />
        </Field>
        <Field label={t("soc.sourceName")} hint={t("common.optional")}>
          <Input value={name} onChange={(event) => setName(event.target.value)} placeholder={file?.name || "nginx-access"} />
        </Field>
        <Field label={t("soc.logFormat")}>
          <Select value={format} onChange={(event) => setFormat(event.target.value)}>
            {(meta.data?.constants.log_formats || ["auto"]).map((option) => (
              <option key={option} value={option}>{option}</option>
            ))}
          </Select>
        </Field>
        {error ? <InlineAlert tone="danger">{error}</InlineAlert> : null}
      </div>
    </Modal>
  );
}

function AlertDetailModal({
  open,
  onClose,
  data,
  loading,
  error,
  onRetry,
  onUpdate,
  updating,
  onPromote,
  promoting,
  canWrite,
  onEvent
}: {
  open: boolean;
  onClose: () => void;
  data?: AlertDetailResponse;
  loading: boolean;
  error: unknown;
  onRetry: () => void;
  onUpdate: (body: Record<string, unknown>) => void;
  updating: boolean;
  onPromote: () => void;
  promoting: boolean;
  canWrite: boolean;
  onEvent: (id: number) => void;
}) {
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const [note, setNote] = useState("");
  const alert = data?.alert;
  const notes = Array.isArray(alert?.meta.notes) ? (alert?.meta.notes as { at: string; by: string; note: string }[]) : [];

  return (
    <Modal
      open={open}
      onOpenChange={(next) => !next && onClose()}
      title={alert?.title || t("soc.alert")}
      description={
        alert ? (
          <span className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={alert.severity} />
            <StatusBadge status={alert.status} />
            <span className="font-mono text-[9px] text-faint">{alert.event_count} {t("soc.events")}</span>
            <span className="text-[9px] text-faint">{fromNow(alert.last_seen_at, lang)}</span>
          </span>
        ) : undefined
      }
      icon={BellRing}
      size="full"
      footer={
        alert ? (
          <>
            {canWrite ? (
              <Select
                value={alert.status}
                onChange={(event) => onUpdate({ status: event.target.value })}
                className="w-auto"
                disabled={updating}
              >
                {alertStatuses.map((status) => (
                  <option key={status} value={status}>{t(`status.${status}`)}</option>
                ))}
              </Select>
            ) : null}
            {canWrite && !alert.incident_id ? (
              <Button variant="secondary" icon={Siren} loading={promoting} onClick={onPromote}>
                {t("soc.promote")}
              </Button>
            ) : null}
            <Button variant="secondary" onClick={onClose} className="ms-auto">{t("common.close")}</Button>
          </>
        ) : undefined
      }
    >
      {loading ? (
        <div className="space-y-3"><Skeleton className="h-24 rounded-xl" /><Skeleton className="h-56 rounded-xl" /></div>
      ) : error || !data || !alert ? (
        <EmptyState
          icon={AlertTriangle}
          title={t("common.errorTitle")}
          description={error instanceof Error ? error.message : t("common.errorDescription")}
          action={<Button variant="secondary" onClick={onRetry}>{t("common.retry")}</Button>}
        />
      ) : (
        <div className="grid gap-4 lg:grid-cols-12">
          <div className="space-y-4 lg:col-span-7">
            <div className="rounded-xl border border-line/60 bg-panel2/30 p-4">
              <h4 className="text-xs font-semibold text-ink">{t("common.details")}</h4>
              <p className="mt-2 whitespace-pre-wrap text-[10px] leading-relaxed text-muted">{alert.description || t("common.noDescription")}</p>
              <dl className="mt-3 grid gap-3 sm:grid-cols-2">
                <KeyValue label={t("common.severity")} value={<SeverityBadge severity={alert.severity} />} />
                <KeyValue label={t("soc.alertStatus")} value={<StatusBadge status={alert.status} />} />
                <KeyValue label={t("soc.firstSeen")} value={formatDateTime(alert.first_seen_at, lang)} />
                <KeyValue label={t("soc.lastSeen")} value={formatDateTime(alert.last_seen_at, lang)} />
                <KeyValue label={t("soc.rule")} value={data.rule?.name || alert.rule_id || "—"} />
                <KeyValue label={t("soc.incident")} value={alert.incident_id || "—"} mono />
              </dl>
            </div>
            <div className="rounded-xl border border-line/60 bg-panel2/30 p-4">
              <h4 className="text-xs font-semibold text-ink">{t("soc.relatedEvents")} · {data.events.length}</h4>
              {data.events.length ? (
                <div className="mt-2 divide-y divide-line/40">
                  {data.events.map((event) => (
                    <button
                      key={event.id}
                      type="button"
                      onClick={() => onEvent(event.id)}
                      className="flex w-full items-center gap-2 py-2 text-start hover:text-accent2"
                    >
                      <SeverityBadge severity={event.severity} />
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-[10px] text-ink">{event.message || event.event_type}</span>
                        <span className="mt-0.5 block font-mono text-[8px] text-faint">{event.src_ip || "—"} · {event.url || event.event_type}</span>
                      </span>
                      <ArrowUpRight className="h-3 w-3 text-faint" />
                    </button>
                  ))}
                </div>
              ) : (
                <p className="mt-3 text-[10px] text-faint">{t("soc.noEvents")}</p>
              )}
            </div>
          </div>
          <div className="space-y-4 lg:col-span-5">
            <div className="rounded-xl border border-line/60 bg-panel2/30 p-4">
              <h4 className="text-xs font-semibold text-ink">{t("soc.rule")}</h4>
              {data.rule ? (
                <div className="mt-2 space-y-2">
                  <p className="text-[10px] font-medium text-ink">{data.rule.name}</p>
                  <p className="text-[9px] leading-relaxed text-muted">{data.rule.description}</p>
                  <pre className="max-h-40 overflow-auto rounded-lg bg-bg/60 p-2 font-mono text-[8px] text-muted">{JSON.stringify(data.rule.definition, null, 2)}</pre>
                </div>
              ) : (
                <p className="mt-2 text-[10px] text-faint">—</p>
              )}
            </div>
            <div className="rounded-xl border border-line/60 bg-panel2/30 p-4">
              <h4 className="text-xs font-semibold text-ink">{t("soc.notes")}</h4>
              {notes.length ? (
                <div className="mt-2 space-y-2">
                  {notes.map((item, index) => (
                    <div key={index} className="rounded-lg border border-line/40 bg-panel/40 p-2">
                      <p className="text-[9px] text-muted">{item.note}</p>
                      <p className="mt-1 text-[8px] text-faint">{item.by} · {fromNow(item.at, lang)}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="mt-2 text-[10px] text-faint">{t("common.none")}</p>
              )}
              {canWrite ? (
                <div className="mt-3 space-y-2">
                  <Textarea value={note} onChange={(event) => setNote(event.target.value)} rows={3} placeholder={t("soc.notePlaceholder")} maxLength={1000} />
                  <Button
                    size="sm"
                    variant="secondary"
                    loading={updating}
                    disabled={!note.trim()}
                    onClick={() => {
                      onUpdate({ note: note.trim() });
                      setNote("");
                    }}
                  >
                    {t("soc.addNote")}
                  </Button>
                </div>
              ) : null}
            </div>
          </div>
        </div>
      )}
    </Modal>
  );
}

function IncidentDetailModal({
  open,
  onClose,
  data,
  loading,
  error,
  onRetry,
  onStatus,
  updating,
  onNote,
  noting,
  canWrite,
  onOpenAlert
}: {
  open: boolean;
  onClose: () => void;
  data?: IncidentDetailResponse;
  loading: boolean;
  error: unknown;
  onRetry: () => void;
  onStatus: (status: string) => void;
  updating: boolean;
  onNote: (body: string) => void;
  noting: boolean;
  canWrite: boolean;
  onOpenAlert: (id: string) => void;
}) {
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const [note, setNote] = useState("");
  const incident = data?.incident;

  return (
    <Modal
      open={open}
      onOpenChange={(next) => !next && onClose()}
      title={incident?.title || t("soc.incident")}
      description={
        incident ? (
          <span className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={incident.severity} />
            <StatusBadge status={incident.status} />
            <span className="text-[9px] text-faint">{t("soc.opened")} {fromNow(incident.opened_at, lang)}</span>
          </span>
        ) : undefined
      }
      icon={Siren}
      size="full"
      footer={
        incident ? (
          <>
            {canWrite ? (
              <Select value={incident.status} onChange={(event) => onStatus(event.target.value)} className="w-auto" disabled={updating}>
                {incidentStatuses.map((status) => (
                  <option key={status} value={status}>{t(`status.${status}`)}</option>
                ))}
              </Select>
            ) : null}
            <Button variant="secondary" onClick={onClose} className="ms-auto">{t("common.close")}</Button>
          </>
        ) : undefined
      }
    >
      {loading ? (
        <div className="space-y-3"><Skeleton className="h-24 rounded-xl" /><Skeleton className="h-56 rounded-xl" /></div>
      ) : error || !data || !incident ? (
        <EmptyState
          icon={AlertTriangle}
          title={t("common.errorTitle")}
          description={error instanceof Error ? error.message : t("common.errorDescription")}
          action={<Button variant="secondary" onClick={onRetry}>{t("common.retry")}</Button>}
        />
      ) : (
        <div className="grid gap-4 lg:grid-cols-12">
          <div className="space-y-4 lg:col-span-7">
            <div className="rounded-xl border border-line/60 bg-panel2/30 p-4">
              <h4 className="text-xs font-semibold text-ink">{t("soc.incidentSummary")}</h4>
              <p className="mt-2 whitespace-pre-wrap text-[10px] leading-relaxed text-muted">{incident.summary || t("common.noDescription")}</p>
              <dl className="mt-3 grid gap-3 sm:grid-cols-2">
                <KeyValue label={t("soc.incidentStatus")} value={<StatusBadge status={incident.status} />} />
                <KeyValue label={t("common.severity")} value={<SeverityBadge severity={incident.severity} />} />
                <KeyValue label={t("soc.opened")} value={formatDateTime(incident.opened_at, lang)} />
                <KeyValue label={t("common.closed")} value={formatDateTime(incident.closed_at, lang)} />
              </dl>
            </div>
            <div className="rounded-xl border border-line/60 bg-panel2/30 p-4">
              <h4 className="text-xs font-semibold text-ink">{t("soc.relatedEvents")} · {data.alerts.length}</h4>
              {data.alerts.length ? (
                <div className="mt-2 divide-y divide-line/40">
                  {data.alerts.map((alert) => (
                    <button key={alert.id} type="button" onClick={() => onOpenAlert(alert.id)} className="flex w-full items-center gap-2 py-2 text-start hover:text-accent2">
                      <SeverityBadge severity={alert.severity} />
                      <span className="min-w-0 flex-1 truncate text-[10px] text-ink">{alert.title}</span>
                      <StatusBadge status={alert.status} />
                      <ArrowUpRight className="h-3 w-3 text-faint" />
                    </button>
                  ))}
                </div>
              ) : (
                <p className="mt-2 text-[10px] text-faint">{t("soc.noAlerts")}</p>
              )}
            </div>
          </div>
          <div className="space-y-4 lg:col-span-5">
            <div className="rounded-xl border border-line/60 bg-panel2/30 p-4">
              <h4 className="text-xs font-semibold text-ink">{t("soc.timeline")}</h4>
              {data.timeline.length ? (
                <div className="mt-3 space-y-3">
                  {data.timeline.map((event) => (
                    <div key={event.id} className="relative border-s border-line/60 ps-3">
                      <span className="absolute -start-[3px] top-1 h-1.5 w-1.5 rounded-full bg-accent" />
                      <p className="text-[9px] text-muted">{event.body}</p>
                      <p className="mt-0.5 text-[8px] text-faint">{event.actor} · {fromNow(event.ts, lang)} · {event.kind}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="mt-2 text-[10px] text-faint">{t("common.none")}</p>
              )}
            </div>
            {canWrite ? (
              <div className="rounded-xl border border-line/60 bg-panel2/30 p-4">
                <h4 className="text-xs font-semibold text-ink">{t("soc.addNote")}</h4>
                <Textarea className="mt-2" value={note} onChange={(event) => setNote(event.target.value)} rows={3} placeholder={t("soc.notePlaceholder")} maxLength={8000} />
                <Button
                  size="sm"
                  variant="secondary"
                  className="mt-2"
                  loading={noting}
                  disabled={!note.trim()}
                  onClick={() => {
                    onNote(note.trim());
                    setNote("");
                  }}
                >
                  {t("soc.addNote")}
                </Button>
              </div>
            ) : null}
          </div>
        </div>
      )}
    </Modal>
  );
}

function EventModal({
  open,
  onClose,
  data,
  loading,
  error,
  onRetry
}: {
  open: boolean;
  onClose: () => void;
  data?: LogEvent;
  loading: boolean;
  error: unknown;
  onRetry: () => void;
}) {
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  return (
    <Modal
      open={open}
      onOpenChange={(next) => !next && onClose()}
      title={data?.event_type || t("soc.event")}
      description={data ? `${formatDateTime(data.ts || data.ingested_at, lang)} · ${data.src_ip || "—"}` : undefined}
      icon={FileSearch}
      size="lg"
      footer={<Button variant="secondary" onClick={onClose}>{t("common.close")}</Button>}
    >
      {loading ? (
        <Skeleton className="h-72 rounded-xl" />
      ) : error || !data ? (
        <EmptyState
          icon={AlertTriangle}
          title={t("common.errorTitle")}
          description={error instanceof Error ? error.message : t("common.errorDescription")}
          action={<Button variant="secondary" onClick={onRetry}>{t("common.retry")}</Button>}
        />
      ) : (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={data.severity} />
            {data.rule_hits.map((rule) => <Badge key={rule} tone="danger">{rule}</Badge>)}
          </div>
          <p className="rounded-xl border border-line/60 bg-panel2/30 p-3 text-[10px] leading-relaxed text-ink">{data.message || "—"}</p>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="rounded-xl border border-line/60 bg-panel2/30 p-3">
              <dl className="space-y-2.5">
                <KeyValue label={t("soc.time")} value={formatDateTime(data.ts || data.ingested_at, lang)} />
                <KeyValue label={t("soc.sourceIp")} value={data.src_ip || "—"} mono />
                <KeyValue label={t("soc.destinationIp")} value={data.dst_ip || "—"} mono />
                <KeyValue label={t("soc.method")} value={data.method || "—"} />
                <KeyValue label="URL" value={data.url || "—"} mono />
                <KeyValue label={t("soc.statusCode")} value={data.status_code ? String(data.status_code) : "—"} />
                <KeyValue label={t("common.source")} value={data.source_id || "—"} mono />
              </dl>
            </div>
            <div className="rounded-xl border border-line/60 bg-panel2/30 p-3">
              <h4 className="text-xs font-semibold text-ink">{t("soc.userAgent")}</h4>
              <p className="mt-2 break-all font-mono text-[9px] text-muted">{data.user_agent || "—"}</p>
              <h4 className="mt-4 text-xs font-semibold text-ink">{t("soc.fingerprint")}</h4>
              <p className="mt-2 break-all font-mono text-[9px] text-faint">{data.fingerprint || "—"}</p>
            </div>
          </div>
          <div>
            <h4 className="text-xs font-semibold text-ink">{t("soc.raw")}</h4>
            <pre className="mt-2 max-h-72 overflow-auto rounded-xl bg-bg/60 p-3 font-mono text-[9px] leading-relaxed text-muted">
              {JSON.stringify(data.raw || data.meta || {}, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </Modal>
  );
}

function RuleModal({
  open,
  onOpenChange,
  projectId,
  onCreated
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  projectId: string;
  onCreated: () => void;
}) {
  const { t } = useTranslation();
  const toast = useToast();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [definition, setDefinition] = useState(
    JSON.stringify(
      {
        match: "all",
        conditions: [{ field: "event_type", op: "eq", value: "auth_failure" }],
        group_by: ["src_ip"],
        threshold: 1,
        window_minutes: 30
      },
      null,
      2
    )
  );
  const [error, setError] = useState("");

  useEffect(() => {
    if (!open) return;
    setName("");
    setDescription("");
    setSeverity("medium");
    setError("");
  }, [open]);

  const create = useMutation({
    mutationFn: () => {
      let parsed: Record<string, unknown>;
      try {
        parsed = JSON.parse(definition);
      } catch {
        throw new Error(t("soc.invalidJson"));
      }
      return apiFetch<{ rule: DetectionRule }>(`/projects/${projectId}/soc/rules`, {
        method: "POST",
        body: { name: name.trim(), description: description.trim(), severity, enabled: true, definition: parsed }
      });
    },
    onSuccess: () => {
      toast.toast({ title: t("soc.ruleCreated"), variant: "success" });
      onCreated();
    },
    onError: (caught) => setError(errorMessage(caught))
  });

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title={t("soc.ruleBuilder")}
      description={t("soc.ruleBody")}
      icon={ShieldCheck}
      size="lg"
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>{t("common.cancel")}</Button>
          <Button icon={Plus} loading={create.isPending} disabled={!name.trim()} onClick={() => { setError(""); create.mutate(); }}>
            {t("common.create")}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label={t("soc.ruleName")} required>
          <Input value={name} onChange={(event) => setName(event.target.value)} maxLength={200} />
        </Field>
        <Field label={t("soc.ruleDescription")} hint={t("common.optional")}>
          <Textarea value={description} onChange={(event) => setDescription(event.target.value)} rows={2} maxLength={2000} />
        </Field>
        <Field label={t("soc.ruleSeverity")}>
          <Select value={severity} onChange={(event) => setSeverity(event.target.value)}>
            {["critical", "high", "medium", "low", "info"].map((option) => (
              <option key={option} value={option}>{t(`severity.${option}`)}</option>
            ))}
          </Select>
        </Field>
        <Field label={t("soc.ruleExpression")} hint={t("soc.ruleExpressionHint")} required>
          <Textarea value={definition} onChange={(event) => setDefinition(event.target.value)} rows={12} className="font-mono text-[10px]" spellCheck={false} />
        </Field>
        {error ? <InlineAlert tone="danger">{error}</InlineAlert> : null}
      </div>
    </Modal>
  );
}

function IncidentCreateModal({
  open,
  onOpenChange,
  projectId,
  onCreated
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  projectId: string;
  onCreated: (incident: Incident) => void;
}) {
  const { t } = useTranslation();
  const toast = useToast();
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [summary, setSummary] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    if (!open) return;
    setTitle("");
    setSeverity("medium");
    setSummary("");
    setError("");
  }, [open]);

  const create = useMutation({
    mutationFn: () =>
      apiFetch<{ incident: Incident; linked_alerts: number }>(`/projects/${projectId}/soc/incidents`, {
        method: "POST",
        body: { title: title.trim(), severity, summary: summary.trim() }
      }),
    onSuccess: (result) => {
      toast.toast({ title: t("soc.incidentCreated"), variant: "success" });
      onCreated(result.incident);
    },
    onError: (caught) => setError(errorMessage(caught))
  });

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title={t("soc.incidentTitle")}
      description={t("soc.incidentsSubtitle")}
      icon={Siren}
      size="md"
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>{t("common.cancel")}</Button>
          <Button icon={Siren} loading={create.isPending} disabled={title.trim().length < 3} onClick={() => { setError(""); create.mutate(); }}>
            {t("common.create")}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label={t("soc.incident")} required>
          <Input value={title} onChange={(event) => setTitle(event.target.value)} maxLength={300} />
        </Field>
        <Field label={t("common.severity")}>
          <Select value={severity} onChange={(event) => setSeverity(event.target.value)}>
            {["critical", "high", "medium", "low", "info"].map((option) => (
              <option key={option} value={option}>{t(`severity.${option}`)}</option>
            ))}
          </Select>
        </Field>
        <Field label={t("soc.incidentSummary")} hint={t("common.optional")}>
          <Textarea value={summary} onChange={(event) => setSummary(event.target.value)} rows={5} maxLength={8000} />
        </Field>
        {error ? <InlineAlert tone="danger">{error}</InlineAlert> : null}
      </div>
    </Modal>
  );
}
