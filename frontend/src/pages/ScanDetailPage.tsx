import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import {
  AlertTriangle,
  ArrowLeft,
  Ban,
  CheckCircle2,
  ChevronRight,
  CircleDot,
  Clock3,
  Cpu,
  FileWarning,
  Fingerprint,
  Gauge,
  Layers3,
  Play,
  RefreshCw,
  ScanLine,
  ShieldCheck,
  Square,
  Target,
  Terminal,
  Timer,
  UploadCloud,
  XCircle
} from "lucide-react";
import { apiFetch, errorMessage } from "../lib/api";
import { cn, formatDateTime, fromNow } from "../lib/utils";
import { labelOf, useDocumentTitle, useMeta } from "../hooks";
import { useProject } from "../context/ProjectContext";
import { useToast } from "../context/ToastContext";
import type { Job, Lang, Scan, ScanEvent } from "../types";
import { DonutChart } from "../components/charts";
import { ProjectGate } from "../components/common";
import {
  Badge,
  Button,
  Card,
  CopyButton,
  EmptyState,
  InlineAlert,
  KeyValue,
  PageHeader,
  Progress,
  SeverityBadge,
  Skeleton,
  StatusBadge,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger
} from "../components/ui";

interface ScanDetailResponse {
  scan: Scan;
  jobs: Job[];
}

interface EventsResponse {
  items: ScanEvent[];
  last_id: number;
  scan: Pick<Scan, "id" | "status" | "progress" | "phases" | "error">;
}

const activeStatuses = new Set(["queued", "running", "paused"]);
const terminalStatuses = new Set(["completed", "partial", "failed", "canceled"]);
const severityColors: Record<string, string> = {
  critical: "#f43f5e",
  high: "#fb923c",
  medium: "#f59e0b",
  low: "#38bdf8",
  info: "#64748b"
};

export default function ScanDetailPage() {
  return (
    <ProjectGate>
      <ScanDetailContent />
    </ProjectGate>
  );
}

function ScanDetailContent() {
  const { scanId = "" } = useParams();
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const { selectedProject, canWrite } = useProject();
  const meta = useMeta();
  const toast = useToast();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const projectId = selectedProject?.id || "";
  const [tab, setTab] = useState("overview");
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [lastId, setLastId] = useState(0);
  const logEndRef = useRef<HTMLDivElement | null>(null);
  const [followLogs, setFollowLogs] = useState(true);

  const detail = useQuery({
    queryKey: ["scan", projectId, scanId],
    queryFn: () => apiFetch<ScanDetailResponse>(`/projects/${projectId}/scans/${scanId}`),
    enabled: Boolean(projectId && scanId),
    refetchInterval: 4000
  });

  const scan = detail.data?.scan;
  const eventsQuery = useQuery({
    queryKey: ["scan-events", projectId, scanId, lastId],
    queryFn: () =>
      apiFetch<EventsResponse>(`/projects/${projectId}/scans/${scanId}/events`, {
        query: { after_id: lastId, limit: 400 }
      }),
    enabled: Boolean(projectId && scanId),
    refetchInterval: scan && activeStatuses.has(scan.status) ? 1800 : 8000
  });

  useEffect(() => {
    const incoming = eventsQuery.data?.items || [];
    if (!incoming.length) return;
    setEvents((current) => {
      const seen = new Set(current.map((event) => event.id));
      const merged = [...current, ...incoming.filter((event) => !seen.has(event.id))];
      return merged.sort((a, b) => a.id - b.id).slice(-1200);
    });
    setLastId((current) => Math.max(current, eventsQuery.data?.last_id || 0));
  }, [eventsQuery.data]);

  useEffect(() => {
    setEvents([]);
    setLastId(0);
  }, [scanId]);

  useEffect(() => {
    if (followLogs && tab === "events") {
      logEndRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
    }
  }, [events.length, followLogs, tab]);

  useDocumentTitle(scan?.name || t("scanDetail.title"));

  const cancelMutation = useMutation({
    mutationFn: () => apiFetch<{ canceled_jobs: number }>(`/projects/${projectId}/scans/${scanId}/cancel`, { method: "POST" }),
    onSuccess: async () => {
      toast.toast({ title: t("scanDetail.canceled"), variant: "success" });
      await queryClient.invalidateQueries({ queryKey: ["scan", projectId, scanId] });
      await queryClient.invalidateQueries({ queryKey: ["scans", projectId] });
    },
    onError: (error) => toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" })
  });

  const retryMutation = useMutation({
    mutationFn: () => apiFetch<{ scan: Scan }>(`/projects/${projectId}/scans/${scanId}/retry`, { method: "POST" }),
    onSuccess: async () => {
      toast.toast({ title: t("scanDetail.queued"), variant: "success" });
      setEvents([]);
      setLastId(0);
      await queryClient.invalidateQueries({ queryKey: ["scan", projectId, scanId] });
      await queryClient.invalidateQueries({ queryKey: ["scans", projectId] });
    },
    onError: (error) => toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" })
  });

  const severityData = useMemo(
    () =>
      ["critical", "high", "medium", "low", "info"].map((severity) => ({
        name: t(`severity.${severity}`),
        value: scan?.findings?.[severity] || 0,
        color: severityColors[severity]
      })),
    [scan?.findings, t]
  );
  const totalFindings = Object.values(scan?.findings || {}).reduce((sum, value) => sum + Number(value || 0), 0);

  const snapshotScopes = useMemo(() => {
    const scopes = scan?.authorization_snapshot?.scopes;
    return Array.isArray(scopes) ? (scopes as Record<string, unknown>[]) : [];
  }, [scan?.authorization_snapshot]);
  const decisions = useMemo(() => {
    const list = scan?.authorization_snapshot?.decisions;
    return Array.isArray(list) ? (list as Record<string, unknown>[]) : [];
  }, [scan?.authorization_snapshot]);
  const stats = useMemo(() => Object.entries(scan?.stats || {}).slice(0, 16), [scan?.stats]);

  if (detail.isLoading) {
    return (
      <div className="space-y-5">
        <Skeleton className="h-32 w-full rounded-2xl" />
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          {[0, 1, 2, 3].map((key) => (
            <Skeleton key={key} className="h-28 rounded-2xl" />
          ))}
        </div>
        <Skeleton className="h-96 rounded-2xl" />
      </div>
    );
  }

  if (detail.isError || !scan) {
    return (
      <div className="space-y-4">
        <Button variant="ghost" size="sm" icon={ArrowLeft} onClick={() => navigate("/scans")}>
          {t("common.back")}
        </Button>
        <Card className="p-2">
          <EmptyState
            icon={FileWarning}
            title={t("scanDetail.notFound")}
            description={detail.error instanceof Error ? detail.error.message : t("common.errorDescription")}
            action={
              <Button variant="secondary" onClick={() => void detail.refetch()}>
                {t("common.retry")}
              </Button>
            }
          />
        </Card>
      </div>
    );
  }

  const isActive = activeStatuses.has(scan.status);
  const isTerminal = terminalStatuses.has(scan.status);
  const finishedDuration =
    scan.started_at && scan.finished_at
      ? Math.max(0, new Date(scan.finished_at).getTime() - new Date(scan.started_at).getTime())
      : null;

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-2">
        <Button size="sm" variant="ghost" icon={ArrowLeft} onClick={() => navigate("/scans")}>
          {t("scans.title")}
        </Button>
        <ChevronRight className="h-3.5 w-3.5 text-faint rtl:rotate-180" />
        <span className="truncate text-[11px] text-muted">{scan.name}</span>
      </div>

      <PageHeader
        eyebrow={t("scanDetail.title")}
        icon={ScanLine}
        title={scan.name}
        subtitle={
          <span className="flex flex-wrap items-center gap-2">
            <span>{labelOf(meta.data?.constants.scan_kinds, scan.kind, lang)}</span>
            <span>·</span>
            <span>{labelOf(meta.data?.constants.scan_profiles, scan.profile, lang)}</span>
            <span>·</span>
            <span>{scan.engine}</span>
            {scan.engine_version ? <span className="font-mono text-[10px] text-faint">v{scan.engine_version}</span> : null}
          </span>
        }
        actions={
          <>
            {isActive && canWrite ? (
              <Button
                variant="danger"
                icon={Square}
                loading={cancelMutation.isPending}
                onClick={() => cancelMutation.mutate()}
              >
                {t("scanDetail.cancel")}
              </Button>
            ) : null}
            {isTerminal && canWrite ? (
              <Button
                variant="secondary"
                icon={RefreshCw}
                loading={retryMutation.isPending}
                onClick={() => retryMutation.mutate()}
              >
                {t("scanDetail.retry")}
              </Button>
            ) : null}
            <Button
              variant="secondary"
              icon={Target}
              onClick={() => navigate(`/findings?scan=${scan.id}`)}
            >
              {t("dashboard.viewFindings")}
            </Button>
          </>
        }
      />

      {scan.error ? (
        <InlineAlert tone={scan.status === "partial" ? "warning" : "danger"} title={t("scanDetail.failed")}>
          {scan.error}
        </InlineAlert>
      ) : null}
      {scan.cancel_requested && isActive ? (
        <InlineAlert tone="warning" title={t("scanDetail.canceled")}>
          {t("scanDetail.cancel")} · {t("common.live")}
        </InlineAlert>
      ) : null}

      <section className="grid gap-4 xl:grid-cols-12">
        <Card className="p-4 xl:col-span-8">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-4">
              <div
                className="relative grid h-24 w-24 shrink-0 place-items-center rounded-full"
                style={{
                  background: `conic-gradient(rgb(var(--accent)) ${Math.max(0, Math.min(100, scan.progress)) * 3.6}deg, rgb(var(--panel-3)) 0deg)`
                }}
              >
                <div className="grid h-[76px] w-[76px] place-items-center rounded-full bg-panel">
                  <div className="text-center">
                    <p className="font-display text-xl font-semibold tabular-nums text-ink">{scan.progress}%</p>
                    <p className="text-[8px] uppercase tracking-wider text-faint">{t("scanDetail.progress")}</p>
                  </div>
                </div>
              </div>
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <StatusBadge status={scan.status} />
                  {scan.cancel_requested ? <Badge tone="warning">{t("scanDetail.canceled")}</Badge> : null}
                </div>
                <p className="mt-2 text-xs text-muted">
                  {t("scanDetail.targetCount", { count: scan.target_count })} · {scan.target_count} {t("common.targets")}
                </p>
                <p className="mt-1 flex flex-wrap items-center gap-1.5 text-[10px] text-faint">
                  <Clock3 className="h-3 w-3" />
                  {fromNow(scan.created_at, lang)}
                  {finishedDuration !== null ? ` · ${Math.max(1, Math.round(finishedDuration / 1000))}s` : ""}
                  {isActive ? ` · ${t("common.live")}` : ""}
                </p>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-2 text-end">
              <div>
                <p className="text-[9px] uppercase tracking-wider text-faint">{t("scanDetail.findings")}</p>
                <p className="mt-1 font-display text-xl font-semibold tabular-nums text-ink">{totalFindings}</p>
              </div>
              <div>
                <p className="text-[9px] uppercase tracking-wider text-faint">{t("scanDetail.requestedBy")}</p>
                <p className="mt-1 max-w-28 truncate text-[10px] text-muted">{scan.requested_by || "—"}</p>
              </div>
            </div>
          </div>
          <div className="mt-4">
            <Progress
              value={scan.progress}
              tone={scan.status === "failed" ? "danger" : scan.status === "completed" ? "success" : "accent"}
              indeterminate={scan.status === "queued"}
            />
            <div className="mt-2 flex justify-between text-[9px] text-faint">
              <span>{formatDateTime(scan.started_at, lang) || "—"}</span>
              <span>{formatDateTime(scan.finished_at, lang) || (isActive ? t("common.live") : "—")}</span>
            </div>
          </div>

          <div className="mt-5 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
            <div className="rounded-xl border border-line/60 bg-panel2/40 p-3">
              <div className="flex items-center justify-between">
                <span className="text-[9px] uppercase tracking-wider text-faint">{t("scan.engine")}</span>
                <Cpu className="h-3.5 w-3.5 text-accent" />
              </div>
              <p className="mt-1.5 truncate text-[11px] font-medium text-ink">{scan.engine}</p>
            </div>
            <div className="rounded-xl border border-line/60 bg-panel2/40 p-3">
              <div className="flex items-center justify-between">
                <span className="text-[9px] uppercase tracking-wider text-faint">{t("scanDetail.duration")}</span>
                <Timer className="h-3.5 w-3.5 text-accent2" />
              </div>
              <p className="mt-1.5 text-[11px] font-medium text-ink">
                {finishedDuration !== null ? `${Math.max(1, Math.round(finishedDuration / 1000))}s` : "—"}
              </p>
            </div>
            <div className="rounded-xl border border-line/60 bg-panel2/40 p-3">
              <div className="flex items-center justify-between">
                <span className="text-[9px] uppercase tracking-wider text-faint">{t("scan.profile")}</span>
                <Gauge className="h-3.5 w-3.5 text-amber-300" />
              </div>
              <p className="mt-1.5 truncate text-[11px] font-medium text-ink">
                {labelOf(meta.data?.constants.scan_profiles, scan.profile, lang)}
              </p>
            </div>
            <div className="rounded-xl border border-line/60 bg-panel2/40 p-3">
              <div className="flex items-center justify-between">
                <span className="text-[9px] uppercase tracking-wider text-faint">{t("scan.events")}</span>
                <Terminal className="h-3.5 w-3.5 text-emerald-300" />
              </div>
              <p className="mt-1.5 font-mono text-[11px] font-medium text-ink">{events.length}</p>
            </div>
          </div>
        </Card>

        <Card className="xl:col-span-4">
          <div className="border-b border-line/60 px-4 py-3">
            <h3 className="text-xs font-semibold text-ink">{t("scanDetail.phases")}</h3>
            <p className="mt-0.5 text-[10px] text-muted">{t("scans.progress")}</p>
          </div>
          <div className="space-y-0 p-3">
            {scan.phases.length ? (
              scan.phases.map((phase, index) => {
                const phaseLabel = lang === "ar" ? phase.ar : phase.en;
                return (
                  <div key={phase.key} className="relative flex gap-3 pb-4 last:pb-0">
                    {index < scan.phases.length - 1 ? (
                      <span className="absolute start-[9px] top-5 h-full w-px bg-line" />
                    ) : null}
                    <span
                      className={cn(
                        "relative mt-0.5 grid h-5 w-5 shrink-0 place-items-center rounded-full border",
                        phase.status === "running"
                          ? "border-accent bg-accent/15 text-accent"
                          : phase.status === "done"
                            ? "border-emerald-400/30 bg-emerald-400/10 text-emerald-300"
                            : phase.status === "failed"
                              ? "border-rose-400/30 bg-rose-400/10 text-rose-300"
                              : "border-line bg-panel2 text-faint"
                      )}
                    >
                      {phase.status === "running" ? (
                        <CircleDot className="h-3 w-3 animate-pulse" />
                      ) : phase.status === "done" ? (
                        <CheckCircle2 className="h-3 w-3" />
                      ) : phase.status === "failed" ? (
                        <XCircle className="h-3 w-3" />
                      ) : (
                        <span className="h-1.5 w-1.5 rounded-full bg-current" />
                      )}
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center justify-between gap-2">
                        <p className="truncate text-[11px] font-medium text-ink">{phaseLabel}</p>
                        <span className="font-mono text-[9px] text-faint">{phase.progress}%</span>
                      </div>
                      <Progress
                        value={phase.progress}
                        className="mt-1 h-1"
                        tone={phase.status === "failed" ? "danger" : phase.status === "done" ? "success" : "accent"}
                      />
                    </div>
                  </div>
                );
              })
            ) : (
              <p className="py-6 text-center text-[10px] text-faint">{t("common.noneFound")}</p>
            )}
          </div>
        </Card>
      </section>

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="overview" icon={Layers3}>
            {t("scanDetail.summary")}
          </TabsTrigger>
          <TabsTrigger value="events" icon={Terminal} count={events.length}>
            {t("scanDetail.liveLog")}
          </TabsTrigger>
          <TabsTrigger value="targets" icon={Target} count={scan.target_count}>
            {t("scan.targetTitle")}
          </TabsTrigger>
          <TabsTrigger value="authorization" icon={ShieldCheck} count={snapshotScopes.length}>
            {t("scanDetail.authorization")}
          </TabsTrigger>
          <TabsTrigger value="jobs" icon={Cpu} count={detail.data?.jobs.length}>
            {t("dashboard.jobs")}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="mt-4 space-y-4">
          <div className="grid gap-4 lg:grid-cols-12">
            <Card className="p-4 lg:col-span-5">
              <h3 className="text-xs font-semibold text-ink">{t("scanDetail.findings")}</h3>
              <p className="mt-0.5 text-[10px] text-muted">{t("dashboard.severitySubtitle")}</p>
              {totalFindings > 0 ? (
                <DonutChart data={severityData} height={230} centerLabel={t("scanDetail.findings")} centerValue={totalFindings} />
              ) : (
                <EmptyState icon={Fingerprint} title={t("dashboard.noFindings")} description={t("dashboard.noFindingsBody")} />
              )}
            </Card>
            <Card className="p-4 lg:col-span-7">
              <h3 className="text-xs font-semibold text-ink">{t("scanDetail.stats")}</h3>
              <p className="mt-0.5 text-[10px] text-muted">{t("common.evidence")} · {t("common.engine")}</p>
              {stats.length ? (
                <dl className="mt-3 grid gap-2 sm:grid-cols-2">
                  {stats.map(([key, value]) => (
                    <div key={key} className="rounded-lg border border-line/50 bg-panel2/40 px-2.5 py-2">
                      <dt className="truncate text-[9px] uppercase tracking-wider text-faint">{key.replace(/_/g, " ")}</dt>
                      <dd className="mt-0.5 break-words font-mono text-[10px] text-ink">
                        {typeof value === "object" ? JSON.stringify(value) : String(value ?? "—")}
                      </dd>
                    </div>
                  ))}
                </dl>
              ) : (
                <EmptyState icon={Gauge} title={t("common.noneFound")} description={t("common.noneFound")} />
              )}
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="events" className="mt-4">
          <Card className="overflow-hidden">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line/60 bg-panel2/30 px-3.5 py-2.5">
              <div className="flex items-center gap-2 text-[10px] text-muted">
                <span className={cn("relative flex h-2 w-2", isActive && "text-accent2")}>
                  {isActive ? <span className="absolute h-full w-full animate-ping rounded-full bg-accent2 opacity-60" /> : null}
                  <span className={cn("relative h-2 w-2 rounded-full", isActive ? "bg-accent2" : "bg-slate-500")} />
                </span>
                {t("scanDetail.liveLog")}
                <span className="font-mono text-faint">{events.length}</span>
              </div>
              <div className="flex items-center gap-2">
                <Button size="sm" variant="ghost" onClick={() => setFollowLogs((value) => !value)}>
                  {followLogs ? t("common.live") : t("common.paused")}
                </Button>
                <Button size="sm" variant="ghost" icon={RefreshCw} onClick={() => void eventsQuery.refetch()}>
                  {t("common.refresh")}
                </Button>
              </div>
            </div>
            <div className="max-h-[520px] min-h-[240px] overflow-y-auto bg-[#060a12] p-3 font-mono text-[10px] leading-relaxed" dir="ltr">
              {events.length ? (
                <>
                  {events.map((event) => (
                    <div key={event.id} className="flex items-start gap-2 border-b border-white/[0.03] py-1 last:border-0">
                      <span className="w-16 shrink-0 text-right text-[9px] text-slate-600">
                        {new Date(event.ts).toLocaleTimeString(undefined, { hour12: false })}
                      </span>
                      <span
                        className={cn(
                          "w-14 shrink-0 rounded px-1 text-center text-[8px] font-semibold uppercase",
                          event.level === "error"
                            ? "bg-rose-500/15 text-rose-300"
                            : event.level === "warning"
                              ? "bg-amber-500/15 text-amber-300"
                              : event.level === "success"
                                ? "bg-emerald-500/15 text-emerald-300"
                                : "bg-slate-500/10 text-slate-400"
                        )}
                      >
                        {event.level}
                      </span>
                      <span className="w-28 shrink-0 truncate text-[9px] text-violet-300/80">{event.phase || event.kind}</span>
                      <span className="min-w-0 flex-1 whitespace-pre-wrap break-words text-slate-300">{event.message}</span>
                    </div>
                  ))}
                  <div ref={logEndRef} />
                </>
              ) : (
                <div className="flex h-48 flex-col items-center justify-center gap-2 text-center text-slate-500">
                  <Terminal className="h-7 w-7 opacity-40" />
                  <p>{t("scanDetail.noEvents")}</p>
                </div>
              )}
            </div>
          </Card>
        </TabsContent>

        <TabsContent value="targets" className="mt-4">
          <Card className="overflow-hidden">
            <div className="border-b border-line/60 px-4 py-3">
              <h3 className="text-xs font-semibold text-ink">{t("scan.targetTitle")}</h3>
              <p className="mt-0.5 text-[10px] text-muted">{t("projects.policyBody")}</p>
            </div>
            {scan.targets.length ? (
              <div className="divide-y divide-line/50">
                {scan.targets.map((target, index) => {
                  const value = String(target.value || target.host || target.url || JSON.stringify(target));
                  const decision = decisions.find((item) => item.host === (target.host || target.value));
                  const allowed = decision ? Boolean(decision.allowed) : true;
                  return (
                    <div key={`${value}-${index}`} className="flex flex-wrap items-center gap-3 px-4 py-3">
                      <span
                        className={cn(
                          "grid h-8 w-8 shrink-0 place-items-center rounded-lg border",
                          allowed ? "border-emerald-400/20 bg-emerald-400/10 text-emerald-300" : "border-rose-400/20 bg-rose-400/10 text-rose-300"
                        )}
                      >
                        {allowed ? <CheckCircle2 className="h-3.5 w-3.5" /> : <Ban className="h-3.5 w-3.5" />}
                      </span>
                      <div className="min-w-0 flex-1">
                        <p className="break-all font-mono text-[11px] text-ink">{value}</p>
                        <p className="mt-0.5 text-[9px] text-faint">
                          {String(target.type || "target")}
                          {target.port ? ` · :${target.port}` : ""}
                          {decision?.scope_value ? ` · ${String(decision.scope_value)}` : ""}
                        </p>
                      </div>
                      {decision?.reason ? (
                        <span className="rounded-md border border-line bg-panel2 px-2 py-1 text-[9px] text-muted">
                          {String(decision.reason)}
                        </span>
                      ) : null}
                    </div>
                  );
                })}
              </div>
            ) : (
              <EmptyState icon={Target} title={t("common.noneFound")} />
            )}
          </Card>
        </TabsContent>

        <TabsContent value="authorization" className="mt-4 space-y-4">
          <div className="grid gap-4 lg:grid-cols-2">
            <Card className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-xs font-semibold text-ink">{t("scanDetail.authorization")}</h3>
                  <p className="mt-0.5 text-[10px] text-muted">{t("projects.policyBody")}</p>
                </div>
                <ShieldCheck className="h-5 w-5 text-emerald-300" />
              </div>
              <div className="mt-3 space-y-2">
                {snapshotScopes.length ? (
                  snapshotScopes.map((scope, index) => (
                    <div key={String(scope.id || index)} className="rounded-lg border border-line/50 bg-panel2/40 p-2.5">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-[10px] text-ink">{String(scope.value || "—")}</span>
                        <Badge tone={scope.allow_active ? "warning" : "default"}>{String(scope.kind || "")}</Badge>
                        {scope.allow_active ? <Badge tone="warning">{t("projects.allowActive")}</Badge> : null}
                      </div>
                      <p className="mt-1 text-[9px] text-faint">
                        {String(scope.authorized_by || "")} {scope.authorization_ref ? `· ${String(scope.authorization_ref)}` : ""}
                      </p>
                    </div>
                  ))
                ) : (
                  <EmptyState icon={ShieldCheck} title={t("common.noneFound")} />
                )}
              </div>
            </Card>
            <Card className="p-4">
              <h3 className="text-xs font-semibold text-ink">{t("scanDetail.targets")}</h3>
              <p className="mt-0.5 text-[10px] text-muted">{t("projects.scopeNote")}</p>
              <div className="mt-3 space-y-1.5">
                {decisions.length ? (
                  decisions.map((decision, index) => (
                    <div key={index} className="flex items-center gap-2 rounded-lg border border-line/50 bg-panel2/30 px-2.5 py-1.5">
                      {decision.allowed ? (
                        <CheckCircle2 className="h-3 w-3 shrink-0 text-emerald-300" />
                      ) : (
                        <XCircle className="h-3 w-3 shrink-0 text-rose-300" />
                      )}
                      <span className="min-w-0 flex-1 truncate font-mono text-[9px] text-ink">{String(decision.host || "")}</span>
                      <span className="shrink-0 text-[8px] text-faint">{String(decision.reason || "")}</span>
                    </div>
                  ))
                ) : (
                  <p className="py-6 text-center text-[10px] text-faint">{t("common.noneFound")}</p>
                )}
              </div>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="jobs" className="mt-4">
          <Card className="overflow-hidden">
            <div className="border-b border-line/60 px-4 py-3">
              <h3 className="text-xs font-semibold text-ink">{t("dashboard.jobs")}</h3>
              <p className="mt-0.5 text-[10px] text-muted">{t("admin.jobsSubtitle")}</p>
            </div>
            {detail.data?.jobs.length ? (
              <div className="divide-y divide-line/50">
                {detail.data.jobs.map((job) => (
                  <div key={job.id} className="flex flex-wrap items-center gap-3 px-4 py-3">
                    <Cpu className="h-4 w-4 shrink-0 text-accent" />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <p className="font-mono text-[10px] text-ink">{job.type}</p>
                        <StatusBadge status={job.status} />
                      </div>
                      <p className="mt-0.5 text-[9px] text-faint">
                        {job.phase || "—"} · {t("admin.attempts")}: {job.attempts}/{job.max_attempts} · {fromNow(job.created_at, lang)}
                      </p>
                      {job.last_error ? <p className="mt-1 text-[9px] text-rose-300">{job.last_error}</p> : null}
                    </div>
                    <div className="w-24">
                      <Progress value={job.progress} className="h-1" tone={job.status === "failed" ? "danger" : "accent"} />
                      <p className="mt-1 text-end font-mono text-[8px] text-faint">{job.progress}%</p>
                    </div>
                    <CopyButton value={job.id} label="ID" />
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState icon={Cpu} title={t("admin.noJobs")} />
            )}
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
