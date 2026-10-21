import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import {
  Activity,
  ArrowUpRight,
  BellRing,
  Bug,
  CheckCircle2,
  Clock3,
  Database,
  FileCheck2,
  Gauge,
  Layers3,
  Play,
  Radar,
  ScanLine,
  Server,
  ShieldAlert,
  ShieldCheck,
  Siren,
  Sparkles,
  TrendingDown,
  TrendingUp
} from "lucide-react";
import { apiFetch } from "../lib/api";
import { cn, formatBytes, formatDate, formatDateTime, formatNumber, fromNow, percent } from "../lib/utils";
import { currentLang } from "../lib/i18n";
import { useAuth } from "../context/AuthContext";
import { useProject } from "../context/ProjectContext";
import { useDocumentTitle, useHealth } from "../hooks";
import type { DashboardData, Lang } from "../types";
import { ScanComposer } from "../components/ScanComposer";
import { DonutChart, TrendChart } from "../components/charts";
import { DataError, DataLoading, SectionCard } from "../components/common";
import {
  Badge,
  Button,
  Card,
  DataTable,
  EmptyState,
  PageHeader,
  SegmentedControl,
  SeverityBadge,
  Skeleton,
  StatCard,
  StatusBadge,
  type TableColumn
} from "../components/ui";

const severityColors: Record<string, string> = {
  critical: "#f43f5e",
  high: "#fb923c",
  medium: "#f59e0b",
  low: "#38bdf8",
  info: "#64748b"
};

const dayOptions = [7, 14, 30, 90] as const;

function uptime(seconds?: number) {
  if (!seconds) return "—";
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days) return `${days}d ${hours}h`;
  if (hours) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

export default function DashboardPage() {
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const navigate = useNavigate();
  const { user } = useAuth();
  const { setSelectedProject, selectedProject } = useProject();
  const [days, setDays] = useState<(typeof dayOptions)[number]>(14);
  const [composerOpen, setComposerOpen] = useState(false);
  const [composerKind, setComposerKind] = useState("web_vuln");
  useDocumentTitle(t("nav.dashboard"));

  const query = useQuery({
    queryKey: ["dashboard", days],
    queryFn: () => apiFetch<DashboardData>("/system/dashboard", { query: { days } }),
    refetchInterval: 30_000
  });
  const health = useHealth();

  const data = query.data;
  const openSeverity = data?.findings.by_severity || {};
  const openTotal = data?.findings.open_total || 0;

  const greet = () => {
    const hour = new Date().getHours();
    if (hour < 12) return t("dashboard.greetingMorning");
    if (hour < 18) return t("dashboard.greetingAfternoon");
    return t("dashboard.greetingEvening");
  };

  const trendLabels = useMemo(
    () =>
      (data?.trend.days || []).map((day) => {
        try {
          return new Intl.DateTimeFormat(lang === "ar" ? "ar-EG-u-nu-latn" : "en-GB", {
            day: "2-digit",
            month: "short"
          }).format(new Date(`${day}T00:00:00`));
        } catch {
          return day;
        }
      }),
    [data?.trend.days, lang]
  );

  const donutData = useMemo(
    () =>
      ["critical", "high", "medium", "low", "info"].map((severity) => ({
        name: t(`severity.${severity}`),
        value: openSeverity[severity] || 0,
        color: severityColors[severity]
      })),
    [openSeverity, t]
  );

  const openFor = (severity: string) =>
    navigate(`/findings?severity=${encodeURIComponent(severity)}&status=open`);

  const startScan = (kind: string) => {
    setComposerKind(kind);
    if (!selectedProject) {
      navigate("/projects?new=1");
      return;
    }
    setComposerOpen(true);
  };

  const openProjectEntity = (projectId: string, path: string) => {
    if (projectId) setSelectedProject(projectId);
    navigate(path);
  };

  const findingColumns: TableColumn<DashboardData["recent"]["findings"][number]>[] = [
    {
      key: "finding",
      header: t("findings.title"),
      render: (finding) => (
        <div className="min-w-0 max-w-[420px]">
          <p className="truncate font-medium text-ink">{finding.title}</p>
          <p className="mt-0.5 truncate font-mono text-[9px] text-faint">{finding.target || "—"}</p>
        </div>
      )
    },
    {
      key: "severity",
      header: t("common.severity"),
      render: (finding) => <SeverityBadge severity={finding.severity} />
    },
    {
      key: "project",
      header: t("common.project"),
      className: "hidden xl:table-cell",
      headerClassName: "hidden xl:table-cell",
      render: (finding) => <span className="text-[10px] text-muted">{finding.project_name || "—"}</span>
    },
    {
      key: "status",
      header: t("common.status"),
      className: "hidden md:table-cell",
      headerClassName: "hidden md:table-cell",
      render: (finding) => <StatusBadge status={finding.status} />
    },
    {
      key: "seen",
      header: t("common.lastSeen"),
      render: (finding) => <span className="whitespace-nowrap text-[10px]">{fromNow(finding.last_seen_at, lang)}</span>
    }
  ];

  const riskAssetColumns: TableColumn<DashboardData["risk"]["top_assets"][number]>[] = [
    {
      key: "asset",
      header: t("assets.title"),
      render: (asset) => (
        <div className="min-w-0">
          <p className="truncate font-mono text-[11px] font-medium text-ink">{asset.value}</p>
          <p className="mt-0.5 truncate text-[9px] text-faint">
            {asset.type} · {asset.project_name}
          </p>
        </div>
      )
    },
    {
      key: "risk",
      header: t("assets.risk"),
      render: (asset) => <SeverityBadge severity={asset.risk_severity} />
    },
    {
      key: "score",
      header: t("assets.riskScore"),
      render: (asset) => <span className="font-mono text-[11px] tabular-nums text-ink">{asset.risk_score}</span>
    }
  ];

  if (query.isLoading) {
    return (
      <div className="space-y-5">
        <Skeleton className="h-40 w-full rounded-2xl" />
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
          {[0, 1, 2, 3, 4].map((key) => (
            <Skeleton key={key} className="h-28 rounded-2xl" />
          ))}
        </div>
        <Skeleton className="h-80 rounded-2xl" />
      </div>
    );
  }

  if (query.isError || !data) {
    return (
      <DataError
        message={query.error instanceof Error ? query.error.message : undefined}
        onRetry={() => void query.refetch()}
      />
    );
  }

  const jobs = Object.values(data.jobs || {}).reduce((sum, value) => sum + Number(value || 0), 0);
  const healthOk = health.data?.status === "ok";

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow={t("app.commandCenter")}
        icon={Radar}
        title={`${greet()}${user?.full_name ? `، ${user.full_name.split(" ")[0]}` : ""}`}
        subtitle={t("dashboard.subtitle")}
        actions={
          <>
            <SegmentedControl
              value={String(days)}
              onChange={(value) => setDays(Number(value) as (typeof dayOptions)[number])}
              options={dayOptions.map((value) => ({ value: String(value), label: `${value}d` }))}
              size="sm"
            />
            <Button variant="secondary" icon={Bug} onClick={() => navigate("/findings?status=open")}>
              {t("dashboard.viewFindings")}
            </Button>
            <Button icon={Play} onClick={() => startScan("web_vuln")}>
              {t("dashboard.newAssessment")}
            </Button>
          </>
        }
      />

      <section className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-5">
        <StatCard
          label={t("dashboard.criticalOpen")}
          value={formatNumber(openSeverity.critical || 0, lang)}
          sub={t("dashboard.verified", { count: data.findings.verified_open })}
          icon={ShieldAlert}
          tone="danger"
          onClick={() => openFor("critical")}
        />
        <StatCard
          label={t("dashboard.highOpen")}
          value={formatNumber(openSeverity.high || 0, lang)}
          sub={t("dashboard.openFindings") + ` · ${data.findings.open_total}`}
          icon={Bug}
          tone="warning"
          onClick={() => openFor("high")}
        />
        <StatCard
          label={t("dashboard.assets")}
          value={formatNumber(data.assets.total, lang)}
          sub={`${formatNumber(data.assets.monitored, lang)} ${t("common.monitored")}`}
          icon={Server}
          tone="cyan"
          onClick={() => navigate("/assets")}
        />
        <StatCard
          label={t("dashboard.activeScans")}
          value={formatNumber(data.scans.active, lang)}
          sub={`${formatNumber(data.scans.completed_7d, lang)} ${t("scans.completed")} · 7d`}
          icon={ScanLine}
          tone="accent"
          onClick={() => navigate("/scans")}
          footer={
            data.scans.active > 0 ? (
              <span className="flex items-center gap-1.5 text-[9px] text-accent2">
                <span className="relative flex h-1.5 w-1.5">
                  <span className="absolute h-full w-full animate-ping rounded-full bg-accent2 opacity-70" />
                  <span className="relative h-1.5 w-1.5 rounded-full bg-accent2" />
                </span>
                {t("common.live")}
              </span>
            ) : undefined
          }
        />
        <StatCard
          label={t("dashboard.openAlerts")}
          value={formatNumber(data.soc.alerts_open, lang)}
          sub={`${formatNumber(data.soc.events_24h, lang)} ${t("soc.events24h")}`}
          icon={Siren}
          tone="danger"
          onClick={() => navigate("/soc?tab=alerts")}
        />
      </section>

      <section className="grid gap-4 xl:grid-cols-12">
        <SectionCard
          className="xl:col-span-8"
          title={t("dashboard.trendTitle")}
          subtitle={t("dashboard.trendSubtitle")}
          icon={TrendingUp}
          actions={
            <div className="flex items-center gap-3 text-[10px] text-muted">
              <span className="flex items-center gap-1.5">
                <span className="h-1.5 w-1.5 rounded-full bg-accent" />
                {t("dashboard.created")}
              </span>
              <span className="flex items-center gap-1.5">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                {t("dashboard.resolved")}
              </span>
            </div>
          }
          bodyClassName="px-2 pb-2 pt-4 sm:px-3"
        >
          <TrendChart
            labels={trendLabels}
            series={[
              { name: t("dashboard.created"), data: data.trend.findings_created, color: "#8b5cf6" },
              { name: t("dashboard.resolved"), data: data.trend.findings_resolved, color: "#34d399" }
            ]}
            height={278}
            showLegend={false}
          />
        </SectionCard>

        <SectionCard
          className="xl:col-span-4"
          title={t("dashboard.severityTitle")}
          subtitle={t("dashboard.severitySubtitle")}
          icon={Gauge}
          bodyClassName="p-2"
        >
          {openTotal > 0 ? (
            <>
              <DonutChart data={donutData} height={252} centerLabel={t("dashboard.openFindings")} centerValue={openTotal} />
              <div className="grid grid-cols-2 gap-1.5 px-2 pb-2">
                {["critical", "high", "medium", "low"].map((severity) => (
                  <button
                    key={severity}
                    type="button"
                    onClick={() => openFor(severity)}
                    className="flex items-center justify-between rounded-lg border border-line/50 bg-panel2/40 px-2.5 py-1.5 text-[10px] transition hover:border-accent/25 hover:text-ink"
                  >
                    <span className="flex items-center gap-1.5 text-muted">
                      <span className="h-1.5 w-1.5 rounded-full" style={{ background: severityColors[severity] }} />
                      {t(`severity.${severity}`)}
                    </span>
                    <span className="font-mono text-ink">{openSeverity[severity] || 0}</span>
                  </button>
                ))}
              </div>
            </>
          ) : (
            <EmptyState icon={CheckCircle2} title={t("dashboard.noFindings")} description={t("dashboard.noFindingsBody")} />
          )}
        </SectionCard>
      </section>

      <section className="grid gap-4 xl:grid-cols-12">
        <SectionCard
          className="xl:col-span-7"
          title={t("dashboard.topAssets")}
          subtitle={t("dashboard.topAssetsSubtitle")}
          icon={Server}
          actions={
            <Button size="sm" variant="ghost" onClick={() => navigate("/asm")}>
              {t("dashboard.viewAll")} <ArrowUpRight className="h-3.5 w-3.5" />
            </Button>
          }
        >
          {data.risk.top_assets.length ? (
            <DataTable
              columns={riskAssetColumns}
              rows={data.risk.top_assets.slice(0, 6)}
              rowKey={(asset) => asset.id}
              onRowClick={(asset) => openProjectEntity(asset.project_id, `/assets?asset=${asset.id}`)}
            />
          ) : (
            <EmptyState icon={Server} title={t("dashboard.noAssets")} description={t("assets.emptyBody")} />
          )}
        </SectionCard>

        <SectionCard
          className="xl:col-span-5"
          title={t("dashboard.socPulse")}
          subtitle={t("soc.subtitle")}
          icon={Siren}
          actions={
            <Button size="sm" variant="ghost" onClick={() => navigate("/soc")}>
              {t("common.open")} <ArrowUpRight className="h-3.5 w-3.5" />
            </Button>
          }
          bodyClassName="p-4 space-y-3"
        >
          <div className="grid grid-cols-2 gap-2">
            {[
              { label: t("dashboard.openAlerts"), value: data.soc.alerts_open, icon: BellRing, tone: "text-rose-300" },
              { label: t("dashboard.events24h"), value: data.soc.events_24h, icon: Activity, tone: "text-accent2" },
              { label: t("soc.openIncidents"), value: data.soc.incidents_open, icon: ShieldAlert, tone: "text-amber-300" },
              { label: t("soc.sources"), value: data.soc.sources, icon: Layers3, tone: "text-accent" }
            ].map((item) => (
              <div key={item.label} className="rounded-xl border border-line/60 bg-panel2/50 p-3">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[9px] uppercase tracking-[0.08em] text-faint">{item.label}</span>
                  <item.icon className={cn("h-3.5 w-3.5", item.tone)} />
                </div>
                <p className="mt-1.5 font-display text-xl font-semibold tabular-nums text-ink">
                  {formatNumber(item.value, lang)}
                </p>
              </div>
            ))}
          </div>
          <div className="rounded-xl border border-line/60 bg-panel2/30 p-3">
            <div className="flex items-center justify-between text-[10px]">
              <span className="font-medium text-ink">{t("dashboard.coverage")}</span>
              <span className="font-mono text-muted">
                {formatNumber(data.assets.monitored, lang)} / {formatNumber(data.assets.total, lang)}
              </span>
            </div>
            <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-panel3">
              <div
                className="h-full rounded-full bg-gradient-to-r from-accent to-accent2"
                style={{ width: `${percent(data.assets.monitored, data.assets.total)}%` }}
              />
            </div>
            <div className="mt-3 grid grid-cols-2 gap-2 text-[10px]">
              <div className="flex items-center justify-between">
                <span className="text-muted">{t("dashboard.services")}</span>
                <span className="font-mono text-ink">{data.services.open}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted">{t("dashboard.verified")}</span>
                <span className="font-mono text-ink">{data.findings.verified_open}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted">{t("dashboard.reportsReady")}</span>
                <span className="font-mono text-ink">{data.reports.ready}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted">{t("dashboard.jobs")}</span>
                <span className="font-mono text-ink">{jobs}</span>
              </div>
            </div>
          </div>
          {data.recent.alerts.length ? (
            <div className="space-y-1.5">
              {data.recent.alerts.slice(0, 3).map((alert) => (
                <button
                  key={alert.id}
                  type="button"
                  onClick={() => openProjectEntity(alert.project_id, `/soc?tab=alerts&alert=${alert.id}`)}
                  className="flex w-full items-center gap-2 rounded-lg border border-line/40 bg-panel2/30 px-2.5 py-2 text-start transition hover:border-accent/20 hover:bg-panel2/60"
                >
                  <SeverityBadge severity={alert.severity} />
                  <span className="min-w-0 flex-1 truncate text-[10px] text-ink">{alert.title}</span>
                  <span className="shrink-0 text-[9px] text-faint">{fromNow(alert.last_seen_at, lang)}</span>
                </button>
              ))}
            </div>
          ) : null}
        </SectionCard>
      </section>

      <section className="grid gap-4 xl:grid-cols-12">
        <SectionCard
          className="xl:col-span-8"
          title={t("dashboard.recentFindings")}
          subtitle={t("findings.subtitle")}
          icon={Bug}
          actions={
            <Button size="sm" variant="ghost" onClick={() => navigate("/findings")}>
              {t("dashboard.viewAll")} <ArrowUpRight className="h-3.5 w-3.5" />
            </Button>
          }
        >
          <DataTable
            columns={findingColumns}
            rows={data.recent.findings.slice(0, 6)}
            rowKey={(finding) => finding.id}
            onRowClick={(finding) => openProjectEntity(finding.project_id, `/findings?finding=${finding.id}`)}
            empty={<EmptyState icon={Bug} title={t("dashboard.noFindings")} description={t("dashboard.noFindingsBody")} />}
          />
        </SectionCard>

        <SectionCard
          className="xl:col-span-4"
          title={t("dashboard.recentScans")}
          icon={ScanLine}
          actions={
            <Button size="sm" variant="ghost" onClick={() => navigate("/scans")}>
              {t("dashboard.viewAll")}
            </Button>
          }
          bodyClassName="divide-y divide-line/50"
        >
          {data.recent.scans.length ? (
            data.recent.scans.slice(0, 5).map((scan) => (
              <button
                key={scan.id}
                type="button"
                onClick={() => openProjectEntity(scan.project_id, `/scans/${scan.id}`)}
                className="flex w-full items-start gap-3 px-4 py-3 text-start transition hover:bg-panel2/50"
              >
                <span
                  className={cn(
                    "mt-0.5 grid h-8 w-8 shrink-0 place-items-center rounded-lg border",
                    scan.status === "running"
                      ? "border-accent/25 bg-accent/10 text-accent"
                      : scan.status === "failed"
                        ? "border-rose-400/20 bg-rose-400/10 text-rose-300"
                        : "border-line bg-panel2 text-muted"
                  )}
                >
                  <ScanLine className="h-3.5 w-3.5" />
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-[11px] font-medium text-ink">{scan.name}</span>
                  <span className="mt-0.5 flex items-center gap-1.5 text-[9px] text-faint">
                    <span>{scan.project_name || "—"}</span>
                    <span>·</span>
                    <span>{fromNow(scan.created_at, lang)}</span>
                  </span>
                  {scan.status === "running" ? (
                    <span className="mt-1.5 block h-1 overflow-hidden rounded-full bg-panel3">
                      <span className="block h-full bg-gradient-to-r from-accent to-accent2" style={{ width: `${scan.progress}%` }} />
                    </span>
                  ) : null}
                </span>
                <StatusBadge status={scan.status} />
              </button>
            ))
          ) : (
            <EmptyState icon={ScanLine} title={t("dashboard.noScans")} description={t("scans.emptyBody")} />
          )}
        </SectionCard>
      </section>

      <section className="grid gap-4 xl:grid-cols-12">
        <SectionCard
          className="xl:col-span-8"
          title={t("dashboard.environment")}
          subtitle={`${data.scope.projects} ${t("nav.projects")} · ${t("dashboard.evidence") || "Evidence"}`}
          icon={Database}
          bodyClassName="grid gap-3 p-4 sm:grid-cols-2 lg:grid-cols-4"
        >
          <div className="rounded-xl border border-line/60 bg-panel2/40 p-3">
            <div className="flex items-center justify-between">
              <span className="text-[9px] uppercase tracking-wider text-faint">{t("dashboard.database")}</span>
              <Database className="h-3.5 w-3.5 text-accent2" />
            </div>
            <p className="mt-1.5 text-xs font-medium text-ink">{health.data?.database || "—"}</p>
            <p className="mt-0.5 text-[9px] text-faint">{health.data?.database_latency_ms ?? "—"} ms</p>
          </div>
          <div className="rounded-xl border border-line/60 bg-panel2/40 p-3">
            <div className="flex items-center justify-between">
              <span className="text-[9px] uppercase tracking-wider text-faint">{t("dashboard.worker")}</span>
              <Activity className="h-3.5 w-3.5 text-emerald-300" />
            </div>
            <p className="mt-1.5 text-xs font-medium text-ink">
              {health.data?.worker?.running ? t("common.live") : health.data?.worker?.mode || "—"}
            </p>
            <p className="mt-0.5 text-[9px] text-faint">
              {health.data?.worker?.mode || ""} {health.data?.worker?.concurrency ? `· ${health.data.worker.concurrency}` : ""}
            </p>
          </div>
          <div className="rounded-xl border border-line/60 bg-panel2/40 p-3">
            <div className="flex items-center justify-between">
              <span className="text-[9px] uppercase tracking-wider text-faint">{t("dashboard.uptime")}</span>
              <Clock3 className="h-3.5 w-3.5 text-amber-300" />
            </div>
            <p className="mt-1.5 text-xs font-medium text-ink">{uptime(health.data?.uptime_seconds)}</p>
            <p className="mt-0.5 text-[9px] text-faint">{health.data?.version || ""}</p>
          </div>
          <div className="rounded-xl border border-line/60 bg-panel2/40 p-3">
            <div className="flex items-center justify-between">
              <span className="text-[9px] uppercase tracking-wider text-faint">{t("common.status")}</span>
              <ShieldCheck className={cn("h-3.5 w-3.5", healthOk ? "text-emerald-300" : "text-amber-300")} />
            </div>
            <p className={cn("mt-1.5 text-xs font-medium", healthOk ? "text-emerald-300" : "text-amber-300")}>
              {health.data?.status || "—"}
            </p>
            <p className="mt-0.5 text-[9px] text-faint">{health.data?.environment || ""}</p>
          </div>
        </SectionCard>

        <SectionCard
          className="xl:col-span-4"
          title={t("dashboard.labs")}
          icon={Sparkles}
          actions={
            <Button size="sm" variant="ghost" onClick={() => navigate("/labs")}>
              {t("common.open")}
            </Button>
          }
          bodyClassName="grid grid-cols-2 gap-2 p-4"
        >
          {[
            { label: t("dashboard.labsRuns"), value: data.labs.runs },
            { label: t("dashboard.labsPassed"), value: data.labs.labs_passed },
            { label: t("dashboard.totalScore"), value: data.labs.total_score },
            { label: t("dashboard.achievements"), value: data.labs.achievements }
          ].map((item) => (
            <div key={item.label} className="rounded-xl border border-line/60 bg-panel2/40 p-3">
              <p className="text-[9px] uppercase tracking-wider text-faint">{item.label}</p>
              <p className="mt-1 font-display text-xl font-semibold tabular-nums text-ink">{formatNumber(item.value, lang)}</p>
            </div>
          ))}
          <p className="col-span-2 mt-1 flex items-center gap-1.5 text-[9px] text-faint">
            <CheckCircle2 className="h-3 w-3 text-emerald-400" />
            {t("common.poweredBy")} · {formatDateTime(data.generated_at, lang)}
          </p>
        </SectionCard>
      </section>

      <ScanComposer open={composerOpen} onOpenChange={setComposerOpen} defaultKind={composerKind} />
    </div>
  );
}
