import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQueries, useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import {
  AlertTriangle,
  ArrowUpRight,
  Bug,
  CheckCircle2,
  Cookie,
  ExternalLink,
  Eye,
  FileWarning,
  Fingerprint,
  Globe2,
  LockKeyhole,
  Play,
  Radar,
  ScanLine,
  ShieldCheck,
  Sparkles
} from "lucide-react";
import { apiFetch } from "../lib/api";
import { cn, fromNow } from "../lib/utils";
import { useProject } from "../context/ProjectContext";
import { labelOf, useDocumentTitle, useMeta } from "../hooks";
import type { Asset, Finding, Lang, Paged, Scan } from "../types";
import { DonutChart } from "../components/charts";
import { ScanComposer } from "../components/ScanComposer";
import { ProjectGate } from "../components/common";
import {
  Badge,
  Button,
  Card,
  EmptyState,
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

interface FindingsResponse extends Paged<Finding> {
  counts: { by_severity: Record<string, number>; by_status: Record<string, number> };
}

const webCategories = ["xss", "sqli", "csrf", "headers", "cookie", "tls", "exposure", "ssrf", "info_disclosure"] as const;
const severityColors: Record<string, string> = {
  critical: "#f43f5e",
  high: "#fb923c",
  medium: "#f59e0b",
  low: "#38bdf8",
  info: "#64748b"
};

export default function WebSecurityPage() {
  return (
    <ProjectGate>
      <WebSecurityContent />
    </ProjectGate>
  );
}

function WebSecurityContent() {
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const { selectedProject, canWrite } = useProject();
  const meta = useMeta();
  const navigate = useNavigate();
  const projectId = selectedProject?.id || "";
  const [tab, setTab] = useState("overview");
  const [composerOpen, setComposerOpen] = useState(false);
  useDocumentTitle(t("web.title"));

  const categoryQueries = useQueries({
    queries: webCategories.map((category) => ({
      queryKey: ["web-findings", projectId, category],
      queryFn: () =>
        apiFetch<FindingsResponse>(`/projects/${projectId}/findings`, {
          query: { category, limit: 10, sort: "last_seen" }
        }),
      enabled: Boolean(projectId)
    }))
  });

  const assetsQuery = useQuery({
    queryKey: ["web-assets", projectId],
    queryFn: () => apiFetch<Paged<Asset>>(`/projects/${projectId}/assets`, { query: { type: "url", limit: 100 } }),
    enabled: Boolean(projectId)
  });

  const scansQuery = useQuery({
    queryKey: ["web-scans", projectId],
    queryFn: () =>
      apiFetch<Paged<Scan>>(`/projects/${projectId}/scans`, {
        query: { limit: 50 }
      }),
    enabled: Boolean(projectId),
    refetchInterval: 5000
  });

  const isLoading = categoryQueries.some((query) => query.isLoading) || assetsQuery.isLoading || scansQuery.isLoading;
  const anyError = categoryQueries.find((query) => query.isError) || (assetsQuery.isError ? assetsQuery : null);

  const webFindings = useMemo(() => {
    const merged = categoryQueries.flatMap((query) => query.data?.items || []);
    const seen = new Set<string>();
    return merged
      .filter((finding) => {
        if (seen.has(finding.id)) return false;
        seen.add(finding.id);
        return true;
      })
      .sort((a, b) => new Date(b.last_seen_at).getTime() - new Date(a.last_seen_at).getTime());
  }, [categoryQueries]);

  const severityCounts = useMemo(() => {
    const result: Record<string, number> = {};
    categoryQueries.forEach((query) => {
      Object.entries(query.data?.counts.by_severity || {}).forEach(([severity, count]) => {
        result[severity] = (result[severity] || 0) + Number(count);
      });
    });
    return result;
  }, [categoryQueries]);

  const totalFindings = Object.values(severityCounts).reduce((sum, value) => sum + value, 0);
  const categoryTotals = useMemo(
    () => Object.fromEntries(webCategories.map((category, index) => [category, categoryQueries[index]?.data?.total || 0])),
    [categoryQueries]
  );

  const urlAssets = assetsQuery.data?.items || [];
  const webScans = useMemo(
    () => (scansQuery.data?.items || []).filter((scan) => ["web_vuln", "http_analysis"].includes(scan.kind)),
    [scansQuery.data]
  );
  const activeScans = webScans.filter((scan) => ["queued", "running"].includes(scan.status));
  const webServiceHints = useMemo(() => {
    const hints = new Map<string, number>();
    urlAssets.forEach((asset) => {
      Object.entries(asset.meta || {}).forEach(([key, value]) => {
        if (key.toLowerCase().includes("tech") || key === "server" || key === "framework") {
          hints.set(String(value), (hints.get(String(value)) || 0) + 1);
        }
      });
    });
    return Array.from(hints.entries()).sort((a, b) => b[1] - a[1]).slice(0, 8);
  }, [urlAssets]);

  const severityData = useMemo(
    () =>
      ["critical", "high", "medium", "low", "info"].map((severity) => ({
        name: t(`severity.${severity}`),
        value: severityCounts[severity] || 0,
        color: severityColors[severity]
      })),
    [severityCounts, t]
  );

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow={t("nav.web")}
        icon={Globe2}
        title={t("web.title")}
        subtitle={t("web.subtitle")}
        actions={
          <Button icon={Play} onClick={() => setComposerOpen(true)} disabled={!canWrite}>
            {t("web.newAssessment")}
          </Button>
        }
      />

      <section className="grid grid-cols-2 gap-2.5 xl:grid-cols-4">
        {[
          { label: t("web.assets"), value: assetsQuery.data?.total, icon: Globe2, tone: "text-accent" },
          { label: t("web.recentFindings"), value: totalFindings, icon: Bug, tone: "text-rose-300" },
          { label: t("web.tls"), value: categoryTotals.tls || 0, icon: LockKeyhole, tone: "text-amber-300" },
          { label: t("projects.activeScans"), value: activityValue(webScans), icon: ScanLine, tone: "text-accent2" }
        ].map((card) => (
          <div key={card.label} className="surface-card p-3.5">
            <div className="flex items-center justify-between">
              <span className="text-[9px] font-semibold uppercase tracking-[0.1em] text-muted">{card.label}</span>
              <card.icon className={cn("h-4 w-4", card.tone)} />
            </div>
            <p className="mt-2 font-display text-2xl font-semibold tabular-nums text-ink">
              {card.value === undefined || card.value === null ? "—" : card.value}
            </p>
            {card.label === t("projects.activeScans") && activeScans.length ? (
              <span className="mt-1 flex items-center gap-1 text-[9px] text-accent2">
                <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-accent2" /> {t("common.live")}
              </span>
            ) : null}
          </div>
        ))}
      </section>

      {anyError ? (
        <Card className="p-2">
          <EmptyState
            icon={AlertTriangle}
            title={t("common.errorTitle")}
            description={anyError.error instanceof Error ? anyError.error.message : t("common.errorDescription")}
            action={
              <Button variant="secondary" onClick={() => window.location.reload()}>
                {t("common.retry")}
              </Button>
            }
          />
        </Card>
      ) : null}

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="overview" icon={Eye}>
            {t("web.tabOverview")}
          </TabsTrigger>
          <TabsTrigger value="targets" icon={Globe2} count={assetsQuery.data?.total}>
            {t("web.tabTargets")}
          </TabsTrigger>
          <TabsTrigger value="methodology" icon={ShieldCheck}>
            {t("web.tabMethodology")}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="mt-4 space-y-4">
          <div className="grid gap-4 xl:grid-cols-12">
            <Card className="p-4 xl:col-span-5">
              <h3 className="text-xs font-semibold text-ink">{t("web.recentFindings")}</h3>
              <p className="mt-0.5 text-[10px] text-muted">{t("web.evidenceBody")}</p>
              {isLoading ? (
                <Skeleton className="mt-3 h-56 rounded-xl" />
              ) : totalFindings ? (
                <DonutChart data={severityData} height={250} centerLabel={t("web.recentFindings")} centerValue={totalFindings} />
              ) : (
                <EmptyState icon={ShieldCheck} title={t("dashboard.noFindings")} description={t("web.evidenceBody")} />
              )}
            </Card>
            <Card className="p-4 xl:col-span-7">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-xs font-semibold text-ink">{t("web.owasp")}</h3>
                  <p className="mt-0.5 text-[10px] text-muted">{t("web.headers")} · {t("web.cookie")} · {t("web.exposure")}</p>
                </div>
                <Sparkles className="h-4 w-4 text-accent2" />
              </div>
              <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-3">
                {[
                  ["headers", t("web.headers"), categoryTotals.headers],
                  ["cookie", t("web.cookie"), categoryTotals.cookie],
                  ["tls", t("web.tls"), categoryTotals.tls],
                  ["exposure", t("web.exposure"), categoryTotals.exposure],
                  ["xss", t("web.owasp"), categoryTotals.xss],
                  ["sqli", t("web.owasp"), categoryTotals.sqli]
                ].map(([key, label, value], index) => (
                  <button
                    key={key}
                    type="button"
                    onClick={() => navigate(`/findings?category=${key}`)}
                    className="rounded-xl border border-line/60 bg-panel2/40 p-3 text-start transition hover:border-accent/25"
                  >
                    <span className="text-[9px] uppercase tracking-[0.08em] text-faint">{label}</span>
                    <span className="mt-1.5 block font-display text-xl font-semibold tabular-nums text-ink">
                      {value === undefined ? "—" : value}
                    </span>
                    <span className="mt-1 block h-0.5 w-full overflow-hidden rounded-full bg-panel3">
                      <span
                        className={cn("block h-full rounded-full", index % 3 === 0 ? "bg-accent" : index % 3 === 1 ? "bg-accent2" : "bg-amber-300")}
                        style={{ width: `${totalFindings ? Math.min(100, (Number(value || 0) / Math.max(1, totalFindings)) * 100) : 0}%` }}
                      />
                    </span>
                  </button>
                ))}
              </div>
              <div className="mt-3 flex items-start gap-2 rounded-lg border border-line/50 bg-panel2/30 p-2.5">
                <Fingerprint className="mt-0.5 h-3 w-3 shrink-0 text-accent" />
                <p className="text-[9px] leading-relaxed text-faint">{t("web.evidenceBody")}</p>
              </div>
            </Card>
          </div>

          <div className="grid gap-4 xl:grid-cols-12">
            <Card className="overflow-hidden xl:col-span-8">
              <div className="flex items-center justify-between border-b border-line/60 px-4 py-3">
                <div>
                  <h3 className="text-xs font-semibold text-ink">{t("web.recentFindings")}</h3>
                  <p className="mt-0.5 text-[10px] text-muted">{t("dashboard.recentFindings")}</p>
                </div>
                <Button size="sm" variant="ghost" onClick={() => navigate("/findings")}>
                  {t("dashboard.viewAll")}
                </Button>
              </div>
              {isLoading ? (
                <div className="space-y-2 p-4">
                  {[0, 1, 2, 3, 4].map((key) => (
                    <Skeleton key={key} className="h-10 rounded-lg" />
                  ))}
                </div>
              ) : webFindings.length ? (
                <div className="divide-y divide-line/50">
                  {webFindings.slice(0, 8).map((finding) => (
                    <button
                      key={finding.id}
                      type="button"
                      onClick={() => navigate(`/findings?finding=${finding.id}`)}
                      className="flex w-full items-center gap-3 px-4 py-3 text-start transition hover:bg-panel2/50"
                    >
                      <span
                        className={cn("h-2 w-2 shrink-0 rounded-full", {
                          "bg-rose-400": finding.severity === "critical",
                          "bg-orange-400": finding.severity === "high",
                          "bg-amber-400": finding.severity === "medium",
                          "bg-sky-400": finding.severity === "low",
                          "bg-slate-400": finding.severity === "info"
                        })}
                      />
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-[11px] font-medium text-ink">{finding.title}</p>
                        <p className="mt-0.5 truncate font-mono text-[9px] text-faint">{finding.target}</p>
                      </div>
                      <span className="hidden text-[9px] text-faint sm:inline">{fromNow(finding.last_seen_at, lang)}</span>
                      <StatusBadge status={finding.status} />
                      <ArrowUpRight className="h-3 w-3 text-faint rtl:-scale-x-100" />
                    </button>
                  ))}
                </div>
              ) : (
                <EmptyState icon={Globe2} title={t("web.noScopes")} description={t("web.evidenceBody")} />
              )}
            </Card>
            <div className="space-y-4 xl:col-span-4">
              <Card className="p-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-semibold text-ink">{t("web.tech")}</h3>
                  <Radar className="h-4 w-4 text-accent2" />
                </div>
                {webServiceHints.length ? (
                  <div className="mt-3 space-y-1.5">
                    {webServiceHints.map(([hint, count]) => (
                      <div key={hint} className="flex items-center justify-between rounded-lg border border-line/50 bg-panel2/30 px-2.5 py-1.5">
                        <span className="truncate font-mono text-[9px] text-muted">{hint}</span>
                        <span className="text-[9px] text-faint">{count}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="py-5 text-center text-[10px] text-faint">{t("common.noneFound")}</p>
                )}
                <p className="mt-2 text-[9px] leading-relaxed text-faint">
                  {t("web.passiveBody")}
                </p>
              </Card>
              <Card className="p-4">
                <h3 className="text-xs font-semibold text-ink">{t("web.tlsGrade")}</h3>
                <div className="mt-3 flex items-center justify-between">
                  <div>
                    <p className="font-display text-2xl font-semibold tabular-nums text-ink">{categoryTotals.tls || 0}</p>
                    <p className="mt-0.5 text-[9px] text-faint">{t("web.tls")}</p>
                  </div>
                  <LockKeyhole className="h-8 w-8 text-amber-300/70" />
                </div>
                <Progress
                  value={totalFindings ? Math.min(100, ((categoryTotals.tls || 0) / Math.max(1, totalFindings)) * 100) : 0}
                  className="mt-3 h-1.5"
                  tone="warning"
                />
              </Card>
            </div>
          </div>
        </TabsContent>

        <TabsContent value="targets" className="mt-4 space-y-4">
          <div className="grid gap-4 xl:grid-cols-12">
            <Card className="overflow-hidden xl:col-span-7">
              <div className="flex items-center justify-between border-b border-line/60 px-4 py-3">
                <div>
                  <h3 className="text-xs font-semibold text-ink">{t("web.assets")}</h3>
                  <p className="mt-0.5 text-[10px] text-muted">{t("assets.subtitle")}</p>
                </div>
                <Button size="sm" variant="ghost" onClick={() => navigate("/assets")}>
                  {t("dashboard.viewAll")}
                </Button>
              </div>
              {urlAssets.length ? (
                <div className="divide-y divide-line/50">
                  {urlAssets.slice(0, 12).map((asset) => (
                    <button
                      key={asset.id}
                      type="button"
                      onClick={() => navigate(`/assets?asset=${asset.id}`)}
                      className="flex w-full items-center gap-3 px-4 py-3 text-start transition hover:bg-panel2/50"
                    >
                      <Globe2 className="h-4 w-4 shrink-0 text-accent2" />
                      <div className="min-w-0 flex-1">
                        <p className="truncate font-mono text-[10px] text-ink">{asset.value}</p>
                        <p className="mt-0.5 text-[9px] text-faint">
                          {asset.services_count || 0} {t("assets.services")} · {asset.open_findings || 0} {t("nav.findings")}
                        </p>
                      </div>
                      <Badge tone={asset.state === "active" ? "success" : "default"}>{asset.state}</Badge>
                    </button>
                  ))}
                </div>
              ) : (
                <EmptyState icon={Globe2} title={t("assets.emptyTitle")} description={t("assets.emptyBody")} />
              )}
            </Card>
            <Card className="overflow-hidden xl:col-span-5">
              <div className="border-b border-line/60 px-4 py-3">
                <h3 className="text-xs font-semibold text-ink">{t("web.newAssessment")}</h3>
                <p className="mt-0.5 text-[10px] text-muted">{t("scans.subtitle")}</p>
              </div>
              {webScans.length ? (
                <div className="divide-y divide-line/50">
                  {webScans.slice(0, 8).map((scan) => (
                    <button
                      key={scan.id}
                      type="button"
                      onClick={() => navigate(`/scans/${scan.id}`)}
                      className="flex w-full items-center gap-3 px-4 py-3 text-start transition hover:bg-panel2/50"
                    >
                      <ScanLine className="h-4 w-4 shrink-0 text-accent" />
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-[10px] font-medium text-ink">{scan.name}</p>
                        <p className="mt-0.5 text-[9px] text-faint">
                          {labelOf(meta.data?.constants.scan_kinds, scan.kind, lang)} · {fromNow(scan.created_at, lang)}
                        </p>
                      </div>
                      <StatusBadge status={scan.status} />
                    </button>
                  ))}
                </div>
              ) : (
                <EmptyState icon={ScanLine} title={t("scans.emptyTitle")} description={t("scans.emptyBody")} />
              )}
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="methodology" className="mt-4">
          <div className="grid gap-4 lg:grid-cols-3">
            {[
              { icon: Eye, title: t("web.passiveTitle"), body: t("web.passiveBody"), tone: "text-accent2" },
              { icon: ShieldCheck, title: t("web.activeTitle"), body: t("web.activeBody"), tone: "text-amber-300" },
              { icon: Fingerprint, title: t("web.evidenceTitle"), body: t("web.evidenceBody"), tone: "text-emerald-300" }
            ].map((item) => (
              <Card key={item.title} className="p-4">
                <item.icon className={cn("h-5 w-5", item.tone)} />
                <h3 className="mt-3 text-xs font-semibold text-ink">{item.title}</h3>
                <p className="mt-1.5 text-[10px] leading-relaxed text-muted">{item.body}</p>
              </Card>
            ))}
          </div>
          <Card className="mt-4 p-4">
            <div className="flex flex-wrap items-center gap-2">
              <span className="flex items-center gap-1.5 text-[11px] font-medium text-ink">
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-300" /> {t("projects.policyTitle")}
              </span>
              <span className="text-[10px] text-muted">{t("projects.policyBody")}</span>
            </div>
            <div className="mt-3 flex flex-wrap items-center gap-2 text-[9px] text-faint">
              <FileWarning className="h-3 w-3" />
              <span>{t("scan.authAck")}</span>
              <span>·</span>
              <ExternalLink className="h-3 w-3" />
              <span>{t("web.evidenceTitle")}</span>
            </div>
          </Card>
        </TabsContent>
      </Tabs>

      <ScanComposer
        open={composerOpen}
        onOpenChange={setComposerOpen}
        defaultKind="web_vuln"
        kinds={["web_vuln", "http_analysis"]}
      />
    </div>
  );
}

function activityValue(scans: Scan[]): number {
  return scans.filter((scan) => ["queued", "running"].includes(scan.status)).length;
}
