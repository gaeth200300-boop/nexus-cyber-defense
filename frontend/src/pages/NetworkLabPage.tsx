import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  Boxes,
  CheckCircle2,
  Cpu,
  FileUp,
  Globe2,
  Network,
  Play,
  Radar,
  ScanLine,
  Server,
  ShieldAlert,
  ShieldCheck,
  Terminal
} from "lucide-react";
import { apiFetch } from "../lib/api";
import { cn, fromNow } from "../lib/utils";
import { useProject } from "../context/ProjectContext";
import { labelOf, useDocumentTitle, useMeta } from "../hooks";
import type { Lang, Paged, Scan } from "../types";
import { BarChart, DonutChart } from "../components/charts";
import { ScanComposer } from "../components/ScanComposer";
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
  Progress,
  Select,
  SeverityBadge,
  Skeleton,
  StatusBadge
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

const severityColors: Record<string, string> = {
  critical: "#f43f5e",
  high: "#fb923c",
  medium: "#f59e0b",
  low: "#38bdf8",
  info: "#64748b"
};

export default function NetworkLabPage() {
  return (
    <ProjectGate>
      <NetworkContent />
    </ProjectGate>
  );
}

function NetworkContent() {
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const { selectedProject, canWrite } = useProject();
  const meta = useMeta();
  const navigate = useNavigate();
  const projectId = selectedProject?.id || "";
  const [composerOpen, setComposerOpen] = useState(false);
  const [composerKind, setComposerKind] = useState("network_scan");
  const [q, setQ] = useState("");
  const [minSeverity, setMinSeverity] = useState("");
  const [limit, setLimit] = useState(25);
  const [offset, setOffset] = useState(0);
  useDocumentTitle(t("network.title"));

  const overview = useQuery({
    queryKey: ["asm-overview", projectId],
    queryFn: () => apiFetch<AsmOverview>(`/projects/${projectId}/asm/overview`),
    enabled: Boolean(projectId)
  });

  const exposure = useQuery({
    queryKey: ["asm-exposure", projectId, q, minSeverity, limit, offset],
    queryFn: () =>
      apiFetch<Paged<ExposureItem>>(`/projects/${projectId}/asm/exposure`, {
        query: { q, min_severity: minSeverity || undefined, limit, offset }
      }),
    enabled: Boolean(projectId)
  });

  const scans = useQuery({
    queryKey: ["network-scans", projectId],
    queryFn: () => apiFetch<Paged<Scan>>(`/projects/${projectId}/scans`, { query: { kind: "network_scan", limit: 8 } }),
    enabled: Boolean(projectId),
    refetchInterval: 5000
  });

  const data = overview.data;
  const services = exposure.data?.items || [];
  const totalServices = exposure.data?.total || 0;
  const networkScans = scans.data?.items || [];

  const riskData = useMemo(
    () =>
      ["critical", "high", "medium", "low", "info"].map((severity) => ({
        name: t(`severity.${severity}`),
        value: data?.assets.by_risk[severity] || 0,
        color: severityColors[severity]
      })),
    [data?.assets.by_risk, t]
  );

  const portLabels = (data?.services.top_ports || []).map((entry) => `${entry.port}/${entry.protocol}`);
  const portValues = (data?.services.top_ports || []).map((entry) => entry.count);
  const protocolData = useMemo(() => {
    const counts: Record<string, number> = {};
    (data?.services.top_ports || []).forEach((entry) => {
      counts[entry.protocol] = (counts[entry.protocol] || 0) + entry.count;
    });
    return Object.entries(counts).map(([key, value], index) => ({
      name: key.toUpperCase(),
      value,
      color: index === 0 ? "#8b5cf6" : "#22d3ee"
    }));
  }, [data?.services.top_ports]);

  const openComposer = (kind: string) => {
    setComposerKind(kind);
    setComposerOpen(true);
  };

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow={t("nav.network")}
        icon={Radar}
        title={t("network.title")}
        subtitle={t("network.subtitle")}
        actions={
          <>
            <Button variant="secondary" icon={FileUp} onClick={() => openComposer("pcap_analysis")} disabled={!canWrite}>
              PCAP
            </Button>
            <Button icon={Play} onClick={() => openComposer("network_scan")} disabled={!canWrite}>
              {t("network.newScan")}
            </Button>
          </>
        }
      />

      <InlineAlert
        tone={meta.data?.features.nmap_available ? "success" : "info"}
        icon={meta.data?.features.nmap_available ? ShieldCheck : Terminal}
        title={meta.data?.features.nmap_available ? t("network.nmapReady") : t("network.nmapMissing")}
      >
        {t("network.activeWarning")}
      </InlineAlert>

      <section className="grid grid-cols-2 gap-2.5 xl:grid-cols-4">
        {[
          { label: t("network.hosts"), value: data?.assets.total, icon: Boxes, tone: "text-accent" },
          { label: t("network.services"), value: data?.services.open, icon: Server, tone: "text-accent2" },
          { label: t("asm.monitored"), value: data?.assets.monitored, icon: Radar, tone: "text-emerald-300" },
          { label: t("asm.exposedServices"), value: data?.assets.with_open_findings, icon: ShieldAlert, tone: "text-rose-300" }
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
        <div className="grid gap-4 xl:grid-cols-12">
          <Card className="p-4 xl:col-span-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-xs font-semibold text-ink">{t("network.ports")}</h3>
                <p className="mt-0.5 text-[10px] text-muted">{t("network.servicesSubtitle")}</p>
              </div>
              <Cpu className="h-4 w-4 text-accent" />
            </div>
            {portLabels.length ? (
              <BarChart labels={portLabels} values={portValues} horizontal height={245} />
            ) : (
              <p className="py-16 text-center text-[10px] text-faint">{t("network.noServices")}</p>
            )}
          </Card>
          <Card className="p-4 xl:col-span-4">
            <h3 className="text-xs font-semibold text-ink">{t("network.risk")}</h3>
            <p className="mt-0.5 text-[10px] text-muted">{t("asm.riskAssets")}</p>
            {data?.assets.total ? (
              <DonutChart data={riskData} height={245} centerLabel={t("network.assets")} centerValue={data.assets.total} />
            ) : (
              <p className="py-16 text-center text-[10px] text-faint">{t("asm.noAssets")}</p>
            )}
          </Card>
          <Card className="p-4 xl:col-span-4">
            <h3 className="text-xs font-semibold text-ink">{t("network.protocols")}</h3>
            <p className="mt-0.5 text-[10px] text-muted">{t("network.servicesTitle")}</p>
            {protocolData.length ? (
              <DonutChart
                data={protocolData}
                height={245}
                centerLabel={t("network.ports")}
                centerValue={data?.services.open || 0}
              />
            ) : (
              <p className="py-16 text-center text-[10px] text-faint">{t("network.noServices")}</p>
            )}
          </Card>
        </div>
      )}

      <Card className="overflow-hidden">
        <div className="flex flex-wrap items-center gap-2 border-b border-line/60 p-3.5">
          <div className="min-w-0 flex-1">
            <h3 className="text-xs font-semibold text-ink">{t("network.servicesTitle")}</h3>
            <p className="mt-0.5 text-[10px] text-muted">{t("network.servicesSubtitle")}</p>
          </div>
          <Input
            value={q}
            onChange={(event) => {
              setQ(event.target.value);
              setOffset(0);
            }}
            placeholder={t("assets.searchPlaceholder")}
            className="w-auto min-w-[180px]"
          />
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
              <option key={severity} value={severity}>
                {t(`severity.${severity}`)}
              </option>
            ))}
          </Select>
          <span className="text-[9px] text-faint">{t("projects.total", { count: totalServices })}</span>
        </div>

        {exposure.isLoading ? (
          <div className="space-y-2 p-4">
            {[0, 1, 2, 3, 4].map((key) => (
              <Skeleton key={key} className="h-12 rounded-lg" />
            ))}
          </div>
        ) : exposure.isError ? (
          <EmptyState
            icon={AlertTriangle}
            title={t("common.errorTitle")}
            description={exposure.error instanceof Error ? exposure.error.message : t("common.errorDescription")}
          />
        ) : services.length === 0 ? (
          <EmptyState icon={Server} title={t("network.noServices")} description={t("network.servicesSubtitle")} />
        ) : (
          <>
            <div className="hidden md:block">
              <table className="w-full text-start text-[10px]">
                <thead>
                  <tr className="border-b border-line/60 bg-panel2/30 text-[9px] uppercase tracking-[0.08em] text-faint">
                    <th className="px-4 py-2.5 text-start font-medium">{t("network.host")}</th>
                    <th className="px-3 py-2.5 text-start font-medium">{t("network.port")}</th>
                    <th className="px-3 py-2.5 text-start font-medium">{t("network.service")}</th>
                    <th className="px-3 py-2.5 text-start font-medium">{t("network.product")}</th>
                    <th className="px-3 py-2.5 text-start font-medium">{t("common.severity")}</th>
                    <th className="px-3 py-2.5 text-start font-medium">{t("nav.findings")}</th>
                    <th className="px-3 py-2.5 text-start font-medium">{t("network.lastSeen")}</th>
                    <th className="px-3 py-2.5" />
                  </tr>
                </thead>
                <tbody className="divide-y divide-line/50">
                  {services.map((service) => (
                    <tr key={service.service_id} className="group transition hover:bg-panel2/40">
                      <td className="max-w-[260px] px-4 py-2.5">
                        <button
                          type="button"
                          onClick={() => navigate(`/assets?asset=${service.asset.id}`)}
                          className="truncate font-mono text-[10px] text-accent2 hover:underline"
                        >
                          {service.asset.value}
                        </button>
                        <p className="mt-0.5 text-[8px] text-faint">{service.asset.type}</p>
                      </td>
                      <td className="px-3 py-2.5 font-mono text-[10px] tabular-nums text-ink">
                        {service.port}/{service.protocol}
                      </td>
                      <td className="px-3 py-2.5">
                        <span className="flex items-center gap-1.5">
                          {service.name || "—"}
                          {Object.keys(service.tls || {}).length ? (
                            <span title={t("web.tls")}>
                              <ShieldCheck className="h-3 w-3 text-emerald-300" />
                            </span>
                          ) : null}
                        </span>
                      </td>
                      <td className="max-w-[220px] px-3 py-2.5 text-muted">
                        <span className="line-clamp-1">{[service.product, service.version].filter(Boolean).join(" ") || "—"}</span>
                      </td>
                      <td className="px-3 py-2.5">
                        <SeverityBadge severity={service.worst_severity} />
                      </td>
                      <td className={cn("px-3 py-2.5 font-mono tabular-nums", service.open_findings ? "text-rose-300" : "text-faint")}>
                        {service.open_findings}
                      </td>
                      <td className="whitespace-nowrap px-3 py-2.5 text-[9px] text-faint">{fromNow(service.last_seen_at, lang)}</td>
                      <td className="px-3 py-2.5 text-end">
                        <ArrowUpRight className="h-3 w-3 text-faint rtl:-scale-x-100" />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="divide-y divide-line/50 md:hidden">
              {services.map((service) => (
                <button
                  key={service.service_id}
                  type="button"
                  onClick={() => navigate(`/assets?asset=${service.asset.id}`)}
                  className="flex w-full items-center gap-3 p-3.5 text-start hover:bg-panel2/50"
                >
                  <Network className="h-4 w-4 shrink-0 text-accent2" />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate font-mono text-[10px] text-ink">
                      {service.asset.value}:{service.port}/{service.protocol}
                    </span>
                    <span className="mt-0.5 block text-[9px] text-faint">
                      {service.name || "—"} · {service.open_findings} {t("nav.findings")}
                    </span>
                  </span>
                  <SeverityBadge severity={service.worst_severity} />
                </button>
              ))}
            </div>
            <Pagination
              page={Math.floor(offset / limit) + 1}
              pageSize={limit}
              total={totalServices}
              onPageChange={(page) => setOffset((page - 1) * limit)}
              labels={{ previous: t("common.previous"), next: t("common.next"), page: t("common.page"), of: t("common.of") }}
            />
          </>
        )}
      </Card>

      <div className="grid gap-4 xl:grid-cols-12">
        <Card className="overflow-hidden xl:col-span-7">
          <div className="flex items-center justify-between border-b border-line/60 px-4 py-3">
            <div>
              <h3 className="text-xs font-semibold text-ink">{t("network.newTitle")}</h3>
              <p className="mt-0.5 text-[10px] text-muted">{t("scans.subtitle")}</p>
            </div>
            <Button size="sm" variant="ghost" onClick={() => navigate("/scans")}>
              {t("dashboard.viewAll")}
            </Button>
          </div>
          {networkScans.length ? (
            <div className="divide-y divide-line/50">
              {networkScans.map((scan) => (
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
                      {scan.target_count} {t("common.targets")} · {fromNow(scan.created_at, lang)}
                    </p>
                    {scan.status === "running" ? <Progress value={scan.progress} className="mt-1.5 h-1 w-40" /> : null}
                  </div>
                  <StatusBadge status={scan.status} />
                </button>
              ))}
            </div>
          ) : (
            <EmptyState icon={ScanLine} title={t("scans.emptyTitle")} description={t("scans.emptyBody")} />
          )}
        </Card>

        <Card className="p-4 xl:col-span-5">
          <h3 className="text-xs font-semibold text-ink">{t("asm.monitorsTitle")}</h3>
          <p className="mt-0.5 text-[10px] text-muted">{t("asm.monitorsBody")}</p>
          <div className="mt-3 space-y-2">
            <div className="flex items-center justify-between rounded-lg border border-line/50 bg-panel2/30 px-3 py-2">
              <span className="text-[10px] text-muted">{t("asm.monitored")}</span>
              <span className="font-mono text-[11px] text-ink">{data?.assets.monitored || 0}</span>
            </div>
            <div className="flex items-center justify-between rounded-lg border border-line/50 bg-panel2/30 px-3 py-2">
              <span className="text-[10px] text-muted">{t("asm.newLast7d")}</span>
              <span className="font-mono text-[11px] text-ink">{data?.assets.new_last_7d || 0}</span>
            </div>
            <div className="flex items-center justify-between rounded-lg border border-line/50 bg-panel2/30 px-3 py-2">
              <span className="text-[10px] text-muted">{t("asm.lastDiscovery")}</span>
              <span className="text-[10px] text-ink">
                {data?.coverage.last_discovery_at ? fromNow(data.coverage.last_discovery_at, lang) : t("common.never")}
              </span>
            </div>
            <div className="flex items-center justify-between rounded-lg border border-line/50 bg-panel2/30 px-3 py-2">
              <span className="text-[10px] text-muted">{t("asm.changes")}</span>
              <span className="font-mono text-[11px] text-ink">{data?.changes.unacknowledged || 0}</span>
            </div>
          </div>
          {data?.assets.new_last_7d ? (
            <Badge tone="info" className="mt-3">
              <Activity className="me-1 h-3 w-3" /> {t("network.hosts")}: {data.assets.new_last_7d}
            </Badge>
          ) : null}
          <Button
            variant="secondary"
            icon={ShieldCheck}
            className="mt-3 w-full"
            onClick={() => navigate("/asm")}
          >
            {t("asm.title")}
          </Button>
        </Card>
      </div>

      <ScanComposer
        open={composerOpen}
        onOpenChange={setComposerOpen}
        defaultKind={composerKind}
        kinds={composerKind === "pcap_analysis" ? ["pcap_analysis"] : ["network_scan"]}
      />
    </div>
  );
}
