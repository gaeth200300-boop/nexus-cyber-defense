import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import {
  Bug,
  ChevronDown,
  Download,
  Filter,
  Fingerprint,
  Search,
  ShieldCheck,
  SlidersHorizontal,
  X
} from "lucide-react";
import { apiFetch, downloadApiFile } from "../lib/api";
import { cn, formatNumber, fromNow } from "../lib/utils";
import { currentLang } from "../lib/i18n";
import { useProject } from "../context/ProjectContext";
import { useToast } from "../context/ToastContext";
import { labelOf, statusLabel, useDebouncedValue, useDocumentTitle, useMeta } from "../hooks";
import type { Finding, Lang, Paged, StatusMeta } from "../types";
import { FindingDrawer } from "../components/FindingDrawer";
import { ProjectGate } from "../components/common";
import {
  Badge,
  Button,
  Card,
  DataTable,
  EmptyState,
  Input,
  PageHeader,
  Pagination,
  Select,
  SeverityBadge,
  Skeleton,
  StatusBadge,
  type TableColumn
} from "../components/ui";

interface FindingsResponse extends Paged<Finding> {
  counts: {
    by_severity: Record<string, number>;
    by_status: Record<string, number>;
  };
}

const severities = ["critical", "high", "medium", "low", "info"] as const;

export default function FindingsPage() {
  return (
    <ProjectGate>
      <FindingsContent />
    </ProjectGate>
  );
}

function FindingsContent() {
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const { selectedProject } = useProject();
  const meta = useMeta();
  const toast = useToast();
  useDocumentTitle(t("findings.title"));
  const [params, setParams] = useSearchParams();
  const projectId = selectedProject?.id || "";

  const [q, setQ] = useState(params.get("q") || "");
  const debouncedQ = useDebouncedValue(q, 300);
  const [severity, setSeverity] = useState(params.get("severity") || "");
  const [status, setStatus] = useState(params.get("status") || "");
  const [category, setCategory] = useState(params.get("category") || "");
  const [confidence, setConfidence] = useState(params.get("confidence") || "");
  const [verified, setVerified] = useState(params.get("verified") || "");
  const [sort, setSort] = useState("severity");
  const [limit, setLimit] = useState(25);
  const [offset, setOffset] = useState(0);
  const [exporting, setExporting] = useState<"" | "csv" | "json">("");
  const selectedFinding = params.get("finding");
  const scanId = params.get("scan") || "";

  useEffect(() => {
    setOffset(0);
  }, [debouncedQ, severity, status, category, confidence, verified, scanId, sort, limit]);

  const query = useQuery({
    queryKey: ["findings", projectId, debouncedQ, severity, status, category, confidence, verified, scanId, sort, limit, offset],
    queryFn: () =>
      apiFetch<FindingsResponse>(`/projects/${projectId}/findings`, {
        query: {
          q: debouncedQ,
          severity,
          status,
          category,
          confidence,
          verified: verified === "" ? undefined : verified,
          scan_id: scanId || undefined,
          sort,
          limit,
          offset
        }
      }),
    enabled: Boolean(projectId)
  });

  const rows = query.data?.items || [];
  const counts = query.data?.counts.by_severity || {};
  const total = query.data?.total || 0;
  const confidenceOptions = meta.data?.constants.confidences || [];
  const categoryOptions = meta.data?.constants.finding_categories || [];

  const statusOptions = useMemo<StatusMeta[]>(
    () =>
      meta.data?.constants.finding_statuses || [
        { key: "open", labels: { ar: "مفتوحة", en: "Open" } },
        { key: "confirmed", labels: { ar: "مؤكدة", en: "Confirmed" } },
        { key: "fixed", labels: { ar: "مصلحة", en: "Fixed" } },
        { key: "accepted_risk", labels: { ar: "خطر مقبول", en: "Accepted risk" } },
        { key: "false_positive", labels: { ar: "إيجابية كاذبة", en: "False positive" } },
        { key: "duplicate", labels: { ar: "مكررة", en: "Duplicate" } }
      ],
    [meta.data]
  );

  const setFinding = (id: string | null) => {
    const next = new URLSearchParams(params);
    if (id) next.set("finding", id);
    else next.delete("finding");
    setParams(next, { replace: true });
  };

  const resetFilters = () => {
    setQ("");
    setSeverity("");
    setStatus("");
    setCategory("");
    setConfidence("");
    setVerified("");
    setSort("severity");
    setLimit(25);
    setOffset(0);
    if (scanId) {
      const next = new URLSearchParams(params);
      next.delete("scan");
      setParams(next, { replace: true });
    }
  };

  const clearScanFilter = () => {
    const next = new URLSearchParams(params);
    next.delete("scan");
    setParams(next, { replace: true });
  };

  const hasFilters = Boolean(q || severity || status || category || confidence || verified || scanId);

  const exportFindings = async (format: "csv" | "json") => {
    setExporting(format);
    try {
      await downloadApiFile(
        `/projects/${projectId}/findings/export?format=${format}&q=${encodeURIComponent(debouncedQ)}&severity=${encodeURIComponent(severity)}&status=${encodeURIComponent(status)}&category=${encodeURIComponent(category)}`,
        `nexus-findings.${format}`
      );
    } catch (error) {
      toast.toast({
        title: t("toasts.failed"),
        description: error instanceof Error ? error.message : t("common.errorDescription"),
        variant: "error"
      });
    } finally {
      setExporting("");
    }
  };

  const columns: TableColumn<Finding>[] = [
    {
      key: "finding",
      header: t("findings.title"),
      render: (finding) => (
        <div className="flex min-w-0 max-w-[480px] items-start gap-2.5">
          <span className={cn("mt-1.5 h-2 w-2 shrink-0 rounded-full", {
            "bg-rose-400": finding.severity === "critical",
            "bg-orange-400": finding.severity === "high",
            "bg-amber-400": finding.severity === "medium",
            "bg-sky-400": finding.severity === "low",
            "bg-slate-400": finding.severity === "info"
          })} />
          <div className="min-w-0">
            <p className="truncate text-[11px] font-medium text-ink">{finding.title}</p>
            <p className="mt-0.5 truncate font-mono text-[9px] text-faint">
              {finding.target}
              {finding.location ? ` · ${finding.location}` : ""}
            </p>
          </div>
        </div>
      )
    },
    {
      key: "severity",
      header: t("findings.severity"),
      render: (finding) => <SeverityBadge severity={finding.severity} />
    },
    {
      key: "cvss",
      header: t("findings.cvss"),
      className: "hidden md:table-cell",
      headerClassName: "hidden md:table-cell",
      render: (finding) => (
        <span className="font-mono text-[11px] tabular-nums text-ink">{finding.cvss_score ?? "—"}</span>
      )
    },
    {
      key: "status",
      header: t("findings.status"),
      render: (finding) => <StatusBadge status={finding.status} />
    },
    {
      key: "confidence",
      header: t("findings.confidence"),
      className: "hidden xl:table-cell",
      headerClassName: "hidden xl:table-cell",
      render: (finding) => (
        <div>
          <StatusBadge status={finding.confidence} label={labelOf(confidenceOptions, finding.confidence, lang)} />
          {finding.verified ? (
            <p className="mt-1 flex items-center gap-1 text-[9px] text-emerald-300">
              <ShieldCheck className="h-2.5 w-2.5" /> {t("findings.confidenceExact")}
            </p>
          ) : null}
        </div>
      )
    },
    {
      key: "cve",
      header: t("findings.cveOnly"),
      className: "hidden lg:table-cell",
      headerClassName: "hidden lg:table-cell",
      render: (finding) =>
        finding.cve ? (
          <span className="rounded border border-accent2/20 bg-accent2/5 px-1.5 py-0.5 font-mono text-[9px] text-accent2">
            {finding.cve}
          </span>
        ) : (
          <span className="text-[9px] text-faint">—</span>
        )
    },
    {
      key: "seen",
      header: t("findings.lastSeen"),
      render: (finding) => (
        <span className="whitespace-nowrap text-[10px] text-muted">{fromNow(finding.last_seen_at, lang)}</span>
      )
    }
  ];

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow={t("nav.security")}
        icon={Bug}
        title={t("findings.title")}
        subtitle={t("findings.subtitle")}
        actions={
          <>
            <Button
              variant="secondary"
              icon={Download}
              loading={exporting === "csv"}
              disabled={!rows.length || Boolean(exporting)}
              onClick={() => void exportFindings("csv")}
            >
              CSV
            </Button>
            <Button
              variant="secondary"
              icon={Download}
              loading={exporting === "json"}
              disabled={!rows.length || Boolean(exporting)}
              onClick={() => void exportFindings("json")}
            >
              JSON
            </Button>
          </>
        }
      />

      <section className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 xl:grid-cols-5">
        {severities.map((key) => {
          const active = severity === key;
          return (
            <button
              type="button"
              key={key}
              onClick={() => setSeverity(active ? "" : key)}
              className={cn(
                "surface-card relative overflow-hidden p-3.5 text-start transition hover:-translate-y-0.5 hover:border-accent/25",
                active && "border-accent/40 ring-1 ring-accent/20"
              )}
            >
              <div className="flex items-center justify-between">
                <span className="text-[9px] font-semibold uppercase tracking-[0.1em] text-muted">
                  {t(`severity.${key}`)}
                </span>
                <SeverityBadge severity={key} label=" " className="px-1.5" />
              </div>
              <p className="mt-2 font-display text-2xl font-semibold tabular-nums text-ink">
                {formatNumber(counts[key] || 0, lang)}
              </p>
              <div className="mt-2 h-1 overflow-hidden rounded-full bg-panel3">
                <div
                  className={cn("h-full rounded-full", {
                    "bg-rose-400": key === "critical",
                    "bg-orange-400": key === "high",
                    "bg-amber-400": key === "medium",
                    "bg-sky-400": key === "low",
                    "bg-slate-400": key === "info"
                  })}
                  style={{ width: `${total ? Math.min(100, ((counts[key] || 0) / Math.max(1, Object.values(counts).reduce((a, b) => a + b, 0))) * 100) : 0}%` }}
                />
              </div>
            </button>
          );
        })}
      </section>

      <Card className="overflow-hidden">
        <div className="flex flex-wrap items-center gap-2 border-b border-line/60 p-3.5">
          <div className="relative min-w-[220px] flex-1">
            <Search className="pointer-events-none absolute start-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-faint" />
            <Input
              value={q}
              onChange={(event) => setQ(event.target.value)}
              placeholder={t("findings.searchPlaceholder")}
              className="ps-9"
            />
            {q ? (
              <button
                type="button"
                onClick={() => setQ("")}
                className="absolute end-2.5 top-1/2 -translate-y-1/2 rounded p-0.5 text-faint hover:text-ink"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            ) : null}
          </div>
          <Select value={status} onChange={(event) => setStatus(event.target.value)} className="w-auto min-w-[130px]">
            <option value="">{t("findings.status")} · {t("common.all")}</option>
            {statusOptions.map((item) => (
              <option key={item.key} value={item.key}>
                {item.labels[lang]}
              </option>
            ))}
          </Select>
          <Select value={category} onChange={(event) => setCategory(event.target.value)} className="w-auto min-w-[140px]">
            <option value="">{t("findings.category")} · {t("common.all")}</option>
            {categoryOptions.map((item) => (
              <option key={item.key} value={item.key}>
                {item.labels[lang]}
              </option>
            ))}
          </Select>
          <Select value={confidence} onChange={(event) => setConfidence(event.target.value)} className="w-auto min-w-[125px]">
            <option value="">{t("findings.confidence")} · {t("common.all")}</option>
            {confidenceOptions.map((item) => (
              <option key={item.key} value={item.key}>
                {item.labels[lang]}
              </option>
            ))}
          </Select>
          <Select value={verified} onChange={(event) => setVerified(event.target.value)} className="w-auto min-w-[120px]">
            <option value="">{t("common.confidence")}</option>
            <option value="true">{t("findings.verifiedOnly")}</option>
            <option value="false">{t("findings.unverifiedOnly")}</option>
          </Select>
          <Select value={sort} onChange={(event) => setSort(event.target.value)} className="w-auto min-w-[120px]">
            <option value="severity">{t("findings.severity")} ↓</option>
            <option value="last_seen">{t("findings.lastSeen")} ↓</option>
            <option value="first_seen">{t("common.firstSeen")} ↓</option>
            <option value="cvss">{t("findings.cvss")} ↓</option>
            <option value="created">{t("common.created")} ↓</option>
          </Select>
          {hasFilters ? (
            <Button variant="ghost" size="sm" onClick={resetFilters} icon={X}>
              {t("common.clear")}
            </Button>
          ) : null}
        </div>

        <div className="flex items-center justify-between gap-2 border-b border-line/40 bg-panel2/20 px-4 py-2">
          <span className="flex items-center gap-1.5 text-[10px] text-faint">
            <SlidersHorizontal className="h-3 w-3" />
            {t("findings.total", { count: total })}
          </span>
          <span className="flex items-center gap-1.5 text-[10px] text-faint">
            <Filter className="h-3 w-3" />
            {severity ? t(`severity.${severity}`) : t("findings.severity")} · {status ? statusLabel(statusOptions, status, lang) : t("findings.status")}
          </span>
        </div>

        {query.isLoading ? (
          <div className="space-y-2 p-4">
            {[0, 1, 2, 3, 4].map((key) => (
              <Skeleton key={key} className="h-12 w-full rounded-lg" />
            ))}
          </div>
        ) : query.isError ? (
          <EmptyState
            icon={Bug}
            title={t("common.errorTitle")}
            description={query.error instanceof Error ? query.error.message : t("common.errorDescription")}
            action={
              <Button variant="secondary" onClick={() => void query.refetch()}>
                {t("common.retry")}
              </Button>
            }
          />
        ) : rows.length === 0 ? (
          <EmptyState
            icon={Fingerprint}
            title={hasFilters ? t("findings.noResults") : t("findings.emptyTitle")}
            description={hasFilters ? undefined : t("findings.emptyBody")}
            action={
              hasFilters ? (
                <Button variant="secondary" onClick={resetFilters}>
                  {t("common.clear")}
                </Button>
              ) : undefined
            }
          />
        ) : (
          <>
            <div className="hidden md:block">
              <DataTable
                columns={columns}
                rows={rows}
                rowKey={(finding) => finding.id}
                onRowClick={(finding) => setFinding(finding.id)}
              />
            </div>
            <div className="divide-y divide-line/50 md:hidden">
              {rows.map((finding) => (
                <button
                  key={finding.id}
                  type="button"
                  onClick={() => setFinding(finding.id)}
                  className="flex w-full items-start gap-3 p-3.5 text-start transition hover:bg-panel2/50"
                >
                  <span className={cn("mt-1 h-2 w-2 shrink-0 rounded-full", {
                    "bg-rose-400": finding.severity === "critical",
                    "bg-orange-400": finding.severity === "high",
                    "bg-amber-400": finding.severity === "medium",
                    "bg-sky-400": finding.severity === "low",
                    "bg-slate-400": finding.severity === "info"
                  })} />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-[11px] font-medium text-ink">{finding.title}</span>
                    <span className="mt-0.5 block truncate font-mono text-[9px] text-faint">{finding.target}</span>
                    <span className="mt-1.5 flex flex-wrap items-center gap-1.5">
                      <SeverityBadge severity={finding.severity} />
                      <StatusBadge status={finding.status} />
                      <span className="text-[9px] text-faint">{fromNow(finding.last_seen_at, lang)}</span>
                    </span>
                  </span>
                </button>
              ))}
            </div>
            <Pagination
              page={Math.floor(offset / limit) + 1}
              pageSize={limit}
              total={total}
              onPageChange={(page) => setOffset((page - 1) * limit)}
              labels={{ previous: t("common.previous"), next: t("common.next"), page: t("common.page"), of: t("common.of") }}
            />
          </>
        )}
      </Card>

      <FindingDrawer findingId={selectedFinding} open={Boolean(selectedFinding)} onOpenChange={(open) => !open && setFinding(null)} />
    </div>
  );
}
