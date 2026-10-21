import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import {
  AlertTriangle,
  CalendarDays,
  CheckCircle2,
  Clock3,
  Download,
  FileCode2,
  FileJson,
  FileText,
  FileType2,
  Filter,
  Layers3,
  Loader2,
  Plus,
  RefreshCw,
  ShieldCheck,
  Trash2
} from "lucide-react";
import { apiFetch, downloadApiFile, errorMessage } from "../lib/api";
import { cn, formatBytes, formatDateTime, fromNow } from "../lib/utils";
import { useProject } from "../context/ProjectContext";
import { useToast } from "../context/ToastContext";
import { useDocumentTitle, useMeta } from "../hooks";
import type { Lang, Paged, Report, Scan } from "../types";
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
  Progress,
  Select,
  Skeleton,
  StatusBadge,
  Textarea
} from "../components/ui";

interface ReportDetailResponse {
  report: Report;
  file_exists: boolean;
}

const formatIcon: Record<string, typeof FileText> = {
  html: FileCode2,
  pdf: FileType2,
  json: FileJson
};

export default function ReportsPage() {
  return (
    <ProjectGate>
      <ReportsContent />
    </ProjectGate>
  );
}

function ReportsContent() {
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const { selectedProject, canWrite, isProjectAdmin } = useProject();
  const meta = useMeta();
  const toast = useToast();
  const queryClient = useQueryClient();
  const projectId = selectedProject?.id || "";
  useDocumentTitle(t("reports.title"));

  const [kind, setKind] = useState("");
  const [format, setFormat] = useState("");
  const [status, setStatus] = useState("");
  const [limit] = useState(25);
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<Report | null>(null);
  const [actionError, setActionError] = useState("");

  useEffect(() => setOffset(0), [kind, format, status]);

  const reports = useQuery({
    queryKey: ["reports", projectId, kind, format, status, offset],
    queryFn: () =>
      apiFetch<Paged<Report>>(`/projects/${projectId}/reports`, {
        query: {
          kind: kind || undefined,
          status: status || undefined,
          limit,
          offset
        }
      }),
    enabled: Boolean(projectId),
    refetchInterval: (query) =>
      (query.state.data as Paged<Report> | undefined)?.items.some((report) => report.status === "generating") ? 3000 : false
  });

  const detail = useQuery({
    queryKey: ["report", projectId, selected],
    queryFn: () => apiFetch<ReportDetailResponse>(`/projects/${projectId}/reports/${selected}`),
    enabled: Boolean(projectId && selected)
  });

  const regenerate = useMutation({
    mutationFn: (reportId: string) =>
      apiFetch<{ report: Report; job_id: string | null }>(`/projects/${projectId}/reports/${reportId}/regenerate`, {
        method: "POST"
      }),
    onSuccess: async () => {
      toast.toast({ title: t("reports.generating"), variant: "success" });
      await queryClient.invalidateQueries({ queryKey: ["reports", projectId] });
      await queryClient.invalidateQueries({ queryKey: ["report", projectId] });
    },
    onError: (error) => toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" })
  });

  const remove = useMutation({
    mutationFn: (reportId: string) =>
      apiFetch<null>(`/projects/${projectId}/reports/${reportId}`, { method: "DELETE" }),
    onSuccess: async () => {
      toast.toast({ title: t("common.deleted"), variant: "success" });
      setDeleteTarget(null);
      setSelected(null);
      await queryClient.invalidateQueries({ queryKey: ["reports", projectId] });
    },
    onError: (error) => setActionError(errorMessage(error))
  });

  const rows = (reports.data?.items || []).filter((report) => !format || report.format === format);
  const formats = ["html", "pdf", "json"];
  const kindOptions = meta.data?.constants.report_kinds || [];
  const ready = rows.filter((report) => report.status === "ready").length;
  const active = rows.filter((report) => report.status === "generating").length;
  const failed = rows.filter((report) => report.status === "failed").length;

  const kindLabel = (value: string) => {
    const item = kindOptions.find((option) => option.key === value);
    return item ? (lang === "ar" ? item.labels.ar : item.labels.en) : value.replaceAll("_", " ");
  };

  const download = async (report: Report) => {
    try {
      await downloadApiFile(report.download_url);
      toast.toast({ title: t("reports.downloaded"), variant: "success" });
    } catch (error) {
      toast.toast({ title: t("reports.downloadError"), description: errorMessage(error), variant: "error" });
    }
  };

  const selectedReport = detail.data?.report;
  const summarySeverity = (selectedReport?.summary.severity_counts || {}) as Record<string, number>;

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow={t("nav.reports")}
        icon={FileText}
        title={t("reports.title")}
        subtitle={t("reports.subtitle")}
        actions={
          <Button icon={Plus} onClick={() => setCreateOpen(true)} disabled={!canWrite}>
            {t("reports.new")}
          </Button>
        }
      />

      <section className="grid grid-cols-2 gap-2.5 xl:grid-cols-4">
        {[
          { label: t("reports.title"), value: reports.data?.total ?? "—", icon: FileText, tone: "text-accent" },
          { label: t("reports.ready"), value: ready, icon: CheckCircle2, tone: "text-emerald-300" },
          { label: t("reports.generating"), value: active, icon: Loader2, tone: "text-amber-300" },
          { label: t("reports.error"), value: failed, icon: AlertTriangle, tone: "text-rose-300" }
        ].map((card) => (
          <div key={card.label} className="surface-card p-3.5">
            <div className="flex items-center justify-between">
              <span className="text-[9px] font-semibold uppercase tracking-[0.1em] text-muted">{card.label}</span>
              <card.icon className={cn("h-4 w-4", card.tone, card.icon === Loader2 && active ? "animate-spin" : "")} />
            </div>
            <p className="mt-2 font-display text-2xl font-semibold tabular-nums text-ink">{card.value}</p>
          </div>
        ))}
      </section>

      <Card className="overflow-hidden">
        <div className="flex flex-wrap items-center gap-2 border-b border-line/60 p-3.5">
          <div className="flex items-center gap-2 text-[10px] font-semibold text-ink">
            <Filter className="h-3.5 w-3.5 text-accent" /> {t("reports.filters")}
          </div>
          <Select value={kind} onChange={(event) => setKind(event.target.value)} className="w-auto">
            <option value="">{t("reports.allKinds")}</option>
            {kindOptions.map((option) => (
              <option key={option.key} value={option.key}>{lang === "ar" ? option.labels.ar : option.labels.en}</option>
            ))}
          </Select>
          <Select value={format} onChange={(event) => setFormat(event.target.value)} className="w-auto">
            <option value="">{t("reports.allFormats")}</option>
            {formats.map((item) => (
              <option key={item} value={item}>{item.toUpperCase()}</option>
            ))}
          </Select>
          <Select value={status} onChange={(event) => setStatus(event.target.value)} className="w-auto">
            <option value="">{t("common.status")} · {t("common.all")}</option>
            {["generating", "ready", "failed"].map((item) => (
              <option key={item} value={item}>{t(`status.${item}`)}</option>
            ))}
          </Select>
          <Button size="sm" variant="ghost" icon={RefreshCw} className="ms-auto" onClick={() => void reports.refetch()}>
            {t("common.refresh")}
          </Button>
        </div>

        {reports.isLoading ? (
          <div className="space-y-2 p-4">
            {[0, 1, 2, 3].map((key) => <Skeleton key={key} className="h-20 rounded-xl" />)}
          </div>
        ) : reports.isError ? (
          <EmptyState
            icon={AlertTriangle}
            title={t("common.errorTitle")}
            description={reports.error instanceof Error ? reports.error.message : t("common.errorDescription")}
            action={<Button variant="secondary" onClick={() => void reports.refetch()}>{t("common.retry")}</Button>}
          />
        ) : rows.length ? (
          <>
            <div className="divide-y divide-line/50">
              {rows.map((report) => {
                const Icon = formatIcon[report.format] || FileText;
                return (
                  <div key={report.id} className="group flex flex-wrap items-center gap-3 px-4 py-3.5 transition hover:bg-panel2/30">
                    <span className="grid h-10 w-10 shrink-0 place-items-center rounded-xl border border-line bg-panel2 text-accent2">
                      <Icon className="h-4.5 w-4.5" />
                    </span>
                    <button type="button" onClick={() => setSelected(report.id)} className="min-w-0 flex-1 text-start">
                      <div className="flex flex-wrap items-center gap-2">
                        <p className="truncate text-[11px] font-medium text-ink">{report.title}</p>
                        <StatusBadge status={report.status} />
                        <Badge tone="default">{report.format.toUpperCase()}</Badge>
                        <Badge tone="info">{kindLabel(report.kind)}</Badge>
                      </div>
                      <p className="mt-0.5 text-[9px] text-faint">
                        v{report.version} · {fromNow(report.created_at, lang)} · {report.size_bytes ? formatBytes(report.size_bytes) : "—"}
                        {report.period_from ? ` · ${formatDateTime(report.period_from, lang)}` : ""}
                        {report.period_to ? ` → ${formatDateTime(report.period_to, lang)}` : ""}
                      </p>
                      {report.error ? <p className="mt-1 line-clamp-1 text-[9px] text-rose-300">{report.error}</p> : null}
                    </button>
                    <div className="flex items-center gap-1.5">
                      {report.status === "ready" ? (
                        <Button size="sm" variant="secondary" icon={Download} onClick={() => void download(report)}>
                          {t("reports.download")}
                        </Button>
                      ) : report.status === "generating" ? (
                        <div className="w-24">
                          <Progress value={75} indeterminate className="h-1.5" />
                          <p className="mt-1 text-end text-[8px] text-faint">{t("reports.generating")}</p>
                        </div>
                      ) : (
                        <Button size="sm" variant="secondary" icon={RefreshCw} loading={regenerate.isPending && regenerate.variables === report.id} onClick={() => regenerate.mutate(report.id)} disabled={!canWrite}>
                          {t("common.retry")}
                        </Button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
            <Pagination
              page={Math.floor(offset / limit) + 1}
              pageSize={limit}
              total={reports.data?.total || 0}
              onPageChange={(page) => setOffset((page - 1) * limit)}
              labels={{ previous: t("common.previous"), next: t("common.next"), page: t("common.page"), of: t("common.of") }}
            />
          </>
        ) : (
          <EmptyState
            icon={FileText}
            title={t("reports.empty")}
            description={t("reports.emptyBody")}
            action={
              <Button icon={Plus} onClick={() => setCreateOpen(true)} disabled={!canWrite}>
                {t("reports.new")}
              </Button>
            }
          />
        )}
      </Card>

      <Modal
        open={Boolean(selected) && Boolean(selectedReport)}
        onOpenChange={(open) => !open && setSelected(null)}
        title={selectedReport?.title || t("reports.view")}
        description={
          selectedReport ? (
            <span className="flex flex-wrap items-center gap-2">
              <StatusBadge status={selectedReport.status} />
              <Badge tone="default">{selectedReport.format.toUpperCase()}</Badge>
              <Badge tone="info">{kindLabel(selectedReport.kind)}</Badge>
              <span className="text-[9px] text-faint">v{selectedReport.version}</span>
            </span>
          ) : undefined
        }
        icon={FileText}
        size="lg"
        footer={
          selectedReport ? (
            <>
              {selectedReport.status === "ready" ? (
                <Button icon={Download} onClick={() => void download(selectedReport)}>{t("reports.download")}</Button>
              ) : selectedReport.status === "failed" ? (
                <Button icon={RefreshCw} loading={regenerate.isPending} onClick={() => regenerate.mutate(selectedReport.id)} disabled={!canWrite}>
                  {t("common.retry")}
                </Button>
              ) : null}
              {isProjectAdmin ? (
                <Button variant="danger" size="sm" icon={Trash2} onClick={() => setDeleteTarget(selectedReport)} className="ms-auto">
                  {t("common.delete")}
                </Button>
              ) : null}
              <Button variant="secondary" onClick={() => setSelected(null)}>{t("common.close")}</Button>
            </>
          ) : undefined
        }
      >
        {detail.isLoading ? (
          <div className="space-y-3"><Skeleton className="h-20 rounded-xl" /><Skeleton className="h-40 rounded-xl" /></div>
        ) : detail.isError || !selectedReport ? (
          <EmptyState
            icon={AlertTriangle}
            title={t("common.errorTitle")}
            description={detail.error instanceof Error ? detail.error.message : t("common.errorDescription")}
            action={<Button variant="secondary" onClick={() => void detail.refetch()}>{t("common.retry")}</Button>}
          />
        ) : (
          <div className="space-y-4">
            {selectedReport.status === "generating" ? (
              <InlineAlert tone="info" title={t("reports.generatingTitle")}>{t("reports.generatingBody")}</InlineAlert>
            ) : null}
            {selectedReport.error ? (
              <InlineAlert tone="danger" title={t("reports.error")}>{selectedReport.error}</InlineAlert>
            ) : null}
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="rounded-xl border border-line/60 bg-panel2/30 p-3">
                <dl className="space-y-2.5">
                  <KeyValue label={t("reports.version")} value={String(selectedReport.version)} />
                  <KeyValue label={t("reports.format")} value={selectedReport.format.toUpperCase()} />
                  <KeyValue label={t("reports.kind")} value={kindLabel(selectedReport.kind)} />
                  <KeyValue label={t("reports.createdAt")} value={formatDateTime(selectedReport.created_at, lang)} />
                  <KeyValue label={t("reports.completedAt")} value={formatDateTime(selectedReport.completed_at, lang)} />
                </dl>
              </div>
              <div className="rounded-xl border border-line/60 bg-panel2/30 p-3">
                <dl className="space-y-2.5">
                  <KeyValue label={t("reports.size")} value={selectedReport.size_bytes ? formatBytes(selectedReport.size_bytes) : "—"} />
                  <KeyValue label="SHA-256" value={selectedReport.sha256 || "—"} mono />
                  <KeyValue label={t("reports.scans")} value={String(selectedReport.scan_ids.length)} />
                  <KeyValue label={t("reports.language")} value={String(selectedReport.options.lang || "—")} />
                  <KeyValue label={t("common.status")} value={<StatusBadge status={selectedReport.status} />} />
                </dl>
              </div>
            </div>

            {Object.keys(summarySeverity).length ? (
              <div className="rounded-xl border border-line/60 bg-panel2/30 p-3">
                <h4 className="text-xs font-semibold text-ink">{t("reports.summary")}</h4>
                <div className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-5">
                  {["critical", "high", "medium", "low", "info"].map((severity) => (
                    <div key={severity} className="rounded-lg border border-line/50 bg-panel/40 p-2">
                      <p className="text-[8px] uppercase tracking-wider text-faint">{t(`severity.${severity}`)}</p>
                      <p className="mt-0.5 font-display text-lg font-semibold tabular-nums text-ink">{summarySeverity[severity] || 0}</p>
                    </div>
                  ))}
                </div>
                <div className="mt-2 grid grid-cols-3 gap-2">
                  <KeyValue label={t("findings.title")} value={String(selectedReport.summary.findings || "—")} />
                  <KeyValue label={t("copilot.criticalHigh")} value={String(selectedReport.summary.critical_high || "—")} />
                  <KeyValue label={t("nav.assets")} value={String(selectedReport.summary.assets || "—")} />
                </div>
              </div>
            ) : null}

            {selectedReport.scan_ids.length ? (
              <div className="rounded-xl border border-line/60 bg-panel2/30 p-3">
                <h4 className="text-xs font-semibold text-ink">{t("reports.scans")}</h4>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {selectedReport.scan_ids.map((scanId) => (
                    <span key={scanId} className="rounded border border-line bg-panel px-2 py-1 font-mono text-[9px] text-muted">{scanId}</span>
                  ))}
                </div>
              </div>
            ) : null}
          </div>
        )}
      </Modal>

      <CreateReportModal
        open={createOpen}
        onOpenChange={setCreateOpen}
        projectId={projectId}
        lang={lang}
        onCreated={() => {
          setCreateOpen(false);
          void queryClient.invalidateQueries({ queryKey: ["reports", projectId] });
        }}
      />

      <Modal
        open={Boolean(deleteTarget)}
        onOpenChange={(open) => { if (!open) { setDeleteTarget(null); setActionError(""); } }}
        title={t("common.delete")}
        description={deleteTarget?.title}
        icon={Trash2}
        size="sm"
        footer={
          <>
            <Button variant="ghost" onClick={() => setDeleteTarget(null)}>{t("common.cancel")}</Button>
            <Button variant="danger" icon={Trash2} loading={remove.isPending} onClick={() => deleteTarget && remove.mutate(deleteTarget.id)}>
              {t("common.delete")}
            </Button>
          </>
        }
      >
        <p className="text-[11px] leading-relaxed text-muted">{t("reports.deleteBody")}</p>
        {actionError ? <InlineAlert tone="danger" className="mt-3">{actionError}</InlineAlert> : null}
      </Modal>
    </div>
  );
}

function CreateReportModal({
  open,
  onOpenChange,
  projectId,
  lang,
  onCreated
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  projectId: string;
  lang: Lang;
  onCreated: () => void;
}) {
  const { t, i18n } = useTranslation();
  const meta = useMeta();
  const toast = useToast();
  const [kind, setKind] = useState("technical");
  const [format, setFormat] = useState("html");
  const [title, setTitle] = useState("");
  const [reportLang, setReportLang] = useState<Lang>((i18n.language.startsWith("ar") ? "ar" : "en") as Lang);
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [scanIds, setScanIds] = useState<string[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!open) return;
    setKind("technical");
    setFormat("html");
    setTitle("");
    setReportLang((i18n.language.startsWith("ar") ? "ar" : "en") as Lang);
    setFrom("");
    setTo("");
    setScanIds([]);
    setError("");
  }, [open, i18n.language]);

  const scans = useQuery({
    queryKey: ["reports-scan-options", projectId],
    queryFn: () => apiFetch<Paged<Scan>>(`/projects/${projectId}/scans`, { query: { limit: 100, offset: 0 } }),
    enabled: Boolean(projectId && open)
  });

  const reportKinds = meta.data?.constants.report_kinds || [];
  const needsScans = kind === "comparison" || kind === "scan_summary";

  const create = useMutation({
    mutationFn: () => {
      if (kind === "comparison" && scanIds.length !== 2) throw new Error(t("reports.comparisonHint"));
      if (kind === "scan_summary" && !scanIds.length) throw new Error(t("reports.scanHint"));
      return apiFetch<{ report: Report; job_id: string | null }>(`/projects/${projectId}/reports`, {
        method: "POST",
        body: {
          kind,
          format,
          title: title.trim(),
          period_from: from ? new Date(`${from}T00:00:00`).toISOString() : null,
          period_to: to ? new Date(`${to}T23:59:59`).toISOString() : null,
          scan_ids: needsScans ? scanIds : [],
          options: {
            lang: reportLang,
            ...(kind === "comparison" && scanIds.length === 2 ? { scan_a: scanIds[0], scan_b: scanIds[1] } : {})
          }
        }
      });
    },
    onSuccess: () => {
      toast.toast({ title: t("reports.created"), variant: "success" });
      onCreated();
    },
    onError: (caught) => setError(errorMessage(caught))
  });

  const toggleScan = (scanId: string) => {
    setScanIds((current) => {
      if (current.includes(scanId)) return current.filter((id) => id !== scanId);
      if (kind === "comparison") return [...current.slice(-1), scanId];
      return [...current, scanId];
    });
  };

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title={t("reports.newTitle")}
      description={t("reports.subtitle")}
      icon={FileText}
      size="lg"
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>{t("common.cancel")}</Button>
          <Button icon={FileText} loading={create.isPending} onClick={() => { setError(""); create.mutate(); }}>
            {t("reports.generate")}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label={t("reports.kind")} required>
            <Select value={kind} onChange={(event) => { setKind(event.target.value); setScanIds([]); }}>
              {reportKinds.map((option) => (
                <option key={option.key} value={option.key}>{lang === "ar" ? option.labels.ar : option.labels.en}</option>
              ))}
            </Select>
          </Field>
          <Field label={t("reports.format")} required>
            <Select value={format} onChange={(event) => setFormat(event.target.value)}>
              <option value="html">HTML</option>
              <option value="pdf">PDF</option>
              <option value="json">JSON</option>
            </Select>
          </Field>
        </div>
        <Field label={t("reports.titleField")} hint={t("reports.titleHint")}>
          <Input value={title} onChange={(event) => setTitle(event.target.value)} maxLength={250} placeholder={t("reports.titleHint")} />
        </Field>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label={t("reports.language")}>
            <Select value={reportLang} onChange={(event) => setReportLang(event.target.value as Lang)}>
              <option value="ar">العربية</option>
              <option value="en">English</option>
            </Select>
          </Field>
          <div className="grid grid-cols-2 gap-2">
            <Field label={t("reports.periodFrom")}>
              <Input type="date" value={from} onChange={(event) => setFrom(event.target.value)} />
            </Field>
            <Field label={t("reports.periodTo")}>
              <Input type="date" value={to} onChange={(event) => setTo(event.target.value)} />
            </Field>
          </div>
        </div>

        {needsScans ? (
          <Field label={t("reports.scans")} hint={kind === "comparison" ? t("reports.comparisonHint") : t("reports.scansHint")} required>
            {scans.isLoading ? (
              <div className="space-y-1.5">{[0, 1, 2].map((key) => <Skeleton key={key} className="h-8 rounded-lg" />)}</div>
            ) : scans.data?.items.length ? (
              <div className="max-h-56 space-y-1.5 overflow-y-auto rounded-xl border border-line/60 bg-panel/40 p-2">
                {scans.data.items.map((scan) => {
                  const checked = scanIds.includes(scan.id);
                  return (
                    <label
                      key={scan.id}
                      className={cn(
                        "flex cursor-pointer items-center gap-2 rounded-lg border px-2.5 py-2 text-[10px] transition",
                        checked ? "border-accent/30 bg-accent/[0.06] text-ink" : "border-transparent text-muted hover:bg-panel2"
                      )}
                    >
                      <input
                        type={kind === "comparison" ? "checkbox" : "checkbox"}
                        checked={checked}
                        onChange={() => toggleScan(scan.id)}
                        className="h-3 w-3 accent-[rgb(var(--accent))]"
                      />
                      <span className="min-w-0 flex-1 truncate">{scan.name}</span>
                      <Badge tone="default">{scan.kind}</Badge>
                      <StatusBadge status={scan.status} />
                      <span className="font-mono text-[8px] text-faint">{formatDateTime(scan.created_at, lang)}</span>
                    </label>
                  );
                })}
              </div>
            ) : (
              <p className="rounded-lg border border-line/60 bg-panel/40 p-3 text-[10px] text-faint">{t("reports.noScans")}</p>
            )}
            {scanIds.length ? <p className="mt-1.5 text-[9px] text-faint">{scanIds.length} {t("common.selected")}</p> : null}
          </Field>
        ) : null}

        <InlineAlert tone="info" title={t("reports.groundedTitle")}>{t("reports.groundedBody")}</InlineAlert>
        {error ? <InlineAlert tone="danger">{error}</InlineAlert> : null}
      </div>
    </Modal>
  );
}
