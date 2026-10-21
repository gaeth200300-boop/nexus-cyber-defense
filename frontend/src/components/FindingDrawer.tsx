import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  Bug,
  CheckCircle2,
  Clock3,
  Download,
  ExternalLink,
  FileSearch,
  Fingerprint,
  Link2,
  LockKeyhole,
  ScanLine,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Target
} from "lucide-react";
import { apiFetch, errorMessage } from "../lib/api";
import { cn, formatDateTime, fromNow, severityDot } from "../lib/utils";
import { useProject } from "../context/ProjectContext";
import { useToast } from "../context/ToastContext";
import { labelOf, statusLabel, useMeta } from "../hooks";
import type { FindingDetail, Lang } from "../types";
import {
  Button,
  CopyButton,
  DataTable,
  EmptyState,
  Field,
  KeyValue,
  Modal,
  Progress,
  Select,
  SeverityBadge,
  Skeleton,
  StatusBadge,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
  Textarea,
  Tooltip,
  type TableColumn
} from "./ui";

export function FindingDrawer({
  findingId,
  open,
  onOpenChange
}: {
  findingId: string | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const queryClient = useQueryClient();
  const toast = useToast();
  const navigate = useNavigate();
  const { selectedProject, canWrite } = useProject();
  const meta = useMeta();
  const projectId = selectedProject?.id || "";
  const [tab, setTab] = useState("overview");
  const [status, setStatus] = useState("open");
  const [note, setNote] = useState("");
  const [triageNote, setTriageNote] = useState("");

  const detail = useQuery({
    queryKey: ["finding", projectId, findingId],
    queryFn: () => apiFetch<FindingDetail>(`/projects/${projectId}/findings/${findingId}`),
    enabled: open && Boolean(projectId && findingId)
  });

  useEffect(() => {
    if (!open) return;
    setTab("overview");
    setNote("");
  }, [open, findingId]);

  useEffect(() => {
    if (!detail.data) return;
    setStatus(detail.data.finding.status);
    setTriageNote(detail.data.finding.triage_note || "");
  }, [detail.data]);

  const update = useMutation({
    mutationFn: () =>
      apiFetch<{ finding: FindingDetail["finding"] }>(
        `/projects/${projectId}/findings/${findingId}`,
        {
          method: "PATCH",
          body: {
            status,
            note: note.trim(),
            triage_note: triageNote
          }
        }
      ),
    onSuccess: async () => {
      toast.toast({ title: t("findings.updated"), variant: "success" });
      setNote("");
      await queryClient.invalidateQueries({ queryKey: ["finding", projectId, findingId] });
      await queryClient.invalidateQueries({ queryKey: ["findings", projectId] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    },
    onError: (error) => toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" })
  });

  const data = detail.data;
  const finding = data?.finding;
  const statuses = meta.data?.constants.finding_statuses || [];

  const timelineColumns: TableColumn<FindingDetail["timeline"][number]>[] = useMemo(
    () => [
      {
        key: "ts",
        header: t("common.date"),
        render: (event) => (
          <div className="whitespace-nowrap">
            <p className="text-[11px] text-ink">{fromNow(event.ts, lang)}</p>
            <p className="mt-0.5 text-[9px] text-faint">{formatDateTime(event.ts, lang)}</p>
          </div>
        )
      },
      {
        key: "kind",
        header: t("common.type"),
        render: (event) => (
          <div>
            <StatusBadge status={event.kind} label={event.kind.replace(/_/g, " ")} />
            <p className="mt-1 text-[9px] text-faint">{event.actor}</p>
          </div>
        )
      },
      {
        key: "change",
        header: t("common.status"),
        render: (event) =>
          event.from_status || event.to_status ? (
            <span className="inline-flex items-center gap-1.5 text-[10px]">
              <StatusBadge status={event.from_status} />
              <span className="text-faint">→</span>
              <StatusBadge status={event.to_status} />
            </span>
          ) : (
            <span className="text-faint">—</span>
          )
      },
      {
        key: "note",
        header: t("common.notes"),
        render: (event) => <p className="max-w-[320px] whitespace-normal text-[10px] leading-relaxed">{event.note || "—"}</p>
      }
    ],
    [lang, t]
  );

  const evidenceColumns: TableColumn<FindingDetail["evidence"][number]>[] = useMemo(
    () => [
      {
        key: "kind",
        header: t("common.type"),
        render: (evidence) => (
          <div>
            <p className="text-[10px] font-medium text-ink">{evidence.label || evidence.kind}</p>
            <p className="mt-0.5 font-mono text-[9px] uppercase text-faint">{evidence.kind}</p>
          </div>
        )
      },
      {
        key: "source",
        header: t("common.source"),
        render: (evidence) => (
          <div>
            <p className="text-[10px]">{evidence.source || "—"}</p>
            <p className="mt-0.5 text-[9px] text-faint">{fromNow(evidence.created_at, lang)}</p>
          </div>
        )
      },
      {
        key: "redaction",
        header: t("findings.redacted"),
        render: (evidence) =>
          evidence.redacted ? (
            <span className="inline-flex items-center gap-1 text-[9px] text-emerald-300">
              <LockKeyhole className="h-3 w-3" />
              {t("findings.redacted")}
            </span>
          ) : (
            <span className="text-[9px] text-faint">—</span>
          )
      }
    ],
    [lang, t]
  );

  const downloadEvidence = () => {
    if (!finding || !data) return;
    const blob = new Blob([JSON.stringify({ finding, evidence: data.evidence, intel: data.intel }, null, 2)], {
      type: "application/json"
    });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `nexus-finding-${finding.id.slice(0, 8)}.json`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  };

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      size="full"
      icon={Bug}
      title={
        finding ? (
          <span className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            <span>{finding.title}</span>
          </span>
        ) : (
          t("findings.drawerTitle")
        )
      }
      description={
        finding ? (
          <span className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-[10px] text-muted">{finding.target}</span>
            <span className="text-faint">·</span>
            <StatusBadge status={finding.status} />
            {finding.verified ? (
              <span className="inline-flex items-center gap-1 text-[10px] text-emerald-300">
                <ShieldCheck className="h-3 w-3" /> {t("findings.verifiedOnly")}
              </span>
            ) : null}
            {finding.active_check ? (
              <span className="inline-flex items-center gap-1 text-[10px] text-amber-300">
                <ZapIcon /> {t("findings.activeCheck")}
              </span>
            ) : null}
          </span>
        ) : undefined
      }
      footer={
        data ? (
          <>
            <span className="me-auto flex items-center gap-2 text-[10px] text-faint">
              <Fingerprint className="h-3.5 w-3.5" />
              {finding?.detected_by} {finding?.engine_version ? `· v${finding.engine_version}` : ""}
            </span>
            <Button variant="secondary" size="sm" icon={Download} onClick={downloadEvidence}>
              {t("findings.downloadEvidence")}
            </Button>
            <Button variant="secondary" size="sm" onClick={() => onOpenChange(false)}>
              {t("common.close")}
            </Button>
          </>
        ) : undefined
      }
    >
      {detail.isLoading ? (
        <div className="space-y-4">
          <Skeleton className="h-28 rounded-xl" />
          <Skeleton className="h-72 rounded-xl" />
        </div>
      ) : detail.isError || !data || !finding ? (
        <EmptyState
          icon={AlertTriangle}
          title={t("common.errorTitle")}
          description={detail.error instanceof Error ? detail.error.message : t("common.errorDescription")}
          action={
            <Button variant="secondary" onClick={() => void detail.refetch()}>
              {t("common.retry")}
            </Button>
          }
        />
      ) : (
        <div className="space-y-5">
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <div className="rounded-xl border border-line/60 bg-panel2/40 p-3">
              <p className="text-[9px] uppercase tracking-[0.1em] text-faint">{t("findings.priorityScore")}</p>
              <div className="mt-1.5 flex items-end gap-2">
                <span className="font-display text-2xl font-semibold tabular-nums text-ink">{data.priority.score}</span>
                <span className="pb-1 text-[9px] text-faint">/ 100</span>
              </div>
              <Progress value={data.priority.score} className="mt-2" tone={data.priority.score >= 80 ? "danger" : "accent"} />
            </div>
            <div className="rounded-xl border border-line/60 bg-panel2/40 p-3">
              <p className="text-[9px] uppercase tracking-[0.1em] text-faint">{t("findings.confidence")}</p>
              <div className="mt-2">
                <StatusBadge status={finding.confidence} label={labelOf(meta.data?.constants.confidences, finding.confidence, lang)} />
              </div>
              <p className="mt-2 flex items-center gap-1 text-[9px] text-faint">
                <ShieldCheck className="h-3 w-3" /> {finding.verified ? t("findings.confidenceExact") : t("findings.confidenceInferred")}
              </p>
            </div>
            <div className="rounded-xl border border-line/60 bg-panel2/40 p-3">
              <p className="text-[9px] uppercase tracking-[0.1em] text-faint">{t("findings.cvss")}</p>
              <p className="mt-1.5 font-display text-2xl font-semibold tabular-nums text-ink">{finding.cvss_score ?? "—"}</p>
              <p className="mt-1 break-all font-mono text-[9px] text-faint">{finding.cvss_vector || finding.cwe || "—"}</p>
            </div>
            <div className="rounded-xl border border-line/60 bg-panel2/40 p-3">
              <p className="text-[9px] uppercase tracking-[0.1em] text-faint">{t("common.lastSeen")}</p>
              <p className="mt-2 text-xs font-medium text-ink">{fromNow(finding.last_seen_at, lang)}</p>
              <p className="mt-1 flex items-center gap-1 text-[9px] text-faint">
                <Target className="h-3 w-3" /> {finding.occurrence_count} {t("findings.occurrences", { count: finding.occurrence_count })}
              </p>
            </div>
          </div>

          <Tabs value={tab} onValueChange={setTab}>
            <TabsList>
              <TabsTrigger value="overview" icon={FileSearch}>
                {t("findings.overview")}
              </TabsTrigger>
              <TabsTrigger value="evidence" icon={Fingerprint} count={data.evidence.length}>
                {t("findings.evidence")}
              </TabsTrigger>
              <TabsTrigger value="intel" icon={Sparkles} count={data.intel.length}>
                {t("findings.intel")}
              </TabsTrigger>
              <TabsTrigger value="timeline" icon={Clock3} count={data.timeline.length}>
                {t("findings.activity")}
              </TabsTrigger>
              {canWrite ? (
                <TabsTrigger value="triage" icon={ShieldAlert}>
                  {t("findings.triage")}
                </TabsTrigger>
              ) : null}
            </TabsList>

            <TabsContent value="overview" className="mt-4 space-y-4">
              <div className="grid gap-4 lg:grid-cols-3">
                <div className="space-y-4 lg:col-span-2">
                  <div className="rounded-xl border border-line/60 bg-panel2/30 p-4">
                    <h4 className="flex items-center gap-1.5 text-xs font-semibold text-ink">
                      <FileSearch className="h-3.5 w-3.5 text-accent" /> {t("common.description")}
                    </h4>
                    <p className="mt-2 whitespace-pre-wrap text-[11px] leading-relaxed text-muted">
                      {finding.description || "—"}
                    </p>
                  </div>
                  <div className="grid gap-4 md:grid-cols-2">
                    <div className="rounded-xl border border-line/60 bg-panel2/30 p-4">
                      <h4 className="flex items-center gap-1.5 text-xs font-semibold text-ink">
                        <AlertTriangle className="h-3.5 w-3.5 text-amber-300" /> {t("findings.impact")}
                      </h4>
                      <p className="mt-2 whitespace-pre-wrap text-[11px] leading-relaxed text-muted">
                        {finding.impact || "—"}
                      </p>
                    </div>
                    <div className="rounded-xl border border-line/60 bg-panel2/30 p-4">
                      <h4 className="flex items-center gap-1.5 text-xs font-semibold text-ink">
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-300" /> {t("findings.remediation")}
                      </h4>
                      <p className="mt-2 whitespace-pre-wrap text-[11px] leading-relaxed text-muted">
                        {finding.remediation || "—"}
                      </p>
                    </div>
                  </div>
                  {finding.references.length ? (
                    <div className="rounded-xl border border-line/60 bg-panel2/30 p-4">
                      <h4 className="flex items-center gap-1.5 text-xs font-semibold text-ink">
                        <ExternalLink className="h-3.5 w-3.5 text-accent2" /> {t("findings.references")}
                      </h4>
                      <ul className="mt-2 space-y-1.5">
                        {finding.references.map((reference) => (
                          <li key={reference}>
                            <a
                              href={reference}
                              target="_blank"
                              rel="noreferrer noopener"
                              className="break-all text-[10px] text-accent2 hover:underline"
                            >
                              {reference}
                            </a>
                          </li>
                        ))}
                      </ul>
                    </div>
                  ) : null}
                </div>
                <div className="space-y-4">
                  <div className="rounded-xl border border-line/60 bg-panel2/30 p-4">
                    <h4 className="text-xs font-semibold text-ink">{t("findings.priorityReasons")}</h4>
                    <ul className="mt-2 space-y-1.5">
                      {data.priority.reasons.length ? (
                        data.priority.reasons.map((reason) => (
                          <li key={reason} className="flex items-start gap-2 text-[10px] leading-relaxed text-muted">
                            <span className={cn("mt-1 h-1.5 w-1.5 shrink-0 rounded-full", severityDot[finding.severity])} />
                            {reason}
                          </li>
                        ))
                      ) : (
                        <li className="text-[10px] text-faint">—</li>
                      )}
                    </ul>
                  </div>
                  <dl className="grid gap-3 rounded-xl border border-line/60 bg-panel2/30 p-4">
                    <KeyValue label={t("common.target")} value={finding.target} mono />
                    <KeyValue label={t("findings.location")} value={finding.location || "—"} mono />
                    <KeyValue label={t("common.category")} value={labelOf(meta.data?.constants.finding_categories, finding.category, lang)} />
                    <KeyValue label={t("findings.cwe")} value={finding.cwe || "—"} mono />
                    <KeyValue label={t("findings.owasp")} value={finding.owasp || "—"} />
                    <KeyValue label={t("findings.assignee")} value={data.assignee?.name || t("findings.unassigned")} />
                    <KeyValue
                      label={t("assets.title")}
                      value={
                        data.asset ? (
                          <button
                            type="button"
                            className="text-accent2 hover:underline"
                            onClick={() => {
                              onOpenChange(false);
                              navigate(`/assets?asset=${data.asset?.id}`);
                            }}
                          >
                            {data.asset.value}
                          </button>
                        ) : (
                          "—"
                        )
                      }
                    />
                    <KeyValue
                      label={t("nav.scans")}
                      value={
                        data.scan ? (
                          <button
                            type="button"
                            className="inline-flex items-center gap-1 text-accent2 hover:underline"
                            onClick={() => {
                              onOpenChange(false);
                              navigate(`/scans/${data.scan?.id}`);
                            }}
                          >
                            {data.scan.name} <ArrowUpRight className="h-3 w-3" />
                          </button>
                        ) : (
                          "—"
                        )
                      }
                    />
                  </dl>
                  {finding.tags.length ? (
                    <div className="flex flex-wrap gap-1.5">
                      {finding.tags.map((tag) => (
                        <span key={tag} className="rounded-md border border-line bg-panel2 px-2 py-1 text-[9px] text-muted">
                          {tag}
                        </span>
                      ))}
                    </div>
                  ) : null}
                </div>
              </div>
            </TabsContent>

            <TabsContent value="evidence" className="mt-4">
              {data.evidence.length ? (
                <div className="space-y-3">
                  <DataTable
                    columns={evidenceColumns}
                    rows={data.evidence}
                    rowKey={(evidence) => evidence.id}
                    skeletonRows={2}
                  />
                  {data.evidence.map((evidence) => (
                    <details key={evidence.id} className="group rounded-xl border border-line/60 bg-panel2/20">
                      <summary className="flex cursor-pointer items-center gap-2 px-3.5 py-2.5 text-[11px] font-medium text-ink">
                        <FileSearch className="h-3.5 w-3.5 text-accent" />
                        {evidence.label || evidence.kind}
                        <span className="ms-auto font-mono text-[9px] text-faint">{evidence.sha256.slice(0, 16)}…</span>
                      </summary>
                      <div className="space-y-2 border-t border-line/50 p-3.5">
                        {evidence.request ? (
                          <div>
                            <p className="mb-1 text-[9px] uppercase tracking-[0.1em] text-faint">{t("findings.request")}</p>
                            <pre className="max-h-56 overflow-auto rounded-lg bg-bg/70 p-2.5 font-mono text-[9px] leading-relaxed text-muted whitespace-pre-wrap break-all">
                              {evidence.request}
                            </pre>
                          </div>
                        ) : null}
                        {evidence.response ? (
                          <div>
                            <p className="mb-1 text-[9px] uppercase tracking-[0.1em] text-faint">{t("findings.response")}</p>
                            <pre className="max-h-64 overflow-auto rounded-lg bg-bg/70 p-2.5 font-mono text-[9px] leading-relaxed text-muted whitespace-pre-wrap break-all">
                              {evidence.response}
                            </pre>
                          </div>
                        ) : null}
                        {Object.keys(evidence.headers || {}).length ? (
                          <div>
                            <p className="mb-1 text-[9px] uppercase tracking-[0.1em] text-faint">Headers</p>
                            <pre className="max-h-44 overflow-auto rounded-lg bg-bg/70 p-2.5 font-mono text-[9px] leading-relaxed text-muted whitespace-pre-wrap break-all">
                              {JSON.stringify(evidence.headers, null, 2)}
                            </pre>
                          </div>
                        ) : null}
                        <div className="flex flex-wrap items-center gap-2">
                          <CopyButton value={evidence.sha256} label="SHA-256" />
                          {evidence.redacted ? (
                            <span className="rounded-md border border-emerald-400/20 bg-emerald-400/10 px-2 py-1 text-[9px] text-emerald-300">
                              {t("findings.redacted")} · {JSON.stringify(evidence.redaction_summary)}
                            </span>
                          ) : null}
                        </div>
                      </div>
                    </details>
                  ))}
                </div>
              ) : (
                <EmptyState icon={Fingerprint} title={t("findings.noEvidence")} />
              )}
            </TabsContent>

            <TabsContent value="intel" className="mt-4 space-y-3">
              {data.intel.length ? (
                data.intel.map((link) => (
                  <div key={link.cve_id} className="rounded-xl border border-line/60 bg-panel2/30 p-4">
                    <div className="flex flex-wrap items-center gap-2">
                      <button
                        type="button"
                        onClick={() => {
                          onOpenChange(false);
                          navigate(`/intel?cve=${encodeURIComponent(link.cve_id)}`);
                        }}
                        className="font-mono text-sm font-semibold text-accent2 hover:underline"
                      >
                        {link.cve_id}
                      </button>
                      <span
                        className={cn(
                          "rounded-md border px-2 py-0.5 text-[9px] font-semibold",
                          link.match_type === "exact"
                            ? "border-emerald-400/20 bg-emerald-400/10 text-emerald-300"
                            : "border-amber-400/20 bg-amber-400/10 text-amber-300"
                        )}
                      >
                        {link.match_type === "exact" ? t("findings.exact") : t("findings.inferred")}
                      </span>
                      {link.kev ? (
                        <span className="rounded-md border border-rose-400/20 bg-rose-400/10 px-2 py-0.5 text-[9px] font-semibold text-rose-300">
                          {t("findings.kev")}
                          {link.kev_ransomware ? ` · ${t("intel.ransomware")}` : ""}
                        </span>
                      ) : null}
                    </div>
                    <p className="mt-2 text-[11px] leading-relaxed text-muted">{link.cve?.description || "—"}</p>
                    <div className="mt-2 flex flex-wrap gap-4 text-[9px] text-faint">
                      <span>CVSS {link.cve?.cvss_v3_score ?? "—"}</span>
                      <span>{link.cve?.cvss_severity || ""}</span>
                      <span>{t("common.confidence")}: {link.confidence}</span>
                    </div>
                    <p className="mt-2 text-[10px] leading-relaxed text-faint">{link.rationale}</p>
                  </div>
                ))
              ) : (
                <EmptyState icon={Sparkles} title={t("findings.noIntel")} description={t("intel.subtitle")} />
              )}
            </TabsContent>

            <TabsContent value="timeline" className="mt-4">
              {data.timeline.length ? (
                <DataTable
                  columns={timelineColumns}
                  rows={data.timeline}
                  rowKey={(event) => event.id}
                  skeletonRows={3}
                />
              ) : (
                <EmptyState icon={Activity} title={t("common.noneFound")} />
              )}
            </TabsContent>

            {canWrite ? (
              <TabsContent value="triage" className="mt-4">
                <div className="grid gap-4 lg:grid-cols-2">
                  <div className="space-y-3 rounded-xl border border-line/60 bg-panel2/30 p-4">
                    <Field label={t("findings.newStatus")}>
                      <Select value={status} onChange={(event) => setStatus(event.target.value)}>
                        {(statuses.length
                          ? statuses
                          : [
                              { key: "open", labels: { ar: "مفتوحة", en: "Open" } },
                              { key: "confirmed", labels: { ar: "مؤكدة", en: "Confirmed" } },
                              { key: "fixed", labels: { ar: "مصلحة", en: "Fixed" } },
                              { key: "accepted_risk", labels: { ar: "خطر مقبول", en: "Accepted risk" } },
                              { key: "false_positive", labels: { ar: "إيجابية كاذبة", en: "False positive" } }
                            ]
                        ).map((option) => (
                          <option key={option.key} value={option.key}>
                            {statusLabel(statuses, option.key, lang)}
                          </option>
                        ))}
                      </Select>
                    </Field>
                    <Field label={t("findings.note")} hint={t("findings.notePlaceholder")}>
                      <Textarea
                        value={note}
                        onChange={(event) => setNote(event.target.value)}
                        placeholder={t("findings.notePlaceholder")}
                        maxLength={4000}
                      />
                    </Field>
                    <Button
                      icon={ShieldAlert}
                      loading={update.isPending}
                      disabled={!status || update.isPending}
                      onClick={() => update.mutate()}
                    >
                      {t("findings.updateStatus")}
                    </Button>
                  </div>
                  <div className="space-y-3 rounded-xl border border-line/60 bg-panel2/30 p-4">
                    <Field label={t("findings.note")} hint={t("findings.notePlaceholder")}>
                      <Textarea
                        value={triageNote}
                        onChange={(event) => setTriageNote(event.target.value)}
                        placeholder={t("findings.notePlaceholder")}
                        maxLength={4000}
                      />
                    </Field>
                    <p className="text-[10px] leading-relaxed text-faint">
                      {t("findings.triage")} · {t("audit.title") || "Audit"} — {t("footer.policy")}
                    </p>
                    <div className="flex items-center gap-2">
                      <Button
                        variant="secondary"
                        icon={CheckCircle2}
                        loading={update.isPending}
                        onClick={() => update.mutate()}
                      >
                        {t("common.save")}
                      </Button>
                      <Button variant="ghost" onClick={() => {
                        setStatus(finding.status);
                        setTriageNote(finding.triage_note || "");
                        setNote("");
                      }}>
                        {t("common.reset")}
                      </Button>
                    </div>
                  </div>
                </div>
              </TabsContent>
            ) : null}
          </Tabs>
        </div>
      )}
    </Modal>
  );
}

function ZapIcon() {
  return <ShieldAlert className="h-3 w-3" />;
}
