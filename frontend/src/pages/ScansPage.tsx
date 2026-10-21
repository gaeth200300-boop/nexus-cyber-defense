import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  CircleDot,
  Filter,
  Play,
  RefreshCw,
  ScanLine,
  Search,
  Timer,
  XCircle
} from "lucide-react";
import { apiFetch } from "../lib/api";
import { cn, formatNumber, fromNow } from "../lib/utils";
import { useProject } from "../context/ProjectContext";
import { labelOf, useDocumentTitle, useMeta } from "../hooks";
import type { Lang, Paged, Scan } from "../types";
import { ScanComposer } from "../components/ScanComposer";
import { ProjectGate } from "../components/common";
import {
  Button,
  Card,
  EmptyState,
  Input,
  PageHeader,
  Pagination,
  Progress,
  Select,
  Skeleton,
  StatusBadge
} from "../components/ui";

interface ScansResponse extends Paged<Scan> {
  counts: Record<string, number>;
}

const activeStatuses = new Set(["queued", "running"]);

export default function ScansPage() {
  return (
    <ProjectGate>
      <ScansContent />
    </ProjectGate>
  );
}

function ScansContent() {
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const { selectedProject, canWrite } = useProject();
  const meta = useMeta();
  const navigate = useNavigate();
  useDocumentTitle(t("scans.title"));
  const projectId = selectedProject?.id || "";

  const [status, setStatus] = useState("");
  const [kind, setKind] = useState("");
  const [q, setQ] = useState("");
  const [limit, setLimit] = useState(25);
  const [offset, setOffset] = useState(0);
  const [composerOpen, setComposerOpen] = useState(false);

  const query = useQuery({
    queryKey: ["scans", projectId, status, kind, limit, offset],
    queryFn: () =>
      apiFetch<ScansResponse>(`/projects/${projectId}/scans`, {
        query: { status: status || undefined, kind: kind || undefined, limit, offset }
      }),
    enabled: Boolean(projectId),
    refetchInterval: (query) => {
      const data = query.state.data as ScansResponse | undefined;
      return data?.items.some((scan) => activeStatuses.has(scan.status)) ? 4000 : false;
    }
  });

  const rows = useMemo(() => {
    const items = query.data?.items || [];
    if (!q.trim()) return items;
    const needle = q.trim().toLowerCase();
    return items.filter(
      (scan) =>
        scan.name.toLowerCase().includes(needle) ||
        scan.engine.toLowerCase().includes(needle) ||
        scan.targets.some((target) => JSON.stringify(target).toLowerCase().includes(needle))
    );
  }, [query.data?.items, q]);

  const total = query.data?.total || 0;
  const counts = query.data?.counts || {};
  const active = (counts.queued || 0) + (counts.running || 0);
  const kindOptions = meta.data?.constants.scan_kinds || [];

  const statusCards = [
    { key: "", label: t("scans.all"), value: total, icon: ScanLine, tone: "text-accent" },
    { key: "running", label: t("scans.active"), value: (counts.running || 0) + (counts.queued || 0), icon: Activity, tone: "text-accent2" },
    { key: "completed", label: t("scans.completed"), value: counts.completed || 0, icon: CheckCircle2, tone: "text-emerald-300" },
    { key: "partial", label: t("scanDetail.partial"), value: counts.partial || 0, icon: CircleDot, tone: "text-amber-300" },
    { key: "failed", label: t("scans.failed"), value: (counts.failed || 0) + (counts.canceled || 0), icon: XCircle, tone: "text-rose-300" }
  ];

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow={t("nav.security")}
        icon={ScanLine}
        title={t("scans.title")}
        subtitle={t("scans.subtitle")}
        actions={
          <>
            <Button
              variant="secondary"
              icon={RefreshCw}
              onClick={() => void query.refetch()}
              loading={query.isFetching && !query.isLoading}
            >
              {t("common.refresh")}
            </Button>
            <Button icon={Play} onClick={() => setComposerOpen(true)} disabled={!canWrite}>
              {t("scans.newAssessment")}
            </Button>
          </>
        }
      />

      <section className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 xl:grid-cols-5">
        {statusCards.map((card) => {
          const selected = status === card.key;
          return (
            <button
              type="button"
              key={card.key || "all"}
              onClick={() => {
                setStatus(card.key);
                setOffset(0);
              }}
              className={cn(
                "surface-card group p-3.5 text-start transition hover:-translate-y-0.5 hover:border-accent/25",
                selected && "border-accent/40 ring-1 ring-accent/20"
              )}
            >
              <div className="flex items-center justify-between">
                <span className="text-[9px] font-semibold uppercase tracking-[0.1em] text-muted">{card.label}</span>
                <card.icon className={cn("h-4 w-4", card.tone)} />
              </div>
              <p className="mt-2 font-display text-2xl font-semibold tabular-nums text-ink">{formatNumber(card.value, lang)}</p>
              {card.key === "running" && active > 0 ? (
                <span className="mt-1 flex items-center gap-1.5 text-[9px] text-accent2">
                  <span className="relative flex h-1.5 w-1.5">
                    <span className="absolute h-full w-full animate-ping rounded-full bg-accent2 opacity-70" />
                    <span className="relative h-1.5 w-1.5 rounded-full bg-accent2" />
                  </span>
                  {t("common.live")}
                </span>
              ) : null}
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
              placeholder={t("scans.searchPlaceholder")}
              className="ps-9"
            />
          </div>
          <Select
            value={kind}
            onChange={(event) => {
              setKind(event.target.value);
              setOffset(0);
            }}
            className="w-auto min-w-[160px]"
          >
            <option value="">{t("scans.kindFilter")} · {t("common.all")}</option>
            {kindOptions.map((option) => (
              <option key={option.key} value={option.key}>
                {option.labels[lang]}
              </option>
            ))}
          </Select>
          <Select
            value={status}
            onChange={(event) => {
              setStatus(event.target.value);
              setOffset(0);
            }}
            className="w-auto min-w-[140px]"
          >
            <option value="">{t("scans.statusFilter")} · {t("common.all")}</option>
            {["queued", "running", "completed", "partial", "failed", "canceled"].map((state) => (
              <option key={state} value={state}>
                {t(`status.${state}`)}
              </option>
            ))}
          </Select>
          {q || kind || status ? (
            <Button
              size="sm"
              variant="ghost"
              onClick={() => {
                setQ("");
                setKind("");
                setStatus("");
                setOffset(0);
              }}
            >
              {t("common.clear")}
            </Button>
          ) : null}
          <span className="ms-auto hidden items-center gap-1.5 text-[10px] text-faint sm:flex">
            <Filter className="h-3 w-3" /> {formatNumber(total, lang)} {t("scans.title")}
          </span>
        </div>

        {query.isLoading ? (
          <div className="space-y-2 p-4">
            {[0, 1, 2, 3, 4, 5].map((key) => (
              <Skeleton key={key} className="h-16 w-full rounded-xl" />
            ))}
          </div>
        ) : query.isError ? (
          <EmptyState
            icon={AlertTriangle}
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
            icon={ScanLine}
            title={query.data?.items.length ? t("scans.noResults") : t("scans.emptyTitle")}
            description={query.data?.items.length ? undefined : t("scans.emptyBody")}
            action={
              query.data?.items.length ? undefined : (
                <Button icon={Play} onClick={() => setComposerOpen(true)} disabled={!canWrite}>
                  {t("scans.emptyAction")}
                </Button>
              )
            }
          />
        ) : (
          <>
            <div className="divide-y divide-line/50">
              {rows.map((scan) => {
                const isLive = activeStatuses.has(scan.status);
                return (
                  <button
                    key={scan.id}
                    type="button"
                    onClick={() => navigate(`/scans/${scan.id}`)}
                    className="group flex w-full flex-wrap items-center gap-3 px-4 py-3.5 text-start transition hover:bg-panel2/50 sm:flex-nowrap"
                  >
                    <span
                      className={cn(
                        "grid h-10 w-10 shrink-0 place-items-center rounded-xl border transition",
                        scan.status === "running"
                          ? "border-accent/30 bg-accent/10 text-accent"
                          : scan.status === "failed"
                            ? "border-rose-400/20 bg-rose-400/10 text-rose-300"
                            : "border-line bg-panel2 text-muted group-hover:border-accent/20"
                      )}
                    >
                      {scan.status === "running" ? (
                        <span className="relative flex h-4 w-4">
                          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-accent opacity-50" />
                          <ScanLine className="relative h-4 w-4" />
                        </span>
                      ) : (
                        <ScanLine className="h-4 w-4" />
                      )}
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <p className="truncate text-xs font-medium text-ink">{scan.name}</p>
                        {scan.cancel_requested ? (
                          <span className="rounded border border-amber-400/20 bg-amber-400/10 px-1.5 py-0.5 text-[8px] text-amber-300">
                            {t("scanDetail.cancel")}
                          </span>
                        ) : null}
                      </div>
                      <div className="mt-1 flex flex-wrap items-center gap-2 text-[9px] text-faint">
                        <span>{labelOf(meta.data?.constants.scan_kinds, scan.kind, lang)}</span>
                        <span>·</span>
                        <span>{scan.engine}</span>
                        <span>·</span>
                        <span>{t("scanDetail.targetCount", { count: scan.target_count })}</span>
                        <span>·</span>
                        <span>{fromNow(scan.created_at, lang)}</span>
                      </div>
                      {isLive || (scan.progress > 0 && scan.progress < 100) ? (
                        <div className="mt-2 flex max-w-xl items-center gap-2">
                          <Progress
                            value={scan.progress}
                            className="h-1"
                            tone={scan.status === "failed" ? "danger" : isLive ? "accent" : "success"}
                            indeterminate={scan.status === "queued"}
                          />
                          <span className="w-8 shrink-0 text-end font-mono text-[9px] tabular-nums text-faint">
                            {scan.progress}%
                          </span>
                        </div>
                      ) : null}
                    </div>
                    <div className="flex shrink-0 items-center gap-3">
                      {scan.findings && Object.values(scan.findings).some((value) => value > 0) ? (
                        <span className="hidden items-center gap-1 text-[9px] text-faint md:flex">
                          <AlertTriangle className="h-3 w-3 text-amber-300" />
                          {Object.values(scan.findings).reduce((sum, value) => sum + value, 0)}
                        </span>
                      ) : null}
                      {scan.started_at ? (
                        <span className="hidden items-center gap-1 text-[9px] text-faint lg:flex">
                          <Timer className="h-3 w-3" /> {fromNow(scan.started_at, lang)}
                        </span>
                      ) : null}
                      <StatusBadge status={scan.status} />
                    </div>
                  </button>
                );
              })}
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

      <ScanComposer open={composerOpen} onOpenChange={setComposerOpen} />
    </div>
  );
}
