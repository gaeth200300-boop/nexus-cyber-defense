import { useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import {
  AlertTriangle,
  ArrowUpRight,
  BookOpen,
  Bug,
  CalendarClock,
  CheckCircle2,
  Database,
  ExternalLink,
  Fingerprint,
  Link2,
  Loader2,
  RefreshCw,
  Search,
  ShieldAlert,
  Sparkles,
  Siren,
  Zap
} from "lucide-react";
import { apiFetch, errorMessage } from "../lib/api";
import { cn, formatDateTime, fromNow } from "../lib/utils";
import { useAuth } from "../context/AuthContext";
import { useProject } from "../context/ProjectContext";
import { useToast } from "../context/ToastContext";
import { useDebouncedValue, useDocumentTitle } from "../hooks";
import type { CveRecord, KevEntry, Lang, Paged } from "../types";
import {
  Badge,
  Button,
  Card,
  CopyButton,
  DataTable,
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
  type TableColumn
} from "../components/ui";

interface IntelStats {
  cve_records_cached: number;
  finding_links: number;
  kev: { total: number; ransomware: number; sync: Record<string, unknown> };
  kev_sync: Record<string, unknown>;
  cache_hours: number;
  nvd_key_configured: boolean;
  source: string;
  fetched_at: string;
}

interface KevResponse extends Paged<KevEntry> {
  stats: { total: number; ransomware: number; sync: Record<string, unknown> };
}

interface CveSearchResponse {
  items: CveRecord[];
  query: string;
  error: string | null;
}

interface CveDetailResponse {
  cve: CveRecord;
  cache: { fresh: boolean; hours: number };
  error: string | null;
}

interface IntelLink {
  id: string;
  cve_id: string;
  match_type: string;
  confidence: string;
  rationale: string;
  created_at: string;
  kev: boolean;
  finding: { id: string; title: string; severity: string; status: string; target: string };
  cve: CveRecord | null;
}

const cvssColor = (score: number | null) =>
  score === null
    ? "text-faint"
    : score >= 9
      ? "text-rose-300"
      : score >= 7
        ? "text-orange-300"
        : score >= 4
          ? "text-amber-300"
          : "text-emerald-300";

export default function IntelPage() {
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const { user } = useAuth();
  const { selectedProject, canWrite } = useProject();
  const toast = useToast();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [params, setParams] = useSearchParams();
  useDocumentTitle(t("intel.title"));

  const [tab, setTab] = useState("catalog");
  const [search, setSearch] = useState("");
  const [submitted, setSubmitted] = useState("");
  const [kevQ, setKevQ] = useState("");
  const debouncedKevQ = useDebouncedValue(kevQ, 350);
  const [ransomwareOnly, setRansomwareOnly] = useState(false);
  const [limit, setLimit] = useState(25);
  const [offset, setOffset] = useState(0);
  const [linksOffset, setLinksOffset] = useState(0);
  const selectedCve = params.get("cve");
  const projectId = selectedProject?.id || "";

  const stats = useQuery({
    queryKey: ["intel-stats"],
    queryFn: () => apiFetch<IntelStats>("/intel/stats"),
    staleTime: 60_000
  });

  const recent = useQuery({
    queryKey: ["intel-recent"],
    queryFn: () => apiFetch<{ items: CveRecord[]; days: number; error: string | null }>("/intel/recent", { query: { days: 7, limit: 8 } }),
    staleTime: 300_000,
    retry: false
  });

  const searchResults = useQuery({
    queryKey: ["intel-search", submitted],
    queryFn: () => apiFetch<CveSearchResponse>("/intel/search", { query: { q: submitted, limit: 30 } }),
    enabled: submitted.trim().length >= 2,
    retry: false
  });

  const kev = useQuery({
    queryKey: ["intel-kev", debouncedKevQ, ransomwareOnly, limit, offset],
    queryFn: () =>
      apiFetch<KevResponse>("/intel/kev", {
        query: { q: debouncedKevQ, ransomware_only: ransomwareOnly, limit, offset }
      }),
    enabled: tab === "kev"
  });

  const links = useQuery({
    queryKey: ["intel-links", projectId, linksOffset],
    queryFn: () =>
      apiFetch<Paged<IntelLink>>(`/projects/${projectId}/intel/links`, {
        query: { limit: 25, offset: linksOffset }
      }),
    enabled: tab === "links" && Boolean(projectId)
  });

  const cveDetail = useQuery({
    queryKey: ["intel-cve", selectedCve],
    queryFn: () => apiFetch<CveDetailResponse>(`/intel/cve/${selectedCve}`),
    enabled: Boolean(selectedCve),
    retry: false
  });

  const sync = useMutation({
    mutationFn: () =>
      apiFetch<{ result: Record<string, unknown>; stats: Record<string, unknown> }>("/intel/kev/sync", {
        method: "POST",
        body: { force: false }
      }),
    onSuccess: async (result) => {
      toast.toast({
        title: t("intel.sync"),
        description: Object.entries(result.result).slice(0, 3).map(([key, value]) => `${key}: ${String(value)}`).join(" · "),
        variant: "success"
      });
      await queryClient.invalidateQueries({ queryKey: ["intel-kev"] });
      await queryClient.invalidateQueries({ queryKey: ["intel-stats"] });
    },
    onError: (error) => toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" })
  });

  const correlate = useMutation({
    mutationFn: () =>
      apiFetch<{ scan_id: string; job_id: string | null; status: string; note: string }>(
        `/projects/${projectId}/intel/correlate`,
        { method: "POST", body: { max_cves: 40, include_kev: true } }
      ),
    onSuccess: async (result) => {
      toast.toast({ title: t("intel.correlateStarted"), variant: "success" });
      await queryClient.invalidateQueries({ queryKey: ["scans", projectId] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
      navigate(`/scans/${result.scan_id}`);
    },
    onError: (error) => toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" })
  });

  const openCve = (cveId: string) => {
    const next = new URLSearchParams(params);
    next.set("cve", cveId);
    setParams(next, { replace: false });
  };

  const closeCve = () => {
    const next = new URLSearchParams(params);
    next.delete("cve");
    setParams(next, { replace: true });
  };

  const kevColumns: TableColumn<KevEntry>[] = useMemo(
    () => [
      {
        key: "cve",
        header: t("intel.cve"),
        render: (entry) => (
          <button
            type="button"
            onClick={() => openCve(entry.cve_id)}
            className="font-mono text-[11px] font-semibold text-accent2 hover:underline"
          >
            {entry.cve_id}
          </button>
        )
      },
      {
        key: "vendor",
        header: t("intel.affected"),
        render: (entry) => (
          <div className="max-w-[280px]">
            <p className="truncate text-[10px] font-medium text-ink">{entry.vulnerability_name}</p>
            <p className="mt-0.5 truncate text-[9px] text-faint">
              {[entry.vendor_project, entry.product].filter(Boolean).join(" · ")}
            </p>
          </div>
        )
      },
      {
        key: "added",
        header: t("intel.published"),
        className: "hidden lg:table-cell",
        headerClassName: "hidden lg:table-cell",
        render: (entry) => <span className="whitespace-nowrap text-[9px] text-muted">{formatDateTime(entry.date_added, lang)}</span>
      },
      {
        key: "due",
        header: t("intel.kevDue"),
        className: "hidden xl:table-cell",
        headerClassName: "hidden xl:table-cell",
        render: (entry) => <span className="whitespace-nowrap text-[9px] text-muted">{formatDateTime(entry.due_date, lang)}</span>
      },
      {
        key: "ransomware",
        header: t("intel.ransomware"),
        render: (entry) =>
          entry.known_ransomware ? (
            <Badge tone="danger">{t("common.yes")}</Badge>
          ) : (
            <span className="text-[9px] text-faint">—</span>
          )
      }
    ],
    [lang, t]
  );

  const linkColumns: TableColumn<IntelLink>[] = useMemo(
    () => [
      {
        key: "cve",
        header: t("intel.cve"),
        render: (link) => (
          <button type="button" onClick={() => openCve(link.cve_id)} className="font-mono text-[10px] font-semibold text-accent2 hover:underline">
            {link.cve_id}
          </button>
        )
      },
      {
        key: "finding",
        header: t("nav.findings"),
        render: (link) => (
          <button
            type="button"
            onClick={() => navigate(`/findings?finding=${link.finding.id}`)}
            className="max-w-[320px] truncate text-start text-[10px] text-ink hover:text-accent2"
          >
            {link.finding.title}
          </button>
        )
      },
      {
        key: "match",
        header: t("intel.matches"),
        render: (link) => (
          <Badge tone={link.match_type === "exact" ? "success" : "warning"}>
            {link.match_type === "exact" ? t("intel.exact") : t("intel.inferred")}
          </Badge>
        )
      },
      {
        key: "severity",
        header: t("common.severity"),
        render: (link) => <SeverityBadge severity={link.finding.severity} />
      },
      {
        key: "created",
        header: t("common.date"),
        render: (link) => <span className="whitespace-nowrap text-[9px] text-faint">{fromNow(link.created_at, lang)}</span>
      }
    ],
    [lang, t]
  );

  const combinedError = searchResults.data?.error || recent.data?.error;
  const cve = cveDetail.data?.cve;

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow={t("nav.intelligence")}
        icon={Fingerprint}
        title={t("intel.title")}
        subtitle={t("intel.subtitle")}
        actions={
          <>
            {user && ["owner", "admin"].includes(user.role) ? (
              <Button
                variant="secondary"
                icon={RefreshCw}
                loading={sync.isPending}
                onClick={() => sync.mutate()}
              >
                {t("intel.sync")}
              </Button>
            ) : null}
            <Button
              icon={Sparkles}
              loading={correlate.isPending}
              disabled={!canWrite || !projectId}
              onClick={() => correlate.mutate()}
            >
              {t("intel.correlate")}
            </Button>
          </>
        }
      />

      <section className="grid grid-cols-2 gap-2.5 xl:grid-cols-4">
        {[
          { label: t("intel.cve"), value: stats.data?.cve_records_cached, icon: Database, tone: "text-accent" },
          { label: t("intel.kev"), value: stats.data?.kev.total, icon: Siren, tone: "text-rose-300" },
          { label: t("intel.ransomware"), value: stats.data?.kev.ransomware, icon: Zap, tone: "text-amber-300" },
          { label: t("intel.matches"), value: stats.data?.finding_links, icon: Link2, tone: "text-accent2" }
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

      {combinedError ? (
        <InlineAlert tone="warning" title={t("intel.liveDisabled")}>
          {String(combinedError)}
        </InlineAlert>
      ) : null}
      {stats.data && !stats.data.nvd_key_configured ? (
        <InlineAlert tone="info" title={t("intel.liveDisabled")}>
          {t("intel.searchHint")}
        </InlineAlert>
      ) : null}

      <Card className="p-4">
        <form
          onSubmit={(event) => {
            event.preventDefault();
            setSubmitted(search.trim());
            setTab("catalog");
          }}
          className="flex flex-wrap items-center gap-2"
        >
          <div className="relative min-w-[240px] flex-1">
            <Search className="pointer-events-none absolute start-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-faint" />
            <Input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder={t("intel.searchPlaceholder")}
              className="ps-9 font-mono"
            />
          </div>
          <Button type="submit" icon={Search} disabled={search.trim().length < 2}>
            {t("common.search")}
          </Button>
          {submitted ? (
            <Button
              type="button"
              variant="ghost"
              onClick={() => {
                setSearch("");
                setSubmitted("");
              }}
            >
              {t("common.clear")}
            </Button>
          ) : null}
          <span className="ms-auto hidden items-center gap-1.5 text-[9px] text-faint sm:flex">
            <CalendarClock className="h-3 w-3" />
            {stats.data ? `${t("intel.lastSync")}: ${fromNow(stats.data.fetched_at, lang)}` : ""}
          </span>
        </form>
      </Card>

      <div className="grid gap-4 xl:grid-cols-12">
        <div className="xl:col-span-8">
          <Tabs value={tab} onValueChange={setTab}>
            <TabsList>
              <TabsTrigger value="catalog" icon={BookOpen}>
                {submitted ? t("intel.searchTitle") : t("intel.searchTitle")}
              </TabsTrigger>
              <TabsTrigger value="kev" icon={Siren} count={stats.data?.kev.total}>
                {t("intel.kevTitle")}
              </TabsTrigger>
              <TabsTrigger value="links" icon={Link2} count={stats.data?.finding_links}>
                {t("intel.matches")}
              </TabsTrigger>
            </TabsList>

            <TabsContent value="catalog" className="mt-4 space-y-3">
              {submitted ? (
                searchResults.isLoading ? (
                  <div className="space-y-2">
                    {[0, 1, 2, 3].map((key) => (
                      <Skeleton key={key} className="h-20 rounded-xl" />
                    ))}
                  </div>
                ) : searchResults.isError ? (
                  <Card className="p-2">
                    <EmptyState
                      icon={AlertTriangle}
                      title={t("common.errorTitle")}
                      description={searchResults.error instanceof Error ? searchResults.error.message : t("intel.liveDisabled")}
                      action={
                        <Button variant="secondary" onClick={() => void searchResults.refetch()}>
                          {t("common.retry")}
                        </Button>
                      }
                    />
                  </Card>
                ) : searchResults.data?.items.length ? (
                  searchResults.data.items.map((record) => (
                    <CveCard key={record.id} record={record} lang={lang} onOpen={() => openCve(record.id)} />
                  ))
                ) : (
                  <Card className="p-2">
                    <EmptyState icon={Search} title={t("intel.emptyTitle")} description={t("intel.emptyBody")} />
                  </Card>
                )
              ) : (
                <>
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-xs font-semibold text-ink">{t("intel.searchTitle")}</h3>
                      <p className="mt-0.5 text-[10px] text-muted">{t("intel.searchHint")}</p>
                    </div>
                    <Badge tone="info">{recent.data?.days || 7}d</Badge>
                  </div>
                  {recent.isLoading ? (
                    <div className="space-y-2">
                      {[0, 1, 2].map((key) => (
                        <Skeleton key={key} className="h-20 rounded-xl" />
                      ))}
                    </div>
                  ) : recent.isError ? (
                    <Card className="p-2">
                      <EmptyState
                        icon={Database}
                        title={t("intel.emptyTitle")}
                        description={recent.error instanceof Error ? recent.error.message : t("intel.liveDisabled")}
                      />
                    </Card>
                  ) : recent.data?.items.length ? (
                    recent.data.items.map((record) => (
                      <CveCard key={record.id} record={record} lang={lang} onOpen={() => openCve(record.id)} />
                    ))
                  ) : (
                    <Card className="p-2">
                      <EmptyState icon={Database} title={t("intel.emptyTitle")} description={t("intel.emptyBody")} />
                    </Card>
                  )}
                </>
              )}
            </TabsContent>

            <TabsContent value="kev" className="mt-4">
              <Card className="overflow-hidden">
                <div className="flex flex-wrap items-center gap-2 border-b border-line/60 p-3.5">
                  <div className="relative min-w-[180px] flex-1">
                    <Search className="pointer-events-none absolute start-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-faint" />
                    <Input
                      value={kevQ}
                      onChange={(event) => {
                        setKevQ(event.target.value);
                        setOffset(0);
                      }}
                      placeholder={t("intel.searchPlaceholder")}
                      className="ps-9"
                    />
                  </div>
                  <label className="flex cursor-pointer items-center gap-2 rounded-lg border border-line bg-panel2 px-3 py-2 text-[10px] text-muted">
                    <input
                      type="checkbox"
                      checked={ransomwareOnly}
                      onChange={(event) => {
                        setRansomwareOnly(event.target.checked);
                        setOffset(0);
                      }}
                      className="h-3 w-3 accent-[rgb(var(--accent))]"
                    />
                    {t("intel.ransomware")}
                  </label>
                  <span className="ms-auto text-[9px] text-faint">{t("projects.total", { count: kev.data?.total || 0 })}</span>
                </div>
                {kev.isLoading ? (
                  <div className="space-y-2 p-4">
                    {[0, 1, 2, 3].map((key) => (
                      <Skeleton key={key} className="h-10 rounded-lg" />
                    ))}
                  </div>
                ) : kev.isError ? (
                  <EmptyState
                    icon={AlertTriangle}
                    title={t("common.errorTitle")}
                    description={kev.error instanceof Error ? kev.error.message : t("common.errorDescription")}
                  />
                ) : kev.data?.items.length ? (
                  <>
                    <DataTable
                      columns={kevColumns}
                      rows={kev.data.items}
                      rowKey={(entry) => entry.cve_id}
                      onRowClick={(entry) => openCve(entry.cve_id)}
                    />
                    <Pagination
                      page={Math.floor(offset / limit) + 1}
                      pageSize={limit}
                      total={kev.data.total}
                      onPageChange={(page) => setOffset((page - 1) * limit)}
                      labels={{ previous: t("common.previous"), next: t("common.next"), page: t("common.page"), of: t("common.of") }}
                    />
                  </>
                ) : (
                  <EmptyState icon={Siren} title={t("intel.noKev")} description={t("intel.kevSubtitle")} />
                )}
              </Card>
            </TabsContent>

            <TabsContent value="links" className="mt-4">
              <Card className="overflow-hidden">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line/60 p-3.5">
                  <div>
                    <h3 className="text-xs font-semibold text-ink">{t("intel.matches")}</h3>
                    <p className="mt-0.5 text-[10px] text-muted">{t("intel.subtitle")}</p>
                  </div>
                  <Button
                    size="sm"
                    variant="secondary"
                    icon={Sparkles}
                    loading={correlate.isPending}
                    disabled={!canWrite || !projectId}
                    onClick={() => correlate.mutate()}
                  >
                    {t("intel.correlate")}
                  </Button>
                </div>
                {!projectId ? (
                  <EmptyState icon={Link2} title={t("common.noProjectTitle")} description={t("common.noProjectBody")} />
                ) : links.isLoading ? (
                  <div className="space-y-2 p-4">
                    {[0, 1, 2].map((key) => (
                      <Skeleton key={key} className="h-10 rounded-lg" />
                    ))}
                  </div>
                ) : links.isError ? (
                  <EmptyState
                    icon={AlertTriangle}
                    title={t("common.errorTitle")}
                    description={links.error instanceof Error ? links.error.message : t("common.errorDescription")}
                  />
                ) : links.data?.items.length ? (
                  <>
                    <DataTable
                      columns={linkColumns}
                      rows={links.data.items}
                      rowKey={(link) => link.id}
                      onRowClick={(link) => openCve(link.cve_id)}
                    />
                    <Pagination
                      page={Math.floor(linksOffset / 25) + 1}
                      pageSize={25}
                      total={links.data.total}
                      onPageChange={(page) => setLinksOffset((page - 1) * 25)}
                      labels={{ previous: t("common.previous"), next: t("common.next"), page: t("common.page"), of: t("common.of") }}
                    />
                  </>
                ) : (
                  <EmptyState
                    icon={Link2}
                    title={t("intel.noMatches")}
                    description={t("intel.correlateStarted")}
                    action={
                      <Button
                        icon={Sparkles}
                        loading={correlate.isPending}
                        disabled={!canWrite}
                        onClick={() => correlate.mutate()}
                      >
                        {t("intel.correlate")}
                      </Button>
                    }
                  />
                )}
              </Card>
            </TabsContent>
          </Tabs>
        </div>

        <div className="space-y-4 xl:col-span-4">
          <Card className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-xs font-semibold text-ink">{t("intel.kevTitle")}</h3>
                <p className="mt-0.5 text-[10px] text-muted">{t("intel.kevSubtitle")}</p>
              </div>
              <ShieldAlert className="h-4 w-4 text-rose-300" />
            </div>
            <div className="mt-3 grid grid-cols-2 gap-2">
              <div className="rounded-lg border border-line/50 bg-panel2/40 p-2.5">
                <p className="text-[9px] uppercase tracking-wider text-faint">{t("common.total")}</p>
                <p className="mt-1 font-display text-lg font-semibold tabular-nums text-ink">{stats.data?.kev.total ?? "—"}</p>
              </div>
              <div className="rounded-lg border border-line/50 bg-panel2/40 p-2.5">
                <p className="text-[9px] uppercase tracking-wider text-faint">{t("intel.ransomware")}</p>
                <p className="mt-1 font-display text-lg font-semibold tabular-nums text-rose-300">{stats.data?.kev.ransomware ?? "—"}</p>
              </div>
            </div>
            <Button variant="secondary" size="sm" className="mt-3 w-full" onClick={() => setTab("kev")}>
              {t("intel.kevTitle")}
            </Button>
          </Card>
          <Card className="p-4">
            <h3 className="text-xs font-semibold text-ink">{t("intel.metrics")}</h3>
            <dl className="mt-3 space-y-2.5">
              <KeyValue label={t("common.source")} value={stats.data?.source || "NVD 2.0 + CISA KEV"} />
              <KeyValue label={t("intel.lastSync")} value={stats.data ? formatDateTime(stats.data.fetched_at, lang) : "—"} />
              <KeyValue label={t("intel.cvss")} value={`CVSS v3 / v2`} />
              <KeyValue label="Cache" value={stats.data ? `${stats.data.cache_hours}h` : "—"} />
              <KeyValue label={t("intel.matches")} value={String(stats.data?.finding_links ?? "—")} />
            </dl>
          </Card>
          <Card className="p-4">
            <div className="flex items-start gap-2">
              <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-300" />
              <div>
                <h3 className="text-xs font-semibold text-ink">{t("web.evidenceTitle")}</h3>
                <p className="mt-1 text-[10px] leading-relaxed text-muted">{t("intel.searchHint")}</p>
              </div>
            </div>
          </Card>
        </div>
      </div>

      <CveDetailModal
        open={Boolean(selectedCve)}
        onClose={closeCve}
        data={cveDetail.data}
        loading={cveDetail.isLoading}
        error={cveDetail.error}
        onRetry={() => void cveDetail.refetch()}
        onCorrelate={() => correlate.mutate()}
        correlating={correlate.isPending}
        canCorrelate={Boolean(canWrite && projectId)}
      />
    </div>
  );
}

function CveCard({ record, lang, onOpen }: { record: CveRecord; lang: Lang; onOpen: () => void }) {
  const { t } = useTranslation();
  return (
    <button
      type="button"
      onClick={onOpen}
      className="surface-card group w-full p-3.5 text-start transition hover:border-accent/25"
    >
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-[11px] font-semibold text-accent2">{record.id}</span>
        <span className={cn("font-display text-sm font-semibold tabular-nums", cvssColor(record.cvss_v3_score))}>
          {record.cvss_v3_score ?? "—"}
        </span>
        {record.cvss_severity ? <StatusBadge status={record.cvss_severity} /> : null}
        {record.kev ? <Badge tone="danger">{t("findings.kev")}</Badge> : null}
        {record.linked_findings ? <Badge tone="warning">{record.linked_findings} {t("nav.findings")}</Badge> : null}
        <span className="ms-auto text-[9px] text-faint">{record.published_at ? fromNow(record.published_at, lang) : ""}</span>
      </div>
      <p className="mt-2 line-clamp-2 text-[10px] leading-relaxed text-muted">{record.description}</p>
      <div className="mt-2 flex flex-wrap items-center gap-2 text-[8px] text-faint">
        {record.cwes.slice(0, 3).map((cwe) => (
          <span key={cwe} className="rounded border border-line bg-panel2 px-1.5 py-0.5 font-mono">{cwe}</span>
        ))}
        <span className="ms-auto inline-flex items-center gap-1 text-accent2 opacity-0 transition group-hover:opacity-100">
          {t("intel.viewCve")} <ArrowUpRight className="h-2.5 w-2.5" />
        </span>
      </div>
    </button>
  );
}

function CveDetailModal({
  open,
  onClose,
  data,
  loading,
  error,
  onRetry,
  onCorrelate,
  correlating,
  canCorrelate
}: {
  open: boolean;
  onClose: () => void;
  data?: CveDetailResponse;
  loading: boolean;
  error: unknown;
  onRetry: () => void;
  onCorrelate: () => void;
  correlating: boolean;
  canCorrelate: boolean;
}) {
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const cve = data?.cve;
  return (
    <Modal
      open={open}
      onOpenChange={(next) => !next && onClose()}
      title={cve ? <span className="font-mono text-sm">{cve.id}</span> : t("intel.title")}
      description={
        cve ? (
          <span className="flex flex-wrap items-center gap-2">
            <span className={cn("font-display font-semibold", cvssColor(cve.cvss_v3_score))}>CVSS {cve.cvss_v3_score ?? "—"}</span>
            {cve.cvss_severity ? <StatusBadge status={cve.cvss_severity} /> : null}
            {cve.kev ? <Badge tone="danger">{t("findings.kev")}</Badge> : null}
            <span className="text-[9px] text-faint">{formatDateTime(cve.published_at, lang)}</span>
          </span>
        ) : undefined
      }
      icon={Fingerprint}
      size="full"
      footer={
        cve ? (
          <>
            <CopyButton value={cve.id} label="CVE" />
            <a
              href={cve.source_url}
              target="_blank"
              rel="noreferrer noopener"
              className="inline-flex items-center gap-1 text-[10px] text-accent2 hover:underline"
            >
              {t("intel.viewCve")} <ExternalLink className="h-3 w-3" />
            </a>
            <Button
              variant="secondary"
              icon={Sparkles}
              loading={correlating}
              disabled={!canCorrelate}
              onClick={onCorrelate}
              className="ms-auto"
            >
              {t("intel.correlate")}
            </Button>
            <Button variant="secondary" onClick={onClose}>
              {t("common.close")}
            </Button>
          </>
        ) : undefined
      }
    >
      {loading ? (
        <div className="space-y-3">
          <Skeleton className="h-24 rounded-xl" />
          <Skeleton className="h-48 rounded-xl" />
        </div>
      ) : error || !data || !cve ? (
        <EmptyState
          icon={AlertTriangle}
          title={t("common.errorTitle")}
          description={error instanceof Error ? error.message : t("intel.liveDisabled")}
          action={
            <Button variant="secondary" onClick={onRetry}>
              {t("common.retry")}
            </Button>
          }
        />
      ) : (
        <div className="space-y-4">
          <div className="rounded-xl border border-line/60 bg-panel2/30 p-4">
            <p className="text-[11px] leading-relaxed text-muted">{cve.description}</p>
          </div>
          <div className="grid gap-4 lg:grid-cols-3">
            <div className="rounded-xl border border-line/60 bg-panel2/30 p-4">
              <h4 className="text-xs font-semibold text-ink">{t("intel.metrics")}</h4>
              <dl className="mt-3 grid gap-3">
                <KeyValue label="CVSS v3" value={String(cve.cvss_v3_score ?? "—")} />
                <KeyValue label="CVSS v2" value={String(cve.cvss_v2_score ?? "—")} />
                <KeyValue label={t("intel.cvssSeverity")} value={cve.cvss_severity || "—"} />
                <KeyValue label="Vector" value={cve.cvss_v3_vector || "—"} mono />
                <KeyValue label={t("intel.published")} value={formatDateTime(cve.published_at, lang)} />
                <KeyValue label={t("intel.modified")} value={formatDateTime(cve.modified_at, lang)} />
                <KeyValue label="Source" value={cve.source} />
              </dl>
            </div>
            <div className="space-y-4 lg:col-span-2">
              {cve.kev && cve.kev_detail ? (
                <div className="rounded-xl border border-rose-400/20 bg-rose-400/[0.04] p-4">
                  <div className="flex items-center gap-2">
                    <Siren className="h-4 w-4 text-rose-300" />
                    <h4 className="text-xs font-semibold text-rose-200">{t("intel.kevTitle")}</h4>
                    {cve.kev_detail.known_ransomware ? <Badge tone="danger">{t("intel.ransomware")}</Badge> : null}
                  </div>
                  <p className="mt-2 text-[10px] font-medium text-ink">{cve.kev_detail.vulnerability_name}</p>
                  <dl className="mt-2 grid gap-2 sm:grid-cols-2">
                    <KeyValue label={t("intel.affected")} value={`${cve.kev_detail.vendor_project} · ${cve.kev_detail.product}`} />
                    <KeyValue label={t("intel.kevDue")} value={formatDateTime(cve.kev_detail.due_date, lang)} />
                    <KeyValue label={t("intel.requiredAction")} value={cve.kev_detail.required_action || "—"} />
                  </dl>
                </div>
              ) : null}
              <div className="rounded-xl border border-line/60 bg-panel2/30 p-4">
                <h4 className="text-xs font-semibold text-ink">{t("intel.weaknesses")}</h4>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {cve.cwes.length ? (
                    cve.cwes.map((cwe) => (
                      <span key={cwe} className="rounded border border-line bg-panel2 px-2 py-0.5 font-mono text-[9px] text-muted">{cwe}</span>
                    ))
                  ) : (
                    <span className="text-[10px] text-faint">—</span>
                  )}
                </div>
              </div>
              <div className="rounded-xl border border-line/60 bg-panel2/30 p-4">
                <h4 className="text-xs font-semibold text-ink">{t("intel.affected")}</h4>
                {Array.isArray(cve.affected) && cve.affected.length ? (
                  <pre className="mt-2 max-h-40 overflow-auto rounded-lg bg-bg/60 p-2.5 font-mono text-[9px] text-muted">
                    {JSON.stringify(cve.affected, null, 2)}
                  </pre>
                ) : (
                  <p className="mt-2 text-[10px] text-faint">—</p>
                )}
              </div>
              <div className="rounded-xl border border-line/60 bg-panel2/30 p-4">
                <h4 className="text-xs font-semibold text-ink">{t("intel.references")}</h4>
                <ul className="mt-2 space-y-1.5">
                  {cve.references.length ? (
                    cve.references.slice(0, 20).map((reference) => (
                      <li key={reference}>
                        <a href={reference} target="_blank" rel="noreferrer noopener" className="break-all text-[9px] text-accent2 hover:underline">
                          {reference}
                        </a>
                      </li>
                    ))
                  ) : (
                    <li className="text-[10px] text-faint">—</li>
                  )}
                </ul>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2 text-[9px] text-faint">
            {data?.cache.fresh ? <CheckCircle2 className="h-3 w-3 text-emerald-300" /> : <Loader2 className="h-3 w-3" />}
            {data?.cache.hours}h cache · {t("intel.liveDisabled")}
          </div>
        </div>
      )}
    </Modal>
  );
}
