import { useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import {
  Activity,
  AlertTriangle,
  Boxes,
  CheckCircle2,
  ChevronRight,
  Eye,
  EyeOff,
  Fingerprint,
  Globe2,
  Layers3,
  Network,
  Plus,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  X
} from "lucide-react";
import { apiFetch, errorMessage } from "../lib/api";
import { cn, formatDateTime, fromNow, severityClasses } from "../lib/utils";
import { useProject } from "../context/ProjectContext";
import { useToast } from "../context/ToastContext";
import { labelOf, useDebouncedValue, useDocumentTitle, useMeta } from "../hooks";
import type {
  Asset,
  AssetChange,
  AssetDetail,
  AssetService,
  Lang,
  Paged
} from "../types";
import { ProjectGate } from "../components/common";
import {
  Badge,
  Button,
  Card,
  Checkbox,
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
  Skeleton,
  StatusBadge,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
  Textarea,
  type TableColumn
} from "../components/ui";

type TabKey = "inventory" | "changes";

export default function AssetsPage() {
  return (
    <ProjectGate>
      <AssetsContent />
    </ProjectGate>
  );
}

function AssetsContent() {
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const { selectedProject, canWrite } = useProject();
  const meta = useMeta();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [params, setParams] = useSearchParams();
  const projectId = selectedProject?.id || "";
  useDocumentTitle(t("assets.title"));

  const [tab, setTab] = useState<TabKey>("inventory");
  const [q, setQ] = useState("");
  const debouncedQ = useDebouncedValue(q, 300);
  const [type, setType] = useState("");
  const [risk, setRisk] = useState("");
  const [state, setState] = useState("");
  const [monitored, setMonitored] = useState("");
  const [limit, setLimit] = useState(25);
  const [offset, setOffset] = useState(0);
  const [createOpen, setCreateOpen] = useState(false);
  const [changeFilter, setChangeFilter] = useState<"all" | "unacknowledged" | "acknowledged">("unacknowledged");
  const selectedAsset = params.get("asset");

  useEffect(() => setOffset(0), [debouncedQ, type, risk, state, monitored, limit]);

  const assetsQuery = useQuery({
    queryKey: ["assets", projectId, debouncedQ, type, risk, state, monitored, limit, offset],
    queryFn: () =>
      apiFetch<Paged<Asset>>(`/projects/${projectId}/assets`, {
        query: {
          q: debouncedQ,
          type,
          risk,
          state,
          monitored: monitored === "" ? undefined : monitored,
          limit,
          offset
        }
      }),
    enabled: Boolean(projectId) && tab === "inventory"
  });

  const monitoredCount = useQuery({
    queryKey: ["asset-count", projectId, "monitored"],
    queryFn: () => apiFetch<Paged<Asset>>(`/projects/${projectId}/assets`, { query: { monitored: true, limit: 1 } }),
    enabled: Boolean(projectId)
  });
  const criticalCount = useQuery({
    queryKey: ["asset-count", projectId, "critical"],
    queryFn: () => apiFetch<Paged<Asset>>(`/projects/${projectId}/assets`, { query: { risk: "critical", limit: 1 } }),
    enabled: Boolean(projectId)
  });
  const highCount = useQuery({
    queryKey: ["asset-count", projectId, "high"],
    queryFn: () => apiFetch<Paged<Asset>>(`/projects/${projectId}/assets`, { query: { risk: "high", limit: 1 } }),
    enabled: Boolean(projectId)
  });
  const openChanges = useQuery({
    queryKey: ["asset-changes-count", projectId],
    queryFn: () => apiFetch<Paged<AssetChange>>(`/projects/${projectId}/changes`, { query: { acknowledged: false, limit: 1 } }),
    enabled: Boolean(projectId)
  });

  const changesQuery = useQuery({
    queryKey: ["asset-changes", projectId, changeFilter, limit, offset],
    queryFn: () =>
      apiFetch<Paged<AssetChange>>(`/projects/${projectId}/changes`, {
        query: {
          acknowledged: changeFilter === "all" ? undefined : changeFilter === "acknowledged",
          limit,
          offset
        }
      }),
    enabled: Boolean(projectId) && tab === "changes"
  });

  const acknowledge = useMutation({
    mutationFn: (changeId: string) =>
      apiFetch<{ change: AssetChange }>(`/projects/${projectId}/changes/${changeId}/ack`, { method: "POST" }),
    onSuccess: async () => {
      toast.toast({ title: t("asm.acknowledged"), variant: "success" });
      await queryClient.invalidateQueries({ queryKey: ["asset-changes", projectId] });
      await queryClient.invalidateQueries({ queryKey: ["asset-changes-count", projectId] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    },
    onError: (error) => toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" })
  });

  const acknowledgeAll = useMutation({
    mutationFn: () => apiFetch<{ acknowledged: number }>(`/projects/${projectId}/changes/ack-all`, { method: "POST" }),
    onSuccess: async (result) => {
      toast.toast({ title: t("asm.allAcknowledged"), description: String(result.acknowledged), variant: "success" });
      await queryClient.invalidateQueries({ queryKey: ["asset-changes", projectId] });
      await queryClient.invalidateQueries({ queryKey: ["asset-changes-count", projectId] });
    },
    onError: (error) => toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" })
  });

  const setAsset = (id: string | null) => {
    const next = new URLSearchParams(params);
    if (id) next.set("asset", id);
    else next.delete("asset");
    setParams(next, { replace: true });
  };

  const rows = assetsQuery.data?.items || [];
  const total = assetsQuery.data?.total || 0;
  const changeRows = changesQuery.data?.items || [];
  const changeTotal = changesQuery.data?.total || 0;

  const inventoryColumns: TableColumn<Asset>[] = [
    {
      key: "asset",
      header: t("assets.value"),
      render: (asset) => (
        <div className="flex items-center gap-2.5">
          <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-line bg-panel2 text-muted">
            {asset.type === "ip" || asset.type === "network" ? (
              <Network className="h-3.5 w-3.5" />
            ) : asset.type === "url" ? (
              <Globe2 className="h-3.5 w-3.5" />
            ) : (
              <Server className="h-3.5 w-3.5" />
            )}
          </span>
          <div className="min-w-0">
            <p className="truncate font-mono text-[11px] font-medium text-ink">{asset.value}</p>
            <p className="mt-0.5 text-[9px] text-faint">
              {labelOf(
                meta.data?.constants.asset_types.map((key) => ({ key, labels: { ar: key, en: key } })),
                asset.type,
                lang
              )}{" "}
              · {asset.source}
            </p>
          </div>
        </div>
      )
    },
    {
      key: "risk",
      header: t("assets.risk"),
      render: (asset) => (
        <div className="flex items-center gap-2">
          <span className={cn("badge", severityClasses[asset.risk_severity] || "border-line text-muted")}>
            {t(`severity.${asset.risk_severity}`)}
          </span>
          <span className="font-mono text-[9px] text-faint">{asset.risk_score}</span>
        </div>
      )
    },
    {
      key: "state",
      header: t("assets.state"),
      className: "hidden lg:table-cell",
      headerClassName: "hidden lg:table-cell",
      render: (asset) => <StatusBadge status={asset.state} />
    },
    {
      key: "services",
      header: t("assets.services"),
      render: (asset) => <span className="font-mono text-[11px] tabular-nums text-ink">{asset.services_count ?? 0}</span>
    },
    {
      key: "findings",
      header: t("assets.openFindings"),
      render: (asset) => (
        <span className={cn("font-mono text-[11px] tabular-nums", (asset.open_findings || 0) > 0 ? "text-rose-300" : "text-faint")}>
          {asset.open_findings ?? 0}
        </span>
      )
    },
    {
      key: "monitored",
      header: t("assets.monitored"),
      render: (asset) =>
        asset.is_monitored ? (
          <span className="inline-flex items-center gap-1 text-[9px] text-emerald-300">
            <Eye className="h-3 w-3" /> {t("common.yes")}
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 text-[9px] text-faint">
            <EyeOff className="h-3 w-3" /> {t("common.no")}
          </span>
        )
    },
    {
      key: "seen",
      header: t("assets.lastSeen"),
      className: "hidden xl:table-cell",
      headerClassName: "hidden xl:table-cell",
      render: (asset) => <span className="whitespace-nowrap text-[10px] text-muted">{fromNow(asset.last_seen_at, lang)}</span>
    }
  ];

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow={t("nav.security")}
        icon={Boxes}
        title={t("assets.title")}
        subtitle={t("assets.subtitle")}
        actions={
          <>
            <Button variant="secondary" icon={Activity} onClick={() => setTab("changes")}>
              {t("asm.changes")}
              {(openChanges.data?.total || 0) > 0 ? (
                <span className="ms-1 rounded-full bg-amber-400/15 px-1.5 py-0.5 text-[8px] font-semibold text-amber-300">
                  {openChanges.data?.total}
                </span>
              ) : null}
            </Button>
            <Button icon={Plus} onClick={() => setCreateOpen(true)} disabled={!canWrite}>
              {t("assets.add")}
            </Button>
          </>
        }
      />

      <section className="grid grid-cols-2 gap-2.5 xl:grid-cols-4">
        {[
          { label: t("assets.title"), value: assetsQuery.data?.total, icon: Boxes, tone: "text-accent" },
          { label: t("assets.monitored"), value: monitoredCount.data?.total, icon: Eye, tone: "text-accent2" },
          { label: t("severity.critical"), value: criticalCount.data?.total, icon: ShieldAlert, tone: "text-rose-300" },
          { label: t("asm.changes"), value: openChanges.data?.total, icon: Activity, tone: "text-amber-300" }
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

      <Tabs value={tab} onValueChange={(value) => setTab(value as TabKey)}>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <TabsList>
            <TabsTrigger value="inventory" icon={Layers3}>
              {t("asm.tabs.assets")}
            </TabsTrigger>
            <TabsTrigger value="changes" icon={Activity} count={openChanges.data?.total}>
              {t("asm.tabs.changes")}
            </TabsTrigger>
          </TabsList>
          {tab === "changes" ? (
            <div className="flex items-center gap-2">
              <Select
                value={changeFilter}
                onChange={(event) => {
                  setChangeFilter(event.target.value as typeof changeFilter);
                  setOffset(0);
                }}
                className="w-auto"
              >
                <option value="unacknowledged">{t("asm.acknowledge")}</option>
                <option value="acknowledged">{t("asm.acknowledged")}</option>
                <option value="all">{t("common.all")}</option>
              </Select>
              <Button
                size="sm"
                variant="secondary"
                loading={acknowledgeAll.isPending}
                disabled={!canWrite || !(openChanges.data?.total || 0)}
                onClick={() => acknowledgeAll.mutate()}
              >
                {t("asm.acknowledgeAll")}
              </Button>
            </div>
          ) : null}
        </div>

        <TabsContent value="inventory" className="mt-4">
          <Card className="overflow-hidden">
            <div className="flex flex-wrap items-center gap-2 border-b border-line/60 p-3.5">
              <div className="relative min-w-[220px] flex-1">
                <Search className="pointer-events-none absolute start-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-faint" />
                <Input
                  value={q}
                  onChange={(event) => setQ(event.target.value)}
                  placeholder={t("assets.searchPlaceholder")}
                  className="ps-9"
                />
                {q ? (
                  <button
                    type="button"
                    onClick={() => setQ("")}
                    className="absolute end-2.5 top-1/2 -translate-y-1/2 text-faint hover:text-ink"
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>
                ) : null}
              </div>
              <Select value={type} onChange={(event) => setType(event.target.value)} className="w-auto min-w-[130px]">
                <option value="">{t("assets.type")} · {t("common.all")}</option>
                {(meta.data?.constants.asset_types || []).map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </Select>
              <Select value={risk} onChange={(event) => setRisk(event.target.value)} className="w-auto min-w-[125px]">
                <option value="">{t("assets.risk")} · {t("common.all")}</option>
                {["critical", "high", "medium", "low", "info"].map((value) => (
                  <option key={value} value={value}>
                    {t(`severity.${value}`)}
                  </option>
                ))}
              </Select>
              <Select value={monitored} onChange={(event) => setMonitored(event.target.value)} className="w-auto min-w-[125px]">
                <option value="">{t("assets.monitored")} · {t("common.all")}</option>
                <option value="true">{t("common.yes")}</option>
                <option value="false">{t("common.no")}</option>
              </Select>
              {q || type || risk || monitored || state ? (
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => {
                    setQ("");
                    setType("");
                    setRisk("");
                    setState("");
                    setMonitored("");
                  }}
                >
                  {t("common.clear")}
                </Button>
              ) : null}
              <span className="ms-auto text-[9px] text-faint">{t("projects.total", { count: total })}</span>
            </div>

            {assetsQuery.isLoading ? (
              <div className="space-y-2 p-4">
                {[0, 1, 2, 3, 4].map((key) => (
                  <Skeleton key={key} className="h-12 rounded-lg" />
                ))}
              </div>
            ) : assetsQuery.isError ? (
              <EmptyState
                icon={AlertTriangle}
                title={t("common.errorTitle")}
                description={assetsQuery.error instanceof Error ? assetsQuery.error.message : t("common.errorDescription")}
                action={
                  <Button variant="secondary" onClick={() => void assetsQuery.refetch()}>
                    {t("common.retry")}
                  </Button>
                }
              />
            ) : rows.length === 0 ? (
              <EmptyState
                icon={Boxes}
                title={q || type || risk ? t("assets.noResults") : t("assets.emptyTitle")}
                description={q || type || risk ? undefined : t("assets.emptyBody")}
                action={
                  !q && !type && !risk ? (
                    <Button icon={Plus} onClick={() => setCreateOpen(true)} disabled={!canWrite}>
                      {t("assets.add")}
                    </Button>
                  ) : undefined
                }
              />
            ) : (
              <>
                <div className="hidden md:block">
                  <DataTable
                    columns={inventoryColumns}
                    rows={rows}
                    rowKey={(asset) => asset.id}
                    onRowClick={(asset) => setAsset(asset.id)}
                  />
                </div>
                <div className="divide-y divide-line/50 md:hidden">
                  {rows.map((asset) => (
                    <button
                      key={asset.id}
                      type="button"
                      onClick={() => setAsset(asset.id)}
                      className="flex w-full items-center gap-3 p-3.5 text-start hover:bg-panel2/50"
                    >
                      <span className={cn("h-2 w-2 shrink-0 rounded-full", {
                        "bg-rose-400": asset.risk_severity === "critical",
                        "bg-orange-400": asset.risk_severity === "high",
                        "bg-amber-400": asset.risk_severity === "medium",
                        "bg-sky-400": asset.risk_severity === "low",
                        "bg-slate-400": asset.risk_severity === "info"
                      })} />
                      <span className="min-w-0 flex-1">
                        <span className="block truncate font-mono text-[11px] text-ink">{asset.value}</span>
                        <span className="mt-0.5 block text-[9px] text-faint">
                          {asset.type} · {asset.services_count || 0} {t("assets.services")} · {asset.open_findings || 0} {t("nav.findings")}
                        </span>
                      </span>
                      <StatusBadge status={asset.state} />
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
        </TabsContent>

        <TabsContent value="changes" className="mt-4">
          <Card className="overflow-hidden">
            <div className="flex items-center justify-between border-b border-line/60 px-4 py-3">
              <div>
                <h3 className="text-xs font-semibold text-ink">{t("asm.recentChanges")}</h3>
                <p className="mt-0.5 text-[10px] text-muted">{t("asm.subtitle")}</p>
              </div>
              <span className="text-[9px] text-faint">{t("projects.total", { count: changeTotal })}</span>
            </div>
            {changesQuery.isLoading ? (
              <div className="space-y-2 p-4">
                {[0, 1, 2, 3].map((key) => (
                  <Skeleton key={key} className="h-12 rounded-lg" />
                ))}
              </div>
            ) : changesQuery.isError ? (
              <EmptyState
                icon={AlertTriangle}
                title={t("common.errorTitle")}
                description={changesQuery.error instanceof Error ? changesQuery.error.message : t("common.errorDescription")}
              />
            ) : changeRows.length === 0 ? (
              <EmptyState icon={Activity} title={t("asm.emptyChanges")} />
            ) : (
              <>
                <div className="divide-y divide-line/50">
                  {changeRows.map((change) => (
                    <div key={change.id} className="flex flex-wrap items-center gap-3 px-4 py-3.5">
                      <span className={cn("h-2 w-2 shrink-0 rounded-full", {
                        "bg-rose-400": change.severity === "critical",
                        "bg-orange-400": change.severity === "high",
                        "bg-amber-400": change.severity === "medium",
                        "bg-sky-400": change.severity === "low",
                        "bg-slate-400": change.severity === "info"
                      })} />
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <p className="text-[11px] font-medium text-ink">{change.summary}</p>
                          <Badge tone={change.acknowledged_at ? "success" : "warning"}>
                            {change.acknowledged_at ? t("asm.acknowledged") : t("asm.change")}
                          </Badge>
                        </div>
                        <button
                          type="button"
                          onClick={() => setAsset(change.asset_id)}
                          className="mt-1 inline-flex items-center gap-1 font-mono text-[9px] text-accent2 hover:underline"
                        >
                          {change.asset_id.slice(0, 12)} <ChevronRight className="h-2.5 w-2.5" />
                        </button>
                        <span className="ms-2 text-[9px] text-faint">
                          {change.kind} · {fromNow(change.detected_at, lang)}
                        </span>
                      </div>
                      <StatusBadge status={change.severity} label={t(`severity.${change.severity}`)} />
                      {!change.acknowledged_at && canWrite ? (
                        <Button
                          size="sm"
                          variant="secondary"
                          icon={CheckCircle2}
                          loading={acknowledge.isPending && acknowledge.variables === change.id}
                          onClick={() => acknowledge.mutate(change.id)}
                        >
                          {t("asm.acknowledge")}
                        </Button>
                      ) : null}
                    </div>
                  ))}
                </div>
                <Pagination
                  page={Math.floor(offset / limit) + 1}
                  pageSize={limit}
                  total={changeTotal}
                  onPageChange={(page) => setOffset((page - 1) * limit)}
                  labels={{ previous: t("common.previous"), next: t("common.next"), page: t("common.page"), of: t("common.of") }}
                />
              </>
            )}
          </Card>
        </TabsContent>
      </Tabs>

      <CreateAssetModal
        open={createOpen}
        onOpenChange={setCreateOpen}
        projectId={projectId}
        onCreated={(asset) => {
          setCreateOpen(false);
          setAsset(asset.id);
          void queryClient.invalidateQueries({ queryKey: ["assets", projectId] });
          void queryClient.invalidateQueries({ queryKey: ["asset-count", projectId] });
          void queryClient.invalidateQueries({ queryKey: ["dashboard"] });
        }}
      />
      <AssetDetailModal
        assetId={selectedAsset}
        open={Boolean(selectedAsset)}
        onClose={() => setAsset(null)}
        projectId={projectId}
      />
    </div>
  );
}

function CreateAssetModal({
  open,
  onOpenChange,
  projectId,
  onCreated
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  projectId: string;
  onCreated: (asset: Asset) => void;
}) {
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const meta = useMeta();
  const toast = useToast();
  const [type, setType] = useState("domain");
  const [value, setValue] = useState("");
  const [tags, setTags] = useState("");
  const [notes, setNotes] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    if (!open) return;
    setType("domain");
    setValue("");
    setTags("");
    setNotes("");
    setError("");
  }, [open]);

  const create = useMutation({
    mutationFn: () =>
      apiFetch<{ asset: Asset; created: boolean }>(`/projects/${projectId}/assets`, {
        method: "POST",
        body: {
          type,
          value: value.trim(),
          tags: tags.split(",").map((tag) => tag.trim()).filter(Boolean),
          notes: notes.trim()
        }
      }),
    onSuccess: (result) => {
      toast.toast({ title: t("assets.created"), variant: "success" });
      onCreated(result.asset);
    },
    onError: (caught) => setError(errorMessage(caught))
  });

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title={t("assets.manualAdd")}
      description={t("assets.manualHint")}
      icon={Plus}
      size="md"
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            {t("common.cancel")}
          </Button>
          <Button
            icon={Plus}
            loading={create.isPending}
            disabled={!value.trim()}
            onClick={() => {
              setError("");
              create.mutate();
            }}
          >
            {t("common.add")}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label={t("assets.type")} required>
          <Select value={type} onChange={(event) => setType(event.target.value)}>
            {(meta.data?.constants.asset_types || ["domain", "host", "ip", "network", "url"]).map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </Select>
        </Field>
        <Field
          label={t("assets.value")}
          required
          hint={lang === "ar" ? "أدخل نطاقًا أو عنوان IP أو CIDR مطابقًا للنطاق المصرح." : "Enter a hostname, IP, CIDR or URL. Matching scope is still required to assess it."}
        >
          <Input
            value={value}
            onChange={(event) => setValue(event.target.value)}
            placeholder={t("projects.scopeTypePlaceholder")}
            className="font-mono"
            maxLength={512}
          />
        </Field>
        <Field label={t("common.tags")} hint={t("common.optional")}>
          <Input value={tags} onChange={(event) => setTags(event.target.value)} placeholder="production, edge" />
        </Field>
        <Field label={t("common.notes")} hint={t("common.optional")}>
          <Textarea value={notes} onChange={(event) => setNotes(event.target.value)} rows={3} maxLength={2000} />
        </Field>
        {error ? <InlineAlert tone="danger">{error}</InlineAlert> : null}
      </div>
    </Modal>
  );
}

function AssetDetailModal({
  assetId,
  open,
  onClose,
  projectId
}: {
  assetId: string | null;
  open: boolean;
  onClose: () => void;
  projectId: string;
}) {
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const meta = useMeta();
  const toast = useToast();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { canWrite } = useProject();
  const [tab, setTab] = useState("overview");
  const [confirmDelete, setConfirmDelete] = useState(false);

  const detail = useQuery({
    queryKey: ["asset", projectId, assetId],
    queryFn: () => apiFetch<AssetDetail>(`/projects/${projectId}/assets/${assetId}`),
    enabled: open && Boolean(projectId && assetId)
  });

  useEffect(() => {
    if (open) {
      setTab("overview");
      setConfirmDelete(false);
    }
  }, [open, assetId]);

  const toggleMonitor = useMutation({
    mutationFn: (monitored: boolean) =>
      apiFetch<{ asset: Asset }>(`/projects/${projectId}/assets/${assetId}`, {
        method: "PATCH",
        body: { is_monitored: monitored }
      }),
    onSuccess: async () => {
      toast.toast({ title: t("assets.monitorUpdated"), variant: "success" });
      await queryClient.invalidateQueries({ queryKey: ["asset", projectId, assetId] });
      await queryClient.invalidateQueries({ queryKey: ["assets", projectId] });
      await queryClient.invalidateQueries({ queryKey: ["asset-count", projectId] });
    },
    onError: (error) => toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" })
  });

  const remove = useMutation({
    mutationFn: () => apiFetch<{ deleted: boolean }>(`/projects/${projectId}/assets/${assetId}`, { method: "DELETE" }),
    onSuccess: async () => {
      toast.toast({ title: t("toasts.deleted"), variant: "success" });
      onClose();
      await queryClient.invalidateQueries({ queryKey: ["assets", projectId] });
      await queryClient.invalidateQueries({ queryKey: ["asset-count", projectId] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    },
    onError: (error) => toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" })
  });

  const data = detail.data;
  const asset = data?.asset;

  const serviceColumns: TableColumn<AssetService>[] = useMemo(
    () => [
      {
        key: "port",
        header: t("network.port"),
        render: (service) => (
          <span className="font-mono text-[11px] tabular-nums text-ink">
            {service.port}/{service.protocol}
          </span>
        )
      },
      {
        key: "service",
        header: t("network.service"),
        render: (service) => (
          <div>
            <p className="text-[10px] font-medium text-ink">{service.name || "—"}</p>
            <p className="mt-0.5 text-[9px] text-faint">{[service.product, service.version].filter(Boolean).join(" ") || "—"}</p>
          </div>
        )
      },
      {
        key: "state",
        header: t("common.status"),
        render: (service) => <StatusBadge status={service.state} />
      },
      {
        key: "findings",
        header: t("nav.findings"),
        render: (service) => (
          <span className={cn("font-mono text-[10px]", service.open_findings ? "text-rose-300" : "text-faint")}>
            {service.open_findings || 0}
          </span>
        )
      },
      {
        key: "last",
        header: t("common.lastSeen"),
        render: (service) => <span className="whitespace-nowrap text-[9px] text-faint">{fromNow(service.last_seen_at, lang)}</span>
      }
    ],
    [lang, t]
  );

  return (
    <Modal
      open={open}
      onOpenChange={(next) => {
        if (!next) onClose();
      }}
      title={
        asset ? (
          <span className="flex flex-wrap items-center gap-2 font-mono text-sm">
            {asset.value}
            <span className={cn("badge", severityClasses[asset.risk_severity] || "border-line text-muted")}>
              {t(`severity.${asset.risk_severity}`)}
            </span>
          </span>
        ) : (
          t("assets.detailTitle")
        )
      }
      description={
        asset ? (
          <span>
            {asset.type} · {asset.source} · {t("assets.riskScore")}: {asset.risk_score}
          </span>
        ) : undefined
      }
      icon={Boxes}
      size="full"
      footer={
        data && asset ? (
          <>
            {canWrite ? (
              <Button
                variant={asset.is_monitored ? "secondary" : "primary"}
                size="sm"
                icon={asset.is_monitored ? EyeOff : Eye}
                loading={toggleMonitor.isPending}
                onClick={() => toggleMonitor.mutate(!asset.is_monitored)}
              >
                {asset.is_monitored ? t("assets.unmarkMonitored") : t("assets.markMonitored")}
              </Button>
            ) : null}
            {canWrite ? (
              confirmDelete ? (
                <div className="flex items-center gap-2">
                  <span className="text-[10px] text-rose-300">{t("common.delete")}?</span>
                  <Button variant="danger" size="sm" loading={remove.isPending} onClick={() => remove.mutate()}>
                    {t("common.confirm")}
                  </Button>
                  <Button variant="ghost" size="sm" onClick={() => setConfirmDelete(false)}>
                    {t("common.cancel")}
                  </Button>
                </div>
              ) : (
                <Button variant="ghost" size="sm" icon={X} onClick={() => setConfirmDelete(true)}>
                  {t("common.delete")}
                </Button>
              )
            ) : null}
            <Button variant="secondary" size="sm" onClick={onClose} className="ms-auto">
              {t("common.close")}
            </Button>
          </>
        ) : undefined
      }
    >
      {detail.isLoading ? (
        <div className="space-y-4">
          <Skeleton className="h-24 rounded-xl" />
          <Skeleton className="h-64 rounded-xl" />
        </div>
      ) : detail.isError || !data || !asset ? (
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
            {[
              { label: t("assets.riskScore"), value: String(asset.risk_score) },
              { label: t("assets.services"), value: String(data.services.length) },
              { label: t("assets.openFindings"), value: String(data.findings.length) },
              { label: t("assets.changes"), value: String(data.changes.length) }
            ].map((item) => (
              <div key={item.label} className="rounded-xl border border-line/60 bg-panel2/40 p-3">
                <p className="text-[9px] uppercase tracking-[0.1em] text-faint">{item.label}</p>
                <p className="mt-1.5 font-display text-xl font-semibold tabular-nums text-ink">{item.value}</p>
              </div>
            ))}
          </div>

          <Tabs value={tab} onValueChange={setTab}>
            <TabsList>
              <TabsTrigger value="overview" icon={Fingerprint}>
                {t("common.overview")}
              </TabsTrigger>
              <TabsTrigger value="services" icon={Server} count={data.services.length}>
                {t("assets.ports")}
              </TabsTrigger>
              <TabsTrigger value="findings" icon={ShieldAlert} count={data.findings.length}>
                {t("assets.findings")}
              </TabsTrigger>
              <TabsTrigger value="changes" icon={Activity} count={data.changes.length}>
                {t("assets.changes")}
              </TabsTrigger>
            </TabsList>

            <TabsContent value="overview" className="mt-4 grid gap-4 lg:grid-cols-2">
              <div className="rounded-xl border border-line/60 bg-panel2/30 p-4">
                <h4 className="text-xs font-semibold text-ink">{t("common.details")}</h4>
                <dl className="mt-3 grid gap-3 sm:grid-cols-2">
                  <KeyValue label={t("assets.value")} value={asset.value} mono />
                  <KeyValue label={t("assets.type")} value={asset.type} />
                  <KeyValue label={t("assets.state")} value={<StatusBadge status={asset.state} />} />
                  <KeyValue label={t("assets.discoveredBy")} value={asset.source} />
                  <KeyValue label={t("assets.firstSeen")} value={formatDateTime(asset.first_seen_at, lang)} />
                  <KeyValue label={t("assets.lastSeen")} value={formatDateTime(asset.last_seen_at, lang)} />
                  <KeyValue label={t("assets.lastScanned")} value={formatDateTime(asset.last_scanned_at, lang)} />
                  <KeyValue label={t("assets.monitored")} value={asset.is_monitored ? t("common.yes") : t("common.no")} />
                </dl>
                {asset.tags.length ? (
                  <div className="mt-4">
                    <p className="text-[9px] uppercase tracking-wider text-faint">{t("assets.tags")}</p>
                    <div className="mt-1.5 flex flex-wrap gap-1.5">
                      {asset.tags.map((tag) => (
                        <span key={tag} className="rounded-md border border-line bg-panel2 px-2 py-0.5 text-[9px] text-muted">
                          {tag}
                        </span>
                      ))}
                    </div>
                  </div>
                ) : null}
                {typeof asset.meta.notes === "string" && asset.meta.notes ? (
                  <div className="mt-4">
                    <p className="text-[9px] uppercase tracking-wider text-faint">{t("common.notes")}</p>
                    <p className="mt-1 whitespace-pre-wrap text-[10px] leading-relaxed text-muted">{asset.meta.notes}</p>
                  </div>
                ) : null}
              </div>
              <div className="space-y-4">
                <div className="rounded-xl border border-line/60 bg-panel2/30 p-4">
                  <h4 className="text-xs font-semibold text-ink">{t("assets.relationships")}</h4>
                  <dl className="mt-3 grid gap-3">
                    <KeyValue
                      label={t("assets.parent")}
                      value={
                        data.parent ? (
                          <span className="font-mono text-accent2">{data.parent.value}</span>
                        ) : (
                          t("common.none")
                        )
                      }
                    />
                    <KeyValue label={t("assets.children")} value={String(data.children.length)} />
                  </dl>
                  {data.children.length ? (
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {data.children.slice(0, 20).map((child) => (
                        <span key={child.id} className="rounded border border-line bg-panel px-1.5 py-0.5 font-mono text-[9px] text-muted">
                          {child.value}
                        </span>
                      ))}
                    </div>
                  ) : null}
                </div>
                <div className="rounded-xl border border-line/60 bg-panel2/30 p-4">
                  <h4 className="text-xs font-semibold text-ink">{t("assets.risk")}</h4>
                  <div className="mt-2 flex items-center gap-3">
                    <span className={cn("badge", severityClasses[asset.risk_severity] || "border-line text-muted")}>
                      {t(`severity.${asset.risk_severity}`)}
                    </span>
                    <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-panel3">
                      <div
                        className={cn("h-full rounded-full", {
                          "bg-rose-400": asset.risk_severity === "critical",
                          "bg-orange-400": asset.risk_severity === "high",
                          "bg-amber-400": asset.risk_severity === "medium",
                          "bg-sky-400": asset.risk_severity === "low",
                          "bg-slate-400": asset.risk_severity === "info"
                        })}
                        style={{ width: `${Math.max(0, Math.min(100, asset.risk_score))}%` }}
                      />
                    </div>
                    <span className="font-mono text-[10px] text-faint">{asset.risk_score}</span>
                  </div>
                  <p className="mt-2 text-[9px] leading-relaxed text-faint">
                    {t("asm.riskAssets")} · {t("dashboard.topAssetsSubtitle")}
                  </p>
                </div>
              </div>
            </TabsContent>

            <TabsContent value="services" className="mt-4">
              {data.services.length ? (
                <DataTable columns={serviceColumns} rows={data.services} rowKey={(service) => service.id} />
              ) : (
                <EmptyState icon={Server} title={t("assets.noServices")} />
              )}
            </TabsContent>

            <TabsContent value="findings" className="mt-4">
              {data.findings.length ? (
                <div className="divide-y divide-line/50 rounded-xl border border-line/60">
                  {data.findings.map((finding) => (
                    <button
                      key={finding.id}
                      type="button"
                      onClick={() => {
                        onClose();
                        navigate(`/findings?finding=${finding.id}`);
                      }}
                      className="flex w-full items-center gap-2.5 p-3 text-start transition hover:bg-panel2/50"
                    >
                      <span className={cn("h-2 w-2 shrink-0 rounded-full", {
                        "bg-rose-400": finding.severity === "critical",
                        "bg-orange-400": finding.severity === "high",
                        "bg-amber-400": finding.severity === "medium",
                        "bg-sky-400": finding.severity === "low",
                        "bg-slate-400": finding.severity === "info"
                      })} />
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-[10px] font-medium text-ink">{finding.title}</p>
                        <p className="mt-0.5 truncate font-mono text-[9px] text-faint">
                          {finding.category} · {finding.target}
                        </p>
                      </div>
                      <StatusBadge status={finding.status} />
                      <ChevronRight className="h-3 w-3 text-faint rtl:rotate-180" />
                    </button>
                  ))}
                </div>
              ) : (
                <EmptyState icon={ShieldCheck} title={t("assets.noFindings")} />
              )}
            </TabsContent>

            <TabsContent value="changes" className="mt-4">
              {data.changes.length ? (
                <div className="space-y-2">
                  {data.changes.map((change) => (
                    <div key={change.id} className="rounded-xl border border-line/60 bg-panel2/30 p-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <StatusBadge status={change.severity} label={t(`severity.${change.severity}`)} />
                        <span className="text-[10px] font-medium text-ink">{change.summary}</span>
                        <span className="ms-auto text-[9px] text-faint">{fromNow(change.detected_at, lang)}</span>
                      </div>
                      <p className="mt-1 text-[9px] text-faint">{change.kind}</p>
                      {Object.keys(change.before || {}).length || Object.keys(change.after || {}).length ? (
                        <pre className="mt-2 max-h-32 overflow-auto rounded-lg bg-bg/60 p-2 font-mono text-[8px] text-muted">
                          {JSON.stringify({ before: change.before, after: change.after }, null, 2)}
                        </pre>
                      ) : null}
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState icon={Activity} title={t("assets.noChanges")} />
              )}
            </TabsContent>
          </Tabs>
        </div>
      )}
    </Modal>
  );
}
