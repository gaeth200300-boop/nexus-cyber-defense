import { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import {
  Activity,
  AlertTriangle,
  Archive,
  ArrowLeft,
  ArrowUpRight,
  Boxes,
  Bug,
  CalendarClock,
  CheckCircle2,
  ChevronRight,
  CircleSlash,
  Eye,
  EyeOff,
  FileSearch,
  Fingerprint,
  Globe2,
  KeyRound,
  LockKeyhole,
  Plus,
  RefreshCw,
  Save,
  Server,
  ShieldCheck,
  Trash2,
  UserPlus,
  Users
} from "lucide-react";
import { apiFetch, errorMessage } from "../lib/api";
import { cn, formatBytes, formatDateTime, fromNow } from "../lib/utils";
import { useAuth } from "../context/AuthContext";
import { useProject } from "../context/ProjectContext";
import { useToast } from "../context/ToastContext";
import { useDocumentTitle, useMeta } from "../hooks";
import type { Lang, Project, ProjectMember, Scope } from "../types";
import { BarChart, DonutChart } from "../components/charts";
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
  Progress,
  Select,
  Skeleton,
  StatusBadge,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
  Textarea
} from "../components/ui";

interface ProjectDetailResponse {
  project: Project;
}

interface SummaryResponse {
  project: Project;
  assets: { total: number; active: number; by_type: Record<string, number>; by_risk: Record<string, number> };
  services: { open: number };
  findings: {
    open_total: number;
    by_severity: Record<string, number>;
    by_status: Record<string, number>;
    assets_with_open_findings: number;
  };
  scans: {
    total: number;
    by_status: Record<string, number>;
    recent: { id: string; name: string; kind: string; profile: string; status: string; progress: number; created_at: string; finished_at: string | null }[];
  };
  jobs: { queued?: number; running?: number; failed?: number; [key: string]: unknown };
  alerts: { open: number };
  incidents: { open: number };
  reports: { total: number };
  soc: { sources: number; events: number };
  policy: { authorization_scopes: number; allow_private_targets: boolean };
  last_scan_at: string | null;
}

interface MembersResponse {
  items: ProjectMember[];
}

interface ScopesResponse {
  items: Scope[];
  policy: {
    global_private_targets: boolean;
    project_private_targets: boolean;
    active_scanning_enabled: boolean;
    verification_methods: string[];
  };
}

interface VerifyChallengeResponse {
  instructions: Record<string, string>;
  scope: Scope;
}

interface VerifyResponse {
  verified: boolean;
  message: string;
  scope: Scope;
}

const severityColors: Record<string, string> = {
  critical: "#f43f5e",
  high: "#fb923c",
  medium: "#f59e0b",
  low: "#38bdf8",
  info: "#64748b"
};

const riskLabels: Record<string, string> = {
  critical: "#f43f5e",
  high: "#fb923c",
  medium: "#f59e0b",
  low: "#38bdf8",
  none: "#475569"
};

export default function ProjectDetailPage() {
  const { projectId = "" } = useParams();
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const navigate = useNavigate();
  const toast = useToast();
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const { projects, selectedProject, setSelectedProject } = useProject();
  const meta = useMeta();
  const [tab, setTab] = useState("overview");
  const [scopeOpen, setScopeOpen] = useState(false);
  const [memberOpen, setMemberOpen] = useState(false);
  const [verifyTarget, setVerifyTarget] = useState<Scope | null>(null);
  const [archiveOpen, setArchiveOpen] = useState(false);
  const [rowError, setRowError] = useState("");

  useEffect(() => {
    if (projectId && projects.some((item) => item.id === projectId) && selectedProject?.id !== projectId) {
      setSelectedProject(projectId);
    }
  }, [projectId, projects, selectedProject?.id, setSelectedProject]);

  const detail = useQuery({
    queryKey: ["project", projectId],
    queryFn: () => apiFetch<ProjectDetailResponse>(`/projects/${projectId}`),
    enabled: Boolean(projectId)
  });
  const summary = useQuery({
    queryKey: ["project-summary", projectId],
    queryFn: () => apiFetch<SummaryResponse>(`/projects/${projectId}/summary`),
    enabled: Boolean(projectId)
  });
  const members = useQuery({
    queryKey: ["project-members", projectId],
    queryFn: () => apiFetch<MembersResponse>(`/projects/${projectId}/members`),
    enabled: Boolean(projectId)
  });
  const scopes = useQuery({
    queryKey: ["project-scopes", projectId],
    queryFn: () => apiFetch<ScopesResponse>(`/projects/${projectId}/scopes`),
    enabled: Boolean(projectId)
  });

  const project = detail.data?.project || (selectedProject?.id === projectId ? selectedProject : null);
  const role = project?.role || "";
  const canWrite = ["owner", "admin", "analyst"].includes(role);
  const isAdmin = ["owner", "admin"].includes(role);
  const isOwner = role === "owner" || user?.role === "owner";
  const isGlobalAdmin = ["owner", "admin"].includes(user?.role || "");
  useDocumentTitle(project?.name || t("projects.title"));

  const kindLabel = (value?: string) => {
    const item = meta.data?.constants.project_kinds.find((entry) => entry.key === value);
    return item ? (lang === "ar" ? item.labels.ar : item.labels.en) : value || "—";
  };
  const roleLabel = (value: string) => {
    const item = meta.data?.constants.role_labels.find((entry) => entry.key === value);
    return item ? (lang === "ar" ? item.labels.ar : item.labels.en) : value;
  };

  const toggleScope = useMutation({
    mutationFn: (scopeId: string) =>
      apiFetch<{ scope: Scope }>(`/projects/${projectId}/scopes/${scopeId}`, { method: "DELETE" }),
    onSuccess: async () => {
      toast.toast({ title: t("projects.updated"), variant: "success" });
      await queryClient.invalidateQueries({ queryKey: ["project-scopes", projectId] });
      await queryClient.invalidateQueries({ queryKey: ["project-summary", projectId] });
    },
    onError: (error) => setRowError(errorMessage(error))
  });

  const updateScope = useMutation({
    mutationFn: ({ scopeId, body }: { scopeId: string; body: Record<string, unknown> }) =>
      apiFetch<{ scope: Scope }>(`/projects/${projectId}/scopes/${scopeId}`, { method: "PATCH", body }),
    onSuccess: async () => {
      toast.toast({ title: t("projects.updated"), variant: "success" });
      await queryClient.invalidateQueries({ queryKey: ["project-scopes", projectId] });
    },
    onError: (error) => setRowError(errorMessage(error))
  });

  const updateMember = useMutation({
    mutationFn: ({ memberId, role: nextRole }: { memberId: string; role: string }) =>
      apiFetch<{ member: ProjectMember }>(`/projects/${projectId}/members/${memberId}`, {
        method: "PATCH",
        body: { role: nextRole }
      }),
    onSuccess: async () => {
      toast.toast({ title: t("projects.memberUpdated"), variant: "success" });
      await queryClient.invalidateQueries({ queryKey: ["project-members", projectId] });
    },
    onError: (error) => setRowError(errorMessage(error))
  });

  const removeMember = useMutation({
    mutationFn: (memberId: string) =>
      apiFetch<null>(`/projects/${projectId}/members/${memberId}`, { method: "DELETE" }),
    onSuccess: async () => {
      toast.toast({ title: t("projects.memberRemoved"), variant: "success" });
      await queryClient.invalidateQueries({ queryKey: ["project-members", projectId] });
    },
    onError: (error) => setRowError(errorMessage(error))
  });

  const saveSettings = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      apiFetch<{ project: Project }>(`/projects/${projectId}`, { method: "PATCH", body }),
    onSuccess: async () => {
      toast.toast({ title: t("projects.updated"), variant: "success" });
      await queryClient.invalidateQueries({ queryKey: ["project", projectId] });
      await queryClient.invalidateQueries({ queryKey: ["projects"] });
      await queryClient.invalidateQueries({ queryKey: ["project-summary", projectId] });
      await queryClient.invalidateQueries({ queryKey: ["project-scopes", projectId] });
    },
    onError: (error) => setRowError(errorMessage(error))
  });

  const archive = useMutation({
    mutationFn: () => apiFetch<null>(`/projects/${projectId}`, { method: "DELETE" }),
    onSuccess: async () => {
      toast.toast({ title: t("projects.archived"), variant: "success" });
      await queryClient.invalidateQueries({ queryKey: ["projects"] });
      navigate("/projects");
    },
    onError: (error) => setRowError(errorMessage(error))
  });

  const findingsChart = useMemo(() => {
    const counts = summary.data?.findings.by_severity || {};
    return {
      labels: ["critical", "high", "medium", "low", "info"].map((severity) => t(`severity.${severity}`)),
      values: ["critical", "high", "medium", "low", "info"].map((severity) => counts[severity] || 0)
    };
  }, [summary.data?.findings.by_severity, t]);

  const riskChart = useMemo(
    () =>
      Object.entries(summary.data?.assets.by_risk || {})
        .filter(([, value]) => value > 0)
        .map(([risk, value]) => ({
          name: risk === "none" ? t("common.none") : t(`severity.${risk}`),
          value,
          color: riskLabels[risk] || "#64748b"
        })),
    [summary.data?.assets.by_risk, t]
  );

  if (detail.isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-36 rounded-2xl" />
        <Skeleton className="h-20 rounded-xl" />
        <Skeleton className="h-72 rounded-2xl" />
      </div>
    );
  }

  if (detail.isError || !project) {
    return (
      <Card className="p-2">
        <EmptyState
          icon={ShieldCheck}
          title={t("projects.notFound")}
          description={detail.error instanceof Error ? detail.error.message : t("common.errorDescription")}
          action={
            <Button variant="secondary" icon={ArrowLeft} onClick={() => navigate("/projects")}>
              {t("projects.viewAll")}
            </Button>
          }
        />
      </Card>
    );
  }

  const scopeRows = scopes.data?.items || [];
  const memberRows = members.data?.items || [];
  const activeScopes = scopeRows.filter((scope) => scope.is_active && !scope.expired).length;
  const verifiedScopes = scopeRows.filter((scope) => scope.verified_method !== "none" && scope.verified_at).length;

  return (
    <div className="space-y-5">
      <div className="relative overflow-hidden rounded-2xl border border-line/60 bg-gradient-to-br from-accent/[0.07] via-panel to-accent2/[0.04] p-5">
        <div className="absolute -end-10 -top-10 h-44 w-44 rounded-full bg-accent/10 blur-3xl" />
        <div className="relative flex flex-wrap items-start gap-4">
          <span className="grid h-14 w-14 shrink-0 place-items-center rounded-2xl border border-accent/20 bg-accent/[0.08] text-accent">
            <ShieldCheck className="h-7 w-7" />
          </span>
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <button type="button" onClick={() => navigate("/projects")} className="text-[9px] text-faint hover:text-ink">
                {t("projects.viewAll")}
              </button>
              <ChevronRight className="h-3 w-3 text-faint rtl:rotate-180" />
              <Badge tone="info">{kindLabel(project.kind)}</Badge>
              <Badge tone="accent">{roleLabel(role)}</Badge>
              {project.archived ? <Badge tone="default">{t("projects.archivedBadge")}</Badge> : null}
            </div>
            <h1 className="mt-1 font-display text-2xl font-semibold text-ink">{project.name}</h1>
            <p className="mt-1 max-w-3xl text-[11px] leading-relaxed text-muted">{project.description || t("common.noDescription")}</p>
            <div className="mt-2 flex flex-wrap items-center gap-3 text-[8px] text-faint">
              <span className="font-mono">{project.slug}</span>
              <span>· {t("projects.createdAt")} {formatDateTime(project.created_at, lang)}</span>
              <span>· {t("projects.updatedAt")} {fromNow(project.updated_at, lang)}</span>
              <span>· {t("projects.retention")} {project.retention_days}</span>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="secondary" icon={Activity} onClick={() => navigate("/scans")} disabled={!canWrite || project.archived}>
              {t("nav.scans")}
            </Button>
            <Button variant="secondary" icon={Plus} onClick={() => setScopeOpen(true)} disabled={!isAdmin || project.archived}>
              {t("projects.addScope")}
            </Button>
          </div>
        </div>
        <div className="relative mt-4 flex flex-wrap gap-2">
          <Badge tone={activeScopes ? "success" : "warning"} dot>{activeScopes} {t("projects.activeScope")}</Badge>
          <Badge tone={verifiedScopes ? "success" : "warning"} dot>{verifiedScopes} {t("projects.verified")}</Badge>
          <Badge tone={project.allow_private_targets ? "warning" : "default"}>{t("projects.allowPrivate")}: {project.allow_private_targets ? t("common.enabled") : t("common.disabled")}</Badge>
          <Badge tone="default">{t("projects.retention")}: {project.retention_days}</Badge>
        </div>
      </div>

      <section className="grid grid-cols-2 gap-2.5 xl:grid-cols-5">
        {[
          { label: t("projects.assets"), value: summary.data?.assets.total, icon: Boxes, tone: "text-accent" },
          { label: t("projects.openFindings"), value: summary.data?.findings.open_total, icon: Bug, tone: "text-rose-300" },
          { label: t("projects.activeScans"), value: (summary.data?.scans.by_status.queued || 0) + (summary.data?.scans.by_status.running || 0), icon: Activity, tone: "text-amber-300" },
          { label: t("soc.openAlerts"), value: summary.data?.alerts.open, icon: AlertTriangle, tone: "text-orange-300" },
          { label: t("reports.title"), value: summary.data?.reports.total, icon: FileSearch, tone: "text-accent2" }
        ].map((card) => (
          <div key={card.label} className="surface-card p-3.5">
            <div className="flex items-center justify-between">
              <span className="text-[9px] font-semibold uppercase tracking-[0.1em] text-muted">{card.label}</span>
              <card.icon className={cn("h-4 w-4", card.tone)} />
            </div>
            <p className="mt-2 font-display text-2xl font-semibold tabular-nums text-ink">{card.value ?? "—"}</p>
          </div>
        ))}
      </section>

      {rowError ? <InlineAlert tone="danger" title={t("common.errorTitle")}>{rowError}</InlineAlert> : null}

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="overview" icon={Eye}>{t("projects.tabs.overview")}</TabsTrigger>
          <TabsTrigger value="scopes" icon={ShieldCheck} count={scopeRows.length}>{t("projects.tabs.scopes")}</TabsTrigger>
          <TabsTrigger value="members" icon={Users} count={memberRows.length}>{t("projects.tabs.members")}</TabsTrigger>
          <TabsTrigger value="settings" icon={Save}>{t("projects.tabs.settings")}</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="mt-4 space-y-4">
          <div className="grid gap-4 xl:grid-cols-12">
            <Card className="p-4 xl:col-span-5">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-xs font-semibold text-ink">{t("assets.risk")}</h3>
                  <p className="mt-0.5 text-[10px] text-muted">{t("projects.assets")}</p>
                </div>
                <Boxes className="h-4 w-4 text-accent" />
              </div>
              {riskChart.length ? (
                <DonutChart data={riskChart} height={250} centerLabel={t("projects.assets")} centerValue={summary.data?.assets.total || 0} />
              ) : (
                <EmptyState icon={Boxes} title={t("assets.empty")} description={t("assets.subtitle")} />
              )}
            </Card>
            <Card className="p-4 xl:col-span-7">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-xs font-semibold text-ink">{t("findings.title")}</h3>
                  <p className="mt-0.5 text-[10px] text-muted">{t("findings.subtitle")}</p>
                </div>
                <Bug className="h-4 w-4 text-rose-300" />
              </div>
              <BarChart labels={findingsChart.labels} values={findingsChart.values} height={250} color="#8b5cf6" />
            </Card>
          </div>

          <div className="grid gap-4 xl:grid-cols-12">
            <Card className="overflow-hidden xl:col-span-7">
              <div className="flex items-center justify-between border-b border-line/60 px-4 py-3">
                <div>
                  <h3 className="text-xs font-semibold text-ink">{t("dashboard.recentScans")}</h3>
                  <p className="mt-0.5 text-[10px] text-muted">{t("projects.activeScans")}</p>
                </div>
                <Button size="sm" variant="ghost" onClick={() => navigate("/scans")}>{t("dashboard.viewAll")}</Button>
              </div>
              {summary.data?.scans.recent.length ? (
                <div className="divide-y divide-line/50">
                  {summary.data.scans.recent.map((scan) => (
                    <button
                      key={scan.id}
                      type="button"
                      onClick={() => navigate(`/scans/${scan.id}`)}
                      className="flex w-full items-center gap-3 px-4 py-3 text-start hover:bg-panel2/40"
                    >
                      <StatusBadge status={scan.status} />
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-[10px] font-medium text-ink">{scan.name}</span>
                        <span className="mt-0.5 block text-[8px] text-faint">{scan.kind} · {scan.profile} · {fromNow(scan.created_at, lang)}</span>
                      </span>
                      <span className="w-20"><Progress value={scan.progress} className="h-1" /></span>
                      <ChevronRight className="h-3 w-3 text-faint rtl:rotate-180" />
                    </button>
                  ))}
                </div>
              ) : (
                <EmptyState icon={Activity} title={t("scans.empty")} description={t("scans.subtitle")} />
              )}
            </Card>

            <div className="space-y-4 xl:col-span-5">
              <Card className="p-4">
                <h3 className="text-xs font-semibold text-ink">{t("projects.overview")}</h3>
                <dl className="mt-3 space-y-2.5">
                  <KeyValue label={t("projects.scopesTitle")} value={String(summary.data?.policy.authorization_scopes ?? scopeRows.length)} />
                  <KeyValue label={t("projects.members")} value={String(memberRows.length)} />
                  <KeyValue label={t("dashboard.services")} value={String(summary.data?.services.open ?? "—")} />
                  <KeyValue label={t("soc.sources")} value={String(summary.data?.soc.sources ?? "—")} />
                  <KeyValue label={t("soc.tabs.events")} value={String(summary.data?.soc.events ?? "—")} />
                  <KeyValue label={t("dashboard.lastScan")} value={summary.data?.last_scan_at ? fromNow(summary.data.last_scan_at, lang) : t("common.never")} />
                  <KeyValue label={t("dashboard.incidents")} value={String(summary.data?.incidents.open ?? "—")} />
                </dl>
              </Card>
              <div className="rounded-xl border border-accent/15 bg-accent/[0.04] p-4">
                <div className="flex items-start gap-2">
                  <LockKeyhole className="mt-0.5 h-4 w-4 shrink-0 text-accent" />
                  <div>
                    <p className="text-[10px] font-semibold text-ink">{t("projects.policyTitle")}</p>
                    <p className="mt-1 text-[9px] leading-relaxed text-muted">{t("projects.scopeNote")}</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </TabsContent>

        <TabsContent value="scopes" className="mt-4 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h3 className="text-xs font-semibold text-ink">{t("projects.scopesTitle")}</h3>
              <p className="mt-0.5 text-[10px] text-muted">{t("projects.scopesSubtitle")}</p>
            </div>
            <Button size="sm" icon={Plus} onClick={() => setScopeOpen(true)} disabled={!isAdmin || project.archived}>
              {t("projects.addScope")}
            </Button>
          </div>

          {scopes.isLoading ? (
            <div className="space-y-2">{[0, 1, 2].map((key) => <Skeleton key={key} className="h-24 rounded-xl" />)}</div>
          ) : scopeRows.length ? (
            <div className="space-y-2.5">
              {scopeRows.map((scope) => {
                const verified = scope.verified_method !== "none" && Boolean(scope.verified_at);
                return (
                  <Card key={scope.id} className={cn("p-4", !scope.is_active && "opacity-65")}>
                    <div className="flex flex-wrap items-start gap-3">
                      <span className={cn(
                        "grid h-9 w-9 shrink-0 place-items-center rounded-lg border",
                        scope.is_active && !scope.expired ? "border-emerald-400/20 bg-emerald-400/[0.06] text-emerald-300" : "border-line bg-panel2 text-faint"
                      )}>
                        {scope.kind === "cidr" || scope.kind === "ip" ? <Server className="h-4 w-4" /> : <Globe2 className="h-4 w-4" />}
                      </span>
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <p className="font-mono text-[11px] font-medium text-ink">{scope.value}</p>
                          <Badge tone="default">{scope.kind.toUpperCase()}</Badge>
                          <Badge tone={verified ? "success" : "warning"}>{verified ? t("projects.verified") : t("projects.pendingVerification")}</Badge>
                          <Badge tone={scope.allow_active ? "danger" : "default"}>{scope.allow_active ? t("projects.allowActive") : t("common.disabled")}</Badge>
                          {scope.expired ? <Badge tone="danger">{t("projects.expired")}</Badge> : null}
                          {!scope.is_active ? <Badge tone="default">{t("common.disabled")}</Badge> : null}
                        </div>
                        <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[8px] text-faint">
                          <span>{t("projects.includeSubdomains")}: {scope.include_subdomains ? t("common.enabled") : t("common.disabled")}</span>
                          <span>{t("projects.scopeAuthRef")}: {scope.authorization_ref || "—"}</span>
                          <span>{t("projects.scopeExpiry")}: {scope.expires_at ? formatDateTime(scope.expires_at, lang) : t("projects.neverExpires")}</span>
                          <span>{t("projects.scopeLastVerified")}: {scope.verified_at ? fromNow(scope.verified_at, lang) : t("common.never")}</span>
                        </div>
                        {scope.notes ? <p className="mt-1.5 text-[9px] text-muted">{scope.notes}</p> : null}
                      </div>
                      {isAdmin ? (
                        <div className="flex flex-wrap items-center gap-1.5">
                          <Button size="sm" variant="secondary" icon={KeyRound} onClick={() => setVerifyTarget(scope)} disabled={project.archived}>
                            {t("projects.verifyNow")}
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            icon={scope.is_active ? EyeOff : Eye}
                            loading={toggleScope.isPending && toggleScope.variables === scope.id}
                            onClick={() => toggleScope.mutate(scope.id)}
                            disabled={project.archived}
                          >
                            {scope.is_active ? t("common.disabled") : t("projects.activeScope")}
                          </Button>
                        </div>
                      ) : null}
                    </div>
                  </Card>
                );
              })}
            </div>
          ) : (
            <Card className="p-2">
              <EmptyState
                icon={ShieldCheck}
                title={t("projects.noScopes")}
                description={t("projects.scopesSubtitle")}
                action={
                  <Button icon={Plus} onClick={() => setScopeOpen(true)} disabled={!isAdmin}>
                    {t("projects.addScope")}
                  </Button>
                }
              />
            </Card>
          )}

          <InlineAlert tone="warning" title={t("projects.scopeWarning")}>{t("projects.scopeNote")}</InlineAlert>
        </TabsContent>

        <TabsContent value="members" className="mt-4 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h3 className="text-xs font-semibold text-ink">{t("projects.members")}</h3>
              <p className="mt-0.5 text-[10px] text-muted">{t("projects.subtitle")}</p>
            </div>
            <Button size="sm" icon={UserPlus} onClick={() => setMemberOpen(true)} disabled={!isAdmin || project.archived}>
              {t("projects.addMember")}
            </Button>
          </div>
          <Card className="overflow-hidden">
            {members.isLoading ? (
              <div className="space-y-2 p-4">{[0, 1, 2].map((key) => <Skeleton key={key} className="h-14 rounded-lg" />)}</div>
            ) : memberRows.length ? (
              <div className="divide-y divide-line/50">
                {memberRows.map((member) => (
                  <div key={member.id} className="flex flex-wrap items-center gap-3 px-4 py-3.5">
                    <span className="grid h-9 w-9 shrink-0 place-items-center rounded-full border border-line bg-panel2 font-display text-xs font-semibold text-accent2">
                      {(member.name || member.email || "?").slice(0, 1).toUpperCase()}
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <p className="truncate text-[11px] font-medium text-ink">{member.name || member.email}</p>
                        <Badge tone="default">{member.global_role || "—"}</Badge>
                        {member.user_id === user?.id ? <Badge tone="info">{t("labs.you")}</Badge> : null}
                      </div>
                      <p className="mt-0.5 text-[9px] text-faint">{member.email} · {t("projects.createdAt")} {formatDateTime(member.created_at, lang)}</p>
                    </div>
                    {isAdmin ? (
                      <Select
                        value={member.role}
                        onChange={(event) => updateMember.mutate({ memberId: member.id, role: event.target.value })}
                        className="w-auto"
                        disabled={project.archived || updateMember.isPending}
                      >
                        {(meta.data?.constants.project_roles || ["owner", "admin", "analyst", "viewer"]).map((option) => (
                          <option key={option} value={option}>{roleLabel(option)}</option>
                        ))}
                      </Select>
                    ) : (
                      <Badge tone="accent">{roleLabel(member.role)}</Badge>
                    )}
                    {isAdmin ? (
                      <Button
                        size="sm"
                        variant="ghost"
                        icon={Trash2}
                        loading={removeMember.isPending && removeMember.variables === member.id}
                        disabled={project.archived}
                        onClick={() => {
                          if (window.confirm(t("projects.memberRemoveConfirm"))) removeMember.mutate(member.id);
                        }}
                      >
                        {t("common.delete")}
                      </Button>
                    ) : null}
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState icon={Users} title={t("projects.noMembers")} />
            )}
          </Card>
        </TabsContent>

        <TabsContent value="settings" className="mt-4">
          <div className="grid gap-4 xl:grid-cols-12">
            <SettingsCard project={project} isGlobalAdmin={isGlobalAdmin} isAdmin={isAdmin} saving={saveSettings.isPending} onSave={(body) => { setRowError(""); saveSettings.mutate(body); }} />
            <div className="space-y-4 xl:col-span-4">
              <Card className="p-4">
                <h3 className="text-xs font-semibold text-ink">{t("common.details")}</h3>
                <dl className="mt-3 space-y-2.5">
                  <KeyValue label={t("projects.slug")} value={project.slug} mono />
                  <KeyValue label={t("projects.role")} value={roleLabel(role)} />
                  <KeyValue label={t("projects.createdAt")} value={formatDateTime(project.created_at, lang)} />
                  <KeyValue label={t("projects.updatedAt")} value={formatDateTime(project.updated_at, lang)} />
                  <KeyValue label={t("projects.retention")} value={`${project.retention_days} ${t("common.days")}`} />
                </dl>
              </Card>
              <Card className="border-rose-400/20 p-4">
                <div className="flex items-start gap-2">
                  <Archive className="mt-0.5 h-4 w-4 shrink-0 text-rose-300" />
                  <div>
                    <h3 className="text-xs font-semibold text-ink">{t("projects.archive")}</h3>
                    <p className="mt-1 text-[9px] leading-relaxed text-muted">{t("projects.archiveConfirm")}</p>
                    <Button
                      size="sm"
                      variant="danger"
                      icon={Archive}
                      className="mt-3"
                      disabled={!isOwner || project.archived}
                      onClick={() => setArchiveOpen(true)}
                    >
                      {t("projects.archive")}
                    </Button>
                  </div>
                </div>
              </Card>
            </div>
          </div>
        </TabsContent>
      </Tabs>

      <CreateScopeModal
        open={scopeOpen}
        onOpenChange={setScopeOpen}
        projectId={projectId}
        api={meta.data}
        project={project}
        onCreated={() => {
          setScopeOpen(false);
          void queryClient.invalidateQueries({ queryKey: ["project-scopes", projectId] });
          void queryClient.invalidateQueries({ queryKey: ["project-summary", projectId] });
        }}
      />

      <AddMemberModal
        open={memberOpen}
        onOpenChange={setMemberOpen}
        projectId={projectId}
        roles={meta.data?.constants.project_roles || []}
        roleLabel={roleLabel}
        onCreated={() => {
          setMemberOpen(false);
          void queryClient.invalidateQueries({ queryKey: ["project-members", projectId] });
        }}
      />

      <VerifyScopeModal
        scope={verifyTarget}
        projectId={projectId}
        onClose={() => setVerifyTarget(null)}
        onVerified={() => {
          void queryClient.invalidateQueries({ queryKey: ["project-scopes", projectId] });
          void queryClient.invalidateQueries({ queryKey: ["project-summary", projectId] });
        }}
      />

      <Modal
        open={archiveOpen}
        onOpenChange={setArchiveOpen}
        title={t("projects.archive")}
        description={project.name}
        icon={Archive}
        size="sm"
        footer={
          <>
            <Button variant="ghost" onClick={() => setArchiveOpen(false)}>{t("common.cancel")}</Button>
            <Button variant="danger" icon={Archive} loading={archive.isPending} onClick={() => archive.mutate()}>
              {t("projects.archive")}
            </Button>
          </>
        }
      >
        <p className="text-[11px] leading-relaxed text-muted">{t("projects.archiveConfirm")}</p>
      </Modal>
    </div>
  );
}

function SettingsCard({
  project,
  isGlobalAdmin,
  isAdmin,
  saving,
  onSave
}: {
  project: Project;
  isGlobalAdmin: boolean;
  isAdmin: boolean;
  saving: boolean;
  onSave: (body: Record<string, unknown>) => void;
}) {
  const { t, i18n } = useTranslation();
  const meta = useMeta();
  const [name, setName] = useState(project.name);
  const [description, setDescription] = useState(project.description);
  const [kind, setKind] = useState(project.kind);
  const [retention, setRetention] = useState(project.retention_days);
  const [allowPrivate, setAllowPrivate] = useState(project.allow_private_targets);

  useEffect(() => {
    setName(project.name);
    setDescription(project.description);
    setKind(project.kind);
    setRetention(project.retention_days);
    setAllowPrivate(project.allow_private_targets);
  }, [project.id, project.name, project.description, project.kind, project.retention_days, project.allow_private_targets]);

  const kinds = meta.data?.constants.project_kinds || [];

  return (
    <Card className="p-4 xl:col-span-8">
      <h3 className="text-xs font-semibold text-ink">{t("projects.settings")}</h3>
      <p className="mt-0.5 text-[10px] text-muted">{t("projects.retentionHint")}</p>
      <div className="mt-4 space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label={t("projects.name")} required>
            <Input value={name} onChange={(event) => setName(event.target.value)} disabled={!isAdmin || project.archived} maxLength={160} />
          </Field>
          <Field label={t("projects.kind")}>
            <Select value={kind} onChange={(event) => setKind(event.target.value)} disabled={!isAdmin || project.archived}>
              {kinds.map((item) => (
                <option key={item.key} value={item.key}>{i18n.language.startsWith("ar") ? item.labels.ar : item.labels.en}</option>
              ))}
            </Select>
          </Field>
        </div>
        <Field label={t("projects.description")}>
          <Textarea value={description} onChange={(event) => setDescription(event.target.value)} rows={3} disabled={!isAdmin || project.archived} maxLength={2000} />
        </Field>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label={t("projects.retention")} hint={t("projects.retentionHint")}>
            <Input
              type="number"
              min={7}
              max={3650}
              value={retention}
              onChange={(event) => setRetention(Number(event.target.value))}
              disabled={!isAdmin || project.archived}
            />
          </Field>
          <label className={cn("flex items-start gap-2 self-end rounded-xl border border-line/60 bg-panel2/30 p-3", !isGlobalAdmin && "opacity-60")}>
            <input
              type="checkbox"
              checked={allowPrivate}
              onChange={(event) => setAllowPrivate(event.target.checked)}
              disabled={!isGlobalAdmin || project.archived}
              className="mt-0.5 h-3.5 w-3.5 accent-[rgb(var(--accent))]"
            />
            <span>
              <span className="block text-[10px] font-medium text-ink">{t("projects.allowPrivate")}</span>
              <span className="mt-0.5 block text-[9px] leading-relaxed text-faint">{t("projects.allowPrivateHint")}</span>
            </span>
          </label>
        </div>
        <div className="flex justify-end">
          <Button
            icon={Save}
            loading={saving}
            disabled={!isAdmin || project.archived || name.trim().length < 2}
            onClick={() =>
              onSave({
                name: name.trim(),
                description: description.trim(),
                kind,
                retention_days: retention,
                ...(isGlobalAdmin ? { allow_private_targets: allowPrivate } : {})
              })
            }
          >
            {t("common.save")}
          </Button>
        </div>
      </div>
    </Card>
  );
}

function CreateScopeModal({
  open,
  onOpenChange,
  projectId,
  api,
  project,
  onCreated
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  projectId: string;
  api: ReturnType<typeof useMeta>["data"];
  project: Project;
  onCreated: () => void;
}) {
  const { t } = useTranslation();
  const toast = useToast();
  const [kind, setKind] = useState("domain");
  const [value, setValue] = useState("");
  const [includeSubdomains, setIncludeSubdomains] = useState(true);
  const [allowActive, setAllowActive] = useState(false);
  const [authorizationRef, setAuthorizationRef] = useState("");
  const [authorizedBy, setAuthorizedBy] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [notes, setNotes] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    if (!open) return;
    setKind("domain");
    setValue("");
    setIncludeSubdomains(true);
    setAllowActive(false);
    setAuthorizationRef("");
    setAuthorizedBy("");
    setExpiresAt("");
    setNotes("");
    setError("");
  }, [open]);

  const create = useMutation({
    mutationFn: () =>
      apiFetch<{ scope: Scope }>(`/projects/${projectId}/scopes`, {
        method: "POST",
        body: {
          kind,
          value: value.trim(),
          include_subdomains: includeSubdomains,
          allow_active: allowActive,
          authorization_ref: authorizationRef.trim(),
          authorized_by: authorizedBy.trim(),
          expires_at: expiresAt ? new Date(`${expiresAt}T23:59:59`).toISOString() : null,
          notes: notes.trim()
        }
      }),
    onSuccess: () => {
      toast.toast({ title: t("projects.scopeCreated"), variant: "success" });
      onCreated();
    },
    onError: (caught) => setError(errorMessage(caught))
  });

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title={t("projects.addScope")}
      description={t("projects.scopeWarning")}
      icon={ShieldCheck}
      size="lg"
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>{t("common.cancel")}</Button>
          <Button icon={Plus} loading={create.isPending} disabled={!value.trim()} onClick={() => { setError(""); create.mutate(); }}>
            {t("common.add")}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label={t("projects.scopeKind")} required>
            <Select value={kind} onChange={(event) => setKind(event.target.value)}>
              {(api?.constants.scope_kinds || ["domain", "ip", "cidr", "url"]).map((item) => (
                <option key={item} value={item}>{item.toUpperCase()}</option>
              ))}
            </Select>
          </Field>
          <Field label={t("projects.scopeValue")} hint={t("projects.scopeTypePlaceholder")} required>
            <Input value={value} onChange={(event) => setValue(event.target.value)} placeholder={t("projects.scopeTypePlaceholder")} maxLength={255} />
          </Field>
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label={t("projects.authorizationRef")} hint={t("projects.authorizationRefHint")}>
            <Input value={authorizationRef} onChange={(event) => setAuthorizationRef(event.target.value)} maxLength={2000} />
          </Field>
          <Field label={t("projects.authorizedBy")} hint={t("common.optional")}>
            <Input value={authorizedBy} onChange={(event) => setAuthorizedBy(event.target.value)} maxLength={200} />
          </Field>
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label={t("projects.scopeExpiry")} hint={t("projects.neverExpires")}>
            <Input type="date" value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} />
          </Field>
          <Field label={t("common.notes")}>
            <Input value={notes} onChange={(event) => setNotes(event.target.value)} maxLength={2000} />
          </Field>
        </div>
        <div className="grid gap-2 sm:grid-cols-2">
          <label className="flex items-center gap-2 rounded-lg border border-line/60 bg-panel2/30 p-3 text-[10px] text-muted">
            <input type="checkbox" checked={includeSubdomains} onChange={(event) => setIncludeSubdomains(event.target.checked)} className="h-3.5 w-3.5 accent-[rgb(var(--accent))]" />
            {t("projects.includeSubdomains")}
          </label>
          <label className={cn("flex items-center gap-2 rounded-lg border border-line/60 bg-panel2/30 p-3 text-[10px] text-muted", !api?.features.active_scanning_enabled && "opacity-60")}>
            <input
              type="checkbox"
              checked={allowActive}
              onChange={(event) => setAllowActive(event.target.checked)}
              disabled={!api?.features.active_scanning_enabled}
              className="h-3.5 w-3.5 accent-[rgb(var(--accent))]"
            />
            {t("projects.allowActive")}
          </label>
        </div>
        <InlineAlert tone="warning" title={t("projects.allowActive")}>{t("projects.allowActiveHint")}</InlineAlert>
        {project.allow_private_targets ? <InlineAlert tone="info">{t("projects.allowPrivateHint")}</InlineAlert> : null}
        {error ? <InlineAlert tone="danger">{error}</InlineAlert> : null}
      </div>
    </Modal>
  );
}

function AddMemberModal({
  open,
  onOpenChange,
  projectId,
  roles,
  roleLabel,
  onCreated
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  projectId: string;
  roles: string[];
  roleLabel: (role: string) => string;
  onCreated: () => void;
}) {
  const { t } = useTranslation();
  const toast = useToast();
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("analyst");
  const [error, setError] = useState("");

  useEffect(() => {
    if (!open) return;
    setEmail("");
    setRole("analyst");
    setError("");
  }, [open]);

  const add = useMutation({
    mutationFn: () =>
      apiFetch<{ member: ProjectMember }>(`/projects/${projectId}/members`, {
        method: "POST",
        body: { email: email.trim(), role }
      }),
    onSuccess: () => {
      toast.toast({ title: t("projects.memberAdded"), variant: "success" });
      onCreated();
    },
    onError: (caught) => setError(errorMessage(caught))
  });

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title={t("projects.addMember")}
      description={t("projects.subtitle")}
      icon={UserPlus}
      size="md"
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>{t("common.cancel")}</Button>
          <Button icon={UserPlus} loading={add.isPending} disabled={!email.includes("@")} onClick={() => { setError(""); add.mutate(); }}>
            {t("common.add")}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label={t("projects.memberEmail")} required>
          <Input type="email" value={email} onChange={(event) => setEmail(event.target.value)} autoFocus />
        </Field>
        <Field label={t("projects.memberRole")}>
          <Select value={role} onChange={(event) => setRole(event.target.value)}>
            {(roles.length ? roles : ["owner", "admin", "analyst", "viewer"]).map((item) => (
              <option key={item} value={item}>{roleLabel(item)}</option>
            ))}
          </Select>
        </Field>
        {error ? <InlineAlert tone="danger">{error}</InlineAlert> : null}
      </div>
    </Modal>
  );
}

function VerifyScopeModal({
  scope,
  projectId,
  onClose,
  onVerified
}: {
  scope: Scope | null;
  projectId: string;
  onClose: () => void;
  onVerified: () => void;
}) {
  const { t } = useTranslation();
  const [method, setMethod] = useState("dns_txt");
  const [instructions, setInstructions] = useState<Record<string, string> | null>(null);
  const [result, setResult] = useState<VerifyResponse | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    setMethod("dns_txt");
    setInstructions(null);
    setResult(null);
    setError("");
  }, [scope?.id]);

  const challenge = useMutation({
    mutationFn: () =>
      apiFetch<VerifyChallengeResponse>(`/projects/${projectId}/scopes/${scope?.id}/verify/challenge`, {
        method: "POST",
        body: { method }
      }),
    onSuccess: (data) => {
      setInstructions(data.instructions);
      setError("");
    },
    onError: (caught) => setError(errorMessage(caught))
  });

  const verify = useMutation({
    mutationFn: () =>
      apiFetch<VerifyResponse>(`/projects/${projectId}/scopes/${scope?.id}/verify`, { method: "POST" }),
    onSuccess: (data) => {
      setResult(data);
      if (data.verified) {
        onVerified();
        onClose();
      }
    },
    onError: (caught) => setError(errorMessage(caught))
  });

  return (
    <Modal
      open={Boolean(scope)}
      onOpenChange={(open) => !open && onClose()}
      title={t("projects.verifyNow")}
      description={<span className="font-mono text-[10px]">{scope?.value}</span>}
      icon={KeyRound}
      size="lg"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>{t("common.close")}</Button>
          {instructions ? (
            <Button icon={CheckCircle2} loading={verify.isPending} onClick={() => { setError(""); verify.mutate(); }}>
              {t("projects.verifyNow")}
            </Button>
          ) : (
            <Button icon={Fingerprint} loading={challenge.isPending} onClick={() => { setError(""); challenge.mutate(); }}>
              {t("projects.verifyNow")}
            </Button>
          )}
        </>
      }
    >
      <div className="space-y-4">
        <Field label={t("projects.verifyMethod")}>
          <Select value={method} onChange={(event) => { setMethod(event.target.value); setInstructions(null); setResult(null); }}>
            <option value="dns_txt">DNS TXT</option>
            <option value="http_file">HTTP /.well-known/nexus-verify.txt</option>
          </Select>
        </Field>
        {!instructions ? <InlineAlert tone="info">{t("projects.verifyHint")}</InlineAlert> : null}
        {instructions ? (
          <div className="rounded-xl border border-line/60 bg-panel2/30 p-3">
            <h4 className="text-xs font-semibold text-ink">{t("projects.verifyEvidence")}</h4>
            <dl className="mt-2 space-y-2">
              {Object.entries(instructions).map(([key, value]) => (
                <KeyValue key={key} label={key.replaceAll("_", " ")} value={<span className="break-all font-mono">{value}</span>} />
              ))}
            </dl>
          </div>
        ) : null}
        {result && !result.verified ? <InlineAlert tone="warning">{result.message}</InlineAlert> : null}
        {error ? <InlineAlert tone="danger">{error}</InlineAlert> : null}
      </div>
    </Modal>
  );
}
