import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import {
  Activity,
  AlertTriangle,
  Ban,
  CheckCircle2,
  CircleStop,
  Database,
  Download,
  FileText,
  Fingerprint,
  Gauge,
  HardDrive,
  KeyRound,
  Loader2,
  Plus,
  RefreshCw,
  RotateCcw,
  Search,
  ServerCog,
  Settings,
  ShieldCheck,
  Trash2,
  UserPlus,
  Users,
  Wrench,
  XCircle,
  Zap
} from "lucide-react";
import { apiFetch, downloadApiFile, errorMessage } from "../lib/api";
import { cn, formatDateTime, fromNow } from "../lib/utils";
import { useAuth } from "../context/AuthContext";
import { useProject } from "../context/ProjectContext";
import { useToast } from "../context/ToastContext";
import { useDocumentTitle, useMeta } from "../hooks";
import type { Job, Lang } from "../types";
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
  Select,
  Skeleton,
  StatusBadge,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
  Textarea
} from "../components/ui";

interface AdminUser {
  id: string;
  email: string;
  full_name: string;
  role: string;
  is_active: boolean;
  mfa_enabled: boolean;
  last_login_at: string | null;
  created_at: string;
  projects: { project_id: string; role: string }[];
}

interface UsersResponse {
  items: AdminUser[];
  total: number;
  page: number;
  page_size: number;
  roles: string[];
}

interface AuditEntry {
  id: string;
  ts: string;
  actor_user_id: string | null;
  actor_label: string;
  action: string;
  entity_type: string;
  entity_id: string;
  outcome: string;
  project_id: string | null;
  ip: string;
  user_agent: string;
  meta: Record<string, unknown>;
  prev_hash: string;
  entry_hash: string;
}

interface AuditResponse {
  items: AuditEntry[];
  total: number;
  counts: { by_outcome: Record<string, number>; top_actions: { action: string; count: number }[] };
}

interface JobsResponse {
  items: Job[];
  total: number;
  counts: { by_status: Record<string, number> };
}

interface SystemSettings {
  app: { name: string; version: string; environment: string; production: boolean };
  database: { dialect: string };
  storage: { managed_directories: string[]; max_upload_mb: number };
  security: {
    allow_private_targets_global: boolean;
    active_scanning_enabled: boolean;
    rate_limit_per_minute: number;
    access_token_minutes: number;
    refresh_token_days: number;
    allowed_origins: string[];
    policy: Record<string, unknown>;
  };
  worker: {
    inprocess: boolean;
    concurrency: number;
    poll_seconds: number;
    lease_seconds: number;
    max_concurrent_scans: number;
    status: Record<string, unknown>;
  };
  integrations: {
    zap_configured: boolean;
    nmap_path: string;
    nmap_available: boolean;
    nvd_api_key_configured: boolean;
    ai: Record<string, unknown>;
  };
  capabilities_summary: Record<string, unknown>;
  runtime: {
    event_retention_days: number;
    notification_window_days: number;
    project_retention_days_default: number;
    updated_at: string | null;
    updated_by: string | null;
  };
  editable: string[];
  secret_note: string;
}

const tabValues = ["users", "jobs", "audit", "settings"];

export default function AdminPage() {
  const { t } = useTranslation();
  const { user } = useAuth();
  const [params, setParams] = useSearchParams();
  const requested = params.get("tab") || "users";
  const tab = tabValues.includes(requested) ? requested : "users";
  useDocumentTitle(t("admin.title"));
  const isAdmin = ["owner", "admin"].includes(user?.role || "");

  if (!isAdmin) {
    return (
      <Card className="p-2">
        <EmptyState
          icon={ShieldCheck}
          title={t("common.accessDenied")}
          description={t("common.accessDeniedBody")}
        />
      </Card>
    );
  }

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow={t("nav.platform")}
        icon={ServerCog}
        title={t("admin.title")}
        subtitle={t("admin.subtitle")}
      />
      <Tabs value={tab} onValueChange={(value) => setParams({ tab: value }, { replace: true })}>
        <TabsList>
          <TabsTrigger value="users" icon={Users}>{t("admin.users")}</TabsTrigger>
          <TabsTrigger value="jobs" icon={Gauge}>{t("admin.jobs")}</TabsTrigger>
          <TabsTrigger value="audit" icon={FileText}>{t("admin.audit")}</TabsTrigger>
          <TabsTrigger value="settings" icon={Settings}>{t("admin.settings")}</TabsTrigger>
        </TabsList>
        <TabsContent value="users" className="mt-4"><UsersTab /></TabsContent>
        <TabsContent value="jobs" className="mt-4"><JobsTab /></TabsContent>
        <TabsContent value="audit" className="mt-4"><AuditTab /></TabsContent>
        <TabsContent value="settings" className="mt-4"><SettingsTab /></TabsContent>
      </Tabs>
    </div>
  );
}

function UsersTab() {
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const { user: currentUser } = useAuth();
  const meta = useMeta();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [q, setQ] = useState("");
  const [role, setRole] = useState("");
  const [activeOnly, setActiveOnly] = useState(false);
  const [page, setPage] = useState(1);
  const [createOpen, setCreateOpen] = useState(false);
  const [editing, setEditing] = useState<AdminUser | null>(null);
  const [resetTarget, setResetTarget] = useState<AdminUser | null>(null);
  const [deactivateTarget, setDeactivateTarget] = useState<AdminUser | null>(null);
  const [resetPassword, setResetPassword] = useState("");
  const [actionError, setActionError] = useState("");
  const pageSize = 50;

  useEffect(() => setPage(1), [q, role, activeOnly]);

  const users = useQuery({
    queryKey: ["admin-users", q, role, activeOnly, page],
    queryFn: () =>
      apiFetch<UsersResponse>("/users", {
        query: { q, role: role || undefined, active_only: activeOnly, page, page_size: pageSize }
      })
  });

  const update = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Record<string, unknown> }) =>
      apiFetch<{ item: AdminUser }>(`/users/${id}`, { method: "PATCH", body }),
    onSuccess: async () => {
      toast.toast({ title: t("admin.userUpdated"), variant: "success" });
      setEditing(null);
      await queryClient.invalidateQueries({ queryKey: ["admin-users"] });
    },
    onError: (error) => setActionError(errorMessage(error))
  });

  const reset = useMutation({
    mutationFn: () =>
      apiFetch<{ ok: boolean; note: string }>(`/users/${resetTarget?.id}/reset-password`, {
        method: "POST",
        body: { new_password: resetPassword }
      }),
    onSuccess: (result) => {
      toast.toast({ title: t("admin.passwordReset"), description: result.note, variant: "success" });
      setResetTarget(null);
      setResetPassword("");
    },
    onError: (error) => setActionError(errorMessage(error))
  });

  const deactivate = useMutation({
    mutationFn: (id: string) => apiFetch<null>(`/users/${id}`, { method: "DELETE" }),
    onSuccess: async () => {
      toast.toast({ title: t("admin.userDeactivated"), variant: "success" });
      setDeactivateTarget(null);
      await queryClient.invalidateQueries({ queryKey: ["admin-users"] });
    },
    onError: (error) => setActionError(errorMessage(error))
  });

  const roles = meta.data?.constants.global_roles || users.data?.roles || ["owner", "admin", "analyst", "viewer"];
  const rows = users.data?.items || [];
  const canManageRoles = currentUser?.role === "owner";

  const roleLabel = (value: string) => {
    const item = meta.data?.constants.role_labels.find((entry) => entry.key === value);
    return item ? (lang === "ar" ? item.labels.ar : item.labels.en) : value;
  };

  return (
    <>
      <Card className="overflow-hidden">
        <div className="flex flex-wrap items-center gap-2 border-b border-line/60 p-3.5">
          <div className="relative min-w-[200px] flex-1">
            <Search className="pointer-events-none absolute start-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-faint" />
            <Input value={q} onChange={(event) => setQ(event.target.value)} placeholder={t("admin.searchUsers")} className="ps-9" />
          </div>
          <Select value={role} onChange={(event) => setRole(event.target.value)} className="w-auto">
            <option value="">{t("admin.allRoles")}</option>
            {roles.map((item) => <option key={item} value={item}>{roleLabel(item)}</option>)}
          </Select>
          <label className="flex items-center gap-2 rounded-lg border border-line/60 bg-panel/40 px-3 py-2 text-[10px] text-muted">
            <input type="checkbox" checked={activeOnly} onChange={(event) => setActiveOnly(event.target.checked)} className="h-3 w-3 accent-[rgb(var(--accent))]" />
            {t("admin.activeOnly")}
          </label>
          <Button size="sm" icon={UserPlus} onClick={() => setCreateOpen(true)}>{t("admin.createUser")}</Button>
        </div>

        {users.isLoading ? (
          <div className="space-y-2 p-4">{[0, 1, 2, 3].map((key) => <Skeleton key={key} className="h-14 rounded-lg" />)}</div>
        ) : users.isError ? (
          <EmptyState
            icon={AlertTriangle}
            title={t("common.errorTitle")}
            description={users.error instanceof Error ? users.error.message : t("common.errorDescription")}
            action={<Button variant="secondary" onClick={() => void users.refetch()}>{t("common.retry")}</Button>}
          />
        ) : rows.length ? (
          <>
            <div className="divide-y divide-line/50">
              {rows.map((row) => (
                <div key={row.id} className={cn("flex flex-wrap items-center gap-3 px-4 py-3.5", !row.is_active && "opacity-60")}>
                  <span className={cn("grid h-9 w-9 shrink-0 place-items-center rounded-full border font-display text-xs font-semibold", row.is_active ? "border-accent/20 bg-accent/[0.07] text-accent" : "border-line bg-panel2 text-faint")}>
                    {(row.full_name || row.email || "?").slice(0, 1).toUpperCase()}
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <p className="truncate text-[11px] font-medium text-ink">{row.full_name || row.email}</p>
                      <Badge tone={row.role === "owner" ? "accent" : row.role === "admin" ? "info" : "default"}>{roleLabel(row.role)}</Badge>
                      {row.id === currentUser?.id ? <Badge tone="info">{t("labs.you")}</Badge> : null}
                      {!row.is_active ? <Badge tone="danger">{t("status.inactive")}</Badge> : null}
                      {row.mfa_enabled ? <Badge tone="success">MFA</Badge> : null}
                    </div>
                    <p className="mt-0.5 text-[9px] text-faint">
                      {row.email} · {t("admin.lastLogin")}: {row.last_login_at ? fromNow(row.last_login_at, lang) : t("common.never")} · {row.projects.length} {t("projects.title")}
                    </p>
                  </div>
                  <div className="flex flex-wrap items-center gap-1.5">
                    <Button size="sm" variant="ghost" icon={Settings} onClick={() => { setActionError(""); setEditing(row); }}>
                      {t("common.edit")}
                    </Button>
                    <Button size="sm" variant="ghost" icon={KeyRound} onClick={() => { setActionError(""); setResetTarget(row); setResetPassword(""); }}>
                      {t("admin.resetPassword")}
                    </Button>
                    {row.is_active ? (
                      <Button
                        size="sm"
                        variant="ghost"
                        icon={Ban}
                        disabled={row.id === currentUser?.id}
                        onClick={() => { setActionError(""); setDeactivateTarget(row); }}
                      >
                        {t("admin.deactivate")}
                      </Button>
                    ) : null}
                  </div>
                </div>
              ))}
            </div>
            <Pagination
              page={page}
              pageSize={pageSize}
              total={users.data?.total || 0}
              onPageChange={setPage}
              labels={{ previous: t("common.previous"), next: t("common.next"), page: t("common.page"), of: t("common.of") }}
            />
          </>
        ) : (
          <EmptyState icon={Users} title={t("admin.noUsers")} description={t("admin.searchUsers")} />
        )}
      </Card>

      <CreateUserModal
        open={createOpen}
        onOpenChange={setCreateOpen}
        roles={roles}
        roleLabel={roleLabel}
        onCreated={() => {
          setCreateOpen(false);
          void queryClient.invalidateQueries({ queryKey: ["admin-users"] });
        }}
      />

      <Modal
        open={Boolean(editing)}
        onOpenChange={(open) => { if (!open) { setEditing(null); setActionError(""); } }}
        title={t("admin.editUser")}
        description={editing?.email}
        icon={Settings}
        size="md"
        footer={
          <>
            <Button variant="ghost" onClick={() => setEditing(null)}>{t("common.cancel")}</Button>
            <Button
              icon={CheckCircle2}
              loading={update.isPending}
              onClick={() =>
                editing &&
                update.mutate({
                  id: editing.id,
                  body: {
                    full_name: editing.full_name,
                    ...(canManageRoles && editing.id !== currentUser?.id ? { role: editing.role } : {})
                  }
                })
              }
            >
              {t("common.save")}
            </Button>
          </>
        }
      >
        {editing ? (
          <div className="space-y-4">
            <Field label={t("admin.fullName")}>
              <Input value={editing.full_name} onChange={(event) => setEditing({ ...editing, full_name: event.target.value })} maxLength={160} />
            </Field>
            <Field label={t("admin.globalRole")} hint={canManageRoles ? undefined : t("admin.ownerOnlyRoles")}>
              <Select
                value={editing.role}
                onChange={(event) => setEditing({ ...editing, role: event.target.value })}
                disabled={!canManageRoles || editing.id === currentUser?.id}
              >
                {roles.map((item) => <option key={item} value={item}>{roleLabel(item)}</option>)}
              </Select>
            </Field>
            <label className="flex items-center gap-2 rounded-lg border border-line/60 bg-panel2/30 p-3 text-[10px] text-muted">
              <input
                type="checkbox"
                checked={editing.is_active}
                onChange={(event) => setEditing({ ...editing, is_active: event.target.checked })}
                disabled={editing.id === currentUser?.id}
                className="h-3.5 w-3.5 accent-[rgb(var(--accent))]"
              />
              {t("admin.accountActive")}
            </label>
            {editing.id !== currentUser?.id ? (
              <Button
                size="sm"
                variant="secondary"
                icon={editing.is_active ? Ban : CheckCircle2}
                onClick={() => update.mutate({ id: editing.id, body: { is_active: !editing.is_active } })}
              >
                {editing.is_active ? t("admin.deactivate") : t("admin.activate")}
              </Button>
            ) : null}
            {actionError ? <InlineAlert tone="danger">{actionError}</InlineAlert> : null}
          </div>
        ) : null}
      </Modal>

      <Modal
        open={Boolean(resetTarget)}
        onOpenChange={(open) => { if (!open) { setResetTarget(null); setResetPassword(""); setActionError(""); } }}
        title={t("admin.resetPassword")}
        description={resetTarget?.email}
        icon={KeyRound}
        size="sm"
        footer={
          <>
            <Button variant="ghost" onClick={() => setResetTarget(null)}>{t("common.cancel")}</Button>
            <Button variant="danger" loading={reset.isPending} disabled={resetPassword.length < 12} onClick={() => { setActionError(""); reset.mutate(); }}>
              {t("admin.resetPassword")}
            </Button>
          </>
        }
      >
        <Field label={t("profile.newPassword")} hint={t("profile.passwordHint")} required>
          <Input type="password" value={resetPassword} onChange={(event) => setResetPassword(event.target.value)} />
        </Field>
        <p className="mt-2 text-[9px] text-faint">{t("admin.resetNote")}</p>
        {actionError ? <InlineAlert tone="danger" className="mt-3">{actionError}</InlineAlert> : null}
      </Modal>

      <Modal
        open={Boolean(deactivateTarget)}
        onOpenChange={(open) => { if (!open) { setDeactivateTarget(null); setActionError(""); } }}
        title={t("admin.deactivate")}
        description={deactivateTarget?.email}
        icon={Ban}
        size="sm"
        footer={
          <>
            <Button variant="ghost" onClick={() => setDeactivateTarget(null)}>{t("common.cancel")}</Button>
            <Button variant="danger" icon={Ban} loading={deactivate.isPending} onClick={() => deactivateTarget && deactivate.mutate(deactivateTarget.id)}>
              {t("admin.deactivate")}
            </Button>
          </>
        }
      >
        <p className="text-[11px] leading-relaxed text-muted">{t("admin.deactivateBody")}</p>
        {actionError ? <InlineAlert tone="danger" className="mt-3">{actionError}</InlineAlert> : null}
      </Modal>
    </>
  );
}

function CreateUserModal({
  open,
  onOpenChange,
  roles,
  roleLabel,
  onCreated
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  roles: string[];
  roleLabel: (role: string) => string;
  onCreated: () => void;
}) {
  const { t } = useTranslation();
  const toast = useToast();
  const [email, setEmail] = useState("");
  const [fullName, setFullName] = useState("");
  const [role, setRole] = useState("analyst");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    if (!open) return;
    setEmail("");
    setFullName("");
    setRole("analyst");
    setPassword("");
    setError("");
  }, [open]);

  const create = useMutation({
    mutationFn: () =>
      apiFetch<{ item: AdminUser; note: string }>("/users", {
        method: "POST",
        body: { email: email.trim(), full_name: fullName.trim(), role, password }
      }),
    onSuccess: (result) => {
      toast.toast({ title: t("admin.userCreated"), description: result.note, variant: "success" });
      onCreated();
    },
    onError: (caught) => setError(errorMessage(caught))
  });

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title={t("admin.createUser")}
      description={t("admin.createUserBody")}
      icon={UserPlus}
      size="md"
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>{t("common.cancel")}</Button>
          <Button icon={UserPlus} loading={create.isPending} disabled={!email.includes("@") || password.length < 12} onClick={() => { setError(""); create.mutate(); }}>
            {t("common.create")}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label={t("admin.email")} required>
          <Input type="email" value={email} onChange={(event) => setEmail(event.target.value)} autoFocus />
        </Field>
        <Field label={t("admin.fullName")}>
          <Input value={fullName} onChange={(event) => setFullName(event.target.value)} maxLength={160} />
        </Field>
        <Field label={t("admin.globalRole")}>
          <Select value={role} onChange={(event) => setRole(event.target.value)}>
            {roles.map((item) => <option key={item} value={item}>{roleLabel(item)}</option>)}
          </Select>
        </Field>
        <Field label={t("admin.initialPassword")} hint={t("profile.passwordHint")} required>
          <Input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="new-password" />
        </Field>
        <InlineAlert tone="info">{t("admin.initialPasswordBody")}</InlineAlert>
        {error ? <InlineAlert tone="danger">{error}</InlineAlert> : null}
      </div>
    </Modal>
  );
}

function JobsTab() {
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const meta = useMeta();
  const toast = useToast();
  const queryClient = useQueryClient();
  const { projects } = useProject();
  const [status, setStatus] = useState("");
  const [type, setType] = useState("");
  const [page, setPage] = useState(1);
  const pageSize = 50;

  useEffect(() => setPage(1), [status, type]);

  const jobs = useQuery({
    queryKey: ["admin-jobs", status, type, page],
    queryFn: () =>
      apiFetch<JobsResponse>("/system/jobs", {
        query: { status: status || undefined, type: type || undefined, limit: pageSize, offset: (page - 1) * pageSize }
      }),
    refetchInterval: (query) =>
      (query.state.data as JobsResponse | undefined)?.items.some((job) => job.status === "queued" || job.status === "running") ? 4000 : false
  });

  const retry = useMutation({
    mutationFn: (id: string) => apiFetch<{ job: Job }>(`/system/jobs/${id}/retry`, { method: "POST" }),
    onSuccess: async () => {
      toast.toast({ title: t("admin.jobRetried"), variant: "success" });
      await queryClient.invalidateQueries({ queryKey: ["admin-jobs"] });
    },
    onError: (error) => toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" })
  });

  const cancel = useMutation({
    mutationFn: (id: string) => apiFetch<{ job: Job }>(`/system/jobs/${id}/cancel`, { method: "POST" }),
    onSuccess: async () => {
      toast.toast({ title: t("admin.jobCanceled"), variant: "success" });
      await queryClient.invalidateQueries({ queryKey: ["admin-jobs"] });
    },
    onError: (error) => toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" })
  });

  const projectName = (id: string | null) => projects.find((project) => project.id === id)?.name || id || "—";
  const rows = jobs.data?.items || [];
  const counts = jobs.data?.counts.by_status || {};

  return (
    <Card className="overflow-hidden">
      <div className="flex flex-wrap items-center gap-2 border-b border-line/60 p-3.5">
        <div className="flex flex-wrap gap-2">
          {["queued", "running", "failed", "succeeded"].map((state) => (
            <button
              key={state}
              type="button"
              onClick={() => setStatus(status === state ? "" : state)}
              className={cn(
                "rounded-lg border px-2.5 py-1.5 text-[9px] transition",
                status === state ? "border-accent/30 bg-accent/[0.08] text-ink" : "border-line/60 bg-panel/40 text-muted hover:text-ink"
              )}
            >
              {t(`status.${state}`)} <span className="ms-1 font-mono tabular-nums text-faint">{counts[state] || 0}</span>
            </button>
          ))}
        </div>
        <Select value={type} onChange={(event) => setType(event.target.value)} className="ms-auto w-auto">
          <option value="">{t("admin.allJobTypes")}</option>
          {(meta.data?.constants.job_types || []).map((item) => <option key={item} value={item}>{item.replaceAll("_", " ")}</option>)}
        </Select>
        <span className="text-[9px] text-faint">{jobs.data?.total || 0} {t("admin.jobs")}</span>
      </div>
      {jobs.isLoading ? (
        <div className="space-y-2 p-4">{[0, 1, 2, 3].map((key) => <Skeleton key={key} className="h-14 rounded-lg" />)}</div>
      ) : rows.length ? (
        <>
          <div className="divide-y divide-line/50">
            {rows.map((job) => (
              <div key={job.id} className="flex flex-wrap items-center gap-3 px-4 py-3.5">
                <span className={cn(
                  "grid h-9 w-9 shrink-0 place-items-center rounded-lg border",
                  job.status === "running" ? "border-sky-400/20 bg-sky-400/[0.06] text-sky-300" :
                  job.status === "failed" ? "border-rose-400/20 bg-rose-400/[0.06] text-rose-300" :
                  job.status === "succeeded" ? "border-emerald-400/20 bg-emerald-400/[0.06] text-emerald-300" : "border-line bg-panel2 text-faint"
                )}>
                  {job.status === "running" ? <Loader2 className="h-4 w-4 animate-spin" /> : job.status === "failed" ? <XCircle className="h-4 w-4" /> : job.status === "succeeded" ? <CheckCircle2 className="h-4 w-4" /> : <Activity className="h-4 w-4" />}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="text-[11px] font-medium text-ink">{job.type.replaceAll("_", " ")}</p>
                    <StatusBadge status={job.status} />
                    {job.attempts ? <Badge tone="warning">{job.attempts}/{job.max_attempts}</Badge> : null}
                  </div>
                  <p className="mt-0.5 text-[9px] text-faint">
                    {projectName(job.project_id)} · {t("admin.created")} {fromNow(job.created_at, lang)}
                    {job.phase ? ` · ${job.phase}` : ""}
                    {job.last_error ? ` · ${job.last_error}` : ""}
                  </p>
                </div>
                <div className="w-24">
                  <div className="flex justify-between text-[8px] text-faint"><span>{job.progress}%</span><span>{job.status}</span></div>
                  <div className="mt-1 h-1 overflow-hidden rounded-full bg-panel3"><div className="h-full rounded-full bg-accent" style={{ width: `${Math.max(0, Math.min(100, job.progress))}%` }} /></div>
                </div>
                {job.status === "queued" || job.status === "running" ? (
                  <Button size="sm" variant="ghost" icon={CircleStop} loading={cancel.isPending && cancel.variables === job.id} onClick={() => cancel.mutate(job.id)}>
                    {t("common.cancel")}
                  </Button>
                ) : (
                  <Button size="sm" variant="ghost" icon={RotateCcw} loading={retry.isPending && retry.variables === job.id} onClick={() => retry.mutate(job.id)}>
                    {t("common.retry")}
                  </Button>
                )}
              </div>
            ))}
          </div>
          <Pagination
            page={page}
            pageSize={pageSize}
            total={jobs.data?.total || 0}
            onPageChange={setPage}
            labels={{ previous: t("common.previous"), next: t("common.next"), page: t("common.page"), of: t("common.of") }}
          />
        </>
      ) : (
        <EmptyState icon={Activity} title={t("admin.noJobs")} description={t("admin.jobsBody")} />
      )}
    </Card>
  );
}

function AuditTab() {
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const toast = useToast();
  const [q, setQ] = useState("");
  const [outcome, setOutcome] = useState("");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<AuditEntry | null>(null);
  const pageSize = 50;

  useEffect(() => setPage(1), [q, outcome]);

  const audit = useQuery({
    queryKey: ["admin-audit", q, outcome, page],
    queryFn: () =>
      apiFetch<AuditResponse>("/audit", {
        query: { q, outcome: outcome || undefined, limit: pageSize, offset: (page - 1) * pageSize }
      })
  });

  const verify = useMutation({
    mutationFn: () => apiFetch<{ ok: boolean; checked: number; broken_at?: Record<string, unknown>; detail?: string; last_hash?: string; scope: string }>("/audit/verify"),
    onSuccess: (result) => {
      toast.toast({
        title: result.ok ? t("admin.chainValid") : t("admin.chainBroken"),
        description: `${result.checked} ${t("admin.entriesChecked")}`,
        variant: result.ok ? "success" : "error"
      });
    },
    onError: (error) => toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" })
  });

  const exportCsv = async () => {
    try {
      await downloadApiFile("/audit/export");
      toast.toast({ title: t("admin.exported"), variant: "success" });
    } catch (error) {
      toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" });
    }
  };

  const rows = audit.data?.items || [];
  const counts = audit.data?.counts.by_outcome || {};

  return (
    <>
      <Card className="overflow-hidden">
        <div className="flex flex-wrap items-center gap-2 border-b border-line/60 p-3.5">
          <div className="relative min-w-[200px] flex-1">
            <Search className="pointer-events-none absolute start-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-faint" />
            <Input value={q} onChange={(event) => setQ(event.target.value)} placeholder={t("admin.searchAudit")} className="ps-9" />
          </div>
          <Select value={outcome} onChange={(event) => setOutcome(event.target.value)} className="w-auto">
            <option value="">{t("admin.allOutcomes")}</option>
            {["success", "denied", "error"].map((item) => <option key={item} value={item}>{t(`outcome.${item}`)} ({counts[item] || 0})</option>)}
          </Select>
          <Button size="sm" variant="secondary" icon={ShieldCheck} loading={verify.isPending} onClick={() => verify.mutate()}>
            {t("admin.verifyChain")}
          </Button>
          <Button size="sm" variant="secondary" icon={Download} onClick={() => void exportCsv()}>
            CSV
          </Button>
        </div>
        {audit.isLoading ? (
          <div className="space-y-2 p-4">{[0, 1, 2, 3].map((key) => <Skeleton key={key} className="h-12 rounded-lg" />)}</div>
        ) : rows.length ? (
          <>
            <div className="divide-y divide-line/50">
              {rows.map((entry) => (
                <button
                  key={entry.id}
                  type="button"
                  onClick={() => setSelected(entry)}
                  className="flex w-full flex-wrap items-center gap-3 px-4 py-3 text-start hover:bg-panel2/40"
                >
                  <span className={cn(
                    "h-2 w-2 shrink-0 rounded-full",
                    entry.outcome === "success" ? "bg-emerald-400" : entry.outcome === "denied" ? "bg-amber-400" : "bg-rose-400"
                  )} />
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <p className="font-mono text-[10px] font-medium text-ink">{entry.action}</p>
                      <Badge tone={entry.outcome === "success" ? "success" : entry.outcome === "denied" ? "warning" : "danger"}>{entry.outcome}</Badge>
                      {entry.project_id ? <Badge tone="default">{entry.project_id.slice(0, 8)}</Badge> : null}
                    </div>
                    <p className="mt-0.5 truncate text-[9px] text-faint">
                      {entry.actor_label || entry.actor_user_id || "system"} · {entry.entity_type || "—"} · {entry.ip || "—"} · {formatDateTime(entry.ts, lang)}
                    </p>
                  </div>
                  <span className="font-mono text-[8px] text-faint">{entry.entry_hash.slice(0, 12)}…</span>
                </button>
              ))}
            </div>
            <Pagination
              page={page}
              pageSize={pageSize}
              total={audit.data?.total || 0}
              onPageChange={setPage}
              labels={{ previous: t("common.previous"), next: t("common.next"), page: t("common.page"), of: t("common.of") }}
            />
          </>
        ) : (
          <EmptyState icon={FileText} title={t("admin.noAudit")} description={t("admin.auditBody")} />
        )}
      </Card>

      <Modal
        open={Boolean(selected)}
        onOpenChange={(open) => !open && setSelected(null)}
        title={selected?.action || t("admin.audit")}
        description={selected ? `${formatDateTime(selected.ts, lang)} · ${selected.outcome}` : undefined}
        icon={FileText}
        size="lg"
        footer={<Button variant="secondary" onClick={() => setSelected(null)}>{t("common.close")}</Button>}
      >
        {selected ? (
          <div className="space-y-3">
            <dl className="grid gap-2.5 sm:grid-cols-2">
              <KeyValue label={t("admin.actor")} value={selected.actor_label || selected.actor_user_id || "system"} />
              <KeyValue label={t("admin.ip")} value={selected.ip || "—"} mono />
              <KeyValue label={t("admin.entity")} value={`${selected.entity_type || "—"} / ${selected.entity_id || "—"}`} mono />
              <KeyValue label={t("admin.project")} value={selected.project_id || "—"} mono />
              <KeyValue label={t("admin.prevHash")} value={selected.prev_hash.slice(0, 24)} mono />
              <KeyValue label={t("admin.entryHash")} value={selected.entry_hash.slice(0, 24)} mono />
            </dl>
            <div>
              <h4 className="text-xs font-semibold text-ink">{t("admin.meta")}</h4>
              <pre className="mt-1.5 max-h-64 overflow-auto rounded-xl bg-bg/60 p-3 font-mono text-[9px] leading-relaxed text-muted">
                {JSON.stringify(selected.meta, null, 2)}
              </pre>
            </div>
            <div>
              <h4 className="text-xs font-semibold text-ink">User agent</h4>
              <p className="mt-1 break-all font-mono text-[9px] text-faint">{selected.user_agent || "—"}</p>
            </div>
          </div>
        ) : null}
      </Modal>
    </>
  );
}

function SettingsTab() {
  const { t } = useTranslation();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [eventRetention, setEventRetention] = useState<number | "">("");
  const [notificationWindow, setNotificationWindow] = useState<number | "">("");
  const [projectRetention, setProjectRetention] = useState<number | "">("");
  const [maintenanceOpen, setMaintenanceOpen] = useState(false);

  const settings = useQuery({
    queryKey: ["admin-settings"],
    queryFn: () => apiFetch<SystemSettings>("/system/settings")
  });

  useEffect(() => {
    if (!settings.data) return;
    setEventRetention(settings.data.runtime.event_retention_days);
    setNotificationWindow(settings.data.runtime.notification_window_days);
    setProjectRetention(settings.data.runtime.project_retention_days_default);
  }, [settings.data?.runtime.event_retention_days, settings.data?.runtime.notification_window_days, settings.data?.runtime.project_retention_days_default]);

  const save = useMutation({
    mutationFn: () =>
      apiFetch<{ runtime: SystemSettings["runtime"]; changed: Record<string, number> }>("/system/settings", {
        method: "PATCH",
        body: {
          event_retention_days: eventRetention === "" ? undefined : Number(eventRetention),
          notification_window_days: notificationWindow === "" ? undefined : Number(notificationWindow),
          project_retention_days_default: projectRetention === "" ? undefined : Number(projectRetention)
        }
      }),
    onSuccess: async () => {
      toast.toast({ title: t("admin.settingsSaved"), variant: "success" });
      await queryClient.invalidateQueries({ queryKey: ["admin-settings"] });
    },
    onError: (error) => toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" })
  });

  const maintenance = useMutation({
    mutationFn: () =>
      apiFetch<{ job: Job | null; enqueued: boolean; note: string }>("/system/maintenance", {
        method: "POST",
        body: { tasks: ["reap", "prune", "kev"], force_kev: false }
      }),
    onSuccess: (result) => {
      toast.toast({
        title: result.enqueued ? t("admin.maintenanceQueued") : t("admin.maintenanceActive"),
        description: result.note || result.job?.id,
        variant: "success"
      });
      setMaintenanceOpen(false);
      void queryClient.invalidateQueries({ queryKey: ["admin-jobs"] });
    },
    onError: (error) => toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" })
  });

  if (settings.isLoading) {
    return <div className="space-y-4"><Skeleton className="h-40 rounded-2xl" /><Skeleton className="h-72 rounded-2xl" /></div>;
  }
  if (settings.isError || !settings.data) {
    return (
      <Card className="p-2">
        <EmptyState
          icon={AlertTriangle}
          title={t("common.errorTitle")}
          description={settings.error instanceof Error ? settings.error.message : t("common.errorDescription")}
          action={<Button variant="secondary" onClick={() => void settings.refetch()}>{t("common.retry")}</Button>}
        />
      </Card>
    );
  }

  const data = settings.data;
  const ai = data.integrations.ai || {};

  return (
    <>
      <div className="grid gap-4 xl:grid-cols-12">
        <Card className="p-4 xl:col-span-7">
          <h3 className="text-xs font-semibold text-ink">{t("admin.runtime")}</h3>
          <p className="mt-0.5 text-[10px] text-muted">{t("admin.runtimeBody")}</p>
          <div className="mt-4 grid gap-4 sm:grid-cols-3">
            <Field label={t("admin.eventRetention")}>
              <Input type="number" min={1} max={365} value={eventRetention} onChange={(event) => setEventRetention(event.target.value === "" ? "" : Number(event.target.value))} />
            </Field>
            <Field label={t("admin.notificationWindow")}>
              <Input type="number" min={1} max={90} value={notificationWindow} onChange={(event) => setNotificationWindow(event.target.value === "" ? "" : Number(event.target.value))} />
            </Field>
            <Field label={t("admin.projectRetention")}>
              <Input type="number" min={30} max={3650} value={projectRetention} onChange={(event) => setProjectRetention(event.target.value === "" ? "" : Number(event.target.value))} />
            </Field>
          </div>
          <div className="mt-4 flex flex-wrap items-center gap-2">
            <Button icon={CheckCircle2} loading={save.isPending} onClick={() => save.mutate()}>{t("common.save")}</Button>
            <Button variant="secondary" icon={Wrench} onClick={() => setMaintenanceOpen(true)}>{t("admin.maintenance")}</Button>
            <Button variant="ghost" icon={RefreshCw} onClick={() => void settings.refetch()}>{t("common.refresh")}</Button>
          </div>
          <p className="mt-2 text-[8px] text-faint">
            {t("common.updated")}: {data.runtime.updated_at ? fromNow(data.runtime.updated_at, "en") : t("common.never")}
          </p>
        </Card>

        <Card className="p-4 xl:col-span-5">
          <h3 className="text-xs font-semibold text-ink">{t("admin.system")}</h3>
          <dl className="mt-3 space-y-2.5">
            <KeyValue label={t("admin.appVersion")} value={`${data.app.name} ${data.app.version}`} />
            <KeyValue label={t("app.environment")} value={data.app.environment} />
            <KeyValue label={t("admin.database")} value={data.database.dialect} />
            <KeyValue label={t("admin.production")} value={data.app.production ? t("common.enabled") : t("common.disabled")} />
            <KeyValue label={t("admin.maxUpload")} value={`${data.storage.max_upload_mb} MB`} />
            <KeyValue label={t("admin.storage")} value={data.storage.managed_directories.join(", ")} />
          </dl>
        </Card>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-12">
        <Card className="p-4 xl:col-span-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-semibold text-ink">{t("admin.security")}</h3>
            <ShieldCheck className="h-4 w-4 text-emerald-300" />
          </div>
          <dl className="mt-3 space-y-2.5">
            <KeyValue label={t("projects.allowPrivate")} value={data.security.allow_private_targets_global ? t("common.enabled") : t("common.disabled")} />
            <KeyValue label={t("projects.allowActive")} value={data.security.active_scanning_enabled ? t("common.enabled") : t("common.disabled")} />
            <KeyValue label={t("admin.rateLimit")} value={`${data.security.rate_limit_per_minute}/min`} />
            <KeyValue label={t("admin.accessToken")} value={`${data.security.access_token_minutes} min`} />
            <KeyValue label={t("admin.refreshToken")} value={`${data.security.refresh_token_days} days`} />
            <KeyValue label={t("admin.origins")} value={data.security.allowed_origins.join(", ") || "—"} />
          </dl>
        </Card>

        <Card className="p-4 xl:col-span-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-semibold text-ink">{t("admin.worker")}</h3>
            <CpuIcon />
          </div>
          <dl className="mt-3 space-y-2.5">
            <KeyValue label={t("admin.workerMode")} value={data.worker.inprocess ? t("admin.inProcessWorker") : t("admin.externalWorker")} />
            <KeyValue label={t("admin.concurrency")} value={String(data.worker.concurrency)} />
            <KeyValue label={t("admin.pollSeconds")} value={String(data.worker.poll_seconds)} />
            <KeyValue label={t("admin.leaseSeconds")} value={String(data.worker.lease_seconds)} />
            <KeyValue label={t("admin.maxConcurrentScans")} value={String(data.worker.max_concurrent_scans)} />
            <KeyValue label={t("admin.workerLive")} value={data.worker.status.in_process ? t("admin.workerActive") : t("admin.workerInactive")} />
            <KeyValue label={t("admin.jobsDone")} value={String(data.worker.status.jobs_done ?? 0)} />
          </dl>
        </Card>

        <Card className="p-4 xl:col-span-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-semibold text-ink">{t("admin.integrations")}</h3>
            <Zap className="h-4 w-4 text-amber-300" />
          </div>
          <dl className="mt-3 space-y-2.5">
            <KeyValue label="Nmap" value={data.integrations.nmap_available ? data.integrations.nmap_path : t("common.offline")} />
            <KeyValue label="OWASP ZAP" value={data.integrations.zap_configured ? t("common.enabled") : t("common.disabled")} />
            <KeyValue label="NVD API key" value={data.integrations.nvd_api_key_configured ? t("common.enabled") : t("common.disabled")} />
            <KeyValue label={t("admin.aiProvider")} value={String(ai.provider || "deterministic")} />
            <KeyValue label={t("admin.aiConfigured")} value={ai.configured ? t("common.enabled") : t("common.disabled")} />
          </dl>
        </Card>
      </div>

      <div className="mt-4 rounded-xl border border-line/50 bg-panel2/20 p-3 text-[9px] leading-relaxed text-faint">
        <Fingerprint className="me-1 inline h-3 w-3 text-accent2" /> {t("admin.secretNote")}
      </div>

      <Modal
        open={maintenanceOpen}
        onOpenChange={setMaintenanceOpen}
        title={t("admin.maintenance")}
        description={t("admin.maintenanceBody")}
        icon={Wrench}
        size="sm"
        footer={
          <>
            <Button variant="ghost" onClick={() => setMaintenanceOpen(false)}>{t("common.cancel")}</Button>
            <Button icon={Wrench} loading={maintenance.isPending} onClick={() => maintenance.mutate()}>{t("admin.runMaintenance")}</Button>
          </>
        }
      >
        <p className="text-[11px] leading-relaxed text-muted">{t("admin.maintenanceBody")}</p>
      </Modal>
    </>
  );
}

function CpuIcon() {
  return <Gauge className="h-4 w-4 text-accent2" />;
}
