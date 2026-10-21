import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import {
  AlertTriangle,
  CheckCircle2,
  Copy,
  Fingerprint,
  KeyRound,
  LockKeyhole,
  LogOut,
  Plus,
  ShieldCheck,
  Trash2,
  UserRound,
  Users
} from "lucide-react";
import { apiFetch, errorMessage, clearTokens } from "../lib/api";
import { cn, formatDateTime, fromNow } from "../lib/utils";
import { useAuth } from "../context/AuthContext";
import { useProject } from "../context/ProjectContext";
import { useToast } from "../context/ToastContext";
import { useDocumentTitle, useMeta } from "../hooks";
import type { Lang } from "../types";
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
  Select,
  Skeleton,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger
} from "../components/ui";

interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  scopes: string[];
  rate_limit_per_min: number;
  created_at: string;
  expires_at: string | null;
  last_used_at: string | null;
  revoked: boolean;
}

interface KeysResponse {
  items: ApiKey[];
}

interface MfaSetupResponse {
  secret: string;
  provisioning_uri: string;
  recovery_codes: string[];
  note: string;
}

const scopeFamilies = ["findings", "scans", "assets", "projects", "reports", "intel", "soc", "labs", "copilot", "system"];

export default function ProfilePage() {
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const { user, authMethod, logout, refreshMe } = useAuth();
  const { projects } = useProject();
  const meta = useMeta();
  const toast = useToast();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [tab, setTab] = useState("security");
  useDocumentTitle(t("profile.title"));

  const memberships = useMemo(
    () =>
      (user?.projects || []).map((membership) => ({
        ...membership,
        project: projects.find((project) => project.id === membership.project_id)
      })),
    [user?.projects, projects]
  );

  const roleLabel = (value: string) => {
    const item = meta.data?.constants.role_labels.find((entry) => entry.key === value);
    return item ? (lang === "ar" ? item.labels.ar : item.labels.en) : value;
  };

  return (
    <div className="space-y-5">
      <div className="relative overflow-hidden rounded-2xl border border-line/60 bg-gradient-to-br from-accent/[0.08] via-panel to-accent2/[0.04] p-5">
        <div className="absolute -end-8 -top-8 h-36 w-36 rounded-full bg-accent/10 blur-3xl" />
        <div className="relative flex flex-wrap items-center gap-4">
          <span className="grid h-16 w-16 shrink-0 place-items-center rounded-2xl border border-accent/20 bg-accent/[0.08] font-display text-2xl font-semibold text-accent">
            {(user?.full_name || user?.email || "?").slice(0, 1).toUpperCase()}
          </span>
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="font-display text-2xl font-semibold text-ink">{user?.full_name || user?.email}</h1>
              <Badge tone="accent">{roleLabel(user?.role || "")}</Badge>
              {user?.mfa_enabled ? <Badge tone="success" dot>{t("profile.mfaOn")}</Badge> : <Badge tone="warning" dot>{t("profile.mfaOff")}</Badge>}
            </div>
            <p className="mt-1 text-[11px] text-muted">{user?.email}</p>
            <div className="mt-2 flex flex-wrap items-center gap-3 text-[8px] text-faint">
              <span>{t("profile.authMethod")}: {authMethod}</span>
              <span>· {t("profile.lastLogin")}: {user?.last_login_at ? fromNow(user.last_login_at, lang) : t("common.never")}</span>
              <span>· {t("profile.memberSince")}: {formatDateTime(user?.created_at, lang)}</span>
            </div>
          </div>
          <Button variant="secondary" icon={LogOut} onClick={() => void logout()} className="self-start">
            {t("profile.signOut")}
          </Button>
        </div>
      </div>

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="security" icon={LockKeyhole}>{t("profile.security")}</TabsTrigger>
          <TabsTrigger value="keys" icon={KeyRound}>{t("profile.apiKeys")}</TabsTrigger>
          <TabsTrigger value="access" icon={Users} count={memberships.length}>{t("profile.access")}</TabsTrigger>
        </TabsList>

        <TabsContent value="security" className="mt-4">
          <div className="grid gap-4 xl:grid-cols-12">
            <PasswordCard onChanged={() => { clearTokens(); queryClient.clear(); navigate("/login"); }} />
            <MfaCard
              enabled={Boolean(user?.mfa_enabled)}
              onChanged={async () => {
                await refreshMe();
                await queryClient.invalidateQueries({ queryKey: ["meta"] });
              }}
            />
          </div>
          <div className="mt-4 grid gap-4 xl:grid-cols-12">
            <Card className="p-4 xl:col-span-7">
              <div className="flex items-start gap-2.5">
                <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-emerald-300" />
                <div>
                  <h3 className="text-xs font-semibold text-ink">{t("profile.sessionsTitle")}</h3>
                  <p className="mt-1 text-[9px] leading-relaxed text-muted">{t("profile.sessionsBody")}</p>
                </div>
              </div>
              <dl className="mt-3 grid gap-2.5 sm:grid-cols-2">
                <KeyValue label={t("profile.authMethod")} value={authMethod} />
                <KeyValue label={t("profile.lastLogin")} value={user?.last_login_at ? formatDateTime(user.last_login_at, lang) : t("common.never")} />
                <KeyValue label={t("profile.accountState")} value={<Badge tone={user?.is_active ? "success" : "danger"}>{user?.is_active ? t("status.active") : t("status.inactive")}</Badge>} />
                <KeyValue label={t("profile.mfa")} value={user?.mfa_enabled ? t("common.enabled") : t("common.disabled")} />
              </dl>
              <Button
                variant="danger"
                size="sm"
                icon={LogOut}
                className="mt-4"
                onClick={async () => {
                  await logout();
                  navigate("/login");
                }}
              >
                {t("profile.signOutAll")}
              </Button>
            </Card>
            <Card className="p-4 xl:col-span-5">
              <h3 className="text-xs font-semibold text-ink">{t("profile.honestTitle")}</h3>
              <ul className="mt-2 space-y-2">
                {[t("profile.honest1"), t("profile.honest2"), t("profile.honest3")].map((item) => (
                  <li key={item} className="flex items-start gap-2 text-[9px] leading-relaxed text-muted">
                    <CheckCircle2 className="mt-0.5 h-3 w-3 shrink-0 text-accent2" /> {item}
                  </li>
                ))}
              </ul>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="keys" className="mt-4">
          <ApiKeysSection />
        </TabsContent>

        <TabsContent value="access" className="mt-4">
          <Card className="overflow-hidden">
            <div className="border-b border-line/60 p-4">
              <h3 className="text-xs font-semibold text-ink">{t("profile.access")}</h3>
              <p className="mt-0.5 text-[10px] text-muted">{t("profile.accessBody")}</p>
            </div>
            {memberships.length ? (
              <div className="divide-y divide-line/50">
                {memberships.map((membership) => (
                  <button
                    key={membership.project_id}
                    type="button"
                    onClick={() => membership.project && navigate(`/projects/${membership.project_id}`)}
                    className="flex w-full flex-wrap items-center gap-3 px-4 py-3.5 text-start hover:bg-panel2/40"
                  >
                    <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-line bg-panel2 text-accent">
                      <ShieldCheck className="h-4 w-4" />
                    </span>
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-[11px] font-medium text-ink">
                        {membership.project?.name || membership.project_id}
                      </p>
                      <p className="mt-0.5 text-[9px] text-faint">
                        {membership.project ? membership.project.slug : t("common.unknown")}
                        {membership.project ? ` · ${membership.project.counts?.assets || 0} ${t("projects.assets")}` : ""}
                      </p>
                    </div>
                    <Badge tone="accent">{roleLabel(membership.role)}</Badge>
                  </button>
                ))}
              </div>
            ) : (
              <EmptyState icon={Users} title={t("projects.noMembers")} description={t("profile.accessBody")} />
            )}
            <div className="border-t border-line/50 px-4 py-3">
              <div className="grid gap-2.5 sm:grid-cols-3">
                <KeyValue label={t("profile.globalRole")} value={roleLabel(user?.role || "")} />
                <KeyValue label={t("profile.accountState")} value={user?.is_active ? t("status.active") : t("status.inactive")} />
                <KeyValue label={t("profile.memberSince")} value={formatDateTime(user?.created_at, lang)} />
              </div>
            </div>
          </Card>
        </TabsContent>
      </Tabs>

      <div className="flex items-center gap-2 rounded-xl border border-line/50 bg-panel2/20 p-3 text-[9px] leading-relaxed text-faint">
        <Fingerprint className="h-3.5 w-3.5 shrink-0 text-accent2" />
        {t("profile.footnote")}
      </div>
    </div>
  );
}

function PasswordCard({ onChanged }: { onChanged: () => void }) {
  const { t } = useTranslation();
  const toast = useToast();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");

  const change = useMutation({
    mutationFn: () =>
      apiFetch<null>("/auth/password", {
        method: "POST",
        body: { current_password: current, new_password: next }
      }),
    onSuccess: () => {
      toast.toast({ title: t("profile.passwordChanged"), description: t("profile.signInAgain"), variant: "success" });
      onChanged();
    },
    onError: (caught) => setError(errorMessage(caught))
  });

  const mismatch = confirm.length > 0 && next !== confirm;
  const valid = current.length > 0 && next.length >= 12 && next === confirm;

  return (
    <Card className="p-4 xl:col-span-7">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-xs font-semibold text-ink">{t("profile.changePassword")}</h3>
          <p className="mt-0.5 text-[10px] text-muted">{t("profile.passwordBody")}</p>
        </div>
        <LockKeyhole className="h-4 w-4 text-accent" />
      </div>
      <div className="mt-4 space-y-3">
        <Field label={t("profile.currentPassword")} required>
          <Input type="password" value={current} onChange={(event) => setCurrent(event.target.value)} autoComplete="current-password" />
        </Field>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label={t("profile.newPassword")} hint={t("profile.passwordHint")} required>
            <Input type="password" value={next} onChange={(event) => setNext(event.target.value)} autoComplete="new-password" />
          </Field>
          <Field label={t("profile.confirmPassword")} required>
            <Input type="password" value={confirm} onChange={(event) => setConfirm(event.target.value)} autoComplete="new-password" />
          </Field>
        </div>
        {mismatch ? <InlineAlert tone="danger">{t("profile.passwordMismatch")}</InlineAlert> : null}
        {error ? <InlineAlert tone="danger">{error}</InlineAlert> : null}
        <div className="flex justify-end">
          <Button icon={LockKeyhole} loading={change.isPending} disabled={!valid} onClick={() => { setError(""); change.mutate(); }}>
            {t("common.save")}
          </Button>
        </div>
      </div>
    </Card>
  );
}

function MfaCard({ enabled, onChanged }: { enabled: boolean; onChanged: () => void | Promise<void> }) {
  const { t } = useTranslation();
  const toast = useToast();
  const [setup, setSetup] = useState<MfaSetupResponse | null>(null);
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [disableOpen, setDisableOpen] = useState(false);

  const startSetup = useMutation({
    mutationFn: () => apiFetch<MfaSetupResponse>("/auth/mfa/setup", { method: "POST" }),
    onSuccess: (data) => {
      setSetup(data);
      setError("");
    },
    onError: (caught) => setError(errorMessage(caught))
  });

  const enable = useMutation({
    mutationFn: () => apiFetch<{ mfa_enabled: boolean }>("/auth/mfa/enable", { method: "POST", body: { code } }),
    onSuccess: async () => {
      toast.toast({ title: t("profile.mfaEnabled"), variant: "success" });
      setSetup(null);
      setCode("");
      await onChanged();
    },
    onError: (caught) => setError(errorMessage(caught))
  });

  const disable = useMutation({
    mutationFn: () => apiFetch<{ mfa_enabled: boolean }>("/auth/mfa/disable", { method: "POST", body: { password } }),
    onSuccess: async () => {
      toast.toast({ title: t("profile.mfaDisabled"), variant: "success" });
      setDisableOpen(false);
      setPassword("");
      await onChanged();
    },
    onError: (caught) => setError(errorMessage(caught))
  });

  const copy = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      toast.toast({ title: t("common.copied"), variant: "success" });
    } catch {
      toast.toast({ title: t("common.copyFailed"), variant: "warning" });
    }
  };

  return (
    <>
      <Card className={cn("p-4 xl:col-span-5", enabled ? "border-emerald-400/20" : "border-line/60")}>
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-xs font-semibold text-ink">{t("profile.mfa")}</h3>
            <p className="mt-0.5 text-[10px] text-muted">{t("profile.mfaBody")}</p>
          </div>
          <span className={cn("grid h-9 w-9 place-items-center rounded-xl border", enabled ? "border-emerald-400/20 bg-emerald-400/[0.06] text-emerald-300" : "border-line bg-panel2 text-faint")}>
            <Fingerprint className="h-4 w-4" />
          </span>
        </div>
        <div className="mt-3">
          <Badge tone={enabled ? "success" : "warning"} dot>{enabled ? t("profile.mfaOn") : t("profile.mfaOff")}</Badge>
        </div>
        <p className="mt-3 text-[9px] leading-relaxed text-muted">{t("profile.mfaHint")}</p>
        {error ? <InlineAlert tone="danger" className="mt-3">{error}</InlineAlert> : null}
        <div className="mt-4 flex justify-end">
          {enabled ? (
            <Button variant="danger" size="sm" icon={ShieldCheck} onClick={() => { setError(""); setDisableOpen(true); }}>
              {t("profile.disableMfa")}
            </Button>
          ) : (
            <Button variant="secondary" size="sm" icon={Fingerprint} loading={startSetup.isPending} onClick={() => { setError(""); startSetup.mutate(); }}>
              {t("profile.enableMfa")}
            </Button>
          )}
        </div>
      </Card>

      <Modal
        open={Boolean(setup)}
        onOpenChange={(open) => { if (!open) { setSetup(null); setCode(""); setError(""); } }}
        title={t("profile.enableMfa")}
        description={setup?.note}
        icon={Fingerprint}
        size="md"
        footer={
          <>
            <Button variant="ghost" onClick={() => { setSetup(null); setCode(""); }}>{t("common.cancel")}</Button>
            <Button icon={CheckCircle2} loading={enable.isPending} disabled={code.trim().length < 6} onClick={() => { setError(""); enable.mutate(); }}>
              {t("profile.confirmMfa")}
            </Button>
          </>
        }
      >
        {setup ? (
          <div className="space-y-4">
            <Field label="TOTP secret">
              <div className="flex gap-2">
                <Input readOnly value={setup.secret} className="font-mono" />
                <Button type="button" variant="secondary" icon={Copy} onClick={() => void copy(setup.secret)}>{t("common.copy")}</Button>
              </div>
            </Field>
            <Field label="Provisioning URI">
              <div className="flex gap-2">
                <Input readOnly value={setup.provisioning_uri} className="font-mono text-[9px]" />
                <Button type="button" variant="secondary" icon={Copy} onClick={() => void copy(setup.provisioning_uri)}>{t("common.copy")}</Button>
              </div>
            </Field>
            <div className="rounded-xl border border-amber-400/20 bg-amber-400/[0.04] p-3">
              <h4 className="flex items-center gap-1.5 text-[10px] font-semibold text-amber-200"><AlertTriangle className="h-3.5 w-3.5" /> {t("profile.recoveryCodes")}</h4>
              <div className="mt-2 grid grid-cols-2 gap-1 font-mono text-[9px] text-muted">
                {setup.recovery_codes.map((item) => <span key={item} className="rounded bg-panel/60 px-1.5 py-1">{item}</span>)}
              </div>
              <Button variant="ghost" size="sm" icon={Copy} className="mt-2" onClick={() => void copy(setup.recovery_codes.join("\n"))}>{t("common.copy")}</Button>
            </div>
            <Field label={t("profile.mfaCode")} required>
              <Input value={code} onChange={(event) => setCode(event.target.value)} inputMode="numeric" maxLength={10} autoFocus />
            </Field>
            {error ? <InlineAlert tone="danger">{error}</InlineAlert> : null}
          </div>
        ) : null}
      </Modal>

      <Modal
        open={disableOpen}
        onOpenChange={(open) => { setDisableOpen(open); if (!open) { setPassword(""); setError(""); } }}
        title={t("profile.disableMfa")}
        description={t("profile.mfaHint")}
        icon={ShieldCheck}
        size="sm"
        footer={
          <>
            <Button variant="ghost" onClick={() => setDisableOpen(false)}>{t("common.cancel")}</Button>
            <Button variant="danger" loading={disable.isPending} disabled={!password} onClick={() => { setError(""); disable.mutate(); }}>
              {t("profile.disableMfa")}
            </Button>
          </>
        }
      >
        <Field label={t("profile.currentPassword")} required>
          <Input type="password" value={password} onChange={(event) => setPassword(event.target.value)} />
        </Field>
        {error ? <InlineAlert tone="danger" className="mt-3">{error}</InlineAlert> : null}
      </Modal>
    </>
  );
}

function ApiKeysSection() {
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const toast = useToast();
  const queryClient = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [createdKey, setCreatedKey] = useState<string | null>(null);
  const [revokeTarget, setRevokeTarget] = useState<ApiKey | null>(null);
  const [error, setError] = useState("");

  const keys = useQuery({
    queryKey: ["apikeys"],
    queryFn: () => apiFetch<KeysResponse>("/apikeys")
  });

  const revoke = useMutation({
    mutationFn: (keyId: string) => apiFetch<null>(`/apikeys/${keyId}`, { method: "DELETE" }),
    onSuccess: async () => {
      toast.toast({ title: t("profile.keyRevoked"), variant: "success" });
      setRevokeTarget(null);
      await queryClient.invalidateQueries({ queryKey: ["apikeys"] });
    },
    onError: (caught) => setError(errorMessage(caught))
  });

  const copy = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      toast.toast({ title: t("common.copied"), variant: "success" });
    } catch {
      toast.toast({ title: t("common.copyFailed"), variant: "warning" });
    }
  };

  const rows = keys.data?.items || [];

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h3 className="text-xs font-semibold text-ink">{t("profile.apiKeys")}</h3>
          <p className="mt-0.5 text-[10px] text-muted">{t("profile.apiKeysBody")}</p>
        </div>
        <Button size="sm" icon={Plus} onClick={() => setCreateOpen(true)}>{t("profile.createKey")}</Button>
      </div>

      <Card className="overflow-hidden">
        {keys.isLoading ? (
          <div className="space-y-2 p-4">{[0, 1, 2].map((key) => <Skeleton key={key} className="h-14 rounded-lg" />)}</div>
        ) : rows.length ? (
          <div className="divide-y divide-line/50">
            {rows.map((key) => (
              <div key={key.id} className={cn("flex flex-wrap items-center gap-3 px-4 py-3.5", key.revoked && "opacity-60")}>
                <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-line bg-panel2 text-accent2">
                  <KeyRound className="h-4 w-4" />
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="text-[11px] font-medium text-ink">{key.name}</p>
                    {key.revoked ? <Badge tone="danger">{t("profile.revoked")}</Badge> : <Badge tone="success" dot>{t("status.active")}</Badge>}
                  </div>
                  <p className="mt-0.5 font-mono text-[9px] text-faint">{key.prefix}••••••••</p>
                  <p className="mt-0.5 text-[8px] text-faint">
                    {key.scopes.join(", ")} · {key.rate_limit_per_min} req/min · {t("profile.createdAt")} {fromNow(key.created_at, lang)}
                    {key.expires_at ? ` · ${t("profile.expiresAt")} ${formatDateTime(key.expires_at, lang)}` : ""}
                    {key.last_used_at ? ` · ${t("profile.lastUsed")} ${fromNow(key.last_used_at, lang)}` : ""}
                  </p>
                </div>
                {!key.revoked ? (
                  <Button size="sm" variant="ghost" icon={Trash2} onClick={() => { setError(""); setRevokeTarget(key); }}>
                    {t("profile.revoke")}
                  </Button>
                ) : null}
              </div>
            ))}
          </div>
        ) : (
          <EmptyState
            icon={KeyRound}
            title={t("profile.noKeys")}
            description={t("profile.apiKeysBody")}
            action={<Button icon={Plus} onClick={() => setCreateOpen(true)}>{t("profile.createKey")}</Button>}
          />
        )}
      </Card>

      <CreateKeyModal
        open={createOpen}
        onOpenChange={setCreateOpen}
        onCreated={(raw) => {
          setCreateOpen(false);
          setCreatedKey(raw);
          void queryClient.invalidateQueries({ queryKey: ["apikeys"] });
        }}
      />

      <Modal
        open={Boolean(createdKey)}
        onOpenChange={(open) => !open && setCreatedKey(null)}
        title={t("profile.keyCreated")}
        description={t("profile.keyOnce")}
        icon={KeyRound}
        size="md"
        footer={<Button variant="secondary" onClick={() => setCreatedKey(null)}>{t("common.close")}</Button>}
      >
        <div className="space-y-3">
          <div className="flex gap-2">
            <Input readOnly value={createdKey || ""} className="font-mono text-[10px]" />
            <Button variant="secondary" icon={Copy} onClick={() => createdKey && void copy(createdKey)}>{t("common.copy")}</Button>
          </div>
          <InlineAlert tone="warning">{t("profile.keyOnce")}</InlineAlert>
        </div>
      </Modal>

      <Modal
        open={Boolean(revokeTarget)}
        onOpenChange={(open) => { if (!open) { setRevokeTarget(null); setError(""); } }}
        title={t("profile.revoke")}
        description={revokeTarget?.name}
        icon={Trash2}
        size="sm"
        footer={
          <>
            <Button variant="ghost" onClick={() => setRevokeTarget(null)}>{t("common.cancel")}</Button>
            <Button variant="danger" loading={revoke.isPending} onClick={() => revokeTarget && revoke.mutate(revokeTarget.id)}>{t("profile.revoke")}</Button>
          </>
        }
      >
        <p className="text-[11px] leading-relaxed text-muted">{t("profile.revokeBody")}</p>
        {error ? <InlineAlert tone="danger" className="mt-3">{error}</InlineAlert> : null}
      </Modal>
    </div>
  );
}

function CreateKeyModal({
  open,
  onOpenChange,
  onCreated
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated: (key: string) => void;
}) {
  const { t } = useTranslation();
  const toast = useToast();
  const [name, setName] = useState("");
  const [writeAccess, setWriteAccess] = useState(false);
  const [hiddenFamilies, setHiddenFamilies] = useState<string[]>([]);
  const [expires, setExpires] = useState(90);
  const [rateLimit, setRateLimit] = useState(120);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!open) return;
    setName("");
    setWriteAccess(false);
    setHiddenFamilies([]);
    setExpires(90);
    setRateLimit(120);
    setError("");
  }, [open]);

  const scopes = useMemo(() => {
    const read = ["read:*"];
    const write = writeAccess ? ["write:*"] : [];
    return [...read, ...write];
  }, [writeAccess]);

  const create = useMutation({
    mutationFn: () =>
      apiFetch<{ key: string; item: ApiKey; note: string }>("/apikeys", {
        method: "POST",
        body: {
          name: name.trim(),
          scopes,
          expires_in_days: expires,
          rate_limit_per_min: rateLimit
        }
      }),
    onSuccess: (result) => {
      toast.toast({ title: t("profile.keyCreated"), description: result.note, variant: "success" });
      onCreated(result.key);
    },
    onError: (caught) => setError(errorMessage(caught))
  });

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title={t("profile.createKey")}
      description={t("profile.apiKeysBody")}
      icon={KeyRound}
      size="md"
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>{t("common.cancel")}</Button>
          <Button icon={Plus} loading={create.isPending} disabled={name.trim().length < 2} onClick={() => { setError(""); create.mutate(); }}>
            {t("common.create")}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label={t("common.name")} required>
          <Input value={name} onChange={(event) => setName(event.target.value)} maxLength={120} placeholder="ci-pipeline" />
        </Field>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label={t("profile.expiresIn")}>
            <Select value={String(expires)} onChange={(event) => setExpires(Number(event.target.value))}>
              {[30, 90, 180, 365, 730].map((days) => <option key={days} value={days}>{days}</option>)}
            </Select>
          </Field>
          <Field label={t("profile.rateLimit")}>
            <Input type="number" min={10} max={5000} value={rateLimit} onChange={(event) => setRateLimit(Number(event.target.value))} />
          </Field>
        </div>
        <div className="rounded-xl border border-line/60 bg-panel2/30 p-3">
          <h4 className="text-[10px] font-semibold text-ink">{t("profile.scopes")}</h4>
          <div className="mt-2 space-y-2">
            <label className="flex items-center gap-2 text-[10px] text-muted">
              <input type="checkbox" checked readOnly className="h-3.5 w-3.5 accent-[rgb(var(--accent))]" /> read:*
            </label>
            <label className="flex items-center gap-2 text-[10px] text-muted">
              <input type="checkbox" checked={writeAccess} onChange={(event) => setWriteAccess(event.target.checked)} className="h-3.5 w-3.5 accent-[rgb(var(--accent))]" />
              write:* — {t("profile.writeHint")}
            </label>
          </div>
          <p className="mt-2 text-[8px] leading-relaxed text-faint">{t("profile.scopeHint")}</p>
        </div>
        <InlineAlert tone="warning">{t("profile.keyOnce")}</InlineAlert>
        {error ? <InlineAlert tone="danger">{error}</InlineAlert> : null}
      </div>
    </Modal>
  );
}
