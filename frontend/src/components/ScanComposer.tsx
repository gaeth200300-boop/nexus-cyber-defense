import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import {
  AlertTriangle,
  CheckCircle2,
  FileUp,
  Loader2,
  LockKeyhole,
  Play,
  Radar,
  ScanLine,
  ShieldCheck,
  UploadCloud
} from "lucide-react";
import { apiFetch, ApiError, errorMessage } from "../lib/api";
import { cn, formatBytes } from "../lib/utils";
import { currentLang } from "../lib/i18n";
import { useMeta, labelOf } from "../hooks";
import { useProject } from "../context/ProjectContext";
import { useToast } from "../context/ToastContext";
import type { Paged, Scan, Scope } from "../types";
import {
  Button,
  Checkbox,
  Field,
  InlineAlert,
  Input,
  Modal,
  Select,
  Textarea
} from "./ui";

interface ScopesResponse {
  items: Scope[];
  policy: Record<string, unknown>;
}

interface UploadResponse {
  upload_path: string;
  source_name?: string;
  size_bytes: number;
  sha256: string;
}

interface CreateResponse {
  scan: Scan;
  job?: { id: string } | null;
  authorization?: Record<string, unknown>;
}

const fileKinds = new Set(["pcap_analysis", "log_analysis"]);

const activeProfiles = new Set(["safe_active", "zap_active"]);

export function ScanComposer({
  open,
  onOpenChange,
  defaultKind = "web_vuln",
  kinds,
  onCreated
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  defaultKind?: string;
  kinds?: string[];
  onCreated?: (scan: Scan) => void;
}) {
  const { t, i18n } = useTranslation();
  const lang = i18n.language.startsWith("ar") ? "ar" : "en";
  const { selectedProject, canWrite } = useProject();
  const meta = useMeta();
  const toast = useToast();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const projectId = selectedProject?.id || "";

  const [kind, setKind] = useState(defaultKind);
  const [profile, setProfile] = useState("passive");
  const [name, setName] = useState("");
  const [targets, setTargets] = useState("");
  const [ports, setPorts] = useState("22,80,443,8000-8100");
  const [useNmap, setUseNmap] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [ack, setAck] = useState(false);
  const [error, setError] = useState<{ message: string; hint?: string; code?: string } | null>(null);
  const [stage, setStage] = useState<"idle" | "uploading" | "creating">("idle");

  const availableKinds = useMemo(() => {
    const list = kinds || meta.data?.constants.scan_kinds.map((item) => item.key) || [];
    return list;
  }, [kinds, meta.data]);

  const scopesQuery = useQuery({
    queryKey: ["scopes", projectId],
    queryFn: () => apiFetch<ScopesResponse>(`/projects/${projectId}/scopes`),
    enabled: open && Boolean(projectId)
  });

  const activeScopes = useMemo(
    () => (scopesQuery.data?.items || []).filter((scope) => scope.is_active && !scope.expired),
    [scopesQuery.data]
  );
  const activeAuthorized = activeScopes.filter((scope) => scope.allow_active);

  useEffect(() => {
    if (!open) return;
    setKind(defaultKind);
    setProfile(defaultKind === "network_scan" ? "safe_active" : "passive");
    setError(null);
    setStage("idle");
    setAck(false);
    setName("");
    setTargets("");
    setFile(null);
  }, [open, defaultKind]);

  useEffect(() => {
    if (fileKinds.has(kind) || kind === "intel_correlation") setProfile("passive");
    else if (kind === "network_scan") setProfile("safe_active");
  }, [kind]);

  const requiresActive = kind === "network_scan" || activeProfiles.has(profile);
  const isFile = fileKinds.has(kind);
  const noTargets = kind === "intel_correlation";
  const profileOptions = useMemo(() => {
    const all = meta.data?.constants.scan_profiles || [];
    if (isFile || kind === "intel_correlation") return all.filter((item) => item.key === "passive");
    if (kind === "web_vuln") {
      const zapEnabled = meta.data?.features.zap_configured;
      return all.filter(
        (item) =>
          !item.key.startsWith("zap_") || zapEnabled
      );
    }
    return all.filter((item) => !item.key.startsWith("zap_"));
  }, [meta.data, isFile, kind]);

  const targetList = useMemo(
    () =>
      targets
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean),
    [targets]
  );

  const resetSubmit = () => setStage("idle");

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    if (!canWrite) {
      setError({ message: t("common.accessDeniedBody") });
      return;
    }
    if (isFile && !file) {
      setError({ message: t("scan.uploadFirst") });
      return;
    }
    if (!isFile && !noTargets && targetList.length === 0) {
      setError({ message: t("scan.targetRequired") });
      return;
    }
    if (requiresActive && !ack) {
      setError({ message: t("scan.authAckRequired") });
      return;
    }
    const options: Record<string, unknown> = {};
    if (kind === "network_scan") {
      if (ports.trim()) options.ports = ports.trim();
      options.use_nmap = useNmap;
    }
    try {
      if (isFile && file) {
        setStage("uploading");
        const form = new FormData();
        form.append("file", file);
        form.append("kind", kind);
        const upload = await apiFetch<UploadResponse>(`/projects/${projectId}/scans/uploads`, {
          method: "POST",
          rawBody: form
        });
        options.upload_path = upload.upload_path;
        options.source_name = upload.source_name || file.name;
        options.format = "auto";
      }
      setStage("creating");
      const payload = {
        kind,
        profile,
        name: name.trim(),
        targets: isFile || noTargets ? [] : targetList,
        options,
        priority: 100,
        idempotency_key: `ui-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
      };
      const result = await apiFetch<CreateResponse>(`/projects/${projectId}/scans`, {
        method: "POST",
        body: payload
      });
      toast.toast({
        title: t("scan.created"),
        description: `${result.scan.name} · ${labelOf(meta.data?.constants.scan_kinds, result.scan.kind, lang as "ar" | "en")}`,
        variant: "success"
      });
      await queryClient.invalidateQueries({ queryKey: ["scans", projectId] });
      await queryClient.invalidateQueries({ queryKey: ["scan-counts", projectId] });
      await queryClient.invalidateQueries({ queryKey: ["findings", projectId] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
      await queryClient.invalidateQueries({ queryKey: ["jobs"] });
      onOpenChange(false);
      if (onCreated) onCreated(result.scan);
      else navigate(`/scans/${result.scan.id}`);
    } catch (caught) {
      resetSubmit();
      if (caught instanceof ApiError) {
        const hint = typeof caught.detail?.hint === "string" ? caught.detail.hint : undefined;
        setError({ message: caught.message, hint, code: caught.code });
      } else {
        setError({ message: errorMessage(caught) });
      }
    }
  };

  const loading = stage !== "idle";
  const kindLabel = labelOf(meta.data?.constants.scan_kinds, kind, lang as "ar" | "en");
  const projectNoActive = requiresActive && activeAuthorized.length === 0;

  return (
    <Modal
      open={open}
      onOpenChange={(next) => {
        if (!loading) onOpenChange(next);
      }}
      title={t("scan.newTitle")}
      description={selectedProject ? `${selectedProject.name} · ${t("common.poweredBy")}` : undefined}
      size="lg"
      icon={ScanLine}
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)} disabled={loading}>
            {t("common.cancel")}
          </Button>
          <Button
            type="submit"
            form="scan-composer-form"
            loading={loading}
            disabled={!canWrite}
            icon={loading ? undefined : Play}
          >
            {stage === "uploading"
              ? t("soc.uploading")
              : stage === "creating"
                ? t("scan.starting")
                : t("scan.start")}
          </Button>
        </>
      }
    >
      <form id="scan-composer-form" onSubmit={submit} className="space-y-5">
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label={t("scan.kind")} required>
            <Select value={kind} onChange={(event) => setKind(event.target.value)}>
              {availableKinds.map((value) => (
                <option key={value} value={value}>
                  {labelOf(meta.data?.constants.scan_kinds, value, lang as "ar" | "en")}
                </option>
              ))}
            </Select>
          </Field>
          <Field label={t("scan.profile")} hint={t("scan.profileHint")} required>
            <Select value={profile} onChange={(event) => setProfile(event.target.value)}>
              {profileOptions.map((item) => (
                <option key={item.key} value={item.key}>
                  {item.labels?.[lang as "ar" | "en"] || item.key}
                </option>
              ))}
            </Select>
          </Field>
        </div>

        <div
          className={cn(
            "flex items-center gap-2 rounded-lg border px-3 py-2 text-[10px]",
            requiresActive
              ? "border-amber-400/20 bg-amber-400/[0.05] text-amber-200"
              : "border-emerald-400/15 bg-emerald-400/[0.04] text-emerald-200"
          )}
        >
          {requiresActive ? <AlertTriangle className="h-3.5 w-3.5" /> : <ShieldCheck className="h-3.5 w-3.5" />}
          {requiresActive ? t("scan.activeScopeWarning") : t("network.passiveRequired")}
        </div>

        <Field label={t("scan.name")} hint={t("scan.nameHint")}>
          <Input
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder={`${kindLabel} · ${new Date().toLocaleDateString(lang === "ar" ? "ar" : "en-GB")}`}
            maxLength={200}
          />
        </Field>

        {isFile ? (
          <div className="space-y-3">
            <Field label={t("scan.upload")} hint={t("scan.uploadFirst")} required>
              <label
                className={cn(
                  "flex cursor-pointer flex-col items-center justify-center gap-2 rounded-xl border border-dashed border-line bg-panel2/40 px-4 py-7 text-center transition hover:border-accent/35 hover:bg-accent/[0.03]",
                  file && "border-accent/30 bg-accent/[0.04]"
                )}
              >
                <input
                  type="file"
                  className="sr-only"
                  accept={kind === "pcap_analysis" ? ".pcap,.pcapng,.cap" : ".log,.txt,.json,.csv,.gz"}
                  onChange={(event) => setFile(event.target.files?.[0] || null)}
                />
                {file ? (
                  <>
                    <CheckCircle2 className="h-6 w-6 text-emerald-400" />
                    <span className="max-w-full truncate text-xs font-medium text-ink">{file.name}</span>
                    <span className="text-[10px] text-muted">{formatBytes(file.size)}</span>
                  </>
                ) : (
                  <>
                    <UploadCloud className="h-6 w-6 text-accent" />
                    <span className="text-xs font-medium text-ink">{t("scan.selectFile")}</span>
                    <span className="text-[10px] text-muted">
                      {kind === "pcap_analysis" ? "PCAP / PCAPNG / CAP" : "LOG / TXT / JSON / CSV"}
                    </span>
                  </>
                )}
              </label>
            </Field>
            <InlineAlert tone="info" icon={FileUp}>
              {t("scan.passiveOnly")} {t("network.pcapNote")}
            </InlineAlert>
          </div>
        ) : noTargets ? (
          <InlineAlert tone="info" icon={Radar}>
            {t("scan.intelNoTargets")}
          </InlineAlert>
        ) : (
          <div className="space-y-4">
            <Field
              label={t("scan.targetTitle")}
              hint={
                kind === "network_scan"
                  ? t("scan.networkTargetsHint")
                  : t("scan.webTargetsHint")
              }
              required
            >
              <Textarea
                value={targets}
                onChange={(event) => setTargets(event.target.value)}
                placeholder={kind === "network_scan" ? "app.example.com\n203.0.113.10" : "https://app.example.com"}
                rows={4}
                className="font-mono text-xs"
                spellCheck={false}
              />
            </Field>

            {activeScopes.length ? (
              <div className="rounded-xl border border-line/60 bg-panel2/40 p-3">
                <p className="mb-2 flex items-center gap-1.5 text-[10px] font-medium text-muted">
                  <LockKeyhole className="h-3 w-3 text-emerald-400" />
                  {t("scan.targetTitle")} ({activeScopes.length})
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {activeScopes.slice(0, 8).map((scope) => (
                    <span
                      key={scope.id}
                      className="inline-flex items-center gap-1 rounded-md border border-line bg-panel px-2 py-1 font-mono text-[9px] text-muted"
                      title={scope.authorization_ref}
                    >
                      {scope.value}
                      {scope.allow_active ? <span className="h-1 w-1 rounded-full bg-amber-400" /> : null}
                    </span>
                  ))}
                  {activeScopes.length > 8 ? (
                    <span className="px-2 py-1 text-[9px] text-faint">+{activeScopes.length - 8}</span>
                  ) : null}
                </div>
              </div>
            ) : (
              <InlineAlert
                tone="warning"
                title={requiresActive ? t("network.activeAuth") : t("web.noScopes")}
              >
                {projectNoActive
                  ? t("network.activeWarning")
                  : scopesQuery.isLoading
                    ? t("common.loading")
                    : t("web.noScopesBody")}
              </InlineAlert>
            )}

            {kind === "network_scan" ? (
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label={t("scan.ports")} hint={t("scan.portsHint")}>
                  <Input
                    value={ports}
                    onChange={(event) => setPorts(event.target.value)}
                    placeholder="22,80,443,8000-8100"
                    className="font-mono text-xs"
                  />
                </Field>
                <div className="flex flex-col justify-end gap-2 pb-1">
                  <Checkbox
                    checked={useNmap}
                    onChange={setUseNmap}
                    label={
                      <span>
                        Nmap{" "}
                        <span className={meta.data?.features.nmap_available ? "text-emerald-300" : "text-amber-300"}>
                          {meta.data?.features.nmap_available ? t("admin.integrationAvailable") : t("admin.integrationMissing")}
                        </span>
                      </span>
                    }
                  />
                  <p className="text-[10px] text-faint">
                    {meta.data?.features.nmap_available
                      ? "Service/version detection can enrich banners."
                      : "Nmap not detected — the native TCP connect scanner is used."}
                  </p>
                </div>
              </div>
            ) : null}
          </div>
        )}

        {requiresActive ? (
          <Checkbox
            checked={ack}
            onChange={setAck}
            className="rounded-xl border border-amber-400/20 bg-amber-400/[0.04] p-3"
            label={<span className="text-amber-100/80">{t("scan.authAck")}</span>}
          />
        ) : null}

        {error ? (
          <InlineAlert tone="danger" title={error.code ? error.code.replace(/_/g, " ") : undefined}>
            <p>{error.message}</p>
            {error.hint ? <p className="mt-1 text-ink/70">{error.hint}</p> : null}
          </InlineAlert>
        ) : null}

        {!selectedProject ? <InlineAlert tone="warning">{t("common.noProjectBody")}</InlineAlert> : null}
        {!canWrite ? <InlineAlert tone="warning">{t("common.accessDeniedBody")}</InlineAlert> : null}
        {loading ? (
          <div className="flex items-center gap-2 text-[10px] text-muted">
            <Loader2 className="h-3.5 w-3.5 animate-spin text-accent" />
            {t("common.saving")}
          </div>
        ) : null}
      </form>
    </Modal>
  );
}
