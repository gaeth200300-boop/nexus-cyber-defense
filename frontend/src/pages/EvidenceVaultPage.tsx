import { useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import {
  Fingerprint,
  Hash,
  Lock,
  RefreshCw,
  ShieldCheck,
  Upload,
  XCircle
} from "lucide-react";
import { apiFetch, errorMessage } from "../lib/api";
import { cn, formatDateTime } from "../lib/utils";
import { useDocumentTitle } from "../hooks";
import { useRequiredProjectId } from "../context/ProjectContext";
import { useToast } from "../context/ToastContext";
import { DataError, ProjectGate, SectionCard } from "../components/common";
import { Badge, Button, Card, EmptyState, PageHeader, Skeleton, StatCard } from "../components/ui";
import type { EvidenceRecord, EvidenceVerification, Lang } from "../types";

export default function EvidenceVaultPage() {
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const projectId = useRequiredProjectId();
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const fileRef = useRef<HTMLInputElement>(null);
  const [label, setLabel] = useState("");
  useDocumentTitle(t("vault.title"));

  const evidence = useQuery({
    queryKey: ["evidence", projectId],
    queryFn: () =>
      apiFetch<{ items: EvidenceRecord[]; total: number }>(`/projects/${projectId}/evidence`, {
        query: { limit: 200 }
      }),
    enabled: Boolean(projectId)
  });

  const verification = useQuery({
    queryKey: ["evidence-verify", projectId],
    queryFn: () => apiFetch<EvidenceVerification>(`/projects/${projectId}/evidence/verify`),
    enabled: Boolean(projectId)
  });

  const upload = useMutation({
    mutationFn: async () => {
      const file = fileRef.current?.files?.[0];
      if (!file) throw new Error(t("vault.selectFile"));
      const form = new FormData();
      form.append("file", file);
      form.append("label", label || file.name);
      form.append("kind", "upload");
      return apiFetch<EvidenceRecord>(`/projects/${projectId}/evidence`, {
        method: "POST",
        rawBody: form
      });
    },
    onSuccess: () => {
      setLabel("");
      if (fileRef.current) fileRef.current.value = "";
      toast({ title: t("vault.uploaded"), variant: "success" });
      void queryClient.invalidateQueries({ queryKey: ["evidence", projectId] });
      void queryClient.invalidateQueries({ queryKey: ["evidence-verify", projectId] });
    },
    onError: (error) => toast({ title: t("common.errorTitle"), description: errorMessage(error), variant: "error" })
  });

  const items = evidence.data?.items || [];
  const verify = verification.data;

  return (
    <ProjectGate>
      <div className="space-y-5">
        <PageHeader
          eyebrow={t("vault.eyebrow")}
          icon={Lock}
          title={t("vault.title")}
          subtitle={t("vault.subtitle")}
          actions={
            <Button
              variant="secondary"
              size="sm"
              icon={RefreshCw}
              onClick={() => {
                void evidence.refetch();
                void verification.refetch();
              }}
              disabled={evidence.isFetching}
            >
              {t("common.refresh")}
            </Button>
          }
        />

        {evidence.isLoading ? (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
              {[0, 1, 2, 3].map((key) => (
                <Skeleton key={key} className="h-24 rounded-2xl" />
              ))}
            </div>
            <Skeleton className="h-80 rounded-2xl" />
          </div>
        ) : evidence.isError ? (
          <Card>
            <DataError
              message={evidence.error instanceof Error ? evidence.error.message : undefined}
              onRetry={() => void evidence.refetch()}
            />
          </Card>
        ) : (
          <>
            <section className="grid grid-cols-2 gap-3 lg:grid-cols-4">
              <StatCard
                label={t("vault.total")}
                value={verify?.total ?? items.length}
                sub={t("vault.totalSub")}
                icon={Lock}
                tone="accent"
              />
              <StatCard
                label={t("vault.verified")}
                value={verify?.verified ?? 0}
                sub={t("vault.verifiedSub")}
                icon={ShieldCheck}
                tone="success"
              />
              <StatCard
                label={t("vault.mismatched")}
                value={verify?.mismatched.length ?? 0}
                sub={t("vault.mismatchedSub")}
                icon={XCircle}
                tone="danger"
              />
              <StatCard
                label={t("vault.missingDigest")}
                value={verify?.missing_digest.length ?? 0}
                sub={t("vault.missingDigestSub")}
                icon={Hash}
                tone="warning"
              />
            </section>

            {verify && !verify.integrity_ok ? (
              <Card className="border-rose-400/25 bg-rose-500/[0.06] p-4">
                <p className="text-xs font-semibold text-rose-200">{t("vault.integrityBroken")}</p>
                <ul className="mt-1.5 space-y-1">
                  {verify.mismatched.map((item) => (
                    <li key={item.id} className="text-[10px] leading-relaxed text-rose-200/85">
                      {item.label} â€” {item.recorded.slice(0, 16)}â€¦ vs {item.in_custody.map((value) => value.slice(0, 16)).join(", ")}â€¦
                    </li>
                  ))}
                </ul>
              </Card>
            ) : null}

            <section className="grid gap-4 xl:grid-cols-12">
              <SectionCard
                className="xl:col-span-7"
                title={t("vault.repository")}
                subtitle={t("vault.repositorySubtitle")}
                icon={Lock}
                bodyClassName="divide-y divide-line/40"
              >
                {items.length ? (
                  items.map((item) => (
                    <div key={item.id} className="px-4 py-3.5">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="truncate text-[11px] font-medium text-ink">
                          {item.label || item.kind}
                        </span>
                        <div className="flex items-center gap-1.5">
                          <Badge tone="default">{item.kind}</Badge>
                          {item.sha256 ? (
                            <Badge tone="success">{t("vault.hashed")}</Badge>
                          ) : (
                            <Badge tone="warning">{t("vault.noHash")}</Badge>
                          )}
                        </div>
                      </div>
                      {item.sha256 ? (
                        <p className="mt-1 break-all font-mono text-[9px] text-faint">{item.sha256}</p>
                      ) : null}
                      <p className="mt-1 text-[9px] text-faint">
                        {item.source} Â· {item.created_at ? formatDateTime(item.created_at, lang) : ""}
                      </p>
                      {item.custody.length ? (
                        <ol className="mt-2 space-y-1 border-s border-line/60 ps-3">
                          {item.custody.map((entry) => (
                            <li key={entry.id} className="text-[10px] leading-relaxed text-muted">
                              <span className="font-medium text-ink">{entry.action}</span>
                              <span className="ms-1.5 text-faint">{entry.actor_label}</span>
                              {entry.location ? <span className="ms-1.5 text-faint">Â· {entry.location}</span> : null}
                              {entry.created_at ? (
                                <span className="ms-1.5 text-faint">Â· {formatDateTime(entry.created_at, lang)}</span>
                              ) : null}
                              {entry.notes ? <span className="block text-faint">{entry.notes}</span> : null}
                            </li>
                          ))}
                        </ol>
                      ) : (
                        <p className="mt-1.5 text-[10px] text-faint">{t("vault.noCustody")}</p>
                      )}
                    </div>
                  ))
                ) : (
                  <EmptyState
                    icon={Lock}
                    title={t("vault.empty")}
                    description={t("vault.emptyBody")}
                  />
                )}
              </SectionCard>

              <div className="space-y-4 xl:col-span-5">
                <SectionCard
                  title={t("vault.addEvidence")}
                  subtitle={t("vault.addEvidenceSubtitle")}
                  icon={Upload}
                  bodyClassName="space-y-3 p-4"
                >
                  <div>
                    <label className="text-[9px] uppercase tracking-[0.1em] text-faint" htmlFor="vault-label">
                      {t("common.name")}
                    </label>
                    <input
                      id="vault-label"
                      value={label}
                      onChange={(event) => setLabel(event.target.value)}
                      placeholder={t("vault.labelPlaceholder")}
                      className="mt-1 w-full rounded-xl border border-line bg-panel2 px-3 py-2 text-xs text-ink outline-none transition focus:border-accent/40"
                    />
                  </div>
                  <div>
                    <label className="text-[9px] uppercase tracking-[0.1em] text-faint" htmlFor="vault-file">
                      {t("vault.file")}
                    </label>
                    <input
                      id="vault-file"
                      ref={fileRef}
                      type="file"
                      onChange={() => upload.mutate()}
                      className="mt-1 w-full text-[10px] text-muted file:me-3 file:rounded-lg file:border file:border-line file:bg-panel2 file:px-3 file:py-1.5 file:text-[10px] file:text-ink"
                    />
                  </div>
                  {upload.isPending ? (
                    <p className="text-[10px] text-accent2">{t("common.saving")}</p>
                  ) : null}
                  <p className="text-[10px] leading-relaxed text-faint">{t("vault.formats")}</p>
                </SectionCard>

                <SectionCard
                  title={t("vault.integrityTitle")}
                  subtitle={t("vault.integritySubtitle")}
                  icon={Fingerprint}
                  bodyClassName="space-y-2 p-4"
                >
                  <p className="text-[10px] leading-relaxed text-muted">{verify?.note}</p>
                  <div className="rounded-xl border border-line/60 bg-panel2/40 p-3">
                    <div className="flex items-center justify-between text-[10px]">
                      <span className="text-muted">{t("vault.checked")}</span>
                      <span className="font-mono text-ink">{verify?.checked ?? 0}</span>
                    </div>
                    <div className="mt-1.5 flex items-center justify-between text-[10px]">
                      <span className="text-muted">{t("vault.verified")}</span>
                      <span className="font-mono text-emerald-300">{verify?.verified ?? 0}</span>
                    </div>
                    <div className="mt-1.5 flex items-center justify-between text-[10px]">
                      <span className="text-muted">{t("vault.mismatched")}</span>
                      <span className={cn("font-mono", (verify?.mismatched.length ?? 0) ? "text-rose-300" : "text-ink")}>
                        {verify?.mismatched.length ?? 0}
                      </span>
                    </div>
                  </div>
                </SectionCard>
              </div>
            </section>
          </>
        )}
      </div>
    </ProjectGate>
  );
}

