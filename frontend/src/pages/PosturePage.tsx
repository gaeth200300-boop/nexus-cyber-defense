import { useQuery, useMutation } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import {
  AlertCircle,
  Camera,
  CheckCircle2,
  Gauge,
  Info,
  RefreshCw,
  ShieldCheck,
  TrendingUp
} from "lucide-react";
import { apiFetch } from "../lib/api";
import { cn, formatDateTime, percent } from "../lib/utils";
import { useDocumentTitle } from "../hooks";
import { useRequiredProjectId } from "../context/ProjectContext";
import { DataError, ProjectGate, SectionCard } from "../components/common";
import { Badge, Button, Card, EmptyState, PageHeader, Progress, Skeleton, StatCard } from "../components/ui";
import type { Lang, PostureResponse } from "../types";

function gradeTone(grade: string): string {
  if (grade === "A" || grade === "B") return "text-emerald-300";
  if (grade === "C") return "text-cyan-300";
  if (grade === "D") return "text-amber-300";
  return "text-rose-300";
}

export default function PosturePage() {
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const projectId = useRequiredProjectId();
  useDocumentTitle(t("posture.title"));

  const query = useQuery({
    queryKey: ["posture", projectId],
    queryFn: () => apiFetch<PostureResponse>(`/projects/${projectId}/posture`),
    enabled: Boolean(projectId)
  });

  const snapshot = useMutation({
    mutationFn: () =>
      apiFetch<PostureResponse>(`/projects/${projectId}/posture/snapshot`, {
        method: "POST",
        body: { save: true }
      }),
    onSuccess: () => void query.refetch()
  });

  const data = query.data;

  return (
    <ProjectGate>
      <div className="space-y-5">
        <PageHeader
          eyebrow={t("posture.eyebrow")}
          icon={Gauge}
          title={t("posture.title")}
          subtitle={t("posture.subtitle")}
          actions={
            <>
              <Button
                variant="secondary"
                size="sm"
                icon={Camera}
                onClick={() => snapshot.mutate()}
                disabled={snapshot.isPending || !data}
              >
                {t("posture.snapshot")}
              </Button>
              <Button
                variant="secondary"
                size="sm"
                icon={RefreshCw}
                onClick={() => void query.refetch()}
                disabled={query.isFetching}
              >
                {t("common.refresh")}
              </Button>
            </>
          }
        />

        {query.isLoading ? (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
              {[0, 1, 2, 3].map((key) => (
                <Skeleton key={key} className="h-24 rounded-2xl" />
              ))}
            </div>
            <Skeleton className="h-80 rounded-2xl" />
          </div>
        ) : query.isError ? (
          <Card>
            <DataError
              message={query.error instanceof Error ? query.error.message : undefined}
              onRetry={() => void query.refetch()}
            />
          </Card>
        ) : !data ? (
          <Card>
            <EmptyState icon={Gauge} title={t("posture.empty")} description={t("posture.emptyBody")} />
          </Card>
        ) : (
          <>
            <section className="grid gap-4 lg:grid-cols-12">
              <Card className="relative overflow-hidden p-5 lg:col-span-4">
                <div className="pointer-events-none absolute -end-16 -top-16 h-48 w-48 rounded-full bg-accent/10 blur-3xl" />
                <div className="relative">
                  <p className="text-[9px] uppercase tracking-[0.14em] text-faint">{t("posture.score")}</p>
                  <div className="mt-2 flex items-end gap-3">
                    <span className="font-display text-5xl font-semibold tabular-nums text-ink">
                      {data.score.toFixed(1)}
                    </span>
                    <span className={cn("mb-1.5 font-display text-2xl font-semibold", gradeTone(data.grade))}>
                      {data.grade}
                    </span>
                  </div>
                  <Progress value={data.score} className="mt-3" tone={data.score >= 70 ? "success" : data.score >= 40 ? "warning" : "danger"} />
                  <p className="mt-2 text-[10px] leading-relaxed text-muted">{t("posture.coverage", { value: data.coverage })}</p>
                  <dl className="mt-4 grid grid-cols-2 gap-2 text-[10px]">
                    <div className="rounded-lg border border-line/60 bg-panel2/40 p-2">
                      <dt className="text-faint">{t("posture.measuredWeight")}</dt>
                      <dd className="mt-0.5 font-mono tabular-nums text-ink">
                        {data.measured_weight}/{data.model_weight}
                      </dd>
                    </div>
                    <div className="rounded-lg border border-line/60 bg-panel2/40 p-2">
                      <dt className="text-faint">{t("posture.measuredFactors")}</dt>
                      <dd className="mt-0.5 font-mono tabular-nums text-ink">
                        {data.factors.length}/{data.methodology.model.length}
                      </dd>
                    </div>
                  </dl>
                </div>
              </Card>

              <div className="grid grid-cols-2 gap-3 lg:col-span-8">
                <StatCard
                  label={t("posture.openFindings")}
                  value={data.counts.open_findings ?? 0}
                  sub={`${data.counts.critical_open ?? 0} ${t("severity.critical")} · ${data.counts.high_open ?? 0} ${t("severity.high")}`}
                  icon={AlertCircle}
                  tone="danger"
                />
                <StatCard
                  label={t("posture.assets")}
                  value={data.counts.assets ?? 0}
                  sub={`${data.counts.services ?? 0} ${t("posture.services")}`}
                  icon={ShieldCheck}
                  tone="cyan"
                />
                <StatCard
                  label={t("posture.detections")}
                  value={data.counts.alerts ?? 0}
                  sub={`${data.counts.incidents ?? 0} ${t("posture.incidents")}`}
                  icon={CheckCircle2}
                  tone="warning"
                />
                <StatCard
                  label={t("posture.evidence")}
                  value={data.counts.evidence ?? 0}
                  sub={t("posture.evidenceSub")}
                  icon={TrendingUp}
                  tone="success"
                />
              </div>
            </section>

            <section className="grid gap-4 xl:grid-cols-12">
              <SectionCard
                className="xl:col-span-7"
                title={t("posture.factorsTitle")}
                subtitle={t("posture.factorsSubtitle")}
                icon={Gauge}
                bodyClassName="divide-y divide-line/40"
              >
                {data.factors.map((factor) => (
                  <div key={factor.key} className="px-4 py-3.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="text-[11px] font-medium text-ink">
                        {lang === "ar" ? factor.label_ar : factor.label_en}
                      </span>
                      <span className="font-mono text-[10px] tabular-nums text-muted">
                        {factor.earned.toFixed(1)}/{factor.max.toFixed(0)}
                        <span className="ms-2 text-faint">w{factor.weight}</span>
                      </span>
                    </div>
                    <Progress
                      value={factor.percent}
                      className="mt-2"
                      tone={factor.percent >= 80 ? "success" : factor.percent >= 50 ? "warning" : "danger"}
                    />
                    <p className="mt-1.5 text-[10px] leading-relaxed text-muted">{factor.detail}</p>
                  </div>
                ))}
                {!data.factors.length ? (
                  <EmptyState icon={Gauge} title={t("posture.noFactors")} description={t("posture.noFactorsBody")} />
                ) : null}
              </SectionCard>

              <div className="space-y-4 xl:col-span-5">
                <SectionCard
                  title={t("posture.missingTitle")}
                  subtitle={t("posture.missingSubtitle")}
                  icon={AlertCircle}
                  bodyClassName="divide-y divide-line/40"
                >
                  {data.missing_information.map((item) => (
                    <div key={item.key} className="px-4 py-3">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-[11px] font-medium text-ink">
                          {lang === "ar" ? item.label_ar : item.label_en}
                        </span>
                        <Badge tone="warning">w{item.weight}</Badge>
                      </div>
                      <p className="mt-1 text-[10px] leading-relaxed text-muted">{item.reason}</p>
                    </div>
                  ))}
                  {!data.missing_information.length ? (
                    <div className="px-4 py-5 text-center text-[10px] text-emerald-300">
                      {t("posture.fullyMeasured")}
                    </div>
                  ) : null}
                </SectionCard>

                <SectionCard
                  title={t("posture.actionsTitle")}
                  subtitle={t("posture.actionsSubtitle")}
                  icon={TrendingUp}
                  bodyClassName="divide-y divide-line/40"
                >
                  {data.top_actions.map((item) => (
                    <div key={item.key} className="px-4 py-3 text-[11px] leading-relaxed text-muted">
                      {item.action}
                    </div>
                  ))}
                  {!data.top_actions.length ? (
                    <div className="px-4 py-5 text-center text-[10px] text-muted">
                      {t("posture.noActions")}
                    </div>
                  ) : null}
                </SectionCard>

                <SectionCard
                  title={t("posture.methodTitle")}
                  subtitle={t("posture.methodSubtitle")}
                  icon={Info}
                  bodyClassName="space-y-2 p-4"
                >
                  {data.methodology.notes.map((note) => (
                    <p key={note} className="flex gap-2 text-[10px] leading-relaxed text-muted">
                      <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-accent/60" />
                      {note}
                    </p>
                  ))}
                  <div className="mt-3 rounded-lg border border-line/60 bg-panel2/40 p-3">
                    <p className="text-[9px] uppercase tracking-[0.1em] text-faint">{t("posture.weights")}</p>
                    <ul className="mt-1.5 space-y-1">
                      {data.methodology.model.map((factor) => (
                        <li key={factor.key} className="flex items-center justify-between text-[10px]">
                          <span className="text-muted">
                            {lang === "ar" ? factor.label_ar : factor.label_en}
                          </span>
                          <span className="font-mono tabular-nums text-ink">{factor.weight}</span>
                        </li>
                      ))}
                    </ul>
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
