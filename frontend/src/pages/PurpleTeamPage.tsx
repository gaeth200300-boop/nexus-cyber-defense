import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import {
  CheckCircle2,
  Crosshair,
  FlaskConical,
  Play,
  RefreshCw,
  ShieldQuestion,
  Target,
  XCircle
} from "lucide-react";
import { apiFetch, errorMessage } from "../lib/api";
import { cn, formatDateTime } from "../lib/utils";
import { useDocumentTitle } from "../hooks";
import { useRequiredProjectId } from "../context/ProjectContext";
import { useToast } from "../context/ToastContext";
import { DataError, ProjectGate, SectionCard } from "../components/common";
import { Badge, Button, Card, EmptyState, PageHeader, Progress, Skeleton, StatCard } from "../components/ui";
import type { Lang, PurpleRunResult, PurpleScenario, PurpleSimulation } from "../types";

export default function PurpleTeamPage() {
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const projectId = useRequiredProjectId();
  const { toast } = useToast();
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [result, setResult] = useState<PurpleRunResult | null>(null);
  useDocumentTitle(t("purple.title"));

  const scenarios = useQuery({
    queryKey: ["purple-scenarios", projectId],
    queryFn: () =>
      apiFetch<{ items: PurpleScenario[]; count: number }>(`/projects/${projectId}/purple/scenarios`),
    enabled: Boolean(projectId)
  });

  const simulations = useQuery({
    queryKey: ["purple-simulations", projectId],
    queryFn: () =>
      apiFetch<{ items: PurpleSimulation[] }>(`/projects/${projectId}/purple/simulations`),
    enabled: Boolean(projectId)
  });

  const run = useMutation({
    mutationFn: (scenarioKey: string) =>
      apiFetch<PurpleRunResult>(`/projects/${projectId}/purple/run`, {
        method: "POST",
        body: { scenario_key: scenarioKey, notes: "" }
      }),
    onSuccess: (data) => {
      setResult(data);
      toast({ title: t("purple.completed"), variant: "success" });
      void simulations.refetch();
    },
    onError: (error) => toast({ title: t("common.errorTitle"), description: errorMessage(error), variant: "error" })
  });

  const items = scenarios.data?.items || [];
  const selected = items.find((item) => item.key === selectedKey) || items[0] || null;
  const average = simulations.data?.items.length
    ? simulations.data.items.reduce((sum, item) => sum + item.score, 0) / simulations.data.items.length
    : null;

  return (
    <ProjectGate>
      <div className="space-y-5">
        <PageHeader
          eyebrow={t("purple.eyebrow")}
          icon={Crosshair}
          title={t("purple.title")}
          subtitle={t("purple.subtitle")}
          actions={
            <Button
              variant="secondary"
              size="sm"
              icon={RefreshCw}
              onClick={() => void scenarios.refetch()}
              disabled={scenarios.isFetching}
            >
              {t("common.refresh")}
            </Button>
          }
        />

        {scenarios.isLoading ? (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
              {[0, 1, 2, 3].map((key) => (
                <Skeleton key={key} className="h-24 rounded-2xl" />
              ))}
            </div>
            <Skeleton className="h-80 rounded-2xl" />
          </div>
        ) : scenarios.isError ? (
          <Card>
            <DataError
              message={scenarios.error instanceof Error ? scenarios.error.message : undefined}
              onRetry={() => void scenarios.refetch()}
            />
          </Card>
        ) : (
          <>
            <section className="grid grid-cols-2 gap-3 lg:grid-cols-4">
              <StatCard
                label={t("purple.scenarios")}
                value={items.length}
                sub={t("purple.scenariosSub")}
                icon={FlaskConical}
                tone="accent"
              />
              <StatCard
                label={t("purple.runs")}
                value={simulations.data?.items.length ?? 0}
                sub={t("purple.runsSub")}
                icon={Play}
                tone="cyan"
              />
              <StatCard
                label={t("purple.average")}
                value={average === null ? "â€”" : `${average.toFixed(0)}%`}
                sub={t("purple.averageSub")}
                icon={Target}
                tone="success"
              />
              <StatCard
                label={t("purple.lastRun")}
                value={
                  simulations.data?.items.length
                    ? formatDateTime(simulations.data.items[0].started_at, lang)
                    : "â€”"
                }
                sub={t("purple.lastRunSub")}
                icon={ShieldQuestion}
                tone="muted"
              />
            </section>

            <section className="grid gap-4 xl:grid-cols-12">
              <SectionCard
                className="xl:col-span-5"
                title={t("purple.catalogue")}
                subtitle={t("purple.catalogueSubtitle")}
                icon={FlaskConical}
                bodyClassName="divide-y divide-line/40"
              >
                {items.map((scenario) => (
                  <button
                    key={scenario.key}
                    type="button"
                    onClick={() => {
                      setSelectedKey(scenario.key);
                      setResult(null);
                    }}
                    className={cn(
                      "flex w-full flex-col gap-1 px-4 py-3 text-start transition",
                      selected?.key === scenario.key ? "bg-accent/[0.07]" : "hover:bg-panel2/50"
                    )}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <span className="min-w-0 flex-1 text-[11px] font-medium text-ink">
                        {lang === "ar" ? scenario.title_ar : scenario.title_en}
                      </span>
                      <Badge
                        tone={
                          scenario.severity === "critical"
                            ? "danger"
                            : scenario.severity === "high"
                              ? "warning"
                              : "default"
                        }
                      >
                        {scenario.technique}
                      </Badge>
                    </div>
                    <p className="line-clamp-2 text-[10px] leading-relaxed text-muted">
                      {lang === "ar" ? scenario.description_ar : scenario.description_en}
                    </p>
                    <span className="text-[9px] uppercase tracking-wider text-faint">{scenario.division}</span>
                  </button>
                ))}
              </SectionCard>

              <div className="space-y-4 xl:col-span-7">
                {selected ? (
                  <SectionCard
                    title={lang === "ar" ? selected.title_ar : selected.title_en}
                    subtitle={selected.technique}
                    icon={Target}
                    actions={
                      <Button
                        size="sm"
                        icon={Play}
                        onClick={() => run.mutate(selected.key)}
                        disabled={run.isPending}
                      >
                        {t("purple.run")}
                      </Button>
                    }
                    bodyClassName="space-y-3 p-4"
                  >
                    <p className="text-[11px] leading-relaxed text-muted">
                      {lang === "ar" ? selected.description_ar : selected.description_en}
                    </p>
                    <div className="rounded-xl border border-line/60 bg-panel2/40 p-3">
                      <p className="text-[9px] uppercase tracking-[0.1em] text-faint">
                        {t("purple.expectedTelemetry")}
                      </p>
                      <ul className="mt-2 space-y-1.5">
                        {selected.expected_telemetry.map((signal) => (
                          <li key={signal.signal} className="flex items-center gap-2 text-[10px]">
                            <span className="font-mono text-accent2">{signal.signal}</span>
                            <span className="text-faint">Â· {signal.field}</span>
                            <span className="truncate font-mono text-[9px] text-faint">{signal.pattern}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                    <p className="text-[10px] leading-relaxed text-muted">
                      <span className="text-ink">{t("purple.defensiveNote")}:</span>{" "}
                      {lang === "ar" ? selected.defensive_note_ar : selected.defensive_note_en}
                    </p>
                  </SectionCard>
                ) : null}

                {result ? (
                  <SectionCard
                    title={t("purple.resultTitle")}
                    subtitle={t("purple.resultSubtitle")}
                    icon={Crosshair}
                    bodyClassName="space-y-3 p-4"
                  >
                    <div className="flex items-center gap-4">
                      <div className="flex-1">
                        <div className="flex items-center justify-between text-[10px]">
                          <span className="text-muted">{t("purple.coverage")}</span>
                          <span className="font-mono tabular-nums text-ink">{result.score}%</span>
                        </div>
                        <Progress
                          value={result.score}
                          className="mt-1.5"
                          tone={result.score >= 80 ? "success" : result.score >= 50 ? "warning" : "danger"}
                        />
                      </div>
                      <Badge tone={result.score >= 80 ? "success" : result.score >= 50 ? "warning" : "danger"}>
                        {result.detections.length}/{result.expected.length}
                      </Badge>
                    </div>

                    <ul className="space-y-1.5">
                      {result.observed.map((signal) => (
                        <li
                          key={signal.signal}
                          className="flex items-center gap-2 rounded-lg border border-line/60 bg-panel2/40 px-2.5 py-2"
                        >
                          {signal.detected ? (
                            <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-emerald-400" />
                          ) : (
                            <XCircle className="h-3.5 w-3.5 shrink-0 text-rose-400" />
                          )}
                          <span className="min-w-0 flex-1 truncate font-mono text-[10px] text-ink">
                            {signal.signal}
                          </span>
                          <span className="shrink-0 text-[9px] text-faint">{signal.field}</span>
                        </li>
                      ))}
                    </ul>

                    <p className="rounded-xl border border-amber-400/20 bg-amber-400/[0.06] p-3 text-[10px] leading-relaxed text-amber-100/90">
                      {result.recommendation}
                    </p>
                  </SectionCard>
                ) : (
                  <Card>
                    <EmptyState
                      icon={Play}
                      title={t("purple.noResult")}
                      description={t("purple.noResultBody")}
                    />
                  </Card>
                )}

                <SectionCard
                  title={t("purple.history")}
                  subtitle={t("purple.historySubtitle")}
                  icon={FlaskConical}
                  bodyClassName="divide-y divide-line/40"
                >
                  {simulations.data?.items.length ? (
                    simulations.data.items.map((simulation) => (
                      <div key={simulation.id} className="flex items-center justify-between gap-3 px-4 py-3">
                        <div className="min-w-0">
                          <p className="truncate text-[11px] text-ink">{simulation.scenario_title}</p>
                          <p className="mt-0.5 text-[9px] text-faint">
                            {simulation.started_at ? formatDateTime(simulation.started_at, lang) : ""} Â·{" "}
                            {simulation.missed.length} {t("purple.missed")}
                          </p>
                        </div>
                        <span
                          className={cn(
                            "shrink-0 font-mono text-xs tabular-nums",
                            simulation.score >= 80
                              ? "text-emerald-300"
                              : simulation.score >= 50
                                ? "text-amber-300"
                                : "text-rose-300"
                          )}
                        >
                          {simulation.score}%
                        </span>
                      </div>
                    ))
                  ) : (
                    <EmptyState icon={FlaskConical} title={t("purple.noRuns")} description={t("purple.noRunsBody")} />
                  )}
                </SectionCard>
              </div>
            </section>
          </>
        )}
      </div>
    </ProjectGate>
  );
}

