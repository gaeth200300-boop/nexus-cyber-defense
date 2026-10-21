import { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import {
  AlertTriangle,
  ArrowLeft,
  Award,
  CheckCircle2,
  ChevronRight,
  Clock3,
  Download,
  FileSearch,
  Flag,
  FlaskConical,
  Lightbulb,
  Loader2,
  LockKeyhole,
  Play,
  RotateCcw,
  ShieldCheck,
  Sparkles,
  Target,
  XCircle
} from "lucide-react";
import { apiFetch, downloadApiFile, errorMessage } from "../lib/api";
import { cn, formatDateTime, fromNow } from "../lib/utils";
import { useProject } from "../context/ProjectContext";
import { useToast } from "../context/ToastContext";
import { useDocumentTitle } from "../hooks";
import type { Lab, LabCheck, LabCheckResult, LabRun, Lang } from "../types";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  InlineAlert,
  KeyValue,
  PageHeader,
  Progress,
  Skeleton,
  StatusBadge,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger
} from "../components/ui";

interface LabDetailResponse {
  lab: Lab & { run?: LabRun | null; hints?: { en: string; ar: string }[] };
}

interface SubmitResponse {
  run_id: string;
  lab_id: string;
  passed: boolean;
  score: number;
  max_points: number;
  checks: LabCheckResult[];
  achievements: string[];
  pending: boolean;
  run: LabRun;
  explanations: Record<string, { explanation_en: string; explanation_ar: string }>;
}

interface HintResponse {
  hint: { en: string; ar: string } | null;
  index?: number;
  used: number;
  total: number;
  message?: string;
  run: LabRun;
}

export default function LabDetailPage() {
  const { labId = "" } = useParams();
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const navigate = useNavigate();
  const toast = useToast();
  const queryClient = useQueryClient();
  const { selectedProject, canWrite } = useProject();
  const [tab, setTab] = useState("brief");
  const [answers, setAnswers] = useState<Record<string, string>>({});
  const [explanations, setExplanations] = useState<Record<string, { explanation_en: string; explanation_ar: string }>>({});
  const [confirmReset, setConfirmReset] = useState(false);

  const detail = useQuery({
    queryKey: ["lab", labId],
    queryFn: () => apiFetch<LabDetailResponse>(`/labs/${labId}`),
    enabled: Boolean(labId)
  });

  const lab = detail.data?.lab;
  const run = lab?.run || null;
  useDocumentTitle(lab ? (lang === "ar" ? lab.title_ar : lab.title_en) : t("labs.title"));

  useEffect(() => {
    if (run) setAnswers(run.answers || {});
  }, [run?.id, run?.answers]);

  const start = useMutation({
    mutationFn: () =>
      apiFetch<{ run: LabRun }>(`/labs/${labId}/start`, {
        method: "POST",
        body: { project_id: selectedProject?.id || null }
      }),
    onSuccess: async () => {
      toast.toast({ title: t("labs.started"), variant: "success" });
      await queryClient.invalidateQueries({ queryKey: ["lab", labId] });
      await queryClient.invalidateQueries({ queryKey: ["lab-stats"] });
      setTab("checks");
    },
    onError: (error) => toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" })
  });

  const submit = useMutation({
    mutationFn: () =>
      apiFetch<SubmitResponse>(`/labs/runs/${run?.id}/submit`, {
        method: "POST",
        body: { answers }
      }),
    onSuccess: async (result) => {
      setExplanations(result.explanations || {});
      if (result.passed) {
        toast.toast({ title: t("labs.passed"), description: `${result.score}/${result.max_points}`, variant: "success" });
        setTab("checks");
      } else if (result.pending) {
        toast.toast({ title: t("labs.result"), description: t("labs.pending"), variant: "warning" });
      } else {
        toast.toast({ title: t("labs.incorrect"), variant: "warning" });
      }
      await queryClient.invalidateQueries({ queryKey: ["lab", labId] });
      await queryClient.invalidateQueries({ queryKey: ["lab-stats"] });
      await queryClient.invalidateQueries({ queryKey: ["lab-leaderboard"] });
    },
    onError: (error) => toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" })
  });

  const hint = useMutation({
    mutationFn: () => apiFetch<HintResponse>(`/labs/runs/${run?.id}/hint`, { method: "POST" }),
    onSuccess: async (result) => {
      if (!result.hint) {
        toast.toast({ title: t("labs.noHints"), description: result.message, variant: "default" });
        return;
      }
      toast.toast({ title: t("labs.hint"), description: lang === "ar" ? result.hint.ar : result.hint.en, variant: "default" });
      await queryClient.invalidateQueries({ queryKey: ["lab", labId] });
    },
    onError: (error) => toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" })
  });

  const reset = useMutation({
    mutationFn: () => apiFetch<{ run: LabRun }>(`/labs/runs/${run?.id}/reset`, { method: "POST" }),
    onSuccess: async () => {
      setConfirmReset(false);
      setAnswers({});
      setExplanations({});
      toast.toast({ title: t("labs.resetDone"), variant: "success" });
      await queryClient.invalidateQueries({ queryKey: ["lab", labId] });
      await queryClient.invalidateQueries({ queryKey: ["lab-stats"] });
    },
    onError: (error) => toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" })
  });

  const checkResults = useMemo(() => {
    const map = new Map<string, LabCheckResult>();
    (run?.checks_result || []).forEach((result) => map.set(result.key, result));
    return map;
  }, [run?.checks_result]);

  const resultByKey = (key: string) => checkResults.get(key);
  const quizChecks = lab?.checks.filter((check) => check.type === "quiz") || [];
  const autoChecks = lab?.checks.filter((check) => check.type !== "quiz") || [];
  const projectChecks = autoChecks.some((check) => check.type === "project_state");
  const allAnswered = quizChecks.every((check) => answers[check.key]);
  const passed = run?.status === "passed";

  return (
    <div className="space-y-5">
      <button
        type="button"
        onClick={() => navigate("/labs")}
        className="inline-flex items-center gap-1.5 text-[10px] text-muted transition hover:text-ink"
      >
        <ArrowLeft className="h-3.5 w-3.5 rtl:rotate-180" /> {t("labs.back")}
      </button>

      {detail.isLoading ? (
        <div className="space-y-4">
          <Skeleton className="h-36 rounded-2xl" />
          <Skeleton className="h-72 rounded-2xl" />
        </div>
      ) : detail.isError || !lab ? (
        <Card className="p-2">
          <EmptyState
            icon={FlaskConical}
            title={t("common.errorTitle")}
            description={detail.error instanceof Error ? detail.error.message : t("common.errorDescription")}
            action={<Button variant="secondary" onClick={() => void detail.refetch()}>{t("common.retry")}</Button>}
          />
        </Card>
      ) : (
        <>
          <div className="relative overflow-hidden rounded-2xl border border-line/60 bg-gradient-to-br from-accent/[0.08] via-panel to-accent2/[0.05] p-5">
            <div className="absolute -end-8 -top-8 h-40 w-40 rounded-full bg-accent/10 blur-3xl" />
            <div className="relative flex flex-wrap items-start gap-3">
              <span className="grid h-12 w-12 shrink-0 place-items-center rounded-xl border border-accent/20 bg-accent/[0.08] text-accent">
                <FlaskConical className="h-6 w-6" />
              </span>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone="accent">{label(lab.category_label, lang)}</Badge>
                  <Badge tone="info">{label(lab.level_label, lang)}</Badge>
                  {passed ? <Badge tone="success" dot>{t("labs.passed")}</Badge> : run ? <Badge tone="warning" dot>{t("labs.inProgress")}</Badge> : null}
                  {lab.requires_private_access ? <Badge tone="warning"><LockKeyhole className="h-2.5 w-2.5" /> private</Badge> : null}
                </div>
                <h1 className="mt-2 font-display text-2xl font-semibold text-ink">{lang === "ar" ? lab.title_ar : lab.title_en}</h1>
                <p className="mt-1 max-w-3xl text-[11px] leading-relaxed text-muted">{lang === "ar" ? lab.description_ar : lab.description_en}</p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                {!run ? (
                  <Button icon={Play} loading={start.isPending} onClick={() => start.mutate()} disabled={!canWrite}>
                    {t("labs.start")}
                  </Button>
                ) : passed ? (
                  <Button variant="secondary" icon={RotateCcw} onClick={() => start.mutate()} disabled={!canWrite}>
                    {t("labs.retry")}
                  </Button>
                ) : (
                  <Badge tone="info">{t("labs.attempt")} #{run.attempts}</Badge>
                )}
              </div>
            </div>

            <div className="relative mt-4 grid grid-cols-2 gap-2 sm:grid-cols-4">
              {[
                { icon: Target, label: t("labs.checks"), value: `${lab.check_count}` },
                { icon: Sparkles, label: t("labs.points"), value: `${run?.score ?? lab.user_state.best_score}/${lab.max_points}` },
                { icon: Lightbulb, label: t("labs.hints"), value: `${run?.hints_used.length ?? 0}/${lab.hints_total}` },
                { icon: Clock3, label: t("labs.status"), value: run ? t(`status.${run.status}`) : t("labs.start") }
              ].map((item) => (
                <div key={item.label} className="rounded-xl border border-line/50 bg-panel/40 p-2.5">
                  <div className="flex items-center gap-1.5 text-[8px] uppercase tracking-wider text-faint">
                    <item.icon className="h-3 w-3" /> {item.label}
                  </div>
                  <p className="mt-1 text-[11px] font-semibold text-ink">{item.value}</p>
                </div>
              ))}
            </div>
            {run ? (
              <div className="relative mt-3">
                <Progress value={lab.max_points ? (run.score / lab.max_points) * 100 : 0} className="h-1.5" tone={passed ? "success" : "accent"} />
              </div>
            ) : null}
          </div>

          {run?.status === "failed" ? <InlineAlert tone="warning" title={t("labs.incorrect")}>{t("labs.reviewEvidence")}</InlineAlert> : null}
          {projectChecks && !run?.project_id ? (
            <InlineAlert tone="info" title={t("labs.projectCheckTitle")}>{t("labs.projectCheckBody")}</InlineAlert>
          ) : null}

          <Tabs value={tab} onValueChange={setTab}>
            <TabsList>
              <TabsTrigger value="brief" icon={FileSearch}>{t("labs.brief")}</TabsTrigger>
              <TabsTrigger value="checks" icon={Target} count={lab.check_count}>{t("labs.checks")}</TabsTrigger>
              <TabsTrigger value="hints" icon={Lightbulb} count={run?.hints_used.length || 0}>{t("labs.hints")}</TabsTrigger>
            </TabsList>

            <TabsContent value="brief" className="mt-4">
              <div className="grid gap-4 xl:grid-cols-12">
                <Card className="p-4 xl:col-span-8">
                  <h3 className="text-xs font-semibold text-ink">{t("labs.brief")}</h3>
                  <p className="mt-2 whitespace-pre-wrap text-[11px] leading-relaxed text-muted">
                    {lang === "ar" ? lab.description_ar : lab.description_en}
                  </p>
                  <h3 className="mt-5 text-xs font-semibold text-ink">{t("labs.objectives")}</h3>
                  <ol className="mt-2 space-y-2">
                    {lab.objectives.map((objective) => (
                      <li key={objective.key} className="flex items-start gap-2 text-[10px] leading-relaxed text-muted">
                        <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-300" />
                        {lang === "ar" ? objective.label_ar : objective.label_en}
                      </li>
                    ))}
                  </ol>
                </Card>
                <div className="space-y-4 xl:col-span-4">
                  <Card className="p-4">
                    <h3 className="text-xs font-semibold text-ink">{t("common.details")}</h3>
                    <dl className="mt-3 space-y-2.5">
                      <KeyValue label={t("labs.category")} value={label(lab.category_label, lang)} />
                      <KeyValue label={t("labs.level")} value={label(lab.level_label, lang)} />
                      <KeyValue label={t("labs.points")} value={String(lab.max_points)} />
                      <KeyValue label={t("labs.target")} value={lab.target_kind} />
                      <KeyValue label={t("labs.attempts")} value={String(lab.user_state.attempts)} />
                      <KeyValue label={t("labs.bestScore")} value={`${lab.user_state.best_score}/${lab.max_points}`} />
                    </dl>
                    {lab.fixture_available ? (
                      <Button
                        variant="secondary"
                        icon={Download}
                        className="mt-3 w-full"
                        onClick={() => void downloadApiFile(`/labs/${lab.id}/fixture`)}
                      >
                        {t("labs.downloadFixture")}
                      </Button>
                    ) : null}
                  </Card>
                  <Card className="p-4">
                    <div className="flex items-start gap-2">
                      <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-emerald-300" />
                      <div>
                        <h3 className="text-xs font-semibold text-ink">{t("labs.honestTitle")}</h3>
                        <p className="mt-1 text-[9px] leading-relaxed text-muted">{t("labs.honestBody")}</p>
                      </div>
                    </div>
                  </Card>
                </div>
              </div>
            </TabsContent>

            <TabsContent value="checks" className="mt-4 space-y-4">
              {!run ? (
                <Card className="p-8">
                  <EmptyState
                    icon={FlaskConical}
                    title={t("labs.notStarted")}
                    description={t("labs.notStartedBody")}
                    action={<Button icon={Play} loading={start.isPending} onClick={() => start.mutate()} disabled={!canWrite}>{t("labs.start")}</Button>}
                  />
                </Card>
              ) : (
                <>
                  {quizChecks.length ? (
                    <Card className="p-4">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div>
                          <h3 className="text-xs font-semibold text-ink">{t("labs.questions")}</h3>
                          <p className="mt-0.5 text-[10px] text-muted">{t("labs.answerHint")}</p>
                        </div>
                        <Badge tone="info">{quizChecks.filter((check) => answers[check.key]).length}/{quizChecks.length}</Badge>
                      </div>
                      <div className="mt-4 space-y-4">
                        {quizChecks.map((check, index) => (
                          <QuizCheck
                            key={check.key}
                            check={check}
                            index={index}
                            lang={lang}
                            value={answers[check.key] || ""}
                            onChange={(value) => setAnswers((current) => ({ ...current, [check.key]: value }))}
                            result={resultByKey(check.key)}
                            explanation={explanations[check.key]}
                            disabled={passed || run.status === "reset"}
                          />
                        ))}
                      </div>
                    </Card>
                  ) : null}

                  {autoChecks.length ? (
                    <Card className="p-4">
                      <h3 className="text-xs font-semibold text-ink">{t("labs.autoChecks")}</h3>
                      <p className="mt-0.5 text-[10px] text-muted">{t("labs.autoChecksBody")}</p>
                      <div className="mt-3 divide-y divide-line/50">
                        {autoChecks.map((check) => {
                          const result = resultByKey(check.key);
                          return (
                            <div key={check.key} className="flex flex-wrap items-center gap-3 py-3">
                              <CheckStatus status={result?.status} />
                              <div className="min-w-0 flex-1">
                                <p className="text-[10px] font-medium text-ink">{lang === "ar" ? check.label_ar : check.label_en}</p>
                                <p className="mt-0.5 text-[9px] text-faint">
                                  {check.type === "file_analysis" ? t("labs.fixtureHint") : check.type === "project_state" ? t("labs.projectCheckBody") : check.type}
                                  {result?.detail ? ` · ${result.detail}` : ""}
                                </p>
                              </div>
                              <span className="font-mono text-[9px] text-faint">{check.points} pts</span>
                            </div>
                          );
                        })}
                      </div>
                    </Card>
                  ) : null}

                  {run.status !== "reset" ? (
                    <div className="flex flex-wrap items-center gap-2">
                      <Button
                        icon={Flag}
                        loading={submit.isPending}
                        onClick={() => submit.mutate()}
                        disabled={!canWrite || !allAnswered || run.status === "passed"}
                      >
                        {t("labs.submitAnswer")}
                      </Button>
                      {run.status === "passed" ? (
                        <Badge tone="success"><Award className="h-3 w-3" /> {run.score}/{lab.max_points}</Badge>
                      ) : (
                        <span className="text-[9px] text-faint">{t("labs.submitHint")}</span>
                      )}
                      <div className="ms-auto flex items-center gap-2">
                        {confirmReset ? (
                          <>
                            <span className="text-[9px] text-rose-300">{t("labs.resetConfirm")}</span>
                            <Button size="sm" variant="danger" loading={reset.isPending} onClick={() => reset.mutate()}>{t("common.confirm")}</Button>
                            <Button size="sm" variant="ghost" onClick={() => setConfirmReset(false)}>{t("common.cancel")}</Button>
                          </>
                        ) : (
                          <Button size="sm" variant="ghost" icon={RotateCcw} onClick={() => setConfirmReset(true)} disabled={!canWrite}>
                            {t("labs.reset")}
                          </Button>
                        )}
                      </div>
                    </div>
                  ) : null}
                </>
              )}
            </TabsContent>

            <TabsContent value="hints" className="mt-4">
              <Card className="p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <h3 className="text-xs font-semibold text-ink">{t("labs.hints")}</h3>
                    <p className="mt-0.5 text-[10px] text-muted">{t("labs.hintsBody")}</p>
                  </div>
                  <Button
                    size="sm"
                    variant="secondary"
                    icon={Lightbulb}
                    loading={hint.isPending}
                    disabled={!canWrite || !run || (run.hints_used.length >= lab.hints_total)}
                    onClick={() => hint.mutate()}
                  >
                    {t("labs.revealHint")}
                  </Button>
                </div>
                {!run ? (
                  <p className="mt-4 text-[10px] text-faint">{t("labs.startToHint")}</p>
                ) : lab.hints?.length ? (
                  <div className="mt-4 space-y-2">
                    {lab.hints.map((hintText, index) => (
                      <div key={index} className="rounded-xl border border-amber-400/20 bg-amber-400/[0.04] p-3">
                        <p className="text-[8px] uppercase tracking-wider text-amber-300/70">{t("labs.hint")} {index + 1}</p>
                        <p className="mt-1 text-[10px] leading-relaxed text-muted">{lang === "ar" ? hintText.ar : hintText.en}</p>
                      </div>
                    ))}
                    {run.hints_used.length < lab.hints_total ? (
                      <div className="flex items-center justify-center gap-2 rounded-xl border border-dashed border-line/60 p-4 text-[9px] text-faint">
                        <LockKeyhole className="h-3.5 w-3.5" /> {lab.hints_total - run.hints_used.length} {t("labs.hintsRemaining")}
                      </div>
                    ) : null}
                  </div>
                ) : (
                  <EmptyState icon={Lightbulb} title={t("labs.noHints")} />
                )}
              </Card>
            </TabsContent>
          </Tabs>
        </>
      )}
    </div>
  );
}

function QuizCheck({
  check,
  index,
  lang,
  value,
  onChange,
  result,
  explanation,
  disabled
}: {
  check: LabCheck;
  index: number;
  lang: Lang;
  value: string;
  onChange: (value: string) => void;
  result?: LabCheckResult;
  explanation?: { explanation_en: string; explanation_ar: string };
  disabled?: boolean;
}) {
  const { t } = useTranslation();
  const explanationText = explanation ? (lang === "ar" ? explanation.explanation_ar : explanation.explanation_en) : "";
  return (
    <div className="rounded-xl border border-line/60 bg-panel2/20 p-3.5">
      <div className="flex flex-wrap items-start gap-2">
        <span className="grid h-6 w-6 shrink-0 place-items-center rounded-md border border-line bg-panel2 font-mono text-[9px] text-faint">{index + 1}</span>
        <p className="min-w-0 flex-1 text-[11px] font-medium leading-relaxed text-ink">{lang === "ar" ? check.question_ar || check.label_ar : check.question_en || check.label_en}</p>
        <span className="font-mono text-[9px] text-faint">{check.points}</span>
        {result ? <CheckStatus status={result.status} /> : null}
      </div>
      <div className="mt-3 grid gap-1.5 sm:grid-cols-2">
        {(check.options || []).map((option) => (
          <label
            key={option.id}
            className={cn(
              "flex cursor-pointer items-center gap-2 rounded-lg border px-2.5 py-2 text-[10px] transition",
              value === option.id ? "border-accent/35 bg-accent/[0.07] text-ink" : "border-line/60 bg-panel/30 text-muted hover:border-line",
              disabled && "cursor-not-allowed opacity-70"
            )}
          >
            <input
              type="radio"
              name={check.key}
              value={option.id}
              checked={value === option.id}
              onChange={() => onChange(option.id)}
              disabled={disabled}
              className="h-3 w-3 accent-[rgb(var(--accent))]"
            />
            {lang === "ar" ? option.ar : option.en}
          </label>
        ))}
      </div>
      {result?.status === "failed" ? (
        <p className="mt-2 flex items-center gap-1 text-[9px] text-rose-300"><XCircle className="h-3 w-3" /> {t("labs.incorrect")}</p>
      ) : result?.status === "passed" ? (
        <p className="mt-2 flex items-center gap-1 text-[9px] text-emerald-300"><CheckCircle2 className="h-3 w-3" /> {t("labs.correct")}</p>
      ) : null}
      {explanationText && result?.status === "passed" ? (
        <p className="mt-2 rounded-lg border border-emerald-400/15 bg-emerald-400/[0.04] p-2 text-[9px] leading-relaxed text-muted">{explanationText}</p>
      ) : null}
    </div>
  );
}

function CheckStatus({ status }: { status?: string }) {
  const { t } = useTranslation();
  if (!status) return null;
  if (status === "passed") return <Badge tone="success"><CheckCircle2 className="h-2.5 w-2.5" /> {t("labs.correct")}</Badge>;
  if (status === "failed") return <Badge tone="danger"><XCircle className="h-2.5 w-2.5" /> {t("labs.failed")}</Badge>;
  if (status === "needs_project") return <Badge tone="warning"><LockKeyhole className="h-2.5 w-2.5" /> {t("labs.needsProject")}</Badge>;
  if (status === "needs_answers") return <Badge tone="info">{t("labs.needsAnswer")}</Badge>;
  return <Badge tone="default">{status.replaceAll("_", " ")}</Badge>;
}

function label(labels: Record<string, string> | undefined, lang: Lang): string {
  return labels?.[lang] || labels?.en || "";
}
