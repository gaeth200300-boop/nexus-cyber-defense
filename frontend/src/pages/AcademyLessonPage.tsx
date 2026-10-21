import { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import {
  ArrowLeft,
  ArrowRight,
  Bookmark,
  BookmarkCheck,
  BookOpen,
  CheckCircle2,
  ChevronRight,
  Clock3,
  ExternalLink,
  FileText,
  FlaskConical,
  GraduationCap,
  Info,
  ListChecks,
  LockKeyhole,
  NotebookPen,
  Play,
  Save,
  ShieldCheck,
  Target,
  Timer,
  Trophy,
  Video,
  XCircle
} from "lucide-react";
import { apiFetch, errorMessage } from "../lib/api";
import { cn, formatDateTime } from "../lib/utils";
import { useToast } from "../context/ToastContext";
import { useDocumentTitle } from "../hooks";
import {
  academyDivisionLabel,
  academyLessonSummary,
  academyLessonTitle,
  academyThemes
} from "../config/academy";
import type {
  AcademyLesson,
  AcademyLessonResponse,
  AcademyQuizResponse,
  AcademyUserState,
  Lang
} from "../types";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorState,
  InlineAlert,
  KeyValue,
  PageHeader,
  Progress,
  Skeleton,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
  Textarea,
  buttonClass
} from "../components/ui";

export default function AcademyLessonPage() {
  const { slug: lessonId = "" } = useParams();
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const navigate = useNavigate();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [tab, setTab] = useState("lesson");
  const [answers, setAnswers] = useState<Record<string, string>>({});
  const [quizResult, setQuizResult] = useState<AcademyQuizResponse | null>(null);
  const [notes, setNotes] = useState("");
  const [notesDirty, setNotesDirty] = useState(false);
  const [loadedSlug, setLoadedSlug] = useState<string | null>(null);

  const detailQuery = useQuery({
    queryKey: ["academy-lesson", lessonId],
    queryFn: () => apiFetch<AcademyLessonResponse>(`/academy/lessons/${lessonId}`),
    enabled: Boolean(lessonId)
  });

  const lesson = detailQuery.data?.lesson;
  const theme = academyThemes[lesson?.division || "defense"] || academyThemes.defense;
  const Icon = theme.icon;
  useDocumentTitle(lesson ? academyLessonTitle(lesson, lang) : t("academy.lessonTitle"));

  const refreshLearning = async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ["academy-lesson", lessonId] }),
      queryClient.invalidateQueries({ queryKey: ["academy-overview"] }),
      queryClient.invalidateQueries({ queryKey: ["academy-lessons"] }),
      queryClient.invalidateQueries({ queryKey: ["academy-learning-path"] }),
      queryClient.invalidateQueries({ queryKey: ["academy-paths"] }),
      queryClient.invalidateQueries({ queryKey: ["academy-certificates"] })
    ]);
  };

  const progress = useMutation({
    mutationFn: (status: "in_progress" | "completed") =>
      apiFetch<{ user_state: AcademyUserState }>(`/academy/lessons/${lessonId}/progress`, {
        method: "PUT",
        body: { status }
      }),
    onSuccess: async (_data, status) => {
      toast.toast({
        title: status === "completed" ? t("academy.completeToast") : t("academy.progressSaved"),
        variant: "success"
      });
      await refreshLearning();
    },
    onError: (error) =>
      toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" })
  });

  const bookmark = useMutation({
    mutationFn: () =>
      apiFetch<{ user_state: AcademyUserState }>(`/academy/lessons/${lessonId}/bookmark`, {
        method: "POST",
        body: { bookmarked: !lesson?.bookmarked }
      }),
    onSuccess: async (data) => {
      toast.toast({
        title: data.user_state.bookmarked ? t("academy.bookmarkAdded") : t("academy.bookmarkRemoved"),
        variant: "success"
      });
      await refreshLearning();
    },
    onError: (error) =>
      toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" })
  });

  const saveNotes = useMutation({
    mutationFn: () =>
      apiFetch<{ notes: string; user_state: AcademyUserState }>(`/academy/lessons/${lessonId}/notes`, {
        method: "PUT",
        body: { notes }
      }),
    onSuccess: async () => {
      setNotesDirty(false);
      toast.toast({ title: t("academy.notesSaved"), variant: "success" });
      await refreshLearning();
    },
    onError: (error) =>
      toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" })
  });

  const submitQuiz = useMutation({
    mutationFn: (payload: Record<string, string>) =>
      apiFetch<AcademyQuizResponse>(`/academy/lessons/${lessonId}/quiz`, {
        method: "POST",
        body: { answers: payload }
      }),
    onSuccess: async (result) => {
      setQuizResult(result);
      toast.toast({
        title: result.passed ? t("academy.quizPassed") : t("academy.quizFailed"),
        description: `${result.score}% · ${result.correct}/${result.total}`,
        variant: result.passed ? "success" : "warning"
      });
      await refreshLearning();
    },
    onError: (error) =>
      toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" })
  });

  useEffect(() => {
    if (!lesson || loadedSlug === lesson.slug) return;
    setAnswers({});
    setNotes(lesson.notes || "");
    setNotesDirty(false);
    setQuizResult(null);
    setLoadedSlug(lesson.slug);
  }, [lesson, loadedSlug]);

  const resultsById = useMemo(() => {
    const map = new Map<string, AcademyQuizResponse["details"][number]>();
    quizResult?.details.forEach((result) => map.set(result.id, result));
    return map;
  }, [quizResult]);

  if (detailQuery.isLoading) {
    return (
      <div className="space-y-5">
        <Skeleton className="h-28 rounded-2xl" />
        <div className="grid gap-4 xl:grid-cols-12">
          <Skeleton className="h-[32rem] rounded-2xl xl:col-span-8" />
          <Skeleton className="h-96 rounded-2xl xl:col-span-4" />
        </div>
      </div>
    );
  }

  if (detailQuery.isError || !lesson) {
    return (
      <div className="space-y-5">
        <PageHeader
          eyebrow={t("academy.eyebrow")}
          icon={GraduationCap}
          title={t("academy.lessonTitle")}
          subtitle={t("academy.notFoundBody")}
          actions={<Button icon={ArrowLeft} onClick={() => navigate("/academy")}>{t("academy.backToAcademy")}</Button>}
        />
        <ErrorState
          error={detailQuery.error}
          title={t("common.errorTitle")}
          description={t("common.errorDescription")}
          onRetry={() => void detailQuery.refetch()}
        />
      </div>
    );
  }

  const detail = detailQuery.data;
  const completed = lesson.status === "completed";
  const inProgress = lesson.status === "in_progress";
  const description = lang === "ar" ? lesson.description_ar : lesson.description_en;
  const exercise = lang === "ar" ? lesson.exercise_ar : lesson.exercise_en;
  const quiz = lesson.quiz || [];
  const answered = quiz.every((question) => Boolean(answers[question.id]));
  const relatedLessons = detail?.related || [];

  const submit = () => {
    if (!answered) {
      toast.toast({ title: t("academy.answerAll"), variant: "warning" });
      return;
    }
    submitQuiz.mutate(answers);
  };

  return (
    <div className="space-y-5">
      <button
        type="button"
        onClick={() => navigate(`/academy/${lesson.division}`)}
        className="inline-flex items-center gap-1.5 text-[11px] font-medium text-muted transition hover:text-ink focus-ring"
      >
        <ArrowLeft className="h-3.5 w-3.5 rtl:rotate-180" />
        {t("academy.backToDivision")}
      </button>

      <PageHeader
        eyebrow={academyDivisionLabel(lesson.division, lang)}
        icon={Icon}
        title={academyLessonTitle(lesson, lang)}
        subtitle={academyLessonSummary(lesson, lang)}
        actions={
          <>
            <Button
              variant="secondary"
              icon={lesson.bookmarked ? BookmarkCheck : Bookmark}
              loading={bookmark.isPending}
              onClick={() => bookmark.mutate()}
            >
              {lesson.bookmarked ? t("academy.bookmarkRemove") : t("academy.bookmarkAdd")}
            </Button>
            {completed ? (
              <Button variant="success" icon={CheckCircle2} disabled>
                {t("academy.completedBadge")}
              </Button>
            ) : (
              <Button
                icon={CheckCircle2}
                loading={progress.isPending}
                onClick={() => progress.mutate("completed")}
              >
                {t("academy.markComplete")}
              </Button>
            )}
          </>
        }
      >
        <div className="flex flex-wrap items-center gap-2">
          <Badge tone={completed ? "success" : inProgress ? "warning" : "default"} dot>
            {completed ? t("academy.completedBadge") : inProgress ? t("academy.inProgressBadge") : t("academy.notStarted")}
          </Badge>
          <Badge tone={lesson.difficulty === "advanced" ? "warning" : lesson.difficulty === "intermediate" ? "info" : "success"}>
            {t(`labs.${lesson.difficulty}`, lesson.difficulty)}
          </Badge>
          <span className="inline-flex items-center gap-1 rounded-full border border-line/70 bg-panel2/50 px-2 py-0.5 text-[10px] text-muted">
            <Clock3 className="h-3 w-3" /> {t("academy.studyMinutes", { count: lesson.duration_minutes })}
          </span>
          <span className="inline-flex items-center gap-1 rounded-full border border-line/70 bg-panel2/50 px-2 py-0.5 text-[10px] text-muted">
            <ListChecks className="h-3 w-3" /> {t("academy.lessonNumber", { index: lesson.order_index })}
          </span>
          <Badge tone={lesson.video_status === "verified" ? "success" : "warning"}>
            {lesson.video_status === "verified" ? t("academy.videoVerified") : t("academy.videoPending")}
          </Badge>
          {lesson.quiz_attempts ? (
            <Badge tone="default">{t("academy.quizAttempts", { count: lesson.quiz_attempts })}</Badge>
          ) : null}
        </div>
      </PageHeader>

      <div className="grid gap-4 xl:grid-cols-12">
        <div className="min-w-0 space-y-4 xl:col-span-8">
          <Tabs value={tab} onValueChange={setTab}>
            <TabsList>
              <TabsTrigger value="lesson" icon={BookOpen}>{t("academy.overview")}</TabsTrigger>
              <TabsTrigger value="quiz" icon={ListChecks} count={quiz.length}>{t("academy.knowledgeCheck")}</TabsTrigger>
              <TabsTrigger value="notes" icon={NotebookPen}>{t("academy.notes")}</TabsTrigger>
            </TabsList>

            <TabsContent value="lesson" className="mt-4 space-y-4">
              <Card className="p-5">
                <div className="flex items-start gap-3">
                  <span className={cn("grid h-9 w-9 shrink-0 place-items-center rounded-xl border", theme.chip)}>
                    <FileText className="h-4 w-4" />
                  </span>
                  <div className="min-w-0">
                    <h2 className="text-sm font-semibold text-ink">{t("academy.overview")}</h2>
                    <p className="mt-2 whitespace-pre-line text-xs leading-relaxed text-muted">{description}</p>
                  </div>
                </div>
              </Card>

              <Card className="p-5">
                <div className="flex items-center gap-2">
                  <Target className="h-4 w-4 text-accent2" />
                  <h2 className="text-sm font-semibold text-ink">{t("academy.objectives")}</h2>
                </div>
                {lesson.objectives.length ? (
                  <ul className="mt-3 space-y-2">
                    {lesson.objectives.map((objective, index) => (
                      <li key={`${objective.en}-${index}`} className="flex items-start gap-2.5 rounded-lg border border-line/60 bg-panel2/30 p-2.5">
                        <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-300" />
                        <span className="text-[11px] leading-relaxed text-muted">{lang === "ar" ? objective.ar : objective.en}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="mt-2 text-xs text-muted">{t("academy.noObjectives")}</p>
                )}
              </Card>

              <Card className="p-5">
                <div className="flex items-center gap-2">
                  <FlaskConical className="h-4 w-4 text-violet-300" />
                  <h2 className="text-sm font-semibold text-ink">{t("academy.exercise")}</h2>
                </div>
                <p className="mt-2 whitespace-pre-line text-xs leading-relaxed text-muted">{exercise}</p>
                <InlineAlert tone="warning" icon={ShieldCheck} className="mt-3" title={t("academy.authorizedOnly")}>
                  {t("academy.exercise")}
                </InlineAlert>
              </Card>

              <div className="grid gap-3 sm:grid-cols-2">
                <Card className="p-4">
                  <div className="flex items-center gap-2">
                    <BookOpen className="h-4 w-4 text-accent" />
                    <h2 className="text-xs font-semibold text-ink">{t("academy.officialDocs")}</h2>
                  </div>
                  <p className="mt-1.5 line-clamp-2 text-[10px] leading-relaxed text-muted">
                    {lang === "ar" ? lesson.resource_label_ar : lesson.resource_label_en}
                  </p>
                  {lesson.resource_url ? (
                    <a
                      href={lesson.resource_url}
                      target="_blank"
                      rel="noreferrer noopener"
                      className={buttonClass("secondary", "sm", "mt-3")}
                    >
                      <ExternalLink className="h-3.5 w-3.5" />
                      {t("academy.openResource")}
                    </a>
                  ) : null}
                </Card>

                <Card className="p-4">
                  <div className="flex items-center gap-2">
                    <Video className="h-4 w-4 text-amber-300" />
                    <h2 className="text-xs font-semibold text-ink">{t("academy.video")}</h2>
                  </div>
                  {lesson.video_status === "verified" && lesson.video_url ? (
                    <>
                      <p className="mt-1.5 text-[10px] leading-relaxed text-muted">{t("academy.verifiedVideoBody")}</p>
                      <a
                        href={lesson.video_url}
                        target="_blank"
                        rel="noreferrer noopener"
                        className={buttonClass("secondary", "sm", "mt-3")}
                      >
                        <Play className="h-3.5 w-3.5" />
                        {t("academy.videoVerified")}
                      </a>
                    </>
                  ) : (
                    <div className="mt-2">
                      <p className="text-[10px] font-medium text-amber-200">{t("academy.videoPending")}</p>
                      <p className="mt-1 text-[10px] leading-relaxed text-muted">{t("academy.videoPendingBody")}</p>
                    </div>
                  )}
                </Card>
              </div>
            </TabsContent>
            <TabsContent value="quiz" className="mt-4 space-y-4">
              <Card className="p-5">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-start gap-3">
                    <span className={cn("grid h-9 w-9 shrink-0 place-items-center rounded-xl border", theme.chip)}>
                      <ListChecks className="h-4 w-4" />
                    </span>
                    <div>
                      <h2 className="text-sm font-semibold text-ink">{t("academy.knowledgeCheck")}</h2>
                      <p className="mt-1 text-[10px] leading-relaxed text-muted">{t("academy.knowledgeCheckBody")}</p>
                    </div>
                  </div>
                  <Badge tone="info">{quiz.length} {t("academy.question")}</Badge>
                </div>

                {quiz.length === 0 ? (
                  <p className="mt-4 text-xs text-muted">{t("academy.quizNotAvailable")}</p>
                ) : (
                  <>
                    <div className="mt-4 space-y-3">
                      {quiz.map((question, index) => {
                        const result = resultsById.get(question.id);
                        return (
                          <div
                            key={question.id}
                            className={cn(
                              "rounded-xl border p-3.5 transition",
                              result
                                ? result.correct
                                  ? "border-emerald-500/30 bg-emerald-500/[0.04]"
                                  : "border-rose-500/30 bg-rose-500/[0.04]"
                                : "border-line/70 bg-panel2/30"
                            )}
                          >
                            <div className="flex items-start gap-2.5">
                              <span className="grid h-5 w-5 shrink-0 place-items-center rounded-md border border-line/70 bg-panel font-mono text-[9px] text-faint">
                                {index + 1}
                              </span>
                              <p className="text-[11px] font-medium leading-relaxed text-ink">
                                {lang === "ar" ? question.question_ar : question.question_en}
                              </p>
                            </div>

                            <div className="mt-3 grid gap-2 sm:grid-cols-2">
                              {question.options.map((option) => {
                                const selected = answers[question.id] === option.id;
                                const showAnswer = Boolean(result && result.answer === option.id);
                                return (
                                  <button
                                    key={option.id}
                                    type="button"
                                    disabled={Boolean(quizResult) || submitQuiz.isPending}
                                    onClick={() => setAnswers((prev) => ({ ...prev, [question.id]: option.id }))}
                                    className={cn(
                                      "flex items-center gap-2 rounded-lg border px-2.5 py-2 text-start text-[10px] leading-relaxed transition focus-ring disabled:cursor-default",
                                      showAnswer
                                        ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-100"
                                        : selected
                                          ? "border-accent/45 bg-accent/10 text-ink"
                                          : "border-line/70 bg-panel/40 text-muted hover:border-accent/30 hover:text-ink"
                                    )}
                                  >
                                    <span className="grid h-5 w-5 shrink-0 place-items-center rounded-md border border-line/70 bg-panel2/60 font-mono text-[8px] uppercase text-faint">
                                      {option.id}
                                    </span>
                                    <span className="min-w-0 flex-1">{lang === "ar" ? option.ar : option.en}</span>
                                    {showAnswer ? <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-emerald-300" /> : null}
                                  </button>
                                );
                              })}
                            </div>

                            {result ? (
                              <div className="mt-3 border-t border-line/60 pt-2.5">
                                <p className={cn("text-[10px] font-semibold", result.correct ? "text-emerald-300" : "text-rose-300")}>
                                  {result.correct ? t("academy.correct") : t("academy.incorrect")}
                                  <span className="ms-1.5 font-normal text-faint">
                                    {t("academy.correctAnswer")}: {result.answer.toUpperCase()}
                                  </span>
                                </p>
                                <p className="mt-1 text-[10px] leading-relaxed text-muted">
                                  {lang === "ar" ? result.explanation_ar : result.explanation_en}
                                </p>
                              </div>
                            ) : null}
                          </div>
                        );
                      })}
                    </div>

                    {quizResult ? (
                      <div className="mt-4 grid gap-2 sm:grid-cols-3">
                        <div className="rounded-lg border border-line/70 bg-panel2/30 p-3">
                          <p className="text-[9px] uppercase tracking-[0.12em] text-faint">{t("academy.score")}</p>
                          <p className="mt-1 font-mono text-lg font-semibold text-ink">{quizResult.score}%</p>
                        </div>
                        <div className="rounded-lg border border-line/70 bg-panel2/30 p-3">
                          <p className="text-[9px] uppercase tracking-[0.12em] text-faint">{t("academy.correct")}</p>
                          <p className="mt-1 font-mono text-lg font-semibold text-ink">
                            {quizResult.correct}/{quizResult.total}
                          </p>
                        </div>
                        <div className="rounded-lg border border-line/70 bg-panel2/30 p-3">
                          <p className="text-[9px] uppercase tracking-[0.12em] text-faint">{t("academy.attempts")}</p>
                          <p className="mt-1 font-mono text-lg font-semibold text-ink">{quizResult.user_state.quiz_attempts}</p>
                        </div>
                      </div>
                    ) : null}

                    <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
                      <p className="text-[10px] text-faint">
                        {quizResult
                          ? quizResult.passed
                            ? t("academy.quizPassed")
                            : t("academy.quizFailed")
                          : t("academy.answerAll")}
                      </p>
                      <div className="flex flex-wrap gap-2">
                        {quizResult ? (
                          <Button
                            variant="secondary"
                            icon={ArrowRight}
                            onClick={() => {
                              setQuizResult(null);
                              setAnswers({});
                            }}
                          >
                            {t("academy.tryAgain")}
                          </Button>
                        ) : null}
                        <Button
                          icon={Trophy}
                          loading={submitQuiz.isPending}
                          disabled={Boolean(quizResult)}
                          onClick={submit}
                        >
                          {submitQuiz.isPending ? t("academy.submitting") : t("academy.submitAnswers")}
                        </Button>
                      </div>
                    </div>
                  </>
                )}
              </Card>
            </TabsContent>

            <TabsContent value="notes" className="mt-4">
              <Card className="p-5">
                <div className="flex items-start gap-3">
                  <span className={cn("grid h-9 w-9 shrink-0 place-items-center rounded-xl border", theme.chip)}>
                    <NotebookPen className="h-4 w-4" />
                  </span>
                  <div className="min-w-0">
                    <h2 className="text-sm font-semibold text-ink">{t("academy.notes")}</h2>
                    <p className="mt-1 text-[10px] leading-relaxed text-muted">{t("academy.notesBody")}</p>
                  </div>
                </div>
                <Textarea
                  value={notes}
                  onChange={(event) => {
                    setNotes(event.target.value);
                    setNotesDirty(true);
                  }}
                  rows={12}
                  placeholder={t("academy.notesPlaceholder")}
                  className="mt-4"
                />
                <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-[10px] tabular-nums text-faint">
                      {t("academy.notesChars", { count: notes.length })}
                    </span>
                    {notesDirty ? (
                      <Badge tone="warning" dot>
                        {t("academy.notesDirty")}
                      </Badge>
                    ) : null}
                  </div>
                  <Button
                    icon={Save}
                    loading={saveNotes.isPending}
                    disabled={!notesDirty}
                    onClick={() => saveNotes.mutate()}
                  >
                    {t("academy.saveNotes")}
                  </Button>
                </div>
              </Card>
            </TabsContent>
          </Tabs>
        </div>

        <aside className="min-w-0 space-y-4 xl:col-span-4">
          <Card className="p-4">
            <div className="flex items-center justify-between gap-2">
              <h2 className="flex items-center gap-2 text-xs font-semibold text-ink">
                <Target className="h-4 w-4 text-accent2" />
                {t("academy.lessonProgress")}
              </h2>
              <Badge tone={completed ? "success" : inProgress ? "warning" : "default"}>
                {lesson.progress_percent}%
              </Badge>
            </div>
            <Progress value={lesson.progress_percent} tone={completed ? "success" : "accent"} className="mt-3" />
            <dl className="mt-4 space-y-3">
              <KeyValue
                label={t("academy.status")}
                value={
                  completed ? t("academy.completedBadge") : inProgress ? t("academy.inProgressBadge") : t("academy.notStarted")
                }
              />
              <KeyValue label={t("academy.difficulty")} value={t(`labs.${lesson.difficulty}`, lesson.difficulty)} />
              <KeyValue label={t("academy.duration")} value={t("academy.studyMinutes", { count: lesson.duration_minutes })} />
              <KeyValue
                label={t("academy.quizAttempts", { count: lesson.quiz_attempts })}
                value={lesson.quiz_score !== null ? `${lesson.quiz_score}%` : t("academy.noQuiz")}
              />
              {lesson.completed_at ? (
                <KeyValue label={t("academy.completedOn")} value={formatDateTime(lesson.completed_at)} />
              ) : null}
            </dl>
            {!completed ? (
              <Button
                className="mt-4 w-full"
                variant={inProgress ? "secondary" : "primary"}
                icon={Play}
                loading={progress.isPending}
                onClick={() => progress.mutate("completed")}
              >
                {t("academy.markComplete")}
              </Button>
            ) : (
              <div className="mt-4 flex items-center gap-2 rounded-lg border border-emerald-500/25 bg-emerald-500/[0.06] px-3 py-2">
                <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-300" />
                <p className="text-[10px] text-emerald-200">{t("academy.completedBadge")}</p>
              </div>
            )}
          </Card>

          {detail?.prerequisites?.length ? (
            <Card className="p-4">
              <h2 className="flex items-center gap-2 text-xs font-semibold text-ink">
                <LockKeyhole className="h-4 w-4 text-amber-300" />
                {t("academy.prerequisites")}
              </h2>
              <div className="mt-3 space-y-1.5">
                {detail.prerequisites.map((item) => (
                  <button
                    key={item.slug}
                    type="button"
                    onClick={() => navigate(`/academy/lessons/${item.slug}`)}
                    className="flex w-full items-center gap-2 rounded-lg border border-line/60 bg-panel2/30 px-2.5 py-2 text-start transition hover:border-accent/30 hover:bg-panel2/60 focus-ring"
                  >
                    <BookOpen className="h-3.5 w-3.5 shrink-0 text-faint" />
                    <span className="min-w-0 flex-1 truncate text-[10px] text-muted">
                      {lang === "ar" ? item.title_ar : item.title_en}
                    </span>
                    <ChevronRight className="h-3 w-3 shrink-0 text-faint rtl:rotate-180" />
                  </button>
                ))}
              </div>
            </Card>
          ) : null}

          {relatedLessons.length ? (
            <Card className="p-4">
              <h2 className="flex items-center gap-2 text-xs font-semibold text-ink">
                <ArrowRight className="h-4 w-4 text-accent" />
                {t("academy.related")}
              </h2>
              <div className="mt-3 space-y-1.5">
                {relatedLessons.slice(0, 4).map((item) => (
                  <button
                    key={item.slug}
                    type="button"
                    onClick={() => navigate(`/academy/lessons/${item.slug}`)}
                    className="flex w-full items-center gap-2 rounded-lg border border-line/60 bg-panel2/30 px-2.5 py-2 text-start transition hover:border-accent/30 hover:bg-panel2/60 focus-ring"
                  >
                    <BookOpen className="h-3.5 w-3.5 shrink-0 text-faint" />
                    <span className="min-w-0 flex-1 truncate text-[10px] text-muted">
                      {lang === "ar" ? item.title_ar : item.title_en}
                    </span>
                    <ChevronRight className="h-3 w-3 shrink-0 text-faint rtl:rotate-180" />
                  </button>
                ))}
              </div>
              <Button
                variant="ghost"
                size="sm"
                className="mt-2 w-full"
                onClick={() => navigate(`/academy/${lesson.division}`)}
              >
                {t("academy.openDivision")}
              </Button>
            </Card>
          ) : null}

          <Card className="p-4">
            <div className="flex items-center gap-2">
              <Info className="h-4 w-4 text-accent2" />
              <h2 className="text-xs font-semibold text-ink">{t("academy.privateProgress")}</h2>
            </div>
            <p className="mt-2 text-[10px] leading-relaxed text-muted">{t("academy.privateBody")}</p>
            <div className="mt-3 space-y-2 border-t border-line/60 pt-3">
              <div className="flex items-start gap-2">
                <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-300" />
                <p className="text-[10px] leading-relaxed text-muted">{t("academy.serverBody")}</p>
              </div>
              <div className="flex items-start gap-2">
                <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-cyan-300" />
                <p className="text-[10px] leading-relaxed text-muted">{t("academy.verifiedBody")}</p>
              </div>
            </div>
            <p className="mt-3 text-[8px] leading-relaxed text-faint">{t("academy.disclaimer")}</p>
          </Card>
        </aside>
      </div>
    </div>
  );
}