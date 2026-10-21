import { useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import {
  ArrowLeft,
  ArrowRight,
  Award,
  Bookmark,
  BookmarkCheck,
  CheckCircle2,
  ChevronDown,
  Clock3,
  GraduationCap,
  Layers3,
  LockKeyhole,
  RefreshCw,
  Search,
  Sparkles,
  Target,
  Timer,
  Trophy,
  X
} from "lucide-react";
import { apiFetch, errorMessage } from "../lib/api";
import { cn, formatDate } from "../lib/utils";
import { useToast } from "../context/ToastContext";
import { useDocumentTitle } from "../hooks";
import {
  academyDivisionTitle,
  academyDivisions,
  academyLessonSummary,
  academyReasonLabel,
  academyStageKey,
  academyStageTitle,
  academyThemes,
  isAcademyDivision
} from "../config/academy";
import type {
  AcademyCertificate,
  AcademyCertificatesResponse,
  AcademyDivision,
  AcademyLesson,
  AcademyLessonList,
  AcademyLearningPath,
  AcademyOverview,
  Lang
} from "../types";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorState,
  Input,
  KeyValue,
  PageHeader,
  Progress,
  Select,
  Skeleton,
  StatCard
} from "../components/ui";

const difficultyTone: Record<string, "success" | "info" | "warning"> = {
  beginner: "success",
  intermediate: "info",
  advanced: "warning"
};

export default function AcademyDivisionPage() {
  const { division = "" } = useParams();
  const valid = isAcademyDivision(division);
  const divisionKey = valid ? division : "";
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const navigate = useNavigate();
  const toast = useToast();
  const queryClient = useQueryClient();

  const [q, setQ] = useState("");
  const [category, setCategory] = useState("");
  const [difficulty, setDifficulty] = useState("");
  const [status, setStatus] = useState("");
  const [bookmarkedOnly, setBookmarkedOnly] = useState(false);
  const [collapsed, setCollapsed] = useState<string[]>([]);

  const overview = useQuery({
    queryKey: ["academy-overview"],
    queryFn: () => apiFetch<AcademyOverview>("/academy/overview")
  });

  const lessonsQuery = useQuery({
    queryKey: ["academy-lessons", divisionKey],
    queryFn: () =>
      apiFetch<AcademyLessonList>("/academy/lessons", {
        query: { division: divisionKey, limit: 100 }
      }),
    enabled: valid
  });

  const path = useQuery({
    queryKey: ["academy-learning-path", divisionKey],
    queryFn: () =>
      apiFetch<AcademyLearningPath>("/academy/learning-path", {
        query: { division: divisionKey }
      }),
    enabled: valid
  });

  const certificates = useQuery({
    queryKey: ["academy-certificates"],
    queryFn: () => apiFetch<AcademyCertificatesResponse>("/academy/certificates"),
    enabled: valid
  });

  const meta = overview.data?.divisions.find((item) => item.key === divisionKey);
  const lessons = lessonsQuery.data?.items || [];
  const stages = meta?.stages || [];
  const bucket = overview.data?.summary.divisions[divisionKey];
  useDocumentTitle(meta ? academyDivisionTitle(meta, lang) : t("academy.title"));

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return lessons.filter((lesson) => {
      if (category && lesson.category !== category) return false;
      if (difficulty && lesson.difficulty !== difficulty) return false;
      if (status && lesson.status !== status) return false;
      if (bookmarkedOnly && !lesson.bookmarked) return false;
      if (!needle) return true;
      return [lesson.title_en, lesson.title_ar, lesson.summary_en, lesson.summary_ar, lesson.category]
        .join(" ")
        .toLowerCase()
        .includes(needle);
    });
  }, [lessons, q, category, difficulty, status, bookmarkedOnly]);

  const groups = useMemo(() => {
    if (!stages.length) {
      return filtered.length ? [{ key: "all", stage: null, lessons: filtered }] : [];
    }
    return stages
      .map((stage) => ({
        key: stage.key,
        stage,
        lessons: filtered.filter((lesson) => academyStageKey(lesson, stages) === stage.key)
      }))
      .filter((group) => group.lessons.length > 0);
  }, [filtered, stages]);

  const filtersActive = Boolean(q || category || difficulty || status || bookmarkedOnly);
  const nextLesson = path.data?.recommendations[0];
  const existingCertificate = certificates.data?.items.find((item) => item.division === divisionKey);
  const allComplete = Boolean(meta && meta.total > 0 && meta.completed >= meta.total);

  const issueCertificate = useMutation({
    mutationFn: () =>
      apiFetch<AcademyCertificate>(`/academy/certificates/${divisionKey}`, {
        method: "POST",
        body: { display_name: "" }
      }),
    onSuccess: async () => {
      toast.toast({ title: t("academy.issued"), variant: "success" });
      await queryClient.invalidateQueries({ queryKey: ["academy-certificates"] });
    },
    onError: (error) =>
      toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" })
  });

  const resetFilters = () => {
    setQ("");
    setCategory("");
    setDifficulty("");
    setStatus("");
    setBookmarkedOnly(false);
  };

  if (!valid) {
    return (
      <div className="space-y-5">
        <PageHeader
          eyebrow={t("academy.eyebrow")}
          icon={GraduationCap}
          title={t("academy.notFound")}
          subtitle={t("academy.notFoundBody")}
          actions={
            <Button icon={ArrowLeft} onClick={() => navigate("/academy")}>
              {t("academy.backToAcademy")}
            </Button>
          }
        />
        <Card>
          <EmptyState
            icon={Search}
            title={t("academy.notFound")}
            description={t("academy.notFoundBody")}
            action={
              <Button variant="secondary" onClick={() => navigate("/academy")}>
                {t("academy.openAcademy")}
              </Button>
            }
          />
        </Card>
      </div>
    );
  }

  const theme = academyThemes[divisionKey] || academyThemes.defense;
  const Icon = theme.icon;
  const categoryMeta = meta?.categories.find((item) => item.key === category);

  return (
    <div className="space-y-5">
      <button
        type="button"
        onClick={() => navigate("/academy")}
        className="inline-flex items-center gap-1.5 text-[11px] font-medium text-muted transition hover:text-ink focus-ring"
      >
        <ArrowLeft className="h-3.5 w-3.5 rtl:rotate-180" />
        {t("academy.backToAcademy")}
      </button>

      <PageHeader
        eyebrow={t("academy.eyebrow")}
        icon={Icon}
        title={meta ? academyDivisionTitle(meta, lang) : t("academy.division")}
        subtitle={
          meta
            ? `${lang === "ar" ? meta.tagline_ar : meta.tagline_en} ${lang === "ar" ? meta.description_ar : meta.description_en}`
            : t("academy.subtitle")
        }
        actions={
          nextLesson ? (
            <Button icon={Sparkles} onClick={() => navigate(`/academy/lessons/${nextLesson.slug}`)}>
              {t("academy.nextLesson")}
            </Button>
          ) : allComplete ? (
            <Badge tone="success" dot>{t("academy.divisionComplete")}</Badge>
          ) : null
        }
      />

      <section className="grid grid-cols-2 gap-2.5 xl:grid-cols-4">
        <StatCard
          label={t("academy.completedLessons")}
          value={meta ? `${meta.completed}/${meta.total}` : "—"}
          sub={meta ? t("academy.catalogCount", { count: meta.total }) : undefined}
          icon={CheckCircle2}
          tone="success"
        />
        <StatCard
          label={t("academy.progress")}
          value={meta ? `${meta.percent}%` : "—"}
          sub={allComplete ? t("academy.divisionComplete") : t("academy.overall")}
          icon={Target}
          tone="cyan"
        />
        <StatCard
          label={t("academy.averageQuiz")}
          value={meta?.average_quiz != null ? `${meta.average_quiz}%` : "—"}
          sub={t("academy.score")}
          icon={Trophy}
          tone="warning"
        />
        <StatCard
          label={t("academy.studyTime")}
          value={bucket ? t("academy.studyMinutes", { count: bucket.minutes_completed }) : "—"}
          sub={bucket ? `${bucket.minutes_completed}/${bucket.minutes_total}` : undefined}
          icon={Clock3}
          tone="accent"
        />
      </section>

      {nextLesson ? (
        <div className={cn("relative overflow-hidden rounded-2xl border p-4", theme.ring)}>
          <div className={cn("pointer-events-none absolute -end-8 -top-10 h-32 w-32 rounded-full blur-3xl", theme.glow)} />
          <div className="relative flex flex-wrap items-center gap-3">
            <span className={cn("grid h-10 w-10 shrink-0 place-items-center rounded-xl border", theme.chip)}>
              <Target className="h-4.5 w-4.5" />
            </span>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <Badge tone="accent">{t("academy.recommended")}</Badge>
                <span className="text-[9px] text-faint">
                  {t("academy.reason")}: {academyReasonLabel(nextLesson.reason, t)}
                </span>
              </div>
              <p className="mt-1 truncate text-xs font-semibold text-ink">
                {lang === "ar" ? nextLesson.title_ar : nextLesson.title_en}
              </p>
            </div>
            <Button size="sm" icon={ArrowRight} onClick={() => navigate(`/academy/lessons/${nextLesson.slug}`)}>
              {t("academy.openLesson")}
            </Button>
          </div>
        </div>
      ) : null}

      <Card className="p-3">
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative min-w-[210px] flex-1">
            <Search className="pointer-events-none absolute start-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-faint" />
            <Input
              value={q}
              onChange={(event) => setQ(event.target.value)}
              placeholder={t("academy.searchPlaceholder")}
              className="ps-9"
            />
          </div>
          <Select value={category} onChange={(event) => setCategory(event.target.value)} className="w-auto max-w-[220px]">
            <option value="">{t("academy.allCategories")}</option>
            {(meta?.categories || []).map((item) => (
              <option key={item.key} value={item.key}>{lang === "ar" ? item.ar : item.en}</option>
            ))}
          </Select>
          <Select value={difficulty} onChange={(event) => setDifficulty(event.target.value)} className="w-auto">
            <option value="">{t("academy.difficulty")} · {t("common.all")}</option>
            <option value="beginner">{t("labs.beginner")}</option>
            <option value="intermediate">{t("labs.intermediate")}</option>
            <option value="advanced">{t("labs.advanced")}</option>
          </Select>
          <Select value={status} onChange={(event) => setStatus(event.target.value)} className="w-auto">
            <option value="">{t("academy.allStatuses")}</option>
            <option value="not_started">{t("academy.notStarted")}</option>
            <option value="in_progress">{t("academy.inProgressBadge")}</option>
            <option value="completed">{t("academy.completedBadge")}</option>
          </Select>
          <Button
            variant={bookmarkedOnly ? "primary" : "secondary"}
            size="md"
            icon={bookmarkedOnly ? BookmarkCheck : Bookmark}
            onClick={() => setBookmarkedOnly((current) => !current)}
          >
            {t("academy.bookmarked")}
          </Button>
        </div>
        <div className="mt-2.5 flex flex-wrap items-center justify-between gap-2 border-t border-line/60 pt-2.5">
          <span className="text-[10px] text-faint">
            {t("academy.showing", { shown: filtered.length, total: lessons.length })}
            {categoryMeta ? ` · ${lang === "ar" ? categoryMeta.ar : categoryMeta.en}` : ""}
          </span>
          <div className="flex flex-wrap items-center gap-2">
            {filtersActive ? (
              <Button variant="ghost" size="sm" icon={X} onClick={resetFilters}>
                {t("academy.resetFilters")}
              </Button>
            ) : null}
            <Button variant="ghost" size="sm" onClick={() => setCollapsed([])}>
              {t("academy.expandAll")}
            </Button>
            <Button variant="ghost" size="sm" onClick={() => setCollapsed(stages.map((stage) => stage.key))}>
              {t("academy.collapseAll")}
            </Button>
          </div>
        </div>
      </Card>

      {lessonsQuery.isLoading ? (
        <div className="space-y-3">
          {[0, 1, 2].map((key) => <Skeleton key={key} className="h-44 rounded-2xl" />)}
        </div>
      ) : lessonsQuery.isError ? (
        <ErrorState
          error={lessonsQuery.error}
          title={t("common.errorTitle")}
          description={t("common.errorDescription")}
          onRetry={() => void lessonsQuery.refetch()}
        />
      ) : groups.length ? (
        <div className="space-y-3">
          {groups.map((group, index) => {
            const isCollapsed = collapsed.includes(group.key);
            const stageLessons = group.stage
              ? lessons.filter((lesson) => academyStageKey(lesson, stages) === group.stage?.key)
              : lessons;
            const done = stageLessons.filter((lesson) => lesson.status === "completed").length;
            const percent = stageLessons.length ? (done / stageLessons.length) * 100 : 0;
            return (
              <Card key={group.key} className="overflow-hidden">
                <button
                  type="button"
                  onClick={() =>
                    setCollapsed((current) =>
                      current.includes(group.key)
                        ? current.filter((key) => key !== group.key)
                        : [...current, group.key]
                    )
                  }
                  className="flex w-full flex-wrap items-center gap-3 p-4 text-start transition hover:bg-panel2/40"
                >
                  <span className={cn("grid h-10 w-10 shrink-0 place-items-center rounded-xl border font-display text-xs font-semibold", theme.chip)}>
                    {String(index + 1).padStart(2, "0")}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="flex flex-wrap items-center gap-2">
                      <span className="truncate text-xs font-semibold text-ink">
                        {group.stage ? academyStageTitle(group.stage, lang) : t("academy.catalog")}
                      </span>
                      {group.stage ? (
                        <Badge tone={difficultyTone[group.stage.difficulty] || "default"}>
                          {t(`labs.${group.stage.difficulty}`, group.stage.difficulty)}
                        </Badge>
                      ) : null}
                      <span className="inline-flex items-center gap-1 text-[9px] text-faint">
                        <Timer className="h-3 w-3" /> {t("academy.studyMinutes", { count: group.stage?.minutes || 0 })}
                      </span>
                      <span className="inline-flex items-center gap-1 text-[9px] text-faint">
                        <Layers3 className="h-3 w-3" /> {group.lessons.length} {t("academy.lessons")}
                      </span>
                    </span>
                    <span className="mt-2 flex max-w-md items-center gap-2">
                      <Progress value={percent} className="h-1.5" tone={percent >= 100 ? "success" : "accent"} />
                      <span className="shrink-0 font-mono text-[9px] text-faint">{done}/{stageLessons.length}</span>
                    </span>
                  </span>
                  <ChevronDown className={cn("h-4 w-4 shrink-0 text-faint transition-transform", isCollapsed && "-rotate-90 rtl:rotate-90")} />
                </button>
                {isCollapsed ? null : (
                  <div className="grid gap-2.5 border-t border-line/60 p-3 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4">
                    {group.lessons.map((lesson) => (
                      <LessonCard
                        key={lesson.id}
                        lesson={lesson}
                        meta={meta}
                        lang={lang}
                        onOpen={() => navigate(`/academy/lessons/${lesson.slug}`)}
                      />
                    ))}
                  </div>
                )}
              </Card>
            );
          })}
        </div>
      ) : (
        <Card>
          <EmptyState
            icon={filtersActive ? Search : GraduationCap}
            title={filtersActive ? t("academy.noLessons") : t("academy.noBookmarks")}
            description={filtersActive ? t("academy.resetFilters") : t("academy.subtitle")}
            action={filtersActive ? <Button variant="secondary" icon={RefreshCw} onClick={resetFilters}>{t("academy.resetFilters")}</Button> : undefined}
          />
        </Card>
      )}

      <Card className="overflow-hidden">
        <div className="flex flex-wrap items-start justify-between gap-4 p-5">
          <div className="min-w-0 max-w-2xl">
            <Badge tone={existingCertificate ? "success" : "accent"} dot>{t("academy.certificate")}</Badge>
            <h2 className="mt-2 text-sm font-semibold text-ink">
              {meta ? academyDivisionTitle(meta, lang) : t("academy.division")}
            </h2>
            <p className="mt-1 text-[11px] leading-relaxed text-muted">
              {existingCertificate ? existingCertificate.disclaimer : t("academy.certificateBody")}
            </p>
          </div>
          <Award className={cn("h-6 w-6", allComplete ? "text-amber-300" : "text-faint")} />
        </div>
        {existingCertificate ? (
          <div className="grid gap-3 border-t border-line/60 p-5 sm:grid-cols-3">
            <KeyValue label={t("academy.serial")} value={existingCertificate.serial} mono />
            <KeyValue label={t("academy.issuedAt")} value={formatDate(existingCertificate.issued_at, lang)} />
            <KeyValue
              label={t("academy.average")}
              value={`${existingCertificate.average_quiz}% · ${existingCertificate.lessons_completed} ${t("academy.lessons")}`}
            />
          </div>
        ) : (
          <div className="border-t border-line/60 p-5">
            <div className="flex flex-wrap items-center gap-3">
              <div className="min-w-0 flex-1">
                <div className="flex items-center justify-between text-[10px] text-muted">
                  <span>{t("academy.certificateProgress", { completed: meta?.completed ?? 0, total: meta?.total ?? 100 })}</span>
                  <span className="font-mono text-faint">{meta?.percent ?? 0}%</span>
                </div>
                <Progress value={meta?.percent ?? 0} className="mt-1.5 h-2" tone={allComplete ? "success" : "accent"} />
              </div>
              <Button
                icon={allComplete ? Award : LockKeyhole}
                disabled={!allComplete || issueCertificate.isPending}
                loading={issueCertificate.isPending}
                onClick={() => issueCertificate.mutate()}
              >
                {t("academy.issueCertificate")}
              </Button>
            </div>
            {!allComplete ? (
              <p className="mt-2 text-[10px] text-faint">{t("academy.certificateLocked")}</p>
            ) : null}
          </div>
        )}
      </Card>
    </div>
  );
}

function LessonCard({
  lesson,
  meta,
  lang,
  onOpen
}: {
  lesson: AcademyLesson;
  meta?: AcademyDivision;
  lang: Lang;
  onOpen: () => void;
}) {
  const { t } = useTranslation();
  const category = meta?.categories.find((item) => item.key === lesson.category);
  const completed = lesson.status === "completed";
  const inProgress = lesson.status === "in_progress";
  return (
    <button
      type="button"
      onClick={onOpen}
      className={cn(
        "group flex h-full flex-col rounded-xl border border-line/70 bg-panel2/35 p-3 text-start transition hover:border-accent/30 hover:bg-panel2/60",
        completed && "border-emerald-400/15"
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <span className="font-mono text-[9px] uppercase tracking-[0.12em] text-faint">
          #{String(lesson.order_index).padStart(2, "0")}
        </span>
        <span className="flex items-center gap-1.5">
          {lesson.bookmarked ? <BookmarkCheck className="h-3.5 w-3.5 text-amber-300" /> : null}
          {completed ? (
            <CheckCircle2 className="h-3.5 w-3.5 text-emerald-300" />
          ) : inProgress ? (
            <Clock3 className="h-3.5 w-3.5 text-amber-300" />
          ) : null}
        </span>
      </div>
      <p className="mt-1.5 line-clamp-2 text-[11px] font-semibold leading-snug text-ink">
        {category ? (lang === "ar" ? category.ar : category.en) : lesson.category}
      </p>
      <p className="mt-1 line-clamp-2 text-[9px] leading-relaxed text-muted">{academyLessonSummary(lesson, lang)}</p>
      <div className="mt-auto flex flex-wrap items-center gap-2 pt-2.5 text-[9px] text-faint">
        <span className="inline-flex items-center gap-1"><Clock3 className="h-3 w-3" /> {lesson.duration_minutes}m</span>
        {lesson.quiz_score != null ? (
          <span className={cn("inline-flex items-center gap-1", lesson.quiz_score >= 60 ? "text-emerald-300" : "text-amber-300")}>
            <Trophy className="h-3 w-3" /> {lesson.quiz_score}%
          </span>
        ) : null}
        <Badge tone={completed ? "success" : inProgress ? "warning" : "default"} className="ms-auto px-1.5 py-0 text-[8px]">
          {completed ? t("academy.completedBadge") : inProgress ? t("academy.inProgressBadge") : t("academy.notStarted")}
        </Badge>
      </div>
    </button>
  );
}