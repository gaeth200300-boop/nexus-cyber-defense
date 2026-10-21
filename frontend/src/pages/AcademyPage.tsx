import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import {
  ArrowRight,
  Award,
  BookOpen,
  Bookmark,
  CheckCircle2,
  Clock3,
  GraduationCap,
  Layers3,
  LockKeyhole,
  Sparkles,
  Target,
  Timer
} from "lucide-react";
import { apiFetch } from "../lib/api";
import { cn } from "../lib/utils";
import { useDocumentTitle } from "../hooks";
import {
  academyDivisionLabel,
  academyDivisionTagline,
  academyDivisionTitle,
  academyDivisions as divisionOrder,
  academyReasonLabel,
  academyThemes as themes
} from "../config/academy";
import type {
  AcademyCertificate,
  AcademyCertificatesResponse,
  AcademyDivision,
  AcademyLearningPath,
  AcademyOverview,
  Lang
} from "../types";
import {
  Badge,
  Button,
  Card,
  ErrorState,
  PageHeader,
  Skeleton,
  StatCard
} from "../components/ui";

export default function AcademyPage() {
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const navigate = useNavigate();
  useDocumentTitle(t("academy.title"));

  const overview = useQuery({
    queryKey: ["academy-overview"],
    queryFn: () => apiFetch<AcademyOverview>("/academy/overview")
  });

  const paths = useQuery({
    queryKey: ["academy-paths"],
    queryFn: async () => {
      const results = await Promise.all(
        divisionOrder.map((division) =>
          apiFetch<AcademyLearningPath>("/academy/learning-path", { query: { division } })
        )
      );
      return results;
    }
  });

  const certificates = useQuery({
    queryKey: ["academy-certificates"],
    queryFn: () => apiFetch<AcademyCertificatesResponse>("/academy/certificates")
  });

  const divisions = overview.data?.divisions || [];
  const summary = overview.data?.summary;
  const totalLessons = summary?.total_lessons ?? 300;
  const inProgress = summary
    ? Object.values(summary.divisions).reduce((sum, bucket) => sum + bucket.in_progress, 0)
    : 0;
  const studyMinutes = summary
    ? Object.values(summary.divisions).reduce((sum, bucket) => sum + bucket.minutes_completed, 0)
    : 0;
  const firstOpen = divisions.find((division) => division.percent < 100) || divisions[0];
  const recommendations = (paths.data || [])
    .map((path) => path.recommendations[0])
    .filter(Boolean)
    .slice(0, 3);
  const records = certificates.data?.items || [];

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow={t("academy.eyebrow")}
        icon={GraduationCap}
        title={t("academy.title")}
        subtitle={t("academy.subtitle")}
        actions={
          <Button
            icon={Sparkles}
            onClick={() => navigate(firstOpen ? `/academy/${firstOpen.key}` : "/academy/defense")}
            disabled={!divisions.length}
          >
            {t("academy.startLearning")}
          </Button>
        }
      />

      <section className="relative overflow-hidden rounded-2xl border border-accent/20 bg-gradient-to-br from-accent/[0.10] via-panel to-accent2/[0.07] p-5 sm:p-7">
        <div className="pointer-events-none absolute -end-12 -top-16 h-56 w-56 rounded-full bg-accent/15 blur-3xl" />
        <div className="pointer-events-none absolute -bottom-24 start-1/3 h-56 w-56 rounded-full bg-accent2/10 blur-3xl" />
        <div className="relative grid gap-6 lg:grid-cols-[1.4fr_1fr] lg:items-center">
          <div>
            <Badge tone="accent" dot>{t("academy.badge")}</Badge>
            <h2 className="mt-3 max-w-2xl font-display text-xl font-semibold leading-snug tracking-tight text-ink sm:text-2xl">
              {t("academy.heroTitle")}
            </h2>
            <p className="mt-2 max-w-2xl text-xs leading-relaxed text-muted sm:text-sm">
              {t("academy.heroBody")}
            </p>
            <div className="mt-4 flex flex-wrap items-center gap-2">
              <Button icon={BookOpen} onClick={() => navigate(firstOpen ? `/academy/${firstOpen.key}` : "/academy/defense")}>
                {t("academy.openDivision")}
              </Button>
              <span className="inline-flex items-center gap-1.5 rounded-full border border-line/70 bg-panel/60 px-2.5 py-1 text-[10px] text-muted">
                <LockKeyhole className="h-3 w-3 text-accent2" />
                {t("academy.privateProgress")}
              </span>
              <span className="inline-flex items-center gap-1.5 rounded-full border border-line/70 bg-panel/60 px-2.5 py-1 text-[10px] text-muted">
                <CheckCircle2 className="h-3 w-3 text-emerald-300" />
                {t("academy.serverGraded")}
              </span>
            </div>
          </div>
          <div className="grid grid-cols-3 gap-2.5">
            {divisionOrder.map((key) => {
              const division = divisions.find((item) => item.key === key);
              const theme = themes[key];
              const Icon = theme.icon;
              return (
                <div key={key} className="rounded-xl border border-line/70 bg-panel/55 p-3 text-center backdrop-blur-sm">
                  <span className={cn("mx-auto grid h-9 w-9 place-items-center rounded-xl border", theme.chip)}>
                    <Icon className="h-4 w-4" />
                  </span>
                  <p className="mt-2 truncate text-[10px] font-semibold text-ink">
                    {division ? academyDivisionTitle(division, lang) : academyDivisionLabel(key, lang)}
                  </p>
                  <p className="mt-0.5 font-display text-lg font-semibold tabular-nums text-ink">
                    {division?.lesson_count ?? 100}
                  </p>
                  <p className="text-[8px] uppercase tracking-[0.12em] text-faint">{t("academy.lessons")}</p>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      <section className="grid grid-cols-2 gap-2.5 xl:grid-cols-4">
        <StatCard
          label={t("academy.completedLessons")}
          value={summary ? `${summary.completed}/${totalLessons}` : "—"}
          sub={t("academy.overall")}
          icon={CheckCircle2}
          tone="success"
        />
        <StatCard
          label={t("academy.inProgress")}
          value={summary ? inProgress : "—"}
          sub={t("academy.lessons")}
          icon={Target}
          tone="cyan"
        />
        <StatCard
          label={t("academy.bookmarked")}
          value={summary ? summary.bookmarked : "—"}
          sub={t("academy.lessons")}
          icon={Bookmark}
          tone="warning"
        />
        <StatCard
          label={t("academy.studyTime")}
          value={summary ? t("academy.studyMinutes", { count: studyMinutes }) : "—"}
          sub={t("academy.completed")}
          icon={Clock3}
          tone="accent"
        />
      </section>

      {recommendations.length ? (
        <section className="space-y-3">
          <div className="flex items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold tracking-tight text-ink">{t("academy.recommended")}</h2>
              <p className="mt-0.5 text-[11px] text-muted">{t("academy.continueLearning")}</p>
            </div>
            <Button variant="ghost" size="sm" icon={ArrowRight} onClick={() => navigate("/academy/defense")}>
              {t("academy.catalog")}
            </Button>
          </div>
          <div className="grid gap-3 lg:grid-cols-3">
            {recommendations.map((lesson) => {
              if (!lesson) return null;
              const theme = themes[lesson.division] || themes.defense;
              const Icon = theme.icon;
              return (
                <button
                  key={lesson.slug}
                  type="button"
                  onClick={() => navigate(`/academy/lessons/${lesson.slug}`)}
                  className="surface-card group flex items-start gap-3 p-4 text-start transition hover:border-accent/25"
                >
                  <span className={cn("grid h-10 w-10 shrink-0 place-items-center rounded-xl border", theme.chip)}>
                    <Icon className="h-4 w-4" />
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="flex items-center gap-2">
                      <Badge tone="default">{academyDivisionLabel(lesson.division, lang)}</Badge>
                      <span className="text-[9px] text-faint">{t(`labs.${lesson.difficulty}`, lesson.difficulty)}</span>
                    </span>
                    <span className="mt-1.5 block truncate text-xs font-semibold text-ink">
                      {lang === "ar" ? lesson.title_ar : lesson.title_en}
                    </span>
                    <span className="mt-1 block line-clamp-2 text-[10px] leading-relaxed text-muted">
                      {academyReasonLabel(lesson.reason, t)}
                    </span>
                    <span className="mt-2 flex items-center gap-1 text-[9px] text-accent2">
                      {t("academy.resume")}
                      <ArrowRight className="h-3 w-3 transition group-hover:translate-x-0.5 rtl:rotate-180" />
                    </span>
                  </span>
                </button>
              );
            })}
          </div>
        </section>
      ) : null}

      {overview.isLoading ? (
        <div className="grid gap-4 lg:grid-cols-3">
          {[0, 1, 2].map((key) => <Skeleton key={key} className="h-72 rounded-2xl" />)}
        </div>
      ) : overview.isError ? (
        <ErrorState
          error={overview.error}
          title={t("common.errorTitle")}
          description={t("common.errorDescription")}
          onRetry={() => void overview.refetch()}
        />
      ) : (
        <section className="grid gap-4 lg:grid-cols-3">
          {divisions.map((division) => (
            <DivisionCard
              key={division.key}
              division={division}
              lang={lang}
              onOpen={() => navigate(`/academy/${division.key}`)}
            />
          ))}
        </section>
      )}

      <section className="grid gap-3 lg:grid-cols-3">
        {[
          { icon: LockKeyhole, title: t("academy.privateProgress"), body: t("academy.privateBody"), tone: "text-cyan-300" },
          { icon: CheckCircle2, title: t("academy.serverGraded"), body: t("academy.serverBody"), tone: "text-emerald-300" },
          { icon: Award, title: t("academy.verifiedOnly"), body: t("academy.verifiedBody"), tone: "text-amber-300" }
        ].map((item) => (
          <div key={item.title} className="surface-card flex items-start gap-3 p-4">
            <span className="grid h-9 w-9 shrink-0 place-items-center rounded-xl border border-line bg-panel2">
              <item.icon className={cn("h-4 w-4", item.tone)} />
            </span>
            <div className="min-w-0">
              <p className="text-xs font-semibold text-ink">{item.title}</p>
              <p className="mt-1 text-[10px] leading-relaxed text-muted">{item.body}</p>
            </div>
          </div>
        ))}
      </section>

      {records.length ? (
        <section className="space-y-3">
          <div className="flex items-center gap-2">
            <Award className="h-4 w-4 text-amber-300" />
            <h2 className="text-sm font-semibold tracking-tight text-ink">{t("academy.records")}</h2>
          </div>
          <div className="grid gap-3 lg:grid-cols-3">
            {records.map((record) => <RecordCard key={record.id} record={record} lang={lang} />)}
          </div>
        </section>
      ) : null}
    </div>
  );
}

function DivisionCard({
  division,
  lang,
  onOpen
}: {
  division: AcademyDivision;
  lang: Lang;
  onOpen: () => void;
}) {
  const { t } = useTranslation();
  const theme = themes[division.key] || themes.defense;
  const Icon = theme.icon;
  return (
    <button
      type="button"
      onClick={onOpen}
      className={cn(
        "surface-card group relative flex h-full flex-col overflow-hidden bg-gradient-to-br p-5 text-start transition hover:-translate-y-0.5 hover:border-accent/25",
        theme.gradient
      )}
    >
      <span className={cn("pointer-events-none absolute -end-10 -top-12 h-40 w-40 rounded-full blur-3xl", theme.glow)} />
      <span className="relative flex items-start justify-between gap-3">
        <span className={cn("grid h-11 w-11 place-items-center rounded-xl border", theme.chip)}>
          <Icon className="h-5 w-5" />
        </span>
        <Badge tone={division.percent >= 100 ? "success" : "default"}>
          {division.percent >= 100 ? t("academy.divisionComplete") : `${division.percent}%`}
        </Badge>
      </span>
      <span className="relative mt-4 block font-display text-lg font-semibold text-ink">{academyDivisionTitle(division, lang)}</span>
      <span className="relative mt-1 block text-[11px] leading-relaxed text-muted">{academyDivisionTagline(division, lang)}</span>
      <span className="relative mt-3 flex flex-wrap items-center gap-x-3 gap-y-1 text-[9px] text-faint">
        <span className="flex items-center gap-1"><BookOpen className="h-3 w-3" /> {division.lesson_count} {t("academy.lessons")}</span>
        <span className="flex items-center gap-1"><Layers3 className="h-3 w-3" /> {division.categories.length} {t("academy.tracks")}</span>
        <span className="flex items-center gap-1"><Timer className="h-3 w-3" /> {division.stages.length} {t("academy.stages")}</span>
      </span>
      <span className="relative mt-auto block pt-4">
        <span className="flex items-center justify-between text-[9px] text-faint">
          <span>{t("academy.completed")}</span>
          <span className="font-mono">{division.completed}/{division.total || division.lesson_count}</span>
        </span>
        <span className="mt-1.5 block h-1.5 overflow-hidden rounded-full bg-panel3">
          <span
            className={cn("block h-full rounded-full bg-gradient-to-r transition-[width] duration-500", theme.bar)}
            style={{ width: `${Math.max(0, Math.min(100, division.percent))}%` }}
          />
        </span>
        <span className="mt-3 flex items-center justify-between">
          <span className="text-[9px] text-muted">
            {division.average_quiz != null ? `${t("academy.averageQuiz")}: ${division.average_quiz}%` : t("academy.noQuiz")}
          </span>
          <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-accent2">
            {t("academy.openDivision")}
            <ArrowRight className="h-3.5 w-3.5 transition group-hover:translate-x-0.5 rtl:rotate-180" />
          </span>
        </span>
      </span>
    </button>
  );
}

function RecordCard({ record, lang }: { record: AcademyCertificate; lang: Lang }) {
  const { t } = useTranslation();
  return (
    <Card className="p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <Badge tone="success" dot>{t("academy.certificate")}</Badge>
          <p className="mt-2 truncate text-xs font-semibold text-ink">{record.display_name}</p>
          <p className="mt-0.5 text-[10px] text-muted">{academyDivisionLabel(record.division, lang)}</p>
        </div>
        <Award className="h-5 w-5 text-amber-300" />
      </div>
      <div className="mt-3 flex items-center justify-between border-t border-line/60 pt-2.5 text-[9px] text-faint">
        <span className="font-mono">{record.serial}</span>
        <span>{record.lessons_completed} {t("academy.lessons")} · {record.average_quiz}%</span>
      </div>
      <p className="mt-2 line-clamp-2 text-[8px] leading-relaxed text-faint">{t("academy.disclaimer")}</p>
    </Card>
  );
}
