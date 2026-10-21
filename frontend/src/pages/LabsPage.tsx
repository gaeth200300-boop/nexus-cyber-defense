import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import {
  Activity,
  ArrowUpRight,
  Award,
  BookOpen,
  CheckCircle2,
  ChevronRight,
  Clock3,
  Crown,
  FlaskConical,
  Layers3,
  Medal,
  Search,
  ShieldCheck,
  Sparkles,
  Target,
  Trophy,
  Users
} from "lucide-react";
import { apiFetch } from "../lib/api";
import { cn, fromNow } from "../lib/utils";
import { useAuth } from "../context/AuthContext";
import { useDocumentTitle } from "../hooks";
import type { Lab, LabRun, Lang } from "../types";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  Input,
  PageHeader,
  Progress,
  Select,
  Skeleton,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger
} from "../components/ui";

interface LabsResponse {
  items: Lab[];
  total: number;
  categories: { key: string; labels: Record<Lang, string>; count: number }[];
  levels: { key: string; labels: Record<Lang, string> }[];
}

interface LabStats {
  runs: number;
  labs_passed: number;
  total_score: number;
  achievements: { code: string; title_en: string; title_ar: string; points: number; earned_at: string | null }[];
  recent_runs: LabRun[];
}

interface LeaderboardResponse {
  items: {
    user_id: string;
    name: string;
    score: number;
    labs_passed: number;
    last_pass_at: string | null;
    is_me: boolean;
  }[];
  total: number;
}

const levelTone: Record<string, string> = {
  beginner: "success",
  intermediate: "info",
  advanced: "warning",
  expert: "danger"
};

export default function LabsPage() {
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const { user } = useAuth();
  const navigate = useNavigate();
  const [tab, setTab] = useState("catalog");
  const [q, setQ] = useState("");
  const [category, setCategory] = useState("");
  const [level, setLevel] = useState("");
  useDocumentTitle(t("labs.title"));

  const labs = useQuery({
    queryKey: ["labs", q, category, level],
    queryFn: () =>
      apiFetch<LabsResponse>("/labs", {
        query: { q, category: category || undefined, level: level || undefined, limit: 100 }
      })
  });

  const stats = useQuery({
    queryKey: ["lab-stats"],
    queryFn: () => apiFetch<LabStats>("/labs/me/stats")
  });

  const leaderboard = useQuery({
    queryKey: ["lab-leaderboard"],
    queryFn: () => apiFetch<LeaderboardResponse>("/labs/leaderboard", { query: { limit: 20 } }),
    enabled: tab === "leaderboard"
  });

  const items = labs.data?.items || [];
  const categories = labs.data?.categories || [];
  const levels = labs.data?.levels || [];
  const completed = labs.data?.items.filter((lab) => lab.user_state.passed).length || 0;
  const progress = items.length ? (completed / items.length) * 100 : 0;

  const featured = useMemo(
    () => [...items].sort((a, b) => Number(a.user_state.passed) - Number(b.user_state.passed) || a.order_index - b.order_index)[0],
    [items]
  );

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow={t("nav.labs")}
        icon={FlaskConical}
        title={t("labs.title")}
        subtitle={t("labs.subtitle")}
        actions={
          <Button variant="secondary" icon={Trophy} onClick={() => setTab("leaderboard")}>
            {t("labs.leaderboard")}
          </Button>
        }
      />

      <section className="grid grid-cols-2 gap-2.5 xl:grid-cols-4">
        {[
          { label: t("labs.completed"), value: stats.data?.labs_passed, icon: CheckCircle2, tone: "text-emerald-300" },
          { label: t("labs.totalPoints"), value: stats.data?.total_score, icon: Award, tone: "text-amber-300" },
          { label: t("labs.attempts"), value: stats.data?.runs, icon: Activity, tone: "text-accent2" },
          { label: t("labs.achievements"), value: stats.data?.achievements.length, icon: Medal, tone: "text-accent" }
        ].map((card) => (
          <div key={card.label} className="surface-card p-3.5">
            <div className="flex items-center justify-between">
              <span className="text-[9px] font-semibold uppercase tracking-[0.1em] text-muted">{card.label}</span>
              <card.icon className={cn("h-4 w-4", card.tone)} />
            </div>
            <p className="mt-2 font-display text-2xl font-semibold tabular-nums text-ink">
              {card.value === undefined ? "—" : card.value}
            </p>
          </div>
        ))}
      </section>

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="catalog" icon={BookOpen} count={labs.data?.total}>
            {t("labs.catalog")}
          </TabsTrigger>
          <TabsTrigger value="progress" icon={Target}>
            {t("labs.progress")}
          </TabsTrigger>
          <TabsTrigger value="leaderboard" icon={Trophy}>
            {t("labs.leaderboard")}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="catalog" className="mt-4 space-y-4">
          {featured ? (
            <div className="relative overflow-hidden rounded-2xl border border-accent/20 bg-gradient-to-br from-accent/[0.10] via-panel to-accent2/[0.06] p-5">
              <div className="absolute end-4 top-4 h-32 w-32 rounded-full bg-accent/10 blur-3xl" />
              <div className="relative flex flex-wrap items-center gap-3">
                <Badge tone="accent">{t("labs.featured")}</Badge>
                <Badge tone={(levelTone[featured.level] as "success") || "default"}>{label(featured.level_label, lang)}</Badge>
                <span className="text-[9px] text-faint">{label(featured.category_label, lang)}</span>
              </div>
              <h2 className="relative mt-3 font-display text-xl font-semibold text-ink">
                {lang === "ar" ? featured.title_ar : featured.title_en}
              </h2>
              <p className="relative mt-1.5 max-w-2xl text-[11px] leading-relaxed text-muted">
                {lang === "ar" ? featured.description_ar : featured.description_en}
              </p>
              <div className="relative mt-4 flex flex-wrap items-center gap-4">
                <span className="flex items-center gap-1.5 text-[10px] text-muted">
                  <Target className="h-3.5 w-3.5 text-accent" /> {featured.check_count} {t("labs.checks")}
                </span>
                <span className="flex items-center gap-1.5 text-[10px] text-muted">
                  <Sparkles className="h-3.5 w-3.5 text-amber-300" /> {featured.max_points} {t("labs.points")}
                </span>
                <Button icon={ArrowUpRight} onClick={() => navigate(`/labs/${featured.slug}`)} className="ms-auto">
                  {featured.user_state.passed ? t("labs.review") : t("labs.start")}
                </Button>
              </div>
            </div>
          ) : null}

          <div className="flex flex-wrap items-center gap-2">
            <div className="relative min-w-[200px] flex-1">
              <Search className="pointer-events-none absolute start-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-faint" />
              <Input value={q} onChange={(event) => setQ(event.target.value)} placeholder={t("labs.searchPlaceholder")} className="ps-9" />
            </div>
            <Select value={category} onChange={(event) => setCategory(event.target.value)} className="w-auto">
              <option value="">{t("common.category")} · {t("common.all")}</option>
              {categories.map((item) => (
                <option key={item.key} value={item.key}>{label(item.labels, lang)} ({item.count})</option>
              ))}
            </Select>
            <Select value={level} onChange={(event) => setLevel(event.target.value)} className="w-auto">
              <option value="">{t("labs.level")} · {t("common.all")}</option>
              {levels.map((item) => (
                <option key={item.key} value={item.key}>{label(item.labels, lang)}</option>
              ))}
            </Select>
          </div>

          {labs.isLoading ? (
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
              {[0, 1, 2, 3, 4, 5].map((key) => <Skeleton key={key} className="h-56 rounded-2xl" />)}
            </div>
          ) : labs.isError ? (
            <Card className="p-2">
              <EmptyState
                icon={FlaskConical}
                title={t("common.errorTitle")}
                description={labs.error instanceof Error ? labs.error.message : t("common.errorDescription")}
                action={<Button variant="secondary" onClick={() => void labs.refetch()}>{t("common.retry")}</Button>}
              />
            </Card>
          ) : items.length ? (
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
              {items.map((lab) => (
                <button
                  key={lab.id}
                  type="button"
                  onClick={() => navigate(`/labs/${lab.slug}`)}
                  className={cn(
                    "surface-card group flex h-full flex-col p-4 text-start transition hover:border-accent/25",
                    lab.user_state.passed && "border-emerald-400/15"
                  )}
                >
                  <div className="flex items-start justify-between gap-2">
                    <Badge tone={(levelTone[lab.level] as "success") || "default"}>{label(lab.level_label, lang)}</Badge>
                    {lab.user_state.passed ? (
                      <Badge tone="success" dot>{t("labs.passed")}</Badge>
                    ) : lab.user_state.active_run_id ? (
                      <Badge tone="warning" dot>{t("labs.inProgress")}</Badge>
                    ) : (
                      <span className="flex items-center gap-1 text-[9px] text-faint">
                        <Target className="h-3 w-3" /> {lab.max_points}
                      </span>
                    )}
                  </div>
                  <h3 className="mt-3 line-clamp-2 font-display text-sm font-semibold text-ink">
                    {lang === "ar" ? lab.title_ar : lab.title_en}
                  </h3>
                  <p className="mt-1.5 line-clamp-2 text-[10px] leading-relaxed text-muted">
                    {lang === "ar" ? lab.description_ar : lab.description_en}
                  </p>
                  <div className="mt-auto pt-3">
                    <div className="flex items-center gap-2 text-[9px] text-faint">
                      <span>{label(lab.category_label, lang)}</span>
                      <span>·</span>
                      <span>{lab.check_count} {t("labs.checks")}</span>
                      <span>·</span>
                      <span>{lab.hints_total} {t("labs.hints")}</span>
                    </div>
                    <div className="mt-2 flex items-center gap-2">
                      <Progress value={lab.user_state.passed ? 100 : lab.user_state.best_score / Math.max(1, lab.max_points) * 100} className="h-1.5" tone={lab.user_state.passed ? "success" : "accent"} />
                      <span className="w-12 text-end font-mono text-[9px] text-faint">{lab.user_state.best_score}/{lab.max_points}</span>
                    </div>
                  </div>
                </button>
              ))}
            </div>
          ) : (
            <Card className="p-2">
              <EmptyState icon={BookOpen} title={t("labs.noLabs")} description={t("labs.subtitle")} />
            </Card>
          )}
        </TabsContent>

        <TabsContent value="progress" className="mt-4 space-y-4">
          <div className="grid gap-4 xl:grid-cols-12">
            <Card className="p-4 xl:col-span-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-xs font-semibold text-ink">{t("labs.overallProgress")}</h3>
                  <p className="mt-0.5 text-[10px] text-muted">{t("labs.subtitle")}</p>
                </div>
                <ShieldCheck className="h-4 w-4 text-emerald-300" />
              </div>
              <p className="mt-4 font-display text-4xl font-semibold tabular-nums text-ink">
                {Math.round(progress)}<span className="text-sm text-faint">%</span>
              </p>
              <Progress value={progress} className="mt-2 h-2" tone="success" />
              <p className="mt-2 text-[9px] text-faint">{completed} / {items.length} {t("labs.labsCompleted")}</p>
              <div className="mt-4 space-y-2">
                {categories.map((item) => {
                  const categoryLabs = items.filter((entry) => entry.category === item.key);
                  const done = categoryLabs.filter((entry) => entry.user_state.passed).length;
                  return (
                    <div key={item.key} className="flex items-center gap-2">
                      <span className="flex-1 text-[9px] text-muted">{label(item.labels, lang)}</span>
                      <Progress value={categoryLabs.length ? done / categoryLabs.length * 100 : 0} className="h-1 w-20" />
                      <span className="w-8 text-end font-mono text-[8px] text-faint">{done}/{categoryLabs.length}</span>
                    </div>
                  );
                })}
              </div>
            </Card>

            <Card className="overflow-hidden xl:col-span-4">
              <div className="border-b border-line/60 px-4 py-3">
                <h3 className="text-xs font-semibold text-ink">{t("labs.achievements")}</h3>
                <p className="mt-0.5 text-[10px] text-muted">{t("labs.achievementsSubtitle")}</p>
              </div>
              {stats.data?.achievements.length ? (
                <div className="divide-y divide-line/50">
                  {stats.data.achievements.map((achievement) => (
                    <div key={achievement.code} className="flex items-center gap-3 px-4 py-3">
                      <span className="grid h-8 w-8 place-items-center rounded-full border border-amber-400/20 bg-amber-400/[0.08] text-amber-300">
                        <Medal className="h-4 w-4" />
                      </span>
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-[10px] font-medium text-ink">{lang === "ar" ? achievement.title_ar : achievement.title_en}</p>
                        <p className="mt-0.5 text-[8px] text-faint">+{achievement.points} · {fromNow(achievement.earned_at, lang)}</p>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState icon={Medal} title={t("labs.noAchievements")} />
              )}
            </Card>

            <Card className="overflow-hidden xl:col-span-4">
              <div className="border-b border-line/60 px-4 py-3">
                <h3 className="text-xs font-semibold text-ink">{t("labs.recentRuns")}</h3>
                <p className="mt-0.5 text-[10px] text-muted">{t("labs.attempts")}</p>
              </div>
              {stats.data?.recent_runs.length ? (
                <div className="divide-y divide-line/50">
                  {stats.data.recent_runs.slice(0, 8).map((run) => (
                    <button
                      key={run.id}
                      type="button"
                      onClick={() => run.lab && navigate(`/labs/${run.lab.slug}`)}
                      className="flex w-full items-center gap-2 px-4 py-3 text-start hover:bg-panel2/40"
                    >
                      <span className={cn("grid h-7 w-7 place-items-center rounded-full border", run.status === "passed" ? "border-emerald-400/20 bg-emerald-400/10 text-emerald-300" : "border-line bg-panel2 text-faint")}>
                        {run.status === "passed" ? <CheckCircle2 className="h-3.5 w-3.5" /> : <Clock3 className="h-3.5 w-3.5" />}
                      </span>
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-[9px] font-medium text-ink">
                          {run.lab ? (lang === "ar" ? run.lab.title_ar : run.lab.title_en) : run.lab_id}
                        </p>
                        <p className="mt-0.5 text-[8px] text-faint">{run.status} · {run.score} · {fromNow(run.started_at, lang)}</p>
                      </div>
                      <ChevronRight className="h-3 w-3 text-faint rtl:rotate-180" />
                    </button>
                  ))}
                </div>
              ) : (
                <EmptyState icon={Activity} title={t("labs.noRuns")} />
              )}
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="leaderboard" className="mt-4">
          <Card className="overflow-hidden">
            <div className="flex items-center justify-between border-b border-line/60 p-4">
              <div>
                <h3 className="text-xs font-semibold text-ink">{t("labs.leaderboard")}</h3>
                <p className="mt-0.5 text-[10px] text-muted">{t("labs.leaderboardSubtitle")}</p>
              </div>
              <Users className="h-4 w-4 text-accent2" />
            </div>
            {leaderboard.isLoading ? (
              <div className="space-y-2 p-4">{[0, 1, 2, 3].map((key) => <Skeleton key={key} className="h-12 rounded-lg" />)}</div>
            ) : leaderboard.data?.items.length ? (
              <div className="divide-y divide-line/50">
                {leaderboard.data.items.map((entry, index) => (
                  <div key={entry.user_id} className={cn("flex items-center gap-3 px-4 py-3", entry.is_me && "bg-accent/[0.04]")}>
                    <span className={cn("grid h-8 w-8 shrink-0 place-items-center rounded-full border font-display text-xs font-semibold", index === 0 ? "border-amber-400/30 bg-amber-400/10 text-amber-300" : index === 1 ? "border-slate-300/20 bg-slate-300/[0.06] text-slate-200" : index === 2 ? "border-orange-400/20 bg-orange-400/[0.06] text-orange-300" : "border-line bg-panel2 text-faint")}>
                      {index < 3 ? <Crown className="h-4 w-4" /> : index + 1}
                    </span>
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-[10px] font-medium text-ink">
                        {entry.name}
                        {entry.is_me ? <span className="ms-1.5 text-[8px] text-accent2">({t("labs.you")})</span> : null}
                      </p>
                      <p className="mt-0.5 text-[8px] text-faint">{entry.labs_passed} {t("labs.labsCompleted")} · {entry.last_pass_at ? fromNow(entry.last_pass_at, lang) : t("common.never")}</p>
                    </div>
                    <span className="font-display text-sm font-semibold tabular-nums text-ink">{entry.score}</span>
                    <span className="text-[8px] text-faint">{t("labs.points")}</span>
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState icon={Trophy} title={t("labs.noLeaderboard")} description={t("labs.leaderboardSubtitle")} />
            )}
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

function label(labels: Record<string, string> | undefined, lang: Lang): string {
  return labels?.[lang] || labels?.en || "";
}
