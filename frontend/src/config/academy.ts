import { Microscope, ShieldCheck, Swords, type LucideIcon } from "lucide-react";
import type { AcademyDivision, AcademyLesson, AcademyStage, Lang } from "../types";

export const academyDivisions = ["defense", "offense", "forensics"] as const;
export type AcademyDivisionId = (typeof academyDivisions)[number];

export interface AcademyTheme {
  icon: LucideIcon;
  text: string;
  chip: string;
  bar: string;
  glow: string;
  gradient: string;
  ring: string;
}

export const academyThemes: Record<string, AcademyTheme> = {
  defense: {
    icon: ShieldCheck,
    text: "text-cyan-300",
    chip: "border-cyan-400/25 bg-cyan-400/10 text-cyan-300",
    bar: "from-cyan-500 to-teal-400",
    glow: "bg-cyan-500/10",
    gradient: "from-cyan-500/[0.09] via-panel to-panel",
    ring: "border-cyan-400/25 bg-cyan-400/[0.06]"
  },
  offense: {
    icon: Swords,
    text: "text-violet-300",
    chip: "border-violet-400/25 bg-violet-400/10 text-violet-300",
    bar: "from-violet-500 to-fuchsia-400",
    glow: "bg-violet-500/10",
    gradient: "from-violet-500/[0.09] via-panel to-panel",
    ring: "border-violet-400/25 bg-violet-400/[0.06]"
  },
  forensics: {
    icon: Microscope,
    text: "text-amber-300",
    chip: "border-amber-400/25 bg-amber-400/10 text-amber-300",
    bar: "from-amber-500 to-orange-400",
    glow: "bg-amber-500/10",
    gradient: "from-amber-500/[0.09] via-panel to-panel",
    ring: "border-amber-400/25 bg-amber-400/[0.06]"
  }
};

const fallbackLabels: Record<string, Record<Lang, string>> = {
  defense: { en: "Defense", ar: "الدفاع السيبراني" },
  offense: { en: "Offense", ar: "الأمن الهجومي" },
  forensics: { en: "Forensics", ar: "التحليل الجنائي الرقمي" }
};

const fallbackTaglines: Record<string, Record<Lang, string>> = {
  defense: { en: "Blue-team operations, detection, and response.", ar: "عمليات الفريق الأزرق والكشف والاستجابة." },
  offense: { en: "Authorized offensive testing and scoped labs.", ar: "اختبار هجومي مصرح به ومختبرات محددة النطاق." },
  forensics: { en: "Evidence preservation, analysis, and reporting.", ar: "حفظ الأدلة وتحليلها وإعداد التقارير." }
};

export function isAcademyDivision(value: string | undefined): value is AcademyDivisionId {
  return Boolean(value && (academyDivisions as readonly string[]).includes(value));
}

export function academyDivisionLabel(division: string, lang: Lang): string {
  return fallbackLabels[division]?.[lang] || division;
}

export function academyDivisionTitle(division: AcademyDivision | undefined, lang: Lang): string {
  if (!division) return "";
  return lang === "ar" ? division.title_ar : division.title_en;
}

export function academyDivisionTagline(division: AcademyDivision | undefined, lang: Lang): string {
  if (!division) return "";
  return lang === "ar" ? division.tagline_ar : division.tagline_en;
}

export function academyStageKey(lesson: AcademyLesson, stages: AcademyStage[]): string {
  const tag = Array.isArray(lesson.tags) ? lesson.tags[2] : undefined;
  if (tag) return tag;
  const index = Math.max(0, (lesson.order_index - 1) % Math.max(1, stages.length));
  return stages[index]?.key || "";
}

export function academyStageTitle(stage: AcademyStage | undefined, lang: Lang): string {
  if (!stage) return "";
  return lang === "ar" ? stage.ar : stage.en;
}

export function academyLessonTitle(lesson: AcademyLesson, lang: Lang): string {
  return lang === "ar" ? lesson.title_ar : lesson.title_en;
}

export function academyLessonSummary(lesson: AcademyLesson, lang: Lang): string {
  return lang === "ar" ? lesson.summary_ar : lesson.summary_en;
}

const reasonKeys: Record<string, string> = {
  "Continue where you stopped.": "academy.reasonContinue",
  "Reinforce a completed lesson.": "academy.reasonReinforce",
  "Finish the prerequisite lesson first.": "academy.reasonPrereq",
  "Next in this category.": "academy.reasonNext"
};

export function academyReasonLabel(reason: string, t: (key: string) => string): string {
  const key = reasonKeys[reason];
  return key ? t(key) : reason;
}