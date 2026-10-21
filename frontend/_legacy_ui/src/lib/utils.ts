import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import { formatDistanceToNow, format, parseISO, isValid } from "date-fns";
import { ar, enUS } from "date-fns/locale";
import type { Lang } from "../types";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function toDate(value?: string | null): Date | null {
  if (!value) return null;
  try {
    const date = parseISO(value);
    return isValid(date) ? date : null;
  } catch {
    return null;
  }
}

export function formatDateTime(value?: string | null, lang: Lang = "ar", withSeconds = false): string {
  const date = toDate(value);
  if (!date) return "—";
  return new Intl.DateTimeFormat(lang === "ar" ? "ar" : "en-GB", {
    dateStyle: "medium",
    timeStyle: withSeconds ? "medium" : "short"
  }).format(date);
}

export function formatDate(value?: string | null, lang: Lang = "ar"): string {
  const date = toDate(value);
  if (!date) return "—";
  return new Intl.DateTimeFormat(lang === "ar" ? "ar" : "en-GB", {
    dateStyle: "medium"
  }).format(date);
}

export function fromNow(value?: string | null, lang: Lang = "ar"): string {
  const date = toDate(value);
  if (!date) return "—";
  return formatDistanceToNow(date, {
    addSuffix: true,
    locale: lang === "ar" ? ar : enUS
  });
}

export function formatClock(value?: string | null): string {
  const date = toDate(value) ?? new Date();
  return format(date, "HH:mm:ss");
}

export function formatBytes(bytes?: number | null): string {
  if (!bytes || bytes < 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / 1024 ** i;
  return `${value >= 10 || i === 0 ? Math.round(value) : value.toFixed(1)} ${units[i]}`;
}

/** Short Arabic date used throughout list/table views. */
export function fmtDate(value?: string | null): string {
  return formatDate(value, "ar");
}

/** Arabic date + time used in audit/table views. */
export function fmtDateTime(value?: string | null): string {
  return formatDateTime(value, "ar");
}

/** Human-readable file sizes (alias kept for page-level imports). */
export function fmtBytes(bytes?: number | null): string {
  return formatBytes(bytes);
}

/** Duration in milliseconds, e.g. 3723000 -> "1س 2د". */
export function fmtDuration(ms?: number | null): string {
  if (ms == null || !Number.isFinite(ms) || ms < 0) return "—";
  const totalSeconds = Math.floor(ms / 1000);
  const days = Math.floor(totalSeconds / 86400);
  const hours = Math.floor((totalSeconds % 86400) / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  if (days > 0) return `${days}ي ${hours}س`;
  if (hours > 0) return `${hours}س ${minutes}د`;
  if (minutes > 0) return `${minutes}د ${seconds}ث`;
  return `${seconds}ث`;
}

/** Relative Arabic time, e.g. "قبل 5 دقائق". */
export function timeAgo(value?: string | null): string {
  return fromNow(value, "ar");
}

/** Severity colour token used by charts, dots and progress bars. */
export function severityColor(severity?: string | null): string {
  return severityHex[(severity || "info").toLowerCase()] ?? severityHex.info;
}

/** Build CSV text from a list of rows and column definitions. */
export function toCsv<T extends Record<string, unknown>>(
  rows: T[],
  columns: { key: keyof T | string; label: string }[]
): string {
  const escape = (value: unknown): string => {
    if (value == null) return "";
    const text = Array.isArray(value) ? value.join("; ") : String(value);
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
  };
  const header = columns.map((column) => escape(column.label)).join(",");
  const body = rows.map((row) =>
    columns.map((column) => escape(row[column.key as keyof T])).join(",")
  );
  return [header, ...body].join("\r\n");
}

export function formatNumber(value?: number | null, lang: Lang = "ar"): string {
  if (value == null || Number.isNaN(value)) return "—";
  return new Intl.NumberFormat(lang === "ar" ? "ar" : "en-US").format(value);
}

export function percent(value: number, total: number): number {
  if (!total) return 0;
  return Math.round((value / total) * 100);
}

export function initials(name?: string | null): string {
  if (!name) return "NX";
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (!parts.length) return "NX";
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return `${parts[0][0]}${parts[parts.length - 1][0]}`.toUpperCase();
}

export const severityClasses: Record<string, string> = {
  critical: "border-rose-400/25 bg-rose-400/10 text-rose-300",
  high: "border-orange-400/25 bg-orange-400/10 text-orange-300",
  medium: "border-amber-400/25 bg-amber-400/10 text-amber-300",
  low: "border-sky-400/25 bg-sky-400/10 text-sky-300",
  info: "border-slate-400/25 bg-slate-400/10 text-slate-300"
};

export const severityDot: Record<string, string> = {
  critical: "bg-rose-400",
  high: "bg-orange-400",
  medium: "bg-amber-400",
  low: "bg-sky-400",
  info: "bg-slate-400"
};

export const severityHex: Record<string, string> = {
  critical: "#f43f5e",
  high: "#fb923c",
  medium: "#f59e0b",
  low: "#38bdf8",
  info: "#64748b"
};

export const statusClasses: Record<string, string> = {
  open: "border-sky-400/20 bg-sky-400/10 text-sky-300",
  confirmed: "border-violet-400/25 bg-violet-400/10 text-violet-300",
  fixed: "border-emerald-400/20 bg-emerald-400/10 text-emerald-300",
  accepted_risk: "border-amber-400/20 bg-amber-400/10 text-amber-300",
  false_positive: "border-slate-400/20 bg-slate-400/10 text-slate-300",
  duplicate: "border-slate-400/20 bg-slate-400/10 text-slate-400",
  new: "border-sky-400/20 bg-sky-400/10 text-sky-300",
  acknowledged: "border-violet-400/20 bg-violet-400/10 text-violet-300",
  investigating: "border-amber-400/20 bg-amber-400/10 text-amber-300",
  closed: "border-slate-400/20 bg-slate-400/10 text-slate-300",
  queued: "border-sky-400/20 bg-sky-400/10 text-sky-300",
  running: "border-violet-400/25 bg-violet-400/10 text-violet-300",
  paused: "border-amber-400/20 bg-amber-400/10 text-amber-300",
  completed: "border-emerald-400/20 bg-emerald-400/10 text-emerald-300",
  partial: "border-amber-400/20 bg-amber-400/10 text-amber-300",
  failed: "border-rose-400/20 bg-rose-400/10 text-rose-300",
  canceled: "border-slate-400/20 bg-slate-400/10 text-slate-400",
  succeeded: "border-emerald-400/20 bg-emerald-400/10 text-emerald-300",
  dead: "border-rose-400/20 bg-rose-400/10 text-rose-300",
  generating: "border-violet-400/20 bg-violet-400/10 text-violet-300",
  ready: "border-emerald-400/20 bg-emerald-400/10 text-emerald-300",
  started: "border-violet-400/20 bg-violet-400/10 text-violet-300",
  passed: "border-emerald-400/20 bg-emerald-400/10 text-emerald-300",
  reset: "border-slate-400/20 bg-slate-400/10 text-slate-400",
  active: "border-emerald-400/20 bg-emerald-400/10 text-emerald-300",
  inactive: "border-slate-400/20 bg-slate-400/10 text-slate-400",
  verified: "border-emerald-400/20 bg-emerald-400/10 text-emerald-300",
  unverified: "border-amber-400/20 bg-amber-400/10 text-amber-300"
};

export function titleCase(value?: string | null): string {
  if (!value) return "—";
  return value
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

export function humanizeEngine(value?: string | null): string {
  if (!value) return "—";
  return value.replace(/[_-]+/g, " ");
}

export function truncate(value: string | null | undefined, max = 180): string {
  if (!value) return "";
  return value.length > max ? `${value.slice(0, max)}…` : value;
}

export function parseTags(value: string): string[] {
  return Array.from(
    new Set(
      value
        .split(/[,;\n]+/)
        .map((tag) => tag.trim())
        .filter(Boolean)
    )
  );
}

export function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 8000);
}

export function getInitialTheme(): "dark" | "light" {
  const saved = localStorage.getItem("nexus.theme");
  if (saved === "dark" || saved === "light") return saved;
  return "dark";
}

export function applyTheme(theme: "dark" | "light"): void {
  document.documentElement.dataset.theme = theme;
  document.documentElement.classList.toggle("dark", theme === "dark");
  localStorage.setItem("nexus.theme", theme);
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute("content", theme === "dark" ? "#07080d" : "#f5f6fa");
}

export async function copyText(value: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(value);
    return true;
  } catch {
    try {
      const area = document.createElement("textarea");
      area.value = value;
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.appendChild(area);
      area.select();
      const ok = document.execCommand("copy");
      area.remove();
      return ok;
    } catch {
      return false;
    }
  }
}

export function hashColor(value: string): string {
  let hash = 0;
  for (let i = 0; i < value.length; i += 1) hash = value.charCodeAt(i) + ((hash << 5) - hash);
  const hue = Math.abs(hash) % 360;
  return `linear-gradient(135deg, hsl(${hue} 72% 52%), hsl(${(hue + 50) % 360} 80% 42%))`;
}

export function isActiveStatus(status?: string | null): boolean {
  return status === "queued" || status === "running" || status === "generating";
}

export function pagedOffset(page: number, pageSize: number): number {
  return Math.max(0, (page - 1) * pageSize);
}

export function pageCount(total: number, pageSize: number): number {
  return Math.max(1, Math.ceil(total / pageSize));
}
