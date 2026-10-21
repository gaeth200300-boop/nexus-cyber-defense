import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "./lib/api";
import { currentLang } from "./lib/i18n";
import type { Health, Labeled, Lang, Meta, StatusMeta } from "./types";

export function useDebouncedValue<T>(value: T, delay = 300): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(value), delay);
    return () => window.clearTimeout(timer);
  }, [value, delay]);
  return debounced;
}

export function useMeta() {
  return useQuery({
    queryKey: ["meta"],
    queryFn: () => apiFetch<Meta>("/system/meta"),
    staleTime: 120_000
  });
}

export function useHealth() {
  return useQuery({
    queryKey: ["health"],
    queryFn: () => apiFetch<Health>("/system/health", { auth: false }),
    refetchInterval: 30_000,
    staleTime: 10_000
  });
}

export function useDocumentTitle(title?: string) {
  useEffect(() => {
    const app = "NEXUS · Cyber Defense";
    document.title = title ? `${title} · NEXUS` : app;
  }, [title]);
}

export function labelOf(items: Labeled[] | undefined, key: string | null | undefined, lang: Lang = currentLang()) {
  if (!key) return "—";
  return items?.find((item) => item.key === key)?.labels?.[lang] || key.replace(/[_-]+/g, " ");
}

export function statusLabel(items: StatusMeta[] | undefined, key: string | null | undefined, lang: Lang = currentLang()) {
  if (!key) return "—";
  return items?.find((item) => item.key === key)?.labels?.[lang] || key.replace(/[_-]+/g, " ");
}

export function useCan(roles: string[] = []): boolean {
  const meta = useMeta();
  const role = meta.data?.user.role || "";
  return roles.includes(role);
}
