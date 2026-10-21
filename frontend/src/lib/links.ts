import { useCallback } from "react";
import { useNavigate } from "react-router-dom";
import type { NotificationItem, SearchItem } from "../types";

type Navigator = ReturnType<typeof useNavigate>;
type SetProject = (projectId: string | null) => void;

const entityRoutes: Record<string, (id: string) => string> = {
  project: (id) => `/projects/${id}`,
  asset: (id) => `/assets?asset=${encodeURIComponent(id)}`,
  finding: (id) => `/findings?finding=${encodeURIComponent(id)}`,
  scan: (id) => `/scans/${encodeURIComponent(id)}`,
  alert: (id) => `/soc?tab=alerts&alert=${encodeURIComponent(id)}`,
  incident: (id) => `/soc?tab=incidents&incident=${encodeURIComponent(id)}`,
  report: (id) => `/reports?report=${encodeURIComponent(id)}`,
  lab: (id) => `/labs/${encodeURIComponent(id)}`,
  cve: (id) => `/intel?cve=${encodeURIComponent(id)}`,
  asset_change: () => `/asm?tab=changes`,
  job: () => `/admin?tab=jobs`
};

export function useEntityNavigator() {
  const navigate = useNavigate();

  return useCallback(
    (
      type: string,
      id: string,
      projectId: string | null | undefined,
      setSelectedProject: SetProject,
      onDone?: () => void
    ) => {
      if (projectId) setSelectedProject(projectId);
      const route = entityRoutes[type]?.(id);
      if (route) navigate(route);
      else if (projectId) navigate(`/projects/${projectId}`);
      onDone?.();
    },
    [navigate]
  );
}

export function notificationRoute(item: NotificationItem) {
  return entityRoutes[item.kind]?.(item.entity_id) || (item.project_id ? `/projects/${item.project_id}` : "/dashboard");
}

export function searchRoute(item: SearchItem) {
  return entityRoutes[item.type]?.(item.id) || item.href || "/dashboard";
}

export function useGo() {
  const navigate = useNavigate();
  const go = useCallback((to: string) => navigate(to), [navigate]);
  return go;
}

export type { Navigator };
