import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "../lib/api";
import type { Project } from "../types";

interface ProjectsResponse {
  items: Project[];
  total: number;
}

interface ProjectContextValue {
  projects: Project[];
  selectedProject: Project | null;
  selectedProjectId: string | null;
  setSelectedProject: (projectId: string | null) => void;
  loading: boolean;
  error: unknown;
  refetch: () => Promise<unknown>;
  canWrite: boolean;
  isProjectAdmin: boolean;
}

const ProjectContext = createContext<ProjectContextValue | null>(null);
const STORAGE_KEY = "nexus.project";

export function ProjectProvider({ children }: { children: ReactNode }) {
  const [selectedId, setSelectedId] = useState<string | null>(() => localStorage.getItem(STORAGE_KEY));
  const projectQuery = useQuery({
    queryKey: ["projects"],
    queryFn: () => apiFetch<ProjectsResponse>("/projects"),
    staleTime: 30_000
  });

  const projects = useMemo(
    () => (projectQuery.data?.items || []).filter((project) => !project.archived),
    [projectQuery.data]
  );

  useEffect(() => {
    if (!projects.length) {
      if (selectedId) {
        setSelectedId(null);
        localStorage.removeItem(STORAGE_KEY);
      }
      return;
    }
    const exists = projects.some((project) => project.id === selectedId);
    if (!exists) {
      const initial = projects[0].id;
      setSelectedId(initial);
      localStorage.setItem(STORAGE_KEY, initial);
    }
  }, [projects, selectedId]);

  const setSelectedProject = useCallback((projectId: string | null) => {
    setSelectedId(projectId);
    if (projectId) localStorage.setItem(STORAGE_KEY, projectId);
    else localStorage.removeItem(STORAGE_KEY);
  }, []);

  const selectedProject = useMemo(
    () => projects.find((project) => project.id === selectedId) || null,
    [projects, selectedId]
  );

  const value = useMemo<ProjectContextValue>(() => {
    const role = selectedProject?.role || "";
    return {
      projects,
      selectedProject,
      selectedProjectId: selectedProject?.id || null,
      setSelectedProject,
      loading: projectQuery.isLoading,
      error: projectQuery.error,
      refetch: projectQuery.refetch,
      canWrite: ["owner", "admin", "analyst"].includes(role),
      isProjectAdmin: ["owner", "admin"].includes(role)
    };
  }, [projects, selectedProject, setSelectedProject, projectQuery.isLoading, projectQuery.error, projectQuery.refetch]);

  return <ProjectContext.Provider value={value}>{children}</ProjectContext.Provider>;
}

export function useProject(): ProjectContextValue {
  const value = useContext(ProjectContext);
  if (!value) throw new Error("useProject must be used inside ProjectProvider");
  return value;
}

export function useRequiredProjectId(): string {
  const { selectedProjectId } = useProject();
  return selectedProjectId || "";
}
