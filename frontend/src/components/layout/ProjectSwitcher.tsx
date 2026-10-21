import { useLocation, useNavigate } from "react-router-dom";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { useTranslation } from "react-i18next";
import { Check, ChevronsUpDown, FolderKanban, Plus, ShieldCheck } from "lucide-react";
import { useProject } from "../../context/ProjectContext";
import { cn } from "../../lib/utils";

export function ProjectSwitcher({ compact }: { compact?: boolean }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const location = useLocation();
  const { projects, selectedProject, setSelectedProject } = useProject();

  const select = (projectId: string) => {
    setSelectedProject(projectId);
    if (location.pathname.startsWith("/projects/")) navigate(`/projects/${projectId}`);
  };

  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <button
          type="button"
          className={cn(
            "group flex h-9 items-center gap-2 rounded-xl border border-line bg-panel2/70 px-2.5 text-xs text-ink transition hover:border-accent/30 hover:bg-panel2 focus-ring",
            compact && "w-9 justify-center px-0"
          )}
          title={selectedProject?.name || t("common.selectProject")}
        >
          <span className="grid h-5 w-5 shrink-0 place-items-center rounded-md bg-accent/15 text-accent">
            <FolderKanban className="h-3 w-3" />
          </span>
          {!compact ? (
            <>
              <span className="max-w-36 truncate font-medium">
                {selectedProject?.name || t("common.selectProject")}
              </span>
              <ChevronsUpDown className="h-3.5 w-3.5 shrink-0 text-faint transition group-hover:text-muted" />
            </>
          ) : null}
        </button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content
          align="end"
          sideOffset={8}
          className="z-[95] w-72 overflow-hidden rounded-xl border border-line bg-panel p-1.5 shadow-panel animate-scale-in"
        >
          <div className="px-2.5 pb-1.5 pt-1">
            <p className="text-[9px] font-semibold uppercase tracking-[0.15em] text-faint">
              {t("common.selectProject")}
            </p>
          </div>
          <div className="max-h-72 overflow-y-auto">
            {projects.length ? (
              projects.map((project) => (
                <DropdownMenu.Item
                  key={project.id}
                  onSelect={() => select(project.id)}
                  className="flex cursor-pointer items-center gap-2.5 rounded-lg px-2.5 py-2 text-xs text-muted outline-none transition data-[highlighted]:bg-panel2 data-[highlighted]:text-ink"
                >
                  <span className="grid h-7 w-7 shrink-0 place-items-center rounded-lg border border-line bg-panel2 text-accent">
                    <ShieldCheck className="h-3.5 w-3.5" />
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate font-medium text-ink">{project.name}</span>
                    <span className="block truncate font-mono text-[9px] text-faint">{project.slug}</span>
                  </span>
                  {selectedProject?.id === project.id ? <Check className="h-3.5 w-3.5 text-accent" /> : null}
                </DropdownMenu.Item>
              ))
            ) : (
              <p className="px-2.5 py-4 text-center text-[11px] text-faint">{t("projects.noProjects")}</p>
            )}
          </div>
          <DropdownMenu.Separator className="my-1 h-px bg-line/70" />
          <DropdownMenu.Item
            onSelect={() => navigate("/projects?new=1")}
            className="flex cursor-pointer items-center gap-2 rounded-lg px-2.5 py-2 text-xs text-muted outline-none transition data-[highlighted]:bg-panel2 data-[highlighted]:text-ink"
          >
            <Plus className="h-3.5 w-3.5" />
            {t("projects.new")}
          </DropdownMenu.Item>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}
