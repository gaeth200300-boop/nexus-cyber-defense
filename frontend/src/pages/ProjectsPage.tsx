import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import {
  Activity,
  Archive,
  ArrowUpRight,
  Boxes,
  Bug,
  CheckCircle2,
  ChevronRight,
  FolderKanban,
  Plus,
  Search,
  ShieldCheck,
  UserRound
} from "lucide-react";
import { apiFetch, errorMessage } from "../lib/api";
import { cn, formatDate, fromNow } from "../lib/utils";
import { useAuth } from "../context/AuthContext";
import { useProject } from "../context/ProjectContext";
import { useToast } from "../context/ToastContext";
import { useDocumentTitle, useMeta } from "../hooks";
import type { Lang, Project } from "../types";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  Field,
  InlineAlert,
  Input,
  Modal,
  PageHeader,
  Select,
  Skeleton,
  Textarea
} from "../components/ui";

interface ProjectsResponse {
  items: Project[];
  total: number;
}

const projectTone = ["text-accent", "text-accent2", "text-emerald-300", "text-amber-300", "text-rose-300"];

export default function ProjectsPage() {
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const { user } = useAuth();
  const { setSelectedProject } = useProject();
  const meta = useMeta();
  const navigate = useNavigate();
  const [q, setQ] = useState("");
  const [archived, setArchived] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  useDocumentTitle(t("projects.title"));

  const projects = useQuery({
    queryKey: ["projects", archived],
    queryFn: () => apiFetch<ProjectsResponse>("/projects", { query: { include_archived: archived } })
  });

  const rows = useMemo(() => {
    const items = projects.data?.items || [];
    if (!q.trim()) return items;
    const needle = q.trim().toLowerCase();
    return items.filter(
      (project) =>
        project.name.toLowerCase().includes(needle) ||
        project.slug.toLowerCase().includes(needle) ||
        project.description.toLowerCase().includes(needle)
    );
  }, [projects.data?.items, q]);

  const totalAssets = rows.reduce((sum, project) => sum + (project.counts?.assets || 0), 0);
  const totalFindings = rows.reduce((sum, project) => sum + (project.counts?.open_findings || 0), 0);
  const totalScans = rows.reduce((sum, project) => sum + (project.counts?.active_scans || 0), 0);
  const kindLabels = meta.data?.constants.project_kinds || [];

  const openProject = (project: Project) => {
    setSelectedProject(project.id);
    navigate(`/projects/${project.id}`);
  };

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow={t("nav.workspace")}
        icon={FolderKanban}
        title={t("projects.title")}
        subtitle={t("projects.subtitle")}
        actions={
          <Button icon={Plus} onClick={() => setCreateOpen(true)}>
            {t("projects.new")}
          </Button>
        }
      />

      <section className="grid grid-cols-2 gap-2.5 xl:grid-cols-4">
        {[
          { label: t("projects.title"), value: rows.length, icon: FolderKanban, tone: "text-accent" },
          { label: t("projects.assets"), value: totalAssets, icon: Boxes, tone: "text-accent2" },
          { label: t("projects.openFindings"), value: totalFindings, icon: Bug, tone: "text-rose-300" },
          { label: t("projects.activeScans"), value: totalScans, icon: Activity, tone: "text-amber-300" }
        ].map((card) => (
          <div key={card.label} className="surface-card p-3.5">
            <div className="flex items-center justify-between">
              <span className="text-[9px] font-semibold uppercase tracking-[0.1em] text-muted">{card.label}</span>
              <card.icon className={cn("h-4 w-4", card.tone)} />
            </div>
            <p className="mt-2 font-display text-2xl font-semibold tabular-nums text-ink">{card.value}</p>
          </div>
        ))}
      </section>

      <div className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-[220px] flex-1">
          <Search className="pointer-events-none absolute start-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-faint" />
          <Input value={q} onChange={(event) => setQ(event.target.value)} placeholder={t("projects.search")} className="ps-9" />
        </div>
        <label className="flex items-center gap-2 rounded-lg border border-line/60 bg-panel/40 px-3 py-2 text-[10px] text-muted">
          <input
            type="checkbox"
            checked={archived}
            onChange={(event) => setArchived(event.target.checked)}
            className="h-3 w-3 accent-[rgb(var(--accent))]"
          />
          {t("projects.filterArchived")}
        </label>
        <span className="text-[9px] text-faint">{t("projects.total", { count: rows.length })}</span>
      </div>

      {projects.isLoading ? (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {[0, 1, 2, 3, 4, 5].map((key) => <Skeleton key={key} className="h-52 rounded-2xl" />)}
        </div>
      ) : projects.isError ? (
        <Card className="p-2">
          <EmptyState
            icon={FolderKanban}
            title={t("common.errorTitle")}
            description={projects.error instanceof Error ? projects.error.message : t("common.errorDescription")}
            action={<Button variant="secondary" onClick={() => void projects.refetch()}>{t("common.retry")}</Button>}
          />
        </Card>
      ) : rows.length ? (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {rows.map((project, index) => (
            <button
              key={project.id}
              type="button"
              onClick={() => openProject(project)}
              className={cn(
                "surface-card group flex h-full flex-col p-4 text-start transition hover:border-accent/25",
                project.archived && "opacity-70"
              )}
            >
              <div className="flex items-start justify-between gap-2">
                <span className={cn("grid h-10 w-10 place-items-center rounded-xl border border-line bg-panel2", projectTone[index % projectTone.length])}>
                  <ShieldCheck className="h-5 w-5" />
                </span>
                <div className="flex flex-wrap items-center justify-end gap-1.5">
                  {project.archived ? <Badge tone="default"><Archive className="h-2.5 w-2.5" /> {t("projects.archivedBadge")}</Badge> : null}
                  <Badge tone="info">{kindLabels.find((item) => item.key === project.kind) ? (lang === "ar" ? kindLabels.find((item) => item.key === project.kind)?.labels.ar : kindLabels.find((item) => item.key === project.kind)?.labels.en) : project.kind}</Badge>
                  {project.role ? <Badge tone="accent">{project.role}</Badge> : null}
                </div>
              </div>
              <h3 className="mt-3 line-clamp-2 font-display text-base font-semibold text-ink">{project.name}</h3>
              <p className="mt-1 line-clamp-2 min-h-[28px] text-[10px] leading-relaxed text-muted">
                {project.description || t("common.noDescription")}
              </p>
              <div className="mt-3 grid grid-cols-3 gap-2">
                {[
                  { icon: Boxes, value: project.counts?.assets || 0, label: t("projects.assets") },
                  { icon: Bug, value: project.counts?.open_findings || 0, label: t("projects.openFindings") },
                  { icon: Activity, value: project.counts?.active_scans || 0, label: t("projects.activeScans") }
                ].map((item) => (
                  <div key={item.label} className="rounded-lg border border-line/50 bg-panel2/40 p-2">
                    <div className="flex items-center gap-1 text-[8px] text-faint">
                      <item.icon className="h-2.5 w-2.5" /> {item.label}
                    </div>
                    <p className="mt-0.5 font-display text-sm font-semibold tabular-nums text-ink">{item.value}</p>
                  </div>
                ))}
              </div>
              <div className="mt-auto flex items-center gap-2 pt-3 text-[8px] text-faint">
                <span>{formatDate(project.created_at, lang)}</span>
                <span>·</span>
                <span>{fromNow(project.updated_at, lang)}</span>
                <span className="ms-auto flex items-center gap-1 text-accent2 opacity-0 transition group-hover:opacity-100">
                  {t("projects.open")} <ChevronRight className="h-3 w-3 rtl:rotate-180" />
                </span>
              </div>
            </button>
          ))}
        </div>
      ) : (
        <Card className="p-2">
          <EmptyState
            icon={FolderKanban}
            title={q ? t("common.noneFound") : t("projects.emptyTitle")}
            description={q ? t("projects.noProjects") : t("projects.emptyBody")}
            action={
              !q ? (
                <Button icon={Plus} onClick={() => setCreateOpen(true)}>{t("projects.createFirst")}</Button>
              ) : undefined
            }
          />
        </Card>
      )}

      <div className="rounded-xl border border-accent/15 bg-gradient-to-br from-accent/[0.06] to-accent2/[0.03] p-4">
        <div className="flex items-start gap-2.5">
          <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-accent" />
          <div>
            <p className="text-[11px] font-semibold text-ink">{t("projects.policyTitle")}</p>
            <p className="mt-1 text-[10px] leading-relaxed text-muted">{t("projects.policyBody")}</p>
          </div>
        </div>
      </div>

      <CreateProjectModal
        open={createOpen}
        onOpenChange={setCreateOpen}
        isAdmin={["owner", "admin"].includes(user?.role || "")}
        onCreated={openProject}
      />
    </div>
  );
}

function CreateProjectModal({
  open,
  onOpenChange,
  isAdmin,
  onCreated
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  isAdmin: boolean;
  onCreated: (project: Project) => void;
}) {
  const { t, i18n } = useTranslation();
  const meta = useMeta();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [kind, setKind] = useState("assessment");
  const [allowPrivate, setAllowPrivate] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!open) return;
    setName("");
    setDescription("");
    setKind("assessment");
    setAllowPrivate(false);
    setError("");
  }, [open]);

  const create = useMutation({
    mutationFn: () =>
      apiFetch<{ project: Project }>("/projects", {
        method: "POST",
        body: {
          name: name.trim(),
          description: description.trim(),
          kind,
          allow_private_targets: isAdmin && allowPrivate
        }
      }),
    onSuccess: async (result) => {
      toast.toast({ title: t("projects.created"), variant: "success" });
      await queryClient.invalidateQueries({ queryKey: ["projects"] });
      onOpenChange(false);
      onCreated(result.project);
    },
    onError: (caught) => setError(errorMessage(caught))
  });

  const kinds = meta.data?.constants.project_kinds || [];

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title={t("projects.new")}
      description={t("projects.emptyBody")}
      icon={Plus}
      size="md"
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>{t("common.cancel")}</Button>
          <Button icon={Plus} loading={create.isPending} disabled={name.trim().length < 2} onClick={() => { setError(""); create.mutate(); }}>
            {t("common.create")}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field label={t("projects.name")} required>
          <Input value={name} onChange={(event) => setName(event.target.value)} maxLength={160} autoFocus />
        </Field>
        <Field label={t("projects.description")} hint={t("common.optional")}>
          <Textarea value={description} onChange={(event) => setDescription(event.target.value)} rows={3} maxLength={2000} />
        </Field>
        <Field label={t("projects.kind")}>
          <Select value={kind} onChange={(event) => setKind(event.target.value)}>
            {kinds.map((item) => (
              <option key={item.key} value={item.key}>{i18n.language.startsWith("ar") ? item.labels.ar : item.labels.en}</option>
            ))}
          </Select>
        </Field>
        <label className={cn("flex items-start gap-2 rounded-xl border border-line/60 bg-panel2/30 p-3", !isAdmin && "opacity-60")}>
          <input
            type="checkbox"
            checked={allowPrivate}
            onChange={(event) => setAllowPrivate(event.target.checked)}
            disabled={!isAdmin}
            className="mt-0.5 h-3.5 w-3.5 accent-[rgb(var(--accent))]"
          />
          <span>
            <span className="block text-[10px] font-medium text-ink">{t("projects.allowPrivate")}</span>
            <span className="mt-0.5 block text-[9px] leading-relaxed text-faint">{t("projects.allowPrivateHint")}</span>
          </span>
        </label>
        <InlineAlert tone="info" title={t("projects.policyTitle")}>{t("projects.scopeWarning")}</InlineAlert>
        {error ? <InlineAlert tone="danger">{error}</InlineAlert> : null}
      </div>
    </Modal>
  );
}
