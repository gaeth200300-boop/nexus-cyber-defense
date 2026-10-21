import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import {
  CheckSquare,
  ClipboardList,
  FlaskConical,
  Lightbulb,
  MessageSquarePlus,
  Plus,
  Square,
  Target
} from "lucide-react";
import { apiFetch, errorMessage } from "../lib/api";
import { cn, formatDateTime } from "../lib/utils";
import { useDocumentTitle } from "../hooks";
import { useRequiredProjectId } from "../context/ProjectContext";
import { useToast } from "../context/ToastContext";
import { DataError, ProjectGate, SectionCard } from "../components/common";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  Field,
  Input,
  Modal,
  PageHeader,
  Select,
  Skeleton,
  Textarea
} from "../components/ui";
import type { CaseFile, Lang } from "../types";

const HYPOTHESIS_STATUS = ["open", "supported", "refuted", "superseded"];
const TASK_STATUS = ["todo", "doing", "done", "blocked"];

export default function WorkbenchPage() {
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const projectId = useRequiredProjectId();
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [caseOpen, setCaseOpen] = useState(false);
  const [hypothesisOpen, setHypothesisOpen] = useState(false);
  const [annotationOpen, setAnnotationOpen] = useState(false);
  const [taskOpen, setTaskOpen] = useState(false);
  const [caseDraft, setCaseDraft] = useState({ title: "", summary: "", severity: "medium" });
  const [hypothesisDraft, setHypothesisDraft] = useState({ statement: "", confidence: "tentative", rationale: "" });
  const [annotationDraft, setAnnotationDraft] = useState({ body: "", entity_type: "", entity_id: "" });
  const [taskDraft, setTaskDraft] = useState({ title: "", detail: "", status: "todo" });
  useDocumentTitle(t("workbench.title"));

  const cases = useQuery({
    queryKey: ["cases", projectId],
    queryFn: () =>
      apiFetch<{ items: CaseFile[]; total: number }>(`/projects/${projectId}/cases`, { query: { limit: 100 } }),
    enabled: Boolean(projectId)
  });

  const selected = cases.data?.items.find((item) => item.id === selectedId) || null;

  const invalidate = () => void queryClient.invalidateQueries({ queryKey: ["cases", projectId] });

  const createCase = useMutation({
    mutationFn: () =>
      apiFetch<CaseFile>(`/projects/${projectId}/cases`, { method: "POST", body: caseDraft }),
    onSuccess: (created) => {
      setSelectedId(created.id);
      setCaseOpen(false);
      setCaseDraft({ title: "", summary: "", severity: "medium" });
      toast({ title: t("workbench.caseCreated"), variant: "success" });
      invalidate();
    },
    onError: (error) => toast({ title: t("common.errorTitle"), description: errorMessage(error), variant: "error" })
  });

  const addHypothesis = useMutation({
    mutationFn: () =>
      apiFetch<CaseFile>(`/projects/${projectId}/cases/${selectedId}/hypotheses`, {
        method: "POST",
        body: hypothesisDraft
      }),
    onSuccess: () => {
      setHypothesisOpen(false);
      setHypothesisDraft({ statement: "", confidence: "tentative", rationale: "" });
      toast({ title: t("workbench.hypothesisAdded"), variant: "success" });
      invalidate();
    },
    onError: (error) => toast({ title: t("common.errorTitle"), description: errorMessage(error), variant: "error" })
  });

  const setHypothesisStatus = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      apiFetch<CaseFile>(`/projects/${projectId}/cases/${selectedId}/hypotheses/${id}`, {
        method: "PATCH",
        body: { status }
      }),
    onSuccess: invalidate,
    onError: (error) => toast({ title: t("common.errorTitle"), description: errorMessage(error), variant: "error" })
  });

  const addAnnotation = useMutation({
    mutationFn: () =>
      apiFetch<CaseFile>(`/projects/${projectId}/cases/${selectedId}/annotations`, {
        method: "POST",
        body: annotationDraft
      }),
    onSuccess: () => {
      setAnnotationOpen(false);
      setAnnotationDraft({ body: "", entity_type: "", entity_id: "" });
      toast({ title: t("workbench.annotationAdded"), variant: "success" });
      invalidate();
    },
    onError: (error) => toast({ title: t("common.errorTitle"), description: errorMessage(error), variant: "error" })
  });

  const addTask = useMutation({
    mutationFn: () =>
      apiFetch<CaseFile>(`/projects/${projectId}/cases/${selectedId}/tasks`, { method: "POST", body: taskDraft }),
    onSuccess: () => {
      setTaskOpen(false);
      setTaskDraft({ title: "", detail: "", status: "todo" });
      toast({ title: t("workbench.taskAdded"), variant: "success" });
      invalidate();
    },
    onError: (error) => toast({ title: t("common.errorTitle"), description: errorMessage(error), variant: "error" })
  });

  const toggleTask = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      apiFetch<CaseFile>(`/projects/${projectId}/cases/${selectedId}/tasks/${id}`, {
        method: "PATCH",
        body: { status }
      }),
    onSuccess: invalidate,
    onError: (error) => toast({ title: t("common.errorTitle"), description: errorMessage(error), variant: "error" })
  });

  return (
    <ProjectGate>
      <div className="space-y-5">
        <PageHeader
          eyebrow={t("workbench.eyebrow")}
          icon={FlaskConical}
          title={t("workbench.title")}
          subtitle={t("workbench.subtitle")}
          actions={
            <Button icon={Plus} onClick={() => setCaseOpen(true)}>
              {t("workbench.newCase")}
            </Button>
          }
        />

        {cases.isLoading ? (
          <Skeleton className="h-96 rounded-2xl" />
        ) : cases.isError ? (
          <Card>
            <DataError
              message={cases.error instanceof Error ? cases.error.message : undefined}
              onRetry={() => void cases.refetch()}
            />
          </Card>
        ) : (
          <section className="grid gap-4 xl:grid-cols-12">
            <SectionCard
              className="xl:col-span-4"
              title={t("workbench.cases")}
              subtitle={t("workbench.casesSubtitle")}
              icon={ClipboardList}
              bodyClassName="divide-y divide-line/40"
            >
              {cases.data?.items.length ? (
                cases.data.items.map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => setSelectedId(item.id)}
                    className={cn(
                      "flex w-full flex-col gap-1.5 px-4 py-3 text-start transition",
                      selectedId === item.id ? "bg-accent/[0.07]" : "hover:bg-panel2/50"
                    )}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-[9px] text-accent2">{item.reference}</span>
                      <Badge tone={item.severity === "critical" ? "danger" : item.severity === "high" ? "warning" : "default"}>
                        {item.severity}
                      </Badge>
                    </div>
                    <span className="truncate text-[11px] font-medium text-ink">{item.title}</span>
                    <div className="flex flex-wrap items-center gap-2 text-[9px] text-faint">
                      <span>{item.status}</span>
                      <span>Â·</span>
                      <span>
                        {t("workbench.hypotheses")} {item.counts.hypotheses}
                      </span>
                      <span>Â·</span>
                      <span>
                        {t("workbench.openTasks")} {item.counts.open_tasks}
                      </span>
                    </div>
                  </button>
                ))
              ) : (
                <EmptyState
                  icon={ClipboardList}
                  title={t("workbench.empty")}
                  description={t("workbench.emptyBody")}
                  action={
                    <Button size="sm" icon={Plus} onClick={() => setCaseOpen(true)}>
                      {t("workbench.newCase")}
                    </Button>
                  }
                />
              )}
            </SectionCard>

            <div className="space-y-4 xl:col-span-8">
              {selected ? (
                <>
                  <SectionCard
                    title={selected.title}
                    subtitle={`${selected.reference} Â· ${selected.severity} Â· ${selected.status}`}
                    icon={Target}
                    bodyClassName="space-y-4 p-4"
                  >
                    <p className="text-[11px] leading-relaxed text-muted">{selected.summary || t("workbench.noSummary")}</p>
                    <div className="grid gap-3 sm:grid-cols-3">
                      <div className="rounded-xl border border-line/60 bg-panel2/40 p-3">
                        <p className="text-[9px] uppercase tracking-wider text-faint">{t("workbench.hypotheses")}</p>
                        <p className="mt-1 font-display text-xl font-semibold tabular-nums text-ink">
                          {selected.counts.hypotheses}
                        </p>
                      </div>
                      <div className="rounded-xl border border-line/60 bg-panel2/40 p-3">
                        <p className="text-[9px] uppercase tracking-wider text-faint">{t("workbench.annotations")}</p>
                        <p className="mt-1 font-display text-xl font-semibold tabular-nums text-ink">
                          {selected.counts.annotations}
                        </p>
                      </div>
                      <div className="rounded-xl border border-line/60 bg-panel2/40 p-3">
                        <p className="text-[9px] uppercase tracking-wider text-faint">{t("workbench.tasks")}</p>
                        <p className="mt-1 font-display text-xl font-semibold tabular-nums text-ink">
                          {selected.counts.tasks}
                        </p>
                      </div>
                    </div>
                  </SectionCard>

                  <SectionCard
                    title={t("workbench.hypothesesTitle")}
                    subtitle={t("workbench.hypothesesSubtitle")}
                    icon={Lightbulb}
                    actions={
                      <Button size="sm" variant="secondary" icon={Plus} onClick={() => setHypothesisOpen(true)}>
                        {t("workbench.addHypothesis")}
                      </Button>
                    }
                    bodyClassName="divide-y divide-line/40"
                  >
                    {selected.hypotheses.map((hypothesis) => (
                      <div key={hypothesis.id} className="px-4 py-3">
                        <div className="flex flex-wrap items-start justify-between gap-2">
                          <p className="min-w-0 flex-1 text-[11px] leading-relaxed text-ink">
                            {hypothesis.statement}
                          </p>
                          <Select
                            value={hypothesis.status}
                            onChange={(event) =>
                              setHypothesisStatus.mutate({ id: hypothesis.id, status: event.target.value })
                            }
                            className="h-7 w-32 shrink-0 text-[10px]"
                          >
                            {HYPOTHESIS_STATUS.map((value) => (
                              <option key={value} value={value}>
                                {value}
                              </option>
                            ))}
                          </Select>
                        </div>
                        {hypothesis.rationale ? (
                          <p className="mt-1 text-[10px] leading-relaxed text-muted">{hypothesis.rationale}</p>
                        ) : null}
                        <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                          <Badge tone="default">{hypothesis.confidence}</Badge>
                          {hypothesis.evidence_refs.map((ref) => (
                            <Badge key={`${ref.kind}-${ref.id}`} tone="accent">
                              {ref.label || ref.kind}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    ))}
                    {!selected.hypotheses.length ? (
                      <EmptyState
                        icon={Lightbulb}
                        title={t("workbench.noHypotheses")}
                        description={t("workbench.noHypothesesBody")}
                      />
                    ) : null}
                  </SectionCard>

                  <div className="grid gap-4 lg:grid-cols-2">
                    <SectionCard
                      title={t("workbench.tasksTitle")}
                      subtitle={t("workbench.tasksSubtitle")}
                      icon={CheckSquare}
                      actions={
                        <Button size="sm" variant="secondary" icon={Plus} onClick={() => setTaskOpen(true)}>
                          {t("workbench.addTask")}
                        </Button>
                      }
                      bodyClassName="divide-y divide-line/40"
                    >
                      {selected.tasks.map((task) => (
                        <button
                          key={task.id}
                          type="button"
                          onClick={() =>
                            toggleTask.mutate({
                              id: task.id,
                              status: task.status === "done" ? "todo" : "done"
                            })
                          }
                          className="flex w-full items-start gap-2.5 px-4 py-2.5 text-start transition hover:bg-panel2/50"
                        >
                          {task.status === "done" ? (
                            <CheckSquare className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-400" />
                          ) : (
                            <Square className="mt-0.5 h-3.5 w-3.5 shrink-0 text-faint" />
                          )}
                          <span className="min-w-0 flex-1">
                            <span
                              className={cn(
                                "block text-[11px] text-ink",
                                task.status === "done" && "text-muted line-through"
                              )}
                            >
                              {task.title}
                            </span>
                            {task.detail ? (
                              <span className="mt-0.5 block text-[10px] text-faint">{task.detail}</span>
                            ) : null}
                          </span>
                        </button>
                      ))}
                      {!selected.tasks.length ? (
                        <EmptyState icon={CheckSquare} title={t("workbench.noTasks")} description={t("workbench.noTasksBody")} />
                      ) : null}
                    </SectionCard>

                    <SectionCard
                      title={t("workbench.annotationsTitle")}
                      subtitle={t("workbench.annotationsSubtitle")}
                      icon={MessageSquarePlus}
                      actions={
                        <Button size="sm" variant="secondary" icon={Plus} onClick={() => setAnnotationOpen(true)}>
                          {t("workbench.addAnnotation")}
                        </Button>
                      }
                      bodyClassName="divide-y divide-line/40"
                    >
                      {selected.annotations.map((annotation) => (
                        <div key={annotation.id} className="px-4 py-3">
                          <p className="text-[11px] leading-relaxed text-muted">{annotation.body}</p>
                          <p className="mt-1 text-[9px] text-faint">
                            {annotation.entity_type ? `${annotation.entity_type} Â· ` : ""}
                            {annotation.created_at ? formatDateTime(annotation.created_at, lang) : ""}
                          </p>
                        </div>
                      ))}
                      {!selected.annotations.length ? (
                        <EmptyState
                          icon={MessageSquarePlus}
                          title={t("workbench.noAnnotations")}
                          description={t("workbench.noAnnotationsBody")}
                        />
                      ) : null}
                    </SectionCard>
                  </div>
                </>
              ) : (
                <Card>
                  <EmptyState
                    icon={ClipboardList}
                    title={t("workbench.noSelection")}
                    description={t("workbench.noSelectionBody")}
                  />
                </Card>
              )}
            </div>
          </section>
        )}

        <Modal
          open={caseOpen}
          onOpenChange={setCaseOpen}
          title={t("workbench.newCase")}
          description={t("workbench.caseSubtitle")}
          icon={ClipboardList}
          footer={
            <>
              <Button variant="ghost" onClick={() => setCaseOpen(false)}>
                {t("common.cancel")}
              </Button>
              <Button
                onClick={() => createCase.mutate()}
                disabled={createCase.isPending || caseDraft.title.trim().length < 3}
              >
                {t("common.create")}
              </Button>
            </>
          }
        >
          <div className="space-y-3">
            <Field label={t("common.name")} required>
              <Input
                value={caseDraft.title}
                onChange={(event) => setCaseDraft((prev) => ({ ...prev, title: event.target.value }))}
              />
            </Field>
            <Field label={t("common.description")}>
              <Textarea
                rows={3}
                value={caseDraft.summary}
                onChange={(event) => setCaseDraft((prev) => ({ ...prev, summary: event.target.value }))}
              />
            </Field>
            <Field label={t("common.severity")}>
              <Select
                value={caseDraft.severity}
                onChange={(event) => setCaseDraft((prev) => ({ ...prev, severity: event.target.value }))}
              >
                <option value="low">low</option>
                <option value="medium">medium</option>
                <option value="high">high</option>
                <option value="critical">critical</option>
              </Select>
            </Field>
          </div>
        </Modal>

        <Modal
          open={hypothesisOpen}
          onOpenChange={setHypothesisOpen}
          title={t("workbench.addHypothesis")}
          description={t("workbench.hypothesisSubtitle")}
          icon={Lightbulb}
          footer={
            <>
              <Button variant="ghost" onClick={() => setHypothesisOpen(false)}>
                {t("common.cancel")}
              </Button>
              <Button
                onClick={() => addHypothesis.mutate()}
                disabled={addHypothesis.isPending || hypothesisDraft.statement.trim().length < 5}
              >
                {t("common.add")}
              </Button>
            </>
          }
        >
          <div className="space-y-3">
            <Field label={t("workbench.statement")} required>
              <Textarea
                rows={3}
                value={hypothesisDraft.statement}
                onChange={(event) =>
                  setHypothesisDraft((prev) => ({ ...prev, statement: event.target.value }))
                }
              />
            </Field>
            <Field label={t("common.confidence")}>
              <Select
                value={hypothesisDraft.confidence}
                onChange={(event) =>
                  setHypothesisDraft((prev) => ({ ...prev, confidence: event.target.value }))
                }
              >
                <option value="tentative">tentative</option>
                <option value="firm">firm</option>
                <option value="certain">certain</option>
              </Select>
            </Field>
            <Field label={t("workbench.rationale")}>
              <Textarea
                rows={3}
                value={hypothesisDraft.rationale}
                onChange={(event) =>
                  setHypothesisDraft((prev) => ({ ...prev, rationale: event.target.value }))
                }
              />
            </Field>
          </div>
        </Modal>

        <Modal
          open={annotationOpen}
          onOpenChange={setAnnotationOpen}
          title={t("workbench.addAnnotation")}
          icon={MessageSquarePlus}
          footer={
            <>
              <Button variant="ghost" onClick={() => setAnnotationOpen(false)}>
                {t("common.cancel")}
              </Button>
              <Button onClick={() => addAnnotation.mutate()} disabled={annotationDraft.body.trim().length < 1}>
                {t("common.add")}
              </Button>
            </>
          }
        >
          <div className="space-y-3">
            <Field label={t("common.notes")} required>
              <Textarea
                rows={3}
                value={annotationDraft.body}
                onChange={(event) => setAnnotationDraft((prev) => ({ ...prev, body: event.target.value }))}
              />
            </Field>
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label={t("workbench.entityType")}>
                <Input
                  value={annotationDraft.entity_type}
                  onChange={(event) =>
                    setAnnotationDraft((prev) => ({ ...prev, entity_type: event.target.value }))
                  }
                  placeholder="finding"
                />
              </Field>
              <Field label={t("workbench.entityId")}>
                <Input
                  value={annotationDraft.entity_id}
                  onChange={(event) =>
                    setAnnotationDraft((prev) => ({ ...prev, entity_id: event.target.value }))
                  }
                />
              </Field>
            </div>
          </div>
        </Modal>

        <Modal
          open={taskOpen}
          onOpenChange={setTaskOpen}
          title={t("workbench.addTask")}
          icon={CheckSquare}
          footer={
            <>
              <Button variant="ghost" onClick={() => setTaskOpen(false)}>
                {t("common.cancel")}
              </Button>
              <Button onClick={() => addTask.mutate()} disabled={taskDraft.title.trim().length < 3}>
                {t("common.add")}
              </Button>
            </>
          }
        >
          <div className="space-y-3">
            <Field label={t("common.name")} required>
              <Input
                value={taskDraft.title}
                onChange={(event) => setTaskDraft((prev) => ({ ...prev, title: event.target.value }))}
              />
            </Field>
            <Field label={t("common.description")}>
              <Textarea
                rows={3}
                value={taskDraft.detail}
                onChange={(event) => setTaskDraft((prev) => ({ ...prev, detail: event.target.value }))}
              />
            </Field>
            <Field label={t("common.status")}>
              <Select
                value={taskDraft.status}
                onChange={(event) => setTaskDraft((prev) => ({ ...prev, status: event.target.value }))}
              >
                {TASK_STATUS.map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </Select>
            </Field>
          </div>
        </Modal>
      </div>
    </ProjectGate>
  );
}

