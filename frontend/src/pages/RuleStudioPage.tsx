import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import {
  AlertTriangle,
  Beaker,
  CheckCircle2,
  Code2,
  Eye,
  FileCode2,
  FlaskConical,
  Plus,
  Save,
  ShieldAlert,
  Trash2,
  XCircle
} from "lucide-react";
import { apiFetch, errorMessage } from "../lib/api";
import { cn, formatDateTime } from "../lib/utils";
import { useDocumentTitle } from "../hooks";
import { useRequiredProjectId } from "../context/ProjectContext";
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
import { useToast } from "../context/ToastContext";
import type { Lang, SigmaRule, SigmaTestResult, SigmaValidation } from "../types";

const STARTER_RULE = {
  name: "authentication-failure-burst",
  title: "Authentication failure burst",
  description: "Repeated authentication failures from a single source address.",
  status: "experimental",
  level: "high",
  logsource: { product: "windows", service: "security" },
  detection: {
    selection: { event_type: "auth_failure" },
    condition: "selection"
  },
  falsepositives: ["Users repeatedly mistyping a password."],
  references: ["https://attack.mitre.org/techniques/T1110/"]
};

export default function RuleStudioPage() {
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const projectId = useRequiredProjectId();
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [draft, setDraft] = useState<Record<string, unknown>>(STARTER_RULE);
  const [editorOpen, setEditorOpen] = useState(false);
  const [testResult, setTestResult] = useState<SigmaTestResult | null>(null);
  useDocumentTitle(t("rules.title"));

  const rules = useQuery({
    queryKey: ["sigma-rules", projectId],
    queryFn: () =>
      apiFetch<{ items: SigmaRule[]; total: number }>(`/projects/${projectId}/rules`, { query: { limit: 200 } }),
    enabled: Boolean(projectId)
  });

  const selected = useMemo(
    () => rules.data?.items.find((rule) => rule.id === selectedId) || null,
    [rules.data, selectedId]
  );

  const validation = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      apiFetch<SigmaValidation>(`/projects/${projectId}/rules/validate`, { method: "POST", body }),
    onSuccess: (report) => {
      if (report.valid) {
        toast({ title: t("rules.valid"), variant: "success" });
      } else {
        toast({ title: t("rules.invalid"), variant: "error" });
      }
    }
  });

  const save = useMutation({
    mutationFn: async (body: Record<string, unknown>) => {
      if (selectedId) {
        return apiFetch<SigmaRule>(`/projects/${projectId}/rules/${selectedId}`, { method: "PUT", body });
      }
      return apiFetch<SigmaRule>(`/projects/${projectId}/rules`, { method: "POST", body });
    },
    onSuccess: (rule) => {
      setSelectedId(rule.id);
      setEditorOpen(false);
      toast({ title: t("rules.saved"), variant: "success" });
      void queryClient.invalidateQueries({ queryKey: ["sigma-rules", projectId] });
    },
    onError: (error) => toast({ title: t("common.errorTitle"), description: errorMessage(error), variant: "error" })
  });

  const remove = useMutation({
    mutationFn: (ruleId: string) =>
      apiFetch(`/projects/${projectId}/rules/${ruleId}`, { method: "DELETE" }),
    onSuccess: () => {
      setSelectedId(null);
      toast({ title: t("rules.deleted"), variant: "success" });
      void queryClient.invalidateQueries({ queryKey: ["sigma-rules", projectId] });
    },
    onError: (error) => toast({ title: t("common.errorTitle"), description: errorMessage(error), variant: "error" })
  });

  const test = useMutation({
    mutationFn: (ruleId: string) =>
      apiFetch<SigmaTestResult>(`/projects/${projectId}/rules/${ruleId}/test`, {
        method: "POST",
        body: { limit: 500 }
      }),
    onSuccess: (result) => setTestResult(result),
    onError: (error) => toast({ title: t("common.errorTitle"), description: errorMessage(error), variant: "error" })
  });

  const openEditor = (rule?: SigmaRule) => {
    if (rule) {
      setDraft({
        name: rule.name,
        title: rule.title,
        description: rule.description,
        status: rule.status,
        level: rule.level,
        logsource: rule.logsource,
        detection: rule.detection,
        falsepositives: rule.falsepositives,
        references: rule.references
      });
    } else {
      setDraft(STARTER_RULE);
      setSelectedId(null);
    }
    setEditorOpen(true);
  };

  const parseJson = (value: string, fallback: unknown) => {
    try {
      return JSON.parse(value);
    } catch {
      return fallback;
    }
  };

  return (
    <ProjectGate>
      <div className="space-y-5">
        <PageHeader
          eyebrow={t("rules.eyebrow")}
          icon={FileCode2}
          title={t("rules.title")}
          subtitle={t("rules.subtitle")}
          actions={
            <Button icon={Plus} onClick={() => openEditor()}>
              {t("rules.newRule")}
            </Button>
          }
        />

        {rules.isLoading ? (
          <Skeleton className="h-96 rounded-2xl" />
        ) : rules.isError ? (
          <Card>
            <DataError
              message={rules.error instanceof Error ? rules.error.message : undefined}
              onRetry={() => void rules.refetch()}
            />
          </Card>
        ) : (
          <section className="grid gap-4 xl:grid-cols-12">
            <SectionCard
              className="xl:col-span-5"
              title={t("rules.library")}
              subtitle={t("rules.librarySubtitle")}
              icon={Code2}
              bodyClassName="divide-y divide-line/40"
            >
              {rules.data?.items.length ? (
                rules.data.items.map((rule) => (
                  <button
                    key={rule.id}
                    type="button"
                    onClick={() => setSelectedId(rule.id)}
                    className={cn(
                      "flex w-full flex-col gap-1 px-4 py-3 text-start transition",
                      selectedId === rule.id ? "bg-accent/[0.07]" : "hover:bg-panel2/50"
                    )}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="truncate text-[11px] font-medium text-ink">{rule.title || rule.name}</span>
                      <span
                        className={cn(
                          "shrink-0 rounded-md border px-1.5 py-0.5 text-[9px] font-semibold uppercase",
                          rule.validation?.valid
                            ? "border-emerald-400/20 bg-emerald-400/10 text-emerald-300"
                            : "border-rose-400/20 bg-rose-400/10 text-rose-300"
                        )}
                      >
                        {rule.validation?.valid ? t("rules.valid") : t("rules.invalid")}
                      </span>
                    </div>
                    <span className="truncate font-mono text-[9px] text-faint">{rule.name}</span>
                    <div className="flex flex-wrap items-center gap-1.5">
                      <Badge tone="default">{rule.level}</Badge>
                      <Badge tone="default">{rule.status}</Badge>
                      {rule.last_validated_at ? (
                        <span className="text-[9px] text-faint">
                          {formatDateTime(rule.last_validated_at, lang)}
                        </span>
                      ) : null}
                    </div>
                  </button>
                ))
              ) : (
                <EmptyState
                  icon={FileCode2}
                  title={t("rules.empty")}
                  description={t("rules.emptyBody")}
                  action={
                    <Button size="sm" icon={Plus} onClick={() => openEditor()}>
                      {t("rules.newRule")}
                    </Button>
                  }
                />
              )}
            </SectionCard>

            <div className="space-y-4 xl:col-span-7">
              {selected ? (
                <>
                  <SectionCard
                    title={selected.title || selected.name}
                    subtitle={selected.description || t("rules.noDescription")}
                    icon={FileCode2}
                    actions={
                      <>
                        <Button size="sm" variant="secondary" icon={Eye} onClick={() => openEditor(selected)}>
                          {t("common.edit")}
                        </Button>
                        <Button
                          size="sm"
                          variant="secondary"
                          icon={FlaskConical}
                          onClick={() => test.mutate(selected.id)}
                          disabled={test.isPending}
                        >
                          {t("rules.test")}
                        </Button>
                        <Button
                          size="sm"
                          variant="danger"
                          icon={Trash2}
                          onClick={() => remove.mutate(selected.id)}
                          disabled={remove.isPending}
                        >
                          {t("common.delete")}
                        </Button>
                      </>
                    }
                    bodyClassName="space-y-4 p-4"
                  >
                    <div className="rounded-xl border border-line/60 bg-panel2/40 p-3">
                      <p className="mb-1.5 text-[9px] uppercase tracking-[0.1em] text-faint">
                        {t("rules.detection")}
                      </p>
                      <pre className="overflow-x-auto font-mono text-[10px] leading-relaxed text-muted">
                        {JSON.stringify(selected.detection, null, 2)}
                      </pre>
                    </div>

                    <div className="grid gap-3 sm:grid-cols-2">
                      <div>
                        <p className="mb-1.5 text-[9px] uppercase tracking-[0.1em] text-faint">
                          {t("rules.detects")}
                        </p>
                        <ul className="space-y-1">
                          {(selected.validation?.detects || []).map((item) => (
                            <li key={item} className="flex gap-1.5 text-[10px] leading-relaxed text-muted">
                              <CheckCircle2 className="mt-0.5 h-3 w-3 shrink-0 text-emerald-400/70" />
                              {item}
                            </li>
                          ))}
                          {!(selected.validation?.detects || []).length ? (
                            <li className="text-[10px] text-faint">{t("rules.notValidated")}</li>
                          ) : null}
                        </ul>
                      </div>
                      <div>
                        <p className="mb-1.5 text-[9px] uppercase tracking-[0.1em] text-faint">
                          {t("rules.blindSpots")}
                        </p>
                        <ul className="space-y-1">
                          {(selected.validation?.blind_spots || []).map((item) => (
                            <li key={item} className="flex gap-1.5 text-[10px] leading-relaxed text-muted">
                              <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0 text-amber-400/70" />
                              {item}
                            </li>
                          ))}
                          {!(selected.validation?.blind_spots || []).length ? (
                            <li className="text-[10px] text-faint">{t("rules.notValidated")}</li>
                          ) : null}
                        </ul>
                      </div>
                    </div>

                    {(selected.validation?.errors.length || selected.validation?.warnings.length) ? (
                      <div className="space-y-1.5">
                        {(selected.validation?.errors || []).map((item) => (
                          <p key={item} className="flex gap-1.5 text-[10px] text-rose-300">
                            <XCircle className="mt-0.5 h-3 w-3 shrink-0" />
                            {item}
                          </p>
                        ))}
                        {(selected.validation?.warnings || []).map((item) => (
                          <p key={item} className="flex gap-1.5 text-[10px] text-amber-300">
                            <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" />
                            {item}
                          </p>
                        ))}
                      </div>
                    ) : null}
                  </SectionCard>

                  <SectionCard
                    title={t("rules.testTitle")}
                    subtitle={t("rules.testSubtitle")}
                    icon={Beaker}
                  >
                    {testResult ? (
                      <div className="space-y-3 p-4">
                        <div className="grid grid-cols-3 gap-2 text-center">
                          <div className="rounded-lg border border-line/60 bg-panel2/40 p-2">
                            <p className="text-[9px] uppercase tracking-wider text-faint">
                              {t("rules.testedEvents")}
                            </p>
                            <p className="mt-0.5 font-display text-lg font-semibold tabular-nums text-ink">
                              {testResult.tested_events}
                            </p>
                          </div>
                          <div className="rounded-lg border border-line/60 bg-panel2/40 p-2">
                            <p className="text-[9px] uppercase tracking-wider text-faint">
                              {t("rules.matched")}
                            </p>
                            <p className="mt-0.5 font-display text-lg font-semibold tabular-nums text-accent2">
                              {testResult.matched_events}
                            </p>
                          </div>
                          <div className="rounded-lg border border-line/60 bg-panel2/40 p-2">
                            <p className="text-[9px] uppercase tracking-wider text-faint">
                              {t("rules.matchRate")}
                            </p>
                            <p className="mt-0.5 font-display text-lg font-semibold tabular-nums text-ink">
                              {testResult.match_rate}%
                            </p>
                          </div>
                        </div>
                        <p className="text-[10px] leading-relaxed text-faint">{testResult.sample_size_note}</p>
                        {testResult.matches.length ? (
                          <ul className="space-y-1.5">
                            {testResult.matches.map((match) => (
                              <li
                                key={match.event_id}
                                className="rounded-lg border border-line/60 bg-panel2/40 p-2.5"
                              >
                                <p className="truncate text-[10px] text-ink">{match.message}</p>
                                <p className="mt-0.5 font-mono text-[9px] text-faint">
                                  {match.event_type} Â· {match.src_ip || "-"} Â· {match.ts}
                                </p>
                              </li>
                            ))}
                          </ul>
                        ) : null}
                      </div>
                    ) : (
                      <EmptyState
                        icon={Beaker}
                        title={t("rules.noTest")}
                        description={t("rules.noTestBody")}
                        action={
                          <Button size="sm" icon={FlaskConical} onClick={() => test.mutate(selected.id)}>
                            {t("rules.test")}
                          </Button>
                        }
                      />
                    )}
                  </SectionCard>
                </>
              ) : (
                <Card>
                  <EmptyState
                    icon={ShieldAlert}
                    title={t("rules.noSelection")}
                    description={t("rules.noSelectionBody")}
                  />
                </Card>
              )}
            </div>
          </section>
        )}

        <Modal
          open={editorOpen}
          onOpenChange={setEditorOpen}
          title={selectedId ? t("rules.editRule") : t("rules.newRule")}
          description={t("rules.editorSubtitle")}
          size="lg"
          icon={FileCode2}
          footer={
            <>
              <Button variant="ghost" onClick={() => setEditorOpen(false)}>
                {t("common.cancel")}
              </Button>
              <Button
                variant="secondary"
                icon={ShieldAlert}
                onClick={() => validation.mutate(draft)}
                disabled={validation.isPending}
              >
                {t("rules.validate")}
              </Button>
              <Button icon={Save} onClick={() => save.mutate(draft)} disabled={save.isPending}>
                {t("common.save")}
              </Button>
            </>
          }
        >
          <div className="space-y-3">
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label={t("rules.name")} required>
                <Input
                  value={String(draft.name || "")}
                  onChange={(event) => setDraft((prev) => ({ ...prev, name: event.target.value }))}
                />
              </Field>
              <Field label={t("rules.titleField")}>
                <Input
                  value={String(draft.title || "")}
                  onChange={(event) => setDraft((prev) => ({ ...prev, title: event.target.value }))}
                />
              </Field>
            </div>
            <Field label={t("common.description")}>
              <Textarea
                rows={2}
                value={String(draft.description || "")}
                onChange={(event) => setDraft((prev) => ({ ...prev, description: event.target.value }))}
              />
            </Field>
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label={t("rules.level")}>
                <Select
                  value={String(draft.level || "medium")}
                  onChange={(event) => setDraft((prev) => ({ ...prev, level: event.target.value }))}
                >
                  <option value="informational">informational</option>
                  <option value="low">low</option>
                  <option value="medium">medium</option>
                  <option value="high">high</option>
                  <option value="critical">critical</option>
                </Select>
              </Field>
              <Field label={t("rules.status")}>
                <Select
                  value={String(draft.status || "experimental")}
                  onChange={(event) => setDraft((prev) => ({ ...prev, status: event.target.value }))}
                >
                  <option value="experimental">experimental</option>
                  <option value="test">test</option>
                  <option value="stable">stable</option>
                  <option value="deprecated">deprecated</option>
                </Select>
              </Field>
            </div>
            <Field label={t("rules.logsource")} hint={t("rules.logsourceHint")}>
              <Textarea
                rows={3}
                className="font-mono text-[11px]"
                value={JSON.stringify(draft.logsource || {}, null, 2)}
                onChange={(event) =>
                  setDraft((prev) => ({ ...prev, logsource: parseJson(event.target.value, {}) }))
                }
              />
            </Field>
            <Field label={t("rules.detection")} hint={t("rules.detectionHint")}>
              <Textarea
                rows={6}
                className="font-mono text-[11px]"
                value={JSON.stringify(draft.detection || {}, null, 2)}
                onChange={(event) =>
                  setDraft((prev) => ({ ...prev, detection: parseJson(event.target.value, {}) }))
                }
              />
            </Field>
            {validation.data ? (
              <div className="rounded-xl border border-line/60 bg-panel2/40 p-3">
                <p className="text-[10px] font-medium text-ink">
                  {validation.data.valid ? t("rules.valid") : t("rules.invalid")}
                </p>
                <ul className="mt-1.5 space-y-1">
                  {validation.data.errors.map((item) => (
                    <li key={item} className="text-[10px] text-rose-300">
                      Â· {item}
                    </li>
                  ))}
                  {validation.data.warnings.map((item) => (
                    <li key={item} className="text-[10px] text-amber-300">
                      Â· {item}
                    </li>
                  ))}
                  {validation.data.detects.map((item) => (
                    <li key={item} className="text-[10px] text-muted">
                      Â· {item}
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
          </div>
        </Modal>
      </div>
    </ProjectGate>
  );
}


