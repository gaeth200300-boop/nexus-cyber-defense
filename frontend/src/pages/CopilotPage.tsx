import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import {
  AlertTriangle,
  ArrowRight,
  ArrowUpRight,
  BrainCircuit,
  CheckCircle2,
  Cpu,
  Eraser,
  Fingerprint,
  Gauge,
  Info,
  Layers3,
  Loader2,
  MessageSquare,
  Send,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Target,
  Zap
} from "lucide-react";
import { apiFetch, errorMessage } from "../lib/api";
import { cn, fromNow } from "../lib/utils";
import { useProject } from "../context/ProjectContext";
import { useToast } from "../context/ToastContext";
import { useDocumentTitle } from "../hooks";
import type { Lang, Paged } from "../types";
import { ProjectGate } from "../components/common";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  InlineAlert,
  KeyValue,
  Modal,
  PageHeader,
  Progress,
  SeverityBadge,
  Skeleton,
  StatusBadge,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger
} from "../components/ui";

interface CopilotStatus {
  copilot: {
    configured: boolean;
    provider: string;
    model: string;
    detail: string;
    budget: {
      monthly_tokens: number;
      used_tokens: number;
      remaining_tokens: number;
      requests: number;
      month: string;
    };
    setup_hint: string;
  };
  project_facts: ProjectFacts;
  modes: {
    deterministic: { available: boolean; description: string };
    ai: { available: boolean; description: string };
  };
}

interface ProjectFacts {
  project: { id: string; name: string; kind: string };
  findings_by_severity: Record<string, number>;
  findings_by_status: Record<string, number>;
  total_findings: number;
  critical_high: number;
  assets: number;
  services: number;
  scans: { kind: string; status: string; count: number }[];
  open_alerts: number;
  findings_linked_to_kev: number;
  generated_at: string;
  top_findings: PriorityItem[];
}

interface PriorityItem {
  id: string;
  title: string;
  severity: string;
  confidence: string;
  status: string;
  target: string;
  category: string;
  score: number;
  reasons: string[];
  kev: boolean;
}

interface Citation {
  type: string;
  id: string;
  label: string;
}

interface Analysis {
  engine: string;
  ai_used: boolean;
  status?: string;
  lang: string;
  summary: string;
  plain_language: string;
  technical_detail: string;
  impact: string;
  remediation_steps: string[];
  validation_steps: string[];
  residual_uncertainty: string[];
  priority_score: number;
  priority_reasons: string[];
  citations: Citation[];
  note?: string;
  category_label?: string;
}

interface ChatTurn {
  role: "user" | "assistant";
  content: string;
  status?: string;
  citations?: Citation[];
  engine?: string;
}

interface ChatResponse {
  status: string;
  reply: string;
  engine?: string;
  citations?: Citation[];
  setup?: string;
}

interface PrioritizeResponse {
  status: string;
  ranked: PriorityItem[];
  method: string;
  triage_note?: string;
  note?: string;
  ai_used: boolean;
  engine: string;
}

interface SummarizeResponse {
  status: string;
  facts: ProjectFacts;
  summary?: string;
  note?: string;
  ai_used: boolean;
  engine: string;
  citations: Citation[];
}

const severityTone: Record<string, string> = {
  critical: "border-rose-400/20 bg-rose-400/[0.05]",
  high: "border-orange-400/20 bg-orange-400/[0.05]",
  medium: "border-amber-400/20 bg-amber-400/[0.05]",
  low: "border-sky-400/20 bg-sky-400/[0.05]",
  info: "border-line bg-panel2/30"
};

export default function CopilotPage() {
  return (
    <ProjectGate>
      <CopilotContent />
    </ProjectGate>
  );
}

function CopilotContent() {
  const { t, i18n } = useTranslation();
  const lang = (i18n.language.startsWith("ar") ? "ar" : "en") as Lang;
  const { selectedProject } = useProject();
  const toast = useToast();
  const navigate = useNavigate();
  const projectId = selectedProject?.id || "";
  useDocumentTitle(t("copilot.title"));

  const [tab, setTab] = useState("chat");
  const [input, setInput] = useState("");
  const [messages, setMessages] = useState<ChatTurn[]>([]);
  const [explained, setExplained] = useState<{ finding: PriorityItem; analysis: Analysis } | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  const status = useQuery({
    queryKey: ["copilot-status", projectId],
    queryFn: () => apiFetch<CopilotStatus>(`/projects/${projectId}/copilot/status`),
    enabled: Boolean(projectId)
  });

  const priorities = useQuery({
    queryKey: ["copilot-priorities", projectId],
    queryFn: () => apiFetch<Paged<PriorityItem>>(`/projects/${projectId}/copilot/priorities`, { query: { limit: 50 } }),
    enabled: Boolean(projectId)
  });

  const chat = useMutation({
    mutationFn: (message: string) =>
      apiFetch<ChatResponse>(`/projects/${projectId}/copilot/chat`, {
        method: "POST",
        body: {
          message,
          lang,
          history: messages.slice(-6).map((turn) => ({ role: turn.role, content: turn.content }))
        }
      }),
    onSuccess: (result) => {
      setMessages((current) => [
        ...current,
        {
          role: "assistant",
          content: result.reply || t("copilot.error"),
          status: result.status,
          citations: result.citations,
          engine: result.engine
        }
      ]);
    },
    onError: (error) => {
      setMessages((current) => [
        ...current,
        { role: "assistant", content: `${t("copilot.error")} ${errorMessage(error)}`, status: "error" }
      ]);
    }
  });

  const explain = useMutation({
    mutationFn: (finding: PriorityItem) =>
      apiFetch<{ finding_id: string; analysis: Analysis }>(`/projects/${projectId}/copilot/explain`, {
        method: "POST",
        body: { finding_id: finding.id, lang }
      }),
    onSuccess: (result, finding) => setExplained({ finding, analysis: result.analysis }),
    onError: (error) => toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" })
  });

  const summarize = useMutation({
    mutationFn: () =>
      apiFetch<SummarizeResponse>(`/projects/${projectId}/copilot/summarize`, {
        method: "POST",
        body: { lang }
      }),
    onSuccess: () => setTab("summary"),
    onError: (error) => toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" })
  });

  const triage = useMutation({
    mutationFn: () =>
      apiFetch<PrioritizeResponse>(`/projects/${projectId}/copilot/prioritize`, {
        method: "POST",
        body: { lang, limit: 15 }
      }),
    onError: (error) => toast.toast({ title: t("toasts.failed"), description: errorMessage(error), variant: "error" })
  });

  const configured = Boolean(status.data?.copilot.configured);
  const facts = status.data?.project_facts;
  const budget = status.data?.copilot.budget;
  const priorityRows = priorities.data?.items || facts?.top_findings || [];

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [messages, chat.isPending]);

  const send = () => {
    const message = input.trim();
    if (!message || chat.isPending || !configured) return;
    setMessages((current) => [...current, { role: "user", content: message }]);
    setInput("");
    chat.mutate(message);
  };

  const factsSeverity = useMemo(
    () =>
      ["critical", "high", "medium", "low", "info"].map((severity) => ({
        severity,
        value: facts?.findings_by_severity[severity] || 0
      })),
    [facts?.findings_by_severity]
  );

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow={t("nav.copilot")}
        icon={BrainCircuit}
        title={t("copilot.title")}
        subtitle={t("copilot.subtitle")}
        actions={
          <>
            <Button
              variant="secondary"
              icon={Sparkles}
              loading={summarize.isPending}
              onClick={() => summarize.mutate()}
              disabled={!facts?.total_findings && !facts?.assets}
            >
              {t("copilot.summarizeProject")}
            </Button>
            <Button icon={Gauge} onClick={() => setTab("priorities")}>
              {t("copilot.topFindings")}
            </Button>
          </>
        }
      />

      <div className={cn("rounded-xl border p-3", configured ? "border-emerald-400/20 bg-emerald-400/[0.04]" : "border-amber-400/20 bg-amber-400/[0.04]")}>
        <div className="flex flex-wrap items-center gap-2">
          {configured ? <Zap className="h-4 w-4 text-emerald-300" /> : <Info className="h-4 w-4 text-amber-300" />}
          <span className={cn("text-[11px] font-semibold", configured ? "text-emerald-200" : "text-amber-200")}>
            {configured ? `${t("copilot.deterministic")} + ${status.data?.copilot.provider}:${status.data?.copilot.model}` : t("copilot.notConfigured")}
          </span>
          <span className="text-[10px] text-muted">{status.data?.copilot.detail || t("copilot.grounded")}</span>
          {!configured ? (
            <span className="ms-auto font-mono text-[8px] text-faint">{status.data?.copilot.setup_hint}</span>
          ) : null}
        </div>
      </div>

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="chat" icon={MessageSquare}>
            {t("copilot.title")}
          </TabsTrigger>
          <TabsTrigger value="priorities" icon={Target} count={priorityRows.length}>
            {t("copilot.topFindings")}
          </TabsTrigger>
          <TabsTrigger value="summary" icon={Layers3}>
            {t("copilot.summarizeProject")}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="chat" className="mt-4">
          <div className="grid gap-4 xl:grid-cols-12">
            <Card className="flex min-h-[620px] flex-col overflow-hidden xl:col-span-8">
              <div className="flex items-center justify-between border-b border-line/60 px-4 py-3">
                <div className="flex items-center gap-2">
                  <span className="grid h-8 w-8 place-items-center rounded-lg border border-accent/20 bg-accent/[0.07] text-accent">
                    <BrainCircuit className="h-4 w-4" />
                  </span>
                  <div>
                    <h3 className="text-xs font-semibold text-ink">{t("copilot.title")}</h3>
                    <p className="mt-0.5 text-[9px] text-faint">{t("copilot.scope")}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {messages.length ? (
                    <Button size="sm" variant="ghost" icon={Eraser} onClick={() => setMessages([])}>
                      {t("copilot.clear")}
                    </Button>
                  ) : null}
                  <Badge tone={configured ? "success" : "warning"}>{configured ? t("common.live") : t("copilot.deterministic")}</Badge>
                </div>
              </div>

              <div ref={scrollRef} className="flex-1 space-y-4 overflow-y-auto p-4">
                {status.isLoading ? (
                  <div className="space-y-3">
                    <Skeleton className="h-20 rounded-xl" />
                    <Skeleton className="h-14 w-2/3 rounded-xl" />
                  </div>
                ) : messages.length === 0 ? (
                  <div className="flex h-full flex-col items-center justify-center py-10 text-center">
                    <div className="relative grid h-16 w-16 place-items-center">
                      <div className="absolute inset-0 rounded-2xl bg-accent/15 blur-xl" />
                      <BrainCircuit className="relative h-8 w-8 text-accent" />
                    </div>
                    <h3 className="mt-4 font-display text-lg font-semibold text-ink">{t("copilot.greeting")}</h3>
                    <p className="mt-1 max-w-md text-[10px] leading-relaxed text-muted">{t("copilot.greetingBody")}</p>
                    <div className="mt-5 grid w-full max-w-xl gap-2 sm:grid-cols-2">
                      {[t("copilot.suggest1"), t("copilot.suggest2"), t("copilot.suggest3"), t("copilot.suggest4")].map((suggestion) => (
                        <button
                          key={suggestion}
                          type="button"
                          onClick={() => setInput(suggestion)}
                          className="rounded-xl border border-line/60 bg-panel2/30 px-3 py-2.5 text-start text-[10px] text-muted transition hover:border-accent/25 hover:text-ink"
                        >
                          {suggestion}
                        </button>
                      ))}
                    </div>
                    {!configured ? (
                      <div className="mt-5 max-w-xl">
                        <InlineAlert tone="warning" title={t("copilot.notConfigured")}>
                          {t("copilot.notConfiguredBody")}
                        </InlineAlert>
                      </div>
                    ) : null}
                  </div>
                ) : (
                  messages.map((turn, index) => (
                    <div key={index} className={cn("flex", turn.role === "user" ? "justify-end" : "justify-start")}>
                      <div className={cn("max-w-[86%] rounded-2xl border px-3.5 py-3", turn.role === "user" ? "border-accent/20 bg-accent/[0.08]" : "border-line/60 bg-panel2/40")}>
                        <div className="flex items-center gap-2">
                          {turn.role === "assistant" ? <BrainCircuit className="h-3 w-3 text-accent" /> : <Fingerprint className="h-3 w-3 text-accent2" />}
                          <span className="text-[9px] font-semibold uppercase tracking-wider text-faint">{turn.role === "user" ? "You" : "NEXUS"}</span>
                          {turn.status && turn.status !== "ok" ? <Badge tone="warning">{turn.status.replaceAll("_", " ")}</Badge> : null}
                          {turn.engine ? <span className="text-[8px] text-faint">{turn.engine}</span> : null}
                        </div>
                        <p className="mt-2 whitespace-pre-wrap text-[11px] leading-relaxed text-ink">{turn.content}</p>
                        {turn.citations?.length ? (
                          <div className="mt-2.5 flex flex-wrap gap-1.5 border-t border-line/40 pt-2">
                            <span className="text-[8px] uppercase tracking-wider text-faint">{t("copilot.sources")}</span>
                            {turn.citations.slice(0, 5).map((citation) => (
                              <button
                                key={`${citation.type}-${citation.id}`}
                                type="button"
                                onClick={() => citation.type === "finding" && navigate(`/findings?finding=${citation.id}`)}
                                className="max-w-[190px] truncate rounded border border-line bg-panel px-1.5 py-0.5 text-[8px] text-accent2 hover:underline"
                              >
                                {citation.type}: {citation.label}
                              </button>
                            ))}
                          </div>
                        ) : null}
                      </div>
                    </div>
                  ))
                )}
                {chat.isPending ? (
                  <div className="flex justify-start">
                    <div className="flex items-center gap-2 rounded-2xl border border-line/60 bg-panel2/40 px-3.5 py-3 text-[10px] text-muted">
                      <Loader2 className="h-3.5 w-3.5 animate-spin text-accent" /> {t("copilot.sending")}
                    </div>
                  </div>
                ) : null}
              </div>

              <div className="border-t border-line/60 p-3">
                <div className="flex items-end gap-2">
                  <textarea
                    value={input}
                    onChange={(event) => setInput(event.target.value)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter" && !event.shiftKey) {
                        event.preventDefault();
                        send();
                      }
                    }}
                    rows={2}
                    maxLength={2000}
                    disabled={!configured || chat.isPending}
                    placeholder={configured ? t("copilot.placeholder") : t("copilot.notConfiguredBody")}
                    className="min-h-[48px] flex-1 resize-none rounded-xl border border-line bg-panel/60 px-3 py-2.5 text-[11px] text-ink placeholder:text-faint focus-ring disabled:cursor-not-allowed disabled:opacity-60"
                  />
                  <Button icon={Send} disabled={!configured || !input.trim() || chat.isPending} onClick={send} className="h-[48px]">
                    {t("copilot.send")}
                  </Button>
                </div>
                <div className="mt-2 flex flex-wrap items-center gap-2 text-[8px] text-faint">
                  <ShieldCheck className="h-3 w-3 text-emerald-300" />
                  {t("copilot.disclaimer")}
                  <span className="ms-auto">{t("copilot.grounded")}</span>
                </div>
              </div>
            </Card>

            <aside className="space-y-4 xl:col-span-4">
              <Card className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-xs font-semibold text-ink">{t("copilot.quickActions")}</h3>
                    <p className="mt-0.5 text-[10px] text-muted">{t("copilot.grounded")}</p>
                  </div>
                  <Sparkles className="h-4 w-4 text-accent2" />
                </div>
                <div className="mt-3 space-y-2">
                  <button type="button" onClick={() => summarize.mutate()} className="flex w-full items-center gap-2 rounded-lg border border-line/50 bg-panel2/30 px-3 py-2.5 text-start text-[10px] text-muted hover:border-accent/25 hover:text-ink">
                    <Layers3 className="h-3.5 w-3.5 text-accent" /> {t("copilot.summarizeProject")} <ArrowRight className="ms-auto h-3 w-3 rtl:rotate-180" />
                  </button>
                  <button type="button" onClick={() => setTab("priorities")} className="flex w-full items-center gap-2 rounded-lg border border-line/50 bg-panel2/30 px-3 py-2.5 text-start text-[10px] text-muted hover:border-accent/25 hover:text-ink">
                    <Target className="h-3.5 w-3.5 text-accent2" /> {t("copilot.topFindings")} <ArrowRight className="ms-auto h-3 w-3 rtl:rotate-180" />
                  </button>
                  <button type="button" onClick={() => navigate("/soc")} className="flex w-full items-center gap-2 rounded-lg border border-line/50 bg-panel2/30 px-3 py-2.5 text-start text-[10px] text-muted hover:border-accent/25 hover:text-ink">
                    <ShieldAlert className="h-3.5 w-3.5 text-rose-300" /> {t("nav.soc")} <ArrowRight className="ms-auto h-3 w-3 rtl:rotate-180" />
                  </button>
                </div>
              </Card>

              <Card className="p-4">
                <h3 className="text-xs font-semibold text-ink">{t("copilot.grounded")}</h3>
                <div className="mt-3 grid grid-cols-2 gap-2">
                  {factsSeverity.map((item) => (
                    <div key={item.severity} className={cn("rounded-lg border p-2.5", severityTone[item.severity])}>
                      <p className="text-[8px] uppercase tracking-wider text-faint">{t(`severity.${item.severity}`)}</p>
                      <p className="mt-1 font-display text-lg font-semibold tabular-nums text-ink">{item.value}</p>
                    </div>
                  ))}
                </div>
                <dl className="mt-3 space-y-2">
                  <KeyValue label={t("nav.assets")} value={String(facts?.assets ?? "—")} />
                  <KeyValue label={t("dashboard.services")} value={String(facts?.services ?? "—")} />
                  <KeyValue label={t("soc.openAlerts")} value={String(facts?.open_alerts ?? "—")} />
                  <KeyValue label={t("findings.kev")} value={String(facts?.findings_linked_to_kev ?? "—")} />
                </dl>
              </Card>

              <Card className="p-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-semibold text-ink">{t("copilot.deterministic")}</h3>
                  <Cpu className="h-4 w-4 text-accent" />
                </div>
                {budget ? (
                  <div className="mt-3">
                    <div className="flex items-center justify-between text-[9px] text-faint">
                      <span>{t("copilot.tokens")}</span>
                      <span className="font-mono">
                        {budget.monthly_tokens > 0 ? `${budget.used_tokens} / ${budget.monthly_tokens}` : `${budget.used_tokens} / ∞`}
                      </span>
                    </div>
                    <Progress
                      value={budget.monthly_tokens > 0 ? Math.min(100, (budget.used_tokens / budget.monthly_tokens) * 100) : 0}
                      className="mt-1.5 h-1.5"
                      tone={(budget.monthly_tokens > 0 && budget.used_tokens / budget.monthly_tokens > 0.85) ? "warning" : "accent"}
                    />
                    <p className="mt-2 text-[8px] leading-relaxed text-faint">
                      {t("copilot.grounded")} · {status.data?.copilot.provider || "—"} · {budget.requests} {t("copilot.requests")}
                    </p>
                  </div>
                ) : (
                  <Skeleton className="mt-3 h-14 rounded-lg" />
                )}
              </Card>
            </aside>
          </div>
        </TabsContent>

        <TabsContent value="priorities" className="mt-4 space-y-4">
          <Card className="overflow-hidden">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line/60 p-4">
              <div>
                <h3 className="text-xs font-semibold text-ink">{t("copilot.topFindings")}</h3>
                <p className="mt-0.5 text-[10px] text-muted">{t("copilot.grounded")} · deterministic score</p>
              </div>
              <Button
                size="sm"
                variant="secondary"
                icon={Sparkles}
                loading={triage.isPending}
                onClick={() => triage.mutate()}
              >
                {t("copilot.triageNote")}
              </Button>
            </div>
            {triage.data ? (
              <div className="border-b border-line/60 bg-panel2/20 p-4">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone={triage.data.ai_used ? "success" : "warning"}>
                    {triage.data.ai_used ? t("copilot.aiEnhanced") : t("copilot.deterministic")}
                  </Badge>
                  <span className="text-[9px] text-faint">{triage.data.method}</span>
                </div>
                <p className="mt-2 whitespace-pre-wrap text-[10px] leading-relaxed text-muted">
                  {triage.data.triage_note || triage.data.note || t("copilot.notConfiguredBody")}
                </p>
              </div>
            ) : null}
            {priorities.isLoading ? (
              <div className="space-y-2 p-4">{[0, 1, 2, 3].map((key) => <Skeleton key={key} className="h-16 rounded-lg" />)}</div>
            ) : priorities.isError ? (
              <EmptyState
                icon={AlertTriangle}
                title={t("common.errorTitle")}
                description={priorities.error instanceof Error ? priorities.error.message : t("common.errorDescription")}
              />
            ) : priorityRows.length ? (
              <div className="divide-y divide-line/50">
                {priorityRows.map((finding, index) => (
                  <div key={finding.id} className={cn("flex flex-wrap items-center gap-3 px-4 py-3.5", severityTone[finding.severity])}>
                    <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-line/60 bg-panel/50 font-display text-xs font-semibold text-muted">
                      {index + 1}
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <button type="button" onClick={() => navigate(`/findings?finding=${finding.id}`)} className="truncate text-[11px] font-medium text-ink hover:text-accent2">
                          {finding.title}
                        </button>
                        <SeverityBadge severity={finding.severity} />
                        {finding.kev ? <Badge tone="danger">{t("findings.kev")}</Badge> : null}
                      </div>
                      <p className="mt-0.5 truncate font-mono text-[9px] text-faint">{finding.target || "—"} · {finding.category}</p>
                      <p className="mt-1 line-clamp-1 text-[8px] text-faint">{finding.reasons.join(" · ")}</p>
                    </div>
                    <div className="w-28">
                      <div className="flex items-center justify-between text-[8px] text-faint">
                        <span>{t("copilot.priority")}</span>
                        <span className="font-mono text-ink">{finding.score}</span>
                      </div>
                      <Progress value={finding.score} className="mt-1 h-1.5" tone={finding.score > 75 ? "danger" : finding.score > 45 ? "warning" : "accent"} />
                    </div>
                    <Button
                      size="sm"
                      variant="secondary"
                      icon={BrainCircuit}
                      loading={explain.isPending && explain.variables?.id === finding.id}
                      onClick={() => explain.mutate(finding)}
                    >
                      {t("copilot.explain")}
                    </Button>
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState
                icon={ShieldCheck}
                title={t("copilot.noPriorities")}
                description={t("copilot.empty")}
                action={
                  <Button variant="secondary" onClick={() => navigate("/scans")}>
                    {t("nav.scans")}
                  </Button>
                }
              />
            )}
          </Card>
        </TabsContent>

        <TabsContent value="summary" className="mt-4 space-y-4">
          <div className="grid gap-4 xl:grid-cols-12">
            <Card className="overflow-hidden xl:col-span-8">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line/60 p-4">
                <div>
                  <h3 className="text-xs font-semibold text-ink">{t("copilot.summarizeProject")}</h3>
                  <p className="mt-0.5 text-[10px] text-muted">{t("copilot.grounded")}</p>
                </div>
                <Button
                  size="sm"
                  icon={Sparkles}
                  loading={summarize.isPending}
                  onClick={() => summarize.mutate()}
                  disabled={!facts?.total_findings && !facts?.assets}
                >
                  {t("copilot.generateSummary")}
                </Button>
              </div>
              <div className="p-4">
                {summarize.data?.summary ? (
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge tone={summarize.data.ai_used ? "success" : "warning"}>
                        {summarize.data.ai_used ? t("copilot.aiEnhanced") : t("copilot.deterministic")}
                      </Badge>
                      <span className="text-[9px] text-faint">{summarize.data.engine}</span>
                    </div>
                    <p className="mt-3 whitespace-pre-wrap text-[11px] leading-relaxed text-ink">{summarize.data.summary}</p>
                  </div>
                ) : summarize.data?.note ? (
                  <InlineAlert tone="info" title={t("copilot.deterministic")}>{summarize.data.note}</InlineAlert>
                ) : null}
                {status.isLoading ? (
                  <div className="mt-4 space-y-2"><Skeleton className="h-20 rounded-lg" /><Skeleton className="h-20 rounded-lg" /></div>
                ) : (
                  <div className={cn(summarize.data?.summary || summarize.data?.note ? "mt-4 border-t border-line/50 pt-4" : "")}>
                    <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                      {[
                        { label: t("copilot.totalFindings"), value: facts?.total_findings },
                        { label: t("copilot.criticalHigh"), value: facts?.critical_high },
                        { label: t("nav.assets"), value: facts?.assets },
                        { label: t("soc.openAlerts"), value: facts?.open_alerts }
                      ].map((item) => (
                        <div key={item.label} className="rounded-xl border border-line/60 bg-panel2/30 p-3">
                          <p className="text-[8px] uppercase tracking-wider text-faint">{item.label}</p>
                          <p className="mt-1 font-display text-xl font-semibold tabular-nums text-ink">{item.value ?? "—"}</p>
                        </div>
                      ))}
                    </div>
                    <div className="mt-4 grid gap-3 sm:grid-cols-2">
                      <div className="rounded-xl border border-line/60 bg-panel2/30 p-3">
                        <h4 className="text-[10px] font-semibold text-ink">{t("findings.title")}</h4>
                        <dl className="mt-2 space-y-2">
                          {factsSeverity.map((item) => (
                            <KeyValue key={item.severity} label={t(`severity.${item.severity}`)} value={String(item.value)} />
                          ))}
                        </dl>
                      </div>
                      <div className="rounded-xl border border-line/60 bg-panel2/30 p-3">
                        <h4 className="text-[10px] font-semibold text-ink">{t("copilot.coverage")}</h4>
                        <dl className="mt-2 space-y-2">
                          <KeyValue label={t("dashboard.services")} value={String(facts?.services ?? "—")} />
                          <KeyValue label={t("findings.kev")} value={String(facts?.findings_linked_to_kev ?? "—")} />
                          <KeyValue label={t("nav.scans")} value={String(facts?.scans.reduce((sum, item) => sum + item.count, 0) ?? "—")} />
                          <KeyValue label={t("common.updated")} value={facts?.generated_at ? fromNow(facts.generated_at, lang) : "—"} />
                        </dl>
                      </div>
                    </div>
                    <div className="mt-4">
                      <h4 className="text-[10px] font-semibold text-ink">{t("copilot.topFindings")}</h4>
                      {facts?.top_findings.length ? (
                        <div className="mt-2 space-y-1.5">
                          {facts.top_findings.slice(0, 5).map((finding) => (
                            <button
                              key={finding.id}
                              type="button"
                              onClick={() => navigate(`/findings?finding=${finding.id}`)}
                              className="flex w-full items-center gap-2 rounded-lg border border-line/50 bg-panel2/30 px-2.5 py-2 text-start text-[10px] hover:border-accent/20"
                            >
                              <SeverityBadge severity={finding.severity} />
                              <span className="min-w-0 flex-1 truncate text-ink">{finding.title}</span>
                              <span className="font-mono text-[9px] text-faint">{finding.score}</span>
                              <ArrowUpRight className="h-3 w-3 text-faint" />
                            </button>
                          ))}
                        </div>
                      ) : (
                        <p className="mt-2 text-[10px] text-faint">{t("copilot.noPriorities")}</p>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </Card>
            <div className="space-y-4 xl:col-span-4">
              <Card className="p-4">
                <h3 className="text-xs font-semibold text-ink">{t("copilot.methodTitle")}</h3>
                <div className="mt-3 space-y-3">
                  {[
                    { icon: CheckCircle2, title: t("copilot.factFirst"), body: t("copilot.factFirstBody"), tone: "text-emerald-300" },
                    { icon: ShieldCheck, title: t("copilot.noFabrication"), body: t("copilot.noFabricationBody"), tone: "text-accent2" },
                    { icon: Info, title: t("copilot.aiAdvisory"), body: t("copilot.aiAdvisoryBody"), tone: "text-amber-300" }
                  ].map((item) => (
                    <div key={item.title} className="flex items-start gap-2.5">
                      <item.icon className={cn("mt-0.5 h-4 w-4 shrink-0", item.tone)} />
                      <div>
                        <p className="text-[10px] font-medium text-ink">{item.title}</p>
                        <p className="mt-0.5 text-[9px] leading-relaxed text-muted">{item.body}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </Card>
              <Card className="p-4">
                <h3 className="text-xs font-semibold text-ink">{t("copilot.model")}</h3>
                <dl className="mt-3 space-y-2">
                  <KeyValue label={t("common.engine")} value={status.data?.copilot.provider || "deterministic"} />
                  <KeyValue label="Model" value={status.data?.copilot.model || "—"} mono />
                  <KeyValue label={t("common.status")} value={<Badge tone={configured ? "success" : "warning"}>{configured ? t("common.enabled") : t("copilot.deterministic")}</Badge>} />
                  <KeyValue label="Budget" value={budget ? (budget.monthly_tokens > 0 ? `${budget.remaining_tokens}` : t("copilot.unlimited")) : "—"} />
                </dl>
              </Card>
            </div>
          </div>
        </TabsContent>
      </Tabs>

      <AnalysisModal
        open={Boolean(explained)}
        onClose={() => setExplained(null)}
        finding={explained?.finding}
        analysis={explained?.analysis}
        lang={lang}
      />
    </div>
  );
}

function AnalysisModal({
  open,
  onClose,
  finding,
  analysis,
  lang
}: {
  open: boolean;
  onClose: () => void;
  finding?: PriorityItem;
  analysis?: Analysis;
  lang: Lang;
}) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  return (
    <Modal
      open={open}
      onOpenChange={(next) => !next && onClose()}
      title={finding?.title || t("copilot.explain")}
      description={
        finding ? (
          <span className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            <span className="font-mono text-[9px] text-faint">{finding.target || "—"}</span>
            <Badge tone={analysis?.ai_used ? "success" : "info"}>{analysis?.ai_used ? t("copilot.aiEnhanced") : t("copilot.deterministic")}</Badge>
            {finding.kev ? <Badge tone="danger">{t("findings.kev")}</Badge> : null}
          </span>
        ) : undefined
      }
      icon={BrainCircuit}
      size="full"
      footer={
        <>
          <span className="text-[9px] text-faint">{t("copilot.disclaimer")}</span>
          <Button variant="secondary" onClick={() => { onClose(); if (finding) navigate(`/findings?finding=${finding.id}`); }} className="ms-auto">
            {t("findings.openFinding")}
          </Button>
          <Button variant="secondary" onClick={onClose}>{t("common.close")}</Button>
        </>
      }
    >
      {!analysis || !finding ? (
        <Skeleton className="h-64 rounded-xl" />
      ) : (
        <div className="space-y-4">
          {analysis.note ? <InlineAlert tone="info" title={t("copilot.deterministic")}>{analysis.note}</InlineAlert> : null}
          <div className="grid gap-4 xl:grid-cols-12">
            <div className="space-y-4 xl:col-span-8">
              <div className="rounded-xl border border-line/60 bg-panel2/30 p-4">
                <h4 className="text-xs font-semibold text-ink">{t("copilot.summary")}</h4>
                <p className="mt-2 text-[11px] font-medium leading-relaxed text-ink">{analysis.summary}</p>
                <p className="mt-3 whitespace-pre-wrap text-[10px] leading-relaxed text-muted">{analysis.plain_language}</p>
              </div>
              <div className="grid gap-4 md:grid-cols-2">
                <div className="rounded-xl border border-line/60 bg-panel2/30 p-4">
                  <h4 className="flex items-center gap-1.5 text-xs font-semibold text-ink"><CheckCircle2 className="h-3.5 w-3.5 text-emerald-300" /> {t("copilot.validation")}</h4>
                  <ol className="mt-2 space-y-2">
                    {analysis.validation_steps.map((step, index) => (
                      <li key={index} className="flex gap-2 text-[10px] leading-relaxed text-muted">
                        <span className="font-mono text-[9px] text-faint">{index + 1}.</span> {step}
                      </li>
                    ))}
                  </ol>
                </div>
                <div className="rounded-xl border border-line/60 bg-panel2/30 p-4">
                  <h4 className="flex items-center gap-1.5 text-xs font-semibold text-ink"><ShieldCheck className="h-3.5 w-3.5 text-accent2" /> {t("findings.remediation")}</h4>
                  <ol className="mt-2 space-y-2">
                    {analysis.remediation_steps.length ? analysis.remediation_steps.map((step, index) => (
                      <li key={index} className="flex gap-2 text-[10px] leading-relaxed text-muted">
                        <span className="font-mono text-[9px] text-faint">{index + 1}.</span> {step}
                      </li>
                    )) : <li className="text-[10px] text-faint">{t("common.none")}</li>}
                  </ol>
                </div>
              </div>
              <div className="rounded-xl border border-amber-400/20 bg-amber-400/[0.04] p-4">
                <h4 className="flex items-center gap-1.5 text-xs font-semibold text-amber-200"><AlertTriangle className="h-3.5 w-3.5" /> {t("copilot.uncertainty")}</h4>
                <ul className="mt-2 space-y-1.5">
                  {analysis.residual_uncertainty.map((item, index) => (
                    <li key={index} className="text-[10px] leading-relaxed text-muted">• {item}</li>
                  ))}
                </ul>
              </div>
            </div>
            <div className="space-y-4 xl:col-span-4">
              <div className="rounded-xl border border-line/60 bg-panel2/30 p-4">
                <h4 className="text-xs font-semibold text-ink">{t("copilot.priority")}</h4>
                <p className="mt-2 font-display text-3xl font-semibold tabular-nums text-ink">{analysis.priority_score}</p>
                <Progress value={analysis.priority_score} className="mt-2 h-2" tone={analysis.priority_score > 75 ? "danger" : analysis.priority_score > 45 ? "warning" : "accent"} />
                <ul className="mt-3 space-y-1">
                  {analysis.priority_reasons.map((reason) => (
                    <li key={reason} className="text-[9px] text-faint">• {reason}</li>
                  ))}
                </ul>
              </div>
              <div className="rounded-xl border border-line/60 bg-panel2/30 p-4">
                <h4 className="text-xs font-semibold text-ink">{t("copilot.technical")}</h4>
                <p className="mt-2 whitespace-pre-wrap text-[9px] leading-relaxed text-muted">{analysis.technical_detail || "—"}</p>
              </div>
              <div className="rounded-xl border border-line/60 bg-panel2/30 p-4">
                <h4 className="text-xs font-semibold text-ink">{t("copilot.impact")}</h4>
                <p className="mt-2 whitespace-pre-wrap text-[9px] leading-relaxed text-muted">{analysis.impact || "—"}</p>
              </div>
              <div className="rounded-xl border border-line/60 bg-panel2/30 p-4">
                <h4 className="text-xs font-semibold text-ink">{t("copilot.sources")} · {analysis.citations.length}</h4>
                <div className="mt-2 space-y-1.5">
                  {analysis.citations.map((citation) => (
                    <button
                      key={`${citation.type}-${citation.id}`}
                      type="button"
                      onClick={() => citation.type === "finding" && navigate(`/findings?finding=${citation.id}`)}
                      className="block w-full truncate rounded border border-line bg-panel px-2 py-1 text-start text-[9px] text-accent2 hover:underline"
                    >
                      {citation.type}: {citation.label}
                    </button>
                  ))}
                </div>
              </div>
              <p className="text-[8px] text-faint">{t("copilot.engine")}: {analysis.engine} · {finding.category} · {fromNow(factsTimestamp(), lang)}</p>
            </div>
          </div>
        </div>
      )}
    </Modal>
  );
}

function factsTimestamp(): string {
  return new Date().toISOString();
}
