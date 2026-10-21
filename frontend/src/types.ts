export type Lang = "ar" | "en";

export interface Labeled {
  key: string;
  labels: Record<Lang, string>;
}

export interface StatusMeta {
  key: string;
  labels: Record<Lang, string>;
}

export interface SeverityMeta extends StatusMeta {
  color: string;
  rank: number;
}

export interface Meta {
  app: {
    name: string;
    version: string;
    environment: string;
    api_version: string;
  };
  user: {
    id: string;
    email: string;
    full_name: string;
    role: string;
    mfa_enabled: boolean;
    auth_method: string;
    scopes: string[];
  };
  server_time: string;
  locale: {
    default: Lang;
    supported: Lang[];
    directions: Record<Lang, "rtl" | "ltr">;
  };
  features: {
    ai_configured: boolean;
    ai_provider: string;
    zap_configured: boolean;
    nmap_available: boolean;
    inprocess_worker: boolean;
    allow_private_targets_global: boolean;
    active_scanning_enabled: boolean;
  };
  limits: {
    max_upload_mb: number;
    rate_limit_per_minute: number;
    access_token_minutes: number;
    refresh_token_days: number;
    max_concurrent_scans: number;
  };
  constants: {
    severities: SeverityMeta[];
    confidences: StatusMeta[];
    finding_statuses: StatusMeta[];
    finding_categories: Labeled[];
    scan_statuses: StatusMeta[];
    scan_kinds: Labeled[];
    scan_profiles: Labeled[];
    job_types: string[];
    job_statuses: string[];
    project_kinds: Labeled[];
    global_roles: string[];
    project_roles: string[];
    role_labels: Labeled[];
    scope_kinds: string[];
    scope_verification_methods: string[];
    asset_types: string[];
    service_states: string[];
    asset_change_kinds: Labeled[];
    alert_statuses: StatusMeta[];
    incident_statuses: StatusMeta[];
    log_formats: string[];
    lab_levels: Labeled[];
    lab_categories: Labeled[];
    report_kinds: Labeled[];
    evidence_kinds: string[];
  };
  policy: {
    allow_private_targets: boolean;
    active_scanning_enabled: boolean;
    blocked_networks: string[];
    blocked_hosts: string[];
    note: string;
    [key: string]: unknown;
  };
}

export interface User {
  id: string;
  email: string;
  full_name: string;
  role: string;
  is_active: boolean;
  mfa_enabled: boolean;
  last_login_at: string | null;
  created_at: string;
  projects?: { project_id: string; role: string }[];
}

export interface AuthTokens {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in_minutes: number;
  user: User;
}

export interface Project {
  id: string;
  name: string;
  slug: string;
  description: string;
  kind: string;
  allow_private_targets: boolean;
  retention_days: number;
  settings: Record<string, unknown>;
  archived: boolean;
  created_at: string;
  updated_at: string;
  created_by: string | null;
  role?: string;
  counts?: {
    assets: number;
    open_findings: number;
    active_scans: number;
  };
}

export interface DashboardData {
  scope: { projects: number; project_ids: string[] };
  assets: {
    total: number;
    active: number;
    monitored: number;
    by_type: Record<string, number>;
    by_risk: Record<string, number>;
  };
  services: { open: number };
  findings: {
    open_total: number;
    by_severity: Record<string, number>;
    by_status: Record<string, number>;
    verified_open: number;
    new_7d: number;
    resolved_7d: number;
  };
  scans: {
    total: number;
    active: number;
    by_status: Record<string, number>;
    completed_7d: number;
    failed_7d: number;
  };
  soc: {
    alerts_open: number;
    open_by_severity: Record<string, number>;
    incidents_open: number;
    events_24h: number;
    sources: number;
  };
  reports: { total: number; ready: number };
  jobs: Record<string, number>;
  labs: { runs: number; labs_passed: number; total_score: number; achievements: number };
  risk: {
    top_assets: {
      id: string;
      project_id: string;
      project_name: string;
      value: string;
      type: string;
      risk_severity: string;
      risk_score: number;
      state: string;
      last_seen_at: string;
    }[];
  };
  recent: {
    findings: {
      id: string;
      project_id: string;
      project_name: string;
      title: string;
      severity: string;
      status: string;
      confidence: string;
      target: string;
      last_seen_at: string;
    }[];
    scans: {
      id: string;
      project_id: string;
      project_name: string;
      name: string;
      kind: string;
      status: string;
      progress: number;
      created_at: string;
    }[];
    alerts: {
      id: string;
      project_id: string;
      project_name: string;
      title: string;
      severity: string;
      status: string;
      last_seen_at: string;
    }[];
  };
  trend: {
    days: string[];
    findings_created: number[];
    findings_resolved: number[];
  };
  generated_at: string;
}

export interface Scope {
  id: string;
  kind: string;
  value: string;
  include_subdomains: boolean;
  allow_active: boolean;
  authorization_ref: string;
  authorized_by: string;
  verified_method: string;
  verified_at: string | null;
  verification_evidence: string;
  expires_at: string | null;
  is_active: boolean;
  expired: boolean;
  notes: string;
  created_at: string;
  updated_at: string;
}

export interface ProjectMember {
  id: string;
  user_id: string;
  role: string;
  created_at: string;
  email: string;
  name: string;
  global_role: string;
}

export interface Finding {
  id: string;
  project_id: string;
  scan_id: string | null;
  asset_id: string | null;
  service_id: string | null;
  title: string;
  category: string;
  severity: string;
  confidence: string;
  status: string;
  verified: boolean;
  active_check: boolean;
  cwe: string;
  cve: string;
  owasp: string;
  cvss_score: number | null;
  cvss_vector: string;
  target: string;
  location: string;
  description: string;
  impact: string;
  remediation: string;
  references: string[];
  tags: string[];
  detected_by: string;
  engine_version: string;
  occurrence_count: number;
  duplicate_of: string | null;
  triage_note: string;
  assigned_to: string | null;
  first_seen_at: string;
  last_seen_at: string;
  resolved_at: string | null;
  created_at: string;
}

export interface Evidence {
  id: string;
  kind: string;
  label: string;
  request: string;
  response: string;
  headers: Record<string, string>;
  body: string;
  redacted: boolean;
  redactions: unknown[];
  redaction_summary: Record<string, number> | string;
  sha256: string;
  source: string;
  created_at: string;
}

export interface FindingDetail {
  finding: Finding;
  priority: { score: number; reasons: string[]; method: string };
  evidence: Evidence[];
  timeline: {
    id: string;
    ts: string;
    kind: string;
    actor: string;
    from_status: string;
    to_status: string;
    note: string;
  }[];
  intel: {
    cve_id: string;
    match_type: string;
    confidence: string;
    rationale: string;
    cve: {
      description: string;
      cvss_v3_score: number | null;
      cvss_severity: string;
      published_at: string | null;
    } | null;
    kev: boolean;
    kev_ransomware: boolean;
  }[];
  asset: { id: string; value: string; type: string } | null;
  service: { id: string; port: number; protocol: string; name: string } | null;
  scan: { id: string; name: string; kind: string; status: string } | null;
  assignee: { id: string; name: string } | null;
}

export interface Phase {
  key: string;
  en: string;
  ar: string;
  status: "pending" | "running" | "done" | "skipped" | "failed";
  progress: number;
}

export interface Scan {
  id: string;
  project_id: string;
  name: string;
  kind: string;
  profile: string;
  engine: string;
  engine_version: string;
  status: string;
  progress: number;
  phases: Phase[];
  stats: Record<string, unknown>;
  targets: Record<string, unknown>[];
  options: Record<string, unknown>;
  target_count: number;
  authorization_snapshot: Record<string, unknown>;
  requested_by: string | null;
  started_at: string | null;
  finished_at: string | null;
  heartbeat_at: string | null;
  cancel_requested: boolean;
  error: string;
  created_at: string;
  findings?: Record<string, number>;
}

export interface ScanEvent {
  id: number;
  scan_id: string;
  ts: string;
  level: string;
  kind: string;
  phase: string;
  message: string;
  data: Record<string, unknown>;
}

export interface Job {
  id: string;
  project_id: string;
  scan_id: string | null;
  type: string;
  status: string;
  priority: number;
  attempts: number;
  max_attempts: number;
  progress: number;
  phase: string;
  locked_by: string;
  run_after: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  lease_expires_at: string | null;
  last_error: string;
  result: Record<string, unknown>;
}

export interface Asset {
  id: string;
  type: string;
  value: string;
  normalized_value: string;
  state: string;
  source: string;
  scope_id: string | null;
  parent_id: string | null;
  tags: string[];
  risk_severity: string;
  risk_score: number;
  is_monitored: boolean;
  first_seen_at: string;
  last_seen_at: string;
  last_scanned_at: string | null;
  created_at: string;
  meta: Record<string, unknown>;
  services_count?: number;
  open_findings?: number;
}

export interface AssetService {
  id: string;
  asset_id: string;
  port: number;
  protocol: string;
  state: string;
  name: string;
  product: string;
  version: string;
  banner: string;
  tls: Record<string, unknown>;
  source: string;
  first_seen_at: string;
  last_seen_at: string;
  meta: Record<string, unknown>;
  open_findings?: number;
}

export interface AssetDetail {
  asset: Asset;
  parent: Asset | null;
  children: Asset[];
  services: AssetService[];
  findings: {
    id: string;
    title: string;
    severity: string;
    confidence: string;
    status: string;
    category: string;
    target: string;
    last_seen_at: string;
  }[];
  changes: AssetChange[];
}

export interface AssetChange {
  id: string;
  asset_id: string;
  service_id: string | null;
  scan_id: string | null;
  kind: string;
  severity: string;
  summary: string;
  before: Record<string, unknown>;
  after: Record<string, unknown>;
  detected_at: string;
  acknowledged_at: string | null;
}

export interface Alert {
  id: string;
  rule_id: string;
  title: string;
  description: string;
  severity: string;
  status: string;
  event_count: number;
  group_key: string;
  first_seen_at: string;
  last_seen_at: string;
  assignee_id: string | null;
  incident_id: string | null;
  evidence_event_ids: number[];
  meta: Record<string, unknown>;
}

export interface LogEvent {
  id: number;
  source_id: string | null;
  ts: string | null;
  ingested_at: string;
  severity: string;
  event_type: string;
  message: string;
  src_ip: string;
  dst_ip: string;
  src_port: number | null;
  dst_port: number | null;
  method: string;
  url: string;
  status_code: number | null;
  user_agent: string;
  rule_hits: string[];
  raw?: Record<string, unknown>;
  meta?: Record<string, unknown>;
  fingerprint?: string;
}

export interface Incident {
  id: string;
  title: string;
  severity: string;
  status: string;
  summary: string;
  owner_id: string | null;
  opened_at: string;
  closed_at: string | null;
  created_at: string;
}

export interface LogSource {
  id: string;
  name: string;
  kind: string;
  format: string;
  filename: string;
  size_bytes: number;
  sha256: string;
  event_count: number;
  parse_errors: number;
  created_at: string;
  last_event_at: string | null;
}

export interface DetectionRule {
  id: string;
  name: string;
  description: string;
  severity: string;
  enabled: boolean;
  is_builtin: boolean;
  definition: Record<string, unknown>;
  trigger_count: number;
  last_triggered_at: string | null;
  created_at: string;
}

export interface Report {
  id: string;
  kind: string;
  format: string;
  title: string;
  version: number;
  status: string;
  period_from: string | null;
  period_to: string | null;
  scan_ids: string[];
  options: Record<string, unknown>;
  summary: Record<string, unknown>;
  size_bytes: number;
  sha256: string;
  error: string;
  created_at: string;
  completed_at: string | null;
  download_url: string;
}

export interface LabCheck {
  key: string;
  type: string;
  points: number;
  label_en: string;
  label_ar: string;
  question_en?: string;
  question_ar?: string;
  options?: { id: string; en: string; ar: string }[];
  explanation_en?: string;
  explanation_ar?: string;
  spec?: Record<string, unknown>;
}

export interface Lab {
  id: string;
  slug: string;
  title_en: string;
  title_ar: string;
  category: string;
  category_label: Record<Lang, string>;
  level: string;
  level_label: Record<Lang, string>;
  points: number;
  description_en: string;
  description_ar: string;
  objectives: { key: string; label_en: string; label_ar: string }[];
  checks: LabCheck[];
  check_count: number;
  max_points: number;
  hints_total: number;
  target_kind: string;
  fixture_available: boolean;
  requires_private_access: boolean;
  enabled: boolean;
  order_index: number;
  user_state: {
    best_score: number;
    passed: boolean;
    attempts: number;
    active_run_id: string | null;
    last_run_at: string | null;
  };
  hints?: { en: string; ar: string }[];
  run?: LabRun | null;
}

export interface LabCheckResult {
  key: string;
  type?: string;
  passed: boolean;
  status?: string;
  label_en?: string;
  label_ar?: string;
  points?: number;
  earned?: number;
  detail?: string;
  pending?: boolean;
  [key: string]: unknown;
}

export interface LabRun {
  id: string;
  lab_id: string;
  project_id: string | null;
  status: string;
  score: number;
  attempts: number;
  hints_used: number[];
  checks_result: LabCheckResult[];
  answers: Record<string, string>;
  reset_count: number;
  started_at: string;
  finished_at: string | null;
  lab?: {
    id: string;
    slug: string;
    title_en: string;
    title_ar: string;
    category: string;
    level: string;
    points: number;
    target_kind: string;
  };
}

export interface KevEntry {
  cve_id: string;
  vendor_project: string;
  product: string;
  vulnerability_name: string;
  date_added: string | null;
  due_date: string | null;
  short_description: string;
  required_action: string;
  known_ransomware: boolean;
  notes: string;
  source_url: string;
  fetched_at: string;
}

export interface CveRecord {
  id: string;
  description: string;
  published_at: string | null;
  modified_at: string | null;
  cvss_v3_score: number | null;
  cvss_v3_vector: string;
  cvss_v2_score: number | null;
  cvss_severity: string;
  cwes: string[];
  references: string[];
  affected: unknown[];
  source: string;
  source_url: string;
  fetched_at: string;
  kev: boolean;
  kev_detail?: {
    vendor_project: string;
    product: string;
    vulnerability_name: string;
    date_added: string | null;
    due_date: string | null;
    known_ransomware: boolean;
    required_action: string;
  };
  linked_findings?: number;
}

export interface Capability {
  key: string;
  name_en: string;
  name_ar: string;
  kind: string;
  available: boolean;
  version: string;
  detail: string;
  setup_hint: string;
}

export interface Capabilities {
  capabilities: Record<string, Capability>;
  summary: { total: number; available: number; missing_integrations: string[] };
  detected_at: string;
  note: string;
}

export interface NotificationItem {
  id: string;
  kind: string;
  severity: string;
  title: string;
  message: string;
  project_id: string | null;
  project_name: string;
  entity_id: string;
  href: string;
  ts: string;
}

export interface SearchItem {
  type: string;
  id: string;
  project_id: string | null;
  project_name?: string;
  title: string;
  subtitle: string;
  href: string;
}

export interface SearchResults {
  q: string;
  groups: Record<string, SearchItem[]>;
  total: number;
}

export interface Paged<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
  has_more: boolean;
  counts?: Record<string, unknown>;
}

export interface DashboardSearchParams {
  q?: string;
  limit?: number;
}

export interface Health {
  status: string;
  app: string;
  version: string;
  environment: string;
  database: string;
  database_ok: boolean;
  database_latency_ms: number;
  worker: {
    running?: boolean;
    mode?: string;
    concurrency?: number;
    inprocess?: boolean;
    [key: string]: unknown;
  };
  server_time: string;
  uptime_seconds: number;
  policy: Record<string, unknown>;
}


/* ------------------------------------------------------------------ Academy */

export type AcademyDivisionKey = "defense" | "offense" | "forensics";
export type AcademyLessonStatus = "not_started" | "in_progress" | "completed";

export interface AcademyCategory {
  key: string;
  en: string;
  ar: string;
  focus_en: string;
  focus_ar: string;
}

export interface AcademyStage {
  key: string;
  en: string;
  ar: string;
  difficulty: string;
  minutes: number;
}

export interface AcademyLesson {
  id: string;
  slug: string;
  division: string;
  category: string;
  difficulty: string;
  order_index: number;
  title_en: string;
  title_ar: string;
  summary_en: string;
  summary_ar: string;
  duration_minutes: number;
  video_status: string;
  tags: string[];
  status: AcademyLessonStatus | string;
  progress_percent: number;
  quiz_score: number | null;
  quiz_attempts: number;
  bookmarked: boolean;
  completed_at: string | null;
}

export interface AcademyLessonRef {
  id: string;
  slug: string;
  title_en: string;
  title_ar: string;
  division: string;
  difficulty: string;
  duration_minutes: number;
}

export interface AcademyQuizOption {
  id: string;
  en: string;
  ar: string;
}

export interface AcademyQuizQuestion {
  id: string;
  question_en: string;
  question_ar: string;
  options: AcademyQuizOption[];
}

export interface AcademyLessonDetail extends AcademyLesson {
  description_en: string;
  description_ar: string;
  objectives: { en: string; ar: string }[];
  prerequisites: string[];
  related: string[];
  exercise_en: string;
  exercise_ar: string;
  resource_url: string;
  resource_label_en: string;
  resource_label_ar: string;
  video_url: string;
  notes: string;
  quiz: AcademyQuizQuestion[];
}

export interface AcademyLessonResponse {
  lesson: AcademyLessonDetail;
  prerequisites: AcademyLessonRef[];
  related: AcademyLessonRef[];
}

export interface AcademyUserState {
  status: AcademyLessonStatus | string;
  progress_percent: number;
  quiz_score: number | null;
  quiz_attempts: number;
  bookmarked: boolean;
  has_notes: boolean;
  started_at: string | null;
  completed_at: string | null;
  updated_at: string | null;
}

export interface AcademyQuizResult {
  id: string;
  selected: string | null;
  correct: boolean;
  answer: string;
  explanation_en: string;
  explanation_ar: string;
}

export interface AcademyQuizResponse {
  score: number;
  correct: number;
  total: number;
  pass_percent: number;
  best_score: number;
  passed: boolean;
  details: AcademyQuizResult[];
  user_state: AcademyUserState;
}

export interface AcademyDivision {
  key: string;
  title_en: string;
  title_ar: string;
  tagline_en: string;
  tagline_ar: string;
  description_en: string;
  description_ar: string;
  accent: string;
  icon: string;
  lesson_count: number;
  categories: AcademyCategory[];
  stages: AcademyStage[];
  completed: number;
  total: number;
  percent: number;
  average_quiz: number | null;
}

export interface AcademyDivisionProgress {
  total: number;
  completed: number;
  in_progress: number;
  not_started: number;
  bookmarked: number;
  minutes_total: number;
  minutes_completed: number;
  average_quiz: number | null;
  percent: number;
}

export interface AcademySummary {
  divisions: Record<string, AcademyDivisionProgress>;
  total_lessons: number;
  completed: number;
  bookmarked: number;
}

export interface AcademyOverview {
  divisions: AcademyDivision[];
  summary: AcademySummary;
  generated_at: string;
}

export interface AcademyLessonList {
  items: AcademyLesson[];
  total: number;
  limit: number;
  offset: number;
  returned: number;
}

export interface AcademyPathLesson extends AcademyLesson {
  unmet_prerequisites: string[];
  reason: string;
}

export interface AcademyLearningPath {
  division: string;
  recommendations: AcademyPathLesson[];
  gaps: AcademyPathLesson[];
  weakest: { slug: string; title_en: string; title_ar: string; score: number }[];
  percent: number;
}

export interface AcademyCertificate {
  id: string;
  division: string;
  display_name: string;
  lessons_completed: number;
  average_quiz: number;
  serial: string;
  issued_at: string;
  disclaimer: string;
}

export interface AcademyCertificatesResponse {
  items: AcademyCertificate[];
}
/* ---------------------------------------------------------------------------
 * Command platform: unified graph, timeline, posture, rule studio, workbench,
 * evidence vault, purple team and the security knowledge graph.
 * ------------------------------------------------------------------------- */

export interface GraphNode {
  id: string;
  kind: string;
  label: string;
  sublabel: string;
  severity: string;
  state: string;
  meta: Record<string, unknown>;
  observed_at: string | null;
  degree: number;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  kind: string;
  label: string;
  confidence: "certain" | "firm" | "tentative";
  origin: string;
  observed_at: string | null;
  meta: Record<string, unknown>;
}

export interface AttackPathStep {
  from: string;
  to: string;
  kind: string;
  confidence: string;
  origin: string;
}

export interface AttackPath {
  entry: string;
  length: number;
  steps: AttackPathStep[];
  weakest_link: string;
}

export interface SecurityGraph {
  project_id: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  stats: {
    nodes: number;
    edges: number;
    by_kind: Record<string, number>;
    scans: number;
    assets: number;
    findings: number;
  };
  attack_paths: AttackPath[];
  note: string;
}

export interface TimelineEvent {
  ts: string | null;
  source: string;
  source_label: string;
  kind: string;
  title: string;
  description: string;
  severity: string;
  entity_type: string;
  entity_id: string;
  reference: string;
  confidence: string;
  anomaly: boolean;
  data: Record<string, unknown>;
}

export interface TimelineGroup {
  bucket: string;
  count: number;
  severities: Record<string, number>;
  sources: Record<string, number>;
  events: TimelineEvent[];
}

export interface TimelineResponse {
  project_id: string;
  events: TimelineEvent[];
  groups: TimelineGroup[];
  granularity: string;
  stats: {
    total: number;
    truncated: boolean;
    by_source: Record<string, number>;
    by_severity: Record<string, number>;
    anomalies: number;
    window_start: string | null;
    window_end: string | null;
  };
  sources: { key: string; label: string }[];
  note: string;
}

export interface PostureFactor {
  key: string;
  label_en: string;
  label_ar: string;
  weight: number;
  earned: number;
  max: number;
  percent: number;
  detail: string;
}

export interface PostureMissing {
  key: string;
  label_en: string;
  label_ar: string;
  weight: number;
  reason: string;
}

export interface PostureResponse {
  project_id: string;
  score: number;
  grade: string;
  coverage: number;
  measured_weight: number;
  model_weight: number;
  factors: PostureFactor[];
  missing_information: PostureMissing[];
  top_actions: { key: string; action: string }[];
  counts: Record<string, number>;
  history?: { score: number; grade: string; coverage: number; computed_at: string | null }[];
  methodology: {
    model: { key: string; label_en: string; label_ar: string; weight: number; requires: string }[];
    severity_weights: Record<string, number>;
    notes: string[];
  };
}

export interface SigmaRule {
  id: string;
  name: string;
  title: string;
  description: string;
  status: string;
  author: string;
  license: string;
  level: string;
  logsource: Record<string, unknown>;
  detection: Record<string, unknown>;
  fields: string[];
  falsepositives: string[];
  references: string[];
  tags: string[];
  techniques: string[];
  lessons: string[];
  validation: SigmaValidation;
  last_validated_at: string | null;
  created_at: string | null;
  updated_at: string | null;
}

export interface SigmaValidation {
  valid: boolean;
  errors: string[];
  warnings: string[];
  info: string[];
  detects: string[];
  blind_spots: string[];
  false_positives: string[];
  selections: string[];
}

export interface SigmaTestResult {
  tested_events: number;
  matched_events: number;
  match_rate: number;
  matches: {
    event_id: string;
    ts: string | null;
    severity: string;
    event_type: string;
    message: string;
    src_ip: string;
    dst_ip: string;
    url: string;
  }[];
  sample_size_note: string;
}

export interface CaseHypothesis {
  id: string;
  statement: string;
  status: string;
  confidence: string;
  rationale: string;
  evidence_refs: { kind: string; id: string; label: string }[];
  created_at: string | null;
}

export interface CaseAnnotation {
  id: string;
  body: string;
  entity_type: string;
  entity_id: string;
  author_id: string;
  created_at: string | null;
}

export interface CaseTask {
  id: string;
  title: string;
  detail: string;
  status: string;
  assignee_id: string;
  due_at: string | null;
  created_at: string | null;
}

export interface CaseFile {
  id: string;
  reference: string;
  title: string;
  summary: string;
  status: string;
  severity: string;
  classification: string;
  tags: string[];
  assignee_id: string;
  created_by: string;
  opened_at: string | null;
  closed_at: string | null;
  created_at: string | null;
  updated_at: string | null;
  hypotheses: CaseHypothesis[];
  annotations: CaseAnnotation[];
  tasks: CaseTask[];
  counts: { hypotheses: number; annotations: number; tasks: number; open_tasks: number };
}

export interface CustodyEntry {
  id: string;
  action: string;
  actor_label: string;
  location: string;
  notes: string;
  sha256_at_action: string;
  created_at: string | null;
}

export interface EvidenceRecord {
  id: string;
  finding_id: string | null;
  scan_id: string | null;
  kind: string;
  label: string;
  sha256: string;
  redacted: boolean;
  redactions: { field: string; reason: string }[];
  source: string;
  created_at: string | null;
  custody: CustodyEntry[];
}

export interface EvidenceVerification {
  total: number;
  checked: number;
  verified: number;
  mismatched: { id: string; label: string; recorded: string; in_custody: string[] }[];
  missing_digest: { id: string; label: string; kind: string }[];
  integrity_ok: boolean;
  note: string;
}

export interface PurpleScenario {
  key: string;
  title_en: string;
  title_ar: string;
  division: string;
  technique: string;
  severity: string;
  description_en: string;
  description_ar: string;
  expected_telemetry: { signal: string; field: string; pattern: string }[];
  expected_detections: string[];
  defensive_note_en: string;
  defensive_note_ar: string;
}

export interface PurpleSimulation {
  id: string;
  scenario_key: string;
  scenario_title: string;
  division: string;
  status: string;
  score: number;
  notes: string;
  started_at: string | null;
  finished_at: string | null;
  missed: { signal: string; field: string; detected: boolean; rules: unknown[] }[];
  detections: { signal: string; field: string; detected: boolean; rules: unknown[] }[];
}

export interface PurpleRunResult {
  id: string;
  scenario: PurpleScenario;
  expected: { signal: string; field: string; pattern: string }[];
  observed: { signal: string; field: string; detected: boolean; rules: unknown[] }[];
  detections: { signal: string; field: string; detected: boolean; rules: unknown[] }[];
  missed: { signal: string; field: string; detected: boolean; rules: unknown[] }[];
  score: number;
  rules_evaluated: number;
  recommendation: string;
}

export interface KnowledgeNode {
  id: string;
  kind: string;
  label: string;
  severity: string;
  updated_at: string | null;
  meta: Record<string, unknown>;
}

export interface KnowledgeEdge {
  id: string;
  source: string;
  target: string;
  kind: string;
  label: string;
  confidence: string;
  origin: string;
}

export interface KnowledgeGraph {
  nodes: KnowledgeNode[];
  edges: KnowledgeEdge[];
  stats: Record<string, number>;
  last_updated: string | null;
  sources: { name: string; kind: string; updated_at: string | null }[];
  note: string;
}

