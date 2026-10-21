import { lazy, Suspense } from "react";
import { Link, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { Loader2 } from "lucide-react";
import { useAuth } from "./context/AuthContext";
import { AppShell } from "./components/layout/AppShell";
import { Logo } from "./components/Logo";
import { buttonClass } from "./components/ui";

const LoginPage = lazy(() => import("./pages/LoginPage"));
const DashboardPage = lazy(() => import("./pages/DashboardPage"));
const WebSecurityPage = lazy(() => import("./pages/WebSecurityPage"));
const NetworkLabPage = lazy(() => import("./pages/NetworkLabPage"));
const ScansPage = lazy(() => import("./pages/ScansPage"));
const ScanDetailPage = lazy(() => import("./pages/ScanDetailPage"));
const FindingsPage = lazy(() => import("./pages/FindingsPage"));
const AssetsPage = lazy(() => import("./pages/AssetsPage"));
const IntelPage = lazy(() => import("./pages/IntelPage"));
const ASMPage = lazy(() => import("./pages/ASMPage"));
const SOCPage = lazy(() => import("./pages/SOCPage"));
const CopilotPage = lazy(() => import("./pages/CopilotPage"));
const LabsPage = lazy(() => import("./pages/LabsPage"));
const LabDetailPage = lazy(() => import("./pages/LabDetailPage"));
const ReportsPage = lazy(() => import("./pages/ReportsPage"));
const ProjectsPage = lazy(() => import("./pages/ProjectsPage"));
const ProjectDetailPage = lazy(() => import("./pages/ProjectDetailPage"));
const ProfilePage = lazy(() => import("./pages/ProfilePage"));
const AdminPage = lazy(() => import("./pages/AdminPage"));

// Academy
const AcademyPage = lazy(() => import("./pages/AcademyPage"));
const AcademyDivisionPage = lazy(() => import("./pages/AcademyDivisionPage"));
const AcademyLessonPage = lazy(() => import("./pages/AcademyLessonPage"));

// Command platform
const GraphPage = lazy(() => import("./pages/GraphPage"));
const TimelinePage = lazy(() => import("./pages/TimelinePage"));
const PosturePage = lazy(() => import("./pages/PosturePage"));
const RuleStudioPage = lazy(() => import("./pages/RuleStudioPage"));
const WorkbenchPage = lazy(() => import("./pages/WorkbenchPage"));
const EvidenceVaultPage = lazy(() => import("./pages/EvidenceVaultPage"));
const PurpleTeamPage = lazy(() => import("./pages/PurpleTeamPage"));
const KnowledgePage = lazy(() => import("./pages/KnowledgePage"));

function BootScreen() {
  return (
    <div className="grid min-h-screen place-items-center bg-bg">
      <div className="flex flex-col items-center gap-4">
        <div className="relative grid h-16 w-16 place-items-center">
          <div className="absolute inset-0 animate-pulse rounded-2xl bg-accent/15 blur-xl" />
          <Logo size={54} className="relative" />
        </div>
        <div className="flex items-center gap-2 text-xs text-muted">
          <Loader2 className="h-3.5 w-3.5 animate-spin text-accent" />
          NEXUS
        </div>
      </div>
    </div>
  );
}

function ProtectedRoute() {
  const { user, loading } = useAuth();
  const location = useLocation();
  if (loading) return <BootScreen />;
  if (!user) return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />;
  return <AppShell />;
}

function NotFoundPage() {
  const { t } = useTranslation();
  return (
    <div className="grid min-h-[60vh] place-items-center">
      <div className="text-center">
        <p className="font-mono text-xs uppercase tracking-[0.3em] text-accent2">404</p>
        <h1 className="mt-3 font-display text-3xl font-semibold text-ink">{t("common.noneFound")}</h1>
        <p className="mt-2 text-sm text-muted">{t("common.page")} {t("common.unknown")}</p>
        <Link to="/dashboard" className={buttonClass("primary", "md", "mt-5")}>
          {t("nav.dashboard")}
        </Link>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <Suspense fallback={<BootScreen />}>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route element={<ProtectedRoute />}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/web" element={<WebSecurityPage />} />
          <Route path="/network" element={<NetworkLabPage />} />
          <Route path="/scans" element={<ScansPage />} />
          <Route path="/scans/:scanId" element={<ScanDetailPage />} />
          <Route path="/findings" element={<FindingsPage />} />
          <Route path="/assets" element={<AssetsPage />} />
          <Route path="/intel" element={<IntelPage />} />
          <Route path="/asm" element={<ASMPage />} />
          <Route path="/soc" element={<SOCPage />} />
          <Route path="/copilot" element={<CopilotPage />} />
          <Route path="/labs" element={<LabsPage />} />
          <Route path="/labs/:labId" element={<LabDetailPage />} />
          <Route path="/reports" element={<ReportsPage />} />
          <Route path="/projects" element={<ProjectsPage />} />
          <Route path="/projects/:projectId" element={<ProjectDetailPage />} />
          <Route path="/profile" element={<ProfilePage />} />
          <Route path="/admin" element={<AdminPage />} />

          {/* Academy */}
          <Route path="/academy" element={<AcademyPage />} />
          <Route path="/academy/lessons/:slug" element={<AcademyLessonPage />} />
          <Route path="/academy/:division" element={<AcademyDivisionPage />} />

          {/* Command platform */}
          <Route path="/graph" element={<GraphPage />} />
          <Route path="/timeline" element={<TimelinePage />} />
          <Route path="/posture" element={<PosturePage />} />
          <Route path="/rule-studio" element={<RuleStudioPage />} />
          <Route path="/workbench" element={<WorkbenchPage />} />
          <Route path="/evidence" element={<EvidenceVaultPage />} />
          <Route path="/purple" element={<PurpleTeamPage />} />
          <Route path="/knowledge" element={<KnowledgePage />} />

          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Routes>
    </Suspense>
  );
}
