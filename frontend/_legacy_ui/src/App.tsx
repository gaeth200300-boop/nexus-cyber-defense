import React, { useEffect, useState } from 'react';
import { Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { api, clearTokens, setTokens, getToken, ApiError } from './lib/api';
import { useUi, useAuth } from './lib/store';
import { applyDir } from './lib/i18n';
import { Layout } from './components/Layout';
import LoginPage from './pages/Login';
import BootstrapPage from './pages/Bootstrap';
import Dashboard from './pages/Dashboard';
import Projects from './pages/Projects';
import Assets from './pages/Assets';
import Scans from './pages/Scans';
import ScanDetail from './pages/ScanDetail';
import Findings from './pages/Findings';
import FindingDetail from './pages/FindingDetail';
import Network from './pages/Network';
import Intel from './pages/Intel';
import AttackSurface from './pages/AttackSurface';
import SOC from './pages/SOC';
import Labs from './pages/Labs';
import LabDetail from './pages/LabDetail';
import Copilot from './pages/Copilot';
import Reports from './pages/Reports';
import System from './pages/System';
import Audit from './pages/Audit';
import Users from './pages/Users';
import SearchResults from './pages/SearchResults';

function ToastStack() {
  const [toasts, setToasts] = useState<{ id: number; msg: string; kind: string }[]>([]);
  useEffect(() => {
    (window as any).__toast = (msg: string, kind = 'info') => {
      const id = Date.now() + Math.random();
      setToasts((t) => [...t, { id, msg, kind }]);
      setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 4200);
    };
    return () => { delete (window as any).__toast; };
  }, []);
  return (
    <div className="toast-stack">
      {toasts.map((t) => (
        <div key={t.id} className={cn('toast', t.kind)}>{t.msg}</div>
      ))}
    </div>
  );
}

function cn(...parts: (string | false | null | undefined)[]) {
  return parts.filter(Boolean).join(' ');
}

function Protected({ children }: { children: React.ReactNode }) {
  const { bootstrapped, setUser, setBootstrapped } = useAuth();
  const [checking, setChecking] = useState(true);
  const location = useLocation();

  useEffect(() => {
    let active = true;
    const finish = () => { if (active) setChecking(false); };

    if (!getToken()) {
      // No session: discover whether this is a first-run installation before
      // deciding between /bootstrap and /login.
      api<{ bootstrap_required: boolean }>('/auth/bootstrap')
        .then((d) => { if (active) setBootstrapped(!!d.bootstrap_required); })
        .catch(() => { if (active) setBootstrapped(false); })
        .finally(finish);
      return () => { active = false; };
    }

    // Restore the signed-in profile after a page reload. The Zustand store is
    // intentionally in-memory for the user object; the JWT is persisted.
    api<{ user: any }>('/auth/me')
      .then((d) => {
        if (!active) return;
        setUser(d.user);
        setBootstrapped(false);
      })
      .catch(async () => {
        clearTokens();
        if (!active) return;
        setUser(null);
        try {
          const d = await api<{ bootstrap_required: boolean }>('/auth/bootstrap');
          if (active) setBootstrapped(!!d.bootstrap_required);
        } catch {
          if (active) setBootstrapped(false);
        }
      })
      .finally(finish);

    return () => { active = false; };
  }, [setUser, setBootstrapped]);

  if (checking) {
    return <div style={{ display: 'grid', placeItems: 'center', height: '100vh' }}><div className="spinner" /></div>;
  }
  if (bootstrapped) return <Navigate to="/bootstrap" replace state={{ from: location }} />;
  if (!getToken()) return <Navigate to="/login" replace state={{ from: location }} />;
  return <>{children}</>;
}

export default function App() {
  const { theme, locale } = useUi();
  const { t } = useTranslation();

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
  }, [theme]);

  useEffect(() => {
    applyDir(locale);
  }, [locale]);

  return (
    <>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/bootstrap" element={<BootstrapPage />} />
        <Route
          path="*"
          element={
            <Protected>
              <Layout>
                <Routes>
                  <Route path="/" element={<Navigate to="/dashboard" replace />} />
                  <Route path="/dashboard" element={<Dashboard />} />
                  <Route path="/projects" element={<Projects />} />
                  <Route path="/assets" element={<Assets />} />
                  <Route path="/scans" element={<Scans />} />
                  <Route path="/scans/:id" element={<ScanDetail />} />
                  <Route path="/findings" element={<Findings />} />
                  <Route path="/findings/:id" element={<FindingDetail />} />
                  <Route path="/network" element={<Network />} />
                  <Route path="/intel" element={<Intel />} />
                  <Route path="/asm" element={<AttackSurface />} />
                  <Route path="/soc" element={<SOC />} />
                  <Route path="/labs" element={<Labs />} />
                  <Route path="/labs/:id" element={<LabDetail />} />
                  <Route path="/copilot" element={<Copilot />} />
                  <Route path="/reports" element={<Reports />} />
                  <Route path="/system" element={<System />} />
                  <Route path="/audit" element={<Audit />} />
                  <Route path="/users" element={<Users />} />
                  <Route path="/search" element={<SearchResults />} />
                  <Route path="*" element={<Navigate to="/dashboard" replace />} />
                </Routes>
              </Layout>
            </Protected>
          }
        />
      </Routes>
      <ToastStack />
    </>
  );
}
