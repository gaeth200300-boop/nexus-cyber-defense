import { Suspense, useEffect, useState } from "react";
import { Outlet, useLocation } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { CommandPalette } from "./CommandPalette";
import { Sidebar } from "./Sidebar";
import { Topbar } from "./Topbar";
import { cn } from "../../lib/utils";

const SIDEBAR_KEY = "nexus.sidebar_collapsed";

export function AppShell() {
  const { t } = useTranslation();
  const location = useLocation();
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem(SIDEBAR_KEY) === "1");
  const [mobileOpen, setMobileOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);

  useEffect(() => {
    localStorage.setItem(SIDEBAR_KEY, collapsed ? "1" : "0");
  }, [collapsed]);

  useEffect(() => {
    setMobileOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setPaletteOpen((current) => !current);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  return (
    <div className="min-h-screen">
      <Sidebar
        collapsed={collapsed}
        onToggleCollapsed={() => setCollapsed((current) => !current)}
        mobileOpen={mobileOpen}
        onCloseMobile={() => setMobileOpen(false)}
      />
      <div
        className={cn(
          "flex min-h-screen min-w-0 flex-col transition-[margin] duration-300",
          collapsed ? "lg:ms-[80px]" : "lg:ms-[272px]"
        )}
      >
        <Topbar onOpenMobile={() => setMobileOpen(true)} onOpenPalette={() => setPaletteOpen(true)} />
        <main className="relative flex-1">
          <div className="pointer-events-none fixed inset-0 -z-10 cyber-dots opacity-[0.35]" />
          <div className="mx-auto w-full max-w-[1680px] px-4 py-5 sm:px-6 sm:py-6 lg:px-8 lg:py-7">
            <div key={location.pathname} className="animate-fade-in">
              <Suspense
                fallback={
                  <div className="flex items-center justify-center gap-2 py-24 text-xs text-muted">
                    <span className="h-4 w-4 animate-spin rounded-full border-2 border-accent/30 border-t-accent" />
                    {t("common.loading")}
                  </div>
                }
              >
                <Outlet />
              </Suspense>
            </div>
          </div>
        </main>
        <footer className="mx-auto flex w-full max-w-[1680px] flex-wrap items-center justify-between gap-2 px-4 pb-5 text-[9px] text-faint sm:px-6 lg:px-8">
          <span className="flex items-center gap-2">
            <span className="h-1 w-1 rounded-full bg-accent2" />
            {t("footer.policy")} · {t("common.poweredBy")}
          </span>
          <span className="font-mono uppercase tracking-[0.12em]">NEXUS · CYBER DEFENSE</span>
        </footer>
      </div>
      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} />
    </div>
  );
}
