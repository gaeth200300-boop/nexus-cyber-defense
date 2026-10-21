import { useLocation, useNavigate } from "react-router-dom";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { useTranslation } from "react-i18next";
import {
  ChevronDown,
  Command,
  Languages,
  LogOut,
  Menu,
  Moon,
  Search,
  Settings2,
  Shield,
  Sun,
  UserRound
} from "lucide-react";
import { useAuth } from "../../context/AuthContext";
import { useTheme } from "../../context/ThemeContext";
import { useProject } from "../../context/ProjectContext";
import { useMeta } from "../../hooks";
import { allNavItems } from "../../config/nav";
import { cn } from "../../lib/utils";
import { toggleLanguage } from "../../lib/i18n";
import { Avatar, IconButton, Tooltip } from "../ui";
import { NotificationCenter } from "./NotificationCenter";
import { ProjectSwitcher } from "./ProjectSwitcher";

export function Topbar({
  onOpenMobile,
  onOpenPalette
}: {
  onOpenMobile: () => void;
  onOpenPalette: () => void;
}) {
  const { t, i18n } = useTranslation();
  const location = useLocation();
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const { selectedProject } = useProject();
  const { theme, toggleTheme } = useTheme();
  const meta = useMeta();
  const isAdmin = ["owner", "admin"].includes(user?.role || "");

  const path = location.pathname;
  const active = allNavItems.find((item) => {
    if (item.to === "/dashboard") return path === "/" || path === "/dashboard";
    return path === item.to || path.startsWith(`${item.to}/`);
  });
  let pageTitle = active ? t(active.labelKey) : t("app.commandCenter");
  if (path.startsWith("/scans/") && path !== "/scans") pageTitle = t("scanDetail.title");
  if (path.startsWith("/labs/") && path !== "/labs") pageTitle = t("nav.labs");
  if (path.startsWith("/projects/") && path !== "/projects") pageTitle = selectedProject?.name || t("projects.overview");

  const doLogout = async () => {
    await logout();
    navigate("/login", { replace: true });
  };

  return (
    <header className="topbar-blur sticky top-0 z-30 flex h-[72px] shrink-0 items-center gap-3 border-b border-line/60 px-4 sm:px-6">
      <button
        type="button"
        onClick={onOpenMobile}
        className="grid h-9 w-9 shrink-0 place-items-center rounded-xl border border-line bg-panel2/60 text-muted transition hover:text-ink focus-ring lg:hidden"
        aria-label={t("nav.openMenu")}
      >
        <Menu className="h-4 w-4" />
      </button>

      <div className="hidden min-w-0 items-center gap-2.5 md:flex">
        <span className="hidden font-mono text-[9px] font-medium uppercase tracking-[0.18em] text-faint xl:block">
          NEXUS /
        </span>
        <h2 className="truncate text-sm font-semibold text-ink">{pageTitle}</h2>
        {selectedProject ? (
          <span className="hidden max-w-36 truncate rounded-full border border-line/70 bg-panel2/60 px-2 py-0.5 text-[9px] text-faint xl:block">
            {selectedProject.name}
          </span>
        ) : null}
      </div>

      <div className="flex min-w-0 flex-1 items-center justify-center">
        <button
          type="button"
          onClick={onOpenPalette}
          className="group flex h-9 w-full max-w-md items-center gap-2 rounded-xl border border-line bg-panel2/50 px-3 text-start text-muted transition hover:border-accent/25 hover:bg-panel2 focus-ring"
        >
          <Search className="h-3.5 w-3.5 shrink-0 text-faint transition group-hover:text-accent" />
          <span className="hidden min-w-0 flex-1 truncate text-[11px] sm:block">{t("common.searchPlaceholder")}</span>
          <span className="ms-auto hidden items-center gap-1 sm:flex">
            <kbd className="rounded border border-line bg-panel px-1.5 py-0.5 font-mono text-[8px] text-faint">Ctrl</kbd>
            <kbd className="rounded border border-line bg-panel px-1.5 py-0.5 font-mono text-[8px] text-faint">K</kbd>
          </span>
        </button>
      </div>

      <div className="flex shrink-0 items-center gap-1 sm:gap-1.5">
        <div className="hidden sm:block">
          <ProjectSwitcher />
        </div>
        <div className="hidden md:block">
          <IconButton
            onClick={toggleTheme}
            aria-label={t("common.theme")}
            title={theme === "dark" ? t("common.light") : t("common.dark")}
          >
            {theme === "dark" ? <Sun className="h-[17px] w-[17px]" /> : <Moon className="h-[17px] w-[17px]" />}
          </IconButton>
        </div>
        <Tooltip content={i18n.language.startsWith("ar") ? "English" : "العربية"}>
          <button
            type="button"
            onClick={() => toggleLanguage()}
            className="grid h-9 w-9 place-items-center rounded-xl text-muted transition hover:bg-panel2 hover:text-ink focus-ring"
            aria-label={t("common.language")}
          >
            <span className="text-[10px] font-bold tracking-wide">
              {i18n.language.startsWith("ar") ? "EN" : "ع"}
            </span>
          </button>
        </Tooltip>
        <NotificationCenter />
        <div className="mx-0.5 hidden h-5 w-px bg-line/70 sm:block" />
        <DropdownMenu.Root>
          <DropdownMenu.Trigger asChild>
            <button
              type="button"
              className="group flex items-center gap-2 rounded-xl p-0.5 transition hover:bg-panel2 focus-ring sm:pe-2"
              aria-label={t("nav.profile")}
            >
              <Avatar name={user?.full_name || user?.email} size="sm" />
              <span className="hidden text-start lg:block">
                <span className="block max-w-28 truncate text-[11px] font-medium text-ink">
                  {user?.full_name || "—"}
                </span>
                <span className="block text-[9px] uppercase tracking-wider text-faint">{user?.role || ""}</span>
              </span>
              <ChevronDown className="hidden h-3 w-3 text-faint lg:block" />
            </button>
          </DropdownMenu.Trigger>
          <DropdownMenu.Portal>
            <DropdownMenu.Content
              align="end"
              sideOffset={8}
              className="z-[95] w-60 overflow-hidden rounded-xl border border-line bg-panel p-1.5 shadow-panel animate-scale-in"
            >
              <div className="flex items-center gap-2.5 px-2.5 py-2">
                <Avatar name={user?.full_name || user?.email} size="md" />
                <div className="min-w-0">
                  <p className="truncate text-xs font-semibold text-ink">{user?.full_name || "—"}</p>
                  <p className="truncate text-[10px] text-faint">{user?.email}</p>
                </div>
              </div>
              <DropdownMenu.Separator className="my-1 h-px bg-line/70" />
              <DropdownMenu.Item
                onSelect={() => navigate("/profile")}
                className="flex cursor-pointer items-center gap-2 rounded-lg px-2.5 py-2 text-xs text-muted outline-none data-[highlighted]:bg-panel2 data-[highlighted]:text-ink"
              >
                <UserRound className="h-3.5 w-3.5" />
                {t("nav.profile")}
              </DropdownMenu.Item>
              <DropdownMenu.Item
                onSelect={() => navigate("/projects")}
                className="flex cursor-pointer items-center gap-2 rounded-lg px-2.5 py-2 text-xs text-muted outline-none data-[highlighted]:bg-panel2 data-[highlighted]:text-ink"
              >
                <Shield className="h-3.5 w-3.5" />
                {t("nav.projects")}
              </DropdownMenu.Item>
              {isAdmin ? (
                <DropdownMenu.Item
                  onSelect={() => navigate("/admin?tab=settings")}
                  className="flex cursor-pointer items-center gap-2 rounded-lg px-2.5 py-2 text-xs text-muted outline-none data-[highlighted]:bg-panel2 data-[highlighted]:text-ink"
                >
                  <Settings2 className="h-3.5 w-3.5" />
                  {t("nav.platform")}
                </DropdownMenu.Item>
              ) : null}
              <DropdownMenu.Item
                onSelect={onOpenPalette}
                className="flex cursor-pointer items-center gap-2 rounded-lg px-2.5 py-2 text-xs text-muted outline-none data-[highlighted]:bg-panel2 data-[highlighted]:text-ink"
              >
                <Command className="h-3.5 w-3.5" />
                {t("command.title")}
              </DropdownMenu.Item>
              <DropdownMenu.Separator className="my-1 h-px bg-line/70" />
              <div className="flex items-center justify-between px-2.5 py-1.5">
                <span className="flex items-center gap-1.5 text-[10px] text-faint">
                  <Languages className="h-3 w-3" />
                  {t("app.environment")}
                </span>
                <span className="text-[9px] uppercase tracking-wider text-muted">
                  {meta.data?.app.environment || "—"}
                </span>
              </div>
              <DropdownMenu.Item
                onSelect={() => void doLogout()}
                className="flex cursor-pointer items-center gap-2 rounded-lg px-2.5 py-2 text-xs text-rose-300 outline-none data-[highlighted]:bg-rose-400/10"
              >
                <LogOut className="h-3.5 w-3.5 rtl:flip-x" />
                {t("auth.logout")}
              </DropdownMenu.Item>
            </DropdownMenu.Content>
          </DropdownMenu.Portal>
        </DropdownMenu.Root>
      </div>
    </header>
  );
}
