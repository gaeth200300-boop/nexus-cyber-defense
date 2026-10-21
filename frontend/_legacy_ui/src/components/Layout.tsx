import React, { useEffect, useRef, useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { api, clearTokens } from '../lib/api';
import { useUi, useAuth } from '../lib/store';
import { cn } from '../lib/utils';
import { useQueryClient } from '@tanstack/react-query';

export const NAV_SECTIONS: { section: string; items: { path: string; icon: string; key: string; adminOnly?: boolean }[] }[] = [
  {
    section: 'الرئيسية',
    items: [
      { path: '/dashboard', icon: '▦', key: 'dashboard' },
      { path: '/projects', icon: '▤', key: 'projects' },
    ],
  },
  {
    section: 'الفحص والاختبار',
    items: [
      { path: '/assets', icon: '◈', key: 'assets' },
      { path: '/scans', icon: '▶', key: 'scans' },
      { path: '/findings', icon: '⚠', key: 'findings' },
      { path: '/network', icon: '⬡', key: 'network' },
    ],
  },
  {
    section: 'الأمن والعمليات',
    items: [
      { path: '/intel', icon: '◉', key: 'intel' },
      { path: '/asm', icon: '⬢', key: 'asm' },
      { path: '/soc', icon: '◍', key: 'soc' },
    ],
  },
  {
    section: 'الأدوات',
    items: [
      { path: '/labs', icon: '⚗', key: 'labs' },
      { path: '/copilot', icon: '✦', key: 'copilot' },
      { path: '/reports', icon: '▧', key: 'reports' },
    ],
  },
  {
    section: 'الإدارة',
    items: [
      { path: '/system', icon: '⚙', key: 'system', adminOnly: true },
      { path: '/audit', icon: '☰', key: 'audit', adminOnly: true },
      { path: '/users', icon: '◉', key: 'users', adminOnly: true },
    ],
  },
];

export function Sidebar() {
  const { t } = useTranslation();
  const nav = useNavigate();
  const location = useLocation();
  const { sidebarCollapsed, toggleSidebar, projectId } = useUi();
  const user = useAuth((s) => s.user);
  const setUser = useAuth((s) => s.setUser);
  const queryClient = useQueryClient();
  const [loggingOut, setLoggingOut] = useState(false);

  const isAdmin = user?.role === 'owner' || user?.role === 'admin';

  const handleLogout = async () => {
    if (loggingOut) return;
    setLoggingOut(true);
    try {
      await api('/auth/logout', { method: 'POST' });
    } catch {
      // The local session must still be cleared if the API is unreachable.
    } finally {
      clearTokens();
      setUser(null);
      queryClient.clear();
      nav('/login', { replace: true });
    }
  };

  return (
    <aside className={cn('sidebar', sidebarCollapsed && 'collapsed')}>
      <div className="sidebar-logo">
        <div className="sidebar-logo-mark">N</div>
        <div className="sidebar-logo-text">
          {t('appName')}
          <small>{t('appSuffix')}</small>
        </div>
      </div>
      <div className="sidebar-nav">
        {NAV_SECTIONS.map((sec) => {
          const items = sec.items.filter((i) => !i.adminOnly || isAdmin);
          if (!items.length) return null;
          return (
            <div key={sec.section}>
              {!sidebarCollapsed && <div className="nav-section">{sec.section}</div>}
              {items.map((item) => (
                <div
                  key={item.path}
                  className={cn('nav-item', location.pathname.startsWith(item.path) && 'active')}
                  onClick={() => nav(item.path)}
                  title={t(item.key)}
                >
                  <span className="nav-icon">{item.icon}</span>
                  <span className="nav-label">{t(item.key)}</span>
                </div>
              ))}
            </div>
          );
        })}
      </div>
      <div className="sidebar-footer">
        <div className="sidebar-user">
          <div className="sidebar-user-avatar">{(user?.full_name || '?')[0]?.toUpperCase()}</div>
          <div style={{ overflow: 'hidden' }}>
            <div className="sidebar-user-name">{user?.full_name}</div>
            <div className="sidebar-user-role">{t(user?.role || '')}</div>
          </div>
        </div>
        <button
          type="button"
          className="nav-item sidebar-logout"
          onClick={handleLogout}
          disabled={loggingOut}
          title={t('logout')}
          aria-label={t('logout')}
        >
          <span className="nav-icon">⏻</span>
          <span className="nav-label">{t('logout')}</span>
        </button>
      </div>
    </aside>
  );
}

export function Topbar() {
  const { t, i18n } = useTranslation();
  const nav = useNavigate();
  const { theme, toggleTheme, locale, setLocale, sidebarCollapsed, toggleSidebar, projectId, setProjectId } = useUi();
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [notifOpen, setNotifOpen] = useState(false);
  const [notifs, setNotifs] = useState<any[]>([]);
  const [searchQ, setSearchQ] = useState('');
  const searchRef = useRef<HTMLInputElement>(null);
  const queryClient = useQueryClient();

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        setPaletteOpen((v) => !v);
      }
      if (e.key === 'Escape') {
        setPaletteOpen(false);
        setNotifOpen(false);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  const loadNotifs = () => {
    api<{ items: any[] }>('/system/notifications').then((d) => setNotifs(d.items)).catch(() => {});
  };

  useEffect(() => {
    if (notifOpen) loadNotifs();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [notifOpen]);

  const doSearch = (q: string) => {
    if (!q.trim()) return;
    nav(`/search?q=${encodeURIComponent(q)}`);
    setPaletteOpen(false);
  };

  const paletteItems = [
    { path: '/dashboard', icon: '▦', label: t('dashboard') },
    { path: '/projects', icon: '▤', label: t('projects') },
    { path: '/assets', icon: '◈', label: t('assets') },
    { path: '/scans', icon: '▶', label: t('scans') },
    { path: '/findings', icon: '⚠', label: t('findings') },
    { path: '/network', icon: '⬡', label: t('network') },
    { path: '/intel', icon: '◉', label: t('intel') },
    { path: '/asm', icon: '⬢', label: t('asm') },
    { path: '/soc', icon: '◍', label: t('soc') },
    { path: '/labs', icon: '⚗', label: t('labs') },
    { path: '/copilot', icon: '✦', label: t('copilot') },
    { path: '/reports', icon: '▧', label: t('reports') },
    { path: '/system', icon: '⚙', label: t('system') },
    { path: '/audit', icon: '☰', label: t('audit') },
    { path: '/users', icon: '◉', label: t('users') },
  ];

  return (
    <header className="topbar">
      <button className="topbar-btn" onClick={toggleSidebar} title="Toggle sidebar">☰</button>
      <div className="topbar-search">
        <span>🔍</span>
        <input
          ref={searchRef}
          placeholder={t('searchPlaceholder')}
          value={searchQ}
          onChange={(e) => setSearchQ(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && doSearch(searchQ)}
          onFocus={() => setPaletteOpen(true)}
        />
        <span className="topbar-kbd">Ctrl K</span>
      </div>
      <div className="topbar-spacer" />
      {projectId && (
        <div className="topbar-project" title={t('selectProject')}>◈ {projectId.slice(0, 8)}</div>
      )}
      <button className="topbar-btn" onClick={() => setNotifOpen((v) => !v)} title={t('notifications')}>
        🔔
        {notifs.length > 0 && <span style={{ position: 'absolute', top: 4, insetInlineEnd: 4, width: 8, height: 8, borderRadius: '50%', background: 'var(--red)' }} />}
      </button>
      <button className="topbar-btn" onClick={toggleTheme} title={t('theme')}>
        {theme === 'dark' ? '☀' : '☾'}
      </button>
      <button
        className="icon-btn"
        onClick={() => { const next = locale === 'ar' ? 'en' : 'ar'; setLocale(next); i18n.changeLanguage(next); }}
        title={t('language')}
      >
        {locale === 'ar' ? 'EN' : 'عربي'}
      </button>

      {paletteOpen && (
        <>
          <div style={{ position: 'fixed', inset: 0, zIndex: 90 }} onClick={() => setPaletteOpen(false)} />
          <div className="modal" style={{ position: 'absolute', top: 48, insetInlineStart: '20%', zIndex: 95, padding: 8 }}>
            <div className="palette">
              <div className="palette-input">
                <span>🔍</span>
                <input
                  autoFocus
                  placeholder={t('search')}
                  value={searchQ}
                  onChange={(e) => setSearchQ(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && doSearch(searchQ)}
                />
              </div>
              <div className="palette-list">
                <div className="palette-section">{t('commandPalette')}</div>
                {paletteItems
                  .filter((p) => p.label.toLowerCase().includes(searchQ.toLowerCase()))
                  .map((p) => (
                    <div key={p.path} className="palette-item" onClick={() => { nav(p.path); setPaletteOpen(false); }}>
                      <span className="pal-icon">{p.icon}</span>
                      {p.label}
                    </div>
                  ))}
              </div>
            </div>
          </div>
        </>
      )}

      {notifOpen && (
        <>
          <div style={{ position: 'fixed', inset: 0, zIndex: 90 }} onClick={() => setNotifOpen(false)} />
          <div className="modal notif-panel" style={{ position: 'absolute', top: 48, insetInlineEnd: 16, zIndex: 95 }}>
            <div className="modal-header">
              {t('notifications')}
              <button className="btn btn-ghost btn-sm" onClick={() => setNotifOpen(false)}>✕</button>
            </div>
            <div className="notif-list">
              {notifs.length === 0 && <div className="empty-state" style={{ padding: 24 }}>{t('noNotifications')}</div>}
              {notifs.map((n) => (
                <div key={n.id} className={cn('notif-item', !n.read && 'unread')}>
                  <span className="notif-dot" style={{ visibility: n.read ? 'hidden' : 'visible' }} />
                  <div>
                    <div style={{ fontWeight: 600 }}>{n.title}</div>
                    <div className="text-small text-muted">{n.body}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </header>
  );
}

export function Layout({ children }: { children: React.ReactNode }) {
  return (
    <div className="app-shell">
      <Sidebar />
      <div className="app-main">
        <Topbar />
        <main className="app-content">{children}</main>
      </div>
    </div>
  );
}
