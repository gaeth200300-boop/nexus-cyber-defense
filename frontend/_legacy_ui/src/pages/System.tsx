import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '../lib/api';
import { Card, Badge, Spinner, FieldError } from '../components/ui';
import { fmtBytes, fmtDuration } from '../lib/utils';

export default function System() {
  const { t } = useTranslation();
  const [health, setHealth] = useState<any>(null);
  const [settings, setSettings] = useState<any>(null);
  const [caps, setCaps] = useState<any>(null);
  const [jobs, setJobs] = useState<any[]>([]);
  const [error, setError] = useState('');
  const [editSettings, setEditSettings] = useState<any>({});
  const [saved, setSaved] = useState(false);

  const load = () => {
    Promise.all([
      api<any>('/system/health'),
      api<any>('/system/settings'),
      api<any>('/system/capabilities'),
      api<{ items: any[] }>('/system/jobs?limit=10'),
    ]).then(([h, s, c, j]) => {
      setHealth(h); setSettings(s); setCaps(c); setJobs(j.items);
    }).catch((e) => setError(e.message));
  };

  useEffect(load, []);

  const saveSettings = async () => {
    await api('/system/settings', { method: 'PATCH', body: JSON.stringify(editSettings) });
    setSaved(true);
    load();
    setTimeout(() => setSaved(false), 2000);
  };

  const runMaintenance = async () => {
    await api('/system/maintenance', { method: 'POST', body: JSON.stringify({ tasks: ['reap', 'prune'] }) });
  };

  if (error) return <div className="card"><p style={{ color: 'var(--red)' }}>{error}</p></div>;
  if (!health || !settings) return <Spinner label={t('loading')} />;

  return (
    <div>
      <h1 style={{ fontSize: 20, fontWeight: 800, marginBottom: 4 }}>{t('systemTitle')}</h1>
      <p className="text-muted text-small mb-4">{t('healthStatus')}: <Badge kind="healthy">{health.status}</Badge> · v{health.version}</p>

      <div className="stat-grid mb-4">
        <StatCard icon="⏱" tone="low" value={fmtDuration(health.uptime_seconds * 1000)} label={t('uptime')} />
        <StatCard icon="▦" tone="neutral" value={health.worker?.active_jobs ?? 0} label={t('jobsInQueue')} />
        <StatCard icon="◈" tone="info" value={health.database?.status || '—'} label={t('databaseStatus')} />
        <StatCard icon="⚙" tone="high" value={health.server_time ? new Date(health.server_time).toLocaleTimeString() : '—'} label={t('serverTime')} />
      </div>

      <div className="grid-2" style={{ gridTemplateColumns: '1fr 1fr' }}>
        <Card title={t('capabilitiesTitle')}>
          <div className="text-small flex flex-col gap-2">
            <div className="flex justify-between items-center">
              <span>{t('zapIntegration')}</span>
              <Badge kind={caps?.zap ? 'enabled' : 'disabled'}>{caps?.zap ? t('configured_yes') : t('configured_no')}</Badge>
            </div>
            <div className="flex justify-between items-center">
              <span>{t('nmapIntegration')}</span>
              <Badge kind={caps?.nmap ? 'enabled' : 'disabled'}>{caps?.nmap ? t('configured_yes') : t('configured_no')}</Badge>
            </div>
            <div className="flex justify-between items-center">
              <span>{t('aiIntegration')}</span>
              <Badge kind={caps?.ai ? 'enabled' : 'disabled'}>{caps?.ai ? t('configured_yes') : t('configured_no')}</Badge>
            </div>
            <div className="flex justify-between items-center">
              <span>{t('nvdIntegration')}</span>
              <Badge kind={caps?.nvd_key ? 'enabled' : 'disabled'}>{caps?.nvd_key ? t('configured_yes') : t('configured_no')}</Badge>
            </div>
          </div>
        </Card>

        <Card title={t('settingsTitle')}>
          <div className="form-group">
            <label className="form-label">{t('eventRetention')}</label>
            <input className="form-input" type="number" value={editSettings.event_retention_days ?? settings.event_retention_days ?? 30} onChange={(e) => setEditSettings({ ...editSettings, event_retention_days: Number(e.target.value) })} dir="ltr" />
          </div>
          <div className="form-group">
            <label className="form-label">{t('notificationWindow')}</label>
            <input className="form-input" type="number" value={editSettings.notification_window_days ?? settings.notification_window_days ?? 7} onChange={(e) => setEditSettings({ ...editSettings, notification_window_days: Number(e.target.value) })} dir="ltr" />
          </div>
          <div className="flex gap-2 items-center">
            <button className="btn btn-primary btn-sm" onClick={saveSettings}>{t('saveSettings')}</button>
            {saved && <span style={{ color: 'var(--green)', fontSize: 12 }}>✓ {t('settingsSaved')}</span>}
          </div>
        </Card>
      </div>

      <Card title={t('maintenanceTitle')} className="mt-4">
        <p className="text-small text-muted mb-3">{t('maintenanceDesc')}</p>
        <button className="btn btn-secondary" onClick={runMaintenance}>{t('runMaintenanceBtn')}</button>
      </Card>

      <Card title={t('recentJobs')} className="mt-4">
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>{t('jobType')}</th><th>{t('jobStatus')}</th><th>{t('jobAttempts')}</th><th>{t('jobProgress')}</th><th>{t('jobCreated')}</th></tr></thead>
            <tbody>
              {jobs.map((j) => (
                <tr key={j.id}>
                  <td className="text-small">{j.type}</td>
                  <td><Badge kind={j.status}>{j.status}</Badge></td>
                  <td className="text-small">{j.attempts}/{j.max_attempts}</td>
                  <td style={{ width: 120 }}><div className="progress"><div className="progress-bar" style={{ width: `${j.progress || 0}%` }} /></div></td>
                  <td className="text-small text-muted">{new Date(j.created_at).toLocaleTimeString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

function StatCard({ icon, tone, value, label }: { icon: string; tone: string; value: any; label: string }) {
  const tones: Record<string, string> = { neutral: 'var(--violet-soft);color:var(--violet)', low: 'var(--green-soft);color:var(--green)', medium: 'var(--yellow-soft);color:var(--yellow)', high: 'var(--red-soft);color:var(--red)', info: 'var(--cyan-soft);color:var(--cyan)', healthy: 'var(--green-soft);color:var(--green)' };
  return (
    <div className="stat-card">
      <div className="stat-icon" style={{ background: tones[tone]?.split(';')[0], color: tones[tone]?.split(';')[1] }}>{icon}</div>
      <div>
        <div className="stat-value">{value}</div>
        <div className="stat-label">{label}</div>
      </div>
    </div>
  );
}
