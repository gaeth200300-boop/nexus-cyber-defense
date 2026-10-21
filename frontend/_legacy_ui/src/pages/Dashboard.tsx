import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { api } from '../lib/api';
import { Card, StatCard, Badge, Spinner, Progress } from '../components/ui';
import { severityColor, fmtDate, timeAgo, cn } from '../lib/utils';

interface DashboardData {
  platform: { status: string; worker: string; database: string; uptime_seconds: number; version: string };
  assets: { total: number; monitored: number; by_type: Record<string, number> };
  scans: { total: number; running: number; completed: number; failed: number; today: number };
  findings: { total: number; open: number; by_severity: Record<string, number>; by_status: Record<string, number>; by_category: Record<string, number>; recent: any[] };
  soc: { events: number; alerts: number; open_incidents: number; rules: number };
  timeline: { date: string; findings: number; scans: number; alerts: number }[];
  top_assets: { id: string; value: string; open_findings: number; risk_severity: string }[];
  priorities: any[];
}

/**
 * The dashboard API returns aggregate data grouped by domain. Keep this adapter
 * tolerant of optional fields so an empty installation still renders real
 * zeros and empty states instead of crashing on a missing array.
 */
function normalizeDashboard(raw: any, health: any): DashboardData {
  const recentFindings = raw?.recent?.findings || raw?.findings?.recent || [];
  const recentScans = raw?.recent?.scans || [];
  const findings = raw?.findings || {};
  const scans = raw?.scans || {};
  const soc = raw?.soc || {};
  const trend = raw?.trend || {};
  const today = new Date().toISOString().slice(0, 10);
  const timeline = Array.isArray(raw?.timeline)
    ? raw.timeline
    : (trend.days || []).map((date: string, index: number) => ({
        date,
        findings: trend.findings_created?.[index] || 0,
        scans: trend.scans_created?.[index] || 0,
        alerts: trend.alerts_created?.[index] || 0,
      }));
  const open = Number(findings.open_total ?? findings.open ?? 0);
  const recent = recentFindings.map((finding: any) => ({
    ...finding,
    first_seen_at: finding.first_seen_at || finding.last_seen_at || finding.created_at,
  }));
  return {
    platform: {
      status: health?.status === 'ok' ? 'operational' : 'degraded',
      worker: health?.worker?.in_process ? 'active' : 'inactive',
      database: health?.database_ok ? 'connected' : 'disconnected',
      uptime_seconds: Number(health?.uptime_seconds || 0),
      version: health?.version || '—',
    },
    assets: {
      total: Number(raw?.assets?.total || 0),
      monitored: Number(raw?.assets?.monitored || 0),
      by_type: raw?.assets?.by_type || {},
    },
    scans: {
      total: Number(scans.total || 0),
      running: Number(scans.active ?? scans.running ?? 0),
      completed: Number(scans.by_status?.completed ?? scans.completed ?? 0),
      failed: Number(scans.by_status?.failed ?? scans.failed ?? 0),
      today: recentScans.filter((scan: any) => String(scan.created_at || '').startsWith(today)).length,
    },
    findings: {
      total: Number(findings.total ?? open),
      open,
      by_severity: findings.by_severity || {},
      by_status: findings.by_status || {},
      by_category: findings.by_category || {},
      recent,
    },
    soc: {
      events: Number(soc.events ?? soc.events_24h ?? 0),
      alerts: Number(soc.alerts ?? soc.alerts_open ?? 0),
      open_incidents: Number(soc.open_incidents ?? soc.incidents_open ?? 0),
      rules: Number(soc.rules ?? soc.sources ?? 0),
    },
    timeline,
    top_assets: raw?.top_assets || raw?.risk?.top_assets || [],
    priorities:
      raw?.priorities ||
      recent.filter((finding: any) => ['critical', 'high'].includes(finding.severity)).slice(0, 6),
  };
}

export default function Dashboard() {
  const { t } = useTranslation();
  const nav = useNavigate();
  const [data, setData] = useState<DashboardData | null>(null);
  const [error, setError] = useState('');

  const load = () => {
    Promise.all([
      api<any>('/system/dashboard'),
      api<any>('/system/health').catch(() => null),
    ])
      .then(([raw, health]) => setData(normalizeDashboard(raw, health)))
      .catch((e) => setError(e.message));
  };

  useEffect(load, []);

  if (error) return <div className="card"><p style={{ color: 'var(--red)' }}>{t('error')}: {error}</p></div>;
  if (!data) return <Spinner label={t('loading')} />;

  const maxSev = Math.max(1, ...Object.values(data.findings.by_severity));
  const sevOrder = ['critical', 'high', 'medium', 'low', 'info'];
  const timelineMax = Math.max(1, ...data.timeline.map((d) => d.findings));

  return (
    <div>
      <div className="mb-4">
        <h1 style={{ fontSize: 22, fontWeight: 800 }}>{t('welcomeTitle')}</h1>
        <p className="text-muted text-small">{t('welcomeDesc')}</p>
      </div>

      {/* Platform status strip */}
      <div className="card mb-4" style={{ padding: '14px 20px' }}>
        <div className="flex items-center gap-4" style={{ flexWrap: 'wrap' }}>
          <span className="flex items-center gap-2 text-small">
            <span style={{ width: 9, height: 9, borderRadius: '50%', background: 'var(--green)', display: 'inline-block', boxShadow: '0 0 8px var(--green)' }} />
            <strong>{t('platformStatus')}:</strong> {t('operational')}
          </span>
          <span className="text-small text-muted">·</span>
          <span className="text-small">{t('worker')}: {data.platform.worker === 'active' ? t('workerActive') : t('workerInactive')}</span>
          <span className="text-small text-muted">·</span>
          <span className="text-small">{t('database')}: {t('connected')}</span>
          <span className="text-small text-muted">·</span>
          <span className="text-small text-mono">v{data.platform.version}</span>
          <div className="topbar-spacer" />
          <button className="btn btn-secondary btn-sm" onClick={load}>{t('refreshStatus')}</button>
        </div>
      </div>

      {/* Stat cards */}
      <div className="stat-grid">
        <StatCard icon="◈" tone="neutral" value={data.assets.total} label={t('assetsCount')} />
        <StatCard icon="▶" tone="info" value={data.scans.total} label={t('scansCount')} delta={`${data.scans.today} today`} />
        <StatCard icon="⚠" tone="critical" value={data.findings.open} label={`${t('openCount')} ${t('findingsCount')}`} />
        <StatCard icon="⬢" tone="high" value={data.findings.by_severity.critical || 0} label={t('criticalCount')} />
        <StatCard icon="◍" tone="medium" value={data.soc.alerts} label={`${t('activeAlerts')}`} />
        <StatCard icon="⚗" tone="low" value={data.soc.open_incidents} label={`${t('openIncidents')}`} />
      </div>

      <div className="grid-2" style={{ gridTemplateColumns: '2fr 1fr' }}>
        <div>
          {/* Findings by severity */}
          <Card title={t('bySeverity')} subtitle={t('findingsBySeverity')} className="mb-4">
            <div className="flex flex-col gap-3">
              {sevOrder.map((sev) => {
                const count = data.findings.by_severity[sev] || 0;
                return (
                  <div key={sev} className="flex items-center gap-3">
                    <Badge kind={sev}>{t(sev)}</Badge>
                    <Progress value={(count / maxSev) * 100} />
                    <span className="font-bold text-small" style={{ minWidth: 32, textAlign: 'end' }}>{count}</span>
                  </div>
                );
              })}
            </div>
          </Card>

          {/* Trend chart (SVG line) */}
          <Card title={t('findingsTrend')} subtitle={t('trend')} className="mb-4">
            <TrendChart data={data.timeline} max={timelineMax} />
          </Card>

          {/* By category */}
          <Card title={t('byCategory')} subtitle={t('findingsBySeverity')}>
            <div className="flex flex-wrap gap-2">
              {Object.entries(data.findings.by_category).map(([cat, count]) => (
                <span key={cat} className="badge" style={{ background: 'var(--bg-2)', color: 'var(--txt-1)' }}>
                  {cat} · {count}
                </span>
              ))}
              {Object.keys(data.findings.by_category).length === 0 && <span className="text-muted text-small">{t('noData')}</span>}
            </div>
          </Card>
        </div>

        <div>
          {/* Priorities */}
          <Card title={t('priorities')} subtitle={t('needsAttention')} className="mb-4">
            {data.priorities.length === 0 && <EmptyState2 text={t('noPriorities')} />}
            {data.priorities.slice(0, 6).map((f: any) => (
              <div key={f.id} className="target-row" onClick={() => nav(`/findings/${f.id}`)}>
                <span className="target-status" style={{ background: severityColor(f.severity) }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontWeight: 600, fontSize: 13, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.title}</div>
                  <div className="text-small text-muted">{f.asset?.value || f.target || '—'} · {timeAgo(f.first_seen_at)}</div>
                </div>
                <Badge kind={f.severity}>{t(f.severity)}</Badge>
              </div>
            ))}
          </Card>

          {/* Recent findings */}
          <Card title={t('recentActivity')} subtitle={t('recentFindings')}>
            {data.findings.recent.length === 0 && <EmptyState2 text={t('noFindings')} />}
            {data.findings.recent.slice(0, 5).map((f: any) => (
              <div key={f.id} className="target-row" onClick={() => nav(`/findings/${f.id}`)}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 13, fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.title}</div>
                  <div className="text-small text-muted">{timeAgo(f.first_seen_at)}</div>
                </div>
                <Badge kind={f.severity}>{t(f.severity)}</Badge>
              </div>
            ))}
          </Card>

          {/* Top assets by findings */}
          <Card title={t('topAssetsByFindings')} className="mt-4">
            {data.top_assets.length === 0 && <EmptyState2 text={t('noData')} />}
            {data.top_assets.slice(0, 5).map((a) => (
              <div key={a.id} className="target-row" onClick={() => nav(`/assets?id=${a.id}`)}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div className="text-mono text-small" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.value}</div>
                </div>
                <Badge kind={a.risk_severity || 'info'}>{a.open_findings}</Badge>
              </div>
            ))}
          </Card>
        </div>
      </div>

      {/* Quick actions */}
      <Card title={t('quickActions')} subtitle={t('shortcuts')}>
        <div className="flex gap-3" style={{ flexWrap: 'wrap' }}>
          <button className="btn btn-primary" onClick={() => nav('/scans?new=1')}>▶ {t('newScan')}</button>
          <button className="btn btn-secondary" onClick={() => nav('/projects?new=1')}>▤ {t('newProject')}</button>
          <button className="btn btn-secondary" onClick={() => nav('/reports?new=1')}>▧ {t('newReport')}</button>
          <button className="btn btn-secondary" onClick={() => nav('/assets?new=1')}>◈ {t('addAsset')}</button>
          <button className="btn btn-secondary" onClick={() => nav('/copilot')}>✦ {t('copilot')}</button>
        </div>
      </Card>
    </div>
  );
}

function EmptyState2({ text }: { text: string }) {
  return <div className="text-muted text-small" style={{ padding: '12px 0' }}>{text}</div>;
}

function TrendChart({ data, max }: { data: { date: string; findings: number; scans: number }[]; max: number }) {
  const { t } = useTranslation();
  if (data.length < 2) return <div className="text-muted text-small">{t('noData')}</div>;
  const w = 600, h = 180, pad = 8;
  const pts = data.map((d, i) => ({
    x: pad + (i / (data.length - 1)) * (w - 2 * pad),
    y: h - pad - (d.findings / max) * (h - 2 * pad),
    ...d,
  }));
  const path = pts.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x},${p.y}`).join(' ');
  const area = `${path} L${pts[pts.length - 1].x},${h - pad} L${pts[0].x},${h - pad} Z`;
  return (
    <svg viewBox={`0 0 ${w} ${h}`} style={{ width: '100%', height: 180 }} role="img" aria-label="Findings trend">
      <defs>
        <linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="var(--violet)" stopOpacity="0.3" />
          <stop offset="100%" stopColor="var(--violet)" stopOpacity="0" />
        </linearGradient>
      </defs>
      {[0.25, 0.5, 0.75].map((f) => (
        <line key={f} x1={pad} x2={w - pad} y1={h * f} y2={h * f} stroke="var(--line-soft)" strokeDasharray="3 5" />
      ))}
      <path d={area} fill="url(#trendFill)" />
      <path d={path} fill="none" stroke="var(--violet)" strokeWidth="2" />
      {pts.map((p, i) => (
        <g key={i}>
          <circle cx={p.x} cy={p.y} r="3.5" fill="var(--bg-1)" stroke="var(--violet)" strokeWidth="2" />
          {i % Math.ceil(pts.length / 8) === 0 && (
            <text x={p.x} y={h - 0} fontSize="9" fill="var(--txt-3)" textAnchor="middle">{p.date.slice(5)}</text>
          )}
        </g>
      ))}
    </svg>
  );
}
