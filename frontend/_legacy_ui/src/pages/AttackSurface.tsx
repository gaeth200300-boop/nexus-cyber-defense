import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { api } from '../lib/api';
import { Card, Badge, Spinner, EmptyState, Pagination } from '../components/ui';
import { useUi } from '../lib/store';
import { fmtDate, severityColor } from '../lib/utils';

export default function AttackSurface() {
  const { t } = useTranslation();
  const nav = useNavigate();
  const { projectId } = useUi();
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [tab, setTab] = useState<'overview' | 'exposure' | 'changes'>('overview');
  const [page, setPage] = useState(1);
  const [exposure, setExposure] = useState<any[]>([]);
  const [changes, setChanges] = useState<any[]>([]);
  const [changesTotal, setChangesTotal] = useState(0);

  const load = () => {
    if (!projectId) return;
    setLoading(true);
    api<any>(`/projects/${projectId}/asm/overview`)
      .then(setData)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(load, [projectId]);

  useEffect(() => {
    if (!projectId) return;
    if (tab === 'exposure') {
      api<{ items: any[] }>(`/projects/${projectId}/asm/exposure?limit=25&offset=${(page - 1) * 25}`).then((d) => setExposure(d.items)).catch(() => {});
    }
    if (tab === 'changes') {
      api<{ items: any[]; total: number }>(`/projects/${projectId}/changes?limit=25&offset=${(page - 1) * 25}`).then((d) => { setChanges(d.items); setChangesTotal(d.total); }).catch(() => {});
    }
  }, [projectId, tab, page]);

  const ackChange = async (id: string) => {
    await api(`/projects/${projectId}/changes/${id}/ack`, { method: 'POST' });
    load();
  };

  const ackAll = async () => {
    await api(`/projects/${projectId}/changes/ack-all`, { method: 'POST' });
    load();
  };

  if (!projectId) return <Card><EmptyState title={t('selectProjectFirst')} /></Card>;
  if (loading) return <Spinner />;
  if (error) return <div className="card"><p style={{ color: 'var(--red)' }}>{error}</p></div>;
  if (!data) return null;

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h1 style={{ fontSize: 20, fontWeight: 800 }}>{t('asm')}</h1>
        <button className="btn btn-secondary btn-sm" onClick={ackAll}>{t('ackAllChanges')}</button>
      </div>

      <div className="stat-grid">
        <StatCard icon="◈" tone="neutral" value={data.assets} label={t('totalAssets')} />
        <StatCard icon="◎" tone="low" value={data.monitored} label={t('monitoredAssets')} />
        <StatCard icon="⬡" tone="medium" value={data.services} label={t('servicesExposed')} />
        <StatCard icon="⚡" tone="high" value={data.unacknowledged} label={t('unacknowledgedChanges')} />
      </div>

      <div className="tabs">
        <button className={tab === 'overview' ? 'tab active' : 'tab'} onClick={() => setTab('overview')}>{t('overview')}</button>
        <button className={tab === 'exposure' ? 'tab active' : 'tab'} onClick={() => setTab('exposure')}>{t('exposureTitle')}</button>
        <button className={tab === 'changes' ? 'tab active' : 'tab'} onClick={() => setTab('changes')}>{t('assetChanges')}</button>
      </div>

      {tab === 'overview' && (
        <div className="grid-2" style={{ gridTemplateColumns: '1fr 1fr' }}>
          <Card title={t('assetMap')} subtitle={t('assetRelations')}>
            {(data.assets_list || []).length === 0 && <EmptyState icon="◈" title={t('noData')} />}
            {(data.assets_list || []).slice(0, 12).map((a: any) => (
              <div key={a.id} className="target-row" onClick={() => nav(`/assets?id=${a.id}`)}>
                <span className="target-status" style={{ background: severityColor(a.risk_severity || 'info') }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div className="text-mono text-small" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.value}</div>
                  <div className="text-small text-muted">{a.open_findings} open · {a.services_count} services</div>
                </div>
                <Badge kind={a.risk_severity || 'info'}>{a.risk_severity || '—'}</Badge>
              </div>
            ))}
          </Card>
          <Card title={t('coverageMap')} subtitle={t('exposureMap')}>
            <div className="flex flex-col gap-2">
              {(['critical', 'high', 'medium', 'low'] as const).map((sev) => {
                const count = data.by_severity?.[sev] || 0;
                const pct = data.assets > 0 ? (count / data.assets) * 100 : 0;
                return (
                  <div key={sev}>
                    <div className="flex justify-between text-small mb-1">
                      <Badge kind={sev}>{t(sev)}</Badge>
                      <span>{count}</span>
                    </div>
                    <div className="progress"><div className="progress-bar" style={{ width: `${pct}%`, background: severityColor(sev) }} /></div>
                  </div>
                );
              })}
            </div>
          </Card>
        </div>
      )}

      {tab === 'exposure' && (
        <Card>
          {exposure.length === 0 ? <EmptyState icon="⬡" title={t('noExposure')} /> : (
            <div className="table-wrap">
              <table className="table">
                <thead><tr><th>{t('service')}</th><th>{t('portCol')}</th><th>{t('asset')}</th><th>{t('state')}</th><th>{t('detectedAt')}</th></tr></thead>
                <tbody>
                  {exposure.map((e) => (
                    <tr key={e.id}>
                      <td>{e.service?.name || e.name || '—'}</td>
                      <td className="text-mono">{e.port}</td>
                      <td className="text-mono text-small">{e.asset?.value || e.asset_id}</td>
                      <td><Badge kind={e.state}>{e.state}</Badge></td>
                      <td className="text-small text-muted">{fmtDate(e.first_seen_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <Pagination page={page} pageSize={25} total={exposure.length >= 25 ? page * 25 + 1 : page * 25} onPage={setPage} />
        </Card>
      )}

      {tab === 'changes' && (
        <Card>
          {changes.length === 0 ? <EmptyState icon="⚡" title={t('noData')} /> : (
            <>
              <div className="table-wrap">
                <table className="table">
                  <thead><tr><th>{t('changeType')}</th><th>{t('changeSeverity')}</th><th>{t('summary')}</th><th>{t('asset')}</th><th>{t('detectedAt')}</th><th>{t('actions')}</th></tr></thead>
                  <tbody>
                    {changes.map((c) => (
                      <tr key={c.id}>
                        <td><Badge kind={c.kind}>{c.kind}</Badge></td>
                        <td><Badge kind={c.severity}>{c.severity}</Badge></td>
                        <td style={{ maxWidth: 280 }}>{c.summary}</td>
                        <td className="text-mono text-small">{c.asset?.value || '—'}</td>
                        <td className="text-small text-muted">{fmtDate(c.detected_at)}</td>
                        <td>{!c.acknowledged_at && <button className="btn btn-ghost btn-sm" onClick={() => ackChange(c.id)}>{t('ackChange')}</button>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Pagination page={page} pageSize={25} total={changesTotal} onPage={setPage} />
            </>
          )}
        </Card>
      )}
    </div>
  );
}

function StatCard({ icon, tone, value, label }: { icon: string; tone: string; value: number; label: string }) {
  const tones: Record<string, string> = { neutral: 'var(--violet-soft);color:var(--violet)', low: 'var(--green-soft);color:var(--green)', medium: 'var(--yellow-soft);color:var(--yellow)', high: 'var(--red-soft);color:var(--red)', critical: 'var(--red-soft);color:var(--red)', info: 'var(--cyan-soft);color:var(--cyan)' };
  return (
    <div className="stat-card">
      <div className="stat-icon" style={tone in tones ? { background: tones[tone].split(';')[0], color: tones[tone].split(';')[1] } : {}}>{icon}</div>
      <div>
        <div className="stat-value">{value}</div>
        <div className="stat-label">{label}</div>
      </div>
    </div>
  );
}
