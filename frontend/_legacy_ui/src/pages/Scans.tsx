import React, { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { api } from '../lib/api';
import { Card, Badge, Spinner, Modal, FieldError, EmptyState, Progress } from '../components/ui';
import { useUi } from '../lib/store';
import { fmtDate } from '../lib/utils';

export default function Scans() {
  const { t } = useTranslation();
  const nav = useNavigate();
  const [params, setParams] = useSearchParams();
  const { projectId } = useUi();
  const [scans, setScans] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showNew, setShowNew] = useState(params.get('new') === '1');
  const [name, setName] = useState('');
  const [targets, setTargets] = useState('');
  const [profile, setProfile] = useState('standard');
  const [creating, setCreating] = useState(false);
  const [createErr, setCreateErr] = useState('');

  const load = () => {
    if (!projectId) return;
    setLoading(true);
    api<{ items: any[] }>(`/projects/${projectId}/scans?limit=50`)
      .then((d) => setScans(d.items))
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(load, [projectId]);

  const create = async () => {
    if (!projectId) return;
    setCreating(true);
    setCreateErr('');
    try {
      const res = await api<any>(`/projects/${projectId}/scans`, {
        method: 'POST',
        body: JSON.stringify({
          name: name || `${profile} scan`,
          kind: 'web',
          profile,
          targets: targets.split('\n').map((s) => s.trim()).filter(Boolean),
        }),
      });
      setShowNew(false);
      nav(`/scans/${res.scan.id}`);
    } catch (e: any) {
      setCreateErr(e.message);
    } finally {
      setCreating(false);
    }
  };

  if (!projectId) return <Card><EmptyState title={t('selectProjectFirst')} /></Card>;

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h1 style={{ fontSize: 20, fontWeight: 800 }}>{t('scans')}</h1>
        <button className="btn btn-primary" onClick={() => setShowNew(true)}>▶ {t('newScan')}</button>
      </div>

      {loading ? <Spinner /> : error ? <p style={{ color: 'var(--red)' }}>{error}</p> : scans.length === 0 ? (
        <Card><EmptyState icon="▶" title={t('noData')} desc="Run your first authorized scan." action={<button className="btn btn-primary mt-3" onClick={() => setShowNew(true)}>{t('newScan')}</button>} /></Card>
      ) : (
        <div className="flex flex-col gap-3">
          {scans.map((s) => (
            <Card key={s.id} hover className="card-hover">
              <div className="flex items-center gap-4" style={{ flexWrap: 'wrap' }}>
                <div style={{ flex: 1, minWidth: 200 }}>
                  <div className="flex items-center gap-2">
                    <span className="font-bold">{s.name}</span>
                    <Badge kind={s.status}>{t(s.status)}</Badge>
                    <Badge kind={s.profile}>{t(s.profile)}</Badge>
                  </div>
                  <div className="text-small text-muted mt-1">
                    {s.target_count} {t('targets')} · {t('engine')}: {s.engine || 'internal'} {s.engine_version ? `v${s.engine_version}` : ''} · {fmtDate(s.created_at)}
                  </div>
                </div>
                {(s.status === 'running' || s.status === 'queued') && (
                  <div style={{ width: 160 }}>
                    <Progress value={s.progress || 0} />
                    <div className="text-small text-muted mt-1">{Math.round(s.progress || 0)}%</div>
                  </div>
                )}
                <button className="btn btn-secondary btn-sm" onClick={() => nav(`/scans/${s.id}`)}>{t('viewScan')}</button>
              </div>
            </Card>
          ))}
        </div>
      )}

      {showNew && (
        <Modal title={t('newScan')} onClose={() => setShowNew(false)} footer={
          <>
            <button className="btn btn-ghost" onClick={() => setShowNew(false)}>{t('cancel')}</button>
            <button className="btn btn-primary" onClick={create} disabled={creating || !targets.trim()}>{creating ? t('loading') : t('startScanBtn')}</button>
          </>
        }>
          <div className="form-group">
            <label className="form-label">{t('scanName')}</label>
            <input className="form-input" value={name} onChange={(e) => setName(e.target.value)} placeholder={t('scanNamePlaceholder')} />
          </div>
          <div className="form-group">
            <label className="form-label">{t('scanTargetsLabel')}</label>
            <textarea className="form-textarea" value={targets} onChange={(e) => setTargets(e.target.value)} rows={4} placeholder={t('scanTargetHint')} dir="ltr" />
          </div>
          <div className="form-group">
            <label className="form-label">{t('scanProfileLabel')}</label>
            <select className="form-select" value={profile} onChange={(e) => setProfile(e.target.value)}>
              <option value="quick">{t('quick')}</option>
              <option value="standard">{t('standard')}</option>
              <option value="deep">{t('deep')}</option>
              <option value="passive">{t('passiveOnly')}</option>
            </select>
          </div>
          {createErr && <FieldError message={createErr} />}
        </Modal>
      )}
    </div>
  );
}
